use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{ProfiledAllocator, Relaxed, SAMPLE_BYTES, Suppress};

const MAX_SNAPSHOT: usize = 8 * 1024 * 1024;
const FILES: u64 = 8;

/// Owns the diagnostic thread. Scope exit stops observation and joins it.
pub struct Observation {
    stop: Sender<()>,
    thread: Option<JoinHandle<()>>,
}
impl Drop for Observation {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// MEMORY_PROFILE_DIR must name an existing private directory. Each run creates
/// a fresh child directory; snapshots rotate rather than accumulating forever.
/// No environment setting means counters only, with no thread or stack capture.
pub fn start_from_env<const N: usize>(
    allocator: &'static ProfiledAllocator<mimalloc::MiMalloc, N>,
) -> io::Result<Option<Observation>> {
    let Some(parent) = std::env::var_os("MEMORY_PROFILE_DIR") else {
        return Ok(None);
    };
    let parent = PathBuf::from(parent);
    if !parent.is_absolute() || !parent.is_dir() {
        return Err(io::Error::other(
            "MEMORY_PROFILE_DIR must be an existing absolute directory",
        ));
    }
    let seconds = env_number("MEMORY_PROFILE_SECONDS", 21600, 1, 86400)?;
    let interval = env_number("MEMORY_PROFILE_INTERVAL_SECONDS", 60, 1, 3600)?;
    let stacks = env_number("MEMORY_PROFILE_STACKS", 1, 0, 1)? != 0;
    let sample_bytes = env_number(
        "MEMORY_PROFILE_SAMPLE_BYTES",
        SAMPLE_BYTES as u64,
        1,
        1 << 30,
    )?;
    let stamps = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let directory = parent.join(format!("memory-{}-{stamps}", std::process::id()));
    #[allow(unused_mut)]
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&directory)?;
    let mut executable = fs::File::open(std::env::current_exe()?)?;
    let mut hasher = Sha256::new();
    io::copy(&mut executable, &mut hasher)?;
    let executable_sha256 = format!("{:x}", hasher.finalize());
    atomic_write(
        &directory.join("metadata.json"),
        &serde_json::to_vec_pretty(&serde_json::json!({
            "schema": 1, "pid": std::process::id(), "start_unix_ns": stamps.to_string(),
            "mimalloc_version": mimalloc::MiMalloc.version(), "slots": N,
            "executable_sha256": executable_sha256, "stacks": stacks,
            "sample_bytes": sample_bytes, "seconds": seconds, "interval_seconds": interval,
            "snapshot_files": FILES, "snapshot_limit_bytes": MAX_SNAPSHOT,
            "coverage": "Rust GlobalAlloc requests; native mimalloc JSON statistics are separate",
            "sampling": "p=min(current request bytes/sample_bytes,1); collisions reported; resized samples keep original stack and birth",
            "counter_consistency": "individual relaxed atomics; concurrent snapshots can have small inconsistencies",
            "mimalloc_stats": "Bundled v3 public stats_get_json; MI_STAT=0 essential statistics, detailed bins may be zero"
        }))?,
    )?;
    #[cfg(target_os = "linux")]
    {
        atomic_write(
            &directory.join("initial.maps"),
            &fs::read("/proc/self/maps")?,
        )?;
        atomic_write(
            &directory.join("executable.txt"),
            fs::read_link("/proc/self/exe")?
                .to_string_lossy()
                .as_bytes(),
        )?;
    }
    allocator.sample_bytes.store(sample_bytes as usize, Relaxed);
    let (stop, receiver) = mpsc::channel();
    let thread = std::thread::Builder::new().name("memory-observer".into()).spawn(move || {
        let _suppression = Suppress::enter();
        let start = Instant::now();
        let mut sequence = 0;
        allocator.sampling.store(stacks, Relaxed);
        let reason = loop {
            if !has_disk_headroom(&directory) { break "disk free below 256 MiB".to_owned(); }
            if directory.join("STOP").exists() { break "STOP requested".to_owned(); }
            if let Err(error) = write_snapshot(allocator, &directory, sequence, start) {
                break format!("snapshot failed: {error}");
            }
            sequence += 1;
            let remaining = Duration::from_secs(seconds).saturating_sub(start.elapsed());
            if remaining.is_zero() { break "duration completed".to_owned(); }
            if receiver.recv_timeout(Duration::from_secs(interval).min(remaining)).is_ok() {
                break "observation owner stopped".to_owned();
            }
        };
        allocator.sampling.store(false, Relaxed);
        let result = atomic_write(&directory.join("finished.json"), &serde_json::to_vec(&serde_json::json!({
            "reason": reason, "elapsed_seconds": start.elapsed().as_secs(), "snapshots": sequence
        })).unwrap_or_default());
        if let Err(error) = result { eprintln!("memory profile finish record failed: {error}"); }
    })?;
    Ok(Some(Observation {
        stop,
        thread: Some(thread),
    }))
}

fn env_number(key: &str, default: u64, min: u64, max: u64) -> io::Result<u64> {
    match std::env::var(key) {
        Err(std::env::VarError::NotPresent) => Ok(default),
        Ok(value) => value
            .parse::<u64>()
            .ok()
            .filter(|n| (min..=max).contains(n))
            .ok_or_else(|| io::Error::other(format!("{key} must be between {min} and {max}"))),
        Err(error) => Err(io::Error::other(error)),
    }
}

fn write_snapshot<const N: usize>(
    allocator: &ProfiledAllocator<mimalloc::MiMalloc, N>,
    directory: &Path,
    sequence: u64,
    start: Instant,
) -> io::Result<()> {
    let snapshot = allocator.snapshot();
    // This wrapper calls the public API from the exact linked crate/version.
    // It allocates its JSON through mimalloc directly and frees via its RAII type.
    let native = mimalloc::MiMalloc::stats_json().map_err(io::Error::other)?;
    let native: serde_json::Value = serde_json::from_slice(native.to_bytes())?;
    let summary = serde_json::json!({
        "sequence": sequence, "elapsed_ms": start.elapsed().as_millis(),
        "unix_ms": SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_millis(),
        "live_bytes": snapshot.live_bytes, "live_objects": snapshot.live_objects,
        "allocated_bytes": snapshot.allocated_bytes, "freed_bytes": snapshot.freed_bytes,
        "sampled_live_bytes": snapshot.samples.iter().map(|s| s.bytes as u64).sum::<u64>(),
        "sampled_live_objects": snapshot.samples.len(), "collisions": snapshot.collisions,
        "mimalloc_committed": native.get("committed"), "mimalloc_reserved": native.get("reserved"),
        "mimalloc_process": native.get("process")
    });
    let mut out = Limited(Vec::new());
    serde_json::to_writer(
        &mut out,
        &serde_json::json!({
            "schema": 1, "sequence": sequence,
            "unix_ms": SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_millis(),
            "elapsed_ms": start.elapsed().as_millis(), "rust": snapshot, "mimalloc": native,
            "proc_status": fs::read_to_string("/proc/self/status").ok(),
            "proc_stat": fs::read_to_string("/proc/self/stat").ok(),
            "proc_smaps_rollup": fs::read_to_string("/proc/self/smaps_rollup").ok(),
        }),
    )?;
    atomic_write(
        &directory.join(format!("snapshot-{}.json", sequence % FILES)),
        &out.0,
    )?;
    if sequence == 0 {
        atomic_write(&directory.join("baseline.json"), &out.0)?;
    }
    if start.elapsed() >= Duration::from_secs(300) && !directory.join("warmup.json").exists() {
        atomic_write(&directory.join("warmup.json"), &out.0)?;
    }
    append_summary(directory, &summary)?;
    #[cfg(target_os = "linux")]
    atomic_write(
        &directory.join("latest.maps"),
        &fs::read("/proc/self/maps")?,
    )?;
    Ok(())
}

fn append_summary(directory: &Path, value: &serde_json::Value) -> io::Result<()> {
    let path = directory.join("counters.jsonl");
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    if path.metadata().map(|m| m.len()).unwrap_or(0) + bytes.len() as u64 > 4 * 1024 * 1024 {
        fs::rename(&path, directory.join("counters.previous.jsonl"))?;
    }
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(&bytes)
}

struct Limited(Vec<u8>);
impl Write for Limited {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.0.len().saturating_add(buf.len()) > MAX_SNAPSHOT {
            return Err(io::Error::other("snapshot byte limit exceeded"));
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
    }
    // On Linux rename atomically replaces the previous slot.
    fs::rename(&tmp, path)
}

#[cfg(unix)]
fn has_disk_headroom(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: valid NUL-terminated path and writable statvfs storage.
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return false;
    }
    let stat = unsafe { stat.assume_init() };
    (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64) >= 256 * 1024 * 1024
}
#[cfg(not(unix))]
fn has_disk_headroom(_: &Path) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_refuses_growth_beyond_budget() {
        let mut writer = Limited(vec![0; MAX_SNAPSHOT - 1]);
        assert_eq!(writer.write(&[1]).unwrap(), 1);
        assert!(writer.write(&[2]).is_err());
        assert_eq!(writer.0.len(), MAX_SNAPSHOT);
    }
    #[test]
    fn native_statistics_are_versioned_json() {
        let stats = mimalloc::MiMalloc::stats_json().unwrap();
        let json: serde_json::Value = serde_json::from_slice(stats.to_bytes()).unwrap();
        assert_eq!(
            json["mimalloc_version"].as_u64(),
            Some(mimalloc::MiMalloc.version() as u64)
        );
        assert!(json["committed"].is_object());
        assert!(json["reserved"].is_object());
    }
}
