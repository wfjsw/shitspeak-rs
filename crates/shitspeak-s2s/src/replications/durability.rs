//! Durable-storage readiness for strict-replication participants.
//!
//! The overlay owns and reports the durability of its boot epoch. This module
//! owns the additional terminal-journal probe required by strict replication;
//! the overlay neither opens replication journals nor decides protocol
//! capability from their health.

#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use shitspeak_core::NodeIdentifier;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::capability::StrictParticipantCapability;
use crate::overlay::OverlayNetwork;

const JOURNAL_DIRECTORY: &str = "strict-terminal-journal";
const DURABILITY_PROBE_PAYLOAD: &[u8] = b"strict-replication-durability-v2\n";

static NEXT_DURABILITY_PROBE_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn participant_journal_ready(
    persistence_dir: Option<&Path>,
    self_id: NodeIdentifier,
) -> io::Result<bool> {
    let Some(persistence_dir) = persistence_dir.filter(|dir| !dir.as_os_str().is_empty()) else {
        return Ok(false);
    };
    probe_participant_journal(persistence_dir, self_id)?;
    Ok(true)
}

pub(crate) fn probe_participant_journal(
    persistence_dir: &Path,
    self_id: NodeIdentifier,
) -> io::Result<()> {
    let journal_dir = persistence_dir.join(JOURNAL_DIRECTORY);
    create_directory_with_durable_entries(&journal_dir)?;

    let probe_id = NEXT_DURABILITY_PROBE_ID.fetch_add(1, Ordering::Relaxed);
    let probe_path = journal_dir.join(format!(
        ".strict-replication-durability-{self_id}-{}-{probe_id}",
        std::process::id()
    ));
    let temporary_path = probe_path.with_extension("tmp");
    let result = (|| {
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary_path)?;
            file.write_all(DURABILITY_PROBE_PAYLOAD)?;
            file.sync_all()?;
        }
        replace_file_atomically(&temporary_path, &probe_path)?;
        if fs::read(&probe_path)? != DURABILITY_PROBE_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "strict replication durability probe readback mismatch",
            ));
        }
        sync_parent_directory(&journal_dir)?;
        fs::remove_file(&probe_path)?;
        sync_parent_directory(&journal_dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
        let _ = fs::remove_file(&probe_path);
    }
    result
}

pub(crate) fn spawn_participant_durability_monitor(
    overlay: OverlayNetwork,
    capability: std::sync::Arc<StrictParticipantCapability>,
    shutdown: CancellationToken,
    initial_journal_ready: bool,
) {
    let Some(persistence_dir) = overlay
        .persistence_dir()
        .filter(|dir| !dir.as_os_str().is_empty())
    else {
        return;
    };
    let self_id = overlay.local_node_id();
    let interval = overlay
        .persistence_health_probe_interval()
        .max(std::time::Duration::from_secs(1));
    tokio::spawn(async move {
        let mut journal_ready = initial_journal_ready;
        let mut ready = journal_ready && overlay.local_boot_epoch_durable();
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = ticker.tick() => {
                    let next_journal_ready = match probe_participant_journal(
                        &persistence_dir,
                        self_id,
                    ) {
                        Ok(()) => true,
                        Err(error) => {
                            if journal_ready {
                                warn!(
                                    ?persistence_dir,
                                    %error,
                                    "strict replication terminal journal storage became unavailable"
                                );
                            }
                            false
                        }
                    };
                    if !journal_ready && next_journal_ready {
                        info!(
                            ?persistence_dir,
                            "strict replication terminal journal storage is ready"
                        );
                    }
                    journal_ready = next_journal_ready;

                    let next_ready = journal_ready && overlay.local_boot_epoch_durable();
                    if next_ready != ready {
                        if next_ready {
                            info!(
                                ?persistence_dir,
                                active_boot_epoch = overlay.local_boot_epoch(),
                                "strict replication durable storage is ready for v2"
                            );
                        }
                        capability.update_durable_state_ready(next_ready);
                        ready = next_ready;
                    }
                }
            }
        }
    });
}

#[cfg(not(windows))]
fn replace_file_atomically(temporary_path: &Path, path: &Path) -> io::Result<()> {
    fs::rename(temporary_path, path)
}

#[cfg(windows)]
fn replace_file_atomically(temporary_path: &Path, path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            move_flags: u32,
        ) -> i32;
    }

    fn windows_api_path(path: &Path) -> io::Result<Vec<u16>> {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
        })?;
        let file_name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
        let absolute_path = fs::canonicalize(parent)?.join(file_name);
        let mut wide = absolute_path.as_os_str().encode_wide().collect::<Vec<_>>();
        if wide.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains an embedded NUL",
            ));
        }
        wide.push(0);
        Ok(wide)
    }

    let temporary_wide = windows_api_path(temporary_path)?;
    let path_wide = windows_api_path(path)?;
    let moved = unsafe {
        MoveFileExW(
            temporary_wide.as_ptr(),
            path_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn sync_parent_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(any(windows, all(not(unix), not(windows))))]
fn sync_parent_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}

fn create_directory_with_durable_entries(path: &Path) -> io::Result<()> {
    let mut missing_directories = Vec::new();
    let mut ancestor = path;
    while !ancestor.exists() {
        missing_directories.push(ancestor.to_path_buf());
        ancestor = ancestor.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory path has no existing ancestor",
            )
        })?;
    }

    fs::create_dir_all(path)?;
    for directory in missing_directories.into_iter().rev() {
        let parent = directory
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        sync_parent_directory(parent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn participant_without_persistence_fails_closed() {
        assert!(!participant_journal_ready(None, 7).unwrap());
        assert!(!participant_journal_ready(Some(Path::new("")), 7).unwrap());
    }

    #[test]
    fn participant_probe_requires_a_writable_directory() {
        let root = tempfile::tempdir().unwrap();
        assert!(participant_journal_ready(Some(root.path()), 7).unwrap());

        let regular_file = root.path().join("not-a-directory");
        fs::write(&regular_file, b"x").unwrap();
        assert!(participant_journal_ready(Some(&regular_file), 7).is_err());
    }
}
