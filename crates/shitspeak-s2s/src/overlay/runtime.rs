//! `OverlayInner` — shared overlay state and `OverlayNetwork::start`.
//!
//! Phase 2 wiring:
//!   * `LinkStateDb` is the single source of truth (membership +
//!     routing graph).
//!   * `NeighborMonitor` watches direct L1 streams and maintains
//!     per-neighbor cost readings.
//!   * `LsaEmitter` publishes our LSA on triggered + periodic events.
//!   * `RoutingTables` (per-service-level) are recomputed by Dijkstra
//!     whenever the LSDB changes.
//!   * `ServiceRegistry` dispatches inbound `OverlayData` by tag.

use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{ConnectionManager, Inbound, PeerAddress};

use super::config::OverlayConfig;
use super::distribution::DistributionPlane;
use super::duplicate::DuplicateDetector;
use super::error::OverlayError;
use super::lsdb::{
    ApplicationServices, DistributionCapabilities, LinkStateDb, LsaEmitter, LsaFloodPacer,
    LsaFloor, ReplicationServices, capture_boot_epoch, emit_once, spawn_anti_entropy,
    spawn_emitter_task, spawn_floor_persister,
};
use super::membership::{MembershipTable, spawn_diff_watcher};
use super::messaging::{ServiceRegistry, ordering::OverlayOrdering};
use super::neighbor::hello::{HelloContext, spawn_hello_task, spawn_link_up_watcher};
use super::neighbor::monitor::NeighborMonitor;
use super::routing::{RoutingHandle, new_handle as new_routing_handle, spawn_recomputer};

static LAST_PROCESS_BOOT_EPOCH: AtomicU64 = AtomicU64::new(0);
static LOCAL_BOOT_EPOCH_PROCESS_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
static NEXT_LOCAL_BOOT_EPOCH_TEMP_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_STRICT_REPLICATION_DURABILITY_PROBE_ID: AtomicU64 = AtomicU64::new(1);

const STRICT_REPLICATION_JOURNAL_DIRECTORY: &str = "strict-terminal-journal";
const STRICT_REPLICATION_DURABILITY_PROBE_PAYLOAD: &[u8] = b"strict-replication-durability-v2\n";

#[cfg(windows)]
const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
#[cfg(windows)]
const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

#[cfg(windows)]
#[link(name = "Kernel32")]
unsafe extern "system" {
    fn MoveFileExW(
        existing_file_name: *const u16,
        new_file_name: *const u16,
        move_flags: u32,
    ) -> i32;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactBootEpochReadiness {
    Ready,
    Retryable,
    Blocked,
}

impl ExactBootEpochReadiness {
    fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[derive(Clone, Copy, Debug)]
struct BootEpochDurability {
    readiness: ExactBootEpochReadiness,
    allow_missing_repair: bool,
}

#[derive(Clone, Copy, Debug)]
struct CapturedBootEpoch {
    value: u64,
    durability: BootEpochDurability,
}

/// Probe the durable state required by a local strict-replication participant.
///
/// This deliberately does not describe transit support: a transport-only
/// forwarder can relay opaque strict frames without opening a local journal.
fn strict_replication_participant_journal_ready(
    persistence_dir: Option<&Path>,
    self_id: NodeIdentifier,
) -> io::Result<bool> {
    let Some(persistence_dir) = persistence_dir.filter(|dir| !dir.as_os_str().is_empty()) else {
        return Ok(false);
    };
    probe_strict_replication_durable_state(persistence_dir, self_id)?;
    Ok(true)
}

fn probe_strict_replication_durable_state(
    persistence_dir: &Path,
    self_id: NodeIdentifier,
) -> io::Result<()> {
    let journal_dir = persistence_dir.join(STRICT_REPLICATION_JOURNAL_DIRECTORY);
    create_directory_with_durable_entries(&journal_dir)?;

    let probe_id = NEXT_STRICT_REPLICATION_DURABILITY_PROBE_ID.fetch_add(1, Ordering::Relaxed);
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
            file.write_all(STRICT_REPLICATION_DURABILITY_PROBE_PAYLOAD)?;
            file.sync_all()?;
        }
        replace_file_atomically(&temporary_path, &probe_path)?;
        if fs::read(&probe_path)? != STRICT_REPLICATION_DURABILITY_PROBE_PAYLOAD {
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

#[cfg(not(windows))]
fn replace_file_atomically(temporary_path: &Path, path: &Path) -> io::Result<()> {
    fs::rename(temporary_path, path)
}

#[cfg(windows)]
fn replace_file_atomically(temporary_path: &Path, path: &Path) -> io::Result<()> {
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

#[cfg(windows)]
fn windows_api_path(path: &Path) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "replacement path has no parent directory",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "replacement path has no file name",
        )
    })?;
    let absolute_path = fs::canonicalize(parent)?.join(file_name);
    let mut wide = absolute_path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "replacement path contains an embedded NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(unix)]
fn sync_parent_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(any(windows, all(not(unix), not(windows))))]
fn sync_parent_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}

/// Create a directory tree and persist each new directory entry before it is
/// used as durable protocol state.
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

/// Track local participant durability and update only the participant
/// capability advertised by `LsaEmitter`. Transit capability is initialized
/// independently by the emitter and is never changed by this task.
fn spawn_strict_replication_participant_durability_monitor(
    persistence_dir: Option<PathBuf>,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    boot_epoch_durability: BootEpochDurability,
    emitter: Arc<LsaEmitter>,
    interval: Duration,
    shutdown: CancellationToken,
    initial_journal_ready: bool,
) {
    let Some(persistence_dir) = persistence_dir.filter(|dir| !dir.as_os_str().is_empty()) else {
        return;
    };
    let boot_epoch_path = local_boot_epoch_path(&persistence_dir, self_id);
    let interval = interval.max(Duration::from_secs(1));
    tokio::spawn(async move {
        let mut journal_ready = initial_journal_ready;
        let mut boot_epoch_durability = boot_epoch_durability;
        let mut ready = journal_ready && boot_epoch_durability.readiness.is_ready();
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = ticker.tick() => {
                    let next_journal_ready = match probe_strict_replication_durable_state(
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

                    if boot_epoch_durability.readiness != ExactBootEpochReadiness::Blocked {
                        let next_boot_epoch_readiness = ensure_exact_local_boot_epoch(
                            &boot_epoch_path,
                            self_id,
                            boot_epoch,
                            boot_epoch_durability.allow_missing_repair,
                        );
                        if next_boot_epoch_readiness.is_ready() {
                            boot_epoch_durability.allow_missing_repair = true;
                        } else if next_boot_epoch_readiness == ExactBootEpochReadiness::Blocked {
                            boot_epoch_durability.allow_missing_repair = false;
                        }
                        if boot_epoch_durability.readiness.is_ready()
                            && !next_boot_epoch_readiness.is_ready()
                        {
                            warn!(
                                ?boot_epoch_path,
                                ?next_boot_epoch_readiness,
                                active_boot_epoch = boot_epoch,
                                "local boot epoch durability was lost; disabling v2 advertisement"
                            );
                        } else if !boot_epoch_durability.readiness.is_ready()
                            && next_boot_epoch_readiness.is_ready()
                        {
                            info!(
                                ?boot_epoch_path,
                                active_boot_epoch = boot_epoch,
                                "local boot epoch is durably persisted"
                            );
                        }
                        boot_epoch_durability.readiness = next_boot_epoch_readiness;
                    }

                    let next_ready = journal_ready && boot_epoch_durability.readiness.is_ready();
                    if next_ready != ready {
                        if next_ready {
                            info!(
                                ?persistence_dir,
                                active_boot_epoch = boot_epoch,
                                "strict replication durable storage is ready for v2"
                            );
                        }
                        emitter.update_strict_replication_durable_state_ready(next_ready);
                        ready = next_ready;
                    }
                }
            }
        }
    });
}

#[derive(Debug, Serialize, Deserialize)]
struct LocalBootEpochFileV1 {
    version: u32,
    node_id: NodeIdentifier,
    boot_epoch: u64,
}

fn local_boot_epoch_path(dir: &Path, self_id: NodeIdentifier) -> PathBuf {
    dir.join("overlay")
        .join(format!("local_boot_epoch_{self_id}.json"))
}

fn local_boot_epoch_lock_path(path: &Path) -> PathBuf {
    path.with_extension("lock")
}

fn local_boot_epoch_temporary_path(path: &Path) -> PathBuf {
    let id = NEXT_LOCAL_BOOT_EPOCH_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    path.with_extension(format!("json.{}.{}.tmp", std::process::id(), id))
}

fn read_local_boot_epoch(path: &Path, self_id: NodeIdentifier) -> io::Result<Option<u64>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let file = serde_json::from_slice::<LocalBootEpochFileV1>(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if file.version != 1 || file.node_id != self_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local boot epoch file has an unrecognized version or node id",
        ));
    }
    Ok(Some(file.boot_epoch))
}

fn classify_boot_epoch_error(error: &io::Error) -> ExactBootEpochReadiness {
    if error.kind() == io::ErrorKind::InvalidData {
        ExactBootEpochReadiness::Blocked
    } else {
        ExactBootEpochReadiness::Retryable
    }
}

fn write_exact_local_boot_epoch(
    path: &Path,
    self_id: NodeIdentifier,
    boot_epoch: u64,
) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "local boot epoch path has no parent directory",
        )
    })?;
    let body = LocalBootEpochFileV1 {
        version: 1,
        node_id: self_id,
        boot_epoch,
    };
    let bytes = serde_json::to_vec_pretty(&body)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let temporary_path = local_boot_epoch_temporary_path(path);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        replace_file_atomically(&temporary_path, path)?;
        sync_parent_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn acquire_local_boot_epoch_lock(path: &Path) -> Result<std::fs::File, ExactBootEpochReadiness> {
    let Some(parent) = path.parent() else {
        return Err(ExactBootEpochReadiness::Blocked);
    };
    let parent_was_missing = !parent.exists();
    if let Err(error) = fs::create_dir_all(parent) {
        return Err(classify_boot_epoch_error(&error));
    }
    if parent_was_missing {
        if let Some(grandparent) = parent.parent() {
            if let Err(error) = sync_parent_directory(grandparent) {
                return Err(classify_boot_epoch_error(&error));
            }
        }
    }

    let lock_path = local_boot_epoch_lock_path(path);
    let lock_file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&lock_path)
    {
        Ok(lock_file) => lock_file,
        Err(error) => return Err(classify_boot_epoch_error(&error)),
    };
    match lock_file.try_lock() {
        Ok(()) => Ok(lock_file),
        Err(TryLockError::WouldBlock) => Err(ExactBootEpochReadiness::Retryable),
        Err(TryLockError::Error(error)) => Err(classify_boot_epoch_error(&error)),
    }
}

fn ensure_exact_local_boot_epoch_while_locked(
    path: &Path,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    allow_missing_repair: bool,
) -> ExactBootEpochReadiness {
    let current = match read_local_boot_epoch(path, self_id) {
        Ok(current) => current,
        Err(error) => return classify_boot_epoch_error(&error),
    };
    match current {
        Some(current) if current == boot_epoch => return ExactBootEpochReadiness::Ready,
        Some(current) if current > boot_epoch => return ExactBootEpochReadiness::Blocked,
        None if !allow_missing_repair => return ExactBootEpochReadiness::Blocked,
        Some(_) | None => {}
    }

    if let Err(error) = write_exact_local_boot_epoch(path, self_id, boot_epoch) {
        return classify_boot_epoch_error(&error);
    }
    match read_local_boot_epoch(path, self_id) {
        Ok(Some(current)) if current == boot_epoch => ExactBootEpochReadiness::Ready,
        Ok(Some(current)) if current > boot_epoch => ExactBootEpochReadiness::Blocked,
        Ok(_) => ExactBootEpochReadiness::Blocked,
        Err(error) => classify_boot_epoch_error(&error),
    }
}

fn ensure_exact_local_boot_epoch(
    path: &Path,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    allow_missing_repair: bool,
) -> ExactBootEpochReadiness {
    let _process_lock = LOCAL_BOOT_EPOCH_PROCESS_LOCK.lock();
    let current = match read_local_boot_epoch(path, self_id) {
        Ok(current) => current,
        Err(error) => return classify_boot_epoch_error(&error),
    };
    match current {
        Some(current) if current == boot_epoch => return ExactBootEpochReadiness::Ready,
        Some(current) if current > boot_epoch => return ExactBootEpochReadiness::Blocked,
        None if !allow_missing_repair => return ExactBootEpochReadiness::Blocked,
        Some(_) | None => {}
    }
    let _file_lock = match acquire_local_boot_epoch_lock(path) {
        Ok(lock_file) => lock_file,
        Err(readiness) => return readiness,
    };
    ensure_exact_local_boot_epoch_while_locked(path, self_id, boot_epoch, allow_missing_repair)
}

fn capture_monotonic_boot_epoch(
    self_id: NodeIdentifier,
    persistence_dir: Option<&PathBuf>,
) -> CapturedBootEpoch {
    let captured = capture_boot_epoch();
    let Some(dir) = persistence_dir.filter(|dir| !dir.as_os_str().is_empty()) else {
        return CapturedBootEpoch {
            value: reserve_process_boot_epoch(captured),
            durability: BootEpochDurability {
                readiness: ExactBootEpochReadiness::Blocked,
                allow_missing_repair: false,
            },
        };
    };
    let path = local_boot_epoch_path(dir, self_id);
    let _process_lock = LOCAL_BOOT_EPOCH_PROCESS_LOCK.lock();
    let _file_lock = match acquire_local_boot_epoch_lock(&path) {
        Ok(lock_file) => lock_file,
        Err(readiness) => {
            warn!(
                ?path,
                ?readiness,
                "local boot epoch: unable to reserve an epoch durably; v2 remains disabled"
            );
            return CapturedBootEpoch {
                value: reserve_process_boot_epoch(captured),
                durability: BootEpochDurability {
                    readiness,
                    allow_missing_repair: readiness == ExactBootEpochReadiness::Retryable,
                },
            };
        }
    };
    let previous = match read_local_boot_epoch(&path, self_id) {
        Ok(previous) => previous,
        Err(error) => {
            let readiness = classify_boot_epoch_error(&error);
            warn!(
                ?path,
                %error,
                "local boot epoch: prior epoch is uncertain; v2 remains disabled"
            );
            return CapturedBootEpoch {
                value: reserve_process_boot_epoch(captured),
                durability: BootEpochDurability {
                    readiness,
                    allow_missing_repair: readiness == ExactBootEpochReadiness::Retryable,
                },
            };
        }
    };
    let boot_epoch = reserve_process_boot_epoch(next_boot_epoch(captured, previous));
    let readiness = ensure_exact_local_boot_epoch_while_locked(&path, self_id, boot_epoch, true);
    let allow_missing_repair = match readiness {
        ExactBootEpochReadiness::Ready => true,
        ExactBootEpochReadiness::Retryable => true,
        ExactBootEpochReadiness::Blocked => false,
    };
    if !readiness.is_ready() {
        warn!(
            ?path,
            ?readiness,
            active_boot_epoch = boot_epoch,
            "local boot epoch is not durably persisted; v2 remains disabled"
        );
    }
    CapturedBootEpoch {
        value: boot_epoch,
        durability: BootEpochDurability {
            readiness,
            allow_missing_repair,
        },
    }
}

fn next_boot_epoch(captured: u64, previous: Option<u64>) -> u64 {
    previous
        .and_then(|previous| previous.checked_add(1))
        .map(|next| captured.max(next))
        .unwrap_or(captured)
}

fn reserve_process_boot_epoch(candidate: u64) -> u64 {
    let mut next = candidate;
    loop {
        let previous = LAST_PROCESS_BOOT_EPOCH.load(Ordering::Relaxed);
        if next <= previous {
            let Some(incremented) = previous.checked_add(1) else {
                return previous;
            };
            next = incremented;
        }
        match LAST_PROCESS_BOOT_EPOCH.compare_exchange(
            previous,
            next,
            Ordering::SeqCst,
            Ordering::Relaxed,
        ) {
            Ok(_) => return next,
            Err(_) => continue,
        }
    }
}

pub(crate) struct OverlayInner {
    pub self_id: NodeIdentifier,
    pub boot_epoch: u64,
    pub transport: ConnectionManager,
    pub lsdb: Arc<LinkStateDb>,
    pub table: Arc<MembershipTable>,
    pub neighbor: Arc<NeighborMonitor>,
    pub routing: RoutingHandle,
    pub distribution: Arc<DistributionPlane>,
    pub attachments: Arc<super::attachments::AttachmentCache>,
    pub services: Arc<ServiceRegistry>,
    pub duplicate_detector: Arc<DuplicateDetector>,
    ordering: Arc<OverlayOrdering>,
    pub emitter: Arc<LsaEmitter>,
    pub flood_pacer: Arc<LsaFloodPacer>,
    pub hello: Arc<HelloContext>,
    pub shutdown: CancellationToken,
    pub cfg: OverlayConfig,
    /// Whether this overlay owns local strict-replication state. Transport-
    /// only forwarders leave this disabled while still advertising transit.
    strict_replication_participation_enabled: bool,
    strict_replication_boot_epoch_durability: BootEpochDurability,
    strict_replication_journal_ready_at_start: bool,
}

impl OverlayInner {
    pub fn new(
        transport: ConnectionManager,
        cfg: OverlayConfig,
        max_users: Arc<AtomicU64>,
        replication_services: ReplicationServices,
        application_services: ApplicationServices,
        self_addresses: Vec<PeerAddress>,
    ) -> Self {
        let self_id = transport.local_node_id();
        let strict_replication_participation_enabled = replication_services.strict();
        let captured_boot_epoch = capture_monotonic_boot_epoch(self_id, cfg.persistence_dir());
        let boot_epoch = captured_boot_epoch.value;
        let strict_replication_journal_ready_at_start = if strict_replication_participation_enabled
        {
            match strict_replication_participant_journal_ready(
                cfg.persistence_dir().map(|dir| dir.as_path()),
                self_id,
            ) {
                Ok(ready) => ready,
                Err(error) => {
                    warn!(
                        persistence_dir = ?cfg.persistence_dir(),
                        %error,
                        "strict replication durable storage is not ready; advertising v0"
                    );
                    false
                }
            }
        } else {
            false
        };
        let strict_replication_durable_state_ready_at_start =
            captured_boot_epoch.durability.readiness.is_ready()
                && strict_replication_journal_ready_at_start;

        let floor = Arc::new(LsaFloor::new(self_id, cfg.persistence_dir().cloned()));
        floor.load();
        let lsdb = Arc::new(LinkStateDb::new(floor));

        let (table, events_tx) = super::membership::new_table(self_id, lsdb.clone(), 256);
        let duplicate_detector = Arc::new(DuplicateDetector::new(
            self_id,
            cfg.lsa_max_age()
                .max(cfg.hello_dead_interval().saturating_mul(2)),
        ));

        let neighbor = Arc::new(NeighborMonitor::new(
            self_id,
            transport.clone(),
            duplicate_detector.clone(),
            cfg.clone(),
            events_tx,
        ));

        let routing = new_routing_handle();
        let distribution = Arc::new(DistributionPlane::default());
        let attachments = Arc::new(super::attachments::AttachmentCache::default());
        let services = Arc::new(ServiceRegistry::new());
        let ordering = Arc::new(OverlayOrdering::new(&cfg));

        let emitter = Arc::new(LsaEmitter::new(
            self_id,
            boot_epoch,
            self_addresses,
            max_users,
            cfg.route_transit_messages(),
            replication_services,
            strict_replication_durable_state_ready_at_start,
            application_services,
        ));
        #[cfg(feature = "pre-release-workload")]
        let distribution_profiles = vec![
            super::distribution::VOICE_REALTIME_PROFILE_ID,
            super::distribution::PRE_RELEASE_RELIABLE_PROFILE_ID,
        ];
        #[cfg(not(feature = "pre-release-workload"))]
        let distribution_profiles = vec![super::distribution::VOICE_REALTIME_PROFILE_ID];
        emitter
            .update_distribution_capabilities(DistributionCapabilities::v3(distribution_profiles));
        let flood_pacer = Arc::new(LsaFloodPacer::new(self_id, transport.clone()));

        let shutdown = CancellationToken::new();
        let hello = Arc::new(HelloContext {
            self_id,
            boot_epoch,
            transport: transport.clone(),
            monitor: neighbor.clone(),
            lsdb: lsdb.clone(),
            duplicate_detector: duplicate_detector.clone(),
            cfg: cfg.clone(),
            shutdown: shutdown.clone(),
            nonce_counter: AtomicU64::new(1),
        });

        Self {
            self_id,
            boot_epoch,
            transport,
            lsdb,
            table,
            neighbor,
            routing,
            distribution,
            attachments,
            services,
            duplicate_detector,
            ordering,
            emitter,
            flood_pacer,
            hello,
            shutdown,
            cfg,
            strict_replication_participation_enabled,
            strict_replication_boot_epoch_durability: captured_boot_epoch.durability,
            strict_replication_journal_ready_at_start,
        }
    }

    /// Spawn every long-running task: Hello ticker, link-up watcher,
    /// LSA emitter, floor persister, anti-entropy, routing recomputer,
    /// diff watcher, and the inbound dispatcher.
    pub fn spawn_tasks(self: &Arc<Self>, inbound: Inbound) {
        // Plumb the LSDB change_signal into the LSA emitter so a sync
        // pull that admits new LSAs triggers re-evaluation of routing
        // (the recomputer also subscribes to change_signal directly).
        // Our emitter listens to its own `trigger` Notify which the
        // neighbor monitor pokes; that's separate from LSDB changes.

        // Forward neighbor on_change → emitter.trigger.
        {
            let mon = self.neighbor.clone();
            let em = self.emitter.clone();
            let shutdown = self.shutdown.clone();
            let on_change = mon.on_change();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = on_change.notified() => {}
                    }
                    em.poke();
                }
            });
        }

        // The emitter classifies and stabilizes metric changes. Forward every
        // notification so service-eligibility loss is still immediate.
        {
            let em = self.emitter.clone();
            let shutdown = self.shutdown.clone();
            let on_metric_change = self.neighbor.on_metric_change();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = on_metric_change.notified() => {}
                    }
                    em.poke();
                }
            });
        }

        spawn_hello_task(self.hello.clone());
        spawn_link_up_watcher(self.hello.clone(), self.neighbor.subscribe_link_up());
        if self.strict_replication_participation_enabled {
            spawn_strict_replication_participant_durability_monitor(
                self.cfg.persistence_dir().cloned(),
                self.self_id,
                self.boot_epoch,
                self.strict_replication_boot_epoch_durability,
                self.emitter.clone(),
                self.cfg.peer_persistence_interval(),
                self.shutdown.clone(),
                self.strict_replication_journal_ready_at_start,
            );
        }
        self.flood_pacer
            .clone()
            .spawn(self.cfg.clone(), self.shutdown.clone());
        spawn_emitter_task(
            self.emitter.clone(),
            self.lsdb.clone(),
            self.neighbor.clone(),
            self.transport.clone(),
            self.flood_pacer.clone(),
            self.cfg.clone(),
            self.shutdown.clone(),
        );
        spawn_floor_persister(
            self.lsdb.floor().clone(),
            self.cfg.peer_persistence_interval(),
            self.shutdown.clone(),
        );
        spawn_anti_entropy(
            self.lsdb.clone(),
            self.neighbor.clone(),
            self.transport.clone(),
            self.self_id,
            self.cfg.clone(),
            self.shutdown.clone(),
        );
        spawn_recomputer(
            self.lsdb.clone(),
            self.self_id,
            self.routing.clone(),
            self.transport.clone(),
            self.duplicate_detector.clone(),
            self.cfg.clone(),
            self.shutdown.clone(),
        );
        super::messaging::forward::spawn_ordered_retransmit_task(
            self.ordering.clone(),
            self.transport.clone(),
            self.routing.clone(),
            self.self_id,
            self.cfg.clone(),
            self.shutdown.clone(),
        );
        spawn_diff_watcher(
            self.table.clone(),
            self.lsdb.clone(),
            self.cfg.lsa_max_age(),
            self.cfg.tombstone_in_memory_age(),
            self.shutdown.clone(),
        );
        {
            let mut events = self.table.subscribe();
            let ordering = self.ordering.clone();
            let shutdown = self.shutdown.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        ev = events.recv() => {
                            match ev {
                                Ok(super::MembershipEvent::Restarted(node))
                                | Ok(super::MembershipEvent::Failed(node))
                                | Ok(super::MembershipEvent::Left(node)) => {
                                    ordering.reset_peer(node.node_id()).await;
                                }
                                Ok(super::MembershipEvent::Joined(_)) => {}
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                            }
                        }
                    }
                }
            });
        }

        // Inbound dispatcher.
        let dctx = Arc::new(super::inbound::DispatcherCtx {
            hello: self.hello.clone(),
            monitor: self.neighbor.clone(),
            lsdb: self.lsdb.clone(),
            routing: self.routing.clone(),
            distribution: self.distribution.clone(),
            attachments: self.attachments.clone(),
            services: self.services.clone(),
            duplicate_detector: self.duplicate_detector.clone(),
            ordering: self.ordering.clone(),
            transport: self.transport.clone(),
            self_id: self.self_id,
            shutdown: self.shutdown.clone(),
            cfg: self.cfg.clone(),
            emitter: self.emitter.clone(),
            flood_pacer: self.flood_pacer.clone(),
        });
        super::inbound::spawn_dispatcher(dctx, inbound);

        if let Some(dir) = self.cfg.persistence_dir().cloned() {
            super::discovery::spawn_persister(
                dir,
                self.cfg.peer_persistence_interval(),
                self.transport.clone(),
                self.lsdb.clone(),
                self.shutdown.clone(),
            );
        }
    }

    /// Best-effort: emit one final tombstone LSA, then cancel internal
    /// tasks.
    pub async fn shutdown_graceful(&self) {
        emit_once(
            &self.emitter,
            &self.lsdb,
            &self.neighbor,
            &self.transport,
            &self.flood_pacer,
            &self.cfg,
            true,
        )
        .await;
        self.shutdown.cancel();
    }

    pub(crate) fn ordering(&self) -> &Arc<OverlayOrdering> {
        &self.ordering
    }
}

/// Build the `OverlayInner`, run discovery bootstrap, and spawn all tasks.
pub(crate) async fn start_inner(
    transport: ConnectionManager,
    inbound: Inbound,
    cfg: OverlayConfig,
    max_users: Arc<AtomicU64>,
    replication_services: ReplicationServices,
    application_services: ApplicationServices,
) -> Result<Arc<OverlayInner>, OverlayError> {
    let self_addresses = transport.listen_addresses_with_public_ip_probe().await;
    let inner = Arc::new(OverlayInner::new(
        transport,
        cfg,
        max_users,
        replication_services,
        application_services,
        self_addresses,
    ));

    super::discovery::bootstrap(&inner.cfg, &inner.transport);

    inner.spawn_tasks(inbound);

    Ok(inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_boot_epoch_handles_backward_clock() {
        assert_eq!(next_boot_epoch(100, Some(200)), 201);
        assert_eq!(next_boot_epoch(300, Some(200)), 300);
        assert_eq!(next_boot_epoch(100, Some(u64::MAX)), 100);
    }

    #[test]
    fn monotonic_boot_epoch_advances_persisted_future_epoch() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = local_boot_epoch_path(dir.path(), 7);
        let persisted_future_epoch = capture_boot_epoch()
            .checked_add(60 * 60 * 1_000_000)
            .expect("current boot epoch leaves room for a future test epoch");
        assert_eq!(
            ensure_exact_local_boot_epoch(&path, 7, persisted_future_epoch, true),
            ExactBootEpochReadiness::Ready
        );

        let captured = capture_monotonic_boot_epoch(7, Some(&dir.path().to_path_buf()));
        assert_eq!(captured.value, persisted_future_epoch + 1);
        assert!(captured.durability.readiness.is_ready());

        let reloaded = std::fs::read(&path).unwrap();
        let file: LocalBootEpochFileV1 = serde_json::from_slice(&reloaded).unwrap();
        assert_eq!(file.node_id, 7);
        assert_eq!(file.boot_epoch, persisted_future_epoch + 1);
        assert!(
            std::fs::read_dir(path.parent().unwrap())
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
        );
    }

    #[test]
    fn monotonic_boot_epoch_uses_node_specific_files() {
        let dir = tempfile::TempDir::new().unwrap();
        assert_eq!(
            ensure_exact_local_boot_epoch(&local_boot_epoch_path(dir.path(), 7), 7, 100, true,),
            ExactBootEpochReadiness::Ready
        );

        let captured = capture_monotonic_boot_epoch(8, Some(&dir.path().to_path_buf()));
        assert!(local_boot_epoch_path(dir.path(), 8).exists());

        let node7 = std::fs::read(&local_boot_epoch_path(dir.path(), 7)).unwrap();
        let node7: LocalBootEpochFileV1 = serde_json::from_slice(&node7).unwrap();
        assert_eq!(node7.boot_epoch, 100);

        let node8 = std::fs::read(&local_boot_epoch_path(dir.path(), 8)).unwrap();
        let node8: LocalBootEpochFileV1 = serde_json::from_slice(&node8).unwrap();
        assert_eq!(node8.boot_epoch, captured.value);
        assert!(captured.durability.readiness.is_ready());
    }

    #[test]
    fn sequential_boot_epoch_captures_reserve_distinct_persisted_epochs() {
        let dir = tempfile::TempDir::new().unwrap();
        let persistence_dir = dir.path().to_path_buf();
        let path = local_boot_epoch_path(dir.path(), 7);

        let first = capture_monotonic_boot_epoch(7, Some(&persistence_dir));
        let second = capture_monotonic_boot_epoch(7, Some(&persistence_dir));

        assert!(first.durability.readiness.is_ready());
        assert!(second.durability.readiness.is_ready());
        assert!(second.value > first.value);
        assert_eq!(read_local_boot_epoch(&path, 7).unwrap(), Some(second.value));
    }

    #[test]
    fn retryable_missing_boot_epoch_can_be_repaired_for_the_active_epoch() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = local_boot_epoch_path(dir.path(), 7);
        let mut durability = BootEpochDurability {
            readiness: ExactBootEpochReadiness::Retryable,
            allow_missing_repair: true,
        };

        assert!(!path.exists());
        durability.readiness =
            ensure_exact_local_boot_epoch(&path, 7, 123, durability.allow_missing_repair);

        assert!(durability.readiness.is_ready());
        assert_eq!(read_local_boot_epoch(&path, 7).unwrap(), Some(123));
    }

    #[test]
    fn exact_boot_epoch_persistence_never_replaces_a_higher_epoch() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = local_boot_epoch_path(dir.path(), 7);
        assert_eq!(
            ensure_exact_local_boot_epoch(&path, 7, 100, true),
            ExactBootEpochReadiness::Ready
        );
        let before = std::fs::read(&path).unwrap();

        assert_eq!(
            ensure_exact_local_boot_epoch(&path, 7, 99, true),
            ExactBootEpochReadiness::Blocked
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(read_local_boot_epoch(&path, 7).unwrap(), Some(100));
    }

    #[test]
    fn corrupt_prior_boot_epoch_keeps_v2_fail_closed_without_replacement() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = local_boot_epoch_path(dir.path(), 7);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let corrupt = b"not-json";
        std::fs::write(&path, corrupt).unwrap();

        let captured = capture_monotonic_boot_epoch(7, Some(&dir.path().to_path_buf()));
        assert_eq!(
            captured.durability.readiness,
            ExactBootEpochReadiness::Blocked
        );
        assert!(!captured.durability.allow_missing_repair);
        assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    }

    #[test]
    fn strict_replication_participant_v2_requires_active_durable_storage() {
        assert!(!strict_replication_participant_journal_ready(None, 7).unwrap());
        assert!(!strict_replication_participant_journal_ready(Some(Path::new("")), 7).unwrap());

        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join("persistence");
        assert!(strict_replication_participant_journal_ready(Some(&root), 7).unwrap());
        let journal_dir = root.join(STRICT_REPLICATION_JOURNAL_DIRECTORY);
        assert!(journal_dir.is_dir());
        assert!(std::fs::read_dir(&journal_dir).unwrap().next().is_none());

        let regular_file = dir.path().join("not-a-directory");
        std::fs::write(&regular_file, b"not a directory").unwrap();
        assert!(strict_replication_participant_journal_ready(Some(&regular_file), 7).is_err());
    }
}
