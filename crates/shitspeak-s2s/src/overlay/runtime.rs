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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio_util::sync::CancellationToken;
use tracing::warn;

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

fn capture_monotonic_boot_epoch(self_id: NodeIdentifier, persistence_dir: Option<&PathBuf>) -> u64 {
    let captured = capture_boot_epoch();
    let Some(dir) = persistence_dir else {
        return reserve_process_boot_epoch(captured);
    };
    let path = local_boot_epoch_path(dir, self_id);
    let previous = match std::fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<LocalBootEpochFileV1>(&bytes) {
            Ok(file) if file.version == 1 && file.node_id == self_id => Some(file.boot_epoch),
            Ok(_) => {
                warn!(?path, "local boot epoch: unrecognized file, replacing");
                None
            }
            Err(error) => {
                warn!(?path, %error, "local boot epoch: parse failed, replacing");
                None
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            warn!(?path, %error, "local boot epoch: read failed, using wall clock");
            None
        }
    };
    let boot_epoch = reserve_process_boot_epoch(next_boot_epoch(captured, previous));
    persist_local_boot_epoch(&path, self_id, boot_epoch);
    boot_epoch
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

fn persist_local_boot_epoch(path: &Path, self_id: NodeIdentifier, boot_epoch: u64) {
    if let Some(parent) = path.parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            warn!(?parent, %error, "local boot epoch: cannot create dir");
            return;
        }
    }
    let body = LocalBootEpochFileV1 {
        version: 1,
        node_id: self_id,
        boot_epoch,
    };
    match serde_json::to_vec_pretty(&body) {
        Ok(bytes) => {
            let tmp = path.with_extension("json.tmp");
            if let Err(error) = std::fs::write(&tmp, &bytes) {
                warn!(?tmp, %error, "local boot epoch: write tmp failed");
                return;
            }
            if let Err(error) = std::fs::rename(&tmp, path) {
                warn!(?path, %error, "local boot epoch: rename failed");
            }
        }
        Err(error) => warn!(%error, "local boot epoch: serialize failed"),
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
    pub services: Arc<ServiceRegistry>,
    pub duplicate_detector: Arc<DuplicateDetector>,
    ordering: Arc<OverlayOrdering>,
    pub emitter: Arc<LsaEmitter>,
    pub flood_pacer: Arc<LsaFloodPacer>,
    pub hello: Arc<HelloContext>,
    pub shutdown: CancellationToken,
    pub cfg: OverlayConfig,
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
        let boot_epoch = capture_monotonic_boot_epoch(self_id, cfg.persistence_dir());

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
        let services = Arc::new(ServiceRegistry::new());
        let ordering = Arc::new(OverlayOrdering::new(&cfg));

        let emitter = Arc::new(LsaEmitter::new(
            self_id,
            boot_epoch,
            self_addresses,
            max_users,
            cfg.route_transit_messages(),
            replication_services,
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
            services,
            duplicate_detector,
            ordering,
            emitter,
            flood_pacer,
            hello,
            shutdown,
            cfg,
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
        persist_local_boot_epoch(&path, 7, u64::MAX - 10);

        let boot_epoch = capture_monotonic_boot_epoch(7, Some(&dir.path().to_path_buf()));
        assert_eq!(boot_epoch, u64::MAX - 9);

        let reloaded = std::fs::read(&path).unwrap();
        let file: LocalBootEpochFileV1 = serde_json::from_slice(&reloaded).unwrap();
        assert_eq!(file.node_id, 7);
        assert_eq!(file.boot_epoch, u64::MAX - 9);
    }

    #[test]
    fn monotonic_boot_epoch_uses_node_specific_files() {
        let dir = tempfile::TempDir::new().unwrap();
        persist_local_boot_epoch(&local_boot_epoch_path(dir.path(), 7), 7, u64::MAX - 10);

        let boot_epoch = capture_monotonic_boot_epoch(8, Some(&dir.path().to_path_buf()));
        assert!(local_boot_epoch_path(dir.path(), 8).exists());

        let node7 = std::fs::read(&local_boot_epoch_path(dir.path(), 7)).unwrap();
        let node7: LocalBootEpochFileV1 = serde_json::from_slice(&node7).unwrap();
        assert_eq!(node7.boot_epoch, u64::MAX - 10);

        let node8 = std::fs::read(&local_boot_epoch_path(dir.path(), 8)).unwrap();
        let node8: LocalBootEpochFileV1 = serde_json::from_slice(&node8).unwrap();
        assert_eq!(node8.boot_epoch, boot_epoch);
    }
}
