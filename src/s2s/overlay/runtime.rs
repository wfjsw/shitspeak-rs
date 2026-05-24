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

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::s2s::transport::{ConnectionManager, Inbound, PeerAddress};
use crate::types::NodeIdentifier;

use super::config::OverlayConfig;
use super::error::OverlayError;
use super::lsdb::{
    capture_boot_epoch, emit_once, spawn_anti_entropy, spawn_emitter_task, spawn_floor_persister,
    LinkStateDb, LsaEmitter, LsaFloor,
};
use super::membership::{spawn_diff_watcher, MembershipTable};
use super::messaging::{ordering::OverlayOrdering, ServiceRegistry};
use super::neighbor::hello::{spawn_hello_task, spawn_link_up_watcher, HelloContext};
use super::neighbor::monitor::NeighborMonitor;
use super::routing::{new_handle as new_routing_handle, spawn_recomputer, RoutingHandle};

pub(crate) struct OverlayInner {
    pub self_id: NodeIdentifier,
    pub boot_epoch: u64,
    pub transport: ConnectionManager,
    pub lsdb: Arc<LinkStateDb>,
    pub table: Arc<MembershipTable>,
    pub neighbor: Arc<NeighborMonitor>,
    pub routing: RoutingHandle,
    pub services: Arc<ServiceRegistry>,
    ordering: Arc<OverlayOrdering>,
    pub emitter: Arc<LsaEmitter>,
    pub hello: Arc<HelloContext>,
    pub shutdown: CancellationToken,
    pub cfg: OverlayConfig,
}

impl OverlayInner {
    pub fn new(
        transport: ConnectionManager,
        cfg: OverlayConfig,
        max_users: Arc<AtomicU64>,
        self_addresses: Vec<PeerAddress>,
    ) -> Self {
        let self_id = transport.local_node_id();
        let boot_epoch = capture_boot_epoch();

        let floor = Arc::new(LsaFloor::new(cfg.persistence_dir().cloned()));
        floor.load();
        let lsdb = Arc::new(LinkStateDb::new(floor));

        let (table, events_tx) = super::membership::new_table(self_id, lsdb.clone(), 256);

        let neighbor = Arc::new(NeighborMonitor::new(
            self_id,
            transport.clone(),
            cfg.clone(),
            events_tx,
        ));

        let routing = new_routing_handle();
        let services = Arc::new(ServiceRegistry::new());
        let ordering = Arc::new(OverlayOrdering::new());

        let emitter = Arc::new(LsaEmitter::new(
            self_id,
            boot_epoch,
            self_addresses,
            max_users,
            cfg.route_transit_messages(),
        ));

        let shutdown = CancellationToken::new();
        let hello = Arc::new(HelloContext {
            self_id,
            boot_epoch,
            transport: transport.clone(),
            monitor: neighbor.clone(),
            lsdb: lsdb.clone(),
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
            services,
            ordering,
            emitter,
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

        spawn_hello_task(self.hello.clone());
        spawn_link_up_watcher(self.hello.clone(), self.neighbor.on_link_up());
        spawn_emitter_task(
            self.emitter.clone(),
            self.lsdb.clone(),
            self.neighbor.clone(),
            self.transport.clone(),
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
                                    ordering.reset_peer(node).await;
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
            services: self.services.clone(),
            ordering: self.ordering.clone(),
            transport: self.transport.clone(),
            self_id: self.self_id,
            shutdown: self.shutdown.clone(),
            cfg: self.cfg.clone(),
            emitter: self.emitter.clone(),
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
) -> Result<Arc<OverlayInner>, OverlayError> {
    let self_addresses = transport.listen_addresses_with_public_ip_probe().await;
    let inner = Arc::new(OverlayInner::new(transport, cfg, max_users, self_addresses));

    super::discovery::bootstrap(&inner.cfg, &inner.transport);

    inner.spawn_tasks(inbound);

    Ok(inner)
}
