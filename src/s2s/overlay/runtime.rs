//! `OverlayInner` — shared overlay state and `OverlayNetwork::start`.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::s2s::transport::{ConnectionManager, Inbound};
use crate::types::NodeIdentifier;

use super::config::OverlayConfig;
use super::error::OverlayError;
use super::membership::swim::{
    broadcast_self_status, spawn_reaper, spawn_refuter, spawn_swim_task, PendingAcks, SwimContext,
};
use super::membership::view::MemberStatus;
use super::membership::MembershipTable;

pub(crate) struct OverlayInner {
    pub self_id: NodeIdentifier,
    pub incarnation: u64,
    pub transport: ConnectionManager,
    pub table: Arc<MembershipTable>,
    pub shutdown: CancellationToken,
    pub cfg: OverlayConfig,
    pub swim: Arc<SwimContext>,
}

impl OverlayInner {
    pub fn new(transport: ConnectionManager, cfg: OverlayConfig) -> Self {
        let self_id = transport.local_node_id();
        let incarnation = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);

        let (table, _events_tx) =
            super::membership::new_table(self_id, /*event_capacity=*/ 256);
        let shutdown = CancellationToken::new();
        let pending_acks = Arc::new(PendingAcks::new());
        let refute_signal = Arc::new(Notify::new());

        let swim = Arc::new(SwimContext {
            self_id,
            incarnation: AtomicU64::new(incarnation),
            cfg: cfg.clone(),
            transport: transport.clone(),
            table: table.clone(),
            pending_acks,
            shutdown: shutdown.clone(),
            refute_signal,
            nonce_counter: AtomicU64::new(1),
        });

        Self {
            self_id,
            incarnation,
            transport,
            table,
            shutdown,
            cfg,
            swim,
        }
    }

    /// Spawn every long-running task: SWIM ticker, suspicion reaper,
    /// refute responder, persistence debouncer, and the inbound dispatcher.
    pub fn spawn_tasks(self: &Arc<Self>, inbound: Inbound, persist_trigger: Arc<Notify>) {
        spawn_swim_task(self.swim.clone());
        spawn_reaper(self.swim.clone());
        spawn_refuter(self.swim.clone());
        super::inbound::spawn_dispatcher(self.swim.clone(), inbound);

        if let Some(dir) = self.cfg.persistence_dir().cloned() {
            super::discovery::spawn_persister(
                dir,
                self.cfg.peer_persistence_interval(),
                self.table.clone(),
                persist_trigger,
                self.shutdown.clone(),
            );
        }
    }

    pub async fn shutdown_graceful(&self) {
        // Best-effort: announce LEFT to every alive peer.
        broadcast_self_status(&self.swim, MemberStatus::Left).await;
        self.shutdown.cancel();
    }
}

/// Build the `OverlayInner`, run discovery bootstrap, and spawn all tasks.
pub(crate) async fn start_inner(
    transport: ConnectionManager,
    inbound: Inbound,
    cfg: OverlayConfig,
) -> Result<Arc<OverlayInner>, OverlayError> {
    let inner = Arc::new(OverlayInner::new(transport, cfg));

    super::discovery::bootstrap(&inner.cfg, &inner.table, &inner.transport);

    let persist_trigger = Arc::new(Notify::new());
    inner.spawn_tasks(inbound, persist_trigger);

    Ok(inner)
}
