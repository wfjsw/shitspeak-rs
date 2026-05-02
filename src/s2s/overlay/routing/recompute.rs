//! Debounced routing recompute task.
//!
//! Waits on the LSDB `change_signal`. On wake, sleeps for
//! `cfg.routing_recompute_debounce()` so a flood burst coalesces into
//! one recompute pass, then runs Dijkstra for each `ServiceLevel` and
//! atomically swaps the new tables into an `ArcSwap<RoutingTables>`.

use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio_util::sync::CancellationToken;
use tracing::trace;

use crate::s2s::transport::ServiceLevel;
use crate::types::NodeIdentifier;

use super::super::config::OverlayConfig;
use super::super::lsdb::LinkStateDb;
use super::dijkstra;
use super::RoutingTables;

pub fn spawn_recomputer(
    lsdb: Arc<LinkStateDb>,
    self_id: NodeIdentifier,
    tables: Arc<ArcSwap<RoutingTables>>,
    cfg: OverlayConfig,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        // Compute once at start so the table reflects an empty graph
        // before any LSAs land.
        recompute_now(&lsdb, self_id, &tables, &cfg);

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = lsdb.change_signal().notified() => {}
            }
            // Debounce: drain further notifications during the sleep.
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(cfg.routing_recompute_debounce()) => {}
            }
            recompute_now(&lsdb, self_id, &tables, &cfg);
        }
    });
}

fn recompute_now(
    lsdb: &LinkStateDb,
    self_id: NodeIdentifier,
    tables: &Arc<ArcSwap<RoutingTables>>,
    cfg: &OverlayConfig,
) {
    let reliable = dijkstra::compute(lsdb, self_id, ServiceLevel::Reliable, cfg);
    let rll = dijkstra::compute(lsdb, self_id, ServiceLevel::ReliableLowLatency, cfg);
    let best = dijkstra::compute(lsdb, self_id, ServiceLevel::BestEffort, cfg);
    let new = RoutingTables {
        reliable,
        reliable_low_latency: rll,
        best_effort: best,
    };
    trace!(
        reliable = new.reliable.len(),
        rll = new.reliable_low_latency.len(),
        best_effort = new.best_effort.len(),
        "routing recomputed"
    );
    tables.store(Arc::new(new));
}
