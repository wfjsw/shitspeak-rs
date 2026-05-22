//! Debounced routing recompute task.
//!
//! Waits on the LSDB `change_signal`. On wake, sleeps for
//! `cfg.routing_recompute_debounce()` so a flood burst coalesces into
//! one recompute pass, then runs Dijkstra for each `ServiceLevel` and
//! atomically swaps the new tables into an `ArcSwap<RoutingTables>`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio_util::sync::CancellationToken;
use tracing::trace;

use crate::s2s::transport::{ConnectionManager, ServiceLevel};
use crate::types::NodeIdentifier;

use super::super::config::OverlayConfig;
use super::super::lsdb::LinkStateDb;
use super::dijkstra;
use super::{RoutingMetric, RoutingTables};

pub fn spawn_recomputer(
    lsdb: Arc<LinkStateDb>,
    self_id: NodeIdentifier,
    tables: Arc<ArcSwap<RoutingTables>>,
    transport: ConnectionManager,
    cfg: OverlayConfig,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        // Compute once at start so the table reflects an empty graph
        // before any LSAs land.
        recompute_now(&lsdb, self_id, &tables, &transport, &cfg);

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
            recompute_now(&lsdb, self_id, &tables, &transport, &cfg);
        }
    });
}

fn recompute_now(
    lsdb: &LinkStateDb,
    self_id: NodeIdentifier,
    tables: &Arc<ArcSwap<RoutingTables>>,
    transport: &ConnectionManager,
    cfg: &OverlayConfig,
) {
    let graph = dijkstra::RoutingGraph::from_lsdb(lsdb);
    transport.set_required_outgoing_nodes(component_bridge_targets(&graph, self_id));

    let reliable = dijkstra::compute_on_graph(
        &graph,
        self_id,
        ServiceLevel::Reliable,
        RoutingMetric::PerServiceCost,
        cfg,
    );
    let rll = dijkstra::compute_on_graph(
        &graph,
        self_id,
        ServiceLevel::ReliableLowLatency,
        RoutingMetric::PerServiceCost,
        cfg,
    );
    let best = dijkstra::compute_on_graph(
        &graph,
        self_id,
        ServiceLevel::BestEffort,
        RoutingMetric::PerServiceCost,
        cfg,
    );
    let conversational_reliable = dijkstra::compute_on_graph(
        &graph,
        self_id,
        ServiceLevel::Reliable,
        RoutingMetric::ConversationalQuality,
        cfg,
    );
    let conversational_rll = dijkstra::compute_on_graph(
        &graph,
        self_id,
        ServiceLevel::ReliableLowLatency,
        RoutingMetric::ConversationalQuality,
        cfg,
    );
    let conversational_best = dijkstra::compute_on_graph(
        &graph,
        self_id,
        ServiceLevel::BestEffort,
        RoutingMetric::ConversationalQuality,
        cfg,
    );
    let new = RoutingTables {
        reliable,
        reliable_low_latency: rll,
        best_effort: best,
        conversational_reliable,
        conversational_reliable_low_latency: conversational_rll,
        conversational_best_effort: conversational_best,
    };
    trace!(
        reliable = new.reliable.len(),
        rll = new.reliable_low_latency.len(),
        best_effort = new.best_effort.len(),
        "routing recomputed"
    );
    tables.store(Arc::new(new));
}

fn component_bridge_targets(
    graph_view: &dijkstra::RoutingGraph,
    self_id: NodeIdentifier,
) -> HashSet<NodeIdentifier> {
    if graph_view.active_len() <= 1 || !graph_view.is_active(self_id) {
        return HashSet::new();
    }

    let mut graph: HashMap<NodeIdentifier, Vec<NodeIdentifier>> = HashMap::new();
    for node in graph_view.active_nodes() {
        graph.entry(node).or_default();
    }
    for (origin, links) in graph_view.links_by_origin() {
        for link in links {
            if !graph_view.is_active(link.neighbor) {
                continue;
            }
            graph.entry(origin).or_default().push(link.neighbor);
            graph.entry(link.neighbor).or_default().push(origin);
        }
    }

    let mut seen = HashSet::new();
    let mut components: Vec<Vec<NodeIdentifier>> = Vec::new();
    for start in graph_view.active_nodes() {
        if !seen.insert(start) {
            continue;
        }
        let mut component = Vec::new();
        let mut queue = VecDeque::from([start]);
        while let Some(node) = queue.pop_front() {
            component.push(node);
            if let Some(neighbors) = graph.get(&node) {
                for neighbor in neighbors {
                    if seen.insert(*neighbor) {
                        queue.push_back(*neighbor);
                    }
                }
            }
        }
        component.sort_unstable();
        components.push(component);
    }

    let local_component = components
        .iter()
        .position(|component| component.binary_search(&self_id).is_ok());
    let mut targets = HashSet::new();
    for (idx, component) in components.iter().enumerate() {
        if Some(idx) == local_component {
            continue;
        }
        if let Some(representative) = component.first() {
            targets.insert(*representative);
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::super::config::transport_bit;
    use super::super::super::lsdb::{LinkAdvertised, LsaEntry, LsaFloor};
    use crate::s2s::transport::TransportKind;

    fn entry(origin: NodeIdentifier, links: Vec<NodeIdentifier>) -> LsaEntry {
        LsaEntry {
            origin,
            boot_epoch: 1,
            seq: 1,
            ts_local_received: std::time::Instant::now(),
            tombstone: false,
            addresses: vec![],
            links: links
                .into_iter()
                .map(|neighbor| LinkAdvertised {
                    neighbor,
                    rtt_us: 1_000,
                    jitter_us: 0,
                    throughput_bps: 1_000_000,
                    transports_mask: transport_bit(TransportKind::Tcp),
                    loss_ppm: 0,
                })
                .collect(),
            max_users: 0,
            transit_disabled: false,
        }
    }

    fn build_db(entries: Vec<LsaEntry>) -> LinkStateDb {
        let db = LinkStateDb::new(Arc::new(LsaFloor::new(None)));
        for entry in entries {
            db.admit(entry);
        }
        db
    }

    #[test]
    fn component_bridge_targets_pick_foreign_component_representatives() {
        let db = build_db(vec![
            entry(1, vec![2]),
            entry(2, vec![1]),
            entry(3, vec![4]),
            entry(4, vec![3]),
            entry(5, vec![]),
        ]);

        let graph = dijkstra::RoutingGraph::from_lsdb(&db);
        let targets = component_bridge_targets(&graph, 1);
        assert_eq!(targets, HashSet::from([3, 5]));
    }

    #[test]
    fn component_bridge_targets_empty_when_graph_connected() {
        let db = build_db(vec![
            entry(1, vec![2]),
            entry(2, vec![1, 3]),
            entry(3, vec![2]),
        ]);

        let graph = dijkstra::RoutingGraph::from_lsdb(&db);
        assert!(component_bridge_targets(&graph, 1).is_empty());
    }
}
