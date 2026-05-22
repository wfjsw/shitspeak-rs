//! Per-service-level shortest-path computation over the LSDB graph.
//!
//! For each `ServiceLevel`, we run a single-source Dijkstra from the
//! local node. The default cost function and the per-edge admission
//! filter depend on the level:
//!
//! * `Reliable`: `rtt_us + cfg.reliable_throughput_penalty_us_kbps /
//!   max(throughput_kbps, 1)`. Edges whose `transports_mask` does not
//!   intersect `cfg.reliable_transports_mask` are dropped.
//! * `ReliableLowLatency`: `rtt_us + cfg.rll_jitter_weight * jitter_us`.
//!   Filtered against `cfg.rll_transports_mask`.
//! * `BestEffort`: `rtt_us`. Filtered against
//!   `cfg.best_effort_transports_mask`.
//!
//! Upper layers may request a different `RoutingMetric`; voice uses the
//! E-model-inspired conversational metric. Edges only count if BOTH
//! endpoints have non-tombstone LSAs. This matches LSDB-derived
//! membership: a peer is in the graph iff its LSA is current.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use crate::s2s::transport::{
    conversational_effective_delay_us, conversational_impairment, ServiceLevel,
};
use crate::types::NodeIdentifier;

use super::super::config::OverlayConfig;
use super::super::lsdb::{LinkAdvertised, LinkStateDb, LsaEntry};
use super::RoutingMetric;

#[derive(Debug, Clone, Copy)]
pub struct RouteEntry {
    pub next_hop: NodeIdentifier,
    pub cost: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct RoutingGraph {
    active: HashSet<NodeIdentifier>,
    transit_disabled: HashSet<NodeIdentifier>,
    links: HashMap<NodeIdentifier, Vec<LinkAdvertised>>,
}

impl RoutingGraph {
    pub(crate) fn from_lsdb(lsdb: &LinkStateDb) -> Self {
        lsdb.with_entries(|entries| Self::from_entries(entries.values()))
    }

    fn from_entries<'a>(entries: impl IntoIterator<Item = &'a LsaEntry>) -> Self {
        let mut active = HashSet::new();
        let mut transit_disabled = HashSet::new();
        let mut links = HashMap::new();

        for entry in entries {
            if entry.tombstone {
                continue;
            }
            active.insert(entry.origin);
            if entry.transit_disabled {
                transit_disabled.insert(entry.origin);
            }
            links.insert(entry.origin, entry.links.clone());
        }

        Self {
            active,
            transit_disabled,
            links,
        }
    }

    pub(crate) fn active_len(&self) -> usize {
        self.active.len()
    }

    pub(crate) fn is_active(&self, node: NodeIdentifier) -> bool {
        self.active.contains(&node)
    }

    pub(crate) fn active_nodes(&self) -> impl Iterator<Item = NodeIdentifier> + '_ {
        self.active.iter().copied()
    }

    pub(crate) fn links_by_origin(
        &self,
    ) -> impl Iterator<Item = (NodeIdentifier, &[LinkAdvertised])> + '_ {
        self.links
            .iter()
            .map(|(origin, links)| (*origin, links.as_slice()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PathCost {
    primary: u64,
    latency_us: u64,
    hops: u32,
}

impl PathCost {
    const ZERO: Self = Self {
        primary: 0,
        latency_us: 0,
        hops: 0,
    };

    fn add(self, edge: EdgeCost) -> Self {
        Self {
            primary: self.primary.saturating_add(edge.primary),
            latency_us: self.latency_us.saturating_add(edge.latency_us),
            hops: self.hops.saturating_add(1),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct EdgeCost {
    primary: u64,
    latency_us: u64,
}

/// Compute the shortest-path table from `self_id` for `level`.
/// Returns a map `dst -> RouteEntry`. The local node itself is not
/// included.
pub fn compute(
    lsdb: &LinkStateDb,
    self_id: NodeIdentifier,
    level: ServiceLevel,
    cfg: &OverlayConfig,
) -> HashMap<NodeIdentifier, RouteEntry> {
    compute_with_metric(lsdb, self_id, level, RoutingMetric::PerServiceCost, cfg)
}

/// Compute the shortest-path table with an explicit route-selection metric.
pub fn compute_with_metric(
    lsdb: &LinkStateDb,
    self_id: NodeIdentifier,
    level: ServiceLevel,
    metric: RoutingMetric,
    cfg: &OverlayConfig,
) -> HashMap<NodeIdentifier, RouteEntry> {
    let graph = RoutingGraph::from_lsdb(lsdb);
    compute_on_graph(&graph, self_id, level, metric, cfg)
}

pub(crate) fn compute_on_graph(
    graph: &RoutingGraph,
    self_id: NodeIdentifier,
    level: ServiceLevel,
    metric: RoutingMetric,
    cfg: &OverlayConfig,
) -> HashMap<NodeIdentifier, RouteEntry> {
    let mask = match level {
        ServiceLevel::Reliable => cfg.reliable_transports_mask(),
        ServiceLevel::ReliableLowLatency => cfg.rll_transports_mask(),
        ServiceLevel::BestEffort => cfg.best_effort_transports_mask(),
    };

    let mut adj: HashMap<NodeIdentifier, Vec<(NodeIdentifier, EdgeCost)>> = HashMap::new();
    for (origin, links) in graph.links_by_origin() {
        let mut edges = Vec::new();
        for link in links {
            if !graph.is_active(link.neighbor) || link.transports_mask & mask == 0 {
                continue;
            }
            let cost = compute_cost(link, level, metric, cfg);
            edges.push((link.neighbor, cost));
        }
        adj.insert(origin, edges);
    }

    // Dijkstra from self_id.
    let mut dist: HashMap<NodeIdentifier, PathCost> = HashMap::new();
    let mut prev: HashMap<NodeIdentifier, NodeIdentifier> = HashMap::new();
    let mut heap: BinaryHeap<Reverse<(PathCost, NodeIdentifier)>> = BinaryHeap::new();
    dist.insert(self_id, PathCost::ZERO);
    heap.push(Reverse((PathCost::ZERO, self_id)));

    while let Some(Reverse((d, u))) = heap.pop() {
        if dist.get(&u).is_some_and(|known| d > *known) {
            continue;
        }
        if u != self_id && graph.transit_disabled.contains(&u) {
            continue;
        }
        let Some(neighbors) = adj.get(&u) else {
            continue;
        };
        for (v, w) in neighbors {
            let nd = d.add(*w);
            if dist.get(v).map_or(true, |known| nd < *known) {
                dist.insert(*v, nd);
                prev.insert(*v, u);
                heap.push(Reverse((nd, *v)));
            }
        }
    }

    // Walk back to find the next hop for every destination.
    let mut out = HashMap::new();
    for (dst, cost) in dist {
        if dst == self_id {
            continue;
        }
        // Trace back to the immediate successor of `self_id`.
        let mut cur = dst;
        loop {
            match prev.get(&cur) {
                Some(p) if *p == self_id => {
                    out.insert(
                        dst,
                        RouteEntry {
                            next_hop: cur,
                            cost: cost.primary,
                        },
                    );
                    break;
                }
                Some(p) => cur = *p,
                None => break,
            }
        }
    }
    out
}

fn compute_cost(
    link: &LinkAdvertised,
    level: ServiceLevel,
    metric: RoutingMetric,
    cfg: &OverlayConfig,
) -> EdgeCost {
    let primary = match metric {
        RoutingMetric::PerServiceCost => compute_per_service_cost(link, level, cfg),
        RoutingMetric::ConversationalQuality => (conversational_impairment(
            link.rtt_us as f64,
            link.jitter_us as f64,
            link.throughput_bps as f64,
            link.loss_ppm,
        ) * 1_000.0)
            .ceil()
            .max(1.0) as u64,
    };
    let latency_us = match metric {
        RoutingMetric::PerServiceCost => link.rtt_us.max(1),
        RoutingMetric::ConversationalQuality => {
            conversational_effective_delay_us(link.rtt_us as f64, link.jitter_us as f64).max(1)
        }
    };
    EdgeCost {
        primary: primary.max(1),
        latency_us,
    }
}

fn compute_per_service_cost(
    link: &LinkAdvertised,
    level: ServiceLevel,
    cfg: &OverlayConfig,
) -> u64 {
    match level {
        ServiceLevel::BestEffort => link.rtt_us.max(1),
        ServiceLevel::ReliableLowLatency => {
            let weighted_jitter = (cfg.rll_jitter_weight() * link.jitter_us as f64) as u64;
            (link.rtt_us + weighted_jitter).max(1)
        }
        ServiceLevel::Reliable => {
            let throughput_kbps = (link.throughput_bps as f64 / 1024.0).max(1.0);
            let penalty = (cfg.reliable_throughput_penalty_us_kbps() / throughput_kbps) as u64;
            (link.rtt_us + penalty).max(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use super::super::super::lsdb::{LsaEntry, LsaFloor};

    fn cfg() -> OverlayConfig {
        OverlayConfig::new(vec![])
    }

    fn entry(
        origin: NodeIdentifier,
        boot: u64,
        seq: u64,
        links: Vec<(NodeIdentifier, u64, u64, u64)>,
    ) -> LsaEntry {
        entry_with_loss(
            origin,
            boot,
            seq,
            links
                .into_iter()
                .map(|(n, rtt, jitter, tput)| (n, rtt, jitter, tput, 0))
                .collect(),
        )
    }

    fn entry_with_loss(
        origin: NodeIdentifier,
        boot: u64,
        seq: u64,
        links: Vec<(NodeIdentifier, u64, u64, u64, u32)>,
    ) -> LsaEntry {
        LsaEntry {
            origin,
            boot_epoch: boot,
            seq,
            ts_local_received: std::time::Instant::now(),
            tombstone: false,
            addresses: vec![],
            links: links
                .into_iter()
                .map(|(n, rtt, jitter, tput, loss_ppm)| LinkAdvertised {
                    neighbor: n,
                    rtt_us: rtt,
                    jitter_us: jitter,
                    throughput_bps: tput,
                    transports_mask: super::super::super::config::transport_bit(
                        crate::s2s::transport::TransportKind::Tcp,
                    ),
                    loss_ppm,
                })
                .collect(),
            max_users: 0,
            transit_disabled: false,
        }
    }

    fn build_db(lsas: Vec<LsaEntry>) -> LinkStateDb {
        let floor = Arc::new(LsaFloor::new(None));
        let db = LinkStateDb::new(floor);
        for l in lsas {
            db.admit(l);
        }
        db
    }

    #[test]
    fn line_topology_routes() {
        // 1 -> 2 -> 3
        let db = build_db(vec![
            entry(1, 100, 1, vec![(2, 5_000, 100, 1_000_000)]),
            entry(
                2,
                100,
                1,
                vec![(1, 5_000, 100, 1_000_000), (3, 4_000, 100, 1_000_000)],
            ),
            entry(3, 100, 1, vec![(2, 4_000, 100, 1_000_000)]),
        ]);
        let table = compute(&db, 1, ServiceLevel::ReliableLowLatency, &cfg());
        assert_eq!(table[&2].next_hop, 2);
        assert_eq!(table[&3].next_hop, 2); // via 2
        assert!(table[&3].cost > table[&2].cost);
    }

    #[test]
    fn picks_lower_cost_path() {
        // 1—2 (rtt=10ms), 1—3 (rtt=2ms), 3—2 (rtt=2ms).
        // Direct 1->2 costs 10ms; via 3: 2+2=4ms. So next_hop(2) = 3.
        let db = build_db(vec![
            entry(
                1,
                100,
                1,
                vec![(2, 10_000, 0, 1_000_000), (3, 2_000, 0, 1_000_000)],
            ),
            entry(
                2,
                100,
                1,
                vec![(1, 10_000, 0, 1_000_000), (3, 2_000, 0, 1_000_000)],
            ),
            entry(
                3,
                100,
                1,
                vec![(1, 2_000, 0, 1_000_000), (2, 2_000, 0, 1_000_000)],
            ),
        ]);
        let table = compute(&db, 1, ServiceLevel::ReliableLowLatency, &cfg());
        assert_eq!(table[&2].next_hop, 3);
        assert_eq!(table[&3].next_hop, 3);
    }

    #[test]
    fn conversational_metric_avoids_lossy_low_latency_path() {
        // Default best-effort still picks the lower per-service RTT path
        // through node 3. Conversational routing prefers the direct path
        // because the low-RTT transit edges advertise heavy loss.
        let db = build_db(vec![
            entry_with_loss(
                1,
                100,
                1,
                vec![
                    (2, 10_000, 0, 1_000_000, 0),
                    (3, 2_000, 0, 1_000_000, 250_000),
                ],
            ),
            entry_with_loss(
                2,
                100,
                1,
                vec![
                    (1, 10_000, 0, 1_000_000, 0),
                    (3, 2_000, 0, 1_000_000, 250_000),
                ],
            ),
            entry_with_loss(
                3,
                100,
                1,
                vec![
                    (1, 2_000, 0, 1_000_000, 250_000),
                    (2, 2_000, 0, 1_000_000, 250_000),
                ],
            ),
        ]);

        let default = compute(&db, 1, ServiceLevel::BestEffort, &cfg());
        assert_eq!(default[&2].next_hop, 3);

        let conversational = compute_with_metric(
            &db,
            1,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            &cfg(),
        );
        assert_eq!(conversational[&2].next_hop, 2);
    }

    #[test]
    fn non_transit_origin_can_be_destination_but_not_intermediate() {
        let mut node2 = entry(
            2,
            100,
            1,
            vec![(1, 5_000, 0, 1_000_000), (3, 5_000, 0, 1_000_000)],
        );
        node2.transit_disabled = true;
        let db = build_db(vec![
            entry(1, 100, 1, vec![(2, 5_000, 0, 1_000_000)]),
            node2,
            entry(3, 100, 1, vec![(2, 5_000, 0, 1_000_000)]),
        ]);
        let table = compute(&db, 1, ServiceLevel::ReliableLowLatency, &cfg());
        assert_eq!(table[&2].next_hop, 2);
        assert!(!table.contains_key(&3));
    }

    #[test]
    fn tombstone_origin_drops_from_graph() {
        let mut e2_dead = entry(2, 100, 5, vec![]);
        e2_dead.tombstone = true;
        let db = build_db(vec![
            entry(1, 100, 1, vec![(2, 5_000, 0, 1_000_000)]),
            e2_dead,
        ]);
        let table = compute(&db, 1, ServiceLevel::ReliableLowLatency, &cfg());
        assert!(!table.contains_key(&2));
    }

    #[test]
    fn empty_graph_returns_empty_table() {
        let floor = Arc::new(LsaFloor::new(None));
        let db = LinkStateDb::new(floor);
        let table = compute(&db, 1, ServiceLevel::Reliable, &cfg());
        assert!(table.is_empty());
    }
}
