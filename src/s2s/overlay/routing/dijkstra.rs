//! Per-service-level shortest-path computation over the LSDB graph.
//!
//! For each `ServiceLevel`, we run a single-source Dijkstra from the
//! local node. The cost function and the per-edge admission filter
//! depend on the level:
//!
//! * `Reliable`: `rtt_us + cfg.reliable_throughput_penalty_us_kbps /
//!   max(throughput_kbps, 1)`. Edges whose `transports_mask` does not
//!   intersect `cfg.reliable_transports_mask` are dropped.
//! * `ReliableLowLatency`: `rtt_us + cfg.rll_jitter_weight * jitter_us`.
//!   Filtered against `cfg.rll_transports_mask`.
//! * `BestEffort`: `rtt_us`. Filtered against
//!   `cfg.best_effort_transports_mask`.
//!
//! Edges only count if BOTH endpoints have non-tombstone LSAs. This
//! matches LSDB-derived membership: a peer is in the graph iff its LSA
//! is current.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use crate::s2s::transport::ServiceLevel;
use crate::types::NodeIdentifier;

use super::super::config::OverlayConfig;
use super::super::lsdb::{LinkAdvertised, LinkStateDb};

#[derive(Debug, Clone, Copy)]
pub struct RouteEntry {
    pub next_hop: NodeIdentifier,
    pub cost: u64,
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
    let lsas = lsdb.snapshot();
    // Active origin set (non-tombstone).
    let active: HashSet<NodeIdentifier> = lsas
        .iter()
        .filter(|e| !e.tombstone)
        .map(|e| e.origin)
        .collect();
    let transit_disabled: HashSet<NodeIdentifier> = lsas
        .iter()
        .filter(|e| !e.tombstone && e.transit_disabled)
        .map(|e| e.origin)
        .collect();
    if !active.contains(&self_id) {
        // Local LSA hasn't been admitted yet — early return; routing is
        // empty until we publish ourselves.
    }
    // Adjacency: origin -> [(neighbor, cost)] for *admitted* edges.
    let mut adj: HashMap<NodeIdentifier, Vec<(NodeIdentifier, u64)>> = HashMap::new();
    for e in &lsas {
        if e.tombstone {
            continue;
        }
        let mut edges = Vec::new();
        for link in &e.links {
            if !active.contains(&link.neighbor) {
                continue;
            }
            let mask = match level {
                ServiceLevel::Reliable => cfg.reliable_transports_mask(),
                ServiceLevel::ReliableLowLatency => cfg.rll_transports_mask(),
                ServiceLevel::BestEffort => cfg.best_effort_transports_mask(),
            };
            if link.transports_mask & mask == 0 {
                continue;
            }
            let cost = compute_cost(link, level, cfg);
            edges.push((link.neighbor, cost));
        }
        adj.insert(e.origin, edges);
    }

    // Dijkstra from self_id.
    let mut dist: HashMap<NodeIdentifier, u64> = HashMap::new();
    let mut prev: HashMap<NodeIdentifier, NodeIdentifier> = HashMap::new();
    let mut heap: BinaryHeap<Reverse<(u64, NodeIdentifier)>> = BinaryHeap::new();
    dist.insert(self_id, 0);
    heap.push(Reverse((0, self_id)));

    while let Some(Reverse((d, u))) = heap.pop() {
        if d > *dist.get(&u).unwrap_or(&u64::MAX) {
            continue;
        }
        if u != self_id && transit_disabled.contains(&u) {
            continue;
        }
        let Some(neighbors) = adj.get(&u) else {
            continue;
        };
        for (v, w) in neighbors {
            let nd = d.saturating_add(*w);
            if nd < *dist.get(v).unwrap_or(&u64::MAX) {
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
                            cost,
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

fn compute_cost(link: &LinkAdvertised, level: ServiceLevel, cfg: &OverlayConfig) -> u64 {
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
        LsaEntry {
            origin,
            boot_epoch: boot,
            seq,
            ts_local_received: std::time::Instant::now(),
            tombstone: false,
            addresses: vec![],
            links: links
                .into_iter()
                .map(|(n, rtt, jitter, tput)| LinkAdvertised {
                    neighbor: n,
                    rtt_us: rtt,
                    jitter_us: jitter,
                    throughput_bps: tput,
                    transports_mask: super::super::super::config::transport_bit(
                        crate::s2s::transport::TransportKind::Tcp,
                    ),
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
