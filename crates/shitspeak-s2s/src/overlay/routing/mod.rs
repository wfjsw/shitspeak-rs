//! Per-service-level routing tables, computed by Dijkstra over the
//! LSDB graph and swapped atomically via `ArcSwap`.

pub mod dijkstra;
pub mod dynamic;
pub mod recompute;

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use arc_swap::ArcSwap;
use std::sync::Arc;

use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::ServiceLevel;

use self::dijkstra::{EdgeCost, PathCost, RoutingGraph};
use super::config::OverlayConfig;

pub use self::dijkstra::RouteEntry;
pub use self::recompute::spawn_recomputer;
pub use shitspeak_s2s_transport::RoutingMetric;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RoutingTableKey {
    metric: RoutingMetric,
    level: ServiceLevel,
}

impl RoutingTableKey {
    fn new(metric: RoutingMetric, level: ServiceLevel) -> Self {
        Self { metric, level }
    }
}

/// One snapshot of the service-level tables for every routing metric.
#[derive(Clone)]
pub struct RoutingTables {
    tables: HashMap<RoutingTableKey, HashMap<NodeIdentifier, RouteEntry>>,
    adjacency: HashMap<RoutingTableKey, HashMap<NodeIdentifier, Vec<(NodeIdentifier, EdgeCost)>>>,
    transit_disabled: HashSet<NodeIdentifier>,
}

impl Default for RoutingTables {
    fn default() -> Self {
        let mut tables = HashMap::new();
        let mut adjacency = HashMap::new();
        for metric in RoutingMetric::ALL {
            for level in ServiceLevel::ALL {
                let key = RoutingTableKey::new(metric, level);
                tables.insert(key, HashMap::new());
                adjacency.insert(key, HashMap::new());
            }
        }
        Self {
            tables,
            adjacency,
            transit_disabled: HashSet::new(),
        }
    }
}

impl RoutingTables {
    pub fn empty() -> Self {
        Self::default()
    }

    pub(crate) fn from_graph(
        graph: &RoutingGraph,
        self_id: NodeIdentifier,
        cfg: &OverlayConfig,
    ) -> Self {
        let mut out = Self::empty();
        out.set_transit_disabled_from_graph(graph);
        for metric in RoutingMetric::ALL {
            for level in ServiceLevel::ALL {
                let table = dijkstra::compute_on_graph(graph, self_id, level, metric, cfg);
                let adjacency = dijkstra::adjacency_for(graph, level, metric, cfg);
                out.insert_table_with_adjacency(metric, level, table, adjacency);
            }
        }
        out
    }

    #[cfg(test)]
    pub(crate) fn insert_table(
        &mut self,
        metric: RoutingMetric,
        level: ServiceLevel,
        table: HashMap<NodeIdentifier, RouteEntry>,
    ) {
        self.tables
            .insert(RoutingTableKey::new(metric, level), table);
    }

    pub(crate) fn insert_table_with_adjacency(
        &mut self,
        metric: RoutingMetric,
        level: ServiceLevel,
        table: HashMap<NodeIdentifier, RouteEntry>,
        adjacency: HashMap<NodeIdentifier, Vec<(NodeIdentifier, EdgeCost)>>,
    ) {
        let key = RoutingTableKey::new(metric, level);
        self.tables.insert(key, table);
        self.adjacency.insert(key, adjacency);
    }

    pub(crate) fn set_transit_disabled_from_graph(&mut self, graph: &RoutingGraph) {
        self.transit_disabled = graph
            .active_nodes()
            .filter(|node| graph.transit_disabled(*node))
            .collect();
    }

    pub fn for_level(&self, level: ServiceLevel) -> &HashMap<NodeIdentifier, RouteEntry> {
        self.for_metric_level(RoutingMetric::default_for_level(level), level)
    }

    pub fn for_metric_level(
        &self,
        metric: RoutingMetric,
        level: ServiceLevel,
    ) -> &HashMap<NodeIdentifier, RouteEntry> {
        self.tables
            .get(&RoutingTableKey::new(metric, level))
            .expect("routing table key initialized")
    }

    /// Look up the next hop. Falls back to whichever other level can
    /// satisfy the request without losing the *reliability* property:
    ///
    /// * `BestEffort` → fall back to `Reliable`, then `ReliableLowLatency`.
    ///   (Either is strictly better.)
    /// * `Reliable` → fall back to `ReliableLowLatency` (KCP/QUIC are
    ///   reliable too). NEVER falls back to `BestEffort` — that would
    ///   silently downgrade a reliable request to one that may drop.
    /// * `ReliableLowLatency` → fall back to `Reliable` (plain TCP).
    ///   Loses the low-latency guarantee but preserves reliability.
    ///   Operators who deploy KCP/QUIC alongside TCP get the latency
    ///   benefit; clusters without KCP/QUIC still get their RLL traffic
    ///   delivered.
    pub fn lookup(&self, dst: NodeIdentifier, level: ServiceLevel) -> Option<RouteEntry> {
        self.lookup_default(dst, level)
    }

    fn lookup_default(&self, dst: NodeIdentifier, level: ServiceLevel) -> Option<RouteEntry> {
        if let Some(e) = self
            .for_metric_level(RoutingMetric::default_for_level(level), level)
            .get(&dst)
        {
            return Some(*e);
        }
        match level {
            ServiceLevel::BestEffort => self
                .for_metric_level(
                    RoutingMetric::default_for_level(ServiceLevel::Reliable),
                    ServiceLevel::Reliable,
                )
                .get(&dst)
                .copied()
                .or_else(|| {
                    self.for_metric_level(
                        RoutingMetric::default_for_level(ServiceLevel::ReliableLowLatency),
                        ServiceLevel::ReliableLowLatency,
                    )
                    .get(&dst)
                    .copied()
                }),
            ServiceLevel::Reliable => self
                .for_metric_level(
                    RoutingMetric::default_for_level(ServiceLevel::ReliableLowLatency),
                    ServiceLevel::ReliableLowLatency,
                )
                .get(&dst)
                .copied(),
            ServiceLevel::ReliableLowLatency => self
                .for_metric_level(
                    RoutingMetric::default_for_level(ServiceLevel::Reliable),
                    ServiceLevel::Reliable,
                )
                .get(&dst)
                .copied(),
        }
    }

    pub fn lookup_with_metric(
        &self,
        dst: NodeIdentifier,
        level: ServiceLevel,
        metric: RoutingMetric,
    ) -> Option<RouteEntry> {
        if let Some(e) = self.for_metric_level(metric, level).get(&dst) {
            return Some(*e);
        }
        match level {
            ServiceLevel::BestEffort => self
                .for_metric_level(metric, ServiceLevel::Reliable)
                .get(&dst)
                .copied()
                .or_else(|| {
                    self.for_metric_level(metric, ServiceLevel::ReliableLowLatency)
                        .get(&dst)
                        .copied()
                }),
            ServiceLevel::Reliable => self
                .for_metric_level(metric, ServiceLevel::ReliableLowLatency)
                .get(&dst)
                .copied(),
            ServiceLevel::ReliableLowLatency => self
                .for_metric_level(metric, ServiceLevel::Reliable)
                .get(&dst)
                .copied(),
        }
    }

    pub(crate) fn lookup_path_aware_with_metric(
        &self,
        self_id: NodeIdentifier,
        dst: NodeIdentifier,
        level: ServiceLevel,
        metric: RoutingMetric,
        path_trace: &HashSet<NodeIdentifier>,
    ) -> Option<RouteEntry> {
        if dst == self_id || path_trace.contains(&dst) {
            return None;
        }
        for key in Self::metric_lookup_keys(metric, level).iter().flatten() {
            if let Some(entry) = self.lookup_path_aware_for_key(self_id, dst, key, path_trace, None)
            {
                return Some(entry);
            }
        }
        None
    }

    pub(crate) fn lookup_avoiding_first_hop_with_metric(
        &self,
        self_id: NodeIdentifier,
        dst: NodeIdentifier,
        level: ServiceLevel,
        metric: RoutingMetric,
        path_trace: &HashSet<NodeIdentifier>,
        avoid_next_hop: NodeIdentifier,
    ) -> Option<RouteEntry> {
        if dst == self_id || path_trace.contains(&dst) {
            return None;
        }
        for key in Self::metric_lookup_keys(metric, level).iter().flatten() {
            if let Some(entry) =
                self.lookup_path_aware_for_key(self_id, dst, key, path_trace, Some(avoid_next_hop))
            {
                return Some(entry);
            }
        }
        None
    }

    fn metric_lookup_keys(
        metric: RoutingMetric,
        level: ServiceLevel,
    ) -> [Option<RoutingTableKey>; 3] {
        match level {
            ServiceLevel::BestEffort => [
                Some(RoutingTableKey::new(metric, ServiceLevel::BestEffort)),
                Some(RoutingTableKey::new(metric, ServiceLevel::Reliable)),
                Some(RoutingTableKey::new(
                    metric,
                    ServiceLevel::ReliableLowLatency,
                )),
            ],
            ServiceLevel::Reliable => [
                Some(RoutingTableKey::new(metric, ServiceLevel::Reliable)),
                Some(RoutingTableKey::new(
                    metric,
                    ServiceLevel::ReliableLowLatency,
                )),
                None,
            ],
            ServiceLevel::ReliableLowLatency => [
                Some(RoutingTableKey::new(
                    metric,
                    ServiceLevel::ReliableLowLatency,
                )),
                Some(RoutingTableKey::new(metric, ServiceLevel::Reliable)),
                None,
            ],
        }
    }

    fn lookup_path_aware_for_key(
        &self,
        self_id: NodeIdentifier,
        dst: NodeIdentifier,
        key: &RoutingTableKey,
        path_trace: &HashSet<NodeIdentifier>,
        avoid_first_hop: Option<NodeIdentifier>,
    ) -> Option<RouteEntry> {
        let adjacency = self.adjacency.get(key)?;
        if adjacency.is_empty() {
            return None;
        }

        let mut dist: HashMap<NodeIdentifier, PathCost> = HashMap::new();
        let mut prev: HashMap<NodeIdentifier, NodeIdentifier> = HashMap::new();
        let mut heap: BinaryHeap<Reverse<(PathCost, NodeIdentifier)>> = BinaryHeap::new();
        dist.insert(self_id, PathCost::ZERO);
        heap.push(Reverse((PathCost::ZERO, self_id)));

        while let Some(Reverse((cost, node))) = heap.pop() {
            if dist.get(&node).is_some_and(|known| cost > *known) {
                continue;
            }
            if node == dst {
                break;
            }
            if node != self_id && self.transit_disabled.contains(&node) {
                continue;
            }
            let Some(edges) = adjacency.get(&node) else {
                continue;
            };
            for (neighbor, edge_cost) in edges {
                if node == self_id && avoid_first_hop == Some(*neighbor) {
                    continue;
                }
                if *neighbor == self_id || path_trace.contains(neighbor) {
                    continue;
                }
                let next_cost = cost.add(*edge_cost);
                if dist.get(neighbor).map_or(true, |known| next_cost < *known) {
                    dist.insert(*neighbor, next_cost);
                    prev.insert(*neighbor, node);
                    heap.push(Reverse((next_cost, *neighbor)));
                }
            }
        }

        let cost = dist.get(&dst)?;
        let mut cur = dst;
        loop {
            match prev.get(&cur) {
                Some(parent) if *parent == self_id => {
                    return Some(RouteEntry {
                        next_hop: cur,
                        cost: cost.primary,
                        latency_us: cost.latency_us,
                    });
                }
                Some(parent) => cur = *parent,
                None => return None,
            }
        }
    }

    pub fn has_route(&self, dst: NodeIdentifier, level: ServiceLevel) -> bool {
        self.lookup(dst, level).is_some()
    }

    pub fn has_route_with_metric(
        &self,
        dst: NodeIdentifier,
        level: ServiceLevel,
        metric: RoutingMetric,
    ) -> bool {
        self.lookup_with_metric(dst, level, metric).is_some()
    }
}

/// Concrete handle.
pub type RoutingHandle = Arc<ArcSwap<RoutingTables>>;

pub fn new_handle() -> RoutingHandle {
    Arc::new(ArcSwap::new(Arc::new(RoutingTables::empty())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_route_uses_service_level_fallback_rules() {
        let mut tables = RoutingTables::empty();
        tables
            .tables
            .get_mut(&RoutingTableKey::new(
                RoutingMetric::ReliableLowLatencyCost,
                ServiceLevel::ReliableLowLatency,
            ))
            .unwrap()
            .insert(
                2,
                RouteEntry {
                    next_hop: 2,
                    cost: 10,
                    latency_us: 10,
                },
            );
        tables
            .tables
            .get_mut(&RoutingTableKey::new(
                RoutingMetric::BestEffortCost,
                ServiceLevel::BestEffort,
            ))
            .unwrap()
            .insert(
                3,
                RouteEntry {
                    next_hop: 3,
                    cost: 1,
                    latency_us: 1,
                },
            );

        assert!(tables.has_route(2, ServiceLevel::ReliableLowLatency));
        assert!(tables.has_route(2, ServiceLevel::Reliable));
        assert!(tables.has_route(2, ServiceLevel::BestEffort));
        assert!(!tables.has_route(3, ServiceLevel::Reliable));
        assert!(tables.has_route(3, ServiceLevel::BestEffort));
        assert!(!tables.has_route(4, ServiceLevel::Reliable));
    }
}
