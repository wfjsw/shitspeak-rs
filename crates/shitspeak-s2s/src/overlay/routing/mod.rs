//! Per-service-level routing tables, computed by Dijkstra over the
//! LSDB graph and swapped atomically via `ArcSwap`.

pub mod dijkstra;
pub mod dynamic;
pub mod recompute;

use std::collections::HashMap;

use arc_swap::ArcSwap;
use std::sync::Arc;

use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::ServiceLevel;

pub use dijkstra::RouteEntry;
pub use recompute::spawn_recomputer;
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
}

impl Default for RoutingTables {
    fn default() -> Self {
        let mut tables = HashMap::new();
        for metric in RoutingMetric::ALL {
            for level in ServiceLevel::ALL {
                tables.insert(RoutingTableKey::new(metric, level), HashMap::new());
            }
        }
        Self { tables }
    }
}

impl RoutingTables {
    pub fn empty() -> Self {
        Self::default()
    }

    pub(crate) fn insert_table(
        &mut self,
        metric: RoutingMetric,
        level: ServiceLevel,
        table: HashMap<NodeIdentifier, RouteEntry>,
    ) {
        self.tables
            .insert(RoutingTableKey::new(metric, level), table);
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
