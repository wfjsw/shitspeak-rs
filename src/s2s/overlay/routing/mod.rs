//! Per-service-level routing tables, computed by Dijkstra over the
//! LSDB graph and swapped atomically via `ArcSwap`.

pub mod dijkstra;
pub mod recompute;

use std::collections::HashMap;

use arc_swap::ArcSwap;
use std::sync::Arc;

use crate::s2s::transport::ServiceLevel;
use crate::types::NodeIdentifier;

pub use dijkstra::RouteEntry;
pub use recompute::spawn_recomputer;

/// Route-selection metric used in addition to [`ServiceLevel`].
///
/// The default preserves the historical per-service cost formulas. Upper
/// layers can request a different metric when the payload has different
/// quality needs, for example conversational voice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RoutingMetric {
    #[default]
    PerServiceCost,
    ConversationalQuality,
}

/// One snapshot of all three service-level tables.
#[derive(Default, Clone)]
pub struct RoutingTables {
    pub reliable: HashMap<NodeIdentifier, RouteEntry>,
    pub reliable_low_latency: HashMap<NodeIdentifier, RouteEntry>,
    pub best_effort: HashMap<NodeIdentifier, RouteEntry>,
    conversational_reliable: HashMap<NodeIdentifier, RouteEntry>,
    conversational_reliable_low_latency: HashMap<NodeIdentifier, RouteEntry>,
    conversational_best_effort: HashMap<NodeIdentifier, RouteEntry>,
}

impl RoutingTables {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn for_level(&self, level: ServiceLevel) -> &HashMap<NodeIdentifier, RouteEntry> {
        self.for_metric_level(RoutingMetric::PerServiceCost, level)
    }

    pub fn for_metric_level(
        &self,
        metric: RoutingMetric,
        level: ServiceLevel,
    ) -> &HashMap<NodeIdentifier, RouteEntry> {
        let tables = match metric {
            RoutingMetric::PerServiceCost => (
                &self.reliable,
                &self.reliable_low_latency,
                &self.best_effort,
            ),
            RoutingMetric::ConversationalQuality => (
                &self.conversational_reliable,
                &self.conversational_reliable_low_latency,
                &self.conversational_best_effort,
            ),
        };
        match level {
            ServiceLevel::Reliable => tables.0,
            ServiceLevel::ReliableLowLatency => tables.1,
            ServiceLevel::BestEffort => tables.2,
        }
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
        self.lookup_with_metric(dst, level, RoutingMetric::PerServiceCost)
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
        let reliable = self.for_metric_level(metric, ServiceLevel::Reliable);
        let reliable_low_latency = self.for_metric_level(metric, ServiceLevel::ReliableLowLatency);
        match level {
            ServiceLevel::BestEffort => reliable
                .get(&dst)
                .copied()
                .or_else(|| reliable_low_latency.get(&dst).copied()),
            ServiceLevel::Reliable => reliable_low_latency.get(&dst).copied(),
            ServiceLevel::ReliableLowLatency => reliable.get(&dst).copied(),
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
        tables.reliable_low_latency.insert(
            2,
            RouteEntry {
                next_hop: 2,
                cost: 10,
            },
        );
        tables.best_effort.insert(
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
