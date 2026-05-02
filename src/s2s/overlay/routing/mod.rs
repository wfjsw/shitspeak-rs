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

/// One snapshot of all three service-level tables.
#[derive(Default, Clone)]
pub struct RoutingTables {
    pub reliable: HashMap<NodeIdentifier, RouteEntry>,
    pub reliable_low_latency: HashMap<NodeIdentifier, RouteEntry>,
    pub best_effort: HashMap<NodeIdentifier, RouteEntry>,
}

impl RoutingTables {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn for_level(&self, level: ServiceLevel) -> &HashMap<NodeIdentifier, RouteEntry> {
        match level {
            ServiceLevel::Reliable => &self.reliable,
            ServiceLevel::ReliableLowLatency => &self.reliable_low_latency,
            ServiceLevel::BestEffort => &self.best_effort,
        }
    }

    /// Look up the next hop. Falls back to a stricter (more reliable)
    /// level if the requested level has no entry. Order of fallback is
    /// `BestEffort -> RLL -> Reliable`. Never falls back in the looser
    /// direction.
    pub fn lookup(
        &self,
        dst: NodeIdentifier,
        level: ServiceLevel,
    ) -> Option<RouteEntry> {
        if let Some(e) = self.for_level(level).get(&dst) {
            return Some(*e);
        }
        match level {
            ServiceLevel::BestEffort => self
                .reliable_low_latency
                .get(&dst)
                .copied()
                .or_else(|| self.reliable.get(&dst).copied()),
            ServiceLevel::ReliableLowLatency => self.reliable.get(&dst).copied(),
            ServiceLevel::Reliable => None,
        }
    }
}

/// Concrete handle.
pub type RoutingHandle = Arc<ArcSwap<RoutingTables>>;

pub fn new_handle() -> RoutingHandle {
    Arc::new(ArcSwap::new(Arc::new(RoutingTables::empty())))
}
