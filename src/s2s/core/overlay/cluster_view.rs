use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::s2s::core::NodeId;

use super::types::ClusterView;

const DEFAULT_ROUTE_COOLDOWN: Duration = Duration::from_millis(500);

#[derive(Debug, Clone)]
struct RouteEntry {
    next_hop: NodeId,
    last_update: Instant,
    next_change_not_before: Instant,
}

impl RouteEntry {
    fn fresh(next_hop: NodeId, cooldown: Duration, now: Instant) -> Self {
        Self {
            next_hop,
            last_update: now,
            next_change_not_before: now + cooldown,
        }
    }
}

#[derive(Debug, Default)]
pub struct SharedClusterView {
    local: NodeId,
    alive_nodes: RwLock<HashSet<NodeId>>,
    next_hops: RwLock<HashMap<NodeId, RouteEntry>>,
    direct_hops: RwLock<HashMap<NodeId, RouteEntry>>,
    route_cooldown: Duration,
}

impl SharedClusterView {
    pub fn new(local: NodeId) -> Self {
        Self::with_route_cooldown(local, DEFAULT_ROUTE_COOLDOWN)
    }

    pub fn with_route_cooldown(local: NodeId, route_cooldown: Duration) -> Self {
        let mut alive = HashSet::new();
        alive.insert(local);
        Self {
            local,
            alive_nodes: RwLock::new(alive),
            next_hops: RwLock::new(HashMap::new()),
            direct_hops: RwLock::new(HashMap::new()),
            route_cooldown,
        }
    }

    pub fn mark_alive(&self, node: NodeId) {
        self.alive_nodes.write().insert(node);
    }

    pub fn mark_dead(&self, node: NodeId) {
        self.alive_nodes.write().remove(&node);
        self.next_hops.write().remove(&node);
        self.direct_hops.write().remove(&node);
    }

    pub fn set_route(&self, dst: NodeId, next_hop: NodeId) -> bool {
        Self::set_route_entry(&self.next_hops, dst, next_hop, self.route_cooldown)
    }

    pub fn set_direct_hop(&self, dst: NodeId, next_hop: NodeId) -> bool {
        Self::set_route_entry(&self.direct_hops, dst, next_hop, self.route_cooldown)
    }

    pub fn evict_stale_routes(&self, stale_after: Duration) -> usize {
        Self::evict_stale(&self.next_hops, stale_after)
            + Self::evict_stale(&self.direct_hops, stale_after)
    }

    fn set_route_entry(
        routes: &RwLock<HashMap<NodeId, RouteEntry>>,
        dst: NodeId,
        next_hop: NodeId,
        cooldown: Duration,
    ) -> bool {
        let now = Instant::now();
        let mut routes = routes.write();
        if let Some(existing) = routes.get_mut(&dst) {
            if existing.next_hop == next_hop {
                existing.last_update = now;
                existing.next_change_not_before = now + cooldown;
                return true;
            }

            if now < existing.next_change_not_before {
                return false;
            }

            *existing = RouteEntry::fresh(next_hop, cooldown, now);
            return true;
        }

        routes.insert(dst, RouteEntry::fresh(next_hop, cooldown, now));
        true
    }

    fn evict_stale(routes: &RwLock<HashMap<NodeId, RouteEntry>>, stale_after: Duration) -> usize {
        let now = Instant::now();
        let mut routes = routes.write();
        let before = routes.len();
        routes.retain(|_, entry| now.saturating_duration_since(entry.last_update) < stale_after);
        before.saturating_sub(routes.len())
    }
}

impl ClusterView for SharedClusterView {
    fn local_node(&self) -> NodeId {
        self.local
    }

    fn alive_nodes_excluding_self(&self) -> Vec<NodeId> {
        self.alive_nodes
            .read()
            .iter()
            .copied()
            .filter(|n| *n != self.local)
            .collect()
    }

    fn resolve_next_hop(&self, dst: NodeId) -> Option<NodeId> {
        if dst == self.local {
            return Some(self.local);
        }
        self.next_hops.read().get(&dst).map(|e| e.next_hop)
    }

    fn resolve_direct_hop(&self, dst: NodeId) -> Option<NodeId> {
        if dst == self.local {
            return Some(self.local);
        }
        self.direct_hops.read().get(&dst).map(|e| e.next_hop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_update_is_rejected_during_cooldown() {
        let view = SharedClusterView::with_route_cooldown(1, Duration::from_millis(80));

        assert!(view.set_route(2, 10));
        assert_eq!(view.resolve_next_hop(2), Some(10));

        assert!(!view.set_route(2, 11));
        assert_eq!(view.resolve_next_hop(2), Some(10));

        std::thread::sleep(Duration::from_millis(100));

        assert!(view.set_route(2, 11));
        assert_eq!(view.resolve_next_hop(2), Some(11));
    }

    #[test]
    fn stale_routes_are_evicted() {
        let view = SharedClusterView::with_route_cooldown(1, Duration::from_millis(10));
        assert!(view.set_route(2, 12));
        assert!(view.set_direct_hop(3, 13));

        std::thread::sleep(Duration::from_millis(20));
        let removed = view.evict_stale_routes(Duration::from_millis(5));

        assert_eq!(removed, 2);
        assert_eq!(view.resolve_next_hop(2), None);
        assert_eq!(view.resolve_direct_hop(3), None);
    }
}
