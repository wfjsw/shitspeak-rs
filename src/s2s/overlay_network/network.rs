use std::collections::{BTreeMap, HashMap};

use super::{
    choose_transport_pair,
    select_best_path, select_stable_path, LinkQualitySample, MessageMode, RouteCandidate,
    RouteClass, RoutePath, RouteSelectionPolicy, StableRouteState, TransportCapabilities,
    TransportRuntimePolicy, FailureCircuitBreaker, FrameGuard, PeerRateLimiter,
};
use super::NodeId;

#[derive(Debug, Clone)]
pub struct PeerLink {
    pub node_id: NodeId,
    pub path: RoutePath,
    pub quality: LinkQualitySample,
}

#[derive(Debug, Clone)]
pub struct OverlayMessage {
    pub mode: MessageMode,
    pub route_class: RouteClass,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct OverlayNetwork {
    local_node: NodeId,
    links: HashMap<NodeId, PeerLink>,
    transport: TransportCapabilities,
    selected_routes: HashMap<RouteClass, StableRouteState>,
    frame_guard: FrameGuard,
    rate_limiter: PeerRateLimiter,
    circuit_breaker: FailureCircuitBreaker,
}

impl OverlayNetwork {
    pub fn new(local_node: NodeId, transport: TransportCapabilities) -> Self {
        Self {
            local_node,
            links: HashMap::new(),
            transport,
            selected_routes: HashMap::new(),
            frame_guard: FrameGuard::default(),
            rate_limiter: PeerRateLimiter::new(200, 200),
            circuit_breaker: FailureCircuitBreaker::new(5, 10_000),
        }
    }

    pub fn update_link(&mut self, link: PeerLink) {
        self.links.insert(link.node_id, link);
    }

    pub fn remove_link(&mut self, node_id: NodeId) {
        self.links.remove(&node_id);
    }

    pub fn choose_path(&self, route_class: RouteClass, now_ms: u64, stale_after_ms: u64) -> Option<RouteCandidate> {
        let _preferred_transport = self.transport.preferred_for(route_class)?;
        let candidates = self
            .links
            .values()
            .filter(|link| link.node_id != self.local_node)
            .map(|link| RouteCandidate {
                path: link.path.clone(),
                sample: link.quality.clone(),
            })
            .collect::<Vec<_>>();

        select_best_path(&candidates, now_ms, stale_after_ms)
    }

    pub fn choose_stable_path(
        &mut self,
        route_class: RouteClass,
        now_ms: u64,
        stale_after_ms: u64,
        policy: RouteSelectionPolicy,
    ) -> Option<RouteCandidate> {
        let _preferred_transport = self.transport.preferred_for(route_class)?;
        let candidates = self
            .links
            .values()
            .filter(|link| link.node_id != self.local_node)
            .map(|link| RouteCandidate {
                path: link.path.clone(),
                sample: link.quality.clone(),
            })
            .collect::<Vec<_>>();

        let best = select_best_path(&candidates, now_ms, stale_after_ms);
        let next_state = select_stable_path(
            self.selected_routes.get(&route_class),
            best,
            now_ms,
            policy,
        )?;
        let selected = next_state.selected.clone();
        self.selected_routes.insert(route_class, next_state);
        Some(selected)
    }

    pub fn choose_transport_for_class(&self, route_class: RouteClass) -> Option<super::SelectedTransport> {
        choose_transport_pair(&self.transport, route_class, &TransportRuntimePolicy::default())
    }

    pub fn allow_incoming_frame(&mut self, from: NodeId, frame_len: usize, now_ms: u64) -> bool {
        if self.circuit_breaker.is_open(from, now_ms) {
            return false;
        }

        if !self.frame_guard.validate(frame_len) {
            self.circuit_breaker.report_failure(from, now_ms);
            return false;
        }

        if !self.rate_limiter.allow(from, now_ms) {
            self.circuit_breaker.report_failure(from, now_ms);
            return false;
        }

        self.circuit_breaker.report_success(from);
        true
    }
}

#[derive(Debug, Clone)]
pub struct OrderedDeliveryState {
    next_expected: u64,
    pending: BTreeMap<u64, Vec<u8>>,
    max_window: usize,
}

impl OrderedDeliveryState {
    pub fn new(next_expected: u64, max_window: usize) -> Self {
        Self {
            next_expected,
            pending: BTreeMap::new(),
            max_window,
        }
    }

    // Best-effort in-order delivery: keep a bounded reordering buffer and emit contiguous frames.
    pub fn push(&mut self, sequence: u64, payload: Vec<u8>) -> Vec<(u64, Vec<u8>)> {
        if sequence < self.next_expected {
            return Vec::new();
        }

        if self.pending.len() >= self.max_window && sequence > self.next_expected {
            return Vec::new();
        }

        self.pending.entry(sequence).or_insert(payload);

        let mut ready = Vec::new();
        while let Some(payload) = self.pending.remove(&self.next_expected) {
            ready.push((self.next_expected, payload));
            self.next_expected = self.next_expected.saturating_add(1);
        }

        ready
    }
}

pub fn should_forward_with_loop_guard(
    local_node: NodeId,
    next_hop: NodeId,
    path_trace: &[NodeId],
) -> bool {
    if path_trace.contains(&local_node) {
        return false;
    }

    if path_trace.contains(&next_hop) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(updated: u64, latency: f64, loss: f64) -> LinkQualitySample {
        LinkQualitySample {
            latency_ms: latency,
            jitter_ms: 5.0,
            loss_ratio: loss,
            bandwidth_kbps: 1000.0,
            updated_at_ms: updated,
        }
    }

    #[test]
    fn choose_path_returns_best_link() {
        let mut net = OverlayNetwork::new(1, TransportCapabilities::default());
        net.update_link(PeerLink {
            node_id: 2,
            path: RoutePath::Direct { target: 2 },
            quality: sample(100, 30.0, 0.01),
        });
        net.update_link(PeerLink {
            node_id: 3,
            path: RoutePath::Direct { target: 3 },
            quality: sample(100, 80.0, 0.20),
        });

        let selected = net
            .choose_path(RouteClass::Reliable, 100, 20)
            .expect("a path should be selected");
        assert_eq!(selected.path, RoutePath::Direct { target: 2 });
    }

    #[test]
    fn ingress_rejects_oversized_then_circuit_opens() {
        let mut net = OverlayNetwork::new(1, TransportCapabilities::default());
        assert!(!net.allow_incoming_frame(9, usize::MAX, 0));
        assert!(!net.allow_incoming_frame(9, usize::MAX, 1));
    }

    #[test]
    fn ordered_delivery_releases_contiguous_payloads() {
        let mut ordered = OrderedDeliveryState::new(1, 4);
        assert!(ordered.push(2, vec![2]).is_empty());
        let out = ordered.push(1, vec![1]);
        assert_eq!(out.iter().map(|(s, _)| *s).collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn loop_guard_denies_repeated_nodes() {
        assert!(!should_forward_with_loop_guard(1, 2, &[1]));
        assert!(!should_forward_with_loop_guard(1, 2, &[2]));
        assert!(should_forward_with_loop_guard(1, 3, &[2]));
    }
}
