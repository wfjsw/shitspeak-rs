//! Versioned control-plane state for source-rooted multicast trees.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};
use std::time::Duration;
use std::time::Instant;

use parking_lot::Mutex;
use prost::Message as _;

use bytes::{Bytes, BytesMut};
use shitspeak_core::NodeIdentifier;
use shitspeak_proto::s2s_overlay_proto as pb;
use shitspeak_s2s_transport::{ConnectionManager, MessageClass, ServiceLevel};

use super::messaging::ordering::OverlayOrdering;
use super::routing::RoutingHandle;
use super::{
    OverlayInboundMessage, OverlayNetwork, OverlaySendOptions, RoutingMetric, ServiceInbound,
    distribution_metrics,
};

const RETAINED_VERSIONS: usize = 3;
const UNKNOWN_TREE_FRAMES_PER_KEY: usize = 8;
const UNKNOWN_TREE_FRAMES_TOTAL: usize = 256;
const UNKNOWN_TREE_RECOVERY_RETRY: Duration = Duration::from_millis(10);
const METRIC_TREE_HYSTERESIS: Duration = Duration::from_secs(5);
const EDGE_FAILURE_REPORT_DEDUP: Duration = Duration::from_secs(1);
pub(crate) const DISTRIBUTION_CONTROL_SERVICE_TAG: u32 = 250;
pub(crate) const VOICE_REALTIME_PROFILE_ID: u32 = 1;

/// A stable, service-filtered distribution policy. Profiles deliberately own
/// transport semantics; callers supply only the recipient group.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DistributionProfile {
    id: u32,
    service_tag: u32,
    level: ServiceLevel,
    metric: RoutingMetric,
}

impl DistributionProfile {
    pub(crate) fn id(self) -> u32 {
        self.id
    }

    pub(crate) fn level(self) -> ServiceLevel {
        self.level
    }

    pub(crate) fn metric(self) -> RoutingMetric {
        self.metric
    }

    pub(crate) fn accepts(self, tag: u32) -> bool {
        self.service_tag == tag
    }
}

pub(crate) fn profile_for_service(tag: u32) -> Option<DistributionProfile> {
    let voice = DistributionProfile {
        id: VOICE_REALTIME_PROFILE_ID,
        service_tag: crate::application::proto::VOICE_SERVICE_TAG,
        level: ServiceLevel::BestEffort,
        metric: RoutingMetric::ConversationalQuality,
    };
    voice.accepts(tag).then_some(voice)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct TreeKey {
    pub(crate) source: NodeIdentifier,
    pub(crate) profile: u32,
    pub(crate) group: u64,
    pub(crate) group_version: u64,
    pub(crate) topology_epoch: u64,
    pub(crate) version: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TreeScope {
    source: NodeIdentifier,
    profile: u32,
    group: u64,
    group_version: u64,
    topology_epoch: u64,
}

impl From<TreeKey> for TreeScope {
    fn from(key: TreeKey) -> Self {
        Self {
            source: key.source,
            profile: key.profile,
            group: key.group,
            group_version: key.group_version,
            topology_epoch: key.topology_epoch,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TreeState {
    members: HashSet<NodeIdentifier>,
    children: HashMap<NodeIdentifier, Vec<NodeIdentifier>>,
    nodes: HashSet<NodeIdentifier>,
    /// Source-computed, receiver-specific remote playout baseline. This is
    /// installed out of band with the exact tree version and never appears on
    /// individual voice data frames.
    playout_delays_ms: HashMap<NodeIdentifier, u64>,
    /// Summed source-to-recipient path cost from the routing snapshot that
    /// selected this tree. It is source-local selection state, not wire state.
    recipient_path_cost: Option<u64>,
}

impl TreeState {
    pub(crate) fn new(
        source: NodeIdentifier,
        members: impl IntoIterator<Item = NodeIdentifier>,
        edges: impl IntoIterator<Item = (NodeIdentifier, NodeIdentifier)>,
    ) -> Self {
        Self::new_with_playout(
            source,
            members,
            edges,
            std::iter::empty::<(NodeIdentifier, u64)>(),
        )
    }

    pub(crate) fn new_with_playout(
        source: NodeIdentifier,
        members: impl IntoIterator<Item = NodeIdentifier>,
        edges: impl IntoIterator<Item = (NodeIdentifier, NodeIdentifier)>,
        playout_delays_ms: impl IntoIterator<Item = (NodeIdentifier, u64)>,
    ) -> Self {
        let members: HashSet<_> = members.into_iter().collect();
        let mut children: HashMap<NodeIdentifier, Vec<NodeIdentifier>> = HashMap::new();
        let mut nodes = HashSet::from([source]);
        for (parent, child) in edges {
            if parent == child {
                continue;
            }
            children.entry(parent).or_default().push(child);
            nodes.insert(parent);
            nodes.insert(child);
        }
        for child_nodes in children.values_mut() {
            child_nodes.sort_unstable();
            child_nodes.dedup();
        }
        nodes.extend(members.iter().copied());
        let playout_delays_ms = playout_delays_ms
            .into_iter()
            .filter(|(node, delay_ms)| members.contains(node) && *delay_ms > 0)
            .collect();
        Self {
            members,
            children,
            nodes,
            playout_delays_ms,
            recipient_path_cost: None,
        }
    }

    pub(crate) fn is_member(&self, node: NodeIdentifier) -> bool {
        self.members.contains(&node)
    }

    pub(crate) fn children(&self, node: NodeIdentifier) -> &[NodeIdentifier] {
        self.children.get(&node).map(Vec::as_slice).unwrap_or(&[])
    }

    pub(crate) fn nodes(&self) -> impl Iterator<Item = NodeIdentifier> + '_ {
        self.nodes.iter().copied()
    }

    pub(crate) fn members(&self) -> impl Iterator<Item = NodeIdentifier> + '_ {
        self.members.iter().copied()
    }

    pub(crate) fn edges(&self) -> impl Iterator<Item = (NodeIdentifier, NodeIdentifier)> + '_ {
        self.children
            .iter()
            .flat_map(|(parent, children)| children.iter().map(move |child| (*parent, *child)))
    }

    pub(crate) fn playout_delay_ms(&self, node: NodeIdentifier) -> Option<u64> {
        self.playout_delays_ms.get(&node).copied()
    }

    pub(crate) fn playout_delays_ms(&self) -> impl Iterator<Item = (NodeIdentifier, u64)> + '_ {
        self.playout_delays_ms
            .iter()
            .map(|(node, delay_ms)| (*node, *delay_ms))
    }

    /// Exact recipient members reachable through one direct child branch.
    /// The source tree should be acyclic, but the visited set also bounds this
    /// traversal when inspecting malformed remotely installed control state.
    pub(crate) fn descendant_members(&self, child: NodeIdentifier) -> Vec<NodeIdentifier> {
        let mut pending = vec![child];
        let mut visited = HashSet::new();
        let mut members = Vec::new();
        while let Some(node) = pending.pop() {
            if !visited.insert(node) {
                continue;
            }
            if self.members.contains(&node) {
                members.push(node);
            }
            pending.extend(self.children(node).iter().copied());
        }
        members.sort_unstable();
        members.dedup();
        members
    }

    pub(crate) fn with_recipient_path_cost(mut self, cost: u64) -> Self {
        self.recipient_path_cost = Some(cost);
        self
    }
}

#[derive(Default)]
struct PendingAcks {
    remaining: HashSet<NodeIdentifier>,
}

#[derive(Clone)]
struct ActiveTree {
    state: TreeState,
    candidate: Option<(TreeState, Instant)>,
    /// Failure edges already incorporated into the active replacement. A new
    /// failure gets one structural bypass; unrelated future metric changes
    /// remain subject to the five-second hysteresis.
    applied_failures: HashSet<(NodeIdentifier, NodeIdentifier)>,
}

#[derive(Default)]
struct VersionHistory {
    installed: Vec<u64>,
    activated: Vec<u64>,
}

impl VersionHistory {
    fn record_install(&mut self, version: u64) {
        self.installed.retain(|installed| *installed != version);
        self.installed.push(version);
    }

    fn record_activation(&mut self, version: u64) {
        self.activated.retain(|active| *active != version);
        self.activated.push(version);
        if self.activated.len() > RETAINED_VERSIONS {
            let excess = self.activated.len() - RETAINED_VERSIONS;
            self.activated.drain(..excess);
        }
    }

    fn evicted_versions(&mut self) -> Vec<u64> {
        // An installed replacement must survive until its ACK-gated
        // activation. Keep the latest installation window for receivers that
        // do not observe source activation, plus the source's active snapshot
        // and its two exact predecessors.
        let mut retained: HashSet<u64> = self
            .installed
            .iter()
            .rev()
            .take(RETAINED_VERSIONS)
            .copied()
            .collect();
        retained.extend(self.activated.iter().copied());
        let evicted: Vec<_> = self
            .installed
            .iter()
            .copied()
            .filter(|version| !retained.contains(version))
            .collect();
        self.installed.retain(|version| retained.contains(version));
        evicted
    }
}

/// A frame held only until the exact referenced tree state arrives. It is
/// deliberately opaque to the control plane: replay still goes through the
/// normal data-plane validation path.
#[derive(Debug)]
pub(crate) struct PendingDistributionFrame {
    pub(crate) from: NodeIdentifier,
    pub(crate) data: pb::OverlayData,
    pub(crate) route_transit_messages: bool,
}

impl PendingDistributionFrame {
    pub(crate) fn new(
        from: NodeIdentifier,
        data: pb::OverlayData,
        route_transit_messages: bool,
    ) -> Self {
        Self {
            from,
            data,
            route_transit_messages,
        }
    }
}

#[derive(Debug)]
struct PendingUnknownFrame {
    id: u64,
    frame: PendingDistributionFrame,
}

#[derive(Default)]
struct UnknownTreeFrames {
    by_key: HashMap<TreeKey, Vec<PendingUnknownFrame>>,
    in_flight_requests: HashSet<TreeKey>,
    total: usize,
    next_id: u64,
}

#[derive(Debug)]
pub(crate) enum UnknownTreeEnqueue {
    Queued,
    AlreadyInstalled(PendingDistributionFrame),
    Full,
}

#[derive(Clone)]
pub(crate) struct RecoverySender {
    transport: ConnectionManager,
    routing: RoutingHandle,
    ordering: Arc<OverlayOrdering>,
    self_id: NodeIdentifier,
    boot_epoch: u64,
}

impl RecoverySender {
    async fn request(&self, key: TreeKey) {
        self.send_control(key.source, encode_request(key, self.self_id))
            .await;
    }

    async fn send_failure(&self, key: TreeKey, parent: NodeIdentifier, child: NodeIdentifier) {
        self.send_control(key.source, encode_failure(key, parent, child))
            .await;
    }

    async fn send_control(&self, dst: NodeIdentifier, body: Bytes) {
        let _ = super::messaging::send_unicast_with_routing_metric_unordered_and_options(
            &self.transport,
            &self.routing,
            self.self_id,
            self.boot_epoch,
            &self.ordering,
            dst,
            DISTRIBUTION_CONTROL_SERVICE_TAG,
            ServiceLevel::ReliableLowLatency,
            RoutingMetric::ReliableLowLatencyCost,
            MessageClass::Control,
            body,
            false,
            OverlaySendOptions::default(),
        )
        .await;
    }
}

fn same_tree_structure(left: &TreeState, right: &TreeState) -> bool {
    let mut left_edges: Vec<_> = left.edges().collect();
    left_edges.sort_unstable();
    let mut right_edges: Vec<_> = right.edges().collect();
    right_edges.sort_unstable();
    let mut left_members: Vec<_> = left.members().collect();
    left_members.sort_unstable();
    let mut right_members: Vec<_> = right.members().collect();
    right_members.sort_unstable();
    left_edges == right_edges && left_members == right_members
}

fn same_tree(left: &TreeState, right: &TreeState) -> bool {
    same_tree_structure(left, right) && left.playout_delays_ms == right.playout_delays_ms
}

fn selection_cost_improves_materially(current: &TreeState, candidate: &TreeState) -> bool {
    let (Some(current_cost), Some(candidate_cost)) =
        (current.recipient_path_cost, candidate.recipient_path_cost)
    else {
        return false;
    };
    current_cost > 0 && candidate_cost.saturating_mul(100) <= current_cost.saturating_mul(90)
}

#[derive(Default)]
pub(crate) struct DistributionPlane {
    trees: Mutex<HashMap<TreeKey, Arc<TreeState>>>,
    versions: Mutex<HashMap<TreeScope, VersionHistory>>,
    pending: Mutex<HashMap<TreeKey, PendingAcks>>,
    unknown: Mutex<UnknownTreeFrames>,
    recovery_sender: Mutex<Option<RecoverySender>>,
    self_ref: Mutex<Weak<DistributionPlane>>,
    failed_edges: Mutex<HashMap<TreeScope, HashSet<(NodeIdentifier, NodeIdentifier)>>>,
    /// Reports are deduplicated by source-owned directed edge, rather than by
    /// exact tree version. A replacement can have a different version while
    /// referring to the same physical child edge.
    failure_reported_at: Mutex<HashMap<(NodeIdentifier, NodeIdentifier, NodeIdentifier), Instant>>,
    active_trees: Mutex<HashMap<TreeScope, ActiveTree>>,
}

impl DistributionPlane {
    pub(crate) fn configure_recovery(self: &Arc<Self>, sender: RecoverySender) {
        *self.recovery_sender.lock() = Some(sender);
        *self.self_ref.lock() = Arc::downgrade(self);
    }

    pub(crate) fn select_tree(&self, key: TreeKey, candidate: TreeState) -> TreeState {
        let scope = TreeScope::from(key);
        let failed_edges = self
            .failed_edges
            .lock()
            .get(&scope)
            .cloned()
            .unwrap_or_default();
        let mut active = self.active_trees.lock();
        let Some(current) = active.get_mut(&scope) else {
            let applied_failures = failed_edges
                .iter()
                .copied()
                .filter(|edge| {
                    !candidate
                        .edges()
                        .any(|candidate_edge| candidate_edge == *edge)
                })
                .collect();
            active.insert(
                scope,
                ActiveTree {
                    state: candidate.clone(),
                    candidate: None,
                    applied_failures,
                },
            );
            return candidate;
        };
        if same_tree(&current.state, &candidate) {
            current.candidate = None;
            return current.state.clone();
        }
        // Membership/topology/reparent tree-shape changes are structural and
        // immediately replace the active tree. Only a policy-only update on
        // identical directed edges is subject to metric hysteresis.
        if !same_tree_structure(&current.state, &candidate) {
            let removed_failures: Vec<_> = failed_edges
                .difference(&current.applied_failures)
                .copied()
                .filter(|edge| {
                    !candidate
                        .edges()
                        .any(|candidate_edge| candidate_edge == *edge)
                })
                .collect();
            current.state = candidate.clone();
            current.candidate = None;
            current.applied_failures.extend(removed_failures);
            return candidate;
        }
        // Pure path-cost/playout adjustments must prove a sustained 10%
        // aggregate recipient-path-cost improvement before publication.
        if !selection_cost_improves_materially(&current.state, &candidate) {
            distribution_metrics::record_hysteresis_hold(key.profile);
            current.candidate = None;
            return current.state.clone();
        }
        match &current.candidate {
            Some((pending, since))
                if same_tree(pending, &candidate) && since.elapsed() >= METRIC_TREE_HYSTERESIS =>
            {
                current.state = candidate.clone();
                current.candidate = None;
                candidate
            }
            Some((pending, _)) if same_tree(pending, &candidate) => current.state.clone(),
            _ => {
                current.candidate = Some((candidate, Instant::now()));
                current.state.clone()
            }
        }
    }

    pub(crate) fn failed_edges(&self, key: TreeKey) -> HashSet<(NodeIdentifier, NodeIdentifier)> {
        self.failed_edges
            .lock()
            .get(&TreeScope::from(key))
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn report_edge_failure(
        &self,
        key: TreeKey,
        parent: NodeIdentifier,
        child: NodeIdentifier,
    ) {
        if !self
            .get(key)
            .is_some_and(|tree| tree.edges().any(|edge| edge == (parent, child)))
        {
            return;
        }
        let now = Instant::now();
        {
            let mut reported = self.failure_reported_at.lock();
            reported.retain(|_, reported_at| {
                now.saturating_duration_since(*reported_at) < EDGE_FAILURE_REPORT_DEDUP
            });
            let report_key = (key.source, parent, child);
            if reported.get(&report_key).is_some_and(|reported_at| {
                now.saturating_duration_since(*reported_at) < EDGE_FAILURE_REPORT_DEDUP
            }) {
                return;
            }
            reported.insert(report_key, now);
        }
        let scope = TreeScope::from(key);
        let inserted = self
            .failed_edges
            .lock()
            .entry(scope)
            .or_default()
            .insert((parent, child));
        if !inserted {
            return;
        }
        distribution_metrics::record_reparent(key.profile);
        let (Some(plane), Some(sender)) = (
            self.self_ref.lock().upgrade(),
            self.recovery_sender.lock().clone(),
        ) else {
            return;
        };
        if sender.self_id == key.source {
            return;
        }
        tokio::spawn(async move {
            sender.send_failure(key, parent, child).await;
            drop(plane);
        });
    }

    pub(crate) fn install(&self, key: TreeKey, state: TreeState) -> Vec<PendingDistributionFrame> {
        let tree_edges = state.edges().count();
        let recovered = {
            // Queueing takes these locks in the same order so an install can
            // neither miss a newly queued frame nor replay it under another key.
            let mut trees = self.trees.lock();
            trees.insert(key, Arc::new(state));
            let mut unknown = self.unknown.lock();
            let frames = unknown
                .by_key
                .remove(&key)
                .unwrap_or_default()
                .into_iter()
                .map(|pending| pending.frame)
                .collect();
            unknown.total = unknown.by_key.values().map(Vec::len).sum();
            unknown.in_flight_requests.remove(&key);
            frames
        };
        self.record_installed_version(key);
        distribution_metrics::set_tree_edges(key.profile, tree_edges);
        recovered
    }

    fn record_installed_version(&self, key: TreeKey) {
        let evicted = {
            let mut versions = self.versions.lock();
            let history = versions.entry(TreeScope::from(key)).or_default();
            history.record_install(key.version);
            history.evicted_versions()
        };
        if !evicted.is_empty() {
            let mut trees = self.trees.lock();
            for version in evicted {
                trees.remove(&TreeKey { version, ..key });
            }
        }
    }

    fn record_activated_version(&self, key: TreeKey) {
        let evicted = {
            let mut versions = self.versions.lock();
            let history = versions.entry(TreeScope::from(key)).or_default();
            history.record_install(key.version);
            history.record_activation(key.version);
            history.evicted_versions()
        };
        if !evicted.is_empty() {
            let mut trees = self.trees.lock();
            for version in evicted {
                trees.remove(&TreeKey { version, ..key });
            }
        }
    }

    pub(crate) fn get(&self, key: TreeKey) -> Option<Arc<TreeState>> {
        self.trees.lock().get(&key).cloned()
    }

    pub(crate) fn begin_publish(
        &self,
        key: TreeKey,
        peers: impl IntoIterator<Item = NodeIdentifier>,
    ) -> bool {
        let remaining: HashSet<NodeIdentifier> = peers.into_iter().collect();
        let remaining_count = remaining.len();
        let mut pending = self.pending.lock();
        if pending.contains_key(&key) {
            return false;
        }
        pending.insert(key, PendingAcks { remaining });
        drop(pending);
        distribution_metrics::record_control_publish(key.profile);
        distribution_metrics::set_pending_acks(key.profile, remaining_count);
        if remaining_count == 0 {
            distribution_metrics::record_activation(key.profile);
            self.record_activated_version(key);
        }
        true
    }

    /// Forget a failed publish so the next source frame can retry the exact
    /// tree install while continuing to use the compatibility data path.
    pub(crate) fn abort_publish(&self, key: TreeKey) {
        let removed = {
            let mut pending = self.pending.lock();
            if pending
                .get(&key)
                .is_some_and(|pending| !pending.remaining.is_empty())
            {
                pending.remove(&key);
                true
            } else {
                false
            }
        };
        if removed {
            distribution_metrics::set_pending_acks(key.profile, 0);
        }
    }

    pub(crate) fn acknowledge(&self, key: TreeKey, node: NodeIdentifier) {
        let (remaining, activated) = {
            let mut pending = self.pending.lock();
            let Some(entry) = pending.get_mut(&key) else {
                return;
            };
            let was_pending = !entry.remaining.is_empty();
            entry.remaining.remove(&node);
            (
                entry.remaining.len(),
                was_pending && entry.remaining.is_empty(),
            )
        };
        distribution_metrics::record_control_ack(key.profile);
        distribution_metrics::set_pending_acks(key.profile, remaining);
        if activated {
            distribution_metrics::record_activation(key.profile);
            self.record_activated_version(key);
        }
    }

    pub(crate) fn is_ready(&self, key: TreeKey) -> bool {
        self.pending
            .lock()
            .get(&key)
            .is_some_and(|pending| pending.remaining.is_empty())
    }

    /// Queue a frame for bounded exact-state recovery. The first frame for a
    /// key starts one request task; later frames coalesce onto that task.
    pub(crate) fn queue_unknown(
        &self,
        key: TreeKey,
        frame: PendingDistributionFrame,
        recovery_window: Duration,
    ) -> UnknownTreeEnqueue {
        let start_request = {
            // Keep the tree lock while enqueueing so `install` either drains
            // this frame or reports the exact state already present.
            let trees = self.trees.lock();
            if trees.contains_key(&key) {
                return UnknownTreeEnqueue::AlreadyInstalled(frame);
            }
            let mut unknown = self.unknown.lock();
            if unknown.total >= UNKNOWN_TREE_FRAMES_TOTAL
                || unknown
                    .by_key
                    .get(&key)
                    .is_some_and(|frames| frames.len() >= UNKNOWN_TREE_FRAMES_PER_KEY)
            {
                return UnknownTreeEnqueue::Full;
            }
            unknown.next_id = unknown.next_id.wrapping_add(1).max(1);
            let id = unknown.next_id;
            unknown
                .by_key
                .entry(key)
                .or_default()
                .push(PendingUnknownFrame { id, frame });
            unknown.total += 1;
            let start_request = unknown.in_flight_requests.insert(key);
            drop(unknown);
            drop(trees);
            self.schedule_unknown_expiry(key, id, recovery_window);
            start_request
        };

        if start_request {
            self.start_unknown_recovery(key);
        }
        UnknownTreeEnqueue::Queued
    }

    fn schedule_unknown_expiry(&self, key: TreeKey, id: u64, recovery_window: Duration) {
        let Some(plane) = self.self_ref.lock().upgrade() else {
            return;
        };
        tokio::spawn(async move {
            tokio::time::sleep(recovery_window).await;
            plane.expire_unknown(key, id);
        });
    }

    fn start_unknown_recovery(&self, key: TreeKey) {
        let (Some(plane), Some(sender)) = (
            self.self_ref.lock().upgrade(),
            self.recovery_sender.lock().clone(),
        ) else {
            return;
        };
        tokio::spawn(async move {
            sender.request(key).await;
            tokio::time::sleep(UNKNOWN_TREE_RECOVERY_RETRY).await;
            if plane.has_unknown(key) && plane.get(key).is_none() {
                sender.request(key).await;
            }
        });
    }

    fn has_unknown(&self, key: TreeKey) -> bool {
        self.unknown
            .lock()
            .by_key
            .get(&key)
            .is_some_and(|frames| !frames.is_empty())
    }

    fn expire_unknown(&self, key: TreeKey, id: u64) {
        let mut unknown = self.unknown.lock();
        let Some((removed, empty)) = unknown.by_key.get_mut(&key).map(|frames| {
            let before = frames.len();
            frames.retain(|pending| pending.id != id);
            (before.saturating_sub(frames.len()), frames.is_empty())
        }) else {
            return;
        };
        unknown.total = unknown.total.saturating_sub(removed);
        if empty {
            unknown.by_key.remove(&key);
            unknown.in_flight_requests.remove(&key);
        }
    }

    #[cfg(test)]
    fn unknown_frame_count(&self) -> usize {
        self.unknown.lock().total
    }
}

pub(crate) fn tree_version(
    source: NodeIdentifier,
    profile: u32,
    group: u64,
    group_version: u64,
    topology_epoch: u64,
    state: &TreeState,
) -> u64 {
    // Stable FNV-1a avoids process-random hashing and makes independent
    // publishers produce the same version for the same topology snapshot.
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut members: Vec<_> = state.members().collect();
    members.sort_unstable();
    let mut edges: Vec<_> = state.edges().collect();
    edges.sort_unstable();
    let mut playout_delays: Vec<_> = state.playout_delays_ms().collect();
    playout_delays.sort_unstable();
    for value in std::iter::once(u64::from(source))
        .chain([u64::from(profile), group, group_version, topology_epoch])
        .chain(members.into_iter().map(u64::from))
        .chain(
            edges
                .into_iter()
                .flat_map(|(parent, child)| [u64::from(parent), u64::from(child)]),
        )
        .chain(
            playout_delays
                .into_iter()
                .flat_map(|(node, delay_ms)| [u64::from(node), delay_ms]),
        )
    {
        hash ^= value;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash.max(1)
}

pub(crate) fn register_control_handler(overlay: &OverlayNetwork) {
    overlay
        .inner
        .distribution
        .configure_recovery(RecoverySender {
            transport: overlay.inner.transport.clone(),
            routing: overlay.inner.routing.clone(),
            ordering: overlay.inner.ordering().clone(),
            self_id: overlay.inner.self_id,
            boot_epoch: overlay.inner.boot_epoch,
        });
    overlay.register_service(
        DISTRIBUTION_CONTROL_SERVICE_TAG,
        Arc::new(DistributionControlHandler {
            overlay: overlay.clone(),
            plane: overlay.inner.distribution.clone(),
        }),
    );
}

pub(crate) fn encode_install(key: TreeKey, state: &TreeState) -> Bytes {
    encode_control(pb::DistributionControl {
        body: Some(pb::distribution_control::Body::Install(
            pb::DistributionTreeInstall {
                source: key.source.into(),
                profile: key.profile,
                version: key.version,
                group: key.group,
                group_version: key.group_version,
                topology_epoch: key.topology_epoch,
                members: state.members().map(u32::from).collect(),
                playout_delays: state
                    .playout_delays_ms()
                    .map(|(node, delay_ms)| pb::DistributionTreePlayoutDelay {
                        node: node.into(),
                        delay_ms: delay_ms.min(u64::from(u32::MAX)) as u32,
                    })
                    .collect(),
                edges: state
                    .edges()
                    .map(|(parent, child)| pb::OverlayTreeEdge {
                        parent: parent.into(),
                        child: child.into(),
                    })
                    .collect(),
            },
        )),
    })
}

pub(crate) fn encode_request(key: TreeKey, requester: NodeIdentifier) -> Bytes {
    encode_control(pb::DistributionControl {
        body: Some(pb::distribution_control::Body::Request(
            pb::DistributionTreeRequest {
                source: key.source.into(),
                profile: key.profile,
                version: key.version,
                requester: requester.into(),
                group: key.group,
                group_version: key.group_version,
                topology_epoch: key.topology_epoch,
            },
        )),
    })
}

pub(crate) fn encode_failure(key: TreeKey, parent: NodeIdentifier, child: NodeIdentifier) -> Bytes {
    encode_control(pb::DistributionControl {
        body: Some(pb::distribution_control::Body::Failure(
            pb::DistributionTreeFailure {
                source: key.source.into(),
                profile: key.profile,
                version: key.version,
                group: key.group,
                group_version: key.group_version,
                topology_epoch: key.topology_epoch,
                parent: parent.into(),
                child: child.into(),
            },
        )),
    })
}

fn encode_control(control: pb::DistributionControl) -> Bytes {
    let mut buf = BytesMut::with_capacity(control.encoded_len());
    control
        .encode(&mut buf)
        .expect("distribution control encode");
    buf.freeze()
}

struct DistributionControlHandler {
    overlay: OverlayNetwork,
    plane: Arc<DistributionPlane>,
}

impl ServiceInbound for DistributionControlHandler {
    fn handle(&self, msg: OverlayInboundMessage) {
        let reporter = msg.from;
        let Ok(control) = pb::DistributionControl::decode(msg.body) else {
            return;
        };
        let overlay = self.overlay.clone();
        let plane = self.plane.clone();
        tokio::spawn(async move {
            let Some(body) = control.body else {
                return;
            };
            match body {
                pb::distribution_control::Body::Install(install) => {
                    let Ok(source) = NodeIdentifier::try_from(install.source) else {
                        return;
                    };
                    let members = install
                        .members
                        .into_iter()
                        .filter_map(|node| NodeIdentifier::try_from(node).ok());
                    let edges = install.edges.into_iter().filter_map(|edge| {
                        Some((
                            NodeIdentifier::try_from(edge.parent).ok()?,
                            NodeIdentifier::try_from(edge.child).ok()?,
                        ))
                    });
                    let key = TreeKey {
                        source,
                        profile: install.profile,
                        group: install.group,
                        group_version: install.group_version,
                        topology_epoch: install.topology_epoch,
                        version: install.version,
                    };
                    let playout_delays = install.playout_delays.into_iter().filter_map(|delay| {
                        Some((
                            NodeIdentifier::try_from(delay.node).ok()?,
                            u64::from(delay.delay_ms),
                        ))
                    });
                    let recovered = plane.install(
                        key,
                        TreeState::new_with_playout(source, members, edges, playout_delays),
                    );
                    let ack = encode_control(pb::DistributionControl {
                        body: Some(pb::distribution_control::Body::Ack(
                            pb::DistributionTreeAck {
                                source: source.into(),
                                profile: key.profile,
                                version: key.version,
                                node: overlay.local_node_id().into(),
                                group: key.group,
                                group_version: key.group_version,
                                topology_epoch: key.topology_epoch,
                            },
                        )),
                    });
                    let _ = overlay
                        .send_unicast_unordered_with_routing_metric(
                            source,
                            DISTRIBUTION_CONTROL_SERVICE_TAG,
                            ServiceLevel::ReliableLowLatency,
                            RoutingMetric::ReliableLowLatencyCost,
                            MessageClass::Control,
                            ack,
                        )
                        .await;
                    for frame in recovered {
                        let overlay = overlay.clone();
                        tokio::spawn(async move {
                            super::messaging::forward::replay_distribution_frame(overlay, frame)
                                .await;
                        });
                    }
                }
                pb::distribution_control::Body::Ack(ack) => {
                    let (Ok(source), Ok(node)) = (
                        NodeIdentifier::try_from(ack.source),
                        NodeIdentifier::try_from(ack.node),
                    ) else {
                        return;
                    };
                    if source == overlay.local_node_id() {
                        plane.acknowledge(
                            TreeKey {
                                source,
                                profile: ack.profile,
                                group: ack.group,
                                group_version: ack.group_version,
                                topology_epoch: ack.topology_epoch,
                                version: ack.version,
                            },
                            node,
                        );
                    }
                }
                pb::distribution_control::Body::Request(request) => {
                    let (Ok(source), Ok(requester)) = (
                        NodeIdentifier::try_from(request.source),
                        NodeIdentifier::try_from(request.requester),
                    ) else {
                        return;
                    };
                    if source != overlay.local_node_id() {
                        return;
                    }
                    distribution_metrics::record_state_request(request.profile);
                    let key = TreeKey {
                        source,
                        profile: request.profile,
                        group: request.group,
                        group_version: request.group_version,
                        topology_epoch: request.topology_epoch,
                        version: request.version,
                    };
                    let Some(tree) = plane.get(key) else {
                        return;
                    };
                    let _ = overlay
                        .send_unicast_unordered_with_routing_metric(
                            requester,
                            DISTRIBUTION_CONTROL_SERVICE_TAG,
                            ServiceLevel::ReliableLowLatency,
                            RoutingMetric::ReliableLowLatencyCost,
                            MessageClass::Control,
                            encode_install(key, &tree),
                        )
                        .await;
                }
                pb::distribution_control::Body::Failure(failure) => {
                    let (Ok(source), Ok(parent), Ok(child)) = (
                        NodeIdentifier::try_from(failure.source),
                        NodeIdentifier::try_from(failure.parent),
                        NodeIdentifier::try_from(failure.child),
                    ) else {
                        return;
                    };
                    // A relay reports its own failed send, while a receiver
                    // can report expiry of its parent edge. Do not let an
                    // unrelated control sender poison a source tree.
                    if reporter != parent && reporter != child {
                        return;
                    }
                    if source == overlay.local_node_id() {
                        plane.report_edge_failure(
                            TreeKey {
                                source,
                                profile: failure.profile,
                                group: failure.group,
                                group_version: failure.group_version,
                                topology_epoch: failure.topology_epoch,
                                version: failure.version,
                            },
                            parent,
                            child,
                        );
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(group: u64, version: u64) -> TreeKey {
        TreeKey {
            source: 1,
            profile: VOICE_REALTIME_PROFILE_ID,
            group,
            group_version: 1,
            topology_epoch: 1,
            version,
        }
    }

    fn frame(message_id: u64) -> PendingDistributionFrame {
        PendingDistributionFrame::new(
            2,
            pb::OverlayData {
                origin_message_id: message_id,
                ..Default::default()
            },
            true,
        )
    }

    fn state() -> TreeState {
        TreeState::new(1, [2], [(1, 2)])
    }

    fn state_with_delay(delay_ms: u64) -> TreeState {
        TreeState::new_with_playout(1, [2], [(1, 2)], [(2, delay_ms)])
    }

    fn state_with_delay_and_cost(delay_ms: u64, cost: u64) -> TreeState {
        state_with_delay(delay_ms).with_recipient_path_cost(cost)
    }

    #[test]
    fn playout_delay_is_part_of_exact_tree_version() {
        let lower = state_with_delay(100);
        let higher = state_with_delay(120);
        assert_ne!(
            tree_version(1, VOICE_REALTIME_PROFILE_ID, 1, 1, 1, &lower),
            tree_version(1, VOICE_REALTIME_PROFILE_ID, 1, 1, 1, &higher)
        );
    }

    #[test]
    fn metric_hysteresis_requires_ten_percent_path_cost_improvement() {
        let current = state_with_delay_and_cost(100, 100);
        assert!(!selection_cost_improves_materially(
            &current,
            &state_with_delay_and_cost(120, 91)
        ));
        assert!(selection_cost_improves_materially(
            &current,
            &state_with_delay_and_cost(120, 90)
        ));
        assert!(!selection_cost_improves_materially(
            &current,
            &state_with_delay_and_cost(120, 110)
        ));
    }

    #[test]
    fn descendant_members_are_exact_to_the_child_branch() {
        let tree = TreeState::new(1, [2, 4, 5], [(1, 2), (1, 3), (3, 4), (3, 5)]);
        assert_eq!(tree.descendant_members(2), vec![2]);
        assert_eq!(tree.descendant_members(3), vec![4, 5]);
        assert!(tree.descendant_members(99).is_empty());
    }

    #[test]
    fn child_edge_failure_reports_are_deduplicated_by_source_directed_edge() {
        let plane = DistributionPlane::default();
        let first = key(1, 1);
        let replacement = key(1, 2);
        plane.install(first, state());
        plane.install(replacement, state());
        plane.report_edge_failure(first, 1, 2);
        plane.report_edge_failure(replacement, 1, 2);
        assert_eq!(plane.failure_reported_at.lock().len(), 1);
        assert!(plane.failed_edges(first).contains(&(1, 2)));

        plane.report_edge_failure(first, 1, 3);
        assert!(plane.failed_edges(first).contains(&(1, 2)));
        assert!(!plane.failed_edges(first).contains(&(1, 3)));
    }

    #[test]
    fn structural_replacement_bypasses_hysteresis_once_then_metric_changes_hold() {
        let plane = DistributionPlane::default();
        let key = key(1, 1);
        let initial = state_with_delay_and_cost(100, 100);
        assert_eq!(
            plane.select_tree(key, initial.clone()).playout_delay_ms(2),
            Some(100)
        );
        plane.install(key, initial);
        plane.report_edge_failure(key, 1, 2);

        let replacement = TreeState::new_with_playout(1, [2], [(1, 3), (3, 2)], [(2, 120)])
            .with_recipient_path_cost(90);
        let selected = plane.select_tree(key, replacement.clone());
        assert_eq!(selected.children(1), &[3]);

        let metric_only = TreeState::new_with_playout(1, [2], [(1, 3), (3, 2)], [(2, 140)])
            .with_recipient_path_cost(80);
        assert_eq!(
            plane.select_tree(key, metric_only).playout_delay_ms(2),
            Some(120),
            "the prior failure must not permanently bypass metric hysteresis"
        );
    }

    #[test]
    fn active_tree_and_two_predecessors_survive_until_replacement_activates() {
        let plane = DistributionPlane::default();
        let first = key(1, 1);
        let second = key(1, 2);
        let third = key(1, 3);
        let replacement = key(1, 4);
        for current in [first, second, third] {
            plane.install(current, state());
            assert!(plane.begin_publish(current, [2]));
            plane.acknowledge(current, 2);
        }

        plane.install(replacement, state());
        for retained in [first, second, third, replacement] {
            assert!(plane.get(retained).is_some());
        }

        assert!(plane.begin_publish(replacement, [2]));
        plane.acknowledge(replacement, 2);
        assert!(plane.get(first).is_none());
        for retained in [second, third, replacement] {
            assert!(plane.get(retained).is_some());
        }
    }

    #[test]
    fn unknown_tree_recovery_coalesces_and_replays_only_the_exact_key() {
        let plane = DistributionPlane::default();
        let missing = key(11, 1);
        let other = key(12, 1);

        assert!(matches!(
            plane.queue_unknown(missing, frame(10), Duration::from_secs(1)),
            UnknownTreeEnqueue::Queued
        ));
        assert!(matches!(
            plane.queue_unknown(missing, frame(11), Duration::from_secs(1)),
            UnknownTreeEnqueue::Queued
        ));
        assert_eq!(plane.unknown.lock().in_flight_requests.len(), 1);
        assert_eq!(plane.unknown_frame_count(), 2);

        assert!(plane.install(other, state()).is_empty());
        assert_eq!(plane.unknown_frame_count(), 2);

        let recovered = plane.install(missing, state());
        assert_eq!(
            recovered
                .iter()
                .map(|frame| frame.data.origin_message_id)
                .collect::<Vec<_>>(),
            vec![10, 11]
        );
        assert_eq!(plane.unknown_frame_count(), 0);
    }

    #[test]
    fn publication_coalesces_until_every_required_ack_activates() {
        let plane = DistributionPlane::default();
        let key = key(11, 1);

        assert!(plane.begin_publish(key, [2, 3]));
        assert!(
            !plane.begin_publish(key, [2, 3]),
            "a second voice frame must not restart the ACK window"
        );
        plane.acknowledge(key, 2);
        assert!(!plane.is_ready(key));
        plane.acknowledge(key, 3);
        assert!(plane.is_ready(key));
        assert!(
            !plane.begin_publish(key, [2, 3]),
            "an active exact tree must remain active for subsequent frames"
        );
    }

    #[test]
    fn unknown_tree_recovery_enforces_per_key_and_global_limits() {
        let plane = DistributionPlane::default();
        let first = key(1, 1);
        for message_id in 0..UNKNOWN_TREE_FRAMES_PER_KEY as u64 {
            assert!(matches!(
                plane.queue_unknown(first, frame(message_id), Duration::from_secs(1)),
                UnknownTreeEnqueue::Queued
            ));
        }
        assert!(matches!(
            plane.queue_unknown(first, frame(99), Duration::from_secs(1)),
            UnknownTreeEnqueue::Full
        ));

        for group in 2..=(UNKNOWN_TREE_FRAMES_TOTAL - UNKNOWN_TREE_FRAMES_PER_KEY + 1) as u64 {
            assert!(matches!(
                plane.queue_unknown(key(group, 1), frame(group), Duration::from_secs(1)),
                UnknownTreeEnqueue::Queued
            ));
        }
        assert_eq!(plane.unknown_frame_count(), UNKNOWN_TREE_FRAMES_TOTAL);
        assert!(matches!(
            plane.queue_unknown(key(999, 1), frame(999), Duration::from_secs(1)),
            UnknownTreeEnqueue::Full
        ));
    }
}
