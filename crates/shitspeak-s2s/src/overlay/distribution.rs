//! Versioned control-plane state for source-rooted multicast trees.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};
use std::time::Duration;
use std::time::Instant;

use parking_lot::Mutex;
use prost::Message as _;
use tracing::debug;

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
const EDGE_FAILURE_REPORT_DEDUP: Duration = Duration::from_secs(1);
const FAILED_EDGE_EXCLUSION: Duration = Duration::from_secs(10);
const METRIC_RESHAPE_HOLD: Duration = Duration::from_secs(5);
const METRIC_RESHAPE_IMPROVEMENT_PERCENT: u64 = 10;
pub(crate) const DISTRIBUTION_CONTROL_SERVICE_TAG: u32 = 250;
pub(crate) const VOICE_REALTIME_PROFILE_ID: u32 = 1;
#[cfg(feature = "pre-release-workload")]
pub(crate) const PRE_RELEASE_RELIABLE_PROFILE_ID: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum TreeEdgePath {
    DirectChild,
    LegacyVia(NodeIdentifier),
}

impl TreeEdgePath {
    pub(crate) fn mode_label(self) -> &'static str {
        match self {
            Self::DirectChild => "direct",
            Self::LegacyVia(_) => "legacy",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TreeEdgeCandidate {
    path: TreeEdgePath,
    pressure: u8,
    route_cost: u64,
}

impl TreeEdgeCandidate {
    pub(crate) fn direct(pressure: u8) -> Self {
        Self {
            path: TreeEdgePath::DirectChild,
            pressure,
            route_cost: 0,
        }
    }

    pub(crate) fn legacy(first_hop: NodeIdentifier, pressure: u8, route_cost: u64) -> Self {
        Self {
            path: TreeEdgePath::LegacyVia(first_hop),
            pressure,
            route_cost,
        }
    }

    pub(crate) fn path(self) -> TreeEdgePath {
        self.path
    }

    pub(crate) fn pressure(self) -> u8 {
        self.pressure
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TreeEdgeStickinessPolicy {
    min_hold: Duration,
    challenger_confirm: Duration,
    idle_reset: Duration,
}

impl TreeEdgeStickinessPolicy {
    pub(crate) fn new(
        min_hold: Duration,
        challenger_confirm: Duration,
        idle_reset: Duration,
    ) -> Self {
        Self {
            min_hold,
            challenger_confirm,
            idle_reset,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct TreeEdgeBindingKey {
    source: NodeIdentifier,
    profile: u32,
    group: u64,
    group_version: u64,
    parent: NodeIdentifier,
    child: NodeIdentifier,
}

impl TreeEdgeBindingKey {
    fn new(key: TreeKey, parent: NodeIdentifier, child: NodeIdentifier) -> Self {
        Self {
            source: key.source,
            profile: key.profile,
            group: key.group,
            group_version: key.group_version,
            parent,
            child,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct TreeEdgeBinding {
    path: TreeEdgePath,
    entered_at: Instant,
    last_used_at: Instant,
    challenger: Option<TreeEdgePath>,
    challenger_since: Option<Instant>,
    challenger_observations: u32,
    pending: Option<(TreeEdgePath, &'static str)>,
    pending_held: Duration,
    pending_confirmation: Duration,
    generation: u64,
    bound: bool,
    no_alternate_reported: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TreeEdgeAttempt {
    key: TreeEdgeBindingKey,
    path: TreeEdgePath,
    generation: u64,
    reason: &'static str,
    incumbent_pressure: Option<u8>,
    chosen_pressure: Option<u8>,
}

impl TreeEdgeAttempt {
    pub(crate) fn path(self) -> TreeEdgePath {
        self.path
    }

    pub(crate) fn incumbent_pressure(self) -> Option<u8> {
        self.incumbent_pressure
    }

    pub(crate) fn chosen_pressure(self) -> Option<u8> {
        self.chosen_pressure
    }
}

fn candidate_for(
    candidates: &[TreeEdgeCandidate],
    path: TreeEdgePath,
) -> Option<TreeEdgeCandidate> {
    candidates
        .iter()
        .copied()
        .find(|candidate| candidate.path == path)
}

fn best_legacy_candidate(
    candidates: &[TreeEdgeCandidate],
    excluded: Option<TreeEdgePath>,
) -> Option<TreeEdgeCandidate> {
    candidates.iter().copied().find(|candidate| {
        matches!(candidate.path, TreeEdgePath::LegacyVia(_)) && excluded != Some(candidate.path)
    })
}

fn observe_tree_edge_challenger(
    binding: &mut TreeEdgeBinding,
    challenger: TreeEdgePath,
    now: Instant,
) {
    if binding.challenger == Some(challenger) {
        binding.challenger_observations = binding.challenger_observations.saturating_add(1);
    } else {
        binding.challenger = Some(challenger);
        binding.challenger_since = Some(now);
        binding.challenger_observations = 1;
    }
}

fn clear_tree_edge_challenger(binding: &mut TreeEdgeBinding) {
    binding.challenger = None;
    binding.challenger_since = None;
    binding.challenger_observations = 0;
}

fn begin_tree_edge_transition(
    binding: &mut TreeEdgeBinding,
    path: TreeEdgePath,
    reason: &'static str,
    now: Instant,
) {
    binding.pending_held = now.saturating_duration_since(binding.entered_at);
    binding.pending_confirmation = binding
        .challenger_since
        .map(|since| now.saturating_duration_since(since))
        .unwrap_or_default();
    binding.generation = binding.generation.wrapping_add(1).max(1);
    binding.pending = Some((path, reason));
    binding.no_alternate_reported = false;
    clear_tree_edge_challenger(binding);
}

fn record_no_tree_edge_alternate(key: TreeEdgeBindingKey, binding: &mut TreeEdgeBinding) {
    if binding.no_alternate_reported {
        return;
    }
    binding.no_alternate_reported = true;
    distribution_metrics::record_tree_edge_binding_event(
        key.parent,
        key.child,
        binding.path.mode_label(),
        binding.path.mode_label(),
        "no_alternate",
    );
}

fn prune_tree_edge_bindings(
    bindings: &mut HashMap<TreeEdgeBindingKey, TreeEdgeBinding>,
    current: TreeEdgeBindingKey,
    idle_reset: Duration,
    now: Instant,
) {
    let mut removed = Vec::new();
    bindings.retain(|key, binding| {
        let superseded_group = key.source == current.source
            && key.profile == current.profile
            && key.group == current.group
            && key.group_version != current.group_version;
        let idle = now.saturating_duration_since(binding.last_used_at) >= idle_reset;
        let keep = !superseded_group && !idle;
        if !keep && binding.bound {
            removed.push((*key, binding.path, idle));
        }
        keep
    });
    for (key, path, idle) in removed {
        distribution_metrics::update_tree_edge_binding(
            key.parent,
            key.child,
            Some(path.mode_label()),
            None,
        );
        if idle {
            distribution_metrics::record_tree_edge_binding_event(
                key.parent,
                key.child,
                path.mode_label(),
                "none",
                "idle_reset",
            );
            debug!(
                source = %key.parent,
                peer = %key.child,
                from_mode = path.mode_label(),
                reason = "idle_reset",
                "voice tree edge binding reset after idle"
            );
        }
    }
}

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
    if voice.accepts(tag) {
        return Some(voice);
    }
    #[cfg(feature = "pre-release-workload")]
    {
        let pre_release = DistributionProfile {
            id: PRE_RELEASE_RELIABLE_PROFILE_ID,
            service_tag: super::PRE_RELEASE_DISTRIBUTION_SERVICE_TAG,
            level: ServiceLevel::ReliableLowLatency,
            metric: RoutingMetric::ReliableLowLatencyCost,
        };
        if pre_release.accepts(tag) {
            return Some(pre_release);
        }
    }
    None
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
    hop_ttl: Option<Duration>,
}

impl TreeState {
    pub(crate) fn new(
        source: NodeIdentifier,
        members: impl IntoIterator<Item = NodeIdentifier>,
        edges: impl IntoIterator<Item = (NodeIdentifier, NodeIdentifier)>,
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
        Self {
            members,
            children,
            nodes,
            hop_ttl: None,
        }
    }

    /// Retained while mixed-version callers still supply the retired metadata.
    /// The values are deliberately ignored: tree state owns topology only.
    #[cfg(test)]
    pub(crate) fn new_with_playout(
        source: NodeIdentifier,
        members: impl IntoIterator<Item = NodeIdentifier>,
        edges: impl IntoIterator<Item = (NodeIdentifier, NodeIdentifier)>,
        _playout_delays_ms: impl IntoIterator<Item = (NodeIdentifier, u64)>,
    ) -> Self {
        Self::new(source, members, edges)
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

    pub(crate) fn with_hop_ttl(mut self, hop_ttl: Duration) -> Self {
        self.hop_ttl = (!hop_ttl.is_zero()).then_some(hop_ttl);
        self
    }

    pub(crate) fn hop_ttl(&self) -> Option<Duration> {
        self.hop_ttl
    }

    pub(crate) fn is_valid_for_source(&self, source: NodeIdentifier) -> bool {
        self.is_valid(source)
    }

    /// Return the portion of this tree needed by the relay below `child`.
    /// The path from the original source to the child is retained so the
    /// existing whole-tree validation rules remain applicable to the hint.
    pub(crate) fn branch_for_child(
        &self,
        source: NodeIdentifier,
        child: NodeIdentifier,
    ) -> Option<Self> {
        if !self.is_reachable_from(source, child) {
            return None;
        }

        let all_edges: Vec<_> = self.edges().collect();
        let mut path_edges = Vec::new();
        let mut current = child;
        while current != source {
            let parent = all_edges
                .iter()
                .find_map(|(parent, edge_child)| (*edge_child == current).then_some(*parent))?;
            path_edges.push((parent, current));
            current = parent;
        }
        path_edges.reverse();

        let mut branch_nodes = HashSet::from([child]);
        let mut pending = vec![child];
        while let Some(node) = pending.pop() {
            for descendant in self.children(node) {
                if branch_nodes.insert(*descendant) {
                    pending.push(*descendant);
                }
            }
        }
        let mut edges = path_edges;
        edges.extend(all_edges.iter().copied().filter(|(parent, edge_child)| {
            branch_nodes.contains(parent) && branch_nodes.contains(edge_child)
        }));
        let members = self
            .members
            .iter()
            .copied()
            .filter(|member| branch_nodes.contains(member));
        let branch = Self::new(source, members, edges).with_hop_ttl_opt(self.hop_ttl);
        branch.is_valid(source).then_some(branch)
    }

    fn with_hop_ttl_opt(mut self, hop_ttl: Option<Duration>) -> Self {
        self.hop_ttl = hop_ttl;
        self
    }

    fn is_valid(&self, source: NodeIdentifier) -> bool {
        if !self.nodes.contains(&source) || self.members.contains(&source) {
            return false;
        }
        let mut parent_count = HashMap::<NodeIdentifier, usize>::new();
        for (parent, child) in self.edges() {
            if parent == child || child == source {
                return false;
            }
            *parent_count.entry(child).or_default() += 1;
        }
        if parent_count.values().any(|count| *count != 1) {
            return false;
        }
        let mut reached = HashSet::from([source]);
        let mut pending = vec![source];
        while let Some(parent) = pending.pop() {
            for child in self.children(parent) {
                if !reached.insert(*child) {
                    return false;
                }
                pending.push(*child);
            }
        }
        reached == self.nodes && self.members.iter().all(|member| reached.contains(member))
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

    pub(crate) fn is_reachable_from(
        &self,
        source: NodeIdentifier,
        destination: NodeIdentifier,
    ) -> bool {
        let mut pending = vec![source];
        let mut visited = HashSet::new();
        while let Some(node) = pending.pop() {
            if !visited.insert(node) {
                continue;
            }
            if node == destination {
                return true;
            }
            pending.extend(self.children(node).iter().copied());
        }
        false
    }
}

#[derive(Default)]
struct PendingAcks {
    remaining: HashSet<NodeIdentifier>,
}

#[derive(Clone)]
struct ActiveTree {
    key: TreeKey,
    state: TreeState,
    path_cost: u64,
    /// Failure edges already incorporated into the active replacement.
    applied_failures: HashSet<(NodeIdentifier, NodeIdentifier)>,
    legacy_members: HashSet<NodeIdentifier>,
}

#[derive(Clone)]
struct CandidateTree {
    key: TreeKey,
    state: TreeState,
    path_cost: u64,
    routing_generation: u64,
    recheck_at: Option<Instant>,
    legacy_members: HashSet<NodeIdentifier>,
}

#[derive(Clone)]
struct MetricProposal {
    state: TreeState,
    path_cost: u64,
    first_seen: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StableTreeScope {
    source: NodeIdentifier,
    profile: u32,
    group: u64,
    group_version: u64,
}

impl From<TreeKey> for StableTreeScope {
    fn from(key: TreeKey) -> Self {
        Self {
            source: key.source,
            profile: key.profile,
            group: key.group,
            group_version: key.group_version,
        }
    }
}

#[derive(Clone)]
pub(crate) struct SelectedTree {
    key: TreeKey,
    state: Arc<TreeState>,
    legacy_members: Arc<HashSet<NodeIdentifier>>,
}

impl SelectedTree {
    pub(crate) fn key(&self) -> TreeKey {
        self.key
    }

    pub(crate) fn state(&self) -> &Arc<TreeState> {
        &self.state
    }

    pub(crate) fn legacy_members(&self) -> &HashSet<NodeIdentifier> {
        &self.legacy_members
    }
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

#[derive(Default)]
pub(crate) struct DistributionPlane {
    trees: Mutex<HashMap<TreeKey, Arc<TreeState>>>,
    versions: Mutex<HashMap<TreeScope, VersionHistory>>,
    pending: Mutex<HashMap<TreeKey, PendingAcks>>,
    unknown: Mutex<UnknownTreeFrames>,
    recovery_sender: Mutex<Option<RecoverySender>>,
    self_ref: Mutex<Weak<DistributionPlane>>,
    failed_edges:
        Mutex<HashMap<StableTreeScope, HashMap<(NodeIdentifier, NodeIdentifier), Instant>>>,
    /// Reports are deduplicated by source-owned directed edge, rather than by
    /// exact tree version. A replacement can have a different version while
    /// referring to the same physical child edge.
    failure_reported_at: Mutex<HashMap<(NodeIdentifier, NodeIdentifier, NodeIdentifier), Instant>>,
    active_trees: Mutex<HashMap<StableTreeScope, ActiveTree>>,
    candidates: Mutex<HashMap<TreeScope, CandidateTree>>,
    metric_proposals: Mutex<HashMap<StableTreeScope, MetricProposal>>,
    routing_generations: Mutex<HashMap<StableTreeScope, u64>>,
    scope_activity: Mutex<HashMap<TreeScope, Instant>>,
    tree_edge_bindings: Mutex<HashMap<TreeEdgeBindingKey, TreeEdgeBinding>>,
    #[cfg(test)]
    control_publishes: Mutex<u64>,
}

impl DistributionPlane {
    pub(crate) fn current_tree_edge_path(
        &self,
        tree_key: TreeKey,
        parent: NodeIdentifier,
        child: NodeIdentifier,
    ) -> Option<TreeEdgePath> {
        self.tree_edge_bindings
            .lock()
            .get(&TreeEdgeBindingKey::new(tree_key, parent, child))
            .filter(|binding| binding.bound)
            .map(|binding| binding.path)
    }

    pub(crate) fn choose_tree_edge(
        &self,
        tree_key: TreeKey,
        parent: NodeIdentifier,
        child: NodeIdentifier,
        mut candidates: Vec<TreeEdgeCandidate>,
        policy: TreeEdgeStickinessPolicy,
        now: Instant,
    ) -> TreeEdgeAttempt {
        let key = TreeEdgeBindingKey::new(tree_key, parent, child);
        candidates.sort_by_key(|candidate| {
            let mode_order = match candidate.path {
                TreeEdgePath::DirectChild => 0,
                TreeEdgePath::LegacyVia(node) => u64::from(node).saturating_add(1),
            };
            (candidate.pressure, candidate.route_cost, mode_order)
        });

        let mut bindings = self.tree_edge_bindings.lock();
        prune_tree_edge_bindings(&mut bindings, key, policy.idle_reset, now);
        let binding = bindings.entry(key).or_insert(TreeEdgeBinding {
            path: TreeEdgePath::DirectChild,
            entered_at: now,
            last_used_at: now,
            challenger: None,
            challenger_since: None,
            challenger_observations: 0,
            pending: Some((TreeEdgePath::DirectChild, "initial")),
            pending_held: Duration::ZERO,
            pending_confirmation: Duration::ZERO,
            generation: 1,
            bound: false,
            no_alternate_reported: false,
        });

        let direct = candidate_for(&candidates, TreeEdgePath::DirectChild);
        let incumbent = candidate_for(&candidates, binding.path);

        if !binding.bound
            && binding.pending == Some((TreeEdgePath::DirectChild, "initial"))
            && direct.is_none_or(|candidate| candidate.pressure >= 3)
            && let Some(replacement) =
                best_legacy_candidate(&candidates, None).filter(|candidate| candidate.pressure < 3)
        {
            binding.pending = Some((replacement.path, "transport_unavailable"));
        }
        if let Some((path, reason)) = binding.pending {
            return TreeEdgeAttempt {
                key,
                path,
                generation: binding.generation,
                reason,
                incumbent_pressure: incumbent.map(|candidate| candidate.pressure),
                chosen_pressure: candidate_for(&candidates, path)
                    .map(|candidate| candidate.pressure),
            };
        }

        // A missing, closed, or fully pressured incumbent is a hard failure.
        // Direct is preferred when escaping a failed fallback; otherwise use
        // the deterministically best usable alternate.
        if incumbent.is_none_or(|candidate| candidate.pressure >= 3) {
            let replacement = match binding.path {
                TreeEdgePath::LegacyVia(_) => direct
                    .filter(|candidate| candidate.pressure < 3)
                    .or_else(|| best_legacy_candidate(&candidates, Some(binding.path))),
                TreeEdgePath::DirectChild => best_legacy_candidate(&candidates, None),
            };
            if let Some(replacement) = replacement.filter(|candidate| candidate.pressure < 3) {
                begin_tree_edge_transition(binding, replacement.path, "transport_unavailable", now);
            } else {
                clear_tree_edge_challenger(binding);
                record_no_tree_edge_alternate(key, binding);
            }
            let (path, reason) = binding.pending.unwrap_or((binding.path, "no_alternate"));
            return TreeEdgeAttempt {
                key,
                path,
                generation: binding.generation,
                reason,
                incumbent_pressure: incumbent.map(|candidate| candidate.pressure),
                chosen_pressure: candidate_for(&candidates, path)
                    .map(|candidate| candidate.pressure),
            };
        }

        let challenger = match binding.path {
            TreeEdgePath::DirectChild => {
                if incumbent.is_some_and(|candidate| candidate.pressure >= 2) {
                    best_legacy_candidate(&candidates, None).filter(|candidate| {
                        incumbent.is_some_and(|current| candidate.pressure < current.pressure)
                    })
                } else {
                    None
                }
            }
            TreeEdgePath::LegacyVia(_) => {
                if direct.is_some_and(|candidate| candidate.pressure <= 1) {
                    direct
                } else {
                    best_legacy_candidate(&candidates, Some(binding.path)).filter(|candidate| {
                        incumbent.is_some_and(|current| candidate.pressure < current.pressure)
                    })
                }
            }
        };

        if let Some(challenger) = challenger {
            observe_tree_edge_challenger(binding, challenger.path, now);
            if now.saturating_duration_since(binding.entered_at) >= policy.min_hold
                && binding.challenger_observations >= 2
                && binding.challenger_since.is_some_and(|since| {
                    now.saturating_duration_since(since) >= policy.challenger_confirm
                })
            {
                begin_tree_edge_transition(
                    binding,
                    challenger.path,
                    if challenger.path == TreeEdgePath::DirectChild {
                        "recovered"
                    } else {
                        "confirmed_challenger"
                    },
                    now,
                );
            }
        } else {
            clear_tree_edge_challenger(binding);
        }

        let (path, reason) = binding.pending.unwrap_or((binding.path, "incumbent"));
        TreeEdgeAttempt {
            key,
            path,
            generation: binding.generation,
            reason,
            incumbent_pressure: incumbent.map(|candidate| candidate.pressure),
            chosen_pressure: candidate_for(&candidates, path).map(|candidate| candidate.pressure),
        }
    }

    pub(crate) fn hard_escape_tree_edge(
        &self,
        attempt: TreeEdgeAttempt,
        mut candidates: Vec<TreeEdgeCandidate>,
        reason: &'static str,
        now: Instant,
    ) -> Option<TreeEdgeAttempt> {
        candidates.sort_by_key(|candidate| {
            (
                candidate.pressure,
                candidate.route_cost,
                match candidate.path {
                    TreeEdgePath::DirectChild => 0,
                    TreeEdgePath::LegacyVia(node) => u64::from(node).saturating_add(1),
                },
            )
        });
        let mut bindings = self.tree_edge_bindings.lock();
        let binding = bindings.get_mut(&attempt.key)?;
        if binding.generation != attempt.generation {
            if binding.path != attempt.path
                && let Some(current) = candidate_for(&candidates, binding.path)
                    .filter(|candidate| candidate.pressure < 3)
            {
                return Some(TreeEdgeAttempt {
                    key: attempt.key,
                    path: current.path,
                    generation: binding.generation,
                    reason,
                    incumbent_pressure: candidate_for(&candidates, attempt.path)
                        .map(|candidate| candidate.pressure),
                    chosen_pressure: Some(current.pressure),
                });
            }
            // A sibling completion may have committed the same pending path.
            // Its rejection still needs one escape retry, but it must create a
            // fresh generation rather than completing the stale decision.
        }
        binding.pending = None;
        let replacement = match attempt.path {
            TreeEdgePath::LegacyVia(_) => candidate_for(&candidates, TreeEdgePath::DirectChild)
                .filter(|candidate| candidate.pressure < 3)
                .or_else(|| best_legacy_candidate(&candidates, Some(attempt.path))),
            TreeEdgePath::DirectChild => best_legacy_candidate(&candidates, None),
        }
        .filter(|candidate| candidate.pressure < 3);
        let Some(replacement) = replacement else {
            record_no_tree_edge_alternate(attempt.key, binding);
            return None;
        };
        begin_tree_edge_transition(binding, replacement.path, reason, now);
        Some(TreeEdgeAttempt {
            key: attempt.key,
            path: replacement.path,
            generation: binding.generation,
            reason,
            incumbent_pressure: candidate_for(&candidates, attempt.path)
                .map(|candidate| candidate.pressure),
            chosen_pressure: Some(replacement.pressure),
        })
    }

    pub(crate) fn complete_tree_edge_attempt(
        &self,
        attempt: TreeEdgeAttempt,
        success: bool,
        now: Instant,
    ) {
        let mut bindings = self.tree_edge_bindings.lock();
        let Some(binding) = bindings.get_mut(&attempt.key) else {
            return;
        };
        if binding.generation != attempt.generation {
            return;
        }
        if !success {
            if binding
                .pending
                .is_some_and(|(path, _)| path == attempt.path)
            {
                binding.pending = None;
                binding.generation = binding.generation.wrapping_add(1).max(1);
            }
            return;
        }

        let previous = binding.bound.then_some(binding.path);
        let changed = previous != Some(attempt.path);
        if !changed {
            binding.last_used_at = now;
            binding.no_alternate_reported = false;
            return;
        }
        let held_for = binding.pending_held;
        let confirmation_for = binding.pending_confirmation;
        binding.path = attempt.path;
        binding.entered_at = changed.then_some(now).unwrap_or(binding.entered_at);
        binding.last_used_at = now;
        binding.bound = true;
        binding.no_alternate_reported = false;
        binding.pending = None;
        clear_tree_edge_challenger(binding);
        binding.generation = binding.generation.wrapping_add(1).max(1);
        if changed {
            distribution_metrics::update_tree_edge_binding(
                attempt.key.parent,
                attempt.key.child,
                previous.map(TreeEdgePath::mode_label),
                Some(attempt.path.mode_label()),
            );
            distribution_metrics::record_tree_edge_binding_event(
                attempt.key.parent,
                attempt.key.child,
                previous.map(TreeEdgePath::mode_label).unwrap_or("none"),
                attempt.path.mode_label(),
                attempt.reason,
            );
            debug!(
                source = %attempt.key.parent,
                peer = %attempt.key.child,
                from_mode = previous.map(TreeEdgePath::mode_label).unwrap_or("none"),
                to_mode = attempt.path.mode_label(),
                reason = attempt.reason,
                held_ms = held_for.as_millis(),
                confirmation_ms = confirmation_for.as_millis(),
                incumbent_pressure = ?attempt.incumbent_pressure,
                chosen_pressure = ?attempt.chosen_pressure,
                chosen_peer = %match attempt.path {
                    TreeEdgePath::DirectChild => attempt.key.child,
                    TreeEdgePath::LegacyVia(first_hop) => first_hop,
                },
                "voice tree edge binding changed"
            );
        }
    }

    pub(crate) fn configure_recovery(self: &Arc<Self>, sender: RecoverySender) {
        *self.recovery_sender.lock() = Some(sender);
        *self.self_ref.lock() = Arc::downgrade(self);
    }

    pub(crate) fn cached_candidate(
        &self,
        key: TreeKey,
        routing_generation: u64,
    ) -> Option<SelectedTree> {
        self.candidates
            .lock()
            .get(&TreeScope::from(key))
            .filter(|candidate| candidate.routing_generation == routing_generation)
            .filter(|candidate| candidate.recheck_at.is_none_or(|at| Instant::now() < at))
            .map(|candidate| SelectedTree {
                key: candidate.key,
                state: Arc::new(candidate.state.clone()),
                legacy_members: Arc::new(candidate.legacy_members.clone()),
            })
    }

    pub(crate) fn prepare_routing_generation(&self, key: TreeKey, routing_generation: u64) {
        let scope = StableTreeScope::from(key);
        self.prune_scope_state(scope);
        let previous_generation = self
            .routing_generations
            .lock()
            .insert(scope, routing_generation);
        let generation_changed = previous_generation != Some(routing_generation);
        let structural_change = self
            .active_trees
            .lock()
            .get(&scope)
            .is_some_and(|active| active.key.topology_epoch != key.topology_epoch);
        if generation_changed || structural_change {
            distribution_metrics::record_candidate_trigger(
                key.profile,
                if previous_generation.is_none() {
                    "group"
                } else if structural_change {
                    "topology"
                } else {
                    "routing"
                },
            );
        }
        if structural_change {
            // A topology epoch proves that service-eligible adjacency changed.
            // Metric-only recomputes are not evidence that a failed edge healed;
            // those exclusions clear only after a successful direct send or TTL.
            self.failed_edges.lock().remove(&scope);
        }
    }

    #[cfg(test)]
    pub(crate) fn stage_candidate(
        &self,
        key: TreeKey,
        candidate: TreeState,
        path_cost: u64,
        routing_generation: u64,
    ) -> Option<SelectedTree> {
        self.stage_candidate_with_legacy(
            key,
            candidate,
            path_cost,
            routing_generation,
            HashSet::new(),
        )
    }

    pub(crate) fn stage_candidate_with_legacy(
        &self,
        key: TreeKey,
        candidate: TreeState,
        path_cost: u64,
        routing_generation: u64,
        legacy_members: HashSet<NodeIdentifier>,
    ) -> Option<SelectedTree> {
        distribution_metrics::record_candidate_build(key.profile, "attempt");
        if !candidate.is_valid(key.source) {
            distribution_metrics::record_candidate_build(key.profile, "invalid");
            return None;
        }
        let stable_scope = StableTreeScope::from(key);
        self.prepare_routing_generation(key, routing_generation);
        let stale_keys = {
            let current_scope = TreeScope::from(key);
            let mut candidates = self.candidates.lock();
            let stale: Vec<_> = candidates
                .iter()
                .filter_map(|(scope, candidate)| {
                    (scope != &current_scope
                        && scope.source == stable_scope.source
                        && scope.profile == stable_scope.profile
                        && scope.group == stable_scope.group
                        && scope.group_version == stable_scope.group_version)
                        .then_some(candidate.key)
                })
                .collect();
            candidates.retain(|scope, _| {
                scope == &current_scope
                    || scope.source != stable_scope.source
                    || scope.profile != stable_scope.profile
                    || scope.group != stable_scope.group
                    || scope.group_version != stable_scope.group_version
            });
            stale
        };
        if !stale_keys.is_empty() {
            let mut pending = self.pending.lock();
            for stale_key in stale_keys {
                pending.remove(&stale_key);
            }
        }
        let currently_failed = self.failed_edges(key);
        if let Some(active) = self.active_trees.lock().get(&stable_scope).cloned() {
            let topology_changed = active.key.topology_epoch != key.topology_epoch;
            let capability_changed = active.legacy_members != legacy_members;
            if !topology_changed
                && same_tree_structure(&active.state, &candidate)
                && active.legacy_members == legacy_members
            {
                self.candidates.lock().insert(
                    TreeScope::from(key),
                    CandidateTree {
                        key: active.key,
                        state: active.state.clone(),
                        path_cost: active.path_cost,
                        routing_generation,
                        recheck_at: None,
                        legacy_members: active.legacy_members.clone(),
                    },
                );
                self.metric_proposals.lock().remove(&stable_scope);
                return Some(SelectedTree {
                    key: active.key,
                    state: Arc::new(active.state.clone()),
                    legacy_members: Arc::new(active.legacy_members.clone()),
                });
            }
            let failed_replacement = active.state.edges().any(|edge| {
                currently_failed.contains(&edge)
                    && active.applied_failures.contains(&edge)
                    && !candidate
                        .edges()
                        .any(|candidate_edge| candidate_edge == edge)
            });
            let improved = path_cost.saturating_mul(100)
                <= active
                    .path_cost
                    .saturating_mul(100 - METRIC_RESHAPE_IMPROVEMENT_PERCENT);
            let metric_ready = if improved {
                let mut proposals = self.metric_proposals.lock();
                let proposal = proposals
                    .entry(stable_scope)
                    .or_insert_with(|| MetricProposal {
                        state: candidate.clone(),
                        path_cost,
                        first_seen: Instant::now(),
                    });
                if !same_tree_structure(&proposal.state, &candidate) {
                    *proposal = MetricProposal {
                        state: candidate.clone(),
                        path_cost,
                        first_seen: Instant::now(),
                    };
                } else {
                    proposal.path_cost = path_cost;
                }
                proposal.first_seen.elapsed() >= METRIC_RESHAPE_HOLD
            } else {
                self.metric_proposals.lock().remove(&stable_scope);
                false
            };
            if !topology_changed && !capability_changed && !failed_replacement && !metric_ready {
                distribution_metrics::record_hysteresis_hold(key.profile);
                self.candidates.lock().insert(
                    TreeScope::from(key),
                    CandidateTree {
                        key: active.key,
                        state: active.state.clone(),
                        path_cost: active.path_cost,
                        routing_generation,
                        recheck_at: improved.then(|| {
                            self.metric_proposals
                                .lock()
                                .get(&stable_scope)
                                .expect("improved metric proposal installed")
                                .first_seen
                                + METRIC_RESHAPE_HOLD
                        }),
                        legacy_members: active.legacy_members.clone(),
                    },
                );
                return Some(SelectedTree {
                    key: active.key,
                    state: Arc::new(active.state.clone()),
                    legacy_members: Arc::new(active.legacy_members.clone()),
                });
            }
        }
        self.metric_proposals.lock().remove(&stable_scope);
        let selected = SelectedTree {
            key,
            state: Arc::new(candidate.clone()),
            legacy_members: Arc::new(legacy_members.clone()),
        };
        self.candidates.lock().insert(
            TreeScope::from(key),
            CandidateTree {
                key,
                state: candidate,
                path_cost,
                routing_generation,
                recheck_at: None,
                legacy_members,
            },
        );
        distribution_metrics::record_candidate_build(key.profile, "staged");
        Some(selected)
    }

    fn prune_scope_state(&self, current: StableTreeScope) {
        let stale = |scope: &StableTreeScope| {
            scope.source == current.source
                && scope.profile == current.profile
                && scope.group == current.group
                && scope.group_version != current.group_version
        };
        self.active_trees.lock().retain(|scope, _| !stale(scope));
        self.failed_edges.lock().retain(|scope, _| !stale(scope));
        self.metric_proposals
            .lock()
            .retain(|scope, _| !stale(scope));
        self.routing_generations
            .lock()
            .retain(|scope, _| !stale(scope));
        self.scope_activity.lock().retain(|scope, _| {
            scope.source != current.source
                || scope.profile != current.profile
                || scope.group != current.group
                || scope.group_version == current.group_version
        });
        self.candidates.lock().retain(|scope, _| {
            !(scope.source == current.source
                && scope.profile == current.profile
                && scope.group == current.group
                && scope.group_version != current.group_version)
        });
        self.pending.lock().retain(|key, _| {
            key.source != current.source
                || key.profile != current.profile
                || key.group != current.group
                || key.group_version == current.group_version
        });
        self.versions.lock().retain(|scope, _| {
            scope.source != current.source
                || scope.profile != current.profile
                || scope.group != current.group
                || scope.group_version == current.group_version
        });
        self.trees.lock().retain(|key, _| {
            key.source != current.source
                || key.profile != current.profile
                || key.group != current.group
                || key.group_version == current.group_version
        });
        let mut removed_bindings = Vec::new();
        self.tree_edge_bindings.lock().retain(|key, binding| {
            let stale = key.source == current.source
                && key.profile == current.profile
                && key.group == current.group
                && key.group_version != current.group_version;
            if stale && binding.bound {
                removed_bindings.push((*key, binding.path));
            }
            !stale
        });
        for (key, path) in removed_bindings {
            distribution_metrics::update_tree_edge_binding(
                key.parent,
                key.child,
                Some(path.mode_label()),
                None,
            );
        }
        let now = Instant::now();
        self.failure_reported_at.lock().retain(|_, reported_at| {
            now.saturating_duration_since(*reported_at) < EDGE_FAILURE_REPORT_DEDUP
        });
    }

    fn prune_tree_edge_bindings_for_tree(&self, key: TreeKey, state: &TreeState) {
        let edges: HashSet<_> = state.edges().collect();
        let mut removed = Vec::new();
        self.tree_edge_bindings
            .lock()
            .retain(|binding_key, binding| {
                let in_scope = binding_key.source == key.source
                    && binding_key.profile == key.profile
                    && binding_key.group == key.group
                    && binding_key.group_version == key.group_version;
                let keep = !in_scope || edges.contains(&(binding_key.parent, binding_key.child));
                if !keep && binding.bound {
                    removed.push((*binding_key, binding.path));
                }
                keep
            });
        for (binding_key, path) in removed {
            distribution_metrics::update_tree_edge_binding(
                binding_key.parent,
                binding_key.child,
                Some(path.mode_label()),
                None,
            );
        }
    }

    pub(crate) fn active_tree(&self, key: TreeKey) -> Option<SelectedTree> {
        self.active_trees
            .lock()
            .get(&StableTreeScope::from(key))
            .map(|active| SelectedTree {
                key: active.key,
                state: Arc::new(active.state.clone()),
                legacy_members: Arc::new(active.legacy_members.clone()),
            })
    }

    pub(crate) fn failed_edges(&self, key: TreeKey) -> HashSet<(NodeIdentifier, NodeIdentifier)> {
        let now = Instant::now();
        let mut failures = self.failed_edges.lock();
        let Some(edges) = failures.get_mut(&StableTreeScope::from(key)) else {
            return HashSet::new();
        };
        edges.retain(|_, failed_at| {
            now.saturating_duration_since(*failed_at) < FAILED_EDGE_EXCLUSION
        });
        edges.keys().copied().collect()
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
        let scope = StableTreeScope::from(key);
        let previous = self
            .failed_edges
            .lock()
            .entry(scope)
            .or_default()
            .insert((parent, child), now);
        if previous.is_some_and(|failed_at| {
            now.saturating_duration_since(failed_at) < FAILED_EDGE_EXCLUSION
        }) {
            return;
        }
        distribution_metrics::record_candidate_trigger(key.profile, "failed_edge");
        let invalidated: Vec<_> = self
            .candidates
            .lock()
            .iter()
            .filter_map(|(candidate_scope, candidate)| {
                (candidate_scope.source == scope.source
                    && candidate_scope.profile == scope.profile
                    && candidate_scope.group == scope.group
                    && candidate_scope.group_version == scope.group_version
                    && candidate.state.edges().any(|edge| edge == (parent, child)))
                .then_some(candidate.key)
            })
            .collect();
        self.candidates.lock().retain(|candidate_scope, _| {
            candidate_scope.source != scope.source
                || candidate_scope.profile != scope.profile
                || candidate_scope.group != scope.group
                || candidate_scope.group_version != scope.group_version
        });
        let mut pending = self.pending.lock();
        for invalidated_key in invalidated {
            pending.remove(&invalidated_key);
        }
        drop(pending);
        if let Some(active) = self
            .active_trees
            .lock()
            .get_mut(&StableTreeScope::from(key))
        {
            active.applied_failures.insert((parent, child));
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

    pub(crate) fn record_edge_success(
        &self,
        key: TreeKey,
        parent: NodeIdentifier,
        child: NodeIdentifier,
    ) {
        let scope = StableTreeScope::from(key);
        let mut failures = self.failed_edges.lock();
        if let Some(edges) = failures.get_mut(&scope) {
            edges.remove(&(parent, child));
            if edges.is_empty() {
                failures.remove(&scope);
            }
        }
        drop(failures);
        if let Some(active) = self.active_trees.lock().get_mut(&scope) {
            active.applied_failures.remove(&(parent, child));
        }
    }

    pub(crate) fn install(&self, key: TreeKey, state: TreeState) -> Vec<PendingDistributionFrame> {
        self.try_install(key, state).unwrap_or_default()
    }

    fn try_install(&self, key: TreeKey, state: TreeState) -> Option<Vec<PendingDistributionFrame>> {
        if !state.is_valid(key.source) {
            distribution_metrics::record_candidate_build(key.profile, "invalid_install");
            return None;
        }
        self.prune_scope_state(StableTreeScope::from(key));
        self.prune_install_scopes(key);
        self.prune_tree_edge_bindings_for_tree(key, &state);
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
        Some(recovered)
    }

    fn prune_install_scopes(&self, key: TreeKey) {
        let current = TreeScope::from(key);
        let stable = StableTreeScope::from(key);
        let active_scope = self
            .active_trees
            .lock()
            .get(&stable)
            .map(|active| TreeScope::from(active.key));
        let stale = {
            let mut activity = self.scope_activity.lock();
            activity.insert(current, Instant::now());
            let mut matching: Vec<_> = activity
                .iter()
                .filter(|(scope, _)| {
                    scope.source == stable.source
                        && scope.profile == stable.profile
                        && scope.group == stable.group
                        && scope.group_version == stable.group_version
                })
                .map(|(scope, at)| (*scope, *at))
                .collect();
            matching.sort_unstable_by_key(|(_, at)| std::cmp::Reverse(*at));
            let mut retained: HashSet<_> = matching
                .iter()
                .take(RETAINED_VERSIONS)
                .map(|(scope, _)| *scope)
                .collect();
            retained.insert(current);
            retained.extend(active_scope);
            let stale: HashSet<_> = matching
                .into_iter()
                .map(|(scope, _)| scope)
                .filter(|scope| !retained.contains(scope))
                .collect();
            activity.retain(|scope, _| !stale.contains(scope));
            stale
        };
        if stale.is_empty() {
            return;
        }
        self.versions
            .lock()
            .retain(|scope, _| !stale.contains(scope));
        self.trees
            .lock()
            .retain(|tree_key, _| !stale.contains(&TreeScope::from(*tree_key)));
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
        #[cfg(test)]
        {
            *self.control_publishes.lock() += 1;
        }
        distribution_metrics::record_control_publish(key.profile);
        distribution_metrics::set_pending_acks(key.profile, remaining_count);
        if remaining_count == 0 {
            self.activate_candidate(key);
        }
        true
    }

    #[cfg(test)]
    pub(crate) fn control_publish_count_for_test(&self) -> u64 {
        *self.control_publishes.lock()
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

    pub(crate) fn expire_candidate(&self, key: TreeKey) {
        self.abort_publish(key);
        let scope = TreeScope::from(key);
        self.candidates
            .lock()
            .retain(|candidate_scope, candidate| candidate_scope != &scope || candidate.key != key);
    }

    pub(crate) fn pending_peers(&self, key: TreeKey) -> Vec<NodeIdentifier> {
        self.pending
            .lock()
            .get(&key)
            .map(|pending| pending.remaining.iter().copied().collect())
            .unwrap_or_default()
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
            self.activate_candidate(key);
        }
    }

    fn activate_candidate(&self, key: TreeKey) {
        let scope = TreeScope::from(key);
        let candidate = self.candidates.lock().get(&scope).cloned();
        let Some(candidate) = candidate else { return };
        if candidate.key != key {
            return;
        }
        let failed_edges = self.failed_edges(key);
        if candidate
            .state
            .edges()
            .any(|edge| failed_edges.contains(&edge))
        {
            self.pending.lock().remove(&key);
            return;
        }
        let applied_failures = failed_edges
            .into_iter()
            .filter(|failed| !candidate.state.edges().any(|edge| edge == *failed))
            .collect();
        self.prune_tree_edge_bindings_for_tree(key, &candidate.state);
        self.active_trees.lock().insert(
            StableTreeScope::from(key),
            ActiveTree {
                key,
                state: candidate.state,
                path_cost: candidate.path_cost,
                applied_failures,
                legacy_members: candidate.legacy_members,
            },
        );
        self.pending.lock().remove(&key);
        distribution_metrics::set_pending_acks(key.profile, 0);
        distribution_metrics::record_activation(key.profile);
        self.record_activated_version(key);
    }

    #[cfg(test)]
    pub(crate) fn is_ready(&self, key: TreeKey) -> bool {
        self.active_tree(key)
            .is_some_and(|active| active.key() == key)
            || self
                .pending
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
    for value in std::iter::once(u64::from(source))
        .chain([
            u64::from(profile),
            group,
            group_version,
            topology_epoch,
            state
                .hop_ttl()
                .map(|ttl| ttl.as_millis().min(u128::from(u64::MAX)) as u64)
                .unwrap_or_default(),
        ])
        .chain(members.into_iter().map(u64::from))
        .chain(
            edges
                .into_iter()
                .flat_map(|(parent, child)| [u64::from(parent), u64::from(child)]),
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
                // Reserved wire field for mixed-version compatibility. New
                // senders intentionally do not publish playout policy.
                playout_delays: Vec::new(),
                edges: state
                    .edges()
                    .map(|(parent, child)| pb::OverlayTreeEdge {
                        parent: parent.into(),
                        child: child.into(),
                    })
                    .collect(),
                hop_ttl_ms: state
                    .hop_ttl()
                    .map(|ttl| ttl.as_millis().min(u128::from(u32::MAX)) as u32)
                    .unwrap_or_default(),
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

fn installed_tree_state(
    source: NodeIdentifier,
    install: &pb::DistributionTreeInstall,
) -> TreeState {
    let members = install
        .members
        .iter()
        .filter_map(|node| NodeIdentifier::try_from(*node).ok());
    let edges = install.edges.iter().filter_map(|edge| {
        Some((
            NodeIdentifier::try_from(edge.parent).ok()?,
            NodeIdentifier::try_from(edge.child).ok()?,
        ))
    });
    // `playout_delays` remains decodable on the wire for mixed deployments,
    // but remote playout is no longer a distribution-tree concern.
    let state = TreeState::new(source, members, edges);
    if install.hop_ttl_ms == 0 {
        state
    } else {
        state.with_hop_ttl(Duration::from_millis(u64::from(install.hop_ttl_ms)))
    }
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
                    let key = TreeKey {
                        source,
                        profile: install.profile,
                        group: install.group,
                        group_version: install.group_version,
                        topology_epoch: install.topology_epoch,
                        version: install.version,
                    };
                    let Some(recovered) =
                        plane.try_install(key, installed_tree_state(source, &install))
                    else {
                        return;
                    };
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
                    if reporter != node {
                        return;
                    }
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

    #[cfg(feature = "pre-release-workload")]
    #[test]
    fn pre_release_service_selects_reliable_generic_profile() {
        let profile = profile_for_service(super::super::PRE_RELEASE_DISTRIBUTION_SERVICE_TAG)
            .expect("pre-release distribution profile");
        assert_eq!(profile.id(), PRE_RELEASE_RELIABLE_PROFILE_ID);
        assert_eq!(profile.level(), ServiceLevel::ReliableLowLatency);
        assert_eq!(profile.metric(), RoutingMetric::ReliableLowLatencyCost);
        assert!(profile_for_service(crate::application::proto::VOICE_SERVICE_TAG).is_some());
    }

    #[cfg(feature = "pre-release-workload")]
    #[test]
    fn candidate_trigger_counts_distinct_routing_generations() {
        let plane = DistributionPlane::default();
        let mut candidate = key(77, 1);
        candidate.profile = PRE_RELEASE_RELIABLE_PROFILE_ID;
        let before = distribution_metrics::pre_release_counters().3;

        plane.prepare_routing_generation(candidate, 10);
        plane.prepare_routing_generation(candidate, 10);
        plane.prepare_routing_generation(candidate, 11);

        assert_eq!(distribution_metrics::pre_release_counters().3 - before, 2);
    }

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

    fn sticky_policy() -> TreeEdgeStickinessPolicy {
        TreeEdgeStickinessPolicy::new(
            Duration::from_millis(750),
            Duration::from_millis(500),
            Duration::from_secs(2),
        )
    }

    #[test]
    fn tree_edge_soft_switch_requires_hold_and_stable_challenger() {
        let plane = DistributionPlane::default();
        let tree_key = key(90, 1);
        let start = Instant::now();
        let initial = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct(1)],
            sticky_policy(),
            start,
        );
        assert_eq!(initial.path(), TreeEdgePath::DirectChild);
        plane.complete_tree_edge_attempt(initial, true, start);

        let candidates = || {
            vec![
                TreeEdgeCandidate::direct(2),
                TreeEdgeCandidate::legacy(3, 1, 10),
            ]
        };
        let first = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            candidates(),
            sticky_policy(),
            start + Duration::from_millis(249),
        );
        assert_eq!(first.path(), TreeEdgePath::DirectChild);
        let before = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            candidates(),
            sticky_policy(),
            start + Duration::from_millis(749),
        );
        assert_eq!(before.path(), TreeEdgePath::DirectChild);
        let confirmed = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            candidates(),
            sticky_policy(),
            start + Duration::from_millis(750),
        );
        assert_eq!(confirmed.path(), TreeEdgePath::LegacyVia(3));
        assert_eq!(confirmed.reason, "confirmed_challenger");
    }

    #[test]
    fn tree_edge_challenger_change_resets_confirmation() {
        let plane = DistributionPlane::default();
        let tree_key = key(91, 1);
        let start = Instant::now();
        let initial = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct(1)],
            sticky_policy(),
            start,
        );
        plane.complete_tree_edge_attempt(initial, true, start);
        let at = |ms| start + Duration::from_millis(ms);
        let _ = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![
                TreeEdgeCandidate::direct(2),
                TreeEdgeCandidate::legacy(3, 1, 1),
            ],
            sticky_policy(),
            at(750),
        );
        let changed = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![
                TreeEdgeCandidate::direct(2),
                TreeEdgeCandidate::legacy(4, 1, 1),
            ],
            sticky_policy(),
            at(1_250),
        );
        assert_eq!(changed.path(), TreeEdgePath::DirectChild);
        let not_yet = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![
                TreeEdgeCandidate::direct(2),
                TreeEdgeCandidate::legacy(4, 1, 1),
            ],
            sticky_policy(),
            at(1_749),
        );
        assert_eq!(not_yet.path(), TreeEdgePath::DirectChild);
        let confirmed = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![
                TreeEdgeCandidate::direct(2),
                TreeEdgeCandidate::legacy(4, 1, 1),
            ],
            sticky_policy(),
            at(1_750),
        );
        assert_eq!(confirmed.path(), TreeEdgePath::LegacyVia(4));
    }

    #[test]
    fn tree_edge_idle_reset_and_stale_completion_are_deterministic() {
        let plane = DistributionPlane::default();
        let tree_key = key(92, 1);
        let start = Instant::now();
        let stale = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct(1)],
            sticky_policy(),
            start,
        );
        plane.complete_tree_edge_attempt(stale, true, start);
        plane.complete_tree_edge_attempt(stale, true, start + Duration::from_millis(10));
        assert_eq!(
            plane.current_tree_edge_path(tree_key, 1, 2),
            Some(TreeEdgePath::DirectChild)
        );

        let reset = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![TreeEdgeCandidate::direct(1)],
            sticky_policy(),
            start + Duration::from_secs(2),
        );
        assert_eq!(reset.path(), TreeEdgePath::DirectChild);
        assert_eq!(reset.reason, "initial");
    }

    #[test]
    fn hard_escape_prefers_direct_then_deterministic_fallback() {
        let plane = DistributionPlane::default();
        let tree_key = key(93, 1);
        let start = Instant::now();
        let direct = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![
                TreeEdgeCandidate::direct(3),
                TreeEdgeCandidate::legacy(4, 1, 20),
                TreeEdgeCandidate::legacy(3, 1, 10),
            ],
            sticky_policy(),
            start,
        );
        assert_eq!(direct.path(), TreeEdgePath::LegacyVia(3));
        plane.complete_tree_edge_attempt(direct, true, start);

        let failed_fallback = plane.choose_tree_edge(
            tree_key,
            1,
            2,
            vec![
                TreeEdgeCandidate::direct(1),
                TreeEdgeCandidate::legacy(3, 3, 10),
            ],
            sticky_policy(),
            start + Duration::from_millis(1),
        );
        assert_eq!(failed_fallback.path(), TreeEdgePath::DirectChild);
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

    fn state_with_ignored_playout(delay_ms: u64) -> TreeState {
        TreeState::new_with_playout(1, [2], [(1, 2)], [(2, delay_ms)])
    }

    #[test]
    fn ignored_playout_metadata_does_not_change_exact_tree_version() {
        let plain = state();
        let with_legacy_metadata = state_with_ignored_playout(120);
        assert_eq!(
            tree_version(1, VOICE_REALTIME_PROFILE_ID, 1, 1, 1, &plain),
            tree_version(1, VOICE_REALTIME_PROFILE_ID, 1, 1, 1, &with_legacy_metadata)
        );
    }

    #[test]
    fn install_ignores_legacy_playout_metadata() {
        let install = pb::DistributionTreeInstall {
            source: 1,
            members: vec![2],
            edges: vec![pb::OverlayTreeEdge {
                parent: 1,
                child: 2,
            }],
            playout_delays: vec![pb::DistributionTreePlayoutDelay {
                node: 2,
                delay_ms: 750,
            }],
            ..Default::default()
        };
        let installed = installed_tree_state(1, &install);

        assert_eq!(installed.children(1), &[2]);
        assert!(installed.is_member(2));
        assert_eq!(
            tree_version(1, VOICE_REALTIME_PROFILE_ID, 1, 1, 1, &installed),
            tree_version(1, VOICE_REALTIME_PROFILE_ID, 1, 1, 1, &state())
        );
    }

    #[test]
    fn install_encoding_leaves_legacy_playout_metadata_empty() {
        let control = pb::DistributionControl::decode(encode_install(key(1, 1), &state())).unwrap();
        let Some(pb::distribution_control::Body::Install(install)) = control.body else {
            panic!("expected tree install");
        };

        assert!(install.playout_delays.is_empty());
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
    fn structural_replacement_keeps_active_until_candidate_acknowledged() {
        let plane = DistributionPlane::default();
        let initial_key = key(1, 1);
        let initial = state_with_ignored_playout(100);
        plane
            .stage_candidate(initial_key, initial.clone(), 100, 1)
            .unwrap();
        plane.install(initial_key, initial);
        assert!(plane.begin_publish(initial_key, [2]));
        plane.acknowledge(initial_key, 2);
        plane.report_edge_failure(initial_key, 1, 2);

        let replacement = TreeState::new_with_playout(1, [2], [(1, 3), (3, 2)], [(2, 120)]);
        let replacement_key = key(1, 2);
        let selected = plane
            .stage_candidate(replacement_key, replacement.clone(), 120, 1)
            .unwrap();
        assert_eq!(selected.state().children(1), &[3]);
        assert_eq!(
            plane.active_tree(replacement_key).unwrap().key(),
            initial_key
        );
        plane.install(replacement_key, replacement);
        assert!(plane.begin_publish(replacement_key, [2, 3]));
        plane.acknowledge(replacement_key, 2);
        assert_eq!(
            plane.active_tree(replacement_key).unwrap().key(),
            initial_key
        );
        plane.acknowledge(replacement_key, 3);
        assert_eq!(
            plane.active_tree(replacement_key).unwrap().key(),
            replacement_key
        );

        let unchanged_topology = TreeState::new_with_playout(1, [2], [(1, 3), (3, 2)], [(2, 140)]);
        assert_eq!(
            plane
                .stage_candidate(key(1, 3), unchanged_topology, 140, 3)
                .unwrap()
                .state()
                .children(1),
            &[3],
            "ignored playout metadata does not republish an unchanged tree"
        );
    }

    #[test]
    fn topology_epoch_change_bypasses_metric_reshape_hysteresis() {
        let plane = DistributionPlane::default();
        let initial_key = key(1, 1);
        let initial = state();
        plane
            .stage_candidate(initial_key, initial.clone(), 100, 1)
            .unwrap();
        plane.install(initial_key, initial);
        assert!(plane.begin_publish(initial_key, [2]));
        plane.acknowledge(initial_key, 2);

        let replacement_key = TreeKey {
            topology_epoch: 2,
            version: 2,
            ..initial_key
        };
        let replacement = TreeState::new(1, [2], [(1, 3), (3, 2)]);
        let selected = plane
            .stage_candidate(replacement_key, replacement, 200, 2)
            .expect("structural replacement");

        assert_eq!(selected.key(), replacement_key);
        assert_eq!(
            plane.active_tree(replacement_key).unwrap().key(),
            initial_key
        );
    }

    #[test]
    fn routing_generation_invalidates_cached_candidate() {
        let plane = DistributionPlane::default();
        let current = key(1, 1);
        plane
            .stage_candidate(current, state(), 100, 41)
            .expect("initial candidate");
        assert!(plane.cached_candidate(current, 41).is_some());
        assert!(plane.cached_candidate(current, 42).is_none());
    }

    #[test]
    fn cached_candidate_preserves_legacy_branch_recipients() {
        let plane = DistributionPlane::default();
        let current = key(1, 1);
        plane
            .stage_candidate_with_legacy(current, state(), 100, 41, HashSet::from([7, 8]))
            .expect("initial candidate");

        let cached = plane.cached_candidate(current, 41).unwrap();
        assert_eq!(cached.legacy_members(), &HashSet::from([7, 8]));
    }

    #[test]
    fn metric_reshape_must_remain_improved_for_five_seconds() {
        let plane = DistributionPlane::default();
        let initial_key = key(1, 1);
        let initial = state();
        plane
            .stage_candidate(initial_key, initial.clone(), 100, 1)
            .unwrap();
        plane.install(initial_key, initial);
        assert!(plane.begin_publish(initial_key, [2]));
        plane.acknowledge(initial_key, 2);

        let replacement_key = key(1, 2);
        let replacement = TreeState::new(1, [2], [(1, 3), (3, 2)]);
        let held = plane
            .stage_candidate(replacement_key, replacement.clone(), 80, 2)
            .unwrap();
        assert_eq!(held.key(), initial_key);
        let scope = StableTreeScope::from(replacement_key);
        plane
            .metric_proposals
            .lock()
            .get_mut(&scope)
            .unwrap()
            .first_seen -= METRIC_RESHAPE_HOLD;
        plane
            .candidates
            .lock()
            .get_mut(&TreeScope::from(replacement_key))
            .unwrap()
            .recheck_at = Some(Instant::now() - Duration::from_millis(1));
        assert!(plane.cached_candidate(replacement_key, 2).is_none());
        let selected = plane
            .stage_candidate(replacement_key, replacement, 79, 2)
            .unwrap();
        assert_eq!(selected.key(), replacement_key);
    }

    #[test]
    fn successful_direct_edge_clears_failure_exclusion() {
        let plane = DistributionPlane::default();
        let current = key(1, 1);
        plane.install(current, state());
        plane.report_edge_failure(current, 1, 2);
        assert!(plane.failed_edges(current).contains(&(1, 2)));

        plane.record_edge_success(current, 1, 2);
        assert!(!plane.failed_edges(current).contains(&(1, 2)));
    }

    #[test]
    fn metric_routing_generation_preserves_failure_exclusion_hold() {
        let plane = DistributionPlane::default();
        let current = key(1, 1);
        plane.prepare_routing_generation(current, 10);
        plane.install(current, state());
        plane.report_edge_failure(current, 1, 2);
        assert!(plane.failed_edges(current).contains(&(1, 2)));

        plane.prepare_routing_generation(current, 11);
        assert!(plane.failed_edges(current).contains(&(1, 2)));
    }

    #[test]
    fn receiver_install_state_is_bounded_across_topology_epochs() {
        let plane = DistributionPlane::default();
        let base = key(1, 1);
        for topology_epoch in 1..=6 {
            let current = TreeKey {
                topology_epoch,
                version: topology_epoch,
                ..base
            };
            plane.install(current, state());
        }
        let matching_scopes = plane
            .scope_activity
            .lock()
            .keys()
            .filter(|scope| {
                scope.source == base.source
                    && scope.profile == base.profile
                    && scope.group == base.group
                    && scope.group_version == base.group_version
            })
            .count();
        assert!(matching_scopes <= RETAINED_VERSIONS);
        assert!(plane.get(base).is_none());
    }

    #[test]
    fn receiver_install_prunes_obsolete_group_version() {
        let plane = DistributionPlane::default();
        let old = key(1, 1);
        plane.install(old, state());
        let new = TreeKey {
            group_version: 2,
            version: 2,
            ..old
        };
        plane.install(new, state());
        assert!(plane.get(old).is_none());
        assert!(plane.get(new).is_some());
    }

    #[test]
    fn edge_failure_cancels_candidate_and_late_ack_cannot_activate_it() {
        let plane = DistributionPlane::default();
        let initial_key = key(1, 1);
        let initial = state();
        plane
            .stage_candidate(initial_key, initial.clone(), 100, 1)
            .unwrap();
        plane.install(initial_key, initial);
        assert!(plane.begin_publish(initial_key, [2]));
        plane.acknowledge(initial_key, 2);

        let replacement_key = TreeKey {
            topology_epoch: 2,
            version: 2,
            ..initial_key
        };
        let replacement = TreeState::new(1, [2], [(1, 3), (3, 2)]);
        plane
            .stage_candidate(replacement_key, replacement.clone(), 90, 2)
            .unwrap();
        plane.install(replacement_key, replacement);
        assert!(plane.begin_publish(replacement_key, [2, 3]));
        plane.report_edge_failure(replacement_key, 1, 3);
        plane.acknowledge(replacement_key, 2);
        plane.acknowledge(replacement_key, 3);
        assert_eq!(
            plane.active_tree(replacement_key).unwrap().key(),
            initial_key
        );
        assert!(plane.pending_peers(replacement_key).is_empty());
    }

    #[test]
    fn active_tree_and_two_predecessors_survive_until_replacement_activates() {
        let plane = DistributionPlane::default();
        let first = key(1, 1);
        let second = key(1, 2);
        let third = key(1, 3);
        let replacement = key(1, 4);
        for (generation, current) in [first, second, third].into_iter().enumerate() {
            let tree = state();
            plane.candidates.lock().insert(
                TreeScope::from(current),
                CandidateTree {
                    key: current,
                    state: tree.clone(),
                    path_cost: 100,
                    routing_generation: generation as u64 + 1,
                    recheck_at: None,
                    legacy_members: HashSet::new(),
                },
            );
            plane.install(current, tree);
            assert!(plane.begin_publish(current, [2]));
            plane.acknowledge(current, 2);
        }

        let replacement_state = state();
        plane.candidates.lock().insert(
            TreeScope::from(replacement),
            CandidateTree {
                key: replacement,
                state: replacement_state.clone(),
                path_cost: 100,
                routing_generation: 4,
                recheck_at: None,
                legacy_members: HashSet::new(),
            },
        );
        plane.install(replacement, replacement_state);
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
    fn control_publish_test_counter_is_plane_local() {
        let first = DistributionPlane::default();
        let second = DistributionPlane::default();

        assert!(first.begin_publish(key(12, 1), [2]));
        assert_eq!(first.control_publish_count_for_test(), 1);
        assert_eq!(second.control_publish_count_for_test(), 0);

        assert!(second.begin_publish(key(13, 1), [2]));
        assert_eq!(first.control_publish_count_for_test(), 1);
        assert_eq!(second.control_publish_count_for_test(), 1);
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
