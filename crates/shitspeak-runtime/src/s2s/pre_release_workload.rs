//! Opt-in workload embedded in real server processes for the serialized
//! 16-node pre-release gate. It is compiled out of ordinary builds.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use shitspeak_s2s::overlay::{
    OverlayInboundMessage, OverlayNetwork, OverlaySendOptions,
    PRE_RELEASE_DISTRIBUTION_SERVICE_TAG, RoutingMetric, ServiceInbound,
};
use shitspeak_s2s::replications::strict::{LogSlice, StrictLogEntry, StrictLogMetadata};
use shitspeak_s2s::replications::{ReplicationError, ReplicationManager, StrictReplicable};
use shitspeak_s2s::testing::{FaultSelector, LinkChaos, MessageType};
use shitspeak_s2s_transport::{MessageClass, ServiceLevel, TransportKind};

use crate::types::NodeIdentifier;

const TOPIC: &str = "pre-release/control-plane/v1";
const GROUP: u64 = 0x7072_656c_6561_7365;
const GROUP_VERSION: u64 = 1;
const SCORED_MARKER: &[u8] = b"PRTREE1:S:";
const UNSCORED_MARKER: &[u8] = b"PRTREE1:U:";

pub(super) fn enabled() -> bool {
    std::env::var_os("SHITSPEAK_PRE_RELEASE_ARTIFACT_PATH").is_some()
}

pub(super) fn configured_chaos(_local_node: NodeIdentifier) -> LinkChaos {
    LinkChaos::with_seed(env_u64("SHITSPEAK_PRE_RELEASE_SEED", 1))
}

pub(super) fn start(
    overlay: OverlayNetwork,
    replications: Arc<ReplicationManager>,
    chaos: Option<LinkChaos>,
    mut shutdown: watch::Receiver<()>,
) -> Option<JoinHandle<()>> {
    let artifact = PathBuf::from(std::env::var_os("SHITSPEAK_PRE_RELEASE_ARTIFACT_PATH")?);
    let node = overlay.local_node_id();
    let repo = WorkloadRepo::new();
    let strict = match replications.register_strict(TOPIC, repo.clone()) {
        Ok(handle) => handle,
        Err(error) => {
            tracing::error!(%error, "pre-release strict workload registration failed");
            return None;
        }
    };
    let mut restored = NodeEvidence::load_or_new(&artifact, node);
    // An interrupted task cannot survive a process restart.
    restored.strict_in_flight = 0;
    let metric_lsa_start = overlay.pre_release_metric_lsa_emissions();
    let activation_offset = restored.tree_activations;
    let candidate_offset = restored.candidate_builds;
    let candidate_trigger_offset = restored.candidate_trigger_changes;
    let fallback_offset = restored.whole_group_fallbacks_after_initial_activation;
    let distribution_start = overlay.pre_release_distribution_counters();
    let evidence = Arc::new(Mutex::new(restored));
    let delivery = Arc::new(WorkloadDelivery {
        evidence: evidence.clone(),
    });
    overlay.register_service(PRE_RELEASE_DISTRIBUTION_SERVICE_TAG, delivery);

    Some(tokio::spawn(async move {
        let boot_epoch = overlay.local_boot_epoch();
        let tree_source = env_node("SHITSPEAK_PRE_RELEASE_TREE_SOURCE", 1);
        let ack_sender = env_node("SHITSPEAK_PRE_RELEASE_ACK_DROP_SENDER", 3);
        let proposers = env_nodes("SHITSPEAK_PRE_RELEASE_STRICT_PROPOSERS", &[1, 8]);
        let mut tree_seq = 0_u64;
        let mut strict_seq = 0_u64;
        let mut observed_epoch = Some(overlay.pre_release_distribution_epoch());
        let mut activation_seen = false;
        let mut ack_drop_armed = evidence.lock().ack_drop_armed;
        let mut strict_acks_held = false;
        let mut fallback_baseline = distribution_start.1;
        let mut last_metric_lsa = metric_lsa_start;
        let mut tree_tick = tokio::time::interval(Duration::from_millis(250));
        let mut strict_tick = tokio::time::interval(Duration::from_secs(2));
        let mut persist_tick = tokio::time::interval(Duration::from_secs(1));
        tree_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        strict_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Let membership and the dedicated strict topic converge first.
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
            _ = shutdown.changed() => return,
        }

        loop {
            tokio::select! {
                _ = tree_tick.tick(), if node == tree_source => {
                    let control = workload_control(&artifact);
                    if !control.is_valid() {
                        continue;
                    }
                    evidence.lock().adopt_run(&control, node);
                    if !control.send_tree {
                        continue;
                    }
                    tree_seq = tree_seq.saturating_add(1);
                    let id = format!("{node}-{boot_epoch}-{tree_seq}");
                    let marker = if control.record_tree { SCORED_MARKER } else { UNSCORED_MARKER };
                    let mut payload = Vec::with_capacity(marker.len() + id.len());
                    payload.extend_from_slice(marker);
                    payload.extend_from_slice(id.as_bytes());
                    let body = Bytes::from(payload);
                    let recipients: Vec<_> = overlay.alive_members()
                        .into_iter()
                        .filter(|peer| *peer != node)
                        .collect();
                    let options = OverlaySendOptions::default().expire_after(Duration::from_millis(750));
                    let result = if control.phase == WorkloadPhase::Tree {
                        overlay.send_multicast_tree_unordered_with_routing_metric_and_group_options(
                            &recipients,
                            GROUP,
                            GROUP_VERSION,
                            PRE_RELEASE_DISTRIBUTION_SERVICE_TAG,
                            ServiceLevel::ReliableLowLatency,
                            RoutingMetric::ReliableLowLatencyCost,
                            MessageClass::Regular,
                            body,
                            options,
                        ).await
                    } else {
                        overlay.send_multicast_unordered_with_routing_metric_and_options(
                            &recipients,
                            PRE_RELEASE_DISTRIBUTION_SERVICE_TAG,
                            ServiceLevel::ReliableLowLatency,
                            RoutingMetric::ReliableLowLatencyCost,
                            MessageClass::Regular,
                            body,
                            options,
                        ).await
                    };
                    let mut state = evidence.lock();
                    if result.is_ok() {
                        if control.record_tree {
                            state.expected_delivery_ids.push(id.clone());
                            state.deliveries.push(id);
                        } else {
                            state.unscored_tree_send_calls = state.unscored_tree_send_calls.saturating_add(1);
                        }
                        if control.phase == WorkloadPhase::Tree {
                            state.tree_send_calls = state.tree_send_calls.saturating_add(1);
                            if control.record_tree {
                                state.scored_tree_send_calls = state.scored_tree_send_calls.saturating_add(1);
                            }
                            if !control.record_tree && control.restart_window {
                                state.restart_tree_send_calls = state.restart_tree_send_calls.saturating_add(1);
                            }
                        } else {
                            state.legacy_send_calls = state.legacy_send_calls.saturating_add(1);
                            if control.record_tree {
                                state.scored_legacy_send_calls = state.scored_legacy_send_calls.saturating_add(1);
                            }
                        }
                    } else {
                        state.tree_send_failures = state.tree_send_failures.saturating_add(1);
                    }
                }
                _ = strict_tick.tick(), if proposers.contains(&node) => {
                    let control = workload_control(&artifact);
                    if !control.is_valid() {
                        continue;
                    }
                    evidence.lock().adopt_run(&control, node);
                    strict_seq = strict_seq.saturating_add(1);
                    let op = WorkloadOp {
                        id: format!("{node}-{boot_epoch}-{strict_seq}"),
                    };
                    {
                        let mut state = evidence.lock();
                        state.strict_proposals = state.strict_proposals.saturating_add(1);
                        state.strict_in_flight = state.strict_in_flight.saturating_add(1);
                        state.max_strict_in_flight = state.max_strict_in_flight.max(state.strict_in_flight);
                    }
                    let strict = strict.clone();
                    let proposal_evidence = evidence.clone();
                    tokio::spawn(async move {
                        let result = strict.propose(op.clone()).await;
                        let mut state = proposal_evidence.lock();
                        state.strict_in_flight = state.strict_in_flight.saturating_sub(1);
                        if let Err(error) = result {
                            tracing::warn!(%error, "pre-release strict proposal failed");
                            state.strict_proposal_failures = state.strict_proposal_failures.saturating_add(1);
                            let kind = replication_error_kind(&error).to_owned();
                            *state.strict_proposal_failures_by_kind.entry(kind).or_default() += 1;
                            if matches!(error, ReplicationError::ProposeTimeout(_)) {
                                state.strict_propose_timeouts = state.strict_propose_timeouts.saturating_add(1);
                            }
                        } else {
                            state.expected_strict_ids.push(op.id);
                        }
                    });
                }
                _ = persist_tick.tick() => {
                    let control = workload_control(&artifact);
                    if !control.is_valid() {
                        continue;
                    }
                    evidence.lock().adopt_run(&control, node);
                    if let Some(chaos) = chaos.as_ref() {
                        if control.hold_strict_acks != strict_acks_held {
                            set_strict_ack_hold(chaos, node, control.hold_strict_acks);
                            strict_acks_held = control.hold_strict_acks;
                        }
                    }
                    let epoch = overlay.pre_release_distribution_epoch();
                    if control.metric_mask_window {
                        if observed_epoch.is_some_and(|previous| previous != epoch) {
                            let mut state = evidence.lock();
                            state.topology_epoch_changes_during_metric_mask_churn = state
                                .topology_epoch_changes_during_metric_mask_churn
                                .saturating_add(1);
                        }
                        observed_epoch = Some(epoch);
                    } else {
                        observed_epoch = None;
                    }
                    let metric_lsa_now = overlay.pre_release_metric_lsa_emissions();
                    let metric_lsa_delta = metric_lsa_now.saturating_sub(last_metric_lsa);
                    last_metric_lsa = metric_lsa_now;
                    let remaining = chaos.as_ref()
                        .map(|chaos| chaos.remaining_type_drops_from(ack_sender, MessageType::DistributionAck))
                        .unwrap_or_default();
                    let mut snapshot = evidence.lock().clone();
                    snapshot.elapsed_seconds = control.scenario_elapsed_seconds as f64;
                    snapshot.strict_log = repo.ordered_ids();
                    let distribution = overlay.pre_release_distribution_counters();
                    if !activation_seen && distribution.0 > distribution_start.0 {
                        activation_seen = true;
                        fallback_baseline = distribution.1;
                    }
                    if node == env_node("SHITSPEAK_PRE_RELEASE_ACK_DROP_TARGET", 1)
                        && activation_seen && control.arm_ack_drop && !ack_drop_armed
                    {
                        if let Some(chaos) = chaos.as_ref() {
                            chaos.drop_next_of_type_from(ack_sender, MessageType::DistributionAck, 1);
                            ack_drop_armed = true;
                        }
                    }
                    snapshot.candidate_builds = candidate_offset
                        .saturating_add(distribution.2.saturating_sub(distribution_start.2));
                    snapshot.candidate_trigger_changes = candidate_trigger_offset
                        .saturating_add(distribution.3.saturating_sub(distribution_start.3));
                    if activation_seen {
                        snapshot.whole_group_fallbacks_after_initial_activation = fallback_offset
                            .saturating_add(distribution.1.saturating_sub(fallback_baseline));
                    }
                    snapshot.selected_ack_drops = if node == env_node("SHITSPEAK_PRE_RELEASE_ACK_DROP_TARGET", 1) {
                        snapshot.selected_ack_drops.max(u64::from(ack_drop_armed).saturating_sub(u64::from(remaining)))
                    } else {
                        0
                    };
                    snapshot.ack_drop_armed = ack_drop_armed;
                    snapshot.tree_activations = activation_offset
                        .saturating_add(distribution.0.saturating_sub(distribution_start.0));
                    if control.metric_mask_window {
                        snapshot.metric_lsa_emissions = snapshot.metric_lsa_emissions.saturating_add(metric_lsa_delta);
                    }
                    snapshot.run_id.clone_from(&control.run_id);
                    snapshot.phase = control.phase.label().to_owned();
                    snapshot.control_generation = control.generation;
                    snapshot.process_boot_epoch = boot_epoch;
                    snapshot.strict_ack_hold_active = strict_acks_held;
                    snapshot.heartbeat_unix_ms = unix_time_ms();
                    if let Err(error) = persist(&artifact, &snapshot) {
                        tracing::warn!(path = %artifact.display(), %error, "pre-release evidence write failed");
                    }
                }
                _ = shutdown.changed() => break,
            }
        }
    }))
}

fn persist(path: &Path, evidence: &NodeEvidence) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension("tmp");
    let mut bytes = serde_json::to_vec_pretty(evidence)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    bytes.push(b'\n');
    std::fs::write(&temp, bytes)?;
    std::fs::rename(temp, path)
}

fn workload_control(artifact: &Path) -> WorkloadControl {
    let control = artifact.with_file_name("pre-release-workload-control.json");
    std::fs::read(control)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<WorkloadControl>(&bytes).ok())
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum WorkloadPhase {
    Tree,
    Legacy,
    #[default]
    Disabled,
}

impl WorkloadPhase {
    fn label(self) -> &'static str {
        match self {
            Self::Tree => "tree",
            Self::Legacy => "legacy",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Clone, Deserialize)]
struct WorkloadControl {
    schema_version: u32,
    run_id: String,
    generation: u64,
    phase: WorkloadPhase,
    send_tree: bool,
    record_tree: bool,
    arm_ack_drop: bool,
    metric_mask_window: bool,
    restart_window: bool,
    hold_strict_acks: bool,
    scenario_elapsed_seconds: u64,
}

fn set_strict_ack_hold(chaos: &LinkChaos, local_node: NodeIdentifier, hold: bool) {
    for sender in 1..=16 {
        if sender == local_node {
            continue;
        }
        for transport in [
            TransportKind::Tcp,
            TransportKind::Kcp,
            TransportKind::Quic,
            TransportKind::Udp,
        ] {
            let selector = FaultSelector::new(sender, transport, MessageType::StrictAck);
            if hold {
                chaos.hold(selector);
            } else {
                chaos.release(selector);
            }
        }
    }
}

impl WorkloadControl {
    fn is_valid(&self) -> bool {
        self.schema_version == 2 && !self.run_id.is_empty() && self.phase != WorkloadPhase::Disabled
    }
}

impl Default for WorkloadControl {
    fn default() -> Self {
        Self {
            schema_version: 0,
            run_id: String::new(),
            generation: 0,
            phase: WorkloadPhase::Disabled,
            send_tree: false,
            record_tree: false,
            arm_ack_drop: false,
            metric_mask_window: false,
            restart_window: false,
            hold_strict_acks: false,
            scenario_elapsed_seconds: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NodeEvidence {
    schema_version: u32,
    node: String,
    run_id: String,
    heartbeat_unix_ms: u64,
    process_boot_epoch: u64,
    phase: String,
    control_generation: u64,
    elapsed_seconds: f64,
    strict_proposals: u64,
    strict_proposal_failures: u64,
    strict_proposal_failures_by_kind: BTreeMap<String, u64>,
    strict_propose_timeouts: u64,
    strict_in_flight: u64,
    strict_ack_hold_active: bool,
    max_strict_in_flight: u64,
    expected_strict_ids: Vec<String>,
    strict_log: Vec<String>,
    expected_delivery_ids: Vec<String>,
    deliveries: Vec<String>,
    selected_ack_drops: u64,
    ack_drop_armed: bool,
    tree_activations: u64,
    tree_send_calls: u64,
    legacy_send_calls: u64,
    scored_tree_send_calls: u64,
    scored_legacy_send_calls: u64,
    unscored_tree_send_calls: u64,
    restart_tree_send_calls: u64,
    tree_send_failures: u64,
    metric_lsa_emissions: u64,
    topology_epoch_changes_during_metric_mask_churn: u64,
    candidate_builds: u64,
    candidate_trigger_changes: u64,
    whole_group_fallbacks_after_initial_activation: u64,
}

impl NodeEvidence {
    fn load_or_new(path: &Path, node: NodeIdentifier) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Self>(&bytes).ok())
            .filter(|evidence| {
                evidence.schema_version == 2 && evidence.node == format!("node-{node:02}")
            })
            .unwrap_or_else(|| Self::new(node))
    }

    fn new(node: NodeIdentifier) -> Self {
        Self {
            schema_version: 2,
            node: format!("node-{node:02}"),
            run_id: String::new(),
            heartbeat_unix_ms: 0,
            process_boot_epoch: 0,
            phase: "disabled".to_owned(),
            control_generation: 0,
            elapsed_seconds: 0.0,
            strict_proposals: 0,
            strict_proposal_failures: 0,
            strict_proposal_failures_by_kind: BTreeMap::new(),
            strict_propose_timeouts: 0,
            strict_in_flight: 0,
            strict_ack_hold_active: false,
            max_strict_in_flight: 0,
            expected_strict_ids: Vec::new(),
            strict_log: Vec::new(),
            expected_delivery_ids: Vec::new(),
            deliveries: Vec::new(),
            selected_ack_drops: 0,
            ack_drop_armed: false,
            tree_activations: 0,
            tree_send_calls: 0,
            legacy_send_calls: 0,
            scored_tree_send_calls: 0,
            scored_legacy_send_calls: 0,
            unscored_tree_send_calls: 0,
            restart_tree_send_calls: 0,
            tree_send_failures: 0,
            metric_lsa_emissions: 0,
            topology_epoch_changes_during_metric_mask_churn: 0,
            candidate_builds: 0,
            candidate_trigger_changes: 0,
            whole_group_fallbacks_after_initial_activation: 0,
        }
    }

    fn adopt_run(&mut self, control: &WorkloadControl, node: NodeIdentifier) {
        if self.run_id != control.run_id {
            *self = Self::new(node);
            self.run_id.clone_from(&control.run_id);
        }
    }
}

struct WorkloadDelivery {
    evidence: Arc<Mutex<NodeEvidence>>,
}

impl ServiceInbound for WorkloadDelivery {
    fn handle(&self, message: OverlayInboundMessage) {
        if let Some(id) = message.body.strip_prefix(SCORED_MARKER) {
            if let Ok(id) = std::str::from_utf8(id) {
                self.evidence.lock().deliveries.push(id.to_owned());
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WorkloadOp {
    id: String,
}

#[derive(Default)]
struct RepoState {
    version: u64,
    entries: Vec<(u64, WorkloadOp, Option<StrictLogMetadata>)>,
}

struct WorkloadRepo {
    state: Mutex<RepoState>,
}

impl WorkloadRepo {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(RepoState::default()),
        })
    }

    fn ordered_ids(&self) -> Vec<String> {
        self.state
            .lock()
            .entries
            .iter()
            .map(|(_, op, _)| op.id.clone())
            .collect()
    }
}

#[async_trait]
impl StrictReplicable for WorkloadRepo {
    type Op = WorkloadOp;

    fn current_version(&self) -> u64 {
        self.state.lock().version
    }

    fn snapshot(&self) -> (u64, Bytes) {
        let state = self.state.lock();
        let entries: Vec<_> = state
            .entries
            .iter()
            .map(|(v, op, _)| (*v, op.clone()))
            .collect();
        let bytes = Bytes::from(rmp_serde::to_vec(&entries).unwrap_or_default());
        (state.version, bytes)
    }

    fn log_since(&self, since: u64) -> LogSlice<StrictLogEntry<Self::Op>> {
        let entries = self
            .state
            .lock()
            .entries
            .iter()
            .filter(|(version, _, _)| *version > since)
            .map(|(version, op, metadata)| {
                (
                    *version,
                    StrictLogEntry {
                        op: op.clone(),
                        metadata: *metadata,
                    },
                )
            })
            .collect();
        LogSlice::Available(entries)
    }

    async fn apply_committed(&self, version: u64, op: Self::Op) {
        self.apply_committed_with_metadata(version, op, None).await;
    }

    async fn apply_committed_with_metadata(
        &self,
        version: u64,
        op: Self::Op,
        metadata: Option<StrictLogMetadata>,
    ) {
        let mut state = self.state.lock();
        state.version = version;
        state.entries.push((version, op, metadata));
    }

    async fn install_snapshot(&self, version: u64, snapshot: Bytes) {
        let entries: Vec<(u64, WorkloadOp)> = rmp_serde::from_slice(&snapshot).unwrap_or_default();
        let mut state = self.state.lock();
        state.version = version;
        state.entries = entries.into_iter().map(|(v, op)| (v, op, None)).collect();
    }
}

fn env_u64(name: &str, fallback: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(fallback)
}

fn env_node(name: &str, fallback: NodeIdentifier) -> NodeIdentifier {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(fallback)
}

fn env_nodes(name: &str, fallback: &[NodeIdentifier]) -> BTreeSet<NodeIdentifier> {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|part| part.trim().parse().ok())
                .collect()
        })
        .filter(|nodes: &BTreeSet<_>| !nodes.is_empty())
        .unwrap_or_else(|| fallback.iter().copied().collect())
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn replication_error_kind(error: &ReplicationError) -> &'static str {
    match error {
        ReplicationError::Overlay(_) => "overlay",
        ReplicationError::Encode(_) => "encode",
        ReplicationError::Decode(_) => "decode",
        ReplicationError::MsgpackEncode(_) => "msgpack_encode",
        ReplicationError::MsgpackDecode(_) => "msgpack_decode",
        ReplicationError::TopicNotRegistered(_) => "topic_not_registered",
        ReplicationError::TopicAlreadyRegistered(_) => "topic_already_registered",
        ReplicationError::QuorumLost => "quorum_lost",
        ReplicationError::ProposeTimeout(_) => "propose_timeout",
        ReplicationError::Shutdown => "shutdown",
        ReplicationError::NotOwner { .. } => "not_owner",
        ReplicationError::Malformed(_) => "malformed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_loads_existing_delivery_and_timeout_evidence() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("pre-release-workload.json");
        let mut original = NodeEvidence::new(7);
        original.expected_delivery_ids.push("tree-1".to_owned());
        original.deliveries.push("tree-1".to_owned());
        original.strict_propose_timeouts = 2;
        persist(&path, &original).expect("persist evidence");

        let restored = NodeEvidence::load_or_new(&path, 7);
        assert_eq!(restored.expected_delivery_ids, ["tree-1"]);
        assert_eq!(restored.deliveries, ["tree-1"]);
        assert_eq!(restored.strict_propose_timeouts, 2);
    }
}
