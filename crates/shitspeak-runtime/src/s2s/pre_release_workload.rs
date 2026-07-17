//! Opt-in workload embedded in real server processes for the serialized
//! 16-node pre-release gate. It is compiled out of ordinary builds.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::fs::File;

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use shitspeak_s2s::overlay::{
    OverlayInboundMessage, OverlayNetwork, OverlaySendOptions,
    PRE_RELEASE_DISTRIBUTION_SERVICE_TAG, RoutingMetric, STRICT_REPLICATION_PROTOCOL_VERSION,
    ServiceInbound,
};
use shitspeak_s2s::replications::strict::{
    LogSlice, StrictCommitApplyOutcome, StrictLogEntry, StrictLogMetadata, StrictSnapshotError,
};
use shitspeak_s2s::replications::{ReplicationError, ReplicationManager, StrictReplicable};
use shitspeak_s2s::testing::{FaultSelector, LinkChaos, MessageType};
use shitspeak_s2s_transport::{MessageClass, ServiceLevel, TransportKind};

use crate::types::NodeIdentifier;

const TOPIC: &str = "pre-release/control-plane/v1";
const GROUP: u64 = 0x7072_656c_6561_7365;
const GROUP_VERSION: u64 = 1;
const SCORED_MARKER: &[u8] = b"PRTREE1:S:";
const UNSCORED_MARKER: &[u8] = b"PRTREE1:U:";
const WORKLOAD_REPO_STATE_SCHEMA_VERSION: u32 = 1;

static NEXT_WORKLOAD_REPO_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

pub(super) fn strict_topic() -> &'static str {
    TOPIC
}

#[cfg(windows)]
const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
#[cfg(windows)]
const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

#[cfg(windows)]
#[link(name = "Kernel32")]
unsafe extern "system" {
    fn MoveFileExW(
        existing_file_name: *const u16,
        new_file_name: *const u16,
        move_flags: u32,
    ) -> i32;
}

pub(super) fn enabled() -> bool {
    std::env::var_os("SHITSPEAK_PRE_RELEASE_ARTIFACT_PATH").is_some()
}

pub(super) fn configured_chaos(_local_node: NodeIdentifier) -> LinkChaos {
    LinkChaos::with_seed(env_u64("SHITSPEAK_PRE_RELEASE_SEED", 1))
}

pub(super) struct StartedWorkload {
    task: JoinHandle<()>,
}

impl StartedWorkload {
    pub(super) fn into_task(self) -> JoinHandle<()> {
        self.task
    }
}

pub(super) fn start(
    overlay: OverlayNetwork,
    replications: Arc<ReplicationManager>,
    chaos: Option<LinkChaos>,
    mut shutdown: watch::Receiver<()>,
) -> Option<StartedWorkload> {
    let artifact = PathBuf::from(std::env::var_os("SHITSPEAK_PRE_RELEASE_ARTIFACT_PATH")?);
    let node = overlay.local_node_id();
    let repo = match WorkloadRepo::open(&artifact) {
        Ok(repo) => repo,
        Err(error) => {
            tracing::error!(path = %artifact.display(), %error, "pre-release strict workload state initialization failed");
            return None;
        }
    };
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

    Some(StartedWorkload {
        task: tokio::spawn(async move {
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
        }),
    })
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct WorkloadOperationId {
    high: u64,
    low: u64,
}

impl From<StrictLogMetadata> for WorkloadOperationId {
    fn from(metadata: StrictLogMetadata) -> Self {
        Self {
            high: metadata.op_id_hi,
            low: metadata.op_id_lo,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
struct PersistedWorkloadMetadata {
    operation_id: WorkloadOperationId,
    ts_final: u64,
}

impl From<StrictLogMetadata> for PersistedWorkloadMetadata {
    fn from(metadata: StrictLogMetadata) -> Self {
        Self {
            operation_id: metadata.into(),
            ts_final: metadata.ts_final,
        }
    }
}

impl From<PersistedWorkloadMetadata> for StrictLogMetadata {
    fn from(metadata: PersistedWorkloadMetadata) -> Self {
        Self {
            op_id_hi: metadata.operation_id.high,
            op_id_lo: metadata.operation_id.low,
            ts_final: metadata.ts_final,
        }
    }
}

#[derive(Clone)]
struct WorkloadEntry {
    version: u64,
    op: WorkloadOp,
    metadata: Option<StrictLogMetadata>,
}

#[derive(Clone, Deserialize, Serialize)]
struct PersistedWorkloadEntry {
    version: u64,
    op: WorkloadOp,
    metadata: Option<PersistedWorkloadMetadata>,
}

impl From<&WorkloadEntry> for PersistedWorkloadEntry {
    fn from(entry: &WorkloadEntry) -> Self {
        Self {
            version: entry.version,
            op: entry.op.clone(),
            metadata: entry.metadata.map(Into::into),
        }
    }
}

impl From<PersistedWorkloadEntry> for WorkloadEntry {
    fn from(entry: PersistedWorkloadEntry) -> Self {
        Self {
            version: entry.version,
            op: entry.op,
            metadata: entry.metadata.map(Into::into),
        }
    }
}

#[derive(Clone, Default)]
struct RepoState {
    version: u64,
    /// The newest snapshot installation. Older logs cannot be served without
    /// first transferring that snapshot.
    history_floor: u64,
    entries: Vec<WorkloadEntry>,
    operation_ids: BTreeSet<WorkloadOperationId>,
}

#[derive(Deserialize, Serialize)]
struct PersistedWorkloadRepoState {
    schema_version: u32,
    version: u64,
    history_floor: u64,
    entries: Vec<PersistedWorkloadEntry>,
    operation_ids: Vec<WorkloadOperationId>,
}

#[derive(Deserialize, Serialize)]
struct WorkloadSnapshot {
    schema_version: u32,
    entries: Vec<PersistedWorkloadEntry>,
    operation_ids: Vec<WorkloadOperationId>,
}

impl RepoState {
    fn persisted(&self) -> PersistedWorkloadRepoState {
        PersistedWorkloadRepoState {
            schema_version: WORKLOAD_REPO_STATE_SCHEMA_VERSION,
            version: self.version,
            history_floor: self.history_floor,
            entries: self.entries.iter().map(Into::into).collect(),
            operation_ids: self.operation_ids.iter().copied().collect(),
        }
    }

    fn snapshot(&self) -> WorkloadSnapshot {
        WorkloadSnapshot {
            schema_version: WORKLOAD_REPO_STATE_SCHEMA_VERSION,
            entries: self.entries.iter().map(Into::into).collect(),
            operation_ids: self.operation_ids.iter().copied().collect(),
        }
    }

    fn from_persisted(persisted: PersistedWorkloadRepoState) -> io::Result<Self> {
        if persisted.schema_version != WORKLOAD_REPO_STATE_SCHEMA_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported pre-release workload repository state schema {}",
                    persisted.schema_version
                ),
            ));
        }
        Self::from_parts(
            persisted.version,
            persisted.history_floor,
            persisted.entries,
            persisted.operation_ids,
        )
    }

    fn from_snapshot(version: u64, snapshot: WorkloadSnapshot) -> io::Result<Self> {
        if snapshot.schema_version != WORKLOAD_REPO_STATE_SCHEMA_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported pre-release workload snapshot schema {}",
                    snapshot.schema_version
                ),
            ));
        }
        Self::from_parts(version, version, snapshot.entries, snapshot.operation_ids)
    }

    fn from_parts(
        version: u64,
        history_floor: u64,
        entries: Vec<PersistedWorkloadEntry>,
        operation_ids: Vec<WorkloadOperationId>,
    ) -> io::Result<Self> {
        if history_floor > version {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pre-release workload history floor exceeds its version",
            ));
        }

        let operation_id_count = operation_ids.len();
        let operation_ids: BTreeSet<_> = operation_ids.into_iter().collect();
        if operation_ids.len() != operation_id_count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pre-release workload operation-id ledger contains duplicates",
            ));
        }
        let mut metadata_ids = BTreeSet::new();
        let mut previous_version = None;
        let mut decoded_entries = Vec::with_capacity(entries.len());
        for PersistedWorkloadEntry {
            version: entry_version,
            op,
            metadata,
        } in entries
        {
            if entry_version > version {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pre-release workload entry exceeds snapshot version",
                ));
            }
            if previous_version.is_some_and(|previous| entry_version <= previous) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pre-release workload entries are not strictly version ordered",
                ));
            }
            previous_version = Some(entry_version);
            if let Some(metadata) = metadata {
                if !operation_ids.contains(&metadata.operation_id)
                    || !metadata_ids.insert(metadata.operation_id)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "pre-release workload operation-id ledger does not match entries",
                    ));
                }
                decoded_entries.push(WorkloadEntry {
                    version: entry_version,
                    op,
                    metadata: Some(metadata.into()),
                });
            } else {
                decoded_entries.push(WorkloadEntry {
                    version: entry_version,
                    op,
                    metadata: None,
                });
            }
        }
        if metadata_ids != operation_ids {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pre-release workload operation-id ledger is not represented by state",
            ));
        }

        Ok(Self {
            version,
            history_floor,
            entries: decoded_entries,
            operation_ids,
        })
    }
}

struct WorkloadRepo {
    state: Mutex<RepoState>,
    state_path: PathBuf,
    /// A failed durable write means this instance can no longer truthfully
    /// advertise the current strict protocol. A verified reopen is required
    /// before v2 can be considered available again.
    strict_durability_poisoned: AtomicBool,
}

impl WorkloadRepo {
    fn open(artifact_path: &Path) -> io::Result<Arc<Self>> {
        let state_path = workload_repo_state_path(artifact_path)?;
        let state = load_workload_repo_state(&state_path)?;
        // Verify the derived state root before advertising protocol v2. This
        // also turns a missing state file into a durable empty ledger.
        persist_workload_repo_state(&state_path, &state)?;
        Ok(Arc::new(Self {
            state: Mutex::new(state),
            state_path,
            strict_durability_poisoned: AtomicBool::new(false),
        }))
    }

    fn persist_state(&self, state: &RepoState) -> io::Result<()> {
        let result = persist_workload_repo_state(&self.state_path, state);
        if result.is_err() {
            self.strict_durability_poisoned
                .store(true, Ordering::Release);
        }
        result
    }

    fn ordered_ids(&self) -> Vec<String> {
        self.state
            .lock()
            .entries
            .iter()
            .map(|entry| entry.op.id.clone())
            .collect()
    }

    fn apply_legacy(&self, version: u64, op: WorkloadOp) {
        let mut state = self.state.lock();
        if version <= state.version {
            return;
        }
        let mut next = state.clone();
        next.version = version;
        next.entries.push(WorkloadEntry {
            version,
            op,
            metadata: None,
        });
        if let Err(error) = self.persist_state(&next) {
            tracing::warn!(path = %self.state_path.display(), %error, "pre-release legacy strict workload operation persistence failed");
            return;
        }
        *state = next;
    }
}

#[async_trait]
impl StrictReplicable for WorkloadRepo {
    type Op = WorkloadOp;

    fn strict_replication_protocol_version(&self) -> u32 {
        if self.strict_durability_poisoned.load(Ordering::Acquire) {
            0
        } else {
            STRICT_REPLICATION_PROTOCOL_VERSION
        }
    }

    fn current_version(&self) -> u64 {
        self.state.lock().version
    }

    fn snapshot(&self) -> Result<(u64, Bytes), StrictSnapshotError> {
        let state = self.state.lock();
        let version = state.version;
        let bytes = rmp_serde::to_vec(&state.snapshot())
            .map(Bytes::from)
            .map_err(|error| {
                StrictSnapshotError::new(format!("workload snapshot encode failed: {error}"))
            })?;
        Ok((version, bytes))
    }

    fn log_since(&self, since: u64) -> LogSlice<StrictLogEntry<Self::Op>> {
        let state = self.state.lock();
        if since < state.history_floor {
            return LogSlice::TooOld;
        }
        LogSlice::Available(
            state
                .entries
                .iter()
                .filter(|entry| entry.version > since)
                .map(|entry| {
                    (
                        entry.version,
                        StrictLogEntry {
                            op: entry.op.clone(),
                            metadata: entry.metadata,
                        },
                    )
                })
                .collect(),
        )
    }

    async fn apply_committed(&self, version: u64, op: Self::Op) {
        self.apply_legacy(version, op);
    }

    async fn apply_committed_with_metadata(
        &self,
        version: u64,
        op: Self::Op,
        metadata: Option<StrictLogMetadata>,
    ) {
        if let Some(metadata) = metadata {
            if self.apply_committed_once(version, op, metadata).await
                == StrictCommitApplyOutcome::Failed
            {
                tracing::warn!("pre-release strict workload operation apply failed");
            }
        } else {
            self.apply_legacy(version, op);
        }
    }

    async fn apply_committed_once(
        &self,
        version: u64,
        op: Self::Op,
        metadata: StrictLogMetadata,
    ) -> StrictCommitApplyOutcome {
        let operation_id = WorkloadOperationId::from(metadata);
        let mut state = self.state.lock();
        if state.operation_ids.contains(&operation_id) {
            return StrictCommitApplyOutcome::AlreadyApplied;
        }
        if version <= state.version {
            return StrictCommitApplyOutcome::Failed;
        }

        let mut next = state.clone();
        next.version = version;
        next.entries.push(WorkloadEntry {
            version,
            op,
            metadata: Some(metadata),
        });
        next.operation_ids.insert(operation_id);
        if let Err(error) = self.persist_state(&next) {
            tracing::warn!(path = %self.state_path.display(), %error, "pre-release strict workload operation persistence failed");
            return StrictCommitApplyOutcome::Failed;
        }
        *state = next;
        StrictCommitApplyOutcome::Applied
    }

    async fn install_snapshot(
        &self,
        version: u64,
        snapshot: Bytes,
    ) -> Result<(), StrictSnapshotError> {
        let snapshot: WorkloadSnapshot = rmp_serde::from_slice(&snapshot).map_err(|error| {
            StrictSnapshotError::new(format!("workload snapshot decode failed: {error}"))
        })?;
        let next = RepoState::from_snapshot(version, snapshot).map_err(|error| {
            StrictSnapshotError::new(format!("workload snapshot validation failed: {error}"))
        })?;
        let mut state = self.state.lock();
        if version < state.version {
            return Ok(());
        }
        if !state.operation_ids.is_subset(&next.operation_ids) {
            return Err(StrictSnapshotError::new(
                "workload snapshot omits locally durable terminal operation ids",
            ));
        }
        self.persist_state(&next).map_err(|error| {
            StrictSnapshotError::new(format!("workload snapshot persistence failed: {error}"))
        })?;
        *state = next;
        Ok(())
    }
}

fn workload_repo_state_path(artifact_path: &Path) -> io::Result<PathBuf> {
    let file_name = artifact_path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "pre-release workload artifact path has no file name",
        )
    })?;
    let parent = artifact_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut state_file_name = file_name.to_os_string();
    state_file_name.push(".strict-replication-state.json");
    Ok(parent.join(state_file_name))
}

fn load_workload_repo_state(path: &Path) -> io::Result<RepoState> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(RepoState::default()),
        Err(error) => return Err(error),
    };
    let persisted = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    RepoState::from_persisted(persisted)
}

fn persist_workload_repo_state(path: &Path, state: &RepoState) -> io::Result<()> {
    let bytes = serde_json::to_vec(&state.persisted())
        .map_err(|error| io::Error::other(error.to_string()))?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "pre-release workload repository state path has no parent",
        )
    })?;
    fs::create_dir_all(parent)?;
    let temporary_path = workload_repo_temporary_path(path);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        replace_workload_repo_file_atomically(&temporary_path, path)?;
        sync_workload_repo_parent_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn workload_repo_temporary_path(path: &Path) -> PathBuf {
    let id = NEXT_WORKLOAD_REPO_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
    path.with_extension(format!("json.{}.{}.tmp", std::process::id(), id))
}

#[cfg(not(windows))]
fn replace_workload_repo_file_atomically(temporary_path: &Path, path: &Path) -> io::Result<()> {
    fs::rename(temporary_path, path)
}

#[cfg(windows)]
fn replace_workload_repo_file_atomically(temporary_path: &Path, path: &Path) -> io::Result<()> {
    let temporary_wide = workload_repo_windows_api_path(temporary_path)?;
    let path_wide = workload_repo_windows_api_path(path)?;
    let moved = unsafe {
        MoveFileExW(
            temporary_wide.as_ptr(),
            path_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn workload_repo_windows_api_path(path: &Path) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "pre-release workload repository state path has no parent",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "pre-release workload repository state path has no file name",
        )
    })?;
    let absolute_path = fs::canonicalize(parent)?.join(file_name);
    let mut wide = absolute_path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pre-release workload repository state path contains an embedded NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(unix)]
fn sync_workload_repo_parent_directory(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_workload_repo_parent_directory(_parent: &Path) -> io::Result<()> {
    Ok(())
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
        ReplicationError::OriginAuthentication(_) => "origin_authentication",
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

    fn workload_op(id: &str) -> WorkloadOp {
        WorkloadOp { id: id.to_owned() }
    }

    fn strict_metadata(high: u64, low: u64, ts_final: u64) -> StrictLogMetadata {
        StrictLogMetadata {
            op_id_hi: high,
            op_id_lo: low,
            ts_final,
        }
    }

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

    #[tokio::test]
    async fn workload_repo_persists_operation_ids_and_deduplicates_terminal_replay() {
        let dir = tempfile::tempdir().expect("temp dir");
        let artifact = dir.path().join("node-01-evidence.json");
        let metadata = strict_metadata(101, 202, 303);

        {
            let repo = WorkloadRepo::open(&artifact).expect("open durable workload repo");
            assert_eq!(
                repo.strict_replication_protocol_version(),
                STRICT_REPLICATION_PROTOCOL_VERSION
            );
            assert_eq!(
                repo.apply_committed_once(1, workload_op("first"), metadata)
                    .await,
                StrictCommitApplyOutcome::Applied
            );
            assert_eq!(repo.ordered_ids(), ["first"]);
        }

        let repo = WorkloadRepo::open(&artifact).expect("reopen durable workload repo");
        assert_eq!(repo.current_version(), 1);
        assert_eq!(repo.ordered_ids(), ["first"]);
        assert_eq!(
            repo.apply_committed_once(2, workload_op("replayed"), metadata)
                .await,
            StrictCommitApplyOutcome::AlreadyApplied
        );
        assert_eq!(repo.current_version(), 1);
        assert_eq!(repo.ordered_ids(), ["first"]);
        assert!(workload_repo_state_path(&artifact).unwrap().is_file());
    }

    #[tokio::test]
    async fn workload_repo_persistence_failure_latches_current_protocol_off_until_reopen() {
        let dir = tempfile::tempdir().expect("temp dir");
        let artifact = dir.path().join("node-01-evidence.json");
        let repo = WorkloadRepo::open(&artifact).expect("open durable workload repo");
        let state_path = workload_repo_state_path(&artifact).expect("state path");

        assert_eq!(
            repo.strict_replication_protocol_version(),
            STRICT_REPLICATION_PROTOCOL_VERSION
        );
        std::fs::remove_file(&state_path).expect("remove state file");
        std::fs::create_dir(&state_path).expect("replace state file with directory");

        assert_eq!(
            repo.apply_committed_once(
                1,
                workload_op("write-fails"),
                strict_metadata(301, 302, 303)
            )
            .await,
            StrictCommitApplyOutcome::Failed
        );
        assert_eq!(repo.strict_replication_protocol_version(), 0);

        // Restoring the path allows state writes again, but does not let this
        // in-process repository re-advertise a capability it previously lost.
        std::fs::remove_dir(&state_path).expect("remove blocking directory");
        assert_eq!(
            repo.apply_committed_once(
                1,
                workload_op("write-recovers"),
                strict_metadata(304, 305, 306)
            )
            .await,
            StrictCommitApplyOutcome::Applied
        );
        assert_eq!(repo.strict_replication_protocol_version(), 0);

        drop(repo);
        let reopened = WorkloadRepo::open(&artifact).expect("reopen repaired workload repo");
        assert_eq!(
            reopened.strict_replication_protocol_version(),
            STRICT_REPLICATION_PROTOCOL_VERSION
        );
    }

    #[test]
    fn malformed_persisted_workload_state_fails_closed_on_open() {
        let dir = tempfile::tempdir().expect("temp dir");
        let artifact = dir.path().join("node-01-evidence.json");
        let state_path = workload_repo_state_path(&artifact).expect("state path");
        std::fs::write(&state_path, b"not-json").expect("write malformed state");

        let error = match WorkloadRepo::open(&artifact) {
            Ok(_) => panic!("corrupt state must not be accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn workload_snapshot_atomically_transfers_state_and_operation_ids() {
        let dir = tempfile::tempdir().expect("temp dir");
        let source_artifact = dir.path().join("source-evidence.json");
        let target_artifact = dir.path().join("target-evidence.json");
        let metadata = strict_metadata(401, 402, 403);

        let source = WorkloadRepo::open(&source_artifact).expect("open source repo");
        assert_eq!(
            source
                .apply_committed_once(1, workload_op("snapshot-entry"), metadata)
                .await,
            StrictCommitApplyOutcome::Applied
        );
        let (snapshot_version, snapshot_bytes) = source.snapshot().expect("capture snapshot");
        let decoded: WorkloadSnapshot =
            rmp_serde::from_slice(&snapshot_bytes).expect("decode snapshot");
        assert_eq!(snapshot_version, 1);
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(
            decoded.operation_ids,
            [WorkloadOperationId {
                high: 401,
                low: 402
            }]
        );

        // A later source commit cannot change the bytes or version that were
        // already captured under the snapshot lock.
        assert_eq!(
            source
                .apply_committed_once(
                    2,
                    workload_op("later-entry"),
                    strict_metadata(404, 405, 406)
                )
                .await,
            StrictCommitApplyOutcome::Applied
        );

        {
            let target = WorkloadRepo::open(&target_artifact).expect("open target repo");
            target
                .install_snapshot(snapshot_version, snapshot_bytes)
                .await
                .expect("install snapshot");
            assert_eq!(target.current_version(), 1);
            assert_eq!(target.ordered_ids(), ["snapshot-entry"]);
            assert!(matches!(target.log_since(0), LogSlice::TooOld));
            assert!(
                matches!(target.log_since(1), LogSlice::Available(entries) if entries.is_empty())
            );
        }

        let target = WorkloadRepo::open(&target_artifact).expect("reopen target repo");
        assert_eq!(
            target
                .apply_committed_once(2, workload_op("terminal-replay"), metadata)
                .await,
            StrictCommitApplyOutcome::AlreadyApplied
        );
        assert_eq!(target.current_version(), 1);
        assert_eq!(target.ordered_ids(), ["snapshot-entry"]);
    }

    #[tokio::test]
    async fn workload_snapshot_rejects_an_unrepresented_operation_id_without_mutation() {
        let dir = tempfile::tempdir().expect("temp dir");
        let artifact = dir.path().join("node-01-evidence.json");
        let repo = WorkloadRepo::open(&artifact).expect("open workload repo");
        assert_eq!(
            repo.apply_committed_once(1, workload_op("kept"), strict_metadata(501, 502, 503))
                .await,
            StrictCommitApplyOutcome::Applied
        );

        let malformed = WorkloadSnapshot {
            schema_version: WORKLOAD_REPO_STATE_SCHEMA_VERSION,
            entries: Vec::new(),
            operation_ids: vec![WorkloadOperationId {
                high: 601,
                low: 602,
            }],
        };
        let bytes = Bytes::from(rmp_serde::to_vec(&malformed).expect("encode malformed snapshot"));
        assert!(repo.install_snapshot(2, bytes).await.is_err());
        assert_eq!(repo.current_version(), 1);
        assert_eq!(repo.ordered_ids(), ["kept"]);
        assert_eq!(
            repo.strict_replication_protocol_version(),
            STRICT_REPLICATION_PROTOCOL_VERSION,
            "a semantic peer snapshot rejection must not poison local durability"
        );
    }

    #[tokio::test]
    async fn workload_snapshot_rejects_missing_local_terminal_ids_at_equal_and_newer_versions() {
        let dir = tempfile::tempdir().expect("temp dir");
        let artifact = dir.path().join("node-01-evidence.json");
        let repo = WorkloadRepo::open(&artifact).expect("open workload repo");
        let local_metadata = strict_metadata(701, 702, 703);
        assert_eq!(
            repo.apply_committed_once(1, workload_op("locally-terminal"), local_metadata)
                .await,
            StrictCommitApplyOutcome::Applied
        );

        let stale_missing_local_ledger = WorkloadSnapshot {
            schema_version: WORKLOAD_REPO_STATE_SCHEMA_VERSION,
            entries: Vec::new(),
            operation_ids: Vec::new(),
        };
        let bytes = Bytes::from(
            rmp_serde::to_vec(&stale_missing_local_ledger)
                .expect("encode stale snapshot missing local terminal id"),
        );
        repo.install_snapshot(0, bytes)
            .await
            .expect("stale snapshot must be a no-op");
        assert_eq!(repo.current_version(), 1);
        assert_eq!(repo.ordered_ids(), ["locally-terminal"]);

        for version in [1, 2] {
            let missing_local_ledger = WorkloadSnapshot {
                schema_version: WORKLOAD_REPO_STATE_SCHEMA_VERSION,
                entries: Vec::new(),
                operation_ids: Vec::new(),
            };
            let bytes = Bytes::from(
                rmp_serde::to_vec(&missing_local_ledger)
                    .expect("encode snapshot missing local terminal id"),
            );
            assert!(repo.install_snapshot(version, bytes).await.is_err());
            assert_eq!(repo.current_version(), 1);
            assert_eq!(repo.ordered_ids(), ["locally-terminal"]);
        }

        drop(repo);
        let reopened = WorkloadRepo::open(&artifact).expect("reopen workload repo");
        assert_eq!(reopened.current_version(), 1);
        assert_eq!(reopened.ordered_ids(), ["locally-terminal"]);
        assert_eq!(
            reopened
                .apply_committed_once(2, workload_op("replay"), local_metadata)
                .await,
            StrictCommitApplyOutcome::AlreadyApplied
        );
    }

    #[tokio::test]
    async fn workload_snapshot_accepts_a_superset_of_local_terminal_ids() {
        let dir = tempfile::tempdir().expect("temp dir");
        let artifact = dir.path().join("node-01-evidence.json");
        let repo = WorkloadRepo::open(&artifact).expect("open workload repo");
        let local_metadata = strict_metadata(801, 802, 803);
        let remote_metadata = strict_metadata(804, 805, 806);
        assert_eq!(
            repo.apply_committed_once(1, workload_op("local"), local_metadata)
                .await,
            StrictCommitApplyOutcome::Applied
        );

        let local_id = WorkloadOperationId::from(local_metadata);
        let remote_id = WorkloadOperationId::from(remote_metadata);
        let superset = WorkloadSnapshot {
            schema_version: WORKLOAD_REPO_STATE_SCHEMA_VERSION,
            entries: vec![
                PersistedWorkloadEntry {
                    version: 1,
                    op: workload_op("local"),
                    metadata: Some(local_metadata.into()),
                },
                PersistedWorkloadEntry {
                    version: 2,
                    op: workload_op("remote"),
                    metadata: Some(remote_metadata.into()),
                },
            ],
            operation_ids: vec![local_id, remote_id],
        };
        let bytes = Bytes::from(rmp_serde::to_vec(&superset).expect("encode superset snapshot"));
        repo.install_snapshot(2, bytes)
            .await
            .expect("superset snapshot must install");

        assert_eq!(repo.current_version(), 2);
        assert_eq!(repo.ordered_ids(), ["local", "remote"]);
        assert!(matches!(repo.log_since(0), LogSlice::TooOld));
        assert_eq!(
            repo.apply_committed_once(3, workload_op("local-replay"), local_metadata)
                .await,
            StrictCommitApplyOutcome::AlreadyApplied
        );
        assert_eq!(
            repo.apply_committed_once(3, workload_op("remote-replay"), remote_metadata)
                .await,
            StrictCommitApplyOutcome::AlreadyApplied
        );
    }
}
