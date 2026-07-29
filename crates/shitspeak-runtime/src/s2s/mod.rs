use std::collections::{BTreeSet, HashMap, HashSet, hash_map::Entry};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use prost::Message as ProstMessage;
use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

use crate::blob_store::ChannelBlobStore;
use crate::client::client_session_identifier::ClientSessionIdentifier;
use crate::client::state_log::{ClientGlobalStateDelta, ClientStateLogEntry, ClientStateOperation};
use crate::client_repository::{
    ClientOriginLogSlice, ClientRepository, ClientSnapshotInstallOutcome,
};
use crate::geoip::NodeGeo;
use crate::server::Server;
use crate::types::{DEFAULT_SERVER_ID, NodeIdentifier, StrictReplicationMetadata};
use crate::voice::metrics::{
    S2SVoiceGatewayDropDirection, S2SVoiceGatewayDropReason, record_s2s_gateway_drop,
};
use shitspeak_state::{BanEntry, BanOp, BanOperation, BanRepository};
use shitspeak_state::{
    ChannelOp, ChannelOperation, ChannelRepoError, ChannelRepository, StrictOperationApplyOutcome,
    StrictOperationId,
};

use shitspeak_s2s::application as s2s_application;
use shitspeak_s2s::application::error::ApplicationError;
use shitspeak_s2s::application::gateway::{
    AdaptiveReceiver as S2SAdaptiveReceiver, AdaptiveSender as S2SAdaptiveSender,
    EstimatedCommand as EstimatedS2SCommand, QueueBudget as S2SQueueBudget,
    run_sender_sharded_gateway,
};
use shitspeak_s2s::application::moderation::ModerationApplier;
use shitspeak_s2s::application::proto::{
    ModerationCommand, ModerationEnvelope, PluginDataEnvelope, TextMessageEnvelope,
    UserRemovePatch, UserStatePatch, UserStatsReply, VoiceFrame, VoiceIntent,
};
use shitspeak_s2s::application::voice::{AudioSink, RecipientIndex, RecipientIndexUpdate};
use shitspeak_s2s::geo::SharedNodeGeo;
use shitspeak_s2s::overlay as s2s_overlay;
use shitspeak_s2s::overlay::OverlayNetwork;
use shitspeak_s2s::replications as s2s_replications;
pub use shitspeak_s2s::replications::channel_topics::{
    channel_blob_topic, channel_topic, server_id_from_channel_blob_topic,
    server_id_from_channel_topic,
};
use shitspeak_s2s::replications::owner::{OwnerSnapshotInstallError, OwnerSnapshotInstallOutcome};
use shitspeak_s2s::replications::{
    BlobReplicable, OwnerReplicable, ReplicationManager, StrictReplicable,
};
use shitspeak_s2s::status as s2s_status;
#[cfg(any(test, feature = "pre-release-workload"))]
use shitspeak_s2s::testing as s2s_testing;
use shitspeak_s2s_transport as s2s_transport;
use shitspeak_s2s_transport::{ConnectionManager, TransportConfig};

#[cfg(feature = "pre-release-workload")]
mod pre_release_workload;

const S2S_CLIENT_REPLICATION_WORKER_CAPACITY: usize = 4096;
const MAX_CLIENT_ORIGIN_SNAPSHOT_ENTRIES: usize = 1_000_000;
const MAX_CLIENT_ORIGIN_SNAPSHOT_BYTES: usize = 128 * 1024 * 1024;
const S2S_GATEWAY_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const STRICT_PROPOSAL_GATEWAY_SLACK_TICKS: u32 = 4;
const VOICE_RECIPIENT_INDEX_REFRESH_INTERVAL: Duration = Duration::from_millis(100);
const S2S_CHANNEL_REPLICATION_SLOW_STAGE: Duration = Duration::from_secs(1);
const S2S_CLIENT_REPLICATION_SLOW_PROPOSE: Duration = Duration::from_secs(1);
const S2S_CLIENT_REPLICATION_SLOW_QUEUE_WAIT: Duration = Duration::from_millis(250);
const S2S_CLIENT_SNAPSHOT_DEFER_ERROR_AFTER: Duration = Duration::from_secs(20);
const S2S_GATEWAY_MEMORY_FRACTION_DIVISOR: u64 = 20;
const S2S_GATEWAY_MIN_BUDGET_BYTES: u64 = 16 * 1024 * 1024;
const S2S_GATEWAY_FALLBACK_BUDGET_BYTES: u64 = 64 * 1024 * 1024;
const S2S_GATEWAY_MAX_BUDGET_BYTES: u64 = 512 * 1024 * 1024;
const S2S_GATEWAY_COMMAND_OVERHEAD_BYTES: usize = 512;
const S2S_GATEWAY_CONTROL_MIN_BYTES: usize = 1024 * 1024;
const S2S_GATEWAY_LANE_MIN_BYTES: usize = 512 * 1024;
const S2S_VOICE_GATEWAY_MIN_SHARDS: usize = 2;
const S2S_VOICE_GATEWAY_MAX_SHARDS: usize = 16;
const OBSERVABILITY_GEO_RETRY_INITIAL_INTERVAL: Duration = Duration::from_secs(1);
const OBSERVABILITY_GEO_RETRY_CAP: Duration = Duration::from_secs(5 * 60);

fn strict_proposal_gateway_response_timeout(cfg: &s2s_replications::ReplicationConfig) -> Duration {
    let slack = cfg
        .delivery_tick_interval()
        .checked_mul(STRICT_PROPOSAL_GATEWAY_SLACK_TICKS)
        .unwrap_or_else(|| cfg.max_clock_tick());
    S2S_GATEWAY_RESPONSE_TIMEOUT.max(cfg.propose_ttl().saturating_add(slack))
}

fn channel_op_log_fields(op: &ChannelOp) -> (&'static str, Option<u32>) {
    match op {
        ChannelOp::CreateChannel { channel } => ("CreateChannel", Some(channel.id)),
        ChannelOp::EditChannel { id, .. } => ("EditChannel", Some(*id)),
        ChannelOp::UpdateChannel { id, .. } => ("UpdateChannel", Some(*id)),
        ChannelOp::MarkPendingDelete { id, .. } => ("MarkPendingDelete", Some(*id)),
        ChannelOp::DeleteChannel { id, .. } => ("DeleteChannel", Some(*id)),
        ChannelOp::CancelPendingDelete { id, .. } => ("CancelPendingDelete", Some(*id)),
        ChannelOp::AddLink { a, .. } => ("AddLink", Some(*a)),
        ChannelOp::RemoveLink { a, .. } => ("RemoveLink", Some(*a)),
        ChannelOp::SetAcls { channel_id, .. } => ("SetAcls", Some(*channel_id)),
        ChannelOp::InstallSnapshot { .. } => ("InstallSnapshot", None),
    }
}

pub struct S2SManager {
    enabled: bool,
    config_error: Option<String>,
    transport_config: Option<TransportConfig>,
    overlay_config: s2s_overlay::OverlayConfig,
    application_config: s2s_application::ApplicationConfig,
    transport_tuning: s2s_transport::TransportTuning,
    overlay_tuning: s2s_overlay::OverlayTuning,
    replication_config: s2s_replications::ReplicationConfig,
    status_http_listen: Option<SocketAddr>,
    local_geo: SharedNodeGeo,
    max_users: Arc<AtomicU64>,
    state: RwLock<S2SRuntimeState>,
}

#[derive(Default)]
struct S2SRuntimeState {
    transport: Option<ConnectionManager>,
    overlay: Option<OverlayNetwork>,
    local_geo: Option<SharedNodeGeo>,
    replications: Option<Arc<ReplicationManager>>,
    application: Option<Arc<s2s_application::ApplicationLayer>>,
    recipient_index: Option<Arc<RecipientIndex>>,
    server: Option<Weak<Box<Server>>>,
    channel_replications:
        HashMap<String, s2s_replications::StrictHandle<ChannelReplicationAdapter>>,
    ban_replication: Option<s2s_replications::StrictHandle<BanReplicationAdapter>>,
    client_replication: Option<s2s_replications::OwnerHandle<ClientReplicationAdapter>>,
    channel_blob_replications:
        HashMap<String, s2s_replications::BlobHandle<ChannelBlobReplicationAdapter>>,
    bridge_tasks: Vec<JoinHandle<()>>,
    gateway_tx: Option<S2SGatewayTx>,
    startup_duplicate_failures: u64,
    last_startup_duplicate_node: Option<NodeIdentifier>,
    #[cfg(any(test, feature = "pre-release-workload"))]
    inbound_chaos: Option<s2s_testing::LinkChaos>,
}

enum S2SNativeCommand {
    ApplyModeration {
        from: NodeIdentifier,
        envelope: ModerationEnvelope,
    },
    DeliverPluginData {
        from: NodeIdentifier,
        envelope: PluginDataEnvelope,
    },
    DeliverTextMessage {
        from: NodeIdentifier,
        envelope: TextMessageEnvelope,
    },
    DeliverVoice {
        from_immediate: NodeIdentifier,
        frame: VoiceFrame,
    },
}

enum S2SNativeClass {
    Control,
    Bulk,
    Voice,
}

impl S2SNativeCommand {
    fn class(&self) -> S2SNativeClass {
        match self {
            Self::ApplyModeration { .. } => S2SNativeClass::Control,
            Self::DeliverPluginData { .. } | Self::DeliverTextMessage { .. } => {
                S2SNativeClass::Bulk
            }
            Self::DeliverVoice { .. } => S2SNativeClass::Voice,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::ApplyModeration { .. } => "moderation",
            Self::DeliverPluginData { .. } => "plugin_data",
            Self::DeliverTextMessage { .. } => "text_message",
            Self::DeliverVoice { .. } => "voice",
        }
    }

    fn estimated_bytes(&self) -> usize {
        match self {
            Self::ApplyModeration { envelope, .. } => estimate_proto(envelope),
            Self::DeliverPluginData { envelope, .. } => estimate_proto(envelope),
            Self::DeliverTextMessage { envelope, .. } => estimate_proto(envelope),
            Self::DeliverVoice { frame, .. } => estimate_proto(frame),
        }
    }
}

enum NativeToS2SCommand {
    ProposeChannel {
        server_id: String,
        op: ChannelOp,
        accepted: Option<oneshot::Sender<()>>,
        respond: oneshot::Sender<ChannelOpProposeResult>,
    },
    ProposeBan {
        op: BanOp,
        respond: oneshot::Sender<bool>,
    },
    ProposeClientReplication(ClientStateLogEntry),
    RefreshVoiceRecipientIndex(RecipientIndexUpdate),
    DispatchPluginData {
        owner: NodeIdentifier,
        envelope: PluginDataEnvelope,
    },
    DispatchTextMessage {
        owner: NodeIdentifier,
        envelope: TextMessageEnvelope,
    },
    DispatchModeration {
        owner: NodeIdentifier,
        envelope: ModerationEnvelope,
    },
    DispatchUserStats {
        owner: NodeIdentifier,
        actor_session: u32,
        target_session: u32,
        stats_only: bool,
        server_id: String,
        respond: oneshot::Sender<Result<UserStatsReply, ApplicationError>>,
    },
    SendVoiceForChannel {
        sender_session: u32,
        server_id: String,
        source_channel: u32,
        is_terminator: bool,
        payload: Bytes,
    },
    SendVoiceForTargetChannels {
        sender_session: u32,
        server_id: String,
        target_channels: Arc<[u32]>,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
    },
    SendVoiceBroadcast {
        sender_session: u32,
        server_id: String,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
    },
}

enum S2SGatewayClass {
    Control,
    Replication,
    Bulk,
    Voice,
    Coalesced,
}

impl NativeToS2SCommand {
    fn class(&self) -> S2SGatewayClass {
        match self {
            Self::ProposeChannel { .. }
            | Self::ProposeBan { .. }
            | Self::DispatchModeration { .. }
            | Self::DispatchUserStats { .. } => S2SGatewayClass::Control,
            Self::ProposeClientReplication(_) => S2SGatewayClass::Replication,
            Self::DispatchPluginData { .. } | Self::DispatchTextMessage { .. } => {
                S2SGatewayClass::Bulk
            }
            Self::SendVoiceForChannel { .. }
            | Self::SendVoiceForTargetChannels { .. }
            | Self::SendVoiceBroadcast { .. } => S2SGatewayClass::Voice,
            Self::RefreshVoiceRecipientIndex(_) => S2SGatewayClass::Coalesced,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::ProposeChannel { .. } => "channel_proposal",
            Self::ProposeBan { .. } => "ban_proposal",
            Self::ProposeClientReplication(_) => "client_replication",
            Self::RefreshVoiceRecipientIndex(_) => "voice_recipient_index",
            Self::DispatchPluginData { .. } => "plugin_data",
            Self::DispatchTextMessage { .. } => "text_message",
            Self::DispatchModeration { .. } => "moderation",
            Self::DispatchUserStats { .. } => "user_stats",
            Self::SendVoiceForChannel { .. }
            | Self::SendVoiceForTargetChannels { .. }
            | Self::SendVoiceBroadcast { .. } => "voice",
        }
    }

    fn estimated_bytes(&self) -> usize {
        match self {
            Self::ProposeChannel { .. } | Self::ProposeBan { .. } => {
                S2S_GATEWAY_COMMAND_OVERHEAD_BYTES
            }
            Self::ProposeClientReplication(entry) => estimate_client_replication_entry(entry),
            Self::RefreshVoiceRecipientIndex(snapshot) => {
                estimate_recipient_index_snapshot(snapshot)
            }
            Self::DispatchPluginData { envelope, .. } => estimate_proto(envelope),
            Self::DispatchTextMessage { envelope, .. } => estimate_proto(envelope),
            Self::DispatchModeration { envelope, .. } => estimate_proto(envelope),
            Self::DispatchUserStats { server_id, .. } => {
                S2S_GATEWAY_COMMAND_OVERHEAD_BYTES.saturating_add(server_id.len())
            }
            Self::SendVoiceForChannel {
                server_id, payload, ..
            } => S2S_GATEWAY_COMMAND_OVERHEAD_BYTES
                .saturating_add(server_id.len())
                .saturating_add(payload.len()),
            Self::SendVoiceForTargetChannels {
                server_id,
                target_channels,
                payload,
                intent,
                ..
            } => S2S_GATEWAY_COMMAND_OVERHEAD_BYTES
                .saturating_add(server_id.len())
                .saturating_add(
                    target_channels
                        .len()
                        .saturating_mul(std::mem::size_of::<u32>()),
                )
                .saturating_add(payload.len())
                .saturating_add(intent.encoded_len()),
            Self::SendVoiceBroadcast {
                server_id,
                payload,
                intent,
                ..
            } => S2S_GATEWAY_COMMAND_OVERHEAD_BYTES
                .saturating_add(server_id.len())
                .saturating_add(payload.len())
                .saturating_add(intent.encoded_len()),
        }
    }

    fn voice_sender_session(&self) -> Option<u32> {
        match self {
            Self::SendVoiceForChannel { sender_session, .. }
            | Self::SendVoiceForTargetChannels { sender_session, .. }
            | Self::SendVoiceBroadcast { sender_session, .. } => Some(*sender_session),
            _ => None,
        }
    }
}

fn estimate_proto(message: &impl ProstMessage) -> usize {
    S2S_GATEWAY_COMMAND_OVERHEAD_BYTES.saturating_add(message.encoded_len())
}

fn estimate_client_replication_entry(entry: &ClientStateLogEntry) -> usize {
    S2S_GATEWAY_COMMAND_OVERHEAD_BYTES.saturating_add(
        rmp_serde::to_vec(entry)
            .map(|bytes| bytes.len())
            .unwrap_or(1024),
    )
}

fn estimate_recipient_index_snapshot(update: &RecipientIndexUpdate) -> usize {
    update
        .snapshot()
        .iter()
        .map(|(key, nodes)| {
            S2S_GATEWAY_COMMAND_OVERHEAD_BYTES
                .saturating_add(key.server_id().len())
                .saturating_add(std::mem::size_of::<u32>())
                .saturating_add(
                    nodes
                        .len()
                        .saturating_mul(std::mem::size_of::<NodeIdentifier>()),
                )
        })
        .sum::<usize>()
        .saturating_add(
            update
                .complete_servers()
                .iter()
                .map(String::len)
                .sum::<usize>(),
        )
        .saturating_add(
            update
                .covered_nodes()
                .len()
                .saturating_mul(std::mem::size_of::<NodeIdentifier>()),
        )
        .max(S2S_GATEWAY_COMMAND_OVERHEAD_BYTES)
}

#[derive(Clone)]
struct S2SGatewayTx {
    control: S2SAdaptiveSender<NativeToS2SCommand>,
    replication: S2SAdaptiveSender<NativeToS2SCommand>,
    bulk: S2SAdaptiveSender<NativeToS2SCommand>,
    voice: S2SAdaptiveSender<NativeToS2SCommand>,
    coalesced: S2SAdaptiveSender<NativeToS2SCommand>,
}

struct S2SGatewayRx {
    control: S2SAdaptiveReceiver<NativeToS2SCommand>,
    replication: S2SAdaptiveReceiver<NativeToS2SCommand>,
    bulk: S2SAdaptiveReceiver<NativeToS2SCommand>,
    voice: S2SAdaptiveReceiver<NativeToS2SCommand>,
    coalesced: S2SAdaptiveReceiver<NativeToS2SCommand>,
}

impl S2SGatewayTx {
    fn new(budget: S2SQueueBudget) -> (Self, S2SGatewayRx) {
        let max = budget.max_bytes();
        let control_bytes = max
            .saturating_mul(30)
            .checked_div(100)
            .unwrap_or(S2S_GATEWAY_CONTROL_MIN_BYTES)
            .max(S2S_GATEWAY_CONTROL_MIN_BYTES)
            .min(max);
        let replication_bytes = max
            .saturating_mul(25)
            .checked_div(100)
            .unwrap_or(S2S_GATEWAY_LANE_MIN_BYTES)
            .max(S2S_GATEWAY_LANE_MIN_BYTES)
            .min(max);
        let bulk_bytes = max
            .saturating_mul(20)
            .checked_div(100)
            .unwrap_or(S2S_GATEWAY_LANE_MIN_BYTES)
            .max(S2S_GATEWAY_LANE_MIN_BYTES)
            .min(max);
        let voice_bytes = max
            .saturating_mul(50)
            .checked_div(100)
            .unwrap_or(S2S_GATEWAY_LANE_MIN_BYTES)
            .max(S2S_GATEWAY_LANE_MIN_BYTES)
            .min(max);
        let coalesced_bytes = max
            .saturating_mul(10)
            .checked_div(100)
            .unwrap_or(S2S_GATEWAY_LANE_MIN_BYTES)
            .max(S2S_GATEWAY_LANE_MIN_BYTES)
            .min(max);

        let (control, control_rx) = S2SAdaptiveSender::new(budget.split(control_bytes));
        let (replication, replication_rx) = S2SAdaptiveSender::new(budget.split(replication_bytes));
        let (bulk, bulk_rx) = S2SAdaptiveSender::new(budget.split(bulk_bytes));
        let (voice, voice_rx) = S2SAdaptiveSender::new(budget.split(voice_bytes));
        let (coalesced, coalesced_rx) = S2SAdaptiveSender::new(budget.split(coalesced_bytes));
        (
            Self {
                control,
                replication,
                bulk,
                voice,
                coalesced,
            },
            S2SGatewayRx {
                control: control_rx,
                replication: replication_rx,
                bulk: bulk_rx,
                voice: voice_rx,
                coalesced: coalesced_rx,
            },
        )
    }

    async fn send_lossless(&self, command: NativeToS2SCommand) -> bool {
        match command.class() {
            S2SGatewayClass::Control => self.control.send(command).await,
            S2SGatewayClass::Replication => self.replication.send(command).await,
            S2SGatewayClass::Bulk => self.bulk.send(command).await,
            S2SGatewayClass::Coalesced => self.coalesced.send(command).await,
            S2SGatewayClass::Voice => self.voice.send(command).await,
        }
    }

    fn try_send_voice(&self, command: NativeToS2SCommand) -> bool {
        self.voice.try_send(command)
    }

    fn try_send_coalesced(&self, command: NativeToS2SCommand) -> bool {
        self.coalesced.try_send(command)
    }
}

#[derive(Clone)]
struct S2SNativeGatewayTx {
    control: S2SAdaptiveSender<S2SNativeCommand>,
    bulk: S2SAdaptiveSender<S2SNativeCommand>,
    voice: S2SAdaptiveSender<S2SNativeCommand>,
}

struct S2SNativeGatewayRx {
    control: S2SAdaptiveReceiver<S2SNativeCommand>,
    bulk: S2SAdaptiveReceiver<S2SNativeCommand>,
    voice: S2SAdaptiveReceiver<S2SNativeCommand>,
}

impl S2SNativeGatewayTx {
    fn new(budget: S2SQueueBudget) -> (Self, S2SNativeGatewayRx) {
        let max = budget.max_bytes();
        let control_bytes = max
            .saturating_mul(40)
            .checked_div(100)
            .unwrap_or(S2S_GATEWAY_CONTROL_MIN_BYTES)
            .max(S2S_GATEWAY_CONTROL_MIN_BYTES)
            .min(max);
        let bulk_bytes = max
            .saturating_mul(25)
            .checked_div(100)
            .unwrap_or(S2S_GATEWAY_LANE_MIN_BYTES)
            .max(S2S_GATEWAY_LANE_MIN_BYTES)
            .min(max);
        let voice_bytes = max
            .saturating_mul(50)
            .checked_div(100)
            .unwrap_or(S2S_GATEWAY_LANE_MIN_BYTES)
            .max(S2S_GATEWAY_LANE_MIN_BYTES)
            .min(max);

        let (control, control_rx) = S2SAdaptiveSender::new(budget.split(control_bytes));
        let (bulk, bulk_rx) = S2SAdaptiveSender::new(budget.split(bulk_bytes));
        let (voice, voice_rx) = S2SAdaptiveSender::new(budget.split(voice_bytes));
        (
            Self {
                control,
                bulk,
                voice,
            },
            S2SNativeGatewayRx {
                control: control_rx,
                bulk: bulk_rx,
                voice: voice_rx,
            },
        )
    }

    async fn send_lossless(&self, command: S2SNativeCommand) -> bool {
        match command.class() {
            S2SNativeClass::Control => self.control.send(command).await,
            S2SNativeClass::Bulk => self.bulk.send(command).await,
            S2SNativeClass::Voice => self.voice.send(command).await,
        }
    }

    fn try_send_voice(&self, command: S2SNativeCommand) -> bool {
        self.voice.try_send(command)
    }
}

impl EstimatedS2SCommand for NativeToS2SCommand {
    fn label(&self) -> &'static str {
        NativeToS2SCommand::label(self)
    }

    fn estimated_bytes(&self) -> usize {
        NativeToS2SCommand::estimated_bytes(self)
    }
}

impl EstimatedS2SCommand for S2SNativeCommand {
    fn label(&self) -> &'static str {
        S2SNativeCommand::label(self)
    }

    fn estimated_bytes(&self) -> usize {
        S2SNativeCommand::estimated_bytes(self)
    }
}

fn auto_s2s_gateway_budget_bytes() -> usize {
    let detected = available_memory_bytes().map(|bytes| {
        bytes
            .checked_div(S2S_GATEWAY_MEMORY_FRACTION_DIVISOR)
            .unwrap_or(S2S_GATEWAY_FALLBACK_BUDGET_BYTES)
    });
    let bytes = detected.unwrap_or(S2S_GATEWAY_FALLBACK_BUDGET_BYTES);
    bytes
        .clamp(S2S_GATEWAY_MIN_BUDGET_BYTES, S2S_GATEWAY_MAX_BUDGET_BYTES)
        .min(usize::MAX as u64) as usize
}

fn auto_s2s_gateway_budget() -> S2SQueueBudget {
    S2SQueueBudget::new(auto_s2s_gateway_budget_bytes(), S2S_GATEWAY_LANE_MIN_BYTES)
}

#[cfg(windows)]
fn available_memory_bytes() -> Option<u64> {
    use std::mem::size_of;
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    let mut status = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        dwMemoryLoad: 0,
        ullTotalPhys: 0,
        ullAvailPhys: 0,
        ullTotalPageFile: 0,
        ullAvailPageFile: 0,
        ullTotalVirtual: 0,
        ullAvailVirtual: 0,
        ullAvailExtendedVirtual: 0,
    };
    let ok = unsafe { GlobalMemoryStatusEx(&mut status) };
    (ok != 0).then_some(status.ullAvailPhys)
}

#[cfg(not(windows))]
fn available_memory_bytes() -> Option<u64> {
    parse_mem_available_from_proc().or_else(parse_cgroup_memory_available)
}

#[cfg(not(windows))]
fn parse_mem_available_from_proc() -> Option<u64> {
    let contents = std::fs::read_to_string("/proc/meminfo").ok()?;
    contents.lines().find_map(|line| {
        let rest = line.strip_prefix("MemAvailable:")?.trim();
        let kb = rest.split_whitespace().next()?.parse::<u64>().ok()?;
        kb.checked_mul(1024)
    })
}

#[cfg(not(windows))]
fn parse_cgroup_memory_available() -> Option<u64> {
    let max = std::fs::read_to_string("/sys/fs/cgroup/memory.max")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())?;
    let current = std::fs::read_to_string("/sys/fs/cgroup/memory.current")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())?;
    max.checked_sub(current)
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum ChannelOpProposeResult {
    Proposed,
    Unavailable,
    Failed(String),
}

impl ChannelOpProposeResult {
    pub fn failed(reason: impl Into<String>) -> Self {
        Self::Failed(reason.into())
    }

    pub fn is_proposed(&self) -> bool {
        matches!(self, Self::Proposed)
    }

    pub fn should_apply_locally(&self) -> bool {
        matches!(self, Self::Unavailable)
    }

    pub fn failure_reason(&self) -> Option<&str> {
        match self {
            Self::Failed(reason) => Some(reason),
            Self::Proposed | Self::Unavailable => None,
        }
    }
}

#[must_use]
pub struct ChannelOpProposal {
    accepted: Option<oneshot::Receiver<()>>,
    completed: Option<oneshot::Receiver<ChannelOpProposeResult>>,
    timeout: Duration,
}

impl ChannelOpProposal {
    pub async fn accepted(&mut self) -> ChannelOpProposeResult {
        let Some(accepted) = self.accepted.take() else {
            return ChannelOpProposeResult::failed(
                "s2s channel proposal acceptance was unavailable",
            );
        };
        match tokio::time::timeout(self.timeout, accepted).await {
            Ok(Ok(())) => ChannelOpProposeResult::Proposed,
            Ok(Err(_)) => match self.wait_completed(self.timeout).await {
                ChannelOpCompletion::Completed(result) => result,
                ChannelOpCompletion::Pending => {
                    let reason = "s2s channel proposal timed out waiting for gateway response";
                    error!(reason);
                    ChannelOpProposeResult::failed(reason)
                }
            },
            Err(_) => {
                let reason = "s2s channel proposal timed out waiting for acceptance";
                error!(reason);
                ChannelOpProposeResult::failed(reason)
            }
        }
    }

    pub async fn completed(mut self) -> ChannelOpProposeResult {
        match self.wait_completed(self.timeout).await {
            ChannelOpCompletion::Completed(result) => result,
            ChannelOpCompletion::Pending => {
                let reason = "s2s channel proposal timed out waiting for gateway response";
                error!(reason);
                ChannelOpProposeResult::failed(reason)
            }
        }
    }

    pub async fn completed_after_acceptance(mut self) -> ChannelOpProposeResult {
        let Some(completed) = self.completed.take() else {
            return ChannelOpProposeResult::failed("s2s channel proposal response was unavailable");
        };
        match completed.await {
            Ok(result) => result,
            Err(_) => {
                let reason = "s2s gateway dropped accepted channel proposal response";
                error!(reason);
                ChannelOpProposeResult::failed(reason)
            }
        }
    }

    pub async fn wait_completed_for(&mut self, timeout: Duration) -> ChannelOpCompletion {
        self.wait_completed(timeout).await
    }

    async fn wait_completed(&mut self, timeout: Duration) -> ChannelOpCompletion {
        let Some(completed) = self.completed.as_mut() else {
            return ChannelOpCompletion::Completed(ChannelOpProposeResult::failed(
                "s2s channel proposal response was unavailable",
            ));
        };
        match tokio::time::timeout(timeout, completed).await {
            Ok(Ok(result)) => {
                self.completed = None;
                ChannelOpCompletion::Completed(result)
            }
            Ok(Err(_)) => {
                self.completed = None;
                let reason = "s2s gateway dropped channel proposal response";
                error!(reason);
                ChannelOpCompletion::Completed(ChannelOpProposeResult::failed(reason))
            }
            Err(_) => ChannelOpCompletion::Pending,
        }
    }
}

#[must_use]
pub enum ChannelOpCompletion {
    Completed(ChannelOpProposeResult),
    Pending,
}

#[must_use]
pub enum ChannelOpProposalStart {
    Started(ChannelOpProposal),
    Unavailable,
}

impl ChannelOpProposalStart {
    pub async fn completed(self) -> ChannelOpProposeResult {
        match self {
            Self::Started(proposal) => proposal.completed().await,
            Self::Unavailable => ChannelOpProposeResult::Unavailable,
        }
    }

    pub fn should_apply_locally(&self) -> bool {
        matches!(self, Self::Unavailable)
    }

    pub fn into_started(self) -> Option<ChannelOpProposal> {
        match self {
            Self::Started(proposal) => Some(proposal),
            Self::Unavailable => None,
        }
    }
}

struct S2SGateways {
    native_tx: S2SNativeGatewayTx,
    s2s_tx: S2SGatewayTx,
    s2s_rx: S2SGatewayRx,
    native_runtime: tokio::runtime::Handle,
}

pub(crate) struct S2SRuntimeTask {
    thread: Option<thread::JoinHandle<()>>,
    native_tasks: Vec<JoinHandle<()>>,
}

impl S2SRuntimeTask {
    pub(crate) async fn join(mut self) {
        if let Some(thread) = self.thread.take() {
            match tokio::task::spawn_blocking(move || thread.join()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    warn!("s2s runtime thread panicked");
                }
                Err(e) => {
                    warn!(error = %e, "failed to join s2s runtime thread");
                }
            }
        }

        for task in self.native_tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

impl S2SManager {
    pub fn initialize(config: &shitspeak_runtime_config::Config) -> Self {
        let auto_advertise_host = config
            .register_hostname
            .as_deref()
            .map(str::trim)
            .filter(|host| !host.is_empty());
        let (transport_config, config_error) = match config
            .s2s
            .transport_config_with_max_users_and_auto_advertise_host(
                config.max_users,
                auto_advertise_host,
            ) {
            Ok(cfg) => (cfg, None),
            Err(e) => (None, Some(e)),
        };

        #[cfg(feature = "pre-release-workload")]
        let inbound_chaos = pre_release_workload::enabled().then(|| {
            let local_node = config.s2s.local_node_id().unwrap_or_default();
            pre_release_workload::configured_chaos(local_node)
        });
        let state = S2SRuntimeState {
            #[cfg(feature = "pre-release-workload")]
            inbound_chaos,
            ..S2SRuntimeState::default()
        };

        Self {
            enabled: config.s2s.is_enabled(),
            config_error,
            transport_config,
            overlay_config: config.s2s.overlay_config(),
            application_config: config.s2s.application.clone(),
            transport_tuning: config.s2s.transport.clone(),
            overlay_tuning: config.s2s.overlay.clone(),
            replication_config: config.s2s.replications.clone().into(),
            status_http_listen: config.s2s.status_http_listen,
            local_geo: SharedNodeGeo::new(config.s2s.geo.manual_geo()),
            max_users: Arc::new(AtomicU64::new(config.max_users)),
            state: RwLock::new(state),
        }
    }

    /// Apply the operator-configured transport tunables on top of a
    /// caller-built [`s2s_transport::TransportConfig`] (which still owns
    /// PKI paths, listeners, and the rest).
    pub fn apply_transport_tuning(
        &self,
        cfg: s2s_transport::TransportConfig,
    ) -> s2s_transport::TransportConfig {
        self.transport_tuning.apply(cfg)
    }

    /// Fallible variant that also loads any configured compression dictionary.
    pub fn try_apply_transport_tuning(
        &self,
        cfg: s2s_transport::TransportConfig,
    ) -> Result<s2s_transport::TransportConfig, String> {
        self.transport_tuning.try_apply(cfg)
    }

    /// Apply the operator-configured overlay tunables on top of a
    /// caller-built [`s2s_overlay::OverlayConfig`].
    pub fn apply_overlay_tuning(
        &self,
        cfg: s2s_overlay::OverlayConfig,
    ) -> s2s_overlay::OverlayConfig {
        self.overlay_tuning
            .apply(cfg)
            .with_transport_routing_policy(self.transport_tuning.routing_policy())
    }

    /// Resolved replication tunables, ready to hand to
    /// [`s2s_replications::ReplicationManager::with_config`].
    pub fn replication_config(&self) -> &s2s_replications::ReplicationConfig {
        &self.replication_config
    }

    pub fn prometheus_metrics_text(&self) -> Option<String> {
        let state = self.state.read();
        if let (Some(overlay), Some(transport)) = (state.overlay.as_ref(), state.transport.as_ref())
        {
            return Some(s2s_status::render_prometheus_metrics(
                overlay,
                transport,
                state.local_geo.as_ref().and_then(SharedNodeGeo::get),
            ));
        }
        (state.startup_duplicate_failures > 0).then(|| {
            let node = state
                .last_startup_duplicate_node
                .map(|node| node.to_string())
                .unwrap_or_default();
            format!(
                "# HELP shitspeak_s2s_duplicate_node_startup_failures_total S2S startup failures caused by duplicate node-id detection.\n# TYPE shitspeak_s2s_duplicate_node_startup_failures_total counter\nshitspeak_s2s_duplicate_node_startup_failures_total{{node=\"{node}\"}} {}\n",
                state.startup_duplicate_failures
            )
        })
    }

    pub(crate) fn prometheus_samples(&self) -> Option<Vec<s2s_status::PrometheusSample>> {
        let state = self.state.read();
        if let (Some(overlay), Some(transport)) = (state.overlay.as_ref(), state.transport.as_ref())
        {
            return Some(s2s_status::prometheus_samples(
                overlay,
                transport,
                state.local_geo.as_ref().and_then(SharedNodeGeo::get),
            ));
        }
        (state.startup_duplicate_failures > 0).then(|| {
            vec![s2s_status::PrometheusSample::new(
                "shitspeak_s2s_duplicate_node_startup_failures_total",
                vec![(
                    "node".to_owned(),
                    state
                        .last_startup_duplicate_node
                        .map(|node| node.to_string())
                        .unwrap_or_default(),
                )],
                state.startup_duplicate_failures as f64,
            )]
        })
    }

    pub fn prometheus_remote_write_requests(
        &self,
        batch_size: usize,
        external_labels: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<Vec<u8>>> {
        let samples = self.prometheus_samples()?;
        if samples.is_empty() {
            return Some(Vec::new());
        }
        let timestamp_ms = crate::observability::now_unix_ms();
        let batch_size = batch_size.max(1);
        Some(
            samples
                .chunks(batch_size)
                .map(|chunk| {
                    crate::observability::remote_write_body_with_labels(
                        chunk,
                        timestamp_ms,
                        external_labels,
                    )
                })
                .collect(),
        )
    }

    /// Attach a fully-started overlay and spin up the `ReplicationManager`
    /// and `ApplicationLayer` on top of it. Mostly used by older tests;
    /// production startup goes through [`Self::spawn_runtime_task`].
    pub fn attach_overlay(&self, overlay: OverlayNetwork) {
        overlay.update_local_max_users(self.max_users.load(std::sync::atomic::Ordering::Relaxed));
        let repl =
            ReplicationManager::with_config(overlay.clone(), self.replication_config.clone());
        let app = s2s_application::ApplicationLayer::new_with_capacity_source(
            overlay.clone(),
            self.application_config.clone(),
            self.max_users.clone(),
        );
        let mut state = self.state.write();
        state.overlay = Some(overlay);
        state.local_geo = Some(self.local_geo.clone());
        state.replications = Some(repl);
        state.application = Some(app);
    }

    pub fn overlay(&self) -> Option<OverlayNetwork> {
        self.state.read().overlay.clone()
    }

    #[cfg(test)]
    pub(crate) fn transport(&self) -> Option<ConnectionManager> {
        self.state.read().transport.clone()
    }

    pub fn update_max_users(&self, max_users: u64) {
        self.max_users
            .store(max_users, std::sync::atomic::Ordering::Relaxed);
        if let Some(overlay) = self.overlay() {
            overlay.update_local_max_users(max_users);
        }
    }

    pub fn update_route_transit_messages(&self, enabled: bool) {
        if let Some(overlay) = self.overlay() {
            overlay.update_route_transit_messages(enabled);
        }
    }

    pub fn cluster_max_users(&self) -> Option<u64> {
        self.overlay().map(|overlay| {
            let local_node_id = overlay.local_node_id();
            let local_max_users = self.max_users.load(std::sync::atomic::Ordering::Relaxed);
            overlay
                .members()
                .into_iter()
                .filter(|member| {
                    member.node_id() != local_node_id
                        && member.status() == s2s_overlay::MemberStatus::Alive
                })
                .map(|member| member.max_users())
                .fold(local_max_users, u64::saturating_add)
        })
    }

    pub fn replications(&self) -> Option<Arc<ReplicationManager>> {
        self.state.read().replications.clone()
    }

    pub fn application(&self) -> Option<Arc<s2s_application::ApplicationLayer>> {
        self.state.read().application.clone()
    }

    pub fn log_startup_summary(&self) {
        if !self.enabled {
            info!("s2s disabled");
            return;
        }
        if let Some(error) = &self.config_error {
            warn!(error = %error, "s2s enabled but configuration is invalid");
            return;
        }
        let seed_count = self
            .transport_config
            .as_ref()
            .map(|cfg| cfg.seed_address_count())
            .unwrap_or(0);
        info!(seed_count, "s2s enabled");
    }

    fn clear_gateway_tx(&self) {
        self.state.write().gateway_tx = None;
    }

    pub async fn propose_channel_op(
        &self,
        server_id: Option<&str>,
        op: ChannelOp,
    ) -> ChannelOpProposeResult {
        self.start_channel_op_proposal(server_id, op)
            .await
            .completed()
            .await
    }

    pub async fn start_channel_op_proposal(
        &self,
        server_id: Option<&str>,
        op: ChannelOp,
    ) -> ChannelOpProposalStart {
        let server_id = server_id.unwrap_or(DEFAULT_SERVER_ID).to_owned();
        let Some(tx) = self.state.read().gateway_tx.clone() else {
            return ChannelOpProposalStart::Unavailable;
        };
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (respond, rx) = oneshot::channel();
        if !tx
            .send_lossless(NativeToS2SCommand::ProposeChannel {
                server_id,
                op,
                accepted: Some(accepted_tx),
                respond,
            })
            .await
        {
            return ChannelOpProposalStart::Unavailable;
        }
        ChannelOpProposalStart::Started(ChannelOpProposal {
            accepted: Some(accepted_rx),
            completed: Some(rx),
            timeout: strict_proposal_gateway_response_timeout(&self.replication_config),
        })
    }

    async fn propose_channel_op_direct_with_accepted(
        &self,
        server_id: &str,
        op: ChannelOp,
        accepted: Option<oneshot::Sender<()>>,
    ) -> ChannelOpProposeResult {
        let started_at = Instant::now();
        let (op_kind, channel_id) = channel_op_log_fields(&op);
        let handle = match self.channel_replication_handle(server_id) {
            Some(handle) => handle,
            None => {
                error!(
                    server_id,
                    op_kind,
                    channel_id = ?channel_id,
                    "s2s channel op propose failed: replication handle unavailable"
                );
                return ChannelOpProposeResult::failed(
                    "s2s channel replication handle unavailable",
                );
            }
        };
        let operation = ChannelOperation {
            server_id: server_id.to_owned(),
            version: 0,
            node_id: handle.local_node_id(),
            timestamp: chrono::Utc::now().timestamp(),
            emits_client_message: true,
            op,
        };
        debug!(
            server_id,
            op_kind,
            channel_id = ?channel_id,
            node_id = operation.node_id,
            "s2s channel op proposal started"
        );
        match handle.propose_with_accepted(operation).await {
            Ok(mut proposal) => {
                if let Some(accepted) = accepted {
                    if let Some(accepted_rx) = proposal.take_accepted_receiver() {
                        let accepted_started_at = started_at;
                        let accepted_server_id = server_id.to_owned();
                        tokio::spawn(async move {
                            if accepted_rx.await.is_ok() {
                                let elapsed = accepted_started_at.elapsed();
                                if elapsed >= S2S_CHANNEL_REPLICATION_SLOW_STAGE {
                                    warn!(
                                        server_id = %accepted_server_id,
                                        op_kind,
                                        channel_id = ?channel_id,
                                        accepted_elapsed_ms = elapsed.as_millis(),
                                        "s2s channel op proposal accepted slowly"
                                    );
                                } else {
                                    debug!(
                                        server_id = %accepted_server_id,
                                        op_kind,
                                        channel_id = ?channel_id,
                                        accepted_elapsed_ms = elapsed.as_millis(),
                                        "s2s channel op proposal accepted"
                                    );
                                }
                                let _ = accepted.send(());
                            }
                        });
                    }
                }
                match proposal.delivered().await {
                    Ok(version) => {
                        let elapsed = started_at.elapsed();
                        if elapsed >= S2S_CHANNEL_REPLICATION_SLOW_STAGE {
                            warn!(
                                server_id,
                                op_kind,
                                channel_id = ?channel_id,
                                version,
                                delivered_elapsed_ms = elapsed.as_millis(),
                                "s2s channel op proposal delivered slowly"
                            );
                        } else {
                            debug!(
                                server_id,
                                op_kind,
                                channel_id = ?channel_id,
                                version,
                                delivered_elapsed_ms = elapsed.as_millis(),
                                "s2s channel op proposal delivered"
                            );
                        }
                        ChannelOpProposeResult::Proposed
                    }
                    Err(e) => {
                        let reason = e.to_string();
                        error!(
                            server_id,
                            op_kind,
                            channel_id = ?channel_id,
                            elapsed_ms = started_at.elapsed().as_millis(),
                            error = %e,
                            "s2s channel op propose failed"
                        );
                        ChannelOpProposeResult::failed(reason)
                    }
                }
            }
            Err(e) => {
                let reason = e.to_string();
                error!(
                    server_id,
                    op_kind,
                    channel_id = ?channel_id,
                    elapsed_ms = started_at.elapsed().as_millis(),
                    error = %e,
                    "s2s channel op propose failed"
                );
                ChannelOpProposeResult::failed(reason)
            }
        }
    }

    pub async fn propose_ban_op(&self, op: BanOp) -> bool {
        let Some(tx) = self.state.read().gateway_tx.clone() else {
            return false;
        };
        let (respond, rx) = oneshot::channel();
        if !tx
            .send_lossless(NativeToS2SCommand::ProposeBan { op, respond })
            .await
        {
            return false;
        }
        tokio::time::timeout(
            strict_proposal_gateway_response_timeout(&self.replication_config),
            rx,
        )
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false)
    }

    async fn propose_ban_op_direct(&self, op: BanOp) -> bool {
        let Some(handle) = self.state.read().ban_replication.clone() else {
            return false;
        };
        let operation = BanOperation {
            version: 0,
            node_id: handle.local_node_id(),
            timestamp: chrono::Utc::now().timestamp(),
            op,
        };
        match handle.propose(operation).await {
            Ok(_) => true,
            Err(e) => {
                warn!(error = %e, "s2s ban op propose failed");
                false
            }
        }
    }

    async fn send_s2s_lossless_command(&self, command: NativeToS2SCommand) -> bool {
        let Some(tx) = self.state.read().gateway_tx.clone() else {
            trace!(
                label = command.label(),
                "s2s gateway unavailable; dropping command"
            );
            return false;
        };
        tx.send_lossless(command).await
    }

    pub async fn dispatch_plugin_data(
        &self,
        owner: NodeIdentifier,
        envelope: PluginDataEnvelope,
    ) -> bool {
        self.send_s2s_lossless_command(NativeToS2SCommand::DispatchPluginData { owner, envelope })
            .await
    }

    pub async fn dispatch_text_message(
        &self,
        owner: NodeIdentifier,
        envelope: TextMessageEnvelope,
    ) -> bool {
        self.send_s2s_lossless_command(NativeToS2SCommand::DispatchTextMessage { owner, envelope })
            .await
    }

    pub async fn dispatch_moderation_user_state(
        &self,
        server_id: Option<&str>,
        actor: ClientSessionIdentifier,
        target: ClientSessionIdentifier,
        patch: UserStatePatch,
    ) -> bool {
        let server_id = server_id.unwrap_or(DEFAULT_SERVER_ID);
        let envelope = ModerationEnvelope {
            actor_session: actor.to_u32(),
            target_session: target.to_u32(),
            issued_at_ms: now_ms(),
            server_id: server_id.to_owned(),
            command: Some(ModerationCommand::UserState(patch)),
        };
        self.send_s2s_lossless_command(NativeToS2SCommand::DispatchModeration {
            owner: target.get_node_id(),
            envelope,
        })
        .await
    }

    pub async fn dispatch_moderation_user_remove(
        &self,
        server_id: Option<&str>,
        actor: ClientSessionIdentifier,
        target: ClientSessionIdentifier,
        patch: UserRemovePatch,
    ) -> bool {
        let server_id = server_id.unwrap_or(DEFAULT_SERVER_ID);
        let envelope = ModerationEnvelope {
            actor_session: actor.to_u32(),
            target_session: target.to_u32(),
            issued_at_ms: now_ms(),
            server_id: server_id.to_owned(),
            command: Some(ModerationCommand::UserRemove(patch)),
        };
        self.send_s2s_lossless_command(NativeToS2SCommand::DispatchModeration {
            owner: target.get_node_id(),
            envelope,
        })
        .await
    }

    pub async fn dispatch_user_stats_request(
        &self,
        owner: NodeIdentifier,
        actor_session: u32,
        target_session: u32,
        stats_only: bool,
        server_id: String,
    ) -> Result<UserStatsReply, ApplicationError> {
        let Some(tx) = self.state.read().gateway_tx.clone() else {
            return Err(ApplicationError::Unavailable);
        };
        let (respond, rx) = oneshot::channel();
        if !tx
            .send_lossless(NativeToS2SCommand::DispatchUserStats {
                owner,
                actor_session,
                target_session,
                stats_only,
                server_id,
                respond,
            })
            .await
        {
            return Err(ApplicationError::Unavailable);
        }
        tokio::time::timeout(S2S_GATEWAY_RESPONSE_TIMEOUT, rx)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(Err(ApplicationError::Unavailable))
    }

    pub fn send_voice_for_channel(
        &self,
        sender_session: u32,
        server_id: String,
        source_channel: u32,
        is_terminator: bool,
        payload: Bytes,
    ) -> bool {
        let Some(tx) = self.state.read().gateway_tx.clone() else {
            trace!(label = "voice", "s2s gateway unavailable; dropping command");
            record_s2s_gateway_drop(
                S2SVoiceGatewayDropDirection::NativeToS2s,
                S2SVoiceGatewayDropReason::Unavailable,
            );
            return false;
        };
        let sent = tx.try_send_voice(NativeToS2SCommand::SendVoiceForChannel {
            sender_session,
            server_id,
            source_channel,
            is_terminator,
            payload,
        });
        if !sent {
            record_s2s_gateway_drop(
                S2SVoiceGatewayDropDirection::NativeToS2s,
                S2SVoiceGatewayDropReason::FullOrClosed,
            );
        }
        sent
    }

    pub fn send_voice_for_target_channels(
        &self,
        sender_session: u32,
        server_id: String,
        target_channels: Arc<[u32]>,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
    ) -> bool {
        let Some(tx) = self.state.read().gateway_tx.clone() else {
            trace!(label = "voice", "s2s gateway unavailable; dropping command");
            record_s2s_gateway_drop(
                S2SVoiceGatewayDropDirection::NativeToS2s,
                S2SVoiceGatewayDropReason::Unavailable,
            );
            return false;
        };
        let sent = tx.try_send_voice(NativeToS2SCommand::SendVoiceForTargetChannels {
            sender_session,
            server_id,
            target_channels,
            target_kind,
            is_terminator,
            payload,
            intent,
        });
        if !sent {
            record_s2s_gateway_drop(
                S2SVoiceGatewayDropDirection::NativeToS2s,
                S2SVoiceGatewayDropReason::FullOrClosed,
            );
        }
        sent
    }

    pub fn send_voice_broadcast(
        &self,
        sender_session: u32,
        server_id: String,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
    ) -> bool {
        let Some(tx) = self.state.read().gateway_tx.clone() else {
            trace!(label = "voice", "s2s gateway unavailable; dropping command");
            record_s2s_gateway_drop(
                S2SVoiceGatewayDropDirection::NativeToS2s,
                S2SVoiceGatewayDropReason::Unavailable,
            );
            return false;
        };
        let sent = tx.try_send_voice(NativeToS2SCommand::SendVoiceBroadcast {
            sender_session,
            server_id,
            target_kind,
            is_terminator,
            payload,
            intent,
        });
        if !sent {
            record_s2s_gateway_drop(
                S2SVoiceGatewayDropDirection::NativeToS2s,
                S2SVoiceGatewayDropReason::FullOrClosed,
            );
        }
        sent
    }

    pub async fn get_channel_blob(&self, server_id: Option<&str>, key: &str) -> Option<Bytes> {
        let server_id = server_id.unwrap_or(DEFAULT_SERVER_ID);
        let handle = self.channel_blob_replication_handle(server_id)?;
        handle.get(key).await
    }

    fn channel_replication_handle(
        &self,
        server_id: &str,
    ) -> Option<s2s_replications::StrictHandle<ChannelReplicationAdapter>> {
        {
            let state = self.state.read();
            if let Some(handle) = state.channel_replications.get(server_id).cloned() {
                return Some(handle);
            }
        }

        let (replications, server) = {
            let state = self.state.read();
            let replications = state.replications.clone()?;
            let server = state.server.clone()?.upgrade()?;
            (replications, server)
        };

        match self.register_channel_replication_scope(&replications, &server, server_id) {
            Ok(handle) => Some(handle),
            Err(e) => {
                warn!(server_id, error = %e, "failed to register scoped s2s channel replication");
                None
            }
        }
    }

    fn channel_blob_replication_handle(
        &self,
        server_id: &str,
    ) -> Option<s2s_replications::BlobHandle<ChannelBlobReplicationAdapter>> {
        {
            let state = self.state.read();
            if let Some(handle) = state.channel_blob_replications.get(server_id).cloned() {
                return Some(handle);
            }
        }

        let (replications, server) = {
            let state = self.state.read();
            let replications = state.replications.clone()?;
            let server = state.server.clone()?.upgrade()?;
            (replications, server)
        };

        match self.register_channel_blob_replication_scope(&replications, &server, server_id) {
            Ok(handle) => Some(handle),
            Err(e) => {
                warn!(server_id, error = %e, "failed to register scoped s2s channel blob replication");
                None
            }
        }
    }

    pub(crate) fn spawn_runtime_task(
        self: Arc<Self>,
        server: Weak<Box<Server>>,
        shutdown: watch::Receiver<()>,
    ) -> S2SRuntimeTask {
        let native_runtime = tokio::runtime::Handle::current();
        let gateway_budget = auto_s2s_gateway_budget();
        let (native_tx, native_rx) = S2SNativeGatewayTx::new(gateway_budget.clone());
        let (s2s_tx, s2s_rx) = S2SGatewayTx::new(gateway_budget);
        if self.enabled && self.config_error.is_none() && self.transport_config.is_some() {
            self.state.write().gateway_tx = Some(s2s_tx.clone());
        } else {
            self.clear_gateway_tx();
        }
        let native_gateway_task = native_runtime.spawn(run_native_gateway(
            server.clone(),
            native_rx,
            shutdown.clone(),
        ));
        let gateways = S2SGateways {
            native_tx,
            s2s_tx,
            s2s_rx,
            native_runtime,
        };

        let thread = thread::Builder::new()
            .name("s2s-runtime".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .thread_name("s2s-runtime-worker")
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(e) => {
                        warn!(error = %e, "failed to build s2s tokio runtime");
                        return;
                    }
                };

                runtime.block_on(async move {
                    self.run_runtime(server, shutdown, gateways).await;
                });
            });

        match thread {
            Ok(thread) => S2SRuntimeTask {
                thread: Some(thread),
                native_tasks: vec![native_gateway_task],
            },
            Err(e) => {
                warn!(error = %e, "failed to spawn s2s runtime thread");
                S2SRuntimeTask {
                    thread: None,
                    native_tasks: vec![native_gateway_task],
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn install_test_inbound_chaos(&self, chaos: s2s_testing::LinkChaos) {
        self.state.write().inbound_chaos = Some(chaos);
    }

    #[cfg(test)]
    pub(crate) fn test_inbound_chaos(&self) -> Option<s2s_testing::LinkChaos> {
        self.state.read().inbound_chaos.clone()
    }

    async fn run_runtime(
        self: Arc<Self>,
        server: Weak<Box<Server>>,
        mut shutdown: watch::Receiver<()>,
        gateways: S2SGateways,
    ) {
        if !self.enabled {
            self.clear_gateway_tx();
            drop(gateways);
            let _ = shutdown.changed().await;
            return;
        }

        if let Some(error) = &self.config_error {
            warn!(error = %error, "s2s startup skipped");
            self.clear_gateway_tx();
            drop(gateways);
            let _ = shutdown.changed().await;
            return;
        }

        let Some(transport_config) = self.transport_config.clone() else {
            warn!("s2s startup skipped: no transport config");
            self.clear_gateway_tx();
            drop(gateways);
            let _ = shutdown.changed().await;
            return;
        };

        let (transport, inbound) = match ConnectionManager::start(transport_config).await {
            Ok(parts) => parts,
            Err(e) => {
                warn!(error = %e, "s2s transport startup failed");
                self.clear_gateway_tx();
                drop(gateways);
                let _ = shutdown.changed().await;
                return;
            }
        };
        #[cfg(any(test, feature = "pre-release-workload"))]
        let inbound = {
            let chaos = self.state.read().inbound_chaos.clone();
            if let Some(chaos) = chaos {
                chaos.install(inbound)
            } else {
                inbound
            }
        };

        let local_node = transport.local_node_id();
        let preflight_window = self
            .overlay_config
            .hello_interval()
            .saturating_mul(2)
            .min(self.overlay_config.hello_dead_interval())
            .min(Duration::from_millis(250))
            .max(Duration::from_millis(100));
        let (inbound, duplicate_evidence) =
            s2s_overlay::duplicate_startup_preflight(local_node, inbound, preflight_window).await;
        if let Some(evidence) = duplicate_evidence {
            error!(
                node = local_node,
                source = evidence.source(),
                kind = evidence.kind(),
                "fatal s2s startup failure: duplicate local node id observed on the network; disabling S2S for this server process"
            );
            {
                let mut state = self.state.write();
                state.startup_duplicate_failures =
                    state.startup_duplicate_failures.saturating_add(1);
                state.last_startup_duplicate_node = Some(local_node);
            }
            transport.shutdown().await;
            self.clear_gateway_tx();
            drop(gateways);
            let _ = shutdown.changed().await;
            return;
        }

        let local_geo = self.local_geo.clone();

        let overlay = match OverlayNetwork::start_with_max_users(
            transport.clone(),
            inbound,
            self.overlay_config.clone(),
            self.max_users.clone(),
        )
        .await
        {
            Ok(overlay) => overlay,
            Err(e) => {
                warn!(error = %e, "s2s overlay startup failed");
                transport.shutdown().await;
                self.clear_gateway_tx();
                drop(gateways);
                let _ = shutdown.changed().await;
                return;
            }
        };

        let replications =
            ReplicationManager::with_config(overlay.clone(), self.replication_config.clone());
        let application = s2s_application::ApplicationLayer::new_with_capacity_source(
            overlay.clone(),
            self.application_config.clone(),
            self.max_users.clone(),
        );
        let recipient_index = RecipientIndex::new();
        let server_handle = server.upgrade();

        #[cfg(feature = "pre-release-workload")]
        let pre_release_workload_enabled = pre_release_workload::enabled();
        let mut expected_strict_topics = BTreeSet::new();
        if server_handle.is_some() {
            expected_strict_topics.insert(channel_topic(DEFAULT_SERVER_ID));
            expected_strict_topics.insert("bans".to_owned());
        }
        #[cfg(feature = "pre-release-workload")]
        if pre_release_workload_enabled {
            expected_strict_topics.insert(pre_release_workload::strict_topic().to_owned());
        }
        replications.set_expected_strict_topics(expected_strict_topics.iter().cloned());

        application.user_stats().set_responder(
            crate::client::handlers::ServerUserStatsResponder::new(server.clone()),
        );
        let S2SGateways {
            native_tx,
            s2s_tx,
            s2s_rx,
            native_runtime,
        } = gateways;
        let native_sink = Arc::new(S2SNativeGatewaySink::new(native_tx));
        application.moderation().set_applier(native_sink.clone());
        application.voice().set_audio_sink(native_sink.clone());
        application
            .voice()
            .set_recipient_index(recipient_index.clone());
        application.plugin_data().set_sink(native_sink.clone());
        application.text_message().set_sink(native_sink);

        let (
            channel_replications,
            ban_replication,
            client_replication,
            channel_blob_replications,
            bridge_tasks,
        ) = match server_handle.as_ref() {
            Some(server) => {
                self.register_repositories(
                    Arc::clone(&self),
                    &replications,
                    application.clone(),
                    server,
                    recipient_index.clone(),
                    &native_runtime,
                    s2s_tx.clone(),
                    s2s_rx,
                    shutdown.clone(),
                )
                .await
            }
            None => {
                warn!("s2s repository replication skipped: server handle dropped");
                (HashMap::new(), None, None, HashMap::new(), Vec::new())
            }
        };

        #[cfg(feature = "pre-release-workload")]
        let started_pre_release_workload = if pre_release_workload_enabled {
            let chaos = self.state.read().inbound_chaos.clone();
            pre_release_workload::start(
                overlay.clone(),
                replications.clone(),
                chaos,
                shutdown.clone(),
            )
        } else {
            None
        };

        if !expected_strict_topics.is_empty() && !replications.strict_capability_activation_ready()
        {
            warn!(
                required_version = s2s_overlay::STRICT_REPLICATION_PROTOCOL_VERSION,
                expected_topics = ?expected_strict_topics,
                "strict replication remains at v0 until every expected repository and its authenticated v2 frame prerequisites are ready"
            );
        }

        {
            let mut state = self.state.write();
            state.transport = Some(transport.clone());
            state.overlay = Some(overlay.clone());
            state.local_geo = Some(local_geo.clone());
            state.replications = Some(replications.clone());
            state.application = Some(application.clone());
            state.recipient_index = Some(recipient_index);
            state.server = Some(server.clone());
            state.channel_replications = channel_replications;
            state.ban_replication = ban_replication;
            state.client_replication = client_replication;
            state.channel_blob_replications = channel_blob_replications;
            state.bridge_tasks = bridge_tasks;
            #[cfg(feature = "pre-release-workload")]
            if let Some(workload) = started_pre_release_workload {
                state.bridge_tasks.push(workload.into_task());
            }
        }

        if let Some(server) = server_handle.as_ref() {
            let channels = server.get_channels().clone();
            let manager = Arc::clone(&self);
            let server_weak = server_handle.as_ref().map(Arc::downgrade);
            replications.set_strict_topic_resolver(Some(Arc::new(move |topic, parts| {
                let server_id = server_id_from_channel_topic(topic)?;
                let repo = Arc::new(ChannelReplicationAdapter::new(
                    server_id.clone(),
                    channels.clone(),
                    server_weak.clone(),
                ));
                let runtime = parts.build_runtime(topic.to_owned(), repo);
                runtime.start();
                let handle = s2s_replications::StrictHandle::with_runtime(runtime.clone());
                manager
                    .state
                    .write()
                    .channel_replications
                    .entry(server_id)
                    .or_insert(handle);
                Some(runtime)
            })));

            let channel_blobs = server.get_channel_blobs().clone();
            let channels_for_blobs = server.get_channels().clone();
            let manager = Arc::clone(&self);
            replications.set_blob_topic_resolver(Some(Arc::new(move |topic, parts| {
                let server_id = server_id_from_channel_blob_topic(topic)?;
                let repo = Arc::new(ChannelBlobReplicationAdapter::new(
                    server_id.clone(),
                    channel_blobs.clone(),
                    channels_for_blobs.clone(),
                ));
                let runtime = parts.build_runtime(topic.to_owned(), repo);
                runtime.start();
                let handle = s2s_replications::BlobHandle::with_runtime(runtime.clone());
                manager
                    .state
                    .write()
                    .channel_blob_replications
                    .entry(server_id)
                    .or_insert(handle);
                Some(runtime)
            })));
        }

        start_observability_geo_retry(local_geo.clone(), shutdown.clone());
        let status_task = self.status_http_listen.and_then(|listen| {
            match s2s_status::spawn_status_server(
                listen,
                overlay.clone(),
                transport.clone(),
                local_geo.clone(),
                shutdown.clone(),
            ) {
                Ok(task) => Some(task),
                Err(error) => {
                    warn!(%listen, %error, "s2s topology HTTP server startup failed");
                    None
                }
            }
        });

        info!(node = overlay.local_node_id(), "s2s runtime started");

        let _ = shutdown.changed().await;

        let bridge_tasks = {
            let mut state = self.state.write();
            let bridge_tasks = std::mem::take(&mut state.bridge_tasks);
            state.channel_replications.clear();
            state.ban_replication = None;
            state.client_replication = None;
            state.channel_blob_replications.clear();
            state.server = None;
            state.recipient_index = None;
            state.application = None;
            state.replications = None;
            state.local_geo = None;
            state.overlay = None;
            state.transport = None;
            state.gateway_tx = None;
            bridge_tasks
        };
        for task in bridge_tasks {
            task.abort();
        }
        if let Some(task) = status_task {
            task.abort();
        }

        replications.set_strict_topic_resolver(None);
        replications.set_blob_topic_resolver(None);
        application.shutdown().await;
        replications.shutdown().await;
        overlay.shutdown().await;
        transport.shutdown().await;

        info!("s2s runtime stopped");
    }

    async fn register_repositories(
        &self,
        manager: Arc<S2SManager>,
        replications: &Arc<ReplicationManager>,
        application: Arc<s2s_application::ApplicationLayer>,
        server: &Arc<Box<Server>>,
        recipient_index: Arc<RecipientIndex>,
        native_runtime: &tokio::runtime::Handle,
        s2s_tx: S2SGatewayTx,
        s2s_rx: S2SGatewayRx,
        shutdown: watch::Receiver<()>,
    ) -> (
        HashMap<String, s2s_replications::StrictHandle<ChannelReplicationAdapter>>,
        Option<s2s_replications::StrictHandle<BanReplicationAdapter>>,
        Option<s2s_replications::OwnerHandle<ClientReplicationAdapter>>,
        HashMap<String, s2s_replications::BlobHandle<ChannelBlobReplicationAdapter>>,
        Vec<JoinHandle<()>>,
    ) {
        let bans = Arc::new(BanReplicationAdapter::new(server.get_bans().clone()));
        let clients = Arc::new(ClientReplicationAdapter::new(
            server.get_clients().clone(),
            server.get_channels().clone(),
            replications.local_boot_epoch(),
        ));

        let mut channel_handles = HashMap::new();
        if let Err(e) = self.register_channel_replication_scope_into(
            replications,
            server,
            DEFAULT_SERVER_ID,
            &mut channel_handles,
        ) {
            warn!(error = %e, "failed to register s2s channel replication");
        }
        let mut channel_blob_handles = HashMap::new();
        if let Err(e) = self.register_channel_blob_replication_scope_into(
            replications,
            server,
            DEFAULT_SERVER_ID,
            &mut channel_blob_handles,
        ) {
            warn!(error = %e, "failed to register s2s channel blob replication");
        }
        let ban_handle = match replications.register_strict("bans", bans) {
            Ok(handle) => Some(handle),
            Err(e) => {
                warn!(error = %e, "failed to register s2s ban replication");
                None
            }
        };
        let client_handle = match replications.register_owner("clients", clients) {
            Ok(handle) => Some(handle),
            Err(e) => {
                warn!(error = %e, "failed to register s2s client replication");
                None
            }
        };

        let mut bridge_tasks = Vec::new();
        let voice_delivery_strategy = application.voice().delivery_strategy();
        if let Some(handle) = client_handle.clone() {
            bridge_tasks.push(spawn_native_client_replication_bridge(
                native_runtime,
                server.get_clients().clone(),
                s2s_tx.clone(),
                shutdown.clone(),
            ));
            bridge_tasks.push(spawn_s2s_gateway_receiver(
                s2s_rx,
                manager,
                application,
                Some(handle),
                recipient_index.clone(),
                self.replication_config.client_replication_max_in_flight(),
            ));
        } else {
            bridge_tasks.push(spawn_s2s_gateway_receiver(
                s2s_rx,
                manager,
                application,
                None,
                recipient_index.clone(),
                self.replication_config.client_replication_max_in_flight(),
            ));
        }
        if voice_delivery_strategy == s2s_application::DeliveryStrategy::Targeted {
            bridge_tasks.push(spawn_native_voice_recipient_index_bridge(
                native_runtime,
                server.get_clients().clone(),
                server.get_channels().clone(),
                s2s_tx.clone(),
                shutdown,
            ));
        }

        (
            channel_handles,
            ban_handle,
            client_handle,
            channel_blob_handles,
            bridge_tasks,
        )
    }

    fn register_channel_replication_scope(
        &self,
        replications: &Arc<ReplicationManager>,
        server: &Arc<Box<Server>>,
        server_id: &str,
    ) -> Result<
        s2s_replications::StrictHandle<ChannelReplicationAdapter>,
        s2s_replications::ReplicationError,
    > {
        let mut state = self.state.write();
        self.register_channel_replication_scope_into(
            replications,
            server,
            server_id,
            &mut state.channel_replications,
        )
    }

    fn register_channel_replication_scope_into(
        &self,
        replications: &Arc<ReplicationManager>,
        server: &Arc<Box<Server>>,
        server_id: &str,
        handles: &mut HashMap<String, s2s_replications::StrictHandle<ChannelReplicationAdapter>>,
    ) -> Result<
        s2s_replications::StrictHandle<ChannelReplicationAdapter>,
        s2s_replications::ReplicationError,
    > {
        match handles.entry(server_id.to_owned()) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                let topic = channel_topic(server_id);
                let repo = Arc::new(ChannelReplicationAdapter::new(
                    server_id.to_owned(),
                    server.get_channels().clone(),
                    Some(Arc::downgrade(server)),
                ));
                let handle = replications.register_strict(topic, repo)?;
                entry.insert(handle.clone());
                Ok(handle)
            }
        }
    }

    fn register_channel_blob_replication_scope(
        &self,
        replications: &Arc<ReplicationManager>,
        server: &Arc<Box<Server>>,
        server_id: &str,
    ) -> Result<
        s2s_replications::BlobHandle<ChannelBlobReplicationAdapter>,
        s2s_replications::ReplicationError,
    > {
        let mut state = self.state.write();
        self.register_channel_blob_replication_scope_into(
            replications,
            server,
            server_id,
            &mut state.channel_blob_replications,
        )
    }

    fn register_channel_blob_replication_scope_into(
        &self,
        replications: &Arc<ReplicationManager>,
        server: &Arc<Box<Server>>,
        server_id: &str,
        handles: &mut HashMap<String, s2s_replications::BlobHandle<ChannelBlobReplicationAdapter>>,
    ) -> Result<
        s2s_replications::BlobHandle<ChannelBlobReplicationAdapter>,
        s2s_replications::ReplicationError,
    > {
        match handles.entry(server_id.to_owned()) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                let topic = channel_blob_topic(server_id);
                let repo = Arc::new(ChannelBlobReplicationAdapter::new(
                    server_id.to_owned(),
                    server.get_channel_blobs().clone(),
                    server.get_channels().clone(),
                ));
                let runtime = replications
                    .blob_topic_parts()
                    .build_runtime(topic.clone(), repo);
                runtime.start();
                replications.install_blob_runtime(topic, runtime.clone())?;
                let handle = s2s_replications::BlobHandle::with_runtime(runtime);
                entry.insert(handle.clone());
                Ok(handle)
            }
        }
    }
}

pub fn start_observability_geo_resolution(
    configured_geo: Option<NodeGeo>,
    shutdown: watch::Receiver<()>,
) -> SharedNodeGeo {
    let local_geo = SharedNodeGeo::new(configured_geo);
    start_observability_geo_retry(local_geo.clone(), shutdown);
    local_geo
}

fn start_observability_geo_retry(local_geo: SharedNodeGeo, shutdown: watch::Receiver<()>) {
    if local_geo.get().is_some() {
        return;
    }

    tokio::spawn(retry_observability_geo_until_resolved(
        local_geo,
        shutdown,
        OBSERVABILITY_GEO_RETRY_INITIAL_INTERVAL,
        OBSERVABILITY_GEO_RETRY_CAP,
        || async { shitspeak_s2s_transport::discover_public_geo().await },
    ));
}

async fn retry_observability_geo_until_resolved<F, Fut>(
    local_geo: SharedNodeGeo,
    mut shutdown: watch::Receiver<()>,
    retry_initial_interval: Duration,
    retry_cap: Duration,
    mut probe: F,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<NodeGeo>>,
{
    if local_geo.get().is_some() {
        return;
    }

    let retry_cap = retry_cap.max(retry_initial_interval);
    let mut retry_delay = retry_initial_interval;
    loop {
        let discovered = tokio::select! {
            _ = shutdown.changed() => return,
            discovered = probe() => discovered,
        };
        if let Some(geo) = discovered {
            if local_geo.set_if_missing(geo) {
                info!("public node geolocation resolved");
            }
            return;
        }

        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(retry_delay) => {}
        }
        retry_delay = retry_delay.saturating_mul(2).min(retry_cap);
    }
}

fn spawn_native_client_replication_bridge(
    runtime: &tokio::runtime::Handle,
    repo: Arc<ClientRepository>,
    tx: S2SGatewayTx,
    mut shutdown: watch::Receiver<()>,
) -> JoinHandle<()> {
    let mut rx = repo.subscribe();
    runtime.spawn(async move {
        loop {
            let payload = tokio::select! {
                _ = shutdown.changed() => return,
                next = rx.recv() => next,
            };
            match payload {
                Ok(payload) => {
                    let entry = payload.entry.clone();
                    if entry.node_id != repo.local_node_id() {
                        continue;
                    }
                    if !tx
                        .send_lossless(NativeToS2SCommand::ProposeClientReplication(
                            (*entry).clone(),
                        ))
                        .await
                    {
                        warn!(
                            version = entry.version,
                            "s2s client replication gateway closed; dropping proposal"
                        );
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "s2s client replication bridge lagged");
                }
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    })
}

fn spawn_native_voice_recipient_index_bridge(
    runtime: &tokio::runtime::Handle,
    repo: Arc<ClientRepository>,
    channels: Arc<ChannelRepository>,
    tx: S2SGatewayTx,
    mut shutdown: watch::Receiver<()>,
) -> JoinHandle<()> {
    let mut rx = repo.subscribe();
    runtime.spawn(async move {
        enqueue_voice_recipient_index_snapshot(&repo, &channels, &tx).await;
        let mut dirty = false;
        let mut refresh = tokio::time::interval(VOICE_RECIPIENT_INDEX_REFRESH_INTERVAL);
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        refresh.tick().await;
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = refresh.tick(), if dirty => {
                    dirty = false;
                    enqueue_voice_recipient_index_snapshot(&repo, &channels, &tx).await;
                }
                payload = rx.recv() => {
                    match payload {
                        Ok(payload) => {
                            if client_entry_affects_voice_recipient_index(&payload.entry) {
                                dirty = true;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(skipped, "s2s voice recipient index bridge lagged");
                            dirty = true;
                        }
                        Err(broadcast::error::RecvError::Closed) => return,
                    }
                }
            }
        }
    })
}

fn client_entry_affects_voice_recipient_index(entry: &ClientStateLogEntry) -> bool {
    entry.op.affects_voice_routing()
}

async fn enqueue_voice_recipient_index_snapshot(
    repo: &Arc<ClientRepository>,
    channels: &Arc<ChannelRepository>,
    tx: &S2SGatewayTx,
) {
    let snapshot = repo.voice_recipient_index_snapshot().await;
    let (_, versions) = repo.snapshot_with_versions().await;
    let complete_servers = channels.known_server_ids().into_iter().collect();
    let covered_nodes = versions.keys().copied().collect();
    let update = RecipientIndexUpdate::new(snapshot, complete_servers, covered_nodes);
    if !tx.try_send_coalesced(NativeToS2SCommand::RefreshVoiceRecipientIndex(update)) {
        warn!("s2s voice recipient index gateway full; dropping snapshot");
    }
}

fn spawn_s2s_gateway_receiver(
    rx: S2SGatewayRx,
    manager: Arc<S2SManager>,
    application: Arc<s2s_application::ApplicationLayer>,
    client_handle: Option<s2s_replications::OwnerHandle<ClientReplicationAdapter>>,
    recipient_index: Arc<RecipientIndex>,
    client_replication_max_in_flight: usize,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let client_proposal_tx = spawn_client_replication_proposal_worker(
            client_handle,
            S2S_CLIENT_REPLICATION_WORKER_CAPACITY,
            client_replication_max_in_flight,
        );
        let S2SGatewayRx {
            control,
            replication,
            bulk,
            voice,
            coalesced,
        } = rx;
        let control_task = run_s2s_control_gateway(control, manager, application.clone());
        let replication_task = run_s2s_replication_gateway(replication, client_proposal_tx);
        let bulk_task = run_s2s_bulk_gateway(bulk, application.clone());
        let voice_task = run_s2s_voice_gateway(voice, application);
        let coalesced_task = run_s2s_coalesced_gateway(coalesced, recipient_index);
        tokio::join!(
            control_task,
            replication_task,
            bulk_task,
            voice_task,
            coalesced_task
        );
    })
}

async fn run_s2s_control_gateway(
    mut rx: S2SAdaptiveReceiver<NativeToS2SCommand>,
    manager: Arc<S2SManager>,
    application: Arc<s2s_application::ApplicationLayer>,
) {
    while let Some(command) = rx.recv().await {
        match command {
            NativeToS2SCommand::ProposeChannel {
                server_id,
                op,
                accepted,
                respond,
            } => {
                let manager = Arc::clone(&manager);
                tokio::spawn(async move {
                    let result = manager
                        .propose_channel_op_direct_with_accepted(&server_id, op, accepted)
                        .await;
                    let _ = respond.send(result);
                });
            }
            NativeToS2SCommand::ProposeBan { op, respond } => {
                let _ = respond.send(manager.propose_ban_op_direct(op).await);
            }
            NativeToS2SCommand::DispatchModeration { owner, envelope } => {
                if let Err(e) = application
                    .moderation()
                    .dispatch_envelope_for_gateway(owner, envelope)
                    .await
                {
                    warn!(error = %e, owner, "moderation dispatch failed");
                }
            }
            NativeToS2SCommand::DispatchUserStats {
                owner,
                actor_session,
                target_session,
                stats_only,
                server_id,
                respond,
            } => {
                let result = application
                    .user_stats()
                    .dispatch_request(
                        owner,
                        actor_session,
                        target_session,
                        stats_only,
                        server_id,
                        None,
                    )
                    .await;
                let _ = respond.send(result);
            }
            other => {
                warn!(
                    label = other.label(),
                    "unexpected command on s2s control gateway lane"
                );
            }
        }
    }
}

async fn run_s2s_replication_gateway(
    mut rx: S2SAdaptiveReceiver<NativeToS2SCommand>,
    client_proposal_tx: ClientReplicationProposalQueue,
) {
    while let Some(command) = rx.recv().await {
        match command {
            NativeToS2SCommand::ProposeClientReplication(entry) => {
                match client_proposal_tx.try_send(QueuedClientReplicationProposal {
                    entry,
                    enqueued_at: Instant::now(),
                }) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(proposal)) => {
                        warn!(
                            version = proposal.entry.version,
                            "s2s client replication worker full; dropping proposal"
                        );
                    }
                    Err(mpsc::error::TrySendError::Closed(proposal)) => {
                        warn!(
                            version = proposal.entry.version,
                            "s2s client replication worker stopped; dropping proposal"
                        );
                    }
                }
            }
            other => {
                warn!(
                    label = other.label(),
                    "unexpected command on s2s replication gateway lane"
                );
            }
        }
    }
}

async fn run_s2s_bulk_gateway(
    mut rx: S2SAdaptiveReceiver<NativeToS2SCommand>,
    application: Arc<s2s_application::ApplicationLayer>,
) {
    while let Some(command) = rx.recv().await {
        match command {
            NativeToS2SCommand::DispatchPluginData { owner, envelope } => {
                if let Err(e) = application.plugin_data().dispatch(owner, envelope).await {
                    warn!(error = %e, owner, "plugin data dispatch failed");
                }
            }
            NativeToS2SCommand::DispatchTextMessage { owner, envelope } => {
                if let Err(e) = application.text_message().dispatch(owner, envelope).await {
                    warn!(error = %e, owner, "text message dispatch failed");
                }
            }
            other => {
                warn!(
                    label = other.label(),
                    "unexpected command on s2s bulk gateway lane"
                );
            }
        }
    }
}

async fn run_s2s_voice_gateway(
    rx: S2SAdaptiveReceiver<NativeToS2SCommand>,
    application: Arc<s2s_application::ApplicationLayer>,
) {
    run_sender_sharded_gateway(
        rx,
        s2s_voice_gateway_shard_count(),
        |command| command.voice_sender_session().unwrap_or_default(),
        move |command| {
            let application = application.clone();
            async move { run_s2s_voice_command(application, command).await }
        },
    )
    .await;
}

fn s2s_voice_gateway_shard_count() -> usize {
    thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(S2S_VOICE_GATEWAY_MIN_SHARDS)
        .clamp(S2S_VOICE_GATEWAY_MIN_SHARDS, S2S_VOICE_GATEWAY_MAX_SHARDS)
}

async fn run_s2s_voice_command(
    application: Arc<s2s_application::ApplicationLayer>,
    command: NativeToS2SCommand,
) {
    match command {
        NativeToS2SCommand::SendVoiceForChannel {
            sender_session,
            server_id,
            source_channel,
            is_terminator,
            payload,
        } => {
            if let Err(e) = application
                .voice()
                .send_for_channel(
                    sender_session,
                    server_id,
                    source_channel,
                    is_terminator,
                    payload,
                )
                .await
            {
                trace!(error = %e, "voice s2s send_for_channel failed");
            }
        }
        NativeToS2SCommand::SendVoiceForTargetChannels {
            sender_session,
            server_id,
            target_channels,
            target_kind,
            is_terminator,
            payload,
            intent,
        } => {
            if let Err(e) = application
                .voice()
                .send_for_target_channels(
                    sender_session,
                    server_id,
                    target_channels,
                    target_kind,
                    is_terminator,
                    payload,
                    intent,
                )
                .await
            {
                trace!(error = %e, "voice s2s send_for_target_channels failed");
            }
        }
        NativeToS2SCommand::SendVoiceBroadcast {
            sender_session,
            server_id,
            target_kind,
            is_terminator,
            payload,
            intent,
        } => {
            if let Err(e) = application
                .voice()
                .send_broadcast(
                    sender_session,
                    server_id,
                    target_kind,
                    is_terminator,
                    payload,
                    intent,
                )
                .await
            {
                trace!(error = %e, "voice s2s send_broadcast failed");
            }
        }
        other => {
            warn!(
                label = other.label(),
                "unexpected command on s2s voice gateway lane"
            );
        }
    }
}

async fn run_s2s_coalesced_gateway(
    mut rx: S2SAdaptiveReceiver<NativeToS2SCommand>,
    recipient_index: Arc<RecipientIndex>,
) {
    while let Some(command) = rx.recv().await {
        match command {
            NativeToS2SCommand::RefreshVoiceRecipientIndex(update) => {
                recipient_index.replace_all_complete(update);
            }
            other => {
                warn!(
                    label = other.label(),
                    "unexpected command on s2s coalesced gateway lane"
                );
            }
        }
    }
}

struct QueuedClientReplicationProposal {
    entry: ClientStateLogEntry,
    enqueued_at: Instant,
}

#[derive(Clone)]
struct ClientReplicationProposalQueue {
    tx: mpsc::Sender<QueuedClientReplicationProposal>,
    depth: Arc<AtomicUsize>,
}

impl ClientReplicationProposalQueue {
    fn try_send(
        &self,
        proposal: QueuedClientReplicationProposal,
    ) -> Result<(), mpsc::error::TrySendError<QueuedClientReplicationProposal>> {
        let depth = self.depth.fetch_add(1, Ordering::Relaxed) + 1;
        s2s_replications::metrics::set_client_replication_queue_depth(depth);
        match self.tx.try_send(proposal) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.mark_dequeued();
                Err(error)
            }
        }
    }

    fn mark_dequeued(&self) {
        let depth = self
            .depth
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_sub(1)
            })
            .unwrap_or(0)
            .saturating_sub(1);
        s2s_replications::metrics::set_client_replication_queue_depth(depth);
    }
}

fn spawn_client_replication_proposal_worker(
    client_handle: Option<s2s_replications::OwnerHandle<ClientReplicationAdapter>>,
    capacity: usize,
    max_in_flight: usize,
) -> ClientReplicationProposalQueue {
    let (tx, mut rx) = mpsc::channel::<QueuedClientReplicationProposal>(capacity.max(1));
    let queue = ClientReplicationProposalQueue {
        tx,
        depth: Arc::new(AtomicUsize::new(0)),
    };
    let worker_queue = queue.clone();
    tokio::spawn(async move {
        let permits = Arc::new(Semaphore::new(max_in_flight.max(1)));
        while let Some(proposal) = rx.recv().await {
            worker_queue.mark_dequeued();
            let queue_wait = proposal.enqueued_at.elapsed();
            s2s_replications::metrics::record_client_replication_queue_wait(queue_wait);
            if queue_wait >= S2S_CLIENT_REPLICATION_SLOW_QUEUE_WAIT {
                warn!(
                    version = proposal.entry.version,
                    queue_wait_ms = queue_wait.as_millis(),
                    "s2s client replication proposal waited in worker queue"
                );
            }
            let Some(handle) = client_handle.clone() else {
                warn!(
                    version = proposal.entry.version,
                    "s2s client replication gateway has no owner handle; dropping proposal"
                );
                continue;
            };
            let permits = Arc::clone(&permits);
            tokio::spawn(async move {
                let Ok(_permit) = permits.acquire_owned().await else {
                    return;
                };
                let started = Instant::now();
                let version = proposal.entry.version;
                match handle.propose(proposal.entry).await {
                    Ok(_) => {
                        let elapsed = started.elapsed();
                        if elapsed >= S2S_CLIENT_REPLICATION_SLOW_PROPOSE {
                            warn!(
                                version,
                                elapsed_ms = elapsed.as_millis(),
                                "s2s client replication propose was slow"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(version, error = %e, "s2s client replication propose failed");
                    }
                }
            });
        }
    });
    queue
}

async fn run_native_gateway(
    server: Weak<Box<Server>>,
    rx: S2SNativeGatewayRx,
    shutdown: watch::Receiver<()>,
) {
    let S2SNativeGatewayRx {
        control,
        bulk,
        voice,
    } = rx;
    let control_task = run_native_control_gateway(server.clone(), control, shutdown.clone());
    let bulk_task = run_native_bulk_gateway(server.clone(), bulk, shutdown.clone());
    let voice_task = run_native_voice_gateway(server, voice, shutdown);
    tokio::join!(control_task, bulk_task, voice_task);
}

struct S2SNativeGatewaySink {
    tx: S2SNativeGatewayTx,
}

impl S2SNativeGatewaySink {
    fn new(tx: S2SNativeGatewayTx) -> Self {
        Self { tx }
    }

    async fn send_lossless(&self, command: S2SNativeCommand) {
        if !self.tx.send_lossless(command).await {
            trace!("s2s native gateway closed; dropping command");
        }
    }

    fn try_send_voice(&self, command: S2SNativeCommand) {
        let label = command.label();
        if !self.tx.try_send_voice(command) {
            record_s2s_gateway_drop(
                S2SVoiceGatewayDropDirection::S2sToNative,
                S2SVoiceGatewayDropReason::FullOrClosed,
            );
            warn!(label, "s2s native gateway full; dropping command");
        }
    }
}

#[async_trait]
impl ModerationApplier for S2SNativeGatewaySink {
    async fn apply(&self, from: NodeIdentifier, envelope: ModerationEnvelope) {
        self.send_lossless(S2SNativeCommand::ApplyModeration { from, envelope })
            .await;
    }
}

#[async_trait]
impl AudioSink for S2SNativeGatewaySink {
    async fn deliver(&self, from_immediate: NodeIdentifier, frame: VoiceFrame, _is_repair: bool) {
        self.try_send_voice(S2SNativeCommand::DeliverVoice {
            from_immediate,
            frame,
        });
    }
}

#[async_trait]
impl s2s_application::plugin_data::PluginDataSink for S2SNativeGatewaySink {
    async fn deliver(&self, from: NodeIdentifier, envelope: PluginDataEnvelope) {
        self.send_lossless(S2SNativeCommand::DeliverPluginData { from, envelope })
            .await;
    }
}

#[async_trait]
impl s2s_application::text_message::TextMessageSink for S2SNativeGatewaySink {
    async fn deliver(&self, from: NodeIdentifier, envelope: TextMessageEnvelope) {
        self.send_lossless(S2SNativeCommand::DeliverTextMessage { from, envelope })
            .await;
    }
}

async fn run_native_control_gateway(
    server: Weak<Box<Server>>,
    mut rx: S2SAdaptiveReceiver<S2SNativeCommand>,
    mut shutdown: watch::Receiver<()>,
) {
    loop {
        let command = tokio::select! {
            _ = shutdown.changed() => return,
            next = rx.recv() => match next {
                Some(command) => command,
                None => return,
            },
        };
        let Some(server) = server.upgrade() else {
            return;
        };
        match command {
            S2SNativeCommand::ApplyModeration { from, envelope } => {
                apply_s2s_moderation(&server, from, envelope).await;
            }
            other => warn!(
                label = other.label(),
                "unexpected command on native control gateway lane"
            ),
        }
    }
}

async fn run_native_bulk_gateway(
    server: Weak<Box<Server>>,
    mut rx: S2SAdaptiveReceiver<S2SNativeCommand>,
    mut shutdown: watch::Receiver<()>,
) {
    loop {
        let command = tokio::select! {
            _ = shutdown.changed() => return,
            next = rx.recv() => match next {
                Some(command) => command,
                None => return,
            },
        };
        let Some(server) = server.upgrade() else {
            return;
        };
        match command {
            S2SNativeCommand::DeliverPluginData { from, envelope } => {
                trace!(from, "s2s plugin data handed to native gateway");
                deliver_plugin_data_to_local_recipients(&server, envelope).await;
            }
            S2SNativeCommand::DeliverTextMessage { from, envelope } => {
                trace!(from, "s2s text message handed to native gateway");
                deliver_text_message_to_local_recipients(&server, envelope).await;
            }
            other => warn!(
                label = other.label(),
                "unexpected command on native bulk gateway lane"
            ),
        }
    }
}

async fn run_native_voice_gateway(
    server: Weak<Box<Server>>,
    mut rx: S2SAdaptiveReceiver<S2SNativeCommand>,
    mut shutdown: watch::Receiver<()>,
) {
    loop {
        let command = tokio::select! {
            _ = shutdown.changed() => return,
            next = rx.recv() => match next {
                Some(command) => command,
                None => return,
            },
        };
        let Some(server) = server.upgrade() else {
            return;
        };
        match command {
            S2SNativeCommand::DeliverVoice {
                from_immediate,
                frame,
            } => {
                crate::voice::route_s2s_voice_frame(&server, from_immediate, frame).await;
            }
            other => warn!(
                label = other.label(),
                "unexpected command on native voice gateway lane"
            ),
        }
    }
}

async fn deliver_plugin_data_to_local_recipients(
    server: &Arc<Box<Server>>,
    envelope: PluginDataEnvelope,
) {
    if envelope.receiver_sessions.is_empty() {
        return;
    }

    let server_id = if envelope.server_id.is_empty() {
        crate::types::default_server_id()
    } else {
        envelope.server_id
    };
    let sender_id = ClientSessionIdentifier::from(envelope.sender_session);
    let sender = server
        .get_clients()
        .get_client_in_server(&server_id, sender_id)
        .await;
    if server.get_hide_users_without_traverse() && sender.is_none() {
        return;
    }
    for receiver in envelope.receiver_sessions {
        let id = ClientSessionIdentifier::from(receiver);
        if id.get_node_id() == server.get_clients().local_node_id() {
            let Some(target) = server
                .get_clients()
                .get_client_in_server(&server_id, id)
                .await
            else {
                continue;
            };
            if let Some(sender) = sender.as_ref() {
                if !crate::client::visibility::can_view_user(server, sender, &target).await {
                    continue;
                }
                if !crate::client::visibility::can_view_user(server, &target, sender).await {
                    continue;
                }
            }
            let message: shitspeak_messages::messages::Message =
                shitspeak_messages::messages::encoder::PluginDataTransmission {
                    sender_session: Some(envelope.sender_session),
                    receiver_sessions: vec![receiver],
                    data: Some(envelope.data.clone()),
                    data_id: envelope.data_id.clone(),
                }
                .into();
            server
                .get_clients()
                .send_to_in_server(&server_id, id, &message)
                .await;
        }
    }
}

async fn deliver_text_message_to_local_recipients(
    server: &Arc<Box<Server>>,
    envelope: TextMessageEnvelope,
) {
    if envelope.receiver_sessions.is_empty() {
        return;
    }

    let server_id = if envelope.server_id.is_empty() {
        crate::types::default_server_id()
    } else {
        envelope.server_id
    };
    let sender_id = ClientSessionIdentifier::from(envelope.sender_session);
    let sender = server
        .get_clients()
        .get_client_in_server(&server_id, sender_id)
        .await;
    if server.get_hide_users_without_traverse() && sender.is_none() {
        return;
    }
    for receiver in envelope.receiver_sessions {
        let id = ClientSessionIdentifier::from(receiver);
        if id.get_node_id() != server.get_clients().local_node_id() {
            continue;
        }
        let Some(target) = server
            .get_clients()
            .get_client_in_server(&server_id, id)
            .await
        else {
            continue;
        };
        if !target.is_authenticated() {
            continue;
        }
        if let Some(sender) = sender.as_ref() {
            if !crate::client::visibility::can_view_user(server, sender, &target).await {
                continue;
            }
            if !crate::client::visibility::can_view_user(server, &target, sender).await {
                continue;
            }
        }
        let message: shitspeak_messages::messages::Message =
            shitspeak_messages::messages::encoder::TextMessage {
                actor: Some(envelope.sender_session),
                session: envelope.session.clone(),
                channel_id: envelope.channel_id.clone(),
                tree_id: envelope.tree_id.clone(),
                message: envelope.message.clone(),
            }
            .into();
        server
            .get_clients()
            .send_to_in_server(&server_id, id, &message)
            .await;
    }
}

async fn apply_s2s_moderation(
    server: &Arc<Box<Server>>,
    from: NodeIdentifier,
    envelope: ModerationEnvelope,
) {
    let target_id = ClientSessionIdentifier::from(envelope.target_session);
    if target_id.get_node_id() != server.get_clients().local_node_id() {
        trace!(
            from,
            target = envelope.target_session,
            "s2s moderation ignored: target is not local"
        );
        return;
    }

    let server_id = if envelope.server_id.is_empty() {
        crate::types::default_server_id()
    } else {
        envelope.server_id.clone()
    };
    match envelope.command {
        Some(ModerationCommand::UserState(patch)) => {
            apply_user_state_patch(server, &server_id, envelope.actor_session, target_id, patch)
                .await;
        }
        Some(ModerationCommand::UserRemove(patch)) => {
            apply_user_remove_patch(server, &server_id, envelope.actor_session, target_id, patch)
                .await;
        }
        None => {
            trace!(from, "s2s moderation ignored: empty command");
        }
    }
}

async fn apply_user_state_patch(
    server: &Arc<Box<Server>>,
    server_id: &str,
    actor_session: u32,
    target_id: ClientSessionIdentifier,
    patch: UserStatePatch,
) {
    let Some(target) = server
        .get_clients()
        .get_client_in_server(server_id, target_id)
        .await
    else {
        return;
    };
    let actor = ClientSessionIdentifier::from(actor_session);
    let Some(actor_client) = server
        .get_clients()
        .get_client_in_server(server_id, actor)
        .await
    else {
        return;
    };
    if !crate::client::visibility::can_view_user(server, &actor_client, &target).await {
        return;
    }

    if let Some(expected) = patch.expected_from_channel {
        if target.get_current_channel_id() != expected {
            trace!(
                target = u32::from(target_id),
                expected,
                actual = target.get_current_channel_id(),
                "s2s moderation user-state skipped: channel precondition failed"
            );
            return;
        }
    }

    let has_channel_dependency = patch.channel_id.is_some()
        || patch.mute.is_some()
        || patch.deaf.is_some()
        || patch.suppress.is_some()
        || patch.priority_speaker.is_some()
        || !patch.listening_channel_add.is_empty()
        || !patch.listening_channel_remove.is_empty();
    let channel_version_dep =
        has_channel_dependency.then(|| server.get_channels().current_version_in_server(server_id));
    let should_stage_channel_cache = patch.channel_id.is_some()
        || !patch.listening_channel_add.is_empty()
        || !patch.listening_channel_remove.is_empty();
    let channel_cache_key = if should_stage_channel_cache {
        crate::user_channel_cache::cache_key_for_client(target.as_ref()).await
    } else {
        None
    };
    let mut cache_listening_channel_ids = None;
    let hidden_before = target.is_hidden_from_regular_users();
    let post_move_destination_perms = if let Some(channel_id) = patch.channel_id {
        Some(
            crate::client::acl::compute_permissions_for_client_as_if_in_channel(
                server, &target, channel_id,
            )
            .await,
        )
    } else {
        None
    };
    let can_receive_voice;
    {
        let mut gs =
            target.write_global_state_as(server.get_clients(), Some(actor), channel_version_dep);

        if let Some(mute) = patch.mute {
            if gs.is_muted() != mute {
                gs.set_mute(mute);
                if !mute {
                    gs.set_deaf(false);
                }
            }
            if gs.is_suppressed() && !mute {
                gs.set_hidden_from_regular_users(false);
                gs.set_suppress(false);
            }
        }
        if let Some(deaf) = patch.deaf {
            if gs.is_deafened() != deaf {
                gs.set_deaf(deaf);
                if deaf && !gs.is_muted() {
                    gs.set_mute(true);
                }
            }
        }
        if let Some(priority_speaker) = patch.priority_speaker {
            if gs.is_priority_speaker() != priority_speaker {
                gs.set_priority_speaker(priority_speaker);
            }
        }
        if let Some(channel_id) = patch.channel_id {
            gs.set_current_channel_id(channel_id);
        }
        if let Some(suppress) = patch.suppress {
            if !suppress {
                gs.set_hidden_from_regular_users(false);
            }
            if gs.is_suppressed() != suppress {
                gs.set_suppress(suppress);
            }
        }
        if let Some(destination_perms) = post_move_destination_perms {
            gs.set_suppress(!destination_perms.contains(shitspeak_state::ACLPermissions::Speak));
        }
        for channel_id in &patch.listening_channel_add {
            gs.listen_channel(*channel_id);
        }
        for channel_id in &patch.listening_channel_remove {
            gs.unlisten_channel(*channel_id);
        }
        if !patch.listening_channel_add.is_empty() || !patch.listening_channel_remove.is_empty() {
            cache_listening_channel_ids = Some(
                gs.get_listening_channel_id()
                    .iter()
                    .copied()
                    .collect::<Vec<_>>(),
            );
        }
        can_receive_voice = gs.can_receive_voice();
    }
    target.set_can_receive_voice(can_receive_voice);
    if hidden_before != target.is_hidden_from_regular_users() {
        crate::toggle_superuser_visibility::refresh_context_menu(server, &target).await;
    }

    if let Some(cache_key) = channel_cache_key.as_deref() {
        if let Some(channel_id) = patch.channel_id {
            if let Err(error) = server
                .get_user_channel_cache()
                .remember_last_channel(cache_key, channel_id)
                .await
            {
                tracing::warn!(
                    error = %error,
                    cache_key,
                    "failed to stage user last channel cache"
                );
            }
        }
        if let Some(channel_ids) = cache_listening_channel_ids {
            if let Err(error) = server
                .get_user_channel_cache()
                .remember_listening_channels(cache_key, channel_ids)
                .await
            {
                tracing::warn!(
                    error = %error,
                    cache_key,
                    "failed to stage user listening channel cache"
                );
            }
        }
    }
}

async fn apply_user_remove_patch(
    server: &Arc<Box<Server>>,
    server_id: &str,
    actor_session: u32,
    target_id: ClientSessionIdentifier,
    patch: UserRemovePatch,
) {
    let Some(target) = server
        .get_clients()
        .get_client_in_server(server_id, target_id)
        .await
    else {
        return;
    };
    let actor = ClientSessionIdentifier::from(actor_session);
    let Some(actor_client) = server
        .get_clients()
        .get_client_in_server(server_id, actor)
        .await
    else {
        return;
    };
    if !crate::client::visibility::can_view_user(server, &actor_client, &target).await {
        return;
    }

    if patch.ban {
        let reason = patch.reason.clone().unwrap_or_default();
        let address = target.get_real_ip_address();
        let entry = BanEntry {
            address,
            mask: if address.is_ipv4() { 32 } else { 128 },
            name: {
                let gs = target.read_global_state();
                gs.get_display_name_opt().map(ToOwned::to_owned)
            },
            hash: target.get_certificate_hash().map(hex::encode),
            reason: if reason.is_empty() {
                None
            } else {
                Some(reason.clone())
            },
            start: chrono::Utc::now().timestamp(),
            duration: 0,
        };
        if let Err(e) = server.get_bans().add_ban(entry).await {
            warn!(error = %e, "s2s moderation failed to persist ban");
        }
        info!(
            actor = actor_session,
            target = u32::from(target_id),
            "s2s moderation added ban"
        );
    }

    let actor_for_target =
        if crate::client::visibility::can_view_user(server, &target, &actor_client).await {
            Some(actor_session)
        } else {
            None
        };
    let remove_notice: shitspeak_messages::messages::Message =
        shitspeak_messages::messages::encoder::UserRemove {
            session: u32::from(target_id),
            actor: actor_for_target,
            reason: patch.reason.clone(),
            ban: Some(patch.ban),
        }
        .into();
    if let Err(e) = target.write_proto_message_direct(&remove_notice).await {
        trace!(
            error = %e,
            target = u32::from(target_id),
            "s2s moderation failed to send kick notice to target before disconnect",
        );
    }

    let old_channel_id = target.get_current_channel_id();
    let removed = server
        .get_clients()
        .remove_client_in_server_with_metadata(
            server_id,
            target_id,
            Some(actor),
            patch.reason.clone(),
            patch.ban,
        )
        .await;
    let target = removed.as_ref().unwrap_or(&target);
    if let Err(e) = target.force_disconnect().await {
        trace!(
            error = %e,
            target = u32::from(target_id),
            "s2s moderation failed to forcibly disconnect removed client",
        );
    }
    crate::client::handlers::temp_channel::reap_if_empty_temporary_on_server(
        server,
        server_id,
        old_channel_id,
    )
    .await;
}

pub fn install_channel_replication_resolver(
    replications: &Arc<ReplicationManager>,
    channels: Arc<ChannelRepository>,
) {
    replications.set_strict_topic_resolver(Some(Arc::new(move |topic, parts| {
        let server_id = server_id_from_channel_topic(topic)?;
        let repo = Arc::new(ChannelReplicationAdapter::new(
            server_id,
            channels.clone(),
            None,
        ));
        let runtime = parts.build_runtime(topic.to_owned(), repo);
        runtime.start();
        Some(runtime)
    })));
}

pub fn install_channel_blob_replication_resolver(
    replications: &Arc<ReplicationManager>,
    blobs: Arc<ChannelBlobStore>,
    channels: Arc<ChannelRepository>,
) {
    replications.set_blob_topic_resolver(Some(Arc::new(move |topic, parts| {
        let server_id = server_id_from_channel_blob_topic(topic)?;
        let repo = Arc::new(ChannelBlobReplicationAdapter::new(
            server_id,
            blobs.clone(),
            channels.clone(),
        ));
        let runtime = parts.build_runtime(topic.to_owned(), repo);
        runtime.start();
        Some(runtime)
    })));
}

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

#[derive(Clone)]
pub struct ChannelReplicationAdapter {
    server_id: String,
    repo: Arc<ChannelRepository>,
    server: Option<Weak<Box<Server>>>,
}

impl ChannelReplicationAdapter {
    pub fn new(
        server_id: String,
        repo: Arc<ChannelRepository>,
        server: Option<Weak<Box<Server>>>,
    ) -> Self {
        Self {
            server_id,
            repo,
            server,
        }
    }

    fn bind_operation_to_topic(&self, op: &mut ChannelOperation) -> bool {
        if op.server_id.is_empty() || op.server_id == DEFAULT_SERVER_ID {
            op.server_id.clone_from(&self.server_id);
        }
        op.server_id == self.server_id
    }

    async fn apply_strict_committed_once(
        &self,
        version: u64,
        mut op: ChannelOperation,
        metadata: s2s_replications::strict::StrictLogMetadata,
    ) -> s2s_replications::strict::StrictCommitApplyOutcome {
        op.version = version;
        if !self.bind_operation_to_topic(&mut op) {
            warn!(
                topic_server_id = %self.server_id,
                operation_server_id = %op.server_id,
                "s2s strict channel operation does not match its topic scope"
            );
            return s2s_replications::strict::StrictCommitApplyOutcome::Failed;
        }
        let evict_pending_delete = match &op.op {
            ChannelOp::MarkPendingDelete {
                id,
                nonce,
                evict_clients,
            } if *evict_clients => {
                let fallback = self
                    .repo
                    .get_channel_in_server(&op.server_id, *id)
                    .await
                    .and_then(|channel| channel.parent_id)
                    .unwrap_or(0);
                Some((*id, *nonce, fallback))
            }
            _ => None,
        };
        let op_server_id = op.server_id.clone();
        let applied_operation = op.clone();
        let outcome = match self
            .repo
            .apply_s2s_strict_operation(op, strict_log_metadata_to_repo(metadata))
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                warn!(error = ?error, "s2s strict channel operation apply failed");
                return s2s_replications::strict::StrictCommitApplyOutcome::Failed;
            }
        };
        match outcome {
            StrictOperationApplyOutcome::Applied => {}
            StrictOperationApplyOutcome::AlreadyApplied => {
                return s2s_replications::strict::StrictCommitApplyOutcome::AlreadyApplied;
            }
            StrictOperationApplyOutcome::VersionConflict => {
                warn!(
                    version,
                    "s2s strict channel operation version conflicts with repository state"
                );
                return s2s_replications::strict::StrictCommitApplyOutcome::Failed;
            }
        }
        if matches!(&applied_operation.op, ChannelOp::SetAcls { .. }) {
            let server = self.server.as_ref().and_then(Weak::upgrade);
            if let Some(server) =
                server.filter(|server| server.get_reevaluate_speak_on_acl_change())
            {
                // ACL re-evaluation is client-facing projection work and may be
                // expensive for a large affected subtree.  The strict repository
                // apply is already durable at this point, so do not hold the
                // replication delivery loop (and the proposer's completion
                // waiter) behind per-client permission calculations.
                tokio::spawn(async move {
                    server
                        .reevaluate_speak_after_acl_change(&applied_operation)
                        .await;
                });
            }
        }
        if let (Some(server), Some((id, nonce, fallback))) = (
            self.server.as_ref().and_then(Weak::upgrade),
            evict_pending_delete,
        ) {
            let moved = crate::user_channel_cache::move_local_clients_out_of_pending_delete(
                &server,
                &op_server_id,
                id,
                nonce,
                fallback,
                version,
            )
            .await;
            if moved > 0 {
                trace!(
                    server_id = %op_server_id,
                    channel_id = id,
                    nonce,
                    moved,
                    "moved local clients out of replicated pending-delete subtree"
                );
            }
        }
        s2s_replications::strict::StrictCommitApplyOutcome::Applied
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChannelSnapshot {
    channels: Vec<shitspeak_state::Channel>,
    freshness: i64,
    strict_operation_ids: Vec<StrictOperationId>,
}

fn strict_log_metadata_from_repo(
    metadata: StrictReplicationMetadata,
) -> s2s_replications::strict::StrictLogMetadata {
    s2s_replications::strict::StrictLogMetadata {
        op_id_hi: metadata.op_id_hi(),
        op_id_lo: metadata.op_id_lo(),
        ts_final: metadata.ts_final(),
    }
}

fn strict_log_metadata_to_repo(
    metadata: s2s_replications::strict::StrictLogMetadata,
) -> StrictReplicationMetadata {
    StrictReplicationMetadata::new(metadata.op_id_hi, metadata.op_id_lo, metadata.ts_final)
}

#[async_trait]
impl StrictReplicable for ChannelReplicationAdapter {
    type Op = ChannelOperation;

    fn current_version(&self) -> u64 {
        self.repo.current_version_in_server(&self.server_id)
    }

    fn history_metadata(&self) -> s2s_replications::strict::HistoryMetadata {
        s2s_replications::strict::HistoryMetadata {
            version: self.repo.current_version_in_server(&self.server_id),
            freshness: self.repo.latest_timestamp_in_server(&self.server_id),
        }
    }

    fn strict_replication_protocol_version(&self) -> u32 {
        if self.repo.strict_operation_durability_enabled() {
            s2s_overlay::STRICT_REPLICATION_PROTOCOL_VERSION
        } else {
            0
        }
    }

    fn legacy_applied_operation_ids(&self) -> Vec<(u64, u64)> {
        self.repo
            .strict_operation_ids_in_server(&self.server_id)
            .into_iter()
            .map(|id| (id.op_id_hi(), id.op_id_lo()))
            .collect()
    }

    fn snapshot_with_metadata(
        &self,
    ) -> Result<
        (s2s_replications::strict::HistoryMetadata, Bytes),
        s2s_replications::strict::StrictSnapshotError,
    > {
        let repo = self.repo.clone();
        let server_id = self.server_id.clone();
        let strict_snapshot = block_in_place_or_current(|handle| {
            handle.block_on(repo.s2s_snapshot_in_server(&server_id))
        })
        .ok_or_else(|| {
            s2s_replications::strict::StrictSnapshotError::new(
                "s2s channel snapshot requires a multi-thread Tokio runtime",
            )
        })?;
        let (version, channels, freshness, strict_operation_ids) = strict_snapshot.into_parts();
        let bytes = rmp_serde::to_vec(&ChannelSnapshot {
            channels,
            freshness,
            // Frozen compatibility ledger for pre-v5 receivers. New applied
            // operation ownership lives in the S2S checkpoint envelope.
            strict_operation_ids,
        })
        .map(Bytes::from)
        .map_err(|error| {
            s2s_replications::strict::StrictSnapshotError::new(format!(
                "s2s channel snapshot serialization failed: {error}"
            ))
        })?;
        Ok((
            s2s_replications::strict::HistoryMetadata { version, freshness },
            bytes,
        ))
    }

    fn log_since(
        &self,
        since: u64,
    ) -> s2s_replications::strict::LogSlice<s2s_replications::strict::StrictLogEntry<Self::Op>>
    {
        let repo = self.repo.clone();
        let server_id = self.server_id.clone();
        let entries = block_in_place_or_current(|handle| {
            handle.block_on(repo.strict_log_entries_since_in_server(&server_id, since))
        });
        match entries.flatten() {
            Some(entries) => s2s_replications::strict::LogSlice::Available(
                entries
                    .into_iter()
                    .map(|entry| {
                        let op = entry.op();
                        let version = op.version;
                        let mut canonical_op = (*op).clone();
                        // The terminal journal stores the proposal before the repository
                        // assigns its out-of-band version. Restore that field before
                        // constructing the catchup terminal proof.
                        canonical_op.version = 0;
                        let metadata = entry.strict_metadata().map(strict_log_metadata_from_repo);
                        let log_entry = match metadata {
                            Some(metadata) => {
                                s2s_replications::strict::StrictLogEntry::with_metadata(
                                    canonical_op,
                                    metadata,
                                )
                            }
                            None => s2s_replications::strict::StrictLogEntry::new(canonical_op),
                        };
                        (version, log_entry)
                    })
                    .collect(),
            ),
            None => s2s_replications::strict::LogSlice::TooOld,
        }
    }

    async fn apply_committed(&self, version: u64, mut op: Self::Op) {
        op.version = version;
        if !self.bind_operation_to_topic(&mut op) {
            warn!(
                topic_server_id = %self.server_id,
                operation_server_id = %op.server_id,
                "s2s channel operation does not match its topic scope"
            );
            return;
        }
        let evict_pending_delete = match &op.op {
            ChannelOp::MarkPendingDelete {
                id,
                nonce,
                evict_clients,
            } if *evict_clients => {
                let fallback = self
                    .repo
                    .get_channel_in_server(&op.server_id, *id)
                    .await
                    .and_then(|channel| channel.parent_id)
                    .unwrap_or(0);
                Some((*id, *nonce, fallback))
            }
            _ => None,
        };
        let op_server_id = op.server_id.clone();
        let applied_operation = op.clone();
        if let Err(e) = self.repo.apply_committed_operation(op).await {
            warn!(error = ?e, "s2s channel operation apply failed");
            return;
        }
        if matches!(&applied_operation.op, ChannelOp::SetAcls { .. }) {
            let server = self.server.as_ref().and_then(Weak::upgrade);
            if let Some(server) =
                server.filter(|server| server.get_reevaluate_speak_on_acl_change())
            {
                // Keep replicated state application independent of potentially
                // slow per-client ACL projection work.  Suppression converges in
                // the background from the committed repository state.
                tokio::spawn(async move {
                    server
                        .reevaluate_speak_after_acl_change(&applied_operation)
                        .await;
                });
            }
        }
        if let (Some(server), Some((id, nonce, fallback))) = (
            self.server.as_ref().and_then(Weak::upgrade),
            evict_pending_delete,
        ) {
            let moved = crate::user_channel_cache::move_local_clients_out_of_pending_delete(
                &server,
                &op_server_id,
                id,
                nonce,
                fallback,
                version,
            )
            .await;
            if moved > 0 {
                trace!(
                    server_id = %op_server_id,
                    channel_id = id,
                    nonce,
                    moved,
                    "moved local clients out of replicated pending-delete subtree"
                );
            }
        }
    }

    async fn apply_committed_with_metadata(
        &self,
        version: u64,
        op: Self::Op,
        metadata: Option<s2s_replications::strict::StrictLogMetadata>,
    ) {
        if let Some(metadata) = metadata {
            let _ = self
                .apply_strict_committed_once(version, op, metadata)
                .await;
        } else {
            self.apply_committed(version, op).await;
        }
    }

    async fn apply_committed_once(
        &self,
        version: u64,
        op: Self::Op,
        metadata: s2s_replications::strict::StrictLogMetadata,
    ) -> s2s_replications::strict::StrictCommitApplyOutcome {
        self.apply_strict_committed_once(version, op, metadata)
            .await
    }

    async fn install_snapshot(
        &self,
        version: u64,
        snapshot: Bytes,
    ) -> Result<(), s2s_replications::strict::StrictSnapshotError> {
        let decoded: ChannelSnapshot = rmp_serde::from_slice(&snapshot).map_err(|error| {
            s2s_replications::strict::StrictSnapshotError::new(format!(
                "s2s channel snapshot decode failed: {error}"
            ))
        })?;
        self.repo
            .install_s2s_checkpoint_snapshot_in_server(
                &self.server_id,
                version,
                decoded.channels,
                decoded.freshness,
            )
            .await
            .map_err(|error| {
                let message = format!("s2s channel snapshot install failed: {error:?}");
                match error {
                    ChannelRepoError::WalIo(_) => {
                        s2s_replications::strict::StrictSnapshotError::durability_failure(message)
                    }
                    _ => s2s_replications::strict::StrictSnapshotError::new(message),
                }
            })
    }
}

#[derive(Clone)]
pub struct ChannelBlobReplicationAdapter {
    server_id: String,
    blobs: Arc<ChannelBlobStore>,
    channels: Arc<ChannelRepository>,
}

impl ChannelBlobReplicationAdapter {
    pub fn new(
        server_id: String,
        blobs: Arc<ChannelBlobStore>,
        channels: Arc<ChannelRepository>,
    ) -> Self {
        Self {
            server_id,
            blobs,
            channels,
        }
    }
}

#[async_trait]
impl BlobReplicable for ChannelBlobReplicationAdapter {
    async fn get_blob(&self, key: &str) -> Option<Bytes> {
        self.blobs.get(key).await.ok().flatten()
    }

    async fn put_blob(
        &self,
        key: &str,
        data: Bytes,
    ) -> Result<(), s2s_replications::ReplicationError> {
        let written = self.blobs.put(&data).await.map_err(|_| {
            s2s_replications::ReplicationError::Malformed("channel blob store write failed")
        })?;
        if written == key {
            Ok(())
        } else {
            Err(s2s_replications::ReplicationError::Malformed(
                "channel blob key does not match content",
            ))
        }
    }

    async fn delete_blob(&self, key: &str) -> Result<(), s2s_replications::ReplicationError> {
        self.blobs.delete(key).await.map_err(|_| {
            s2s_replications::ReplicationError::Malformed("channel blob delete failed")
        })
    }

    async fn stored_keys(&self) -> HashSet<String> {
        self.blobs.keys().await.unwrap_or_default()
    }

    async fn referenced_keys(&self) -> HashSet<String> {
        self.channels
            .get_all_in_server(&self.server_id)
            .await
            .into_iter()
            .filter_map(|channel| channel.description_hash.clone())
            .filter(|key| key.len() == 40)
            .collect()
    }
}

#[derive(Clone)]
pub struct BanReplicationAdapter {
    repo: Arc<BanRepository>,
}

impl BanReplicationAdapter {
    pub fn new(repo: Arc<BanRepository>) -> Self {
        Self { repo }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BanSnapshot {
    entries: Vec<BanEntry>,
    freshness: i64,
    strict_operation_ids: Vec<StrictOperationId>,
}

#[async_trait]
impl StrictReplicable for BanReplicationAdapter {
    type Op = BanOperation;

    fn current_version(&self) -> u64 {
        self.repo.current_version()
    }

    fn history_metadata(&self) -> s2s_replications::strict::HistoryMetadata {
        s2s_replications::strict::HistoryMetadata {
            version: self.repo.current_version(),
            freshness: self.repo.latest_timestamp(),
        }
    }

    fn strict_replication_protocol_version(&self) -> u32 {
        if self.repo.durable_storage_enabled() {
            s2s_overlay::STRICT_REPLICATION_PROTOCOL_VERSION
        } else {
            0
        }
    }

    fn legacy_applied_operation_ids(&self) -> Vec<(u64, u64)> {
        self.repo
            .strict_operation_ids()
            .unwrap_or_default()
            .into_iter()
            .map(|id| (id.op_id_hi(), id.op_id_lo()))
            .collect()
    }

    fn snapshot_with_metadata(
        &self,
    ) -> Result<
        (s2s_replications::strict::HistoryMetadata, Bytes),
        s2s_replications::strict::StrictSnapshotError,
    > {
        let strict_snapshot = self.repo.strict_snapshot_v5().map_err(|error| {
            let message = format!("s2s ban snapshot capture failed: {error}");
            if self.repo.strict_durability_failure_observed() {
                s2s_replications::strict::StrictSnapshotError::durability_failure(message)
            } else {
                s2s_replications::strict::StrictSnapshotError::new(message)
            }
        })?;
        let (version, entries, freshness, strict_operation_ids) = strict_snapshot.into_parts();
        let bytes = rmp_serde::to_vec(&BanSnapshot {
            entries,
            freshness,
            // Frozen compatibility ledger for pre-v5 snapshot decoders.
            strict_operation_ids,
        })
        .map(Bytes::from)
        .map_err(|error| {
            s2s_replications::strict::StrictSnapshotError::new(format!(
                "s2s ban snapshot serialization failed: {error}"
            ))
        })?;
        Ok((
            s2s_replications::strict::HistoryMetadata { version, freshness },
            bytes,
        ))
    }

    fn log_since(
        &self,
        since: u64,
    ) -> s2s_replications::strict::LogSlice<s2s_replications::strict::StrictLogEntry<Self::Op>>
    {
        let repo = self.repo.clone();
        let entries = block_in_place_or_current(|handle| {
            handle.block_on(repo.strict_log_entries_since(since))
        });
        match entries.flatten() {
            Some(entries) => s2s_replications::strict::LogSlice::Available(
                entries
                    .into_iter()
                    .map(|entry| {
                        let op = entry.op();
                        let version = op.version;
                        let mut canonical_op = (*op).clone();
                        // Restore the version-zero proposal held by the terminal journal;
                        // catchup carries the assigned version separately.
                        canonical_op.version = 0;
                        let metadata = entry.strict_metadata().map(strict_log_metadata_from_repo);
                        let log_entry = match metadata {
                            Some(metadata) => {
                                s2s_replications::strict::StrictLogEntry::with_metadata(
                                    canonical_op,
                                    metadata,
                                )
                            }
                            None => s2s_replications::strict::StrictLogEntry::new(canonical_op),
                        };
                        (version, log_entry)
                    })
                    .collect(),
            ),
            None => s2s_replications::strict::LogSlice::TooOld,
        }
    }

    async fn apply_committed(&self, version: u64, mut op: Self::Op) {
        op.version = version;
        self.repo.apply_remote_operation(Arc::new(op)).await;
    }

    async fn apply_committed_with_metadata(
        &self,
        version: u64,
        op: Self::Op,
        metadata: Option<s2s_replications::strict::StrictLogMetadata>,
    ) {
        if let Some(metadata) = metadata {
            let _ = self.apply_committed_once(version, op, metadata).await;
        } else {
            self.apply_committed(version, op).await;
        }
    }

    async fn apply_committed_once(
        &self,
        version: u64,
        mut op: Self::Op,
        metadata: s2s_replications::strict::StrictLogMetadata,
    ) -> s2s_replications::strict::StrictCommitApplyOutcome {
        op.version = version;
        match self
            .repo
            .apply_strict_operation_v5(Arc::new(op), strict_log_metadata_to_repo(metadata))
            .await
        {
            Ok(StrictOperationApplyOutcome::Applied) => {
                s2s_replications::strict::StrictCommitApplyOutcome::Applied
            }
            Ok(StrictOperationApplyOutcome::AlreadyApplied) => {
                s2s_replications::strict::StrictCommitApplyOutcome::AlreadyApplied
            }
            Ok(StrictOperationApplyOutcome::VersionConflict) => {
                warn!(
                    version,
                    "s2s strict ban operation version conflicts with repository state"
                );
                s2s_replications::strict::StrictCommitApplyOutcome::Failed
            }
            Err(error) => {
                warn!(error = %error, "s2s strict ban operation apply failed");
                s2s_replications::strict::StrictCommitApplyOutcome::Failed
            }
        }
    }

    async fn install_snapshot(
        &self,
        version: u64,
        snapshot: Bytes,
    ) -> Result<(), s2s_replications::strict::StrictSnapshotError> {
        let decoded: BanSnapshot = rmp_serde::from_slice(&snapshot).map_err(|error| {
            s2s_replications::strict::StrictSnapshotError::new(format!(
                "s2s ban snapshot decode failed: {error}"
            ))
        })?;
        self.repo
            .install_s2s_snapshot_v5(version, decoded.entries, decoded.freshness)
            .await
            .map_err(|error| {
                let message = format!("s2s ban snapshot install failed: {error}");
                if self.repo.strict_durability_failure_observed() {
                    s2s_replications::strict::StrictSnapshotError::durability_failure(message)
                } else {
                    s2s_replications::strict::StrictSnapshotError::new(message)
                }
            })
    }
}

#[derive(Clone)]
struct ClientReplicationAdapter {
    clients: Arc<ClientRepository>,
    channels: Arc<ChannelRepository>,
    local_epoch: u64,
    snapshot_deferrals: ClientSnapshotDeferralGuard,
}

#[derive(Clone, Default)]
struct ClientSnapshotDeferralGuard {
    state: Arc<Mutex<ClientSnapshotDeferralState>>,
}

#[derive(Default)]
struct ClientSnapshotDeferralState {
    next_generation: u64,
    by_origin: HashMap<NodeIdentifier, ClientSnapshotDeferral>,
}

struct ClientSnapshotDeferral {
    generation: u64,
    epoch: u64,
    version: u64,
    deferred_at: tokio::time::Instant,
    error_emitted: bool,
}

impl ClientSnapshotDeferralGuard {
    fn record_deferred(&self, origin: NodeIdentifier, epoch: u64, version: u64) {
        let (generation, deadline) = {
            let mut state = self.state.lock();
            if let Some(deferred) = state.by_origin.get_mut(&origin) {
                deferred.epoch = epoch;
                deferred.version = version;
                return;
            }

            state.next_generation = state.next_generation.wrapping_add(1);
            let generation = state.next_generation;
            let deferred_at = tokio::time::Instant::now();
            state.by_origin.insert(
                origin,
                ClientSnapshotDeferral {
                    generation,
                    epoch,
                    version,
                    deferred_at,
                    error_emitted: false,
                },
            );
            (
                generation,
                deferred_at + S2S_CLIENT_SNAPSHOT_DEFER_ERROR_AFTER,
            )
        };

        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            let overdue = {
                let mut state = state.lock();
                let Some(deferred) = state.by_origin.get_mut(&origin) else {
                    return;
                };
                if deferred.generation != generation || deferred.error_emitted {
                    return;
                }
                deferred.error_emitted = true;
                Some((
                    deferred.epoch,
                    deferred.version,
                    deferred.deferred_at.elapsed(),
                ))
            };
            if let Some((epoch, version, deferred_for)) = overdue {
                error!(
                    origin,
                    epoch,
                    version,
                    deferred_for_ms = deferred_for.as_millis() as u64,
                    "s2s client snapshot has remained deferred on recipient"
                );
            }
        });
    }

    fn clear(&self, origin: NodeIdentifier) {
        self.state.lock().by_origin.remove(&origin);
    }

    #[cfg(test)]
    fn status(&self, origin: NodeIdentifier) -> Option<(u64, u64, u64, bool)> {
        self.state.lock().by_origin.get(&origin).map(|deferred| {
            (
                deferred.generation,
                deferred.epoch,
                deferred.version,
                deferred.error_emitted,
            )
        })
    }
}

impl ClientReplicationAdapter {
    fn new(
        clients: Arc<ClientRepository>,
        channels: Arc<ChannelRepository>,
        local_epoch: u64,
    ) -> Self {
        Self {
            clients,
            channels,
            local_epoch,
            snapshot_deferrals: ClientSnapshotDeferralGuard::default(),
        }
    }

    async fn sanitize_channel_dependencies(
        &self,
        entry: &mut ClientStateLogEntry,
        current_channel_version: u64,
    ) {
        if entry.channel_version_dep.unwrap_or(0) > current_channel_version {
            return;
        }

        let server_id = entry.op.server_id().to_owned();
        let valid_channels: HashSet<u32> = self
            .channels
            .get_all_in_server(&server_id)
            .await
            .into_iter()
            .map(|channel| channel.id)
            .collect();

        match &mut entry.op {
            ClientStateOperation::AddClient { initial_state, .. } => {
                sanitize_initial_client_channels(initial_state, &valid_channels);
            }
            ClientStateOperation::UpdateGlobalState { delta, .. } => {
                sanitize_update_client_channels(delta, &valid_channels);
            }
            ClientStateOperation::RemoveClient { .. } => {}
            ClientStateOperation::ResetNode { .. } => {}
        }
    }
}

fn sanitize_initial_client_channels(
    delta: &mut ClientGlobalStateDelta,
    valid_channels: &HashSet<u32>,
) {
    if delta
        .current_channel_id
        .is_some_and(|channel_id| !valid_channels.contains(&channel_id))
    {
        delta.current_channel_id = Some(0);
    }
    retain_valid_channel_delta(delta, valid_channels);
}

fn sanitize_update_client_channels(
    delta: &mut ClientGlobalStateDelta,
    valid_channels: &HashSet<u32>,
) {
    if delta
        .current_channel_id
        .is_some_and(|channel_id| !valid_channels.contains(&channel_id))
    {
        delta.current_channel_id = None;
        if !(delta.hidden_from_regular_users == Some(false) && delta.suppress == Some(false)) {
            delta.suppress = None;
        }
    }
    retain_valid_channel_delta(delta, valid_channels);
}

fn retain_valid_channel_delta(delta: &mut ClientGlobalStateDelta, valid_channels: &HashSet<u32>) {
    if let Some(channel_ids) = delta.listening_channel_add.as_mut() {
        channel_ids.retain(|channel_id| valid_channels.contains(channel_id));
        if channel_ids.is_empty() {
            delta.listening_channel_add = None;
        }
    }
    if let Some(channel_ids) = delta.listening_channel_remove.as_mut() {
        channel_ids.retain(|channel_id| valid_channels.contains(channel_id));
        if channel_ids.is_empty() {
            delta.listening_channel_remove = None;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientOriginSnapshot {
    version: u64,
    entries: Vec<ClientStateLogEntry>,
}

#[async_trait]
impl OwnerReplicable for ClientReplicationAdapter {
    type Op = ClientStateLogEntry;

    fn local_version(&self) -> u64 {
        self.clients.current_version()
    }

    fn known_versions(&self) -> HashMap<NodeIdentifier, (u64, u64)> {
        let clients = self.clients.clone();
        let local_node = self.clients.local_node_id();
        let local_epoch = self.local_epoch;
        let mut versions = HashMap::from([(local_node, (local_epoch, self.local_version()))]);
        if let Some(remote_versions) = block_in_place_or_current(|handle| {
            handle.block_on(clients.known_remote_origin_versions())
        }) {
            versions.extend(remote_versions);
        }
        versions
    }

    fn snapshot_for_origin(&self, origin: NodeIdentifier) -> Option<(u64, u64, Bytes)> {
        let clients = self.clients.clone();
        let channels = Arc::clone(&self.channels);
        let local_node = self.clients.local_node_id();
        let local_epoch = self.local_epoch;
        block_in_place_or_current(|handle| {
            let (epoch, version, mut entries) = if origin == local_node {
                let (version, entries) = handle.block_on(clients.local_origin_snapshot_entries());
                (local_epoch, version, entries)
            } else {
                handle.block_on(clients.remote_origin_snapshot_entries(origin))?
            };
            for entry in &mut entries {
                entry.channel_version_dep =
                    Some(channels.current_version_in_server(entry.op.server_id()));
            }
            if entries.len() > MAX_CLIENT_ORIGIN_SNAPSHOT_ENTRIES {
                return None;
            }
            let encoded = rmp_serde::to_vec(&ClientOriginSnapshot { version, entries }).ok()?;
            if encoded.len() > MAX_CLIENT_ORIGIN_SNAPSHOT_BYTES {
                return None;
            }
            let bytes = Bytes::from(encoded);
            Some((epoch, version, bytes))
        })
        .flatten()
    }

    fn log_for_origin(
        &self,
        origin: NodeIdentifier,
        since: u64,
    ) -> s2s_replications::owner::LogSlice<Self::Op> {
        let clients = self.clients.clone();
        let slice = block_in_place_or_current(|handle| {
            handle.block_on(clients.get_log_slice_for_node(origin, since))
        });
        match slice {
            Some(ClientOriginLogSlice::Available(entries)) => {
                s2s_replications::owner::LogSlice::Available(
                    entries
                        .into_iter()
                        .map(|entry| (entry.version, (*entry).clone()))
                        .collect(),
                )
            }
            Some(ClientOriginLogSlice::TooOld) | None => s2s_replications::owner::LogSlice::TooOld,
        }
    }

    async fn apply_remote(
        &self,
        origin: NodeIdentifier,
        epoch: u64,
        version: u64,
        mut op: Self::Op,
    ) {
        op.node_id = origin;
        op.version = version;
        let current_channel_version = self.channels.current_version_in_server(op.op.server_id());
        self.sanitize_channel_dependencies(&mut op, current_channel_version)
            .await;
        if let Err(()) = self
            .clients
            .apply_remote_operation_with_epoch(epoch, Arc::new(op), current_channel_version)
            .await
        {
            warn!(origin, version, "s2s client operation apply failed");
        }
    }

    async fn install_snapshot_for_origin(
        &self,
        origin: NodeIdentifier,
        epoch: u64,
        version: u64,
        snapshot: Bytes,
    ) -> Result<OwnerSnapshotInstallOutcome, OwnerSnapshotInstallError> {
        let outcome = async {
            if snapshot.len() > MAX_CLIENT_ORIGIN_SNAPSHOT_BYTES {
                return Err(OwnerSnapshotInstallError::new(format!(
                    "s2s client snapshot for origin {origin} is {} bytes; maximum is {MAX_CLIENT_ORIGIN_SNAPSHOT_BYTES}",
                    snapshot.len()
                )));
            }
            let decoded: ClientOriginSnapshot = match rmp_serde::from_slice(&snapshot) {
                Ok(snapshot) => snapshot,
                Err(e) => {
                    return Err(OwnerSnapshotInstallError::new(format!(
                        "s2s client snapshot decode failed for origin {origin}: {e}"
                    )));
                }
            };
            let mut current_channel_versions = HashMap::new();
            let mut entries = Vec::with_capacity(decoded.entries.len());
            for mut entry in decoded.entries {
                let current_channel_version = self
                    .channels
                    .current_version_in_server(entry.op.server_id());
                current_channel_versions
                    .entry(entry.op.server_id().to_owned())
                    .and_modify(|version: &mut u64| {
                        *version = (*version).max(current_channel_version)
                    })
                    .or_insert(current_channel_version);
                self.sanitize_channel_dependencies(&mut entry, current_channel_version)
                    .await;
                entries.push(entry);
            }
            match self
                .clients
                .install_remote_client_snapshot(
                    origin,
                    epoch,
                    version,
                    decoded.version,
                    entries,
                    &current_channel_versions,
                )
                .await
                .map_err(|error| OwnerSnapshotInstallError::new(error.to_string()))?
            {
                ClientSnapshotInstallOutcome::Installed => {
                    Ok(OwnerSnapshotInstallOutcome::Installed)
                }
                ClientSnapshotInstallOutcome::Deferred => {
                    Ok(OwnerSnapshotInstallOutcome::Deferred)
                }
            }
        }
        .await;

        match outcome {
            Ok(OwnerSnapshotInstallOutcome::Deferred) => {
                self.snapshot_deferrals
                    .record_deferred(origin, epoch, version);
                Ok(OwnerSnapshotInstallOutcome::Deferred)
            }
            Ok(OwnerSnapshotInstallOutcome::Installed) => {
                self.snapshot_deferrals.clear(origin);
                Ok(OwnerSnapshotInstallOutcome::Installed)
            }
            Err(error) => {
                self.snapshot_deferrals.clear(origin);
                Err(error)
            }
        }
    }

    async fn reset_origin(&self, origin: NodeIdentifier, new_epoch: u64) {
        self.snapshot_deferrals.clear(origin);
        if origin != self.clients.local_node_id() {
            self.clients
                .reset_clients_from_node(origin, new_epoch)
                .await;
        }
    }

    async fn remove_origin(&self, origin: NodeIdentifier) {
        self.snapshot_deferrals.clear(origin);
        if origin != self.clients.local_node_id() {
            self.clients.remove_clients_from_node(origin).await;
        }
    }

    fn local_op_already_applied(&self, op: &Self::Op) -> bool {
        op.node_id == self.clients.local_node_id() && op.version <= self.clients.current_version()
    }

    fn local_version_hint(&self, op: &Self::Op) -> Option<u64> {
        (op.node_id == self.clients.local_node_id()).then_some(op.version)
    }
}

fn block_in_place_or_current<T>(f: impl FnOnce(&tokio::runtime::Handle) -> T) -> Option<T> {
    let handle = tokio::runtime::Handle::try_current().ok()?;
    if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread {
        // A synchronous trait callback cannot safely re-enter this runtime.
        return None;
    }
    Some(tokio::task::block_in_place(|| f(&handle)))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;
    use shitspeak_state::{ChannelRepoTuning, ChannelRepository, ChannelRootConfig};

    fn test_node_geo(latitude: f64) -> NodeGeo {
        NodeGeo::new(latitude, 0.0, None, None, None, "test").expect("valid coordinates")
    }

    #[tokio::test(start_paused = true)]
    async fn public_geo_retries_with_backoff_until_the_first_success_then_freezes() {
        let local_geo = SharedNodeGeo::default();
        let attempts = Arc::new(AtomicUsize::new(0));
        let outcomes = Arc::new(Mutex::new(VecDeque::from([
            None,
            None,
            None,
            None,
            None,
            Some(test_node_geo(1.0)),
            Some(test_node_geo(2.0)),
        ])));
        let (shutdown_tx, shutdown_rx) = watch::channel(());
        let probe_attempts = Arc::clone(&attempts);
        let probe_outcomes = Arc::clone(&outcomes);
        let retry_initial = Duration::from_secs(1);
        let retry_cap = Duration::from_secs(4);
        let task = tokio::spawn(retry_observability_geo_until_resolved(
            local_geo.clone(),
            shutdown_rx,
            retry_initial,
            retry_cap,
            move || {
                let attempts = Arc::clone(&probe_attempts);
                let outcomes = Arc::clone(&probe_outcomes);
                async move {
                    attempts.fetch_add(1, Ordering::Relaxed);
                    outcomes.lock().pop_front().flatten()
                }
            },
        ));

        tokio::task::yield_now().await;
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        assert!(local_geo.get().is_none());

        tokio::time::advance(retry_initial).await;
        tokio::task::yield_now().await;
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
        assert!(local_geo.get().is_none());

        tokio::time::advance(retry_initial.saturating_mul(2)).await;
        tokio::task::yield_now().await;
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
        assert!(local_geo.get().is_none());

        tokio::time::advance(retry_cap).await;
        tokio::task::yield_now().await;
        assert_eq!(attempts.load(Ordering::Relaxed), 4);
        assert!(local_geo.get().is_none());

        tokio::time::advance(retry_cap).await;
        tokio::task::yield_now().await;
        assert_eq!(attempts.load(Ordering::Relaxed), 5);
        assert!(local_geo.get().is_none());

        tokio::time::advance(retry_cap).await;
        task.await.expect("geo retry task completes after success");
        assert_eq!(attempts.load(Ordering::Relaxed), 6);
        assert_eq!(local_geo.get().map(|geo| geo.latitude()), Some(1.0));
        assert_eq!(outcomes.lock().len(), 1, "later results must not be probed");

        tokio::time::advance(retry_cap.saturating_mul(3)).await;
        assert_eq!(attempts.load(Ordering::Relaxed), 6);
        assert_eq!(local_geo.get().map(|geo| geo.latitude()), Some(1.0));
        drop(shutdown_tx);
    }

    #[tokio::test(start_paused = true)]
    async fn configured_geo_skips_public_geo_probes() {
        let local_geo = SharedNodeGeo::new(Some(test_node_geo(1.0)));
        let attempts = Arc::new(AtomicUsize::new(0));
        let (shutdown_tx, shutdown_rx) = watch::channel(());
        let probe_attempts = Arc::clone(&attempts);
        let task = tokio::spawn(retry_observability_geo_until_resolved(
            local_geo.clone(),
            shutdown_rx,
            Duration::from_secs(60),
            Duration::from_secs(300),
            move || {
                let attempts = Arc::clone(&probe_attempts);
                async move {
                    attempts.fetch_add(1, Ordering::Relaxed);
                    Some(test_node_geo(2.0))
                }
            },
        ));

        task.await.expect("configured geo bypasses retry worker");
        tokio::time::advance(Duration::from_secs(300)).await;
        assert_eq!(attempts.load(Ordering::Relaxed), 0);
        assert_eq!(local_geo.get().map(|geo| geo.latitude()), Some(1.0));
        drop(shutdown_tx);
    }

    #[test]
    fn strict_proposal_gateway_timeout_tracks_replication_ttl() {
        let timeout = strict_proposal_gateway_response_timeout(
            &s2s_replications::ReplicationConfig::default(),
        );

        assert!(timeout > s2s_replications::ReplicationConfig::default().propose_ttl());
        assert_eq!(timeout, Duration::from_millis(10_200));
    }

    #[test]
    fn invalid_remote_move_preserves_explicit_hidden_mode_unsuppress() {
        let mut delta = ClientGlobalStateDelta {
            current_channel_id: Some(99),
            suppress: Some(false),
            hidden_from_regular_users: Some(false),
            ..Default::default()
        };

        sanitize_update_client_channels(&mut delta, &HashSet::from([0]));

        assert_eq!(delta.current_channel_id, None);
        assert_eq!(delta.hidden_from_regular_users, Some(false));
        assert_eq!(delta.suppress, Some(false));
    }

    #[test]
    fn strict_proposal_gateway_timeout_keeps_generic_floor() {
        let cfg = s2s_replications::ReplicationConfig::default()
            .with_propose_ttl(Duration::from_millis(100))
            .with_delivery_tick_interval(Duration::from_millis(50));

        assert_eq!(
            strict_proposal_gateway_response_timeout(&cfg),
            S2S_GATEWAY_RESPONSE_TIMEOUT
        );
    }

    #[tokio::test(start_paused = true)]
    #[tracing_test::traced_test]
    async fn client_snapshot_deferral_guard_errors_once_per_continuous_interval() {
        let guard = ClientSnapshotDeferralGuard::default();

        guard.record_deferred(1, 42, 10);
        tokio::task::yield_now().await;
        let (generation, _, _, error_emitted) = guard.status(1).unwrap();
        assert!(!error_emitted);

        tokio::time::advance(Duration::from_secs(19)).await;
        tokio::task::yield_now().await;
        assert!(!guard.status(1).unwrap().3);

        guard.record_deferred(1, 43, 11);
        assert_eq!(guard.status(1), Some((generation, 43, 11, false)));
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(guard.status(1), Some((generation, 43, 11, true)));
        assert!(logs_contain(
            "ERROR client_snapshot_deferral_guard_errors_once_per_continuous_interval: shitspeak_runtime::s2s: s2s client snapshot has remained deferred on recipient"
        ));

        guard.record_deferred(1, 44, 12);
        tokio::time::advance(S2S_CLIENT_SNAPSHOT_DEFER_ERROR_AFTER).await;
        tokio::task::yield_now().await;
        assert_eq!(
            guard.status(1),
            Some((generation, 44, 12, true)),
            "retries must not emit another error or restart the interval"
        );

        guard.record_deferred(2, 50, 20);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        guard.clear(2);
        guard.record_deferred(2, 51, 21);
        tokio::task::yield_now().await;
        let replacement = guard.status(2).unwrap();
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        assert_eq!(guard.status(2), Some(replacement));
        assert!(!replacement.3, "a stale timer must not flag a new interval");
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        assert!(guard.status(2).unwrap().3);

        guard.clear(1);
        assert_eq!(guard.status(1), None);
    }

    #[test]
    fn voice_recipient_index_filter_ignores_unrelated_client_updates() {
        let entry = ClientStateLogEntry {
            version: 1,
            node_id: 1,
            timestamp: 0,
            channel_version_dep: None,
            op: ClientStateOperation::UpdateGlobalState {
                server_id: DEFAULT_SERVER_ID.to_owned(),
                session_id: ClientSessionIdentifier::new(1, 1).unwrap(),
                client_instance_id: 1,
                sender_session_id: None,
                delta: ClientGlobalStateDelta {
                    self_mute: Some(true),
                    ..Default::default()
                },
            },
        };

        assert!(!client_entry_affects_voice_recipient_index(&entry));
    }

    #[test]
    fn voice_recipient_index_filter_detects_channel_updates() {
        let entry = ClientStateLogEntry {
            version: 1,
            node_id: 1,
            timestamp: 0,
            channel_version_dep: None,
            op: ClientStateOperation::UpdateGlobalState {
                server_id: DEFAULT_SERVER_ID.to_owned(),
                session_id: ClientSessionIdentifier::new(1, 1).unwrap(),
                client_instance_id: 1,
                sender_session_id: None,
                delta: ClientGlobalStateDelta {
                    current_channel_id: Some(42),
                    ..Default::default()
                },
            },
        };

        assert!(client_entry_affects_voice_recipient_index(&entry));
    }

    #[test]
    fn voice_recipient_index_filter_detects_non_default_server_scopes() {
        let entry = ClientStateLogEntry {
            version: 1,
            node_id: 1,
            timestamp: 0,
            channel_version_dep: None,
            op: ClientStateOperation::UpdateGlobalState {
                server_id: "other".to_owned(),
                session_id: ClientSessionIdentifier::new(1, 1).unwrap(),
                client_instance_id: 1,
                sender_session_id: None,
                delta: ClientGlobalStateDelta {
                    current_channel_id: Some(42),
                    ..Default::default()
                },
            },
        };

        assert!(client_entry_affects_voice_recipient_index(&entry));
    }

    fn test_channel_repo(node_id: u16) -> Arc<ChannelRepository> {
        ChannelRepository::new_in_memory(
            node_id,
            ChannelRootConfig::new("Root"),
            ChannelRepoTuning {
                log_max_entries: 128,
                snapshot_every_ops: 100,
                snapshot_every_secs: 60,
                wal_compaction_expire_count: 100,
            },
        )
    }

    fn persisted_channel_tuning() -> ChannelRepoTuning {
        ChannelRepoTuning {
            log_max_entries: 128,
            snapshot_every_ops: 100,
            snapshot_every_secs: 60,
            wal_compaction_expire_count: 100,
        }
    }

    fn strict_log_metadata(
        op_id_hi: u64,
        op_id_lo: u64,
        ts_final: u64,
    ) -> s2s_replications::strict::StrictLogMetadata {
        s2s_replications::strict::StrictLogMetadata {
            op_id_hi,
            op_id_lo,
            ts_final,
        }
    }

    fn strict_channel_create_op(channel_id: u32) -> ChannelOperation {
        ChannelOperation {
            server_id: DEFAULT_SERVER_ID.to_owned(),
            version: 0,
            node_id: 1,
            timestamp: 123,
            emits_client_message: true,
            op: ChannelOp::CreateChannel {
                channel: shitspeak_state::Channel::new(
                    channel_id,
                    "strict-snapshot",
                    0,
                    0,
                    Some(0),
                ),
            },
        }
    }

    fn strict_ban_add_op(address: &str) -> BanOperation {
        BanOperation {
            version: 0,
            node_id: 1,
            timestamp: 123,
            op: BanOp::AddBan {
                entry: BanEntry {
                    address: address.parse().expect("test address"),
                    mask: 32,
                    name: Some("strict-snapshot".to_owned()),
                    hash: None,
                    reason: Some("snapshot replay test".to_owned()),
                    start: 123,
                    duration: 0,
                },
            },
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn strict_adapter_logs_restore_version_zero_proposal_bytes() {
        let channel_proposal = strict_channel_create_op(69);
        let channel_proposal_bytes =
            rmp_serde::to_vec(&channel_proposal).expect("encode channel proposal");
        let channel_adapter = ChannelReplicationAdapter::new(
            DEFAULT_SERVER_ID.to_owned(),
            test_channel_repo(1),
            None,
        );
        let channel_metadata = strict_log_metadata(101, 102, 103);
        assert_eq!(
            channel_adapter
                .apply_committed_once(1, channel_proposal, channel_metadata)
                .await,
            s2s_replications::strict::StrictCommitApplyOutcome::Applied
        );
        let s2s_replications::strict::LogSlice::Available(channel_log) =
            channel_adapter.log_since(0)
        else {
            panic!("channel strict log must be available");
        };
        assert_eq!(channel_log.len(), 1);
        let (channel_version, channel_entry) = &channel_log[0];
        assert_eq!(*channel_version, 1);
        assert_eq!(channel_entry.op.version, 0);
        assert_eq!(channel_entry.metadata, Some(channel_metadata));
        assert_eq!(
            rmp_serde::to_vec(&channel_entry.op).expect("encode logged channel proposal"),
            channel_proposal_bytes
        );

        let ban_proposal = strict_ban_add_op("203.0.113.69");
        let ban_proposal_bytes = rmp_serde::to_vec(&ban_proposal).expect("encode ban proposal");
        let ban_adapter = BanReplicationAdapter::new(BanRepository::new_in_memory(1));
        let ban_metadata = strict_log_metadata(201, 202, 203);
        assert_eq!(
            ban_adapter
                .apply_committed_once(1, ban_proposal, ban_metadata)
                .await,
            s2s_replications::strict::StrictCommitApplyOutcome::Applied
        );
        let s2s_replications::strict::LogSlice::Available(ban_log) = ban_adapter.log_since(0)
        else {
            panic!("ban strict log must be available");
        };
        assert_eq!(ban_log.len(), 1);
        let (ban_version, ban_entry) = &ban_log[0];
        assert_eq!(*ban_version, 1);
        assert_eq!(ban_entry.op.version, 0);
        assert_eq!(ban_entry.metadata, Some(ban_metadata));
        assert_eq!(
            rmp_serde::to_vec(&ban_entry.op).expect("encode logged ban proposal"),
            ban_proposal_bytes
        );
    }

    #[test]
    fn strict_production_adapters_require_durable_repositories_for_v2() {
        let channels = test_channel_repo(1);
        let channel_adapter =
            ChannelReplicationAdapter::new(DEFAULT_SERVER_ID.to_owned(), channels, None);
        assert_eq!(channel_adapter.strict_replication_protocol_version(), 0);

        let bans = BanRepository::new_in_memory(1);
        let ban_adapter = BanReplicationAdapter::new(bans);
        assert_eq!(ban_adapter.strict_replication_protocol_version(), 0);
    }

    #[tokio::test]
    async fn strict_production_adapters_report_malformed_snapshot_payloads() {
        let channel_adapter = ChannelReplicationAdapter::new(
            DEFAULT_SERVER_ID.to_owned(),
            test_channel_repo(1),
            None,
        );
        assert!(
            channel_adapter
                .install_snapshot(1, Bytes::from_static(b"not-msgpack"))
                .await
                .is_err()
        );

        let ban_adapter = BanReplicationAdapter::new(BanRepository::new_in_memory(1));
        assert!(
            ban_adapter
                .install_snapshot(1, Bytes::from_static(b"not-msgpack"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn strict_production_adapters_reject_snapshots_without_operation_ids() {
        #[derive(Serialize)]
        struct ChannelSnapshotWithoutOperationIds {
            channels: Vec<shitspeak_state::Channel>,
            freshness: i64,
        }

        #[derive(Serialize)]
        struct BanSnapshotWithoutOperationIds {
            entries: Vec<BanEntry>,
            freshness: i64,
        }

        let channel_adapter = ChannelReplicationAdapter::new(
            DEFAULT_SERVER_ID.to_owned(),
            test_channel_repo(1),
            None,
        );
        let channel_snapshot = rmp_serde::to_vec_named(&ChannelSnapshotWithoutOperationIds {
            channels: Vec::new(),
            freshness: 0,
        })
        .expect("encode incomplete channel snapshot");
        assert!(
            channel_adapter
                .install_snapshot(1, Bytes::from(channel_snapshot))
                .await
                .is_err()
        );

        let ban_adapter = BanReplicationAdapter::new(BanRepository::new_in_memory(1));
        let ban_snapshot = rmp_serde::to_vec_named(&BanSnapshotWithoutOperationIds {
            entries: Vec::new(),
            freshness: 0,
        })
        .expect("encode incomplete ban snapshot");
        assert!(
            ban_adapter
                .install_snapshot(1, Bytes::from(ban_snapshot))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn v5_snapshot_adapters_preserve_legacy_repository_ledgers() {
        let channels = test_channel_repo(1);
        let channel_adapter = ChannelReplicationAdapter::new(
            DEFAULT_SERVER_ID.to_owned(),
            Arc::clone(&channels),
            None,
        );
        let mut local_channel_op = strict_channel_create_op(70);
        local_channel_op.version = 1;
        assert_eq!(
            channels
                .apply_strict_operation_once(
                    local_channel_op,
                    StrictReplicationMetadata::new(901, 902, 1),
                )
                .await
                .unwrap(),
            StrictOperationApplyOutcome::Applied
        );
        let channel_snapshot = rmp_serde::to_vec(&ChannelSnapshot {
            channels: vec![shitspeak_state::Channel::new(
                71,
                "replacement",
                0,
                0,
                Some(0),
            )],
            freshness: 124,
            strict_operation_ids: vec![StrictOperationId::new(903, 904)],
        })
        .expect("encode channel snapshot");
        channel_adapter
            .install_snapshot(1, Bytes::from(channel_snapshot))
            .await
            .unwrap();
        assert!(channels.get_channel(70).await.is_none());
        assert_eq!(channels.get_channel(71).await.unwrap().name, "replacement");
        assert_eq!(
            channels.strict_operation_ids(),
            vec![StrictOperationId::new(901, 902)]
        );

        let bans = BanRepository::new_in_memory(1);
        let ban_adapter = BanReplicationAdapter::new(Arc::clone(&bans));
        let mut local_ban_op = strict_ban_add_op("203.0.113.90");
        local_ban_op.version = 1;
        assert_eq!(
            bans.apply_strict_operation_once(
                Arc::new(local_ban_op),
                StrictReplicationMetadata::new(905, 906, 1),
            )
            .await
            .unwrap(),
            StrictOperationApplyOutcome::Applied
        );
        let ban_snapshot = rmp_serde::to_vec(&BanSnapshot {
            entries: vec![BanEntry {
                address: "203.0.113.91".parse().unwrap(),
                mask: 32,
                name: Some("replacement".to_owned()),
                hash: None,
                reason: None,
                start: 124,
                duration: 0,
            }],
            freshness: 124,
            strict_operation_ids: vec![StrictOperationId::new(907, 908)],
        })
        .expect("encode ban snapshot");
        ban_adapter
            .install_snapshot(1, Bytes::from(ban_snapshot))
            .await
            .unwrap();
        let active_bans = bans.get_active_bans().await;
        assert_eq!(active_bans.len(), 1);
        assert_eq!(
            active_bans[0].address,
            "203.0.113.91".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(
            bans.strict_operation_ids().unwrap(),
            vec![StrictOperationId::new(905, 906)]
        );
    }

    #[tokio::test]
    async fn channel_strict_snapshot_classifies_only_persistence_failures_as_durability_failures() {
        let storage_failure_dir = tempfile::tempdir().expect("storage failure tempdir");
        let storage_failure_repo = ChannelRepository::open(
            1,
            storage_failure_dir.path(),
            ChannelRootConfig::new("Root"),
            persisted_channel_tuning(),
        )
        .await
        .expect("open persisted channel repo");
        let storage_failure_adapter = ChannelReplicationAdapter::new(
            DEFAULT_SERVER_ID.to_owned(),
            Arc::clone(&storage_failure_repo),
            None,
        );
        std::fs::create_dir(
            storage_failure_dir
                .path()
                .join("channels.snapshot.json.tmp"),
        )
        .expect("block the replacement snapshot temp file");
        let snapshot = rmp_serde::to_vec(&ChannelSnapshot {
            channels: vec![shitspeak_state::Channel::new(
                7,
                "replacement",
                0,
                0,
                Some(0),
            )],
            freshness: 0,
            strict_operation_ids: Vec::new(),
        })
        .expect("encode replacement snapshot");

        let error = storage_failure_adapter
            .install_snapshot(1, Bytes::from(snapshot))
            .await
            .expect_err("snapshot persistence must fail");
        assert!(error.is_durability_failure());
        assert!(!storage_failure_repo.strict_operation_durability_enabled());

        let semantic_failure_dir = tempfile::tempdir().expect("semantic failure tempdir");
        let semantic_failure_repo = ChannelRepository::open(
            1,
            semantic_failure_dir.path(),
            ChannelRootConfig::new("Root"),
            persisted_channel_tuning(),
        )
        .await
        .expect("open persisted channel repo");
        let mut local_op = strict_channel_create_op(8);
        local_op.version = 1;
        assert_eq!(
            semantic_failure_repo
                .apply_strict_operation_once(
                    local_op,
                    StrictReplicationMetadata::new(901, 902, 903),
                )
                .await
                .expect("apply local strict operation"),
            StrictOperationApplyOutcome::Applied
        );
        let semantic_failure_adapter = ChannelReplicationAdapter::new(
            DEFAULT_SERVER_ID.to_owned(),
            Arc::clone(&semantic_failure_repo),
            None,
        );
        let semantic_snapshot = rmp_serde::to_vec(&ChannelSnapshot {
            channels: vec![shitspeak_state::Channel::new(
                9,
                "semantic-replacement",
                0,
                0,
                Some(0),
            )],
            freshness: 0,
            strict_operation_ids: Vec::new(),
        })
        .expect("encode semantic replacement snapshot");

        let error = semantic_failure_adapter
            .install_snapshot(1, Bytes::from(semantic_snapshot))
            .await
            .expect_err("snapshot without a local operation id must be rejected");
        assert!(!error.is_durability_failure());
        assert!(semantic_failure_repo.strict_operation_durability_enabled());
    }

    #[tokio::test]
    async fn channel_strict_adapter_fails_closed_on_current_thread_runtime() {
        let adapter = ChannelReplicationAdapter::new(
            DEFAULT_SERVER_ID.to_owned(),
            test_channel_repo(1),
            None,
        );

        assert!(adapter.snapshot().is_err());
        assert!(matches!(
            adapter.log_since(0),
            s2s_replications::strict::LogSlice::TooOld
        ));
    }

    #[tokio::test]
    async fn strict_production_adapters_fail_delivery_on_version_conflict() {
        let channels = test_channel_repo(1);
        channels
            .create_channel(shitspeak_state::Channel::new(70, "existing", 0, 0, Some(0)))
            .await
            .expect("create existing channel");
        let channel_adapter = ChannelReplicationAdapter::new(
            DEFAULT_SERVER_ID.to_owned(),
            Arc::clone(&channels),
            None,
        );
        assert_eq!(
            channel_adapter
                .apply_committed_once(
                    1,
                    strict_channel_create_op(71),
                    strict_log_metadata(1, 2, 3)
                )
                .await,
            s2s_replications::strict::StrictCommitApplyOutcome::Failed
        );

        let bans = BanRepository::new_in_memory(1);
        let mut existing_ban = strict_ban_add_op("203.0.113.70");
        existing_ban.version = 1;
        bans.apply_remote_operation(Arc::new(existing_ban)).await;
        let ban_adapter = BanReplicationAdapter::new(bans);
        assert_eq!(
            ban_adapter
                .apply_committed_once(
                    1,
                    strict_ban_add_op("203.0.113.71"),
                    strict_log_metadata(4, 5, 6)
                )
                .await,
            s2s_replications::strict::StrictCommitApplyOutcome::Failed
        );
    }

    #[tokio::test]
    async fn channel_replication_adapter_rejects_cross_scope_operations() {
        let channels = test_channel_repo(1);
        let adapter =
            ChannelReplicationAdapter::new("tenant-a".to_owned(), Arc::clone(&channels), None);
        let mut mismatched_op = strict_channel_create_op(72);
        mismatched_op.server_id = "tenant-b".to_owned();

        adapter.apply_committed(1, mismatched_op.clone()).await;
        assert_eq!(channels.current_version_in_server("tenant-a"), 0);
        assert_eq!(channels.current_version_in_server("tenant-b"), 0);
        assert!(
            channels
                .get_channel_in_server("tenant-b", 72)
                .await
                .is_none()
        );

        assert_eq!(
            adapter
                .apply_committed_once(1, mismatched_op, strict_log_metadata(7, 8, 9))
                .await,
            s2s_replications::strict::StrictCommitApplyOutcome::Failed
        );
        assert_eq!(channels.current_version_in_server("tenant-a"), 0);
        assert_eq!(channels.current_version_in_server("tenant-b"), 0);
        assert!(
            channels
                .get_channel_in_server("tenant-b", 72)
                .await
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn channel_v5_snapshot_transfer_survives_restart_without_repository_ledger_growth() {
        let source_dir = tempfile::tempdir().expect("source tempdir");
        let source_repo = ChannelRepository::open(
            1,
            source_dir.path(),
            ChannelRootConfig::new("Root"),
            persisted_channel_tuning(),
        )
        .await
        .expect("open source channel repo");
        let source = ChannelReplicationAdapter::new(
            DEFAULT_SERVER_ID.to_owned(),
            Arc::clone(&source_repo),
            None,
        );
        assert_eq!(
            source.strict_replication_protocol_version(),
            s2s_overlay::STRICT_REPLICATION_PROTOCOL_VERSION
        );
        let op = strict_channel_create_op(71);

        assert_eq!(
            source
                .apply_committed_once(1, op, strict_log_metadata(71, 72, 73))
                .await,
            s2s_replications::strict::StrictCommitApplyOutcome::Applied
        );
        assert!(source_repo.strict_operation_ids().is_empty());
        let (version, bytes) = source.snapshot().expect("capture channel snapshot");
        assert_eq!(version, 1);
        let decoded: ChannelSnapshot =
            rmp_serde::from_slice(&bytes).expect("decode channel snapshot");
        assert!(decoded.strict_operation_ids.is_empty());

        let sink_dir = tempfile::tempdir().expect("sink tempdir");
        {
            let sink_repo = ChannelRepository::open(
                2,
                sink_dir.path(),
                ChannelRootConfig::new("Root"),
                persisted_channel_tuning(),
            )
            .await
            .expect("open sink channel repo");
            let sink = ChannelReplicationAdapter::new(
                DEFAULT_SERVER_ID.to_owned(),
                Arc::clone(&sink_repo),
                None,
            );
            sink.install_snapshot(version, bytes)
                .await
                .expect("install channel snapshot");
            assert!(sink_repo.get_channel(71).await.is_some());
            assert!(matches!(
                sink.log_since(0),
                s2s_replications::strict::LogSlice::TooOld
            ));
        }

        let recovered_repo = ChannelRepository::open(
            2,
            sink_dir.path(),
            ChannelRootConfig::new("Root"),
            persisted_channel_tuning(),
        )
        .await
        .expect("reopen sink channel repo");
        let recovered = ChannelReplicationAdapter::new(
            DEFAULT_SERVER_ID.to_owned(),
            Arc::clone(&recovered_repo),
            None,
        );
        assert_eq!(recovered_repo.current_version(), version);
        assert!(recovered_repo.strict_operation_ids().is_empty());
        let next = strict_channel_create_op(72);
        assert_eq!(
            recovered
                .apply_committed_once(2, next, strict_log_metadata(74, 75, 76))
                .await,
            s2s_replications::strict::StrictCommitApplyOutcome::Applied
        );
        assert_eq!(recovered_repo.current_version(), 2);
        assert!(recovered_repo.strict_operation_ids().is_empty());
        assert_eq!(
            recovered_repo
                .get_channel(71)
                .await
                .expect("snapshot channel exists")
                .name,
            "strict-snapshot"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ban_v5_snapshot_transfer_survives_restart_without_repository_ledger_growth() {
        let source_dir = tempfile::tempdir().expect("source tempdir");
        let source_repo = BanRepository::open(1, source_dir.path())
            .await
            .expect("open source ban repo");
        let source = BanReplicationAdapter::new(Arc::clone(&source_repo));
        assert_eq!(
            source.strict_replication_protocol_version(),
            s2s_overlay::STRICT_REPLICATION_PROTOCOL_VERSION
        );
        let op = strict_ban_add_op("203.0.113.71");

        assert_eq!(
            source
                .apply_committed_once(1, op.clone(), strict_log_metadata(81, 82, 83))
                .await,
            s2s_replications::strict::StrictCommitApplyOutcome::Applied
        );
        assert!(source_repo.strict_operation_ids().unwrap().is_empty());
        let (version, bytes) = source.snapshot().expect("capture ban snapshot");
        assert_eq!(version, 1);
        let decoded: BanSnapshot = rmp_serde::from_slice(&bytes).expect("decode ban snapshot");
        assert!(decoded.strict_operation_ids.is_empty());

        let sink_dir = tempfile::tempdir().expect("sink tempdir");
        {
            let sink_repo = BanRepository::open(2, sink_dir.path())
                .await
                .expect("open sink ban repo");
            let sink = BanReplicationAdapter::new(Arc::clone(&sink_repo));
            sink.install_snapshot(version, bytes)
                .await
                .expect("install ban snapshot");
            assert_eq!(sink_repo.get_active_bans().await.len(), 1);
            assert!(matches!(
                sink.log_since(0),
                s2s_replications::strict::LogSlice::TooOld
            ));
        }

        let recovered_repo = BanRepository::open(2, sink_dir.path())
            .await
            .expect("reopen sink ban repo");
        let recovered = BanReplicationAdapter::new(Arc::clone(&recovered_repo));
        assert_eq!(recovered_repo.current_version(), version);
        assert_eq!(recovered_repo.get_active_bans().await.len(), 1);
        assert!(recovered_repo.strict_operation_ids().unwrap().is_empty());

        let next = strict_ban_add_op("203.0.113.72");
        assert_eq!(
            recovered
                .apply_committed_once(2, next, strict_log_metadata(84, 85, 86))
                .await,
            s2s_replications::strict::StrictCommitApplyOutcome::Applied
        );
        assert_eq!(recovered_repo.current_version(), 2);
        assert_eq!(recovered_repo.get_active_bans().await.len(), 2);
        assert!(recovered_repo.strict_operation_ids().unwrap().is_empty());
    }

    async fn make_published_web_client(
        repo: &ClientRepository,
        server_id: &str,
        port: u16,
        name: &str,
    ) -> Arc<Box<crate::client::Client>> {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let peer = SocketAddr::new(ip, port);
        let local = SocketAddr::new(ip, 64738);
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let client = repo
            .allocate_web_client_in_server(server_id, ip, peer, local, tx)
            .await;
        {
            let mut gs = client.write_global_state_direct();
            gs.set_display_name(Some(name.to_owned()));
            gs.set_user_id(Some(u32::from(port)));
        }
        repo.publish_client_in_server(server_id, client.get_session_id())
            .await;
        client
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn client_replication_initial_snapshot_contains_only_live_clients() {
        let clients = Arc::new(ClientRepository::new(1, 128));
        let channels = test_channel_repo(1);
        let adapter = ClientReplicationAdapter::new(Arc::clone(&clients), channels, 42);

        let old = make_published_web_client(&clients, DEFAULT_SERVER_ID, 30001, "old-user").await;
        let old_session = old.get_session_id();
        {
            let mut gs = old.write_global_state(&clients);
            gs.set_display_name(Some("old-user-renamed".to_owned()));
        }
        clients
            .remove_client_in_server(DEFAULT_SERVER_ID, old_session)
            .await;
        let live = make_published_web_client(&clients, DEFAULT_SERVER_ID, 30002, "live-user").await;

        assert!(matches!(
            adapter.log_for_origin(clients.local_node_id(), 0),
            s2s_replications::owner::LogSlice::Available(entries)
                if entries.first().map(|(version, _)| *version) == Some(1)
        ));

        let (_epoch, version, bytes) = adapter
            .snapshot_for_origin(clients.local_node_id())
            .expect("local origin snapshot is available");
        let decoded: ClientOriginSnapshot = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded.version, version);
        assert_eq!(decoded.entries.len(), 1);
        match &decoded.entries[0].op {
            ClientStateOperation::AddClient {
                session_id,
                client_instance_id,
                initial_state,
                ..
            } => {
                assert_eq!(*session_id, live.get_session_id());
                assert_eq!(*client_instance_id, live.client_instance_id());
                assert_eq!(
                    initial_state.display_name,
                    Some(Some("live-user".to_owned()))
                );
            }
            other => panic!("expected live AddClient snapshot entry, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn client_replication_snapshot_install_does_not_replay_old_activity_trail() {
        let origin_clients = Arc::new(ClientRepository::new(1, 128));
        let origin_channels = test_channel_repo(1);
        let origin_adapter =
            ClientReplicationAdapter::new(Arc::clone(&origin_clients), origin_channels, 42);

        let old =
            make_published_web_client(&origin_clients, DEFAULT_SERVER_ID, 30101, "old-user").await;
        let old_session = old.get_session_id();
        let old_instance_id = old.client_instance_id();
        {
            let mut gs = old.write_global_state(&origin_clients);
            gs.set_display_name(Some("old-user-renamed".to_owned()));
        }
        origin_clients
            .remove_client_in_server(DEFAULT_SERVER_ID, old_session)
            .await;
        let live =
            make_published_web_client(&origin_clients, DEFAULT_SERVER_ID, 30102, "live-user").await;
        let (_epoch, version, bytes) = origin_adapter
            .snapshot_for_origin(origin_clients.local_node_id())
            .expect("local origin snapshot is available");

        let peer_clients = Arc::new(ClientRepository::new(2, 128));
        let peer_channels = test_channel_repo(2);
        let peer_adapter =
            ClientReplicationAdapter::new(Arc::clone(&peer_clients), peer_channels, 77);
        let mut rx = peer_clients.subscribe();

        peer_adapter
            .install_snapshot_for_origin(origin_clients.local_node_id(), 42, version, bytes)
            .await
            .expect("valid client snapshot installs");

        let snapshot_start = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("snapshot should broadcast reset start")
            .expect("snapshot broadcast channel open");
        assert!(matches!(
            snapshot_start.entry.op,
            ClientStateOperation::ResetNode { .. }
        ));
        assert_eq!(snapshot_start.versions.get(&1), Some(&0));
        let snapshot_message = rx.recv().await.expect("snapshot AddClient");
        assert!(matches!(
            snapshot_message.entry.op,
            ClientStateOperation::AddClient { .. }
        ));
        let snapshot_marker = rx.recv().await.expect("snapshot version marker");
        assert_eq!(snapshot_marker.versions.get(&1), Some(&version));
        assert!(matches!(
            snapshot_marker.entry.op,
            ClientStateOperation::ResetNode { .. }
        ));
        assert!(rx.try_recv().is_err());

        let replicated_live = peer_clients
            .get_client_in_server(DEFAULT_SERVER_ID, live.get_session_id())
            .await
            .expect("live client should be installed from snapshot");
        assert_eq!(old_session, live.get_session_id());
        assert_ne!(replicated_live.client_instance_id(), old_instance_id);
        assert_eq!(
            replicated_live.display_name_opt().as_deref(),
            Some("live-user")
        );

        assert!(
            peer_clients
                .replay_since_in_server(DEFAULT_SERVER_ID, &HashMap::new())
                .await
                .is_err(),
            "synthetic snapshot baseline is not incremental replay history"
        );
        let (messages, _) = peer_clients
            .replay_since_in_server(
                DEFAULT_SERVER_ID,
                &HashMap::from([(origin_clients.local_node_id(), version)]),
            )
            .await
            .expect("replay from the installed snapshot floor succeeds");
        assert!(messages.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn client_replication_empty_snapshot_advances_origin_without_user_messages() {
        let origin_clients = Arc::new(ClientRepository::new(1, 128));
        let origin_channels = test_channel_repo(1);
        let origin_adapter =
            ClientReplicationAdapter::new(Arc::clone(&origin_clients), origin_channels, 42);

        let old =
            make_published_web_client(&origin_clients, DEFAULT_SERVER_ID, 30201, "old-user").await;
        origin_clients
            .remove_client_in_server(DEFAULT_SERVER_ID, old.get_session_id())
            .await;
        let (_epoch, version, bytes) = origin_adapter
            .snapshot_for_origin(origin_clients.local_node_id())
            .expect("local origin snapshot is available");
        let decoded: ClientOriginSnapshot = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded.version, version);
        assert!(decoded.entries.is_empty());
        assert!(version > 0);

        let peer_clients = Arc::new(ClientRepository::new(2, 128));
        let peer_channels = test_channel_repo(2);
        let peer_adapter =
            ClientReplicationAdapter::new(Arc::clone(&peer_clients), peer_channels, 77);
        let mut rx = peer_clients.subscribe();

        peer_adapter
            .install_snapshot_for_origin(origin_clients.local_node_id(), 42, version, bytes)
            .await
            .expect("valid empty client snapshot installs");

        let snapshot_start = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("snapshot should broadcast reset start")
            .expect("snapshot broadcast channel open");
        assert!(matches!(
            snapshot_start.entry.op,
            ClientStateOperation::ResetNode { .. }
        ));
        assert_eq!(snapshot_start.versions.get(&1), Some(&0));
        let snapshot_marker = rx.recv().await.expect("snapshot version marker");
        assert_eq!(snapshot_marker.versions.get(&1), Some(&version));
        assert!(rx.try_recv().is_err());

        assert!(
            peer_clients
                .replay_since_in_server(DEFAULT_SERVER_ID, &HashMap::new())
                .await
                .is_err()
        );
        let (messages, _) = peer_clients
            .replay_since_in_server(
                DEFAULT_SERVER_ID,
                &HashMap::from([(origin_clients.local_node_id(), version)]),
            )
            .await
            .expect("replay from empty snapshot floor succeeds");
        assert!(messages.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn client_replication_reports_empty_local_epoch_and_materialized_remote_versions() {
        let clients = Arc::new(ClientRepository::new(2, 128));
        let adapter = ClientReplicationAdapter::new(Arc::clone(&clients), test_channel_repo(2), 77);

        assert_eq!(adapter.known_versions(), HashMap::from([(2, (77, 0))]));

        clients.reset_clients_from_node(1, 42).await;
        assert_eq!(
            adapter.known_versions(),
            HashMap::from([(1, (42, 0)), (2, (77, 0))])
        );
        clients.remove_clients_from_node(1).await;
        assert_eq!(adapter.known_versions(), HashMap::from([(2, (77, 0))]));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn client_snapshot_defers_atomically_then_installs_and_relays_canonically() {
        let origin_clients = Arc::new(ClientRepository::new(1, 128));
        let origin_adapter =
            ClientReplicationAdapter::new(Arc::clone(&origin_clients), test_channel_repo(1), 42);
        let live =
            make_published_web_client(&origin_clients, DEFAULT_SERVER_ID, 30301, "dependent-user")
                .await;
        {
            let mut state = live.write_global_state(&origin_clients);
            state.set_current_channel_id(42);
        }
        let (_, version, bytes) = origin_adapter
            .snapshot_for_origin(1)
            .expect("origin snapshot available");
        let mut decoded: ClientOriginSnapshot = rmp_serde::from_slice(&bytes).unwrap();
        assert!(
            decoded
                .entries
                .iter()
                .all(|entry| entry.channel_version_dep == Some(0)),
            "snapshot provider stamps its source channel version"
        );
        for entry in &mut decoded.entries {
            entry.channel_version_dep = Some(1);
        }
        let dependent_bytes = Bytes::from(rmp_serde::to_vec(&decoded).unwrap());

        let peer_clients = Arc::new(ClientRepository::new(2, 128));
        let peer_channels = test_channel_repo(2);
        let peer_adapter = ClientReplicationAdapter::new(
            Arc::clone(&peer_clients),
            Arc::clone(&peer_channels),
            77,
        );
        assert_eq!(
            peer_adapter
                .install_snapshot_for_origin(1, 42, version, dependent_bytes.clone())
                .await
                .unwrap(),
            OwnerSnapshotInstallOutcome::Deferred
        );
        assert_eq!(
            peer_adapter
                .snapshot_deferrals
                .status(1)
                .map(|status| status.1),
            Some(42),
            "recipient tracks the deferred snapshot epoch"
        );
        assert!(
            peer_adapter
                .install_snapshot_for_origin(1, 42, version, Bytes::from_static(b"invalid"))
                .await
                .is_err()
        );
        assert_eq!(
            peer_adapter.snapshot_deferrals.status(1),
            None,
            "rejecting a snapshot clears its deferral watchdog"
        );
        assert_eq!(
            peer_adapter
                .install_snapshot_for_origin(1, 42, version, dependent_bytes.clone())
                .await
                .unwrap(),
            OwnerSnapshotInstallOutcome::Deferred
        );
        assert!(
            peer_clients
                .get_client(live.get_session_id())
                .await
                .is_none()
        );
        assert!(!peer_adapter.known_versions().contains_key(&1));

        let mut channel_snapshot = peer_channels
            .get_all()
            .await
            .into_iter()
            .map(|channel| channel.as_ref().clone())
            .collect::<Vec<_>>();
        channel_snapshot.push(shitspeak_state::Channel::new(42, "ready", 0, 0, Some(0)));
        peer_channels
            .install_s2s_snapshot(1, channel_snapshot)
            .await
            .unwrap();
        assert_eq!(
            peer_adapter
                .install_snapshot_for_origin(1, 42, version, dependent_bytes.clone())
                .await
                .unwrap(),
            OwnerSnapshotInstallOutcome::Installed
        );
        assert_eq!(
            peer_adapter.snapshot_deferrals.status(1),
            None,
            "installing the snapshot clears its deferral watchdog"
        );
        let replicated = peer_clients
            .get_client(live.get_session_id())
            .await
            .expect("deferred snapshot installs after channel convergence");
        assert_eq!(replicated.get_current_channel_id(), 42);
        assert_eq!(peer_adapter.known_versions().get(&1), Some(&(42, version)));

        let (relay_epoch, relay_version, relay_bytes) = peer_adapter
            .snapshot_for_origin(1)
            .expect("materialized remote origin can be relayed");
        assert_eq!((relay_epoch, relay_version), (42, version));
        let relay: ClientOriginSnapshot = rmp_serde::from_slice(&relay_bytes).unwrap();
        assert_eq!(relay.version, version);
        assert_eq!(relay.entries.len(), 1);
        assert_eq!(relay.entries[0].channel_version_dep, Some(1));
        assert!(matches!(
            peer_adapter.log_for_origin(1, 0),
            s2s_replications::owner::LogSlice::TooOld
        ));
        assert!(matches!(
            peer_adapter.log_for_origin(1, version),
            s2s_replications::owner::LogSlice::Available(entries) if entries.is_empty()
        ));

        assert!(
            peer_adapter
                .install_snapshot_for_origin(1, 42, version + 1, dependent_bytes.clone())
                .await
                .is_err(),
            "envelope/embedded version mismatch is rejected"
        );
        if version > 1 {
            let mut regressive = decoded.clone();
            regressive.version = version - 1;
            assert!(
                peer_adapter
                    .install_snapshot_for_origin(
                        1,
                        42,
                        regressive.version,
                        Bytes::from(rmp_serde::to_vec(&regressive).unwrap()),
                    )
                    .await
                    .is_err(),
                "same-epoch snapshot cannot roll the materialized version backward"
            );
        }
        let mut stale_epoch = decoded.clone();
        stale_epoch.version = version + 1;
        assert!(
            peer_adapter
                .install_snapshot_for_origin(
                    1,
                    41,
                    stale_epoch.version,
                    Bytes::from(rmp_serde::to_vec(&stale_epoch).unwrap()),
                )
                .await
                .is_err(),
            "older-epoch snapshot is fenced"
        );

        let mut malformed = relay;
        malformed.version += 1;
        malformed.entries[0].op = ClientStateOperation::ResetNode {
            server_id: DEFAULT_SERVER_ID.to_owned(),
        };
        assert!(
            peer_adapter
                .install_snapshot_for_origin(
                    1,
                    42,
                    malformed.version,
                    Bytes::from(rmp_serde::to_vec(&malformed).unwrap()),
                )
                .await
                .is_err()
        );
        assert!(
            peer_clients
                .get_client(live.get_session_id())
                .await
                .is_some()
        );
        assert_eq!(peer_adapter.known_versions().get(&1), Some(&(42, version)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn client_snapshot_replacement_publishes_global_reset_adds_and_final_vector() {
        let origin_clients = Arc::new(ClientRepository::new(1, 128));
        let origin_adapter =
            ClientReplicationAdapter::new(Arc::clone(&origin_clients), test_channel_repo(1), 42);
        let live =
            make_published_web_client(&origin_clients, DEFAULT_SERVER_ID, 30401, "removed-user")
                .await;
        let (_, version, bytes) = origin_adapter.snapshot_for_origin(1).unwrap();
        let mut replacement: ClientOriginSnapshot = rmp_serde::from_slice(&bytes).unwrap();

        let peer_clients = Arc::new(ClientRepository::new(2, 128));
        let peer_adapter =
            ClientReplicationAdapter::new(Arc::clone(&peer_clients), test_channel_repo(2), 77);
        peer_adapter
            .install_snapshot_for_origin(1, 42, version, bytes)
            .await
            .unwrap();
        let mut rx = peer_clients.subscribe();
        replacement.version = version + 1;
        let ClientStateOperation::AddClient {
            client_instance_id, ..
        } = &mut replacement.entries[0].op
        else {
            unreachable!()
        };
        *client_instance_id = client_instance_id.saturating_add(1);
        let replacement_version = replacement.version;
        peer_adapter
            .install_snapshot_for_origin(
                1,
                42,
                replacement_version,
                Bytes::from(rmp_serde::to_vec(&replacement).unwrap()),
            )
            .await
            .unwrap();

        let identity_start = rx.recv().await.unwrap();
        assert_eq!(identity_start.versions.get(&1), Some(&0));
        assert!(matches!(
            identity_start.entry.op,
            ClientStateOperation::ResetNode { .. }
        ));
        let identity_add = rx.recv().await.unwrap();
        assert_eq!(identity_add.versions.get(&1), Some(&0));
        assert!(matches!(
            identity_add.entry.op,
            ClientStateOperation::AddClient { .. }
        ));
        let identity_marker = rx.recv().await.unwrap();
        assert_eq!(identity_marker.versions.get(&1), Some(&replacement_version));
        assert!(matches!(
            identity_marker.entry.op,
            ClientStateOperation::ResetNode { .. }
        ));
        assert!(rx.try_recv().is_err());

        let empty_version = replacement_version + 1;
        let empty = Bytes::from(
            rmp_serde::to_vec(&ClientOriginSnapshot {
                version: empty_version,
                entries: Vec::new(),
            })
            .unwrap(),
        );
        assert_eq!(
            peer_adapter
                .install_snapshot_for_origin(1, 42, empty_version, empty.clone())
                .await
                .unwrap(),
            OwnerSnapshotInstallOutcome::Installed
        );
        assert!(
            peer_clients
                .get_client(live.get_session_id())
                .await
                .is_none()
        );

        let empty_start = rx.recv().await.unwrap();
        assert_eq!(empty_start.versions.get(&1), Some(&0));
        assert!(matches!(
            empty_start.entry.op,
            ClientStateOperation::ResetNode { .. }
        ));
        let empty_end = rx.recv().await.unwrap();
        assert_eq!(empty_end.versions.get(&1), Some(&empty_version));
        assert!(matches!(
            empty_end.entry.op,
            ClientStateOperation::ResetNode { .. }
        ));
        assert!(rx.try_recv().is_err());

        peer_adapter
            .install_snapshot_for_origin(1, 42, empty_version, empty)
            .await
            .unwrap();
        assert!(
            rx.try_recv().is_err(),
            "duplicate snapshot is side-effect free"
        );
    }
}
