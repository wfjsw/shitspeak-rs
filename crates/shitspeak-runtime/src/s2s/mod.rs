use std::collections::{BTreeSet, HashMap, HashSet, hash_map::Entry};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use prost::Message as ProstMessage;
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, Semaphore, broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

use crate::ban_repository::{BanEntry, BanOp, BanOperation, BanRepository};
use crate::blob_store::ChannelBlobStore;
use crate::channel_repository::{ChannelOp, ChannelOperation, ChannelRepository};
use crate::client::client_session_identifier::ClientSessionIdentifier;
use crate::client::state_log::{ClientGlobalStateDelta, ClientStateLogEntry, ClientStateOperation};
use crate::client_repository::ClientRepository;
use crate::geoip::NodeGeo;
use crate::server::Server;
use crate::types::{DEFAULT_SERVER_ID, NodeIdentifier, StrictReplicationMetadata};

use shitspeak_s2s::application as s2s_application;
use shitspeak_s2s::application::error::ApplicationError;
use shitspeak_s2s::application::moderation::ModerationApplier;
use shitspeak_s2s::application::proto::{
    ModerationCommand, ModerationEnvelope, PluginDataEnvelope, TextMessageEnvelope,
    UserRemovePatch, UserStatePatch, UserStatsReply, VoiceFrame, VoiceIntent,
};
use shitspeak_s2s::application::voice::{AudioSink, RecipientIndex};
use shitspeak_s2s::overlay as s2s_overlay;
use shitspeak_s2s::overlay::OverlayNetwork;
use shitspeak_s2s::replications as s2s_replications;
use shitspeak_s2s::replications::{
    BlobReplicable, OwnerReplicable, ReplicationManager, StrictReplicable,
};
use shitspeak_s2s::status as s2s_status;
#[cfg(test)]
use shitspeak_s2s::testing as s2s_testing;
use shitspeak_s2s_transport as s2s_transport;
use shitspeak_s2s_transport::{ConnectionManager, TransportConfig};

const S2S_CLIENT_REPLICATION_WORKER_CAPACITY: usize = 4096;
const S2S_CLIENT_REPLICATION_MAX_IN_FLIGHT: usize = 256;
const S2S_GATEWAY_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const STRICT_PROPOSAL_GATEWAY_SLACK_TICKS: u32 = 4;
const VOICE_RECIPIENT_INDEX_REFRESH_INTERVAL: Duration = Duration::from_millis(100);
const S2S_CHANNEL_REPLICATION_SLOW_STAGE: Duration = Duration::from_secs(1);
const S2S_CLIENT_REPLICATION_SLOW_PROPOSE: Duration = Duration::from_secs(1);
const S2S_CLIENT_REPLICATION_SLOW_QUEUE_WAIT: Duration = Duration::from_millis(250);
const S2S_GATEWAY_MEMORY_FRACTION_DIVISOR: u64 = 20;
const S2S_GATEWAY_MIN_BUDGET_BYTES: u64 = 16 * 1024 * 1024;
const S2S_GATEWAY_FALLBACK_BUDGET_BYTES: u64 = 64 * 1024 * 1024;
const S2S_GATEWAY_MAX_BUDGET_BYTES: u64 = 512 * 1024 * 1024;
const S2S_GATEWAY_COMMAND_OVERHEAD_BYTES: usize = 512;
const S2S_GATEWAY_CONTROL_MIN_BYTES: usize = 1024 * 1024;
const S2S_GATEWAY_LANE_MIN_BYTES: usize = 512 * 1024;

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
    local_geo: Option<NodeGeo>,
    max_users: Arc<AtomicU64>,
    state: RwLock<S2SRuntimeState>,
}

#[derive(Default)]
struct S2SRuntimeState {
    transport: Option<ConnectionManager>,
    overlay: Option<OverlayNetwork>,
    local_geo: Option<NodeGeo>,
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
    #[cfg(test)]
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
    RefreshVoiceRecipientIndex(HashMap<u32, BTreeSet<NodeIdentifier>>),
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
            Self::SendVoiceForChannel { .. } | Self::SendVoiceBroadcast { .. } => {
                S2SGatewayClass::Voice
            }
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
            Self::SendVoiceForChannel { .. } | Self::SendVoiceBroadcast { .. } => "voice",
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

fn estimate_recipient_index_snapshot(snapshot: &HashMap<u32, BTreeSet<NodeIdentifier>>) -> usize {
    snapshot
        .values()
        .map(|nodes| {
            S2S_GATEWAY_COMMAND_OVERHEAD_BYTES.saturating_add(
                nodes
                    .len()
                    .saturating_mul(std::mem::size_of::<NodeIdentifier>()),
            )
        })
        .sum::<usize>()
        .max(S2S_GATEWAY_COMMAND_OVERHEAD_BYTES)
}

#[derive(Clone)]
struct S2SQueueBudget {
    inner: Arc<S2SQueueBudgetInner>,
}

struct S2SQueueBudgetInner {
    max_bytes: usize,
    used_bytes: AtomicUsize,
    notify: Notify,
}

impl S2SQueueBudget {
    fn auto() -> Self {
        Self::new(auto_s2s_gateway_budget_bytes())
    }

    fn new(max_bytes: usize) -> Self {
        Self {
            inner: Arc::new(S2SQueueBudgetInner {
                max_bytes: max_bytes.max(S2S_GATEWAY_LANE_MIN_BYTES),
                used_bytes: AtomicUsize::new(0),
                notify: Notify::new(),
            }),
        }
    }

    fn split(&self, max_bytes: usize) -> S2SQueueLaneBudget {
        S2SQueueLaneBudget {
            global: self.clone(),
            max_bytes: max_bytes.max(S2S_GATEWAY_LANE_MIN_BYTES),
            used_bytes: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[derive(Clone)]
struct S2SQueueLaneBudget {
    global: S2SQueueBudget,
    max_bytes: usize,
    used_bytes: Arc<AtomicUsize>,
}

impl S2SQueueLaneBudget {
    async fn reserve(&self, bytes: usize) -> Option<S2SQueuePermit> {
        let bytes = bytes.max(1);
        if bytes > self.max_bytes || bytes > self.global.inner.max_bytes {
            return None;
        }
        loop {
            if let Some(permit) = self.try_reserve(bytes) {
                return Some(permit);
            }
            self.global.inner.notify.notified().await;
        }
    }

    fn try_reserve(&self, bytes: usize) -> Option<S2SQueuePermit> {
        let bytes = bytes.max(1);
        if bytes > self.max_bytes || bytes > self.global.inner.max_bytes {
            return None;
        }
        try_add_with_limit(&self.used_bytes, bytes, self.max_bytes)?;
        if try_add_with_limit(
            &self.global.inner.used_bytes,
            bytes,
            self.global.inner.max_bytes,
        )
        .is_none()
        {
            self.used_bytes.fetch_sub(bytes, Ordering::Release);
            return None;
        }
        Some(S2SQueuePermit {
            lane: self.clone(),
            bytes,
        })
    }

    #[cfg(test)]
    fn available_bytes(&self) -> usize {
        self.max_bytes
            .saturating_sub(self.used_bytes.load(Ordering::Acquire))
    }
}

struct S2SQueuePermit {
    lane: S2SQueueLaneBudget,
    bytes: usize,
}

impl Drop for S2SQueuePermit {
    fn drop(&mut self) {
        self.lane
            .used_bytes
            .fetch_sub(self.bytes, Ordering::Release);
        self.lane
            .global
            .inner
            .used_bytes
            .fetch_sub(self.bytes, Ordering::Release);
        self.lane.global.inner.notify.notify_waiters();
    }
}

struct S2SQueued<T> {
    command: T,
    _permit: S2SQueuePermit,
}

fn try_add_with_limit(counter: &AtomicUsize, add: usize, limit: usize) -> Option<()> {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let next = current.checked_add(add)?;
        if next > limit {
            return None;
        }
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(()),
            Err(actual) => current = actual,
        }
    }
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
        let max = budget.inner.max_bytes;
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
        let max = budget.inner.max_bytes;
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

struct S2SAdaptiveSender<T> {
    tx: mpsc::UnboundedSender<S2SQueued<T>>,
    budget: S2SQueueLaneBudget,
}

struct S2SAdaptiveReceiver<T> {
    rx: mpsc::UnboundedReceiver<S2SQueued<T>>,
}

impl<T> Clone for S2SAdaptiveSender<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            budget: self.budget.clone(),
        }
    }
}

impl<T> S2SAdaptiveSender<T>
where
    T: EstimatedS2SCommand,
{
    fn new(budget: S2SQueueLaneBudget) -> (Self, S2SAdaptiveReceiver<T>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx, budget }, S2SAdaptiveReceiver { rx })
    }

    async fn send(&self, command: T) -> bool {
        let label = command.label();
        let Some(permit) = self.budget.reserve(command.estimated_bytes()).await else {
            warn!(
                label,
                "s2s gateway command exceeds adaptive queue budget; dropping command"
            );
            return false;
        };
        match self.tx.send(S2SQueued {
            command,
            _permit: permit,
        }) {
            Ok(()) => true,
            Err(_) => {
                trace!(label, "s2s gateway closed; dropping command");
                false
            }
        }
    }

    fn try_send(&self, command: T) -> bool {
        let label = command.label();
        let Some(permit) = self.budget.try_reserve(command.estimated_bytes()) else {
            warn!(label, "s2s gateway full; dropping command");
            return false;
        };
        match self.tx.send(S2SQueued {
            command,
            _permit: permit,
        }) {
            Ok(()) => true,
            Err(_) => {
                trace!(label, "s2s gateway closed; dropping command");
                false
            }
        }
    }
}

impl<T> S2SAdaptiveReceiver<T> {
    async fn recv(&mut self) -> Option<T> {
        self.rx.recv().await.map(|queued| queued.command)
    }
}

trait EstimatedS2SCommand {
    fn label(&self) -> &'static str;

    fn estimated_bytes(&self) -> usize;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum ChannelOpProposeResult {
    Proposed,
    Unavailable,
    Failed,
}

impl ChannelOpProposeResult {
    pub fn is_proposed(self) -> bool {
        matches!(self, Self::Proposed)
    }

    pub fn should_apply_locally(self) -> bool {
        matches!(self, Self::Unavailable)
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
            return ChannelOpProposeResult::Failed;
        };
        match tokio::time::timeout(self.timeout, accepted).await {
            Ok(Ok(())) => ChannelOpProposeResult::Proposed,
            Ok(Err(_)) => match self.wait_completed(self.timeout).await {
                ChannelOpCompletion::Completed(result) => result,
                ChannelOpCompletion::Pending => {
                    error!("s2s channel proposal timed out waiting for gateway response");
                    ChannelOpProposeResult::Failed
                }
            },
            Err(_) => {
                error!("s2s channel proposal timed out waiting for acceptance");
                ChannelOpProposeResult::Failed
            }
        }
    }

    pub async fn completed(mut self) -> ChannelOpProposeResult {
        match self.wait_completed(self.timeout).await {
            ChannelOpCompletion::Completed(result) => result,
            ChannelOpCompletion::Pending => {
                error!("s2s channel proposal timed out waiting for gateway response");
                ChannelOpProposeResult::Failed
            }
        }
    }

    pub async fn completed_after_acceptance(mut self) -> ChannelOpProposeResult {
        let Some(completed) = self.completed.take() else {
            return ChannelOpProposeResult::Failed;
        };
        match completed.await {
            Ok(result) => result,
            Err(_) => {
                error!("s2s gateway dropped accepted channel proposal response");
                ChannelOpProposeResult::Failed
            }
        }
    }

    pub async fn wait_completed_for(&mut self, timeout: Duration) -> ChannelOpCompletion {
        self.wait_completed(timeout).await
    }

    async fn wait_completed(&mut self, timeout: Duration) -> ChannelOpCompletion {
        let Some(completed) = self.completed.as_mut() else {
            return ChannelOpCompletion::Completed(ChannelOpProposeResult::Failed);
        };
        match tokio::time::timeout(timeout, completed).await {
            Ok(Ok(result)) => {
                self.completed = None;
                ChannelOpCompletion::Completed(result)
            }
            Ok(Err(_)) => {
                self.completed = None;
                error!("s2s gateway dropped channel proposal response");
                ChannelOpCompletion::Completed(ChannelOpProposeResult::Failed)
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
    pub fn initialize(config: &crate::config::Config) -> Self {
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
            local_geo: config.s2s.geo.manual_geo(),
            max_users: Arc::new(AtomicU64::new(config.max_users)),
            state: RwLock::new(S2SRuntimeState::default()),
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
        self.overlay_tuning.apply(cfg)
    }

    /// Resolved replication tunables, ready to hand to
    /// [`s2s_replications::ReplicationManager::with_config`].
    pub fn replication_config(&self) -> &s2s_replications::ReplicationConfig {
        &self.replication_config
    }

    pub fn prometheus_metrics_text(&self) -> Option<String> {
        let state = self.state.read();
        let overlay = state.overlay.as_ref()?;
        let transport = state.transport.as_ref()?;
        Some(s2s_status::render_prometheus_metrics(
            overlay,
            transport,
            state.local_geo.clone(),
        ))
    }

    pub(crate) fn prometheus_samples(&self) -> Option<Vec<s2s_status::PrometheusSample>> {
        let state = self.state.read();
        let overlay = state.overlay.as_ref()?;
        let transport = state.transport.as_ref()?;
        Some(s2s_status::prometheus_samples(
            overlay,
            transport,
            state.local_geo.clone(),
        ))
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
        let app = s2s_application::ApplicationLayer::new(
            overlay.clone(),
            self.application_config.clone(),
        );
        let mut state = self.state.write();
        state.overlay = Some(overlay);
        state.local_geo = self.local_geo.clone();
        state.replications = Some(repl);
        state.application = Some(app);
    }

    pub fn overlay(&self) -> Option<OverlayNetwork> {
        self.state.read().overlay.clone()
    }

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
                return ChannelOpProposeResult::Failed;
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
                    if let Some(mut accepted_rx) = proposal.take_accepted_receiver() {
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
                        error!(
                            server_id,
                            op_kind,
                            channel_id = ?channel_id,
                            elapsed_ms = started_at.elapsed().as_millis(),
                            error = %e,
                            "s2s channel op propose failed"
                        );
                        ChannelOpProposeResult::Failed
                    }
                }
            }
            Err(e) => {
                error!(
                    server_id,
                    op_kind,
                    channel_id = ?channel_id,
                    elapsed_ms = started_at.elapsed().as_millis(),
                    error = %e,
                    "s2s channel op propose failed"
                );
                ChannelOpProposeResult::Failed
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
            return false;
        };
        tx.try_send_voice(NativeToS2SCommand::SendVoiceForChannel {
            sender_session,
            server_id,
            source_channel,
            is_terminator,
            payload,
        })
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
            return false;
        };
        tx.try_send_voice(NativeToS2SCommand::SendVoiceBroadcast {
            sender_session,
            server_id,
            target_kind,
            is_terminator,
            payload,
            intent,
        })
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
        let gateway_budget = S2SQueueBudget::auto();
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
        #[cfg(test)]
        let inbound = {
            let chaos = self.state.read().inbound_chaos.clone();
            if let Some(chaos) = chaos {
                chaos.install(inbound)
            } else {
                inbound
            }
        };

        let local_geo = resolve_observability_geo(self.local_geo.clone()).await;

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
        let application = s2s_application::ApplicationLayer::new(
            overlay.clone(),
            self.application_config.clone(),
        );
        let recipient_index = RecipientIndex::new();
        let server_handle = server.upgrade();
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

        {
            let mut state = self.state.write();
            state.transport = Some(transport.clone());
            state.overlay = Some(overlay.clone());
            state.local_geo = local_geo.clone();
            state.replications = Some(replications.clone());
            state.application = Some(application.clone());
            state.recipient_index = Some(recipient_index);
            state.server = Some(server.clone());
            state.channel_replications = channel_replications;
            state.ban_replication = ban_replication;
            state.client_replication = client_replication;
            state.channel_blob_replications = channel_blob_replications;
            state.bridge_tasks = bridge_tasks;
        }

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
            ));
        } else {
            bridge_tasks.push(spawn_s2s_gateway_receiver(
                s2s_rx,
                manager,
                application,
                None,
                recipient_index.clone(),
            ));
        }
        if voice_delivery_strategy == s2s_application::DeliveryStrategy::Targeted {
            bridge_tasks.push(spawn_native_voice_recipient_index_bridge(
                native_runtime,
                server.get_clients().clone(),
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
                let runtime = replications
                    .strict_topic_parts()
                    .build_runtime(topic.clone(), repo);
                runtime.start();
                replications.install_strict_runtime(topic, runtime.clone())?;
                let handle = s2s_replications::StrictHandle::with_runtime(runtime);
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

pub async fn resolve_observability_geo(configured_geo: Option<NodeGeo>) -> Option<NodeGeo> {
    if configured_geo.is_some() {
        return configured_geo;
    }
    shitspeak_s2s_transport::discover_public_geo().await
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
    tx: S2SGatewayTx,
    mut shutdown: watch::Receiver<()>,
) -> JoinHandle<()> {
    let mut rx = repo.subscribe();
    runtime.spawn(async move {
        enqueue_voice_recipient_index_snapshot(&repo, &tx).await;
        let mut dirty = false;
        let mut refresh = tokio::time::interval(VOICE_RECIPIENT_INDEX_REFRESH_INTERVAL);
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        refresh.tick().await;
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = refresh.tick(), if dirty => {
                    dirty = false;
                    enqueue_voice_recipient_index_snapshot(&repo, &tx).await;
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
    if entry.op.server_id() != DEFAULT_SERVER_ID {
        return false;
    }

    match &entry.op {
        ClientStateOperation::AddClient { .. } | ClientStateOperation::RemoveClient { .. } => true,
        ClientStateOperation::UpdateGlobalState { delta, .. } => {
            delta.current_channel_id.is_some()
                || delta
                    .listening_channel_add
                    .as_ref()
                    .is_some_and(|channels| !channels.is_empty())
                || delta
                    .listening_channel_remove
                    .as_ref()
                    .is_some_and(|channels| !channels.is_empty())
        }
        ClientStateOperation::ResetNode { .. } => true,
    }
}

async fn enqueue_voice_recipient_index_snapshot(repo: &Arc<ClientRepository>, tx: &S2SGatewayTx) {
    let snapshot = repo.voice_recipient_index_snapshot().await;
    if !tx.try_send_coalesced(NativeToS2SCommand::RefreshVoiceRecipientIndex(snapshot)) {
        warn!("s2s voice recipient index gateway full; dropping snapshot");
    }
}

fn spawn_s2s_gateway_receiver(
    rx: S2SGatewayRx,
    manager: Arc<S2SManager>,
    application: Arc<s2s_application::ApplicationLayer>,
    client_handle: Option<s2s_replications::OwnerHandle<ClientReplicationAdapter>>,
    recipient_index: Arc<RecipientIndex>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let client_proposal_tx = spawn_client_replication_proposal_worker(
            client_handle,
            S2S_CLIENT_REPLICATION_WORKER_CAPACITY,
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
    client_proposal_tx: mpsc::Sender<QueuedClientReplicationProposal>,
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
    mut rx: S2SAdaptiveReceiver<NativeToS2SCommand>,
    application: Arc<s2s_application::ApplicationLayer>,
) {
    let permits = Arc::new(Semaphore::new(default_s2s_voice_gateway_concurrency()));
    while let Some(command) = rx.recv().await {
        let Ok(permit) = permits.clone().acquire_owned().await else {
            return;
        };
        let application = application.clone();
        tokio::spawn(async move {
            let _permit = permit;
            run_s2s_voice_command(application, command).await;
        });
    }
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
            NativeToS2SCommand::RefreshVoiceRecipientIndex(snapshot) => {
                recipient_index.replace_all(snapshot);
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

fn default_s2s_voice_gateway_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .saturating_mul(4)
        .clamp(4, 64)
}

struct QueuedClientReplicationProposal {
    entry: ClientStateLogEntry,
    enqueued_at: Instant,
}

fn spawn_client_replication_proposal_worker(
    client_handle: Option<s2s_replications::OwnerHandle<ClientReplicationAdapter>>,
    capacity: usize,
) -> mpsc::Sender<QueuedClientReplicationProposal> {
    let (tx, mut rx) = mpsc::channel::<QueuedClientReplicationProposal>(capacity.max(1));
    tokio::spawn(async move {
        let permits = Arc::new(Semaphore::new(S2S_CLIENT_REPLICATION_MAX_IN_FLIGHT));
        while let Some(proposal) = rx.recv().await {
            let queue_wait = proposal.enqueued_at.elapsed();
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
    tx
}

async fn run_native_gateway(
    server: Weak<Box<Server>>,
    rx: S2SNativeGatewayRx,
    mut shutdown: watch::Receiver<()>,
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
    async fn deliver(&self, from_immediate: NodeIdentifier, frame: VoiceFrame) {
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
    let permits = Arc::new(Semaphore::new(default_s2s_voice_gateway_concurrency()));
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
        let Ok(permit) = permits.clone().acquire_owned().await else {
            return;
        };
        tokio::spawn(async move {
            let _permit = permit;
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
        });
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
            let message: crate::messages::Message =
                crate::messages::encoder::PluginDataTransmission {
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
        let message: crate::messages::Message = crate::messages::encoder::TextMessage {
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
            if gs.is_suppressed() != suppress {
                gs.set_suppress(suppress);
            }
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

    if let Some(channel_id) = patch.channel_id {
        if let Err(error) =
            crate::client::handlers::send_enter_permission_queries(server, &target, channel_id)
                .await
        {
            tracing::warn!(
                error = %error,
                target = u32::from(target_id),
                channel_id,
                "failed to send enter permission queries after s2s user-state patch"
            );
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
    let remove_notice: crate::messages::Message = crate::messages::encoder::UserRemove {
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

pub fn server_id_from_channel_topic(topic: &str) -> Option<String> {
    if topic == "channels" {
        Some(DEFAULT_SERVER_ID.to_owned())
    } else {
        topic
            .strip_prefix("channels:")
            .filter(|server_id| !server_id.is_empty())
            .map(str::to_owned)
    }
}

pub fn server_id_from_channel_blob_topic(topic: &str) -> Option<String> {
    if topic == "channel_blobs" {
        Some(DEFAULT_SERVER_ID.to_owned())
    } else {
        topic
            .strip_prefix("channel_blobs:")
            .filter(|server_id| !server_id.is_empty())
            .map(str::to_owned)
    }
}

pub fn channel_topic(server_id: &str) -> String {
    if server_id == DEFAULT_SERVER_ID {
        "channels".to_owned()
    } else {
        format!("channels:{server_id}")
    }
}

pub fn channel_blob_topic(server_id: &str) -> String {
    if server_id == DEFAULT_SERVER_ID {
        "channel_blobs".to_owned()
    } else {
        format!("channel_blobs:{server_id}")
    }
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChannelSnapshot {
    channels: Vec<crate::channels::Channel>,
    #[serde(default)]
    freshness: i64,
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

    fn snapshot(&self) -> (u64, Bytes) {
        let version = self.repo.current_version_in_server(&self.server_id);
        let repo = self.repo.clone();
        let server_id = self.server_id.clone();
        let channels =
            block_in_place_or_current(|handle| handle.block_on(repo.get_all_in_server(&server_id)))
                .unwrap_or_default();
        let freshness = self.repo.latest_timestamp_in_server(&self.server_id);
        let bytes = Bytes::from(
            rmp_serde::to_vec(&ChannelSnapshot {
                channels,
                freshness,
            })
            .unwrap_or_default(),
        );
        (version, bytes)
    }

    fn log_since(
        &self,
        since: u64,
    ) -> s2s_replications::strict::LogSlice<s2s_replications::strict::StrictLogEntry<Self::Op>>
    {
        let repo = self.repo.clone();
        let server_id = self.server_id.clone();
        let entries = block_in_place_or_current(|handle| {
            handle.block_on(repo.get_log_entries_since_in_server(&server_id, since))
        });
        match entries {
            Some(entries) => s2s_replications::strict::LogSlice::Available(
                entries
                    .into_iter()
                    .map(|entry| {
                        let op = entry.op();
                        let metadata = entry.strict_metadata().map(strict_log_metadata_from_repo);
                        let log_entry = match metadata {
                            Some(metadata) => {
                                s2s_replications::strict::StrictLogEntry::with_metadata(
                                    (*op).clone(),
                                    metadata,
                                )
                            }
                            None => s2s_replications::strict::StrictLogEntry::new((*op).clone()),
                        };
                        (op.version, log_entry)
                    })
                    .collect(),
            ),
            None => s2s_replications::strict::LogSlice::TooOld,
        }
    }

    async fn apply_committed(&self, version: u64, mut op: Self::Op) {
        op.version = version;
        if op.server_id.is_empty() || op.server_id == DEFAULT_SERVER_ID {
            op.server_id = self.server_id.clone();
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
        let applied_op = op.op.clone();
        if let Err(e) = self.repo.apply_committed_operation(op).await {
            warn!(error = ?e, "s2s channel operation apply failed");
            return;
        }
        if let Some(server) = self.server.as_ref().and_then(Weak::upgrade) {
            server
                .reevaluate_speak_after_acl_change(&op_server_id, &applied_op, version)
                .await;
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
        let mut op = op;
        op.version = version;
        if op.server_id.is_empty() || op.server_id == DEFAULT_SERVER_ID {
            op.server_id = self.server_id.clone();
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
        let applied_op = op.op.clone();
        let metadata = metadata.map(strict_log_metadata_to_repo);
        if let Err(e) = self
            .repo
            .apply_committed_operation_with_metadata(op, metadata)
            .await
        {
            warn!(error = ?e, "s2s channel operation apply failed");
            return;
        }
        if let Some(server) = self.server.as_ref().and_then(Weak::upgrade) {
            server
                .reevaluate_speak_after_acl_change(&op_server_id, &applied_op, version)
                .await;
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

    async fn install_snapshot(&self, version: u64, snapshot: Bytes) {
        let decoded: ChannelSnapshot = match rmp_serde::from_slice(&snapshot) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                warn!(error = %e, "s2s channel snapshot decode failed");
                return;
            }
        };
        if let Err(e) = self
            .repo
            .install_s2s_snapshot_in_server(
                &self.server_id,
                version,
                decoded.channels,
                decoded.freshness,
            )
            .await
        {
            warn!(error = ?e, "s2s channel snapshot install failed");
        }
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
            .filter_map(|channel| channel.description_hash)
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
    #[serde(default)]
    freshness: i64,
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

    fn snapshot(&self) -> (u64, Bytes) {
        let version = self.repo.current_version();
        let repo = self.repo.clone();
        let entries = block_in_place_or_current(|handle| handle.block_on(repo.get_active_bans()))
            .unwrap_or_default();
        let freshness = self.repo.latest_timestamp();
        let bytes =
            Bytes::from(rmp_serde::to_vec(&BanSnapshot { entries, freshness }).unwrap_or_default());
        (version, bytes)
    }

    fn log_since(
        &self,
        since: u64,
    ) -> s2s_replications::strict::LogSlice<s2s_replications::strict::StrictLogEntry<Self::Op>>
    {
        let repo = self.repo.clone();
        let entries =
            block_in_place_or_current(|handle| handle.block_on(repo.get_log_entries_since(since)));
        match entries {
            Some(entries) => s2s_replications::strict::LogSlice::Available(
                entries
                    .into_iter()
                    .map(|entry| {
                        let op = entry.op();
                        let metadata = entry.strict_metadata().map(strict_log_metadata_from_repo);
                        let log_entry = match metadata {
                            Some(metadata) => {
                                s2s_replications::strict::StrictLogEntry::with_metadata(
                                    (*op).clone(),
                                    metadata,
                                )
                            }
                            None => s2s_replications::strict::StrictLogEntry::new((*op).clone()),
                        };
                        (op.version, log_entry)
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
        mut op: Self::Op,
        metadata: Option<s2s_replications::strict::StrictLogMetadata>,
    ) {
        op.version = version;
        self.repo
            .apply_remote_operation_with_metadata(
                Arc::new(op),
                metadata.map(strict_log_metadata_to_repo),
            )
            .await;
    }

    async fn install_snapshot(&self, version: u64, snapshot: Bytes) {
        let decoded: BanSnapshot = match rmp_serde::from_slice(&snapshot) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                warn!(error = %e, "s2s ban snapshot decode failed");
                return;
            }
        };
        self.repo
            .install_s2s_snapshot(version, decoded.entries, decoded.freshness)
            .await;
    }
}

#[derive(Clone)]
struct ClientReplicationAdapter {
    clients: Arc<ClientRepository>,
    channels: Arc<ChannelRepository>,
    local_epoch: u64,
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
        delta.suppress = None;
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
        block_in_place_or_current(|handle| {
            let (_, versions) = handle.block_on(clients.snapshot_with_versions());
            versions
                .get(&local_node)
                .copied()
                .map(|version| HashMap::from([(local_node, (local_epoch, version))]))
                .unwrap_or_default()
        })
        .unwrap_or_default()
    }

    fn snapshot_for_origin(&self, origin: NodeIdentifier) -> Option<(u64, u64, Bytes)> {
        let clients = self.clients.clone();
        block_in_place_or_current(|handle| {
            let (version, entries) = handle.block_on(clients.local_origin_snapshot_entries());
            let bytes =
                Bytes::from(rmp_serde::to_vec(&ClientOriginSnapshot { version, entries }).ok()?);
            Some((self.local_epoch, version, bytes))
        })
        .flatten()
        .filter(|_| origin == self.clients.local_node_id())
    }

    fn log_for_origin(
        &self,
        origin: NodeIdentifier,
        since: u64,
    ) -> s2s_replications::owner::LogSlice<Self::Op> {
        if since == 0 {
            return s2s_replications::owner::LogSlice::TooOld;
        }

        let clients = self.clients.clone();
        let entries = block_in_place_or_current(|handle| {
            handle.block_on(clients.get_log_since_for_node(origin, since))
        });
        match entries {
            Some(entries) => s2s_replications::owner::LogSlice::Available(
                entries
                    .into_iter()
                    .map(|entry| (entry.version, (*entry).clone()))
                    .collect(),
            ),
            None => s2s_replications::owner::LogSlice::TooOld,
        }
    }

    async fn apply_remote(
        &self,
        origin: NodeIdentifier,
        _epoch: u64,
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
            .apply_remote_operation(Arc::new(op), current_channel_version)
            .await
        {
            warn!(origin, version, "s2s client operation apply failed");
        }
    }

    async fn install_snapshot_for_origin(
        &self,
        origin: NodeIdentifier,
        _epoch: u64,
        _version: u64,
        snapshot: Bytes,
    ) {
        let decoded: ClientOriginSnapshot = match rmp_serde::from_slice(&snapshot) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                warn!(origin, error = %e, "s2s client snapshot decode failed");
                return;
            }
        };
        let mut entries = Vec::with_capacity(decoded.entries.len());
        for mut entry in decoded.entries {
            let current_channel_version = self
                .channels
                .current_version_in_server(entry.op.server_id());
            self.sanitize_channel_dependencies(&mut entry, current_channel_version)
                .await;
            entries.push(entry);
        }
        self.clients
            .install_remote_client_snapshot(origin, decoded.version, entries)
            .await;
    }

    async fn reset_origin(&self, origin: NodeIdentifier, _new_epoch: u64) {
        if origin != self.clients.local_node_id() {
            self.clients.clear_clients_from_node(origin).await;
        }
    }

    async fn remove_origin(&self, origin: NodeIdentifier) {
        if origin != self.clients.local_node_id() {
            self.clients.clear_clients_from_node(origin).await;
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
    Some(tokio::task::block_in_place(|| f(&handle)))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use super::*;
    use crate::channel_repository::{ChannelRepoTuning, ChannelRepository, ChannelRootConfig};
    use crate::messages::Message;

    #[test]
    fn strict_proposal_gateway_timeout_tracks_replication_ttl() {
        let timeout = strict_proposal_gateway_response_timeout(
            &s2s_replications::ReplicationConfig::default(),
        );

        assert!(timeout > s2s_replications::ReplicationConfig::default().propose_ttl());
        assert_eq!(timeout, Duration::from_millis(10_200));
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

    #[derive(Debug, PartialEq, Eq)]
    struct TestGatewayCommand {
        label: &'static str,
        bytes: usize,
    }

    impl EstimatedS2SCommand for TestGatewayCommand {
        fn label(&self) -> &'static str {
            self.label
        }

        fn estimated_bytes(&self) -> usize {
            self.bytes
        }
    }

    #[test]
    fn queue_budget_releases_permits_when_command_is_dropped() {
        let budget = S2SQueueBudget::new(S2S_GATEWAY_LANE_MIN_BYTES);
        let lane = budget.split(S2S_GATEWAY_LANE_MIN_BYTES);
        let permit = lane
            .try_reserve(S2S_GATEWAY_LANE_MIN_BYTES * 3 / 4)
            .expect("reserve fits");

        assert!(lane.try_reserve(S2S_GATEWAY_LANE_MIN_BYTES / 2).is_none());
        drop(permit);
        assert!(lane.try_reserve(S2S_GATEWAY_LANE_MIN_BYTES / 2).is_some());
    }

    #[tokio::test]
    async fn adaptive_sender_drops_voice_style_command_when_budget_is_full() {
        let budget = S2SQueueBudget::new(S2S_GATEWAY_LANE_MIN_BYTES);
        let (tx, mut rx) = S2SAdaptiveSender::new(budget.split(S2S_GATEWAY_LANE_MIN_BYTES));

        assert!(tx.try_send(TestGatewayCommand {
            label: "voice",
            bytes: S2S_GATEWAY_LANE_MIN_BYTES * 3 / 4,
        }));
        assert!(!tx.try_send(TestGatewayCommand {
            label: "voice",
            bytes: S2S_GATEWAY_LANE_MIN_BYTES / 2,
        }));

        assert_eq!(
            rx.recv().await,
            Some(TestGatewayCommand {
                label: "voice",
                bytes: S2S_GATEWAY_LANE_MIN_BYTES * 3 / 4,
            })
        );
        assert!(tx.try_send(TestGatewayCommand {
            label: "voice",
            bytes: S2S_GATEWAY_LANE_MIN_BYTES / 2,
        }));
    }

    #[tokio::test]
    async fn adaptive_sender_rejects_oversized_lossless_command_without_waiting() {
        let budget = S2SQueueBudget::new(S2S_GATEWAY_LANE_MIN_BYTES);
        let (tx, _rx) = S2SAdaptiveSender::new(budget.split(S2S_GATEWAY_LANE_MIN_BYTES));

        assert!(
            !tx.send(TestGatewayCommand {
                label: "control",
                bytes: S2S_GATEWAY_LANE_MIN_BYTES + 1,
            })
            .await
        );
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
    fn voice_recipient_index_filter_ignores_non_default_server_scopes() {
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

        assert!(!client_entry_affects_voice_recipient_index(&entry));
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
            s2s_replications::owner::LogSlice::TooOld
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
            .await;

        let snapshot_message = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("snapshot should broadcast live AddClient")
            .expect("snapshot broadcast channel open");
        assert!(matches!(
            snapshot_message.entry.op,
            ClientStateOperation::AddClient { .. }
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

        let (messages, versions) = peer_clients
            .replay_since_in_server(DEFAULT_SERVER_ID, &HashMap::new())
            .await
            .expect("snapshot replay succeeds");
        assert_eq!(
            versions.get(&origin_clients.local_node_id()),
            Some(&version)
        );
        assert_eq!(
            messages
                .iter()
                .filter(|message| matches!(message, Message::UserState(_)))
                .count(),
            1
        );
        assert!(
            messages
                .iter()
                .all(|message| !matches!(message, Message::UserRemove(_)))
        );
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
            .await;

        let snapshot_marker = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("snapshot should broadcast version marker")
            .expect("snapshot broadcast channel open");
        assert!(matches!(
            snapshot_marker.entry.op,
            ClientStateOperation::ResetNode { .. }
        ));
        assert!(rx.try_recv().is_err());

        let (messages, versions) = peer_clients
            .replay_since_in_server(DEFAULT_SERVER_ID, &HashMap::new())
            .await
            .expect("empty snapshot replay succeeds");
        assert_eq!(
            versions.get(&origin_clients.local_node_id()),
            Some(&version)
        );
        assert!(messages.is_empty());
    }
}
