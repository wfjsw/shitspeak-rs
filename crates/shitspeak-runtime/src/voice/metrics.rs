use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use shitspeak_core::{ClientSessionIdentifier, NodeIdentifier};
use shitspeak_s2s::status::PrometheusSample;

use super::dispatch_tuning::{VoiceDispatchPlan, VoiceDispatchPlanSource};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum VoiceIngressTransport {
    Udp,
    TcpTunnel,
}

impl VoiceIngressTransport {
    fn label(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::TcpTunnel => "tcp_tunnel",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum UdpDecryptPath {
    Address,
    IpFallback,
}

impl UdpDecryptPath {
    fn label(self) -> &'static str {
        match self {
            Self::Address => "address",
            Self::IpFallback => "ip_fallback",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum UdpDecryptResult {
    Success,
    Failure,
    NoCryptState,
}

impl UdpDecryptResult {
    fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::NoCryptState => "no_crypt_state",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum UdpDrainDropReason {
    ProcessingQueueFull,
    ProcessingQueueClosed,
    VoiceDisabled,
    PacketTooShort,
    PacketTooLarge,
    PingDecodeFailed,
}

impl UdpDrainDropReason {
    fn label(self) -> &'static str {
        match self {
            Self::ProcessingQueueFull => "processing_queue_full",
            Self::ProcessingQueueClosed => "processing_queue_closed",
            Self::VoiceDisabled => "voice_disabled",
            Self::PacketTooShort => "packet_too_short",
            Self::PacketTooLarge => "packet_too_large",
            Self::PingDecodeFailed => "ping_decode_failed",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceQueueDropReason {
    RoutingQueueFullOrClosed,
    TcpQueueFull,
    TcpQueueClosed,
}

impl VoiceQueueDropReason {
    fn label(self) -> &'static str {
        match self {
            Self::RoutingQueueFullOrClosed => "routing_queue_full_or_closed",
            Self::TcpQueueFull => "tcp_queue_full",
            Self::TcpQueueClosed => "tcp_queue_closed",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceRouteSource {
    Local,
    S2s,
    Loopback,
}

impl VoiceRouteSource {
    fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::S2s => "s2s",
            Self::Loopback => "loopback",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceRouteKind {
    Normal,
    Target,
    Loopback,
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceRouteScope {
    Normal,
    TargetChannel,
    WholeServer,
}

impl VoiceRouteScope {
    fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::TargetChannel => "target_channel",
            Self::WholeServer => "whole_server",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceRouteCacheLayer {
    Topology,
    Authorization,
    Recipients,
}

impl VoiceRouteCacheLayer {
    fn label(self) -> &'static str {
        match self {
            Self::Topology => "topology",
            Self::Authorization => "authorization",
            Self::Recipients => "recipients",
        }
    }
}

impl VoiceRouteKind {
    fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Target => "target",
            Self::Loopback => "loopback",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceDispatchMode {
    Sequential,
    Rayon,
}

impl VoiceDispatchMode {
    fn label(self) -> &'static str {
        match self {
            Self::Sequential => "sequential",
            Self::Rayon => "rayon",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoicePipelinePath {
    UdpIngress,
    LocalSequential,
    LocalRayon,
    S2sForward,
}

impl VoicePipelinePath {
    fn label(self) -> &'static str {
        match self {
            Self::UdpIngress => "udp_ingress",
            Self::LocalSequential => "local_sequential",
            Self::LocalRayon => "local_rayon",
            Self::S2sForward => "s2s_forward",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoicePipelineStage {
    UdpClientLookup,
    UdpDecrypt,
    UdpPacketDecode,
    Encode,
    RecipientLookup,
    TcpEnqueue,
    UdpEncryptQueue,
    UdpFlush,
    RayonEncryptJoin,
    S2sPayloadEncode,
    S2sGatewayEnqueue,
}

impl VoicePipelineStage {
    fn label(self) -> &'static str {
        match self {
            Self::UdpClientLookup => "udp_client_lookup",
            Self::UdpDecrypt => "udp_decrypt",
            Self::UdpPacketDecode => "udp_packet_decode",
            Self::Encode => "encode",
            Self::RecipientLookup => "recipient_lookup",
            Self::TcpEnqueue => "tcp_enqueue",
            Self::UdpEncryptQueue => "udp_encrypt_queue",
            Self::UdpFlush => "udp_flush",
            Self::RayonEncryptJoin => "rayon_encrypt_join",
            Self::S2sPayloadEncode => "s2s_payload_encode",
            Self::S2sGatewayEnqueue => "s2s_gateway_enqueue",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceEgressTransport {
    Udp,
    TcpTunnel,
}

impl VoiceEgressTransport {
    fn label(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::TcpTunnel => "tcp_tunnel",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceEgressResult {
    Queued,
    Sent,
    Dropped,
    Failed,
}

impl VoiceEgressResult {
    fn label(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sent => "sent",
            Self::Dropped => "dropped",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceAgeStage {
    UdpPacket,
    RoutingQueue,
}

impl VoiceAgeStage {
    fn label(self) -> &'static str {
        match self {
            Self::UdpPacket => "udp_packet",
            Self::RoutingQueue => "routing_queue",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceSchedulerStage {
    UdpProcessing,
    RoutingTask,
}

impl VoiceSchedulerStage {
    fn label(self) -> &'static str {
        match self {
            Self::UdpProcessing => "udp_processing",
            Self::RoutingTask => "routing_task",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceUdpSendResult {
    WouldBlock,
    Partial,
    Failed,
    RetryBudgetExhausted,
}

impl VoiceUdpSendResult {
    fn label(self) -> &'static str {
        match self {
            Self::WouldBlock => "would_block",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::RetryBudgetExhausted => "retry_budget_exhausted",
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum VoiceContinuityResult {
    Frame,
    ForwardGap,
    DuplicateOrOld,
    ResetOrTerminator,
}

impl VoiceContinuityResult {
    fn label(self) -> &'static str {
        match self {
            Self::Frame => "frame",
            Self::ForwardGap => "forward_gap",
            Self::DuplicateOrOld => "duplicate_or_old",
            Self::ResetOrTerminator => "reset_or_terminator",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceQueueKind {
    UdpProcessing,
    Routing,
    TcpFallback,
    UdpFanout,
}

impl VoiceQueueKind {
    fn label(self) -> &'static str {
        match self {
            Self::UdpProcessing => "udp_processing",
            Self::Routing => "routing",
            Self::TcpFallback => "tcp_fallback",
            Self::UdpFanout => "udp_fanout",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceQueueEnqueueResult {
    Accepted,
    Full,
    Closed,
    Dropped,
}

impl VoiceQueueEnqueueResult {
    fn label(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Full => "full",
            Self::Closed => "closed",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum S2SVoiceGatewayDropDirection {
    NativeToS2s,
    S2sToNative,
}

impl S2SVoiceGatewayDropDirection {
    fn label(self) -> &'static str {
        match self {
            Self::NativeToS2s => "native_to_s2s",
            Self::S2sToNative => "s2s_to_native",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum S2SVoiceGatewayDropReason {
    Unavailable,
    FullOrClosed,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum RemotePlayoutResult {
    TalkspurtStarted,
    Scheduled,
    Released,
    OriginalTimelineRebased,
    LateRepairDropped,
    RepairBeforePlayout,
    RepairAfterPlayout,
    DecodeFailed,
}

impl RemotePlayoutResult {
    fn label(self) -> &'static str {
        match self {
            Self::TalkspurtStarted => "talkspurt_started",
            Self::Scheduled => "scheduled",
            Self::Released => "released",
            Self::OriginalTimelineRebased => "original_timeline_rebased",
            Self::LateRepairDropped => "late_repair_dropped",
            Self::RepairBeforePlayout => "repair_before_playout",
            Self::RepairAfterPlayout => "repair_after_playout",
            Self::DecodeFailed => "decode_failed",
        }
    }
}

impl S2SVoiceGatewayDropReason {
    fn label(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::FullOrClosed => "full_or_closed",
        }
    }
}

const INGRESS_TRANSPORT_COUNT: usize = 2;
const UDP_DECRYPT_PATH_COUNT: usize = 2;
const UDP_DECRYPT_RESULT_COUNT: usize = 3;
const UDP_DRAIN_DROP_REASON_COUNT: usize = 6;
const VOICE_QUEUE_DROP_REASON_COUNT: usize = 3;
const VOICE_ROUTE_SOURCE_COUNT: usize = 3;
const VOICE_ROUTE_KIND_COUNT: usize = 3;
const VOICE_ROUTE_CACHE_SOURCE_COUNT: usize = 2;
const VOICE_ROUTE_CACHE_LAYER_COUNT: usize = 3;
const VOICE_ROUTE_SCOPE_COUNT: usize = 3;
const VOICE_DISPATCH_MODE_COUNT: usize = 2;
const VOICE_PIPELINE_PATH_COUNT: usize = 4;
const VOICE_PIPELINE_STAGE_COUNT: usize = 11;
const VOICE_EGRESS_TRANSPORT_COUNT: usize = 2;
const VOICE_EGRESS_RESULT_COUNT: usize = 4;
const VOICE_AGE_STAGE_COUNT: usize = 2;
const VOICE_SCHEDULER_STAGE_COUNT: usize = 2;
const VOICE_UDP_SEND_RESULT_COUNT: usize = 4;
const S2S_VOICE_GATEWAY_DROP_DIRECTION_COUNT: usize = 2;
const S2S_VOICE_GATEWAY_DROP_REASON_COUNT: usize = 2;
const VOICE_QUEUE_KIND_COUNT: usize = 4;
const VOICE_QUEUE_ENQUEUE_RESULT_COUNT: usize = 4;

const REMOTE_PLAYOUT_LATENESS_BUCKETS_MS: [(&str, u64); 8] = [
    ("le_1", 1),
    ("le_5", 5),
    ("le_10", 10),
    ("le_20", 20),
    ("le_50", 50),
    ("le_100", 100),
    ("le_250", 250),
    ("gt_250", u64::MAX),
];

const ROUTE_DIMENSIONS: [(VoiceRouteSource, VoiceRouteKind); 5] = [
    (VoiceRouteSource::Local, VoiceRouteKind::Normal),
    (VoiceRouteSource::Local, VoiceRouteKind::Target),
    (VoiceRouteSource::S2s, VoiceRouteKind::Normal),
    (VoiceRouteSource::S2s, VoiceRouteKind::Target),
    (VoiceRouteSource::Loopback, VoiceRouteKind::Loopback),
];
const PIPELINE_PATHS: [VoicePipelinePath; VOICE_PIPELINE_PATH_COUNT] = [
    VoicePipelinePath::UdpIngress,
    VoicePipelinePath::LocalSequential,
    VoicePipelinePath::LocalRayon,
    VoicePipelinePath::S2sForward,
];
const PIPELINE_STAGES: [VoicePipelineStage; VOICE_PIPELINE_STAGE_COUNT] = [
    VoicePipelineStage::UdpClientLookup,
    VoicePipelineStage::UdpDecrypt,
    VoicePipelineStage::UdpPacketDecode,
    VoicePipelineStage::Encode,
    VoicePipelineStage::RecipientLookup,
    VoicePipelineStage::TcpEnqueue,
    VoicePipelineStage::UdpEncryptQueue,
    VoicePipelineStage::UdpFlush,
    VoicePipelineStage::RayonEncryptJoin,
    VoicePipelineStage::S2sPayloadEncode,
    VoicePipelineStage::S2sGatewayEnqueue,
];

const FANOUT_BUCKETS: [(&str, u64); 8] = [
    ("0", 0),
    ("1", 1),
    ("2_4", 4),
    ("5_16", 16),
    ("17_64", 64),
    ("65_256", 256),
    ("257_512", 512),
    ("513_plus", u64::MAX),
];
const ROUTE_DURATION_BUCKETS_US: [(&str, u64); 8] = [
    ("le_100", 100),
    ("le_250", 250),
    ("le_500", 500),
    ("le_1000", 1_000),
    ("le_2500", 2_500),
    ("le_5000", 5_000),
    ("le_10000", 10_000),
    ("gt_10000", u64::MAX),
];
const UDP_FALLBACK_CANDIDATE_BUCKETS: [(&str, u64); 7] = [
    ("0", 0),
    ("1", 1),
    ("2_4", 4),
    ("5_8", 8),
    ("9_16", 16),
    ("17_32", 32),
    ("33_plus", u64::MAX),
];
const PACKET_AGE_BUCKETS_MS: [(&str, u64); 8] = [
    ("le_10", 10),
    ("le_20", 20),
    ("le_50", 50),
    ("le_100", 100),
    ("le_120", 120),
    ("le_250", 250),
    ("le_500", 500),
    ("gt_500", u64::MAX),
];
const SCHEDULER_DELAY_BUCKETS_US: [(&str, u64); 8] = [
    ("le_100", 100),
    ("le_250", 250),
    ("le_500", 500),
    ("le_1000", 1_000),
    ("le_2500", 2_500),
    ("le_5000", 5_000),
    ("le_10000", 10_000),
    ("gt_10000", u64::MAX),
];
const VOICE_BATCH_SIZE_BUCKETS: [(&str, u64); 8] = [
    ("1", 1),
    ("2", 2),
    ("3_4", 4),
    ("5_8", 8),
    ("9_16", 16),
    ("17_32", 32),
    ("33_64", 64),
    ("65_plus", u64::MAX),
];
const VOICE_BATCH_BYTES_BUCKETS: [(&str, u64); 8] = [
    ("le_512", 512),
    ("le_1024", 1_024),
    ("le_2048", 2_048),
    ("le_4096", 4_096),
    ("le_8192", 8_192),
    ("le_16384", 16_384),
    ("le_65536", 65_536),
    ("gt_65536", u64::MAX),
];

#[derive(Default)]
struct RemotePlayoutMetrics {
    events: HashMap<(NodeIdentifier, RemotePlayoutResult), u64>,
    selected_delay_ms: HashMap<NodeIdentifier, u64>,
    release_lateness_buckets: HashMap<(NodeIdentifier, &'static str), u64>,
}

static REMOTE_PLAYOUT: LazyLock<Mutex<RemotePlayoutMetrics>> =
    LazyLock::new(|| Mutex::new(RemotePlayoutMetrics::default()));

static INGRESS_PACKETS: [AtomicU64; INGRESS_TRANSPORT_COUNT] = [const { AtomicU64::new(0) }; 2];
static INGRESS_BYTES: [AtomicU64; INGRESS_TRANSPORT_COUNT] = [const { AtomicU64::new(0) }; 2];
static UDP_DECRYPT_ATTEMPTS: [[AtomicU64; UDP_DECRYPT_RESULT_COUNT]; UDP_DECRYPT_PATH_COUNT] =
    [const { [const { AtomicU64::new(0) }; UDP_DECRYPT_RESULT_COUNT] }; UDP_DECRYPT_PATH_COUNT];
static UDP_IP_FALLBACKS: AtomicU64 = AtomicU64::new(0);
static UDP_IP_FALLBACK_CANDIDATE_BUCKETS: [AtomicU64; UDP_FALLBACK_CANDIDATE_BUCKETS.len()] =
    [const { AtomicU64::new(0) }; UDP_FALLBACK_CANDIDATE_BUCKETS.len()];
static UDP_DRAIN_DROPS: [AtomicU64; UDP_DRAIN_DROP_REASON_COUNT] =
    [const { AtomicU64::new(0) }; UDP_DRAIN_DROP_REASON_COUNT];
static QUEUE_DROPS: [AtomicU64; VOICE_QUEUE_DROP_REASON_COUNT] =
    [const { AtomicU64::new(0) }; VOICE_QUEUE_DROP_REASON_COUNT];
static ROUTED_FRAMES: [AtomicU64; VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT] =
    [const { AtomicU64::new(0) }; VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT];
static ROUTE_CACHE_HITS: [AtomicU64;
    VOICE_ROUTE_CACHE_SOURCE_COUNT * VOICE_ROUTE_CACHE_LAYER_COUNT] =
    [const { AtomicU64::new(0) }; VOICE_ROUTE_CACHE_SOURCE_COUNT * VOICE_ROUTE_CACHE_LAYER_COUNT];
static ROUTE_CACHE_MISSES: [AtomicU64;
    VOICE_ROUTE_CACHE_SOURCE_COUNT * VOICE_ROUTE_CACHE_LAYER_COUNT] =
    [const { AtomicU64::new(0) }; VOICE_ROUTE_CACHE_SOURCE_COUNT * VOICE_ROUTE_CACHE_LAYER_COUNT];
static ROUTE_SCOPE_RESOLUTIONS: [AtomicU64;
    VOICE_ROUTE_CACHE_SOURCE_COUNT * VOICE_ROUTE_SCOPE_COUNT] =
    [const { AtomicU64::new(0) }; VOICE_ROUTE_CACHE_SOURCE_COUNT * VOICE_ROUTE_SCOPE_COUNT];
static ROUTE_RESOLUTION_DURATION_TOTAL_US: [AtomicU64;
    VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT] =
    [const { AtomicU64::new(0) }; VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT];
static ROUTE_DURATION_TOTAL_US: [AtomicU64; VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT] =
    [const { AtomicU64::new(0) }; VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT];
static ROUTE_DURATION_BUCKETS: [[AtomicU64; ROUTE_DURATION_BUCKETS_US.len()];
    VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT] =
    [const { [const { AtomicU64::new(0) }; ROUTE_DURATION_BUCKETS_US.len()] };
        VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT];
static FANOUT_BUCKETS_TOTAL: [[AtomicU64; FANOUT_BUCKETS.len()];
    VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT] =
    [const { [const { AtomicU64::new(0) }; FANOUT_BUCKETS.len()] };
        VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT];
static DISPATCH_FRAMES: [AtomicU64; VOICE_DISPATCH_MODE_COUNT] =
    [const { AtomicU64::new(0) }; VOICE_DISPATCH_MODE_COUNT];
static DISPATCH_TUNING_SMALL_THRESHOLD: AtomicU64 = AtomicU64::new(512);
static DISPATCH_TUNING_SMALL_MIN_LEN: AtomicU64 = AtomicU64::new(256);
static DISPATCH_TUNING_LARGE_THRESHOLD: AtomicU64 = AtomicU64::new(512);
static DISPATCH_TUNING_LARGE_MIN_LEN: AtomicU64 = AtomicU64::new(256);
static DISPATCH_TUNING_SOURCE: AtomicU64 = AtomicU64::new(3);
static DISPATCH_TUNING_CALIBRATION_DURATION_US: AtomicU64 = AtomicU64::new(0);
static PIPELINE_STAGE_EVENTS: [[AtomicU64; VOICE_PIPELINE_STAGE_COUNT]; VOICE_PIPELINE_PATH_COUNT] =
    [const { [const { AtomicU64::new(0) }; VOICE_PIPELINE_STAGE_COUNT] }; VOICE_PIPELINE_PATH_COUNT];
static PIPELINE_STAGE_DURATION_TOTAL_US: [[AtomicU64; VOICE_PIPELINE_STAGE_COUNT];
    VOICE_PIPELINE_PATH_COUNT] = [const { [const { AtomicU64::new(0) }; VOICE_PIPELINE_STAGE_COUNT] };
    VOICE_PIPELINE_PATH_COUNT];
static PIPELINE_STAGE_DURATION_BUCKETS: [[[AtomicU64; ROUTE_DURATION_BUCKETS_US.len()];
    VOICE_PIPELINE_STAGE_COUNT];
    VOICE_PIPELINE_PATH_COUNT] = [const {
    [const { [const { AtomicU64::new(0) }; ROUTE_DURATION_BUCKETS_US.len()] };
        VOICE_PIPELINE_STAGE_COUNT]
}; VOICE_PIPELINE_PATH_COUNT];
static EGRESS_PACKETS: [[AtomicU64; VOICE_EGRESS_RESULT_COUNT]; VOICE_EGRESS_TRANSPORT_COUNT] =
    [const { [const { AtomicU64::new(0) }; VOICE_EGRESS_RESULT_COUNT] };
        VOICE_EGRESS_TRANSPORT_COUNT];
static EGRESS_BYTES: [[AtomicU64; VOICE_EGRESS_RESULT_COUNT]; VOICE_EGRESS_TRANSPORT_COUNT] =
    [const { [const { AtomicU64::new(0) }; VOICE_EGRESS_RESULT_COUNT] };
        VOICE_EGRESS_TRANSPORT_COUNT];
static S2S_FORWARD_ATTEMPTS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
static S2S_GATEWAY_DROPS: [[AtomicU64; S2S_VOICE_GATEWAY_DROP_REASON_COUNT];
    S2S_VOICE_GATEWAY_DROP_DIRECTION_COUNT] =
    [const { [const { AtomicU64::new(0) }; S2S_VOICE_GATEWAY_DROP_REASON_COUNT] };
        S2S_VOICE_GATEWAY_DROP_DIRECTION_COUNT];
static PACKET_AGE_BUCKETS: [[AtomicU64; PACKET_AGE_BUCKETS_MS.len()]; VOICE_AGE_STAGE_COUNT] =
    [const { [const { AtomicU64::new(0) }; PACKET_AGE_BUCKETS_MS.len()] }; VOICE_AGE_STAGE_COUNT];
static STALE_DROPS: [AtomicU64; VOICE_AGE_STAGE_COUNT] =
    [const { AtomicU64::new(0) }; VOICE_AGE_STAGE_COUNT];
static SCHEDULER_DELAY_BUCKETS: [[AtomicU64; SCHEDULER_DELAY_BUCKETS_US.len()];
    VOICE_SCHEDULER_STAGE_COUNT] =
    [const { [const { AtomicU64::new(0) }; SCHEDULER_DELAY_BUCKETS_US.len()] };
        VOICE_SCHEDULER_STAGE_COUNT];
static CRYPT_LOCK_CONTENTION_DROPS: AtomicU64 = AtomicU64::new(0);
static UDP_SEND_EVENTS: [AtomicU64; VOICE_UDP_SEND_RESULT_COUNT] =
    [const { AtomicU64::new(0) }; VOICE_UDP_SEND_RESULT_COUNT];
static UDP_RECV_BATCHES: AtomicU64 = AtomicU64::new(0);
static UDP_RECV_DATAGRAMS: AtomicU64 = AtomicU64::new(0);
static UDP_RECV_BATCH_SIZE_BUCKETS: [AtomicU64; VOICE_BATCH_SIZE_BUCKETS.len()] =
    [const { AtomicU64::new(0) }; VOICE_BATCH_SIZE_BUCKETS.len()];
static UDP_EGRESS_BATCHES: AtomicU64 = AtomicU64::new(0);
static UDP_EGRESS_DATAGRAMS: AtomicU64 = AtomicU64::new(0);
static UDP_EGRESS_BATCH_SIZE_BUCKETS: [AtomicU64; VOICE_BATCH_SIZE_BUCKETS.len()] =
    [const { AtomicU64::new(0) }; VOICE_BATCH_SIZE_BUCKETS.len()];
static UDP_EGRESS_BATCH_BYTES_BUCKETS: [AtomicU64; VOICE_BATCH_BYTES_BUCKETS.len()] =
    [const { AtomicU64::new(0) }; VOICE_BATCH_BYTES_BUCKETS.len()];
static UDP_EGRESS_SEND_DURATION_BUCKETS: [AtomicU64; ROUTE_DURATION_BUCKETS_US.len()] =
    [const { AtomicU64::new(0) }; ROUTE_DURATION_BUCKETS_US.len()];
static QUEUE_STATUS: [Mutex<VoiceQueueStatus>; VOICE_QUEUE_KIND_COUNT] =
    [const { Mutex::new(VoiceQueueStatus::new()) }; VOICE_QUEUE_KIND_COUNT];
static QUEUE_ENQUEUES: [[AtomicU64; VOICE_QUEUE_ENQUEUE_RESULT_COUNT]; VOICE_QUEUE_KIND_COUNT] =
    [const { [const { AtomicU64::new(0) }; VOICE_QUEUE_ENQUEUE_RESULT_COUNT] };
        VOICE_QUEUE_KIND_COUNT];
static CONTINUITY: LazyLock<Mutex<VoiceContinuityState>> =
    LazyLock::new(|| Mutex::new(VoiceContinuityState::default()));

#[derive(Default)]
struct VoiceContinuityState {
    sessions: HashMap<(VoiceIngressTransport, u32), u64>,
    counters: HashMap<(VoiceIngressTransport, u16, VoiceContinuityResult), u64>,
}

#[derive(Clone, Copy)]
struct VoiceQueueStatus {
    depth: u64,
    high_watermark: u64,
    capacity: u64,
    samples: u64,
    full_samples: u64,
}

impl VoiceQueueStatus {
    const fn new() -> Self {
        Self {
            depth: 0,
            high_watermark: 0,
            capacity: 0,
            samples: 0,
            full_samples: 0,
        }
    }
}

fn transport_index(transport: VoiceIngressTransport) -> usize {
    match transport {
        VoiceIngressTransport::Udp => 0,
        VoiceIngressTransport::TcpTunnel => 1,
    }
}

fn decrypt_path_index(path: UdpDecryptPath) -> usize {
    match path {
        UdpDecryptPath::Address => 0,
        UdpDecryptPath::IpFallback => 1,
    }
}

fn decrypt_result_index(result: UdpDecryptResult) -> usize {
    match result {
        UdpDecryptResult::Success => 0,
        UdpDecryptResult::Failure => 1,
        UdpDecryptResult::NoCryptState => 2,
    }
}

fn udp_drain_drop_index(reason: UdpDrainDropReason) -> usize {
    match reason {
        UdpDrainDropReason::ProcessingQueueFull => 0,
        UdpDrainDropReason::ProcessingQueueClosed => 1,
        UdpDrainDropReason::VoiceDisabled => 2,
        UdpDrainDropReason::PacketTooShort => 3,
        UdpDrainDropReason::PacketTooLarge => 4,
        UdpDrainDropReason::PingDecodeFailed => 5,
    }
}

fn queue_drop_index(reason: VoiceQueueDropReason) -> usize {
    match reason {
        VoiceQueueDropReason::RoutingQueueFullOrClosed => 0,
        VoiceQueueDropReason::TcpQueueFull => 1,
        VoiceQueueDropReason::TcpQueueClosed => 2,
    }
}

fn route_source_index(source: VoiceRouteSource) -> usize {
    match source {
        VoiceRouteSource::Local => 0,
        VoiceRouteSource::S2s => 1,
        VoiceRouteSource::Loopback => 2,
    }
}

fn route_kind_index(kind: VoiceRouteKind) -> usize {
    match kind {
        VoiceRouteKind::Normal => 0,
        VoiceRouteKind::Target => 1,
        VoiceRouteKind::Loopback => 2,
    }
}

fn route_index(source: VoiceRouteSource, kind: VoiceRouteKind) -> usize {
    route_source_index(source) * VOICE_ROUTE_KIND_COUNT + route_kind_index(kind)
}

fn route_cache_index(source: VoiceRouteSource, layer: VoiceRouteCacheLayer) -> usize {
    let source = match source {
        VoiceRouteSource::Local => 0,
        VoiceRouteSource::S2s => 1,
        VoiceRouteSource::Loopback => return 0,
    };
    let layer = match layer {
        VoiceRouteCacheLayer::Topology => 0,
        VoiceRouteCacheLayer::Authorization => 1,
        VoiceRouteCacheLayer::Recipients => 2,
    };
    source * VOICE_ROUTE_CACHE_LAYER_COUNT + layer
}

fn route_scope_index(source: VoiceRouteSource, scope: VoiceRouteScope) -> usize {
    let source = match source {
        VoiceRouteSource::Local => 0,
        VoiceRouteSource::S2s => 1,
        VoiceRouteSource::Loopback => return 0,
    };
    let scope = match scope {
        VoiceRouteScope::Normal => 0,
        VoiceRouteScope::TargetChannel => 1,
        VoiceRouteScope::WholeServer => 2,
    };
    source * VOICE_ROUTE_SCOPE_COUNT + scope
}

fn dispatch_mode_index(mode: VoiceDispatchMode) -> usize {
    match mode {
        VoiceDispatchMode::Sequential => 0,
        VoiceDispatchMode::Rayon => 1,
    }
}

fn pipeline_path_index(path: VoicePipelinePath) -> usize {
    match path {
        VoicePipelinePath::UdpIngress => 0,
        VoicePipelinePath::LocalSequential => 1,
        VoicePipelinePath::LocalRayon => 2,
        VoicePipelinePath::S2sForward => 3,
    }
}

fn pipeline_stage_index(stage: VoicePipelineStage) -> usize {
    match stage {
        VoicePipelineStage::UdpClientLookup => 0,
        VoicePipelineStage::UdpDecrypt => 1,
        VoicePipelineStage::UdpPacketDecode => 2,
        VoicePipelineStage::Encode => 3,
        VoicePipelineStage::RecipientLookup => 4,
        VoicePipelineStage::TcpEnqueue => 5,
        VoicePipelineStage::UdpEncryptQueue => 6,
        VoicePipelineStage::UdpFlush => 7,
        VoicePipelineStage::RayonEncryptJoin => 8,
        VoicePipelineStage::S2sPayloadEncode => 9,
        VoicePipelineStage::S2sGatewayEnqueue => 10,
    }
}

fn egress_transport_index(transport: VoiceEgressTransport) -> usize {
    match transport {
        VoiceEgressTransport::Udp => 0,
        VoiceEgressTransport::TcpTunnel => 1,
    }
}

fn egress_result_index(result: VoiceEgressResult) -> usize {
    match result {
        VoiceEgressResult::Queued => 0,
        VoiceEgressResult::Sent => 1,
        VoiceEgressResult::Dropped => 2,
        VoiceEgressResult::Failed => 3,
    }
}

fn age_stage_index(stage: VoiceAgeStage) -> usize {
    match stage {
        VoiceAgeStage::UdpPacket => 0,
        VoiceAgeStage::RoutingQueue => 1,
    }
}

fn scheduler_stage_index(stage: VoiceSchedulerStage) -> usize {
    match stage {
        VoiceSchedulerStage::UdpProcessing => 0,
        VoiceSchedulerStage::RoutingTask => 1,
    }
}

fn udp_send_result_index(result: VoiceUdpSendResult) -> usize {
    match result {
        VoiceUdpSendResult::WouldBlock => 0,
        VoiceUdpSendResult::Partial => 1,
        VoiceUdpSendResult::Failed => 2,
        VoiceUdpSendResult::RetryBudgetExhausted => 3,
    }
}

fn queue_kind_index(kind: VoiceQueueKind) -> usize {
    match kind {
        VoiceQueueKind::UdpProcessing => 0,
        VoiceQueueKind::Routing => 1,
        VoiceQueueKind::TcpFallback => 2,
        VoiceQueueKind::UdpFanout => 3,
    }
}

fn queue_enqueue_result_index(result: VoiceQueueEnqueueResult) -> usize {
    match result {
        VoiceQueueEnqueueResult::Accepted => 0,
        VoiceQueueEnqueueResult::Full => 1,
        VoiceQueueEnqueueResult::Closed => 2,
        VoiceQueueEnqueueResult::Dropped => 3,
    }
}

fn s2s_gateway_drop_direction_index(direction: S2SVoiceGatewayDropDirection) -> usize {
    match direction {
        S2SVoiceGatewayDropDirection::NativeToS2s => 0,
        S2SVoiceGatewayDropDirection::S2sToNative => 1,
    }
}

fn s2s_gateway_drop_reason_index(reason: S2SVoiceGatewayDropReason) -> usize {
    match reason {
        S2SVoiceGatewayDropReason::Unavailable => 0,
        S2SVoiceGatewayDropReason::FullOrClosed => 1,
    }
}

fn increment(value: &AtomicU64, amount: u64) {
    value.fetch_add(amount, Ordering::Relaxed);
}

fn observe_bucket(buckets: &[AtomicU64], definitions: &[(&str, u64)], value: u64) {
    if let Some((index, _)) = definitions
        .iter()
        .enumerate()
        .find(|(_, (_, upper_bound))| value <= *upper_bound)
    {
        increment(&buckets[index], 1);
    }
}

pub(crate) fn record_ingress(transport: VoiceIngressTransport, bytes: usize) {
    let index = transport_index(transport);
    increment(&INGRESS_PACKETS[index], 1);
    increment(&INGRESS_BYTES[index], bytes as u64);
}

pub(crate) fn record_udp_decrypt(path: UdpDecryptPath, result: UdpDecryptResult) {
    increment(
        &UDP_DECRYPT_ATTEMPTS[decrypt_path_index(path)][decrypt_result_index(result)],
        1,
    );
}

pub(crate) fn record_udp_ip_fallback(candidates: usize) {
    increment(&UDP_IP_FALLBACKS, 1);
    observe_bucket(
        &UDP_IP_FALLBACK_CANDIDATE_BUCKETS,
        &UDP_FALLBACK_CANDIDATE_BUCKETS,
        candidates as u64,
    );
}

pub(crate) fn record_udp_drain_drop(reason: UdpDrainDropReason) {
    increment(&UDP_DRAIN_DROPS[udp_drain_drop_index(reason)], 1);
}

pub(crate) fn record_queue_drop(reason: VoiceQueueDropReason) {
    increment(&QUEUE_DROPS[queue_drop_index(reason)], 1);
}

pub(crate) fn record_packet_age(stage: VoiceAgeStage, age: Duration) {
    let age_ms = age.as_millis().min(u64::MAX as u128) as u64;
    observe_bucket(
        &PACKET_AGE_BUCKETS[age_stage_index(stage)],
        &PACKET_AGE_BUCKETS_MS,
        age_ms,
    );
}

pub(crate) fn record_stale_drop(stage: VoiceAgeStage) {
    increment(&STALE_DROPS[age_stage_index(stage)], 1);
}

pub(crate) fn record_scheduler_delay(stage: VoiceSchedulerStage, delay: Duration) {
    let delay_us = delay.as_micros().min(u64::MAX as u128) as u64;
    observe_bucket(
        &SCHEDULER_DELAY_BUCKETS[scheduler_stage_index(stage)],
        &SCHEDULER_DELAY_BUCKETS_US,
        delay_us,
    );
}

pub(crate) fn record_route(
    source: VoiceRouteSource,
    kind: VoiceRouteKind,
    fanout: usize,
    duration: Duration,
) {
    let index = route_index(source, kind);
    increment(&ROUTED_FRAMES[index], 1);
    observe_bucket(&FANOUT_BUCKETS_TOTAL[index], &FANOUT_BUCKETS, fanout as u64);
    let duration_us = duration.as_micros().min(u64::MAX as u128) as u64;
    increment(&ROUTE_DURATION_TOTAL_US[index], duration_us);
    observe_bucket(
        &ROUTE_DURATION_BUCKETS[index],
        &ROUTE_DURATION_BUCKETS_US,
        duration_us,
    );
}

pub(crate) fn record_route_resolution(
    source: VoiceRouteSource,
    kind: VoiceRouteKind,
    duration: Duration,
) {
    let index = route_index(source, kind);
    let duration_us = duration.as_micros().min(u64::MAX as u128) as u64;
    increment(&ROUTE_RESOLUTION_DURATION_TOTAL_US[index], duration_us);
}

pub(crate) fn record_route_cache(source: VoiceRouteSource, layer: VoiceRouteCacheLayer, hit: bool) {
    let index = route_cache_index(source, layer);
    if hit {
        increment(&ROUTE_CACHE_HITS[index], 1);
    } else {
        increment(&ROUTE_CACHE_MISSES[index], 1);
    }
}

pub(crate) fn record_route_scope(source: VoiceRouteSource, scope: VoiceRouteScope) {
    increment(
        &ROUTE_SCOPE_RESOLUTIONS[route_scope_index(source, scope)],
        1,
    );
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct VoiceRouteMetricSnapshot {
    frames: u64,
    duration: Duration,
}

#[cfg(test)]
impl VoiceRouteMetricSnapshot {
    pub(crate) fn frames(self) -> u64 {
        self.frames
    }

    pub(crate) fn duration(self) -> Duration {
        self.duration
    }

    pub(crate) fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            frames: self.frames.saturating_sub(earlier.frames),
            duration: self.duration.saturating_sub(earlier.duration),
        }
    }
}

#[cfg(test)]
pub(crate) fn route_metric_snapshot(
    source: VoiceRouteSource,
    kind: VoiceRouteKind,
) -> VoiceRouteMetricSnapshot {
    let index = route_index(source, kind);
    VoiceRouteMetricSnapshot {
        frames: ROUTED_FRAMES[index].load(Ordering::Relaxed),
        duration: Duration::from_micros(ROUTE_DURATION_TOTAL_US[index].load(Ordering::Relaxed)),
    }
}

#[cfg(test)]
pub(crate) fn route_resolution_metric_snapshot(
    source: VoiceRouteSource,
    kind: VoiceRouteKind,
) -> VoiceRouteMetricSnapshot {
    let index = route_index(source, kind);
    VoiceRouteMetricSnapshot {
        frames: ROUTED_FRAMES[index].load(Ordering::Relaxed),
        duration: Duration::from_micros(
            ROUTE_RESOLUTION_DURATION_TOTAL_US[index].load(Ordering::Relaxed),
        ),
    }
}

pub(crate) fn record_dispatch(mode: VoiceDispatchMode) {
    increment(&DISPATCH_FRAMES[dispatch_mode_index(mode)], 1);
}

pub(crate) fn record_dispatch_tuning(plan: VoiceDispatchPlan, calibration_duration: Duration) {
    DISPATCH_TUNING_SMALL_THRESHOLD.store(
        plan.small_payload().fanout_threshold() as u64,
        Ordering::Relaxed,
    );
    DISPATCH_TUNING_SMALL_MIN_LEN.store(
        plan.small_payload().rayon_min_len() as u64,
        Ordering::Relaxed,
    );
    DISPATCH_TUNING_LARGE_THRESHOLD.store(
        plan.large_payload().fanout_threshold() as u64,
        Ordering::Relaxed,
    );
    DISPATCH_TUNING_LARGE_MIN_LEN.store(
        plan.large_payload().rayon_min_len() as u64,
        Ordering::Relaxed,
    );
    DISPATCH_TUNING_SOURCE.store(plan.source().metric_value(), Ordering::Relaxed);
    DISPATCH_TUNING_CALIBRATION_DURATION_US.store(
        calibration_duration.as_micros().min(u64::MAX as u128) as u64,
        Ordering::Relaxed,
    );
}

pub(crate) fn record_pipeline_stage(
    path: VoicePipelinePath,
    stage: VoicePipelineStage,
    duration: Duration,
) {
    let path_index = pipeline_path_index(path);
    let stage_index = pipeline_stage_index(stage);
    let duration_us = duration.as_micros().min(u64::MAX as u128) as u64;
    increment(&PIPELINE_STAGE_EVENTS[path_index][stage_index], 1);
    increment(
        &PIPELINE_STAGE_DURATION_TOTAL_US[path_index][stage_index],
        duration_us,
    );
    observe_bucket(
        &PIPELINE_STAGE_DURATION_BUCKETS[path_index][stage_index],
        &ROUTE_DURATION_BUCKETS_US,
        duration_us,
    );
}

pub(crate) fn record_egress(
    transport: VoiceEgressTransport,
    result: VoiceEgressResult,
    packets: usize,
    bytes: usize,
) {
    if packets == 0 && bytes == 0 {
        return;
    }
    let transport_index = egress_transport_index(transport);
    let result_index = egress_result_index(result);
    increment(
        &EGRESS_PACKETS[transport_index][result_index],
        packets as u64,
    );
    increment(&EGRESS_BYTES[transport_index][result_index], bytes as u64);
}

pub(crate) fn record_crypt_lock_contention_drop(packets: usize) {
    increment(&CRYPT_LOCK_CONTENTION_DROPS, packets as u64);
}

pub(crate) fn record_udp_send_result(result: VoiceUdpSendResult, events: u64) {
    if events == 0 {
        return;
    }
    increment(&UDP_SEND_EVENTS[udp_send_result_index(result)], events);
}

pub(crate) fn record_udp_recv_batch(datagrams: usize) {
    if datagrams == 0 {
        return;
    }
    increment(&UDP_RECV_BATCHES, 1);
    increment(&UDP_RECV_DATAGRAMS, datagrams as u64);
    observe_bucket(
        &UDP_RECV_BATCH_SIZE_BUCKETS,
        &VOICE_BATCH_SIZE_BUCKETS,
        datagrams as u64,
    );
}

pub(crate) fn record_udp_egress_batch(datagrams: usize, bytes: usize, duration: Duration) {
    if datagrams == 0 {
        return;
    }
    increment(&UDP_EGRESS_BATCHES, 1);
    increment(&UDP_EGRESS_DATAGRAMS, datagrams as u64);
    observe_bucket(
        &UDP_EGRESS_BATCH_SIZE_BUCKETS,
        &VOICE_BATCH_SIZE_BUCKETS,
        datagrams as u64,
    );
    observe_bucket(
        &UDP_EGRESS_BATCH_BYTES_BUCKETS,
        &VOICE_BATCH_BYTES_BUCKETS,
        bytes as u64,
    );
    observe_bucket(
        &UDP_EGRESS_SEND_DURATION_BUCKETS,
        &ROUTE_DURATION_BUCKETS_US,
        duration.as_micros().min(u64::MAX as u128) as u64,
    );
}

pub(crate) fn record_queue_status(kind: VoiceQueueKind, depth: usize, capacity: usize) {
    let mut status = QUEUE_STATUS[queue_kind_index(kind)].lock().unwrap();
    let depth = depth as u64;
    let capacity = capacity as u64;
    status.depth = depth;
    status.high_watermark = status.high_watermark.max(depth);
    status.capacity = capacity;
    status.samples = status.samples.saturating_add(1);
    if capacity > 0 && depth >= capacity {
        status.full_samples = status.full_samples.saturating_add(1);
    }
}

pub(crate) fn record_queue_enqueue(kind: VoiceQueueKind, result: VoiceQueueEnqueueResult) {
    increment(
        &QUEUE_ENQUEUES[queue_kind_index(kind)][queue_enqueue_result_index(result)],
        1,
    );
}

pub(crate) fn record_native_ingress_continuity(
    transport: VoiceIngressTransport,
    session: ClientSessionIdentifier,
    frame_number: u64,
    is_terminator: bool,
) {
    let origin_node = session.get_node_id();
    let session_key = (transport, session.to_u32());
    let mut state = CONTINUITY.lock().unwrap();
    *state
        .counters
        .entry((transport, origin_node, VoiceContinuityResult::Frame))
        .or_default() += 1;

    match state.sessions.insert(session_key, frame_number) {
        Some(previous) if frame_number > previous.saturating_add(1) => {
            *state
                .counters
                .entry((transport, origin_node, VoiceContinuityResult::ForwardGap))
                .or_default() += frame_number.saturating_sub(previous.saturating_add(1));
        }
        Some(previous) if frame_number <= previous => {
            *state
                .counters
                .entry((
                    transport,
                    origin_node,
                    VoiceContinuityResult::DuplicateOrOld,
                ))
                .or_default() += 1;
        }
        _ => {}
    }

    if is_terminator {
        *state
            .counters
            .entry((
                transport,
                origin_node,
                VoiceContinuityResult::ResetOrTerminator,
            ))
            .or_default() += 1;
    }
}

pub(crate) fn record_s2s_forward(sent: bool) {
    increment(&S2S_FORWARD_ATTEMPTS[usize::from(sent)], 1);
}

pub(crate) fn record_s2s_gateway_drop(
    direction: S2SVoiceGatewayDropDirection,
    reason: S2SVoiceGatewayDropReason,
) {
    increment(
        &S2S_GATEWAY_DROPS[s2s_gateway_drop_direction_index(direction)]
            [s2s_gateway_drop_reason_index(reason)],
        1,
    );
}

pub(crate) fn record_remote_playout_event(
    origin_node: NodeIdentifier,
    result: RemotePlayoutResult,
) {
    let mut metrics = REMOTE_PLAYOUT.lock().unwrap();
    *metrics.events.entry((origin_node, result)).or_default() += 1;
}

pub(crate) fn record_remote_playout_delay(origin_node: NodeIdentifier, delay_ms: u64) {
    REMOTE_PLAYOUT
        .lock()
        .unwrap()
        .selected_delay_ms
        .insert(origin_node, delay_ms);
}

pub(crate) fn record_remote_playout_release(origin_node: NodeIdentifier, lateness_ms: u64) {
    let mut metrics = REMOTE_PLAYOUT.lock().unwrap();
    *metrics
        .events
        .entry((origin_node, RemotePlayoutResult::Released))
        .or_default() += 1;
    let bucket = REMOTE_PLAYOUT_LATENESS_BUCKETS_MS
        .iter()
        .find_map(|(label, upper)| (lateness_ms <= *upper).then_some(*label))
        .unwrap_or("gt_250");
    *metrics
        .release_lateness_buckets
        .entry((origin_node, bucket))
        .or_default() += 1;
}

fn dispatch_tuning_source_label(value: u64) -> &'static str {
    match value {
        0 => VoiceDispatchPlanSource::StartupCalibrated.as_str(),
        1 => VoiceDispatchPlanSource::Fixed.as_str(),
        2 => VoiceDispatchPlanSource::Sequential.as_str(),
        _ => VoiceDispatchPlanSource::Fallback.as_str(),
    }
}

pub(crate) fn prometheus_samples() -> Vec<PrometheusSample> {
    let mut samples = Vec::new();

    for transport in [VoiceIngressTransport::Udp, VoiceIngressTransport::TcpTunnel] {
        let index = transport_index(transport);
        let labels = vec![("transport".to_owned(), transport.label().to_owned())];
        samples.push(PrometheusSample::new(
            "shitspeak_voice_ingress_packets_total",
            labels.clone(),
            INGRESS_PACKETS[index].load(Ordering::Relaxed) as f64,
        ));
        samples.push(PrometheusSample::new(
            "shitspeak_voice_ingress_bytes_total",
            labels,
            INGRESS_BYTES[index].load(Ordering::Relaxed) as f64,
        ));
    }

    for path in [UdpDecryptPath::Address, UdpDecryptPath::IpFallback] {
        for result in [
            UdpDecryptResult::Success,
            UdpDecryptResult::Failure,
            UdpDecryptResult::NoCryptState,
        ] {
            samples.push(PrometheusSample::new(
                "shitspeak_voice_udp_decrypt_attempts_total",
                vec![
                    ("path".to_owned(), path.label().to_owned()),
                    ("result".to_owned(), result.label().to_owned()),
                ],
                UDP_DECRYPT_ATTEMPTS[decrypt_path_index(path)][decrypt_result_index(result)]
                    .load(Ordering::Relaxed) as f64,
            ));
        }
    }

    samples.push(PrometheusSample::new(
        "shitspeak_voice_udp_ip_fallbacks_total",
        Vec::new(),
        UDP_IP_FALLBACKS.load(Ordering::Relaxed) as f64,
    ));
    for (index, (bucket, _)) in UDP_FALLBACK_CANDIDATE_BUCKETS.iter().enumerate() {
        samples.push(PrometheusSample::new(
            "shitspeak_voice_udp_ip_fallback_candidate_bucket_total",
            vec![("bucket".to_owned(), (*bucket).to_owned())],
            UDP_IP_FALLBACK_CANDIDATE_BUCKETS[index].load(Ordering::Relaxed) as f64,
        ));
    }

    for reason in [
        UdpDrainDropReason::ProcessingQueueFull,
        UdpDrainDropReason::ProcessingQueueClosed,
        UdpDrainDropReason::VoiceDisabled,
        UdpDrainDropReason::PacketTooShort,
        UdpDrainDropReason::PacketTooLarge,
        UdpDrainDropReason::PingDecodeFailed,
    ] {
        samples.push(PrometheusSample::new(
            "shitspeak_voice_udp_drain_drops_total",
            vec![("reason".to_owned(), reason.label().to_owned())],
            UDP_DRAIN_DROPS[udp_drain_drop_index(reason)].load(Ordering::Relaxed) as f64,
        ));
    }

    for reason in [
        VoiceQueueDropReason::RoutingQueueFullOrClosed,
        VoiceQueueDropReason::TcpQueueFull,
        VoiceQueueDropReason::TcpQueueClosed,
    ] {
        samples.push(PrometheusSample::new(
            "shitspeak_voice_queue_drops_total",
            vec![("reason".to_owned(), reason.label().to_owned())],
            QUEUE_DROPS[queue_drop_index(reason)].load(Ordering::Relaxed) as f64,
        ));
    }

    for stage in [VoiceAgeStage::UdpPacket, VoiceAgeStage::RoutingQueue] {
        for (bucket_index, (bucket, _)) in PACKET_AGE_BUCKETS_MS.iter().enumerate() {
            samples.push(PrometheusSample::new(
                "shitspeak_voice_packet_age_ms_bucket_total",
                vec![
                    ("stage".to_owned(), stage.label().to_owned()),
                    ("bucket".to_owned(), (*bucket).to_owned()),
                ],
                PACKET_AGE_BUCKETS[age_stage_index(stage)][bucket_index].load(Ordering::Relaxed)
                    as f64,
            ));
        }
        samples.push(PrometheusSample::new(
            "shitspeak_voice_stale_drops_total",
            vec![("stage".to_owned(), stage.label().to_owned())],
            STALE_DROPS[age_stage_index(stage)].load(Ordering::Relaxed) as f64,
        ));
    }

    for (source, kind) in ROUTE_DIMENSIONS {
        let index = route_index(source, kind);
        let labels = vec![
            ("source".to_owned(), source.label().to_owned()),
            ("kind".to_owned(), kind.label().to_owned()),
        ];
        samples.push(PrometheusSample::new(
            "shitspeak_voice_routed_frames_total",
            labels.clone(),
            ROUTED_FRAMES[index].load(Ordering::Relaxed) as f64,
        ));
        for (bucket_index, (bucket, _)) in FANOUT_BUCKETS.iter().enumerate() {
            let mut labels = labels.clone();
            labels.push(("bucket".to_owned(), (*bucket).to_owned()));
            samples.push(PrometheusSample::new(
                "shitspeak_voice_fanout_bucket_total",
                labels,
                FANOUT_BUCKETS_TOTAL[index][bucket_index].load(Ordering::Relaxed) as f64,
            ));
        }
        for (bucket_index, (bucket, _)) in ROUTE_DURATION_BUCKETS_US.iter().enumerate() {
            let mut labels = labels.clone();
            labels.push(("bucket".to_owned(), (*bucket).to_owned()));
            samples.push(PrometheusSample::new(
                "shitspeak_voice_route_duration_us_bucket_total",
                labels,
                ROUTE_DURATION_BUCKETS[index][bucket_index].load(Ordering::Relaxed) as f64,
            ));
        }
        samples.push(PrometheusSample::new(
            "shitspeak_voice_route_resolution_duration_us_total",
            labels,
            ROUTE_RESOLUTION_DURATION_TOTAL_US[index].load(Ordering::Relaxed) as f64,
        ));
    }

    for source in [VoiceRouteSource::Local, VoiceRouteSource::S2s] {
        for layer in [
            VoiceRouteCacheLayer::Topology,
            VoiceRouteCacheLayer::Authorization,
            VoiceRouteCacheLayer::Recipients,
        ] {
            let index = route_cache_index(source, layer);
            for (result, value) in [
                ("hit", ROUTE_CACHE_HITS[index].load(Ordering::Relaxed)),
                ("miss", ROUTE_CACHE_MISSES[index].load(Ordering::Relaxed)),
            ] {
                samples.push(PrometheusSample::new(
                    "shitspeak_voice_route_cache_events_total",
                    vec![
                        ("source".to_owned(), source.label().to_owned()),
                        ("layer".to_owned(), layer.label().to_owned()),
                        ("result".to_owned(), result.to_owned()),
                    ],
                    value as f64,
                ));
            }
        }
    }

    for source in [VoiceRouteSource::Local, VoiceRouteSource::S2s] {
        for scope in [
            VoiceRouteScope::Normal,
            VoiceRouteScope::TargetChannel,
            VoiceRouteScope::WholeServer,
        ] {
            samples.push(PrometheusSample::new(
                "shitspeak_voice_route_scope_resolutions_total",
                vec![
                    ("source".to_owned(), source.label().to_owned()),
                    ("scope".to_owned(), scope.label().to_owned()),
                ],
                ROUTE_SCOPE_RESOLUTIONS[route_scope_index(source, scope)].load(Ordering::Relaxed)
                    as f64,
            ));
        }
    }

    for stage in [
        VoiceSchedulerStage::UdpProcessing,
        VoiceSchedulerStage::RoutingTask,
    ] {
        for (bucket_index, (bucket, _)) in SCHEDULER_DELAY_BUCKETS_US.iter().enumerate() {
            samples.push(PrometheusSample::new(
                "shitspeak_voice_scheduler_delay_us_bucket_total",
                vec![
                    ("stage".to_owned(), stage.label().to_owned()),
                    ("bucket".to_owned(), (*bucket).to_owned()),
                ],
                SCHEDULER_DELAY_BUCKETS[scheduler_stage_index(stage)][bucket_index]
                    .load(Ordering::Relaxed) as f64,
            ));
        }
    }

    for mode in [VoiceDispatchMode::Sequential, VoiceDispatchMode::Rayon] {
        samples.push(PrometheusSample::new(
            "shitspeak_voice_dispatch_frames_total",
            vec![("mode".to_owned(), mode.label().to_owned())],
            DISPATCH_FRAMES[dispatch_mode_index(mode)].load(Ordering::Relaxed) as f64,
        ));
    }

    let dispatch_tuning_source =
        dispatch_tuning_source_label(DISPATCH_TUNING_SOURCE.load(Ordering::Relaxed));
    for (payload_class, threshold, min_len) in [
        (
            "le_512",
            DISPATCH_TUNING_SMALL_THRESHOLD.load(Ordering::Relaxed),
            DISPATCH_TUNING_SMALL_MIN_LEN.load(Ordering::Relaxed),
        ),
        (
            "gt_512",
            DISPATCH_TUNING_LARGE_THRESHOLD.load(Ordering::Relaxed),
            DISPATCH_TUNING_LARGE_MIN_LEN.load(Ordering::Relaxed),
        ),
    ] {
        for (setting, value) in [("fanout_threshold", threshold), ("rayon_min_len", min_len)] {
            samples.push(PrometheusSample::new(
                "shitspeak_voice_dispatch_tuning",
                vec![
                    ("payload_class".to_owned(), payload_class.to_owned()),
                    ("setting".to_owned(), setting.to_owned()),
                    ("source".to_owned(), dispatch_tuning_source.to_owned()),
                ],
                value as f64,
            ));
        }
    }
    samples.push(PrometheusSample::new(
        "shitspeak_voice_dispatch_calibration_duration_seconds",
        vec![("source".to_owned(), dispatch_tuning_source.to_owned())],
        DISPATCH_TUNING_CALIBRATION_DURATION_US.load(Ordering::Relaxed) as f64 / 1_000_000.0,
    ));

    for path in PIPELINE_PATHS {
        for stage in PIPELINE_STAGES {
            let path_index = pipeline_path_index(path);
            let stage_index = pipeline_stage_index(stage);
            let labels = vec![
                ("path".to_owned(), path.label().to_owned()),
                ("stage".to_owned(), stage.label().to_owned()),
            ];
            samples.push(PrometheusSample::new(
                "shitspeak_voice_pipeline_stage_events_total",
                labels.clone(),
                PIPELINE_STAGE_EVENTS[path_index][stage_index].load(Ordering::Relaxed) as f64,
            ));
            samples.push(PrometheusSample::new(
                "shitspeak_voice_pipeline_stage_duration_us_total",
                labels.clone(),
                PIPELINE_STAGE_DURATION_TOTAL_US[path_index][stage_index].load(Ordering::Relaxed)
                    as f64,
            ));
            for (bucket_index, (bucket, _)) in ROUTE_DURATION_BUCKETS_US.iter().enumerate() {
                let mut labels = labels.clone();
                labels.push(("bucket".to_owned(), (*bucket).to_owned()));
                samples.push(PrometheusSample::new(
                    "shitspeak_voice_pipeline_stage_duration_us_bucket_total",
                    labels,
                    PIPELINE_STAGE_DURATION_BUCKETS[path_index][stage_index][bucket_index]
                        .load(Ordering::Relaxed) as f64,
                ));
            }
        }
    }

    for transport in [VoiceEgressTransport::Udp, VoiceEgressTransport::TcpTunnel] {
        for result in [
            VoiceEgressResult::Queued,
            VoiceEgressResult::Sent,
            VoiceEgressResult::Dropped,
            VoiceEgressResult::Failed,
        ] {
            let transport_index = egress_transport_index(transport);
            let result_index = egress_result_index(result);
            let labels = vec![
                ("transport".to_owned(), transport.label().to_owned()),
                ("result".to_owned(), result.label().to_owned()),
            ];
            samples.push(PrometheusSample::new(
                "shitspeak_voice_egress_packets_total",
                labels.clone(),
                EGRESS_PACKETS[transport_index][result_index].load(Ordering::Relaxed) as f64,
            ));
            samples.push(PrometheusSample::new(
                "shitspeak_voice_egress_bytes_total",
                labels,
                EGRESS_BYTES[transport_index][result_index].load(Ordering::Relaxed) as f64,
            ));
        }
    }

    samples.push(PrometheusSample::new(
        "shitspeak_voice_crypt_lock_contention_drops_total",
        Vec::new(),
        CRYPT_LOCK_CONTENTION_DROPS.load(Ordering::Relaxed) as f64,
    ));
    for result in [
        VoiceUdpSendResult::WouldBlock,
        VoiceUdpSendResult::Partial,
        VoiceUdpSendResult::Failed,
        VoiceUdpSendResult::RetryBudgetExhausted,
    ] {
        samples.push(PrometheusSample::new(
            "shitspeak_voice_udp_send_events_total",
            vec![("result".to_owned(), result.label().to_owned())],
            UDP_SEND_EVENTS[udp_send_result_index(result)].load(Ordering::Relaxed) as f64,
        ));
    }
    samples.push(PrometheusSample::new(
        "shitspeak_voice_udp_recv_batches_total",
        Vec::new(),
        UDP_RECV_BATCHES.load(Ordering::Relaxed) as f64,
    ));
    samples.push(PrometheusSample::new(
        "shitspeak_voice_udp_recv_datagrams_total",
        Vec::new(),
        UDP_RECV_DATAGRAMS.load(Ordering::Relaxed) as f64,
    ));
    for (bucket_index, (bucket, _)) in VOICE_BATCH_SIZE_BUCKETS.iter().enumerate() {
        samples.push(PrometheusSample::new(
            "shitspeak_voice_udp_recv_batch_size_bucket_total",
            vec![("bucket".to_owned(), (*bucket).to_owned())],
            UDP_RECV_BATCH_SIZE_BUCKETS[bucket_index].load(Ordering::Relaxed) as f64,
        ));
        samples.push(PrometheusSample::new(
            "shitspeak_voice_udp_egress_batch_size_bucket_total",
            vec![("bucket".to_owned(), (*bucket).to_owned())],
            UDP_EGRESS_BATCH_SIZE_BUCKETS[bucket_index].load(Ordering::Relaxed) as f64,
        ));
    }
    samples.push(PrometheusSample::new(
        "shitspeak_voice_udp_egress_batches_total",
        Vec::new(),
        UDP_EGRESS_BATCHES.load(Ordering::Relaxed) as f64,
    ));
    samples.push(PrometheusSample::new(
        "shitspeak_voice_udp_egress_datagrams_total",
        Vec::new(),
        UDP_EGRESS_DATAGRAMS.load(Ordering::Relaxed) as f64,
    ));
    for (bucket_index, (bucket, _)) in VOICE_BATCH_BYTES_BUCKETS.iter().enumerate() {
        samples.push(PrometheusSample::new(
            "shitspeak_voice_udp_egress_batch_bytes_bucket_total",
            vec![("bucket".to_owned(), (*bucket).to_owned())],
            UDP_EGRESS_BATCH_BYTES_BUCKETS[bucket_index].load(Ordering::Relaxed) as f64,
        ));
    }
    for (bucket_index, (bucket, _)) in ROUTE_DURATION_BUCKETS_US.iter().enumerate() {
        samples.push(PrometheusSample::new(
            "shitspeak_voice_udp_egress_send_duration_us_bucket_total",
            vec![("bucket".to_owned(), (*bucket).to_owned())],
            UDP_EGRESS_SEND_DURATION_BUCKETS[bucket_index].load(Ordering::Relaxed) as f64,
        ));
    }

    {
        let state = CONTINUITY.lock().unwrap();
        for ((transport, origin_node, result), count) in &state.counters {
            samples.push(PrometheusSample::new(
                "shitspeak_voice_ingress_continuity_total",
                vec![
                    ("transport".to_owned(), transport.label().to_owned()),
                    ("origin_node".to_owned(), origin_node.to_string()),
                    ("result".to_owned(), result.label().to_owned()),
                ],
                *count as f64,
            ));
        }
    }

    {
        let state = REMOTE_PLAYOUT.lock().unwrap();
        for ((origin_node, result), count) in &state.events {
            samples.push(PrometheusSample::new(
                "shitspeak_voice_remote_playout_events_total",
                vec![
                    ("origin_node".to_owned(), origin_node.to_string()),
                    ("result".to_owned(), result.label().to_owned()),
                ],
                *count as f64,
            ));
        }
        for (origin_node, delay_ms) in &state.selected_delay_ms {
            samples.push(PrometheusSample::new(
                "shitspeak_voice_remote_playout_selected_delay_ms",
                vec![("origin_node".to_owned(), origin_node.to_string())],
                *delay_ms as f64,
            ));
        }
        for ((origin_node, bucket), count) in &state.release_lateness_buckets {
            samples.push(PrometheusSample::new(
                "shitspeak_voice_remote_playout_release_lateness_ms_bucket_total",
                vec![
                    ("origin_node".to_owned(), origin_node.to_string()),
                    ("bucket".to_owned(), (*bucket).to_owned()),
                ],
                *count as f64,
            ));
        }
    }

    for kind in [
        VoiceQueueKind::UdpProcessing,
        VoiceQueueKind::Routing,
        VoiceQueueKind::TcpFallback,
        VoiceQueueKind::UdpFanout,
    ] {
        let status = *QUEUE_STATUS[queue_kind_index(kind)].lock().unwrap();
        for (metric, value) in [
            ("depth", status.depth),
            ("high_watermark", status.high_watermark),
            ("capacity", status.capacity),
            ("samples", status.samples),
            ("full_samples", status.full_samples),
        ] {
            samples.push(PrometheusSample::new(
                "shitspeak_voice_queue_status",
                vec![
                    ("queue".to_owned(), kind.label().to_owned()),
                    ("metric".to_owned(), metric.to_owned()),
                ],
                value as f64,
            ));
        }
        for result in [
            VoiceQueueEnqueueResult::Accepted,
            VoiceQueueEnqueueResult::Full,
            VoiceQueueEnqueueResult::Closed,
            VoiceQueueEnqueueResult::Dropped,
        ] {
            samples.push(PrometheusSample::new(
                "shitspeak_voice_queue_enqueues_total",
                vec![
                    ("queue".to_owned(), kind.label().to_owned()),
                    ("result".to_owned(), result.label().to_owned()),
                ],
                QUEUE_ENQUEUES[queue_kind_index(kind)][queue_enqueue_result_index(result)]
                    .load(Ordering::Relaxed) as f64,
            ));
        }
    }

    for sent in [false, true] {
        samples.push(PrometheusSample::new(
            "shitspeak_voice_s2s_forward_attempts_total",
            vec![("sent".to_owned(), sent.to_string())],
            S2S_FORWARD_ATTEMPTS[usize::from(sent)].load(Ordering::Relaxed) as f64,
        ));
    }
    for direction in [
        S2SVoiceGatewayDropDirection::NativeToS2s,
        S2SVoiceGatewayDropDirection::S2sToNative,
    ] {
        for reason in [
            S2SVoiceGatewayDropReason::Unavailable,
            S2SVoiceGatewayDropReason::FullOrClosed,
        ] {
            samples.push(PrometheusSample::new(
                "shitspeak_voice_s2s_gateway_drops_total",
                vec![
                    ("direction".to_owned(), direction.label().to_owned()),
                    ("reason".to_owned(), reason.label().to_owned()),
                ],
                S2S_GATEWAY_DROPS[s2s_gateway_drop_direction_index(direction)]
                    [s2s_gateway_drop_reason_index(reason)]
                .load(Ordering::Relaxed) as f64,
            ));
        }
    }

    samples
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn sample_value(samples: &[PrometheusSample], name: &str, labels: &[(&str, &str)]) -> f64 {
        samples
            .iter()
            .filter(|sample| sample.name() == name)
            .filter(|sample| {
                labels.iter().all(|(key, value)| {
                    sample
                        .labels()
                        .iter()
                        .any(|(label_key, label_value)| label_key == key && label_value == value)
                })
            })
            .map(PrometheusSample::value)
            .sum()
    }

    #[test]
    fn dispatch_tuning_metrics_expose_the_resolved_profiles() {
        record_dispatch_tuning(VoiceDispatchPlan::conservative(), Duration::from_millis(12));

        let samples = prometheus_samples();
        assert_eq!(
            sample_value(
                &samples,
                "shitspeak_voice_dispatch_tuning",
                &[
                    ("payload_class", "le_512"),
                    ("setting", "fanout_threshold"),
                    ("source", "fallback"),
                ],
            ),
            512.0
        );
        assert_eq!(
            sample_value(
                &samples,
                "shitspeak_voice_dispatch_tuning",
                &[
                    ("payload_class", "gt_512"),
                    ("setting", "rayon_min_len"),
                    ("source", "fallback"),
                ],
            ),
            256.0
        );
        assert_eq!(
            sample_value(
                &samples,
                "shitspeak_voice_dispatch_calibration_duration_seconds",
                &[("source", "fallback")],
            ),
            0.012
        );
    }

    fn assert_no_unbounded_voice_labels(sample: &PrometheusSample) {
        for forbidden in ["session", "user", "ip", "channel"] {
            assert!(
                sample
                    .labels()
                    .iter()
                    .all(|(label, _)| label.as_str() != forbidden),
                "{forbidden} label must not be exported on {}",
                sample.name()
            );
        }
    }

    #[test]
    fn route_samples_use_only_real_route_dimensions() {
        let route_dimensions = prometheus_samples()
            .into_iter()
            .filter(|sample| sample.name() == "shitspeak_voice_routed_frames_total")
            .map(|sample| {
                let source = sample
                    .labels()
                    .iter()
                    .find_map(|(key, value)| (key == "source").then_some(value.as_str()))
                    .expect("source label");
                let kind = sample
                    .labels()
                    .iter()
                    .find_map(|(key, value)| (key == "kind").then_some(value.as_str()))
                    .expect("kind label");
                (source.to_owned(), kind.to_owned())
            })
            .collect::<BTreeSet<_>>();

        assert_eq!(
            route_dimensions,
            BTreeSet::from([
                ("local".to_owned(), "normal".to_owned()),
                ("local".to_owned(), "target".to_owned()),
                ("s2s".to_owned(), "normal".to_owned()),
                ("s2s".to_owned(), "target".to_owned()),
                ("loopback".to_owned(), "loopback".to_owned()),
            ])
        );
    }

    #[test]
    fn udp_batch_and_queue_metrics_record_diagnostic_buckets() {
        let before = prometheus_samples();

        record_udp_recv_batch(5);
        record_udp_egress_batch(17, 70_000, Duration::from_micros(6_000));
        record_udp_send_result(VoiceUdpSendResult::RetryBudgetExhausted, 2);
        record_queue_status(VoiceQueueKind::UdpFanout, 32, 32);
        record_queue_enqueue(VoiceQueueKind::UdpFanout, VoiceQueueEnqueueResult::Full);

        let after = prometheus_samples();
        assert!(
            sample_value(&after, "shitspeak_voice_udp_recv_batches_total", &[])
                >= sample_value(&before, "shitspeak_voice_udp_recv_batches_total", &[]) + 1.0
        );
        assert!(
            sample_value(
                &after,
                "shitspeak_voice_udp_recv_batch_size_bucket_total",
                &[("bucket", "5_8")]
            ) >= sample_value(
                &before,
                "shitspeak_voice_udp_recv_batch_size_bucket_total",
                &[("bucket", "5_8")]
            ) + 1.0
        );
        assert!(
            sample_value(
                &after,
                "shitspeak_voice_udp_egress_batch_size_bucket_total",
                &[("bucket", "17_32")]
            ) >= sample_value(
                &before,
                "shitspeak_voice_udp_egress_batch_size_bucket_total",
                &[("bucket", "17_32")]
            ) + 1.0
        );
        assert!(
            sample_value(
                &after,
                "shitspeak_voice_udp_egress_batch_bytes_bucket_total",
                &[("bucket", "gt_65536")]
            ) >= sample_value(
                &before,
                "shitspeak_voice_udp_egress_batch_bytes_bucket_total",
                &[("bucket", "gt_65536")]
            ) + 1.0
        );
        assert!(
            sample_value(
                &after,
                "shitspeak_voice_udp_send_events_total",
                &[("result", "retry_budget_exhausted")]
            ) >= sample_value(
                &before,
                "shitspeak_voice_udp_send_events_total",
                &[("result", "retry_budget_exhausted")]
            ) + 2.0
        );
        assert!(
            sample_value(
                &after,
                "shitspeak_voice_queue_enqueues_total",
                &[("queue", "udp_fanout"), ("result", "full")]
            ) >= sample_value(
                &before,
                "shitspeak_voice_queue_enqueues_total",
                &[("queue", "udp_fanout"), ("result", "full")]
            ) + 1.0
        );
        assert!(
            sample_value(
                &after,
                "shitspeak_voice_queue_status",
                &[("queue", "udp_fanout"), ("metric", "high_watermark")]
            ) >= 32.0
        );

        for sample in after.iter().filter(|sample| {
            matches!(
                sample.name(),
                "shitspeak_voice_udp_recv_batches_total"
                    | "shitspeak_voice_udp_recv_datagrams_total"
                    | "shitspeak_voice_udp_recv_batch_size_bucket_total"
                    | "shitspeak_voice_udp_egress_batches_total"
                    | "shitspeak_voice_udp_egress_datagrams_total"
                    | "shitspeak_voice_udp_egress_batch_size_bucket_total"
                    | "shitspeak_voice_udp_egress_batch_bytes_bucket_total"
                    | "shitspeak_voice_udp_egress_send_duration_us_bucket_total"
                    | "shitspeak_voice_queue_status"
                    | "shitspeak_voice_queue_enqueues_total"
            )
        }) {
            assert_no_unbounded_voice_labels(sample);
        }
    }

    #[test]
    fn native_ingress_continuity_aggregates_by_origin_node_only() {
        let session = ClientSessionIdentifier::new(4094, 77).expect("test session id");
        let before = prometheus_samples();

        record_native_ingress_continuity(VoiceIngressTransport::Udp, session, 10, false);
        record_native_ingress_continuity(VoiceIngressTransport::Udp, session, 12, false);
        record_native_ingress_continuity(VoiceIngressTransport::Udp, session, 12, false);
        record_native_ingress_continuity(VoiceIngressTransport::Udp, session, 13, true);

        let after = prometheus_samples();
        assert!(
            sample_value(
                &after,
                "shitspeak_voice_ingress_continuity_total",
                &[
                    ("transport", "udp"),
                    ("origin_node", "4094"),
                    ("result", "frame"),
                ]
            ) >= sample_value(
                &before,
                "shitspeak_voice_ingress_continuity_total",
                &[
                    ("transport", "udp"),
                    ("origin_node", "4094"),
                    ("result", "frame"),
                ]
            ) + 4.0
        );
        assert!(
            sample_value(
                &after,
                "shitspeak_voice_ingress_continuity_total",
                &[
                    ("transport", "udp"),
                    ("origin_node", "4094"),
                    ("result", "forward_gap"),
                ]
            ) >= sample_value(
                &before,
                "shitspeak_voice_ingress_continuity_total",
                &[
                    ("transport", "udp"),
                    ("origin_node", "4094"),
                    ("result", "forward_gap"),
                ]
            ) + 1.0
        );
        assert!(
            sample_value(
                &after,
                "shitspeak_voice_ingress_continuity_total",
                &[
                    ("transport", "udp"),
                    ("origin_node", "4094"),
                    ("result", "duplicate_or_old"),
                ]
            ) >= sample_value(
                &before,
                "shitspeak_voice_ingress_continuity_total",
                &[
                    ("transport", "udp"),
                    ("origin_node", "4094"),
                    ("result", "duplicate_or_old"),
                ]
            ) + 1.0
        );
        assert!(
            sample_value(
                &after,
                "shitspeak_voice_ingress_continuity_total",
                &[
                    ("transport", "udp"),
                    ("origin_node", "4094"),
                    ("result", "reset_or_terminator"),
                ]
            ) >= sample_value(
                &before,
                "shitspeak_voice_ingress_continuity_total",
                &[
                    ("transport", "udp"),
                    ("origin_node", "4094"),
                    ("result", "reset_or_terminator"),
                ]
            ) + 1.0
        );

        for sample in after
            .iter()
            .filter(|sample| sample.name() == "shitspeak_voice_ingress_continuity_total")
        {
            assert_no_unbounded_voice_labels(sample);
        }
    }

    #[test]
    fn remote_playout_repair_outcomes_are_reported_separately() {
        let origin_node = 77;
        let before = prometheus_samples();
        record_remote_playout_event(origin_node, RemotePlayoutResult::RepairBeforePlayout);
        record_remote_playout_event(origin_node, RemotePlayoutResult::RepairAfterPlayout);
        let after = prometheus_samples();

        for result in ["repair_before_playout", "repair_after_playout"] {
            assert!(
                sample_value(
                    &after,
                    "shitspeak_voice_remote_playout_events_total",
                    &[("origin_node", "77"), ("result", result)],
                ) >= sample_value(
                    &before,
                    "shitspeak_voice_remote_playout_events_total",
                    &[("origin_node", "77"), ("result", result)],
                ) + 1.0
            );
        }
    }
}
