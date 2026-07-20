//! Per-link telemetry: EWMA latency + RFC-3550-style jitter, packet loss, and
//! a sliding bandwidth meter. Aggregated per `(node, ServiceLevel)` so callers
//! can score path quality among co-existing transports.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex as StdMutex};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::types::NodeIdentifier;

use super::service_level::{MessageClass, RoutingMetric, ServiceLevel, TransportKind};

const E_MODEL_R0: f64 = 93.2;
const E_MODEL_DELAY_KNEE_MS: f64 = 177.3;
const E_MODEL_JITTER_BUFFER_FLOOR_MS: f64 = 20.0;
const E_MODEL_JITTER_BUFFER_MULTIPLIER: f64 = 4.0;
const E_MODEL_JITTER_IMPAIRMENT_FREE_MS: f64 = 5.0;
const E_MODEL_JITTER_IMPAIRMENT_PER_MS: f64 = 0.12;
const E_MODEL_PACKET_LOSS_ROBUSTNESS: f64 = 20.0;
const E_MODEL_BURST_RATIO: f64 = 1.0;
const E_MODEL_REFERENCE_THROUGHPUT_BYTES_PER_SEC: f64 = 24_000.0;
const E_MODEL_THROUGHPUT_IMPAIRMENT_PER_LOG2: f64 = 4.0;
const E_MODEL_MAX_THROUGHPUT_IMPAIRMENT: f64 = 20.0;
const DEFAULT_RELIABLE_THROUGHPUT_PENALTY_US_KBPS: f64 = 1_000_000.0;
const DEFAULT_RLL_JITTER_WEIGHT: f64 = 4.0;
const MAX_PACKET_LOSS_PPM: u32 = 1_000_000;
const DEFAULT_PACKET_LOSS_EWMA_ALPHA: f64 = 0.02;
const PACKET_LOSS_EWMA_METRIC_WEIGHT: f64 = 0.25;
// On reliable streams, an expired ping means "pong was not observed before our
// timeout", not necessarily packet loss. Native/data health counters are the
// stronger loss sources for TCP/KCP/QUIC, so stream probe loss is bounded.
const STREAM_PROBE_LOSS_METRIC_WEIGHT: f64 = 0.25;
const STREAM_PROBE_LOSS_EFFECTIVE_CAP_PPM: u32 = 100_000;
const NATIVE_LOSS_METRIC_WEIGHT: f64 = 0.5;
const DATA_HEALTH_METRIC_WEIGHT: f64 = 0.25;
const NATIVE_LOSS_EFFECTIVE_CAP_PPM: u32 = 250_000;
const DATA_HEALTH_EFFECTIVE_CAP_PPM: u32 = 100_000;
const LOSS_EFFECTIVE_SAMPLE_FLOOR: u64 = 32;
pub(crate) const QUEUE_WATERMARK_LOG_INTERVAL: Duration = Duration::from_secs(3 * 60);
const EXPIRED_OUTBOUND_DROP_STAGE_COUNT: usize = 3;
const EXPIRED_OUTBOUND_DROP_TRANSPORT_COUNT: usize = 5;
const MESSAGE_CLASS_COUNT: usize = 3;
const TRANSPORT_KIND_COUNT: usize = 4;
const TRANSPORT_PIPELINE_STAGE_COUNT: usize = 8;

const EXPIRED_OUTBOUND_DROP_STAGES: [ExpiredOutboundDropStage; EXPIRED_OUTBOUND_DROP_STAGE_COUNT] = [
    ExpiredOutboundDropStage::PeerQueueEnqueue,
    ExpiredOutboundDropStage::PeerQueueDispatch,
    ExpiredOutboundDropStage::TransportWrite,
];
const EXPIRED_OUTBOUND_DROP_TRANSPORTS: [Option<TransportKind>;
    EXPIRED_OUTBOUND_DROP_TRANSPORT_COUNT] = [
    None,
    Some(TransportKind::Tcp),
    Some(TransportKind::Kcp),
    Some(TransportKind::Quic),
    Some(TransportKind::Udp),
];
const MESSAGE_CLASSES: [MessageClass; MESSAGE_CLASS_COUNT] = [
    MessageClass::Control,
    MessageClass::HighPriority,
    MessageClass::Regular,
];
const TRANSPORT_KINDS: [TransportKind; TRANSPORT_KIND_COUNT] = [
    TransportKind::Tcp,
    TransportKind::Kcp,
    TransportKind::Quic,
    TransportKind::Udp,
];
const TRANSPORT_PIPELINE_STAGES: [TransportPipelineStage; TRANSPORT_PIPELINE_STAGE_COUNT] = [
    TransportPipelineStage::FrameEncode,
    TransportPipelineStage::FrameDecode,
    TransportPipelineStage::L1Compress,
    TransportPipelineStage::L1Decompress,
    TransportPipelineStage::UdpEncrypt,
    TransportPipelineStage::UdpDecrypt,
    TransportPipelineStage::StreamWrite,
    TransportPipelineStage::SocketWrite,
];
const TRANSPORT_PIPELINE_DURATION_BUCKETS_US: [(&str, u64); 8] = [
    ("le_100", 100),
    ("le_250", 250),
    ("le_500", 500),
    ("le_1000", 1_000),
    ("le_2500", 2_500),
    ("le_5000", 5_000),
    ("le_10000", 10_000),
    ("gt_10000", u64::MAX),
];
const TRANSPORT_IO_BATCH_SIZE_BUCKETS: [(&str, u64); 8] = [
    ("1", 1),
    ("2", 2),
    ("3_4", 4),
    ("5_8", 8),
    ("9_16", 16),
    ("17_32", 32),
    ("33_64", 64),
    ("65_plus", u64::MAX),
];

static TRANSPORT_IO: LazyLock<StdMutex<TransportIoMetrics>> =
    LazyLock::new(|| StdMutex::new(TransportIoMetrics::default()));

static TRANSPORT_PIPELINE_STAGE_EVENTS: [[AtomicU64; TRANSPORT_PIPELINE_STAGE_COUNT];
    TRANSPORT_KIND_COUNT] =
    [const { [const { AtomicU64::new(0) }; TRANSPORT_PIPELINE_STAGE_COUNT] }; TRANSPORT_KIND_COUNT];
static TRANSPORT_PIPELINE_STAGE_DURATION_TOTAL_US: [[AtomicU64; TRANSPORT_PIPELINE_STAGE_COUNT];
    TRANSPORT_KIND_COUNT] =
    [const { [const { AtomicU64::new(0) }; TRANSPORT_PIPELINE_STAGE_COUNT] }; TRANSPORT_KIND_COUNT];
static TRANSPORT_PIPELINE_STAGE_DURATION_BUCKETS: [[[AtomicU64;
    TRANSPORT_PIPELINE_DURATION_BUCKETS_US.len()];
    TRANSPORT_PIPELINE_STAGE_COUNT];
    TRANSPORT_KIND_COUNT] = [const {
    [const { [const { AtomicU64::new(0) }; TRANSPORT_PIPELINE_DURATION_BUCKETS_US.len()] };
        TRANSPORT_PIPELINE_STAGE_COUNT]
}; TRANSPORT_KIND_COUNT];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportPipelineStage {
    FrameEncode,
    FrameDecode,
    L1Compress,
    L1Decompress,
    UdpEncrypt,
    UdpDecrypt,
    StreamWrite,
    SocketWrite,
}

impl TransportPipelineStage {
    pub fn name(self) -> &'static str {
        match self {
            Self::FrameEncode => "frame_encode",
            Self::FrameDecode => "frame_decode",
            Self::L1Compress => "l1_compress",
            Self::L1Decompress => "l1_decompress",
            Self::UdpEncrypt => "udp_encrypt",
            Self::UdpDecrypt => "udp_decrypt",
            Self::StreamWrite => "stream_write",
            Self::SocketWrite => "socket_write",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportPipelineStageSnapshot {
    transport: TransportKind,
    stage: TransportPipelineStage,
    events: u64,
    duration_us: u64,
    buckets: [u64; TRANSPORT_PIPELINE_DURATION_BUCKETS_US.len()],
}

impl TransportPipelineStageSnapshot {
    pub fn transport(&self) -> TransportKind {
        self.transport
    }

    pub fn stage(&self) -> TransportPipelineStage {
        self.stage
    }

    pub fn events(&self) -> u64 {
        self.events
    }

    pub fn duration_us(&self) -> u64 {
        self.duration_us
    }

    pub fn buckets(&self) -> [(&'static str, u64); TRANSPORT_PIPELINE_DURATION_BUCKETS_US.len()] {
        std::array::from_fn(|index| {
            (
                TRANSPORT_PIPELINE_DURATION_BUCKETS_US[index].0,
                self.buckets[index],
            )
        })
    }
}

pub fn record_transport_pipeline_stage(
    transport: TransportKind,
    stage: TransportPipelineStage,
    duration: Duration,
) {
    let transport_index = transport_pipeline_kind_index(transport);
    let stage_index = transport_pipeline_stage_index(stage);
    let duration_us = duration.as_micros().min(u64::MAX as u128) as u64;
    TRANSPORT_PIPELINE_STAGE_EVENTS[transport_index][stage_index].fetch_add(1, Ordering::Relaxed);
    TRANSPORT_PIPELINE_STAGE_DURATION_TOTAL_US[transport_index][stage_index]
        .fetch_add(duration_us, Ordering::Relaxed);
    if let Some((bucket_index, _)) = TRANSPORT_PIPELINE_DURATION_BUCKETS_US
        .iter()
        .enumerate()
        .find(|(_, (_, upper_bound))| duration_us <= *upper_bound)
    {
        TRANSPORT_PIPELINE_STAGE_DURATION_BUCKETS[transport_index][stage_index][bucket_index]
            .fetch_add(1, Ordering::Relaxed);
    }
}

pub fn transport_pipeline_stage_snapshots() -> Vec<TransportPipelineStageSnapshot> {
    let mut out = Vec::new();
    for transport in TRANSPORT_KINDS {
        for stage in TRANSPORT_PIPELINE_STAGES {
            let transport_index = transport_pipeline_kind_index(transport);
            let stage_index = transport_pipeline_stage_index(stage);
            out.push(TransportPipelineStageSnapshot {
                transport,
                stage,
                events: TRANSPORT_PIPELINE_STAGE_EVENTS[transport_index][stage_index]
                    .load(Ordering::Relaxed),
                duration_us: TRANSPORT_PIPELINE_STAGE_DURATION_TOTAL_US[transport_index]
                    [stage_index]
                    .load(Ordering::Relaxed),
                buckets: std::array::from_fn(|bucket_index| {
                    TRANSPORT_PIPELINE_STAGE_DURATION_BUCKETS[transport_index][stage_index]
                        [bucket_index]
                        .load(Ordering::Relaxed)
                }),
            });
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportIoDirection {
    Ingress,
    Egress,
}

impl TransportIoDirection {
    pub fn name(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportIoPressureResult {
    WouldBlock,
    Partial,
    Timeout,
    Error,
}

impl TransportIoPressureResult {
    pub fn name(self) -> &'static str {
        match self {
            Self::WouldBlock => "would_block",
            Self::Partial => "partial",
            Self::Timeout => "timeout",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TransportIoKey {
    peer: NodeIdentifier,
    transport: TransportKind,
    direction: TransportIoDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TransportIoFrameKey {
    peer: NodeIdentifier,
    transport: TransportKind,
    direction: TransportIoDirection,
    class: MessageClass,
}

#[derive(Debug, Clone)]
struct TransportIoCounter {
    batches: u64,
    bytes: u64,
    batch_size_buckets: [u64; TRANSPORT_IO_BATCH_SIZE_BUCKETS.len()],
    pressure: [u64; TRANSPORT_IO_PRESSURE_RESULT_COUNT],
}

impl Default for TransportIoCounter {
    fn default() -> Self {
        Self {
            batches: 0,
            bytes: 0,
            batch_size_buckets: [0; TRANSPORT_IO_BATCH_SIZE_BUCKETS.len()],
            pressure: [0; TRANSPORT_IO_PRESSURE_RESULT_COUNT],
        }
    }
}

#[derive(Debug, Default)]
struct TransportIoMetrics {
    io: HashMap<TransportIoKey, TransportIoCounter>,
    frames: HashMap<TransportIoFrameKey, u64>,
}

const TRANSPORT_IO_PRESSURE_RESULT_COUNT: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportIoSnapshot {
    peer: NodeIdentifier,
    transport: TransportKind,
    direction: TransportIoDirection,
    batches: u64,
    bytes: u64,
    batch_size_buckets: [u64; TRANSPORT_IO_BATCH_SIZE_BUCKETS.len()],
    pressure: [u64; TRANSPORT_IO_PRESSURE_RESULT_COUNT],
}

impl TransportIoSnapshot {
    pub fn peer(&self) -> NodeIdentifier {
        self.peer
    }

    pub fn transport(&self) -> TransportKind {
        self.transport
    }

    pub fn direction(&self) -> TransportIoDirection {
        self.direction
    }

    pub fn batches(&self) -> u64 {
        self.batches
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn batch_size_buckets(
        &self,
    ) -> [(&'static str, u64); TRANSPORT_IO_BATCH_SIZE_BUCKETS.len()] {
        std::array::from_fn(|index| {
            (
                TRANSPORT_IO_BATCH_SIZE_BUCKETS[index].0,
                self.batch_size_buckets[index],
            )
        })
    }

    pub fn pressure(
        &self,
    ) -> [(TransportIoPressureResult, u64); TRANSPORT_IO_PRESSURE_RESULT_COUNT] {
        std::array::from_fn(|index| (transport_io_pressure_result(index), self.pressure[index]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportIoFrameSnapshot {
    peer: NodeIdentifier,
    transport: TransportKind,
    direction: TransportIoDirection,
    class: MessageClass,
    frames: u64,
}

impl TransportIoFrameSnapshot {
    pub fn peer(&self) -> NodeIdentifier {
        self.peer
    }

    pub fn transport(&self) -> TransportKind {
        self.transport
    }

    pub fn direction(&self) -> TransportIoDirection {
        self.direction
    }

    pub fn class(&self) -> MessageClass {
        self.class
    }

    pub fn frames(&self) -> u64 {
        self.frames
    }
}

pub fn record_transport_io_batch(
    peer: NodeIdentifier,
    transport: TransportKind,
    direction: TransportIoDirection,
    frames: usize,
    bytes: usize,
) {
    if frames == 0 && bytes == 0 {
        return;
    }
    let mut metrics = TRANSPORT_IO.lock().unwrap();
    let entry = metrics
        .io
        .entry(TransportIoKey {
            peer,
            transport,
            direction,
        })
        .or_default();
    entry.batches = entry.batches.saturating_add(1);
    entry.bytes = entry.bytes.saturating_add(bytes as u64);
    if let Some((bucket_index, _)) = TRANSPORT_IO_BATCH_SIZE_BUCKETS
        .iter()
        .enumerate()
        .find(|(_, (_, upper_bound))| frames as u64 <= *upper_bound)
    {
        entry.batch_size_buckets[bucket_index] =
            entry.batch_size_buckets[bucket_index].saturating_add(1);
    }
}

pub fn record_transport_io_frames(
    peer: NodeIdentifier,
    transport: TransportKind,
    direction: TransportIoDirection,
    class: MessageClass,
    frames: usize,
) {
    if frames == 0 {
        return;
    }
    let mut metrics = TRANSPORT_IO.lock().unwrap();
    let entry = metrics
        .frames
        .entry(TransportIoFrameKey {
            peer,
            transport,
            direction,
            class,
        })
        .or_default();
    *entry = entry.saturating_add(frames as u64);
}

pub fn record_transport_io_pressure(
    peer: NodeIdentifier,
    transport: TransportKind,
    direction: TransportIoDirection,
    result: TransportIoPressureResult,
    events: u64,
) {
    if events == 0 {
        return;
    }
    let mut metrics = TRANSPORT_IO.lock().unwrap();
    let entry = metrics
        .io
        .entry(TransportIoKey {
            peer,
            transport,
            direction,
        })
        .or_default();
    entry.pressure[transport_io_pressure_result_index(result)] =
        entry.pressure[transport_io_pressure_result_index(result)].saturating_add(events);
}

pub fn transport_io_snapshots() -> Vec<TransportIoSnapshot> {
    let metrics = TRANSPORT_IO.lock().unwrap();
    let mut out = metrics
        .io
        .iter()
        .map(|(key, counter)| TransportIoSnapshot {
            peer: key.peer,
            transport: key.transport,
            direction: key.direction,
            batches: counter.batches,
            bytes: counter.bytes,
            batch_size_buckets: counter.batch_size_buckets,
            pressure: counter.pressure,
        })
        .collect::<Vec<_>>();
    out.sort_by_key(|snapshot| {
        (
            snapshot.peer,
            transport_pipeline_kind_index(snapshot.transport),
            match snapshot.direction {
                TransportIoDirection::Ingress => 0u8,
                TransportIoDirection::Egress => 1u8,
            },
        )
    });
    out
}

pub fn transport_io_frame_snapshots() -> Vec<TransportIoFrameSnapshot> {
    let metrics = TRANSPORT_IO.lock().unwrap();
    let mut out = metrics
        .frames
        .iter()
        .map(|(key, frames)| TransportIoFrameSnapshot {
            peer: key.peer,
            transport: key.transport,
            direction: key.direction,
            class: key.class,
            frames: *frames,
        })
        .collect::<Vec<_>>();
    out.sort_by_key(|snapshot| {
        (
            snapshot.peer,
            transport_pipeline_kind_index(snapshot.transport),
            match snapshot.direction {
                TransportIoDirection::Ingress => 0u8,
                TransportIoDirection::Egress => 1u8,
            },
            message_class_index(snapshot.class),
        )
    });
    out
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueStatusSnapshot {
    high_depth: usize,
    depth: usize,
    capacity: usize,
    samples: u64,
    full_samples: u64,
}

impl QueueStatusSnapshot {
    pub(crate) fn new(
        high_depth: usize,
        depth: usize,
        capacity: usize,
        samples: u64,
        full_samples: u64,
    ) -> Self {
        Self {
            high_depth,
            depth,
            capacity,
            samples,
            full_samples,
        }
    }

    pub(crate) fn with_current(self, depth: usize, capacity: usize) -> Self {
        Self {
            high_depth: self.high_depth.max(depth),
            depth,
            capacity,
            samples: self.samples,
            full_samples: self.full_samples,
        }
    }

    pub fn high_depth(&self) -> usize {
        self.high_depth
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn samples(&self) -> u64 {
        self.samples
    }

    pub fn full_samples(&self) -> u64 {
        self.full_samples
    }
}

#[derive(Debug)]
pub(crate) struct QueueWatermark {
    high_depth: usize,
    last_depth: usize,
    capacity: usize,
    samples: u64,
    full_samples: u64,
    last_report: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueueWatermarkReport {
    status: QueueStatusSnapshot,
    interval: Duration,
}

impl QueueWatermarkReport {
    pub(crate) fn status(&self) -> QueueStatusSnapshot {
        self.status
    }

    pub(crate) fn interval(&self) -> Duration {
        self.interval
    }
}

impl QueueWatermark {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            high_depth: 0,
            last_depth: 0,
            capacity: 0,
            samples: 0,
            full_samples: 0,
            last_report: now,
        }
    }

    pub(crate) fn record(
        &mut self,
        now: Instant,
        depth: usize,
        capacity: usize,
        is_full: bool,
    ) -> Option<QueueWatermarkReport> {
        self.high_depth = self.high_depth.max(depth);
        self.last_depth = depth;
        self.capacity = capacity;
        self.samples = self.samples.saturating_add(1);
        if is_full {
            self.full_samples = self.full_samples.saturating_add(1);
        }

        let interval = now.duration_since(self.last_report);
        if interval < QUEUE_WATERMARK_LOG_INTERVAL {
            return None;
        }

        let report = QueueWatermarkReport {
            status: self.snapshot(),
            interval,
        };
        self.high_depth = 0;
        self.last_depth = depth;
        self.capacity = capacity;
        self.samples = 0;
        self.full_samples = 0;
        self.last_report = now;
        Some(report)
    }

    pub(crate) fn snapshot(&self) -> QueueStatusSnapshot {
        QueueStatusSnapshot::new(
            self.high_depth,
            self.last_depth,
            self.capacity,
            self.samples,
            self.full_samples,
        )
    }
}

pub fn apply_packet_loss_penalty(cost: f64, packet_loss_ppm: u32) -> f64 {
    let success = 1.0 - (packet_loss_ppm.min(999_999) as f64 / MAX_PACKET_LOSS_PPM as f64);
    (cost / success.max(0.001)).max(1.0)
}

pub fn conversational_effective_delay_us(rtt_us: f64, jitter_us: f64) -> u64 {
    let one_way_ms = rtt_us.max(1.0) / 2_000.0;
    let jitter_ms = jitter_us.max(0.0) / 1_000.0;
    let jitter_buffer_ms =
        E_MODEL_JITTER_BUFFER_FLOOR_MS.max(jitter_ms * E_MODEL_JITTER_BUFFER_MULTIPLIER);
    ((one_way_ms + jitter_buffer_ms) * 1_000.0).ceil() as u64
}

pub fn conversational_impairment(
    rtt_us: f64,
    jitter_us: f64,
    throughput_bytes_per_sec: f64,
    packet_loss_ppm: u32,
) -> f64 {
    let delay_ms = conversational_effective_delay_us(rtt_us, jitter_us) as f64 / 1_000.0;
    let delay_impairment = 0.024 * delay_ms
        + if delay_ms > E_MODEL_DELAY_KNEE_MS {
            0.11 * (delay_ms - E_MODEL_DELAY_KNEE_MS)
        } else {
            0.0
        };

    let jitter_ms = jitter_us.max(0.0) / 1_000.0;
    let jitter_impairment = ((jitter_ms - E_MODEL_JITTER_IMPAIRMENT_FREE_MS).max(0.0)
        * E_MODEL_JITTER_IMPAIRMENT_PER_MS)
        .min(15.0);

    let loss_pct = (packet_loss_ppm as f64 / 10_000.0).clamp(0.0, 100.0);
    let loss_impairment = if loss_pct <= 0.0 {
        0.0
    } else {
        (95.0 * loss_pct * E_MODEL_BURST_RATIO) / (loss_pct + E_MODEL_PACKET_LOSS_ROBUSTNESS)
    };

    let throughput = throughput_bytes_per_sec.max(1.0);
    let throughput_impairment = if throughput >= E_MODEL_REFERENCE_THROUGHPUT_BYTES_PER_SEC {
        0.0
    } else {
        (E_MODEL_REFERENCE_THROUGHPUT_BYTES_PER_SEC / throughput).log2()
            * E_MODEL_THROUGHPUT_IMPAIRMENT_PER_LOG2
    }
    .clamp(0.0, E_MODEL_MAX_THROUGHPUT_IMPAIRMENT);

    delay_impairment + jitter_impairment + loss_impairment + throughput_impairment
}

pub fn conversational_quality_score(
    rtt_us: f64,
    jitter_us: f64,
    throughput_bytes_per_sec: f64,
    packet_loss_ppm: u32,
) -> f64 {
    (E_MODEL_R0
        - conversational_impairment(rtt_us, jitter_us, throughput_bytes_per_sec, packet_loss_ppm))
    .clamp(0.0, 100.0)
}

/// EWMA smoothing coefficients for [`PeerMetrics`]. Values are configured
/// in [`super::config::TransportConfig`]; the [`Default`] impl mirrors
/// the historical hard-coded constants.
#[derive(Debug, Clone, Copy)]
pub struct MetricsTuning {
    /// Smoothing coefficient for the latency EWMA.
    pub latency_alpha: f64,
    /// Smoothing coefficient for the jitter EWMA (RFC 3550 uses 1/16).
    pub jitter_alpha: f64,
    /// Smoothing coefficient for the long-term packet-loss EWMA.
    pub packet_loss_alpha: f64,
}

impl Default for MetricsTuning {
    fn default() -> Self {
        Self {
            latency_alpha: 0.2,
            jitter_alpha: 1.0 / 16.0,
            packet_loss_alpha: DEFAULT_PACKET_LOSS_EWMA_ALPHA,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KcpRuntimeMetricsSnapshot {
    closed: bool,
    pending_sender: bool,
    waiting_conv: bool,
    wait_snd: u64,
    snd_wnd: u64,
    rmt_wnd: u64,
    input_queue_drops: u64,
    no_progress_closes: u64,
    last_input_age_ms: Option<u64>,
    outstanding_no_progress_age_ms: Option<u64>,
}

impl KcpRuntimeMetricsSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        closed: bool,
        pending_sender: bool,
        waiting_conv: bool,
        wait_snd: u64,
        snd_wnd: u64,
        rmt_wnd: u64,
        input_queue_drops: u64,
        no_progress_closes: u64,
        last_input_age_ms: Option<u64>,
        outstanding_no_progress_age_ms: Option<u64>,
    ) -> Self {
        Self {
            closed,
            pending_sender,
            waiting_conv,
            wait_snd,
            snd_wnd,
            rmt_wnd,
            input_queue_drops,
            no_progress_closes,
            last_input_age_ms,
            outstanding_no_progress_age_ms,
        }
    }

    pub fn closed(&self) -> bool {
        self.closed
    }

    pub fn pending_sender(&self) -> bool {
        self.pending_sender
    }

    pub fn waiting_conv(&self) -> bool {
        self.waiting_conv
    }

    pub fn wait_snd(&self) -> u64 {
        self.wait_snd
    }

    pub fn snd_wnd(&self) -> u64 {
        self.snd_wnd
    }

    pub fn rmt_wnd(&self) -> u64 {
        self.rmt_wnd
    }

    pub fn input_queue_drops(&self) -> u64 {
        self.input_queue_drops
    }

    pub fn no_progress_closes(&self) -> u64 {
        self.no_progress_closes
    }

    pub fn last_input_age_ms(&self) -> Option<u64> {
        self.last_input_age_ms
    }

    pub fn outstanding_no_progress_age_ms(&self) -> Option<u64> {
        self.outstanding_no_progress_age_ms
    }
}

#[derive(Debug, Clone, Default)]
pub struct LinkMetrics {
    /// Smoothed round-trip time in microseconds.
    rtt_us: f64,
    /// Smoothed |Δrtt| in microseconds (jitter).
    jitter_us: f64,
    /// Data payload bytes received since the window started.
    recv_bytes: u64,
    /// Data payload bytes sent since the window started.
    sent_bytes: u64,
    /// Encoded transport-frame bytes received since the window started.
    wire_recv_bytes: u64,
    /// Encoded transport-frame bytes sent since the window started.
    wire_sent_bytes: u64,
    /// Original data payload bytes sent through the L1 compression path.
    l1_uncompressed_sent_bytes: u64,
    /// Encoded data payload bytes sent after L1 compression or identity.
    l1_encoded_sent_bytes: u64,
    /// Original data payload bytes received through the L1 compression path.
    l1_uncompressed_recv_bytes: u64,
    /// Encoded data payload bytes received before L1 decompression.
    l1_encoded_recv_bytes: u64,
    /// The wall-clock window over which `recv_bytes` / `sent_bytes` apply.
    window: Duration,
    /// Transport health loss breakdown. The legacy `packet_loss_ppm()` getter
    /// intentionally returns the conservative effective value from this model.
    loss: LossBreakdown,
    samples: u64,
    last_update: Option<Instant>,
    throughput_confidence_ppm: u32,
    unmatched_probe_pongs: u64,
    consecutive_probe_losses: u32,
    kcp_runtime: Option<KcpRuntimeMetricsSnapshot>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LossBreakdown {
    probe_loss_ppm: u32,
    probe_loss_ewma_ppm: u32,
    native_loss_ppm: u32,
    native_loss_ewma_ppm: u32,
    data_health_ppm: u32,
    effective_loss_ppm: u32,
    probe_sample_count: u64,
    lost_probe_sample_count: u64,
    probe_loss_ewma_sample_count: u64,
    native_sample_count: u64,
    native_lost_sample_count: u64,
    data_health_sample_count: u64,
    data_health_failure_count: u64,
    loss_sample_count: u64,
}

impl LossBreakdown {
    #[allow(clippy::too_many_arguments)]
    fn from_components(
        transport: TransportKind,
        probe_loss_ppm: u32,
        probe_loss_ewma_ppm: u32,
        probe_loss_ewma_sample_count: u64,
        probe_sample_count: u64,
        lost_probe_sample_count: u64,
        native_loss_ppm: u32,
        native_loss_ewma_ppm: u32,
        native_sample_count: u64,
        native_lost_sample_count: u64,
        data_health_ppm: u32,
        data_health_sample_count: u64,
        data_health_failure_count: u64,
    ) -> Self {
        let effective_loss_ppm = effective_loss_ppm(
            transport,
            probe_loss_ppm,
            probe_loss_ewma_ppm,
            probe_loss_ewma_sample_count,
            probe_sample_count,
            native_loss_ppm,
            native_sample_count,
            data_health_ppm,
            data_health_sample_count,
        );
        Self {
            probe_loss_ppm,
            probe_loss_ewma_ppm,
            native_loss_ppm,
            native_loss_ewma_ppm,
            data_health_ppm,
            effective_loss_ppm,
            probe_sample_count,
            lost_probe_sample_count,
            probe_loss_ewma_sample_count,
            native_sample_count,
            native_lost_sample_count,
            data_health_sample_count,
            data_health_failure_count,
            loss_sample_count: probe_sample_count
                .saturating_add(native_sample_count)
                .saturating_add(data_health_sample_count),
        }
    }

    pub fn probe_loss_ppm(&self) -> u32 {
        self.probe_loss_ppm
    }

    pub fn probe_loss_ewma_ppm(&self) -> u32 {
        self.probe_loss_ewma_ppm
    }

    pub fn native_loss_ppm(&self) -> u32 {
        self.native_loss_ppm
    }

    pub fn native_loss_ewma_ppm(&self) -> u32 {
        self.native_loss_ewma_ppm
    }

    pub fn data_health_ppm(&self) -> u32 {
        self.data_health_ppm
    }

    pub fn effective_loss_ppm(&self) -> u32 {
        self.effective_loss_ppm
    }

    pub fn probe_sample_count(&self) -> u64 {
        self.probe_sample_count
    }

    pub fn lost_probe_sample_count(&self) -> u64 {
        self.lost_probe_sample_count
    }

    pub fn probe_loss_ewma_sample_count(&self) -> u64 {
        self.probe_loss_ewma_sample_count
    }

    pub fn native_sample_count(&self) -> u64 {
        self.native_sample_count
    }

    pub fn native_lost_sample_count(&self) -> u64 {
        self.native_lost_sample_count
    }

    pub fn data_health_sample_count(&self) -> u64 {
        self.data_health_sample_count
    }

    pub fn data_health_failure_count(&self) -> u64 {
        self.data_health_failure_count
    }

    pub fn loss_sample_count(&self) -> u64 {
        self.loss_sample_count
    }
}

impl LinkMetrics {
    pub fn rtt_us(&self) -> f64 {
        self.rtt_us
    }

    pub fn jitter_us(&self) -> f64 {
        self.jitter_us
    }

    pub fn recv_bytes(&self) -> u64 {
        self.recv_bytes
    }

    pub fn sent_bytes(&self) -> u64 {
        self.sent_bytes
    }

    pub fn wire_recv_bytes(&self) -> u64 {
        self.wire_recv_bytes
    }

    pub fn wire_sent_bytes(&self) -> u64 {
        self.wire_sent_bytes
    }

    pub fn l1_uncompressed_sent_bytes(&self) -> u64 {
        self.l1_uncompressed_sent_bytes
    }

    pub fn l1_encoded_sent_bytes(&self) -> u64 {
        self.l1_encoded_sent_bytes
    }

    pub fn l1_uncompressed_recv_bytes(&self) -> u64 {
        self.l1_uncompressed_recv_bytes
    }

    pub fn l1_encoded_recv_bytes(&self) -> u64 {
        self.l1_encoded_recv_bytes
    }

    pub fn window(&self) -> Duration {
        self.window
    }

    pub fn loss_breakdown(&self) -> LossBreakdown {
        self.loss
    }

    pub fn packet_loss_ppm(&self) -> u32 {
        self.effective_packet_loss_ppm()
    }

    pub fn packet_loss_ewma_ppm(&self) -> u32 {
        self.loss.probe_loss_ewma_ppm()
    }

    pub fn effective_packet_loss_ppm(&self) -> u32 {
        self.loss.effective_loss_ppm()
    }

    pub fn probe_loss_ppm(&self) -> u32 {
        self.loss.probe_loss_ppm()
    }

    pub fn probe_loss_ewma_ppm(&self) -> u32 {
        self.loss.probe_loss_ewma_ppm()
    }

    pub fn native_loss_ppm(&self) -> u32 {
        self.loss.native_loss_ppm()
    }

    pub fn native_loss_ewma_ppm(&self) -> u32 {
        self.loss.native_loss_ewma_ppm()
    }

    pub fn data_health_ppm(&self) -> u32 {
        self.loss.data_health_ppm()
    }

    pub fn loss_sample_count(&self) -> u64 {
        self.loss.loss_sample_count()
    }

    pub fn native_loss_samples(&self) -> u64 {
        self.loss.native_sample_count()
    }

    pub fn native_lost_samples(&self) -> u64 {
        self.loss.native_lost_sample_count()
    }

    pub fn data_health_samples(&self) -> u64 {
        self.loss.data_health_sample_count()
    }

    pub fn data_health_failures(&self) -> u64 {
        self.loss.data_health_failure_count()
    }

    pub fn probe_packets(&self) -> u64 {
        self.loss.probe_sample_count()
    }

    pub fn lost_probe_packets(&self) -> u64 {
        self.loss.lost_probe_sample_count()
    }

    pub fn unmatched_probe_pongs(&self) -> u64 {
        self.unmatched_probe_pongs
    }

    pub fn consecutive_probe_losses(&self) -> u32 {
        self.consecutive_probe_losses
    }

    pub fn kcp_runtime(&self) -> Option<&KcpRuntimeMetricsSnapshot> {
        self.kcp_runtime.as_ref()
    }

    pub fn samples(&self) -> u64 {
        self.samples
    }

    pub fn last_update(&self) -> Option<Instant> {
        self.last_update
    }

    /// Approximate average inbound bandwidth in bytes/sec over the current window.
    pub fn recv_bps(&self) -> f64 {
        if self.window.is_zero() {
            return 0.0;
        }
        (self.recv_bytes as f64) / self.window.as_secs_f64()
    }

    /// Approximate average outbound bandwidth in bytes/sec over the current window.
    pub fn sent_bps(&self) -> f64 {
        if self.window.is_zero() {
            return 0.0;
        }
        (self.sent_bytes as f64) / self.window.as_secs_f64()
    }

    pub fn observed_recv_bps(&self) -> f64 {
        self.recv_bps()
    }

    pub fn observed_sent_bps(&self) -> f64 {
        self.sent_bps()
    }

    pub fn throughput_confidence_ppm(&self) -> u32 {
        self.throughput_confidence_ppm
    }

    pub fn wire_recv_bps(&self) -> f64 {
        if self.window.is_zero() {
            return 0.0;
        }
        (self.wire_recv_bytes as f64) / self.window.as_secs_f64()
    }

    pub fn wire_sent_bps(&self) -> f64 {
        if self.window.is_zero() {
            return 0.0;
        }
        (self.wire_sent_bytes as f64) / self.window.as_secs_f64()
    }

    pub fn l1_compression_sent_ratio(&self) -> Option<f64> {
        compression_ratio(self.l1_encoded_sent_bytes, self.l1_uncompressed_sent_bytes)
    }

    pub fn l1_compression_recv_ratio(&self) -> Option<f64> {
        compression_ratio(self.l1_encoded_recv_bytes, self.l1_uncompressed_recv_bytes)
    }

    pub fn l1_compression_total_ratio(&self) -> Option<f64> {
        compression_ratio(
            self.l1_encoded_sent_bytes
                .saturating_add(self.l1_encoded_recv_bytes),
            self.l1_uncompressed_sent_bytes
                .saturating_add(self.l1_uncompressed_recv_bytes),
        )
    }

    /// Passive outbound payload throughput in bytes/sec. This is a lower bound
    /// based only on real application data, not active probes.
    pub fn estimated_throughput_bps(&self) -> f64 {
        self.observed_sent_bps()
    }

    /// E-model-inspired conversational link-quality score. Higher is better.
    /// Packet loss uses the rolling estimate with a lower-weight long-term
    /// EWMA floor so persistent reliability issues still influence ranking.
    ///
    /// Links without RTT samples are left unranked so the dial scheduler can
    /// prefer peers with observed quality.
    pub fn quality_score(&self) -> Option<f64> {
        if self.samples == 0 {
            return None;
        }

        Some(
            conversational_quality_score(
                self.rtt_us,
                self.jitter_us,
                self.estimated_throughput_bps(),
                self.effective_packet_loss_ppm(),
            ) * 1_000.0,
        )
    }

    /// Cost of this link under the sender-selected route metric. Lower is
    /// better. Links without RTT samples are left unranked.
    pub fn routing_cost(&self, _level: ServiceLevel, metric: RoutingMetric) -> Option<f64> {
        if self.samples == 0 {
            return None;
        }

        Some(match metric {
            RoutingMetric::ReliableCost => self.reliable_cost(),
            RoutingMetric::ReliableLowLatencyCost => self.reliable_low_latency_cost(),
            RoutingMetric::BestEffortCost => self.best_effort_cost(),
            RoutingMetric::ConversationalQuality => conversational_impairment(
                self.rtt_us,
                self.jitter_us,
                self.estimated_throughput_bps(),
                self.effective_packet_loss_ppm(),
            ),
        })
    }

    fn best_effort_cost(&self) -> f64 {
        apply_packet_loss_penalty(self.rtt_us.max(1.0), self.effective_packet_loss_ppm())
    }

    fn reliable_low_latency_cost(&self) -> f64 {
        apply_packet_loss_penalty(
            (self.rtt_us + DEFAULT_RLL_JITTER_WEIGHT * self.jitter_us).max(1.0),
            self.effective_packet_loss_ppm(),
        )
    }

    fn reliable_cost(&self) -> f64 {
        let throughput_kbps = (self.estimated_throughput_bps() / 1024.0).max(1.0);
        let penalty = DEFAULT_RELIABLE_THROUGHPUT_PENALTY_US_KBPS / throughput_kbps;
        apply_packet_loss_penalty(
            (self.rtt_us + penalty).max(1.0),
            self.effective_packet_loss_ppm(),
        )
    }
}

fn compression_ratio(encoded_bytes: u64, uncompressed_bytes: u64) -> Option<f64> {
    if uncompressed_bytes == 0 {
        None
    } else {
        Some(encoded_bytes as f64 / uncompressed_bytes as f64)
    }
}

fn probe_effective_loss_ppm(
    transport: TransportKind,
    rolling_ppm: u32,
    ewma_ppm: u32,
    ewma_sample_count: u64,
    rolling_sample_count: u64,
) -> u32 {
    let rolling_effective = if rolling_sample_count >= LOSS_EFFECTIVE_SAMPLE_FLOOR {
        rolling_ppm
    } else {
        0
    };
    let ewma_effective = if ewma_sample_count >= LOSS_EFFECTIVE_SAMPLE_FLOOR {
        capped_weighted_ppm(
            ewma_ppm,
            PACKET_LOSS_EWMA_METRIC_WEIGHT,
            MAX_PACKET_LOSS_PPM,
        )
    } else {
        0
    };
    let raw_effective = rolling_effective.max(ewma_effective);
    if transport.is_stream() {
        capped_weighted_ppm(
            raw_effective,
            STREAM_PROBE_LOSS_METRIC_WEIGHT,
            STREAM_PROBE_LOSS_EFFECTIVE_CAP_PPM,
        )
    } else {
        raw_effective
    }
}

fn capped_weighted_ppm(ppm: u32, weight: f64, cap: u32) -> u32 {
    ((ppm as f64 * weight).round().clamp(0.0, cap as f64)) as u32
}

fn effective_loss_ppm(
    transport: TransportKind,
    probe_loss_ppm: u32,
    probe_loss_ewma_ppm: u32,
    probe_loss_ewma_sample_count: u64,
    probe_sample_count: u64,
    native_loss_ppm: u32,
    native_sample_count: u64,
    data_health_ppm: u32,
    data_health_sample_count: u64,
) -> u32 {
    let probe_effective = probe_effective_loss_ppm(
        transport,
        probe_loss_ppm,
        probe_loss_ewma_ppm,
        probe_loss_ewma_sample_count,
        probe_sample_count,
    );
    let native_effective = if native_sample_count >= LOSS_EFFECTIVE_SAMPLE_FLOOR {
        capped_weighted_ppm(
            native_loss_ppm,
            NATIVE_LOSS_METRIC_WEIGHT,
            NATIVE_LOSS_EFFECTIVE_CAP_PPM,
        )
    } else {
        0
    };
    let data_effective = if data_health_sample_count >= LOSS_EFFECTIVE_SAMPLE_FLOOR {
        capped_weighted_ppm(
            data_health_ppm,
            DATA_HEALTH_METRIC_WEIGHT,
            DATA_HEALTH_EFFECTIVE_CAP_PPM,
        )
    } else {
        0
    };
    probe_effective.max(native_effective).max(data_effective)
}

fn loss_ppm(lost: u64, total: u64) -> u32 {
    if total == 0 {
        return 0;
    }
    ((lost.min(total) as f64 / total as f64) * MAX_PACKET_LOSS_PPM as f64)
        .round()
        .clamp(0.0, MAX_PACKET_LOSS_PPM as f64) as u32
}

#[derive(Debug)]
struct SlidingCounters {
    bytes: u64,
    window_start: Instant,
    window: Duration,
}

impl SlidingCounters {
    fn new(window: Duration) -> Self {
        Self {
            bytes: 0,
            window_start: Instant::now(),
            window,
        }
    }
    fn record(&mut self, n: u64) {
        self.maybe_roll();
        self.bytes = self.bytes.saturating_add(n);
    }
    fn maybe_roll(&mut self) {
        if self.window_start.elapsed() >= self.window {
            self.bytes = 0;
            self.window_start = Instant::now();
        }
    }
    fn snapshot(&self) -> (u64, Duration) {
        let age = self.window_start.elapsed();
        if age >= self.window {
            return (0, age);
        }
        (self.bytes, age)
    }
}

fn throughput_confidence_ppm(
    sent_bytes: u64,
    recv_bytes: u64,
    sent_age: Duration,
    recv_age: Duration,
) -> u32 {
    if sent_bytes == 0 && recv_bytes == 0 {
        return 0;
    }
    let age = sent_age.max(recv_age).as_secs_f64();
    if age <= 0.0 {
        return MAX_PACKET_LOSS_PPM;
    }
    ((age / 1.0).min(1.0) * MAX_PACKET_LOSS_PPM as f64).round() as u32
}

#[derive(Debug)]
struct LossWindow {
    delivered: u64,
    lost: u64,
    window_start: Instant,
    window: Duration,
}

impl LossWindow {
    fn new(window: Duration) -> Self {
        Self {
            delivered: 0,
            lost: 0,
            window_start: Instant::now(),
            window,
        }
    }

    fn record_delivered(&mut self) {
        self.record_units(1, 0);
    }

    fn record_lost(&mut self) {
        self.record_units(1, 1);
    }

    fn record_units(&mut self, total: u64, lost: u64) {
        if total == 0 {
            return;
        }
        self.maybe_roll();
        let lost = lost.min(total);
        self.delivered = self.delivered.saturating_add(total.saturating_sub(lost));
        self.lost = self.lost.saturating_add(lost);
    }

    fn maybe_roll(&mut self) {
        if self.window_start.elapsed() >= self.window {
            self.delivered = 0;
            self.lost = 0;
            self.window_start = Instant::now();
        }
    }

    fn snapshot(&self) -> (u64, u64, Duration) {
        let age = self.window_start.elapsed();
        if age >= self.window {
            return (0, 0, age);
        }
        (self.delivered, self.lost, age)
    }
}

#[derive(Debug)]
struct LinkInner {
    rtt_us: Option<f64>,
    jitter_us: f64,
    last_rtt_sample_us: Option<f64>,
    samples: u64,
    last_update: Option<Instant>,
    sent: SlidingCounters,
    recv: SlidingCounters,
    wire_sent: SlidingCounters,
    wire_recv: SlidingCounters,
    l1_uncompressed_sent: SlidingCounters,
    l1_encoded_sent: SlidingCounters,
    l1_uncompressed_recv: SlidingCounters,
    l1_encoded_recv: SlidingCounters,
    probe_loss: LossWindow,
    probe_loss_ewma_ppm: f64,
    probe_loss_ewma_samples: u64,
    consecutive_probe_losses: u32,
    native_loss: LossWindow,
    native_loss_ewma_ppm: f64,
    native_loss_ewma_samples: u64,
    data_health: LossWindow,
    unmatched_probe_pongs: u64,
    kcp_runtime: Option<KcpRuntimeMetricsSnapshot>,
}

impl LinkInner {
    fn new(window: Duration) -> Self {
        Self {
            rtt_us: None,
            jitter_us: 0.0,
            last_rtt_sample_us: None,
            samples: 0,
            last_update: None,
            sent: SlidingCounters::new(window),
            recv: SlidingCounters::new(window),
            wire_sent: SlidingCounters::new(window),
            wire_recv: SlidingCounters::new(window),
            l1_uncompressed_sent: SlidingCounters::new(window),
            l1_encoded_sent: SlidingCounters::new(window),
            l1_uncompressed_recv: SlidingCounters::new(window),
            l1_encoded_recv: SlidingCounters::new(window),
            probe_loss: LossWindow::new(window),
            probe_loss_ewma_ppm: 0.0,
            probe_loss_ewma_samples: 0,
            consecutive_probe_losses: 0,
            native_loss: LossWindow::new(window),
            native_loss_ewma_ppm: 0.0,
            native_loss_ewma_samples: 0,
            data_health: LossWindow::new(window),
            unmatched_probe_pongs: 0,
            kcp_runtime: None,
        }
    }

    fn record_probe_loss_sample(&mut self, lost: bool, alpha: f64) {
        if lost {
            self.probe_loss.record_lost();
            self.consecutive_probe_losses = self.consecutive_probe_losses.saturating_add(1);
        } else {
            self.probe_loss.record_delivered();
            self.consecutive_probe_losses = 0;
        }
        let sample = if lost { MAX_PACKET_LOSS_PPM } else { 0 };
        update_loss_ewma(
            &mut self.probe_loss_ewma_ppm,
            &mut self.probe_loss_ewma_samples,
            sample,
            alpha,
        );
    }

    fn record_native_loss_sample(&mut self, sent_units: u64, lost_units: u64, alpha: f64) {
        if sent_units == 0 {
            return;
        }
        let lost_units = lost_units.min(sent_units);
        self.native_loss.record_units(sent_units, lost_units);
        update_loss_ewma(
            &mut self.native_loss_ewma_ppm,
            &mut self.native_loss_ewma_samples,
            loss_ppm(lost_units, sent_units),
            alpha,
        );
    }

    fn record_data_health_sample(&mut self, failed: bool) {
        if failed {
            self.data_health.record_lost();
        } else {
            self.data_health.record_delivered();
        }
    }
}

fn update_loss_ewma(ewma_ppm: &mut f64, samples: &mut u64, sample_ppm: u32, alpha: f64) {
    let sample = sample_ppm.min(MAX_PACKET_LOSS_PPM) as f64;
    if *samples == 0 {
        *ewma_ppm = sample;
    } else {
        let alpha = alpha.clamp(0.0, 1.0);
        *ewma_ppm += alpha * (sample - *ewma_ppm);
    }
    *samples = (*samples).saturating_add(1);
}

/// Per-`(transport, service-level)` metrics for a single peer.
#[derive(Debug)]
pub struct PeerMetrics {
    inner: Mutex<HashMap<TransportKind, LinkInner>>,
    window: Duration,
    tuning: MetricsTuning,
}

impl PeerMetrics {
    pub fn new(window: Duration, tuning: MetricsTuning) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            window,
            tuning,
        }
    }

    pub fn record_rtt(&self, transport: TransportKind, rtt: Duration) {
        self.record_rtt_sample(transport, rtt);
    }

    pub fn record_native_rtt(&self, transport: TransportKind, rtt: Duration) {
        self.record_rtt_sample(transport, rtt);
    }

    fn record_rtt_sample(&self, transport: TransportKind, rtt: Duration) {
        let sample = rtt.as_micros() as f64;
        let mut g = self.inner.lock();
        let entry = g
            .entry(transport)
            .or_insert_with(|| LinkInner::new(self.window));
        entry.samples += 1;
        entry.last_update = Some(Instant::now());
        entry.rtt_us = Some(match entry.rtt_us {
            None => sample,
            Some(prev) => prev + self.tuning.latency_alpha * (sample - prev),
        });
        if let Some(prev_sample) = entry.last_rtt_sample_us {
            let delta = (sample - prev_sample).abs();
            entry.jitter_us += self.tuning.jitter_alpha * (delta - entry.jitter_us);
        }
        entry.last_rtt_sample_us = Some(sample);
    }

    pub fn record_sent(&self, transport: TransportKind, bytes: usize) {
        let mut g = self.inner.lock();
        g.entry(transport)
            .or_insert_with(|| LinkInner::new(self.window))
            .wire_sent
            .record(bytes as u64);
    }

    pub fn record_recv(&self, transport: TransportKind, bytes: usize) {
        let mut g = self.inner.lock();
        g.entry(transport)
            .or_insert_with(|| LinkInner::new(self.window))
            .wire_recv
            .record(bytes as u64);
    }

    pub fn record_payload_sent(&self, transport: TransportKind, bytes: usize) {
        let mut g = self.inner.lock();
        g.entry(transport)
            .or_insert_with(|| LinkInner::new(self.window))
            .sent
            .record(bytes as u64);
    }

    pub fn record_payload_recv(&self, transport: TransportKind, bytes: usize) {
        let mut g = self.inner.lock();
        g.entry(transport)
            .or_insert_with(|| LinkInner::new(self.window))
            .recv
            .record(bytes as u64);
    }

    pub fn record_l1_compression_sent(
        &self,
        transport: TransportKind,
        uncompressed_bytes: usize,
        encoded_bytes: usize,
    ) {
        if uncompressed_bytes == 0 {
            return;
        }
        let mut g = self.inner.lock();
        let entry = g
            .entry(transport)
            .or_insert_with(|| LinkInner::new(self.window));
        entry.l1_uncompressed_sent.record(uncompressed_bytes as u64);
        entry.l1_encoded_sent.record(encoded_bytes as u64);
    }

    pub fn record_l1_compression_recv(
        &self,
        transport: TransportKind,
        uncompressed_bytes: usize,
        encoded_bytes: usize,
    ) {
        if uncompressed_bytes == 0 {
            return;
        }
        let mut g = self.inner.lock();
        let entry = g
            .entry(transport)
            .or_insert_with(|| LinkInner::new(self.window));
        entry.l1_uncompressed_recv.record(uncompressed_bytes as u64);
        entry.l1_encoded_recv.record(encoded_bytes as u64);
    }

    pub fn record_probe_delivered(&self, transport: TransportKind) {
        let mut g = self.inner.lock();
        let entry = g
            .entry(transport)
            .or_insert_with(|| LinkInner::new(self.window));
        entry.record_probe_loss_sample(false, self.tuning.packet_loss_alpha);
    }

    pub fn record_probe_lost(&self, transport: TransportKind) {
        let mut g = self.inner.lock();
        let entry = g
            .entry(transport)
            .or_insert_with(|| LinkInner::new(self.window));
        entry.record_probe_loss_sample(true, self.tuning.packet_loss_alpha);
    }

    pub fn record_unmatched_probe_pong(&self, transport: TransportKind) {
        let mut g = self.inner.lock();
        let entry = g
            .entry(transport)
            .or_insert_with(|| LinkInner::new(self.window));
        entry.unmatched_probe_pongs = entry.unmatched_probe_pongs.saturating_add(1);
        entry.last_update = Some(Instant::now());
    }

    pub fn record_native_loss_sample(
        &self,
        transport: TransportKind,
        sent_units: u64,
        lost_units: u64,
    ) {
        if sent_units == 0 {
            return;
        }
        let mut g = self.inner.lock();
        let entry = g
            .entry(transport)
            .or_insert_with(|| LinkInner::new(self.window));
        entry.record_native_loss_sample(sent_units, lost_units, self.tuning.packet_loss_alpha);
        entry.last_update = Some(Instant::now());
    }

    pub fn record_data_health_success(&self, transport: TransportKind) {
        self.record_data_health_sample(transport, false);
    }

    pub fn record_data_health_failure(&self, transport: TransportKind) {
        self.record_data_health_sample(transport, true);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_kcp_runtime_sample(
        &self,
        transport: TransportKind,
        closed: bool,
        pending_sender: bool,
        waiting_conv: bool,
        wait_snd: u64,
        snd_wnd: u64,
        rmt_wnd: u64,
        input_queue_drops: u64,
        no_progress_closes: u64,
        last_input_age_ms: Option<u64>,
        outstanding_no_progress_age_ms: Option<u64>,
    ) {
        let mut g = self.inner.lock();
        let entry = g
            .entry(transport)
            .or_insert_with(|| LinkInner::new(self.window));
        entry.kcp_runtime = Some(KcpRuntimeMetricsSnapshot::new(
            closed,
            pending_sender,
            waiting_conv,
            wait_snd,
            snd_wnd,
            rmt_wnd,
            input_queue_drops,
            no_progress_closes,
            last_input_age_ms,
            outstanding_no_progress_age_ms,
        ));
    }

    fn record_data_health_sample(&self, transport: TransportKind, failed: bool) {
        let mut g = self.inner.lock();
        let entry = g
            .entry(transport)
            .or_insert_with(|| LinkInner::new(self.window));
        entry.record_data_health_sample(failed);
        entry.last_update = Some(Instant::now());
    }

    pub fn snapshot_per_transport(&self) -> HashMap<TransportKind, LinkMetrics> {
        let g = self.inner.lock();
        g.iter()
            .map(|(t, inner)| {
                let (sent_bytes, sent_age) = inner.sent.snapshot();
                let (recv_bytes, recv_age) = inner.recv.snapshot();
                let (wire_sent_bytes, wire_sent_age) = inner.wire_sent.snapshot();
                let (wire_recv_bytes, wire_recv_age) = inner.wire_recv.snapshot();
                let (l1_uncompressed_sent_bytes, l1_uncompressed_sent_age) =
                    inner.l1_uncompressed_sent.snapshot();
                let (l1_encoded_sent_bytes, l1_encoded_sent_age) = inner.l1_encoded_sent.snapshot();
                let (l1_uncompressed_recv_bytes, l1_uncompressed_recv_age) =
                    inner.l1_uncompressed_recv.snapshot();
                let (l1_encoded_recv_bytes, l1_encoded_recv_age) = inner.l1_encoded_recv.snapshot();
                let (probe_delivered, probe_lost, probe_loss_age) = inner.probe_loss.snapshot();
                let (native_delivered, native_lost, native_loss_age) = inner.native_loss.snapshot();
                let (data_health_ok, data_health_failed, data_health_age) =
                    inner.data_health.snapshot();
                let probe_packets = probe_delivered.saturating_add(probe_lost);
                let native_samples = native_delivered.saturating_add(native_lost);
                let data_health_samples = data_health_ok.saturating_add(data_health_failed);
                let probe_loss_ppm = loss_ppm(probe_lost, probe_packets);
                let native_loss_ppm = loss_ppm(native_lost, native_samples);
                let data_health_ppm = loss_ppm(data_health_failed, data_health_samples);
                let loss = LossBreakdown::from_components(
                    *t,
                    probe_loss_ppm,
                    inner
                        .probe_loss_ewma_ppm
                        .round()
                        .clamp(0.0, MAX_PACKET_LOSS_PPM as f64) as u32,
                    inner.probe_loss_ewma_samples,
                    probe_packets,
                    probe_lost,
                    native_loss_ppm,
                    inner
                        .native_loss_ewma_ppm
                        .round()
                        .clamp(0.0, MAX_PACKET_LOSS_PPM as f64) as u32,
                    native_samples,
                    native_lost,
                    data_health_ppm,
                    data_health_samples,
                    data_health_failed,
                );
                let window = self.window.min(
                    recv_age
                        .max(sent_age)
                        .max(wire_recv_age)
                        .max(wire_sent_age)
                        .max(l1_uncompressed_sent_age)
                        .max(l1_encoded_sent_age)
                        .max(l1_uncompressed_recv_age)
                        .max(l1_encoded_recv_age)
                        .max(probe_loss_age)
                        .max(native_loss_age)
                        .max(data_health_age)
                        .max(Duration::from_micros(1)),
                );
                let throughput_confidence_ppm =
                    throughput_confidence_ppm(sent_bytes, recv_bytes, sent_age, recv_age);
                let m = LinkMetrics {
                    rtt_us: inner.rtt_us.unwrap_or(0.0),
                    jitter_us: inner.jitter_us,
                    sent_bytes,
                    recv_bytes,
                    wire_sent_bytes,
                    wire_recv_bytes,
                    l1_uncompressed_sent_bytes,
                    l1_encoded_sent_bytes,
                    l1_uncompressed_recv_bytes,
                    l1_encoded_recv_bytes,
                    window,
                    loss,
                    samples: inner.samples,
                    last_update: inner.last_update,
                    throughput_confidence_ppm,
                    unmatched_probe_pongs: inner.unmatched_probe_pongs,
                    consecutive_probe_losses: inner.consecutive_probe_losses,
                    kcp_runtime: inner.kcp_runtime.clone(),
                };
                (*t, m)
            })
            .collect()
    }

    /// Rank measured candidate transports for a requested service level using
    /// the sender-selected route metric. Returns only candidates with enough
    /// samples to compute a metric; callers can append their fixed fallback
    /// order for unmeasured transports.
    pub fn ranked_transports_for(
        &self,
        requested: ServiceLevel,
        metric: RoutingMetric,
        candidates: &[TransportKind],
    ) -> Vec<TransportKind> {
        let snapshot = self.snapshot_per_transport();
        let mut ranked: Vec<(TransportKind, f64)> = candidates
            .iter()
            .filter(|&&transport| transport.is_acceptable_for(requested))
            .copied()
            .filter_map(|transport| {
                snapshot
                    .get(&transport)
                    .and_then(|link| link.routing_cost(requested, metric))
                    .map(|cost| (transport, cost))
            })
            .collect();
        ranked.sort_by(|a, b| {
            a.1.partial_cmp(&b.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    transport_tie_rank(a.0, requested).cmp(&transport_tie_rank(b.0, requested))
                })
        });
        ranked.into_iter().map(|(transport, _)| transport).collect()
    }

    /// For a requested service level, pick the best measured candidate using
    /// the sender-selected route metric.
    #[allow(dead_code)]
    pub fn best_transport_for(
        &self,
        requested: ServiceLevel,
        metric: RoutingMetric,
        candidates: &[TransportKind],
    ) -> Option<TransportKind> {
        self.ranked_transports_for(requested, metric, candidates)
            .into_iter()
            .next()
    }
}

fn transport_tie_rank(transport: TransportKind, requested: ServiceLevel) -> (u8, u8, u8) {
    let provided = transport.service_level();
    let exact_first = if provided == requested { 0 } else { 1 };
    (exact_first, provided as u8, transport_kind_order(transport))
}

fn transport_kind_order(transport: TransportKind) -> u8 {
    match transport {
        TransportKind::Tcp => 3,
        TransportKind::Quic => 1,
        TransportKind::Kcp => 2,
        TransportKind::Udp => 0,
    }
}

/// Aggregated snapshot for the whole manager. Keyed by node, then transport.
#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    per_node: HashMap<NodeIdentifier, HashMap<TransportKind, LinkMetrics>>,
    outbound_queues: Vec<OutboundQueueStatusSnapshot>,
    inbound_queues: Vec<InboundQueueStatusSnapshot>,
    expired_outbound_drops: Vec<ExpiredOutboundDropSnapshot>,
    transport_health_exclusions: Vec<TransportHealthExclusionSnapshot>,
    voice_transport_bindings: Vec<VoiceTransportBindingSnapshot>,
    voice_transport_binding_events: Vec<VoiceTransportBindingEventSnapshot>,
    voice_transport_challengers: Vec<VoiceTransportChallengerSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundQueueStatusSnapshot {
    peer: NodeIdentifier,
    kind: OutboundQueueKind,
    status: QueueStatusSnapshot,
}

impl OutboundQueueStatusSnapshot {
    pub(crate) fn new_routed(peer: NodeIdentifier, status: QueueStatusSnapshot) -> Self {
        Self {
            peer,
            kind: OutboundQueueKind::Routed,
            status,
        }
    }

    pub(crate) fn new_transport(
        peer: NodeIdentifier,
        transport: TransportKind,
        status: QueueStatusSnapshot,
    ) -> Self {
        Self {
            peer,
            kind: OutboundQueueKind::Transport(transport),
            status,
        }
    }

    pub fn peer(&self) -> NodeIdentifier {
        self.peer
    }

    pub fn transport(&self) -> Option<TransportKind> {
        match self.kind {
            OutboundQueueKind::Routed => None,
            OutboundQueueKind::Transport(transport) => Some(transport),
        }
    }

    pub(crate) fn queue_key(&self) -> (u8, Option<TransportKind>) {
        match self.kind {
            OutboundQueueKind::Routed => (0, None),
            OutboundQueueKind::Transport(transport) => (1, Some(transport)),
        }
    }

    pub fn status(&self) -> QueueStatusSnapshot {
        self.status
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundQueueKind {
    Routed,
    Transport(TransportKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiredOutboundDropStage {
    PeerQueueEnqueue,
    PeerQueueDispatch,
    TransportWrite,
}

impl ExpiredOutboundDropStage {
    pub fn name(self) -> &'static str {
        match self {
            Self::PeerQueueEnqueue => "peer_queue_enqueue",
            Self::PeerQueueDispatch => "peer_queue_dispatch",
            Self::TransportWrite => "transport_write",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TransportHealthExclusionReason {
    KcpFailaway,
    StaleQueue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VoiceTransportBindingEventReason {
    Initial,
    IdleReset,
    ConfirmedChallenger,
    DeadlineImpossible,
    TransportUnavailable,
    QueueFull,
    StreamClosed,
    SendRejected,
    Recovered,
    NoAlternate,
}

impl VoiceTransportBindingEventReason {
    pub fn name(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::IdleReset => "idle_reset",
            Self::ConfirmedChallenger => "confirmed_challenger",
            Self::DeadlineImpossible => "deadline_impossible",
            Self::TransportUnavailable => "transport_unavailable",
            Self::QueueFull => "queue_full",
            Self::StreamClosed => "stream_closed",
            Self::SendRejected => "send_rejected",
            Self::Recovered => "recovered",
            Self::NoAlternate => "no_alternate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VoiceTransportChallengerOutcome {
    Started,
    Reset,
    Confirmed,
}

impl VoiceTransportChallengerOutcome {
    pub fn name(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Reset => "reset",
            Self::Confirmed => "confirmed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoiceTransportBindingSnapshot {
    peer: NodeIdentifier,
    transport: TransportKind,
}

impl VoiceTransportBindingSnapshot {
    pub(crate) fn new(peer: NodeIdentifier, transport: TransportKind) -> Self {
        Self { peer, transport }
    }

    pub fn peer(&self) -> NodeIdentifier {
        self.peer
    }
    pub fn transport(&self) -> TransportKind {
        self.transport
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoiceTransportBindingEventSnapshot {
    peer: NodeIdentifier,
    from: Option<TransportKind>,
    to: Option<TransportKind>,
    reason: VoiceTransportBindingEventReason,
    events: u64,
}

impl VoiceTransportBindingEventSnapshot {
    pub(crate) fn new(
        peer: NodeIdentifier,
        from: Option<TransportKind>,
        to: Option<TransportKind>,
        reason: VoiceTransportBindingEventReason,
        events: u64,
    ) -> Self {
        Self {
            peer,
            from,
            to,
            reason,
            events,
        }
    }

    pub fn peer(&self) -> NodeIdentifier {
        self.peer
    }
    pub fn from_transport(&self) -> Option<TransportKind> {
        self.from
    }
    pub fn to_transport(&self) -> Option<TransportKind> {
        self.to
    }
    pub fn reason(&self) -> VoiceTransportBindingEventReason {
        self.reason
    }
    pub fn events(&self) -> u64 {
        self.events
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoiceTransportChallengerSnapshot {
    peer: NodeIdentifier,
    incumbent: TransportKind,
    challenger: TransportKind,
    outcome: VoiceTransportChallengerOutcome,
    events: u64,
}

impl VoiceTransportChallengerSnapshot {
    pub(crate) fn new(
        peer: NodeIdentifier,
        incumbent: TransportKind,
        challenger: TransportKind,
        outcome: VoiceTransportChallengerOutcome,
        events: u64,
    ) -> Self {
        Self {
            peer,
            incumbent,
            challenger,
            outcome,
            events,
        }
    }

    pub fn peer(&self) -> NodeIdentifier {
        self.peer
    }
    pub fn incumbent(&self) -> TransportKind {
        self.incumbent
    }
    pub fn challenger(&self) -> TransportKind {
        self.challenger
    }
    pub fn outcome(&self) -> VoiceTransportChallengerOutcome {
        self.outcome
    }
    pub fn events(&self) -> u64 {
        self.events
    }
}

impl TransportHealthExclusionReason {
    pub fn name(self) -> &'static str {
        match self {
            Self::KcpFailaway => "kcp_failaway",
            Self::StaleQueue => "stale_queue",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportHealthExclusionSnapshot {
    peer: NodeIdentifier,
    transport: TransportKind,
    reason: TransportHealthExclusionReason,
    exclusions: u64,
}

impl TransportHealthExclusionSnapshot {
    pub(crate) fn new(
        peer: NodeIdentifier,
        transport: TransportKind,
        reason: TransportHealthExclusionReason,
        exclusions: u64,
    ) -> Self {
        Self {
            peer,
            transport,
            reason,
            exclusions,
        }
    }

    pub fn peer(&self) -> NodeIdentifier {
        self.peer
    }

    pub fn transport(&self) -> TransportKind {
        self.transport
    }

    pub fn reason(&self) -> TransportHealthExclusionReason {
        self.reason
    }

    pub fn exclusions(&self) -> u64 {
        self.exclusions
    }
}

pub(crate) struct ExpiredOutboundDropCounters {
    counters: [[[AtomicU64; MESSAGE_CLASS_COUNT]; EXPIRED_OUTBOUND_DROP_TRANSPORT_COUNT];
        EXPIRED_OUTBOUND_DROP_STAGE_COUNT],
}

impl Default for ExpiredOutboundDropCounters {
    fn default() -> Self {
        Self {
            counters: std::array::from_fn(|_| {
                std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0)))
            }),
        }
    }
}

impl ExpiredOutboundDropCounters {
    pub(crate) fn record(
        &self,
        stage: ExpiredOutboundDropStage,
        transport: Option<TransportKind>,
        class: MessageClass,
    ) {
        self.counters[expired_outbound_drop_stage_index(stage)]
            [expired_outbound_drop_transport_index(transport)][message_class_index(class)]
        .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshots(&self, peer: NodeIdentifier) -> Vec<ExpiredOutboundDropSnapshot> {
        let mut out = Vec::new();
        for stage in EXPIRED_OUTBOUND_DROP_STAGES {
            for transport in EXPIRED_OUTBOUND_DROP_TRANSPORTS {
                for class in MESSAGE_CLASSES {
                    let frames = self.counters[expired_outbound_drop_stage_index(stage)]
                        [expired_outbound_drop_transport_index(transport)]
                        [message_class_index(class)]
                    .load(Ordering::Relaxed);
                    if frames == 0 {
                        continue;
                    }
                    out.push(ExpiredOutboundDropSnapshot {
                        peer,
                        stage,
                        transport,
                        class,
                        frames,
                    });
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiredOutboundDropSnapshot {
    peer: NodeIdentifier,
    stage: ExpiredOutboundDropStage,
    transport: Option<TransportKind>,
    class: MessageClass,
    frames: u64,
}

impl ExpiredOutboundDropSnapshot {
    pub fn peer(&self) -> NodeIdentifier {
        self.peer
    }

    pub fn stage(&self) -> ExpiredOutboundDropStage {
        self.stage
    }

    pub fn transport(&self) -> Option<TransportKind> {
        self.transport
    }

    pub fn class(&self) -> MessageClass {
        self.class
    }

    pub fn frames(&self) -> u64 {
        self.frames
    }
}

fn expired_outbound_drop_stage_index(stage: ExpiredOutboundDropStage) -> usize {
    match stage {
        ExpiredOutboundDropStage::PeerQueueEnqueue => 0,
        ExpiredOutboundDropStage::PeerQueueDispatch => 1,
        ExpiredOutboundDropStage::TransportWrite => 2,
    }
}

fn expired_outbound_drop_transport_index(transport: Option<TransportKind>) -> usize {
    match transport {
        None => 0,
        Some(TransportKind::Tcp) => 1,
        Some(TransportKind::Kcp) => 2,
        Some(TransportKind::Quic) => 3,
        Some(TransportKind::Udp) => 4,
    }
}

fn message_class_index(class: MessageClass) -> usize {
    match class {
        MessageClass::Control => 0,
        MessageClass::HighPriority => 1,
        MessageClass::Regular => 2,
    }
}

fn transport_pipeline_kind_index(transport: TransportKind) -> usize {
    match transport {
        TransportKind::Tcp => 0,
        TransportKind::Kcp => 1,
        TransportKind::Quic => 2,
        TransportKind::Udp => 3,
    }
}

fn transport_pipeline_stage_index(stage: TransportPipelineStage) -> usize {
    match stage {
        TransportPipelineStage::FrameEncode => 0,
        TransportPipelineStage::FrameDecode => 1,
        TransportPipelineStage::L1Compress => 2,
        TransportPipelineStage::L1Decompress => 3,
        TransportPipelineStage::UdpEncrypt => 4,
        TransportPipelineStage::UdpDecrypt => 5,
        TransportPipelineStage::StreamWrite => 6,
        TransportPipelineStage::SocketWrite => 7,
    }
}

fn transport_io_pressure_result_index(result: TransportIoPressureResult) -> usize {
    match result {
        TransportIoPressureResult::WouldBlock => 0,
        TransportIoPressureResult::Partial => 1,
        TransportIoPressureResult::Timeout => 2,
        TransportIoPressureResult::Error => 3,
    }
}

fn transport_io_pressure_result(index: usize) -> TransportIoPressureResult {
    match index {
        0 => TransportIoPressureResult::WouldBlock,
        1 => TransportIoPressureResult::Partial,
        2 => TransportIoPressureResult::Timeout,
        _ => TransportIoPressureResult::Error,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboundQueueStatusSnapshot {
    class: MessageClass,
    status: QueueStatusSnapshot,
}

impl InboundQueueStatusSnapshot {
    pub(crate) fn new(class: MessageClass, status: QueueStatusSnapshot) -> Self {
        Self { class, status }
    }

    pub fn class(&self) -> MessageClass {
        self.class
    }

    pub fn status(&self) -> QueueStatusSnapshot {
        self.status
    }
}

impl MetricsSnapshot {
    pub fn per_node(&self) -> &HashMap<NodeIdentifier, HashMap<TransportKind, LinkMetrics>> {
        &self.per_node
    }

    pub fn for_node(&self, node: NodeIdentifier) -> Option<&HashMap<TransportKind, LinkMetrics>> {
        self.per_node.get(&node)
    }

    pub fn outbound_queues(&self) -> &[OutboundQueueStatusSnapshot] {
        &self.outbound_queues
    }

    pub fn inbound_queues(&self) -> &[InboundQueueStatusSnapshot] {
        &self.inbound_queues
    }

    pub fn expired_outbound_drops(&self) -> &[ExpiredOutboundDropSnapshot] {
        &self.expired_outbound_drops
    }

    pub fn transport_health_exclusions(&self) -> &[TransportHealthExclusionSnapshot] {
        &self.transport_health_exclusions
    }

    pub fn voice_transport_bindings(&self) -> &[VoiceTransportBindingSnapshot] {
        &self.voice_transport_bindings
    }

    pub fn voice_transport_binding_events(&self) -> &[VoiceTransportBindingEventSnapshot] {
        &self.voice_transport_binding_events
    }

    pub fn voice_transport_challengers(&self) -> &[VoiceTransportChallengerSnapshot] {
        &self.voice_transport_challengers
    }
}

/// Helper for the manager to assemble a `MetricsSnapshot` across all peers.
pub fn assemble_snapshot<I>(
    iter: I,
    outbound_queues: Vec<OutboundQueueStatusSnapshot>,
    inbound_queues: Vec<InboundQueueStatusSnapshot>,
    expired_outbound_drops: Vec<ExpiredOutboundDropSnapshot>,
    transport_health_exclusions: Vec<TransportHealthExclusionSnapshot>,
    voice_transport_bindings: Vec<VoiceTransportBindingSnapshot>,
    voice_transport_binding_events: Vec<VoiceTransportBindingEventSnapshot>,
    voice_transport_challengers: Vec<VoiceTransportChallengerSnapshot>,
) -> MetricsSnapshot
where
    I: IntoIterator<Item = (NodeIdentifier, Arc<PeerMetrics>)>,
{
    let mut per_node = HashMap::new();
    for (node, m) in iter {
        per_node.insert(node, m.snapshot_per_transport());
    }
    MetricsSnapshot {
        per_node,
        outbound_queues,
        inbound_queues,
        expired_outbound_drops,
        transport_health_exclusions,
        voice_transport_bindings,
        voice_transport_binding_events,
        voice_transport_challengers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_io_snapshots_record_bounded_bidirectional_labels() {
        let peer = 4094;

        record_transport_io_batch(
            peer,
            TransportKind::Udp,
            TransportIoDirection::Egress,
            5,
            4096,
        );
        record_transport_io_frames(
            peer,
            TransportKind::Udp,
            TransportIoDirection::Egress,
            MessageClass::Regular,
            5,
        );
        record_transport_io_pressure(
            peer,
            TransportKind::Udp,
            TransportIoDirection::Egress,
            TransportIoPressureResult::Partial,
            2,
        );

        let snapshot = transport_io_snapshots()
            .into_iter()
            .find(|snapshot| {
                snapshot.peer() == peer
                    && snapshot.transport() == TransportKind::Udp
                    && snapshot.direction() == TransportIoDirection::Egress
            })
            .expect("transport IO snapshot");

        assert!(snapshot.batches() >= 1);
        assert!(snapshot.bytes() >= 4096);
        assert!(
            snapshot
                .batch_size_buckets()
                .into_iter()
                .any(|(bucket, count)| bucket == "5_8" && count >= 1)
        );
        assert!(
            snapshot
                .pressure()
                .into_iter()
                .any(|(result, count)| result == TransportIoPressureResult::Partial && count >= 2)
        );

        let frames = transport_io_frame_snapshots()
            .into_iter()
            .find(|snapshot| {
                snapshot.peer() == peer
                    && snapshot.transport() == TransportKind::Udp
                    && snapshot.direction() == TransportIoDirection::Egress
                    && snapshot.class() == MessageClass::Regular
            })
            .expect("transport IO frame snapshot");
        assert!(frames.frames() >= 5);
    }

    #[test]
    fn ewma_smoothing() {
        let m = PeerMetrics::new(Duration::from_secs(5), MetricsTuning::default());
        for us in [10_000, 12_000, 11_000, 13_000, 10_500] {
            m.record_rtt(TransportKind::Tcp, Duration::from_micros(us as u64));
        }
        let snap = m.snapshot_per_transport();
        let tcp = snap.get(&TransportKind::Tcp).unwrap();
        // EWMA with α=0.2 starting at 10000, sequence above ~ converges near 11k.
        assert!(
            tcp.rtt_us > 10_000.0 && tcp.rtt_us < 12_500.0,
            "rtt {}",
            tcp.rtt_us
        );
        assert!(tcp.jitter_us > 0.0);
        assert_eq!(tcp.samples, 5);
    }

    #[test]
    fn native_rtt_feeds_latency_metric() {
        let m = PeerMetrics::new(Duration::from_secs(5), MetricsTuning::default());
        m.record_native_rtt(TransportKind::Kcp, Duration::from_millis(18));

        let snap = m.snapshot_per_transport();
        let kcp = snap.get(&TransportKind::Kcp).unwrap();
        assert_eq!(kcp.rtt_us(), 18_000.0);
        assert_eq!(kcp.samples(), 1);
    }

    #[test]
    fn best_transport_picks_lowest_rtt() {
        let m = PeerMetrics::new(Duration::from_secs(5), MetricsTuning::default());
        let candidates = [TransportKind::Tcp, TransportKind::Quic, TransportKind::Udp];
        m.record_rtt(TransportKind::Tcp, Duration::from_millis(50));
        m.record_rtt(TransportKind::Quic, Duration::from_millis(20));
        m.record_rtt(TransportKind::Udp, Duration::from_millis(15));

        // For best-effort, all three qualify; lowest RTT wins.
        assert_eq!(
            m.best_transport_for(
                ServiceLevel::BestEffort,
                RoutingMetric::BestEffortCost,
                &candidates
            ),
            Some(TransportKind::Udp)
        );
        // For RLL, QUIC wins on latency; TCP remains an acceptable fallback.
        assert_eq!(
            m.best_transport_for(
                ServiceLevel::ReliableLowLatency,
                RoutingMetric::ReliableLowLatencyCost,
                &candidates
            ),
            Some(TransportKind::Quic)
        );
        // For Reliable, both TCP and QUIC qualify (QUIC is strictly stronger);
        // QUIC wins on lowest RTT.
        assert_eq!(
            m.best_transport_for(
                ServiceLevel::Reliable,
                RoutingMetric::ReliableCost,
                &candidates
            ),
            Some(TransportKind::Quic)
        );
    }

    #[test]
    fn reliable_policy_prefers_higher_throughput_over_lower_rtt() {
        let m = PeerMetrics::new(Duration::from_secs(60), MetricsTuning::default());
        let candidates = [TransportKind::Tcp, TransportKind::Quic];

        {
            let mut g = m.inner.lock();
            g.insert(
                TransportKind::Tcp,
                LinkInner {
                    rtt_us: Some(5_000.0),
                    samples: 1,
                    sent: SlidingCounters {
                        bytes: 1_024,
                        window_start: Instant::now() - Duration::from_secs(1),
                        window: Duration::from_secs(60),
                    },
                    ..LinkInner::new(Duration::from_secs(60))
                },
            );
            g.insert(
                TransportKind::Quic,
                LinkInner {
                    rtt_us: Some(25_000.0),
                    samples: 1,
                    sent: SlidingCounters {
                        bytes: 1024 * 1024,
                        window_start: Instant::now() - Duration::from_secs(1),
                        window: Duration::from_secs(60),
                    },
                    ..LinkInner::new(Duration::from_secs(60))
                },
            );
        }

        assert_eq!(
            m.best_transport_for(
                ServiceLevel::Reliable,
                RoutingMetric::ReliableCost,
                &candidates
            ),
            Some(TransportKind::Quic)
        );
    }

    #[test]
    fn conversational_policy_can_upgrade_best_effort_from_jittery_udp() {
        let m = PeerMetrics::new(Duration::from_secs(60), MetricsTuning::default());
        let candidates = [TransportKind::Udp, TransportKind::Quic];

        m.record_rtt(TransportKind::Udp, Duration::from_millis(10));
        m.record_rtt(TransportKind::Udp, Duration::from_millis(250));
        m.record_rtt(TransportKind::Quic, Duration::from_millis(70));
        m.record_rtt(TransportKind::Quic, Duration::from_millis(71));

        assert_eq!(
            m.best_transport_for(
                ServiceLevel::BestEffort,
                RoutingMetric::BestEffortCost,
                &candidates
            ),
            Some(TransportKind::Udp)
        );
        assert_eq!(
            m.best_transport_for(
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
                &candidates
            ),
            Some(TransportKind::Quic)
        );
    }

    #[test]
    fn packet_loss_penalty_affects_transport_ranking() {
        let m = PeerMetrics::new(Duration::from_secs(60), MetricsTuning::default());
        let candidates = [TransportKind::Udp, TransportKind::Quic];

        m.record_rtt(TransportKind::Udp, Duration::from_millis(10));
        for _ in 0..16 {
            m.record_probe_delivered(TransportKind::Udp);
            m.record_probe_lost(TransportKind::Udp);
        }

        m.record_rtt(TransportKind::Quic, Duration::from_millis(15));
        m.record_probe_delivered(TransportKind::Quic);

        assert_eq!(
            m.best_transport_for(
                ServiceLevel::BestEffort,
                RoutingMetric::BestEffortCost,
                &candidates
            ),
            Some(TransportKind::Quic)
        );

        let udp = m
            .snapshot_per_transport()
            .get(&TransportKind::Udp)
            .unwrap()
            .packet_loss_ppm();
        assert_eq!(udp, 500_000);
    }

    #[test]
    fn packet_loss_ewma_tracks_probe_outcomes() {
        let m = PeerMetrics::new(
            Duration::from_secs(60),
            MetricsTuning {
                packet_loss_alpha: 0.5,
                ..MetricsTuning::default()
            },
        );

        m.record_probe_lost(TransportKind::Tcp);
        m.record_probe_delivered(TransportKind::Tcp);

        let snap = m.snapshot_per_transport();
        let tcp = snap.get(&TransportKind::Tcp).unwrap();
        assert_eq!(tcp.probe_loss_ppm(), 500_000);
        assert_eq!(tcp.packet_loss_ewma_ppm(), 500_000);
        assert_eq!(tcp.packet_loss_ppm(), 0);
    }

    #[test]
    fn consecutive_probe_losses_increment_and_reset() {
        let m = PeerMetrics::new(Duration::from_secs(60), MetricsTuning::default());

        m.record_probe_lost(TransportKind::Quic);
        m.record_probe_lost(TransportKind::Quic);
        let snap = m.snapshot_per_transport();
        assert_eq!(
            snap.get(&TransportKind::Quic)
                .unwrap()
                .consecutive_probe_losses(),
            2
        );

        m.record_probe_delivered(TransportKind::Quic);
        let snap = m.snapshot_per_transport();
        assert_eq!(
            snap.get(&TransportKind::Quic)
                .unwrap()
                .consecutive_probe_losses(),
            0
        );
    }

    #[test]
    fn packet_loss_ewma_contributes_lower_weight_to_link_cost() {
        let clean = LinkMetrics {
            rtt_us: 10_000.0,
            samples: 1,
            ..LinkMetrics::default()
        };
        let historical_loss = LinkMetrics {
            loss: LossBreakdown::from_components(
                TransportKind::Udp,
                0,
                400_000,
                LOSS_EFFECTIVE_SAMPLE_FLOOR,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ),
            ..clean
        };
        let current_loss = LinkMetrics {
            loss: LossBreakdown::from_components(
                TransportKind::Udp,
                200_000,
                400_000,
                LOSS_EFFECTIVE_SAMPLE_FLOOR,
                LOSS_EFFECTIVE_SAMPLE_FLOOR,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ),
            ..clean
        };

        assert_eq!(clean.effective_packet_loss_ppm(), 0);
        assert_eq!(historical_loss.effective_packet_loss_ppm(), 100_000);
        assert_eq!(current_loss.effective_packet_loss_ppm(), 200_000);

        let clean_cost = clean
            .routing_cost(ServiceLevel::BestEffort, RoutingMetric::BestEffortCost)
            .unwrap();
        let historical_loss_cost = historical_loss
            .routing_cost(ServiceLevel::BestEffort, RoutingMetric::BestEffortCost)
            .unwrap();

        assert!(
            historical_loss_cost > clean_cost,
            "historical_loss_cost={historical_loss_cost} clean_cost={clean_cost}"
        );
    }

    #[test]
    fn stream_probe_loss_waits_for_sample_floor_and_is_capped() {
        let sparse = LossBreakdown::from_components(
            TransportKind::Kcp,
            MAX_PACKET_LOSS_PPM,
            MAX_PACKET_LOSS_PPM,
            LOSS_EFFECTIVE_SAMPLE_FLOOR - 1,
            LOSS_EFFECTIVE_SAMPLE_FLOOR - 1,
            LOSS_EFFECTIVE_SAMPLE_FLOOR - 1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        assert_eq!(sparse.effective_loss_ppm(), 0);

        let stream = LossBreakdown::from_components(
            TransportKind::Kcp,
            MAX_PACKET_LOSS_PPM,
            MAX_PACKET_LOSS_PPM,
            LOSS_EFFECTIVE_SAMPLE_FLOOR,
            LOSS_EFFECTIVE_SAMPLE_FLOOR,
            LOSS_EFFECTIVE_SAMPLE_FLOOR,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        assert_eq!(
            stream.effective_loss_ppm(),
            STREAM_PROBE_LOSS_EFFECTIVE_CAP_PPM
        );

        let datagram = LossBreakdown::from_components(
            TransportKind::Udp,
            MAX_PACKET_LOSS_PPM,
            MAX_PACKET_LOSS_PPM,
            LOSS_EFFECTIVE_SAMPLE_FLOOR,
            LOSS_EFFECTIVE_SAMPLE_FLOOR,
            LOSS_EFFECTIVE_SAMPLE_FLOOR,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        assert_eq!(datagram.effective_loss_ppm(), MAX_PACKET_LOSS_PPM);
    }

    #[test]
    fn native_loss_waits_for_sample_floor_then_applies_cap() {
        let below_floor = LossBreakdown::from_components(
            TransportKind::Tcp,
            0,
            0,
            0,
            0,
            0,
            800_000,
            800_000,
            LOSS_EFFECTIVE_SAMPLE_FLOOR - 1,
            24,
            0,
            0,
            0,
        );
        assert_eq!(below_floor.effective_loss_ppm(), 0);

        let above_floor = LossBreakdown::from_components(
            TransportKind::Tcp,
            0,
            0,
            0,
            0,
            0,
            800_000,
            800_000,
            LOSS_EFFECTIVE_SAMPLE_FLOOR,
            26,
            0,
            0,
            0,
        );
        assert_eq!(
            above_floor.effective_loss_ppm(),
            NATIVE_LOSS_EFFECTIVE_CAP_PPM
        );
    }

    #[test]
    fn data_health_waits_for_sample_floor_and_is_capped() {
        let below_floor = LossBreakdown::from_components(
            TransportKind::Tcp,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            500_000,
            LOSS_EFFECTIVE_SAMPLE_FLOOR - 1,
            15,
        );
        assert_eq!(below_floor.effective_loss_ppm(), 0);

        let above_floor = LossBreakdown::from_components(
            TransportKind::Tcp,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            800_000,
            LOSS_EFFECTIVE_SAMPLE_FLOOR,
            26,
        );
        assert_eq!(
            above_floor.effective_loss_ppm(),
            DATA_HEALTH_EFFECTIVE_CAP_PPM
        );
    }

    #[test]
    fn peer_metrics_records_native_and_data_health_breakdown() {
        let m = PeerMetrics::new(Duration::from_secs(60), MetricsTuning::default());
        m.record_native_loss_sample(TransportKind::Tcp, 40, 4);
        for _ in 0..31 {
            m.record_data_health_success(TransportKind::Tcp);
        }
        m.record_data_health_failure(TransportKind::Tcp);

        let snap = m.snapshot_per_transport();
        let tcp = snap.get(&TransportKind::Tcp).unwrap();
        assert_eq!(tcp.native_loss_ppm(), 100_000);
        assert_eq!(tcp.native_loss_samples(), 40);
        assert_eq!(tcp.native_lost_samples(), 4);
        assert_eq!(tcp.data_health_ppm(), 31_250);
        assert_eq!(tcp.data_health_samples(), 32);
        assert_eq!(tcp.data_health_failures(), 1);
        assert_eq!(tcp.effective_packet_loss_ppm(), 50_000);
    }

    #[test]
    fn observed_throughput_is_directional_and_passive() {
        let m = PeerMetrics::new(Duration::from_secs(60), MetricsTuning::default());
        m.record_probe_delivered(TransportKind::Tcp);
        m.record_payload_sent(TransportKind::Tcp, 100);
        m.record_payload_recv(TransportKind::Tcp, 50);
        let snap = m.snapshot_per_transport();
        let tcp = snap.get(&TransportKind::Tcp).unwrap();
        assert!(tcp.observed_sent_bps() > tcp.observed_recv_bps());
        assert_eq!(tcp.estimated_throughput_bps(), tcp.observed_sent_bps());
        assert!(tcp.throughput_confidence_ppm() > 0);
    }

    #[test]
    fn quality_score_prefers_stronger_composite_link() {
        assert_eq!(LinkMetrics::default().quality_score(), None);

        let tcp = LinkMetrics {
            rtt_us: 5_000.0,
            jitter_us: 75_000.0,
            sent_bytes: 1_024,
            window: Duration::from_secs(1),
            samples: 2,
            ..LinkMetrics::default()
        }
        .quality_score()
        .unwrap();
        let quic = LinkMetrics {
            rtt_us: 25_000.0,
            jitter_us: 1_000.0,
            sent_bytes: 1024 * 1024,
            window: Duration::from_secs(1),
            samples: 2,
            ..LinkMetrics::default()
        }
        .quality_score()
        .unwrap();

        assert!(quic > tcp, "quic={quic} tcp={tcp}");
    }

    #[test]
    fn bandwidth_counters_accumulate() {
        let m = PeerMetrics::new(Duration::from_secs(60), MetricsTuning::default());
        m.record_payload_sent(TransportKind::Tcp, 1024);
        m.record_payload_recv(TransportKind::Tcp, 512);
        m.record_sent(TransportKind::Tcp, 2048);
        m.record_recv(TransportKind::Tcp, 1536);
        let snap = m.snapshot_per_transport();
        let tcp = snap.get(&TransportKind::Tcp).unwrap();
        assert_eq!(tcp.sent_bytes, 1024);
        assert_eq!(tcp.recv_bytes, 512);
        assert_eq!(tcp.wire_sent_bytes(), 2048);
        assert_eq!(tcp.wire_recv_bytes(), 1536);
    }

    #[test]
    fn l1_compression_counters_report_ratios() {
        let m = PeerMetrics::new(Duration::from_secs(60), MetricsTuning::default());
        m.record_l1_compression_sent(TransportKind::Tcp, 1_000, 400);
        m.record_l1_compression_recv(TransportKind::Tcp, 2_000, 1_000);

        let snap = m.snapshot_per_transport();
        let tcp = snap.get(&TransportKind::Tcp).unwrap();

        assert_eq!(tcp.l1_uncompressed_sent_bytes(), 1_000);
        assert_eq!(tcp.l1_encoded_sent_bytes(), 400);
        assert_eq!(tcp.l1_uncompressed_recv_bytes(), 2_000);
        assert_eq!(tcp.l1_encoded_recv_bytes(), 1_000);
        assert_eq!(tcp.l1_compression_sent_ratio(), Some(0.4));
        assert_eq!(tcp.l1_compression_recv_ratio(), Some(0.5));
        assert_eq!(tcp.l1_compression_total_ratio(), Some(1_400.0 / 3_000.0));
    }
}
