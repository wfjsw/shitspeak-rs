//! Per-peer state held by the supervisor.
//!
//! The supervisor owns one `PeerState` per known peer; that struct contains
//! the dial address book, the set of currently-active streams, reconnect
//! backoff, and aggregated metrics.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use parking_lot::Mutex;
use prost::Message as _;
use rand::RngExt;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::types::NodeIdentifier;

use super::SendOptions;
use super::adaptive_queue::{
    AdaptiveQueueBudget, AdaptiveQueueReceiver, AdaptiveQueueSender, Queued, SendAdaptiveError,
    TryAdaptiveSendError,
};
use super::latest_wins_queue::{
    LatestWinsQueueItem, LatestWinsReceiver, LatestWinsSendError, LatestWinsSender,
    latest_wins_queue,
};
use super::metrics::{
    DatagramPathEvidenceSnapshot, DatagramPathHealthReason, DatagramPathHealthSnapshot,
    DatagramPathHealthState, ExpiredOutboundDropCounters, ExpiredOutboundDropSnapshot,
    ExpiredOutboundDropStage, MetricsTuning, OutboundQueueStatusSnapshot, PeerMetrics,
    QueueStatusSnapshot, QueueWatermark, TransportHealthExclusionReason,
    TransportHealthExclusionSnapshot, VoiceTransportBindingEventReason,
    VoiceTransportBindingEventSnapshot, VoiceTransportBindingSnapshot,
    VoiceTransportChallengerOutcome, VoiceTransportChallengerSnapshot,
};
use super::service_level::{
    DeliveryPath, MessageClass, PeerAddress, RoutingMetric, ServiceLevel, TransportKind,
};

const MAX_OBSERVED_REMOTE_IPS: usize = 8;
const BACKOFF_JITTER_DIVISOR: u64 = 5;

#[derive(Debug, Clone, Copy)]
pub(crate) struct VoiceTransportCandidateScore {
    transport: TransportKind,
    pressure: u8,
    cost: Option<f64>,
}

impl VoiceTransportCandidateScore {
    pub(crate) fn new(transport: TransportKind, pressure: u8, cost: Option<f64>) -> Self {
        Self {
            transport,
            pressure,
            cost,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct VoiceTransportDecision {
    preferred: TransportKind,
    incumbent: Option<TransportKind>,
    reason: VoiceTransportBindingEventReason,
}

impl VoiceTransportDecision {
    pub(crate) fn preferred(self) -> TransportKind {
        self.preferred
    }
    pub(crate) fn incumbent(self) -> Option<TransportKind> {
        self.incumbent
    }
    pub(crate) fn reason(self) -> VoiceTransportBindingEventReason {
        self.reason
    }
    pub(crate) fn with_reason(mut self, reason: VoiceTransportBindingEventReason) -> Self {
        self.reason = reason;
        self
    }
}

#[derive(Debug, Default)]
struct VoiceTransportBinding {
    selected_transport: Option<TransportKind>,
    selected_at: Option<Instant>,
    last_success_at: Option<Instant>,
    challenger_transport: Option<TransportKind>,
    challenger_since: Option<Instant>,
    challenger_observations: u32,
    no_alternate_reported: bool,
    events: HashMap<
        (
            Option<TransportKind>,
            Option<TransportKind>,
            VoiceTransportBindingEventReason,
        ),
        u64,
    >,
    challenger_events: HashMap<
        (
            TransportKind,
            TransportKind,
            VoiceTransportChallengerOutcome,
        ),
        u64,
    >,
}

#[derive(Debug, Clone, Copy)]
struct DatagramPathHealthObservation {
    state: DatagramPathHealthState,
    reason: DatagramPathHealthReason,
    effective_loss_ppm: Option<u32>,
    path_health_score_ppm: Option<u32>,
    loss_samples: u64,
    transitions: u64,
    changed_at: Instant,
    observed_at: Instant,
    last_evidence_generation: Option<u64>,
    last_scored_generation: Option<u64>,
    last_diagnostic_generation: Option<u64>,
    diagnostic_observed_at: Option<Instant>,
    consecutive_bad_windows: u32,
    healthy_since: Option<Instant>,
    recovery_healthy_span: Duration,
    recovery_required: bool,
    sample_confidence_ppm: u32,
    enqueue_accepted: u64,
    enqueue_rejected: u64,
    too_large: u64,
    pressure: u64,
    outcome_successes: u64,
    outcome_failures: u64,
    ingress_validated: u64,
    ingress_rejected: u64,
    ingress_read_failures: u64,
}

impl VoiceTransportBinding {
    fn clear_challenger(&mut self, outcome: VoiceTransportChallengerOutcome) {
        if let (Some(incumbent), Some(challenger)) =
            (self.selected_transport, self.challenger_transport)
        {
            let counter = self
                .challenger_events
                .entry((incumbent, challenger, outcome))
                .or_default();
            *counter = counter.saturating_add(1);
        }
        self.challenger_transport = None;
        self.challenger_since = None;
        self.challenger_observations = 0;
    }

    fn record_event(
        &mut self,
        from: Option<TransportKind>,
        to: Option<TransportKind>,
        reason: VoiceTransportBindingEventReason,
    ) {
        let counter = self.events.entry((from, to, reason)).or_default();
        *counter = counter.saturating_add(1);
    }
}

/// One outbound frame, addressed to a specific stream.
#[derive(Debug, Clone)]
pub struct OutboundFrame {
    level: ServiceLevel,
    class: MessageClass,
    payload: Bytes,
    options: SendOptions,
}

impl OutboundFrame {
    pub fn new(level: ServiceLevel, class: MessageClass, payload: Bytes) -> Self {
        Self::with_options(level, class, payload, SendOptions::default())
    }

    pub fn with_options(
        level: ServiceLevel,
        class: MessageClass,
        payload: Bytes,
        options: SendOptions,
    ) -> Self {
        Self {
            level,
            class,
            payload,
            options,
        }
    }

    pub(crate) fn from_variant(
        level: ServiceLevel,
        class: MessageClass,
        variant: &TransportPayloadVariant,
        options: SendOptions,
    ) -> Self {
        Self::with_options(level, class, variant.primary.clone(), options)
    }

    pub fn level(&self) -> ServiceLevel {
        self.level
    }

    pub fn class(&self) -> MessageClass {
        self.class
    }

    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    pub fn options(&self) -> SendOptions {
        self.options
    }
}

impl LatestWinsQueueItem for OutboundFrame {
    fn estimated_queue_bytes(&self) -> usize {
        super::frame::build_frame(
            u16::MAX,
            u16::MAX,
            self.level,
            super::frame::FrameType::Data,
            self.class,
            u64::MAX,
            self.payload.clone(),
        )
        .encoded_len()
    }
}

/// A primary transport payload plus optional disposable sidecars.
#[derive(Debug, Clone)]
pub struct TransportPayloadVariant {
    primary: Bytes,
    sidecars: Vec<Bytes>,
}

impl TransportPayloadVariant {
    pub fn new(primary: Bytes) -> Self {
        Self {
            primary,
            sidecars: Vec::new(),
        }
    }

    pub fn with_sidecars(mut self, sidecars: impl IntoIterator<Item = Bytes>) -> Self {
        self.sidecars = sidecars.into_iter().collect();
        self
    }

    pub fn primary(&self) -> &Bytes {
        &self.primary
    }

    pub fn sidecars(&self) -> &[Bytes] {
        &self.sidecars
    }

    pub(crate) fn estimated_bytes(&self) -> usize {
        self.primary
            .len()
            .saturating_add(self.sidecars.iter().map(Bytes::len).sum::<usize>())
    }
}

/// Payload variants selected after the manager chooses a transport.
#[derive(Debug, Clone)]
pub struct TransportPayloadPlan {
    default: TransportPayloadVariant,
    variants: Vec<(TransportKind, TransportPayloadVariant)>,
    quic_v2: Option<TransportPayloadVariant>,
}

impl TransportPayloadPlan {
    pub fn new(primary: Bytes) -> Self {
        Self {
            default: TransportPayloadVariant::new(primary),
            variants: Vec::new(),
            quic_v2: None,
        }
    }

    pub fn with_variant(
        mut self,
        transport: TransportKind,
        variant: TransportPayloadVariant,
    ) -> Self {
        if let Some(existing) = self
            .variants
            .iter_mut()
            .find(|(kind, _)| *kind == transport)
        {
            existing.1 = variant;
        } else {
            self.variants.push((transport, variant));
        }
        self
    }

    pub fn default_variant(&self) -> &TransportPayloadVariant {
        &self.default
    }

    pub fn with_quic_v2_variant(mut self, variant: TransportPayloadVariant) -> Self {
        self.quic_v2 = Some(variant);
        self
    }

    pub fn variant(&self, transport: TransportKind) -> &TransportPayloadVariant {
        self.variants
            .iter()
            .find(|(kind, _)| *kind == transport)
            .map(|(_, variant)| variant)
            .unwrap_or(&self.default)
    }

    pub(crate) fn variant_for_session(
        &self,
        transport: TransportKind,
        quic_v2: bool,
    ) -> &TransportPayloadVariant {
        if transport == TransportKind::Quic && quic_v2 {
            return self.quic_v2.as_ref().unwrap_or(&self.default);
        }
        self.variant(transport)
    }

    pub(crate) fn estimated_bytes(&self) -> usize {
        self.default
            .estimated_bytes()
            .saturating_add(
                self.variants
                    .iter()
                    .map(|(_, variant)| variant.estimated_bytes())
                    .sum::<usize>(),
            )
            .saturating_add(
                self.quic_v2
                    .as_ref()
                    .map(TransportPayloadVariant::estimated_bytes)
                    .unwrap_or_default(),
            )
    }
}

/// A durable outbound message queued before selecting a transport.
#[derive(Debug, Clone)]
pub(crate) struct OutboundEnvelope {
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    fixed_transport: Option<TransportKind>,
    class: MessageClass,
    payloads: TransportPayloadPlan,
    options: SendOptions,
}

impl OutboundEnvelope {
    #[allow(dead_code)]
    pub fn routed(
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        payload: Bytes,
        options: SendOptions,
    ) -> Self {
        Self::routed_with_payloads(
            level,
            routing_metric,
            class,
            TransportPayloadPlan::new(payload),
            options,
        )
    }

    pub fn routed_with_payloads(
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        payloads: TransportPayloadPlan,
        options: SendOptions,
    ) -> Self {
        Self {
            level,
            routing_metric,
            fixed_transport: None,
            class,
            payloads,
            options,
        }
    }

    pub fn fixed_transport(
        transport: TransportKind,
        class: MessageClass,
        payload: Bytes,
        options: SendOptions,
    ) -> Self {
        Self::fixed_transport_with_payloads(
            transport,
            class,
            TransportPayloadPlan::new(payload),
            options,
        )
    }

    pub fn fixed_transport_with_payloads(
        transport: TransportKind,
        class: MessageClass,
        payloads: TransportPayloadPlan,
        options: SendOptions,
    ) -> Self {
        Self {
            level: transport.service_level(),
            routing_metric: RoutingMetric::default_for_level(transport.service_level()),
            fixed_transport: Some(transport),
            class,
            payloads,
            options,
        }
    }

    pub fn level(&self) -> ServiceLevel {
        self.level
    }

    pub fn routing_metric(&self) -> RoutingMetric {
        self.routing_metric
    }

    pub fn target_transport(&self) -> Option<TransportKind> {
        self.fixed_transport
    }

    pub fn class(&self) -> MessageClass {
        self.class
    }

    pub fn payload(&self) -> &Bytes {
        self.payloads.default_variant().primary()
    }

    pub fn payloads(&self) -> &TransportPayloadPlan {
        &self.payloads
    }

    pub fn options(&self) -> SendOptions {
        self.options
    }

    pub fn is_expired_at(&self, now: Instant) -> bool {
        self.options.is_expired_at(now)
    }
}

#[derive(Clone)]
pub(crate) struct PeerOutboundSender {
    control: AdaptiveQueueSender<OutboundEnvelope>,
    high_priority: AdaptiveQueueSender<OutboundEnvelope>,
    regular: AdaptiveQueueSender<OutboundEnvelope>,
    capacity_bytes: usize,
}

impl PeerOutboundSender {
    fn new(budget: AdaptiveQueueBudget) -> (Self, PeerOutboundReceiver) {
        let capacity_bytes = budget.max_bytes();
        let [control, high_priority, regular] = [
            budget.split_exact(capacity_bytes),
            budget.split_exact(capacity_bytes.saturating_mul(3) / 4),
            budget.split_exact(capacity_bytes / 2),
        ];
        let (control, control_receiver) = AdaptiveQueueSender::new(control);
        let (high_priority, high_priority_receiver) = AdaptiveQueueSender::new(high_priority);
        let (regular, regular_receiver) = AdaptiveQueueSender::new(regular);
        (
            Self {
                control,
                high_priority,
                regular,
                capacity_bytes,
            },
            PeerOutboundReceiver {
                control: control_receiver,
                high_priority: high_priority_receiver,
                regular: regular_receiver,
                control_open: true,
                high_priority_open: true,
                regular_open: true,
            },
        )
    }

    pub(crate) fn try_send(
        &self,
        envelope: OutboundEnvelope,
    ) -> Result<(), TryAdaptiveSendError<OutboundEnvelope>> {
        match envelope.class() {
            MessageClass::Control => self.control.try_send(envelope),
            MessageClass::HighPriority => self.high_priority.try_send(envelope),
            MessageClass::Regular => self.regular.try_send(envelope),
        }
    }

    pub(crate) async fn send(
        &self,
        envelope: OutboundEnvelope,
    ) -> Result<(), SendAdaptiveError<OutboundEnvelope>> {
        match envelope.class() {
            MessageClass::Control => self.control.send(envelope).await,
            MessageClass::HighPriority => self.high_priority.send(envelope).await,
            MessageClass::Regular => self.regular.send(envelope).await,
        }
    }

    pub(crate) fn depth_bytes(&self) -> usize {
        self.control
            .depth_bytes()
            .saturating_add(self.high_priority.depth_bytes())
            .saturating_add(self.regular.depth_bytes())
    }

    pub(crate) fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }

    pub(crate) fn class_depth_and_capacity(&self, class: MessageClass) -> (usize, usize) {
        let sender = match class {
            MessageClass::Control => &self.control,
            MessageClass::HighPriority => &self.high_priority,
            MessageClass::Regular => &self.regular,
        };
        (sender.depth_bytes(), sender.capacity_bytes())
    }
}

pub(crate) struct PeerOutboundReceiver {
    control: AdaptiveQueueReceiver<OutboundEnvelope>,
    high_priority: AdaptiveQueueReceiver<OutboundEnvelope>,
    regular: AdaptiveQueueReceiver<OutboundEnvelope>,
    control_open: bool,
    high_priority_open: bool,
    regular_open: bool,
}

impl PeerOutboundReceiver {
    pub(crate) fn try_recv(
        &mut self,
        class: MessageClass,
    ) -> Result<Queued<OutboundEnvelope>, tokio::sync::mpsc::error::TryRecvError> {
        let (receiver, open) = match class {
            MessageClass::Control => (&mut self.control, &mut self.control_open),
            MessageClass::HighPriority => (&mut self.high_priority, &mut self.high_priority_open),
            MessageClass::Regular => (&mut self.regular, &mut self.regular_open),
        };
        match receiver.try_recv_queued() {
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                *open = false;
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
            }
            result => result,
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        !self.control_open && !self.high_priority_open && !self.regular_open
    }

    pub(crate) async fn recv(&mut self) -> Option<Queued<OutboundEnvelope>> {
        loop {
            if self.is_closed() {
                return None;
            }
            tokio::select! {
                biased;
                queued = self.control.recv_queued(), if self.control_open => {
                    match queued {
                        Some(queued) => return Some(queued),
                        None => self.control_open = false,
                    }
                }
                queued = self.high_priority.recv_queued(), if self.high_priority_open => {
                    match queued {
                        Some(queued) => return Some(queued),
                        None => self.high_priority_open = false,
                    }
                }
                queued = self.regular.recv_queued(), if self.regular_open => {
                    match queued {
                        Some(queued) => return Some(queued),
                        None => self.regular_open = false,
                    }
                }
            }
        }
    }
}

/// Sender-side handle to a single live stream connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct StreamKey {
    transport: TransportKind,
    remote_addr: Option<SocketAddr>,
    is_dialer: bool,
}

/// Negotiated application protocol for a live QUIC session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QuicSessionProtocol {
    S2s1,
    S2s2,
}

impl QuicSessionProtocol {
    pub const fn name(self) -> &'static str {
        match self {
            Self::S2s1 => "s2s/1",
            Self::S2s2 => "s2s/2",
        }
    }
}

/// Immutable status for one currently-live QUIC session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicSessionStatusSnapshot {
    peer: NodeIdentifier,
    remote_addr: Option<SocketAddr>,
    dialer: bool,
    protocol: QuicSessionProtocol,
    three_lane_ready: bool,
    max_datagram_size: Option<usize>,
    datagram_send_buffer_bytes: usize,
    datagram_receive_buffer_bytes: usize,
    datagrams_queued: u64,
    datagrams_received: u64,
    datagrams_dropped: u64,
}

impl QuicSessionStatusSnapshot {
    pub fn peer(&self) -> NodeIdentifier {
        self.peer
    }

    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    pub fn is_dialer(&self) -> bool {
        self.dialer
    }

    pub fn protocol(&self) -> QuicSessionProtocol {
        self.protocol
    }

    pub fn three_lane_ready(&self) -> bool {
        self.three_lane_ready
    }

    pub fn max_datagram_size(&self) -> Option<usize> {
        self.max_datagram_size
    }

    pub fn datagram_send_buffer_bytes(&self) -> usize {
        self.datagram_send_buffer_bytes
    }

    pub fn datagram_receive_buffer_bytes(&self) -> usize {
        self.datagram_receive_buffer_bytes
    }

    pub fn datagrams_queued(&self) -> u64 {
        self.datagrams_queued
    }

    pub fn datagrams_received(&self) -> u64 {
        self.datagrams_received
    }

    pub fn datagrams_dropped(&self) -> u64 {
        self.datagrams_dropped
    }
}

impl StreamKey {
    pub fn new(transport: TransportKind, remote_addr: Option<SocketAddr>, is_dialer: bool) -> Self {
        Self {
            transport,
            remote_addr,
            is_dialer,
        }
    }

    pub fn transport(&self) -> TransportKind {
        self.transport
    }
}

pub(crate) struct ActiveStream {
    transport: TransportKind,
    remote_addr: Option<SocketAddr>,
    sender: SessionSender,
    closed: CancellationToken,
    is_dialer: bool,
    installed_at: Instant,
}

impl ActiveStream {
    pub fn new(
        transport: TransportKind,
        remote_addr: Option<SocketAddr>,
        sender: AdaptiveQueueSender<OutboundFrame>,
        closed: CancellationToken,
        is_dialer: bool,
    ) -> Self {
        Self {
            transport,
            remote_addr,
            sender: SessionSender::Legacy(sender),
            closed,
            is_dialer,
            installed_at: Instant::now(),
        }
    }

    pub(crate) fn new_quic_v2(
        remote_addr: Option<SocketAddr>,
        sender: QuicV2SessionSender,
        closed: CancellationToken,
        is_dialer: bool,
    ) -> Self {
        Self {
            transport: TransportKind::Quic,
            remote_addr,
            sender: SessionSender::QuicV2(sender),
            closed,
            is_dialer,
            installed_at: Instant::now(),
        }
    }

    pub fn transport(&self) -> TransportKind {
        self.transport
    }

    pub fn is_alive(&self) -> bool {
        !self.closed.is_cancelled() && !self.sender.is_closed()
    }

    pub fn is_dialer(&self) -> bool {
        self.is_dialer
    }

    pub fn installed_at(&self) -> Instant {
        self.installed_at
    }

    pub fn key(&self) -> StreamKey {
        StreamKey::new(self.transport, self.remote_addr, self.is_dialer)
    }

    pub fn cancel(&self) {
        self.closed.cancel();
    }

    fn quic_status(
        &self,
        peer: NodeIdentifier,
        configured_send_buffer_bytes: usize,
        configured_receive_buffer_bytes: usize,
    ) -> Option<QuicSessionStatusSnapshot> {
        if self.transport != TransportKind::Quic || !self.is_alive() {
            return None;
        }
        let (
            protocol,
            three_lane_ready,
            max_datagram_size,
            datagram_send_buffer_bytes,
            datagram_receive_buffer_bytes,
            datagrams_queued,
            datagrams_received,
            datagrams_dropped,
        ) = match &self.sender {
            SessionSender::Legacy(_) => (
                QuicSessionProtocol::S2s1,
                false,
                None,
                configured_send_buffer_bytes,
                configured_receive_buffer_bytes,
                0,
                0,
                0,
            ),
            SessionSender::QuicV2(sender) => {
                let runtime = sender.runtime_status();
                (
                    QuicSessionProtocol::S2s2,
                    true,
                    Some(runtime.max_datagram_size),
                    runtime.datagram_send_buffer_bytes,
                    runtime.datagram_receive_buffer_bytes,
                    runtime.datagrams_queued,
                    runtime.datagrams_received,
                    runtime.datagrams_dropped,
                )
            }
        };
        Some(QuicSessionStatusSnapshot {
            peer,
            remote_addr: self.remote_addr,
            dialer: self.is_dialer,
            protocol,
            three_lane_ready,
            max_datagram_size,
            datagram_send_buffer_bytes,
            datagram_receive_buffer_bytes,
            datagrams_queued,
            datagrams_received,
            datagrams_dropped,
        })
    }
}

#[derive(Clone)]
pub(crate) enum SessionSender {
    Legacy(AdaptiveQueueSender<OutboundFrame>),
    QuicV2(QuicV2SessionSender),
}

#[derive(Clone)]
pub(crate) struct QuicV2SessionSender {
    control: AdaptiveQueueSender<OutboundFrame>,
    high_priority: AdaptiveQueueSender<OutboundFrame>,
    regular: AdaptiveQueueSender<OutboundFrame>,
    datagram: LatestWinsSender<OutboundFrame>,
    runtime: Arc<QuicV2RuntimeState>,
}

struct QuicV2RuntimeState {
    datagram_evidence_session: AtomicU64,
    max_datagram_size: AtomicUsize,
    datagram_send_buffer_bytes: usize,
    datagram_receive_buffer_bytes: usize,
    datagrams_queued: AtomicU64,
    datagrams_received: AtomicU64,
    datagrams_dropped: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
struct QuicV2RuntimeStatus {
    max_datagram_size: usize,
    datagram_send_buffer_bytes: usize,
    datagram_receive_buffer_bytes: usize,
    datagrams_queued: u64,
    datagrams_received: u64,
    datagrams_dropped: u64,
}

pub(crate) struct QuicV2SessionReceivers {
    control: AdaptiveQueueReceiver<OutboundFrame>,
    high_priority: AdaptiveQueueReceiver<OutboundFrame>,
    regular: AdaptiveQueueReceiver<OutboundFrame>,
    datagram: LatestWinsReceiver<OutboundFrame>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SessionSendOutcome {
    evicted_items: usize,
    dropped_expired: bool,
}

impl SessionSendOutcome {
    pub(crate) fn evicted_items(self) -> usize {
        self.evicted_items
    }

    pub(crate) fn dropped_expired(self) -> bool {
        self.dropped_expired
    }
}

#[derive(Debug)]
pub(crate) enum SessionTrySendError {
    Full,
    Closed,
    TooLarge,
}

impl QuicV2SessionSender {
    pub(crate) fn new(
        stream_lane_bytes: usize,
        datagram_bytes: usize,
        datagram_receive_buffer_bytes: usize,
        max_datagram_size: usize,
    ) -> (Self, QuicV2SessionReceivers) {
        // Each reliable lane owns an independent budget. A stalled Regular
        // writer must not consume the reservation pool used by Control or
        // HighPriority.
        let control_budget = AdaptiveQueueBudget::new(stream_lane_bytes);
        let high_budget = AdaptiveQueueBudget::new(stream_lane_bytes);
        let regular_budget = AdaptiveQueueBudget::new(stream_lane_bytes);
        let (control, control_rx) =
            AdaptiveQueueSender::new(control_budget.split(stream_lane_bytes));
        let (high_priority, high_priority_rx) =
            AdaptiveQueueSender::new(high_budget.split(stream_lane_bytes));
        let (regular, regular_rx) =
            AdaptiveQueueSender::new(regular_budget.split(stream_lane_bytes));
        let (datagram, datagram_rx) = latest_wins_queue(datagram_bytes);
        (
            Self {
                control,
                high_priority,
                regular,
                datagram,
                runtime: Arc::new(QuicV2RuntimeState {
                    datagram_evidence_session: AtomicU64::new(0),
                    max_datagram_size: AtomicUsize::new(max_datagram_size),
                    datagram_send_buffer_bytes: datagram_bytes,
                    datagram_receive_buffer_bytes,
                    datagrams_queued: AtomicU64::new(0),
                    datagrams_received: AtomicU64::new(0),
                    datagrams_dropped: AtomicU64::new(0),
                }),
            },
            QuicV2SessionReceivers {
                control: control_rx,
                high_priority: high_priority_rx,
                regular: regular_rx,
                datagram: datagram_rx,
            },
        )
    }

    fn stream_sender(&self, class: MessageClass) -> &AdaptiveQueueSender<OutboundFrame> {
        match class {
            MessageClass::Control => &self.control,
            MessageClass::HighPriority => &self.high_priority,
            MessageClass::Regular => &self.regular,
        }
    }

    fn try_send(&self, frame: OutboundFrame) -> Result<SessionSendOutcome, SessionTrySendError> {
        if frame.level() == ServiceLevel::BestEffort {
            if frame.options().is_expired() {
                self.record_datagram_drop();
                super::metrics::record_quic_datagram_drop(
                    super::metrics::QuicDatagramDropReason::Expired,
                );
                return Ok(SessionSendOutcome {
                    dropped_expired: true,
                    ..SessionSendOutcome::default()
                });
            }
            return self.datagram.try_send(frame).map_or_else(
                |error| match error {
                    LatestWinsSendError::Closed(_) => Err(SessionTrySendError::Closed),
                    LatestWinsSendError::TooLarge { .. } => Err(SessionTrySendError::TooLarge),
                },
                |result| {
                    Ok(SessionSendOutcome {
                        evicted_items: result.evicted_items(),
                        dropped_expired: false,
                    })
                },
            );
        }
        self.try_send_stream(frame)
    }

    fn try_send_stream(
        &self,
        frame: OutboundFrame,
    ) -> Result<SessionSendOutcome, SessionTrySendError> {
        self.stream_sender(frame.class())
            .try_send(frame)
            .map(|()| SessionSendOutcome::default())
            .map_err(|error| match error {
                TryAdaptiveSendError::Full(_) => SessionTrySendError::Full,
                TryAdaptiveSendError::Closed(_) => SessionTrySendError::Closed,
            })
    }

    fn depth_capacity(&self, level: ServiceLevel, class: MessageClass) -> (usize, usize) {
        if level == ServiceLevel::BestEffort {
            return (self.datagram.depth_bytes(), self.datagram.capacity_bytes());
        }
        let sender = self.stream_sender(class);
        (sender.depth_bytes(), sender.capacity_bytes())
    }

    fn stream_depth_capacity(&self, class: MessageClass) -> (usize, usize) {
        let sender = self.stream_sender(class);
        (sender.depth_bytes(), sender.capacity_bytes())
    }

    fn aggregate_depth_capacity(&self) -> (usize, usize) {
        let senders = [&self.control, &self.high_priority, &self.regular];
        let depth = senders
            .iter()
            .map(|sender| sender.depth_bytes())
            .sum::<usize>()
            .saturating_add(self.datagram.depth_bytes());
        let capacity = senders
            .iter()
            .map(|sender| sender.capacity_bytes())
            .sum::<usize>()
            .saturating_add(self.datagram.capacity_bytes());
        (depth, capacity)
    }

    fn is_closed(&self) -> bool {
        self.control.is_closed()
            || self.high_priority.is_closed()
            || self.regular.is_closed()
            || self.datagram.is_closed()
    }

    pub(crate) fn set_max_datagram_size(&self, bytes: usize) {
        self.runtime
            .max_datagram_size
            .store(bytes, Ordering::Relaxed);
    }

    pub(crate) fn set_datagram_evidence_session(&self, session: u64) {
        self.runtime
            .datagram_evidence_session
            .store(session, Ordering::Release);
    }

    pub(crate) fn datagram_evidence_session(&self) -> u64 {
        self.runtime
            .datagram_evidence_session
            .load(Ordering::Acquire)
    }

    pub(crate) fn max_datagram_size(&self) -> usize {
        self.runtime
            .max_datagram_size
            .load(Ordering::Relaxed)
            .min(self.datagram.capacity_bytes())
    }

    pub(crate) fn record_datagram_queued(&self) {
        self.runtime
            .datagrams_queued
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_datagram_received(&self) {
        self.runtime
            .datagrams_received
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_datagram_drop(&self) {
        self.runtime
            .datagrams_dropped
            .fetch_add(1, Ordering::Relaxed);
    }

    fn runtime_status(&self) -> QuicV2RuntimeStatus {
        QuicV2RuntimeStatus {
            max_datagram_size: self.runtime.max_datagram_size.load(Ordering::Relaxed),
            datagram_send_buffer_bytes: self.runtime.datagram_send_buffer_bytes,
            datagram_receive_buffer_bytes: self.runtime.datagram_receive_buffer_bytes,
            datagrams_queued: self.runtime.datagrams_queued.load(Ordering::Relaxed),
            datagrams_received: self.runtime.datagrams_received.load(Ordering::Relaxed),
            datagrams_dropped: self.runtime.datagrams_dropped.load(Ordering::Relaxed),
        }
    }
}

impl QuicV2SessionReceivers {
    pub(crate) fn into_parts(
        self,
    ) -> (
        AdaptiveQueueReceiver<OutboundFrame>,
        AdaptiveQueueReceiver<OutboundFrame>,
        AdaptiveQueueReceiver<OutboundFrame>,
        LatestWinsReceiver<OutboundFrame>,
    ) {
        (
            self.control,
            self.high_priority,
            self.regular,
            self.datagram,
        )
    }
}

impl SessionSender {
    pub(crate) fn quic_v2_datagram_evidence_session(&self) -> Option<u64> {
        match self {
            Self::QuicV2(sender) => Some(sender.datagram_evidence_session()),
            Self::Legacy(_) => None,
        }
    }

    pub(crate) fn try_send(
        &self,
        frame: OutboundFrame,
    ) -> Result<SessionSendOutcome, SessionTrySendError> {
        match self {
            Self::Legacy(sender) => sender
                .try_send(frame)
                .map(|()| SessionSendOutcome::default())
                .map_err(|error| match error {
                    TryAdaptiveSendError::Full(_) => SessionTrySendError::Full,
                    TryAdaptiveSendError::Closed(_) => SessionTrySendError::Closed,
                }),
            Self::QuicV2(sender) => sender.try_send(frame),
        }
    }

    pub(crate) fn try_send_for_path(
        &self,
        path: DeliveryPath,
        frame: OutboundFrame,
    ) -> Result<SessionSendOutcome, SessionTrySendError> {
        match (self, path) {
            (Self::QuicV2(sender), DeliveryPath::QuicStream) => sender.try_send_stream(frame),
            _ => self.try_send(frame),
        }
    }

    pub(crate) fn depth_capacity(
        &self,
        level: ServiceLevel,
        class: MessageClass,
    ) -> (usize, usize) {
        match self {
            Self::Legacy(sender) => (sender.depth_bytes(), sender.capacity_bytes()),
            Self::QuicV2(sender) => sender.depth_capacity(level, class),
        }
    }

    pub(crate) fn depth_capacity_for_path(
        &self,
        path: DeliveryPath,
        level: ServiceLevel,
        class: MessageClass,
    ) -> (usize, usize) {
        match (self, path) {
            (Self::QuicV2(sender), DeliveryPath::QuicStream) => sender.stream_depth_capacity(class),
            _ => self.depth_capacity(level, class),
        }
    }

    pub(crate) fn depth_bytes(&self) -> usize {
        self.aggregate_depth_capacity().0
    }

    pub(crate) fn capacity_bytes(&self) -> usize {
        self.aggregate_depth_capacity().1
    }

    fn aggregate_depth_capacity(&self) -> (usize, usize) {
        match self {
            Self::Legacy(sender) => (sender.depth_bytes(), sender.capacity_bytes()),
            Self::QuicV2(sender) => sender.aggregate_depth_capacity(),
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        match self {
            Self::Legacy(sender) => sender.is_closed(),
            Self::QuicV2(sender) => sender.is_closed(),
        }
    }

    pub(crate) fn quic_v2_max_datagram_size(&self) -> Option<usize> {
        match self {
            Self::QuicV2(sender) => Some(sender.max_datagram_size()),
            Self::Legacy(_) => None,
        }
    }

    pub(crate) fn record_quic_datagram_drop(&self) {
        if let Self::QuicV2(sender) = self {
            sender.record_datagram_drop();
        }
    }
}

#[derive(Debug)]
pub(crate) struct BackoffState {
    initial: Duration,
    next_delay: Duration,
    retry_delay: Duration,
    last_attempt: Option<Instant>,
    consecutive_failures: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct BackoffSnapshot {
    retry_delay: Duration,
    next_delay: Duration,
    consecutive_failures: u32,
}

impl BackoffSnapshot {
    pub fn retry_delay(&self) -> Duration {
        self.retry_delay
    }

    pub fn next_delay(&self) -> Duration {
        self.next_delay
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressBackoffSnapshot {
    retry_delay: Duration,
    next_delay: Duration,
    retry_after: Option<SystemTime>,
    consecutive_failures: u32,
}

impl AddressBackoffSnapshot {
    pub fn new(
        retry_delay: Duration,
        next_delay: Duration,
        retry_after: Option<SystemTime>,
        consecutive_failures: u32,
    ) -> Self {
        Self {
            retry_delay,
            next_delay,
            retry_after,
            consecutive_failures,
        }
    }

    pub fn retry_delay(&self) -> Duration {
        self.retry_delay
    }

    pub fn next_delay(&self) -> Duration {
        self.next_delay
    }

    pub fn retry_after(&self) -> Option<SystemTime> {
        self.retry_after
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }
}

impl BackoffState {
    pub fn new(initial: Duration) -> Self {
        Self {
            initial,
            next_delay: initial,
            retry_delay: initial,
            last_attempt: None,
            consecutive_failures: 0,
        }
    }

    fn from_snapshot(
        initial: Duration,
        snapshot: AddressBackoffSnapshot,
        now: Instant,
        wall_now: SystemTime,
    ) -> Self {
        let mut retry_delay = nonzero_or(snapshot.retry_delay(), initial);
        let next_delay = nonzero_or(snapshot.next_delay(), initial);
        let last_attempt = snapshot.retry_after().and_then(|retry_after| {
            let remaining = retry_after.duration_since(wall_now).ok()?;
            if remaining.is_zero() {
                return None;
            }
            if remaining > retry_delay {
                retry_delay = remaining;
                return Some(now);
            }
            let elapsed = retry_delay.saturating_sub(remaining);
            now.checked_sub(elapsed).or(Some(now))
        });

        Self {
            initial,
            next_delay,
            retry_delay,
            last_attempt,
            consecutive_failures: snapshot.consecutive_failures(),
        }
    }

    pub fn ready(&self, now: Instant, retry_cap: Duration) -> bool {
        let effective_delay = self.retry_delay.min(retry_cap);
        match self.last_attempt {
            None => true,
            Some(at) => now.duration_since(at) >= effective_delay,
        }
    }

    pub fn record_attempt(&mut self) {
        self.last_attempt = Some(Instant::now());
    }

    pub fn record_failure(&mut self, retry_cap: Duration) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let doubled = self.next_delay.saturating_mul(2);
        self.next_delay = if doubled > retry_cap {
            retry_cap
        } else {
            doubled
        };
        self.retry_delay = jittered_delay(self.next_delay.min(retry_cap), retry_cap);
        self.last_attempt = Some(Instant::now());
    }

    pub fn record_failure_with_floor(&mut self, retry_floor: Duration, retry_cap: Duration) {
        let retry_cap = retry_cap.max(retry_floor);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let doubled = self.next_delay.saturating_mul(2);
        self.next_delay = doubled.max(retry_floor).min(retry_cap);
        self.retry_delay = jittered_delay(self.next_delay, retry_cap);
        self.last_attempt = Some(Instant::now());
    }

    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.next_delay = self.initial;
        self.retry_delay = self.initial;
    }

    fn snapshot(&self) -> BackoffSnapshot {
        BackoffSnapshot {
            retry_delay: self.retry_delay,
            next_delay: self.next_delay,
            consecutive_failures: self.consecutive_failures,
        }
    }

    fn address_snapshot(&self, now: Instant, wall_now: SystemTime) -> AddressBackoffSnapshot {
        let retry_after = self.last_attempt.map(|last_attempt| {
            let elapsed = now
                .checked_duration_since(last_attempt)
                .unwrap_or(Duration::ZERO);
            let remaining = self.retry_delay.saturating_sub(elapsed);
            wall_now.checked_add(remaining).unwrap_or(wall_now)
        });
        AddressBackoffSnapshot::new(
            self.retry_delay,
            self.next_delay,
            retry_after,
            self.consecutive_failures,
        )
    }
}

fn nonzero_or(value: Duration, fallback: Duration) -> Duration {
    if value.is_zero() { fallback } else { value }
}

fn jittered_delay(base: Duration, cap: Duration) -> Duration {
    let base_nanos = base.as_nanos().min(u64::MAX as u128) as u64;
    let cap_nanos = cap.as_nanos().min(u64::MAX as u128) as u64;
    let jitter_window = base_nanos / BACKOFF_JITTER_DIVISOR;
    if jitter_window == 0 {
        return base;
    }
    let low = base_nanos.saturating_sub(jitter_window);
    let high = base_nanos
        .saturating_add(jitter_window)
        .min(cap_nanos.max(low));
    Duration::from_nanos(rand::rng().random_range(low..=high))
}

/// Aggregate state for one peer. The supervisor mutates this through `Mutex`
/// guards held briefly across non-blocking work.
pub(crate) struct PeerState {
    node_id: NodeIdentifier,
    addresses: Mutex<Vec<PeerAddress>>,
    advertised_addresses: Mutex<HashSet<PeerAddress>>,
    streams: Mutex<HashMap<StreamKey, ActiveStream>>,
    outbound_sender: PeerOutboundSender,
    outbound_receiver: Mutex<Option<PeerOutboundReceiver>>,
    udp_seen_at: Mutex<Option<Instant>>,
    udp_addr: Mutex<Option<std::net::SocketAddr>>,
    /// Authenticated inbound remote IPs by transport. Source ports are often
    /// ephemeral; IPs are combined only with same-transport service ports.
    observed_remote_ips: Mutex<HashMap<TransportKind, Vec<std::net::IpAddr>>>,
    last_seen_wall: Mutex<Option<SystemTime>>,
    metrics: Arc<PeerMetrics>,
    backoff_initial: Duration,
    address_backoffs: Mutex<HashMap<PeerAddress, BackoffState>>,
    outbound_queue_watermark: Mutex<QueueWatermark>,
    outbound_stream_queue_watermarks: Mutex<HashMap<TransportKind, QueueWatermark>>,
    /// Current encrypted UDP datagram ceiling for this peer. The UDP endpoint
    /// lowers it after a packet-too-large error; the manager uses it while
    /// building transport-specific payload variants.
    udp_datagram_mtu: AtomicUsize,
    /// Largest UDP datagram budget we will try after an authenticated probe.
    udp_datagram_mtu_ceiling: AtomicUsize,
    udp_datagram_mtu_last_probe: Mutex<Option<Instant>>,
    expired_outbound_drops: ExpiredOutboundDropCounters,
    transport_health_exclusions:
        Mutex<HashMap<(TransportKind, TransportHealthExclusionReason), u64>>,
    datagram_path_health: Mutex<HashMap<DeliveryPath, DatagramPathHealthObservation>>,
    /// KCP is kept out of BestEffort selection after failaway/no-progress
    /// until the native KCP sampler observes a newer ACK-derived RTT sample.
    kcp_best_effort_recovery_after_rtt_samples: Mutex<Option<u64>>,
    voice_transport_binding: Mutex<VoiceTransportBinding>,
    outbound_dispatch_notify: Notify,
    /// Set true while a connect attempt is in flight, to prevent duplicate
    /// dials racing inside the supervisor.
    connecting: AtomicBool,
}

impl PeerState {
    pub fn new(
        node_id: NodeIdentifier,
        backoff_initial: Duration,
        bandwidth_window: Duration,
        metrics_tuning: MetricsTuning,
        outbound_queue_bytes: usize,
    ) -> Arc<Self> {
        let outbound_budget = AdaptiveQueueBudget::new(outbound_queue_bytes);
        let (outbound_sender, outbound_receiver) = PeerOutboundSender::new(outbound_budget);
        Arc::new(Self {
            node_id,
            addresses: Mutex::new(Vec::new()),
            advertised_addresses: Mutex::new(HashSet::new()),
            streams: Mutex::new(HashMap::new()),
            outbound_sender,
            outbound_receiver: Mutex::new(Some(outbound_receiver)),
            udp_seen_at: Mutex::new(None),
            udp_addr: Mutex::new(None),
            observed_remote_ips: Mutex::new(HashMap::new()),
            last_seen_wall: Mutex::new(None),
            metrics: Arc::new(PeerMetrics::new(bandwidth_window, metrics_tuning)),
            backoff_initial,
            address_backoffs: Mutex::new(HashMap::new()),
            outbound_queue_watermark: Mutex::new(QueueWatermark::new(Instant::now())),
            outbound_stream_queue_watermarks: Mutex::new(HashMap::new()),
            udp_datagram_mtu: AtomicUsize::new(1200),
            udp_datagram_mtu_ceiling: AtomicUsize::new(1200),
            udp_datagram_mtu_last_probe: Mutex::new(None),
            expired_outbound_drops: ExpiredOutboundDropCounters::default(),
            transport_health_exclusions: Mutex::new(HashMap::new()),
            datagram_path_health: Mutex::new(HashMap::new()),
            kcp_best_effort_recovery_after_rtt_samples: Mutex::new(None),
            voice_transport_binding: Mutex::new(VoiceTransportBinding::default()),
            outbound_dispatch_notify: Notify::new(),
            connecting: AtomicBool::new(false),
        })
    }

    pub fn node_id(&self) -> NodeIdentifier {
        self.node_id
    }

    pub fn metrics(&self) -> &Arc<PeerMetrics> {
        &self.metrics
    }

    pub fn take_outbound_receiver(&self) -> Option<PeerOutboundReceiver> {
        self.outbound_receiver.lock().take()
    }

    pub fn outbound_sender(&self) -> PeerOutboundSender {
        self.outbound_sender.clone()
    }

    pub fn outbound_queue_depth_bytes(&self) -> usize {
        self.outbound_sender.depth_bytes()
    }

    pub fn outbound_queue_capacity_bytes(&self) -> usize {
        self.outbound_sender.capacity_bytes()
    }

    pub(crate) fn udp_datagram_mtu(&self) -> usize {
        self.udp_datagram_mtu.load(Ordering::Relaxed)
    }

    pub(crate) fn set_udp_datagram_mtu_limits(&self, mtu: usize, ceiling: usize) {
        self.udp_datagram_mtu.store(mtu, Ordering::Relaxed);
        self.udp_datagram_mtu_ceiling
            .store(ceiling.max(mtu), Ordering::Relaxed);
        *self.udp_datagram_mtu_last_probe.lock() = None;
    }

    pub(crate) fn reduce_udp_datagram_mtu(&self, rejected_datagram_bytes: usize) -> usize {
        let mut current = self.udp_datagram_mtu();
        loop {
            let reduced = current
                .min(rejected_datagram_bytes.saturating_sub(64))
                .max(576);
            if reduced >= current {
                return current;
            }
            match self.udp_datagram_mtu.compare_exchange_weak(
                current,
                reduced,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return reduced,
                Err(observed) => current = observed,
            }
        }
    }

    pub(crate) fn claim_udp_datagram_mtu_probe(
        &self,
        now: Instant,
        interval: Duration,
        step: usize,
    ) -> Option<usize> {
        let current = self.udp_datagram_mtu();
        let ceiling = self.udp_datagram_mtu_ceiling.load(Ordering::Relaxed);
        if interval.is_zero() || step == 0 || current >= ceiling {
            return None;
        }
        let mut last_probe = self.udp_datagram_mtu_last_probe.lock();
        if last_probe.is_some_and(|last| now.saturating_duration_since(last) < interval) {
            return None;
        }
        *last_probe = Some(now);
        Some(current.saturating_add(step).min(ceiling))
    }

    pub(crate) fn confirm_udp_datagram_mtu(&self, confirmed_mtu: usize) -> usize {
        let ceiling = self.udp_datagram_mtu_ceiling.load(Ordering::Relaxed);
        let mut current = self.udp_datagram_mtu();
        loop {
            let confirmed = confirmed_mtu.min(ceiling);
            if confirmed <= current {
                return current;
            }
            match self.udp_datagram_mtu.compare_exchange_weak(
                current,
                confirmed,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return confirmed,
                Err(observed) => current = observed,
            }
        }
    }

    pub fn notify_outbound_dispatch(&self) {
        self.outbound_dispatch_notify.notify_one();
    }

    pub async fn wait_for_outbound_dispatch_signal(&self) {
        self.outbound_dispatch_notify.notified().await;
    }

    /// Atomically claim the connect slot. Returns `true` if this caller now
    /// owns the in-flight dial; `false` if another task already had it.
    pub fn try_begin_connect(&self) -> bool {
        self.connecting
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Release the connect slot previously claimed via `try_begin_connect`.
    pub fn end_connect(&self) {
        self.connecting.store(false, Ordering::SeqCst);
    }

    /// Add an address if it isn't already known. Returns true if newly added.
    pub fn add_address(&self, addr: PeerAddress) -> bool {
        self.note_seen_now();
        let mut g = self.addresses.lock();
        if g.contains(&addr) {
            return false;
        }
        g.push(addr);
        self.ensure_address_backoff(addr);
        true
    }

    /// Add an address while preserving an externally observed last-seen time,
    /// such as one loaded from disk.
    pub fn add_address_seen_at(&self, addr: PeerAddress, seen_at: SystemTime) -> bool {
        self.note_seen_at(seen_at);
        let mut g = self.addresses.lock();
        if g.contains(&addr) {
            return false;
        }
        g.push(addr);
        self.ensure_address_backoff(addr);
        true
    }

    pub fn add_address_seen_at_with_backoff(
        &self,
        addr: PeerAddress,
        seen_at: SystemTime,
        backoff: Option<AddressBackoffSnapshot>,
    ) -> bool {
        self.note_seen_at(seen_at);
        let mut g = self.addresses.lock();
        let added = if g.contains(&addr) {
            false
        } else {
            g.push(addr);
            true
        };
        drop(g);

        if let Some(backoff) = backoff {
            self.restore_address_backoff(addr, backoff);
        } else {
            self.ensure_address_backoff(addr);
        }

        added
    }

    fn ensure_address_backoff(&self, addr: PeerAddress) {
        self.address_backoffs
            .lock()
            .entry(addr)
            .or_insert_with(|| BackoffState::new(self.backoff_initial));
    }

    pub fn restore_address_backoff(&self, addr: PeerAddress, backoff: AddressBackoffSnapshot) {
        self.address_backoffs.lock().insert(
            addr,
            BackoffState::from_snapshot(
                self.backoff_initial,
                backoff,
                Instant::now(),
                SystemTime::now(),
            ),
        );
    }

    pub fn address_retry_ready(
        &self,
        addr: PeerAddress,
        now: Instant,
        retry_cap: Duration,
    ) -> bool {
        self.address_backoffs
            .lock()
            .get(&addr)
            .is_none_or(|backoff| backoff.ready(now, retry_cap))
    }

    pub fn record_address_attempt(&self, addr: PeerAddress) {
        self.address_backoffs
            .lock()
            .entry(addr)
            .or_insert_with(|| BackoffState::new(self.backoff_initial))
            .record_attempt();
    }

    pub fn record_address_failure(
        &self,
        addr: PeerAddress,
        retry_cap: Duration,
    ) -> BackoffSnapshot {
        let mut address_backoffs = self.address_backoffs.lock();
        let backoff = address_backoffs
            .entry(addr)
            .or_insert_with(|| BackoffState::new(self.backoff_initial));
        backoff.record_failure(retry_cap);
        backoff.snapshot()
    }

    pub fn record_address_failure_with_floor(
        &self,
        addr: PeerAddress,
        retry_floor: Duration,
        retry_cap: Duration,
    ) -> BackoffSnapshot {
        let mut address_backoffs = self.address_backoffs.lock();
        let backoff = address_backoffs
            .entry(addr)
            .or_insert_with(|| BackoffState::new(self.backoff_initial));
        backoff.record_failure_with_floor(retry_floor, retry_cap);
        backoff.snapshot()
    }

    pub fn record_address_success(&self, addr: PeerAddress) {
        self.address_backoffs
            .lock()
            .entry(addr)
            .or_insert_with(|| BackoffState::new(self.backoff_initial))
            .record_success();
    }

    pub fn note_observed_remote_addr(&self, transport: TransportKind, addr: std::net::SocketAddr) {
        let ip = canonical_ip(addr.ip());
        if ip_looks_unusable(ip) {
            return;
        }
        let mut observed_by_transport = self.observed_remote_ips.lock();
        let observed = observed_by_transport.entry(transport).or_default();
        if let Some(pos) = observed.iter().position(|candidate| *candidate == ip) {
            observed.remove(pos);
        }
        observed.push(ip);
        if observed.len() > MAX_OBSERVED_REMOTE_IPS {
            observed.remove(0);
        }
        self.note_seen_now();
    }

    pub fn address_candidates(&self, addr: PeerAddress) -> Vec<PeerAddress> {
        let published = canonical_socket_addr(addr.addr());
        let published_addr = PeerAddress::new(published, addr.transport());
        let observed = self
            .observed_remote_ips
            .lock()
            .get(&addr.transport())
            .cloned()
            .unwrap_or_default();
        let mut candidates = Vec::new();

        if published_ip_looks_usable(published.ip()) {
            push_unique_candidate(&mut candidates, published_addr);
        }

        for observed_ip in observed {
            if should_add_observed_candidate(published.ip(), observed_ip) {
                push_unique_candidate(
                    &mut candidates,
                    PeerAddress::new(
                        canonical_socket_addr(std::net::SocketAddr::new(
                            observed_ip,
                            published.port(),
                        )),
                        addr.transport(),
                    ),
                );
            }
        }

        candidates
    }

    pub fn replace_advertised_addresses(&self, addrs: &[PeerAddress]) {
        let mut advertised = self.advertised_addresses.lock();
        advertised.clear();
        advertised.extend(addrs.iter().copied());
    }

    pub fn address_is_actively_advertised(&self, addr: PeerAddress) -> bool {
        self.advertised_addresses.lock().contains(&addr)
    }

    pub fn address_matches_live_remote_ip(&self, addr: PeerAddress) -> bool {
        let ip = canonical_ip(addr.addr().ip());
        let mut streams = self.streams.lock();
        prune_dead_streams(&mut streams);
        streams.values().any(|stream| {
            stream.is_alive()
                && stream
                    .remote_addr
                    .is_some_and(|remote_addr| canonical_ip(remote_addr.ip()) == ip)
        })
    }

    pub fn address_is_currently_confirmed(&self, addr: PeerAddress) -> bool {
        self.address_is_actively_advertised(addr) || self.address_matches_live_remote_ip(addr)
    }

    pub fn confirm_address(&self, addr: PeerAddress) {
        let mut g = self.addresses.lock();
        if let Some(pos) = g.iter().position(|candidate| *candidate == addr) {
            let addr = g.remove(pos);
            g.insert(0, addr);
        } else {
            g.insert(0, addr);
        }
        self.ensure_address_backoff(addr);
    }

    pub fn note_seen_now(&self) {
        self.note_seen_at(SystemTime::now());
    }

    pub fn note_seen_at(&self, seen_at: SystemTime) {
        let mut g = self.last_seen_wall.lock();
        if g.is_none_or(|prev| seen_at > prev) {
            *g = Some(seen_at);
        }
    }

    pub fn last_seen(&self) -> Option<SystemTime> {
        *self.last_seen_wall.lock()
    }

    pub fn last_seen_age(&self, now: SystemTime) -> Option<Duration> {
        self.last_seen().map(|seen| {
            now.duration_since(seen)
                .unwrap_or_else(|_| Duration::from_secs(0))
        })
    }

    pub fn remove_address(&self, addr: PeerAddress) -> bool {
        let mut g = self.addresses.lock();
        let before = g.len();
        g.retain(|a| *a != addr);
        let removed = g.len() != before;
        drop(g);
        if removed {
            self.address_backoffs.lock().remove(&addr);
            self.advertised_addresses.lock().remove(&addr);
        }
        removed
    }

    pub fn snapshot_addresses(&self) -> Vec<PeerAddress> {
        self.addresses.lock().clone()
    }

    pub fn snapshot_address_backoffs(
        &self,
        addresses: &[PeerAddress],
        now: Instant,
        wall_now: SystemTime,
    ) -> HashMap<PeerAddress, AddressBackoffSnapshot> {
        let backoffs = self.address_backoffs.lock();
        addresses
            .iter()
            .filter_map(|addr| {
                backoffs
                    .get(addr)
                    .map(|backoff| (*addr, backoff.address_snapshot(now, wall_now)))
            })
            .collect()
    }

    pub(crate) fn max_consecutive_failures_for_transports(
        &self,
        transports: &[TransportKind],
    ) -> u32 {
        self.address_backoffs
            .lock()
            .iter()
            .filter(|(addr, _)| transports.contains(&addr.transport()))
            .map(|(_, backoff)| backoff.consecutive_failures)
            .max()
            .unwrap_or(0)
    }

    pub fn install_stream(&self, stream: ActiveStream) {
        let key = stream.key();
        let mut g = self.streams.lock();
        prune_dead_streams(&mut g);
        if stream.transport() == TransportKind::Udp {
            drop_udp_streams(&mut g);
        }
        if let Some(prev) = g.insert(key, stream) {
            prev.closed.cancel();
        }
        self.notify_outbound_dispatch();
        self.note_seen_now();
    }

    /// Install a stream unless the exact same connection key is already live.
    pub fn try_install_stream(&self, new_stream: ActiveStream) -> Result<(), ActiveStream> {
        let key = new_stream.key();
        let mut g = self.streams.lock();
        prune_dead_streams(&mut g);
        if new_stream.transport() == TransportKind::Udp {
            drop_udp_streams(&mut g);
        }
        if g.get(&key).is_some_and(ActiveStream::is_alive) {
            return Err(new_stream);
        }
        if let Some(prev) = g.insert(key, new_stream) {
            prev.closed.cancel();
        }
        self.notify_outbound_dispatch();
        self.note_seen_now();
        Ok(())
    }

    pub fn drop_stream(&self, kind: TransportKind) {
        let mut g = self.streams.lock();
        g.retain(|key, stream| {
            if key.transport() == kind {
                stream.cancel();
                false
            } else {
                true
            }
        });
        self.notify_outbound_dispatch();
    }

    pub fn has_live_outgoing_to(&self, addr: PeerAddress) -> bool {
        let key = StreamKey::new(addr.transport(), Some(addr.addr()), true);
        let mut g = self.streams.lock();
        prune_dead_streams(&mut g);
        if addr.transport() == TransportKind::Udp {
            return g
                .values()
                .any(|stream| stream.transport == TransportKind::Udp && stream.is_alive());
        }
        g.get(&key).is_some_and(ActiveStream::is_alive)
    }

    pub fn live_kinds(&self) -> Vec<TransportKind> {
        let mut g = self.streams.lock();
        prune_dead_streams(&mut g);
        let mut kinds = Vec::new();
        for stream in g.values() {
            if stream.is_alive() && !kinds.contains(&stream.transport()) {
                kinds.push(stream.transport());
            }
        }
        kinds
    }

    pub(crate) fn quic_session_status(
        &self,
        configured_send_buffer_bytes: usize,
        configured_receive_buffer_bytes: usize,
    ) -> Vec<QuicSessionStatusSnapshot> {
        let mut streams = self.streams.lock();
        prune_dead_streams(&mut streams);
        let mut out = streams
            .values()
            .filter_map(|stream| {
                stream.quic_status(
                    self.node_id,
                    configured_send_buffer_bytes,
                    configured_receive_buffer_bytes,
                )
            })
            .collect::<Vec<_>>();
        out.sort_by_key(|snapshot| {
            (
                snapshot.remote_addr(),
                snapshot.is_dialer(),
                snapshot.protocol(),
            )
        });
        out
    }

    /// Attempt to obtain a sender for any stream of the requested transport.
    /// Drops the stream if it has died.
    pub fn try_get_stream(&self, kind: TransportKind) -> Option<SessionSender> {
        let mut g = self.streams.lock();
        prune_dead_streams(&mut g);
        g.values()
            .filter(|s| s.transport() == kind && s.is_alive())
            .max_by_key(|s| s.installed_at())
            .map(|s| s.sender.clone())
    }

    /// Obtain the newest live QUIC v2 sender. QUIC DATAGRAM is a delivery
    /// path of an s2s/2 session, not a separate physical transport, so callers
    /// selecting that path must not let a newer legacy s2s/1 stream mask it.
    pub(crate) fn try_get_quic_v2_stream(&self) -> Option<SessionSender> {
        let mut streams = self.streams.lock();
        prune_dead_streams(&mut streams);
        streams
            .values()
            .filter(|stream| {
                stream.transport() == TransportKind::Quic
                    && stream.is_alive()
                    && stream.sender.quic_v2_max_datagram_size().is_some()
            })
            .max_by_key(|stream| stream.installed_at())
            .map(|stream| stream.sender.clone())
    }

    pub fn record_outbound_queue_sample(
        &self,
        class: MessageClass,
        depth: usize,
        capacity: usize,
        is_full: bool,
    ) {
        let report =
            self.outbound_queue_watermark
                .lock()
                .record(Instant::now(), depth, capacity, is_full);
        if let Some(report) = report {
            let status = report.status();
            tracing::debug!(
                peer = %self.node_id,
                ?class,
                queue_capacity = status.capacity(),
                queue_depth = status.depth(),
                queue_high_watermark = status.high_depth(),
                queue_samples = status.samples(),
                queue_full_samples = status.full_samples(),
                interval_secs = report.interval().as_secs(),
                "s2s outbound peer queue watermark"
            );
        }
    }

    pub fn record_outbound_stream_queue_sample(
        &self,
        transport: TransportKind,
        class: MessageClass,
        depth: usize,
        capacity: usize,
        is_full: bool,
    ) {
        let report = {
            let now = Instant::now();
            let mut watermarks = self.outbound_stream_queue_watermarks.lock();
            watermarks
                .entry(transport)
                .or_insert_with(|| QueueWatermark::new(now))
                .record(now, depth, capacity, is_full)
        };
        if let Some(report) = report {
            let status = report.status();
            tracing::debug!(
                peer = %self.node_id,
                ?transport,
                ?class,
                queue_capacity = status.capacity(),
                queue_depth = status.depth(),
                queue_high_watermark = status.high_depth(),
                queue_samples = status.samples(),
                queue_full_samples = status.full_samples(),
                interval_secs = report.interval().as_secs(),
                "s2s outbound stream queue watermark"
            );
        }
    }

    pub fn outbound_queue_status(&self) -> Vec<OutboundQueueStatusSnapshot> {
        let mut out = Vec::new();
        let routed_status = self
            .outbound_queue_watermark
            .lock()
            .snapshot()
            .with_current(
                self.outbound_queue_depth_bytes(),
                self.outbound_queue_capacity_bytes(),
            );
        out.push(OutboundQueueStatusSnapshot::new_routed(
            self.node_id,
            routed_status,
        ));

        let current_by_transport = {
            let mut streams = self.streams.lock();
            prune_dead_streams(&mut streams);
            let mut current = HashMap::<TransportKind, (usize, usize)>::new();
            for stream in streams.values().filter(|stream| stream.is_alive()) {
                let depth = stream.sender.depth_bytes();
                let capacity = stream.sender.capacity_bytes();
                current
                    .entry(stream.transport())
                    .and_modify(|(current_depth, current_capacity)| {
                        *current_depth = (*current_depth).max(depth);
                        *current_capacity = (*current_capacity).max(capacity);
                    })
                    .or_insert((depth, capacity));
            }
            current
        };

        let watermarks = self.outbound_stream_queue_watermarks.lock();
        let mut transports: HashSet<_> = watermarks.keys().copied().collect();
        transports.extend(current_by_transport.keys().copied());

        out.extend(transports.into_iter().map(|transport| {
            let mut status = watermarks
                .get(&transport)
                .map(QueueWatermark::snapshot)
                .unwrap_or_default();
            if let Some((depth, capacity)) = current_by_transport.get(&transport).copied() {
                status = status.with_current(depth, capacity);
            }
            OutboundQueueStatusSnapshot::new_transport(self.node_id, transport, status)
        }));
        out.sort_by_key(|snapshot| snapshot.queue_key());
        out
    }

    pub(crate) fn outbound_stream_queue_status(
        &self,
        transport: TransportKind,
    ) -> Option<QueueStatusSnapshot> {
        let current = {
            let mut streams = self.streams.lock();
            prune_dead_streams(&mut streams);
            streams
                .values()
                .filter(|stream| stream.is_alive() && stream.transport() == transport)
                .max_by_key(|stream| stream.installed_at())
                .map(|stream| (stream.sender.depth_bytes(), stream.sender.capacity_bytes()))
        };

        let mut status = self
            .outbound_stream_queue_watermarks
            .lock()
            .get(&transport)
            .map(QueueWatermark::snapshot)
            .unwrap_or_default();
        if let Some((depth, capacity)) = current {
            status = status.with_current(depth, capacity);
        }
        Some(status)
    }

    pub(crate) fn outbound_lane_queue_status(
        &self,
        transport: TransportKind,
        level: ServiceLevel,
        class: MessageClass,
    ) -> Option<QueueStatusSnapshot> {
        let mut streams = self.streams.lock();
        prune_dead_streams(&mut streams);
        streams
            .values()
            .filter(|stream| stream.is_alive() && stream.transport() == transport)
            .max_by_key(|stream| stream.installed_at())
            .map(|stream| {
                let (depth, capacity) = stream.sender.depth_capacity(level, class);
                QueueStatusSnapshot::default().with_current(depth, capacity)
            })
    }

    pub(crate) fn record_expired_outbound_drop(
        &self,
        stage: ExpiredOutboundDropStage,
        transport: Option<TransportKind>,
        class: MessageClass,
    ) {
        self.expired_outbound_drops.record(stage, transport, class);
    }

    pub(crate) fn expired_outbound_drop_status(&self) -> Vec<ExpiredOutboundDropSnapshot> {
        self.expired_outbound_drops.snapshots(self.node_id)
    }

    pub(crate) fn record_transport_health_exclusion(
        &self,
        transport: TransportKind,
        reason: TransportHealthExclusionReason,
    ) {
        let mut counters = self.transport_health_exclusions.lock();
        let counter = counters.entry((transport, reason)).or_insert(0);
        *counter = counter.saturating_add(1);
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn observe_datagram_path_health(
        &self,
        path: DeliveryPath,
        effective_loss_ppm: Option<u32>,
        loss_samples: u64,
        min_samples: u64,
        address_failures_blocked: bool,
        consecutive_probe_losses_blocked: bool,
        suspect_effective_loss_ppm: u32,
        recover_effective_loss_ppm: u32,
        hard_effective_loss_ppm: u32,
        now: Instant,
    ) -> DatagramPathHealthState {
        debug_assert!(path.is_datagram());
        let mut observations = self.datagram_path_health.lock();
        let previous = observations.get(&path).copied();
        let sampled_loss = effective_loss_ppm.filter(|_| loss_samples >= min_samples);
        let recover_effective_loss_ppm = recover_effective_loss_ppm.min(suspect_effective_loss_ppm);

        let (state, reason) = if address_failures_blocked {
            (
                DatagramPathHealthState::Blocked,
                DatagramPathHealthReason::AddressFailures,
            )
        } else if consecutive_probe_losses_blocked {
            (
                DatagramPathHealthState::Blocked,
                DatagramPathHealthReason::ProbeFailures,
            )
        } else if sampled_loss.is_some_and(|loss| loss >= hard_effective_loss_ppm) {
            (
                DatagramPathHealthState::Blocked,
                DatagramPathHealthReason::HardLoss,
            )
        } else if sampled_loss.is_none() {
            (
                DatagramPathHealthState::Probing,
                DatagramPathHealthReason::InsufficientSamples,
            )
        } else if sampled_loss.is_some_and(|loss| loss >= suspect_effective_loss_ppm) {
            (
                DatagramPathHealthState::Suspect,
                DatagramPathHealthReason::MeasuredLoss,
            )
        } else if previous.is_some_and(|observation| {
            matches!(
                observation.state,
                DatagramPathHealthState::Suspect | DatagramPathHealthState::Blocked
            ) && sampled_loss.is_none_or(|loss| loss > recover_effective_loss_ppm)
        }) {
            let previous = previous.expect("checked above");
            (previous.state, previous.reason)
        } else if sampled_loss.is_some() {
            let recovered = previous.is_some_and(|observation| {
                matches!(
                    observation.state,
                    DatagramPathHealthState::Suspect | DatagramPathHealthState::Blocked
                )
            });
            (
                DatagramPathHealthState::Healthy,
                if recovered {
                    DatagramPathHealthReason::Recovered
                } else {
                    DatagramPathHealthReason::WithinThreshold
                },
            )
        } else {
            unreachable!("sampled loss handled above")
        };

        let state_changed = previous.is_none_or(|observation| observation.state != state);
        let observation = DatagramPathHealthObservation {
            state,
            reason,
            effective_loss_ppm,
            path_health_score_ppm: None,
            loss_samples,
            transitions: previous
                .map(|observation| {
                    observation
                        .transitions
                        .saturating_add(u64::from(state_changed))
                })
                .unwrap_or(0),
            changed_at: previous
                .filter(|_| !state_changed)
                .map(|observation| observation.changed_at)
                .unwrap_or(now),
            observed_at: now,
            last_evidence_generation: previous
                .and_then(|observation| observation.last_evidence_generation),
            last_scored_generation: previous
                .and_then(|observation| observation.last_scored_generation),
            last_diagnostic_generation: previous
                .and_then(|observation| observation.last_diagnostic_generation),
            diagnostic_observed_at: previous
                .and_then(|observation| observation.diagnostic_observed_at),
            consecutive_bad_windows: previous
                .map(|observation| observation.consecutive_bad_windows)
                .unwrap_or(0),
            healthy_since: previous.and_then(|observation| observation.healthy_since),
            recovery_healthy_span: previous
                .map(|observation| observation.recovery_healthy_span)
                .unwrap_or(Duration::ZERO),
            recovery_required: previous.is_some_and(|observation| observation.recovery_required),
            sample_confidence_ppm: if min_samples == 0 {
                1_000_000
            } else {
                loss_samples
                    .saturating_mul(1_000_000)
                    .saturating_div(min_samples)
                    .min(1_000_000) as u32
            },
            enqueue_accepted: 0,
            enqueue_rejected: 0,
            too_large: 0,
            pressure: 0,
            outcome_successes: 0,
            outcome_failures: 0,
            ingress_validated: 0,
            ingress_rejected: 0,
            ingress_read_failures: 0,
        };
        observations.insert(path, observation);
        state
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn observe_quic_datagram_path_health(
        &self,
        evidence: &[DatagramPathEvidenceSnapshot],
        min_samples: u64,
        suspect_score_ppm: u32,
        recover_score_ppm: u32,
        suspect_bad_windows: u32,
        recover_healthy_for: Duration,
        stale_after: Duration,
        now: Instant,
    ) -> DatagramPathHealthState {
        let path = DeliveryPath::QuicDatagram;
        let mut observations = self.datagram_path_health.lock();
        let previous = observations.get(&path).copied();
        let fresh = evidence
            .iter()
            .copied()
            .filter(|evidence| {
                evidence.completed_at().is_some_and(|completed_at| {
                    now.saturating_duration_since(completed_at) < stale_after
                })
            })
            .collect::<Vec<_>>();
        if fresh.is_empty() {
            let state = DatagramPathHealthState::Probing;
            let state_changed = previous.is_none_or(|observation| observation.state != state);
            let previous = previous.unwrap_or(DatagramPathHealthObservation {
                state,
                reason: DatagramPathHealthReason::InsufficientSamples,
                effective_loss_ppm: None,
                path_health_score_ppm: None,
                loss_samples: 0,
                transitions: 0,
                changed_at: now,
                observed_at: now,
                last_evidence_generation: None,
                last_scored_generation: None,
                last_diagnostic_generation: None,
                diagnostic_observed_at: None,
                consecutive_bad_windows: 0,
                healthy_since: None,
                recovery_healthy_span: Duration::ZERO,
                recovery_required: false,
                sample_confidence_ppm: 0,
                enqueue_accepted: 0,
                enqueue_rejected: 0,
                too_large: 0,
                pressure: 0,
                outcome_successes: 0,
                outcome_failures: 0,
                ingress_validated: 0,
                ingress_rejected: 0,
                ingress_read_failures: 0,
            });
            observations.insert(
                path,
                DatagramPathHealthObservation {
                    state,
                    reason: DatagramPathHealthReason::InsufficientSamples,
                    transitions: previous
                        .transitions
                        .saturating_add(u64::from(state_changed)),
                    changed_at: if state_changed {
                        now
                    } else {
                        previous.changed_at
                    },
                    consecutive_bad_windows: 0,
                    healthy_since: None,
                    recovery_healthy_span: Duration::ZERO,
                    sample_confidence_ppm: 0,
                    ..previous
                },
            );
            return state;
        }
        let mut current = previous.unwrap_or(DatagramPathHealthObservation {
            state: DatagramPathHealthState::Probing,
            reason: DatagramPathHealthReason::InsufficientSamples,
            effective_loss_ppm: None,
            path_health_score_ppm: None,
            loss_samples: 0,
            transitions: 0,
            changed_at: now,
            observed_at: now,
            last_evidence_generation: None,
            last_scored_generation: None,
            last_diagnostic_generation: None,
            diagnostic_observed_at: None,
            consecutive_bad_windows: 0,
            healthy_since: None,
            recovery_healthy_span: Duration::ZERO,
            recovery_required: false,
            sample_confidence_ppm: 0,
            enqueue_accepted: 0,
            enqueue_rejected: 0,
            too_large: 0,
            pressure: 0,
            outcome_successes: 0,
            outcome_failures: 0,
            ingress_validated: 0,
            ingress_rejected: 0,
            ingress_read_failures: 0,
        });
        let last_generation = current.last_evidence_generation.unwrap_or(0);
        for evidence in fresh
            .into_iter()
            .filter(|evidence| evidence.generation() > last_generation)
        {
            let completed_at = evidence.completed_at().unwrap_or(now);
            let samples = evidence.samples();
            current.last_evidence_generation = Some(evidence.generation());

            if evidence.has_diagnostics() {
                current.last_diagnostic_generation = Some(evidence.generation());
                current.diagnostic_observed_at = Some(completed_at);
                current.too_large = evidence.too_large();
                current.pressure = evidence.pressure();
                current.ingress_validated = evidence.ingress_validated();
                current.ingress_rejected = evidence.ingress_rejected();
                current.ingress_read_failures = evidence.ingress_read_failures();
            }

            // Diagnostic-only windows update telemetry without changing any
            // pending entry/recovery progress.
            if samples == 0 {
                continue;
            }
            current.observed_at = completed_at;
            current.last_scored_generation = Some(evidence.generation());
            current.enqueue_accepted = evidence.enqueue_accepted();
            current.enqueue_rejected = evidence.enqueue_rejected();
            current.outcome_successes = evidence.outcome_successes();
            current.outcome_failures = evidence.outcome_failures();
            let confidence_ppm = if min_samples == 0 {
                1_000_000
            } else {
                samples
                    .saturating_mul(1_000_000)
                    .saturating_div(min_samples)
                    .min(1_000_000) as u32
            };
            let score_ppm = evidence.health_score_ppm();
            let old_state = current.state;
            current.loss_samples = samples;
            current.sample_confidence_ppm = confidence_ppm;
            current.path_health_score_ppm = Some(score_ppm);

            if samples < min_samples {
                current.reason = DatagramPathHealthReason::InsufficientSamples;
            } else if score_ppm >= suspect_score_ppm {
                current.consecutive_bad_windows = current.consecutive_bad_windows.saturating_add(1);
                current.healthy_since = None;
                current.recovery_healthy_span = Duration::ZERO;
                current.reason = DatagramPathHealthReason::LaneOutcomeFailures;
                if current.consecutive_bad_windows >= suspect_bad_windows {
                    current.state = DatagramPathHealthState::Suspect;
                    current.recovery_required = true;
                }
            } else if score_ppm <= recover_score_ppm {
                current.consecutive_bad_windows = 0;
                if current.recovery_required {
                    let since = current.healthy_since.get_or_insert(completed_at);
                    current.recovery_healthy_span = completed_at.saturating_duration_since(*since);
                    if current.recovery_healthy_span >= recover_healthy_for {
                        current.state = DatagramPathHealthState::Healthy;
                        current.reason = DatagramPathHealthReason::Recovered;
                        current.healthy_since = None;
                        current.recovery_required = false;
                    }
                } else {
                    current.state = DatagramPathHealthState::Healthy;
                    current.reason = DatagramPathHealthReason::WithinThreshold;
                    current.healthy_since = None;
                    current.recovery_healthy_span = Duration::ZERO;
                }
            } else {
                current.consecutive_bad_windows = 0;
                current.healthy_since = None;
                current.recovery_healthy_span = Duration::ZERO;
            }
            if current.state != old_state {
                current.transitions = current.transitions.saturating_add(1);
                current.changed_at = completed_at;
            }
        }
        let state = current.state;
        observations.insert(path, current);
        state
    }

    pub(crate) fn datagram_path_health_status(
        &self,
        stale_after: Duration,
    ) -> Vec<DatagramPathHealthSnapshot> {
        let now = Instant::now();
        let observations = self.datagram_path_health.lock();
        let mut snapshots = observations
            .iter()
            .filter(|(_, observation)| {
                now.saturating_duration_since(observation.observed_at) < stale_after
                    || observation
                        .diagnostic_observed_at
                        .is_some_and(|observed_at| {
                            now.saturating_duration_since(observed_at) < stale_after
                        })
            })
            .map(|(path, observation)| {
                DatagramPathHealthSnapshot::new(
                    self.node_id,
                    *path,
                    observation.state,
                    observation.reason,
                    observation.effective_loss_ppm,
                    observation.path_health_score_ppm,
                    observation.loss_samples,
                    observation.transitions,
                    now.saturating_duration_since(observation.changed_at),
                    now.saturating_duration_since(observation.observed_at),
                    observation.last_scored_generation,
                    observation.last_diagnostic_generation,
                    observation
                        .diagnostic_observed_at
                        .map(|observed_at| now.saturating_duration_since(observed_at)),
                    observation.sample_confidence_ppm,
                    observation.enqueue_accepted,
                    observation.enqueue_rejected,
                    observation.too_large,
                    observation.pressure,
                    observation.outcome_successes,
                    observation.outcome_failures,
                    observation.ingress_validated,
                    observation.ingress_rejected,
                    observation.ingress_read_failures,
                    observation.consecutive_bad_windows,
                    observation.recovery_healthy_span,
                    observation.recovery_required,
                )
            })
            .collect::<Vec<_>>();
        snapshots.sort_by_key(|snapshot| snapshot.path());
        snapshots
    }

    pub(crate) fn reset_datagram_path_health(&self, path: DeliveryPath) {
        self.datagram_path_health.lock().remove(&path);
    }

    pub(crate) fn require_kcp_best_effort_recovery(&self) {
        let mut required_after = self.kcp_best_effort_recovery_after_rtt_samples.lock();
        if required_after.is_none() {
            *required_after = Some(self.metrics.rtt_sample_count(TransportKind::Kcp));
        }
    }

    pub(crate) fn record_native_transport_rtt(&self, transport: TransportKind, rtt: Duration) {
        self.metrics.record_native_rtt(transport, rtt);
        if transport != TransportKind::Kcp {
            return;
        }

        let rtt_samples = self.metrics.rtt_sample_count(transport);
        let recovery_completed = {
            let mut required_after = self.kcp_best_effort_recovery_after_rtt_samples.lock();
            if required_after.is_some_and(|baseline| rtt_samples > baseline) {
                *required_after = None;
                true
            } else {
                false
            }
        };
        if recovery_completed {
            self.notify_outbound_dispatch();
        }
    }

    pub(crate) fn kcp_best_effort_recovery_pending(&self) -> bool {
        let rtt_samples = self.metrics.rtt_sample_count(TransportKind::Kcp);
        let mut required_after = self.kcp_best_effort_recovery_after_rtt_samples.lock();
        let Some(baseline) = *required_after else {
            return false;
        };
        if rtt_samples > baseline {
            *required_after = None;
            false
        } else {
            true
        }
    }

    pub(crate) fn transport_health_exclusion_status(
        &self,
    ) -> Vec<TransportHealthExclusionSnapshot> {
        let mut out = self
            .transport_health_exclusions
            .lock()
            .iter()
            .filter_map(|((transport, reason), exclusions)| {
                (*exclusions > 0).then(|| {
                    TransportHealthExclusionSnapshot::new(
                        self.node_id,
                        *transport,
                        *reason,
                        *exclusions,
                    )
                })
            })
            .collect::<Vec<_>>();
        out.sort_by_key(|snapshot| (snapshot.peer(), snapshot.transport(), snapshot.reason()));
        out
    }

    pub(crate) fn choose_voice_transport(
        &self,
        candidates: &[VoiceTransportCandidateScore],
        now: Instant,
        min_hold: Duration,
        challenger_confirm: Duration,
        idle_reset: Duration,
        improvement_pct: u32,
        observe: bool,
    ) -> Option<VoiceTransportDecision> {
        let best = *candidates.first()?;
        let mut binding = self.voice_transport_binding.lock();

        if binding
            .last_success_at
            .is_some_and(|last| now.saturating_duration_since(last) >= idle_reset)
        {
            let previous = binding.selected_transport;
            return Some(VoiceTransportDecision {
                preferred: best.transport,
                incumbent: previous,
                reason: VoiceTransportBindingEventReason::IdleReset,
            });
        }

        let Some(incumbent) = binding.selected_transport else {
            return Some(VoiceTransportDecision {
                preferred: best.transport,
                incumbent: None,
                reason: VoiceTransportBindingEventReason::Initial,
            });
        };
        let Some(incumbent_score) = candidates
            .iter()
            .copied()
            .find(|candidate| candidate.transport == incumbent)
        else {
            return Some(VoiceTransportDecision {
                preferred: best.transport,
                incumbent: Some(incumbent),
                reason: VoiceTransportBindingEventReason::TransportUnavailable,
            });
        };

        if best.transport == incumbent {
            if observe {
                binding.clear_challenger(VoiceTransportChallengerOutcome::Reset);
            }
            return Some(VoiceTransportDecision {
                preferred: incumbent,
                incumbent: Some(incumbent),
                reason: VoiceTransportBindingEventReason::Recovered,
            });
        }

        let held_for = binding
            .selected_at
            .map(|selected_at| now.saturating_duration_since(selected_at))
            .unwrap_or_default();
        if held_for < min_hold
            || !voice_transport_materially_better(best, incumbent_score, improvement_pct)
        {
            if observe {
                binding.clear_challenger(VoiceTransportChallengerOutcome::Reset);
            }
            return Some(VoiceTransportDecision {
                preferred: incumbent,
                incumbent: Some(incumbent),
                reason: VoiceTransportBindingEventReason::Recovered,
            });
        }

        if binding.challenger_transport != Some(best.transport) {
            if observe {
                binding.clear_challenger(VoiceTransportChallengerOutcome::Reset);
                binding.challenger_transport = Some(best.transport);
                binding.challenger_since = Some(now);
                binding.challenger_observations = 1;
                let counter = binding
                    .challenger_events
                    .entry((
                        incumbent,
                        best.transport,
                        VoiceTransportChallengerOutcome::Started,
                    ))
                    .or_default();
                *counter = counter.saturating_add(1);
            }
            return Some(VoiceTransportDecision {
                preferred: incumbent,
                incumbent: Some(incumbent),
                reason: VoiceTransportBindingEventReason::Recovered,
            });
        }

        if observe {
            binding.challenger_observations = binding.challenger_observations.saturating_add(1);
        }
        let confirmed_for = binding
            .challenger_since
            .map(|since| now.saturating_duration_since(since))
            .unwrap_or_default();
        let confirmed = confirmed_for >= challenger_confirm && binding.challenger_observations >= 2;
        Some(VoiceTransportDecision {
            preferred: if confirmed { best.transport } else { incumbent },
            incumbent: Some(incumbent),
            reason: if confirmed {
                VoiceTransportBindingEventReason::ConfirmedChallenger
            } else {
                VoiceTransportBindingEventReason::Recovered
            },
        })
    }

    pub(crate) fn record_voice_transport_success(
        &self,
        transport: TransportKind,
        now: Instant,
        reason: VoiceTransportBindingEventReason,
        incumbent_failure: Option<VoiceTransportBindingEventReason>,
        selected_pressure: Option<u8>,
        incumbent_pressure: Option<u8>,
    ) {
        let mut binding = self.voice_transport_binding.lock();
        let previous = binding.selected_transport;
        if previous != Some(transport) || reason == VoiceTransportBindingEventReason::IdleReset {
            let actual_reason = incumbent_failure.unwrap_or(reason);
            let held_for = binding
                .selected_at
                .map(|selected_at| now.saturating_duration_since(selected_at))
                .unwrap_or_default();
            let confirmed_for = binding
                .challenger_since
                .map(|since| now.saturating_duration_since(since))
                .unwrap_or_default();
            if actual_reason == VoiceTransportBindingEventReason::ConfirmedChallenger {
                binding.clear_challenger(VoiceTransportChallengerOutcome::Confirmed);
            } else {
                binding.clear_challenger(VoiceTransportChallengerOutcome::Reset);
            }
            binding.record_event(previous, Some(transport), actual_reason);
            binding.selected_transport = Some(transport);
            binding.selected_at = Some(now);
            tracing::debug!(
                peer = %self.node_id,
                ?previous,
                selected = ?transport,
                selected_pressure,
                incumbent_pressure,
                reason = actual_reason.name(),
                held_ms = held_for.as_millis(),
                confirmation_ms = confirmed_for.as_millis(),
                "updated voice transport binding"
            );
        } else if reason == VoiceTransportBindingEventReason::ConfirmedChallenger {
            // The confirmed challenger was attempted first but rejected the
            // frame, and the incumbent subsequently admitted it. Require a
            // fresh confirmation window before trying that challenger again.
            binding.clear_challenger(VoiceTransportChallengerOutcome::Reset);
        }
        binding.last_success_at = Some(now);
        binding.no_alternate_reported = false;
    }

    pub(crate) fn record_voice_transport_no_alternate(&self) -> bool {
        let mut binding = self.voice_transport_binding.lock();
        if binding.no_alternate_reported {
            return false;
        }
        let selected = binding.selected_transport;
        binding.record_event(
            selected,
            None,
            VoiceTransportBindingEventReason::NoAlternate,
        );
        binding.no_alternate_reported = true;
        true
    }

    pub(crate) fn voice_transport_binding_status(&self) -> Option<VoiceTransportBindingSnapshot> {
        self.voice_transport_binding
            .lock()
            .selected_transport
            .map(|transport| VoiceTransportBindingSnapshot::new(self.node_id, transport))
    }

    pub(crate) fn voice_transport_binding_ages(&self, now: Instant) -> (Duration, Duration) {
        let binding = self.voice_transport_binding.lock();
        let held = binding
            .selected_at
            .map(|selected_at| now.saturating_duration_since(selected_at))
            .unwrap_or_default();
        let confirmation = binding
            .challenger_since
            .map(|since| now.saturating_duration_since(since))
            .unwrap_or_default();
        (held, confirmation)
    }

    pub(crate) fn voice_transport_binding_event_status(
        &self,
    ) -> Vec<VoiceTransportBindingEventSnapshot> {
        let binding = self.voice_transport_binding.lock();
        let mut out = binding
            .events
            .iter()
            .filter_map(|((from, to, reason), events)| {
                (*events > 0).then(|| {
                    VoiceTransportBindingEventSnapshot::new(
                        self.node_id,
                        *from,
                        *to,
                        *reason,
                        *events,
                    )
                })
            })
            .collect::<Vec<_>>();
        out.sort_by_key(|event| (event.from_transport(), event.to_transport(), event.reason()));
        out
    }

    pub(crate) fn voice_transport_challenger_status(
        &self,
    ) -> Vec<VoiceTransportChallengerSnapshot> {
        let binding = self.voice_transport_binding.lock();
        let mut out = binding
            .challenger_events
            .iter()
            .filter_map(|((incumbent, challenger, outcome), events)| {
                (*events > 0).then(|| {
                    VoiceTransportChallengerSnapshot::new(
                        self.node_id,
                        *incumbent,
                        *challenger,
                        *outcome,
                        *events,
                    )
                })
            })
            .collect::<Vec<_>>();
        out.sort_by_key(|event| (event.incumbent(), event.challenger(), event.outcome()));
        out
    }

    pub fn has_any_live_stream(&self) -> bool {
        let mut g = self.streams.lock();
        prune_dead_streams(&mut g);
        g.values().any(ActiveStream::is_alive)
    }

    pub fn outgoing_live_count(&self) -> usize {
        let mut g = self.streams.lock();
        prune_dead_streams(&mut g);
        g.values().filter(|s| s.is_alive() && s.is_dialer()).count()
    }

    pub fn outgoing_live_keys(&self) -> Vec<StreamKey> {
        let mut g = self.streams.lock();
        prune_dead_streams(&mut g);
        g.iter()
            .filter_map(|(key, stream)| {
                if stream.is_alive() && stream.is_dialer() {
                    Some(*key)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn drop_outgoing_stream(&self, key: StreamKey) -> bool {
        let mut g = self.streams.lock();
        if let Some(prev) = g.remove(&key) {
            prev.closed.cancel();
            self.notify_outbound_dispatch();
            true
        } else {
            false
        }
    }

    pub fn note_udp_seen(&self, addr: std::net::SocketAddr) {
        *self.udp_seen_at.lock() = Some(Instant::now());
        *self.udp_addr.lock() = Some(addr);
        self.note_observed_remote_addr(TransportKind::Udp, addr);
    }
}

fn voice_transport_materially_better(
    challenger: VoiceTransportCandidateScore,
    incumbent: VoiceTransportCandidateScore,
    improvement_pct: u32,
) -> bool {
    if challenger.pressure != incumbent.pressure {
        return challenger.pressure < incumbent.pressure;
    }
    let (Some(challenger_cost), Some(incumbent_cost)) = (challenger.cost, incumbent.cost) else {
        return false;
    };
    if !challenger_cost.is_finite() || !incumbent_cost.is_finite() {
        return false;
    }
    let required = 1.0 - (improvement_pct.min(100) as f64 / 100.0);
    challenger_cost <= incumbent_cost * required
}

fn prune_dead_streams(streams: &mut HashMap<StreamKey, ActiveStream>) {
    streams.retain(|_, stream| {
        if stream.is_alive() {
            true
        } else {
            stream.cancel();
            false
        }
    });
}

fn drop_udp_streams(streams: &mut HashMap<StreamKey, ActiveStream>) {
    streams.retain(|key, stream| {
        if key.transport() == TransportKind::Udp {
            stream.cancel();
            false
        } else {
            true
        }
    });
}

fn push_unique_candidate(candidates: &mut Vec<PeerAddress>, addr: PeerAddress) {
    let canonical = PeerAddress::new(canonical_socket_addr(addr.addr()), addr.transport());
    if canonical.is_dialable() && !candidates.contains(&canonical) {
        candidates.push(canonical);
    }
}

fn published_ip_looks_usable(published: std::net::IpAddr) -> bool {
    !ip_looks_unusable(published)
}

fn should_add_observed_candidate(published: std::net::IpAddr, observed: std::net::IpAddr) -> bool {
    let published = canonical_ip(published);
    let observed = canonical_ip(observed);
    // Never add an observed IP that cannot be dialed.
    if ip_looks_unusable(observed) || observed == published {
        return false;
    }
    true
}

fn ip_looks_unusable(ip: std::net::IpAddr) -> bool {
    ip.is_unspecified() || ip.is_multicast()
}

fn canonical_socket_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(canonical_ip(addr.ip()), addr.port())
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
    }
}

pub(crate) fn retry_cap_for_last_seen_age(
    last_seen_age: Option<Duration>,
    recent_cap: Duration,
    stale_cap: Duration,
    stale_after: Duration,
) -> Duration {
    let Some(age) = last_seen_age else {
        return stale_cap.max(recent_cap);
    };
    if age >= stale_after || stale_after.is_zero() {
        return stale_cap.max(recent_cap);
    }

    let recent_ms = recent_cap.as_millis();
    let stale_ms = stale_cap.max(recent_cap).as_millis();
    let span_ms = stale_after.as_millis().max(1);
    let age_ms = age.as_millis().min(span_ms);
    let interpolated = recent_ms + ((stale_ms - recent_ms) * age_ms / span_ms);
    Duration::from_millis(interpolated.min(u64::MAX as u128) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt as _;

    #[tokio::test]
    async fn quic_v2_sender_routes_best_effort_before_message_class() {
        let (sender, receivers) = QuicV2SessionSender::new(64 * 1024, 64 * 1024, 256 * 1024, 1200);
        let (mut control, mut high, mut regular, mut datagram) = receivers.into_parts();

        for class in [
            MessageClass::Control,
            MessageClass::HighPriority,
            MessageClass::Regular,
        ] {
            sender
                .try_send(OutboundFrame::new(
                    ServiceLevel::BestEffort,
                    class,
                    Bytes::from_static(b"datagram"),
                ))
                .expect("best-effort enqueue");
            assert_eq!(datagram.recv().await.expect("datagram").class(), class);
        }

        for level in [ServiceLevel::Reliable, ServiceLevel::ReliableLowLatency] {
            for (class, expected) in [
                (MessageClass::Control, &mut control),
                (MessageClass::HighPriority, &mut high),
                (MessageClass::Regular, &mut regular),
            ] {
                sender
                    .try_send(OutboundFrame::new(
                        level,
                        class,
                        Bytes::from_static(b"stream"),
                    ))
                    .expect("reliable enqueue");
                let received = expected.recv().await.expect("stream lane");
                assert_eq!(received.level(), level);
                assert_eq!(received.class(), class);
            }
        }
    }

    #[tokio::test]
    async fn quic_v2_sender_can_force_best_effort_onto_a_reliable_stream_path() {
        let (sender, receivers) = QuicV2SessionSender::new(64 * 1024, 64 * 1024, 256 * 1024, 1200);
        let session = SessionSender::QuicV2(sender);
        let (_control, mut high, _regular, datagram) = receivers.into_parts();

        session
            .try_send_for_path(
                DeliveryPath::QuicStream,
                OutboundFrame::new(
                    ServiceLevel::BestEffort,
                    MessageClass::HighPriority,
                    Bytes::from_static(b"stream fallback"),
                ),
            )
            .expect("reliable-stream fallback enqueue");

        let (stream_depth, stream_capacity) = session.depth_capacity_for_path(
            DeliveryPath::QuicStream,
            ServiceLevel::BestEffort,
            MessageClass::HighPriority,
        );
        let (datagram_depth, datagram_capacity) = session.depth_capacity_for_path(
            DeliveryPath::QuicDatagram,
            ServiceLevel::BestEffort,
            MessageClass::HighPriority,
        );
        assert!(stream_depth > 0);
        assert!(stream_capacity > 0);
        assert_eq!(datagram_depth, 0);
        assert!(datagram_capacity > 0);

        let received = high.recv().await.expect("high-priority reliable lane");
        assert_eq!(received.level(), ServiceLevel::BestEffort);
        assert_eq!(received.payload().as_ref(), b"stream fallback");
        assert_eq!(datagram.depth_bytes(), 0);
    }

    #[tokio::test]
    async fn expired_best_effort_does_not_evict_a_live_datagram() {
        let (sender, receivers) = QuicV2SessionSender::new(4096, 1200, 1200, 1200);
        let (_, _, _, mut datagram) = receivers.into_parts();
        sender
            .try_send(OutboundFrame::new(
                ServiceLevel::BestEffort,
                MessageClass::HighPriority,
                Bytes::from_static(b"live"),
            ))
            .expect("live datagram");
        sender
            .try_send(OutboundFrame::with_options(
                ServiceLevel::BestEffort,
                MessageClass::HighPriority,
                Bytes::from(vec![0; 1100]),
                SendOptions::default().expire_after(Duration::ZERO),
            ))
            .expect("expired datagram is consumed as a drop");

        assert_eq!(
            datagram.recv().await.expect("live item").payload().as_ref(),
            b"live"
        );
        assert_eq!(sender.runtime_status().datagrams_dropped, 1);
    }

    #[test]
    fn live_quic_v2_status_is_an_immutable_runtime_snapshot() {
        let peer = peer_for_address_tests();
        let (sender, _receivers) = QuicV2SessionSender::new(4096, 65_536, 262_144, 1200);
        sender.set_max_datagram_size(1376);
        sender.record_datagram_queued();
        sender.record_datagram_received();
        sender.record_datagram_drop();
        let remote_addr = "127.0.0.1:64741".parse().expect("socket address");
        peer.install_stream(ActiveStream::new_quic_v2(
            Some(remote_addr),
            sender.clone(),
            CancellationToken::new(),
            true,
        ));

        let snapshot = peer.quic_session_status(1, 2);
        assert_eq!(snapshot.len(), 1);
        let snapshot = &snapshot[0];
        assert_eq!(snapshot.peer(), 2);
        assert_eq!(snapshot.remote_addr(), Some(remote_addr));
        assert!(snapshot.is_dialer());
        assert_eq!(snapshot.protocol(), QuicSessionProtocol::S2s2);
        assert!(snapshot.three_lane_ready());
        assert_eq!(snapshot.max_datagram_size(), Some(1376));
        assert_eq!(snapshot.datagram_send_buffer_bytes(), 65_536);
        assert_eq!(snapshot.datagram_receive_buffer_bytes(), 262_144);
        assert_eq!(snapshot.datagrams_queued(), 1);
        assert_eq!(snapshot.datagrams_received(), 1);
        assert_eq!(snapshot.datagrams_dropped(), 1);

        sender.record_datagram_queued();
        assert_eq!(snapshot.datagrams_queued(), 1, "snapshot must not be live");
    }

    #[test]
    fn outbound_frame_retains_requested_service_level() {
        let frame = OutboundFrame::with_options(
            ServiceLevel::BestEffort,
            MessageClass::HighPriority,
            Bytes::from_static(b"voice"),
            SendOptions::default(),
        );

        assert_eq!(frame.level(), ServiceLevel::BestEffort);
        assert_eq!(frame.class(), MessageClass::HighPriority);
    }

    #[test]
    fn backoff_doubles_then_caps() {
        let mut b = BackoffState::new(Duration::from_millis(250));
        assert_eq!(b.next_delay, Duration::from_millis(250));
        b.record_failure(Duration::from_secs(2));
        assert_eq!(b.next_delay, Duration::from_millis(500));
        b.record_failure(Duration::from_secs(2));
        assert_eq!(b.next_delay, Duration::from_secs(1));
        b.record_failure(Duration::from_secs(2));
        assert_eq!(b.next_delay, Duration::from_secs(2));
        b.record_failure(Duration::from_secs(2));
        assert_eq!(b.next_delay, Duration::from_secs(2));
        b.record_success();
        assert_eq!(b.next_delay, Duration::from_millis(250));
        assert_eq!(b.consecutive_failures, 0);
    }

    #[test]
    fn outbound_queue_watermark_reports_and_resets_window() {
        let start = Instant::now();
        let mut watermark = QueueWatermark::new(start);

        assert!(
            watermark
                .record(start + Duration::from_secs(30), 2, 8, false)
                .is_none()
        );
        assert!(
            watermark
                .record(start + Duration::from_secs(60), 6, 8, true)
                .is_none()
        );

        let report = watermark
            .record(
                start + crate::metrics::QUEUE_WATERMARK_LOG_INTERVAL,
                4,
                8,
                false,
            )
            .expect("watermark interval elapsed");
        let status = report.status();

        assert_eq!(status.high_depth(), 6);
        assert_eq!(status.depth(), 4);
        assert_eq!(status.capacity(), 8);
        assert_eq!(status.samples(), 3);
        assert_eq!(status.full_samples(), 1);

        assert!(
            watermark
                .record(
                    start + crate::metrics::QUEUE_WATERMARK_LOG_INTERVAL + Duration::from_secs(30),
                    1,
                    8,
                    false,
                )
                .is_none()
        );
        let report = watermark
            .record(
                start + crate::metrics::QUEUE_WATERMARK_LOG_INTERVAL * 2,
                3,
                8,
                false,
            )
            .expect("second watermark interval elapsed");
        let status = report.status();
        assert_eq!(status.high_depth(), 3);
        assert_eq!(status.samples(), 2);
        assert_eq!(status.full_samples(), 0);
    }

    #[test]
    fn backoff_jitters_retry_delay_within_bounds() {
        let mut b = BackoffState::new(Duration::from_millis(250));

        b.record_failure(Duration::from_secs(2));

        assert!(b.retry_delay >= Duration::from_millis(400));
        assert!(b.retry_delay <= Duration::from_millis(600));
    }

    #[test]
    fn backoff_jitters_capped_retry_delay_within_cap() {
        let mut b = BackoffState::new(Duration::from_millis(250));

        b.record_failure(Duration::from_millis(500));

        assert!(b.retry_delay >= Duration::from_millis(400));
        assert!(b.retry_delay <= Duration::from_millis(500));
    }

    #[test]
    fn backoff_failure_with_floor_jumps_to_floor_then_caps() {
        let mut b = BackoffState::new(Duration::from_millis(250));
        let floor = Duration::from_secs(5 * 60);
        let cap = Duration::from_secs(30 * 60);

        b.record_failure_with_floor(floor, cap);
        assert_eq!(b.next_delay, floor);
        b.record_failure_with_floor(floor, cap);
        assert_eq!(b.next_delay, Duration::from_secs(10 * 60));
        b.record_failure_with_floor(floor, cap);
        assert_eq!(b.next_delay, Duration::from_secs(20 * 60));
        b.record_failure_with_floor(floor, cap);
        assert_eq!(b.next_delay, cap);
    }

    #[test]
    fn backoff_waits_from_failure_completion() {
        let mut b = BackoffState::new(Duration::from_millis(250));
        b.record_attempt();
        b.last_attempt = Some(Instant::now() - Duration::from_secs(60));

        b.record_failure(Duration::from_secs(30));
        let last_attempt = b.last_attempt.unwrap();
        let retry_delay = b.retry_delay;

        assert!(!b.ready(
            last_attempt + retry_delay.saturating_sub(Duration::from_nanos(1)),
            Duration::from_secs(30)
        ));
        assert!(b.ready(last_attempt + retry_delay, Duration::from_secs(30)));
    }

    #[test]
    fn restored_backoff_preserves_future_retry_deadline() {
        let now = Instant::now();
        let wall_now = std::time::UNIX_EPOCH + Duration::from_secs(1_000);
        let snapshot = AddressBackoffSnapshot::new(
            Duration::from_secs(10),
            Duration::from_secs(20),
            Some(wall_now + Duration::from_secs(5)),
            2,
        );

        let b = BackoffState::from_snapshot(Duration::from_millis(250), snapshot, now, wall_now);

        assert!(!b.ready(now + Duration::from_secs(4), Duration::from_secs(30)));
        assert!(b.ready(now + Duration::from_secs(5), Duration::from_secs(30)));
        assert_eq!(b.next_delay, Duration::from_secs(20));
        assert_eq!(b.consecutive_failures, 2);
    }

    #[test]
    fn restored_expired_backoff_is_immediately_ready() {
        let now = Instant::now();
        let wall_now = std::time::UNIX_EPOCH + Duration::from_secs(1_000);
        let snapshot = AddressBackoffSnapshot::new(
            Duration::from_secs(10),
            Duration::from_secs(20),
            Some(wall_now - Duration::from_secs(1)),
            2,
        );

        let b = BackoffState::from_snapshot(Duration::from_millis(250), snapshot, now, wall_now);

        assert!(b.ready(now, Duration::from_secs(30)));
        assert_eq!(b.next_delay, Duration::from_secs(20));
        assert_eq!(b.consecutive_failures, 2);
    }

    #[test]
    fn retry_cap_grows_with_last_seen_age() {
        let recent = Duration::from_secs(30);
        let stale = Duration::from_secs(600);
        let stale_after = Duration::from_secs(60);

        assert_eq!(
            retry_cap_for_last_seen_age(Some(Duration::ZERO), recent, stale, stale_after),
            recent
        );
        assert_eq!(
            retry_cap_for_last_seen_age(Some(Duration::from_secs(60)), recent, stale, stale_after),
            stale
        );
        assert_eq!(
            retry_cap_for_last_seen_age(None, recent, stale, stale_after),
            stale
        );
        let mid =
            retry_cap_for_last_seen_age(Some(Duration::from_secs(30)), recent, stale, stale_after);
        assert!(mid > recent);
        assert!(mid < stale);
    }

    fn peer_for_address_tests() -> Arc<PeerState> {
        PeerState::new(
            2,
            Duration::from_millis(250),
            Duration::from_secs(5),
            MetricsTuning::default(),
            1024 * 1024,
        )
    }

    fn observe_quic_test_window(
        peer: &PeerState,
        generation: u64,
        successes: u64,
        failures: u64,
        completed_at: Instant,
        bad_windows: u32,
        now: Instant,
    ) -> DatagramPathHealthState {
        let evidence =
            DatagramPathEvidenceSnapshot::for_test(generation, successes, failures, completed_at);
        peer.observe_quic_datagram_path_health(
            std::slice::from_ref(&evidence),
            1,
            100_000,
            10_000,
            bad_windows,
            Duration::from_secs(10),
            Duration::from_secs(60),
            now,
        )
    }

    #[test]
    fn quic_datagram_suspect_requires_distinct_completed_bad_windows() {
        let peer = peer_for_address_tests();
        let start = Instant::now();
        assert_eq!(
            observe_quic_test_window(&peer, 1, 0, 1, start, 3, start),
            DatagramPathHealthState::Probing
        );
        assert_eq!(
            observe_quic_test_window(&peer, 1, 0, 1, start, 3, start + Duration::from_secs(1),),
            DatagramPathHealthState::Probing
        );
        assert_eq!(
            observe_quic_test_window(
                &peer,
                2,
                0,
                1,
                start + Duration::from_secs(1),
                3,
                start + Duration::from_secs(1),
            ),
            DatagramPathHealthState::Probing
        );
        assert_eq!(
            observe_quic_test_window(
                &peer,
                3,
                0,
                1,
                start + Duration::from_secs(2),
                3,
                start + Duration::from_secs(2),
            ),
            DatagramPathHealthState::Suspect
        );
        let snapshot = peer.datagram_path_health_status(Duration::from_secs(60))[0];
        assert_eq!(snapshot.consecutive_bad_windows(), 3);
    }

    #[test]
    fn quic_datagram_suspect_accepts_two_window_configuration() {
        let peer = peer_for_address_tests();
        let start = Instant::now();
        assert_eq!(
            observe_quic_test_window(&peer, 1, 0, 1, start, 2, start),
            DatagramPathHealthState::Probing
        );
        assert_eq!(
            observe_quic_test_window(
                &peer,
                2,
                0,
                1,
                start + Duration::from_secs(1),
                2,
                start + Duration::from_secs(1),
            ),
            DatagramPathHealthState::Suspect
        );
    }

    #[test]
    fn quic_datagram_recovery_needs_new_healthy_windows_spanning_duration() {
        let peer = peer_for_address_tests();
        let start = Instant::now();
        assert_eq!(
            observe_quic_test_window(&peer, 1, 0, 1, start, 2, start),
            DatagramPathHealthState::Probing
        );
        assert_eq!(
            observe_quic_test_window(
                &peer,
                2,
                0,
                1,
                start + Duration::from_secs(1),
                2,
                start + Duration::from_secs(1),
            ),
            DatagramPathHealthState::Suspect
        );
        let snapshot = peer.datagram_path_health_status(Duration::from_secs(60))[0];
        assert_eq!(snapshot.recovery_healthy_age(), Duration::ZERO);
        assert_eq!(
            observe_quic_test_window(
                &peer,
                3,
                1,
                0,
                start + Duration::from_secs(2),
                2,
                start + Duration::from_secs(2),
            ),
            DatagramPathHealthState::Suspect
        );
        // Re-reading one completed generation cannot satisfy the time gate.
        assert_eq!(
            observe_quic_test_window(
                &peer,
                3,
                1,
                0,
                start + Duration::from_secs(2),
                2,
                start + Duration::from_secs(20),
            ),
            DatagramPathHealthState::Suspect
        );
        let snapshot = peer.datagram_path_health_status(Duration::from_secs(60))[0];
        assert_eq!(snapshot.recovery_healthy_age(), Duration::ZERO);
        assert_eq!(
            observe_quic_test_window(
                &peer,
                4,
                1,
                0,
                start + Duration::from_secs(11),
                2,
                start + Duration::from_secs(11),
            ),
            DatagramPathHealthState::Suspect
        );
        assert_eq!(
            observe_quic_test_window(
                &peer,
                5,
                1,
                0,
                start + Duration::from_secs(12),
                2,
                start + Duration::from_secs(12),
            ),
            DatagramPathHealthState::Healthy
        );
    }

    #[test]
    fn quic_datagram_midband_and_stale_evidence_reset_pending_progress() {
        let peer = peer_for_address_tests();
        let start = Instant::now();
        assert_eq!(
            observe_quic_test_window(&peer, 1, 0, 1, start, 3, start),
            DatagramPathHealthState::Probing
        );
        // Five percent is between the one and ten percent thresholds.
        assert_eq!(
            observe_quic_test_window(
                &peer,
                2,
                95,
                5,
                start + Duration::from_secs(1),
                3,
                start + Duration::from_secs(1),
            ),
            DatagramPathHealthState::Probing
        );
        let snapshot = peer.datagram_path_health_status(Duration::from_secs(60))[0];
        assert_eq!(snapshot.consecutive_bad_windows(), 0);

        assert_eq!(
            peer.observe_quic_datagram_path_health(
                &[],
                1,
                100_000,
                10_000,
                3,
                Duration::from_secs(10),
                Duration::from_secs(60),
                start + Duration::from_secs(2),
            ),
            DatagramPathHealthState::Probing
        );
        let snapshot = peer.datagram_path_health_status(Duration::from_secs(60))[0];
        assert_eq!(snapshot.consecutive_bad_windows(), 0);
        assert_eq!(snapshot.recovery_healthy_age(), Duration::ZERO);
    }

    #[test]
    fn quic_datagram_replays_all_unobserved_windows_in_order() {
        let peer = peer_for_address_tests();
        let start = Instant::now();
        let windows = [
            DatagramPathEvidenceSnapshot::for_test(1, 0, 1, start),
            DatagramPathEvidenceSnapshot::for_test(2, 0, 1, start + Duration::from_secs(1)),
            DatagramPathEvidenceSnapshot::for_test(3, 0, 1, start + Duration::from_secs(2)),
        ];
        assert_eq!(
            peer.observe_quic_datagram_path_health(
                &windows,
                1,
                100_000,
                10_000,
                3,
                Duration::from_secs(10),
                Duration::from_secs(60),
                start + Duration::from_secs(2),
            ),
            DatagramPathHealthState::Suspect
        );
    }

    #[test]
    fn quic_datagram_diagnostic_only_window_preserves_suspect_state() {
        let peer = peer_for_address_tests();
        let start = Instant::now();
        observe_quic_test_window(&peer, 1, 0, 1, start, 2, start);
        observe_quic_test_window(
            &peer,
            2,
            0,
            1,
            start + Duration::from_secs(1),
            2,
            start + Duration::from_secs(1),
        );
        let diagnostic = DatagramPathEvidenceSnapshot::diagnostic_for_test(
            3,
            2,
            4,
            6,
            start + Duration::from_secs(2),
        );
        assert_eq!(
            peer.observe_quic_datagram_path_health(
                std::slice::from_ref(&diagnostic),
                1,
                100_000,
                10_000,
                2,
                Duration::from_secs(10),
                Duration::from_secs(60),
                start + Duration::from_secs(2),
            ),
            DatagramPathHealthState::Suspect
        );
        let snapshot = peer.datagram_path_health_status(Duration::from_secs(60))[0];
        assert!(snapshot.recovery_required());
        assert_eq!(snapshot.consecutive_bad_windows(), 2);
        assert_eq!(snapshot.scored_generation(), Some(2));
        assert_eq!(snapshot.diagnostic_generation(), Some(3));
        assert_eq!(snapshot.loss_samples(), 1);
        assert_eq!(snapshot.outcome_failures(), 1);
        assert_eq!(snapshot.too_large(), 2);
        assert_eq!(snapshot.pressure(), 4);
        assert_eq!(snapshot.ingress_validated(), 6);
    }

    #[test]
    fn stale_status_scrape_cannot_bypass_quic_datagram_recovery() {
        let peer = peer_for_address_tests();
        let start = Instant::now();
        observe_quic_test_window(&peer, 1, 0, 1, start, 2, start);
        assert_eq!(
            observe_quic_test_window(
                &peer,
                2,
                0,
                1,
                start + Duration::from_secs(1),
                2,
                start + Duration::from_secs(1),
            ),
            DatagramPathHealthState::Suspect
        );
        assert_eq!(
            peer.observe_quic_datagram_path_health(
                &[],
                1,
                100_000,
                10_000,
                2,
                Duration::from_secs(10),
                Duration::from_secs(1),
                start + Duration::from_secs(3),
            ),
            DatagramPathHealthState::Probing
        );
        assert!(peer.datagram_path_health_status(Duration::ZERO).is_empty());
        assert_eq!(
            observe_quic_test_window(
                &peer,
                3,
                1,
                0,
                start + Duration::from_secs(4),
                2,
                start + Duration::from_secs(4),
            ),
            DatagramPathHealthState::Probing
        );
        assert_eq!(
            observe_quic_test_window(
                &peer,
                4,
                1,
                0,
                start + Duration::from_secs(14),
                2,
                start + Duration::from_secs(14),
            ),
            DatagramPathHealthState::Healthy
        );
    }

    #[test]
    fn kcp_recovery_arming_does_not_move_an_existing_rtt_baseline() {
        let peer = peer_for_address_tests();
        peer.require_kcp_best_effort_recovery();
        peer.metrics()
            .record_native_rtt(TransportKind::Kcp, Duration::from_millis(40));

        peer.require_kcp_best_effort_recovery();

        assert!(
            !peer.kcp_best_effort_recovery_pending(),
            "re-arming must not replace the original RTT baseline"
        );
    }

    #[test]
    fn kcp_recovery_wakes_dispatch_only_after_ack_progress() {
        let peer = peer_for_address_tests();
        peer.require_kcp_best_effort_recovery();

        assert!(
            peer.wait_for_outbound_dispatch_signal()
                .now_or_never()
                .is_none(),
            "arming recovery must not wake the dispatcher"
        );

        peer.record_native_transport_rtt(TransportKind::Kcp, Duration::from_millis(40));
        assert!(
            peer.wait_for_outbound_dispatch_signal()
                .now_or_never()
                .is_some(),
            "fresh KCP ACK progress should wake the dispatcher"
        );
        assert!(!peer.kcp_best_effort_recovery_pending());

        peer.record_native_transport_rtt(TransportKind::Kcp, Duration::from_millis(35));
        assert!(
            peer.wait_for_outbound_dispatch_signal()
                .now_or_never()
                .is_none(),
            "RTT sampling without a pending recovery must not wake the dispatcher"
        );
    }

    #[test]
    fn udp_mtu_probe_promotes_only_after_confirmation() {
        let peer = peer_for_address_tests();
        peer.set_udp_datagram_mtu_limits(1136, 1436);
        let now = Instant::now();

        assert_eq!(
            peer.claim_udp_datagram_mtu_probe(now, Duration::from_secs(1), 64),
            Some(1200)
        );
        assert_eq!(peer.udp_datagram_mtu(), 1136);
        assert_eq!(peer.confirm_udp_datagram_mtu(1200), 1200);
        assert_eq!(
            peer.claim_udp_datagram_mtu_probe(now, Duration::from_secs(1), 64),
            None
        );
    }

    #[test]
    fn rejected_larger_probe_keeps_the_confirmed_udp_budget() {
        let peer = peer_for_address_tests();
        peer.set_udp_datagram_mtu_limits(1136, 1436);

        assert_eq!(peer.reduce_udp_datagram_mtu(1200), 1136);
        assert_eq!(peer.udp_datagram_mtu(), 1136);
    }

    #[test]
    fn peer_backoff_is_tracked_per_address() {
        let peer = peer_for_address_tests();
        let first = PeerAddress::new("10.1.2.3:64739".parse().unwrap(), TransportKind::Tcp);
        let second = PeerAddress::new("10.1.2.4:64739".parse().unwrap(), TransportKind::Tcp);
        let retry_cap = Duration::from_secs(30);

        peer.add_address(first);
        peer.add_address(second);
        peer.record_address_failure(first, retry_cap);
        let now = Instant::now();

        assert!(!peer.address_retry_ready(first, now, retry_cap));
        assert!(peer.address_retry_ready(second, now, retry_cap));

        peer.record_address_failure(second, retry_cap);
        peer.record_address_success(first);
        let backoffs = peer.address_backoffs.lock();
        assert_eq!(
            backoffs.get(&first).unwrap().next_delay,
            Duration::from_millis(250)
        );
        assert_eq!(
            backoffs.get(&second).unwrap().next_delay,
            Duration::from_millis(500)
        );
    }

    #[test]
    fn removing_address_prunes_address_backoff() {
        let peer = peer_for_address_tests();
        let addr = PeerAddress::new("10.1.2.3:64739".parse().unwrap(), TransportKind::Tcp);

        peer.add_address(addr);
        peer.replace_advertised_addresses(&[addr]);
        peer.record_address_failure(addr, Duration::from_secs(30));
        assert!(peer.address_backoffs.lock().contains_key(&addr));
        assert!(peer.address_is_actively_advertised(addr));

        assert!(peer.remove_address(addr));
        assert!(!peer.address_backoffs.lock().contains_key(&addr));
        assert!(!peer.address_is_actively_advertised(addr));
    }

    fn active_stream_for_test(
        transport: TransportKind,
        remote_addr: SocketAddr,
        is_dialer: bool,
    ) -> (
        ActiveStream,
        crate::adaptive_queue::AdaptiveQueueReceiver<OutboundFrame>,
    ) {
        let budget = crate::adaptive_queue::AdaptiveQueueBudget::new(1024 * 1024);
        let (tx, rx) = crate::adaptive_queue::AdaptiveQueueSender::new(budget.split(1024 * 1024));
        (
            ActiveStream::new(
                transport,
                Some(remote_addr),
                tx,
                CancellationToken::new(),
                is_dialer,
            ),
            rx,
        )
    }

    #[test]
    fn same_transport_streams_with_different_remote_addresses_coexist() {
        let peer = peer_for_address_tests();
        let first_addr = "10.1.2.3:64739".parse().unwrap();
        let second_addr = "10.1.2.4:64739".parse().unwrap();
        let (first, _first_rx) = active_stream_for_test(TransportKind::Tcp, first_addr, true);
        let (second, _second_rx) = active_stream_for_test(TransportKind::Tcp, second_addr, true);

        assert!(peer.try_install_stream(first).is_ok());
        assert!(peer.try_install_stream(second).is_ok());

        assert_eq!(peer.outgoing_live_count(), 2);
        assert!(peer.has_live_outgoing_to(PeerAddress::new(first_addr, TransportKind::Tcp)));
        assert!(peer.has_live_outgoing_to(PeerAddress::new(second_addr, TransportKind::Tcp)));
    }

    #[test]
    fn udp_stream_replaces_existing_udp_path() {
        let peer = peer_for_address_tests();
        let first_addr = "10.1.2.3:64742".parse().unwrap();
        let second_addr = "10.1.2.4:64742".parse().unwrap();
        let (first, _first_rx) = active_stream_for_test(TransportKind::Udp, first_addr, true);
        let (second, _second_rx) = active_stream_for_test(TransportKind::Udp, second_addr, true);

        peer.install_stream(first);
        peer.install_stream(second);

        assert_eq!(peer.outgoing_live_count(), 1);
        assert!(peer.has_live_outgoing_to(PeerAddress::new(first_addr, TransportKind::Udp)));
        assert!(peer.has_live_outgoing_to(PeerAddress::new(second_addr, TransportKind::Udp)));
    }

    #[test]
    fn exact_duplicate_stream_key_is_rejected() {
        let peer = peer_for_address_tests();
        let addr = "10.1.2.3:64739".parse().unwrap();
        let (first, _first_rx) = active_stream_for_test(TransportKind::Tcp, addr, true);
        let (duplicate, _duplicate_rx) = active_stream_for_test(TransportKind::Tcp, addr, true);

        assert!(peer.try_install_stream(first).is_ok());
        assert!(peer.try_install_stream(duplicate).is_err());

        assert_eq!(peer.outgoing_live_count(), 1);
        assert!(peer.has_live_outgoing_to(PeerAddress::new(addr, TransportKind::Tcp)));
    }

    #[test]
    fn stream_lookup_prefers_newest_live_stream_for_transport() {
        let peer = peer_for_address_tests();
        let old_addr = "10.1.2.3:64739".parse().unwrap();
        let new_addr = "10.1.2.4:64739".parse().unwrap();
        let (old_stream, mut old_rx) = active_stream_for_test(TransportKind::Tcp, old_addr, true);
        assert!(peer.try_install_stream(old_stream).is_ok());

        std::thread::sleep(Duration::from_millis(1));

        let (new_stream, mut new_rx) = active_stream_for_test(TransportKind::Tcp, new_addr, false);
        assert!(peer.try_install_stream(new_stream).is_ok());

        let sender = peer.try_get_stream(TransportKind::Tcp).unwrap();
        sender
            .try_send(OutboundFrame::new(
                ServiceLevel::Reliable,
                MessageClass::Regular,
                Bytes::from_static(b"new"),
            ))
            .unwrap();

        assert!(old_rx.try_recv().is_err());
        assert_eq!(
            new_rx.try_recv().unwrap().payload(),
            &Bytes::from_static(b"new")
        );
    }

    #[test]
    fn udp_inbound_session_satisfies_address_dial_check() {
        let peer = peer_for_address_tests();
        let addr = "10.1.2.3:64739".parse().unwrap();
        let (inbound, _rx) = active_stream_for_test(TransportKind::Udp, addr, false);

        assert!(peer.try_install_stream(inbound).is_ok());

        assert_eq!(peer.outgoing_live_count(), 0);
        assert!(peer.has_live_outgoing_to(PeerAddress::new(addr, TransportKind::Udp)));
    }

    #[test]
    fn tcp_inbound_session_does_not_satisfy_outgoing_dial_check() {
        let peer = peer_for_address_tests();
        let addr = "10.1.2.3:64739".parse().unwrap();
        let (inbound, _rx) = active_stream_for_test(TransportKind::Tcp, addr, false);

        assert!(peer.try_install_stream(inbound).is_ok());

        assert!(!peer.has_live_outgoing_to(PeerAddress::new(addr, TransportKind::Tcp)));
    }

    #[test]
    fn address_confirmation_uses_active_advertisement_or_live_remote_ip() {
        let peer = peer_for_address_tests();
        let advertised = PeerAddress::new("10.1.2.3:64739".parse().unwrap(), TransportKind::Tcp);
        let same_ip = PeerAddress::new("10.1.2.4:64740".parse().unwrap(), TransportKind::Quic);
        let other = PeerAddress::new("10.1.2.5:64741".parse().unwrap(), TransportKind::Quic);
        let (stream, _rx) =
            active_stream_for_test(TransportKind::Tcp, "10.1.2.4:51000".parse().unwrap(), false);

        peer.replace_advertised_addresses(&[advertised]);
        assert!(peer.try_install_stream(stream).is_ok());

        assert!(peer.address_is_currently_confirmed(advertised));
        assert!(peer.address_is_currently_confirmed(same_ip));
        assert!(!peer.address_is_currently_confirmed(other));
    }

    #[test]
    fn address_confirmation_canonicalizes_ipv4_mapped_live_remote_ip() {
        let peer = peer_for_address_tests();
        let same_ip = PeerAddress::new("10.1.2.4:64740".parse().unwrap(), TransportKind::Quic);
        let (stream, _rx) = active_stream_for_test(
            TransportKind::Tcp,
            "[::ffff:10.1.2.4]:51000".parse().unwrap(),
            false,
        );

        assert!(peer.try_install_stream(stream).is_ok());

        assert!(peer.address_is_currently_confirmed(same_ip));
    }

    #[test]
    fn observed_remote_ips_create_candidates_for_wildcard_advertised_address() {
        let peer = peer_for_address_tests();
        peer.note_observed_remote_addr(TransportKind::Kcp, "10.1.2.3:51000".parse().unwrap());
        peer.note_observed_remote_addr(TransportKind::Kcp, "10.1.2.4:52000".parse().unwrap());

        let candidates = peer.address_candidates(PeerAddress::new(
            "0.0.0.0:64740".parse().unwrap(),
            TransportKind::Kcp,
        ));

        assert_eq!(
            candidates,
            vec![
                PeerAddress::new("10.1.2.3:64740".parse().unwrap(), TransportKind::Kcp),
                PeerAddress::new("10.1.2.4:64740".parse().unwrap(), TransportKind::Kcp),
            ]
        );
    }

    #[test]
    fn observed_remote_ip_is_appended_to_remote_loopback_advertised_address() {
        let peer = peer_for_address_tests();
        peer.note_observed_remote_addr(TransportKind::Tcp, "10.1.2.3:51000".parse().unwrap());

        let published = PeerAddress::new("127.0.0.1:64739".parse().unwrap(), TransportKind::Tcp);
        let candidates = peer.address_candidates(PeerAddress::new(
            "127.0.0.1:64739".parse().unwrap(),
            TransportKind::Tcp,
        ));

        assert_eq!(
            candidates,
            vec![
                published,
                PeerAddress::new("10.1.2.3:64739".parse().unwrap(), TransportKind::Tcp)
            ]
        );
    }

    #[test]
    fn observed_ipv4_mapped_remote_ip_matches_ipv4_published_address() {
        let peer = peer_for_address_tests();
        peer.note_observed_remote_addr(
            TransportKind::Tcp,
            "[::ffff:10.1.2.3]:51000".parse().unwrap(),
        );

        let published = PeerAddress::new("10.1.2.3:64739".parse().unwrap(), TransportKind::Tcp);

        assert_eq!(peer.address_candidates(published), vec![published]);
    }

    #[test]
    fn mapped_published_address_is_canonicalized_to_ipv4_candidate() {
        let peer = peer_for_address_tests();
        let mapped = PeerAddress::new(
            "[::ffff:10.1.2.3]:64739".parse().unwrap(),
            TransportKind::Tcp,
        );
        let canonical = PeerAddress::new("10.1.2.3:64739".parse().unwrap(), TransportKind::Tcp);

        assert_eq!(peer.address_candidates(mapped), vec![canonical]);
    }

    #[test]
    fn concrete_private_advertised_address_appends_private_observed_candidate() {
        let peer = peer_for_address_tests();
        peer.note_observed_remote_addr(TransportKind::Quic, "10.1.2.3:51000".parse().unwrap());

        let published = PeerAddress::new("10.4.5.6:64741".parse().unwrap(), TransportKind::Quic);
        assert_eq!(
            peer.address_candidates(published),
            vec![
                published,
                PeerAddress::new("10.1.2.3:64741".parse().unwrap(), TransportKind::Quic)
            ]
        );
    }

    #[test]
    fn observed_remote_ips_only_create_candidates_for_same_transport() {
        let peer = peer_for_address_tests();
        peer.note_observed_remote_addr(TransportKind::Tcp, "10.1.2.3:51000".parse().unwrap());

        assert_eq!(
            peer.address_candidates(PeerAddress::new(
                "0.0.0.0:64740".parse().unwrap(),
                TransportKind::Kcp,
            )),
            Vec::<PeerAddress>::new()
        );

        peer.note_observed_remote_addr(TransportKind::Kcp, "10.1.2.4:52000".parse().unwrap());

        assert_eq!(
            peer.address_candidates(PeerAddress::new(
                "0.0.0.0:64740".parse().unwrap(),
                TransportKind::Kcp,
            )),
            vec![PeerAddress::new(
                "10.1.2.4:64740".parse().unwrap(),
                TransportKind::Kcp,
            )]
        );
    }

    #[test]
    fn public_observation_is_appended_to_private_published_address() {
        let peer = peer_for_address_tests();
        peer.note_observed_remote_addr(TransportKind::Quic, "8.8.8.8:51000".parse().unwrap());

        let published = PeerAddress::new("10.4.5.6:64741".parse().unwrap(), TransportKind::Quic);
        let candidates = peer.address_candidates(PeerAddress::new(
            "10.4.5.6:64741".parse().unwrap(),
            TransportKind::Quic,
        ));

        assert_eq!(
            candidates,
            vec![
                published,
                PeerAddress::new("8.8.8.8:64741".parse().unwrap(), TransportKind::Quic)
            ]
        );
    }

    #[test]
    fn confirmed_address_moves_to_front_for_future_dials_and_persistence() {
        let peer = peer_for_address_tests();
        let first = PeerAddress::new("10.1.2.3:64741".parse().unwrap(), TransportKind::Quic);
        let second = PeerAddress::new("10.1.2.4:64741".parse().unwrap(), TransportKind::Quic);

        assert!(peer.add_address(first));
        assert!(peer.add_address(second));
        peer.confirm_address(second);

        assert_eq!(peer.snapshot_addresses(), vec![second, first]);
    }

    fn voice_candidate(
        transport: TransportKind,
        pressure: u8,
        cost: f64,
    ) -> VoiceTransportCandidateScore {
        VoiceTransportCandidateScore::new(transport, pressure, Some(cost))
    }

    #[test]
    fn voice_transport_binding_observes_hold_and_confirmation_boundaries() {
        let peer = peer_for_address_tests();
        let start = Instant::now();
        let initial = [voice_candidate(TransportKind::Tcp, 1, 100.0)];
        let decision = peer
            .choose_voice_transport(
                &initial,
                start,
                Duration::from_millis(750),
                Duration::from_millis(500),
                Duration::from_millis(2_000),
                15,
                true,
            )
            .unwrap();
        peer.record_voice_transport_success(
            decision.preferred(),
            start,
            decision.reason(),
            None,
            None,
            None,
        );

        let challenger = [
            voice_candidate(TransportKind::Kcp, 0, 50.0),
            voice_candidate(TransportKind::Tcp, 1, 100.0),
        ];
        for offset in [749, 750, 1_249] {
            let decision = peer
                .choose_voice_transport(
                    &challenger,
                    start + Duration::from_millis(offset),
                    Duration::from_millis(750),
                    Duration::from_millis(500),
                    Duration::from_millis(2_000),
                    15,
                    true,
                )
                .unwrap();
            assert_eq!(decision.preferred(), TransportKind::Tcp, "offset={offset}");
        }
        let confirmed = peer
            .choose_voice_transport(
                &challenger,
                start + Duration::from_millis(1_250),
                Duration::from_millis(750),
                Duration::from_millis(500),
                Duration::from_millis(2_000),
                15,
                true,
            )
            .unwrap();
        assert_eq!(confirmed.preferred(), TransportKind::Kcp);
        assert_eq!(
            confirmed.reason(),
            VoiceTransportBindingEventReason::ConfirmedChallenger
        );
    }

    #[test]
    fn idle_reset_commits_only_after_success_and_emits_one_transition() {
        let peer = peer_for_address_tests();
        let start = Instant::now();
        peer.record_voice_transport_success(
            TransportKind::Tcp,
            start,
            VoiceTransportBindingEventReason::Initial,
            None,
            None,
            None,
        );
        let candidates = [voice_candidate(TransportKind::Kcp, 0, 50.0)];

        let before = peer
            .choose_voice_transport(
                &candidates,
                start + Duration::from_millis(1_999),
                Duration::from_millis(750),
                Duration::from_millis(500),
                Duration::from_millis(2_000),
                15,
                true,
            )
            .unwrap();
        assert_eq!(
            before.reason(),
            VoiceTransportBindingEventReason::TransportUnavailable
        );
        assert_eq!(
            peer.voice_transport_binding_status().unwrap().transport(),
            TransportKind::Tcp
        );

        let reset = peer
            .choose_voice_transport(
                &candidates,
                start + Duration::from_millis(2_000),
                Duration::from_millis(750),
                Duration::from_millis(500),
                Duration::from_millis(2_000),
                15,
                true,
            )
            .unwrap();
        assert_eq!(reset.reason(), VoiceTransportBindingEventReason::IdleReset);
        assert_eq!(
            peer.voice_transport_binding_status().unwrap().transport(),
            TransportKind::Tcp
        );
        peer.record_voice_transport_success(
            reset.preferred(),
            start + Duration::from_millis(2_000),
            reset.reason(),
            None,
            None,
            None,
        );
        let idle_events = peer
            .voice_transport_binding_event_status()
            .into_iter()
            .filter(|event| event.reason() == VoiceTransportBindingEventReason::IdleReset)
            .collect::<Vec<_>>();
        assert_eq!(idle_events.len(), 1);
        assert_eq!(idle_events[0].from_transport(), Some(TransportKind::Tcp));
        assert_eq!(idle_events[0].to_transport(), Some(TransportKind::Kcp));
        assert_eq!(idle_events[0].events(), 1);
    }

    #[test]
    fn no_alternate_is_latched_per_failed_episode() {
        let peer = peer_for_address_tests();
        peer.record_voice_transport_no_alternate();
        peer.record_voice_transport_no_alternate();
        let count = || {
            peer.voice_transport_binding_event_status()
                .into_iter()
                .filter(|event| event.reason() == VoiceTransportBindingEventReason::NoAlternate)
                .map(|event| event.events())
                .sum::<u64>()
        };
        assert_eq!(count(), 1);
        peer.record_voice_transport_success(
            TransportKind::Tcp,
            Instant::now(),
            VoiceTransportBindingEventReason::Initial,
            None,
            None,
            None,
        );
        peer.record_voice_transport_no_alternate();
        assert_eq!(count(), 2);
    }

    #[test]
    fn challenger_identity_reset_and_read_only_queries_do_not_advance_state() {
        let peer = peer_for_address_tests();
        let start = Instant::now();
        let uncommitted = peer
            .choose_voice_transport(
                &[voice_candidate(TransportKind::Tcp, 1, 100.0)],
                start,
                Duration::from_millis(750),
                Duration::from_millis(500),
                Duration::from_millis(2_000),
                15,
                true,
            )
            .unwrap();
        assert!(peer.voice_transport_binding_status().is_none());
        peer.record_voice_transport_success(
            uncommitted.preferred(),
            start,
            uncommitted.reason(),
            None,
            None,
            None,
        );

        let kcp = [
            voice_candidate(TransportKind::Kcp, 0, 50.0),
            voice_candidate(TransportKind::Tcp, 1, 100.0),
        ];
        let quic = [
            voice_candidate(TransportKind::Quic, 0, 40.0),
            voice_candidate(TransportKind::Tcp, 1, 100.0),
        ];
        let choose = |candidates: &[VoiceTransportCandidateScore], offset, observe| {
            peer.choose_voice_transport(
                candidates,
                start + Duration::from_millis(offset),
                Duration::from_millis(750),
                Duration::from_millis(500),
                Duration::from_millis(2_000),
                15,
                observe,
            )
            .unwrap()
            .preferred()
        };
        assert_eq!(choose(&kcp, 750, true), TransportKind::Tcp);
        assert_eq!(choose(&quic, 1_000, true), TransportKind::Tcp);
        assert_eq!(choose(&quic, 1_500, false), TransportKind::Tcp);
        assert_eq!(choose(&quic, 1_500, true), TransportKind::Quic);
    }
}
