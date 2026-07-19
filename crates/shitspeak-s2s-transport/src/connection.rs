//! Per-peer state held by the supervisor.
//!
//! The supervisor owns one `PeerState` per known peer; that struct contains
//! the dial address book, the set of currently-active streams, reconnect
//! backoff, and aggregated metrics.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use parking_lot::Mutex;
use rand::RngExt;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::types::NodeIdentifier;

use super::SendOptions;
use super::adaptive_queue::{
    AdaptiveQueueBudget, AdaptiveQueueReceiver, AdaptiveQueueSender, Queued, SendAdaptiveError,
    TryAdaptiveSendError,
};
use super::metrics::{
    ExpiredOutboundDropCounters, ExpiredOutboundDropSnapshot, ExpiredOutboundDropStage,
    MetricsTuning, OutboundQueueStatusSnapshot, PeerMetrics, QueueStatusSnapshot, QueueWatermark,
    TransportHealthExclusionReason, TransportHealthExclusionSnapshot,
};
use super::service_level::{MessageClass, PeerAddress, RoutingMetric, ServiceLevel, TransportKind};

const MAX_OBSERVED_REMOTE_IPS: usize = 8;
const BACKOFF_JITTER_DIVISOR: u64 = 5;

/// One outbound frame, addressed to a specific stream.
#[derive(Debug, Clone)]
pub struct OutboundFrame {
    class: MessageClass,
    payload: Bytes,
    options: SendOptions,
}

impl OutboundFrame {
    pub fn new(class: MessageClass, payload: Bytes) -> Self {
        Self::with_options(class, payload, SendOptions::default())
    }

    pub fn with_options(class: MessageClass, payload: Bytes, options: SendOptions) -> Self {
        Self {
            class,
            payload,
            options,
        }
    }

    pub(crate) fn from_variant(
        class: MessageClass,
        variant: &TransportPayloadVariant,
        options: SendOptions,
    ) -> Self {
        Self::with_options(class, variant.primary.clone(), options)
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
}

impl TransportPayloadPlan {
    pub fn new(primary: Bytes) -> Self {
        Self {
            default: TransportPayloadVariant::new(primary),
            variants: Vec::new(),
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

    pub fn variant(&self, transport: TransportKind) -> &TransportPayloadVariant {
        self.variants
            .iter()
            .find(|(kind, _)| *kind == transport)
            .map(|(_, variant)| variant)
            .unwrap_or(&self.default)
    }

    pub(crate) fn estimated_bytes(&self) -> usize {
        self.default.estimated_bytes().saturating_add(
            self.variants
                .iter()
                .map(|(_, variant)| variant.estimated_bytes())
                .sum::<usize>(),
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
    sender: AdaptiveQueueSender<OutboundFrame>,
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
            sender,
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

    /// Attempt to obtain a sender for any stream of the requested transport.
    /// Drops the stream if it has died.
    pub fn try_get_stream(
        &self,
        kind: TransportKind,
    ) -> Option<AdaptiveQueueSender<OutboundFrame>> {
        let mut g = self.streams.lock();
        prune_dead_streams(&mut g);
        g.values()
            .filter(|s| s.transport() == kind && s.is_alive())
            .max_by_key(|s| s.installed_at())
            .map(|s| s.sender.clone())
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
}
