//! Inbound `VoiceFrame` decode + central dispatch task, and the
//! speaker-side public API (`VoiceService`).
//!
//! The dispatch task decodes `VoiceFrame`s, applies the reorder gate, and
//! hands emitted frames to the installed audio sink. The speaker-side API
//! wraps already-encoded audio payloads with unresolved routing intent.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::stream::{self, StreamExt};
use parking_lot::RwLock;
use scc::HashMap as SccMap;
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::trace;

use crate::application::config::{DeliveryStrategy, VoiceConfig};
use crate::application::error::ApplicationError;
use crate::application::proto::{
    self, VoiceFrame, VoiceIntent, VoiceIntentKind, VoiceIntentNormal, VoicePathFeedback,
    VoiceRepairRequest,
};
use crate::application::voice::budget::{ProactiveCreditPermit, ProactiveCreditRequest};
use crate::application::voice::fec;
use crate::application::voice::metrics;
use crate::application::voice::metrics::{
    RepairDestinationStage, VoiceIngressClass, VoiceProactiveKind, VoiceProactiveResult,
    VoiceReceiveResult, VoiceRepairResult, VoiceSendMode, VoiceSendResult,
};
use crate::application::voice::proactive_utility::proactive_marginal_utility_micros;
use crate::application::voice::reorder::{
    self, FlushByPeer, GapReport, Reorderer, VoiceCopyKind, VoiceRouteHint,
};
use crate::application::voice::repair::{REPAIR_RESPONSE_PAGE_SEQUENCES, RepairCache, RepairFrame};
use crate::application::voice::send::{
    self, DistributionGroup, OverlayVoiceTransport, VoiceTransport,
};
use crate::application::voice::sink::AudioSink;
use crate::application::voice::targeted::{RecipientIndex, RemoteNodeLookup};
use crate::application::voice::{AdaptiveVoiceBudget, VoiceBytePermit};
use crate::overlay::{OverlayInboundMessage, OverlayNetwork, ServiceInbound, VoiceRouteQuality};
use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::TransportKind;

type AudioSinkSlot = Arc<RwLock<Option<Arc<dyn AudioSink>>>>;
type RecipientIndexSlot = Arc<RwLock<Option<Arc<RecipientIndex>>>>;

const REPAIR_REQUEST_QUEUE_CAPACITY: usize = 256;
const REPAIR_REQUEST_MAX_STREAMS: usize = 256;
const REPAIR_REQUEST_MAX_CONCURRENCY: usize = 16;
const REPAIR_REQUEST_MAX_ATTEMPTS_PER_PAGE: u8 = 3;
const REPAIR_REQUEST_POLL_INTERVAL: Duration = Duration::from_millis(5);
const REPAIR_REQUEST_MAX_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const REPAIR_RESPONSE_QUEUE_CAPACITY: usize = 256;
const REPAIR_RESPONSE_MAX_STREAMS: usize = 256;
const REPAIR_RESPONSE_MIN_CONCURRENCY: usize = 2;
const REPAIR_RESPONSE_MAX_CONCURRENCY: usize = 16;
const DISTANT_REPAIR_PATH_LATENCY_US: u64 = 150_000;
const PROACTIVE_WORKER_CONCURRENCY: usize = 4;
const TAIL_REPAIR_CONCURRENCY: usize = 4;
const PROACTIVE_FAILURE_BACKOFF_INITIAL: Duration = Duration::from_millis(50);
const PROACTIVE_FAILURE_BACKOFF_MAX: Duration = Duration::from_millis(800);
const TAIL_REPAIR_SUFFIX_FRAMES: u64 = 8;
const TAIL_REPAIR_MAX_ATTEMPTS: u8 = 12;
const TAIL_REPAIR_INITIAL_DELAY: Duration = Duration::from_millis(50);
const TAIL_REPAIR_INTERVAL: Duration = Duration::from_millis(100);
const TAIL_REPAIR_FAILURE_BACKOFF_MAX: Duration = Duration::from_millis(800);
const TAIL_REPAIR_SEND_TIMEOUT_MAX: Duration = Duration::from_millis(100);
// 250 ms so the sender reacts to a bad route within ~a quarter second rather
// than a second: a held chunk is a UX symptom (delayed playout) the router
// should fold in before it becomes a clip.
const PATH_FEEDBACK_INTERVAL: Duration = Duration::from_millis(250);

/// Decoded inbound voice frame along with the immediate sender (next-hop
/// peer that delivered the overlay frame, not necessarily the originator).
#[derive(Debug, Clone)]
pub struct VoiceDelivery {
    pub from: NodeIdentifier,
    pub frame: VoiceFrame,
    copy_kind: VoiceCopyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RepairRequestKey {
    destination: NodeIdentifier,
    sender_session: u32,
    sender_epoch: u64,
}

#[derive(Debug)]
struct RepairRequestState {
    from: NodeIdentifier,
    tracked_first_seq: u64,
    attempts: u8,
    requested_page_last: Option<u64>,
    retry_interval: Duration,
    next_attempt: Instant,
    send_cancel: CancellationToken,
    in_flight_generation: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TailRepairKey {
    destination: NodeIdentifier,
    sender_session: u32,
    sender_epoch: u64,
    terminal_seq: u64,
}

#[derive(Debug, Clone)]
struct TailRepairEntry {
    attempts: u8,
    next_retry: Instant,
    expires_at: Instant,
    cancel: CancellationToken,
}

type TailRepairState = Arc<parking_lot::Mutex<HashMap<TailRepairKey, TailRepairEntry>>>;

#[derive(Debug, Clone, Copy)]
struct ProactivePressureEntry {
    consecutive_failures: u8,
    blocked_until: Instant,
    generation: u64,
}

#[derive(Debug, Clone, Copy)]
struct ProactiveSendToken {
    recovery_reservation: Option<u64>,
    observed_failure_generation: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProactiveSendRejection {
    Cooldown(Instant),
    InFlight,
}

/// Per-destination cooldown for low-priority proactive copies. Transport
/// backpressure normally returns immediately, so without this gate every
/// already-queued copy would hammer the same full outbound queue in turn.
#[derive(Default)]
struct ProactivePressureState {
    destinations: parking_lot::Mutex<HashMap<NodeIdentifier, ProactivePressureEntry>>,
    in_flight: parking_lot::Mutex<HashMap<NodeIdentifier, u64>>,
    next_generation: AtomicU64,
    next_send_token: AtomicU64,
}

impl ProactivePressureState {
    fn is_blocked(&self, destination: NodeIdentifier, now: Instant) -> bool {
        self.blocked_until(destination, now).is_some()
            || self.in_flight.lock().contains_key(&destination)
    }

    fn blocked_until(&self, destination: NodeIdentifier, now: Instant) -> Option<Instant> {
        let destinations = self.destinations.lock();
        let blocked_until = destinations
            .get(&destination)
            .map(|entry| entry.blocked_until)?;
        (blocked_until > now).then_some(blocked_until)
    }

    /// Healthy destinations retain cross-speaker concurrency. Once a failure
    /// exists, admit only one recovery probe for the destination at a time.
    fn try_start_send(
        &self,
        destination: NodeIdentifier,
        now: Instant,
    ) -> Result<ProactiveSendToken, ProactiveSendRejection> {
        let destinations = self.destinations.lock();
        if let Some(entry) = destinations
            .get(&destination)
            .filter(|entry| entry.blocked_until > now)
        {
            return Err(ProactiveSendRejection::Cooldown(entry.blocked_until));
        }
        let Some(failure) = destinations.get(&destination) else {
            return Ok(ProactiveSendToken {
                recovery_reservation: None,
                observed_failure_generation: None,
            });
        };
        let observed_failure_generation = Some(failure.generation);
        let mut in_flight = self.in_flight.lock();
        if in_flight.contains_key(&destination) {
            return Err(ProactiveSendRejection::InFlight);
        }
        let id = self
            .next_send_token
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        in_flight.insert(destination, id);
        Ok(ProactiveSendToken {
            recovery_reservation: Some(id),
            observed_failure_generation,
        })
    }

    fn complete_success(&self, destination: NodeIdentifier, token: ProactiveSendToken) {
        let mut destinations = self.destinations.lock();
        if let Some(reservation) = token.recovery_reservation {
            let mut in_flight = self.in_flight.lock();
            if in_flight.get(&destination).copied() != Some(reservation) {
                return;
            }
            in_flight.remove(&destination);
        }
        let unchanged = destinations
            .get(&destination)
            .is_some_and(|entry| Some(entry.generation) == token.observed_failure_generation);
        if unchanged {
            destinations.remove(&destination);
        }
    }

    fn cancel_send(&self, destination: NodeIdentifier, token: ProactiveSendToken) {
        let Some(reservation) = token.recovery_reservation else {
            return;
        };
        let mut in_flight = self.in_flight.lock();
        if in_flight.get(&destination).copied() == Some(reservation) {
            in_flight.remove(&destination);
        }
    }

    fn complete_failure(
        &self,
        destination: NodeIdentifier,
        token: ProactiveSendToken,
        now: Instant,
        initial: Duration,
        maximum: Duration,
    ) -> Instant {
        let mut destinations = self.destinations.lock();
        if let Some(reservation) = token.recovery_reservation {
            let mut in_flight = self.in_flight.lock();
            if in_flight.get(&destination).copied() != Some(reservation) {
                return destinations
                    .get(&destination)
                    .map_or(now + initial, |entry| entry.blocked_until);
            }
            in_flight.remove(&destination);
        }
        if let Some(newer_failure) = destinations
            .get(&destination)
            .filter(|entry| Some(entry.generation) != token.observed_failure_generation)
        {
            // Concurrent healthy sends can discover the same outage. Treat
            // them as one failure wave instead of multiplying the backoff.
            return newer_failure.blocked_until;
        }
        self.record_failure_locked(&mut destinations, destination, now, initial, maximum)
    }

    #[cfg(test)]
    fn record_failure(&self, destination: NodeIdentifier, now: Instant) -> Instant {
        self.record_failure_with_backoff(
            destination,
            now,
            PROACTIVE_FAILURE_BACKOFF_INITIAL,
            PROACTIVE_FAILURE_BACKOFF_MAX,
        )
    }

    #[cfg(test)]
    fn record_failure_with_backoff(
        &self,
        destination: NodeIdentifier,
        now: Instant,
        initial: Duration,
        maximum: Duration,
    ) -> Instant {
        let mut destinations = self.destinations.lock();
        self.record_failure_locked(&mut destinations, destination, now, initial, maximum)
    }

    fn record_failure_locked(
        &self,
        destinations: &mut HashMap<NodeIdentifier, ProactivePressureEntry>,
        destination: NodeIdentifier,
        now: Instant,
        initial: Duration,
        maximum: Duration,
    ) -> Instant {
        let consecutive_failures = destinations
            .get(&destination)
            .map_or(1, |entry| entry.consecutive_failures.saturating_add(1));
        let blocked_until = now + exponential_backoff(initial, maximum, consecutive_failures);
        let generation = self
            .next_generation
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        destinations.insert(
            destination,
            ProactivePressureEntry {
                consecutive_failures,
                blocked_until,
                generation,
            },
        );
        blocked_until
    }
}

impl RepairRequestKey {
    fn new(gap: GapReport) -> Self {
        Self {
            destination: repair_destination(gap.sender_session),
            sender_session: gap.sender_session,
            sender_epoch: gap.sender_epoch,
        }
    }
}

#[derive(Clone)]
struct RepairRequestScheduler {
    tx: mpsc::Sender<GapReport>,
}

impl RepairRequestScheduler {
    fn schedule(&self, source: NodeIdentifier, gap: GapReport) {
        let destination = repair_destination(gap.sender_session);
        if destination == source {
            metrics::record_repair(source, destination, VoiceRepairResult::RequestSuppressed, 1);
            return;
        }
        match self.tx.try_send(gap) {
            Ok(()) => {
                metrics::record_repair(source, destination, VoiceRepairResult::RequestScheduled, 1)
            }
            Err(_) => {
                metrics::record_repair(
                    source,
                    destination,
                    VoiceRepairResult::RequestSuppressed,
                    1,
                );
            }
        }
    }
}

fn repair_destination(sender_session: u32) -> NodeIdentifier {
    shitspeak_core::ClientSessionIdentifier::from(sender_session).get_node_id()
}

#[derive(Debug, Clone)]
struct RepairResponseRequest {
    from: NodeIdentifier,
    request: VoiceRepairRequest,
    deadline: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RepairResponseKey {
    destination: NodeIdentifier,
    sender_session: u32,
    sender_epoch: u64,
}

#[derive(Debug)]
struct RepairResponseState {
    cursor_floor: u64,
    pending: Option<RepairResponseRequest>,
    queued: bool,
    in_flight: bool,
    in_flight_last_seq: Option<u64>,
}

struct RepairResponseFrameResult {
    completed_seq: u64,
    continuation: Option<RepairResponseRequest>,
}

impl RepairResponseKey {
    fn new(work: &RepairResponseRequest) -> Self {
        Self {
            destination: work.from,
            sender_session: work.request.sender_session,
            sender_epoch: work.request.sender_epoch,
        }
    }
}

/// Work whose byte reservation remains live until serialized dispatch has
/// processed the frame. The unbounded lane is therefore still byte bounded.
struct InboundVoiceWork {
    delivery: VoiceDelivery,
    _permit: VoiceBytePermit,
}

/// The dispatch task drains primary work before proactive copies. Deadline
/// fires share the same serialized fan-out but use a capacity-one channel.
enum DispatchEvent {
    Inbound(InboundVoiceWork),
    DeadlineFired,
}

/// A low-priority proactive alternate held behind a byte permit until its
/// dedicated worker submits it to the transport.
struct ProactiveSendWork {
    sender_session: u32,
    dst: NodeIdentifier,
    body: Bytes,
    avoid_first_hop: Option<NodeIdentifier>,
    expires_at: Instant,
    _permit: VoiceBytePermit,
    credit_permit: ProactiveCreditPermit,
}

struct ProactiveRepairCandidate {
    dst: NodeIdentifier,
    repair_first_hop: NodeIdentifier,
    avoid_first_hop: Option<NodeIdentifier>,
    expires_at: Instant,
    marginal_utility_micros: u64,
    copy_index: usize,
}

#[derive(Default)]
struct PathFeedbackAccumulator {
    windows: parking_lot::Mutex<HashMap<NodeIdentifier, PathFeedbackWindow>>,
}

#[derive(Clone, Copy)]
struct PathFeedbackWindow {
    started_at: Instant,
    received_frames: u32,
    gap_buffered: u32,
    deadline_flush: u32,
    /// Longest chunk-hold delay (beyond the in-order skew tolerance) imposed
    /// on this peer's frames within the window, in microseconds.
    max_held_delay_us: u64,
}

impl PathFeedbackWindow {
    fn new(started_at: Instant) -> Self {
        Self {
            started_at,
            received_frames: 0,
            gap_buffered: 0,
            deadline_flush: 0,
            max_held_delay_us: 0,
        }
    }
}

impl PathFeedbackAccumulator {
    fn record(
        &self,
        from: NodeIdentifier,
        result: VoiceReceiveResult,
        count: usize,
    ) -> Option<VoicePathFeedback> {
        let now = Instant::now();
        let mut windows = self.windows.lock();
        let window = windows.entry(from).or_insert_with(|| PathFeedbackWindow::new(now));
        window.received_frames = window.received_frames.saturating_add(count as u32);
        if result == VoiceReceiveResult::GapBuffered {
            window.gap_buffered = window.gap_buffered.saturating_add(count as u32);
        }
        if result == VoiceReceiveResult::DeadlineFlush {
            window.deadline_flush = window.deadline_flush.saturating_add(count as u32);
        }
        Self::flush_if_due(&mut windows, from, now)
    }

    /// Record the longest hold a chunk of this peer's frames absorbed before
    /// release. Separate from [`Self::record`] so a deadline flush can report
    /// both its frame count and its held delay without the two racing on the
    /// window boundary.
    fn record_held_delay(
        &self,
        from: NodeIdentifier,
        max_held_delay_us: u64,
    ) -> Option<VoicePathFeedback> {
        let now = Instant::now();
        let mut windows = self.windows.lock();
        let window = windows.entry(from).or_insert_with(|| PathFeedbackWindow::new(now));
        window.max_held_delay_us = window.max_held_delay_us.max(max_held_delay_us);
        Self::flush_if_due(&mut windows, from, now)
    }

    fn flush_if_due(
        windows: &mut HashMap<NodeIdentifier, PathFeedbackWindow>,
        from: NodeIdentifier,
        now: Instant,
    ) -> Option<VoicePathFeedback> {
        let window = windows.get_mut(&from)?;
        if now.saturating_duration_since(window.started_at) < PATH_FEEDBACK_INTERVAL {
            return None;
        }
        let feedback = VoicePathFeedback {
            received_frames: window.received_frames,
            gap_buffered: window.gap_buffered,
            deadline_flush: window.deadline_flush,
            max_held_delay_us: u32::try_from(window.max_held_delay_us).unwrap_or(u32::MAX),
        };
        *window = PathFeedbackWindow::new(now);
        Some(feedback)
    }
}

struct RepairFrameContext {
    deadline_origin: Instant,
    route_qualities: Vec<Option<VoiceRouteQuality>>,
}

/// Central handle for the voice L3 service.
///
/// Owns:
/// * the inbound mpsc + dispatch task (receiver side),
/// * the outbound `VoiceTransport` (sender side),
/// * the per-(sender_session) sequence counter,
/// * the swappable [`AudioSink`] the dispatch task delivers to.
///
/// `sender_epoch` is captured once at construction from the overlay's
/// `local_boot_epoch`, since it's stable for the process lifetime.
pub struct VoiceService {
    transport: Arc<dyn VoiceTransport>,
    cfg: VoiceConfig,
    _shutdown: CancellationToken,
    primary_inbox_tx: mpsc::UnboundedSender<InboundVoiceWork>,
    proactive_inbox_tx: mpsc::UnboundedSender<InboundVoiceWork>,
    proactive_send_tx: mpsc::UnboundedSender<ProactiveSendWork>,
    proactive_pressure: Arc<ProactivePressureState>,
    repair_response_tx: mpsc::Sender<RepairResponseRequest>,
    tail_repairs: TailRepairState,

    /// Live byte and speaker admission limits derived from runtime capacity.
    voice_budget: AdaptiveVoiceBudget,

    /// Set once at construction from the overlay's `local_boot_epoch`.
    sender_epoch: u64,

    /// Per-local-sender-session monotonic counter for `s2s_seq`. Keyed
    /// by composite `ClientSessionIdentifier::to_u32()`.
    seq_counters: Arc<SccMap<u32, AtomicU64>>,

    /// Sender-side FEC block windows per (sender_session, sender_epoch).
    fec_sender: Arc<fec::FecSenderState>,

    /// Receiver-side delivery callback. Hot-swappable so the `Server`
    /// can install its sink after construction. `None` until set —
    /// frames are decoded and dropped (with a trace) until then.
    audio_sink: AudioSinkSlot,

    /// Per-speaker reorder gate.
    _reorderer: Arc<Reorderer>,

    /// Recently-originated voice frames available for best-effort repair.
    repair_cache: Arc<RepairCache>,

    /// Resolved delivery strategy parsed from config (cached).
    delivery_strategy: DeliveryStrategy,

    /// Channel→nodes index used by `send_for_channel` under the
    /// `"targeted"` strategy. `None` until populated; targeted mode
    /// degrades to broadcast when the index is empty.
    recipient_index: RecipientIndexSlot,
}

impl VoiceService {
    pub fn new(
        overlay: OverlayNetwork,
        cfg: VoiceConfig,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        Self::new_with_capacity_source(overlay, cfg, shutdown, Arc::new(AtomicU64::new(5_000)))
    }

    /// Construct the voice service with a shared live user-capacity source.
    /// New work samples this source when reserving admission capacity; queued
    /// work is deliberately never evicted if the limit is lowered.
    pub fn new_with_capacity_source(
        overlay: OverlayNetwork,
        cfg: VoiceConfig,
        shutdown: CancellationToken,
        max_users: Arc<AtomicU64>,
    ) -> Arc<Self> {
        let sender_epoch = overlay.local_boot_epoch();
        let transport: Arc<dyn VoiceTransport> = Arc::new(OverlayVoiceTransport { overlay });
        Self::new_with_transport_and_capacity_source(
            transport,
            cfg,
            shutdown,
            sender_epoch,
            max_users,
        )
    }

    /// Constructor used by unit tests to inject a fake transport.
    pub fn new_with_transport(
        transport: Arc<dyn VoiceTransport>,
        cfg: VoiceConfig,
        shutdown: CancellationToken,
        sender_epoch: u64,
    ) -> Arc<Self> {
        Self::new_with_transport_and_capacity_source(
            transport,
            cfg,
            shutdown,
            sender_epoch,
            Arc::new(AtomicU64::new(5_000)),
        )
    }

    /// Test-oriented transport constructor which still follows a live user
    /// capacity source.
    pub(crate) fn new_with_transport_and_capacity_source(
        transport: Arc<dyn VoiceTransport>,
        cfg: VoiceConfig,
        shutdown: CancellationToken,
        sender_epoch: u64,
        max_users: Arc<AtomicU64>,
    ) -> Arc<Self> {
        let voice_budget = AdaptiveVoiceBudget::with_repair_reservations(
            max_users.clone(),
            cfg.repair_reactive_reserve_pct,
            cfg.repair_reactive_hard_reserve_pct,
        );
        voice_budget.link_reactive_scheduler_shutdown(shutdown.clone());
        publish_proactive_budget(&voice_budget);
        let (primary_inbox_tx, primary_inbox_rx) = mpsc::unbounded_channel::<InboundVoiceWork>();
        let (proactive_inbox_tx, proactive_inbox_rx) =
            mpsc::unbounded_channel::<InboundVoiceWork>();
        let (deadline_tx, deadline_rx) = mpsc::channel::<()>(1);
        let (proactive_send_tx, proactive_send_rx) = mpsc::unbounded_channel::<ProactiveSendWork>();
        let proactive_pressure = Arc::new(ProactivePressureState::default());
        let reactive_pressure = Arc::new(ProactivePressureState::default());
        let (repair_request_tx, repair_request_rx) = mpsc::channel(REPAIR_REQUEST_QUEUE_CAPACITY);
        let repair_request_scheduler = RepairRequestScheduler {
            tx: repair_request_tx,
        };
        let (repair_response_tx, repair_response_rx) =
            mpsc::channel(REPAIR_RESPONSE_QUEUE_CAPACITY);
        let tail_repairs: TailRepairState = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let audio_sink: AudioSinkSlot = Arc::new(RwLock::new(None));
        let reorderer = Reorderer::new_with_capacity_source(cfg.clone(), max_users);
        let repair_cache = Arc::new(RepairCache::new(Duration::from_millis(cfg.repair_cache_ms)));
        let path_feedback = Arc::new(PathFeedbackAccumulator::default());
        let repair_request_ttl_ms =
            repair_deadline_transport_ttl_ms(&cfg, cfg.repair_request_ttl_ms);
        spawn_repair_request_worker(
            repair_request_rx,
            reorderer.clone(),
            transport.clone(),
            repair_request_ttl_ms,
            shutdown.clone(),
        );
        spawn_repair_response_worker(
            repair_response_rx,
            transport.clone(),
            repair_cache.clone(),
            cfg.clone(),
            voice_budget.clone(),
            shutdown.clone(),
        );
        let fec_state = Arc::new(fec::ReceiverFecState::new(cfg.voice_fec_receiver_window));
        spawn_dispatch_task(
            primary_inbox_rx,
            proactive_inbox_rx,
            deadline_rx,
            shutdown.clone(),
            audio_sink.clone(),
            reorderer.clone(),
            transport.clone(),
            cfg.clone(),
            voice_budget.clone(),
            repair_request_scheduler,
            path_feedback.clone(),
            fec_state,
        );
        spawn_proactive_worker(
            proactive_send_rx,
            transport.clone(),
            voice_budget.clone(),
            proactive_pressure.clone(),
            shutdown.clone(),
        );
        spawn_tail_repair_worker(
            tail_repairs.clone(),
            transport.clone(),
            repair_cache.clone(),
            cfg.clone(),
            voice_budget.clone(),
            reactive_pressure,
            shutdown.clone(),
        );
        reorder::spawn_deadline_task(reorderer.clone(), shutdown.clone(), move || {
            let _ = deadline_tx.try_send(());
        });
        let delivery_strategy = DeliveryStrategy::parse(&cfg.delivery_strategy);
        let fec_sender = Arc::new(fec::FecSenderState::new(
            cfg.voice_fec_enabled,
            cfg.voice_fec_block_size,
            cfg.voice_fec_parity_blocks,
        ));
        Arc::new(Self {
            transport,
            cfg,
            _shutdown: shutdown,
            primary_inbox_tx,
            proactive_inbox_tx,
            proactive_send_tx,
            proactive_pressure,
            repair_response_tx,
            tail_repairs,
            voice_budget,
            sender_epoch,
            seq_counters: Arc::new(SccMap::new()),
            fec_sender,
            audio_sink,
            _reorderer: reorderer,
            repair_cache,
            delivery_strategy,
            recipient_index: Arc::new(RwLock::new(None)),
        })
    }

    pub fn delivery_strategy(&self) -> DeliveryStrategy {
        self.delivery_strategy
    }

    /// Install (or replace) the recipient index used by targeted mode.
    /// No-op for broadcast mode (the index is consulted only when
    /// `delivery_strategy == Targeted`).
    pub fn set_recipient_index(&self, index: Arc<RecipientIndex>) {
        *self.recipient_index.write() = Some(index);
    }

    pub fn clear_recipient_index(&self) {
        *self.recipient_index.write() = None;
    }

    /// Install (or replace) the receiver-side delivery sink. The
    /// dispatch task picks up the new sink on its next inbound frame.
    pub fn set_audio_sink(&self, sink: Arc<dyn AudioSink>) {
        *self.audio_sink.write() = Some(sink);
    }

    /// Remove any installed sink. Subsequent frames are decoded and
    /// dropped until a new sink is installed.
    pub fn clear_audio_sink(&self) {
        *self.audio_sink.write() = None;
    }

    /// `ServiceInbound` impl that decodes envelope bytes and pushes onto
    /// the primary or lower-priority proactive dispatch lane.
    pub fn inbound_handler(&self) -> Arc<dyn ServiceInbound> {
        Arc::new(VoiceInbound {
            primary_inbox_tx: self.primary_inbox_tx.clone(),
            proactive_inbox_tx: self.proactive_inbox_tx.clone(),
            voice_budget: self.voice_budget.clone(),
        })
    }

    pub fn repair_inbound_handler(&self) -> Arc<dyn ServiceInbound> {
        Arc::new(VoiceRepairInbound {
            transport: self.transport.clone(),
            repair_enabled: self.cfg.repair_enabled,
            response_tx: self.repair_response_tx.clone(),
            tail_repairs: self.tail_repairs.clone(),
            response_ttl: Duration::from_millis(
                self.cfg
                    .repair_transport_ttl_ms
                    .min(self.cfg.repair_cache_ms)
                    .max(1),
            ),
        })
    }

    pub fn path_feedback_inbound_handler(&self) -> Arc<dyn ServiceInbound> {
        Arc::new(VoicePathFeedbackInbound {
            transport: self.transport.clone(),
        })
    }

    pub fn config(&self) -> &VoiceConfig {
        &self.cfg
    }

    pub fn local_node_id(&self) -> NodeIdentifier {
        self.transport.local_node_id()
    }

    /// Allocate the next monotonic `s2s_seq` for `sender_session`. Per
    /// the wire-envelope contract, this is independent of the in-payload
    /// Mumble `frame_number`.
    pub fn next_seq(&self, sender_session: u32) -> u64 {
        self.seq_counters
            .entry_sync(sender_session)
            .or_insert_with(|| AtomicU64::new(0))
            .get()
            .fetch_add(1, Ordering::Relaxed)
    }

    /// Reset the per-session counter when a local client disconnects.
    /// Optional; harmless to skip — the counter just stays around.
    pub fn drop_session(&self, sender_session: u32) {
        let _ = self.seq_counters.remove_sync(&sender_session);
    }

    /// Broadcast a voice frame to every alive node (other than self).
    /// `payload` is the already-encoded UDP audio body — receivers do
    /// not re-encode, they hand it directly to local fan-out.
    pub async fn send_broadcast(
        &self,
        sender_session: u32,
        server_id: String,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
    ) -> Result<(), ApplicationError> {
        let dsts = self.remote_voice_members();
        if dsts.is_empty() {
            metrics::record_send(
                self.transport.local_node_id(),
                VoiceSendMode::Broadcast,
                0,
                payload.len(),
                VoiceSendResult::Noop,
            );
            return Ok(());
        }
        let (mut envelope, seq) = self.encode(
            sender_session,
            server_id,
            target_kind,
            is_terminator,
            payload,
            intent,
        )?;
        let bytes = envelope.original_body();
        let repair_context = self.capture_repair_frame_context(&dsts);
        self.cache_original(sender_session, seq, bytes.clone());
        let result = if self.cfg.tree_delivery_enabled {
            self.transport
                .send_tree_multicast(
                    &dsts,
                    DistributionGroup::broadcast(),
                    bytes.clone(),
                    self.cfg.transport_ttl(),
                )
                .await
        } else {
            self.transport
                .send_multicast(&dsts, bytes.clone(), self.cfg.transport_ttl())
                .await
        };
        metrics::record_send(
            self.transport.local_node_id(),
            VoiceSendMode::Broadcast,
            dsts.len(),
            bytes.len(),
            if result.is_ok() {
                VoiceSendResult::Sent
            } else {
                VoiceSendResult::Failed
            },
        );
        if result.is_err() {
            self.cancel_terminal_repairs(sender_session, seq, &dsts);
        }
        result?;
        let fec_payload = envelope.payload();
        self.emit_fec_if_due(
            sender_session,
            seq,
            &fec_payload,
            is_terminator,
            &dsts,
            repair_context.as_ref(),
        )
        .await;
        self.admit_original_repair_credit(
            sender_session,
            &dsts,
            repair_context.as_ref(),
            bytes.len(),
        );
        self.register_terminal_repairs(
            sender_session,
            seq,
            bytes.clone(),
            is_terminator,
            &dsts,
            repair_context.as_ref(),
        );
        self.refresh_cache_and_queue_proactive_repairs(
            sender_session,
            seq,
            &mut envelope,
            is_terminator,
            &dsts,
            repair_context.as_ref(),
        );
        if is_terminator {
            self.extend_terminal_cache(sender_session, seq, bytes);
        }
        Ok(())
    }

    /// Multicast to a specific node set (used by whisper-to-direct-session
    /// and by the opt-in `"targeted"` mode).
    pub async fn send_multicast(
        &self,
        sender_session: u32,
        server_id: String,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
        dsts: &[NodeIdentifier],
    ) -> Result<(), ApplicationError> {
        self.send_multicast_for_group(
            sender_session,
            server_id,
            target_kind,
            is_terminator,
            payload,
            intent,
            dsts,
            DistributionGroup::recipient_snapshot(dsts),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_multicast_for_group(
        &self,
        sender_session: u32,
        server_id: String,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
        dsts: &[NodeIdentifier],
        group: DistributionGroup,
    ) -> Result<(), ApplicationError> {
        if dsts.is_empty() {
            metrics::record_send(
                self.transport.local_node_id(),
                VoiceSendMode::Multicast,
                0,
                payload.len(),
                VoiceSendResult::Noop,
            );
            return Ok(());
        }
        let (mut envelope, seq) = self.encode(
            sender_session,
            server_id,
            target_kind,
            is_terminator,
            payload,
            intent,
        )?;
        let bytes = envelope.original_body();
        let repair_context = self.capture_repair_frame_context(dsts);
        self.cache_original(sender_session, seq, bytes.clone());
        let result = if self.cfg.tree_delivery_enabled {
            self.transport
                .send_tree_multicast(dsts, group, bytes.clone(), self.cfg.transport_ttl())
                .await
        } else {
            self.transport
                .send_multicast(dsts, bytes.clone(), self.cfg.transport_ttl())
                .await
        };
        metrics::record_send(
            self.transport.local_node_id(),
            VoiceSendMode::Multicast,
            dsts.len(),
            bytes.len(),
            if result.is_ok() {
                VoiceSendResult::Sent
            } else {
                VoiceSendResult::Failed
            },
        );
        if result.is_err() {
            self.cancel_terminal_repairs(sender_session, seq, dsts);
        }
        result?;
        let fec_payload = envelope.payload();
        self.emit_fec_if_due(
            sender_session,
            seq,
            &fec_payload,
            is_terminator,
            dsts,
            repair_context.as_ref(),
        )
        .await;
        self.admit_original_repair_credit(
            sender_session,
            dsts,
            repair_context.as_ref(),
            bytes.len(),
        );
        self.register_terminal_repairs(
            sender_session,
            seq,
            bytes.clone(),
            is_terminator,
            dsts,
            repair_context.as_ref(),
        );
        self.refresh_cache_and_queue_proactive_repairs(
            sender_session,
            seq,
            &mut envelope,
            is_terminator,
            dsts,
            repair_context.as_ref(),
        );
        if is_terminator {
            self.extend_terminal_cache(sender_session, seq, bytes);
        }
        Ok(())
    }

    /// Channel-aware send: routes the frame according to the
    /// configured `delivery_strategy`.
    ///
    /// * `Broadcast` — calls `send_broadcast` (overlay broadcast to
    ///   every alive peer; receivers filter locally).
    /// * `Targeted` — looks up `channel_id` in the recipient index
    ///   and multicasts to the resulting node set (excluding self).
    ///   Falls back to broadcast when the index has no entry for
    ///   the channel (cold start, sparse population).
    ///
    /// `channel_id` is the speaker's *current* channel id — the same
    /// channel that drives local fan-out's "in same channel?" check.
    pub async fn send_for_channel(
        &self,
        sender_session: u32,
        server_id: String,
        channel_id: u32,
        is_terminator: bool,
        payload: Bytes,
    ) -> Result<(), ApplicationError> {
        let payload_len = payload.len();
        let intent = normal_intent(channel_id);
        match self.delivery_strategy {
            DeliveryStrategy::Broadcast => {
                self.send_broadcast(sender_session, server_id, 0, is_terminator, payload, intent)
                    .await
            }
            DeliveryStrategy::Targeted => {
                let local = self.transport.local_node_id();
                let lookup = self.recipient_index.read().as_ref().map(|idx| {
                    idx.lookup_remote_nodes_for_in_server(&server_id, channel_id, local)
                });
                match lookup {
                    Some(RemoteNodeLookup::Nodes(dsts)) => {
                        if dsts.is_empty() {
                            // Index exists but only the speaker is in the
                            // channel; nothing to do for cross-node delivery.
                            metrics::record_send(
                                self.transport.local_node_id(),
                                VoiceSendMode::TargetedNoop,
                                0,
                                payload_len,
                                VoiceSendResult::Noop,
                            );
                            return Ok(());
                        }
                        let group = DistributionGroup::targeted(&server_id, &[channel_id], &dsts);
                        let result = self
                            .send_multicast_for_group(
                                sender_session,
                                server_id,
                                0,
                                is_terminator,
                                payload,
                                intent,
                                &dsts,
                                group,
                            )
                            .await;
                        metrics::record_send(
                            self.transport.local_node_id(),
                            VoiceSendMode::Targeted,
                            dsts.len(),
                            payload_len,
                            if result.is_ok() {
                                VoiceSendResult::Sent
                            } else {
                                VoiceSendResult::Failed
                            },
                        );
                        result
                    }
                    Some(RemoteNodeLookup::Missing { .. }) | None => {
                        // No index entry yet — degrade safely to broadcast.
                        trace!(
                            server_id = %server_id,
                            channel_id,
                            "voice targeted: no index entry; falling back to broadcast"
                        );
                        let result = self
                            .send_broadcast(
                                sender_session,
                                server_id,
                                0,
                                is_terminator,
                                payload,
                                intent,
                            )
                            .await;
                        metrics::record_send(
                            self.transport.local_node_id(),
                            VoiceSendMode::TargetedFallback,
                            0,
                            payload_len,
                            if result.is_ok() {
                                VoiceSendResult::Sent
                            } else {
                                VoiceSendResult::Failed
                            },
                        );
                        result
                    }
                }
            }
        }
    }

    /// Channel-aware send that preserves the original target kind and intent
    /// while reusing the targeted delivery strategy's recipient-index
    /// multicast path. Normal speech may supply its source channel together
    /// with Speak-authorized linked channels.
    pub async fn send_for_target_channels(
        &self,
        sender_session: u32,
        server_id: String,
        channel_ids: Arc<[u32]>,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
    ) -> Result<(), ApplicationError> {
        let payload_len = payload.len();
        match self.delivery_strategy {
            DeliveryStrategy::Broadcast => {
                self.send_broadcast(
                    sender_session,
                    server_id,
                    target_kind,
                    is_terminator,
                    payload,
                    intent,
                )
                .await
            }
            DeliveryStrategy::Targeted => {
                let local = self.transport.local_node_id();
                let voice_members = self.remote_voice_members();
                let lookup = self.recipient_index.read().as_ref().map(|idx| {
                    if channel_ids.is_empty() {
                        idx.lookup_remote_nodes_for_server_in_server(
                            &server_id,
                            local,
                            &voice_members,
                        )
                    } else {
                        idx.lookup_remote_nodes_for_complete_shared_channels_in_server(
                            &server_id,
                            channel_ids.clone(),
                            local,
                            &voice_members,
                        )
                    }
                });
                let dsts = match lookup {
                    Some(RemoteNodeLookup::Nodes(dsts)) => dsts,
                    Some(RemoteNodeLookup::Missing { channel_id }) => {
                        trace!(
                            server_id = %server_id,
                            channel_id,
                            "voice targeted: incomplete target channel index; falling back to broadcast"
                        );
                        let result = self
                            .send_broadcast(
                                sender_session,
                                server_id,
                                target_kind,
                                is_terminator,
                                payload,
                                intent,
                            )
                            .await;
                        metrics::record_send(
                            self.transport.local_node_id(),
                            VoiceSendMode::TargetedFallback,
                            0,
                            payload_len,
                            if result.is_ok() {
                                VoiceSendResult::Sent
                            } else {
                                VoiceSendResult::Failed
                            },
                        );
                        return result;
                    }
                    None => {
                        let channel_id = channel_ids.first().copied().unwrap_or(0);
                        trace!(
                            server_id = %server_id,
                            channel_id,
                            "voice targeted: incomplete target channel index; falling back to broadcast"
                        );
                        let result = self
                            .send_broadcast(
                                sender_session,
                                server_id,
                                target_kind,
                                is_terminator,
                                payload,
                                intent,
                            )
                            .await;
                        metrics::record_send(
                            self.transport.local_node_id(),
                            VoiceSendMode::TargetedFallback,
                            0,
                            payload_len,
                            if result.is_ok() {
                                VoiceSendResult::Sent
                            } else {
                                VoiceSendResult::Failed
                            },
                        );
                        return result;
                    }
                };
                if dsts.is_empty() {
                    metrics::record_send(
                        self.transport.local_node_id(),
                        VoiceSendMode::TargetedNoop,
                        0,
                        payload_len,
                        VoiceSendResult::Noop,
                    );
                    return Ok(());
                }
                let group = DistributionGroup::targeted(&server_id, &channel_ids, &dsts);
                let result = self
                    .send_multicast_for_group(
                        sender_session,
                        server_id,
                        target_kind,
                        is_terminator,
                        payload,
                        intent,
                        &dsts,
                        group,
                    )
                    .await;
                metrics::record_send(
                    self.transport.local_node_id(),
                    VoiceSendMode::Targeted,
                    dsts.len(),
                    payload_len,
                    if result.is_ok() {
                        VoiceSendResult::Sent
                    } else {
                        VoiceSendResult::Failed
                    },
                );
                result
            }
        }
    }

    pub async fn send_for_server(
        &self,
        sender_session: u32,
        server_id: String,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
    ) -> Result<(), ApplicationError> {
        self.send_for_target_channels(
            sender_session,
            server_id,
            Arc::from([]),
            target_kind,
            is_terminator,
            payload,
            intent,
        )
        .await
    }

    /// Unicast to a single peer.
    pub async fn send_unicast(
        &self,
        sender_session: u32,
        server_id: String,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
        dst: NodeIdentifier,
    ) -> Result<(), ApplicationError> {
        let (mut envelope, seq) = self.encode(
            sender_session,
            server_id,
            target_kind,
            is_terminator,
            payload,
            intent,
        )?;
        let bytes = envelope.original_body();
        let repair_context = self.capture_repair_frame_context(&[dst]);
        self.cache_original(sender_session, seq, bytes.clone());
        let result = self
            .transport
            .send_unicast(dst, bytes.clone(), self.cfg.transport_ttl())
            .await;
        metrics::record_send(
            self.transport.local_node_id(),
            VoiceSendMode::Unicast,
            1,
            bytes.len(),
            if result.is_ok() {
                VoiceSendResult::Sent
            } else {
                VoiceSendResult::Failed
            },
        );
        if result.is_err() {
            self.cancel_terminal_repairs(sender_session, seq, &[dst]);
        }
        result?;
        let fec_payload = envelope.payload();
        self.emit_fec_if_due(
            sender_session,
            seq,
            &fec_payload,
            is_terminator,
            &[dst],
            repair_context.as_ref(),
        )
        .await;
        self.admit_original_repair_credit(
            sender_session,
            &[dst],
            repair_context.as_ref(),
            bytes.len(),
        );
        self.register_terminal_repairs(
            sender_session,
            seq,
            bytes.clone(),
            is_terminator,
            &[dst],
            repair_context.as_ref(),
        );
        self.refresh_cache_and_queue_proactive_repairs(
            sender_session,
            seq,
            &mut envelope,
            is_terminator,
            &[dst],
            repair_context.as_ref(),
        );
        if is_terminator {
            self.extend_terminal_cache(sender_session, seq, bytes);
        }
        Ok(())
    }

    fn encode(
        &self,
        sender_session: u32,
        server_id: String,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
    ) -> Result<(send::PreparedVoiceEnvelope, u64), ApplicationError> {
        let seq = self.next_seq(sender_session);
        let envelope = send::PreparedVoiceEnvelope::new(
            sender_session,
            server_id,
            self.sender_epoch,
            seq,
            target_kind,
            is_terminator,
            payload,
            intent,
        )?;
        Ok((envelope, seq))
    }

    /// Feed the just-sent frame into the sender FEC window and, when a block
    /// completes, emit one parity copy per first hop whose live datagram loss
    /// clears the `voice_fec_loss_gate_ppm` gate. The gate fires on the worse
    /// of the routing-selected transport and the datagram lane (UDP/KCP) —
    /// best-effort voice may ride any live transport, and the send-time
    /// deadline-queue penalty can push it off a low-loss QUIC stream onto the
    /// lossy datagram lane, so the selected transport's loss understates what
    /// the datagram lane actually delivers. Parity copies are bounded by the
    /// per-first-hop `voice_overlap` lane-headroom budget inside the
    /// transport, so a healthy lane pays nothing and a lossy lane gets
    /// bounded redundancy.
    async fn emit_fec_if_due(
        &self,
        sender_session: u32,
        seq: u64,
        payload: &Bytes,
        is_terminator: bool,
        dsts: &[NodeIdentifier],
        repair_context: Option<&RepairFrameContext>,
    ) {
        if !self.cfg.voice_fec_enabled {
            return;
        }
        let Some(block) = self.fec_sender.push(
            sender_session,
            self.sender_epoch,
            seq,
            payload.clone(),
            is_terminator,
        ) else {
            return;
        };
        // Group destinations by first hop. The parity copy uses the same
        // first hop its block's data frames used, so the receiver's FEC
        // mirror keys `(sender_session, sender_epoch, from)` align.
        let mut hops: HashMap<NodeIdentifier, (Vec<NodeIdentifier>, u32)> = HashMap::new();
        let qualities = repair_context
            .map(|context| context.route_qualities.as_slice())
            .unwrap_or(&[]);
        for (index, &dst) in dsts.iter().enumerate() {
            let Some(quality) = qualities.get(index).copied().flatten() else {
                continue;
            };
            let entry = hops.entry(quality.next_hop()).or_default();
            entry.0.push(dst);
            entry.1 = entry.1.max(Self::fec_gate_loss_ppm(quality));
        }
        let ttl = self.cfg.transport_ttl();
        for (&first_hop, (hop_dsts, gate_loss_ppm)) in &hops {
            if u64::from(*gate_loss_ppm) < u64::from(self.cfg.voice_fec_loss_gate_ppm) {
                continue;
            }
            // Emit every configured parity index (0 = XOR sum, and with
            // `voice_fec_parity_blocks = 2`, 1 = GF-weighted sum) to each
            // first hop that cleared the gate. A `None` encode (index not
            // built into this block) skips silently.
            for index in 0..self.cfg.voice_fec_parity_blocks {
                let Some(parity_body) = self.encode_fec_parity(sender_session, index, &block)
                else {
                    continue;
                };
                let parity_len = parity_body.len();
                let outcome = self
                    .transport
                    .send_fec_frame(hop_dsts, Some(first_hop), parity_body, ttl)
                    .await;
                metrics::record_fec_send(
                    self.transport.local_node_id(),
                    first_hop,
                    parity_len,
                    outcome,
                );
            }
        }
    }

    /// Encode a FEC parity frame from a completed block for one parity index.
    /// Index 0 is the plain XOR sum, index 1 the GF(2^8) weighted sum (present
    /// only when the block was built with `voice_fec_parity_blocks = 2`). The
    /// frame carries the block's member seqs and terminator mask; its own
    /// `s2s_seq` is the completing member's seq (debug only, not part of the
    /// data sequence). `None` when the block has no payload for that index or
    /// the frame cannot be encoded.
    fn encode_fec_parity(
        &self,
        sender_session: u32,
        index: usize,
        block: &fec::FecBlockToSend,
    ) -> Option<Bytes> {
        let payload = match index {
            0 => block.parity.clone(),
            1 => block.parity2.clone()?,
            _ => return None,
        };
        let frame = VoiceFrame {
            sender_session,
            server_id: String::new(),
            sender_epoch: self.sender_epoch,
            s2s_seq: block.member_seqs.last().copied().unwrap_or(0),
            target_kind: 0,
            is_terminator: false,
            payload,
            intent: None,
            proactive_copy: false,
            fec_parity: true,
            fec_member_seqs: block.member_seqs.clone(),
            fec_terminator_mask: block.terminator_mask,
            fec_parity_index: index as u32,
        };
        Some(Bytes::from(proto::encode_voice(&frame).ok()?))
    }

    /// Effective loss the FEC gate should fire on for a first hop: the worse
    /// of the routing-selected transport and the datagram lane that actually
    /// carries best-effort voice (UDP/KCP). The selected transport's loss
    /// understates the lane when the send-time deadline-queue penalty pushes
    /// voice off a low-loss stream onto the datagram lane.
    fn fec_gate_loss_ppm(quality: VoiceRouteQuality) -> u32 {
        quality
            .loss_ppm()
            .max(quality.datagram_loss_ppm().unwrap_or(0))
    }

    fn remote_voice_members(&self) -> Vec<NodeIdentifier> {
        let local = self.transport.local_node_id();
        self.transport
            .voice_members()
            .into_iter()
            .filter(|node| *node != local)
            .collect()
    }

    fn cache_original(&self, sender_session: u32, s2s_seq: u64, body: Bytes) {
        if !self.cfg.repair_enabled {
            return;
        }
        self.repair_cache.insert(RepairFrame::new(
            sender_session,
            self.sender_epoch,
            s2s_seq,
            body,
        ));
    }

    fn admit_original_repair_credit(
        &self,
        sender_session: u32,
        dsts: &[NodeIdentifier],
        repair_context: Option<&RepairFrameContext>,
        original_bytes: usize,
    ) {
        if !self.cfg.repair_enabled {
            return;
        }
        let mut accepted_hops = HashSet::new();
        for (index, &dst) in dsts.iter().enumerate() {
            let first_hop = repair_context
                .and_then(|context| context.route_qualities.get(index).copied().flatten())
                .map(|quality| quality.next_hop())
                .unwrap_or(dst);
            accepted_hops.insert(first_hop);
        }
        for first_hop in accepted_hops {
            self.voice_budget.mint_link_credit(
                first_hop,
                sender_session,
                self.sender_epoch,
                original_bytes,
            );
        }
        publish_proactive_budget(&self.voice_budget);
    }

    fn register_terminal_repairs(
        &self,
        sender_session: u32,
        terminal_seq: u64,
        terminal_body: Bytes,
        is_terminator: bool,
        dsts: &[NodeIdentifier],
        repair_context: Option<&RepairFrameContext>,
    ) {
        if !self.cfg.repair_enabled || !is_terminator {
            return;
        }
        let Some(repair_context) = repair_context else {
            return;
        };
        let now = repair_context.deadline_origin;
        let expires_at = now + tail_repair_lifetime(&self.cfg);
        self.extend_terminal_cache(sender_session, terminal_seq, terminal_body);
        debug_assert_eq!(repair_context.route_qualities.len(), dsts.len());
        let local_node = self.transport.local_node_id();
        let destinations = dsts
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, destination)| *destination != local_node)
            .map(|(index, destination)| {
                let delay = tail_repair_initial_delay(
                    &self.cfg,
                    repair_context.route_qualities.get(index).copied().flatten(),
                );
                (destination, delay)
            })
            .collect::<Vec<_>>();
        let mut repairs = self.tail_repairs.lock();
        for (destination, initial_delay) in destinations {
            if let Some(previous) = repairs.insert(
                TailRepairKey {
                    destination,
                    sender_session,
                    sender_epoch: self.sender_epoch,
                    terminal_seq,
                },
                TailRepairEntry {
                    attempts: 0,
                    next_retry: now + initial_delay,
                    expires_at,
                    cancel: CancellationToken::new(),
                },
            ) {
                previous.cancel.cancel();
            }
        }
    }

    fn cancel_terminal_repairs(
        &self,
        sender_session: u32,
        terminal_seq: u64,
        dsts: &[NodeIdentifier],
    ) {
        if !self.cfg.repair_enabled {
            return;
        }
        let mut repairs = self.tail_repairs.lock();
        for &destination in dsts {
            if let Some(entry) = repairs.remove(&TailRepairKey {
                destination,
                sender_session,
                sender_epoch: self.sender_epoch,
                terminal_seq,
            }) {
                entry.cancel.cancel();
            }
        }
    }

    fn extend_terminal_cache(&self, sender_session: u32, terminal_seq: u64, body: Bytes) {
        if !self.cfg.repair_enabled {
            return;
        }
        self.repair_cache.insert_with_cache_ttl(
            RepairFrame::new(sender_session, self.sender_epoch, terminal_seq, body),
            tail_repair_lifetime(&self.cfg),
        );
    }

    fn refresh_cache_and_queue_proactive_repairs(
        &self,
        sender_session: u32,
        s2s_seq: u64,
        envelope: &mut send::PreparedVoiceEnvelope,
        is_terminator: bool,
        dsts: &[NodeIdentifier],
        repair_context: Option<&RepairFrameContext>,
    ) {
        if !self.cfg.repair_enabled {
            return;
        }
        let Some(repair_context) = repair_context else {
            return;
        };
        debug_assert_eq!(repair_context.route_qualities.len(), dsts.len());
        let local_node = self.transport.local_node_id();
        let blocked = dsts
            .iter()
            .map(|&dst| {
                dst != local_node && self.proactive_pressure.is_blocked(dst, Instant::now())
            })
            .collect::<Vec<_>>();
        let allocation_now = Instant::now();
        let mut candidates = Vec::new();
        for (index, &dst) in dsts.iter().enumerate() {
            if dst == local_node {
                continue;
            }
            if blocked[index] {
                metrics::record_proactive_outcome(
                    VoiceProactiveKind::Ordinary,
                    VoiceProactiveResult::QueueShed,
                );
                continue;
            }
            let quality = repair_context.route_qualities.get(index).copied().flatten();
            let avoid_first_hop = quality.map(|q| q.next_hop());
            let transport_ttl = adaptive_repair_transport_ttl(&self.cfg, quality);
            let Some(original_need_micros) = proactive_repair_score_micros(&self.cfg, quality)
            else {
                continue;
            };
            let extra_copies = proactive_repair_extra_copy_count(
                self.cfg.repair_max_extra_copies_per_frame.min(2),
                original_need_micros,
                proactive_repair_sample(dst, s2s_seq),
            );
            let expires_at = repair_context
                .deadline_origin
                .checked_add(transport_ttl)
                .unwrap_or(repair_context.deadline_origin);
            let remaining = expires_at.saturating_duration_since(allocation_now);
            let Some(quality) = quality else {
                continue;
            };
            for copy_index in 0..extra_copies {
                let marginal_utility_micros = proactive_marginal_utility_micros(
                    original_need_micros,
                    remaining,
                    is_terminator,
                    copy_index,
                    quality,
                );
                if marginal_utility_micros == 0 {
                    continue;
                }
                candidates.push(ProactiveRepairCandidate {
                    dst,
                    repair_first_hop: quality.alternate_next_hop().unwrap_or(dst),
                    avoid_first_hop,
                    expires_at,
                    marginal_utility_micros,
                    copy_index,
                });
            }
        }

        if candidates.is_empty() {
            self.voice_budget
                .reserve_proactive_credit_batch(s2s_seq, &[]);
            publish_proactive_budget(&self.voice_budget);
            return;
        }
        let proactive_body = match envelope.proactive_body() {
            Ok(marked) => marked,
            Err(error) => {
                trace!(%error, "voice proactive repair: mark envelope failed");
                return;
            }
        };
        let reserve_bytes = proactive_body.len();
        let mut credit_grants = (0..candidates.len()).map(|_| None).collect::<Vec<_>>();
        let mut by_first_hop = HashMap::<NodeIdentifier, Vec<usize>>::new();
        for (index, candidate) in candidates.iter().enumerate() {
            by_first_hop
                .entry(candidate.repair_first_hop)
                .or_default()
                .push(index);
        }
        for (first_hop, indexes) in by_first_hop {
            let requests = indexes
                .iter()
                .map(|&index| {
                    let candidate = &candidates[index];
                    ProactiveCreditRequest::new(
                        u32::from(candidate.dst),
                        reserve_bytes,
                        candidate.marginal_utility_micros,
                        candidate.copy_index,
                    )
                })
                .collect::<Vec<_>>();
            for (index, grant) in indexes.into_iter().zip(
                self.voice_budget
                    .reserve_link_proactive_credit_batch(first_hop, s2s_seq, &requests),
            ) {
                credit_grants[index] = grant;
            }
        }
        for (candidate, credit_permit) in candidates.into_iter().zip(credit_grants) {
            let Some(credit_permit) = credit_permit else {
                metrics::record_proactive_outcome(
                    VoiceProactiveKind::Ordinary,
                    VoiceProactiveResult::CreditShed,
                );
                continue;
            };
            let Some(queue_permit) = self.voice_budget.try_reserve_proactive(reserve_bytes) else {
                drop(credit_permit);
                metrics::record_proactive_outcome(
                    VoiceProactiveKind::Ordinary,
                    VoiceProactiveResult::QueueBudgetShed,
                );
                continue;
            };
            let work = ProactiveSendWork {
                sender_session,
                dst: candidate.dst,
                body: proactive_body.clone(),
                avoid_first_hop: candidate.avoid_first_hop,
                expires_at: candidate.expires_at,
                _permit: queue_permit,
                credit_permit,
            };
            if self.proactive_send_tx.send(work).is_ok() {
                metrics::record_proactive_outcome(
                    VoiceProactiveKind::Ordinary,
                    VoiceProactiveResult::Queued,
                );
            } else {
                metrics::record_proactive_outcome(
                    VoiceProactiveKind::Ordinary,
                    VoiceProactiveResult::QueueShed,
                );
            }
        }
        publish_proactive_budget(&self.voice_budget);
    }

    fn capture_repair_frame_context(&self, dsts: &[NodeIdentifier]) -> Option<RepairFrameContext> {
        if !self.cfg.repair_enabled {
            return None;
        }
        let deadline_origin = Instant::now();
        let local_node = self.transport.local_node_id();
        let remote = dsts
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, destination)| *destination != local_node)
            .collect::<Vec<_>>();
        let remote_destinations = remote
            .iter()
            .map(|(_, destination)| *destination)
            .collect::<Vec<_>>();
        let remote_qualities = self.transport.voice_route_qualities(&remote_destinations);
        let mut aligned = vec![None; dsts.len()];
        for ((index, _), quality) in remote.into_iter().zip(remote_qualities) {
            aligned[index] = quality;
        }
        Some(RepairFrameContext {
            deadline_origin,
            route_qualities: aligned,
        })
    }
}

fn proactive_repair_score_micros(
    cfg: &VoiceConfig,
    quality: Option<crate::overlay::VoiceRouteQuality>,
) -> Option<u64> {
    let quality = quality?;
    if quality.transport() != TransportKind::Udp {
        return None;
    }
    if quality.loss_ppm() >= cfg.repair_full_dup_loss_ppm {
        return Some(1_000_000);
    }
    let distant_path = quality.path_latency_us() >= DISTANT_REPAIR_PATH_LATENCY_US;
    let distant_loss_start_ppm = cfg.repair_loss_start_ppm.saturating_div(4).max(1);
    let distant_full_dup_loss_ppm = cfg
        .repair_loss_start_ppm
        .saturating_div(2)
        .max(distant_loss_start_ppm)
        .min(cfg.repair_full_dup_loss_ppm.max(1));
    if distant_path && quality.loss_ppm() >= distant_full_dup_loss_ppm {
        return Some(1_000_000);
    }
    let jitter_start_us = cfg.repair_jitter_start_ms.saturating_mul(1_000);
    let distant_jitter_start_us = jitter_start_us.saturating_div(2).max(1);
    let normal_trigger =
        quality.loss_ppm() >= cfg.repair_loss_start_ppm || quality.jitter_us() >= jitter_start_us;
    let distant_trigger = distant_path
        && (quality.loss_ppm() >= distant_loss_start_ppm
            || quality.jitter_us() >= distant_jitter_start_us);
    if !normal_trigger && !distant_trigger {
        return None;
    }

    let full_loss = if distant_trigger {
        distant_full_dup_loss_ppm
    } else {
        cfg.repair_full_dup_loss_ppm.max(1)
    };
    let loss_score = (u64::from(quality.loss_ppm()).saturating_mul(1_000_000))
        .saturating_div(u64::from(full_loss));
    let jitter_denominator = if distant_trigger {
        distant_jitter_start_us.saturating_mul(2).max(1)
    } else {
        jitter_start_us.saturating_mul(3).max(1)
    };
    let jitter_score = if jitter_start_us == 0 {
        1_000_000
    } else {
        quality
            .jitter_us()
            .saturating_mul(1_000_000)
            .saturating_div(jitter_denominator)
    };
    let distant_score = if distant_trigger { 500_000 } else { 0 };
    Some(
        loss_score
            .max(jitter_score)
            .max(distant_score)
            .clamp(1, 1_000_000),
    )
}

fn proactive_repair_extra_copy_count(
    max_extra_copies: usize,
    score_micros: u64,
    sample: u64,
) -> usize {
    let max_extra_copies = max_extra_copies.min(2);
    if max_extra_copies == 0 || score_micros == 0 {
        return 0;
    }
    let max_extra_copies_u64 = max_extra_copies as u64;
    let scaled = score_micros
        .min(1_000_000)
        .saturating_mul(max_extra_copies_u64);
    let guaranteed = scaled / 1_000_000;
    let fractional = u64::from(sample < scaled % 1_000_000);
    guaranteed
        .saturating_add(fractional)
        .min(max_extra_copies_u64) as usize
}

fn proactive_repair_sample(dst: NodeIdentifier, s2s_seq: u64) -> u64 {
    let mut x = (u64::from(u32::from(dst)) << 32) ^ s2s_seq;
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^= x >> 33;
    x % 1_000_000
}

fn route_hint_from_quality(quality: crate::overlay::VoiceRouteQuality) -> VoiceRouteHint {
    VoiceRouteHint::new(
        quality.path_latency_us(),
        quality.jitter_us(),
        quality.loss_ppm(),
    )
}

fn adaptive_repair_transport_ttl(
    cfg: &VoiceConfig,
    quality: Option<crate::overlay::VoiceRouteQuality>,
) -> Duration {
    let base = cfg.repair_transport_ttl_ms;
    let adaptive = quality
        .map(route_hint_from_quality)
        .map(|hint| Reorderer::route_repair_delay_ms_for_config(cfg, hint))
        .unwrap_or(base);
    Duration::from_millis(base.max(adaptive))
}

/// Wait long enough for a healthy terminal ACK to make a round trip before
/// retransmitting the cached suffix. Route latency is an effective one-way
/// estimate, so add it to the existing route-aware repair delay to cover the
/// return leg. Keep one worker interval before cache expiry for a final try.
fn tail_repair_initial_delay(cfg: &VoiceConfig, quality: Option<VoiceRouteQuality>) -> Duration {
    let fallback_ms = TAIL_REPAIR_INITIAL_DELAY.as_millis() as u64;
    let Some(quality) = quality else {
        return TAIL_REPAIR_INITIAL_DELAY;
    };
    let lifetime_ms = tail_repair_lifetime(cfg).as_millis() as u64;
    let scan_ms = TAIL_REPAIR_INTERVAL.as_millis() as u64;
    let maximum_ms = lifetime_ms.saturating_sub(scan_ms).max(fallback_ms);
    let path_ms = quality.path_latency_us().saturating_add(999) / 1_000;
    let route_delay_ms =
        Reorderer::route_repair_delay_ms_for_config(cfg, route_hint_from_quality(quality));
    Duration::from_millis(
        route_delay_ms
            .saturating_add(path_ms)
            .clamp(fallback_ms, maximum_ms),
    )
}

fn normal_intent(channel_id: u32) -> VoiceIntent {
    VoiceIntent {
        kind: Some(VoiceIntentKind::Normal(VoiceIntentNormal {
            source_channel: channel_id,
        })),
    }
}

pub struct VoiceInbound {
    primary_inbox_tx: mpsc::UnboundedSender<InboundVoiceWork>,
    proactive_inbox_tx: mpsc::UnboundedSender<InboundVoiceWork>,
    voice_budget: AdaptiveVoiceBudget,
}

impl ServiceInbound for VoiceInbound {
    fn handle(&self, msg: OverlayInboundMessage) {
        match proto::decode_voice(&msg.body) {
            Ok(frame) => {
                let copy_kind = if msg.is_distribution_repair {
                    VoiceCopyKind::ReactiveRepair
                } else if frame.fec_parity {
                    // A FEC parity frame is never audio. Classify it as
                    // proactive-class so it draws from the repair reserve
                    // rather than primary audio admission; the dispatch task
                    // intercepts it before the reorder.
                    VoiceCopyKind::Fec
                } else if frame.proactive_copy {
                    VoiceCopyKind::Proactive
                } else {
                    VoiceCopyKind::Original
                };
                let class = if matches!(
                    copy_kind,
                    VoiceCopyKind::Proactive | VoiceCopyKind::Fec
                ) {
                    VoiceIngressClass::Proactive
                } else {
                    VoiceIngressClass::Primary
                };
                let permit = match class {
                    VoiceIngressClass::Primary => {
                        self.voice_budget.try_reserve_primary(msg.body.len())
                    }
                    VoiceIngressClass::Proactive => {
                        self.voice_budget.try_reserve_proactive(msg.body.len())
                    }
                };
                let Some(permit) = permit else {
                    metrics::record_ingress_admission_drop(class);
                    publish_ingress_budget(&self.voice_budget);
                    return;
                };
                let work = InboundVoiceWork {
                    delivery: VoiceDelivery {
                        from: msg.from,
                        frame,
                        copy_kind,
                    },
                    _permit: permit,
                };
                let result = match class {
                    VoiceIngressClass::Primary => self.primary_inbox_tx.send(work),
                    VoiceIngressClass::Proactive => self.proactive_inbox_tx.send(work),
                };
                if result.is_err() {
                    metrics::record_ingress_admission_drop(class);
                }
                publish_ingress_budget(&self.voice_budget);
            }
            Err(e) => {
                trace!(error=%e, from=%msg.from, "voice: decode failed");
            }
        }
    }
}

struct VoiceRepairInbound {
    transport: Arc<dyn VoiceTransport>,
    repair_enabled: bool,
    response_tx: mpsc::Sender<RepairResponseRequest>,
    tail_repairs: TailRepairState,
    response_ttl: Duration,
}

struct VoicePathFeedbackInbound {
    transport: Arc<dyn VoiceTransport>,
}

impl ServiceInbound for VoicePathFeedbackInbound {
    fn handle(&self, msg: OverlayInboundMessage) {
        match proto::decode_voice_path_feedback(&msg.body) {
            Ok(feedback) => self.transport.record_path_feedback(msg.from, feedback),
            Err(error) => trace!(%error, from = %msg.from, "voice path feedback: decode failed"),
        }
    }
}

impl ServiceInbound for VoiceRepairInbound {
    fn handle(&self, msg: OverlayInboundMessage) {
        if !self.repair_enabled {
            return;
        }
        let source = self.transport.local_node_id();
        let request = match proto::decode_voice_repair_request(&msg.body) {
            Ok(request) => request,
            Err(e) => {
                trace!(error=%e, from=%msg.from, "voice repair: decode failed");
                return;
            }
        };
        if request.tail_ack {
            let key = TailRepairKey {
                destination: msg.from,
                sender_session: request.sender_session,
                sender_epoch: request.sender_epoch,
                terminal_seq: request.last_seq,
            };
            if let Some(entry) = self.tail_repairs.lock().remove(&key) {
                entry.cancel.cancel();
                metrics::record_repair(source, msg.from, VoiceRepairResult::TailAckReceived, 1);
            }
            return;
        }
        let request_ttl = if request.request_ttl_ms == 0 {
            self.response_ttl
        } else {
            Duration::from_millis(u64::from(request.request_ttl_ms)).min(self.response_ttl)
        };
        let work = RepairResponseRequest {
            from: msg.from,
            request,
            deadline: Instant::now()
                .checked_add(request_ttl)
                .unwrap_or_else(Instant::now),
        };
        if self.response_tx.try_send(work).is_err() {
            metrics::record_repair(source, msg.from, VoiceRepairResult::RequestSuppressed, 1);
        }
    }
}

fn spawn_dispatch_task(
    mut primary_rx: mpsc::UnboundedReceiver<InboundVoiceWork>,
    mut proactive_rx: mpsc::UnboundedReceiver<InboundVoiceWork>,
    mut deadline_rx: mpsc::Receiver<()>,
    shutdown: CancellationToken,
    audio_sink: AudioSinkSlot,
    reorderer: Arc<Reorderer>,
    transport: Arc<dyn VoiceTransport>,
    cfg: VoiceConfig,
    voice_budget: AdaptiveVoiceBudget,
    repair_request_scheduler: RepairRequestScheduler,
    path_feedback: Arc<PathFeedbackAccumulator>,
    fec_state: Arc<fec::ReceiverFecState>,
) {
    tokio::spawn(async move {
        let mut primary_open = true;
        let mut proactive_open = true;
        let mut deadline_open = true;
        loop {
            // Greedily drain the latency-critical lane first. Proactive
            // duplicates cannot preempt an original or reactive repair.
            let ready = if primary_open {
                match primary_rx.try_recv() {
                    Ok(work) => Some(DispatchEvent::Inbound(work)),
                    Err(mpsc::error::TryRecvError::Empty) => None,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        primary_open = false;
                        None
                    }
                }
            } else {
                None
            };
            let event = match ready {
                Some(event) => event,
                None => {
                    if !primary_open && !proactive_open && !deadline_open {
                        return;
                    }
                    tokio::select! {
                        biased;
                        _ = shutdown.cancelled() => return,
                        work = primary_rx.recv(), if primary_open => match work {
                            Some(work) => DispatchEvent::Inbound(work),
                            None => {
                                primary_open = false;
                                continue;
                            }
                        },
                        wake = deadline_rx.recv(), if deadline_open => match wake {
                            Some(()) => DispatchEvent::DeadlineFired,
                            None => {
                                deadline_open = false;
                                continue;
                            }
                        },
                        work = proactive_rx.recv(), if proactive_open => match work {
                            Some(work) => DispatchEvent::Inbound(work),
                            None => {
                                proactive_open = false;
                                continue;
                            }
                        },
                    }
                }
            };

            let source = transport.local_node_id();
            let (report, inbound_labels, _inbound_permit) = match event {
                DispatchEvent::Inbound(InboundVoiceWork { delivery, _permit }) => {
                    let origin_node = shitspeak_core::ClientSessionIdentifier::from(
                        delivery.frame.sender_session,
                    )
                    .get_node_id();
                    let from = delivery.from;
                    let sender_session = delivery.frame.sender_session;
                    let sender_epoch = delivery.frame.sender_epoch;
                    let fec_enabled = cfg.voice_fec_enabled;
                    let is_parity = delivery.frame.fec_parity;
                    let report = if fec_enabled && is_parity {
                        // Parity frame: never audio. Record the block and try
                        // to reconstruct against the current reorder gap
                        // (None recovers anything the mirror can).
                        fec_state.record_parity(
                            from,
                            sender_session,
                            sender_epoch,
                            delivery.frame.fec_member_seqs.clone(),
                            delivery.frame.payload.clone(),
                            delivery.frame.fec_parity_index as usize,
                            delivery.frame.fec_terminator_mask,
                        );
                        let mut report = reorder::ReorderReport::empty();
                        let gap = reorderer.live_missing_range(sender_session, sender_epoch);
                        for recovered in fec_state.try_reconstruct(from, sender_session, sender_epoch, gap) {
                            report = report.merge(
                                reorderer.push_with_route_hint_report_with_copy_kind(
                                    from,
                                    recovered,
                                    None,
                                    VoiceCopyKind::Fec,
                                ),
                            );
                        }
                        report
                    } else if !fec_enabled && is_parity {
                        // FEC disabled on this receiver but a parity frame
                        // arrived (mixed fleet): it is not audio, drop it.
                        reorder::ReorderReport::empty()
                    } else {
                        if fec_enabled {
                            fec_state.record_frame(from, delivery.frame.clone());
                        }
                        let route_hint = reorderer
                            .may_arm_gap(&delivery.frame, delivery.copy_kind)
                            .then(|| {
                                transport
                                    .voice_route_quality(origin_node)
                                    .map(route_hint_from_quality)
                            })
                            .flatten();
                        let mut report =
                            reorderer.push_with_route_hint_report_with_copy_kind(
                                from,
                                delivery.frame,
                                route_hint,
                                delivery.copy_kind,
                            );
                        // A data push just opened a gap: the parity block for
                        // it may already be in the mirror. Reconstruct the
                        // live range now.
                        if fec_enabled && report.opened_gap().is_some() {
                            let gap =
                                reorderer.live_missing_range(sender_session, sender_epoch);
                            for recovered in fec_state.try_reconstruct(
                                from,
                                sender_session,
                                sender_epoch,
                                gap,
                            ) {
                                report = report.merge(
                                    reorderer.push_with_route_hint_report_with_copy_kind(
                                        from,
                                        recovered,
                                        None,
                                        VoiceCopyKind::Fec,
                                    ),
                                );
                            }
                        }
                        report
                    };
                    if cfg.repair_enabled
                        && let Some(gap) = report.opened_gap()
                    {
                        metrics::record_repair(
                            source,
                            repair_destination(gap.sender_session),
                            VoiceRepairResult::GapDetected,
                            1,
                        );
                        repair_request_scheduler.schedule(source, gap);
                    }
                    (report, Some((origin_node, from)), Some(_permit))
                }
                DispatchEvent::DeadlineFired => {
                    // Sample the held-delay state BEFORE the drain: flushing a
                    // held chunk resets its `hold_started_at`, so observing
                    // after the drain loses exactly the delay the chunk just
                    // absorbed (the signal the gauges and Pillar D feedback
                    // exist to surface).
                    let held = reorderer.held_state();
                    let report = reorderer.drain_expired_report();
                    metrics::set_reorder_held(held.0, held.1);
                    (report, None, None)
                }
            };
            metrics::set_reorder_pending(source, report.pending_total());
            metrics::set_reorder_speaker_state(
                reorderer.tracked_speaker_count(),
                reorderer.tracked_speaker_capacity(),
            );
            if let Some((origin_node, from_immediate)) = inbound_labels {
                for result in report.result_counts() {
                    metrics::record_receive(
                        source,
                        origin_node,
                        from_immediate,
                        result.result(),
                        result.count(),
                    );
                    if let Some(feedback) =
                        path_feedback.record(from_immediate, result.result(), result.count())
                    {
                        let transport = transport.clone();
                        tokio::spawn(async move {
                            let _ = transport.send_path_feedback(from_immediate, feedback).await;
                        });
                    }
                }
            }
            // Captured before `into_marked_emissions` moves `report`: the
            // per-peer flush attribution is needed to feed the path-feedback
            // accumulator on the deadline path.
            let deadline_flushes: Vec<FlushByPeer> = if inbound_labels.is_none() {
                report.flushes_by_peer().to_vec()
            } else {
                Vec::new()
            };
            let emits = report.into_marked_emissions();
            if inbound_labels.is_none() {
                for emission in &emits {
                    let from = emission.from();
                    let frame = emission.frame();
                    let origin_node =
                        shitspeak_core::ClientSessionIdentifier::from(frame.sender_session)
                            .get_node_id();
                    metrics::record_receive(
                        source,
                        origin_node,
                        from,
                        VoiceReceiveResult::DeadlineFlush,
                        1,
                    );
                }
                // Path feedback on the deadline path. This is the previous
                // dead path: deadline events never reached the accumulator
                // (it was only fed from push events), so `deadline_flush`
                // was always zero in the receiver's report. A flushed chunk
                // is reported to the immediate peer that carried it, along
                // with the held delay the chunk absorbed before release.
                for flush in deadline_flushes {
                    let from = flush.from;
                    if let Some(feedback) = path_feedback.record(
                        from,
                        VoiceReceiveResult::DeadlineFlush,
                        flush.count,
                    ) {
                        let transport = transport.clone();
                        tokio::spawn(async move {
                            let _ = transport.send_path_feedback(from, feedback).await;
                        });
                    }
                    if let Some(feedback) =
                        path_feedback.record_held_delay(from, flush.max_held_delay_us)
                    {
                        let transport = transport.clone();
                        tokio::spawn(async move {
                            let _ = transport.send_path_feedback(from, feedback).await;
                        });
                    }
                }
            }
            if emits.is_empty() {
                drop(_inbound_permit);
                publish_ingress_budget(&voice_budget);
                continue;
            }
            let sink = audio_sink.read().clone();
            match sink {
                Some(sink) => {
                    for emission in emits {
                        let (from, frame, is_repair) = emission.into_parts();
                        let tail_ack = cfg.repair_enabled && frame.is_terminator;
                        let ack_sender_session = frame.sender_session;
                        let ack_sender_epoch = frame.sender_epoch;
                        let ack_terminal_seq = frame.s2s_seq;
                        sink.deliver(from, frame, is_repair).await;
                        if tail_ack {
                            spawn_tail_ack(
                                transport.clone(),
                                shutdown.clone(),
                                ack_sender_session,
                                ack_sender_epoch,
                                ack_terminal_seq,
                                cfg.repair_request_ttl_ms,
                            );
                        }
                    }
                }
                None => {
                    for emission in &emits {
                        let from = emission.from();
                        let frame = emission.frame();
                        let origin_node =
                            shitspeak_core::ClientSessionIdentifier::from(frame.sender_session)
                                .get_node_id();
                        metrics::record_receive(
                            source,
                            origin_node,
                            from,
                            VoiceReceiveResult::NoSinkDrop,
                            1,
                        );
                    }
                    trace!(
                        n = emits.len(),
                        "voice: no audio sink installed; dropping emit batch",
                    )
                }
            }
            drop(_inbound_permit);
            publish_ingress_budget(&voice_budget);
        }
    });
}

fn publish_ingress_budget(budget: &AdaptiveVoiceBudget) {
    metrics::set_ingress_queue_budget(
        VoiceIngressClass::Primary,
        budget.primary_capacity_bytes(),
        budget.primary_reserved_bytes(),
    );
    metrics::set_ingress_queue_budget(
        VoiceIngressClass::Proactive,
        budget.proactive_capacity_bytes(),
        budget.proactive_reserved_bytes(),
    );
}

fn publish_proactive_budget(budget: &AdaptiveVoiceBudget) {
    publish_ingress_budget(budget);
    metrics::set_proactive_queue_budget(
        budget.proactive_capacity_bytes(),
        budget.proactive_reserved_bytes(),
    );
    metrics::set_proactive_credit(
        budget.proactive_credit_balance_bytes(),
        budget.proactive_credit_burst_bytes(),
    );
    let (proactive, reactive, hard_reserve, borrowed, debt, active_destinations) =
        budget.repair_allocator_state_bytes();
    metrics::set_repair_allocator_state(
        proactive,
        reactive,
        hard_reserve,
        borrowed,
        debt,
        active_destinations,
    );
}

/// Send proactively-marked alternates outside the foreground voice path.
/// The unbounded work queue is bounded by `VoiceBytePermit`; at most four
/// speaker/destination lanes await transport completion concurrently.
fn spawn_proactive_worker(
    mut rx: mpsc::UnboundedReceiver<ProactiveSendWork>,
    transport: Arc<dyn VoiceTransport>,
    voice_budget: AdaptiveVoiceBudget,
    pressure: Arc<ProactivePressureState>,
    shutdown: CancellationToken,
) {
    let mut lane_txs = Vec::with_capacity(PROACTIVE_WORKER_CONCURRENCY);
    for _ in 0..PROACTIVE_WORKER_CONCURRENCY {
        let (lane_tx, mut lane_rx) = mpsc::unbounded_channel::<ProactiveSendWork>();
        lane_txs.push(lane_tx);
        let transport = transport.clone();
        let voice_budget = voice_budget.clone();
        let pressure = pressure.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let source = transport.local_node_id();
            loop {
                let work = tokio::select! {
                    _ = shutdown.cancelled() => return,
                    work = lane_rx.recv() => match work {
                        Some(work) => work,
                        None => return,
                    },
                };
                let ProactiveSendWork {
                    sender_session: _,
                    dst,
                    body,
                    avoid_first_hop,
                    expires_at,
                    _permit,
                    credit_permit,
                } = work;
                let now = Instant::now();
                let Some(transport_ttl) = expires_at
                    .checked_duration_since(now)
                    .filter(|remaining| !remaining.is_zero())
                else {
                    metrics::record_proactive_outcome(
                        VoiceProactiveKind::Ordinary,
                        VoiceProactiveResult::QueueShed,
                    );
                    drop(credit_permit);
                    drop(_permit);
                    publish_proactive_budget(&voice_budget);
                    continue;
                };
                let pressure_token = match pressure.try_start_send(dst, now) {
                    Ok(token) => token,
                    Err(_) => {
                        metrics::record_proactive_outcome(
                            VoiceProactiveKind::Ordinary,
                            VoiceProactiveResult::QueueShed,
                        );
                        drop(_permit);
                        drop(credit_permit);
                        publish_proactive_budget(&voice_budget);
                        continue;
                    }
                };
                let send_result = tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => {
                        pressure.cancel_send(dst, pressure_token);
                        return;
                    },
                    result = async {
                        credit_permit.record_attempt();
                        transport.send_proactive_repair_frame(
                            dst,
                            body,
                            avoid_first_hop,
                            transport_ttl,
                        ).await
                    } => result,
                };
                match send_result {
                    Ok(()) => {
                        credit_permit.commit();
                        pressure.complete_success(dst, pressure_token);
                        metrics::record_repair(
                            source,
                            dst,
                            VoiceRepairResult::ProactiveCopySent,
                            1,
                        );
                        metrics::record_proactive_outcome(
                            VoiceProactiveKind::Ordinary,
                            VoiceProactiveResult::Sent,
                        );
                    }
                    Err(error) => {
                        drop(credit_permit);
                        pressure.complete_failure(
                            dst,
                            pressure_token,
                            Instant::now(),
                            PROACTIVE_FAILURE_BACKOFF_INITIAL,
                            PROACTIVE_FAILURE_BACKOFF_MAX,
                        );
                        trace!(%error, %dst, "voice proactive repair send failed; cooling down destination");
                        metrics::record_proactive_outcome(
                            VoiceProactiveKind::Ordinary,
                            VoiceProactiveResult::SendFailed,
                        );
                    }
                }
                drop(_permit);
                publish_proactive_budget(&voice_budget);
            }
        });
    }

    tokio::spawn(async move {
        loop {
            let work = tokio::select! {
                _ = shutdown.cancelled() => return,
                work = rx.recv() => match work {
                    Some(work) => work,
                    None => return,
                },
            };
            let lane = (work.sender_session as usize
                ^ usize::try_from(u32::from(work.dst)).unwrap_or(0))
                % PROACTIVE_WORKER_CONCURRENCY;
            if lane_txs[lane].send(work).is_err() {
                return;
            }
        }
    });
}

/// Keep the end of every originated utterance alive until the receiver has
/// emitted its terminator contiguously. A terminator has no later packet that
/// could open a reorder gap, so ordinary NACK repair cannot discover a loss at
/// the tail. These bounded, proactively marked suffix copies use an isolated
/// sender-side reactive budget/pressure lane, but retain proactive receiver
/// semantics so they can advance a healthy stream, and stop immediately on ACK.
fn spawn_tail_repair_worker(
    repairs: TailRepairState,
    transport: Arc<dyn VoiceTransport>,
    repair_cache: Arc<RepairCache>,
    cfg: VoiceConfig,
    voice_budget: AdaptiveVoiceBudget,
    pressure: Arc<ProactivePressureState>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(TAIL_REPAIR_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    for entry in repairs.lock().values() {
                        entry.cancel.cancel();
                    }
                    return;
                },
                _ = ticker.tick() => {}
            }
            dispatch_due_tail_repairs_with_shutdown(
                &repairs,
                transport.as_ref(),
                &repair_cache,
                &cfg,
                &voice_budget,
                &pressure,
                Instant::now(),
                &shutdown,
            )
            .await;
        }
    });
}

#[cfg(test)]
async fn dispatch_due_tail_repairs(
    repairs: &TailRepairState,
    transport: &dyn VoiceTransport,
    repair_cache: &RepairCache,
    cfg: &VoiceConfig,
    voice_budget: &AdaptiveVoiceBudget,
    pressure: &ProactivePressureState,
    now: Instant,
) {
    dispatch_due_tail_repairs_with_shutdown(
        repairs,
        transport,
        repair_cache,
        cfg,
        voice_budget,
        pressure,
        now,
        &CancellationToken::new(),
    )
    .await;
}

async fn dispatch_due_tail_repairs_with_shutdown(
    repairs: &TailRepairState,
    transport: &dyn VoiceTransport,
    repair_cache: &RepairCache,
    cfg: &VoiceConfig,
    voice_budget: &AdaptiveVoiceBudget,
    pressure: &ProactivePressureState,
    now: Instant,
    shutdown: &CancellationToken,
) {
    let mut due: Vec<(Instant, TailRepairKey)> = {
        let mut state = repairs.lock();
        state.retain(|_, entry| {
            let keep = entry.expires_at > now;
            if !keep {
                entry.cancel.cancel();
            }
            keep
        });
        state
            .iter()
            .filter_map(|(key, entry)| {
                if entry.next_retry > now || entry.attempts >= TAIL_REPAIR_MAX_ATTEMPTS {
                    return None;
                }
                Some((entry.expires_at, *key))
            })
            .collect()
    };
    due.sort_unstable_by_key(|(deadline, key)| {
        (
            *deadline,
            u32::from(key.destination),
            key.sender_session,
            key.sender_epoch,
            key.terminal_seq,
        )
    });
    let mut ready = due
        .into_iter()
        .map(|(_, key)| {
            let first_seq = key
                .terminal_seq
                .saturating_sub(TAIL_REPAIR_SUFFIX_FRAMES.saturating_sub(1));
            (key, first_seq)
        })
        .collect::<VecDeque<_>>();
    let mut sends = stream::FuturesUnordered::new();
    let mut active_destinations = HashSet::new();
    let transport_slots = Arc::new(Semaphore::new(TAIL_REPAIR_CONCURRENCY));
    loop {
        loop {
            let Some(ready_index) = ready
                .iter()
                .position(|(key, _)| !active_destinations.contains(&key.destination))
            else {
                break;
            };
            let Some((key, seq)) = ready.remove(ready_index) else {
                break;
            };
            let Some(entry) = repairs.lock().get(&key).cloned() else {
                continue;
            };
            if entry.expires_at <= Instant::now() || entry.cancel.is_cancelled() {
                continue;
            }
            let pressure_token =
                match pressure.try_start_send(key.destination, Instant::now().max(now)) {
                    Ok(token) => token,
                    Err(ProactiveSendRejection::Cooldown(blocked_until)) => {
                        if let Some(entry) = repairs.lock().get_mut(&key) {
                            entry.next_retry = entry.next_retry.max(blocked_until);
                        }
                        continue;
                    }
                    Err(ProactiveSendRejection::InFlight) => {
                        ready.push_back((key, seq));
                        break;
                    }
                };
            let next_attempt = entry.attempts.saturating_add(1);
            let cancel = entry.cancel.clone();
            let transport_slots = transport_slots.clone();
            active_destinations.insert(key.destination);
            sends.push(async move {
                let result = send_tail_repair_frame(
                    repairs,
                    transport,
                    repair_cache,
                    cfg,
                    voice_budget,
                    shutdown,
                    key,
                    seq,
                    next_attempt,
                    entry.expires_at,
                    cancel,
                    transport_slots,
                )
                .await;
                (key, seq, next_attempt, pressure_token, result)
            });
        }
        let Some((key, seq, next_attempt, pressure_token, result)) = sends.next().await else {
            break;
        };
        active_destinations.remove(&key.destination);
        let attempt_committed = repairs
            .lock()
            .get(&key)
            .is_some_and(|entry| entry.attempts >= next_attempt);
        match result {
            TailFrameResult::Sent => {
                pressure.complete_success(key.destination, pressure_token);
                if seq < key.terminal_seq {
                    // Yield after every frame so all other ready destinations
                    // reach the reactive EDF/DRR allocator before this suffix
                    // can consume another transport slot.
                    ready.push_back((key, seq.saturating_add(1)));
                } else {
                    finish_tail_attempt(repairs, key, next_attempt, None, Instant::now().max(now));
                }
            }
            TailFrameResult::Skipped => {
                pressure.cancel_send(key.destination, pressure_token);
                if seq < key.terminal_seq {
                    ready.push_back((key, seq.saturating_add(1)));
                } else {
                    finish_tail_attempt(repairs, key, next_attempt, None, Instant::now().max(now));
                }
            }
            TailFrameResult::SendFailed => {
                let retry = pressure.complete_failure(
                    key.destination,
                    pressure_token,
                    Instant::now().max(now),
                    TAIL_REPAIR_INTERVAL,
                    TAIL_REPAIR_FAILURE_BACKOFF_MAX,
                );
                finish_tail_attempt(
                    repairs,
                    key,
                    next_attempt,
                    Some(retry),
                    Instant::now().max(now),
                );
            }
            TailFrameResult::CreditUnavailable | TailFrameResult::QueueUnavailable => {
                pressure.cancel_send(key.destination, pressure_token);
                if attempt_committed {
                    finish_tail_attempt(repairs, key, next_attempt, None, Instant::now().max(now));
                }
            }
            TailFrameResult::Cancelled => {
                pressure.cancel_send(key.destination, pressure_token);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TailFrameResult {
    Sent,
    Skipped,
    CreditUnavailable,
    QueueUnavailable,
    SendFailed,
    Cancelled,
}

#[allow(clippy::too_many_arguments)]
async fn send_tail_repair_frame(
    repairs: &TailRepairState,
    transport: &dyn VoiceTransport,
    repair_cache: &RepairCache,
    cfg: &VoiceConfig,
    voice_budget: &AdaptiveVoiceBudget,
    shutdown: &CancellationToken,
    key: TailRepairKey,
    seq: u64,
    next_attempt: u8,
    repair_deadline: Instant,
    cancel: CancellationToken,
    transport_slots: Arc<Semaphore>,
) -> TailFrameResult {
    let Some(frame) = repair_cache
        .lookup_range(key.sender_session, key.sender_epoch, seq, seq)
        .into_iter()
        .next()
    else {
        return TailFrameResult::Skipped;
    };
    let body = match send::mark_proactive_copy(frame.body()) {
        Ok(body) => body,
        Err(error) => {
            trace!(%error, "voice tail repair: mark envelope failed");
            return TailFrameResult::Skipped;
        }
    };
    metrics::record_repair_destination_bytes(
        key.destination,
        RepairDestinationStage::Requested,
        body.len(),
    );
    let quality = transport.voice_route_quality(key.destination);
    let avoid_first_hop = quality.map(|quality| quality.next_hop());
    let first_hop = quality
        .and_then(|quality| quality.alternate_next_hop())
        .unwrap_or(key.destination);
    let credit_reservation = voice_budget.reserve_link_reactive_credit_scheduled(
        first_hop,
        u32::from(key.destination),
        body.len(),
        repair_deadline,
        next_attempt > 1,
    );
    let credit_permit = tokio::select! {
        biased;
        _ = shutdown.cancelled() => return TailFrameResult::Cancelled,
        _ = cancel.cancelled() => return TailFrameResult::Cancelled,
        permit = credit_reservation => permit,
    };
    let Some(credit_permit) = credit_permit else {
        metrics::record_repair_destination_bytes(
            key.destination,
            RepairDestinationStage::Shed,
            body.len(),
        );
        metrics::record_proactive_outcome(
            VoiceProactiveKind::Tail,
            VoiceProactiveResult::CreditShed,
        );
        publish_proactive_budget(voice_budget);
        return TailFrameResult::CreditUnavailable;
    };
    if cancel.is_cancelled() || shutdown.is_cancelled() || repair_deadline <= Instant::now() {
        drop(credit_permit);
        publish_proactive_budget(voice_budget);
        return TailFrameResult::Cancelled;
    }
    let Some(queue_permit) = voice_budget.try_reserve_primary(body.len()) else {
        drop(credit_permit);
        metrics::record_proactive_outcome(
            VoiceProactiveKind::Tail,
            VoiceProactiveResult::QueueBudgetShed,
        );
        publish_proactive_budget(voice_budget);
        return TailFrameResult::QueueUnavailable;
    };
    let transport_slot = tokio::select! {
        biased;
        _ = shutdown.cancelled() => None,
        _ = cancel.cancelled() => None,
        permit = tokio::time::timeout_at(repair_deadline.into(), transport_slots.acquire()) => {
            permit.ok().and_then(Result::ok)
        }
    };
    let Some(transport_slot) = transport_slot else {
        drop(queue_permit);
        drop(credit_permit);
        publish_proactive_budget(voice_budget);
        return if cancel.is_cancelled() || shutdown.is_cancelled() {
            TailFrameResult::Cancelled
        } else {
            TailFrameResult::QueueUnavailable
        };
    };
    {
        let mut state = repairs.lock();
        let Some(entry) = state.get_mut(&key) else {
            drop(queue_permit);
            drop(credit_permit);
            publish_proactive_budget(voice_budget);
            return TailFrameResult::Cancelled;
        };
        if entry.cancel.is_cancelled() || entry.expires_at <= Instant::now() {
            drop(queue_permit);
            drop(credit_permit);
            publish_proactive_budget(voice_budget);
            return TailFrameResult::Cancelled;
        }
        entry.attempts = entry.attempts.max(next_attempt);
    }
    let ttl = adaptive_repair_transport_ttl(cfg, quality);
    let send_deadline = repair_deadline.min(Instant::now() + tail_repair_send_timeout(ttl));
    credit_permit.record_attempt();
    let send_result = tokio::select! {
        biased;
        _ = shutdown.cancelled() => None,
        _ = cancel.cancelled() => None,
        result = tokio::time::timeout_at(
            send_deadline.into(),
            transport.send_proactive_repair_frame(
                key.destination,
                body,
                avoid_first_hop,
                ttl,
            ),
        ) => Some(result),
    };
    drop(transport_slot);
    drop(queue_permit);
    let Some(send_result) = send_result else {
        drop(credit_permit);
        publish_proactive_budget(voice_budget);
        return TailFrameResult::Cancelled;
    };
    match send_result {
        Ok(Ok(())) => {
            // Once the transport reports acceptance, charge the attempt even
            // if an ACK or shutdown raced immediately afterward: bytes may
            // already have been emitted and cannot be recalled.
            credit_permit.commit();
            publish_proactive_budget(voice_budget);
            metrics::record_repair(
                transport.local_node_id(),
                key.destination,
                VoiceRepairResult::TailRetrySent,
                1,
            );
            metrics::record_proactive_outcome(VoiceProactiveKind::Tail, VoiceProactiveResult::Sent);
            TailFrameResult::Sent
        }
        Ok(Err(error)) => {
            drop(credit_permit);
            publish_proactive_budget(voice_budget);
            metrics::record_proactive_outcome(
                VoiceProactiveKind::Tail,
                VoiceProactiveResult::SendFailed,
            );
            trace!(%error, "voice tail repair send failed; backing off destination");
            TailFrameResult::SendFailed
        }
        Err(_) => {
            drop(credit_permit);
            publish_proactive_budget(voice_budget);
            metrics::record_proactive_outcome(
                VoiceProactiveKind::Tail,
                VoiceProactiveResult::SendFailed,
            );
            trace!(destination = %key.destination, "voice tail repair send timed out");
            TailFrameResult::SendFailed
        }
    }
}

fn finish_tail_attempt(
    repairs: &TailRepairState,
    key: TailRepairKey,
    attempt: u8,
    destination_retry: Option<Instant>,
    finished_at: Instant,
) {
    let mut state = repairs.lock();
    let Some(entry) = state.get_mut(&key) else {
        return;
    };
    if entry.attempts < attempt {
        return;
    }
    let attempt_retry = finished_at
        + exponential_backoff(
            TAIL_REPAIR_INTERVAL,
            TAIL_REPAIR_FAILURE_BACKOFF_MAX,
            entry.attempts,
        );
    entry.next_retry = entry
        .next_retry
        .max(attempt_retry)
        .max(destination_retry.unwrap_or(attempt_retry));
    if entry.attempts >= TAIL_REPAIR_MAX_ATTEMPTS {
        if let Some(entry) = state.remove(&key) {
            entry.cancel.cancel();
        }
    }
}

fn exponential_backoff(initial: Duration, maximum: Duration, failures: u8) -> Duration {
    let shift = u32::from(failures.saturating_sub(1)).min(31);
    initial.saturating_mul(1_u32 << shift).min(maximum)
}

fn tail_repair_send_timeout(transport_ttl: Duration) -> Duration {
    transport_ttl
        .min(TAIL_REPAIR_SEND_TIMEOUT_MAX)
        .max(Duration::from_millis(1))
}

fn spawn_tail_ack(
    transport: Arc<dyn VoiceTransport>,
    shutdown: CancellationToken,
    sender_session: u32,
    sender_epoch: u64,
    terminal_seq: u64,
    request_ttl_ms: u64,
) {
    tokio::spawn(async move {
        let destination = repair_destination(sender_session);
        let request = VoiceRepairRequest {
            sender_session,
            sender_epoch,
            first_seq: terminal_seq,
            last_seq: terminal_seq,
            request_sent_unix_ms: 0,
            request_ttl_ms: request_ttl_ms.min(u64::from(u32::MAX)) as u32,
            tail_ack: true,
        };
        let Ok(body) = proto::encode_voice_repair_request(&request) else {
            return;
        };
        let result = tokio::select! {
            _ = shutdown.cancelled() => return,
            result = transport.send_repair_request(
                destination,
                body,
                Duration::from_millis(request_ttl_ms),
            ) => result,
        };
        if result.is_ok() {
            metrics::record_repair(
                transport.local_node_id(),
                destination,
                VoiceRepairResult::TailAckSent,
                1,
            );
        }
    });
}

fn tail_repair_lifetime(cfg: &VoiceConfig) -> Duration {
    Duration::from_millis(cfg.repair_cache_ms.max(250))
}

fn spawn_repair_request_worker(
    mut rx: mpsc::Receiver<GapReport>,
    reorderer: Arc<Reorderer>,
    transport: Arc<dyn VoiceTransport>,
    request_ttl_ms: u64,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        let source = transport.local_node_id();
        let mut active = HashMap::<RepairRequestKey, RepairRequestState>::new();
        let mut jobs = tokio::task::JoinSet::<(RepairRequestKey, u64, u64, bool)>::new();
        let mut next_generation = 0_u64;
        let mut ticker = tokio::time::interval(REPAIR_REQUEST_POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                gap = rx.recv() => {
                    let Some(gap) = gap else { return; };
                    let key = RepairRequestKey::new(gap);
                    let stale = active
                        .iter()
                        .filter_map(|(key, state)| {
                            reorderer
                                .current_actionable_gap(
                                    state.from,
                                    key.sender_session,
                                    key.sender_epoch,
                                )
                                .is_none()
                                .then_some(*key)
                        })
                        .collect::<Vec<_>>();
                    for stale_key in stale {
                        if let Some(state) = active.remove(&stale_key) {
                            state.send_cancel.cancel();
                        }
                    }
                    if let Some(state) = active.get_mut(&key) {
                        state.from = gap.from;
                    } else if active.len() >= REPAIR_REQUEST_MAX_STREAMS {
                        metrics::record_repair(
                            source,
                            key.destination,
                            VoiceRepairResult::RequestSuppressed,
                            1,
                        );
                    } else if let Some(actionable) = reorderer.current_actionable_gap(
                        gap.from,
                        gap.sender_session,
                        gap.sender_epoch,
                    ) {
                        let now = Instant::now();
                        let current = actionable.gap();
                        let remaining = actionable.deadline().saturating_duration_since(now);
                        active.insert(
                            key,
                            RepairRequestState {
                                from: gap.from,
                                tracked_first_seq: current.first_seq,
                                attempts: 0,
                                requested_page_last: None,
                                retry_interval: repair_request_retry_interval(remaining),
                                next_attempt: now,
                                send_cancel: CancellationToken::new(),
                                in_flight_generation: None,
                            },
                        );
                    } else {
                        metrics::record_repair(
                            source,
                            key.destination,
                            VoiceRepairResult::RequestSuppressed,
                            1,
                        );
                    }
                }
                result = jobs.join_next(), if !jobs.is_empty() => {
                    match result {
                        Some(Ok((key, generation, first_seq, sent))) => {
                            if let Some(state) = active.get_mut(&key)
                                && state.in_flight_generation == Some(generation)
                            {
                                state.in_flight_generation = None;
                                if sent && state.tracked_first_seq == first_seq {
                                    state.attempts = state.attempts.saturating_add(1);
                                }
                            }
                        }
                        Some(Err(error)) => {
                            trace!(%error, "voice repair: request job failed");
                        }
                        None => {}
                    }
                }
                _ = ticker.tick() => {}
            }

            let now = Instant::now();
            let mut remove = Vec::new();
            let mut due = Vec::new();
            let mut slots = REPAIR_REQUEST_MAX_CONCURRENCY.saturating_sub(jobs.len());
            let keys = active.keys().copied().collect::<Vec<_>>();
            for key in keys {
                let Some(state) = active.get_mut(&key) else {
                    continue;
                };
                let Some(actionable) = reorderer.current_actionable_gap(
                    state.from,
                    key.sender_session,
                    key.sender_epoch,
                ) else {
                    remove.push(key);
                    continue;
                };
                let gap = actionable.gap();
                let deadline = actionable.deadline();
                if gap.first_seq != state.tracked_first_seq {
                    state.tracked_first_seq = gap.first_seq;
                    state.attempts = 0;
                    let remaining = deadline.saturating_duration_since(now);
                    state.retry_interval = repair_request_retry_interval(remaining);
                    if state
                        .requested_page_last
                        .is_some_and(|last| gap.first_seq > last)
                    {
                        state.requested_page_last = None;
                    }
                    state.next_attempt = now + REPAIR_REQUEST_POLL_INTERVAL.min(remaining);
                }
                if slots == 0
                    || state.in_flight_generation.is_some()
                    || state.attempts >= REPAIR_REQUEST_MAX_ATTEMPTS_PER_PAGE
                    || state.next_attempt > now
                {
                    continue;
                }
                let page_last = state.requested_page_last.unwrap_or_else(|| {
                    gap.last_seq.min(
                        gap.first_seq
                            .saturating_add(REPAIR_RESPONSE_PAGE_SEQUENCES.saturating_sub(1)),
                    )
                });
                state.requested_page_last = Some(page_last);
                state.next_attempt = now + state.retry_interval;
                let generation = next_generation;
                next_generation = next_generation.wrapping_add(1);
                state.in_flight_generation = Some(generation);
                due.push((
                    key,
                    key.destination,
                    GapReport {
                        last_seq: gap.last_seq.min(page_last),
                        ..gap
                    },
                    state.send_cancel.clone(),
                    generation,
                    deadline,
                ));
                slots -= 1;
            }
            for key in remove {
                if let Some(state) = active.remove(&key) {
                    state.send_cancel.cancel();
                }
            }
            for (key, destination, gap, send_cancel, generation, deadline) in due {
                let transport = transport.clone();
                jobs.spawn(async move {
                    let sent = tokio::select! {
                        _ = send_cancel.cancelled() => false,
                        sent = send_repair_request_attempt(
                            source,
                            destination,
                            gap,
                            transport,
                            request_ttl_ms,
                            deadline,
                        ) => sent,
                    };
                    (key, generation, gap.first_seq, sent)
                });
            }
        }
    });
}

fn repair_request_retry_interval(remaining: Duration) -> Duration {
    (remaining / 3).clamp(
        REPAIR_REQUEST_POLL_INTERVAL,
        REPAIR_REQUEST_MAX_RETRY_INTERVAL,
    )
}

fn repair_deadline_transport_ttl_ms(cfg: &VoiceConfig, configured_ttl_ms: u64) -> u64 {
    configured_ttl_ms
        .max(cfg.reorder_max_delay_ms)
        .max(cfg.adaptive_jitter_max_delay_ms)
}

async fn send_repair_request_attempt(
    source: NodeIdentifier,
    destination: NodeIdentifier,
    gap: GapReport,
    transport: Arc<dyn VoiceTransport>,
    transport_ttl_ms: u64,
    actionable_deadline: Instant,
) -> bool {
    let remaining = actionable_deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return false;
    }
    // The request's actionable window cannot outlive the packet on the wire:
    // cap the carried TTL at the transport bound even when the chunk-hold
    // deadline (Pillar A) extends well past the in-order skew tolerance.
    let request_ttl_ms = remaining
        .as_millis()
        .min(u128::from(transport_ttl_ms))
        .clamp(1, u128::from(u32::MAX)) as u32;
    let request = VoiceRepairRequest {
        sender_session: gap.sender_session,
        sender_epoch: gap.sender_epoch,
        first_seq: gap.first_seq,
        last_seq: gap.last_seq,
        request_sent_unix_ms: 0,
        request_ttl_ms,
        tail_ack: false,
    };
    let Ok(body) = proto::encode_voice_repair_request(&request) else {
        metrics::record_repair(source, destination, VoiceRepairResult::RequestSuppressed, 1);
        return false;
    };
    if transport
        .send_repair_request(destination, body, Duration::from_millis(transport_ttl_ms))
        .await
        .is_ok()
    {
        metrics::record_repair(source, destination, VoiceRepairResult::RequestSent, 1);
        true
    } else {
        metrics::record_repair(source, destination, VoiceRepairResult::RequestFailed, 1);
        false
    }
}

fn spawn_repair_response_worker(
    rx: mpsc::Receiver<RepairResponseRequest>,
    transport: Arc<dyn VoiceTransport>,
    repair_cache: Arc<RepairCache>,
    cfg: VoiceConfig,
    voice_budget: AdaptiveVoiceBudget,
    shutdown: CancellationToken,
) {
    let concurrency = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(REPAIR_RESPONSE_MIN_CONCURRENCY)
        .clamp(
            REPAIR_RESPONSE_MIN_CONCURRENCY,
            REPAIR_RESPONSE_MAX_CONCURRENCY,
        );
    spawn_repair_response_worker_with_concurrency(
        rx,
        transport,
        repair_cache,
        cfg,
        voice_budget,
        shutdown,
        concurrency,
    );
}

fn spawn_repair_response_worker_with_concurrency(
    mut rx: mpsc::Receiver<RepairResponseRequest>,
    transport: Arc<dyn VoiceTransport>,
    repair_cache: Arc<RepairCache>,
    cfg: VoiceConfig,
    voice_budget: AdaptiveVoiceBudget,
    shutdown: CancellationToken,
    concurrency: usize,
) {
    let concurrency = concurrency.max(1);
    tokio::spawn(async move {
        let source = transport.local_node_id();
        let mut states = HashMap::<RepairResponseKey, RepairResponseState>::new();
        let mut ready = VecDeque::<RepairResponseKey>::new();
        let mut jobs = tokio::task::JoinSet::new();
        let mut task_keys = HashMap::new();
        let mut in_flight_destinations = HashSet::new();
        let transport_slots = Arc::new(Semaphore::new(concurrency));
        let mut rx_open = true;
        loop {
            let ready_visits = ready.len();
            for _ in 0..ready_visits {
                let Some(key) = ready.pop_front() else {
                    break;
                };
                if in_flight_destinations.contains(&key.destination) {
                    ready.push_back(key);
                    continue;
                }
                let Some(state) = states.get_mut(&key) else {
                    continue;
                };
                state.queued = false;
                let Some(work) = state.pending.take() else {
                    continue;
                };
                state.in_flight = true;
                state.in_flight_last_seq = Some(work.request.first_seq);
                in_flight_destinations.insert(key.destination);
                let transport = transport.clone();
                let repair_cache = repair_cache.clone();
                let voice_budget = voice_budget.clone();
                let transport_slots = transport_slots.clone();
                let ttl = Duration::from_millis(repair_deadline_transport_ttl_ms(
                    &cfg,
                    cfg.repair_transport_ttl_ms,
                ));
                let handle = jobs.spawn(async move {
                    let result = send_repair_response(
                        work,
                        transport,
                        repair_cache,
                        &voice_budget,
                        transport_slots,
                        ttl,
                    )
                    .await;
                    (key, result)
                });
                task_keys.insert(handle.id(), key);
            }

            if !rx_open && jobs.is_empty() && ready.is_empty() {
                return;
            }

            tokio::select! {
                _ = shutdown.cancelled() => return,
                result = jobs.join_next_with_id(), if !jobs.is_empty() => {
                    let completed = match result {
                        Some(Ok((task_id, completed))) => {
                            task_keys.remove(&task_id);
                            Some(completed)
                        }
                        Some(Err(error)) => {
                            let completed = task_keys.remove(&error.id()).map(|key| {
                                let completed_seq = states
                                    .get(&key)
                                    .and_then(|state| state.in_flight_last_seq)
                                    .unwrap_or(0);
                                (key, RepairResponseFrameResult {
                                    completed_seq,
                                    continuation: None,
                                })
                            });
                            trace!(%error, "voice repair: response job failed");
                            completed
                        }
                        None => None,
                    };
                    if let Some((key, result)) = completed
                        && let Some(state) = states.get_mut(&key)
                    {
                        in_flight_destinations.remove(&key.destination);
                        state.in_flight = false;
                        state.in_flight_last_seq.take();
                        state.cursor_floor = state
                            .cursor_floor
                            .max(result.completed_seq.saturating_add(1));
                        if let Some(mut continuation) = result.continuation {
                            if let Some(pending) = state.pending.take() {
                                continuation.request.first_seq = continuation
                                    .request
                                    .first_seq
                                    .min(pending.request.first_seq);
                                continuation.request.last_seq = continuation
                                    .request
                                    .last_seq
                                    .max(pending.request.last_seq);
                                continuation.deadline = continuation.deadline.min(pending.deadline);
                            }
                            continuation.request.first_seq = continuation
                                .request
                                .first_seq
                                .max(state.cursor_floor);
                            if continuation.request.first_seq <= continuation.request.last_seq {
                                state.pending = Some(continuation);
                            }
                        }
                        if state.pending.is_some() {
                            if !state.queued {
                                state.queued = true;
                                ready.push_back(key);
                            }
                        } else {
                            states.remove(&key);
                        }
                    }
                }
                work = rx.recv(), if rx_open => match work {
                    Some(mut work) => {
                        let key = RepairResponseKey::new(&work);
                        if let Some(state) = states.get_mut(&key) {
                            let requested_first = work.request.first_seq;
                            let floor = state.cursor_floor.max(
                                state
                                    .in_flight_last_seq
                                    .map(|last_seq| last_seq.saturating_add(1))
                                    .unwrap_or(0),
                            );
                            if requested_first < floor {
                                metrics::record_repair(
                                    source,
                                    key.destination,
                                    VoiceRepairResult::RequestSuppressed,
                                    1,
                                );
                            }
                            work.request.first_seq = requested_first.max(floor);
                            if work.request.first_seq > work.request.last_seq {
                                continue;
                            }
                            if let Some(pending) = state.pending.as_mut() {
                                pending.request.first_seq = pending
                                    .request
                                    .first_seq
                                    .min(work.request.first_seq)
                                    .max(floor);
                                pending.request.last_seq = pending
                                    .request
                                    .last_seq
                                    .max(work.request.last_seq);
                                pending.deadline = pending.deadline.min(work.deadline);
                            } else {
                                state.pending = Some(work);
                            }
                            if !state.in_flight && !state.queued {
                                state.queued = true;
                                ready.push_back(key);
                            }
                        } else if states.len() >= REPAIR_RESPONSE_MAX_STREAMS {
                            metrics::record_repair(
                                source,
                                key.destination,
                                VoiceRepairResult::RequestSuppressed,
                                1,
                            );
                        } else {
                            states.insert(
                                key,
                                RepairResponseState {
                                    cursor_floor: work.request.first_seq,
                                    pending: Some(work),
                                    queued: true,
                                    in_flight: false,
                                    in_flight_last_seq: None,
                                },
                            );
                            ready.push_back(key);
                        }
                    }
                    None => rx_open = false,
                },
            }
        }
    });
}

async fn send_repair_response(
    mut work: RepairResponseRequest,
    transport: Arc<dyn VoiceTransport>,
    repair_cache: Arc<RepairCache>,
    voice_budget: &AdaptiveVoiceBudget,
    transport_slots: Arc<Semaphore>,
    ttl: Duration,
) -> RepairResponseFrameResult {
    let source = transport.local_node_id();
    let completed_seq = work.request.first_seq;
    let continuation = (completed_seq < work.request.last_seq).then(|| {
        work.request.first_seq = completed_seq.saturating_add(1);
        work.clone()
    });
    if work.deadline <= Instant::now() {
        return RepairResponseFrameResult {
            completed_seq,
            continuation: None,
        };
    }
    let frames = repair_cache.lookup_range(
        work.request.sender_session,
        work.request.sender_epoch,
        completed_seq,
        completed_seq,
    );
    let Some(frame) = frames.into_iter().next() else {
        metrics::record_repair(source, work.from, VoiceRepairResult::FrameMissed, 1);
        return RepairResponseFrameResult {
            completed_seq,
            continuation,
        };
    };
    let destination = work.from;
    let repair_deadline = work.deadline;
    let avoid_first_hop = transport
        .voice_route_quality(destination)
        .filter(|quality| quality.transport() == TransportKind::Udp)
        .map(|quality| quality.next_hop());
    let body = frame.body().clone();
    let mut accepted = send_budgeted_repair_frame(
        transport.as_ref(),
        voice_budget,
        destination,
        body.clone(),
        avoid_first_hop,
        ttl,
        repair_deadline,
        false,
        transport_slots.as_ref(),
    )
    .await;
    if !accepted && avoid_first_hop.is_some() {
        accepted = send_budgeted_repair_frame(
            transport.as_ref(),
            voice_budget,
            destination,
            body.clone(),
            None,
            ttl,
            repair_deadline,
            true,
            transport_slots.as_ref(),
        )
        .await;
    }
    if !accepted {
        tokio::task::yield_now().await;
        accepted = send_budgeted_repair_frame(
            transport.as_ref(),
            voice_budget,
            destination,
            body,
            None,
            ttl,
            repair_deadline,
            true,
            transport_slots.as_ref(),
        )
        .await;
    }
    if !accepted {
        metrics::record_repair(source, destination, VoiceRepairResult::FrameSendFailed, 1);
    } else {
        metrics::record_repair(source, destination, VoiceRepairResult::FrameServed, 1);
    }
    RepairResponseFrameResult {
        completed_seq,
        continuation,
    }
}

async fn send_budgeted_repair_frame(
    transport: &dyn VoiceTransport,
    voice_budget: &AdaptiveVoiceBudget,
    destination: NodeIdentifier,
    body: Bytes,
    avoid_first_hop: Option<NodeIdentifier>,
    ttl: Duration,
    deadline: Instant,
    retry: bool,
    transport_slots: &Semaphore,
) -> bool {
    metrics::record_repair_destination_bytes(
        destination,
        RepairDestinationStage::Requested,
        body.len(),
    );
    let first_hop = transport
        .voice_route_quality(destination)
        .map(|quality| {
            if avoid_first_hop == Some(quality.next_hop()) {
                quality.alternate_next_hop().unwrap_or(quality.next_hop())
            } else {
                quality.next_hop()
            }
        })
        .unwrap_or(destination);
    let Some(credit_permit) = voice_budget
        .reserve_link_reactive_credit_scheduled(
            first_hop,
            u32::from(destination),
            body.len(),
            deadline,
            retry,
        )
        .await
    else {
        metrics::record_repair_destination_bytes(
            destination,
            RepairDestinationStage::Shed,
            body.len(),
        );
        publish_proactive_budget(voice_budget);
        return false;
    };
    let transport_slot =
        match tokio::time::timeout_at(deadline.into(), transport_slots.acquire()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) | Err(_) => {
                drop(credit_permit);
                publish_proactive_budget(voice_budget);
                return false;
            }
        };
    credit_permit.record_attempt();
    let result = match tokio::time::timeout_at(
        deadline.into(),
        transport.send_repair_frame(destination, body, avoid_first_hop, ttl),
    )
    .await
    {
        Ok(Ok(())) => {
            credit_permit.commit();
            publish_proactive_budget(voice_budget);
            true
        }
        Ok(Err(_)) | Err(_) => {
            drop(credit_permit);
            publish_proactive_budget(voice_budget);
            false
        }
    };
    drop(transport_slot);
    result
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use super::*;
    use tokio::sync::Semaphore;

    use crate::application::voice::send::{
        DistributionGroupKind,
        testing::{FakeCall, FakeVoiceTransport},
    };
    use crate::application::voice::sink::testing::RecordingSink;

    struct ControlledUnicastTransport {
        inner: Arc<FakeVoiceTransport>,
        primary_entered: Semaphore,
        primary_release: Semaphore,
        proactive_entered: Semaphore,
        proactive_release: Semaphore,
        fail_primary: bool,
    }

    impl ControlledUnicastTransport {
        fn new(fail_primary: bool) -> Arc<Self> {
            Arc::new(Self {
                inner: FakeVoiceTransport::new(7, vec![2, 3]),
                primary_entered: Semaphore::new(0),
                primary_release: Semaphore::new(0),
                proactive_entered: Semaphore::new(0),
                proactive_release: Semaphore::new(0),
                fail_primary,
            })
        }
    }

    #[async_trait::async_trait]
    impl VoiceTransport for ControlledUnicastTransport {
        async fn send_unicast(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner
                .calls
                .lock()
                .unwrap()
                .push(FakeCall::Unicast { dst, body, ttl });
            self.primary_entered.add_permits(1);
            self.primary_release
                .acquire()
                .await
                .expect("test release semaphore remains open")
                .forget();
            if self.fail_primary {
                Err(ApplicationError::Unavailable)
            } else {
                Ok(())
            }
        }

        async fn send_multicast(
            &self,
            dsts: &[NodeIdentifier],
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner.send_multicast(dsts, body, ttl).await
        }

        async fn send_broadcast(&self, body: Bytes, ttl: Duration) -> Result<(), ApplicationError> {
            self.inner.send_broadcast(body, ttl).await
        }

        async fn send_repair_request(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner.send_repair_request(dst, body, ttl).await
        }

        async fn send_repair_frame(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            avoid_first_hop: Option<NodeIdentifier>,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner
                .send_repair_frame(dst, body, avoid_first_hop, ttl)
                .await
        }

        async fn send_proactive_repair_frame(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            avoid_first_hop: Option<NodeIdentifier>,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            let result = self
                .inner
                .send_proactive_repair_frame(dst, body, avoid_first_hop, ttl)
                .await;
            self.proactive_entered.add_permits(1);
            self.proactive_release
                .acquire()
                .await
                .expect("test release semaphore remains open")
                .forget();
            result
        }

        fn alive_members(&self) -> Vec<NodeIdentifier> {
            self.inner.alive_members()
        }

        fn local_node_id(&self) -> NodeIdentifier {
            self.inner.local_node_id()
        }

        fn voice_route_quality(
            &self,
            dst: NodeIdentifier,
        ) -> Option<crate::overlay::VoiceRouteQuality> {
            self.inner.voice_route_quality(dst)
        }

        fn voice_route_qualities(
            &self,
            dsts: &[NodeIdentifier],
        ) -> Vec<Option<crate::overlay::VoiceRouteQuality>> {
            self.inner.voice_route_qualities(dsts)
        }
    }

    struct PressuredProactiveTransport {
        inner: Arc<FakeVoiceTransport>,
        proactive_attempts: AtomicU64,
    }

    impl PressuredProactiveTransport {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: FakeVoiceTransport::new(7, vec![2]),
                proactive_attempts: AtomicU64::new(0),
            })
        }
    }

    #[async_trait::async_trait]
    impl VoiceTransport for PressuredProactiveTransport {
        async fn send_unicast(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner.send_unicast(dst, body, ttl).await
        }

        async fn send_multicast(
            &self,
            dsts: &[NodeIdentifier],
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner.send_multicast(dsts, body, ttl).await
        }

        async fn send_broadcast(&self, body: Bytes, ttl: Duration) -> Result<(), ApplicationError> {
            self.inner.send_broadcast(body, ttl).await
        }

        async fn send_repair_request(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner.send_repair_request(dst, body, ttl).await
        }

        async fn send_repair_frame(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            avoid_first_hop: Option<NodeIdentifier>,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner
                .send_repair_frame(dst, body, avoid_first_hop, ttl)
                .await
        }

        async fn send_proactive_repair_frame(
            &self,
            dst: NodeIdentifier,
            _body: Bytes,
            _avoid_first_hop: Option<NodeIdentifier>,
            _ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.proactive_attempts.fetch_add(1, Ordering::SeqCst);
            Err(ApplicationError::Overlay(
                crate::overlay::OverlayError::Send(
                    shitspeak_s2s_transport::SendError::Backpressure {
                        node: dst,
                        transport: TransportKind::Kcp,
                    },
                ),
            ))
        }

        fn alive_members(&self) -> Vec<NodeIdentifier> {
            self.inner.alive_members()
        }

        fn local_node_id(&self) -> NodeIdentifier {
            self.inner.local_node_id()
        }

        fn voice_route_quality(
            &self,
            dst: NodeIdentifier,
        ) -> Option<crate::overlay::VoiceRouteQuality> {
            self.inner.voice_route_quality(dst)
        }
    }

    struct SelectivelyHungProactiveTransport {
        inner: Arc<FakeVoiceTransport>,
        hung_entered: Semaphore,
    }

    impl SelectivelyHungProactiveTransport {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: FakeVoiceTransport::new(7, vec![2, 3]),
                hung_entered: Semaphore::new(0),
            })
        }
    }

    #[async_trait::async_trait]
    impl VoiceTransport for SelectivelyHungProactiveTransport {
        async fn send_unicast(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner.send_unicast(dst, body, ttl).await
        }

        async fn send_multicast(
            &self,
            dsts: &[NodeIdentifier],
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner.send_multicast(dsts, body, ttl).await
        }

        async fn send_broadcast(&self, body: Bytes, ttl: Duration) -> Result<(), ApplicationError> {
            self.inner.send_broadcast(body, ttl).await
        }

        async fn send_repair_request(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner.send_repair_request(dst, body, ttl).await
        }

        async fn send_repair_frame(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            avoid_first_hop: Option<NodeIdentifier>,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner
                .send_repair_frame(dst, body, avoid_first_hop, ttl)
                .await
        }

        async fn send_proactive_repair_frame(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            avoid_first_hop: Option<NodeIdentifier>,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            if dst == 2 {
                self.hung_entered.add_permits(1);
                return std::future::pending().await;
            }
            self.inner
                .send_proactive_repair_frame(dst, body, avoid_first_hop, ttl)
                .await
        }

        fn alive_members(&self) -> Vec<NodeIdentifier> {
            self.inner.alive_members()
        }

        fn local_node_id(&self) -> NodeIdentifier {
            self.inner.local_node_id()
        }

        fn voice_route_quality(
            &self,
            _dst: NodeIdentifier,
        ) -> Option<crate::overlay::VoiceRouteQuality> {
            None
        }
    }

    struct ControlledRepairTransport {
        inner: Arc<FakeVoiceTransport>,
        repair_entered: Semaphore,
        repair_release: Semaphore,
        active_repairs: AtomicU64,
        max_active_repairs: AtomicU64,
        failures_remaining: AtomicU64,
    }

    impl ControlledRepairTransport {
        fn new() -> Arc<Self> {
            Self::with_failures(0)
        }

        fn with_failures(failures: u64) -> Arc<Self> {
            Arc::new(Self {
                inner: FakeVoiceTransport::new(7, vec![2, 3, 4]),
                repair_entered: Semaphore::new(0),
                repair_release: Semaphore::new(0),
                active_repairs: AtomicU64::new(0),
                max_active_repairs: AtomicU64::new(0),
                failures_remaining: AtomicU64::new(failures),
            })
        }
    }

    #[async_trait::async_trait]
    impl VoiceTransport for ControlledRepairTransport {
        async fn send_unicast(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner.send_unicast(dst, body, ttl).await
        }

        async fn send_multicast(
            &self,
            dsts: &[NodeIdentifier],
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner.send_multicast(dsts, body, ttl).await
        }

        async fn send_broadcast(&self, body: Bytes, ttl: Duration) -> Result<(), ApplicationError> {
            self.inner.send_broadcast(body, ttl).await
        }

        async fn send_repair_request(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner.send_repair_request(dst, body, ttl).await
        }

        async fn send_repair_frame(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            avoid_first_hop: Option<NodeIdentifier>,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            let active = self.active_repairs.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active_repairs.fetch_max(active, Ordering::SeqCst);
            let result = self
                .inner
                .send_repair_frame(dst, body, avoid_first_hop, ttl)
                .await;
            self.repair_entered.add_permits(1);
            self.repair_release
                .acquire()
                .await
                .expect("test release semaphore remains open")
                .forget();
            self.active_repairs.fetch_sub(1, Ordering::SeqCst);
            let fail = self
                .failures_remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok();
            if fail {
                Err(ApplicationError::Unavailable)
            } else {
                result
            }
        }

        async fn send_proactive_repair_frame(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            avoid_first_hop: Option<NodeIdentifier>,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner
                .send_proactive_repair_frame(dst, body, avoid_first_hop, ttl)
                .await
        }

        fn alive_members(&self) -> Vec<NodeIdentifier> {
            self.inner.alive_members()
        }

        fn local_node_id(&self) -> NodeIdentifier {
            self.inner.local_node_id()
        }

        fn voice_route_quality(
            &self,
            dst: NodeIdentifier,
        ) -> Option<crate::overlay::VoiceRouteQuality> {
            self.inner.voice_route_quality(dst)
        }
    }

    struct ControlledRepairRequestTransport {
        inner: Arc<FakeVoiceTransport>,
        request_entered: Semaphore,
        request_release: Semaphore,
        active_requests: AtomicU64,
        request_attempts: AtomicU64,
        failures_remaining: AtomicU64,
        block_requests: bool,
    }

    struct ActiveRequestGuard<'a>(&'a AtomicU64);

    impl Drop for ActiveRequestGuard<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl ControlledRepairRequestTransport {
        fn new() -> Arc<Self> {
            Self::new_inner(0, true)
        }

        fn with_failures(failures: u64) -> Arc<Self> {
            Self::new_inner(failures, false)
        }

        fn new_inner(failures: u64, block_requests: bool) -> Arc<Self> {
            Arc::new(Self {
                inner: FakeVoiceTransport::new(7, vec![12]),
                request_entered: Semaphore::new(0),
                request_release: Semaphore::new(0),
                active_requests: AtomicU64::new(0),
                request_attempts: AtomicU64::new(0),
                failures_remaining: AtomicU64::new(failures),
                block_requests,
            })
        }
    }

    #[async_trait::async_trait]
    impl VoiceTransport for ControlledRepairRequestTransport {
        async fn send_unicast(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner.send_unicast(dst, body, ttl).await
        }

        async fn send_multicast(
            &self,
            dsts: &[NodeIdentifier],
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner.send_multicast(dsts, body, ttl).await
        }

        async fn send_broadcast(&self, body: Bytes, ttl: Duration) -> Result<(), ApplicationError> {
            self.inner.send_broadcast(body, ttl).await
        }

        async fn send_repair_request(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.request_attempts.fetch_add(1, Ordering::SeqCst);
            self.active_requests.fetch_add(1, Ordering::SeqCst);
            let _active = ActiveRequestGuard(&self.active_requests);
            self.request_entered.add_permits(1);
            if self.block_requests {
                self.request_release
                    .acquire()
                    .await
                    .expect("test release semaphore remains open")
                    .forget();
            }
            if self
                .failures_remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                return Err(ApplicationError::Unavailable);
            }
            self.inner.send_repair_request(dst, body, ttl).await
        }

        async fn send_repair_frame(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            avoid_first_hop: Option<NodeIdentifier>,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner
                .send_repair_frame(dst, body, avoid_first_hop, ttl)
                .await
        }

        async fn send_proactive_repair_frame(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            avoid_first_hop: Option<NodeIdentifier>,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner
                .send_proactive_repair_frame(dst, body, avoid_first_hop, ttl)
                .await
        }

        fn alive_members(&self) -> Vec<NodeIdentifier> {
            self.inner.alive_members()
        }

        fn local_node_id(&self) -> NodeIdentifier {
            self.inner.local_node_id()
        }

        fn voice_route_quality(
            &self,
            dst: NodeIdentifier,
        ) -> Option<crate::overlay::VoiceRouteQuality> {
            self.inner.voice_route_quality(dst)
        }
    }

    struct AlternateFailRepairTransport {
        inner: Arc<FakeVoiceTransport>,
    }

    #[async_trait::async_trait]
    impl VoiceTransport for AlternateFailRepairTransport {
        async fn send_unicast(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner.send_unicast(dst, body, ttl).await
        }

        async fn send_multicast(
            &self,
            dsts: &[NodeIdentifier],
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner.send_multicast(dsts, body, ttl).await
        }

        async fn send_broadcast(&self, body: Bytes, ttl: Duration) -> Result<(), ApplicationError> {
            self.inner.send_broadcast(body, ttl).await
        }

        async fn send_repair_request(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner.send_repair_request(dst, body, ttl).await
        }

        async fn send_repair_frame(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            avoid_first_hop: Option<NodeIdentifier>,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            if avoid_first_hop.is_some() {
                return Err(ApplicationError::Unavailable);
            }
            self.inner
                .send_repair_frame(dst, body, avoid_first_hop, ttl)
                .await
        }

        async fn send_proactive_repair_frame(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
            avoid_first_hop: Option<NodeIdentifier>,
            ttl: Duration,
        ) -> Result<(), ApplicationError> {
            self.inner
                .send_proactive_repair_frame(dst, body, avoid_first_hop, ttl)
                .await
        }

        fn alive_members(&self) -> Vec<NodeIdentifier> {
            self.inner.alive_members()
        }

        fn local_node_id(&self) -> NodeIdentifier {
            self.inner.local_node_id()
        }

        fn voice_route_quality(
            &self,
            dst: NodeIdentifier,
        ) -> Option<crate::overlay::VoiceRouteQuality> {
            self.inner.voice_route_quality(dst)
        }
    }

    fn make_legacy_service(transport: Arc<FakeVoiceTransport>) -> Arc<VoiceService> {
        let mut cfg = VoiceConfig::default();
        cfg.tree_delivery_enabled = false;
        VoiceService::new_with_transport(transport, cfg, CancellationToken::new(), 42)
    }

    fn make_default_tree_service(transport: Arc<FakeVoiceTransport>) -> Arc<VoiceService> {
        VoiceService::new_with_transport(
            transport,
            VoiceConfig::default(),
            CancellationToken::new(),
            42,
        )
    }

    #[derive(Default)]
    struct RepairProbeSink {
        repairs: Mutex<Vec<bool>>,
    }

    impl RepairProbeSink {
        fn snapshot(&self) -> Vec<bool> {
            self.repairs.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl AudioSink for RepairProbeSink {
        async fn deliver(
            &self,
            _from_immediate: NodeIdentifier,
            _frame: VoiceFrame,
            is_repair: bool,
        ) {
            self.repairs.lock().unwrap().push(is_repair);
        }
    }

    #[test]
    fn path_feedback_accumulator_reports_held_delay_and_resets() {
        let acc = PathFeedbackAccumulator::default();
        // Push and deadline events accumulate per window; the held delay is a
        // separate record that maxes into the window.
        assert!(acc.record(22, VoiceReceiveResult::GapBuffered, 3).is_none());
        assert!(acc.record(22, VoiceReceiveResult::DeadlineFlush, 2).is_none());
        assert!(acc.record_held_delay(22, 123_456).is_none());
        std::thread::sleep(PATH_FEEDBACK_INTERVAL + Duration::from_millis(20));
        // The triggering event's counts join the window being flushed: 3 gap +
        // 2 flush (pre-sleep) + 1 flush (the trigger itself).
        let feedback = acc
            .record(22, VoiceReceiveResult::DeadlineFlush, 1)
            .expect("window elapsed; feedback flushed");
        assert_eq!(feedback.received_frames, 6);
        assert_eq!(feedback.gap_buffered, 3);
        assert_eq!(feedback.deadline_flush, 3);
        assert_eq!(feedback.max_held_delay_us, 123_456);
        // The window reset: further records stay buffered until it elapses.
        assert!(acc.record(22, VoiceReceiveResult::DeadlineFlush, 1).is_none());
        // A second peer's window is independent.
        assert!(acc.record_held_delay(33, 999).is_none());
        std::thread::sleep(PATH_FEEDBACK_INTERVAL + Duration::from_millis(20));
        let feedback = acc
            .record_held_delay(33, 456_789)
            .expect("other peer's window elapsed");
        assert_eq!(feedback.received_frames, 0);
        assert_eq!(feedback.max_held_delay_us, 456_789);
    }

    #[tokio::test]
    async fn broadcast_emits_envelope_and_advances_seq() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_legacy_service(transport.clone());

        let payload = Bytes::from_static(b"opus-1");
        svc.send_broadcast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            false,
            payload.clone(),
            normal_intent(5),
        )
        .await
        .unwrap();
        svc.send_broadcast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            true,
            Bytes::from_static(b"opus-2"),
            normal_intent(5),
        )
        .await
        .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 2);
        let first = match &calls[0] {
            FakeCall::Multicast { dsts, body, ttl } => {
                assert_eq!(dsts.as_slice(), &[1, 2, 3]);
                assert_eq!(*ttl, VoiceConfig::default().transport_ttl());
                proto::decode_voice(body.as_ref()).unwrap()
            }
            other => panic!("expected Multicast, got {other:?}"),
        };
        let second = match &calls[1] {
            FakeCall::Multicast { dsts, body, ttl } => {
                assert_eq!(dsts.as_slice(), &[1, 2, 3]);
                assert_eq!(*ttl, VoiceConfig::default().transport_ttl());
                proto::decode_voice(body.as_ref()).unwrap()
            }
            other => panic!("expected Multicast, got {other:?}"),
        };
        assert_eq!(first.sender_session, 0xABC);
        assert_eq!(first.sender_epoch, 42);
        assert_eq!(first.s2s_seq, 0);
        assert_eq!(first.payload, b"opus-1".as_ref());
        assert!(!first.is_terminator);
        assert_eq!(second.s2s_seq, 1);
        assert_eq!(second.payload, b"opus-2".as_ref());
        assert!(second.is_terminator);
    }

    #[tokio::test]
    async fn default_tree_delivery_routes_broadcast_and_explicit_groups() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_default_tree_service(transport.clone());

        svc.send_broadcast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            false,
            Bytes::from_static(b"broadcast"),
            normal_intent(5),
        )
        .await
        .unwrap();
        svc.send_multicast(
            0xABC,
            shitspeak_core::default_server_id(),
            2,
            false,
            Bytes::from_static(b"explicit"),
            normal_intent(5),
            &[1, 3],
        )
        .await
        .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 2);
        match &calls[0] {
            FakeCall::TreeMulticast {
                dsts,
                group,
                body,
                ttl,
            } => {
                assert_eq!(dsts.as_slice(), &[1, 2, 3]);
                assert_eq!(*group, DistributionGroup::broadcast());
                assert_eq!(*ttl, VoiceConfig::default().transport_ttl());
                assert_eq!(
                    proto::decode_voice(body.as_ref()).unwrap().payload.as_ref(),
                    b"broadcast"
                );
            }
            other => panic!("expected TreeMulticast, got {other:?}"),
        }
        match &calls[1] {
            FakeCall::TreeMulticast {
                dsts,
                group,
                body,
                ttl,
            } => {
                assert_eq!(dsts.as_slice(), &[1, 3]);
                assert_eq!(group.kind(), DistributionGroupKind::RecipientSnapshot);
                assert_eq!(group.id(), group.version());
                assert_eq!(*ttl, VoiceConfig::default().transport_ttl());
                assert_eq!(
                    proto::decode_voice(body.as_ref()).unwrap().payload.as_ref(),
                    b"explicit"
                );
            }
            other => panic!("expected TreeMulticast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn broadcast_uses_voice_members_not_all_alive_members() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3, 4]);
        transport.set_voice_members(vec![2, 4, 7]);
        let svc = make_legacy_service(transport.clone());

        svc.send_broadcast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            false,
            Bytes::from_static(b"x"),
            normal_intent(5),
        )
        .await
        .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            FakeCall::Multicast { dsts, .. } => assert_eq!(dsts.as_slice(), &[2, 4]),
            other => panic!("expected Multicast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn multicast_skips_when_dsts_empty() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_legacy_service(transport.clone());
        svc.send_multicast(
            0xABC,
            shitspeak_core::default_server_id(),
            2,
            false,
            Bytes::from_static(b"x"),
            normal_intent(5),
            &[],
        )
        .await
        .unwrap();
        assert!(transport.calls().is_empty());
    }

    #[tokio::test]
    async fn multicast_emits_envelope_with_dsts() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_legacy_service(transport.clone());
        svc.send_multicast(
            0xABC,
            shitspeak_core::default_server_id(),
            2,
            false,
            Bytes::from_static(b"whisper"),
            normal_intent(5),
            &[1, 3],
        )
        .await
        .unwrap();
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            FakeCall::Multicast { dsts, body, ttl } => {
                assert_eq!(dsts.as_slice(), &[1, 3]);
                assert_eq!(*ttl, VoiceConfig::default().transport_ttl());
                let f = proto::decode_voice(body.as_ref()).unwrap();
                assert_eq!(f.target_kind, 2);
                assert_eq!(f.payload, b"whisper".as_ref());
            }
            other => panic!("expected Multicast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unicast_emits_to_single_dst() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_legacy_service(transport.clone());
        svc.send_unicast(
            0xABC,
            shitspeak_core::default_server_id(),
            2,
            true,
            Bytes::from_static(b"end"),
            normal_intent(5),
            5,
        )
        .await
        .unwrap();
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            FakeCall::Unicast { dst, body, ttl } => {
                assert_eq!(*dst, 5);
                assert_eq!(*ttl, VoiceConfig::default().transport_ttl());
                let f = proto::decode_voice(body.as_ref()).unwrap();
                assert!(f.is_terminator);
            }
            other => panic!("expected Unicast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn normal_sends_use_configured_transport_ttl() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let mut cfg = VoiceConfig::default();
        cfg.tree_delivery_enabled = false;
        cfg.set_transport_ttl_ms(180);
        let svc =
            VoiceService::new_with_transport(transport.clone(), cfg, CancellationToken::new(), 42);

        svc.send_multicast(
            0xABC,
            shitspeak_core::default_server_id(),
            2,
            false,
            Bytes::from_static(b"ttl"),
            normal_intent(5),
            &[1, 3],
        )
        .await
        .unwrap();
        svc.send_unicast(
            0xABC,
            shitspeak_core::default_server_id(),
            2,
            false,
            Bytes::from_static(b"ttl"),
            normal_intent(5),
            3,
        )
        .await
        .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 2);
        for call in calls {
            let ttl = match call {
                FakeCall::Multicast { ttl, .. } | FakeCall::Unicast { ttl, .. } => ttl,
                other => panic!("expected normal voice send, got {other:?}"),
            };
            assert_eq!(ttl, Duration::from_millis(180));
        }
    }

    #[tokio::test]
    async fn contiguous_terminator_sends_tail_ack_after_sink_delivery() {
        let transport = FakeVoiceTransport::new(7, vec![2]);
        let svc = make_legacy_service(transport.clone());
        let sink = RecordingSink::new();
        svc.set_audio_sink(sink.clone());
        let sender_session = shitspeak_core::ClientSessionIdentifier::new(7, 0xABC)
            .unwrap()
            .to_u32();
        let body = send::build_envelope(
            sender_session,
            shitspeak_core::default_server_id(),
            42,
            17,
            0,
            true,
            Bytes::from_static(b"tail"),
            normal_intent(5),
        )
        .unwrap();

        svc.inbound_handler().handle(OverlayInboundMessage {
            from: 2,
            origin_boot_epoch: 0,
            level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body,
            remote_playout_delay_ms: None,
            is_distribution_repair: false,
        });

        for _ in 0..100 {
            if sink.len() == 1 && transport.calls().len() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(sink.len(), 1);
        let calls = wait_for_call_count(&transport, 1).await;
        match &calls[0] {
            FakeCall::RepairRequest { dst, body, .. } => {
                assert_eq!(*dst, 7);
                let ack = proto::decode_voice_repair_request(body).unwrap();
                assert!(ack.tail_ack);
                assert_eq!(ack.sender_session, sender_session);
                assert_eq!(ack.sender_epoch, 42);
                assert_eq!(ack.first_seq, 17);
                assert_eq!(ack.last_seq, 17);
            }
            other => panic!("expected tail acknowledgement, got {other:?}"),
        }
    }

    #[test]
    fn tail_retry_delay_uses_fallback_without_route_quality() {
        assert_eq!(
            tail_repair_initial_delay(&VoiceConfig::default(), None),
            TAIL_REPAIR_INITIAL_DELAY,
        );
    }

    #[test]
    fn tail_retry_delay_covers_route_round_trip_and_quality_margin() {
        let quality = VoiceRouteQuality::new(2, TransportKind::Tcp, 90_001, 20_999, 10_001);

        assert_eq!(
            tail_repair_initial_delay(&VoiceConfig::default(), Some(quality)),
            Duration::from_millis(255),
        );
    }

    #[test]
    fn tail_retry_delay_leaves_one_worker_interval_before_cache_expiry() {
        let quality = VoiceRouteQuality::new(2, TransportKind::Tcp, 1_000_000, 1_000_000, 100_000);
        assert_eq!(
            tail_repair_initial_delay(&VoiceConfig::default(), Some(quality)),
            Duration::from_millis(1_500),
        );

        let mut short_cache = VoiceConfig::default();
        short_cache.repair_cache_ms = 1;
        assert_eq!(
            tail_repair_initial_delay(&short_cache, Some(quality)),
            Duration::from_millis(150),
        );
    }

    #[tokio::test]
    async fn terminal_repairs_use_destination_specific_route_delay() {
        let transport = FakeVoiceTransport::new(7, vec![2, 3]);
        transport.set_voice_route_quality(
            2,
            VoiceRouteQuality::new(2, TransportKind::Tcp, 1_000, 0, 0),
        );
        transport.set_voice_route_quality(
            3,
            VoiceRouteQuality::new(3, TransportKind::Tcp, 237_000, 0, 0),
        );
        let svc = VoiceService::new_with_transport(
            transport.clone(),
            VoiceConfig::default(),
            CancellationToken::new(),
            42,
        );

        let destinations = [2, 3];
        let context = svc
            .capture_repair_frame_context(&destinations)
            .expect("repair context capture");
        svc.register_terminal_repairs(
            0xABC,
            0,
            Bytes::from_static(b"terminal"),
            true,
            &destinations,
            Some(&context),
        );

        let repairs = svc.tail_repairs.lock();
        let retry_for = |destination| {
            repairs
                .iter()
                .find_map(|(key, entry)| {
                    (key.destination == destination).then_some(entry.next_retry)
                })
                .expect("destination tail repair")
        };
        assert_eq!(
            retry_for(3).duration_since(retry_for(2)),
            Duration::from_millis(444),
        );
        assert_eq!(transport.route_quality_batches(), vec![vec![2, 3]]);
        assert_eq!(transport.route_quality_scalar_calls(), 0);
    }

    #[tokio::test]
    async fn tail_retry_stops_when_destination_acknowledges() {
        let transport = FakeVoiceTransport::new(7, vec![2]);
        let mut cfg = VoiceConfig::default();
        cfg.repair_cache_ms = 1;
        let svc =
            VoiceService::new_with_transport(transport.clone(), cfg, CancellationToken::new(), 42);
        svc.send_unicast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            true,
            Bytes::from_static(b"tail"),
            normal_intent(5),
            2,
        )
        .await
        .unwrap();
        // The tail dispatch reserves from the per-first-hop link bucket for
        // the destination carrying the terminal frame.
        svc.voice_budget.mint_link_credit(2, 0xABC, 42, usize::MAX);
        let mut calls = transport.calls();
        for _ in 0..60 {
            if calls.len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
            calls = transport.calls();
        }
        assert!(matches!(
            calls.get(1),
            Some(FakeCall::RepairFrame {
                dst: 2,
                is_repair: false,
                body,
                ..
            }) if proto::decode_voice(body).unwrap().proactive_copy
        ));

        let ack = VoiceRepairRequest {
            sender_session: 0xABC,
            sender_epoch: 42,
            first_seq: 0,
            last_seq: 0,
            request_sent_unix_ms: 0,
            request_ttl_ms: 0,
            tail_ack: true,
        };
        svc.repair_inbound_handler().handle(OverlayInboundMessage {
            from: 2,
            origin_boot_epoch: 0,
            level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body: proto::encode_voice_repair_request(&ack).unwrap(),
            remote_playout_delay_ms: None,
            is_distribution_repair: false,
        });
        assert!(svc.tail_repairs.lock().is_empty());

        tokio::time::sleep(TAIL_REPAIR_INTERVAL + Duration::from_millis(30)).await;
        assert_eq!(transport.calls().len(), 2);
    }

    fn cache_single_tail_frame(repair_cache: &RepairCache, sender_session: u32, sender_epoch: u64) {
        let body = send::build_envelope(
            sender_session,
            shitspeak_core::default_server_id(),
            sender_epoch,
            0,
            0,
            true,
            Bytes::from_static(b"tail"),
            normal_intent(5),
        )
        .unwrap();
        repair_cache.insert(RepairFrame::new(sender_session, sender_epoch, 0, body));
    }

    fn due_tail_key(
        repairs: &TailRepairState,
        destination: NodeIdentifier,
        sender_session: u32,
        sender_epoch: u64,
        now: Instant,
    ) -> TailRepairKey {
        let key = TailRepairKey {
            destination,
            sender_session,
            sender_epoch,
            terminal_seq: 0,
        };
        repairs.lock().insert(
            key,
            TailRepairEntry {
                attempts: 0,
                next_retry: now,
                expires_at: now + Duration::from_secs(10),
                cancel: CancellationToken::new(),
            },
        );
        key
    }

    fn funded_repair_budget(first_hops: &[NodeIdentifier]) -> AdaptiveVoiceBudget {
        let budget = AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(5_000)));
        for &first_hop in first_hops {
            budget.mint_link_credit(first_hop, 0, 0, usize::MAX);
        }
        budget
    }

    #[tokio::test]
    async fn tail_repairs_charge_full_reactive_credit() {
        let transport = FakeVoiceTransport::new(7, vec![2]);
        let repairs: TailRepairState = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let repair_cache = RepairCache::new(Duration::from_secs(10));
        cache_single_tail_frame(&repair_cache, 0xABB, 42);
        let now = Instant::now();
        let key = due_tail_key(&repairs, 2, 0xABB, 42, now);
        let voice_budget = AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(5_000)));
        let pressure = ProactivePressureState::default();
        let cached = repair_cache.lookup_range(0xABB, 42, 0, 0);
        let marked_body = send::mark_proactive_copy(cached[0].body()).unwrap();
        let cfg = VoiceConfig::default();
        let dispatch = dispatch_due_tail_repairs(
            &repairs,
            transport.as_ref(),
            &repair_cache,
            &cfg,
            &voice_budget,
            &pressure,
            now,
        );
        let mut funded_link_balance = 0usize;
        let fund = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert!(transport.calls().is_empty());
            // Tail dispatch reserves from the per-link bucket for the first
            // hop that accepted the original. Fund it to capacity so the
            // reactive reservation is admitted, then capture the funded
            // balance to measure the frame charge below.
            voice_budget.mint_link_credit(2, 0xABB, 42, usize::MAX);
            funded_link_balance = voice_budget.link_credit_balance_quarters(2);
        };
        tokio::join!(dispatch, fund);
        assert_eq!(transport.calls().len(), 1);
        assert_eq!(voice_budget.proactive_reserved_bytes(), 0);
        // A committed tail repair charges the full reactive credit for the
        // marked frame body (one byte = four quarter credits) on the link
        // bucket the original flowed through.
        assert_eq!(
            funded_link_balance.saturating_sub(voice_budget.link_credit_balance_quarters(2)),
            marked_body.len() * 4,
            "tail repair should charge full reactive credit on the per-link bucket"
        );
        assert!(repairs.lock()[&key].attempts > 0);
    }

    #[tokio::test]
    async fn tail_removal_cancels_credit_wait_without_sending_or_charging() {
        let transport = FakeVoiceTransport::new(7, vec![2]);
        let repairs: TailRepairState = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let repair_cache = RepairCache::new(Duration::from_secs(10));
        cache_single_tail_frame(&repair_cache, 0xABC, 42);
        let now = Instant::now();
        let key = due_tail_key(&repairs, 2, 0xABC, 42, now);
        let voice_budget = AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(5_000)));
        let pressure = ProactivePressureState::default();
        let cfg = VoiceConfig::default();
        let dispatch = dispatch_due_tail_repairs(
            &repairs,
            transport.as_ref(),
            &repair_cache,
            &cfg,
            &voice_budget,
            &pressure,
            now,
        );
        let acknowledge = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let entry = repairs.lock().remove(&key).expect("pending tail repair");
            entry.cancel.cancel();
        };
        tokio::time::timeout(Duration::from_millis(250), async {
            tokio::join!(dispatch, acknowledge);
        })
        .await
        .expect("tail cancellation must wake the credit wait");
        assert!(transport.calls().is_empty());
        assert_eq!(voice_budget.proactive_credit_balance_quarters(), 0);
        assert_eq!(voice_budget.proactive_reserved_bytes(), 0);
    }

    #[tokio::test]
    async fn tail_removal_cancels_transport_wait_and_refunds_tentative_credit() {
        let transport = ControlledUnicastTransport::new(false);
        let repairs: TailRepairState = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let repair_cache = RepairCache::new(Duration::from_secs(10));
        cache_single_tail_frame(&repair_cache, 0xABC, 42);
        let now = Instant::now();
        let key = due_tail_key(&repairs, 2, 0xABC, 42, now);
        let voice_budget = funded_repair_budget(&[2]);
        let starting_credit = voice_budget.link_credit_balance_quarters(2);
        let pressure = ProactivePressureState::default();
        let cfg = VoiceConfig::default();
        let dispatch = dispatch_due_tail_repairs(
            &repairs,
            transport.as_ref(),
            &repair_cache,
            &cfg,
            &voice_budget,
            &pressure,
            now,
        );
        let acknowledge = async {
            transport
                .proactive_entered
                .acquire()
                .await
                .expect("tail transport attempt should start")
                .forget();
            let entry = repairs.lock().remove(&key).expect("pending tail repair");
            entry.cancel.cancel();
        };
        tokio::time::timeout(Duration::from_millis(250), async {
            tokio::join!(dispatch, acknowledge);
        })
        .await
        .expect("tail cancellation must wake the transport wait");
        assert_eq!(
            voice_budget.link_credit_balance_quarters(2),
            starting_credit
        );
        assert_eq!(voice_budget.proactive_reserved_bytes(), 0);
    }

    #[tokio::test]
    async fn tail_backpressure_stops_the_suffix_and_exponentially_backs_off() {
        let transport = PressuredProactiveTransport::new();
        let repairs: TailRepairState = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let repair_cache = RepairCache::new(Duration::from_secs(10));
        let sender_epoch = 42;
        let sender_sessions = [0xABC, 0xABD];
        for sender_session in sender_sessions {
            for sequence in 0..TAIL_REPAIR_SUFFIX_FRAMES {
                let body = send::build_envelope(
                    sender_session,
                    shitspeak_core::default_server_id(),
                    sender_epoch,
                    sequence,
                    0,
                    sequence + 1 == TAIL_REPAIR_SUFFIX_FRAMES,
                    Bytes::from_static(b"tail"),
                    normal_intent(5),
                )
                .unwrap();
                repair_cache.insert(RepairFrame::new(
                    sender_session,
                    sender_epoch,
                    sequence,
                    body,
                ));
            }
        }

        let now = Instant::now();
        let keys = sender_sessions.map(|sender_session| TailRepairKey {
            destination: 2,
            sender_session,
            sender_epoch,
            terminal_seq: TAIL_REPAIR_SUFFIX_FRAMES - 1,
        });
        for key in keys {
            repairs.lock().insert(
                key,
                TailRepairEntry {
                    attempts: 0,
                    next_retry: now,
                    expires_at: now + Duration::from_secs(10),
                    cancel: CancellationToken::new(),
                },
            );
        }
        let cfg = VoiceConfig::default();
        let voice_budget = funded_repair_budget(&[2]);
        let pressure = ProactivePressureState::default();

        dispatch_due_tail_repairs(
            &repairs,
            transport.as_ref(),
            &repair_cache,
            &cfg,
            &voice_budget,
            &pressure,
            now,
        )
        .await;
        assert_eq!(
            transport.proactive_attempts.load(Ordering::SeqCst),
            1,
            "one full destination must stop the suffix and coalesce other tails"
        );
        let first_blocked_until = pressure
            .blocked_until(2, now)
            .expect("failed tail should install destination cooldown");
        assert!(
            repairs
                .lock()
                .values()
                .all(|entry| entry.next_retry >= first_blocked_until)
        );

        dispatch_due_tail_repairs(
            &repairs,
            transport.as_ref(),
            &repair_cache,
            &cfg,
            &voice_budget,
            &pressure,
            first_blocked_until - Duration::from_nanos(1),
        )
        .await;
        assert_eq!(transport.proactive_attempts.load(Ordering::SeqCst), 1);

        let second_attempt = first_blocked_until;
        dispatch_due_tail_repairs(
            &repairs,
            transport.as_ref(),
            &repair_cache,
            &cfg,
            &voice_budget,
            &pressure,
            second_attempt,
        )
        .await;
        assert_eq!(transport.proactive_attempts.load(Ordering::SeqCst), 2);
        assert!(
            repairs
                .lock()
                .values()
                .all(|entry| entry.next_retry > second_attempt)
        );
        assert_eq!(pressure.destinations.lock()[&2].consecutive_failures, 2);
    }

    #[tokio::test]
    async fn accepted_tail_without_ack_exponentially_backs_off() {
        let transport = FakeVoiceTransport::new(7, vec![2]);
        let repairs: TailRepairState = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let repair_cache = RepairCache::new(Duration::from_secs(10));
        let sender_session = 0xABC;
        let sender_epoch = 42;
        let body = send::build_envelope(
            sender_session,
            shitspeak_core::default_server_id(),
            sender_epoch,
            0,
            0,
            true,
            Bytes::from_static(b"tail"),
            normal_intent(5),
        )
        .unwrap();
        repair_cache.insert(RepairFrame::new(sender_session, sender_epoch, 0, body));

        let now = Instant::now();
        let key = TailRepairKey {
            destination: 2,
            sender_session,
            sender_epoch,
            terminal_seq: 0,
        };
        repairs.lock().insert(
            key,
            TailRepairEntry {
                attempts: 0,
                next_retry: now,
                expires_at: now + Duration::from_secs(10),
                cancel: CancellationToken::new(),
            },
        );
        let cfg = VoiceConfig::default();
        let voice_budget = funded_repair_budget(&[2]);
        let pressure = ProactivePressureState::default();

        dispatch_due_tail_repairs(
            &repairs,
            transport.as_ref(),
            &repair_cache,
            &cfg,
            &voice_budget,
            &pressure,
            now,
        )
        .await;
        assert_eq!(transport.calls().len(), 1);

        let second_attempt = repairs.lock()[&key].next_retry;
        dispatch_due_tail_repairs(
            &repairs,
            transport.as_ref(),
            &repair_cache,
            &cfg,
            &voice_budget,
            &pressure,
            second_attempt,
        )
        .await;
        assert_eq!(transport.calls().len(), 2);

        // A successful enqueue without an ACK is not proof of delivery. The
        // old fixed cadence would send a third copy here; the regression fix
        // waits twice as long after the second unacknowledged attempt.
        let third_attempt = repairs.lock()[&key].next_retry;
        assert!(third_attempt >= second_attempt + TAIL_REPAIR_INTERVAL.saturating_mul(2));
        dispatch_due_tail_repairs(
            &repairs,
            transport.as_ref(),
            &repair_cache,
            &cfg,
            &voice_budget,
            &pressure,
            third_attempt - Duration::from_nanos(1),
        )
        .await;
        assert_eq!(transport.calls().len(), 2);
        assert_eq!(repairs.lock()[&key].next_retry, third_attempt);
    }

    #[tokio::test]
    async fn accepted_unacked_tails_do_not_block_other_utterances() {
        let transport = FakeVoiceTransport::new(7, vec![2]);
        let repairs: TailRepairState = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let repair_cache = RepairCache::new(Duration::from_secs(10));
        let now = Instant::now();
        for sender_session in [0xAC1, 0xAC2] {
            cache_single_tail_frame(&repair_cache, sender_session, 42);
            due_tail_key(&repairs, 2, sender_session, 42, now);
        }
        let voice_budget = funded_repair_budget(&[2]);
        let pressure = ProactivePressureState::default();

        dispatch_due_tail_repairs(
            &repairs,
            transport.as_ref(),
            &repair_cache,
            &VoiceConfig::default(),
            &voice_budget,
            &pressure,
            now,
        )
        .await;

        assert_eq!(transport.calls().len(), 2);
        assert!(repairs.lock().values().all(|entry| entry.attempts == 1));
        assert!(!pressure.is_blocked(2, Instant::now()));
    }

    #[tokio::test]
    async fn tail_retry_delay_starts_after_a_slow_enqueue_finishes() {
        let transport = ControlledUnicastTransport::new(false);
        let repairs: TailRepairState = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let repair_cache = Arc::new(RepairCache::new(Duration::from_secs(10)));
        let voice_budget = funded_repair_budget(&[2]);
        let pressure = Arc::new(ProactivePressureState::default());
        let sender_session = 0xAC0;
        let sender_epoch = 42;
        cache_single_tail_frame(&repair_cache, sender_session, sender_epoch);
        let batch_started_at = Instant::now();
        let key = due_tail_key(&repairs, 2, sender_session, sender_epoch, batch_started_at);

        let task = tokio::spawn({
            let repairs = repairs.clone();
            let transport = transport.clone();
            let repair_cache = repair_cache.clone();
            let voice_budget = voice_budget.clone();
            let pressure = pressure.clone();
            async move {
                dispatch_due_tail_repairs(
                    &repairs,
                    transport.as_ref(),
                    &repair_cache,
                    &VoiceConfig::default(),
                    &voice_budget,
                    &pressure,
                    batch_started_at,
                )
                .await;
            }
        });
        tokio::time::timeout(
            Duration::from_secs(1),
            transport.proactive_entered.acquire(),
        )
        .await
        .expect("tail send should enter the controlled transport")
        .unwrap()
        .forget();
        let released_at = Instant::now();
        transport.proactive_release.add_permits(1);
        task.await.expect("tail dispatcher should finish");

        assert!(
            repairs.lock()[&key].next_retry >= released_at + TAIL_REPAIR_INTERVAL,
            "transport wait time must not consume the retry backoff"
        );
    }

    #[tokio::test]
    async fn hung_tail_destination_times_out_before_another_destination_dispatches() {
        let transport = SelectivelyHungProactiveTransport::new();
        let repairs: TailRepairState = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let repair_cache = RepairCache::new(Duration::from_secs(10));
        let voice_budget = funded_repair_budget(&[2, 3]);
        let pressure = ProactivePressureState::default();
        let sender_epoch = 42;
        let now = Instant::now();
        cache_single_tail_frame(&repair_cache, 0xAC3, sender_epoch);
        due_tail_key(&repairs, 2, 0xAC3, sender_epoch, now);
        let mut cfg = VoiceConfig::default();
        cfg.repair_transport_ttl_ms = 10;

        tokio::time::timeout(
            Duration::from_millis(200),
            dispatch_due_tail_repairs(
                &repairs,
                transport.as_ref(),
                &repair_cache,
                &cfg,
                &voice_budget,
                &pressure,
                now,
            ),
        )
        .await
        .expect("hung transport must be bounded by the enqueue timeout");
        assert_eq!(transport.hung_entered.available_permits(), 1);

        let next_batch = Instant::now();
        cache_single_tail_frame(&repair_cache, 0xAC4, sender_epoch);
        due_tail_key(&repairs, 3, 0xAC4, sender_epoch, next_batch);
        dispatch_due_tail_repairs(
            &repairs,
            transport.as_ref(),
            &repair_cache,
            &cfg,
            &voice_budget,
            &pressure,
            next_batch,
        )
        .await;

        assert!(
            transport
                .inner
                .calls()
                .iter()
                .any(|call| matches!(call, FakeCall::RepairFrame { dst: 3, .. }))
        );
    }

    fn make_service_with_strategy(
        transport: Arc<FakeVoiceTransport>,
        strategy: &str,
    ) -> Arc<VoiceService> {
        make_service_with_strategy_and_tree_delivery(transport, strategy, false)
    }

    fn make_service_with_strategy_and_tree_delivery(
        transport: Arc<FakeVoiceTransport>,
        strategy: &str,
        tree_delivery_enabled: bool,
    ) -> Arc<VoiceService> {
        let mut cfg = VoiceConfig::default();
        cfg.delivery_strategy = strategy.to_string();
        cfg.tree_delivery_enabled = tree_delivery_enabled;
        VoiceService::new_with_transport(transport, cfg, CancellationToken::new(), 42)
    }

    async fn wait_for_call_count(transport: &FakeVoiceTransport, count: usize) -> Vec<FakeCall> {
        for _ in 0..50 {
            let calls = transport.calls();
            if calls.len() >= count {
                return calls;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        transport.calls()
    }

    fn repair_test_frame(sender_session: u32, sender_epoch: u64, s2s_seq: u64) -> VoiceFrame {
        VoiceFrame {
            sender_session,
            server_id: shitspeak_core::default_server_id(),
            sender_epoch,
            s2s_seq,
            target_kind: 0,
            is_terminator: false,
            payload: Bytes::from(format!("repair-{s2s_seq}").into_bytes()),
            intent: Some(VoiceIntent {
                kind: Some(VoiceIntentKind::Normal(VoiceIntentNormal {
                    source_channel: 0,
                })),
            }),
            proactive_copy: false,
            fec_parity: false,
            fec_member_seqs: Vec::new(),
            fec_terminator_mask: 0,
            fec_parity_index: 0,
        }
    }

    #[test]
    fn proactive_repair_defaults_remain_enabled() {
        let cfg = VoiceConfig::default();
        assert_eq!(cfg.repair_loss_start_ppm, 10_000);
        assert_eq!(cfg.repair_full_dup_loss_ppm, 30_000);
        assert_eq!(cfg.repair_jitter_start_ms, 40);
        assert_eq!(cfg.repair_max_extra_copies_per_frame, 1);
    }

    #[test]
    fn repair_request_stream_key_coalesces_ranges_and_distinguishes_epochs() {
        let gap = GapReport {
            from: 11,
            sender_session: shitspeak_core::ClientSessionIdentifier::new(12, 0xABC)
                .unwrap()
                .to_u32(),
            sender_epoch: 42,
            first_seq: 7,
            last_seq: 9,
        };
        let mut advanced = gap;
        advanced.first_seq = 10;
        advanced.last_seq = 12;
        let mut restarted = gap;
        restarted.sender_epoch = 43;

        let first = RepairRequestKey::new(gap);
        let same_stream = RepairRequestKey::new(advanced);
        let second = RepairRequestKey::new(restarted);
        assert_eq!(first, same_stream);
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn repair_request_coordinator_coalesces_and_bounds_retries() {
        let transport = FakeVoiceTransport::new(7, vec![12]);
        let mut cfg = VoiceConfig::default();
        cfg.adaptive_jitter_enabled = false;
        cfg.reorder_max_delay_ms = 90;
        let reorderer = Reorderer::new(cfg.clone());
        let sender_session = shitspeak_core::ClientSessionIdentifier::new(12, 0xABC)
            .unwrap()
            .to_u32();
        reorderer.push(11, repair_test_frame(sender_session, 42, 0));
        let opened = reorderer.push_with_route_hint_report(
            11,
            repair_test_frame(sender_session, 42, 2),
            None,
        );
        let gap = opened.opened_gap().expect("gap should open");

        let (tx, rx) = mpsc::channel(REPAIR_REQUEST_QUEUE_CAPACITY);
        let shutdown = CancellationToken::new();
        spawn_repair_request_worker(
            rx,
            reorderer,
            transport.clone(),
            cfg.repair_request_ttl_ms,
            shutdown.clone(),
        );
        for _ in 0..100 {
            tx.try_send(gap).expect("duplicate report should fit");
        }

        tokio::time::sleep(Duration::from_millis(120)).await;
        let requests = transport
            .calls()
            .into_iter()
            .filter(|call| matches!(call, FakeCall::RepairRequest { .. }))
            .count();
        assert!(
            (2..=REPAIR_REQUEST_MAX_ATTEMPTS_PER_PAGE as usize).contains(&requests),
            "the stable gap should retry without exceeding its page budget; requests={requests}"
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn repair_request_coordinator_stops_after_gap_closes() {
        let transport = FakeVoiceTransport::new(7, vec![12]);
        let mut cfg = VoiceConfig::default();
        cfg.adaptive_jitter_enabled = false;
        cfg.reorder_max_delay_ms = 120;
        let reorderer = Reorderer::new(cfg.clone());
        let sender_session = shitspeak_core::ClientSessionIdentifier::new(12, 0xABC)
            .unwrap()
            .to_u32();
        reorderer.push(11, repair_test_frame(sender_session, 42, 0));
        let opened = reorderer.push_with_route_hint_report(
            11,
            repair_test_frame(sender_session, 42, 2),
            None,
        );
        let gap = opened.opened_gap().expect("gap should open");

        let (tx, rx) = mpsc::channel(REPAIR_REQUEST_QUEUE_CAPACITY);
        let shutdown = CancellationToken::new();
        spawn_repair_request_worker(
            rx,
            reorderer.clone(),
            transport.clone(),
            cfg.repair_request_ttl_ms,
            shutdown.clone(),
        );
        tx.send(gap).await.unwrap();
        let calls = wait_for_call_count(&transport, 1).await;
        assert!(matches!(calls[0], FakeCall::RepairRequest { .. }));

        reorderer.push_with_route_hint_report_with_repair(
            11,
            repair_test_frame(sender_session, 42, 1),
            None,
            true,
        );
        tokio::time::sleep(Duration::from_millis(140)).await;
        let requests = transport
            .calls()
            .into_iter()
            .filter(|call| matches!(call, FakeCall::RepairRequest { .. }))
            .count();
        assert_eq!(requests, 1);
        shutdown.cancel();
    }

    #[tokio::test]
    async fn repair_request_coordinator_cancels_an_in_flight_send_after_convergence() {
        let transport = ControlledRepairRequestTransport::new();
        let mut cfg = VoiceConfig::default();
        cfg.adaptive_jitter_enabled = false;
        cfg.reorder_max_delay_ms = 120;
        let reorderer = Reorderer::new(cfg.clone());
        let sender_session = shitspeak_core::ClientSessionIdentifier::new(12, 0xABC)
            .unwrap()
            .to_u32();
        reorderer.push(11, repair_test_frame(sender_session, 42, 0));
        let opened = reorderer.push_with_route_hint_report(
            11,
            repair_test_frame(sender_session, 42, 2),
            None,
        );
        let gap = opened.opened_gap().expect("gap should open");

        let (tx, rx) = mpsc::channel(REPAIR_REQUEST_QUEUE_CAPACITY);
        let shutdown = CancellationToken::new();
        spawn_repair_request_worker(
            rx,
            reorderer.clone(),
            transport.clone(),
            cfg.repair_request_ttl_ms,
            shutdown.clone(),
        );
        tx.send(gap).await.unwrap();
        tokio::time::timeout(
            Duration::from_millis(100),
            transport.request_entered.acquire(),
        )
        .await
        .expect("the initial request should enter the transport")
        .unwrap()
        .forget();

        reorderer.push_with_route_hint_report_with_repair(
            11,
            repair_test_frame(sender_session, 42, 1),
            None,
            true,
        );
        tokio::time::timeout(Duration::from_millis(100), async {
            while transport.active_requests.load(Ordering::SeqCst) != 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the converged stream should cancel its blocked request future");

        assert!(
            transport.inner.calls().is_empty(),
            "a converged stream must cancel its blocked repair send"
        );
        assert_eq!(transport.request_entered.available_permits(), 0);
        shutdown.cancel();
    }

    #[tokio::test]
    async fn repair_request_rejection_does_not_consume_the_three_send_budget() {
        let transport = ControlledRepairRequestTransport::with_failures(3);
        let mut cfg = VoiceConfig::default();
        cfg.adaptive_jitter_enabled = false;
        cfg.reorder_max_delay_ms = 1_000;
        cfg.adaptive_jitter_min_delay_ms = 1_000;
        cfg.adaptive_jitter_max_delay_ms = 1_000;
        let reorderer = Reorderer::new(cfg.clone());
        let sender_session = shitspeak_core::ClientSessionIdentifier::new(12, 0xABC)
            .unwrap()
            .to_u32();
        reorderer.push(11, repair_test_frame(sender_session, 42, 0));
        let opened = reorderer.push_with_route_hint_report(
            11,
            repair_test_frame(sender_session, 42, 2),
            None,
        );

        let (tx, rx) = mpsc::channel(REPAIR_REQUEST_QUEUE_CAPACITY);
        let shutdown = CancellationToken::new();
        spawn_repair_request_worker(
            rx,
            reorderer,
            transport.clone(),
            cfg.repair_request_ttl_ms,
            shutdown.clone(),
        );
        tx.send(opened.opened_gap().expect("gap should open"))
            .await
            .unwrap();

        let completed = tokio::time::timeout(Duration::from_millis(700), async {
            while transport.inner.calls().len() < REPAIR_REQUEST_MAX_ATTEMPTS_PER_PAGE as usize {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await;
        assert!(
            completed.is_ok(),
            "three accepted sends should follow transient admission failures; attempts={} accepted={}",
            transport.request_attempts.load(Ordering::SeqCst),
            transport.inner.calls().len()
        );

        assert_eq!(
            transport.request_attempts.load(Ordering::SeqCst),
            3 + u64::from(REPAIR_REQUEST_MAX_ATTEMPTS_PER_PAGE)
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn repair_request_coordinator_retries_residual_after_cursor_progress() {
        let transport = FakeVoiceTransport::new(7, vec![12]);
        let mut cfg = VoiceConfig::default();
        cfg.adaptive_jitter_enabled = false;
        cfg.reorder_max_delay_ms = 500;
        cfg.adaptive_jitter_min_delay_ms = 500;
        cfg.adaptive_jitter_max_delay_ms = 500;
        let reorderer = Reorderer::new(cfg.clone());
        let sender_session = shitspeak_core::ClientSessionIdentifier::new(12, 0xABC)
            .unwrap()
            .to_u32();
        reorderer.push(11, repair_test_frame(sender_session, 42, 0));
        let opened = reorderer.push_with_route_hint_report(
            11,
            repair_test_frame(sender_session, 42, 6),
            None,
        );
        let gap = opened.opened_gap().expect("gap should open");

        let (tx, rx) = mpsc::channel(REPAIR_REQUEST_QUEUE_CAPACITY);
        let shutdown = CancellationToken::new();
        spawn_repair_request_worker(
            rx,
            reorderer.clone(),
            transport.clone(),
            cfg.repair_request_ttl_ms,
            shutdown.clone(),
        );
        tx.send(gap).await.unwrap();
        tokio::time::sleep(Duration::from_millis(180)).await;
        assert_eq!(
            transport
                .calls()
                .iter()
                .filter(|call| matches!(call, FakeCall::RepairRequest { .. }))
                .count(),
            REPAIR_REQUEST_MAX_ATTEMPTS_PER_PAGE as usize
        );

        reorderer.push_with_route_hint_report_with_repair(
            11,
            repair_test_frame(sender_session, 42, 1),
            None,
            true,
        );
        tokio::time::timeout(Duration::from_millis(40), async {
            loop {
                let saw_residual = transport.calls().iter().any(|call| {
                    let FakeCall::RepairRequest { body, .. } = call else {
                        return false;
                    };
                    proto::decode_voice_repair_request(body)
                        .is_ok_and(|request| request.first_seq == 2 && request.last_seq == 5)
                });
                if saw_residual {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("cursor progress must schedule the residual page after the 5 ms settling delay");
        shutdown.cancel();
    }

    #[tokio::test]
    async fn repair_request_coordinator_continues_after_a_32_sequence_page() {
        let transport = FakeVoiceTransport::new(7, vec![12]);
        let mut cfg = VoiceConfig::default();
        cfg.adaptive_jitter_enabled = false;
        cfg.reorder_max_delay_ms = 2_000;
        cfg.adaptive_jitter_min_delay_ms = 2_000;
        cfg.adaptive_jitter_max_delay_ms = 2_000;
        let reorderer = Reorderer::new(cfg.clone());
        let sender_session = shitspeak_core::ClientSessionIdentifier::new(12, 0xABC)
            .unwrap()
            .to_u32();
        reorderer.push(11, repair_test_frame(sender_session, 42, 0));
        let opened = reorderer.push_with_route_hint_report(
            11,
            repair_test_frame(sender_session, 42, 34),
            None,
        );
        let gap = opened.opened_gap().expect("gap should open");

        let (tx, rx) = mpsc::channel(REPAIR_REQUEST_QUEUE_CAPACITY);
        let shutdown = CancellationToken::new();
        spawn_repair_request_worker(
            rx,
            reorderer.clone(),
            transport.clone(),
            cfg.repair_request_ttl_ms,
            shutdown.clone(),
        );
        tx.send(gap).await.unwrap();
        let first = wait_for_call_count(&transport, 1).await;
        let FakeCall::RepairRequest { body, .. } = &first[0] else {
            panic!("expected initial repair request");
        };
        let first_request = proto::decode_voice_repair_request(body).unwrap();
        assert_eq!((first_request.first_seq, first_request.last_seq), (1, 32));

        for seq in 1..=31 {
            reorderer.push_with_route_hint_report_with_repair(
                11,
                repair_test_frame(sender_session, 42, seq),
                None,
                true,
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
            assert_eq!(
                transport
                    .calls()
                    .into_iter()
                    .filter(|call| matches!(call, FakeCall::RepairRequest { .. }))
                    .count(),
                1,
                "progress inside one response page must not create overlapping requests"
            );
        }
        reorderer.push_with_route_hint_report_with_repair(
            11,
            repair_test_frame(sender_session, 42, 32),
            None,
            true,
        );
        let current = reorderer
            .current_actionable_gap(11, sender_session, 42)
            .expect("the next page should remain actionable");
        assert_eq!((current.gap().first_seq, current.gap().last_seq), (33, 33));

        let calls = wait_for_call_count(&transport, 2).await;
        let continuation = calls.iter().find_map(|call| {
            let FakeCall::RepairRequest { body, .. } = call else {
                return None;
            };
            let request = proto::decode_voice_repair_request(body).ok()?;
            (request.first_seq == 33).then_some(request)
        });
        let continuation = continuation.expect("coordinator should request the next page");
        assert_eq!((continuation.first_seq, continuation.last_seq), (33, 33));

        reorderer.push_with_route_hint_report_with_repair(
            11,
            repair_test_frame(sender_session, 42, 33),
            None,
            true,
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn proactive_copy_is_marked_and_cached_original_replays_for_later_nack() {
        let transport = FakeVoiceTransport::new(7, vec![2, 3]);
        transport.set_voice_route_quality(
            2,
            crate::overlay::VoiceRouteQuality::new(
                2,
                TransportKind::Udp,
                20_000,
                VoiceConfig::default().repair_full_dup_loss_ppm,
                0,
            )
            .with_alternate_route_quality(3, 10_000, TransportKind::Quic, 0, 0),
        );
        let svc = make_legacy_service(transport.clone());
        // This test covers marker/cache semantics, not the source-side rate
        // budget. Seed credit so the first qualifying alternate is admitted;
        // the proactive copy rides the alternate first hop 3.
        svc.voice_budget.mint_link_credit(3, 0xABC, 42, usize::MAX);
        svc.send_unicast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            false,
            Bytes::from_static(b"opus"),
            normal_intent(5),
            2,
        )
        .await
        .unwrap();

        assert_eq!(transport.route_quality_batches(), vec![vec![2]]);
        assert_eq!(transport.route_quality_scalar_calls(), 0);

        let calls = wait_for_call_count(&transport, 2).await;
        assert_eq!(calls.len(), 2);
        match &calls[1] {
            FakeCall::RepairFrame {
                dst,
                body,
                is_repair,
                ..
            } => {
                assert_eq!(*dst, 2);
                assert!(!is_repair);
                assert!(proto::decode_voice(body).unwrap().proactive_copy);
            }
            other => panic!("expected proactive repair frame, got {other:?}"),
        }

        let request = VoiceRepairRequest {
            sender_session: 0xABC,
            sender_epoch: 42,
            first_seq: 0,
            last_seq: 0,
            request_sent_unix_ms: 0,
            request_ttl_ms: 0,
            tail_ack: false,
        };
        svc.repair_inbound_handler().handle(OverlayInboundMessage {
            from: 3,
            origin_boot_epoch: 0,
            level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body: proto::encode_voice_repair_request(&request).unwrap(),
            remote_playout_delay_ms: None,
            is_distribution_repair: false,
        });
        let calls = wait_for_call_count(&transport, 3).await;
        match &calls[2] {
            FakeCall::RepairFrame {
                dst,
                body,
                is_repair,
                ..
            } => {
                assert_eq!(*dst, 3);
                assert!(*is_repair);
                assert!(!proto::decode_voice(body).unwrap().proactive_copy);
            }
            other => panic!("expected NACK replay frame, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn primary_lane_drains_before_a_saturated_proactive_backlog() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_legacy_service(transport);
        let sink = RecordingSink::new();
        svc.set_audio_sink(sink.clone());
        let inbound = svc.inbound_handler();

        // Queue enough marked copies to consume the low-priority lane before
        // yielding to the dispatch task. The following ordinary frame must
        // still be the first release.
        for session in 1..256_u32 {
            let body = send::mark_proactive_copy(
                &send::build_envelope(
                    session,
                    shitspeak_core::default_server_id(),
                    42,
                    0,
                    0,
                    false,
                    Bytes::from(vec![0; 512]),
                    normal_intent(5),
                )
                .unwrap(),
            )
            .unwrap();
            inbound.handle(OverlayInboundMessage {
                from: 11,
                origin_boot_epoch: 0,
                level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
                class: shitspeak_s2s_transport::MessageClass::HighPriority,
                body,
                remote_playout_delay_ms: None,
                is_distribution_repair: false,
            });
        }
        let primary_session = 0xABCD;
        inbound.handle(OverlayInboundMessage {
            from: 11,
            origin_boot_epoch: 0,
            level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body: send::build_envelope(
                primary_session,
                shitspeak_core::default_server_id(),
                42,
                0,
                0,
                false,
                Bytes::from_static(b"primary"),
                normal_intent(5),
            )
            .unwrap(),
            remote_playout_delay_ms: None,
            is_distribution_repair: false,
        });

        for _ in 0..50 {
            if sink.len() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(sink.snapshot()[0].1.sender_session, primary_session);
    }

    #[tokio::test]
    async fn proactive_worker_preserves_same_key_fifo_and_cross_key_concurrency() {
        let transport = ControlledUnicastTransport::new(false);
        let budget =
            AdaptiveVoiceBudget::with_repair_reservations(Arc::new(AtomicU64::new(5_000)), 0, 0);
        let shutdown = CancellationToken::new();
        let (tx, rx) = mpsc::unbounded_channel();
        spawn_proactive_worker(
            rx,
            transport.clone(),
            budget.clone(),
            Arc::new(ProactivePressureState::default()),
            shutdown.clone(),
        );

        let work = |sender_session, dst, body: &'static [u8]| {
            let body = Bytes::from_static(body);
            let permit = budget
                .try_reserve_proactive(body.len())
                .expect("test proactive work fits byte budget");
            budget.mint_proactive_credit(body.len().saturating_mul(4));
            let credit_permit = budget
                .try_reserve_proactive_credit(body.len())
                .expect("test proactive work fits repair credit");
            ProactiveSendWork {
                sender_session,
                dst,
                body,
                avoid_first_hop: None,
                expires_at: Instant::now() + Duration::from_secs(1),
                _permit: permit,
                credit_permit,
            }
        };
        tx.send(work(100, 2, b"a0")).unwrap();
        tx.send(work(100, 2, b"a1")).unwrap();
        tx.send(work(101, 2, b"b0")).unwrap();

        tokio::time::timeout(
            Duration::from_secs(1),
            transport.proactive_entered.acquire_many(2),
        )
        .await
        .expect("different proactive keys should overlap on a healthy destination")
        .unwrap()
        .forget();
        let first_bodies: Vec<Bytes> = transport
            .inner
            .calls()
            .iter()
            .filter_map(|call| match call {
                FakeCall::RepairFrame { body, .. } => Some(body.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(first_bodies.len(), 2);
        assert!(first_bodies.contains(&Bytes::from_static(b"a0")));
        assert!(first_bodies.contains(&Bytes::from_static(b"b0")));
        assert!(!first_bodies.contains(&Bytes::from_static(b"a1")));

        transport.proactive_release.add_permits(2);
        tokio::time::timeout(
            Duration::from_secs(1),
            transport.proactive_entered.acquire(),
        )
        .await
        .expect("second same-key frame should start after the first completes")
        .unwrap()
        .forget();
        let bodies: Vec<Bytes> = transport
            .inner
            .calls()
            .iter()
            .filter_map(|call| match call {
                FakeCall::RepairFrame { body, .. } => Some(body.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(bodies.last(), Some(&Bytes::from_static(b"a1")));
        transport.proactive_release.add_permits(1);
        shutdown.cancel();
    }

    #[tokio::test]
    async fn proactive_worker_cancellation_releases_hung_send_permit() {
        let transport = ControlledUnicastTransport::new(false);
        let budget =
            AdaptiveVoiceBudget::with_repair_reservations(Arc::new(AtomicU64::new(5_000)), 0, 0);
        let shutdown = CancellationToken::new();
        let (tx, rx) = mpsc::unbounded_channel();
        spawn_proactive_worker(
            rx,
            transport.clone(),
            budget.clone(),
            Arc::new(ProactivePressureState::default()),
            shutdown.clone(),
        );
        let body = Bytes::from_static(b"hung");
        let body_len = body.len();
        let permit = budget
            .try_reserve_proactive(body.len())
            .expect("test proactive work fits byte budget");
        budget.mint_proactive_credit(body.len().saturating_mul(4));
        let credit_permit = budget
            .try_reserve_proactive_credit(body.len())
            .expect("test proactive work fits repair credit");
        tx.send(ProactiveSendWork {
            sender_session: 100,
            dst: 2,
            body,
            avoid_first_hop: None,
            expires_at: Instant::now() + Duration::from_secs(1),
            _permit: permit,
            credit_permit,
        })
        .unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            transport.proactive_entered.acquire(),
        )
        .await
        .expect("proactive send should enter transport")
        .unwrap()
        .forget();
        assert!(budget.proactive_reserved_bytes() > 0);

        shutdown.cancel();
        for _ in 0..50 {
            if budget.proactive_reserved_bytes() == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(budget.proactive_reserved_bytes(), 0);
        assert_eq!(budget.proactive_credit_balance_bytes(), body_len);
    }

    #[tokio::test]
    async fn queued_proactive_expiry_refunds_credit_before_transport_attempt() {
        let transport = ControlledUnicastTransport::new(false);
        let budget =
            AdaptiveVoiceBudget::with_repair_reservations(Arc::new(AtomicU64::new(5_000)), 0, 0);
        let shutdown = CancellationToken::new();
        let (tx, rx) = mpsc::unbounded_channel();
        spawn_proactive_worker(
            rx,
            transport.clone(),
            budget.clone(),
            Arc::new(ProactivePressureState::default()),
            shutdown.clone(),
        );
        let work = |body: &'static [u8], expires_at| {
            let body = Bytes::from_static(body);
            let queue_permit = budget.try_reserve_proactive(body.len()).unwrap();
            budget.mint_proactive_credit(body.len() * 4);
            let credit_permit = budget.try_reserve_proactive_credit(body.len()).unwrap();
            ProactiveSendWork {
                sender_session: 100,
                dst: 2,
                body,
                avoid_first_hop: None,
                expires_at,
                _permit: queue_permit,
                credit_permit,
            }
        };
        tx.send(work(b"a", Instant::now() + Duration::from_secs(1)))
            .unwrap();
        tx.send(work(b"b", Instant::now() + Duration::from_millis(10)))
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            transport.proactive_entered.acquire(),
        )
        .await
        .unwrap()
        .unwrap()
        .forget();
        tokio::time::sleep(Duration::from_millis(20)).await;
        transport.proactive_release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(1), async {
            while budget.proactive_reserved_bytes() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(budget.proactive_credit_balance_bytes(), 1);
        let attempts = transport
            .inner
            .calls()
            .iter()
            .filter(|call| matches!(call, FakeCall::RepairFrame { .. }))
            .count();
        assert_eq!(attempts, 1);
        shutdown.cancel();
    }

    #[tokio::test]
    async fn proactive_backpressure_sheds_already_queued_copies_without_touching_primary_voice() {
        let transport = PressuredProactiveTransport::new();
        let budget =
            AdaptiveVoiceBudget::with_repair_reservations(Arc::new(AtomicU64::new(5_000)), 0, 0);
        let pressure = Arc::new(ProactivePressureState::default());
        let shutdown = CancellationToken::new();
        let (tx, rx) = mpsc::unbounded_channel();
        spawn_proactive_worker(
            rx,
            transport.clone(),
            budget.clone(),
            pressure.clone(),
            shutdown.clone(),
        );

        for sequence in 0..32_u64 {
            let body = Bytes::from(sequence.to_le_bytes().to_vec());
            let permit = budget
                .try_reserve_proactive(body.len())
                .expect("regression workload fits proactive byte budget");
            budget.mint_proactive_credit(body.len().saturating_mul(4));
            let credit_permit = budget
                .try_reserve_proactive_credit(body.len())
                .expect("regression workload fits repair credit");
            tx.send(ProactiveSendWork {
                sender_session: 100,
                dst: 2,
                body,
                avoid_first_hop: None,
                expires_at: Instant::now() + Duration::from_secs(1),
                _permit: permit,
                credit_permit,
            })
            .unwrap();
        }

        tokio::time::timeout(Duration::from_secs(1), async {
            while budget.proactive_reserved_bytes() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pressured proactive queue should be shed promptly");

        assert_eq!(
            transport.proactive_attempts.load(Ordering::SeqCst),
            1,
            "one full queue must not cause every queued copy to retry"
        );
        assert_eq!(budget.proactive_credit_balance_bytes(), 32 * 8);
        assert!(pressure.is_blocked(2, Instant::now()));

        transport
            .send_unicast(2, Bytes::from_static(b"primary"), Duration::from_secs(1))
            .await
            .expect("repair pressure must not gate primary voice");
        assert!(matches!(
            transport.inner.calls().last(),
            Some(FakeCall::Unicast { body, .. }) if body == &Bytes::from_static(b"primary")
        ));
        shutdown.cancel();
    }

    #[tokio::test]
    async fn four_lanes_reserve_one_recovery_probe_for_a_failed_destination() {
        let transport = ControlledUnicastTransport::new(false);
        let budget =
            AdaptiveVoiceBudget::with_repair_reservations(Arc::new(AtomicU64::new(5_000)), 0, 0);
        let pressure = Arc::new(ProactivePressureState::default());
        let failed_at = Instant::now();
        pressure.record_failure(2, failed_at);
        pressure
            .destinations
            .lock()
            .get_mut(&2)
            .unwrap()
            .blocked_until = failed_at;
        let shutdown = CancellationToken::new();
        let (tx, rx) = mpsc::unbounded_channel();
        spawn_proactive_worker(
            rx,
            transport.clone(),
            budget.clone(),
            pressure.clone(),
            shutdown.clone(),
        );

        let make_work = |sender_session| {
            let body = Bytes::from_static(b"probe");
            let permit = budget
                .try_reserve_proactive(body.len())
                .expect("concurrency regression fits proactive byte budget");
            budget.mint_proactive_credit(body.len().saturating_mul(4));
            let credit_permit = budget
                .try_reserve_proactive_credit(body.len())
                .expect("concurrency regression fits repair credit");
            ProactiveSendWork {
                sender_session,
                dst: 2,
                body,
                avoid_first_hop: None,
                expires_at: Instant::now() + Duration::from_secs(1),
                _permit: permit,
                credit_permit,
            }
        };

        let first = make_work(100);
        let one_permit_bytes = first._permit.charged_bytes();
        tx.send(first).unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            transport.proactive_entered.acquire(),
        )
        .await
        .expect("first lane should enter transport")
        .unwrap()
        .forget();

        // These session IDs cover the other three lane hashes for dst 2.
        for sender_session in [101, 102, 103] {
            tx.send(make_work(sender_session)).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while budget.proactive_reserved_bytes() != one_permit_bytes {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("other destination lanes should shed behind the reservation");
        assert_eq!(
            transport.inner.calls().len(),
            1,
            "four worker lanes must produce one transport call for a destination"
        );

        transport.proactive_release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(1), async {
            while budget.proactive_reserved_bytes() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the admitted proactive send should finish");
        shutdown.cancel();
    }

    #[test]
    fn older_success_token_does_not_clear_a_newer_failure_generation() {
        let pressure = ProactivePressureState::default();
        let now = Instant::now();
        let older = pressure
            .try_start_send(2, now)
            .expect("initial probe is admitted");
        pressure.record_failure(2, now);
        let failure_generation = pressure.destinations.lock()[&2].generation;

        pressure.complete_success(2, older);
        assert_eq!(
            pressure.destinations.lock()[&2].generation,
            failure_generation
        );
    }

    #[test]
    fn delayed_failure_starts_cooldown_at_completion_time() {
        let pressure = ProactivePressureState::default();
        let started_at = Instant::now();
        let token = pressure
            .try_start_send(2, started_at)
            .expect("healthy send is admitted");
        let completed_at = started_at + Duration::from_secs(2);

        let blocked_until = pressure.complete_failure(
            2,
            token,
            completed_at,
            TAIL_REPAIR_INTERVAL,
            TAIL_REPAIR_FAILURE_BACKOFF_MAX,
        );
        assert_eq!(blocked_until, completed_at + TAIL_REPAIR_INTERVAL);
        assert!(pressure.is_blocked(2, completed_at));
    }

    #[test]
    fn successful_probe_after_cooldown_clears_failure_history() {
        let pressure = ProactivePressureState::default();
        let now = Instant::now();
        let blocked_until = pressure.record_failure(2, now);
        let token = pressure
            .try_start_send(2, blocked_until)
            .expect("a probe is admitted when its cooldown expires");

        pressure.complete_success(2, token);
        assert!(!pressure.destinations.lock().contains_key(&2));

        pressure.record_failure(2, blocked_until);
        assert_eq!(
            pressure.destinations.lock()[&2].consecutive_failures,
            1,
            "a successful recovery resets the next failure's backoff history"
        );
    }

    #[tokio::test]
    async fn live_capacity_reduction_keeps_queued_primary_and_rejects_new_work() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let max_users = Arc::new(AtomicU64::new(5_000));
        let svc = VoiceService::new_with_transport_and_capacity_source(
            transport,
            VoiceConfig::default(),
            CancellationToken::new(),
            42,
            max_users.clone(),
        );
        let inbound = svc.inbound_handler();
        let large = Bytes::from(vec![0; 300_000]);
        let make_body = |session| {
            send::build_envelope(
                session,
                shitspeak_core::default_server_id(),
                42,
                0,
                0,
                false,
                large.clone(),
                normal_intent(5),
            )
            .unwrap()
        };
        inbound.handle(OverlayInboundMessage {
            from: 11,
            origin_boot_epoch: 0,
            level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body: make_body(1),
            remote_playout_delay_ms: None,
            is_distribution_repair: false,
        });
        let reserved = svc.voice_budget.primary_reserved_bytes();
        assert!(reserved > 256 * 1024);

        max_users.store(100, Ordering::Relaxed);
        inbound.handle(OverlayInboundMessage {
            from: 11,
            origin_boot_epoch: 0,
            level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body: make_body(2),
            remote_playout_delay_ms: None,
            is_distribution_repair: false,
        });
        assert_eq!(svc.voice_budget.primary_reserved_bytes(), reserved);

        // Let dispatch release the retained item. The reduction affects only
        // later reservation attempts; it never evicts queued voice.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(svc.voice_budget.primary_reserved_bytes(), 0);
    }

    #[tokio::test]
    async fn send_for_channel_broadcast_strategy_multicasts_to_voice_members() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "broadcast");
        svc.send_for_channel(
            0xABC,
            shitspeak_core::default_server_id(),
            /*channel=*/ 5,
            false,
            Bytes::from_static(b"x"),
        )
        .await
        .unwrap();
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert!(matches!(calls[0], FakeCall::Multicast { .. }));
    }

    #[tokio::test]
    async fn send_for_channel_targeted_falls_back_to_voice_member_multicast_when_no_index() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        svc.send_for_channel(
            0xABC,
            shitspeak_core::default_server_id(),
            5,
            false,
            Bytes::from_static(b"x"),
        )
        .await
        .unwrap();
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert!(matches!(calls[0], FakeCall::Multicast { .. }));
    }

    #[tokio::test]
    async fn send_for_channel_targeted_uses_index() {
        use crate::application::voice::targeted::RecipientIndex;
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        idx.add(5, 1);
        idx.add(5, 2);
        idx.add(5, 7); // self — must be filtered out
        svc.set_recipient_index(idx);
        svc.send_for_channel(
            0xABC,
            shitspeak_core::default_server_id(),
            5,
            false,
            Bytes::from_static(b"x"),
        )
        .await
        .unwrap();
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            FakeCall::Multicast { dsts, .. } => {
                let mut sorted = dsts.clone();
                sorted.sort();
                assert_eq!(sorted, vec![1, 2]);
            }
            other => panic!("expected Multicast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn targeted_tree_group_tracks_only_its_recipient_snapshot() {
        use crate::application::voice::targeted::RecipientIndex;

        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy_and_tree_delivery(transport.clone(), "targeted", true);
        let idx = RecipientIndex::new();
        idx.add_in_server("tenant-a", 5, 1);
        idx.add_in_server("tenant-a", 5, 2);
        svc.set_recipient_index(idx.clone());

        svc.send_for_channel(
            0xABC,
            "tenant-a".to_owned(),
            5,
            false,
            Bytes::from_static(b"x"),
        )
        .await
        .unwrap();

        // This changes RecipientIndex generation but not the target's
        // resolved membership, so the distribution group must be unchanged.
        idx.add_in_server("tenant-a", 99, 3);
        svc.send_for_channel(
            0xABC,
            "tenant-a".to_owned(),
            5,
            false,
            Bytes::from_static(b"y"),
        )
        .await
        .unwrap();

        idx.add_in_server("tenant-a", 5, 3);
        svc.send_for_channel(
            0xABC,
            "tenant-a".to_owned(),
            5,
            false,
            Bytes::from_static(b"z"),
        )
        .await
        .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 3);
        let groups: Vec<_> = calls
            .iter()
            .map(|call| match call {
                FakeCall::TreeMulticast { group, .. } => *group,
                other => panic!("expected tree multicast, got {other:?}"),
            })
            .collect();
        assert_eq!(
            groups[0].kind(),
            crate::application::voice::send::DistributionGroupKind::Targeted
        );
        assert_eq!(groups[0].id(), groups[1].id());
        assert_eq!(groups[0].version(), groups[1].version());
        assert_eq!(groups[1].id(), groups[2].id());
        assert_ne!(groups[1].version(), groups[2].version());
    }

    #[tokio::test]
    async fn send_for_channel_targeted_scopes_index_by_server_id() {
        use crate::application::voice::targeted::RecipientIndex;
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        idx.add_in_server("alpha", 5, 1);
        idx.add_in_server("beta", 5, 2);
        idx.add_in_server("beta", 5, 7);
        svc.set_recipient_index(idx);

        svc.send_for_channel(0xABC, "beta".to_owned(), 5, false, Bytes::from_static(b"x"))
            .await
            .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            FakeCall::Multicast { dsts, body, .. } => {
                assert_eq!(dsts, &vec![2]);
                let frame = proto::decode_voice(body.as_ref()).unwrap();
                assert_eq!(frame.server_id, "beta");
            }
            other => panic!("expected Multicast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_for_target_channels_targeted_preserves_shout_intent() {
        use crate::application::proto::{VoiceIntentKind, VoiceIntentTarget, VoiceTargetChannel};
        use crate::application::voice::targeted::{
            RecipientIndex, RecipientIndexKey, RecipientIndexSnapshot, RecipientIndexUpdate,
        };

        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        let mut snapshot = RecipientIndexSnapshot::new();
        snapshot.insert(
            RecipientIndexKey::new(shitspeak_core::default_server_id(), 5),
            [1].into_iter().collect(),
        );
        snapshot.insert(
            RecipientIndexKey::new(shitspeak_core::default_server_id(), 6),
            [2, 7].into_iter().collect(),
        );
        idx.replace_all_complete(RecipientIndexUpdate::new(
            snapshot,
            [shitspeak_core::default_server_id()].into_iter().collect(),
            [1, 2, 3, 7].into_iter().collect(),
        ));
        svc.set_recipient_index(idx);

        let intent = VoiceIntent {
            kind: Some(VoiceIntentKind::Target(VoiceIntentTarget {
                source_channel: 5,
                sessions: Vec::new(),
                channels: vec![VoiceTargetChannel {
                    id: 5,
                    children: false,
                    links: true,
                    group: String::new(),
                }],
            })),
        };
        svc.send_for_target_channels(
            0xABC,
            shitspeak_core::default_server_id(),
            Arc::from([5, 6]),
            1,
            false,
            Bytes::from_static(b"shout"),
            intent,
        )
        .await
        .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            FakeCall::Multicast { dsts, body, .. } => {
                let mut sorted = dsts.clone();
                sorted.sort();
                assert_eq!(sorted, vec![1, 2]);
                let frame = proto::decode_voice(body.as_ref()).unwrap();
                assert_eq!(frame.target_kind, 1);
                assert!(matches!(
                    frame.intent.and_then(|intent| intent.kind),
                    Some(VoiceIntentKind::Target(_))
                ));
            }
            other => panic!("expected Multicast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_for_target_channels_targeted_preserves_normal_intent() {
        use crate::application::proto::VoiceIntentKind;
        use crate::application::voice::targeted::{
            RecipientIndex, RecipientIndexKey, RecipientIndexSnapshot, RecipientIndexUpdate,
        };

        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        let mut snapshot = RecipientIndexSnapshot::new();
        snapshot.insert(
            RecipientIndexKey::new(shitspeak_core::default_server_id(), 5),
            [1].into_iter().collect(),
        );
        snapshot.insert(
            RecipientIndexKey::new(shitspeak_core::default_server_id(), 6),
            [2, 7].into_iter().collect(),
        );
        idx.replace_all_complete(RecipientIndexUpdate::new(
            snapshot,
            [shitspeak_core::default_server_id()].into_iter().collect(),
            [1, 2, 3, 7].into_iter().collect(),
        ));
        svc.set_recipient_index(idx);

        svc.send_for_target_channels(
            0xABC,
            shitspeak_core::default_server_id(),
            Arc::from([5, 6]),
            0,
            false,
            Bytes::from_static(b"normal"),
            normal_intent(5),
        )
        .await
        .unwrap();

        match &transport.calls()[0] {
            FakeCall::Multicast { dsts, body, .. } => {
                let mut sorted = dsts.clone();
                sorted.sort();
                assert_eq!(sorted, vec![1, 2]);
                let frame = proto::decode_voice(body.as_ref()).unwrap();
                assert_eq!(frame.target_kind, 0);
                assert!(matches!(
                    frame.intent.and_then(|intent| intent.kind),
                    Some(VoiceIntentKind::Normal(normal)) if normal.source_channel == 5
                ));
            }
            other => panic!("expected Multicast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_for_server_targeted_uses_complete_server_membership() {
        use crate::application::proto::{VoiceIntentKind, VoiceIntentTarget, VoiceTargetChannel};
        use crate::application::voice::targeted::{
            RecipientIndex, RecipientIndexKey, RecipientIndexSnapshot, RecipientIndexUpdate,
        };

        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        let mut snapshot = RecipientIndexSnapshot::new();
        snapshot.insert(
            RecipientIndexKey::new("alpha", 5),
            [1, 2].into_iter().collect(),
        );
        idx.replace_all_complete(RecipientIndexUpdate::new(
            snapshot,
            ["alpha".to_owned()].into_iter().collect(),
            [1, 2, 3, 7].into_iter().collect(),
        ));
        svc.set_recipient_index(idx);
        let intent = VoiceIntent {
            kind: Some(VoiceIntentKind::Target(VoiceIntentTarget {
                source_channel: 0,
                sessions: Vec::new(),
                channels: vec![VoiceTargetChannel {
                    id: 0,
                    children: true,
                    links: false,
                    group: String::new(),
                }],
            })),
        };

        svc.send_for_server(
            0xABC,
            "alpha".to_owned(),
            1,
            false,
            Bytes::from_static(b"server"),
            intent,
        )
        .await
        .unwrap();

        match &transport.calls()[0] {
            FakeCall::Multicast { dsts, .. } => assert_eq!(dsts, &vec![1, 2]),
            other => panic!("expected server-scoped multicast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_for_target_channels_falls_back_when_any_channel_missing() {
        use crate::application::proto::{VoiceIntentKind, VoiceIntentTarget, VoiceTargetChannel};
        use crate::application::voice::targeted::RecipientIndex;

        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        idx.add(5, 1);
        svc.set_recipient_index(idx);

        let intent = VoiceIntent {
            kind: Some(VoiceIntentKind::Target(VoiceIntentTarget {
                source_channel: 5,
                sessions: Vec::new(),
                channels: vec![VoiceTargetChannel {
                    id: 5,
                    children: false,
                    links: true,
                    group: String::new(),
                }],
            })),
        };
        svc.send_for_target_channels(
            0xABC,
            shitspeak_core::default_server_id(),
            Arc::from([5, 6]),
            1,
            false,
            Bytes::from_static(b"shout"),
            intent,
        )
        .await
        .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert!(matches!(calls[0], FakeCall::Multicast { .. }));
    }

    #[tokio::test]
    async fn normal_channel_set_falls_back_when_linked_channel_is_missing() {
        use crate::application::proto::VoiceIntentKind;
        use crate::application::voice::targeted::RecipientIndex;

        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        idx.add(5, 1);
        svc.set_recipient_index(idx);

        svc.send_for_target_channels(
            0xABC,
            shitspeak_core::default_server_id(),
            Arc::from([5, 6]),
            0,
            false,
            Bytes::from_static(b"normal"),
            normal_intent(5),
        )
        .await
        .unwrap();

        match &transport.calls()[0] {
            FakeCall::Multicast { dsts, body, .. } => {
                assert_eq!(dsts, &vec![1, 2, 3]);
                let frame = proto::decode_voice(body.as_ref()).unwrap();
                assert!(matches!(
                    frame.intent.and_then(|intent| intent.kind),
                    Some(VoiceIntentKind::Normal(normal)) if normal.source_channel == 5
                ));
            }
            other => panic!("expected broadcast fallback, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_for_target_channels_targeted_missing_channel_is_server_scoped() {
        use crate::application::proto::{VoiceIntentKind, VoiceIntentTarget, VoiceTargetChannel};
        use crate::application::voice::targeted::RecipientIndex;

        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        idx.add_in_server("alpha", 5, 1);
        idx.add_in_server("alpha", 6, 1);
        idx.add_in_server("beta", 5, 2);
        svc.set_recipient_index(idx);

        let intent = VoiceIntent {
            kind: Some(VoiceIntentKind::Target(VoiceIntentTarget {
                source_channel: 5,
                sessions: Vec::new(),
                channels: vec![VoiceTargetChannel {
                    id: 5,
                    children: false,
                    links: false,
                    group: String::new(),
                }],
            })),
        };
        svc.send_for_target_channels(
            0xABC,
            "beta".to_owned(),
            Arc::from([5, 6]),
            1,
            false,
            Bytes::from_static(b"shout"),
            intent,
        )
        .await
        .unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert!(
            matches!(calls[0], FakeCall::Multicast { .. }),
            "missing beta channel 6 should fall back despite alpha channel 6 existing"
        );
    }

    #[tokio::test]
    async fn send_for_channel_targeted_no_op_when_only_self_in_channel() {
        use crate::application::voice::targeted::RecipientIndex;
        let transport = FakeVoiceTransport::new(7, vec![1, 2]);
        let svc = make_service_with_strategy(transport.clone(), "targeted");
        let idx = RecipientIndex::new();
        idx.add(5, 7); // only self
        svc.set_recipient_index(idx);
        svc.send_for_channel(
            0xABC,
            shitspeak_core::default_server_id(),
            5,
            false,
            Bytes::from_static(b"x"),
        )
        .await
        .unwrap();
        // No cross-node calls — speaker is the only channel resident.
        assert!(transport.calls().is_empty());
    }

    #[tokio::test]
    async fn ingress_dispatches_decoded_frame_to_installed_sink() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_legacy_service(transport);
        let sink = RecordingSink::new();
        svc.set_audio_sink(sink.clone());

        // Synthesize an inbound overlay message and feed it through the
        // production decode path.
        let envelope = send::build_envelope(
            0xABC,
            shitspeak_core::default_server_id(),
            42,
            5,
            0,
            true,
            Bytes::from_static(b"opus-bytes"),
            normal_intent(5),
        )
        .unwrap();
        svc.inbound_handler().handle(OverlayInboundMessage {
            from: 11,
            origin_boot_epoch: 0,
            level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body: envelope,
            remote_playout_delay_ms: None,
            is_distribution_repair: false,
        });

        // Dispatch task is async; poll with a small bounded retry.
        for _ in 0..50 {
            if sink.len() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let received = sink.snapshot();
        assert_eq!(received.len(), 1);
        let (from, frame) = &received[0];
        assert_eq!(*from, 11);
        assert_eq!(frame.sender_session, 0xABC);
        assert_eq!(frame.s2s_seq, 5);
        assert!(frame.is_terminator);
        assert_eq!(frame.payload, b"opus-bytes".as_ref());
    }

    #[tokio::test]
    async fn ingress_uses_origin_route_quality_for_reorder_deadline() {
        let transport = FakeVoiceTransport::new(7, vec![11, 12]);
        transport.set_voice_route_quality(
            11,
            crate::overlay::VoiceRouteQuality::new(11, TransportKind::Tcp, 1_000, 0, 0),
        );
        transport.set_voice_route_quality(
            12,
            crate::overlay::VoiceRouteQuality::new(11, TransportKind::Tcp, 237_000, 0, 0),
        );
        let mut cfg = VoiceConfig::default();
        // Keep the chunk-hold window short: this test exercises the origin
        // quality extension of the skew deadline, not the (default 1600 ms)
        // hold-first budget. With the hint the skew deadline is ~257 ms; a
        // 50 ms hold then flushes the whole buffered chunk at ~307 ms.
        cfg.chunk_hold_budget_ms = 50;
        let svc = VoiceService::new_with_transport(
            transport,
            cfg,
            CancellationToken::new(),
            42,
        );
        let sink = RecordingSink::new();
        svc.set_audio_sink(sink.clone());
        let sender_session = shitspeak_core::ClientSessionIdentifier::new(12, 0xABC)
            .unwrap()
            .to_u32();
        let inbound = svc.inbound_handler();

        for seq in [0, 2] {
            let body = send::build_envelope(
                sender_session,
                shitspeak_core::default_server_id(),
                42,
                seq,
                0,
                false,
                Bytes::from_static(b"opus"),
                normal_intent(5),
            )
            .unwrap();
            inbound.handle(OverlayInboundMessage {
                from: 11,
                origin_boot_epoch: 0,
                level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
                class: shitspeak_s2s_transport::MessageClass::HighPriority,
                body,
                remote_playout_delay_ms: None,
                is_distribution_repair: false,
            });
        }

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            sink.len(),
            1,
            "relay RTT must not shorten the origin deadline"
        );
        // The chunk-hold window ends at ~307 ms, after which the whole
        // buffered chunk [0, 2] flushes contiguously.
        for _ in 0..300 {
            if sink.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(sink.len(), 2);
    }

    #[tokio::test]
    async fn late_proactive_copy_does_not_rebase_an_established_stream() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_legacy_service(transport);
        let sink = RecordingSink::new();
        svc.set_audio_sink(sink.clone());

        let original = send::build_envelope(
            0xABC,
            shitspeak_core::default_server_id(),
            42,
            5,
            0,
            false,
            Bytes::from_static(b"original"),
            normal_intent(5),
        )
        .unwrap();
        let late_proactive = send::mark_proactive_copy(
            &send::build_envelope(
                0xABC,
                shitspeak_core::default_server_id(),
                42,
                4,
                0,
                false,
                Bytes::from_static(b"late-proactive"),
                normal_intent(5),
            )
            .unwrap(),
        )
        .unwrap();

        let inbound = svc.inbound_handler();
        for body in [original, late_proactive] {
            inbound.handle(OverlayInboundMessage {
                from: 11,
                origin_boot_epoch: 0,
                level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
                class: shitspeak_s2s_transport::MessageClass::HighPriority,
                body,
                remote_playout_delay_ms: None,
                is_distribution_repair: false,
            });
        }

        for _ in 0..50 {
            if sink.len() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        let received = sink.snapshot();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].1.s2s_seq, 5);
    }

    #[tokio::test]
    async fn ingress_passes_tree_repair_identity_to_audio_sink() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_legacy_service(transport);
        let sink = Arc::new(RepairProbeSink::default());
        svc.set_audio_sink(sink.clone());
        let original = send::build_envelope(
            0xABC,
            shitspeak_core::default_server_id(),
            42,
            0,
            0,
            false,
            Bytes::from_static(b"original"),
            normal_intent(5),
        )
        .unwrap();

        svc.inbound_handler().handle(OverlayInboundMessage {
            from: 11,
            origin_boot_epoch: 0,
            level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body: original,
            remote_playout_delay_ms: None,
            is_distribution_repair: false,
        });
        let buffered_original = send::build_envelope(
            0xABC,
            shitspeak_core::default_server_id(),
            42,
            2,
            0,
            false,
            Bytes::from_static(b"buffered-original"),
            normal_intent(5),
        )
        .unwrap();
        svc.inbound_handler().handle(OverlayInboundMessage {
            from: 11,
            origin_boot_epoch: 0,
            level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body: buffered_original,
            remote_playout_delay_ms: None,
            is_distribution_repair: false,
        });
        let repair = send::build_envelope(
            0xABC,
            shitspeak_core::default_server_id(),
            42,
            1,
            0,
            false,
            Bytes::from_static(b"repair"),
            normal_intent(5),
        )
        .unwrap();
        svc.inbound_handler().handle(OverlayInboundMessage {
            from: 11,
            origin_boot_epoch: 0,
            level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body: repair,
            remote_playout_delay_ms: None,
            is_distribution_repair: true,
        });

        for _ in 0..50 {
            if sink.snapshot().len() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(sink.snapshot(), vec![false, true, false]);
    }

    #[derive(Default)]
    struct FecProbeSink {
        frames: Mutex<Vec<(u64, Bytes)>>,
    }

    impl FecProbeSink {
        fn snapshot(&self) -> Vec<(u64, Bytes)> {
            self.frames.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl AudioSink for FecProbeSink {
        async fn deliver(&self, _from: NodeIdentifier, frame: VoiceFrame, _is_repair: bool) {
            self.frames.lock().unwrap().push((frame.s2s_seq, frame.payload));
        }
    }

    async fn wait_for_fec_sink(sink: &FecProbeSink, len: usize) -> Vec<(u64, Bytes)> {
        for _ in 0..50 {
            let snapshot = sink.snapshot();
            if snapshot.len() >= len {
                return snapshot;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        sink.snapshot()
    }

    fn fec_data_frame(seq: u64, payload: &[u8]) -> Bytes {
        let frame = VoiceFrame {
            sender_session: 0xABC,
            server_id: shitspeak_core::default_server_id(),
            sender_epoch: 42,
            s2s_seq: seq,
            target_kind: 0,
            is_terminator: false,
            payload: Bytes::copy_from_slice(payload),
            intent: None,
            proactive_copy: false,
            fec_parity: false,
            fec_member_seqs: Vec::new(),
            fec_terminator_mask: 0,
            fec_parity_index: 0,
        };
        Bytes::from(proto::encode_voice(&frame).unwrap())
    }

    fn fec_parity_frame(
        sender_session: u32,
        sender_epoch: u64,
        member_seqs: Vec<u64>,
        parity: &[u8],
        parity_index: u32,
        terminator_mask: u32,
    ) -> Bytes {
        let frame = VoiceFrame {
            sender_session,
            server_id: shitspeak_core::default_server_id(),
            sender_epoch,
            s2s_seq: *member_seqs.last().unwrap(),
            target_kind: 0,
            is_terminator: false,
            payload: Bytes::copy_from_slice(parity),
            intent: None,
            proactive_copy: false,
            fec_parity: true,
            fec_member_seqs: member_seqs,
            fec_terminator_mask: terminator_mask,
            fec_parity_index: parity_index,
        };
        Bytes::from(proto::encode_voice(&frame).unwrap())
    }

    fn fec_xor(payloads: &[&[u8]]) -> Vec<u8> {
        let mut acc = vec![0u8; payloads[0].len()];
        for payload in payloads {
            for (index, byte) in payload.iter().copied().enumerate() {
                acc[index] ^= byte;
            }
        }
        acc
    }

    /// GF(2^8)-weighted parity (parity index 1) for the test helper's payloads:
    /// byte-wise `2^member_index · payload`, XORed across members.
    fn fec_gf_parity(payloads: &[&[u8]]) -> Vec<u8> {
        let mut acc = vec![0u8; payloads[0].len()];
        for (index, payload) in payloads.iter().enumerate() {
            let coefficient = fec::gf_pow2(index as u8);
            for (byte, &value) in payload.iter().enumerate() {
                acc[byte] ^= fec::gf_mul(coefficient, value);
            }
        }
        acc
    }

    fn inject_voice_inbound(svc: &VoiceService, from: NodeIdentifier, body: Bytes) {
        svc.inbound_handler().handle(OverlayInboundMessage {
            from,
            origin_boot_epoch: 0,
            level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body,
            remote_playout_delay_ms: None,
            is_distribution_repair: false,
        });
    }

    #[tokio::test]
    async fn fec_send_emits_parity_only_when_loss_gate_is_met() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        // Loss below the gate (0.1% < 1%): no parity may ever leave.
        for &dst in &[1u16, 2, 3] {
            transport.set_voice_route_quality(
                dst,
                VoiceRouteQuality::new(dst, TransportKind::Udp, 1_000, 1_000, 100),
            );
        }
        let mut cfg = VoiceConfig::default();
        cfg.voice_fec_enabled = true;
        cfg.voice_fec_block_size = 4;
        cfg.voice_fec_loss_gate_ppm = 10_000;
        cfg.tree_delivery_enabled = false;
        let svc = VoiceService::new_with_transport(
            transport.clone(),
            cfg,
            CancellationToken::new(),
            42,
        );
        for _ in 0..4 {
            svc.send_broadcast(
                0xABC,
                shitspeak_core::default_server_id(),
                0,
                false,
                Bytes::from_static(b"abcd"),
                normal_intent(5),
            )
            .await
            .unwrap();
        }
        for call in transport.calls() {
            if let FakeCall::Multicast { body, .. } = call {
                let frame = proto::decode_voice(&body).unwrap();
                assert!(!frame.fec_parity, "parity emitted below the loss gate");
            }
        }

        // Loss above the gate (5% >= 1%): the next block emits parity.
        for &dst in &[1u16, 2, 3] {
            transport.set_voice_route_quality(
                dst,
                VoiceRouteQuality::new(dst, TransportKind::Udp, 1_000, 50_000, 100),
            );
        }
        let calls_before = transport.calls().len();
        for _ in 0..4 {
            svc.send_broadcast(
                0xABC,
                shitspeak_core::default_server_id(),
                0,
                false,
                Bytes::from_static(b"abcd"),
                normal_intent(5),
            )
            .await
            .unwrap();
        }
        let parity = transport.calls()[calls_before..].iter().find_map(|call| {
            if let FakeCall::Multicast { body, .. } = call {
                let frame = proto::decode_voice(body).ok()?;
                return frame.fec_parity.then_some(frame);
            }
            None
        });
        let parity = parity.expect("parity frame should be emitted above the loss gate");
        assert_eq!(parity.fec_member_seqs, vec![4, 5, 6, 7]);
        assert_eq!(parity.payload.len(), 4);
        assert_eq!(parity.s2s_seq, 7);

        // Selected transport loss below the gate (0.005% < 1%) but the
        // datagram lane that actually carries best-effort voice is above it
        // (5% >= 1%): the gate must key on the datagram lane, not the
        // routing-selected best transport. This is the 4->8 case — QUIC is
        // near-lossless while UDP/KCP carry the voice at ~2-3% effective loss.
        for &dst in &[1u16, 2, 3] {
            transport.set_voice_route_quality(
                dst,
                VoiceRouteQuality::new(dst, TransportKind::Quic, 1_000, 50, 100)
                    .with_datagram_loss_ppm(Some(50_000)),
            );
        }
        let calls_before = transport.calls().len();
        for _ in 0..4 {
            svc.send_broadcast(
                0xABC,
                shitspeak_core::default_server_id(),
                0,
                false,
                Bytes::from_static(b"abcd"),
                normal_intent(5),
            )
            .await
            .unwrap();
        }
        let parity = transport.calls()[calls_before..].iter().find_map(|call| {
            if let FakeCall::Multicast { body, .. } = call {
                let frame = proto::decode_voice(body).ok()?;
                return frame.fec_parity.then_some(frame);
            }
            None
        });
        let parity = parity.expect(
            "parity frame should be emitted when the datagram lane clears the gate even though \
             the selected transport does not",
        );
        assert_eq!(parity.fec_member_seqs, vec![8, 9, 10, 11]);
        assert_eq!(parity.payload.len(), 4);
        assert_eq!(parity.s2s_seq, 11);
    }

    #[tokio::test]
    async fn fec_receiver_reconstructs_missing_frame() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let mut cfg = VoiceConfig::default();
        cfg.voice_fec_enabled = true;
        cfg.voice_fec_receiver_window = 8;
        let svc = VoiceService::new_with_transport(
            transport,
            cfg,
            CancellationToken::new(),
            42,
        );
        let sink = Arc::new(FecProbeSink::default());
        svc.set_audio_sink(sink.clone());

        // Frames 1,2,3 arrive; frame 4 is lost on the wire.
        inject_voice_inbound(&svc, 11, fec_data_frame(1, b"aaaa"));
        inject_voice_inbound(&svc, 11, fec_data_frame(2, b"bbbb"));
        inject_voice_inbound(&svc, 11, fec_data_frame(3, b"cccc"));
        wait_for_fec_sink(&sink, 3).await;

        // Parity block {1,2,3,4}: recovered 4 = parity ^ a ^ b ^ c = d.
        let parity = fec_xor(&[b"aaaa", b"bbbb", b"cccc", b"dddd"]);
        inject_voice_inbound(&svc, 11, fec_parity_frame(0xABC, 42, vec![1, 2, 3, 4], &parity, 0, 0));

        let frames = wait_for_fec_sink(&sink, 4).await;
        assert_eq!(frames[3].0, 4);
        assert_eq!(frames[3].1.as_ref(), b"dddd");
    }

    #[tokio::test]
    async fn fec_receiver_reconstructs_gap_frame_on_gap_open() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let mut cfg = VoiceConfig::default();
        cfg.voice_fec_enabled = true;
        cfg.voice_fec_receiver_window = 8;
        let svc = VoiceService::new_with_transport(transport, cfg, CancellationToken::new(), 42);
        let sink = Arc::new(FecProbeSink::default());
        svc.set_audio_sink(sink.clone());

        // Frames 1,2,3 deliver; frame 5 arrives before frame 4, opening the
        // gap [4,4]. The gap-open trigger must reconstruct 4 immediately
        // from the already-cached parity block.
        inject_voice_inbound(&svc, 11, fec_data_frame(1, b"aaaa"));
        inject_voice_inbound(&svc, 11, fec_data_frame(2, b"bbbb"));
        inject_voice_inbound(&svc, 11, fec_data_frame(3, b"cccc"));
        wait_for_fec_sink(&sink, 3).await;
        let parity = fec_xor(&[b"aaaa", b"bbbb", b"cccc", b"dddd"]);
        inject_voice_inbound(&svc, 11, fec_parity_frame(0xABC, 42, vec![1, 2, 3, 4], &parity, 0, 0));
        // Let the parity arrival settle into the mirror before the gap opens.
        tokio::time::sleep(Duration::from_millis(10)).await;
        inject_voice_inbound(&svc, 11, fec_data_frame(5, b"eeee"));

        let frames = wait_for_fec_sink(&sink, 5).await;
        assert_eq!(frames[3].0, 4);
        assert_eq!(frames[3].1.as_ref(), b"dddd");
        assert_eq!(frames[4].0, 5);
    }

    #[tokio::test]
    async fn fec_receiver_recovers_two_missing_frames_with_two_parities() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let mut cfg = VoiceConfig::default();
        cfg.voice_fec_enabled = true;
        cfg.voice_fec_receiver_window = 8;
        let svc = VoiceService::new_with_transport(transport, cfg, CancellationToken::new(), 42);
        let sink = Arc::new(FecProbeSink::default());
        svc.set_audio_sink(sink.clone());

        // Frames 1,2 arrive; frames 3,4 are lost on the wire.
        inject_voice_inbound(&svc, 11, fec_data_frame(1, b"aaaa"));
        inject_voice_inbound(&svc, 11, fec_data_frame(2, b"bbbb"));
        wait_for_fec_sink(&sink, 2).await;

        // Both parity frames for block {1,2,3,4}: index 0 (XOR) and index 1
        // (GF-weighted) together recover the two missing members.
        let members: [&[u8]; 4] = [b"aaaa", b"bbbb", b"cccc", b"dddd"];
        let xor_parity = fec_xor(&members);
        let gf_parity = fec_gf_parity(&members);
        inject_voice_inbound(
            &svc,
            11,
            fec_parity_frame(0xABC, 42, vec![1, 2, 3, 4], &xor_parity, 0, 0),
        );
        inject_voice_inbound(
            &svc,
            11,
            fec_parity_frame(0xABC, 42, vec![1, 2, 3, 4], &gf_parity, 1, 0),
        );

        let frames = wait_for_fec_sink(&sink, 4).await;
        assert_eq!(frames[2].0, 3);
        assert_eq!(frames[2].1.as_ref(), b"cccc");
        assert_eq!(frames[3].0, 4);
        assert_eq!(frames[3].1.as_ref(), b"dddd");
    }

    #[tokio::test]
    async fn ingress_drops_when_no_sink_installed() {
        let transport = FakeVoiceTransport::new(7, vec![1]);
        let svc = make_legacy_service(transport);
        let envelope = send::build_envelope(
            0xABC,
            shitspeak_core::default_server_id(),
            42,
            0,
            0,
            false,
            Bytes::from_static(b"x"),
            normal_intent(5),
        )
        .unwrap();
        svc.inbound_handler().handle(OverlayInboundMessage {
            from: 1,
            origin_boot_epoch: 0,
            level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body: envelope,
            remote_playout_delay_ms: None,
            is_distribution_repair: false,
        });
        // Give the dispatch task a chance to run; verify it doesn't panic.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn ingress_gap_requests_repair_immediately() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = VoiceService::new_with_transport(
            transport.clone(),
            VoiceConfig::default(),
            CancellationToken::new(),
            42,
        );
        let inbound = svc.inbound_handler();
        let sender_session = shitspeak_core::ClientSessionIdentifier::new(12, 0xABC)
            .unwrap()
            .to_u32();

        for seq in [0, 2] {
            let envelope = send::build_envelope(
                sender_session,
                shitspeak_core::default_server_id(),
                42,
                seq,
                0,
                false,
                Bytes::from(format!("opus-{seq}").into_bytes()),
                normal_intent(5),
            )
            .unwrap();
            inbound.handle(OverlayInboundMessage {
                from: 11,
                origin_boot_epoch: 0,
                level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
                class: shitspeak_s2s_transport::MessageClass::HighPriority,
                body: envelope,
                remote_playout_delay_ms: None,
                is_distribution_repair: false,
            });
        }

        let calls = wait_for_call_count(&transport, 1).await;
        match &calls[0] {
            FakeCall::RepairRequest { dst, body, ttl } => {
                assert_eq!(*dst, 12, "repair must target the origin, not relay 11");
                assert_eq!(
                    *ttl,
                    Duration::from_millis(VoiceConfig::default().repair_request_ttl_ms)
                );
                let request = proto::decode_voice_repair_request(body.as_ref()).unwrap();
                assert_eq!(request.sender_session, sender_session);
                assert_eq!(request.sender_epoch, 42);
                assert_eq!(request.first_seq, 1);
                assert_eq!(request.last_seq, 1);
                assert_eq!(request.request_sent_unix_ms, 0);
                assert!(
                    request.request_ttl_ms > 0
                        && u64::from(request.request_ttl_ms)
                            <= VoiceConfig::default().repair_request_ttl_ms,
                    "the request carries its remaining actionable deadline, not a rebased TTL"
                );
            }
            other => panic!("expected RepairRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ingress_enqueues_one_repair_request_for_an_open_gap() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = VoiceService::new_with_transport(
            transport.clone(),
            VoiceConfig::default(),
            CancellationToken::new(),
            42,
        );
        let inbound = svc.inbound_handler();
        let sender_session = shitspeak_core::ClientSessionIdentifier::new(12, 0xABC)
            .unwrap()
            .to_u32();

        for seq in [0, 2, 3, 4] {
            let envelope = send::build_envelope(
                sender_session,
                shitspeak_core::default_server_id(),
                42,
                seq,
                0,
                false,
                Bytes::from(format!("opus-{seq}").into_bytes()),
                normal_intent(5),
            )
            .unwrap();
            inbound.handle(OverlayInboundMessage {
                from: 11,
                origin_boot_epoch: 0,
                level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
                class: shitspeak_s2s_transport::MessageClass::HighPriority,
                body: envelope,
                remote_playout_delay_ms: None,
                is_distribution_repair: false,
            });
        }

        let calls = wait_for_call_count(&transport, 1).await;
        assert_eq!(
            calls
                .iter()
                .filter(|call| matches!(call, FakeCall::RepairRequest { .. }))
                .count(),
            1,
        );
    }

    #[tokio::test]
    async fn repair_handler_replays_cached_exact_frame() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_legacy_service(transport.clone());
        svc.send_unicast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            false,
            Bytes::from_static(b"opus-exact"),
            normal_intent(5),
            2,
        )
        .await
        .unwrap();
        let original = match &transport.calls()[0] {
            FakeCall::Unicast { body, .. } => body.clone(),
            other => panic!("expected Unicast, got {other:?}"),
        };
        svc.voice_budget
            .mint_link_credit(2, 0xABC, 42, usize::MAX);
        let request = VoiceRepairRequest {
            sender_session: 0xABC,
            sender_epoch: 42,
            first_seq: 0,
            last_seq: 0,
            request_sent_unix_ms: 0,
            request_ttl_ms: 0,
            tail_ack: false,
        };
        let request_body = proto::encode_voice_repair_request(&request).unwrap();
        svc.repair_inbound_handler().handle(OverlayInboundMessage {
            from: 2,
            origin_boot_epoch: 0,
            level: shitspeak_s2s_transport::ServiceLevel::ReliableLowLatency,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body: request_body,
            remote_playout_delay_ms: None,
            is_distribution_repair: false,
        });

        let calls = wait_for_call_count(&transport, 2).await;
        match &calls[1] {
            FakeCall::RepairFrame {
                dst,
                body,
                ttl,
                is_repair,
                ..
            } => {
                assert_eq!(*dst, 2);
                assert_eq!(body, &original);
                assert!(*is_repair);
                assert_eq!(
                    *ttl,
                    Duration::from_millis(VoiceConfig::default().repair_transport_ttl_ms)
                );
            }
            other => panic!("expected RepairFrame, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn repair_response_falls_back_when_alternate_first_hop_fails() {
        let inner = FakeVoiceTransport::new(7, vec![2]);
        inner.set_voice_route_quality(
            2,
            crate::overlay::VoiceRouteQuality::new(2, TransportKind::Udp, 0, 0, 0),
        );
        let transport: Arc<dyn VoiceTransport> = Arc::new(AlternateFailRepairTransport {
            inner: inner.clone(),
        });
        let cache = Arc::new(RepairCache::new(Duration::from_secs(1)));
        let sender_session = 0xABC;
        let body = send::build_envelope(
            sender_session,
            shitspeak_core::default_server_id(),
            42,
            7,
            0,
            false,
            Bytes::from_static(b"fallback-repair"),
            normal_intent(5),
        )
        .unwrap();
        cache.insert(RepairFrame::new(sender_session, 42, 7, body.clone()));
        // The repair response reserves from the link bucket for the first hop
        // the original took (destination 2; its alternate fails on purpose).
        let voice_budget = AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(5_000)));
        voice_budget.mint_link_credit(2, 0xABC, 42, usize::MAX);

        send_repair_response(
            RepairResponseRequest {
                from: 2,
                request: VoiceRepairRequest {
                    sender_session,
                    sender_epoch: 42,
                    first_seq: 7,
                    last_seq: 7,
                    request_sent_unix_ms: 0,
                    request_ttl_ms: 0,
                    tail_ack: false,
                },
                deadline: Instant::now() + Duration::from_secs(1),
            },
            transport,
            cache,
            &voice_budget,
            Arc::new(Semaphore::new(1)),
            Duration::from_millis(100),
        )
        .await;

        let calls = inner.calls();
        assert_eq!(calls.len(), 1);
        assert!(matches!(
            &calls[0],
            FakeCall::RepairFrame {
                dst: 2,
                body: sent,
                avoid_first_hop: None,
                is_repair: true,
                ..
            } if sent == &body
        ));
    }

    #[tokio::test]
    async fn repair_responses_overlap_across_requests_with_bounded_concurrency() {
        let transport = ControlledRepairTransport::new();
        let repair_cache = Arc::new(RepairCache::new(Duration::from_secs(1)));
        for (sender_session, s2s_seq, body) in [
            (100, 0, Bytes::from_static(b"a0")),
            (100, 1, Bytes::from_static(b"a1")),
            (200, 0, Bytes::from_static(b"b0")),
            (300, 0, Bytes::from_static(b"c0")),
        ] {
            repair_cache.insert(RepairFrame::new(sender_session, 42, s2s_seq, body));
        }

        let (tx, rx) = mpsc::channel(3);
        let shutdown = CancellationToken::new();
        let voice_budget = AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(5_000)));
        // One repair response per peer destination; each reserves from its
        // own per-first-hop link bucket.
        for peer in [2, 3, 4] {
            voice_budget.mint_link_credit(peer, 0, 0, usize::MAX);
        }
        spawn_repair_response_worker_with_concurrency(
            rx,
            transport.clone(),
            repair_cache,
            VoiceConfig::default(),
            voice_budget,
            shutdown.clone(),
            2,
        );
        for (from, sender_session, last_seq) in [(2, 100, 1), (3, 200, 0), (4, 300, 0)] {
            tx.send(RepairResponseRequest {
                from,
                request: VoiceRepairRequest {
                    sender_session,
                    sender_epoch: 42,
                    first_seq: 0,
                    last_seq,
                    request_sent_unix_ms: 0,
                    request_ttl_ms: 0,
                    tail_ack: false,
                },
                deadline: Instant::now() + Duration::from_secs(1),
            })
            .await
            .unwrap();
        }

        tokio::time::timeout(
            Duration::from_secs(1),
            transport.repair_entered.acquire_many(2),
        )
        .await
        .expect("two independent repair requests should overlap")
        .unwrap()
        .forget();
        assert_eq!(transport.active_repairs.load(Ordering::SeqCst), 2);
        assert_eq!(transport.max_active_repairs.load(Ordering::SeqCst), 2);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                transport.repair_entered.acquire()
            )
            .await
            .is_err(),
            "the third request must wait for a response slot"
        );

        transport.repair_release.add_permits(4);
        let calls = wait_for_call_count(&transport.inner, 4).await;
        for _ in 0..50 {
            if transport.active_repairs.load(Ordering::SeqCst) == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(transport.active_repairs.load(Ordering::SeqCst), 0);
        assert!(transport.max_active_repairs.load(Ordering::SeqCst) <= 2);

        let first_request_bodies: Vec<Bytes> = calls
            .iter()
            .filter_map(|call| match call {
                FakeCall::RepairFrame { dst: 2, body, .. } => Some(body.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            first_request_bodies,
            vec![Bytes::from_static(b"a0"), Bytes::from_static(b"a1")],
            "frames within one request must retain cache sequence order"
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn overlapping_nack_does_not_replay_the_in_flight_or_completed_prefix() {
        let transport = ControlledRepairTransport::new();
        let repair_cache = Arc::new(RepairCache::new(Duration::from_secs(1)));
        for seq in 0..=4 {
            repair_cache.insert(RepairFrame::new(100, 42, seq, Bytes::from(vec![seq as u8])));
        }
        let (tx, rx) = mpsc::channel(4);
        let shutdown = CancellationToken::new();
        let voice_budget = AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(5_000)));
        voice_budget.mint_link_credit(2, 0, 0, usize::MAX);
        spawn_repair_response_worker_with_concurrency(
            rx,
            transport.clone(),
            repair_cache,
            VoiceConfig::default(),
            voice_budget,
            shutdown.clone(),
            2,
        );
        let work = RepairResponseRequest {
            from: 2,
            request: VoiceRepairRequest {
                sender_session: 100,
                sender_epoch: 42,
                first_seq: 0,
                last_seq: 2,
                request_sent_unix_ms: 0,
                request_ttl_ms: 0,
                tail_ack: false,
            },
            deadline: Instant::now() + Duration::from_secs(1),
        };
        tx.send(work.clone()).await.unwrap();
        tokio::time::timeout(
            Duration::from_millis(100),
            transport.repair_entered.acquire(),
        )
        .await
        .expect("first response frame should start")
        .unwrap()
        .forget();
        let mut first_overlap = work.clone();
        first_overlap.request.first_seq = 1;
        first_overlap.request.last_seq = 3;
        tx.send(first_overlap).await.unwrap();
        let mut later_overlap = work;
        later_overlap.request.first_seq = 2;
        later_overlap.request.last_seq = 4;
        tx.send(later_overlap).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        transport.repair_release.add_permits(5);
        let calls = wait_for_call_count(&transport.inner, 5).await;
        let bodies = calls
            .iter()
            .filter_map(|call| match call {
                FakeCall::RepairFrame { body, .. } => Some(body.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            bodies,
            vec![
                Bytes::from_static(&[0]),
                Bytes::from_static(&[1]),
                Bytes::from_static(&[2]),
                Bytes::from_static(&[3]),
                Bytes::from_static(&[4]),
            ]
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn repair_response_coalesces_overlap_and_replays_once_after_send_failure() {
        let transport = ControlledRepairTransport::with_failures(2);
        let repair_cache = Arc::new(RepairCache::new(Duration::from_secs(1)));
        repair_cache.insert(RepairFrame::new(100, 42, 0, Bytes::from_static(b"retry-0")));

        let (tx, rx) = mpsc::channel(16);
        let shutdown = CancellationToken::new();
        let voice_budget = AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(5_000)));
        voice_budget.mint_link_credit(2, 0, 0, usize::MAX);
        spawn_repair_response_worker_with_concurrency(
            rx,
            transport.clone(),
            repair_cache,
            VoiceConfig::default(),
            voice_budget,
            shutdown.clone(),
            2,
        );
        let work = RepairResponseRequest {
            from: 2,
            request: VoiceRepairRequest {
                sender_session: 100,
                sender_epoch: 42,
                first_seq: 0,
                last_seq: 0,
                request_sent_unix_ms: 0,
                request_ttl_ms: 0,
                tail_ack: false,
            },
            deadline: Instant::now() + Duration::from_secs(1),
        };
        tx.send(work.clone()).await.unwrap();
        tokio::time::timeout(
            Duration::from_millis(100),
            transport.repair_entered.acquire(),
        )
        .await
        .expect("the first response should start")
        .unwrap()
        .forget();

        for _ in 0..10 {
            tx.send(work.clone()).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(transport.active_repairs.load(Ordering::SeqCst), 1);
        transport.repair_release.add_permits(1);

        tokio::time::timeout(
            Duration::from_millis(100),
            transport.repair_entered.acquire(),
        )
        .await
        .expect("the bounded admission retry should follow the first rejection")
        .unwrap()
        .forget();
        transport.repair_release.add_permits(1);
        for _ in 0..50 {
            if transport.active_repairs.load(Ordering::SeqCst) == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }

        assert_eq!(
            transport.inner.calls().len(),
            2,
            "overlap received during the in-flight frame must not replay that frame"
        );
        assert_eq!(transport.max_active_repairs.load(Ordering::SeqCst), 1);
        shutdown.cancel();
    }

    #[tokio::test]
    async fn cold_start_nack_waits_for_sufficient_accepted_original_credit() {
        let transport = ControlledUnicastTransport::new(false);
        let svc = VoiceService::new_with_transport(
            transport.clone(),
            VoiceConfig::default(),
            CancellationToken::new(),
            42,
        );
        let send = tokio::spawn({
            let svc = svc.clone();
            async move {
                svc.send_unicast(
                    0xABC,
                    shitspeak_core::default_server_id(),
                    0,
                    false,
                    Bytes::from_static(b"pending-original"),
                    normal_intent(5),
                    2,
                )
                .await
            }
        });
        transport.primary_entered.acquire().await.unwrap().forget();
        let original = match &transport.inner.calls()[0] {
            FakeCall::Unicast { body, .. } => body.clone(),
            other => panic!("expected pending unicast, got {other:?}"),
        };
        let request = VoiceRepairRequest {
            sender_session: 0xABC,
            sender_epoch: 42,
            first_seq: 0,
            last_seq: 0,
            request_sent_unix_ms: 0,
            request_ttl_ms: 0,
            tail_ack: false,
        };
        svc.repair_inbound_handler().handle(OverlayInboundMessage {
            from: 3,
            origin_boot_epoch: 0,
            level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body: proto::encode_voice_repair_request(&request).unwrap(),
            remote_playout_delay_ms: None,
            is_distribution_repair: false,
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(transport.inner.calls().len(), 1);

        svc.voice_budget
            .mint_link_credit(3, 0xABC, 42, usize::MAX);
        let calls = wait_for_call_count(&transport.inner, 2).await;
        match &calls[1] {
            FakeCall::RepairFrame {
                body, is_repair, ..
            } => {
                assert_eq!(body, &original);
                assert!(*is_repair);
                assert!(!proto::decode_voice(body).unwrap().proactive_copy);
            }
            other => panic!("expected repair while primary is pending, got {other:?}"),
        }
        transport.primary_release.add_permits(1);
        send.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn failed_primary_send_mints_no_credit_and_queues_no_proactive_copy() {
        let transport = ControlledUnicastTransport::new(true);
        transport.inner.set_voice_route_quality(
            2,
            crate::overlay::VoiceRouteQuality::new(
                2,
                TransportKind::Udp,
                20_000,
                VoiceConfig::default().repair_full_dup_loss_ppm,
                0,
            ),
        );
        let svc = VoiceService::new_with_transport(
            transport.clone(),
            VoiceConfig::default(),
            CancellationToken::new(),
            42,
        );
        transport.primary_release.add_permits(1);
        let result = svc
            .send_unicast(
                0xABC,
                shitspeak_core::default_server_id(),
                0,
                false,
                Bytes::from_static(b"failed-original"),
                normal_intent(5),
                2,
            )
            .await;

        assert!(result.is_err());
        let calls = transport.inner.calls();
        assert_eq!(calls.len(), 1);
        let original_bytes = match &calls[0] {
            FakeCall::Unicast { body, .. } => body.len(),
            other => panic!("expected failed original attempt, got {other:?}"),
        };
        assert_eq!(
            svc.voice_budget.proactive_credit_balance_quarters(),
            0,
            "a rejected primary does not mint repair credit for its {original_bytes} bytes"
        );
        assert_eq!(transport.inner.route_quality_batches(), vec![vec![2]]);
        assert_eq!(transport.inner.route_quality_scalar_calls(), 0);
    }

    #[tokio::test]
    async fn failed_terminator_captures_quality_once_and_cancels_tail_repair() {
        let transport = ControlledUnicastTransport::new(true);
        transport.inner.set_voice_route_quality(
            2,
            VoiceRouteQuality::new(2, TransportKind::Udp, 20_000, 0, 0),
        );
        let svc = VoiceService::new_with_transport(
            transport.clone(),
            VoiceConfig::default(),
            CancellationToken::new(),
            42,
        );
        transport.primary_release.add_permits(1);

        let result = svc
            .send_unicast(
                0xABC,
                shitspeak_core::default_server_id(),
                0,
                true,
                Bytes::from_static(b"failed-terminator"),
                normal_intent(5),
                2,
            )
            .await;

        assert!(result.is_err());
        assert_eq!(transport.inner.route_quality_batches(), vec![vec![2]]);
        assert_eq!(transport.inner.route_quality_scalar_calls(), 0);
        assert!(svc.tail_repairs.lock().is_empty());
    }

    #[tokio::test]
    async fn terminator_reuses_one_quality_batch_for_tail_and_proactive_repairs() {
        let transport = FakeVoiceTransport::new(7, vec![2, 3]);
        transport.set_voice_route_quality(
            2,
            VoiceRouteQuality::new(2, TransportKind::Udp, 20_000, 0, 0),
        );
        transport.set_voice_route_quality(
            3,
            VoiceRouteQuality::new(3, TransportKind::Udp, 40_000, 0, 0),
        );
        let svc = make_legacy_service(transport.clone());

        svc.send_multicast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            true,
            Bytes::from_static(b"terminator"),
            normal_intent(5),
            &[2, 3],
        )
        .await
        .unwrap();

        assert_eq!(transport.route_quality_batches(), vec![vec![2, 3]]);
        assert_eq!(transport.route_quality_scalar_calls(), 0);
        assert_eq!(svc.tail_repairs.lock().len(), 2);
    }

    #[tokio::test]
    async fn repair_disabled_send_captures_no_route_quality() {
        let transport = FakeVoiceTransport::new(7, vec![2]);
        transport.set_voice_route_quality(
            2,
            VoiceRouteQuality::new(2, TransportKind::Udp, 20_000, 1_000_000, 0),
        );
        let mut cfg = VoiceConfig::default();
        cfg.repair_enabled = false;
        cfg.tree_delivery_enabled = false;
        let svc =
            VoiceService::new_with_transport(transport.clone(), cfg, CancellationToken::new(), 42);

        svc.send_unicast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            false,
            Bytes::from_static(b"repair-disabled"),
            normal_intent(5),
            2,
        )
        .await
        .unwrap();

        assert!(transport.route_quality_batches().is_empty());
        assert_eq!(transport.route_quality_scalar_calls(), 0);
    }

    #[tokio::test]
    async fn ordinary_send_captures_one_aligned_batch_before_pressure_filtering() {
        let transport = FakeVoiceTransport::new(7, vec![2, 3]);
        let svc = make_legacy_service(transport.clone());
        svc.proactive_pressure.record_failure(2, Instant::now());

        svc.send_multicast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            false,
            Bytes::from_static(b"pressure-filter"),
            normal_intent(5),
            &[2, 3],
        )
        .await
        .unwrap();

        assert_eq!(transport.route_quality_batches(), vec![vec![2, 3]]);
        assert_eq!(transport.route_quality_scalar_calls(), 0);
    }

    #[tokio::test]
    async fn proactive_repairs_reuse_the_pre_send_quality_snapshot() {
        let transport = ControlledUnicastTransport::new(false);
        let captured = VoiceRouteQuality::new(
            2,
            TransportKind::Udp,
            20_000,
            VoiceConfig::default().repair_full_dup_loss_ppm,
            0,
        )
        .with_alternate_route_quality(3, 10_000, TransportKind::Quic, 0, 0);
        transport.inner.set_voice_route_quality(2, captured);
        let svc = VoiceService::new_with_transport(
            transport.clone(),
            VoiceConfig::default(),
            CancellationToken::new(),
            42,
        );
        svc.voice_budget
            .mint_link_credit(3, 0xABC, 42, usize::MAX);
        let send = tokio::spawn({
            let svc = svc.clone();
            async move {
                svc.send_unicast(
                    0xABC,
                    shitspeak_core::default_server_id(),
                    0,
                    false,
                    Bytes::from_static(b"snapshot"),
                    normal_intent(5),
                    2,
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(1), transport.primary_entered.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        assert_eq!(transport.inner.route_quality_batches(), vec![vec![2]]);
        transport.inner.set_voice_route_quality(
            2,
            VoiceRouteQuality::new(2, TransportKind::Udp, 20_000, 0, 0),
        );
        transport.primary_release.add_permits(1);
        send.await.unwrap().unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            transport.proactive_entered.acquire(),
        )
        .await
        .expect("captured alternate should remain eligible")
        .unwrap()
        .forget();
        transport.proactive_release.add_permits(1);
        assert_eq!(transport.inner.route_quality_batches(), vec![vec![2]]);
        assert_eq!(transport.inner.route_quality_scalar_calls(), 0);
    }

    #[tokio::test]
    async fn expired_or_zero_utility_candidates_are_filtered_before_credit_reservation() {
        let transport = FakeVoiceTransport::new(7, vec![2]);
        let svc = make_legacy_service(transport.clone());
        svc.voice_budget.mint_proactive_credit(1_024);
        let quality = VoiceRouteQuality::new(
            2,
            TransportKind::Udp,
            20_000,
            VoiceConfig::default().repair_full_dup_loss_ppm,
            0,
        )
        .with_alternate_route_quality(3, 10_000, TransportKind::Quic, 0, 0);
        let (mut expired, _) = svc
            .encode(
                0xABC,
                shitspeak_core::default_server_id(),
                0,
                false,
                Bytes::from_static(b"expired"),
                normal_intent(5),
            )
            .unwrap();
        svc.refresh_cache_and_queue_proactive_repairs(
            0xABC,
            1,
            &mut expired,
            false,
            &[2],
            Some(&RepairFrameContext {
                deadline_origin: Instant::now() - Duration::from_secs(1),
                route_qualities: vec![Some(quality)],
            }),
        );

        let (mut unmeasured, _) = svc
            .encode(
                0xABC,
                shitspeak_core::default_server_id(),
                0,
                false,
                Bytes::from_static(b"unmeasured"),
                normal_intent(5),
            )
            .unwrap();
        svc.refresh_cache_and_queue_proactive_repairs(
            0xABC,
            2,
            &mut unmeasured,
            false,
            &[2],
            Some(&RepairFrameContext {
                deadline_origin: Instant::now(),
                route_qualities: vec![Some(VoiceRouteQuality::new(
                    2,
                    TransportKind::Udp,
                    20_000,
                    VoiceConfig::default().repair_full_dup_loss_ppm,
                    0,
                ))],
            }),
        );
        tokio::task::yield_now().await;
        assert!(transport.calls().is_empty());
        assert_eq!(svc.voice_budget.proactive_reserved_bytes(), 0);
        assert_eq!(svc.voice_budget.proactive_credit_balance_bytes(), 256);
    }

    #[test]
    fn proactive_copy_demand_sampling_remains_fractional_and_deterministic() {
        assert_eq!(proactive_repair_extra_copy_count(2, 250_000, 499_999), 1);
        assert_eq!(proactive_repair_extra_copy_count(2, 250_000, 500_000), 0);
        assert_eq!(proactive_repair_extra_copy_count(2, 500_000, 999_999), 1);
        assert_eq!(proactive_repair_extra_copy_count(2, 750_000, 499_999), 2);
        assert_eq!(proactive_repair_extra_copy_count(2, 750_000, 500_000), 1);
        assert_eq!(proactive_repair_extra_copy_count(2, 1_000_000, 999_999), 2);
        assert_eq!(
            proactive_repair_sample(2, 77),
            proactive_repair_sample(2, 77)
        );
    }

    #[tokio::test]
    async fn repair_handler_accepts_timestamped_request_without_clock_agreement() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = make_legacy_service(transport.clone());
        svc.send_unicast(
            0xABC,
            shitspeak_core::default_server_id(),
            0,
            false,
            Bytes::from_static(b"opus-exact"),
            normal_intent(5),
            2,
        )
        .await
        .unwrap();
        svc.voice_budget
            .mint_link_credit(2, 0xABC, 42, usize::MAX);
        let request = VoiceRepairRequest {
            sender_session: 0xABC,
            sender_epoch: 42,
            first_seq: 0,
            last_seq: 0,
            request_sent_unix_ms: 1,
            request_ttl_ms: 1,
            tail_ack: false,
        };
        let request_body = proto::encode_voice_repair_request(&request).unwrap();
        svc.repair_inbound_handler().handle(OverlayInboundMessage {
            from: 2,
            origin_boot_epoch: 0,
            level: shitspeak_s2s_transport::ServiceLevel::BestEffort,
            class: shitspeak_s2s_transport::MessageClass::HighPriority,
            body: request_body,
            remote_playout_delay_ms: None,
            is_distribution_repair: false,
        });

        let calls = wait_for_call_count(&transport, 2).await;
        assert!(matches!(calls[1], FakeCall::RepairFrame { .. }));
    }

    #[tokio::test]
    async fn per_session_counters_independent() {
        let transport = FakeVoiceTransport::new(7, vec![1]);
        let svc = make_legacy_service(transport.clone());
        for session in [0xAAA, 0xBBB] {
            for _ in 0..3 {
                svc.send_broadcast(
                    session,
                    shitspeak_core::default_server_id(),
                    0,
                    false,
                    Bytes::from_static(b"x"),
                    normal_intent(5),
                )
                .await
                .unwrap();
            }
        }
        let calls = transport.calls();
        assert_eq!(calls.len(), 6);
        let seqs: Vec<(u32, u64)> = calls
            .iter()
            .map(|c| match c {
                FakeCall::Multicast { body, .. } => {
                    let f = proto::decode_voice(body.as_ref()).unwrap();
                    (f.sender_session, f.s2s_seq)
                }
                _ => panic!(),
            })
            .collect();
        assert_eq!(
            seqs,
            vec![
                (0xAAA, 0),
                (0xAAA, 1),
                (0xAAA, 2),
                (0xBBB, 0),
                (0xBBB, 1),
                (0xBBB, 2),
            ]
        );
    }
}
