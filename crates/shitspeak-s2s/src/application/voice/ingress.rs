//! Inbound `VoiceFrame` decode + central dispatch task, and the
//! speaker-side public API (`VoiceService`).
//!
//! The dispatch task decodes `VoiceFrame`s, applies the reorder gate, and
//! hands emitted frames to the installed audio sink. The speaker-side API
//! wraps already-encoded audio payloads with unresolved routing intent.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::RwLock;
use scc::HashMap as SccMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::trace;

use crate::application::config::{DeliveryStrategy, VoiceConfig};
use crate::application::error::ApplicationError;
use crate::application::proto::{
    self, VoiceFrame, VoiceIntent, VoiceIntentKind, VoiceIntentNormal, VoicePathFeedback,
};
use crate::application::voice::budget::{ProactiveCreditPermit, ProactiveCreditRequest};
use crate::application::voice::fec;
use crate::application::voice::metrics;
use crate::application::voice::metrics::{
    VoiceIngressClass, VoiceProactiveKind, VoiceProactiveResult, VoiceReceiveResult,
    VoiceRepairResult, VoiceSendMode, VoiceSendResult,
};
use crate::application::voice::proactive_utility::proactive_marginal_utility_micros;
use crate::application::voice::reorder::{self, Reorderer, VoiceCopyKind, VoiceRouteHint};
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

const DISTANT_REPAIR_PATH_LATENCY_US: u64 = 150_000;
const PROACTIVE_WORKER_CONCURRENCY: usize = 4;
const PROACTIVE_FAILURE_BACKOFF_INITIAL: Duration = Duration::from_millis(50);
const PROACTIVE_FAILURE_BACKOFF_MAX: Duration = Duration::from_millis(800);
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

/// Work whose byte reservation remains live until serialized dispatch has
/// processed the frame. The unbounded lane is therefore still byte bounded,
/// except for FEC parity, which is exempt from the byte budget and bounded by
/// the sender's parity rate instead.
struct InboundVoiceWork {
    delivery: VoiceDelivery,
    _permit: Option<VoiceBytePermit>,
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
        let window = windows
            .entry(from)
            .or_insert_with(|| PathFeedbackWindow::new(now));
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
        let window = windows
            .entry(from)
            .or_insert_with(|| PathFeedbackWindow::new(now));
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
    shutdown: CancellationToken,
    primary_inbox_tx: mpsc::UnboundedSender<InboundVoiceWork>,
    proactive_inbox_tx: mpsc::UnboundedSender<InboundVoiceWork>,
    proactive_send_tx: mpsc::UnboundedSender<ProactiveSendWork>,
    proactive_pressure: Arc<ProactivePressureState>,

    /// Live byte and speaker admission limits derived from runtime capacity.
    voice_budget: AdaptiveVoiceBudget,

    /// Set once at construction from the overlay's `local_boot_epoch`.
    sender_epoch: u64,

    /// Per-local-sender-session monotonic counter for `s2s_seq`. Keyed
    /// by composite `ClientSessionIdentifier::to_u32()`.
    seq_counters: Arc<SccMap<u32, AtomicU64>>,

    /// Sender-side FEC windows per speaker, link, and recipient set.
    fec_sender: Arc<fec::FecSenderState>,

    /// Receiver-side delivery callback. Hot-swappable so the `Server`
    /// can install its sink after construction. `None` until set —
    /// frames are decoded and dropped (with a trace) until then.
    audio_sink: AudioSinkSlot,

    /// Per-speaker reorder gate.
    _reorderer: Arc<Reorderer>,

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
        let transport: Arc<dyn VoiceTransport> = Arc::new(send::FecVoiceTransport::new(
            transport,
            &cfg,
            shutdown.clone(),
        ));
        let voice_budget = AdaptiveVoiceBudget::new(max_users.clone());
        publish_proactive_budget(&voice_budget);
        let (primary_inbox_tx, primary_inbox_rx) = mpsc::unbounded_channel::<InboundVoiceWork>();
        let (proactive_inbox_tx, proactive_inbox_rx) =
            mpsc::unbounded_channel::<InboundVoiceWork>();
        let (deadline_tx, deadline_rx) = mpsc::channel::<()>(1);
        let (proactive_send_tx, proactive_send_rx) = mpsc::unbounded_channel::<ProactiveSendWork>();
        let proactive_pressure = Arc::new(ProactivePressureState::default());
        let audio_sink: AudioSinkSlot = Arc::new(RwLock::new(None));
        let reorderer = Reorderer::new_with_capacity_source(cfg.clone(), max_users);
        let path_feedback = Arc::new(PathFeedbackAccumulator::default());
        let fec_state = Arc::new(fec::ReceiverFecState::new(fec::receiver_window_for(
            cfg.voice_fec_receiver_window,
            cfg.voice_fec_block_size,
            cfg.voice_fec_interleave_depth,
        )));
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
        reorder::spawn_deadline_task(reorderer.clone(), shutdown.clone(), move || {
            let _ = deadline_tx.try_send(());
        });
        let delivery_strategy = DeliveryStrategy::parse(&cfg.delivery_strategy);
        let fec_sender = Arc::new(fec::FecSenderState::new(
            cfg.voice_fec_block_size,
            cfg.voice_fec_parity_blocks,
            cfg.voice_fec_interleave_depth,
        ));
        Arc::new(Self {
            transport,
            cfg,
            shutdown,
            primary_inbox_tx,
            proactive_inbox_tx,
            proactive_send_tx,
            proactive_pressure,
            voice_budget,
            sender_epoch,
            seq_counters: Arc::new(SccMap::new()),
            fec_sender,
            audio_sink,
            _reorderer: reorderer,
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

    /// Accepts and discards repair requests and tail ACKs from peers that
    /// still run reactive repair. Remove once every peer runs a release
    /// without it.
    pub fn repair_inbound_handler(&self) -> Arc<dyn ServiceInbound> {
        Arc::new(VoiceRepairInbound)
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
        result?;
        let fec_payload = envelope.payload();
        self.emit_fec_if_due(
            sender_session,
            seq,
            &fec_payload,
            is_terminator,
            &dsts,
            repair_context.as_ref(),
            self.cfg
                .tree_delivery_enabled
                .then(DistributionGroup::broadcast),
        )
        .await;
        self.admit_original_repair_credit(
            sender_session,
            &dsts,
            repair_context.as_ref(),
            bytes.len(),
        );
        self.refresh_cache_and_queue_proactive_repairs(
            sender_session,
            seq,
            &mut envelope,
            is_terminator,
            &dsts,
            repair_context.as_ref(),
        );
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
        result?;
        let fec_payload = envelope.payload();
        self.emit_fec_if_due(
            sender_session,
            seq,
            &fec_payload,
            is_terminator,
            dsts,
            repair_context.as_ref(),
            self.cfg.tree_delivery_enabled.then_some(group),
        )
        .await;
        self.admit_original_repair_credit(
            sender_session,
            dsts,
            repair_context.as_ref(),
            bytes.len(),
        );
        self.refresh_cache_and_queue_proactive_repairs(
            sender_session,
            seq,
            &mut envelope,
            is_terminator,
            dsts,
            repair_context.as_ref(),
        );
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
        result?;
        let fec_payload = envelope.payload();
        self.emit_fec_if_due(
            sender_session,
            seq,
            &fec_payload,
            is_terminator,
            &[dst],
            repair_context.as_ref(),
            None,
        )
        .await;
        self.admit_original_repair_credit(
            sender_session,
            &[dst],
            repair_context.as_ref(),
            bytes.len(),
        );
        self.refresh_cache_and_queue_proactive_repairs(
            sender_session,
            seq,
            &mut envelope,
            is_terminator,
            &[dst],
            repair_context.as_ref(),
        );
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

    /// Feed the just-sent frame into the sender FEC streams and emit the
    /// parity it made due. Parity follows the data's route so the listener
    /// receives both at the same latency: tree voice (`tree_group`) sends it
    /// into the same distribution tree, group and recipients as the data, so
    /// every edge carries it along its own binding (direct, relay, or split).
    /// Routed voice groups destinations by the data's first hop and sends
    /// parity there, or over the route's alternate first hop when that path's
    /// metrics can carry it (a burst on the data path cannot then take the
    /// parity too). Only destinations over an unreliable voice transport get
    /// parity. Measured loss does not gate protection and parity is not
    /// charged to a byte budget; only a routed first hop whose datagram lane
    /// is shedding at the send path skips the parity it would carry. Rows
    /// owed after a terminator are paced out by a background task.
    #[allow(clippy::too_many_arguments)]
    async fn emit_fec_if_due(
        &self,
        sender_session: u32,
        seq: u64,
        payload: &Bytes,
        is_terminator: bool,
        dsts: &[NodeIdentifier],
        repair_context: Option<&RepairFrameContext>,
        tree_group: Option<DistributionGroup>,
    ) {
        if !self.cfg.voice_fec_enabled {
            return;
        }
        let qualities = repair_context
            .map(|context| context.route_qualities.as_slice())
            .unwrap_or(&[]);
        let unreliable = |index: usize| {
            qualities
                .get(index)
                .copied()
                .flatten()
                .filter(|quality| !quality.reliable())
        };
        if let Some(group) = tree_group {
            if !(0..dsts.len()).any(|index| unreliable(index).is_some()) {
                return;
            }
            // One stream for the whole tree: the tree carries every row to
            // every recipient, whatever route each edge is bound to.
            let local = self.transport.local_node_id();
            let emissions = self.fec_sender.push(
                local,
                dsts,
                sender_session,
                self.sender_epoch,
                seq,
                payload.clone(),
                is_terminator,
            );
            // A second copy of every row detours around the first hop(s) the
            // data leaves on, where such a route exists, so one burst on the
            // data path cannot take both the data and all its parity.
            let unreliable_dsts: Vec<_> = dsts
                .iter()
                .enumerate()
                .filter(|(index, _)| unreliable(*index).is_some())
                .map(|(_, dst)| *dst)
                .collect();
            let detours = self
                .transport
                .voice_tree_parity_detours(group, &unreliable_dsts);
            let route = FecParityRoute::Tree {
                source: local,
                dsts: dsts.to_vec(),
                group,
                detours,
            };
            self.emit_parity(route, emissions, sender_session).await;
            return;
        }
        // Group destinations by the data's first hop: a block holds only
        // frames that took one link to one recipient set.
        let mut hops: HashMap<NodeIdentifier, FecHopGroup> = HashMap::new();
        let mut alternate_shedding: HashMap<NodeIdentifier, bool> = HashMap::new();
        for (index, &dst) in dsts.iter().enumerate() {
            let Some(quality) = unreliable(index) else {
                continue;
            };
            let diverse = quality.alternate_next_hop().is_some_and(|alternate| {
                let shedding = *alternate_shedding
                    .entry(alternate)
                    .or_insert_with(|| self.transport.datagram_lane_shedding(alternate));
                fec::parity_alternate_usable(quality, shedding)
            });
            let group = hops.entry(quality.next_hop()).or_default();
            group.dsts.push(dst);
            group.primary_shedding |= quality.datagram_lane_shedding();
            if diverse {
                group.alternate_dsts.push(dst);
            } else {
                group.primary_dsts.push(dst);
            }
        }
        for (first_hop, group) in hops {
            let emissions = self.fec_sender.push(
                first_hop,
                &group.dsts,
                sender_session,
                self.sender_epoch,
                seq,
                payload.clone(),
                is_terminator,
            );
            // Send-path pressure gate: while the first-hop datagram lane is
            // evicting (frames shed before the wire), parity sent over it would
            // be shed too — emitting it only adds offered load to the lane
            // already failing to drain. Alternate-path parity avoids that lane.
            let primary_dsts = if group.primary_shedding {
                Vec::new()
            } else {
                group.primary_dsts
            };
            let route = FecParityRoute::Hop(FecParityTargets {
                first_hop,
                primary_dsts,
                alternate_dsts: group.alternate_dsts,
            });
            self.emit_parity(route, emissions, sender_session).await;
        }
    }

    /// Send the parity rows due now, then pace any rows owed after a
    /// terminator from a background task.
    async fn emit_parity(
        &self,
        route: FecParityRoute,
        emissions: Vec<fec::ParityEmission>,
        sender_session: u32,
    ) {
        let ttl = self.cfg.transport_ttl();
        let (now, tail): (Vec<_>, Vec<_>) = emissions
            .into_iter()
            .partition(|emission| emission.tail_step == 0);
        for emission in now {
            send_parity_emission(
                self.transport.as_ref(),
                &route,
                &emission,
                sender_session,
                self.sender_epoch,
                ttl,
            )
            .await;
        }
        if tail.is_empty() {
            return;
        }
        let transport = self.transport.clone();
        let shutdown = self.shutdown.clone();
        let sender_epoch = self.sender_epoch;
        tokio::spawn(async move {
            let started = tokio::time::Instant::now();
            for emission in tail {
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep_until(started + emission.delay()) => {}
                }
                let remaining = ttl.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return;
                }
                send_parity_emission(
                    transport.as_ref(),
                    &route,
                    &emission,
                    sender_session,
                    sender_epoch,
                    remaining,
                )
                .await;
            }
        });
    }

    fn remote_voice_members(&self) -> Vec<NodeIdentifier> {
        let local = self.transport.local_node_id();
        self.transport
            .voice_members()
            .into_iter()
            .filter(|node| *node != local)
            .collect()
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
                // Route quality exposes one alternate, so at most one extra
                // copy can use a distinct link.
                self.cfg.repair_max_extra_copies_per_frame.min(1),
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
            let Some(repair_first_hop) = quality
                .alternate_next_hop()
                .filter(|hop| *hop != quality.next_hop())
            else {
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
                    repair_first_hop,
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
        if !self.cfg.repair_enabled && !self.cfg.voice_fec_enabled {
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
                    // A FEC parity frame is never audio. It rides the
                    // low-priority lane so it cannot preempt originals, and
                    // the dispatch task intercepts it before the reorder.
                    VoiceCopyKind::Fec
                } else if frame.proactive_copy {
                    VoiceCopyKind::Proactive
                } else {
                    VoiceCopyKind::Original
                };
                let class = if matches!(copy_kind, VoiceCopyKind::Proactive | VoiceCopyKind::Fec) {
                    VoiceIngressClass::Proactive
                } else {
                    VoiceIngressClass::Primary
                };
                let permit = match copy_kind {
                    // Parity is exempt from the ingress byte budget: shedding
                    // it under queue pressure would discard the redundancy
                    // exactly when loss is highest.
                    VoiceCopyKind::Fec => None,
                    _ => {
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
                        Some(permit)
                    }
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

struct VoiceRepairInbound;

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
    fn handle(&self, _msg: OverlayInboundMessage) {}
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
                        // Parity frame: never audio. Record the block and
                        // recover whatever the reorder still wants.
                        let recorded = fec_state.record_parity(
                            sender_session,
                            sender_epoch,
                            delivery.frame.fec_member_seqs.clone(),
                            delivery.frame.payload.clone(),
                            delivery.frame.fec_parity_index,
                            delivery.frame.fec_terminator_mask,
                        );
                        if recorded {
                            push_fec_recovered(
                                &reorderer,
                                &fec_state,
                                from,
                                sender_session,
                                sender_epoch,
                            )
                            .unwrap_or_else(|| reorderer.idle_report())
                        } else {
                            reorderer.idle_report()
                        }
                    } else if is_parity {
                        reorderer.idle_report()
                    } else {
                        // An overdue next frame is recovered before this data
                        // frame is pushed: an arrival past the delivery
                        // deadline releases past missing sequences, which
                        // would turn an in-order recovery into a late fill.
                        let before = if fec_enabled {
                            fec_state.record_frame(delivery.frame.clone());
                            push_fec_recovered(
                                &reorderer,
                                &fec_state,
                                from,
                                sender_session,
                                sender_epoch,
                            )
                        } else {
                            None
                        };
                        let route_hint = reorderer
                            .may_arm_gap(&delivery.frame, delivery.copy_kind)
                            .then(|| {
                                transport
                                    .voice_route_quality(origin_node)
                                    .map(route_hint_from_quality)
                            })
                            .flatten();
                        let report = reorderer.push_with_route_hint_report_with_copy_kind(
                            from,
                            delivery.frame,
                            route_hint,
                            delivery.copy_kind,
                        );
                        let report = match before {
                            Some(before) => before.merge(report),
                            None => report,
                        };
                        // A data frame can complete the `k` symbols a parity
                        // block needs, or open a gap a mirrored block covers.
                        let recovered = fec_enabled
                            .then(|| {
                                push_fec_recovered(
                                    &reorderer,
                                    &fec_state,
                                    from,
                                    sender_session,
                                    sender_epoch,
                                )
                            })
                            .flatten();
                        match recovered {
                            Some(recovered) => report.merge(recovered),
                            None => report,
                        }
                    };
                    if let Some(gap) = report.opened_gap() {
                        metrics::record_gap_opened(
                            gap.last_seq.saturating_sub(gap.first_seq).saturating_add(1),
                        );
                    }
                    (report, Some((origin_node, from)), _permit)
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
                    if result.result() == VoiceReceiveResult::DeadlineFlush {
                        continue;
                    }
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
            // Ingress can flush an expired suffix carried by a different
            // immediate peer. Attribute it to the peers that buffered it.
            let deadline_flushes = report.flushes_by_peer().to_vec();
            if let Some((origin_node, _)) = inbound_labels {
                for flush in &deadline_flushes {
                    metrics::record_receive(
                        source,
                        origin_node,
                        flush.from,
                        VoiceReceiveResult::DeadlineFlush,
                        flush.count,
                    );
                }
            }
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
            }
            // Deadline and ingress flushes share peer feedback and held delay.
            for flush in deadline_flushes {
                let from = flush.from;
                if let Some(feedback) =
                    path_feedback.record(from, VoiceReceiveResult::DeadlineFlush, flush.count)
                {
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
                        sink.deliver(from, frame, is_repair).await;
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

/// Destinations sharing one data first hop, split by which path their parity
/// rides.
#[derive(Default)]
struct FecHopGroup {
    dsts: Vec<NodeIdentifier>,
    primary_dsts: Vec<NodeIdentifier>,
    alternate_dsts: Vec<NodeIdentifier>,
    primary_shedding: bool,
}

/// Where one first hop's parity goes: `primary_dsts` over the data's own first
/// hop, `alternate_dsts` over each route's alternate (avoiding `first_hop`).
struct FecParityTargets {
    first_hop: NodeIdentifier,
    primary_dsts: Vec<NodeIdentifier>,
    alternate_dsts: Vec<NodeIdentifier>,
}

/// The route a FEC stream's parity takes: the data's distribution tree (plus
/// detours independent of the data's first hops), or the routed first hop
/// (and its alternate) of routed voice.
enum FecParityRoute {
    Tree {
        source: NodeIdentifier,
        dsts: Vec<NodeIdentifier>,
        group: DistributionGroup,
        /// `(data first hop to avoid, recipients)` for the second copy.
        detours: Vec<(NodeIdentifier, Vec<NodeIdentifier>)>,
    },
    Hop(FecParityTargets),
}

async fn send_parity_emission(
    transport: &dyn VoiceTransport,
    route: &FecParityRoute,
    emission: &fec::ParityEmission,
    sender_session: u32,
    sender_epoch: u64,
    ttl: Duration,
) {
    let Some(body) = emission.encode(sender_session, sender_epoch) else {
        return;
    };
    let targets = match route {
        FecParityRoute::Tree {
            source,
            dsts,
            group,
            detours,
        } => {
            let outcome = match transport
                .send_tree_multicast(dsts, *group, body.clone(), ttl)
                .await
            {
                Ok(()) => fec::FecSendOutcome::Sent,
                Err(_) => fec::FecSendOutcome::Shed,
            };
            metrics::record_fec_send(
                transport.local_node_id(),
                *source,
                body.len(),
                outcome,
                fec::FecParityPath::Tree,
            );
            for (avoid, detour_dsts) in detours {
                let outcome = transport
                    .send_fec_frame(detour_dsts, Some(*avoid), Some(*avoid), body.clone(), ttl)
                    .await;
                metrics::record_fec_send(
                    transport.local_node_id(),
                    *avoid,
                    body.len(),
                    outcome,
                    fec::FecParityPath::Alternate,
                );
            }
            return;
        }
        FecParityRoute::Hop(targets) => targets,
    };
    for (dsts, avoid, path) in [
        (&targets.primary_dsts, None, fec::FecParityPath::Primary),
        (
            &targets.alternate_dsts,
            Some(targets.first_hop),
            fec::FecParityPath::Alternate,
        ),
    ] {
        if dsts.is_empty() {
            continue;
        }
        let outcome = transport
            .send_fec_frame(dsts, Some(targets.first_hop), avoid, body.clone(), ttl)
            .await;
        metrics::record_fec_send(
            transport.local_node_id(),
            targets.first_hop,
            body.len(),
            outcome,
            path,
        );
    }
}

/// Recover the FEC block members the reorder still wants for one mirror and
/// push them into the reorder, recording whether each landed in time, late
/// (a hole the reorder already released past), or was discarded. `None` when
/// nothing was recovered.
fn push_fec_recovered(
    reorderer: &Reorderer,
    fec_state: &fec::ReceiverFecState,
    from: NodeIdentifier,
    sender_session: u32,
    sender_epoch: u64,
) -> Option<reorder::ReorderReport> {
    let wanted = |seq: u64| reorderer.fec_wants(sender_session, sender_epoch, seq);
    let mut report: Option<reorder::ReorderReport> = None;
    // Each recovery can advance the cursor and make a stashed reconstruction
    // the next wanted frame, so repeat until nothing more comes out. The stash
    // is bounded, so this terminates.
    loop {
        let recovered = fec_state.try_reconstruct(sender_session, sender_epoch, &wanted);
        if recovered.is_empty() {
            break;
        }
        for recovered in recovered {
            let pushed = reorderer.push_with_route_hint_report_with_copy_kind(
                from,
                recovered,
                None,
                VoiceCopyKind::Fec,
            );
            metrics::record_fec_recovery(pushed.result_counts());
            report = Some(match report {
                Some(report) => report.merge(pushed),
                None => pushed,
            });
        }
    }
    report
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
    let (proactive, active_destinations) = budget.repair_allocator_state_bytes();
    metrics::set_repair_allocator_state(proactive, active_destinations);
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

fn exponential_backoff(initial: Duration, maximum: Duration, failures: u8) -> Duration {
    let shift = u32::from(failures.saturating_sub(1)).min(31);
    initial.saturating_mul(1_u32 << shift).min(maximum)
}

#[cfg(test)]
mod tests {
    use shitspeak_core::default_server_id;
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

    fn repair_transport(destinations: Vec<NodeIdentifier>) -> Arc<FakeVoiceTransport> {
        let transport = FakeVoiceTransport::new(7, destinations.clone());
        for destination in destinations {
            // Originals use a relay; repair uses the independently funded direct link.
            transport.set_voice_route_quality(
                destination,
                VoiceRouteQuality::new(destination + 100, TransportKind::Tcp, 0, 0, 0)
                    .with_alternate_route(destination, 0),
            );
        }
        transport
    }

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
                inner: repair_transport(vec![2, 3]),
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
                inner: repair_transport(vec![2]),
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
        assert!(
            acc.record(22, VoiceReceiveResult::DeadlineFlush, 2)
                .is_none()
        );
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
        assert!(
            acc.record(22, VoiceReceiveResult::DeadlineFlush, 1)
                .is_none()
        );
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

    #[test]
    fn proactive_repair_defaults_remain_enabled() {
        let cfg = VoiceConfig::default();
        assert_eq!(cfg.repair_loss_start_ppm, 10_000);
        assert_eq!(cfg.repair_full_dup_loss_ppm, 30_000);
        assert_eq!(cfg.repair_jitter_start_ms, 40);
        assert_eq!(cfg.repair_max_extra_copies_per_frame, 1);
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
        let budget = AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(5_000)));
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
        let budget = AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(5_000)));
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
        let budget = AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(5_000)));
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
        let budget = AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(5_000)));
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
        let budget = AdaptiveVoiceBudget::new(Arc::new(AtomicU64::new(5_000)));
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
            PROACTIVE_FAILURE_BACKOFF_INITIAL,
            PROACTIVE_FAILURE_BACKOFF_MAX,
        );
        assert_eq!(
            blocked_until,
            completed_at + PROACTIVE_FAILURE_BACKOFF_INITIAL
        );
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
        idx.add_in_server(default_server_id().as_str(), 5, 1);
        idx.add_in_server(default_server_id().as_str(), 5, 2);
        idx.add_in_server(default_server_id().as_str(), 5, 7); // self — must be filtered out
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
        idx.add_in_server(default_server_id().as_str(), 5, 1);
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
        idx.add_in_server(default_server_id().as_str(), 5, 1);
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
        idx.add_in_server(default_server_id().as_str(), 5, 7); // only self
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
    async fn ingress_caps_origin_route_quality_at_the_continuous_delivery_deadline() {
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
        // A 257 ms route estimate and extra hold must fit inside the
        // 18 ms delivery cadence established by the first 20 ms packet.
        cfg.adaptive_jitter_max_delay_ms = 400;
        cfg.chunk_hold_budget_ms = 50;
        let svc = VoiceService::new_with_transport(transport, cfg, CancellationToken::new(), 42);
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
                Bytes::from_static(&[0, 0x2a, 1, 8]),
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

        tokio::time::timeout(Duration::from_millis(80), async {
            while sink.len() < 2 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("route quality must not delay audio beyond the packet cadence");
        assert_eq!(
            sink.snapshot()
                .iter()
                .map(|(_, f)| f.s2s_seq)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );
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
            self.frames
                .lock()
                .unwrap()
                .push((frame.s2s_seq, frame.payload));
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
        row: u32,
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
            fec_parity_index: fec::RS_PARITY_INDEX_BASE + row,
        };
        Bytes::from(proto::encode_voice(&frame).unwrap())
    }

    fn fec_rs_parity(payloads: &[&[u8]], row: usize) -> Vec<u8> {
        fec::tests::rs_parity(payloads, row)
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
    async fn fec_send_is_always_on_without_reactive_repair() {
        for transport_kind in [TransportKind::Udp, TransportKind::Quic] {
            for tree_delivery_enabled in [false, true] {
                let transport = FakeVoiceTransport::new(7, vec![1]);
                transport.set_voice_route_quality(
                    1,
                    VoiceRouteQuality::new(1, transport_kind, 1_000, 0, 0),
                );
                let mut cfg: VoiceConfig = serde_json::from_str(
                    r#"{"voice_fec_enabled":true,"voice_fec_loss_gate_ppm":1000000,"repair_enabled":false,"voice_fec_block_size":4,"voice_fec_interleave_depth":1}"#,
                )
                .unwrap();
                cfg.tree_delivery_enabled = tree_delivery_enabled;
                let parity_count = cfg.voice_fec_parity_blocks;
                let svc = VoiceService::new_with_transport(
                    transport.clone(),
                    cfg,
                    CancellationToken::new(),
                    42,
                );
                // The block completes on the fourth frame; its rows are paced
                // out one per frame from there.
                for _ in 0..(3 + parity_count) {
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
                let rows = transport
                    .calls()
                    .iter()
                    .filter_map(|call| {
                        // Parity rides the data's own route: the tree when
                        // tree delivery is on, the routed multicast otherwise.
                        let body = match call {
                            FakeCall::TreeMulticast { body, .. } if tree_delivery_enabled => body,
                            FakeCall::Multicast { body, .. } if !tree_delivery_enabled => body,
                            _ => return None,
                        };
                        let frame = proto::decode_voice(body).unwrap();
                        frame.fec_parity.then(|| {
                            assert_eq!(frame.fec_member_seqs, vec![0, 1, 2, 3]);
                            frame.fec_parity_index
                        })
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    rows,
                    (0..parity_count as u32)
                        .map(|row| fec::RS_PARITY_INDEX_BASE + row)
                        .collect::<Vec<_>>(),
                    "{transport_kind:?}, tree={tree_delivery_enabled}"
                );
            }
        }
    }

    #[tokio::test]
    async fn accepted_copy_does_not_wait_for_parity() {
        let transport = ControlledUnicastTransport::new(false);
        transport.proactive_release.add_permits(4);
        let mut cfg = VoiceConfig::default();
        cfg.voice_fec_block_size = 4;
        cfg.voice_fec_parity_blocks = 1;
        cfg.voice_fec_interleave_depth = 1;
        let svc =
            VoiceService::new_with_transport(transport.clone(), cfg, CancellationToken::new(), 42);
        for seq in 0..4 {
            tokio::time::timeout(
                Duration::from_millis(100),
                svc.transport.send_proactive_repair_frame(
                    2,
                    fec_data_frame(seq, b"abcd"),
                    Some(102),
                    Duration::from_secs(1),
                ),
            )
            .await
            .expect("accepted data must not wait for parity admission")
            .unwrap();
        }
        transport.proactive_release.add_permits(1);
        wait_for_call_count(&transport.inner, 5).await;
    }

    #[tokio::test]
    async fn extra_copies_receive_fec_on_unreliable_alternate_links() {
        for enabled in [false, true] {
            for (kind, reliable) in [
                (TransportKind::Udp, false),
                (TransportKind::Quic, false),
                (TransportKind::Tcp, true),
                (TransportKind::Kcp, true),
                (TransportKind::Quic, true),
            ] {
                let transport = FakeVoiceTransport::new(7, vec![2, 3]);
                transport.set_voice_route_quality(
                    2,
                    VoiceRouteQuality::new(2, TransportKind::Tcp, 0, 0, 0)
                        .with_alternate_route_quality(3, 0, kind, 0, 0)
                        .with_alternate_reliable_transport(reliable),
                );
                let mut cfg = VoiceConfig::default();
                cfg.voice_fec_enabled = enabled;
                cfg.voice_fec_block_size = 4;
                cfg.voice_fec_parity_blocks = 2;
                cfg.voice_fec_interleave_depth = 1;
                let svc = VoiceService::new_with_transport(
                    transport.clone(),
                    cfg,
                    CancellationToken::new(),
                    42,
                );
                // Four frames complete the block; the fifth carries its
                // second, paced parity row.
                for seq in 0..5 {
                    let body = fec_data_frame(seq, b"abcd");
                    svc.transport
                        .send_proactive_repair_frame(
                            2,
                            send::mark_proactive_copy(&body).unwrap(),
                            Some(2),
                            Duration::from_secs(1),
                        )
                        .await
                        .unwrap();
                }
                let expected = if enabled && !reliable { 2 } else { 0 };
                let calls = wait_for_call_count(&transport, 5 + expected).await;
                let parities = calls
                    .iter()
                    .filter_map(|call| {
                        let FakeCall::RepairFrame {
                            body,
                            avoid_first_hop,
                            ..
                        } = call
                        else {
                            panic!("copy and parity must use the alternate: {call:?}");
                        };
                        assert_eq!(*avoid_first_hop, Some(2));
                        let frame = proto::decode_voice(body).unwrap();
                        frame.fec_parity.then_some(frame)
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    parities.len(),
                    expected,
                    "enabled={enabled}, {kind:?}, reliable={reliable}"
                );
                assert_eq!(calls.len(), 5 + expected);
                for parity in parities {
                    assert_eq!(parity.fec_member_seqs, vec![0, 1, 2, 3]);
                }
            }
        }
    }

    #[tokio::test]
    async fn proactive_copies_require_an_alternate_and_do_not_repeat_on_it() {
        for has_alternate in [false, true] {
            let transport = FakeVoiceTransport::new(7, vec![2, 3]);
            let mut quality = VoiceRouteQuality::new(2, TransportKind::Udp, 1_000, 1_000_000, 0);
            if has_alternate {
                quality = quality.with_alternate_route_quality(3, 500, TransportKind::Quic, 0, 0);
            }
            transport.set_voice_route_quality(2, quality);
            let mut cfg = VoiceConfig::default();
            cfg.repair_max_extra_copies_per_frame = 2;
            let svc = VoiceService::new_with_transport(
                transport.clone(),
                cfg,
                CancellationToken::new(),
                42,
            );
            for hop in [2, 3] {
                svc.voice_budget
                    .mint_link_credit(hop, 0xABC, 42, usize::MAX);
            }
            svc.send_unicast(
                0xABC,
                default_server_id(),
                0,
                false,
                Bytes::from_static(b"abcd"),
                normal_intent(5),
                2,
            )
            .await
            .unwrap();
            if has_alternate {
                wait_for_call_count(&transport, 2).await;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            let calls = transport.calls();
            assert_eq!(calls.len(), if has_alternate { 2 } else { 1 });
            for call in calls.iter().skip(1) {
                assert!(matches!(
                    call,
                    FakeCall::RepairFrame {
                        avoid_first_hop: Some(2),
                        ..
                    }
                ));
            }
        }
    }

    #[tokio::test]
    async fn fec_send_skips_disabled_and_reliable_links() {
        for (enabled, quality) in [
            (
                false,
                VoiceRouteQuality::new(1, TransportKind::Udp, 1_000, 50_000, 0),
            ),
            (
                false,
                VoiceRouteQuality::new(1, TransportKind::Quic, 1_000, 50_000, 0),
            ),
            (
                true,
                VoiceRouteQuality::new(1, TransportKind::Tcp, 1_000, 50_000, 0),
            ),
            (
                true,
                VoiceRouteQuality::new(1, TransportKind::Kcp, 1_000, 50_000, 0),
            ),
            (
                true,
                VoiceRouteQuality::new(1, TransportKind::Quic, 1_000, 50_000, 0)
                    .with_reliable_transport(true),
            ),
        ] {
            let transport = FakeVoiceTransport::new(7, vec![1]);
            transport.set_voice_route_quality(1, quality);
            let mut cfg = VoiceConfig::default();
            cfg.voice_fec_enabled = enabled;
            cfg.repair_enabled = false;
            let svc = VoiceService::new_with_transport(
                transport.clone(),
                cfg,
                CancellationToken::new(),
                42,
            );
            for _ in 0..4 {
                svc.send_broadcast(
                    0xABC,
                    default_server_id(),
                    0,
                    false,
                    Bytes::from_static(b"abcd"),
                    normal_intent(5),
                )
                .await
                .unwrap();
            }
            assert_eq!(transport.calls().len(), 4, "enabled={enabled}, {quality:?}");
        }
    }

    #[tokio::test]
    async fn fec_send_protects_unreliable_transports_with_pressure_limits() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        // Reliable TCP links need no parity.
        for &dst in &[1u16, 2, 3] {
            transport.set_voice_route_quality(
                dst,
                VoiceRouteQuality::new(dst, TransportKind::Tcp, 1_000, 1_000, 100),
            );
        }
        let mut cfg = VoiceConfig::default();
        cfg.voice_fec_enabled = true;
        cfg.voice_fec_block_size = 4;
        cfg.voice_fec_parity_blocks = 1;
        cfg.voice_fec_interleave_depth = 1;
        cfg.tree_delivery_enabled = false;
        let svc =
            VoiceService::new_with_transport(transport.clone(), cfg, CancellationToken::new(), 42);
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
                assert!(!frame.fec_parity, "parity emitted over a reliable link");
            }
        }

        // Unreliable UDP links get parity.
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
        let parity = parity.expect("UDP should receive parity");
        assert_eq!(parity.fec_member_seqs, vec![4, 5, 6, 7]);
        // Length prefix + the 4-byte member payload.
        assert_eq!(parity.payload.len(), 6);
        assert_eq!(parity.s2s_seq, 7);

        // Healthy QUIC datagrams also receive parity, independent of UDP loss.
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
        assert_eq!(
            transport.calls()[calls_before..]
                .iter()
                .filter(|call| {
                    matches!(call, FakeCall::Multicast { body, .. }
                if proto::decode_voice(body).unwrap().fec_parity)
                })
                .count(),
            3
        );

        // Lossy QUIC datagrams keep receiving parity.
        for &dst in &[1u16, 2, 3] {
            transport.set_voice_route_quality(
                dst,
                VoiceRouteQuality::new(dst, TransportKind::Quic, 1_000, 50_000, 100),
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
        let parity = parity.expect("QUIC datagrams should receive parity");
        assert_eq!(parity.fec_member_seqs, vec![12, 13, 14, 15]);
        // Length prefix + the 4-byte member payload.
        assert_eq!(parity.payload.len(), 6);
        assert_eq!(parity.s2s_seq, 15);

        // Send-path shedding still suppresses parity until the lane recovers.
        for &dst in &[1u16, 2, 3] {
            transport.set_voice_route_quality(
                dst,
                VoiceRouteQuality::new(dst, TransportKind::Quic, 1_000, 50_000, 100)
                    .with_datagram_lane_shedding(true),
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
        for call in &transport.calls()[calls_before..] {
            if let FakeCall::Multicast { body, .. } = call {
                let frame = proto::decode_voice(body).unwrap();
                assert!(
                    !frame.fec_parity,
                    "parity emitted while the datagram lane is evicting at the send path"
                );
            }
        }
    }

    #[tokio::test]
    async fn fec_parity_rides_a_usable_alternate_even_while_the_primary_sheds() {
        for (alternate_loss, primary_shedding, parity_on_alternate) in [
            (0, false, true),
            (0, true, true),
            // A far lossier alternate cannot carry the parity; the primary
            // does unless it is shedding.
            (500_000, false, false),
        ] {
            let transport = FakeVoiceTransport::new(7, vec![1]);
            transport.set_voice_route_quality(
                1,
                VoiceRouteQuality::new(1, TransportKind::Udp, 1_000, 0, 0)
                    .with_alternate_route_quality(5, 2_000, TransportKind::Udp, alternate_loss, 0)
                    .with_datagram_lane_shedding(primary_shedding),
            );
            let mut cfg = VoiceConfig::default();
            cfg.repair_enabled = false;
            cfg.tree_delivery_enabled = false;
            cfg.voice_fec_block_size = 2;
            cfg.voice_fec_parity_blocks = 1;
            cfg.voice_fec_interleave_depth = 1;
            let svc = VoiceService::new_with_transport(
                transport.clone(),
                cfg,
                CancellationToken::new(),
                42,
            );
            for _ in 0..2 {
                svc.send_broadcast(
                    0xABC,
                    default_server_id(),
                    0,
                    false,
                    Bytes::from_static(b"abcd"),
                    normal_intent(5),
                )
                .await
                .unwrap();
            }
            let parity_calls: Vec<Option<NodeIdentifier>> = transport
                .calls()
                .iter()
                .filter_map(|call| match call {
                    FakeCall::Multicast { body, .. }
                        if proto::decode_voice(body).unwrap().fec_parity =>
                    {
                        Some(None)
                    }
                    FakeCall::RepairFrame {
                        body,
                        avoid_first_hop,
                        ..
                    } if proto::decode_voice(body).unwrap().fec_parity => Some(*avoid_first_hop),
                    _ => None,
                })
                .collect();
            let expected = match (parity_on_alternate, primary_shedding) {
                (true, _) => vec![Some(1)],
                (false, false) => vec![None],
                (false, true) => vec![],
            };
            assert_eq!(
                parity_calls, expected,
                "alternate_loss={alternate_loss}, primary_shedding={primary_shedding}"
            );
        }
    }

    #[tokio::test]
    async fn tree_voice_parity_follows_the_data_tree() {
        // Tree delivery binds each edge to its own route (direct, a relay, or
        // a split) that only the tree knows. Parity routed any other way —
        // the routing table's first hop or its alternate — reaches the
        // listener at a different latency than the data it protects. It must
        // ride the same tree, group and recipients as the data.
        let transport = FakeVoiceTransport::new(7, vec![1, 2]);
        for dst in [1u16, 2] {
            transport.set_voice_route_quality(
                dst,
                VoiceRouteQuality::new(dst, TransportKind::Udp, 1_000, 0, 0)
                    .with_alternate_route_quality(5, 2_000, TransportKind::Udp, 0, 0),
            );
        }
        let mut cfg = VoiceConfig::default();
        cfg.repair_enabled = false;
        cfg.tree_delivery_enabled = true;
        cfg.voice_fec_block_size = 2;
        cfg.voice_fec_parity_blocks = 1;
        cfg.voice_fec_interleave_depth = 1;
        let svc =
            VoiceService::new_with_transport(transport.clone(), cfg, CancellationToken::new(), 42);
        for _ in 0..2 {
            svc.send_broadcast(
                0xABC,
                default_server_id(),
                0,
                false,
                Bytes::from_static(b"abcd"),
                normal_intent(5),
            )
            .await
            .unwrap();
        }
        let calls = transport.calls();
        let mut parity_calls = 0;
        for call in &calls {
            let (body, via_tree) = match call {
                FakeCall::TreeMulticast {
                    body, dsts, group, ..
                } => {
                    assert_eq!(*group, DistributionGroup::broadcast());
                    let mut dsts = dsts.clone();
                    dsts.sort_unstable();
                    assert_eq!(dsts, vec![1, 2]);
                    (body, true)
                }
                FakeCall::Multicast { body, .. } | FakeCall::RepairFrame { body, .. } => {
                    (body, false)
                }
                other => panic!("unexpected call {other:?}"),
            };
            if proto::decode_voice(body).unwrap().fec_parity {
                assert!(via_tree, "parity left the data tree: {call:?}");
                parity_calls += 1;
            }
        }
        assert_eq!(parity_calls, 1, "one block, one parity row");
    }

    #[tokio::test]
    async fn tree_voice_parity_also_rides_an_independent_first_hop() {
        // Recipient 1's data leaves on first hop 1 and a route avoiding it
        // exists; recipient 2 has no such route. Every parity row goes into
        // the data tree for both, and a second copy detours around first hop 1
        // for recipient 1 only, so a burst on 1's data path cannot take both.
        let transport = FakeVoiceTransport::new(7, vec![1, 2]);
        for dst in [1u16, 2] {
            transport.set_voice_route_quality(
                dst,
                VoiceRouteQuality::new(dst, TransportKind::Udp, 1_000, 0, 0),
            );
        }
        transport.set_tree_parity_detour(1, 1);
        let mut cfg = VoiceConfig::default();
        cfg.repair_enabled = false;
        cfg.tree_delivery_enabled = true;
        cfg.voice_fec_block_size = 2;
        cfg.voice_fec_parity_blocks = 1;
        cfg.voice_fec_interleave_depth = 1;
        let svc =
            VoiceService::new_with_transport(transport.clone(), cfg, CancellationToken::new(), 42);
        for _ in 0..2 {
            svc.send_broadcast(
                0xABC,
                default_server_id(),
                0,
                false,
                Bytes::from_static(b"abcd"),
                normal_intent(5),
            )
            .await
            .unwrap();
        }
        let mut tree_parity = 0;
        let mut detour_parity = Vec::new();
        for call in transport.calls() {
            match call {
                FakeCall::TreeMulticast { body, .. }
                    if proto::decode_voice(&body).unwrap().fec_parity =>
                {
                    tree_parity += 1;
                }
                FakeCall::RepairFrame {
                    dst,
                    body,
                    avoid_first_hop,
                    ..
                } if proto::decode_voice(&body).unwrap().fec_parity => {
                    detour_parity.push((dst, avoid_first_hop));
                }
                _ => {}
            }
        }
        assert_eq!(tree_parity, 1);
        assert_eq!(detour_parity, vec![(1, Some(1))]);
    }

    #[tokio::test]
    async fn fec_receiver_solves_parity_that_arrived_over_a_different_peer() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = VoiceService::new_with_transport(
            transport,
            VoiceConfig::default(),
            CancellationToken::new(),
            42,
        );
        let sink = Arc::new(FecProbeSink::default());
        svc.set_audio_sink(sink.clone());
        // Data rides peer 11; the block's parity rides the alternate, peer 12.
        inject_voice_inbound(&svc, 11, fec_data_frame(1, b"aaaa"));
        inject_voice_inbound(&svc, 11, fec_data_frame(2, b"bbbb"));
        wait_for_fec_sink(&sink, 2).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        let parity = fec_rs_parity(&[b"aaaa", b"bbbb", b"cc"], 0);
        inject_voice_inbound(
            &svc,
            12,
            fec_parity_frame(0xABC, 42, vec![1, 2, 3], &parity, 0, 0),
        );
        let frames = wait_for_fec_sink(&sink, 3).await;
        assert_eq!(frames[2].0, 3);
        assert_eq!(frames[2].1.as_ref(), b"cc");
    }

    #[tokio::test]
    async fn fec_receiver_reconstructs_missing_frame() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let mut cfg: VoiceConfig =
            serde_json::from_str(r#"{"voice_fec_enabled":true,"repair_enabled":false}"#).unwrap();
        cfg.voice_fec_receiver_window = 8;
        let svc = VoiceService::new_with_transport(transport, cfg, CancellationToken::new(), 42);
        let sink = Arc::new(FecProbeSink::default());
        svc.set_audio_sink(sink.clone());

        // Frames 1,2,3 arrive; frame 4 is lost on the wire.
        inject_voice_inbound(&svc, 11, fec_data_frame(1, b"aaaa"));
        inject_voice_inbound(&svc, 11, fec_data_frame(2, b"bbbb"));
        inject_voice_inbound(&svc, 11, fec_data_frame(3, b"cccc"));
        wait_for_fec_sink(&sink, 3).await;

        // One parity row of block {1,2,3,4} recovers the single loss, whose
        // length differs from its siblings', once 4 is overdue.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let parity = fec_rs_parity(&[b"aaaa", b"bbbb", b"cccc", b"ddd"], 0);
        inject_voice_inbound(
            &svc,
            11,
            fec_parity_frame(0xABC, 42, vec![1, 2, 3, 4], &parity, 0, 0),
        );

        let frames = wait_for_fec_sink(&sink, 4).await;
        assert_eq!(frames[3].0, 4);
        assert_eq!(frames[3].1.as_ref(), b"ddd");
    }

    #[tokio::test]
    async fn fec_receiver_ignores_retired_xor_parity() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = VoiceService::new_with_transport(
            transport,
            VoiceConfig::default(),
            CancellationToken::new(),
            42,
        );
        let sink = Arc::new(FecProbeSink::default());
        svc.set_audio_sink(sink.clone());
        inject_voice_inbound(&svc, 11, fec_data_frame(1, b"aaaa"));
        wait_for_fec_sink(&sink, 1).await;
        // A pre-Reed-Solomon peer's XOR parity (wire index 0) must not be
        // solved as a Reed-Solomon row.
        let frame = VoiceFrame {
            sender_session: 0xABC,
            server_id: shitspeak_core::default_server_id(),
            sender_epoch: 42,
            s2s_seq: 2,
            target_kind: 0,
            is_terminator: false,
            payload: Bytes::from_static(&[3, 3, 3, 3]),
            intent: None,
            proactive_copy: false,
            fec_parity: true,
            fec_member_seqs: vec![1, 2],
            fec_terminator_mask: 0,
            fec_parity_index: 0,
        };
        inject_voice_inbound(&svc, 11, proto::encode_voice(&frame).unwrap());
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(sink.snapshot().len(), 1);
    }

    #[tokio::test]
    async fn fec_receiver_reconstructs_gap_frame_before_the_gap_opens() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let mut cfg = VoiceConfig::default();
        cfg.voice_fec_enabled = true;
        cfg.voice_fec_receiver_window = 8;
        let svc = VoiceService::new_with_transport(transport, cfg, CancellationToken::new(), 42);
        let sink = Arc::new(FecProbeSink::default());
        svc.set_audio_sink(sink.clone());

        // Frames 1,2,3 deliver and the block's parity outruns frame 4, which
        // is lost: the parity alone recovers 4 in order, and 5 follows it.
        inject_voice_inbound(&svc, 11, fec_data_frame(1, b"aaaa"));
        inject_voice_inbound(&svc, 11, fec_data_frame(2, b"bbbb"));
        inject_voice_inbound(&svc, 11, fec_data_frame(3, b"cccc"));
        wait_for_fec_sink(&sink, 3).await;
        let parity = fec_rs_parity(&[b"aaaa", b"bbbb", b"cccc", b"dddd"], 0);
        inject_voice_inbound(
            &svc,
            11,
            fec_parity_frame(0xABC, 42, vec![1, 2, 3, 4], &parity, 0, 0),
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
        inject_voice_inbound(&svc, 11, fec_data_frame(5, b"eeee"));

        let frames = wait_for_fec_sink(&sink, 5).await;
        assert_eq!(frames[3].0, 4);
        assert_eq!(frames[3].1.as_ref(), b"dddd");
        assert_eq!(frames[4].0, 5);
    }

    #[tokio::test]
    async fn fec_receiver_late_fills_a_hole_the_reorder_released() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = VoiceService::new_with_transport(
            transport,
            VoiceConfig::default(),
            CancellationToken::new(),
            42,
        );
        let sink = Arc::new(FecProbeSink::default());
        svc.set_audio_sink(sink.clone());

        // Block {1,2,3,4} with one parity row: 1 and 2 arrive and 3 is lost.
        // Frame 4 arrives after the delivery cadence, so the reorder releases
        // past 3 before the block can be solved; the parity then arrives and
        // 3 is emitted late, exactly once.
        let members: [&[u8]; 4] = [b"aaaa", b"bb", b"cccccc", b"dddd"];
        inject_voice_inbound(&svc, 11, fec_data_frame(1, members[0]));
        inject_voice_inbound(&svc, 11, fec_data_frame(2, members[1]));
        wait_for_fec_sink(&sink, 2).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        inject_voice_inbound(&svc, 11, fec_data_frame(4, members[3]));
        wait_for_fec_sink(&sink, 3).await;
        let parity = fec_rs_parity(&members, 0);
        inject_voice_inbound(
            &svc,
            11,
            fec_parity_frame(0xABC, 42, vec![1, 2, 3, 4], &parity, 0, 0),
        );

        let frames = wait_for_fec_sink(&sink, 4).await;
        let order: Vec<u64> = frames.iter().map(|(seq, _)| *seq).collect();
        assert_eq!(order, vec![1, 2, 4, 3]);
        assert_eq!(frames[3].1.as_ref(), members[2]);
        // A second copy of the parity cannot emit 3 again.
        inject_voice_inbound(
            &svc,
            11,
            fec_parity_frame(0xABC, 42, vec![1, 2, 3, 4], &parity, 0, 0),
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(sink.snapshot().len(), 4);
    }

    #[tokio::test]
    async fn fec_does_not_race_an_in_flight_original_on_a_faster_path() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = VoiceService::new_with_transport(
            transport,
            VoiceConfig::default(),
            CancellationToken::new(),
            42,
        );
        let sink = Arc::new(FecProbeSink::default());
        svc.set_audio_sink(sink.clone());

        // Data rides a slower relay; the block's parity arrives first over a
        // faster path while frame 3 is still in flight and nothing past it
        // has arrived. Emitting 3 from parity now would deliver frames at two
        // latencies — jitter the listener hears — so it waits for a later
        // frame to prove 3 is actually missing.
        // Two 60 ms SILK frames per packet: frame 3 is due 108 ms after
        // frame 2 is delivered.
        const PACKET: &[u8] = &[0, 0x2a, 1, 0x19];
        let members: [&[u8]; 3] = [PACKET; 3];
        inject_voice_inbound(&svc, 11, fec_data_frame(1, PACKET));
        inject_voice_inbound(&svc, 11, fec_data_frame(2, PACKET));
        wait_for_fec_sink(&sink, 2).await;
        inject_voice_inbound(
            &svc,
            12,
            fec_parity_frame(0xABC, 42, vec![1, 2, 3], &fec_rs_parity(&members, 0), 0, 0),
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            sink.snapshot().len(),
            2,
            "frame 3 emitted from parity early"
        );

        // Frame 3 is lost after all: frame 4 proves it and parity fills it.
        inject_voice_inbound(&svc, 11, fec_data_frame(4, PACKET));
        let frames = wait_for_fec_sink(&sink, 4).await;
        let order: Vec<u64> = frames.iter().map(|(seq, _)| *seq).collect();
        assert_eq!(order, vec![1, 2, 3, 4]);
        assert_eq!(frames[2].1.as_ref(), PACKET);
    }

    #[tokio::test]
    async fn fec_does_not_recover_ahead_of_a_merely_delayed_original() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = VoiceService::new_with_transport(
            transport,
            VoiceConfig::default(),
            CancellationToken::new(),
            42,
        );
        let sink = Arc::new(FecProbeSink::default());
        svc.set_audio_sink(sink.clone());

        // Interleaved block {2,4,6}: frame 2 and two parity rows arrive while
        // frame 3 is still in flight. Nothing past 3 has arrived, so 3 is not
        // lost; recovering 4 and 6 now would let the reorder release past 3
        // and discard it when it lands.
        let members: [&[u8]; 3] = [b"bbbb", b"dddd", b"ffff"];
        inject_voice_inbound(&svc, 11, fec_data_frame(1, b"aaaa"));
        inject_voice_inbound(&svc, 11, fec_data_frame(2, members[0]));
        wait_for_fec_sink(&sink, 2).await;
        for row in 0..2 {
            inject_voice_inbound(
                &svc,
                12,
                fec_parity_frame(
                    0xABC,
                    42,
                    vec![2, 4, 6],
                    &fec_rs_parity(&members, row as usize),
                    row,
                    0,
                ),
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        inject_voice_inbound(&svc, 11, fec_data_frame(3, b"cccc"));

        let frames = wait_for_fec_sink(&sink, 3).await;
        let order: Vec<u64> = frames.iter().map(|(seq, _)| *seq).collect();
        assert_eq!(
            &order[..3],
            &[1, 2, 3],
            "delayed original was skipped: {order:?}"
        );
        assert_eq!(frames[2].1.as_ref(), b"cccc");

        // Once frame 5 arrives, 4 is a genuine hole behind it and the block's
        // parity recovers it without waiting for another trigger. 6 is solved
        // too, but waits until it is overdue; frame 7 arriving late recovers
        // it in order ahead of 7.
        inject_voice_inbound(&svc, 11, fec_data_frame(5, b"eeee"));
        let frames = wait_for_fec_sink(&sink, 5).await;
        let order: Vec<u64> = frames.iter().map(|(seq, _)| *seq).collect();
        assert_eq!(order, vec![1, 2, 3, 4, 5]);
        assert_eq!(frames[3].1.as_ref(), b"dddd");
        tokio::time::sleep(Duration::from_millis(10)).await;
        inject_voice_inbound(&svc, 11, fec_data_frame(7, b"gggg"));
        let frames = wait_for_fec_sink(&sink, 7).await;
        let order: Vec<u64> = frames.iter().map(|(seq, _)| *seq).collect();
        assert_eq!(order, vec![1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(frames[5].1.as_ref(), b"ffff");
    }

    #[tokio::test]
    async fn fec_parity_is_exempt_from_the_ingress_byte_budget() {
        let transport = FakeVoiceTransport::new(7, vec![1, 2, 3]);
        let svc = VoiceService::new_with_transport(
            transport,
            VoiceConfig::default(),
            CancellationToken::new(),
            42,
        );
        let sink = Arc::new(FecProbeSink::default());
        svc.set_audio_sink(sink.clone());
        inject_voice_inbound(&svc, 11, fec_data_frame(1, b"aaaa"));
        wait_for_fec_sink(&sink, 1).await;
        // Exhaust the proactive ingress lane parity used to draw from.
        let mut held = Vec::new();
        while let Some(permit) = svc.voice_budget.try_reserve_proactive(64 * 1024) {
            held.push(permit);
        }
        while let Some(permit) = svc.voice_budget.try_reserve_proactive(1) {
            held.push(permit);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        let parity = fec_rs_parity(&[b"aaaa", b"bbbb"], 0);
        inject_voice_inbound(
            &svc,
            11,
            fec_parity_frame(0xABC, 42, vec![1, 2], &parity, 0, 0),
        );
        let frames = wait_for_fec_sink(&sink, 2).await;
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[1].1.as_ref(), b"bbbb");
        drop(held);
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

        // Any two Reed-Solomon rows of block {1,2,3,4} recover both; 3 is
        // overdue when they arrive.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let members: [&[u8]; 4] = [b"aaaa", b"bbbb", b"cccc", b"dddd"];
        inject_voice_inbound(
            &svc,
            11,
            fec_parity_frame(
                0xABC,
                42,
                vec![1, 2, 3, 4],
                &fec_rs_parity(&members, 0),
                0,
                0,
            ),
        );
        inject_voice_inbound(
            &svc,
            11,
            fec_parity_frame(
                0xABC,
                42,
                vec![1, 2, 3, 4],
                &fec_rs_parity(&members, 2),
                2,
                0,
            ),
        );

        wait_for_fec_sink(&sink, 3).await;
        // 4 is solved with 3 but waits for its own due time; frame 5 arriving
        // late recovers it in order ahead of 5.
        tokio::time::sleep(Duration::from_millis(10)).await;
        inject_voice_inbound(&svc, 11, fec_data_frame(5, b"eeee"));
        let frames = wait_for_fec_sink(&sink, 5).await;
        assert_eq!(frames[2].0, 3);
        assert_eq!(frames[2].1.as_ref(), b"cccc");
        assert_eq!(frames[3].0, 4);
        assert_eq!(frames[3].1.as_ref(), b"dddd");
        assert_eq!(frames[4].0, 5);
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
    async fn failed_terminator_captures_quality_once() {
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
    }

    #[tokio::test]
    async fn terminator_reuses_one_quality_batch_for_fec_and_proactive_repairs() {
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
    }

    #[tokio::test]
    async fn repair_and_fec_disabled_send_captures_no_route_quality() {
        let transport = FakeVoiceTransport::new(7, vec![2]);
        transport.set_voice_route_quality(
            2,
            VoiceRouteQuality::new(2, TransportKind::Udp, 20_000, 1_000_000, 0),
        );
        let mut cfg = VoiceConfig::default();
        cfg.repair_enabled = false;
        cfg.voice_fec_enabled = false;
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
        svc.voice_budget.mint_link_credit(3, 0xABC, 42, usize::MAX);
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
        assert_eq!(
            transport.inner.route_quality_scalar_calls(),
            1,
            "FEC checks the copy link without changing the captured duplicate decision"
        );
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
