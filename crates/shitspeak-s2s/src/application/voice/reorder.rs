//! Per-speaker reorder buffer for inbound voice frames.
//!
//! Sits between the dispatch task (which decodes inbound `OverlayData`
//! frames) and the [`AudioSink`] (which runs local fan-out). Holds back
//! Holds only frames that arrived after an actual S2S sequence gap. In-order
//! frames emit immediately; a per-speaker deadline gives a repair copy a short
//! opportunity to close the gap before the buffered suffix emits in sequence
//! order.
//!
//! All emit decisions are made under a single `parking_lot::Mutex`;
//! the lock is never held across an `await`. The dispatch task and the
//! deadline task both feed into the same single mpsc so that
//! `AudioSink::deliver` calls remain serialized (per-sender ordering is
//! preserved).
//!
//! `sender_epoch` distinguishes a restarted sender from a delayed copy of an
//! existing stream. A newer ordinary original resets the speaker state; late
//! same-epoch originals are discarded so they cannot rewind delivery.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::trace;

use crate::application::config::VoiceConfig;
use crate::application::proto::VoiceFrame;
use crate::application::voice::metrics::{self, VoiceDeadlineWakeResult, VoiceReceiveResult};
use shitspeak_core::NodeIdentifier;

const ADAPTIVE_JITTER_IN_ORDER_DECAY_RUN: u32 = 16;
const DEFAULT_MAX_USERS: u64 = 5_000;
const MIN_TRACKED_SPEAKERS: usize = 1_024;
const MAX_TRACKED_SPEAKERS: usize = 16_384;

/// One emit decision: forward the bundled `(from_immediate, frame)` to
/// the audio sink.
pub type Emission = (NodeIdentifier, VoiceFrame);

/// Provenance of one copy of a voice frame.
///
/// A proactive copy is eligible to establish delivery when it wins the race
/// with the original, but it must never rewind an established sender cursor.
/// Reactive repairs are still more constrained: they only fill an already
/// open gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum VoiceCopyKind {
    ReactiveRepair,
    Proactive,
    Original,
}

impl VoiceCopyKind {
    fn is_reactive_repair(self) -> bool {
        matches!(self, Self::ReactiveRepair)
    }
}

/// Internal form of an emitted frame that preserves whether this exact copy
/// was the tree's one alternate repair. The public reorder API intentionally
/// retains its original tuple shape; only the voice ingress needs this
/// additional delivery provenance.
#[derive(Debug, Clone)]
pub(crate) struct ReorderEmission {
    from: NodeIdentifier,
    frame: VoiceFrame,
    copy_kind: VoiceCopyKind,
}

impl ReorderEmission {
    fn new(from: NodeIdentifier, frame: VoiceFrame, copy_kind: VoiceCopyKind) -> Self {
        Self {
            from,
            frame,
            copy_kind,
        }
    }

    pub(crate) fn into_parts(self) -> (NodeIdentifier, VoiceFrame, bool) {
        (self.from, self.frame, self.copy_kind.is_reactive_repair())
    }

    pub(crate) fn from(&self) -> NodeIdentifier {
        self.from
    }

    pub(crate) fn frame(&self) -> &VoiceFrame {
        &self.frame
    }

    fn into_emission(self) -> Emission {
        (self.from, self.frame)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReorderResultCount {
    result: VoiceReceiveResult,
    count: usize,
}

impl ReorderResultCount {
    fn new(result: VoiceReceiveResult, count: usize) -> Self {
        Self { result, count }
    }

    pub(crate) fn result(self) -> VoiceReceiveResult {
        self.result
    }

    pub(crate) fn count(self) -> usize {
        self.count
    }
}

/// One peer's share of a deadline flush in a single drain pass.
///
/// When a chunk's chunk-hold budget exhausts, the whole buffered chunk emits
/// at once. `count` is how many of those frames arrived via `from`, and
/// `max_held_delay_us` is the longest any flushed chunk was held beyond the
/// in-order skew tolerance. This is the receiver-side UX symptom (delayed
/// playout) attributed to the immediate peer that carried the frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FlushByPeer {
    pub from: NodeIdentifier,
    pub count: usize,
    pub max_held_delay_us: u64,
}

#[derive(Debug, Default)]
pub(crate) struct ReorderReport {
    emissions: Vec<ReorderEmission>,
    results: Vec<ReorderResultCount>,
    pending_total: usize,
    opened_gap: Option<GapReport>,
    flushes_by_peer: Vec<FlushByPeer>,
}

impl ReorderReport {
    fn new(
        emissions: Vec<ReorderEmission>,
        results: Vec<ReorderResultCount>,
        pending_total: usize,
        opened_gap: Option<GapReport>,
    ) -> Self {
        Self {
            emissions,
            results,
            pending_total,
            opened_gap,
            flushes_by_peer: Vec::new(),
        }
    }

    fn with_flushes(mut self, flushes_by_peer: Vec<FlushByPeer>) -> Self {
        self.flushes_by_peer = flushes_by_peer;
        self
    }

    /// Deadline flushes attributed per immediate peer, including the held
    /// delay each chunk was forced to absorb before release.
    pub(crate) fn flushes_by_peer(&self) -> &[FlushByPeer] {
        &self.flushes_by_peer
    }

    pub(crate) fn result_counts(&self) -> &[ReorderResultCount] {
        &self.results
    }

    pub(crate) fn pending_total(&self) -> usize {
        self.pending_total
    }

    /// The one transition from no pending suffix to an open S2S sequence gap.
    /// Ingress uses this to schedule exactly one repair request.
    pub(crate) fn opened_gap(&self) -> Option<GapReport> {
        self.opened_gap
    }

    pub(crate) fn into_emissions(self) -> Vec<Emission> {
        self.emissions
            .into_iter()
            .map(ReorderEmission::into_emission)
            .collect()
    }

    pub(crate) fn into_marked_emissions(self) -> Vec<ReorderEmission> {
        self.emissions
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapReport {
    pub from: NodeIdentifier,
    pub sender_session: u32,
    pub sender_epoch: u64,
    pub first_seq: u64,
    pub last_seq: u64,
}

/// The currently actionable missing range for an already-open gap.
///
/// Unlike [`GapReport`], which records the range that originally opened the
/// gap, this range follows repair progress while retaining the original
/// playout deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActionableGap {
    gap: GapReport,
    deadline: Instant,
}

impl ActionableGap {
    pub(crate) fn gap(self) -> GapReport {
        self.gap
    }

    pub(crate) fn deadline(self) -> Instant {
        self.deadline
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoiceRouteHint {
    path_latency_us: u64,
    jitter_us: u64,
    loss_ppm: u32,
}

impl VoiceRouteHint {
    pub fn new(path_latency_us: u64, jitter_us: u64, loss_ppm: u32) -> Self {
        Self {
            path_latency_us,
            jitter_us,
            loss_ppm,
        }
    }
}

/// Public reorder gate. Cheap to clone — internally `Arc`-wrapped.
pub struct Reorderer {
    cfg: VoiceConfig,
    max_users: Arc<AtomicU64>,
    state: Mutex<ReorderInner>,
    deadline_notify: Arc<Notify>,
    deadline_wake_pending: AtomicBool,
    deadline_wake_ack: Notify,
}

struct ReorderInner {
    per_sender: HashMap<u32, SenderState>,
    deadlines: BinaryHeap<Reverse<(Instant, u32)>>,
    idle_deadlines: BinaryHeap<Reverse<(Instant, u32)>>,
    total_pending: usize,
}

struct SenderState {
    sender_epoch: u64,
    next_seq: u64,
    pending: BTreeMap<u64, ReorderEmission>,
    deadline: Option<Instant>,
    /// The instant the open gap's in-order skew tolerance expires. When the
    /// deadline fires unfilled the chunk enters hold-first mode: it is held
    /// (rather than flushed around the hole) until this instant plus
    /// `chunk_hold_budget_ms`, and the whole chunk then emits at once.
    /// `None` when no gap is open.
    hold_started_at: Option<Instant>,
    adaptive_delay_ms: u64,
    in_order_run: u32,
    last_activity: Instant,
}

impl Reorderer {
    pub fn new(cfg: VoiceConfig) -> Arc<Self> {
        Self::new_with_capacity_source(cfg, Arc::new(AtomicU64::new(DEFAULT_MAX_USERS)))
    }

    /// Construct a reorderer whose tracked-speaker limit follows the shared
    /// runtime user-capacity source. Existing streams are never evicted when
    /// the configured capacity falls; the current value gates only new state.
    pub(crate) fn new_with_capacity_source(
        cfg: VoiceConfig,
        max_users: Arc<AtomicU64>,
    ) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            max_users,
            state: Mutex::new(ReorderInner {
                per_sender: HashMap::new(),
                deadlines: BinaryHeap::new(),
                idle_deadlines: BinaryHeap::new(),
                total_pending: 0,
            }),
            deadline_notify: Arc::new(Notify::new()),
            deadline_wake_pending: AtomicBool::new(false),
            deadline_wake_ack: Notify::new(),
        })
    }

    pub fn deadline_notify(&self) -> Arc<Notify> {
        self.deadline_notify.clone()
    }

    pub fn config(&self) -> &VoiceConfig {
        &self.cfg
    }

    /// Maximum concurrently tracked speaker streams for the current runtime
    /// user limit. It intentionally applies only to new stream admission.
    pub(crate) fn tracked_speaker_capacity(&self) -> usize {
        self.max_users
            .load(Ordering::Relaxed)
            .saturating_mul(2)
            .clamp(MIN_TRACKED_SPEAKERS as u64, MAX_TRACKED_SPEAKERS as u64) as usize
    }

    pub(crate) fn tracked_speaker_count(&self) -> usize {
        self.state.lock().per_sender.len()
    }

    /// Cheap preflight for computing route quality outside the reorder lock.
    /// The subsequent push remains authoritative if state changes meanwhile.
    pub(crate) fn may_arm_gap(&self, frame: &VoiceFrame, copy_kind: VoiceCopyKind) -> bool {
        if self.cfg.reorder_disabled || copy_kind != VoiceCopyKind::Original {
            return false;
        }
        let state = self.state.lock();
        let Some(entry) = state.per_sender.get(&frame.sender_session) else {
            return false;
        };
        if entry.sender_epoch != frame.sender_epoch
            || entry.deadline.is_some()
            || frame.s2s_seq <= entry.next_seq
        {
            return false;
        }
        if let Some(existing) = entry.pending.get(&frame.s2s_seq) {
            return copy_kind > existing.copy_kind;
        }
        let per_sender_cap = self.cfg.reorder_max_buffered_frames;
        if per_sender_cap == 0 {
            return false;
        }
        let evicts_tail = if entry.pending.len() >= per_sender_cap {
            let Some(farthest_seq) = entry.pending.keys().next_back().copied() else {
                return false;
            };
            if frame.s2s_seq > farthest_seq {
                return false;
            }
            true
        } else {
            false
        };
        let pending_after_eviction = state.total_pending.saturating_sub(usize::from(evicts_tail));
        pending_after_eviction < self.cfg.reorder_max_total_buffer
    }

    /// Earliest gap or idle-pruning deadline. Used by the deadline task to
    /// decide how long to sleep.
    pub fn next_deadline(&self) -> Option<Instant> {
        let state = self.state.lock();
        match (state.deadlines.peek(), state.idle_deadlines.peek()) {
            (Some(Reverse((deadline, _))), Some(Reverse((idle, _)))) => {
                Some((*deadline).min(*idle))
            }
            (Some(Reverse((deadline, _))), None) => Some(*deadline),
            (None, Some(Reverse((idle, _)))) => Some(*idle),
            (None, None) => None,
        }
    }

    fn adaptive_delay_bounds_ms(&self) -> (u64, u64) {
        let min = self.cfg.adaptive_jitter_min_delay_ms;
        let max = self.cfg.adaptive_jitter_max_delay_ms.max(min);
        (min, max)
    }

    fn initial_adaptive_delay_ms(&self) -> u64 {
        let (min, max) = self.adaptive_delay_bounds_ms();
        self.cfg.reorder_max_delay_ms.clamp(min, max)
    }

    pub fn route_repair_delay_ms_for_config(cfg: &VoiceConfig, hint: VoiceRouteHint) -> u64 {
        let min = cfg.adaptive_jitter_min_delay_ms;
        let base = cfg
            .reorder_max_delay_ms
            .clamp(min, cfg.adaptive_jitter_max_delay_ms.max(min));
        let path_ms = hint.path_latency_us.saturating_add(999) / 1_000;
        let jitter_ms = hint.jitter_us.saturating_add(999) / 1_000;
        let loss_margin_ms = u64::from(hint.loss_ppm / 1_000).min(100);
        let route_delay = path_ms
            .saturating_add(jitter_ms.saturating_mul(3))
            .saturating_add(loss_margin_ms)
            .saturating_add(20);
        base.max(route_delay).min(cfg.repair_cache_ms.max(base))
    }

    pub fn route_repair_delay_ms(&self, hint: VoiceRouteHint) -> u64 {
        Self::route_repair_delay_ms_for_config(&self.cfg, hint)
    }

    fn effective_delay_ms(&self, entry: &SenderState) -> u64 {
        if self.cfg.adaptive_jitter_enabled {
            entry.adaptive_delay_ms
        } else {
            self.initial_adaptive_delay_ms()
        }
    }

    fn effective_route_delay_ms(
        &self,
        entry: &SenderState,
        route_hint: Option<VoiceRouteHint>,
    ) -> u64 {
        let base = self.effective_delay_ms(entry);
        let Some(hint) = route_hint else {
            return base;
        };
        base.max(self.route_repair_delay_ms(hint))
            .min(self.cfg.repair_cache_ms.max(base))
    }

    fn arm_gap(
        &self,
        state: &mut ReorderInner,
        entry: &mut SenderState,
        session: u32,
        from: NodeIdentifier,
        sender_epoch: u64,
        route_hint: Option<VoiceRouteHint>,
        now: Instant,
    ) -> GapReport {
        let deadline =
            now + Duration::from_millis(self.effective_route_delay_ms(entry, route_hint));
        entry.deadline = Some(deadline);
        // The chunk enters hold-first mode when this skew deadline passes
        // unfilled; it stays held until `hold_started_at + chunk_hold_budget_ms`.
        entry.hold_started_at = Some(deadline);
        state.deadlines.push(Reverse((deadline, session)));
        self.deadline_notify.notify_one();
        let first_pending = entry
            .pending
            .keys()
            .next()
            .copied()
            .expect("a gap is armed only after buffering a suffix");
        GapReport {
            from,
            sender_session: session,
            sender_epoch,
            first_seq: entry.next_seq,
            last_seq: first_pending.saturating_sub(1),
        }
    }

    /// The absolute instant beyond which an open gap is permanently missed.
    /// This is the chunk-hold deadline: the in-order skew tolerance plus the
    /// hold budget. Zero hold budget collapses it to the skew deadline (the
    /// legacy flush behavior).
    fn gap_hold_deadline(&self, entry: &SenderState) -> Option<Instant> {
        entry
            .hold_started_at
            .map(|start| start + Duration::from_millis(self.cfg.chunk_hold_budget_ms))
    }

    /// Whether the sender's open gap is still repairable. The gap stays live
    /// through the in-order skew tolerance AND the chunk-hold window, so a
    /// late repair can still close the hole and emit the whole chunk
    /// contiguously (delayed) instead of clipping.
    fn gap_is_live(&self, entry: &SenderState, now: Instant) -> bool {
        if entry.pending.is_empty() {
            return false;
        }
        matches!(self.gap_hold_deadline(entry), Some(deadline) if deadline > now)
    }

    /// Whether the chunk is currently being held beyond the in-order skew
    /// tolerance (the skew deadline has passed and the hold budget has not).
    fn chunk_in_hold(&self, entry: &SenderState, now: Instant) -> bool {
        let Some(started) = entry.hold_started_at else {
            return false;
        };
        started <= now
            && matches!(self.gap_hold_deadline(entry), Some(deadline) if deadline > now)
    }

    fn grow_adaptive_delay(&self, entry: &mut SenderState) {
        if !self.cfg.adaptive_jitter_enabled {
            return;
        }
        let (_, max) = self.adaptive_delay_bounds_ms();
        entry.adaptive_delay_ms = entry
            .adaptive_delay_ms
            .saturating_add(self.cfg.adaptive_jitter_growth_step_ms)
            .min(max);
        entry.in_order_run = 0;
    }

    fn record_clean_in_order(&self, entry: &mut SenderState) {
        if !self.cfg.adaptive_jitter_enabled {
            return;
        }
        entry.in_order_run = entry.in_order_run.saturating_add(1);
        if entry.in_order_run < ADAPTIVE_JITTER_IN_ORDER_DECAY_RUN {
            return;
        }
        let (min, _) = self.adaptive_delay_bounds_ms();
        entry.adaptive_delay_ms = entry
            .adaptive_delay_ms
            .saturating_sub(self.cfg.adaptive_jitter_decay_step_ms)
            .max(min);
        entry.in_order_run = 0;
    }

    fn idle_reset_duration(&self) -> Duration {
        Duration::from_millis(self.cfg.reorder_idle_reset_ms.max(1))
    }

    fn enqueue_idle_deadline(&self, state: &mut ReorderInner, session: u32, now: Instant) {
        let deadline = now + self.idle_reset_duration();
        let current_earliest = match (state.deadlines.peek(), state.idle_deadlines.peek()) {
            (Some(Reverse((gap, _))), Some(Reverse((idle, _)))) => Some((*gap).min(*idle)),
            (Some(Reverse((gap, _))), None) => Some(*gap),
            (None, Some(Reverse((idle, _)))) => Some(*idle),
            (None, None) => None,
        };
        state.idle_deadlines.push(Reverse((deadline, session)));
        // A quiet stream has no gap deadline to wake the task, so interrupt a
        // current sleep only when this creates an earlier deadline.
        if match current_earliest {
            Some(current) => deadline < current,
            None => true,
        } {
            self.deadline_notify.notify_one();
        }
    }

    fn prune_idle(&self, state: &mut ReorderInner, now: Instant) {
        while let Some(Reverse((deadline, session))) = state.idle_deadlines.peek().copied() {
            if deadline > now {
                break;
            }
            state.idle_deadlines.pop();

            let Some(entry) = state.per_sender.get(&session) else {
                continue;
            };
            let current_deadline = entry.last_activity + self.idle_reset_duration();
            if current_deadline > now {
                // The speaker was active after this timer was armed. Requeue
                // once at its actual idle boundary instead of per packet.
                state
                    .idle_deadlines
                    .push(Reverse((current_deadline, session)));
                continue;
            }

            let removed = state
                .per_sender
                .remove(&session)
                .expect("sender state existed while pruning");
            state.total_pending = state.total_pending.saturating_sub(removed.pending.len());
        }
    }

    /// Push an inbound delivery through the gate. Returns the sequence
    /// of frames the caller should hand to the audio sink, in the order
    /// they're returned. May be empty (frame is buffered) or contain
    /// multiple entries (the frame closed a gap and drained pending).
    pub fn push(&self, from: NodeIdentifier, frame: VoiceFrame) -> Vec<Emission> {
        self.push_with_route_hint(from, frame, None)
    }

    /// Push an inbound delivery with an optional route-quality hint. When
    /// present, the hint raises the per-sender deadline enough to leave room
    /// for a NACK round trip and repair copy on farther or lossier paths.
    pub fn push_with_route_hint(
        &self,
        from: NodeIdentifier,
        frame: VoiceFrame,
        route_hint: Option<VoiceRouteHint>,
    ) -> Vec<Emission> {
        self.push_with_route_hint_report(from, frame, route_hint)
            .into_emissions()
    }

    pub(crate) fn push_with_route_hint_report(
        &self,
        from: NodeIdentifier,
        frame: VoiceFrame,
        route_hint: Option<VoiceRouteHint>,
    ) -> ReorderReport {
        self.push_with_route_hint_report_with_copy_kind(
            from,
            frame,
            route_hint,
            VoiceCopyKind::Original,
        )
    }

    /// Compatibility entry point for callers that only distinguish ordinary
    /// originals from reactive repairs. New callers should retain proactive
    /// provenance with [`VoiceCopyKind`].
    #[cfg(test)]
    pub(crate) fn push_with_route_hint_report_with_repair(
        &self,
        from: NodeIdentifier,
        frame: VoiceFrame,
        route_hint: Option<VoiceRouteHint>,
        is_repair: bool,
    ) -> ReorderReport {
        let copy_kind = if is_repair {
            VoiceCopyKind::ReactiveRepair
        } else {
            VoiceCopyKind::Original
        };
        self.push_with_route_hint_report_with_copy_kind(from, frame, route_hint, copy_kind)
    }

    pub(crate) fn push_with_route_hint_report_with_copy_kind(
        &self,
        from: NodeIdentifier,
        frame: VoiceFrame,
        route_hint: Option<VoiceRouteHint>,
        copy_kind: VoiceCopyKind,
    ) -> ReorderReport {
        if self.cfg.reorder_disabled {
            return ReorderReport::new(
                vec![ReorderEmission::new(from, frame, copy_kind)],
                vec![ReorderResultCount::new(VoiceReceiveResult::InOrder, 1)],
                0,
                None,
            );
        }

        let mut emit: Vec<ReorderEmission> = Vec::new();
        let mut results: Vec<ReorderResultCount> = Vec::new();
        let mut state = self.state.lock();
        let session = frame.sender_session;
        let frame_seq = frame.s2s_seq;
        let sender_epoch = frame.sender_epoch;
        let now = Instant::now();
        self.prune_idle(&mut state, now);

        // A reactive repair cannot create a speaker stream. An original or
        // proactive copy may bootstrap when it wins the race to the receiver.
        if !state.per_sender.contains_key(&session) && copy_kind.is_reactive_repair() {
            results.push(ReorderResultCount::new(
                VoiceReceiveResult::DuplicateOrLate,
                1,
            ));
            return ReorderReport::new(emit, results, state.total_pending, None);
        }

        if !state.per_sender.contains_key(&session)
            && state.per_sender.len() >= self.tracked_speaker_capacity()
        {
            results.push(ReorderResultCount::new(
                VoiceReceiveResult::SpeakerStateDrop,
                1,
            ));
            return ReorderReport::new(emit, results, state.total_pending, None);
        }

        // Bootstrap from the first original or proactive sequence instead of
        // assuming a source always starts at zero.
        let initial_adaptive_delay_ms = self.initial_adaptive_delay_ms();
        if !state.per_sender.contains_key(&session) {
            state.per_sender.insert(
                session,
                SenderState {
                    sender_epoch,
                    next_seq: frame_seq,
                    pending: BTreeMap::new(),
                    deadline: None,
                    hold_started_at: None,
                    adaptive_delay_ms: initial_adaptive_delay_ms,
                    in_order_run: 0,
                    last_activity: now,
                },
            );
            self.enqueue_idle_deadline(&mut state, session, now);
        }

        // Take the speaker state out of the map while deciding this frame so
        // global pending/deadline accounting remains independent of the
        // per-speaker buffer borrow.
        let mut entry = state
            .per_sender
            .remove(&session)
            .expect("speaker state was just inserted or already present");

        // A newer ordinary original is the sender-restart discriminator. A
        // proactive or reactive copy must never reset an established stream,
        // and a delayed frame from an older epoch cannot be useful anymore.
        if sender_epoch != entry.sender_epoch {
            if sender_epoch < entry.sender_epoch || copy_kind != VoiceCopyKind::Original {
                results.push(ReorderResultCount::new(
                    VoiceReceiveResult::DuplicateOrLate,
                    1,
                ));
                state.per_sender.insert(session, entry);
                return ReorderReport::new(emit, results, state.total_pending, None);
            }

            let dropped = std::mem::take(&mut entry.pending).len();
            state.total_pending = state.total_pending.saturating_sub(dropped);
            entry.sender_epoch = sender_epoch;
            entry.next_seq = frame_seq;
            entry.deadline = None;
            entry.hold_started_at = None;
            entry.adaptive_delay_ms = initial_adaptive_delay_ms;
            entry.in_order_run = 0;
        }
        entry.last_activity = now;

        // Once a stream has advanced, every lower same-epoch sequence is a
        // duplicate or late arrival. Rewinding here re-emits audio and breaks
        // the receiver's monotonic stream contract.
        if frame_seq < entry.next_seq {
            results.push(ReorderResultCount::new(
                VoiceReceiveResult::DuplicateOrLate,
                1,
            ));
            state.per_sender.insert(session, entry);
            return ReorderReport::new(emit, results, state.total_pending, None);
        }

        // In-order frames emit immediately and drain a contiguous buffered
        // suffix immediately. This is ordering only, never media pacing.
        if frame_seq == entry.next_seq {
            // A reactive repair may only close a previously opened gap. It
            // cannot advance a healthy stream by itself.
            let gap_open = self.gap_is_live(&entry, now);
            if copy_kind.is_reactive_repair() && !gap_open {
                results.push(ReorderResultCount::new(
                    VoiceReceiveResult::DuplicateOrLate,
                    1,
                ));
                state.per_sender.insert(session, entry);
                return ReorderReport::new(emit, results, state.total_pending, None);
            }
            results.push(ReorderResultCount::new(VoiceReceiveResult::InOrder, 1));
            emit.push(ReorderEmission::new(from, frame, copy_kind));
            entry.next_seq = entry.next_seq.saturating_add(1);
            let mut drained_count: usize = 0;
            loop {
                let next_pending_seq = entry.pending.keys().next().copied();
                match next_pending_seq {
                    Some(seq) if seq == entry.next_seq => {
                        let pair = entry.pending.remove(&seq).unwrap();
                        entry.next_seq = entry.next_seq.saturating_add(1);
                        emit.push(pair);
                        drained_count += 1;
                    }
                    _ => break,
                }
            }
            if entry.pending.is_empty() {
                entry.deadline = None;
                entry.hold_started_at = None;
            }
            if drained_count > 0 {
                results.push(ReorderResultCount::new(
                    VoiceReceiveResult::GapFilled,
                    drained_count,
                ));
                entry.in_order_run = 0;
            } else if entry.pending.is_empty() {
                self.record_clean_in_order(&mut entry);
            }
            state.total_pending = state.total_pending.saturating_sub(drained_count);
        } else {
            // A reactive repair cannot create a new gap. It can only join an
            // existing suffix opened by an original or proactive copy.
            let gap_open = self.gap_is_live(&entry, now);
            if copy_kind.is_reactive_repair() && !gap_open {
                results.push(ReorderResultCount::new(
                    VoiceReceiveResult::DuplicateOrLate,
                    1,
                ));
                state.per_sender.insert(session, entry);
                return ReorderReport::new(emit, results, state.total_pending, None);
            }

            // A real gap: retain the nearest pending suffix, not the oldest
            // arrival. Keeping the earliest available sequence maximizes the
            // chance a single repair can immediately drain useful audio.
            if let Some(existing) = entry.pending.get(&frame_seq) {
                if copy_kind > existing.copy_kind {
                    entry
                        .pending
                        .insert(frame_seq, ReorderEmission::new(from, frame, copy_kind));
                    results.push(ReorderResultCount::new(VoiceReceiveResult::GapBuffered, 1));

                    let gap = if entry.deadline.is_none() && copy_kind == VoiceCopyKind::Original {
                        Some(self.arm_gap(
                            &mut state,
                            &mut entry,
                            session,
                            from,
                            sender_epoch,
                            route_hint,
                            now,
                        ))
                    } else {
                        None
                    };
                    state.per_sender.insert(session, entry);
                    return ReorderReport::new(emit, results, state.total_pending, gap);
                } else {
                    results.push(ReorderResultCount::new(
                        VoiceReceiveResult::DuplicateOrLate,
                        1,
                    ));
                }
                state.per_sender.insert(session, entry);
                return ReorderReport::new(emit, results, state.total_pending, None);
            }

            let per_sender_cap = self.cfg.reorder_max_buffered_frames;
            if per_sender_cap == 0 {
                results.push(ReorderResultCount::new(VoiceReceiveResult::BufferDrop, 1));
                state.per_sender.insert(session, entry);
                return ReorderReport::new(emit, results, state.total_pending, None);
            }
            if entry.pending.len() >= per_sender_cap {
                let farthest_seq = *entry
                    .pending
                    .keys()
                    .next_back()
                    .expect("nonempty pending buffer at capacity");
                if frame_seq > farthest_seq {
                    results.push(ReorderResultCount::new(VoiceReceiveResult::BufferDrop, 1));
                    state.per_sender.insert(session, entry);
                    return ReorderReport::new(emit, results, state.total_pending, None);
                }
                entry.pending.remove(&farthest_seq);
                state.total_pending = state.total_pending.saturating_sub(1);
                results.push(ReorderResultCount::new(VoiceReceiveResult::BufferDrop, 1));
            }

            // Node-wide cap is an emergency guard. Do not evict another
            // speaker's earliest pending frame to admit this one.
            if state.total_pending >= self.cfg.reorder_max_total_buffer {
                trace!(
                    session,
                    seq = frame_seq,
                    "voice reorder: node-wide buffer full; dropping"
                );
                results.push(ReorderResultCount::new(VoiceReceiveResult::BufferDrop, 1));
                state.per_sender.insert(session, entry);
                return ReorderReport::new(emit, results, state.total_pending, None);
            }

            entry
                .pending
                .insert(frame_seq, ReorderEmission::new(from, frame, copy_kind));
            entry.in_order_run = 0;
            results.push(ReorderResultCount::new(VoiceReceiveResult::GapBuffered, 1));
            state.total_pending = state.total_pending.saturating_add(1);

            let gap = if entry.deadline.is_none() && copy_kind == VoiceCopyKind::Original {
                Some(self.arm_gap(
                    &mut state,
                    &mut entry,
                    session,
                    from,
                    sender_epoch,
                    route_hint,
                    now,
                ))
            } else {
                None
            };
            state.per_sender.insert(session, entry);
            return ReorderReport::new(emit, results, state.total_pending, gap);
        }

        // Terminators take the same ordered path as all other frames. They do
        // not flush a noncontiguous suffix early.
        state.per_sender.insert(session, entry);
        ReorderReport::new(emit, results, state.total_pending, None)
    }

    /// Drain every deadline that has expired. Returns frames in
    /// per-sender seq order; cross-sender ordering is unspecified.
    pub fn drain_expired(&self) -> Vec<Emission> {
        self.drain_expired_report().into_emissions()
    }

    pub(crate) fn drain_expired_report(&self) -> ReorderReport {
        let mut emit: Vec<ReorderEmission> = Vec::new();
        let mut results: Vec<ReorderResultCount> = Vec::new();
        let mut flushes_by_peer: Vec<FlushByPeer> = Vec::new();
        let mut state = self.state.lock();
        let now = Instant::now();
        self.prune_idle(&mut state, now);
        loop {
            let next = state.deadlines.peek().copied();
            let Some(Reverse((deadline, session))) = next else {
                break;
            };
            if deadline > now {
                break;
            }
            state.deadlines.pop();
            // Stale heap entry? The gap may have been filled, rebased, or
            // the speaker may have been pruned.
            let Some(entry) = state.per_sender.get(&session) else {
                continue;
            };
            if entry.deadline != Some(deadline) {
                continue;
            }

            // Hold-first gap policy: when the in-order skew tolerance (the
            // armed deadline) expires with the hole still open, the chunk is
            // HELD rather than flushed around the hole. Only the chunk-hold
            // budget is the point of no return; until then a late repair can
            // still emit the whole chunk contiguously (delayed) rather than
            // clip.
            if let Some(hold_started) = entry.hold_started_at {
                let hold_until = hold_started
                    + Duration::from_millis(self.cfg.chunk_hold_budget_ms);
                if now < hold_until {
                    // Re-arm the deadline task for the hold-budget expiry and
                    // keep the whole buffered chunk.
                    let entry = state.per_sender.get_mut(&session).unwrap();
                    entry.deadline = Some(hold_until);
                    state.deadlines.push(Reverse((hold_until, session)));
                    continue;
                }
            }

            // Drain in seq order, jump next_seq past the highest seq
            // we drained. This is the whole buffered chunk at once: a
            // contiguous, delayed emit rather than a per-frame skip.
            let drained: Vec<(u64, ReorderEmission)> = {
                let entry = state.per_sender.get_mut(&session).unwrap();
                // Sample the held delay BEFORE clearing `hold_started_at`:
                // this is the exact UX cost the receiver just imposed (the
                // chunk played out late, after the whole hold window).
                let held_delay_us = entry
                    .hold_started_at
                    .map(|start| {
                        u64::try_from(now.saturating_duration_since(start).as_micros())
                            .unwrap_or(u64::MAX)
                    })
                    .unwrap_or(0);
                let drained: Vec<(u64, ReorderEmission)> =
                    std::mem::take(&mut entry.pending).into_iter().collect();
                entry.deadline = None;
                entry.hold_started_at = None;
                if !drained.is_empty() {
                    self.grow_adaptive_delay(entry);
                }
                if let Some((max_seq, _)) = drained.last() {
                    entry.next_seq = max_seq.saturating_add(1);
                }
                for (_, emission) in &drained {
                    let from = emission.from();
                    match flushes_by_peer.iter_mut().find(|flush| flush.from == from) {
                        Some(flush) => {
                            flush.count = flush.count.saturating_add(1);
                            flush.max_held_delay_us = flush.max_held_delay_us.max(held_delay_us);
                        }
                        None => flushes_by_peer.push(FlushByPeer {
                            from,
                            count: 1,
                            max_held_delay_us: held_delay_us,
                        }),
                    }
                }
                drained
            };
            state.total_pending = state.total_pending.saturating_sub(drained.len());
            if !drained.is_empty() {
                results.push(ReorderResultCount::new(
                    VoiceReceiveResult::DeadlineFlush,
                    drained.len(),
                ));
            }
            for (_, emission) in drained {
                emit.push(emission);
            }
        }
        self.prune_idle(&mut state, now);
        let pending_total = state.total_pending;
        drop(state);
        self.acknowledge_deadline_wake();
        ReorderReport::new(emit, results, pending_total, None).with_flushes(flushes_by_peer)
    }

    fn acknowledge_deadline_wake(&self) {
        if self.deadline_wake_pending.swap(false, Ordering::AcqRel) {
            self.deadline_wake_ack.notify_one();
        }
    }

    pub fn gap_for_frame(&self, from: NodeIdentifier, frame: &VoiceFrame) -> Option<GapReport> {
        if self.cfg.reorder_disabled || frame.s2s_seq == 0 {
            return None;
        }
        let state = self.state.lock();
        let entry = state.per_sender.get(&frame.sender_session)?;
        if entry.sender_epoch != frame.sender_epoch
            || entry.next_seq >= frame.s2s_seq
            || !entry.pending.contains_key(&frame.s2s_seq)
        {
            return None;
        }
        Some(GapReport {
            from,
            sender_session: frame.sender_session,
            sender_epoch: frame.sender_epoch,
            first_seq: entry.next_seq,
            last_seq: frame.s2s_seq.saturating_sub(1),
        })
    }

    pub fn gap_still_missing(&self, gap: GapReport) -> bool {
        let state = self.state.lock();
        let Some(entry) = state.per_sender.get(&gap.sender_session) else {
            return false;
        };
        entry.sender_epoch == gap.sender_epoch
            && entry.next_seq <= gap.last_seq
            && self.gap_is_live(entry, Instant::now())
    }

    /// Return the live missing range for an existing repair coordinator.
    ///
    /// The caller supplies the immediate peer captured when the gap opened;
    /// sender state deliberately contains no routing information. The query
    /// is fenced by epoch and by the original reorder deadline, and never
    /// rearms or extends that deadline.
    pub(crate) fn current_actionable_gap(
        &self,
        from: NodeIdentifier,
        sender_session: u32,
        sender_epoch: u64,
    ) -> Option<ActionableGap> {
        if self.cfg.reorder_disabled {
            return None;
        }

        let state = self.state.lock();
        let entry = state.per_sender.get(&sender_session)?;
        // The repair coordinator should keep repairing until the chunk-hold
        // deadline, not just the in-order skew tolerance.
        let deadline = self.gap_hold_deadline(entry)?;
        if entry.sender_epoch != sender_epoch || deadline <= Instant::now() {
            return None;
        }
        let first_pending = entry.pending.keys().next().copied()?;
        if entry.next_seq >= first_pending {
            return None;
        }

        Some(ActionableGap {
            gap: GapReport {
                from,
                sender_session,
                sender_epoch,
                first_seq: entry.next_seq,
                last_seq: first_pending.saturating_sub(1),
            },
            deadline,
        })
    }
    #[cfg(test)]
    pub fn pending_total(&self) -> usize {
        self.state.lock().total_pending
    }

    #[cfg(test)]
    pub fn adaptive_delay_ms_for(&self, session: u32) -> Option<u64> {
        self.state
            .lock()
            .per_sender
            .get(&session)
            .map(|entry| entry.adaptive_delay_ms)
    }

    /// `(held_frames, max_held_delay_us)` sampled under one lock.
    ///
    /// A drain resets `hold_started_at` on the flushed sessions, so callers
    /// that observe held state around a drain (metrics gauges, feedback) must
    /// sample it with this method BEFORE draining, or the flushed chunks'
    /// delay is lost.
    pub(crate) fn held_state(&self) -> (usize, u64) {
        let state = self.state.lock();
        let now = Instant::now();
        let mut held_frames: usize = 0;
        let mut max_held_delay_us = 0u64;
        for entry in state.per_sender.values() {
            if !self.chunk_in_hold(entry, now) {
                continue;
            }
            held_frames = held_frames.saturating_add(entry.pending.len());
            if let Some(start) = entry.hold_started_at {
                let delay_us =
                    u64::try_from(now.saturating_duration_since(start).as_micros())
                        .unwrap_or(u64::MAX);
                max_held_delay_us = max_held_delay_us.max(delay_us);
            }
        }
        (held_frames, max_held_delay_us)
    }
}

/// Background task that watches the reorderer's deadline heap and
/// nudges the dispatch task to drain expired entries via
/// `dispatch_tx`. At most one nudge can be outstanding: after sending it,
/// this task waits for `drain_expired_report` to acknowledge dispatch before
/// considering another deadline. That keeps an expired entry from producing a
/// zero-duration wake loop while dispatch is busy.
pub fn spawn_deadline_task<F>(reorderer: Arc<Reorderer>, shutdown: CancellationToken, nudge: F)
where
    F: Fn() + Send + 'static,
{
    let notify = reorderer.deadline_notify();
    tokio::spawn(async move {
        loop {
            let next = reorderer.next_deadline();
            let sleep_for = match next {
                Some(deadline) => deadline.saturating_duration_since(Instant::now()),
                None => Duration::from_secs(3600),
            };
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(sleep_for) => {
                    if let Some(deadline) = reorderer.next_deadline() {
                        if Instant::now() >= deadline {
                            if reorderer
                                .deadline_wake_pending
                                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                                .is_ok()
                            {
                                metrics::record_deadline_wake(VoiceDeadlineWakeResult::Sent);
                                nudge();
                            } else {
                                metrics::record_deadline_wake(VoiceDeadlineWakeResult::Coalesced);
                            }
                            tokio::select! {
                                _ = shutdown.cancelled() => return,
                                _ = reorderer.deadline_wake_ack.notified() => {}
                            }
                        }
                    }
                }
                _ = notify.notified() => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::application::proto::{VoiceIntent, VoiceIntentKind, VoiceIntentNormal};
    use bytes::Bytes;
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::mpsc;

    fn cfg() -> VoiceConfig {
        VoiceConfig::default()
    }

    fn frame(session: u32, epoch: u64, seq: u64, terminator: bool) -> VoiceFrame {
        VoiceFrame {
            sender_session: session,
            server_id: shitspeak_core::default_server_id(),
            sender_epoch: epoch,
            s2s_seq: seq,
            target_kind: 0,
            is_terminator: terminator,
            payload: Bytes::from(format!("p-{seq}").into_bytes()),
            intent: Some(VoiceIntent {
                kind: Some(VoiceIntentKind::Normal(VoiceIntentNormal {
                    source_channel: 0,
                })),
            }),
            proactive_copy: false,
        }
    }

    #[test]
    fn in_order_pass_through() {
        let r = Reorderer::new(cfg());
        for s in 0..5 {
            let emits = r.push(11, frame(0xABC, 1, s, false));
            assert_eq!(emits.len(), 1);
            assert_eq!(emits[0].0, 11);
            assert_eq!(emits[0].1.s2s_seq, s);
        }
        assert_eq!(r.pending_total(), 0);
    }

    #[test]
    fn single_gap_then_fill() {
        let r = Reorderer::new(cfg());
        // 0 emits, 2 buffered, 1 fills the gap → emit 1, 2 in order.
        assert_eq!(r.push(11, frame(0xABC, 1, 0, false)).len(), 1);
        assert_eq!(r.push(11, frame(0xABC, 1, 2, false)).len(), 0);
        let emits = r.push(11, frame(0xABC, 1, 1, false));
        let seqs: Vec<u64> = emits.iter().map(|(_, f)| f.s2s_seq).collect();
        assert_eq!(seqs, vec![1, 2]);
        assert_eq!(r.pending_total(), 0);
    }

    #[test]
    fn reports_only_the_transition_that_opens_a_gap() {
        let r = Reorderer::new(cfg());
        r.push(11, frame(0xABC, 7, 0, false));

        let first = r.push_with_route_hint_report(11, frame(0xABC, 7, 3, false), None);
        let gap = first.opened_gap().expect("first buffered suffix opens gap");
        assert_eq!((gap.first_seq, gap.last_seq, gap.sender_epoch), (1, 2, 7));

        let later = r.push_with_route_hint_report(11, frame(0xABC, 7, 4, false), None);
        assert!(later.opened_gap().is_none());
    }

    #[test]
    fn duplicate_repair_frame_does_not_rebase_or_double_emit() {
        let r = Reorderer::new(cfg());
        assert_eq!(r.push(11, frame(0xABC, 1, 0, false)).len(), 1);
        assert!(
            r.push_with_route_hint_report_with_repair(11, frame(0xABC, 1, 0, false), None, true)
                .into_emissions()
                .is_empty()
        );
        assert_eq!(r.push(11, frame(0xABC, 1, 1, false)).len(), 1);
        assert!(
            r.push_with_route_hint_report_with_repair(11, frame(0xABC, 1, 1, false), None, true)
                .into_emissions()
                .is_empty()
        );
    }

    #[test]
    fn alternate_repair_provenance_survives_reordering() {
        let r = Reorderer::new(cfg());
        assert_eq!(r.push(11, frame(0xABC, 1, 0, false)).len(), 1);
        assert!(r.push(11, frame(0xABC, 1, 2, false)).is_empty());
        let emissions = r
            .push_with_route_hint_report_with_repair(11, frame(0xABC, 1, 1, false), None, true)
            .into_marked_emissions();
        let observed: Vec<_> = emissions
            .into_iter()
            .map(|emission| {
                let (_, frame, is_repair) = emission.into_parts();
                (frame.s2s_seq, is_repair)
            })
            .collect();
        assert_eq!(observed, vec![(1, true), (2, false)]);
    }

    #[test]
    fn original_replaces_buffered_repair_for_the_same_sequence() {
        let r = Reorderer::new(cfg());
        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 3, false));
        r.push_with_route_hint_report_with_repair(11, frame(0xABC, 1, 2, false), None, true);

        r.push_with_route_hint_report_with_repair(11, frame(0xABC, 1, 2, false), None, false);
        let emissions = r
            .push_with_route_hint_report_with_repair(11, frame(0xABC, 1, 1, false), None, false)
            .into_marked_emissions();
        let observed: Vec<_> = emissions
            .into_iter()
            .map(|emission| {
                let (_, frame, is_repair) = emission.into_parts();
                (frame.s2s_seq, is_repair)
            })
            .collect();
        assert_eq!(observed, vec![(1, false), (2, false), (3, false)]);
    }

    #[test]
    fn proactive_copy_can_bootstrap_and_emits_as_ordinary_voice() {
        let r = Reorderer::new(cfg());

        let emissions = r
            .push_with_route_hint_report_with_copy_kind(
                11,
                frame(0xABC, 1, 42, false),
                None,
                VoiceCopyKind::Proactive,
            )
            .into_marked_emissions();

        assert_eq!(emissions.len(), 1);
        let (_, frame, is_repair) = emissions.into_iter().next().unwrap().into_parts();
        assert_eq!(frame.s2s_seq, 42);
        assert!(!is_repair);
    }

    #[test]
    fn proactive_suffix_waits_for_an_original_to_confirm_the_gap() {
        let r = Reorderer::new(cfg());
        r.push(11, frame(0xABC, 1, 0, false));

        let proactive = r.push_with_route_hint_report_with_copy_kind(
            12,
            frame(0xABC, 1, 2, false),
            None,
            VoiceCopyKind::Proactive,
        );
        assert!(proactive.opened_gap().is_none());

        let original = r.push_with_route_hint_report_with_copy_kind(
            11,
            frame(0xABC, 1, 3, false),
            None,
            VoiceCopyKind::Original,
        );
        let gap = original.opened_gap().expect("original confirms the gap");
        assert_eq!((gap.first_seq, gap.last_seq), (1, 1));

        let emissions = r.push(11, frame(0xABC, 1, 1, false));
        assert_eq!(
            emissions
                .iter()
                .map(|(_, frame)| frame.s2s_seq)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn original_replacing_same_sequence_proactive_confirms_the_gap() {
        let r = Reorderer::new(cfg());
        r.push(11, frame(0xABC, 1, 0, false));
        let proactive = r.push_with_route_hint_report_with_copy_kind(
            12,
            frame(0xABC, 1, 2, false),
            None,
            VoiceCopyKind::Proactive,
        );
        assert!(proactive.opened_gap().is_none());

        let original = r.push_with_route_hint_report_with_copy_kind(
            11,
            frame(0xABC, 1, 2, false),
            None,
            VoiceCopyKind::Original,
        );
        let gap = original
            .opened_gap()
            .expect("same-sequence original confirms the gap");
        assert_eq!((gap.first_seq, gap.last_seq), (1, 1));
    }

    #[test]
    fn late_proactive_copy_cannot_rebase_an_established_cursor() {
        let r = Reorderer::new(cfg());
        assert_eq!(r.push(11, frame(0xABC, 1, 10, false)).len(), 1);
        assert!(r.push(11, frame(0xABC, 1, 12, false)).is_empty());
        assert_eq!(r.pending_total(), 1);

        let late = r
            .push_with_route_hint_report_with_copy_kind(
                11,
                frame(0xABC, 1, 4, false),
                None,
                VoiceCopyKind::Proactive,
            )
            .into_marked_emissions();
        assert!(late.is_empty());
        assert_eq!(r.pending_total(), 1);

        let emissions = r.push(11, frame(0xABC, 1, 11, false));
        assert_eq!(
            emissions
                .iter()
                .map(|(_, frame)| frame.s2s_seq)
                .collect::<Vec<_>>(),
            vec![11, 12]
        );
    }

    #[test]
    fn pending_copy_precedence_is_original_then_proactive_then_reactive() {
        let r = Reorderer::new(cfg());
        r.push(11, frame(0xABC, 1, 0, false));
        assert!(r.push(11, frame(0xABC, 1, 4, false)).is_empty());

        r.push_with_route_hint_report_with_copy_kind(
            11,
            frame(0xABC, 1, 2, false),
            None,
            VoiceCopyKind::ReactiveRepair,
        );
        r.push_with_route_hint_report_with_copy_kind(
            11,
            frame(0xABC, 1, 2, false),
            None,
            VoiceCopyKind::Proactive,
        );
        r.push_with_route_hint_report_with_copy_kind(
            11,
            frame(0xABC, 1, 2, false),
            None,
            VoiceCopyKind::Original,
        );

        let emissions = r
            .push_with_route_hint_report_with_copy_kind(
                11,
                frame(0xABC, 1, 1, false),
                None,
                VoiceCopyKind::Original,
            )
            .into_marked_emissions();
        assert_eq!(
            emissions
                .iter()
                .map(|emission| (emission.frame.s2s_seq, emission.copy_kind))
                .collect::<Vec<_>>(),
            vec![(1, VoiceCopyKind::Original), (2, VoiceCopyKind::Original),]
        );
    }

    #[test]
    fn gap_remains_missing_after_partial_fill() {
        let r = Reorderer::new(cfg());
        assert_eq!(r.push(11, frame(0xABC, 1, 0, false)).len(), 1);
        let out_of_order = frame(0xABC, 1, 3, false);
        assert!(r.push(11, out_of_order.clone()).is_empty());
        let gap = r.gap_for_frame(11, &out_of_order).unwrap();
        assert_eq!(gap.first_seq, 1);
        assert_eq!(gap.last_seq, 2);

        assert_eq!(r.push(11, frame(0xABC, 1, 1, false)).len(), 1);
        assert!(r.gap_still_missing(gap));

        let seqs: Vec<u64> = r
            .push(11, frame(0xABC, 1, 2, false))
            .into_iter()
            .map(|(_, frame)| frame.s2s_seq)
            .collect();
        assert_eq!(seqs, vec![2, 3]);
        assert!(!r.gap_still_missing(gap));
    }

    #[test]
    fn current_actionable_gap_tracks_successive_holes_without_extending_deadline() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 500;
        c.adaptive_jitter_min_delay_ms = 500;
        c.adaptive_jitter_max_delay_ms = 500;
        let r = Reorderer::new(c);
        let session = 0xABC;

        r.push(11, frame(session, 7, 0, false));
        r.push(11, frame(session, 7, 3, false));
        r.push(11, frame(session, 7, 5, false));

        let initial = r
            .current_actionable_gap(11, session, 7)
            .expect("the first hole is actionable");
        assert_eq!((initial.gap().first_seq, initial.gap().last_seq), (1, 2));
        let original_deadline = initial.deadline();

        assert_eq!(r.push(11, frame(session, 7, 1, false)).len(), 1);
        let partial = r
            .current_actionable_gap(11, session, 7)
            .expect("the remainder of the first hole is actionable");
        assert_eq!((partial.gap().first_seq, partial.gap().last_seq), (2, 2));
        assert_eq!(partial.deadline(), original_deadline);

        assert_eq!(
            r.push(11, frame(session, 7, 2, false))
                .iter()
                .map(|(_, frame)| frame.s2s_seq)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        let later = r
            .current_actionable_gap(11, session, 7)
            .expect("the later hole under the same deadline is actionable");
        assert_eq!((later.gap().first_seq, later.gap().last_seq), (4, 4));
        assert_eq!(later.deadline(), original_deadline);
    }

    #[test]
    fn current_actionable_gap_rejects_closed_expired_and_old_epoch_state() {
        let session = 0xABC;

        let r = Reorderer::new(cfg());
        r.push(11, frame(session, 1, 0, false));
        r.push(11, frame(session, 1, 2, false));
        assert!(r.current_actionable_gap(11, session, 1).is_some());
        r.push(11, frame(session, 1, 1, false));
        assert!(r.current_actionable_gap(11, session, 1).is_none());

        r.push(11, frame(session, 1, 4, false));
        assert!(r.current_actionable_gap(11, session, 1).is_some());
        r.push(11, frame(session, 2, 0, false));
        assert!(r.current_actionable_gap(11, session, 1).is_none());

        let mut c = cfg();
        c.reorder_max_delay_ms = 5;
        c.adaptive_jitter_min_delay_ms = 5;
        c.adaptive_jitter_max_delay_ms = 5;
        // Tiny hold budget: by the time the sleep elapses both the skew
        // tolerance and the chunk-hold window have passed, so the gap is
        // permanently missed.
        c.chunk_hold_budget_ms = 2;
        let expired = Reorderer::new(c);
        expired.push(11, frame(session, 3, 0, false));
        let out_of_order = frame(session, 3, 2, false);
        expired.push(11, out_of_order.clone());
        let opened = expired
            .gap_for_frame(11, &out_of_order)
            .expect("gap exists before its deadline");
        std::thread::sleep(Duration::from_millis(10));
        assert!(expired.current_actionable_gap(11, session, 3).is_none());
        assert!(!expired.gap_still_missing(opened));
    }

    #[test]
    fn deadline_fire_holds_chunk_until_repair_or_budget() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 40;
        c.adaptive_jitter_min_delay_ms = 40;
        c.adaptive_jitter_max_delay_ms = 40;
        let r = Reorderer::new(c);
        // 0 emits, 2 buffers (gap at 1). The 40ms in-order skew tolerance
        // expires but the chunk is HELD instead of flushed around the hole.
        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 2, false));
        std::thread::sleep(Duration::from_millis(60));
        assert!(r.drain_expired().is_empty());
        assert_eq!(r.held_state().0, 1);
        assert!(r.held_state().1 > 0);
        // A repair within the hold window still emits the whole chunk
        // contiguously (delayed), never a hole mid-playback.
        let repaired = r
            .push_with_route_hint_report_with_repair(11, frame(0xABC, 1, 1, false), None, true)
            .into_emissions();
        let seqs: Vec<u64> = repaired.iter().map(|(_, f)| f.s2s_seq).collect();
        assert_eq!(seqs, vec![1, 2]);
        // The stream is back in order.
        let on = r.push(11, frame(0xABC, 1, 3, false));
        let seqs: Vec<u64> = on.iter().map(|(_, f)| f.s2s_seq).collect();
        assert_eq!(seqs, vec![3]);
        assert_eq!(r.held_state().0, 0);
    }

    #[test]
    fn hold_budget_exhaustion_flushes_whole_chunk_at_once() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 40;
        c.adaptive_jitter_min_delay_ms = 40;
        c.adaptive_jitter_max_delay_ms = 40;
        c.chunk_hold_budget_ms = 5;
        let r = Reorderer::new(c);
        // 0 emits; 2 and 4 buffer (holes at 1 and 3). Once the chunk-hold
        // budget is exhausted the whole buffered chunk emits in one delayed
        // contiguous flush and the stream advances past it.
        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 2, false));
        r.push(11, frame(0xABC, 1, 4, false));
        std::thread::sleep(Duration::from_millis(60));
        let drained = r.drain_expired();
        let seqs: Vec<u64> = drained.iter().map(|(_, f)| f.s2s_seq).collect();
        assert_eq!(seqs, vec![2, 4]);
        // After the flush the holes are permanently missed: a late repair is
        // no longer admissible.
        let late = r
            .push_with_route_hint_report_with_repair(11, frame(0xABC, 1, 1, false), None, true)
            .into_emissions();
        assert!(late.is_empty());
        assert_eq!(r.held_state().0, 0);
    }

    #[test]
    fn held_flush_attributes_count_and_delay_per_peer() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 40;
        c.adaptive_jitter_min_delay_ms = 40;
        c.adaptive_jitter_max_delay_ms = 40;
        c.chunk_hold_budget_ms = 5;
        let r = Reorderer::new(c);
        // Two immediate peers feed the same stream (a route switch in flight).
        // The chunk is held past the skew deadline and flushes at
        // hold-exhaustion; the flush must be attributed to the peer that
        // actually carried the frames, together with the held delay.
        r.push(11, frame(0xABC, 1, 0, false));
        r.push(22, frame(0xABC, 1, 2, false));
        std::thread::sleep(Duration::from_millis(60));
        let report = r.drain_expired_report();
        let flushes = report.flushes_by_peer();
        assert_eq!(flushes.len(), 1, "only the buffering peer flushed");
        assert_eq!(flushes[0].from, 22);
        assert_eq!(flushes[0].count, 1);
        assert!(
            flushes[0].max_held_delay_us > 15_000,
            "held beyond the 40ms skew tolerance by ~20ms, got {}us",
            flushes[0].max_held_delay_us
        );
        let seqs: Vec<u64> = report
            .into_marked_emissions()
            .iter()
            .map(|e| e.frame().s2s_seq)
            .collect();
        assert_eq!(seqs, vec![2]);
        // The drain reset the hold state; the post-drain observation is 0.
        assert_eq!(r.held_state(), (0, 0));
    }

    #[test]
    fn chunk_hold_budget_zero_flushes_at_the_skew_deadline() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 5;
        c.adaptive_jitter_min_delay_ms = 5;
        c.adaptive_jitter_max_delay_ms = 5;
        c.chunk_hold_budget_ms = 0;
        let r = Reorderer::new(c);
        // Zero hold budget is the legacy policy: the chunk flushes at the
        // in-order skew deadline with no additional hold.
        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 2, false));
        std::thread::sleep(Duration::from_millis(10));
        let drained = r.drain_expired();
        let seqs: Vec<u64> = drained.iter().map(|(_, f)| f.s2s_seq).collect();
        assert_eq!(seqs, vec![2]);
        assert_eq!(r.held_state().0, 0);
    }

    #[test]
    fn expired_gap_rejects_reactive_repair_before_the_deadline_task_drains() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 5;
        c.adaptive_jitter_min_delay_ms = 5;
        c.adaptive_jitter_max_delay_ms = 5;
        // Tiny hold budget: the whole chunk-hold window exhausts while the
        // test sleeps, so the gap is permanently missed before the repair.
        c.chunk_hold_budget_ms = 2;
        let r = Reorderer::new(c);

        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 2, false));
        std::thread::sleep(Duration::from_millis(10));

        let repair = r
            .push_with_route_hint_report_with_copy_kind(
                11,
                frame(0xABC, 1, 1, false),
                None,
                VoiceCopyKind::ReactiveRepair,
            )
            .into_marked_emissions();
        assert!(repair.is_empty());
        assert_eq!(
            r.drain_expired()
                .iter()
                .map(|(_, frame)| frame.s2s_seq)
                .collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[test]
    fn newer_sender_epoch_resets_state() {
        let r = Reorderer::new(cfg());
        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 5, false));

        // A newer epoch starts a fresh sequence and discards stale buffered
        // audio from the previous stream.
        let emits = r.push(11, frame(0xABC, 2, 0, false));
        let seqs: Vec<u64> = emits.iter().map(|(_, f)| f.s2s_seq).collect();
        assert_eq!(seqs, vec![0]);
        assert_eq!(r.pending_total(), 0);
        assert_eq!(r.push(11, frame(0xABC, 2, 1, false)).len(), 1);
        assert!(r.push(11, frame(0xABC, 1, 6, false)).is_empty());
    }

    #[test]
    fn idle_prune_bootstraps_next_ordinary_but_not_repair() {
        let mut c = cfg();
        c.reorder_idle_reset_ms = 5;
        let r = Reorderer::new(c);
        assert_eq!(r.push(11, frame(0xABC, 1, 0, false)).len(), 1);
        std::thread::sleep(Duration::from_millis(10));
        r.drain_expired();

        let repair = r
            .push_with_route_hint_report_with_repair(11, frame(0xABC, 2, 99, false), None, true)
            .into_emissions();
        assert!(repair.is_empty());

        let ordinary = r.push(11, frame(0xABC, 2, 99, false));
        assert_eq!(
            ordinary.iter().map(|(_, f)| f.s2s_seq).collect::<Vec<_>>(),
            vec![99]
        );
    }

    #[tokio::test]
    async fn deadline_task_prunes_idle_stream_without_a_gap() {
        let mut c = cfg();
        c.reorder_idle_reset_ms = 10;
        let r = Reorderer::new(c);
        let shutdown = CancellationToken::new();
        let (nudge_tx, mut nudge_rx) = mpsc::channel(1);
        spawn_deadline_task(r.clone(), shutdown.clone(), move || {
            let _ = nudge_tx.try_send(());
        });

        assert_eq!(r.push(11, frame(0xABC, 1, 0, false)).len(), 1);
        tokio::time::timeout(Duration::from_millis(500), nudge_rx.recv())
            .await
            .expect("idle deadline should wake dispatch")
            .expect("deadline task should remain running");

        assert!(r.drain_expired_report().into_emissions().is_empty());
        assert_eq!(r.tracked_speaker_count(), 0);
        assert!(
            r.push_with_route_hint_report_with_repair(11, frame(0xABC, 2, 99, false), None, true)
                .into_emissions()
                .is_empty()
        );
        assert_eq!(r.push(11, frame(0xABC, 2, 99, false)).len(), 1);
        shutdown.cancel();
    }

    #[test]
    fn tracked_speaker_admission_follows_live_capacity_without_eviction() {
        let max_users = Arc::new(AtomicU64::new(100));
        let mut c = cfg();
        c.reorder_idle_reset_ms = 60_000;
        let r = Reorderer::new_with_capacity_source(c, max_users.clone());

        assert_eq!(r.tracked_speaker_capacity(), 1_024);
        for session in 0..1_024 {
            assert_eq!(r.push(11, frame(session, 1, 0, false)).len(), 1);
        }
        assert_eq!(r.tracked_speaker_count(), 1_024);

        let dropped_at_floor = r.push_with_route_hint_report(11, frame(1_024, 1, 0, false), None);
        assert_eq!(
            dropped_at_floor.result_counts(),
            &[ReorderResultCount::new(
                VoiceReceiveResult::SpeakerStateDrop,
                1
            )]
        );
        assert_eq!(dropped_at_floor.into_emissions().len(), 0);
        assert_eq!(r.tracked_speaker_count(), 1_024);

        max_users.store(5_000, Ordering::Relaxed);
        assert_eq!(r.tracked_speaker_capacity(), 10_000);
        for session in 1_024..10_000 {
            assert_eq!(r.push(11, frame(session, 1, 0, false)).len(), 1);
        }
        assert_eq!(r.tracked_speaker_count(), 10_000);

        max_users.store(100, Ordering::Relaxed);
        assert_eq!(r.tracked_speaker_capacity(), 1_024);
        assert_eq!(r.push(11, frame(0, 1, 1, false)).len(), 1);
        assert_eq!(r.tracked_speaker_count(), 10_000);

        let dropped_after_reduction =
            r.push_with_route_hint_report(11, frame(10_000, 1, 0, false), None);
        assert_eq!(
            dropped_after_reduction.result_counts(),
            &[ReorderResultCount::new(
                VoiceReceiveResult::SpeakerStateDrop,
                1
            )]
        );
        assert!(dropped_after_reduction.into_emissions().is_empty());
        assert_eq!(r.tracked_speaker_count(), 10_000);
    }

    #[tokio::test]
    async fn deadline_nudge_is_coalesced_until_dispatch_drains() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 5;
        c.adaptive_jitter_min_delay_ms = 5;
        c.adaptive_jitter_max_delay_ms = 5;
        // The first deadline (skew tolerance) still wakes dispatch; a tiny
        // hold budget means the drain that happens later actually flushes.
        c.chunk_hold_budget_ms = 5;
        let r = Reorderer::new(c);
        let shutdown = CancellationToken::new();
        let nudges = Arc::new(AtomicUsize::new(0));
        let (nudge_tx, mut nudge_rx) = mpsc::channel(1);
        let nudge_count = nudges.clone();
        spawn_deadline_task(r.clone(), shutdown.clone(), move || {
            nudge_count.fetch_add(1, Ordering::Relaxed);
            let _ = nudge_tx.try_send(());
        });

        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 2, false));
        tokio::time::timeout(Duration::from_millis(500), nudge_rx.recv())
            .await
            .expect("expired gap should wake dispatch")
            .expect("deadline task should remain running");

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(nudges.load(Ordering::Relaxed), 1);
        assert!(matches!(
            nudge_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        assert_eq!(
            r.drain_expired_report()
                .into_emissions()
                .iter()
                .map(|(_, frame)| frame.s2s_seq)
                .collect::<Vec<_>>(),
            vec![2]
        );
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert_eq!(nudges.load(Ordering::Relaxed), 1);
        shutdown.cancel();
    }

    #[test]
    fn late_same_epoch_original_does_not_rebase_or_double_emit() {
        let r = Reorderer::new(cfg());
        r.push(11, frame(0xABC, 1, 10, false));
        r.push(11, frame(0xABC, 1, 12, false));
        assert_eq!(r.pending_total(), 1);

        assert!(r.push(11, frame(0xABC, 1, 4, false)).is_empty());
        assert_eq!(r.pending_total(), 1);

        let emits = r.push(11, frame(0xABC, 1, 11, false));
        assert_eq!(
            emits.iter().map(|(_, f)| f.s2s_seq).collect::<Vec<_>>(),
            vec![11, 12]
        );
        assert_eq!(r.pending_total(), 0);
    }

    #[test]
    fn per_sender_buffer_cap_retains_nearest_sequences() {
        let mut c = cfg();
        c.reorder_max_buffered_frames = 2;
        let r = Reorderer::new(c);
        // Hold seq 0 in next_seq, then buffer 2 and 4. A later seq 6 is
        // farther from the gap and is discarded. Seq 3 replaces farthest 4.
        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 2, false));
        r.push(11, frame(0xABC, 1, 4, false));
        r.push(11, frame(0xABC, 1, 6, false));
        r.push(11, frame(0xABC, 1, 3, false));
        assert_eq!(r.pending_total(), 2);
        let emits = r.push(11, frame(0xABC, 1, 1, false));
        let seqs: Vec<u64> = emits.iter().map(|(_, f)| f.s2s_seq).collect();
        assert_eq!(seqs, vec![1, 2, 3]);
        assert_eq!(r.pending_total(), 0);
    }

    #[test]
    fn node_wide_cap_drops_tail() {
        let mut c = cfg();
        c.reorder_max_total_buffer = 1;
        // Per-sender cap larger than node-wide so we hit node-wide
        // first.
        c.reorder_max_buffered_frames = 16;
        let r = Reorderer::new(c);
        // Sender A: emit 0, buffer 2 → 1 entry pending (cap reached).
        r.push(11, frame(0xAAA, 1, 0, false));
        r.push(11, frame(0xAAA, 1, 2, false));
        assert_eq!(r.pending_total(), 1);
        // Sender B: emit 0, attempt to buffer 2 → node-wide cap full,
        // dropped.
        r.push(11, frame(0xBBB, 1, 0, false));
        r.push(11, frame(0xBBB, 1, 2, false));
        assert_eq!(r.pending_total(), 1);
    }

    #[test]
    fn terminator_does_not_flush_noncontiguous_suffix() {
        let r = Reorderer::new(cfg());
        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 2, false)); // gap
        r.push(11, frame(0xABC, 1, 4, false));
        // A terminator at seq 1 closes only the contiguous prefix.
        let emits = r.push(11, frame(0xABC, 1, 1, true));
        let seqs: Vec<u64> = emits.iter().map(|(_, f)| f.s2s_seq).collect();
        assert_eq!(seqs, vec![1, 2]);
        assert_eq!(r.pending_total(), 1);
    }

    #[test]
    fn adaptive_delay_grows_after_gap_and_deadline_flush() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 5;
        c.adaptive_jitter_min_delay_ms = 5;
        c.adaptive_jitter_max_delay_ms = 25;
        c.adaptive_jitter_growth_step_ms = 10;
        // The flush that triggers adaptive growth is the chunk-hold
        // exhaustion, so keep the hold window short.
        c.chunk_hold_budget_ms = 5;
        let r = Reorderer::new(c);

        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 2, false));
        assert_eq!(r.adaptive_delay_ms_for(0xABC), Some(5));

        std::thread::sleep(Duration::from_millis(20));
        let drained = r.drain_expired();
        let seqs: Vec<u64> = drained.iter().map(|(_, f)| f.s2s_seq).collect();
        assert_eq!(seqs, vec![2]);
        assert_eq!(r.adaptive_delay_ms_for(0xABC), Some(15));
    }

    #[test]
    fn adaptive_delay_decays_after_sustained_in_order_frames() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 25;
        c.adaptive_jitter_min_delay_ms = 5;
        c.adaptive_jitter_max_delay_ms = 25;
        c.adaptive_jitter_growth_step_ms = 10;
        c.adaptive_jitter_decay_step_ms = 5;
        let r = Reorderer::new(c);

        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 2, false));
        r.push(11, frame(0xABC, 1, 1, false));
        assert_eq!(r.adaptive_delay_ms_for(0xABC), Some(25));

        for seq in 3..19 {
            r.push(11, frame(0xABC, 1, seq, false));
        }
        assert_eq!(r.adaptive_delay_ms_for(0xABC), Some(20));
    }

    #[test]
    fn adaptive_delay_stays_within_bounds() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 10;
        c.adaptive_jitter_min_delay_ms = 10;
        c.adaptive_jitter_max_delay_ms = 20;
        c.adaptive_jitter_growth_step_ms = 50;
        c.adaptive_jitter_decay_step_ms = 50;
        let r = Reorderer::new(c);

        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 2, false));
        assert_eq!(r.adaptive_delay_ms_for(0xABC), Some(10));

        for seq in 1..19 {
            r.push(11, frame(0xABC, 1, seq, false));
        }
        assert_eq!(r.adaptive_delay_ms_for(0xABC), Some(10));
    }

    #[test]
    fn route_hint_extends_gap_deadline_and_chunk_is_held_for_repair() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 5;
        c.adaptive_jitter_enabled = false;
        c.adaptive_jitter_min_delay_ms = 40;
        c.adaptive_jitter_max_delay_ms = 120;
        let r = Reorderer::new(c);

        r.push(11, frame(0xABC, 1, 0, false));
        let hint = VoiceRouteHint::new(237_000, 0, 0);
        assert!(
            r.push_with_route_hint(11, frame(0xABC, 1, 2, false), Some(hint))
                .is_empty()
        );

        // Past the adaptive max (120ms) but before the route-extended skew
        // tolerance (≈257ms): nothing is drained yet.
        std::thread::sleep(Duration::from_millis(130));
        assert!(r.drain_expired().is_empty());
        // Past the skew tolerance: the chunk is HELD, not flushed around the
        // hole, so the gap stays actionable for a late repair.
        std::thread::sleep(Duration::from_millis(150));
        assert!(r.drain_expired().is_empty());
        assert_eq!(r.held_state().0, 1);
        let gap = r
            .gap_for_frame(11, &frame(0xABC, 1, 2, false))
            .expect("gap stays open during the hold");
        assert!(r.gap_still_missing(gap));
        // A late fill still emits the whole chunk contiguously (delayed).
        let emits = r.push(11, frame(0xABC, 1, 1, false));
        let seqs: Vec<u64> = emits.iter().map(|(_, f)| f.s2s_seq).collect();
        assert_eq!(seqs, vec![1, 2]);
    }

    #[test]
    fn route_delay_uses_quality_margin_and_cache_cap() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 40;
        c.adaptive_jitter_min_delay_ms = 40;
        c.adaptive_jitter_max_delay_ms = 120;
        c.repair_cache_ms = 300;

        assert_eq!(
            Reorderer::route_repair_delay_ms_for_config(
                &c,
                VoiceRouteHint::new(90_001, 10_001, 20_999),
            ),
            164
        );
        assert_eq!(
            Reorderer::route_repair_delay_ms_for_config(
                &c,
                VoiceRouteHint::new(1_000_000, 100_000, 1_000_000),
            ),
            300
        );
    }

    #[test]
    fn gap_preflight_identifies_only_originals_that_may_arm() {
        let r = Reorderer::new(cfg());
        let seq0 = frame(0xABC, 1, 0, false);
        assert!(!r.may_arm_gap(&seq0, VoiceCopyKind::Original));
        r.push(11, seq0);
        assert!(!r.may_arm_gap(&frame(0xABC, 1, 1, false), VoiceCopyKind::Original));

        let proactive = frame(0xABC, 1, 2, false);
        assert!(!r.may_arm_gap(&proactive, VoiceCopyKind::Proactive));
        r.push_with_route_hint_report_with_copy_kind(12, proactive, None, VoiceCopyKind::Proactive);
        assert!(r.may_arm_gap(&frame(0xABC, 1, 3, false), VoiceCopyKind::Original));
        assert!(r.may_arm_gap(&frame(0xABC, 1, 2, false), VoiceCopyKind::Original));
        assert!(!r.may_arm_gap(&frame(0xABC, 1, 3, false), VoiceCopyKind::ReactiveRepair));
    }

    #[test]
    fn adaptive_disabled_preserves_fixed_deadline_delay() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 5;
        c.adaptive_jitter_enabled = false;
        c.adaptive_jitter_min_delay_ms = 100;
        c.adaptive_jitter_max_delay_ms = 120;
        // The fixed skew deadline (100ms) gates when the hold starts; a tiny
        // hold budget makes the flush land right at the fixed deadline.
        c.chunk_hold_budget_ms = 5;
        let r = Reorderer::new(c);

        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 2, false));
        std::thread::sleep(Duration::from_millis(10));
        assert!(r.drain_expired().is_empty());
        std::thread::sleep(Duration::from_millis(110));
        let drained = r.drain_expired();
        let seqs: Vec<u64> = drained.iter().map(|(_, f)| f.s2s_seq).collect();
        assert_eq!(seqs, vec![2]);
    }

    #[test]
    fn reorder_disabled_passes_through() {
        let mut c = cfg();
        c.reorder_disabled = true;
        let r = Reorderer::new(c);
        // No buffering — out-of-order is forwarded as-is.
        let emits = r.push(11, frame(0xABC, 1, 5, false));
        assert_eq!(emits.len(), 1);
        assert_eq!(emits[0].1.s2s_seq, 5);
        assert_eq!(r.pending_total(), 0);
    }
}
