//! Per-(sender, epoch) reorder buffer for inbound voice frames.
//!
//! Sits between the dispatch task (which decodes inbound `OverlayData`
//! frames) and the [`AudioSink`] (which runs local fan-out). Holds back
//! out-of-order frames for a fixed or adaptive per-sender jitter delay
//! to give a late-arriving in-sequence frame time to land; on deadline, emits
//! pending in sequence order and skips past the gap.
//!
//! All emit decisions are made under a single `parking_lot::Mutex`;
//! the lock is never held across an `await`. The dispatch task and the
//! deadline task both feed into the same single mpsc so that
//! `AudioSink::deliver` calls remain serialized (per-sender ordering is
//! preserved).
//!
//! See the [`crate::application`] design notes for the rationale on
//! exposing the reorder window to operators rather than picking a
//! one-size-fits-all default.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::trace;

use crate::application::config::VoiceConfig;
use crate::application::proto::VoiceFrame;
use crate::application::voice::metrics::VoiceReceiveResult;
use shitspeak_core::NodeIdentifier;

const ADAPTIVE_JITTER_IN_ORDER_DECAY_RUN: u32 = 16;
const ADAPTIVE_REPAIR_DELAY_MARGIN_MS: u64 = 20;
const ADAPTIVE_REPAIR_LOSS_BONUS_MAX_MS: u64 = 200;

/// One emit decision: forward the bundled `(from_immediate, frame)` to
/// the audio sink.
pub type Emission = (NodeIdentifier, VoiceFrame);

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

#[derive(Debug, Default)]
pub(crate) struct ReorderReport {
    emissions: Vec<Emission>,
    results: Vec<ReorderResultCount>,
    pending_total: usize,
}

impl ReorderReport {
    fn new(
        emissions: Vec<Emission>,
        results: Vec<ReorderResultCount>,
        pending_total: usize,
    ) -> Self {
        Self {
            emissions,
            results,
            pending_total,
        }
    }

    pub(crate) fn result_counts(&self) -> &[ReorderResultCount] {
        &self.results
    }

    pub(crate) fn pending_total(&self) -> usize {
        self.pending_total
    }

    pub(crate) fn into_emissions(self) -> Vec<Emission> {
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
    state: Mutex<ReorderInner>,
    deadline_notify: Arc<Notify>,
}

struct ReorderInner {
    per_sender: HashMap<u32, SenderState>,
    deadlines: BinaryHeap<Reverse<(Instant, u32)>>,
    total_pending: usize,
}

struct SenderState {
    epoch: u64,
    next_seq: u64,
    pending: BTreeMap<u64, (NodeIdentifier, VoiceFrame)>,
    deadline: Option<Instant>,
    adaptive_delay_ms: u64,
    route_repair_delay_ms: u64,
    in_order_run: u32,
}

impl Reorderer {
    pub fn new(cfg: VoiceConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            state: Mutex::new(ReorderInner {
                per_sender: HashMap::new(),
                deadlines: BinaryHeap::new(),
                total_pending: 0,
            }),
            deadline_notify: Arc::new(Notify::new()),
        })
    }

    pub fn deadline_notify(&self) -> Arc<Notify> {
        self.deadline_notify.clone()
    }

    pub fn config(&self) -> &VoiceConfig {
        &self.cfg
    }

    /// Earliest pending deadline across all senders, or `None` if no
    /// senders currently have pending. Used by the deadline task to
    /// decide how long to sleep.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.state.lock().deadlines.peek().map(|Reverse((d, _))| *d)
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
        let path_ms = hint.path_latency_us.saturating_add(999) / 1_000;
        let jitter_ms = hint.jitter_us.saturating_add(999) / 1_000;
        let loss_bonus_ms =
            (u64::from(hint.loss_ppm).saturating_div(1_000)).min(ADAPTIVE_REPAIR_LOSS_BONUS_MAX_MS);
        let computed = cfg
            .repair_nack_delay_ms
            .saturating_add(path_ms.saturating_mul(2))
            .saturating_add(jitter_ms.saturating_mul(3))
            .saturating_add(loss_bonus_ms)
            .saturating_add(ADAPTIVE_REPAIR_DELAY_MARGIN_MS);
        let min = cfg.adaptive_jitter_min_delay_ms;
        let max = cfg.adaptive_jitter_max_delay_ms.max(min);
        computed.clamp(min, max)
    }

    pub fn route_repair_delay_ms(&self, hint: VoiceRouteHint) -> u64 {
        Self::route_repair_delay_ms_for_config(&self.cfg, hint)
    }

    fn effective_delay_ms(&self, entry: &SenderState) -> u64 {
        let base = if self.cfg.adaptive_jitter_enabled {
            entry.adaptive_delay_ms
        } else {
            self.cfg.reorder_max_delay_ms
        };
        base.max(entry.route_repair_delay_ms)
    }

    fn reset_adaptive_delay(&self, entry: &mut SenderState) {
        entry.adaptive_delay_ms = self.initial_adaptive_delay_ms();
        entry.in_order_run = 0;
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
        if self.cfg.reorder_disabled {
            return ReorderReport::new(
                vec![(from, frame)],
                vec![ReorderResultCount::new(VoiceReceiveResult::InOrder, 1)],
                0,
            );
        }

        let mut emit: Vec<Emission> = Vec::new();
        let mut results: Vec<ReorderResultCount> = Vec::new();
        let mut state = self.state.lock();
        let session = frame.sender_session;
        let arrived_epoch = frame.sender_epoch;

        // Make sure the per-sender entry exists.
        let initial_adaptive_delay_ms = self.initial_adaptive_delay_ms();
        let entry = state
            .per_sender
            .entry(session)
            .or_insert_with(|| SenderState {
                epoch: arrived_epoch,
                next_seq: 0,
                pending: BTreeMap::new(),
                deadline: None,
                adaptive_delay_ms: initial_adaptive_delay_ms,
                route_repair_delay_ms: route_hint
                    .map(|hint| self.route_repair_delay_ms(hint))
                    .unwrap_or(0),
                in_order_run: 0,
            });
        if let Some(hint) = route_hint {
            entry.route_repair_delay_ms = self.route_repair_delay_ms(hint);
        }

        // ── 1. Sender restart (strictly greater epoch) ────────────────
        if arrived_epoch > entry.epoch {
            results.push(ReorderResultCount::new(VoiceReceiveResult::EpochReset, 1));
            // Flush pending under old epoch in seq order, then reset.
            let drained: Vec<(NodeIdentifier, VoiceFrame)> = std::mem::take(&mut entry.pending)
                .into_iter()
                .map(|(_, e)| e)
                .collect();
            state.total_pending = state.total_pending.saturating_sub(drained.len());
            for e in drained {
                emit.push(e);
            }
            let entry = state.per_sender.get_mut(&session).unwrap();
            entry.epoch = arrived_epoch;
            entry.next_seq = 0;
            entry.deadline = None;
            self.reset_adaptive_delay(entry);
            if let Some(hint) = route_hint {
                entry.route_repair_delay_ms = self.route_repair_delay_ms(hint);
            }
        } else if arrived_epoch < entry.epoch {
            // Old-epoch frame; drop silently.
            results.push(ReorderResultCount::new(
                VoiceReceiveResult::DuplicateOrLate,
                1,
            ));
            return ReorderReport::new(emit, results, state.total_pending);
        }

        // Re-borrow after the mutation above (needed if we hit the
        // restart branch).
        let entry = state.per_sender.get_mut(&session).unwrap();

        // ── 2. Drop too-late frames ───────────────────────────────────
        let max_lag = self.cfg.reorder_max_drop_lag_frames;
        let too_late = entry
            .next_seq
            .saturating_sub(frame.s2s_seq.saturating_add(1))
            >= max_lag;
        if frame.s2s_seq < entry.next_seq && too_late {
            trace!(
                session,
                seq = frame.s2s_seq,
                next = entry.next_seq,
                "voice reorder: dropping too-late frame"
            );
            self.grow_adaptive_delay(entry);
            results.push(ReorderResultCount::new(
                VoiceReceiveResult::DuplicateOrLate,
                1,
            ));
            return ReorderReport::new(emit, results, state.total_pending);
        }
        // Strictly-less but within lag: still drop (duplicate or out-of-
        // order older). next_seq has already advanced; we can't unwind.
        if frame.s2s_seq < entry.next_seq {
            self.grow_adaptive_delay(entry);
            results.push(ReorderResultCount::new(
                VoiceReceiveResult::DuplicateOrLate,
                1,
            ));
            return ReorderReport::new(emit, results, state.total_pending);
        }

        // ── 3. In-order match: emit + drain contiguous suffix ─────────
        if frame.s2s_seq == entry.next_seq {
            results.push(ReorderResultCount::new(VoiceReceiveResult::InOrder, 1));
            emit.push((from, frame.clone()));
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
            }
            if drained_count > 0 {
                results.push(ReorderResultCount::new(
                    VoiceReceiveResult::GapFilled,
                    drained_count,
                ));
                self.grow_adaptive_delay(entry);
            } else if entry.pending.is_empty() {
                self.record_clean_in_order(entry);
            }
            state.total_pending = state.total_pending.saturating_sub(drained_count);
        } else {
            // ── 4. Gap: insert into pending. ───────────────────────────
            // Per-sender cap: drop oldest pending if over the cap.
            if entry.pending.len() >= self.cfg.reorder_max_buffered_frames {
                if let Some(&oldest_seq) = entry.pending.keys().next() {
                    entry.pending.remove(&oldest_seq);
                    state.total_pending = state.total_pending.saturating_sub(1);
                    results.push(ReorderResultCount::new(VoiceReceiveResult::BufferDrop, 1));
                }
            }
            // Node-wide cap: drop-tail.
            if state.total_pending >= self.cfg.reorder_max_total_buffer {
                trace!(
                    session,
                    seq = frame.s2s_seq,
                    "voice reorder: node-wide buffer full; dropping"
                );
                results.push(ReorderResultCount::new(VoiceReceiveResult::BufferDrop, 1));
                return ReorderReport::new(emit, results, state.total_pending);
            }
            let (inserted_new, deadline_delay_ms) = {
                let entry = state.per_sender.get_mut(&session).unwrap();
                let was_empty_before_insert = entry.pending.is_empty();
                let inserted_new = entry
                    .pending
                    .insert(frame.s2s_seq, (from, frame.clone()))
                    .is_none();
                if inserted_new {
                    self.grow_adaptive_delay(entry);
                }
                (
                    inserted_new,
                    was_empty_before_insert.then(|| self.effective_delay_ms(entry)),
                )
            };
            if inserted_new {
                results.push(ReorderResultCount::new(VoiceReceiveResult::GapBuffered, 1));
                state.total_pending = state.total_pending.saturating_add(1);
            } else {
                results.push(ReorderResultCount::new(
                    VoiceReceiveResult::DuplicateOrLate,
                    1,
                ));
            }
            if let Some(delay_ms) = deadline_delay_ms {
                let deadline = Instant::now() + Duration::from_millis(delay_ms);
                let entry = state.per_sender.get_mut(&session).unwrap();
                entry.deadline = Some(deadline);
                state.deadlines.push(Reverse((deadline, session)));
                self.deadline_notify.notify_one();
            }
        }

        // ── 7. Terminator: flush any pending for this sender now ──────
        if frame.is_terminator {
            let entry = state.per_sender.get_mut(&session).unwrap();
            let drained: Vec<(NodeIdentifier, VoiceFrame)> = std::mem::take(&mut entry.pending)
                .into_iter()
                .map(|(_, e)| e)
                .collect();
            state.total_pending = state.total_pending.saturating_sub(drained.len());
            let entry = state.per_sender.get_mut(&session).unwrap();
            // Advance next_seq past the drained range so subsequent
            // late frames are dropped via the lag check.
            if let Some((_, last_frame)) = drained.last() {
                entry.next_seq = last_frame.s2s_seq.saturating_add(1);
            }
            entry.deadline = None;
            if !drained.is_empty() {
                results.push(ReorderResultCount::new(
                    VoiceReceiveResult::GapFilled,
                    drained.len(),
                ));
            }
            for e in drained {
                emit.push(e);
            }
        }

        ReorderReport::new(emit, results, state.total_pending)
    }

    /// Drain every deadline that has expired. Returns frames in
    /// per-sender seq order; cross-sender ordering is unspecified.
    pub fn drain_expired(&self) -> Vec<Emission> {
        self.drain_expired_report().into_emissions()
    }

    pub(crate) fn drain_expired_report(&self) -> ReorderReport {
        let mut emit: Vec<Emission> = Vec::new();
        let mut results: Vec<ReorderResultCount> = Vec::new();
        let mut state = self.state.lock();
        let now = Instant::now();
        loop {
            let next = state.deadlines.peek().copied();
            let Some(Reverse((deadline, session))) = next else {
                break;
            };
            if deadline > now {
                break;
            }
            state.deadlines.pop();
            // Stale heap entry? (Sender's current deadline differs or
            // sender was reset.)
            let Some(entry) = state.per_sender.get(&session) else {
                continue;
            };
            if entry.deadline != Some(deadline) {
                continue;
            }

            // Drain in seq order, jump next_seq past the highest seq
            // we drained.
            let drained: Vec<(u64, NodeIdentifier, VoiceFrame)> = {
                let entry = state.per_sender.get_mut(&session).unwrap();
                let drained: Vec<(u64, NodeIdentifier, VoiceFrame)> =
                    std::mem::take(&mut entry.pending)
                        .into_iter()
                        .map(|(s, (f, fr))| (s, f, fr))
                        .collect();
                entry.deadline = None;
                if !drained.is_empty() {
                    self.grow_adaptive_delay(entry);
                }
                if let Some((max_seq, _, _)) = drained.last() {
                    entry.next_seq = max_seq.saturating_add(1);
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
            for (_, from, frame) in drained {
                emit.push((from, frame));
            }
        }
        ReorderReport::new(emit, results, state.total_pending)
    }

    pub fn gap_for_frame(&self, from: NodeIdentifier, frame: &VoiceFrame) -> Option<GapReport> {
        if self.cfg.reorder_disabled || frame.s2s_seq == 0 {
            return None;
        }
        let state = self.state.lock();
        let entry = state.per_sender.get(&frame.sender_session)?;
        if entry.epoch != frame.sender_epoch
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
        entry.epoch == gap.sender_epoch
            && entry.next_seq <= gap.last_seq
            && !entry.pending.is_empty()
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

    #[cfg(test)]
    pub fn route_repair_delay_ms_for(&self, session: u32) -> Option<u64> {
        self.state
            .lock()
            .per_sender
            .get(&session)
            .map(|entry| entry.route_repair_delay_ms)
    }
}

/// Background task that watches the reorderer's deadline heap and
/// nudges the dispatch task to drain expired entries via
/// `dispatch_tx`. Owns the long-running `tokio::time::sleep_until`
/// future so the dispatch task itself stays purely event-driven.
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
                            nudge();
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
    fn duplicate_repair_frame_does_not_double_emit() {
        let r = Reorderer::new(cfg());
        assert_eq!(r.push(11, frame(0xABC, 1, 0, false)).len(), 1);
        assert!(r.push(11, frame(0xABC, 1, 0, false)).is_empty());
        assert_eq!(r.push(11, frame(0xABC, 1, 1, false)).len(), 1);
        assert!(r.push(11, frame(0xABC, 1, 1, false)).is_empty());
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
    fn deadline_fire_skips_gap() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 5;
        c.adaptive_jitter_enabled = false;
        let r = Reorderer::new(c);
        // 0 emits, 2 buffers (gap at 1), wait, deadline drains 2 and
        // jumps next_seq to 3.
        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 2, false));
        std::thread::sleep(Duration::from_millis(10));
        let drained = r.drain_expired();
        let seqs: Vec<u64> = drained.iter().map(|(_, f)| f.s2s_seq).collect();
        assert_eq!(seqs, vec![2]);
        // After the skip, pushing 1 (now too-late by 1) is dropped.
        let late = r.push(11, frame(0xABC, 1, 1, false));
        assert!(late.is_empty());
        // Pushing 3 in order works.
        let on = r.push(11, frame(0xABC, 1, 3, false));
        let seqs: Vec<u64> = on.iter().map(|(_, f)| f.s2s_seq).collect();
        assert_eq!(seqs, vec![3]);
    }

    #[test]
    fn sender_restart_resets_state() {
        let r = Reorderer::new(cfg());
        // Build up some pending under epoch 1.
        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 5, false)); // gap → buffered
        assert_eq!(r.pending_total(), 1);
        // Same sender, higher epoch — the new frame's seq=0 starts the
        // new epoch's sequence; the old pending is flushed.
        let emits = r.push(11, frame(0xABC, 2, 0, false));
        // Old-epoch pending (seq 5) is flushed first, then new-epoch
        // seq 0 is emitted.
        let seqs: Vec<u64> = emits.iter().map(|(_, f)| f.s2s_seq).collect();
        assert_eq!(seqs, vec![5, 0]);
        assert_eq!(r.pending_total(), 0);
    }

    #[test]
    fn drop_lag_clamp() {
        let mut c = cfg();
        c.reorder_max_drop_lag_frames = 3;
        let r = Reorderer::new(c);
        // Advance next_seq to 10.
        for s in 0..10 {
            r.push(11, frame(0xABC, 1, s, false));
        }
        // Frames within lag (next-3 .. next-1) → drop silently.
        assert!(r.push(11, frame(0xABC, 1, 7, false)).is_empty());
        // Frame outside lag → also dropped (the `too_late` branch).
        assert!(r.push(11, frame(0xABC, 1, 5, false)).is_empty());
    }

    #[test]
    fn per_sender_buffer_cap_drops_oldest() {
        let mut c = cfg();
        c.reorder_max_buffered_frames = 2;
        let r = Reorderer::new(c);
        // Hold seq 0 in next_seq, then buffer 2, 3, 4 (cap 2 → seq 2 is
        // dropped when 4 arrives).
        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 2, false));
        r.push(11, frame(0xABC, 1, 3, false));
        r.push(11, frame(0xABC, 1, 4, false));
        // Pending should hold seq 3 and 4 only.
        assert_eq!(r.pending_total(), 2);
        let emits = r.push(11, frame(0xABC, 1, 1, false));
        let seqs: Vec<u64> = emits.iter().map(|(_, f)| f.s2s_seq).collect();
        // Emits [1] (gap closed), but seq 3 is not contiguous (2 was
        // dropped), so we don't drain past 1. Pending still holds 3, 4.
        assert_eq!(seqs, vec![1]);
        assert_eq!(r.pending_total(), 2);
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
    fn terminator_flushes_immediately() {
        let r = Reorderer::new(cfg());
        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 2, false)); // gap
        r.push(11, frame(0xABC, 1, 4, false));
        // Now a terminator at seq 1 — closes the gap (seq 1) and
        // flushes 2, 4 immediately, even with a hole at 3.
        let emits = r.push(11, frame(0xABC, 1, 1, true));
        let seqs: Vec<u64> = emits.iter().map(|(_, f)| f.s2s_seq).collect();
        // Order: 1 (in-sequence), 2 (drained as contiguous), 4 (the
        // terminator-flush path).
        assert_eq!(seqs, vec![1, 2, 4]);
        assert_eq!(r.pending_total(), 0);
    }

    #[test]
    fn adaptive_delay_grows_after_gap_and_deadline_flush() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 5;
        c.adaptive_jitter_min_delay_ms = 5;
        c.adaptive_jitter_max_delay_ms = 25;
        c.adaptive_jitter_growth_step_ms = 10;
        let r = Reorderer::new(c);

        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 2, false));
        assert_eq!(r.adaptive_delay_ms_for(0xABC), Some(15));

        std::thread::sleep(Duration::from_millis(20));
        let drained = r.drain_expired();
        let seqs: Vec<u64> = drained.iter().map(|(_, f)| f.s2s_seq).collect();
        assert_eq!(seqs, vec![2]);
        assert_eq!(r.adaptive_delay_ms_for(0xABC), Some(25));
    }

    #[test]
    fn adaptive_delay_decays_after_sustained_in_order_frames() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 5;
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
        assert_eq!(r.adaptive_delay_ms_for(0xABC), Some(20));

        for seq in 1..19 {
            r.push(11, frame(0xABC, 1, seq, false));
        }
        assert_eq!(r.adaptive_delay_ms_for(0xABC), Some(10));
    }

    #[test]
    fn route_hint_holds_gap_for_far_lossy_repair() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 5;
        c.adaptive_jitter_enabled = false;
        c.adaptive_jitter_min_delay_ms = 40;
        c.adaptive_jitter_max_delay_ms = 600;
        c.repair_nack_delay_ms = 8;
        let r = Reorderer::new(c);

        r.push(11, frame(0xABC, 1, 0, false));
        let hint = VoiceRouteHint::new(90_000, 30_000, 20_000);
        assert!(
            r.push_with_route_hint(11, frame(0xABC, 1, 2, false), Some(hint))
                .is_empty()
        );

        let route_delay = r.route_repair_delay_ms_for(0xABC).unwrap();
        assert!(route_delay >= 300, "route delay was {route_delay}ms");
        std::thread::sleep(Duration::from_millis(20));
        assert!(r.drain_expired().is_empty());
    }

    #[test]
    fn adaptive_disabled_preserves_fixed_deadline_delay() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 5;
        c.adaptive_jitter_enabled = false;
        c.adaptive_jitter_min_delay_ms = 100;
        c.adaptive_jitter_max_delay_ms = 120;
        let r = Reorderer::new(c);

        r.push(11, frame(0xABC, 1, 0, false));
        r.push(11, frame(0xABC, 1, 2, false));
        std::thread::sleep(Duration::from_millis(10));

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
