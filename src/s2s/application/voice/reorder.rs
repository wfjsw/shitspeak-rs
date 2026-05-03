//! Per-(sender, epoch) reorder buffer for inbound voice frames.
//!
//! Sits between the dispatch task (which decodes inbound `OverlayData`
//! frames) and the [`AudioSink`] (which runs local fan-out). Holds back
//! out-of-order frames for at most `reorder_max_delay_ms` to give a
//! late-arriving in-sequence frame time to land; on deadline, emits
//! pending in sequence order and skips past the gap.
//!
//! All emit decisions are made under a single `parking_lot::Mutex`;
//! the lock is never held across an `await`. The dispatch task and the
//! deadline task both feed into the same single mpsc so that
//! `AudioSink::deliver` calls remain serialized (per-sender ordering is
//! preserved).
//!
//! See the [`crate::s2s::application`] design notes for the rationale on
//! exposing the reorder window to operators rather than picking a
//! one-size-fits-all default.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::{mpsc, Notify};
use tokio_util::sync::CancellationToken;
use tracing::trace;

use crate::s2s::application::config::VoiceConfig;
use crate::s2s::application::proto::VoiceFrame;
use crate::types::NodeIdentifier;

/// One emit decision: forward the bundled `(from_immediate, frame)` to
/// the audio sink.
pub type Emission = (NodeIdentifier, VoiceFrame);

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

    /// Push an inbound delivery through the gate. Returns the sequence
    /// of frames the caller should hand to the audio sink, in the order
    /// they're returned. May be empty (frame is buffered) or contain
    /// multiple entries (the frame closed a gap and drained pending).
    pub fn push(&self, from: NodeIdentifier, frame: VoiceFrame) -> Vec<Emission> {
        if self.cfg.reorder_disabled {
            return vec![(from, frame)];
        }

        let mut emit: Vec<Emission> = Vec::new();
        let mut state = self.state.lock();
        let session = frame.sender_session;
        let arrived_epoch = frame.sender_epoch;

        // Make sure the per-sender entry exists.
        let entry = state
            .per_sender
            .entry(session)
            .or_insert_with(|| SenderState {
                epoch: arrived_epoch,
                next_seq: 0,
                pending: BTreeMap::new(),
                deadline: None,
            });

        // ── 1. Sender restart (strictly greater epoch) ────────────────
        if arrived_epoch > entry.epoch {
            // Flush pending under old epoch in seq order, then reset.
            let drained: Vec<(NodeIdentifier, VoiceFrame)> =
                std::mem::take(&mut entry.pending)
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
        } else if arrived_epoch < entry.epoch {
            // Old-epoch frame; drop silently.
            return emit;
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
            return emit;
        }
        // Strictly-less but within lag: still drop (duplicate or out-of-
        // order older). next_seq has already advanced; we can't unwind.
        if frame.s2s_seq < entry.next_seq {
            return emit;
        }

        // ── 3. In-order match: emit + drain contiguous suffix ─────────
        if frame.s2s_seq == entry.next_seq {
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
            state.total_pending = state.total_pending.saturating_sub(drained_count);
        } else {
            // ── 4. Gap: insert into pending. ───────────────────────────
            // Per-sender cap: drop oldest pending if over the cap.
            if entry.pending.len() >= self.cfg.reorder_max_buffered_frames {
                if let Some(&oldest_seq) = entry.pending.keys().next() {
                    entry.pending.remove(&oldest_seq);
                    state.total_pending = state.total_pending.saturating_sub(1);
                }
            }
            // Node-wide cap: drop-tail.
            if state.total_pending >= self.cfg.reorder_max_total_buffer {
                trace!(
                    session,
                    seq = frame.s2s_seq,
                    "voice reorder: node-wide buffer full; dropping"
                );
                return emit;
            }
            let entry = state.per_sender.get_mut(&session).unwrap();
            let was_empty_before_insert = entry.pending.is_empty();
            entry.pending.insert(frame.s2s_seq, (from, frame.clone()));
            state.total_pending = state.total_pending.saturating_add(1);
            if was_empty_before_insert {
                let deadline = Instant::now()
                    + Duration::from_millis(self.cfg.reorder_max_delay_ms);
                let entry = state.per_sender.get_mut(&session).unwrap();
                entry.deadline = Some(deadline);
                state.deadlines.push(Reverse((deadline, session)));
                self.deadline_notify.notify_one();
            }
        }

        // ── 7. Terminator: flush any pending for this sender now ──────
        if frame.is_terminator {
            let entry = state.per_sender.get_mut(&session).unwrap();
            let drained: Vec<(NodeIdentifier, VoiceFrame)> =
                std::mem::take(&mut entry.pending)
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
            for e in drained {
                emit.push(e);
            }
        }

        emit
    }

    /// Drain every deadline that has expired. Returns frames in
    /// per-sender seq order; cross-sender ordering is unspecified.
    pub fn drain_expired(&self) -> Vec<Emission> {
        let mut emit: Vec<Emission> = Vec::new();
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
                if let Some((max_seq, _, _)) = drained.last() {
                    entry.next_seq = max_seq.saturating_add(1);
                }
                drained
            };
            state.total_pending = state.total_pending.saturating_sub(drained.len());
            for (_, from, frame) in drained {
                emit.push((from, frame));
            }
        }
        emit
    }

    #[cfg(test)]
    pub fn pending_total(&self) -> usize {
        self.state.lock().total_pending
    }
}

/// Background task that watches the reorderer's deadline heap and
/// nudges the dispatch task to drain expired entries via
/// `dispatch_tx`. Owns the long-running `tokio::time::sleep_until`
/// future so the dispatch task itself stays purely event-driven.
pub fn spawn_deadline_task<F>(
    reorderer: Arc<Reorderer>,
    shutdown: CancellationToken,
    nudge: F,
) where
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

    use bytes::Bytes;

    fn cfg() -> VoiceConfig {
        VoiceConfig::default()
    }

    fn frame(session: u32, epoch: u64, seq: u64, terminator: bool) -> VoiceFrame {
        VoiceFrame {
            sender_session: session,
            sender_epoch: epoch,
            s2s_seq: seq,
            target_kind: 0,
            is_terminator: terminator,
            payload: Bytes::from(format!("p-{seq}").into_bytes()).to_vec(),
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
    fn deadline_fire_skips_gap() {
        let mut c = cfg();
        c.reorder_max_delay_ms = 5;
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
