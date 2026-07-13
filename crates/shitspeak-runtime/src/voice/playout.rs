//! Remote S2S voice playout scheduling.
//!
//! S2S ordering makes overlay sequence delivery deterministic, but it does
//! not prevent an entire talkspurt from arriving in a burst after a long-haul
//! delay. This stage is deliberately after S2S reorder and before local
//! recipient fan-out. It uses the native Mumble `frame_number` timeline, not
//! S2S packet sequence, so repair and normal copies share one media clock.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use shitspeak_s2s::application::proto::VoiceFrame;
use shitspeak_s2s::application::voice::RemoteVoicePlayoutPolicy;

use super::codec::Audio;
use super::metrics;
use crate::client::client_session_identifier::ClientSessionIdentifier;
use crate::types::NodeIdentifier;

/// Mumble's current native voice framing convention is one frame number per
/// 20 ms audio packet. The scheduler intentionally uses this media timeline
/// rather than arrival or S2S sequence timing.
const NATIVE_VOICE_FRAME_INTERVAL: Duration = Duration::from_millis(20);
const ARRIVAL_HISTORY_CAPACITY: usize = 128;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct RemoteVoiceStreamKey {
    origin_node: NodeIdentifier,
    sender_session: u32,
    sender_epoch: u64,
}

struct RemoteVoiceStreamState {
    arrival_anchor: Option<(u64, Instant)>,
    arrival_delays_ms: VecDeque<u64>,
    last_arrival: Instant,
    idle_reset: Duration,
    generation: u64,
    talkspurt_first_frame: u64,
    talkspurt_release_at: Instant,
    latched_delay_ms: u64,
    terminator_arrived: bool,
    terminator_frame: Option<u64>,
    queued_frames: HashMap<u64, Instant>,
    last_scheduled_frame: Option<u64>,
    last_released_frame: Option<u64>,
}

struct ScheduledRemoteVoiceFrame {
    due: Instant,
    order: u64,
    key: RemoteVoiceStreamKey,
    generation: u64,
    from_immediate: NodeIdentifier,
    frame: VoiceFrame,
    decoded: Audio,
}

impl PartialEq for ScheduledRemoteVoiceFrame {
    fn eq(&self, other: &Self) -> bool {
        self.due == other.due && self.order == other.order
    }
}

impl Eq for ScheduledRemoteVoiceFrame {}

impl PartialOrd for ScheduledRemoteVoiceFrame {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledRemoteVoiceFrame {
    fn cmp(&self, other: &Self) -> Ordering {
        // `BinaryHeap` is a max-heap; reverse deadline order for the earliest
        // release first, retaining insertion order for equal deadlines.
        other
            .due
            .cmp(&self.due)
            .then_with(|| other.order.cmp(&self.order))
    }
}

pub(crate) struct ReleasedRemoteVoiceFrame {
    pub(crate) from_immediate: NodeIdentifier,
    pub(crate) frame: VoiceFrame,
    pub(crate) decoded: Audio,
}

/// One owner lives on the native S2S voice gateway task, so it needs no
/// locking and can order releases across talkspurts without blocking inbound
/// gateway reads.
#[derive(Default)]
pub(crate) struct RemoteVoicePlayout {
    streams: HashMap<RemoteVoiceStreamKey, RemoteVoiceStreamState>,
    pending: BinaryHeap<ScheduledRemoteVoiceFrame>,
    next_order: u64,
}

impl RemoteVoicePlayout {
    /// Decode and schedule a remote S2S voice frame. Decode failures are kept
    /// out of local fan-out just as they were before the playout stage.
    pub(crate) fn schedule(
        &mut self,
        from_immediate: NodeIdentifier,
        frame: VoiceFrame,
        policy: RemoteVoicePlayoutPolicy,
        is_repair: bool,
    ) {
        self.schedule_at(from_immediate, frame, policy, is_repair, Instant::now());
    }

    fn schedule_at(
        &mut self,
        from_immediate: NodeIdentifier,
        frame: VoiceFrame,
        policy: RemoteVoicePlayoutPolicy,
        is_repair: bool,
        now: Instant,
    ) {
        let sender = ClientSessionIdentifier::from(frame.sender_session);
        let origin_node = sender.get_node_id();
        let decoded = match Audio::decode(&frame.payload, Some(sender)) {
            Ok(decoded) => decoded,
            Err(error) => {
                metrics::record_remote_playout_event(
                    origin_node,
                    metrics::RemotePlayoutResult::DecodeFailed,
                );
                tracing::trace!(
                    from = from_immediate,
                    sender = frame.sender_session,
                    error = %error,
                    "s2s remote voice playout decode failed"
                );
                return;
            }
        };
        let key = RemoteVoiceStreamKey {
            origin_node,
            sender_session: frame.sender_session,
            sender_epoch: frame.sender_epoch,
        };

        let talkspurt_is_inactive = self.streams.get(&key).is_none_or(|state| {
            now.saturating_duration_since(state.last_arrival) >= state.idle_reset
        });
        if is_repair && talkspurt_is_inactive {
            // A repair can only fill media that still belongs to a live
            // talkspurt. Do not let an orphaned repair establish a new media
            // clock or extend a completed stream.
            metrics::record_remote_playout_event(
                origin_node,
                metrics::RemotePlayoutResult::RepairAfterPlayout,
            );
            return;
        }
        let new_talkspurt = !is_repair
            && self.streams.get(&key).is_none_or(|state| {
                state.terminator_arrived
                    || now.saturating_duration_since(state.last_arrival) >= state.idle_reset
            });
        let state = self
            .streams
            .entry(key)
            .or_insert_with(|| RemoteVoiceStreamState {
                arrival_anchor: None,
                arrival_delays_ms: VecDeque::with_capacity(ARRIVAL_HISTORY_CAPACITY),
                last_arrival: now,
                idle_reset: Duration::from_millis(policy.idle_reset_ms()),
                generation: 0,
                talkspurt_first_frame: decoded.frame_number,
                talkspurt_release_at: now,
                latched_delay_ms: policy.min_delay_ms(),
                terminator_arrived: false,
                terminator_frame: None,
                queued_frames: HashMap::new(),
                last_scheduled_frame: None,
                last_released_frame: None,
            });

        if new_talkspurt {
            state.arrival_anchor = None;
        }
        record_arrival_delay(state, decoded.frame_number, now);
        state.last_arrival = now;
        state.idle_reset = Duration::from_millis(policy.idle_reset_ms());

        if new_talkspurt {
            state.generation = state.generation.wrapping_add(1);
            state.talkspurt_first_frame = decoded.frame_number;
            state.latched_delay_ms = resolve_delay_ms(state, policy);
            state.talkspurt_release_at = now + Duration::from_millis(state.latched_delay_ms);
            state.terminator_arrived = false;
            state.terminator_frame = None;
            state.queued_frames.clear();
            state.last_scheduled_frame = None;
            state.last_released_frame = None;
            state.arrival_anchor = Some((decoded.frame_number, now));
            metrics::record_remote_playout_delay(origin_node, state.latched_delay_ms);
            metrics::record_remote_playout_event(
                origin_node,
                metrics::RemotePlayoutResult::TalkspurtStarted,
            );
        }

        if decoded.frame_number < state.talkspurt_first_frame {
            metrics::record_remote_playout_event(
                origin_node,
                if is_repair {
                    metrics::RemotePlayoutResult::RepairAfterPlayout
                } else {
                    metrics::RemotePlayoutResult::LateRepairDropped
                },
            );
            return;
        }
        if let Some(scheduled_due) = state.queued_frames.get(&decoded.frame_number).copied() {
            metrics::record_remote_playout_event(
                origin_node,
                if is_repair {
                    if now < scheduled_due {
                        metrics::RemotePlayoutResult::RepairBeforePlayout
                    } else {
                        metrics::RemotePlayoutResult::RepairAfterPlayout
                    }
                } else {
                    metrics::RemotePlayoutResult::LateRepairDropped
                },
            );
            return;
        }
        if is_repair
            && state
                .terminator_frame
                .is_some_and(|terminator| decoded.frame_number > terminator)
        {
            metrics::record_remote_playout_event(
                origin_node,
                metrics::RemotePlayoutResult::RepairAfterPlayout,
            );
            return;
        }
        if state
            .last_released_frame
            .is_some_and(|released| decoded.frame_number <= released)
        {
            metrics::record_remote_playout_event(
                origin_node,
                if is_repair {
                    metrics::RemotePlayoutResult::RepairAfterPlayout
                } else {
                    metrics::RemotePlayoutResult::LateRepairDropped
                },
            );
            return;
        }

        let frame_offset = decoded
            .frame_number
            .saturating_sub(state.talkspurt_first_frame);
        let nominal_due = add_frame_offset(state.talkspurt_release_at, frame_offset);
        let mut due = nominal_due;
        if due <= now {
            if is_repair {
                metrics::record_remote_playout_event(
                    origin_node,
                    metrics::RemotePlayoutResult::RepairAfterPlayout,
                );
                return;
            }
            let contiguous_original = state
                .last_scheduled_frame
                .is_some_and(|previous| decoded.frame_number == previous.saturating_add(1));
            if contiguous_original {
                // Preserve a complete, paced talkspurt when ordinary sender
                // timer/runtime drift exhausts the initial buffer. Rebase the
                // remaining media timeline rather than releasing all overdue
                // frames together. Older or duplicate media frames remain
                // rejected above, so a repair cannot revive played audio.
                due = now + NATIVE_VOICE_FRAME_INTERVAL;
                let shift = due.saturating_duration_since(nominal_due);
                state.talkspurt_release_at += shift;
                metrics::record_remote_playout_event(
                    origin_node,
                    metrics::RemotePlayoutResult::OriginalTimelineRebased,
                );
            } else {
                // A repair cannot change already-played audio. Treat any frame
                // that missed its media deadline as stale rather than
                // releasing a late packet that would chop the talkspurt.
                metrics::record_remote_playout_event(
                    origin_node,
                    metrics::RemotePlayoutResult::LateRepairDropped,
                );
                return;
            }
        }

        state.queued_frames.insert(decoded.frame_number, due);
        state.last_scheduled_frame = Some(
            state
                .last_scheduled_frame
                .unwrap_or(decoded.frame_number)
                .max(decoded.frame_number),
        );
        if frame.is_terminator {
            // The terminator remains a scheduled media frame. It deliberately
            // does not release buffered speech early.
            state.terminator_arrived = true;
            state.terminator_frame = Some(decoded.frame_number);
        }
        let generation = state.generation;
        self.next_order = self.next_order.wrapping_add(1);
        self.pending.push(ScheduledRemoteVoiceFrame {
            due,
            order: self.next_order,
            key,
            generation,
            from_immediate,
            frame,
            decoded,
        });
        if is_repair {
            metrics::record_remote_playout_event(
                origin_node,
                metrics::RemotePlayoutResult::RepairBeforePlayout,
            );
        }
        metrics::record_remote_playout_event(origin_node, metrics::RemotePlayoutResult::Scheduled);
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.pending.peek().map(|entry| entry.due)
    }

    pub(crate) fn release_due(&mut self) -> Vec<ReleasedRemoteVoiceFrame> {
        self.release_due_at(Instant::now())
    }

    fn release_due_at(&mut self, now: Instant) -> Vec<ReleasedRemoteVoiceFrame> {
        let mut released = Vec::new();
        while self.pending.peek().is_some_and(|entry| entry.due <= now) {
            let entry = self.pending.pop().expect("heap peeked");
            let Some(state) = self.streams.get_mut(&entry.key) else {
                continue;
            };
            if state.generation == entry.generation {
                state.queued_frames.remove(&entry.decoded.frame_number);
                state.last_released_frame = Some(
                    state
                        .last_released_frame
                        .unwrap_or(entry.decoded.frame_number)
                        .max(entry.decoded.frame_number),
                );
            }
            let lateness_ms = now
                .saturating_duration_since(entry.due)
                .as_millis()
                .min(u128::from(u64::MAX)) as u64;
            metrics::record_remote_playout_release(entry.key.origin_node, lateness_ms);
            released.push(ReleasedRemoteVoiceFrame {
                from_immediate: entry.from_immediate,
                frame: entry.frame,
                decoded: entry.decoded,
            });
        }
        self.streams.retain(|_, state| {
            !state.queued_frames.is_empty()
                || now.saturating_duration_since(state.last_arrival) < state.idle_reset
        });
        released
    }
}

fn record_arrival_delay(state: &mut RemoteVoiceStreamState, frame_number: u64, now: Instant) {
    let arrival_delay_ms = state
        .arrival_anchor
        .and_then(|(anchor_frame, anchor_at)| {
            let expected = add_frame_offset(anchor_at, frame_number.saturating_sub(anchor_frame));
            now.checked_duration_since(expected)
        })
        .map(|delay| delay.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0);
    if state.arrival_delays_ms.len() == ARRIVAL_HISTORY_CAPACITY {
        state.arrival_delays_ms.pop_front();
    }
    state.arrival_delays_ms.push_back(arrival_delay_ms);
}

fn resolve_delay_ms(state: &RemoteVoiceStreamState, policy: RemoteVoicePlayoutPolicy) -> u64 {
    let observed_p99_ms = p99_ms(&state.arrival_delays_ms);
    policy
        .preferred_delay_ms()
        .unwrap_or(0)
        .max(observed_p99_ms)
        .saturating_add(policy.p99_margin_ms())
        .clamp(policy.min_delay_ms(), policy.max_delay_ms())
}

fn p99_ms(samples: &VecDeque<u64>) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut values: Vec<_> = samples.iter().copied().collect();
    values.sort_unstable();
    let index = values
        .len()
        .saturating_mul(99)
        .div_ceil(100)
        .saturating_sub(1);
    values[index]
}

fn add_frame_offset(base: Instant, frames: u64) -> Instant {
    let duration = NATIVE_VOICE_FRAME_INTERVAL
        .checked_mul(frames.min(u64::from(u32::MAX)) as u32)
        .unwrap_or(Duration::MAX);
    base.checked_add(duration).unwrap_or(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use shitspeak_s2s::application::proto::{VoiceIntent, VoiceIntentKind, VoiceIntentNormal};

    fn frame(number: u64, terminator: bool) -> VoiceFrame {
        frame_with_s2s_seq(number, number, terminator)
    }

    fn frame_with_s2s_seq(number: u64, s2s_seq: u64, terminator: bool) -> VoiceFrame {
        assert!(
            number < 128,
            "test legacy audio payload only encodes small frame numbers"
        );
        let payload = Bytes::from(vec![0x80, number as u8, 0x01, 0x11]);
        VoiceFrame {
            sender_session: (1_u32 << 16) | 7,
            server_id: String::new(),
            sender_epoch: 1,
            s2s_seq,
            target_kind: 0,
            is_terminator: terminator,
            payload,
            intent: Some(VoiceIntent {
                kind: Some(VoiceIntentKind::Normal(VoiceIntentNormal {
                    source_channel: 1,
                })),
            }),
        }
    }

    fn schedule_original(
        playout: &mut RemoteVoicePlayout,
        now: Instant,
        frame: VoiceFrame,
        policy: RemoteVoicePlayoutPolicy,
    ) {
        playout.schedule_at(1, frame, policy, false, now);
    }

    fn schedule_repair(
        playout: &mut RemoteVoicePlayout,
        now: Instant,
        frame: VoiceFrame,
        policy: RemoteVoicePlayoutPolicy,
    ) {
        playout.schedule_at(1, frame, policy, true, now);
    }

    fn scheduled_due(playout: &RemoteVoicePlayout, frame_number: u64) -> Instant {
        playout
            .pending
            .iter()
            .find(|entry| entry.decoded.frame_number == frame_number)
            .map(|entry| entry.due)
            .unwrap_or_else(|| panic!("frame {frame_number} was not scheduled"))
    }

    fn selected_delay_policy(delay_ms: u64) -> RemoteVoicePlayoutPolicy {
        RemoteVoicePlayoutPolicy::new(0, 750, 0, 20).with_preferred_delay_ms(Some(delay_ms))
    }

    #[test]
    fn p99_uses_bounded_tail_value() {
        let samples = (0..ARRIVAL_HISTORY_CAPACITY)
            .map(|value| value as u64)
            .collect::<VecDeque<_>>();
        assert_eq!(p99_ms(&samples), 126);
    }

    #[test]
    fn preferred_delay_is_clamped_and_dominates_arrival_baseline() {
        let state = RemoteVoiceStreamState {
            arrival_anchor: None,
            arrival_delays_ms: VecDeque::from([30, 40]),
            last_arrival: Instant::now(),
            idle_reset: Duration::from_secs(1),
            generation: 0,
            talkspurt_first_frame: 0,
            talkspurt_release_at: Instant::now(),
            latched_delay_ms: 0,
            terminator_arrived: false,
            terminator_frame: None,
            queued_frames: HashMap::new(),
            last_scheduled_frame: None,
            last_released_frame: None,
        };
        let policy =
            RemoteVoicePlayoutPolicy::new(80, 100, 60, 2_000).with_preferred_delay_ms(Some(95));
        assert_eq!(resolve_delay_ms(&state, policy), 100);
    }

    #[test]
    fn terminator_is_scheduled_like_media_not_released_immediately() {
        let mut playout = RemoteVoicePlayout::default();
        let started_at = Instant::now();
        let policy = selected_delay_policy(100);
        schedule_original(&mut playout, started_at, frame(10, false), policy);
        schedule_original(
            &mut playout,
            started_at + Duration::from_millis(1),
            frame(11, true),
            policy,
        );
        assert_eq!(
            scheduled_due(&playout, 11),
            scheduled_due(&playout, 10) + NATIVE_VOICE_FRAME_INTERVAL
        );
        assert!(
            playout
                .release_due_at(started_at + Duration::from_millis(99))
                .is_empty()
        );
        assert_eq!(playout.pending.len(), 2);
    }

    #[test]
    fn next_talkspurt_does_not_cancel_the_delayed_prior_terminator() {
        let mut playout = RemoteVoicePlayout::default();
        let started_at = Instant::now();
        let policy = selected_delay_policy(0);
        schedule_original(&mut playout, started_at, frame(10, false), policy);
        schedule_original(&mut playout, started_at, frame(11, true), policy);
        // A next utterance may arrive before the prior terminator is due.
        // Its new generation must not invalidate the already-scheduled end.
        schedule_original(
            &mut playout,
            started_at + Duration::from_millis(1),
            frame(0, false),
            policy,
        );
        let released = playout.release_due_at(started_at + Duration::from_millis(21));
        assert!(
            released
                .iter()
                .any(|release| release.frame.is_terminator && release.decoded.frame_number == 11)
        );
    }

    #[test]
    fn frame_number_pacing_ignores_s2s_sequence() {
        let mut playout = RemoteVoicePlayout::default();
        let started_at = Instant::now();
        let policy = selected_delay_policy(100);
        schedule_original(
            &mut playout,
            started_at,
            frame_with_s2s_seq(10, 1, false),
            policy,
        );
        schedule_original(
            &mut playout,
            started_at + Duration::from_millis(1),
            frame_with_s2s_seq(12, 9_999_999, false),
            policy,
        );
        assert_eq!(
            scheduled_due(&playout, 12).duration_since(scheduled_due(&playout, 10)),
            Duration::from_millis(40)
        );
    }

    #[test]
    fn policy_change_is_latched_until_the_next_talkspurt() {
        let mut playout = RemoteVoicePlayout::default();
        let started_at = Instant::now();
        let initial = selected_delay_policy(80);
        let updated = selected_delay_policy(700);
        schedule_original(&mut playout, started_at, frame(10, false), initial);
        let first_due = scheduled_due(&playout, 10);
        schedule_original(
            &mut playout,
            started_at + Duration::from_millis(1),
            frame(11, false),
            updated,
        );
        schedule_original(
            &mut playout,
            started_at + Duration::from_millis(2),
            frame(12, true),
            updated,
        );
        assert_eq!(
            scheduled_due(&playout, 11),
            first_due + NATIVE_VOICE_FRAME_INTERVAL
        );
        assert_eq!(
            scheduled_due(&playout, 12),
            first_due + NATIVE_VOICE_FRAME_INTERVAL * 2
        );

        schedule_original(
            &mut playout,
            started_at + Duration::from_millis(3),
            frame(100, false),
            updated,
        );
        assert_eq!(
            scheduled_due(&playout, 100),
            started_at + Duration::from_millis(703)
        );
    }

    #[test]
    fn idle_reset_starts_a_new_talkspurt_with_the_new_policy() {
        let mut playout = RemoteVoicePlayout::default();
        let started_at = Instant::now();
        let initial = selected_delay_policy(80);
        let updated = selected_delay_policy(300);
        schedule_original(&mut playout, started_at, frame(10, false), initial);
        let state = playout
            .streams
            .values_mut()
            .next()
            .expect("stream is created");
        state.last_arrival = started_at;

        let resumed_at = started_at + Duration::from_millis(20);
        schedule_original(&mut playout, resumed_at, frame(100, false), updated);
        assert_eq!(
            scheduled_due(&playout, 100),
            resumed_at + Duration::from_millis(300)
        );
    }

    #[test]
    fn repair_before_scheduled_playout_is_admitted_on_the_media_timeline() {
        let mut playout = RemoteVoicePlayout::default();
        let started_at = Instant::now();
        let policy = selected_delay_policy(100);
        schedule_original(&mut playout, started_at, frame(10, false), policy);
        schedule_original(
            &mut playout,
            started_at + Duration::from_millis(1),
            frame(12, false),
            policy,
        );
        schedule_repair(
            &mut playout,
            started_at + Duration::from_millis(2),
            frame(11, false),
            policy,
        );
        assert_eq!(
            scheduled_due(&playout, 11),
            scheduled_due(&playout, 10) + NATIVE_VOICE_FRAME_INTERVAL
        );
        assert_eq!(playout.pending.len(), 3);
    }

    #[test]
    fn repair_after_terminator_stays_in_the_prior_talkspurt_timeline() {
        let mut playout = RemoteVoicePlayout::default();
        let started_at = Instant::now();
        let policy = selected_delay_policy(100);
        schedule_original(&mut playout, started_at, frame(10, false), policy);
        schedule_original(
            &mut playout,
            started_at + Duration::from_millis(1),
            frame(12, true),
            policy,
        );

        // The terminator has arrived but is still scheduled in the future.
        // A late repair of frame 11 must use that prior media clock rather
        // than establish a new talkspurt.
        schedule_repair(
            &mut playout,
            started_at + Duration::from_millis(2),
            frame(11, false),
            policy,
        );
        assert_eq!(
            scheduled_due(&playout, 11),
            scheduled_due(&playout, 10) + NATIVE_VOICE_FRAME_INTERVAL
        );
        assert_eq!(
            scheduled_due(&playout, 12),
            scheduled_due(&playout, 10) + NATIVE_VOICE_FRAME_INTERVAL * 2
        );

        let pending_before = playout.pending.len();
        schedule_repair(
            &mut playout,
            started_at + Duration::from_millis(3),
            frame(13, false),
            policy,
        );
        assert_eq!(playout.pending.len(), pending_before);
    }

    #[test]
    fn orphan_or_idle_repair_never_starts_a_talkspurt() {
        let mut playout = RemoteVoicePlayout::default();
        let started_at = Instant::now();
        let policy = selected_delay_policy(100);
        schedule_repair(&mut playout, started_at, frame(10, false), policy);
        assert!(playout.streams.is_empty());
        assert!(playout.pending.is_empty());

        schedule_original(&mut playout, started_at, frame(10, false), policy);
        schedule_repair(
            &mut playout,
            started_at + Duration::from_millis(20),
            frame(11, false),
            policy,
        );
        assert_eq!(playout.pending.len(), 1);
        assert!(playout.streams.values().all(|state| state.generation == 1));
    }

    #[test]
    fn repair_after_its_scheduled_playout_is_dropped() {
        let mut playout = RemoteVoicePlayout::default();
        let started_at = Instant::now();
        let policy = selected_delay_policy(20);
        schedule_original(&mut playout, started_at, frame(10, false), policy);
        schedule_original(
            &mut playout,
            started_at + Duration::from_millis(1),
            frame(12, false),
            policy,
        );

        // Frame 11's media deadline was `started_at + 40 ms`, so a repair
        // received after that deadline may not rebase or chop the talkspurt.
        schedule_repair(
            &mut playout,
            started_at + Duration::from_millis(41),
            frame(11, false),
            policy,
        );
        assert_eq!(playout.pending.len(), 2);
    }

    #[test]
    fn release_lateness_is_recorded_in_the_bounded_metric() {
        let mut playout = RemoteVoicePlayout::default();
        let started_at = Instant::now();
        schedule_original(
            &mut playout,
            started_at,
            frame(10, false),
            selected_delay_policy(0),
        );
        assert_eq!(
            playout
                .release_due_at(started_at + Duration::from_millis(51))
                .len(),
            1
        );
        assert!(metrics::prometheus_samples().iter().any(|sample| {
            sample.name() == "shitspeak_voice_remote_playout_release_lateness_ms_bucket_total"
                && sample
                    .labels()
                    .iter()
                    .any(|(key, value)| key == "origin_node" && value == "1")
                && sample
                    .labels()
                    .iter()
                    .any(|(key, value)| key == "bucket" && value == "le_100")
                && sample.value() >= 1.0
        }));
    }

    #[test]
    fn bounded_contiguous_original_drift_rebases_without_an_immediate_release() {
        let mut playout = RemoteVoicePlayout::default();
        let started_at = Instant::now();
        let policy = selected_delay_policy(1);
        schedule_original(&mut playout, started_at, frame(10, false), policy);
        assert_eq!(
            playout
                .release_due_at(started_at + Duration::from_millis(1))
                .len(),
            1
        );

        // The native next frame is six milliseconds behind its original media
        // deadline. It is still a contiguous original, so preserve cadence by
        // shifting the remainder of this fixed talkspurt timeline.
        schedule_original(
            &mut playout,
            started_at + Duration::from_millis(27),
            frame(11, false),
            policy,
        );
        assert!(
            playout
                .release_due_at(started_at + Duration::from_millis(27))
                .is_empty()
        );
        assert!(
            playout
                .next_deadline()
                .is_some_and(|deadline| deadline > started_at + Duration::from_millis(37))
        );
    }
}
