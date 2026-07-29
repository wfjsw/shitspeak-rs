//! Loss recovery for correlated strict-repair v3 control exchanges.
//!
//! The transport bulk pacer owns enqueue backpressure.  This coordinator
//! retransmits an already-enqueued request or final ACK when the corresponding
//! peer response is lost, without changing its transfer, nonce, or cursor.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::super::proto::{
    StrictCatchupReq, StrictClockProbeReq, StrictHistoryProbeReq, StrictHistoryTransferResp,
    StrictTerminalSyncAck, StrictTerminalSyncReq,
};
use super::sync_v3::PeerIncarnation;
use shitspeak_core::NodeIdentifier;

#[derive(Clone)]
struct Scheduled<T> {
    message: T,
    delay: Duration,
    next_at: Instant,
    expires_at: Instant,
    attempt: u32,
}

pub(super) struct V3RetryState {
    requests: HashMap<PeerIncarnation, Scheduled<StrictTerminalSyncReq>>,
    final_acks: HashMap<(PeerIncarnation, u64), Scheduled<StrictTerminalSyncAck>>,
    history_requests: HashMap<PeerIncarnation, Scheduled<StrictCatchupReq>>,
    history_final_acks: HashMap<(PeerIncarnation, u64), Scheduled<StrictCatchupReq>>,
    clock_probes: HashMap<PeerIncarnation, Scheduled<StrictClockProbeReq>>,
    history_probes: HashMap<PeerIncarnation, Scheduled<StrictHistoryProbeReq>>,
}

impl Default for V3RetryState {
    fn default() -> Self {
        Self {
            requests: HashMap::new(),
            final_acks: HashMap::new(),
            history_requests: HashMap::new(),
            history_final_acks: HashMap::new(),
            clock_probes: HashMap::new(),
            history_probes: HashMap::new(),
        }
    }
}

impl V3RetryState {
    /// Whether any correlated V3 transmission can still be retried with a
    /// cut, cursor, or snapshot identity captured before a checkpoint.
    pub(super) fn has_checkpoint_blocking_work(&self, now: Instant) -> bool {
        self.requests
            .values()
            .any(|pending| pending.expires_at > now)
            || self
                .final_acks
                .values()
                .any(|pending| pending.expires_at > now)
            || self
                .history_requests
                .values()
                .any(|pending| pending.expires_at > now)
            || self
                .history_final_acks
                .values()
                .any(|pending| pending.expires_at > now)
            || self
                .clock_probes
                .values()
                .any(|pending| pending.expires_at > now)
            || self
                .history_probes
                .values()
                .any(|pending| pending.expires_at > now)
    }

    pub(super) fn register_request(
        &mut self,
        peer: PeerIncarnation,
        request: StrictTerminalSyncReq,
        initial_delay: Duration,
        ttl: Duration,
        jitter_pct: u32,
        salt: u64,
    ) {
        let now = Instant::now();
        let next_at = now
            + jittered(
                initial_delay,
                jitter_pct,
                identity_salt(peer, request.transfer_id, request.request_nonce, 0, salt),
            );
        self.requests.insert(
            peer,
            Scheduled {
                message: request,
                delay: initial_delay,
                next_at,
                expires_at: now + ttl,
                attempt: 0,
            },
        );
    }

    pub(super) fn complete_request(&mut self, peer: PeerIncarnation, nonce: u64) {
        if self
            .requests
            .get(&peer)
            .is_some_and(|pending| pending.message.request_nonce == nonce)
        {
            self.requests.remove(&peer);
        }
    }

    pub(super) fn request_nonce_is_current(&self, peer: PeerIncarnation, nonce: u64) -> bool {
        self.requests
            .get(&peer)
            .is_some_and(|pending| pending.message.request_nonce == nonce)
    }

    pub(super) fn extend_current_request_expiry(&mut self, peer: PeerIncarnation, ttl: Duration) {
        let pending = self
            .requests
            .get_mut(&peer)
            .expect("checked request exists");
        pending.expires_at = pending
            .expires_at
            .checked_add(ttl)
            .unwrap_or(pending.expires_at);
    }

    pub(super) fn register_final_ack(
        &mut self,
        peer: PeerIncarnation,
        ack: StrictTerminalSyncAck,
        initial_delay: Duration,
        ttl: Duration,
        jitter_pct: u32,
        salt: u64,
    ) {
        let now = Instant::now();
        let key = (peer, ack.transfer_id);
        let next_at = now
            + jittered(
                initial_delay,
                jitter_pct,
                identity_salt(peer, ack.transfer_id, ack.request_nonce, 0, salt),
            );
        self.final_acks.insert(
            key,
            Scheduled {
                message: ack,
                delay: initial_delay,
                next_at,
                expires_at: now + ttl,
                attempt: 0,
            },
        );
    }

    /// Stop retrying only the exact final ACK whose delivery was correlated.
    /// A delayed delivery notification from an older nonce must not cancel a
    /// newer ACK retry that reused the peer/transfer key.
    pub(super) fn complete_final_ack(
        &mut self,
        peer: PeerIncarnation,
        transfer_id: u64,
        nonce: u64,
    ) {
        let key = (peer, transfer_id);
        if self
            .final_acks
            .get(&key)
            .is_some_and(|pending| pending.message.request_nonce == nonce)
        {
            self.final_acks.remove(&key);
        }
    }

    pub(super) fn register_history_request(
        &mut self,
        peer: PeerIncarnation,
        request: StrictCatchupReq,
        initial_delay: Duration,
        ttl: Duration,
        jitter_pct: u32,
        salt: u64,
    ) {
        let Some(transfer) = request.history_transfer.as_ref() else {
            return;
        };
        let now = Instant::now();
        let next_at = now
            + jittered(
                initial_delay,
                jitter_pct,
                identity_salt(peer, transfer.transfer_id, transfer.request_nonce, 0, salt),
            );
        self.history_requests.insert(
            peer,
            Scheduled {
                message: request,
                delay: initial_delay,
                next_at,
                expires_at: now + ttl,
                attempt: 0,
            },
        );
    }

    pub(super) fn register_history_probe(
        &mut self,
        peer: PeerIncarnation,
        request: StrictHistoryProbeReq,
        initial_delay: Duration,
        ttl: Duration,
        jitter_pct: u32,
        salt: u64,
    ) {
        let now = Instant::now();
        let next_at = now
            + jittered(
                initial_delay,
                jitter_pct,
                identity_salt(peer, 0, request.request_nonce, 0, salt),
            );
        self.history_probes.insert(
            peer,
            Scheduled {
                message: request,
                delay: initial_delay,
                next_at,
                expires_at: now + ttl,
                attempt: 0,
            },
        );
    }

    pub(super) fn register_clock_probe(
        &mut self,
        peer: PeerIncarnation,
        request: StrictClockProbeReq,
        initial_delay: Duration,
        ttl: Duration,
        jitter_pct: u32,
        salt: u64,
    ) {
        let now = Instant::now();
        let next_at = now
            + jittered(
                initial_delay,
                jitter_pct,
                identity_salt(peer, 0, request.request_nonce, 0, salt),
            );
        self.clock_probes.insert(
            peer,
            Scheduled {
                message: request,
                delay: initial_delay,
                next_at,
                expires_at: now + ttl,
                attempt: 0,
            },
        );
    }

    pub(super) fn complete_clock_probe(&mut self, peer: PeerIncarnation, nonce: u64) {
        if self
            .clock_probes
            .get(&peer)
            .is_some_and(|pending| pending.message.request_nonce == nonce)
        {
            self.clock_probes.remove(&peer);
        }
    }

    pub(super) fn complete_history_probe(&mut self, peer: PeerIncarnation, nonce: u64) {
        if self
            .history_probes
            .get(&peer)
            .is_some_and(|pending| pending.message.request_nonce == nonce)
        {
            self.history_probes.remove(&peer);
        }
    }

    pub(super) fn history_probe_nonce_is_scheduled(
        &self,
        peer: PeerIncarnation,
        nonce: u64,
    ) -> bool {
        self.history_probes
            .get(&peer)
            .is_some_and(|pending| pending.message.request_nonce == nonce)
    }

    pub(super) fn expedite_history_probe(
        &mut self,
        peer: PeerIncarnation,
        nonce: u64,
        now: Instant,
    ) {
        if let Some(pending) = self
            .history_probes
            .get_mut(&peer)
            .filter(|pending| pending.message.request_nonce == nonce)
        {
            pending.next_at = pending.next_at.min(now);
        }
    }

    pub(super) fn complete_history_request(&mut self, peer: PeerIncarnation, nonce: u64) {
        if self.history_requests.get(&peer).is_some_and(|pending| {
            pending
                .message
                .history_transfer
                .as_ref()
                .is_some_and(|transfer| transfer.request_nonce == nonce)
        }) {
            self.history_requests.remove(&peer);
        }
    }

    pub(super) fn cancel_history_request(&mut self, peer: PeerIncarnation) {
        self.history_requests.remove(&peer);
    }

    pub(super) fn register_history_final_ack(
        &mut self,
        peer: PeerIncarnation,
        ack: StrictCatchupReq,
        initial_delay: Duration,
        ttl: Duration,
        jitter_pct: u32,
        salt: u64,
    ) {
        let Some(transfer) = ack.history_transfer.as_ref() else {
            return;
        };
        let now = Instant::now();
        let key = (peer, transfer.transfer_id);
        let next_at = now
            + jittered(
                initial_delay,
                jitter_pct,
                identity_salt(peer, transfer.transfer_id, transfer.request_nonce, 0, salt),
            );
        self.history_final_acks.insert(
            key,
            Scheduled {
                message: ack,
                delay: initial_delay,
                next_at,
                expires_at: now + ttl,
                attempt: 0,
            },
        );
    }

    /// Complete only the final ACK identified by an authenticated peer's
    /// exact, operation-free confirmation. Ordinary history responses use a
    /// client request nonce and therefore cannot clear this retry slot.
    pub(super) fn complete_history_final_ack(
        &mut self,
        peer: PeerIncarnation,
        confirmation: &StrictHistoryTransferResp,
        local_boot_epoch: u64,
    ) -> bool {
        let key = (peer, confirmation.transfer_id);
        let confirmed = self.history_final_acks.get(&key).is_some_and(|pending| {
            pending
                .message
                .history_transfer
                .as_ref()
                .is_some_and(|final_ack| {
                    final_ack.final_ack
                        && confirmation.expected_requester_boot_epoch == local_boot_epoch
                        && confirmation.request_nonce == final_ack.request_nonce
                        && confirmation.cursor == final_ack.expected_cursor
                        && confirmation.target_version == final_ack.target_version
                })
        });
        if confirmed {
            self.history_final_acks.remove(&key);
        }
        confirmed
    }

    pub(super) fn due(
        &mut self,
        now: Instant,
        max_delay: Duration,
        jitter_pct: u32,
        salt: u64,
    ) -> (
        Vec<(PeerIncarnation, StrictTerminalSyncReq)>,
        Vec<(PeerIncarnation, StrictTerminalSyncAck)>,
        Vec<(PeerIncarnation, StrictCatchupReq)>,
        Vec<(PeerIncarnation, StrictCatchupReq)>,
        Vec<(PeerIncarnation, StrictHistoryProbeReq)>,
    ) {
        self.expire(now);
        let mut requests = Vec::new();
        for (peer, pending) in &mut self.requests {
            if pending.next_at > now {
                continue;
            }
            requests.push((*peer, pending.message.clone()));
            let schedule_salt = identity_salt(
                *peer,
                pending.message.transfer_id,
                pending.message.request_nonce,
                pending.attempt.saturating_add(1),
                salt,
            );
            advance_schedule(pending, now, max_delay, jitter_pct, schedule_salt);
        }
        let mut final_acks = Vec::new();
        for ((peer, _), pending) in &mut self.final_acks {
            if pending.next_at > now {
                continue;
            }
            final_acks.push((*peer, pending.message.clone()));
            let schedule_salt = identity_salt(
                *peer,
                pending.message.transfer_id,
                pending.message.request_nonce,
                pending.attempt.saturating_add(1),
                salt,
            );
            advance_schedule(pending, now, max_delay, jitter_pct, schedule_salt);
        }
        let mut history_requests = Vec::new();
        for (peer, pending) in &mut self.history_requests {
            if pending.next_at > now {
                continue;
            }
            history_requests.push((*peer, pending.message.clone()));
            let transfer = pending
                .message
                .history_transfer
                .as_ref()
                .expect("registered history request has correlation");
            let schedule_salt = identity_salt(
                *peer,
                transfer.transfer_id,
                transfer.request_nonce,
                pending.attempt.saturating_add(1),
                salt,
            );
            advance_schedule(pending, now, max_delay, jitter_pct, schedule_salt);
        }
        let mut history_final_acks = Vec::new();
        for ((peer, _), pending) in &mut self.history_final_acks {
            if pending.next_at > now {
                continue;
            }
            history_final_acks.push((*peer, pending.message.clone()));
            let transfer = pending
                .message
                .history_transfer
                .as_ref()
                .expect("registered history final ACK has correlation");
            let schedule_salt = identity_salt(
                *peer,
                transfer.transfer_id,
                transfer.request_nonce,
                pending.attempt.saturating_add(1),
                salt,
            );
            advance_schedule(pending, now, max_delay, jitter_pct, schedule_salt);
        }
        let mut history_probes = Vec::new();
        for (peer, pending) in &mut self.history_probes {
            if pending.next_at > now {
                continue;
            }
            history_probes.push((*peer, pending.message.clone()));
            let schedule_salt = identity_salt(
                *peer,
                0,
                pending.message.request_nonce,
                pending.attempt.saturating_add(1),
                salt,
            );
            advance_schedule(pending, now, max_delay, jitter_pct, schedule_salt);
        }
        (
            requests,
            final_acks,
            history_requests,
            history_final_acks,
            history_probes,
        )
    }

    pub(super) fn due_clock_probes(
        &mut self,
        now: Instant,
        max_delay: Duration,
        jitter_pct: u32,
        salt: u64,
    ) -> Vec<(PeerIncarnation, StrictClockProbeReq)> {
        self.clock_probes
            .retain(|_, pending| pending.expires_at > now);
        let mut probes = Vec::new();
        for (peer, pending) in &mut self.clock_probes {
            if pending.next_at > now {
                continue;
            }
            probes.push((*peer, pending.message.clone()));
            let schedule_salt = identity_salt(
                *peer,
                0,
                pending.message.request_nonce,
                pending.attempt.saturating_add(1),
                salt,
            );
            advance_schedule(pending, now, max_delay, jitter_pct, schedule_salt);
        }
        probes
    }

    pub(super) fn clock_probe_is_current(
        &self,
        peer: PeerIncarnation,
        request: &StrictClockProbeReq,
    ) -> bool {
        self.clock_probes.get(&peer).is_some_and(|pending| {
            pending.message.request_nonce == request.request_nonce
                && pending.message.reason == request.reason
        })
    }

    pub(super) fn request_is_current(
        &self,
        peer: PeerIncarnation,
        request: &StrictTerminalSyncReq,
    ) -> bool {
        self.requests.get(&peer).is_some_and(|pending| {
            pending.message.transfer_id == request.transfer_id
                && pending.message.request_nonce == request.request_nonce
                && pending.message.expected_cursor == request.expected_cursor
        })
    }

    pub(super) fn final_ack_is_current(
        &self,
        peer: PeerIncarnation,
        ack: &StrictTerminalSyncAck,
    ) -> bool {
        self.final_acks
            .get(&(peer, ack.transfer_id))
            .is_some_and(|pending| {
                pending.message.request_nonce == ack.request_nonce
                    && pending.message.target_cut == ack.target_cut
            })
    }

    pub(super) fn history_request_is_current(
        &self,
        peer: PeerIncarnation,
        request: &StrictCatchupReq,
    ) -> bool {
        let Some(expected) = request.history_transfer.as_ref() else {
            return false;
        };
        self.history_requests.get(&peer).is_some_and(|pending| {
            pending
                .message
                .history_transfer
                .as_ref()
                .is_some_and(|current| {
                    current.transfer_id == expected.transfer_id
                        && current.request_nonce == expected.request_nonce
                        && current.expected_cursor == expected.expected_cursor
                })
        })
    }

    pub(super) fn history_final_ack_is_current(
        &self,
        peer: PeerIncarnation,
        request: &StrictCatchupReq,
    ) -> bool {
        let Some(expected) = request.history_transfer.as_ref() else {
            return false;
        };
        self.history_final_acks
            .get(&(peer, expected.transfer_id))
            .is_some_and(|pending| {
                pending
                    .message
                    .history_transfer
                    .as_ref()
                    .is_some_and(|current| {
                        current.request_nonce == expected.request_nonce
                            && current.acknowledged_request_nonce
                                == expected.acknowledged_request_nonce
                            && current.final_ack
                    })
            })
    }

    pub(super) fn history_probe_is_current(
        &self,
        peer: PeerIncarnation,
        request: &StrictHistoryProbeReq,
    ) -> bool {
        self.history_probes.get(&peer).is_some_and(|pending| {
            pending.message.request_nonce == request.request_nonce
                && pending.message.reason == request.reason
        })
    }

    pub(super) fn discard_peer(&mut self, node: NodeIdentifier) {
        self.requests.retain(|peer, _| peer.node() != node);
        self.final_acks.retain(|(peer, _), _| peer.node() != node);
        self.history_requests.retain(|peer, _| peer.node() != node);
        self.history_final_acks
            .retain(|(peer, _), _| peer.node() != node);
        self.clock_probes.retain(|peer, _| peer.node() != node);
        self.history_probes.retain(|peer, _| peer.node() != node);
    }

    fn expire(&mut self, now: Instant) {
        self.requests.retain(|_, pending| pending.expires_at > now);
        self.final_acks
            .retain(|_, pending| pending.expires_at > now);
        self.history_requests
            .retain(|_, pending| pending.expires_at > now);
        self.history_final_acks
            .retain(|_, pending| pending.expires_at > now);
        self.clock_probes
            .retain(|_, pending| pending.expires_at > now);
        self.history_probes
            .retain(|_, pending| pending.expires_at > now);
    }
}

fn advance_schedule<T>(
    pending: &mut Scheduled<T>,
    now: Instant,
    max_delay: Duration,
    jitter_pct: u32,
    salt: u64,
) {
    pending.attempt = pending.attempt.saturating_add(1);
    pending.delay = pending.delay.saturating_mul(2).min(max_delay);
    pending.next_at = now + jittered(pending.delay, jitter_pct, salt);
}

fn identity_salt(
    peer: PeerIncarnation,
    transfer_id: u64,
    nonce: u64,
    attempt: u32,
    salt: u64,
) -> u64 {
    let mut value = salt ^ (peer.node() as u64);
    for word in [peer.boot_epoch(), transfer_id, nonce, attempt as u64] {
        value ^= word;
        value = value.wrapping_mul(0x100_0000_01b3);
        value ^= value >> 32;
    }
    value
}

fn jittered(delay: Duration, jitter_pct: u32, salt: u64) -> Duration {
    if delay.is_zero() || jitter_pct == 0 {
        return delay;
    }
    let pct = jitter_pct.min(100) as i128;
    let span = pct.saturating_mul(2).saturating_add(1);
    let offset_pct = (salt as i128 % span) - pct;
    let nanos = delay.as_nanos().min(i128::MAX as u128) as i128;
    let adjusted = nanos
        .saturating_add(nanos.saturating_mul(offset_pct) / 100)
        .max(0);
    Duration::from_nanos(adjusted.min(u64::MAX as i128) as u64)
}

#[cfg(test)]
mod tests {
    use super::{PeerIncarnation, V3RetryState, jittered};
    use crate::replications::proto::{
        StrictCatchupReq, StrictClockProbeReq, StrictHistoryProbeReq, StrictHistoryTransferReq,
        StrictHistoryTransferResp, StrictTerminalSyncAck, StrictTerminalSyncReq,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn deterministic_jitter_stays_inside_configured_band() {
        let base = Duration::from_millis(1_000);
        assert_eq!(jittered(base, 25, 17), jittered(base, 25, 17));
        for salt in 0..256 {
            let delay = jittered(base, 25, salt);
            assert!(delay >= Duration::from_millis(750));
            assert!(delay <= Duration::from_millis(1_250));
        }
    }

    #[test]
    fn live_retry_blocks_checkpoint_but_expired_retry_does_not() {
        let peer = PeerIncarnation::new(7, 70);
        let mut state = V3RetryState::default();
        let now = Instant::now();
        state.register_request(
            peer,
            StrictTerminalSyncReq {
                request_nonce: 1,
                ..Default::default()
            },
            Duration::from_secs(1),
            Duration::from_secs(30),
            0,
            0,
        );

        assert!(state.has_checkpoint_blocking_work(now));
        assert!(!state.has_checkpoint_blocking_work(now + Duration::from_secs(31)));
    }

    #[test]
    fn retry_keeps_identity_and_progress_replaces_the_old_request() {
        let peer = PeerIncarnation::new(7, 70);
        let mut state = V3RetryState::default();
        let initial = StrictTerminalSyncReq {
            transfer_id: 0,
            request_nonce: 11,
            expected_cursor: 0,
            ..Default::default()
        };
        state.register_request(
            peer,
            initial.clone(),
            Duration::ZERO,
            Duration::from_secs(30),
            25,
            1,
        );
        let (due, _, _, _, _) = state.due(Instant::now(), Duration::from_secs(5), 25, 1);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].1, initial);

        let continuation = StrictTerminalSyncReq {
            transfer_id: 19,
            request_nonce: 12,
            expected_cursor: 128,
            ..Default::default()
        };
        state.register_request(
            peer,
            continuation.clone(),
            Duration::from_millis(250),
            Duration::from_secs(30),
            25,
            1,
        );
        assert!(!state.request_is_current(peer, &initial));
        assert!(state.request_is_current(peer, &continuation));
        state.complete_request(peer, continuation.request_nonce);
        assert!(!state.request_is_current(peer, &continuation));
    }

    #[test]
    fn history_probe_retries_one_identity_until_response() {
        let peer = PeerIncarnation::new(7, 70);
        let mut state = V3RetryState::default();
        let request = StrictHistoryProbeReq {
            request_nonce: 31,
            reason: 7,
            ..Default::default()
        };
        state.register_history_probe(
            peer,
            request.clone(),
            Duration::ZERO,
            Duration::from_secs(30),
            0,
            1,
        );

        let (_, _, _, _, due) = state.due(Instant::now(), Duration::from_secs(5), 0, 1);
        assert_eq!(due, vec![(peer, request.clone())]);
        assert!(state.history_probe_is_current(peer, &request));
        state.complete_history_probe(peer, request.request_nonce);
        assert!(!state.history_probe_is_current(peer, &request));
    }

    #[test]
    fn history_final_ack_requires_exact_correlated_confirmation() {
        let peer = PeerIncarnation::new(7, 70);
        let mut state = V3RetryState::default();
        let ack = StrictCatchupReq {
            history_transfer: Some(StrictHistoryTransferReq {
                transfer_id: 51,
                request_nonce: 52,
                expected_cursor: 53,
                target_version: 54,
                final_ack: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        state.register_history_final_ack(
            peer,
            ack.clone(),
            Duration::ZERO,
            Duration::from_secs(30),
            0,
            1,
        );
        let confirmation = StrictHistoryTransferResp {
            expected_requester_boot_epoch: 99,
            transfer_id: 51,
            request_nonce: 52,
            cursor: 53,
            target_version: 54,
        };

        for mismatched in [
            StrictHistoryTransferResp {
                request_nonce: 55,
                ..confirmation.clone()
            },
            StrictHistoryTransferResp {
                transfer_id: 56,
                ..confirmation.clone()
            },
            StrictHistoryTransferResp {
                expected_requester_boot_epoch: 100,
                ..confirmation.clone()
            },
        ] {
            assert!(!state.complete_history_final_ack(peer, &mismatched, 99));
            assert!(state.history_final_ack_is_current(peer, &ack));
        }

        assert!(state.complete_history_final_ack(peer, &confirmation, 99));
        assert!(!state.history_final_ack_is_current(peer, &ack));
    }

    #[test]
    fn clock_probe_retry_keeps_identity_and_doubles_to_the_bound() {
        let peer = PeerIncarnation::new(7, 70);
        let mut state = V3RetryState::default();
        let request = StrictClockProbeReq {
            request_nonce: 41,
            reason: 5,
            ..Default::default()
        };
        let registered_at = Instant::now();
        state.register_clock_probe(
            peer,
            request.clone(),
            Duration::from_secs(1),
            Duration::from_secs(30),
            0,
            1,
        );

        assert!(
            state
                .due_clock_probes(
                    registered_at + Duration::from_millis(900),
                    Duration::from_secs(2),
                    0,
                    1,
                )
                .is_empty()
        );
        assert_eq!(
            state.due_clock_probes(
                registered_at + Duration::from_millis(1_100),
                Duration::from_secs(2),
                0,
                1,
            ),
            vec![(peer, request.clone())]
        );
        assert!(
            state
                .due_clock_probes(
                    registered_at + Duration::from_millis(3_000),
                    Duration::from_secs(2),
                    0,
                    1,
                )
                .is_empty()
        );
        assert_eq!(
            state.due_clock_probes(
                registered_at + Duration::from_millis(3_101),
                Duration::from_secs(2),
                0,
                1,
            ),
            vec![(peer, request.clone())]
        );
        state.complete_clock_probe(peer, request.request_nonce);
        assert!(!state.clock_probe_is_current(peer, &request));
    }

    #[test]
    fn incarnation_discard_cancels_request_and_final_ack_retries() {
        let peer = PeerIncarnation::new(7, 70);
        let mut state = V3RetryState::default();
        let request = StrictTerminalSyncReq {
            request_nonce: 21,
            ..Default::default()
        };
        let ack = StrictTerminalSyncAck {
            transfer_id: 22,
            request_nonce: 21,
            ..Default::default()
        };
        state.register_request(
            peer,
            request.clone(),
            Duration::from_millis(250),
            Duration::from_secs(30),
            25,
            2,
        );
        state.register_final_ack(
            peer,
            ack.clone(),
            Duration::from_millis(250),
            Duration::from_secs(30),
            25,
            2,
        );
        state.discard_peer(7);
        assert!(!state.request_is_current(peer, &request));
        assert!(!state.final_ack_is_current(peer, &ack));
    }
}
