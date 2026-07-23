//! Loss recovery for correlated strict-repair v3 control exchanges.
//!
//! The transport bulk pacer owns enqueue backpressure.  This coordinator
//! retransmits an already-enqueued request or final ACK when the corresponding
//! peer response is lost, without changing its transfer, nonce, or cursor.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::super::proto::{StrictCatchupReq, StrictTerminalSyncAck, StrictTerminalSyncReq};
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
}

impl Default for V3RetryState {
    fn default() -> Self {
        Self {
            requests: HashMap::new(),
            final_acks: HashMap::new(),
            history_requests: HashMap::new(),
            history_final_acks: HashMap::new(),
        }
    }
}

impl V3RetryState {
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
        (requests, final_acks, history_requests, history_final_acks)
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

    pub(super) fn discard_peer(&mut self, node: NodeIdentifier) {
        self.requests.retain(|peer, _| peer.node() != node);
        self.final_acks.retain(|(peer, _), _| peer.node() != node);
        self.history_requests.retain(|peer, _| peer.node() != node);
        self.history_final_acks
            .retain(|(peer, _), _| peer.node() != node);
    }

    fn expire(&mut self, now: Instant) {
        self.requests.retain(|_, pending| pending.expires_at > now);
        self.final_acks
            .retain(|_, pending| pending.expires_at > now);
        self.history_requests
            .retain(|_, pending| pending.expires_at > now);
        self.history_final_acks
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
    use crate::replications::proto::{StrictTerminalSyncAck, StrictTerminalSyncReq};
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
        let (due, _, _, _) = state.due(Instant::now(), Duration::from_secs(5), 25, 1);
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
