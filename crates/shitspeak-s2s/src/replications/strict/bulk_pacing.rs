//! Shared strict-replication bulk admission by physical first hop.
//!
//! A single [`BulkPacer`] is owned by `OverlayStrictNet`, which is in turn
//! shared by every strict topic registered with one replication manager. The
//! accounting key is therefore the selected first hop, not the logical topic
//! or destination.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::time::sleep;

use super::super::metrics::{self, StrictCatchupThrottleReason};
use shitspeak_core::NodeIdentifier;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct LogicalPageKey {
    destination: NodeIdentifier,
    topic: String,
    page: BulkPageIdentity,
}

/// Stable protocol identity for one operation-bearing page.
///
/// Terminal transfers explicitly echo the request nonce in their page and
/// final ACK. A history continuation explicitly echoes the preceding
/// response nonce.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum BulkPageIdentity {
    Legacy,
    Terminal {
        transfer_id: u64,
        request_nonce: u64,
    },
    History {
        transfer_id: u64,
        request_nonce: u64,
    },
}

impl BulkPageIdentity {
    pub(crate) fn terminal(transfer_id: u64, request_nonce: u64) -> Self {
        Self::Terminal {
            transfer_id,
            request_nonce,
        }
    }

    pub(crate) fn history(transfer_id: u64, request_nonce: u64) -> Self {
        Self::History {
            transfer_id,
            request_nonce,
        }
    }
}

struct HopBudget {
    in_flight_bytes: usize,
    rate_tokens: f64,
    last_refill: Instant,
}

struct ReservationRecord {
    key: LogicalPageKey,
    next_hop: NodeIdentifier,
    bytes: usize,
    retained: bool,
}

#[derive(Default)]
struct BulkPacerState {
    next_id: u64,
    hops: HashMap<NodeIdentifier, HopBudget>,
    reservations: HashMap<u64, ReservationRecord>,
    outstanding_by_key: HashMap<LogicalPageKey, u64>,
}

#[derive(Debug)]
pub(super) enum BulkAdmissionError {
    FrameTooLarge {
        encoded_bytes: usize,
        max_bytes: usize,
    },
}

enum TryReserve {
    Admitted(BulkReservation),
    Wait(Duration),
    FrameTooLarge,
}

/// Cross-topic, per-next-hop byte and rate scheduler.
pub(super) struct BulkPacer {
    max_in_flight_bytes: usize,
    rate_bytes_per_second: u64,
    state: Mutex<BulkPacerState>,
    changed: Notify,
}

impl BulkPacer {
    pub(super) fn new(max_in_flight_bytes: usize, rate_bytes_per_second: u64) -> Arc<Self> {
        Arc::new(Self {
            max_in_flight_bytes: max_in_flight_bytes.max(1),
            rate_bytes_per_second: rate_bytes_per_second.max(1),
            state: Mutex::new(BulkPacerState::default()),
            changed: Notify::new(),
        })
    }

    /// Reserve the exact authenticated strict frame size against its current
    /// physical first hop. A retained replay of this exact protocol page is
    /// replaced here; reservations for earlier or later pages remain until
    /// their own correlated continuation, ACK, cancellation, or TTL.
    pub(super) async fn reserve(
        self: &Arc<Self>,
        destination: NodeIdentifier,
        topic: &str,
        page: BulkPageIdentity,
        next_hop: NodeIdentifier,
        encoded_bytes: usize,
    ) -> Result<BulkReservation, BulkAdmissionError> {
        let key = LogicalPageKey {
            destination,
            topic: topic.to_owned(),
            page,
        };
        loop {
            let notified = self.changed.notified();
            match self.try_reserve(key.clone(), next_hop, encoded_bytes) {
                TryReserve::Admitted(reservation) => return Ok(reservation),
                TryReserve::FrameTooLarge => {
                    return Err(BulkAdmissionError::FrameTooLarge {
                        encoded_bytes,
                        max_bytes: self.max_in_flight_bytes,
                    });
                }
                TryReserve::Wait(delay) => {
                    metrics::record_strict_catchup_throttled(
                        StrictCatchupThrottleReason::NextHopBytes,
                    );
                    tokio::select! {
                        _ = notified => {}
                        _ = sleep(delay) => {}
                    }
                }
            }
        }
    }

    fn try_reserve(
        self: &Arc<Self>,
        key: LogicalPageKey,
        next_hop: NodeIdentifier,
        encoded_bytes: usize,
    ) -> TryReserve {
        if encoded_bytes > self.max_in_flight_bytes {
            return TryReserve::FrameTooLarge;
        }

        let now = Instant::now();
        let mut state = self.state.lock();

        // A retained copy of this exact page is replaced by a cached replay.
        // A copy still being enqueued is not: concurrent duplicate responders
        // must wait rather than temporarily under-accounting the first hop.
        if let Some(existing_id) = state.outstanding_by_key.get(&key).copied() {
            let retained = state
                .reservations
                .get(&existing_id)
                .is_some_and(|record| record.retained);
            if retained {
                Self::release_locked(&mut state, existing_id);
                self.changed.notify_waiters();
            } else {
                return TryReserve::Wait(Duration::from_millis(10));
            }
        }

        let hop = state.entry_or_insert_hop(next_hop, self.max_in_flight_bytes, now);
        refill_rate_tokens(
            hop,
            now,
            self.max_in_flight_bytes,
            self.rate_bytes_per_second,
        );

        let Some(new_in_flight) = hop.in_flight_bytes.checked_add(encoded_bytes) else {
            return TryReserve::Wait(Duration::from_millis(10));
        };
        if new_in_flight > self.max_in_flight_bytes {
            return TryReserve::Wait(Duration::from_millis(100));
        }
        if hop.rate_tokens < encoded_bytes as f64 {
            let missing = encoded_bytes as f64 - hop.rate_tokens;
            let seconds = missing / self.rate_bytes_per_second as f64;
            return TryReserve::Wait(
                Duration::from_secs_f64(seconds).max(Duration::from_millis(1)),
            );
        }

        hop.in_flight_bytes = new_in_flight;
        hop.rate_tokens -= encoded_bytes as f64;
        let id = state.next_reservation_id();
        state.reservations.insert(
            id,
            ReservationRecord {
                key: key.clone(),
                next_hop,
                bytes: encoded_bytes,
                retained: false,
            },
        );
        state.outstanding_by_key.insert(key, id);
        metrics::record_strict_catchup_bulk_in_flight_bytes_delta(encoded_bytes as isize);
        TryReserve::Admitted(BulkReservation {
            pacer: Arc::clone(self),
            id,
            release_on_drop: true,
        })
    }

    /// Release an outstanding page after an authenticated continuation or
    /// final acknowledgement has passed protocol validation.
    pub(super) fn acknowledge(
        &self,
        destination: NodeIdentifier,
        topic: &str,
        page: BulkPageIdentity,
    ) {
        let key = LogicalPageKey {
            destination,
            topic: topic.to_owned(),
            page,
        };
        let mut state = self.state.lock();
        if let Some(id) = state.outstanding_by_key.get(&key).copied() {
            // A delayed ACK must not refund a newer page which is still in
            // the act of being enqueued. Protocol handlers call this method
            // only after validating transfer/nonce/cursor correlation.
            let retained = state
                .reservations
                .get(&id)
                .is_some_and(|record| record.retained);
            if retained {
                Self::release_locked(&mut state, id);
                self.changed.notify_waiters();
            }
        }
    }

    /// Unconditionally release a page when its route/incarnation is no
    /// longer usable, including an enqueue currently in progress.
    pub(super) fn cancel(&self, destination: NodeIdentifier, topic: &str) {
        let mut state = self.state.lock();
        let ids: Vec<_> = state
            .outstanding_by_key
            .iter()
            .filter_map(|(key, id)| {
                (key.destination == destination && key.topic == topic).then_some(*id)
            })
            .collect();
        let mut released = false;
        for id in ids {
            released |= Self::release_locked(&mut state, id);
        }
        if released {
            self.changed.notify_waiters();
        }
    }

    fn release(&self, id: u64) {
        let mut state = self.state.lock();
        if Self::release_locked(&mut state, id) {
            self.changed.notify_waiters();
        }
    }

    fn retain(&self, id: u64) -> bool {
        let mut state = self.state.lock();
        let Some(record) = state.reservations.get_mut(&id) else {
            return false;
        };
        record.retained = true;
        true
    }

    fn release_locked(state: &mut BulkPacerState, id: u64) -> bool {
        let Some(record) = state.reservations.remove(&id) else {
            return false;
        };
        if state.outstanding_by_key.get(&record.key) == Some(&id) {
            state.outstanding_by_key.remove(&record.key);
        }
        if let Some(hop) = state.hops.get_mut(&record.next_hop) {
            hop.in_flight_bytes = hop.in_flight_bytes.saturating_sub(record.bytes);
        }
        metrics::record_strict_catchup_bulk_in_flight_bytes_delta(-(record.bytes as isize));
        true
    }
}

impl BulkPacerState {
    fn entry_or_insert_hop(
        &mut self,
        next_hop: NodeIdentifier,
        initial_tokens: usize,
        now: Instant,
    ) -> &mut HopBudget {
        self.hops.entry(next_hop).or_insert(HopBudget {
            in_flight_bytes: 0,
            rate_tokens: initial_tokens as f64,
            last_refill: now,
        })
    }

    fn next_reservation_id(&mut self) -> u64 {
        loop {
            self.next_id = self.next_id.wrapping_add(1);
            if self.next_id != 0 && !self.reservations.contains_key(&self.next_id) {
                return self.next_id;
            }
        }
    }
}

fn refill_rate_tokens(
    hop: &mut HopBudget,
    now: Instant,
    burst_bytes: usize,
    rate_bytes_per_second: u64,
) {
    let elapsed = now.saturating_duration_since(hop.last_refill);
    hop.last_refill = now;
    hop.rate_tokens = (hop.rate_tokens + elapsed.as_secs_f64() * rate_bytes_per_second as f64)
        .min(burst_bytes as f64);
}

/// RAII protection for an admitted physical enqueue. A successful enqueue
/// retains the reservation until its continuation/ACK or the transfer TTL;
/// failed and cancelled attempts release immediately.
pub(super) struct BulkReservation {
    pacer: Arc<BulkPacer>,
    id: u64,
    release_on_drop: bool,
}

impl BulkReservation {
    pub(super) fn retain_until(mut self, ttl: Duration) {
        if !self.pacer.retain(self.id) {
            return;
        }
        self.release_on_drop = false;
        let pacer = Arc::clone(&self.pacer);
        let id = self.id;
        tokio::spawn(async move {
            sleep(ttl).await;
            pacer.release(id);
        });
    }
}

impl Drop for BulkReservation {
    fn drop(&mut self) {
        if self.release_on_drop {
            self.pacer.release(self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shared_first_hop_cap_applies_across_topics_and_destinations() {
        let pacer = BulkPacer::new(64 * 1024, 1024 * 1024 * 1024);
        for (destination, topic) in [(10, "a"), (11, "b"), (12, "c"), (13, "d")] {
            pacer
                .reserve(destination, topic, BulkPageIdentity::Legacy, 2, 16 * 1024)
                .await
                .expect("page should fit")
                .retain_until(Duration::from_secs(10));
        }

        let blocked = tokio::time::timeout(
            Duration::from_millis(20),
            pacer.reserve(14, "e", BulkPageIdentity::Legacy, 2, 16 * 1024),
        )
        .await;
        assert!(blocked.is_err(), "the fifth shared-hop page must wait");

        pacer.acknowledge(10, "a", BulkPageIdentity::Legacy);
        let fifth = tokio::time::timeout(
            Duration::from_millis(100),
            pacer.reserve(14, "e", BulkPageIdentity::Legacy, 2, 16 * 1024),
        )
        .await
        .expect("ACK should wake shared-hop admission")
        .expect("page should fit after refund");
        drop(fifth);
    }

    #[tokio::test]
    async fn one_frame_cannot_exceed_the_next_hop_cap() {
        let pacer = BulkPacer::new(1024, 1024);
        let result = pacer
            .reserve(10, "topic", BulkPageIdentity::Legacy, 2, 1025)
            .await;
        assert!(matches!(
            result,
            Err(BulkAdmissionError::FrameTooLarge {
                encoded_bytes: 1025,
                max_bytes: 1024,
            })
        ));
    }

    #[tokio::test]
    async fn delayed_terminal_ack_cannot_release_a_newer_page() {
        let pacer = BulkPacer::new(32 * 1024, 1024 * 1024 * 1024);
        let first = BulkPageIdentity::terminal(7, 101);
        let second = BulkPageIdentity::terminal(7, 102);

        pacer
            .reserve(10, "topic", first, 2, 8 * 1024)
            .await
            .expect("first page should fit")
            .retain_until(Duration::from_secs(10));
        pacer.acknowledge(10, "topic", first);
        pacer
            .reserve(10, "topic", second, 2, 12 * 1024)
            .await
            .expect("second page should fit")
            .retain_until(Duration::from_secs(10));

        pacer.acknowledge(10, "topic", first);
        let state = pacer.state.lock();
        let second_key = LogicalPageKey {
            destination: 10,
            topic: "topic".to_owned(),
            page: second,
        };
        let second_id = state
            .outstanding_by_key
            .get(&second_key)
            .expect("newer page must remain reserved");
        assert_eq!(
            state.reservations.get(second_id).map(|record| record.bytes),
            Some(12 * 1024)
        );
    }

    #[tokio::test]
    async fn delayed_history_ack_cannot_release_a_newer_page() {
        let pacer = BulkPacer::new(32 * 1024, 1024 * 1024 * 1024);
        let first = BulkPageIdentity::history(9, 201);
        let second = BulkPageIdentity::history(9, 202);

        pacer
            .reserve(10, "topic", first, 2, 8 * 1024)
            .await
            .expect("first page should fit")
            .retain_until(Duration::from_secs(10));
        pacer.acknowledge(10, "topic", first);
        pacer
            .reserve(10, "topic", second, 2, 12 * 1024)
            .await
            .expect("second page should fit")
            .retain_until(Duration::from_secs(10));

        pacer.acknowledge(10, "topic", first);
        let state = pacer.state.lock();
        let second_key = LogicalPageKey {
            destination: 10,
            topic: "topic".to_owned(),
            page: second,
        };
        assert!(state.outstanding_by_key.contains_key(&second_key));
    }
}
