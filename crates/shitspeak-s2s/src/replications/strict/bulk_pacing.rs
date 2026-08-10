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
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

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
    RecoveryTerminal {
        transfer_id: u64,
        request_nonce: u64,
    },
    RecoverySnapshot {
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

    pub(crate) fn recovery_terminal(transfer_id: u64, request_nonce: u64) -> Self {
        Self::RecoveryTerminal {
            transfer_id,
            request_nonce,
        }
    }

    pub(crate) fn recovery_snapshot(transfer_id: u64, request_nonce: u64) -> Self {
        Self::RecoverySnapshot {
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
    Busy {
        retry_after: Duration,
    },
    FrameTooLarge {
        encoded_bytes: usize,
        max_bytes: usize,
    },
}

/// Cross-topic, per-next-hop byte and rate scheduler.
pub(super) struct BulkPacer {
    max_in_flight_bytes: usize,
    rate_bytes_per_second: u64,
    shutdown: CancellationToken,
    state: Mutex<BulkPacerState>,
}

impl BulkPacer {
    pub(super) fn new(max_in_flight_bytes: usize, rate_bytes_per_second: u64) -> Arc<Self> {
        Self::new_with_shutdown(
            max_in_flight_bytes,
            rate_bytes_per_second,
            CancellationToken::new(),
        )
    }

    pub(super) fn new_with_shutdown(
        max_in_flight_bytes: usize,
        rate_bytes_per_second: u64,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            max_in_flight_bytes: max_in_flight_bytes.max(1),
            rate_bytes_per_second: rate_bytes_per_second.max(1),
            shutdown,
            state: Mutex::new(BulkPacerState::default()),
        })
    }

    /// Reserve the exact authenticated strict frame size against its current
    /// physical first hop. A retained replay of this exact protocol page is
    /// replaced here; reservations for earlier or later pages remain until
    /// their own correlated continuation, ACK, cancellation, or TTL.
    pub(super) fn try_reserve(
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
        if encoded_bytes > self.max_in_flight_bytes {
            return Err(BulkAdmissionError::FrameTooLarge {
                encoded_bytes,
                max_bytes: self.max_in_flight_bytes,
            });
        }

        let now = Instant::now();
        let mut state = self.state.lock();

        // The ordered overlay already owns a retained copy of this exact page.
        // Do not enqueue or account a duplicate: its physical retry is owned
        // by the overlay, while the requester keeps the correlated protocol
        // session alive until the page arrives.
        if state.outstanding_by_key.contains_key(&key) {
            return Ok(BulkReservation {
                pacer: Arc::clone(self),
                id: None,
                release_on_drop: false,
            });
        }

        let hop = state.entry_or_insert_hop(next_hop, self.max_in_flight_bytes, now);
        refill_rate_tokens(
            hop,
            now,
            self.max_in_flight_bytes,
            self.rate_bytes_per_second,
        );

        let Some(new_in_flight) = hop.in_flight_bytes.checked_add(encoded_bytes) else {
            return Err(BulkAdmissionError::Busy {
                retry_after: Duration::from_millis(10),
            });
        };
        if new_in_flight > self.max_in_flight_bytes {
            metrics::record_strict_catchup_throttled(StrictCatchupThrottleReason::NextHopBytes);
            return Err(BulkAdmissionError::Busy {
                retry_after: Duration::from_millis(100),
            });
        }
        if hop.rate_tokens < encoded_bytes as f64 {
            let missing = encoded_bytes as f64 - hop.rate_tokens;
            let seconds = missing / self.rate_bytes_per_second as f64;
            return Err(BulkAdmissionError::Busy {
                retry_after: Duration::from_secs_f64(seconds).max(Duration::from_millis(1)),
            });
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
            },
        );
        state.outstanding_by_key.insert(key, id);
        metrics::record_strict_catchup_bulk_in_flight_bytes_delta(encoded_bytes as isize);
        Ok(BulkReservation {
            pacer: Arc::clone(self),
            id: Some(id),
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
            // The logical key includes the exact transfer and request nonce,
            // so it cannot name a newer page. The receiver may authenticate
            // the page before the transport send future returns; release that
            // in-progress reservation now. A later retain/drop observes that
            // the id is gone and safely becomes a no-op.
            Self::release_locked(&mut state, id);
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
        for id in ids {
            Self::release_locked(&mut state, id);
        }
    }

    fn release(&self, id: u64) {
        let mut state = self.state.lock();
        Self::release_locked(&mut state, id);
    }

    fn retain(&self, id: u64) -> bool {
        self.state.lock().reservations.contains_key(&id)
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
    id: Option<u64>,
    release_on_drop: bool,
}

impl BulkReservation {
    pub(super) fn is_coalesced(&self) -> bool {
        self.id.is_none()
    }

    pub(super) fn retain_until(mut self, ttl: Duration) {
        let Some(id) = self.id else {
            return;
        };
        if !self.pacer.retain(id) {
            return;
        }
        self.release_on_drop = false;
        let pacer = Arc::clone(&self.pacer);
        let shutdown = pacer.shutdown.clone();
        tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {}
                _ = sleep(ttl) => {}
            }
            pacer.release(id);
        });
    }
}

impl Drop for BulkReservation {
    fn drop(&mut self) {
        if self.release_on_drop
            && let Some(id) = self.id
        {
            self.pacer.release(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shared_first_hop_cap_returns_busy_without_blocking() {
        let pacer = BulkPacer::new(64 * 1024, 1024 * 1024 * 1024);
        for (destination, topic) in [(10, "a"), (11, "b"), (12, "c"), (13, "d")] {
            pacer
                .try_reserve(destination, topic, BulkPageIdentity::Legacy, 2, 16 * 1024)
                .expect("page should fit")
                .retain_until(Duration::from_secs(10));
        }

        let busy = pacer.try_reserve(14, "e", BulkPageIdentity::Legacy, 2, 16 * 1024);
        assert!(matches!(busy, Err(BulkAdmissionError::Busy { .. })));

        pacer.acknowledge(10, "a", BulkPageIdentity::Legacy);
        let fifth = pacer
            .try_reserve(14, "e", BulkPageIdentity::Legacy, 2, 16 * 1024)
            .expect("page should fit after refund");
        drop(fifth);
    }

    #[tokio::test]
    async fn retained_exact_page_retry_coalesces_instead_of_reporting_backpressure() {
        let pacer = BulkPacer::new(64 * 1024, 1024 * 1024 * 1024);
        let page = BulkPageIdentity::recovery_terminal(17, 91);
        pacer
            .try_reserve(10, "topic", page, 2, 16 * 1024)
            .expect("first page should reserve")
            .retain_until(Duration::from_secs(10));

        let replay = pacer
            .try_reserve(10, "topic", page, 2, 16 * 1024)
            .expect("an exact retained replay must coalesce");
        assert!(
            replay.is_coalesced(),
            "an exact retained replay is already in flight and must coalesce as success"
        );
    }

    #[tokio::test]
    async fn authenticated_ack_before_send_retain_releases_the_exact_in_progress_reservation() {
        let pacer = BulkPacer::new(8 * 1024, 1024 * 1024 * 1024);
        let page = BulkPageIdentity::recovery_terminal(17, 91);
        let reservation = pacer
            .try_reserve(10, "topic", page, 2, 8 * 1024)
            .expect("page should reserve the full hop budget");

        // A loopback-fast receiver can authenticate and ACK the page while
        // the transport send future is still returning to retain it.
        pacer.acknowledge(10, "topic", page);
        reservation.retain_until(Duration::from_secs(10));

        let replacement = pacer
            .try_reserve(
                10,
                "topic",
                BulkPageIdentity::recovery_terminal(17, 92),
                2,
                8 * 1024,
            )
            .expect("the early ACK must make the full budget immediately reusable");
        {
            let state = pacer.state.lock();
            assert_eq!(state.reservations.len(), 1);
            assert_eq!(
                state.hops.get(&2).map(|hop| hop.in_flight_bytes),
                Some(8 * 1024)
            );
            assert!(!state.outstanding_by_key.contains_key(&LogicalPageKey {
                destination: 10,
                topic: "topic".to_owned(),
                page,
            }));
        }
        let _replacement = replacement;
    }

    #[tokio::test]
    async fn shutdown_releases_retained_pages_without_waiting_for_ttl() {
        let shutdown = CancellationToken::new();
        let pacer = BulkPacer::new_with_shutdown(8 * 1024, 1024 * 1024 * 1024, shutdown.clone());
        pacer
            .try_reserve(
                10,
                "topic",
                BulkPageIdentity::recovery_terminal(17, 91),
                2,
                8 * 1024,
            )
            .expect("page should reserve")
            .retain_until(Duration::from_secs(60));

        shutdown.cancel();
        for _ in 0..16 {
            if pacer.state.lock().reservations.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            pacer.state.lock().reservations.is_empty(),
            "shutdown must cancel TTL waits and release bulk gauges before runtime teardown"
        );
    }

    #[test]
    fn one_frame_cannot_exceed_the_next_hop_cap() {
        let pacer = BulkPacer::new(1024, 1024);
        let result = pacer.try_reserve(10, "topic", BulkPageIdentity::Legacy, 2, 1025);
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
            .try_reserve(10, "topic", first, 2, 8 * 1024)
            .expect("first page should fit")
            .retain_until(Duration::from_secs(10));
        pacer.acknowledge(10, "topic", first);
        pacer
            .try_reserve(10, "topic", second, 2, 12 * 1024)
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
            .try_reserve(10, "topic", first, 2, 8 * 1024)
            .expect("first page should fit")
            .retain_until(Duration::from_secs(10));
        pacer.acknowledge(10, "topic", first);
        pacer
            .try_reserve(10, "topic", second, 2, 12 * 1024)
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
