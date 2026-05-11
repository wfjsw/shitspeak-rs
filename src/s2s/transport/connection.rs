//! Per-peer state held by the supervisor.
//!
//! The supervisor owns one `PeerState` per known peer; that struct contains
//! the dial address book, the set of currently-active streams (one per
//! transport flavor), reconnect backoff, and aggregated metrics.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::types::NodeIdentifier;

use super::metrics::{MetricsTuning, PeerMetrics};
use super::service_level::{MessageClass, PeerAddress, TransportKind};

/// One outbound frame, addressed to a specific stream.
#[derive(Debug, Clone)]
pub(crate) struct OutboundFrame {
    class: MessageClass,
    payload: Bytes,
}

impl OutboundFrame {
    pub fn new(class: MessageClass, payload: Bytes) -> Self {
        Self { class, payload }
    }

    pub fn class(&self) -> MessageClass {
        self.class
    }

    pub fn payload(&self) -> &Bytes {
        &self.payload
    }
}

/// Sender-side handle to a single live stream connection.
pub(crate) struct ActiveStream {
    transport: TransportKind,
    sender: mpsc::Sender<OutboundFrame>,
    closed: CancellationToken,
}

impl ActiveStream {
    pub fn new(
        transport: TransportKind,
        sender: mpsc::Sender<OutboundFrame>,
        closed: CancellationToken,
    ) -> Self {
        Self {
            transport,
            sender,
            closed,
        }
    }

    pub fn transport(&self) -> TransportKind {
        self.transport
    }

    pub fn is_alive(&self) -> bool {
        !self.closed.is_cancelled() && !self.sender.is_closed()
    }

    pub fn cancel(&self) {
        self.closed.cancel();
    }
}

#[derive(Debug)]
pub(crate) struct BackoffState {
    initial: Duration,
    cap: Duration,
    next_delay: Duration,
    last_attempt: Option<Instant>,
    consecutive_failures: u32,
}

impl BackoffState {
    pub fn new(initial: Duration, cap: Duration) -> Self {
        Self {
            initial,
            cap,
            next_delay: initial,
            last_attempt: None,
            consecutive_failures: 0,
        }
    }

    pub fn ready(&self, now: Instant) -> bool {
        match self.last_attempt {
            None => true,
            Some(at) => now.duration_since(at) >= self.next_delay,
        }
    }

    pub fn record_attempt(&mut self) {
        self.last_attempt = Some(Instant::now());
    }

    pub fn record_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let doubled = self.next_delay.saturating_mul(2);
        self.next_delay = if doubled > self.cap {
            self.cap
        } else {
            doubled
        };
    }

    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.next_delay = self.initial;
    }
}

/// Aggregate state for one peer. The supervisor mutates this through `Mutex`
/// guards held briefly across non-blocking work.
pub(crate) struct PeerState {
    node_id: NodeIdentifier,
    addresses: Mutex<Vec<PeerAddress>>,
    streams: Mutex<HashMap<TransportKind, ActiveStream>>,
    udp_seen_at: Mutex<Option<Instant>>,
    udp_addr: Mutex<Option<std::net::SocketAddr>>,
    metrics: Arc<PeerMetrics>,
    backoff: Mutex<BackoffState>,
    outbound_seq: AtomicU32,
    /// Set true while a connect attempt is in flight, to prevent duplicate
    /// dials racing inside the supervisor.
    connecting: AtomicBool,
}

impl PeerState {
    pub fn new(
        node_id: NodeIdentifier,
        backoff_initial: Duration,
        backoff_cap: Duration,
        bandwidth_window: Duration,
        metrics_tuning: MetricsTuning,
    ) -> Arc<Self> {
        Arc::new(Self {
            node_id,
            addresses: Mutex::new(Vec::new()),
            streams: Mutex::new(HashMap::new()),
            udp_seen_at: Mutex::new(None),
            udp_addr: Mutex::new(None),
            metrics: Arc::new(PeerMetrics::new(bandwidth_window, metrics_tuning)),
            backoff: Mutex::new(BackoffState::new(backoff_initial, backoff_cap)),
            outbound_seq: AtomicU32::new(0),
            connecting: AtomicBool::new(false),
        })
    }

    pub fn node_id(&self) -> NodeIdentifier {
        self.node_id
    }

    pub fn metrics(&self) -> &Arc<PeerMetrics> {
        &self.metrics
    }

    pub fn backoff(&self) -> &Mutex<BackoffState> {
        &self.backoff
    }

    /// Atomically claim the connect slot. Returns `true` if this caller now
    /// owns the in-flight dial; `false` if another task already had it.
    pub fn try_begin_connect(&self) -> bool {
        self.connecting
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Release the connect slot previously claimed via `try_begin_connect`.
    pub fn end_connect(&self) {
        self.connecting.store(false, Ordering::SeqCst);
    }

    pub fn next_seq(&self) -> u32 {
        self.outbound_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Add an address if it isn't already known. Returns true if newly added.
    pub fn add_address(&self, addr: PeerAddress) -> bool {
        let mut g = self.addresses.lock();
        if g.contains(&addr) {
            return false;
        }
        g.push(addr);
        true
    }

    pub fn remove_address(&self, addr: PeerAddress) {
        let mut g = self.addresses.lock();
        g.retain(|a| *a != addr);
    }

    pub fn snapshot_addresses(&self) -> Vec<PeerAddress> {
        self.addresses.lock().clone()
    }

    pub fn install_stream(&self, stream: ActiveStream) {
        let kind = stream.transport;
        let mut g = self.streams.lock();
        if let Some(prev) = g.insert(kind, stream) {
            prev.closed.cancel();
        }
    }

    /// Install with simultaneous-dial tiebreaker. Returns `Err(stream)` if the
    /// caller should discard the new stream (the existing one wins).
    ///
    /// Convention: when both sides race a connection of the same `kind`, the
    /// lower-numbered node keeps its dial-side stream, the higher-numbered
    /// node keeps its accept-side stream. Both sides converge on the same
    /// physical connection.
    pub fn try_install_stream(
        &self,
        self_id: NodeIdentifier,
        is_dialer: bool,
        new_stream: ActiveStream,
    ) -> Result<(), ActiveStream> {
        let kind = new_stream.transport;
        let mut g = self.streams.lock();
        if let Some(existing) = g.get(&kind) {
            if existing.is_alive() {
                let prefer_dialer = self_id < self.node_id;
                let new_is_preferred = is_dialer == prefer_dialer;
                if !new_is_preferred {
                    return Err(new_stream);
                }
            }
        }
        if let Some(prev) = g.insert(kind, new_stream) {
            prev.closed.cancel();
        }
        Ok(())
    }

    pub fn drop_stream(&self, kind: TransportKind) {
        let mut g = self.streams.lock();
        if let Some(prev) = g.remove(&kind) {
            prev.closed.cancel();
        }
    }

    pub fn live_kinds(&self) -> Vec<TransportKind> {
        self.streams
            .lock()
            .iter()
            .filter(|(_, s)| s.is_alive())
            .map(|(k, _)| *k)
            .collect()
    }

    /// Attempt to obtain a sender for any stream of the requested transport.
    /// Drops the stream if it has died.
    pub fn try_get_stream(&self, kind: TransportKind) -> Option<mpsc::Sender<OutboundFrame>> {
        let mut g = self.streams.lock();
        if let Some(s) = g.get(&kind) {
            if s.is_alive() {
                return Some(s.sender.clone());
            }
            let dead = g.remove(&kind);
            if let Some(d) = dead {
                d.closed.cancel();
            }
        }
        None
    }

    pub fn has_any_live_stream(&self) -> bool {
        self.streams.lock().values().any(|s| s.is_alive())
    }

    pub fn note_udp_seen(&self, addr: std::net::SocketAddr) {
        *self.udp_seen_at.lock() = Some(Instant::now());
        *self.udp_addr.lock() = Some(addr);
    }

    pub fn udp_addr(&self) -> Option<std::net::SocketAddr> {
        *self.udp_addr.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_then_caps() {
        let mut b = BackoffState::new(Duration::from_millis(250), Duration::from_secs(2));
        assert_eq!(b.next_delay, Duration::from_millis(250));
        b.record_failure();
        assert_eq!(b.next_delay, Duration::from_millis(500));
        b.record_failure();
        assert_eq!(b.next_delay, Duration::from_secs(1));
        b.record_failure();
        assert_eq!(b.next_delay, Duration::from_secs(2));
        b.record_failure();
        assert_eq!(b.next_delay, Duration::from_secs(2));
        b.record_success();
        assert_eq!(b.next_delay, Duration::from_millis(250));
        assert_eq!(b.consecutive_failures, 0);
    }
}
