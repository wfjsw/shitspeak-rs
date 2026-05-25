//! Per-peer state held by the supervisor.
//!
//! The supervisor owns one `PeerState` per known peer; that struct contains
//! the dial address book, the set of currently-active streams, reconnect
//! backoff, and aggregated metrics.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use parking_lot::Mutex;
use rand::RngExt;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::types::NodeIdentifier;

use super::SendOptions;
use super::metrics::{MetricsTuning, PeerMetrics};
use super::service_level::{MessageClass, PeerAddress, TransportKind};

const MAX_OBSERVED_REMOTE_IPS: usize = 8;
const BACKOFF_JITTER_DIVISOR: u64 = 5;

/// One outbound frame, addressed to a specific stream.
#[derive(Debug, Clone)]
pub(crate) struct OutboundFrame {
    class: MessageClass,
    payload: Bytes,
    options: SendOptions,
}

impl OutboundFrame {
    pub fn new(class: MessageClass, payload: Bytes) -> Self {
        Self::with_options(class, payload, SendOptions::default())
    }

    pub fn with_options(class: MessageClass, payload: Bytes, options: SendOptions) -> Self {
        Self {
            class,
            payload,
            options,
        }
    }

    pub fn class(&self) -> MessageClass {
        self.class
    }

    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    pub fn options(&self) -> SendOptions {
        self.options
    }
}

/// Sender-side handle to a single live stream connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct StreamKey {
    transport: TransportKind,
    remote_addr: Option<SocketAddr>,
    is_dialer: bool,
}

impl StreamKey {
    pub fn new(transport: TransportKind, remote_addr: Option<SocketAddr>, is_dialer: bool) -> Self {
        Self {
            transport,
            remote_addr,
            is_dialer,
        }
    }

    pub fn transport(&self) -> TransportKind {
        self.transport
    }
}

pub(crate) struct ActiveStream {
    transport: TransportKind,
    remote_addr: Option<SocketAddr>,
    sender: mpsc::Sender<OutboundFrame>,
    closed: CancellationToken,
    is_dialer: bool,
    installed_at: Instant,
}

impl ActiveStream {
    pub fn new(
        transport: TransportKind,
        remote_addr: Option<SocketAddr>,
        sender: mpsc::Sender<OutboundFrame>,
        closed: CancellationToken,
        is_dialer: bool,
    ) -> Self {
        Self {
            transport,
            remote_addr,
            sender,
            closed,
            is_dialer,
            installed_at: Instant::now(),
        }
    }

    pub fn transport(&self) -> TransportKind {
        self.transport
    }

    pub fn is_alive(&self) -> bool {
        !self.closed.is_cancelled() && !self.sender.is_closed()
    }

    pub fn is_dialer(&self) -> bool {
        self.is_dialer
    }

    pub fn installed_at(&self) -> Instant {
        self.installed_at
    }

    pub fn key(&self) -> StreamKey {
        StreamKey::new(self.transport, self.remote_addr, self.is_dialer)
    }

    pub fn cancel(&self) {
        self.closed.cancel();
    }
}

#[derive(Debug)]
pub(crate) struct BackoffState {
    initial: Duration,
    next_delay: Duration,
    retry_delay: Duration,
    last_attempt: Option<Instant>,
    consecutive_failures: u32,
}

impl BackoffState {
    pub fn new(initial: Duration) -> Self {
        Self {
            initial,
            next_delay: initial,
            retry_delay: initial,
            last_attempt: None,
            consecutive_failures: 0,
        }
    }

    pub fn ready(&self, now: Instant, retry_cap: Duration) -> bool {
        let effective_delay = self.retry_delay.min(retry_cap);
        match self.last_attempt {
            None => true,
            Some(at) => now.duration_since(at) >= effective_delay,
        }
    }

    pub fn record_attempt(&mut self) {
        self.last_attempt = Some(Instant::now());
    }

    pub fn record_failure(&mut self, retry_cap: Duration) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let doubled = self.next_delay.saturating_mul(2);
        self.next_delay = if doubled > retry_cap {
            retry_cap
        } else {
            doubled
        };
        self.retry_delay = jittered_delay(self.next_delay.min(retry_cap), retry_cap);
        self.last_attempt = Some(Instant::now());
    }

    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.next_delay = self.initial;
        self.retry_delay = self.initial;
    }
}

fn jittered_delay(base: Duration, cap: Duration) -> Duration {
    let base_nanos = base.as_nanos().min(u64::MAX as u128) as u64;
    let cap_nanos = cap.as_nanos().min(u64::MAX as u128) as u64;
    let jitter_window = base_nanos / BACKOFF_JITTER_DIVISOR;
    if jitter_window == 0 {
        return base;
    }
    let low = base_nanos.saturating_sub(jitter_window);
    let high = base_nanos
        .saturating_add(jitter_window)
        .min(cap_nanos.max(low));
    Duration::from_nanos(rand::rng().random_range(low..=high))
}

/// Aggregate state for one peer. The supervisor mutates this through `Mutex`
/// guards held briefly across non-blocking work.
pub(crate) struct PeerState {
    node_id: NodeIdentifier,
    addresses: Mutex<Vec<PeerAddress>>,
    streams: Mutex<HashMap<StreamKey, ActiveStream>>,
    udp_seen_at: Mutex<Option<Instant>>,
    udp_addr: Mutex<Option<std::net::SocketAddr>>,
    /// Authenticated inbound remote IPs by transport. Source ports are often
    /// ephemeral; IPs are combined only with same-transport service ports.
    observed_remote_ips: Mutex<HashMap<TransportKind, Vec<std::net::IpAddr>>>,
    last_seen_wall: Mutex<Option<SystemTime>>,
    metrics: Arc<PeerMetrics>,
    backoff_initial: Duration,
    address_backoffs: Mutex<HashMap<PeerAddress, BackoffState>>,
    /// Set true while a connect attempt is in flight, to prevent duplicate
    /// dials racing inside the supervisor.
    connecting: AtomicBool,
}

impl PeerState {
    pub fn new(
        node_id: NodeIdentifier,
        backoff_initial: Duration,
        bandwidth_window: Duration,
        metrics_tuning: MetricsTuning,
    ) -> Arc<Self> {
        Arc::new(Self {
            node_id,
            addresses: Mutex::new(Vec::new()),
            streams: Mutex::new(HashMap::new()),
            udp_seen_at: Mutex::new(None),
            udp_addr: Mutex::new(None),
            observed_remote_ips: Mutex::new(HashMap::new()),
            last_seen_wall: Mutex::new(None),
            metrics: Arc::new(PeerMetrics::new(bandwidth_window, metrics_tuning)),
            backoff_initial,
            address_backoffs: Mutex::new(HashMap::new()),
            connecting: AtomicBool::new(false),
        })
    }

    pub fn node_id(&self) -> NodeIdentifier {
        self.node_id
    }

    pub fn metrics(&self) -> &Arc<PeerMetrics> {
        &self.metrics
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

    /// Add an address if it isn't already known. Returns true if newly added.
    pub fn add_address(&self, addr: PeerAddress) -> bool {
        self.note_seen_now();
        let mut g = self.addresses.lock();
        if g.contains(&addr) {
            return false;
        }
        g.push(addr);
        self.ensure_address_backoff(addr);
        true
    }

    /// Add an address while preserving an externally observed last-seen time,
    /// such as one loaded from disk.
    pub fn add_address_seen_at(&self, addr: PeerAddress, seen_at: SystemTime) -> bool {
        self.note_seen_at(seen_at);
        let mut g = self.addresses.lock();
        if g.contains(&addr) {
            return false;
        }
        g.push(addr);
        self.ensure_address_backoff(addr);
        true
    }

    fn ensure_address_backoff(&self, addr: PeerAddress) {
        self.address_backoffs
            .lock()
            .entry(addr)
            .or_insert_with(|| BackoffState::new(self.backoff_initial));
    }

    pub fn address_retry_ready(
        &self,
        addr: PeerAddress,
        now: Instant,
        retry_cap: Duration,
    ) -> bool {
        self.address_backoffs
            .lock()
            .get(&addr)
            .is_none_or(|backoff| backoff.ready(now, retry_cap))
    }

    pub fn record_address_attempt(&self, addr: PeerAddress) {
        self.address_backoffs
            .lock()
            .entry(addr)
            .or_insert_with(|| BackoffState::new(self.backoff_initial))
            .record_attempt();
    }

    pub fn record_address_failure(&self, addr: PeerAddress, retry_cap: Duration) {
        self.address_backoffs
            .lock()
            .entry(addr)
            .or_insert_with(|| BackoffState::new(self.backoff_initial))
            .record_failure(retry_cap);
    }

    pub fn record_address_success(&self, addr: PeerAddress) {
        self.address_backoffs
            .lock()
            .entry(addr)
            .or_insert_with(|| BackoffState::new(self.backoff_initial))
            .record_success();
    }

    pub fn note_observed_remote_addr(&self, transport: TransportKind, addr: std::net::SocketAddr) {
        let ip = addr.ip();
        if ip_looks_unusable(ip) {
            return;
        }
        let mut observed_by_transport = self.observed_remote_ips.lock();
        let observed = observed_by_transport.entry(transport).or_default();
        if let Some(pos) = observed.iter().position(|candidate| *candidate == ip) {
            observed.remove(pos);
        }
        observed.push(ip);
        if observed.len() > MAX_OBSERVED_REMOTE_IPS {
            observed.remove(0);
        }
        self.note_seen_now();
    }

    pub fn address_candidates(&self, addr: PeerAddress) -> Vec<PeerAddress> {
        let published = addr.addr();
        let observed = self
            .observed_remote_ips
            .lock()
            .get(&addr.transport())
            .cloned()
            .unwrap_or_default();
        let mut candidates = Vec::new();

        if published_ip_looks_usable(published.ip()) {
            push_unique_candidate(&mut candidates, addr);
        }

        for observed_ip in observed {
            if should_add_observed_candidate(published.ip(), observed_ip) {
                push_unique_candidate(
                    &mut candidates,
                    PeerAddress::new(
                        std::net::SocketAddr::new(observed_ip, published.port()),
                        addr.transport(),
                    ),
                );
            }
        }

        candidates
    }

    pub fn confirm_address(&self, addr: PeerAddress) {
        let mut g = self.addresses.lock();
        if let Some(pos) = g.iter().position(|candidate| *candidate == addr) {
            let addr = g.remove(pos);
            g.insert(0, addr);
        } else {
            g.insert(0, addr);
        }
        self.ensure_address_backoff(addr);
    }

    pub fn note_seen_now(&self) {
        self.note_seen_at(SystemTime::now());
    }

    pub fn note_seen_at(&self, seen_at: SystemTime) {
        let mut g = self.last_seen_wall.lock();
        if g.is_none_or(|prev| seen_at > prev) {
            *g = Some(seen_at);
        }
    }

    pub fn last_seen(&self) -> Option<SystemTime> {
        *self.last_seen_wall.lock()
    }

    pub fn last_seen_age(&self, now: SystemTime) -> Option<Duration> {
        self.last_seen().map(|seen| {
            now.duration_since(seen)
                .unwrap_or_else(|_| Duration::from_secs(0))
        })
    }

    pub fn remove_address(&self, addr: PeerAddress) -> bool {
        let mut g = self.addresses.lock();
        let before = g.len();
        g.retain(|a| *a != addr);
        let removed = g.len() != before;
        drop(g);
        if removed {
            self.address_backoffs.lock().remove(&addr);
        }
        removed
    }

    pub fn snapshot_addresses(&self) -> Vec<PeerAddress> {
        self.addresses.lock().clone()
    }

    pub fn install_stream(&self, stream: ActiveStream) {
        let key = stream.key();
        let mut g = self.streams.lock();
        prune_dead_streams(&mut g);
        if stream.transport() == TransportKind::Udp {
            drop_udp_streams(&mut g);
        }
        if let Some(prev) = g.insert(key, stream) {
            prev.closed.cancel();
        }
        self.note_seen_now();
    }

    /// Install a stream unless the exact same connection key is already live.
    pub fn try_install_stream(&self, new_stream: ActiveStream) -> Result<(), ActiveStream> {
        let key = new_stream.key();
        let mut g = self.streams.lock();
        prune_dead_streams(&mut g);
        if new_stream.transport() == TransportKind::Udp {
            drop_udp_streams(&mut g);
        }
        if g.get(&key).is_some_and(ActiveStream::is_alive) {
            return Err(new_stream);
        }
        if let Some(prev) = g.insert(key, new_stream) {
            prev.closed.cancel();
        }
        self.note_seen_now();
        Ok(())
    }

    pub fn drop_stream(&self, kind: TransportKind) {
        let mut g = self.streams.lock();
        g.retain(|key, stream| {
            if key.transport() == kind {
                stream.cancel();
                false
            } else {
                true
            }
        });
    }

    pub fn has_live_outgoing_to(&self, addr: PeerAddress) -> bool {
        let key = StreamKey::new(addr.transport(), Some(addr.addr()), true);
        let mut g = self.streams.lock();
        prune_dead_streams(&mut g);
        if addr.transport() == TransportKind::Udp {
            return g
                .values()
                .any(|stream| stream.transport == TransportKind::Udp && stream.is_alive());
        }
        g.get(&key).is_some_and(ActiveStream::is_alive)
    }

    pub fn live_kinds(&self) -> Vec<TransportKind> {
        let mut g = self.streams.lock();
        prune_dead_streams(&mut g);
        let mut kinds = Vec::new();
        for stream in g.values() {
            if stream.is_alive() && !kinds.contains(&stream.transport()) {
                kinds.push(stream.transport());
            }
        }
        kinds
    }

    /// Attempt to obtain a sender for any stream of the requested transport.
    /// Drops the stream if it has died.
    pub fn try_get_stream(&self, kind: TransportKind) -> Option<mpsc::Sender<OutboundFrame>> {
        let mut g = self.streams.lock();
        prune_dead_streams(&mut g);
        g.values()
            .filter(|s| s.transport() == kind && s.is_alive())
            .max_by_key(|s| s.installed_at())
            .map(|s| s.sender.clone())
    }

    pub fn has_any_live_stream(&self) -> bool {
        let mut g = self.streams.lock();
        prune_dead_streams(&mut g);
        g.values().any(ActiveStream::is_alive)
    }

    pub fn outgoing_live_count(&self) -> usize {
        let mut g = self.streams.lock();
        prune_dead_streams(&mut g);
        g.values().filter(|s| s.is_alive() && s.is_dialer()).count()
    }

    pub fn outgoing_live_keys(&self) -> Vec<StreamKey> {
        let mut g = self.streams.lock();
        prune_dead_streams(&mut g);
        g.iter()
            .filter_map(|(key, stream)| {
                if stream.is_alive() && stream.is_dialer() {
                    Some(*key)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn drop_outgoing_stream(&self, key: StreamKey) -> bool {
        let mut g = self.streams.lock();
        if let Some(prev) = g.remove(&key) {
            prev.closed.cancel();
            true
        } else {
            false
        }
    }

    pub fn note_udp_seen(&self, addr: std::net::SocketAddr) {
        *self.udp_seen_at.lock() = Some(Instant::now());
        *self.udp_addr.lock() = Some(addr);
        self.note_observed_remote_addr(TransportKind::Udp, addr);
    }

    pub fn udp_addr(&self) -> Option<std::net::SocketAddr> {
        *self.udp_addr.lock()
    }
}

fn prune_dead_streams(streams: &mut HashMap<StreamKey, ActiveStream>) {
    streams.retain(|_, stream| {
        if stream.is_alive() {
            true
        } else {
            stream.cancel();
            false
        }
    });
}

fn drop_udp_streams(streams: &mut HashMap<StreamKey, ActiveStream>) {
    streams.retain(|key, stream| {
        if key.transport() == TransportKind::Udp {
            stream.cancel();
            false
        } else {
            true
        }
    });
}

fn push_unique_candidate(candidates: &mut Vec<PeerAddress>, addr: PeerAddress) {
    if addr.is_dialable() && !candidates.contains(&addr) {
        candidates.push(addr);
    }
}

fn published_ip_looks_usable(published: std::net::IpAddr) -> bool {
    !ip_looks_unusable(published)
}

fn should_add_observed_candidate(published: std::net::IpAddr, observed: std::net::IpAddr) -> bool {
    // Never add an observed IP that cannot be dialed.
    if ip_looks_unusable(observed) || observed == published {
        return false;
    }
    true
}

fn ip_looks_unusable(ip: std::net::IpAddr) -> bool {
    ip.is_unspecified() || ip.is_multicast()
}

pub(crate) fn retry_cap_for_last_seen_age(
    last_seen_age: Option<Duration>,
    recent_cap: Duration,
    stale_cap: Duration,
    stale_after: Duration,
) -> Duration {
    let Some(age) = last_seen_age else {
        return stale_cap.max(recent_cap);
    };
    if age >= stale_after || stale_after.is_zero() {
        return stale_cap.max(recent_cap);
    }

    let recent_ms = recent_cap.as_millis();
    let stale_ms = stale_cap.max(recent_cap).as_millis();
    let span_ms = stale_after.as_millis().max(1);
    let age_ms = age.as_millis().min(span_ms);
    let interpolated = recent_ms + ((stale_ms - recent_ms) * age_ms / span_ms);
    Duration::from_millis(interpolated.min(u64::MAX as u128) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_then_caps() {
        let mut b = BackoffState::new(Duration::from_millis(250));
        assert_eq!(b.next_delay, Duration::from_millis(250));
        b.record_failure(Duration::from_secs(2));
        assert_eq!(b.next_delay, Duration::from_millis(500));
        b.record_failure(Duration::from_secs(2));
        assert_eq!(b.next_delay, Duration::from_secs(1));
        b.record_failure(Duration::from_secs(2));
        assert_eq!(b.next_delay, Duration::from_secs(2));
        b.record_failure(Duration::from_secs(2));
        assert_eq!(b.next_delay, Duration::from_secs(2));
        b.record_success();
        assert_eq!(b.next_delay, Duration::from_millis(250));
        assert_eq!(b.consecutive_failures, 0);
    }

    #[test]
    fn backoff_jitters_retry_delay_within_bounds() {
        let mut b = BackoffState::new(Duration::from_millis(250));

        b.record_failure(Duration::from_secs(2));

        assert!(b.retry_delay >= Duration::from_millis(400));
        assert!(b.retry_delay <= Duration::from_millis(600));
    }

    #[test]
    fn backoff_jitters_capped_retry_delay_within_cap() {
        let mut b = BackoffState::new(Duration::from_millis(250));

        b.record_failure(Duration::from_millis(500));

        assert!(b.retry_delay >= Duration::from_millis(400));
        assert!(b.retry_delay <= Duration::from_millis(500));
    }

    #[test]
    fn backoff_waits_from_failure_completion() {
        let mut b = BackoffState::new(Duration::from_millis(250));
        b.record_attempt();
        b.last_attempt = Some(Instant::now() - Duration::from_secs(60));

        b.record_failure(Duration::from_secs(30));
        let last_attempt = b.last_attempt.unwrap();
        let retry_delay = b.retry_delay;

        assert!(!b.ready(
            last_attempt + retry_delay.saturating_sub(Duration::from_nanos(1)),
            Duration::from_secs(30)
        ));
        assert!(b.ready(last_attempt + retry_delay, Duration::from_secs(30)));
    }

    #[test]
    fn retry_cap_grows_with_last_seen_age() {
        let recent = Duration::from_secs(30);
        let stale = Duration::from_secs(600);
        let stale_after = Duration::from_secs(60);

        assert_eq!(
            retry_cap_for_last_seen_age(Some(Duration::ZERO), recent, stale, stale_after),
            recent
        );
        assert_eq!(
            retry_cap_for_last_seen_age(Some(Duration::from_secs(60)), recent, stale, stale_after),
            stale
        );
        assert_eq!(
            retry_cap_for_last_seen_age(None, recent, stale, stale_after),
            stale
        );
        let mid =
            retry_cap_for_last_seen_age(Some(Duration::from_secs(30)), recent, stale, stale_after);
        assert!(mid > recent);
        assert!(mid < stale);
    }

    fn peer_for_address_tests() -> Arc<PeerState> {
        PeerState::new(
            2,
            Duration::from_millis(250),
            Duration::from_secs(5),
            MetricsTuning::default(),
        )
    }

    #[test]
    fn peer_backoff_is_tracked_per_address() {
        let peer = peer_for_address_tests();
        let first = PeerAddress::new("10.1.2.3:64739".parse().unwrap(), TransportKind::Tcp);
        let second = PeerAddress::new("10.1.2.4:64739".parse().unwrap(), TransportKind::Tcp);
        let retry_cap = Duration::from_secs(30);

        peer.add_address(first);
        peer.add_address(second);
        peer.record_address_failure(first, retry_cap);
        let now = Instant::now();

        assert!(!peer.address_retry_ready(first, now, retry_cap));
        assert!(peer.address_retry_ready(second, now, retry_cap));

        peer.record_address_failure(second, retry_cap);
        peer.record_address_success(first);
        let backoffs = peer.address_backoffs.lock();
        assert_eq!(
            backoffs.get(&first).unwrap().next_delay,
            Duration::from_millis(250)
        );
        assert_eq!(
            backoffs.get(&second).unwrap().next_delay,
            Duration::from_millis(500)
        );
    }

    #[test]
    fn removing_address_prunes_address_backoff() {
        let peer = peer_for_address_tests();
        let addr = PeerAddress::new("10.1.2.3:64739".parse().unwrap(), TransportKind::Tcp);

        peer.add_address(addr);
        peer.record_address_failure(addr, Duration::from_secs(30));
        assert!(peer.address_backoffs.lock().contains_key(&addr));

        assert!(peer.remove_address(addr));
        assert!(!peer.address_backoffs.lock().contains_key(&addr));
    }

    fn active_stream_for_test(
        transport: TransportKind,
        remote_addr: SocketAddr,
        is_dialer: bool,
    ) -> (ActiveStream, mpsc::Receiver<OutboundFrame>) {
        let (tx, rx) = mpsc::channel(1);
        (
            ActiveStream::new(
                transport,
                Some(remote_addr),
                tx,
                CancellationToken::new(),
                is_dialer,
            ),
            rx,
        )
    }

    #[test]
    fn same_transport_streams_with_different_remote_addresses_coexist() {
        let peer = peer_for_address_tests();
        let first_addr = "10.1.2.3:64739".parse().unwrap();
        let second_addr = "10.1.2.4:64739".parse().unwrap();
        let (first, _first_rx) = active_stream_for_test(TransportKind::Tcp, first_addr, true);
        let (second, _second_rx) = active_stream_for_test(TransportKind::Tcp, second_addr, true);

        assert!(peer.try_install_stream(first).is_ok());
        assert!(peer.try_install_stream(second).is_ok());

        assert_eq!(peer.outgoing_live_count(), 2);
        assert!(peer.has_live_outgoing_to(PeerAddress::new(first_addr, TransportKind::Tcp)));
        assert!(peer.has_live_outgoing_to(PeerAddress::new(second_addr, TransportKind::Tcp)));
    }

    #[test]
    fn udp_stream_replaces_existing_udp_path() {
        let peer = peer_for_address_tests();
        let first_addr = "10.1.2.3:64742".parse().unwrap();
        let second_addr = "10.1.2.4:64742".parse().unwrap();
        let (first, _first_rx) = active_stream_for_test(TransportKind::Udp, first_addr, true);
        let (second, _second_rx) = active_stream_for_test(TransportKind::Udp, second_addr, true);

        peer.install_stream(first);
        peer.install_stream(second);

        assert_eq!(peer.outgoing_live_count(), 1);
        assert!(peer.has_live_outgoing_to(PeerAddress::new(first_addr, TransportKind::Udp)));
        assert!(peer.has_live_outgoing_to(PeerAddress::new(second_addr, TransportKind::Udp)));
    }

    #[test]
    fn exact_duplicate_stream_key_is_rejected() {
        let peer = peer_for_address_tests();
        let addr = "10.1.2.3:64739".parse().unwrap();
        let (first, _first_rx) = active_stream_for_test(TransportKind::Tcp, addr, true);
        let (duplicate, _duplicate_rx) = active_stream_for_test(TransportKind::Tcp, addr, true);

        assert!(peer.try_install_stream(first).is_ok());
        assert!(peer.try_install_stream(duplicate).is_err());

        assert_eq!(peer.outgoing_live_count(), 1);
        assert!(peer.has_live_outgoing_to(PeerAddress::new(addr, TransportKind::Tcp)));
    }

    #[test]
    fn stream_lookup_prefers_newest_live_stream_for_transport() {
        let peer = peer_for_address_tests();
        let old_addr = "10.1.2.3:64739".parse().unwrap();
        let new_addr = "10.1.2.4:64739".parse().unwrap();
        let (old_stream, mut old_rx) = active_stream_for_test(TransportKind::Tcp, old_addr, true);
        assert!(peer.try_install_stream(old_stream).is_ok());

        std::thread::sleep(Duration::from_millis(1));

        let (new_stream, mut new_rx) = active_stream_for_test(TransportKind::Tcp, new_addr, false);
        assert!(peer.try_install_stream(new_stream).is_ok());

        let sender = peer.try_get_stream(TransportKind::Tcp).unwrap();
        sender
            .try_send(OutboundFrame::new(
                MessageClass::Regular,
                Bytes::from_static(b"new"),
            ))
            .unwrap();

        assert!(old_rx.try_recv().is_err());
        assert_eq!(
            new_rx.try_recv().unwrap().payload(),
            &Bytes::from_static(b"new")
        );
    }

    #[test]
    fn udp_inbound_session_satisfies_address_dial_check() {
        let peer = peer_for_address_tests();
        let addr = "10.1.2.3:64739".parse().unwrap();
        let (inbound, _rx) = active_stream_for_test(TransportKind::Udp, addr, false);

        assert!(peer.try_install_stream(inbound).is_ok());

        assert_eq!(peer.outgoing_live_count(), 0);
        assert!(peer.has_live_outgoing_to(PeerAddress::new(addr, TransportKind::Udp)));
    }

    #[test]
    fn tcp_inbound_session_does_not_satisfy_outgoing_dial_check() {
        let peer = peer_for_address_tests();
        let addr = "10.1.2.3:64739".parse().unwrap();
        let (inbound, _rx) = active_stream_for_test(TransportKind::Tcp, addr, false);

        assert!(peer.try_install_stream(inbound).is_ok());

        assert!(!peer.has_live_outgoing_to(PeerAddress::new(addr, TransportKind::Tcp)));
    }

    #[test]
    fn observed_remote_ips_create_candidates_for_wildcard_advertised_address() {
        let peer = peer_for_address_tests();
        peer.note_observed_remote_addr(TransportKind::Kcp, "10.1.2.3:51000".parse().unwrap());
        peer.note_observed_remote_addr(TransportKind::Kcp, "10.1.2.4:52000".parse().unwrap());

        let candidates = peer.address_candidates(PeerAddress::new(
            "0.0.0.0:64740".parse().unwrap(),
            TransportKind::Kcp,
        ));

        assert_eq!(
            candidates,
            vec![
                PeerAddress::new("10.1.2.3:64740".parse().unwrap(), TransportKind::Kcp),
                PeerAddress::new("10.1.2.4:64740".parse().unwrap(), TransportKind::Kcp),
            ]
        );
    }

    #[test]
    fn observed_remote_ip_is_appended_to_remote_loopback_advertised_address() {
        let peer = peer_for_address_tests();
        peer.note_observed_remote_addr(TransportKind::Tcp, "10.1.2.3:51000".parse().unwrap());

        let published = PeerAddress::new("127.0.0.1:64739".parse().unwrap(), TransportKind::Tcp);
        let candidates = peer.address_candidates(PeerAddress::new(
            "127.0.0.1:64739".parse().unwrap(),
            TransportKind::Tcp,
        ));

        assert_eq!(
            candidates,
            vec![
                published,
                PeerAddress::new("10.1.2.3:64739".parse().unwrap(), TransportKind::Tcp)
            ]
        );
    }

    #[test]
    fn concrete_private_advertised_address_appends_private_observed_candidate() {
        let peer = peer_for_address_tests();
        peer.note_observed_remote_addr(TransportKind::Quic, "10.1.2.3:51000".parse().unwrap());

        let published = PeerAddress::new("10.4.5.6:64741".parse().unwrap(), TransportKind::Quic);
        assert_eq!(
            peer.address_candidates(published),
            vec![
                published,
                PeerAddress::new("10.1.2.3:64741".parse().unwrap(), TransportKind::Quic)
            ]
        );
    }

    #[test]
    fn observed_remote_ips_only_create_candidates_for_same_transport() {
        let peer = peer_for_address_tests();
        peer.note_observed_remote_addr(TransportKind::Tcp, "10.1.2.3:51000".parse().unwrap());

        assert_eq!(
            peer.address_candidates(PeerAddress::new(
                "0.0.0.0:64740".parse().unwrap(),
                TransportKind::Kcp,
            )),
            Vec::<PeerAddress>::new()
        );

        peer.note_observed_remote_addr(TransportKind::Kcp, "10.1.2.4:52000".parse().unwrap());

        assert_eq!(
            peer.address_candidates(PeerAddress::new(
                "0.0.0.0:64740".parse().unwrap(),
                TransportKind::Kcp,
            )),
            vec![PeerAddress::new(
                "10.1.2.4:64740".parse().unwrap(),
                TransportKind::Kcp,
            )]
        );
    }

    #[test]
    fn public_observation_is_appended_to_private_published_address() {
        let peer = peer_for_address_tests();
        peer.note_observed_remote_addr(TransportKind::Quic, "8.8.8.8:51000".parse().unwrap());

        let published = PeerAddress::new("10.4.5.6:64741".parse().unwrap(), TransportKind::Quic);
        let candidates = peer.address_candidates(PeerAddress::new(
            "10.4.5.6:64741".parse().unwrap(),
            TransportKind::Quic,
        ));

        assert_eq!(
            candidates,
            vec![
                published,
                PeerAddress::new("8.8.8.8:64741".parse().unwrap(), TransportKind::Quic)
            ]
        );
    }

    #[test]
    fn confirmed_address_moves_to_front_for_future_dials_and_persistence() {
        let peer = peer_for_address_tests();
        let first = PeerAddress::new("10.1.2.3:64741".parse().unwrap(), TransportKind::Quic);
        let second = PeerAddress::new("10.1.2.4:64741".parse().unwrap(), TransportKind::Quic);

        assert!(peer.add_address(first));
        assert!(peer.add_address(second));
        peer.confirm_address(second);

        assert_eq!(peer.snapshot_addresses(), vec![second, first]);
    }
}
