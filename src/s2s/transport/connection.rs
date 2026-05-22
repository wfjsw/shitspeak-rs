//! Per-peer state held by the supervisor.
//!
//! The supervisor owns one `PeerState` per known peer; that struct contains
//! the dial address book, the set of currently-active streams (one per
//! transport flavor), reconnect backoff, and aggregated metrics.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::types::NodeIdentifier;

use super::metrics::{MetricsTuning, PeerMetrics};
use super::service_level::{MessageClass, PeerAddress, TransportKind};

const MAX_OBSERVED_REMOTE_IPS: usize = 8;

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
    is_dialer: bool,
}

impl ActiveStream {
    pub fn new(
        transport: TransportKind,
        sender: mpsc::Sender<OutboundFrame>,
        closed: CancellationToken,
        is_dialer: bool,
    ) -> Self {
        Self {
            transport,
            sender,
            closed,
            is_dialer,
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

    pub fn cancel(&self) {
        self.closed.cancel();
    }
}

#[derive(Debug)]
pub(crate) struct BackoffState {
    initial: Duration,
    next_delay: Duration,
    last_attempt: Option<Instant>,
    consecutive_failures: u32,
}

impl BackoffState {
    pub fn new(initial: Duration) -> Self {
        Self {
            initial,
            next_delay: initial,
            last_attempt: None,
            consecutive_failures: 0,
        }
    }

    pub fn ready(&self, now: Instant, retry_cap: Duration) -> bool {
        let effective_delay = self.next_delay.min(retry_cap);
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
    /// Authenticated inbound remote IPs. Source ports are often ephemeral; the
    /// IPs are combined with published service ports to form dial candidates.
    observed_remote_ips: Mutex<Vec<std::net::IpAddr>>,
    last_seen_wall: Mutex<Option<SystemTime>>,
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
        bandwidth_window: Duration,
        metrics_tuning: MetricsTuning,
    ) -> Arc<Self> {
        Arc::new(Self {
            node_id,
            addresses: Mutex::new(Vec::new()),
            streams: Mutex::new(HashMap::new()),
            udp_seen_at: Mutex::new(None),
            udp_addr: Mutex::new(None),
            observed_remote_ips: Mutex::new(Vec::new()),
            last_seen_wall: Mutex::new(None),
            metrics: Arc::new(PeerMetrics::new(bandwidth_window, metrics_tuning)),
            backoff: Mutex::new(BackoffState::new(backoff_initial)),
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
        self.note_seen_now();
        let mut g = self.addresses.lock();
        if g.contains(&addr) {
            return false;
        }
        g.push(addr);
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
        true
    }

    pub fn note_observed_remote_addr(&self, addr: std::net::SocketAddr) {
        let ip = addr.ip();
        if ip_looks_unusable(ip) {
            return;
        }
        let mut observed = self.observed_remote_ips.lock();
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
        let observed = self.observed_remote_ips.lock().clone();
        let mut candidates = Vec::new();

        if published_ip_looks_usable(published.ip(), &observed) {
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
        g.len() != before
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
        self.note_seen_now();
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
        self.note_seen_now();
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

    pub fn outgoing_live_count(&self) -> usize {
        self.streams
            .lock()
            .values()
            .filter(|s| s.is_alive() && s.is_dialer())
            .count()
    }

    pub fn outgoing_live_kinds(&self) -> Vec<TransportKind> {
        self.streams
            .lock()
            .values()
            .filter(|s| s.is_alive() && s.is_dialer())
            .map(|s| s.transport())
            .collect()
    }

    pub fn drop_outgoing_stream(&self, kind: TransportKind) -> bool {
        let mut g = self.streams.lock();
        let should_drop = g
            .get(&kind)
            .is_some_and(|stream| stream.is_alive() && stream.is_dialer());
        if !should_drop {
            return false;
        }
        if let Some(prev) = g.remove(&kind) {
            prev.closed.cancel();
            true
        } else {
            false
        }
    }

    pub fn note_udp_seen(&self, addr: std::net::SocketAddr) {
        *self.udp_seen_at.lock() = Some(Instant::now());
        *self.udp_addr.lock() = Some(addr);
        self.note_observed_remote_addr(addr);
    }

    pub fn udp_addr(&self) -> Option<std::net::SocketAddr> {
        *self.udp_addr.lock()
    }
}

fn push_unique_candidate(candidates: &mut Vec<PeerAddress>, addr: PeerAddress) {
    if addr.is_dialable() && !candidates.contains(&addr) {
        candidates.push(addr);
    }
}

fn published_ip_looks_usable(published: std::net::IpAddr, observed: &[std::net::IpAddr]) -> bool {
    if ip_looks_unusable(published) {
        return false;
    }
    !(published.is_loopback() && observed.iter().any(|ip| !ip.is_loopback()))
        && !(!ip_looks_public(published) && observed.iter().any(|ip| ip_looks_public(*ip)))
}

fn should_add_observed_candidate(published: std::net::IpAddr, observed: std::net::IpAddr) -> bool {
    if ip_looks_unusable(observed) || observed == published {
        return false;
    }
    true
}

fn ip_looks_unusable(ip: std::net::IpAddr) -> bool {
    ip.is_unspecified() || ip.is_multicast()
}

fn ip_looks_private(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_private()
                || ip.is_link_local()
                || ip.is_documentation()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 198 && (18..=19).contains(&octets[1]))
        }
        std::net::IpAddr::V6(ip) => {
            let segments = ip.segments();
            ((segments[0] & 0xfe00) == 0xfc00)
                || ((segments[0] & 0xffc0) == 0xfe80)
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

fn ip_looks_public(ip: std::net::IpAddr) -> bool {
    !ip_looks_unusable(ip) && !ip.is_loopback() && !ip_looks_private(ip)
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
    fn observed_remote_ips_create_candidates_for_wildcard_advertised_address() {
        let peer = peer_for_address_tests();
        peer.note_observed_remote_addr("10.1.2.3:51000".parse().unwrap());
        peer.note_observed_remote_addr("10.1.2.4:52000".parse().unwrap());

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
    fn observed_remote_ip_replaces_remote_loopback_advertised_address() {
        let peer = peer_for_address_tests();
        peer.note_observed_remote_addr("10.1.2.3:51000".parse().unwrap());

        let candidates = peer.address_candidates(PeerAddress::new(
            "127.0.0.1:64739".parse().unwrap(),
            TransportKind::Tcp,
        ));

        assert_eq!(
            candidates,
            vec![PeerAddress::new(
                "10.1.2.3:64739".parse().unwrap(),
                TransportKind::Tcp
            )]
        );
    }

    #[test]
    fn concrete_advertised_address_and_observed_ips_are_all_candidates() {
        let peer = peer_for_address_tests();
        peer.note_observed_remote_addr("10.1.2.3:51000".parse().unwrap());

        let published = PeerAddress::new("10.4.5.6:64741".parse().unwrap(), TransportKind::Quic);
        assert_eq!(
            peer.address_candidates(published),
            vec![
                published,
                PeerAddress::new("10.1.2.3:64741".parse().unwrap(), TransportKind::Quic),
            ]
        );
    }

    #[test]
    fn public_observation_rules_out_private_published_address() {
        let peer = peer_for_address_tests();
        peer.note_observed_remote_addr("8.8.8.8:51000".parse().unwrap());

        let candidates = peer.address_candidates(PeerAddress::new(
            "10.4.5.6:64741".parse().unwrap(),
            TransportKind::Quic,
        ));

        assert_eq!(
            candidates,
            vec![PeerAddress::new(
                "8.8.8.8:64741".parse().unwrap(),
                TransportKind::Quic
            )]
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
