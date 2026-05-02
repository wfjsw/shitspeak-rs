use std::path::PathBuf;
use std::time::Duration;

use crate::s2s::transport::{PeerAddress, TransportKind};
use crate::types::NodeIdentifier;

/// Bitmask over `TransportKind` values (1 << TransportKind::Tcp etc).
/// Used as an admission filter on routing edges per service-level.
pub type TransportMask = u32;

#[inline]
pub const fn transport_bit(k: TransportKind) -> u32 {
    1u32 << kind_to_idx(k)
}

#[inline]
pub const fn kind_to_idx(k: TransportKind) -> u32 {
    match k {
        TransportKind::Tcp => 0,
        TransportKind::Kcp => 1,
        TransportKind::Quic => 2,
        TransportKind::Udp => 3,
    }
}

#[inline]
pub const fn idx_to_kind(i: u32) -> Option<TransportKind> {
    match i {
        0 => Some(TransportKind::Tcp),
        1 => Some(TransportKind::Kcp),
        2 => Some(TransportKind::Quic),
        3 => Some(TransportKind::Udp),
        _ => None,
    }
}

/// `{Tcp, Kcp, Quic}` — the three reliable streams. Default for both
/// `Reliable` and `ReliableLowLatency` admission. `Udp` is lossy/datagram-
/// based and is excluded by default for any reliable level.
pub const RELIABLE_TRANSPORTS_DEFAULT: TransportMask =
    transport_bit(TransportKind::Tcp) | transport_bit(TransportKind::Kcp) | transport_bit(TransportKind::Quic);
pub const ALL_TRANSPORTS_DEFAULT: TransportMask = RELIABLE_TRANSPORTS_DEFAULT | transport_bit(TransportKind::Udp);

/// Knobs for [`super::OverlayNetwork::start`].
#[derive(Debug, Clone)]
pub struct OverlayConfig {
    seed_peers: Vec<SeedPeer>,
    persistence_dir: Option<PathBuf>,

    // ── Direct-link Hello (replaces SWIM probes) ──
    hello_interval: Duration,
    hello_dead_interval: Duration,

    // ── LSA lifecycle ──
    lsa_refresh_interval: Duration,
    lsa_max_age: Duration,
    tombstone_in_memory_age: Duration,

    // ── Anti-entropy ──
    anti_entropy_interval: Duration,

    // ── Persistence (unchanged from Phase 1) ──
    peer_persistence_interval: Duration,

    // ── Routing recompute debounce ──
    routing_recompute_debounce: Duration,

    // ── Cost-function knobs (operator-tunable; see crate docs) ──
    reliable_throughput_penalty_us_kbps: f64,
    rll_jitter_weight: f64,
    reliable_transports_mask: TransportMask,
    rll_transports_mask: TransportMask,
    best_effort_transports_mask: TransportMask,

    // ── Cost-change re-emit thresholds ──
    cost_rerun_rtt_pct: f64,        // re-emit when RTT shifts >= this fraction
    cost_rerun_throughput_pct: f64, // re-emit when throughput shifts >= this fraction
}

impl OverlayConfig {
    pub fn new(seed_peers: Vec<SeedPeer>) -> Self {
        Self {
            seed_peers,
            persistence_dir: None,

            hello_interval: Duration::from_secs(1),
            hello_dead_interval: Duration::from_secs(4),

            lsa_refresh_interval: Duration::from_secs(30),
            lsa_max_age: Duration::from_secs(120),
            tombstone_in_memory_age: Duration::from_secs(300),

            anti_entropy_interval: Duration::from_secs(60),

            peer_persistence_interval: Duration::from_secs(30),
            routing_recompute_debounce: Duration::from_millis(25),

            reliable_throughput_penalty_us_kbps: 1_000_000.0,
            rll_jitter_weight: 4.0,
            reliable_transports_mask: RELIABLE_TRANSPORTS_DEFAULT,
            rll_transports_mask: RELIABLE_TRANSPORTS_DEFAULT,
            best_effort_transports_mask: ALL_TRANSPORTS_DEFAULT,

            cost_rerun_rtt_pct: 0.25,
            cost_rerun_throughput_pct: 0.50,
        }
    }

    // ── Getters ──

    pub fn seed_peers(&self) -> &[SeedPeer] {
        &self.seed_peers
    }
    pub fn persistence_dir(&self) -> Option<&PathBuf> {
        self.persistence_dir.as_ref()
    }
    pub fn hello_interval(&self) -> Duration {
        self.hello_interval
    }
    pub fn hello_dead_interval(&self) -> Duration {
        self.hello_dead_interval
    }
    pub fn lsa_refresh_interval(&self) -> Duration {
        self.lsa_refresh_interval
    }
    pub fn lsa_max_age(&self) -> Duration {
        self.lsa_max_age
    }
    pub fn tombstone_in_memory_age(&self) -> Duration {
        self.tombstone_in_memory_age
    }
    pub fn anti_entropy_interval(&self) -> Duration {
        self.anti_entropy_interval
    }
    pub fn peer_persistence_interval(&self) -> Duration {
        self.peer_persistence_interval
    }
    pub fn routing_recompute_debounce(&self) -> Duration {
        self.routing_recompute_debounce
    }
    pub fn reliable_throughput_penalty_us_kbps(&self) -> f64 {
        self.reliable_throughput_penalty_us_kbps
    }
    pub fn rll_jitter_weight(&self) -> f64 {
        self.rll_jitter_weight
    }
    pub fn reliable_transports_mask(&self) -> TransportMask {
        self.reliable_transports_mask
    }
    pub fn rll_transports_mask(&self) -> TransportMask {
        self.rll_transports_mask
    }
    pub fn best_effort_transports_mask(&self) -> TransportMask {
        self.best_effort_transports_mask
    }
    pub fn cost_rerun_rtt_pct(&self) -> f64 {
        self.cost_rerun_rtt_pct
    }
    pub fn cost_rerun_throughput_pct(&self) -> f64 {
        self.cost_rerun_throughput_pct
    }

    // ── Builder setters ──

    pub fn with_persistence_dir(mut self, dir: PathBuf) -> Self {
        self.persistence_dir = Some(dir);
        self
    }
    pub fn with_hello_interval(mut self, d: Duration) -> Self {
        self.hello_interval = d;
        self
    }
    pub fn with_hello_dead_interval(mut self, d: Duration) -> Self {
        self.hello_dead_interval = d;
        self
    }
    pub fn with_lsa_refresh_interval(mut self, d: Duration) -> Self {
        self.lsa_refresh_interval = d;
        self
    }
    pub fn with_lsa_max_age(mut self, d: Duration) -> Self {
        self.lsa_max_age = d;
        self
    }
    pub fn with_tombstone_in_memory_age(mut self, d: Duration) -> Self {
        self.tombstone_in_memory_age = d;
        self
    }
    pub fn with_anti_entropy_interval(mut self, d: Duration) -> Self {
        self.anti_entropy_interval = d;
        self
    }
    pub fn with_peer_persistence_interval(mut self, d: Duration) -> Self {
        self.peer_persistence_interval = d;
        self
    }
    pub fn with_routing_recompute_debounce(mut self, d: Duration) -> Self {
        self.routing_recompute_debounce = d;
        self
    }
    pub fn with_reliable_throughput_penalty_us_kbps(mut self, v: f64) -> Self {
        self.reliable_throughput_penalty_us_kbps = v;
        self
    }
    pub fn with_rll_jitter_weight(mut self, v: f64) -> Self {
        self.rll_jitter_weight = v;
        self
    }
    pub fn with_reliable_transports_mask(mut self, m: TransportMask) -> Self {
        self.reliable_transports_mask = m;
        self
    }
    pub fn with_rll_transports_mask(mut self, m: TransportMask) -> Self {
        self.rll_transports_mask = m;
        self
    }
    pub fn with_best_effort_transports_mask(mut self, m: TransportMask) -> Self {
        self.best_effort_transports_mask = m;
        self
    }
}

/// Bootstrap peer entry from operator config. The node id is required so the
/// local node can call `transport.add_address(id, addr)` directly without
/// waiting for a TLS handshake to disclose the peer's CN.
#[derive(Debug, Clone)]
pub struct SeedPeer {
    node_id: NodeIdentifier,
    addresses: Vec<PeerAddress>,
}

impl SeedPeer {
    pub fn new(node_id: NodeIdentifier, addresses: Vec<PeerAddress>) -> Self {
        Self { node_id, addresses }
    }

    pub fn node_id(&self) -> NodeIdentifier {
        self.node_id
    }

    pub fn addresses(&self) -> &[PeerAddress] {
        &self.addresses
    }
}
