use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

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
pub const RELIABLE_TRANSPORTS_DEFAULT: TransportMask = transport_bit(TransportKind::Tcp)
    | transport_bit(TransportKind::Kcp)
    | transport_bit(TransportKind::Quic);
pub const ALL_TRANSPORTS_DEFAULT: TransportMask =
    RELIABLE_TRANSPORTS_DEFAULT | transport_bit(TransportKind::Udp);

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
    lsa_flood_pacing_interval: Duration,
    lsa_flood_max_batch_lsas: usize,
    lsa_refresh_reduction_enabled: bool,
    lsa_unchanged_refresh_interval: Duration,

    // ── Anti-entropy ──
    anti_entropy_interval: Duration,

    // ── Persistence (unchanged from Phase 1) ──
    peer_persistence_interval: Duration,

    // ── Routing recompute debounce ──
    routing_recompute_debounce: Duration,
    routing_dynamic_spf_enabled: bool,

    // ── Cost-function knobs (operator-tunable; see crate docs) ──
    reliable_throughput_penalty_us_kbps: f64,
    rll_jitter_weight: f64,
    reliable_transports_mask: TransportMask,
    rll_transports_mask: TransportMask,
    best_effort_transports_mask: TransportMask,
    max_route_packet_loss_ppm: u32,

    // ── Cost-change re-emit thresholds ──
    cost_rerun_rtt_pct: f64, // re-emit when RTT shifts >= this fraction
    cost_rerun_throughput_pct: f64, // re-emit when throughput shifts >= this fraction
    cost_rerun_min_interval: Duration,
    cost_rerun_loss_ppm: u32,

    // ── Transit routing ──
    /// When enabled, inbound overlay data for other nodes may be forwarded
    /// through this node. Local delivery and locally originated messages are
    /// unaffected.
    route_transit_messages: bool,

    // ── LSDB sync chunking ──
    /// Max LSAs per `LsdbSyncResp` frame. The responder splits a delta
    /// across multiple frames when it exceeds this cap.
    lsdb_sync_max_response_lsas: usize,

    // ── Ordered overlay lanes ──
    ordered_lane_cap: NonZeroUsize,
    ordered_pending_window_packets: usize,
    ordered_reorder_buffer_packets: usize,
    ordered_repair_cache_packets: usize,
    ordered_ack_timeout: Duration,
    ordered_retry_initial: Duration,
    ordered_retry_max: Duration,
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
            lsa_flood_pacing_interval: Duration::from_millis(1000),
            lsa_flood_max_batch_lsas: 4096,
            lsa_refresh_reduction_enabled: true,
            lsa_unchanged_refresh_interval: Duration::from_secs(90),

            anti_entropy_interval: Duration::from_secs(60),

            peer_persistence_interval: Duration::from_secs(30),
            routing_recompute_debounce: Duration::from_millis(25),
            routing_dynamic_spf_enabled: true,

            reliable_throughput_penalty_us_kbps: 1_000_000.0,
            rll_jitter_weight: 4.0,
            reliable_transports_mask: RELIABLE_TRANSPORTS_DEFAULT,
            rll_transports_mask: RELIABLE_TRANSPORTS_DEFAULT,
            best_effort_transports_mask: ALL_TRANSPORTS_DEFAULT,
            max_route_packet_loss_ppm: 500_000,

            cost_rerun_rtt_pct: 0.25,
            cost_rerun_throughput_pct: 0.50,
            cost_rerun_min_interval: Duration::from_secs(5),
            cost_rerun_loss_ppm: 100_000,

            route_transit_messages: true,
            lsdb_sync_max_response_lsas: 2048,
            ordered_lane_cap: NonZeroUsize::new(64).expect("non-zero ordered lane cap"),
            ordered_pending_window_packets: 1024,
            ordered_reorder_buffer_packets: 1024,
            ordered_repair_cache_packets: 1024,
            ordered_ack_timeout: Duration::from_millis(250),
            ordered_retry_initial: Duration::from_millis(250),
            ordered_retry_max: Duration::from_secs(2),
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
    pub fn lsa_flood_pacing_interval(&self) -> Duration {
        self.lsa_flood_pacing_interval
    }
    pub fn lsa_flood_max_batch_lsas(&self) -> usize {
        self.lsa_flood_max_batch_lsas
    }
    pub fn lsa_refresh_reduction_enabled(&self) -> bool {
        self.lsa_refresh_reduction_enabled
    }
    pub fn lsa_unchanged_refresh_interval(&self) -> Duration {
        self.lsa_unchanged_refresh_interval
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
    pub fn routing_dynamic_spf_enabled(&self) -> bool {
        self.routing_dynamic_spf_enabled
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
    pub fn max_route_packet_loss_ppm(&self) -> u32 {
        self.max_route_packet_loss_ppm
    }
    pub fn cost_rerun_rtt_pct(&self) -> f64 {
        self.cost_rerun_rtt_pct
    }
    pub fn cost_rerun_throughput_pct(&self) -> f64 {
        self.cost_rerun_throughput_pct
    }
    pub fn cost_rerun_min_interval(&self) -> Duration {
        self.cost_rerun_min_interval
    }
    pub fn cost_rerun_loss_ppm(&self) -> u32 {
        self.cost_rerun_loss_ppm
    }

    pub fn route_transit_messages(&self) -> bool {
        self.route_transit_messages
    }

    pub fn lsdb_sync_max_response_lsas(&self) -> usize {
        self.lsdb_sync_max_response_lsas
    }

    pub fn ordered_lane_cap(&self) -> NonZeroUsize {
        self.ordered_lane_cap
    }

    pub fn ordered_pending_window_packets(&self) -> usize {
        self.ordered_pending_window_packets
    }

    pub fn ordered_reorder_buffer_packets(&self) -> usize {
        self.ordered_reorder_buffer_packets
    }

    pub fn ordered_repair_cache_packets(&self) -> usize {
        self.ordered_repair_cache_packets
    }

    pub fn ordered_ack_timeout(&self) -> Duration {
        self.ordered_ack_timeout
    }

    pub fn ordered_retry_initial(&self) -> Duration {
        self.ordered_retry_initial
    }

    pub fn ordered_retry_max(&self) -> Duration {
        self.ordered_retry_max
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
    pub fn with_lsa_flood_pacing_interval(mut self, d: Duration) -> Self {
        self.lsa_flood_pacing_interval = d;
        self
    }
    pub fn with_lsa_flood_max_batch_lsas(mut self, n: usize) -> Self {
        self.lsa_flood_max_batch_lsas = n.max(1);
        self
    }
    pub fn with_lsa_refresh_reduction_enabled(mut self, enabled: bool) -> Self {
        self.lsa_refresh_reduction_enabled = enabled;
        self
    }
    pub fn with_lsa_unchanged_refresh_interval(mut self, d: Duration) -> Self {
        self.lsa_unchanged_refresh_interval = d;
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
    pub fn with_routing_dynamic_spf_enabled(mut self, enabled: bool) -> Self {
        self.routing_dynamic_spf_enabled = enabled;
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
    pub fn with_max_route_packet_loss_ppm(mut self, ppm: u32) -> Self {
        self.max_route_packet_loss_ppm = ppm.min(1_000_000);
        self
    }
    pub fn with_cost_rerun_min_interval(mut self, d: Duration) -> Self {
        self.cost_rerun_min_interval = d;
        self
    }
    pub fn with_cost_rerun_loss_ppm(mut self, ppm: u32) -> Self {
        self.cost_rerun_loss_ppm = ppm.min(1_000_000);
        self
    }

    pub fn with_route_transit_messages(mut self, enabled: bool) -> Self {
        self.route_transit_messages = enabled;
        self
    }

    pub fn with_lsdb_sync_max_response_lsas(mut self, n: usize) -> Self {
        self.lsdb_sync_max_response_lsas = n;
        self
    }

    pub fn with_ordered_lane_cap(mut self, cap: NonZeroUsize) -> Self {
        self.ordered_lane_cap = cap;
        self
    }

    pub fn with_ordered_pending_window_packets(mut self, n: usize) -> Self {
        self.ordered_pending_window_packets = n;
        self
    }

    pub fn with_ordered_reorder_buffer_packets(mut self, n: usize) -> Self {
        self.ordered_reorder_buffer_packets = n;
        self
    }

    pub fn with_ordered_repair_cache_packets(mut self, n: usize) -> Self {
        self.ordered_repair_cache_packets = n;
        self
    }

    pub fn with_ordered_ack_timeout(mut self, d: Duration) -> Self {
        self.ordered_ack_timeout = d;
        self
    }

    pub fn with_ordered_retry_initial(mut self, d: Duration) -> Self {
        self.ordered_retry_initial = d;
        self
    }

    pub fn with_ordered_retry_max(mut self, d: Duration) -> Self {
        self.ordered_retry_max = d;
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

/// TOML-deserializable shadow of [`OverlayConfig`]. Only the tunables
/// surfaced from the operator config live here; other [`OverlayConfig`]
/// fields (timers, transport masks, etc.) stay Rust-builder-only for now.
#[derive(Deserialize, Debug, Clone)]
pub struct OverlayTuning {
    #[serde(default = "default_hello_interval_ms")]
    pub hello_interval_ms: u64,

    #[serde(default = "default_hello_dead_interval_ms")]
    pub hello_dead_interval_ms: u64,

    #[serde(default = "default_lsa_max_age_ms")]
    pub lsa_max_age_ms: u64,

    /// Whether this node forwards inbound overlay data whose final destination
    /// is another node. Local delivery and local origination are unaffected.
    #[serde(default = "default_route_transit_messages")]
    pub route_transit_messages: bool,

    /// Max LSAs per `LsdbSyncResp` frame.
    #[serde(default = "default_lsdb_sync_max_response_lsas")]
    pub lsdb_sync_max_response_lsas: usize,

    /// Milliseconds to coalesce LSA floods before sending.
    #[serde(default = "default_lsa_flood_pacing_interval_ms")]
    pub lsa_flood_pacing_interval_ms: u64,

    /// Max LSAs per paced `LsaFlood` frame.
    #[serde(default = "default_lsa_flood_max_batch_lsas")]
    pub lsa_flood_max_batch_lsas: usize,

    #[serde(default = "default_lsa_refresh_reduction_enabled")]
    pub lsa_refresh_reduction_enabled: bool,

    #[serde(default = "default_lsa_unchanged_refresh_interval_secs")]
    pub lsa_unchanged_refresh_interval_secs: u64,

    #[serde(default = "default_routing_dynamic_spf_enabled")]
    pub routing_dynamic_spf_enabled: bool,

    #[serde(default = "default_cost_rerun_min_interval_ms")]
    pub cost_rerun_min_interval_ms: u64,
    #[serde(default = "default_cost_rerun_loss_ppm")]
    pub cost_rerun_loss_ppm: u32,

    #[serde(default = "default_ordered_lane_cap")]
    pub ordered_lane_cap: usize,
    #[serde(default = "default_ordered_pending_window_packets")]
    pub ordered_pending_window_packets: usize,
    #[serde(default = "default_ordered_reorder_buffer_packets")]
    pub ordered_reorder_buffer_packets: usize,
    #[serde(default = "default_ordered_repair_cache_packets")]
    pub ordered_repair_cache_packets: usize,
    #[serde(default = "default_ordered_ack_timeout_ms")]
    pub ordered_ack_timeout_ms: u64,
    #[serde(default = "default_ordered_retry_initial_ms")]
    pub ordered_retry_initial_ms: u64,
    #[serde(default = "default_ordered_retry_max_ms")]
    pub ordered_retry_max_ms: u64,
}

impl Default for OverlayTuning {
    fn default() -> Self {
        Self {
            hello_interval_ms: default_hello_interval_ms(),
            hello_dead_interval_ms: default_hello_dead_interval_ms(),
            lsa_max_age_ms: default_lsa_max_age_ms(),
            route_transit_messages: default_route_transit_messages(),
            lsdb_sync_max_response_lsas: default_lsdb_sync_max_response_lsas(),
            lsa_flood_pacing_interval_ms: default_lsa_flood_pacing_interval_ms(),
            lsa_flood_max_batch_lsas: default_lsa_flood_max_batch_lsas(),
            lsa_refresh_reduction_enabled: default_lsa_refresh_reduction_enabled(),
            lsa_unchanged_refresh_interval_secs: default_lsa_unchanged_refresh_interval_secs(),
            routing_dynamic_spf_enabled: default_routing_dynamic_spf_enabled(),
            cost_rerun_min_interval_ms: default_cost_rerun_min_interval_ms(),
            cost_rerun_loss_ppm: default_cost_rerun_loss_ppm(),
            ordered_lane_cap: default_ordered_lane_cap(),
            ordered_pending_window_packets: default_ordered_pending_window_packets(),
            ordered_reorder_buffer_packets: default_ordered_reorder_buffer_packets(),
            ordered_repair_cache_packets: default_ordered_repair_cache_packets(),
            ordered_ack_timeout_ms: default_ordered_ack_timeout_ms(),
            ordered_retry_initial_ms: default_ordered_retry_initial_ms(),
            ordered_retry_max_ms: default_ordered_retry_max_ms(),
        }
    }
}

impl OverlayTuning {
    /// Apply the tunables on top of an `OverlayConfig` built from the
    /// existing seed-peer / persistence-dir machinery.
    pub fn apply(&self, cfg: OverlayConfig) -> OverlayConfig {
        cfg.with_hello_interval(Duration::from_millis(self.hello_interval_ms))
            .with_hello_dead_interval(Duration::from_millis(self.hello_dead_interval_ms))
            .with_lsa_max_age(Duration::from_millis(self.lsa_max_age_ms))
            .with_route_transit_messages(self.route_transit_messages)
            .with_lsdb_sync_max_response_lsas(self.lsdb_sync_max_response_lsas)
            .with_lsa_flood_pacing_interval(Duration::from_millis(
                self.lsa_flood_pacing_interval_ms,
            ))
            .with_lsa_flood_max_batch_lsas(self.lsa_flood_max_batch_lsas)
            .with_lsa_refresh_reduction_enabled(self.lsa_refresh_reduction_enabled)
            .with_lsa_unchanged_refresh_interval(Duration::from_secs(
                self.lsa_unchanged_refresh_interval_secs,
            ))
            .with_routing_dynamic_spf_enabled(self.routing_dynamic_spf_enabled)
            .with_cost_rerun_min_interval(Duration::from_millis(self.cost_rerun_min_interval_ms))
            .with_cost_rerun_loss_ppm(self.cost_rerun_loss_ppm)
            .with_ordered_lane_cap(
                NonZeroUsize::new(self.ordered_lane_cap)
                    .unwrap_or_else(|| NonZeroUsize::new(default_ordered_lane_cap()).unwrap()),
            )
            .with_ordered_pending_window_packets(self.ordered_pending_window_packets)
            .with_ordered_reorder_buffer_packets(self.ordered_reorder_buffer_packets)
            .with_ordered_repair_cache_packets(self.ordered_repair_cache_packets)
            .with_ordered_ack_timeout(Duration::from_millis(self.ordered_ack_timeout_ms))
            .with_ordered_retry_initial(Duration::from_millis(self.ordered_retry_initial_ms))
            .with_ordered_retry_max(Duration::from_millis(self.ordered_retry_max_ms))
    }
}

fn default_hello_interval_ms() -> u64 {
    1_000
}

fn default_hello_dead_interval_ms() -> u64 {
    4_000
}

fn default_lsa_max_age_ms() -> u64 {
    120_000
}

fn default_route_transit_messages() -> bool {
    true
}

fn default_lsdb_sync_max_response_lsas() -> usize {
    2048
}

fn default_lsa_flood_pacing_interval_ms() -> u64 {
    1000
}

fn default_lsa_flood_max_batch_lsas() -> usize {
    4096
}

fn default_lsa_refresh_reduction_enabled() -> bool {
    true
}

fn default_lsa_unchanged_refresh_interval_secs() -> u64 {
    90
}

fn default_routing_dynamic_spf_enabled() -> bool {
    true
}

fn default_cost_rerun_min_interval_ms() -> u64 {
    5_000
}
fn default_cost_rerun_loss_ppm() -> u32 {
    100_000
}

fn default_ordered_lane_cap() -> usize {
    64
}
fn default_ordered_pending_window_packets() -> usize {
    1024
}
fn default_ordered_reorder_buffer_packets() -> usize {
    1024
}
fn default_ordered_repair_cache_packets() -> usize {
    1024
}
fn default_ordered_ack_timeout_ms() -> u64 {
    250
}
fn default_ordered_retry_initial_ms() -> u64 {
    250
}
fn default_ordered_retry_max_ms() -> u64 {
    2_000
}
