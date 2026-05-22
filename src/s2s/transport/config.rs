use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use super::service_level::PeerAddress;

/// Knobs for [`super::ConnectionManager::start`]. All listeners are optional —
/// at least one must be set or [`super::ConfigError::NoListener`] is returned.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    ca_path: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,

    tcp_listen: Option<SocketAddr>,
    kcp_listen: Option<SocketAddr>,
    quic_listen: Option<SocketAddr>,
    udp_listen: Option<SocketAddr>,
    tcp_advertise: Vec<SocketAddr>,
    kcp_advertise: Vec<SocketAddr>,
    quic_advertise: Vec<SocketAddr>,
    udp_advertise: Vec<SocketAddr>,
    tcp_advertise_override: bool,
    kcp_advertise_override: bool,
    quic_advertise_override: bool,
    udp_advertise_override: bool,
    seed_addresses: Vec<PeerAddress>,

    backoff_initial: Duration,
    backoff_cap: Duration,
    stale_backoff_cap: Duration,
    stale_backoff_after: Duration,
    reconnect_check_interval: Duration,
    /// How often to give an otherwise unselected peer/transport one
    /// exploratory dial while the outgoing cap is full. Set to zero to disable.
    unselected_link_probe_interval: Duration,
    ping_interval: Duration,
    bandwidth_window: Duration,

    /// How often to send a bandwidth-probe Ping (in addition to the small,
    /// latency-only `ping_interval`). The receiver echoes the payload back as
    /// a Pong so the round trip carries enough bytes to be meaningful.
    /// Set to zero to disable.
    bandwidth_probe_interval: Duration,
    /// Payload size of each bandwidth probe, in bytes. The link's *utilized*
    /// bandwidth meter measures only bytes that actually flowed; the probe
    /// gives a non-zero floor estimate of throughput when the link is idle.
    bandwidth_probe_size: usize,

    inbound_high_capacity: usize,
    inbound_regular_capacity: usize,
    outbound_capacity: usize,

    max_frame_bytes: usize,
    udp_mtu: usize,

    // ── Per-link metrics smoothing ──
    /// EWMA coefficient for the latency estimate.
    latency_ewma_alpha: f64,
    /// EWMA coefficient for the jitter estimate (RFC 3550 uses 1/16).
    jitter_ewma_alpha: f64,
    /// EWMA coefficient for the active-probe throughput estimate.
    throughput_ewma_alpha: f64,

    /// Cap on in-flight pings remembered per stream/UDP session. Older
    /// entries are dropped when the buffer fills, preventing unbounded
    /// memory if pongs are lost.
    max_pending_pings: usize,

    /// Soft cap on live outbound transport sessions. Inbound sessions remain
    /// accepted so a too-low cap cannot isolate this node by itself.
    max_outgoing_connections: usize,
}

impl TransportConfig {
    pub fn new(ca_path: PathBuf, cert_path: PathBuf, key_path: PathBuf) -> Self {
        Self {
            ca_path,
            cert_path,
            key_path,
            tcp_listen: None,
            kcp_listen: None,
            quic_listen: None,
            udp_listen: None,
            tcp_advertise: Vec::new(),
            kcp_advertise: Vec::new(),
            quic_advertise: Vec::new(),
            udp_advertise: Vec::new(),
            tcp_advertise_override: false,
            kcp_advertise_override: false,
            quic_advertise_override: false,
            udp_advertise_override: false,
            seed_addresses: Vec::new(),
            backoff_initial: Duration::from_millis(250),
            backoff_cap: Duration::from_secs(30),
            stale_backoff_cap: Duration::from_secs(10 * 60),
            stale_backoff_after: Duration::from_secs(60 * 60),
            reconnect_check_interval: Duration::from_secs(1),
            unselected_link_probe_interval: Duration::from_secs(30),
            ping_interval: Duration::from_secs(2),
            bandwidth_window: Duration::from_secs(5),
            bandwidth_probe_interval: Duration::from_secs(15),
            bandwidth_probe_size: 4096,
            inbound_high_capacity: 1024,
            inbound_regular_capacity: 1024,
            outbound_capacity: 256,
            max_frame_bytes: 1 << 20,
            udp_mtu: 1200,
            latency_ewma_alpha: 0.2,
            jitter_ewma_alpha: 1.0 / 16.0,
            throughput_ewma_alpha: 0.3,
            max_pending_pings: 64,
            max_outgoing_connections: 1024,
        }
    }

    // --- Getters ---

    pub fn ca_path(&self) -> &Path {
        &self.ca_path
    }

    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    pub fn tcp_listen(&self) -> Option<SocketAddr> {
        self.tcp_listen
    }

    pub fn kcp_listen(&self) -> Option<SocketAddr> {
        self.kcp_listen
    }

    pub fn quic_listen(&self) -> Option<SocketAddr> {
        self.quic_listen
    }

    pub fn udp_listen(&self) -> Option<SocketAddr> {
        self.udp_listen
    }

    pub fn tcp_advertise(&self) -> &[SocketAddr] {
        &self.tcp_advertise
    }

    pub fn kcp_advertise(&self) -> &[SocketAddr] {
        &self.kcp_advertise
    }

    pub fn quic_advertise(&self) -> &[SocketAddr] {
        &self.quic_advertise
    }

    pub fn udp_advertise(&self) -> &[SocketAddr] {
        &self.udp_advertise
    }

    pub fn tcp_advertise_override(&self) -> bool {
        self.tcp_advertise_override
    }

    pub fn kcp_advertise_override(&self) -> bool {
        self.kcp_advertise_override
    }

    pub fn quic_advertise_override(&self) -> bool {
        self.quic_advertise_override
    }

    pub fn udp_advertise_override(&self) -> bool {
        self.udp_advertise_override
    }

    pub fn seed_addresses(&self) -> &[PeerAddress] {
        &self.seed_addresses
    }

    pub fn backoff_initial(&self) -> Duration {
        self.backoff_initial
    }

    pub fn backoff_cap(&self) -> Duration {
        self.backoff_cap
    }

    pub fn stale_backoff_cap(&self) -> Duration {
        self.stale_backoff_cap
    }

    pub fn stale_backoff_after(&self) -> Duration {
        self.stale_backoff_after
    }

    pub fn reconnect_check_interval(&self) -> Duration {
        self.reconnect_check_interval
    }

    pub fn unselected_link_probe_interval(&self) -> Duration {
        self.unselected_link_probe_interval
    }

    pub fn ping_interval(&self) -> Duration {
        self.ping_interval
    }

    pub fn bandwidth_window(&self) -> Duration {
        self.bandwidth_window
    }

    pub fn bandwidth_probe_interval(&self) -> Duration {
        self.bandwidth_probe_interval
    }

    pub fn bandwidth_probe_size(&self) -> usize {
        self.bandwidth_probe_size
    }

    pub fn inbound_high_capacity(&self) -> usize {
        self.inbound_high_capacity
    }

    pub fn inbound_regular_capacity(&self) -> usize {
        self.inbound_regular_capacity
    }

    pub fn outbound_capacity(&self) -> usize {
        self.outbound_capacity
    }

    pub fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }

    pub fn udp_mtu(&self) -> usize {
        self.udp_mtu
    }

    pub fn latency_ewma_alpha(&self) -> f64 {
        self.latency_ewma_alpha
    }

    pub fn jitter_ewma_alpha(&self) -> f64 {
        self.jitter_ewma_alpha
    }

    pub fn throughput_ewma_alpha(&self) -> f64 {
        self.throughput_ewma_alpha
    }

    pub fn max_pending_pings(&self) -> usize {
        self.max_pending_pings
    }

    pub fn max_outgoing_connections(&self) -> usize {
        self.max_outgoing_connections
    }

    // --- Chainable setters ---

    pub fn with_tcp_listen(mut self, addr: SocketAddr) -> Self {
        self.tcp_listen = Some(addr);
        self
    }

    pub fn with_kcp_listen(mut self, addr: SocketAddr) -> Self {
        self.kcp_listen = Some(addr);
        self
    }

    pub fn with_quic_listen(mut self, addr: SocketAddr) -> Self {
        self.quic_listen = Some(addr);
        self
    }

    pub fn with_udp_listen(mut self, addr: SocketAddr) -> Self {
        self.udp_listen = Some(addr);
        self
    }

    pub fn with_tcp_advertise(mut self, addr: SocketAddr) -> Self {
        self.tcp_advertise.push(addr);
        self
    }

    pub fn with_kcp_advertise(mut self, addr: SocketAddr) -> Self {
        self.kcp_advertise.push(addr);
        self
    }

    pub fn with_quic_advertise(mut self, addr: SocketAddr) -> Self {
        self.quic_advertise.push(addr);
        self
    }

    pub fn with_udp_advertise(mut self, addr: SocketAddr) -> Self {
        self.udp_advertise.push(addr);
        self
    }

    pub fn with_tcp_advertise_override(mut self, addr: SocketAddr) -> Self {
        self.tcp_advertise_override = true;
        self.tcp_advertise.push(addr);
        self
    }

    pub fn with_kcp_advertise_override(mut self, addr: SocketAddr) -> Self {
        self.kcp_advertise_override = true;
        self.kcp_advertise.push(addr);
        self
    }

    pub fn with_quic_advertise_override(mut self, addr: SocketAddr) -> Self {
        self.quic_advertise_override = true;
        self.quic_advertise.push(addr);
        self
    }

    pub fn with_udp_advertise_override(mut self, addr: SocketAddr) -> Self {
        self.udp_advertise_override = true;
        self.udp_advertise.push(addr);
        self
    }

    pub fn with_seed_addresses(mut self, addrs: Vec<PeerAddress>) -> Self {
        self.seed_addresses = addrs;
        self
    }

    pub fn with_seed_address(mut self, addr: PeerAddress) -> Self {
        self.seed_addresses.push(addr);
        self
    }

    pub fn with_backoff_initial(mut self, d: Duration) -> Self {
        self.backoff_initial = d;
        self
    }

    pub fn with_backoff_cap(mut self, d: Duration) -> Self {
        self.backoff_cap = d;
        self
    }

    pub fn with_stale_backoff_cap(mut self, d: Duration) -> Self {
        self.stale_backoff_cap = d;
        self
    }

    pub fn with_stale_backoff_after(mut self, d: Duration) -> Self {
        self.stale_backoff_after = d;
        self
    }

    pub fn with_reconnect_check_interval(mut self, d: Duration) -> Self {
        self.reconnect_check_interval = d;
        self
    }

    pub fn with_unselected_link_probe_interval(mut self, d: Duration) -> Self {
        self.unselected_link_probe_interval = d;
        self
    }

    pub fn with_ping_interval(mut self, d: Duration) -> Self {
        self.ping_interval = d;
        self
    }

    pub fn with_bandwidth_window(mut self, d: Duration) -> Self {
        self.bandwidth_window = d;
        self
    }

    pub fn with_bandwidth_probe_interval(mut self, d: Duration) -> Self {
        self.bandwidth_probe_interval = d;
        self
    }

    pub fn with_bandwidth_probe_size(mut self, n: usize) -> Self {
        self.bandwidth_probe_size = n;
        self
    }

    pub fn with_inbound_high_capacity(mut self, n: usize) -> Self {
        self.inbound_high_capacity = n;
        self
    }

    pub fn with_inbound_regular_capacity(mut self, n: usize) -> Self {
        self.inbound_regular_capacity = n;
        self
    }

    pub fn with_outbound_capacity(mut self, n: usize) -> Self {
        self.outbound_capacity = n;
        self
    }

    pub fn with_max_frame_bytes(mut self, n: usize) -> Self {
        self.max_frame_bytes = n;
        self
    }

    pub fn with_udp_mtu(mut self, n: usize) -> Self {
        self.udp_mtu = n;
        self
    }

    pub fn with_latency_ewma_alpha(mut self, v: f64) -> Self {
        self.latency_ewma_alpha = v;
        self
    }

    pub fn with_jitter_ewma_alpha(mut self, v: f64) -> Self {
        self.jitter_ewma_alpha = v;
        self
    }

    pub fn with_throughput_ewma_alpha(mut self, v: f64) -> Self {
        self.throughput_ewma_alpha = v;
        self
    }

    pub fn with_max_pending_pings(mut self, n: usize) -> Self {
        self.max_pending_pings = n;
        self
    }

    pub fn with_max_outgoing_connections(mut self, n: usize) -> Self {
        self.max_outgoing_connections = n;
        self
    }
}

/// TOML-deserializable shadow of the per-link metrics smoothing, ping-cap,
/// and connection-selection knobs. Only these tunables are surfaced here; other [`TransportConfig`]
/// fields (listen addrs, PKI paths, queue sizes, etc.) stay Rust-builder-
/// only for now.
#[derive(Deserialize, Debug, Clone)]
pub struct TransportTuning {
    #[serde(default = "default_latency_ewma_alpha")]
    pub latency_ewma_alpha: f64,
    #[serde(default = "default_jitter_ewma_alpha")]
    pub jitter_ewma_alpha: f64,
    #[serde(default = "default_throughput_ewma_alpha")]
    pub throughput_ewma_alpha: f64,
    #[serde(default = "default_max_pending_pings")]
    pub max_pending_pings: usize,
    #[serde(default = "default_recent_probe_retry_cap_secs")]
    pub recent_probe_retry_cap_secs: u64,
    #[serde(default = "default_stale_probe_retry_cap_secs")]
    pub stale_probe_retry_cap_secs: u64,
    #[serde(default = "default_stale_probe_age_secs")]
    pub stale_probe_age_secs: u64,
    #[serde(default = "default_unselected_link_probe_interval_secs")]
    pub unselected_link_probe_interval_secs: u64,
    #[serde(default = "default_max_outgoing_connections")]
    pub max_outgoing_connections: usize,
}

impl Default for TransportTuning {
    fn default() -> Self {
        Self {
            latency_ewma_alpha: default_latency_ewma_alpha(),
            jitter_ewma_alpha: default_jitter_ewma_alpha(),
            throughput_ewma_alpha: default_throughput_ewma_alpha(),
            max_pending_pings: default_max_pending_pings(),
            recent_probe_retry_cap_secs: default_recent_probe_retry_cap_secs(),
            stale_probe_retry_cap_secs: default_stale_probe_retry_cap_secs(),
            stale_probe_age_secs: default_stale_probe_age_secs(),
            unselected_link_probe_interval_secs: default_unselected_link_probe_interval_secs(),
            max_outgoing_connections: default_max_outgoing_connections(),
        }
    }
}

impl TransportTuning {
    /// Apply the tunables on top of an existing `TransportConfig`.
    pub fn apply(&self, cfg: TransportConfig) -> TransportConfig {
        cfg.with_latency_ewma_alpha(self.latency_ewma_alpha)
            .with_jitter_ewma_alpha(self.jitter_ewma_alpha)
            .with_throughput_ewma_alpha(self.throughput_ewma_alpha)
            .with_max_pending_pings(self.max_pending_pings)
            .with_backoff_cap(Duration::from_secs(self.recent_probe_retry_cap_secs))
            .with_stale_backoff_cap(Duration::from_secs(self.stale_probe_retry_cap_secs))
            .with_stale_backoff_after(Duration::from_secs(self.stale_probe_age_secs))
            .with_unselected_link_probe_interval(Duration::from_secs(
                self.unselected_link_probe_interval_secs,
            ))
            .with_max_outgoing_connections(self.max_outgoing_connections)
    }
}

fn default_latency_ewma_alpha() -> f64 {
    0.2
}
fn default_jitter_ewma_alpha() -> f64 {
    1.0 / 16.0
}
fn default_throughput_ewma_alpha() -> f64 {
    0.3
}
fn default_max_pending_pings() -> usize {
    64
}
fn default_recent_probe_retry_cap_secs() -> u64 {
    30
}
fn default_stale_probe_retry_cap_secs() -> u64 {
    10 * 60
}
fn default_stale_probe_age_secs() -> u64 {
    60 * 60
}
fn default_unselected_link_probe_interval_secs() -> u64 {
    30
}
fn default_max_outgoing_connections() -> usize {
    1024
}
