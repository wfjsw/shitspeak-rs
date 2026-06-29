use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use super::compression::{
    CompressionConfig, adaptive_dictionary_cache_file,
    default_compression_adaptive_dictionary_enabled, default_compression_enabled,
    default_compression_level, default_compression_min_bytes,
    default_compression_min_savings_percent,
};
use super::service_level::{PeerAddress, SeedAddress};

/// Knobs for [`super::ConnectionManager::start`]. All listeners are optional —
/// at least one must be set or [`super::ConfigError::NoListener`] is returned.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    ca_path: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,

    tcp_listen: Vec<SocketAddr>,
    kcp_listen: Vec<SocketAddr>,
    quic_listen: Vec<SocketAddr>,
    udp_listen: Vec<SocketAddr>,
    tcp_advertise: Vec<SocketAddr>,
    kcp_advertise: Vec<SocketAddr>,
    quic_advertise: Vec<SocketAddr>,
    udp_advertise: Vec<SocketAddr>,
    tcp_advertise_override: bool,
    kcp_advertise_override: bool,
    quic_advertise_override: bool,
    udp_advertise_override: bool,
    seed_addresses: Vec<PeerAddress>,
    seed_targets: Vec<SeedAddress>,

    backoff_initial: Duration,
    backoff_cap: Duration,
    stale_backoff_cap: Duration,
    stale_backoff_after: Duration,
    unconfirmed_address_retry_floor: Duration,
    unconfirmed_address_retry_cap: Duration,
    unconfirmed_address_decay_failures: u32,
    reconnect_check_interval: Duration,
    /// Per-address outbound dial deadline. Zero disables the deadline.
    dial_attempt_timeout: Duration,
    /// How often to give an otherwise unselected peer/transport one
    /// exploratory dial while the outgoing cap is full. Set to zero to disable.
    unselected_link_probe_interval: Duration,
    ping_interval: Duration,
    idle_ping_interval: Duration,
    bandwidth_window: Duration,

    /// Deprecated no-op retained so older config files and tests still parse.
    bandwidth_probe_interval: Duration,
    /// Deprecated no-op retained so older config files and tests still parse.
    bandwidth_probe_size: usize,

    inbound_control_capacity: usize,
    inbound_high_capacity: usize,
    inbound_regular_capacity: usize,
    outbound_capacity: usize,

    max_frame_bytes: usize,
    udp_mtu: usize,
    compression: CompressionConfig,

    // ── Per-link metrics smoothing ──
    /// EWMA coefficient for the latency estimate.
    latency_ewma_alpha: f64,
    /// EWMA coefficient for the jitter estimate (RFC 3550 uses 1/16).
    jitter_ewma_alpha: f64,
    /// EWMA coefficient for the long-term packet-loss estimate.
    packet_loss_ewma_alpha: f64,
    /// How often stream transports sample native transport loss counters.
    /// Set to zero to disable native sampling.
    native_stats_interval: Duration,

    /// Cap on in-flight pings remembered per stream/UDP session. Older
    /// entries are dropped when the buffer fills, preventing unbounded
    /// memory if pongs are lost.
    max_pending_pings: usize,

    /// Soft cap on live outbound transport sessions. Inbound sessions remain
    /// accepted so a too-low cap cannot isolate this node by itself.
    max_outgoing_connections: usize,

    /// Whether private listen/advertise addresses should be published in the
    /// overlay. LAN/VPN/container clusters usually need this enabled.
    advertise_private_ips: bool,

    /// Local interface names whose addresses should be published when listen
    /// addresses need automatic advertise expansion.
    local_advertise_interfaces: Vec<String>,
}

impl TransportConfig {
    pub fn new(ca_path: PathBuf, cert_path: PathBuf, key_path: PathBuf) -> Self {
        Self {
            ca_path,
            cert_path,
            key_path,
            tcp_listen: Vec::new(),
            kcp_listen: Vec::new(),
            quic_listen: Vec::new(),
            udp_listen: Vec::new(),
            tcp_advertise: Vec::new(),
            kcp_advertise: Vec::new(),
            quic_advertise: Vec::new(),
            udp_advertise: Vec::new(),
            tcp_advertise_override: false,
            kcp_advertise_override: false,
            quic_advertise_override: false,
            udp_advertise_override: false,
            seed_addresses: Vec::new(),
            seed_targets: Vec::new(),
            backoff_initial: Duration::from_millis(250),
            backoff_cap: Duration::from_secs(30),
            stale_backoff_cap: Duration::from_secs(10 * 60),
            stale_backoff_after: Duration::from_secs(60 * 60),
            unconfirmed_address_retry_floor: Duration::from_secs(5 * 60),
            unconfirmed_address_retry_cap: Duration::from_secs(30 * 60),
            unconfirmed_address_decay_failures: 5,
            reconnect_check_interval: Duration::from_secs(1),
            dial_attempt_timeout: Duration::from_secs(10),
            unselected_link_probe_interval: Duration::from_secs(30),
            ping_interval: Duration::from_secs(2),
            idle_ping_interval: Duration::from_secs(10),
            bandwidth_window: Duration::from_secs(5),
            bandwidth_probe_interval: Duration::ZERO,
            bandwidth_probe_size: 0,
            inbound_control_capacity: 1024,
            inbound_high_capacity: 1024,
            inbound_regular_capacity: 1024,
            outbound_capacity: 256,
            max_frame_bytes: 1 << 20,
            udp_mtu: 1200,
            compression: CompressionConfig::default(),
            latency_ewma_alpha: 0.2,
            jitter_ewma_alpha: 1.0 / 16.0,
            packet_loss_ewma_alpha: 0.02,
            native_stats_interval: Duration::from_secs(1),
            max_pending_pings: 64,
            max_outgoing_connections: 1024,
            advertise_private_ips: true,
            local_advertise_interfaces: Vec::new(),
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
        self.tcp_listen.first().copied()
    }

    pub fn kcp_listen(&self) -> Option<SocketAddr> {
        self.kcp_listen.first().copied()
    }

    pub fn quic_listen(&self) -> Option<SocketAddr> {
        self.quic_listen.first().copied()
    }

    pub fn udp_listen(&self) -> Option<SocketAddr> {
        self.udp_listen.first().copied()
    }

    pub fn tcp_listen_addrs(&self) -> &[SocketAddr] {
        &self.tcp_listen
    }

    pub fn kcp_listen_addrs(&self) -> &[SocketAddr] {
        &self.kcp_listen
    }

    pub fn quic_listen_addrs(&self) -> &[SocketAddr] {
        &self.quic_listen
    }

    pub fn udp_listen_addrs(&self) -> &[SocketAddr] {
        &self.udp_listen
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

    pub fn seed_address_count(&self) -> usize {
        self.seed_addresses
            .len()
            .saturating_add(self.seed_targets.len())
    }

    pub fn seed_targets(&self) -> Vec<SeedAddress> {
        let mut targets = self.seed_targets.clone();
        targets.extend(
            self.seed_addresses
                .iter()
                .copied()
                .map(SeedAddress::from_peer_address),
        );
        targets
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

    pub fn unconfirmed_address_retry_floor(&self) -> Duration {
        self.unconfirmed_address_retry_floor
    }

    pub fn unconfirmed_address_retry_cap(&self) -> Duration {
        self.unconfirmed_address_retry_cap
    }

    pub fn unconfirmed_address_decay_failures(&self) -> u32 {
        self.unconfirmed_address_decay_failures
    }

    pub fn reconnect_check_interval(&self) -> Duration {
        self.reconnect_check_interval
    }

    pub fn dial_attempt_timeout(&self) -> Duration {
        self.dial_attempt_timeout
    }

    pub fn unselected_link_probe_interval(&self) -> Duration {
        self.unselected_link_probe_interval
    }

    pub fn ping_interval(&self) -> Duration {
        self.ping_interval
    }
    pub fn idle_ping_interval(&self) -> Duration {
        self.idle_ping_interval
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

    pub fn inbound_control_capacity(&self) -> usize {
        self.inbound_control_capacity
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

    pub fn compression_enabled(&self) -> bool {
        self.compression.enabled()
    }

    pub fn compression_min_bytes(&self) -> usize {
        self.compression.min_bytes()
    }

    pub fn compression_min_savings_percent(&self) -> u8 {
        self.compression.min_savings_percent()
    }

    pub fn compression_level(&self) -> i32 {
        self.compression.level()
    }

    pub fn compression_adaptive_dictionary_enabled(&self) -> bool {
        self.compression.adaptive_dictionary_enabled()
    }

    pub fn compression_dictionary_len(&self) -> Option<usize> {
        self.compression.dictionary_len()
    }

    pub fn compression_cached_adaptive_dictionary_len(&self) -> Option<usize> {
        self.compression
            .cached_adaptive_dictionary()
            .as_ref()
            .map(|dict| dict.len())
    }

    pub fn compression_dictionary_id(&self) -> Option<u32> {
        self.compression.dictionary_id()
    }

    pub(crate) fn compression_config(&self) -> &CompressionConfig {
        &self.compression
    }

    pub fn latency_ewma_alpha(&self) -> f64 {
        self.latency_ewma_alpha
    }

    pub fn jitter_ewma_alpha(&self) -> f64 {
        self.jitter_ewma_alpha
    }

    pub fn packet_loss_ewma_alpha(&self) -> f64 {
        self.packet_loss_ewma_alpha
    }

    pub fn native_stats_interval(&self) -> Duration {
        self.native_stats_interval
    }

    pub fn max_pending_pings(&self) -> usize {
        self.max_pending_pings
    }

    pub fn max_outgoing_connections(&self) -> usize {
        self.max_outgoing_connections
    }

    pub fn advertise_private_ips(&self) -> bool {
        self.advertise_private_ips
    }

    pub fn local_advertise_interfaces(&self) -> &[String] {
        &self.local_advertise_interfaces
    }

    // --- Chainable setters ---

    pub fn with_tcp_listen(mut self, addr: SocketAddr) -> Self {
        push_unique_socket_addr(&mut self.tcp_listen, addr);
        self
    }

    pub fn with_kcp_listen(mut self, addr: SocketAddr) -> Self {
        push_unique_socket_addr(&mut self.kcp_listen, addr);
        self
    }

    pub fn with_quic_listen(mut self, addr: SocketAddr) -> Self {
        push_unique_socket_addr(&mut self.quic_listen, addr);
        self
    }

    pub fn with_udp_listen(mut self, addr: SocketAddr) -> Self {
        push_unique_socket_addr(&mut self.udp_listen, addr);
        self
    }

    pub fn with_tcp_listen_addrs(mut self, addrs: impl IntoIterator<Item = SocketAddr>) -> Self {
        for addr in addrs {
            push_unique_socket_addr(&mut self.tcp_listen, addr);
        }
        self
    }

    pub fn with_kcp_listen_addrs(mut self, addrs: impl IntoIterator<Item = SocketAddr>) -> Self {
        for addr in addrs {
            push_unique_socket_addr(&mut self.kcp_listen, addr);
        }
        self
    }

    pub fn with_quic_listen_addrs(mut self, addrs: impl IntoIterator<Item = SocketAddr>) -> Self {
        for addr in addrs {
            push_unique_socket_addr(&mut self.quic_listen, addr);
        }
        self
    }

    pub fn with_udp_listen_addrs(mut self, addrs: impl IntoIterator<Item = SocketAddr>) -> Self {
        for addr in addrs {
            push_unique_socket_addr(&mut self.udp_listen, addr);
        }
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

    pub fn with_seed_targets(mut self, targets: Vec<SeedAddress>) -> Self {
        self.seed_targets = targets;
        self
    }

    pub fn with_seed_target(mut self, target: SeedAddress) -> Self {
        self.seed_targets.push(target);
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

    pub fn with_unconfirmed_address_retry_floor(mut self, d: Duration) -> Self {
        self.unconfirmed_address_retry_floor = d;
        self
    }

    pub fn with_unconfirmed_address_retry_cap(mut self, d: Duration) -> Self {
        self.unconfirmed_address_retry_cap = d;
        self
    }

    pub fn with_unconfirmed_address_decay_failures(mut self, failures: u32) -> Self {
        self.unconfirmed_address_decay_failures = failures;
        self
    }

    pub fn with_reconnect_check_interval(mut self, d: Duration) -> Self {
        self.reconnect_check_interval = d;
        self
    }

    pub fn with_dial_attempt_timeout(mut self, d: Duration) -> Self {
        self.dial_attempt_timeout = d;
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

    pub fn with_idle_ping_interval(mut self, d: Duration) -> Self {
        self.idle_ping_interval = d;
        self
    }

    pub fn with_bandwidth_window(mut self, d: Duration) -> Self {
        self.bandwidth_window = d;
        self
    }

    pub fn with_bandwidth_probe_interval(mut self, d: Duration) -> Self {
        let _ = d;
        self.bandwidth_probe_interval = Duration::ZERO;
        self
    }

    pub fn with_bandwidth_probe_size(mut self, n: usize) -> Self {
        let _ = n;
        self.bandwidth_probe_size = 0;
        self
    }

    pub fn with_inbound_control_capacity(mut self, n: usize) -> Self {
        self.inbound_control_capacity = n;
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

    pub fn with_compression_enabled(mut self, enabled: bool) -> Self {
        self.compression = self.compression.with_enabled(enabled);
        self
    }

    pub fn with_compression_min_bytes(mut self, n: usize) -> Self {
        self.compression = self.compression.with_min_bytes(n);
        self
    }

    pub fn with_compression_min_savings_percent(mut self, percent: u8) -> Self {
        self.compression = self.compression.with_min_savings_percent(percent);
        self
    }

    pub fn with_compression_level(mut self, level: i32) -> Self {
        self.compression = self.compression.with_level(level);
        self
    }

    pub fn with_compression_adaptive_dictionary_enabled(mut self, enabled: bool) -> Self {
        self.compression = self.compression.with_adaptive_dictionary_enabled(enabled);
        self
    }

    pub fn try_with_compression_dictionary_bytes(
        mut self,
        dictionary: Vec<u8>,
    ) -> io::Result<Self> {
        self.compression = self.compression.with_dictionary_bytes(dictionary)?;
        Ok(self)
    }

    pub fn without_compression_dictionary(mut self) -> Self {
        self.compression = self.compression.without_dictionary();
        self
    }

    pub fn with_compression_adaptive_dictionary_cache_dir(
        mut self,
        persistence_dir: PathBuf,
    ) -> Self {
        self.compression = self
            .compression
            .with_adaptive_dictionary_cache_file(adaptive_dictionary_cache_file(&persistence_dir));
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

    pub fn with_packet_loss_ewma_alpha(mut self, v: f64) -> Self {
        self.packet_loss_ewma_alpha = v;
        self
    }

    pub fn with_native_stats_interval(mut self, d: Duration) -> Self {
        self.native_stats_interval = d;
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

    pub fn with_advertise_private_ips(mut self, enabled: bool) -> Self {
        self.advertise_private_ips = enabled;
        self
    }

    pub fn with_local_advertise_interfaces(
        mut self,
        interfaces: impl IntoIterator<Item = String>,
    ) -> Self {
        self.local_advertise_interfaces.clear();
        for interface in interfaces {
            let interface = interface.trim();
            if !interface.is_empty()
                && !self
                    .local_advertise_interfaces
                    .iter()
                    .any(|existing| existing.eq_ignore_ascii_case(interface))
            {
                self.local_advertise_interfaces.push(interface.to_string());
            }
        }
        self
    }
}

fn push_unique_socket_addr(out: &mut Vec<SocketAddr>, addr: SocketAddr) {
    if !out.contains(&addr) {
        out.push(addr);
    }
}

/// TOML-deserializable shadow of the per-link metrics smoothing, ping-cap,
/// queue-size, and connection-selection knobs. Listener, advertise, PKI, and
/// seed fields stay on the higher-level S2S config because they need custom
/// parsing and validation.
#[derive(Deserialize, Debug, Clone)]
pub struct TransportTuning {
    #[serde(default = "default_latency_ewma_alpha")]
    pub latency_ewma_alpha: f64,
    #[serde(default = "default_jitter_ewma_alpha")]
    pub jitter_ewma_alpha: f64,
    #[serde(default = "default_packet_loss_ewma_alpha")]
    pub packet_loss_ewma_alpha: f64,
    #[serde(default = "default_ping_interval_secs")]
    pub ping_interval_secs: u64,
    #[serde(default = "default_idle_ping_interval_secs")]
    pub idle_ping_interval_secs: u64,
    #[serde(default = "default_native_stats_interval_secs")]
    pub native_stats_interval_secs: u64,
    #[serde(default = "default_max_pending_pings")]
    pub max_pending_pings: usize,
    #[serde(default = "default_recent_probe_retry_cap_secs")]
    pub recent_probe_retry_cap_secs: u64,
    #[serde(default = "default_stale_probe_retry_cap_secs")]
    pub stale_probe_retry_cap_secs: u64,
    #[serde(default = "default_stale_probe_age_secs")]
    pub stale_probe_age_secs: u64,
    #[serde(default = "default_unconfirmed_address_retry_floor_secs")]
    pub unconfirmed_address_retry_floor_secs: u64,
    #[serde(default = "default_unconfirmed_address_retry_cap_secs")]
    pub unconfirmed_address_retry_cap_secs: u64,
    #[serde(default = "default_unconfirmed_address_decay_failures")]
    pub unconfirmed_address_decay_failures: u32,
    /// Per-address outbound dial deadline. Set to zero to disable.
    #[serde(default = "default_dial_attempt_timeout_secs")]
    pub dial_attempt_timeout_secs: u64,
    #[serde(default = "default_unselected_link_probe_interval_secs")]
    pub unselected_link_probe_interval_secs: u64,
    #[serde(default = "default_max_outgoing_connections")]
    pub max_outgoing_connections: usize,
    #[serde(default = "default_inbound_control_capacity")]
    inbound_control_capacity: usize,
    #[serde(default = "default_inbound_high_capacity")]
    inbound_high_capacity: usize,
    #[serde(default = "default_inbound_regular_capacity")]
    inbound_regular_capacity: usize,
    #[serde(default = "default_outbound_capacity")]
    outbound_capacity: usize,
    #[serde(default = "default_compression_enabled")]
    compression_enabled: bool,
    #[serde(default = "default_compression_min_bytes")]
    compression_min_bytes: usize,
    #[serde(default = "default_compression_min_savings_percent")]
    compression_min_savings_percent: u8,
    #[serde(default = "default_compression_level")]
    compression_level: i32,
    #[serde(default = "default_compression_adaptive_dictionary_enabled")]
    compression_adaptive_dictionary_enabled: bool,
    /// Optional static zstd dictionary file for L1 payload compression. Stream
    /// peers require a matching dictionary fingerprint before static
    /// dictionary frames are sent; UDP has no dictionary negotiation.
    #[serde(default)]
    compression_dictionary_path: Option<PathBuf>,
}

impl Default for TransportTuning {
    fn default() -> Self {
        Self {
            latency_ewma_alpha: default_latency_ewma_alpha(),
            jitter_ewma_alpha: default_jitter_ewma_alpha(),
            packet_loss_ewma_alpha: default_packet_loss_ewma_alpha(),
            ping_interval_secs: default_ping_interval_secs(),
            idle_ping_interval_secs: default_idle_ping_interval_secs(),
            native_stats_interval_secs: default_native_stats_interval_secs(),
            max_pending_pings: default_max_pending_pings(),
            recent_probe_retry_cap_secs: default_recent_probe_retry_cap_secs(),
            stale_probe_retry_cap_secs: default_stale_probe_retry_cap_secs(),
            stale_probe_age_secs: default_stale_probe_age_secs(),
            unconfirmed_address_retry_floor_secs: default_unconfirmed_address_retry_floor_secs(),
            unconfirmed_address_retry_cap_secs: default_unconfirmed_address_retry_cap_secs(),
            unconfirmed_address_decay_failures: default_unconfirmed_address_decay_failures(),
            dial_attempt_timeout_secs: default_dial_attempt_timeout_secs(),
            unselected_link_probe_interval_secs: default_unselected_link_probe_interval_secs(),
            max_outgoing_connections: default_max_outgoing_connections(),
            inbound_control_capacity: default_inbound_control_capacity(),
            inbound_high_capacity: default_inbound_high_capacity(),
            inbound_regular_capacity: default_inbound_regular_capacity(),
            outbound_capacity: default_outbound_capacity(),
            compression_enabled: default_compression_enabled(),
            compression_min_bytes: default_compression_min_bytes(),
            compression_min_savings_percent: default_compression_min_savings_percent(),
            compression_level: default_compression_level(),
            compression_adaptive_dictionary_enabled:
                default_compression_adaptive_dictionary_enabled(),
            compression_dictionary_path: None,
        }
    }
}

impl TransportTuning {
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_outbound_capacity_for_test(&mut self, n: usize) {
        self.outbound_capacity = n.max(1);
    }

    /// Apply the tunables on top of an existing `TransportConfig`.
    pub fn apply(&self, cfg: TransportConfig) -> TransportConfig {
        cfg.with_latency_ewma_alpha(self.latency_ewma_alpha)
            .with_jitter_ewma_alpha(self.jitter_ewma_alpha)
            .with_packet_loss_ewma_alpha(self.packet_loss_ewma_alpha)
            .with_ping_interval(Duration::from_secs(self.ping_interval_secs))
            .with_idle_ping_interval(Duration::from_secs(self.idle_ping_interval_secs))
            .with_native_stats_interval(Duration::from_secs(self.native_stats_interval_secs))
            .with_max_pending_pings(self.max_pending_pings)
            .with_backoff_cap(Duration::from_secs(self.recent_probe_retry_cap_secs))
            .with_stale_backoff_cap(Duration::from_secs(self.stale_probe_retry_cap_secs))
            .with_stale_backoff_after(Duration::from_secs(self.stale_probe_age_secs))
            .with_unconfirmed_address_retry_floor(Duration::from_secs(
                self.unconfirmed_address_retry_floor_secs,
            ))
            .with_unconfirmed_address_retry_cap(Duration::from_secs(
                self.unconfirmed_address_retry_cap_secs,
            ))
            .with_unconfirmed_address_decay_failures(self.unconfirmed_address_decay_failures)
            .with_dial_attempt_timeout(Duration::from_secs(self.dial_attempt_timeout_secs))
            .with_unselected_link_probe_interval(Duration::from_secs(
                self.unselected_link_probe_interval_secs,
            ))
            .with_max_outgoing_connections(self.max_outgoing_connections)
            .with_inbound_control_capacity(self.inbound_control_capacity.max(1))
            .with_inbound_high_capacity(self.inbound_high_capacity.max(1))
            .with_inbound_regular_capacity(self.inbound_regular_capacity.max(1))
            .with_outbound_capacity(self.outbound_capacity.max(1))
            .with_compression_enabled(self.compression_enabled)
            .with_compression_min_bytes(self.compression_min_bytes)
            .with_compression_min_savings_percent(self.compression_min_savings_percent)
            .with_compression_level(self.compression_level)
            .with_compression_adaptive_dictionary_enabled(
                self.compression_adaptive_dictionary_enabled,
            )
    }

    /// Apply tunables and load the optional compression dictionary from disk.
    pub fn try_apply(&self, cfg: TransportConfig) -> Result<TransportConfig, String> {
        let mut cfg = self.apply(cfg);
        if let Some(path) = &self.compression_dictionary_path {
            let dictionary = fs::read(path).map_err(|e| {
                format!(
                    "failed to read s2s.transport.compression_dictionary_path {}: {e}",
                    path.display()
                )
            })?;
            cfg = cfg
                .try_with_compression_dictionary_bytes(dictionary)
                .map_err(|e| {
                    format!(
                        "invalid s2s.transport.compression_dictionary_path {}: {e}",
                        path.display()
                    )
                })?;
        }
        Ok(cfg)
    }
}

fn default_latency_ewma_alpha() -> f64 {
    0.2
}
fn default_jitter_ewma_alpha() -> f64 {
    1.0 / 16.0
}
fn default_packet_loss_ewma_alpha() -> f64 {
    0.02
}
fn default_ping_interval_secs() -> u64 {
    2
}
fn default_idle_ping_interval_secs() -> u64 {
    10
}
fn default_native_stats_interval_secs() -> u64 {
    1
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
fn default_unconfirmed_address_retry_floor_secs() -> u64 {
    5 * 60
}
fn default_unconfirmed_address_retry_cap_secs() -> u64 {
    30 * 60
}
fn default_unconfirmed_address_decay_failures() -> u32 {
    5
}
fn default_dial_attempt_timeout_secs() -> u64 {
    10
}
fn default_unselected_link_probe_interval_secs() -> u64 {
    30
}
fn default_max_outgoing_connections() -> usize {
    1024
}
fn default_inbound_control_capacity() -> usize {
    1024
}
fn default_inbound_high_capacity() -> usize {
    1024
}
fn default_inbound_regular_capacity() -> usize {
    1024
}
fn default_outbound_capacity() -> usize {
    256
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> TransportConfig {
        TransportConfig::new("ca.pem".into(), "cert.pem".into(), "key.pem".into())
    }

    #[test]
    fn deprecated_bandwidth_probe_builders_are_noops() {
        let cfg = base_config()
            .with_bandwidth_probe_interval(Duration::from_secs(5))
            .with_bandwidth_probe_size(65_536);

        assert_eq!(cfg.bandwidth_probe_interval(), Duration::ZERO);
        assert_eq!(cfg.bandwidth_probe_size(), 0);
    }

    #[test]
    fn deprecated_noop_tuning_keys_parse_without_enabling_probes() {
        let tuning: TransportTuning = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    throughput_ewma_alpha = 0.75
                    bandwidth_probe_interval_secs = 2
                    bandwidth_probe_size = 65536
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("transport tuning parses");
        let cfg = tuning.apply(base_config());

        assert_eq!(cfg.bandwidth_probe_interval(), Duration::ZERO);
        assert_eq!(cfg.bandwidth_probe_size(), 0);
    }

    #[test]
    fn transport_tuning_applies_queue_capacities() {
        let tuning: TransportTuning = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    inbound_control_capacity = 2048
                    inbound_high_capacity = 4096
                    inbound_regular_capacity = 65536
                    outbound_capacity = 8192
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("transport tuning parses");
        let cfg = tuning.apply(base_config());

        assert_eq!(cfg.inbound_control_capacity(), 2048);
        assert_eq!(cfg.inbound_high_capacity(), 4096);
        assert_eq!(cfg.inbound_regular_capacity(), 65_536);
        assert_eq!(cfg.outbound_capacity(), 8192);
    }
}
