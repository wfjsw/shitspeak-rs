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
    /// How long to suppress a seed target that resolves back to this node.
    self_seed_quarantine: Duration,
    /// How often to give an otherwise unselected peer/transport one
    /// exploratory dial while the outgoing cap is full. Set to zero to disable.
    unselected_link_probe_interval: Duration,
    /// Max address/transport dial attempts spawned for one peer in one
    /// supervisor tick.
    max_dial_attempts_per_peer_tick: usize,
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
    kcp_tuning: KcpTuning,
    stream_write_timeout: Duration,
    /// Maximum time allowed to establish and acknowledge all required QUIC v2 lanes.
    quic_session_setup_timeout: Duration,
    /// Quinn's unreliable DATAGRAM send-buffer budget. Zero disables sending.
    quic_datagram_send_buffer_bytes: usize,
    /// Quinn's unreliable DATAGRAM receive-buffer budget. Zero disables receiving.
    quic_datagram_receive_buffer_bytes: usize,
    /// Test seam for emulating an older peer that only advertises s2s/1.
    quic_alpn_protocols_override: Option<Vec<Vec<u8>>>,
    compression: CompressionConfig,
    routing_policy: TransportRoutingPolicy,

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

    /// Local server user cap used to size transport burst buffers that absorb
    /// fanout proportional to the number of clients this node can host.
    max_users: usize,

    /// Whether private listen/advertise addresses should be published in the
    /// overlay. LAN/VPN/container clusters usually need this enabled.
    advertise_private_ips: bool,

    /// Local interface names whose addresses should be published when listen
    /// addresses need automatic advertise expansion.
    local_advertise_interfaces: Vec<String>,

    /// Failures while resolving implicit advertise candidates. They are
    /// retained until all address-discovery sources have been considered so
    /// startup can decide whether S2S has any usable advertised address.
    implicit_advertise_failures: Vec<String>,
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
            self_seed_quarantine: Duration::from_secs(60 * 60),
            unselected_link_probe_interval: Duration::from_secs(30),
            max_dial_attempts_per_peer_tick: 1,
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
            kcp_tuning: KcpTuning::default(),
            stream_write_timeout: Duration::from_millis(default_stream_write_timeout_ms()),
            quic_session_setup_timeout: Duration::from_millis(
                default_quic_session_setup_timeout_ms(),
            ),
            quic_datagram_send_buffer_bytes: default_quic_datagram_send_buffer_bytes(),
            quic_datagram_receive_buffer_bytes: default_quic_datagram_receive_buffer_bytes(),
            quic_alpn_protocols_override: None,
            compression: CompressionConfig::default(),
            routing_policy: TransportRoutingPolicy::default(),
            latency_ewma_alpha: 0.2,
            jitter_ewma_alpha: 1.0 / 16.0,
            packet_loss_ewma_alpha: 0.02,
            native_stats_interval: Duration::from_secs(1),
            max_pending_pings: 64,
            max_outgoing_connections: 1024,
            max_users: 100,
            advertise_private_ips: true,
            local_advertise_interfaces: Vec::new(),
            implicit_advertise_failures: Vec::new(),
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

    pub fn self_seed_quarantine(&self) -> Duration {
        self.self_seed_quarantine
    }

    pub fn unselected_link_probe_interval(&self) -> Duration {
        self.unselected_link_probe_interval
    }

    pub fn max_dial_attempts_per_peer_tick(&self) -> usize {
        self.max_dial_attempts_per_peer_tick
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

    pub fn kcp_tuning(&self) -> KcpTuning {
        self.kcp_tuning
    }

    pub fn stream_write_timeout(&self) -> Duration {
        self.stream_write_timeout
    }

    pub fn quic_session_setup_timeout(&self) -> Duration {
        self.quic_session_setup_timeout
    }

    pub fn quic_datagram_send_buffer_bytes(&self) -> usize {
        self.quic_datagram_send_buffer_bytes
    }

    pub fn quic_datagram_receive_buffer_bytes(&self) -> usize {
        self.quic_datagram_receive_buffer_bytes
    }

    pub(crate) fn quic_alpn_protocols_override(&self) -> Option<&[Vec<u8>]> {
        self.quic_alpn_protocols_override.as_deref()
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

    pub fn routing_policy(&self) -> TransportRoutingPolicy {
        self.routing_policy
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

    pub fn max_users(&self) -> usize {
        self.max_users
    }

    pub fn advertise_private_ips(&self) -> bool {
        self.advertise_private_ips
    }

    pub fn local_advertise_interfaces(&self) -> &[String] {
        &self.local_advertise_interfaces
    }

    pub fn implicit_advertise_failures(&self) -> &[String] {
        &self.implicit_advertise_failures
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

    pub fn with_self_seed_quarantine(mut self, d: Duration) -> Self {
        self.self_seed_quarantine = d;
        self
    }

    pub fn with_unselected_link_probe_interval(mut self, d: Duration) -> Self {
        self.unselected_link_probe_interval = d;
        self
    }

    pub fn with_max_dial_attempts_per_peer_tick(mut self, n: usize) -> Self {
        self.max_dial_attempts_per_peer_tick = n.max(1);
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

    pub fn with_kcp_tuning(mut self, tuning: KcpTuning) -> Self {
        self.kcp_tuning = tuning;
        self
    }

    pub fn with_stream_write_timeout(mut self, timeout: Duration) -> Self {
        self.stream_write_timeout = timeout;
        self
    }

    pub fn with_quic_session_setup_timeout(mut self, timeout: Duration) -> Self {
        self.quic_session_setup_timeout = timeout;
        self
    }

    pub fn with_quic_datagram_send_buffer_bytes(mut self, bytes: usize) -> Self {
        self.quic_datagram_send_buffer_bytes = bytes;
        self
    }

    pub fn with_quic_datagram_receive_buffer_bytes(mut self, bytes: usize) -> Self {
        self.quic_datagram_receive_buffer_bytes = bytes;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_quic_v1_only_for_test(mut self) -> Self {
        self.quic_alpn_protocols_override = Some(vec![b"s2s/1".to_vec()]);
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

    pub fn with_routing_policy(mut self, policy: TransportRoutingPolicy) -> Self {
        self.routing_policy = policy;
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

    pub fn with_max_users(mut self, n: usize) -> Self {
        self.max_users = n.max(1);
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

    pub fn with_implicit_advertise_failure(mut self, failure: String) -> Self {
        if !self.implicit_advertise_failures.contains(&failure) {
            self.implicit_advertise_failures.push(failure);
        }
        self
    }
}

fn push_unique_socket_addr(out: &mut Vec<SocketAddr>, addr: SocketAddr) {
    if !out.contains(&addr) {
        out.push(addr);
    }
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct KcpTuning {
    #[serde(default = "default_kcp_nodelay")]
    nodelay: bool,
    #[serde(default = "default_kcp_interval_ms")]
    interval_ms: u32,
    #[serde(default = "default_kcp_fast_resend")]
    fast_resend: u32,
    #[serde(default = "default_kcp_no_congestion")]
    no_congestion: bool,
    #[serde(default = "default_kcp_flush_write")]
    flush_write: bool,
    #[serde(default = "default_kcp_flush_acks_input")]
    flush_acks_input: bool,
    #[serde(
        default = "default_kcp_failaway_with_alternative_ms",
        alias = "kcp_failaway_with_alternative_ms"
    )]
    failaway_with_alternative_ms: u64,
    #[serde(
        default = "default_kcp_failaway_without_alternative_ms",
        alias = "kcp_failaway_without_alternative_ms"
    )]
    failaway_without_alternative_ms: u64,
    #[serde(
        default = "default_kcp_no_progress_close_ms",
        alias = "kcp_no_progress_close_ms"
    )]
    no_progress_close_ms: u64,
}

impl Default for KcpTuning {
    fn default() -> Self {
        Self {
            nodelay: default_kcp_nodelay(),
            interval_ms: default_kcp_interval_ms(),
            fast_resend: default_kcp_fast_resend(),
            no_congestion: default_kcp_no_congestion(),
            flush_write: default_kcp_flush_write(),
            flush_acks_input: default_kcp_flush_acks_input(),
            failaway_with_alternative_ms: default_kcp_failaway_with_alternative_ms(),
            failaway_without_alternative_ms: default_kcp_failaway_without_alternative_ms(),
            no_progress_close_ms: default_kcp_no_progress_close_ms(),
        }
    }
}

impl KcpTuning {
    pub fn nodelay(&self) -> bool {
        self.nodelay
    }

    pub fn interval_ms(&self) -> u32 {
        self.interval_ms
    }

    pub fn fast_resend(&self) -> u32 {
        self.fast_resend
    }

    pub fn no_congestion(&self) -> bool {
        self.no_congestion
    }

    pub fn flush_write(&self) -> bool {
        self.flush_write
    }

    pub fn flush_acks_input(&self) -> bool {
        self.flush_acks_input
    }

    pub fn failaway_with_alternative(&self) -> Duration {
        Duration::from_millis(self.failaway_with_alternative_ms)
    }

    pub fn failaway_without_alternative(&self) -> Duration {
        Duration::from_millis(self.failaway_without_alternative_ms)
    }

    pub fn no_progress_close(&self) -> Duration {
        Duration::from_millis(self.no_progress_close_ms)
    }
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportRoutingPolicy {
    #[serde(default = "default_voice_path_stickiness_enabled")]
    voice_path_stickiness_enabled: bool,
    #[serde(default = "default_voice_path_min_hold_ms")]
    voice_path_min_hold_ms: u64,
    #[serde(default = "default_voice_path_challenger_confirm_ms")]
    voice_path_challenger_confirm_ms: u64,
    #[serde(default = "default_voice_path_idle_reset_ms")]
    voice_path_idle_reset_ms: u64,
    #[serde(default = "default_conversational_path_effective_loss_suspect_ppm")]
    conversational_path_effective_loss_suspect_ppm: u32,
    #[serde(default = "default_conversational_path_effective_loss_recover_ppm")]
    conversational_path_effective_loss_recover_ppm: u32,
    #[serde(default = "default_udp_family_min_samples")]
    udp_family_min_samples: u64,
    #[serde(default = "default_udp_family_probe_loss_block_count")]
    udp_family_probe_loss_block_count: u32,
    #[serde(default = "default_udp_family_block_loss_ppm")]
    udp_family_block_loss_ppm: u32,
    #[serde(default = "default_udp_family_loss_excess_over_tcp_ppm")]
    udp_family_loss_excess_over_tcp_ppm: u32,
    #[serde(default = "default_best_effort_datagram_effective_loss_suspect_ppm")]
    best_effort_datagram_effective_loss_suspect_ppm: u32,
    #[serde(default = "default_best_effort_datagram_effective_loss_recover_ppm")]
    best_effort_datagram_effective_loss_recover_ppm: u32,
    #[serde(default = "default_best_effort_quic_datagram_health_suspect_ppm")]
    best_effort_quic_datagram_health_suspect_ppm: u32,
    #[serde(default = "default_best_effort_quic_datagram_health_recover_ppm")]
    best_effort_quic_datagram_health_recover_ppm: u32,
    #[serde(default = "default_best_effort_datagram_suspect_bad_windows")]
    best_effort_datagram_suspect_bad_windows: u32,
    #[serde(default = "default_best_effort_datagram_recover_healthy_ms")]
    best_effort_datagram_recover_healthy_ms: u64,
    #[serde(default = "default_large_rtt_threshold_ms")]
    large_rtt_threshold_ms: u64,
    #[serde(default = "default_lossy_link_threshold_ppm")]
    lossy_link_threshold_ppm: u32,
    #[serde(default = "default_bulk_payload_threshold_bytes")]
    bulk_payload_threshold_bytes: usize,
    #[serde(default = "default_bulk_backlog_threshold_bytes")]
    bulk_backlog_threshold_bytes: usize,
    #[serde(default = "default_transport_switch_improvement_pct")]
    transport_switch_improvement_pct: u32,
    #[serde(default = "default_best_effort_kcp_cost_penalty_pct")]
    best_effort_kcp_cost_penalty_pct: u32,
    #[serde(default = "default_transport_metric_stale_after_ms")]
    transport_metric_stale_after_ms: u64,
}

impl Default for TransportRoutingPolicy {
    fn default() -> Self {
        Self {
            voice_path_stickiness_enabled: default_voice_path_stickiness_enabled(),
            voice_path_min_hold_ms: default_voice_path_min_hold_ms(),
            voice_path_challenger_confirm_ms: default_voice_path_challenger_confirm_ms(),
            voice_path_idle_reset_ms: default_voice_path_idle_reset_ms(),
            conversational_path_effective_loss_suspect_ppm:
                default_conversational_path_effective_loss_suspect_ppm(),
            conversational_path_effective_loss_recover_ppm:
                default_conversational_path_effective_loss_recover_ppm(),
            udp_family_min_samples: default_udp_family_min_samples(),
            udp_family_probe_loss_block_count: default_udp_family_probe_loss_block_count(),
            udp_family_block_loss_ppm: default_udp_family_block_loss_ppm(),
            udp_family_loss_excess_over_tcp_ppm: default_udp_family_loss_excess_over_tcp_ppm(),
            best_effort_datagram_effective_loss_suspect_ppm:
                default_best_effort_datagram_effective_loss_suspect_ppm(),
            best_effort_datagram_effective_loss_recover_ppm:
                default_best_effort_datagram_effective_loss_recover_ppm(),
            best_effort_quic_datagram_health_suspect_ppm:
                default_best_effort_quic_datagram_health_suspect_ppm(),
            best_effort_quic_datagram_health_recover_ppm:
                default_best_effort_quic_datagram_health_recover_ppm(),
            best_effort_datagram_suspect_bad_windows:
                default_best_effort_datagram_suspect_bad_windows(),
            best_effort_datagram_recover_healthy_ms:
                default_best_effort_datagram_recover_healthy_ms(),
            large_rtt_threshold_ms: default_large_rtt_threshold_ms(),
            lossy_link_threshold_ppm: default_lossy_link_threshold_ppm(),
            bulk_payload_threshold_bytes: default_bulk_payload_threshold_bytes(),
            bulk_backlog_threshold_bytes: default_bulk_backlog_threshold_bytes(),
            transport_switch_improvement_pct: default_transport_switch_improvement_pct(),
            best_effort_kcp_cost_penalty_pct: default_best_effort_kcp_cost_penalty_pct(),
            transport_metric_stale_after_ms: default_transport_metric_stale_after_ms(),
        }
    }
}

impl TransportRoutingPolicy {
    pub fn voice_path_stickiness_enabled(&self) -> bool {
        self.voice_path_stickiness_enabled
    }

    pub fn voice_path_min_hold(&self) -> Duration {
        Duration::from_millis(self.voice_path_min_hold_ms)
    }

    pub fn voice_path_challenger_confirm(&self) -> Duration {
        Duration::from_millis(self.voice_path_challenger_confirm_ms)
    }

    pub fn voice_path_idle_reset(&self) -> Duration {
        Duration::from_millis(self.voice_path_idle_reset_ms)
    }

    pub fn conversational_path_effective_loss_suspect_ppm(&self) -> u32 {
        self.conversational_path_effective_loss_suspect_ppm
    }

    pub fn conversational_path_effective_loss_recover_ppm(&self) -> u32 {
        self.conversational_path_effective_loss_recover_ppm
    }

    pub fn udp_family_min_samples(&self) -> u64 {
        self.udp_family_min_samples
    }

    pub fn udp_family_probe_loss_block_count(&self) -> u32 {
        self.udp_family_probe_loss_block_count
    }

    pub fn udp_family_block_loss_ppm(&self) -> u32 {
        self.udp_family_block_loss_ppm
    }

    pub fn udp_family_loss_excess_over_tcp_ppm(&self) -> u32 {
        self.udp_family_loss_excess_over_tcp_ppm
    }

    pub fn best_effort_datagram_effective_loss_suspect_ppm(&self) -> u32 {
        self.best_effort_datagram_effective_loss_suspect_ppm
    }

    pub fn best_effort_datagram_effective_loss_recover_ppm(&self) -> u32 {
        self.best_effort_datagram_effective_loss_recover_ppm
    }

    pub fn best_effort_quic_datagram_health_suspect_ppm(&self) -> u32 {
        self.best_effort_quic_datagram_health_suspect_ppm
    }

    pub fn best_effort_quic_datagram_health_recover_ppm(&self) -> u32 {
        self.best_effort_quic_datagram_health_recover_ppm
    }

    pub fn best_effort_datagram_suspect_bad_windows(&self) -> u32 {
        self.best_effort_datagram_suspect_bad_windows
    }

    pub fn best_effort_datagram_recover_healthy(&self) -> Duration {
        Duration::from_millis(self.best_effort_datagram_recover_healthy_ms)
    }

    pub fn large_rtt_threshold_ms(&self) -> u64 {
        self.large_rtt_threshold_ms
    }

    pub fn lossy_link_threshold_ppm(&self) -> u32 {
        self.lossy_link_threshold_ppm
    }

    pub fn bulk_payload_threshold_bytes(&self) -> usize {
        self.bulk_payload_threshold_bytes
    }

    pub fn bulk_backlog_threshold_bytes(&self) -> usize {
        self.bulk_backlog_threshold_bytes
    }

    pub fn transport_switch_improvement_pct(&self) -> u32 {
        self.transport_switch_improvement_pct
    }

    pub fn best_effort_kcp_cost_penalty_pct(&self) -> u32 {
        self.best_effort_kcp_cost_penalty_pct
    }

    pub fn transport_metric_stale_after(&self) -> Duration {
        Duration::from_millis(self.transport_metric_stale_after_ms)
    }

    pub fn with_udp_family_min_samples(mut self, samples: u64) -> Self {
        self.udp_family_min_samples = samples;
        self
    }

    pub fn with_udp_family_probe_loss_block_count(mut self, count: u32) -> Self {
        self.udp_family_probe_loss_block_count = count;
        self
    }

    pub fn with_udp_family_block_loss_ppm(mut self, ppm: u32) -> Self {
        self.udp_family_block_loss_ppm = ppm.min(1_000_000);
        self
    }

    pub fn with_udp_family_loss_excess_over_tcp_ppm(mut self, ppm: u32) -> Self {
        self.udp_family_loss_excess_over_tcp_ppm = ppm.min(1_000_000);
        self
    }

    pub fn with_best_effort_datagram_effective_loss_suspect_ppm(mut self, ppm: u32) -> Self {
        self.best_effort_datagram_effective_loss_suspect_ppm = ppm.min(1_000_000);
        self
    }

    pub fn with_best_effort_datagram_effective_loss_recover_ppm(mut self, ppm: u32) -> Self {
        self.best_effort_datagram_effective_loss_recover_ppm = ppm.min(1_000_000);
        self
    }

    pub fn with_best_effort_quic_datagram_health_suspect_ppm(mut self, ppm: u32) -> Self {
        self.best_effort_quic_datagram_health_suspect_ppm = ppm.min(1_000_000);
        self
    }

    pub fn with_best_effort_quic_datagram_health_recover_ppm(mut self, ppm: u32) -> Self {
        self.best_effort_quic_datagram_health_recover_ppm = ppm.min(1_000_000);
        self
    }

    pub fn with_best_effort_datagram_suspect_bad_windows(mut self, windows: u32) -> Self {
        self.best_effort_datagram_suspect_bad_windows = windows;
        self
    }

    pub fn with_best_effort_datagram_recover_healthy(mut self, duration: Duration) -> Self {
        self.best_effort_datagram_recover_healthy_ms =
            duration.as_millis().min(u128::from(u64::MAX)) as u64;
        self
    }

    pub fn with_large_rtt_threshold_ms(mut self, ms: u64) -> Self {
        self.large_rtt_threshold_ms = ms;
        self
    }

    pub fn with_lossy_link_threshold_ppm(mut self, ppm: u32) -> Self {
        self.lossy_link_threshold_ppm = ppm.min(1_000_000);
        self
    }

    pub fn with_bulk_payload_threshold_bytes(mut self, bytes: usize) -> Self {
        self.bulk_payload_threshold_bytes = bytes;
        self
    }

    pub fn with_bulk_backlog_threshold_bytes(mut self, bytes: usize) -> Self {
        self.bulk_backlog_threshold_bytes = bytes;
        self
    }

    pub fn with_transport_switch_improvement_pct(mut self, pct: u32) -> Self {
        self.transport_switch_improvement_pct = pct;
        self
    }

    pub fn with_best_effort_kcp_cost_penalty_pct(mut self, pct: u32) -> Self {
        self.best_effort_kcp_cost_penalty_pct = pct;
        self
    }

    pub fn with_transport_metric_stale_after(mut self, duration: Duration) -> Self {
        self.transport_metric_stale_after_ms =
            duration.as_millis().min(u128::from(u64::MAX)) as u64;
        self
    }

    pub fn with_voice_path_stickiness_enabled(mut self, enabled: bool) -> Self {
        self.voice_path_stickiness_enabled = enabled;
        self
    }

    pub fn with_voice_path_min_hold(mut self, duration: Duration) -> Self {
        self.voice_path_min_hold_ms = duration.as_millis().min(u128::from(u64::MAX)) as u64;
        self
    }

    pub fn with_voice_path_challenger_confirm(mut self, duration: Duration) -> Self {
        self.voice_path_challenger_confirm_ms =
            duration.as_millis().min(u128::from(u64::MAX)) as u64;
        self
    }

    pub fn with_voice_path_idle_reset(mut self, duration: Duration) -> Self {
        self.voice_path_idle_reset_ms = duration.as_millis().min(u128::from(u64::MAX)) as u64;
        self
    }

    pub fn with_conversational_path_effective_loss_suspect_ppm(mut self, ppm: u32) -> Self {
        self.conversational_path_effective_loss_suspect_ppm = ppm.min(1_000_000);
        self
    }

    pub fn with_conversational_path_effective_loss_recover_ppm(mut self, ppm: u32) -> Self {
        self.conversational_path_effective_loss_recover_ppm = ppm.min(1_000_000);
        self
    }

    fn validate(&self) -> Result<(), String> {
        if self.conversational_path_effective_loss_suspect_ppm > 1_000_000
            || self.conversational_path_effective_loss_recover_ppm > 1_000_000
        {
            return Err(
                "s2s.transport conversational-path effective-loss thresholds must not exceed 1000000 ppm"
                    .into(),
            );
        }
        if self.conversational_path_effective_loss_recover_ppm
            > self.conversational_path_effective_loss_suspect_ppm
        {
            return Err(
                "s2s.transport.conversational_path_effective_loss_recover_ppm must not exceed conversational_path_effective_loss_suspect_ppm"
                    .into(),
            );
        }
        if self.best_effort_datagram_effective_loss_suspect_ppm > 1_000_000
            || self.best_effort_datagram_effective_loss_recover_ppm > 1_000_000
        {
            return Err(
                "s2s.transport BestEffort datagram effective-loss thresholds must not exceed 1000000 ppm"
                    .into(),
            );
        }
        if self.best_effort_datagram_effective_loss_recover_ppm
            > self.best_effort_datagram_effective_loss_suspect_ppm
        {
            return Err(
                "s2s.transport.best_effort_datagram_effective_loss_recover_ppm must not exceed best_effort_datagram_effective_loss_suspect_ppm"
                    .into(),
            );
        }
        if self.best_effort_quic_datagram_health_suspect_ppm > 1_000_000
            || self.best_effort_quic_datagram_health_recover_ppm > 1_000_000
        {
            return Err(
                "s2s.transport QUIC DATAGRAM local-health thresholds must not exceed 1000000 ppm"
                    .into(),
            );
        }
        if self.best_effort_quic_datagram_health_recover_ppm
            > self.best_effort_quic_datagram_health_suspect_ppm
        {
            return Err(
                "s2s.transport.best_effort_quic_datagram_health_recover_ppm must not exceed best_effort_quic_datagram_health_suspect_ppm"
                    .into(),
            );
        }
        if !(2..=3).contains(&self.best_effort_datagram_suspect_bad_windows) {
            return Err(
                "s2s.transport.best_effort_datagram_suspect_bad_windows must be 2 or 3".into(),
            );
        }
        if !(10_000..=30_000).contains(&self.best_effort_datagram_recover_healthy_ms) {
            return Err(
                "s2s.transport.best_effort_datagram_recover_healthy_ms must be between 10000 and 30000"
                    .into(),
            );
        }
        if self.voice_path_min_hold_ms == 0
            || self.voice_path_challenger_confirm_ms == 0
            || self.voice_path_idle_reset_ms == 0
        {
            return Err("s2s.transport voice-path stickiness timings must be non-zero".into());
        }
        if self.voice_path_idle_reset_ms
            < self
                .voice_path_min_hold_ms
                .max(self.voice_path_challenger_confirm_ms)
        {
            return Err(
                "s2s.transport.voice_path_idle_reset_ms must be at least the larger of voice_path_min_hold_ms and voice_path_challenger_confirm_ms"
                    .into(),
            );
        }
        Ok(())
    }
}

/// TOML-deserializable shadow of the per-link metrics smoothing, ping-cap,
/// adaptive queue floor hints, and connection-selection knobs. Listener,
/// advertise, PKI, and seed fields stay on the higher-level S2S config because
/// they need custom parsing and validation.
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
    #[serde(default = "default_stream_write_timeout_ms")]
    pub stream_write_timeout_ms: u64,
    #[serde(default = "default_quic_session_setup_timeout_ms")]
    quic_session_setup_timeout_ms: u64,
    #[serde(default = "default_quic_datagram_send_buffer_bytes")]
    quic_datagram_send_buffer_bytes: usize,
    #[serde(default = "default_quic_datagram_receive_buffer_bytes")]
    quic_datagram_receive_buffer_bytes: usize,
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
    #[serde(default = "default_self_seed_quarantine_secs")]
    pub self_seed_quarantine_secs: u64,
    #[serde(default = "default_unselected_link_probe_interval_secs")]
    pub unselected_link_probe_interval_secs: u64,
    #[serde(default = "default_max_dial_attempts_per_peer_tick")]
    pub max_dial_attempts_per_peer_tick: usize,
    #[serde(default = "default_max_outgoing_connections")]
    pub max_outgoing_connections: usize,
    #[serde(default)]
    kcp: KcpTuning,
    /// Legacy message-count hint used as a minimum adaptive byte budget.
    #[serde(default = "default_inbound_control_capacity")]
    inbound_control_capacity: usize,
    /// Legacy message-count hint used as a minimum adaptive byte budget.
    #[serde(default = "default_inbound_high_capacity")]
    inbound_high_capacity: usize,
    /// Legacy message-count hint used as a minimum adaptive byte budget.
    #[serde(default = "default_inbound_regular_capacity")]
    inbound_regular_capacity: usize,
    /// Legacy message-count hint used as a minimum adaptive byte budget.
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
    #[serde(default, flatten)]
    routing_policy: TransportRoutingPolicy,
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
            stream_write_timeout_ms: default_stream_write_timeout_ms(),
            quic_session_setup_timeout_ms: default_quic_session_setup_timeout_ms(),
            quic_datagram_send_buffer_bytes: default_quic_datagram_send_buffer_bytes(),
            quic_datagram_receive_buffer_bytes: default_quic_datagram_receive_buffer_bytes(),
            max_pending_pings: default_max_pending_pings(),
            recent_probe_retry_cap_secs: default_recent_probe_retry_cap_secs(),
            stale_probe_retry_cap_secs: default_stale_probe_retry_cap_secs(),
            stale_probe_age_secs: default_stale_probe_age_secs(),
            unconfirmed_address_retry_floor_secs: default_unconfirmed_address_retry_floor_secs(),
            unconfirmed_address_retry_cap_secs: default_unconfirmed_address_retry_cap_secs(),
            unconfirmed_address_decay_failures: default_unconfirmed_address_decay_failures(),
            dial_attempt_timeout_secs: default_dial_attempt_timeout_secs(),
            self_seed_quarantine_secs: default_self_seed_quarantine_secs(),
            unselected_link_probe_interval_secs: default_unselected_link_probe_interval_secs(),
            max_dial_attempts_per_peer_tick: default_max_dial_attempts_per_peer_tick(),
            max_outgoing_connections: default_max_outgoing_connections(),
            kcp: KcpTuning::default(),
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
            routing_policy: TransportRoutingPolicy::default(),
        }
    }
}

impl TransportTuning {
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_outbound_capacity_for_test(&mut self, n: usize) {
        self.outbound_capacity = n.max(1);
    }

    pub fn routing_policy(&self) -> TransportRoutingPolicy {
        self.routing_policy
    }

    /// Apply the tunables on top of an existing `TransportConfig`.
    pub fn apply(&self, cfg: TransportConfig) -> TransportConfig {
        cfg.with_latency_ewma_alpha(self.latency_ewma_alpha)
            .with_jitter_ewma_alpha(self.jitter_ewma_alpha)
            .with_packet_loss_ewma_alpha(self.packet_loss_ewma_alpha)
            .with_ping_interval(Duration::from_secs(self.ping_interval_secs))
            .with_idle_ping_interval(Duration::from_secs(self.idle_ping_interval_secs))
            .with_native_stats_interval(Duration::from_secs(self.native_stats_interval_secs))
            .with_stream_write_timeout(Duration::from_millis(self.stream_write_timeout_ms))
            .with_quic_session_setup_timeout(Duration::from_millis(
                self.quic_session_setup_timeout_ms,
            ))
            .with_quic_datagram_send_buffer_bytes(self.quic_datagram_send_buffer_bytes)
            .with_quic_datagram_receive_buffer_bytes(self.quic_datagram_receive_buffer_bytes)
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
            .with_self_seed_quarantine(Duration::from_secs(self.self_seed_quarantine_secs))
            .with_unselected_link_probe_interval(Duration::from_secs(
                self.unselected_link_probe_interval_secs,
            ))
            .with_max_dial_attempts_per_peer_tick(self.max_dial_attempts_per_peer_tick)
            .with_max_outgoing_connections(self.max_outgoing_connections)
            .with_kcp_tuning(self.kcp)
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
            .with_routing_policy(self.routing_policy)
    }

    /// Apply tunables and load the optional compression dictionary from disk.
    pub fn try_apply(&self, cfg: TransportConfig) -> Result<TransportConfig, String> {
        self.routing_policy.validate()?;
        validate_quic_datagram_buffer(
            "quic_datagram_send_buffer_bytes",
            self.quic_datagram_send_buffer_bytes,
        )?;
        validate_quic_datagram_buffer(
            "quic_datagram_receive_buffer_bytes",
            self.quic_datagram_receive_buffer_bytes,
        )?;
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
fn default_stream_write_timeout_ms() -> u64 {
    1_000
}
fn default_quic_session_setup_timeout_ms() -> u64 {
    10_000
}
fn default_quic_datagram_send_buffer_bytes() -> usize {
    65_536
}
fn default_quic_datagram_receive_buffer_bytes() -> usize {
    262_144
}
fn validate_quic_datagram_buffer(name: &str, bytes: usize) -> Result<(), String> {
    const MIN_ENABLED_QUIC_DATAGRAM_BUFFER_BYTES: usize = 1_200;
    if bytes != 0 && bytes < MIN_ENABLED_QUIC_DATAGRAM_BUFFER_BYTES {
        return Err(format!(
            "s2s.transport.{name} must be zero or at least {MIN_ENABLED_QUIC_DATAGRAM_BUFFER_BYTES} bytes"
        ));
    }
    Ok(())
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
fn default_self_seed_quarantine_secs() -> u64 {
    60 * 60
}
fn default_unselected_link_probe_interval_secs() -> u64 {
    30
}
fn default_max_dial_attempts_per_peer_tick() -> usize {
    1
}
fn default_max_outgoing_connections() -> usize {
    1024
}
fn default_inbound_control_capacity() -> usize {
    16384
}
fn default_inbound_high_capacity() -> usize {
    32768
}
fn default_inbound_regular_capacity() -> usize {
    32768
}
fn default_outbound_capacity() -> usize {
    131072
}
fn default_kcp_nodelay() -> bool {
    true
}
fn default_kcp_interval_ms() -> u32 {
    10
}
fn default_kcp_fast_resend() -> u32 {
    2
}
fn default_kcp_no_congestion() -> bool {
    false
}
fn default_kcp_flush_write() -> bool {
    true
}
fn default_kcp_flush_acks_input() -> bool {
    true
}
fn default_kcp_failaway_with_alternative_ms() -> u64 {
    250
}
fn default_kcp_failaway_without_alternative_ms() -> u64 {
    750
}
fn default_kcp_no_progress_close_ms() -> u64 {
    1_500
}
fn default_udp_family_min_samples() -> u64 {
    32
}
fn default_udp_family_probe_loss_block_count() -> u32 {
    3
}
fn default_udp_family_block_loss_ppm() -> u32 {
    250_000
}
fn default_udp_family_loss_excess_over_tcp_ppm() -> u32 {
    50_000
}
fn default_conversational_path_effective_loss_suspect_ppm() -> u32 {
    3_000
}
fn default_conversational_path_effective_loss_recover_ppm() -> u32 {
    1_500
}
fn default_best_effort_datagram_effective_loss_suspect_ppm() -> u32 {
    5_000
}
fn default_best_effort_datagram_effective_loss_recover_ppm() -> u32 {
    2_500
}
fn default_best_effort_quic_datagram_health_suspect_ppm() -> u32 {
    100_000
}
fn default_best_effort_quic_datagram_health_recover_ppm() -> u32 {
    10_000
}
fn default_best_effort_datagram_suspect_bad_windows() -> u32 {
    3
}
fn default_best_effort_datagram_recover_healthy_ms() -> u64 {
    10_000
}
fn default_large_rtt_threshold_ms() -> u64 {
    100
}
fn default_lossy_link_threshold_ppm() -> u32 {
    20_000
}
fn default_bulk_payload_threshold_bytes() -> usize {
    65_536
}
fn default_bulk_backlog_threshold_bytes() -> usize {
    262_144
}
fn default_transport_switch_improvement_pct() -> u32 {
    15
}
fn default_best_effort_kcp_cost_penalty_pct() -> u32 {
    25
}
fn default_transport_metric_stale_after_ms() -> u64 {
    1_500
}
fn default_voice_path_stickiness_enabled() -> bool {
    true
}
fn default_voice_path_min_hold_ms() -> u64 {
    750
}
fn default_voice_path_challenger_confirm_ms() -> u64 {
    500
}
fn default_voice_path_idle_reset_ms() -> u64 {
    2_000
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

    #[test]
    fn quic_v2_tuning_defaults_are_enabled_and_bounded() {
        let cfg = TransportTuning::default().try_apply(base_config()).unwrap();

        assert_eq!(
            cfg.quic_session_setup_timeout(),
            Duration::from_millis(10_000)
        );
        assert_eq!(cfg.quic_datagram_send_buffer_bytes(), 65_536);
        assert_eq!(cfg.quic_datagram_receive_buffer_bytes(), 262_144);
    }

    #[test]
    fn quic_v2_tuning_parses_and_applies() {
        let tuning: TransportTuning = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    quic_session_setup_timeout_ms = 3456
                    quic_datagram_send_buffer_bytes = 4096
                    quic_datagram_receive_buffer_bytes = 8192
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("transport tuning parses");
        let cfg = tuning.try_apply(base_config()).unwrap();

        assert_eq!(
            cfg.quic_session_setup_timeout(),
            Duration::from_millis(3_456)
        );
        assert_eq!(cfg.quic_datagram_send_buffer_bytes(), 4_096);
        assert_eq!(cfg.quic_datagram_receive_buffer_bytes(), 8_192);
    }

    #[test]
    fn quic_v2_tuning_allows_disabled_datagram_buffers() {
        let mut tuning = TransportTuning::default();
        tuning.quic_datagram_send_buffer_bytes = 0;
        tuning.quic_datagram_receive_buffer_bytes = 0;

        let cfg = tuning.try_apply(base_config()).unwrap();
        assert_eq!(cfg.quic_datagram_send_buffer_bytes(), 0);
        assert_eq!(cfg.quic_datagram_receive_buffer_bytes(), 0);
    }

    #[test]
    fn quic_v2_tuning_accepts_minimum_enabled_datagram_buffers() {
        let mut tuning = TransportTuning::default();
        tuning.quic_datagram_send_buffer_bytes = 1_200;
        tuning.quic_datagram_receive_buffer_bytes = 1_200;

        let cfg = tuning.try_apply(base_config()).unwrap();
        assert_eq!(cfg.quic_datagram_send_buffer_bytes(), 1_200);
        assert_eq!(cfg.quic_datagram_receive_buffer_bytes(), 1_200);
    }

    #[test]
    fn quic_v2_tuning_rejects_undersized_enabled_datagram_buffers() {
        for key in [
            "quic_datagram_send_buffer_bytes",
            "quic_datagram_receive_buffer_bytes",
        ] {
            for bytes in [1, 1_199] {
                let source = format!("{key} = {bytes}");
                let tuning: TransportTuning = ::config::Config::builder()
                    .add_source(::config::File::from_str(
                        &source,
                        ::config::FileFormat::Toml,
                    ))
                    .build()
                    .expect("config builder")
                    .try_deserialize()
                    .expect("transport tuning parses before semantic validation");
                let error = tuning.try_apply(base_config()).unwrap_err();

                assert!(error.contains(key), "error: {error}");
                assert!(error.contains("zero or at least 1200"), "error: {error}");
            }
        }
    }

    #[test]
    fn quic_v2_transport_config_builders_update_private_fields() {
        let cfg = base_config()
            .with_quic_session_setup_timeout(Duration::from_millis(987))
            .with_quic_datagram_send_buffer_bytes(2_400)
            .with_quic_datagram_receive_buffer_bytes(4_800);

        assert_eq!(cfg.quic_session_setup_timeout(), Duration::from_millis(987));
        assert_eq!(cfg.quic_datagram_send_buffer_bytes(), 2_400);
        assert_eq!(cfg.quic_datagram_receive_buffer_bytes(), 4_800);
    }

    #[test]
    fn transport_routing_policy_defaults_are_conservative() {
        let policy = TransportRoutingPolicy::default();

        assert_eq!(policy.udp_family_min_samples(), 32);
        assert_eq!(policy.udp_family_probe_loss_block_count(), 3);
        assert_eq!(policy.udp_family_block_loss_ppm(), 250_000);
        assert_eq!(policy.udp_family_loss_excess_over_tcp_ppm(), 50_000);
        assert_eq!(
            policy.conversational_path_effective_loss_suspect_ppm(),
            3_000
        );
        assert_eq!(
            policy.conversational_path_effective_loss_recover_ppm(),
            1_500
        );
        assert_eq!(
            policy.best_effort_datagram_effective_loss_suspect_ppm(),
            5_000
        );
        assert_eq!(
            policy.best_effort_datagram_effective_loss_recover_ppm(),
            2_500
        );
        assert_eq!(
            policy.best_effort_quic_datagram_health_suspect_ppm(),
            100_000
        );
        assert_eq!(
            policy.best_effort_quic_datagram_health_recover_ppm(),
            10_000
        );
        assert_eq!(policy.best_effort_datagram_suspect_bad_windows(), 3);
        assert_eq!(
            policy.best_effort_datagram_recover_healthy(),
            Duration::from_secs(10)
        );
        assert_eq!(policy.large_rtt_threshold_ms(), 100);
        assert_eq!(policy.lossy_link_threshold_ppm(), 20_000);
        assert_eq!(policy.bulk_payload_threshold_bytes(), 65_536);
        assert_eq!(policy.bulk_backlog_threshold_bytes(), 262_144);
        assert_eq!(policy.transport_switch_improvement_pct(), 15);
        assert_eq!(policy.best_effort_kcp_cost_penalty_pct(), 25);
        assert!(policy.voice_path_stickiness_enabled());
        assert_eq!(policy.voice_path_min_hold(), Duration::from_millis(750));
        assert_eq!(
            policy.voice_path_challenger_confirm(),
            Duration::from_millis(500)
        );
        assert_eq!(policy.voice_path_idle_reset(), Duration::from_millis(2_000));
        assert_eq!(
            policy.transport_metric_stale_after(),
            Duration::from_millis(1_500)
        );
    }

    #[test]
    fn transport_routing_policy_builders_update_private_fields() {
        let policy = TransportRoutingPolicy::default()
            .with_udp_family_min_samples(12)
            .with_udp_family_probe_loss_block_count(4)
            .with_udp_family_block_loss_ppm(2_000_000)
            .with_udp_family_loss_excess_over_tcp_ppm(70_000)
            .with_conversational_path_effective_loss_suspect_ppm(8_000)
            .with_conversational_path_effective_loss_recover_ppm(3_000)
            .with_best_effort_datagram_effective_loss_suspect_ppm(12_000)
            .with_best_effort_datagram_effective_loss_recover_ppm(6_000)
            .with_best_effort_quic_datagram_health_suspect_ppm(150_000)
            .with_best_effort_quic_datagram_health_recover_ppm(20_000)
            .with_best_effort_datagram_suspect_bad_windows(2)
            .with_best_effort_datagram_recover_healthy(Duration::from_secs(20))
            .with_large_rtt_threshold_ms(80)
            .with_lossy_link_threshold_ppm(30_000)
            .with_bulk_payload_threshold_bytes(32_768)
            .with_bulk_backlog_threshold_bytes(131_072)
            .with_transport_switch_improvement_pct(25)
            .with_best_effort_kcp_cost_penalty_pct(40)
            .with_transport_metric_stale_after(Duration::from_millis(900))
            .with_voice_path_stickiness_enabled(false)
            .with_voice_path_min_hold(Duration::from_millis(800))
            .with_voice_path_challenger_confirm(Duration::from_millis(600))
            .with_voice_path_idle_reset(Duration::from_millis(2_500));

        assert_eq!(policy.udp_family_min_samples(), 12);
        assert_eq!(policy.udp_family_probe_loss_block_count(), 4);
        assert_eq!(policy.udp_family_block_loss_ppm(), 1_000_000);
        assert_eq!(policy.udp_family_loss_excess_over_tcp_ppm(), 70_000);
        assert_eq!(
            policy.conversational_path_effective_loss_suspect_ppm(),
            8_000
        );
        assert_eq!(
            policy.conversational_path_effective_loss_recover_ppm(),
            3_000
        );
        assert_eq!(
            policy.best_effort_datagram_effective_loss_suspect_ppm(),
            12_000
        );
        assert_eq!(
            policy.best_effort_datagram_effective_loss_recover_ppm(),
            6_000
        );
        assert_eq!(
            policy.best_effort_quic_datagram_health_suspect_ppm(),
            150_000
        );
        assert_eq!(
            policy.best_effort_quic_datagram_health_recover_ppm(),
            20_000
        );
        assert_eq!(policy.best_effort_datagram_suspect_bad_windows(), 2);
        assert_eq!(
            policy.best_effort_datagram_recover_healthy(),
            Duration::from_secs(20)
        );
        assert_eq!(policy.large_rtt_threshold_ms(), 80);
        assert_eq!(policy.lossy_link_threshold_ppm(), 30_000);
        assert_eq!(policy.bulk_payload_threshold_bytes(), 32_768);
        assert_eq!(policy.bulk_backlog_threshold_bytes(), 131_072);
        assert_eq!(policy.transport_switch_improvement_pct(), 25);
        assert_eq!(policy.best_effort_kcp_cost_penalty_pct(), 40);
        assert!(!policy.voice_path_stickiness_enabled());
        assert_eq!(policy.voice_path_min_hold(), Duration::from_millis(800));
        assert_eq!(
            policy.voice_path_challenger_confirm(),
            Duration::from_millis(600)
        );
        assert_eq!(policy.voice_path_idle_reset(), Duration::from_millis(2_500));
        assert_eq!(
            policy.transport_metric_stale_after(),
            Duration::from_millis(900)
        );
    }

    #[test]
    fn transport_routing_policy_serde_defaults_kcp_penalty() {
        let tuning: TransportTuning = ::config::Config::builder()
            .add_source(::config::File::from_str(
                "transport_switch_improvement_pct = 20",
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("transport tuning parses");

        assert_eq!(
            tuning.routing_policy().best_effort_kcp_cost_penalty_pct(),
            25
        );
    }

    #[test]
    fn transport_tuning_parses_and_applies_routing_policy() {
        let tuning: TransportTuning = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    udp_family_min_samples = 8
                    udp_family_probe_loss_block_count = 5
                    udp_family_block_loss_ppm = 200000
                    udp_family_loss_excess_over_tcp_ppm = 40000
                    conversational_path_effective_loss_suspect_ppm = 7000
                    conversational_path_effective_loss_recover_ppm = 3000
                    best_effort_datagram_effective_loss_suspect_ppm = 9000
                    best_effort_datagram_effective_loss_recover_ppm = 4000
                    best_effort_quic_datagram_health_suspect_ppm = 120000
                    best_effort_quic_datagram_health_recover_ppm = 12000
                    best_effort_datagram_suspect_bad_windows = 2
                    best_effort_datagram_recover_healthy_ms = 15000
                    large_rtt_threshold_ms = 120
                    lossy_link_threshold_ppm = 15000
                    bulk_payload_threshold_bytes = 32768
                    bulk_backlog_threshold_bytes = 98304
                    transport_switch_improvement_pct = 20
                    best_effort_kcp_cost_penalty_pct = 35
                    transport_metric_stale_after_ms = 800
                    voice_path_stickiness_enabled = false
                    voice_path_min_hold_ms = 900
                    voice_path_challenger_confirm_ms = 650
                    voice_path_idle_reset_ms = 3000
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("transport tuning parses");
        let cfg = tuning.apply(base_config());
        let policy = cfg.routing_policy();

        assert_eq!(tuning.routing_policy().udp_family_min_samples(), 8);
        assert_eq!(policy.udp_family_min_samples(), 8);
        assert_eq!(policy.udp_family_probe_loss_block_count(), 5);
        assert_eq!(policy.udp_family_block_loss_ppm(), 200_000);
        assert_eq!(policy.udp_family_loss_excess_over_tcp_ppm(), 40_000);
        assert_eq!(
            policy.conversational_path_effective_loss_suspect_ppm(),
            7_000
        );
        assert_eq!(
            policy.conversational_path_effective_loss_recover_ppm(),
            3_000
        );
        assert_eq!(
            policy.best_effort_datagram_effective_loss_suspect_ppm(),
            9_000
        );
        assert_eq!(
            policy.best_effort_datagram_effective_loss_recover_ppm(),
            4_000
        );
        assert_eq!(
            policy.best_effort_quic_datagram_health_suspect_ppm(),
            120_000
        );
        assert_eq!(
            policy.best_effort_quic_datagram_health_recover_ppm(),
            12_000
        );
        assert_eq!(policy.best_effort_datagram_suspect_bad_windows(), 2);
        assert_eq!(
            policy.best_effort_datagram_recover_healthy(),
            Duration::from_secs(15)
        );
        assert_eq!(policy.large_rtt_threshold_ms(), 120);
        assert_eq!(policy.lossy_link_threshold_ppm(), 15_000);
        assert_eq!(policy.bulk_payload_threshold_bytes(), 32_768);
        assert_eq!(policy.bulk_backlog_threshold_bytes(), 98_304);
        assert_eq!(policy.transport_switch_improvement_pct(), 20);
        assert_eq!(policy.best_effort_kcp_cost_penalty_pct(), 35);
        assert!(!policy.voice_path_stickiness_enabled());
        assert_eq!(policy.voice_path_min_hold(), Duration::from_millis(900));
        assert_eq!(
            policy.voice_path_challenger_confirm(),
            Duration::from_millis(650)
        );
        assert_eq!(policy.voice_path_idle_reset(), Duration::from_millis(3_000));
        assert_eq!(
            policy.transport_metric_stale_after(),
            Duration::from_millis(800)
        );
    }

    #[test]
    fn transport_tuning_rejects_invalid_voice_path_timings_on_apply() {
        for source in [
            "voice_path_min_hold_ms = 0",
            "voice_path_challenger_confirm_ms = 0",
            "voice_path_idle_reset_ms = 0",
            "voice_path_min_hold_ms = 1000\nvoice_path_idle_reset_ms = 999",
            "voice_path_challenger_confirm_ms = 1000\nvoice_path_idle_reset_ms = 999",
        ] {
            let tuning: TransportTuning = ::config::Config::builder()
                .add_source(::config::File::from_str(source, ::config::FileFormat::Toml))
                .build()
                .expect("config builder")
                .try_deserialize()
                .expect("transport tuning parses before semantic validation");
            assert!(tuning.try_apply(base_config()).is_err(), "source: {source}");
        }
    }

    #[test]
    fn transport_tuning_rejects_invalid_effective_loss_thresholds() {
        for source in [
            "conversational_path_effective_loss_suspect_ppm = 1000001",
            "conversational_path_effective_loss_recover_ppm = 1000001",
            "conversational_path_effective_loss_suspect_ppm = 4000\nconversational_path_effective_loss_recover_ppm = 5000",
            "best_effort_datagram_effective_loss_suspect_ppm = 1000001",
            "best_effort_datagram_effective_loss_recover_ppm = 1000001",
            "best_effort_datagram_effective_loss_suspect_ppm = 4000\nbest_effort_datagram_effective_loss_recover_ppm = 5000",
        ] {
            let tuning: TransportTuning = ::config::Config::builder()
                .add_source(::config::File::from_str(source, ::config::FileFormat::Toml))
                .build()
                .expect("config builder")
                .try_deserialize()
                .expect("transport tuning parses before semantic validation");
            assert!(tuning.try_apply(base_config()).is_err(), "source: {source}");
        }
    }

    #[test]
    fn transport_tuning_rejects_invalid_quic_datagram_health_gates() {
        for source in [
            "best_effort_quic_datagram_health_suspect_ppm = 1000001",
            "best_effort_quic_datagram_health_recover_ppm = 1000001",
            "best_effort_quic_datagram_health_suspect_ppm = 10000\nbest_effort_quic_datagram_health_recover_ppm = 10001",
            "best_effort_datagram_suspect_bad_windows = 1",
            "best_effort_datagram_suspect_bad_windows = 4",
            "best_effort_datagram_recover_healthy_ms = 9999",
            "best_effort_datagram_recover_healthy_ms = 30001",
        ] {
            let tuning: TransportTuning = ::config::Config::builder()
                .add_source(::config::File::from_str(source, ::config::FileFormat::Toml))
                .build()
                .expect("config builder")
                .try_deserialize()
                .expect("transport tuning parses before semantic validation");
            assert!(tuning.try_apply(base_config()).is_err(), "source: {source}");
        }
    }

    #[test]
    fn transport_tuning_applies_nested_kcp_tuning() {
        let tuning: TransportTuning = ::config::Config::builder()
            .add_source(::config::File::from_str(
                r#"
                    [kcp]
                    nodelay = false
                    interval_ms = 20
                    fast_resend = 3
                    no_congestion = true
                    flush_write = false
                    flush_acks_input = false
                    failaway_with_alternative_ms = 111
                    failaway_without_alternative_ms = 222
                    no_progress_close_ms = 333
                "#,
                ::config::FileFormat::Toml,
            ))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("transport tuning parses");
        let cfg = tuning.apply(base_config());
        let kcp = cfg.kcp_tuning();

        assert!(!kcp.nodelay());
        assert_eq!(kcp.interval_ms(), 20);
        assert_eq!(kcp.fast_resend(), 3);
        assert!(kcp.no_congestion());
        assert!(!kcp.flush_write());
        assert!(!kcp.flush_acks_input());
        assert_eq!(kcp.failaway_with_alternative(), Duration::from_millis(111));
        assert_eq!(
            kcp.failaway_without_alternative(),
            Duration::from_millis(222)
        );
        assert_eq!(kcp.no_progress_close(), Duration::from_millis(333));
    }

    #[test]
    fn kcp_tuning_defaults_are_realtime_stable() {
        let kcp = base_config().kcp_tuning();

        assert!(kcp.nodelay());
        assert_eq!(kcp.interval_ms(), 10);
        assert_eq!(kcp.fast_resend(), 2);
        assert!(!kcp.no_congestion());
        assert!(kcp.flush_write());
        assert!(kcp.flush_acks_input());
        assert_eq!(kcp.failaway_with_alternative(), Duration::from_millis(250));
        assert_eq!(
            kcp.failaway_without_alternative(),
            Duration::from_millis(750)
        );
        assert_eq!(kcp.no_progress_close(), Duration::from_millis(1_500));
    }
}
