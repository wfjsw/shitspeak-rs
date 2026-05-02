use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

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

    backoff_initial: Duration,
    backoff_cap: Duration,
    reconnect_check_interval: Duration,
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
            backoff_initial: Duration::from_millis(250),
            backoff_cap: Duration::from_secs(30),
            reconnect_check_interval: Duration::from_secs(1),
            ping_interval: Duration::from_secs(2),
            bandwidth_window: Duration::from_secs(5),
            bandwidth_probe_interval: Duration::from_secs(15),
            bandwidth_probe_size: 4096,
            inbound_high_capacity: 1024,
            inbound_regular_capacity: 1024,
            outbound_capacity: 256,
            max_frame_bytes: 1 << 20,
            udp_mtu: 1200,
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

    pub fn backoff_initial(&self) -> Duration {
        self.backoff_initial
    }

    pub fn backoff_cap(&self) -> Duration {
        self.backoff_cap
    }

    pub fn reconnect_check_interval(&self) -> Duration {
        self.reconnect_check_interval
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

    pub fn with_backoff_initial(mut self, d: Duration) -> Self {
        self.backoff_initial = d;
        self
    }

    pub fn with_backoff_cap(mut self, d: Duration) -> Self {
        self.backoff_cap = d;
        self
    }

    pub fn with_reconnect_check_interval(mut self, d: Duration) -> Self {
        self.reconnect_check_interval = d;
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
}
