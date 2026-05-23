use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

use crate::constants::APP_PROTO_VER;
use crate::protocol_version::ProtocolVersion;

use config::{Config as ConfigCrate, Environment, File};
use serde::{Deserialize, Deserializer};

use crate::s2s::application::ApplicationConfig;
use crate::s2s::overlay::OverlayTuning;
use crate::s2s::replications::ReplicationTuning;
use crate::s2s::transport::{PeerAddress, TransportConfig, TransportKind, TransportTuning};

#[derive(Deserialize, Debug, Clone, Default)]
pub struct S2sConfig {
    /// S2S is explicit opt-in. Disabled configs do not need PKI/listen fields.
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub ca_path: Option<PathBuf>,
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    #[serde(default)]
    pub key_path: Option<PathBuf>,

    #[serde(default)]
    pub tcp_listen: Option<SocketAddr>,
    #[serde(default)]
    pub kcp_listen: Option<SocketAddr>,
    #[serde(default)]
    pub quic_listen: Option<SocketAddr>,
    #[serde(default)]
    pub udp_listen: Option<SocketAddr>,
    #[serde(default, deserialize_with = "deserialize_advertise_overrides")]
    pub tcp_advertise: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_advertise_overrides")]
    pub kcp_advertise: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_advertise_overrides")]
    pub quic_advertise: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_advertise_overrides")]
    pub udp_advertise: Vec<String>,

    /// Optional plain HTTP listener for the S2S topology/status page.
    #[serde(default)]
    pub status_http_listen: Option<SocketAddr>,

    #[serde(default)]
    pub persistence_dir: Option<PathBuf>,

    #[serde(default)]
    pub seed_addresses: Vec<S2sSeedAddressConfig>,

    /// L3 application-layer tunables (moderation + voice). Lives under
    /// `[s2s.application.*]` in TOML.
    #[serde(default)]
    pub application: ApplicationConfig,

    /// L1 transport-layer metrics smoothing + ping-cap tunables. Lives
    /// under `[s2s.transport.*]` in TOML.
    #[serde(default)]
    pub transport: TransportTuning,

    /// L2 overlay-layer tunables. Lives under `[s2s.overlay.*]` in TOML.
    #[serde(default)]
    pub overlay: OverlayTuning,

    /// L3 replications-layer tunables (Tempo + owner-mode). Lives under
    /// `[s2s.replications.*]` in TOML.
    #[serde(default)]
    pub replications: ReplicationTuning,
}

impl S2sConfig {
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn transport_config(&self) -> Result<Option<TransportConfig>, String> {
        self.transport_config_with_auto_advertise_host(None)
    }

    pub fn transport_config_with_auto_advertise_host(
        &self,
        auto_advertise_host: Option<&str>,
    ) -> Result<Option<TransportConfig>, String> {
        if !self.enabled {
            return Ok(None);
        }

        let ca_path = self
            .ca_path
            .clone()
            .ok_or_else(|| "s2s.enabled=true requires s2s.ca_path".to_string())?;
        let cert_path = self
            .cert_path
            .clone()
            .ok_or_else(|| "s2s.enabled=true requires s2s.cert_path".to_string())?;
        let key_path = self
            .key_path
            .clone()
            .ok_or_else(|| "s2s.enabled=true requires s2s.key_path".to_string())?;

        let mut cfg = TransportConfig::new(ca_path, cert_path, key_path);
        if let Some(addr) = self.tcp_listen {
            cfg = cfg.with_tcp_listen(addr);
        }
        if let Some(addr) = self.kcp_listen {
            cfg = cfg.with_kcp_listen(addr);
        }
        if let Some(addr) = self.quic_listen {
            cfg = cfg.with_quic_listen(addr);
        }
        if let Some(addr) = self.udp_listen {
            cfg = cfg.with_udp_listen(addr);
        }
        let tcp_advertise = resolve_s2s_advertise_overrides(
            "s2s.tcp_advertise",
            &self.tcp_advertise,
            auto_advertise_host,
            self.tcp_listen,
        )?;
        for addr in tcp_advertise.addrs {
            cfg = if tcp_advertise.is_override {
                cfg.with_tcp_advertise_override(addr)
            } else {
                cfg.with_tcp_advertise(addr)
            };
        }
        let kcp_advertise = resolve_s2s_advertise_overrides(
            "s2s.kcp_advertise",
            &self.kcp_advertise,
            auto_advertise_host,
            self.kcp_listen,
        )?;
        for addr in kcp_advertise.addrs {
            cfg = if kcp_advertise.is_override {
                cfg.with_kcp_advertise_override(addr)
            } else {
                cfg.with_kcp_advertise(addr)
            };
        }
        let quic_advertise = resolve_s2s_advertise_overrides(
            "s2s.quic_advertise",
            &self.quic_advertise,
            auto_advertise_host,
            self.quic_listen,
        )?;
        for addr in quic_advertise.addrs {
            cfg = if quic_advertise.is_override {
                cfg.with_quic_advertise_override(addr)
            } else {
                cfg.with_quic_advertise(addr)
            };
        }
        let udp_advertise = resolve_s2s_advertise_overrides(
            "s2s.udp_advertise",
            &self.udp_advertise,
            auto_advertise_host,
            self.udp_listen,
        )?;
        for addr in udp_advertise.addrs {
            cfg = if udp_advertise.is_override {
                cfg.with_udp_advertise_override(addr)
            } else {
                cfg.with_udp_advertise(addr)
            };
        }

        cfg = cfg.with_seed_addresses(
            self.seed_addresses
                .iter()
                .map(S2sSeedAddressConfig::peer_address)
                .collect::<Result<Vec<_>, _>>()?,
        );
        Ok(Some(self.transport.apply(cfg)))
    }

    pub fn overlay_config(&self) -> crate::s2s::overlay::OverlayConfig {
        let mut cfg = crate::s2s::overlay::OverlayConfig::new(Vec::new());
        if let Some(dir) = self.persistence_dir.clone() {
            cfg = cfg.with_persistence_dir(dir);
        }
        self.overlay.apply(cfg)
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct S2sSeedAddressConfig {
    transport: S2sTransportKindConfig,
    addr: String,
}

impl S2sSeedAddressConfig {
    pub fn new(transport: S2sTransportKindConfig, addr: SocketAddr) -> Self {
        Self {
            transport,
            addr: addr.to_string(),
        }
    }

    pub fn transport(&self) -> S2sTransportKindConfig {
        self.transport
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn peer_address(&self) -> Result<PeerAddress, String> {
        let addr = resolve_s2s_addr("s2s seed address", &self.addr)?;
        Ok(PeerAddress::new(addr, self.transport.into()))
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AdvertiseOverrides {
    One(String),
    Many(Vec<String>),
}

struct ResolvedAdvertiseAddrs {
    addrs: Vec<SocketAddr>,
    is_override: bool,
}

fn deserialize_advertise_overrides<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = AdvertiseOverrides::deserialize(deserializer)?;
    let values = match raw {
        AdvertiseOverrides::One(value) => vec![value],
        AdvertiseOverrides::Many(values) => values,
    };
    Ok(values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect())
}

fn resolve_s2s_advertise_overrides(
    label: &str,
    values: &[String],
    auto_advertise_host: Option<&str>,
    listen: Option<SocketAddr>,
) -> Result<ResolvedAdvertiseAddrs, String> {
    let mut resolved = Vec::new();
    if !values.is_empty() {
        for value in values {
            push_unique_socket_addrs(&mut resolved, resolve_s2s_advertise_addrs(label, value)?);
        }
        return Ok(ResolvedAdvertiseAddrs {
            addrs: resolved,
            is_override: true,
        });
    }

    let Some(host) = auto_advertise_host
        .map(str::trim)
        .filter(|host| !host.is_empty())
    else {
        return Ok(ResolvedAdvertiseAddrs {
            addrs: Vec::new(),
            is_override: false,
        });
    };
    let Some(listen) = listen else {
        return Ok(ResolvedAdvertiseAddrs {
            addrs: Vec::new(),
            is_override: false,
        });
    };
    let value = format_host_port(host, listen.port());
    push_unique_socket_addrs(&mut resolved, resolve_s2s_advertise_addrs(label, &value)?);
    Ok(ResolvedAdvertiseAddrs {
        addrs: resolved,
        is_override: false,
    })
}

fn push_unique_socket_addrs(out: &mut Vec<SocketAddr>, addrs: Vec<SocketAddr>) {
    for addr in addrs {
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
}

fn format_host_port(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}

fn resolve_s2s_advertise_addrs(label: &str, value: &str) -> Result<Vec<SocketAddr>, String> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        if addr.ip().is_unspecified() {
            return Err(format!(
                "{label} {value:?} must not resolve to an unspecified address"
            ));
        }
        return Ok(vec![addr]);
    }

    let mut resolved = Vec::new();
    for addr in value
        .to_socket_addrs()
        .map_err(|e| format!("invalid {label} {value:?}: {e}"))?
    {
        if !is_routable_advertise_ip(addr.ip()) {
            continue;
        }
        if !resolved.contains(&addr) {
            resolved.push(addr);
        }
    }
    if resolved.is_empty() {
        return Err(format!(
            "{label} {value:?} did not resolve to any routable advertise addresses"
        ));
    }
    Ok(resolved)
}

fn resolve_s2s_addr(label: &str, value: &str) -> Result<SocketAddr, String> {
    let addr = value
        .to_socket_addrs()
        .map_err(|e| format!("invalid {label} {value:?}: {e}"))?
        .next()
        .ok_or_else(|| format!("{label} {value:?} resolved to no addresses"))?;
    if addr.ip().is_unspecified() {
        return Err(format!(
            "{label} {value:?} must not resolve to an unspecified address"
        ));
    }
    Ok(addr)
}

fn is_routable_advertise_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            let octets = ip.octets();
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && octets[0] != 0
                && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
                && !(octets[0] == 198 && (18..=19).contains(&octets[1]))
        }
        std::net::IpAddr::V6(ip) => {
            let segments = ip.segments();
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !((segments[0] & 0xffc0) == 0xfe80)
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum S2sTransportKindConfig {
    Tcp,
    Kcp,
    Quic,
    Udp,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UdpPingUserCountScope {
    Cluster,
    Local,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebAuthMode {
    Password,
    Sso,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerEntrypointConfig {
    pub server_id: String,
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub udp_ping_status_server_id: Option<String>,
    #[serde(default)]
    pub sni: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WebSsoConfig {
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub jwks_url: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default = "default_sso_subject_claim")]
    pub subject_claim: String,
    #[serde(default = "default_sso_username_claim")]
    pub username_claim: String,
    #[serde(default = "default_sso_groups_claim")]
    pub groups_claim: String,
}

impl Default for WebSsoConfig {
    fn default() -> Self {
        Self {
            issuer: None,
            jwks_url: None,
            audience: None,
            subject_claim: default_sso_subject_claim(),
            username_claim: default_sso_username_claim(),
            groups_claim: default_sso_groups_claim(),
        }
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WebAuthConfig {
    #[serde(default = "default_web_auth_modes")]
    pub modes: Vec<WebAuthMode>,
    #[serde(default = "default_true")]
    pub password_enabled: bool,
    #[serde(default)]
    pub sso: WebSsoConfig,
}

impl Default for WebAuthConfig {
    fn default() -> Self {
        Self {
            modes: default_web_auth_modes(),
            password_enabled: true,
            sso: WebSsoConfig::default(),
        }
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WebRtcIceServerConfig {
    pub urls: Vec<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub credential: Option<String>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WebRtcConfig {
    #[serde(default)]
    pub ice_servers: Vec<WebRtcIceServerConfig>,
    #[serde(default = "default_web_max_speaker_ssrcs")]
    pub max_speaker_ssrcs: u32,
    #[serde(default = "default_web_audio_bitrate")]
    pub audio_bitrate: u32,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WebMoqConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub listen: Option<SocketAddr>,
    #[serde(default)]
    pub public_url: Option<String>,
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    #[serde(default = "default_web_max_speaker_ssrcs")]
    pub max_speaker_tracks: u32,
    #[serde(default = "default_web_audio_bitrate")]
    pub audio_bitrate: u32,
}

impl Default for WebMoqConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: None,
            public_url: None,
            cert_path: None,
            key_path: None,
            max_speaker_tracks: default_web_max_speaker_ssrcs(),
            audio_bitrate: default_web_audio_bitrate(),
        }
    }
}

impl Default for WebRtcConfig {
    fn default() -> Self {
        Self {
            ice_servers: Vec::new(),
            max_speaker_ssrcs: default_web_max_speaker_ssrcs(),
            audio_bitrate: default_web_audio_bitrate(),
        }
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WebConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub listen: Option<SocketAddr>,
    #[serde(default)]
    pub public_base_url: Option<String>,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub auth: WebAuthConfig,
    #[serde(default)]
    pub webrtc: WebRtcConfig,
    #[serde(default)]
    pub moq: WebMoqConfig,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: None,
            public_base_url: None,
            allowed_origins: Vec::new(),
            auth: WebAuthConfig::default(),
            webrtc: WebRtcConfig::default(),
            moq: WebMoqConfig::default(),
        }
    }
}

impl From<S2sTransportKindConfig> for TransportKind {
    fn from(value: S2sTransportKindConfig) -> Self {
        match value {
            S2sTransportKindConfig::Tcp => TransportKind::Tcp,
            S2sTransportKindConfig::Kcp => TransportKind::Kcp,
            S2sTransportKindConfig::Quic => TransportKind::Quic,
            S2sTransportKindConfig::Udp => TransportKind::Udp,
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub node_id: u16,
    pub listen: String,
    #[serde(default)]
    pub server_entrypoints: Vec<ServerEntrypointConfig>,
    pub register_name: String,

    // ── Public server registration ────────────────────────────────────────
    /// Password for authenticating with the public server registry.
    #[serde(default)]
    pub register_password: Option<String>,
    /// URL of the public server registry.
    #[serde(default)]
    pub register_url: Option<String>,
    /// Hostname (or IP) that the registry should advertise for this server.
    /// If empty, the server's listen address is used.
    #[serde(default)]
    pub register_hostname: Option<String>,
    /// Geographic location string (e.g. "New York, USA") for the registry.
    #[serde(default)]
    pub register_location: Option<String>,
    pub cert_path: String,
    pub key_path: String,
    pub send_version: bool,
    pub send_build_info: bool,
    pub send_os_info: bool,
    /// Server protocol version advertised to clients and used as the
    /// server-side feature gate for protocol-version-dependent behavior.
    /// Defaults to the compile-time `APP_PROTO_VER`; tests can override it
    /// per server without mutating global process state.
    #[serde(default = "default_server_protocol_version")]
    pub server_protocol_version: ProtocolVersion,
    pub allowed_proxies: Vec<String>,
    pub min_client_version: u64,
    pub max_users: u64,

    // ── Authentication backend ───────────────────────────────────────────
    /// Optional WASM authenticator module loaded by the binary at startup and
    /// on hot reload. `None` falls back to the built-in demo authenticator.
    #[serde(default)]
    pub authenticator_wasm_path: Option<PathBuf>,

    // ── Mumble standard server config ──────────────────────────────────────
    #[serde(default)]
    pub welcome_text: Option<String>,
    #[serde(default = "default_max_bandwidth")]
    pub max_bandwidth: u32,
    #[serde(default = "default_true")]
    pub allow_html: bool,
    #[serde(default = "default_max_text_message_length")]
    pub max_text_message_length: u32,
    #[serde(default = "default_max_image_message_length")]
    pub max_image_message_length: u32,
    #[serde(default)]
    pub default_channel: u32,
    #[serde(default)]
    pub cert_required: bool,

    // ── Blob / persistence ─────────────────────────────────────────────────
    /// Directory used for WAL, snapshot, and blob storage.
    /// `None` = in-memory only (no persistence).
    #[serde(default)]
    pub blob_storage_dir: Option<PathBuf>,
    /// Max channel log entries kept in memory for replay/S2S.
    #[serde(default = "default_channel_log_max_entries")]
    pub channel_log_max_entries: usize,
    /// Max client log entries kept in memory for replay/S2S.
    #[serde(default = "default_client_log_max_entries")]
    pub client_log_max_entries: usize,
    /// Snapshot cadence based on committed channel operations.
    #[serde(default = "default_channel_snapshot_every_ops")]
    pub channel_snapshot_every_ops: u64,
    /// Snapshot cadence based on elapsed seconds.
    #[serde(default = "default_channel_snapshot_every_secs")]
    pub channel_snapshot_every_secs: i64,
    /// Number of oldest WAL log lines to expire on each compaction pass.
    /// Compaction is best-effort and may keep more data to reduce churn.
    #[serde(default = "default_channel_wal_compaction_expire_count")]
    pub channel_wal_compaction_expire_count: usize,

    // ── UDP voice ──────────────────────────────────────────────────────────
    /// Whether to accept UDP voice packets.  When `false`, the UDP drain
    /// loop still runs (for ping/latency) but voice packets are silently
    /// dropped.  Default: `true`.
    #[serde(default = "default_true")]
    pub udp_voice_enabled: bool,
    /// Whether to respond to UDP ping packets with server information
    /// (version, user count, max users, bandwidth).  Default: `true`.
    #[serde(default = "default_true")]
    pub udp_ping_enabled: bool,
    /// Controls whether UDP pings display clusterwide users/max users or only
    /// this node's local users/max users. Default: `cluster`.
    #[serde(default = "default_udp_ping_user_count_scope")]
    pub udp_ping_user_count_scope: UdpPingUserCountScope,
    /// Capacity of the bounded channel between the UDP drain task and the
    /// processing task.  Larger values tolerate processing bursts at the
    /// cost of memory.  Default: 2048 (~2 MB of buffered packets).
    #[serde(default = "default_udp_channel_size")]
    pub udp_channel_size: usize,

    // ── Idle timeout ──────────────────────────────────────────────────────
    /// Seconds of inactivity (no ping) before a client is disconnected.
    /// Default: 30.
    #[serde(default = "default_idle_timeout")]
    pub client_idle_timeout_secs: u64,
    /// Milliseconds before a pending two-phase channel delete is rolled back.
    /// Default: 5000.
    #[serde(default = "default_pending_delete_timeout_ms")]
    pub pending_delete_timeout_ms: u64,

    // ── Access control ────────────────────────────────────────────────────
    /// Groups required to connect.  If empty, all authenticated users are
    /// allowed.  If non-empty, a user must belong to at least one of these
    /// groups to pass authentication.
    #[serde(default)]
    pub required_groups: Vec<String>,

    /// When `true`, `ChannelState` messages include `is_enter_restricted`
    /// and `can_enter` fields computed from ACLs.  Default: `false`.
    #[serde(default)]
    pub send_permission_info: bool,

    /// When `true`, clients only receive user/session information for users
    /// whose current channel they can Traverse. Default: `false`.
    #[serde(default)]
    pub hide_users_without_traverse: bool,

    // ── S2S cluster bootstrap ───────────────────────────────────────────
    #[serde(default)]
    pub s2s: S2sConfig,

    // ── Browser WebRTC gateway ──────────────────────────────────────────
    #[serde(default)]
    pub web: WebConfig,
}

fn default_max_bandwidth() -> u32 {
    72_000
}
fn default_true() -> bool {
    true
}

fn default_server_protocol_version() -> ProtocolVersion {
    APP_PROTO_VER
}
fn default_max_text_message_length() -> u32 {
    5_000
}
fn default_max_image_message_length() -> u32 {
    131_072
}
fn default_udp_channel_size() -> usize {
    2048
}
fn default_udp_ping_user_count_scope() -> UdpPingUserCountScope {
    UdpPingUserCountScope::Cluster
}
fn default_idle_timeout() -> u64 {
    30
}
fn default_pending_delete_timeout_ms() -> u64 {
    5_000
}
fn default_channel_log_max_entries() -> usize {
    10_000
}
fn default_client_log_max_entries() -> usize {
    10_000
}
fn default_channel_snapshot_every_ops() -> u64 {
    10
}
fn default_channel_snapshot_every_secs() -> i64 {
    60
}
fn default_channel_wal_compaction_expire_count() -> usize {
    2_000
}
fn default_sso_subject_claim() -> String {
    "sub".to_string()
}
fn default_sso_username_claim() -> String {
    "preferred_username".to_string()
}
fn default_sso_groups_claim() -> String {
    "groups".to_string()
}
fn default_web_auth_modes() -> Vec<WebAuthMode> {
    vec![WebAuthMode::Password]
}
fn default_web_max_speaker_ssrcs() -> u32 {
    64
}
fn default_web_audio_bitrate() -> u32 {
    64_000
}

impl Config {
    pub fn load() -> Self {
        Self::build_config()
            .try_deserialize()
            .expect("Failed to load config.toml")
    }

    /// Reload config from disk. Returns `Ok(Some(new_config))` if the file
    /// was read successfully, `Ok(None)` if the file doesn't exist, or an
    /// error if deserialization fails.
    pub fn reload() -> Result<Option<Self>, config::ConfigError> {
        // Check if the file actually exists before trying to deserialize
        if !std::path::Path::new("config.toml").exists() {
            return Ok(None);
        }
        Self::build_config().try_deserialize().map(Some)
    }

    fn build_config() -> ConfigCrate {
        ConfigCrate::builder()
            .add_source(File::with_name("config"))
            .add_source(Environment::with_prefix("SHITSPEAK").separator("_"))
            .build()
            .expect("Failed to build config sources")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::time::Duration;

    fn parse_s2s(raw: &str) -> Result<S2sConfig, ::config::ConfigError> {
        ::config::Config::builder()
            .add_source(::config::File::from_str(raw, ::config::FileFormat::Toml))
            .build()?
            .try_deserialize()
    }

    /// Ensure the checked-in `config.toml` parses cleanly under the current
    /// schema, including the new `[s2s.transport]`, `[s2s.overlay]`, and
    /// `[s2s.replications]` sections.
    #[test]
    fn live_config_toml_parses() {
        let raw = std::fs::read_to_string("config.toml").expect("config.toml missing");
        let cfg: Config = ::config::Config::builder()
            .add_source(::config::File::from_str(&raw, ::config::FileFormat::Toml))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");
        assert_eq!(
            cfg.udp_ping_user_count_scope,
            UdpPingUserCountScope::Cluster
        );
        // Spot-check a value from each new block.
        assert!(cfg.s2s.transport.latency_ewma_alpha > 0.0);
        assert!(cfg.s2s.overlay.lsdb_sync_max_response_lsas >= 1);
        assert!(
            cfg.s2s.replications.propose_ttl_ms >= cfg.s2s.replications.delivery_tick_interval_ms
        );
        assert!(!cfg.web.enabled);
        assert_eq!(cfg.web.auth.modes.len(), 2);
        assert_eq!(cfg.web.webrtc.max_speaker_ssrcs, 64);
        assert!(!cfg.web.moq.enabled);
        assert_eq!(cfg.web.moq.max_speaker_tracks, 64);
    }

    #[test]
    fn udp_ping_user_count_scope_parses_local() {
        let raw = r#"
            node_id = 1
            listen = "127.0.0.1:64738"
            register_name = "test"
            cert_path = "cert.pem"
            key_path = "key.pem"
            send_version = true
            send_build_info = true
            send_os_info = true
            allowed_proxies = []
            min_client_version = 0
            max_users = 100
            udp_ping_user_count_scope = "local"
        "#;
        let cfg: Config = ::config::Config::builder()
            .add_source(::config::File::from_str(raw, ::config::FileFormat::Toml))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");
        assert_eq!(cfg.udp_ping_user_count_scope, UdpPingUserCountScope::Local);
    }

    #[test]
    fn server_entrypoints_parse_port_and_sni_scopes() {
        let raw = r#"
            node_id = 1
            listen = "127.0.0.1:64738"
            register_name = "test"
            cert_path = "cert.pem"
            key_path = "key.pem"
            send_version = true
            send_build_info = true
            send_os_info = true
            allowed_proxies = []
            min_client_version = 0
            max_users = 100

            [[server_entrypoints]]
            server_id = "tenant-a"
            listen = "127.0.0.1:64748"
            udp_ping_status_server_id = "tenant-a-status"
            sni = ["tenant-a.example.test", "TENANT-A-ALT.example.test"]

            [[server_entrypoints]]
            server_id = "tenant-b"
            sni = ["tenant-b.example.test"]
        "#;
        let cfg: Config = ::config::Config::builder()
            .add_source(::config::File::from_str(raw, ::config::FileFormat::Toml))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");

        assert_eq!(cfg.server_entrypoints.len(), 2);
        assert_eq!(cfg.server_entrypoints[0].server_id, "tenant-a");
        assert_eq!(
            cfg.server_entrypoints[0].listen.as_deref(),
            Some("127.0.0.1:64748")
        );
        assert_eq!(
            cfg.server_entrypoints[0]
                .udp_ping_status_server_id
                .as_deref(),
            Some("tenant-a-status")
        );
        assert_eq!(cfg.server_entrypoints[0].sni.len(), 2);
        assert_eq!(cfg.server_entrypoints[1].server_id, "tenant-b");
        assert!(cfg.server_entrypoints[1].listen.is_none());
        assert!(cfg.server_entrypoints[1]
            .udp_ping_status_server_id
            .is_none());
    }

    #[test]
    fn s2s_is_disabled_by_default() {
        let cfg = S2sConfig::default();
        assert!(!cfg.is_enabled());
        assert!(cfg.transport_config().unwrap().is_none());
    }

    #[test]
    fn web_config_defaults_to_password_auth() {
        let cfg = WebConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.auth.modes, vec![WebAuthMode::Password]);
        assert!(cfg.auth.password_enabled);
        assert_eq!(cfg.auth.sso.subject_claim, "sub");
        assert_eq!(cfg.webrtc.max_speaker_ssrcs, 64);
        assert!(!cfg.moq.enabled);
        assert_eq!(cfg.moq.max_speaker_tracks, 64);
    }

    #[test]
    fn web_config_parses_ice_and_sso() {
        let raw = r#"
            enabled = true
            listen = "127.0.0.1:64739"
            public_base_url = "https://voice.example.test"
            allowed_origins = ["https://voice.example.test"]

            [auth]
            modes = ["password", "sso"]
            password_enabled = true

            [auth.sso]
            issuer = "https://idp.example.test"
            jwks_url = "https://idp.example.test/jwks"
            audience = "shitspeak"
            subject_claim = "uid"
            username_claim = "name"
            groups_claim = "roles"

            [webrtc]
            max_speaker_ssrcs = 8
            audio_bitrate = 48000
            ice_servers = [
                { urls = ["turn:turn.example.test:3478"], username = "u", credential = "p" },
            ]

            [moq]
            enabled = true
            listen = "127.0.0.1:64740"
            public_url = "https://voice.example.test/web/moq"
            cert_path = "moq-cert.pem"
            key_path = "moq-key.pem"
            max_speaker_tracks = 6
            audio_bitrate = 32000
        "#;
        let cfg: WebConfig = ::config::Config::builder()
            .add_source(::config::File::from_str(raw, ::config::FileFormat::Toml))
            .build()
            .expect("config builder")
            .try_deserialize()
            .expect("config deserialize");

        assert!(cfg.enabled);
        assert_eq!(
            cfg.auth.modes,
            vec![WebAuthMode::Password, WebAuthMode::Sso]
        );
        assert_eq!(cfg.auth.sso.subject_claim, "uid");
        assert_eq!(cfg.webrtc.max_speaker_ssrcs, 8);
        assert_eq!(cfg.webrtc.ice_servers[0].username.as_deref(), Some("u"));
        assert!(cfg.moq.enabled);
        assert_eq!(cfg.moq.listen.unwrap().to_string(), "127.0.0.1:64740");
        assert_eq!(
            cfg.moq.public_url.as_deref(),
            Some("https://voice.example.test/web/moq")
        );
        assert_eq!(
            cfg.moq.cert_path.as_deref(),
            Some(Path::new("moq-cert.pem"))
        );
        assert_eq!(cfg.moq.key_path.as_deref(), Some(Path::new("moq-key.pem")));
        assert_eq!(cfg.moq.max_speaker_tracks, 6);
        assert_eq!(cfg.moq.audio_bitrate, 32000);
    }

    #[test]
    fn s2s_enabled_flat_seed_addresses_parse() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_listen = "0.0.0.0:64739"
            kcp_listen = "0.0.0.0:64740"
            quic_listen = "0.0.0.0:64741"
            udp_listen = "0.0.0.0:64742"
            tcp_advertise = ["127.0.0.1:64739", "127.0.0.2:64739"]
            kcp_advertise = ["127.0.0.1:64740"]
            quic_advertise = ["127.0.0.1:64741"]
            udp_advertise = ["127.0.0.1:64742"]
            status_http_listen = "0.0.0.0:64750"
            persistence_dir = "s2s-state"

            seed_addresses = [
                { transport = "tcp", addr = "10.0.0.2:64739" },
                { transport = "quic", addr = "localhost:64741" },
                { transport = "udp", addr = "10.0.0.4:64742" },
            ]

            [transport]
            recent_probe_retry_cap_secs = 31
            stale_probe_retry_cap_secs = 601
            stale_probe_age_secs = 3601
            unselected_link_probe_interval_secs = 41
            max_outgoing_connections = 777
        "#;
        let cfg: S2sConfig = parse_s2s(raw).expect("s2s config parses");
        assert!(cfg.is_enabled());
        assert_eq!(cfg.seed_addresses.len(), 3);
        assert_eq!(
            cfg.seed_addresses[0].transport(),
            S2sTransportKindConfig::Tcp
        );
        assert_eq!(
            cfg.seed_addresses[1].transport(),
            S2sTransportKindConfig::Quic
        );
        assert_eq!(
            cfg.seed_addresses[2].transport(),
            S2sTransportKindConfig::Udp
        );
        assert_eq!(cfg.seed_addresses[1].addr(), "localhost:64741");
        assert_eq!(
            cfg.status_http_listen,
            Some("0.0.0.0:64750".parse().unwrap())
        );

        let transport = cfg
            .transport_config()
            .expect("valid transport config")
            .expect("s2s enabled");
        assert_eq!(transport.seed_addresses().len(), 3);
        assert_eq!(
            transport.tcp_advertise(),
            &[
                "127.0.0.1:64739".parse::<SocketAddr>().unwrap(),
                "127.0.0.2:64739".parse::<SocketAddr>().unwrap()
            ]
        );
        assert_eq!(
            transport.kcp_advertise(),
            &["127.0.0.1:64740".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            transport.quic_advertise(),
            &["127.0.0.1:64741".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            transport.udp_advertise(),
            &["127.0.0.1:64742".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(transport.backoff_cap(), Duration::from_secs(31));
        assert_eq!(transport.stale_backoff_cap(), Duration::from_secs(601));
        assert_eq!(transport.stale_backoff_after(), Duration::from_secs(3601));
        assert_eq!(
            transport.unselected_link_probe_interval(),
            Duration::from_secs(41)
        );
        assert_eq!(transport.max_outgoing_connections(), 777);
        assert!(cfg.overlay_config().persistence_dir().is_some());
    }

    #[test]
    fn s2s_overlay_route_transit_messages_parses() {
        let raw = r#"
            enabled = false

            [overlay]
            route_transit_messages = false
        "#;
        let cfg: S2sConfig = parse_s2s(raw).expect("s2s config parses");
        assert!(!cfg.overlay.route_transit_messages);
        assert!(!cfg.overlay_config().route_transit_messages());
    }

    #[test]
    fn s2s_enabled_requires_identity_paths() {
        let cfg = S2sConfig {
            enabled: true,
            ..Default::default()
        };
        let error = cfg.transport_config().unwrap_err();
        assert!(error.contains("ca_path"));
    }

    #[test]
    fn s2s_rejects_invalid_seed_transport() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            seed_addresses = [
                { transport = "ws", addr = "10.0.0.2:64739" },
            ]
        "#;
        assert!(parse_s2s(raw).is_err());
    }

    #[test]
    fn s2s_rejects_invalid_seed_address() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            seed_addresses = [
                { transport = "tcp", addr = "not an address" },
            ]
        "#;
        let cfg = parse_s2s(raw).expect("seed address text deserializes");
        assert!(cfg.transport_config().is_err());
    }

    #[test]
    fn s2s_rejects_unspecified_seed_address() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            seed_addresses = [
                { transport = "tcp", addr = "0.0.0.0:64739" },
            ]
        "#;
        let cfg = parse_s2s(raw).expect("seed address text deserializes");
        let err = cfg
            .transport_config()
            .expect_err("unspecified seed address is not dialable");
        assert!(err.contains("must not resolve to an unspecified address"));
    }

    #[test]
    fn s2s_rejects_unspecified_advertise_address() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_advertise = ["0.0.0.0:64739"]
        "#;
        let cfg = parse_s2s(raw).expect("advertise address text deserializes");
        let err = cfg
            .transport_config()
            .expect_err("unspecified advertise address is not dialable");
        assert!(err.contains("must not resolve to an unspecified address"));
    }

    #[test]
    fn s2s_rejects_hostname_advertise_without_routable_addresses() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_advertise = ["localhost:64739"]
        "#;
        let cfg = parse_s2s(raw).expect("advertise hostname text deserializes");
        let err = cfg
            .transport_config()
            .expect_err("hostname advertise must resolve to routable addresses");
        assert!(err.contains("did not resolve to any routable advertise addresses"));
    }

    #[test]
    fn s2s_dns_advertise_filter_allows_private_network_addresses() {
        assert!(is_routable_advertise_ip("10.182.157.4".parse().unwrap()));
        assert!(is_routable_advertise_ip("fd00::1".parse().unwrap()));
        assert!(!is_routable_advertise_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_routable_advertise_ip("169.254.1.1".parse().unwrap()));
    }

    #[test]
    fn s2s_blank_scalar_advertise_is_treated_as_no_override() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_listen = "0.0.0.0:64739"
            tcp_advertise = ""
        "#;
        let cfg = parse_s2s(raw).expect("blank legacy advertise string deserializes");
        let transport = cfg
            .transport_config()
            .expect("blank advertise is ignored")
            .expect("s2s enabled");
        assert!(transport.tcp_advertise().is_empty());
    }

    #[test]
    fn s2s_auto_advertise_host_is_used_when_no_override_is_set() {
        let raw = r#"
            enabled = true
            ca_path = "s2s-ca.pem"
            cert_path = "s2s-node.pem"
            key_path = "s2s-node.key"
            tcp_listen = "0.0.0.0:64739"
        "#;
        let cfg = parse_s2s(raw).expect("s2s config parses");
        let transport = cfg
            .transport_config_with_auto_advertise_host(Some("127.0.0.1"))
            .expect("auto advertise host resolves")
            .expect("s2s enabled");
        assert_eq!(
            transport.tcp_advertise(),
            &["127.0.0.1:64739".parse::<SocketAddr>().unwrap()]
        );
    }
}
