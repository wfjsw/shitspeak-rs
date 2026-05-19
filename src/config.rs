use std::net::SocketAddr;
use std::path::PathBuf;

use crate::constants::APP_PROTO_VER;
use crate::protocol_version::ProtocolVersion;

use config::{Config as ConfigCrate, Environment, File};
use serde::Deserialize;

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

        cfg = cfg.with_seed_addresses(
            self.seed_addresses
                .iter()
                .map(S2sSeedAddressConfig::peer_address)
                .collect(),
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

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct S2sSeedAddressConfig {
    transport: S2sTransportKindConfig,
    addr: SocketAddr,
}

impl S2sSeedAddressConfig {
    pub fn new(transport: S2sTransportKindConfig, addr: SocketAddr) -> Self {
        Self { transport, addr }
    }

    pub fn transport(&self) -> S2sTransportKindConfig {
        self.transport
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn peer_address(&self) -> PeerAddress {
        PeerAddress::new(self.addr, self.transport.into())
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
        assert_eq!(cfg.server_entrypoints[0].sni.len(), 2);
        assert_eq!(cfg.server_entrypoints[1].server_id, "tenant-b");
        assert!(cfg.server_entrypoints[1].listen.is_none());
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
            persistence_dir = "s2s-state"

            seed_addresses = [
                { transport = "tcp", addr = "10.0.0.2:64739" },
                { transport = "quic", addr = "10.0.0.3:64741" },
                { transport = "udp", addr = "10.0.0.4:64742" },
            ]
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

        let transport = cfg
            .transport_config()
            .expect("valid transport config")
            .expect("s2s enabled");
        assert_eq!(transport.seed_addresses().len(), 3);
        assert!(cfg.overlay_config().persistence_dir().is_some());
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
        assert!(parse_s2s(raw).is_err());
    }
}
