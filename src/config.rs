use std::path::PathBuf;

use serde::Deserialize;
use config::{Config as ConfigCrate, Environment, File};

use crate::s2s::application::ApplicationConfig;
use crate::s2s::overlay::OverlayTuning;
use crate::s2s::replications::ReplicationTuning;
use crate::s2s::transport::TransportTuning;

#[derive(Deserialize, Debug, Clone, Default)]
pub struct S2sConfig {
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

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub node_id: u16,
    pub listen: String,
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
}

fn default_max_bandwidth() -> u32 { 72_000 }
fn default_true() -> bool { true }
fn default_max_text_message_length() -> u32 { 5_000 }
fn default_max_image_message_length() -> u32 { 131_072 }
fn default_udp_channel_size() -> usize { 2048 }
fn default_idle_timeout() -> u64 { 30 }
fn default_channel_log_max_entries() -> usize { 10_000 }
fn default_client_log_max_entries() -> usize { 10_000 }
fn default_channel_snapshot_every_ops() -> u64 { 10 }
fn default_channel_snapshot_every_secs() -> i64 { 60 }
fn default_channel_wal_compaction_expire_count() -> usize { 2_000 }

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
        // Spot-check a value from each new block.
        assert!(cfg.s2s.transport.latency_ewma_alpha > 0.0);
        assert!(cfg.s2s.overlay.lsdb_sync_max_response_lsas >= 1);
        assert!(cfg.s2s.replications.propose_ttl_ms >= cfg.s2s.replications.delivery_tick_interval_ms);
    }
}

