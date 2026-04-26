use std::path::PathBuf;

use serde::Deserialize;
use config::{Config as ConfigCrate, Environment, File};

use crate::constants::MAX_NODE_ID;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub node_id: u16,
    pub listen: String,
    pub opus_threshold: u16,
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

    // ── Listener volume broadcast (mumble 1.4.0+) ──────────────────────────
    /// When `true`, listener volume adjustments are broadcast in `UserState`
    /// to all v1.4.0+ clients.  When `false`, sent only to the owning session.
    #[serde(default = "default_true")]
    pub broadcast_listener_volume_adjustments: bool,

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

