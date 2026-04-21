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
}

fn default_max_bandwidth() -> u32 { 72_000 }
fn default_true() -> bool { true }
fn default_max_text_message_length() -> u32 { 5_000 }
fn default_max_image_message_length() -> u32 { 131_072 }
fn default_udp_channel_size() -> usize { 2048 }
fn default_idle_timeout() -> u64 { 30 }

impl Config {
    pub fn load() -> Self {
        ConfigCrate::builder()
            .add_source(File::with_name("config"))
            .add_source(Environment::with_prefix("SHITSPEAK").separator("_"))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap()
    }
}

