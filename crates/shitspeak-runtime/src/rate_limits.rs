//! Abuse-protection rate limits and size caps.
//!
//! All limits are deliberately generous: they stop floods and brute force
//! without ever affecting legitimate clients, clusters, or deployments where
//! several Mumble instances share one public IP.

use std::time::Duration;

/// Maximum keys tracked by any keyed rate limiter (bounds memory).
pub const RATE_LIMITER_MAX_ENTRIES: usize = 65_536;

// ── Client protocol messages (M6) ──────────────────────────────────────────

/// Per-message-type rate tiers (M6). Text messages relay to every recipient,
/// while state changes can cause other server-side work. Query messages bypass
/// this limiter, and RequestBlob has its own per-client FIFO queue. Realtime
/// messages (Ping, UDPTunnel) also bypass the limiter entirely.
///
/// Values are (rate_per_second, burst) per client session per tier.
pub const MESSAGE_TIER_TEXT_RATE_PER_SECOND: f64 = 30.0;
pub const MESSAGE_TIER_TEXT_BURST: f64 = 60.0;
pub const MESSAGE_TIER_STATE_RATE_PER_SECOND: f64 = 100.0;
pub const MESSAGE_TIER_STATE_BURST: f64 = 300.0;

/// Tier indices used by [`crate::server::connection::message_rate_tier`].
pub const MESSAGE_TIER_TEXT: usize = 0;
pub const MESSAGE_TIER_STATE: usize = 1;
pub const MESSAGE_TIER_COUNT: usize = 2;

/// Maximum concurrently in-flight handler tasks per connection. When reached,
/// the connection stops reading (TCP backpressure) instead of spawning
/// unbounded tasks.
pub const MAX_IN_FLIGHT_HANDLERS: usize = 32;

// ── UDP ping reflector ─────────────────────────────────────────────────────

/// UDP ping replies allowed per source IP. Multiple Mumble instances behind
/// one NAT each keep their own limiter, so legit server-browser traffic is
/// unaffected.
pub const UDP_PING_RATE_PER_SECOND: f64 = 20.0;
pub const UDP_PING_BURST: f64 = 100.0;

// ── Temporary channels (M12) ───────────────────────────────────────────────

/// Temporary channel creations allowed per client.
pub const TEMP_CHANNEL_RATE_PER_SECOND: f64 = 1.0;
pub const TEMP_CHANNEL_BURST: f64 = 10.0;

// ── S2S UDP key exchange (M2) ──────────────────────────────────────────────

/// Key-offer/key-ready handshake packets allowed per source IP. Steady-state
/// traffic never hits this: key exchanges happen once per establishment and
/// on re-key only, so a hub bursting many handshakes at startup stays far
/// under the limit.
pub const S2S_KEY_EXCHANGE_RATE_PER_SECOND: f64 = 10.0;
pub const S2S_KEY_EXCHANGE_BURST: f64 = 64.0;

// ── Connection handling (H2) ───────────────────────────────────────────────

/// Deadline for completing a TLS handshake after TCP accept.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

// ── Channel limits (M12) ───────────────────────────────────────────────────

/// Maximum channel name length in bytes.
pub const MAX_CHANNEL_NAME_BYTES: usize = 128;
/// Maximum channel description blob size in bytes.
pub const MAX_CHANNEL_DESCRIPTION_BYTES: usize = 1_048_576;

// ── Session blobs (M5) ─────────────────────────────────────────────────────

/// Maximum size of a fetched session blob (texture/comment) in bytes.
pub const MAX_SESSION_BLOB_BYTES: usize = 1_048_576;
/// Default total on-disk budget for the session blob cache before LRU
/// eviction of *unreferenced* blobs. Configurable via
/// `session_blob_cache_budget_bytes` (0 disables eviction).
pub const DEFAULT_SESSION_BLOB_TOTAL_BUDGET_BYTES: u64 = 256 * 1024 * 1024;
