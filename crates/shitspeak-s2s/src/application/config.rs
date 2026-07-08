use serde::Deserialize;

/// Top-level configuration block for the application (L3) layer.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct ApplicationConfig {
    #[serde(default)]
    pub voice: VoiceConfig,
}

/// Voice-service tunables. Moderation is fire-and-forget and exposes no
/// knobs.
#[derive(Deserialize, Debug, Clone)]
pub struct VoiceConfig {
    /// `"broadcast"` (default) or `"targeted"`. Broadcast routes every
    /// frame to every alive node; targeted maintains a recipient index
    /// and fans out per channel/listener subscription.
    #[serde(default = "default_delivery_strategy")]
    pub delivery_strategy: String,

    /// Per-(sender, epoch) max wait before emitting `pending` past a gap.
    /// Higher = more reorder tolerance, more glass-to-glass latency.
    #[serde(default = "default_reorder_max_delay_ms")]
    pub reorder_max_delay_ms: u64,

    /// Per-sender pending cap (drop oldest pending when exceeded).
    #[serde(default = "default_reorder_max_buffered_frames")]
    pub reorder_max_buffered_frames: usize,

    /// Frames older than `next_seq_to_emit - this` are dropped on receipt.
    #[serde(default = "default_reorder_max_drop_lag_frames")]
    pub reorder_max_drop_lag_frames: u64,

    /// Node-wide pending cap across all senders (drop-tail).
    #[serde(default = "default_reorder_max_total_buffer")]
    pub reorder_max_total_buffer: usize,

    /// Fast-path bypass — receivers emit frames in arrival order without
    /// any pending state. Useful when the operator's backbone genuinely
    /// doesn't reorder.
    #[serde(default)]
    pub reorder_disabled: bool,

    /// Use per-sender adaptive jitter delay instead of the fixed
    /// `reorder_max_delay_ms` gap deadline.
    #[serde(default = "default_adaptive_jitter_enabled")]
    pub adaptive_jitter_enabled: bool,

    /// Lower bound for the adaptive per-sender reorder delay.
    #[serde(default = "default_adaptive_jitter_min_delay_ms")]
    pub adaptive_jitter_min_delay_ms: u64,

    /// Upper bound for the adaptive per-sender reorder delay.
    #[serde(default = "default_adaptive_jitter_max_delay_ms")]
    pub adaptive_jitter_max_delay_ms: u64,

    /// Amount added after observed jitter/loss pressure.
    #[serde(default = "default_adaptive_jitter_growth_step_ms")]
    pub adaptive_jitter_growth_step_ms: u64,

    /// Amount removed after sustained in-order delivery.
    #[serde(default = "default_adaptive_jitter_decay_step_ms")]
    pub adaptive_jitter_decay_step_ms: u64,

    /// Enable bounded best-effort repair for S2S voice gaps.
    #[serde(default = "default_repair_enabled")]
    pub repair_enabled: bool,

    /// Delay before requesting repair for a still-open sequence gap.
    #[serde(default = "default_repair_nack_delay_ms")]
    pub repair_nack_delay_ms: u64,

    /// How long the origin keeps encoded voice frames available for replay.
    #[serde(default = "default_repair_cache_ms")]
    pub repair_cache_ms: u64,

    /// Short transport TTL for replayed/alternate voice repair frames.
    #[serde(default = "default_repair_transport_ttl_ms")]
    pub repair_transport_ttl_ms: u64,

    /// Start sending proactive alternate copies when UDP loss reaches this.
    #[serde(default = "default_repair_loss_start_ppm")]
    pub repair_loss_start_ppm: u32,

    /// Reach the configured proactive copy budget when UDP loss reaches this.
    #[serde(default = "default_repair_full_dup_loss_ppm")]
    pub repair_full_dup_loss_ppm: u32,

    /// Start proactive alternate copies when UDP jitter reaches this many ms.
    #[serde(default = "default_repair_jitter_start_ms")]
    pub repair_jitter_start_ms: u64,

    /// Extra repair copies allowed per voice frame.
    #[serde(default = "default_repair_max_extra_copies_per_frame")]
    pub repair_max_extra_copies_per_frame: usize,
}

impl Default for VoiceConfig {
    fn default() -> Self {
        Self {
            delivery_strategy: default_delivery_strategy(),
            reorder_max_delay_ms: default_reorder_max_delay_ms(),
            reorder_max_buffered_frames: default_reorder_max_buffered_frames(),
            reorder_max_drop_lag_frames: default_reorder_max_drop_lag_frames(),
            reorder_max_total_buffer: default_reorder_max_total_buffer(),
            reorder_disabled: false,
            adaptive_jitter_enabled: default_adaptive_jitter_enabled(),
            adaptive_jitter_min_delay_ms: default_adaptive_jitter_min_delay_ms(),
            adaptive_jitter_max_delay_ms: default_adaptive_jitter_max_delay_ms(),
            adaptive_jitter_growth_step_ms: default_adaptive_jitter_growth_step_ms(),
            adaptive_jitter_decay_step_ms: default_adaptive_jitter_decay_step_ms(),
            repair_enabled: default_repair_enabled(),
            repair_nack_delay_ms: default_repair_nack_delay_ms(),
            repair_cache_ms: default_repair_cache_ms(),
            repair_transport_ttl_ms: default_repair_transport_ttl_ms(),
            repair_loss_start_ppm: default_repair_loss_start_ppm(),
            repair_full_dup_loss_ppm: default_repair_full_dup_loss_ppm(),
            repair_jitter_start_ms: default_repair_jitter_start_ms(),
            repair_max_extra_copies_per_frame: default_repair_max_extra_copies_per_frame(),
        }
    }
}

/// What `delivery_strategy` resolves to, after parsing the config string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStrategy {
    Broadcast,
    Targeted,
}

impl DeliveryStrategy {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "targeted" => DeliveryStrategy::Targeted,
            _ => DeliveryStrategy::Broadcast,
        }
    }
}

fn default_delivery_strategy() -> String {
    "broadcast".to_owned()
}
fn default_reorder_max_delay_ms() -> u64 {
    20
}
fn default_reorder_max_buffered_frames() -> usize {
    4
}
fn default_reorder_max_drop_lag_frames() -> u64 {
    16
}
fn default_reorder_max_total_buffer() -> usize {
    1024
}
fn default_adaptive_jitter_enabled() -> bool {
    true
}
fn default_adaptive_jitter_min_delay_ms() -> u64 {
    40
}
fn default_adaptive_jitter_max_delay_ms() -> u64 {
    600
}
fn default_adaptive_jitter_growth_step_ms() -> u64 {
    80
}
fn default_adaptive_jitter_decay_step_ms() -> u64 {
    20
}
fn default_repair_enabled() -> bool {
    true
}
fn default_repair_nack_delay_ms() -> u64 {
    8
}
fn default_repair_cache_ms() -> u64 {
    300
}
fn default_repair_transport_ttl_ms() -> u64 {
    120
}
fn default_repair_loss_start_ppm() -> u32 {
    10_000
}
fn default_repair_full_dup_loss_ppm() -> u32 {
    30_000
}
fn default_repair_jitter_start_ms() -> u64 {
    40
}
fn default_repair_max_extra_copies_per_frame() -> usize {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voice_repair_defaults_deserialize_enabled() {
        let cfg: ApplicationConfig = serde_json::from_str(r#"{"voice":{}}"#).unwrap();
        assert!(cfg.voice.repair_enabled);
        assert_eq!(cfg.voice.repair_nack_delay_ms, 8);
        assert_eq!(cfg.voice.repair_cache_ms, 300);
        assert_eq!(cfg.voice.repair_transport_ttl_ms, 120);
        assert_eq!(cfg.voice.repair_loss_start_ppm, 10_000);
        assert_eq!(cfg.voice.repair_full_dup_loss_ppm, 30_000);
        assert_eq!(cfg.voice.repair_jitter_start_ms, 40);
        assert_eq!(cfg.voice.repair_max_extra_copies_per_frame, 1);
    }
}
