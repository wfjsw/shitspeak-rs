use std::time::Duration;

use serde::{
    Deserialize,
    de::{Error as _, IgnoredAny},
};

/// Top-level configuration block for the application (L3) layer.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct ApplicationConfig {
    #[serde(default)]
    pub voice: VoiceConfig,
}

/// Voice-service tunables. Moderation is fire-and-forget and exposes no
/// knobs.
#[derive(Debug, Clone)]
pub struct VoiceConfig {
    /// `"broadcast"` (default) or `"targeted"`. Broadcast routes every
    /// frame to every alive node; targeted maintains a recipient index
    /// and fans out per channel/listener subscription.
    pub delivery_strategy: String,

    /// Use the generic distribution-tree transport for either broadcast or
    /// targeted voice recipient sets.
    pub tree_delivery_enabled: bool,

    /// Per-speaker max wait before emitting `pending` past a gap.
    /// Higher = more reorder tolerance, more glass-to-glass latency.
    pub reorder_max_delay_ms: u64,

    /// Per-sender pending cap (drop oldest pending when exceeded).
    pub reorder_max_buffered_frames: usize,

    /// Node-wide pending cap across all senders (drop-tail).
    pub reorder_max_total_buffer: usize,

    /// Idle time after which an inactive speaker's reorder state is pruned.
    pub reorder_idle_reset_ms: u64,

    /// When a gap's in-order skew tolerance (`reorder_max_delay_ms` / the
    /// adaptive delay) expires unfilled, how much longer the receiver keeps
    /// the whole buffered chunk held so a late repair can close the hole
    /// without a clip. Bounded delay beats a permanent hole. Set to 0 to
    /// flush at the skew tolerance as before.
    pub chunk_hold_budget_ms: u64,

    /// Fast-path bypass — receivers emit frames in arrival order without
    /// any pending state. Useful when the operator's backbone genuinely
    /// doesn't reorder.
    pub reorder_disabled: bool,

    /// Use per-sender adaptive jitter delay instead of the fixed
    /// `reorder_max_delay_ms` gap deadline.
    pub adaptive_jitter_enabled: bool,

    /// Lower bound for the adaptive per-sender reorder delay.
    pub adaptive_jitter_min_delay_ms: u64,

    /// Upper bound for the adaptive per-sender reorder delay.
    pub adaptive_jitter_max_delay_ms: u64,

    /// Amount added after observed jitter/loss pressure.
    pub adaptive_jitter_growth_step_ms: u64,

    /// Amount removed after sustained in-order delivery.
    pub adaptive_jitter_decay_step_ms: u64,

    /// Enable bounded best-effort repair for S2S voice gaps.
    pub repair_enabled: bool,

    /// How long the origin keeps encoded voice frames available for replay.
    pub repair_cache_ms: u64,

    /// Short transport TTL for normal outbound voice frames.
    transport_ttl_ms: u64,

    /// Short transport TTL for replayed/alternate voice repair frames.
    pub repair_transport_ttl_ms: u64,

    /// Short transport TTL for repair requests. Defaults to
    /// `repair_transport_ttl_ms` when omitted.
    pub repair_request_ttl_ms: u64,

    /// Start sending proactive alternate copies when UDP loss reaches this.
    pub repair_loss_start_ppm: u32,

    /// Reach the configured proactive copy budget when UDP loss reaches this.
    pub repair_full_dup_loss_ppm: u32,

    /// Start proactive alternate copies when UDP jitter reaches this many ms.
    pub repair_jitter_start_ms: u64,

    /// Extra proactive copies allowed per voice frame (0 through 2).
    pub repair_max_extra_copies_per_frame: usize,

    /// Percentage of the repair mint reserved for reactive/tail repair.
    pub repair_reactive_reserve_pct: u8,

    /// Percentage of the repair mint that proactive work may never borrow.
    pub repair_reactive_hard_reserve_pct: u8,

    /// Change-set C3: enable best-effort block FEC over the datagram voice
    /// lane. The sender XORs the last `voice_fec_block_size` equal-length
    /// payloads of a speaker into one parity frame, sent unicast to each
    /// first hop that carried the block. Parity frames are rate-limited by
    /// the per-first-hop `voice_overlap` lane-headroom budget (capacity ∝
    /// accepted original bytes) and only emitted when the first hop's live
    /// loss reaches `voice_fec_loss_gate_ppm`, so healthy lanes pay nothing.
    pub voice_fec_enabled: bool,

    /// Number of consecutive equal-length payloads covered by one parity
    /// frame. A block whose members are not all the same length is dropped
    /// (no redundancy) rather than sent with length ambiguity.
    pub voice_fec_block_size: usize,

    /// How many recent payloads per `(sender_session, sender_epoch, from)`
    /// the receiver caches to XOR against a parity block, and how many
    /// received parity blocks it retains.
    pub voice_fec_receiver_window: usize,

    /// Emit FEC parity for a first hop only when its live lane loss reaches
    /// this many ppm (derived from the datagram-lane loss metric). Defaults
    /// to `repair_loss_start_ppm` semantics.
    pub voice_fec_loss_gate_ppm: u32,
}

impl Default for VoiceConfig {
    fn default() -> Self {
        Self {
            delivery_strategy: default_delivery_strategy(),
            tree_delivery_enabled: default_tree_delivery_enabled(),
            reorder_max_delay_ms: default_reorder_max_delay_ms(),
            reorder_max_buffered_frames: default_reorder_max_buffered_frames(),
            reorder_max_total_buffer: default_reorder_max_total_buffer(),
            reorder_idle_reset_ms: default_reorder_idle_reset_ms(),
            chunk_hold_budget_ms: default_chunk_hold_budget_ms(),
            reorder_disabled: false,
            adaptive_jitter_enabled: default_adaptive_jitter_enabled(),
            adaptive_jitter_min_delay_ms: default_adaptive_jitter_min_delay_ms(),
            adaptive_jitter_max_delay_ms: default_adaptive_jitter_max_delay_ms(),
            adaptive_jitter_growth_step_ms: default_adaptive_jitter_growth_step_ms(),
            adaptive_jitter_decay_step_ms: default_adaptive_jitter_decay_step_ms(),
            repair_enabled: default_repair_enabled(),
            repair_cache_ms: default_repair_cache_ms(),
            transport_ttl_ms: default_transport_ttl_ms(),
            repair_transport_ttl_ms: default_repair_transport_ttl_ms(),
            repair_request_ttl_ms: default_repair_transport_ttl_ms(),
            repair_loss_start_ppm: default_repair_loss_start_ppm(),
            repair_full_dup_loss_ppm: default_repair_full_dup_loss_ppm(),
            repair_jitter_start_ms: default_repair_jitter_start_ms(),
            repair_max_extra_copies_per_frame: default_repair_max_extra_copies_per_frame(),
            repair_reactive_reserve_pct: default_repair_reactive_reserve_pct(),
            repair_reactive_hard_reserve_pct: default_repair_reactive_hard_reserve_pct(),
            voice_fec_enabled: default_voice_fec_enabled(),
            voice_fec_block_size: default_voice_fec_block_size(),
            voice_fec_receiver_window: default_voice_fec_receiver_window(),
            voice_fec_loss_gate_ppm: default_voice_fec_loss_gate_ppm(),
        }
    }
}

#[derive(Deserialize)]
struct VoiceConfigWire {
    #[serde(default = "default_delivery_strategy")]
    delivery_strategy: String,
    #[serde(default = "default_tree_delivery_enabled")]
    tree_delivery_enabled: bool,
    #[serde(default = "default_reorder_max_delay_ms")]
    reorder_max_delay_ms: u64,
    #[serde(default = "default_reorder_max_buffered_frames")]
    reorder_max_buffered_frames: usize,
    #[serde(default = "default_reorder_max_total_buffer")]
    reorder_max_total_buffer: usize,
    #[serde(default = "default_reorder_idle_reset_ms")]
    reorder_idle_reset_ms: u64,
    #[serde(default = "default_chunk_hold_budget_ms")]
    chunk_hold_budget_ms: u64,
    #[serde(default)]
    reorder_disabled: bool,
    #[serde(default = "default_adaptive_jitter_enabled")]
    adaptive_jitter_enabled: bool,
    #[serde(default = "default_adaptive_jitter_min_delay_ms")]
    adaptive_jitter_min_delay_ms: u64,
    #[serde(default = "default_adaptive_jitter_max_delay_ms")]
    adaptive_jitter_max_delay_ms: u64,
    // Compatibility-only for one release. Reorder is now the sole remote
    // buffer, and a gap opens a repair request immediately.
    #[serde(default)]
    remote_playout_min_ms: Option<IgnoredAny>,
    #[serde(default)]
    remote_playout_max_ms: Option<IgnoredAny>,
    #[serde(default)]
    remote_playout_p99_margin_ms: Option<IgnoredAny>,
    #[serde(default)]
    remote_playout_idle_reset_ms: Option<IgnoredAny>,
    #[serde(default)]
    reorder_max_drop_lag_frames: Option<IgnoredAny>,
    #[serde(default = "default_adaptive_jitter_growth_step_ms")]
    adaptive_jitter_growth_step_ms: u64,
    #[serde(default = "default_adaptive_jitter_decay_step_ms")]
    adaptive_jitter_decay_step_ms: u64,
    #[serde(default = "default_repair_enabled")]
    repair_enabled: bool,
    #[serde(default)]
    repair_nack_delay_ms: Option<IgnoredAny>,
    #[serde(default = "default_repair_cache_ms")]
    repair_cache_ms: u64,
    #[serde(default = "default_transport_ttl_ms")]
    transport_ttl_ms: u64,
    #[serde(default = "default_repair_transport_ttl_ms")]
    repair_transport_ttl_ms: u64,
    #[serde(default)]
    repair_request_ttl_ms: Option<u64>,
    #[serde(default = "default_repair_loss_start_ppm")]
    repair_loss_start_ppm: u32,
    #[serde(default = "default_repair_full_dup_loss_ppm")]
    repair_full_dup_loss_ppm: u32,
    #[serde(default = "default_repair_jitter_start_ms")]
    repair_jitter_start_ms: u64,
    #[serde(default = "default_repair_max_extra_copies_per_frame")]
    repair_max_extra_copies_per_frame: usize,
    #[serde(default = "default_repair_reactive_reserve_pct")]
    repair_reactive_reserve_pct: u8,
    #[serde(default = "default_repair_reactive_hard_reserve_pct")]
    repair_reactive_hard_reserve_pct: u8,
    #[serde(default = "default_voice_fec_enabled")]
    voice_fec_enabled: bool,
    #[serde(default = "default_voice_fec_block_size")]
    voice_fec_block_size: usize,
    #[serde(default = "default_voice_fec_receiver_window")]
    voice_fec_receiver_window: usize,
    #[serde(default = "default_voice_fec_loss_gate_ppm")]
    voice_fec_loss_gate_ppm: u32,
}

impl<'de> Deserialize<'de> for VoiceConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = VoiceConfigWire::deserialize(deserializer)?;
        if raw.repair_max_extra_copies_per_frame > 2 {
            return Err(D::Error::custom(
                "repair_max_extra_copies_per_frame must be between 0 and 2",
            ));
        }
        if raw.repair_reactive_reserve_pct > 100 {
            return Err(D::Error::custom(
                "repair_reactive_reserve_pct must be between 0 and 100",
            ));
        }
        if raw.repair_reactive_hard_reserve_pct > raw.repair_reactive_reserve_pct {
            return Err(D::Error::custom(
                "repair_reactive_hard_reserve_pct must not exceed repair_reactive_reserve_pct",
            ));
        }
        if raw.voice_fec_block_size < 2 || raw.voice_fec_block_size > 32 {
            return Err(D::Error::custom(
                "voice_fec_block_size must be between 2 and 32",
            ));
        }
        let _ = (
            raw.remote_playout_min_ms.as_ref(),
            raw.remote_playout_max_ms.as_ref(),
            raw.remote_playout_p99_margin_ms.as_ref(),
            raw.remote_playout_idle_reset_ms.as_ref(),
            raw.reorder_max_drop_lag_frames.as_ref(),
            raw.repair_nack_delay_ms.as_ref(),
        );
        Ok(Self {
            delivery_strategy: raw.delivery_strategy,
            tree_delivery_enabled: raw.tree_delivery_enabled,
            reorder_max_delay_ms: raw.reorder_max_delay_ms,
            reorder_max_buffered_frames: raw.reorder_max_buffered_frames,
            reorder_max_total_buffer: raw.reorder_max_total_buffer,
            reorder_idle_reset_ms: raw.reorder_idle_reset_ms,
            chunk_hold_budget_ms: raw.chunk_hold_budget_ms,
            reorder_disabled: raw.reorder_disabled,
            adaptive_jitter_enabled: raw.adaptive_jitter_enabled,
            adaptive_jitter_min_delay_ms: raw.adaptive_jitter_min_delay_ms,
            adaptive_jitter_max_delay_ms: raw.adaptive_jitter_max_delay_ms,
            adaptive_jitter_growth_step_ms: raw.adaptive_jitter_growth_step_ms,
            adaptive_jitter_decay_step_ms: raw.adaptive_jitter_decay_step_ms,
            repair_enabled: raw.repair_enabled,
            repair_cache_ms: raw.repair_cache_ms,
            transport_ttl_ms: raw.transport_ttl_ms,
            repair_transport_ttl_ms: raw.repair_transport_ttl_ms,
            repair_request_ttl_ms: raw
                .repair_request_ttl_ms
                .unwrap_or(raw.repair_transport_ttl_ms),
            repair_loss_start_ppm: raw.repair_loss_start_ppm,
            repair_full_dup_loss_ppm: raw.repair_full_dup_loss_ppm,
            repair_jitter_start_ms: raw.repair_jitter_start_ms,
            repair_max_extra_copies_per_frame: raw.repair_max_extra_copies_per_frame,
            repair_reactive_reserve_pct: raw.repair_reactive_reserve_pct,
            repair_reactive_hard_reserve_pct: raw.repair_reactive_hard_reserve_pct,
            voice_fec_enabled: raw.voice_fec_enabled,
            voice_fec_block_size: raw.voice_fec_block_size,
            voice_fec_receiver_window: raw.voice_fec_receiver_window,
            voice_fec_loss_gate_ppm: raw.voice_fec_loss_gate_ppm,
        })
    }
}

impl VoiceConfig {
    pub fn transport_ttl(&self) -> Duration {
        Duration::from_millis(self.transport_ttl_ms)
    }

    pub fn transport_ttl_ms(&self) -> u64 {
        self.transport_ttl_ms
    }

    pub fn set_transport_ttl_ms(&mut self, ms: u64) {
        self.transport_ttl_ms = ms;
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
fn default_tree_delivery_enabled() -> bool {
    true
}
fn default_reorder_max_delay_ms() -> u64 {
    40
}
fn default_reorder_max_buffered_frames() -> usize {
    48
}
fn default_reorder_max_total_buffer() -> usize {
    4_096
}
fn default_reorder_idle_reset_ms() -> u64 {
    2_000
}
fn default_chunk_hold_budget_ms() -> u64 {
    1_600
}
fn default_adaptive_jitter_enabled() -> bool {
    true
}
fn default_adaptive_jitter_min_delay_ms() -> u64 {
    40
}
fn default_adaptive_jitter_max_delay_ms() -> u64 {
    120
}
fn default_adaptive_jitter_growth_step_ms() -> u64 {
    20
}
fn default_adaptive_jitter_decay_step_ms() -> u64 {
    10
}
fn default_repair_enabled() -> bool {
    true
}
fn default_repair_cache_ms() -> u64 {
    1_600
}
fn default_transport_ttl_ms() -> u64 {
    750
}
fn default_repair_transport_ttl_ms() -> u64 {
    750
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
fn default_repair_reactive_reserve_pct() -> u8 {
    30
}
fn default_repair_reactive_hard_reserve_pct() -> u8 {
    10
}
fn default_voice_fec_enabled() -> bool {
    false
}
fn default_voice_fec_block_size() -> usize {
    4
}
fn default_voice_fec_receiver_window() -> usize {
    8
}
fn default_voice_fec_loss_gate_ppm() -> u32 {
    10_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voice_repair_defaults_deserialize_enabled() {
        let cfg: ApplicationConfig = serde_json::from_str(r#"{"voice":{}}"#).unwrap();
        assert!(cfg.voice.tree_delivery_enabled);
        assert!(cfg.voice.repair_enabled);
        assert_eq!(cfg.voice.repair_cache_ms, 1_600);
        assert_eq!(cfg.voice.transport_ttl_ms(), 750);
        assert_eq!(cfg.voice.repair_transport_ttl_ms, 750);
        assert_eq!(cfg.voice.repair_request_ttl_ms, 750);
        assert_eq!(cfg.voice.reorder_max_delay_ms, 40);
        assert_eq!(cfg.voice.reorder_max_buffered_frames, 48);
        assert_eq!(cfg.voice.reorder_max_total_buffer, 4_096);
        assert_eq!(cfg.voice.reorder_idle_reset_ms, 2_000);
        assert_eq!(cfg.voice.chunk_hold_budget_ms, 1_600);
        assert_eq!(cfg.voice.adaptive_jitter_min_delay_ms, 40);
        assert_eq!(cfg.voice.adaptive_jitter_max_delay_ms, 120);
        assert_eq!(cfg.voice.adaptive_jitter_growth_step_ms, 20);
        assert_eq!(cfg.voice.adaptive_jitter_decay_step_ms, 10);
        assert_eq!(cfg.voice.repair_loss_start_ppm, 10_000);
        assert_eq!(cfg.voice.repair_full_dup_loss_ppm, 30_000);
        assert_eq!(cfg.voice.repair_jitter_start_ms, 40);
        assert_eq!(cfg.voice.repair_max_extra_copies_per_frame, 1);
        assert_eq!(cfg.voice.repair_reactive_reserve_pct, 30);
        assert_eq!(cfg.voice.repair_reactive_hard_reserve_pct, 10);
    }

    #[test]
    fn voice_transport_ttl_can_be_overridden() {
        let cfg: ApplicationConfig =
            serde_json::from_str(r#"{"voice":{"transport_ttl_ms":180}}"#).unwrap();
        assert_eq!(cfg.voice.transport_ttl_ms(), 180);
        assert_eq!(cfg.voice.transport_ttl(), Duration::from_millis(180));
    }

    #[test]
    fn tree_delivery_can_be_explicitly_disabled_for_legacy_rollout() {
        let cfg: ApplicationConfig =
            serde_json::from_str(r#"{"voice":{"tree_delivery_enabled":false}}"#).unwrap();
        assert!(!cfg.voice.tree_delivery_enabled);
    }

    #[test]
    fn voice_repair_request_ttl_defaults_to_transport_ttl() {
        let cfg: ApplicationConfig =
            serde_json::from_str(r#"{"voice":{"repair_transport_ttl_ms":300}}"#).unwrap();
        assert_eq!(cfg.voice.repair_transport_ttl_ms, 300);
        assert_eq!(cfg.voice.repair_request_ttl_ms, 300);
    }

    #[test]
    fn voice_repair_request_ttl_can_be_overridden() {
        let cfg: ApplicationConfig = serde_json::from_str(
            r#"{"voice":{"repair_transport_ttl_ms":300,"repair_request_ttl_ms":90}}"#,
        )
        .unwrap();
        assert_eq!(cfg.voice.repair_transport_ttl_ms, 300);
        assert_eq!(cfg.voice.repair_request_ttl_ms, 90);
    }

    #[test]
    fn obsolete_remote_playout_and_reorder_keys_are_accepted_and_ignored() {
        let cfg: ApplicationConfig = serde_json::from_str(
            r#"{"voice":{"remote_playout_min_ms":80,"remote_playout_max_ms":750,"remote_playout_p99_margin_ms":60,"remote_playout_idle_reset_ms":2000,"reorder_max_drop_lag_frames":16,"repair_nack_delay_ms":8}}"#,
        )
        .unwrap();
        assert_eq!(cfg.voice.reorder_idle_reset_ms, 2_000);
        assert_eq!(cfg.voice.reorder_max_delay_ms, 40);
        assert!(cfg.voice.repair_enabled);
    }

    #[test]
    fn voice_repair_extra_copy_limit_accepts_zero_through_two() {
        for copies in 0..=2 {
            let cfg: ApplicationConfig = serde_json::from_str(&format!(
                r#"{{"voice":{{"repair_max_extra_copies_per_frame":{copies}}}}}"#
            ))
            .unwrap();
            assert_eq!(cfg.voice.repair_max_extra_copies_per_frame, copies);
        }
    }

    #[test]
    fn voice_repair_extra_copy_limit_rejects_values_above_two() {
        for copies in [3, usize::MAX] {
            let error = serde_json::from_str::<ApplicationConfig>(&format!(
                r#"{{"voice":{{"repair_max_extra_copies_per_frame":{copies}}}}}"#
            ))
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("repair_max_extra_copies_per_frame must be between 0 and 2")
            );
        }
    }

    #[test]
    fn voice_repair_reserve_percentages_are_validated() {
        let cfg: ApplicationConfig = serde_json::from_str(
            r#"{"voice":{"repair_reactive_reserve_pct":40,"repair_reactive_hard_reserve_pct":15}}"#,
        )
        .unwrap();
        assert_eq!(cfg.voice.repair_reactive_reserve_pct, 40);
        assert_eq!(cfg.voice.repair_reactive_hard_reserve_pct, 15);

        let error = serde_json::from_str::<ApplicationConfig>(
            r#"{"voice":{"repair_reactive_reserve_pct":25,"repair_reactive_hard_reserve_pct":26}}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains(
            "repair_reactive_hard_reserve_pct must not exceed repair_reactive_reserve_pct"
        ));

        let error = serde_json::from_str::<ApplicationConfig>(
            r#"{"voice":{"repair_reactive_reserve_pct":101}}"#,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("repair_reactive_reserve_pct must be between 0 and 100")
        );
    }
}
