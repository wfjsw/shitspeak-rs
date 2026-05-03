//! Tunables for the replications subsystem.
//!
//! Two replication modes share this config: strict (Tempo) and
//! owner-scoped. The defaults mirror the historical hard-coded values
//! the runtimes used before these knobs were exposed.

use std::time::Duration;

use serde::Deserialize;

/// Operator-tunable knobs for [`super::ReplicationManager`].
#[derive(Debug, Clone)]
pub struct ReplicationConfig {
    // ── Strict (Tempo) clock-tick scaling ──
    /// Used when the LSDB has no measured edges yet (cold start, single-node
    /// cluster).
    fallback_clock_tick: Duration,
    /// Floor on the dynamic tick interval.
    min_clock_tick: Duration,
    /// Ceiling on the dynamic tick interval.
    max_clock_tick: Duration,

    // ── Strict delivery loop / GC ──
    /// Cadence of the delivery + GC pass.
    delivery_tick_interval: Duration,
    /// Per-proposal timeout. After this the propose future fails with
    /// [`super::error::ReplicationError::ProposeTimeout`].
    propose_ttl: Duration,
    /// Cap on concurrent in-flight proposals from this node.
    propose_semaphore_size: usize,
    /// Cap on `CatchupOp`s returned per `StrictCatchupResp` chunk.
    strict_max_catchup_ops: usize,
    /// Pending propose entries are GC'd after this period. Must be longer
    /// than `propose_ttl` so a proposer's caller-visible timeout fires
    /// before the remote-side state evaporates.
    pending_propose_ttl: Duration,
    /// Recovery in-progress state is dropped after this many seconds
    /// without a quorum of acks.
    recovery_ttl: Duration,

    // ── Owner-scoped ──
    /// Suppress duplicate per-origin catchup requests within this window.
    owner_catchup_timeout: Duration,
    /// Cap on `CatchupOp`s returned per `OwnerCatchupResp` chunk.
    owner_max_catchup_ops: usize,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            fallback_clock_tick: Duration::from_millis(250),
            min_clock_tick: Duration::from_millis(100),
            max_clock_tick: Duration::from_secs(5),

            delivery_tick_interval: Duration::from_millis(50),
            propose_ttl: Duration::from_secs(10),
            propose_semaphore_size: 32,
            strict_max_catchup_ops: 256,
            pending_propose_ttl: Duration::from_secs(20),
            recovery_ttl: Duration::from_secs(10),

            owner_catchup_timeout: Duration::from_secs(5),
            owner_max_catchup_ops: 256,
        }
    }
}

impl ReplicationConfig {
    pub fn fallback_clock_tick(&self) -> Duration {
        self.fallback_clock_tick
    }
    pub fn min_clock_tick(&self) -> Duration {
        self.min_clock_tick
    }
    pub fn max_clock_tick(&self) -> Duration {
        self.max_clock_tick
    }
    pub fn delivery_tick_interval(&self) -> Duration {
        self.delivery_tick_interval
    }
    pub fn propose_ttl(&self) -> Duration {
        self.propose_ttl
    }
    pub fn propose_semaphore_size(&self) -> usize {
        self.propose_semaphore_size
    }
    pub fn strict_max_catchup_ops(&self) -> usize {
        self.strict_max_catchup_ops
    }
    pub fn pending_propose_ttl(&self) -> Duration {
        self.pending_propose_ttl
    }
    pub fn recovery_ttl(&self) -> Duration {
        self.recovery_ttl
    }
    pub fn owner_catchup_timeout(&self) -> Duration {
        self.owner_catchup_timeout
    }
    pub fn owner_max_catchup_ops(&self) -> usize {
        self.owner_max_catchup_ops
    }

    pub fn with_fallback_clock_tick(mut self, d: Duration) -> Self {
        self.fallback_clock_tick = d;
        self
    }
    pub fn with_min_clock_tick(mut self, d: Duration) -> Self {
        self.min_clock_tick = d;
        self
    }
    pub fn with_max_clock_tick(mut self, d: Duration) -> Self {
        self.max_clock_tick = d;
        self
    }
    pub fn with_delivery_tick_interval(mut self, d: Duration) -> Self {
        self.delivery_tick_interval = d;
        self
    }
    pub fn with_propose_ttl(mut self, d: Duration) -> Self {
        self.propose_ttl = d;
        self
    }
    pub fn with_propose_semaphore_size(mut self, n: usize) -> Self {
        self.propose_semaphore_size = n;
        self
    }
    pub fn with_strict_max_catchup_ops(mut self, n: usize) -> Self {
        self.strict_max_catchup_ops = n;
        self
    }
    pub fn with_pending_propose_ttl(mut self, d: Duration) -> Self {
        self.pending_propose_ttl = d;
        self
    }
    pub fn with_recovery_ttl(mut self, d: Duration) -> Self {
        self.recovery_ttl = d;
        self
    }
    pub fn with_owner_catchup_timeout(mut self, d: Duration) -> Self {
        self.owner_catchup_timeout = d;
        self
    }
    pub fn with_owner_max_catchup_ops(mut self, n: usize) -> Self {
        self.owner_max_catchup_ops = n;
        self
    }
}

/// TOML-deserializable shadow of [`ReplicationConfig`]. Each field maps
/// directly to a getter on the runtime config; `Duration`s are surfaced as
/// `_ms` / `_secs` integers for ergonomic TOML editing.
#[derive(Deserialize, Debug, Clone)]
pub struct ReplicationTuning {
    #[serde(default = "default_fallback_clock_tick_ms")]
    pub fallback_clock_tick_ms: u64,
    #[serde(default = "default_min_clock_tick_ms")]
    pub min_clock_tick_ms: u64,
    #[serde(default = "default_max_clock_tick_ms")]
    pub max_clock_tick_ms: u64,
    #[serde(default = "default_delivery_tick_interval_ms")]
    pub delivery_tick_interval_ms: u64,
    #[serde(default = "default_propose_ttl_ms")]
    pub propose_ttl_ms: u64,
    #[serde(default = "default_propose_semaphore_size")]
    pub propose_semaphore_size: usize,
    #[serde(default = "default_strict_max_catchup_ops")]
    pub strict_max_catchup_ops: usize,
    #[serde(default = "default_pending_propose_ttl_ms")]
    pub pending_propose_ttl_ms: u64,
    #[serde(default = "default_recovery_ttl_ms")]
    pub recovery_ttl_ms: u64,
    #[serde(default = "default_owner_catchup_timeout_ms")]
    pub owner_catchup_timeout_ms: u64,
    #[serde(default = "default_owner_max_catchup_ops")]
    pub owner_max_catchup_ops: usize,
}

impl Default for ReplicationTuning {
    fn default() -> Self {
        Self {
            fallback_clock_tick_ms: default_fallback_clock_tick_ms(),
            min_clock_tick_ms: default_min_clock_tick_ms(),
            max_clock_tick_ms: default_max_clock_tick_ms(),
            delivery_tick_interval_ms: default_delivery_tick_interval_ms(),
            propose_ttl_ms: default_propose_ttl_ms(),
            propose_semaphore_size: default_propose_semaphore_size(),
            strict_max_catchup_ops: default_strict_max_catchup_ops(),
            pending_propose_ttl_ms: default_pending_propose_ttl_ms(),
            recovery_ttl_ms: default_recovery_ttl_ms(),
            owner_catchup_timeout_ms: default_owner_catchup_timeout_ms(),
            owner_max_catchup_ops: default_owner_max_catchup_ops(),
        }
    }
}

impl From<ReplicationTuning> for ReplicationConfig {
    fn from(t: ReplicationTuning) -> Self {
        ReplicationConfig::default()
            .with_fallback_clock_tick(Duration::from_millis(t.fallback_clock_tick_ms))
            .with_min_clock_tick(Duration::from_millis(t.min_clock_tick_ms))
            .with_max_clock_tick(Duration::from_millis(t.max_clock_tick_ms))
            .with_delivery_tick_interval(Duration::from_millis(t.delivery_tick_interval_ms))
            .with_propose_ttl(Duration::from_millis(t.propose_ttl_ms))
            .with_propose_semaphore_size(t.propose_semaphore_size)
            .with_strict_max_catchup_ops(t.strict_max_catchup_ops)
            .with_pending_propose_ttl(Duration::from_millis(t.pending_propose_ttl_ms))
            .with_recovery_ttl(Duration::from_millis(t.recovery_ttl_ms))
            .with_owner_catchup_timeout(Duration::from_millis(t.owner_catchup_timeout_ms))
            .with_owner_max_catchup_ops(t.owner_max_catchup_ops)
    }
}

fn default_fallback_clock_tick_ms() -> u64 { 250 }
fn default_min_clock_tick_ms() -> u64 { 100 }
fn default_max_clock_tick_ms() -> u64 { 5_000 }
fn default_delivery_tick_interval_ms() -> u64 { 50 }
fn default_propose_ttl_ms() -> u64 { 10_000 }
fn default_propose_semaphore_size() -> usize { 32 }
fn default_strict_max_catchup_ops() -> usize { 256 }
fn default_pending_propose_ttl_ms() -> u64 { 20_000 }
fn default_recovery_ttl_ms() -> u64 { 10_000 }
fn default_owner_catchup_timeout_ms() -> u64 { 5_000 }
fn default_owner_max_catchup_ops() -> usize { 256 }
