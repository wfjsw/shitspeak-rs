//! Tunables for the replications subsystem.
//!
//! Two replication modes share this config: strict (Tempo) and
//! owner-scoped. The defaults mirror the historical hard-coded values
//! the runtimes used before these knobs were exposed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde::Deserialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::metrics::{self, CatchupMode};

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
    /// Minimum interval between bootstrap-catchup attempts. Triggered both
    /// by topic registration and by `Joined`/`Restarted` membership events;
    /// this throttle dedupes burst events so we don't fan out duplicate
    /// requests when several peers join in quick succession after a heal.
    strict_bootstrap_retry_interval: Duration,
    /// Minimum interval between steady-state catchup probes after bootstrap.
    strict_steady_state_catchup_interval: Duration,
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
    /// Cadence for owner-mode anti-entropy scans of alive origins.
    owner_anti_entropy_interval: Duration,
    /// Cap on `CatchupOp`s returned per `OwnerCatchupResp` chunk.
    owner_max_catchup_ops: usize,

    // ── Shared catchup / gateway protection ──
    /// Maximum catchup responses that may be built/sent concurrently across
    /// this replication manager.
    catchup_max_in_flight_total: usize,
    /// Maximum catchup responses that may be built/sent concurrently for one
    /// `(topic, peer)` pair.
    catchup_max_in_flight_per_peer: usize,
    /// Cap on concurrent client owner-replication proposals issued by the
    /// runtime gateway.
    client_replication_max_in_flight: usize,
    catchup_limiter: Arc<CatchupLimiter>,

    // ── Content-addressed blobs ──
    /// Max bytes per blob chunk carried inside a replication frame.
    blob_chunk_size: usize,
    /// Total time a blob fetch may stay in-flight before waiters are failed.
    blob_request_timeout: Duration,
    /// Time to wait for offers before re-broadcasting the find request.
    blob_offer_wait: Duration,
    /// Minimum time before retrying unanswered chunk requests.
    blob_retry_interval: Duration,
    /// Number of providers to request from concurrently for one blob.
    blob_max_parallel_peers: usize,
    /// Cadence for scanning unused channel blobs.
    blob_decay_interval: Duration,
    /// Time an unreferenced blob must remain unused before deletion.
    blob_unused_grace: Duration,
    /// Delay before retrying bulk replication sends that hit backpressure.
    bulk_retry_delay: Duration,
    /// Max blob chunk indexes requested from one provider at a time.
    bulk_max_in_flight_per_peer: usize,
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
            strict_bootstrap_retry_interval: Duration::from_millis(500),
            strict_steady_state_catchup_interval: Duration::from_secs(5),
            pending_propose_ttl: Duration::from_secs(20),
            recovery_ttl: Duration::from_secs(10),

            owner_catchup_timeout: Duration::from_secs(5),
            owner_anti_entropy_interval: Duration::from_secs(30),
            owner_max_catchup_ops: 256,
            catchup_max_in_flight_total: 8,
            catchup_max_in_flight_per_peer: 1,
            client_replication_max_in_flight: 32,
            catchup_limiter: Arc::new(CatchupLimiter::new(8, 1)),

            blob_chunk_size: 64 * 1024,
            blob_request_timeout: Duration::from_secs(10),
            blob_offer_wait: Duration::from_millis(250),
            blob_retry_interval: Duration::from_millis(500),
            blob_max_parallel_peers: 3,
            blob_decay_interval: Duration::from_secs(60),
            blob_unused_grace: Duration::from_secs(600),
            bulk_retry_delay: Duration::from_millis(250),
            bulk_max_in_flight_per_peer: 1,
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
    pub fn strict_bootstrap_retry_interval(&self) -> Duration {
        self.strict_bootstrap_retry_interval
    }
    pub fn strict_steady_state_catchup_interval(&self) -> Duration {
        self.strict_steady_state_catchup_interval
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
    pub fn owner_anti_entropy_interval(&self) -> Duration {
        self.owner_anti_entropy_interval
    }
    pub fn owner_max_catchup_ops(&self) -> usize {
        self.owner_max_catchup_ops
    }
    pub fn catchup_max_in_flight_total(&self) -> usize {
        self.catchup_max_in_flight_total
    }
    pub fn catchup_max_in_flight_per_peer(&self) -> usize {
        self.catchup_max_in_flight_per_peer
    }
    pub fn client_replication_max_in_flight(&self) -> usize {
        self.client_replication_max_in_flight
    }
    pub(crate) fn try_begin_catchup(
        &self,
        mode: CatchupMode,
        topic: &str,
        peer: u16,
    ) -> Option<CatchupPermit> {
        self.catchup_limiter.try_begin(mode, topic, peer)
    }
    pub fn blob_chunk_size(&self) -> usize {
        self.blob_chunk_size
    }
    pub fn blob_request_timeout(&self) -> Duration {
        self.blob_request_timeout
    }
    pub fn blob_offer_wait(&self) -> Duration {
        self.blob_offer_wait
    }
    pub fn blob_retry_interval(&self) -> Duration {
        self.blob_retry_interval
    }
    pub fn blob_max_parallel_peers(&self) -> usize {
        self.blob_max_parallel_peers
    }
    pub fn blob_decay_interval(&self) -> Duration {
        self.blob_decay_interval
    }
    pub fn blob_unused_grace(&self) -> Duration {
        self.blob_unused_grace
    }
    pub fn bulk_retry_delay(&self) -> Duration {
        self.bulk_retry_delay
    }
    pub fn bulk_max_in_flight_per_peer(&self) -> usize {
        self.bulk_max_in_flight_per_peer
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
    pub fn with_strict_bootstrap_retry_interval(mut self, d: Duration) -> Self {
        self.strict_bootstrap_retry_interval = d;
        self
    }
    pub fn with_strict_steady_state_catchup_interval(mut self, d: Duration) -> Self {
        self.strict_steady_state_catchup_interval = d;
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
    pub fn with_owner_anti_entropy_interval(mut self, d: Duration) -> Self {
        self.owner_anti_entropy_interval = d;
        self
    }
    pub fn with_owner_max_catchup_ops(mut self, n: usize) -> Self {
        self.owner_max_catchup_ops = n;
        self
    }
    pub fn with_catchup_max_in_flight_total(mut self, n: usize) -> Self {
        self.catchup_max_in_flight_total = n.max(1);
        self.rebuild_catchup_limiter();
        self
    }
    pub fn with_catchup_max_in_flight_per_peer(mut self, n: usize) -> Self {
        self.catchup_max_in_flight_per_peer = n.max(1);
        self.rebuild_catchup_limiter();
        self
    }
    pub fn with_client_replication_max_in_flight(mut self, n: usize) -> Self {
        self.client_replication_max_in_flight = n.max(1);
        self
    }
    pub fn with_blob_chunk_size(mut self, n: usize) -> Self {
        self.blob_chunk_size = n.max(1);
        self
    }
    pub fn with_blob_request_timeout(mut self, d: Duration) -> Self {
        self.blob_request_timeout = d;
        self
    }
    pub fn with_blob_offer_wait(mut self, d: Duration) -> Self {
        self.blob_offer_wait = d;
        self
    }
    pub fn with_blob_retry_interval(mut self, d: Duration) -> Self {
        self.blob_retry_interval = d;
        self
    }
    pub fn with_blob_max_parallel_peers(mut self, n: usize) -> Self {
        self.blob_max_parallel_peers = n.max(1);
        self
    }
    pub fn with_blob_decay_interval(mut self, d: Duration) -> Self {
        self.blob_decay_interval = d;
        self
    }
    pub fn with_blob_unused_grace(mut self, d: Duration) -> Self {
        self.blob_unused_grace = d;
        self
    }
    pub fn with_bulk_retry_delay(mut self, d: Duration) -> Self {
        self.bulk_retry_delay = d;
        self
    }
    pub fn with_bulk_max_in_flight_per_peer(mut self, n: usize) -> Self {
        self.bulk_max_in_flight_per_peer = n.max(1);
        self
    }

    fn rebuild_catchup_limiter(&mut self) {
        self.catchup_limiter = Arc::new(CatchupLimiter::new(
            self.catchup_max_in_flight_total,
            self.catchup_max_in_flight_per_peer,
        ));
    }
}

#[derive(Debug)]
struct CatchupLimiter {
    total: Arc<Semaphore>,
    per_peer_limit: usize,
    by_pair: Mutex<HashMap<CatchupKey, Arc<Semaphore>>>,
}

impl CatchupLimiter {
    fn new(total_limit: usize, per_peer_limit: usize) -> Self {
        Self {
            total: Arc::new(Semaphore::new(total_limit.max(1))),
            per_peer_limit: per_peer_limit.max(1),
            by_pair: Mutex::new(HashMap::new()),
        }
    }

    fn try_begin(&self, mode: CatchupMode, topic: &str, peer: u16) -> Option<CatchupPermit> {
        let key = CatchupKey {
            topic: topic.to_owned(),
            peer,
        };
        let pair = {
            let mut by_pair = self.by_pair.lock();
            by_pair
                .entry(key)
                .or_insert_with(|| Arc::new(Semaphore::new(self.per_peer_limit)))
                .clone()
        };
        let Ok(pair_permit) = pair.try_acquire_owned() else {
            metrics::record_catchup_suppressed(mode);
            return None;
        };
        let Ok(total_permit) = self.total.clone().try_acquire_owned() else {
            metrics::record_catchup_suppressed(mode);
            return None;
        };
        metrics::record_catchup_active_delta(1);
        Some(CatchupPermit {
            _total_permit: total_permit,
            _pair_permit: pair_permit,
        })
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
struct CatchupKey {
    topic: String,
    peer: u16,
}

pub(crate) struct CatchupPermit {
    _total_permit: OwnedSemaphorePermit,
    _pair_permit: OwnedSemaphorePermit,
}

impl Drop for CatchupPermit {
    fn drop(&mut self) {
        metrics::record_catchup_active_delta(-1);
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
    #[serde(default = "default_strict_bootstrap_retry_interval_ms")]
    pub strict_bootstrap_retry_interval_ms: u64,
    #[serde(default = "default_strict_steady_state_catchup_interval_ms")]
    pub strict_steady_state_catchup_interval_ms: u64,
    #[serde(default = "default_pending_propose_ttl_ms")]
    pub pending_propose_ttl_ms: u64,
    #[serde(default = "default_recovery_ttl_ms")]
    pub recovery_ttl_ms: u64,
    #[serde(default = "default_owner_catchup_timeout_ms")]
    pub owner_catchup_timeout_ms: u64,
    #[serde(default = "default_owner_anti_entropy_interval_ms")]
    pub owner_anti_entropy_interval_ms: u64,
    #[serde(default = "default_owner_max_catchup_ops")]
    pub owner_max_catchup_ops: usize,
    #[serde(default = "default_catchup_max_in_flight_total")]
    pub catchup_max_in_flight_total: usize,
    #[serde(default = "default_catchup_max_in_flight_per_peer")]
    pub catchup_max_in_flight_per_peer: usize,
    #[serde(default = "default_client_replication_max_in_flight")]
    pub client_replication_max_in_flight: usize,
    #[serde(default = "default_blob_chunk_size")]
    pub blob_chunk_size: usize,
    #[serde(default = "default_blob_request_timeout_ms")]
    pub blob_request_timeout_ms: u64,
    #[serde(default = "default_blob_offer_wait_ms")]
    pub blob_offer_wait_ms: u64,
    #[serde(default = "default_blob_retry_interval_ms")]
    pub blob_retry_interval_ms: u64,
    #[serde(default = "default_blob_max_parallel_peers")]
    pub blob_max_parallel_peers: usize,
    #[serde(default = "default_blob_decay_interval_ms")]
    pub blob_decay_interval_ms: u64,
    #[serde(default = "default_blob_unused_grace_ms")]
    pub blob_unused_grace_ms: u64,
    #[serde(default = "default_bulk_retry_delay_ms")]
    pub bulk_retry_delay_ms: u64,
    #[serde(default = "default_bulk_max_in_flight_per_peer")]
    pub bulk_max_in_flight_per_peer: usize,
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
            strict_bootstrap_retry_interval_ms: default_strict_bootstrap_retry_interval_ms(),
            strict_steady_state_catchup_interval_ms:
                default_strict_steady_state_catchup_interval_ms(),
            pending_propose_ttl_ms: default_pending_propose_ttl_ms(),
            recovery_ttl_ms: default_recovery_ttl_ms(),
            owner_catchup_timeout_ms: default_owner_catchup_timeout_ms(),
            owner_anti_entropy_interval_ms: default_owner_anti_entropy_interval_ms(),
            owner_max_catchup_ops: default_owner_max_catchup_ops(),
            catchup_max_in_flight_total: default_catchup_max_in_flight_total(),
            catchup_max_in_flight_per_peer: default_catchup_max_in_flight_per_peer(),
            client_replication_max_in_flight: default_client_replication_max_in_flight(),
            blob_chunk_size: default_blob_chunk_size(),
            blob_request_timeout_ms: default_blob_request_timeout_ms(),
            blob_offer_wait_ms: default_blob_offer_wait_ms(),
            blob_retry_interval_ms: default_blob_retry_interval_ms(),
            blob_max_parallel_peers: default_blob_max_parallel_peers(),
            blob_decay_interval_ms: default_blob_decay_interval_ms(),
            blob_unused_grace_ms: default_blob_unused_grace_ms(),
            bulk_retry_delay_ms: default_bulk_retry_delay_ms(),
            bulk_max_in_flight_per_peer: default_bulk_max_in_flight_per_peer(),
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
            .with_strict_bootstrap_retry_interval(Duration::from_millis(
                t.strict_bootstrap_retry_interval_ms,
            ))
            .with_strict_steady_state_catchup_interval(Duration::from_millis(
                t.strict_steady_state_catchup_interval_ms,
            ))
            .with_pending_propose_ttl(Duration::from_millis(t.pending_propose_ttl_ms))
            .with_recovery_ttl(Duration::from_millis(t.recovery_ttl_ms))
            .with_owner_catchup_timeout(Duration::from_millis(t.owner_catchup_timeout_ms))
            .with_owner_anti_entropy_interval(Duration::from_millis(
                t.owner_anti_entropy_interval_ms,
            ))
            .with_owner_max_catchup_ops(t.owner_max_catchup_ops)
            .with_catchup_max_in_flight_total(t.catchup_max_in_flight_total)
            .with_catchup_max_in_flight_per_peer(t.catchup_max_in_flight_per_peer)
            .with_client_replication_max_in_flight(t.client_replication_max_in_flight)
            .with_blob_chunk_size(t.blob_chunk_size)
            .with_blob_request_timeout(Duration::from_millis(t.blob_request_timeout_ms))
            .with_blob_offer_wait(Duration::from_millis(t.blob_offer_wait_ms))
            .with_blob_retry_interval(Duration::from_millis(t.blob_retry_interval_ms))
            .with_blob_max_parallel_peers(t.blob_max_parallel_peers)
            .with_blob_decay_interval(Duration::from_millis(t.blob_decay_interval_ms))
            .with_blob_unused_grace(Duration::from_millis(t.blob_unused_grace_ms))
            .with_bulk_retry_delay(Duration::from_millis(t.bulk_retry_delay_ms))
            .with_bulk_max_in_flight_per_peer(t.bulk_max_in_flight_per_peer)
    }
}

fn default_fallback_clock_tick_ms() -> u64 {
    250
}
fn default_min_clock_tick_ms() -> u64 {
    100
}
fn default_max_clock_tick_ms() -> u64 {
    5_000
}
fn default_delivery_tick_interval_ms() -> u64 {
    50
}
fn default_propose_ttl_ms() -> u64 {
    10_000
}
fn default_propose_semaphore_size() -> usize {
    32
}
fn default_strict_max_catchup_ops() -> usize {
    256
}
fn default_strict_bootstrap_retry_interval_ms() -> u64 {
    500
}
fn default_strict_steady_state_catchup_interval_ms() -> u64 {
    5_000
}
fn default_pending_propose_ttl_ms() -> u64 {
    20_000
}
fn default_recovery_ttl_ms() -> u64 {
    10_000
}
fn default_owner_catchup_timeout_ms() -> u64 {
    5_000
}
fn default_owner_anti_entropy_interval_ms() -> u64 {
    30_000
}
fn default_owner_max_catchup_ops() -> usize {
    256
}
fn default_catchup_max_in_flight_total() -> usize {
    8
}
fn default_catchup_max_in_flight_per_peer() -> usize {
    1
}
fn default_client_replication_max_in_flight() -> usize {
    32
}
fn default_blob_chunk_size() -> usize {
    64 * 1024
}
fn default_blob_request_timeout_ms() -> u64 {
    10_000
}
fn default_blob_offer_wait_ms() -> u64 {
    250
}
fn default_blob_retry_interval_ms() -> u64 {
    500
}
fn default_blob_max_parallel_peers() -> usize {
    3
}
fn default_blob_decay_interval_ms() -> u64 {
    60_000
}
fn default_blob_unused_grace_ms() -> u64 {
    600_000
}
fn default_bulk_retry_delay_ms() -> u64 {
    250
}
fn default_bulk_max_in_flight_per_peer() -> usize {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catchup_limiter_enforces_per_peer_and_total_limits() {
        let cfg = ReplicationConfig::default()
            .with_catchup_max_in_flight_total(2)
            .with_catchup_max_in_flight_per_peer(1);

        let first = cfg
            .try_begin_catchup(CatchupMode::Owner, "clients", 11)
            .expect("first catchup permit");
        assert!(
            cfg.try_begin_catchup(CatchupMode::Owner, "clients", 11)
                .is_none(),
            "same topic/peer should be limited to one active catchup"
        );

        let second = cfg
            .try_begin_catchup(CatchupMode::Owner, "clients", 12)
            .expect("second peer catchup permit");
        assert!(
            cfg.try_begin_catchup(CatchupMode::Owner, "clients", 13)
                .is_none(),
            "total catchup limit should cap concurrent catchups across peers"
        );

        drop(first);
        let third = cfg
            .try_begin_catchup(CatchupMode::Owner, "clients", 13)
            .expect("total permit released");

        drop(second);
        drop(third);
    }
}
