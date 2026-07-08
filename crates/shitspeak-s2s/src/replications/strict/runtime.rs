//! Tempo state machine + delivery loop for one strict topic.
//!
//! The state struct ([`StrictState`]) is deliberately non-generic and
//! side-effect-free so it's directly unit-testable. The generic
//! [`StrictRuntime`] ties it to a `StrictReplicable` repo and a
//! [`StrictNet`] network abstraction (the production impl is
//! [`OverlayStrictNet`], the test impl is in `test_support.rs`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use rand::seq::SliceRandom;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, trace, warn};

use super::super::config::ReplicationConfig;
use super::super::error::ReplicationError;
use super::super::metrics::{self, CatchupMode, ReplicationPipelineKind, ReplicationPipelineStage};
use super::super::proto::{
    self as repl_proto, REPLICATION_SERVICE_TAG, StrictBody, StrictCatchupReq, StrictCatchupResp,
    StrictClockTick, StrictCommit, StrictPropose, StrictProposeAck, StrictRecoveryAck,
    StrictRecoveryCommit, StrictRecoveryReq,
};
use super::super::topic::ErasedStrictRuntime;
use super::{HistoryMetadata, StrictLogMetadata, StrictReplicable};
use crate::overlay::{MembershipEvent, OverlayNetwork, OverlaySendOptions};
use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{MessageClass, RoutingMetric, ServiceLevel};

// ---------- Tunables ----------

/// Maximum number of clock ticks emitted in one demand-driven active burst.
///
/// A single tick should normally be enough after a commit because commit
/// handlers first raise the local clock to `ts_final`; the extra ticks cover
/// crossed wakeups and delayed peer observations without returning to the old
/// always-on heartbeat behavior.
const CLOCK_TICK_ACTIVE_BURST_TICKS: usize = 3;
const CLOCK_TICK_BURST_COOLDOWN_MULTIPLIER: u32 = 4;
const PROPOSE_RETRY_TICKS: usize = 80;
pub(super) const STRICT_REPLICATION_SLOW_STAGE: Duration = Duration::from_secs(1);
const STRICT_DELIVERY_BLOCKED_LOG_INTERVAL: Duration = Duration::from_secs(5);
// Keep commit gossip alive through the hostile-link/jitter window. A peer can
// miss the first quorum commit fanout but still be alive and routable shortly
// after; these retries are the steady-state repair path for that case.
const COMMIT_FANOUT_RETRY_TICKS: usize = 80;
/// Compute p95 of a slice of edge RTTs, clamped to
/// `[cfg.min_clock_tick(), cfg.max_clock_tick()]`. Empty input
/// → `cfg.fallback_clock_tick()`. Uses nearest-rank:
/// idx = `ceil(0.95 * n) - 1`.
pub(crate) fn p95_clock_tick_interval(samples: &[Duration], cfg: &ReplicationConfig) -> Duration {
    if samples.is_empty() {
        return cfg.fallback_clock_tick();
    }
    let mut buf: Vec<Duration> = samples.to_vec();
    buf.sort_unstable();
    let n = buf.len();
    // ceil(0.95 * n) - 1, with saturating subtraction for n=1.
    let idx_one_based = ((n as f64) * 0.95).ceil() as usize;
    let idx = idx_one_based.saturating_sub(1).min(n - 1);
    buf[idx].clamp(cfg.min_clock_tick(), cfg.max_clock_tick())
}

// ---------- OpId ----------

/// Globally unique op identifier. Encoded on the wire as `(hi, lo)`.
pub(crate) type OpId = (u64, u64);

#[inline]
pub(crate) fn make_op_id(self_id: NodeIdentifier, boot_epoch: u64, counter: u64) -> OpId {
    let hi = ((self_id as u64) << 48) | (boot_epoch & 0x0000_FFFF_FFFF_FFFF);
    (hi, counter)
}

/// Tempo fast quorum = ceil(3n/4). Defined in its own fn so unit tests can
/// pin the values across cluster sizes.
#[inline]
pub(crate) fn fast_quorum_size(n: usize) -> usize {
    if n == 0 { 0 } else { (3 * n).div_ceil(4) }
}

// ---------- Network abstraction ----------

#[async_trait]
pub(crate) trait StrictNet: Send + Sync + 'static {
    async fn send_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: StrictBody,
    ) -> Result<(), ReplicationError>;
    async fn send_bulk_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: StrictBody,
        _retry_delay: Duration,
    ) -> Result<(), ReplicationError> {
        self.send_unicast(dst, topic, body).await
    }
    async fn send_multicast(
        &self,
        dsts: &[NodeIdentifier],
        topic: &str,
        body: StrictBody,
    ) -> Result<(), ReplicationError>;
    async fn send_broadcast(&self, topic: &str, body: StrictBody) -> Result<(), ReplicationError>;
    fn alive_members(&self) -> Vec<NodeIdentifier>;
    fn has_route(&self, _dst: NodeIdentifier, _level: ServiceLevel) -> bool {
        true
    }
    fn has_live_route(&self, dst: NodeIdentifier, level: ServiceLevel) -> bool {
        self.has_route(dst, level)
    }
    /// Snapshot of every directed-edge RTT in the overlay's LSDB. Used to
    /// scale the clock-tick cadence to measured network latency.
    fn edge_rtt_snapshot(&self) -> Vec<Duration>;
}

/// Production `StrictNet` impl that wraps `OverlayNetwork`.
pub(crate) struct OverlayStrictNet {
    pub overlay: OverlayNetwork,
}

#[async_trait]
impl StrictNet for OverlayStrictNet {
    async fn send_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: StrictBody,
    ) -> Result<(), ReplicationError> {
        let options = if matches!(&body, StrictBody::CatchupResp(_)) {
            OverlaySendOptions::default().allow_l1_compression()
        } else {
            OverlaySendOptions::default()
        };
        let msg = repl_proto::wrap_strict(topic, body);
        let encode_started_at = Instant::now();
        let encoded = repl_proto::encode(&msg);
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::ProtobufEncode,
            encode_started_at.elapsed(),
        );
        let bytes = encoded?;
        self.overlay
            .send_unicast_unordered_with_routing_metric_and_options(
                dst,
                REPLICATION_SERVICE_TAG,
                ServiceLevel::Reliable,
                RoutingMetric::ReliableCost,
                MessageClass::Regular,
                bytes,
                options,
            )
            .await?;
        Ok(())
    }

    async fn send_bulk_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: StrictBody,
        retry_delay: Duration,
    ) -> Result<(), ReplicationError> {
        let msg = repl_proto::wrap_strict(topic, body);
        let encode_started_at = Instant::now();
        let encoded = repl_proto::encode(&msg);
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::ProtobufEncode,
            encode_started_at.elapsed(),
        );
        let bytes = encoded?;
        let options = OverlaySendOptions::default()
            .allow_l1_compression()
            .expire_after(retry_delay);
        let result = self
            .overlay
            .send_unicast_unordered_with_routing_metric_and_options(
                dst,
                REPLICATION_SERVICE_TAG,
                ServiceLevel::Reliable,
                RoutingMetric::ReliableCost,
                MessageClass::Regular,
                bytes.clone(),
                options,
            )
            .await;
        if let Err(error) = result {
            if replication_bulk_backpressure(&error) {
                sleep(retry_delay).await;
                self.overlay
                    .send_unicast_unordered_with_routing_metric_and_options(
                        dst,
                        REPLICATION_SERVICE_TAG,
                        ServiceLevel::Reliable,
                        RoutingMetric::ReliableCost,
                        MessageClass::Regular,
                        bytes,
                        options,
                    )
                    .await?;
                return Ok(());
            }
            return Err(error.into());
        }
        Ok(())
    }

    async fn send_multicast(
        &self,
        dsts: &[NodeIdentifier],
        topic: &str,
        body: StrictBody,
    ) -> Result<(), ReplicationError> {
        if dsts.is_empty() {
            return Ok(());
        }
        let msg = repl_proto::wrap_strict(topic, body);
        let encode_started_at = Instant::now();
        let encoded = repl_proto::encode(&msg);
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::ProtobufEncode,
            encode_started_at.elapsed(),
        );
        let bytes = encoded?;
        self.overlay
            .send_multicast_unordered_with_routing_metric(
                dsts,
                REPLICATION_SERVICE_TAG,
                ServiceLevel::Reliable,
                RoutingMetric::ReliableCost,
                MessageClass::Regular,
                bytes,
            )
            .await?;
        Ok(())
    }

    async fn send_broadcast(&self, topic: &str, body: StrictBody) -> Result<(), ReplicationError> {
        let dsts = self.alive_members();
        self.send_multicast(&dsts, topic, body).await
    }

    fn alive_members(&self) -> Vec<NodeIdentifier> {
        self.overlay.strict_replication_members()
    }

    fn has_route(&self, dst: NodeIdentifier, level: ServiceLevel) -> bool {
        self.overlay.has_route(dst, level)
    }

    fn has_live_route(&self, dst: NodeIdentifier, level: ServiceLevel) -> bool {
        self.overlay.has_live_route(dst, level)
    }

    fn edge_rtt_snapshot(&self) -> Vec<Duration> {
        self.overlay.edge_rtt_snapshot()
    }
}

fn replication_bulk_backpressure(error: &crate::overlay::OverlayError) -> bool {
    matches!(
        error,
        crate::overlay::OverlayError::Send(shitspeak_s2s_transport::SendError::Backpressure { .. })
    )
}

// ---------- State machine ----------

pub(crate) struct Proposal {
    pub op_msgpack: Bytes,
    pub ts_propose: u64,
    pub acks: HashMap<NodeIdentifier, u64>, // ack_node -> ts_local
    pub target_set: HashSet<NodeIdentifier>,
    pub accepted_waker: Option<oneshot::Sender<()>>,
    pub waker: Option<oneshot::Sender<Result<u64, ReplicationError>>>,
    pub committed: bool,
    pub started_at: Instant,
    /// Permit released when this proposal is removed from `proposals`.
    pub _permit: OwnedSemaphorePermit,
}

pub(crate) struct BufferedOp {
    pub op_msgpack: Bytes,
    pub ts_final: u64,
    pub op_id: OpId,
    buffered_at: Instant,
}

pub(crate) type BufferKey = (u64, OpId); // (ts_final, op_id)

pub(crate) const HISTORY_ELECTION_SNAPSHOT_TOKEN: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HistoryRank {
    pub version: u64,
    pub freshness: i64,
    pub runtime_started_at: u64,
    pub node_id: NodeIdentifier,
}

fn bootstrap_reachable_peers(net: &dyn StrictNet, self_id: NodeIdentifier) -> Vec<NodeIdentifier> {
    net.alive_members()
        .into_iter()
        .filter(|node| *node != self_id && net.has_route(*node, ServiceLevel::Reliable))
        .collect()
}

impl HistoryRank {
    pub fn local<R: StrictReplicable>(rt: &StrictRuntime<R>) -> Self {
        let metadata = rt.repo.history_metadata();
        Self::from_metadata(metadata, rt.boot_epoch, rt.self_id)
    }

    pub fn from_metadata(
        metadata: HistoryMetadata,
        runtime_started_at: u64,
        node_id: NodeIdentifier,
    ) -> Self {
        Self {
            version: metadata.version,
            freshness: metadata.freshness,
            runtime_started_at,
            node_id,
        }
    }

    pub fn beats(self, other: Self) -> bool {
        (
            self.version,
            self.freshness,
            std::cmp::Reverse(self.runtime_started_at),
            std::cmp::Reverse(self.node_id),
        ) > (
            other.version,
            other.freshness,
            std::cmp::Reverse(other.runtime_started_at),
            std::cmp::Reverse(other.node_id),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HistoryElectionCandidate {
    pub rank: HistoryRank,
    pub snapshot_version: u64,
    pub snapshot_msgpack: Bytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HistoryElectionSnapshotRequest {
    peer: NodeIdentifier,
    expected_rank: HistoryRank,
}

impl HistoryElectionSnapshotRequest {
    pub(crate) fn new(peer: NodeIdentifier, expected_rank: HistoryRank) -> Self {
        Self {
            peer,
            expected_rank,
        }
    }

    pub(crate) fn peer(&self) -> NodeIdentifier {
        self.peer
    }

    pub(crate) fn expected_rank(&self) -> HistoryRank {
        self.expected_rank
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HistoryElectionPhase {
    Idle,
    Probing {
        pending_peers: HashSet<NodeIdentifier>,
        best_remote_rank: Option<HistoryRank>,
        started_at: Instant,
    },
    FetchingSnapshot {
        peer: NodeIdentifier,
        expected_rank: HistoryRank,
        started_at: Instant,
    },
    Installing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HistoryProbeResponseOutcome {
    Ignored,
    Pending,
    Finished,
    FetchSnapshot(HistoryElectionSnapshotRequest),
}

impl HistoryProbeResponseOutcome {
    pub(crate) fn is_ignored(&self) -> bool {
        matches!(self, Self::Ignored)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HistorySnapshotResponseOutcome {
    Ignored,
    Retry,
    Install(HistoryElectionCandidate),
}

impl Default for HistoryElectionPhase {
    fn default() -> Self {
        Self::Idle
    }
}

/// A `StrictPropose` we've ack'd but not yet committed. Held by every
/// replica that received the original Propose, so a takeover coordinator
/// can recover the op via the Tempo slow-path if the original coord dies.
pub(crate) struct PendingPropose {
    pub coord_node: NodeIdentifier,
    pub op_msgpack: Bytes,
    pub ts_local: u64,
    pub seen_at: Instant,
}

struct PendingProposeRetry {
    op_msgpack: Bytes,
    ts_propose: u64,
    src_clock: u64,
    dsts: Vec<NodeIdentifier>,
    started_at: Instant,
    ack_count: usize,
    target_count: usize,
    fast_quorum: usize,
}

struct AcceptedProposal {
    body: StrictBody,
    dsts: Vec<NodeIdentifier>,
    accepted_waker: Option<oneshot::Sender<()>>,
    elapsed: Duration,
    ack_count: usize,
    target_count: usize,
    fast_quorum: usize,
    ts_final: u64,
    clock_now: u64,
    op_bytes: usize,
    commit_buffer_len: usize,
    pending_local_proposals: usize,
    pending_remote_proposes: usize,
}

struct BufferedCommitLog {
    source: &'static str,
    from: Option<NodeIdentifier>,
    coord_node: Option<NodeIdentifier>,
    op_id: OpId,
    ts_final: u64,
    clock_now: u64,
    op_bytes: usize,
    commit_buffer_len: usize,
    pending_local_proposals: usize,
    pending_remote_proposes: usize,
}

#[derive(Clone, Copy)]
struct DeliveryWatermark {
    high_water: u64,
    low_water_node: NodeIdentifier,
    low_water_clock: u64,
    missing_clock_peers: usize,
}

#[derive(Clone)]
struct UncommittedProposalBlocker {
    kind: &'static str,
    op_id: OpId,
    coord_node: NodeIdentifier,
    ts: u64,
    age: Duration,
}

#[derive(Clone, Copy)]
struct NextBufferedOpDiagnostics {
    key: BufferKey,
    op_id: OpId,
    ts_final: u64,
    buffered_for: Duration,
}

struct DeliveryBlockDiagnostics {
    next: NextBufferedOpDiagnostics,
    raw_high_water: u64,
    effective_high_water: u64,
    watermark: DeliveryWatermark,
    pending_blocker: Option<UncommittedProposalBlocker>,
    alive_count: usize,
    commit_buffer_len: usize,
    pending_local_proposals: usize,
    pending_remote_proposes: usize,
}

#[derive(Default)]
struct DeliveryBlockedLogState {
    key: Option<BufferKey>,
    blocked_since: Option<Instant>,
    last_log_at: Option<Instant>,
}

/// Pure Tempo state machine. No async, no I/O — all logic operates on
/// in-memory state and returns effects. Designed to be exercised by unit
/// tests directly.
pub(crate) struct StrictState {
    pub clock: u64,
    /// `peer_clocks[m]` is the highest `src_clock` we've observed from `m`,
    /// piggybacked on any inbound frame. Includes self (kept in sync with
    /// `clock`).
    pub peer_clocks: HashMap<NodeIdentifier, u64>,
    pub proposals: HashMap<OpId, Proposal>,
    pub commit_buffer: BTreeMap<BufferKey, BufferedOp>,
    pub delivered_high_water: u64,
    /// Per-op-id pending Propose state (for slow-path recovery).
    pub pending_proposes: HashMap<OpId, PendingPropose>,
    /// Per-op-id highest ballot we've promised in a `RecoveryReq`. Replicas
    /// reject any `RecoveryCommit` with `ballot < promised`.
    pub recovery_promises: HashMap<OpId, u64>,
    /// Op-ids ever buffered for delivery (via `Commit` or `RecoveryCommit`).
    /// Used to dedup repeat commits with possibly-different `ts_final`.
    pub committed_ids: HashSet<OpId>,
    /// `op_id -> ts_final` for committed ops, retained until the op has
    /// cleared `delivered_high_water`. Lets us answer a recovery Prepare
    /// with the original `ts_final` even after the commit_buffer entry
    /// has been drained.
    pub committed_ts_final: HashMap<OpId, u64>,
    /// True when startup or partition-heal convergence still needs election.
    history_election_requested: bool,
    history_election_phase: HistoryElectionPhase,
    pub history_alive_peers: HashSet<NodeIdentifier>,
}

impl StrictState {
    pub fn new() -> Self {
        Self {
            clock: 0,
            peer_clocks: HashMap::new(),
            proposals: HashMap::new(),
            commit_buffer: BTreeMap::new(),
            delivered_high_water: 0,
            pending_proposes: HashMap::new(),
            recovery_promises: HashMap::new(),
            committed_ids: HashSet::new(),
            committed_ts_final: HashMap::new(),
            history_election_requested: true,
            history_election_phase: HistoryElectionPhase::Idle,
            history_alive_peers: HashSet::new(),
        }
    }

    /// Tempo clock advance: `clock = max(clock, peer_clock) + 1`.
    pub fn advance_clock(&mut self, peer_clock: u64) -> u64 {
        if peer_clock > self.clock {
            self.clock = peer_clock + 1;
        } else {
            self.clock += 1;
        }
        self.clock
    }

    /// Local-only tick (used when proposing).
    pub fn tick_clock(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// Update `peer_clocks[peer]` if `peer_clock` is higher than what we
    /// already had.
    pub fn observe_peer(&mut self, peer: NodeIdentifier, peer_clock: u64) {
        let entry = self.peer_clocks.entry(peer).or_insert(0);
        if peer_clock > *entry {
            *entry = peer_clock;
        }
    }

    /// Compute delivery high-water = `min(peer_clocks ∪ {self.clock})` over
    /// the current alive set. Peers known-alive but with no observation yet
    /// contribute `0`, holding delivery back until they tick — which is
    /// the conservative correct choice.
    pub fn delivery_high_water(&self, self_id: NodeIdentifier, alive: &[NodeIdentifier]) -> u64 {
        let mut min_seen = self.clock; // self's contribution
        for m in alive.iter().copied() {
            if m == self_id {
                continue;
            }
            let c = self.peer_clocks.get(&m).copied().unwrap_or(0);
            if c < min_seen {
                min_seen = c;
            }
        }
        min_seen
    }

    /// Buffer a committed op for later delivery. Idempotent: if an entry
    /// for the same `(ts_final, op_id)` is already present, leave it.
    pub fn buffer_commit(&mut self, op_id: OpId, ts_final: u64, op_msgpack: Bytes) {
        let key: BufferKey = (ts_final, op_id);
        self.commit_buffer.entry(key).or_insert(BufferedOp {
            op_msgpack,
            ts_final,
            op_id,
            buffered_at: Instant::now(),
        });
    }

    /// Pop every entry with `ts_final <= high_water` in
    /// `(ts_final, op_id)` ascending order. Caller is responsible for
    /// applying via the repo and firing wakers.
    pub fn drain_deliverable(&mut self, high_water: u64) -> Vec<BufferedOp> {
        let mut out = Vec::new();
        loop {
            let next_key = match self.commit_buffer.iter().next() {
                Some((k, _)) => *k,
                None => break,
            };
            if next_key.0 > high_water {
                break;
            }
            let (_, v) = self.commit_buffer.pop_first().unwrap();
            out.push(v);
        }
        out
    }

    /// Earliest timestamp of a proposal this node has observed but not yet
    /// seen committed. A future commit for it can still land at this timestamp
    /// or later, so delivery must not pass it.
    pub fn earliest_uncommitted_proposal_ts(&self) -> Option<u64> {
        self.proposals
            .values()
            .filter(|p| !p.committed)
            .map(|p| p.ts_propose)
            .chain(self.pending_proposes.values().map(|p| p.ts_local))
            .min()
    }

    /// Fail every in-flight proposal whose received acks plus still-reachable
    /// missing targets can no longer reach fast-quorum. Returns the wakers to
    /// fire externally (locking discipline: state lock held during the search,
    /// then released before sending).
    pub fn fail_quorum_lost(
        &mut self,
        alive: &HashSet<NodeIdentifier>,
    ) -> Vec<(OpId, oneshot::Sender<Result<u64, ReplicationError>>)> {
        let mut to_fire = Vec::new();
        let mut to_remove = Vec::new();
        for (op_id, p) in self.proposals.iter_mut() {
            if p.committed {
                continue;
            }
            let fq = fast_quorum_size(p.target_set.len());
            let reachable_missing = p
                .target_set
                .iter()
                .filter(|n| alive.contains(*n) && !p.acks.contains_key(*n))
                .count();
            let possible_acks = p.acks.len() + reachable_missing;
            if possible_acks < fq {
                if let Some(w) = p.waker.take() {
                    to_fire.push((*op_id, w));
                }
                to_remove.push(*op_id);
            }
        }
        for id in to_remove {
            self.proposals.remove(&id);
        }
        to_fire
    }

    /// Returns true when a history-election snapshot can be installed without
    /// racing active strict traffic.
    pub fn can_bootstrap_catchup(&self) -> bool {
        self.history_election_requested
            && !matches!(
                self.history_election_phase,
                HistoryElectionPhase::Installing
            )
            && self.proposals.is_empty()
            && self.commit_buffer.is_empty()
            && self.pending_proposes.is_empty()
            && self.recovery_promises.is_empty()
    }

    pub fn can_start_history_election(&self) -> bool {
        self.can_bootstrap_catchup()
            && matches!(self.history_election_phase, HistoryElectionPhase::Idle)
    }

    #[cfg(test)]
    pub fn history_election_pending(&self) -> bool {
        self.history_election_requested
    }

    pub fn history_election_active(&self) -> bool {
        !matches!(self.history_election_phase, HistoryElectionPhase::Idle)
    }

    pub fn history_election_blocks_steady_state(&self) -> bool {
        self.history_election_requested || self.history_election_active()
    }

    #[cfg(test)]
    pub fn history_election_installing(&self) -> bool {
        matches!(
            self.history_election_phase,
            HistoryElectionPhase::Installing
        )
    }

    #[cfg(test)]
    pub fn history_election_fetching_snapshot(&self) -> Option<HistoryElectionSnapshotRequest> {
        match self.history_election_phase {
            HistoryElectionPhase::FetchingSnapshot {
                peer,
                expected_rank,
                ..
            } => Some(HistoryElectionSnapshotRequest::new(peer, expected_rank)),
            _ => None,
        }
    }

    pub fn request_history_election(&mut self) {
        if matches!(
            self.history_election_phase,
            HistoryElectionPhase::Installing
        ) {
            return;
        }
        self.history_election_requested = true;
        self.history_election_phase = HistoryElectionPhase::Idle;
    }

    pub fn begin_history_election(&mut self, peers: impl IntoIterator<Item = NodeIdentifier>) {
        if !self.can_start_history_election() {
            return;
        }
        let peers: HashSet<NodeIdentifier> = peers.into_iter().collect();
        self.history_alive_peers = peers.clone();
        self.history_election_phase = HistoryElectionPhase::Probing {
            pending_peers: peers,
            best_remote_rank: None,
            started_at: Instant::now(),
        };
    }

    pub fn history_election_timed_out(&self, now: Instant, timeout: Duration) -> bool {
        self.history_election_requested
            && match self.history_election_phase {
                HistoryElectionPhase::Probing { started_at, .. }
                | HistoryElectionPhase::FetchingSnapshot { started_at, .. } => {
                    now.duration_since(started_at) >= timeout
                }
                HistoryElectionPhase::Idle | HistoryElectionPhase::Installing => false,
            }
    }

    pub fn observe_history_alive_peers(
        &mut self,
        peers: impl IntoIterator<Item = NodeIdentifier>,
    ) -> bool {
        let peers: HashSet<NodeIdentifier> = peers.into_iter().collect();
        let expanded = peers
            .iter()
            .any(|peer| !self.history_alive_peers.contains(peer));
        self.history_alive_peers = peers;
        if expanded && !self.history_election_requested && !self.history_election_active() {
            self.request_history_election();
            true
        } else {
            false
        }
    }

    pub fn abandon_history_election_peer(
        &mut self,
        peer: NodeIdentifier,
    ) -> Option<HistoryElectionSnapshotRequest> {
        self.history_alive_peers.remove(&peer);
        match &mut self.history_election_phase {
            HistoryElectionPhase::Probing { pending_peers, .. } => {
                pending_peers.remove(&peer);
                if !pending_peers.is_empty() {
                    return None;
                }
            }
            _ => return None,
        }
        let best_rank = match &self.history_election_phase {
            HistoryElectionPhase::Probing {
                best_remote_rank, ..
            } => *best_remote_rank,
            _ => None,
        };
        let Some(best_rank) = best_rank else {
            self.history_election_phase = HistoryElectionPhase::Idle;
            self.history_election_requested = true;
            return None;
        };

        let request = HistoryElectionSnapshotRequest::new(best_rank.node_id, best_rank);
        self.history_election_phase = HistoryElectionPhase::FetchingSnapshot {
            peer: request.peer(),
            expected_rank: request.expected_rank(),
            started_at: Instant::now(),
        };
        Some(request)
    }

    pub fn record_history_probe_response(
        &mut self,
        peer: NodeIdentifier,
        remote_rank: HistoryRank,
        local_rank: HistoryRank,
    ) -> HistoryProbeResponseOutcome {
        match &mut self.history_election_phase {
            HistoryElectionPhase::Probing {
                pending_peers,
                best_remote_rank,
                ..
            } => {
                if !pending_peers.remove(&peer) {
                    return HistoryProbeResponseOutcome::Ignored;
                }
                if remote_rank.beats(local_rank) {
                    let replace = match best_remote_rank {
                        Some(current) => remote_rank.beats(*current),
                        None => true,
                    };
                    if replace {
                        *best_remote_rank = Some(remote_rank);
                    }
                }
            }
            _ => return HistoryProbeResponseOutcome::Ignored,
        }
        self.complete_history_probe_if_ready()
    }

    fn complete_history_probe_if_ready(&mut self) -> HistoryProbeResponseOutcome {
        let Some(best_rank) = (match &self.history_election_phase {
            HistoryElectionPhase::Probing {
                pending_peers,
                best_remote_rank,
                ..
            } if pending_peers.is_empty() => *best_remote_rank,
            HistoryElectionPhase::Probing { .. } => return HistoryProbeResponseOutcome::Pending,
            _ => return HistoryProbeResponseOutcome::Ignored,
        }) else {
            self.finish_history_election();
            return HistoryProbeResponseOutcome::Finished;
        };

        let request = HistoryElectionSnapshotRequest::new(best_rank.node_id, best_rank);
        self.history_election_phase = HistoryElectionPhase::FetchingSnapshot {
            peer: request.peer(),
            expected_rank: request.expected_rank(),
            started_at: Instant::now(),
        };
        HistoryProbeResponseOutcome::FetchSnapshot(request)
    }

    pub fn record_history_snapshot_response(
        &mut self,
        peer: NodeIdentifier,
        remote_rank: HistoryRank,
        local_rank: HistoryRank,
        snapshot_version: u64,
        snapshot_msgpack: Bytes,
    ) -> HistorySnapshotResponseOutcome {
        let expected_rank = match self.history_election_phase {
            HistoryElectionPhase::FetchingSnapshot {
                peer: expected_peer,
                expected_rank,
                ..
            } if expected_peer == peer => expected_rank,
            HistoryElectionPhase::FetchingSnapshot { .. } => {
                return HistorySnapshotResponseOutcome::Ignored;
            }
            _ => return HistorySnapshotResponseOutcome::Ignored,
        };

        if !remote_rank.beats(local_rank) {
            self.finish_history_election();
            return HistorySnapshotResponseOutcome::Ignored;
        }

        if remote_rank == expected_rank && !snapshot_msgpack.is_empty() {
            self.history_election_phase = HistoryElectionPhase::Installing;
            return HistorySnapshotResponseOutcome::Install(HistoryElectionCandidate {
                rank: remote_rank,
                snapshot_version,
                snapshot_msgpack,
            });
        }

        self.request_history_election();
        HistorySnapshotResponseOutcome::Retry
    }

    pub fn finish_history_election(&mut self) {
        self.history_election_requested = false;
        self.history_election_phase = HistoryElectionPhase::Idle;
    }

    /// Record a Propose we just ack'd so a takeover can recover it.
    pub fn record_pending_propose(
        &mut self,
        op_id: OpId,
        coord: NodeIdentifier,
        op_msgpack: Bytes,
        ts_local: u64,
        now: Instant,
    ) {
        self.pending_proposes.insert(
            op_id,
            PendingPropose {
                coord_node: coord,
                op_msgpack,
                ts_local,
                seen_at: now,
            },
        );
    }

    /// Mark `op_id` as committed (via either Commit or RecoveryCommit) and
    /// drop any pending Propose we held for it. Returns `true` if this is
    /// the first time we've seen the op committed (caller should then
    /// buffer + advance clocks); `false` if we've already committed it.
    pub fn mark_committed(&mut self, op_id: OpId, ts_final: u64) -> bool {
        let inserted = self.committed_ids.insert(op_id);
        if inserted {
            self.committed_ts_final.insert(op_id, ts_final);
            self.pending_proposes.remove(&op_id);
        }
        inserted
    }

    /// Returns `true` and updates `recovery_promises[op_id] = ballot` iff
    /// `ballot > current promised`.
    pub fn try_promise(&mut self, op_id: OpId, ballot: u64) -> bool {
        let entry = self.recovery_promises.entry(op_id).or_insert(0);
        if ballot > *entry {
            *entry = ballot;
            true
        } else {
            false
        }
    }

    /// Drop committed_ts_final entries that have been delivered
    /// everywhere. Frees the recovery state we no longer need to answer
    /// Prepare requests for. Conservative: only drops when the op's
    /// `ts_final < self.delivered_high_water` (strictly less, so the same
    /// ts_final cannot be re-bufferable from a stale commit).
    pub fn gc_committed_ts_final(&mut self) {
        let dhw = self.delivered_high_water;
        self.committed_ts_final
            .retain(|_, ts_final| *ts_final >= dhw);
    }

    /// Drop pending_proposes entries older than `pending_propose_ttl` only
    /// after their coordinator is no longer alive and they no longer protect
    /// the ordering of buffered commits.
    /// Returns the dropped op-ids for logging.
    pub fn gc_stale_pending_proposes(
        &mut self,
        now: Instant,
        pending_propose_ttl: Duration,
        alive: &HashSet<NodeIdentifier>,
    ) -> Vec<OpId> {
        let mut dropped = Vec::new();
        let max_buffered_ts = self.commit_buffer.keys().next_back().map(|(ts, _)| *ts);
        self.pending_proposes.retain(|op_id, p| {
            let stale = now.duration_since(p.seen_at) >= pending_propose_ttl;
            let coord_alive = alive.contains(&p.coord_node);
            let protects_buffered_commit = max_buffered_ts.is_some_and(|ts| ts >= p.ts_local);
            if stale {
                if coord_alive || protects_buffered_commit {
                    return true;
                }
                dropped.push(*op_id);
            }
            !stale
        });
        dropped
    }

    /// Garbage-collect proposals stuck longer than `propose_ttl`.
    pub fn gc_stale_proposals(
        &mut self,
        now: Instant,
        propose_ttl: Duration,
    ) -> Vec<oneshot::Sender<Result<u64, ReplicationError>>> {
        let mut to_fire = Vec::new();
        let mut to_remove = Vec::new();
        for (op_id, p) in self.proposals.iter_mut() {
            if p.committed {
                continue;
            }
            if now.duration_since(p.started_at) >= propose_ttl {
                if let Some(w) = p.waker.take() {
                    to_fire.push(w);
                }
                to_remove.push(*op_id);
            }
        }
        for id in to_remove {
            self.proposals.remove(&id);
        }
        to_fire
    }
}

impl Default for StrictState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------- Recovery state (takeover-side) ----------

/// One in-progress recovery attempt for a single `op_id`. Lives on the
/// node that took over coordination. Removed once we either broadcast a
/// `RecoveryCommit` or abort.
pub(crate) struct Recovery {
    pub coord_node: NodeIdentifier,
    pub ballot: u64,
    pub started_at: Instant,
    /// Snapshot of alive members (∪ {self}) at recovery start, used for
    /// the recovery quorum size and to decide where to send Prepare.
    pub target_set: HashSet<NodeIdentifier>,
    pub prepare_acks: HashMap<NodeIdentifier, RecoveryPrepareAck>,
}

#[derive(Clone)]
pub(crate) struct RecoveryPrepareAck {
    pub promised: bool,
    pub has_committed: bool,
    pub committed_ts_final: u64,
    pub has_op: bool,
    pub ts_local: u64,
    pub op_msgpack: Bytes,
}

#[inline]
pub(crate) fn recovery_quorum_size(n: usize) -> usize {
    if n == 0 { 0 } else { n / 2 + 1 }
}

#[inline]
pub(crate) fn make_ballot(takeover_node: NodeIdentifier, attempt: u64) -> u64 {
    ((takeover_node as u64) << 32) | (attempt & 0xFFFF_FFFF)
}

// ---------- Generic runtime ----------

pub struct StrictRuntime<R: StrictReplicable> {
    pub(super) repo: Arc<R>,
    pub(super) self_id: NodeIdentifier,
    pub(super) boot_epoch: u64,
    pub(super) topic: String,
    pub(super) net: Arc<dyn StrictNet>,
    pub(super) state: Mutex<StrictState>,
    pub(super) deliver_signal: Notify,
    pub(super) clock_tick_signal: Notify,
    pub(super) propose_semaphore: Arc<Semaphore>,
    pub(super) next_op_counter: AtomicU64,
    /// Monotonically increasing per-takeover-attempt counter, used as the
    /// low 32 bits of `ballot` so retries always outrank prior attempts.
    pub(super) recovery_attempt_counter: AtomicU64,
    /// In-progress recoveries we're leading. Async-driven, ephemeral —
    /// not part of the pure state machine.
    pub(super) recoveries: Mutex<HashMap<OpId, Recovery>>,
    /// Weak self-pointer set immediately after `Arc::new`, used to spawn
    /// async work (recovery) from `&self` callbacks like `on_membership`.
    pub(super) weak_self: Mutex<Option<Weak<Self>>>,
    /// Time of the last bootstrap-catchup attempt. None = never. Used to
    /// throttle retries triggered by Joined/Restarted membership events
    /// (the alive view can outrun the routing table immediately after a
    /// heal, so the initial attempt may fail with NoRoute and we rely on
    /// later membership events to drive a retry).
    pub(super) last_bootstrap_attempt: Mutex<Option<Instant>>,
    delivery_blocked_log: Mutex<DeliveryBlockedLogState>,
    pub(super) shutdown: CancellationToken,
    pub(super) cfg: Arc<ReplicationConfig>,
}

impl<R: StrictReplicable> StrictRuntime<R> {
    pub(crate) fn new(
        repo: Arc<R>,
        self_id: NodeIdentifier,
        boot_epoch: u64,
        topic: String,
        net: Arc<dyn StrictNet>,
        shutdown: CancellationToken,
        cfg: Arc<ReplicationConfig>,
    ) -> Arc<Self> {
        let propose_semaphore = Arc::new(Semaphore::new(cfg.propose_semaphore_size()));
        let arc = Arc::new(Self {
            repo,
            self_id,
            boot_epoch,
            topic,
            net,
            state: Mutex::new(StrictState::new()),
            deliver_signal: Notify::new(),
            clock_tick_signal: Notify::new(),
            propose_semaphore,
            next_op_counter: AtomicU64::new(1),
            recovery_attempt_counter: AtomicU64::new(1),
            recoveries: Mutex::new(HashMap::new()),
            weak_self: Mutex::new(None),
            last_bootstrap_attempt: Mutex::new(None),
            delivery_blocked_log: Mutex::new(DeliveryBlockedLogState::default()),
            shutdown,
            cfg,
        });
        *arc.weak_self.lock() = Some(Arc::downgrade(&arc));
        arc
    }

    /// Spawn the delivery and clock-tick loops. Optionally kick off
    /// catch-up if the repo is empty and there's at least one alive peer.
    pub fn start(self: &Arc<Self>) {
        spawn_delivery_loop(self.clone());
        spawn_clock_tick_loop(self.clone());
        spawn_bootstrap_retry_loop(self.clone());
        spawn_steady_state_catchup_loop(self.clone());
    }

    fn wake_clock_tick_loop(&self) {
        self.clock_tick_signal.notify_one();
    }

    fn wake_delivery_and_clock_tick(&self) {
        self.deliver_signal.notify_one();
        self.wake_clock_tick_loop();
    }

    pub(crate) async fn send_history_snapshot_request(
        &self,
        request: HistoryElectionSnapshotRequest,
    ) -> Result<(), ReplicationError> {
        let body = StrictBody::CatchupReq(StrictCatchupReq {
            src_node: self.self_id as u32,
            since_version: 0,
            chunk_token: HISTORY_ELECTION_SNAPSHOT_TOKEN,
            force_snapshot: true,
            history_probe_only: false,
        });
        metrics::record_catchup_request(CatchupMode::Strict);
        self.net
            .send_unicast(request.peer(), &self.topic, body)
            .await
    }

    /// Send startup election probes while no strict traffic has been
    /// observed locally. Peers first respond with metadata-only history ranks;
    /// the best rank wins exactly one follow-up snapshot request.
    pub(crate) async fn try_bootstrap_catchup(self: &Arc<Self>) {
        {
            let state = self.state.lock();
            if !state.can_start_history_election() {
                return;
            }
        }
        {
            let mut last = self.last_bootstrap_attempt.lock();
            let now = Instant::now();
            if let Some(prev) = *last {
                if now.duration_since(prev) < self.cfg.strict_bootstrap_retry_interval() {
                    return;
                }
            }
            *last = Some(now);
        }
        let peers = bootstrap_reachable_peers(self.net.as_ref(), self.self_id);
        {
            let mut state = self.state.lock();
            state.observe_history_alive_peers(peers.iter().copied());
            if !state.can_start_history_election() {
                return;
            }
        }
        if peers.is_empty() && self.repo.current_version() == 0 {
            self.state.lock().finish_history_election();
            return;
        }
        if peers.is_empty() {
            return;
        }
        self.state
            .lock()
            .begin_history_election(peers.iter().copied());
        self.wake_clock_tick_loop();
        for dst in peers {
            let body = StrictBody::CatchupReq(StrictCatchupReq {
                src_node: self.self_id as u32,
                since_version: 0,
                chunk_token: 0,
                force_snapshot: false,
                history_probe_only: true,
            });
            metrics::record_catchup_request(CatchupMode::Strict);
            match self.net.send_unicast(dst, &self.topic, body).await {
                Ok(()) => {}
                Err(e) => {
                    debug!(%dst, error=%e, "strict catchup bootstrap send failed");
                    let request = self.state.lock().abandon_history_election_peer(dst);
                    if let Some(request) = request {
                        if let Err(e) = self.send_history_snapshot_request(request).await {
                            debug!(
                                dst = request.peer(),
                                error = %e,
                                "strict catchup winning snapshot request failed"
                            );
                            self.state.lock().request_history_election();
                        }
                    }
                }
            }
        }
    }

    /// Compute `(target_set, fast_quorum)` from the current alive view.
    pub fn snapshot_target_set(&self) -> (HashSet<NodeIdentifier>, usize) {
        let alive = self.net.alive_members();
        let mut tgt: HashSet<NodeIdentifier> = alive.into_iter().collect();
        tgt.insert(self.self_id);
        let fq = fast_quorum_size(tgt.len());
        (tgt, fq)
    }

    pub fn next_op_id(&self) -> OpId {
        let counter = self.next_op_counter.fetch_add(1, Ordering::Relaxed);
        make_op_id(self.self_id, self.boot_epoch, counter)
    }

    pub(crate) fn spawn_propose_retries(self: &Arc<Self>, op_id: OpId) {
        let rt = self.clone();
        tokio::spawn(async move {
            for _ in 0..PROPOSE_RETRY_TICKS {
                tokio::select! {
                    _ = rt.shutdown.cancelled() => return,
                    _ = tokio::time::sleep(rt.cfg.delivery_tick_interval()) => {},
                }

                let Some(retry) = rt.pending_propose_retry(op_id) else {
                    return;
                };
                if retry.dsts.is_empty() {
                    continue;
                }
                debug!(
                    topic = %rt.topic,
                    op_id_hi = op_id.0,
                    op_id_lo = op_id.1,
                    elapsed_ms = retry.started_at.elapsed().as_millis(),
                    ack_count = retry.ack_count,
                    target_count = retry.target_count,
                    fast_quorum = retry.fast_quorum,
                    missing_count = retry.dsts.len(),
                    "strict proposal retrying missing quorum acks"
                );
                let body = StrictBody::Propose(StrictPropose {
                    coord_node: rt.self_id as u32,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    ts_propose: retry.ts_propose,
                    op_msgpack: retry.op_msgpack,
                    src_clock: retry.src_clock,
                });
                if let Err(e) = rt.net.send_multicast(&retry.dsts, &rt.topic, body).await {
                    trace!(error=%e, "send propose retry multicast failed");
                }
            }
        });
    }

    fn pending_propose_retry(&self, op_id: OpId) -> Option<PendingProposeRetry> {
        let s = self.state.lock();
        let p = s.proposals.get(&op_id)?;
        if p.committed {
            return None;
        }
        let ack_count = p.acks.len();
        let target_count = p.target_set.len();
        let fast_quorum = fast_quorum_size(target_count);
        let dsts = p
            .target_set
            .iter()
            .filter(|node| **node != self.self_id && !p.acks.contains_key(*node))
            .copied()
            .collect();
        Some(PendingProposeRetry {
            op_msgpack: p.op_msgpack.clone(),
            ts_propose: p.ts_propose,
            src_clock: s.clock,
            dsts,
            started_at: p.started_at,
            ack_count,
            target_count,
            fast_quorum,
        })
    }

    // ------ Inbound recv handlers ------

    pub async fn recv_propose(&self, from: NodeIdentifier, p: StrictPropose) {
        let coord = match node_from_u32(p.coord_node) {
            Some(c) => c,
            None => {
                warn!(node = p.coord_node, "strict propose has invalid coord_node");
                return;
            }
        };
        let op_id: OpId = (p.op_id_hi, p.op_id_lo);
        // Update peer clock + advance our clock; reply with ack. Stash the
        // op so a takeover can recover it via the slow-path if `coord` dies.
        let ts_local;
        let local_clock_after;
        {
            let mut s = self.state.lock();
            s.observe_peer(from, p.src_clock);
            ts_local = s.advance_clock(p.ts_propose);
            local_clock_after = s.clock;
            s.peer_clocks.insert(self.self_id, local_clock_after);
            // Skip stash if we've already buffered a Commit/RecoveryCommit
            // for this op_id (a stale Propose retransmission).
            if !s.committed_ids.contains(&op_id) {
                s.record_pending_propose(
                    op_id,
                    coord,
                    Bytes::from(p.op_msgpack.clone()),
                    ts_local,
                    Instant::now(),
                );
            }
        }
        let ack = StrictBody::ProposeAck(StrictProposeAck {
            ack_node: self.self_id as u32,
            coord_node: coord as u32,
            op_id_hi: p.op_id_hi,
            op_id_lo: p.op_id_lo,
            ts_local,
            src_clock: local_clock_after,
        });
        if let Err(e) = self.net.send_unicast(coord, &self.topic, ack).await {
            trace!(error=%e, "send propose-ack failed");
        }
    }

    pub async fn recv_propose_ack(&self, _from: NodeIdentifier, ack: StrictProposeAck) {
        let op_id: OpId = (ack.op_id_hi, ack.op_id_lo);
        let ack_node = match node_from_u32(ack.ack_node) {
            Some(node) => node,
            None => {
                warn!(
                    node = ack.ack_node,
                    "strict propose ack has invalid ack_node"
                );
                return;
            }
        };
        let coord = match node_from_u32(ack.coord_node) {
            Some(node) => node,
            None => {
                warn!(
                    node = ack.coord_node,
                    "strict propose ack has invalid coord_node"
                );
                return;
            }
        };
        if coord != self.self_id {
            trace!(coord, "strict propose ack ignored: not coordinator");
            return;
        }
        // Update peer clock.
        {
            let mut s = self.state.lock();
            s.observe_peer(ack_node, ack.src_clock);
        }

        // Decide whether quorum reached for this proposal we're coordinating.
        let mut to_send: Option<AcceptedProposal> = {
            let mut s = self.state.lock();

            // Phase 1: read fields from the proposal entry and decide.
            let op_bytes: Bytes;
            let op_bytes_len: usize;
            let dsts: Vec<NodeIdentifier>;
            let ts_final: u64;
            let accepted_waker: Option<oneshot::Sender<()>>;
            let elapsed: Duration;
            let ack_count: usize;
            let target_count: usize;
            let fast_quorum: usize;
            {
                let Some(p) = s.proposals.get_mut(&op_id) else {
                    return;
                };
                if p.committed {
                    return;
                }
                if !p.target_set.contains(&ack_node) {
                    trace!(ack_node, "strict propose ack ignored: outside target set");
                    return;
                }
                p.acks.insert(ack_node, ack.ts_local);
                target_count = p.target_set.len();
                fast_quorum = fast_quorum_size(target_count);
                if p.acks.len() < fast_quorum {
                    return;
                }
                ts_final = p.acks.values().copied().max().unwrap_or(p.ts_propose);
                p.committed = true;
                accepted_waker = p.accepted_waker.take();
                op_bytes = p.op_msgpack.clone();
                op_bytes_len = op_bytes.len();
                elapsed = p.started_at.elapsed();
                ack_count = p.acks.len();
                dsts = p
                    .target_set
                    .iter()
                    .filter(|n| **n != self.self_id)
                    .copied()
                    .collect();
            }

            // Phase 2: mutate sibling fields of `s` now that `p` is dropped.
            if ts_final > s.clock {
                s.clock = ts_final;
            }
            let clock_now = s.clock;
            s.peer_clocks.insert(self.self_id, clock_now);
            s.mark_committed(op_id, ts_final);
            s.buffer_commit(op_id, ts_final, op_bytes.clone());
            let commit_buffer_len = s.commit_buffer.len();
            let pending_local_proposals = s.proposals.values().filter(|p| !p.committed).count();
            let pending_remote_proposes = s.pending_proposes.len();

            let body = StrictBody::Commit(StrictCommit {
                coord_node: self.self_id as u32,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_final,
                op_msgpack: op_bytes,
                src_clock: clock_now,
            });
            Some(AcceptedProposal {
                body,
                dsts,
                accepted_waker,
                elapsed,
                ack_count,
                target_count,
                fast_quorum,
                ts_final,
                clock_now,
                op_bytes: op_bytes_len,
                commit_buffer_len,
                pending_local_proposals,
                pending_remote_proposes,
            })
        };

        if let Some(accepted) = to_send.as_ref() {
            log_accepted_proposal(&self.topic, op_id, accepted);
        }

        let accepted_waker = to_send
            .as_mut()
            .and_then(|accepted| accepted.accepted_waker.take());
        if let Some(w) = accepted_waker {
            let _ = w.send(());
        }
        self.wake_delivery_and_clock_tick();

        if let Some(accepted) = to_send {
            if let Err(e) = self
                .net
                .send_multicast(&accepted.dsts, &self.topic, accepted.body.clone())
                .await
            {
                trace!(error=%e, "send commit multicast failed");
            }
            spawn_commit_fanout_retries(
                self.net.clone(),
                self.shutdown.clone(),
                self.topic.clone(),
                accepted.dsts,
                accepted.body,
                self.cfg.delivery_tick_interval(),
            );
        }
    }

    pub async fn recv_commit(&self, from: NodeIdentifier, c: StrictCommit) {
        let op_id: OpId = (c.op_id_hi, c.op_id_lo);
        let mut notify = false;
        let mut gossip: Option<StrictBody> = None;
        let mut buffered_log: Option<BufferedCommitLog> = None;
        {
            let mut s = self.state.lock();
            s.observe_peer(from, c.src_clock);
            // clock = max(clock, ts_final)
            if c.ts_final > s.clock {
                s.clock = c.ts_final;
            }
            let clock_now = s.clock;
            s.peer_clocks.insert(self.self_id, clock_now);
            // Idempotent: only buffer once. A late Commit arriving after a
            // RecoveryCommit (or vice versa) for the same op_id with a
            // different ts_final is silently ignored — a correct
            // implementation guarantees they agree (see plan §1.4); a
            // mismatch is logged at error level for postmortem.
            if let Some(prev_ts) = s.committed_ts_final.get(&op_id).copied() {
                if prev_ts != c.ts_final {
                    error!(
                        op_id_hi = op_id.0,
                        op_id_lo = op_id.1,
                        prev_ts,
                        new_ts = c.ts_final,
                        "strict commit ts_final disagreement; keeping first"
                    );
                }
            } else if s.mark_committed(op_id, c.ts_final) {
                let op_msgpack = Bytes::from(c.op_msgpack);
                let op_bytes = op_msgpack.len();
                s.buffer_commit(op_id, c.ts_final, op_msgpack.clone());
                buffered_log = Some(BufferedCommitLog {
                    source: "commit",
                    from: Some(from),
                    coord_node: node_from_u32(c.coord_node),
                    op_id,
                    ts_final: c.ts_final,
                    clock_now,
                    op_bytes,
                    commit_buffer_len: s.commit_buffer.len(),
                    pending_local_proposals: s.proposals.values().filter(|p| !p.committed).count(),
                    pending_remote_proposes: s.pending_proposes.len(),
                });
                notify = true;
                gossip = Some(StrictBody::Commit(StrictCommit {
                    coord_node: c.coord_node,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    ts_final: c.ts_final,
                    op_msgpack,
                    src_clock: clock_now,
                }));
            }
        }
        if let Some(log) = buffered_log {
            log_buffered_commit(&self.topic, log);
        }
        if notify {
            self.wake_delivery_and_clock_tick();
        }
        if let Some(body) = gossip {
            let dsts: Vec<NodeIdentifier> = self
                .net
                .alive_members()
                .into_iter()
                .filter(|node| *node != self.self_id)
                .collect();
            if let Err(e) = self
                .net
                .send_multicast(&dsts, &self.topic, body.clone())
                .await
            {
                trace!(error=%e, "send commit gossip multicast failed");
            }
            spawn_commit_fanout_retries(
                self.net.clone(),
                self.shutdown.clone(),
                self.topic.clone(),
                dsts,
                body,
                self.cfg.delivery_tick_interval(),
            );
        }
    }

    pub fn recv_clock_tick(&self, from: NodeIdentifier, t: StrictClockTick) {
        {
            let mut s = self.state.lock();
            s.observe_peer(from, t.src_clock);
        }
        // Tick may unblock delivery.
        self.deliver_signal.notify_one();
    }

    pub async fn recv_catchup_req(&self, from: NodeIdentifier, req: StrictCatchupReq) {
        super::catchup::respond_to_request(self, from, req).await
    }

    pub async fn recv_catchup_resp(&self, from: NodeIdentifier, resp: StrictCatchupResp) {
        super::catchup::apply_response(self, from, resp).await
    }

    // ------ Slow-path recovery handlers ------

    /// Phase 1 (Prepare): respond with our current state for `op_id` and,
    /// if the ballot is higher than any we've previously promised, accept
    /// it as our new promise.
    pub async fn recv_recovery_req(&self, from: NodeIdentifier, req: StrictRecoveryReq) {
        let op_id: OpId = (req.op_id_hi, req.op_id_lo);
        let coord = match node_from_u32(req.coord_node) {
            Some(c) => c,
            None => {
                warn!(node = req.coord_node, "recovery req has invalid coord_node");
                return;
            }
        };
        let takeover = match node_from_u32(req.takeover_node) {
            Some(c) => c,
            None => {
                warn!(
                    node = req.takeover_node,
                    "recovery req has invalid takeover_node"
                );
                return;
            }
        };
        let (promised, has_committed, committed_ts_final, has_op, ts_local, op_msgpack, src_clock) = {
            let mut s = self.state.lock();
            s.observe_peer(from, req.src_clock);
            let promised = s.try_promise(op_id, req.ballot);
            let committed_ts_final = s.committed_ts_final.get(&op_id).copied();
            let has_committed = committed_ts_final.is_some();
            let pending = s.pending_proposes.get(&op_id);
            let (has_op, ts_local, op_msgpack) = pending
                .map(|p| (true, p.ts_local, p.op_msgpack.clone()))
                .unwrap_or((false, 0, Bytes::new()));
            (
                promised,
                has_committed,
                committed_ts_final.unwrap_or(0),
                has_op,
                ts_local,
                op_msgpack,
                s.clock,
            )
        };
        let body = StrictBody::RecoveryAck(StrictRecoveryAck {
            ack_node: self.self_id as u32,
            ballot: req.ballot,
            coord_node: coord as u32,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            promised,
            has_committed,
            committed_ts_final,
            has_op,
            ts_local,
            op_msgpack,
            src_clock,
        });
        if let Err(e) = self.net.send_unicast(takeover, &self.topic, body).await {
            trace!(error=%e, "send recovery-ack failed");
        }
    }

    /// Phase 1 reply (takeover-side): accumulate acks, decide outcome
    /// once we have a recovery quorum.
    pub async fn recv_recovery_ack(&self, from: NodeIdentifier, ack: StrictRecoveryAck) {
        let op_id: OpId = (ack.op_id_hi, ack.op_id_lo);
        // Update peer clock.
        {
            let mut s = self.state.lock();
            s.observe_peer(from, ack.src_clock);
        }

        // Decide whether quorum is now reached.
        let decision = {
            let mut recoveries = self.recoveries.lock();
            let Some(rec) = recoveries.get_mut(&op_id) else {
                return;
            };
            if ack.ballot != rec.ballot {
                return; // stale ack from a previous attempt
            }
            rec.prepare_acks.insert(
                from,
                RecoveryPrepareAck {
                    promised: ack.promised,
                    has_committed: ack.has_committed,
                    committed_ts_final: ack.committed_ts_final,
                    has_op: ack.has_op,
                    ts_local: ack.ts_local,
                    op_msgpack: ack.op_msgpack,
                },
            );
            let rq = recovery_quorum_size(rec.target_set.len());
            if rec.prepare_acks.len() < rq {
                return;
            }
            // Quorum reached. Decide.
            let any_promise_lost = rec.prepare_acks.values().any(|a| !a.promised);
            if any_promise_lost {
                // A higher ballot exists; abort. Liveness will recover via
                // RecoveryCommit from the higher-ballot takeover.
                debug!(
                    op_id_hi = op_id.0,
                    op_id_lo = op_id.1,
                    "recovery aborted: higher ballot promised elsewhere"
                );
                recoveries.remove(&op_id);
                return;
            }
            // Prefer any has_committed result (the original coord did
            // commit before dying, somewhere in the recovery quorum).
            let committed_choice = rec
                .prepare_acks
                .values()
                .filter(|a| a.has_committed)
                .max_by_key(|a| a.committed_ts_final)
                .cloned();
            if let Some(c) = committed_choice {
                let ts_final = c.committed_ts_final;
                let bytes = if c.op_msgpack.is_empty() {
                    // Edge case: an ack reported has_committed=true but
                    // didn't include op_msgpack (e.g. it had committed
                    // long enough ago that committed_ts_final was GC'd —
                    // shouldn't happen, but be defensive). Fall back to
                    // any has_op ack with the same ts_final.
                    rec.prepare_acks
                        .values()
                        .find(|a| a.has_op && a.ts_local == ts_final)
                        .map(|a| a.op_msgpack.clone())
                        .unwrap_or_else(Bytes::new)
                } else {
                    c.op_msgpack
                };
                let coord = rec.coord_node;
                let ballot = rec.ballot;
                let target = rec.target_set.clone();
                recoveries.remove(&op_id);
                Some((ts_final, bytes, coord, ballot, target))
            } else {
                // No committed ack — the original coord never committed.
                // Pick the highest ts_local among has_op acks. If none has
                // an op, recovery aborts (no replica even saw the Propose).
                let best = rec
                    .prepare_acks
                    .values()
                    .filter(|a| a.has_op)
                    .max_by_key(|a| a.ts_local)
                    .cloned();
                match best {
                    Some(b) => {
                        let coord = rec.coord_node;
                        let ballot = rec.ballot;
                        let target = rec.target_set.clone();
                        recoveries.remove(&op_id);
                        Some((b.ts_local, b.op_msgpack, coord, ballot, target))
                    }
                    None => {
                        debug!(
                            op_id_hi = op_id.0,
                            op_id_lo = op_id.1,
                            "recovery aborted: no replica holds the op (genuinely lost)"
                        );
                        recoveries.remove(&op_id);
                        None
                    }
                }
            }
        };

        let Some((ts_final, op_msgpack, coord, ballot, target)) = decision else {
            return;
        };

        // Apply locally + advance our clock; broadcast RecoveryCommit.
        let clock_now;
        let mut notify = false;
        let mut buffered_log: Option<BufferedCommitLog> = None;
        {
            let mut s = self.state.lock();
            if ts_final > s.clock {
                s.clock = ts_final;
            }
            clock_now = s.clock;
            s.peer_clocks.insert(self.self_id, clock_now);
            if s.committed_ts_final.get(&op_id).copied().is_none()
                && s.mark_committed(op_id, ts_final)
            {
                let op_bytes = op_msgpack.len();
                s.buffer_commit(op_id, ts_final, op_msgpack.clone());
                buffered_log = Some(BufferedCommitLog {
                    source: "recovery_decision",
                    from: None,
                    coord_node: Some(coord),
                    op_id,
                    ts_final,
                    clock_now,
                    op_bytes,
                    commit_buffer_len: s.commit_buffer.len(),
                    pending_local_proposals: s.proposals.values().filter(|p| !p.committed).count(),
                    pending_remote_proposes: s.pending_proposes.len(),
                });
                notify = true;
            }
        }
        if let Some(log) = buffered_log {
            log_buffered_commit(&self.topic, log);
        }
        if notify {
            self.wake_delivery_and_clock_tick();
        }

        let dsts: Vec<NodeIdentifier> = target
            .iter()
            .filter(|n| **n != self.self_id)
            .copied()
            .collect();
        let body = StrictBody::RecoveryCommit(StrictRecoveryCommit {
            takeover_node: self.self_id as u32,
            ballot,
            coord_node: coord as u32,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            ts_final,
            op_msgpack,
            src_clock: clock_now,
        });
        if !dsts.is_empty() {
            if let Err(e) = self.net.send_multicast(&dsts, &self.topic, body).await {
                trace!(error=%e, "send recovery-commit multicast failed");
            }
        }
    }

    /// Phase 2 (Accept-and-Commit): apply if our promise still allows it.
    pub async fn recv_recovery_commit(&self, from: NodeIdentifier, c: StrictRecoveryCommit) {
        let op_id: OpId = (c.op_id_hi, c.op_id_lo);
        let mut notify = false;
        let mut buffered_log: Option<BufferedCommitLog> = None;
        {
            let mut s = self.state.lock();
            s.observe_peer(from, c.src_clock);
            let promised_now = s.recovery_promises.get(&op_id).copied().unwrap_or(0);
            if c.ballot < promised_now {
                trace!(
                    ballot = c.ballot,
                    promised = promised_now,
                    "recovery commit rejected: stale ballot"
                );
                return;
            }
            // Promote our promise so subsequent stale messages are filtered.
            s.try_promise(op_id, c.ballot);
            if c.ts_final > s.clock {
                s.clock = c.ts_final;
            }
            let clock_now = s.clock;
            s.peer_clocks.insert(self.self_id, clock_now);
            // Same dedup discipline as recv_commit.
            if let Some(prev_ts) = s.committed_ts_final.get(&op_id).copied() {
                if prev_ts != c.ts_final {
                    error!(
                        op_id_hi = op_id.0,
                        op_id_lo = op_id.1,
                        prev_ts,
                        new_ts = c.ts_final,
                        "recovery commit ts_final disagreement; keeping first"
                    );
                }
            } else if s.mark_committed(op_id, c.ts_final) {
                let op_msgpack = Bytes::from(c.op_msgpack);
                let op_bytes = op_msgpack.len();
                s.buffer_commit(op_id, c.ts_final, op_msgpack);
                buffered_log = Some(BufferedCommitLog {
                    source: "recovery_commit",
                    from: Some(from),
                    coord_node: node_from_u32(c.coord_node),
                    op_id,
                    ts_final: c.ts_final,
                    clock_now,
                    op_bytes,
                    commit_buffer_len: s.commit_buffer.len(),
                    pending_local_proposals: s.proposals.values().filter(|p| !p.committed).count(),
                    pending_remote_proposes: s.pending_proposes.len(),
                });
                notify = true;
            }
        }
        if let Some(log) = buffered_log {
            log_buffered_commit(&self.topic, log);
        }
        if notify {
            self.wake_delivery_and_clock_tick();
        }
    }

    /// Initiate recovery for every pending Propose whose coord just died,
    /// for which we are the deterministic takeover (= smallest alive node
    /// id excluding the failed coord). Idempotent: skips op_ids that
    /// already have an in-progress recovery.
    pub async fn maybe_initiate_recovery(&self, failed_coord: NodeIdentifier) {
        let alive_with_self: HashSet<NodeIdentifier> = self
            .net
            .alive_members()
            .into_iter()
            .chain([self.self_id])
            .collect();
        let takeover = alive_with_self
            .iter()
            .filter(|n| **n != failed_coord)
            .copied()
            .min();
        if takeover != Some(self.self_id) {
            return;
        }
        // Snapshot candidate op_ids quickly.
        let candidates: Vec<(OpId, PendingProposeSnapshot)> = {
            let s = self.state.lock();
            s.pending_proposes
                .iter()
                .filter(|(op_id, pp)| {
                    pp.coord_node == failed_coord && !s.committed_ids.contains(op_id)
                })
                .map(|(id, pp)| {
                    (
                        *id,
                        PendingProposeSnapshot {
                            ts_local: pp.ts_local,
                            op_msgpack: pp.op_msgpack.clone(),
                        },
                    )
                })
                .collect()
        };
        for (op_id, snap) in candidates {
            let already_running = {
                let recoveries = self.recoveries.lock();
                recoveries.contains_key(&op_id)
            };
            if already_running {
                continue;
            }
            let attempt = self
                .recovery_attempt_counter
                .fetch_add(1, Ordering::Relaxed);
            let ballot = make_ballot(self.self_id, attempt);
            // Self-ack inline (we always promise our own ballot on creation).
            let self_ack = {
                let mut s = self.state.lock();
                let promised = s.try_promise(op_id, ballot);
                let committed_ts_final = s.committed_ts_final.get(&op_id).copied();
                RecoveryPrepareAck {
                    promised,
                    has_committed: committed_ts_final.is_some(),
                    committed_ts_final: committed_ts_final.unwrap_or(0),
                    has_op: true,
                    ts_local: snap.ts_local,
                    op_msgpack: snap.op_msgpack,
                }
            };
            let mut prepare_acks = HashMap::new();
            prepare_acks.insert(self.self_id, self_ack);
            let target_set = alive_with_self.clone();
            {
                let mut recoveries = self.recoveries.lock();
                recoveries.insert(
                    op_id,
                    Recovery {
                        coord_node: failed_coord,
                        ballot,
                        started_at: Instant::now(),
                        target_set: target_set.clone(),
                        prepare_acks,
                    },
                );
            }
            // Single-node mesh edge case: recovery_quorum = 1, self-ack
            // already satisfies it. Trigger the decision path manually.
            let rq = recovery_quorum_size(target_set.len());
            if rq <= 1 {
                self.try_decide_self_recovery(op_id).await;
                continue;
            }
            // Broadcast Prepare to everyone in target_set except self.
            let dsts: Vec<NodeIdentifier> = target_set
                .iter()
                .filter(|n| **n != self.self_id)
                .copied()
                .collect();
            let src_clock = {
                let s = self.state.lock();
                s.clock
            };
            let body = StrictBody::RecoveryReq(StrictRecoveryReq {
                takeover_node: self.self_id as u32,
                ballot,
                coord_node: failed_coord as u32,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                src_clock,
            });
            if let Err(e) = self.net.send_multicast(&dsts, &self.topic, body).await {
                trace!(error=%e, "send recovery-prepare multicast failed");
            }
        }
    }

    /// Single-node-mesh recovery shortcut: feed the takeover's self-ack
    /// back through the same decision path as `recv_recovery_ack` would
    /// take from a remote, by synthesising a no-op ack call.
    async fn try_decide_self_recovery(&self, op_id: OpId) {
        // Build a synthetic ack matching what we already have in
        // recoveries[op_id].prepare_acks[self_id]. The decision logic in
        // recv_recovery_ack will see prepare_acks.len() == 1 and resolve.
        let synth = {
            let recoveries = self.recoveries.lock();
            let Some(rec) = recoveries.get(&op_id) else {
                return;
            };
            let Some(self_ack) = rec.prepare_acks.get(&self.self_id) else {
                return;
            };
            StrictRecoveryAck {
                ack_node: self.self_id as u32,
                ballot: rec.ballot,
                coord_node: rec.coord_node as u32,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                promised: self_ack.promised,
                has_committed: self_ack.has_committed,
                committed_ts_final: self_ack.committed_ts_final,
                has_op: self_ack.has_op,
                ts_local: self_ack.ts_local,
                op_msgpack: self_ack.op_msgpack.clone(),
                src_clock: 0,
            }
        };
        // The ack handler will re-insert (idempotent), see quorum, decide.
        self.recv_recovery_ack(self.self_id, synth).await;
    }

    /// Handle alive-set changes. Called from the manager's membership-event
    /// fanout. Fires `QuorumLost` for any in-flight proposals that can no
    /// longer reach fast-quorum, and initiates slow-path recovery for any
    /// pending Propose whose coord just died.
    pub fn on_membership_change(&self, ev: &MembershipEvent) {
        // If a coord died (Failed or Left), we may need to take over
        // recovery for any of its in-flight Proposes we hold.
        let failed_coord = match ev {
            MembershipEvent::Failed(n) | MembershipEvent::Left(n) => Some(*n),
            _ => None,
        };
        let peer_removed = matches!(
            ev,
            MembershipEvent::Failed(_) | MembershipEvent::Left(_) | MembershipEvent::Restarted(_)
        );
        if peer_removed {
            let alive_set: HashSet<NodeIdentifier> = self
                .net
                .alive_members()
                .into_iter()
                .chain([self.self_id])
                .collect();
            let wakers = {
                let mut s = self.state.lock();
                s.fail_quorum_lost(&alive_set)
            };
            for (op_id, w) in wakers {
                warn!(
                    topic = %self.topic,
                    op_id_hi = op_id.0,
                    op_id_lo = op_id.1,
                    alive = ?alive_set,
                    event = ?ev,
                    "strict proposal failed because fast quorum became unreachable"
                );
                let _ = w.send(Err(ReplicationError::QuorumLost));
            }
        }
        if let Some(coord) = failed_coord {
            // Spawn a task — maybe_initiate_recovery is async (needs the
            // network). Upgrade the weak self-pointer set in `new()`.
            let weak = self.weak_self.lock().clone();
            if let Some(weak) = weak {
                tokio::spawn(async move {
                    if let Some(rt) = weak.upgrade() {
                        rt.maybe_initiate_recovery(coord).await;
                    }
                });
            }
        }

        // A peer became reachable or restarted. Trigger history election for
        // both startup catchup and partition heal: split sides can have
        // divergent strict histories, so the merged cluster must converge on
        // one rank before normal traffic resumes.
        let peer_added = matches!(
            ev,
            MembershipEvent::Joined(_) | MembershipEvent::Restarted(_),
        );
        if peer_added {
            self.state.lock().request_history_election();
            self.wake_clock_tick_loop();
            let weak = self.weak_self.lock().clone();
            if let Some(weak) = weak {
                tokio::spawn(async move {
                    if let Some(rt) = weak.upgrade() {
                        rt.try_bootstrap_catchup().await;
                    }
                });
            }
        }

        self.deliver_signal.notify_one();
    }
}

/// Lightweight snapshot of a pending Propose, used to copy the bits we
/// need out from under the state lock before doing async work.
struct PendingProposeSnapshot {
    ts_local: u64,
    op_msgpack: Bytes,
}

#[async_trait]
impl<R: StrictReplicable> ErasedStrictRuntime for StrictRuntime<R> {
    async fn dispatch(&self, from: NodeIdentifier, body: StrictBody) {
        match body {
            StrictBody::Propose(p) => self.recv_propose(from, p).await,
            StrictBody::ProposeAck(a) => self.recv_propose_ack(from, a).await,
            StrictBody::Commit(c) => self.recv_commit(from, c).await,
            StrictBody::ClockTick(t) => self.recv_clock_tick(from, t),
            StrictBody::CatchupReq(r) => self.recv_catchup_req(from, r).await,
            StrictBody::CatchupResp(r) => self.recv_catchup_resp(from, r).await,
            StrictBody::RecoveryReq(r) => self.recv_recovery_req(from, r).await,
            StrictBody::RecoveryAck(a) => self.recv_recovery_ack(from, a).await,
            StrictBody::RecoveryCommit(c) => self.recv_recovery_commit(from, c).await,
        }
    }

    fn on_membership(&self, ev: &MembershipEvent) {
        // Re-evaluate quorum + maybe initiate recovery on every event.
        // (Cheap path; spawn only fires on Failed/Left.)
        self.on_membership_change(ev);
    }

    fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

// ---------- Background loops ----------

fn spawn_commit_fanout_retries(
    net: Arc<dyn StrictNet>,
    shutdown: CancellationToken,
    topic: String,
    dsts: Vec<NodeIdentifier>,
    body: StrictBody,
    interval: Duration,
) {
    if dsts.is_empty() {
        return;
    }
    tokio::spawn(async move {
        for _ in 0..COMMIT_FANOUT_RETRY_TICKS {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(interval) => {},
            }
            if let Err(e) = net.send_multicast(&dsts, &topic, body.clone()).await {
                trace!(error=%e, "commit fanout retry failed");
            }
        }
    });
}

fn spawn_delivery_loop<R: StrictReplicable>(rt: Arc<StrictRuntime<R>>) {
    let weak = {
        let rt = rt;
        Arc::downgrade(&rt)
    };
    tokio::spawn(async move {
        let Some(rt) = weak.upgrade() else {
            return;
        };
        let mut ticker = tokio::time::interval(rt.cfg.delivery_tick_interval());
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = rt.shutdown.cancelled() => return,
                _ = rt.deliver_signal.notified() => {}
                _ = ticker.tick() => {}
            }
            run_delivery_pass(&rt).await;
            run_gc_pass(&rt);
        }
    });
}

async fn run_delivery_pass<R: StrictReplicable>(rt: &Arc<StrictRuntime<R>>) {
    let alive = delivery_members(rt.net.as_ref(), rt.self_id);
    let now = Instant::now();
    let mut blocked: Option<DeliveryBlockDiagnostics> = None;
    let to_apply: Vec<BufferedOp> = {
        let mut s = rt.state.lock();
        let watermark = delivery_watermark(&s, rt.self_id, &alive);
        let raw_high_water = watermark.high_water;
        let pending_blocker = earliest_uncommitted_proposal_blocker(&s, rt.self_id, now);
        let mut effective_high_water = raw_high_water;
        if let Some(ts) = s.earliest_uncommitted_proposal_ts() {
            effective_high_water = effective_high_water.min(ts.saturating_sub(1));
        }
        let drained = s.drain_deliverable(effective_high_water);
        if let Some(next) = next_buffered_op_diagnostics(&s, now) {
            if next.ts_final > effective_high_water {
                blocked = Some(DeliveryBlockDiagnostics {
                    next,
                    raw_high_water,
                    effective_high_water,
                    watermark,
                    pending_blocker,
                    alive_count: alive.len(),
                    commit_buffer_len: s.commit_buffer.len(),
                    pending_local_proposals: s.proposals.values().filter(|p| !p.committed).count(),
                    pending_remote_proposes: s.pending_proposes.len(),
                });
            }
        }
        drained
    };
    if let Some(diagnostics) = blocked {
        log_delivery_blocked(rt, diagnostics);
    } else {
        clear_delivery_blocked(rt);
    }
    for buf in to_apply {
        let buffered_for = buf.buffered_at.elapsed();
        let decode_started_at = Instant::now();
        let op: R::Op = match rmp_serde::from_slice(&buf.op_msgpack) {
            Ok(o) => o,
            Err(e) => {
                metrics::record_pipeline_stage(
                    ReplicationPipelineKind::Strict,
                    ReplicationPipelineStage::MsgpackDecode,
                    decode_started_at.elapsed(),
                );
                warn!(
                    error = %e,
                    topic = %rt.topic,
                    op_id_hi = buf.op_id.0,
                    op_id_lo = buf.op_id.1,
                    ts_final = buf.ts_final,
                    buffered_for_ms = buffered_for.as_millis(),
                    "failed to decode committed op msgpack"
                );
                continue;
            }
        };
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::MsgpackDecode,
            decode_started_at.elapsed(),
        );
        let version = rt.repo.current_version() + 1;
        debug!(
            topic = %rt.topic,
            op_id_hi = buf.op_id.0,
            op_id_lo = buf.op_id.1,
            ts_final = buf.ts_final,
            version,
            buffered_for_ms = buffered_for.as_millis(),
            op_bytes = buf.op_msgpack.len(),
            "strict delivery applying committed op"
        );
        let apply_started = Instant::now();
        rt.repo
            .apply_committed_with_metadata(
                version,
                op,
                Some(StrictLogMetadata {
                    op_id_hi: buf.op_id.0,
                    op_id_lo: buf.op_id.1,
                    ts_final: buf.ts_final,
                }),
            )
            .await;
        let apply_elapsed = apply_started.elapsed();
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::RepoApply,
            apply_elapsed,
        );
        // Fire local proposer's waker, if any, and clear the proposal.
        let (waker, local_proposal_elapsed) = {
            let mut s = rt.state.lock();
            if buf.ts_final > s.delivered_high_water {
                s.delivered_high_water = buf.ts_final;
            }
            let proposal = s.proposals.remove(&buf.op_id);
            let elapsed = proposal.as_ref().map(|p| p.started_at.elapsed());
            let waker = proposal.and_then(|p| p.waker);
            (waker, elapsed)
        };
        log_delivery_applied(
            &rt.topic,
            &buf,
            version,
            buffered_for,
            apply_elapsed,
            local_proposal_elapsed,
        );
        if let Some(w) = waker {
            let _ = w.send(Ok(version));
        }
    }
}

fn delivery_watermark(
    state: &StrictState,
    self_id: NodeIdentifier,
    alive: &[NodeIdentifier],
) -> DeliveryWatermark {
    let high_water = state.delivery_high_water(self_id, alive);
    let mut low_water_node = self_id;
    let mut low_water_clock = state.clock;
    let mut missing_clock_peers = 0;
    for node in alive.iter().copied() {
        if node == self_id {
            continue;
        }
        match state.peer_clocks.get(&node).copied() {
            Some(clock) => {
                if clock <= low_water_clock {
                    low_water_node = node;
                    low_water_clock = clock;
                }
            }
            None => {
                missing_clock_peers += 1;
                if low_water_clock != 0 {
                    low_water_node = node;
                    low_water_clock = 0;
                }
            }
        }
    }
    DeliveryWatermark {
        high_water,
        low_water_node,
        low_water_clock,
        missing_clock_peers,
    }
}

fn delivery_members(net: &dyn StrictNet, self_id: NodeIdentifier) -> Vec<NodeIdentifier> {
    let mut seen = HashSet::new();
    let mut members = Vec::new();
    for node in net.alive_members().into_iter().chain([self_id]) {
        if !seen.insert(node) {
            continue;
        }
        if node == self_id || net.has_live_route(node, ServiceLevel::Reliable) {
            members.push(node);
        }
    }
    members
}

fn earliest_uncommitted_proposal_blocker(
    state: &StrictState,
    self_id: NodeIdentifier,
    now: Instant,
) -> Option<UncommittedProposalBlocker> {
    let local = state
        .proposals
        .iter()
        .filter(|(_, proposal)| !proposal.committed)
        .map(|(op_id, proposal)| UncommittedProposalBlocker {
            kind: "local",
            op_id: *op_id,
            coord_node: self_id,
            ts: proposal.ts_propose,
            age: now.saturating_duration_since(proposal.started_at),
        });
    let remote = state
        .pending_proposes
        .iter()
        .map(|(op_id, pending)| UncommittedProposalBlocker {
            kind: "remote",
            op_id: *op_id,
            coord_node: pending.coord_node,
            ts: pending.ts_local,
            age: now.saturating_duration_since(pending.seen_at),
        });
    local.chain(remote).min_by_key(|blocker| blocker.ts)
}

fn next_buffered_op_diagnostics(
    state: &StrictState,
    now: Instant,
) -> Option<NextBufferedOpDiagnostics> {
    state
        .commit_buffer
        .iter()
        .next()
        .map(|(key, buffered)| NextBufferedOpDiagnostics {
            key: *key,
            op_id: buffered.op_id,
            ts_final: buffered.ts_final,
            buffered_for: now.saturating_duration_since(buffered.buffered_at),
        })
}

fn log_delivery_blocked<R: StrictReplicable>(
    rt: &Arc<StrictRuntime<R>>,
    diagnostics: DeliveryBlockDiagnostics,
) {
    let now = Instant::now();
    let (blocked_for, should_log) = {
        let mut state = rt.delivery_blocked_log.lock();
        if state.key != Some(diagnostics.next.key) {
            state.key = Some(diagnostics.next.key);
            state.blocked_since = Some(now);
            state.last_log_at = None;
        }
        let blocked_since = state.blocked_since.unwrap_or(now);
        let blocked_for = now.saturating_duration_since(blocked_since);
        let log_interval_elapsed = state.last_log_at.is_none_or(|last| {
            now.saturating_duration_since(last) >= STRICT_DELIVERY_BLOCKED_LOG_INTERVAL
        });
        let should_log = blocked_for >= STRICT_REPLICATION_SLOW_STAGE && log_interval_elapsed;
        if should_log {
            state.last_log_at = Some(now);
        }
        (blocked_for, should_log)
    };
    if !should_log {
        return;
    }

    let blocker_kind = diagnostics
        .pending_blocker
        .as_ref()
        .map(|blocker| blocker.kind)
        .unwrap_or("none");
    let blocker_op_id_hi = diagnostics
        .pending_blocker
        .as_ref()
        .map(|blocker| blocker.op_id.0)
        .unwrap_or(0);
    let blocker_op_id_lo = diagnostics
        .pending_blocker
        .as_ref()
        .map(|blocker| blocker.op_id.1)
        .unwrap_or(0);
    let blocker_coord_node = diagnostics
        .pending_blocker
        .as_ref()
        .map(|blocker| blocker.coord_node)
        .unwrap_or(0);
    let blocker_ts = diagnostics
        .pending_blocker
        .as_ref()
        .map(|blocker| blocker.ts)
        .unwrap_or(0);
    let blocker_age_ms = diagnostics
        .pending_blocker
        .as_ref()
        .map(|blocker| blocker.age.as_millis())
        .unwrap_or(0);

    warn!(
        topic = %rt.topic,
        op_id_hi = diagnostics.next.op_id.0,
        op_id_lo = diagnostics.next.op_id.1,
        ts_final = diagnostics.next.ts_final,
        blocked_for_ms = blocked_for.as_millis(),
        buffered_for_ms = diagnostics.next.buffered_for.as_millis(),
        raw_high_water = diagnostics.raw_high_water,
        effective_high_water = diagnostics.effective_high_water,
        low_water_node = diagnostics.watermark.low_water_node,
        low_water_clock = diagnostics.watermark.low_water_clock,
        missing_clock_peers = diagnostics.watermark.missing_clock_peers,
        blocker_kind,
        blocker_op_id_hi,
        blocker_op_id_lo,
        blocker_coord_node,
        blocker_ts,
        blocker_age_ms,
        alive_count = diagnostics.alive_count,
        commit_buffer_len = diagnostics.commit_buffer_len,
        pending_local_proposals = diagnostics.pending_local_proposals,
        pending_remote_proposes = diagnostics.pending_remote_proposes,
        "strict delivery blocked"
    );
}

fn clear_delivery_blocked<R: StrictReplicable>(rt: &Arc<StrictRuntime<R>>) {
    let mut state = rt.delivery_blocked_log.lock();
    if state.key.is_some() {
        *state = DeliveryBlockedLogState::default();
    }
}

fn log_delivery_applied(
    topic: &str,
    buf: &BufferedOp,
    version: u64,
    buffered_for: Duration,
    apply_elapsed: Duration,
    local_proposal_elapsed: Option<Duration>,
) {
    if apply_elapsed >= STRICT_REPLICATION_SLOW_STAGE
        || local_proposal_elapsed.is_some_and(|elapsed| elapsed >= STRICT_REPLICATION_SLOW_STAGE)
    {
        warn!(
            topic = %topic,
            op_id_hi = buf.op_id.0,
            op_id_lo = buf.op_id.1,
            ts_final = buf.ts_final,
            version,
            buffered_for_ms = buffered_for.as_millis(),
            apply_elapsed_ms = apply_elapsed.as_millis(),
            local_proposal_elapsed_ms = ?local_proposal_elapsed.map(|elapsed| elapsed.as_millis()),
            "strict delivery applied slowly"
        );
    } else {
        debug!(
            topic = %topic,
            op_id_hi = buf.op_id.0,
            op_id_lo = buf.op_id.1,
            ts_final = buf.ts_final,
            version,
            buffered_for_ms = buffered_for.as_millis(),
            apply_elapsed_ms = apply_elapsed.as_millis(),
            local_proposal_elapsed_ms = ?local_proposal_elapsed.map(|elapsed| elapsed.as_millis()),
            "strict delivery applied"
        );
    }
}

fn run_gc_pass<R: StrictReplicable>(rt: &Arc<StrictRuntime<R>>) {
    let now = Instant::now();
    let propose_ttl = rt.cfg.propose_ttl();
    let wakers = {
        let mut s = rt.state.lock();
        s.gc_stale_proposals(now, propose_ttl)
    };
    for w in wakers {
        let _ = w.send(Err(ReplicationError::ProposeTimeout(propose_ttl)));
    }
    // Recovery-related GC: drop ancient pending Proposes (we're past the
    // window where any takeover would still be useful), drop committed
    // ts_final entries that have been delivered everywhere, and drop
    // hung in-progress recoveries that never reached quorum.
    {
        let alive: HashSet<NodeIdentifier> = rt
            .net
            .alive_members()
            .into_iter()
            .chain([rt.self_id])
            .collect();
        let mut s = rt.state.lock();
        let _dropped = s.gc_stale_pending_proposes(now, rt.cfg.pending_propose_ttl(), &alive);
        s.gc_committed_ts_final();
    }
    {
        let mut recoveries = rt.recoveries.lock();
        let recovery_ttl = rt.cfg.recovery_ttl();
        recoveries.retain(|_, rec| now.duration_since(rec.started_at) < recovery_ttl);
    }
}

fn spawn_clock_tick_loop<R: StrictReplicable>(rt: Arc<StrictRuntime<R>>) {
    let weak = {
        let rt = rt;
        Arc::downgrade(&rt)
    };
    tokio::spawn(async move {
        let Some(rt) = weak.upgrade() else {
            return;
        };
        loop {
            tokio::select! {
                _ = rt.shutdown.cancelled() => return,
                _ = rt.clock_tick_signal.notified() => {}
            }
            loop {
                // Every wake publishes at least one fresh local clock. The
                // local commit buffer may have drained already, but peers can
                // still be waiting for this node's clock to cross their
                // delivery high-water.
                emit_clock_tick(&rt).await;
                let mut last_interval = rt.current_clock_tick_interval();
                for _ in 1..CLOCK_TICK_ACTIVE_BURST_TICKS {
                    if !rt.clock_tick_needed() {
                        break;
                    }
                    if !sleep_or_shutdown(&rt, last_interval).await {
                        return;
                    }
                    emit_clock_tick(&rt).await;
                    last_interval = rt.current_clock_tick_interval();
                }
                if !rt.clock_tick_needed() {
                    break;
                }
                let cooldown = clock_tick_burst_cooldown(last_interval, &rt.cfg);
                tokio::select! {
                    _ = rt.shutdown.cancelled() => return,
                    _ = rt.clock_tick_signal.notified() => {},
                    _ = tokio::time::sleep(cooldown) => {},
                }
            }
        }
    });
}

impl<R: StrictReplicable> StrictRuntime<R> {
    fn current_clock_tick_interval(&self) -> Duration {
        // Recompute every time: LSDB RTT measurements drift with network
        // conditions, and clock bursts should follow current link latency.
        let samples = self.net.edge_rtt_snapshot();
        p95_clock_tick_interval(&samples, &self.cfg)
    }

    fn clock_tick_needed(&self) -> bool {
        let alive = delivery_members(self.net.as_ref(), self.self_id);
        let state = self.state.lock();
        clock_tick_needed_for_state(&state, self.self_id, &alive)
    }
}

fn log_buffered_commit(topic: &str, log: BufferedCommitLog) {
    debug!(
        topic = %topic,
        source = log.source,
        from = ?log.from,
        coord_node = ?log.coord_node,
        op_id_hi = log.op_id.0,
        op_id_lo = log.op_id.1,
        ts_final = log.ts_final,
        clock_now = log.clock_now,
        op_bytes = log.op_bytes,
        commit_buffer_len = log.commit_buffer_len,
        pending_local_proposals = log.pending_local_proposals,
        pending_remote_proposes = log.pending_remote_proposes,
        "strict commit buffered"
    );
}

fn log_accepted_proposal(topic: &str, op_id: OpId, accepted: &AcceptedProposal) {
    if accepted.elapsed >= STRICT_REPLICATION_SLOW_STAGE {
        warn!(
            topic = %topic,
            op_id_hi = op_id.0,
            op_id_lo = op_id.1,
            elapsed_ms = accepted.elapsed.as_millis(),
            ack_count = accepted.ack_count,
            target_count = accepted.target_count,
            fast_quorum = accepted.fast_quorum,
            ts_final = accepted.ts_final,
            clock_now = accepted.clock_now,
            op_bytes = accepted.op_bytes,
            commit_buffer_len = accepted.commit_buffer_len,
            pending_local_proposals = accepted.pending_local_proposals,
            pending_remote_proposes = accepted.pending_remote_proposes,
            "strict proposal accepted slowly"
        );
    } else {
        debug!(
            topic = %topic,
            op_id_hi = op_id.0,
            op_id_lo = op_id.1,
            elapsed_ms = accepted.elapsed.as_millis(),
            ack_count = accepted.ack_count,
            target_count = accepted.target_count,
            fast_quorum = accepted.fast_quorum,
            ts_final = accepted.ts_final,
            clock_now = accepted.clock_now,
            commit_buffer_len = accepted.commit_buffer_len,
            pending_local_proposals = accepted.pending_local_proposals,
            pending_remote_proposes = accepted.pending_remote_proposes,
            "strict proposal accepted"
        );
    }
}

fn clock_tick_needed_for_state(
    state: &StrictState,
    self_id: NodeIdentifier,
    alive: &[NodeIdentifier],
) -> bool {
    if !state.commit_buffer.is_empty() {
        return true;
    }
    alive
        .iter()
        .filter(|node| **node != self_id)
        .any(|node| !state.peer_clocks.contains_key(node))
}

async fn emit_clock_tick<R: StrictReplicable>(rt: &Arc<StrictRuntime<R>>) {
    let clock = {
        let mut s = rt.state.lock();
        advance_clock_for_tick(&mut s, rt.self_id)
    };
    let body = StrictBody::ClockTick(StrictClockTick {
        src_node: rt.self_id as u32,
        src_clock: clock,
    });
    if let Err(e) = rt.net.send_broadcast(&rt.topic, body).await {
        trace!(error=%e, "clock tick broadcast failed");
    }
}

async fn sleep_or_shutdown<R: StrictReplicable>(
    rt: &Arc<StrictRuntime<R>>,
    duration: Duration,
) -> bool {
    tokio::select! {
        _ = rt.shutdown.cancelled() => false,
        _ = tokio::time::sleep(duration) => true,
    }
}

fn clock_tick_burst_cooldown(interval: Duration, cfg: &ReplicationConfig) -> Duration {
    interval
        .checked_mul(CLOCK_TICK_BURST_COOLDOWN_MULTIPLIER)
        .unwrap_or_else(|| cfg.max_clock_tick())
        .clamp(cfg.min_clock_tick(), cfg.max_clock_tick())
}

fn advance_clock_for_tick(state: &mut StrictState, self_id: NodeIdentifier) -> u64 {
    let clock = state.tick_clock();
    // Keep our own peer_clocks slot in sync.
    state.peer_clocks.insert(self_id, clock);
    clock
}

/// Periodic catchup-bootstrap retry loop. Runs while a history election is
/// pending, and also keeps an idle watch on alive-set expansion so partition
/// heals that do not emit `Joined`/`Restarted` still trigger election.
fn spawn_bootstrap_retry_loop<R: StrictReplicable>(rt: Arc<StrictRuntime<R>>) {
    let weak = Arc::downgrade(&rt);
    drop(rt);
    tokio::spawn(async move {
        let Some(rt) = weak.upgrade() else {
            return;
        };
        let interval = rt.cfg.strict_bootstrap_retry_interval();
        loop {
            let peers = bootstrap_reachable_peers(rt.net.as_ref(), rt.self_id);
            let should_probe = {
                let mut state = rt.state.lock();
                state.observe_history_alive_peers(peers.iter().copied());
                if state.history_election_timed_out(Instant::now(), interval.saturating_mul(5)) {
                    state.request_history_election();
                }
                state.can_start_history_election()
            };
            if should_probe {
                rt.try_bootstrap_catchup().await;
            }
            tokio::select! {
                _ = rt.shutdown.cancelled() => return,
                _ = tokio::time::sleep(interval) => {}
            }
        }
    });
}

fn spawn_steady_state_catchup_loop<R: StrictReplicable>(rt: Arc<StrictRuntime<R>>) {
    let weak = Arc::downgrade(&rt);
    drop(rt);
    tokio::spawn(async move {
        let Some(rt) = weak.upgrade() else {
            return;
        };
        let mut ticker = tokio::time::interval(rt.cfg.strict_steady_state_catchup_interval());
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = rt.shutdown.cancelled() => return,
                _ = ticker.tick() => {
                    request_steady_state_catchup(&rt).await;
                }
            }
        }
    });
}

async fn request_steady_state_catchup<R: StrictReplicable>(rt: &Arc<StrictRuntime<R>>) {
    if rt.state.lock().history_election_blocks_steady_state() {
        return;
    }
    let alive = rt.net.alive_members();
    let mut peers: Vec<NodeIdentifier> = alive
        .into_iter()
        .filter(|node| *node != rt.self_id && rt.net.has_route(*node, ServiceLevel::Reliable))
        .collect();
    if peers.is_empty() {
        return;
    }
    let dst = {
        let mut rng = rand::rng();
        peers.shuffle(&mut rng);
        peers[0]
    };
    let req = StrictCatchupReq {
        src_node: rt.self_id as u32,
        since_version: rt.repo.current_version(),
        chunk_token: 0,
        force_snapshot: false,
        history_probe_only: false,
    };
    metrics::record_catchup_request(CatchupMode::Strict);
    let _ = rt
        .net
        .send_unicast(dst, &rt.topic, StrictBody::CatchupReq(req))
        .await;
}

// ---------- Helpers ----------

#[inline]
pub(crate) fn node_from_u32(v: u32) -> Option<NodeIdentifier> {
    if v <= u16::MAX as u32 {
        Some(v as NodeIdentifier)
    } else {
        None
    }
}

// ---------- Unit tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replications::test_support::{CountingStrictRepo, MockNet};

    fn strict_probe_resp(
        node: NodeIdentifier,
        version: u64,
        freshness: i64,
        runtime_started_at: u64,
    ) -> StrictCatchupResp {
        StrictCatchupResp {
            snapshot_version: 0,
            snapshot_msgpack: Bytes::new(),
            ops: Vec::new(),
            has_more: false,
            next_chunk_token: 0,
            too_old_use_snapshot: false,
            history_version: version,
            history_freshness: freshness,
            runtime_started_at,
            history_node: u32::from(node),
        }
    }

    fn strict_snapshot_resp(
        rank: HistoryRank,
        snapshot_version: u64,
        snapshot: Bytes,
    ) -> StrictCatchupResp {
        StrictCatchupResp {
            snapshot_version,
            snapshot_msgpack: snapshot,
            ops: Vec::new(),
            has_more: false,
            next_chunk_token: 0,
            too_old_use_snapshot: true,
            history_version: rank.version,
            history_freshness: rank.freshness,
            runtime_started_at: rank.runtime_started_at,
            history_node: u32::from(rank.node_id),
        }
    }

    #[test]
    fn p95_clock_tick_returns_fallback_when_empty() {
        let cfg = ReplicationConfig::default();
        assert_eq!(
            p95_clock_tick_interval(&[], &cfg),
            cfg.fallback_clock_tick()
        );
    }

    #[test]
    fn p95_clock_tick_picks_correct_index_via_nearest_rank() {
        let cfg = ReplicationConfig::default();
        // n=20, p=0.95: idx_one_based = ceil(19.0) = 19, idx = 18.
        // Samples 50..=1000ms by 50: samples[18] = 950ms.
        let samples: Vec<Duration> = (1..=20).map(|i| Duration::from_millis(i * 50)).collect();
        let p95 = p95_clock_tick_interval(&samples, &cfg);
        assert_eq!(p95, Duration::from_millis(950));
        // n=100, samples 1..=100ms: idx_one_based = 95, idx = 94.
        // samples[94] = 95ms, clamped up to min_clock_tick().
        let samples: Vec<Duration> = (1..=100).map(Duration::from_millis).collect();
        let p95 = p95_clock_tick_interval(&samples, &cfg);
        assert_eq!(p95, cfg.min_clock_tick());
    }

    #[test]
    fn p95_clock_tick_clamps_to_min() {
        let cfg = ReplicationConfig::default();
        // All samples below min_clock_tick() ⇒ result clamped up.
        let samples = vec![Duration::from_millis(5); 10];
        assert_eq!(
            p95_clock_tick_interval(&samples, &cfg),
            cfg.min_clock_tick()
        );
    }

    #[test]
    fn p95_clock_tick_clamps_to_max() {
        let cfg = ReplicationConfig::default();
        // All samples above max_clock_tick() ⇒ result clamped down.
        let samples = vec![Duration::from_secs(30); 10];
        assert_eq!(
            p95_clock_tick_interval(&samples, &cfg),
            cfg.max_clock_tick()
        );
    }

    #[test]
    fn p95_clock_tick_ignores_single_outlier_above_p95_index() {
        let cfg = ReplicationConfig::default();
        // 19 fast edges + 1 slow outlier. n=20, idx = 18.
        // After sort, samples[18] is the last fast edge, samples[19] is the
        // outlier. The outlier sits at p100, NOT p95 — so p95 == 150ms.
        let mut samples: Vec<Duration> = vec![Duration::from_millis(150); 19];
        samples.push(Duration::from_secs(2));
        let p95 = p95_clock_tick_interval(&samples, &cfg);
        assert_eq!(p95, Duration::from_millis(150));

        // 39 fast edges + 1 outlier (n=40). idx = 37, still in the fast block.
        let mut samples: Vec<Duration> = vec![Duration::from_millis(150); 39];
        samples.push(Duration::from_secs(2));
        let p95 = p95_clock_tick_interval(&samples, &cfg);
        assert_eq!(p95, Duration::from_millis(150));
    }

    #[test]
    fn fast_quorum_size_matches_paper() {
        // ceil(3n/4)
        assert_eq!(fast_quorum_size(0), 0);
        assert_eq!(fast_quorum_size(1), 1);
        assert_eq!(fast_quorum_size(2), 2);
        assert_eq!(fast_quorum_size(3), 3);
        assert_eq!(fast_quorum_size(4), 3);
        assert_eq!(fast_quorum_size(5), 4);
        assert_eq!(fast_quorum_size(8), 6);
        assert_eq!(fast_quorum_size(9), 7);
    }

    #[test]
    fn make_op_id_unique_per_node_and_counter() {
        let a = make_op_id(7, 100, 1);
        let b = make_op_id(7, 100, 2);
        let c = make_op_id(8, 100, 1);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.0, c.0 ^ ((7u64 ^ 8u64) << 48));
    }

    #[test]
    fn clock_advances_on_propose_receive() {
        let mut s = StrictState::new();
        s.clock = 5;
        let new_clock = s.advance_clock(10);
        assert_eq!(new_clock, 11);
        assert_eq!(s.clock, 11);
        // If peer's clock is lower, our clock just ticks.
        let new_clock = s.advance_clock(3);
        assert_eq!(new_clock, 12);
    }

    #[test]
    fn clock_tick_advances_local_clock_and_peer_slot() {
        let mut s = StrictState::new();
        s.clock = 7;
        s.peer_clocks.insert(10, 7);

        let tick = advance_clock_for_tick(&mut s, 10);

        assert_eq!(tick, 8);
        assert_eq!(s.clock, 8);
        assert_eq!(s.peer_clocks[&10], 8);
    }

    #[test]
    fn clock_tick_not_needed_when_idle_and_alive_peers_observed() {
        let mut s = StrictState::new();
        s.finish_history_election();
        s.peer_clocks.insert(20, 3);
        s.peer_clocks.insert(30, 5);

        assert!(!clock_tick_needed_for_state(&s, 10, &[10, 20, 30]));
    }

    #[test]
    fn clock_tick_needed_for_pending_commit_buffer() {
        let mut s = StrictState::new();
        s.finish_history_election();
        s.peer_clocks.insert(20, 3);
        s.buffer_commit((1, 1), 5, Bytes::new());

        assert!(clock_tick_needed_for_state(&s, 10, &[10, 20]));
    }

    #[test]
    fn clock_tick_needed_for_unobserved_alive_peer() {
        let mut s = StrictState::new();
        s.finish_history_election();
        s.peer_clocks.insert(20, 3);

        assert!(clock_tick_needed_for_state(&s, 10, &[10, 20, 30]));
    }

    #[test]
    fn clock_tick_not_needed_for_history_election_alone() {
        let s = StrictState::new();

        assert!(!clock_tick_needed_for_state(&s, 10, &[10]));
    }

    #[test]
    fn observe_peer_keeps_max_only() {
        let mut s = StrictState::new();
        s.observe_peer(1, 50);
        s.observe_peer(1, 30); // ignored
        s.observe_peer(1, 100);
        assert_eq!(s.peer_clocks[&1], 100);
    }

    #[test]
    fn commit_buffer_orders_by_ts_then_op_id() {
        let mut s = StrictState::new();
        s.buffer_commit((100, 1), 3, Bytes::from_static(b"a"));
        s.buffer_commit((50, 5), 1, Bytes::from_static(b"b"));
        s.buffer_commit((75, 3), 1, Bytes::from_static(b"c"));
        let drained = s.drain_deliverable(10);
        assert_eq!(drained.len(), 3);
        // Expected order: (1, (50,5)), (1, (75,3)), (3, (100,1))
        assert_eq!(drained[0].ts_final, 1);
        assert_eq!(drained[0].op_id, (50, 5));
        assert_eq!(drained[1].ts_final, 1);
        assert_eq!(drained[1].op_id, (75, 3));
        assert_eq!(drained[2].ts_final, 3);
        assert_eq!(drained[2].op_id, (100, 1));
    }

    #[test]
    fn drain_deliverable_respects_high_water() {
        let mut s = StrictState::new();
        s.buffer_commit((1, 1), 5, Bytes::new());
        s.buffer_commit((2, 1), 10, Bytes::new());
        let d = s.drain_deliverable(7);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].ts_final, 5);
        // The unread one stays.
        assert_eq!(s.commit_buffer.len(), 1);
    }

    #[test]
    fn earliest_uncommitted_proposal_ts_blocks_delivery_past_pending_work() {
        let mut s = StrictState::new();
        s.pending_proposes.insert(
            (1, 1),
            PendingPropose {
                coord_node: 20,
                op_msgpack: Bytes::new(),
                ts_local: 5,
                seen_at: Instant::now(),
            },
        );
        s.buffer_commit((2, 2), 6, Bytes::from_static(b"later"));

        let hw = s
            .earliest_uncommitted_proposal_ts()
            .map(|ts| 10.min(ts.saturating_sub(1)))
            .unwrap_or(10);
        let drained = s.drain_deliverable(hw);

        assert!(drained.is_empty());
        assert_eq!(s.commit_buffer.len(), 1);
        s.pending_proposes.clear();
        assert_eq!(s.drain_deliverable(10).len(), 1);
    }

    #[test]
    fn delivery_high_water_is_min_over_alive_set_plus_self() {
        let mut s = StrictState::new();
        s.clock = 7;
        s.peer_clocks.insert(10, 7);
        s.peer_clocks.insert(20, 5);
        s.peer_clocks.insert(30, 9);
        s.peer_clocks.insert(99, 0); // not in alive snapshot below
        let alive = vec![10u16, 20, 30];
        let hw = s.delivery_high_water(10, &alive);
        assert_eq!(hw, 5); // min(self=7, 20=5, 30=9)
    }

    #[test]
    fn delivery_blocked_when_alive_peer_has_no_clock_observation() {
        let mut s = StrictState::new();
        s.clock = 7;
        s.peer_clocks.insert(20, 5);
        // 30 alive but never observed => contributes 0.
        let alive = vec![10u16, 20, 30];
        let hw = s.delivery_high_water(10, &alive);
        assert_eq!(hw, 0);
    }

    #[test]
    fn delivery_members_exclude_alive_peers_without_live_routes() {
        let net = MockNet::new(10, vec![10, 20, 30]);
        net.set_live_reliable_routes([20]);

        let members = delivery_members(net.as_ref(), 10);

        assert_eq!(members, vec![10, 20]);
    }

    #[test]
    fn delivery_high_water_ignores_unroutable_unobserved_peer() {
        let net = MockNet::new(10, vec![10, 20, 30]);
        net.set_live_reliable_routes([20]);
        let alive = delivery_members(net.as_ref(), 10);
        let mut s = StrictState::new();
        s.clock = 7;
        s.peer_clocks.insert(20, 5);

        let hw = s.delivery_high_water(10, &alive);

        assert_eq!(hw, 5);
    }

    #[test]
    fn clock_tick_not_needed_for_unroutable_unobserved_peer() {
        let net = MockNet::new(10, vec![10, 20, 30]);
        net.set_live_reliable_routes([20]);
        let alive = delivery_members(net.as_ref(), 10);
        let mut s = StrictState::new();
        s.finish_history_election();
        s.peer_clocks.insert(20, 3);

        assert!(!clock_tick_needed_for_state(&s, 10, &alive));
    }

    #[test]
    fn fail_quorum_lost_when_alive_set_shrinks() {
        let mut s = StrictState::new();
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let (tx, _rx) = oneshot::channel();
        let mut target = HashSet::new();
        target.insert(10);
        target.insert(20);
        target.insert(30);
        target.insert(40);
        let op_id: OpId = (1, 1);
        s.proposals.insert(
            op_id,
            Proposal {
                op_msgpack: Bytes::new(),
                ts_propose: 1,
                acks: HashMap::new(),
                target_set: target,
                accepted_waker: None,
                waker: Some(tx),
                committed: false,
                started_at: Instant::now(),
                _permit: permit,
            },
        );
        // fast_quorum(4) = 3. Shrink alive to {10, 20} => still=2 < 3.
        let alive: HashSet<NodeIdentifier> = [10u16, 20].into_iter().collect();
        let wakers = s.fail_quorum_lost(&alive);
        assert_eq!(wakers.len(), 1);
        assert!(s.proposals.is_empty());
    }

    #[test]
    fn fail_quorum_lost_keeps_proposal_when_quorum_reachable() {
        let mut s = StrictState::new();
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let (tx, _rx) = oneshot::channel();
        let mut target = HashSet::new();
        target.insert(10);
        target.insert(20);
        target.insert(30);
        target.insert(40);
        let op_id: OpId = (2, 2);
        s.proposals.insert(
            op_id,
            Proposal {
                op_msgpack: Bytes::new(),
                ts_propose: 1,
                acks: HashMap::new(),
                target_set: target,
                accepted_waker: None,
                waker: Some(tx),
                committed: false,
                started_at: Instant::now(),
                _permit: permit,
            },
        );
        // 3 still alive, fq=3, ok.
        let alive: HashSet<NodeIdentifier> = [10u16, 20, 30].into_iter().collect();
        let wakers = s.fail_quorum_lost(&alive);
        assert_eq!(wakers.len(), 0);
        assert_eq!(s.proposals.len(), 1);
    }

    #[test]
    fn fail_quorum_lost_counts_already_received_acks() {
        let mut s = StrictState::new();
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let (tx, _rx) = oneshot::channel();
        let target = HashSet::from([10u16, 20, 30, 40]);
        let op_id: OpId = (4, 4);
        s.proposals.insert(
            op_id,
            Proposal {
                op_msgpack: Bytes::new(),
                ts_propose: 1,
                acks: HashMap::from([(10, 1), (30, 2)]),
                target_set: target,
                accepted_waker: None,
                waker: Some(tx),
                committed: false,
                started_at: Instant::now(),
                _permit: permit,
            },
        );

        // fast_quorum(4) = 3. Even though only {10, 20} are still alive,
        // ack from 30 was already received, so ack(10) + ack(30) +
        // reachable missing 20 can still reach quorum.
        let alive: HashSet<NodeIdentifier> = [10u16, 20].into_iter().collect();
        let wakers = s.fail_quorum_lost(&alive);

        assert_eq!(wakers.len(), 0);
        assert_eq!(s.proposals.len(), 1);
    }

    #[test]
    fn gc_stale_proposals_fires_after_ttl() {
        let cfg = ReplicationConfig::default();
        let mut s = StrictState::new();
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let (tx, _rx) = oneshot::channel();
        let mut target = HashSet::new();
        target.insert(10);
        let op_id: OpId = (3, 3);
        let stale = Instant::now() - cfg.propose_ttl() - Duration::from_secs(1);
        s.proposals.insert(
            op_id,
            Proposal {
                op_msgpack: Bytes::new(),
                ts_propose: 1,
                acks: HashMap::new(),
                target_set: target,
                accepted_waker: None,
                waker: Some(tx),
                committed: false,
                started_at: stale,
                _permit: permit,
            },
        );
        let wakers = s.gc_stale_proposals(Instant::now(), cfg.propose_ttl());
        assert_eq!(wakers.len(), 1);
        assert!(s.proposals.is_empty());
    }

    // ---- Slow-path recovery state-machine tests ----

    #[test]
    fn recovery_quorum_size_matches_majority() {
        assert_eq!(recovery_quorum_size(0), 0);
        assert_eq!(recovery_quorum_size(1), 1);
        assert_eq!(recovery_quorum_size(2), 2);
        assert_eq!(recovery_quorum_size(3), 2);
        assert_eq!(recovery_quorum_size(4), 3);
        assert_eq!(recovery_quorum_size(5), 3);
        assert_eq!(recovery_quorum_size(7), 4);
    }

    #[test]
    fn make_ballot_orders_by_node_then_attempt() {
        let a = make_ballot(2, 1);
        let b = make_ballot(2, 5);
        let c = make_ballot(3, 0);
        assert!(a < b, "same node, higher attempt wins");
        assert!(b < c, "higher node id outranks");
    }

    #[test]
    fn try_promise_is_monotonic() {
        let mut s = StrictState::new();
        let op_id: OpId = (1, 1);
        assert!(s.try_promise(op_id, 10));
        assert_eq!(s.recovery_promises[&op_id], 10);
        // Lower or equal ballots are rejected (no update, returns false).
        assert!(!s.try_promise(op_id, 5));
        assert!(!s.try_promise(op_id, 10));
        assert_eq!(s.recovery_promises[&op_id], 10);
        // Strictly higher succeeds.
        assert!(s.try_promise(op_id, 11));
        assert_eq!(s.recovery_promises[&op_id], 11);
    }

    #[test]
    fn mark_committed_dedups_repeat_calls() {
        let mut s = StrictState::new();
        let op_id: OpId = (7, 7);
        assert!(s.mark_committed(op_id, 100));
        assert_eq!(s.committed_ts_final[&op_id], 100);
        // Second call: false (already marked); does NOT overwrite ts_final.
        assert!(!s.mark_committed(op_id, 999));
        assert_eq!(s.committed_ts_final[&op_id], 100);
    }

    #[test]
    fn mark_committed_clears_pending_propose() {
        let mut s = StrictState::new();
        let op_id: OpId = (1, 2);
        s.record_pending_propose(op_id, 5, Bytes::from_static(b"x"), 33, Instant::now());
        assert!(s.pending_proposes.contains_key(&op_id));
        s.mark_committed(op_id, 50);
        assert!(!s.pending_proposes.contains_key(&op_id));
    }

    #[test]
    fn bootstrap_catchup_disabled_after_observed_strict_traffic() {
        let mut s = StrictState::new();
        assert!(s.can_bootstrap_catchup());

        s.record_pending_propose((1, 1), 10, Bytes::from_static(b"op"), 1, Instant::now());
        assert!(!s.can_bootstrap_catchup());
    }

    #[test]
    fn history_election_can_be_rearmed_after_prior_commits() {
        let mut s = StrictState::new();
        s.finish_history_election();
        s.committed_ids.insert((1, 1));
        s.committed_ts_final.insert((1, 1), 10);

        assert!(!s.can_bootstrap_catchup());
        s.request_history_election();

        assert!(s.can_bootstrap_catchup());
        assert!(s.history_election_pending());
    }

    #[test]
    fn history_election_rearm_stays_blocked_by_inflight_state() {
        let mut s = StrictState::new();
        s.finish_history_election();
        s.request_history_election();
        assert!(s.can_bootstrap_catchup());

        s.record_pending_propose((1, 1), 10, Bytes::from_static(b"op"), 1, Instant::now());
        assert!(!s.can_bootstrap_catchup());
    }

    #[tokio::test]
    async fn first_seen_commit_is_gossiped_with_local_clock() {
        let net = MockNet::new(2, vec![1, 2, 3, 4]);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            2,
            0,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&1234u64).unwrap());

        rt.recv_commit(
            1,
            StrictCommit {
                coord_node: 1,
                op_id_hi: 1,
                op_id_lo: 7,
                ts_final: 10,
                op_msgpack,
                src_clock: 9,
            },
        )
        .await;

        let captures = net.drain_captures();
        assert_eq!(captures.len(), 1);
        match &captures[0] {
            crate::replications::test_support::CapturedFrame::StrictMulticast {
                dsts,
                body,
                ..
            } => {
                assert_eq!(dsts, &[1, 3, 4]);
                match body {
                    StrictBody::Commit(commit) => {
                        assert_eq!(commit.coord_node, 1);
                        assert_eq!(commit.op_id_hi, 1);
                        assert_eq!(commit.op_id_lo, 7);
                        assert_eq!(commit.ts_final, 10);
                        assert_eq!(commit.src_clock, 10);
                    }
                    other => panic!("unexpected gossip body: {other:?}"),
                }
            }
            other => panic!("unexpected capture: {other:?}"),
        }
    }

    #[tokio::test]
    async fn bootstrap_catchup_only_targets_reliably_routable_peers() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_reliable_routes([3]);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            0,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        rt.try_bootstrap_catchup().await;

        let captures = net.captures();
        assert_eq!(captures.len(), 1);
        match &captures[0] {
            crate::replications::test_support::CapturedFrame::StrictUnicast {
                dst, body, ..
            } => {
                assert_eq!(*dst, 3);
                let StrictBody::CatchupReq(req) = body else {
                    panic!("expected catchup request, got {body:?}");
                };
                assert!(req.history_probe_only);
                assert!(!req.force_snapshot);
                assert_eq!(req.chunk_token, 0);
            }
            other => panic!("unexpected capture: {other:?}"),
        }
        assert_eq!(rt.state.lock().history_alive_peers, HashSet::from([3]));
    }

    #[tokio::test]
    async fn strict_history_probe_only_response_has_no_snapshot_or_ops() {
        let net = MockNet::new(2, vec![1, 2]);
        let repo = CountingStrictRepo::new();
        {
            let mut state = repo.state.lock();
            state.0 = 2;
            state.1 = vec![(1, 101, None), (2, 102, None)];
        }
        let rt = StrictRuntime::new(
            repo,
            2,
            77,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        rt.recv_catchup_req(
            1,
            StrictCatchupReq {
                src_node: 1,
                since_version: 0,
                chunk_token: HISTORY_ELECTION_SNAPSHOT_TOKEN,
                force_snapshot: true,
                history_probe_only: true,
            },
        )
        .await;

        let captures = net.drain_captures();
        assert_eq!(captures.len(), 1);
        match &captures[0] {
            crate::replications::test_support::CapturedFrame::StrictUnicast {
                dst, body, ..
            } => {
                assert_eq!(*dst, 1);
                let StrictBody::CatchupResp(resp) = body else {
                    panic!("expected catchup response, got {body:?}");
                };
                assert_eq!(resp.snapshot_msgpack.len(), 0);
                assert_eq!(resp.ops.len(), 0);
                assert!(!resp.has_more);
                assert!(!resp.too_old_use_snapshot);
                assert_eq!(resp.history_version, 2);
                assert_eq!(resp.runtime_started_at, 77);
                assert_eq!(resp.history_node, 2);
            }
            other => panic!("unexpected capture: {other:?}"),
        }
    }

    #[tokio::test]
    async fn strict_catchup_request_uses_chunk_token_as_continuation() {
        let net = MockNet::new(2, vec![1, 2]);
        let repo = CountingStrictRepo::new();
        {
            let mut state = repo.state.lock();
            state.0 = 5;
            state.1 = (1u64..=5)
                .map(|version| {
                    (
                        version,
                        100 + version,
                        Some(StrictLogMetadata {
                            op_id_hi: 7,
                            op_id_lo: version,
                            ts_final: version * 10,
                        }),
                    )
                })
                .collect();
        }
        let rt = StrictRuntime::new(
            repo,
            2,
            0,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default().with_strict_max_catchup_ops(2)),
        );

        rt.recv_catchup_req(
            1,
            StrictCatchupReq {
                src_node: 1,
                since_version: 0,
                chunk_token: 2,
                force_snapshot: false,
                history_probe_only: false,
            },
        )
        .await;

        let captures = net.drain_captures();
        assert_eq!(captures.len(), 1);
        match &captures[0] {
            crate::replications::test_support::CapturedFrame::StrictUnicast {
                dst, body, ..
            } => {
                assert_eq!(*dst, 1);
                let StrictBody::CatchupResp(resp) = body else {
                    panic!("expected catchup response, got {body:?}");
                };
                let versions: Vec<u64> = resp.ops.iter().map(|op| op.version).collect();
                assert_eq!(versions, vec![3, 4]);
                assert!(resp.has_more);
                assert_eq!(resp.next_chunk_token, 4);
            }
            other => panic!("unexpected capture: {other:?}"),
        }
    }

    #[tokio::test]
    async fn strict_catchup_followup_uses_response_token_when_repo_version_lags() {
        let net = MockNet::new(1, vec![1, 2]);
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo.clone(),
            1,
            0,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        rt.state.lock().finish_history_election();

        let ops: Vec<repl_proto::CatchupOp> = (1u64..=2)
            .map(|version| repl_proto::CatchupOp {
                version,
                op_msgpack: Bytes::from(rmp_serde::to_vec(&(200 + version)).unwrap()),
                strict_op_id_hi: 9,
                strict_op_id_lo: version,
                strict_ts_final: 100 + version,
            })
            .collect();

        rt.recv_catchup_resp(
            2,
            StrictCatchupResp {
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops,
                has_more: true,
                next_chunk_token: 2,
                too_old_use_snapshot: false,
                history_version: 2,
                history_freshness: 0,
                runtime_started_at: 0,
                history_node: 2,
            },
        )
        .await;

        assert_eq!(repo.current_version(), 0);
        assert_eq!(rt.state.lock().commit_buffer.len(), 2);

        let captures = net.drain_captures();
        assert_eq!(captures.len(), 1);
        match &captures[0] {
            crate::replications::test_support::CapturedFrame::StrictUnicast {
                dst, body, ..
            } => {
                assert_eq!(*dst, 2);
                let StrictBody::CatchupReq(req) = body else {
                    panic!("expected catchup request, got {body:?}");
                };
                assert_eq!(req.since_version, 2);
                assert_eq!(req.chunk_token, 2);
                assert!(!req.force_snapshot);
            }
            other => panic!("unexpected capture: {other:?}"),
        }
    }

    #[tokio::test]
    async fn strict_catchup_followup_targets_reliably_routable_peer() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_reliable_routes([3]);
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo,
            1,
            0,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        rt.state.lock().finish_history_election();

        rt.recv_catchup_resp(
            2,
            StrictCatchupResp {
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: vec![repl_proto::CatchupOp {
                    version: 1,
                    op_msgpack: Bytes::from(rmp_serde::to_vec(&201u64).unwrap()),
                    strict_op_id_hi: 9,
                    strict_op_id_lo: 1,
                    strict_ts_final: 101,
                }],
                has_more: true,
                next_chunk_token: 1,
                too_old_use_snapshot: false,
                history_version: 1,
                history_freshness: 0,
                runtime_started_at: 0,
                history_node: 2,
            },
        )
        .await;

        let captures = net.drain_captures();
        assert_eq!(captures.len(), 1);
        match &captures[0] {
            crate::replications::test_support::CapturedFrame::StrictUnicast {
                dst, body, ..
            } => {
                assert_eq!(*dst, 3);
                assert!(matches!(body, StrictBody::CatchupReq(_)));
            }
            other => panic!("unexpected capture: {other:?}"),
        }
    }

    #[test]
    fn history_rank_orders_by_version_freshness_runtime_then_node() {
        let base = HistoryRank {
            version: 10,
            freshness: 100,
            runtime_started_at: 50,
            node_id: 8,
        };

        assert!(
            HistoryRank {
                version: 11,
                ..base
            }
            .beats(base)
        );
        assert!(
            HistoryRank {
                freshness: 101,
                ..base
            }
            .beats(base)
        );
        assert!(
            HistoryRank {
                runtime_started_at: 49,
                ..base
            }
            .beats(base)
        );
        assert!(HistoryRank { node_id: 7, ..base }.beats(base));
        assert!(!HistoryRank { node_id: 9, ..base }.beats(base));
    }

    #[test]
    fn history_election_waits_for_all_peers_and_keeps_best_candidate() {
        let mut s = StrictState::new();
        s.begin_history_election([2, 3, 4]);
        let local_rank = HistoryRank {
            version: 8,
            freshness: 0,
            runtime_started_at: 100,
            node_id: 1,
        };

        let rank_from_3 = HistoryRank {
            version: 10,
            freshness: 200,
            runtime_started_at: 50,
            node_id: 3,
        };
        let rank_from_4 = HistoryRank {
            version: 10,
            freshness: 200,
            runtime_started_at: 50,
            node_id: 4,
        };
        let rank_from_2 = HistoryRank {
            version: 9,
            freshness: 999,
            runtime_started_at: 1,
            node_id: 2,
        };

        assert_eq!(
            s.record_history_probe_response(2, rank_from_2, local_rank),
            HistoryProbeResponseOutcome::Pending
        );
        assert_eq!(
            s.record_history_probe_response(4, rank_from_4, local_rank),
            HistoryProbeResponseOutcome::Pending
        );
        let outcome = s.record_history_probe_response(3, rank_from_3, local_rank);
        let HistoryProbeResponseOutcome::FetchSnapshot(request) = outcome else {
            panic!("last probe should elect a snapshot fetch, got {outcome:?}");
        };

        assert_eq!(request.peer(), 3);
        assert_eq!(request.expected_rank(), rank_from_3);
        assert!(s.history_election_pending());
        assert_eq!(s.history_election_fetching_snapshot(), Some(request));

        let outcome = s.record_history_snapshot_response(
            3,
            rank_from_3,
            local_rank,
            10,
            Bytes::from_static(b"node3"),
        );
        let HistorySnapshotResponseOutcome::Install(winner) = outcome else {
            panic!("winning snapshot should enter install phase, got {outcome:?}");
        };

        assert_eq!(winner.rank, rank_from_3);
        assert_eq!(winner.snapshot_version, 10);
        assert!(s.history_election_pending());
        assert!(s.history_election_installing());

        s.finish_history_election();
        assert!(!s.history_election_pending());
        assert!(!s.history_election_installing());
    }

    #[tokio::test]
    async fn strict_history_election_fetches_only_best_snapshot() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo,
            1,
            100,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        rt.try_bootstrap_catchup().await;

        let captures = net.drain_captures();
        assert_eq!(captures.len(), 2);
        let mut probe_dsts = Vec::new();
        for capture in &captures {
            let crate::replications::test_support::CapturedFrame::StrictUnicast {
                dst, body, ..
            } = capture
            else {
                panic!("unexpected capture: {capture:?}");
            };
            probe_dsts.push(*dst);
            let StrictBody::CatchupReq(req) = body else {
                panic!("expected catchup request, got {body:?}");
            };
            assert!(req.history_probe_only);
            assert!(!req.force_snapshot);
            assert_eq!(req.chunk_token, 0);
        }
        probe_dsts.sort_unstable();
        assert_eq!(probe_dsts, vec![2, 3]);

        rt.recv_catchup_resp(2, strict_probe_resp(2, 10, 100, 40))
            .await;
        assert!(net.drain_captures().is_empty());

        rt.recv_catchup_resp(3, strict_probe_resp(3, 8, 999, 1))
            .await;

        let captures = net.drain_captures();
        assert_eq!(captures.len(), 1);
        match &captures[0] {
            crate::replications::test_support::CapturedFrame::StrictUnicast {
                dst, body, ..
            } => {
                assert_eq!(*dst, 2);
                let StrictBody::CatchupReq(req) = body else {
                    panic!("expected catchup request, got {body:?}");
                };
                assert!(!req.history_probe_only);
                assert!(req.force_snapshot);
                assert_eq!(req.chunk_token, HISTORY_ELECTION_SNAPSHOT_TOKEN);
            }
            other => panic!("unexpected capture: {other:?}"),
        }
    }

    #[tokio::test]
    async fn strict_history_election_local_best_requests_no_snapshot() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        let repo = CountingStrictRepo::new();
        repo.state.lock().0 = 12;
        let rt = StrictRuntime::new(
            repo,
            1,
            100,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        rt.try_bootstrap_catchup().await;
        assert_eq!(net.drain_captures().len(), 2);

        rt.recv_catchup_resp(2, strict_probe_resp(2, 10, 100, 40))
            .await;
        rt.recv_catchup_resp(3, strict_probe_resp(3, 11, 100, 40))
            .await;

        assert!(net.drain_captures().is_empty());
        assert!(!rt.state.lock().history_election_pending());
    }

    #[tokio::test]
    async fn strict_history_election_ignores_non_winning_snapshot_response() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo.clone(),
            1,
            100,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        rt.try_bootstrap_catchup().await;
        net.drain_captures();
        rt.recv_catchup_resp(2, strict_probe_resp(2, 10, 100, 40))
            .await;
        rt.recv_catchup_resp(3, strict_probe_resp(3, 9, 100, 40))
            .await;
        let captures = net.drain_captures();
        assert_eq!(captures.len(), 1);

        let rank_from_3 = HistoryRank {
            version: 9,
            freshness: 100,
            runtime_started_at: 40,
            node_id: 3,
        };
        let snapshot = Bytes::from(rmp_serde::to_vec(&vec![(9u64, 909u64)]).unwrap());
        rt.recv_catchup_resp(3, strict_snapshot_resp(rank_from_3, 9, snapshot))
            .await;

        assert_eq!(repo.current_version(), 0);
        assert_eq!(repo.log(), Vec::<(u64, u64)>::new());
        let fetching = rt
            .state
            .lock()
            .history_election_fetching_snapshot()
            .expect("winning fetch should still be in progress");
        assert_eq!(fetching.peer(), 2);
        assert!(net.drain_captures().is_empty());
    }

    #[tokio::test]
    async fn bootstrap_send_failures_keep_retry_throttle() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.fail_strict_unicasts_to([2, 3]);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            100,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        rt.try_bootstrap_catchup().await;

        assert!(rt.last_bootstrap_attempt.lock().is_some());
        assert!(rt.state.lock().history_election_pending());
        assert!(!rt.state.lock().history_election_active());
        assert!(net.drain_captures().is_empty());
    }

    #[tokio::test]
    async fn steady_state_catchup_stands_down_while_history_election_is_pending() {
        let net = MockNet::new(1, vec![1, 2]);
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo,
            1,
            0,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        request_steady_state_catchup(&rt).await;

        assert!(
            net.drain_captures().is_empty(),
            "ordinary catchup must not race a pending history election"
        );
    }

    #[tokio::test]
    async fn non_snapshot_catchup_response_is_ignored_during_history_election() {
        let net = MockNet::new(1, vec![1, 2]);
        let repo = CountingStrictRepo::new();
        repo.apply_committed(1, 101).await;
        let rt = StrictRuntime::new(
            repo.clone(),
            1,
            0,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        rt.recv_catchup_resp(
            2,
            StrictCatchupResp {
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: vec![repl_proto::CatchupOp {
                    version: 1,
                    op_msgpack: Bytes::from(rmp_serde::to_vec(&201u64).unwrap()),
                    strict_op_id_hi: 0,
                    strict_op_id_lo: 0,
                    strict_ts_final: 0,
                }],
                has_more: false,
                next_chunk_token: 1,
                too_old_use_snapshot: false,
                history_version: 1,
                history_freshness: 0,
                runtime_started_at: 0,
                history_node: 2,
            },
        )
        .await;

        assert_eq!(repo.current_version(), 1);
        assert_eq!(repo.log(), vec![(1, 101)]);
        assert!(rt.state.lock().history_election_pending());
        assert!(net.drain_captures().is_empty());
    }

    #[tokio::test]
    async fn empty_repo_accepts_log_catchup_during_startup_history_election() {
        let net = MockNet::new(1, vec![1, 2]);
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo.clone(),
            1,
            0,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        rt.recv_catchup_resp(
            2,
            StrictCatchupResp {
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: vec![
                    repl_proto::CatchupOp {
                        version: 1,
                        op_msgpack: Bytes::from(rmp_serde::to_vec(&201u64).unwrap()),
                        strict_op_id_hi: 0,
                        strict_op_id_lo: 0,
                        strict_ts_final: 0,
                    },
                    repl_proto::CatchupOp {
                        version: 2,
                        op_msgpack: Bytes::from(rmp_serde::to_vec(&202u64).unwrap()),
                        strict_op_id_hi: 0,
                        strict_op_id_lo: 0,
                        strict_ts_final: 0,
                    },
                ],
                has_more: false,
                next_chunk_token: 2,
                too_old_use_snapshot: false,
                history_version: 2,
                history_freshness: 0,
                runtime_started_at: 0,
                history_node: 2,
            },
        )
        .await;

        assert_eq!(repo.log(), vec![(1, 201), (2, 202)]);
        assert!(rt.state.lock().history_election_pending());
    }

    #[test]
    fn gc_stale_pending_proposes_drops_old_entries() {
        let cfg = ReplicationConfig::default();
        let mut s = StrictState::new();
        let stale_at = Instant::now() - cfg.pending_propose_ttl() - Duration::from_secs(1);
        let fresh_at = Instant::now();
        s.record_pending_propose((1, 1), 5, Bytes::new(), 1, stale_at);
        s.record_pending_propose((2, 2), 5, Bytes::new(), 2, fresh_at);
        let alive = HashSet::new();
        let dropped =
            s.gc_stale_pending_proposes(Instant::now(), cfg.pending_propose_ttl(), &alive);
        assert_eq!(dropped, vec![(1, 1)]);
        assert_eq!(s.pending_proposes.len(), 1);
        assert!(s.pending_proposes.contains_key(&(2, 2)));
    }

    #[test]
    fn gc_stale_pending_proposes_keeps_entries_from_alive_coord() {
        let cfg = ReplicationConfig::default();
        let mut s = StrictState::new();
        let stale_at = Instant::now() - cfg.pending_propose_ttl() - Duration::from_secs(1);
        s.record_pending_propose((1, 1), 5, Bytes::new(), 40, stale_at);
        let alive = HashSet::from([5u16]);

        let dropped =
            s.gc_stale_pending_proposes(Instant::now(), cfg.pending_propose_ttl(), &alive);

        assert!(dropped.is_empty());
        assert!(s.pending_proposes.contains_key(&(1, 1)));
    }

    #[test]
    fn gc_stale_pending_proposes_keeps_ordering_barriers_for_later_commits() {
        let cfg = ReplicationConfig::default();
        let mut s = StrictState::new();
        let stale_at = Instant::now() - cfg.pending_propose_ttl() - Duration::from_secs(1);
        s.record_pending_propose((1, 1), 5, Bytes::new(), 40, stale_at);
        s.buffer_commit((2, 2), 50, Bytes::new());
        let alive = HashSet::new();

        let dropped =
            s.gc_stale_pending_proposes(Instant::now(), cfg.pending_propose_ttl(), &alive);

        assert!(dropped.is_empty());
        assert!(s.pending_proposes.contains_key(&(1, 1)));
    }

    #[test]
    fn gc_committed_ts_final_drops_below_high_water() {
        let mut s = StrictState::new();
        s.delivered_high_water = 50;
        s.committed_ts_final.insert((1, 1), 30); // below: drop
        s.committed_ts_final.insert((2, 2), 50); // exactly at: keep
        s.committed_ts_final.insert((3, 3), 100); // above: keep
        s.gc_committed_ts_final();
        assert!(!s.committed_ts_final.contains_key(&(1, 1)));
        assert!(s.committed_ts_final.contains_key(&(2, 2)));
        assert!(s.committed_ts_final.contains_key(&(3, 3)));
    }
}
