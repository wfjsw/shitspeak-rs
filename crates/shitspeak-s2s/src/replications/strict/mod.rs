//! Strict (Tempo) replication: leader-less, multi-writer, total-order
//! broadcast over the L2 overlay.
//!
//! See `runtime.rs` for the state machine. This file holds the public
//! `StrictReplicable` trait, `StrictHandle` (caller-facing), and
//! shared types.

pub(crate) mod bulk_pacing;
pub mod catchup;
pub(crate) mod history_v3;
pub mod propose;
pub(crate) mod retry_v3;
pub mod runtime;
pub(crate) mod session_reducer;
pub(crate) mod sync_v3;
pub(crate) mod terminal_journal;
pub(crate) mod terminal_journal_sqlite;

#[cfg(test)]
mod checkpoint_design_tests;
#[cfg(test)]
mod sync_v3_tests;
#[cfg(test)]
mod terminal_journal_sqlite_tests;

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::oneshot;

use super::error::ReplicationError;

/// What the responder hands back when asked for ops in (since, current].
#[derive(Clone, Debug)]
pub enum LogSlice<Op> {
    /// Caller can satisfy from the in-memory log.
    Available(Vec<(u64, Op)>),
    /// Requester is too far behind; a fresh snapshot is needed.
    TooOld,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryMetadata {
    pub version: u64,
    pub freshness: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StrictLogMetadata {
    pub op_id_hi: u64,
    pub op_id_lo: u64,
    pub ts_final: u64,
}

#[derive(Clone, Debug)]
pub struct StrictLogEntry<Op> {
    pub op: Op,
    pub metadata: Option<StrictLogMetadata>,
}

/// Failure while capturing or installing a strict-replication snapshot.
///
/// Snapshot failures are recoverable protocol events: catchup must retain
/// its history election and retry rather than treating a partial or rejected
/// snapshot as installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StrictSnapshotErrorKind {
    Semantic,
    Durability,
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("strict snapshot failed: {message}")]
pub struct StrictSnapshotError {
    message: String,
    kind: StrictSnapshotErrorKind,
}

impl StrictSnapshotError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: StrictSnapshotErrorKind::Semantic,
        }
    }

    /// Construct an error proving that this replica could not durably install
    /// a snapshot. The strict runtime withdraws its advertised protocol
    /// capability for this process when it observes this result.
    pub fn durability_failure(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: StrictSnapshotErrorKind::Durability,
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn is_durability_failure(&self) -> bool {
        self.kind == StrictSnapshotErrorKind::Durability
    }
}

/// Result of passing a terminally committed operation through the
/// repository's operation-id idempotency boundary.
///
/// A v1 strict implementation must retain the operation id together with
/// the application state. After a crash, the terminal journal deliberately
/// replays the committed value; `AlreadyApplied` is therefore a successful
/// delivery result, not an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrictCommitApplyOutcome {
    Applied,
    AlreadyApplied,
    Failed,
}

impl<Op> StrictLogEntry<Op> {
    pub fn new(op: Op) -> Self {
        Self { op, metadata: None }
    }

    pub fn with_metadata(op: Op, metadata: StrictLogMetadata) -> Self {
        Self {
            op,
            metadata: Some(metadata),
        }
    }
}

/// Repository-side contract for the strict (Tempo) replication mode.
///
/// # Apply ordering
///
/// `apply_committed` is invoked by the runtime at the **delivery** stage of
/// the Tempo protocol — after the op has cleared fast-quorum acks,
/// `ts_final` has been decided, and the entry has been popped from the
/// commit buffer in `(ts_final, op_id)` order. The proposer is not
/// privileged: locally proposed ops follow the same delivery rule. Do NOT
/// pre-apply from a `propose` wrapper — doing so breaks total order across
/// replicas.
///
/// # Snapshot consistency
///
/// `snapshot` MUST be atomic: the returned `version` MUST equal
/// `current_version()` at the moment the snapshot bytes were captured.
/// Implementations are expected to briefly quiesce (e.g. grab their
/// internal `RwLock`) while reading.
#[async_trait]
pub trait StrictReplicable: Send + Sync + 'static {
    type Op: Serialize + DeserializeOwned + Send + Sync + Clone + 'static;

    /// Highest strict protocol version this repository can apply safely.
    ///
    /// Version 1 requires an atomic operation-id ledger that survives the
    /// repository's normal snapshot/recovery path. The conservative default
    /// keeps generic implementations on the legacy protocol until they opt
    /// into that contract.
    fn strict_replication_protocol_version(&self) -> u32 {
        0
    }

    /// Legacy repository-owned operation ids used once while upgrading the
    /// delivery ledger into durable S2S journal records.
    fn legacy_applied_operation_ids(&self) -> Vec<(u64, u64)> {
        Vec::new()
    }

    /// Latest applied version.
    fn current_version(&self) -> u64;

    /// Metadata used during startup history election. Higher `version`
    /// wins, then higher `freshness`; runtime age and node id are supplied
    /// by the replication runtime.
    fn history_metadata(&self) -> HistoryMetadata {
        HistoryMetadata {
            version: self.current_version(),
            freshness: 0,
        }
    }

    /// Atomically capture a snapshot. The returned `version` matches the
    /// applied state captured by `msgpack_bytes`.
    ///
    /// Capture errors must be reported rather than represented as an empty
    /// snapshot: a responder will fail closed and let the requester retry.
    fn snapshot(&self) -> Result<(u64, Bytes), StrictSnapshotError>;

    /// Ops with version in `(since, current_version]`. Returns
    /// `LogSlice::TooOld` when the structure can no longer satisfy from its
    /// in-memory log; the runtime will fall back to a snapshot.
    fn log_since(&self, since: u64) -> LogSlice<StrictLogEntry<Self::Op>>;

    /// Apply a committed op. Called by the runtime on the delivery path,
    /// in `(ts_final, op_id)` order, with monotonically increasing
    /// `version`.
    async fn apply_committed(&self, version: u64, op: Self::Op);

    async fn apply_committed_with_metadata(
        &self,
        version: u64,
        op: Self::Op,
        _metadata: Option<StrictLogMetadata>,
    ) {
        self.apply_committed(version, op).await;
    }

    /// Apply a strict operation once using its stable operation id.
    ///
    /// Implementations advertising protocol v1 must override this method
    /// with an atomic, durable operation-id claim. The default preserves the
    /// legacy trait contract for implementations which remain on v0.
    async fn apply_committed_once(
        &self,
        version: u64,
        op: Self::Op,
        metadata: StrictLogMetadata,
    ) -> StrictCommitApplyOutcome {
        self.apply_committed_with_metadata(version, op, Some(metadata))
            .await;
        StrictCommitApplyOutcome::Applied
    }

    /// Replace local state with the supplied snapshot.
    ///
    /// The implementation must not report success until the snapshot is
    /// durably installed. On failure, the runtime keeps the history election
    /// pending and retries from a fresh source.
    ///
    /// A v2-capable implementation must reject a replacement snapshot whose
    /// strict operation-id ledger omits any locally durable terminal operation
    /// that the replacement could erase. It must not merge that local id into
    /// the incoming ledger: doing so would turn a required replay into an
    /// irreversible `AlreadyApplied` result while the operation's state is
    /// absent.
    async fn install_snapshot(
        &self,
        version: u64,
        snapshot: Bytes,
    ) -> Result<(), StrictSnapshotError>;
}

/// Caller-facing handle for a strict topic. Cloning is cheap (internally an
/// `Arc`).
pub struct StrictHandle<R: StrictReplicable> {
    pub(crate) runtime: Arc<runtime::StrictRuntime<R>>,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone)]
pub struct StrictDebugState {
    election_pending: bool,
    election_active: bool,
    can_start_election: bool,
    history_probe_pending_peers: Option<usize>,
    history_alive_peers: usize,
    clock: u64,
    earliest_pending: Option<((u64, u64), u64, shitspeak_core::NodeIdentifier)>,
    earliest_pending_promise_ballot: Option<u64>,
    earliest_pending_protocol_version: Option<u32>,
    earliest_buffered: Option<((u64, u64), u64)>,
    /// Oldest local proposal and its phase-one/phase-two quorum progress:
    /// `(op_id, propose_acks, positive_accept_acks, targets, accept_started, committed)`.
    local_proposal_quorum: Option<((u64, u64), usize, usize, usize, bool, bool)>,
    local_proposal_acks: Option<Vec<(shitspeak_core::NodeIdentifier, u64)>>,
    local_proposal_invalid_targets: Option<Vec<shitspeak_core::NodeIdentifier>>,
    local_proposal_accept_ack_count: Option<usize>,
    local_proposal_accept_acks: Option<Vec<(shitspeak_core::NodeIdentifier, bool)>>,
    local_proposal_phase_two_retry: Option<(usize, usize)>,
    accepted_values: Vec<((u64, u64), u64)>,
    local_proposals: usize,
    pending_proposes: usize,
    buffered_commits: usize,
    unresolved_promises: usize,
    unresolved_terminal_promises: usize,
    admitted_peers: usize,
    awaiting_local_cut_peers: usize,
    awaiting_peer_proof_peers: usize,
    pending_admission_proofs: Vec<(shitspeak_core::NodeIdentifier, bool, bool)>,
    highest_admission_barrier: u64,
    active_recoveries: usize,
}

#[cfg(any(test, feature = "test-support"))]
impl StrictDebugState {
    pub fn election_pending(&self) -> bool {
        self.election_pending
    }
    pub fn election_active(&self) -> bool {
        self.election_active
    }
    pub fn can_start_election(&self) -> bool {
        self.can_start_election
    }
    pub fn history_probe_pending_peers(&self) -> Option<usize> {
        self.history_probe_pending_peers
    }
    pub fn history_alive_peers(&self) -> usize {
        self.history_alive_peers
    }
    pub fn clock(&self) -> u64 {
        self.clock
    }
    pub fn earliest_pending(&self) -> Option<((u64, u64), u64, shitspeak_core::NodeIdentifier)> {
        self.earliest_pending
    }
    pub fn earliest_pending_promise_ballot(&self) -> Option<u64> {
        self.earliest_pending_promise_ballot
    }
    pub fn earliest_pending_protocol_version(&self) -> Option<u32> {
        self.earliest_pending_protocol_version
    }
    pub fn earliest_buffered(&self) -> Option<((u64, u64), u64)> {
        self.earliest_buffered
    }
    /// Oldest local proposal's phase-one and phase-two quorum progress:
    /// `(op_id, propose_acks, positive_accept_acks, targets, accept_started, committed)`.
    pub fn local_proposal_quorum(&self) -> Option<((u64, u64), usize, usize, usize, bool, bool)> {
        self.local_proposal_quorum
    }
    pub fn local_proposal_acks(&self) -> Option<&[(shitspeak_core::NodeIdentifier, u64)]> {
        self.local_proposal_acks.as_deref()
    }
    pub fn local_proposal_invalid_targets(&self) -> Option<&[shitspeak_core::NodeIdentifier]> {
        self.local_proposal_invalid_targets.as_deref()
    }
    pub fn local_proposal_accept_ack_count(&self) -> Option<usize> {
        self.local_proposal_accept_ack_count
    }
    pub fn local_proposal_accept_acks(&self) -> Option<&[(shitspeak_core::NodeIdentifier, bool)]> {
        self.local_proposal_accept_acks.as_deref()
    }
    pub fn local_proposal_phase_two_retry(&self) -> Option<(usize, usize)> {
        self.local_proposal_phase_two_retry
    }
    pub fn accepted_values(&self) -> &[((u64, u64), u64)] {
        &self.accepted_values
    }
    pub fn local_proposals(&self) -> usize {
        self.local_proposals
    }
    pub fn pending_proposes(&self) -> usize {
        self.pending_proposes
    }
    pub fn buffered_commits(&self) -> usize {
        self.buffered_commits
    }
    pub fn unresolved_promises(&self) -> usize {
        self.unresolved_promises
    }
    pub fn unresolved_terminal_promises(&self) -> usize {
        self.unresolved_terminal_promises
    }
    pub fn admitted_peers(&self) -> usize {
        self.admitted_peers
    }
    pub fn awaiting_local_cut_peers(&self) -> usize {
        self.awaiting_local_cut_peers
    }
    pub fn awaiting_peer_proof_peers(&self) -> usize {
        self.awaiting_peer_proof_peers
    }
    pub fn pending_admission_proofs(&self) -> &[(shitspeak_core::NodeIdentifier, bool, bool)] {
        &self.pending_admission_proofs
    }
    pub fn highest_admission_barrier(&self) -> u64 {
        self.highest_admission_barrier
    }
    pub fn active_recoveries(&self) -> usize {
        self.active_recoveries
    }
}

/// In-flight strict proposal with separate accepted and delivered stages.
pub struct StrictProposal {
    accepted: Option<oneshot::Receiver<()>>,
    delivered: oneshot::Receiver<Result<u64, ReplicationError>>,
}

impl StrictProposal {
    /// Resolves when the local coordinator has gathered fast-quorum acks
    /// and decided the proposal's final timestamp.
    pub async fn accepted(&mut self) -> Result<(), ReplicationError> {
        let Some(accepted) = self.accepted.take() else {
            return Ok(());
        };
        accepted.await.map_err(|_| ReplicationError::Shutdown)
    }

    /// Take the accepted-stage receiver for callers that need to forward it
    /// while independently awaiting delivery.
    pub fn take_accepted_receiver(&mut self) -> Option<oneshot::Receiver<()>> {
        self.accepted.take()
    }

    /// Resolves once the operation has been delivered locally
    /// (post-`apply_committed`).
    pub async fn delivered(self) -> Result<u64, ReplicationError> {
        match self.delivered.await {
            Ok(res) => res,
            Err(_) => Err(ReplicationError::Shutdown),
        }
    }
}

impl<R: StrictReplicable> Clone for StrictHandle<R> {
    fn clone(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
        }
    }
}

impl<R: StrictReplicable> StrictHandle<R> {
    pub fn with_runtime(runtime: Arc<runtime::StrictRuntime<R>>) -> Self {
        Self { runtime }
    }

    /// Propose an op. Resolves once the op has been delivered locally
    /// (post-`apply_committed`). The returned `u64` is the `version` the
    /// op was applied at.
    pub async fn propose(&self, op: R::Op) -> Result<u64, ReplicationError> {
        let (tx, rx) = oneshot::channel();
        self.runtime.clone().begin_propose(op, tx).await?;
        match rx.await {
            Ok(res) => res,
            Err(_) => Err(ReplicationError::Shutdown),
        }
    }

    /// Begin an op proposal and return handles for both the accepted and
    /// delivered stages.
    pub async fn propose_with_accepted(
        &self,
        op: R::Op,
    ) -> Result<StrictProposal, ReplicationError> {
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (delivered_tx, delivered_rx) = oneshot::channel();
        self.runtime
            .clone()
            .begin_propose_with_accepted(op, Some(accepted_tx), delivered_tx)
            .await?;
        Ok(StrictProposal {
            accepted: Some(accepted_rx),
            delivered: delivered_rx,
        })
    }

    /// Read-only snapshot of the underlying repo's current version.
    pub fn current_version(&self) -> u64 {
        self.runtime.repo.current_version()
    }

    pub fn local_node_id(&self) -> shitspeak_core::NodeIdentifier {
        self.runtime.self_id
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_state(&self) -> StrictDebugState {
        self.runtime.debug_state()
    }
}
