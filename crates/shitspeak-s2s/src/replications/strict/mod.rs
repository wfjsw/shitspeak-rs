//! Strict (Tempo) replication: leader-less, multi-writer, total-order
//! broadcast over the L2 overlay.
//!
//! See `runtime.rs` for the state machine. This file holds the public
//! `StrictReplicable` trait, `StrictHandle` (caller-facing), and
//! shared types.

pub mod catchup;
pub mod propose;
pub mod runtime;

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

    /// Atomic snapshot. Returns `(version, msgpack_bytes)` where `version`
    /// matches the applied state captured by `msgpack_bytes`.
    fn snapshot(&self) -> (u64, Bytes);

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

    /// Replace local state with the supplied snapshot.
    async fn install_snapshot(&self, version: u64, snapshot: Bytes);
}

/// Caller-facing handle for a strict topic. Cloning is cheap (internally an
/// `Arc`).
pub struct StrictHandle<R: StrictReplicable> {
    pub(crate) runtime: Arc<runtime::StrictRuntime<R>>,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy)]
pub struct StrictDebugState {
    election_pending: bool,
    election_active: bool,
    can_start_election: bool,
    local_proposals: usize,
    pending_proposes: usize,
    buffered_commits: usize,
    unresolved_promises: usize,
    active_recoveries: usize,
}

#[cfg(any(test, feature = "test-support"))]
impl StrictDebugState {
    pub fn election_pending(self) -> bool {
        self.election_pending
    }
    pub fn election_active(self) -> bool {
        self.election_active
    }
    pub fn can_start_election(self) -> bool {
        self.can_start_election
    }
    pub fn local_proposals(self) -> usize {
        self.local_proposals
    }
    pub fn pending_proposes(self) -> usize {
        self.pending_proposes
    }
    pub fn buffered_commits(self) -> usize {
        self.buffered_commits
    }
    pub fn unresolved_promises(self) -> usize {
        self.unresolved_promises
    }
    pub fn active_recoveries(self) -> usize {
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
