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
use serde::{de::DeserializeOwned, Serialize};
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

    /// Atomic snapshot. Returns `(version, msgpack_bytes)` where `version`
    /// matches the applied state captured by `msgpack_bytes`.
    fn snapshot(&self) -> (u64, Bytes);

    /// Ops with version in `(since, current_version]`. Returns
    /// `LogSlice::TooOld` when the structure can no longer satisfy from its
    /// in-memory log; the runtime will fall back to a snapshot.
    fn log_since(&self, since: u64) -> LogSlice<Self::Op>;

    /// Apply a committed op. Called by the runtime on the delivery path,
    /// in `(ts_final, op_id)` order, with monotonically increasing
    /// `version`.
    async fn apply_committed(&self, version: u64, op: Self::Op);

    /// Replace local state with the supplied snapshot.
    async fn install_snapshot(&self, version: u64, snapshot: Bytes);
}

/// Caller-facing handle for a strict topic. Cloning is cheap (internally an
/// `Arc`).
pub struct StrictHandle<R: StrictReplicable> {
    pub(crate) runtime: Arc<runtime::StrictRuntime<R>>,
}

impl<R: StrictReplicable> Clone for StrictHandle<R> {
    fn clone(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
        }
    }
}

impl<R: StrictReplicable> StrictHandle<R> {
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

    /// Read-only snapshot of the underlying repo's current version.
    pub fn current_version(&self) -> u64 {
        self.runtime.repo.current_version()
    }
}
