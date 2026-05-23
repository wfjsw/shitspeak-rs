//! Owner-scoped replication: single-writer (per-node), multi-reader,
//! transient. Each node "owns" its slot — only the owner ever proposes ops
//! tagged with its NodeIdentifier. Other replicas track per-origin sequence
//! state, with epoch (`boot_epoch`) reset driven by the overlay's LSDB.

pub mod catchup;
pub mod runtime;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{de::DeserializeOwned, Serialize};

use super::error::ReplicationError;
use crate::types::NodeIdentifier;

/// What the responder hands back for an origin's catchup window.
#[derive(Clone, Debug)]
pub enum LogSlice<Op> {
    Available(Vec<(u64, Op)>),
    TooOld,
}

/// Repository-side contract for the owner-scoped replication mode.
///
/// # Apply ordering
///
/// On the **owner's** node, the runtime drives `apply_remote(self_id, …)`
/// AFTER the broadcast send returns — i.e. broadcast first, local apply
/// second. This is the inverse of a primary-first design and is deliberate:
/// under owner crash between broadcast and apply, the overlay's
/// `boot_epoch` advance + `reset_origin` flow GCs any orphan op that landed
/// on replicas. Adapter authors MUST NOT pre-apply inside their own
/// `propose` wrapper, or the cluster-consistent crash-recovery property is
/// lost.
///
/// On a **remote** node, `apply_remote` runs upon receipt of `OwnerOp` once
/// the version is the next-expected one for `(origin, known_epoch)`.
///
/// # Epoch source
///
/// `epoch` is the origin's overlay `boot_epoch`. The runtime does not
/// invent epochs — it forwards the value the LSDB admitted.
#[async_trait]
pub trait OwnerReplicable: Send + Sync + 'static {
    type Op: Serialize + DeserializeOwned + Send + Sync + Clone + 'static;

    /// Local owner's own version (only meaningful on the owning node).
    fn local_version(&self) -> u64;

    /// {origin -> (epoch, version)} for every origin this replica tracks.
    fn known_versions(&self) -> HashMap<NodeIdentifier, (u64, u64)>;

    /// Atomic snapshot of `origin`'s state. Returns
    /// `(epoch, version, msgpack_bytes)`. `None` if the origin is unknown.
    fn snapshot_for_origin(&self, origin: NodeIdentifier) -> Option<(u64, u64, Bytes)>;

    /// Ops for `origin` in `(since, current]`. `LogSlice::TooOld` triggers
    /// a snapshot fallback in the runtime.
    fn log_for_origin(&self, origin: NodeIdentifier, since: u64) -> LogSlice<Self::Op>;

    /// Apply an op from `origin` at `(epoch, version)`. Called by the
    /// runtime in strict per-origin order.
    async fn apply_remote(&self, origin: NodeIdentifier, epoch: u64, version: u64, op: Self::Op);

    /// Replace local state for `origin` with the supplied snapshot.
    async fn install_snapshot_for_origin(
        &self,
        origin: NodeIdentifier,
        epoch: u64,
        version: u64,
        snapshot: Bytes,
    );

    /// Called whenever the runtime detects a strictly-greater epoch for
    /// `origin` -- either via a fresh `OwnerOp` carrying the new epoch or
    /// via the overlay's `MembershipEvent::Restarted`. This is restart
    /// handling: implementations should drop any state under the old epoch.
    async fn reset_origin(&self, origin: NodeIdentifier, new_epoch: u64);

    /// Called when membership reports that `origin` is offline without a
    /// replacement epoch. Transient implementations can remove visible state;
    /// durable implementations may keep their data and leave this as a no-op.
    async fn remove_origin(&self, _origin: NodeIdentifier) {}
}

/// Caller-facing handle for an owner-scoped topic.
pub struct OwnerHandle<R: OwnerReplicable> {
    pub(crate) runtime: Arc<runtime::OwnerRuntime<R>>,
}

impl<R: OwnerReplicable> Clone for OwnerHandle<R> {
    fn clone(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
        }
    }
}

impl<R: OwnerReplicable> OwnerHandle<R> {
    /// Propose an op as the topic's owner. Broadcasts to the cluster, then
    /// applies locally. Resolves once the local apply has returned.
    pub async fn propose(&self, op: R::Op) -> Result<u64, ReplicationError> {
        self.runtime.clone().propose_local(op).await
    }

    pub fn local_version(&self) -> u64 {
        self.runtime.repo.local_version()
    }
}
