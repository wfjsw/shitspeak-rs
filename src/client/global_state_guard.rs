//! Transactional write guard for `ClientGlobalState`.
//!
//! `GlobalStateWriteGuard` wraps a `RwLockWriteGuard<ClientGlobalState>` and
//! snapshots the state at acquisition time.  On drop (or explicit `commit`),
//! it computes a `ClientGlobalStateDelta`, creates a `ClientStateLogEntry`,
//! and commits it to the `ClientRepository` — bumping the global version by 1.
//!
//! Multiple mutations within a single guard acquisition are batched into one
//! version bump and one log entry.

use std::ops::{Deref, DerefMut};

use tokio::sync::RwLockWriteGuard;

use crate::client::{
    client_global_state::ClientGlobalState,
    client_session_identifier::ClientSessionIdentifier,
    state_log::{ClientGlobalStateDelta, ClientStateOperation},
};
use crate::client_repository::ClientRepository;

pub struct GlobalStateWriteGuard<'a> {
    /// The actual write lock on the client's global state.
    inner: RwLockWriteGuard<'a, ClientGlobalState>,
    /// Snapshot taken at guard creation, used to compute the delta on commit.
    original: ClientGlobalState,
    /// Reference to the repository for committing the log entry.
    repo: &'a ClientRepository,
    /// The session that owns this state.
    session_id: ClientSessionIdentifier,
    /// Whether the guard has already been committed (or rolled back).
    committed: bool,
}

impl<'a> GlobalStateWriteGuard<'a> {
    pub(crate) fn new(
        inner: RwLockWriteGuard<'a, ClientGlobalState>,
        repo: &'a ClientRepository,
        session_id: ClientSessionIdentifier,
    ) -> Self {
        let original = inner.clone();
        Self {
            inner,
            original,
            repo,
            session_id,
            committed: false,
        }
    }

    /// Explicitly commit the changes, consuming the guard.
    ///
    /// Computes the delta between the original snapshot and the current state,
    /// creates a log entry, and commits it to the repository.
    /// Returns the version number that was assigned.
    pub fn commit(mut self) -> u64 {
        self.committed = true;
        let delta = ClientGlobalStateDelta::from_diff(&self.original, &self.inner);
        if delta.is_empty() {
            return self.repo.current_version();
        }
        let entry = self.repo.make_entry(ClientStateOperation::UpdateGlobalState {
            session_id: self.session_id,
            delta,
        });
        let version = entry.version;
        self.repo.commit_sync(entry);
        version
    }

    /// Roll back the changes without logging.
    ///
    /// The guard is dropped without computing a delta or creating a log entry.
    /// Note: the in-memory state has already been mutated; this only prevents
    /// the log entry from being created.  The state will be whatever it was
    /// mutated to.
    pub fn rollback(mut self) {
        self.committed = true;
    }
}

impl<'a> Deref for GlobalStateWriteGuard<'a> {
    type Target = ClientGlobalState;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a> DerefMut for GlobalStateWriteGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<'a> Drop for GlobalStateWriteGuard<'a> {
    fn drop(&mut self) {
        if !self.committed {
            let delta = ClientGlobalStateDelta::from_diff(&self.original, &self.inner);
            if delta.is_empty() {
                return;
            }
            let entry = self.repo.make_entry(ClientStateOperation::UpdateGlobalState {
                session_id: self.session_id,
                delta,
            });
            self.repo.commit_sync(entry);
        }
    }
}
