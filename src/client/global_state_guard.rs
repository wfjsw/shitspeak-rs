//! Transactional write guard for `ClientGlobalState`.
//!
//! `GlobalStateWriteGuard` wraps a `RwLockWriteGuard<ClientGlobalState>` and
//! enables setter-level delta recording on acquisition.  On drop (or explicit
//! `commit`), it takes the recorded `ClientGlobalStateDelta`, creates a
//! `ClientStateLogEntry`,
//! and commits it to the `ClientRepository` — bumping the global version by 1.
//!
//! Multiple mutations within a single guard acquisition are batched into one
//! version bump and one log entry.

use std::ops::{Deref, DerefMut};

use parking_lot::RwLockWriteGuard;

use crate::client::{
    client_global_state::ClientGlobalState, client_session_identifier::ClientSessionIdentifier,
    state_log::ClientStateOperation,
};
use crate::client_repository::ClientRepository;

pub struct GlobalStateWriteGuard<'a> {
    /// The actual write lock on the client's global state.
    inner: RwLockWriteGuard<'a, ClientGlobalState>,
    /// Reference to the repository for committing the log entry.
    repo: &'a ClientRepository,
    /// The session that owns this state.
    session_id: ClientSessionIdentifier,
    /// The server-id scope that owns this state.
    server_id: String,
    /// The session that initiated this mutation.
    sender_session_id: Option<ClientSessionIdentifier>,
    /// The channel version at the time this guard was acquired.
    /// `Some(v)` means this mutation depends on channel state ≥ v.
    channel_version_dep: Option<u64>,
    /// Whether the guard has already been committed (or rolled back).
    committed: bool,
}

impl<'a> GlobalStateWriteGuard<'a> {
    pub(crate) fn new(
        mut inner: RwLockWriteGuard<'a, ClientGlobalState>,
        repo: &'a ClientRepository,
        server_id: String,
        session_id: ClientSessionIdentifier,
        sender_session_id: Option<ClientSessionIdentifier>,
        channel_version_dep: Option<u64>,
    ) -> Self {
        inner.begin_delta_recording();
        Self {
            inner,
            repo,
            server_id,
            session_id,
            sender_session_id,
            channel_version_dep,
            committed: false,
        }
    }

    /// Explicitly commit the changes, consuming the guard.
    ///
    /// Uses the delta recorded by setters while this guard is active,
    /// creates a log entry, and commits it to the repository.
    /// Returns the version number that was assigned.
    pub fn commit(mut self) -> u64 {
        self.committed = true;
        let delta = self.inner.finish_delta_recording();
        if delta.is_empty() {
            return self.repo.current_version();
        }
        self.repo.commit_operation_sync(
            ClientStateOperation::UpdateGlobalState {
                server_id: self.server_id.clone(),
                session_id: self.session_id,
                sender_session_id: self.sender_session_id,
                delta,
            },
            self.channel_version_dep,
        );
        // Return the new version (best-effort: peek after commit)
        self.repo.current_version()
    }

    /// Roll back the changes without logging.
    ///
    /// The guard is dropped without computing a delta or creating a log entry.
    /// Note: the in-memory state has already been mutated; this only prevents
    /// the log entry from being created.  The state will be whatever it was
    /// mutated to.
    pub fn rollback(mut self) {
        self.committed = true;
        self.inner.cancel_delta_recording();
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
            let delta = self.inner.finish_delta_recording();
            if delta.is_empty() {
                return;
            }
            self.repo.commit_operation_sync(
                ClientStateOperation::UpdateGlobalState {
                    server_id: self.server_id.clone(),
                    session_id: self.session_id,
                    sender_session_id: self.sender_session_id,
                    delta,
                },
                self.channel_version_dep,
            );
        }
    }
}
