//! Durable state for strict protocol terminal-resolution records.
//!
//! The strict runtime owns one journal per topic and calls these synchronous
//! methods while holding its state lock. Each successful mutation is first
//! written to a temporary file and atomically replaced into place, so a crash
//! cannot leave a partially written journal visible on the next startup.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const JOURNAL_DIRECTORY: &str = "strict-terminal-journal";
const JOURNAL_VERSION: u32 = 1;

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

#[cfg(windows)]
const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
#[cfg(windows)]
const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

#[cfg(windows)]
#[link(name = "Kernel32")]
unsafe extern "system" {
    fn MoveFileExW(
        existing_file_name: *const u16,
        new_file_name: *const u16,
        move_flags: u32,
    ) -> i32;
}

/// An operation identifier encoded by strict protocol messages as `(hi, lo)`.
pub(crate) type TerminalJournalOpId = (u64, u64);

/// One member incarnation frozen into a strict protocol v2 proposal target
/// descriptor.
///
/// Descriptors are ordered by node id and contain each node at most once.
/// Keeping the incarnation alongside the node prevents a restarted member
/// from being mistaken for the member that was originally targeted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FrozenTarget {
    node: u16,
    boot_epoch: u64,
}

impl FrozenTarget {
    pub(crate) fn new(node: u16, boot_epoch: u64) -> Self {
        Self { node, boot_epoch }
    }

    pub(crate) fn node(&self) -> u16 {
        self.node
    }

    pub(crate) fn boot_epoch(&self) -> u64 {
        self.boot_epoch
    }

    /// Return whether `targets` is strictly ordered by node id. This rejects
    /// duplicate nodes even when their boot epochs differ.
    pub(crate) fn is_canonical(targets: &[Self]) -> bool {
        targets.windows(2).all(|pair| pair[0].node < pair[1].node)
    }

    /// Return whether `targets` can represent a frozen proposal descriptor.
    /// Every strict proposal targets itself, so an empty descriptor is never
    /// valid.
    pub(crate) fn is_valid_descriptor(targets: &[Self]) -> bool {
        !targets.is_empty() && Self::is_canonical(targets)
    }

    /// Sort a unique target list into its durable representation. Duplicate
    /// node ids are rejected rather than choosing an incarnation implicitly.
    #[cfg(test)]
    pub(crate) fn canonicalize(mut targets: Vec<Self>) -> Option<Vec<Self>> {
        targets.sort_unstable_by_key(Self::node);
        Self::is_valid_descriptor(&targets).then_some(targets)
    }

    /// Find a node in a canonical descriptor without rebuilding a lookup map.
    pub(crate) fn find_in_canonical(targets: &[Self], node: u16) -> Option<&Self> {
        targets
            .binary_search_by_key(&node, Self::node)
            .ok()
            .map(|index| &targets[index])
    }
}

/// The exact resolver incarnation that made a v2 terminal decision.
///
/// This is retained with the terminal fence because a later catchup receiver
/// must verify the same identity that direct `StrictDecision` handling does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TerminalResolver {
    node: u16,
    boot_epoch: u64,
}

impl TerminalResolver {
    pub(crate) fn new(node: u16, boot_epoch: u64) -> Self {
        Self { node, boot_epoch }
    }

    pub(crate) fn node(&self) -> u16 {
        self.node
    }

    pub(crate) fn boot_epoch(&self) -> u64 {
        self.boot_epoch
    }
}

/// A v2 proposal retained until a terminal decision resolves it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingProposal {
    ts_local: u64,
    op_msgpack: Vec<u8>,
}

impl PendingProposal {
    pub(crate) fn new(ts_local: u64, op_msgpack: Vec<u8>) -> Self {
        Self {
            ts_local,
            op_msgpack,
        }
    }

    pub(crate) fn from_bytes(ts_local: u64, op_msgpack: Bytes) -> Self {
        Self::new(ts_local, op_msgpack.to_vec())
    }

    pub(crate) fn ts_local(&self) -> u64 {
        self.ts_local
    }

    #[cfg(test)]
    pub(crate) fn op_msgpack(&self) -> &[u8] {
        &self.op_msgpack
    }

    pub(crate) fn op_msgpack_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(&self.op_msgpack)
    }
}

/// A commit value which may be accepted or chosen as the terminal decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CommitCandidate {
    ballot: u64,
    ts_final: u64,
    op_msgpack: Vec<u8>,
}

impl CommitCandidate {
    pub(crate) fn new(ballot: u64, ts_final: u64, op_msgpack: Vec<u8>) -> Self {
        Self {
            ballot,
            ts_final,
            op_msgpack,
        }
    }

    pub(crate) fn from_bytes(ballot: u64, ts_final: u64, op_msgpack: Bytes) -> Self {
        Self::new(ballot, ts_final, op_msgpack.to_vec())
    }

    pub(crate) fn ballot(&self) -> u64 {
        self.ballot
    }

    pub(crate) fn ts_final(&self) -> u64 {
        self.ts_final
    }

    pub(crate) fn op_msgpack(&self) -> &[u8] {
        &self.op_msgpack
    }

    pub(crate) fn op_msgpack_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(&self.op_msgpack)
    }

    fn has_same_value(&self, other: &Self) -> bool {
        self.ts_final == other.ts_final && self.op_msgpack == other.op_msgpack
    }
}

/// An immutable terminal outcome for a strict operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub(crate) enum TerminalDecision {
    Commit { candidate: CommitCandidate },
    Abort { ballot: u64 },
}

impl TerminalDecision {
    pub(crate) fn commit(candidate: CommitCandidate) -> Self {
        Self::Commit { candidate }
    }

    pub(crate) fn commit_bytes(ballot: u64, ts_final: u64, op_msgpack: Bytes) -> Self {
        Self::commit(CommitCandidate::from_bytes(ballot, ts_final, op_msgpack))
    }

    pub(crate) fn abort(ballot: u64) -> Self {
        Self::Abort { ballot }
    }

    pub(crate) fn ballot(&self) -> u64 {
        match self {
            Self::Commit { candidate } => candidate.ballot(),
            Self::Abort { ballot } => *ballot,
        }
    }

    #[cfg(test)]
    pub(crate) fn committed_candidate(&self) -> Option<&CommitCandidate> {
        match self {
            Self::Commit { candidate } => Some(candidate),
            Self::Abort { .. } => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn is_abort(&self) -> bool {
        matches!(self, Self::Abort { .. })
    }
}

/// The durable terminal-resolution state for one operation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TerminalJournalRecord {
    promise_ballot: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    frozen_targets: Option<Vec<FrozenTarget>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_resolver: Option<TerminalResolver>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_proposal: Option<PendingProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_commit: Option<CommitCandidate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_decision: Option<TerminalDecision>,
}

impl TerminalJournalRecord {
    pub(crate) fn promise_ballot(&self) -> u64 {
        self.promise_ballot
    }

    pub(crate) fn frozen_targets(&self) -> Option<&[FrozenTarget]> {
        self.frozen_targets.as_deref()
    }

    pub(crate) fn terminal_resolver(&self) -> Option<TerminalResolver> {
        self.terminal_resolver
    }

    pub(crate) fn pending_proposal(&self) -> Option<&PendingProposal> {
        self.pending_proposal.as_ref()
    }

    pub(crate) fn accepted_commit(&self) -> Option<&CommitCandidate> {
        self.accepted_commit.as_ref()
    }

    pub(crate) fn terminal_decision(&self) -> Option<&TerminalDecision> {
        self.terminal_decision.as_ref()
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.terminal_decision.is_some()
    }
}

/// One record returned by [`TerminalJournal::snapshot`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TerminalJournalSnapshotEntry {
    op_id: TerminalJournalOpId,
    record: TerminalJournalRecord,
}

impl TerminalJournalSnapshotEntry {
    pub(crate) fn into_parts(self) -> (TerminalJournalOpId, TerminalJournalRecord) {
        (self.op_id, self.record)
    }
}

/// Persistence or invariant failure from the terminal-resolution journal.
#[derive(Debug, Error)]
pub(crate) enum TerminalJournalError {
    #[error("strict terminal journal I/O failed at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("strict terminal journal JSON failed at {path:?}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("unsupported strict terminal journal version {version} at {path:?}")]
    UnsupportedVersion { path: PathBuf, version: u32 },
    #[error(
        "strict terminal journal topic mismatch at {path:?}: expected {expected:?}, found {found:?}"
    )]
    TopicMismatch {
        path: PathBuf,
        expected: String,
        found: String,
    },
    #[error("strict terminal journal is already locked at {path:?}")]
    AlreadyLocked { path: PathBuf },
    #[error("duplicate strict terminal journal operation ({op_id_hi}, {op_id_lo}) at {path:?}")]
    DuplicateRecord {
        path: PathBuf,
        op_id_hi: u64,
        op_id_lo: u64,
    },
    #[error(
        "invalid strict terminal journal record ({op_id_hi}, {op_id_lo}) at {path:?}: {reason}"
    )]
    InvalidRecord {
        path: PathBuf,
        op_id_hi: u64,
        op_id_lo: u64,
        reason: &'static str,
    },
    #[error(
        "strict terminal journal cannot accept a different value at the same ballot for operation ({op_id_hi}, {op_id_lo})"
    )]
    ConflictingAcceptedValue { op_id_hi: u64, op_id_lo: u64 },
    #[error(
        "strict terminal journal cannot accept ballot {ballot} below promised ballot {promised_ballot} for operation ({op_id_hi}, {op_id_lo})"
    )]
    AcceptBelowPromise {
        op_id_hi: u64,
        op_id_lo: u64,
        ballot: u64,
        promised_ballot: u64,
    },
    #[error(
        "strict terminal journal cannot replace terminal decision for operation ({op_id_hi}, {op_id_lo})"
    )]
    ConflictingTerminalDecision { op_id_hi: u64, op_id_lo: u64 },
    #[error(
        "strict terminal journal cannot abort operation ({op_id_hi}, {op_id_lo}) after accepting a commit value"
    )]
    AbortAfterAccept { op_id_hi: u64, op_id_lo: u64 },
    #[error(
        "strict terminal journal cannot commit a value different from the accepted value for operation ({op_id_hi}, {op_id_lo})"
    )]
    CommitDiffersFromAccepted { op_id_hi: u64, op_id_lo: u64 },
    #[error(
        "strict terminal journal cannot decide ballot {ballot} below promised ballot {promised_ballot} for operation ({op_id_hi}, {op_id_lo})"
    )]
    DecisionBelowPromise {
        op_id_hi: u64,
        op_id_lo: u64,
        ballot: u64,
        promised_ballot: u64,
    },
    #[error(
        "strict terminal journal requires a non-empty canonical frozen target descriptor for operation ({op_id_hi}, {op_id_lo})"
    )]
    InvalidFrozenTargets { op_id_hi: u64, op_id_lo: u64 },
    #[error(
        "strict terminal journal cannot replace the frozen target descriptor for operation ({op_id_hi}, {op_id_lo})"
    )]
    ConflictingFrozenTargets { op_id_hi: u64, op_id_lo: u64 },
    #[error(
        "strict terminal journal cannot replace the terminal resolver identity for operation ({op_id_hi}, {op_id_lo})"
    )]
    ConflictingTerminalResolver { op_id_hi: u64, op_id_lo: u64 },
    #[error(
        "strict terminal journal requires v2 resolver identity for operation ({op_id_hi}, {op_id_lo})"
    )]
    MissingV2TerminalIdentity { op_id_hi: u64, op_id_lo: u64 },
    #[error(
        "strict terminal journal cannot replace the pending proposal for operation ({op_id_hi}, {op_id_lo})"
    )]
    ConflictingPendingProposal { op_id_hi: u64, op_id_lo: u64 },
    #[error("strict terminal journal terminal-decision generation is exhausted")]
    DecisionGenerationExhausted,
}

/// A per-topic terminal-resolution journal.
///
/// With `None` (or an empty path) for `root`, the journal is intentionally
/// in-memory. This supports tests and keeps the caller responsible for
/// refusing the durable protocol version when persistence is unavailable.
pub(crate) struct TerminalJournal {
    topic: String,
    path: Option<PathBuf>,
    // Retains the stable sidecar lock while the journal JSON is replaced.
    _lock_file: Option<File>,
    records: BTreeMap<TerminalJournalOpId, TerminalJournalRecord>,
    // Persisted monotonic fence-cut identifier. Catchup peers echo this only
    // after they have installed every terminal decision in the corresponding
    // stable journal snapshot.
    terminal_decision_generation: u64,
}

impl TerminalJournal {
    /// Load the current topic journal. Missing files are an empty journal.
    pub(crate) fn load(
        root: Option<PathBuf>,
        topic: impl Into<String>,
    ) -> Result<Self, TerminalJournalError> {
        let topic = topic.into();
        let path = journal_path(root.as_deref(), &topic);
        let Some(path) = path else {
            return Ok(Self {
                topic,
                path: None,
                _lock_file: None,
                records: BTreeMap::new(),
                terminal_decision_generation: 0,
            });
        };

        let parent = path.parent().expect("journal path always has a parent");
        let parent_was_missing = !parent.exists();
        fs::create_dir_all(parent).map_err(|source| TerminalJournalError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        if parent_was_missing {
            // Sync the directory entry for a newly-created journal
            // directory before relying on files beneath it for a terminal
            // fence. The later sync of `parent` persists the replacement
            // journal file itself.
            if let Some(grandparent) = parent.parent() {
                sync_parent_directory(grandparent)?;
            }
        }

        let lock_path = journal_lock_path(&path);
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&lock_path)
            .map_err(|source| TerminalJournalError::Io {
                path: lock_path.clone(),
                source,
            })?;
        match lock_file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(TerminalJournalError::AlreadyLocked { path: lock_path });
            }
            Err(TryLockError::Error(source)) => {
                return Err(TerminalJournalError::Io {
                    path: lock_path,
                    source,
                });
            }
        }

        let (records, terminal_decision_generation) = match fs::read(&path) {
            Ok(bytes) => load_records(&path, &topic, &bytes)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => (BTreeMap::new(), 0),
            Err(source) => {
                return Err(TerminalJournalError::Io {
                    path: path.clone(),
                    source,
                });
            }
        };

        Ok(Self {
            topic,
            path: Some(path),
            _lock_file: Some(lock_file),
            records,
            terminal_decision_generation,
        })
    }

    pub(crate) fn in_memory(topic: impl Into<String>) -> Self {
        Self {
            topic: topic.into(),
            path: None,
            _lock_file: None,
            records: BTreeMap::new(),
            terminal_decision_generation: 0,
        }
    }

    /// Whether updates are synchronously persisted to disk.
    pub(crate) fn durable_persistence_enabled(&self) -> bool {
        self.path.is_some()
    }

    #[cfg(test)]
    pub(crate) fn persistence_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub(crate) fn get(&self, op_id: TerminalJournalOpId) -> Option<&TerminalJournalRecord> {
        self.records.get(&op_id)
    }

    /// Return a stable, operation-id-sorted copy suitable for catchup.
    pub(crate) fn snapshot(&self) -> Vec<TerminalJournalSnapshotEntry> {
        self.records
            .iter()
            .map(|(op_id, record)| TerminalJournalSnapshotEntry {
                op_id: *op_id,
                record: record.clone(),
            })
            .collect()
    }

    /// Return a stable journal image together with the terminal-decision
    /// generation that names its fence cut.
    pub(crate) fn snapshot_with_terminal_decision_generation(
        &self,
    ) -> (u64, Vec<TerminalJournalSnapshotEntry>) {
        (self.terminal_decision_generation, self.snapshot())
    }

    pub(crate) fn terminal_decision_generation(&self) -> u64 {
        self.terminal_decision_generation
    }

    /// Record a higher promise ballot. Returns whether durable state changed.
    ///
    /// A terminal record already fences all later ballots, so it remains
    /// unchanged and returns `false`.
    pub(crate) fn upsert_promise(
        &mut self,
        op_id: TerminalJournalOpId,
        ballot: u64,
    ) -> Result<bool, TerminalJournalError> {
        self.mutate(op_id, |record| {
            if record.is_terminal() || ballot <= record.promise_ballot {
                return Ok(false);
            }
            record.promise_ballot = ballot;
            Ok(true)
        })
    }

    /// Persist the prepared v2 proposal together with its frozen target
    /// descriptor. Both fields are written by one atomic journal mutation.
    #[cfg(test)]
    pub(crate) fn upsert_v2_pending(
        &mut self,
        op_id: TerminalJournalOpId,
        frozen_targets: &[FrozenTarget],
        ts_local: u64,
        op_msgpack: Vec<u8>,
    ) -> Result<bool, TerminalJournalError> {
        self.upsert_v2_pending_proposal(
            op_id,
            frozen_targets,
            PendingProposal::new(ts_local, op_msgpack),
        )
    }

    /// Persist the prepared v2 proposal supplied as `Bytes`.
    pub(crate) fn upsert_v2_pending_bytes(
        &mut self,
        op_id: TerminalJournalOpId,
        frozen_targets: &[FrozenTarget],
        ts_local: u64,
        op_msgpack: Bytes,
    ) -> Result<bool, TerminalJournalError> {
        self.upsert_v2_pending_proposal(
            op_id,
            frozen_targets,
            PendingProposal::from_bytes(ts_local, op_msgpack),
        )
    }

    /// Record a v2 promise while proving that the resolver is using the same
    /// immutable target descriptor as the original proposal.
    pub(crate) fn upsert_v2_promise(
        &mut self,
        op_id: TerminalJournalOpId,
        frozen_targets: &[FrozenTarget],
        ballot: u64,
    ) -> Result<bool, TerminalJournalError> {
        self.mutate(op_id, |record| {
            let descriptor_changed = attach_v2_targets(record, op_id, frozen_targets)?;
            if record.is_terminal() || ballot <= record.promise_ballot {
                return Ok(descriptor_changed);
            }
            record.promise_ballot = ballot;
            Ok(true)
        })
    }

    /// Persist an accepted commit candidate supplied as owned message bytes.
    #[cfg(test)]
    pub(crate) fn upsert_accepted(
        &mut self,
        op_id: TerminalJournalOpId,
        ballot: u64,
        ts_final: u64,
        op_msgpack: Vec<u8>,
    ) -> Result<bool, TerminalJournalError> {
        self.upsert_accepted_candidate(op_id, CommitCandidate::new(ballot, ts_final, op_msgpack))
    }

    /// Persist an accepted commit candidate supplied as `Bytes`.
    pub(crate) fn upsert_accepted_bytes(
        &mut self,
        op_id: TerminalJournalOpId,
        ballot: u64,
        ts_final: u64,
        op_msgpack: Bytes,
    ) -> Result<bool, TerminalJournalError> {
        self.upsert_accepted_candidate(
            op_id,
            CommitCandidate::from_bytes(ballot, ts_final, op_msgpack),
        )
    }

    pub(crate) fn upsert_accepted_candidate(
        &mut self,
        op_id: TerminalJournalOpId,
        candidate: CommitCandidate,
    ) -> Result<bool, TerminalJournalError> {
        self.mutate(op_id, |record| {
            upsert_accepted_candidate_in_record(record, op_id, candidate)
        })
    }

    /// Persist a v2 accepted value together with a matching frozen target
    /// descriptor, using `Bytes`.
    pub(crate) fn upsert_v2_accepted_bytes(
        &mut self,
        op_id: TerminalJournalOpId,
        frozen_targets: &[FrozenTarget],
        ballot: u64,
        ts_final: u64,
        op_msgpack: Bytes,
    ) -> Result<bool, TerminalJournalError> {
        self.upsert_v2_accepted_candidate(
            op_id,
            frozen_targets,
            CommitCandidate::from_bytes(ballot, ts_final, op_msgpack),
        )
    }

    fn upsert_v2_pending_proposal(
        &mut self,
        op_id: TerminalJournalOpId,
        frozen_targets: &[FrozenTarget],
        pending: PendingProposal,
    ) -> Result<bool, TerminalJournalError> {
        self.mutate(op_id, |record| {
            let descriptor_changed = attach_v2_targets(record, op_id, frozen_targets)?;
            if record.is_terminal() {
                return Ok(descriptor_changed);
            }
            match record.pending_proposal.as_ref() {
                Some(existing) if existing == &pending => Ok(descriptor_changed),
                Some(_) => Err(TerminalJournalError::ConflictingPendingProposal {
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                }),
                None => {
                    record.pending_proposal = Some(pending);
                    Ok(true)
                }
            }
        })
    }

    fn upsert_v2_accepted_candidate(
        &mut self,
        op_id: TerminalJournalOpId,
        frozen_targets: &[FrozenTarget],
        candidate: CommitCandidate,
    ) -> Result<bool, TerminalJournalError> {
        self.mutate(op_id, |record| {
            let descriptor_changed = attach_v2_targets(record, op_id, frozen_targets)?;
            let accepted_changed = upsert_accepted_candidate_in_record(record, op_id, candidate)?;
            Ok(descriptor_changed || accepted_changed)
        })
    }

    /// Record a terminal decision. Terminal records are immutable: a commit
    /// beats a later abort, and an abort rejects every later commit.
    pub(crate) fn upsert_decision(
        &mut self,
        op_id: TerminalJournalOpId,
        decision: TerminalDecision,
    ) -> Result<bool, TerminalJournalError> {
        self.mutate(op_id, |record| {
            if record.frozen_targets.is_some() {
                return Err(TerminalJournalError::MissingV2TerminalIdentity {
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                });
            }
            upsert_decision_in_record(record, op_id, decision)
        })
    }

    /// Persist a v2 terminal commit together with its frozen target
    /// descriptor. A cold receiver writes the descriptor and terminal fence in
    /// the same journal replacement, so it cannot recover a terminal v2
    /// decision without its original membership proof.
    pub(crate) fn upsert_v2_commit_decision_bytes(
        &mut self,
        op_id: TerminalJournalOpId,
        frozen_targets: &[FrozenTarget],
        resolver: TerminalResolver,
        ballot: u64,
        ts_final: u64,
        op_msgpack: Bytes,
    ) -> Result<bool, TerminalJournalError> {
        self.upsert_v2_decision(
            op_id,
            frozen_targets,
            resolver,
            TerminalDecision::commit_bytes(ballot, ts_final, op_msgpack),
        )
    }

    /// Persist a v2 terminal abort together with its frozen target descriptor.
    pub(crate) fn upsert_v2_abort_decision(
        &mut self,
        op_id: TerminalJournalOpId,
        frozen_targets: &[FrozenTarget],
        resolver: TerminalResolver,
        ballot: u64,
    ) -> Result<bool, TerminalJournalError> {
        self.upsert_v2_decision(
            op_id,
            frozen_targets,
            resolver,
            TerminalDecision::abort(ballot),
        )
    }

    fn upsert_v2_decision(
        &mut self,
        op_id: TerminalJournalOpId,
        frozen_targets: &[FrozenTarget],
        resolver: TerminalResolver,
        decision: TerminalDecision,
    ) -> Result<bool, TerminalJournalError> {
        self.mutate(op_id, |record| {
            let identity_changed =
                attach_v2_terminal_identity(record, op_id, frozen_targets, resolver)?;
            let decision_changed = learn_v2_terminal_decision_in_record(record, op_id, decision)?;
            Ok(identity_changed || decision_changed)
        })
    }

    #[cfg(test)]
    pub(crate) fn upsert_commit_decision(
        &mut self,
        op_id: TerminalJournalOpId,
        ballot: u64,
        ts_final: u64,
        op_msgpack: Vec<u8>,
    ) -> Result<bool, TerminalJournalError> {
        self.upsert_decision(
            op_id,
            TerminalDecision::commit(CommitCandidate::new(ballot, ts_final, op_msgpack)),
        )
    }

    pub(crate) fn upsert_commit_decision_bytes(
        &mut self,
        op_id: TerminalJournalOpId,
        ballot: u64,
        ts_final: u64,
        op_msgpack: Bytes,
    ) -> Result<bool, TerminalJournalError> {
        self.upsert_decision(
            op_id,
            TerminalDecision::commit_bytes(ballot, ts_final, op_msgpack),
        )
    }

    pub(crate) fn upsert_abort_decision(
        &mut self,
        op_id: TerminalJournalOpId,
        ballot: u64,
    ) -> Result<bool, TerminalJournalError> {
        self.upsert_decision(op_id, TerminalDecision::abort(ballot))
    }

    fn mutate(
        &mut self,
        op_id: TerminalJournalOpId,
        mutate: impl FnOnce(&mut TerminalJournalRecord) -> Result<bool, TerminalJournalError>,
    ) -> Result<bool, TerminalJournalError> {
        let had_terminal_decision = self
            .records
            .get(&op_id)
            .is_some_and(TerminalJournalRecord::is_terminal);
        let mut records = self.records.clone();
        let record = records.entry(op_id).or_default();
        let changed = mutate(record)?;
        if !changed {
            return Ok(false);
        }

        let terminal_decision_generation = if !had_terminal_decision && record.is_terminal() {
            self.terminal_decision_generation
                .checked_add(1)
                .ok_or(TerminalJournalError::DecisionGenerationExhausted)?
        } else {
            self.terminal_decision_generation
        };
        self.persist(&records, terminal_decision_generation)?;
        self.records = records;
        self.terminal_decision_generation = terminal_decision_generation;
        Ok(true)
    }

    fn persist(
        &self,
        records: &BTreeMap<TerminalJournalOpId, TerminalJournalRecord>,
        terminal_decision_generation: u64,
    ) -> Result<(), TerminalJournalError> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        let payload = PersistedTerminalJournal {
            version: JOURNAL_VERSION,
            topic: self.topic.clone(),
            terminal_decision_generation,
            records: records
                .iter()
                .map(
                    |((op_id_hi, op_id_lo), record)| PersistedTerminalJournalRecord {
                        op_id_hi: *op_id_hi,
                        op_id_lo: *op_id_lo,
                        record: record.clone(),
                    },
                )
                .collect(),
        };
        let bytes =
            serde_json::to_vec_pretty(&payload).map_err(|source| TerminalJournalError::Json {
                path: path.clone(),
                source,
            })?;

        let parent = path.parent().expect("journal path always has a parent");
        fs::create_dir_all(parent).map_err(|source| TerminalJournalError::Io {
            path: parent.to_path_buf(),
            source,
        })?;

        let temporary_path = temporary_path(path);
        let write_result = write_temporary_file(&temporary_path, &bytes)
            .and_then(|()| replace_file_atomically(&temporary_path, path))
            .map_err(|source| TerminalJournalError::Io {
                path: if temporary_path.exists() {
                    temporary_path.clone()
                } else {
                    path.clone()
                },
                source,
            });
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temporary_path);
            return Err(error);
        }

        sync_parent_directory(parent)?;
        Ok(())
    }
}

fn attach_v2_targets(
    record: &mut TerminalJournalRecord,
    op_id: TerminalJournalOpId,
    frozen_targets: &[FrozenTarget],
) -> Result<bool, TerminalJournalError> {
    if !FrozenTarget::is_valid_descriptor(frozen_targets) {
        return Err(TerminalJournalError::InvalidFrozenTargets {
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
        });
    }

    if record.is_terminal() {
        return match record.frozen_targets.as_deref() {
            Some(existing) if existing == frozen_targets => Ok(false),
            Some(_) => Err(TerminalJournalError::ConflictingFrozenTargets {
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
            }),
            None => Ok(false),
        };
    }

    match record.frozen_targets.as_deref() {
        Some(existing) if existing == frozen_targets => Ok(false),
        Some(_) => Err(TerminalJournalError::ConflictingFrozenTargets {
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
        }),
        None => {
            record.frozen_targets = Some(frozen_targets.to_vec());
            Ok(true)
        }
    }
}

fn attach_v2_terminal_identity(
    record: &mut TerminalJournalRecord,
    op_id: TerminalJournalOpId,
    frozen_targets: &[FrozenTarget],
    resolver: TerminalResolver,
) -> Result<bool, TerminalJournalError> {
    if record.is_terminal() && record.frozen_targets.as_deref() != Some(frozen_targets) {
        return Err(TerminalJournalError::ConflictingFrozenTargets {
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
        });
    }
    let targets_changed = attach_v2_targets(record, op_id, frozen_targets)?;
    if FrozenTarget::find_in_canonical(frozen_targets, resolver.node())
        .is_none_or(|target| target.boot_epoch() != resolver.boot_epoch())
    {
        return Err(TerminalJournalError::ConflictingTerminalResolver {
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
        });
    }
    let resolver_changed = match record.terminal_resolver {
        Some(existing) if existing == resolver => false,
        Some(_) => {
            return Err(TerminalJournalError::ConflictingTerminalResolver {
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
            });
        }
        None => {
            record.terminal_resolver = Some(resolver);
            true
        }
    };
    Ok(targets_changed || resolver_changed)
}

fn upsert_accepted_candidate_in_record(
    record: &mut TerminalJournalRecord,
    op_id: TerminalJournalOpId,
    candidate: CommitCandidate,
) -> Result<bool, TerminalJournalError> {
    if candidate.ballot() < record.promise_ballot {
        return Err(TerminalJournalError::AcceptBelowPromise {
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            ballot: candidate.ballot(),
            promised_ballot: record.promise_ballot,
        });
    }
    if let Some(decision) = record.terminal_decision() {
        return match decision {
            TerminalDecision::Commit {
                candidate: committed,
            } if committed.has_same_value(&candidate) => Ok(false),
            TerminalDecision::Commit { .. } | TerminalDecision::Abort { .. } => {
                Err(TerminalJournalError::ConflictingTerminalDecision {
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                })
            }
        };
    }

    match record.accepted_commit.as_ref() {
        Some(existing) if existing == &candidate => Ok(false),
        Some(existing) if existing.ballot() == candidate.ballot() => {
            Err(TerminalJournalError::ConflictingAcceptedValue {
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
            })
        }
        Some(existing) if existing.ballot() > candidate.ballot() => Ok(false),
        _ => {
            record.promise_ballot = record.promise_ballot.max(candidate.ballot());
            record.accepted_commit = Some(candidate);
            Ok(true)
        }
    }
}

fn upsert_decision_in_record(
    record: &mut TerminalJournalRecord,
    op_id: TerminalJournalOpId,
    decision: TerminalDecision,
) -> Result<bool, TerminalJournalError> {
    if let Some(existing) = record.terminal_decision() {
        match (existing, &decision) {
            (
                TerminalDecision::Commit {
                    candidate: existing_candidate,
                },
                TerminalDecision::Commit {
                    candidate: next_candidate,
                },
            ) if existing_candidate.has_same_value(next_candidate) => {
                if next_candidate.ballot() <= existing_candidate.ballot() {
                    return Ok(false);
                }
                record.promise_ballot = record.promise_ballot.max(next_candidate.ballot());
                record.accepted_commit = Some(next_candidate.clone());
                record.terminal_decision = Some(decision);
                return Ok(true);
            }
            (TerminalDecision::Commit { .. }, TerminalDecision::Abort { .. }) => {
                return Ok(false);
            }
            (
                TerminalDecision::Abort {
                    ballot: existing_ballot,
                },
                TerminalDecision::Abort {
                    ballot: next_ballot,
                },
            ) => {
                if next_ballot <= existing_ballot {
                    return Ok(false);
                }
                record.promise_ballot = record.promise_ballot.max(*next_ballot);
                record.terminal_decision = Some(decision);
                return Ok(true);
            }
            _ => {
                return Err(TerminalJournalError::ConflictingTerminalDecision {
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                });
            }
        }
    }

    let decision_ballot = decision.ballot();
    if decision_ballot < record.promise_ballot {
        return Err(TerminalJournalError::DecisionBelowPromise {
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            ballot: decision_ballot,
            promised_ballot: record.promise_ballot,
        });
    }

    match &decision {
        TerminalDecision::Commit { candidate } => {
            if let Some(accepted) = record.accepted_commit.as_ref() {
                if !accepted.has_same_value(candidate) {
                    return Err(TerminalJournalError::CommitDiffersFromAccepted {
                        op_id_hi: op_id.0,
                        op_id_lo: op_id.1,
                    });
                }
            }
            record.promise_ballot = record.promise_ballot.max(candidate.ballot());
            record.accepted_commit = Some(candidate.clone());
        }
        TerminalDecision::Abort { ballot } => {
            if record.accepted_commit.is_some() {
                return Err(TerminalJournalError::AbortAfterAccept {
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                });
            }
            record.promise_ballot = record.promise_ballot.max(*ballot);
        }
    }
    record.pending_proposal = None;
    record.terminal_decision = Some(decision);
    Ok(true)
}

/// A descriptor-bearing v2 decision may arrive after this replica made a
/// higher prepare promise. Promises fence new accepts; they must not prevent
/// learning an already chosen terminal outcome whose immutable membership and
/// resolver identity have been validated by the caller.
fn learn_v2_terminal_decision_in_record(
    record: &mut TerminalJournalRecord,
    op_id: TerminalJournalOpId,
    decision: TerminalDecision,
) -> Result<bool, TerminalJournalError> {
    if record.terminal_decision().is_some() || decision.ballot() >= record.promise_ballot {
        return upsert_decision_in_record(record, op_id, decision);
    }

    match &decision {
        TerminalDecision::Commit { candidate } => {
            if let Some(accepted) = record.accepted_commit.as_ref() {
                if !accepted.has_same_value(candidate) {
                    return Err(TerminalJournalError::CommitDiffersFromAccepted {
                        op_id_hi: op_id.0,
                        op_id_lo: op_id.1,
                    });
                }
            }
            record.accepted_commit = Some(candidate.clone());
        }
        TerminalDecision::Abort { .. } if record.accepted_commit.is_some() => {
            return Err(TerminalJournalError::AbortAfterAccept {
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
            });
        }
        TerminalDecision::Abort { .. } => {}
    }
    record.pending_proposal = None;
    record.terminal_decision = Some(decision);
    Ok(true)
}

#[derive(Serialize, Deserialize)]
struct PersistedTerminalJournal {
    version: u32,
    topic: String,
    #[serde(default)]
    terminal_decision_generation: u64,
    records: Vec<PersistedTerminalJournalRecord>,
}

#[derive(Serialize, Deserialize)]
struct PersistedTerminalJournalRecord {
    op_id_hi: u64,
    op_id_lo: u64,
    #[serde(flatten)]
    record: TerminalJournalRecord,
}

fn journal_path(root: Option<&Path>, topic: &str) -> Option<PathBuf> {
    let root = root.filter(|root| !root.as_os_str().is_empty())?;
    Some(
        root.join(JOURNAL_DIRECTORY)
            .join(format!("topic-{}.json", hex::encode(topic.as_bytes()))),
    )
}

fn journal_lock_path(path: &Path) -> PathBuf {
    path.with_extension("lock")
}

fn load_records(
    path: &Path,
    expected_topic: &str,
    bytes: &[u8],
) -> Result<(BTreeMap<TerminalJournalOpId, TerminalJournalRecord>, u64), TerminalJournalError> {
    let payload: PersistedTerminalJournal =
        serde_json::from_slice(bytes).map_err(|source| TerminalJournalError::Json {
            path: path.to_path_buf(),
            source,
        })?;
    if payload.version != JOURNAL_VERSION {
        return Err(TerminalJournalError::UnsupportedVersion {
            path: path.to_path_buf(),
            version: payload.version,
        });
    }
    if payload.topic != expected_topic {
        return Err(TerminalJournalError::TopicMismatch {
            path: path.to_path_buf(),
            expected: expected_topic.to_owned(),
            found: payload.topic,
        });
    }

    let mut records = BTreeMap::new();
    for entry in payload.records {
        let op_id = (entry.op_id_hi, entry.op_id_lo);
        if records.contains_key(&op_id) {
            return Err(TerminalJournalError::DuplicateRecord {
                path: path.to_path_buf(),
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
            });
        }
        validate_record(path, op_id, &entry.record)?;
        records.insert(op_id, entry.record);
    }
    // Journals written before the generation field existed must not use zero
    // as a successful fence-sync token when they already contain decisions.
    // One is sufficient: every subsequent newly learned decision advances it.
    let terminal_decision_generation = if payload.terminal_decision_generation == 0
        && records.values().any(TerminalJournalRecord::is_terminal)
    {
        1
    } else {
        payload.terminal_decision_generation
    };
    Ok((records, terminal_decision_generation))
}

fn validate_record(
    path: &Path,
    op_id: TerminalJournalOpId,
    record: &TerminalJournalRecord,
) -> Result<(), TerminalJournalError> {
    let invalid = |reason| TerminalJournalError::InvalidRecord {
        path: path.to_path_buf(),
        op_id_hi: op_id.0,
        op_id_lo: op_id.1,
        reason,
    };

    if let Some(frozen_targets) = record.frozen_targets() {
        if !FrozenTarget::is_valid_descriptor(frozen_targets) {
            return Err(invalid(
                "frozen target descriptor is empty, unordered, or has duplicate nodes",
            ));
        }
    }
    if record.pending_proposal().is_some() && record.frozen_targets().is_none() {
        return Err(invalid(
            "pending v2 proposal is missing its frozen target descriptor",
        ));
    }
    if record.terminal_decision().is_none() && record.terminal_resolver().is_some() {
        return Err(invalid(
            "nonterminal record retains a terminal resolver identity",
        ));
    }

    if let Some(accepted) = record.accepted_commit() {
        if accepted.ballot() > record.promise_ballot() {
            return Err(invalid("accepted commit ballot exceeds promised ballot"));
        }
    }

    let Some(decision) = record.terminal_decision() else {
        return Ok(());
    };
    if record.pending_proposal().is_some() {
        return Err(invalid("terminal decision retains a pending proposal"));
    }
    if decision.ballot() > record.promise_ballot() {
        return Err(invalid("terminal decision ballot exceeds promised ballot"));
    }
    match (record.frozen_targets(), record.terminal_resolver()) {
        (None, None) => {}
        (Some(targets), Some(resolver))
            if FrozenTarget::find_in_canonical(targets, resolver.node())
                .is_some_and(|target| target.boot_epoch() == resolver.boot_epoch()) => {}
        (Some(_), None) => {
            return Err(invalid(
                "v2 terminal decision is missing its resolver identity",
            ));
        }
        (None, Some(_)) => {
            return Err(invalid(
                "legacy terminal decision unexpectedly has a resolver identity",
            ));
        }
        (Some(_), Some(_)) => {
            return Err(invalid(
                "v2 terminal resolver is not present in the frozen target descriptor",
            ));
        }
    }

    match decision {
        TerminalDecision::Commit { candidate } => match record.accepted_commit() {
            Some(accepted) if accepted == candidate => Ok(()),
            Some(_) => Err(invalid("terminal commit differs from accepted commit")),
            None => Err(invalid("terminal commit is missing its accepted commit")),
        },
        TerminalDecision::Abort { .. } if record.accepted_commit().is_some() => {
            Err(invalid("terminal abort follows an accepted commit"))
        }
        TerminalDecision::Abort { .. } => Ok(()),
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let id = NEXT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
    path.with_extension(format!("json.{}.{}.tmp", std::process::id(), id))
}

fn write_temporary_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(windows))]
fn replace_file_atomically(temporary_path: &Path, path: &Path) -> io::Result<()> {
    fs::rename(temporary_path, path)
}

#[cfg(windows)]
fn replace_file_atomically(temporary_path: &Path, path: &Path) -> io::Result<()> {
    let temporary_wide = windows_api_path(temporary_path)?;
    let path_wide = windows_api_path(path)?;

    // The temporary journal lives beside its destination, so this is a
    // same-volume replacement. `MOVEFILE_WRITE_THROUGH` is supported here
    // and makes `MoveFileExW` wait until the move reaches disk.
    let moved = unsafe {
        MoveFileExW(
            temporary_wide.as_ptr(),
            path_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn windows_api_path(path: &Path) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal replacement path has no parent directory",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal replacement path has no file name",
        )
    })?;

    // `canonicalize` returns Windows' extended-length path form. Canonicalize
    // the already-created parent because a first-write destination does not
    // exist yet, then reattach its single path component.
    let absolute_path = fs::canonicalize(parent)?.join(file_name);
    let mut wide = absolute_path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal replacement path contains an embedded NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<(), TerminalJournalError> {
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|source| TerminalJournalError::Io {
            path: parent.to_path_buf(),
            source,
        })
}

#[cfg(windows)]
fn sync_parent_directory(_parent: &Path) -> Result<(), TerminalJournalError> {
    // Windows does not expose a directory fsync through `std`. The replacement
    // call above uses `MOVEFILE_WRITE_THROUGH` and waits for the move to disk.
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn sync_parent_directory(_parent: &Path) -> Result<(), TerminalJournalError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{env, fs, process::Command};

    use bytes::Bytes;
    use tempfile::TempDir;

    use super::{
        FrozenTarget, TerminalDecision, TerminalJournal, TerminalJournalError, TerminalResolver,
    };

    #[test]
    fn in_memory_journal_tracks_promise_accept_and_commit() {
        let mut journal = TerminalJournal::in_memory("channels");
        assert!(!journal.durable_persistence_enabled());
        assert!(journal.upsert_promise((1, 2), 7).unwrap());
        assert!(
            journal
                .upsert_accepted_bytes((1, 2), 7, 99, Bytes::from_static(b"op"))
                .unwrap()
        );
        assert!(
            journal
                .upsert_commit_decision((1, 2), 7, 99, b"op".to_vec())
                .unwrap()
        );

        let record = journal.get((1, 2)).unwrap();
        assert_eq!(record.promise_ballot(), 7);
        assert_eq!(record.accepted_commit().unwrap().ts_final(), 99);
        assert_eq!(
            record
                .terminal_decision()
                .unwrap()
                .committed_candidate()
                .unwrap()
                .op_msgpack(),
            b"op"
        );
        assert_eq!(journal.snapshot().len(), 1);
    }

    #[test]
    fn durable_journal_survives_reload_with_owned_payload() {
        let root = TempDir::new().unwrap();
        let path;
        {
            let mut journal =
                TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
            assert!(journal.durable_persistence_enabled());
            assert!(journal.upsert_promise((3, 4), 12).unwrap());
            assert!(
                journal
                    .upsert_accepted((3, 4), 12, 55, vec![0, 1, 2, 255])
                    .unwrap()
            );
            assert!(journal.upsert_abort_decision((9, 9), 18).unwrap());
            path = journal.persistence_path().unwrap().to_path_buf();
        }

        assert!(path.is_file());
        let reloaded = TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
        let accepted = reloaded.get((3, 4)).unwrap().accepted_commit().unwrap();
        assert_eq!(accepted.ballot(), 12);
        assert_eq!(accepted.ts_final(), 55);
        assert_eq!(accepted.op_msgpack(), [0, 1, 2, 255]);
        assert!(
            reloaded
                .get((9, 9))
                .unwrap()
                .terminal_decision()
                .unwrap()
                .is_abort()
        );
        let directory = path.parent().unwrap();
        assert!(fs::read_dir(directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[test]
    fn v2_pending_descriptor_and_accept_survive_reload() {
        let root = TempDir::new().unwrap();
        let op_id = (7, 8);
        let frozen_targets = vec![FrozenTarget::new(1, 10), FrozenTarget::new(4, 40)];
        {
            let mut journal =
                TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
            assert!(
                journal
                    .upsert_v2_pending_bytes(
                        op_id,
                        &frozen_targets,
                        55,
                        Bytes::from_static(b"prepared-op"),
                    )
                    .unwrap()
            );
            assert!(
                journal
                    .upsert_v2_promise(op_id, &frozen_targets, 12)
                    .unwrap()
            );
            assert!(
                journal
                    .upsert_v2_accepted_bytes(
                        op_id,
                        &frozen_targets,
                        12,
                        77,
                        Bytes::from_static(b"prepared-op"),
                    )
                    .unwrap()
            );
        }

        let reloaded = TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
        let record = reloaded.get(op_id).unwrap();
        assert_eq!(record.frozen_targets(), Some(frozen_targets.as_slice()));
        let pending = record.pending_proposal().unwrap();
        assert_eq!(pending.ts_local(), 55);
        assert_eq!(pending.op_msgpack(), b"prepared-op");
        let accepted = record.accepted_commit().unwrap();
        assert_eq!(accepted.ballot(), 12);
        assert_eq!(accepted.ts_final(), 77);
        assert_eq!(accepted.op_msgpack(), b"prepared-op");
    }

    #[test]
    fn v2_cold_receiver_terminal_commit_persists_descriptor_atomically() {
        let root = TempDir::new().unwrap();
        let op_id = (11, 12);
        let frozen_targets = vec![FrozenTarget::new(1, 10), FrozenTarget::new(4, 40)];
        {
            let mut journal =
                TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
            assert!(
                journal
                    .upsert_v2_commit_decision_bytes(
                        op_id,
                        &frozen_targets,
                        TerminalResolver::new(1, 10),
                        12,
                        77,
                        Bytes::from_static(b"cold-receiver-op"),
                    )
                    .unwrap()
            );

            let record = journal.get(op_id).unwrap();
            assert_eq!(record.frozen_targets(), Some(frozen_targets.as_slice()));
            assert!(record.pending_proposal().is_none());
            assert_eq!(record.promise_ballot(), 12);
            assert_eq!(record.accepted_commit().unwrap().ballot(), 12);
            assert_eq!(record.accepted_commit().unwrap().ts_final(), 77);
            assert_eq!(
                record
                    .terminal_decision()
                    .unwrap()
                    .committed_candidate()
                    .unwrap()
                    .op_msgpack(),
                b"cold-receiver-op"
            );
        }

        let reloaded = TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
        let record = reloaded.get(op_id).unwrap();
        assert_eq!(record.frozen_targets(), Some(frozen_targets.as_slice()));
        assert!(record.pending_proposal().is_none());
        assert_eq!(record.promise_ballot(), 12);
        assert_eq!(record.accepted_commit().unwrap().ts_final(), 77);
        assert_eq!(
            record
                .terminal_decision()
                .unwrap()
                .committed_candidate()
                .unwrap()
                .op_msgpack(),
            b"cold-receiver-op"
        );
    }

    #[test]
    fn v2_terminal_abort_retains_descriptor_and_rejects_partial_or_conflicting_updates() {
        let mut journal = TerminalJournal::in_memory("channels");
        let op_id = (13, 14);
        let frozen_targets = vec![FrozenTarget::new(1, 10), FrozenTarget::new(4, 40)];

        assert!(
            journal
                .upsert_v2_pending_bytes(
                    op_id,
                    &frozen_targets,
                    50,
                    Bytes::from_static(b"prepared-op"),
                )
                .unwrap()
        );
        assert!(
            journal
                .upsert_v2_abort_decision(op_id, &frozen_targets, TerminalResolver::new(1, 10), 8,)
                .unwrap()
        );
        let record = journal.get(op_id).unwrap();
        assert_eq!(record.frozen_targets(), Some(frozen_targets.as_slice()));
        assert!(record.pending_proposal().is_none());
        assert!(record.terminal_decision().unwrap().is_abort());

        let conflicting_targets = vec![FrozenTarget::new(1, 10), FrozenTarget::new(4, 41)];
        assert!(matches!(
            journal.upsert_v2_abort_decision(
                op_id,
                &conflicting_targets,
                TerminalResolver::new(1, 10),
                9,
            ),
            Err(TerminalJournalError::ConflictingFrozenTargets { .. })
        ));
        let record = journal.get(op_id).unwrap();
        assert_eq!(record.frozen_targets(), Some(frozen_targets.as_slice()));
        assert_eq!(record.terminal_decision().unwrap().ballot(), 8);

        let low_ballot_op = (15, 16);
        assert!(journal.upsert_promise(low_ballot_op, 10).unwrap());
        // A chosen V2 decision remains learnable after a later local
        // prepare promise. The promise fences future accepts; it cannot
        // retroactively invalidate a terminal quorum decision.
        assert!(
            journal
                .upsert_v2_abort_decision(
                    low_ballot_op,
                    &frozen_targets,
                    TerminalResolver::new(1, 10),
                    9,
                )
                .unwrap()
        );
        let record = journal.get(low_ballot_op).unwrap();
        assert_eq!(record.frozen_targets(), Some(frozen_targets.as_slice()));
        assert_eq!(record.promise_ballot(), 10);
        assert_eq!(record.terminal_decision().unwrap().ballot(), 9);

        let invalid_descriptor_op = (17, 18);
        assert!(matches!(
            journal.upsert_v2_abort_decision(
                invalid_descriptor_op,
                &[],
                TerminalResolver::new(1, 10),
                1,
            ),
            Err(TerminalJournalError::InvalidFrozenTargets { .. })
        ));
        assert!(journal.get(invalid_descriptor_op).is_none());
    }

    #[test]
    fn v2_target_descriptors_are_canonical_immutable_and_clear_when_terminal() {
        let canonical = vec![FrozenTarget::new(1, 10), FrozenTarget::new(4, 40)];
        assert!(FrozenTarget::is_canonical(&canonical));
        assert!(FrozenTarget::is_valid_descriptor(&canonical));
        assert_eq!(
            FrozenTarget::canonicalize(vec![FrozenTarget::new(4, 40), FrozenTarget::new(1, 10)]),
            Some(canonical.clone())
        );
        assert_eq!(
            FrozenTarget::canonicalize(vec![FrozenTarget::new(1, 10), FrozenTarget::new(1, 11)]),
            None
        );
        assert_eq!(
            FrozenTarget::find_in_canonical(&canonical, 4).map(FrozenTarget::boot_epoch),
            Some(40)
        );

        let mut journal = TerminalJournal::in_memory("channels");
        assert!(
            journal
                .upsert_v2_pending((1, 2), &canonical, 5, b"op".to_vec())
                .unwrap()
        );
        assert!(matches!(
            journal.upsert_v2_promise((1, 2), &[FrozenTarget::new(1, 10)], 6),
            Err(TerminalJournalError::ConflictingFrozenTargets { .. })
        ));
        assert!(matches!(
            journal.upsert_v2_accepted_bytes(
                (1, 2),
                &[FrozenTarget::new(1, 10)],
                6,
                9,
                Bytes::from_static(b"op"),
            ),
            Err(TerminalJournalError::ConflictingFrozenTargets { .. })
        ));
        assert!(matches!(
            journal.upsert_v2_pending((1, 2), &canonical, 6, b"other".to_vec()),
            Err(TerminalJournalError::ConflictingPendingProposal { .. })
        ));
        assert!(matches!(
            journal.upsert_v2_pending(
                (3, 4),
                &[FrozenTarget::new(1, 10), FrozenTarget::new(1, 11)],
                1,
                b"invalid".to_vec(),
            ),
            Err(TerminalJournalError::InvalidFrozenTargets { .. })
        ));
        assert!(journal.get((3, 4)).is_none());

        assert!(
            journal
                .upsert_v2_abort_decision((1, 2), &canonical, TerminalResolver::new(1, 10), 0,)
                .unwrap()
        );
        let record = journal.get((1, 2)).unwrap();
        assert_eq!(record.frozen_targets(), Some(canonical.as_slice()));
        assert!(record.pending_proposal().is_none());
        assert!(
            !journal
                .upsert_v2_pending((1, 2), &canonical, 5, b"op".to_vec())
                .unwrap()
        );
    }

    #[test]
    fn durable_journal_replaces_existing_file_on_second_update() {
        let root = TempDir::new().unwrap();
        {
            let mut journal =
                TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
            assert!(journal.upsert_promise((1, 2), 7).unwrap());
            assert!(journal.upsert_promise((3, 4), 9).unwrap());
        }

        let reloaded = TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
        assert_eq!(reloaded.get((1, 2)).unwrap().promise_ballot(), 7);
        assert_eq!(reloaded.get((3, 4)).unwrap().promise_ballot(), 9);
    }

    #[cfg(windows)]
    #[test]
    fn windows_replacement_path_uses_extended_length_form() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("journal.json");

        let wide = super::windows_api_path(&path).unwrap();
        assert_eq!(
            &wide[..4],
            &[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16]
        );
        assert_eq!(wide.last(), Some(&0));
    }

    #[test]
    fn durable_journal_lock_excludes_another_process_after_mutation() {
        let root = TempDir::new().unwrap();
        let topic = "channels";
        let probe_result = root.path().join("lock-probe-result");
        let mut journal = TerminalJournal::load(Some(root.path().to_path_buf()), topic).unwrap();
        assert!(journal.upsert_promise((3, 4), 12).unwrap());

        let other_topic = TerminalJournal::load(Some(root.path().to_path_buf()), "users").unwrap();
        drop(other_topic);

        let status = Command::new(env::current_exe().unwrap())
            .arg("durable_journal_lock_probe")
            .arg("--nocapture")
            .env("SHITSPEAK_TERMINAL_JOURNAL_LOCK_PROBE_ROOT", root.path())
            .env(
                "SHITSPEAK_TERMINAL_JOURNAL_LOCK_PROBE_RESULT",
                &probe_result,
            )
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(fs::read_to_string(&probe_result).unwrap(), "already_locked");

        drop(journal);
        assert!(TerminalJournal::load(Some(root.path().to_path_buf()), topic).is_ok());
    }

    #[test]
    fn durable_journal_lock_probe() {
        let Some(root) = env::var_os("SHITSPEAK_TERMINAL_JOURNAL_LOCK_PROBE_ROOT") else {
            return;
        };
        let result = env::var_os("SHITSPEAK_TERMINAL_JOURNAL_LOCK_PROBE_RESULT").unwrap();

        assert!(matches!(
            TerminalJournal::load(Some(root.into()), "channels"),
            Err(TerminalJournalError::AlreadyLocked { .. })
        ));
        fs::write(result, "already_locked").unwrap();
    }

    #[test]
    fn promise_and_accept_updates_are_monotonic() {
        let mut journal = TerminalJournal::in_memory("channels");
        assert!(journal.upsert_promise((1, 1), 10).unwrap());
        assert!(!journal.upsert_promise((1, 1), 9).unwrap());
        assert!(
            journal
                .upsert_accepted((1, 1), 11, 100, b"new".to_vec())
                .unwrap()
        );
        assert!(matches!(
            journal.upsert_accepted((1, 1), 10, 100, b"old".to_vec()),
            Err(TerminalJournalError::AcceptBelowPromise { .. })
        ));
        assert_eq!(journal.get((1, 1)).unwrap().promise_ballot(), 11);
        assert_eq!(
            journal
                .get((1, 1))
                .unwrap()
                .accepted_commit()
                .unwrap()
                .op_msgpack(),
            b"new"
        );
    }

    #[test]
    fn terminal_commit_can_be_rebroadcast_at_a_higher_resolution_ballot() {
        let mut journal = TerminalJournal::in_memory("channels");
        assert!(
            journal
                .upsert_commit_decision((1, 1), 3, 10, b"value".to_vec())
                .unwrap()
        );
        assert!(
            journal
                .upsert_commit_decision((1, 1), 4, 10, b"value".to_vec())
                .unwrap()
        );
        assert_eq!(
            journal
                .get((1, 1))
                .unwrap()
                .terminal_decision()
                .unwrap()
                .ballot(),
            4
        );
        assert!(!journal.upsert_abort_decision((1, 1), 4).unwrap());
        assert!(matches!(
            journal.upsert_commit_decision((1, 1), 5, 10, b"other".to_vec()),
            Err(TerminalJournalError::ConflictingTerminalDecision { .. })
        ));

        let mut accepted = TerminalJournal::in_memory("users");
        accepted
            .upsert_accepted((2, 2), 3, 11, b"value".to_vec())
            .unwrap();
        assert!(matches!(
            accepted.upsert_abort_decision((2, 2), 4),
            Err(TerminalJournalError::AbortAfterAccept { .. })
        ));
    }

    #[test]
    fn journal_rejects_duplicate_serialized_operation_ids() {
        let root = TempDir::new().unwrap();
        let topic = "channels";
        let directory = root.path().join("strict-terminal-journal");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!("topic-{}.json", hex::encode(topic.as_bytes())));
        fs::write(
            path,
            r#"{"version":1,"topic":"channels","records":[{"op_id_hi":1,"op_id_lo":2,"promise_ballot":3},{"op_id_hi":1,"op_id_lo":2,"promise_ballot":4}]}"#,
        )
        .unwrap();

        assert!(matches!(
            TerminalJournal::load(Some(root.path().to_path_buf()), topic),
            Err(TerminalJournalError::DuplicateRecord { .. })
        ));
    }

    #[test]
    fn journal_rejects_persisted_records_that_violate_mutation_invariants() {
        let records = [
            (
                "accepted ballot above promise",
                r#"{"op_id_hi":1,"op_id_lo":2,"promise_ballot":3,"accepted_commit":{"ballot":4,"ts_final":5,"op_msgpack":[1]}}"#,
            ),
            (
                "abort after accept",
                r#"{"op_id_hi":1,"op_id_lo":2,"promise_ballot":4,"accepted_commit":{"ballot":4,"ts_final":5,"op_msgpack":[1]},"terminal_decision":{"outcome":"abort","ballot":4}}"#,
            ),
            (
                "commit without accept",
                r#"{"op_id_hi":1,"op_id_lo":2,"promise_ballot":4,"terminal_decision":{"outcome":"commit","candidate":{"ballot":4,"ts_final":5,"op_msgpack":[1]}}}"#,
            ),
            (
                "commit differs from accept",
                r#"{"op_id_hi":1,"op_id_lo":2,"promise_ballot":4,"accepted_commit":{"ballot":4,"ts_final":5,"op_msgpack":[1]},"terminal_decision":{"outcome":"commit","candidate":{"ballot":4,"ts_final":6,"op_msgpack":[2]}}}"#,
            ),
            (
                "pending proposal without frozen targets",
                r#"{"op_id_hi":1,"op_id_lo":2,"promise_ballot":0,"pending_proposal":{"ts_local":5,"op_msgpack":[1]}}"#,
            ),
            (
                "unordered frozen targets",
                r#"{"op_id_hi":1,"op_id_lo":2,"promise_ballot":0,"frozen_targets":[{"node":4,"boot_epoch":4},{"node":1,"boot_epoch":1}]}"#,
            ),
            (
                "terminal decision retains pending proposal",
                r#"{"op_id_hi":1,"op_id_lo":2,"promise_ballot":4,"frozen_targets":[{"node":1,"boot_epoch":1}],"pending_proposal":{"ts_local":3,"op_msgpack":[1]},"terminal_decision":{"outcome":"abort","ballot":4}}"#,
            ),
        ];

        for (name, record) in records {
            let root = TempDir::new().unwrap();
            let topic = "channels";
            let directory = root.path().join("strict-terminal-journal");
            fs::create_dir_all(&directory).unwrap();
            let path = directory.join(format!("topic-{}.json", hex::encode(topic.as_bytes())));
            fs::write(
                path,
                format!(r#"{{"version":1,"topic":"{topic}","records":[{record}]}}"#),
            )
            .unwrap();

            assert!(
                matches!(
                    TerminalJournal::load(Some(root.path().to_path_buf()), topic),
                    Err(TerminalJournalError::InvalidRecord { .. })
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn terminal_decision_serializes_a_tagged_outcome() {
        let encoded = serde_json::to_string(&TerminalDecision::abort(5)).unwrap();
        assert!(encoded.contains(r#""outcome":"abort""#));
    }
}
