//! Durable state for strict protocol terminal-resolution records.
//!
//! The strict runtime owns one journal per topic and calls these synchronous
//! methods while holding its state lock. Durable mutations commit one encoded
//! record and the resulting terminal cut in a SQLite transaction.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions, TryLockError},
    io,
    path::{Path, PathBuf},
};

use aws_lc_rs::{
    digest::{SHA256, digest},
    rand::{SecureRandom, SystemRandom},
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::terminal_journal_sqlite::{SqliteTerminalJournalError, SqliteTerminalJournalStore};

const JOURNAL_DIRECTORY: &str = "strict-terminal-journal";
const JOURNAL_VERSION: u32 = 2;
const LEGACY_JOURNAL_VERSION: u32 = 1;
const JOURNAL_ID_LEN: usize = 16;
const DIGEST_LEN: usize = 32;
const EMPTY_CHAIN_DIGEST: [u8; DIGEST_LEN] = [0; DIGEST_LEN];

/// An operation identifier encoded by strict protocol messages as `(hi, lo)`.
pub(crate) type TerminalJournalOpId = (u64, u64);

/// A durable, source-specific name for one terminal-journal fence cut.
///
/// The lineage and chain identify an ordered source history. The terminal-set
/// digest identifies the order-independent set of fences at the cut, allowing
/// independently learned but equivalent terminal state to take the fast path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TerminalCut {
    journal_id: [u8; JOURNAL_ID_LEN],
    generation: u64,
    chain_digest: [u8; DIGEST_LEN],
    terminal_set_digest: [u8; DIGEST_LEN],
}

impl TerminalCut {
    pub(crate) fn new(
        journal_id: [u8; JOURNAL_ID_LEN],
        generation: u64,
        chain_digest: [u8; DIGEST_LEN],
        terminal_set_digest: [u8; DIGEST_LEN],
    ) -> Self {
        Self {
            journal_id,
            generation,
            chain_digest,
            terminal_set_digest,
        }
    }

    pub(crate) fn journal_id(&self) -> &[u8; JOURNAL_ID_LEN] {
        &self.journal_id
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn chain_digest(&self) -> &[u8; DIGEST_LEN] {
        &self.chain_digest
    }

    pub(crate) fn terminal_set_digest(&self) -> &[u8; DIGEST_LEN] {
        &self.terminal_set_digest
    }

    /// Compare the authenticated ordered position while deliberately ignoring
    /// the set digest. Intermediate v3 delta pages carry the source chain
    /// position, but the complete canonical set digest is only authenticated
    /// once the fixed transfer target has been installed.
    pub(crate) fn has_same_chain_position(&self, other: &Self) -> bool {
        self.journal_id == other.journal_id
            && self.generation == other.generation
            && self.chain_digest == other.chain_digest
    }
}

/// The exact source-journal transition assigned when one operation first
/// became terminal.
///
/// Runtime decision construction obtains this value while still holding the
/// journal mutation lock. That prevents a concurrent append from making an
/// outbound decision advertise another operation's generation or digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TerminalTransition {
    previous_cut: TerminalCut,
    resulting_cut: TerminalCut,
    decision_digest: [u8; DIGEST_LEN],
}

impl TerminalTransition {
    pub(crate) fn previous_cut(&self) -> TerminalCut {
        self.previous_cut
    }

    pub(crate) fn resulting_cut(&self) -> TerminalCut {
        self.resulting_cut
    }

    /// Check that another journal lineage assigned this exact durable
    /// decision at the advertised contiguous transition.
    pub(crate) fn verifies_source_transition(
        &self,
        source_previous: &TerminalCut,
        source_resulting: &TerminalCut,
    ) -> bool {
        source_previous.journal_id == source_resulting.journal_id
            && source_previous.generation.checked_add(1) == Some(source_resulting.generation)
            && terminal_chain_digest(
                source_resulting.journal_id,
                source_previous.chain_digest,
                source_resulting.generation,
                self.decision_digest,
            ) == source_resulting.chain_digest
    }
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_chain_digest: Option<[u8; DIGEST_LEN]>,
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

    pub(crate) fn terminal_generation(&self) -> Option<u64> {
        self.terminal_generation
    }

    pub(crate) fn terminal_chain_digest(&self) -> Option<&[u8; DIGEST_LEN]> {
        self.terminal_chain_digest.as_ref()
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

/// One ordered terminal delta returned by [`TerminalJournal::terminal_deltas_after`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TerminalJournalDeltaEntry {
    generation: u64,
    chain_digest: [u8; DIGEST_LEN],
    op_id: TerminalJournalOpId,
    record: TerminalJournalRecord,
}

impl TerminalJournalDeltaEntry {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        u64,
        [u8; DIGEST_LEN],
        TerminalJournalOpId,
        TerminalJournalRecord,
    ) {
        (self.generation, self.chain_digest, self.op_id, self.record)
    }
}

/// A bounded immutable terminal-delta page captured at one target cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TerminalJournalDeltaPage {
    base: TerminalCut,
    target: TerminalCut,
    entries: Vec<TerminalJournalDeltaEntry>,
    has_more: bool,
}

impl TerminalJournalDeltaPage {
    #[cfg(test)]
    pub(crate) fn base(&self) -> TerminalCut {
        self.base
    }

    #[cfg(test)]
    pub(crate) fn target(&self) -> TerminalCut {
        self.target
    }

    #[cfg(test)]
    pub(crate) fn entries(&self) -> &[TerminalJournalDeltaEntry] {
        &self.entries
    }

    #[cfg(test)]
    pub(crate) fn has_more(&self) -> bool {
        self.has_more
    }

    pub(crate) fn into_entries(self) -> Vec<TerminalJournalDeltaEntry> {
        self.entries
    }
}

/// A bounded exact-state checkpoint page containing terminal records only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TerminalJournalCheckpointPage {
    target: TerminalCut,
    cursor: u64,
    next_cursor: u64,
    entries: Vec<TerminalJournalSnapshotEntry>,
    has_more: bool,
}

impl TerminalJournalCheckpointPage {
    #[cfg(test)]
    pub(crate) fn target(&self) -> TerminalCut {
        self.target
    }

    pub(crate) fn cursor(&self) -> u64 {
        self.cursor
    }

    #[cfg(test)]
    pub(crate) fn next_cursor(&self) -> u64 {
        self.next_cursor
    }

    #[cfg(test)]
    pub(crate) fn entries(&self) -> &[TerminalJournalSnapshotEntry] {
        &self.entries
    }

    #[cfg(test)]
    pub(crate) fn has_more(&self) -> bool {
        self.has_more
    }

    pub(crate) fn into_entries(self) -> Vec<TerminalJournalSnapshotEntry> {
        self.entries
    }
}

/// Persistence or invariant failure from the terminal-resolution journal.
#[derive(Debug, Error)]
pub(crate) enum TerminalJournalError {
    #[error(transparent)]
    Sqlite(#[from] SqliteTerminalJournalError),
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
    #[error("strict terminal journal could not generate a journal lineage identifier")]
    JournalIdGeneration,
    #[error("invalid strict terminal journal metadata at {path:?}: {reason}")]
    InvalidMetadata { path: PathBuf, reason: &'static str },
}

/// A per-topic terminal-resolution journal.
///
/// With `None` (or an empty path) for `root`, the journal is intentionally
/// in-memory. This supports tests and keeps the caller responsible for
/// refusing the durable protocol version when persistence is unavailable.
pub(crate) struct TerminalJournal {
    path: Option<PathBuf>,
    // Retains the stable per-topic sidecar lock for this process lifetime.
    _lock_file: Option<File>,
    store: Option<SqliteTerminalJournalStore>,
    records: BTreeMap<TerminalJournalOpId, TerminalJournalRecord>,
    journal_id: [u8; JOURNAL_ID_LEN],
    // Persisted monotonic fence-cut identifier. Catchup peers echo this only
    // after they have installed every terminal decision in the corresponding
    // stable journal snapshot.
    terminal_decision_generation: u64,
    terminal_chain_digest: [u8; DIGEST_LEN],
    terminal_set_digest: [u8; DIGEST_LEN],
    generation_index: BTreeMap<u64, TerminalJournalOpId>,
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
            let journal_id = generate_journal_id()?;
            let terminal_set_digest = compute_terminal_set_digest(&BTreeMap::new());
            return Ok(Self {
                path: None,
                _lock_file: None,
                store: None,
                records: BTreeMap::new(),
                journal_id,
                terminal_decision_generation: 0,
                terminal_chain_digest: EMPTY_CHAIN_DIGEST,
                terminal_set_digest,
                generation_index: BTreeMap::new(),
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

        let mut store = SqliteTerminalJournalStore::open(&path, topic.clone())?;
        let loaded = if let Some(loaded) = store.load()? {
            let (mut records, cut) = loaded.into_parts();
            let derived = validate_loaded_sqlite(&path, &mut records, &cut)?;
            LoadedTerminalJournal::from_derived(records, *cut.journal_id(), derived)
        } else {
            let legacy_path = legacy_journal_path(&path);
            let loaded = match fs::read(&legacy_path) {
                Ok(bytes) => load_records(&legacy_path, &topic, &bytes)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    LoadedTerminalJournal::empty(generate_journal_id()?)
                }
                Err(source) => {
                    return Err(TerminalJournalError::Io {
                        path: legacy_path,
                        source,
                    });
                }
            };
            let cut = TerminalCut::new(
                loaded.journal_id,
                loaded.terminal_decision_generation,
                loaded.terminal_chain_digest,
                loaded.terminal_set_digest,
            );
            // The legacy JSON remains in place as a rollback artifact. Once
            // this transaction commits SQLite is the sole authoritative
            // journal and subsequent startups never consult the JSON file.
            store.replace_all(loaded.records.iter(), &cut)?;
            loaded
        };

        Ok(Self {
            path: Some(path),
            _lock_file: Some(lock_file),
            store: Some(store),
            records: loaded.records,
            journal_id: loaded.journal_id,
            terminal_decision_generation: loaded.terminal_decision_generation,
            terminal_chain_digest: loaded.terminal_chain_digest,
            terminal_set_digest: loaded.terminal_set_digest,
            generation_index: loaded.generation_index,
        })
    }

    pub(crate) fn in_memory(_topic: impl Into<String>) -> Self {
        let journal_id = generate_journal_id()
            .expect("the system random generator must provide a terminal journal id");
        Self {
            path: None,
            _lock_file: None,
            store: None,
            records: BTreeMap::new(),
            journal_id,
            terminal_decision_generation: 0,
            terminal_chain_digest: EMPTY_CHAIN_DIGEST,
            terminal_set_digest: compute_terminal_set_digest(&BTreeMap::new()),
            generation_index: BTreeMap::new(),
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

    pub(crate) fn terminal_cut(&self) -> TerminalCut {
        TerminalCut::new(
            self.journal_id,
            self.terminal_decision_generation,
            self.terminal_chain_digest,
            self.terminal_set_digest,
        )
    }

    /// Return the exact authenticated cut for one retained generation.
    /// Generation zero names the empty prefix of this journal lineage.
    pub(crate) fn terminal_cut_at(&self, generation: u64) -> Option<TerminalCut> {
        if generation > self.terminal_decision_generation {
            return None;
        }
        let chain_digest = if generation == 0 {
            EMPTY_CHAIN_DIGEST
        } else {
            *self
                .generation_index
                .get(&generation)
                .and_then(|op_id| self.records.get(op_id))
                .and_then(TerminalJournalRecord::terminal_chain_digest)?
        };
        Some(TerminalCut::new(
            self.journal_id,
            generation,
            chain_digest,
            compute_terminal_set_digest_through(&self.records, generation),
        ))
    }

    /// Return the immutable transition assigned to one terminal record.
    pub(crate) fn terminal_transition(
        &self,
        op_id: TerminalJournalOpId,
    ) -> Option<TerminalTransition> {
        let record = self.records.get(&op_id)?;
        let generation = record.terminal_generation()?;
        Some(TerminalTransition {
            previous_cut: self.terminal_cut_at(generation.checked_sub(1)?)?,
            resulting_cut: self.terminal_cut_at(generation)?,
            decision_digest: canonical_terminal_decision_digest(op_id, record),
        })
    }

    pub(crate) fn terminal_set_matches(&self, digest: &[u8]) -> bool {
        digest == self.terminal_set_digest.as_slice()
    }

    /// Verify one source-journal transition without mutating this journal.
    ///
    /// This is intentionally expressed in durable journal types rather than
    /// protobuf types. Callers must first validate and canonicalize the wire
    /// terminal identity exactly as normal decision installation does.
    pub(crate) fn verifies_terminal_transition(
        previous: &TerminalCut,
        generation: u64,
        op_id: TerminalJournalOpId,
        frozen_targets: Option<&[FrozenTarget]>,
        resolver: Option<TerminalResolver>,
        decision: &TerminalDecision,
        advertised_previous_chain_digest: &[u8],
        advertised_chain_digest: &[u8],
    ) -> bool {
        if advertised_previous_chain_digest != previous.chain_digest.as_slice()
            || advertised_chain_digest.len() != DIGEST_LEN
        {
            return false;
        }
        Self::terminal_transition_chain_digest(
            previous,
            generation,
            op_id,
            frozen_targets,
            resolver,
            decision,
        )
        .is_some_and(|digest| digest.as_slice() == advertised_chain_digest)
    }

    /// Calculate the authenticated chain result for one already validated
    /// canonical terminal state. Checkpoint receivers use this to reconstruct
    /// and verify the source chain even though checkpoint entries omit the
    /// redundant per-record chain fields.
    pub(crate) fn terminal_transition_chain_digest(
        previous: &TerminalCut,
        generation: u64,
        op_id: TerminalJournalOpId,
        frozen_targets: Option<&[FrozenTarget]>,
        resolver: Option<TerminalResolver>,
        decision: &TerminalDecision,
    ) -> Option<[u8; DIGEST_LEN]> {
        if generation != previous.generation.checked_add(1)? {
            return None;
        }
        let record = TerminalJournalRecord {
            frozen_targets: frozen_targets.map(<[FrozenTarget]>::to_vec),
            terminal_resolver: resolver,
            terminal_decision: Some(decision.clone()),
            ..TerminalJournalRecord::default()
        };
        Some(terminal_chain_digest(
            previous.journal_id,
            previous.chain_digest,
            generation,
            canonical_terminal_decision_digest(op_id, &record),
        ))
    }

    /// Return whether `cut` is a valid prefix of this journal lineage.
    ///
    /// The set digest deliberately does not participate in prefix validation:
    /// only the current set digest is retained, while the chain authenticates
    /// every historical generation in the source ordering.
    pub(crate) fn recognizes_terminal_cut(&self, cut: &TerminalCut) -> bool {
        if cut.journal_id != self.journal_id || cut.generation > self.terminal_decision_generation {
            return false;
        }
        if cut.generation == 0 {
            return cut.chain_digest == EMPTY_CHAIN_DIGEST;
        }
        self.generation_index
            .get(&cut.generation)
            .and_then(|op_id| self.records.get(op_id))
            .and_then(TerminalJournalRecord::terminal_chain_digest)
            .is_some_and(|digest| digest == &cut.chain_digest)
    }

    /// Select at most `max_entries` terminal generations after a recognized
    /// source cut. `None` requests a checkpoint because the cut is not a
    /// prefix of this journal lineage. A zero bound is treated as one so a
    /// continuation can never return a non-progressing `has_more` page.
    #[cfg(test)]
    pub(crate) fn terminal_deltas_after(
        &self,
        base: &TerminalCut,
        max_entries: usize,
    ) -> Option<TerminalJournalDeltaPage> {
        self.terminal_deltas_between(base, &self.terminal_cut(), max_entries)
    }

    /// Select a bounded delta page without advancing beyond a transfer's
    /// previously captured target cut.
    pub(crate) fn terminal_deltas_between(
        &self,
        base: &TerminalCut,
        target: &TerminalCut,
        max_entries: usize,
    ) -> Option<TerminalJournalDeltaPage> {
        if !self.recognizes_terminal_cut(base)
            || !self.recognizes_terminal_cut(target)
            || base.generation > target.generation
        {
            return None;
        }

        let entries = if base.generation == target.generation {
            Vec::new()
        } else {
            self.generation_index
                .range(base.generation + 1..=target.generation)
                .take(max_entries.max(1))
                .map(|(generation, op_id)| {
                    let record = self
                        .records
                        .get(op_id)
                        .expect("generation index references a terminal record");
                    TerminalJournalDeltaEntry {
                        generation: *generation,
                        chain_digest: *record
                            .terminal_chain_digest()
                            .expect("indexed terminal record has a chain digest"),
                        op_id: *op_id,
                        record: record.clone(),
                    }
                })
                .collect::<Vec<_>>()
        };
        let last_generation = entries
            .last()
            .map(TerminalJournalDeltaEntry::generation)
            .unwrap_or(base.generation);
        Some(TerminalJournalDeltaPage {
            base: *base,
            target: *target,
            entries,
            has_more: last_generation < target.generation,
        })
    }

    /// Return a bounded, generation-ordered page of the exact terminal fence
    /// set. A zero bound is treated as one to guarantee cursor progress.
    /// Nonterminal promise/accept records are intentionally excluded.
    #[cfg(test)]
    pub(crate) fn terminal_checkpoint_page(
        &self,
        cursor: u64,
        max_entries: usize,
    ) -> TerminalJournalCheckpointPage {
        self.terminal_checkpoint_page_at(&self.terminal_cut(), cursor, max_entries)
            .expect("the current terminal cut is always recognized")
    }

    /// Return a stable checkpoint page bounded by a previously captured cut.
    /// New decisions append later generations and cannot move its cursor.
    pub(crate) fn terminal_checkpoint_page_at(
        &self,
        target: &TerminalCut,
        cursor: u64,
        max_entries: usize,
    ) -> Option<TerminalJournalCheckpointPage> {
        if !self.recognizes_terminal_cut(target) {
            return None;
        }
        let start = usize::try_from(cursor).unwrap_or(usize::MAX);
        let entries = self
            .generation_index
            .iter()
            .take(usize::try_from(target.generation).unwrap_or(usize::MAX))
            .skip(start)
            .take(max_entries.max(1))
            .map(|(_, op_id)| TerminalJournalSnapshotEntry {
                op_id: *op_id,
                record: self
                    .records
                    .get(op_id)
                    .expect("generation index references a terminal record")
                    .clone(),
            })
            .collect::<Vec<_>>();
        let next_cursor = cursor.saturating_add(entries.len() as u64);
        Some(TerminalJournalCheckpointPage {
            target: *target,
            cursor,
            next_cursor,
            entries,
            has_more: next_cursor < target.generation,
        })
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
        let previous_record = self.records.get(&op_id).cloned();
        let had_terminal_decision = previous_record
            .as_ref()
            .is_some_and(TerminalJournalRecord::is_terminal);
        let changed = match mutate(self.records.entry(op_id).or_default()) {
            Ok(changed) => changed,
            Err(error) => {
                restore_record(&mut self.records, op_id, previous_record);
                return Err(error);
            }
        };
        if !changed {
            restore_record(&mut self.records, op_id, previous_record);
            return Ok(false);
        }

        let became_terminal = !had_terminal_decision
            && self
                .records
                .get(&op_id)
                .is_some_and(TerminalJournalRecord::is_terminal);
        if became_terminal {
            let generation = self
                .terminal_decision_generation
                .checked_add(1)
                .ok_or(TerminalJournalError::DecisionGenerationExhausted);
            let generation = match generation {
                Ok(generation) => generation,
                Err(error) => {
                    restore_record(&mut self.records, op_id, previous_record);
                    return Err(error);
                }
            };
            self.records
                .get_mut(&op_id)
                .expect("changed journal record remains present")
                .terminal_generation = Some(generation);
        }
        let derived = match derive_terminal_state(&mut self.records, self.journal_id) {
            Ok(derived) => derived,
            Err(reason) => {
                restore_record(&mut self.records, op_id, previous_record);
                return Err(TerminalJournalError::InvalidMetadata {
                    path: self.path.clone().unwrap_or_default(),
                    reason,
                });
            }
        };
        let cut = TerminalCut::new(
            self.journal_id,
            derived.terminal_decision_generation,
            derived.terminal_chain_digest,
            derived.terminal_set_digest,
        );
        if let Some(store) = self.store.as_mut() {
            let record = self
                .records
                .get(&op_id)
                .expect("changed journal record remains present");
            if let Err(error) = store.upsert_record(op_id, record, &cut) {
                restore_record(&mut self.records, op_id, previous_record);
                return Err(error.into());
            }
        }
        self.terminal_decision_generation = derived.terminal_decision_generation;
        self.terminal_chain_digest = derived.terminal_chain_digest;
        self.terminal_set_digest = derived.terminal_set_digest;
        self.generation_index = derived.generation_index;
        Ok(true)
    }
}

fn restore_record(
    records: &mut BTreeMap<TerminalJournalOpId, TerminalJournalRecord>,
    op_id: TerminalJournalOpId,
    previous: Option<TerminalJournalRecord>,
) {
    match previous {
        Some(previous) => {
            records.insert(op_id, previous);
        }
        None => {
            records.remove(&op_id);
        }
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
            ) if existing_candidate.has_same_value(next_candidate) => return Ok(false),
            (TerminalDecision::Commit { .. }, TerminalDecision::Abort { .. }) => {
                return Ok(false);
            }
            (TerminalDecision::Abort { .. }, TerminalDecision::Abort { .. }) => return Ok(false),
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

struct DerivedTerminalState {
    terminal_decision_generation: u64,
    terminal_chain_digest: [u8; DIGEST_LEN],
    terminal_set_digest: [u8; DIGEST_LEN],
    generation_index: BTreeMap<u64, TerminalJournalOpId>,
}

struct LoadedTerminalJournal {
    records: BTreeMap<TerminalJournalOpId, TerminalJournalRecord>,
    journal_id: [u8; JOURNAL_ID_LEN],
    terminal_decision_generation: u64,
    terminal_chain_digest: [u8; DIGEST_LEN],
    terminal_set_digest: [u8; DIGEST_LEN],
    generation_index: BTreeMap<u64, TerminalJournalOpId>,
}

impl LoadedTerminalJournal {
    fn empty(journal_id: [u8; JOURNAL_ID_LEN]) -> Self {
        Self {
            records: BTreeMap::new(),
            journal_id,
            terminal_decision_generation: 0,
            terminal_chain_digest: EMPTY_CHAIN_DIGEST,
            terminal_set_digest: compute_terminal_set_digest(&BTreeMap::new()),
            generation_index: BTreeMap::new(),
        }
    }

    fn from_derived(
        records: BTreeMap<TerminalJournalOpId, TerminalJournalRecord>,
        journal_id: [u8; JOURNAL_ID_LEN],
        derived: DerivedTerminalState,
    ) -> Self {
        Self {
            records,
            journal_id,
            terminal_decision_generation: derived.terminal_decision_generation,
            terminal_chain_digest: derived.terminal_chain_digest,
            terminal_set_digest: derived.terminal_set_digest,
            generation_index: derived.generation_index,
        }
    }
}

fn generate_journal_id() -> Result<[u8; JOURNAL_ID_LEN], TerminalJournalError> {
    let random = SystemRandom::new();
    let mut journal_id = [0; JOURNAL_ID_LEN];
    random
        .fill(&mut journal_id)
        .map_err(|_| TerminalJournalError::JournalIdGeneration)?;
    if journal_id == [0; JOURNAL_ID_LEN] {
        random
            .fill(&mut journal_id)
            .map_err(|_| TerminalJournalError::JournalIdGeneration)?;
    }
    (journal_id != [0; JOURNAL_ID_LEN])
        .then_some(journal_id)
        .ok_or(TerminalJournalError::JournalIdGeneration)
}

fn derive_terminal_state(
    records: &mut BTreeMap<TerminalJournalOpId, TerminalJournalRecord>,
    journal_id: [u8; JOURNAL_ID_LEN],
) -> Result<DerivedTerminalState, &'static str> {
    let mut generation_index = BTreeMap::new();
    for (op_id, record) in records.iter() {
        if record.is_terminal() {
            let generation = record
                .terminal_generation
                .ok_or("terminal record is missing its generation")?;
            if generation == 0 || generation_index.insert(generation, *op_id).is_some() {
                return Err("terminal generations are zero or duplicated");
            }
        } else if record.terminal_generation.is_some() || record.terminal_chain_digest.is_some() {
            return Err("nonterminal record retains terminal cut metadata");
        }
    }
    for (offset, generation) in generation_index.keys().copied().enumerate() {
        if generation != (offset as u64).saturating_add(1) {
            return Err("terminal generations are not contiguous");
        }
    }

    let mut previous = EMPTY_CHAIN_DIGEST;
    for (generation, op_id) in &generation_index {
        let record = records
            .get_mut(op_id)
            .expect("generation index references an existing record");
        previous = terminal_chain_digest(
            journal_id,
            previous,
            *generation,
            canonical_terminal_decision_digest(*op_id, record),
        );
        record.terminal_chain_digest = Some(previous);
    }

    Ok(DerivedTerminalState {
        terminal_decision_generation: generation_index.len() as u64,
        terminal_chain_digest: previous,
        terminal_set_digest: compute_terminal_set_digest(records),
        generation_index,
    })
}

fn terminal_chain_digest(
    journal_id: [u8; JOURNAL_ID_LEN],
    previous: [u8; DIGEST_LEN],
    generation: u64,
    decision_digest: [u8; DIGEST_LEN],
) -> [u8; DIGEST_LEN] {
    let mut image = Vec::with_capacity(24 + DIGEST_LEN * 2);
    image.extend_from_slice(b"shitspeak-terminal-chain-v2\0");
    image.extend_from_slice(&journal_id);
    image.extend_from_slice(&previous);
    image.extend_from_slice(&generation.to_be_bytes());
    image.extend_from_slice(&decision_digest);
    sha256(&image)
}

fn compute_terminal_set_digest(
    records: &BTreeMap<TerminalJournalOpId, TerminalJournalRecord>,
) -> [u8; DIGEST_LEN] {
    compute_terminal_set_digest_through(records, u64::MAX)
}

fn compute_terminal_set_digest_through(
    records: &BTreeMap<TerminalJournalOpId, TerminalJournalRecord>,
    through_generation: u64,
) -> [u8; DIGEST_LEN] {
    let included = |record: &&TerminalJournalRecord| {
        record
            .terminal_generation()
            .is_some_and(|generation| generation <= through_generation)
    };
    let terminal_count = records.values().filter(included).count() as u64;
    let mut image = Vec::with_capacity(40 + terminal_count as usize * DIGEST_LEN);
    image.extend_from_slice(b"shitspeak-terminal-set-v2\0");
    image.extend_from_slice(&terminal_count.to_be_bytes());
    for (op_id, record) in records.iter().filter(|(_, record)| {
        record
            .terminal_generation()
            .is_some_and(|generation| generation <= through_generation)
    }) {
        image.extend_from_slice(&canonical_terminal_decision_digest(*op_id, record));
    }
    sha256(&image)
}

fn canonical_terminal_decision_digest(
    op_id: TerminalJournalOpId,
    record: &TerminalJournalRecord,
) -> [u8; DIGEST_LEN] {
    let mut image = Vec::new();
    image.extend_from_slice(b"shitspeak-terminal-decision-v2\0");
    image.extend_from_slice(&op_id.0.to_be_bytes());
    image.extend_from_slice(&op_id.1.to_be_bytes());
    match record.frozen_targets() {
        Some(targets) => {
            image.push(1);
            image.extend_from_slice(&(targets.len() as u64).to_be_bytes());
            for target in targets {
                image.extend_from_slice(&target.node().to_be_bytes());
                image.extend_from_slice(&target.boot_epoch().to_be_bytes());
            }
        }
        None => image.push(0),
    }
    match record.terminal_resolver() {
        Some(resolver) => {
            image.push(1);
            image.extend_from_slice(&resolver.node().to_be_bytes());
            image.extend_from_slice(&resolver.boot_epoch().to_be_bytes());
        }
        None => image.push(0),
    }
    match record
        .terminal_decision()
        .expect("terminal digest is computed only for a terminal record")
    {
        TerminalDecision::Commit { candidate } => {
            image.push(1);
            // A higher-ballot rebroadcast of this chosen value is an
            // idempotent no-op. The resolution ballot therefore does not
            // participate in the immutable terminal outcome identity.
            image.extend_from_slice(&candidate.ts_final().to_be_bytes());
            image.extend_from_slice(&(candidate.op_msgpack().len() as u64).to_be_bytes());
            image.extend_from_slice(candidate.op_msgpack());
        }
        TerminalDecision::Abort { .. } => {
            image.push(2);
        }
    }
    sha256(&image)
}

fn sha256(image: &[u8]) -> [u8; DIGEST_LEN] {
    let digest = digest(&SHA256, image);
    let mut bytes = [0; DIGEST_LEN];
    bytes.copy_from_slice(digest.as_ref());
    bytes
}

#[derive(Serialize, Deserialize)]
struct PersistedTerminalJournal {
    version: u32,
    topic: String,
    #[serde(default)]
    journal_id: [u8; JOURNAL_ID_LEN],
    #[serde(default)]
    terminal_decision_generation: u64,
    #[serde(default)]
    terminal_chain_digest: [u8; DIGEST_LEN],
    #[serde(default)]
    terminal_set_digest: [u8; DIGEST_LEN],
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
            .join(format!("topic-{}.sqlite3", hex::encode(topic.as_bytes()))),
    )
}

fn legacy_journal_path(sqlite_path: &Path) -> PathBuf {
    sqlite_path.with_extension("json")
}

fn journal_lock_path(path: &Path) -> PathBuf {
    path.with_extension("lock")
}

fn load_records(
    path: &Path,
    expected_topic: &str,
    bytes: &[u8],
) -> Result<LoadedTerminalJournal, TerminalJournalError> {
    let payload: PersistedTerminalJournal =
        serde_json::from_slice(bytes).map_err(|source| TerminalJournalError::Json {
            path: path.to_path_buf(),
            source,
        })?;
    if payload.version != LEGACY_JOURNAL_VERSION && payload.version != JOURNAL_VERSION {
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

    let version = payload.version;
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
    if version == LEGACY_JOURNAL_VERSION {
        let journal_id = generate_journal_id()?;
        for (offset, record) in records
            .values_mut()
            .filter(|record| record.is_terminal())
            .enumerate()
        {
            record.terminal_generation = Some((offset as u64).saturating_add(1));
        }
        let derived = derive_terminal_state(&mut records, journal_id).map_err(|reason| {
            TerminalJournalError::InvalidMetadata {
                path: path.to_path_buf(),
                reason,
            }
        })?;
        return Ok(LoadedTerminalJournal::from_derived(
            records, journal_id, derived,
        ));
    }

    if payload.journal_id == [0; JOURNAL_ID_LEN] {
        return Err(TerminalJournalError::InvalidMetadata {
            path: path.to_path_buf(),
            reason: "journal lineage identifier is missing or all zero",
        });
    }
    let persisted_record_metadata = records
        .iter()
        .filter_map(|(op_id, record)| {
            record.is_terminal().then_some((
                *op_id,
                (record.terminal_generation, record.terminal_chain_digest),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let derived = derive_terminal_state(&mut records, payload.journal_id).map_err(|reason| {
        TerminalJournalError::InvalidMetadata {
            path: path.to_path_buf(),
            reason,
        }
    })?;
    if payload.terminal_decision_generation != derived.terminal_decision_generation
        || payload.terminal_chain_digest != derived.terminal_chain_digest
        || payload.terminal_set_digest != derived.terminal_set_digest
    {
        return Err(TerminalJournalError::InvalidMetadata {
            path: path.to_path_buf(),
            reason: "persisted terminal cut does not match the terminal records",
        });
    }
    if persisted_record_metadata.iter().any(|(op_id, metadata)| {
        let record = records
            .get(op_id)
            .expect("derived terminal record remains present");
        metadata.0 != record.terminal_generation || metadata.1 != record.terminal_chain_digest
    }) {
        return Err(TerminalJournalError::InvalidMetadata {
            path: path.to_path_buf(),
            reason: "persisted terminal generation or chain digest is invalid",
        });
    }
    Ok(LoadedTerminalJournal::from_derived(
        records,
        payload.journal_id,
        derived,
    ))
}

fn validate_loaded_sqlite(
    path: &Path,
    records: &mut BTreeMap<TerminalJournalOpId, TerminalJournalRecord>,
    cut: &TerminalCut,
) -> Result<DerivedTerminalState, TerminalJournalError> {
    if cut.journal_id() == &[0; JOURNAL_ID_LEN] {
        return Err(TerminalJournalError::InvalidMetadata {
            path: path.to_path_buf(),
            reason: "journal lineage identifier is missing or all zero",
        });
    }
    for (op_id, record) in records.iter() {
        validate_record(path, *op_id, record)?;
    }
    let persisted_record_metadata = records
        .iter()
        .filter_map(|(op_id, record)| {
            record.is_terminal().then_some((
                *op_id,
                (record.terminal_generation, record.terminal_chain_digest),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let derived = derive_terminal_state(records, *cut.journal_id()).map_err(|reason| {
        TerminalJournalError::InvalidMetadata {
            path: path.to_path_buf(),
            reason,
        }
    })?;
    if cut.generation() != derived.terminal_decision_generation
        || cut.chain_digest() != &derived.terminal_chain_digest
        || cut.terminal_set_digest() != &derived.terminal_set_digest
    {
        return Err(TerminalJournalError::InvalidMetadata {
            path: path.to_path_buf(),
            reason: "persisted terminal cut does not match the terminal records",
        });
    }
    if persisted_record_metadata.iter().any(|(op_id, metadata)| {
        let derived_record = records
            .get(op_id)
            .expect("derived SQLite journal retains every record");
        metadata.0 != derived_record.terminal_generation
            || metadata.1 != derived_record.terminal_chain_digest
    }) {
        return Err(TerminalJournalError::InvalidMetadata {
            path: path.to_path_buf(),
            reason: "persisted terminal generation or chain digest is invalid",
        });
    }
    Ok(derived)
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

#[cfg(all(windows, test))]
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
    // Windows does not expose a directory fsync through `std`.
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
    fn terminal_identity_is_immutable_across_higher_ballot_rebroadcasts() {
        let mut journal = TerminalJournal::in_memory("channels");
        assert!(
            journal
                .upsert_commit_decision((1, 1), 3, 10, b"value".to_vec())
                .unwrap()
        );
        let original_cut = journal.terminal_cut();
        assert!(
            !journal
                .upsert_commit_decision((1, 1), 4, 10, b"value".to_vec())
                .unwrap()
        );
        assert_eq!(journal.terminal_cut(), original_cut);
        let commit_record = journal.get((1, 1)).unwrap();
        assert_eq!(commit_record.promise_ballot(), 3);
        assert_eq!(commit_record.accepted_commit().unwrap().ballot(), 3);
        assert_eq!(commit_record.terminal_decision().unwrap().ballot(), 3);
        assert!(!journal.upsert_abort_decision((1, 1), 4).unwrap());
        assert!(matches!(
            journal.upsert_commit_decision((1, 1), 5, 10, b"other".to_vec()),
            Err(TerminalJournalError::ConflictingTerminalDecision { .. })
        ));

        assert!(journal.upsert_abort_decision((3, 3), 6).unwrap());
        let abort_cut = journal.terminal_cut();
        assert!(!journal.upsert_abort_decision((3, 3), 9).unwrap());
        assert_eq!(journal.terminal_cut(), abort_cut);
        let abort_record = journal.get((3, 3)).unwrap();
        assert_eq!(abort_record.promise_ballot(), 6);
        assert_eq!(abort_record.terminal_decision().unwrap().ballot(), 6);

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

    #[test]
    fn terminal_deltas_are_generation_ordered_and_bounded() {
        let mut journal = TerminalJournal::in_memory("channels");
        let empty_cut = journal.terminal_cut();
        assert!(journal.upsert_abort_decision((9, 9), 1).unwrap());
        assert!(journal.upsert_abort_decision((1, 1), 2).unwrap());
        assert!(journal.upsert_abort_decision((5, 5), 3).unwrap());

        let first = journal.terminal_deltas_after(&empty_cut, 2).unwrap();
        assert_eq!(first.entries().len(), 2);
        assert_eq!(first.entries()[0].generation(), 1);
        assert_eq!(first.entries()[0].clone().into_parts().2, (9, 9));
        assert_eq!(first.entries()[1].generation(), 2);
        assert_eq!(first.entries()[1].clone().into_parts().2, (1, 1));
        assert!(first.has_more());
        assert_eq!(first.target(), journal.terminal_cut());

        let second_base = journal.terminal_cut_at(2).unwrap();
        assert!(journal.recognizes_terminal_cut(&second_base));
        let second = journal.terminal_deltas_after(&second_base, 2).unwrap();
        assert_eq!(second.entries().len(), 1);
        assert_eq!(second.entries()[0].clone().into_parts().2, (5, 5));
        assert!(!second.has_more());

        let foreign = super::TerminalCut::new([0x55; 16], 0, [0; 32], [0; 32]);
        assert!(journal.terminal_deltas_after(&foreign, 1).is_none());
    }

    #[test]
    fn source_transition_verification_authenticates_the_canonical_decision() {
        let mut journal = TerminalJournal::in_memory("channels");
        let base = journal.terminal_cut();
        journal
            .upsert_commit_decision((9, 9), 7, 11, b"value".to_vec())
            .unwrap();
        let delta = journal
            .terminal_deltas_after(&base, 1)
            .unwrap()
            .into_entries()
            .pop()
            .unwrap();
        let (generation, chain, op_id, record) = delta.into_parts();
        let decision = record.terminal_decision().unwrap();

        assert!(TerminalJournal::verifies_terminal_transition(
            &base,
            generation,
            op_id,
            record.frozen_targets(),
            record.terminal_resolver(),
            decision,
            base.chain_digest(),
            &chain,
        ));
        assert!(!TerminalJournal::verifies_terminal_transition(
            &base,
            generation,
            (op_id.0, op_id.1 + 1),
            record.frozen_targets(),
            record.terminal_resolver(),
            decision,
            base.chain_digest(),
            &chain,
        ));
        assert_eq!(
            TerminalJournal::terminal_transition_chain_digest(
                &base,
                generation,
                op_id,
                record.frozen_targets(),
                record.terminal_resolver(),
                decision,
            ),
            Some(chain),
        );
    }

    #[test]
    fn intermediate_terminal_cut_is_exact_and_continues_to_a_fixed_target() {
        let mut journal = TerminalJournal::in_memory("channels");
        let zero = journal.terminal_cut_at(0).unwrap();
        journal.upsert_abort_decision((9, 9), 1).unwrap();
        journal.upsert_abort_decision((1, 1), 2).unwrap();
        let intermediate = journal.terminal_cut_at(1).unwrap();
        let target = journal.terminal_cut();
        let mut prefix = TerminalJournal::in_memory("channels");
        prefix.journal_id = journal.journal_id;
        prefix.upsert_abort_decision((9, 9), 1).unwrap();

        assert!(journal.recognizes_terminal_cut(&zero));
        assert!(journal.recognizes_terminal_cut(&intermediate));
        assert_eq!(intermediate, prefix.terminal_cut());
        assert_ne!(
            intermediate.terminal_set_digest(),
            zero.terminal_set_digest()
        );
        assert_ne!(
            intermediate.terminal_set_digest(),
            target.terminal_set_digest()
        );

        let page = journal
            .terminal_deltas_between(&intermediate, &target, 1)
            .unwrap();
        assert_eq!(page.base(), intermediate);
        assert_eq!(page.target(), target);
        assert_eq!(page.entries().len(), 1);
        assert_eq!(page.entries()[0].generation(), 2);
        assert!(!page.has_more());
    }

    #[test]
    fn terminal_set_digest_is_independent_of_learning_order() {
        let mut left = TerminalJournal::in_memory("channels");
        let mut right = TerminalJournal::in_memory("channels");
        right.journal_id = left.journal_id;
        left.upsert_abort_decision((1, 1), 4).unwrap();
        left.upsert_abort_decision((2, 2), 5).unwrap();
        right.upsert_abort_decision((2, 2), 5).unwrap();
        right.upsert_abort_decision((1, 1), 4).unwrap();

        assert_eq!(
            left.terminal_cut().terminal_set_digest(),
            right.terminal_cut().terminal_set_digest()
        );
        assert_ne!(
            left.terminal_cut().chain_digest(),
            right.terminal_cut().chain_digest()
        );
    }

    #[test]
    fn terminal_checkpoint_is_bounded_and_excludes_nonterminal_records() {
        let mut journal = TerminalJournal::in_memory("channels");
        journal.upsert_promise((0, 0), 7).unwrap();
        journal.upsert_abort_decision((1, 1), 8).unwrap();
        journal.upsert_abort_decision((2, 2), 9).unwrap();

        let first = journal.terminal_checkpoint_page(0, 1);
        assert_eq!(first.cursor(), 0);
        assert_eq!(first.next_cursor(), 1);
        assert_eq!(first.entries().len(), 1);
        assert_eq!(first.entries()[0].clone().into_parts().0, (1, 1));
        assert!(first.has_more());
        let second = journal.terminal_checkpoint_page(first.next_cursor(), 1);
        assert_eq!(second.entries()[0].clone().into_parts().0, (2, 2));
        assert!(!second.has_more());
    }

    #[test]
    fn zero_page_bounds_still_advance_delta_and_checkpoint_cursors() {
        let mut journal = TerminalJournal::in_memory("channels");
        let empty_cut = journal.terminal_cut();
        journal.upsert_abort_decision((1, 1), 1).unwrap();
        journal.upsert_abort_decision((2, 2), 2).unwrap();

        let first_delta = journal.terminal_deltas_after(&empty_cut, 0).unwrap();
        assert_eq!(first_delta.entries().len(), 1);
        assert_eq!(first_delta.entries()[0].generation(), 1);
        assert!(first_delta.has_more());
        let generation_one = journal.terminal_cut_at(1).unwrap();
        let second_delta = journal
            .terminal_deltas_between(&generation_one, &first_delta.target(), 0)
            .unwrap();
        assert_eq!(second_delta.entries().len(), 1);
        assert_eq!(second_delta.entries()[0].generation(), 2);
        assert!(!second_delta.has_more());

        let first_checkpoint = journal.terminal_checkpoint_page(0, 0);
        assert_eq!(first_checkpoint.entries().len(), 1);
        assert_eq!(first_checkpoint.next_cursor(), 1);
        assert!(first_checkpoint.has_more());
        let second_checkpoint = journal.terminal_checkpoint_page_at(
            &first_checkpoint.target(),
            first_checkpoint.next_cursor(),
            0,
        );
        let second_checkpoint = second_checkpoint.unwrap();
        assert_eq!(second_checkpoint.entries().len(), 1);
        assert_eq!(second_checkpoint.next_cursor(), 2);
        assert!(!second_checkpoint.has_more());
    }

    #[test]
    fn legacy_journal_is_migrated_to_sqlite_and_retained_for_rollback() {
        let root = TempDir::new().unwrap();
        let topic = "channels";
        let directory = root.path().join("strict-terminal-journal");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!("topic-{}.json", hex::encode(topic.as_bytes())));
        fs::write(
            &path,
            r#"{"version":1,"topic":"channels","terminal_decision_generation":1,"records":[{"op_id_hi":1,"op_id_lo":2,"promise_ballot":3,"terminal_decision":{"outcome":"abort","ballot":3}}]}"#,
        )
        .unwrap();

        let journal = TerminalJournal::load(Some(root.path().to_path_buf()), topic).unwrap();
        assert_eq!(journal.terminal_cut().generation(), 1);
        assert_ne!(journal.terminal_cut().journal_id(), &[0; 16]);
        assert_eq!(journal.get((1, 2)).unwrap().terminal_generation(), Some(1));
        assert_eq!(
            journal.persistence_path().unwrap().extension().unwrap(),
            "sqlite3"
        );
        let retained: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(retained["version"], 1);
        drop(journal);

        let reloaded = TerminalJournal::load(Some(root.path().to_path_buf()), topic).unwrap();
        assert_eq!(reloaded.terminal_cut().generation(), 1);
        assert_eq!(reloaded.get((1, 2)).unwrap().terminal_generation(), Some(1));
    }
}
