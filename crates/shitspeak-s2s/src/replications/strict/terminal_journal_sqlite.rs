//! SQLite persistence for the strict terminal journal.
//!
//! This module deliberately contains no async synchronization. `rusqlite`
//! calls, and especially a `FULL`-synchronous commit, must be scheduled by the
//! caller on the shared S2S blocking pool rather than on a Tokio executor
//! thread. A mutation serializes only the changed record and commits that row
//! and its resulting terminal cut in one transaction.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::terminal_journal::{
    JOURNAL_ID_LEN, TerminalCut, TerminalJournalOpId, TerminalJournalRecord,
};

const LEGACY_SCHEMA_VERSION: i64 = 3;
const RECOVERY_V8_SCHEMA_VERSION: i64 = 5;
const RECOVERY_ATTEMPT_ID_LEN: usize = 16;

/// A participant incarnation named by a durable recovery certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct DurableRecoveryParticipant {
    node_id: u16,
    boot_epoch: u64,
}

impl DurableRecoveryParticipant {
    pub(crate) fn new(node_id: u16, boot_epoch: u64) -> Self {
        Self {
            node_id,
            boot_epoch,
        }
    }

    pub(crate) fn node_id(self) -> u16 {
        self.node_id
    }

    pub(crate) fn boot_epoch(self) -> u64 {
        self.boot_epoch
    }
}

/// The logical target certified before a concrete donor representation is selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DurableRecoveryTarget {
    repository_version: u64,
    history_freshness: i64,
    terminal_set_digest: [u8; 32],
}

impl DurableRecoveryTarget {
    pub(crate) fn new(
        repository_version: u64,
        history_freshness: i64,
        terminal_set_digest: [u8; 32],
    ) -> Self {
        Self {
            repository_version,
            history_freshness,
            terminal_set_digest,
        }
    }

    pub(crate) fn repository_version(self) -> u64 {
        self.repository_version
    }

    pub(crate) fn history_freshness(self) -> i64 {
        self.history_freshness
    }

    pub(crate) fn terminal_set_digest(&self) -> &[u8; 32] {
        &self.terminal_set_digest
    }
}

/// One authenticated witness and the exact terminal representation it attested.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DurableRecoveryWitness {
    participant: DurableRecoveryParticipant,
    terminal_cut: TerminalCut,
    #[serde(default)]
    history_rank: u64,
}

impl DurableRecoveryWitness {
    pub(crate) fn new(participant: DurableRecoveryParticipant, terminal_cut: TerminalCut) -> Self {
        Self {
            participant,
            terminal_cut,
            history_rank: 0,
        }
    }

    pub(crate) fn with_history_rank(mut self, history_rank: u64) -> Self {
        self.history_rank = history_rank;
        self
    }

    pub(crate) fn participant(self) -> DurableRecoveryParticipant {
        self.participant
    }

    pub(crate) fn terminal_cut(self) -> TerminalCut {
        self.terminal_cut
    }

    pub(crate) fn history_rank(self) -> u64 {
        self.history_rank
    }
}

/// A durable summary of a failed donor interaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DurableRecoveryFailure {
    donor: DurableRecoveryParticipant,
    reason: String,
    occurrences: u64,
}

impl DurableRecoveryFailure {
    pub(crate) fn new(
        donor: DurableRecoveryParticipant,
        reason: impl Into<String>,
        occurrences: u64,
    ) -> Self {
        Self {
            donor,
            reason: reason.into(),
            occurrences,
        }
    }

    pub(crate) fn donor(&self) -> DurableRecoveryParticipant {
        self.donor
    }

    pub(crate) fn reason(&self) -> &str {
        &self.reason
    }

    pub(crate) fn occurrences(&self) -> u64 {
        self.occurrences
    }
}

/// Durable reducer phase. Wire cursors and transport nonces intentionally do not appear here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DurableRecoveryPhase {
    Certifying,
    FetchingTerminalCheckpoint,
    FetchingRepositorySnapshot,
    Prepared,
    Installing,
    Verifying,
    Backoff,
}

impl DurableRecoveryPhase {
    fn encode(self) -> i64 {
        match self {
            Self::Certifying => 1,
            Self::FetchingTerminalCheckpoint => 2,
            Self::FetchingRepositorySnapshot => 3,
            Self::Prepared => 4,
            Self::Installing => 5,
            Self::Verifying => 6,
            Self::Backoff => 7,
        }
    }

    fn decode(path: &Path, value: i64) -> Result<Self, SqliteTerminalJournalError> {
        match value {
            1 => Ok(Self::Certifying),
            2 => Ok(Self::FetchingTerminalCheckpoint),
            3 => Ok(Self::FetchingRepositorySnapshot),
            4 => Ok(Self::Prepared),
            5 => Ok(Self::Installing),
            6 => Ok(Self::Verifying),
            7 => Ok(Self::Backoff),
            _ => Err(SqliteTerminalJournalError::InvalidData {
                path: path.to_path_buf(),
                reason: "recovery phase is invalid",
            }),
        }
    }
}

/// All durable state owned by one active recovery attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DurableRecoveryAttempt {
    attempt_id: [u8; RECOVERY_ATTEMPT_ID_LEN],
    phase: DurableRecoveryPhase,
    frozen_quorum_denominator: u64,
    frozen_electorate: Vec<u16>,
    target: Option<DurableRecoveryTarget>,
    witnesses: Vec<DurableRecoveryWitness>,
    donor_order: Vec<DurableRecoveryParticipant>,
    current_donor_index: Option<u64>,
    current_donor: Option<DurableRecoveryParticipant>,
    representation_cut: Option<TerminalCut>,
    failure_history: Vec<DurableRecoveryFailure>,
}

impl DurableRecoveryAttempt {
    pub(crate) fn new(
        attempt_id: [u8; RECOVERY_ATTEMPT_ID_LEN],
        phase: DurableRecoveryPhase,
        frozen_quorum_denominator: u64,
        target: Option<DurableRecoveryTarget>,
        witnesses: Vec<DurableRecoveryWitness>,
        donor_order: Vec<DurableRecoveryParticipant>,
        current_donor_index: Option<u64>,
        current_donor: Option<DurableRecoveryParticipant>,
        representation_cut: Option<TerminalCut>,
        failure_history: Vec<DurableRecoveryFailure>,
    ) -> Result<Self, &'static str> {
        let denominator = usize::try_from(frozen_quorum_denominator)
            .map_err(|_| "recovery electorate denominator does not fit usize")?;
        if denominator > usize::from(u16::MAX) + 1 {
            return Err("recovery electorate cannot fit node identifiers");
        }
        let mut frozen_electorate = witnesses
            .iter()
            .map(|witness| witness.participant().node_id())
            .collect::<Vec<_>>();
        let mut candidate = 0u16;
        while frozen_electorate.len() < denominator {
            if !frozen_electorate.contains(&candidate) {
                frozen_electorate.push(candidate);
            }
            if frozen_electorate.len() < denominator {
                candidate = candidate
                    .checked_add(1)
                    .ok_or("recovery electorate cannot fit the frozen denominator")?;
            }
        }
        frozen_electorate.sort_unstable();
        Self::new_with_electorate(
            attempt_id,
            phase,
            frozen_quorum_denominator,
            frozen_electorate,
            target,
            witnesses,
            donor_order,
            current_donor_index,
            current_donor,
            representation_cut,
            failure_history,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_electorate(
        attempt_id: [u8; RECOVERY_ATTEMPT_ID_LEN],
        phase: DurableRecoveryPhase,
        frozen_quorum_denominator: u64,
        frozen_electorate: Vec<u16>,
        target: Option<DurableRecoveryTarget>,
        witnesses: Vec<DurableRecoveryWitness>,
        donor_order: Vec<DurableRecoveryParticipant>,
        current_donor_index: Option<u64>,
        current_donor: Option<DurableRecoveryParticipant>,
        representation_cut: Option<TerminalCut>,
        failure_history: Vec<DurableRecoveryFailure>,
    ) -> Result<Self, &'static str> {
        if frozen_quorum_denominator == 0 {
            return Err("recovery quorum denominator must be nonzero");
        }
        if usize::try_from(frozen_quorum_denominator).ok() != Some(frozen_electorate.len()) {
            return Err("recovery electorate does not match its frozen denominator");
        }
        if frozen_electorate.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err("recovery electorate must be strictly sorted by node id");
        }
        if witnesses
            .windows(2)
            .any(|pair| pair[0].participant() >= pair[1].participant())
        {
            return Err("recovery witnesses must be strictly sorted by participant incarnation");
        }
        if witnesses
            .iter()
            .map(|witness| witness.participant().node_id())
            .collect::<BTreeSet<_>>()
            .len()
            != witnesses.len()
        {
            return Err("recovery witnesses must occupy distinct node seats");
        }
        if witnesses.iter().any(|witness| {
            frozen_electorate
                .binary_search(&witness.participant().node_id())
                .is_err()
        }) {
            return Err("recovery witness is outside the frozen electorate");
        }
        let has_certificate_state = !witnesses.is_empty()
            || !donor_order.is_empty()
            || current_donor_index.is_some()
            || current_donor.is_some()
            || representation_cut.is_some();
        if target.is_none() && has_certificate_state {
            return Err("uncertified recovery attempt contains certificate or donor state");
        }
        if target.is_none()
            && !matches!(
                phase,
                DurableRecoveryPhase::Certifying | DurableRecoveryPhase::Backoff
            )
        {
            return Err("uncertified recovery phase must be certifying or backoff");
        }
        if let Some(target) = target {
            if witnesses.iter().any(|witness| {
                witness.terminal_cut().terminal_set_digest() != target.terminal_set_digest()
            }) {
                return Err("recovery witness does not attest the logical terminal-set digest");
            }
            if representation_cut
                .is_some_and(|cut| cut.terminal_set_digest() != target.terminal_set_digest())
            {
                return Err("recovery representation does not match the certified target");
            }
        }
        let mut distinct_donors = donor_order.clone();
        distinct_donors.sort_unstable();
        distinct_donors.dedup();
        if distinct_donors.len() != donor_order.len() {
            return Err("recovery donor order contains duplicate incarnations");
        }
        if donor_order.iter().any(|donor| {
            witnesses
                .binary_search_by_key(donor, |witness| witness.participant())
                .is_err()
        }) {
            return Err("recovery donor is not a certified witness");
        }
        match (current_donor_index, current_donor) {
            (None, None) => {}
            (Some(index), Some(donor)) => {
                let index = usize::try_from(index)
                    .map_err(|_| "recovery current donor index is out of range")?;
                if donor_order.get(index) != Some(&donor) {
                    return Err("recovery current donor does not match donor order index");
                }
            }
            _ => return Err("recovery current donor and index must be persisted together"),
        }
        Ok(Self {
            attempt_id,
            phase,
            frozen_quorum_denominator,
            frozen_electorate,
            target,
            witnesses,
            donor_order,
            current_donor_index,
            current_donor,
            representation_cut,
            failure_history,
        })
    }

    pub(crate) fn new_certifying(
        attempt_id: [u8; RECOVERY_ATTEMPT_ID_LEN],
        frozen_quorum_denominator: u64,
        failure_history: Vec<DurableRecoveryFailure>,
    ) -> Result<Self, &'static str> {
        Self::new_uncertified(
            attempt_id,
            DurableRecoveryPhase::Certifying,
            frozen_quorum_denominator,
            failure_history,
        )
    }

    pub(crate) fn new_uncertified(
        attempt_id: [u8; RECOVERY_ATTEMPT_ID_LEN],
        phase: DurableRecoveryPhase,
        frozen_quorum_denominator: u64,
        failure_history: Vec<DurableRecoveryFailure>,
    ) -> Result<Self, &'static str> {
        if !matches!(
            phase,
            DurableRecoveryPhase::Certifying | DurableRecoveryPhase::Backoff
        ) {
            return Err("uncertified recovery phase must be certifying or backoff");
        }
        Self::new(
            attempt_id,
            phase,
            frozen_quorum_denominator,
            None,
            Vec::new(),
            Vec::new(),
            None,
            None,
            None,
            failure_history,
        )
    }

    pub(crate) fn attempt_id(&self) -> &[u8; RECOVERY_ATTEMPT_ID_LEN] {
        &self.attempt_id
    }

    pub(crate) fn phase(&self) -> DurableRecoveryPhase {
        self.phase
    }

    pub(crate) fn frozen_quorum_denominator(&self) -> u64 {
        self.frozen_quorum_denominator
    }

    pub(crate) fn frozen_electorate(&self) -> &[u16] {
        &self.frozen_electorate
    }

    pub(crate) fn target(&self) -> Option<DurableRecoveryTarget> {
        self.target
    }

    pub(crate) fn witnesses(&self) -> &[DurableRecoveryWitness] {
        &self.witnesses
    }

    pub(crate) fn donor_order(&self) -> &[DurableRecoveryParticipant] {
        &self.donor_order
    }

    pub(crate) fn current_donor_index(&self) -> Option<u64> {
        self.current_donor_index
    }

    pub(crate) fn current_donor(&self) -> Option<DurableRecoveryParticipant> {
        self.current_donor
    }

    pub(crate) fn representation_cut(&self) -> Option<TerminalCut> {
        self.representation_cut
    }

    pub(crate) fn failure_history(&self) -> &[DurableRecoveryFailure] {
        &self.failure_history
    }
}

/// Repository metadata bound into a staged image intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DurableRecoveryRepositoryMetadata {
    version: u64,
    freshness: i64,
}

impl DurableRecoveryRepositoryMetadata {
    pub(crate) fn new(version: u64, freshness: i64) -> Self {
        Self { version, freshness }
    }

    pub(crate) fn version(self) -> u64 {
        self.version
    }

    pub(crate) fn freshness(self) -> i64 {
        self.freshness
    }
}

/// A fully downloaded and fsynced repository image awaiting installation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DurableRecoveryArtifactIntent {
    attempt_id: [u8; RECOVERY_ATTEMPT_ID_LEN],
    staging_path: PathBuf,
    content_digest: [u8; 32],
    content_length: u64,
    repository_metadata: DurableRecoveryRepositoryMetadata,
    terminal_cut: TerminalCut,
}

impl DurableRecoveryArtifactIntent {
    pub(crate) fn new(
        attempt_id: [u8; RECOVERY_ATTEMPT_ID_LEN],
        staging_path: PathBuf,
        content_digest: [u8; 32],
        content_length: u64,
        repository_metadata: DurableRecoveryRepositoryMetadata,
        terminal_cut: TerminalCut,
    ) -> Self {
        Self {
            attempt_id,
            staging_path,
            content_digest,
            content_length,
            repository_metadata,
            terminal_cut,
        }
    }

    pub(crate) fn attempt_id(&self) -> &[u8; RECOVERY_ATTEMPT_ID_LEN] {
        &self.attempt_id
    }

    pub(crate) fn staging_path(&self) -> &Path {
        &self.staging_path
    }

    pub(crate) fn content_digest(&self) -> &[u8; 32] {
        &self.content_digest
    }

    pub(crate) fn content_length(&self) -> u64 {
        self.content_length
    }

    pub(crate) fn repository_metadata(&self) -> DurableRecoveryRepositoryMetadata {
        self.repository_metadata
    }

    pub(crate) fn terminal_cut(&self) -> TerminalCut {
        self.terminal_cut
    }
}
#[derive(Debug, Error)]
pub(crate) enum SqliteTerminalJournalError {
    #[error("strict terminal journal SQLite failed at {path:?}: {source}")]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("strict terminal journal record encoding failed: {0}")]
    Encode(#[source] rmp_serde::encode::Error),
    #[error("strict terminal journal record decoding failed: {0}")]
    Decode(#[source] rmp_serde::decode::Error),
    #[error("strict recovery metadata encoding failed: {0}")]
    RecoveryEncode(#[source] rmp_serde::encode::Error),
    #[error("strict recovery metadata decoding failed: {0}")]
    RecoveryDecode(#[source] rmp_serde::decode::Error),
    #[error("unsupported strict terminal journal SQLite schema version {version} at {path:?}")]
    UnsupportedSchema { path: PathBuf, version: i64 },
    #[error(
        "strict terminal journal topic mismatch at {path:?}: expected {expected:?}, found {found:?}"
    )]
    TopicMismatch {
        path: PathBuf,
        expected: String,
        found: String,
    },
    #[error("invalid strict terminal journal SQLite data at {path:?}: {reason}")]
    InvalidData { path: PathBuf, reason: &'static str },
}

/// Complete state loaded from SQLite at startup.
pub(crate) struct LoadedSqliteTerminalJournal {
    records: BTreeMap<TerminalJournalOpId, TerminalJournalRecord>,
    cut: TerminalCut,
    checkpoint_epoch: u64,
    checkpoint_repository_version: u64,
    retired_origins: BTreeMap<u64, u64>,
    repository_image_install_pending: bool,
    repository_image_install_freshness: i64,
}

impl LoadedSqliteTerminalJournal {
    pub(crate) fn install_pending(&self) -> bool {
        self.repository_image_install_pending
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        BTreeMap<TerminalJournalOpId, TerminalJournalRecord>,
        TerminalCut,
        u64,
        u64,
        BTreeMap<u64, u64>,
        bool,
        i64,
    ) {
        (
            self.records,
            self.cut,
            self.checkpoint_epoch,
            self.checkpoint_repository_version,
            self.retired_origins,
            self.repository_image_install_pending,
            self.repository_image_install_freshness,
        )
    }
}

/// A single-connection SQLite store intended to be owned by one blocking
/// journal worker.
pub(crate) struct SqliteTerminalJournalStore {
    path: PathBuf,
    topic: String,
    connection: Connection,
}

impl SqliteTerminalJournalStore {
    /// Opens or creates a store. An empty store has no journal identity until
    /// [`Self::initialize`] or [`Self::replace_all`] commits one.
    pub(crate) fn open(
        path: impl AsRef<Path>,
        topic: impl Into<String>,
    ) -> Result<Self, SqliteTerminalJournalError> {
        let path = path.as_ref().to_path_buf();
        let topic = topic.into();
        Self::open_inner(path, topic)
    }

    fn open_inner(path: PathBuf, topic: String) -> Result<Self, SqliteTerminalJournalError> {
        let mut connection =
            Connection::open(&path).map_err(|source| sqlite_error(&path, source))?;
        connection
            .busy_timeout(Duration::from_millis(250))
            .map_err(|source| sqlite_error(&path, source))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 PRAGMA foreign_keys = ON;
                 PRAGMA wal_autocheckpoint = 1000;",
            )
            .map_err(|source| sqlite_error(&path, source))?;

        let version = connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .map_err(|source| sqlite_error(&path, source))?;
        match version {
            0 => {
                create_schema_v3(&path, &mut connection)?;
                migrate_schema_v3_to_v4(&path, &mut connection)?;
                migrate_schema_v4_to_v5(&path, &mut connection)?;
            }
            1 => {
                migrate_schema_v1_to_v2(&path, &mut connection)?;
                migrate_schema_v2_to_v3(&path, &mut connection)?;
                migrate_schema_v3_to_v4(&path, &mut connection)?;
                migrate_schema_v4_to_v5(&path, &mut connection)?;
            }
            2 => {
                migrate_schema_v2_to_v3(&path, &mut connection)?;
                migrate_schema_v3_to_v4(&path, &mut connection)?;
                migrate_schema_v4_to_v5(&path, &mut connection)?;
            }
            LEGACY_SCHEMA_VERSION => {
                migrate_schema_v3_to_v4(&path, &mut connection)?;
                migrate_schema_v4_to_v5(&path, &mut connection)?;
            }
            4 => migrate_schema_v4_to_v5(&path, &mut connection)?,
            RECOVERY_V8_SCHEMA_VERSION => {}
            version => {
                return Err(SqliteTerminalJournalError::UnsupportedSchema { path, version });
            }
        }

        Ok(Self {
            path,
            topic,
            connection,
        })
    }

    pub(crate) fn load_recovery_attempt(
        &self,
    ) -> Result<Option<DurableRecoveryAttempt>, SqliteTerminalJournalError> {
        let row = self
            .connection
            .query_row(
                "SELECT attempt_id, phase, frozen_quorum_denominator, frozen_electorate,
                        repository_version, history_freshness, terminal_set_digest,
                        witnesses, donor_order, current_donor_index, current_donor_node,
                        current_donor_boot_epoch, representation_journal_id,
                        representation_generation, representation_chain_digest,
                        representation_terminal_set_digest, failure_history
                 FROM strict_recovery_state WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, Option<Vec<u8>>>(5)?,
                        row.get::<_, Option<Vec<u8>>>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                        row.get::<_, Option<Vec<u8>>>(9)?,
                        row.get::<_, Option<i64>>(10)?,
                        row.get::<_, Option<Vec<u8>>>(11)?,
                        row.get::<_, Option<Vec<u8>>>(12)?,
                        row.get::<_, Option<Vec<u8>>>(13)?,
                        row.get::<_, Option<Vec<u8>>>(14)?,
                        row.get::<_, Option<Vec<u8>>>(15)?,
                        row.get::<_, Vec<u8>>(16)?,
                    ))
                },
            )
            .optional()
            .map_err(|source| sqlite_error(&self.path, source))?;
        let Some((
            attempt_id,
            phase,
            denominator,
            frozen_electorate,
            repository_version,
            history_freshness,
            terminal_set_digest,
            witnesses,
            donor_order,
            current_donor_index,
            current_donor_node,
            current_donor_boot_epoch,
            representation_journal_id,
            representation_generation,
            representation_chain_digest,
            representation_terminal_set_digest,
            failure_history,
        )) = row
        else {
            return Ok(None);
        };
        let target = decode_recovery_target(
            &self.path,
            repository_version,
            history_freshness,
            terminal_set_digest,
        )?;
        let current_donor_index = decode_optional_u64(
            &self.path,
            current_donor_index,
            "recovery current donor index has invalid length",
        )?;
        let current_donor =
            decode_recovery_participant(&self.path, current_donor_node, current_donor_boot_epoch)?;
        let representation_cut = decode_optional_cut(
            &self.path,
            representation_journal_id,
            representation_generation,
            representation_chain_digest,
            representation_terminal_set_digest,
        )?;
        DurableRecoveryAttempt::new_with_electorate(
            decode_array(
                &self.path,
                &attempt_id,
                "recovery attempt id has invalid length",
            )?,
            DurableRecoveryPhase::decode(&self.path, phase)?,
            decode_u64(
                &self.path,
                &denominator,
                "recovery quorum denominator has invalid length",
            )?,
            rmp_serde::from_slice(&frozen_electorate)
                .map_err(SqliteTerminalJournalError::RecoveryDecode)?,
            target,
            rmp_serde::from_slice(&witnesses)
                .map_err(SqliteTerminalJournalError::RecoveryDecode)?,
            rmp_serde::from_slice(&donor_order)
                .map_err(SqliteTerminalJournalError::RecoveryDecode)?,
            current_donor_index,
            current_donor,
            representation_cut,
            rmp_serde::from_slice(&failure_history)
                .map_err(SqliteTerminalJournalError::RecoveryDecode)?,
        )
        .map(Some)
        .map_err(|reason| SqliteTerminalJournalError::InvalidData {
            path: self.path.clone(),
            reason,
        })
    }

    pub(crate) fn persist_recovery_attempt(
        &mut self,
        attempt: &DurableRecoveryAttempt,
    ) -> Result<(), SqliteTerminalJournalError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, source))?;
        write_recovery_attempt(&self.path, &transaction, attempt)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, source))
    }

    pub(crate) fn load_recovery_artifact_intent(
        &self,
    ) -> Result<Option<DurableRecoveryArtifactIntent>, SqliteTerminalJournalError> {
        let row = self
            .connection
            .query_row(
                "SELECT attempt_id, staging_path, content_digest, content_length,
                        repository_version, history_freshness, journal_id, generation,
                        chain_digest, terminal_set_digest
                 FROM strict_recovery_artifact WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                        row.get::<_, Vec<u8>>(9)?,
                    ))
                },
            )
            .optional()
            .map_err(|source| sqlite_error(&self.path, source))?;
        let Some((
            attempt_id,
            staging_path,
            content_digest,
            content_length,
            repository_version,
            history_freshness,
            journal_id,
            generation,
            chain_digest,
            terminal_set_digest,
        )) = row
        else {
            return Ok(None);
        };
        Ok(Some(DurableRecoveryArtifactIntent::new(
            decode_array(
                &self.path,
                &attempt_id,
                "recovery artifact attempt id has invalid length",
            )?,
            rmp_serde::from_slice(&staging_path)
                .map_err(SqliteTerminalJournalError::RecoveryDecode)?,
            decode_array(
                &self.path,
                &content_digest,
                "recovery artifact content digest has invalid length",
            )?,
            decode_u64(
                &self.path,
                &content_length,
                "recovery artifact content length has invalid length",
            )?,
            DurableRecoveryRepositoryMetadata::new(
                decode_u64(
                    &self.path,
                    &repository_version,
                    "recovery artifact repository version has invalid length",
                )?,
                decode_i64(
                    &self.path,
                    &history_freshness,
                    "recovery artifact history freshness has invalid length",
                )?,
            ),
            decode_cut(
                &self.path,
                &journal_id,
                &generation,
                &chain_digest,
                &terminal_set_digest,
            )?,
        )))
    }

    pub(crate) fn persist_recovery_artifact_intent(
        &mut self,
        intent: &DurableRecoveryArtifactIntent,
    ) -> Result<(), SqliteTerminalJournalError> {
        let attempt = self.load_recovery_attempt()?.ok_or_else(|| {
            SqliteTerminalJournalError::InvalidData {
                path: self.path.clone(),
                reason: "recovery artifact exists without an active recovery attempt",
            }
        })?;
        validate_artifact_intent(&self.path, &attempt, intent)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, source))?;
        write_recovery_artifact(&self.path, &transaction, intent)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, source))
    }

    /// In one durable SQLite transaction, installs the verified terminal
    /// checkpoint and records the exact staged repository image that must be
    /// rolled forward. The repository itself is not mutated here.
    pub(crate) fn prepare_recovery_install<'a>(
        &mut self,
        records: impl IntoIterator<Item = (&'a TerminalJournalOpId, &'a TerminalJournalRecord)>,
        checkpoint_epoch: u64,
        retired_origins: &BTreeMap<u64, u64>,
        cut: &TerminalCut,
        attempt: &DurableRecoveryAttempt,
        intent: &DurableRecoveryArtifactIntent,
    ) -> Result<(), SqliteTerminalJournalError> {
        if attempt.phase() != DurableRecoveryPhase::Installing {
            return Err(SqliteTerminalJournalError::InvalidData {
                path: self.path.clone(),
                reason: "recovery journal preparation requires the installing phase",
            });
        }
        validate_artifact_intent(&self.path, attempt, intent)?;
        if intent.terminal_cut() != *cut {
            return Err(SqliteTerminalJournalError::InvalidData {
                path: self.path.clone(),
                reason: "recovery artifact terminal cut does not match installed checkpoint",
            });
        }
        let encoded = encode_records(records.into_iter().collect())?;
        let repository_metadata = intent.repository_metadata();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, source))?;
        transaction
            .execute("DELETE FROM journal_records", [])
            .map_err(|source| sqlite_error(&self.path, source))?;
        insert_records(&self.path, &transaction, encoded)?;
        transaction
            .execute("DELETE FROM retired_origins", [])
            .map_err(|source| sqlite_error(&self.path, source))?;
        {
            let mut statement = transaction
                .prepare("INSERT INTO retired_origins (op_id_hi, max_counter) VALUES (?1, ?2)")
                .map_err(|source| sqlite_error(&self.path, source))?;
            for (origin, counter) in retired_origins {
                statement
                    .execute(params![
                        origin.to_be_bytes().as_slice(),
                        counter.to_be_bytes().as_slice()
                    ])
                    .map_err(|source| sqlite_error(&self.path, source))?;
            }
        }
        transaction
            .execute(
                "INSERT INTO journal_checkpoint
                     (singleton, epoch, repository_version, repository_image_install_pending,
                      repository_image_install_freshness)
                 VALUES (1, ?1, ?2, 1, ?3)
                 ON CONFLICT(singleton) DO UPDATE SET
                     epoch = excluded.epoch,
                     repository_version = excluded.repository_version,
                     repository_image_install_pending = 1,
                     repository_image_install_freshness = excluded.repository_image_install_freshness",
                params![
                    checkpoint_epoch.to_be_bytes().as_slice(),
                    repository_metadata.version().to_be_bytes().as_slice(),
                    repository_metadata.freshness().to_be_bytes().as_slice(),
                ],
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        write_metadata(&transaction, &self.topic, cut)
            .map_err(|source| sqlite_error(&self.path, source))?;
        write_recovery_attempt(&self.path, &transaction, attempt)?;
        write_recovery_artifact(&self.path, &transaction, intent)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, source))
    }

    /// Completes an installed and verified recovery image. Every durable
    /// coordinate must still name the exact attempt, repository envelope, and
    /// representation cut prepared earlier; otherwise the transaction rolls
    /// back without clearing any pending state.
    pub(crate) fn finalize_recovery_install(
        &mut self,
        attempt_id: &[u8; RECOVERY_ATTEMPT_ID_LEN],
        checkpoint_epoch: u64,
        repository_metadata: DurableRecoveryRepositoryMetadata,
        cut: &TerminalCut,
    ) -> Result<(), SqliteTerminalJournalError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, source))?;
        let checkpoint_changed = transaction
            .execute(
                "UPDATE journal_checkpoint
                 SET repository_image_install_pending = 0,
                     repository_image_install_freshness = ?4
                 WHERE singleton = 1
                   AND epoch = ?1
                   AND repository_version = ?2
                   AND repository_image_install_pending = 1
                   AND repository_image_install_freshness = ?3
                   AND EXISTS (
                       SELECT 1 FROM journal_metadata
                       WHERE singleton = 1 AND journal_id = ?5 AND generation = ?6
                         AND chain_digest = ?7 AND terminal_set_digest = ?8
                   )",
                params![
                    checkpoint_epoch.to_be_bytes().as_slice(),
                    repository_metadata.version().to_be_bytes().as_slice(),
                    repository_metadata.freshness().to_be_bytes().as_slice(),
                    0_i64.to_be_bytes().as_slice(),
                    cut.journal_id().as_slice(),
                    cut.generation().to_be_bytes().as_slice(),
                    cut.chain_digest().as_slice(),
                    cut.terminal_set_digest().as_slice(),
                ],
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        if checkpoint_changed != 1 {
            return Err(SqliteTerminalJournalError::InvalidData {
                path: self.path.clone(),
                reason: "recovery finalization does not match pending journal checkpoint",
            });
        }
        let artifact_changed = transaction
            .execute(
                "DELETE FROM strict_recovery_artifact
                 WHERE singleton = 1 AND attempt_id = ?1
                   AND repository_version = ?2 AND history_freshness = ?3
                   AND journal_id = ?4 AND generation = ?5
                   AND chain_digest = ?6 AND terminal_set_digest = ?7",
                params![
                    attempt_id.as_slice(),
                    repository_metadata.version().to_be_bytes().as_slice(),
                    repository_metadata.freshness().to_be_bytes().as_slice(),
                    cut.journal_id().as_slice(),
                    cut.generation().to_be_bytes().as_slice(),
                    cut.chain_digest().as_slice(),
                    cut.terminal_set_digest().as_slice(),
                ],
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        if artifact_changed != 1 {
            return Err(SqliteTerminalJournalError::InvalidData {
                path: self.path.clone(),
                reason: "recovery finalization does not match staged artifact intent",
            });
        }
        let attempt_changed = transaction
            .execute(
                "DELETE FROM strict_recovery_state
                 WHERE singleton = 1 AND attempt_id = ?1 AND phase = ?2
                   AND repository_version = ?3 AND history_freshness = ?4
                   AND terminal_set_digest = ?5
                   AND representation_journal_id = ?6
                   AND representation_generation = ?7
                   AND representation_chain_digest = ?8
                   AND representation_terminal_set_digest = ?9",
                params![
                    attempt_id.as_slice(),
                    DurableRecoveryPhase::Verifying.encode(),
                    repository_metadata.version().to_be_bytes().as_slice(),
                    repository_metadata.freshness().to_be_bytes().as_slice(),
                    cut.terminal_set_digest().as_slice(),
                    cut.journal_id().as_slice(),
                    cut.generation().to_be_bytes().as_slice(),
                    cut.chain_digest().as_slice(),
                    cut.terminal_set_digest().as_slice(),
                ],
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        if attempt_changed != 1 {
            return Err(SqliteTerminalJournalError::InvalidData {
                path: self.path.clone(),
                reason: "recovery finalization does not match verifying recovery attempt",
            });
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, source))
    }

    /// Removes every durable object owned by exactly one attempt. A stale
    /// cancellation cannot clear a newer recovery.
    pub(crate) fn clear_recovery_attempt(
        &mut self,
        attempt_id: &[u8; RECOVERY_ATTEMPT_ID_LEN],
    ) -> Result<(), SqliteTerminalJournalError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, source))?;
        transaction
            .execute(
                "DELETE FROM strict_recovery_artifact WHERE singleton = 1 AND attempt_id = ?1",
                [attempt_id.as_slice()],
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        let changed = transaction
            .execute(
                "DELETE FROM strict_recovery_state WHERE singleton = 1 AND attempt_id = ?1",
                [attempt_id.as_slice()],
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        if changed != 1 {
            return Err(SqliteTerminalJournalError::InvalidData {
                path: self.path.clone(),
                reason: "recovery cleanup attempt id does not match active recovery",
            });
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, source))
    }

    /// Loads all durable state. `None` denotes a newly-created, uninitialized
    /// database, not an empty initialized journal.
    pub(crate) fn load(
        &self,
    ) -> Result<Option<LoadedSqliteTerminalJournal>, SqliteTerminalJournalError> {
        self.load_inner()
    }

    /// Rebinds an initialized but otherwise pristine pre-v8 journal to the
    /// deterministic topic bootstrap lineage. Every durable guard is checked
    /// in the same transaction as the metadata update so startup can never
    /// rewrite a journal while recovery or repository installation is active.
    pub(crate) fn normalize_pristine_bootstrap_lineage(
        &mut self,
        current_cut: &TerminalCut,
        bootstrap_journal_id: [u8; JOURNAL_ID_LEN],
    ) -> Result<bool, SqliteTerminalJournalError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, source))?;
        let changed = transaction
            .execute(
                "UPDATE journal_metadata
                 SET journal_id = ?1
                 WHERE singleton = 1 AND topic = ?2
                   AND journal_id = ?3 AND generation = ?4
                   AND chain_digest = ?5 AND terminal_set_digest = ?6
                   AND NOT EXISTS (SELECT 1 FROM journal_records)
                   AND NOT EXISTS (SELECT 1 FROM retired_origins)
                   AND NOT EXISTS (SELECT 1 FROM strict_recovery_state)
                   AND NOT EXISTS (SELECT 1 FROM strict_recovery_artifact)
                   AND NOT EXISTS (
                       SELECT 1 FROM journal_checkpoint
                       WHERE epoch != ?7 OR repository_version != ?7
                          OR repository_image_install_pending != 0
                          OR repository_image_install_freshness != ?8
                   )",
                params![
                    bootstrap_journal_id.as_slice(),
                    self.topic,
                    current_cut.journal_id().as_slice(),
                    current_cut.generation().to_be_bytes().as_slice(),
                    current_cut.chain_digest().as_slice(),
                    current_cut.terminal_set_digest().as_slice(),
                    0_u64.to_be_bytes().as_slice(),
                    0_i64.to_be_bytes().as_slice(),
                ],
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, source))?;
        Ok(changed == 1)
    }

    fn load_inner(
        &self,
    ) -> Result<Option<LoadedSqliteTerminalJournal>, SqliteTerminalJournalError> {
        let metadata = self
            .connection
            .query_row(
                "SELECT topic, journal_id, generation, chain_digest, terminal_set_digest
                 FROM journal_metadata WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|source| sqlite_error(&self.path, source))?;
        let Some((topic, journal_id, generation, chain_digest, terminal_set_digest)) = metadata
        else {
            let orphaned_rows = self
                .connection
                .query_row(
                    "SELECT
                         (SELECT count(*) FROM journal_records) +
                         (SELECT count(*) FROM journal_checkpoint) +
                         (SELECT count(*) FROM retired_origins)",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|source| sqlite_error(&self.path, source))?;
            if orphaned_rows != 0 {
                return Err(SqliteTerminalJournalError::InvalidData {
                    path: self.path.clone(),
                    reason: "journal rows exist without journal metadata",
                });
            }
            return Ok(None);
        };
        if topic != self.topic {
            return Err(SqliteTerminalJournalError::TopicMismatch {
                path: self.path.clone(),
                expected: self.topic.clone(),
                found: topic,
            });
        }
        let cut = decode_cut(
            &self.path,
            &journal_id,
            &generation,
            &chain_digest,
            &terminal_set_digest,
        )?;

        let mut statement = self
            .connection
            .prepare(
                "SELECT op_id_hi, op_id_lo, record
                 FROM journal_records ORDER BY op_id_hi, op_id_lo",
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|source| sqlite_error(&self.path, source))?;
        let mut records = BTreeMap::new();
        for row in rows {
            let (hi, lo, encoded) = row.map_err(|source| sqlite_error(&self.path, source))?;
            let op_id = (
                decode_u64(&self.path, &hi, "operation high id has invalid length")?,
                decode_u64(&self.path, &lo, "operation low id has invalid length")?,
            );
            let record =
                rmp_serde::from_slice(&encoded).map_err(SqliteTerminalJournalError::Decode)?;
            records.insert(op_id, record);
        }
        let checkpoint = self
            .connection
            .query_row(
                "SELECT epoch, repository_version, repository_image_install_pending,
                        repository_image_install_freshness
                 FROM journal_checkpoint WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|source| sqlite_error(&self.path, source))?;
        let has_checkpoint = checkpoint.is_some();
        let (
            checkpoint_epoch,
            checkpoint_repository_version,
            repository_image_install_pending,
            repository_image_install_freshness,
        ) = match checkpoint {
            Some((epoch, version, pending, freshness)) => (
                decode_u64(&self.path, &epoch, "checkpoint epoch has invalid length")?,
                decode_u64(
                    &self.path,
                    &version,
                    "checkpoint repository version has invalid length",
                )?,
                match pending {
                    0 => false,
                    1 => true,
                    _ => {
                        return Err(SqliteTerminalJournalError::InvalidData {
                            path: self.path.clone(),
                            reason: "repository image install marker is invalid",
                        });
                    }
                },
                decode_i64(
                    &self.path,
                    &freshness,
                    "repository image install freshness has invalid length",
                )?,
            ),
            None => (0, 0, false, 0),
        };
        let mut statement = self
            .connection
            .prepare("SELECT op_id_hi, max_counter FROM retired_origins ORDER BY op_id_hi")
            .map_err(|source| sqlite_error(&self.path, source))?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|source| sqlite_error(&self.path, source))?;
        let mut retired_origins = BTreeMap::new();
        for row in rows {
            let (origin, counter) = row.map_err(|source| sqlite_error(&self.path, source))?;
            retired_origins.insert(
                decode_u64(&self.path, &origin, "retired origin has invalid length")?,
                decode_u64(&self.path, &counter, "retired counter has invalid length")?,
            );
        }
        if !retired_origins.is_empty() && !has_checkpoint {
            return Err(SqliteTerminalJournalError::InvalidData {
                path: self.path.clone(),
                reason: "retired origins exist without checkpoint metadata",
            });
        }
        if records.keys().any(|op_id| {
            let node = op_id.0 >> 48;
            let lower = node << 48;
            let upper = lower | 0x0000_FFFF_FFFF_FFFF;
            retired_origins
                .range(lower..=upper)
                .next_back()
                .is_some_and(|(origin, counter)| {
                    op_id.0 < *origin || (op_id.0 == *origin && op_id.1 <= *counter)
                })
        }) {
            return Err(SqliteTerminalJournalError::InvalidData {
                path: self.path.clone(),
                reason: "retained journal record is covered by a retired origin",
            });
        }
        Ok(Some(LoadedSqliteTerminalJournal {
            records,
            cut,
            checkpoint_epoch,
            checkpoint_repository_version,
            retired_origins,
            repository_image_install_pending,
            repository_image_install_freshness,
        }))
    }

    /// Atomically upserts one record and the terminal cut produced by that
    /// mutation. Only the changed record is serialized.
    pub(crate) fn upsert_record(
        &mut self,
        op_id: TerminalJournalOpId,
        record: &TerminalJournalRecord,
        cut: &TerminalCut,
    ) -> Result<(), SqliteTerminalJournalError> {
        self.upsert_record_inner(op_id, record, cut)
    }

    fn upsert_record_inner(
        &mut self,
        op_id: TerminalJournalOpId,
        record: &TerminalJournalRecord,
        cut: &TerminalCut,
    ) -> Result<(), SqliteTerminalJournalError> {
        let encoded =
            rmp_serde::to_vec_named(record).map_err(SqliteTerminalJournalError::Encode)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, source))?;
        transaction
            .execute(
                "INSERT INTO journal_records (op_id_hi, op_id_lo, record)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(op_id_hi, op_id_lo) DO UPDATE SET record = excluded.record",
                params![
                    op_id.0.to_be_bytes().as_slice(),
                    op_id.1.to_be_bytes().as_slice(),
                    encoded
                ],
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        write_metadata(&transaction, &self.topic, cut)
            .map_err(|source| sqlite_error(&self.path, source))?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, source))
    }

    /// Atomically replaces all records. This is the JSON migration and exact
    /// checkpoint-install hook; it performs one durable commit for the batch.
    pub(crate) fn replace_all<'a>(
        &mut self,
        records: impl IntoIterator<Item = (&'a TerminalJournalOpId, &'a TerminalJournalRecord)>,
        cut: &TerminalCut,
    ) -> Result<(), SqliteTerminalJournalError> {
        let records = records.into_iter().collect::<Vec<_>>();
        self.replace_all_inner(records, cut)
    }

    fn replace_all_inner(
        &mut self,
        records: Vec<(&TerminalJournalOpId, &TerminalJournalRecord)>,
        cut: &TerminalCut,
    ) -> Result<(), SqliteTerminalJournalError> {
        let encoded = encode_records(records)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, source))?;
        transaction
            .execute("DELETE FROM journal_records", [])
            .map_err(|source| sqlite_error(&self.path, source))?;
        insert_records(&self.path, &transaction, encoded)?;
        write_metadata(&transaction, &self.topic, cut)
            .map_err(|source| sqlite_error(&self.path, source))?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, source))
    }

    pub(crate) fn checkpoint(
        &mut self,
        epoch: u64,
        repository_version: u64,
        retired_origins: &BTreeMap<u64, u64>,
        cut: &TerminalCut,
    ) -> Result<(), SqliteTerminalJournalError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, source))?;
        transaction
            .execute("DELETE FROM journal_records", [])
            .map_err(|source| sqlite_error(&self.path, source))?;
        transaction
            .execute("DELETE FROM retired_origins", [])
            .map_err(|source| sqlite_error(&self.path, source))?;
        {
            let mut statement = transaction
                .prepare("INSERT INTO retired_origins (op_id_hi, max_counter) VALUES (?1, ?2)")
                .map_err(|source| sqlite_error(&self.path, source))?;
            for (origin, counter) in retired_origins {
                statement
                    .execute(params![
                        origin.to_be_bytes().as_slice(),
                        counter.to_be_bytes().as_slice()
                    ])
                    .map_err(|source| sqlite_error(&self.path, source))?;
            }
        }
        transaction
            .execute(
                "INSERT INTO journal_checkpoint
                     (singleton, epoch, repository_version, repository_image_install_pending,
                      repository_image_install_freshness)
                 VALUES (1, ?1, ?2, 0, ?3)
                 ON CONFLICT(singleton) DO UPDATE SET
                     epoch = excluded.epoch,
                     repository_version = excluded.repository_version,
                     repository_image_install_pending = excluded.repository_image_install_pending,
                     repository_image_install_freshness = excluded.repository_image_install_freshness",
                params![
                    epoch.to_be_bytes().as_slice(),
                    repository_version.to_be_bytes().as_slice(),
                    0_i64.to_be_bytes().as_slice()
                ],
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        write_metadata(&transaction, &self.topic, cut)
            .map_err(|source| sqlite_error(&self.path, source))?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, source))
    }

    /// Atomically prepares repository coverage without rotating the active
    /// terminal set. The pending marker remains durable until the paired
    /// repository image has been installed and explicitly completed. History
    /// recovery synchronizes the terminal set before fetching that image, so
    /// retaining it keeps the receiver equal to the elected source.
    pub(crate) fn install_repository_base<'a>(
        &mut self,
        records: impl IntoIterator<Item = (&'a TerminalJournalOpId, &'a TerminalJournalRecord)>,
        epoch: u64,
        repository_version: u64,
        repository_freshness: i64,
        retired_origins: &BTreeMap<u64, u64>,
        cut: &TerminalCut,
    ) -> Result<(), SqliteTerminalJournalError> {
        let encoded = encode_records(records.into_iter().collect())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, source))?;
        transaction
            .execute("DELETE FROM journal_records", [])
            .map_err(|source| sqlite_error(&self.path, source))?;
        insert_records(&self.path, &transaction, encoded)?;
        transaction
            .execute("DELETE FROM retired_origins", [])
            .map_err(|source| sqlite_error(&self.path, source))?;
        {
            let mut statement = transaction
                .prepare("INSERT INTO retired_origins (op_id_hi, max_counter) VALUES (?1, ?2)")
                .map_err(|source| sqlite_error(&self.path, source))?;
            for (origin, counter) in retired_origins {
                statement
                    .execute(params![
                        origin.to_be_bytes().as_slice(),
                        counter.to_be_bytes().as_slice()
                    ])
                    .map_err(|source| sqlite_error(&self.path, source))?;
            }
        }
        transaction
            .execute(
                "INSERT INTO journal_checkpoint
                     (singleton, epoch, repository_version, repository_image_install_pending,
                      repository_image_install_freshness)
                 VALUES (1, ?1, ?2, 1, ?3)
                 ON CONFLICT(singleton) DO UPDATE SET
                     epoch = excluded.epoch,
                     repository_version = excluded.repository_version,
                     repository_image_install_pending = excluded.repository_image_install_pending,
                     repository_image_install_freshness = excluded.repository_image_install_freshness",
                params![
                    epoch.to_be_bytes().as_slice(),
                    repository_version.to_be_bytes().as_slice(),
                    repository_freshness.to_be_bytes().as_slice()
                ],
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        write_metadata(&transaction, &self.topic, cut)
            .map_err(|source| sqlite_error(&self.path, source))?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, source))
    }

    /// Durably completes the cross-store repository image installation that
    /// was prepared by [`Self::install_repository_base`]. The checkpoint
    /// epoch and elected repository rank must still identify that exact
    /// preparation.
    pub(crate) fn complete_repository_image_install(
        &mut self,
        epoch: u64,
        repository_version: u64,
        repository_freshness: i64,
    ) -> Result<(), SqliteTerminalJournalError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, source))?;
        let changed = transaction
            .execute(
                "UPDATE journal_checkpoint
                 SET repository_image_install_pending = 0,
                     repository_image_install_freshness = ?4
                 WHERE singleton = 1 AND epoch = ?1 AND repository_version = ?2
                     AND repository_image_install_freshness = ?3",
                params![
                    epoch.to_be_bytes().as_slice(),
                    repository_version.to_be_bytes().as_slice(),
                    repository_freshness.to_be_bytes().as_slice(),
                    0_i64.to_be_bytes().as_slice()
                ],
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        if changed != 1 {
            return Err(SqliteTerminalJournalError::InvalidData {
                path: self.path.clone(),
                reason: "repository image install completion does not match checkpoint metadata",
            });
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, source))
    }
}

fn create_schema_v3(
    path: &Path,
    connection: &mut Connection,
) -> Result<(), SqliteTerminalJournalError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|source| sqlite_error(path, source))?;
    transaction
        .execute_batch(
            "CREATE TABLE journal_metadata (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 topic TEXT NOT NULL,
                 journal_id BLOB NOT NULL CHECK (length(journal_id) = 16),
                 generation BLOB NOT NULL CHECK (length(generation) = 8),
                 chain_digest BLOB NOT NULL CHECK (length(chain_digest) = 32),
                 terminal_set_digest BLOB NOT NULL CHECK (length(terminal_set_digest) = 32)
             ) STRICT;
             CREATE TABLE journal_records (
                 op_id_hi BLOB NOT NULL CHECK (length(op_id_hi) = 8),
                 op_id_lo BLOB NOT NULL CHECK (length(op_id_lo) = 8),
                 record BLOB NOT NULL,
                 PRIMARY KEY (op_id_hi, op_id_lo)
             ) WITHOUT ROWID, STRICT;
             CREATE TABLE journal_checkpoint (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 epoch BLOB NOT NULL CHECK (length(epoch) = 8),
                 repository_version BLOB NOT NULL CHECK (length(repository_version) = 8),
                 repository_image_install_pending INTEGER NOT NULL DEFAULT 0
                     CHECK (repository_image_install_pending IN (0, 1)),
                 repository_image_install_freshness BLOB NOT NULL
                     DEFAULT X'0000000000000000'
                     CHECK (length(repository_image_install_freshness) = 8)
             ) STRICT;
             CREATE TABLE retired_origins (
                 op_id_hi BLOB PRIMARY KEY CHECK (length(op_id_hi) = 8),
                 max_counter BLOB NOT NULL CHECK (length(max_counter) = 8)
             ) WITHOUT ROWID, STRICT;
             PRAGMA user_version = 3;",
        )
        .map_err(|source| sqlite_error(path, source))?;
    transaction
        .commit()
        .map_err(|source| sqlite_error(path, source))
}

fn migrate_schema_v1_to_v2(
    path: &Path,
    connection: &mut Connection,
) -> Result<(), SqliteTerminalJournalError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|source| sqlite_error(path, source))?;
    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS journal_checkpoint (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 epoch BLOB NOT NULL CHECK (length(epoch) = 8),
                 repository_version BLOB NOT NULL CHECK (length(repository_version) = 8)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS retired_origins (
                 op_id_hi BLOB PRIMARY KEY CHECK (length(op_id_hi) = 8),
                 max_counter BLOB NOT NULL CHECK (length(max_counter) = 8)
             ) WITHOUT ROWID, STRICT;
             PRAGMA user_version = 2;",
        )
        .map_err(|source| sqlite_error(path, source))?;
    transaction
        .commit()
        .map_err(|source| sqlite_error(path, source))
}

fn migrate_schema_v2_to_v3(
    path: &Path,
    connection: &mut Connection,
) -> Result<(), SqliteTerminalJournalError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|source| sqlite_error(path, source))?;
    transaction
        .execute_batch(
            "ALTER TABLE journal_checkpoint ADD COLUMN
                 repository_image_install_pending INTEGER NOT NULL DEFAULT 0
                 CHECK (repository_image_install_pending IN (0, 1));
             ALTER TABLE journal_checkpoint ADD COLUMN
                 repository_image_install_freshness BLOB NOT NULL
                 DEFAULT X'0000000000000000'
                 CHECK (length(repository_image_install_freshness) = 8);
             PRAGMA user_version = 3;",
        )
        .map_err(|source| sqlite_error(path, source))?;
    transaction
        .commit()
        .map_err(|source| sqlite_error(path, source))
}

fn migrate_schema_v3_to_v4(
    path: &Path,
    connection: &mut Connection,
) -> Result<(), SqliteTerminalJournalError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|source| sqlite_error(path, source))?;
    transaction
        .execute_batch(
            "CREATE TABLE strict_recovery_state (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 attempt_id BLOB NOT NULL UNIQUE CHECK (length(attempt_id) = 16),
                 phase INTEGER NOT NULL CHECK (phase BETWEEN 1 AND 7),
                 frozen_quorum_denominator BLOB NOT NULL
                     CHECK (length(frozen_quorum_denominator) = 8),
                 repository_version BLOB CHECK
                     (repository_version IS NULL OR length(repository_version) = 8),
                 history_freshness BLOB CHECK
                     (history_freshness IS NULL OR length(history_freshness) = 8),
                 terminal_set_digest BLOB CHECK
                     (terminal_set_digest IS NULL OR length(terminal_set_digest) = 32),
                 witnesses BLOB NOT NULL,
                 donor_order BLOB NOT NULL,
                 current_donor_index BLOB CHECK
                     (current_donor_index IS NULL OR length(current_donor_index) = 8),
                 current_donor_node INTEGER CHECK
                     (current_donor_node IS NULL OR current_donor_node BETWEEN 0 AND 65535),
                 current_donor_boot_epoch BLOB CHECK
                     (current_donor_boot_epoch IS NULL OR length(current_donor_boot_epoch) = 8),
                 representation_journal_id BLOB CHECK
                     (representation_journal_id IS NULL OR length(representation_journal_id) = 16),
                 representation_generation BLOB CHECK
                     (representation_generation IS NULL OR length(representation_generation) = 8),
                 representation_chain_digest BLOB CHECK
                     (representation_chain_digest IS NULL OR length(representation_chain_digest) = 32),
                 representation_terminal_set_digest BLOB CHECK
                     (representation_terminal_set_digest IS NULL OR
                      length(representation_terminal_set_digest) = 32),
                 failure_history BLOB NOT NULL,
                 CHECK ((repository_version IS NULL) = (history_freshness IS NULL)
                    AND (repository_version IS NULL) = (terminal_set_digest IS NULL)),
                 CHECK ((current_donor_index IS NULL) = (current_donor_node IS NULL)
                    AND (current_donor_index IS NULL) = (current_donor_boot_epoch IS NULL)),
                 CHECK ((representation_journal_id IS NULL) =
                        (representation_generation IS NULL)
                    AND (representation_journal_id IS NULL) =
                        (representation_chain_digest IS NULL)
                    AND (representation_journal_id IS NULL) =
                        (representation_terminal_set_digest IS NULL))
             ) STRICT;
             CREATE TABLE strict_recovery_artifact (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 attempt_id BLOB NOT NULL CHECK (length(attempt_id) = 16),
                 staging_path BLOB NOT NULL,
                 content_digest BLOB NOT NULL CHECK (length(content_digest) = 32),
                 content_length BLOB NOT NULL CHECK (length(content_length) = 8),
                 repository_version BLOB NOT NULL CHECK (length(repository_version) = 8),
                 history_freshness BLOB NOT NULL CHECK (length(history_freshness) = 8),
                 journal_id BLOB NOT NULL CHECK (length(journal_id) = 16),
                 generation BLOB NOT NULL CHECK (length(generation) = 8),
                 chain_digest BLOB NOT NULL CHECK (length(chain_digest) = 32),
                 terminal_set_digest BLOB NOT NULL CHECK (length(terminal_set_digest) = 32),
                 FOREIGN KEY (attempt_id) REFERENCES strict_recovery_state (attempt_id)
                     ON DELETE RESTRICT
             ) STRICT;
             PRAGMA user_version = 4;",
        )
        .map_err(|source| sqlite_error(path, source))?;
    transaction
        .commit()
        .map_err(|source| sqlite_error(path, source))
}

fn migrate_schema_v4_to_v5(
    path: &Path,
    connection: &mut Connection,
) -> Result<(), SqliteTerminalJournalError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|source| sqlite_error(path, source))?;
    transaction
        .execute_batch(
            "ALTER TABLE strict_recovery_state ADD COLUMN
                 frozen_electorate BLOB NOT NULL DEFAULT X'90';
             PRAGMA user_version = 5;",
        )
        .map_err(|source| sqlite_error(path, source))?;
    transaction
        .commit()
        .map_err(|source| sqlite_error(path, source))
}

fn write_recovery_attempt(
    path: &Path,
    transaction: &rusqlite::Transaction<'_>,
    attempt: &DurableRecoveryAttempt,
) -> Result<(), SqliteTerminalJournalError> {
    let frozen_electorate = rmp_serde::to_vec_named(attempt.frozen_electorate())
        .map_err(SqliteTerminalJournalError::RecoveryEncode)?;
    let witnesses = rmp_serde::to_vec_named(attempt.witnesses())
        .map_err(SqliteTerminalJournalError::RecoveryEncode)?;
    let donor_order = rmp_serde::to_vec_named(attempt.donor_order())
        .map_err(SqliteTerminalJournalError::RecoveryEncode)?;
    let failure_history = rmp_serde::to_vec_named(attempt.failure_history())
        .map_err(SqliteTerminalJournalError::RecoveryEncode)?;
    let target = attempt.target();
    let repository_version = target.map(|target| target.repository_version().to_be_bytes());
    let history_freshness = target.map(|target| target.history_freshness().to_be_bytes());
    let terminal_set_digest = target.map(|target| *target.terminal_set_digest());
    let current_donor_index = attempt.current_donor_index().map(u64::to_be_bytes);
    let current_donor_node = attempt
        .current_donor()
        .map(|participant| i64::from(participant.node_id()));
    let current_donor_boot_epoch = attempt
        .current_donor()
        .map(|participant| participant.boot_epoch().to_be_bytes());
    let representation = attempt.representation_cut();
    let representation_journal_id = representation.map(|cut| *cut.journal_id());
    let representation_generation = representation.map(|cut| cut.generation().to_be_bytes());
    let representation_chain_digest = representation.map(|cut| *cut.chain_digest());
    let representation_terminal_set_digest = representation.map(|cut| *cut.terminal_set_digest());
    transaction
        .execute(
            "INSERT INTO strict_recovery_state
                 (singleton, attempt_id, phase, frozen_quorum_denominator, frozen_electorate,
                  repository_version, history_freshness, terminal_set_digest,
                  witnesses, donor_order, current_donor_index, current_donor_node,
                  current_donor_boot_epoch, representation_journal_id,
                  representation_generation, representation_chain_digest,
                  representation_terminal_set_digest, failure_history)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                     ?12, ?13, ?14, ?15, ?16, ?17)
             ON CONFLICT(singleton) DO UPDATE SET
                 attempt_id = excluded.attempt_id,
                 phase = excluded.phase,
                 frozen_quorum_denominator = excluded.frozen_quorum_denominator,
                 frozen_electorate = excluded.frozen_electorate,
                 repository_version = excluded.repository_version,
                 history_freshness = excluded.history_freshness,
                 terminal_set_digest = excluded.terminal_set_digest,
                 witnesses = excluded.witnesses,
                 donor_order = excluded.donor_order,
                 current_donor_index = excluded.current_donor_index,
                 current_donor_node = excluded.current_donor_node,
                 current_donor_boot_epoch = excluded.current_donor_boot_epoch,
                 representation_journal_id = excluded.representation_journal_id,
                 representation_generation = excluded.representation_generation,
                 representation_chain_digest = excluded.representation_chain_digest,
                 representation_terminal_set_digest =
                     excluded.representation_terminal_set_digest,
                 failure_history = excluded.failure_history",
            params![
                attempt.attempt_id().as_slice(),
                attempt.phase().encode(),
                attempt.frozen_quorum_denominator().to_be_bytes().as_slice(),
                frozen_electorate,
                repository_version.as_ref().map(|value| value.as_slice()),
                history_freshness.as_ref().map(|value| value.as_slice()),
                terminal_set_digest.as_ref().map(|value| value.as_slice()),
                witnesses,
                donor_order,
                current_donor_index.as_ref().map(|value| value.as_slice()),
                current_donor_node,
                current_donor_boot_epoch
                    .as_ref()
                    .map(|value| value.as_slice()),
                representation_journal_id
                    .as_ref()
                    .map(|value| value.as_slice()),
                representation_generation
                    .as_ref()
                    .map(|value| value.as_slice()),
                representation_chain_digest
                    .as_ref()
                    .map(|value| value.as_slice()),
                representation_terminal_set_digest
                    .as_ref()
                    .map(|value| value.as_slice()),
                failure_history,
            ],
        )
        .map_err(|source| sqlite_error(path, source))?;
    Ok(())
}

fn validate_artifact_intent(
    path: &Path,
    attempt: &DurableRecoveryAttempt,
    intent: &DurableRecoveryArtifactIntent,
) -> Result<(), SqliteTerminalJournalError> {
    let target = attempt
        .target()
        .ok_or_else(|| SqliteTerminalJournalError::InvalidData {
            path: path.to_path_buf(),
            reason: "recovery artifact requires a certified recovery target",
        })?;
    let metadata = intent.repository_metadata();
    if attempt.attempt_id() != intent.attempt_id() {
        return Err(SqliteTerminalJournalError::InvalidData {
            path: path.to_path_buf(),
            reason: "recovery artifact attempt id does not match active recovery",
        });
    }
    if target.repository_version() != metadata.version()
        || target.history_freshness() != metadata.freshness()
    {
        return Err(SqliteTerminalJournalError::InvalidData {
            path: path.to_path_buf(),
            reason: "recovery artifact repository metadata does not match certified target",
        });
    }
    if target.terminal_set_digest() != intent.terminal_cut().terminal_set_digest() {
        return Err(SqliteTerminalJournalError::InvalidData {
            path: path.to_path_buf(),
            reason: "recovery artifact terminal cut does not match certified target",
        });
    }
    if attempt.representation_cut() != Some(intent.terminal_cut()) {
        return Err(SqliteTerminalJournalError::InvalidData {
            path: path.to_path_buf(),
            reason: "recovery artifact does not match the selected representation cut",
        });
    }
    Ok(())
}

fn write_recovery_artifact(
    path: &Path,
    transaction: &rusqlite::Transaction<'_>,
    intent: &DurableRecoveryArtifactIntent,
) -> Result<(), SqliteTerminalJournalError> {
    let staging_path = rmp_serde::to_vec_named(intent.staging_path())
        .map_err(SqliteTerminalJournalError::RecoveryEncode)?;
    let metadata = intent.repository_metadata();
    let cut = intent.terminal_cut();
    transaction
        .execute(
            "INSERT INTO strict_recovery_artifact
                 (singleton, attempt_id, staging_path, content_digest, content_length,
                  repository_version, history_freshness, journal_id, generation,
                  chain_digest, terminal_set_digest)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(singleton) DO UPDATE SET
                 attempt_id = excluded.attempt_id,
                 staging_path = excluded.staging_path,
                 content_digest = excluded.content_digest,
                 content_length = excluded.content_length,
                 repository_version = excluded.repository_version,
                 history_freshness = excluded.history_freshness,
                 journal_id = excluded.journal_id,
                 generation = excluded.generation,
                 chain_digest = excluded.chain_digest,
                 terminal_set_digest = excluded.terminal_set_digest",
            params![
                intent.attempt_id().as_slice(),
                staging_path,
                intent.content_digest().as_slice(),
                intent.content_length().to_be_bytes().as_slice(),
                metadata.version().to_be_bytes().as_slice(),
                metadata.freshness().to_be_bytes().as_slice(),
                cut.journal_id().as_slice(),
                cut.generation().to_be_bytes().as_slice(),
                cut.chain_digest().as_slice(),
                cut.terminal_set_digest().as_slice(),
            ],
        )
        .map_err(|source| sqlite_error(path, source))?;
    Ok(())
}

fn encode_records(
    records: Vec<(&TerminalJournalOpId, &TerminalJournalRecord)>,
) -> Result<Vec<(TerminalJournalOpId, Vec<u8>)>, SqliteTerminalJournalError> {
    records
        .into_iter()
        .map(|(op_id, record)| {
            rmp_serde::to_vec_named(record)
                .map(|record| (*op_id, record))
                .map_err(SqliteTerminalJournalError::Encode)
        })
        .collect()
}

fn insert_records(
    path: &Path,
    transaction: &rusqlite::Transaction<'_>,
    records: Vec<(TerminalJournalOpId, Vec<u8>)>,
) -> Result<(), SqliteTerminalJournalError> {
    let mut statement = transaction
        .prepare(
            "INSERT INTO journal_records (op_id_hi, op_id_lo, record)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(op_id_hi, op_id_lo) DO UPDATE SET record = excluded.record",
        )
        .map_err(|source| sqlite_error(path, source))?;
    for (op_id, record) in records {
        statement
            .execute(params![
                op_id.0.to_be_bytes().as_slice(),
                op_id.1.to_be_bytes().as_slice(),
                record
            ])
            .map_err(|source| sqlite_error(path, source))?;
    }
    Ok(())
}

fn write_metadata(
    transaction: &rusqlite::Transaction<'_>,
    topic: &str,
    cut: &TerminalCut,
) -> Result<(), rusqlite::Error> {
    transaction.execute(
        "INSERT INTO journal_metadata
             (singleton, topic, journal_id, generation, chain_digest, terminal_set_digest)
         VALUES (1, ?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(singleton) DO UPDATE SET
             topic = excluded.topic,
             journal_id = excluded.journal_id,
             generation = excluded.generation,
             chain_digest = excluded.chain_digest,
             terminal_set_digest = excluded.terminal_set_digest",
        params![
            topic,
            cut.journal_id().as_slice(),
            cut.generation().to_be_bytes().as_slice(),
            cut.chain_digest().as_slice(),
            cut.terminal_set_digest().as_slice(),
        ],
    )?;
    Ok(())
}

fn decode_cut(
    path: &Path,
    journal_id: &[u8],
    generation: &[u8],
    chain_digest: &[u8],
    terminal_set_digest: &[u8],
) -> Result<TerminalCut, SqliteTerminalJournalError> {
    Ok(TerminalCut::new(
        decode_array(path, journal_id, "journal id has invalid length")?,
        decode_u64(path, generation, "generation has invalid length")?,
        decode_array(path, chain_digest, "chain digest has invalid length")?,
        decode_array(
            path,
            terminal_set_digest,
            "terminal-set digest has invalid length",
        )?,
    ))
}

fn decode_recovery_target(
    path: &Path,
    repository_version: Option<Vec<u8>>,
    history_freshness: Option<Vec<u8>>,
    terminal_set_digest: Option<Vec<u8>>,
) -> Result<Option<DurableRecoveryTarget>, SqliteTerminalJournalError> {
    match (repository_version, history_freshness, terminal_set_digest) {
        (None, None, None) => Ok(None),
        (Some(version), Some(freshness), Some(digest)) => Ok(Some(DurableRecoveryTarget::new(
            decode_u64(
                path,
                &version,
                "recovery repository version has invalid length",
            )?,
            decode_i64(
                path,
                &freshness,
                "recovery history freshness has invalid length",
            )?,
            decode_array(
                path,
                &digest,
                "recovery terminal-set digest has invalid length",
            )?,
        ))),
        _ => Err(SqliteTerminalJournalError::InvalidData {
            path: path.to_path_buf(),
            reason: "recovery logical target is only partially present",
        }),
    }
}

fn decode_recovery_participant(
    path: &Path,
    node_id: Option<i64>,
    boot_epoch: Option<Vec<u8>>,
) -> Result<Option<DurableRecoveryParticipant>, SqliteTerminalJournalError> {
    match (node_id, boot_epoch) {
        (None, None) => Ok(None),
        (Some(node_id), Some(boot_epoch)) => Ok(Some(DurableRecoveryParticipant::new(
            u16::try_from(node_id).map_err(|_| SqliteTerminalJournalError::InvalidData {
                path: path.to_path_buf(),
                reason: "recovery current donor node id is invalid",
            })?,
            decode_u64(
                path,
                &boot_epoch,
                "recovery current donor boot epoch has invalid length",
            )?,
        ))),
        _ => Err(SqliteTerminalJournalError::InvalidData {
            path: path.to_path_buf(),
            reason: "recovery current donor is only partially present",
        }),
    }
}

fn decode_optional_cut(
    path: &Path,
    journal_id: Option<Vec<u8>>,
    generation: Option<Vec<u8>>,
    chain_digest: Option<Vec<u8>>,
    terminal_set_digest: Option<Vec<u8>>,
) -> Result<Option<TerminalCut>, SqliteTerminalJournalError> {
    match (journal_id, generation, chain_digest, terminal_set_digest) {
        (None, None, None, None) => Ok(None),
        (Some(journal_id), Some(generation), Some(chain_digest), Some(terminal_set_digest)) => {
            decode_cut(
                path,
                &journal_id,
                &generation,
                &chain_digest,
                &terminal_set_digest,
            )
            .map(Some)
        }
        _ => Err(SqliteTerminalJournalError::InvalidData {
            path: path.to_path_buf(),
            reason: "recovery representation cut is only partially present",
        }),
    }
}

fn decode_optional_u64(
    path: &Path,
    bytes: Option<Vec<u8>>,
    reason: &'static str,
) -> Result<Option<u64>, SqliteTerminalJournalError> {
    bytes
        .map(|bytes| decode_u64(path, &bytes, reason))
        .transpose()
}

fn decode_u64(
    path: &Path,
    bytes: &[u8],
    reason: &'static str,
) -> Result<u64, SqliteTerminalJournalError> {
    Ok(u64::from_be_bytes(decode_array(path, bytes, reason)?))
}

fn decode_i64(
    path: &Path,
    bytes: &[u8],
    reason: &'static str,
) -> Result<i64, SqliteTerminalJournalError> {
    Ok(i64::from_be_bytes(decode_array(path, bytes, reason)?))
}

fn decode_array<const N: usize>(
    path: &Path,
    bytes: &[u8],
    reason: &'static str,
) -> Result<[u8; N], SqliteTerminalJournalError> {
    bytes
        .try_into()
        .map_err(|_| SqliteTerminalJournalError::InvalidData {
            path: path.to_path_buf(),
            reason,
        })
}

fn sqlite_error(path: &Path, source: rusqlite::Error) -> SqliteTerminalJournalError {
    SqliteTerminalJournalError::Sqlite {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_upserts_and_reopens() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal.sqlite3");
        let initial = TerminalCut::new([7; 16], 0, [0; 32], [1; 32]);
        let resulting = TerminalCut::new([7; 16], 1, [2; 32], [3; 32]);
        let record = TerminalJournalRecord::default();
        {
            let mut store = SqliteTerminalJournalStore::open(&path, "topic").unwrap();
            assert!(store.load().unwrap().is_none());
            store.replace_all(std::iter::empty(), &initial).unwrap();
            store
                .upsert_record((u64::MAX, 42), &record, &resulting)
                .unwrap();
        }
        let store = SqliteTerminalJournalStore::open(&path, "topic").unwrap();
        let (records, cut, _, _, _, pending, freshness) =
            store.load().unwrap().unwrap().into_parts();
        assert_eq!(records.get(&(u64::MAX, 42)), Some(&record));
        assert_eq!(cut, resulting);
        assert!(!pending);
        assert_eq!(freshness, 0);
    }

    #[test]
    fn replace_all_is_exact() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal.sqlite3");
        let cut = TerminalCut::new([9; 16], 2, [4; 32], [5; 32]);
        let records = BTreeMap::from([
            ((1, 2), TerminalJournalRecord::default()),
            ((3, 4), TerminalJournalRecord::default()),
        ]);
        let mut store = SqliteTerminalJournalStore::open(&path, "topic").unwrap();
        store.replace_all(records.iter(), &cut).unwrap();
        let (loaded, loaded_cut, _, _, _, pending, freshness) =
            store.load().unwrap().unwrap().into_parts();
        assert_eq!(loaded, records);
        assert_eq!(loaded_cut, cut);
        assert!(!pending);
        assert_eq!(freshness, 0);
    }
}
