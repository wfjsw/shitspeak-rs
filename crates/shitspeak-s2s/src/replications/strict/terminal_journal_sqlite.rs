//! SQLite persistence for the strict terminal journal.
//!
//! This module deliberately contains no async synchronization. `rusqlite`
//! calls, and especially a `FULL`-synchronous commit, must be scheduled by the
//! caller on the shared S2S blocking pool rather than on a Tokio executor
//! thread. A mutation serializes only the changed record and commits that row
//! and its resulting terminal cut in one transaction.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;

use super::terminal_journal::{TerminalCut, TerminalJournalOpId, TerminalJournalRecord};

const SCHEMA_VERSION: i64 = 2;
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
}

impl LoadedSqliteTerminalJournal {
    pub(crate) fn into_parts(
        self,
    ) -> (
        BTreeMap<TerminalJournalOpId, TerminalJournalRecord>,
        TerminalCut,
        u64,
        u64,
        BTreeMap<u64, u64>,
    ) {
        (
            self.records,
            self.cut,
            self.checkpoint_epoch,
            self.checkpoint_repository_version,
            self.retired_origins,
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
            0 => create_schema_v2(&path, &mut connection)?,
            1 => migrate_schema_v1_to_v2(&path, &mut connection)?,
            SCHEMA_VERSION => {}
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

    /// Loads all durable state. `None` denotes a newly-created, uninitialized
    /// database, not an empty initialized journal.
    pub(crate) fn load(
        &self,
    ) -> Result<Option<LoadedSqliteTerminalJournal>, SqliteTerminalJournalError> {
        self.load_inner()
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
                "SELECT epoch, repository_version FROM journal_checkpoint WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|source| sqlite_error(&self.path, source))?;
        let has_checkpoint = checkpoint.is_some();
        let (checkpoint_epoch, checkpoint_repository_version) = match checkpoint {
            Some((epoch, version)) => (
                decode_u64(&self.path, &epoch, "checkpoint epoch has invalid length")?,
                decode_u64(
                    &self.path,
                    &version,
                    "checkpoint repository version has invalid length",
                )?,
            ),
            None => (0, 0),
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
                "INSERT INTO journal_checkpoint (singleton, epoch, repository_version)
                 VALUES (1, ?1, ?2)
                 ON CONFLICT(singleton) DO UPDATE SET
                     epoch = excluded.epoch,
                     repository_version = excluded.repository_version",
                params![
                    epoch.to_be_bytes().as_slice(),
                    repository_version.to_be_bytes().as_slice()
                ],
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        write_metadata(&transaction, &self.topic, cut)
            .map_err(|source| sqlite_error(&self.path, source))?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, source))
    }

    /// Atomically install repository coverage without rotating the active
    /// terminal set. History recovery synchronizes that set before fetching
    /// the repository image, so retaining it keeps the receiver's terminal
    /// digest equal to the elected source after snapshot installation.
    pub(crate) fn install_repository_base<'a>(
        &mut self,
        records: impl IntoIterator<Item = (&'a TerminalJournalOpId, &'a TerminalJournalRecord)>,
        epoch: u64,
        repository_version: u64,
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
                "INSERT INTO journal_checkpoint (singleton, epoch, repository_version)
                 VALUES (1, ?1, ?2)
                 ON CONFLICT(singleton) DO UPDATE SET
                     epoch = excluded.epoch,
                     repository_version = excluded.repository_version",
                params![
                    epoch.to_be_bytes().as_slice(),
                    repository_version.to_be_bytes().as_slice()
                ],
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        write_metadata(&transaction, &self.topic, cut)
            .map_err(|source| sqlite_error(&self.path, source))?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, source))
    }
}

fn create_schema_v2(
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
                 repository_version BLOB NOT NULL CHECK (length(repository_version) = 8)
             ) STRICT;
             CREATE TABLE retired_origins (
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

fn decode_u64(
    path: &Path,
    bytes: &[u8],
    reason: &'static str,
) -> Result<u64, SqliteTerminalJournalError> {
    Ok(u64::from_be_bytes(decode_array(path, bytes, reason)?))
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
        let (records, cut, _, _, _) = store.load().unwrap().unwrap().into_parts();
        assert_eq!(records.get(&(u64::MAX, 42)), Some(&record));
        assert_eq!(cut, resulting);
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
        let (loaded, loaded_cut, _, _, _) = store.load().unwrap().unwrap().into_parts();
        assert_eq!(loaded, records);
        assert_eq!(loaded_cut, cut);
    }
}
