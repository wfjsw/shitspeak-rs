use std::{collections::BTreeMap, fs, sync::Arc, thread};

use bytes::Bytes;
use rusqlite::Connection;
use tempfile::TempDir;

use super::{
    terminal_journal::{
        FrozenTarget, TerminalCut, TerminalJournal, TerminalJournalRecord, TerminalResolver,
    },
    terminal_journal_sqlite::{
        DurableRecoveryArtifactIntent, DurableRecoveryAttempt, DurableRecoveryFailure,
        DurableRecoveryParticipant, DurableRecoveryPhase, DurableRecoveryRepositoryMetadata,
        DurableRecoveryTarget, DurableRecoveryWitness, SqliteTerminalJournalError,
        SqliteTerminalJournalStore,
    },
};

#[test]
fn schema_v1_migration_preserves_records_and_cut() {
    let root = TempDir::new().unwrap();
    let path = root.path().join("journal.sqlite3");
    let op_id = (7, 9);
    let record = TerminalJournalRecord::default();
    let cut = TerminalCut::new([3; 16], 0, [4; 32], [5; 32]);

    {
        let mut store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
        store.replace_all([(&op_id, &record)], &cut).unwrap();
    }
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TABLE strict_recovery_artifact;
                 DROP TABLE strict_recovery_state;
                 DROP TABLE journal_checkpoint;
                 DROP TABLE retired_origins;
                 PRAGMA user_version = 1;",
            )
            .unwrap();
    }

    {
        let store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
        let (records, loaded_cut, epoch, repository_version, retired, pending, freshness) =
            store.load().unwrap().unwrap().into_parts();
        assert_eq!(records.get(&op_id), Some(&record));
        assert_eq!(loaded_cut, cut);
        assert_eq!(epoch, 0);
        assert_eq!(repository_version, 0);
        assert!(retired.is_empty());
        assert!(!pending);
        assert_eq!(freshness, 0);
    }

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        5
    );
    for table in ["journal_checkpoint", "retired_origins"] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }
    for column in [
        "repository_image_install_pending",
        "repository_image_install_freshness",
    ] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM pragma_table_info('journal_checkpoint')
                     WHERE name = ?1",
                    [column],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }
}

#[test]
fn schema_v2_migration_preserves_checkpoint_and_defaults_install_complete() {
    let root = TempDir::new().unwrap();
    let path = root.path().join("journal.sqlite3");
    let cut = TerminalCut::new([8; 16], 0, [0; 32], [9; 32]);
    let retired = BTreeMap::from([(17, 23)]);
    {
        let mut store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
        store.replace_all(std::iter::empty(), &cut).unwrap();
        store.checkpoint(4, 44, &retired, &cut).unwrap();
    }
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TABLE strict_recovery_artifact;
                 DROP TABLE strict_recovery_state;
                 ALTER TABLE journal_checkpoint RENAME TO journal_checkpoint_v3;
                 CREATE TABLE journal_checkpoint (
                     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                     epoch BLOB NOT NULL CHECK (length(epoch) = 8),
                     repository_version BLOB NOT NULL CHECK (length(repository_version) = 8)
                 ) STRICT;
                 INSERT INTO journal_checkpoint (singleton, epoch, repository_version)
                     SELECT singleton, epoch, repository_version FROM journal_checkpoint_v3;
                 DROP TABLE journal_checkpoint_v3;
                 PRAGMA user_version = 2;",
            )
            .unwrap();
    }

    {
        let store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
        let (records, loaded_cut, epoch, repository_version, loaded_retired, pending, freshness) =
            store.load().unwrap().unwrap().into_parts();
        assert!(records.is_empty());
        assert_eq!(loaded_cut, cut);
        assert_eq!(epoch, 4);
        assert_eq!(repository_version, 44);
        assert_eq!(loaded_retired, retired);
        assert!(!pending);
        assert_eq!(freshness, 0);
    }

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        5
    );
    for column in [
        "repository_image_install_pending",
        "repository_image_install_freshness",
    ] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM pragma_table_info('journal_checkpoint')
                     WHERE name = ?1",
                    [column],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }
}

#[test]
fn repository_image_install_marker_is_durable_and_coordinate_matched() {
    let root = TempDir::new().unwrap();
    let path = root.path().join("journal.sqlite3");
    let cut = TerminalCut::new([10; 16], 1, [11; 32], [12; 32]);
    let op_id = (13, 14);
    let record = TerminalJournalRecord::default();
    {
        let mut store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
        store
            .install_repository_base([(&op_id, &record)], 5, 9_540, -17, &BTreeMap::new(), &cut)
            .unwrap();
    }

    {
        let mut store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
        let (_, _, epoch, repository_version, _, pending, freshness) =
            store.load().unwrap().unwrap().into_parts();
        assert_eq!(epoch, 5);
        assert_eq!(repository_version, 9_540);
        assert!(pending);
        assert_eq!(freshness, -17);

        assert!(
            store
                .complete_repository_image_install(4, 9_540, -17)
                .is_err()
        );
        assert!(
            store
                .complete_repository_image_install(5, 9_539, -17)
                .is_err()
        );
        assert!(
            store
                .complete_repository_image_install(5, 9_540, -18)
                .is_err()
        );
        let (_, _, _, _, _, pending, freshness) = store.load().unwrap().unwrap().into_parts();
        assert!(pending);
        assert_eq!(freshness, -17);
        store
            .complete_repository_image_install(5, 9_540, -17)
            .unwrap();
    }

    {
        let mut store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
        let (_, _, _, _, _, pending, freshness) = store.load().unwrap().unwrap().into_parts();
        assert!(!pending);
        assert_eq!(freshness, 0);
        store
            .install_repository_base(
                [(&op_id, &record)],
                6,
                9_541,
                i64::MAX,
                &BTreeMap::new(),
                &cut,
            )
            .unwrap();
        let (_, _, _, _, _, pending, freshness) = store.load().unwrap().unwrap().into_parts();
        assert!(pending);
        assert_eq!(freshness, i64::MAX);
        store.checkpoint(7, 9_541, &BTreeMap::new(), &cut).unwrap();
        let (_, _, _, _, _, pending, freshness) = store.load().unwrap().unwrap().into_parts();
        assert!(!pending);
        assert_eq!(freshness, 0);
    }
}

fn recovery_attempt(
    phase: DurableRecoveryPhase,
    attempt_id: [u8; 16],
    cut: TerminalCut,
) -> DurableRecoveryAttempt {
    let first = DurableRecoveryParticipant::new(1, 101);
    let second = DurableRecoveryParticipant::new(4, 404);
    DurableRecoveryAttempt::new_with_electorate(
        attempt_id,
        phase,
        4,
        vec![1, 2, 3, 4],
        Some(DurableRecoveryTarget::new(
            9_540,
            -17,
            *cut.terminal_set_digest(),
        )),
        vec![
            DurableRecoveryWitness::new(first, cut),
            DurableRecoveryWitness::new(second, cut),
        ],
        vec![second, first],
        Some(0),
        Some(second),
        Some(cut),
        vec![DurableRecoveryFailure::new(first, "route-loss", 2)],
    )
    .unwrap()
}

#[test]
fn schema_v5_is_activated_automatically() {
    let root = TempDir::new().unwrap();
    let path = root.path().join("journal.sqlite3");
    {
        SqliteTerminalJournalStore::open(&path, "channels").unwrap();
    }

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        5
    );
    for table in ["strict_recovery_state", "strict_recovery_artifact"] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }
}

#[test]
fn recovery_attempt_and_artifact_round_trip_exactly() {
    let root = TempDir::new().unwrap();
    let path = root.path().join("journal.sqlite3");
    let cut = TerminalCut::new([10; 16], 7, [11; 32], [12; 32]);
    let attempt = recovery_attempt(DurableRecoveryPhase::Prepared, [13; 16], cut);
    let artifact = DurableRecoveryArtifactIntent::new(
        [13; 16],
        root.path().join("recovery-stage.snapshot"),
        [14; 32],
        123_456,
        DurableRecoveryRepositoryMetadata::new(9_540, -17),
        cut,
    );
    {
        let mut store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
        store.persist_recovery_attempt(&attempt).unwrap();
        store.persist_recovery_artifact_intent(&artifact).unwrap();
    }

    let mut store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
    assert_eq!(
        store.load_recovery_attempt().unwrap(),
        Some(attempt.clone())
    );
    assert_eq!(
        store.load_recovery_artifact_intent().unwrap(),
        Some(artifact.clone())
    );
    let first = attempt.witnesses()[0].participant();
    assert_eq!(attempt.frozen_electorate(), &[1, 2, 3, 4]);
    assert_eq!(first.node_id(), 1);
    assert_eq!(first.boot_epoch(), 101);
    assert_eq!(attempt.failure_history()[0].donor(), first);
    assert_eq!(attempt.failure_history()[0].reason(), "route-loss");
    assert_eq!(attempt.failure_history()[0].occurrences(), 2);
    assert_eq!(attempt.current_donor_index(), Some(0));
    assert_eq!(
        attempt.current_donor(),
        Some(DurableRecoveryParticipant::new(4, 404))
    );
    assert_eq!(attempt.representation_cut(), Some(cut));
    assert_eq!(
        artifact.staging_path(),
        root.path().join("recovery-stage.snapshot")
    );
    assert_eq!(artifact.content_digest(), &[14; 32]);
    assert_eq!(artifact.content_length(), 123_456);

    assert!(store.clear_recovery_attempt(&[99; 16]).is_err());
    assert_eq!(store.load_recovery_attempt().unwrap(), Some(attempt));
    assert_eq!(
        store.load_recovery_artifact_intent().unwrap(),
        Some(artifact)
    );
    store.clear_recovery_attempt(&[13; 16]).unwrap();
    assert!(store.load_recovery_attempt().unwrap().is_none());
    assert!(store.load_recovery_artifact_intent().unwrap().is_none());
}

#[test]
fn schema_v4_active_attempt_migrates_fail_closed_without_inventing_electorate() {
    let root = TempDir::new().unwrap();
    let path = root.path().join("journal.sqlite3");
    let cut = TerminalCut::new([15; 16], 3, [16; 32], [17; 32]);
    let attempt = recovery_attempt(DurableRecoveryPhase::Prepared, [18; 16], cut);
    {
        let mut store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
        store.persist_recovery_attempt(&attempt).unwrap();
    }
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "ALTER TABLE strict_recovery_state DROP COLUMN frozen_electorate;
                 PRAGMA user_version = 4;",
            )
            .unwrap();
    }

    let store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
    let error = store
        .load_recovery_attempt()
        .expect_err("a v4 attempt has no trustworthy frozen electorate");
    assert!(error.to_string().contains("frozen denominator"));
}

#[test]
fn recovery_checkpoint_and_staged_intent_commit_together() {
    let root = TempDir::new().unwrap();
    let path = root.path().join("journal.sqlite3");
    let cut = TerminalCut::new([21; 16], 8, [22; 32], [23; 32]);
    let attempt = recovery_attempt(DurableRecoveryPhase::Installing, [24; 16], cut);
    let artifact = DurableRecoveryArtifactIntent::new(
        [24; 16],
        root.path().join("prepared.snapshot"),
        [25; 32],
        4_096,
        DurableRecoveryRepositoryMetadata::new(9_540, -17),
        cut,
    );
    let op_id = (26, 27);
    let record = TerminalJournalRecord::default();
    {
        let mut store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
        store
            .prepare_recovery_install(
                [(&op_id, &record)],
                9,
                &BTreeMap::from([((1_u64 << 48) | 28, 29)]),
                &cut,
                &attempt,
                &artifact,
            )
            .unwrap();
    }

    let store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
    let (records, loaded_cut, epoch, version, retired, pending, freshness) =
        store.load().unwrap().unwrap().into_parts();
    assert_eq!(records.get(&op_id), Some(&record));
    assert_eq!(loaded_cut, cut);
    assert_eq!(epoch, 9);
    assert_eq!(version, 9_540);
    assert_eq!(retired, BTreeMap::from([((1_u64 << 48) | 28, 29)]));
    assert!(pending);
    assert_eq!(freshness, -17);
    assert_eq!(store.load_recovery_attempt().unwrap(), Some(attempt));
    assert_eq!(
        store.load_recovery_artifact_intent().unwrap(),
        Some(artifact)
    );
}

#[test]
fn recovery_certificate_requires_sorted_distinct_witnesses_and_certified_donors() {
    let cut = TerminalCut::new([31; 16], 0, [32; 32], [33; 32]);
    let target = DurableRecoveryTarget::new(1, 2, [33; 32]);
    let first = DurableRecoveryParticipant::new(1, 1);
    let second = DurableRecoveryParticipant::new(2, 2);
    assert!(
        DurableRecoveryAttempt::new(
            [34; 16],
            DurableRecoveryPhase::Certifying,
            2,
            Some(target),
            vec![
                DurableRecoveryWitness::new(second, cut),
                DurableRecoveryWitness::new(first, cut),
            ],
            vec![first],
            Some(0),
            Some(first),
            Some(cut),
            vec![],
        )
        .is_err()
    );
    assert!(
        DurableRecoveryAttempt::new(
            [34; 16],
            DurableRecoveryPhase::Certifying,
            2,
            Some(target),
            vec![DurableRecoveryWitness::new(first, cut)],
            vec![second],
            Some(0),
            Some(second),
            Some(cut),
            vec![],
        )
        .is_err()
    );
    let restarted_first = DurableRecoveryParticipant::new(1, 2);
    assert!(
        DurableRecoveryAttempt::new_with_electorate(
            [34; 16],
            DurableRecoveryPhase::FetchingTerminalCheckpoint,
            2,
            vec![1, 2],
            Some(target),
            vec![
                DurableRecoveryWitness::new(first, cut),
                DurableRecoveryWitness::new(restarted_first, cut),
            ],
            vec![first],
            Some(0),
            Some(first),
            Some(cut),
            vec![],
        )
        .is_err()
    );
}

#[test]
fn certifying_attempt_without_a_certificate_round_trips() {
    let root = TempDir::new().unwrap();
    let path = root.path().join("journal.sqlite3");
    let attempt = DurableRecoveryAttempt::new_certifying([35; 16], 4, vec![]).unwrap();
    {
        let mut store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
        store.persist_recovery_attempt(&attempt).unwrap();
    }

    let store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
    let loaded = store.load_recovery_attempt().unwrap().unwrap();
    assert_eq!(loaded, attempt);
    assert_eq!(loaded.phase(), DurableRecoveryPhase::Certifying);
    assert!(loaded.target().is_none());
    assert!(loaded.witnesses().is_empty());
    assert!(loaded.donor_order().is_empty());
    assert_eq!(loaded.current_donor_index(), None);
    assert_eq!(loaded.current_donor(), None);
    assert_eq!(loaded.representation_cut(), None);
}

#[test]
fn recovery_attempt_rejects_inconsistent_donor_progress() {
    let cut = TerminalCut::new([36; 16], 1, [37; 32], [38; 32]);
    let target = DurableRecoveryTarget::new(10, 11, [38; 32]);
    let first = DurableRecoveryParticipant::new(1, 100);
    let second = DurableRecoveryParticipant::new(2, 200);
    let witnesses = vec![
        DurableRecoveryWitness::new(first, cut),
        DurableRecoveryWitness::new(second, cut),
    ];
    assert!(
        DurableRecoveryAttempt::new(
            [39; 16],
            DurableRecoveryPhase::FetchingTerminalCheckpoint,
            2,
            Some(target),
            witnesses.clone(),
            vec![second, first],
            Some(0),
            Some(first),
            Some(cut),
            vec![],
        )
        .is_err()
    );
    assert!(
        DurableRecoveryAttempt::new(
            [39; 16],
            DurableRecoveryPhase::FetchingTerminalCheckpoint,
            2,
            Some(target),
            witnesses,
            vec![second, first],
            Some(2),
            Some(first),
            Some(cut),
            vec![],
        )
        .is_err()
    );
}

#[test]
fn finalize_recovery_install_is_exactly_guarded_and_atomic() {
    let root = TempDir::new().unwrap();
    let path = root.path().join("journal.sqlite3");
    let cut = TerminalCut::new([40; 16], 12, [41; 32], [42; 32]);
    let installing = recovery_attempt(DurableRecoveryPhase::Installing, [43; 16], cut);
    let verifying = recovery_attempt(DurableRecoveryPhase::Verifying, [43; 16], cut);
    let metadata = DurableRecoveryRepositoryMetadata::new(9_540, -17);
    let artifact = DurableRecoveryArtifactIntent::new(
        [43; 16],
        root.path().join("finalize.snapshot"),
        [44; 32],
        8_192,
        metadata,
        cut,
    );
    let mut store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
    store
        .prepare_recovery_install(
            std::iter::empty(),
            13,
            &BTreeMap::new(),
            &cut,
            &installing,
            &artifact,
        )
        .unwrap();
    store.persist_recovery_attempt(&verifying).unwrap();

    assert!(
        store
            .finalize_recovery_install(&[45; 16], 13, metadata, &cut)
            .is_err()
    );
    assert!(
        store
            .finalize_recovery_install(
                &[43; 16],
                13,
                DurableRecoveryRepositoryMetadata::new(9_541, -17),
                &cut,
            )
            .is_err()
    );
    let wrong_cut = TerminalCut::new([46; 16], 12, [41; 32], [42; 32]);
    assert!(
        store
            .finalize_recovery_install(&[43; 16], 13, metadata, &wrong_cut)
            .is_err()
    );
    let (_, loaded_cut, _, _, _, pending, freshness) = store.load().unwrap().unwrap().into_parts();
    assert_eq!(loaded_cut, cut);
    assert!(pending);
    assert_eq!(freshness, -17);
    assert_eq!(store.load_recovery_attempt().unwrap(), Some(verifying));
    assert_eq!(
        store.load_recovery_artifact_intent().unwrap(),
        Some(artifact)
    );

    store
        .finalize_recovery_install(&[43; 16], 13, metadata, &cut)
        .unwrap();
    let (_, loaded_cut, _, _, _, pending, freshness) = store.load().unwrap().unwrap().into_parts();
    assert_eq!(loaded_cut, cut);
    assert!(!pending);
    assert_eq!(freshness, 0);
    assert!(store.load_recovery_attempt().unwrap().is_none());
    assert!(store.load_recovery_artifact_intent().unwrap().is_none());
}

#[test]
fn sqlite_rejects_rows_without_journal_metadata() {
    let root = TempDir::new().unwrap();
    let path = root.path().join("journal.sqlite3");
    {
        let _store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
    }

    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "INSERT INTO journal_records (op_id_hi, op_id_lo, record) VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    1_u64.to_be_bytes().as_slice(),
                    2_u64.to_be_bytes().as_slice(),
                    rmp_serde::to_vec_named(&TerminalJournalRecord::default()).unwrap(),
                ],
            )
            .unwrap();
    }

    let store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
    assert!(matches!(
        store.load(),
        Err(SqliteTerminalJournalError::InvalidData { .. })
    ));
}

#[test]
fn sqlite_rejects_retired_origins_without_checkpoint_metadata() {
    let root = TempDir::new().unwrap();
    let path = root.path().join("journal.sqlite3");
    let cut = TerminalCut::new([6; 16], 0, [0; 32], [7; 32]);
    {
        let mut store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
        store.replace_all(std::iter::empty(), &cut).unwrap();
    }

    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "INSERT INTO retired_origins (op_id_hi, max_counter) VALUES (?1, ?2)",
                rusqlite::params![
                    11_u64.to_be_bytes().as_slice(),
                    12_u64.to_be_bytes().as_slice(),
                ],
            )
            .unwrap();
    }

    let store = SqliteTerminalJournalStore::open(&path, "channels").unwrap();
    assert!(matches!(
        store.load(),
        Err(SqliteTerminalJournalError::InvalidData { .. })
    ));
}

#[test]
fn sqlite_reload_preserves_records_terminal_cuts_and_generation_order() {
    let root = TempDir::new().unwrap();
    let targets = vec![FrozenTarget::new(1, 10), FrozenTarget::new(4, 40)];
    let first_terminal = (u64::MAX, u64::MAX - 1);
    let second_terminal = (1, 2);
    let pending = (3, 4);

    let (expected_snapshot, expected_cut, empty_cut, persistence_path) = {
        let mut journal =
            TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
        let empty_cut = journal.terminal_cut();

        journal
            .upsert_v2_commit_decision_bytes(
                first_terminal,
                &targets,
                TerminalResolver::new(1, 10),
                u64::MAX,
                u64::MAX - 2,
                Bytes::from_static(b"chosen-value"),
            )
            .unwrap();
        journal
            .upsert_v2_abort_decision(second_terminal, &targets, TerminalResolver::new(4, 40), 17)
            .unwrap();
        journal
            .upsert_v2_pending_bytes(pending, &targets, 91, Bytes::from_static(b"pending-value"))
            .unwrap();
        journal
            .upsert_v2_accepted_bytes(
                pending,
                &targets,
                19,
                101,
                Bytes::from_static(b"pending-value"),
            )
            .unwrap();

        (
            journal.snapshot(),
            journal.terminal_cut(),
            empty_cut,
            journal.persistence_path().unwrap().to_path_buf(),
        )
    };

    assert_eq!(persistence_path.extension().unwrap(), "sqlite3");
    let reloaded = TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
    assert_eq!(reloaded.snapshot(), expected_snapshot);
    assert_eq!(reloaded.terminal_cut(), expected_cut);

    let deltas = reloaded
        .terminal_deltas_after(&empty_cut, usize::MAX)
        .unwrap();
    assert_eq!(deltas.entries().len(), 2);
    assert_eq!(deltas.entries()[0].generation(), 1);
    assert_eq!(deltas.entries()[0].clone().into_parts().2, first_terminal);
    assert_eq!(deltas.entries()[1].generation(), 2);
    assert_eq!(deltas.entries()[1].clone().into_parts().2, second_terminal);
}

#[test]
fn legacy_json_is_retained_but_sqlite_is_authoritative_after_migration() {
    let root = TempDir::new().unwrap();
    let topic = "channels";
    let directory = root.path().join("strict-terminal-journal");
    fs::create_dir_all(&directory).unwrap();
    let legacy_path = directory.join(format!("topic-{}.json", hex::encode(topic.as_bytes())));
    fs::write(
        &legacy_path,
        r#"{"version":1,"topic":"channels","terminal_decision_generation":1,"records":[{"op_id_hi":1,"op_id_lo":2,"promise_ballot":3,"terminal_decision":{"outcome":"abort","ballot":3}}]}"#,
    )
    .unwrap();

    let (expected_snapshot, expected_cut, sqlite_path) = {
        let journal = TerminalJournal::load(Some(root.path().to_path_buf()), topic).unwrap();
        (
            journal.snapshot(),
            journal.terminal_cut(),
            journal.persistence_path().unwrap().to_path_buf(),
        )
    };
    assert!(legacy_path.is_file());
    assert!(sqlite_path.is_file());
    assert_eq!(sqlite_path.extension().unwrap(), "sqlite3");

    // Once migration commits, a stale or corrupt legacy image must not be
    // re-imported over the authoritative database.
    fs::write(&legacy_path, b"not valid JSON").unwrap();
    let reloaded = TerminalJournal::load(Some(root.path().to_path_buf()), topic).unwrap();
    assert_eq!(reloaded.snapshot(), expected_snapshot);
    assert_eq!(reloaded.terminal_cut(), expected_cut);
}

#[test]
fn sqlite_writers_for_distinct_topics_do_not_share_a_database_lock() {
    const WRITES: u64 = 32;
    let root = TempDir::new().unwrap();
    let root = Arc::new(root.path().to_path_buf());

    let handles: Vec<_> = ["channels", "users"]
        .into_iter()
        .map(|topic| {
            let root = Arc::clone(&root);
            thread::spawn(move || {
                let mut journal = TerminalJournal::load(Some((*root).clone()), topic).unwrap();
                for index in 0..WRITES {
                    journal
                        .upsert_abort_decision((index, index + 1), index + 1)
                        .unwrap();
                }
                journal.persistence_path().unwrap().to_path_buf()
            })
        })
        .collect();

    let paths: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_ne!(paths[0], paths[1]);

    for topic in ["channels", "users"] {
        let journal = TerminalJournal::load(Some((*root).clone()), topic).unwrap();
        assert_eq!(journal.snapshot().len(), WRITES as usize);
        assert_eq!(journal.terminal_cut().generation(), WRITES);
    }
}

#[test]
fn failed_sqlite_transaction_does_not_publish_the_candidate_in_memory() {
    let root = TempDir::new().unwrap();
    let mut journal = TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
    let original_cut = journal.terminal_cut();
    let path = journal.persistence_path().unwrap().to_path_buf();

    let injector = Connection::open(path).unwrap();
    injector
        .execute_batch(
            "CREATE TRIGGER reject_terminal_journal_insert
             BEFORE INSERT ON journal_records
             BEGIN
                 SELECT RAISE(ABORT, 'injected transaction failure');
             END;",
        )
        .unwrap();

    assert!(journal.upsert_abort_decision((7, 8), 9).is_err());
    assert!(journal.get((7, 8)).is_none());
    assert_eq!(journal.terminal_cut(), original_cut);
    drop(injector);
    drop(journal);

    let reloaded = TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
    assert!(reloaded.get((7, 8)).is_none());
    assert_eq!(reloaded.terminal_cut(), original_cut);
}
