use std::{fs, sync::Arc, thread};

use bytes::Bytes;
use rusqlite::Connection;
use tempfile::TempDir;

use super::terminal_journal::{FrozenTarget, TerminalJournal, TerminalResolver};

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
