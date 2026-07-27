use std::collections::BTreeMap;

use tempfile::TempDir;

use super::terminal_journal::{DeliveryDisposition, TerminalJournal};

type OpId = (u64, u64);

fn commit(journal: &mut TerminalJournal, op_id: OpId, version: u64) {
    journal
        .upsert_commit_decision(op_id, version, version, vec![version as u8])
        .unwrap();
}

fn commit_and_finish(journal: &mut TerminalJournal, op_id: OpId, version: u64) {
    commit(journal, op_id, version);
    assert_eq!(
        journal.begin_delivery(op_id, version).unwrap(),
        DeliveryDisposition::Apply
    );
    journal.finish_delivery(op_id, version).unwrap();
}

#[test]
fn delivery_intent_recovery_uses_the_durable_repository_version() {
    let root = TempDir::new().unwrap();
    let applied = (0x0001_0000_0000_0011, 1);
    let not_applied = (0x0001_0000_0000_0011, 2);

    {
        let mut journal =
            TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
        commit(&mut journal, applied, 8);
        commit(&mut journal, not_applied, 9);
        assert_eq!(
            journal.begin_delivery(applied, 8).unwrap(),
            DeliveryDisposition::Apply
        );
        assert_eq!(
            journal.begin_delivery(not_applied, 9).unwrap(),
            DeliveryDisposition::Apply
        );
        // Crash here: the repository committed version 8, but the journal did
        // not observe either delivery completion.
    }

    let mut recovered = TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
    recovered.recover_delivery_intents(8).unwrap();

    assert_eq!(
        recovered.begin_delivery(applied, 8).unwrap(),
        DeliveryDisposition::AlreadyApplied
    );
    assert_eq!(
        recovered.begin_delivery(not_applied, 9).unwrap(),
        DeliveryDisposition::Apply
    );
}

#[test]
fn legacy_delivery_migration_preserves_s2s_delivery_markers() {
    let root = TempDir::new().unwrap();
    let legacy = (0x0001_0000_0000_0011, 1);
    let legacy_with_intent = (0x0001_0000_0000_0011, 2);
    let s2s_owned = (0x0002_0000_0000_0022, 2);

    {
        let mut journal =
            TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
        commit(&mut journal, legacy, 7);
        commit(&mut journal, legacy_with_intent, 8);
        assert_eq!(
            journal.begin_delivery(legacy_with_intent, 8).unwrap(),
            DeliveryDisposition::Apply
        );
        commit_and_finish(&mut journal, s2s_owned, 9);

        journal
            .merge_legacy_delivery_checkpoint(
                10,
                &BTreeMap::from([(legacy, 10), (legacy_with_intent, 10)]),
            )
            .unwrap();

        assert_eq!(journal.delivery_version(legacy), Some(10));
        assert_eq!(journal.delivery_version(legacy_with_intent), Some(8));
        assert_eq!(journal.delivery_version(s2s_owned), Some(9));
        assert!(journal.get(legacy).unwrap().is_delivered());
        assert!(journal.get(legacy_with_intent).unwrap().is_delivered());
        assert!(journal.get(s2s_owned).unwrap().is_delivered());
    }

    let reloaded = TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
    assert_eq!(reloaded.delivery_version(legacy), Some(10));
    assert_eq!(reloaded.delivery_version(legacy_with_intent), Some(8));
    assert_eq!(reloaded.delivery_version(s2s_owned), Some(9));
    assert!(reloaded.get(legacy).unwrap().is_delivered());
    assert!(reloaded.get(legacy_with_intent).unwrap().is_delivered());
    assert!(reloaded.get(s2s_owned).unwrap().is_delivered());
}

#[test]
fn checkpoint_refuses_to_trim_unresolved_records() {
    let mut journal = TerminalJournal::in_memory("channels");
    let applied = (0x0001_0000_0000_0022, 1);
    let promised = (0x0002_0000_0000_0033, 7);
    commit_and_finish(&mut journal, applied, 1);
    journal.upsert_promise(promised, 12).unwrap();

    let records_before = journal.snapshot();
    let cut_before = journal.terminal_cut();
    assert!(journal.checkpoint(1).is_err());

    assert_eq!(journal.snapshot(), records_before);
    assert_eq!(journal.terminal_cut(), cut_before);
    assert_eq!(journal.get(promised).unwrap().promise_ballot(), 12);
}

#[test]
fn trim_reload_preserves_checkpoint_epoch_and_a_bounded_suffix() {
    let root = TempDir::new().unwrap();
    let origin = 0x0003_0000_0000_0044;

    let (checkpoint_epoch, checkpoint_repository_version) = {
        let mut journal =
            TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
        for counter in 1..=32 {
            commit_and_finish(&mut journal, (origin, counter), counter);
        }

        let checkpoint = journal.checkpoint(32).unwrap();
        assert_eq!(journal.record_count(), 0);
        assert_eq!(checkpoint.repository_version(), 32);

        // Work after the checkpoint is the bounded suffix retained for normal
        // replay and terminal catch-up.
        for counter in 33..=36 {
            commit_and_finish(&mut journal, (origin, counter), counter);
        }
        assert_eq!(journal.record_count(), 4);
        (checkpoint.epoch(), checkpoint.repository_version())
    };

    let reloaded = TerminalJournal::load(Some(root.path().to_path_buf()), "channels").unwrap();
    assert_eq!(reloaded.checkpoint_epoch(), checkpoint_epoch);
    assert_eq!(
        reloaded.checkpoint_repository_version(),
        checkpoint_repository_version
    );
    assert_eq!(reloaded.record_count(), 4);
    assert!(reloaded.is_retired((origin, 32)));
    assert!(!reloaded.is_retired((origin, 33)));
}

#[test]
fn checkpoint_refuses_to_retire_unseen_operation_counter_gaps() {
    let mut journal = TerminalJournal::in_memory("channels");
    let old_epoch = 0x0004_0000_0000_0055;
    commit_and_finish(&mut journal, (old_epoch, 10), 1);
    assert!(journal.checkpoint(1).is_err());

    assert!(!journal.is_retired((old_epoch, 1)));
    assert!(!journal.is_retired((old_epoch, 9)));
    assert!(!journal.is_retired((old_epoch, 10)));
    assert!(journal.get((old_epoch, 10)).is_some());
}

#[test]
fn retired_floor_digest_is_not_the_fresh_empty_set_digest() {
    let fresh = TerminalJournal::in_memory("channels");
    let fresh_digest = *fresh.terminal_cut().terminal_set_digest();

    let mut checkpointed = TerminalJournal::in_memory("channels");
    let origin = 0x0005_0000_0000_0066;
    for counter in 1..=4 {
        commit_and_finish(&mut checkpointed, (origin, counter), counter);
    }
    checkpointed.checkpoint(4).unwrap();

    assert_eq!(checkpointed.record_count(), 0);
    assert_ne!(
        checkpointed.terminal_cut().terminal_set_digest(),
        &fresh_digest
    );
}

#[test]
fn repeated_checkpoints_keep_only_one_floor_per_origin_and_no_retired_rows() {
    let mut journal = TerminalJournal::in_memory("channels");
    let origin = 0x0006_0000_0000_0077;

    for counter in 1..=64 {
        commit_and_finish(&mut journal, (origin, counter), counter);
        journal.checkpoint(counter).unwrap();

        assert_eq!(journal.record_count(), 0);
        assert_eq!(
            journal.retired_origins(),
            BTreeMap::from([(origin, counter)])
        );
    }
}

#[test]
fn retired_boot_incarnations_compact_to_one_floor_per_node() {
    let mut journal = TerminalJournal::in_memory("channels");
    let old_origin = 0x0007_0000_0000_0001;
    let new_origin = 0x0007_0000_0000_0002;

    commit_and_finish(&mut journal, (old_origin, 1), 1);
    journal.checkpoint(1).unwrap();
    commit_and_finish(&mut journal, (new_origin, 1), 2);
    journal.checkpoint(2).unwrap();

    assert_eq!(journal.retired_origins(), BTreeMap::from([(new_origin, 1)]));
    assert!(journal.is_retired((old_origin, u64::MAX)));
    assert!(journal.is_retired((new_origin, 1)));
    assert!(!journal.is_retired((new_origin, 2)));
}
