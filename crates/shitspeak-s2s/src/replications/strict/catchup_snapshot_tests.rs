use std::collections::BTreeMap;

use bytes::Bytes;

use super::{
    S2S_SNAPSHOT_ENVELOPE_BOUND_VERSION, S2S_SNAPSHOT_ENVELOPE_VERSION, S2sAppliedOperation,
    S2sBoundSnapshotEnvelope, S2sRetiredOperation, S2sSnapshotEnvelope,
    decode_s2s_snapshot_envelope, delivery_checkpoint_is_valid,
};
use crate::replications::strict::terminal_journal::TerminalJournal;

#[test]
fn snapshot_envelope_roundtrip_retains_applied_operations_and_retirement_floors() {
    let repository_snapshot = Bytes::from_static(b"repository-checkpoint");
    let envelope = S2sSnapshotEnvelope {
        version: S2S_SNAPSHOT_ENVELOPE_VERSION,
        repository_snapshot: repository_snapshot.to_vec(),
        applied_operations: vec![
            S2sAppliedOperation {
                op_id_hi: 11,
                op_id_lo: 3,
                repository_version: 40,
            },
            S2sAppliedOperation {
                op_id_hi: 22,
                op_id_lo: 9,
                repository_version: 41,
            },
        ],
        retired_operations: vec![
            S2sRetiredOperation {
                op_id_hi: 11,
                max_counter: 2,
            },
            S2sRetiredOperation {
                op_id_hi: 33,
                max_counter: 17,
            },
        ],
    };

    let encoded = Bytes::from(rmp_serde::to_vec_named(&envelope).unwrap());
    let decoded = decode_s2s_snapshot_envelope(encoded).unwrap();

    assert_eq!(decoded.repository_snapshot, repository_snapshot);
    assert_eq!(decoded.applied_operations.get(&(11, 3)), Some(&40));
    assert_eq!(decoded.applied_operations.get(&(22, 9)), Some(&41));
    assert_eq!(decoded.applied_operations.len(), 2);
    assert_eq!(
        decoded.retired_operations,
        BTreeMap::from([(11_u64, 2_u64), (33_u64, 17_u64)])
    );
    assert!(decoded.terminal_cut.is_none());
}

#[test]
fn bound_snapshot_envelope_roundtrip_retains_its_terminal_cut() {
    let terminal_cut = TerminalJournal::in_memory("channels").terminal_cut();
    let envelope = S2sBoundSnapshotEnvelope {
        version: S2S_SNAPSHOT_ENVELOPE_BOUND_VERSION,
        repository_snapshot: b"repository-checkpoint".to_vec(),
        applied_operations: Vec::new(),
        retired_operations: Vec::new(),
        terminal_cut,
    };

    let decoded =
        decode_s2s_snapshot_envelope(Bytes::from(rmp_serde::to_vec_named(&envelope).unwrap()))
            .unwrap();

    assert_eq!(decoded.terminal_cut, Some(terminal_cut));
}

#[test]
fn snapshot_envelope_rejects_duplicate_applied_operation_ids() {
    let envelope = S2sSnapshotEnvelope {
        version: S2S_SNAPSHOT_ENVELOPE_VERSION,
        repository_snapshot: Vec::new(),
        applied_operations: vec![
            S2sAppliedOperation {
                op_id_hi: 11,
                op_id_lo: 3,
                repository_version: 40,
            },
            S2sAppliedOperation {
                op_id_hi: 11,
                op_id_lo: 3,
                repository_version: 41,
            },
        ],
        retired_operations: Vec::new(),
    };

    assert!(
        decode_s2s_snapshot_envelope(Bytes::from(rmp_serde::to_vec_named(&envelope).unwrap()))
            .is_err()
    );
}

#[test]
fn snapshot_envelope_rejects_duplicate_retired_origins() {
    let envelope = S2sSnapshotEnvelope {
        version: S2S_SNAPSHOT_ENVELOPE_VERSION,
        repository_snapshot: Vec::new(),
        applied_operations: Vec::new(),
        retired_operations: vec![
            S2sRetiredOperation {
                op_id_hi: 11,
                max_counter: 3,
            },
            S2sRetiredOperation {
                op_id_hi: 11,
                max_counter: 4,
            },
        ],
    };

    assert!(
        decode_s2s_snapshot_envelope(Bytes::from(rmp_serde::to_vec_named(&envelope).unwrap()))
            .is_err()
    );
}

#[test]
fn delivery_checkpoint_rejects_applied_id_at_exact_retired_floor() {
    assert!(!delivery_checkpoint_is_valid(
        40,
        &std::collections::HashMap::from([((11, 3), 40)]),
        &BTreeMap::from([(11, 3)]),
    ));
}

#[test]
fn delivery_checkpoint_rejects_applied_counter_covered_by_retired_floor() {
    assert!(!delivery_checkpoint_is_valid(
        40,
        &std::collections::HashMap::from([((11, 2), 40)]),
        &BTreeMap::from([(11, 3)]),
    ));
}

#[test]
fn delivery_checkpoint_rejects_applied_version_beyond_repository_image() {
    assert!(!delivery_checkpoint_is_valid(
        40,
        &std::collections::HashMap::from([((11, 4), 41)]),
        &BTreeMap::from([(11, 3)]),
    ));
}
