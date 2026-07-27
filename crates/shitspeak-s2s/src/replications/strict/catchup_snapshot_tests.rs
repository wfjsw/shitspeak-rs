use std::collections::BTreeMap;

use bytes::Bytes;

use super::{
    S2S_SNAPSHOT_ENVELOPE_VERSION, S2sAppliedOperation, S2sRetiredOperation, S2sSnapshotEnvelope,
    decode_s2s_snapshot_envelope,
};

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
    let (decoded_snapshot, decoded_applied, decoded_retired) =
        decode_s2s_snapshot_envelope(encoded).unwrap();

    assert_eq!(decoded_snapshot, repository_snapshot);
    assert_eq!(decoded_applied.get(&(11, 3)), Some(&40));
    assert_eq!(decoded_applied.get(&(22, 9)), Some(&41));
    assert_eq!(decoded_applied.len(), 2);
    assert_eq!(
        decoded_retired,
        BTreeMap::from([(11_u64, 2_u64), (33_u64, 17_u64)])
    );
}
