use std::sync::Arc;

use crate::channel_repository::{ChannelOperation, ChannelRepository};

use super::{StrictCommitReservation, StrictReplicationRuntime};

pub fn channel_operation_to_payload(op: &ChannelOperation) -> Result<Vec<u8>, String> {
    serde_json::to_vec(op).map_err(|e| format!("encode channel operation failed: {e}"))
}

pub fn channel_operation_from_payload(payload: &[u8]) -> Result<ChannelOperation, String> {
    serde_json::from_slice(payload).map_err(|e| format!("decode channel operation failed: {e}"))
}

pub fn reserve_channel_commit(
    runtime: &mut StrictReplicationRuntime,
) -> Result<StrictCommitReservation, String> {
    runtime.reserve_commit()
}

pub async fn commit_local_channel_operation(
    runtime: &mut StrictReplicationRuntime,
    repository: &Arc<ChannelRepository>,
    mut operation: ChannelOperation,
) -> Result<Arc<ChannelOperation>, String> {
    let reservation = reserve_channel_commit(runtime)?;
    operation.version = reservation.index;
    let committed = repository
        .apply_committed_operation(operation)
        .await
        .map_err(|e| format!("persist committed channel operation failed: {e}"))?;
    runtime.commit_reserved(reservation)?;
    Ok(committed)
}

pub async fn apply_replicated_channel_operation(
    repository: &Arc<ChannelRepository>,
    operation: ChannelOperation,
) -> Result<Arc<ChannelOperation>, String> {
    repository
        .apply_committed_operation(operation)
        .await
        .map_err(|e| format!("apply replicated channel operation failed: {e}"))
}

pub async fn apply_replicated_channel_payload(
    repository: &Arc<ChannelRepository>,
    payload: &[u8],
) -> Result<Arc<ChannelOperation>, String> {
    let operation = channel_operation_from_payload(payload)?;
    apply_replicated_channel_operation(repository, operation).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel_repository::{ChannelOp, ChannelRepoTuning};
    use crate::channels::Channel;

    #[test]
    fn payload_roundtrip_preserves_channel_operation() {
        let operation = ChannelOperation {
            version: 17,
            node_id: 2,
            timestamp: 123_456,
            op: ChannelOp::CreateChannel {
                channel: Channel::new(10, "Lobby", 0, 0, Some(0)),
            },
        };

        let payload = channel_operation_to_payload(&operation).expect("encode should succeed");
        let decoded = channel_operation_from_payload(&payload).expect("decode should succeed");

        assert_eq!(decoded.version, 17);
        assert_eq!(decoded.node_id, 2);
        assert!(matches!(decoded.op, ChannelOp::CreateChannel { .. }));
    }

    #[tokio::test]
    async fn local_commit_uses_repository_commit_path() {
        let mut runtime = StrictReplicationRuntime::new(1);
        runtime.update_partition_role(3, 3);

        let operation = ChannelOperation {
            version: 0,
            node_id: 1,
            timestamp: 999,
            op: ChannelOp::CreateChannel {
                channel: Channel::new(22, "ConsensusRoom", 0, 0, Some(0)),
            },
        };

        let tuning = ChannelRepoTuning {
            log_max_entries: 128,
            snapshot_every_ops: 10,
            snapshot_every_secs: 60,
            wal_compaction_expire_count: 2000,
        };
        let repo = ChannelRepository::new_in_memory(2, tuning);

        let committed = commit_local_channel_operation(&mut runtime, &repo, operation)
            .await
            .expect("local committed operation should succeed");

        let created = repo
            .get_channel(22)
            .await
            .expect("replicated channel should exist");
        assert_eq!(committed.version, repo.current_version());
        assert!(committed.version > 0);
        assert_eq!(created.name, "ConsensusRoom");
        assert_eq!(created.parent_id, Some(0));
    }

    #[tokio::test]
    async fn replicated_payload_persists_through_repository_path() {
        let tuning = ChannelRepoTuning {
            log_max_entries: 64,
            snapshot_every_ops: 10,
            snapshot_every_secs: 60,
            wal_compaction_expire_count: 2000,
        };
        let repo = ChannelRepository::new_in_memory(3, tuning);

        let operation = ChannelOperation {
            version: 4,
            node_id: 1,
            timestamp: 321,
            op: ChannelOp::CreateChannel {
                channel: Channel::new(99, "PayloadRoom", 0, 0, Some(0)),
            },
        };
        let payload = channel_operation_to_payload(&operation).expect("payload should encode");

        let committed = apply_replicated_channel_payload(&repo, &payload)
            .await
            .expect("apply payload should succeed");

        assert_eq!(committed.version, 4);
        assert_eq!(repo.current_version(), 4);
        assert!(repo.get_channel(99).await.is_some());
    }
}
