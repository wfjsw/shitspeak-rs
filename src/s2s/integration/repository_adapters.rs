use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::broadcast;

use crate::ban_repository::{BanEntry, BanOperation, BanRepository};
use crate::channel_repository::{ChannelOperation, ChannelRepository};
use crate::channels::Channel;
use crate::client::state_log::{ClientStateBroadcastPayload, ClientStateLogEntry};
use crate::client_repository::ClientRepository;
use crate::s2s::core::replication::{OwnerReplicableRepository, ReplicableRepository, StrictReplicableRepository};
use crate::s2s::core::NodeId;

#[derive(Debug, Clone)]
pub struct AdapterError {
    message: String,
}

impl AdapterError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for AdapterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AdapterError {}

#[derive(Clone)]
pub struct ChannelStrictAdapter {
    repo: Arc<ChannelRepository>,
}

impl ChannelStrictAdapter {
    pub fn new(repo: Arc<ChannelRepository>) -> Self {
        Self { repo }
    }
}

impl ReplicableRepository for ChannelStrictAdapter {
    type Op = ChannelOperation;
    type Error = AdapterError;

    fn current_version(&self) -> u64 {
        self.repo.current_version()
    }

    fn subscribe_local(&self) -> broadcast::Receiver<Arc<Self::Op>> {
        self.repo.subscribe()
    }
}

#[async_trait]
impl StrictReplicableRepository for ChannelStrictAdapter {
    async fn apply_replicated(&self, op: Self::Op) -> Result<(), Self::Error> {
        self.repo
            .apply_remote_operation(Arc::new(op))
            .await
            .map_err(|e| AdapterError::new(format!("channel apply failed: {e}")))
    }

    async fn export_snapshot(&self) -> Result<Vec<u8>, Self::Error> {
        let channels = self.repo.get_all().await;
        serde_json::to_vec(&channels)
            .map_err(|e| AdapterError::new(format!("channel snapshot encode failed: {e}")))
    }

    async fn install_snapshot(&self, _bytes: &[u8]) -> Result<(), Self::Error> {
        Err(AdapterError::new(
            "channel snapshot install not yet supported by adapter",
        ))
    }

    async fn get_log_since(&self, version: u64) -> Result<Vec<Self::Op>, Self::Error> {
        Ok(self
            .repo
            .get_log_since(version)
            .await
            .into_iter()
            .map(|op| (*op).clone())
            .collect())
    }
}

#[derive(Clone)]
pub struct BanStrictAdapter {
    repo: Arc<BanRepository>,
}

impl BanStrictAdapter {
    pub fn new(repo: Arc<BanRepository>) -> Self {
        Self { repo }
    }
}

impl ReplicableRepository for BanStrictAdapter {
    type Op = BanOperation;
    type Error = AdapterError;

    fn current_version(&self) -> u64 {
        self.repo.current_version()
    }

    fn subscribe_local(&self) -> broadcast::Receiver<Arc<Self::Op>> {
        self.repo.subscribe()
    }
}

#[async_trait]
impl StrictReplicableRepository for BanStrictAdapter {
    async fn apply_replicated(&self, op: Self::Op) -> Result<(), Self::Error> {
        self.repo.apply_remote_operation(Arc::new(op)).await;
        Ok(())
    }

    async fn export_snapshot(&self) -> Result<Vec<u8>, Self::Error> {
        let bans = self.repo.get_active_bans().await;
        serde_json::to_vec(&bans)
            .map_err(|e| AdapterError::new(format!("ban snapshot encode failed: {e}")))
    }

    async fn install_snapshot(&self, bytes: &[u8]) -> Result<(), Self::Error> {
        let entries: Vec<BanEntry> = serde_json::from_slice(bytes)
            .map_err(|e| AdapterError::new(format!("ban snapshot decode failed: {e}")))?;
        self.repo
            .set_bans(entries)
            .await
            .map_err(|e| AdapterError::new(format!("ban snapshot install failed: {e}")))
    }

    async fn get_log_since(&self, version: u64) -> Result<Vec<Self::Op>, Self::Error> {
        Ok(self
            .repo
            .get_log_since(version)
            .await
            .into_iter()
            .map(|op| (*op).clone())
            .collect())
    }
}

#[derive(Clone)]
pub struct ClientOwnerAdapter {
    repo: Arc<ClientRepository>,
}

impl ClientOwnerAdapter {
    pub fn new(repo: Arc<ClientRepository>) -> Self {
        Self { repo }
    }
}

impl ReplicableRepository for ClientOwnerAdapter {
    type Op = ClientStateLogEntry;
    type Error = AdapterError;

    fn current_version(&self) -> u64 {
        self.repo.current_version()
    }

    fn subscribe_local(&self) -> broadcast::Receiver<Arc<Self::Op>> {
        let mut src = self.repo.subscribe();
        let (tx, rx) = broadcast::channel(512);
        tokio::spawn(async move {
            loop {
                match src.recv().await {
                    Ok(payload) => {
                        let payload: Arc<ClientStateBroadcastPayload> = payload;
                        let _ = tx.send(Arc::new((*payload.entry).clone()));
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        rx
    }
}

#[async_trait]
impl OwnerReplicableRepository for ClientOwnerAdapter {
    fn owner_node(&self) -> NodeId {
        self.repo.local_node_id()
    }

    async fn apply_replicated(&self, op: Self::Op) -> Result<(), Self::Error> {
        self.repo
            .apply_remote_operation(Arc::new(op), u64::MAX)
            .await
            .map_err(|_| AdapterError::new("client apply failed"))
    }

    async fn reset_for_epoch(&self, _owner: NodeId, _new_epoch: String) {
        // Owner epoch reset teardown is pending integration.
    }

    async fn get_origin_log_since(
        &self,
        origin: NodeId,
        since: u64,
    ) -> Result<Vec<Self::Op>, Self::Error> {
        let entries = self.repo.get_log_since(since).await;
        Ok(entries
            .into_iter()
            .map(|op| (*op).clone())
            .filter(|op| op.node_id == origin)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel_repository::ChannelRepoTuning;

    #[tokio::test]
    async fn channel_adapter_export_snapshot_works() {
        let repo = ChannelRepository::new_in_memory(
            1,
            ChannelRepoTuning {
                log_max_entries: 64,
                snapshot_every_ops: 16,
                snapshot_every_secs: 60,
                wal_compaction_expire_count: 128,
            },
        );
        let adapter = ChannelStrictAdapter::new(repo);
        let bytes = adapter.export_snapshot().await.expect("snapshot should encode");
        let decoded: Vec<Channel> = serde_json::from_slice(&bytes).expect("snapshot should decode");
        assert!(!decoded.is_empty());
    }

    #[tokio::test]
    async fn ban_adapter_export_snapshot_works() {
        let repo = BanRepository::new_in_memory(1);
        let adapter = BanStrictAdapter::new(repo);
        let bytes = adapter.export_snapshot().await.expect("snapshot should encode");
        let _decoded: Vec<BanEntry> = serde_json::from_slice(&bytes).expect("snapshot should decode");
    }

    #[tokio::test]
    async fn client_adapter_owner_node_matches_repo() {
        let repo = Arc::new(ClientRepository::new(9, 64));
        let adapter = ClientOwnerAdapter::new(repo);
        assert_eq!(adapter.owner_node(), 9);
    }
}
