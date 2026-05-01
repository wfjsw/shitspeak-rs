use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::broadcast;

use crate::s2s::core::NodeId;

pub trait ReplicableRepository: Send + Sync {
    type Op: Serialize + DeserializeOwned + Send + Sync + Clone + 'static;
    type Error: std::error::Error + Send + Sync + 'static;

    fn current_version(&self) -> u64;
    fn subscribe_local(&self) -> broadcast::Receiver<Arc<Self::Op>>;
}

#[async_trait::async_trait]
pub trait StrictReplicableRepository: ReplicableRepository {
    async fn apply_replicated(&self, op: Self::Op) -> Result<(), Self::Error>;
    async fn export_snapshot(&self) -> Result<Vec<u8>, Self::Error>;
    async fn install_snapshot(&self, bytes: &[u8]) -> Result<(), Self::Error>;
    async fn get_log_since(&self, version: u64) -> Result<Vec<Self::Op>, Self::Error>;
}

#[async_trait::async_trait]
pub trait OwnerReplicableRepository: ReplicableRepository {
    fn owner_node(&self) -> NodeId;
    async fn apply_replicated(&self, op: Self::Op) -> Result<(), Self::Error>;
    async fn reset_for_epoch(&self, owner: NodeId, new_epoch: String);
    async fn get_origin_log_since(
        &self,
        origin: NodeId,
        since: u64,
    ) -> Result<Vec<Self::Op>, Self::Error>;
}
