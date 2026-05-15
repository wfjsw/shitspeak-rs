//! `ReplCluster` — one `ReplicationManager` per node atop the shared
//! [`Cluster`](crate::s2s::testing::Cluster) test harness.

use std::sync::Arc;
use std::time::Duration;

use crate::s2s::testing::{
    full_mesh_seeds, wait_for_full_alive_mesh, wait_for_full_routing, Cluster,
};

use super::super::{
    OwnerHandle, OwnerReplicable, ReplicationConfig, ReplicationError, ReplicationManager,
    StrictHandle, StrictReplicable,
};

pub struct ReplCluster {
    pub cluster: Cluster,
    pub managers: Vec<Arc<ReplicationManager>>,
}

impl ReplCluster {
    /// Build a full-mesh `n`-node cluster with a `ReplicationManager` per
    /// node, and wait for full alive mesh + full routing.
    pub async fn build_full_mesh(node_ids: &[u16]) -> Self {
        let cluster = Cluster::build(node_ids, full_mesh_seeds).await;
        assert!(
            wait_for_full_alive_mesh(&cluster, Duration::from_secs(5)).await,
            "alive mesh did not form"
        );
        assert!(
            wait_for_full_routing(&cluster, Duration::from_secs(5)).await,
            "routing did not converge"
        );
        let managers: Vec<Arc<ReplicationManager>> = cluster
            .nodes
            .iter()
            .map(|n| ReplicationManager::new(n.overlay.clone()))
            .collect();
        Self { cluster, managers }
    }

    pub async fn build_full_mesh_with_config(node_ids: &[u16], cfg: ReplicationConfig) -> Self {
        let cluster = Cluster::build(node_ids, full_mesh_seeds).await;
        assert!(
            wait_for_full_alive_mesh(&cluster, Duration::from_secs(5)).await,
            "alive mesh did not form"
        );
        assert!(
            wait_for_full_routing(&cluster, Duration::from_secs(5)).await,
            "routing did not converge"
        );
        let managers: Vec<Arc<ReplicationManager>> = cluster
            .nodes
            .iter()
            .map(|n| ReplicationManager::with_config(n.overlay.clone(), cfg.clone()))
            .collect();
        Self { cluster, managers }
    }

    pub fn manager(&self, idx: usize) -> &Arc<ReplicationManager> {
        &self.managers[idx]
    }

    pub fn register_strict<R: StrictReplicable>(
        &self,
        idx: usize,
        topic: &str,
        repo: Arc<R>,
    ) -> Result<StrictHandle<R>, ReplicationError> {
        self.managers[idx].register_strict(topic, repo)
    }

    pub fn register_owner<R: OwnerReplicable>(
        &self,
        idx: usize,
        topic: &str,
        repo: Arc<R>,
    ) -> Result<OwnerHandle<R>, ReplicationError> {
        self.managers[idx].register_owner(topic, repo)
    }

    pub async fn shutdown(&self) {
        for m in &self.managers {
            m.shutdown().await;
        }
        self.cluster.shutdown_all().await;
    }
}
