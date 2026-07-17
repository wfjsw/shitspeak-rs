//! `ReplCluster` — one `ReplicationManager` per node atop the shared
//! [`Cluster`](shitspeak_s2s::testing::Cluster) test harness.

use std::sync::Arc;
use std::time::Duration;

use shitspeak_s2s::overlay::OverlayConfig;
use shitspeak_s2s::replications::{
    OwnerHandle, OwnerReplicable, ReplicationConfig, ReplicationError, ReplicationManager,
    StrictHandle, StrictReplicable,
};
use shitspeak_s2s::testing::{
    Cluster, full_mesh_seeds, wait_for_full_alive_mesh, wait_for_full_routing, wait_until,
};
use tempfile::TempDir;

pub(crate) struct ReplCluster {
    pub(crate) cluster: Cluster,
    pub(crate) managers: Vec<Arc<ReplicationManager>>,
    persistence_dirs: Vec<TempDir>,
}

impl ReplCluster {
    /// Build a full-mesh `n`-node cluster with a `ReplicationManager` per
    /// node, and wait for full alive mesh + full routing.
    pub async fn build_full_mesh(node_ids: &[u16]) -> Self {
        Self::build_with_overlay_config(node_ids, ReplicationConfig::default(), repl_overlay_cfg)
            .await
    }

    pub async fn build_full_mesh_fast_failure(node_ids: &[u16]) -> Self {
        Self::build_with_overlay_config(
            node_ids,
            ReplicationConfig::default(),
            repl_fast_failure_overlay_cfg,
        )
        .await
    }

    pub async fn build_full_mesh_with_config(node_ids: &[u16], cfg: ReplicationConfig) -> Self {
        Self::build_with_overlay_config(node_ids, cfg, repl_overlay_cfg).await
    }

    pub async fn build_full_mesh_fast_failure_with_config(
        node_ids: &[u16],
        cfg: ReplicationConfig,
    ) -> Self {
        Self::build_with_overlay_config(node_ids, cfg, repl_fast_failure_overlay_cfg).await
    }

    async fn build_with_overlay_config(
        node_ids: &[u16],
        cfg: ReplicationConfig,
        configure_overlay: fn(usize, OverlayConfig) -> OverlayConfig,
    ) -> Self {
        // Strict v2 requires a durable terminal journal. Keep a distinct
        // root per node so the real-network harness exercises the same
        // capability path as production and can reuse one root on restart.
        let persistence_dirs: Vec<_> = node_ids
            .iter()
            .map(|_| TempDir::new().expect("strict test persistence dir"))
            .collect();
        let persistence_paths: Vec<_> = persistence_dirs
            .iter()
            .map(|dir| dir.path().to_path_buf())
            .collect();
        let cluster = Cluster::build_with_cfg(node_ids, full_mesh_seeds, move |idx, base| {
            configure_overlay(idx, base).with_persistence_dir(persistence_paths[idx].clone())
        })
        .await;
        Self::from_cluster(cluster, cfg, persistence_dirs).await
    }

    async fn from_cluster(
        cluster: Cluster,
        cfg: ReplicationConfig,
        persistence_dirs: Vec<TempDir>,
    ) -> Self {
        assert!(
            wait_for_full_alive_mesh(&cluster, Duration::from_secs(8)).await,
            "alive mesh did not form"
        );
        assert!(
            wait_for_full_routing(&cluster, Duration::from_secs(8)).await,
            "routing did not converge"
        );
        let managers: Vec<Arc<ReplicationManager>> = cluster
            .nodes
            .iter()
            .map(|n| ReplicationManager::with_config(n.overlay.clone(), cfg.clone()))
            .collect();
        Self {
            cluster,
            managers,
            persistence_dirs,
        }
    }

    pub fn manager(&self, idx: usize) -> &Arc<ReplicationManager> {
        &self.managers[idx]
    }

    pub fn persistence_dir(&self, idx: usize) -> &std::path::Path {
        self.persistence_dirs[idx].path()
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

fn repl_overlay_cfg(_idx: usize, cfg: OverlayConfig) -> OverlayConfig {
    cfg.with_lsa_max_age(Duration::from_secs(60))
}

fn repl_fast_failure_overlay_cfg(_idx: usize, cfg: OverlayConfig) -> OverlayConfig {
    cfg.with_lsa_max_age(Duration::from_secs(5))
}
