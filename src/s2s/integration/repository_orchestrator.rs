use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::RwLock;
use tokio::task::JoinHandle;

use crate::s2s::core::overlay::Overlay;
use crate::s2s::core::replication::{OwnerReplicableRepository, StrictReplicableRepository};
use crate::s2s::core::transport::StreamClass;

use super::VoiceStreamAdapter;

#[derive(Clone)]
pub struct S2SOrchestrator {
    overlay: Overlay,
    started: Arc<AtomicBool>,
    strict_registrations: Arc<RwLock<Vec<String>>>,
    owner_registrations: Arc<RwLock<Vec<String>>>,
    strict_workers: Arc<RwLock<Vec<JoinHandle<()>>>>,
    owner_workers: Arc<RwLock<Vec<JoinHandle<()>>>>,
}

impl S2SOrchestrator {
    pub fn new(overlay: Overlay) -> Self {
        Self {
            overlay,
            started: Arc::new(AtomicBool::new(false)),
            strict_registrations: Arc::new(RwLock::new(Vec::new())),
            owner_registrations: Arc::new(RwLock::new(Vec::new())),
            strict_workers: Arc::new(RwLock::new(Vec::new())),
            owner_workers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn overlay(&self) -> &Overlay {
        &self.overlay
    }

    pub fn voice_adapter(&self) -> VoiceStreamAdapter {
        VoiceStreamAdapter::new(self.overlay.clone())
    }

    pub fn is_started(&self) -> bool {
        self.started.load(Ordering::Relaxed)
    }

    pub fn strict_count(&self) -> usize {
        self.strict_registrations.read().len()
    }

    pub fn owner_count(&self) -> usize {
        self.owner_registrations.read().len()
    }

    pub fn strict_worker_count(&self) -> usize {
        self.strict_workers.read().len()
    }

    pub fn owner_worker_count(&self) -> usize {
        self.owner_workers.read().len()
    }

    pub async fn start(&self) -> Result<(), String> {
        self.started.store(true, Ordering::Relaxed);
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<(), String> {
        self.started.store(false, Ordering::Relaxed);

        {
            let mut workers = self.strict_workers.write();
            for worker in workers.drain(..) {
                worker.abort();
            }
        }
        {
            let mut workers = self.owner_workers.write();
            for worker in workers.drain(..) {
                worker.abort();
            }
        }

        Ok(())
    }

    pub fn register_strict<R>(&self, name: &str, _repo: Arc<R>)
    where
        R: StrictReplicableRepository + 'static,
    {
        self.strict_registrations.write().push(name.to_owned());

        let repo = Arc::clone(&_repo);
        let overlay = self.overlay.clone();
        let label = name.to_owned();
        let handle = tokio::spawn(async move {
            let mut rx = repo.subscribe_local();
            loop {
                let op = match rx.recv().await {
                    Ok(op) => op,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };

                let payload = match serde_json::to_vec(&*op) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        tracing::warn!(repo = %label, %err, "strict worker encode failed");
                        continue;
                    }
                };

                if let Err(err) = overlay
                    .send_broadcast(StreamClass::Reliable, Bytes::from(payload))
                    .await
                {
                    tracing::warn!(repo = %label, %err, "strict worker broadcast failed");
                }
            }
        });

        self.strict_workers.write().push(handle);
    }

    pub fn register_owner<R>(&self, name: &str, _repo: Arc<R>)
    where
        R: OwnerReplicableRepository + 'static,
    {
        self.owner_registrations.write().push(name.to_owned());

        let repo = Arc::clone(&_repo);
        let overlay = self.overlay.clone();
        let label = name.to_owned();
        let handle = tokio::spawn(async move {
            let mut rx = repo.subscribe_local();
            loop {
                let op = match rx.recv().await {
                    Ok(op) => op,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };

                let payload = match serde_json::to_vec(&*op) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        tracing::warn!(repo = %label, %err, "owner worker encode failed");
                        continue;
                    }
                };

                if let Err(err) = overlay
                    .send_broadcast(StreamClass::Reliable, Bytes::from(payload))
                    .await
                {
                    tracing::warn!(repo = %label, %err, "owner worker broadcast failed");
                }
            }
        });

        self.owner_workers.write().push(handle);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use async_trait::async_trait;

    use crate::s2s::core::overlay::types::ClusterView;
    use crate::s2s::core::transport::{StreamClass, Transport, TransportError};
    use crate::s2s::core::NodeId;

    use super::*;

    #[derive(Default)]
    struct NullTransport;

    impl Transport for NullTransport {
        fn try_send_frame(
            &self,
            _next_hop: NodeId,
            _class: StreamClass,
            _payload: bytes::Bytes,
        ) -> Result<(), TransportError> {
            Ok(())
        }

        fn try_send_batch(
            &self,
            _next_hop: NodeId,
            _class: StreamClass,
            payloads: &[bytes::Bytes],
        ) -> Result<usize, TransportError> {
            Ok(payloads.len())
        }

        fn bind_udp(&self, _listen: &str) -> Result<std::net::SocketAddr, TransportError> {
            "127.0.0.1:0"
                .parse()
                .map_err(|e| TransportError::Io(format!("null parse failed: {e}")))
        }

        fn register_peer_addr(&self, _node_id: NodeId, _addr: std::net::SocketAddr) -> Result<(), TransportError> {
            Ok(())
        }
    }

    struct NullClusterView;

    impl ClusterView for NullClusterView {
        fn local_node(&self) -> NodeId {
            1
        }

        fn alive_nodes_excluding_self(&self) -> Vec<NodeId> {
            vec![]
        }

        fn resolve_next_hop(&self, _dst: NodeId) -> Option<NodeId> {
            None
        }

        fn resolve_direct_hop(&self, _dst: NodeId) -> Option<NodeId> {
            None
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("dummy")]
    struct DummyErr;

    struct DummyStrictRepo;

    impl crate::s2s::core::replication::ReplicableRepository for DummyStrictRepo {
        type Op = HashMap<String, String>;
        type Error = DummyErr;

        fn current_version(&self) -> u64 {
            0
        }

        fn subscribe_local(&self) -> tokio::sync::broadcast::Receiver<Arc<Self::Op>> {
            let (_tx, rx) = tokio::sync::broadcast::channel(1);
            rx
        }
    }

    #[async_trait]
    impl StrictReplicableRepository for DummyStrictRepo {
        async fn apply_replicated(&self, _op: Self::Op) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn export_snapshot(&self) -> Result<Vec<u8>, Self::Error> {
            Ok(Vec::new())
        }

        async fn install_snapshot(&self, _bytes: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn get_log_since(&self, _version: u64) -> Result<Vec<Self::Op>, Self::Error> {
            Ok(Vec::new())
        }
    }

    struct DummyOwnerRepo;

    impl crate::s2s::core::replication::ReplicableRepository for DummyOwnerRepo {
        type Op = HashMap<String, String>;
        type Error = DummyErr;

        fn current_version(&self) -> u64 {
            0
        }

        fn subscribe_local(&self) -> tokio::sync::broadcast::Receiver<Arc<Self::Op>> {
            let (_tx, rx) = tokio::sync::broadcast::channel(1);
            rx
        }
    }

    #[async_trait]
    impl OwnerReplicableRepository for DummyOwnerRepo {
        fn owner_node(&self) -> NodeId {
            1
        }

        async fn apply_replicated(&self, _op: Self::Op) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn reset_for_epoch(&self, _owner: NodeId, _new_epoch: String) {}

        async fn get_origin_log_since(
            &self,
            _origin: NodeId,
            _since: u64,
        ) -> Result<Vec<Self::Op>, Self::Error> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn orchestrator_tracks_registrations_and_lifecycle() {
        let (overlay, _rx) = Overlay::new(Arc::new(NullTransport), Arc::new(NullClusterView));
        let orchestrator = S2SOrchestrator::new(overlay);

        orchestrator.register_strict("channels", Arc::new(DummyStrictRepo));
        orchestrator.register_owner("clients", Arc::new(DummyOwnerRepo));

        assert_eq!(orchestrator.strict_count(), 1);
        assert_eq!(orchestrator.owner_count(), 1);
        assert_eq!(orchestrator.strict_worker_count(), 1);
        assert_eq!(orchestrator.owner_worker_count(), 1);
        assert!(!orchestrator.is_started());

        orchestrator.start().await.expect("start succeeds");
        assert!(orchestrator.is_started());
        orchestrator.shutdown().await.expect("shutdown succeeds");
        assert!(!orchestrator.is_started());
        assert_eq!(orchestrator.strict_worker_count(), 0);
        assert_eq!(orchestrator.owner_worker_count(), 0);
    }
}
