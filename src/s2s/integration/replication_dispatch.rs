use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum RepositoryKind {
    Channel,
    Ban,
    Client,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReplicationEnvelope {
    pub repository: RepositoryKind,
    pub payload: Vec<u8>,
}

impl ReplicationEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("replication envelope encode failed: {e}"))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes)
            .map_err(|e| format!("replication envelope decode failed: {e}"))
    }
}

pub trait ReplicationInboundHandler: Send + Sync {
    fn handle(&self, payload: Bytes) -> Result<(), String>;
}

#[derive(Clone, Default)]
pub struct ReplicationHandlerRegistry {
    handlers: Arc<RwLock<HashMap<RepositoryKind, Arc<dyn ReplicationInboundHandler>>>>,
}

impl ReplicationHandlerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &self,
        kind: RepositoryKind,
        handler: Arc<dyn ReplicationInboundHandler>,
    ) {
        self.handlers.write().insert(kind, handler);
    }

    pub fn handler_count(&self) -> usize {
        self.handlers.read().len()
    }

    pub fn dispatch(&self, envelope: ReplicationEnvelope) -> Result<(), String> {
        let handler = {
            let handlers = self.handlers.read();
            handlers.get(&envelope.repository).cloned()
        };

        let Some(handler) = handler else {
            return Err(format!(
                "no replication handler registered for {:?}",
                envelope.repository
            ));
        };

        handler.handle(Bytes::from(envelope.payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct CaptureHandler {
        calls: RwLock<Vec<Vec<u8>>>,
    }

    impl ReplicationInboundHandler for CaptureHandler {
        fn handle(&self, payload: Bytes) -> Result<(), String> {
            self.calls.write().push(payload.to_vec());
            Ok(())
        }
    }

    #[test]
    fn envelope_round_trip_works() {
        let envelope = ReplicationEnvelope {
            repository: RepositoryKind::Channel,
            payload: b"abc".to_vec(),
        };

        let bytes = envelope.encode().expect("encode should succeed");
        let decoded = ReplicationEnvelope::decode(&bytes).expect("decode should succeed");

        assert_eq!(decoded.repository, RepositoryKind::Channel);
        assert_eq!(decoded.payload, b"abc");
    }

    #[test]
    fn registry_dispatches_by_repository_kind() {
        let registry = ReplicationHandlerRegistry::new();
        let channel = Arc::new(CaptureHandler::default());
        let client = Arc::new(CaptureHandler::default());

        registry.register(RepositoryKind::Channel, channel.clone());
        registry.register(RepositoryKind::Client, client.clone());

        registry
            .dispatch(ReplicationEnvelope {
                repository: RepositoryKind::Client,
                payload: b"hello".to_vec(),
            })
            .expect("dispatch should succeed");

        assert!(channel.calls.read().is_empty());
        assert_eq!(client.calls.read().len(), 1);
        assert_eq!(client.calls.read()[0], b"hello");
    }
}
