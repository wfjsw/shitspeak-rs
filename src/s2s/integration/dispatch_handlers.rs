use std::sync::Arc;

use bytes::Bytes;
use parking_lot::RwLock;

use super::replication_dispatch::ReplicationInboundHandler;

pub trait ChannelReplicationSink: Send + Sync {
    fn ingest_channel_frame(&self, payload: Bytes) -> Result<(), String>;
}

pub trait BanReplicationSink: Send + Sync {
    fn ingest_ban_frame(&self, payload: Bytes) -> Result<(), String>;
}

pub trait ClientReplicationSink: Send + Sync {
    fn ingest_client_frame(&self, payload: Bytes) -> Result<(), String>;
}

#[derive(Clone, Default)]
pub struct ReplicationDispatchContext {
    pub channel_sink: Arc<RwLock<Option<Arc<dyn ChannelReplicationSink>>>>,
    pub ban_sink: Arc<RwLock<Option<Arc<dyn BanReplicationSink>>>>,
    pub client_sink: Arc<RwLock<Option<Arc<dyn ClientReplicationSink>>>>,
}

impl ReplicationDispatchContext {
    pub fn new() -> Self {
        Self::default()
    }
}

pub struct ChannelReplicationHandler {
    context: ReplicationDispatchContext,
}

impl ChannelReplicationHandler {
    pub fn new(context: ReplicationDispatchContext) -> Self {
        Self { context }
    }
}

impl ReplicationInboundHandler for ChannelReplicationHandler {
    fn handle(&self, payload: Bytes) -> Result<(), String> {
        let sink = self.context.channel_sink.read();
        if let Some(sink) = sink.as_ref() {
            sink.ingest_channel_frame(payload)
        } else {
            tracing::debug!("channel replication sink unavailable; inbound frame ignored");
            Ok(())
        }
    }
}

pub struct BanReplicationHandler {
    context: ReplicationDispatchContext,
}

impl BanReplicationHandler {
    pub fn new(context: ReplicationDispatchContext) -> Self {
        Self { context }
    }
}

impl ReplicationInboundHandler for BanReplicationHandler {
    fn handle(&self, payload: Bytes) -> Result<(), String> {
        let sink = self.context.ban_sink.read();
        if let Some(sink) = sink.as_ref() {
            sink.ingest_ban_frame(payload)
        } else {
            tracing::debug!("ban replication sink unavailable; inbound frame ignored");
            Ok(())
        }
    }
}

pub struct ClientReplicationHandler {
    context: ReplicationDispatchContext,
}

impl ClientReplicationHandler {
    pub fn new(context: ReplicationDispatchContext) -> Self {
        Self { context }
    }
}

impl ReplicationInboundHandler for ClientReplicationHandler {
    fn handle(&self, payload: Bytes) -> Result<(), String> {
        let sink = self.context.client_sink.read();
        if let Some(sink) = sink.as_ref() {
            sink.ingest_client_frame(payload)
        } else {
            tracing::debug!("client replication sink unavailable; inbound frame ignored");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct CaptureSink {
        frames: RwLock<Vec<Vec<u8>>>,
    }

    impl ChannelReplicationSink for CaptureSink {
        fn ingest_channel_frame(&self, payload: Bytes) -> Result<(), String> {
            self.frames.write().push(payload.to_vec());
            Ok(())
        }
    }

    impl BanReplicationSink for CaptureSink {
        fn ingest_ban_frame(&self, payload: Bytes) -> Result<(), String> {
            self.frames.write().push(payload.to_vec());
            Ok(())
        }
    }

    impl ClientReplicationSink for CaptureSink {
        fn ingest_client_frame(&self, payload: Bytes) -> Result<(), String> {
            self.frames.write().push(payload.to_vec());
            Ok(())
        }
    }

    #[test]
    fn handlers_are_noop_without_sink() {
        let context = ReplicationDispatchContext::new();
        let channel = ChannelReplicationHandler::new(context.clone());
        let ban = BanReplicationHandler::new(context.clone());
        let client = ClientReplicationHandler::new(context);

        assert!(channel.handle(Bytes::from_static(b"a")).is_ok());
        assert!(ban.handle(Bytes::from_static(b"b")).is_ok());
        assert!(client.handle(Bytes::from_static(b"c")).is_ok());
    }

    #[test]
    fn channel_handler_forwards_to_registered_sink() {
        let context = ReplicationDispatchContext::new();
        let sink = Arc::new(CaptureSink::default());
        *context.channel_sink.write() = Some(sink.clone());

        let handler = ChannelReplicationHandler::new(context);
        handler
            .handle(Bytes::from_static(b"payload"))
            .expect("dispatch should succeed");

        assert_eq!(sink.frames.read().len(), 1);
    }
}
