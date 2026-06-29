use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::trace;

use crate::application::error::ApplicationError;
use crate::application::proto::{self, PLUGIN_DATA_SERVICE_TAG, PluginDataEnvelope};
use crate::overlay::{OverlayInboundMessage, OverlayNetwork, OverlaySendOptions, ServiceInbound};
use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{MessageClass, ServiceLevel};

pub const PLUGIN_DATA_LEVEL: ServiceLevel = ServiceLevel::Reliable;
pub const PLUGIN_DATA_CLASS: MessageClass = MessageClass::Regular;

#[async_trait]
pub trait PluginDataTransport: Send + Sync + 'static {
    async fn send_unicast(&self, dst: NodeIdentifier, body: Bytes) -> Result<(), ApplicationError>;
}

pub struct OverlayPluginDataTransport {
    overlay: OverlayNetwork,
}

#[async_trait]
impl PluginDataTransport for OverlayPluginDataTransport {
    async fn send_unicast(&self, dst: NodeIdentifier, body: Bytes) -> Result<(), ApplicationError> {
        self.overlay
            .send_unicast_with_options(
                dst,
                PLUGIN_DATA_SERVICE_TAG,
                PLUGIN_DATA_LEVEL,
                PLUGIN_DATA_CLASS,
                body,
                OverlaySendOptions::default().allow_l1_compression(),
            )
            .await?;
        Ok(())
    }
}

#[async_trait]
pub trait PluginDataSink: Send + Sync + 'static {
    async fn deliver(&self, from: NodeIdentifier, envelope: PluginDataEnvelope);
}

pub struct PluginDataDelivery {
    from: NodeIdentifier,
    envelope: PluginDataEnvelope,
}

pub struct PluginDataService {
    transport: Arc<dyn PluginDataTransport>,
    inbox_tx: mpsc::UnboundedSender<PluginDataDelivery>,
    sink: Arc<parking_lot::RwLock<Option<Arc<dyn PluginDataSink>>>>,
}

impl PluginDataService {
    pub fn new(overlay: OverlayNetwork, shutdown: CancellationToken) -> Arc<Self> {
        let transport: Arc<dyn PluginDataTransport> =
            Arc::new(OverlayPluginDataTransport { overlay });
        Self::new_with_transport(transport, shutdown)
    }

    pub fn new_with_transport(
        transport: Arc<dyn PluginDataTransport>,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel::<PluginDataDelivery>();
        let sink = Arc::new(parking_lot::RwLock::new(None));
        spawn_dispatch_task(inbox_rx, shutdown, sink.clone());
        Arc::new(Self {
            transport,
            inbox_tx,
            sink,
        })
    }

    pub fn inbound_handler(&self) -> Arc<dyn ServiceInbound> {
        Arc::new(PluginDataInbound {
            inbox_tx: self.inbox_tx.clone(),
        })
    }

    pub fn set_sink(&self, sink: Arc<dyn PluginDataSink>) {
        *self.sink.write() = Some(sink);
    }

    pub fn clear_sink(&self) {
        *self.sink.write() = None;
    }

    pub async fn dispatch(
        &self,
        owner: NodeIdentifier,
        envelope: PluginDataEnvelope,
    ) -> Result<(), ApplicationError> {
        let bytes = proto::encode_plugin_data(&envelope)?;
        self.transport.send_unicast(owner, bytes).await
    }
}

pub struct PluginDataInbound {
    inbox_tx: mpsc::UnboundedSender<PluginDataDelivery>,
}

impl ServiceInbound for PluginDataInbound {
    fn handle(&self, msg: OverlayInboundMessage) {
        match proto::decode_plugin_data(&msg.body) {
            Ok(envelope) => {
                let _ = self.inbox_tx.send(PluginDataDelivery {
                    from: msg.from,
                    envelope,
                });
            }
            Err(e) => {
                trace!(error=%e, from=%msg.from, "plugin data: decode failed");
            }
        }
    }
}

fn spawn_dispatch_task(
    mut rx: mpsc::UnboundedReceiver<PluginDataDelivery>,
    shutdown: CancellationToken,
    sink: Arc<parking_lot::RwLock<Option<Arc<dyn PluginDataSink>>>>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                next = rx.recv() => {
                    let Some(delivery) = next else { return };
                    let sink_now = sink.read().clone();
                    match sink_now {
                        Some(sink) => sink.deliver(delivery.from, delivery.envelope).await,
                        None => trace!(
                            from = %delivery.from,
                            sender = delivery.envelope.sender_session,
                            "plugin data: no sink installed; dropping",
                        ),
                    }
                }
            }
        }
    });
}

#[cfg(test)]
pub mod testing {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Default)]
    pub struct FakePluginDataTransport {
        calls: Mutex<Vec<(NodeIdentifier, Bytes)>>,
    }

    impl FakePluginDataTransport {
        pub fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        pub fn calls(&self) -> Vec<(NodeIdentifier, Bytes)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl PluginDataTransport for FakePluginDataTransport {
        async fn send_unicast(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
        ) -> Result<(), ApplicationError> {
            self.calls.lock().unwrap().push((dst, body));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testing::FakePluginDataTransport;

    #[tokio::test]
    async fn dispatch_unicasts_encoded_envelope() {
        let transport = FakePluginDataTransport::new();
        let svc =
            PluginDataService::new_with_transport(transport.clone(), CancellationToken::new());
        let envelope = PluginDataEnvelope {
            sender_session: 1,
            receiver_sessions: vec![2, 3],
            data: Bytes::from_static(b"payload"),
            data_id: Some("id".to_string()),
            server_id: shitspeak_core::default_server_id(),
        };

        svc.dispatch(9, envelope.clone()).await.unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 9);
        assert_eq!(proto::decode_plugin_data(&calls[0].1).unwrap(), envelope);
    }
}
