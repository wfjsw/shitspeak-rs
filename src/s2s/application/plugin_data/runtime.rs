use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::trace;

use crate::client::client_session_identifier::ClientSessionIdentifier;
use crate::messages::encoder::PluginDataTransmission;
use crate::messages::Message;
use crate::s2s::application::error::ApplicationError;
use crate::s2s::application::proto::{self, PluginDataEnvelope, PLUGIN_DATA_SERVICE_TAG};
use crate::s2s::overlay::{OverlayInboundMessage, OverlayNetwork, ServiceInbound};
use crate::s2s::transport::{MessageClass, ServiceLevel};
use crate::server::Server;
use crate::types::NodeIdentifier;

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
            .send_unicast(
                dst,
                PLUGIN_DATA_SERVICE_TAG,
                PLUGIN_DATA_LEVEL,
                PLUGIN_DATA_CLASS,
                body,
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

pub async fn deliver_to_local_recipients(server: &Arc<Box<Server>>, envelope: PluginDataEnvelope) {
    if envelope.receiver_sessions.is_empty() {
        return;
    }

    let server_id = if envelope.server_id.is_empty() {
        crate::types::default_server_id()
    } else {
        envelope.server_id
    };
    let sender_id = ClientSessionIdentifier::from(envelope.sender_session);
    let sender = server
        .get_clients()
        .get_client_in_server(&server_id, sender_id)
        .await;
    if server.get_hide_users_without_traverse() && sender.is_none() {
        return;
    }
    for receiver in envelope.receiver_sessions {
        let id = ClientSessionIdentifier::from(receiver);
        if id.get_node_id() == server.get_clients().local_node_id() {
            let Some(target) = server
                .get_clients()
                .get_client_in_server(&server_id, id)
                .await
            else {
                continue;
            };
            if let Some(sender) = sender.as_ref() {
                if !crate::client::visibility::can_view_user(server, sender, &target).await {
                    continue;
                }
                if !crate::client::visibility::can_view_user(server, &target, sender).await {
                    continue;
                }
            }
            let message: Message = PluginDataTransmission {
                sender_session: Some(envelope.sender_session),
                receiver_sessions: vec![receiver],
                data: Some(envelope.data.clone()),
                data_id: envelope.data_id.clone(),
            }
            .into();
            server
                .get_clients()
                .send_to_in_server(&server_id, id, &message)
                .await;
        }
    }
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
            server_id: crate::types::default_server_id(),
        };

        svc.dispatch(9, envelope.clone()).await.unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 9);
        assert_eq!(proto::decode_plugin_data(&calls[0].1).unwrap(), envelope);
    }
}
