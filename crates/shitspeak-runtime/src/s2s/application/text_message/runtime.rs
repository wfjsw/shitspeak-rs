use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::trace;

use crate::client::client_session_identifier::ClientSessionIdentifier;
use crate::messages::Message;
use crate::messages::encoder::TextMessage;
use crate::s2s::application::error::ApplicationError;
use crate::s2s::application::proto::{self, TEXT_MESSAGE_SERVICE_TAG, TextMessageEnvelope};
use crate::s2s::overlay::{
    OverlayInboundMessage, OverlayNetwork, OverlaySendOptions, ServiceInbound,
};
use crate::s2s::transport::{MessageClass, ServiceLevel};
use crate::server::Server;
use crate::types::NodeIdentifier;

pub const TEXT_MESSAGE_LEVEL: ServiceLevel = ServiceLevel::Reliable;
pub const TEXT_MESSAGE_CLASS: MessageClass = MessageClass::Regular;

#[async_trait]
pub trait TextMessageTransport: Send + Sync + 'static {
    async fn send_unicast(&self, dst: NodeIdentifier, body: Bytes) -> Result<(), ApplicationError>;
}

pub struct OverlayTextMessageTransport {
    overlay: OverlayNetwork,
}

#[async_trait]
impl TextMessageTransport for OverlayTextMessageTransport {
    async fn send_unicast(&self, dst: NodeIdentifier, body: Bytes) -> Result<(), ApplicationError> {
        self.overlay
            .send_unicast_with_options(
                dst,
                TEXT_MESSAGE_SERVICE_TAG,
                TEXT_MESSAGE_LEVEL,
                TEXT_MESSAGE_CLASS,
                body,
                OverlaySendOptions::default().allow_l1_compression(),
            )
            .await?;
        Ok(())
    }
}

#[async_trait]
pub trait TextMessageSink: Send + Sync + 'static {
    async fn deliver(&self, from: NodeIdentifier, envelope: TextMessageEnvelope);
}

pub struct TextMessageDelivery {
    from: NodeIdentifier,
    envelope: TextMessageEnvelope,
}

pub struct TextMessageService {
    transport: Arc<dyn TextMessageTransport>,
    inbox_tx: mpsc::UnboundedSender<TextMessageDelivery>,
    sink: Arc<parking_lot::RwLock<Option<Arc<dyn TextMessageSink>>>>,
}

impl TextMessageService {
    pub fn new(overlay: OverlayNetwork, shutdown: CancellationToken) -> Arc<Self> {
        let transport: Arc<dyn TextMessageTransport> =
            Arc::new(OverlayTextMessageTransport { overlay });
        Self::new_with_transport(transport, shutdown)
    }

    pub fn new_with_transport(
        transport: Arc<dyn TextMessageTransport>,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel::<TextMessageDelivery>();
        let sink = Arc::new(parking_lot::RwLock::new(None));
        spawn_dispatch_task(inbox_rx, shutdown, sink.clone());
        Arc::new(Self {
            transport,
            inbox_tx,
            sink,
        })
    }

    pub fn inbound_handler(&self) -> Arc<dyn ServiceInbound> {
        Arc::new(TextMessageInbound {
            inbox_tx: self.inbox_tx.clone(),
        })
    }

    pub fn set_sink(&self, sink: Arc<dyn TextMessageSink>) {
        *self.sink.write() = Some(sink);
    }

    pub fn clear_sink(&self) {
        *self.sink.write() = None;
    }

    pub async fn dispatch(
        &self,
        owner: NodeIdentifier,
        envelope: TextMessageEnvelope,
    ) -> Result<(), ApplicationError> {
        let bytes = proto::encode_text_message(&envelope)?;
        self.transport.send_unicast(owner, bytes).await
    }
}

pub struct TextMessageInbound {
    inbox_tx: mpsc::UnboundedSender<TextMessageDelivery>,
}

impl ServiceInbound for TextMessageInbound {
    fn handle(&self, msg: OverlayInboundMessage) {
        match proto::decode_text_message(&msg.body) {
            Ok(envelope) => {
                let _ = self.inbox_tx.send(TextMessageDelivery {
                    from: msg.from,
                    envelope,
                });
            }
            Err(e) => {
                trace!(error=%e, from=%msg.from, "text message: decode failed");
            }
        }
    }
}

fn spawn_dispatch_task(
    mut rx: mpsc::UnboundedReceiver<TextMessageDelivery>,
    shutdown: CancellationToken,
    sink: Arc<parking_lot::RwLock<Option<Arc<dyn TextMessageSink>>>>,
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
                            "text message: no sink installed; dropping",
                        ),
                    }
                }
            }
        }
    });
}

pub async fn deliver_to_local_recipients(server: &Arc<Box<Server>>, envelope: TextMessageEnvelope) {
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
        if id.get_node_id() != server.get_clients().local_node_id() {
            continue;
        }
        let Some(target) = server
            .get_clients()
            .get_client_in_server(&server_id, id)
            .await
        else {
            continue;
        };
        if !target.is_authenticated() {
            continue;
        }
        if let Some(sender) = sender.as_ref() {
            if !crate::client::visibility::can_view_user(server, sender, &target).await {
                continue;
            }
            if !crate::client::visibility::can_view_user(server, &target, sender).await {
                continue;
            }
        }
        let message: Message = TextMessage {
            actor: Some(envelope.sender_session),
            session: envelope.session.clone(),
            channel_id: envelope.channel_id.clone(),
            tree_id: envelope.tree_id.clone(),
            message: envelope.message.clone(),
        }
        .into();
        server
            .get_clients()
            .send_to_in_server(&server_id, id, &message)
            .await;
    }
}

#[cfg(test)]
pub mod testing {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Default)]
    pub struct FakeTextMessageTransport {
        calls: Mutex<Vec<(NodeIdentifier, Bytes)>>,
    }

    impl FakeTextMessageTransport {
        pub fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        pub fn calls(&self) -> Vec<(NodeIdentifier, Bytes)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl TextMessageTransport for FakeTextMessageTransport {
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
    use testing::FakeTextMessageTransport;

    #[tokio::test]
    async fn dispatch_unicasts_encoded_envelope() {
        let transport = FakeTextMessageTransport::new();
        let svc =
            TextMessageService::new_with_transport(transport.clone(), CancellationToken::new());
        let envelope = TextMessageEnvelope {
            sender_session: 1,
            receiver_sessions: vec![2, 3],
            session: vec![2, 3],
            channel_id: vec![0],
            tree_id: vec![],
            message: "hello".to_string(),
            server_id: crate::types::default_server_id(),
        };

        svc.dispatch(9, envelope.clone()).await.unwrap();

        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 9);
        assert_eq!(proto::decode_text_message(&calls[0].1).unwrap(), envelope);
    }
}
