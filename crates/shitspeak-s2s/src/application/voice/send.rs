//! Speaker-side send primitives for the voice service.
//!
//! `VoiceTransport` is the narrow interface the rest of the codebase
//! talks to. The production impl wraps [`OverlayNetwork`]; tests can
//! substitute a recording fake to assert the dispatch shape (level,
//! class, recipients, encoded bytes) without standing up a cluster.

use async_trait::async_trait;
use bytes::Bytes;

use crate::application::error::ApplicationError;
use crate::application::proto::{self, VOICE_SERVICE_TAG, VoiceIntent};
use crate::overlay::{OverlayNetwork, RoutingMetric};
use shitspeak_s2s_transport::{MessageClass, ServiceLevel};
use shitspeak_core::NodeIdentifier;

/// Voice frames are best-effort by design (drop tolerated, latency
/// critical) and run on the high-priority receiver queue.
pub const VOICE_LEVEL: ServiceLevel = ServiceLevel::BestEffort;
pub const VOICE_CLASS: MessageClass = MessageClass::HighPriority;
pub const VOICE_ROUTING_METRIC: RoutingMetric = RoutingMetric::ConversationalQuality;

/// Narrow send-only interface used by the voice service. Production
/// impl: [`OverlayVoiceTransport`]. Test impl: see the unit tests below.
#[async_trait]
pub trait VoiceTransport: Send + Sync + 'static {
    async fn send_unicast(&self, dst: NodeIdentifier, body: Bytes) -> Result<(), ApplicationError>;

    async fn send_multicast(
        &self,
        dsts: &[NodeIdentifier],
        body: Bytes,
    ) -> Result<(), ApplicationError>;

    async fn send_broadcast(&self, body: Bytes) -> Result<(), ApplicationError>;

    fn alive_members(&self) -> Vec<NodeIdentifier>;

    fn local_node_id(&self) -> NodeIdentifier;
}

/// Production `VoiceTransport` impl backed by the overlay network.
pub struct OverlayVoiceTransport {
    pub overlay: OverlayNetwork,
}

#[async_trait]
impl VoiceTransport for OverlayVoiceTransport {
    async fn send_unicast(&self, dst: NodeIdentifier, body: Bytes) -> Result<(), ApplicationError> {
        self.overlay
            .send_unicast_with_routing_metric_and_transit_processing(
                dst,
                VOICE_SERVICE_TAG,
                VOICE_LEVEL,
                VOICE_ROUTING_METRIC,
                VOICE_CLASS,
                body,
            )
            .await?;
        Ok(())
    }

    async fn send_multicast(
        &self,
        dsts: &[NodeIdentifier],
        body: Bytes,
    ) -> Result<(), ApplicationError> {
        if dsts.is_empty() {
            return Ok(());
        }
        self.overlay
            .send_multicast_with_routing_metric_and_transit_processing(
                dsts,
                VOICE_SERVICE_TAG,
                VOICE_LEVEL,
                VOICE_ROUTING_METRIC,
                VOICE_CLASS,
                body,
            )
            .await?;
        Ok(())
    }

    async fn send_broadcast(&self, body: Bytes) -> Result<(), ApplicationError> {
        self.overlay
            .send_broadcast_with_routing_metric_and_transit_processing(
                VOICE_SERVICE_TAG,
                VOICE_LEVEL,
                VOICE_ROUTING_METRIC,
                VOICE_CLASS,
                body,
            )
            .await?;
        Ok(())
    }

    fn alive_members(&self) -> Vec<NodeIdentifier> {
        self.overlay.alive_members()
    }

    fn local_node_id(&self) -> NodeIdentifier {
        self.overlay.local_node_id()
    }
}

/// Build the wire envelope and encode it. Pulled out so unit tests can
/// reach in without a transport.
pub fn build_envelope(
    sender_session: u32,
    server_id: String,
    sender_epoch: u64,
    s2s_seq: u64,
    target_kind: u32,
    is_terminator: bool,
    payload: Bytes,
    intent: VoiceIntent,
) -> Result<Bytes, prost::EncodeError> {
    let frame = proto::VoiceFrame {
        sender_session,
        server_id,
        sender_epoch,
        s2s_seq,
        target_kind,
        is_terminator,
        payload,
        intent: Some(intent),
    };
    proto::encode_voice(&frame)
}

#[cfg(test)]
pub(crate) mod testing {
    use std::sync::Arc;
    use std::sync::Mutex;

    use super::*;

    /// Recording fake for asserting send shape in unit tests.
    #[derive(Debug, Default)]
    pub struct FakeVoiceTransport {
        pub local_node: NodeIdentifier,
        pub alive: Vec<NodeIdentifier>,
        pub calls: Mutex<Vec<FakeCall>>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum FakeCall {
        Unicast {
            dst: NodeIdentifier,
            body: Bytes,
        },
        Multicast {
            dsts: Vec<NodeIdentifier>,
            body: Bytes,
        },
        Broadcast {
            body: Bytes,
        },
    }

    impl FakeVoiceTransport {
        pub fn new(local_node: NodeIdentifier, alive: Vec<NodeIdentifier>) -> Arc<Self> {
            Arc::new(Self {
                local_node,
                alive,
                calls: Mutex::new(Vec::new()),
            })
        }

        pub fn calls(&self) -> Vec<FakeCall> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl VoiceTransport for FakeVoiceTransport {
        async fn send_unicast(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
        ) -> Result<(), ApplicationError> {
            self.calls
                .lock()
                .unwrap()
                .push(FakeCall::Unicast { dst, body });
            Ok(())
        }

        async fn send_multicast(
            &self,
            dsts: &[NodeIdentifier],
            body: Bytes,
        ) -> Result<(), ApplicationError> {
            self.calls.lock().unwrap().push(FakeCall::Multicast {
                dsts: dsts.to_vec(),
                body,
            });
            Ok(())
        }

        async fn send_broadcast(&self, body: Bytes) -> Result<(), ApplicationError> {
            self.calls
                .lock()
                .unwrap()
                .push(FakeCall::Broadcast { body });
            Ok(())
        }

        fn alive_members(&self) -> Vec<NodeIdentifier> {
            self.alive.clone()
        }

        fn local_node_id(&self) -> NodeIdentifier {
            self.local_node
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let payload = Bytes::from_static(b"opus-bytes-here");
        let bytes = build_envelope(
            0xABC_12345,
            shitspeak_core::default_server_id(),
            1_700_000_000_000_000,
            42,
            0,
            false,
            payload.clone(),
            VoiceIntent {
                kind: Some(proto::VoiceIntentKind::Normal(proto::VoiceIntentNormal {
                    source_channel: 5,
                })),
            },
        )
        .unwrap();
        let decoded = proto::decode_voice(&bytes).unwrap();
        assert_eq!(decoded.sender_session, 0xABC_12345);
        assert_eq!(decoded.server_id, shitspeak_core::default_server_id());
        assert_eq!(decoded.sender_epoch, 1_700_000_000_000_000);
        assert_eq!(decoded.s2s_seq, 42);
        assert_eq!(decoded.target_kind, 0);
        assert!(!decoded.is_terminator);
        assert_eq!(decoded.payload, payload.as_ref());
        assert!(matches!(
            decoded.intent.and_then(|i| i.kind),
            Some(proto::VoiceIntentKind::Normal(n)) if n.source_channel == 5
        ));
    }
}
