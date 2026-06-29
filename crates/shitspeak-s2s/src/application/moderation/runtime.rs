//! `ServiceInbound` adapter, central dispatch task, and the
//! caller-facing send API for moderation envelopes.
//!
//! ## Send side
//!
//! [`ModerationService::dispatch_user_state`] and
//! [`ModerationService::dispatch_user_remove`] are the only public
//! send entry-points. They pack the moderator-driven intent into a
//! [`ModerationEnvelope`] and ship it via overlay unicast to the owner
//! node of `target` (extracted from the composite
//! [`ClientSessionIdentifier`](crate::client::client_session_identifier::ClientSessionIdentifier)).
//!
//! ## Apply side
//!
//! Inbound envelopes pass through the central dispatch task and are
//! handed to a swappable [`ModerationApplier`]. The production sink
//! lives in the `Server` layer and applies the mutation through the
//! existing `GlobalStateWriteGuard`. Tests substitute a recording
//! applier to assert routing.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::trace;

use crate::application::error::ApplicationError;
use crate::application::proto::{
    self, MODERATION_SERVICE_TAG, ModerationCommand, ModerationEnvelope, UserRemovePatch,
    UserStatePatch,
};
use crate::overlay::{OverlayInboundMessage, OverlayNetwork, ServiceInbound};
use shitspeak_core::ClientSessionIdentifier;
use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{MessageClass, ServiceLevel};

/// Moderation envelopes are reliable + low-latency at the transport
/// layer (KCP/QUIC preferred, plain TCP acceptable as a fallback per
/// the routing fallback rules) and run on the regular receiver queue
/// (not latency-critical enough to displace voice).
pub const MODERATION_LEVEL: ServiceLevel = ServiceLevel::ReliableLowLatency;
pub const MODERATION_CLASS: MessageClass = MessageClass::Regular;

/// Decoded inbound moderation envelope along with the immediate sender.
#[derive(Debug, Clone)]
pub struct ModerationDelivery {
    pub from: NodeIdentifier,
    pub envelope: ModerationEnvelope,
}

/// Send-only abstraction for outbound moderation envelopes. Production
/// impl wraps [`OverlayNetwork`]; tests inject a recording fake.
#[async_trait]
pub trait ModerationTransport: Send + Sync + 'static {
    async fn send_unicast(&self, dst: NodeIdentifier, body: Bytes) -> Result<(), ApplicationError>;
}

/// Production `ModerationTransport` impl backed by the overlay.
pub struct OverlayModerationTransport {
    pub overlay: OverlayNetwork,
}

#[async_trait]
impl ModerationTransport for OverlayModerationTransport {
    async fn send_unicast(&self, dst: NodeIdentifier, body: Bytes) -> Result<(), ApplicationError> {
        self.overlay
            .send_unicast(
                dst,
                MODERATION_SERVICE_TAG,
                MODERATION_LEVEL,
                MODERATION_CLASS,
                body,
            )
            .await?;
        Ok(())
    }
}

/// Receiver-side apply hook. Implementations should finish quickly or
/// spawn their own task; the dispatch task awaits the call serially.
#[async_trait]
pub trait ModerationApplier: Send + Sync + 'static {
    async fn apply(&self, from: NodeIdentifier, envelope: ModerationEnvelope);
}

type ApplierSlot = Arc<RwLock<Option<Arc<dyn ModerationApplier>>>>;

/// Central handle for the moderation L3 service. Owns the inbound mpsc,
/// the dispatch task, the outbound transport, and the swappable
/// applier slot.
pub struct ModerationService {
    transport: Arc<dyn ModerationTransport>,
    _shutdown: CancellationToken,
    inbox_tx: mpsc::UnboundedSender<ModerationDelivery>,
    applier: ApplierSlot,
}

impl ModerationService {
    pub fn new(overlay: OverlayNetwork, shutdown: CancellationToken) -> Arc<Self> {
        let transport: Arc<dyn ModerationTransport> =
            Arc::new(OverlayModerationTransport { overlay });
        Self::new_with_transport(transport, shutdown)
    }

    pub fn new_with_transport(
        transport: Arc<dyn ModerationTransport>,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel::<ModerationDelivery>();
        let applier: ApplierSlot = Arc::new(RwLock::new(None));
        spawn_dispatch_task(inbox_rx, shutdown.clone(), applier.clone());
        Arc::new(Self {
            transport,
            _shutdown: shutdown,
            inbox_tx,
            applier,
        })
    }

    /// `ServiceInbound` impl that decodes envelope bytes and pushes
    /// onto the central dispatch mpsc.
    pub fn inbound_handler(&self) -> Arc<dyn ServiceInbound> {
        Arc::new(ModerationInbound {
            inbox_tx: self.inbox_tx.clone(),
        })
    }

    /// Install (or replace) the receiver-side applier.
    pub fn set_applier(&self, applier: Arc<dyn ModerationApplier>) {
        *self.applier.write() = Some(applier);
    }

    pub fn clear_applier(&self) {
        *self.applier.write() = None;
    }

    /// Ship a moderator-driven UserState mutation to the owner node of
    /// `target`. Fire-and-forget — successful application propagates
    /// back via owner-scoped replication of `ClientGlobalState`.
    pub async fn dispatch_user_state(
        &self,
        server_id: Option<&str>,
        actor: ClientSessionIdentifier,
        target: ClientSessionIdentifier,
        patch: UserStatePatch,
    ) -> Result<(), ApplicationError> {
        let server_id = server_id.unwrap_or(shitspeak_core::DEFAULT_SERVER_ID);
        let env = ModerationEnvelope {
            actor_session: actor.to_u32(),
            target_session: target.to_u32(),
            issued_at_ms: now_ms(),
            server_id: server_id.to_owned(),
            command: Some(ModerationCommand::UserState(patch)),
        };
        self.dispatch_envelope(target.get_node_id(), env).await
    }

    /// Ship a moderator-driven UserRemove (kick / ban) to the owner.
    pub async fn dispatch_user_remove(
        &self,
        server_id: Option<&str>,
        actor: ClientSessionIdentifier,
        target: ClientSessionIdentifier,
        patch: UserRemovePatch,
    ) -> Result<(), ApplicationError> {
        let server_id = server_id.unwrap_or(shitspeak_core::DEFAULT_SERVER_ID);
        let env = ModerationEnvelope {
            actor_session: actor.to_u32(),
            target_session: target.to_u32(),
            issued_at_ms: now_ms(),
            server_id: server_id.to_owned(),
            command: Some(ModerationCommand::UserRemove(patch)),
        };
        self.dispatch_envelope(target.get_node_id(), env).await
    }

    async fn dispatch_envelope(
        &self,
        owner: NodeIdentifier,
        env: ModerationEnvelope,
    ) -> Result<(), ApplicationError> {
        let bytes = proto::encode_moderation(&env)?;
        self.transport.send_unicast(owner, bytes).await
    }

    pub async fn dispatch_envelope_for_gateway(
        &self,
        owner: NodeIdentifier,
        env: ModerationEnvelope,
    ) -> Result<(), ApplicationError> {
        self.dispatch_envelope(owner, env).await
    }
}

pub struct ModerationInbound {
    inbox_tx: mpsc::UnboundedSender<ModerationDelivery>,
}

impl ServiceInbound for ModerationInbound {
    fn handle(&self, msg: OverlayInboundMessage) {
        match proto::decode_moderation(&msg.body) {
            Ok(envelope) => {
                let _ = self.inbox_tx.send(ModerationDelivery {
                    from: msg.from,
                    envelope,
                });
            }
            Err(e) => {
                trace!(error=%e, from=%msg.from, "moderation: decode failed");
            }
        }
    }
}

fn spawn_dispatch_task(
    mut rx: mpsc::UnboundedReceiver<ModerationDelivery>,
    shutdown: CancellationToken,
    applier: ApplierSlot,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                next = rx.recv() => {
                    let Some(delivery) = next else { return };
                    let applier_now = applier.read().clone();
                    match applier_now {
                        Some(a) => a.apply(delivery.from, delivery.envelope).await,
                        None => trace!(
                            from = %delivery.from,
                            target = delivery.envelope.target_session,
                            "moderation: no applier installed; dropping",
                        ),
                    }
                }
            }
        }
    });
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(any(test, feature = "test-support"))]
pub mod testing {
    use std::sync::Mutex;

    use super::*;

    /// Recording fake for asserting outbound dispatch shape.
    #[derive(Default)]
    pub struct FakeModerationTransport {
        pub calls: Mutex<Vec<(NodeIdentifier, Bytes)>>,
    }

    impl FakeModerationTransport {
        pub fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        pub fn calls(&self) -> Vec<(NodeIdentifier, Bytes)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ModerationTransport for FakeModerationTransport {
        async fn send_unicast(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
        ) -> Result<(), ApplicationError> {
            self.calls.lock().unwrap().push((dst, body));
            Ok(())
        }
    }

    /// Recording applier for asserting receive-side shape.
    #[derive(Default)]
    pub struct RecordingApplier {
        pub received: Mutex<Vec<(NodeIdentifier, ModerationEnvelope)>>,
    }

    impl RecordingApplier {
        pub fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        pub fn snapshot(&self) -> Vec<(NodeIdentifier, ModerationEnvelope)> {
            self.received.lock().unwrap().clone()
        }

        pub fn len(&self) -> usize {
            self.received.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl ModerationApplier for RecordingApplier {
        async fn apply(&self, from: NodeIdentifier, envelope: ModerationEnvelope) {
            self.received.lock().unwrap().push((from, envelope));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use testing::{FakeModerationTransport, RecordingApplier};

    fn cancel() -> CancellationToken {
        CancellationToken::new()
    }

    #[tokio::test]
    async fn dispatch_user_state_unicasts_to_target_owner() {
        let transport = FakeModerationTransport::new();
        let svc = ModerationService::new_with_transport(transport.clone(), cancel());
        let actor = ClientSessionIdentifier::new(0xABC, 0x12345).unwrap();
        let target = ClientSessionIdentifier::new(0xDEF, 0x67890).unwrap();
        let patch = UserStatePatch {
            channel_id: None,
            mute: Some(true),
            deaf: None,
            suppress: None,
            priority_speaker: None,
            listening_channel_add: vec![],
            listening_channel_remove: vec![],
            expected_from_channel: None,
        };
        svc.dispatch_user_state(None, actor, target, patch.clone())
            .await
            .unwrap();
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        let (dst, body) = &calls[0];
        assert_eq!(*dst, 0xDEF, "should unicast to target's owner node");
        let env = proto::decode_moderation(body).unwrap();
        assert_eq!(env.actor_session, actor.to_u32());
        assert_eq!(env.target_session, target.to_u32());
        match env.command {
            Some(ModerationCommand::UserState(p)) => assert_eq!(p, patch),
            other => panic!("expected UserState, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_user_remove_unicasts_to_target_owner() {
        let transport = FakeModerationTransport::new();
        let svc = ModerationService::new_with_transport(transport.clone(), cancel());
        let actor = ClientSessionIdentifier::new(1, 1).unwrap();
        let target = ClientSessionIdentifier::new(7, 1).unwrap();
        let patch = UserRemovePatch {
            reason: Some("spam".to_string()),
            ban: true,
        };
        svc.dispatch_user_remove(None, actor, target, patch.clone())
            .await
            .unwrap();
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 7);
        let env = proto::decode_moderation(&calls[0].1).unwrap();
        match env.command {
            Some(ModerationCommand::UserRemove(p)) => assert_eq!(p, patch),
            other => panic!("expected UserRemove, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn applier_receives_decoded_envelope() {
        let transport = FakeModerationTransport::new();
        let svc = ModerationService::new_with_transport(transport, cancel());
        let applier = RecordingApplier::new();
        svc.set_applier(applier.clone());

        let env = ModerationEnvelope {
            actor_session: 1,
            target_session: 2,
            issued_at_ms: 0,
            server_id: shitspeak_core::default_server_id(),
            command: Some(ModerationCommand::UserRemove(UserRemovePatch {
                reason: None,
                ban: false,
            })),
        };
        let bytes = proto::encode_moderation(&env).unwrap();
        svc.inbound_handler().handle(OverlayInboundMessage {
            from: 99,
            level: MODERATION_LEVEL,
            class: MODERATION_CLASS,
            body: bytes,
        });

        // Allow the dispatch task to drain.
        for _ in 0..50 {
            if applier.len() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let received = applier.snapshot();
        assert_eq!(received.len(), 1);
        let (from, decoded) = &received[0];
        assert_eq!(*from, 99);
        assert_eq!(decoded, &env);
    }
}
