//! `ServiceInbound` adapter, central dispatch task, and the caller-facing
//! send API for the UserStats RPC. See [`super`] for the design.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use scc::HashMap as SccMap;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::trace;

use crate::s2s::application::error::ApplicationError;
use crate::s2s::application::proto::{
    self, UserStatsEnvelope, UserStatsKind, UserStatsReply, UserStatsRequest,
    USER_STATS_SERVICE_TAG,
};
use crate::s2s::overlay::{OverlayInboundMessage, OverlayNetwork, ServiceInbound};
use crate::s2s::transport::{MessageClass, ServiceLevel};
use crate::types::NodeIdentifier;

/// UserStats RPC traffic is reliable + low-latency (a moderator UI is
/// waiting on the reply) but not realtime — same level as moderation.
pub const USER_STATS_LEVEL: ServiceLevel = ServiceLevel::ReliableLowLatency;
pub const USER_STATS_CLASS: MessageClass = MessageClass::Regular;

/// Default timeout for a `dispatch_request` to receive a reply. Picked
/// to be longer than typical inter-DC RTT but short enough that a
/// moderator UI doesn't visibly stall on a missing reply.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Decoded inbound envelope along with the immediate sender.
#[derive(Debug, Clone)]
pub struct UserStatsDelivery {
    pub from: NodeIdentifier,
    pub envelope: UserStatsEnvelope,
}

/// Outcome of a [`UserStatsResponder::respond`] call. The owner-side
/// applier returns these instead of building a reply directly so it can
/// signal "target session not found here" without round-tripping a
/// custom error type.
#[derive(Debug, Clone)]
pub struct UserStatsApplyOutcome {
    pub found: bool,
    /// Encoded `MumbleProto.UserStats` body. Empty when `found = false`.
    pub payload: Bytes,
}

/// Send-only abstraction for outbound UserStats envelopes. Production
/// impl wraps [`OverlayNetwork`]; tests inject a recording fake.
#[async_trait]
pub trait UserStatsTransport: Send + Sync + 'static {
    async fn send_unicast(&self, dst: NodeIdentifier, body: Bytes) -> Result<(), ApplicationError>;
}

/// Production [`UserStatsTransport`] impl backed by the overlay.
pub struct OverlayUserStatsTransport {
    pub overlay: OverlayNetwork,
}

#[async_trait]
impl UserStatsTransport for OverlayUserStatsTransport {
    async fn send_unicast(&self, dst: NodeIdentifier, body: Bytes) -> Result<(), ApplicationError> {
        self.overlay
            .send_unicast(
                dst,
                USER_STATS_SERVICE_TAG,
                USER_STATS_LEVEL,
                USER_STATS_CLASS,
                body,
            )
            .await?;
        Ok(())
    }
}

/// Owner-side responder: looks up the target's stats locally and produces
/// the encoded `MumbleProto.UserStats` payload that will be shipped back
/// to the originator. Production impl lives in the `Server` layer.
#[async_trait]
pub trait UserStatsResponder: Send + Sync + 'static {
    async fn respond(
        &self,
        from: NodeIdentifier,
        request: UserStatsRequest,
    ) -> UserStatsApplyOutcome;
}

type ResponderSlot = Arc<RwLock<Option<Arc<dyn UserStatsResponder>>>>;

/// Central handle for the UserStats RPC. Owns the inbound mpsc, the
/// dispatch task, the outbound transport, the swappable responder slot,
/// and the pending-request map used for reply correlation.
pub struct UserStatsService {
    transport: Arc<dyn UserStatsTransport>,
    shutdown: CancellationToken,
    inbox_tx: mpsc::UnboundedSender<UserStatsDelivery>,
    responder: ResponderSlot,
    /// `request_id → oneshot sender for the reply`. Populated by
    /// [`Self::dispatch_request`], drained by the inbound dispatcher
    /// when a matching `Reply` arrives.
    pending: Arc<SccMap<u64, oneshot::Sender<UserStatsReply>>>,
    /// Strictly-monotonic counter feeding `request_id` for outbound
    /// requests. `0` is reserved as "uninitialized" by the proto so we
    /// start from `1`.
    next_request_id: AtomicU64,
}

impl UserStatsService {
    pub fn new(overlay: OverlayNetwork, shutdown: CancellationToken) -> Arc<Self> {
        let transport: Arc<dyn UserStatsTransport> =
            Arc::new(OverlayUserStatsTransport { overlay });
        Self::new_with_transport(transport, shutdown)
    }

    pub fn new_with_transport(
        transport: Arc<dyn UserStatsTransport>,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel::<UserStatsDelivery>();
        let responder: ResponderSlot = Arc::new(RwLock::new(None));
        let pending: Arc<SccMap<u64, oneshot::Sender<UserStatsReply>>> =
            Arc::new(SccMap::default());
        let svc = Arc::new(Self {
            transport: transport.clone(),
            shutdown: shutdown.clone(),
            inbox_tx,
            responder: responder.clone(),
            pending: pending.clone(),
            next_request_id: AtomicU64::new(1),
        });
        spawn_dispatch_task(inbox_rx, shutdown, transport, responder, pending);
        svc
    }

    /// `ServiceInbound` impl that decodes envelope bytes and pushes
    /// onto the central dispatch mpsc.
    pub fn inbound_handler(&self) -> Arc<dyn ServiceInbound> {
        Arc::new(UserStatsInbound {
            inbox_tx: self.inbox_tx.clone(),
        })
    }

    /// Install (or replace) the owner-side responder.
    pub fn set_responder(&self, responder: Arc<dyn UserStatsResponder>) {
        *self.responder.write() = Some(responder);
    }

    pub fn clear_responder(&self) {
        *self.responder.write() = None;
    }

    /// Ship a UserStats request to the owner of `target` and await the
    /// reply with [`DEFAULT_REQUEST_TIMEOUT`]. The owner unicasts a
    /// matching `Reply` back; the inbound dispatcher correlates it with
    /// the parked oneshot via `request_id`.
    pub async fn dispatch_request(
        &self,
        owner: NodeIdentifier,
        actor_session: u32,
        target_session: u32,
        stats_only: bool,
    ) -> Result<UserStatsReply, ApplicationError> {
        self.dispatch_request_with_timeout(
            owner,
            actor_session,
            target_session,
            stats_only,
            DEFAULT_REQUEST_TIMEOUT,
        )
        .await
    }

    pub async fn dispatch_request_with_timeout(
        &self,
        owner: NodeIdentifier,
        actor_session: u32,
        target_session: u32,
        stats_only: bool,
        timeout: Duration,
    ) -> Result<UserStatsReply, ApplicationError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let req = UserStatsRequest {
            request_id,
            actor_session,
            target_session,
            stats_only,
        };
        let env = UserStatsEnvelope {
            kind: Some(UserStatsKind::Request(req)),
        };
        let bytes = proto::encode_user_stats(&env)?;

        let (tx, rx) = oneshot::channel::<UserStatsReply>();
        // Insert before sending: if the reply races us, the dispatcher
        // would otherwise drop it as orphan.
        let _ = self.pending.insert_async(request_id, tx).await;

        // PendingGuard reaps on any path that does not receive a reply.
        let guard = PendingGuard {
            pending: self.pending.clone(),
            request_id,
            armed: true,
        };

        if let Err(e) = self.transport.send_unicast(owner, bytes).await {
            drop(guard); // remove the pending entry; nothing will fulfil it
            return Err(e);
        }

        let recv = tokio::time::timeout(timeout, rx).await;
        match recv {
            Ok(Ok(reply)) => {
                // Reply was delivered; the dispatcher already removed the
                // pending entry. Disarm the guard so it doesn't double-remove.
                let mut guard = guard;
                guard.armed = false;
                Ok(reply)
            }
            Ok(Err(_canceled)) => {
                drop(guard);
                Err(ApplicationError::Unavailable)
            }
            Err(_timed_out) => {
                drop(guard);
                Err(ApplicationError::Timeout)
            }
        }
    }
}

/// RAII helper that removes a pending request entry if the awaiting
/// task gives up before a reply arrives. Without this the map would
/// leak entries every time a request times out or the transport fails.
struct PendingGuard {
    pending: Arc<SccMap<u64, oneshot::Sender<UserStatsReply>>>,
    request_id: u64,
    armed: bool,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if self.armed {
            self.pending.remove(&self.request_id);
        }
    }
}

pub struct UserStatsInbound {
    inbox_tx: mpsc::UnboundedSender<UserStatsDelivery>,
}

impl ServiceInbound for UserStatsInbound {
    fn handle(&self, msg: OverlayInboundMessage) {
        match proto::decode_user_stats(&msg.body) {
            Ok(envelope) => {
                let _ = self.inbox_tx.send(UserStatsDelivery {
                    from: msg.from,
                    envelope,
                });
            }
            Err(e) => {
                trace!(error=%e, from=%msg.from, "user_stats: decode failed");
            }
        }
    }
}

fn spawn_dispatch_task(
    mut rx: mpsc::UnboundedReceiver<UserStatsDelivery>,
    shutdown: CancellationToken,
    transport: Arc<dyn UserStatsTransport>,
    responder: ResponderSlot,
    pending: Arc<SccMap<u64, oneshot::Sender<UserStatsReply>>>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                next = rx.recv() => {
                    let Some(delivery) = next else { return };
                    let UserStatsDelivery { from, envelope } = delivery;
                    let Some(kind) = envelope.kind else {
                        trace!(from=%from, "user_stats: empty envelope; dropping");
                        continue;
                    };
                    match kind {
                        UserStatsKind::Request(req) => {
                            let transport = Arc::clone(&transport);
                            let responder = Arc::clone(&responder);
                            tokio::spawn(async move {
                                handle_request(&transport, &responder, from, req).await;
                            });
                        }
                        UserStatsKind::Reply(reply) => {
                            handle_reply(&pending, from, reply);
                        }
                    }
                }
            }
        }
    });
}

async fn handle_request(
    transport: &Arc<dyn UserStatsTransport>,
    responder_slot: &ResponderSlot,
    from: NodeIdentifier,
    req: UserStatsRequest,
) {
    let responder_now = responder_slot.read().clone();
    let outcome = match responder_now {
        Some(r) => r.respond(from, req.clone()).await,
        None => {
            trace!(
                from = %from,
                target = req.target_session,
                "user_stats: no responder installed; replying not_found",
            );
            UserStatsApplyOutcome {
                found: false,
                payload: Bytes::new(),
            }
        }
    };
    let reply = UserStatsReply {
        request_id: req.request_id,
        found: outcome.found,
        payload: outcome.payload,
    };
    let env = UserStatsEnvelope {
        kind: Some(UserStatsKind::Reply(reply)),
    };
    let bytes = match proto::encode_user_stats(&env) {
        Ok(b) => b,
        Err(e) => {
            trace!(error=%e, request_id=req.request_id, "user_stats: encode reply failed");
            return;
        }
    };
    if let Err(e) = transport.send_unicast(from, bytes).await {
        trace!(error=%e, request_id=req.request_id, dst=%from, "user_stats: reply unicast failed");
    }
}

fn handle_reply(
    pending: &Arc<SccMap<u64, oneshot::Sender<UserStatsReply>>>,
    from: NodeIdentifier,
    reply: UserStatsReply,
) {
    let request_id = reply.request_id;
    let removed = pending.remove(&request_id);
    match removed {
        Some((_, tx)) => {
            // Receiver may have already been dropped if the awaiting
            // task timed out concurrently with a slow reply — that's
            // fine, we just drop the reply.
            let _ = tx.send(reply);
        }
        None => {
            trace!(
                from = %from,
                request_id,
                "user_stats: orphan reply (no pending request); dropping",
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use std::sync::Mutex;

    use super::*;

    /// Recording fake for asserting outbound dispatch shape.
    #[derive(Default)]
    pub struct FakeUserStatsTransport {
        pub calls: Mutex<Vec<(NodeIdentifier, Bytes)>>,
    }

    impl FakeUserStatsTransport {
        pub fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        pub fn calls(&self) -> Vec<(NodeIdentifier, Bytes)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl UserStatsTransport for FakeUserStatsTransport {
        async fn send_unicast(
            &self,
            dst: NodeIdentifier,
            body: Bytes,
        ) -> Result<(), ApplicationError> {
            self.calls.lock().unwrap().push((dst, body));
            Ok(())
        }
    }

    /// A fixed responder that replies with the same payload regardless
    /// of request shape. Records the requests it saw.
    pub struct FixedResponder {
        pub outcome: UserStatsApplyOutcome,
        pub seen: Mutex<Vec<(NodeIdentifier, UserStatsRequest)>>,
    }

    impl FixedResponder {
        pub fn new(outcome: UserStatsApplyOutcome) -> Arc<Self> {
            Arc::new(Self {
                outcome,
                seen: Mutex::new(Vec::new()),
            })
        }

        pub fn snapshot(&self) -> Vec<(NodeIdentifier, UserStatsRequest)> {
            self.seen.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl UserStatsResponder for FixedResponder {
        async fn respond(
            &self,
            from: NodeIdentifier,
            request: UserStatsRequest,
        ) -> UserStatsApplyOutcome {
            self.seen.lock().unwrap().push((from, request));
            self.outcome.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::testing::{FakeUserStatsTransport, FixedResponder};
    use super::*;

    fn cancel() -> CancellationToken {
        CancellationToken::new()
    }

    #[tokio::test]
    async fn dispatch_request_unicasts_to_owner() {
        let transport = FakeUserStatsTransport::new();
        let svc = UserStatsService::new_with_transport(transport.clone(), cancel());
        // No responder installed — we just want to inspect the outbound shape.
        // Use a short timeout because nothing will reply.
        let res = svc
            .dispatch_request_with_timeout(
                42,
                0xABC_12345,
                0xDEF_67890,
                false,
                Duration::from_millis(50),
            )
            .await;
        assert!(matches!(res, Err(ApplicationError::Timeout)));
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 42);
        let env = proto::decode_user_stats(&calls[0].1).unwrap();
        match env.kind.unwrap() {
            UserStatsKind::Request(req) => {
                assert_eq!(req.actor_session, 0xABC_12345);
                assert_eq!(req.target_session, 0xDEF_67890);
                assert!(!req.stats_only);
                assert_eq!(req.request_id, 1);
            }
            other => panic!("expected Request, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_correlates_reply_to_request() {
        // Loopback transport shared between originator (node 11) and owner
        // (node 99): unicasts addressed to either id are routed to that
        // service's inbound handler, simulating the overlay round-trip.
        struct LoopbackTransport {
            originator_inbound: parking_lot::Mutex<Option<Arc<dyn ServiceInbound>>>,
            owner_inbound: parking_lot::Mutex<Option<Arc<dyn ServiceInbound>>>,
        }
        #[async_trait]
        impl UserStatsTransport for LoopbackTransport {
            async fn send_unicast(
                &self,
                dst: NodeIdentifier,
                body: Bytes,
            ) -> Result<(), ApplicationError> {
                let (target, from) = if dst == 99 {
                    (self.owner_inbound.lock().clone(), 11)
                } else {
                    (self.originator_inbound.lock().clone(), 99)
                };
                let target = target.expect("inbound not yet wired");
                target.handle(OverlayInboundMessage {
                    from,
                    level: USER_STATS_LEVEL,
                    class: USER_STATS_CLASS,
                    body,
                });
                Ok(())
            }
        }

        let loopback = Arc::new(LoopbackTransport {
            originator_inbound: parking_lot::Mutex::new(None),
            owner_inbound: parking_lot::Mutex::new(None),
        });

        // Owner: a service that replies via the same loopback so its
        // outbound `Reply` reaches the originator's inbound handler.
        let owner = UserStatsService::new_with_transport(loopback.clone(), cancel());
        let payload = Bytes::from_static(b"encoded-userstats-body");
        let responder = FixedResponder::new(UserStatsApplyOutcome {
            found: true,
            payload: payload.clone(),
        });
        owner.set_responder(responder.clone());
        *loopback.owner_inbound.lock() = Some(owner.inbound_handler());

        let originator = UserStatsService::new_with_transport(loopback.clone(), cancel());
        *loopback.originator_inbound.lock() = Some(originator.inbound_handler());

        let reply = originator
            .dispatch_request_with_timeout(99, 1, 2, true, Duration::from_millis(500))
            .await
            .expect("reply should arrive");
        assert!(reply.found);
        assert_eq!(reply.payload, payload);
        assert_eq!(reply.request_id, 1);

        let seen = responder.snapshot();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, 11);
        assert_eq!(seen[0].1.actor_session, 1);
        assert_eq!(seen[0].1.target_session, 2);
        assert!(seen[0].1.stats_only);
    }

    #[tokio::test]
    async fn missing_responder_returns_not_found_reply() {
        let owner_transport = FakeUserStatsTransport::new();
        let owner = UserStatsService::new_with_transport(owner_transport.clone(), cancel());
        // No responder installed.

        let req = UserStatsRequest {
            request_id: 7,
            actor_session: 1,
            target_session: 2,
            stats_only: false,
        };
        let env = UserStatsEnvelope {
            kind: Some(UserStatsKind::Request(req)),
        };
        let bytes = proto::encode_user_stats(&env).unwrap();
        owner.inbound_handler().handle(OverlayInboundMessage {
            from: 5,
            level: USER_STATS_LEVEL,
            class: USER_STATS_CLASS,
            body: bytes,
        });

        // The dispatch task should produce a reply unicast back to from=5.
        for _ in 0..50 {
            if !owner_transport.calls().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let calls = owner_transport.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 5);
        let env = proto::decode_user_stats(&calls[0].1).unwrap();
        match env.kind.unwrap() {
            UserStatsKind::Reply(r) => {
                assert_eq!(r.request_id, 7);
                assert!(!r.found);
                assert!(r.payload.is_empty());
            }
            other => panic!("expected Reply, got {other:?}"),
        }
    }
}
