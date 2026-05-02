//! Cluster-wide replications subsystem.
//!
//! Two replication modes layered atop the L2 overlay:
//!
//! * **Strict (Tempo)** — leader-less, multi-writer total-order broadcast.
//!   Used by repositories that require linearizable writes across the
//!   cluster (channels, bans).
//! * **Owner-scoped** — single-writer (per-node), multi-reader. Each node
//!   "owns" its slot and is the only proposer for it. Used for per-node
//!   transient state (clients).
//!
//! See the trait docs on [`StrictReplicable`] and [`OwnerReplicable`] for
//! the load-bearing local-apply ordering rules.
//!
//! ## Lifecycle
//!
//! [`ReplicationManager::new`] registers a single L3 service handler with
//! the overlay under [`REPLICATION_SERVICE_TAG`] (= 1). All inbound
//! `OverlayData` frames with that tag are decoded as
//! [`proto::ReplicationMessage`], routed by topic-string into the
//! per-topic runtime, and dispatched serially on a central task. The
//! central task is a deliberate simplification — per-topic ordering
//! is preserved (FIFO from the mpsc), and cross-topic ordering is not
//! a documented guarantee. If cross-topic isolation becomes a
//! bottleneck, switch to per-topic mpsc + drain task.

pub mod error;
pub mod owner;
pub mod proto;
pub mod strict;
mod topic;

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod integration_tests;

use std::sync::Arc;

use scc::HashMap as SccMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::s2s::overlay::{
    MembershipEvent, OverlayInboundMessage, OverlayNetwork, ServiceInbound,
};
use crate::types::NodeIdentifier;

pub use error::ReplicationError;
pub use owner::{OwnerHandle, OwnerReplicable};
pub use proto::REPLICATION_SERVICE_TAG;
pub use strict::{StrictHandle, StrictReplicable};

use self::owner::runtime::{OverlayOwnerNet, OwnerNet, OwnerRuntime};
use self::proto::{OwnerBody, ReplBody, StrictBody};
use self::strict::runtime::{OverlayStrictNet, StrictNet, StrictRuntime};
use self::topic::{ErasedOwnerRuntime, ErasedStrictRuntime, InboundBody, InboundFrame};

/// Public entry-point for cluster replications. Cheap to clone — internally
/// an `Arc`.
#[derive(Clone)]
pub struct ReplicationManager {
    inner: Arc<ManagerInner>,
}

struct ManagerInner {
    overlay: OverlayNetwork,
    self_id: NodeIdentifier,
    self_epoch: u64,
    strict_topics: Arc<SccMap<String, Arc<dyn ErasedStrictRuntime>>>,
    owner_topics: Arc<SccMap<String, Arc<dyn ErasedOwnerRuntime>>>,
    inbox_tx: mpsc::UnboundedSender<InboundFrame>,
    shutdown: CancellationToken,
    strict_net: Arc<dyn StrictNet>,
    owner_net: Arc<dyn OwnerNet>,
}

impl ReplicationManager {
    /// Build a replication manager bound to the supplied overlay. Spawns
    /// the central inbound dispatch task and the membership-event fan-out
    /// task; registers the L3 service handler.
    pub fn new(overlay: OverlayNetwork) -> Arc<Self> {
        let self_id = overlay.local_node_id();
        let self_epoch = overlay.local_boot_epoch();
        let strict_topics: Arc<SccMap<String, Arc<dyn ErasedStrictRuntime>>> =
            Arc::new(SccMap::new());
        let owner_topics: Arc<SccMap<String, Arc<dyn ErasedOwnerRuntime>>> =
            Arc::new(SccMap::new());
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();

        let strict_net: Arc<dyn StrictNet> = Arc::new(OverlayStrictNet {
            overlay: overlay.clone(),
        });
        let owner_net: Arc<dyn OwnerNet> = Arc::new(OverlayOwnerNet {
            overlay: overlay.clone(),
        });

        let inner = Arc::new(ManagerInner {
            overlay: overlay.clone(),
            self_id,
            self_epoch,
            strict_topics: strict_topics.clone(),
            owner_topics: owner_topics.clone(),
            inbox_tx: inbox_tx.clone(),
            shutdown: shutdown.clone(),
            strict_net,
            owner_net,
        });

        // Register the L3 service handler. The overlay calls `handle`
        // synchronously per the trait contract; we just decode and push.
        let handler = Arc::new(InboundHandler { inbox_tx });
        overlay.register_service(REPLICATION_SERVICE_TAG, handler);

        // Spawn the central dispatch task.
        spawn_dispatch_task(
            inbox_rx,
            strict_topics.clone(),
            owner_topics.clone(),
            shutdown.clone(),
        );

        // Spawn the membership-event fan-out task.
        let mut events = overlay.subscribe_membership();
        let strict_for_ev = strict_topics.clone();
        let owner_for_ev = owner_topics.clone();
        let shutdown_for_ev = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_for_ev.cancelled() => return,
                    ev = events.recv() => {
                        match ev {
                            Ok(ev) => {
                                strict_for_ev.scan(|_, rt| rt.on_membership(&ev));
                                owner_for_ev.scan(|_, rt| rt.on_membership(&ev));
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                warn!(skipped = n, "membership event subscriber lagged");
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                        }
                    }
                }
            }
        });

        Arc::new(Self { inner })
    }

    /// Local node id (mirrors the overlay).
    pub fn local_node_id(&self) -> NodeIdentifier {
        self.inner.self_id
    }

    /// Register a strict (Tempo) topic. Returns the caller-facing handle
    /// used to propose ops.
    pub fn register_strict<R: StrictReplicable>(
        &self,
        topic: impl Into<String>,
        repo: Arc<R>,
    ) -> Result<StrictHandle<R>, ReplicationError> {
        let topic = topic.into();
        if self.inner.strict_topics.contains(&topic) || self.inner.owner_topics.contains(&topic) {
            return Err(ReplicationError::TopicAlreadyRegistered(topic));
        }
        let runtime = StrictRuntime::new(
            repo,
            self.inner.self_id,
            self.inner.self_epoch,
            topic.clone(),
            self.inner.strict_net.clone(),
            self.inner.shutdown.child_token(),
        );
        runtime.start();
        let erased: Arc<dyn ErasedStrictRuntime> = runtime.clone();
        let _ = self.inner.strict_topics.insert(topic, erased);
        Ok(StrictHandle { runtime })
    }

    /// Register an owner-scoped topic.
    pub fn register_owner<R: OwnerReplicable>(
        &self,
        topic: impl Into<String>,
        repo: Arc<R>,
    ) -> Result<OwnerHandle<R>, ReplicationError> {
        let topic = topic.into();
        if self.inner.strict_topics.contains(&topic) || self.inner.owner_topics.contains(&topic) {
            return Err(ReplicationError::TopicAlreadyRegistered(topic));
        }
        let runtime = OwnerRuntime::new(
            repo,
            self.inner.self_id,
            self.inner.self_epoch,
            topic.clone(),
            self.inner.owner_net.clone(),
            self.inner.shutdown.child_token(),
        );
        let erased: Arc<dyn ErasedOwnerRuntime> = runtime.clone();
        let _ = self.inner.owner_topics.insert(topic, erased);
        Ok(OwnerHandle { runtime })
    }

    /// Cancel all background tasks and unregister the L3 handler.
    pub async fn shutdown(&self) {
        self.inner.shutdown.cancel();
        self.inner
            .strict_topics
            .scan(|_, rt| rt.shutdown());
        self.inner.owner_topics.scan(|_, rt| rt.shutdown());
        self.inner
            .overlay
            .unregister_service(REPLICATION_SERVICE_TAG);
    }
}

// ---------- Service inbound adapter ----------

/// Decode an overlay payload into the per-topic `InboundFrame` shape,
/// returning `None` if the bytes don't parse as a `ReplicationMessage`
/// or carry no body. Shared by the production handler and the test-only
/// filtered handler.
fn decode_to_frame(msg: OverlayInboundMessage) -> Option<InboundFrame> {
    let decoded = match proto::decode(&msg.body) {
        Ok(d) => d,
        Err(e) => {
            trace!(error=%e, "replications: decode failed");
            return None;
        }
    };
    let topic = decoded.topic;
    let body = match decoded.body? {
        ReplBody::Strict(strict) => InboundBody::Strict(strict.body?),
        ReplBody::Owner(owner) => InboundBody::Owner(owner.body?),
    };
    Some(InboundFrame {
        from: msg.from,
        topic,
        body,
    })
}

/// `ServiceInbound` impl that decodes the overlay payload and pushes onto
/// the manager's central dispatch mpsc. Per the overlay's trait contract,
/// `handle` returns immediately without awaiting.
struct InboundHandler {
    inbox_tx: mpsc::UnboundedSender<InboundFrame>,
}

impl ServiceInbound for InboundHandler {
    fn handle(&self, msg: OverlayInboundMessage) {
        if let Some(frame) = decode_to_frame(msg) {
            let _ = self.inbox_tx.send(frame);
        }
    }
}

/// Test-only inbound handler that runs each decoded frame through a
/// predicate and forwards iff the predicate returns `true`. Installed
/// via [`ReplicationManager::set_inbound_filter`].
#[cfg(test)]
struct FilteredInboundHandler {
    inbox_tx: mpsc::UnboundedSender<InboundFrame>,
    predicate: Arc<dyn Fn(&InboundFrame) -> bool + Send + Sync>,
}

#[cfg(test)]
impl ServiceInbound for FilteredInboundHandler {
    fn handle(&self, msg: OverlayInboundMessage) {
        let Some(frame) = decode_to_frame(msg) else {
            return;
        };
        if (self.predicate)(&frame) {
            let _ = self.inbox_tx.send(frame);
        }
    }
}

#[cfg(test)]
impl ReplicationManager {
    /// Replace the registered service handler with one that filters
    /// inbound frames through `predicate` (`true` = forward, `false` = drop).
    /// The predicate sees the post-decode [`InboundFrame`] so callers
    /// don't have to deal with protobuf themselves. Re-registration is
    /// idempotent per `ServiceRegistry`.
    pub(crate) fn set_inbound_filter<F>(&self, predicate: F)
    where
        F: Fn(&InboundFrame) -> bool + Send + Sync + 'static,
    {
        let inbox_tx = self.inner.inbox_tx.clone();
        let handler = Arc::new(FilteredInboundHandler {
            inbox_tx,
            predicate: Arc::new(predicate),
        });
        self.inner
            .overlay
            .register_service(REPLICATION_SERVICE_TAG, handler);
    }
}

fn spawn_dispatch_task(
    mut rx: mpsc::UnboundedReceiver<InboundFrame>,
    strict_topics: Arc<SccMap<String, Arc<dyn ErasedStrictRuntime>>>,
    owner_topics: Arc<SccMap<String, Arc<dyn ErasedOwnerRuntime>>>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                next = rx.recv() => {
                    let Some(frame) = next else { return };
                    match frame.body {
                        InboundBody::Strict(b) => {
                            let rt = strict_topics
                                .read(&frame.topic, |_, v| v.clone());
                            if let Some(rt) = rt {
                                rt.dispatch(frame.from, b).await;
                            } else {
                                trace!(topic=%frame.topic, "strict frame for unknown topic");
                            }
                        }
                        InboundBody::Owner(b) => {
                            let rt = owner_topics
                                .read(&frame.topic, |_, v| v.clone());
                            if let Some(rt) = rt {
                                rt.dispatch(frame.from, b).await;
                            } else {
                                trace!(topic=%frame.topic, "owner frame for unknown topic");
                            }
                        }
                    }
                }
            }
        }
    });
}
