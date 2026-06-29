//! Cluster-wide replications subsystem.
//!
//! Three replication modes layered atop the L2 overlay:
//!
//! * **Strict (Tempo)** — leader-less, multi-writer total-order broadcast.
//!   Used by repositories that require linearizable writes across the
//!   cluster (channels, bans).
//! * **Owner-scoped** — single-writer (per-node), multi-reader. Each node
//!   "owns" its slot and is the only proposer for it. Used for per-node
//!   transient state (clients).
//! * **Blob** — demand-driven, content-addressed immutable data transfer.
//!   Used by channel description blobs. This mode does not synchronize a
//!   versioned log; it fetches missing content from any peer that has it.
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

pub mod blob;
pub mod config;
pub mod error;
pub mod owner;
pub mod proto;
pub mod strict;
mod topic;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

use std::sync::Arc;

use parking_lot::RwLock;
use scc::HashMap as SccMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{trace, warn};

use crate::overlay::{OverlayInboundMessage, OverlayNetwork, ServiceInbound};
use shitspeak_core::NodeIdentifier;

pub use blob::{BlobHandle, BlobReplicable};
pub use config::{ReplicationConfig, ReplicationTuning};
pub use error::ReplicationError;
pub use owner::{OwnerHandle, OwnerReplicable};
pub use proto::REPLICATION_SERVICE_TAG;
pub use strict::{StrictHandle, StrictReplicable};

use self::blob::{BlobNet, BlobRuntime, OverlayBlobNet};
use self::owner::runtime::{OverlayOwnerNet, OwnerNet, OwnerRuntime};
use self::proto::ReplBody;
use self::strict::runtime::{OverlayStrictNet, StrictNet, StrictRuntime};
use self::topic::{
    ErasedBlobRuntime, ErasedOwnerRuntime, ErasedStrictRuntime, InboundBody, InboundFrame,
};

/// Public entry-point for cluster replications. Cheap to clone — internally
/// an `Arc`.
#[derive(Clone)]
pub struct ReplicationManager {
    inner: Arc<ManagerInner>,
}

#[derive(Clone)]
pub struct StrictTopicRuntimeParts {
    self_id: NodeIdentifier,
    self_epoch: u64,
    net: Arc<dyn StrictNet>,
    shutdown: CancellationToken,
    cfg: Arc<ReplicationConfig>,
}

#[derive(Clone)]
pub struct BlobTopicRuntimeParts {
    self_id: NodeIdentifier,
    net: Arc<dyn BlobNet>,
    shutdown: CancellationToken,
    cfg: Arc<ReplicationConfig>,
}

pub type StrictTopicResolver = Arc<
    dyn Fn(&str, StrictTopicRuntimeParts) -> Option<Arc<dyn ErasedStrictRuntime>> + Send + Sync,
>;
pub type BlobTopicResolver =
    Arc<dyn Fn(&str, BlobTopicRuntimeParts) -> Option<Arc<dyn ErasedBlobRuntime>> + Send + Sync>;

impl StrictTopicRuntimeParts {
    pub fn build_runtime<R: StrictReplicable>(
        &self,
        topic: String,
        repo: Arc<R>,
    ) -> Arc<StrictRuntime<R>> {
        StrictRuntime::new(
            repo,
            self.self_id,
            self.self_epoch,
            topic,
            self.net.clone(),
            self.shutdown.child_token(),
            self.cfg.clone(),
        )
    }
}

impl BlobTopicRuntimeParts {
    pub fn build_runtime<R: BlobReplicable>(
        &self,
        topic: String,
        repo: Arc<R>,
    ) -> Arc<BlobRuntime<R>> {
        BlobRuntime::new(
            repo,
            self.self_id,
            topic,
            self.net.clone(),
            self.shutdown.child_token(),
            self.cfg.clone(),
        )
    }
}

struct ManagerInner {
    overlay: OverlayNetwork,
    self_id: NodeIdentifier,
    self_epoch: u64,
    strict_topics: Arc<SccMap<String, Arc<dyn ErasedStrictRuntime>>>,
    owner_topics: Arc<SccMap<String, Arc<dyn ErasedOwnerRuntime>>>,
    blob_topics: Arc<SccMap<String, Arc<dyn ErasedBlobRuntime>>>,
    _inbox_tx: mpsc::UnboundedSender<InboundFrame>,
    shutdown: CancellationToken,
    strict_net: Arc<dyn StrictNet>,
    owner_net: Arc<dyn OwnerNet>,
    blob_net: Arc<dyn BlobNet>,
    strict_topic_resolver: RwLock<Option<StrictTopicResolver>>,
    blob_topic_resolver: RwLock<Option<BlobTopicResolver>>,
    cfg: Arc<ReplicationConfig>,
}

impl ReplicationManager {
    /// Build a replication manager bound to the supplied overlay with the
    /// default [`ReplicationConfig`]. See [`Self::with_config`] to override
    /// the tunables.
    pub fn new(overlay: OverlayNetwork) -> Arc<Self> {
        Self::with_config(overlay, ReplicationConfig::default())
    }

    /// Build a replication manager bound to the supplied overlay. Spawns
    /// the central inbound dispatch task and the membership-event fan-out
    /// task; registers the L3 service handler.
    pub fn with_config(overlay: OverlayNetwork, cfg: ReplicationConfig) -> Arc<Self> {
        let self_id = overlay.local_node_id();
        let self_epoch = overlay.local_boot_epoch();
        let strict_topics: Arc<SccMap<String, Arc<dyn ErasedStrictRuntime>>> =
            Arc::new(SccMap::new());
        let owner_topics: Arc<SccMap<String, Arc<dyn ErasedOwnerRuntime>>> =
            Arc::new(SccMap::new());
        let blob_topics: Arc<SccMap<String, Arc<dyn ErasedBlobRuntime>>> = Arc::new(SccMap::new());
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();

        let strict_net: Arc<dyn StrictNet> = Arc::new(OverlayStrictNet {
            overlay: overlay.clone(),
        });
        let owner_net: Arc<dyn OwnerNet> = Arc::new(OverlayOwnerNet {
            overlay: overlay.clone(),
        });
        let blob_net: Arc<dyn BlobNet> = Arc::new(OverlayBlobNet {
            overlay: overlay.clone(),
        });

        let cfg = Arc::new(cfg);
        let inner = Arc::new(ManagerInner {
            overlay: overlay.clone(),
            self_id,
            self_epoch,
            strict_topics: strict_topics.clone(),
            owner_topics: owner_topics.clone(),
            blob_topics: blob_topics.clone(),
            _inbox_tx: inbox_tx.clone(),
            shutdown: shutdown.clone(),
            strict_net,
            owner_net,
            blob_net,
            strict_topic_resolver: RwLock::new(None),
            blob_topic_resolver: RwLock::new(None),
            cfg,
        });

        // Register the L3 service handler. The overlay calls `handle`
        // synchronously per the trait contract; we just decode and push.
        let handler = Arc::new(InboundHandler { inbox_tx });
        overlay.register_service(REPLICATION_SERVICE_TAG, handler);

        // Spawn the central dispatch task.
        spawn_dispatch_task(inbox_rx, inner.clone());

        // Spawn the membership-event fan-out task.
        let mut events = overlay.subscribe_membership();
        let strict_for_ev = strict_topics.clone();
        let owner_for_ev = owner_topics.clone();
        let blob_for_ev = blob_topics.clone();
        let shutdown_for_ev = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_for_ev.cancelled() => return,
                    ev = events.recv() => {
                        match ev {
                            Ok(ev) => {
                                strict_for_ev.iter_sync(|_, rt| {
                                    rt.on_membership(&ev);
                                    true
                                });
                                owner_for_ev.iter_sync(|_, rt| {
                                    rt.on_membership(&ev);
                                    true
                                });
                                blob_for_ev.iter_sync(|_, rt| {
                                    rt.on_membership(&ev);
                                    true
                                });
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

    /// Local node boot epoch captured by the overlay at S2S runtime start.
    pub fn local_boot_epoch(&self) -> u64 {
        self.inner.self_epoch
    }

    /// Register a strict (Tempo) topic. Returns the caller-facing handle
    /// used to propose ops.
    pub fn register_strict<R: StrictReplicable>(
        &self,
        topic: impl Into<String>,
        repo: Arc<R>,
    ) -> Result<StrictHandle<R>, ReplicationError> {
        let topic = topic.into();
        if self.inner.strict_topics.contains_sync(&topic)
            || self.inner.owner_topics.contains_sync(&topic)
            || self.inner.blob_topics.contains_sync(&topic)
        {
            return Err(ReplicationError::TopicAlreadyRegistered(topic));
        }
        let runtime = StrictRuntime::new(
            repo,
            self.inner.self_id,
            self.inner.self_epoch,
            topic.clone(),
            self.inner.strict_net.clone(),
            self.inner.shutdown.child_token(),
            self.inner.cfg.clone(),
        );
        runtime.start();
        let erased: Arc<dyn ErasedStrictRuntime> = runtime.clone();
        let _ = self.inner.strict_topics.insert_sync(topic, erased);
        Ok(StrictHandle { runtime })
    }

    pub fn strict_topic_parts(&self) -> StrictTopicRuntimeParts {
        StrictTopicRuntimeParts {
            self_id: self.inner.self_id,
            self_epoch: self.inner.self_epoch,
            net: self.inner.strict_net.clone(),
            shutdown: self.inner.shutdown.clone(),
            cfg: self.inner.cfg.clone(),
        }
    }

    pub fn install_strict_runtime(
        &self,
        topic: String,
        runtime: Arc<dyn ErasedStrictRuntime>,
    ) -> Result<(), ReplicationError> {
        if self.inner.strict_topics.contains_sync(&topic)
            || self.inner.owner_topics.contains_sync(&topic)
            || self.inner.blob_topics.contains_sync(&topic)
        {
            return Err(ReplicationError::TopicAlreadyRegistered(topic));
        }
        let _ = self.inner.strict_topics.insert_sync(topic, runtime);
        Ok(())
    }

    pub fn set_strict_topic_resolver(&self, resolver: Option<StrictTopicResolver>) {
        *self.inner.strict_topic_resolver.write() = resolver;
    }

    /// Register an owner-scoped topic.
    pub fn register_owner<R: OwnerReplicable>(
        &self,
        topic: impl Into<String>,
        repo: Arc<R>,
    ) -> Result<OwnerHandle<R>, ReplicationError> {
        let topic = topic.into();
        if self.inner.strict_topics.contains_sync(&topic)
            || self.inner.owner_topics.contains_sync(&topic)
            || self.inner.blob_topics.contains_sync(&topic)
        {
            return Err(ReplicationError::TopicAlreadyRegistered(topic));
        }
        let runtime = OwnerRuntime::new(
            repo,
            self.inner.self_id,
            self.inner.self_epoch,
            topic.clone(),
            self.inner.owner_net.clone(),
            self.inner.shutdown.child_token(),
            self.inner.cfg.clone(),
        );
        let erased: Arc<dyn ErasedOwnerRuntime> = runtime.clone();
        let _ = self.inner.owner_topics.insert_sync(topic, erased);
        runtime.start();
        Ok(OwnerHandle { runtime })
    }

    /// Register a content-addressed blob topic.
    pub fn register_blob<R: BlobReplicable>(
        &self,
        topic: impl Into<String>,
        repo: Arc<R>,
    ) -> Result<BlobHandle<R>, ReplicationError> {
        let topic = topic.into();
        if self.inner.strict_topics.contains_sync(&topic)
            || self.inner.owner_topics.contains_sync(&topic)
            || self.inner.blob_topics.contains_sync(&topic)
        {
            return Err(ReplicationError::TopicAlreadyRegistered(topic));
        }
        let runtime = BlobRuntime::new(
            repo,
            self.inner.self_id,
            topic.clone(),
            self.inner.blob_net.clone(),
            self.inner.shutdown.child_token(),
            self.inner.cfg.clone(),
        );
        runtime.start();
        let erased: Arc<dyn ErasedBlobRuntime> = runtime.clone();
        let _ = self.inner.blob_topics.insert_sync(topic, erased);
        Ok(BlobHandle { runtime })
    }

    pub fn blob_topic_parts(&self) -> BlobTopicRuntimeParts {
        BlobTopicRuntimeParts {
            self_id: self.inner.self_id,
            net: self.inner.blob_net.clone(),
            shutdown: self.inner.shutdown.clone(),
            cfg: self.inner.cfg.clone(),
        }
    }

    pub fn install_blob_runtime(
        &self,
        topic: String,
        runtime: Arc<dyn ErasedBlobRuntime>,
    ) -> Result<(), ReplicationError> {
        if self.inner.strict_topics.contains_sync(&topic)
            || self.inner.owner_topics.contains_sync(&topic)
            || self.inner.blob_topics.contains_sync(&topic)
        {
            return Err(ReplicationError::TopicAlreadyRegistered(topic));
        }
        let _ = self.inner.blob_topics.insert_sync(topic, runtime);
        Ok(())
    }

    pub fn set_blob_topic_resolver(&self, resolver: Option<BlobTopicResolver>) {
        *self.inner.blob_topic_resolver.write() = resolver;
    }

    /// Cancel all background tasks and unregister the L3 handler.
    pub async fn shutdown(&self) {
        self.inner.shutdown.cancel();
        self.inner.strict_topics.iter_sync(|_, rt| {
            rt.shutdown();
            true
        });
        self.inner.owner_topics.iter_sync(|_, rt| {
            rt.shutdown();
            true
        });
        self.inner.blob_topics.iter_sync(|_, rt| {
            rt.shutdown();
            true
        });
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
        ReplBody::Blob(blob) => InboundBody::Blob(blob.body?),
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
#[cfg(any(test, feature = "test-support"))]
struct FilteredInboundHandler {
    inbox_tx: mpsc::UnboundedSender<InboundFrame>,
    predicate: Arc<dyn Fn(&InboundFrame) -> bool + Send + Sync>,
}

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
impl ReplicationManager {
    /// Replace the registered service handler with one that filters
    /// inbound frames through `predicate` (`true` = forward, `false` = drop).
    /// The predicate sees the post-decode [`InboundFrame`] so callers
    /// don't have to deal with protobuf themselves. Re-registration is
    /// idempotent per `ServiceRegistry`.
    pub fn set_inbound_filter<F>(&self, predicate: F)
    where
        F: Fn(&InboundFrame) -> bool + Send + Sync + 'static,
    {
        let inbox_tx = self.inner._inbox_tx.clone();
        let handler = Arc::new(FilteredInboundHandler {
            inbox_tx,
            predicate: Arc::new(predicate),
        });
        self.inner
            .overlay
            .register_service(REPLICATION_SERVICE_TAG, handler);
    }

    pub fn set_owner_op_inbound_filter<F>(&self, predicate: F)
    where
        F: Fn(NodeIdentifier, u64) -> bool + Send + Sync + 'static,
    {
        self.set_inbound_filter(move |frame| {
            if let InboundBody::Owner(self::proto::OwnerBody::Op(op)) = &frame.body {
                return predicate(op.origin_node as NodeIdentifier, op.origin_version);
            }
            true
        });
    }
}

fn spawn_dispatch_task(mut rx: mpsc::UnboundedReceiver<InboundFrame>, inner: Arc<ManagerInner>) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = inner.shutdown.cancelled() => return,
                next = rx.recv() => {
                    let Some(frame) = next else { return };
                    match frame.body {
                        InboundBody::Strict(b) => {
                            let mut rt = inner.strict_topics
                                .read_sync(&frame.topic, |_, v| v.clone());
                            if rt.is_none() {
                                if let Some(resolver) = inner.strict_topic_resolver.read().clone() {
                                    let parts = StrictTopicRuntimeParts {
                                        self_id: inner.self_id,
                                        self_epoch: inner.self_epoch,
                                        net: inner.strict_net.clone(),
                                        shutdown: inner.shutdown.clone(),
                                        cfg: inner.cfg.clone(),
                                    };
                                    rt = resolver(&frame.topic, parts);
                                    if let Some(rt) = rt.as_ref() {
                                        let _ = inner.strict_topics.insert_sync(frame.topic.clone(), rt.clone());
                                    }
                                }
                            }
                            if let Some(rt) = rt {
                                rt.dispatch(frame.from, b).await;
                            } else {
                                trace!(topic=%frame.topic, "strict frame for unknown topic");
                            }
                        }
                        InboundBody::Owner(b) => {
                            let rt = inner.owner_topics
                                .read_sync(&frame.topic, |_, v| v.clone());
                            if let Some(rt) = rt {
                                rt.dispatch(frame.from, b).await;
                            } else {
                                trace!(topic=%frame.topic, "owner frame for unknown topic");
                            }
                        }
                        InboundBody::Blob(b) => {
                            let mut rt = inner.blob_topics
                                .read_sync(&frame.topic, |_, v| v.clone());
                            if rt.is_none() {
                                if let Some(resolver) = inner.blob_topic_resolver.read().clone() {
                                    let parts = BlobTopicRuntimeParts {
                                        self_id: inner.self_id,
                                        net: inner.blob_net.clone(),
                                        shutdown: inner.shutdown.clone(),
                                        cfg: inner.cfg.clone(),
                                    };
                                    rt = resolver(&frame.topic, parts);
                                    if let Some(rt) = rt.as_ref() {
                                        let _ = inner.blob_topics.insert_sync(frame.topic.clone(), rt.clone());
                                    }
                                }
                            }
                            if let Some(rt) = rt {
                                rt.dispatch(frame.from, b).await;
                            } else {
                                trace!(topic=%frame.topic, "blob frame for unknown topic");
                            }
                        }
                    }
                }
            }
        }
    });
}
