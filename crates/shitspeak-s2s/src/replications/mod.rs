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
mod capability;
pub mod channel_topics;
pub mod config;
mod durability;
pub mod error;
pub mod metrics;
pub mod owner;
pub mod proto;
pub(crate) mod protocol;
pub mod strict;
mod topic;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::{Mutex, RwLock};
use scc::HashMap as SccMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{trace, warn};

use crate::overlay::{
    MemberIncarnation, MembershipEvent, OverlayInboundMessage, OverlayNetwork, ServiceInbound,
};
use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::OriginSignature;

pub use blob::{BlobHandle, BlobReplicable};
pub use config::{ReplicationConfig, ReplicationTuning};
pub use error::ReplicationError;
pub use owner::{OwnerHandle, OwnerReplicable};
pub use proto::REPLICATION_SERVICE_TAG;
pub use strict::{StrictHandle, StrictReplicable, StrictSnapshotError};

/// Encode the replication service's entry in the generic opaque LSA
/// capability envelope.
///
/// Callers that construct the overlay before [`ReplicationManager`] exists
/// use this to publish an authoritative initial state. A fully disabled node
/// emits a valid empty envelope, so peers do not mistake it for a legacy LSA.
pub fn encode_replication_upper_layer_capabilities(
    strict_enabled: bool,
    content_enabled: bool,
    owner_enabled: bool,
    strict_participant_protocol_version: u32,
) -> Vec<u8> {
    let strict_participant_protocol_version = if strict_enabled {
        strict_participant_protocol_version
    } else {
        0
    };
    protocol::encode_upper_layer_capabilities(protocol::ReplicationProtocolCapabilities::new(
        strict_enabled,
        content_enabled,
        owner_enabled,
        strict_participant_protocol_version,
    ))
    .expect("built-in replication capabilities fit the bounded envelope")
}

use self::blob::{BlobNet, BlobRuntime, OverlayBlobNet};
use self::capability::StrictParticipantCapability;
use self::durability::{participant_journal_ready, spawn_participant_durability_monitor};
use self::metrics::{ReplicationPipelineKind, ReplicationPipelineStage};
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
    strict_participant_capability: Arc<StrictParticipantCapability>,
    strict_capability_registry: Mutex<StrictCapabilityRegistry>,
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

/// Manager-owned lifecycle state for local strict-v2 advertisement.
///
/// `expected_topics` is the exact coordinated startup set when a caller has
/// declared one. Direct manager users instead begin an implicit pass from
/// their first successfully installed topic. `vetted_topics` contains every
/// successfully installed runtime topic, including valid lazy channel scopes.
/// Every installed topic remains part of future readiness probes so a dynamic
/// repository can withdraw capability but cannot silently re-enable a prior
/// loss.
#[derive(Default)]
struct StrictCapabilityRegistry {
    expected_topics: BTreeSet<String>,
    vetted_topics: BTreeSet<String>,
    reserved_topics: BTreeSet<String>,
    /// An explicit empty manifest is intentional: do not infer a capability
    /// activation pass from a later lazy registration.
    explicit_manifest_declared: bool,
    /// Direct registration is allowed to open exactly one inferred pass. A
    /// capability loss must still require an explicit coordinated rearm.
    implicit_registration_pass_started: bool,
    activation_pending: bool,
    activation_completed: bool,
}

enum StrictCapabilityReadiness {
    AwaitingRegistration,
    Incapable,
    Ready,
}

impl StrictCapabilityRegistry {
    /// Start the optional direct-registration lifecycle after a runtime has
    /// actually been installed. Starting only after finalization means a
    /// failed registration cannot leave an absent topic blocking activation.
    ///
    /// This is intentionally one-shot. Once an inferred pass has observed a
    /// repository capability loss, a later lazy registration cannot rearm the
    /// local LSA; callers must use the explicit coordinated manifest path.
    fn start_implicit_registration_pass(&mut self, topic: &str) -> bool {
        if self.explicit_manifest_declared || self.implicit_registration_pass_started {
            return false;
        }
        self.expected_topics.insert(topic.to_owned());
        self.implicit_registration_pass_started = true;
        self.activation_pending = true;
        self.activation_completed = false;
        true
    }
}

#[cfg(test)]
mod strict_capability_registry_tests {
    use super::StrictCapabilityRegistry;

    #[test]
    fn direct_registration_starts_one_implicit_pass() {
        let mut registry = StrictCapabilityRegistry::default();

        assert!(registry.start_implicit_registration_pass("channels"));
        assert!(registry.expected_topics.contains("channels"));
        assert_eq!(registry.expected_topics.len(), 1);
        assert!(registry.activation_pending);
        assert!(!registry.activation_completed);

        assert!(!registry.start_implicit_registration_pass("bans"));
        assert!(!registry.expected_topics.contains("bans"));
    }

    #[test]
    fn explicit_empty_manifest_disables_implicit_activation() {
        let mut registry = StrictCapabilityRegistry::default();
        registry.explicit_manifest_declared = true;
        registry.activation_pending = true;

        assert!(!registry.start_implicit_registration_pass("channels"));
        assert!(registry.expected_topics.is_empty());
        assert!(registry.activation_pending);
    }

    #[test]
    fn implicit_mode_cannot_rearm_after_a_capability_loss() {
        let mut registry = StrictCapabilityRegistry::default();
        assert!(registry.start_implicit_registration_pass("channels"));

        // Mirrors the `Incapable` transition after a registered runtime fails
        // its v2 probe.
        registry.activation_pending = false;
        registry.activation_completed = false;

        assert!(!registry.start_implicit_registration_pass("bans"));
        assert!(registry.expected_topics.contains("channels"));
        assert!(!registry.expected_topics.contains("bans"));
        assert!(!registry.activation_pending);
        assert!(!registry.activation_completed);
    }
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
        let legacy_services = overlay.legacy_local_replication_services();
        let initial_journal_ready = if legacy_services.strict() {
            match participant_journal_ready(overlay.persistence_dir().as_deref(), self_id) {
                Ok(ready) => ready,
                Err(error) => {
                    warn!(
                        persistence_dir = ?overlay.persistence_dir(),
                        %error,
                        "strict replication durable storage is not ready; advertising v0"
                    );
                    false
                }
            }
        } else {
            false
        };
        let initial_durable_state_ready =
            initial_journal_ready && overlay.local_boot_epoch_durable();
        let publisher_overlay = overlay.clone();
        let strict_participant_capability = StrictParticipantCapability::new(
            legacy_services.strict(),
            initial_durable_state_ready,
            protocol::STRICT_PROTOCOL_VERSION,
            move |participant_version| {
                let replication_capabilities = protocol::ReplicationProtocolCapabilities::new(
                    legacy_services.strict(),
                    legacy_services.content(),
                    legacy_services.owner(),
                    participant_version,
                );
                match publisher_overlay.modify_upper_layer_capabilities(|current| {
                    protocol::merge_upper_layer_capabilities(current, replication_capabilities)
                        .map(Some)
                }) {
                    Ok(_) => {}
                    Err(error) => {
                        warn!(%error, "refusing to replace malformed local upper-layer capabilities");
                    }
                }
                // Deprecated rolling-upgrade fields. New readers ignore
                // transit policy and consume the opaque participant record.
                publisher_overlay
                    .update_legacy_strict_replication_protocol_versions(participant_version, 2);
            },
        );
        strict_participant_capability.publish_current();
        let strict_topics: Arc<SccMap<String, Arc<dyn ErasedStrictRuntime>>> =
            Arc::new(SccMap::new());
        let owner_topics: Arc<SccMap<String, Arc<dyn ErasedOwnerRuntime>>> =
            Arc::new(SccMap::new());
        let blob_topics: Arc<SccMap<String, Arc<dyn ErasedBlobRuntime>>> = Arc::new(SccMap::new());
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();

        let strict_net: Arc<dyn StrictNet> = Arc::new(OverlayStrictNet::new(
            overlay.clone(),
            strict_participant_capability.clone(),
        ));
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
            strict_participant_capability: strict_participant_capability.clone(),
            strict_capability_registry: Mutex::new(StrictCapabilityRegistry::default()),
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

        if legacy_services.strict() {
            spawn_participant_durability_monitor(
                overlay.clone(),
                strict_participant_capability,
                shutdown.clone(),
                initial_journal_ready,
            );
        }

        // Register the L3 service handler. The overlay calls `handle`
        // synchronously per the trait contract; we just decode and push.
        let handler = Arc::new(InboundHandler {
            inbox_tx,
            overlay: overlay.clone(),
        });
        overlay.register_service(REPLICATION_SERVICE_TAG, handler);

        // Spawn the central dispatch task.
        spawn_dispatch_task(inbox_rx, inner.clone());

        // Spawn the membership-event fan-out task.
        let mut events = overlay.subscribe_membership();
        let mut membership_view = current_membership_view(&overlay);
        let overlay_for_ev = overlay.clone();
        let strict_for_ev = strict_topics.clone();
        let owner_for_ev = owner_topics.clone();
        let blob_for_ev = blob_topics.clone();
        let shutdown_for_ev = shutdown;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_for_ev.cancelled() => return,
                    ev = events.recv() => {
                        if !handle_membership_result(
                            ev,
                            &mut membership_view,
                            &strict_for_ev,
                            &owner_for_ev,
                            &blob_for_ev,
                            || current_membership_view(&overlay_for_ev),
                        ) {
                            return;
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

    /// Effective strict participant protocol floor observed by this manager.
    /// Nonparticipants never enter this calculation.
    pub fn strict_protocol_version(&self) -> u32 {
        self.inner.strict_net.strict_replication_protocol_version()
    }

    /// Register a strict (Tempo) topic. Returns the caller-facing handle
    /// used to propose ops.
    ///
    /// When no explicit expected-topic manifest was declared, the first
    /// successfully installed topic automatically opens an inferred strict-v2
    /// capability pass. Call [`Self::set_expected_strict_topics`] when the
    /// application knows a complete startup set and requires that whole set to
    /// be verified before the local LSA can advertise v2.
    pub fn register_strict<R: StrictReplicable>(
        &self,
        topic: impl Into<String>,
        repo: Arc<R>,
    ) -> Result<StrictHandle<R>, ReplicationError> {
        let topic = topic.into();
        self.inner.reserve_strict_topic(&topic)?;
        let runtime = StrictRuntime::new(
            repo,
            self.inner.self_id,
            self.inner.self_epoch,
            topic.clone(),
            self.inner.strict_net.clone(),
            self.inner.shutdown.child_token(),
            self.inner.cfg.clone(),
        );
        runtime
            .seed_membership_snapshot(current_membership_view(&self.inner.overlay).into_values());
        runtime.start();
        let erased: Arc<dyn ErasedStrictRuntime> = runtime.clone();
        if let Err(error) = self
            .inner
            .finalize_reserved_strict_runtime(topic.clone(), erased)
        {
            runtime.shutdown();
            self.inner.release_strict_topic_reservation(&topic);
            return Err(error);
        }
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

    /// Declare the complete coordinated strict-topic set before its
    /// repositories begin registration.
    ///
    /// The manager derives the advertised protocol capability from the
    /// concrete runtimes; callers never supply a parallel version vector.
    /// Replacing this set is the explicit coordinated lifecycle action that
    /// may rearm a prior repository-capability loss.
    pub fn set_expected_strict_topics<I, T>(&self, topics: I) -> bool
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.inner.set_expected_strict_topics(topics)
    }

    /// Re-evaluate the manager-owned strict capability registry.
    ///
    /// Normal registration paths invoke this automatically. Once a
    /// repository loss has withdrawn v2, this method remains fail-closed;
    /// only [`Self::set_expected_strict_topics`] opens a new coordinated
    /// re-registration pass.
    pub fn refresh_strict_capability_activation(&self) -> bool {
        self.inner.refresh_strict_capability_activation()
    }

    /// Whether the local manager currently has an activated strict-v2
    /// registry and the overlay is advertising the current protocol.
    pub fn strict_capability_activation_ready(&self) -> bool {
        self.inner.strict_capability_activation_ready()
    }

    pub fn install_strict_runtime(
        &self,
        topic: String,
        runtime: Arc<dyn ErasedStrictRuntime>,
    ) -> Result<(), ReplicationError> {
        self.inner.install_strict_runtime(topic, runtime)
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

impl ManagerInner {
    fn set_expected_strict_topics<I, T>(&self, topics: I) -> bool
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let expected_topics = topics
            .into_iter()
            .map(Into::into)
            .filter(|topic: &String| !topic.is_empty())
            .collect();
        let mut registry = self.strict_capability_registry.lock();
        registry.explicit_manifest_declared = true;
        registry.expected_topics = expected_topics;
        // Include any runtime installed before a coordinator declared its
        // manifest. This keeps an existing lazy topic from being forgotten
        // by a later explicit re-registration pass.
        self.strict_topics.iter_sync(|topic, _| {
            registry.vetted_topics.insert(topic.clone());
            true
        });
        registry.activation_pending = true;
        registry.activation_completed = false;
        self.strict_participant_capability
            .begin_repository_registration();
        self.refresh_strict_capability_activation_locked(&mut registry)
    }

    fn reserve_strict_topic(&self, topic: &str) -> Result<(), ReplicationError> {
        let mut registry = self.strict_capability_registry.lock();
        if self.strict_topics.contains_sync(topic)
            || self.owner_topics.contains_sync(topic)
            || self.blob_topics.contains_sync(topic)
            || registry.reserved_topics.contains(topic)
        {
            return Err(ReplicationError::TopicAlreadyRegistered(topic.to_owned()));
        }
        registry.reserved_topics.insert(topic.to_owned());
        Ok(())
    }

    fn release_strict_topic_reservation(&self, topic: &str) {
        self.strict_capability_registry
            .lock()
            .reserved_topics
            .remove(topic);
    }

    fn finalize_reserved_strict_runtime(
        &self,
        topic: String,
        runtime: Arc<dyn ErasedStrictRuntime>,
    ) -> Result<(), ReplicationError> {
        let mut registry = self.strict_capability_registry.lock();
        if !registry.reserved_topics.remove(&topic)
            || self.strict_topics.contains_sync(&topic)
            || self.owner_topics.contains_sync(&topic)
            || self.blob_topics.contains_sync(&topic)
        {
            return Err(ReplicationError::TopicAlreadyRegistered(topic));
        }
        if self
            .strict_topics
            .insert_sync(topic.clone(), runtime)
            .is_err()
        {
            return Err(ReplicationError::TopicAlreadyRegistered(topic));
        }
        registry.vetted_topics.insert(topic.clone());
        if registry.start_implicit_registration_pass(&topic) {
            self.strict_participant_capability
                .begin_repository_registration();
        }
        let _ = self.refresh_strict_capability_activation_locked(&mut registry);
        Ok(())
    }

    fn install_strict_runtime(
        &self,
        topic: String,
        runtime: Arc<dyn ErasedStrictRuntime>,
    ) -> Result<(), ReplicationError> {
        self.reserve_strict_topic(&topic)?;
        if let Err(error) = self.finalize_reserved_strict_runtime(topic.clone(), runtime) {
            self.release_strict_topic_reservation(&topic);
            return Err(error);
        }
        Ok(())
    }

    fn refresh_strict_capability_activation(&self) -> bool {
        let mut registry = self.strict_capability_registry.lock();
        self.refresh_strict_capability_activation_locked(&mut registry)
    }

    fn strict_capability_activation_ready(&self) -> bool {
        let registry = self.strict_capability_registry.lock();
        self.strict_capability_activation_ready_locked(&registry)
    }

    fn strict_capability_activation_ready_locked(
        &self,
        registry: &StrictCapabilityRegistry,
    ) -> bool {
        registry.activation_completed
            && self.strict_participant_capability.protocol_version()
                >= protocol::STRICT_PROTOCOL_VERSION
    }

    fn refresh_strict_capability_activation_locked(
        &self,
        registry: &mut StrictCapabilityRegistry,
    ) -> bool {
        match self.strict_capability_readiness(registry) {
            StrictCapabilityReadiness::AwaitingRegistration => {
                if registry.activation_pending {
                    self.strict_participant_capability
                        .update_repository_registration_ready(false);
                }
                false
            }
            StrictCapabilityReadiness::Incapable => {
                // A registered runtime or its authenticated frame path cannot
                // uphold v2. This revokes the current activation pass; only a
                // later `set_expected_strict_topics` lifecycle setup may
                // rearm it.
                registry.activation_pending = false;
                registry.activation_completed = false;
                self.strict_participant_capability
                    .report_repository_capability_loss();
                false
            }
            StrictCapabilityReadiness::Ready if registry.activation_pending => {
                let accepted = self
                    .strict_participant_capability
                    .update_repository_registration_ready(true);
                registry.activation_pending = false;
                registry.activation_completed = accepted;
                self.strict_capability_activation_ready_locked(registry)
            }
            StrictCapabilityReadiness::Ready => {
                self.strict_capability_activation_ready_locked(registry)
            }
        }
    }

    fn strict_capability_readiness(
        &self,
        registry: &StrictCapabilityRegistry,
    ) -> StrictCapabilityReadiness {
        if registry.expected_topics.is_empty() {
            return StrictCapabilityReadiness::AwaitingRegistration;
        }
        let mut topics = registry.expected_topics.clone();
        topics.extend(registry.vetted_topics.iter().cloned());
        let strict_max_catchup_bytes = self.cfg.strict_max_catchup_bytes();
        for topic in topics {
            let Some(runtime) = self
                .strict_topics
                .read_sync(&topic, |_, runtime| runtime.clone())
            else {
                return StrictCapabilityReadiness::AwaitingRegistration;
            };
            if !runtime.strict_v2_advertisement_prerequisites_ready()
                || !self
                    .strict_net
                    .current_protocol_prerequisites_ready(&topic, strict_max_catchup_bytes)
            {
                return StrictCapabilityReadiness::Incapable;
            }
        }
        StrictCapabilityReadiness::Ready
    }
}

fn current_membership_view(overlay: &OverlayNetwork) -> HashMap<NodeIdentifier, MemberIncarnation> {
    overlay
        .members()
        .into_iter()
        .filter(|member| member.status().is_reachable())
        .map(|member| (member.node_id(), member.member_incarnation()))
        .collect()
}

fn update_membership_view(
    view: &mut HashMap<NodeIdentifier, MemberIncarnation>,
    event: &MembershipEvent,
) {
    match event {
        MembershipEvent::Joined(member) | MembershipEvent::Restarted(member) => {
            let should_apply = view
                .get(&member.node_id())
                .is_none_or(|current| member.incarnation() > current.incarnation());
            if should_apply {
                view.insert(member.node_id(), *member);
            }
        }
        MembershipEvent::Left(member) | MembershipEvent::Failed(member) => {
            let is_current = view
                .get(&member.node_id())
                .is_some_and(|current| current.incarnation() == member.incarnation());
            if is_current {
                view.remove(&member.node_id());
            }
        }
    }
}

fn reconcile_membership_views(
    previous: &HashMap<NodeIdentifier, MemberIncarnation>,
    current: &HashMap<NodeIdentifier, MemberIncarnation>,
) -> Vec<MembershipEvent> {
    let mut nodes: Vec<_> = previous.keys().chain(current.keys()).copied().collect();
    nodes.sort_unstable();
    nodes.dedup();
    nodes
        .into_iter()
        .filter_map(|node| match (previous.get(&node), current.get(&node)) {
            (Some(old), None) => Some(MembershipEvent::Failed(*old)),
            (None, Some(new)) => Some(MembershipEvent::Joined(*new)),
            (Some(old), Some(new)) if old.incarnation() != new.incarnation() => {
                Some(MembershipEvent::Restarted(*new))
            }
            _ => None,
        })
        .collect()
}

fn fan_out_membership_event(
    event: &MembershipEvent,
    strict_topics: &SccMap<String, Arc<dyn ErasedStrictRuntime>>,
    owner_topics: &SccMap<String, Arc<dyn ErasedOwnerRuntime>>,
    blob_topics: &SccMap<String, Arc<dyn ErasedBlobRuntime>>,
) {
    strict_topics.iter_sync(|_, runtime| {
        runtime.on_membership(event);
        true
    });
    owner_topics.iter_sync(|_, runtime| {
        runtime.on_membership(event);
        true
    });
    blob_topics.iter_sync(|_, runtime| {
        runtime.on_membership(event);
        true
    });
}

fn handle_membership_result(
    result: Result<MembershipEvent, tokio::sync::broadcast::error::RecvError>,
    membership_view: &mut HashMap<NodeIdentifier, MemberIncarnation>,
    strict_topics: &SccMap<String, Arc<dyn ErasedStrictRuntime>>,
    owner_topics: &SccMap<String, Arc<dyn ErasedOwnerRuntime>>,
    blob_topics: &SccMap<String, Arc<dyn ErasedBlobRuntime>>,
    current_view: impl FnOnce() -> HashMap<NodeIdentifier, MemberIncarnation>,
) -> bool {
    match result {
        Ok(event) => {
            fan_out_membership_event(&event, strict_topics, owner_topics, blob_topics);
            update_membership_view(membership_view, &event);
            true
        }
        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
            warn!(skipped, "membership event subscriber lagged");
            let current = current_view();
            for event in reconcile_membership_views(membership_view, &current) {
                fan_out_membership_event(&event, strict_topics, owner_topics, blob_topics);
            }
            *membership_view = current;
            true
        }
        Err(tokio::sync::broadcast::error::RecvError::Closed) => false,
    }
}

#[cfg(test)]
mod membership_reconciliation_tests {
    use super::*;
    use crate::replications::config::ReplicationConfig;
    use crate::replications::proto::StrictBody;
    use crate::replications::strict::runtime::{StrictNet, StrictRuntime};
    use crate::replications::test_support::{CapturedFrame, CountingStrictRepo, MockNet};
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn lag_reconciliation_recovers_restart_join_and_failure() {
        let previous = HashMap::from([
            (2, MemberIncarnation::new(2, 7)),
            (3, MemberIncarnation::new(3, 4)),
        ]);
        let current = HashMap::from([
            (2, MemberIncarnation::new(2, 8)),
            (4, MemberIncarnation::new(4, 1)),
        ]);

        let events = reconcile_membership_views(&previous, &current);

        assert_eq!(events.len(), 3);
        assert!(matches!(
            &events[0],
            MembershipEvent::Restarted(member)
                if member.node_id() == 2 && member.incarnation() == 8
        ));
        assert!(matches!(
            &events[1],
            MembershipEvent::Failed(member)
                if member.node_id() == 3 && member.incarnation() == 4
        ));
        assert!(matches!(
            &events[2],
            MembershipEvent::Joined(member)
                if member.node_id() == 4 && member.incarnation() == 1
        ));
    }

    #[test]
    fn membership_view_ignores_stale_and_duplicate_incarnation_events() {
        let current = MemberIncarnation::new(2, 8);
        let mut view = HashMap::from([(2, current)]);

        update_membership_view(
            &mut view,
            &MembershipEvent::Restarted(MemberIncarnation::new(2, 7)),
        );
        update_membership_view(&mut view, &MembershipEvent::Restarted(current));
        update_membership_view(
            &mut view,
            &MembershipEvent::Failed(MemberIncarnation::new(2, 7)),
        );

        assert_eq!(view.get(&2), Some(&current));

        update_membership_view(&mut view, &MembershipEvent::Failed(current));
        assert!(!view.contains_key(&2));
    }

    #[tokio::test]
    async fn lagged_manager_subscriber_reconciles_restart_into_strict_runtime() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_strict_replication_protocol_version(
            crate::overlay::STRICT_REPLICATION_PROTOCOL_VERSION,
        );
        net.set_epoch(2, 8);
        let runtime = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            42,
            "lag-reconcile".to_owned(),
            net.clone() as Arc<dyn StrictNet>,
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let strict_topics: SccMap<String, Arc<dyn ErasedStrictRuntime>> = SccMap::new();
        let owner_topics: SccMap<String, Arc<dyn ErasedOwnerRuntime>> = SccMap::new();
        let blob_topics: SccMap<String, Arc<dyn ErasedBlobRuntime>> = SccMap::new();
        assert!(
            strict_topics
                .insert_sync("lag-reconcile".to_owned(), runtime)
                .is_ok()
        );

        let (events, mut subscriber) = tokio::sync::broadcast::channel(1);
        let mut membership_view = HashMap::from([(2, MemberIncarnation::new(2, 7))]);
        events
            .send(MembershipEvent::Joined(MemberIncarnation::new(3, 1)))
            .expect("subscriber is active");
        events
            .send(MembershipEvent::Failed(MemberIncarnation::new(3, 1)))
            .expect("subscriber is active");

        let result = subscriber.recv().await;
        assert!(matches!(
            result,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(1))
        ));
        assert!(handle_membership_result(
            result,
            &mut membership_view,
            &strict_topics,
            &owner_topics,
            &blob_topics,
            || HashMap::from([(2, MemberIncarnation::new(2, 8))]),
        ));

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if net.captures().iter().any(|frame| {
                    matches!(
                        frame,
                        CapturedFrame::StrictUnicast {
                            dst: 2,
                            body: StrictBody::CatchupReq(request),
                            ..
                        } if request.history_probe_only
                    )
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reconciled restart should start strict history election");

        assert_eq!(
            membership_view.get(&2).map(MemberIncarnation::incarnation),
            Some(8)
        );
    }
}

// ---------- Service inbound adapter ----------

/// Decode an overlay payload into the per-topic `InboundFrame` shape,
/// returning `None` if the bytes don't parse as a `ReplicationMessage`
/// or carry no body. Strict frames additionally require a verified detached
/// origin proof before entering the manager inbox. Shared by the production
/// handler and the test-only filtered handler.
fn decode_to_frame(
    msg: OverlayInboundMessage,
    overlay: Option<&OverlayNetwork>,
) -> Option<InboundFrame> {
    let decode_started_at = Instant::now();
    if !proto::strict_origin_auth_wire_within_bounds(&msg.body) {
        trace!("strict origin proof wire representation exceeds its bound");
        return None;
    }
    let decoded = match proto::decode(&msg.body) {
        Ok(d) => d,
        Err(e) => {
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Unknown,
                ReplicationPipelineStage::InboundDecode,
                decode_started_at.elapsed(),
            );
            trace!(error=%e, "replications: decode failed");
            return None;
        }
    };
    let topic = decoded.topic;
    let (body, origin_authenticated) = match decoded.body? {
        ReplBody::Strict(strict) => {
            let body = strict.body?;
            let origin_authenticated = match strict.origin_auth {
                Some(auth) => {
                    if !proto::strict_origin_auth_within_bounds(&auth) {
                        trace!("strict origin proof exceeds the v2 wire bound");
                        return None;
                    }
                    let origin_node = match NodeIdentifier::try_from(auth.origin_node) {
                        Ok(node) => node,
                        Err(_) => {
                            trace!(
                                origin_node = auth.origin_node,
                                "strict origin proof has invalid node"
                            );
                            return None;
                        }
                    };
                    if origin_node != msg.from || auth.origin_boot_epoch != msg.origin_boot_epoch {
                        trace!(
                            claimed_node = origin_node,
                            envelope_node = msg.from,
                            claimed_epoch = auth.origin_boot_epoch,
                            envelope_epoch = msg.origin_boot_epoch,
                            "strict origin proof does not match overlay envelope"
                        );
                        return None;
                    }
                    let signature_scheme = match u16::try_from(auth.signature_scheme) {
                        Ok(scheme) => scheme,
                        Err(_) => {
                            trace!(
                                signature_scheme = auth.signature_scheme,
                                "strict origin proof has invalid signature scheme"
                            );
                            return None;
                        }
                    };
                    let signing_payload = match proto::strict_origin_signing_payload(
                        &topic,
                        &body,
                        auth.origin_node,
                        auth.origin_boot_epoch,
                    ) {
                        Ok(payload) => payload,
                        Err(error) => {
                            trace!(%error, "strict origin proof payload encode failed");
                            return None;
                        }
                    };
                    let proof = OriginSignature::from_parts(
                        signature_scheme,
                        auth.certificate_chain
                            .into_iter()
                            .map(|certificate| certificate.to_vec())
                            .collect(),
                        auth.signature.to_vec(),
                    );
                    let Some(overlay) = overlay else {
                        trace!(
                            "strict origin proof cannot be verified without an overlay identity"
                        );
                        return None;
                    };
                    if let Err(error) =
                        overlay.verify_origin_payload(origin_node, &proof, &signing_payload)
                    {
                        trace!(%error, from = msg.from, "strict origin proof verification failed");
                        return None;
                    }
                    true
                }
                None => {
                    // Keep legacy wire data decodable at the protobuf layer,
                    // but do not enqueue an unauthenticated strict operation.
                    // The inbox is unbounded and strict handlers can mutate
                    // durable state, so admission must fail closed here.
                    trace!("strict frame is missing an origin proof");
                    return None;
                }
            };
            (InboundBody::Strict(body), origin_authenticated)
        }
        ReplBody::Owner(owner) => (InboundBody::Owner(owner.body?), false),
        ReplBody::Blob(blob) => (InboundBody::Blob(blob.body?), false),
    };
    metrics::record_pipeline_stage(
        inbound_pipeline_kind(&body),
        ReplicationPipelineStage::InboundDecode,
        decode_started_at.elapsed(),
    );
    Some(InboundFrame {
        from: msg.from,
        origin_boot_epoch: msg.origin_boot_epoch,
        origin_authenticated,
        topic,
        body,
    })
}

fn inbound_pipeline_kind(body: &InboundBody) -> ReplicationPipelineKind {
    match body {
        InboundBody::Strict(_) => ReplicationPipelineKind::Strict,
        InboundBody::Owner(_) => ReplicationPipelineKind::Owner,
        InboundBody::Blob(_) => ReplicationPipelineKind::Blob,
    }
}

/// `ServiceInbound` impl that decodes the overlay payload and pushes onto
/// the manager's central dispatch mpsc. Per the overlay's trait contract,
/// `handle` returns immediately without awaiting.
struct InboundHandler {
    inbox_tx: mpsc::UnboundedSender<InboundFrame>,
    overlay: OverlayNetwork,
}

impl ServiceInbound for InboundHandler {
    fn handle(&self, msg: OverlayInboundMessage) {
        if let Some(frame) = decode_to_frame(msg, Some(&self.overlay)) {
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
    overlay: OverlayNetwork,
    predicate: Arc<dyn Fn(&InboundFrame) -> bool + Send + Sync>,
}

#[cfg(any(test, feature = "test-support"))]
impl ServiceInbound for FilteredInboundHandler {
    fn handle(&self, msg: OverlayInboundMessage) {
        let Some(frame) = decode_to_frame(msg, Some(&self.overlay)) else {
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
            overlay: self.inner.overlay.clone(),
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
                    let kind = inbound_pipeline_kind(&frame.body);
                    let dispatch_started_at = Instant::now();
                    match frame.body {
                        InboundBody::Strict(b) => {
                            let mut rt = inner.strict_topics
                                .read_sync(&frame.topic, |_, v| v.clone());
                            if rt.is_none() {
                                if let Some(resolver) = inner.strict_topic_resolver.read().clone() {
                                    if inner.reserve_strict_topic(&frame.topic).is_ok() {
                                        let parts = StrictTopicRuntimeParts {
                                            self_id: inner.self_id,
                                            self_epoch: inner.self_epoch,
                                            net: inner.strict_net.clone(),
                                            shutdown: inner.shutdown.clone(),
                                            cfg: inner.cfg.clone(),
                                        };
                                        rt = resolver(&frame.topic, parts);
                                        if let Some(resolved) = rt.as_ref() {
                                            if inner
                                                .finalize_reserved_strict_runtime(
                                                    frame.topic.clone(),
                                                    resolved.clone(),
                                                )
                                                .is_err()
                                            {
                                                resolved.shutdown();
                                                inner.release_strict_topic_reservation(&frame.topic);
                                                rt = inner
                                                    .strict_topics
                                                    .read_sync(&frame.topic, |_, runtime| runtime.clone());
                                            }
                                        } else {
                                            inner.release_strict_topic_reservation(&frame.topic);
                                        }
                                    } else {
                                        // A concurrent explicit registration
                                        // already owns the topic reservation.
                                        // Use its runtime if it has completed
                                        // admission instead of constructing a
                                        // second side-effecting runtime.
                                        if rt.is_none() {
                                            rt = inner
                                                .strict_topics
                                                .read_sync(&frame.topic, |_, runtime| runtime.clone());
                                        }
                                    }
                                }
                            }
                            if let Some(rt) = rt {
                                rt.dispatch(
                                    frame.from,
                                    frame.origin_boot_epoch,
                                    frame.origin_authenticated,
                                    b,
                                )
                                .await;
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
                    metrics::record_pipeline_stage(
                        kind,
                        ReplicationPipelineStage::Dispatch,
                        dispatch_started_at.elapsed(),
                    );
                }
            }
        }
    });
}

#[cfg(test)]
mod inbound_frame_tests {
    use shitspeak_s2s_transport::{MessageClass, ServiceLevel};

    use super::*;
    use crate::replications::proto::{self, StrictBody};

    #[test]
    fn decode_rejects_a_proofless_strict_frame_before_the_inbox() {
        let body = proto::encode(&proto::wrap_strict(
            "strict-topic",
            StrictBody::ClockTick(Default::default()),
        ))
        .expect("strict frame should encode");
        assert!(
            decode_to_frame(
                OverlayInboundMessage {
                    from: 7,
                    origin_boot_epoch: 41,
                    level: ServiceLevel::Reliable,
                    class: MessageClass::Regular,
                    body,
                    remote_playout_delay_ms: None,
                    is_distribution_repair: false,
                },
                None,
            )
            .is_none()
        );
    }

    #[test]
    fn decode_rejects_a_strict_proof_that_disagrees_with_the_envelope() {
        let body = proto::encode(&proto::wrap_strict_with_origin_auth(
            "strict-topic",
            StrictBody::ClockTick(Default::default()),
            proto::StrictOriginAuth {
                origin_node: 8,
                origin_boot_epoch: 41,
                signature_scheme: 0x0807,
                certificate_chain: vec![bytes::Bytes::from_static(&[1])],
                signature: bytes::Bytes::from_static(&[2]),
            },
        ))
        .expect("strict frame should encode");

        assert!(
            decode_to_frame(
                OverlayInboundMessage {
                    from: 7,
                    origin_boot_epoch: 41,
                    level: ServiceLevel::Reliable,
                    class: MessageClass::Regular,
                    body,
                    remote_playout_delay_ms: None,
                    is_distribution_repair: false,
                },
                None,
            )
            .is_none()
        );
    }
}
