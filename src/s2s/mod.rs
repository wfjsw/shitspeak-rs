pub mod application;
pub mod overlay;
pub mod replications;
pub mod transport;

#[cfg(test)]
pub(crate) mod testing;

use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tracing::{info, trace, warn};

use crate::ban_repository::{BanEntry, BanOp, BanOperation, BanRepository};
use crate::blob_store::ChannelBlobStore;
use crate::channel_repository::{ChannelOp, ChannelOperation, ChannelRepository};
use crate::client::client_session_identifier::ClientSessionIdentifier;
use crate::client::state_log::ClientStateLogEntry;
use crate::client_repository::ClientRepository;
use crate::server::Server;
use crate::types::{NodeIdentifier, DEFAULT_SERVER_ID};

use self::application::moderation::ModerationApplier;
use self::application::plugin_data::ServerPluginDataSink;
use self::application::proto::{
    ModerationCommand, ModerationEnvelope, UserRemovePatch, UserStatePatch, VoiceFrame,
};
use self::application::voice::{AudioSink, RecipientIndex};
use self::overlay::OverlayNetwork;
use self::replications::{BlobReplicable, OwnerReplicable, ReplicationManager, StrictReplicable};
use self::transport::{ConnectionManager, TransportConfig};

pub struct S2SManager {
    enabled: bool,
    config_error: Option<String>,
    transport_config: Option<TransportConfig>,
    overlay_config: overlay::OverlayConfig,
    application_config: application::ApplicationConfig,
    transport_tuning: transport::TransportTuning,
    overlay_tuning: overlay::OverlayTuning,
    replication_config: replications::ReplicationConfig,
    max_users: Arc<AtomicU64>,
    state: RwLock<S2SRuntimeState>,
}

#[derive(Default)]
struct S2SRuntimeState {
    transport: Option<ConnectionManager>,
    overlay: Option<OverlayNetwork>,
    replications: Option<Arc<ReplicationManager>>,
    application: Option<Arc<application::ApplicationLayer>>,
    recipient_index: Option<Arc<RecipientIndex>>,
    server: Option<Weak<Box<Server>>>,
    channel_replications: HashMap<String, replications::StrictHandle<ChannelReplicationAdapter>>,
    ban_replication: Option<replications::StrictHandle<BanReplicationAdapter>>,
    client_replication: Option<replications::OwnerHandle<ClientReplicationAdapter>>,
    channel_blob_replications:
        HashMap<String, replications::BlobHandle<ChannelBlobReplicationAdapter>>,
    bridge_tasks: Vec<JoinHandle<()>>,
}

impl S2SManager {
    pub fn initialize(config: &crate::config::Config) -> Self {
        let (transport_config, config_error) = match config.s2s.transport_config() {
            Ok(cfg) => (cfg, None),
            Err(e) => (None, Some(e)),
        };

        Self {
            enabled: config.s2s.is_enabled(),
            config_error,
            transport_config,
            overlay_config: config.s2s.overlay_config(),
            application_config: config.s2s.application.clone(),
            transport_tuning: config.s2s.transport.clone(),
            overlay_tuning: config.s2s.overlay.clone(),
            replication_config: config.s2s.replications.clone().into(),
            max_users: Arc::new(AtomicU64::new(config.max_users)),
            state: RwLock::new(S2SRuntimeState::default()),
        }
    }

    /// Apply the operator-configured transport tunables on top of a
    /// caller-built [`transport::TransportConfig`] (which still owns
    /// PKI paths, listeners, and the rest).
    pub fn apply_transport_tuning(
        &self,
        cfg: transport::TransportConfig,
    ) -> transport::TransportConfig {
        self.transport_tuning.apply(cfg)
    }

    /// Apply the operator-configured overlay tunables on top of a
    /// caller-built [`overlay::OverlayConfig`].
    pub fn apply_overlay_tuning(&self, cfg: overlay::OverlayConfig) -> overlay::OverlayConfig {
        self.overlay_tuning.apply(cfg)
    }

    /// Resolved replication tunables, ready to hand to
    /// [`replications::ReplicationManager::with_config`].
    pub fn replication_config(&self) -> &replications::ReplicationConfig {
        &self.replication_config
    }

    /// Attach a fully-started overlay and spin up the `ReplicationManager`
    /// and `ApplicationLayer` on top of it. Mostly used by older tests;
    /// production startup goes through [`Self::spawn_runtime_task`].
    pub fn attach_overlay(&self, overlay: OverlayNetwork) {
        overlay.update_local_max_users(self.max_users.load(std::sync::atomic::Ordering::Relaxed));
        let repl =
            ReplicationManager::with_config(overlay.clone(), self.replication_config.clone());
        let app =
            application::ApplicationLayer::new(overlay.clone(), self.application_config.clone());
        let mut state = self.state.write();
        state.overlay = Some(overlay);
        state.replications = Some(repl);
        state.application = Some(app);
    }

    pub fn overlay(&self) -> Option<OverlayNetwork> {
        self.state.read().overlay.clone()
    }

    pub fn update_max_users(&self, max_users: u64) {
        self.max_users
            .store(max_users, std::sync::atomic::Ordering::Relaxed);
        if let Some(overlay) = self.overlay() {
            overlay.update_local_max_users(max_users);
        }
    }

    pub fn update_route_transit_messages(&self, enabled: bool) {
        if let Some(overlay) = self.overlay() {
            overlay.update_route_transit_messages(enabled);
        }
    }

    pub fn cluster_max_users(&self) -> Option<u64> {
        self.overlay().map(|overlay| overlay.alive_max_users())
    }

    pub fn replications(&self) -> Option<Arc<ReplicationManager>> {
        self.state.read().replications.clone()
    }

    pub fn application(&self) -> Option<Arc<application::ApplicationLayer>> {
        self.state.read().application.clone()
    }

    pub fn log_startup_summary(&self) {
        if !self.enabled {
            info!("s2s disabled");
            return;
        }
        if let Some(error) = &self.config_error {
            warn!(error = %error, "s2s enabled but configuration is invalid");
            return;
        }
        let seed_count = self
            .transport_config
            .as_ref()
            .map(|cfg| cfg.seed_addresses().len())
            .unwrap_or(0);
        info!(seed_count, "s2s enabled");
    }

    pub async fn propose_channel_op(&self, op: ChannelOp) -> bool {
        self.propose_channel_op_in_server(DEFAULT_SERVER_ID, op)
            .await
    }

    pub async fn propose_channel_op_in_server(&self, server_id: &str, op: ChannelOp) -> bool {
        let handle = match self.channel_replication_handle(server_id) {
            Some(handle) => handle,
            None => return false,
        };
        let operation = ChannelOperation {
            server_id: server_id.to_owned(),
            version: 0,
            node_id: handle.local_node_id(),
            timestamp: chrono::Utc::now().timestamp(),
            emits_client_message: true,
            op,
        };
        match handle.propose(operation).await {
            Ok(_) => true,
            Err(e) => {
                warn!(error = %e, "s2s channel op propose failed");
                false
            }
        }
    }

    pub async fn propose_ban_op(&self, op: BanOp) -> bool {
        let Some(handle) = self.state.read().ban_replication.clone() else {
            return false;
        };
        let operation = BanOperation {
            version: 0,
            node_id: handle.local_node_id(),
            timestamp: chrono::Utc::now().timestamp(),
            op,
        };
        match handle.propose(operation).await {
            Ok(_) => true,
            Err(e) => {
                warn!(error = %e, "s2s ban op propose failed");
                false
            }
        }
    }

    pub async fn get_channel_blob(&self, key: &str) -> Option<Bytes> {
        self.get_channel_blob_in_server(DEFAULT_SERVER_ID, key)
            .await
    }

    pub async fn get_channel_blob_in_server(&self, server_id: &str, key: &str) -> Option<Bytes> {
        let handle = self.channel_blob_replication_handle(server_id)?;
        handle.get(key).await
    }

    fn channel_replication_handle(
        &self,
        server_id: &str,
    ) -> Option<replications::StrictHandle<ChannelReplicationAdapter>> {
        {
            let state = self.state.read();
            if let Some(handle) = state.channel_replications.get(server_id).cloned() {
                return Some(handle);
            }
        }

        let (replications, server) = {
            let state = self.state.read();
            let replications = state.replications.clone()?;
            let server = state.server.clone()?.upgrade()?;
            (replications, server)
        };

        match self.register_channel_replication_scope(&replications, &server, server_id) {
            Ok(handle) => Some(handle),
            Err(e) => {
                warn!(server_id, error = %e, "failed to register scoped s2s channel replication");
                None
            }
        }
    }

    fn channel_blob_replication_handle(
        &self,
        server_id: &str,
    ) -> Option<replications::BlobHandle<ChannelBlobReplicationAdapter>> {
        {
            let state = self.state.read();
            if let Some(handle) = state.channel_blob_replications.get(server_id).cloned() {
                return Some(handle);
            }
        }

        let (replications, server) = {
            let state = self.state.read();
            let replications = state.replications.clone()?;
            let server = state.server.clone()?.upgrade()?;
            (replications, server)
        };

        match self.register_channel_blob_replication_scope(&replications, &server, server_id) {
            Ok(handle) => Some(handle),
            Err(e) => {
                warn!(server_id, error = %e, "failed to register scoped s2s channel blob replication");
                None
            }
        }
    }

    pub fn spawn_runtime_task(
        self: Arc<Self>,
        server: Weak<Box<Server>>,
        shutdown: watch::Receiver<()>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            self.run_runtime(server, shutdown).await;
        })
    }

    async fn run_runtime(
        self: Arc<Self>,
        server: Weak<Box<Server>>,
        mut shutdown: watch::Receiver<()>,
    ) {
        if !self.enabled {
            let _ = shutdown.changed().await;
            return;
        }

        if let Some(error) = &self.config_error {
            warn!(error = %error, "s2s startup skipped");
            let _ = shutdown.changed().await;
            return;
        }

        let Some(transport_config) = self.transport_config.clone() else {
            warn!("s2s startup skipped: no transport config");
            let _ = shutdown.changed().await;
            return;
        };

        let (transport, inbound) = match ConnectionManager::start(transport_config).await {
            Ok(parts) => parts,
            Err(e) => {
                warn!(error = %e, "s2s transport startup failed");
                let _ = shutdown.changed().await;
                return;
            }
        };

        let overlay = match OverlayNetwork::start_with_max_users(
            transport.clone(),
            inbound,
            self.overlay_config.clone(),
            self.max_users.clone(),
        )
        .await
        {
            Ok(overlay) => overlay,
            Err(e) => {
                warn!(error = %e, "s2s overlay startup failed");
                transport.shutdown().await;
                let _ = shutdown.changed().await;
                return;
            }
        };

        let replications =
            ReplicationManager::with_config(overlay.clone(), self.replication_config.clone());
        let application =
            application::ApplicationLayer::new(overlay.clone(), self.application_config.clone());
        let recipient_index = RecipientIndex::new();
        let server_handle = server.upgrade();
        if let Some(server) = server_handle.as_ref() {
            let channels = server.get_channels().clone();
            let manager = Arc::clone(&self);
            replications.set_strict_topic_resolver(Some(Arc::new(move |topic, parts| {
                let server_id = server_id_from_channel_topic(topic)?;
                let repo = Arc::new(ChannelReplicationAdapter::new(
                    server_id.clone(),
                    channels.clone(),
                ));
                let runtime = parts.build_runtime(topic.to_owned(), repo);
                runtime.start();
                let handle = replications::StrictHandle::with_runtime(runtime.clone());
                manager
                    .state
                    .write()
                    .channel_replications
                    .entry(server_id)
                    .or_insert(handle);
                Some(runtime)
            })));

            let channel_blobs = server.get_channel_blobs().clone();
            let channels_for_blobs = server.get_channels().clone();
            let manager = Arc::clone(&self);
            replications.set_blob_topic_resolver(Some(Arc::new(move |topic, parts| {
                let server_id = server_id_from_channel_blob_topic(topic)?;
                let repo = Arc::new(ChannelBlobReplicationAdapter::new(
                    server_id.clone(),
                    channel_blobs.clone(),
                    channels_for_blobs.clone(),
                ));
                let runtime = parts.build_runtime(topic.to_owned(), repo);
                runtime.start();
                let handle = replications::BlobHandle::with_runtime(runtime.clone());
                manager
                    .state
                    .write()
                    .channel_blob_replications
                    .entry(server_id)
                    .or_insert(handle);
                Some(runtime)
            })));
        }

        application.user_stats().set_responder(
            crate::client::handlers::ServerUserStatsResponder::new(server.clone()),
        );
        application
            .moderation()
            .set_applier(Arc::new(ServerModerationApplier::new(server.clone())));
        application
            .voice()
            .set_audio_sink(Arc::new(ServerVoiceSink::new(server.clone())));
        application
            .voice()
            .set_recipient_index(recipient_index.clone());
        application
            .plugin_data()
            .set_sink(ServerPluginDataSink::new(server.clone()));

        let (
            channel_replications,
            ban_replication,
            client_replication,
            channel_blob_replications,
            bridge_tasks,
        ) = match server_handle.as_ref() {
            Some(server) => {
                self.register_repositories(&replications, server, recipient_index.clone())
                    .await
            }
            None => {
                warn!("s2s repository replication skipped: server handle dropped");
                (HashMap::new(), None, None, HashMap::new(), Vec::new())
            }
        };

        {
            let mut state = self.state.write();
            state.transport = Some(transport.clone());
            state.overlay = Some(overlay.clone());
            state.replications = Some(replications.clone());
            state.application = Some(application.clone());
            state.recipient_index = Some(recipient_index);
            state.server = Some(server.clone());
            state.channel_replications = channel_replications;
            state.ban_replication = ban_replication;
            state.client_replication = client_replication;
            state.channel_blob_replications = channel_blob_replications;
            state.bridge_tasks = bridge_tasks;
        }

        info!(node = overlay.local_node_id(), "s2s runtime started");

        let _ = shutdown.changed().await;

        let bridge_tasks = {
            let mut state = self.state.write();
            let bridge_tasks = std::mem::take(&mut state.bridge_tasks);
            state.channel_replications.clear();
            state.ban_replication = None;
            state.client_replication = None;
            state.channel_blob_replications.clear();
            state.server = None;
            state.recipient_index = None;
            state.application = None;
            state.replications = None;
            state.overlay = None;
            state.transport = None;
            bridge_tasks
        };
        for task in bridge_tasks {
            task.abort();
        }

        replications.set_strict_topic_resolver(None);
        replications.set_blob_topic_resolver(None);
        application.shutdown().await;
        replications.shutdown().await;
        overlay.shutdown().await;
        transport.shutdown().await;

        info!("s2s runtime stopped");
    }

    async fn register_repositories(
        &self,
        replications: &Arc<ReplicationManager>,
        server: &Arc<Box<Server>>,
        recipient_index: Arc<RecipientIndex>,
    ) -> (
        HashMap<String, replications::StrictHandle<ChannelReplicationAdapter>>,
        Option<replications::StrictHandle<BanReplicationAdapter>>,
        Option<replications::OwnerHandle<ClientReplicationAdapter>>,
        HashMap<String, replications::BlobHandle<ChannelBlobReplicationAdapter>>,
        Vec<JoinHandle<()>>,
    ) {
        let bans = Arc::new(BanReplicationAdapter::new(server.get_bans().clone()));
        let clients = Arc::new(ClientReplicationAdapter::new(
            server.get_clients().clone(),
            server.get_channels().clone(),
        ));

        let mut channel_handles = HashMap::new();
        if let Err(e) = self.register_channel_replication_scope_into(
            replications,
            server,
            DEFAULT_SERVER_ID,
            &mut channel_handles,
        ) {
            warn!(error = %e, "failed to register s2s channel replication");
        }
        let mut channel_blob_handles = HashMap::new();
        if let Err(e) = self.register_channel_blob_replication_scope_into(
            replications,
            server,
            DEFAULT_SERVER_ID,
            &mut channel_blob_handles,
        ) {
            warn!(error = %e, "failed to register s2s channel blob replication");
        }
        let ban_handle = match replications.register_strict("bans", bans) {
            Ok(handle) => Some(handle),
            Err(e) => {
                warn!(error = %e, "failed to register s2s ban replication");
                None
            }
        };
        let client_handle = match replications.register_owner("clients", clients) {
            Ok(handle) => Some(handle),
            Err(e) => {
                warn!(error = %e, "failed to register s2s client replication");
                None
            }
        };

        let mut bridge_tasks = Vec::new();
        if let Some(handle) = client_handle.clone() {
            bridge_tasks.push(spawn_client_replication_bridge(
                server.get_clients().clone(),
                handle,
            ));
        }
        bridge_tasks.push(spawn_voice_recipient_index_bridge(
            server.get_clients().clone(),
            recipient_index,
        ));

        (
            channel_handles,
            ban_handle,
            client_handle,
            channel_blob_handles,
            bridge_tasks,
        )
    }

    fn register_channel_replication_scope(
        &self,
        replications: &Arc<ReplicationManager>,
        server: &Arc<Box<Server>>,
        server_id: &str,
    ) -> Result<replications::StrictHandle<ChannelReplicationAdapter>, replications::ReplicationError>
    {
        let mut state = self.state.write();
        self.register_channel_replication_scope_into(
            replications,
            server,
            server_id,
            &mut state.channel_replications,
        )
    }

    fn register_channel_replication_scope_into(
        &self,
        replications: &Arc<ReplicationManager>,
        server: &Arc<Box<Server>>,
        server_id: &str,
        handles: &mut HashMap<String, replications::StrictHandle<ChannelReplicationAdapter>>,
    ) -> Result<replications::StrictHandle<ChannelReplicationAdapter>, replications::ReplicationError>
    {
        match handles.entry(server_id.to_owned()) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                let topic = channel_topic(server_id);
                let repo = Arc::new(ChannelReplicationAdapter::new(
                    server_id.to_owned(),
                    server.get_channels().clone(),
                ));
                let runtime = replications
                    .strict_topic_parts()
                    .build_runtime(topic.clone(), repo);
                runtime.start();
                replications.install_strict_runtime(topic, runtime.clone())?;
                let handle = replications::StrictHandle::with_runtime(runtime);
                entry.insert(handle.clone());
                Ok(handle)
            }
        }
    }

    fn register_channel_blob_replication_scope(
        &self,
        replications: &Arc<ReplicationManager>,
        server: &Arc<Box<Server>>,
        server_id: &str,
    ) -> Result<
        replications::BlobHandle<ChannelBlobReplicationAdapter>,
        replications::ReplicationError,
    > {
        let mut state = self.state.write();
        self.register_channel_blob_replication_scope_into(
            replications,
            server,
            server_id,
            &mut state.channel_blob_replications,
        )
    }

    fn register_channel_blob_replication_scope_into(
        &self,
        replications: &Arc<ReplicationManager>,
        server: &Arc<Box<Server>>,
        server_id: &str,
        handles: &mut HashMap<String, replications::BlobHandle<ChannelBlobReplicationAdapter>>,
    ) -> Result<
        replications::BlobHandle<ChannelBlobReplicationAdapter>,
        replications::ReplicationError,
    > {
        match handles.entry(server_id.to_owned()) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                let topic = channel_blob_topic(server_id);
                let repo = Arc::new(ChannelBlobReplicationAdapter::new(
                    server_id.to_owned(),
                    server.get_channel_blobs().clone(),
                    server.get_channels().clone(),
                ));
                let runtime = replications
                    .blob_topic_parts()
                    .build_runtime(topic.clone(), repo);
                runtime.start();
                replications.install_blob_runtime(topic, runtime.clone())?;
                let handle = replications::BlobHandle::with_runtime(runtime);
                entry.insert(handle.clone());
                Ok(handle)
            }
        }
    }
}

fn spawn_client_replication_bridge(
    repo: Arc<ClientRepository>,
    handle: replications::OwnerHandle<ClientReplicationAdapter>,
) -> JoinHandle<()> {
    let mut rx = repo.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(payload) => {
                    let entry = payload.entry.clone();
                    if entry.node_id != repo.local_node_id() {
                        continue;
                    }
                    if let Err(e) = handle.propose((*entry).clone()).await {
                        warn!(error = %e, version = entry.version, "s2s client replication propose failed");
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "s2s client replication bridge lagged");
                }
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    })
}

fn spawn_voice_recipient_index_bridge(
    repo: Arc<ClientRepository>,
    index: Arc<RecipientIndex>,
) -> JoinHandle<()> {
    let mut rx = repo.subscribe();
    tokio::spawn(async move {
        index.replace_all(repo.voice_recipient_index_snapshot().await);
        loop {
            match rx.recv().await {
                Ok(_) => {
                    index.replace_all(repo.voice_recipient_index_snapshot().await);
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "s2s voice recipient index bridge lagged");
                    index.replace_all(repo.voice_recipient_index_snapshot().await);
                }
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    })
}

struct ServerModerationApplier {
    server: Weak<Box<Server>>,
}

impl ServerModerationApplier {
    fn new(server: Weak<Box<Server>>) -> Self {
        Self { server }
    }
}

#[async_trait]
impl ModerationApplier for ServerModerationApplier {
    async fn apply(&self, from: NodeIdentifier, envelope: ModerationEnvelope) {
        let Some(server) = self.server.upgrade() else {
            return;
        };
        let target_id = ClientSessionIdentifier::from(envelope.target_session);
        if target_id.get_node_id() != server.get_clients().local_node_id() {
            trace!(
                from,
                target = envelope.target_session,
                "s2s moderation ignored: target is not local"
            );
            return;
        }

        let server_id = if envelope.server_id.is_empty() {
            crate::types::default_server_id()
        } else {
            envelope.server_id.clone()
        };
        match envelope.command {
            Some(ModerationCommand::UserState(patch)) => {
                apply_user_state_patch(
                    &server,
                    &server_id,
                    envelope.actor_session,
                    target_id,
                    patch,
                )
                .await;
            }
            Some(ModerationCommand::UserRemove(patch)) => {
                apply_user_remove_patch(
                    &server,
                    &server_id,
                    envelope.actor_session,
                    target_id,
                    patch,
                )
                .await;
            }
            None => {
                trace!(from, "s2s moderation ignored: empty command");
            }
        }
    }
}

async fn apply_user_state_patch(
    server: &Arc<Box<Server>>,
    server_id: &str,
    actor_session: u32,
    target_id: ClientSessionIdentifier,
    patch: UserStatePatch,
) {
    let Some(target) = server
        .get_clients()
        .get_client_in_server(server_id, target_id)
        .await
    else {
        return;
    };

    if let Some(expected) = patch.expected_from_channel {
        if target.get_current_channel_id() != expected {
            trace!(
                target = u32::from(target_id),
                expected,
                actual = target.get_current_channel_id(),
                "s2s moderation user-state skipped: channel precondition failed"
            );
            return;
        }
    }

    let actor = ClientSessionIdentifier::from(actor_session);
    let has_channel_dependency = patch.channel_id.is_some()
        || patch.mute.is_some()
        || patch.deaf.is_some()
        || patch.suppress.is_some()
        || patch.priority_speaker.is_some()
        || !patch.listening_channel_add.is_empty()
        || !patch.listening_channel_remove.is_empty();
    let channel_version_dep =
        has_channel_dependency.then(|| server.get_channels().current_version_in_server(server_id));

    let mut gs =
        target.write_global_state_as(server.get_clients(), Some(actor), channel_version_dep);

    if let Some(mute) = patch.mute {
        if gs.is_muted() != mute {
            gs.set_mute(mute);
            if !mute {
                gs.set_deaf(false);
            }
        }
        if gs.is_suppressed() && !mute {
            gs.set_suppress(false);
        }
    }
    if let Some(deaf) = patch.deaf {
        if gs.is_deafened() != deaf {
            gs.set_deaf(deaf);
            if deaf && !gs.is_muted() {
                gs.set_mute(true);
            }
        }
    }
    if let Some(suppress) = patch.suppress {
        if gs.is_suppressed() != suppress {
            gs.set_suppress(suppress);
        }
    }
    if let Some(priority_speaker) = patch.priority_speaker {
        if gs.is_priority_speaker() != priority_speaker {
            gs.set_priority_speaker(priority_speaker);
        }
    }
    if let Some(channel_id) = patch.channel_id {
        gs.set_current_channel_id(channel_id);
    }
    for channel_id in patch.listening_channel_add {
        gs.listen_channel(channel_id);
    }
    for channel_id in patch.listening_channel_remove {
        gs.unlisten_channel(channel_id);
    }
}

async fn apply_user_remove_patch(
    server: &Arc<Box<Server>>,
    server_id: &str,
    actor_session: u32,
    target_id: ClientSessionIdentifier,
    patch: UserRemovePatch,
) {
    let Some(target) = server
        .get_clients()
        .get_client_in_server(server_id, target_id)
        .await
    else {
        return;
    };

    if patch.ban {
        let reason = patch.reason.clone().unwrap_or_default();
        let address = target.get_real_ip_address();
        let entry = BanEntry {
            address,
            mask: if address.is_ipv4() { 32 } else { 128 },
            name: {
                let gs = target.read_global_state();
                gs.get_display_name_opt().map(ToOwned::to_owned)
            },
            hash: target.get_certificate_hash().map(hex::encode),
            reason: if reason.is_empty() {
                None
            } else {
                Some(reason.clone())
            },
            start: chrono::Utc::now().timestamp(),
            duration: 0,
        };
        if let Err(e) = server.get_bans().add_ban(entry).await {
            warn!(error = %e, "s2s moderation failed to persist ban");
        }
        info!(
            actor = actor_session,
            target = u32::from(target_id),
            "s2s moderation added ban"
        );
    }

    let removed = server
        .get_clients()
        .remove_client_in_server(server_id, target_id)
        .await;
    let target = removed.as_ref().unwrap_or(&target);
    if let Err(e) = target.disconnect().await {
        trace!(
            error = %e,
            target = u32::from(target_id),
            "s2s moderation failed to gracefully disconnect removed client",
        );
    }
}

struct ServerVoiceSink {
    server: Weak<Box<Server>>,
}

impl ServerVoiceSink {
    fn new(server: Weak<Box<Server>>) -> Self {
        Self { server }
    }
}

#[async_trait]
impl AudioSink for ServerVoiceSink {
    async fn deliver(&self, from_immediate: NodeIdentifier, frame: VoiceFrame) {
        let Some(server) = self.server.upgrade() else {
            return;
        };
        crate::voice::route_s2s_voice_frame(&server, from_immediate, frame).await;
    }
}

fn server_id_from_channel_topic(topic: &str) -> Option<String> {
    if topic == "channels" {
        Some(DEFAULT_SERVER_ID.to_owned())
    } else {
        topic
            .strip_prefix("channels:")
            .filter(|server_id| !server_id.is_empty())
            .map(str::to_owned)
    }
}

fn server_id_from_channel_blob_topic(topic: &str) -> Option<String> {
    if topic == "channel_blobs" {
        Some(DEFAULT_SERVER_ID.to_owned())
    } else {
        topic
            .strip_prefix("channel_blobs:")
            .filter(|server_id| !server_id.is_empty())
            .map(str::to_owned)
    }
}

fn channel_topic(server_id: &str) -> String {
    if server_id == DEFAULT_SERVER_ID {
        "channels".to_owned()
    } else {
        format!("channels:{server_id}")
    }
}

fn channel_blob_topic(server_id: &str) -> String {
    if server_id == DEFAULT_SERVER_ID {
        "channel_blobs".to_owned()
    } else {
        format!("channel_blobs:{server_id}")
    }
}

#[derive(Clone)]
struct ChannelReplicationAdapter {
    server_id: String,
    repo: Arc<ChannelRepository>,
}

impl ChannelReplicationAdapter {
    fn new(server_id: String, repo: Arc<ChannelRepository>) -> Self {
        Self { server_id, repo }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChannelSnapshot {
    channels: Vec<crate::channels::Channel>,
}

#[async_trait]
impl StrictReplicable for ChannelReplicationAdapter {
    type Op = ChannelOperation;

    fn current_version(&self) -> u64 {
        self.repo.current_version_in_server(&self.server_id)
    }

    fn snapshot(&self) -> (u64, Bytes) {
        let version = self.repo.current_version_in_server(&self.server_id);
        let repo = self.repo.clone();
        let server_id = self.server_id.clone();
        let channels =
            block_in_place_or_current(|handle| handle.block_on(repo.get_all_in_server(&server_id)))
                .unwrap_or_default();
        let bytes =
            Bytes::from(rmp_serde::to_vec(&ChannelSnapshot { channels }).unwrap_or_default());
        (version, bytes)
    }

    fn log_since(&self, since: u64) -> replications::strict::LogSlice<Self::Op> {
        let repo = self.repo.clone();
        let server_id = self.server_id.clone();
        let entries = block_in_place_or_current(|handle| {
            handle.block_on(repo.get_log_since_in_server(&server_id, since))
        });
        match entries {
            Some(entries) => replications::strict::LogSlice::Available(
                entries
                    .into_iter()
                    .map(|op| (op.version, (*op).clone()))
                    .collect(),
            ),
            None => replications::strict::LogSlice::TooOld,
        }
    }

    async fn apply_committed(&self, version: u64, mut op: Self::Op) {
        op.version = version;
        if op.server_id.is_empty() || op.server_id == DEFAULT_SERVER_ID {
            op.server_id = self.server_id.clone();
        }
        if let Err(e) = self.repo.apply_committed_operation(op).await {
            warn!(error = ?e, "s2s channel operation apply failed");
        }
    }

    async fn install_snapshot(&self, version: u64, snapshot: Bytes) {
        let decoded: ChannelSnapshot = match rmp_serde::from_slice(&snapshot) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                warn!(error = %e, "s2s channel snapshot decode failed");
                return;
            }
        };
        if let Err(e) = self
            .repo
            .install_s2s_snapshot_in_server(&self.server_id, version, decoded.channels)
            .await
        {
            warn!(error = ?e, "s2s channel snapshot install failed");
        }
    }
}

#[derive(Clone)]
struct ChannelBlobReplicationAdapter {
    server_id: String,
    blobs: Arc<ChannelBlobStore>,
    channels: Arc<ChannelRepository>,
}

impl ChannelBlobReplicationAdapter {
    fn new(
        server_id: String,
        blobs: Arc<ChannelBlobStore>,
        channels: Arc<ChannelRepository>,
    ) -> Self {
        Self {
            server_id,
            blobs,
            channels,
        }
    }
}

#[async_trait]
impl BlobReplicable for ChannelBlobReplicationAdapter {
    async fn get_blob(&self, key: &str) -> Option<Bytes> {
        self.blobs.get(key).await.ok().flatten()
    }

    async fn put_blob(&self, key: &str, data: Bytes) -> Result<(), replications::ReplicationError> {
        let written = self.blobs.put(&data).await.map_err(|_| {
            replications::ReplicationError::Malformed("channel blob store write failed")
        })?;
        if written == key {
            Ok(())
        } else {
            Err(replications::ReplicationError::Malformed(
                "channel blob key does not match content",
            ))
        }
    }

    async fn delete_blob(&self, key: &str) -> Result<(), replications::ReplicationError> {
        self.blobs
            .delete(key)
            .await
            .map_err(|_| replications::ReplicationError::Malformed("channel blob delete failed"))
    }

    async fn stored_keys(&self) -> HashSet<String> {
        self.blobs.keys().await.unwrap_or_default()
    }

    async fn referenced_keys(&self) -> HashSet<String> {
        self.channels
            .get_all_in_server(&self.server_id)
            .await
            .into_iter()
            .filter_map(|channel| channel.description_hash)
            .filter(|key| key.len() == 40)
            .collect()
    }
}

#[derive(Clone)]
struct BanReplicationAdapter {
    repo: Arc<BanRepository>,
}

impl BanReplicationAdapter {
    fn new(repo: Arc<BanRepository>) -> Self {
        Self { repo }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BanSnapshot {
    entries: Vec<BanEntry>,
}

#[async_trait]
impl StrictReplicable for BanReplicationAdapter {
    type Op = BanOperation;

    fn current_version(&self) -> u64 {
        self.repo.current_version()
    }

    fn snapshot(&self) -> (u64, Bytes) {
        let version = self.repo.current_version();
        let repo = self.repo.clone();
        let entries = block_in_place_or_current(|handle| handle.block_on(repo.get_active_bans()))
            .unwrap_or_default();
        let bytes = Bytes::from(rmp_serde::to_vec(&BanSnapshot { entries }).unwrap_or_default());
        (version, bytes)
    }

    fn log_since(&self, since: u64) -> replications::strict::LogSlice<Self::Op> {
        let repo = self.repo.clone();
        let entries =
            block_in_place_or_current(|handle| handle.block_on(repo.get_log_since(since)));
        match entries {
            Some(entries) => replications::strict::LogSlice::Available(
                entries
                    .into_iter()
                    .map(|op| (op.version, (*op).clone()))
                    .collect(),
            ),
            None => replications::strict::LogSlice::TooOld,
        }
    }

    async fn apply_committed(&self, version: u64, mut op: Self::Op) {
        op.version = version;
        self.repo.apply_remote_operation(Arc::new(op)).await;
    }

    async fn install_snapshot(&self, version: u64, snapshot: Bytes) {
        let decoded: BanSnapshot = match rmp_serde::from_slice(&snapshot) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                warn!(error = %e, "s2s ban snapshot decode failed");
                return;
            }
        };
        self.repo
            .install_s2s_snapshot(version, decoded.entries)
            .await;
    }
}

#[derive(Clone)]
struct ClientReplicationAdapter {
    clients: Arc<ClientRepository>,
    channels: Arc<ChannelRepository>,
}

impl ClientReplicationAdapter {
    fn new(clients: Arc<ClientRepository>, channels: Arc<ChannelRepository>) -> Self {
        Self { clients, channels }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientOriginSnapshot {
    version: u64,
    entries: Vec<ClientStateLogEntry>,
}

#[async_trait]
impl OwnerReplicable for ClientReplicationAdapter {
    type Op = ClientStateLogEntry;

    fn local_version(&self) -> u64 {
        self.clients.current_version()
    }

    fn known_versions(&self) -> HashMap<NodeIdentifier, (u64, u64)> {
        let clients = self.clients.clone();
        block_in_place_or_current(|handle| {
            let (_, versions) = handle.block_on(clients.snapshot_with_versions());
            versions
                .into_iter()
                .map(|(node, version)| (node, (0, version)))
                .collect()
        })
        .unwrap_or_default()
    }

    fn snapshot_for_origin(&self, origin: NodeIdentifier) -> Option<(u64, u64, Bytes)> {
        let clients = self.clients.clone();
        block_in_place_or_current(|handle| {
            let entries = handle.block_on(clients.get_log_since(0));
            let version = entries.last().map(|entry| entry.version).unwrap_or(0);
            let entries: Vec<ClientStateLogEntry> =
                entries.into_iter().map(|entry| (*entry).clone()).collect();
            let bytes =
                Bytes::from(rmp_serde::to_vec(&ClientOriginSnapshot { version, entries }).ok()?);
            Some((0, version, bytes))
        })
        .flatten()
        .filter(|_| origin == self.clients.local_node_id())
    }

    fn log_for_origin(
        &self,
        origin: NodeIdentifier,
        since: u64,
    ) -> replications::owner::LogSlice<Self::Op> {
        if origin != self.clients.local_node_id() {
            return replications::owner::LogSlice::Available(Vec::new());
        }
        let clients = self.clients.clone();
        let entries =
            block_in_place_or_current(|handle| handle.block_on(clients.get_log_since(since)));
        match entries {
            Some(entries) => replications::owner::LogSlice::Available(
                entries
                    .into_iter()
                    .map(|entry| (entry.version, (*entry).clone()))
                    .collect(),
            ),
            None => replications::owner::LogSlice::TooOld,
        }
    }

    async fn apply_remote(
        &self,
        origin: NodeIdentifier,
        _epoch: u64,
        version: u64,
        mut op: Self::Op,
    ) {
        op.node_id = origin;
        op.version = version;
        let current_channel_version = self.channels.current_version_in_server(op.op.server_id());
        if let Err(()) = self
            .clients
            .apply_remote_operation(Arc::new(op), current_channel_version)
            .await
        {
            warn!(origin, version, "s2s client operation apply failed");
        }
    }

    async fn install_snapshot_for_origin(
        &self,
        origin: NodeIdentifier,
        _epoch: u64,
        _version: u64,
        snapshot: Bytes,
    ) {
        let decoded: ClientOriginSnapshot = match rmp_serde::from_slice(&snapshot) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                warn!(origin, error = %e, "s2s client snapshot decode failed");
                return;
            }
        };
        for mut entry in decoded.entries {
            entry.node_id = origin;
            let current_channel_version = self
                .channels
                .current_version_in_server(entry.op.server_id());
            if let Err(()) = self
                .clients
                .apply_remote_operation(Arc::new(entry), current_channel_version)
                .await
            {
                warn!(origin, "s2s client snapshot entry apply failed");
                return;
            }
        }
    }

    async fn reset_origin(&self, origin: NodeIdentifier, _new_epoch: u64) {
        if origin != self.clients.local_node_id() {
            self.clients.clear_clients_from_node(origin).await;
        }
    }
}

fn block_in_place_or_current<T>(f: impl FnOnce(&tokio::runtime::Handle) -> T) -> Option<T> {
    let handle = tokio::runtime::Handle::try_current().ok()?;
    Some(tokio::task::block_in_place(|| f(&handle)))
}
