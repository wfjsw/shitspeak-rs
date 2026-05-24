pub mod application;
pub mod overlay;
pub mod replications;
pub mod status;
pub mod transport;

#[cfg(test)]
pub(crate) mod testing;

use std::collections::{hash_map::Entry, BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Weak};
use std::thread;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
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

use self::application::error::ApplicationError;
use self::application::moderation::ModerationApplier;
use self::application::proto::{
    ModerationCommand, ModerationEnvelope, PluginDataEnvelope, UserRemovePatch, UserStatePatch,
    UserStatsReply, VoiceFrame, VoiceIntent,
};
use self::application::voice::{AudioSink, RecipientIndex};
use self::overlay::OverlayNetwork;
use self::replications::{BlobReplicable, OwnerReplicable, ReplicationManager, StrictReplicable};
use self::transport::{ConnectionManager, TransportConfig};

const NATIVE_GATEWAY_CAPACITY: usize = 4096;
const S2S_GATEWAY_CAPACITY: usize = 4096;
const S2S_GATEWAY_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct S2SManager {
    enabled: bool,
    config_error: Option<String>,
    transport_config: Option<TransportConfig>,
    overlay_config: overlay::OverlayConfig,
    application_config: application::ApplicationConfig,
    transport_tuning: transport::TransportTuning,
    overlay_tuning: overlay::OverlayTuning,
    replication_config: replications::ReplicationConfig,
    status_http_listen: Option<SocketAddr>,
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
    gateway_tx: Option<mpsc::Sender<NativeToS2SCommand>>,
}

enum S2SNativeCommand {
    ApplyModeration {
        from: NodeIdentifier,
        envelope: ModerationEnvelope,
    },
    DeliverPluginData {
        from: NodeIdentifier,
        envelope: PluginDataEnvelope,
    },
    DeliverVoice {
        from_immediate: NodeIdentifier,
        frame: VoiceFrame,
    },
}

enum NativeToS2SCommand {
    ProposeChannel {
        server_id: String,
        op: ChannelOp,
        respond: oneshot::Sender<bool>,
    },
    ProposeBan {
        op: BanOp,
        respond: oneshot::Sender<bool>,
    },
    ProposeClientReplication(ClientStateLogEntry),
    RefreshVoiceRecipientIndex(HashMap<u32, BTreeSet<NodeIdentifier>>),
    DispatchPluginData {
        owner: NodeIdentifier,
        envelope: PluginDataEnvelope,
    },
    DispatchModeration {
        owner: NodeIdentifier,
        envelope: ModerationEnvelope,
    },
    DispatchUserStats {
        owner: NodeIdentifier,
        actor_session: u32,
        target_session: u32,
        stats_only: bool,
        server_id: String,
        respond: oneshot::Sender<Result<UserStatsReply, ApplicationError>>,
    },
    SendVoiceForChannel {
        sender_session: u32,
        server_id: String,
        source_channel: u32,
        is_terminator: bool,
        payload: Bytes,
    },
    SendVoiceBroadcast {
        sender_session: u32,
        server_id: String,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
    },
}

struct S2SGateways {
    native_tx: mpsc::Sender<S2SNativeCommand>,
    s2s_tx: mpsc::Sender<NativeToS2SCommand>,
    s2s_rx: mpsc::Receiver<NativeToS2SCommand>,
    native_runtime: tokio::runtime::Handle,
}

pub(crate) struct S2SRuntimeTask {
    thread: Option<thread::JoinHandle<()>>,
    native_tasks: Vec<JoinHandle<()>>,
}

impl S2SRuntimeTask {
    pub(crate) async fn join(mut self) {
        if let Some(thread) = self.thread.take() {
            match tokio::task::spawn_blocking(move || thread.join()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    warn!("s2s runtime thread panicked");
                }
                Err(e) => {
                    warn!(error = %e, "failed to join s2s runtime thread");
                }
            }
        }

        for task in self.native_tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

impl S2SManager {
    pub fn initialize(config: &crate::config::Config) -> Self {
        let auto_advertise_host = config
            .register_hostname
            .as_deref()
            .map(str::trim)
            .filter(|host| !host.is_empty());
        let (transport_config, config_error) = match config
            .s2s
            .transport_config_with_auto_advertise_host(auto_advertise_host)
        {
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
            status_http_listen: config.s2s.status_http_listen,
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

    fn clear_gateway_tx(&self) {
        self.state.write().gateway_tx = None;
    }

    pub async fn propose_channel_op(&self, server_id: Option<&str>, op: ChannelOp) -> bool {
        let server_id = server_id.unwrap_or(DEFAULT_SERVER_ID).to_owned();
        let Some(tx) = self.state.read().gateway_tx.clone() else {
            return false;
        };
        let (respond, rx) = oneshot::channel();
        match tx.try_send(NativeToS2SCommand::ProposeChannel {
            server_id,
            op,
            respond,
        }) {
            Ok(()) => tokio::time::timeout(S2S_GATEWAY_RESPONSE_TIMEOUT, rx)
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(false),
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("s2s gateway full; dropping channel proposal");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    async fn propose_channel_op_direct(&self, server_id: &str, op: ChannelOp) -> bool {
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
        let Some(tx) = self.state.read().gateway_tx.clone() else {
            return false;
        };
        let (respond, rx) = oneshot::channel();
        match tx.try_send(NativeToS2SCommand::ProposeBan { op, respond }) {
            Ok(()) => tokio::time::timeout(S2S_GATEWAY_RESPONSE_TIMEOUT, rx)
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(false),
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("s2s gateway full; dropping ban proposal");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    async fn propose_ban_op_direct(&self, op: BanOp) -> bool {
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

    fn try_send_s2s_command(&self, command: NativeToS2SCommand, label: &'static str) -> bool {
        let Some(tx) = self.state.read().gateway_tx.clone() else {
            trace!(label, "s2s gateway unavailable; dropping command");
            return false;
        };
        match tx.try_send(command) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(label, "s2s gateway full; dropping command");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                trace!(label, "s2s gateway closed; dropping command");
                false
            }
        }
    }

    pub fn dispatch_plugin_data(
        &self,
        owner: NodeIdentifier,
        envelope: PluginDataEnvelope,
    ) -> bool {
        self.try_send_s2s_command(
            NativeToS2SCommand::DispatchPluginData { owner, envelope },
            "plugin_data",
        )
    }

    pub fn dispatch_moderation_user_state(
        &self,
        server_id: Option<&str>,
        actor: ClientSessionIdentifier,
        target: ClientSessionIdentifier,
        patch: UserStatePatch,
    ) -> bool {
        let server_id = server_id.unwrap_or(DEFAULT_SERVER_ID);
        let envelope = ModerationEnvelope {
            actor_session: actor.to_u32(),
            target_session: target.to_u32(),
            issued_at_ms: now_ms(),
            server_id: server_id.to_owned(),
            command: Some(ModerationCommand::UserState(patch)),
        };
        self.try_send_s2s_command(
            NativeToS2SCommand::DispatchModeration {
                owner: target.get_node_id(),
                envelope,
            },
            "moderation",
        )
    }

    pub fn dispatch_moderation_user_remove(
        &self,
        server_id: Option<&str>,
        actor: ClientSessionIdentifier,
        target: ClientSessionIdentifier,
        patch: UserRemovePatch,
    ) -> bool {
        let server_id = server_id.unwrap_or(DEFAULT_SERVER_ID);
        let envelope = ModerationEnvelope {
            actor_session: actor.to_u32(),
            target_session: target.to_u32(),
            issued_at_ms: now_ms(),
            server_id: server_id.to_owned(),
            command: Some(ModerationCommand::UserRemove(patch)),
        };
        self.try_send_s2s_command(
            NativeToS2SCommand::DispatchModeration {
                owner: target.get_node_id(),
                envelope,
            },
            "moderation",
        )
    }

    pub async fn dispatch_user_stats_request(
        &self,
        owner: NodeIdentifier,
        actor_session: u32,
        target_session: u32,
        stats_only: bool,
        server_id: String,
    ) -> Result<UserStatsReply, ApplicationError> {
        let Some(tx) = self.state.read().gateway_tx.clone() else {
            return Err(ApplicationError::Unavailable);
        };
        let (respond, rx) = oneshot::channel();
        match tx.try_send(NativeToS2SCommand::DispatchUserStats {
            owner,
            actor_session,
            target_session,
            stats_only,
            server_id,
            respond,
        }) {
            Ok(()) => tokio::time::timeout(S2S_GATEWAY_RESPONSE_TIMEOUT, rx)
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(Err(ApplicationError::Unavailable)),
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("s2s gateway full; dropping user_stats request");
                Err(ApplicationError::Unavailable)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(ApplicationError::Unavailable),
        }
    }

    pub fn send_voice_for_channel(
        &self,
        sender_session: u32,
        server_id: String,
        source_channel: u32,
        is_terminator: bool,
        payload: Bytes,
    ) -> bool {
        self.try_send_s2s_command(
            NativeToS2SCommand::SendVoiceForChannel {
                sender_session,
                server_id,
                source_channel,
                is_terminator,
                payload,
            },
            "voice",
        )
    }

    pub fn send_voice_broadcast(
        &self,
        sender_session: u32,
        server_id: String,
        target_kind: u32,
        is_terminator: bool,
        payload: Bytes,
        intent: VoiceIntent,
    ) -> bool {
        self.try_send_s2s_command(
            NativeToS2SCommand::SendVoiceBroadcast {
                sender_session,
                server_id,
                target_kind,
                is_terminator,
                payload,
                intent,
            },
            "voice",
        )
    }

    pub async fn get_channel_blob(&self, server_id: Option<&str>, key: &str) -> Option<Bytes> {
        let server_id = server_id.unwrap_or(DEFAULT_SERVER_ID);
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

    pub(crate) fn spawn_runtime_task(
        self: Arc<Self>,
        server: Weak<Box<Server>>,
        shutdown: watch::Receiver<()>,
    ) -> S2SRuntimeTask {
        let native_runtime = tokio::runtime::Handle::current();
        let (native_tx, native_rx) = mpsc::channel(NATIVE_GATEWAY_CAPACITY);
        let (s2s_tx, s2s_rx) = mpsc::channel(S2S_GATEWAY_CAPACITY);
        if self.enabled && self.config_error.is_none() && self.transport_config.is_some() {
            self.state.write().gateway_tx = Some(s2s_tx.clone());
        } else {
            self.clear_gateway_tx();
        }
        let native_gateway_task = native_runtime.spawn(run_native_gateway(
            server.clone(),
            native_rx,
            shutdown.clone(),
        ));
        let gateways = S2SGateways {
            native_tx,
            s2s_tx,
            s2s_rx,
            native_runtime,
        };

        let thread = thread::Builder::new()
            .name("s2s-runtime".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .thread_name("s2s-runtime-worker")
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(e) => {
                        warn!(error = %e, "failed to build s2s tokio runtime");
                        return;
                    }
                };

                runtime.block_on(async move {
                    self.run_runtime(server, shutdown, gateways).await;
                });
            });

        match thread {
            Ok(thread) => S2SRuntimeTask {
                thread: Some(thread),
                native_tasks: vec![native_gateway_task],
            },
            Err(e) => {
                warn!(error = %e, "failed to spawn s2s runtime thread");
                S2SRuntimeTask {
                    thread: None,
                    native_tasks: vec![native_gateway_task],
                }
            }
        }
    }

    async fn run_runtime(
        self: Arc<Self>,
        server: Weak<Box<Server>>,
        mut shutdown: watch::Receiver<()>,
        gateways: S2SGateways,
    ) {
        if !self.enabled {
            self.clear_gateway_tx();
            drop(gateways);
            let _ = shutdown.changed().await;
            return;
        }

        if let Some(error) = &self.config_error {
            warn!(error = %error, "s2s startup skipped");
            self.clear_gateway_tx();
            drop(gateways);
            let _ = shutdown.changed().await;
            return;
        }

        let Some(transport_config) = self.transport_config.clone() else {
            warn!("s2s startup skipped: no transport config");
            self.clear_gateway_tx();
            drop(gateways);
            let _ = shutdown.changed().await;
            return;
        };

        let (transport, inbound) = match ConnectionManager::start(transport_config).await {
            Ok(parts) => parts,
            Err(e) => {
                warn!(error = %e, "s2s transport startup failed");
                self.clear_gateway_tx();
                drop(gateways);
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
                self.clear_gateway_tx();
                drop(gateways);
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
        let S2SGateways {
            native_tx,
            s2s_tx,
            s2s_rx,
            native_runtime,
        } = gateways;
        let native_sink = Arc::new(S2SNativeGatewaySink::new(native_tx));
        application.moderation().set_applier(native_sink.clone());
        application.voice().set_audio_sink(native_sink.clone());
        application
            .voice()
            .set_recipient_index(recipient_index.clone());
        application.plugin_data().set_sink(native_sink);

        let (
            channel_replications,
            ban_replication,
            client_replication,
            channel_blob_replications,
            bridge_tasks,
        ) = match server_handle.as_ref() {
            Some(server) => {
                self.register_repositories(
                    Arc::clone(&self),
                    &replications,
                    application.clone(),
                    server,
                    recipient_index.clone(),
                    &native_runtime,
                    s2s_tx.clone(),
                    s2s_rx,
                    shutdown.clone(),
                )
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

        let status_task = self.status_http_listen.and_then(|listen| {
            match status::spawn_status_server(
                listen,
                overlay.clone(),
                transport.clone(),
                shutdown.clone(),
            ) {
                Ok(task) => Some(task),
                Err(error) => {
                    warn!(%listen, %error, "s2s topology HTTP server startup failed");
                    None
                }
            }
        });

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
            state.gateway_tx = None;
            bridge_tasks
        };
        for task in bridge_tasks {
            task.abort();
        }
        if let Some(task) = status_task {
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
        manager: Arc<S2SManager>,
        replications: &Arc<ReplicationManager>,
        application: Arc<application::ApplicationLayer>,
        server: &Arc<Box<Server>>,
        recipient_index: Arc<RecipientIndex>,
        native_runtime: &tokio::runtime::Handle,
        s2s_tx: mpsc::Sender<NativeToS2SCommand>,
        s2s_rx: mpsc::Receiver<NativeToS2SCommand>,
        shutdown: watch::Receiver<()>,
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
            replications.local_boot_epoch(),
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
            bridge_tasks.push(spawn_native_client_replication_bridge(
                native_runtime,
                server.get_clients().clone(),
                s2s_tx.clone(),
                shutdown.clone(),
            ));
            bridge_tasks.push(spawn_s2s_gateway_receiver(
                s2s_rx,
                manager,
                application,
                Some(handle),
                recipient_index.clone(),
            ));
        } else {
            bridge_tasks.push(spawn_s2s_gateway_receiver(
                s2s_rx,
                manager,
                application,
                None,
                recipient_index.clone(),
            ));
        }
        bridge_tasks.push(spawn_native_voice_recipient_index_bridge(
            native_runtime,
            server.get_clients().clone(),
            s2s_tx.clone(),
            shutdown,
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

fn spawn_native_client_replication_bridge(
    runtime: &tokio::runtime::Handle,
    repo: Arc<ClientRepository>,
    tx: mpsc::Sender<NativeToS2SCommand>,
    mut shutdown: watch::Receiver<()>,
) -> JoinHandle<()> {
    let mut rx = repo.subscribe();
    runtime.spawn(async move {
        loop {
            let payload = tokio::select! {
                _ = shutdown.changed() => return,
                next = rx.recv() => next,
            };
            match payload {
                Ok(payload) => {
                    let entry = payload.entry.clone();
                    if entry.node_id != repo.local_node_id() {
                        continue;
                    }
                    match tx.try_send(NativeToS2SCommand::ProposeClientReplication(
                        (*entry).clone(),
                    )) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            warn!(
                                version = entry.version,
                                "s2s client replication gateway full; dropping proposal"
                            );
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => return,
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

fn spawn_native_voice_recipient_index_bridge(
    runtime: &tokio::runtime::Handle,
    repo: Arc<ClientRepository>,
    tx: mpsc::Sender<NativeToS2SCommand>,
    mut shutdown: watch::Receiver<()>,
) -> JoinHandle<()> {
    let mut rx = repo.subscribe();
    runtime.spawn(async move {
        enqueue_voice_recipient_index_snapshot(&repo, &tx).await;
        loop {
            let payload = tokio::select! {
                _ = shutdown.changed() => return,
                next = rx.recv() => next,
            };
            match payload {
                Ok(_) => {
                    enqueue_voice_recipient_index_snapshot(&repo, &tx).await;
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "s2s voice recipient index bridge lagged");
                    enqueue_voice_recipient_index_snapshot(&repo, &tx).await;
                }
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    })
}

async fn enqueue_voice_recipient_index_snapshot(
    repo: &Arc<ClientRepository>,
    tx: &mpsc::Sender<NativeToS2SCommand>,
) {
    let snapshot = repo.voice_recipient_index_snapshot().await;
    match tx.try_send(NativeToS2SCommand::RefreshVoiceRecipientIndex(snapshot)) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            warn!("s2s voice recipient index gateway full; dropping snapshot");
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {}
    }
}

fn spawn_s2s_gateway_receiver(
    mut rx: mpsc::Receiver<NativeToS2SCommand>,
    manager: Arc<S2SManager>,
    application: Arc<application::ApplicationLayer>,
    client_handle: Option<replications::OwnerHandle<ClientReplicationAdapter>>,
    recipient_index: Arc<RecipientIndex>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(command) = rx.recv().await {
            match command {
                NativeToS2SCommand::ProposeChannel {
                    server_id,
                    op,
                    respond,
                } => {
                    let _ = respond.send(manager.propose_channel_op_direct(&server_id, op).await);
                }
                NativeToS2SCommand::ProposeBan { op, respond } => {
                    let _ = respond.send(manager.propose_ban_op_direct(op).await);
                }
                NativeToS2SCommand::ProposeClientReplication(entry) => {
                    let Some(handle) = client_handle.as_ref() else {
                        warn!(
                            version = entry.version,
                            "s2s client replication gateway has no owner handle; dropping proposal"
                        );
                        continue;
                    };
                    if let Err(e) = handle.propose(entry).await {
                        warn!(error = %e, "s2s client replication propose failed");
                    }
                }
                NativeToS2SCommand::RefreshVoiceRecipientIndex(snapshot) => {
                    recipient_index.replace_all(snapshot);
                }
                NativeToS2SCommand::DispatchPluginData { owner, envelope } => {
                    if let Err(e) = application.plugin_data().dispatch(owner, envelope).await {
                        warn!(error = %e, owner, "plugin data dispatch failed");
                    }
                }
                NativeToS2SCommand::DispatchModeration { owner, envelope } => {
                    if let Err(e) = application
                        .moderation()
                        .dispatch_envelope_for_gateway(owner, envelope)
                        .await
                    {
                        warn!(error = %e, owner, "moderation dispatch failed");
                    }
                }
                NativeToS2SCommand::DispatchUserStats {
                    owner,
                    actor_session,
                    target_session,
                    stats_only,
                    server_id,
                    respond,
                } => {
                    let result = application
                        .user_stats()
                        .dispatch_request(
                            owner,
                            actor_session,
                            target_session,
                            stats_only,
                            server_id,
                            None,
                        )
                        .await;
                    let _ = respond.send(result);
                }
                NativeToS2SCommand::SendVoiceForChannel {
                    sender_session,
                    server_id,
                    source_channel,
                    is_terminator,
                    payload,
                } => {
                    if let Err(e) = application
                        .voice()
                        .send_for_channel(
                            sender_session,
                            server_id,
                            source_channel,
                            is_terminator,
                            payload,
                        )
                        .await
                    {
                        trace!(error = %e, "voice s2s send_for_channel failed");
                    }
                }
                NativeToS2SCommand::SendVoiceBroadcast {
                    sender_session,
                    server_id,
                    target_kind,
                    is_terminator,
                    payload,
                    intent,
                } => {
                    if let Err(e) = application
                        .voice()
                        .send_broadcast(
                            sender_session,
                            server_id,
                            target_kind,
                            is_terminator,
                            payload,
                            intent,
                        )
                        .await
                    {
                        trace!(error = %e, "voice s2s send_broadcast failed");
                    }
                }
            }
        }
    })
}

async fn run_native_gateway(
    server: Weak<Box<Server>>,
    mut rx: mpsc::Receiver<S2SNativeCommand>,
    mut shutdown: watch::Receiver<()>,
) {
    loop {
        let command = tokio::select! {
            _ = shutdown.changed() => return,
            next = rx.recv() => match next {
                Some(command) => command,
                None => return,
            },
        };
        let Some(server) = server.upgrade() else {
            return;
        };
        match command {
            S2SNativeCommand::ApplyModeration { from, envelope } => {
                apply_s2s_moderation(&server, from, envelope).await;
            }
            S2SNativeCommand::DeliverPluginData { from, envelope } => {
                trace!(from, "s2s plugin data handed to native gateway");
                application::plugin_data::runtime::deliver_to_local_recipients(&server, envelope)
                    .await;
            }
            S2SNativeCommand::DeliverVoice {
                from_immediate,
                frame,
            } => {
                crate::voice::route_s2s_voice_frame(&server, from_immediate, frame).await;
            }
        }
    }
}

struct S2SNativeGatewaySink {
    tx: mpsc::Sender<S2SNativeCommand>,
}

impl S2SNativeGatewaySink {
    fn new(tx: mpsc::Sender<S2SNativeCommand>) -> Self {
        Self { tx }
    }

    fn try_send(&self, command: S2SNativeCommand, label: &'static str) {
        match self.tx.try_send(command) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(label, "s2s native gateway full; dropping command");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                trace!(label, "s2s native gateway closed; dropping command");
            }
        }
    }
}

#[async_trait]
impl ModerationApplier for S2SNativeGatewaySink {
    async fn apply(&self, from: NodeIdentifier, envelope: ModerationEnvelope) {
        self.try_send(
            S2SNativeCommand::ApplyModeration { from, envelope },
            "moderation",
        );
    }
}

#[async_trait]
impl AudioSink for S2SNativeGatewaySink {
    async fn deliver(&self, from_immediate: NodeIdentifier, frame: VoiceFrame) {
        self.try_send(
            S2SNativeCommand::DeliverVoice {
                from_immediate,
                frame,
            },
            "voice",
        );
    }
}

#[async_trait]
impl application::plugin_data::PluginDataSink for S2SNativeGatewaySink {
    async fn deliver(&self, from: NodeIdentifier, envelope: PluginDataEnvelope) {
        self.try_send(
            S2SNativeCommand::DeliverPluginData { from, envelope },
            "plugin_data",
        );
    }
}

async fn apply_s2s_moderation(
    server: &Arc<Box<Server>>,
    from: NodeIdentifier,
    envelope: ModerationEnvelope,
) {
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
            apply_user_state_patch(server, &server_id, envelope.actor_session, target_id, patch)
                .await;
        }
        Some(ModerationCommand::UserRemove(patch)) => {
            apply_user_remove_patch(server, &server_id, envelope.actor_session, target_id, patch)
                .await;
        }
        None => {
            trace!(from, "s2s moderation ignored: empty command");
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
    let actor = ClientSessionIdentifier::from(actor_session);
    let Some(actor_client) = server
        .get_clients()
        .get_client_in_server(server_id, actor)
        .await
    else {
        return;
    };
    if !crate::client::visibility::can_view_user(server, &actor_client, &target).await {
        return;
    }

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

    let has_channel_dependency = patch.channel_id.is_some()
        || patch.mute.is_some()
        || patch.deaf.is_some()
        || patch.suppress.is_some()
        || patch.priority_speaker.is_some()
        || !patch.listening_channel_add.is_empty()
        || !patch.listening_channel_remove.is_empty();
    let channel_version_dep =
        has_channel_dependency.then(|| server.get_channels().current_version_in_server(server_id));
    let should_stage_channel_cache = patch.channel_id.is_some()
        || !patch.listening_channel_add.is_empty()
        || !patch.listening_channel_remove.is_empty();
    let channel_cache_key = if should_stage_channel_cache {
        crate::user_channel_cache::cache_key_for_client(target.as_ref()).await
    } else {
        None
    };
    let mut cache_listening_channel_ids = None;
    {
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
        if let Some(priority_speaker) = patch.priority_speaker {
            if gs.is_priority_speaker() != priority_speaker {
                gs.set_priority_speaker(priority_speaker);
            }
        }
        if let Some(channel_id) = patch.channel_id {
            gs.set_current_channel_id(channel_id);
        }
        if let Some(suppress) = patch.suppress {
            if gs.is_suppressed() != suppress {
                gs.set_suppress(suppress);
            }
        }
        for channel_id in &patch.listening_channel_add {
            gs.listen_channel(*channel_id);
        }
        for channel_id in &patch.listening_channel_remove {
            gs.unlisten_channel(*channel_id);
        }
        if !patch.listening_channel_add.is_empty() || !patch.listening_channel_remove.is_empty() {
            cache_listening_channel_ids = Some(
                gs.get_listening_channel_id()
                    .iter()
                    .copied()
                    .collect::<Vec<_>>(),
            );
        }
    }

    if let Some(cache_key) = channel_cache_key.as_deref() {
        if let Some(channel_id) = patch.channel_id {
            if let Err(error) = server
                .get_user_channel_cache()
                .remember_last_channel(cache_key, channel_id)
                .await
            {
                tracing::warn!(
                    error = %error,
                    cache_key,
                    "failed to stage user last channel cache"
                );
            }
        }
        if let Some(channel_ids) = cache_listening_channel_ids {
            if let Err(error) = server
                .get_user_channel_cache()
                .remember_listening_channels(cache_key, channel_ids)
                .await
            {
                tracing::warn!(
                    error = %error,
                    cache_key,
                    "failed to stage user listening channel cache"
                );
            }
        }
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
    let actor = ClientSessionIdentifier::from(actor_session);
    let Some(actor_client) = server
        .get_clients()
        .get_client_in_server(server_id, actor)
        .await
    else {
        return;
    };
    if !crate::client::visibility::can_view_user(server, &actor_client, &target).await {
        return;
    }

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

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
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
    #[serde(default)]
    freshness: i64,
}

#[async_trait]
impl StrictReplicable for ChannelReplicationAdapter {
    type Op = ChannelOperation;

    fn current_version(&self) -> u64 {
        self.repo.current_version_in_server(&self.server_id)
    }

    fn history_metadata(&self) -> replications::strict::HistoryMetadata {
        replications::strict::HistoryMetadata {
            version: self.repo.current_version_in_server(&self.server_id),
            freshness: self.repo.latest_timestamp_in_server(&self.server_id),
        }
    }

    fn snapshot(&self) -> (u64, Bytes) {
        let version = self.repo.current_version_in_server(&self.server_id);
        let repo = self.repo.clone();
        let server_id = self.server_id.clone();
        let channels =
            block_in_place_or_current(|handle| handle.block_on(repo.get_all_in_server(&server_id)))
                .unwrap_or_default();
        let freshness = self.repo.latest_timestamp_in_server(&self.server_id);
        let bytes = Bytes::from(
            rmp_serde::to_vec(&ChannelSnapshot {
                channels,
                freshness,
            })
            .unwrap_or_default(),
        );
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
            .install_s2s_snapshot_in_server(
                &self.server_id,
                version,
                decoded.channels,
                decoded.freshness,
            )
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
    #[serde(default)]
    freshness: i64,
}

#[async_trait]
impl StrictReplicable for BanReplicationAdapter {
    type Op = BanOperation;

    fn current_version(&self) -> u64 {
        self.repo.current_version()
    }

    fn history_metadata(&self) -> replications::strict::HistoryMetadata {
        replications::strict::HistoryMetadata {
            version: self.repo.current_version(),
            freshness: self.repo.latest_timestamp(),
        }
    }

    fn snapshot(&self) -> (u64, Bytes) {
        let version = self.repo.current_version();
        let repo = self.repo.clone();
        let entries = block_in_place_or_current(|handle| handle.block_on(repo.get_active_bans()))
            .unwrap_or_default();
        let freshness = self.repo.latest_timestamp();
        let bytes =
            Bytes::from(rmp_serde::to_vec(&BanSnapshot { entries, freshness }).unwrap_or_default());
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
            .install_s2s_snapshot(version, decoded.entries, decoded.freshness)
            .await;
    }
}

#[derive(Clone)]
struct ClientReplicationAdapter {
    clients: Arc<ClientRepository>,
    channels: Arc<ChannelRepository>,
    local_epoch: u64,
}

impl ClientReplicationAdapter {
    fn new(
        clients: Arc<ClientRepository>,
        channels: Arc<ChannelRepository>,
        local_epoch: u64,
    ) -> Self {
        Self {
            clients,
            channels,
            local_epoch,
        }
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
        let local_node = self.clients.local_node_id();
        let local_epoch = self.local_epoch;
        block_in_place_or_current(|handle| {
            let (_, versions) = handle.block_on(clients.snapshot_with_versions());
            versions
                .get(&local_node)
                .copied()
                .map(|version| HashMap::from([(local_node, (local_epoch, version))]))
                .unwrap_or_default()
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
            Some((self.local_epoch, version, bytes))
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

    async fn remove_origin(&self, origin: NodeIdentifier) {
        if origin != self.clients.local_node_id() {
            self.clients.clear_clients_from_node(origin).await;
        }
    }
}

fn block_in_place_or_current<T>(f: impl FnOnce(&tokio::runtime::Handle) -> T) -> Option<T> {
    let handle = tokio::runtime::Handle::try_current().ok()?;
    Some(tokio::task::block_in_place(|| f(&handle)))
}
