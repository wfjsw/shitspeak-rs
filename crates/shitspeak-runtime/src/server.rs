use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, RwLock as StdRwLock, Weak};

use bytes::{Bytes, BytesMut};
use parking_lot::{Mutex, RwLock as ParkingRwLock};

use cidr::AnyIpCidr;
use prost::{EncodeError, Message as _};
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::api::{Authenticator, ReloadableAuthenticator};
use crate::blob_store::{ChannelBlobStore, SessionBlobStore};
use crate::client::Client;
use crate::errors::MessageHandlerError;
use crate::geoip::{GeoIpResolver, IpGeoMetadata};
use crate::messages::encoder::Version;
use crate::user_channel_cache::UserChannelCache;
use crate::voice::dispatch_tuning::VoiceDispatchPlan;
use crate::{
    client_repository::ClientRepository,
    codec_info::CodecInfo,
    constants::MTU,
    s2s::S2SManager,
    types::{NodeIdentifier, default_server_id},
};
use shitspeak_runtime_config::{CertificateHashProtection, Config, UdpPingUserCountScope};
use shitspeak_state::{
    ChannelOp, ChannelRepoTuning, ChannelRepository, ChannelRepositoryObserver, ChannelRootConfig,
};

mod auth_finalization;
pub(crate) mod client_projection;
mod client_projection_pool;
mod connection;
mod entrypoints;
mod extensions;
pub(crate) mod sharded_subscriber;
mod tls;
mod udp_recv_batch;

#[cfg(test)]
mod tests;

pub use auth_finalization::AuthFinalizationPermit;
#[cfg(test)]
pub(crate) use auth_finalization::AuthFinalizationTestGateHandle;
pub use extensions::{
    AlpnConnectionInfo, ServerExtension, ServerExtensionFuture, ServerExtensions,
};

use auth_finalization::AuthFinalizationQueue;
use connection::sorted_channel_ids;
use entrypoints::{
    EntrypointBindings, EntrypointListenSpec, EntrypointRuntime, ServerTcpListener, UdpPacket,
    UdpPacketPool, bind_entrypoint_socket_pair, bind_entrypoints, entrypoint_config_routes,
};
use tls::{load_c2s_tls_acceptor, validate_privacy_config};
use udp_recv_batch::{VOICE_UDP_RECV_BATCH_MAX_DATAGRAMS, VoiceUdpRecvBatch, recv_voice_udp_batch};

const UDP_PROCESSING_MIN_BASELINE_CAPACITY: usize = 1024;
const UDP_PROCESSING_PACKETS_PER_USER_BASELINE: usize = 16;
const UDP_PROCESSING_BURST_MULTIPLIER: usize = 5;
const UDP_PROCESSING_MIN_HARD_CAPACITY: usize =
    UDP_PROCESSING_MIN_BASELINE_CAPACITY * UDP_PROCESSING_BURST_MULTIPLIER;
const UDP_PROCESSING_PACKETS_PER_USER_HARD_CAP: usize = 128;

fn validate_visibility_config(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    if config.hide_channels_without_traverse && !config.hide_users_without_traverse {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "hide_channels_without_traverse requires hide_users_without_traverse",
        )));
    }
    Ok(())
}

fn channel_repo_tuning(config: &Config) -> ChannelRepoTuning {
    ChannelRepoTuning {
        log_max_entries: config.channel_log_max_entries.max(1),
        snapshot_every_ops: config.channel_snapshot_every_ops.max(1),
        snapshot_every_secs: config.channel_snapshot_every_secs.max(1),
        wal_compaction_expire_count: config.channel_wal_compaction_expire_count,
    }
}

fn channel_root_config(config: &Config) -> ChannelRootConfig {
    ChannelRootConfig::new(config.root_channel_name.clone())
}

struct ClientRepositoryChannelObserver {
    clients: Weak<ClientRepository>,
}

#[async_trait::async_trait]
impl ChannelRepositoryObserver for ClientRepositoryChannelObserver {
    async fn channel_version_advanced(&self, server_id: &str, channel_version: u64) {
        if let Some(clients) = self.clients.upgrade() {
            clients.drain_pending_ops(server_id, channel_version).await;
        }
    }

    async fn repair_missing_channels(
        &self,
        server_id: &str,
        valid_channel_ids: &HashSet<u32>,
        channel_version: u64,
    ) -> usize {
        let Some(clients) = self.clients.upgrade() else {
            return 0;
        };

        let mut repaired = 0;
        for client in clients.get_local_clients_in_server(server_id).await {
            let missing_listeners: Vec<u32> = client
                .get_listening_channel_ids()
                .into_iter()
                .filter(|channel_id| !valid_channel_ids.contains(channel_id))
                .collect();
            let missing_current = !valid_channel_ids.contains(&client.get_current_channel_id());
            if !missing_current && missing_listeners.is_empty() {
                continue;
            }

            let mut state = client.write_global_state_as(
                &clients,
                Some(client.get_session_id()),
                Some(channel_version),
            );
            if missing_current {
                state.set_current_channel_id(0);
            }
            for channel_id in missing_listeners {
                state.unlisten_channel(channel_id);
            }
            repaired += 1;
        }
        repaired
    }
}

#[cfg(test)]
use auth_finalization::{AuthFinalizationAdmission, should_send_auth_finalization_queue_notice};
#[cfg(test)]
use connection::{activate_client_projection, activate_client_subscriptions};
#[cfg(test)]
use entrypoints::{
    DYNAMIC_ENTRYPOINT_MAX_PORT, DYNAMIC_ENTRYPOINT_MIN_PORT, dynamic_bind_error_is_retryable,
    dynamic_entrypoint_bind_candidate, register_sni_entrypoints,
};
#[cfg(test)]
use tls::{c2s_cipher_suite_provides_pfs, c2s_pfs_tls_provider, load_c2s_tls_config};
pub struct Server {
    node_identifier: NodeIdentifier,

    // Shared config — can be hot-reloaded at runtime
    config: Arc<StdRwLock<Config>>,
    voice_dispatch_plan: VoiceDispatchPlan,

    allowed_proxies: Vec<AnyIpCidr>,

    tls_acceptor: ParkingRwLock<TlsAcceptor>,
    extensions: ServerExtensions,
    entrypoints: Arc<ParkingRwLock<EntrypointBindings>>,
    entrypoint_runtime: Mutex<Option<EntrypointRuntime>>,
    entrypoint_reload_lock: tokio::sync::Mutex<()>,

    clients: Arc<ClientRepository>,
    channels: Arc<ChannelRepository>,
    visibility_fanout_index: Arc<crate::client::visibility::VisibilityFanoutIndex>,
    auth_finalization_queue: Arc<AuthFinalizationQueue>,
    crypt_setup_semaphore: Arc<tokio::sync::Semaphore>,
    channel_blobs: Arc<ChannelBlobStore>,
    session_blobs: Arc<SessionBlobStore>,
    user_channel_cache: Arc<UserChannelCache>,
    bans: Arc<shitspeak_state::BanRepository>,

    codec_info: Mutex<CodecInfo>,

    /// Registry of server-defined context menu actions.
    context_actions: Arc<crate::context_action::ContextActionRegistry>,

    s2s_manager: Arc<S2SManager>,
    geoip_resolver: ParkingRwLock<Arc<GeoIpResolver>>,
    shutdown_tx: tokio::sync::watch::Sender<()>,
    visibility_reload_tx: broadcast::Sender<()>,
    client_projection_pool: std::sync::OnceLock<client_projection_pool::ClientProjectionPool>,
}

impl Server {
    pub async fn new<A: Authenticator>(
        config: Config,
        authenticator: A,
    ) -> Result<Arc<Box<Self>>, Box<dyn std::error::Error>> {
        Self::new_with_extensions(config, authenticator, ServerExtensions::default()).await
    }

    pub async fn new_with_extensions<A: Authenticator>(
        config: Config,
        authenticator: A,
        extensions: ServerExtensions,
    ) -> Result<Arc<Box<Self>>, Box<dyn std::error::Error>> {
        Self::new_with_reloadable_authenticator_and_extensions(
            config,
            ReloadableAuthenticator::fixed(authenticator),
            extensions,
        )
        .await
    }

    pub async fn new_with_reloadable_authenticator(
        config: Config,
        authenticator: ReloadableAuthenticator,
    ) -> Result<Arc<Box<Self>>, Box<dyn std::error::Error>> {
        Self::new_with_reloadable_authenticator_and_extensions(
            config,
            authenticator,
            ServerExtensions::default(),
        )
        .await
    }

    pub async fn new_with_reloadable_authenticator_and_extensions(
        config: Config,
        authenticator: ReloadableAuthenticator,
        extensions: ServerExtensions,
    ) -> Result<Arc<Box<Self>>, Box<dyn std::error::Error>> {
        Self::new_with_reloadable_authenticator_and_extensions_and_voice_dispatch_plan(
            config,
            authenticator,
            extensions,
            VoiceDispatchPlan::conservative(),
        )
        .await
    }

    pub(crate) async fn new_with_reloadable_authenticator_and_extensions_and_voice_dispatch_plan(
        config: Config,
        authenticator: ReloadableAuthenticator,
        extensions: ServerExtensions,
        voice_dispatch_plan: VoiceDispatchPlan,
    ) -> Result<Arc<Box<Self>>, Box<dyn std::error::Error>> {
        Version::cache_server_os_info();

        let allowed_proxies = config
            .allowed_proxies
            .iter()
            .map(|proxy| AnyIpCidr::from_str(proxy))
            .collect::<Result<Vec<_>, _>>()?;
        validate_visibility_config(&config)?;
        validate_privacy_config(&config)?;

        let tls_acceptor = load_c2s_tls_acceptor(&config, &extensions)?;

        let entrypoints = bind_entrypoints(&config).await?;

        // ── Channel repository & blob stores ─────────────────────────────
        let node_id = config.local_node_id().map_err(std::io::Error::other)?;
        let client_log_max_entries = config.client_log_max_entries;
        let auth_finalization_concurrency = config.auth_finalization_concurrency.max(1);
        let channel_repo_tuning = channel_repo_tuning(&config);
        let channel_root_config = channel_root_config(&config);
        let (channels, channel_blobs, session_blobs, user_channel_cache, bans) = match &config
            .blob_storage_dir
        {
            Some(dir) => {
                let ch_repo =
                    ChannelRepository::open(node_id, dir, channel_root_config, channel_repo_tuning)
                        .await?;
                let ch_blobs = Arc::new(ChannelBlobStore::open(dir).await?);
                let s_blobs = Arc::new(SessionBlobStore::open(dir).await?);
                let user_channel_cache = UserChannelCache::open(dir).await?;
                let ban_repo = shitspeak_state::BanRepository::open(node_id, dir).await?;
                (ch_repo, ch_blobs, s_blobs, user_channel_cache, ban_repo)
            }
            None => {
                // In-memory mode: use a temp dir for blob stores so the
                // code paths are uniform; blobs won't survive restarts.
                let tmp = std::env::temp_dir().join("shitspeak-blobs");
                let ch_repo = ChannelRepository::new_in_memory(
                    node_id,
                    channel_root_config,
                    channel_repo_tuning,
                );
                let ch_blobs = Arc::new(ChannelBlobStore::open(&tmp).await?);
                let s_blobs = Arc::new(SessionBlobStore::open(&tmp).await?);
                let user_channel_cache = UserChannelCache::new_in_memory();
                let ban_repo = shitspeak_state::BanRepository::new_in_memory(node_id);
                (ch_repo, ch_blobs, s_blobs, user_channel_cache, ban_repo)
            }
        };

        let config = Arc::new(StdRwLock::new(config));
        let s2s_manager = Arc::new(S2SManager::initialize(
            &config.read().expect("Config RwLock poisoned"),
        ));
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(());
        let (visibility_reload_tx, _visibility_reload_rx) = broadcast::channel(64);

        let server = Arc::new(Box::new(Server {
            node_identifier: node_id,
            voice_dispatch_plan,
            allowed_proxies,
            tls_acceptor: ParkingRwLock::new(tls_acceptor),
            extensions,
            entrypoints: Arc::new(ParkingRwLock::new(entrypoints)),
            entrypoint_runtime: Mutex::new(None),
            entrypoint_reload_lock: tokio::sync::Mutex::new(()),
            clients: Arc::new(ClientRepository::new(node_id, client_log_max_entries)),
            channels,
            visibility_fanout_index: Arc::new(
                crate::client::visibility::VisibilityFanoutIndex::new(),
            ),
            auth_finalization_queue: Arc::new(AuthFinalizationQueue::new(
                auth_finalization_concurrency,
                authenticator,
            )),
            crypt_setup_semaphore: Arc::new(tokio::sync::Semaphore::new(
                auth_finalization_concurrency,
            )),
            channel_blobs,
            session_blobs,
            user_channel_cache,
            bans,
            codec_info: Mutex::new(CodecInfo::default()),
            config: Arc::clone(&config),
            context_actions: Arc::new(crate::context_action::ContextActionRegistry::new()),
            s2s_manager,
            geoip_resolver: ParkingRwLock::new(Arc::new(GeoIpResolver::new(
                config.read().expect("Config RwLock poisoned").geoip.clone(),
            ))),
            shutdown_tx,
            visibility_reload_tx,
            client_projection_pool: std::sync::OnceLock::new(),
        }));

        let projection_pool = client_projection_pool::ClientProjectionPool::spawn(
            Arc::downgrade(&server),
            server.clients.subscribe(),
            server.channels.subscribe(),
            server.subscribe_visibility_reload(),
        )?;
        server
            .client_projection_pool
            .set(projection_pool)
            .map_err(|_| std::io::Error::other("client projection pool initialized twice"))?;

        // Wire cross-repo causal notification: ChannelRepository notifies
        // ClientRepository to drain pending ops after remote channel ops.
        server
            .channels
            .set_observer(Arc::new(ClientRepositoryChannelObserver {
                clients: Arc::downgrade(&server.clients),
            }));

        Ok(server)
    }

    /// Read the current config (acquires a read lock).
    pub fn read_config(&self) -> std::sync::RwLockReadGuard<'_, Config> {
        self.config.read().expect("Config RwLock poisoned")
    }

    pub(crate) fn voice_dispatch_plan(&self) -> VoiceDispatchPlan {
        self.voice_dispatch_plan
    }

    /// Local TCP listen address. Useful for tests that bind to `127.0.0.1:0`.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        let entrypoints = self.entrypoints.read();
        entrypoints
            .tcp_listeners
            .first()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no TCP listeners"))?
            .listener
            .local_addr()
    }

    /// Local UDP listen address. Useful for tests that bind to `127.0.0.1:0`.
    pub fn local_udp_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        let entrypoints = self.entrypoints.read();
        entrypoints
            .udp_sockets
            .first()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no UDP sockets"))?
            .local_addr()
    }

    pub fn shutdown_receiver(&self) -> tokio::sync::watch::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Subscribe to live visibility-policy changes. Each active transport
    /// keeps its own channel/user shadows, so it must reconcile locally when
    /// either hide flag changes during a config reload.
    pub fn subscribe_visibility_reload(&self) -> broadcast::Receiver<()> {
        self.visibility_reload_tx.subscribe()
    }

    pub(crate) fn client_projection_pool(&self) -> &client_projection_pool::ClientProjectionPool {
        self.client_projection_pool
            .get()
            .expect("client projection pool must be initialized before Server is returned")
    }

    pub async fn lookup_ip_geo_metadata(&self, ip: std::net::IpAddr) -> Option<IpGeoMetadata> {
        let resolver = self.geoip_resolver.read().clone();
        resolver.lookup_ip_metadata(ip).await
    }

    pub fn authenticator_watch_paths(&self) -> Vec<PathBuf> {
        let config = self.read_config();
        let mut paths = Vec::new();
        if let Some(path) = config.authenticator.wasm().path() {
            paths.push(path.clone());
        }
        if let Some(path) = config.authenticator.exec().command() {
            paths.push(path.clone());
        }
        paths
    }

    pub fn c2s_tls_identity_paths(&self) -> (PathBuf, PathBuf) {
        let config = self.read_config();
        (
            PathBuf::from(&config.cert_path),
            PathBuf::from(&config.key_path),
        )
    }

    fn replace_c2s_tls_acceptor(&self, tls_acceptor: TlsAcceptor) {
        *self.tls_acceptor.write() = tls_acceptor;
    }

    fn reload_c2s_tls_identity(
        &self,
        new_config: &Config,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let tls_acceptor = load_c2s_tls_acceptor(new_config, &self.extensions)?;
        self.replace_c2s_tls_acceptor(tls_acceptor);
        Ok(())
    }

    pub fn authenticator_arc(&self) -> Arc<dyn Authenticator> {
        self.auth_finalization_queue.authenticator_arc()
    }

    pub async fn run(self: &Arc<Box<Self>>) -> Result<(), Box<dyn std::error::Error>> {
        let mut shutdown_rx = self.shutdown_receiver();
        let listen_addrs: Vec<String> = {
            let entrypoints = self.entrypoints.read();
            entrypoints
                .tcp_listeners
                .iter()
                .filter_map(|entry| entry.listener.local_addr().ok())
                .map(|addr| addr.to_string())
                .collect()
        };
        tracing::info!("Server is running on {}", listen_addrs.join(", "));
        self.s2s_manager.log_startup_summary();

        // Snapshot startup-only config values (cannot be hot-reloaded).
        let (
            configured_udp_channel_size,
            max_users,
            udp_voice_enabled,
            udp_ping_enabled,
            idle_timeout_secs,
            pending_delete_timeout_ms,
        ) = {
            let config = self.read_config();
            (
                config.udp_channel_size,
                config.max_users,
                config.udp_voice_enabled,
                config.udp_ping_enabled,
                config.client_idle_timeout_secs,
                config.pending_delete_timeout_ms,
            )
        };
        let udp_channel_size =
            effective_udp_processing_channel_size(configured_udp_channel_size, max_users);
        tracing::debug!(
            configured_udp_channel_size,
            max_users,
            udp_channel_size,
            "native UDP processing channel sized"
        );

        // Bounded channel shared between UDP drain and processing tasks.
        let (udp_in, udp_out) = tokio::sync::mpsc::channel::<UdpPacket>(udp_channel_size);
        let udp_packet_pool = UdpPacketPool::new(
            MTU,
            udp_channel_size.saturating_add(VOICE_UDP_RECV_BATCH_MAX_DATAGRAMS),
        );

        // Internal shutdown channel: used to signal all spawned tasks regardless
        // of whether shutdown originated from the external signal or a task dying.
        let (internal_tx, internal_rx) = tokio::sync::watch::channel(());

        {
            let mut runtime = self.entrypoint_runtime.lock();
            *runtime = Some(EntrypointRuntime {
                udp_in: udp_in.clone(),
                udp_packet_pool: udp_packet_pool.clone(),
                udp_voice_enabled,
                udp_ping_enabled,
                shutdown: internal_rx.clone(),
            });
        }
        let mut udp_process = Self::spawn_udp_process(
            Arc::clone(self),
            udp_out,
            udp_ping_enabled,
            internal_rx.clone(),
        );
        self.spawn_entrypoint_tasks_for_existing_bindings(&udp_in, &udp_packet_pool, &internal_rx);
        let mut idle_reaper =
            Self::spawn_idle_reaper(Arc::clone(self), idle_timeout_secs, internal_rx.clone());
        let mut pending_delete_watchdog = Self::spawn_pending_delete_watchdog(
            Arc::clone(self),
            pending_delete_timeout_ms,
            internal_rx.clone(),
        );
        let mut extension_tasks = JoinSet::<()>::new();
        self.extensions
            .spawn_tasks(Arc::clone(self), internal_rx.clone(), &mut extension_tasks)?;
        let s2s_task = Arc::clone(&self.s2s_manager)
            .spawn_runtime_task(Arc::downgrade(self), internal_rx.clone());
        let metrics_source: Arc<dyn crate::observability::S2sMetricsSource> =
            Arc::new(crate::observability::ServerMetricsSource::new(
                self.s2s_manager.clone(),
                self.clients.clone(),
                self.channels.clone(),
            ));
        let observability_metrics_task = {
            let metrics = self.read_config().observability.metrics.clone();
            if metrics.enabled {
                metrics.listen.and_then(|listen| {
                    match crate::observability::spawn_metrics_server(
                        listen,
                        metrics.path.clone(),
                        metrics_source.clone(),
                        internal_rx.clone(),
                    ) {
                        Ok(task) => Some(task),
                        Err(error) => {
                            tracing::warn!(
                                %listen,
                                %error,
                                "observability metrics HTTP server startup failed"
                            );
                            None
                        }
                    }
                })
            } else {
                None
            }
        };
        let observability_remote_write_task = {
            let config = self
                .read_config()
                .observability
                .metrics
                .remote_write
                .clone();
            crate::observability::spawn_remote_write(config, metrics_source, internal_rx.clone())
        };

        // Public server registration (periodic HTTP POST to registry).
        // This task is optional and may exit early when registration is disabled;
        // it must never terminate the main server loop.
        let register_task =
            crate::register::spawn_register_task(Arc::clone(self), internal_rx.clone());

        // Wait for any task to finish (error) or for the caller to request
        // shutdown by sending on the shared watch channel.
        tokio::select! {
            result = &mut udp_process => { let _ = result; }
            result = &mut idle_reaper => { let _ = result; }
            result = &mut pending_delete_watchdog => { let _ = result; }
            result = extension_tasks.join_next(), if !extension_tasks.is_empty() => { let _ = result; }
            _ = shutdown_rx.changed() => {
                tracing::info!("Shutdown signal received.");
            }
        }

        // Ensure every spawned runtime task observes shutdown before joining.
        let _ = internal_tx.send(());

        let _ = udp_process.await;
        let _ = idle_reaper.await;
        let _ = pending_delete_watchdog.await;
        while extension_tasks.join_next().await.is_some() {}
        s2s_task.join().await;
        if let Some(task) = observability_metrics_task {
            let _ = task.await;
        }
        if let Some(task) = observability_remote_write_task {
            let _ = task.await;
        }
        let _ = register_task.await;

        Ok(())
    }

    /// Spawn the UDP drain task: receive packets as fast as possible and
    /// push voice packets into the channel.  Ping packets are handled
    /// directly (responded to immediately).
    fn spawn_udp_drain(
        server: Arc<Box<Self>>,
        socket: Arc<tokio::net::UdpSocket>,
        tx: tokio::sync::mpsc::Sender<UdpPacket>,
        packet_pool: UdpPacketPool,
        voice_enabled: bool,
        ping_enabled: bool,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut batch = VoiceUdpRecvBatch::new(VOICE_UDP_RECV_BATCH_MAX_DATAGRAMS, MTU);
            let local_addr = socket
                .local_addr()
                .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
            tracing::info!("UDP drain started, listening on {}", local_addr);
            loop {
                let received = tokio::select! {
                    result = recv_voice_udp_batch(&socket, &mut batch) => match result {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::warn!("UDP recv error: {e}");
                            continue;
                        }
                    },
                    _ = shutdown.changed() => break,
                };
                crate::voice::metrics::record_udp_recv_batch(received);

                for datagram in batch.iter().take(received) {
                    if shutdown.has_changed().unwrap_or(true) {
                        break;
                    }
                    Self::handle_udp_drain_datagram(
                        &server,
                        &socket,
                        &tx,
                        &packet_pool,
                        local_addr,
                        datagram.payload(),
                        datagram.src_addr(),
                        voice_enabled,
                        ping_enabled,
                    )
                    .await;
                }
            }
            tracing::info!("UDP drain stopped");
        })
    }

    async fn handle_udp_drain_datagram(
        server: &Arc<Box<Self>>,
        socket: &Arc<tokio::net::UdpSocket>,
        tx: &tokio::sync::mpsc::Sender<UdpPacket>,
        packet_pool: &UdpPacketPool,
        local_addr: std::net::SocketAddr,
        packet: &[u8],
        src_addr: std::net::SocketAddr,
        voice_enabled: bool,
        ping_enabled: bool,
    ) {
        if packet.len() <= 1 {
            // Empty packages or packages consisting only of the header byte are invalid.
            crate::voice::metrics::record_udp_drain_drop(
                crate::voice::metrics::UdpDrainDropReason::PacketTooShort,
            );
            return;
        }

        tracing::trace!("UDP received {} bytes from {}", packet.len(), src_addr);

        if ping_enabled {
            match crate::voice::ping::PingRequest::decode(packet) {
                Ok(ping) => {
                    tracing::trace!(
                        "UDP ping from {}: timestamp={}, format={}",
                        src_addr,
                        ping.timestamp,
                        ping.format
                    );
                    let status_server_id =
                        server.udp_ping_status_server_id_for_port(local_addr.port());
                    let reply =
                        match Self::build_ping_response(server, &ping, &status_server_id).await {
                            Ok(r) => r,
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to build UDP ping response for {}: {e}",
                                    src_addr
                                );
                                return;
                            }
                        };
                    match socket.send_to(&reply, src_addr).await {
                        Ok(sent) => {
                            tracing::trace!("UDP ping reply sent to {}: {} bytes", src_addr, sent)
                        }
                        Err(e) => tracing::warn!("UDP ping reply failed to {}: {e}", src_addr),
                    }
                    return;
                }
                Err(crate::voice::codec::DecodeError::NotPing) => {
                    // Not a ping packet, continue with normal processing.
                }
                Err(e) => {
                    crate::voice::metrics::record_udp_drain_drop(
                        crate::voice::metrics::UdpDrainDropReason::PingDecodeFailed,
                    );
                    tracing::trace!("UDP packet decode failed from {}: {e}", src_addr);
                    return;
                }
            }
        }

        if voice_enabled {
            let Some(packet) = packet_pool.copy_packet(packet) else {
                crate::voice::metrics::record_udp_drain_drop(
                    crate::voice::metrics::UdpDrainDropReason::PacketTooLarge,
                );
                tracing::trace!(
                    len = packet.len(),
                    mtu = MTU,
                    "UDP packet exceeds pooled buffer size"
                );
                return;
            };
            let capacity = tx.max_capacity();
            let depth = capacity.saturating_sub(tx.capacity());
            crate::voice::metrics::record_queue_status(
                crate::voice::metrics::VoiceQueueKind::UdpProcessing,
                depth,
                capacity,
            );
            match tx.try_send(UdpPacket::new(packet, src_addr, local_addr)) {
                Ok(()) => {
                    crate::voice::metrics::record_queue_enqueue(
                        crate::voice::metrics::VoiceQueueKind::UdpProcessing,
                        crate::voice::metrics::VoiceQueueEnqueueResult::Accepted,
                    );
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    crate::voice::metrics::record_queue_enqueue(
                        crate::voice::metrics::VoiceQueueKind::UdpProcessing,
                        crate::voice::metrics::VoiceQueueEnqueueResult::Full,
                    );
                    crate::voice::metrics::record_udp_drain_drop(
                        crate::voice::metrics::UdpDrainDropReason::ProcessingQueueFull,
                    );
                    tracing::warn!(
                        "UDP processing channel is full, dropping packet from {}",
                        src_addr
                    );
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    crate::voice::metrics::record_queue_enqueue(
                        crate::voice::metrics::VoiceQueueKind::UdpProcessing,
                        crate::voice::metrics::VoiceQueueEnqueueResult::Closed,
                    );
                    crate::voice::metrics::record_udp_drain_drop(
                        crate::voice::metrics::UdpDrainDropReason::ProcessingQueueClosed,
                    );
                    tracing::warn!("UDP processing channel closed for {}", src_addr);
                }
            }
        } else {
            crate::voice::metrics::record_udp_drain_drop(
                crate::voice::metrics::UdpDrainDropReason::VoiceDisabled,
            );
        }
    }

    /// Spawn the UDP processing task: decrypt, parse, and route voice
    /// packets from the channel.  Ping packets are handled directly.
    fn spawn_udp_process(
        server: Arc<Box<Self>>,
        mut rx: tokio::sync::mpsc::Receiver<UdpPacket>,
        ping_enabled: bool,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let udp_packet = tokio::select! {
                    msg = rx.recv() => match msg {
                        Some(m) => m,
                        None => break,
                    },
                    _ = shutdown.changed() => break,
                };
                let packet_age = udp_packet.enqueue_age();
                crate::voice::metrics::record_packet_age(
                    crate::voice::metrics::VoiceAgeStage::UdpPacket,
                    packet_age,
                );
                crate::voice::metrics::record_scheduler_delay(
                    crate::voice::metrics::VoiceSchedulerStage::UdpProcessing,
                    packet_age,
                );
                if packet_age > server.read_config().voice.max_udp_packet_age() {
                    crate::voice::metrics::record_stale_drop(
                        crate::voice::metrics::VoiceAgeStage::UdpPacket,
                    );
                    continue;
                }
                let (packet, src_addr, local_addr) = udp_packet.into_parts();

                // Try address-based match first.  If the cached entry exists but
                // decrypt fails (stale NAT binding, crypt state re-keyed, etc.)
                // the binding is removed and we fall through to IP-based candidate
                // probing so the packet is not silently dropped.
                let mut decrypted_from_match: Option<Bytes> = None;
                let mut matched_via_ip_fallback = false;
                let mut decrypt_scratch = [0u8; MTU];

                let client = {
                    let lookup_started_at = std::time::Instant::now();
                    let address_match = server
                        .clients
                        .get_client_by_udp_endpoint(local_addr, src_addr)
                        .await;
                    crate::voice::metrics::record_pipeline_stage(
                        crate::voice::metrics::VoicePipelinePath::UdpIngress,
                        crate::voice::metrics::VoicePipelineStage::UdpClientLookup,
                        lookup_started_at.elapsed(),
                    );
                    let mut found = None;

                    if let Some(c) = address_match {
                        let decrypt_result: Option<Result<Bytes, _>> = {
                            let mut crypt = c.crypt_state();
                            crypt.as_mut().map(|state| {
                                let mut dec = BytesMut::new();
                                let decrypt_started_at = std::time::Instant::now();
                                let result = state.decrypt(&mut dec, &packet).map(|_| dec.freeze());
                                crate::voice::metrics::record_pipeline_stage(
                                    crate::voice::metrics::VoicePipelinePath::UdpIngress,
                                    crate::voice::metrics::VoicePipelineStage::UdpDecrypt,
                                    decrypt_started_at.elapsed(),
                                );
                                result
                            })
                        };

                        match decrypt_result {
                            Some(Ok(dec)) => {
                                crate::voice::metrics::record_udp_decrypt(
                                    crate::voice::metrics::UdpDecryptPath::Address,
                                    crate::voice::metrics::UdpDecryptResult::Success,
                                );
                                tracing::trace!(
                                    "UDP client matched by address: {} -> session {:?}",
                                    src_addr,
                                    c.get_session_id()
                                );
                                decrypted_from_match = Some(dec);
                                found = Some(c);
                            }
                            Some(Err(e)) => {
                                crate::voice::metrics::record_udp_decrypt(
                                    crate::voice::metrics::UdpDecryptPath::Address,
                                    crate::voice::metrics::UdpDecryptResult::Failure,
                                );
                                tracing::trace!(
                                    "UDP address-match decrypt failed for {:?} from {}: {:?}, removing stale binding",
                                    c.get_session_id(),
                                    src_addr,
                                    e
                                );
                                server
                                    .clients
                                    .unbind_client_udp_endpoint(local_addr, src_addr);
                            }
                            None => {
                                crate::voice::metrics::record_udp_decrypt(
                                    crate::voice::metrics::UdpDecryptPath::Address,
                                    crate::voice::metrics::UdpDecryptResult::NoCryptState,
                                );
                                tracing::trace!(
                                    "UDP address-matched client {:?} has no crypt state, removing stale binding",
                                    c.get_session_id()
                                );
                                server
                                    .clients
                                    .unbind_client_udp_endpoint(local_addr, src_addr);
                            }
                        }
                    }

                    if found.is_none() {
                        let lookup_started_at = std::time::Instant::now();
                        let candidates = server.clients.get_clients_by_ip(&src_addr.ip()).await;
                        crate::voice::metrics::record_pipeline_stage(
                            crate::voice::metrics::VoicePipelinePath::UdpIngress,
                            crate::voice::metrics::VoicePipelineStage::UdpClientLookup,
                            lookup_started_at.elapsed(),
                        );
                        crate::voice::metrics::record_udp_ip_fallback(candidates.len());
                        let mut matched = None;
                        for c in &candidates {
                            let decrypted = {
                                let mut crypt = c.crypt_state();
                                match crypt.as_mut() {
                                    Some(state) => {
                                        let decrypt_started_at = std::time::Instant::now();
                                        let decrypt_result =
                                            state.decrypt_into(&mut decrypt_scratch, &packet);
                                        crate::voice::metrics::record_pipeline_stage(
                                            crate::voice::metrics::VoicePipelinePath::UdpIngress,
                                            crate::voice::metrics::VoicePipelineStage::UdpDecrypt,
                                            decrypt_started_at.elapsed(),
                                        );
                                        match decrypt_result {
                                            Ok(plain_len) => {
                                                crate::voice::metrics::record_udp_decrypt(
                                                    crate::voice::metrics::UdpDecryptPath::IpFallback,
                                                    crate::voice::metrics::UdpDecryptResult::Success,
                                                );
                                                tracing::trace!(
                                                    "UDP packet from {} successfully decrypted with client {:?} during IP fallback",
                                                    src_addr,
                                                    c.get_session_id()
                                                );
                                                Some(Bytes::copy_from_slice(
                                                    &decrypt_scratch[..plain_len],
                                                ))
                                            }
                                            Err(e) => {
                                                crate::voice::metrics::record_udp_decrypt(
                                                    crate::voice::metrics::UdpDecryptPath::IpFallback,
                                                    crate::voice::metrics::UdpDecryptResult::Failure,
                                                );
                                                tracing::trace!(
                                                    "UDP packet from {} failed to decrypt with client {:?} during IP fallback: {:?}",
                                                    src_addr,
                                                    c.get_session_id(),
                                                    e
                                                );
                                                None
                                            }
                                        }
                                    }
                                    None => {
                                        crate::voice::metrics::record_udp_decrypt(
                                            crate::voice::metrics::UdpDecryptPath::IpFallback,
                                            crate::voice::metrics::UdpDecryptResult::NoCryptState,
                                        );
                                        tracing::trace!(
                                            "UDP client {:?} has no crypt state yet, skipping for IP fallback",
                                            c.get_session_id()
                                        );
                                        None
                                    }
                                }
                            };
                            if let Some(decrypted) = decrypted {
                                matched = Some(c.clone());
                                decrypted_from_match = Some(decrypted);
                                matched_via_ip_fallback = true;
                                break;
                            }
                        }

                        tracing::trace!(
                            "UDP client {} matched by IP fallback: candidates={}, matched={:?}",
                            src_addr,
                            candidates.len(),
                            matched.as_ref().map(|c| c.get_session_id()),
                        );
                        found = matched;
                    }

                    found
                };

                let Some(client) = client else { continue };

                client.record_udp_packet(packet.len()).await;
                client.touch_activity();

                // A valid encrypted UDP packet indicates UDP path is working.
                client.set_prefer_tcp_tunnel(false);

                if matched_via_ip_fallback {
                    tracing::trace!(
                        "Binding UDP address {} to client {:?} after successful IP fallback match",
                        src_addr,
                        client.get_session_id()
                    );

                    server
                        .clients
                        .bind_client_udp_endpoint_in_server(
                            &client.server_id(),
                            client.get_session_id(),
                            Some(local_addr),
                            src_addr,
                        )
                        .await;
                }

                // Packet was already decrypted during client matching.
                let Some(decrypted) = decrypted_from_match else {
                    continue;
                };

                // After decryption, check if this is a ping or audio packet.
                let decode_started_at = std::time::Instant::now();
                let decoded_packet = crate::voice::codec::IncomingUdpPacket::decode_owned(
                    decrypted,
                    Some(client.get_session_id()),
                );
                crate::voice::metrics::record_pipeline_stage(
                    crate::voice::metrics::VoicePipelinePath::UdpIngress,
                    crate::voice::metrics::VoicePipelineStage::UdpPacketDecode,
                    decode_started_at.elapsed(),
                );
                match decoded_packet {
                    Ok(crate::voice::codec::IncomingUdpPacket::Ping(ping)) => {
                        tracing::trace!(
                            "UDP ping from {}: timestamp={}, format={}",
                            src_addr,
                            ping.timestamp,
                            ping.format
                        );
                        let cleartext = match ping.encode_authenticated_echo() {
                            Ok(reply) => reply,
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to encode authenticated UDP ping response for {}: {e}",
                                    src_addr
                                );
                                continue;
                            }
                        };
                        let encrypted = {
                            let mut crypt = client.crypt_state();
                            let Some(state) = crypt.as_mut() else {
                                tracing::warn!(
                                    "no crypt state available for authenticated UDP ping reply to {}",
                                    src_addr
                                );
                                continue;
                            };
                            let mut encrypted = vec![0u8; cleartext.len() + state.overhead()];
                            if let Err(e) = state.encrypt(&mut encrypted, &cleartext) {
                                tracing::warn!(
                                    "Failed to encrypt authenticated UDP ping response for {}: {:?}",
                                    src_addr,
                                    e
                                );
                                continue;
                            }
                            encrypted
                        };
                        let socket = server
                            .udp_socket_for_local_addr(local_addr)
                            .or_else(|| server.default_udp_socket());
                        let Some(socket) = socket else {
                            tracing::warn!("no UDP socket available for ping reply");
                            continue;
                        };
                        match socket.send_to(&encrypted, src_addr).await {
                            Ok(sent) => tracing::trace!(
                                "authenticated UDP ping reply sent to {}: {} bytes",
                                src_addr,
                                sent
                            ),
                            Err(e) => tracing::warn!("UDP ping reply failed to {}: {e}", src_addr),
                        }
                        continue;
                    }
                    Ok(crate::voice::codec::IncomingUdpPacket::Audio(decoded_audio)) => {
                        if !client.is_authenticated() {
                            tracing::trace!(
                                "UDP audio packet from {} matched unauthenticated client {:?}; dropping",
                                src_addr,
                                client.get_session_id()
                            );
                            continue;
                        }
                        crate::voice::metrics::record_ingress(
                            crate::voice::metrics::VoiceIngressTransport::Udp,
                            packet.len(),
                        );
                        crate::voice::metrics::record_native_ingress_event(
                            crate::voice::metrics::VoiceIngressTransport::Udp,
                            matches!(
                                &decoded_audio.audio_payload,
                                crate::voice::codec::AudioPayload::Opus(payload)
                                    if payload.is_terminator
                            ),
                        );
                        tracing::trace!(
                            "UDP audio packet from {}: sender_session={:?}, frame_number={}, format={:?}, payload_len={}",
                            src_addr,
                            decoded_audio.sender_session,
                            decoded_audio.frame_number,
                            decoded_audio.format,
                            decoded_audio.audio_payload.len()
                        );
                        client.push_voice_routing(decoded_audio);
                    }
                    Err(e) => {
                        tracing::trace!("UDP packet decode failed from {}: {e}", src_addr);
                        continue;
                    }
                }
            }
        })
    }

    fn udp_socket_for_local_addr(
        &self,
        local_addr: SocketAddr,
    ) -> Option<Arc<tokio::net::UdpSocket>> {
        self.entrypoints
            .read()
            .udp_socket_by_port
            .get(&local_addr.port())
            .cloned()
    }

    pub fn udp_socket_for_client_addr(
        &self,
        local_addr: SocketAddr,
    ) -> Option<Arc<tokio::net::UdpSocket>> {
        self.udp_socket_for_local_addr(local_addr)
            .or_else(|| self.default_udp_socket())
    }

    pub fn udp_socket_for_client(&self, client: &Client) -> Option<Arc<tokio::net::UdpSocket>> {
        self.udp_socket_for_client_addr(client.get_local_address())
    }

    fn default_udp_socket(&self) -> Option<Arc<tokio::net::UdpSocket>> {
        self.entrypoints.read().udp_sockets.first().cloned()
    }

    /// Spawn the TCP accept loop for one listener.
    fn spawn_tcp_accept(
        server: Arc<Box<Self>>,
        listener: Arc<tokio::net::TcpListener>,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let local_addr = listener
                .local_addr()
                .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
            tracing::info!("TCP accept started, listening on {}", local_addr);
            loop {
                let (tcp_stream, remote_addr) = tokio::select! {
                    result = listener.accept() => match result {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("TCP accept error: {e}");
                            continue;
                        }
                    },
                    _ = shutdown.changed() => break,
                };
                let conn_server = Arc::clone(&server);
                let provisional_server_id =
                    conn_server.provisional_server_id_for_port(local_addr.port());
                tokio::spawn(async move {
                    let _ = conn_server
                        .handle_incoming_connection(tcp_stream, remote_addr, provisional_server_id)
                        .await;
                });
            }
            tracing::info!("TCP accept stopped for {}", local_addr);
        })
    }

    fn provisional_server_id_for_port(&self, port: u16) -> String {
        self.entrypoints
            .read()
            .server_id_by_port
            .get(&port)
            .cloned()
            .unwrap_or_else(default_server_id)
    }

    fn udp_ping_status_server_id_for_port(&self, port: u16) -> String {
        self.entrypoints
            .read()
            .udp_ping_status_server_id_by_port
            .get(&port)
            .cloned()
            .unwrap_or_else(default_server_id)
    }

    fn spawn_entrypoint_tasks_for_existing_bindings(
        self: &Arc<Box<Self>>,
        udp_in: &tokio::sync::mpsc::Sender<UdpPacket>,
        udp_packet_pool: &UdpPacketPool,
        shutdown: &tokio::sync::watch::Receiver<()>,
    ) {
        let (listeners, sockets) = {
            let entrypoints = self.entrypoints.read();
            (
                entrypoints.tcp_listeners.clone(),
                entrypoints.udp_sockets.clone(),
            )
        };

        for entrypoint in listeners {
            Self::spawn_tcp_accept(Arc::clone(self), entrypoint.listener, shutdown.clone());
        }
        for socket in sockets {
            Self::spawn_udp_drain(
                Arc::clone(self),
                socket,
                udp_in.clone(),
                udp_packet_pool.clone(),
                self.read_config().udp_voice_enabled,
                self.read_config().udp_ping_enabled,
                shutdown.clone(),
            );
        }
    }

    fn spawn_entrypoint_tasks_for_new_binding(
        self: &Arc<Box<Self>>,
        listener: Arc<tokio::net::TcpListener>,
        udp_socket: Arc<tokio::net::UdpSocket>,
    ) {
        let Some(runtime) = self.entrypoint_runtime.lock().clone() else {
            return;
        };

        Self::spawn_tcp_accept(Arc::clone(self), listener, runtime.shutdown.clone());
        Self::spawn_udp_drain(
            Arc::clone(self),
            udp_socket,
            runtime.udp_in,
            runtime.udp_packet_pool,
            runtime.udp_voice_enabled,
            runtime.udp_ping_enabled,
            runtime.shutdown,
        );
    }

    async fn apply_entrypoint_config(
        self: &Arc<Box<Self>>,
        new_config: &Config,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _reload_guard = self.entrypoint_reload_lock.lock().await;
        let (server_id_by_sni, listen_specs) = entrypoint_config_routes(new_config)?;
        let default_port = self.entrypoints.read().default_port;

        let mut new_bindings = Vec::new();
        let mut udp_ping_status_updates = Vec::new();
        for spec in listen_specs {
            let EntrypointListenSpec {
                address,
                server_id,
                udp_ping_status_server_id,
            } = spec;
            if address.port() == default_port {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "server entrypoint for {server_id} reuses the default TCP/UDP port {default_port}"
                    ),
                )
                .into());
            }

            if address.port() != 0 {
                let existing = self
                    .entrypoints
                    .read()
                    .server_id_by_port
                    .get(&address.port())
                    .cloned();
                if let Some(existing) = existing {
                    if existing != server_id {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "TCP/UDP port {} is already mapped to {}, cannot remap to {} during hot reload",
                                address.port(),
                                existing,
                                server_id
                            ),
                        )
                        .into());
                    }
                    udp_ping_status_updates.push((address.port(), udp_ping_status_server_id));
                    continue;
                }
            }

            let (listener, udp_socket) = bind_entrypoint_socket_pair(address).await?;
            let port = listener.local_addr()?.port();
            if port == default_port {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "server entrypoint for {server_id} reuses the default TCP/UDP port {port}"
                    ),
                )
                .into());
            }

            {
                let entrypoints = self.entrypoints.read();
                if let Some(existing) = entrypoints.server_id_by_port.get(&port) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "TCP/UDP port {port} is already mapped to {existing}, cannot map to {server_id} during hot reload"
                        ),
                    )
                    .into());
                }
            }

            new_bindings.push((
                server_id,
                udp_ping_status_server_id,
                Arc::new(listener),
                udp_socket,
                port,
            ));
        }

        {
            let mut entrypoints = self.entrypoints.write();
            entrypoints.server_id_by_sni = server_id_by_sni;
            for (port, udp_ping_status_server_id) in udp_ping_status_updates {
                entrypoints
                    .udp_ping_status_server_id_by_port
                    .insert(port, udp_ping_status_server_id);
            }
            for (server_id, udp_ping_status_server_id, listener, udp_socket, port) in &new_bindings
            {
                entrypoints
                    .server_id_by_port
                    .insert(*port, server_id.clone());
                entrypoints
                    .udp_ping_status_server_id_by_port
                    .insert(*port, udp_ping_status_server_id.clone());
                entrypoints
                    .udp_socket_by_port
                    .insert(*port, Arc::clone(udp_socket));
                entrypoints.udp_sockets.push(Arc::clone(udp_socket));
                entrypoints.tcp_listeners.push(ServerTcpListener {
                    listener: Arc::clone(listener),
                });
            }
        }

        for (server_id, _udp_ping_status_server_id, listener, udp_socket, port) in new_bindings {
            tracing::info!(
                "config reload: added client entrypoint {} for server_id {}",
                port,
                server_id
            );
            self.spawn_entrypoint_tasks_for_new_binding(listener, udp_socket);
        }

        Ok(())
    }

    /// Spawn a periodic task that disconnects authenticated local clients who
    /// haven't sent a ping within `timeout_secs`.
    fn spawn_idle_reaper(
        server: Arc<Box<Self>>,
        timeout_secs: u64,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        let interval = std::time::Duration::from_secs((timeout_secs / 2).max(1));
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = shutdown.changed() => break,
                }

                server
                    .disconnect_idle_local_clients(chrono::Utc::now(), timeout_secs)
                    .await;
            }
        })
    }

    async fn disconnect_idle_local_clients(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        timeout_secs: u64,
    ) {
        let timeout = chrono::Duration::seconds(timeout_secs as i64);
        let clients = self.clients.get_local_clients().await;

        for client in &clients {
            if !client.is_authenticated() {
                continue;
            }
            let last_ping = client.get_last_ping().await;
            if now - last_ping > timeout {
                let sid = client.get_session_id();
                let server_id = client.server_id();
                let old_channel_id = client.get_current_channel_id();
                tracing::info!(
                    "Disconnecting idle local client {:?} (last ping: {}, timeout: {}s)",
                    sid,
                    last_ping,
                    timeout_secs,
                );
                self.clients
                    .remove_client_instance_in_server(&server_id, sid, client.client_instance_id())
                    .await;
                if let Err(e) = client.disconnect().await {
                    tracing::debug!(
                        error = %e,
                        session = u32::from(sid),
                        "failed to disconnect idle client",
                    );
                }
                crate::client::handlers::temp_channel::reap_if_empty_temporary_on_server(
                    self,
                    &server_id,
                    old_channel_id,
                )
                .await;
            }
        }
    }

    /// Spawn a periodic task that rolls back stale pending channel deletes.
    fn spawn_pending_delete_watchdog(
        server: Arc<Box<Self>>,
        timeout_ms: u64,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        let timeout_ms = timeout_ms.max(1);
        let interval = std::time::Duration::from_millis((timeout_ms / 2).max(100));
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = shutdown.changed() => break,
                }

                let server_ids = server.channels.known_server_ids();
                for server_id in server_ids {
                    let expired = server
                        .channels
                        .expired_pending_deletes_in_server(&server_id, timeout_ms as i64)
                        .await;
                    for (channel_id, nonce) in expired {
                        let op = shitspeak_state::ChannelOp::CancelPendingDelete {
                            id: channel_id,
                            nonce,
                        };
                        if server
                            .s2s_manager()
                            .propose_channel_op(Some(&server_id), op)
                            .await
                            .should_apply_locally()
                        {
                            if let Err(e) = server
                                .channels
                                .cancel_pending_delete_in_server(&server_id, channel_id, nonce)
                                .await
                            {
                                tracing::trace!(
                                    server_id,
                                    channel_id,
                                    nonce,
                                    error = ?e,
                                    "pending delete rollback failed"
                                );
                            }
                        }
                    }
                }
            }
        })
    }

    /// Attempt to reload config from disk. On success, applies live entrypoint
    /// bindings, atomically swaps the shared config, and logs changed keys.
    /// Returns an error only if the config file is malformed or an added
    /// entrypoint cannot be bound; the old config stays in place.
    pub async fn reload_config(self: &Arc<Box<Self>>) -> Result<(), Box<dyn std::error::Error>> {
        match Config::reload() {
            Ok(Some(new_config)) => {
                validate_visibility_config(&new_config)?;
                validate_privacy_config(&new_config)?;
                new_config.voice.dispatch().validate().map_err(|error| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
                })?;
                let next_tls_acceptor = load_c2s_tls_acceptor(&new_config, &self.extensions)?;
                let prepared_authenticator = self
                    .auth_finalization_queue
                    .prepare_authenticator_reload(&new_config)?;
                let authenticator_reloaded = prepared_authenticator.is_some();

                self.apply_entrypoint_config(&new_config).await?;

                let (root_channel_config_update, invalidate_acl_cache, visibility_reload) = {
                    let mut invalidate_acl_cache = false;
                    let mut root_channel_config_update = None;
                    let mut visibility_reload = false;
                    let mut current = self.config.write().expect("Config RwLock poisoned");
                    // Log notable changes
                    if current.welcome_text != new_config.welcome_text {
                        tracing::info!("config reload: welcome_text changed");
                    }
                    if current.root_channel_name != new_config.root_channel_name {
                        tracing::info!(
                            "config reload: root_channel_name {:?} -> {:?}",
                            current.root_channel_name,
                            new_config.root_channel_name
                        );
                        root_channel_config_update = Some(channel_root_config(&new_config));
                    }
                    if current.max_bandwidth != new_config.max_bandwidth {
                        tracing::info!(
                            "config reload: max_bandwidth {} -> {}",
                            current.max_bandwidth,
                            new_config.max_bandwidth
                        );
                    }
                    if current.max_users != new_config.max_users {
                        tracing::info!(
                            "config reload: max_users {} -> {}",
                            current.max_users,
                            new_config.max_users
                        );
                        self.s2s_manager.update_max_users(new_config.max_users);
                    }
                    if current.authenticator != new_config.authenticator {
                        tracing::info!(
                            "config reload: authenticator {:?} -> {:?}",
                            current.authenticator,
                            new_config.authenticator
                        );
                    }
                    if current.cert_path != new_config.cert_path
                        || current.key_path != new_config.key_path
                    {
                        tracing::info!(
                            "config reload: C2S TLS identity paths {:?}/{:?} -> {:?}/{:?}",
                            current.cert_path,
                            current.key_path,
                            new_config.cert_path,
                            new_config.key_path
                        );
                    }
                    if current.s2s.overlay.route_transit_messages
                        != new_config.s2s.overlay.route_transit_messages
                    {
                        tracing::info!(
                            "config reload: s2s.overlay.route_transit_messages {} -> {}",
                            current.s2s.overlay.route_transit_messages,
                            new_config.s2s.overlay.route_transit_messages
                        );
                        self.s2s_manager.update_route_transit_messages(
                            new_config.s2s.overlay.route_transit_messages,
                        );
                    }
                    if current.udp_voice_enabled != new_config.udp_voice_enabled {
                        tracing::info!(
                            "config reload: udp_voice_enabled {} -> {}",
                            current.udp_voice_enabled,
                            new_config.udp_voice_enabled
                        );
                    }
                    if current.udp_ping_enabled != new_config.udp_ping_enabled {
                        tracing::info!(
                            "config reload: udp_ping_enabled {} -> {}",
                            current.udp_ping_enabled,
                            new_config.udp_ping_enabled
                        );
                    }
                    if current.udp_ping_user_count_scope != new_config.udp_ping_user_count_scope {
                        tracing::info!(
                            "config reload: udp_ping_user_count_scope {:?} -> {:?}",
                            current.udp_ping_user_count_scope,
                            new_config.udp_ping_user_count_scope
                        );
                    }
                    if current.voice.dispatch() != new_config.voice.dispatch() {
                        tracing::warn!(
                            "config reload: voice.dispatch changed; startup calibration settings apply after restart"
                        );
                    }
                    if current.client_idle_timeout_secs != new_config.client_idle_timeout_secs {
                        tracing::info!(
                            "config reload: client_idle_timeout_secs {} -> {}",
                            current.client_idle_timeout_secs,
                            new_config.client_idle_timeout_secs
                        );
                    }
                    if current.auth_finalization_concurrency
                        != new_config.auth_finalization_concurrency
                    {
                        tracing::info!(
                            "config reload: auth_finalization_concurrency {} -> {} (takes effect after restart)",
                            current.auth_finalization_concurrency,
                            new_config.auth_finalization_concurrency
                        );
                    }
                    if current.required_groups != new_config.required_groups {
                        tracing::info!("config reload: required_groups changed");
                    }
                    if current.geoip != new_config.geoip {
                        tracing::info!("config reload: geoip changed");
                        *self.geoip_resolver.write() =
                            Arc::new(GeoIpResolver::new(new_config.geoip.clone()));
                        invalidate_acl_cache = true;
                        visibility_reload = true;
                    }
                    if current.send_permission_info != new_config.send_permission_info {
                        tracing::info!(
                            "config reload: send_permission_info {} -> {}",
                            current.send_permission_info,
                            new_config.send_permission_info
                        );
                    }
                    if current.hide_users_without_traverse != new_config.hide_users_without_traverse
                    {
                        visibility_reload = true;
                        tracing::info!(
                            "config reload: hide_users_without_traverse {} -> {}",
                            current.hide_users_without_traverse,
                            new_config.hide_users_without_traverse
                        );
                    }
                    if current.hide_channels_without_traverse
                        != new_config.hide_channels_without_traverse
                    {
                        visibility_reload = true;
                        tracing::info!(
                            "config reload: hide_channels_without_traverse {} -> {}",
                            current.hide_channels_without_traverse,
                            new_config.hide_channels_without_traverse
                        );
                    }
                    if current.show_node_id_for_superusers != new_config.show_node_id_for_superusers
                    {
                        tracing::info!(
                            "config reload: show_node_id_for_superusers {} -> {}",
                            current.show_node_id_for_superusers,
                            new_config.show_node_id_for_superusers
                        );
                    }
                    if current.acl.debug_acl_enter() != new_config.acl.debug_acl_enter() {
                        tracing::info!(
                            "config reload: acl.debug_acl_enter {} -> {}",
                            current.acl.debug_acl_enter(),
                            new_config.acl.debug_acl_enter()
                        );
                    }
                    if current.acl.explicit_enter_deny_overrides_write()
                        != new_config.acl.explicit_enter_deny_overrides_write()
                    {
                        tracing::info!(
                            "config reload: acl.explicit_enter_deny_overrides_write {} -> {}",
                            current.acl.explicit_enter_deny_overrides_write(),
                            new_config.acl.explicit_enter_deny_overrides_write()
                        );
                        invalidate_acl_cache = true;
                    }
                    if current.acl.preserve_write_acl_on_edit()
                        != new_config.acl.preserve_write_acl_on_edit()
                    {
                        tracing::info!(
                            "config reload: acl.preserve_write_acl_on_edit {} -> {}",
                            current.acl.preserve_write_acl_on_edit(),
                            new_config.acl.preserve_write_acl_on_edit()
                        );
                    }
                    if current.acl.grant_temp_channel_creator_acl()
                        != new_config.acl.grant_temp_channel_creator_acl()
                    {
                        tracing::info!(
                            "config reload: acl.grant_temp_channel_creator_acl {} -> {}",
                            current.acl.grant_temp_channel_creator_acl(),
                            new_config.acl.grant_temp_channel_creator_acl()
                        );
                    }
                    if current.acl.reevaluate_speak_on_acl_change()
                        != new_config.acl.reevaluate_speak_on_acl_change()
                    {
                        tracing::info!(
                            "config reload: acl.reevaluate_speak_on_acl_change {} -> {}",
                            current.acl.reevaluate_speak_on_acl_change(),
                            new_config.acl.reevaluate_speak_on_acl_change()
                        );
                    }
                    if current.acl.allow_move_without_traverse()
                        != new_config.acl.allow_move_without_traverse()
                    {
                        tracing::info!(
                            "config reload: acl.allow_move_without_traverse {} -> {}",
                            current.acl.allow_move_without_traverse(),
                            new_config.acl.allow_move_without_traverse()
                        );
                    }
                    if current.privacy.certificate_hash_protection()
                        != new_config.privacy.certificate_hash_protection()
                    {
                        tracing::info!(
                            "config reload: privacy.protect_certificate_hashes {} -> {}",
                            current.privacy.certificate_hash_protection(),
                            new_config.privacy.certificate_hash_protection()
                        );
                    }
                    if current.privacy.certificate_hash_secret().is_some()
                        != new_config.privacy.certificate_hash_secret().is_some()
                    {
                        tracing::info!(
                            "config reload: privacy.certificate_hash_secret presence changed"
                        );
                    }
                    if current.server_entrypoints != new_config.server_entrypoints {
                        tracing::info!("config reload: server_entrypoints changed");
                    }
                    self.replace_c2s_tls_acceptor(next_tls_acceptor);
                    tracing::info!("config reload: C2S TLS identity refreshed");
                    *current = new_config;
                    (
                        root_channel_config_update,
                        invalidate_acl_cache,
                        visibility_reload,
                    )
                };
                if let Some(root_channel_config) = root_channel_config_update {
                    self.channels
                        .update_root_channel_config(root_channel_config)
                        .await;
                }
                if invalidate_acl_cache {
                    self.channels.invalidate_all_acl_cache().await;
                }
                if visibility_reload {
                    let _ = self.visibility_reload_tx.send(());
                }
                self.auth_finalization_queue
                    .apply_prepared_authenticator_reload(prepared_authenticator);
                if authenticator_reloaded {
                    tracing::info!("config reload: authenticator backend reloaded");
                }
                tracing::info!("config reload: successfully applied new configuration");
                Ok(())
            }
            Ok(None) => {
                tracing::warn!("config reload: config.toml not found, keeping current config");
                Ok(())
            }
            Err(e) => {
                tracing::error!("config reload: failed to parse config.toml: {e}");
                Err(Box::new(e))
            }
        }
    }

    pub fn get_authenticator(&self) -> &dyn Authenticator {
        self.auth_finalization_queue.authenticator()
    }

    pub fn get_bans(&self) -> &Arc<shitspeak_state::BanRepository> {
        &self.bans
    }

    pub fn get_clients(&self) -> &Arc<ClientRepository> {
        &self.clients
    }

    pub fn get_channels(&self) -> &Arc<ChannelRepository> {
        &self.channels
    }

    pub(crate) fn visibility_fanout_index(
        &self,
    ) -> &Arc<crate::client::visibility::VisibilityFanoutIndex> {
        &self.visibility_fanout_index
    }

    pub fn get_channel_blobs(&self) -> &Arc<ChannelBlobStore> {
        &self.channel_blobs
    }

    pub fn get_session_blobs(&self) -> &Arc<SessionBlobStore> {
        &self.session_blobs
    }

    pub fn get_user_channel_cache(&self) -> &Arc<UserChannelCache> {
        &self.user_channel_cache
    }

    pub fn get_udp_socket(&self) -> Option<Arc<tokio::net::UdpSocket>> {
        self.default_udp_socket()
    }

    pub fn s2s_manager(&self) -> &Arc<S2SManager> {
        &self.s2s_manager
    }

    pub fn get_codec_info(&self) -> parking_lot::MutexGuard<'_, CodecInfo> {
        self.codec_info.lock()
    }

    pub fn get_min_client_version(&self) -> u64 {
        self.read_config().min_client_version
    }

    pub fn get_max_users(&self) -> u64 {
        self.read_config().max_users
    }

    pub fn get_cert_required(&self) -> bool {
        self.read_config().cert_required
    }

    pub fn get_required_groups(&self) -> Vec<String> {
        self.read_config().required_groups.clone()
    }

    pub async fn acquire_auth_finalization_permit(
        self: &Arc<Box<Self>>,
        client: &Arc<Box<Client>>,
    ) -> Result<AuthFinalizationPermit, MessageHandlerError> {
        self.auth_finalization_queue.acquire(client).await
    }

    pub async fn create_client_crypt_state(
        &self,
        client: &Client,
        mode: &str,
    ) -> Result<(), shitspeak_client_crypto::CryptError> {
        let permit = self
            .crypt_setup_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("crypt setup semaphore should not be closed");
        let result = client.create_crypt_state(mode);
        drop(permit);
        result
    }

    #[cfg(test)]
    pub(crate) fn install_auth_finalization_test_gate(
        &self,
        target_acquire: usize,
    ) -> AuthFinalizationTestGateHandle {
        self.auth_finalization_queue
            .install_test_gate(target_acquire)
    }

    pub fn get_send_permission_info(&self) -> bool {
        self.read_config().send_permission_info
    }

    pub fn get_hide_users_without_traverse(&self) -> bool {
        self.read_config().hide_users_without_traverse
    }

    pub fn get_hide_channels_without_traverse(&self) -> bool {
        let config = self.read_config();
        config.hide_channels_without_traverse && config.hide_users_without_traverse
    }

    pub fn get_show_node_id_for_superusers(&self) -> bool {
        self.read_config().show_node_id_for_superusers
    }

    pub fn get_debug_acl_enter(&self) -> bool {
        self.read_config().acl.debug_acl_enter()
    }

    pub fn get_explicit_enter_deny_overrides_write(&self) -> bool {
        self.read_config().acl.explicit_enter_deny_overrides_write()
    }

    pub fn get_preserve_write_acl_on_edit(&self) -> bool {
        self.read_config().acl.preserve_write_acl_on_edit()
    }

    pub fn get_grant_temp_channel_creator_acl(&self) -> bool {
        self.read_config().acl.grant_temp_channel_creator_acl()
    }

    pub fn get_reevaluate_speak_on_acl_change(&self) -> bool {
        self.read_config().acl.reevaluate_speak_on_acl_change()
    }

    pub fn get_allow_move_without_traverse(&self) -> bool {
        self.read_config().acl.allow_move_without_traverse()
    }

    pub(crate) async fn reevaluate_speak_after_acl_change(
        self: &Arc<Box<Self>>,
        operation: &shitspeak_state::ChannelOperation,
    ) {
        if !self.get_reevaluate_speak_on_acl_change() {
            return;
        }
        let ChannelOp::SetAcls { .. } = &operation.op else {
            return;
        };
        let server_id = &operation.server_id;
        if let Some(hint) = self.get_channels().acl_change_hint_for_operation(operation) {
            let impact = hint.impact();
            if !impact.state_changed() {
                return;
            }
            let here_may_change = impact
                .apply_here()
                .effective_permissions()
                .contains(shitspeak_state::ACLPermissions::Speak);
            let subs_may_change = impact
                .apply_subs()
                .effective_permissions()
                .contains(shitspeak_state::ACLPermissions::Speak);
            if !here_may_change && !subs_may_change {
                return;
            }
            let here_changes_structural_descendants = impact
                .apply_here()
                .effective_permissions()
                .contains(shitspeak_state::ACLPermissions::Traverse);

            let affected_channel_ids = hint
                .affected_channel_ids()
                .iter()
                .copied()
                .filter(|channel_id| {
                    (*channel_id == hint.channel_id() && here_may_change)
                        || (*channel_id != hint.channel_id()
                            && (subs_may_change
                                || (here_may_change && here_changes_structural_descendants)))
                })
                .collect::<HashSet<_>>();
            if affected_channel_ids.is_empty() {
                return;
            }
            let affected_clients = self
                .get_clients()
                .get_local_clients_in_channels_in_server(
                    server_id,
                    &sorted_channel_ids(&affected_channel_ids),
                )
                .await;
            let old_acl = crate::client::acl::ChannelAclOverride::new(
                hint.channel_id(),
                hint.old_inherit_acl(),
                hint.old_acls().to_vec(),
            );
            for client in affected_clients {
                let current_channel_id = client.get_current_channel_id();
                let matches_here = here_may_change
                    && crate::client::acl::client_matches_acl_viewer_scope(
                        &client,
                        impact.apply_here().viewer_scope(),
                    );
                let matches_subs = subs_may_change
                    && crate::client::acl::client_matches_acl_viewer_scope(
                        &client,
                        impact.apply_subs().viewer_scope(),
                    );
                let viewer_may_change = if current_channel_id == hint.channel_id() {
                    matches_here
                } else {
                    matches_subs || (here_changes_structural_descendants && matches_here)
                };
                if !viewer_may_change {
                    continue;
                }
                let context = crate::client::acl::ClientAclEvaluationContext::new(
                    self,
                    &client,
                    hint.tree_snapshot(),
                    None,
                )
                .await;
                let new_permissions = context.evaluate(current_channel_id);
                let old_permissions =
                    context.evaluate_with_acl_override(current_channel_id, &old_acl);
                if new_permissions.contains(shitspeak_state::ACLPermissions::Speak)
                    == old_permissions.contains(shitspeak_state::ACLPermissions::Speak)
                {
                    continue;
                }
                loop {
                    let evaluated_channel_id = client.get_current_channel_id();
                    let evaluated_channel_version =
                        self.get_channels().current_version_in_server(server_id);
                    let permissions = crate::client::acl::compute_permissions_for_client(
                        self,
                        &client,
                        evaluated_channel_id,
                    )
                    .await;
                    let mut state = client.write_global_state_as(
                        self.get_clients(),
                        None,
                        Some(evaluated_channel_version),
                    );
                    if state.get_current_channel_id() != evaluated_channel_id
                        || self.get_channels().current_version_in_server(server_id)
                            != evaluated_channel_version
                    {
                        continue;
                    }
                    state.set_suppress(
                        !permissions.contains(shitspeak_state::ACLPermissions::Speak),
                    );
                    break;
                }
            }
            return;
        }

        // Transient hints can be absent for old replayed operations. Keep the
        // original broad reevaluation as the correctness fallback.
        let Some(affected_channel_ids) = self
            .get_channels()
            .acl_affected_channel_ids_for_op(server_id, &operation.op)
            .await
        else {
            return;
        };
        if affected_channel_ids.is_empty() {
            return;
        }

        let affected_clients = self
            .get_clients()
            .get_local_clients_in_channels_in_server(
                server_id,
                &sorted_channel_ids(&affected_channel_ids),
            )
            .await;

        for client in affected_clients {
            loop {
                let evaluated_channel_id = client.get_current_channel_id();
                let evaluated_channel_version =
                    self.get_channels().current_version_in_server(server_id);
                let permissions = crate::client::acl::compute_permissions_for_client(
                    self,
                    &client,
                    evaluated_channel_id,
                )
                .await;
                let mut state = client.write_global_state_as(
                    self.get_clients(),
                    None,
                    Some(evaluated_channel_version),
                );
                if state.get_current_channel_id() != evaluated_channel_id
                    || self.get_channels().current_version_in_server(server_id)
                        != evaluated_channel_version
                {
                    continue;
                }
                state.set_suppress(!permissions.contains(shitspeak_state::ACLPermissions::Speak));
                break;
            }
        }
    }

    pub fn get_certificate_hash_privacy(&self) -> Option<(CertificateHashProtection, String)> {
        let config = self.read_config();
        let protection = config.privacy.certificate_hash_protection();
        if !protection.is_enabled() {
            return None;
        }
        let secret = config
            .privacy
            .certificate_hash_secret()
            .map(str::trim)
            .filter(|secret| !secret.is_empty())
            .map(ToOwned::to_owned)?;
        Some((protection, secret))
    }

    pub fn get_max_bandwidth(&self) -> u32 {
        self.read_config().max_bandwidth
    }

    pub fn get_server_protocol_version(&self) -> crate::protocol_version::ProtocolVersion {
        self.read_config().server_protocol_version
    }

    pub fn get_welcome_text(&self) -> Option<String> {
        self.read_config().welcome_text.clone()
    }

    pub fn get_allow_html(&self) -> bool {
        self.read_config().allow_html
    }

    pub fn get_max_text_message_length(&self) -> u32 {
        self.read_config().max_text_message_length
    }

    pub fn get_max_image_message_length(&self) -> u32 {
        self.read_config().max_image_message_length
    }

    pub fn get_default_channel(&self) -> u32 {
        self.read_config().default_channel
    }
    /// Access the context action registry.
    pub fn context_actions(&self) -> &Arc<crate::context_action::ContextActionRegistry> {
        &self.context_actions
    }

    // ── UDP ping ─────────────────────────────────────────────────────────

    async fn build_ping_response(
        server: &Arc<Box<Self>>,
        ping: &crate::voice::ping::PingRequest,
        status_server_id: &str,
    ) -> Result<Bytes, EncodeError> {
        // Snapshot config values before any .await (RwLockReadGuard is !Send)
        let (local_max_users, max_bandwidth, user_count_scope, server_version) = {
            let cfg = server.read_config();
            (
                cfg.max_users,
                cfg.max_bandwidth,
                cfg.udp_ping_user_count_scope,
                cfg.server_protocol_version,
            )
        };

        let (user_count, max_user_count) = match user_count_scope {
            UdpPingUserCountScope::Cluster => {
                let users = server.clients.len_in_server(status_server_id).await;
                let max_users = server
                    .s2s_manager
                    .cluster_max_users()
                    .filter(|max_users| *max_users > 0)
                    .unwrap_or(local_max_users);
                (users as u64, max_users)
            }
            UdpPingUserCountScope::Local => {
                let users = server.clients.local_len_in_server(status_server_id).await;
                (users as u64, local_max_users)
            }
        };

        let response = crate::voice::ping::PingResponse {
            timestamp: ping.timestamp,
            server_version,
            user_count: user_count.clamp(0, u32::MAX.into()) as u32,
            max_user_count: Some(max_user_count.clamp(0, u32::MAX.into()) as u32),
            max_bandwidth_per_user: max_bandwidth,
        };
        response.encode(ping.format)
    }

    // ── Codec negotiation ────────────────────────────────────────────────

    /// Re-evaluate codec selection across all authenticated clients and
    /// broadcast `CodecVersion` if the selection changed.
    pub async fn recheck_codec_versions(self: &Arc<Box<Self>>) {
        let all_clients = self.clients.get_all_clients().await;

        let mut alpha_count = 0usize;
        let mut beta_count = 0usize;
        let mut prefer_alpha_count = 0usize;
        let mut opus_count = 0usize;
        let total = all_clients.len();

        for client in &all_clients {
            if !client.is_authenticated() {
                continue;
            }
            let local = client.read_local_state();
            if let Some(ref state) = *local {
                if state.supports_opus() {
                    opus_count += 1;
                }
            }
        }

        let changed = {
            let mut codec = self.codec_info.lock();
            codec.recheck(
                alpha_count,
                beta_count,
                prefer_alpha_count,
                opus_count,
                total,
            )
        };

        if changed {
            let msg = {
                let codec = self.codec_info.lock();
                let alpha = codec.alpha_codec();
                let beta = codec.beta_codec();
                let prefer_alpha = codec.prefer_alpha_codec();
                let opus = codec.opus();
                // codec lock released here — block scope ends
                crate::messages::encoder::CodecVersion {
                    alpha,
                    beta,
                    prefer_alpha,
                    opus: Some(opus),
                }
                .into()
            };
            self.clients.broadcast_all(&msg).await;
        }
    }
}

fn effective_udp_processing_channel_size(configured_floor: usize, max_users: u64) -> usize {
    let users = usize::try_from(max_users).unwrap_or(usize::MAX).max(1);
    let baseline = users
        .saturating_mul(UDP_PROCESSING_PACKETS_PER_USER_BASELINE)
        .max(UDP_PROCESSING_MIN_BASELINE_CAPACITY);
    let burst = baseline.saturating_mul(UDP_PROCESSING_BURST_MULTIPLIER);
    let hard = users
        .saturating_mul(UDP_PROCESSING_PACKETS_PER_USER_HARD_CAP)
        .max(UDP_PROCESSING_MIN_HARD_CAPACITY)
        .max(burst);
    configured_floor.max(hard)
}
