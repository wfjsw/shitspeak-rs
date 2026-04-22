use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::str::FromStr;
use std::sync::Arc;

use tokio::sync::Mutex;

use cidr::AnyIpCidr;
use prost::Message as _;
use rustls::pki_types::{pem::PemObject as _, CertificateDer, PrivateKeyDer};
use rustls::version::{TLS12, TLS13};
use tokio_rustls::TlsAcceptor;

use crate::api::Authenticator;
use crate::blob_store::{ChannelBlobStore, SessionBlobStore};
use crate::channel_repository::ChannelRepository;
use crate::client::AsyncMessageHandlerExt;
use crate::client_certificate_verifier::ClientCertificateVerifier;
use crate::errors::{
    HandleIncomingConnectionError,
};
use crate::messages::encoder::Version;
use crate::messages::{Message, WriteMessageExt};
use crate::proxy_protocol::get_proxy_protocol_real_ip;
use crate::{
    client_repository::ClientRepository, codec_info::CodecInfo, config::Config,
    types::NodeIdentifier,
};

pub struct Server {
    node_identifier: NodeIdentifier,

    // Config
    config: Config,

    allowed_proxies: Vec<AnyIpCidr>,

    tcp_listener: tokio::net::TcpListener,
    tls_acceptor: TlsAcceptor,
    udp_socket: Arc<tokio::net::UdpSocket>,

    clients: ClientRepository,
    channels: Arc<ChannelRepository>,
    channel_blobs: Arc<ChannelBlobStore>,
    session_blobs: Arc<SessionBlobStore>,

    codec_info: Mutex<CodecInfo>,

    authenticator: Box<dyn Authenticator>,
}

impl Server {
    pub async fn new<A: Authenticator>(
        config: Config,
        authenticator: A,
    ) -> Result<Arc<Box<Self>>, Box<dyn std::error::Error>> {
        let listen_address = config
            .listen
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| "Invalid listen address")?;

        let allowed_proxies = config
            .allowed_proxies
            .iter()
            .map(|proxy| AnyIpCidr::from_str(proxy))
            .collect::<Result<Vec<_>, _>>()?;

        let certificate =
            CertificateDer::pem_file_iter(&config.cert_path)?.collect::<Result<Vec<_>, _>>()?;
        let private_key = PrivateKeyDer::from_pem_file(&config.key_path)?;

        let tcp_listener = tokio::net::TcpListener::bind(&listen_address).await?;
        let udp_socket = Arc::new(tokio::net::UdpSocket::bind(&listen_address).await?);

        let client_cert_verifier = Arc::new(ClientCertificateVerifier::new());

        let tls_config = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS12, &TLS13])
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(certificate, private_key)?;

        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

        // ── Channel repository & blob stores ─────────────────────────────
        let node_id = config.node_id;
        let (channels, channel_blobs, session_blobs) = match &config.blob_storage_dir {
            Some(dir) => {
                let ch_repo = ChannelRepository::open(node_id, dir).await?;
                let ch_blobs = Arc::new(ChannelBlobStore::open(dir).await?);
                let s_blobs = Arc::new(SessionBlobStore::open(dir).await?);
                (ch_repo, ch_blobs, s_blobs)
            }
            None => {
                // In-memory mode: use a temp dir for blob stores so the
                // code paths are uniform; blobs won't survive restarts.
                let tmp = std::env::temp_dir().join("shitspeak-blobs");
                let ch_repo = ChannelRepository::new_in_memory(node_id);
                let ch_blobs = Arc::new(ChannelBlobStore::open(&tmp).await?);
                let s_blobs = Arc::new(SessionBlobStore::open(&tmp).await?);
                (ch_repo, ch_blobs, s_blobs)
            }
        };

        Ok(Arc::new(Box::new(Server {
            node_identifier: node_id,
            allowed_proxies,
            tcp_listener,
            tls_acceptor,
            udp_socket,
            clients: ClientRepository::new(node_id),
            channels,
            channel_blobs,
            session_blobs,
            codec_info: Mutex::new(CodecInfo::default()),
            authenticator: Box::new(authenticator),
            config,
        })))
    }

    pub async fn run(
        self: &Arc<Box<Self>>,
        shutdown_tx: tokio::sync::watch::Sender<()>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("Server is running on {}", self.tcp_listener.local_addr()?);

        let shutdown_rx = shutdown_tx.subscribe();

        // Bounded channel shared between UDP drain and processing tasks.
        let (udp_in, udp_out) = tokio::sync::mpsc::channel::<(Vec<u8>, std::net::SocketAddr)>(
            self.config.udp_channel_size,
        );

        let udp_drain = Self::spawn_udp_drain(
            Arc::clone(&self.udp_socket),
            udp_in,
            self.config.udp_voice_enabled,
            self.config.udp_ping_enabled,
            Arc::clone(self),
            shutdown_rx.clone(),
        );
        let udp_process = Self::spawn_udp_process(
            Arc::clone(self),
            Arc::clone(&self.udp_socket),
            udp_out,
            self.config.udp_ping_enabled,
            shutdown_rx.clone(),
        );
        let tcp_accept = Self::spawn_tcp_accept(Arc::clone(self), shutdown_rx.clone());
        let idle_reaper = Self::spawn_idle_reaper(
            Arc::clone(self),
            self.config.client_idle_timeout_secs,
            shutdown_rx,
        );

        // Wait for any task to finish (error) or for the shutdown signal
        // to be dropped by the caller (main.rs drops shutdown_tx on Ctrl-C).
        tokio::select! {
            result = udp_drain => { let _ = result; }
            result = udp_process => { let _ = result; }
            result = tcp_accept => { let _ = result; }
            result = idle_reaper => { let _ = result; }
            _ = shutdown_tx.closed() => {
                tracing::info!("Shutdown signal received.");
            }
        }

        Ok(())
    }

    /// Spawn the UDP drain task: receive packets as fast as possible and
    /// push voice packets into the channel.  Ping packets are handled
    /// directly (responded to immediately).
    fn spawn_udp_drain(
        socket: Arc<tokio::net::UdpSocket>,
        tx: tokio::sync::mpsc::Sender<(Vec<u8>, std::net::SocketAddr)>,
        voice_enabled: bool,
        ping_enabled: bool,
        server: Arc<Box<Self>>,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            tracing::info!("UDP drain started, listening on {}", socket.local_addr().unwrap_or_else(|_| std::net::SocketAddr::from(([0,0,0,0], 0))));
            loop {
                let (len, src_addr) = tokio::select! {
                    result = socket.recv_from(&mut buf) => match result {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("UDP recv error: {e}");
                            continue;
                        }
                    },
                    _ = shutdown.changed() => break,
                };

                let packet = &buf[..len];
                tracing::trace!("UDP received {} bytes from {}", len, src_addr);

                if !voice_enabled && !ping_enabled {
                    continue;
                }
                let packet = packet.to_vec();
                if tx.send((packet, src_addr)).await.is_err() {
                    break; // channel closed — shutting down
                }
            }
            tracing::info!("UDP drain stopped");
        })
    }

    /// Spawn the UDP processing task: decrypt, parse, and route voice
    /// packets from the channel.  Ping packets are handled directly.
    fn spawn_udp_process(
        server: Arc<Box<Self>>,
        socket: Arc<tokio::net::UdpSocket>,
        mut rx: tokio::sync::mpsc::Receiver<(Vec<u8>, std::net::SocketAddr)>,
        ping_enabled: bool,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let (packet, src_addr) = tokio::select! {
                    msg = rx.recv() => match msg {
                        Some(m) => m,
                        None => break,
                    },
                    _ = shutdown.changed() => break,
                };
                // Try to match by known UDP address first
                let client = match server.clients.get_client_by_udp_address(&src_addr).await {
                    Some(c) => Some(c),
                    None => {
                        let candidates = server.clients.get_clients_by_ip(&src_addr.ip()).await;
                        let mut matched = None;
                        for c in &candidates {
                            let mut crypt = c.crypt_state().await;
                            if let Some(ref mut state) = *crypt {
                                let mut decrypted = Vec::new();
                                if state.decrypt(&mut decrypted, &packet).is_ok() {
                                    matched = Some(c.clone());
                                    break;
                                }
                            }
                        }
                        matched
                    }
                };

                let Some(client) = client else { continue };
                if !client.is_authenticated().await {
                    continue;
                };

                let decrypted = {
                    let mut crypt = client.crypt_state().await;
                    let mut dec = Vec::new();
                    match crypt.as_mut() {
                        Some(state) => match state.decrypt(&mut dec, &packet) {
                            Ok(()) => dec,
                            Err(_) => continue,
                        },
                        None => continue,
                    }
                };

                // After decryption, check if this is a ping or audio packet.
                match crate::voice::codec::decode_udp_packet(&decrypted) {
                    Ok(crate::voice::codec::UdpPacket::Ping(ping)) => {
                        if ping_enabled {
                            tracing::debug!("UDP ping from {}: timestamp={}", src_addr, ping.timestamp);
                            let reply = Self::build_ping_response(&server, &ping).await;
                            match socket.send_to(&reply, src_addr).await {
                                Ok(sent) => tracing::trace!("UDP ping reply sent to {}: {} bytes", src_addr, sent),
                                Err(e) => tracing::warn!("UDP ping reply failed to {}: {e}", src_addr),
                            }
                        }
                        continue;
                    }
                    Ok(crate::voice::codec::UdpPacket::Audio(decoded_audio)) => {
                        // Validate that the sender_session in the packet matches the
                        // client we identified via UDP address / crypto.  An attacker
                        // could spoof the session ID otherwise.
                        if decoded_audio.sender_session != u32::from(client.get_session_id()) {
                            tracing::debug!(
                                "UDP session mismatch: packet claims {}, client is {:?}",
                                decoded_audio.sender_session,
                                client.get_session_id(),
                            );
                            continue;
                        }

                        crate::voice::route_voice(&server, &client, &decoded_audio, true).await;
                    }
                    Err(e) => {
                        tracing::trace!("UDP packet decode failed from {}: {e}", src_addr);
                        continue;
                    }
                }
            }
        })
    }

    /// Spawn the TCP accept loop.
    fn spawn_tcp_accept(
        server: Arc<Box<Self>>,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let (tcp_stream, remote_addr) = tokio::select! {
                    result = server.tcp_listener.accept() => match result {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("TCP accept error: {e}");
                            continue;
                        }
                    },
                    _ = shutdown.changed() => break,
                };
                let conn_server = Arc::clone(&server);
                tokio::spawn(async move {
                    if let Err(e) = conn_server
                        .handle_incoming_connection(tcp_stream, remote_addr)
                        .await
                    {
                        tracing::warn!("Error handling connection: {}", e);
                    }
                });
            }
        })
    }

    /// Spawn a periodic task that disconnects clients who haven't sent a
    /// ping within `timeout_secs`.
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

                let now = chrono::Utc::now();
                let timeout = chrono::Duration::seconds(timeout_secs as i64);
                let clients = server.clients.get_all_clients().await;

                for client in &clients {
                    let last_ping = client.get_last_ping().await;
                    if now - last_ping > timeout {
                        let sid = client.get_session_id();
                        tracing::info!(
                            "Disconnecting idle client {:?} (last ping: {}, timeout: {}s)",
                            sid,
                            last_ping,
                            timeout_secs,
                        );
                        server.clients.remove_client(sid).await;
                    }
                }
            }
        })
    }

    pub async fn handle_incoming_connection(
        self: &Arc<Box<Self>>,
        tcp_stream: tokio::net::TcpStream,
        remote_addr: std::net::SocketAddr,
    ) -> Result<(), HandleIncomingConnectionError> {
        let real_ip = if self
            .allowed_proxies
            .iter()
            .any(|proxy| proxy.contains(&remote_addr.ip()))
        {
            match get_proxy_protocol_real_ip(&tcp_stream).await? {
                Some(ip) => ip,
                None => remote_addr.ip(),
            }
        } else {
            remote_addr.ip()
        };

        let local_addr = tcp_stream.local_addr()?;
        let tls_acceptor = self.tls_acceptor.clone();
        let mut tls_stream = tls_acceptor.accept(tcp_stream).await?;

        // Send server version
        tls_stream
            .write_proto_message(
                &Version::for_server(
                    self.config.send_version,
                    self.config.send_build_info,
                    self.config.send_os_info,
                )
                .into(),
            )
            .await?;

        let client = self
            .clients
            .allocate_local_client(real_ip, remote_addr, None, local_addr, tls_stream)
            .await;

        let client_session_id = client.get_session_id();

        // Subscriptions start as None — they're activated after auth.
        let mut client_log_rx: Option<tokio::sync::broadcast::Receiver<_>> = None;
        let mut channel_log_rx: Option<tokio::sync::broadcast::Receiver<_>> = None;

        // Run the connection loop.  On any unrecoverable error, clean up
        // the client and return the error to the caller.
        let result: Result<(), HandleIncomingConnectionError> = async {
            loop {
                tokio::select! {
                    // ── Incoming message from this client ────────────────────
                    result = client.read_proto_message() => {
                        match result {
                            Ok(message) => {
                                client.handle_message(self, message).await
                                    .map_err(|_| HandleIncomingConnectionError::MessageHandlerFailed)?;

                                // Transition to post-auth: publish and subscribe.
                                if client.is_authenticated().await && client_log_rx.is_none() {
                                    let channel_snapshot_version = self.channels.current_version();
                                    client.set_last_channel_version(channel_snapshot_version).await;

                                    self.clients.publish_client(client_session_id).await;

                                    client_log_rx = Some(self.clients.subscribe());
                                    channel_log_rx = Some(self.channels.subscribe());

                                    let last_seen = client.get_last_client_versions().await;
                                    let (missed, new_versions) = self.clients.replay_since(&last_seen).await
                                        .map_err(|()| HandleIncomingConnectionError::ClientLogGapUnrecoverable)?;
                                    for msg in &missed {
                                        client.write_proto_message(msg).await
                                            .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
                                    }
                                    client.update_last_client_versions(&new_versions).await;
                                }
                            }
                            Err(_) => return Err(HandleIncomingConnectionError::MessageHandlerFailed),
                        }
                    }

                    // ── Client state change notification ─────────────────────
                    result = recv_optional(client_log_rx.as_mut()), if client_log_rx.is_some() => {
                        match result {
                            Some(Ok(broadcast)) => {
                                tracing::trace!("Received client log broadcast: {:?}", broadcast);

                                let entry = &broadcast.entry;
                                // if entry.op.session_id() == Some(client_session_id) {
                                //     continue;
                                // }
                                let last_seen = client.get_last_client_versions().await;
                                let last_for_node = last_seen.get(&entry.node_id).copied().unwrap_or(0);
                                if entry.version > last_for_node + 1 {
                                    let (missed, new_versions) = self.clients.replay_since(&last_seen).await
                                        .map_err(|()| HandleIncomingConnectionError::ClientLogGapUnrecoverable)?;
                                    for msg in &missed {
                                        client.write_proto_message(msg).await
                                            .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
                                    }
                                    client.update_last_client_versions(&new_versions).await;
                                }
                                if let Some(msg) = entry.to_message(&self.clients).await {
                                    client.write_proto_message(&msg).await
                                        .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
                                }
                                client.update_last_client_versions(&broadcast.versions).await;
                            }
                            Some(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {
                                let last_seen = client.get_last_client_versions().await;
                                let (missed, new_versions) = self.clients.replay_since(&last_seen).await
                                    .map_err(|()| HandleIncomingConnectionError::ClientLogGapUnrecoverable)?;
                                for msg in &missed {
                                    client.write_proto_message(msg).await
                                        .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
                                }
                                client.update_last_client_versions(&new_versions).await;
                            }
                            Some(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                                return Ok(());
                            }
                            None => {} // not subscribed yet
                        }
                    }

                    // ── Channel state change notification ────────────────────
                    result = recv_optional(channel_log_rx.as_mut()), if channel_log_rx.is_some() => {
                        match result {
                            Some(Ok(op)) => {
                                let last = client.get_last_channel_version().await;
                                replay_channel_log_gap(
                                    &client, &self.channels, client_session_id, last, op.version,
                                ).await.map_err(|()| HandleIncomingConnectionError::ChannelLogGapUnrecoverable)?;
                                if let Some(msg) = op.to_message() {
                                    client.write_proto_message(&msg).await
                                        .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
                                }
                                client.set_last_channel_version(op.version).await;
                            }
                            Some(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {
                                let last = client.get_last_channel_version().await;
                                replay_channel_log_gap(
                                    &client, &self.channels, client_session_id, last, u64::MAX,
                                ).await.map_err(|()| HandleIncomingConnectionError::ChannelLogGapUnrecoverable)?;
                            }
                            Some(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                                return Ok(());
                            }
                            None => {} // not subscribed yet
                        }
                    }
                }
            }
        }.await;

        // Single cleanup point: remove the client on any error.
        if result.is_err() {
            self.clients.remove_client(client_session_id).await;
        }
        result
    }

    pub async fn reload(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // self.config = Config::load();
        Ok(())
    }

    pub fn get_authenticator(&self) -> &dyn Authenticator {
        self.authenticator.as_ref()
    }

    pub fn get_clients(&self) -> &ClientRepository {
        &self.clients
    }

    pub fn get_channels(&self) -> &Arc<ChannelRepository> {
        &self.channels
    }

    pub fn get_channel_blobs(&self) -> &Arc<ChannelBlobStore> {
        &self.channel_blobs
    }

    pub fn get_session_blobs(&self) -> &Arc<SessionBlobStore> {
        &self.session_blobs
    }

    pub fn get_udp_socket(&self) -> &Arc<tokio::net::UdpSocket> {
        &self.udp_socket
    }

    pub async fn get_codec_info(&self) -> tokio::sync::MutexGuard<'_, CodecInfo> {
        self.codec_info.lock().await
    }

    pub fn get_min_client_version(&self) -> u64 {
        self.config.min_client_version
    }

    pub fn get_max_users(&self) -> u64 {
        self.config.max_users
    }

    pub fn get_cert_required(&self) -> bool {
        self.config.cert_required
    }

    pub fn get_max_bandwidth(&self) -> u32 {
        self.config.max_bandwidth
    }

    pub fn get_welcome_text(&self) -> Option<&str> {
        self.config.welcome_text.as_deref()
    }

    pub fn get_allow_html(&self) -> bool {
        self.config.allow_html
    }

    pub fn get_max_text_message_length(&self) -> u32 {
        self.config.max_text_message_length
    }

    pub fn get_max_image_message_length(&self) -> u32 {
        self.config.max_image_message_length
    }

    pub fn get_default_channel(&self) -> u32 {
        self.config.default_channel
    }

    
    // ── UDP ping ─────────────────────────────────────────────────────────

    /// Build a ping response with current server information.
    async fn build_ping_response(
        server: &Arc<Box<Self>>,
        ping: &crate::voice::codec::PingRequest,
    ) -> Vec<u8> {
        let response = crate::voice::codec::PingResponse {
            timestamp: ping.timestamp,
            server_version: crate::constants::APP_PROTO_VER,
            user_count: server.clients.get_all_clients().await.len() as u32,
            max_user_count: server.config.max_users as u32,
            max_bandwidth_per_user: server.config.max_bandwidth,
        };
        crate::voice::codec::encode_ping_response(&response, ping.format)
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
            if !client.is_authenticated().await {
                continue;
            }
            let local = client.read_local_state().await;
            if let Some(ref state) = *local {
                if state.supports_opus() {
                    opus_count += 1;
                }
            }
        }

        let mut codec = self.codec_info.lock().await;
        let changed = codec.recheck(
            alpha_count,
            beta_count,
            prefer_alpha_count,
            opus_count,
            total,
        );

        if changed {
            let msg = crate::messages::Message::CodecVersion(crate::mumble_proto::CodecVersion {
                alpha: codec.alpha_codec(),
                beta: codec.beta_codec(),
                prefer_alpha: codec.prefer_alpha_codec(),
                opus: Some(codec.opus()),
            });
            drop(codec);
            self.clients.broadcast_all(&msg).await;
        }
    }
}

// ─── Log gap replay helpers ─────────────────────────────────────────────────

/// Replay missed client-state log entries for `node_id` between `last` and
/// `current` (exclusive).  If `current == u64::MAX`, replays everything
/// after `last`.
///
/// Returns `Err(())` if the gap is unrecoverable (log pruned).
async fn replay_client_log_gap(
    client: &Arc<Box<crate::client::Client>>,
    repo: &crate::client_repository::ClientRepository,
    session_id: crate::client::client_session_identifier::ClientSessionIdentifier,
    node_id: u16,
    last: u64,
    current: u64,
) -> Result<(), ()> {
    if current <= last + 1 {
        return Ok(());
    }

    tracing::warn!(
        "Client {:?} missed client log entries: node={} last={} current={}",
        session_id, node_id, last, current,
    );

    let missed = repo.get_log_since(last).await;
    if missed.is_empty() && last > 0 {
        tracing::error!(
            "Client {:?} client log gap unrecoverable (node={}, last={})",
            session_id, node_id, last,
        );
        return Err(());
    }

    for entry in &missed {
        if entry.version >= current {
            break;
        }
        if entry.op.session_id() == Some(session_id) {
            continue;
        }
        if let Some(msg) = entry.to_message(repo).await {
            if client.write_proto_message(&msg).await.is_err() {
                return Err(());
            }
        }
        let mut ver = HashMap::new();
        ver.insert(entry.node_id, entry.version);
        client.update_last_client_versions(&ver).await;
    }

    Ok(())
}

/// Replay missed channel-state log entries between `last` and `current`
/// (exclusive).  If `current == u64::MAX`, replays everything after `last`.
///
/// Returns `Err(())` if the gap is unrecoverable (log pruned).
async fn replay_channel_log_gap(
    client: &Arc<Box<crate::client::Client>>,
    channels: &Arc<crate::channel_repository::ChannelRepository>,
    session_id: crate::client::client_session_identifier::ClientSessionIdentifier,
    last: u64,
    current: u64,
) -> Result<(), ()> {
    if current <= last + 1 {
        return Ok(());
    }

    tracing::warn!(
        "Client {:?} missed channel log entries: last={} current={}",
        session_id, last, current,
    );

    let missed = channels.get_log_since(last).await;
    if missed.is_empty() && last > 0 {
        tracing::error!(
            "Client {:?} channel log gap unrecoverable (last={})",
            session_id, last,
        );
        return Err(());
    }

    for entry in &missed {
        if entry.version >= current {
            break;
        }
        if let Some(msg) = entry.to_message() {
            if client.write_proto_message(&msg).await.is_err() {
                return Err(());
            }
        }
        client.set_last_channel_version(entry.version).await;
    }

    Ok(())
}

/// Helper for `tokio::select!` with an `Option<Receiver>`.
/// Returns `None` if the receiver is `None` (not subscribed yet),
/// otherwise awaits the next message.
async fn recv_optional<T: Clone>(
    rx: Option<&mut tokio::sync::broadcast::Receiver<T>>,
) -> Option<Result<T, tokio::sync::broadcast::error::RecvError>> {
    match rx {
        Some(rx) => Some(rx.recv().await),
        None => std::future::pending().await,
    }
}
