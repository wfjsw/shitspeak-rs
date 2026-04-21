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
        let udp_process = Self::spawn_udp_process(Arc::clone(self), udp_out, shutdown_rx.clone());
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

                // Check for ping packets first — handle directly.
                if ping_enabled {
                    if let Ok(crate::voice::codec::UdpPacket::Ping(ping)) =
                        crate::voice::codec::decode_udp_packet(packet)
                    {
                        let reply = Self::build_ping_response(&server, &ping).await;
                        let _ = socket.send_to(&reply, src_addr).await;
                        continue;
                    }
                }

                if !voice_enabled {
                    continue;
                }
                let packet = packet.to_vec();
                if tx.send((packet, src_addr)).await.is_err() {
                    break; // channel closed — shutting down
                }
            }
        })
    }

    /// Spawn the UDP processing task: decrypt, parse, and route voice
    /// packets from the channel.
    fn spawn_udp_process(
        server: Arc<Box<Self>>,
        mut rx: tokio::sync::mpsc::Receiver<(Vec<u8>, std::net::SocketAddr)>,
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

                let decoded_audio = match crate::voice::codec::decode_audio_packet(&decrypted) {
                    Ok(a) => a,
                    Err(_) => continue,
                };

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

        // ── Phase A: Pre-authentication ─────────────────────────────────
        // Process messages without a log subscription.  The client is
        // invisible to other subscribers until `publish_client()` is called.
        loop {
            match client.read_and_handle_message(self).await {
                Ok(_) => {
                    if client.is_authenticated().await {
                        break;
                    }
                }
                Err(_) => {
                    self.clients.remove_client(client_session_id).await;
                    return Ok(());
                }
            }
        }

        // ── Phase B: Post-authentication ────────────────────────────────
        // Record the version at the snapshot point, publish the client,
        // then start the log subscription and catch up on any mutations
        // that happened during burst construction.

        let snapshot_version = self.clients.current_version();
        self.clients.publish_client(client_session_id).await;

        let mut log_rx = self.clients.subscribe();

        // Replay any log entries emitted between the snapshot and now.
        {
            let missed = self.clients.get_log_since(snapshot_version).await;
            for entry in &missed {
                if entry.op.session_id() == Some(client_session_id) {
                    continue;
                }
                if let Some(msg) = entry.to_message(&self.clients).await {
                    if client.write_proto_message(&msg).await.is_err() {
                        self.clients.remove_client(client_session_id).await;
                        return Ok(());
                    }
                }
            }
        }

        loop {
            tokio::select! {
                // ── Incoming message from this client ────────────────────
                result = client.read_and_handle_message(self) => {
                    match result {
                        Ok(_) => {}
                        Err(_) => {
                            // On error, remove the client and break the loop.
                            self.clients.remove_client(client_session_id).await;
                            return Ok(());
                        }
                    }
                }

                // ── State change notification from the log ───────────────
                result = log_rx.recv() => {
                    match result {
                        Ok(entry) => {
                            // Don't echo own changes back.
                            if entry.op.session_id() == Some(client_session_id) {
                                continue;
                            }
                            // Convert the log entry to a protobuf message and send it.
                            if let Some(msg) = entry.to_message(&self.clients).await {
                                if client.write_proto_message(&msg).await.is_err() {
                                    return Ok(());
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(
                                "Client {:?} lagged behind by {} log entries; disconnecting",
                                client_session_id,
                                n,
                            );
                            self.clients.remove_client(client_session_id).await;
                            return Ok(());
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            return Ok(());
                        }
                    }
                }
            }
        }
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
            server_version: crate::constants::APP_PROTO_VER.into(),
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
