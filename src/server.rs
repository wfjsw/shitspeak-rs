use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use bytes::{Bytes, BytesMut};
use parking_lot::Mutex;

use cidr::AnyIpCidr;
use prost::{EncodeError, Message as _};
use rustls::pki_types::{pem::PemObject as _, CertificateDer, PrivateKeyDer};
use rustls::version::{TLS12, TLS13};
use tokio_rustls::TlsAcceptor;

use crate::api::Authenticator;
use crate::blob_store::{ChannelBlobStore, SessionBlobStore};
use crate::channel_repository::{ChannelRepoTuning, ChannelRepository};
use crate::client::AsyncMessageHandlerExt;
use crate::client_certificate_verifier::ClientCertificateVerifier;
use crate::errors::{HandleIncomingConnectionError, ReadProtoMessageError};
use crate::messages::encoder::Version;
use crate::messages::{Message, WriteMessageExt};
use crate::proxy_protocol::get_proxy_protocol_real_ip;
use crate::voice::ping::decode_ping_protobuf;
use crate::{
    client_repository::ClientRepository, codec_info::CodecInfo, config::Config, s2s::S2SManager,
    types::NodeIdentifier,
};

pub struct Server {
    node_identifier: NodeIdentifier,

    // Shared config — can be hot-reloaded at runtime
    config: Arc<RwLock<Config>>,

    allowed_proxies: Vec<AnyIpCidr>,

    tcp_listener: tokio::net::TcpListener,
    tls_acceptor: TlsAcceptor,
    udp_socket: Arc<tokio::net::UdpSocket>,

    clients: Arc<ClientRepository>,
    channels: Arc<ChannelRepository>,
    channel_blobs: Arc<ChannelBlobStore>,
    session_blobs: Arc<SessionBlobStore>,
    bans: Arc<crate::ban_repository::BanRepository>,

    codec_info: Mutex<CodecInfo>,

    authenticator: Box<dyn Authenticator>,

    /// Registry of server-defined context menu actions.
    context_actions: Arc<crate::context_action::ContextActionRegistry>,

    s2s_manager: Arc<S2SManager>,
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
        let client_log_max_entries = config.client_log_max_entries;
        let channel_repo_tuning = ChannelRepoTuning::from(&config);
        let (channels, channel_blobs, session_blobs, bans) = match &config.blob_storage_dir {
            Some(dir) => {
                let ch_repo = ChannelRepository::open(node_id, dir, channel_repo_tuning).await?;
                let ch_blobs = Arc::new(ChannelBlobStore::open(dir).await?);
                let s_blobs = Arc::new(SessionBlobStore::open(dir).await?);
                let ban_repo = crate::ban_repository::BanRepository::open(node_id, dir).await?;
                (ch_repo, ch_blobs, s_blobs, ban_repo)
            }
            None => {
                // In-memory mode: use a temp dir for blob stores so the
                // code paths are uniform; blobs won't survive restarts.
                let tmp = std::env::temp_dir().join("shitspeak-blobs");
                let ch_repo = ChannelRepository::new_in_memory(node_id, channel_repo_tuning);
                let ch_blobs = Arc::new(ChannelBlobStore::open(&tmp).await?);
                let s_blobs = Arc::new(SessionBlobStore::open(&tmp).await?);
                let ban_repo = crate::ban_repository::BanRepository::new_in_memory(node_id);
                (ch_repo, ch_blobs, s_blobs, ban_repo)
            }
        };

        let config = Arc::new(RwLock::new(config));
        let s2s_manager = Arc::new(S2SManager::initialize(
            &config.read().expect("Config RwLock poisoned"),
        ));

        let server = Arc::new(Box::new(Server {
            node_identifier: node_id,
            allowed_proxies,
            tcp_listener,
            tls_acceptor,
            udp_socket,
            clients: Arc::new(ClientRepository::new(node_id, client_log_max_entries)),
            channels,
            channel_blobs,
            session_blobs,
            bans,
            codec_info: Mutex::new(CodecInfo::default()),
            authenticator: Box::new(authenticator),
            config,
            context_actions: Arc::new(crate::context_action::ContextActionRegistry::new()),
            s2s_manager,
        }));

        // Wire cross-repo causal notification: ChannelRepository notifies
        // ClientRepository to drain pending ops after remote channel ops.
        server
            .channels
            .set_client_repo(server.clients.clone())
            .await;

        Ok(server)
    }

    /// Read the current config (acquires a read lock).
    pub fn read_config(&self) -> std::sync::RwLockReadGuard<'_, Config> {
        self.config.read().expect("Config RwLock poisoned")
    }

    /// Local TCP listen address. Useful for tests that bind to `127.0.0.1:0`.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.tcp_listener.local_addr()
    }

    /// Local UDP listen address. Useful for tests that bind to `127.0.0.1:0`.
    pub fn local_udp_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.udp_socket.local_addr()
    }

    pub async fn run(
        self: &Arc<Box<Self>>,
        shutdown_tx: tokio::sync::watch::Sender<()>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("Server is running on {}", self.tcp_listener.local_addr()?);
        self.s2s_manager.log_startup_summary();

        let shutdown_rx = shutdown_tx.subscribe();

        // Snapshot startup-only config values (cannot be hot-reloaded).
        let udp_channel_size = self.read_config().udp_channel_size;
        let udp_voice_enabled = self.read_config().udp_voice_enabled;
        let udp_ping_enabled = self.read_config().udp_ping_enabled;
        let idle_timeout_secs = self.read_config().client_idle_timeout_secs;

        // Bounded channel shared between UDP drain and processing tasks.
        let (udp_in, udp_out) =
            tokio::sync::mpsc::channel::<(Bytes, std::net::SocketAddr)>(udp_channel_size);

        let udp_drain = Self::spawn_udp_drain(
            Arc::clone(self),
            Arc::clone(&self.udp_socket),
            udp_in,
            udp_voice_enabled,
            udp_ping_enabled,
            shutdown_rx.clone(),
        );
        let udp_process = Self::spawn_udp_process(
            Arc::clone(self),
            Arc::clone(&self.udp_socket),
            udp_out,
            udp_ping_enabled,
            shutdown_rx.clone(),
        );
        let tcp_accept = Self::spawn_tcp_accept(Arc::clone(self), shutdown_rx.clone());
        let idle_reaper =
            Self::spawn_idle_reaper(Arc::clone(self), idle_timeout_secs, shutdown_rx.clone());
        let _s2s_task = Arc::clone(&self.s2s_manager).spawn_runtime_task(shutdown_rx.clone());

        // Public server registration (periodic HTTP POST to registry).
        // This task is optional and may exit early when registration is disabled;
        // it must never terminate the main server loop.
        let _register_task = crate::register::spawn_register_task(Arc::clone(self), shutdown_rx);

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
        server: Arc<Box<Self>>,
        socket: Arc<tokio::net::UdpSocket>,
        tx: tokio::sync::mpsc::Sender<(Bytes, std::net::SocketAddr)>,
        voice_enabled: bool,
        ping_enabled: bool,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            tracing::info!(
                "UDP drain started, listening on {}",
                socket
                    .local_addr()
                    .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)))
            );
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

                if len <= 1 {
                    // Empty packages or packages consisting only of the header byte are invalid
                    continue;
                }

                let packet = &buf[..len];
                tracing::trace!("UDP received {} bytes from {}", len, src_addr);

                if ping_enabled {
                    match crate::voice::ping::try_decode_ping(packet).await {
                        Ok(ping) => {
                            tracing::debug!(
                                "UDP ping from {}: timestamp={}, format={}",
                                src_addr,
                                ping.timestamp,
                                ping.format
                            );
                            let reply = match Self::build_ping_response(&server, &ping).await {
                                Ok(r) => r,
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to build UDP ping response for {}: {e}",
                                        src_addr
                                    );
                                    continue;
                                }
                            };
                            match socket.send_to(&reply, src_addr).await {
                                Ok(sent) => tracing::trace!(
                                    "UDP ping reply sent to {}: {} bytes",
                                    src_addr,
                                    sent
                                ),
                                Err(e) => {
                                    tracing::warn!("UDP ping reply failed to {}: {e}", src_addr)
                                }
                            }
                            continue;
                        }
                        Err(crate::voice::codec::DecodeError::NotPing) => {
                            // Not a ping packet, continue with normal processing
                        }
                        Err(e) => {
                            tracing::trace!("UDP packet decode failed from {}: {e}", src_addr);
                            continue;
                        }
                    }
                }

                if voice_enabled {
                    let packet = Bytes::copy_from_slice(packet);
                    match tx.try_send((packet, src_addr)) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!(
                                "UDP processing channel is full, dropping packet from {}",
                                src_addr
                            );
                        }
                        Err(e) => {
                            tracing::warn!("UDP processing channel error for {}: {e}", src_addr);
                        }
                    }
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
        mut rx: tokio::sync::mpsc::Receiver<(Bytes, std::net::SocketAddr)>,
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
                // Try address-based match first.  If the cached entry exists but
                // decrypt fails (stale NAT binding, crypt state re-keyed, etc.)
                // the binding is removed and we fall through to IP-based candidate
                // probing so the packet is not silently dropped.
                let mut decrypted_from_match: Option<BytesMut> = None;
                let mut matched_via_ip_fallback = false;

                let client = {
                    let address_match = server.clients.get_client_by_udp_address(&src_addr).await;
                    let mut found = None;

                    if let Some(c) = address_match {
                        if !c.is_authenticated() {
                            tracing::trace!(
                                "UDP client {:?} matched by address is not authenticated, skipping",
                                c.get_session_id()
                            );
                            server.clients.unbind_client_udp_address(&src_addr);
                        } else {
                            let decrypt_result: Option<Result<BytesMut, _>> = {
                                let mut crypt = c.crypt_state();
                                crypt.as_mut().map(|state| {
                                    let mut dec = BytesMut::new();
                                    state.decrypt(&mut dec, &packet).map(|_| dec)
                                })
                            };

                            match decrypt_result {
                                Some(Ok(dec)) => {
                                    tracing::trace!(
                                        "UDP client matched by address: {} -> session {:?}",
                                        src_addr,
                                        c.get_session_id()
                                    );
                                    decrypted_from_match = Some(dec);
                                    found = Some(c);
                                }
                                Some(Err(e)) => {
                                    tracing::trace!("UDP address-match decrypt failed for {:?} from {}: {:?}, removing stale binding", c.get_session_id(), src_addr, e);
                                    server.clients.unbind_client_udp_address(&src_addr);
                                }
                                None => {
                                    tracing::trace!("UDP address-matched client {:?} has no crypt state, removing stale binding", c.get_session_id());
                                    server.clients.unbind_client_udp_address(&src_addr);
                                }
                            }
                        }
                    }

                    if found.is_none() {
                        let candidates = server.clients.get_clients_by_ip(&src_addr.ip()).await;
                        let mut matched = None;
                        for c in &candidates {
                            if !c.is_authenticated() {
                                tracing::trace!("UDP client {:?} is not authenticated, skipping for IP fallback", c.get_session_id());
                                continue;
                            }

                            let decrypted = {
                                let mut crypt = c.crypt_state();
                                match crypt.as_mut() {
                                    Some(state) => {
                                        let mut decrypted = BytesMut::new();
                                        match state.decrypt(&mut decrypted, &packet) {
                                            Ok(()) => {
                                                tracing::trace!("UDP packet from {} successfully decrypted with client {:?} during IP fallback", src_addr, c.get_session_id());
                                                Some(decrypted)
                                            }
                                            Err(e) => {
                                                tracing::trace!("UDP packet from {} failed to decrypt with client {:?} during IP fallback: {:?}", src_addr, c.get_session_id(), e);
                                                None
                                            }
                                        }
                                    }
                                    None => {
                                        tracing::trace!("UDP client {:?} has no crypt state yet, skipping for IP fallback", c.get_session_id());
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

                // A valid UDP voice packet indicates UDP path is working.
                client.set_prefer_tcp_tunnel(false);

                if matched_via_ip_fallback {
                    tracing::trace!(
                        "Binding UDP address {} to client {:?} after successful IP fallback match",
                        src_addr,
                        client.get_session_id()
                    );

                    server
                        .clients
                        .bind_client_udp_address(client.get_session_id(), src_addr)
                        .await;
                }

                // Packet was already decrypted during client matching.
                let Some(decrypted) = decrypted_from_match else {
                    continue;
                };

                // After decryption, check if this is a ping or audio packet.
                match crate::voice::codec::decode_udp_packet(&decrypted).await {
                    Ok(crate::voice::codec::UdpPacket::Ping(ping)) => {
                        tracing::trace!(
                            "UDP ping from {}: timestamp={}, format={}",
                            src_addr,
                            ping.timestamp,
                            ping.format
                        );
                        tracing::debug!("UDP ping from {}: timestamp={}", src_addr, ping.timestamp);
                        let reply = match Self::build_ping_response(&server, &ping).await {
                            Ok(r) => r,
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to build UDP ping response for {}: {e}",
                                    src_addr
                                );
                                continue;
                            }
                        };
                        match socket.send_to(&reply, src_addr).await {
                            Ok(sent) => tracing::trace!(
                                "UDP ping reply sent to {}: {} bytes",
                                src_addr,
                                sent
                            ),
                            Err(e) => tracing::warn!("UDP ping reply failed to {}: {e}", src_addr),
                        }
                        continue;
                    }
                    Ok(crate::voice::codec::UdpPacket::Audio(mut decoded_audio)) => {
                        tracing::trace!(
                            "UDP audio packet from {}: sender_session={}, frame_number={}, format={:?}, payload_len={}",
                            src_addr, decoded_audio.sender_session, decoded_audio.frame_number, decoded_audio.format, decoded_audio.opus_data.len());
                        let actual_session = u32::from(client.get_session_id());
                        if decoded_audio.sender_session != 0
                            && decoded_audio.sender_session != actual_session
                        {
                            tracing::trace!(
                                "UDP sender_session mismatch from {}: packet={}, matched={}",
                                src_addr,
                                decoded_audio.sender_session,
                                actual_session,
                            );
                        }
                        // Trust authenticated client identity derived from
                        // endpoint+crypto match, not packet self-asserted session.
                        decoded_audio.sender_session = actual_session;

                        client.push_voice_routing(decoded_audio, true);
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

        // Send server version (these are startup-only, read once)
        let version = {
            let cfg = self.read_config();
            Version::for_server(cfg.send_version, cfg.send_build_info, cfg.send_os_info)
        }; // cfg dropped here
        tls_stream.write_proto_message(&version.into()).await?;

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
                                match client.handle_message(self, message).await {
                                    Ok(()) => {}
                                    Err(crate::errors::MessageHandlerError::AuthRejection(rejection)) => {
                                        tracing::info!(session = u32::from(client_session_id), reason = rejection.reason(), "closing connection after auth rejection");
                                        return Err(HandleIncomingConnectionError::AuthRejected(rejection));
                                    }
                                    Err(err) => {
                                        return Err(HandleIncomingConnectionError::MessageHandlerFailed(err));
                                    }
                                }

                                // Transition to post-auth: publish and subscribe.
                                if client.is_authenticated() && client_log_rx.is_none() {
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
                            Err(crate::errors::ReadProtoMessageError::UnknownMessageType(err)) => {
                                tracing::warn!(
                                    "Client {:?} sent unknown message type {} — ignoring",
                                    client_session_id,
                                    err.message_type,
                                );
                                // Gracefully ignore unknown message types
                            }
                            Err(err) => return Err(HandleIncomingConnectionError::ReadProtoMessageError(err)),
                        }
                    }

                    // ── Channel state change notification ────────────────────
                    // Must come BEFORE client_log_rx in select! to ensure
                    // channel updates are delivered before client state updates.
                    result = recv_optional(channel_log_rx.as_mut()), if channel_log_rx.is_some() => {
                        match result {
                            Some(Ok(op)) => {
                                let last = client.get_last_channel_version().await;
                                replay_channel_log_gap(
                                    self, &client, &self.channels, client_session_id, last, op.version,
                                ).await.map_err(|()| HandleIncomingConnectionError::ChannelLogGapUnrecoverable)?;

                                // Use unified message conversion function
                                let messages = convert_channel_operation_to_messages(self, &client, &op, &self.channels).await;
                                for msg in messages {
                                    client.write_proto_message(&msg).await
                                        .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
                                }
                                client.set_last_channel_version(op.version).await;
                            }
                            Some(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {
                                let last = client.get_last_channel_version().await;
                                replay_channel_log_gap(
                                    self, &client, &self.channels, client_session_id, last, u64::MAX,
                                ).await.map_err(|()| HandleIncomingConnectionError::ChannelLogGapUnrecoverable)?;
                            }
                            Some(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                                return Ok(());
                            }
                            None => {} // not subscribed yet
                        }
                    }

                    // ── Client state change notification ─────────────────────
                    result = recv_optional(client_log_rx.as_mut()), if client_log_rx.is_some() => {
                        match result {
                            Some(Ok(broadcast)) => {
                                tracing::trace!("Received client log broadcast: {:?}", broadcast);

                                let entry = &broadcast.entry;
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

                                // If this entry has a channel version dependency,
                                // catch up the client's channel view to that dep first.
                                if let Some(dep) = entry.channel_version_dep {
                                    let last_ch = client.get_last_channel_version().await;
                                    if last_ch < dep {
                                        replay_channel_log_gap(
                                            self, &client, &self.channels, client_session_id, last_ch, dep + 1,
                                        ).await.map_err(|()| HandleIncomingConnectionError::ChannelLogGapUnrecoverable)?;
                                    }
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
                }
            }
        }.await;

        // Single cleanup point: remove the client on any error.
        if result.is_err() {
            self.clients.remove_client(client_session_id).await;
        }
        result
    }

    /// Attempt to reload config from disk.  On success, atomically swaps
    /// the shared config and logs the changed keys.  Returns an error only
    /// if the config file is malformed (the old config stays in place).
    pub fn reload_config(&self) -> Result<(), Box<dyn std::error::Error>> {
        match Config::reload() {
            Ok(Some(new_config)) => {
                let mut current = self.config.write().expect("Config RwLock poisoned");
                // Log notable changes
                if current.welcome_text != new_config.welcome_text {
                    tracing::info!("config reload: welcome_text changed");
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
                if current.client_idle_timeout_secs != new_config.client_idle_timeout_secs {
                    tracing::info!(
                        "config reload: client_idle_timeout_secs {} -> {}",
                        current.client_idle_timeout_secs,
                        new_config.client_idle_timeout_secs
                    );
                }
                if current.required_groups != new_config.required_groups {
                    tracing::info!("config reload: required_groups changed");
                }
                if current.send_permission_info != new_config.send_permission_info {
                    tracing::info!(
                        "config reload: send_permission_info {} -> {}",
                        current.send_permission_info,
                        new_config.send_permission_info
                    );
                }
                *current = new_config;
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
        self.authenticator.as_ref()
    }

    pub fn get_bans(&self) -> &Arc<crate::ban_repository::BanRepository> {
        &self.bans
    }

    pub fn get_clients(&self) -> &Arc<ClientRepository> {
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

    pub fn get_send_permission_info(&self) -> bool {
        self.read_config().send_permission_info
    }

    pub fn get_max_bandwidth(&self) -> u32 {
        self.read_config().max_bandwidth
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

    /// Build a ping response with current server information.
    async fn build_ping_response(
        server: &Arc<Box<Self>>,
        ping: &crate::voice::ping::PingRequest,
    ) -> Result<Bytes, EncodeError> {
        // Snapshot config values before any .await (RwLockReadGuard is !Send)
        let (max_users, max_bandwidth) = {
            let cfg = server.read_config();
            (cfg.max_users, cfg.max_bandwidth)
        };
        let response = crate::voice::ping::PingResponse {
            timestamp: ping.timestamp,
            server_version: crate::constants::APP_PROTO_VER,
            user_count: server
                .clients
                .len()
                .await
                .clamp(0, u32::MAX.try_into().unwrap()) as u32,
            max_user_count: Some(max_users.clamp(0, u32::MAX.into()) as u32),
            max_bandwidth_per_user: max_bandwidth,
        };
        crate::voice::ping::encode_ping_response(&response, ping.format)
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

use crate::channel_handler::{
    apply_permission_info_to_channel_state, convert_channel_operation_to_messages,
    replay_channel_log_gap,
};
use crate::utils::recv_optional;

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
        session_id,
        node_id,
        last,
        current,
    );

    let missed = repo.get_log_since(last).await;
    if missed.is_empty() && last > 0 {
        tracing::error!(
            "Client {:?} client log gap unrecoverable (node={}, last={})",
            session_id,
            node_id,
            last,
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
