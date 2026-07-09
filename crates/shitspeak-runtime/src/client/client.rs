use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::{IpAddr, Shutdown, SocketAddr},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use chrono::{DateTime, Utc};
use parking_lot::{
    MappedMutexGuard as ParkingMappedMutexGuard, Mutex as ParkingMutex,
    MutexGuard as ParkingMutexGuard, RwLock as ParkingRwLock,
    RwLockReadGuard as ParkingRwLockReadGuard, RwLockWriteGuard as ParkingRwLockWriteGuard,
};
use rustls::pki_types::CertificateDer;
use socket2::Socket;
use tokio::{
    io::{AsyncWriteExt as _, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::{Mutex as AsyncMutex, RwLock, RwLockWriteGuard, mpsc, watch},
    time::timeout,
};
use tokio_rustls::server::TlsStream;

use crate::{
    client::{
        client_global_state::ClientGlobalState, client_local_state::ClientLocalState,
        client_session_identifier::ClientSessionIdentifier, client_stats::ClientStats,
        crypt::CryptState, global_state_guard::GlobalStateWriteGuard, options::ClientOptions,
        user_info::UserInfoExtended, voice_target::VoiceTarget,
    },
    client_repository::ClientRepository,
    errors::{ReadProtoMessageError, WriteProtoMessageError},
    messages::{Message, ReadMessageExt, WriteMessageExt, encoder as msg_encoder},
    protocol_version::ProtocolVersion,
    types::{DEFAULT_SERVER_ID, ScopedSessionId},
    voice::VoiceRoutingPayload,
};

const VOICE_ROUTING_QUEUE_CAPACITY: usize = 1024;
const VOICE_TCP_QUEUE_CAPACITY: usize = 2048;
const OUTBOUND_MESSAGE_QUEUE_CAPACITY: usize = 1024;
const PROTO_MESSAGE_WRITE_CHUNK_BYTES: usize = 64 * 1024;
const PROTO_MESSAGE_WRITE_CHUNK_MESSAGES: usize = 32;
const UDP_TUNNEL_MESSAGE_TYPE: u16 = 1;
const VOICE_TCP_WRITE_CHUNK_BYTES: usize = 64 * 1024;
const VOICE_TCP_WRITE_CHUNK_MESSAGES: usize = 128;
const GRACEFUL_DISCONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Sentinel bit on the packed `protocol_version` atomic indicating that
/// the value has been set. The packed-u64 encoding from
/// `impl From<ProtocolVersion> for u64` only uses bits 16..64 (it always
/// shifts left by 16), so bit 0 is free to use as a "set" marker.
const PROTOCOL_VERSION_SET_BIT: u64 = 1;

fn proto_message_write_chunk_end(messages: &[Message], start: usize) -> usize {
    let mut bytes = 0usize;
    let mut end = start;
    while end < messages.len() {
        let message_bytes = 6 + messages[end].encoded_len();
        if end > start
            && (end - start >= PROTO_MESSAGE_WRITE_CHUNK_MESSAGES
                || bytes + message_bytes > PROTO_MESSAGE_WRITE_CHUNK_BYTES)
        {
            break;
        }
        bytes += message_bytes;
        end += 1;
    }
    end
}

fn udp_tunnel_write_chunk_end(frames: &[Bytes], start: usize) -> usize {
    let mut bytes = 0usize;
    let mut end = start;
    while end < frames.len() {
        let message_bytes = 6 + frames[end].len();
        if end > start
            && (end - start >= VOICE_TCP_WRITE_CHUNK_MESSAGES
                || bytes + message_bytes > VOICE_TCP_WRITE_CHUNK_BYTES)
        {
            break;
        }
        bytes += message_bytes;
        end += 1;
    }
    end
}

pub type ClientInstanceId = u64;
pub type ClientStateSubscription = tokio::sync::broadcast::Receiver<
    std::sync::Arc<crate::client::state_log::ClientStateBroadcastPayload>,
>;
pub type StagedChannelStateSubscription =
    (u64, crate::channel_repository::ChannelStateSubscription);

#[derive(Debug, Clone, Default)]
pub(crate) struct PostAuthBaseline {
    session_channel_shadow: crate::channel_handler::SessionChannelShadow,
    channel_tree_shadow: crate::channel_handler::ChannelTreeShadow,
    user_visibility: crate::client::visibility::UserVisibilityState,
}

impl PostAuthBaseline {
    pub(crate) fn new(
        session_channel_shadow: crate::channel_handler::SessionChannelShadow,
        channel_tree_shadow: crate::channel_handler::ChannelTreeShadow,
    ) -> Self {
        Self {
            session_channel_shadow,
            channel_tree_shadow,
            user_visibility: crate::client::visibility::UserVisibilityState::default(),
        }
    }

    pub(crate) fn with_user_visibility(
        session_channel_shadow: crate::channel_handler::SessionChannelShadow,
        channel_tree_shadow: crate::channel_handler::ChannelTreeShadow,
        user_visibility: crate::client::visibility::UserVisibilityState,
    ) -> Self {
        Self {
            session_channel_shadow,
            channel_tree_shadow,
            user_visibility,
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        crate::channel_handler::SessionChannelShadow,
        crate::channel_handler::ChannelTreeShadow,
        crate::client::visibility::UserVisibilityState,
    ) {
        (
            self.session_channel_shadow,
            self.channel_tree_shadow,
            self.user_visibility,
        )
    }
}

pub enum ClientOutboundMessage {
    Single(Message),
    Batch(Vec<Message>),
}

pub(crate) fn random_client_instance_id() -> ClientInstanceId {
    loop {
        let id = rand::random::<ClientInstanceId>();
        if id != 0 {
            return id;
        }
    }
}

fn client_tracing_span(
    session_id: ClientSessionIdentifier,
    real_ip_address: IpAddr,
    tcp_address: SocketAddr,
) -> tracing::Span {
    tracing::info_span!(
        "client",
        client_ip = %real_ip_address,
        client_port = tcp_address.port(),
        session = u32::from(session_id),
    )
}

use crate::constants::PROTOBUF_INTRODUCED_VERSION;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientTransportKind {
    NativeMumble,
    WebRtc,
    Moq,
    Remote,
}

pub struct Client {
    session_id: ParkingRwLock<ClientSessionIdentifier>,
    client_instance_id: ClientInstanceId,
    server_id: ParkingRwLock<String>,

    real_ip_address: IpAddr,
    tcp_address: SocketAddr,
    /// Address the client is reachable at over UDP. `None` until the server
    /// has either decoded a valid encrypted UDP packet from the client (which
    /// flows through `bind_client_udp_address`) or the client provided one at
    /// connection time. Stored under an `RwLock` because the voice routing
    /// fan-out reads it for every recipient on every packet, while the
    /// bind/unbind paths write it only on rare events.
    udp_address: ParkingRwLock<Option<SocketAddr>>,
    local_address: SocketAddr,
    tls_ja4: Option<String>,
    uses_proxy_protocol: bool,
    tracing_span: tracing::Span,

    transport: ClientTransport,
    disconnect_tx: watch::Sender<bool>,
    disconnect_rx: watch::Receiver<bool>,
    is_verified: bool,

    // Statistics
    login_time: DateTime<Utc>,
    last_active: ParkingMutex<DateTime<Utc>>,
    last_ping: ParkingMutex<DateTime<Utc>>,
    stats: RwLock<ClientStats>,

    certificate_hash: Option<Bytes>,
    certificate_chain: Vec<CertificateDer<'static>>,
    user_info_extended: ParkingMutex<Option<UserInfoExtended>>,

    options: RwLock<ClientOptions>,

    local_state: ParkingRwLock<Option<ClientLocalState>>,
    global_state: ParkingRwLock<ClientGlobalState>,
    crypt_state: ParkingMutex<Option<CryptState>>,
    voice_targets: ParkingMutex<HashMap<u32, VoiceTarget>>,
    voice_routing_tx: mpsc::Sender<VoiceRoutingPayload>,
    voice_routing_rx: ParkingMutex<Option<mpsc::Receiver<VoiceRoutingPayload>>>,
    /// Per-user outgoing TCP voice tunnel queue. The routing task pushes raw
    /// `UDPTunnel` payload bytes here without awaiting normal control fanout.
    /// Native clients drain this as a separate priority input in the writer
    /// task; gateway clients use the fallback bridge in `voice::routing`.
    voice_tcp_tx: mpsc::Sender<Bytes>,
    voice_tcp_rx: ParkingMutex<Option<mpsc::Receiver<Bytes>>>,
    outbound_message_tx: mpsc::Sender<ClientOutboundMessage>,
    outbound_message_rx: ParkingMutex<Option<mpsc::Receiver<ClientOutboundMessage>>>,

    /// Whether this client has been published to the log (i.e. `AddClient`
    /// has been emitted).  Only published clients generate `RemoveClient`
    /// log entries on disconnect.
    published: AtomicBool,
    pending_client_state_subscription: ParkingMutex<Option<ClientStateSubscription>>,
    pending_channel_state_subscription: ParkingMutex<Option<StagedChannelStateSubscription>>,
    pending_post_auth_baseline: ParkingMutex<Option<PostAuthBaseline>>,

    /// If true, send voice through TCP `UDPTunnel` instead of UDP.
    /// This is toggled when tunneled voice is received and reset once
    /// a valid UDP voice packet is seen again.
    prefer_tcp_tunnel: AtomicBool,
    can_receive_voice: AtomicBool,

    /// Negotiated client protocol version, populated once during the
    /// `Version` handshake (~immediately after `Authenticate`) and never
    /// changed afterwards. Stored as a packed u64 with bit 0 used as a
    /// "set" sentinel — see `protocol_version()` / `set_protocol_version()`
    /// for the bit layout. Atomic so the voice fan-out hot path
    /// (`uses_protobuf()`) reads it without taking a lock.
    protocol_version: AtomicU64,

    /// The last client-state log version this connection has seen,
    /// indexed by node_id.  Used to detect gaps and replay missed entries.
    last_client_version: ParkingMutex<HashMap<u16, u64>>,
    /// The last channel-state log version this connection has seen.
    /// Channels are fully serialized across the cluster, so a single
    /// version counter suffices.
    last_channel_version: ParkingMutex<u64>,
}

enum ClientTransport {
    NativeTls {
        rx: AsyncMutex<ReadHalf<TlsStream<TcpStream>>>,
        tx: AsyncMutex<WriteHalf<TlsStream<TcpStream>>>,
        socket: Option<Socket>,
    },
    WebGateway {
        kind: ClientTransportKind,
        outbound_tx: mpsc::Sender<Message>,
    },
    Remote,
}

impl ClientTransport {
    fn kind(&self) -> ClientTransportKind {
        match self {
            ClientTransport::NativeTls { .. } => ClientTransportKind::NativeMumble,
            ClientTransport::WebGateway { kind, .. } => *kind,
            ClientTransport::Remote => ClientTransportKind::Remote,
        }
    }
}

impl Client {
    pub fn new_local(
        session_id: ClientSessionIdentifier,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        udp_address: Option<SocketAddr>,
        local_address: SocketAddr,
        connection: TlsStream<TcpStream>,
    ) -> Box<Self> {
        Self::new_local_in_server(
            DEFAULT_SERVER_ID.to_owned(),
            session_id,
            real_ip_address,
            tcp_address,
            udp_address,
            local_address,
            connection,
            None,
            false,
        )
    }

    pub fn new_local_in_server(
        server_id: String,
        session_id: ClientSessionIdentifier,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        udp_address: Option<SocketAddr>,
        local_address: SocketAddr,
        connection: TlsStream<TcpStream>,
        tls_ja4: Option<String>,
        uses_proxy_protocol: bool,
    ) -> Box<Self> {
        Self::new_local_in_server_with_instance_id(
            server_id,
            session_id,
            real_ip_address,
            tcp_address,
            udp_address,
            local_address,
            connection,
            tls_ja4,
            uses_proxy_protocol,
            random_client_instance_id(),
        )
    }

    pub(crate) fn new_local_in_server_with_instance_id(
        server_id: String,
        session_id: ClientSessionIdentifier,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        udp_address: Option<SocketAddr>,
        local_address: SocketAddr,
        connection: TlsStream<TcpStream>,
        tls_ja4: Option<String>,
        uses_proxy_protocol: bool,
        client_instance_id: ClientInstanceId,
    ) -> Box<Self> {
        let (certificate_hash, certificate_chain, is_verified) = {
            let (_, tls_connection) = connection.get_ref();
            let certificate_chain = tls_connection
                .peer_certificates()
                .map(|certs| certs.to_vec())
                .unwrap_or_default();
            let certificate_hash = certificate_chain.first().map(|cert| {
                Bytes::copy_from_slice(
                    aws_lc_rs::digest::digest(
                        &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
                        cert.as_ref(),
                    )
                    .as_ref(),
                )
            });
            let is_verified = !certificate_chain.is_empty();
            (certificate_hash, certificate_chain, is_verified)
        };

        let now = Utc::now();

        let (voice_routing_tx, voice_routing_rx) =
            mpsc::channel::<VoiceRoutingPayload>(VOICE_ROUTING_QUEUE_CAPACITY);
        let (voice_tcp_tx, voice_tcp_rx) = mpsc::channel::<Bytes>(VOICE_TCP_QUEUE_CAPACITY);
        let (outbound_message_tx, outbound_message_rx) =
            mpsc::channel::<ClientOutboundMessage>(OUTBOUND_MESSAGE_QUEUE_CAPACITY);

        let socket = socket2::SockRef::from(connection.get_ref().0)
            .try_clone()
            .ok();
        let (connection_rx, connection_tx) = tokio::io::split(connection);
        let (disconnect_tx, disconnect_rx) = watch::channel(false);

        Box::new(Client {
            session_id: ParkingRwLock::new(session_id),
            client_instance_id,
            server_id: ParkingRwLock::new(server_id),
            real_ip_address,
            tcp_address,
            udp_address: ParkingRwLock::new(udp_address),
            local_address,
            tls_ja4,
            uses_proxy_protocol,
            tracing_span: client_tracing_span(session_id, real_ip_address, tcp_address),
            transport: ClientTransport::NativeTls {
                rx: AsyncMutex::new(connection_rx),
                tx: AsyncMutex::new(connection_tx),
                socket,
            },
            disconnect_tx,
            disconnect_rx,
            is_verified,
            login_time: now,
            last_active: ParkingMutex::new(now),
            last_ping: ParkingMutex::new(now),
            stats: RwLock::new(ClientStats::default()),
            certificate_hash,
            certificate_chain,
            user_info_extended: ParkingMutex::new(Some(UserInfoExtended::default())),
            options: RwLock::new(ClientOptions::default()),
            local_state: ParkingRwLock::new(Some(ClientLocalState::new())),
            global_state: ParkingRwLock::new(ClientGlobalState::new()),
            crypt_state: ParkingMutex::new(None),
            voice_targets: ParkingMutex::new(HashMap::new()),
            voice_routing_tx,
            voice_routing_rx: ParkingMutex::new(Some(voice_routing_rx)),
            voice_tcp_tx,
            voice_tcp_rx: ParkingMutex::new(Some(voice_tcp_rx)),
            outbound_message_tx,
            outbound_message_rx: ParkingMutex::new(Some(outbound_message_rx)),
            published: AtomicBool::new(false),
            pending_client_state_subscription: ParkingMutex::new(None),
            pending_channel_state_subscription: ParkingMutex::new(None),
            pending_post_auth_baseline: ParkingMutex::new(None),
            prefer_tcp_tunnel: AtomicBool::new(false),
            can_receive_voice: AtomicBool::new(true),
            protocol_version: AtomicU64::new(0),
            last_client_version: ParkingMutex::new(HashMap::new()),
            last_channel_version: ParkingMutex::new(0),
        })
    }

    pub fn new_web_gateway(
        session_id: ClientSessionIdentifier,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        local_address: SocketAddr,
        outbound_tx: mpsc::Sender<Message>,
    ) -> Box<Self> {
        Self::new_web_gateway_with_kind_in_server(
            DEFAULT_SERVER_ID.to_owned(),
            session_id,
            real_ip_address,
            tcp_address,
            local_address,
            outbound_tx,
            ClientTransportKind::WebRtc,
            random_client_instance_id(),
        )
    }

    pub fn new_web_gateway_in_server(
        server_id: String,
        session_id: ClientSessionIdentifier,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        local_address: SocketAddr,
        outbound_tx: mpsc::Sender<Message>,
    ) -> Box<Self> {
        Self::new_web_gateway_in_server_with_instance_id(
            server_id,
            session_id,
            real_ip_address,
            tcp_address,
            local_address,
            outbound_tx,
            random_client_instance_id(),
        )
    }

    pub(crate) fn new_web_gateway_in_server_with_instance_id(
        server_id: String,
        session_id: ClientSessionIdentifier,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        local_address: SocketAddr,
        outbound_tx: mpsc::Sender<Message>,
        client_instance_id: ClientInstanceId,
    ) -> Box<Self> {
        Self::new_web_gateway_with_kind_in_server(
            server_id,
            session_id,
            real_ip_address,
            tcp_address,
            local_address,
            outbound_tx,
            ClientTransportKind::WebRtc,
            client_instance_id,
        )
    }

    pub fn new_moq_gateway_in_server(
        server_id: String,
        session_id: ClientSessionIdentifier,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        local_address: SocketAddr,
        outbound_tx: mpsc::Sender<Message>,
    ) -> Box<Self> {
        Self::new_moq_gateway_in_server_with_instance_id(
            server_id,
            session_id,
            real_ip_address,
            tcp_address,
            local_address,
            outbound_tx,
            random_client_instance_id(),
        )
    }

    pub(crate) fn new_moq_gateway_in_server_with_instance_id(
        server_id: String,
        session_id: ClientSessionIdentifier,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        local_address: SocketAddr,
        outbound_tx: mpsc::Sender<Message>,
        client_instance_id: ClientInstanceId,
    ) -> Box<Self> {
        Self::new_web_gateway_with_kind_in_server(
            server_id,
            session_id,
            real_ip_address,
            tcp_address,
            local_address,
            outbound_tx,
            ClientTransportKind::Moq,
            client_instance_id,
        )
    }

    fn new_web_gateway_with_kind_in_server(
        server_id: String,
        session_id: ClientSessionIdentifier,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        local_address: SocketAddr,
        outbound_tx: mpsc::Sender<Message>,
        kind: ClientTransportKind,
        client_instance_id: ClientInstanceId,
    ) -> Box<Self> {
        let now = Utc::now();
        let (voice_routing_tx, voice_routing_rx) =
            mpsc::channel::<VoiceRoutingPayload>(VOICE_ROUTING_QUEUE_CAPACITY);
        let (voice_tcp_tx, voice_tcp_rx) = mpsc::channel::<Bytes>(VOICE_TCP_QUEUE_CAPACITY);
        let (outbound_message_tx, outbound_message_rx) =
            mpsc::channel::<ClientOutboundMessage>(OUTBOUND_MESSAGE_QUEUE_CAPACITY);
        let (disconnect_tx, disconnect_rx) = watch::channel(false);

        Box::new(Client {
            session_id: ParkingRwLock::new(session_id),
            client_instance_id,
            server_id: ParkingRwLock::new(server_id),
            real_ip_address,
            tcp_address,
            udp_address: ParkingRwLock::new(None),
            local_address,
            tls_ja4: None,
            uses_proxy_protocol: false,
            tracing_span: client_tracing_span(session_id, real_ip_address, tcp_address),
            transport: ClientTransport::WebGateway { kind, outbound_tx },
            disconnect_tx,
            disconnect_rx,
            is_verified: false,
            login_time: now,
            last_active: ParkingMutex::new(now),
            last_ping: ParkingMutex::new(now),
            stats: RwLock::new(ClientStats::default()),
            certificate_hash: None,
            certificate_chain: Vec::new(),
            user_info_extended: ParkingMutex::new(Some(UserInfoExtended::default())),
            options: RwLock::new(ClientOptions::default()),
            local_state: ParkingRwLock::new(Some(ClientLocalState::new())),
            global_state: ParkingRwLock::new(ClientGlobalState::new()),
            crypt_state: ParkingMutex::new(None),
            voice_targets: ParkingMutex::new(HashMap::new()),
            voice_routing_tx,
            voice_routing_rx: ParkingMutex::new(Some(voice_routing_rx)),
            voice_tcp_tx,
            voice_tcp_rx: ParkingMutex::new(Some(voice_tcp_rx)),
            outbound_message_tx,
            outbound_message_rx: ParkingMutex::new(Some(outbound_message_rx)),
            published: AtomicBool::new(false),
            pending_client_state_subscription: ParkingMutex::new(None),
            pending_channel_state_subscription: ParkingMutex::new(None),
            pending_post_auth_baseline: ParkingMutex::new(None),
            prefer_tcp_tunnel: AtomicBool::new(false),
            can_receive_voice: AtomicBool::new(true),
            protocol_version: AtomicU64::new(0),
            last_client_version: ParkingMutex::new(HashMap::new()),
            last_channel_version: ParkingMutex::new(0),
        })
    }

    pub fn new_remote(
        session_id: ClientSessionIdentifier,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        udp_address: Option<SocketAddr>,
        local_address: SocketAddr,
        cert_hash: Option<Bytes>,
        login_time: DateTime<Utc>,
    ) -> Box<Self> {
        Self::new_remote_in_server(
            DEFAULT_SERVER_ID.to_owned(),
            session_id,
            real_ip_address,
            tcp_address,
            udp_address,
            local_address,
            cert_hash,
            login_time,
            random_client_instance_id(),
        )
    }

    pub fn new_remote_in_server(
        server_id: String,
        session_id: ClientSessionIdentifier,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        udp_address: Option<SocketAddr>,
        local_address: SocketAddr,
        cert_hash: Option<Bytes>,
        login_time: DateTime<Utc>,
        client_instance_id: ClientInstanceId,
    ) -> Box<Self> {
        let is_verified = cert_hash.is_some();
        let (voice_routing_tx, voice_routing_rx) =
            mpsc::channel::<VoiceRoutingPayload>(VOICE_ROUTING_QUEUE_CAPACITY);
        let (voice_tcp_tx, voice_tcp_rx) = mpsc::channel::<Bytes>(VOICE_TCP_QUEUE_CAPACITY);
        let (outbound_message_tx, outbound_message_rx) =
            mpsc::channel::<ClientOutboundMessage>(OUTBOUND_MESSAGE_QUEUE_CAPACITY);
        let (disconnect_tx, disconnect_rx) = watch::channel(false);

        Box::new(Client {
            session_id: ParkingRwLock::new(session_id),
            client_instance_id,
            server_id: ParkingRwLock::new(server_id),
            real_ip_address,
            tcp_address,
            udp_address: ParkingRwLock::new(udp_address),
            local_address,
            tls_ja4: None,
            uses_proxy_protocol: false,
            tracing_span: client_tracing_span(session_id, real_ip_address, tcp_address),
            transport: ClientTransport::Remote,
            disconnect_tx,
            disconnect_rx,
            is_verified,
            login_time,
            last_active: ParkingMutex::new(login_time),
            last_ping: ParkingMutex::new(login_time),
            stats: RwLock::new(ClientStats::default()),
            certificate_hash: cert_hash,
            certificate_chain: Vec::new(),
            user_info_extended: ParkingMutex::new(Some(UserInfoExtended::default())),
            options: RwLock::new(ClientOptions::default()),
            local_state: ParkingRwLock::new(None),
            global_state: ParkingRwLock::new(ClientGlobalState::new()),
            crypt_state: ParkingMutex::new(None),
            voice_targets: ParkingMutex::new(HashMap::new()),
            voice_routing_tx,
            voice_routing_rx: ParkingMutex::new(Some(voice_routing_rx)),
            voice_tcp_tx,
            voice_tcp_rx: ParkingMutex::new(Some(voice_tcp_rx)),
            outbound_message_tx,
            outbound_message_rx: ParkingMutex::new(Some(outbound_message_rx)),
            published: AtomicBool::new(true),
            pending_client_state_subscription: ParkingMutex::new(None),
            pending_channel_state_subscription: ParkingMutex::new(None),
            pending_post_auth_baseline: ParkingMutex::new(None),
            prefer_tcp_tunnel: AtomicBool::new(false),
            can_receive_voice: AtomicBool::new(true),
            protocol_version: AtomicU64::new(0),
            last_client_version: ParkingMutex::new(HashMap::new()),
            last_channel_version: ParkingMutex::new(0),
        })
    }

    pub fn is_registered(&self) -> bool {
        self.global_state.read().is_registered()
    }

    pub fn has_certificate(&self) -> bool {
        self.certificate_hash.is_some()
    }

    pub fn is_published(&self) -> bool {
        self.published.load(Ordering::Acquire)
    }

    pub fn set_published(&self, value: bool) {
        self.published.store(value, Ordering::Release);
    }

    pub fn stage_client_state_subscription(&self, rx: ClientStateSubscription) {
        *self.pending_client_state_subscription.lock() = Some(rx);
    }

    pub fn take_client_state_subscription(&self) -> Option<ClientStateSubscription> {
        self.pending_client_state_subscription.lock().take()
    }

    pub fn stage_channel_state_subscription(
        &self,
        version: u64,
        rx: crate::channel_repository::ChannelStateSubscription,
    ) {
        *self.pending_channel_state_subscription.lock() = Some((version, rx));
    }

    pub fn take_channel_state_subscription(&self) -> Option<StagedChannelStateSubscription> {
        self.pending_channel_state_subscription.lock().take()
    }

    pub(crate) fn stage_post_auth_baseline(&self, baseline: PostAuthBaseline) {
        *self.pending_post_auth_baseline.lock() = Some(baseline);
    }

    pub(crate) fn take_post_auth_baseline(&self) -> Option<PostAuthBaseline> {
        self.pending_post_auth_baseline.lock().take()
    }

    pub fn set_prefer_tcp_tunnel(&self, value: bool) {
        self.prefer_tcp_tunnel.store(value, Ordering::Release);
    }

    pub fn prefers_tcp_tunnel(&self) -> bool {
        self.prefer_tcp_tunnel.load(Ordering::Acquire)
    }

    pub fn can_receive_voice(&self) -> bool {
        if self.can_receive_voice.load(Ordering::Acquire) {
            return true;
        }
        let current = self.global_state.read().can_receive_voice();
        if current {
            self.can_receive_voice.store(true, Ordering::Release);
        }
        current
    }

    pub fn set_can_receive_voice(&self, value: bool) {
        self.can_receive_voice.store(value, Ordering::Release);
    }

    pub fn refresh_can_receive_voice(&self) {
        self.set_can_receive_voice(self.global_state.read().can_receive_voice());
    }

    /// Get a clone of the full per-node last-seen version map.
    pub async fn get_last_client_versions(&self) -> HashMap<u16, u64> {
        self.last_client_version.lock().clone()
    }

    /// Merge the given per-node version map into the client's last-seen
    /// trackers.  Each entry is updated to `max(existing, new)`, except
    /// version `0`, which marks a remote-origin reset and clears that node.
    pub async fn update_last_client_versions(&self, versions: &HashMap<u16, u64>) {
        let mut map = self.last_client_version.lock();
        for (&node_id, &version) in versions {
            if version == 0 {
                map.remove(&node_id);
                continue;
            }
            let entry = map.entry(node_id).or_insert(0);
            *entry = (*entry).max(version);
        }
    }

    pub async fn remove_last_client_version(&self, node_id: u16) {
        self.last_client_version.lock().remove(&node_id);
    }

    /// Get the last channel-state version seen.
    pub async fn get_last_channel_version(&self) -> u64 {
        *self.last_channel_version.lock()
    }

    /// Record a channel-state version seen.
    pub async fn set_last_channel_version(&self, version: u64) {
        *self.last_channel_version.lock() = version;
    }

    pub fn get_groups_clone(&self) -> HashSet<String> {
        self.global_state.read().get_groups().clone()
    }

    pub fn has_group(&self, group: &str) -> bool {
        self.global_state.read().has_group(group)
    }

    pub fn get_certificate_hash(&self) -> Option<&[u8]> {
        self.certificate_hash.as_deref()
    }

    pub fn get_certificate_chain(&self) -> &[CertificateDer<'static>] {
        &self.certificate_chain
    }

    pub fn get_session_id(&self) -> ClientSessionIdentifier {
        *self.session_id.read()
    }

    pub fn client_instance_id(&self) -> ClientInstanceId {
        self.client_instance_id
    }

    pub fn scoped_session_id(&self) -> ScopedSessionId {
        ScopedSessionId::new(self.server_id(), self.get_session_id())
    }

    pub fn server_id(&self) -> String {
        self.server_id.read().clone()
    }

    pub fn set_server_id(&self, server_id: String) {
        *self.server_id.write() = server_id;
    }

    pub fn set_scoped_identity(&self, server_id: String, session_id: ClientSessionIdentifier) {
        *self.server_id.write() = server_id;
        *self.session_id.write() = session_id;
        self.record_tracing_span_session();
    }

    pub fn get_node_id(&self) -> u16 {
        self.get_session_id().get_node_id()
    }

    pub fn get_local_session_id(&self) -> u32 {
        self.get_session_id().get_local_session_id()
    }

    pub fn get_tokens_clone(&self) -> HashSet<String> {
        self.global_state.read().get_tokens().clone()
    }

    pub fn has_token(&self, token: &str) -> bool {
        self.global_state.read().has_token(token)
    }

    pub fn get_current_channel_id(&self) -> u32 {
        self.global_state.read().get_current_channel_id()
    }

    pub fn display_name_opt(&self) -> Option<String> {
        self.global_state
            .read()
            .get_display_name_opt()
            .map(ToOwned::to_owned)
    }

    pub fn get_listening_channel_ids(&self) -> std::collections::HashSet<u32> {
        self.global_state.read().get_listening_channel_id().clone()
    }

    pub fn set_current_channel_id(
        &self,
        channel_id: u32,
        repo: &ClientRepository,
        channel_version: u64,
    ) {
        let previous_channel_id = self.get_current_channel_id();
        let mut gs =
            self.write_global_state_as(repo, Some(self.get_session_id()), Some(channel_version));
        if gs.set_current_channel_id(channel_id) {
            tracing::info!(
                server_id = %self.server_id(),
                session = u32::from(self.get_session_id()),
                user_id = ?gs.get_user_id(),
                display_name = ?gs.get_display_name_opt(),
                previous_channel_id,
                channel_id,
                "client entered channel"
            );
        }
    }

    pub fn get_user_id(&self) -> Option<u32> {
        self.global_state.read().get_user_id()
    }

    pub fn get_acl_generation(&self) -> u64 {
        self.global_state.read().get_acl_generation()
    }

    // pub fn get_display_name(&self) -> Option<String> {
    //     match &*self.user_info.lock() {
    //         Some(info) => Some(info.get_display_name().clone()),
    //         None => match &self.user_info_extended {
    //             Some(ext) => Some(ext.lock().username.clone()),
    //             None => None,
    //         },
    //     }
    // }

    pub fn get_tcp_address(&self) -> SocketAddr {
        self.tcp_address
    }

    pub fn get_local_address(&self) -> SocketAddr {
        self.local_address
    }

    pub fn tls_ja4(&self) -> Option<&str> {
        self.tls_ja4.as_deref()
    }

    pub fn uses_proxy_protocol(&self) -> bool {
        self.uses_proxy_protocol
    }

    pub fn get_udp_address(&self) -> Option<SocketAddr> {
        *self.udp_address.read()
    }

    /// Update the UDP address this client is reachable at. Called from the
    /// `ClientRepository::bind_client_udp_address` / `unbind_client_udp_address`
    /// paths once an incoming encrypted UDP packet has been associated with
    /// this session.
    pub fn set_udp_address(&self, addr: Option<SocketAddr>) {
        *self.udp_address.write() = addr;
    }

    pub fn get_real_ip_address(&self) -> IpAddr {
        self.real_ip_address
    }

    pub(crate) fn tracing_span(&self) -> tracing::Span {
        self.tracing_span.clone()
    }

    pub async fn in_tracing_span<F, T>(&self, future: F) -> T
    where
        F: Future<Output = T>,
    {
        use tracing::Instrument as _;

        future.instrument(self.tracing_span()).await
    }

    pub fn in_tracing_scope<T>(&self, f: impl FnOnce() -> T) -> T {
        self.tracing_span.in_scope(f)
    }

    fn record_tracing_span_session(&self) {
        self.tracing_span
            .record("session", u32::from(self.get_session_id()));
    }

    pub fn get_login_time(&self) -> DateTime<Utc> {
        self.login_time
    }

    pub fn is_verified(&self) -> bool {
        self.is_verified
    }

    pub async fn disconnect(&self) -> Result<(), WriteProtoMessageError> {
        let _ = self.disconnect_tx.send(true);
        if let ClientTransport::NativeTls { tx, socket, .. } = &self.transport {
            match timeout(GRACEFUL_DISCONNECT_TIMEOUT, async {
                let mut guard = tx.lock().await;
                guard.shutdown().await
            })
            .await
            {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(err)) => return Err(err.into()),
                Err(_) => {
                    tracing::debug!(
                        session = u32::from(self.get_session_id()),
                        timeout_ms = GRACEFUL_DISCONNECT_TIMEOUT.as_millis(),
                        "graceful disconnect timed out; forcibly shutting down socket",
                    );
                    Self::shutdown_socket(socket);
                }
            }
        }
        Ok(())
    }

    pub async fn force_disconnect(&self) -> Result<(), WriteProtoMessageError> {
        let _ = self.disconnect_tx.send(true);
        if let ClientTransport::NativeTls { socket, .. } = &self.transport {
            Self::shutdown_socket(socket);
        }
        Ok(())
    }

    fn shutdown_socket(socket: &Option<Socket>) {
        if let Some(socket) = socket {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }

    pub async fn disconnected(&self) {
        let mut rx = self.disconnect_rx.clone();
        if *rx.borrow() {
            return;
        }
        let _ = rx.changed().await;
    }

    pub async fn read_proto_message(&self) -> Result<Message, ReadProtoMessageError> {
        self.in_tracing_span(self.read_proto_message_inner()).await
    }

    async fn read_proto_message_inner(&self) -> Result<Message, ReadProtoMessageError> {
        let ClientTransport::NativeTls { rx, .. } = &self.transport else {
            return Err(transport_not_readable_error().into());
        };
        let mut guard = rx.lock().await;
        let message = guard.read_proto_message().await?;
        self.record_tcp_packets(1, 6 + message.encoded_len()).await;
        Ok(message)
    }

    pub fn transport_kind(&self) -> ClientTransportKind {
        self.transport.kind()
    }

    pub async fn enqueue_proto_message(
        &self,
        message: &Message,
    ) -> Result<(), WriteProtoMessageError> {
        self.in_tracing_span(self.enqueue_proto_message_inner(message))
            .await
    }

    async fn enqueue_proto_message_inner(
        &self,
        message: &Message,
    ) -> Result<(), WriteProtoMessageError> {
        match &self.transport {
            ClientTransport::NativeTls { .. } => {
                self.outbound_message_tx
                    .send(ClientOutboundMessage::Single(message.clone()))
                    .await
                    .map_err(|_| transport_closed_error())?;
            }
            ClientTransport::WebGateway { outbound_tx, .. } => {
                outbound_tx
                    .send(message.clone())
                    .await
                    .map_err(|_| transport_closed_error())?;
                self.record_tcp_packets(1, 6 + message.encoded_len()).await;
            }
            ClientTransport::Remote => return Err(transport_not_writable_error().into()),
        }
        Ok(())
    }

    pub async fn enqueue_proto_message_batch(
        &self,
        messages: &[Message],
    ) -> Result<(), WriteProtoMessageError> {
        self.in_tracing_span(self.enqueue_proto_message_batch_inner(messages))
            .await
    }

    async fn enqueue_proto_message_batch_inner(
        &self,
        messages: &[Message],
    ) -> Result<(), WriteProtoMessageError> {
        if messages.is_empty() {
            return Ok(());
        }

        match &self.transport {
            ClientTransport::NativeTls { .. } => {
                self.outbound_message_tx
                    .send(ClientOutboundMessage::Batch(messages.to_vec()))
                    .await
                    .map_err(|_| transport_closed_error())?;
            }
            ClientTransport::WebGateway { outbound_tx, .. } => {
                for message in messages {
                    outbound_tx
                        .send(message.clone())
                        .await
                        .map_err(|_| transport_closed_error())?;
                }
                let bytes = messages
                    .iter()
                    .map(|message| 6 + message.encoded_len())
                    .sum();
                self.record_tcp_packets(messages.len(), bytes).await;
            }
            ClientTransport::Remote => return Err(transport_not_writable_error().into()),
        }
        Ok(())
    }

    pub fn take_outbound_message_rx(&self) -> Option<mpsc::Receiver<ClientOutboundMessage>> {
        self.outbound_message_rx.lock().take()
    }

    pub async fn write_proto_message(
        &self,
        message: &Message,
    ) -> Result<(), WriteProtoMessageError> {
        self.in_tracing_span(self.write_proto_message_inner(message))
            .await
    }

    async fn write_proto_message_inner(
        &self,
        message: &Message,
    ) -> Result<(), WriteProtoMessageError> {
        match &self.transport {
            ClientTransport::NativeTls { .. } => {
                self.outbound_message_tx
                    .send(ClientOutboundMessage::Single(message.clone()))
                    .await
                    .map_err(|_| transport_closed_error())?;
            }
            ClientTransport::WebGateway { outbound_tx, .. } => {
                outbound_tx
                    .send(message.clone())
                    .await
                    .map_err(|_| transport_closed_error())?;
                self.record_tcp_packets(1, 6 + message.encoded_len()).await;
            }
            ClientTransport::Remote => return Err(transport_not_writable_error().into()),
        }
        Ok(())
    }

    pub async fn write_proto_message_direct(
        &self,
        message: &Message,
    ) -> Result<(), WriteProtoMessageError> {
        self.in_tracing_span(self.write_proto_message_direct_inner(message))
            .await
    }

    async fn write_proto_message_direct_inner(
        &self,
        message: &Message,
    ) -> Result<(), WriteProtoMessageError> {
        let bytes = 6 + message.encoded_len();
        match &self.transport {
            ClientTransport::NativeTls { tx, .. } => {
                let mut guard = tx.lock().await;
                guard.write_proto_message(message).await?;
            }
            ClientTransport::WebGateway { outbound_tx, .. } => {
                outbound_tx
                    .send(message.clone())
                    .await
                    .map_err(|_| transport_closed_error())?;
            }
            ClientTransport::Remote => return Err(transport_not_writable_error().into()),
        }
        self.record_tcp_packets(1, bytes).await;
        Ok(())
    }

    pub async fn write_proto_message_batch(
        &self,
        messages: &[Message],
    ) -> Result<(), WriteProtoMessageError> {
        self.in_tracing_span(self.write_proto_message_batch_inner(messages))
            .await
    }

    async fn write_proto_message_batch_inner(
        &self,
        messages: &[Message],
    ) -> Result<(), WriteProtoMessageError> {
        if messages.is_empty() {
            return Ok(());
        }

        match &self.transport {
            ClientTransport::NativeTls { .. } => {
                self.outbound_message_tx
                    .send(ClientOutboundMessage::Batch(messages.to_vec()))
                    .await
                    .map_err(|_| transport_closed_error())?;
            }
            ClientTransport::WebGateway { outbound_tx, .. } => {
                for message in messages {
                    outbound_tx
                        .send(message.clone())
                        .await
                        .map_err(|_| transport_closed_error())?;
                }
                let bytes = messages
                    .iter()
                    .map(|message| 6 + message.encoded_len())
                    .sum();
                self.record_tcp_packets(messages.len(), bytes).await;
            }
            ClientTransport::Remote => return Err(transport_not_writable_error().into()),
        }
        Ok(())
    }

    pub async fn write_proto_message_batch_direct(
        &self,
        messages: &[Message],
    ) -> Result<(), WriteProtoMessageError> {
        self.in_tracing_span(self.write_proto_message_batch_direct_inner(messages))
            .await
    }

    async fn write_proto_message_batch_direct_inner(
        &self,
        messages: &[Message],
    ) -> Result<(), WriteProtoMessageError> {
        let bytes = messages
            .iter()
            .map(|message| 6 + message.encoded_len())
            .sum();
        match &self.transport {
            ClientTransport::NativeTls { tx, .. } => {
                let mut start = 0;
                while start < messages.len() {
                    let end = proto_message_write_chunk_end(messages, start);
                    {
                        let mut guard = tx.lock().await;
                        guard
                            .write_proto_message_batch(&messages[start..end])
                            .await?;
                    }
                    start = end;
                    if start < messages.len() {
                        tokio::task::yield_now().await;
                    }
                }
            }
            ClientTransport::WebGateway { outbound_tx, .. } => {
                for message in messages {
                    outbound_tx
                        .send(message.clone())
                        .await
                        .map_err(|_| transport_closed_error())?;
                }
            }
            ClientTransport::Remote => return Err(transport_not_writable_error().into()),
        }
        self.record_tcp_packets(messages.len(), bytes).await;
        Ok(())
    }

    pub(crate) async fn write_udp_tunnel_batch_direct(
        &self,
        frames: &[Bytes],
    ) -> Result<(), WriteProtoMessageError> {
        self.in_tracing_span(self.write_udp_tunnel_batch_direct_inner(frames))
            .await
    }

    async fn write_udp_tunnel_batch_direct_inner(
        &self,
        frames: &[Bytes],
    ) -> Result<(), WriteProtoMessageError> {
        if frames.is_empty() {
            return Ok(());
        }

        let bytes = frames.iter().map(|frame| 6 + frame.len()).sum();
        match &self.transport {
            ClientTransport::NativeTls { tx, .. } => {
                let mut start = 0;
                while start < frames.len() {
                    let end = udp_tunnel_write_chunk_end(frames, start);
                    let chunk = &frames[start..end];
                    let chunk_bytes = chunk.iter().map(|frame| 6 + frame.len()).sum();
                    let mut buf = BytesMut::with_capacity(chunk_bytes);
                    for frame in chunk {
                        buf.extend_from_slice(&UDP_TUNNEL_MESSAGE_TYPE.to_be_bytes());
                        buf.extend_from_slice(&(frame.len() as u32).to_be_bytes());
                        buf.extend_from_slice(frame);
                    }
                    {
                        let mut guard = tx.lock().await;
                        guard.write_all(&buf).await?;
                    }
                    start = end;
                    if start < frames.len() {
                        tokio::task::yield_now().await;
                    }
                }
            }
            ClientTransport::WebGateway { outbound_tx, .. } => {
                for frame in frames {
                    outbound_tx
                        .send(Message::UDPTunnel(frame.clone()))
                        .await
                        .map_err(|_| transport_closed_error())?;
                }
            }
            ClientTransport::Remote => return Err(transport_not_writable_error().into()),
        }
        self.record_tcp_packets(frames.len(), bytes).await;
        Ok(())
    }

    pub fn set_tokens(&self, tokens: HashSet<String>, repo: &ClientRepository) {
        let mut gs = self.write_global_state(repo);
        gs.set_tokens(tokens);
    }

    pub async fn get_last_ping(&self) -> DateTime<Utc> {
        let last_ping = self.last_ping.lock();
        *last_ping
    }

    pub fn idle_duration(&self) -> chrono::Duration {
        chrono::Utc::now() - *self.last_active.lock()
    }

    pub fn touch_activity(&self) {
        *self.last_active.lock() = Utc::now();
    }

    pub async fn reset_last_ping(&self) {
        let now = Utc::now();
        *self.last_ping.lock() = now;
        *self.last_active.lock() = now;
    }

    pub async fn record_udp_packet(&self, bytes: usize) {
        let mut stats = self.stats.write().await;
        stats.record_udp_packet(bytes);
    }

    pub async fn record_tcp_packets(&self, packets: usize, bytes: usize) {
        let mut stats = self.stats.write().await;
        stats.record_tcp_packets(packets, bytes);
    }

    // pub async fn update_from_ping_message(&self, ping_message: &Ping) {
    //     {
    //         let mut crypt_state = self.crypt_state.lock().await;
    //         if let Some(state) = crypt_state.as_mut() {
    //             state.update_from_ping_message(ping_message);
    //         }
    //     }

    //     {
    //         let mut stats = self.stats.write().await;
    //         stats.update_from_ping_message(ping_message);
    //     }
    // }

    pub fn crypt_state(&self) -> ParkingMutexGuard<'_, Option<CryptState>> {
        self.crypt_state.lock()
    }

    pub fn try_crypt_state(&self) -> Option<ParkingMutexGuard<'_, Option<CryptState>>> {
        self.crypt_state
            .try_lock_until(std::time::Instant::now() + std::time::Duration::from_millis(10))
    }

    pub fn create_crypt_state(&self, mode: &str) -> Result<(), crate::client::crypt::CryptError> {
        let mut state = self.crypt_state.lock();
        let rng = aws_lc_rs::rand::SystemRandom::new();
        *state = Some(CryptState::generate(mode, &rng)?);
        Ok(())
    }

    pub fn set_voice_target(&self, id: u32, target: VoiceTarget) {
        self.voice_targets.lock().insert(id, target);
    }

    pub fn voice_target(&self, id: u32) -> Option<VoiceTarget> {
        self.voice_targets.lock().get(&id).cloned()
    }

    pub fn push_voice_routing(&self, decoded_audio: crate::voice::codec::Audio) -> bool {
        let payload = VoiceRoutingPayload::new(decoded_audio);
        let capacity = self.voice_routing_tx.max_capacity();
        let depth = capacity.saturating_sub(self.voice_routing_tx.capacity());
        crate::voice::metrics::record_queue_status(
            crate::voice::metrics::VoiceQueueKind::Routing,
            depth,
            capacity,
        );
        match self.voice_routing_tx.try_send(payload) {
            Ok(()) => {
                crate::voice::metrics::record_queue_enqueue(
                    crate::voice::metrics::VoiceQueueKind::Routing,
                    crate::voice::metrics::VoiceQueueEnqueueResult::Accepted,
                );
                true
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                crate::voice::metrics::record_queue_enqueue(
                    crate::voice::metrics::VoiceQueueKind::Routing,
                    crate::voice::metrics::VoiceQueueEnqueueResult::Full,
                );
                crate::voice::metrics::record_queue_drop(
                    crate::voice::metrics::VoiceQueueDropReason::RoutingQueueFullOrClosed,
                );
                tracing::trace!(
                    session = u32::from(self.get_session_id()),
                    "voice routing queue full, dropping packet"
                );
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                crate::voice::metrics::record_queue_enqueue(
                    crate::voice::metrics::VoiceQueueKind::Routing,
                    crate::voice::metrics::VoiceQueueEnqueueResult::Closed,
                );
                crate::voice::metrics::record_queue_drop(
                    crate::voice::metrics::VoiceQueueDropReason::RoutingQueueFullOrClosed,
                );
                tracing::trace!(
                    session = u32::from(self.get_session_id()),
                    "voice routing queue closed, dropping packet"
                );
                false
            }
        }
    }

    /// Take the receiver half of the voice routing queue.  Called once by
    /// `spawn_voice_routing_task`; returns `None` on any subsequent call.
    pub fn take_voice_routing_rx(&self) -> Option<mpsc::Receiver<VoiceRoutingPayload>> {
        self.voice_routing_rx.lock().take()
    }

    /// Enqueue an already-encoded `UDPTunnel` payload for transmission to
    /// this client over its TCP voice tunnel.  Non-blocking: returns
    /// immediately, dropping the packet if the queue is full or closed.
    ///
    /// In debug builds a full queue triggers a `debug_assert!` panic since it
    /// indicates the per-user TCP send task is not keeping up; in release
    /// builds the packet is silently dropped (voice is realtime, backlog is
    /// worse than loss).
    pub fn try_enqueue_voice_tcp(&self, raw: Bytes) -> bool {
        let capacity = self.voice_tcp_tx.max_capacity();
        let depth = capacity.saturating_sub(self.voice_tcp_tx.capacity());
        crate::voice::metrics::record_queue_status(
            crate::voice::metrics::VoiceQueueKind::TcpFallback,
            depth,
            capacity,
        );
        match self.voice_tcp_tx.try_send(raw) {
            Ok(()) => {
                crate::voice::metrics::record_queue_enqueue(
                    crate::voice::metrics::VoiceQueueKind::TcpFallback,
                    crate::voice::metrics::VoiceQueueEnqueueResult::Accepted,
                );
                true
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                crate::voice::metrics::record_queue_enqueue(
                    crate::voice::metrics::VoiceQueueKind::TcpFallback,
                    crate::voice::metrics::VoiceQueueEnqueueResult::Full,
                );
                crate::voice::metrics::record_queue_drop(
                    crate::voice::metrics::VoiceQueueDropReason::TcpQueueFull,
                );
                debug_assert!(
                    false,
                    "voice TCP queue full for session {}",
                    u32::from(self.get_session_id())
                );
                tracing::trace!(
                    session = u32::from(self.get_session_id()),
                    "voice TCP queue full, dropping packet"
                );
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                crate::voice::metrics::record_queue_enqueue(
                    crate::voice::metrics::VoiceQueueKind::TcpFallback,
                    crate::voice::metrics::VoiceQueueEnqueueResult::Closed,
                );
                crate::voice::metrics::record_queue_drop(
                    crate::voice::metrics::VoiceQueueDropReason::TcpQueueClosed,
                );
                tracing::trace!(
                    session = u32::from(self.get_session_id()),
                    "voice TCP queue closed, dropping packet"
                );
                false
            }
        }
    }

    /// Take the receiver half of the voice TCP send queue. Called once by the
    /// native writer task or gateway fallback bridge; returns `None` after that.
    pub fn take_voice_tcp_rx(&self) -> Option<mpsc::Receiver<Bytes>> {
        self.voice_tcp_rx.lock().take()
    }

    pub async fn write_stats(&self) -> RwLockWriteGuard<'_, ClientStats> {
        self.stats.write().await
    }

    // pub async fn create_ping_response(&self, ping_message: &Ping) -> Ping {
    //     let crypt_state = self.crypt_state.lock().await;
    //     if let Some(state) = crypt_state.as_ref() {
    //         state.create_ping_response(ping_message)
    //     } else {
    //         ping_message.default_from_self()
    //     }
    // }

    pub fn is_authenticated(&self) -> bool {
        let local_state_guard = self.local_state.read();
        match &*local_state_guard {
            Some(state) => state.is_authenticated(),
            None => true,
        }
    }

    /// Returns `true` if this client has superuser privileges.
    ///
    pub fn is_superuser(&self) -> bool {
        self.global_state.read().is_superuser()
    }

    pub fn set_authenticated(&self, value: bool) {
        let mut local_state_guard = self.local_state.write();
        match &mut *local_state_guard {
            Some(state) => state.set_authenticated(value),
            None => panic!("Accessing local state on remote user"),
        }
    }

    pub fn language(&self) -> crate::localization::Language {
        self.local_state
            .read()
            .as_ref()
            .map(|state| state.language())
            .unwrap_or_default()
    }

    pub fn set_language(&self, language: crate::localization::Language) {
        if let Some(ref mut state) = *self.local_state.write() {
            state.set_language(language);
        }
    }

    pub fn max_bandwidth(&self, fallback: u32) -> u32 {
        self.local_state
            .read()
            .as_ref()
            .and_then(|state| state.max_bandwidth())
            .unwrap_or(fallback)
    }

    pub fn set_max_bandwidth(&self, max_bandwidth: Option<u32>) {
        if let Some(ref mut state) = *self.local_state.write() {
            state.set_max_bandwidth(max_bandwidth);
        }
    }

    /// Record the negotiated client protocol version. Called once during
    /// the `Version` handshake; subsequent calls are no-ops (the field
    /// is set-once-after-auth). `None` defaults to `1.2.0` to match the
    /// behavior of the legacy `ClientGlobalState::set_protocol_version`.
    pub fn set_protocol_version(&self, version: Option<ProtocolVersion>) {
        // Already set? Don't clobber.
        if self.protocol_version.load(Ordering::Acquire) != 0 {
            return;
        }
        let v = version.unwrap_or(ProtocolVersion::new(1, 2, 0));
        let packed: u64 = u64::from(v) | PROTOCOL_VERSION_SET_BIT;
        // CAS so the first writer wins; later callers (if any) silently no-op.
        let _ =
            self.protocol_version
                .compare_exchange(0, packed, Ordering::AcqRel, Ordering::Acquire);
    }

    /// Returns the negotiated client protocol version, or `None` if the
    /// `Version` handshake hasn't completed yet. Lock-free read.
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        let raw = self.protocol_version.load(Ordering::Acquire);
        if raw & PROTOCOL_VERSION_SET_BIT == 0 {
            return None;
        }
        Some(ProtocolVersion::from(raw & !PROTOCOL_VERSION_SET_BIT))
    }

    /// Whether the client speaks the protobuf-format UDP voice path
    /// (Mumble protocol >= 1.5.0). Read on every voice fan-out fan iteration,
    /// hence the lock-free atomic.
    pub fn uses_protobuf(&self) -> bool {
        self.protocol_version()
            .map_or(false, |v| v >= PROTOBUF_INTRODUCED_VERSION)
    }

    pub fn set_release(&self, release: Option<String>) {
        let mut local_state_guard = self.local_state.write();
        if let Some(ref mut state) = *local_state_guard {
            state.set_release(release);
        }
    }

    pub fn set_os(&self, os: Option<String>) {
        let mut local_state_guard = self.local_state.write();
        if let Some(ref mut state) = *local_state_guard {
            state.set_os(os);
        }
    }

    pub fn set_os_version(&self, os_version: Option<String>) {
        let mut local_state_guard = self.local_state.write();
        if let Some(ref mut state) = *local_state_guard {
            state.set_os_version(os_version);
        }
    }

    pub fn read_global_state(&self) -> ParkingRwLockReadGuard<'_, ClientGlobalState> {
        self.global_state.read()
    }

    pub fn read_local_state(&self) -> ParkingRwLockReadGuard<'_, Option<ClientLocalState>> {
        self.local_state.read()
    }

    pub fn write_local_state(&self) -> ParkingRwLockWriteGuard<'_, Option<ClientLocalState>> {
        self.local_state.write()
    }

    /// Acquire a transactional write guard for `ClientGlobalState`.
    ///
    /// Mutations made through the guard are batched: when the guard is dropped
    /// (or `commit()` is called explicitly), a `ClientGlobalStateDelta` is
    /// computed, a `ClientStateLogEntry` is created, and the global version
    /// is bumped by exactly 1.
    pub fn write_global_state<'a>(
        &'a self,
        repo: &'a ClientRepository,
    ) -> GlobalStateWriteGuard<'a> {
        self.write_global_state_as(repo, Some(self.get_session_id()), None)
    }

    /// Acquire a transactional write guard for `ClientGlobalState` while
    /// explicitly recording who initiated the mutation and the channel
    /// version dependency.
    ///
    /// `channel_version_dep`: `Some(v)` means this mutation depends on
    /// channel state at version `v` or later. `None` means no dependency.
    pub fn write_global_state_as<'a>(
        &'a self,
        repo: &'a ClientRepository,
        sender_session_id: Option<ClientSessionIdentifier>,
        channel_version_dep: Option<u64>,
    ) -> GlobalStateWriteGuard<'a> {
        let inner = self.global_state.write();
        GlobalStateWriteGuard::new(
            inner,
            repo,
            self.server_id(),
            self.get_session_id(),
            self.client_instance_id(),
            sender_session_id,
            channel_version_dep,
        )
    }

    /// Direct (non-transactional) write access to `ClientGlobalState`.
    /// Only for internal use (e.g. `apply_remote_operation`).
    /// Callers should prefer `write_global_state(repo)` for normal mutations.
    pub fn write_global_state_direct(&self) -> ParkingRwLockWriteGuard<'_, ClientGlobalState> {
        self.global_state.write()
    }

    /// Build a `UserState` snapshot of this client suitable for broadcasting
    /// to other clients (i.e. everything a peer needs to know about this user).
    /// Not suitable for continuous update of clients state.
    pub fn build_user_state_for_broadcast(&self) -> msg_encoder::UserState {
        let gs = self.global_state.read();

        let comment_hash_bytes = gs
            .get_comment_hash()
            .and_then(|h| hex::decode(h).ok().map(Bytes::from));
        let texture_hash_bytes = gs
            .get_texture_hash()
            .and_then(|h| hex::decode(h).ok().map(Bytes::from));

        msg_encoder::UserState {
            session: Some(self.get_session_id()),
            actor: None,
            name: gs.get_display_name_opt().map(|s| s.to_owned()),
            user_id: gs.get_user_id(),
            channel_id: Some(gs.get_current_channel_id()),
            mute: if gs.is_muted() { Some(true) } else { None },
            deaf: if gs.is_deafened() { Some(true) } else { None },
            suppress: if gs.is_suppressed() { Some(true) } else { None },
            self_mute: if gs.is_self_muted() { Some(true) } else { None },
            self_deaf: if gs.is_self_deafened() {
                Some(true)
            } else {
                None
            },
            texture: None,
            plugin_context: if gs.get_plugin_context().is_empty() {
                None
            } else {
                Some(Bytes::copy_from_slice(gs.get_plugin_context()))
            },
            plugin_identity: if gs.get_plugin_identity().is_empty() {
                None
            } else {
                Some(gs.get_plugin_identity().to_owned())
            },
            comment: None,
            hash: self.certificate_hash.as_ref().map(|h| hex::encode(h)),
            comment_hash: comment_hash_bytes,
            texture_hash: texture_hash_bytes,
            priority_speaker: if gs.is_priority_speaker() {
                Some(true)
            } else {
                None
            },
            recording: if gs.is_recording() { Some(true) } else { None },
            temporary_access_tokens: Vec::new(),
            listening_channel_add: gs.get_listening_channel_id().iter().copied().collect(),
            listening_channel_remove: Vec::new(),
            listening_volume_adjustment: Vec::new(),
        }
    }

    pub async fn user_info_extended(&self) -> ParkingMappedMutexGuard<'_, UserInfoExtended> {
        let user_info_extended = self.user_info_extended.lock();
        if user_info_extended.is_none() {
            panic!("Accessing user_info_extended of non-local user");
        }
        ParkingMutexGuard::map(user_info_extended, |opt| opt.as_mut().unwrap())
    }
}

fn transport_not_readable_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::NotConnected,
        "client transport cannot receive native protobuf messages",
    )
}

fn transport_not_writable_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::NotConnected,
        "client transport cannot send native protobuf messages",
    )
}

fn transport_closed_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "web gateway client transport is closed",
    )
}
