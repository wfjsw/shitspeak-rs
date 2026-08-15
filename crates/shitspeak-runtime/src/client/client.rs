use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    net::{IpAddr, Shutdown, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
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
use shitspeak_client_crypto::{CryptError, CryptState};
use socket2::Socket;
use tokio::{
    io::{AsyncWriteExt as _, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::{Mutex as AsyncMutex, Notify, RwLock, RwLockWriteGuard, mpsc, watch},
    time::timeout,
};
use tokio_rustls::server::TlsStream;

use crate::{
    client::{
        client_global_state::ClientGlobalState,
        client_local_state::{ClientLocalState, ExpiredAuthenticationAction},
        client_session_identifier::ClientSessionIdentifier,
        client_stats::ClientStats,
        global_state_guard::GlobalStateWriteGuard,
        next_client_instance_id,
        user_info::UserInfoExtended,
        voice_target::VoiceTarget,
    },
    client_repository::ClientRepository,
    errors::{ReadProtoMessageError, WriteProtoMessageError},
    messages::{Message, ReadMessageExt, WriteMessageExt, encoder as msg_encoder},
    protocol_version::ProtocolVersion,
    tls_fingerprint::{TlsFingerprints, ja4x_from_certificate},
    types::{DEFAULT_SERVER_ID, ScopedSessionId},
    voice::VoiceRoutingPayload,
};
use shitspeak_auth::AuthenticationExpiryAction;

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

#[derive(Clone, Copy)]
struct ClientCachedAclPermissions {
    channel_acl_generation: u64,
    client_acl_subject_generation: u64,
    client_acl_home_generation: u64,
    depends_on_home_channel: bool,
    explicit_enter_deny_overrides_write: bool,
    permissions: enumflags2::BitFlags<shitspeak_state::ACLPermissions>,
}

/// Coherent point-in-time copy of the client state used by ACL evaluation.
///
/// Keep the fields private so callers cannot couple themselves to the
/// snapshot representation. Constructing this value takes the global-state
/// read lock once, preventing an ACL evaluation from combining identity or
/// home-channel values from different state revisions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientAclStateSnapshot {
    current_channel_id: u32,
    user_id: Option<u32>,
    groups: HashSet<String>,
    tokens: HashSet<String>,
    is_superuser: bool,
    acl_subject_generation: u64,
    acl_home_generation: u64,
}

impl ClientAclStateSnapshot {
    pub(crate) fn current_channel_id(&self) -> u32 {
        self.current_channel_id
    }

    pub(crate) fn user_id(&self) -> Option<u32> {
        self.user_id
    }

    pub(crate) fn groups(&self) -> &HashSet<String> {
        &self.groups
    }

    pub(crate) fn tokens(&self) -> &HashSet<String> {
        &self.tokens
    }

    pub(crate) fn is_superuser(&self) -> bool {
        self.is_superuser
    }

    pub(crate) fn acl_cache_generations(&self) -> (u64, u64) {
        (self.acl_subject_generation, self.acl_home_generation)
    }
}

#[derive(Default)]
struct CertificateHashProjectionCache {
    visibility_generation: Option<u64>,
    protected_hash_hex: Option<String>,
}

impl ClientCachedAclPermissions {
    fn hit_for(
        self,
        channel_acl_generation: u64,
        client_acl_subject_generation: u64,
        client_acl_home_generation: u64,
        explicit_enter_deny_overrides_write: bool,
    ) -> Option<(enumflags2::BitFlags<shitspeak_state::ACLPermissions>, bool)> {
        (self.channel_acl_generation == channel_acl_generation
            && self.client_acl_subject_generation == client_acl_subject_generation
            && (!self.depends_on_home_channel
                || self.client_acl_home_generation == client_acl_home_generation)
            && self.explicit_enter_deny_overrides_write == explicit_enter_deny_overrides_write)
            .then_some((self.permissions, self.depends_on_home_channel))
    }
}

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

#[derive(Clone, Copy)]
pub(crate) enum VoiceTcpEnqueueResult {
    Accepted,
    Full,
    Closed,
}

pub type ClientStateSubscription = tokio::sync::broadcast::Receiver<
    std::sync::Arc<crate::client::state_log::ClientStateBroadcastPayload>,
>;

pub(crate) struct DeferredSessionBlobResolution {
    user_id: Option<u32>,
    texture_url: Option<String>,
    comment_url: Option<String>,
    texture_revision: u64,
    comment_revision: u64,
}

impl DeferredSessionBlobResolution {
    pub(crate) fn new(
        user_id: Option<u32>,
        texture_url: Option<String>,
        comment_url: Option<String>,
        texture_revision: u64,
        comment_revision: u64,
    ) -> Self {
        Self {
            user_id,
            texture_url,
            comment_url,
            texture_revision,
            comment_revision,
        }
    }

    pub(crate) fn into_parts(self) -> (Option<u32>, Option<String>, Option<String>, u64, u64) {
        (
            self.user_id,
            self.texture_url,
            self.comment_url,
            self.texture_revision,
            self.comment_revision,
        )
    }
}
pub type StagedChannelStateSubscription = (u64, shitspeak_state::ChannelStateSubscription);

#[derive(Default)]
struct ClientProjectionCursorState {
    versions: HashMap<u16, u64>,
    epochs: HashMap<u16, u64>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PostAuthBaseline {
    session_channel_shadow: crate::channel_handler::SessionChannelShadow,
    channel_tree_shadow: crate::channel_handler::ChannelTreeShadow,
    user_visibility: crate::client::visibility::UserVisibilityState,
    visibility_generation: Option<u64>,
}

impl PostAuthBaseline {
    #[cfg(test)]
    pub(crate) fn new(
        session_channel_shadow: crate::channel_handler::SessionChannelShadow,
        channel_tree_shadow: crate::channel_handler::ChannelTreeShadow,
    ) -> Self {
        Self {
            session_channel_shadow,
            channel_tree_shadow,
            user_visibility: crate::client::visibility::UserVisibilityState::default(),
            visibility_generation: None,
        }
    }

    pub(crate) fn with_user_visibility(
        session_channel_shadow: crate::channel_handler::SessionChannelShadow,
        channel_tree_shadow: crate::channel_handler::ChannelTreeShadow,
        user_visibility: crate::client::visibility::UserVisibilityState,
        visibility_generation: u64,
    ) -> Self {
        Self {
            session_channel_shadow,
            channel_tree_shadow,
            user_visibility,
            visibility_generation: Some(visibility_generation),
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        crate::channel_handler::SessionChannelShadow,
        crate::channel_handler::ChannelTreeShadow,
        crate::client::visibility::UserVisibilityState,
        Option<u64>,
    ) {
        (
            self.session_channel_shadow,
            self.channel_tree_shadow,
            self.user_visibility,
            self.visibility_generation,
        )
    }
}

/// An owned group of protocol messages ready to be handed to a connection's
/// writer queue without cloning the individual messages.
#[derive(Debug)]
pub struct OwnedMessageBatch {
    messages: Vec<Message>,
}

impl OwnedMessageBatch {
    pub fn new(messages: Vec<Message>) -> Self {
        Self { messages }
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn into_messages(self) -> Vec<Message> {
        self.messages
    }
}

impl From<Vec<Message>> for OwnedMessageBatch {
    fn from(messages: Vec<Message>) -> Self {
        Self::new(messages)
    }
}

fn try_send_owned_message_batch(
    sender: Option<&mpsc::Sender<ClientOutboundMessage>>,
    batch: OwnedMessageBatch,
) -> Result<(), mpsc::error::TrySendError<ClientOutboundMessage>> {
    if batch.is_empty() {
        return Ok(());
    }

    let outbound = ClientOutboundMessage::Batch(batch.into_messages());
    let Some(sender) = sender else {
        return Err(mpsc::error::TrySendError::Closed(outbound));
    };
    sender.try_send(outbound)
}

fn try_send_owned_gateway_batch(
    sender: &mpsc::Sender<Message>,
    batch: OwnedMessageBatch,
) -> Result<(), mpsc::error::TrySendError<ClientOutboundMessage>> {
    if batch.is_empty() {
        return Ok(());
    }

    let messages = batch.into_messages();
    if messages.len() > sender.max_capacity() {
        return Err(mpsc::error::TrySendError::Full(
            ClientOutboundMessage::Batch(messages),
        ));
    }
    match sender.try_reserve_many(messages.len()) {
        Ok(permits) => {
            for (permit, message) in permits.zip(messages) {
                permit.send(message);
            }
            Ok(())
        }
        Err(mpsc::error::TrySendError::Full(())) => Err(mpsc::error::TrySendError::Full(
            ClientOutboundMessage::Batch(messages),
        )),
        Err(mpsc::error::TrySendError::Closed(())) => Err(mpsc::error::TrySendError::Closed(
            ClientOutboundMessage::Batch(messages),
        )),
    }
}

#[derive(Debug)]
pub enum ClientOutboundMessage {
    Single(Message),
    Batch(Vec<Message>),
}

/// Per-client RequestBlob work that is deliberately serialized by one
/// consumer. `VecDeque::new` keeps idle clients allocation-free; once the
/// consumer catches up, its backing storage is released again.
struct RequestBlobQueue {
    pending: VecDeque<msg_encoder::RequestBlob>,
    limit: usize,
    changed: Arc<Notify>,
}

impl RequestBlobQueue {
    fn new(limit: usize) -> Self {
        Self {
            pending: VecDeque::new(),
            limit,
            changed: Arc::new(Notify::new()),
        }
    }

    fn pop_front(&mut self) -> Option<msg_encoder::RequestBlob> {
        let request = self.pending.pop_front();
        let len = self.pending.len();
        if len == 0 {
            self.pending.shrink_to(0);
        } else if self.pending.capacity() > len.saturating_mul(4) {
            self.pending.shrink_to(len.saturating_mul(2));
        }
        request
    }

    fn clear(&mut self) {
        self.pending.clear();
        self.pending.shrink_to(0);
    }
}

#[derive(Debug)]
pub(crate) enum RequestBlobQueueEnqueueError {
    Full(msg_encoder::RequestBlob),
    Unavailable,
}

fn client_tracing_span(
    server_tracing_span: &tracing::Span,
    session_id: ClientSessionIdentifier,
    client_instance_id: ClientInstanceId,
    certificate_hash: Option<&str>,
    tls_fingerprints: &TlsFingerprints,
    real_ip_address: IpAddr,
    tcp_address: SocketAddr,
    local_address: SocketAddr,
) -> tracing::Span {
    let span = tracing::info_span!(parent: server_tracing_span,
        "client",
        client_cert_hash = tracing::field::Empty,
        client_tls_ja3 = tracing::field::Empty,
        client_tls_ja4 = tracing::field::Empty,
        client_tls_ja4t = tracing::field::Empty,
        client_tls_ja4x = tracing::field::Empty,
        client_tls_ja4l = tracing::field::Empty,
        client_connection_sni = tracing::field::Empty,
        client_real_ip = %real_ip_address,
        client_connection_remote_ip = %tcp_address.ip(),
        client_connection_remote_port = tcp_address.port(),
        client_connection_local_port = local_address.port(),
        client_node = session_id.get_node_id(),
        client_local_session_id = session_id.get_local_session_id(),
        client_instance_id,
        client_auth_session_id = tracing::field::Empty,
        client_user_id = tracing::field::Empty,
        client_user_name = tracing::field::Empty,
        client_fqdn = tracing::field::Empty,
    );
    if let Some(certificate_hash) = certificate_hash {
        span.record("client_cert_hash", certificate_hash);
    }
    if let Some(tls_ja3) = tls_fingerprints.ja3.as_deref() {
        span.record("client_tls_ja3", tls_ja3);
    }
    if let Some(tls_ja4) = tls_fingerprints.ja4.as_deref() {
        span.record("client_tls_ja4", tls_ja4);
    }
    if let Some(tls_ja4t) = tls_fingerprints.ja4t.as_deref() {
        span.record("client_tls_ja4t", tls_ja4t);
    }
    if let Some(tls_ja4x) = tls_fingerprints.ja4x.as_deref() {
        span.record("client_tls_ja4x", tls_ja4x);
    }
    if let Some(tls_ja4l) = tls_fingerprints.ja4l.as_deref() {
        span.record("client_tls_ja4l", tls_ja4l);
    }
    if let Some(tls_sni) = tls_fingerprints.sni.as_deref() {
        span.record("client_connection_sni", tls_sni);
    }
    span
}

fn server_tracing_span(server_id: &str) -> tracing::Span {
    tracing::info_span!("server", virtual_server_id = %server_id)
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
    tls_fingerprints: TlsFingerprints,
    proxy_server_address: Option<SocketAddr>,
    uses_proxy_protocol: bool,
    server_tracing_span: tracing::Span,
    tracing_span: tracing::Span,

    transport: ClientTransport,
    disconnect_tx: watch::Sender<bool>,
    disconnect_rx: watch::Receiver<bool>,
    removed_tx: watch::Sender<bool>,
    removed_rx: watch::Receiver<bool>,
    is_verified: bool,

    // Statistics
    login_time: DateTime<Utc>,
    last_active: ParkingMutex<DateTime<Utc>>,
    last_ping: ParkingMutex<DateTime<Utc>>,
    stats: RwLock<ClientStats>,

    certificate_hash: Option<Bytes>,
    certificate_hash_hex: Option<String>,
    certificate_hash_projection_cache: ParkingMutex<CertificateHashProjectionCache>,
    certificate_chain: Vec<CertificateDer<'static>>,
    user_info_extended: ParkingMutex<Option<UserInfoExtended>>,

    // Pins for session blobs (texture/comment) referenced by this client's
    // state. Holding a pin prevents the blob from being evicted; the pins
    // auto-release when this Client is dropped (disconnect/removal).
    texture_blob_pin: ParkingMutex<Option<crate::blob_store::BlobPin>>,
    comment_blob_pin: ParkingMutex<Option<crate::blob_store::BlobPin>>,

    local_state: ParkingRwLock<Option<ClientLocalState>>,
    global_state: ParkingRwLock<ClientGlobalState>,
    /// Effective permissions owned by this client instance. The map grows to
    /// the channels this connection actually touches and is dropped with the
    /// client, so reconnect churn cannot leave stale global cache entries.
    acl_permission_cache: scc::HashMap<u32, ClientCachedAclPermissions>,
    crypt_state: ParkingMutex<Option<CryptState>>,
    voice_targets: ParkingMutex<HashMap<u32, VoiceTarget>>,
    voice_routing_tx: Option<mpsc::Sender<VoiceRoutingPayload>>,
    voice_routing_rx: ParkingMutex<Option<mpsc::Receiver<VoiceRoutingPayload>>>,
    /// Per-user outgoing TCP voice tunnel queue. The routing task pushes raw
    /// `UDPTunnel` payload bytes here without awaiting normal control fanout.
    /// Native clients drain this as a separate priority input in the writer
    /// task; gateway clients use the fallback bridge in `voice::routing`.
    voice_tcp_tx: Option<mpsc::Sender<Bytes>>,
    voice_tcp_rx: ParkingMutex<Option<mpsc::Receiver<Bytes>>>,
    /// Post-authentication RequestBlob work is serialized by a single
    /// per-client consumer. The queue is installed once its bound can be
    /// sized from the authenticated server's user and channel limits.
    request_blob_queue: ParkingMutex<Option<RequestBlobQueue>>,
    outbound_message_tx: Option<mpsc::Sender<ClientOutboundMessage>>,
    outbound_message_rx: ParkingMutex<Option<mpsc::Receiver<ClientOutboundMessage>>>,

    /// Whether this client has been published to the log (i.e. `AddClient`
    /// has been emitted).  Only published clients generate `RemoveClient`
    /// log entries on disconnect.
    published: AtomicBool,
    pending_client_state_subscription: ParkingMutex<Option<ClientStateSubscription>>,
    pending_channel_state_subscription: ParkingMutex<Option<StagedChannelStateSubscription>>,
    pending_post_auth_baseline: ParkingMutex<Option<PostAuthBaseline>>,
    pending_session_blob_resolution: ParkingMutex<Option<DeferredSessionBlobResolution>>,

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
    client_state_cursors: ParkingMutex<ClientProjectionCursorState>,
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
        let server_tracing_span = server_tracing_span(&server_id);
        Self::new_local_in_server_with_instance_id(
            server_id,
            session_id,
            real_ip_address,
            tcp_address,
            udp_address,
            local_address,
            connection,
            TlsFingerprints {
                ja4: tls_ja4,
                ..TlsFingerprints::default()
            },
            None,
            uses_proxy_protocol,
            server_tracing_span,
            next_client_instance_id(session_id.get_node_id()),
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
        mut tls_fingerprints: TlsFingerprints,
        proxy_server_address: Option<SocketAddr>,
        uses_proxy_protocol: bool,
        server_tracing_span: tracing::Span,
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
        let connection_sni = connection.get_ref().1.server_name().map(ToOwned::to_owned);
        tls_fingerprints.sni = connection_sni.clone().or(tls_fingerprints.sni);
        tls_fingerprints.ja4x = certificate_chain
            .first()
            .and_then(|certificate| ja4x_from_certificate(certificate.as_ref()));

        let now = Utc::now();
        let certificate_hash_hex = certificate_hash.as_deref().map(hex::encode);

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
        let (removed_tx, removed_rx) = watch::channel(false);
        let tracing_span = client_tracing_span(
            &server_tracing_span,
            session_id,
            client_instance_id,
            certificate_hash_hex.as_deref(),
            &tls_fingerprints,
            real_ip_address,
            tcp_address,
            local_address,
        );

        Box::new(Client {
            session_id: ParkingRwLock::new(session_id),
            client_instance_id,
            server_id: ParkingRwLock::new(server_id.clone()),
            real_ip_address,
            tcp_address,
            udp_address: ParkingRwLock::new(udp_address),
            local_address,
            tls_fingerprints,
            proxy_server_address,
            uses_proxy_protocol,
            server_tracing_span,
            tracing_span,
            transport: ClientTransport::NativeTls {
                rx: AsyncMutex::new(connection_rx),
                tx: AsyncMutex::new(connection_tx),
                socket,
            },
            disconnect_tx,
            disconnect_rx,
            removed_tx,
            removed_rx,
            is_verified,
            login_time: now,
            last_active: ParkingMutex::new(now),
            last_ping: ParkingMutex::new(now),
            stats: RwLock::new(ClientStats::default()),
            certificate_hash,
            certificate_hash_hex,
            certificate_hash_projection_cache: ParkingMutex::new(
                CertificateHashProjectionCache::default(),
            ),
            certificate_chain,
            user_info_extended: ParkingMutex::new(Some(UserInfoExtended::default())),
            texture_blob_pin: ParkingMutex::new(None),
            comment_blob_pin: ParkingMutex::new(None),
            local_state: ParkingRwLock::new(Some(ClientLocalState::new())),
            global_state: ParkingRwLock::new(ClientGlobalState::new()),
            acl_permission_cache: scc::HashMap::new(),
            crypt_state: ParkingMutex::new(None),
            voice_targets: ParkingMutex::new(HashMap::new()),
            voice_routing_tx: Some(voice_routing_tx),
            voice_routing_rx: ParkingMutex::new(Some(voice_routing_rx)),
            voice_tcp_tx: Some(voice_tcp_tx),
            voice_tcp_rx: ParkingMutex::new(Some(voice_tcp_rx)),
            request_blob_queue: ParkingMutex::new(None),
            outbound_message_tx: Some(outbound_message_tx),
            outbound_message_rx: ParkingMutex::new(Some(outbound_message_rx)),
            published: AtomicBool::new(false),
            pending_client_state_subscription: ParkingMutex::new(None),
            pending_channel_state_subscription: ParkingMutex::new(None),
            pending_post_auth_baseline: ParkingMutex::new(None),
            pending_session_blob_resolution: ParkingMutex::new(None),
            prefer_tcp_tunnel: AtomicBool::new(false),
            can_receive_voice: AtomicBool::new(true),
            protocol_version: AtomicU64::new(0),
            client_state_cursors: ParkingMutex::new(ClientProjectionCursorState::default()),
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
            next_client_instance_id(session_id.get_node_id()),
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
            next_client_instance_id(session_id.get_node_id()),
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
            next_client_instance_id(session_id.get_node_id()),
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
        let (removed_tx, removed_rx) = watch::channel(false);
        let server_tracing_span = server_tracing_span(&server_id);
        let tracing_span = client_tracing_span(
            &server_tracing_span,
            session_id,
            client_instance_id,
            None,
            &TlsFingerprints::default(),
            real_ip_address,
            tcp_address,
            local_address,
        );

        Box::new(Client {
            session_id: ParkingRwLock::new(session_id),
            client_instance_id,
            server_id: ParkingRwLock::new(server_id.clone()),
            real_ip_address,
            tcp_address,
            udp_address: ParkingRwLock::new(None),
            local_address,
            tls_fingerprints: TlsFingerprints::default(),
            proxy_server_address: None,
            uses_proxy_protocol: false,
            server_tracing_span,
            tracing_span,
            transport: ClientTransport::WebGateway { kind, outbound_tx },
            disconnect_tx,
            disconnect_rx,
            removed_tx,
            removed_rx,
            is_verified: false,
            login_time: now,
            last_active: ParkingMutex::new(now),
            last_ping: ParkingMutex::new(now),
            stats: RwLock::new(ClientStats::default()),
            certificate_hash: None,
            certificate_hash_hex: None,
            certificate_hash_projection_cache: ParkingMutex::new(
                CertificateHashProjectionCache::default(),
            ),
            certificate_chain: Vec::new(),
            user_info_extended: ParkingMutex::new(Some(UserInfoExtended::default())),
            texture_blob_pin: ParkingMutex::new(None),
            comment_blob_pin: ParkingMutex::new(None),
            local_state: ParkingRwLock::new(Some(ClientLocalState::new())),
            global_state: ParkingRwLock::new(ClientGlobalState::new()),
            acl_permission_cache: scc::HashMap::new(),
            crypt_state: ParkingMutex::new(None),
            voice_targets: ParkingMutex::new(HashMap::new()),
            voice_routing_tx: Some(voice_routing_tx),
            voice_routing_rx: ParkingMutex::new(Some(voice_routing_rx)),
            voice_tcp_tx: Some(voice_tcp_tx),
            voice_tcp_rx: ParkingMutex::new(Some(voice_tcp_rx)),
            request_blob_queue: ParkingMutex::new(None),
            outbound_message_tx: Some(outbound_message_tx),
            outbound_message_rx: ParkingMutex::new(Some(outbound_message_rx)),
            published: AtomicBool::new(false),
            pending_client_state_subscription: ParkingMutex::new(None),
            pending_channel_state_subscription: ParkingMutex::new(None),
            pending_post_auth_baseline: ParkingMutex::new(None),
            pending_session_blob_resolution: ParkingMutex::new(None),
            prefer_tcp_tunnel: AtomicBool::new(false),
            can_receive_voice: AtomicBool::new(true),
            protocol_version: AtomicU64::new(0),
            client_state_cursors: ParkingMutex::new(ClientProjectionCursorState::default()),
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
            next_client_instance_id(session_id.get_node_id()),
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
        let certificate_hash_hex = cert_hash.as_deref().map(hex::encode);
        let (disconnect_tx, disconnect_rx) = watch::channel(false);
        let (removed_tx, removed_rx) = watch::channel(false);
        let server_tracing_span = server_tracing_span(&server_id);
        let tracing_span = client_tracing_span(
            &server_tracing_span,
            session_id,
            client_instance_id,
            certificate_hash_hex.as_deref(),
            &TlsFingerprints::default(),
            real_ip_address,
            tcp_address,
            local_address,
        );

        Box::new(Client {
            session_id: ParkingRwLock::new(session_id),
            client_instance_id,
            server_id: ParkingRwLock::new(server_id.clone()),
            real_ip_address,
            tcp_address,
            udp_address: ParkingRwLock::new(udp_address),
            local_address,
            tls_fingerprints: TlsFingerprints::default(),
            proxy_server_address: None,
            uses_proxy_protocol: false,
            server_tracing_span,
            tracing_span,
            transport: ClientTransport::Remote,
            disconnect_tx,
            disconnect_rx,
            removed_tx,
            removed_rx,
            is_verified,
            login_time,
            last_active: ParkingMutex::new(login_time),
            last_ping: ParkingMutex::new(login_time),
            stats: RwLock::new(ClientStats::default()),
            certificate_hash: cert_hash,
            certificate_hash_hex,
            certificate_hash_projection_cache: ParkingMutex::new(
                CertificateHashProjectionCache::default(),
            ),
            certificate_chain: Vec::new(),
            user_info_extended: ParkingMutex::new(Some(UserInfoExtended::default())),
            texture_blob_pin: ParkingMutex::new(None),
            comment_blob_pin: ParkingMutex::new(None),
            local_state: ParkingRwLock::new(None),
            global_state: ParkingRwLock::new(ClientGlobalState::new()),
            acl_permission_cache: scc::HashMap::new(),
            crypt_state: ParkingMutex::new(None),
            voice_targets: ParkingMutex::new(HashMap::new()),
            voice_routing_tx: None,
            voice_routing_rx: ParkingMutex::new(None),
            voice_tcp_tx: None,
            voice_tcp_rx: ParkingMutex::new(None),
            request_blob_queue: ParkingMutex::new(None),
            outbound_message_tx: None,
            outbound_message_rx: ParkingMutex::new(None),
            published: AtomicBool::new(true),
            pending_client_state_subscription: ParkingMutex::new(None),
            pending_channel_state_subscription: ParkingMutex::new(None),
            pending_post_auth_baseline: ParkingMutex::new(None),
            pending_session_blob_resolution: ParkingMutex::new(None),
            prefer_tcp_tunnel: AtomicBool::new(false),
            can_receive_voice: AtomicBool::new(true),
            protocol_version: AtomicU64::new(0),
            client_state_cursors: ParkingMutex::new(ClientProjectionCursorState::default()),
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
        rx: shitspeak_state::ChannelStateSubscription,
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

    pub fn stage_session_blob_resolution(
        &self,
        user_id: Option<u32>,
        texture_url: Option<String>,
        comment_url: Option<String>,
    ) {
        let state = self.global_state.read();
        let resolution = DeferredSessionBlobResolution::new(
            user_id,
            texture_url,
            comment_url,
            state.texture_blob_revision(),
            state.comment_blob_revision(),
        );
        *self.pending_session_blob_resolution.lock() = Some(resolution);
    }

    pub(crate) fn take_session_blob_resolution(&self) -> Option<DeferredSessionBlobResolution> {
        self.pending_session_blob_resolution.lock().take()
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
        self.client_state_cursors.lock().versions.clone()
    }

    /// Merge the given per-node version map into the client's last-seen
    /// trackers.  Each entry is updated to `max(existing, new)`, except
    /// version `0`, which marks a remote-origin reset and clears that node.
    pub async fn update_last_client_versions(&self, versions: &HashMap<u16, u64>) {
        let mut cursors = self.client_state_cursors.lock();
        for (&node_id, &version) in versions {
            if version == 0 {
                cursors.versions.remove(&node_id);
                cursors.epochs.remove(&node_id);
                continue;
            }
            let entry = cursors.versions.entry(node_id).or_insert(0);
            *entry = (*entry).max(version);
        }
    }

    pub async fn remove_last_client_version(&self, node_id: u16) {
        let mut cursors = self.client_state_cursors.lock();
        cursors.versions.remove(&node_id);
        cursors.epochs.remove(&node_id);
    }

    pub async fn get_last_client_epochs(&self) -> HashMap<u16, u64> {
        self.client_state_cursors.lock().epochs.clone()
    }

    pub async fn get_last_client_cursors(&self) -> (HashMap<u16, u64>, HashMap<u16, u64>) {
        let cursors = self.client_state_cursors.lock();
        (cursors.versions.clone(), cursors.epochs.clone())
    }

    /// Replace the complete materialized client-state cursor cut.
    pub async fn set_last_client_cursors(
        &self,
        versions: HashMap<u16, u64>,
        epochs: HashMap<u16, u64>,
    ) {
        let mut cursors = self.client_state_cursors.lock();
        cursors.versions = versions
            .into_iter()
            .filter(|(_, version)| *version != 0)
            .collect();
        cursors.epochs = epochs;
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

    pub(crate) fn acl_state_snapshot(&self) -> ClientAclStateSnapshot {
        let state = self.global_state.read();
        let (acl_subject_generation, acl_home_generation) = state.get_acl_cache_generations();
        ClientAclStateSnapshot {
            current_channel_id: state.get_current_channel_id(),
            user_id: state.get_user_id(),
            groups: state.get_groups().clone(),
            tokens: state.get_tokens().clone(),
            is_superuser: state.is_superuser(),
            acl_subject_generation,
            acl_home_generation,
        }
    }

    pub(crate) fn acl_cache_metadata(&self) -> (bool, (u64, u64)) {
        let state = self.global_state.read();
        (state.is_superuser(), state.get_acl_cache_generations())
    }

    pub fn has_group(&self, group: &str) -> bool {
        self.global_state.read().has_group(group)
    }

    pub fn get_certificate_hash(&self) -> Option<&[u8]> {
        self.certificate_hash.as_deref()
    }

    pub(crate) fn protected_certificate_hash_hex(
        &self,
        visibility_generation: u64,
        protection: shitspeak_runtime_config::CertificateHashProtection,
        secret: &str,
    ) -> Option<String> {
        let source = self.certificate_hash_hex.as_deref()?;
        let mut cache = self.certificate_hash_projection_cache.lock();
        if cache.visibility_generation != Some(visibility_generation) {
            cache.protected_hash_hex =
                crate::privacy::protected_certificate_hash_hex(protection, secret, source);
            cache.visibility_generation = Some(visibility_generation);
        }
        cache.protected_hash_hex.clone()
    }

    pub(crate) fn cached_protected_certificate_hash_hex(
        &self,
        visibility_generation: u64,
    ) -> Option<Option<String>> {
        let cache = self.certificate_hash_projection_cache.lock();
        (cache.visibility_generation == Some(visibility_generation))
            .then(|| cache.protected_hash_hex.clone())
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

    pub(crate) fn with_server_id<R>(&self, read: impl FnOnce(&str) -> R) -> R {
        let server_id = self.server_id.read();
        read(&server_id)
    }

    pub fn set_server_id(&self, server_id: String) {
        self.server_tracing_span
            .record("virtual_server_id", server_id.as_str());
        *self.server_id.write() = server_id;
        self.acl_permission_cache.clear_sync();
    }

    pub fn set_scoped_identity(&self, server_id: String, session_id: ClientSessionIdentifier) {
        self.server_tracing_span
            .record("virtual_server_id", server_id.as_str());
        *self.server_id.write() = server_id;
        *self.session_id.write() = session_id;
        self.acl_permission_cache.clear_sync();
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

    pub fn get_fqdn(&self) -> Option<String> {
        self.global_state.read().get_fqdn().map(ToOwned::to_owned)
    }

    pub fn get_auth_session_id(&self) -> Option<String> {
        self.local_state
            .read()
            .as_ref()
            .and_then(|state| state.auth_session_id())
            .map(ToOwned::to_owned)
    }

    pub fn get_acl_generation(&self) -> u64 {
        self.global_state.read().get_acl_generation()
    }

    pub fn get_acl_cache_generations(&self) -> (u64, u64) {
        self.global_state.read().get_acl_cache_generations()
    }

    pub(crate) fn get_cached_acl_permissions(
        &self,
        channel_id: u32,
        channel_acl_generation: u64,
        client_acl_subject_generation: u64,
        client_acl_home_generation: u64,
        explicit_enter_deny_overrides_write: bool,
    ) -> Option<(enumflags2::BitFlags<shitspeak_state::ACLPermissions>, bool)> {
        self.acl_permission_cache
            .read_sync(&channel_id, |_, entry| {
                entry.hit_for(
                    channel_acl_generation,
                    client_acl_subject_generation,
                    client_acl_home_generation,
                    explicit_enter_deny_overrides_write,
                )
            })
            .flatten()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn cache_acl_permissions(
        &self,
        channel_id: u32,
        channel_acl_generation: u64,
        client_acl_subject_generation: u64,
        client_acl_home_generation: u64,
        depends_on_home_channel: bool,
        explicit_enter_deny_overrides_write: bool,
        permissions: enumflags2::BitFlags<shitspeak_state::ACLPermissions>,
    ) {
        let entry = ClientCachedAclPermissions {
            channel_acl_generation,
            client_acl_subject_generation,
            client_acl_home_generation,
            depends_on_home_channel,
            explicit_enter_deny_overrides_write,
            permissions,
        };
        self.acl_permission_cache.upsert_sync(channel_id, entry);
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
        self.tls_fingerprints.ja4.as_deref()
    }

    pub fn tls_ja3(&self) -> Option<&str> {
        self.tls_fingerprints.ja3.as_deref()
    }

    pub fn tls_ja4t(&self) -> Option<&str> {
        self.tls_fingerprints.ja4t.as_deref()
    }

    pub fn tls_ja4x(&self) -> Option<&str> {
        self.tls_fingerprints.ja4x.as_deref()
    }

    pub fn tls_ja4l(&self) -> Option<&str> {
        self.tls_fingerprints.ja4l.as_deref()
    }

    pub fn tls_sni(&self) -> Option<&str> {
        self.tls_fingerprints.sni.as_deref()
    }

    pub fn proxy_server_address(&self) -> Option<SocketAddr> {
        self.proxy_server_address
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
        match self.real_ip_address {
            IpAddr::V4(address) => IpAddr::V4(address),
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(address)),
        }
    }

    pub(crate) fn tracing_span(&self) -> tracing::Span {
        self.tracing_span.clone()
    }

    pub(crate) fn server_tracing_span(&self) -> tracing::Span {
        self.server_tracing_span.clone()
    }

    pub async fn in_tracing_span<F, T>(&self, future: F) -> T
    where
        F: Future<Output = T>,
    {
        use tracing::Instrument as _;

        future
            .instrument(self.tracing_span())
            .instrument(self.server_tracing_span())
            .await
    }

    pub fn in_tracing_scope<T>(&self, f: impl FnOnce() -> T) -> T {
        self.server_tracing_span()
            .in_scope(|| self.tracing_span.in_scope(f))
    }

    fn record_tracing_span_session(&self) {
        let session_id = self.get_session_id();
        self.tracing_span
            .record("client_node", session_id.get_node_id());
        self.tracing_span
            .record("client_local_session_id", session_id.get_local_session_id());
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

    /// Request immediate connection teardown from synchronous code.
    ///
    /// Projection shards use this when their non-blocking writer delivery
    /// fails. The watch notification wakes the connection task, while closing
    /// the native socket also interrupts any in-flight TLS I/O.
    pub(crate) fn request_disconnect(&self) {
        let _ = self.disconnect_tx.send(true);
        if let ClientTransport::NativeTls { socket, .. } = &self.transport {
            Self::shutdown_socket(socket);
        }
    }

    pub async fn force_disconnect(&self) -> Result<(), WriteProtoMessageError> {
        self.request_disconnect();
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

    pub(crate) fn mark_removed(&self) {
        let _ = self.removed_tx.send(true);
    }

    pub(crate) fn is_removed(&self) -> bool {
        *self.removed_rx.borrow()
    }

    pub(crate) async fn removed(&self) {
        let mut rx = self.removed_rx.clone();
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
                    .as_ref()
                    .ok_or_else(transport_closed_error)?
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
                    .as_ref()
                    .ok_or_else(transport_closed_error)?
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

    /// Try to hand an owned message batch to the native connection writer.
    ///
    /// This is non-blocking and preserves ownership all the way into the
    /// bounded writer queue. A full or closed queue returns the original
    /// outbound value through [`mpsc::error::TrySendError`]. Non-native
    /// Web gateway transports reserve space for the entire batch before
    /// handing off any message, so a full queue cannot receive a partial
    /// batch. Remote transports are reported as closed.
    pub fn try_write_owned_message_batch(
        &self,
        batch: OwnedMessageBatch,
    ) -> Result<(), mpsc::error::TrySendError<ClientOutboundMessage>> {
        match &self.transport {
            ClientTransport::NativeTls { .. } => {
                try_send_owned_message_batch(self.outbound_message_tx.as_ref(), batch)
            }
            ClientTransport::WebGateway { outbound_tx, .. } => {
                try_send_owned_gateway_batch(outbound_tx, batch)
            }
            ClientTransport::Remote => try_send_owned_message_batch(None, batch),
        }
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
                    .as_ref()
                    .ok_or_else(transport_closed_error)?
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
                    .as_ref()
                    .ok_or_else(transport_closed_error)?
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

    /// Hand an owned message batch to the connection writer without cloning
    /// the individual protocol messages.
    pub async fn write_owned_message_batch(
        &self,
        batch: OwnedMessageBatch,
    ) -> Result<(), WriteProtoMessageError> {
        self.in_tracing_span(self.write_owned_message_batch_inner(batch))
            .await
    }

    async fn write_owned_message_batch_inner(
        &self,
        batch: OwnedMessageBatch,
    ) -> Result<(), WriteProtoMessageError> {
        if batch.is_empty() {
            return Ok(());
        }

        let messages = batch.into_messages();
        match &self.transport {
            ClientTransport::NativeTls { .. } => {
                self.outbound_message_tx
                    .as_ref()
                    .ok_or_else(transport_closed_error)?
                    .send(ClientOutboundMessage::Batch(messages))
                    .await
                    .map_err(|_| transport_closed_error())?;
            }
            ClientTransport::WebGateway { outbound_tx, .. } => {
                let message_count = messages.len();
                let bytes = messages
                    .iter()
                    .map(|message| 6 + message.encoded_len())
                    .sum();
                for message in messages {
                    outbound_tx
                        .send(message)
                        .await
                        .map_err(|_| transport_closed_error())?;
                }
                self.record_tcp_packets(message_count, bytes).await;
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

    pub fn create_crypt_state(&self, mode: &str) -> Result<(), CryptError> {
        let mut state = self.crypt_state.lock();
        let rng = aws_lc_rs::rand::SystemRandom::new();
        *state = Some(CryptState::generate(mode, &rng)?);
        Ok(())
    }

    pub fn set_voice_target(&self, id: u32, target: VoiceTarget) {
        self.voice_targets.lock().insert(id, target);
    }

    pub(crate) fn remove_voice_target(&self, id: u32) {
        self.voice_targets.lock().remove(&id);
    }

    pub fn voice_target(&self, id: u32) -> Option<VoiceTarget> {
        self.voice_targets.lock().get(&id).cloned()
    }

    pub fn push_voice_routing(&self, decoded_audio: crate::voice::codec::Audio) -> bool {
        let payload = VoiceRoutingPayload::new(decoded_audio);
        let Some(voice_routing_tx) = self.voice_routing_tx.as_ref() else {
            crate::voice::metrics::record_queue_enqueue(
                crate::voice::metrics::VoiceQueueKind::Routing,
                crate::voice::metrics::VoiceQueueEnqueueResult::Closed,
            );
            crate::voice::metrics::record_queue_drop(
                crate::voice::metrics::VoiceQueueDropReason::RoutingQueueFullOrClosed,
            );
            tracing::trace!(
                session = u32::from(self.get_session_id()),
                "voice routing queue unavailable, dropping packet"
            );
            return false;
        };
        let capacity = voice_routing_tx.max_capacity();
        let depth = capacity.saturating_sub(voice_routing_tx.capacity());
        crate::voice::metrics::record_queue_status(
            crate::voice::metrics::VoiceQueueKind::Routing,
            depth,
            capacity,
        );
        match voice_routing_tx.try_send(payload) {
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

    /// Install the lazy RequestBlob queue after authentication. A second
    /// installation means the lifecycle attempted to start a duplicate
    /// consumer.
    pub(crate) fn install_request_blob_queue(&self, limit: usize) -> bool {
        let mut queue_slot = self.request_blob_queue.lock();
        if queue_slot.is_some() {
            return false;
        }
        *queue_slot = Some(RequestBlobQueue::new(limit));
        true
    }

    /// Queue a RequestBlob job without waiting. The logical limit bounds
    /// retained work while the deque itself allocates only when a burst
    /// arrives.
    pub(crate) fn enqueue_request_blob(
        &self,
        request: msg_encoder::RequestBlob,
    ) -> Result<(), RequestBlobQueueEnqueueError> {
        let changed = {
            let mut queue_slot = self.request_blob_queue.lock();
            let Some(queue) = queue_slot.as_mut() else {
                return Err(RequestBlobQueueEnqueueError::Unavailable);
            };
            if queue.pending.len() >= queue.limit {
                return Err(RequestBlobQueueEnqueueError::Full(request));
            }
            queue.pending.push_back(request);
            Arc::clone(&queue.changed)
        };
        changed.notify_one();
        Ok(())
    }

    /// The worker creates a notification future before inspecting the queue,
    /// so an enqueue in the check-to-wait gap leaves a stored permit.
    pub(crate) fn request_blob_queue_notifier(&self) -> Option<Arc<Notify>> {
        self.request_blob_queue
            .lock()
            .as_ref()
            .map(|queue| Arc::clone(&queue.changed))
    }

    /// Pop one RequestBlob job. Draining the queue releases any burst-sized
    /// allocation rather than retaining it for the life of the connection.
    pub(crate) fn dequeue_request_blob(&self) -> Option<msg_encoder::RequestBlob> {
        self.request_blob_queue.lock().as_mut()?.pop_front()
    }

    pub(crate) fn clear_request_blob_queue(&self) {
        if let Some(queue) = self.request_blob_queue.lock().as_mut() {
            queue.clear();
        }
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
        matches!(
            self.try_enqueue_voice_tcp_inner(raw, true),
            VoiceTcpEnqueueResult::Accepted
        )
    }

    /// Variant for a large, already-batched voice fanout. It avoids a
    /// contended global queue-depth metrics mutex once per recipient; the
    /// batch still records its enqueue and egress outcomes.
    pub(crate) fn try_enqueue_voice_tcp_batched(&self, raw: Bytes) -> VoiceTcpEnqueueResult {
        self.try_enqueue_voice_tcp_inner(raw, false)
    }

    fn try_enqueue_voice_tcp_inner(
        &self,
        raw: Bytes,
        record_metrics: bool,
    ) -> VoiceTcpEnqueueResult {
        let Some(voice_tcp_tx) = self.voice_tcp_tx.as_ref() else {
            if record_metrics {
                crate::voice::metrics::record_queue_enqueue(
                    crate::voice::metrics::VoiceQueueKind::TcpFallback,
                    crate::voice::metrics::VoiceQueueEnqueueResult::Closed,
                );
                crate::voice::metrics::record_queue_drop(
                    crate::voice::metrics::VoiceQueueDropReason::TcpQueueClosed,
                );
                tracing::trace!(
                    session = u32::from(self.get_session_id()),
                    "voice TCP queue unavailable, dropping packet"
                );
            }
            return VoiceTcpEnqueueResult::Closed;
        };
        let capacity = voice_tcp_tx.max_capacity();
        let depth = capacity.saturating_sub(voice_tcp_tx.capacity());
        if record_metrics {
            crate::voice::metrics::record_queue_status(
                crate::voice::metrics::VoiceQueueKind::TcpFallback,
                depth,
                capacity,
            );
        }
        match voice_tcp_tx.try_send(raw) {
            Ok(()) => {
                if record_metrics {
                    crate::voice::metrics::record_queue_enqueue(
                        crate::voice::metrics::VoiceQueueKind::TcpFallback,
                        crate::voice::metrics::VoiceQueueEnqueueResult::Accepted,
                    );
                }
                VoiceTcpEnqueueResult::Accepted
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                if record_metrics {
                    crate::voice::metrics::record_queue_enqueue(
                        crate::voice::metrics::VoiceQueueKind::TcpFallback,
                        crate::voice::metrics::VoiceQueueEnqueueResult::Full,
                    );
                    crate::voice::metrics::record_queue_drop(
                        crate::voice::metrics::VoiceQueueDropReason::TcpQueueFull,
                    );
                }
                debug_assert!(
                    false,
                    "voice TCP queue full for session {}",
                    u32::from(self.get_session_id())
                );
                if record_metrics {
                    tracing::trace!(
                        session = u32::from(self.get_session_id()),
                        "voice TCP queue full, dropping packet"
                    );
                }
                VoiceTcpEnqueueResult::Full
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                if record_metrics {
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
                }
                VoiceTcpEnqueueResult::Closed
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

    pub(crate) fn is_hidden_from_regular_users(&self) -> bool {
        self.global_state.read().is_hidden_from_regular_users()
    }

    pub fn set_authenticated(&self, value: bool) {
        let mut local_state_guard = self.local_state.write();
        match &mut *local_state_guard {
            Some(state) => state.set_authenticated(value),
            None => panic!("Accessing local state on remote user"),
        }
    }

    pub fn is_reauthentication_in_progress(&self) -> bool {
        self.local_state
            .read()
            .as_ref()
            .is_some_and(ClientLocalState::is_reauthentication_in_progress)
    }

    pub fn set_authentication_expiry(
        &self,
        auth_session_id: Option<String>,
        authenticated_until: Option<DateTime<Utc>>,
        authentication_expiry_action: AuthenticationExpiryAction,
    ) {
        {
            let mut local_state = self.local_state.write();
            let state = local_state
                .as_mut()
                .expect("Accessing authentication expiry on remote user");
            state.set_authentication_expiry(
                auth_session_id,
                authenticated_until,
                authentication_expiry_action,
            );
        }
        self.record_tracing_span_authentication();
    }

    pub fn complete_authentication(
        &self,
        auth_session_id: Option<String>,
        authenticated_until: Option<DateTime<Utc>>,
        authentication_expiry_action: AuthenticationExpiryAction,
    ) {
        {
            let mut local_state = self.local_state.write();
            let state = local_state
                .as_mut()
                .expect("Completing authentication on remote user");
            state.complete_authentication(
                auth_session_id,
                authenticated_until,
                authentication_expiry_action,
            );
        }
        self.record_tracing_span_authentication();
    }

    fn record_tracing_span_authentication(&self) {
        let auth_session_id = self
            .local_state
            .read()
            .as_ref()
            .and_then(|state| state.auth_session_id())
            .map(ToOwned::to_owned);
        if let Some(auth_session_id) = auth_session_id {
            self.tracing_span
                .record("client_auth_session_id", auth_session_id.as_str());
        } else {
            self.tracing_span.record("client_auth_session_id", "");
        }
        self.record_tracing_span_identity();
    }

    pub(crate) fn record_tracing_span_identity(&self) {
        let (user_id, user_name, fqdn) = {
            let state = self.global_state.read();
            (
                state.get_user_id(),
                state.get_display_name_opt().map(ToOwned::to_owned),
                state.get_fqdn().map(ToOwned::to_owned),
            )
        };
        if let Some(user_id) = user_id {
            self.tracing_span.record("client_user_id", user_id);
        } else {
            self.tracing_span.record("client_user_id", "");
        }
        if let Some(user_name) = user_name {
            self.tracing_span
                .record("client_user_name", user_name.as_str());
        } else {
            self.tracing_span.record("client_user_name", "");
        }
        if let Some(fqdn) = fqdn {
            self.tracing_span.record("client_fqdn", fqdn.as_str());
        } else {
            self.tracing_span.record("client_fqdn", "");
        }
    }

    pub(crate) fn take_expired_authentication(
        &self,
        now: DateTime<Utc>,
        allow_reauth: bool,
    ) -> Option<ExpiredAuthenticationAction> {
        self.local_state
            .write()
            .as_mut()
            .and_then(|state| state.take_expired_authentication(now, allow_reauth))
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
            hash: self.certificate_hash_hex.clone(),
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

    // ── Session blob reference pins ───────────────────────────────────────
    // A client whose state references a session blob (texture/comment hash)
    // pins it so eviction never removes content that is still in use. The
    // pin is replaced when the reference changes and released when this
    // Client is dropped. Remote clients keep their source URLs, so eviction
    // of their blobs can refetch; pins still apply to whichever client the
    // hash was set on.

    /// Pin the session blob `key` as this client's texture reference,
    /// releasing any previous texture pin.
    pub fn pin_texture_blob(
        &self,
        store: &std::sync::Arc<crate::blob_store::SessionBlobStore>,
        key: &str,
    ) {
        *self.texture_blob_pin.lock() = Some(crate::blob_store::BlobPin::new(store, key));
    }

    /// Pin the session blob `key` as this client's comment reference,
    /// releasing any previous comment pin.
    pub fn pin_comment_blob(
        &self,
        store: &std::sync::Arc<crate::blob_store::SessionBlobStore>,
        key: &str,
    ) {
        *self.comment_blob_pin.lock() = Some(crate::blob_store::BlobPin::new(store, key));
    }

    /// Release this client's texture blob reference (if any).
    pub fn clear_texture_blob_pin(&self) {
        self.texture_blob_pin.lock().take();
    }

    /// Release this client's comment blob reference (if any).
    pub fn clear_comment_blob_pin(&self) {
        self.comment_blob_pin.lock().take();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::mpsc as std_mpsc;

    fn local_test_client() -> Box<Client> {
        let (outbound_tx, _outbound_rx) = mpsc::channel(1);
        Client::new_web_gateway(
            ClientSessionIdentifier::from(0x0002_0001),
            Ipv4Addr::LOCALHOST.into(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 64738)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 64738)),
            outbound_tx,
        )
    }

    fn assert_authentication_update_completes(
        update: impl FnOnce(&Client) + Send + 'static,
    ) -> Box<Client> {
        let client = local_test_client();
        let (completed_tx, completed_rx) = std_mpsc::channel();
        std::thread::spawn(move || {
            update(&client);
            completed_tx
                .send(client)
                .expect("test receiver should remain available");
        });

        completed_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("authentication update must not deadlock on local state")
    }

    #[test]
    fn authentication_state_updates_do_not_reacquire_local_state_lock() {
        let renewed = assert_authentication_update_completes(|client| {
            client.set_authentication_expiry(
                Some("renewal-session".to_owned()),
                Some(Utc::now()),
                AuthenticationExpiryAction::Reauth,
            );
        });
        let renewed_local_state = renewed.local_state.read();
        let renewed_state = renewed_local_state.as_ref().expect("local client state");
        assert!(!renewed_state.is_authenticated());
        assert_eq!(renewed_state.auth_session_id(), Some("renewal-session"));
        assert_eq!(
            renewed_state.authentication_expiry_action(),
            AuthenticationExpiryAction::Reauth
        );

        let authenticated = assert_authentication_update_completes(|client| {
            client.complete_authentication(
                Some("initial-session".to_owned()),
                Some(Utc::now()),
                AuthenticationExpiryAction::Kick,
            );
        });
        let authenticated_local_state = authenticated.local_state.read();
        let authenticated_state = authenticated_local_state
            .as_ref()
            .expect("local client state");
        assert!(authenticated_state.is_authenticated());
        assert_eq!(
            authenticated_state.auth_session_id(),
            Some("initial-session")
        );
        assert_eq!(
            authenticated_state.authentication_expiry_action(),
            AuthenticationExpiryAction::Kick
        );
    }

    #[test]
    fn real_ip_getter_unmaps_ipv4_mapped_ipv6_addresses() {
        let mapped_address = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x5144, 0x2a63));
        let (outbound_tx, _outbound_rx) = mpsc::channel(1);
        let client = Client::new_web_gateway(
            ClientSessionIdentifier::from(0x0002_0001),
            mapped_address,
            SocketAddr::new(mapped_address, 64738),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 64738)),
            outbound_tx,
        );

        assert_eq!(
            client.get_real_ip_address(),
            IpAddr::V4(Ipv4Addr::new(81, 68, 42, 99))
        );
    }

    #[test]
    fn request_blob_queue_is_lazy_fifo_bounded_and_releases_after_drain() {
        let (outbound_tx, _outbound_rx) = mpsc::channel(1);
        let client = Client::new_web_gateway(
            ClientSessionIdentifier::from(0x0002_0001),
            Ipv4Addr::LOCALHOST.into(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 64738)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 64738)),
            outbound_tx,
        );
        assert!(client.install_request_blob_queue(2));
        assert!(!client.install_request_blob_queue(2));
        {
            let queue = client.request_blob_queue.lock();
            assert_eq!(queue.as_ref().unwrap().pending.capacity(), 0);
        }
        let mut first = msg_encoder::RequestBlob::default();
        first.session_texture = vec![1];
        client
            .enqueue_request_blob(first)
            .expect("first RequestBlob job should fit");
        let mut second = msg_encoder::RequestBlob::default();
        second.session_texture = vec![2];
        client
            .enqueue_request_blob(second)
            .expect("second RequestBlob job should fit");
        assert!(matches!(
            client.enqueue_request_blob(msg_encoder::RequestBlob::default()),
            Err(RequestBlobQueueEnqueueError::Full(_))
        ));

        assert_eq!(
            client
                .dequeue_request_blob()
                .expect("first queued job")
                .session_texture,
            vec![1]
        );
        assert_eq!(
            client
                .dequeue_request_blob()
                .expect("second queued job")
                .session_texture,
            vec![2]
        );
        {
            let queue = client.request_blob_queue.lock();
            assert_eq!(queue.as_ref().unwrap().pending.capacity(), 0);
        }
    }

    #[test]
    fn request_blob_queue_releases_excess_partial_burst_storage() {
        let mut queue = RequestBlobQueue::new(16);
        for _ in 0..16 {
            queue.pending.push_back(msg_encoder::RequestBlob::default());
        }
        let burst_capacity = queue.pending.capacity();
        for _ in 0..13 {
            assert!(queue.pop_front().is_some());
        }
        assert_eq!(queue.pending.len(), 3);
        assert!(queue.pending.capacity() < burst_capacity);
        assert!(queue.pending.capacity() >= queue.pending.len());
    }

    #[test]
    fn remote_clients_do_not_allocate_local_only_queues() {
        let client = Client::new_remote_in_server(
            DEFAULT_SERVER_ID.to_owned(),
            ClientSessionIdentifier::from(0x0002_0001),
            Ipv4Addr::LOCALHOST.into(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 64738)),
            None,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 64738)),
            None,
            Utc::now(),
            7,
        );

        assert!(client.voice_routing_tx.is_none());
        assert!(client.take_voice_routing_rx().is_none());
        assert!(client.voice_tcp_tx.is_none());
        assert!(client.take_voice_tcp_rx().is_none());
        assert!(client.outbound_message_tx.is_none());
        assert!(client.take_outbound_message_rx().is_none());

        assert!(!*client.disconnect_rx.borrow());
        client.request_disconnect();
        assert!(*client.disconnect_rx.borrow());

        assert!(!*client.removed_rx.borrow());
        client.mark_removed();
        assert!(*client.removed_rx.borrow());
    }

    #[test]
    fn client_acl_cache_grows_with_touched_channels_and_validates_generations() {
        let client = Client::new_remote_in_server(
            DEFAULT_SERVER_ID.to_owned(),
            ClientSessionIdentifier::from(0x0002_0001),
            Ipv4Addr::LOCALHOST.into(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 64738)),
            None,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 64738)),
            None,
            Utc::now(),
            7,
        );
        let permissions: enumflags2::BitFlags<shitspeak_state::ACLPermissions> =
            shitspeak_state::ACLPermissions::Enter.into();

        // This intentionally exceeds scc::HashCache's default global limit of
        // 256 entries. The per-client map retains the connection's full
        // working set without competing with other clients.
        for channel_id in 0..1024 {
            client.cache_acl_permissions(channel_id, 3, 5, 7, false, false, permissions);
        }
        for channel_id in 0..1024 {
            assert_eq!(
                client.get_cached_acl_permissions(channel_id, 3, 5, 99, false),
                Some((permissions, false))
            );
        }

        assert!(
            client
                .get_cached_acl_permissions(0, 3, 6, 7, false)
                .is_none()
        );
        client.set_server_id("other-server".to_owned());
        assert!(
            client
                .get_cached_acl_permissions(0, 3, 5, 7, false)
                .is_none()
        );
    }

    #[test]
    fn acl_state_snapshot_is_a_coherent_owned_revision() {
        let client = Client::new_remote_in_server(
            DEFAULT_SERVER_ID.to_owned(),
            ClientSessionIdentifier::from(0x0002_0001),
            Ipv4Addr::LOCALHOST.into(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 64738)),
            None,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 64738)),
            None,
            Utc::now(),
            7,
        );
        {
            let mut state = client.write_global_state_direct();
            state.set_current_channel_id(4);
            state.set_user_id(Some(17));
            state.set_groups(["first-group".to_owned()].into_iter().collect());
            state.set_tokens(["FIRST-TOKEN".to_owned()].into_iter().collect());
            state.set_superuser(true);
        }

        let first = client.acl_state_snapshot();
        {
            let mut state = client.write_global_state_direct();
            state.set_current_channel_id(9);
            state.set_user_id(Some(23));
            state.set_groups(["second-group".to_owned()].into_iter().collect());
            state.set_tokens(["second-token".to_owned()].into_iter().collect());
            state.set_superuser(false);
        }
        let second = client.acl_state_snapshot();

        assert_eq!(first.current_channel_id(), 4);
        assert_eq!(first.user_id(), Some(17));
        assert_eq!(first.groups(), &HashSet::from(["first-group".to_owned()]));
        assert_eq!(first.tokens(), &HashSet::from(["first-token".to_owned()]));
        assert!(first.is_superuser());

        assert_eq!(second.current_channel_id(), 9);
        assert_eq!(second.user_id(), Some(23));
        assert_eq!(second.groups(), &HashSet::from(["second-group".to_owned()]));
        assert_eq!(second.tokens(), &HashSet::from(["second-token".to_owned()]));
        assert!(!second.is_superuser());
        assert_ne!(
            first.acl_cache_generations(),
            second.acl_cache_generations()
        );
    }

    #[test]
    fn certificate_hash_projection_cache_reuses_one_value_per_generation() {
        let certificate_hash = Bytes::from_static(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
        ]);
        let client = Client::new_remote_in_server(
            DEFAULT_SERVER_ID.to_owned(),
            ClientSessionIdentifier::from(0x0002_0001),
            Ipv4Addr::LOCALHOST.into(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 64738)),
            None,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 64738)),
            Some(certificate_hash),
            Utc::now(),
            7,
        );
        let protection = shitspeak_runtime_config::CertificateHashProtection::Irreversible;

        assert_eq!(
            client.build_user_state_for_broadcast().hash.as_deref(),
            Some("00112233445566778899aabbccddeeff00112233")
        );

        let generation_seven = client
            .protected_certificate_hash_hex(7, protection, "first-secret")
            .expect("valid certificate hash");
        let same_generation = client
            .protected_certificate_hash_hex(7, protection, "unused-secret")
            .expect("cached certificate hash");
        let generation_eight = client
            .protected_certificate_hash_hex(8, protection, "second-secret")
            .expect("recomputed certificate hash");

        assert_eq!(same_generation, generation_seven);
        assert_ne!(generation_eight, generation_seven);
        assert_eq!(
            generation_eight,
            crate::privacy::protected_certificate_hash_hex(
                protection,
                "second-secret",
                "00112233445566778899aabbccddeeff00112233",
            )
            .unwrap()
        );
        let cache = client.certificate_hash_projection_cache.lock();
        assert_eq!(cache.visibility_generation, Some(8));
        assert_eq!(
            cache.protected_hash_hex.as_deref(),
            Some(&*generation_eight)
        );
    }

    fn ping(timestamp: u64) -> Message {
        Message::Ping(
            msg_encoder::Ping {
                timestamp,
                ..Default::default()
            }
            .into(),
        )
    }

    fn outbound_batch_len(message: ClientOutboundMessage) -> usize {
        match message {
            ClientOutboundMessage::Batch(messages) => messages.len(),
            ClientOutboundMessage::Single(_) => panic!("expected an outbound message batch"),
        }
    }

    #[test]
    fn owned_message_batch_round_trips_without_exposing_storage() {
        let batch = OwnedMessageBatch::new(vec![ping(1), ping(2)]);

        assert!(!batch.is_empty());
        assert_eq!(batch.len(), 2);
        let messages = batch.into_messages();
        assert!(matches!(&messages[0], Message::Ping(ping) if ping.timestamp == Some(1)));
        assert!(matches!(&messages[1], Message::Ping(ping) if ping.timestamp == Some(2)));
    }

    #[test]
    fn owned_message_batch_try_send_is_bounded_and_preserves_rejected_batch() {
        let (tx, mut rx) = mpsc::channel(1);

        try_send_owned_message_batch(Some(&tx), OwnedMessageBatch::new(vec![ping(1), ping(2)]))
            .expect("first batch should fit");
        let full = try_send_owned_message_batch(
            Some(&tx),
            OwnedMessageBatch::new(vec![ping(3), ping(4), ping(5)]),
        )
        .expect_err("second batch should observe the full queue");
        assert!(matches!(full, mpsc::error::TrySendError::Full(_)));
        assert_eq!(outbound_batch_len(full.into_inner()), 3);

        assert_eq!(
            outbound_batch_len(rx.try_recv().expect("queued batch should remain available")),
            2
        );
        drop(rx);

        let closed = try_send_owned_message_batch(Some(&tx), OwnedMessageBatch::new(vec![ping(6)]))
            .expect_err("closed queue should reject the batch");
        assert!(matches!(closed, mpsc::error::TrySendError::Closed(_)));
        assert_eq!(outbound_batch_len(closed.into_inner()), 1);
    }

    #[test]
    fn empty_owned_message_batch_succeeds_without_a_writer() {
        try_send_owned_message_batch(None, OwnedMessageBatch::new(Vec::new()))
            .expect("empty batches do not require a writer queue");
    }

    #[test]
    fn gateway_owned_batch_reservation_prevents_partial_delivery() {
        let (tx, mut rx) = mpsc::channel(2);
        tx.try_send(ping(1))
            .expect("first queue slot should be free");

        let full =
            try_send_owned_gateway_batch(&tx, OwnedMessageBatch::new(vec![ping(2), ping(3)]))
                .expect_err("the complete batch does not fit");
        assert!(matches!(full, mpsc::error::TrySendError::Full(_)));
        assert_eq!(outbound_batch_len(full.into_inner()), 2);

        assert!(matches!(
            rx.try_recv(),
            Ok(Message::Ping(ping)) if ping.timestamp == Some(1)
        ));
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        try_send_owned_gateway_batch(&tx, OwnedMessageBatch::new(vec![ping(4), ping(5)]))
            .expect("the complete batch should fit once capacity is available");
        assert!(matches!(
            rx.try_recv(),
            Ok(Message::Ping(ping)) if ping.timestamp == Some(4)
        ));
        assert!(matches!(
            rx.try_recv(),
            Ok(Message::Ping(ping)) if ping.timestamp == Some(5)
        ));

        let oversized = try_send_owned_gateway_batch(
            &tx,
            OwnedMessageBatch::new(vec![ping(6), ping(7), ping(8)]),
        )
        .expect_err("a batch larger than maximum capacity must not panic");
        assert!(matches!(oversized, mpsc::error::TrySendError::Full(_)));
        assert_eq!(outbound_batch_len(oversized.into_inner()), 3);
    }

    #[tokio::test]
    async fn owned_message_batch_gateway_preserves_order_and_backpressure() {
        let (tx, mut rx) = mpsc::channel(1);
        let client = Client::new_web_gateway(
            ClientSessionIdentifier::from(0x0002_0001),
            Ipv4Addr::LOCALHOST.into(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 64738)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 64738)),
            tx,
        );
        let messages = vec![ping(11), ping(12)];
        let expected_bytes = messages
            .iter()
            .map(|message| 6 + message.encoded_len())
            .sum::<usize>();

        let send = client.write_owned_message_batch(OwnedMessageBatch::new(messages));
        let receive = async {
            let first = rx.recv().await.expect("first message should arrive");
            let second = rx.recv().await.expect("second message should arrive");
            (first, second)
        };
        let (result, (first, second)) = tokio::join!(send, receive);

        result.expect("owned gateway batch should be delivered");
        assert!(matches!(first, Message::Ping(ping) if ping.timestamp == Some(11)));
        assert!(matches!(second, Message::Ping(ping) if ping.timestamp == Some(12)));
        assert_eq!(
            client.stats.read().await.total_volume(),
            expected_bytes as u64
        );
    }
}
