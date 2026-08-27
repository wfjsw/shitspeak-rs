//! UDP packet-encryption endpoint.
//!
//! UDP remains connectionless at the wire level: every datagram carries a
//! small authenticated header and one encrypted protobuf transport frame.
//! AEAD keys come from a signed ephemeral X25519 exchange using the same
//! certificate identity as the stream transports. The per-peer route object
//! exists only to hold send queues, AEAD keys, replay windows, and probe
//! bookkeeping; it does not represent a DTLS-style connection.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement;
use aws_lc_rs::digest;
use aws_lc_rs::hkdf;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature;
use bytes::Bytes;
use prost::Message as _;
use rustls::SignatureScheme;
use rustls_pki_types::CertificateDer;
use tokio::sync::{Mutex, Notify, oneshot};
use tokio::time::{Instant as TokioInstant, Interval, interval_at, sleep};
use tokio_util::sync::CancellationToken;

use shitspeak_core::rate_limit::{KeyedRateLimiter, TokenBucket};

/// Per-source-IP budget for S2S UDP key-exchange packets (offers/readies).
/// The X.509 chain validation and signature verification that follow are
/// CPU-expensive, so floods must be throttled. Steady-state traffic never
/// hits this: key exchanges happen once per establishment and on re-key
/// only, and the burst covers a hub establishing many sessions at startup.
const KEY_EXCHANGE_RATE_PER_SECOND: f64 = 10.0;
const KEY_EXCHANGE_BURST: f64 = 64.0;
const KEY_EXCHANGE_MAX_SOURCES: usize = 65_536;

/// Global budget for key-exchange verification across *all* sources. The
/// per-source-IP limiter alone can be bypassed by rotating spoofed source
/// IPs (each new IP gets a fresh bucket), so a shared bucket bounds the
/// total X.509/signature verification work regardless of IP rotation. Legit
/// clusters are unaffected: handshakes are rare (once per link/establishment).
const KEY_EXCHANGE_GLOBAL_RATE_PER_SECOND: f64 = 100.0;
const KEY_EXCHANGE_GLOBAL_BURST: f64 = 200.0;
use tracing::{debug, trace, warn};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::types::NodeIdentifier;
use shitspeak_proto::s2s_transport_proto as pb;

use super::super::compression::{maybe_compress_frame_payload, validate_and_decode_payload};
use super::super::connection::{ActiveStream, OutboundFrame, PeerState};
use super::super::frame::{FrameType, build_frame};
use super::super::identity::{NodeIdentity, parse_peer_cn};
use super::super::latest_wins_queue::{
    LatestWinsReceiver, TryRecvLatestWinsError, latest_wins_queue_unbounded,
};
use super::super::manager::{InboundDispatch, InboundMessage, ManagerInner};
use super::super::metrics::{
    ExpiredOutboundDropStage, TransportIoDirection, TransportIoPressureResult,
    TransportPipelineStage, record_transport_io_batch, record_transport_io_frames,
    record_transport_io_pressure, record_transport_pipeline_stage,
};
use super::super::service_level::{MessageClass, ServiceLevel, TransportKind};
use super::super::tls;
use super::{
    Endpoint,
    mux::{DISCRIMINATOR_LEN, PrefixedUdpSocket, UdpMuxHandle, UdpMuxSet},
    udp_batch::{RecvDatagramBatch, UDP_RECV_BATCH_MAX_DATAGRAMS},
};

const MAGIC: [u8; 4] = *b"SSU1";
const HEADER_LEN: usize = 20;
const TAG_LEN: usize = 16;
pub(crate) const UDP_ENCRYPTED_OVERHEAD: usize = HEADER_LEN + TAG_LEN;
pub(crate) const UDP_MTU_SAFETY_MARGIN: usize = 64;
pub(crate) const UDP_MIN_DATAGRAM_MTU: usize = 576;
const UDP_AUTOFIT_PROBE_MTU: usize = 1500;
const UDP_MTU_PROBE_STEP: usize = 64;
const UDP_MTU_PROBE_INTERVAL: Duration = Duration::from_secs(30);
const UDP_FRAGMENT_MAGIC: [u8; 4] = *b"SSUF";
const UDP_FRAGMENT_HEADER_LEN: usize = 20;
const UDP_FRAGMENT_TTL: Duration = Duration::from_secs(2);
const UDP_FRAGMENT_MAX_IN_FLIGHT: usize = 64;
const UDP_FRAGMENT_MAX_COUNT: usize = 2048;
const UDP_FRAGMENT_MAX_FRAME_ENVELOPE_BYTES: usize = 64;
const X25519_PUBLIC_KEY_LEN: usize = 32;
const MAX_HANDSHAKE_DATAGRAM: usize = 16 * 1024;
const UDP_KEEPALIVE_MISS_CLOSE_THRESHOLD: usize = 3;
const UDP_KEX_RETRANSMIT_INTERVAL: Duration = Duration::from_millis(750);
const UDP_KEX_RETRANSMIT_MAX_INTERVAL: Duration = Duration::from_secs(8);
const UDP_KEX_RETRANSMIT_JITTER_DIVISOR: u32 = 4;
const UDP_KEX_MAX_RETRANSMIT_AGE: Duration = Duration::from_secs(30);
const UDP_KEX_MAX_RETRANSMITS: u32 = 16;
const UDP_KEX_READY_LOG_INTERVAL: Duration = Duration::from_secs(30);
const UDP_WRITE_BATCH_MAX_FRAMES: usize = 32;
const UDP_WRITE_BATCH_MAX_BYTES: usize = 64 * 1024;
const KEX_TRANSCRIPT_DOMAIN: &[u8] = b"shitspeak-s2s-udp-kex-v1";
const KEX_KEY_INFO: &[u8] = b"shitspeak-s2s-udp-packet-keys-v1";
const SUPPORTED_SIGNATURE_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ED25519,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
];

pub(crate) fn initial_udp_datagram_mtu(configured_mtu: usize) -> usize {
    configured_mtu
        .saturating_sub(UDP_MTU_SAFETY_MARGIN)
        .max(UDP_MIN_DATAGRAM_MTU)
        .min(udp_datagram_mtu_ceiling(configured_mtu))
}

pub(crate) fn udp_datagram_mtu_ceiling(configured_mtu: usize) -> usize {
    configured_mtu
        .max(UDP_AUTOFIT_PROBE_MTU)
        .saturating_sub(UDP_MTU_SAFETY_MARGIN)
        .max(UDP_MIN_DATAGRAM_MTU)
}

pub(crate) struct UdpEndpoint {
    identity: Arc<NodeIdentity>,
    listen_addrs: Vec<SocketAddr>,
    mux: UdpMuxSet,
    sockets: Mutex<UdpSocketSet>,
}

impl UdpEndpoint {
    pub fn new(
        identity: Arc<NodeIdentity>,
        listen_addrs: impl IntoIterator<Item = SocketAddr>,
        mux: UdpMuxSet,
    ) -> Self {
        Self {
            identity,
            listen_addrs: listen_addrs.into_iter().collect(),
            mux,
            sockets: Mutex::new(UdpSocketSet::default()),
        }
    }

    async fn ensure_listen_socket(
        &self,
        addr: SocketAddr,
        inner: Arc<ManagerInner>,
    ) -> io::Result<Arc<UdpSocketState>> {
        let (canonical_addr, ipv6_only) = self.mux.binding_for(addr)?;
        let mut sockets = self.sockets.lock().await;
        if let Some(existing) = sockets.for_bound_addr(canonical_addr, ipv6_only) {
            return Ok(existing.clone());
        }

        let handle = self
            .mux
            .take_handle(addr, TransportKind::Udp, inner.shutdown().child_token())
            .await?;
        let state = Arc::new(UdpSocketState::from_mux(handle));
        sockets.insert(canonical_addr, ipv6_only, state.clone());
        let local_node = inner.self_id();
        tokio::spawn(run_socket_read_loop(
            state.clone(),
            inner.clone(),
            self.identity.clone(),
        ));
        tokio::spawn(run_exchange_retransmit_loop(state.clone(), local_node));
        Ok(state)
    }

    async fn ensure_socket(
        &self,
        remote_addr: SocketAddr,
        inner: Arc<ManagerInner>,
    ) -> io::Result<Arc<UdpSocketState>> {
        {
            let sockets = self.sockets.lock().await;
            if let Some(existing) = sockets.for_addr(remote_addr) {
                return Ok(existing.clone());
            }
        }

        if let Some(addr) = self
            .listen_addrs
            .iter()
            .copied()
            .find(|addr| self.mux.supports_remote(*addr, remote_addr))
        {
            return self.ensure_listen_socket(addr, inner).await;
        }

        let state = Arc::new(UdpSocketState::from_prefixed(
            PrefixedUdpSocket::bind_ephemeral(remote_addr, TransportKind::Udp).await?,
        ));
        let bind_addr = state.socket.local_addr()?;
        let ipv6_only = false;
        let mut sockets = self.sockets.lock().await;
        if let Some(existing) = sockets.for_addr(remote_addr) {
            return Ok(existing.clone());
        }
        sockets.insert(bind_addr, ipv6_only, state.clone());
        let local_node = inner.self_id();
        tokio::spawn(run_socket_read_loop(
            state.clone(),
            inner.clone(),
            self.identity.clone(),
        ));
        tokio::spawn(run_exchange_retransmit_loop(state.clone(), local_node));
        Ok(state)
    }
}

impl Endpoint for UdpEndpoint {
    fn start(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            for addr in self.listen_addrs.iter().copied() {
                self.ensure_listen_socket(addr, inner.clone()).await?;
                debug!(%addr, "udp packet-encryption listener up");
            }
            Ok(())
        }
    }

    fn dial(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
        peer: Arc<PeerState>,
        addr: SocketAddr,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            let socket = self.ensure_socket(addr, inner.clone()).await?;
            let completion =
                start_key_exchange(&inner, &self.identity, socket, peer.node_id(), addr).await?;
            completion.await.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "udp signed key exchange was cancelled",
                )
            })?
        }
    }

    fn dial_unidentified(
        self: Arc<Self>,
        _inner: Arc<ManagerInner>,
        _addr: SocketAddr,
    ) -> impl Future<Output = io::Result<NodeIdentifier>> + Send {
        async move {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "udp packet encryption requires a known peer node id",
            ))
        }
    }
}

#[derive(Default)]
struct UdpSocketSet {
    entries: Vec<UdpSocketEntry>,
}

struct UdpSocketEntry {
    addr: SocketAddr,
    ipv6_only: bool,
    state: Arc<UdpSocketState>,
}

impl UdpSocketSet {
    fn for_addr(&self, addr: SocketAddr) -> Option<&Arc<UdpSocketState>> {
        self.entries
            .iter()
            .find(|entry| super::socket_addr_supports_remote(entry.addr, entry.ipv6_only, addr))
            .map(|entry| &entry.state)
    }

    fn for_bound_addr(&self, addr: SocketAddr, ipv6_only: bool) -> Option<&Arc<UdpSocketState>> {
        self.entries
            .iter()
            .find(|entry| entry.addr == addr && entry.ipv6_only == ipv6_only)
            .map(|entry| &entry.state)
    }

    fn insert(&mut self, addr: SocketAddr, ipv6_only: bool, state: Arc<UdpSocketState>) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.addr == addr && entry.ipv6_only == ipv6_only)
        {
            entry.state = state;
        } else {
            self.entries.push(UdpSocketEntry {
                addr,
                ipv6_only,
                state,
            });
        }
    }
}

struct UdpSocketState {
    socket: UdpIo,
    sessions: Mutex<HashMap<NodeIdentifier, Arc<UdpCryptoSession>>>,
    exchanges: Mutex<HashMap<NodeIdentifier, PeerKeyExchange>>,
    exchange_retransmit: Notify,
    shutdown: CancellationToken,
    /// Per-source-IP rate limit on the (expensive) key-exchange path: X.509
    /// chain validation + signature verification only run when the budget
    /// allows. Steady-state traffic never reaches this — key exchanges are
    /// rare (once per establishment / re-key), and the burst is large enough
    /// for a hub establishing many sessions at startup.
    key_exchange_rate_limiter: KeyedRateLimiter<std::net::IpAddr>,
    /// Global verification budget shared across all sources (see
    /// `KEY_EXCHANGE_GLOBAL_RATE_PER_SECOND`), so spoofed-IP rotation cannot
    /// bypass the per-source limiter.
    key_exchange_global_budget: std::sync::Mutex<TokenBucket>,
}

impl UdpSocketState {
    fn from_mux(handle: UdpMuxHandle) -> Self {
        Self {
            socket: UdpIo::Mux(Arc::new(handle)),
            sessions: Mutex::new(HashMap::new()),
            exchanges: Mutex::new(HashMap::new()),
            exchange_retransmit: Notify::new(),
            shutdown: CancellationToken::new(),
            key_exchange_rate_limiter: KeyedRateLimiter::new(
                KEY_EXCHANGE_RATE_PER_SECOND,
                KEY_EXCHANGE_BURST,
                KEY_EXCHANGE_MAX_SOURCES,
            ),
            key_exchange_global_budget: std::sync::Mutex::new(TokenBucket::new(
                KEY_EXCHANGE_GLOBAL_RATE_PER_SECOND,
                KEY_EXCHANGE_GLOBAL_BURST,
            )),
        }
    }

    fn from_prefixed(socket: PrefixedUdpSocket) -> Self {
        Self {
            socket: UdpIo::Prefixed(Arc::new(socket)),
            sessions: Mutex::new(HashMap::new()),
            exchanges: Mutex::new(HashMap::new()),
            exchange_retransmit: Notify::new(),
            shutdown: CancellationToken::new(),
            key_exchange_rate_limiter: KeyedRateLimiter::new(
                KEY_EXCHANGE_RATE_PER_SECOND,
                KEY_EXCHANGE_BURST,
                KEY_EXCHANGE_MAX_SOURCES,
            ),
            key_exchange_global_budget: std::sync::Mutex::new(TokenBucket::new(
                KEY_EXCHANGE_GLOBAL_RATE_PER_SECOND,
                KEY_EXCHANGE_GLOBAL_BURST,
            )),
        }
    }

    async fn session(&self, node: NodeIdentifier) -> Option<Arc<UdpCryptoSession>> {
        self.sessions.lock().await.get(&node).cloned()
    }

    fn notify_exchange_retransmit(&self) {
        self.exchange_retransmit.notify_one();
    }

    async fn insert_session(&self, session: Arc<UdpCryptoSession>) {
        self.sessions
            .lock()
            .await
            .insert(session.peer_node, session);
    }

    async fn remove_session_if_current(
        &self,
        node: NodeIdentifier,
        session: &Arc<UdpCryptoSession>,
    ) {
        let removed = {
            let mut sessions = self.sessions.lock().await;
            if sessions
                .get(&node)
                .is_some_and(|current| Arc::ptr_eq(current, session))
            {
                sessions.remove(&node);
                true
            } else {
                false
            }
        };
        if removed {
            self.exchanges.lock().await.remove(&node);
        }
    }
}

#[derive(Clone, Debug)]
enum UdpIo {
    Mux(Arc<UdpMuxHandle>),
    Prefixed(Arc<PrefixedUdpSocket>),
}

#[derive(Debug, Default, Clone, Copy)]
struct UdpIoBatchSendOutcome {
    bytes: usize,
    would_block: u64,
    partial: u64,
}

impl UdpIo {
    async fn recv_batch_from(&self, batch: &mut RecvDatagramBatch) -> io::Result<usize> {
        match self {
            Self::Mux(handle) => {
                batch.clear();
                let (len, peer_addr) = handle.recv_from(batch.first_buffer_mut()).await?;
                batch.push_received(0, len, peer_addr);
                Ok(1)
            }
            Self::Prefixed(socket) => {
                batch.clear();
                let (len, peer_addr) = socket.recv_from(batch.first_buffer_mut()).await?;
                batch.push_received(0, len, peer_addr);
                Ok(1)
            }
        }
    }

    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        match self {
            Self::Mux(handle) => handle.send_to(payload, target).await,
            Self::Prefixed(socket) => socket.send_to(payload, target).await,
        }
    }

    async fn send_batch_to(
        &self,
        payloads: &[&[u8]],
        target: SocketAddr,
    ) -> io::Result<UdpIoBatchSendOutcome> {
        match self {
            Self::Mux(handle) => {
                handle
                    .send_batch_to(payloads, target)
                    .await
                    .map(|bytes| UdpIoBatchSendOutcome {
                        bytes,
                        ..UdpIoBatchSendOutcome::default()
                    })
            }
            Self::Prefixed(socket) => {
                socket
                    .send_batch_to(payloads, target)
                    .await
                    .map(|bytes| UdpIoBatchSendOutcome {
                        bytes,
                        ..UdpIoBatchSendOutcome::default()
                    })
            }
        }
    }

    fn overhead(&self) -> usize {
        match self {
            Self::Mux(_) | Self::Prefixed(_) => DISCRIMINATOR_LEN,
        }
    }

    fn payload_mtu(&self, udp_mtu: usize) -> usize {
        udp_mtu.saturating_sub(self.overhead())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Mux(handle) => handle.local_addr(),
            Self::Prefixed(socket) => socket.local_addr(),
        }
    }
}

struct PreparedUdpData {
    datagram: Vec<u8>,
    plaintext: Bytes,
    #[cfg(debug_assertions)]
    frame_type: i32,
    class: MessageClass,
    expires_at: Option<Instant>,
    original_payload_len: usize,
}

#[derive(Default)]
struct UdpFragmentCache {
    entries: HashMap<u64, UdpFragmentEntry>,
}

struct UdpFragmentEntry {
    total_bytes: usize,
    fragment_count: usize,
    fragments: BTreeMap<usize, Bytes>,
    expires_at: Instant,
}

enum UdpFragmentOutcome {
    Whole(Vec<u8>),
    Pending,
    Drop,
}

#[derive(Default)]
struct PeerKeyExchange {
    local: Option<LocalKeyOffer>,
    peer: Option<PeerKeyOffer>,
    candidate: Option<KeyCandidate>,
    peer_addr: Option<SocketAddr>,
    early_ready: Vec<Vec<u8>>,
    waiters: Vec<oneshot::Sender<io::Result<()>>>,
    local_initiated: bool,
    send_budget: ExchangeSendBudget,
    stale_ready: StaleReadyGuard,
}

struct LocalKeyOffer {
    offer_id: u64,
    private_key: Option<agreement::EphemeralPrivateKey>,
    public_key: Vec<u8>,
    packet: Vec<u8>,
}

#[derive(Clone)]
struct PeerKeyOffer {
    offer_id: u64,
    public_key: Vec<u8>,
}

impl PeerKeyOffer {
    fn matches(&self, other: &Self) -> bool {
        self.offer_id == other.offer_id && self.public_key == other.public_key
    }
}

struct KeyCandidate {
    exchange_id: u64,
    peer_addr: SocketAddr,
    seal_key: [u8; 32],
    open_key: [u8; 32],
    ready_packet: Vec<u8>,
    ready_received: bool,
    promoted: bool,
}

#[derive(Default)]
struct ExchangeSendBudget {
    offer: HandshakePacketBudget,
    ready: HandshakePacketBudget,
}

#[derive(Default)]
struct HandshakePacketBudget {
    first_sent: Option<Instant>,
    last_sent: Option<Instant>,
    retransmits: u32,
    exhausted_logged: bool,
}

#[derive(Default)]
struct LogRateLimit {
    last_emitted: Option<Instant>,
    suppressed: u64,
}

impl LogRateLimit {
    fn record(&mut self, now: Instant) -> Option<u64> {
        if self
            .last_emitted
            .is_none_or(|last| now.saturating_duration_since(last) >= UDP_KEX_READY_LOG_INTERVAL)
        {
            self.last_emitted = Some(now);
            return Some(std::mem::take(&mut self.suppressed));
        }
        self.suppressed = self.suppressed.saturating_add(1);
        None
    }

    fn force(&mut self, now: Instant) -> u64 {
        self.last_emitted = Some(now);
        std::mem::take(&mut self.suppressed)
    }
}

#[derive(Default)]
struct StaleReadyGuard {
    // A new exchange map entry restores this one-shot recovery budget after
    // the current exchange succeeds or reaches its 30-second exhaustion cap.
    restart_used: bool,
    log: LogRateLimit,
}

impl StaleReadyGuard {
    fn take_restart(&mut self, source_matches: bool) -> bool {
        if self.restart_used || !source_matches {
            return false;
        }
        self.restart_used = true;
        true
    }
}

struct PromoteSession {
    peer_node: NodeIdentifier,
    peer_addr: SocketAddr,
    is_dialer: bool,
    seal_key: [u8; 32],
    open_key: [u8; 32],
    accepted_seq: Option<u64>,
    waiters: Vec<oneshot::Sender<io::Result<()>>>,
}

struct UdpCryptoSession {
    peer_node: NodeIdentifier,
    peer_addr: parking_lot::Mutex<SocketAddr>,
    socket: UdpIo,
    seal_key: LessSafeKey,
    open_key: LessSafeKey,
    send_seq: AtomicU64,
    next_fragment_id: AtomicU64,
    consecutive_keepalive_misses: AtomicUsize,
    replay: parking_lot::Mutex<ReplayWindow>,
    fragments: parking_lot::Mutex<UdpFragmentCache>,
    pending: Arc<parking_lot::Mutex<PendingPings>>,
    startup_probe_ready: Notify,
}

impl UdpCryptoSession {
    fn new(
        peer_node: NodeIdentifier,
        peer_addr: SocketAddr,
        socket: UdpIo,
        seal_key: [u8; 32],
        open_key: [u8; 32],
        max_pending_pings: usize,
    ) -> io::Result<Self> {
        let seal_key = aead_key(&seal_key)?;
        let open_key = aead_key(&open_key)?;
        Ok(Self {
            peer_node,
            peer_addr: parking_lot::Mutex::new(peer_addr),
            socket,
            seal_key,
            open_key,
            send_seq: AtomicU64::new(1),
            next_fragment_id: AtomicU64::new(1),
            consecutive_keepalive_misses: AtomicUsize::new(0),
            replay: parking_lot::Mutex::new(ReplayWindow::default()),
            fragments: parking_lot::Mutex::new(UdpFragmentCache::default()),
            pending: Arc::new(parking_lot::Mutex::new(PendingPings::new(
                max_pending_pings,
            ))),
            startup_probe_ready: Notify::new(),
        })
    }

    fn update_addr(&self, addr: SocketAddr) {
        *self.peer_addr.lock() = addr;
    }

    async fn send_frame(
        &self,
        frame: &pb::Frame,
        peer: &PeerState,
        udp_mtu: usize,
    ) -> io::Result<usize> {
        let datagram = self.encrypt_frame(frame, self.socket.payload_mtu(udp_mtu))?;
        let addr = *self.peer_addr.lock();
        let write_started_at = Instant::now();
        let n = match self.socket.send_to(&datagram, addr).await {
            Ok(n) => n,
            Err(e) => {
                record_transport_io_pressure(
                    peer.node_id(),
                    TransportKind::Udp,
                    TransportIoDirection::Egress,
                    TransportIoPressureResult::Error,
                    1,
                );
                if is_packet_too_large(&e) {
                    peer.reduce_udp_datagram_mtu(self.socket.overhead() + datagram.len());
                    return Err(e);
                }
                return Err(io::Error::other(format!("udp send: {e}")));
            }
        };
        record_transport_pipeline_stage(
            TransportKind::Udp,
            TransportPipelineStage::SocketWrite,
            write_started_at.elapsed(),
        );
        let class = pb::MessageClass::try_from(frame.message_class)
            .map(MessageClass::from)
            .unwrap_or(MessageClass::Regular);
        record_transport_io_batch(
            peer.node_id(),
            TransportKind::Udp,
            TransportIoDirection::Egress,
            1,
            n,
        );
        record_transport_io_frames(
            peer.node_id(),
            TransportKind::Udp,
            TransportIoDirection::Egress,
            class,
            1,
        );
        peer.metrics().record_sent(TransportKind::Udp, n);
        #[cfg(debug_assertions)]
        crate::debug_io::record_named_sent(udp_frame_kind_name(frame.frame_type), n);
        Ok(n)
    }

    async fn send_data_batch(
        &self,
        batch: &[PreparedUdpData],
        peer: &PeerState,
    ) -> io::Result<usize> {
        if batch.is_empty() {
            return Ok(0);
        }

        let payloads = batch
            .iter()
            .map(|entry| entry.datagram.as_slice())
            .collect::<Vec<_>>();
        let addr = *self.peer_addr.lock();
        let write_started_at = Instant::now();
        let outcome = match self.socket.send_batch_to(&payloads, addr).await {
            Ok(outcome) => outcome,
            Err(e) => {
                record_transport_io_pressure(
                    peer.node_id(),
                    TransportKind::Udp,
                    TransportIoDirection::Egress,
                    TransportIoPressureResult::Error,
                    1,
                );
                if is_packet_too_large(&e) {
                    let largest = batch
                        .iter()
                        .map(|entry| self.socket.overhead() + entry.datagram.len())
                        .max()
                        .unwrap_or(0);
                    peer.reduce_udp_datagram_mtu(largest);
                    return Err(e);
                }
                return Err(io::Error::other(format!("udp send batch: {e}")));
            }
        };
        record_transport_pipeline_stage(
            TransportKind::Udp,
            TransportPipelineStage::SocketWrite,
            write_started_at.elapsed(),
        );
        record_transport_io_batch(
            peer.node_id(),
            TransportKind::Udp,
            TransportIoDirection::Egress,
            batch.len(),
            outcome.bytes,
        );
        record_transport_io_pressure(
            peer.node_id(),
            TransportKind::Udp,
            TransportIoDirection::Egress,
            TransportIoPressureResult::WouldBlock,
            outcome.would_block,
        );
        record_transport_io_pressure(
            peer.node_id(),
            TransportKind::Udp,
            TransportIoDirection::Egress,
            TransportIoPressureResult::Partial,
            outcome.partial,
        );

        for entry in batch {
            peer.metrics()
                .record_sent(TransportKind::Udp, entry.datagram.len());
            record_transport_io_frames(
                peer.node_id(),
                TransportKind::Udp,
                TransportIoDirection::Egress,
                entry.class,
                1,
            );
            #[cfg(debug_assertions)]
            crate::debug_io::record_named_sent(
                udp_frame_kind_name(entry.frame_type),
                entry.datagram.len(),
            );
        }

        Ok(outcome.bytes)
    }

    fn encrypt_frame(&self, frame: &pb::Frame, udp_mtu: usize) -> io::Result<Vec<u8>> {
        let mut plaintext = Vec::with_capacity(frame.encoded_len());
        let encode_started_at = Instant::now();
        frame
            .encode(&mut plaintext)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        record_transport_pipeline_stage(
            TransportKind::Udp,
            TransportPipelineStage::FrameEncode,
            encode_started_at.elapsed(),
        );

        self.encrypt_plaintext(
            frame.src_node as NodeIdentifier,
            frame.dst_node as NodeIdentifier,
            plaintext,
            udp_mtu,
        )
    }

    fn frame_datagram_mtu(&self, frame: &pb::Frame) -> usize {
        self.socket.overhead() + HEADER_LEN + frame.encoded_len() + TAG_LEN
    }

    fn encrypt_data_frame(
        &self,
        frame: &pb::Frame,
        udp_mtu: usize,
    ) -> io::Result<Vec<(Vec<u8>, Bytes)>> {
        let mut plaintext = Vec::with_capacity(frame.encoded_len());
        let encode_started_at = Instant::now();
        frame
            .encode(&mut plaintext)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        record_transport_pipeline_stage(
            TransportKind::Udp,
            TransportPipelineStage::FrameEncode,
            encode_started_at.elapsed(),
        );
        self.encrypt_plaintext_or_fragments(
            frame.src_node as NodeIdentifier,
            frame.dst_node as NodeIdentifier,
            Bytes::from(plaintext),
            udp_mtu,
        )
    }

    fn encrypt_plaintext_or_fragments(
        &self,
        src: NodeIdentifier,
        dst: NodeIdentifier,
        plaintext: Bytes,
        udp_mtu: usize,
    ) -> io::Result<Vec<(Vec<u8>, Bytes)>> {
        if HEADER_LEN + plaintext.len() + TAG_LEN <= udp_mtu {
            let datagram = self.encrypt_plaintext(src, dst, plaintext.to_vec(), udp_mtu)?;
            return Ok(vec![(datagram, plaintext)]);
        }

        let fragment_payload_len =
            udp_mtu.saturating_sub(HEADER_LEN + TAG_LEN + UDP_FRAGMENT_HEADER_LEN);
        if fragment_payload_len == 0 || plaintext.len() > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "udp frame cannot be fragmented within the datagram budget",
            ));
        }
        let fragment_count = plaintext.len().div_ceil(fragment_payload_len);
        if fragment_count > UDP_FRAGMENT_MAX_COUNT || fragment_count > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "udp frame exceeds the fragmentation limit",
            ));
        }
        let fragment_id = self.next_fragment_id.fetch_add(1, Ordering::Relaxed).max(1);
        let mut datagrams = Vec::with_capacity(fragment_count);
        for (index, chunk) in plaintext.chunks(fragment_payload_len).enumerate() {
            let mut fragment = Vec::with_capacity(UDP_FRAGMENT_HEADER_LEN + chunk.len());
            fragment.extend_from_slice(&UDP_FRAGMENT_MAGIC);
            fragment.extend_from_slice(&fragment_id.to_be_bytes());
            fragment.extend_from_slice(&(index as u16).to_be_bytes());
            fragment.extend_from_slice(&(fragment_count as u16).to_be_bytes());
            fragment.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
            fragment.extend_from_slice(chunk);
            let fragment = Bytes::from(fragment);
            let datagram = self.encrypt_plaintext(src, dst, fragment.to_vec(), udp_mtu)?;
            datagrams.push((datagram, fragment));
        }
        Ok(datagrams)
    }

    fn encrypt_plaintext(
        &self,
        src: NodeIdentifier,
        dst: NodeIdentifier,
        plaintext: Vec<u8>,
        udp_mtu: usize,
    ) -> io::Result<Vec<u8>> {
        let seq = self.send_seq.fetch_add(1, Ordering::Relaxed);
        let header = UdpPacketHeader {
            kind: UdpPacketKind::Data,
            src,
            dst,
            seq,
        };
        let header_bytes = header.encode();
        if HEADER_LEN + plaintext.len() + TAG_LEN > udp_mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "encrypted frame {} > udp_mtu {}",
                    HEADER_LEN + plaintext.len() + TAG_LEN,
                    udp_mtu
                ),
            ));
        }
        let mut ciphertext = plaintext;
        let nonce = packet_nonce(header.kind, header.src, header.dst, header.seq)?;
        let encrypt_started_at = Instant::now();
        let encrypt_result = self
            .seal_key
            .seal_in_place_append_tag(nonce, Aad::from(header_bytes), &mut ciphertext)
            .map_err(|_| io::Error::other("udp packet encryption failed"));
        record_transport_pipeline_stage(
            TransportKind::Udp,
            TransportPipelineStage::UdpEncrypt,
            encrypt_started_at.elapsed(),
        );
        encrypt_result?;
        let mut datagram = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        datagram.extend_from_slice(&header_bytes);
        datagram.extend_from_slice(&ciphertext);
        Ok(datagram)
    }

    fn accept_fragment(&self, plaintext: Vec<u8>, max_frame_bytes: usize) -> UdpFragmentOutcome {
        if !plaintext.starts_with(&UDP_FRAGMENT_MAGIC) {
            return UdpFragmentOutcome::Whole(plaintext);
        }
        if plaintext.len() < UDP_FRAGMENT_HEADER_LEN {
            return UdpFragmentOutcome::Drop;
        }
        let fragment_id = u64::from_be_bytes(plaintext[4..12].try_into().expect("fragment id"));
        let fragment_index = usize::from(u16::from_be_bytes(
            plaintext[12..14].try_into().expect("fragment index"),
        ));
        let fragment_count = usize::from(u16::from_be_bytes(
            plaintext[14..16].try_into().expect("fragment count"),
        ));
        let total_bytes = usize::try_from(u32::from_be_bytes(
            plaintext[16..20].try_into().expect("fragment total bytes"),
        ))
        .expect("u32 fits usize");
        let payload = Bytes::copy_from_slice(&plaintext[UDP_FRAGMENT_HEADER_LEN..]);
        if fragment_count == 0
            || fragment_count > UDP_FRAGMENT_MAX_COUNT
            || fragment_index >= fragment_count
            || total_bytes == 0
            || total_bytes > max_frame_bytes.saturating_add(UDP_FRAGMENT_MAX_FRAME_ENVELOPE_BYTES)
            || payload.len() > total_bytes
        {
            return UdpFragmentOutcome::Drop;
        }

        let mut cache = self.fragments.lock();
        let now = Instant::now();
        cache.entries.retain(|_, entry| entry.expires_at > now);
        if !cache.entries.contains_key(&fragment_id)
            && cache.entries.len() >= UDP_FRAGMENT_MAX_IN_FLIGHT
            && let Some(oldest) = cache
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(id, _)| *id)
        {
            cache.entries.remove(&oldest);
        }
        let entry = cache
            .entries
            .entry(fragment_id)
            .or_insert_with(|| UdpFragmentEntry {
                total_bytes,
                fragment_count,
                fragments: BTreeMap::new(),
                expires_at: now + UDP_FRAGMENT_TTL,
            });
        if entry.total_bytes != total_bytes || entry.fragment_count != fragment_count {
            cache.entries.remove(&fragment_id);
            return UdpFragmentOutcome::Drop;
        }
        entry.expires_at = now + UDP_FRAGMENT_TTL;
        entry.fragments.entry(fragment_index).or_insert(payload);
        let received = entry.fragments.values().map(Bytes::len).sum::<usize>();
        if entry.fragments.len() != fragment_count || received != total_bytes {
            return UdpFragmentOutcome::Pending;
        }
        let mut assembled = Vec::with_capacity(total_bytes);
        for index in 0..fragment_count {
            let Some(fragment) = entry.fragments.get(&index) else {
                return UdpFragmentOutcome::Pending;
            };
            assembled.extend_from_slice(fragment);
        }
        cache.entries.remove(&fragment_id);
        (assembled.len() == total_bytes)
            .then_some(assembled)
            .map(UdpFragmentOutcome::Whole)
            .unwrap_or(UdpFragmentOutcome::Drop)
    }

    fn decrypt_packet(&self, packet: &[u8], header: UdpPacketHeader) -> io::Result<Vec<u8>> {
        if header.kind != UdpPacketKind::Data {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "udp non-data packet on encrypted path",
            ));
        }
        if packet.len() < HEADER_LEN + TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short udp encrypted packet",
            ));
        }
        let mut ciphertext = packet[HEADER_LEN..].to_vec();
        let nonce = packet_nonce(header.kind, header.src, header.dst, header.seq)?;
        let decrypt_started_at = Instant::now();
        let decrypt_result = self
            .open_key
            .open_in_place(nonce, Aad::from(&packet[..HEADER_LEN]), &mut ciphertext)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "udp decrypt failed"));
        record_transport_pipeline_stage(
            TransportKind::Udp,
            TransportPipelineStage::UdpDecrypt,
            decrypt_started_at.elapsed(),
        );
        let plaintext = decrypt_result?;
        if !self.replay.lock().accept(header.seq) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "replayed udp packet",
            ));
        }
        Ok(plaintext.to_vec())
    }
}

fn aead_key(key: &[u8; 32]) -> io::Result<LessSafeKey> {
    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| io::Error::other("udp AEAD key init failed"))?;
    Ok(LessSafeKey::new(unbound))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpPacketKind {
    KeyOffer = 1,
    KeyReady = 2,
    Data = 3,
}

impl UdpPacketKind {
    fn decode(value: u8) -> io::Result<Self> {
        match value {
            1 => Ok(Self::KeyOffer),
            2 => Ok(Self::KeyReady),
            3 => Ok(Self::Data),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown udp packet kind",
            )),
        }
    }

    fn encode(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy)]
struct UdpPacketHeader {
    kind: UdpPacketKind,
    src: NodeIdentifier,
    dst: NodeIdentifier,
    seq: u64,
}

impl UdpPacketHeader {
    fn decode(packet: &[u8]) -> io::Result<Self> {
        if packet.len() < HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short udp packet",
            ));
        }
        if packet[..4] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad udp packet magic",
            ));
        }
        let src = u16::from_be_bytes([packet[4], packet[5]]);
        let dst = u16::from_be_bytes([packet[6], packet[7]]);
        let seq = u64::from_be_bytes([
            packet[8], packet[9], packet[10], packet[11], packet[12], packet[13], packet[14],
            packet[15],
        ]);
        let kind = UdpPacketKind::decode(packet[16])?;
        Ok(Self {
            kind,
            src,
            dst,
            seq,
        })
    }

    fn encode(self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&self.src.to_be_bytes());
        out[6..8].copy_from_slice(&self.dst.to_be_bytes());
        out[8..16].copy_from_slice(&self.seq.to_be_bytes());
        out[16] = self.kind.encode();
        out
    }
}

#[cfg(debug_assertions)]
fn udp_datagram_kind_name(kind: UdpPacketKind) -> &'static str {
    match kind {
        UdpPacketKind::KeyOffer => "transport.udp.datagram.key_offer",
        UdpPacketKind::KeyReady => "transport.udp.datagram.key_ready",
        UdpPacketKind::Data => "transport.udp.datagram.data",
    }
}

#[cfg(debug_assertions)]
fn udp_frame_kind_name(frame_type: i32) -> &'static str {
    match pb::FrameType::try_from(frame_type) {
        Ok(pb::FrameType::FrameData) => "transport.udp.frame.data",
        Ok(pb::FrameType::FramePing) => "transport.udp.frame.ping",
        Ok(pb::FrameType::FramePong) => "transport.udp.frame.pong",
        Ok(pb::FrameType::FrameKeepalive) => "transport.udp.frame.keepalive",
        Ok(pb::FrameType::FrameHello) => "transport.udp.frame.hello",
        Ok(pb::FrameType::FrameBye) => "transport.udp.frame.bye",
        Ok(pb::FrameType::FrameDictionary) => "transport.udp.frame.dictionary",
        Ok(pb::FrameType::FrameDictionaryAck) => "transport.udp.frame.dictionary_ack",
        Err(_) => "transport.udp.frame.unknown",
    }
}

fn packet_nonce(
    kind: UdpPacketKind,
    src: NodeIdentifier,
    dst: NodeIdentifier,
    seq: u64,
) -> io::Result<Nonce> {
    let mut nonce = [0u8; 12];
    nonce[..2].copy_from_slice(&src.to_be_bytes());
    nonce[2..4].copy_from_slice(&dst.to_be_bytes());
    let kind_domain = match kind {
        UdpPacketKind::Data => 0u64,
        UdpPacketKind::KeyReady => 1u64 << 62,
        UdpPacketKind::KeyOffer => 2u64 << 62,
    };
    let seq = kind_domain | (seq & 0x3fff_ffff_ffff_ffff);
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    Nonce::try_assume_unique_for_key(&nonce)
        .map_err(|_| io::Error::other("udp nonce construction failed"))
}

fn is_packet_too_large(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(40 | 90 | 10040))
}

#[derive(Default)]
struct ReplayWindow {
    max_seen: u64,
    seen: u128,
}

impl ReplayWindow {
    fn accept(&mut self, seq: u64) -> bool {
        if seq == 0 {
            return false;
        }
        if self.max_seen == 0 {
            self.max_seen = seq;
            self.seen = 1;
            return true;
        }
        if seq > self.max_seen {
            let shift = (seq - self.max_seen).min(128);
            self.seen = if shift == 128 {
                1
            } else {
                (self.seen << shift) | 1
            };
            self.max_seen = seq;
            return true;
        }
        let offset = self.max_seen - seq;
        if offset >= 128 {
            return false;
        }
        let bit = 1u128 << offset;
        if self.seen & bit != 0 {
            return false;
        }
        self.seen |= bit;
        true
    }
}

async fn run_socket_read_loop(
    state: Arc<UdpSocketState>,
    inner: Arc<ManagerInner>,
    identity: Arc<NodeIdentity>,
) {
    let buffer_size = udp_datagram_mtu_ceiling(inner.cfg().udp_mtu()).max(MAX_HANDSHAKE_DATAGRAM)
        + HEADER_LEN
        + TAG_LEN;
    let mut batch = RecvDatagramBatch::new(UDP_RECV_BATCH_MAX_DATAGRAMS, buffer_size);
    loop {
        tokio::select! {
            _ = inner.shutdown().cancelled() => {
                state.shutdown.cancel();
                return;
            }
            result = state.socket.recv_batch_from(&mut batch) => {
                match result {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error=%e, "udp encrypted socket read failed");
                        return;
                    }
                };
                for datagram in batch.iter() {
                    if inner.shutdown().is_cancelled() {
                        state.shutdown.cancel();
                        return;
                    }
                    let peer_addr = datagram.peer_addr();
                    if let Err(e) = handle_udp_datagram(
                        &state,
                        &inner,
                        &identity,
                        datagram.payload(),
                        peer_addr,
                    ).await {
                        if e.kind() != io::ErrorKind::AlreadyExists {
                            trace!(error=%e, %peer_addr, "ignored udp encrypted packet");
                        }
                    }
                }
            }
        }
    }
}

struct ExchangeRetransmitBatch {
    peer_node: NodeIdentifier,
    peer_addr: SocketAddr,
    packets: Vec<Vec<u8>>,
}

async fn run_exchange_retransmit_loop(state: Arc<UdpSocketState>, local_node: NodeIdentifier) {
    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => return,
            _ = state.exchange_retransmit.notified() => {}
        }

        loop {
            tokio::select! {
                _ = state.shutdown.cancelled() => return,
                _ = sleep(UDP_KEX_RETRANSMIT_INTERVAL) => {}
            }

            let (batches, keep_armed) = collect_exchange_retransmits(&state, local_node).await;
            for batch in batches {
                if let Err(e) =
                    send_exchange_packets(&state, batch.peer_node, batch.peer_addr, batch.packets)
                        .await
                {
                    debug!(
                        peer = %batch.peer_node,
                        peer_addr = %batch.peer_addr,
                        error = %e,
                        "udp key exchange retransmit failed"
                    );
                }
            }

            if !keep_armed {
                break;
            }
        }
    }
}

async fn collect_exchange_retransmits(
    state: &Arc<UdpSocketState>,
    local_node: NodeIdentifier,
) -> (Vec<ExchangeRetransmitBatch>, bool) {
    let now = Instant::now();
    let mut exchanges = state.exchanges.lock().await;
    let mut batches = Vec::new();
    let mut keep_armed = false;

    for (&peer_node, exchange) in exchanges.iter_mut() {
        let Some(peer_addr) = exchange_retransmit_addr(exchange) else {
            continue;
        };
        if !exchange_retransmit_active(exchange, now) {
            continue;
        }

        keep_armed = true;
        let packets = exchange_packets_due(exchange, now, local_node, peer_node);
        if !packets.is_empty() {
            batches.push(ExchangeRetransmitBatch {
                peer_node,
                peer_addr,
                packets,
            });
        }
    }

    let exhausted: Vec<_> = exchanges
        .iter()
        .filter_map(|(&peer_node, exchange)| {
            exchange_retransmit_exhausted(exchange, now).then_some(peer_node)
        })
        .collect();
    for peer_node in exhausted {
        if let Some(mut exchange) = exchanges.remove(&peer_node) {
            for waiter in std::mem::take(&mut exchange.waiters) {
                let _ = waiter.send(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "udp key exchange retransmit budget exhausted",
                )));
            }
            debug!(
                local = %local_node,
                peer = %peer_node,
                "removed exhausted udp key exchange"
            );
        }
    }

    (batches, keep_armed)
}

fn exchange_retransmit_addr(exchange: &PeerKeyExchange) -> Option<SocketAddr> {
    if exchange
        .candidate
        .as_ref()
        .is_some_and(|candidate| candidate.promoted)
    {
        return None;
    }
    exchange
        .candidate
        .as_ref()
        .map(|candidate| candidate.peer_addr)
        .or(exchange.peer_addr)
}

fn exchange_retransmit_active(exchange: &PeerKeyExchange, now: Instant) -> bool {
    if exchange
        .candidate
        .as_ref()
        .is_some_and(|candidate| candidate.promoted)
    {
        return false;
    }
    let offer_active =
        exchange.local.is_some() && exchange.send_budget.offer.should_tick_again(now);
    let ready_active =
        exchange.candidate.is_some() && exchange.send_budget.ready.should_tick_again(now);
    offer_active || ready_active
}

fn exchange_retransmit_exhausted(exchange: &PeerKeyExchange, now: Instant) -> bool {
    if exchange
        .candidate
        .as_ref()
        .is_some_and(|candidate| candidate.promoted)
    {
        return false;
    }

    let has_offer = exchange.local.is_some();
    let has_ready = exchange.candidate.is_some();
    if !has_offer && !has_ready {
        return false;
    }

    (!has_offer || exchange.send_budget.offer.is_exhausted(now))
        && (!has_ready || exchange.send_budget.ready.is_exhausted(now))
}

async fn handle_udp_datagram(
    state: &Arc<UdpSocketState>,
    inner: &Arc<ManagerInner>,
    identity: &Arc<NodeIdentity>,
    packet: &[u8],
    peer_addr: SocketAddr,
) -> io::Result<()> {
    let header = match UdpPacketHeader::decode(packet) {
        Ok(header) => {
            #[cfg(debug_assertions)]
            crate::debug_io::record_named_received(
                udp_datagram_kind_name(header.kind),
                packet.len(),
            );
            header
        }
        Err(error) => {
            #[cfg(debug_assertions)]
            crate::debug_io::record_named_received(
                "transport.udp.datagram.decode_error",
                packet.len(),
            );
            return Err(error);
        }
    };
    match header.kind {
        UdpPacketKind::KeyOffer => {
            return handle_key_offer(state, inner, identity, packet, header, peer_addr).await;
        }
        UdpPacketKind::KeyReady => {
            return handle_key_ready(state, inner, identity, packet, header, peer_addr).await;
        }
        UdpPacketKind::Data => {}
    }

    if header.dst != inner.self_id() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "udp packet addressed to another node",
        ));
    }
    if header.src == inner.self_id() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "udp self-loop rejected",
        ));
    }

    let (session, plaintext) = match state.session(header.src).await {
        Some(session) => {
            // Only a packet that successfully authenticates (AEAD open) may
            // migrate the session's destination address. Updating it before
            // decryption let an off-path attacker who knows the peer node id
            // redirect egress traffic by spoofing a single datagram.
            match session.decrypt_packet(packet, header) {
                Ok(plaintext) => {
                    session.update_addr(peer_addr);
                    (session, plaintext)
                }
                Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                    match decrypt_with_candidate_data(state, inner, packet, header, peer_addr)
                        .await?
                    {
                        Some(v) => v,
                        None => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }
        None => match decrypt_with_candidate_data(state, inner, packet, header, peer_addr).await? {
            Some(v) => v,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "udp data arrived before signed key exchange",
                ));
            }
        },
    };

    let mut fragment_input = plaintext;
    let plaintext = loop {
        match session.accept_fragment(fragment_input, inner.cfg().max_frame_bytes()) {
            UdpFragmentOutcome::Whole(next) if next.starts_with(&UDP_FRAGMENT_MAGIC) => {
                fragment_input = next;
            }
            UdpFragmentOutcome::Whole(next) => break next,
            UdpFragmentOutcome::Pending | UdpFragmentOutcome::Drop => return Ok(()),
        }
    };
    let decode_started_at = Instant::now();
    let decoded_frame = pb::Frame::decode(&plaintext[..]);
    record_transport_pipeline_stage(
        TransportKind::Udp,
        TransportPipelineStage::FrameDecode,
        decode_started_at.elapsed(),
    );
    let frame = decoded_frame.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    #[cfg(debug_assertions)]
    crate::debug_io::record_named_received(udp_frame_kind_name(frame.frame_type), packet.len());
    if frame.src_node != u32::from(header.src) || frame.dst_node != u32::from(inner.self_id()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "udp encrypted frame/header mismatch",
        ));
    }
    let peer = inner.get_or_create_peer(header.src);
    peer.metrics().record_recv(TransportKind::Udp, packet.len());
    let class = pb::MessageClass::try_from(frame.message_class)
        .map(MessageClass::from)
        .unwrap_or(MessageClass::Regular);
    record_transport_io_batch(
        peer.node_id(),
        TransportKind::Udp,
        TransportIoDirection::Ingress,
        1,
        packet.len(),
    );
    record_transport_io_frames(
        peer.node_id(),
        TransportKind::Udp,
        TransportIoDirection::Ingress,
        class,
        1,
    );
    handle_frame(
        frame,
        &session,
        inner.self_id(),
        &peer,
        inner.inbound(),
        TransportKind::Udp.service_level(),
        inner.cfg().max_frame_bytes(),
        inner.cfg().compression_config(),
        peer.udp_datagram_mtu(),
    )
    .await
}

async fn handle_key_offer(
    state: &Arc<UdpSocketState>,
    inner: &Arc<ManagerInner>,
    identity: &Arc<NodeIdentity>,
    packet: &[u8],
    header: UdpPacketHeader,
    peer_addr: SocketAddr,
) -> io::Result<()> {
    validate_exchange_header(header, inner.self_id())?;
    // A session already exists: ignore the offer. The address must not be
    // migrated from an unauthenticated handshake packet — the Data path
    // refreshes the peer address only after a successful AEAD open.
    if state.session(header.src).await.is_some() {
        return Ok(());
    }
    // Throttle the expensive verification (X.509 path build + signature
    // check) per source IP and across all sources, so spoofed handshake
    // floods cannot burn CPU (and IP rotation cannot bypass the per-IP
    // budget). The per-IP check runs first so a single-IP flood (already
    // rejected there) cannot drain the global budget for other peers.
    if !state.key_exchange_rate_limiter.try_acquire(&peer_addr.ip()) {
        tracing::debug!(
            source = %peer_addr,
            "S2S UDP key-exchange rate limit exceeded"
        );
        return Ok(());
    }
    let global_allowed = match state.key_exchange_global_budget.lock() {
        Ok(mut bucket) => bucket.try_acquire(),
        Err(poisoned) => poisoned.into_inner().try_acquire(),
    };
    if !global_allowed {
        tracing::debug!(
            source = %peer_addr,
            "S2S UDP key-exchange global rate limit exceeded"
        );
        return Ok(());
    }
    let offer = UdpHandshakeBody::decode(packet)?;
    verify_peer_identity(identity, &offer.cert_chain, header.src)?;

    let transcript = offer_transcript(header.src, header.dst, header.seq, &offer.ephemeral_public);
    verify_transcript_signature(
        &offer.cert_chain,
        offer.signature_scheme,
        &transcript,
        &offer.signature,
    )?;

    let peer_offer = PeerKeyOffer {
        offer_id: header.seq,
        public_key: offer.ephemeral_public,
    };
    let (packets, promote) = accept_peer_offer(
        state,
        identity,
        inner.self_id(),
        header.src,
        peer_addr,
        peer_offer,
    )
    .await?;

    send_exchange_packets(state, header.src, peer_addr, packets).await?;
    if let Some(promote) = promote {
        promote_exchange(inner, state, promote).await?;
    }
    Ok(())
}

async fn handle_key_ready(
    state: &Arc<UdpSocketState>,
    inner: &Arc<ManagerInner>,
    identity: &Arc<NodeIdentity>,
    packet: &[u8],
    header: UdpPacketHeader,
    peer_addr: SocketAddr,
) -> io::Result<()> {
    validate_exchange_header(header, inner.self_id())?;
    // A session already exists: ignore this KeyReady. The address must not be
    // migrated from an unauthenticated handshake packet.
    if state.session(header.src).await.is_some() {
        return Ok(());
    }
    // Throttle the expensive verification per source IP first, then against
    // the global budget (see handle_key_offer).
    if !state.key_exchange_rate_limiter.try_acquire(&peer_addr.ip()) {
        tracing::debug!(
            source = %peer_addr,
            "S2S UDP key-exchange rate limit exceeded"
        );
        return Ok(());
    }
    let global_allowed = match state.key_exchange_global_budget.lock() {
        Ok(mut bucket) => bucket.try_acquire(),
        Err(poisoned) => poisoned.into_inner().try_acquire(),
    };
    if !global_allowed {
        tracing::debug!(
            source = %peer_addr,
            "S2S UDP key-exchange global rate limit exceeded"
        );
        return Ok(());
    }
    let (packets, promote) = accept_key_ready(
        state,
        identity,
        inner.self_id(),
        header.src,
        peer_addr,
        packet,
        header,
    )
    .await?;
    send_exchange_packets(state, header.src, peer_addr, packets).await?;
    if let Some(promote) = promote {
        promote_exchange(inner, state, promote).await?;
    }
    Ok(())
}

fn validate_exchange_header(header: UdpPacketHeader, local_id: NodeIdentifier) -> io::Result<()> {
    if header.dst != local_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "udp key exchange addressed to another node",
        ));
    }
    if header.src == local_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "udp key exchange self-loop rejected",
        ));
    }
    if header.seq == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "udp key exchange id must be non-zero",
        ));
    }
    Ok(())
}

async fn start_key_exchange(
    inner: &Arc<ManagerInner>,
    identity: &NodeIdentity,
    state: Arc<UdpSocketState>,
    peer_node: NodeIdentifier,
    peer_addr: SocketAddr,
) -> io::Result<oneshot::Receiver<io::Result<()>>> {
    // A dial target may come from stale discovery state. Treat it as observed
    // only after the signed key exchange authenticates the peer.
    let peer = inner.get_or_create_peer(peer_node);

    if let Some(existing) = state.session(peer_node).await {
        existing.update_addr(peer_addr);
        install_active_stream(inner, &state, peer, existing, peer_addr, true);
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Ok(()));
        return Ok(rx);
    }

    let (tx, rx) = oneshot::channel();
    let packets = begin_symmetric_exchange(identity, &state, peer_node, peer_addr, tx).await?;
    send_exchange_packets(&state, peer_node, peer_addr, packets).await?;
    Ok(rx)
}

async fn install_session(
    inner: &Arc<ManagerInner>,
    state: &Arc<UdpSocketState>,
    peer_node: NodeIdentifier,
    peer_addr: SocketAddr,
    is_dialer: bool,
    seal_key: [u8; 32],
    open_key: [u8; 32],
    accepted_seq: Option<u64>,
) -> io::Result<Arc<UdpCryptoSession>> {
    let peer = inner.get_or_create_peer(peer_node);
    peer.note_udp_seen(peer_addr);
    let session = Arc::new(UdpCryptoSession::new(
        peer_node,
        peer_addr,
        state.socket.clone(),
        seal_key,
        open_key,
        inner.cfg().max_pending_pings(),
    )?);
    if let Some(seq) = accepted_seq {
        session.replay.lock().accept(seq);
    }
    state.insert_session(session.clone()).await;
    install_active_stream(inner, state, peer, session.clone(), peer_addr, is_dialer);
    Ok(session)
}

async fn begin_symmetric_exchange(
    identity: &NodeIdentity,
    state: &Arc<UdpSocketState>,
    peer_node: NodeIdentifier,
    peer_addr: SocketAddr,
    waiter: oneshot::Sender<io::Result<()>>,
) -> io::Result<Vec<Vec<u8>>> {
    let mut exchanges = state.exchanges.lock().await;
    let exchange = exchanges.entry(peer_node).or_default();
    exchange.peer_addr = Some(peer_addr);
    exchange.local_initiated = true;
    exchange.waiters.push(waiter);
    ensure_local_offer(exchange, identity, peer_node)?;
    let packets = exchange_packets_due(exchange, Instant::now(), identity.node_id(), peer_node);
    state.notify_exchange_retransmit();
    Ok(packets)
}

async fn accept_peer_offer(
    state: &Arc<UdpSocketState>,
    identity: &NodeIdentity,
    local_node: NodeIdentifier,
    peer_node: NodeIdentifier,
    peer_addr: SocketAddr,
    peer_offer: PeerKeyOffer,
) -> io::Result<(Vec<Vec<u8>>, Option<PromoteSession>)> {
    let mut exchanges = state.exchanges.lock().await;
    let exchange = exchanges.entry(peer_node).or_default();
    exchange.peer_addr = Some(peer_addr);
    ensure_local_offer(exchange, identity, peer_node)?;

    let offer_changed = exchange
        .peer
        .as_ref()
        .is_none_or(|existing| !existing.matches(&peer_offer));
    if offer_changed {
        if should_defer_higher_peer_offer(exchange, local_node, peer_node) {
            debug!(
                local = %local_node,
                peer = %peer_node,
                "deferring changed udp key offer from higher peer while current exchange is active"
            );
            let packets = exchange_packets_due(exchange, Instant::now(), local_node, peer_node);
            let promote = promote_if_ready(exchange, local_node, peer_node);
            if promote.is_none() {
                state.notify_exchange_retransmit();
            }
            return Ok((packets, promote));
        }
        if exchange
            .local
            .as_ref()
            .is_none_or(|local| local.private_key.is_none())
        {
            replace_local_offer(exchange, identity, peer_node)?;
        }
        exchange.peer = Some(peer_offer);
        match derive_candidate(exchange, local_node, peer_node, peer_addr) {
            Ok(candidate) => {
                exchange.candidate = Some(candidate);
                exchange.send_budget.ready.reset();
            }
            Err(e) => {
                exchange.local = None;
                exchange.peer = None;
                exchange.candidate = None;
                exchange.send_budget = ExchangeSendBudget::default();
                return Err(e);
            }
        }
        accept_buffered_ready(exchange, local_node, peer_node);
    } else if let Some(candidate) = exchange.candidate.as_mut() {
        candidate.peer_addr = peer_addr;
    }

    let packets = exchange_packets_due(exchange, Instant::now(), local_node, peer_node);
    let promote = promote_if_ready(exchange, local_node, peer_node);
    if promote.is_none() {
        state.notify_exchange_retransmit();
    }
    Ok((packets, promote))
}

async fn accept_key_ready(
    state: &Arc<UdpSocketState>,
    identity: &NodeIdentity,
    local_node: NodeIdentifier,
    peer_node: NodeIdentifier,
    peer_addr: SocketAddr,
    packet: &[u8],
    header: UdpPacketHeader,
) -> io::Result<(Vec<Vec<u8>>, Option<PromoteSession>)> {
    let mut exchanges = state.exchanges.lock().await;
    let exchange = exchanges.entry(peer_node).or_default();
    let now = Instant::now();
    let Some((exchange_id, candidate_peer_addr)) = exchange
        .candidate
        .as_ref()
        .map(|candidate| (candidate.exchange_id, candidate.peer_addr))
    else {
        let buffered = buffer_early_ready(exchange, packet);
        if let Some(suppressed) = exchange.stale_ready.log.record(now) {
            debug!(
                local = %local_node,
                peer = %peer_node,
                received_exchange_id = header.seq,
                buffered,
                suppressed,
                "buffering udp key ready before a candidate exists"
            );
        }
        if !buffered {
            return Ok((Vec::new(), None));
        }
        let packets = exchange_packets_due(exchange, now, local_node, peer_node);
        state.notify_exchange_retransmit();
        return Ok((packets, None));
    };

    if exchange_id != header.seq {
        let source_matches = candidate_peer_addr == peer_addr;
        let restart_allowed =
            local_node < peer_node && exchange.stale_ready.take_restart(source_matches);
        if restart_allowed {
            restart_lower_node_exchange(exchange, identity, peer_node)?;
            let suppressed = exchange.stale_ready.log.force(now);
            debug!(
                local = %local_node,
                peer = %peer_node,
                previous_exchange_id = exchange_id,
                received_exchange_id = header.seq,
                suppressed,
                "restarting udp key exchange after stale key ready"
            );
            let packets = exchange_packets_due(exchange, now, local_node, peer_node);
            state.notify_exchange_retransmit();
            return Ok((packets, None));
        }
        let buffered = if local_node > peer_node && source_matches {
            buffer_early_ready(exchange, packet)
        } else {
            false
        };
        if let Some(suppressed) = exchange.stale_ready.log.record(now) {
            debug!(
                local = %local_node,
                peer = %peer_node,
                expected_exchange_id = exchange_id,
                received_exchange_id = header.seq,
                source_matches,
                restart_rate_limited = local_node < peer_node && source_matches,
                buffered,
                suppressed,
                "ignoring udp key ready for a stale exchange"
            );
        }
        return Ok((Vec::new(), None));
    }

    accept_ready_packet(exchange, local_node, peer_node, packet, header)?;
    if let Some(candidate) = exchange.candidate.as_mut() {
        candidate.peer_addr = peer_addr;
    }
    let packets = exchange_packets_due(exchange, Instant::now(), local_node, peer_node);
    let promote = promote_if_ready(exchange, local_node, peer_node);
    if promote.is_none() {
        state.notify_exchange_retransmit();
    }
    Ok((packets, promote))
}

fn buffer_early_ready(exchange: &mut PeerKeyExchange, packet: &[u8]) -> bool {
    let duplicate = exchange
        .early_ready
        .iter()
        .any(|buffered| buffered.as_slice() == packet);
    if duplicate || exchange.early_ready.len() >= 4 {
        return false;
    }
    exchange.early_ready.push(packet.to_vec());
    true
}

async fn decrypt_with_candidate_data(
    state: &Arc<UdpSocketState>,
    inner: &Arc<ManagerInner>,
    packet: &[u8],
    header: UdpPacketHeader,
    peer_addr: SocketAddr,
) -> io::Result<Option<(Arc<UdpCryptoSession>, Vec<u8>)>> {
    let (plaintext, packets, promote) = {
        let mut exchanges = state.exchanges.lock().await;
        let Some(exchange) = exchanges.get_mut(&header.src) else {
            return Ok(None);
        };
        let Some(candidate) = exchange.candidate.as_mut() else {
            return Ok(None);
        };
        let plaintext = match decrypt_packet_with_key(&candidate.open_key, packet, header) {
            Ok(plaintext) => plaintext,
            Err(_) => return Ok(None),
        };
        // Only a successfully decrypted packet may pin the exchange's peer
        // address (retransmit destination).
        exchange.peer_addr = Some(peer_addr);
        candidate.ready_received = true;
        candidate.peer_addr = peer_addr;
        let packets = exchange_packets_due(exchange, Instant::now(), inner.self_id(), header.src);
        let promote = promote_if_ready(exchange, inner.self_id(), header.src);
        (plaintext, packets, promote)
    };

    send_exchange_packets(state, header.src, peer_addr, packets).await?;
    let Some(mut promote) = promote else {
        return Ok(None);
    };
    promote.accepted_seq = Some(header.seq);
    let session = promote_exchange(inner, state, promote).await?;
    Ok(Some((session, plaintext)))
}

fn ensure_local_offer(
    exchange: &mut PeerKeyExchange,
    identity: &NodeIdentity,
    peer_node: NodeIdentifier,
) -> io::Result<()> {
    let needs_offer = exchange.local.is_none()
        || (exchange.candidate.is_none()
            && exchange
                .local
                .as_ref()
                .is_some_and(|local| local.private_key.is_none()));
    if needs_offer {
        replace_local_offer(exchange, identity, peer_node)?;
    }
    Ok(())
}

fn replace_local_offer(
    exchange: &mut PeerKeyExchange,
    identity: &NodeIdentity,
    peer_node: NodeIdentifier,
) -> io::Result<()> {
    exchange.local = Some(new_local_offer(identity, peer_node)?);
    exchange.send_budget.offer.reset();
    exchange.send_budget.ready.reset();
    Ok(())
}

fn restart_lower_node_exchange(
    exchange: &mut PeerKeyExchange,
    identity: &NodeIdentity,
    peer_node: NodeIdentifier,
) -> io::Result<()> {
    exchange.peer = None;
    exchange.candidate = None;
    exchange.early_ready.clear();
    exchange.local_initiated = true;
    replace_local_offer(exchange, identity, peer_node)
}

fn should_defer_higher_peer_offer(
    exchange: &PeerKeyExchange,
    local_node: NodeIdentifier,
    peer_node: NodeIdentifier,
) -> bool {
    local_node < peer_node
        && exchange
            .candidate
            .as_ref()
            .is_some_and(|candidate| !candidate.promoted)
}

fn new_local_offer(
    identity: &NodeIdentity,
    peer_node: NodeIdentifier,
) -> io::Result<LocalKeyOffer> {
    let (private_key, public_key) = generate_ephemeral_keypair()?;
    let offer_id = rand::random::<u64>().max(1);
    let packet = build_key_offer(identity, peer_node, offer_id, &public_key)?;
    Ok(LocalKeyOffer {
        offer_id,
        private_key: Some(private_key),
        public_key,
        packet,
    })
}

fn derive_candidate(
    exchange: &mut PeerKeyExchange,
    local_node: NodeIdentifier,
    peer_node: NodeIdentifier,
    peer_addr: SocketAddr,
) -> io::Result<KeyCandidate> {
    let local = exchange
        .local
        .as_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing local udp key offer"))?;
    let peer = exchange
        .peer
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing peer udp key offer"))?;
    let private_key = local.private_key.take().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "udp local key offer was already consumed",
        )
    })?;
    let ordered = ordered_offer_material(local_node, peer_node, local, peer);
    let exchange_id = exchange_id(&ordered);
    let keys = derive_key_material(private_key, &peer.public_key, &ordered)?;
    let (seal_key, open_key) = if local_node < peer_node {
        (keys.low_to_high, keys.high_to_low)
    } else {
        (keys.high_to_low, keys.low_to_high)
    };
    let ready_packet = build_key_ready(
        local_node,
        peer_node,
        exchange_id,
        local.offer_id,
        peer.offer_id,
        &seal_key,
    )?;
    Ok(KeyCandidate {
        exchange_id,
        peer_addr,
        seal_key,
        open_key,
        ready_packet,
        ready_received: false,
        promoted: false,
    })
}

fn accept_buffered_ready(
    exchange: &mut PeerKeyExchange,
    local_node: NodeIdentifier,
    peer_node: NodeIdentifier,
) {
    let early = std::mem::take(&mut exchange.early_ready);
    for packet in early {
        let Ok(header) = UdpPacketHeader::decode(&packet) else {
            continue;
        };
        if header.kind != UdpPacketKind::KeyReady
            || header.src != peer_node
            || header.dst != local_node
        {
            continue;
        }
        let _ = accept_ready_packet(exchange, local_node, peer_node, &packet, header);
    }
}

fn accept_ready_packet(
    exchange: &mut PeerKeyExchange,
    local_node: NodeIdentifier,
    peer_node: NodeIdentifier,
    packet: &[u8],
    header: UdpPacketHeader,
) -> io::Result<()> {
    let local = exchange
        .local
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing local udp key offer"))?;
    let peer = exchange
        .peer
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing peer udp key offer"))?;
    let candidate = exchange
        .candidate
        .as_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing udp key candidate"))?;
    open_key_ready(
        &candidate.open_key,
        packet,
        header,
        peer_node,
        local_node,
        candidate.exchange_id,
        peer.offer_id,
        local.offer_id,
    )?;
    candidate.ready_received = true;
    Ok(())
}

fn exchange_packets_due(
    exchange: &mut PeerKeyExchange,
    now: Instant,
    local_node: NodeIdentifier,
    peer_node: NodeIdentifier,
) -> Vec<Vec<u8>> {
    if exchange
        .candidate
        .as_ref()
        .is_some_and(|candidate| candidate.promoted)
    {
        return Vec::new();
    }
    let mut packets = Vec::new();
    if let Some(local) = &exchange.local {
        if exchange.send_budget.offer.should_send(
            now,
            local_node,
            peer_node,
            UdpPacketKind::KeyOffer,
            local.offer_id,
        ) {
            packets.push(local.packet.clone());
        }
    }
    if let Some(candidate) = &exchange.candidate {
        if exchange.send_budget.ready.should_send(
            now,
            local_node,
            peer_node,
            UdpPacketKind::KeyReady,
            candidate.exchange_id,
        ) {
            packets.push(candidate.ready_packet.clone());
        }
    }
    packets
}

impl HandshakePacketBudget {
    fn reset(&mut self) {
        *self = Self::default();
    }

    fn should_tick_again(&self, now: Instant) -> bool {
        let Some(first_sent) = self.first_sent else {
            return true;
        };
        let age = now.saturating_duration_since(first_sent);
        (age < UDP_KEX_MAX_RETRANSMIT_AGE && self.retransmits < UDP_KEX_MAX_RETRANSMITS)
            || !self.exhausted_logged
    }

    fn is_exhausted(&self, now: Instant) -> bool {
        let Some(first_sent) = self.first_sent else {
            return false;
        };
        self.exhausted_logged
            && (now.saturating_duration_since(first_sent) >= UDP_KEX_MAX_RETRANSMIT_AGE
                || self.retransmits >= UDP_KEX_MAX_RETRANSMITS)
    }

    fn should_send(
        &mut self,
        now: Instant,
        local_node: NodeIdentifier,
        peer_node: NodeIdentifier,
        kind: UdpPacketKind,
        seq: u64,
    ) -> bool {
        let Some(first_sent) = self.first_sent else {
            self.first_sent = Some(now);
            self.last_sent = Some(now);
            self.retransmits = 0;
            return true;
        };

        let age = now.saturating_duration_since(first_sent);
        if age >= UDP_KEX_MAX_RETRANSMIT_AGE || self.retransmits >= UDP_KEX_MAX_RETRANSMITS {
            if !self.exhausted_logged {
                self.exhausted_logged = true;
                debug!(
                    local = %local_node,
                    peer = %peer_node,
                    kind = ?kind,
                    seq,
                    age_ms = age.as_millis(),
                    attempts = self.retransmits,
                    "udp key exchange retransmit budget exhausted"
                );
            }
            return false;
        }

        let last_sent = self.last_sent.unwrap_or(first_sent);
        let delay = kex_retransmit_delay(kind, local_node, peer_node, seq, self.retransmits);
        if now.saturating_duration_since(last_sent) < delay {
            return false;
        }

        self.last_sent = Some(now);
        self.retransmits += 1;
        true
    }
}

fn kex_retransmit_delay(
    kind: UdpPacketKind,
    local_node: NodeIdentifier,
    peer_node: NodeIdentifier,
    seq: u64,
    retransmits: u32,
) -> Duration {
    let shift = retransmits.min(30);
    let factor = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
    let base = UDP_KEX_RETRANSMIT_INTERVAL
        .saturating_mul(factor)
        .min(UDP_KEX_RETRANSMIT_MAX_INTERVAL);
    let jitter_window = duration_div(base, UDP_KEX_RETRANSMIT_JITTER_DIVISOR);
    if jitter_window.is_zero() || base >= UDP_KEX_RETRANSMIT_MAX_INTERVAL {
        return base;
    }

    base.saturating_add(kex_retransmit_jitter(
        jitter_window,
        kind,
        local_node,
        peer_node,
        seq,
        retransmits,
    ))
    .min(UDP_KEX_RETRANSMIT_MAX_INTERVAL)
}

fn kex_retransmit_jitter(
    window: Duration,
    kind: UdpPacketKind,
    local_node: NodeIdentifier,
    peer_node: NodeIdentifier,
    seq: u64,
    retransmits: u32,
) -> Duration {
    let window_nanos = window.as_nanos().min(u128::from(u64::MAX)) as u64;
    if window_nanos == 0 {
        return Duration::ZERO;
    }
    let mut value = seq
        ^ (u64::from(local_node) << 48)
        ^ (u64::from(peer_node) << 32)
        ^ (u64::from(retransmits) << 16)
        ^ match kind {
            UdpPacketKind::Data => 0x9e37,
            UdpPacketKind::KeyOffer => 0xbf58,
            UdpPacketKind::KeyReady => 0x94d0,
        };
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^= value >> 31;
    Duration::from_nanos(value % window_nanos)
}

fn duration_div(duration: Duration, divisor: u32) -> Duration {
    if divisor == 0 {
        return duration;
    }
    let nanos = duration.as_nanos() / u128::from(divisor);
    Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
}

fn promote_if_ready(
    exchange: &mut PeerKeyExchange,
    local_node: NodeIdentifier,
    peer_node: NodeIdentifier,
) -> Option<PromoteSession> {
    let candidate = exchange.candidate.as_mut()?;
    if !candidate.ready_received || candidate.promoted {
        return None;
    }
    candidate.promoted = true;
    let promote = PromoteSession {
        peer_node,
        peer_addr: candidate.peer_addr,
        is_dialer: exchange.local_initiated,
        seal_key: candidate.seal_key,
        open_key: candidate.open_key,
        accepted_seq: None,
        waiters: std::mem::take(&mut exchange.waiters),
    };
    trace!(
        peer = %peer_node,
        local = %local_node,
        exchange_id = candidate.exchange_id,
        "udp symmetric key exchange ready"
    );
    Some(promote)
}

async fn send_exchange_packets(
    state: &Arc<UdpSocketState>,
    peer_node: NodeIdentifier,
    peer_addr: SocketAddr,
    packets: Vec<Vec<u8>>,
) -> io::Result<()> {
    for packet in packets {
        let _n = state
            .socket
            .send_to(&packet, peer_addr)
            .await
            .map_err(|e| io::Error::other(format!("udp key exchange send to {peer_node}: {e}")))?;
        #[cfg(debug_assertions)]
        match UdpPacketHeader::decode(&packet) {
            Ok(header) => {
                crate::debug_io::record_named_sent(udp_datagram_kind_name(header.kind), _n);
            }
            Err(_) => {
                crate::debug_io::record_named_sent("transport.udp.datagram.encode_error", _n);
            }
        }
    }
    Ok(())
}

async fn promote_exchange(
    inner: &Arc<ManagerInner>,
    state: &Arc<UdpSocketState>,
    promote: PromoteSession,
) -> io::Result<Arc<UdpCryptoSession>> {
    let PromoteSession {
        peer_node,
        peer_addr,
        is_dialer,
        seal_key,
        open_key,
        accepted_seq,
        waiters,
    } = promote;
    let result = install_session(
        inner,
        state,
        peer_node,
        peer_addr,
        is_dialer,
        seal_key,
        open_key,
        accepted_seq,
    )
    .await;
    let completion_result = result
        .as_ref()
        .map(|_| ())
        .map_err(|e| io::Error::new(e.kind(), e.to_string()));
    for tx in waiters {
        let _ = tx.send(
            completion_result
                .as_ref()
                .map(|_| ())
                .map_err(|e| io::Error::new(e.kind(), format!("udp key exchange failed: {e}"))),
        );
    }
    result
}

#[derive(Debug)]
struct UdpHandshakeBody {
    ephemeral_public: Vec<u8>,
    cert_chain: Vec<CertificateDer<'static>>,
    signature_scheme: u16,
    signature: Vec<u8>,
}

impl UdpHandshakeBody {
    fn encode(&self, header: UdpPacketHeader) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(HEADER_LEN + 256 + self.signature.len());
        out.extend_from_slice(&header.encode());
        put_vec_u16(&mut out, &self.ephemeral_public)?;
        put_u16(&mut out, self.cert_chain.len())?;
        for cert in &self.cert_chain {
            put_vec_u16(&mut out, cert.as_ref())?;
        }
        out.extend_from_slice(&self.signature_scheme.to_be_bytes());
        put_vec_u16(&mut out, &self.signature)?;
        Ok(out)
    }

    fn decode(packet: &[u8]) -> io::Result<Self> {
        let mut reader = PacketReader::new(
            packet
                .get(HEADER_LEN..)
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "short udp packet"))?,
        );
        let ephemeral_public = reader.read_vec_u16()?;
        if ephemeral_public.len() != X25519_PUBLIC_KEY_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad udp ephemeral public key length",
            ));
        }
        let cert_count = reader.read_u16()? as usize;
        if cert_count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "udp handshake missing certificate chain",
            ));
        }
        let mut cert_chain = Vec::with_capacity(cert_count);
        for _ in 0..cert_count {
            cert_chain.push(CertificateDer::from(reader.read_vec_u16()?));
        }
        let signature_scheme = reader.read_u16()?;
        let signature = reader.read_vec_u16()?;
        if signature.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "udp handshake missing signature",
            ));
        }
        reader.finish()?;
        Ok(Self {
            ephemeral_public,
            cert_chain,
            signature_scheme,
            signature,
        })
    }
}

struct PacketReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> PacketReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn read_u16(&mut self) -> io::Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_vec_u16(&mut self) -> io::Result<Vec<u8>> {
        let len = self.read_u16()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn finish(&self) -> io::Result<()> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing bytes in udp handshake",
            ))
        }
    }

    fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let end = self.offset.checked_add(len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "udp handshake length overflow")
        })?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "short udp handshake"))?;
        self.offset = end;
        Ok(bytes)
    }
}

fn put_u16(out: &mut Vec<u8>, value: usize) -> io::Result<()> {
    let value = u16::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "udp handshake field exceeds u16 length",
        )
    })?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn put_vec_u16(out: &mut Vec<u8>, value: &[u8]) -> io::Result<()> {
    put_u16(out, value.len())?;
    out.extend_from_slice(value);
    Ok(())
}

fn build_key_offer(
    identity: &NodeIdentity,
    peer_node: NodeIdentifier,
    offer_id: u64,
    public_key: &[u8],
) -> io::Result<Vec<u8>> {
    let transcript = offer_transcript(identity.node_id(), peer_node, offer_id, public_key);
    let signed = sign_transcript(identity, &transcript)?;
    let body = UdpHandshakeBody {
        ephemeral_public: public_key.to_vec(),
        cert_chain: identity.chain().to_vec(),
        signature_scheme: signed.scheme,
        signature: signed.signature,
    };
    body.encode(UdpPacketHeader {
        kind: UdpPacketKind::KeyOffer,
        src: identity.node_id(),
        dst: peer_node,
        seq: offer_id,
    })
}

fn build_key_ready(
    local_node: NodeIdentifier,
    peer_node: NodeIdentifier,
    exchange_id: u64,
    local_offer_id: u64,
    peer_offer_id: u64,
    seal_key: &[u8; 32],
) -> io::Result<Vec<u8>> {
    let header = UdpPacketHeader {
        kind: UdpPacketKind::KeyReady,
        src: local_node,
        dst: peer_node,
        seq: exchange_id,
    };
    let header_bytes = header.encode();
    let mut plaintext = ready_plaintext(
        local_node,
        peer_node,
        exchange_id,
        local_offer_id,
        peer_offer_id,
    );
    let key = aead_key(seal_key)?;
    let nonce = packet_nonce(header.kind, header.src, header.dst, header.seq)?;
    key.seal_in_place_append_tag(nonce, Aad::from(header_bytes), &mut plaintext)
        .map_err(|_| io::Error::other("udp key ready encryption failed"))?;
    let mut packet = Vec::with_capacity(HEADER_LEN + plaintext.len());
    packet.extend_from_slice(&header_bytes);
    packet.extend_from_slice(&plaintext);
    Ok(packet)
}

fn open_key_ready(
    open_key: &[u8; 32],
    packet: &[u8],
    header: UdpPacketHeader,
    expected_src: NodeIdentifier,
    expected_dst: NodeIdentifier,
    expected_exchange_id: u64,
    expected_sender_offer_id: u64,
    expected_receiver_offer_id: u64,
) -> io::Result<()> {
    if header.kind != UdpPacketKind::KeyReady
        || header.src != expected_src
        || header.dst != expected_dst
        || header.seq != expected_exchange_id
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "udp key ready header mismatch",
        ));
    }
    let plaintext = decrypt_packet_with_key(open_key, packet, header)?;
    let expected = ready_plaintext(
        expected_src,
        expected_dst,
        expected_exchange_id,
        expected_sender_offer_id,
        expected_receiver_offer_id,
    );
    if plaintext != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "udp key ready transcript mismatch",
        ));
    }
    Ok(())
}

fn ready_plaintext(
    src: NodeIdentifier,
    dst: NodeIdentifier,
    exchange_id: u64,
    sender_offer_id: u64,
    receiver_offer_id: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(KEX_TRANSCRIPT_DOMAIN);
    out.extend_from_slice(b":ready:");
    out.extend_from_slice(&src.to_be_bytes());
    out.extend_from_slice(&dst.to_be_bytes());
    out.extend_from_slice(&exchange_id.to_be_bytes());
    out.extend_from_slice(&sender_offer_id.to_be_bytes());
    out.extend_from_slice(&receiver_offer_id.to_be_bytes());
    out
}

fn decrypt_packet_with_key(
    open_key: &[u8; 32],
    packet: &[u8],
    header: UdpPacketHeader,
) -> io::Result<Vec<u8>> {
    if packet.len() < HEADER_LEN + TAG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short udp encrypted packet",
        ));
    }
    let key = aead_key(open_key)?;
    let mut ciphertext = packet[HEADER_LEN..].to_vec();
    let nonce = packet_nonce(header.kind, header.src, header.dst, header.seq)?;
    let decrypt_started_at = Instant::now();
    let decrypt_result = key
        .open_in_place(nonce, Aad::from(&packet[..HEADER_LEN]), &mut ciphertext)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "udp decrypt failed"));
    record_transport_pipeline_stage(
        TransportKind::Udp,
        TransportPipelineStage::UdpDecrypt,
        decrypt_started_at.elapsed(),
    );
    let plaintext = decrypt_result?;
    Ok(plaintext.to_vec())
}

struct SignedTranscript {
    scheme: u16,
    signature: Vec<u8>,
}

fn sign_transcript(identity: &NodeIdentity, transcript: &[u8]) -> io::Result<SignedTranscript> {
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(identity.key())
        .map_err(|e| io::Error::other(format!("udp signing key: {e}")))?;
    let signer = signing_key
        .choose_scheme(SUPPORTED_SIGNATURE_SCHEMES)
        .ok_or_else(|| io::Error::other("udp signing key has no supported signature scheme"))?;
    let scheme = signature_scheme_code(signer.scheme())?;
    let signature = signer
        .sign(transcript)
        .map_err(|e| io::Error::other(format!("udp transcript sign: {e}")))?;
    Ok(SignedTranscript { scheme, signature })
}

fn verify_peer_identity(
    identity: &NodeIdentity,
    chain: &[CertificateDer<'static>],
    expected_node: NodeIdentifier,
) -> io::Result<()> {
    tls::verify_peer_cert_chain(identity.roots().clone(), chain).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("udp peer certificate chain: {e}"),
        )
    })?;
    let node = parse_peer_cn(chain).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("udp peer certificate identity: {e}"),
        )
    })?;
    if node != expected_node {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("udp certificate CN {node} did not match packet source {expected_node}"),
        ));
    }
    Ok(())
}

fn verify_transcript_signature(
    chain: &[CertificateDer<'static>],
    scheme: u16,
    transcript: &[u8],
    sig: &[u8],
) -> io::Result<()> {
    let leaf = chain.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "udp handshake missing certificate leaf",
        )
    })?;
    let (_, parsed) = X509Certificate::from_der(leaf.as_ref()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("udp peer certificate parse: {e}"),
        )
    })?;
    let alg = signature_verification_algorithm(scheme)?;
    let public_key = &parsed.tbs_certificate.subject_pki.subject_public_key.data;
    signature::UnparsedPublicKey::new(alg, public_key)
        .verify(transcript, sig)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad udp handshake signature"))
}

fn signature_scheme_code(scheme: SignatureScheme) -> io::Result<u16> {
    match scheme {
        SignatureScheme::RSA_PKCS1_SHA256 => Ok(0x0401),
        SignatureScheme::ECDSA_NISTP256_SHA256 => Ok(0x0403),
        SignatureScheme::ECDSA_NISTP384_SHA384 => Ok(0x0503),
        SignatureScheme::ECDSA_NISTP521_SHA512 => Ok(0x0603),
        SignatureScheme::RSA_PSS_SHA256 => Ok(0x0804),
        SignatureScheme::ED25519 => Ok(0x0807),
        _ => Err(io::Error::other("unsupported udp signature scheme")),
    }
}

fn signature_verification_algorithm(
    scheme: u16,
) -> io::Result<&'static dyn signature::VerificationAlgorithm> {
    match scheme {
        0x0401 => Ok(&signature::RSA_PKCS1_2048_8192_SHA256),
        0x0403 => Ok(&signature::ECDSA_P256_SHA256_ASN1),
        0x0503 => Ok(&signature::ECDSA_P384_SHA384_ASN1),
        0x0603 => Ok(&signature::ECDSA_P521_SHA512_ASN1),
        0x0804 => Ok(&signature::RSA_PSS_2048_8192_SHA256),
        0x0807 => Ok(&signature::ED25519),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported udp signature scheme",
        )),
    }
}

fn offer_transcript(
    src_node: NodeIdentifier,
    dst_node: NodeIdentifier,
    offer_id: u64,
    public_key: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + public_key.len());
    out.extend_from_slice(KEX_TRANSCRIPT_DOMAIN);
    out.extend_from_slice(b":offer:");
    out.extend_from_slice(&src_node.to_be_bytes());
    out.extend_from_slice(&dst_node.to_be_bytes());
    out.extend_from_slice(&offer_id.to_be_bytes());
    out.extend_from_slice(public_key);
    out
}

fn generate_ephemeral_keypair() -> io::Result<(agreement::EphemeralPrivateKey, Vec<u8>)> {
    let rng = SystemRandom::new();
    let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
        .map_err(|_| io::Error::other("udp ephemeral key generation failed"))?;
    let public_key = private_key
        .compute_public_key()
        .map_err(|_| io::Error::other("udp ephemeral public key failed"))?
        .as_ref()
        .to_vec();
    Ok((private_key, public_key))
}

struct DirectionalKeys {
    low_to_high: [u8; 32],
    high_to_low: [u8; 32],
}

struct OrderedOfferMaterial<'a> {
    low_node: NodeIdentifier,
    high_node: NodeIdentifier,
    low_offer_id: u64,
    high_offer_id: u64,
    low_public_key: &'a [u8],
    high_public_key: &'a [u8],
}

fn ordered_offer_material<'a>(
    local_node: NodeIdentifier,
    peer_node: NodeIdentifier,
    local: &'a LocalKeyOffer,
    peer: &'a PeerKeyOffer,
) -> OrderedOfferMaterial<'a> {
    if local_node < peer_node {
        OrderedOfferMaterial {
            low_node: local_node,
            high_node: peer_node,
            low_offer_id: local.offer_id,
            high_offer_id: peer.offer_id,
            low_public_key: &local.public_key,
            high_public_key: &peer.public_key,
        }
    } else {
        OrderedOfferMaterial {
            low_node: peer_node,
            high_node: local_node,
            low_offer_id: peer.offer_id,
            high_offer_id: local.offer_id,
            low_public_key: &peer.public_key,
            high_public_key: &local.public_key,
        }
    }
}

fn exchange_id(ordered: &OrderedOfferMaterial<'_>) -> u64 {
    let salt = key_schedule_salt(ordered);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&salt[..8]);
    u64::from_be_bytes(bytes).max(1)
}

struct UdpKeyMaterialLen;

impl hkdf::KeyType for UdpKeyMaterialLen {
    fn len(&self) -> usize {
        64
    }
}

fn derive_key_material(
    private_key: agreement::EphemeralPrivateKey,
    peer_public_key: &[u8],
    ordered: &OrderedOfferMaterial<'_>,
) -> io::Result<DirectionalKeys> {
    if peer_public_key.len() != X25519_PUBLIC_KEY_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad udp peer ephemeral public key length",
        ));
    }
    let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public_key);
    agreement::agree_ephemeral(
        private_key,
        &peer_public_key,
        io::Error::new(io::ErrorKind::InvalidData, "bad udp peer ephemeral key"),
        |secret| {
            let salt_bytes = key_schedule_salt(ordered);
            let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt_bytes);
            let prk = salt.extract(secret);
            let info = [KEX_KEY_INFO];
            let okm = prk
                .expand(&info, UdpKeyMaterialLen)
                .map_err(|_| io::Error::other("udp key expansion failed"))?;
            let mut out = [0u8; 64];
            okm.fill(&mut out)
                .map_err(|_| io::Error::other("udp key material fill failed"))?;
            let mut low_to_high = [0u8; 32];
            let mut high_to_low = [0u8; 32];
            low_to_high.copy_from_slice(&out[..32]);
            high_to_low.copy_from_slice(&out[32..]);
            Ok(DirectionalKeys {
                low_to_high,
                high_to_low,
            })
        },
    )
}

fn key_schedule_salt(ordered: &OrderedOfferMaterial<'_>) -> [u8; 32] {
    let mut input =
        Vec::with_capacity(112 + ordered.low_public_key.len() + ordered.high_public_key.len());
    input.extend_from_slice(KEX_TRANSCRIPT_DOMAIN);
    input.extend_from_slice(b":keys:");
    input.extend_from_slice(&ordered.low_node.to_be_bytes());
    input.extend_from_slice(&ordered.high_node.to_be_bytes());
    input.extend_from_slice(&ordered.low_offer_id.to_be_bytes());
    input.extend_from_slice(&ordered.high_offer_id.to_be_bytes());
    input.extend_from_slice(ordered.low_public_key);
    input.extend_from_slice(ordered.high_public_key);
    let digest = digest::digest(&digest::SHA256, &input);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

fn install_active_stream(
    inner: &Arc<ManagerInner>,
    state: &Arc<UdpSocketState>,
    peer: Arc<PeerState>,
    session: Arc<UdpCryptoSession>,
    peer_addr: SocketAddr,
    is_dialer: bool,
) {
    if inner.shutdown().is_cancelled() {
        return;
    }

    let active = spawn_udp_write_pump(
        state.clone(),
        session,
        peer.clone(),
        inner.clone(),
        peer_addr,
        is_dialer,
    );
    if inner.shutdown().is_cancelled() {
        active.cancel();
        return;
    }
    peer.install_stream(active);
}

fn spawn_udp_write_pump(
    state: Arc<UdpSocketState>,
    session: Arc<UdpCryptoSession>,
    peer: Arc<PeerState>,
    inner: Arc<ManagerInner>,
    peer_addr: SocketAddr,
    is_dialer: bool,
) -> ActiveStream {
    // The UDP data lane is unbounded: a best-effort UDP send to the kernel
    // never fails or backpressures, so the app queue must not shed frames on an
    // arbitrary byte budget. Real-time freshness is shed by frame deadline at
    // dequeue time, which keeps the queue bounded by offered rate × deadline.
    let (tx, rx) = latest_wins_queue_unbounded();
    let closed = inner.shutdown().child_token();
    tokio::spawn(run_write(state, session, peer, inner, rx, closed.clone()));
    ActiveStream::new_latest_wins(TransportKind::Udp, Some(peer_addr), tx, closed, is_dialer)
}

fn stabilized_ping_interval(active: Duration, idle: Duration) -> Duration {
    if idle.is_zero() { active } else { idle }
}

async fn run_write(
    state: Arc<UdpSocketState>,
    session: Arc<UdpCryptoSession>,
    peer: Arc<PeerState>,
    inner: Arc<ManagerInner>,
    mut rx: LatestWinsReceiver<OutboundFrame>,
    closed: CancellationToken,
) {
    let level = TransportKind::Udp.service_level();
    let active_ping_interval = inner.cfg().ping_interval();
    let stable_ping_interval =
        stabilized_ping_interval(active_ping_interval, inner.cfg().idle_ping_interval());
    let mut stable_ping_interval_armed = false;
    let pending_timeout = active_ping_interval
        .max(stable_ping_interval)
        .saturating_mul(2)
        .max(Duration::from_secs(1));
    let mut ping_tick = MaybeInterval::maybe(active_ping_interval);
    let mut pending_udp_data = VecDeque::new();

    let hello = build_frame(
        inner.self_id(),
        peer.node_id(),
        level,
        FrameType::Hello,
        MessageClass::Regular,
        now_us(),
        Bytes::new(),
    );
    let hello_result = tokio::select! {
        biased;

        _ = closed.cancelled() => return,
        result = session.send_frame(&hello, &peer, peer.udp_datagram_mtu()) => result,
    };
    if let Err(e) = hello_result {
        warn!(peer=%peer.node_id(), error=%e, "udp encrypted hello failed");
        state
            .remove_session_if_current(peer.node_id(), &session)
            .await;
        closed.cancel();
        return;
    }

    let mut remove_session_on_exit = false;
    loop {
        if let Some(first) = pending_udp_data.pop_front() {
            let Some(first) = drop_expired_prepared_udp_data(first, &peer) else {
                continue;
            };
            if let Err(e) = send_udp_data_batch(
                &session,
                &peer,
                &inner,
                &mut rx,
                &mut pending_udp_data,
                first,
                level,
            )
            .await
            {
                warn!(peer=%peer.node_id(), error=%e, "udp encrypted write failed");
                if is_packet_too_large(&e) {
                    warn!(peer=%peer.node_id(), mtu=peer.udp_datagram_mtu(), "reduced udp datagram budget after packet-too-large error");
                    continue;
                }
                remove_session_on_exit = true;
                break;
            }
            continue;
        }

        tokio::select! {
            biased;
            _ = closed.cancelled() => break,

            maybe_out = rx.recv() => {
                let Some(out) = maybe_out else { break };
                let mut prepared = match prepare_udp_data_frames(out, &session, &peer, &inner, level) {
                    Ok(prepared) => prepared,
                    Err(e) => {
                        warn!(peer=%peer.node_id(), error=%e, "udp outbound frame preparation failed");
                        remove_session_on_exit = true;
                        break;
                    }
                };
                let Some(first) = prepared.pop_front() else {
                    continue;
                };
                pending_udp_data.extend(prepared);
                match send_udp_data_batch(
                    &session,
                    &peer,
                    &inner,
                    &mut rx,
                    &mut pending_udp_data,
                    first,
                    level,
                ).await {
                    Ok(()) => {}
                    Err(e) => {
                        warn!(peer=%peer.node_id(), error=%e, "udp encrypted write failed");
                        if is_packet_too_large(&e) {
                            warn!(peer=%peer.node_id(), mtu=peer.udp_datagram_mtu(), "reduced udp datagram budget after packet-too-large error");
                            continue;
                        }
                        remove_session_on_exit = true;
                        break;
                    }
                }
            }

            _ = session.startup_probe_ready.notified() => {
                if !stable_ping_interval_armed
                    && stable_ping_interval != active_ping_interval
                {
                    ping_tick = MaybeInterval::maybe(stable_ping_interval);
                    stable_ping_interval_armed = true;
                }
            }

            _ = ping_tick.tick() => {
                if record_expired_udp_pending(&session, &peer, pending_timeout) {
                    warn!(peer=%peer.node_id(), misses=UDP_KEEPALIVE_MISS_CLOSE_THRESHOLD, "udp keepalive pongs missed; closing session");
                    remove_session_on_exit = true;
                    break;
                }
                let ts = now_us();
                let probe_mtu = peer.claim_udp_datagram_mtu_probe(
                    Instant::now(),
                    UDP_MTU_PROBE_INTERVAL,
                    UDP_MTU_PROBE_STEP,
                );
                let udp_mtu = probe_mtu.unwrap_or_else(|| peer.udp_datagram_mtu());
                let frame = match probe_mtu {
                    Some(mtu) => udp_mtu_probe_frame(
                        inner.self_id(), peer.node_id(), level, ts, mtu, &session,
                    ),
                    None => build_frame(
                        inner.self_id(), peer.node_id(), level,
                        FrameType::KeepAlive, MessageClass::Regular,
                        ts, Bytes::new(),
                    ),
                };
                match session.send_frame(&frame, &peer, udp_mtu).await {
                    Ok(_) => {
                        if session.pending.lock().insert(ts, probe_mtu).is_some() {
                            peer.metrics().record_probe_lost(TransportKind::Udp);
                        }
                    }
                    Err(e) => {
                        warn!(peer=%peer.node_id(), error=%e, "udp encrypted keepalive failed");
                        if is_packet_too_large(&e) {
                            continue;
                        }
                        remove_session_on_exit = true;
                        break;
                    }
                }
            }

        }
    }
    if remove_session_on_exit {
        state
            .remove_session_if_current(peer.node_id(), &session)
            .await;
    }
    closed.cancel();
    trace!(peer=%peer.node_id(), "udp encrypted write pump exited");
}

fn udp_mtu_probe_frame(
    src: NodeIdentifier,
    dst: NodeIdentifier,
    level: ServiceLevel,
    ts: u64,
    udp_mtu: usize,
    session: &UdpCryptoSession,
) -> pb::Frame {
    let mut frame = build_frame(
        src,
        dst,
        level,
        FrameType::KeepAlive,
        MessageClass::Regular,
        ts,
        Bytes::new(),
    );
    let encoded_budget = session
        .socket
        .payload_mtu(udp_mtu)
        .saturating_sub(UDP_ENCRYPTED_OVERHEAD);
    let mut low = 0usize;
    let mut high = encoded_budget.saturating_sub(frame.encoded_len());
    while low < high {
        let candidate = low + (high - low).div_ceil(2);
        frame.payload = Bytes::from(vec![0; candidate]);
        if frame.encoded_len() <= encoded_budget {
            low = candidate;
        } else {
            high = candidate - 1;
        }
    }
    frame.payload = Bytes::from(vec![0; low]);
    frame
}

fn prepare_udp_data_frames(
    out: OutboundFrame,
    session: &UdpCryptoSession,
    peer: &PeerState,
    inner: &ManagerInner,
    level: ServiceLevel,
) -> io::Result<VecDeque<PreparedUdpData>> {
    let options = out.options();
    if options.is_expired() {
        peer.record_expired_outbound_drop(
            ExpiredOutboundDropStage::TransportWrite,
            Some(TransportKind::Udp),
            out.class(),
        );
        trace!(peer=%peer.node_id(), "dropping expired outbound udp frame");
        return Ok(VecDeque::new());
    }

    let original_payload_len = out.payload().len();
    let class = out.class();
    let mut frame = build_frame(
        inner.self_id(),
        peer.node_id(),
        level,
        FrameType::Data,
        class,
        now_us(),
        out.payload().clone(),
    );
    let compress_started_at = Instant::now();
    let compress_result = maybe_compress_frame_payload(
        &mut frame,
        options,
        inner.cfg().compression_config(),
        inner.cfg().max_frame_bytes(),
    );
    record_transport_pipeline_stage(
        TransportKind::Udp,
        TransportPipelineStage::L1Compress,
        compress_started_at.elapsed(),
    );
    compress_result?;

    let datagrams =
        session.encrypt_data_frame(&frame, session.socket.payload_mtu(peer.udp_datagram_mtu()))?;
    Ok(datagrams
        .into_iter()
        .enumerate()
        .map(|(index, (datagram, plaintext))| PreparedUdpData {
            datagram,
            plaintext,
            #[cfg(debug_assertions)]
            frame_type: frame.frame_type,
            class,
            expires_at: options.expires_at(),
            original_payload_len: (index == 0).then_some(original_payload_len).unwrap_or(0),
        })
        .collect())
}

fn reprepare_udp_data(
    prepared: PreparedUdpData,
    session: &UdpCryptoSession,
    peer: &PeerState,
    inner: &ManagerInner,
) -> io::Result<VecDeque<PreparedUdpData>> {
    let datagrams = session.encrypt_plaintext_or_fragments(
        inner.self_id(),
        peer.node_id(),
        prepared.plaintext,
        session.socket.payload_mtu(peer.udp_datagram_mtu()),
    )?;
    Ok(datagrams
        .into_iter()
        .enumerate()
        .map(|(index, (datagram, plaintext))| PreparedUdpData {
            datagram,
            plaintext,
            #[cfg(debug_assertions)]
            frame_type: prepared.frame_type,
            class: prepared.class,
            expires_at: prepared.expires_at,
            original_payload_len: (index == 0)
                .then_some(prepared.original_payload_len)
                .unwrap_or(0),
        })
        .collect())
}

fn drop_expired_prepared_udp_data(
    prepared: PreparedUdpData,
    peer: &PeerState,
) -> Option<PreparedUdpData> {
    if prepared
        .expires_at
        .is_some_and(|expires_at| Instant::now() >= expires_at)
    {
        peer.record_expired_outbound_drop(
            ExpiredOutboundDropStage::TransportWrite,
            Some(TransportKind::Udp),
            prepared.class,
        );
        trace!(peer=%peer.node_id(), "dropping expired pending outbound udp frame");
        return None;
    }
    Some(prepared)
}

async fn send_udp_data_batch(
    session: &UdpCryptoSession,
    peer: &PeerState,
    inner: &ManagerInner,
    rx: &mut LatestWinsReceiver<OutboundFrame>,
    pending_udp_data: &mut VecDeque<PreparedUdpData>,
    first: PreparedUdpData,
    level: ServiceLevel,
) -> io::Result<()> {
    let mut batch = Vec::with_capacity(UDP_WRITE_BATCH_MAX_FRAMES);
    let mut batch_bytes = first.datagram.len();
    batch.push(first);

    while batch.len() < UDP_WRITE_BATCH_MAX_FRAMES && batch_bytes < UDP_WRITE_BATCH_MAX_BYTES {
        let prepared = if let Some(prepared) = pending_udp_data.pop_front() {
            prepared
        } else {
            let out = match rx.try_recv() {
                Ok(out) => out,
                Err(TryRecvLatestWinsError::Empty) => break,
                Err(TryRecvLatestWinsError::Closed) => break,
            };
            let mut prepared = prepare_udp_data_frames(out, session, peer, inner, level)?;
            let Some(first) = prepared.pop_front() else {
                continue;
            };
            pending_udp_data.extend(prepared);
            first
        };
        let Some(prepared) = drop_expired_prepared_udp_data(prepared, peer) else {
            continue;
        };
        if let Err(prepared) = push_prepared_udp_data(&mut batch, &mut batch_bytes, prepared) {
            pending_udp_data.push_front(prepared);
            break;
        }
    }

    if let Err(error) = session.send_data_batch(&batch, peer).await {
        if is_packet_too_large(&error) {
            let mut retry = VecDeque::new();
            for prepared in batch {
                retry.extend(reprepare_udp_data(prepared, session, peer, inner)?);
            }
            while let Some(prepared) = retry.pop_back() {
                pending_udp_data.push_front(prepared);
            }
            return Ok(());
        }
        return Err(error);
    }
    for entry in batch {
        peer.metrics()
            .record_payload_sent(TransportKind::Udp, entry.original_payload_len);
    }
    Ok(())
}

fn push_prepared_udp_data(
    batch: &mut Vec<PreparedUdpData>,
    batch_bytes: &mut usize,
    prepared: PreparedUdpData,
) -> Result<(), PreparedUdpData> {
    let datagram_len = prepared.datagram.len();
    if !batch.is_empty()
        && (batch.len() >= UDP_WRITE_BATCH_MAX_FRAMES
            || batch_bytes.saturating_add(datagram_len) > UDP_WRITE_BATCH_MAX_BYTES)
    {
        return Err(prepared);
    }
    *batch_bytes = batch_bytes.saturating_add(datagram_len);
    batch.push(prepared);
    Ok(())
}

fn record_expired_udp_pending(
    session: &UdpCryptoSession,
    peer: &PeerState,
    pending_timeout: Duration,
) -> bool {
    let expired = session.pending.lock().expire_older_than(pending_timeout);
    for _ in 0..expired.total {
        peer.metrics().record_probe_lost(TransportKind::Udp);
    }
    if expired.keepalive == 0 {
        return false;
    }
    let misses = session
        .consecutive_keepalive_misses
        .fetch_add(expired.keepalive, Ordering::Relaxed)
        + expired.keepalive;
    misses >= UDP_KEEPALIVE_MISS_CLOSE_THRESHOLD
}

async fn handle_frame(
    mut frame: pb::Frame,
    session: &Arc<UdpCryptoSession>,
    local_id: NodeIdentifier,
    peer: &PeerState,
    inbound: &InboundDispatch,
    level: ServiceLevel,
    max_frame_bytes: usize,
    compression: &super::super::compression::CompressionConfig,
    udp_mtu: usize,
) -> io::Result<()> {
    let decompress_started_at = Instant::now();
    let decompress_result = validate_and_decode_payload(&mut frame, max_frame_bytes, compression);
    record_transport_pipeline_stage(
        TransportKind::Udp,
        TransportPipelineStage::L1Decompress,
        decompress_started_at.elapsed(),
    );
    decompress_result?;
    let ty = match pb::FrameType::try_from(frame.frame_type) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    match ty {
        pb::FrameType::FrameData => {
            let class = pb::MessageClass::try_from(frame.message_class)
                .map(MessageClass::from)
                .unwrap_or(MessageClass::Regular);
            peer.metrics()
                .record_payload_recv(TransportKind::Udp, frame.payload.len());
            inbound.dispatch(InboundMessage::new(
                peer.node_id(),
                level,
                TransportKind::Udp,
                class,
                frame.payload,
            ));
        }
        pb::FrameType::FramePing | pb::FrameType::FrameKeepalive => {
            let pong = build_frame(
                local_id,
                peer.node_id(),
                level,
                FrameType::Pong,
                MessageClass::Regular,
                frame.ts_us,
                frame.payload.clone(),
            );
            session
                .send_frame(&pong, peer, udp_mtu.max(session.frame_datagram_mtu(&pong)))
                .await?;
        }
        pb::FrameType::FramePong => {
            let now = now_us();
            if now > frame.ts_us {
                let rtt = Duration::from_micros(now - frame.ts_us);
                peer.metrics().record_rtt(TransportKind::Udp, rtt);
                if let Some(pending) = session.pending.lock().take(frame.ts_us) {
                    if let Some(mtu) = pending.mtu_probe {
                        peer.confirm_udp_datagram_mtu(mtu);
                    }
                    session
                        .consecutive_keepalive_misses
                        .store(0, Ordering::Relaxed);
                    peer.metrics().record_probe_delivered(TransportKind::Udp);
                    session.startup_probe_ready.notify_one();
                }
            }
        }
        pb::FrameType::FrameHello => {
            trace!(peer=%peer.node_id(), "received udp encrypted transport hello");
        }
        pb::FrameType::FrameDictionary | pb::FrameType::FrameDictionaryAck => {}
        pb::FrameType::FrameBye => {}
    }
    Ok(())
}

struct PendingPings {
    inner: VecDeque<(u64, PendingPing)>,
    cap: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ExpiredPings {
    total: usize,
    keepalive: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingPing {
    sent_at: Instant,
    mtu_probe: Option<usize>,
}

impl PendingPings {
    fn new(cap: usize) -> Self {
        Self {
            inner: VecDeque::with_capacity(cap),
            cap,
        }
    }

    fn insert(&mut self, ts: u64, mtu_probe: Option<usize>) -> Option<PendingPing> {
        if self.cap == 0 {
            return None;
        }
        let evicted = if self.inner.len() >= self.cap {
            self.inner.pop_front().map(|(_, pending)| pending)
        } else {
            None
        };
        self.inner.push_back((
            ts,
            PendingPing {
                sent_at: Instant::now(),
                mtu_probe,
            },
        ));
        evicted
    }

    fn take(&mut self, ts: u64) -> Option<PendingPing> {
        let idx = self
            .inner
            .iter()
            .position(|(pending_ts, _)| *pending_ts == ts)?;
        let (_, pending) = self.inner.remove(idx)?;
        Some(pending)
    }

    fn expire_older_than(&mut self, timeout: Duration) -> ExpiredPings {
        let now = Instant::now();
        let mut expired = ExpiredPings::default();
        while self
            .inner
            .front()
            .is_some_and(|(_, pending)| now.saturating_duration_since(pending.sent_at) >= timeout)
        {
            if let Some((_, pending)) = self.inner.pop_front() {
                expired.total += 1;
                expired.keepalive += usize::from(pending.mtu_probe.is_none());
            }
        }
        expired
    }
}

enum MaybeInterval {
    Enabled(Interval),
    Disabled,
}

impl MaybeInterval {
    fn maybe(duration: Duration) -> Self {
        if duration.is_zero() {
            Self::Disabled
        } else {
            Self::Enabled(interval_at(TokioInstant::now(), duration))
        }
    }

    async fn tick(&mut self) {
        match self {
            Self::Enabled(interval) => {
                interval.tick().await;
            }
            Self::Disabled => std::future::pending::<()>().await,
        }
    }
}

fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_socket_state() -> Arc<UdpSocketState> {
        Arc::new(UdpSocketState::from_prefixed(
            PrefixedUdpSocket::bind_ephemeral(
                SocketAddr::from(([127, 0, 0, 1], 9)),
                TransportKind::Udp,
            )
            .await
            .unwrap(),
        ))
    }

    async fn test_session() -> UdpCryptoSession {
        let state = test_socket_state().await;
        UdpCryptoSession::new(
            2,
            SocketAddr::from(([127, 0, 0, 1], 9)),
            state.socket.clone(),
            [7; 32],
            [7; 32],
            8,
        )
        .expect("test crypto session")
    }

    #[test]
    fn initial_udp_budget_reserves_a_pppoe_safe_margin() {
        assert_eq!(initial_udp_datagram_mtu(1200), 1136);
        assert_eq!(initial_udp_datagram_mtu(600), UDP_MIN_DATAGRAM_MTU);
        assert_eq!(udp_datagram_mtu_ceiling(1200), 1436);
    }

    #[tokio::test]
    async fn mtu_probe_frame_fills_the_candidate_datagram() {
        let session = test_session().await;
        let frame = udp_mtu_probe_frame(1, 2, ServiceLevel::BestEffort, 1, 1200, &session);

        assert!(session.frame_datagram_mtu(&frame) <= 1200);
        assert!(session.frame_datagram_mtu(&frame) > 1200 - 8);
    }

    #[tokio::test]
    async fn oversized_data_frame_fragments_and_reassembles_out_of_order() {
        let session = test_session().await;
        let body = Bytes::from(vec![0xab; 4096]);
        let frame = build_frame(
            1,
            2,
            ServiceLevel::BestEffort,
            FrameType::Data,
            MessageClass::HighPriority,
            1,
            body.clone(),
        );
        let fragments = session
            .encrypt_data_frame(&frame, 575)
            .expect("fragment oversized frame");
        assert!(fragments.len() > 1);

        let mut reassembled = None;
        for (_, fragment) in fragments.into_iter().rev() {
            if let UdpFragmentOutcome::Whole(frame) =
                session.accept_fragment(fragment.to_vec(), 16 * 1024)
            {
                reassembled = Some(frame);
            }
        }
        let decoded = pb::Frame::decode(reassembled.expect("reassembled frame").as_slice())
            .expect("decoded transport frame");
        assert_eq!(decoded.payload, body);
    }

    #[tokio::test]
    async fn refragmented_udp_data_reassembles_without_losing_the_original_frame() {
        let session = test_session().await;
        let body = Bytes::from(vec![0xcd; 4096]);
        let frame = build_frame(
            1,
            2,
            ServiceLevel::BestEffort,
            FrameType::Data,
            MessageClass::HighPriority,
            1,
            body.clone(),
        );
        let mut fragments = session
            .encrypt_data_frame(&frame, 575)
            .expect("fragment oversized frame");
        let (_, first_outer_fragment) = fragments.remove(0);
        let nested = session
            .encrypt_plaintext_or_fragments(1, 2, first_outer_fragment, 300)
            .expect("refragment rejected datagram");

        let mut reassembled = None;
        for (_, nested_fragment) in nested.into_iter().rev() {
            if let UdpFragmentOutcome::Whole(outer_fragment) =
                session.accept_fragment(nested_fragment.to_vec(), 16 * 1024)
            {
                if let UdpFragmentOutcome::Whole(frame) =
                    session.accept_fragment(outer_fragment, 16 * 1024)
                {
                    reassembled = Some(frame);
                }
            }
        }
        for (_, outer_fragment) in fragments {
            if let UdpFragmentOutcome::Whole(frame) =
                session.accept_fragment(outer_fragment.to_vec(), 16 * 1024)
            {
                reassembled = Some(frame);
            }
        }

        let decoded = pb::Frame::decode(reassembled.expect("reassembled frame").as_slice())
            .expect("decoded transport frame");
        assert_eq!(decoded.payload, body);
    }
    use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair};
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    fn test_exchange(ready_received: bool) -> PeerKeyExchange {
        PeerKeyExchange {
            local: Some(LocalKeyOffer {
                offer_id: 11,
                private_key: None,
                public_key: vec![1; X25519_PUBLIC_KEY_LEN],
                packet: vec![0xaa],
            }),
            peer: Some(PeerKeyOffer {
                offer_id: 13,
                public_key: vec![2; X25519_PUBLIC_KEY_LEN],
            }),
            candidate: Some(KeyCandidate {
                exchange_id: 17,
                peer_addr: SocketAddr::from(([127, 0, 0, 1], 64742)),
                seal_key: [3; 32],
                open_key: [4; 32],
                ready_packet: vec![0xbb],
                ready_received,
                promoted: false,
            }),
            peer_addr: Some(SocketAddr::from(([127, 0, 0, 1], 64742))),
            early_ready: Vec::new(),
            waiters: Vec::new(),
            local_initiated: true,
            send_budget: ExchangeSendBudget::default(),
            stale_ready: StaleReadyGuard::default(),
        }
    }

    fn test_identity(node_cn: &str) -> NodeIdentity {
        let dir = TempDir::new().unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["s2s-udp-test-ca".to_string()]).unwrap();
        let mut ca_dn = DistinguishedName::new();
        ca_dn.push(DnType::CommonName, "s2s-udp-test-ca");
        ca_params.distinguished_name = ca_dn;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert: Certificate = ca_params.self_signed(&ca_key).unwrap();

        let node_key = KeyPair::generate().unwrap();
        let mut node_params = CertificateParams::new(vec![format!("node-{node_cn}")]).unwrap();
        let mut node_dn = DistinguishedName::new();
        node_dn.push(DnType::CommonName, node_cn);
        node_params.distinguished_name = node_dn;
        let node_cert = node_params.signed_by(&node_key, &ca_cert, &ca_key).unwrap();

        let ca_path = dir.path().join("ca.pem");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        File::create(&ca_path)
            .unwrap()
            .write_all(ca_cert.pem().as_bytes())
            .unwrap();
        File::create(&cert_path)
            .unwrap()
            .write_all(node_cert.pem().as_bytes())
            .unwrap();
        File::create(&key_path)
            .unwrap()
            .write_all(node_key.serialize_pem().as_bytes())
            .unwrap();

        NodeIdentity::load(&ca_path, &cert_path, &key_path).unwrap()
    }

    #[test]
    fn replay_window_accepts_new_and_rejects_duplicates() {
        let mut replay = ReplayWindow::default();

        assert!(replay.accept(10));
        assert!(!replay.accept(10));
        assert!(replay.accept(9));
        assert!(!replay.accept(9));
        assert!(replay.accept(11));
        assert!(replay.accept(1));
        assert!(!replay.accept(1));
        assert!(replay.accept(200));
        assert!(!replay.accept(11));
    }

    #[test]
    fn packet_header_roundtrips() {
        let header = UdpPacketHeader {
            kind: UdpPacketKind::Data,
            src: 1,
            dst: 2,
            seq: 42,
        };
        let encoded = header.encode();

        assert_eq!(
            UdpPacketHeader::decode(&[encoded.as_slice(), &[0; TAG_LEN]].concat())
                .unwrap()
                .seq,
            42
        );
    }

    #[test]
    fn pending_expiration_counts_keepalives_separately() {
        let mut pending = PendingPings::new(4);

        pending.insert(1, None);
        pending.insert(2, Some(1200));

        let expired = pending.expire_older_than(Duration::ZERO);
        assert_eq!(expired.total, 2);
        assert_eq!(expired.keepalive, 1);
    }

    #[test]
    fn key_exchange_derives_matching_directional_keys() {
        let (low_private, low_public) = generate_ephemeral_keypair().unwrap();
        let (high_private, high_public) = generate_ephemeral_keypair().unwrap();
        let ordered = OrderedOfferMaterial {
            low_node: 7,
            high_node: 9,
            low_offer_id: 11,
            high_offer_id: 13,
            low_public_key: &low_public,
            high_public_key: &high_public,
        };
        let low_keys = derive_key_material(low_private, &high_public, &ordered).unwrap();
        let high_keys = derive_key_material(high_private, &low_public, &ordered).unwrap();

        assert_eq!(low_keys.low_to_high, high_keys.low_to_high);
        assert_eq!(low_keys.high_to_low, high_keys.high_to_low);
        assert_ne!(low_keys.low_to_high, low_keys.high_to_low);
    }

    #[test]
    fn promoted_key_exchange_stops_retransmitting_handshake_packets() {
        let mut exchange = test_exchange(true);
        let now = Instant::now();

        assert_eq!(
            exchange_packets_due(&mut exchange, now, 1, 2),
            vec![vec![0xaa], vec![0xbb]]
        );

        let promote = promote_if_ready(&mut exchange, 1, 2);

        assert!(promote.is_some());
        assert!(exchange_packets_due(&mut exchange, now, 1, 2).is_empty());
        assert!(promote_if_ready(&mut exchange, 1, 2).is_none());
    }

    #[test]
    fn duplicate_key_exchange_packets_are_paced() {
        let mut exchange = test_exchange(false);
        let now = Instant::now();

        assert_eq!(
            exchange_packets_due(&mut exchange, now, 1, 2),
            vec![vec![0xaa], vec![0xbb]]
        );
        assert!(exchange_packets_due(&mut exchange, now, 1, 2).is_empty());
        assert_eq!(
            exchange_packets_due(&mut exchange, now + UDP_KEX_RETRANSMIT_MAX_INTERVAL, 1, 2),
            vec![vec![0xaa], vec![0xbb]]
        );
        assert!(
            exchange_packets_due(&mut exchange, now + UDP_KEX_RETRANSMIT_MAX_INTERVAL, 1, 2)
                .is_empty()
        );
    }

    #[test]
    fn key_exchange_retransmit_attempts_are_capped() {
        let mut exchange = test_exchange(false);
        let now = Instant::now();

        assert_eq!(
            exchange_packets_due(&mut exchange, now, 1, 2),
            vec![vec![0xaa], vec![0xbb]]
        );
        exchange.send_budget.offer.retransmits = UDP_KEX_MAX_RETRANSMITS;
        exchange.send_budget.offer.last_sent = Some(now - UDP_KEX_RETRANSMIT_MAX_INTERVAL);
        exchange.send_budget.ready.retransmits = UDP_KEX_MAX_RETRANSMITS;
        exchange.send_budget.ready.last_sent = Some(now - UDP_KEX_RETRANSMIT_MAX_INTERVAL);

        assert!(
            exchange_packets_due(&mut exchange, now + UDP_KEX_RETRANSMIT_MAX_INTERVAL, 1, 2)
                .is_empty()
        );
    }

    #[test]
    fn key_exchange_retransmit_delay_backs_off_and_caps() {
        let first = kex_retransmit_delay(UdpPacketKind::KeyOffer, 1, 2, 11, 0);
        let second = kex_retransmit_delay(UdpPacketKind::KeyOffer, 1, 2, 11, 1);
        let capped = kex_retransmit_delay(UdpPacketKind::KeyOffer, 1, 2, 11, 10);

        assert!(first >= UDP_KEX_RETRANSMIT_INTERVAL);
        assert!(
            first
                <= UDP_KEX_RETRANSMIT_INTERVAL
                    + duration_div(
                        UDP_KEX_RETRANSMIT_INTERVAL,
                        UDP_KEX_RETRANSMIT_JITTER_DIVISOR
                    )
        );
        assert!(second > first);
        assert_eq!(capped, UDP_KEX_RETRANSMIT_MAX_INTERVAL);
    }

    #[test]
    fn key_exchange_retransmit_age_is_capped() {
        let mut exchange = test_exchange(false);
        let now = Instant::now();

        assert_eq!(
            exchange_packets_due(&mut exchange, now, 1, 2),
            vec![vec![0xaa], vec![0xbb]]
        );
        assert!(
            exchange_packets_due(&mut exchange, now + UDP_KEX_MAX_RETRANSMIT_AGE, 1, 2).is_empty()
        );
    }

    #[tokio::test]
    async fn exchange_retransmit_collector_respects_packet_pacing() {
        let state = test_socket_state().await;
        let mut exchange = test_exchange(false);
        assert_eq!(
            exchange_packets_due(&mut exchange, Instant::now(), 1, 2),
            vec![vec![0xaa], vec![0xbb]]
        );
        state.exchanges.lock().await.insert(2, exchange);

        let (batches, keep_armed) = collect_exchange_retransmits(&state, 1).await;
        assert!(batches.is_empty());
        assert!(keep_armed);

        {
            let mut exchanges = state.exchanges.lock().await;
            let exchange = exchanges.get_mut(&2).unwrap();
            let due = Instant::now() - UDP_KEX_RETRANSMIT_MAX_INTERVAL;
            exchange.send_budget.offer.last_sent = Some(due);
            exchange.send_budget.ready.last_sent = Some(due);
        }

        let (batches, keep_armed) = collect_exchange_retransmits(&state, 1).await;
        assert!(keep_armed);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].peer_node, 2);
        assert_eq!(batches[0].packets, vec![vec![0xaa], vec![0xbb]]);

        let (batches, keep_armed) = collect_exchange_retransmits(&state, 1).await;
        assert!(batches.is_empty());
        assert!(keep_armed);
    }

    #[tokio::test]
    async fn exchange_retransmit_collector_stops_after_budget_exhaustion() {
        let state = test_socket_state().await;
        let mut exchange = test_exchange(false);
        let first_sent = Instant::now() - UDP_KEX_RETRANSMIT_INTERVAL;
        exchange.send_budget.offer.first_sent = Some(first_sent);
        exchange.send_budget.offer.last_sent = Some(first_sent);
        exchange.send_budget.offer.retransmits = UDP_KEX_MAX_RETRANSMITS;
        exchange.send_budget.ready.first_sent = Some(first_sent);
        exchange.send_budget.ready.last_sent = Some(first_sent);
        exchange.send_budget.ready.retransmits = UDP_KEX_MAX_RETRANSMITS;
        state.exchanges.lock().await.insert(2, exchange);

        let (batches, keep_armed) = collect_exchange_retransmits(&state, 1).await;
        assert!(batches.is_empty());
        assert!(keep_armed);

        let (batches, keep_armed) = collect_exchange_retransmits(&state, 1).await;
        assert!(batches.is_empty());
        assert!(!keep_armed);
    }

    #[tokio::test]
    async fn higher_node_buffers_stale_key_ready_for_lower_restart() {
        let identity = test_identity("2");
        let state = test_socket_state().await;
        state.exchanges.lock().await.insert(1, test_exchange(false));
        let header = UdpPacketHeader {
            kind: UdpPacketKind::KeyReady,
            src: 1,
            dst: 2,
            seq: 99,
        };
        let packet = header.encode();

        let (packets, promote) = accept_key_ready(
            &state,
            &identity,
            2,
            1,
            SocketAddr::from(([127, 0, 0, 1], 64742)),
            &packet,
            header,
        )
        .await
        .unwrap();

        assert!(packets.is_empty());
        assert!(promote.is_none());
        assert_eq!(
            state
                .exchanges
                .lock()
                .await
                .get(&1)
                .unwrap()
                .early_ready
                .len(),
            1
        );

        let (packets, promote) = accept_key_ready(
            &state,
            &identity,
            2,
            1,
            SocketAddr::from(([127, 0, 0, 1], 64742)),
            &packet,
            header,
        )
        .await
        .unwrap();
        assert!(packets.is_empty());
        assert!(promote.is_none());
        assert_eq!(
            state
                .exchanges
                .lock()
                .await
                .get(&1)
                .unwrap()
                .early_ready
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn duplicate_early_key_ready_does_not_rearm_retransmission() {
        let identity = test_identity("2");
        let state = test_socket_state().await;
        let mut exchange = test_exchange(false);
        exchange.peer = None;
        exchange.candidate = None;
        state.exchanges.lock().await.insert(1, exchange);
        let header = UdpPacketHeader {
            kind: UdpPacketKind::KeyReady,
            src: 1,
            dst: 2,
            seq: 99,
        };
        let packet = header.encode();
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 64742));

        let (packets, _) = accept_key_ready(&state, &identity, 2, 1, peer_addr, &packet, header)
            .await
            .unwrap();
        assert_eq!(packets, vec![vec![0xaa]]);
        {
            let mut exchanges = state.exchanges.lock().await;
            let exchange = exchanges.get_mut(&1).unwrap();
            exchange.send_budget.offer.last_sent =
                Some(Instant::now() - UDP_KEX_RETRANSMIT_MAX_INTERVAL);
        }

        let (packets, promote) =
            accept_key_ready(&state, &identity, 2, 1, peer_addr, &packet, header)
                .await
                .unwrap();

        assert!(packets.is_empty());
        assert!(promote.is_none());
        let exchanges = state.exchanges.lock().await;
        let exchange = exchanges.get(&1).unwrap();
        assert_eq!(exchange.early_ready.len(), 1);
        assert_eq!(exchange.send_budget.offer.retransmits, 0);
    }

    #[tokio::test]
    async fn lower_node_restarts_key_exchange_on_stale_ready() {
        let identity = test_identity("1");
        let state = test_socket_state().await;
        state.exchanges.lock().await.insert(2, test_exchange(false));
        let header = UdpPacketHeader {
            kind: UdpPacketKind::KeyReady,
            src: 2,
            dst: 1,
            seq: 99,
        };
        let packet = header.encode();

        let (packets, promote) = accept_key_ready(
            &state,
            &identity,
            1,
            2,
            SocketAddr::from(([127, 0, 0, 1], 64742)),
            &packet,
            header,
        )
        .await
        .unwrap();

        assert!(promote.is_none());
        assert_eq!(packets.len(), 1);
        let offer_header = UdpPacketHeader::decode(&packets[0]).unwrap();
        assert_eq!(offer_header.kind, UdpPacketKind::KeyOffer);
        assert_eq!(offer_header.src, 1);
        assert_eq!(offer_header.dst, 2);
        assert_ne!(offer_header.seq, 11);

        let exchanges = state.exchanges.lock().await;
        let exchange = exchanges.get(&2).unwrap();
        let local = exchange.local.as_ref().unwrap();
        assert_eq!(local.offer_id, offer_header.seq);
        assert!(local.private_key.is_some());
        assert!(exchange.peer.is_none());
        assert!(exchange.candidate.is_none());
        assert!(exchange.early_ready.is_empty());
        assert!(exchange.local_initiated);
    }

    #[tokio::test]
    async fn lower_node_rate_limits_stale_ready_restarts() {
        let identity = test_identity("1");
        let state = test_socket_state().await;
        state.exchanges.lock().await.insert(2, test_exchange(false));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 64742));
        let first_header = UdpPacketHeader {
            kind: UdpPacketKind::KeyReady,
            src: 2,
            dst: 1,
            seq: 99,
        };
        let first_packet = first_header.encode();

        let (packets, _) = accept_key_ready(
            &state,
            &identity,
            1,
            2,
            peer_addr,
            &first_packet,
            first_header,
        )
        .await
        .unwrap();
        assert_eq!(packets.len(), 1);
        let restarted_offer_id = state
            .exchanges
            .lock()
            .await
            .get(&2)
            .unwrap()
            .local
            .as_ref()
            .unwrap()
            .offer_id;

        let (_, peer_public_key) = generate_ephemeral_keypair().unwrap();
        let (_, promote) = accept_peer_offer(
            &state,
            &identity,
            1,
            2,
            peer_addr,
            PeerKeyOffer {
                offer_id: 101,
                public_key: peer_public_key,
            },
        )
        .await
        .unwrap();
        assert!(promote.is_none());
        let candidate_exchange_id = state
            .exchanges
            .lock()
            .await
            .get(&2)
            .unwrap()
            .candidate
            .as_ref()
            .unwrap()
            .exchange_id;
        let stale_exchange_id = if candidate_exchange_id == u64::MAX {
            1
        } else {
            candidate_exchange_id + 1
        };
        let second_header = UdpPacketHeader {
            kind: UdpPacketKind::KeyReady,
            src: 2,
            dst: 1,
            seq: stale_exchange_id,
        };
        let second_packet = second_header.encode();
        let (packets, promote) = accept_key_ready(
            &state,
            &identity,
            1,
            2,
            peer_addr,
            &second_packet,
            second_header,
        )
        .await
        .unwrap();

        assert!(packets.is_empty());
        assert!(promote.is_none());
        let exchanges = state.exchanges.lock().await;
        let exchange = exchanges.get(&2).unwrap();
        assert_eq!(
            exchange.local.as_ref().unwrap().offer_id,
            restarted_offer_id
        );
        assert_eq!(exchange.peer.as_ref().unwrap().offer_id, 101);
        assert_eq!(
            exchange.candidate.as_ref().unwrap().exchange_id,
            candidate_exchange_id
        );
        assert!(exchange.stale_ready.restart_used);
    }

    #[tokio::test]
    async fn lower_node_ignores_stale_ready_from_unexpected_address() {
        let identity = test_identity("1");
        let state = test_socket_state().await;
        state.exchanges.lock().await.insert(2, test_exchange(false));
        let header = UdpPacketHeader {
            kind: UdpPacketKind::KeyReady,
            src: 2,
            dst: 1,
            seq: 99,
        };
        let packet = header.encode();

        let (packets, promote) = accept_key_ready(
            &state,
            &identity,
            1,
            2,
            SocketAddr::from(([127, 0, 0, 1], 64743)),
            &packet,
            header,
        )
        .await
        .unwrap();

        assert!(packets.is_empty());
        assert!(promote.is_none());
        let exchanges = state.exchanges.lock().await;
        let exchange = exchanges.get(&2).unwrap();
        assert_eq!(exchange.local.as_ref().unwrap().offer_id, 11);
        assert_eq!(exchange.peer.as_ref().unwrap().offer_id, 13);
        assert_eq!(exchange.candidate.as_ref().unwrap().exchange_id, 17);
        assert!(!exchange.stale_ready.restart_used);
    }

    #[test]
    fn key_ready_logs_are_rate_limited_and_count_suppressed_events() {
        let mut limiter = LogRateLimit::default();
        let now = Instant::now();

        assert_eq!(limiter.record(now), Some(0));
        assert_eq!(limiter.record(now), None);
        assert_eq!(limiter.force(now), 1);
        assert_eq!(limiter.record(now), None);
        assert_eq!(limiter.record(now + UDP_KEX_READY_LOG_INTERVAL), Some(1));
    }

    #[tokio::test]
    async fn lower_node_defers_changed_higher_offer_while_candidate_active() {
        let identity = test_identity("1");
        let state = test_socket_state().await;
        state.exchanges.lock().await.insert(2, test_exchange(false));
        let (_, public_key) = generate_ephemeral_keypair().unwrap();

        let (packets, promote) = accept_peer_offer(
            &state,
            &identity,
            1,
            2,
            SocketAddr::from(([127, 0, 0, 1], 64742)),
            PeerKeyOffer {
                offer_id: 99,
                public_key,
            },
        )
        .await
        .unwrap();

        assert_eq!(packets, vec![vec![0xaa], vec![0xbb]]);
        assert!(promote.is_none());

        let exchanges = state.exchanges.lock().await;
        let exchange = exchanges.get(&2).unwrap();
        assert_eq!(exchange.local.as_ref().unwrap().offer_id, 11);
        assert_eq!(exchange.peer.as_ref().unwrap().offer_id, 13);
        assert_eq!(exchange.candidate.as_ref().unwrap().exchange_id, 17);
    }
}
