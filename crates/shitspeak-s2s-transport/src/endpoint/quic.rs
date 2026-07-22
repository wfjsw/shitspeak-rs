//! QUIC endpoint. Reuses the same rustls server/client configs as the TLS
//! stream transports. The bound `quinn::Endpoint` is built once at endpoint
//! construction time and shared between accept and dial.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use prost::Message as _;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ClientConfig as QuinnClientConfig, Endpoint as QuinnEndpoint, EndpointConfig,
    ServerConfig as QuinnServerConfig, TransportConfig as QuinnTransportConfig, default_runtime,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::super::adaptive_queue::AdaptiveQueueBudget;
use super::super::compression::{maybe_compress_frame_payload, validate_and_decode_payload};
use super::super::connection::{ActiveStream, OutboundFrame, PeerState, QuicV2SessionSender};
use super::super::frame::{FrameType, build_frame, encode_frame_to_bytes};
use super::super::identity::parse_peer_cn;
use super::super::manager::ManagerInner;
use super::super::metrics::{
    DatagramPathEvidenceEvent, QuicDatagramDropReason, QuicDeliveryLane, QuicProtocolErrorReason,
    QuicProtocolResult, QuicProtocolStage, QuicProtocolVersion as MetricQuicProtocolVersion,
    TransportIoDirection, record_quic_datagram_drop, record_quic_lane_delivery,
    record_quic_protocol_error, record_quic_protocol_event,
};
use super::super::native_stats;
use super::super::service_level::{DeliveryPath, MessageClass, ServiceLevel, TransportKind};
use super::super::stream_io::{
    StreamLanePolicy, StreamPumpConfig, spawn_stream_lane_pump, stream_handoff_lane_bytes,
};
use super::{
    Endpoint, install_stream_session,
    mux::{DISCRIMINATOR_LEN, PrefixedUdpSocket, UdpMuxSet},
};

pub(crate) const QUIC_ALPN_V1: &[u8] = b"s2s/1";
pub(crate) const QUIC_ALPN_V2: &[u8] = b"s2s/2";

pub(crate) const QUIC_V2_LANE_PREFACE_LEN: usize = 8;
const QUIC_V2_LANE_MAGIC: &[u8; 4] = b"S2SL";
const QUIC_V2_LANE_VERSION: u8 = 2;
const QUIC_V2_LANE_FLAGS: u8 = 0;
const QUIC_V2_LANE_RESERVED: u8 = 0;

/// Stable application close codes for the v2 session protocol.
pub(crate) const QUIC_CLOSE_SETUP_PROTOCOL: u32 = 0x100;
pub(crate) const QUIC_CLOSE_REQUIRED_LANE_FAILED: u32 = 0x101;
pub(crate) const QUIC_CLOSE_LOCAL_SHUTDOWN: u32 = 0x102;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuicProtocolVersion {
    V1,
    V2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub(crate) enum QuicLane {
    Control = 0,
    HighPriority = 1,
    Regular = 2,
}

impl QuicLane {
    pub(crate) const ALL: [Self; 3] = [Self::Control, Self::HighPriority, Self::Regular];

    #[cfg(test)]
    pub(crate) fn from_message_class(class: MessageClass) -> Self {
        match class {
            MessageClass::Control => Self::Control,
            MessageClass::HighPriority => Self::HighPriority,
            MessageClass::Regular => Self::Regular,
        }
    }

    #[cfg(test)]
    pub(crate) fn message_class(self) -> MessageClass {
        match self {
            Self::Control => MessageClass::Control,
            Self::HighPriority => MessageClass::HighPriority,
            Self::Regular => MessageClass::Regular,
        }
    }

    fn from_wire(value: u8) -> io::Result<Self> {
        match value {
            0 => Ok(Self::Control),
            1 => Ok(Self::HighPriority),
            2 => Ok(Self::Regular),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown QUIC v2 lane {value}"),
            )),
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// Tracks the lane identities observed during accept-side setup. Streams may
/// arrive in any order, but every identity must appear exactly once.
#[derive(Debug, Default)]
pub(crate) struct QuicLaneRegistry {
    seen: [bool; 3],
}

impl QuicLaneRegistry {
    pub(crate) fn register(&mut self, lane: QuicLane) -> io::Result<()> {
        let seen = &mut self.seen[lane.index()];
        if std::mem::replace(seen, true) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("duplicate QUIC v2 {lane:?} lane"),
            ));
        }
        Ok(())
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.seen.iter().all(|seen| *seen)
    }

    pub(crate) fn missing(&self) -> impl Iterator<Item = QuicLane> + '_ {
        QuicLane::ALL
            .into_iter()
            .filter(|lane| !self.seen[lane.index()])
    }
}

/// ALPN preference order for dual-stack QUIC peers.
pub(crate) fn quic_alpn_protocols() -> Vec<Vec<u8>> {
    vec![QUIC_ALPN_V2.to_vec(), QUIC_ALPN_V1.to_vec()]
}

pub(crate) fn parse_negotiated_quic_alpn(
    protocol: Option<&[u8]>,
) -> io::Result<QuicProtocolVersion> {
    match protocol {
        Some(QUIC_ALPN_V2) => Ok(QuicProtocolVersion::V2),
        Some(QUIC_ALPN_V1) => Ok(QuicProtocolVersion::V1),
        Some(protocol) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unsupported negotiated QUIC ALPN {:?}",
                String::from_utf8_lossy(protocol)
            ),
        )),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "QUIC connection did not negotiate ALPN",
        )),
    }
}

pub(crate) fn negotiated_quic_protocol(
    connection: &quinn::Connection,
) -> io::Result<QuicProtocolVersion> {
    let handshake = connection
        .handshake_data()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing QUIC handshake data"))?
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "QUIC handshake data was not produced by rustls",
            )
        })?;
    parse_negotiated_quic_alpn(handshake.protocol.as_deref())
}

fn negotiated_quic_protocol_or_close(
    connection: &quinn::Connection,
) -> io::Result<QuicProtocolVersion> {
    negotiated_quic_protocol(connection).inspect_err(|_| {
        connection.close(
            QUIC_CLOSE_SETUP_PROTOCOL.into(),
            b"missing or unsupported ALPN",
        );
    })
}

pub(crate) fn encode_lane_preface(lane: QuicLane) -> [u8; QUIC_V2_LANE_PREFACE_LEN] {
    [
        QUIC_V2_LANE_MAGIC[0],
        QUIC_V2_LANE_MAGIC[1],
        QUIC_V2_LANE_MAGIC[2],
        QUIC_V2_LANE_MAGIC[3],
        QUIC_V2_LANE_VERSION,
        lane as u8,
        QUIC_V2_LANE_FLAGS,
        QUIC_V2_LANE_RESERVED,
    ]
}

pub(crate) fn decode_lane_preface(preface: [u8; QUIC_V2_LANE_PREFACE_LEN]) -> io::Result<QuicLane> {
    if &preface[..4] != QUIC_V2_LANE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid QUIC v2 lane preface magic",
        ));
    }
    if preface[4] != QUIC_V2_LANE_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported QUIC lane version {}", preface[4]),
        ));
    }
    if preface[6] != QUIC_V2_LANE_FLAGS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported QUIC lane flags 0x{:02x}", preface[6]),
        ));
    }
    if preface[7] != QUIC_V2_LANE_RESERVED {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "QUIC lane reserved byte must be zero",
        ));
    }
    QuicLane::from_wire(preface[5])
}

pub(crate) async fn write_lane_preface<W>(writer: &mut W, lane: QuicLane) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&encode_lane_preface(lane)).await?;
    writer.flush().await
}

pub(crate) async fn read_lane_preface<R>(reader: &mut R) -> io::Result<QuicLane>
where
    R: AsyncRead + Unpin,
{
    let mut preface = [0u8; QUIC_V2_LANE_PREFACE_LEN];
    reader.read_exact(&mut preface).await?;
    decode_lane_preface(preface)
}

/// Initiator half of the v2 lane handshake: write a lane preface and require
/// the acceptor to echo the same lane before the stream can carry frames.
pub(crate) async fn initiate_lane_handshake<W, R>(
    writer: &mut W,
    reader: &mut R,
    lane: QuicLane,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    write_lane_preface(writer, lane).await?;
    let echoed = read_lane_preface(reader).await?;
    if echoed != lane {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("QUIC lane echo mismatch: expected {lane:?}, got {echoed:?}"),
        ));
    }
    Ok(())
}

/// Acceptor half of the v2 lane handshake: validate the peer preface and echo
/// it on the corresponding send half.
pub(crate) async fn accept_lane_handshake<W, R>(
    writer: &mut W,
    reader: &mut R,
) -> io::Result<QuicLane>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let lane = read_lane_preface(reader).await?;
    write_lane_preface(writer, lane).await?;
    Ok(lane)
}

pub(crate) async fn open_v2_lane(
    connection: &quinn::Connection,
    lane: QuicLane,
) -> io::Result<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| io::Error::other(format!("QUIC open {lane:?} lane: {error}")))?;
    initiate_lane_handshake(&mut send, &mut recv, lane).await?;
    Ok((send, recv))
}

pub(crate) async fn accept_v2_lane(
    connection: &quinn::Connection,
) -> io::Result<(QuicLane, quinn::SendStream, quinn::RecvStream)> {
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|error| io::Error::other(format!("QUIC accept v2 lane: {error}")))?;
    let lane = accept_lane_handshake(&mut send, &mut recv).await?;
    Ok((lane, send, recv))
}

/// QUIC endpoint state. Owns the bound `quinn::Endpoint` and the QUIC
/// client config used for outbound connections.
pub(crate) struct QuicEndpoint {
    listen_addrs: Vec<SocketAddr>,
    server_cfg: QuinnServerConfig,
    accept_handles: parking_lot::Mutex<Vec<AcceptEndpoint>>,
    client_cfg: QuinnClientConfig,
    mux: UdpMuxSet,
    datagram_send_buffer_bytes: usize,
    datagram_receive_buffer_bytes: usize,
}

struct AcceptEndpoint {
    handle: QuinnEndpoint,
}

pub(crate) struct QuicBindError {
    addr: SocketAddr,
    source: io::Error,
}

impl QuicBindError {
    pub(crate) fn into_parts(self) -> (SocketAddr, io::Error) {
        (self.addr, self.source)
    }
}

impl QuicEndpoint {
    /// Build a `QuicEndpoint`. If `listen_addrs` is non-empty, each address is
    /// bound in server mode. Empty listeners preserve dial-only operation.
    pub fn new(
        server_tls: Arc<rustls::ServerConfig>,
        client_tls: Arc<rustls::ClientConfig>,
        listen_addrs: impl IntoIterator<Item = SocketAddr>,
        mux: UdpMuxSet,
        datagram_send_buffer_bytes: usize,
        datagram_receive_buffer_bytes: usize,
        alpn_protocols_override: Option<&[Vec<u8>]>,
    ) -> Result<Self, QuicBindError> {
        let listen_addrs = listen_addrs.into_iter().collect::<Vec<_>>();
        let mut server_tls = (*server_tls).clone();
        server_tls.alpn_protocols = alpn_protocols_override
            .map(<[Vec<u8>]>::to_vec)
            .unwrap_or_else(quic_alpn_protocols);

        let mut client_tls = (*client_tls).clone();
        client_tls.alpn_protocols = server_tls.alpn_protocols.clone();
        let qcc: QuicClientConfig = client_tls
            .try_into()
            .map_err(|e| quic_config_error(SocketAddr::from(([0, 0, 0, 0], 0)), e))?;
        let mut client_cfg = QuinnClientConfig::new(Arc::new(qcc));
        client_cfg.transport_config(quic_transport_config(
            datagram_send_buffer_bytes,
            datagram_receive_buffer_bytes,
        ));

        let qsc: QuicServerConfig = server_tls
            .try_into()
            .map_err(|e| quic_config_error(first_listen_addr(&listen_addrs), e))?;
        let server_cfg = QuinnServerConfig::with_crypto(Arc::new(qsc));
        Ok(Self {
            listen_addrs,
            server_cfg,
            accept_handles: parking_lot::Mutex::new(Vec::new()),
            client_cfg,
            mux,
            datagram_send_buffer_bytes,
            datagram_receive_buffer_bytes,
        })
    }

    async fn client_handle(&self, addr: SocketAddr) -> io::Result<QuinnEndpoint> {
        bind_prefixed_client_endpoint(addr).await
    }

    fn client_config_for_path(&self) -> QuinnClientConfig {
        let mut cfg = self.client_cfg.clone();
        cfg.transport_config(quic_transport_config(
            self.datagram_send_buffer_bytes,
            self.datagram_receive_buffer_bytes,
        ));
        cfg
    }
}

fn first_listen_addr(listen_addrs: &[SocketAddr]) -> SocketAddr {
    listen_addrs
        .first()
        .copied()
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)))
}

fn quic_config_error<E: std::fmt::Debug>(addr: SocketAddr, error: E) -> QuicBindError {
    QuicBindError {
        addr,
        source: io::Error::new(io::ErrorKind::InvalidInput, format!("{error:?}")),
    }
}

fn bind_mux_server_endpoint(
    server_cfg: QuinnServerConfig,
    handle: super::mux::UdpMuxHandle,
) -> io::Result<QuinnEndpoint> {
    let runtime = default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
    QuinnEndpoint::new_with_abstract_socket(
        endpoint_config()?,
        Some(server_cfg),
        Arc::new(handle),
        runtime,
    )
}

async fn bind_prefixed_client_endpoint(addr: SocketAddr) -> io::Result<QuinnEndpoint> {
    let socket = PrefixedUdpSocket::bind_ephemeral(addr, TransportKind::Quic).await?;
    let runtime = default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
    QuinnEndpoint::new_with_abstract_socket(endpoint_config()?, None, Arc::new(socket), runtime)
}

fn endpoint_config() -> io::Result<EndpointConfig> {
    let mut cfg = EndpointConfig::default();
    let max_payload = 1472usize.saturating_sub(DISCRIMINATOR_LEN);
    cfg.max_udp_payload_size(max_payload as u16)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e:?}")))?;
    Ok(cfg)
}

fn quic_transport_config(
    datagram_send_buffer_bytes: usize,
    datagram_receive_buffer_bytes: usize,
) -> Arc<QuinnTransportConfig> {
    let mut transport = QuinnTransportConfig::default();
    // QUIC requires a 1200-byte minimum packet. The shared UDP mux adds its
    // discriminator outside that packet, so the physical path must carry at
    // least 1200 + DISCRIMINATOR_LEN bytes of UDP payload.
    transport.initial_mtu(1200);
    transport.min_mtu(1200);
    // The v2 initiator opens exactly one bidirectional stream per reliable
    // lane. Fair scheduling keeps equal-priority lanes making progress.
    transport.max_concurrent_bidi_streams(3u32.into());
    transport.max_concurrent_uni_streams(0u32.into());
    transport.send_fairness(true);
    transport.datagram_send_buffer_size(datagram_send_buffer_bytes);
    transport.datagram_receive_buffer_size(
        (datagram_receive_buffer_bytes > 0).then_some(datagram_receive_buffer_bytes),
    );
    Arc::new(transport)
}

impl Endpoint for QuicEndpoint {
    async fn start(self: Arc<Self>, inner: Arc<ManagerInner>) -> io::Result<()> {
        let mut handles = Vec::with_capacity(self.listen_addrs.len());
        for addr in self.listen_addrs.iter().copied() {
            let mux_handle = self
                .mux
                .take_handle(addr, TransportKind::Quic, inner.shutdown().child_token())
                .await?;
            let mut server_cfg = self.server_cfg.clone();
            server_cfg.transport = quic_transport_config(
                self.datagram_send_buffer_bytes,
                self.datagram_receive_buffer_bytes,
            );
            let handle = bind_mux_server_endpoint(server_cfg, mux_handle)
                .map_err(|e| io::Error::new(e.kind(), format!("quic mux bind {addr}: {e}")))?;
            handles.push(AcceptEndpoint { handle });
        }
        *self.accept_handles.lock() = handles;
        for accept in self.accept_handles.lock().iter() {
            let handle = accept.handle.clone();
            debug!(addr=?handle.local_addr().ok(), "quic listener up");
            tokio::spawn(accept_loop(handle, inner.clone()));
        }
        Ok(())
    }

    async fn dial(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
        peer: Arc<PeerState>,
        addr: SocketAddr,
    ) -> io::Result<()> {
        let connecting = self
            .client_handle(addr)
            .await?
            .connect_with(
                self.client_config_for_path(),
                addr,
                &format!("node-{}", peer.node_id()),
            )
            .map_err(|e| io::Error::other(format!("quic connect_with: {e}")))?;
        let conn = connecting
            .await
            .map_err(|e| io::Error::other(format!("quic connecting: {e}")))?;
        let chain = conn
            .peer_identity()
            .and_then(|d| {
                d.downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>()
                    .ok()
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no quic peer identity"))?;
        let peer_node = parse_peer_cn(&chain)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
        if peer_node != peer.node_id() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "peer certificate node id {peer_node} != expected {}",
                    peer.node_id()
                ),
            ));
        }
        let protocol = negotiated_quic_protocol_or_close(&conn)?;
        record_quic_negotiation(protocol, QuicProtocolResult::Success);
        install_quic_connection(&inner, peer_node, Some(addr), true, conn, protocol).await?;
        Ok(())
    }

    async fn dial_unidentified(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
        addr: SocketAddr,
    ) -> io::Result<crate::types::NodeIdentifier> {
        let connecting = self
            .client_handle(addr)
            .await?
            .connect_with(self.client_config_for_path(), addr, "s2s-seed.local")
            .map_err(|e| io::Error::other(format!("quic connect_with: {e}")))?;
        let conn = connecting
            .await
            .map_err(|e| io::Error::other(format!("quic connecting: {e}")))?;
        let chain = conn
            .peer_identity()
            .and_then(|d| {
                d.downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>()
                    .ok()
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no quic peer identity"))?;
        let peer_node = parse_peer_cn(&chain)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
        if peer_node == inner.self_id() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "self-loop rejected",
            ));
        }
        let protocol = negotiated_quic_protocol_or_close(&conn)?;
        record_quic_negotiation(protocol, QuicProtocolResult::Success);
        install_quic_connection(&inner, peer_node, Some(addr), true, conn, protocol).await?;
        Ok(peer_node)
    }
}

async fn accept_loop(handle: QuinnEndpoint, inner: Arc<ManagerInner>) {
    loop {
        tokio::select! {
            _ = inner.shutdown().cancelled() => return,
            incoming = handle.accept() => {
                let Some(incoming) = incoming else { return };
                let inner_c = inner.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_incoming(inner_c, incoming).await {
                        if is_peer_closed_quic_inbound(&e) {
                            debug!(error=%e, "quic inbound closed by peer during setup");
                        } else {
                            warn!(error=%e, "quic inbound failed");
                        }
                    }
                });
            }
        }
    }
}

fn is_peer_closed_quic_inbound(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::UnexpectedEof
    ) || error.to_string().contains("closed by peer")
}

async fn handle_incoming(inner: Arc<ManagerInner>, incoming: quinn::Incoming) -> io::Result<()> {
    let conn = incoming
        .await
        .map_err(|e| io::Error::other(format!("quic connect: {e}")))?;
    let remote_addr = conn.remote_address();
    let chain = conn
        .peer_identity()
        .and_then(|d| {
            d.downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no quic peer identity"))?;
    let peer_node = parse_peer_cn(&chain)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
    if peer_node == inner.self_id() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "self-loop rejected",
        ));
    }
    inner
        .get_or_create_peer(peer_node)
        .note_observed_remote_addr(TransportKind::Quic, remote_addr);
    let protocol = negotiated_quic_protocol_or_close(&conn)?;
    record_quic_negotiation(protocol, QuicProtocolResult::Success);
    install_quic_connection(&inner, peer_node, Some(remote_addr), false, conn, protocol).await?;
    Ok(())
}

fn record_quic_negotiation(protocol: QuicProtocolVersion, result: QuicProtocolResult) {
    let version = match protocol {
        QuicProtocolVersion::V1 => MetricQuicProtocolVersion::S2s1,
        QuicProtocolVersion::V2 => MetricQuicProtocolVersion::S2s2,
    };
    record_quic_protocol_event(QuicProtocolStage::Negotiation, version, result);
}

async fn install_quic_connection(
    inner: &Arc<ManagerInner>,
    peer_node: crate::types::NodeIdentifier,
    remote_addr: Option<SocketAddr>,
    is_dialer: bool,
    conn: quinn::Connection,
    protocol: QuicProtocolVersion,
) -> io::Result<()> {
    match protocol {
        QuicProtocolVersion::V1 => {
            let native_sampler = Some(native_stats::quic_sampler(conn.clone()));
            let stream_result = if is_dialer {
                conn.open_bi()
                    .await
                    .map_err(|e| io::Error::other(format!("quic open_bi: {e}")))
            } else {
                conn.accept_bi()
                    .await
                    .map_err(|e| io::Error::other(format!("quic accept_bi: {e}")))
            };
            let (send, recv) = match stream_result {
                Ok(stream) => stream,
                Err(error) => {
                    record_quic_protocol_event(
                        QuicProtocolStage::Setup,
                        MetricQuicProtocolVersion::S2s1,
                        QuicProtocolResult::Failure,
                    );
                    return Err(error);
                }
            };
            install_stream_session(
                inner,
                peer_node,
                TransportKind::Quic,
                remote_addr,
                is_dialer,
                BiStream { send, recv },
                native_sampler,
            );
            record_quic_protocol_event(
                QuicProtocolStage::Setup,
                MetricQuicProtocolVersion::S2s1,
                QuicProtocolResult::Success,
            );
            Ok(())
        }
        QuicProtocolVersion::V2 => {
            install_quic_v2_session(inner, peer_node, remote_addr, is_dialer, conn).await
        }
    }
}

async fn setup_quic_v2_lanes(
    conn: &quinn::Connection,
    is_dialer: bool,
    setup_timeout: Duration,
) -> io::Result<[BiStream; 3]> {
    let setup = async {
        let mut lanes: [Option<BiStream>; 3] = std::array::from_fn(|_| None);
        if is_dialer {
            for lane in QuicLane::ALL {
                let (send, recv) = open_v2_lane(conn, lane).await?;
                send.set_priority(0)
                    .map_err(|e| io::Error::other(format!("set QUIC lane priority: {e}")))?;
                lanes[lane.index()] = Some(BiStream { send, recv });
            }
        } else {
            let mut registry = QuicLaneRegistry::default();
            for _ in 0..QuicLane::ALL.len() {
                let (lane, send, recv) = accept_v2_lane(conn).await?;
                registry.register(lane)?;
                send.set_priority(0)
                    .map_err(|e| io::Error::other(format!("set QUIC lane priority: {e}")))?;
                lanes[lane.index()] = Some(BiStream { send, recv });
            }
            if !registry.is_complete() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "missing QUIC v2 lanes: {:?}",
                        registry.missing().collect::<Vec<_>>()
                    ),
                ));
            }
        }
        lanes
            .map(|lane| {
                lane.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing QUIC v2 lane")
                })
            })
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| io::Error::other("invalid QUIC v2 lane count"))
    };

    timeout(setup_timeout, setup)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC v2 lane setup timed out"))?
}

async fn install_quic_v2_session(
    inner: &Arc<ManagerInner>,
    peer_node: crate::types::NodeIdentifier,
    remote_addr: Option<SocketAddr>,
    is_dialer: bool,
    conn: quinn::Connection,
) -> io::Result<()> {
    if inner.cfg().quic_datagram_send_buffer_bytes() == 0
        || inner.cfg().quic_datagram_receive_buffer_bytes() == 0
    {
        record_quic_protocol_event(
            QuicProtocolStage::Setup,
            MetricQuicProtocolVersion::S2s2,
            QuicProtocolResult::Failure,
        );
        conn.close(
            QUIC_CLOSE_SETUP_PROTOCOL.into(),
            b"local DATAGRAM support required",
        );
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "QUIC v2 requires enabled local DATAGRAM send and receive buffers",
        ));
    }
    let Some(max_datagram_size) = conn.max_datagram_size() else {
        record_quic_protocol_event(
            QuicProtocolStage::Setup,
            MetricQuicProtocolVersion::S2s2,
            QuicProtocolResult::Failure,
        );
        conn.close(
            QUIC_CLOSE_SETUP_PROTOCOL.into(),
            b"DATAGRAM support required",
        );
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "QUIC v2 peer did not negotiate DATAGRAM support",
        ));
    };
    let lanes =
        match setup_quic_v2_lanes(&conn, is_dialer, inner.cfg().quic_session_setup_timeout()).await
        {
            Ok(lanes) => lanes,
            Err(error) => {
                record_quic_setup_error(&error);
                record_quic_protocol_event(
                    QuicProtocolStage::Setup,
                    MetricQuicProtocolVersion::S2s2,
                    QuicProtocolResult::Failure,
                );
                conn.close(QUIC_CLOSE_SETUP_PROTOCOL.into(), b"lane setup failed");
                return Err(error);
            }
        };

    let peer = inner.get_or_create_peer(peer_node);
    let closed = inner.shutdown().child_token();
    let budget = AdaptiveQueueBudget::auto();
    let lane_bytes = stream_handoff_lane_bytes(budget.max_bytes(), inner.cfg().max_frame_bytes());
    let (sender, receivers) = QuicV2SessionSender::new(
        lane_bytes,
        inner.cfg().quic_datagram_send_buffer_bytes(),
        inner.cfg().quic_datagram_receive_buffer_bytes(),
        max_datagram_size,
    );
    let active = ActiveStream::new_quic_v2(remote_addr, sender.clone(), closed.clone(), is_dialer);
    if let Err(rejected) = peer.try_install_stream(active) {
        rejected.cancel();
        conn.close(QUIC_CLOSE_LOCAL_SHUTDOWN.into(), b"duplicate session");
        return Ok(());
    }
    let datagram_evidence_session = peer
        .metrics()
        .reset_datagram_path_evidence(DeliveryPath::QuicDatagram);
    sender.set_datagram_evidence_session(datagram_evidence_session);
    peer.reset_datagram_path_health(DeliveryPath::QuicDatagram);

    let close_code = Arc::new(AtomicU32::new(QUIC_CLOSE_REQUIRED_LANE_FAILED));
    let cfg = StreamPumpConfig::new(
        inner.self_id(),
        peer_node,
        TransportKind::Quic,
        inner.cfg().max_frame_bytes(),
        inner.cfg().outbound_capacity(),
        inner.cfg().ping_interval(),
        inner.cfg().idle_ping_interval(),
        inner.cfg().native_stats_interval(),
        inner.cfg().stream_write_timeout(),
        inner.cfg().compression_config().clone(),
        inner.cfg().max_pending_pings(),
    )
    .with_quic_v2_close_code(close_code.clone());
    let (control_rx, high_rx, regular_rx, datagram_rx) = receivers.into_parts();
    let [control, high, regular] = lanes;
    spawn_stream_lane_pump(
        control,
        cfg.clone(),
        peer.clone(),
        inner.inbound().clone(),
        control_rx,
        closed.clone(),
        Some(native_stats::quic_sampler(conn.clone())),
        StreamLanePolicy::quic_v2(MessageClass::Control),
    );
    spawn_stream_lane_pump(
        high,
        cfg.clone(),
        peer.clone(),
        inner.inbound().clone(),
        high_rx,
        closed.clone(),
        None,
        StreamLanePolicy::quic_v2(MessageClass::HighPriority),
    );
    spawn_stream_lane_pump(
        regular,
        cfg,
        peer.clone(),
        inner.inbound().clone(),
        regular_rx,
        closed.clone(),
        None,
        StreamLanePolicy::quic_v2(MessageClass::Regular),
    );

    tokio::spawn(run_quic_datagram_sender(
        conn.clone(),
        sender.clone(),
        datagram_rx,
        inner.clone(),
        peer.clone(),
        closed.clone(),
    ));
    tokio::spawn(run_quic_datagram_receiver(
        conn.clone(),
        sender.clone(),
        inner.clone(),
        peer,
        closed.clone(),
    ));
    let max_datagram_conn = conn.clone();
    let max_datagram_closed = closed.clone();
    tokio::spawn(async move {
        let mut refresh = tokio::time::interval(Duration::from_secs(1));
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = max_datagram_closed.cancelled() => return,
                _ = refresh.tick() => {
                    sender.set_max_datagram_size(
                        max_datagram_conn.max_datagram_size().unwrap_or(0),
                    );
                }
            }
        }
    });
    let shutdown = inner.shutdown().clone();
    tokio::spawn(async move {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                conn.close(QUIC_CLOSE_LOCAL_SHUTDOWN.into(), b"local shutdown");
            }
            _ = closed.cancelled() => {
                conn.close(close_code.load(Ordering::Acquire).into(), b"session failed");
            }
        }
    });
    record_quic_protocol_event(
        QuicProtocolStage::Setup,
        MetricQuicProtocolVersion::S2s2,
        QuicProtocolResult::Success,
    );
    debug!(peer=%peer_node, ?remote_addr, is_dialer, max_datagram_size, "QUIC v2 session ready");
    Ok(())
}

async fn run_quic_datagram_sender(
    conn: quinn::Connection,
    session_sender: QuicV2SessionSender,
    mut rx: super::super::latest_wins_queue::LatestWinsReceiver<OutboundFrame>,
    inner: Arc<ManagerInner>,
    peer: Arc<PeerState>,
    closed: CancellationToken,
) {
    loop {
        let out = tokio::select! {
            _ = closed.cancelled() => return,
            out = rx.recv() => match out {
                Some(out) => out,
                None => return,
            },
        };
        if out.options().is_expired() {
            record_session_datagram_drop(&session_sender, QuicDatagramDropReason::Expired);
            continue;
        }
        let original_payload_len = out.payload().len();
        let mut frame = build_frame(
            inner.self_id(),
            peer.node_id(),
            ServiceLevel::BestEffort,
            FrameType::Data,
            out.class(),
            quic_now_us(),
            out.payload().clone(),
        );
        if frame.encoded_len() > inner.cfg().max_frame_bytes() {
            record_session_datagram_evidence(
                &peer,
                &session_sender,
                DatagramPathEvidenceEvent::TooLarge,
            );
            record_session_datagram_drop(&session_sender, QuicDatagramDropReason::TooLarge);
            continue;
        }
        if maybe_compress_frame_payload(
            &mut frame,
            out.options(),
            inner.cfg().compression_config(),
            inner.cfg().max_frame_bytes(),
        )
        .is_err()
        {
            record_session_datagram_drop(&session_sender, QuicDatagramDropReason::Validation);
            continue;
        }
        let encoded = match encode_frame_to_bytes(&frame) {
            Ok(encoded) => encoded,
            Err(_) => {
                record_session_datagram_drop(&session_sender, QuicDatagramDropReason::Validation);
                continue;
            }
        };
        if out.options().is_expired() {
            record_session_datagram_drop(&session_sender, QuicDatagramDropReason::Expired);
            continue;
        }
        if encoded.len() > inner.cfg().max_frame_bytes() {
            record_session_datagram_evidence(
                &peer,
                &session_sender,
                DatagramPathEvidenceEvent::TooLarge,
            );
            record_session_datagram_drop(&session_sender, QuicDatagramDropReason::TooLarge);
            continue;
        }
        let max_datagram_size = conn.max_datagram_size().unwrap_or(0);
        session_sender.set_max_datagram_size(max_datagram_size);
        if encoded.len() > max_datagram_size {
            record_session_datagram_evidence(
                &peer,
                &session_sender,
                DatagramPathEvidenceEvent::TooLarge,
            );
            record_session_datagram_drop(&session_sender, QuicDatagramDropReason::TooLarge);
            continue;
        }
        if conn.datagram_send_buffer_space() < encoded.len() {
            record_session_datagram_evidence(
                &peer,
                &session_sender,
                DatagramPathEvidenceEvent::Pressure,
            );
            record_session_datagram_drop(
                &session_sender,
                QuicDatagramDropReason::QuinnBufferPressure,
            );
        }
        if out.options().is_expired() {
            record_session_datagram_drop(&session_sender, QuicDatagramDropReason::Expired);
            continue;
        }
        match conn.send_datagram(encoded.clone()) {
            Ok(()) => {
                record_session_datagram_evidence(
                    &peer,
                    &session_sender,
                    DatagramPathEvidenceEvent::OutcomeSuccess,
                );
                session_sender.record_datagram_queued();
                peer.metrics()
                    .record_payload_sent(TransportKind::Quic, original_payload_len);
                peer.metrics()
                    .record_sent(TransportKind::Quic, encoded.len());
                record_quic_lane_delivery(
                    peer.node_id(),
                    TransportIoDirection::Egress,
                    QuicDeliveryLane::Datagram,
                    1,
                    encoded.len(),
                );
                // Quinn schedules queued DATAGRAMs ahead of stream data.
                // Yield between submissions so reliable lane pumps can make
                // progress under sustained best-effort load.
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Err(quinn::SendDatagramError::TooLarge) => {
                record_session_datagram_evidence(
                    &peer,
                    &session_sender,
                    DatagramPathEvidenceEvent::TooLarge,
                );
                record_session_datagram_drop(&session_sender, QuicDatagramDropReason::TooLarge);
            }
            Err(quinn::SendDatagramError::UnsupportedByPeer) => {
                record_session_datagram_evidence(
                    &peer,
                    &session_sender,
                    DatagramPathEvidenceEvent::OutcomeFailure,
                );
                record_session_datagram_drop(&session_sender, QuicDatagramDropReason::Unsupported);
                peer.metrics()
                    .record_data_health_failure(TransportKind::Quic);
                closed.cancel();
                return;
            }
            Err(quinn::SendDatagramError::Disabled) => {
                record_session_datagram_evidence(
                    &peer,
                    &session_sender,
                    DatagramPathEvidenceEvent::OutcomeFailure,
                );
                record_session_datagram_drop(&session_sender, QuicDatagramDropReason::Disabled);
                peer.metrics()
                    .record_data_health_failure(TransportKind::Quic);
                closed.cancel();
                return;
            }
            Err(quinn::SendDatagramError::ConnectionLost(_)) => {
                record_session_datagram_evidence(
                    &peer,
                    &session_sender,
                    DatagramPathEvidenceEvent::OutcomeFailure,
                );
                record_session_datagram_drop(
                    &session_sender,
                    QuicDatagramDropReason::ConnectionLost,
                );
                closed.cancel();
                return;
            }
        }
    }
}

async fn run_quic_datagram_receiver(
    conn: quinn::Connection,
    session_sender: QuicV2SessionSender,
    inner: Arc<ManagerInner>,
    peer: Arc<PeerState>,
    closed: CancellationToken,
) {
    loop {
        let encoded = tokio::select! {
            _ = closed.cancelled() => return,
            result = conn.read_datagram() => match result {
                Ok(encoded) => encoded,
                Err(_) => {
                    record_session_datagram_evidence(
                        &peer,
                        &session_sender,
                        DatagramPathEvidenceEvent::IngressReadFailure,
                    );
                    closed.cancel();
                    return;
                }
            },
        };
        if encoded.len() > inner.cfg().max_frame_bytes() {
            record_session_datagram_evidence(
                &peer,
                &session_sender,
                DatagramPathEvidenceEvent::TooLarge,
            );
            record_session_datagram_evidence(
                &peer,
                &session_sender,
                DatagramPathEvidenceEvent::IngressRejected,
            );
            record_session_datagram_drop(&session_sender, QuicDatagramDropReason::TooLarge);
            continue;
        }
        let mut frame = match super::super::s2s_transport_proto::Frame::decode(encoded.as_ref()) {
            Ok(frame) => frame,
            Err(_) => {
                record_session_datagram_evidence(
                    &peer,
                    &session_sender,
                    DatagramPathEvidenceEvent::IngressRejected,
                );
                record_session_datagram_drop(&session_sender, QuicDatagramDropReason::Decode);
                continue;
            }
        };
        let valid_type =
            frame.frame_type == super::super::s2s_transport_proto::FrameType::FrameData as i32;
        let valid_level = frame.service_level
            == super::super::s2s_transport_proto::ServiceLevel::ServiceBestEffort as i32;
        let valid_source = frame.src_node == u32::from(peer.node_id());
        let valid_destination = frame.dst_node == u32::from(inner.self_id());
        let class = super::super::s2s_transport_proto::MessageClass::try_from(frame.message_class)
            .ok()
            .map(MessageClass::from);
        if !valid_type {
            record_session_datagram_evidence(
                &peer,
                &session_sender,
                DatagramPathEvidenceEvent::IngressRejected,
            );
            record_session_datagram_drop(&session_sender, QuicDatagramDropReason::Validation);
            continue;
        }
        if class.is_none() {
            record_session_datagram_evidence(
                &peer,
                &session_sender,
                DatagramPathEvidenceEvent::IngressRejected,
            );
            record_quic_protocol_error(QuicProtocolErrorReason::ClassMismatch);
            record_session_datagram_drop(&session_sender, QuicDatagramDropReason::Validation);
            continue;
        }
        if !valid_level {
            record_session_datagram_evidence(
                &peer,
                &session_sender,
                DatagramPathEvidenceEvent::IngressRejected,
            );
            record_quic_protocol_error(QuicProtocolErrorReason::ServiceMismatch);
            record_session_datagram_drop(&session_sender, QuicDatagramDropReason::Validation);
            continue;
        }
        if !valid_source {
            record_session_datagram_evidence(
                &peer,
                &session_sender,
                DatagramPathEvidenceEvent::IngressRejected,
            );
            record_quic_protocol_error(QuicProtocolErrorReason::SourceMismatch);
            record_session_datagram_drop(&session_sender, QuicDatagramDropReason::Validation);
            continue;
        }
        if !valid_destination {
            record_session_datagram_evidence(
                &peer,
                &session_sender,
                DatagramPathEvidenceEvent::IngressRejected,
            );
            record_quic_protocol_error(QuicProtocolErrorReason::DestinationMismatch);
            record_session_datagram_drop(&session_sender, QuicDatagramDropReason::Validation);
            continue;
        }
        if validate_and_decode_payload(
            &mut frame,
            inner.cfg().max_frame_bytes(),
            inner.cfg().compression_config(),
        )
        .is_err()
        {
            record_session_datagram_evidence(
                &peer,
                &session_sender,
                DatagramPathEvidenceEvent::IngressRejected,
            );
            record_session_datagram_drop(&session_sender, QuicDatagramDropReason::Validation);
            continue;
        }
        if frame.encoded_len() > inner.cfg().max_frame_bytes() {
            record_session_datagram_evidence(
                &peer,
                &session_sender,
                DatagramPathEvidenceEvent::TooLarge,
            );
            record_session_datagram_evidence(
                &peer,
                &session_sender,
                DatagramPathEvidenceEvent::IngressRejected,
            );
            record_session_datagram_drop(&session_sender, QuicDatagramDropReason::TooLarge);
            continue;
        }
        let class = class.expect("validated above");
        record_session_datagram_evidence(
            &peer,
            &session_sender,
            DatagramPathEvidenceEvent::IngressValidated,
        );
        session_sender.record_datagram_received();
        peer.metrics()
            .record_payload_recv(TransportKind::Quic, frame.payload.len());
        peer.metrics()
            .record_recv(TransportKind::Quic, encoded.len());
        record_quic_lane_delivery(
            peer.node_id(),
            TransportIoDirection::Ingress,
            QuicDeliveryLane::Datagram,
            1,
            encoded.len(),
        );
        inner
            .inbound()
            .dispatch(super::super::manager::InboundMessage::new(
                peer.node_id(),
                ServiceLevel::BestEffort,
                TransportKind::Quic,
                class,
                frame.payload,
            ));
    }
}

fn record_session_datagram_drop(
    session_sender: &QuicV2SessionSender,
    reason: QuicDatagramDropReason,
) {
    session_sender.record_datagram_drop();
    record_quic_datagram_drop(reason);
}

fn record_session_datagram_evidence(
    peer: &PeerState,
    session_sender: &QuicV2SessionSender,
    event: DatagramPathEvidenceEvent,
) {
    peer.metrics().record_datagram_path_evidence_for_session(
        DeliveryPath::QuicDatagram,
        session_sender.datagram_evidence_session(),
        event,
    );
}

fn quic_now_us() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

fn record_quic_setup_error(error: &io::Error) {
    let message = error.to_string();
    let reason = if message.contains("duplicate") {
        QuicProtocolErrorReason::DuplicateLane
    } else if message.contains("missing") || error.kind() == io::ErrorKind::TimedOut {
        QuicProtocolErrorReason::MissingLane
    } else {
        QuicProtocolErrorReason::InvalidPreface
    };
    record_quic_protocol_error(reason);
}

/// Joins a quinn `SendStream` + `RecvStream` into one `AsyncRead + AsyncWrite`.
struct BiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for BiStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        <quinn::RecvStream as AsyncRead>::poll_read(std::pin::Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for BiStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        <quinn::SendStream as AsyncWrite>::poll_write(std::pin::Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        <quinn::SendStream as AsyncWrite>::poll_flush(std::pin::Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        <quinn::SendStream as AsyncWrite>::poll_shutdown(std::pin::Pin::new(&mut self.send), cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_preference_and_parser_cover_v1_v2_and_invalid_values() {
        assert_eq!(
            quic_alpn_protocols(),
            vec![QUIC_ALPN_V2.to_vec(), QUIC_ALPN_V1.to_vec()]
        );
        assert_eq!(
            parse_negotiated_quic_alpn(Some(QUIC_ALPN_V2)).unwrap(),
            QuicProtocolVersion::V2
        );
        assert_eq!(
            parse_negotiated_quic_alpn(Some(QUIC_ALPN_V1)).unwrap(),
            QuicProtocolVersion::V1
        );
        assert_eq!(
            parse_negotiated_quic_alpn(None).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            parse_negotiated_quic_alpn(Some(b"h3")).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn lane_message_class_mapping_is_exhaustive_and_reversible() {
        let cases = [
            (MessageClass::Control, QuicLane::Control),
            (MessageClass::HighPriority, QuicLane::HighPriority),
            (MessageClass::Regular, QuicLane::Regular),
        ];
        for (class, lane) in cases {
            assert_eq!(QuicLane::from_message_class(class), lane);
            assert_eq!(lane.message_class(), class);
        }
    }

    #[test]
    fn lane_prefaces_round_trip() {
        for lane in QuicLane::ALL {
            let encoded = encode_lane_preface(lane);
            assert_eq!(&encoded[..4], b"S2SL");
            assert_eq!(encoded[4], 2);
            assert_eq!(encoded[5], lane as u8);
            assert_eq!(encoded[6], 0);
            assert_eq!(encoded[7], 0);
            assert_eq!(decode_lane_preface(encoded).unwrap(), lane);
        }
    }

    #[test]
    fn lane_preface_rejects_every_noncanonical_field() {
        let valid = encode_lane_preface(QuicLane::Control);

        for index in 0..4 {
            let mut invalid = valid;
            invalid[index] ^= 0xff;
            assert_eq!(
                decode_lane_preface(invalid).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }

        let mut invalid_version = valid;
        invalid_version[4] = 1;
        assert_eq!(
            decode_lane_preface(invalid_version).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        for unknown_lane in [3, u8::MAX] {
            let mut invalid_lane = valid;
            invalid_lane[5] = unknown_lane;
            assert_eq!(
                decode_lane_preface(invalid_lane).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }

        let mut invalid_flags = valid;
        invalid_flags[6] = 1;
        assert_eq!(
            decode_lane_preface(invalid_flags).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut invalid_reserved = valid;
        invalid_reserved[7] = 1;
        assert_eq!(
            decode_lane_preface(invalid_reserved).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn lane_registry_accepts_arbitrary_order_and_rejects_duplicates() {
        let mut registry = QuicLaneRegistry::default();
        assert_eq!(
            registry.missing().collect::<Vec<_>>(),
            QuicLane::ALL.to_vec()
        );

        registry.register(QuicLane::Regular).unwrap();
        registry.register(QuicLane::Control).unwrap();
        assert!(!registry.is_complete());
        assert_eq!(
            registry.missing().collect::<Vec<_>>(),
            vec![QuicLane::HighPriority]
        );
        assert_eq!(
            registry.register(QuicLane::Regular).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        registry.register(QuicLane::HighPriority).unwrap();
        assert!(registry.is_complete());
        assert!(registry.missing().next().is_none());
    }

    #[tokio::test]
    async fn lane_handshake_echoes_and_confirms_each_lane() {
        for lane in QuicLane::ALL {
            let (initiator, acceptor) = tokio::io::duplex(64);
            let (mut initiator_read, mut initiator_write) = tokio::io::split(initiator);
            let (mut acceptor_read, mut acceptor_write) = tokio::io::split(acceptor);

            let (initiated, accepted) = tokio::join!(
                initiate_lane_handshake(&mut initiator_write, &mut initiator_read, lane),
                accept_lane_handshake(&mut acceptor_write, &mut acceptor_read),
            );
            initiated.unwrap();
            assert_eq!(accepted.unwrap(), lane);
        }
    }

    #[tokio::test]
    async fn initiator_rejects_a_different_echoed_lane() {
        let (initiator, acceptor) = tokio::io::duplex(64);
        let (mut initiator_read, mut initiator_write) = tokio::io::split(initiator);
        let (mut acceptor_read, mut acceptor_write) = tokio::io::split(acceptor);

        let initiator_task =
            initiate_lane_handshake(&mut initiator_write, &mut initiator_read, QuicLane::Control);
        let acceptor_task = async {
            assert_eq!(
                read_lane_preface(&mut acceptor_read).await.unwrap(),
                QuicLane::Control
            );
            write_lane_preface(&mut acceptor_write, QuicLane::Regular)
                .await
                .unwrap();
        };
        let (result, ()) = tokio::join!(initiator_task, acceptor_task);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_lane_preface_requires_all_eight_bytes() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(b"S2SL\x02\x00\x00").await.unwrap();
        writer.shutdown().await.unwrap();
        assert_eq!(
            read_lane_preface(&mut reader).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
