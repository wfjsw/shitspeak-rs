//! UDP + DTLS endpoint.
//!
//! Every UDP datagram is encrypted under a DTLS 1.2 session that uses the
//! same CA + node certificate as the stream transports — peer identity is
//! the X.509 Subject CN, parsed as `NodeIdentifier`. webrtc-dtls's
//! `Listener` does the per-source demultiplex on a single bound socket and
//! drives the handshake; for outbound dials we open a fresh ephemeral UDP
//! socket per peer and run the DTLS client side over it.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use prost::Message as _;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{interval, Interval};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};
use webrtc_dtls::conn::DTLSConn;
use webrtc_util::conn::Listener as UtilListener;
use webrtc_util::Conn as UtilConn;

use crate::s2s_transport_proto as pb;
use crate::types::NodeIdentifier;

use super::super::connection::{ActiveStream, OutboundFrame, PeerState};
use super::super::dtls_config::{
    build_client_dtls_config, build_server_dtls_config, peer_node_id_from_dtls,
};
use super::super::frame::{build_frame, FrameType};
use super::super::identity::NodeIdentity;
use super::super::manager::{InboundDispatch, InboundMessage, ManagerInner};
use super::super::service_level::{MessageClass, ServiceLevel, TransportKind};
use super::Endpoint;

/// UDP+DTLS endpoint. Owns the loaded `NodeIdentity` (used to build server
/// and client DTLS configs) and the listen address.
pub(crate) struct UdpEndpoint {
    identity: Arc<NodeIdentity>,
    listen_addr: Option<SocketAddr>,
}

impl UdpEndpoint {
    pub fn new(identity: Arc<NodeIdentity>, listen_addr: Option<SocketAddr>) -> Self {
        Self {
            identity,
            listen_addr,
        }
    }
}

impl Endpoint for UdpEndpoint {
    const KIND: TransportKind = TransportKind::Udp;

    fn start(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            let Some(addr) = self.listen_addr else {
                return Ok(());
            };
            let server_cfg = build_server_dtls_config(&self.identity, inner.cfg().udp_mtu())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e}")))?;
            let listener = webrtc_dtls::listener::listen(addr, server_cfg)
                .await
                .map_err(|e| io::Error::other(format!("udp dtls listen: {e}")))?;
            debug!(%addr, "udp dtls listener up");
            tokio::spawn(accept_loop(listener, inner));
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
            let local_bind: SocketAddr = match addr {
                SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
            };
            let socket = UdpSocket::bind(local_bind).await?;
            socket.connect(addr).await?;
            let conn: Arc<dyn UtilConn + Send + Sync> = Arc::new(socket);

            let server_name = format!("node-{}", peer.node_id());
            let client_cfg =
                build_client_dtls_config(&self.identity, server_name, inner.cfg().udp_mtu())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e}")))?;

            let dtls_conn = DTLSConn::new(conn, client_cfg, true, None)
                .await
                .map_err(|e| io::Error::other(format!("dtls handshake: {e}")))?;
            let peer_node = peer_node_id_from_dtls(&dtls_conn)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
            if peer_node != peer.node_id() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("peer cn {peer_node} != expected {}", peer.node_id()),
                ));
            }
            let dyn_conn: Arc<dyn UtilConn + Send + Sync> = Arc::new(dtls_conn);
            install_session(&inner, peer_node, addr, true, dyn_conn);
            Ok(())
        }
    }

    fn dial_unidentified(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
        addr: SocketAddr,
    ) -> impl Future<Output = io::Result<NodeIdentifier>> + Send {
        async move {
            let local_bind: SocketAddr = match addr {
                SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
            };
            let socket = UdpSocket::bind(local_bind).await?;
            socket.connect(addr).await?;
            let conn: Arc<dyn UtilConn + Send + Sync> = Arc::new(socket);

            let client_cfg = build_client_dtls_config(
                &self.identity,
                "s2s-seed.local".to_string(),
                inner.cfg().udp_mtu(),
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e}")))?;

            let dtls_conn = DTLSConn::new(conn, client_cfg, true, None)
                .await
                .map_err(|e| io::Error::other(format!("dtls handshake: {e}")))?;
            let peer_node = peer_node_id_from_dtls(&dtls_conn)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
            if peer_node == inner.self_id() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "self-loop rejected",
                ));
            }
            let dyn_conn: Arc<dyn UtilConn + Send + Sync> = Arc::new(dtls_conn);
            install_session(&inner, peer_node, addr, true, dyn_conn);
            Ok(peer_node)
        }
    }
}

async fn accept_loop(
    listener: impl UtilListener + Send + Sync + 'static,
    inner: Arc<ManagerInner>,
) {
    loop {
        tokio::select! {
            _ = inner.shutdown().cancelled() => {
                let _ = listener.close().await;
                return;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((conn, peer_addr)) => {
                        let inner_c = inner.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_inbound(inner_c, conn, peer_addr).await {
                                warn!(error=%e, %peer_addr, "udp dtls inbound failed");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error=?e, "udp dtls accept failed");
                    }
                }
            }
        }
    }
}

async fn handle_inbound(
    inner: Arc<ManagerInner>,
    conn: Arc<dyn UtilConn + Send + Sync>,
    peer_addr: SocketAddr,
) -> io::Result<()> {
    let dtls = conn
        .as_any()
        .downcast_ref::<DTLSConn>()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-DTLS conn from listener"))?;
    let peer_node = peer_node_id_from_dtls(dtls)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
    if peer_node == inner.self_id() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "self-loop rejected",
        ));
    }
    install_session(&inner, peer_node, peer_addr, false, conn);
    Ok(())
}

fn install_session(
    inner: &Arc<ManagerInner>,
    peer_node: NodeIdentifier,
    peer_addr: SocketAddr,
    is_dialer: bool,
    conn: Arc<dyn UtilConn + Send + Sync>,
) {
    let peer = inner.get_or_create_peer(peer_node);
    peer.note_udp_seen(peer_addr);
    let active = spawn_dtls_pump(conn, peer.clone(), inner.clone(), inner.inbound().clone());
    if let Err(rejected) = peer.try_install_stream(inner.self_id(), is_dialer, active) {
        rejected.cancel();
    }
}

fn spawn_dtls_pump(
    conn: Arc<dyn UtilConn + Send + Sync>,
    peer: Arc<PeerState>,
    inner: Arc<ManagerInner>,
    inbound: InboundDispatch,
) -> ActiveStream {
    let (tx, rx) = mpsc::channel::<OutboundFrame>(inner.cfg().outbound_capacity());
    let closed = CancellationToken::new();

    let pending: Arc<parking_lot::Mutex<PendingPings>> = Arc::new(parking_lot::Mutex::new(
        PendingPings::new(inner.cfg().max_pending_pings()),
    ));

    {
        let conn = conn.clone();
        let peer = peer.clone();
        let inbound = inbound.clone();
        let inner = inner.clone();
        let closed = closed.clone();
        let pending = pending.clone();
        tokio::spawn(async move {
            run_read(conn, peer, inbound, inner, closed, pending).await;
        });
    }

    {
        let conn = conn.clone();
        let peer = peer.clone();
        let inner = inner.clone();
        let closed = closed.clone();
        let pending = pending.clone();
        tokio::spawn(async move {
            run_write(conn, peer, inner, rx, closed, pending).await;
        });
    }

    ActiveStream::new(TransportKind::Udp, tx, closed)
}

async fn run_read(
    conn: Arc<dyn UtilConn + Send + Sync>,
    peer: Arc<PeerState>,
    inbound: InboundDispatch,
    inner: Arc<ManagerInner>,
    closed: CancellationToken,
    pending: Arc<parking_lot::Mutex<PendingPings>>,
) {
    let mut buf = vec![0u8; inner.cfg().max_frame_bytes().max(2048)];
    let level = TransportKind::Udp.service_level();
    loop {
        tokio::select! {
            _ = closed.cancelled() => break,
            res = conn.recv(&mut buf) => {
                let n = match res {
                    Ok(n) => n,
                    Err(e) => {
                        debug!(peer=%peer.node_id(), error=?e, "udp dtls read error");
                        break;
                    }
                };
                if n == 0 {
                    break;
                }
                peer.metrics().record_recv(TransportKind::Udp, n);
                let frame = match pb::Frame::decode(&buf[..n]) {
                    Ok(f) => f,
                    Err(e) => {
                        warn!(peer=%peer.node_id(), error=%e, "udp dtls frame decode failed");
                        continue;
                    }
                };
                if let Err(e) = handle_frame(
                    frame, n, &conn, inner.self_id(), &peer, &inbound, &pending, level,
                ).await {
                    warn!(peer=%peer.node_id(), error=%e, "udp dtls inbound handling failed");
                    break;
                }
            }
        }
    }
    closed.cancel();
    // Map self-cleans via is_alive-filtering; see stream_io::run_pump for the
    // race rationale.
    let _ = conn.close().await;
    trace!(peer=%peer.node_id(), "udp dtls read pump exited");
}

async fn run_write(
    conn: Arc<dyn UtilConn + Send + Sync>,
    peer: Arc<PeerState>,
    inner: Arc<ManagerInner>,
    mut rx: mpsc::Receiver<OutboundFrame>,
    closed: CancellationToken,
    pending: Arc<parking_lot::Mutex<PendingPings>>,
) {
    let level = TransportKind::Udp.service_level();
    let probe_enabled = inner.cfg().bandwidth_probe_size() > 0;
    let mut ping_tick = MaybeInterval::maybe(inner.cfg().ping_interval());
    let mut probe_tick = if probe_enabled {
        MaybeInterval::maybe(inner.cfg().bandwidth_probe_interval())
    } else {
        MaybeInterval::Disabled
    };

    loop {
        tokio::select! {
            biased;
            _ = closed.cancelled() => break,

            maybe_out = rx.recv() => {
                let Some(out) = maybe_out else { break };
                let frame = build_frame(
                    inner.self_id(),
                    peer.node_id(),
                    level,
                    FrameType::Data,
                    out.class(),
                    peer.next_seq(),
                    now_us(),
                    out.payload().clone(),
                );
                if let Err(e) = send_frame(&conn, &frame, &peer, inner.cfg().udp_mtu()).await {
                    warn!(peer=%peer.node_id(), error=%e, "udp dtls write failed");
                    break;
                }
            }

            _ = ping_tick.tick() => {
                let ts = now_us();
                let frame = build_frame(
                    inner.self_id(), peer.node_id(), level,
                    FrameType::Ping, MessageClass::Regular,
                    peer.next_seq(), ts, Bytes::new(),
                );
                match send_frame(&conn, &frame, &peer, inner.cfg().udp_mtu()).await {
                    Ok(sent) => pending.lock().insert(ts, sent),
                    Err(e) => { warn!(peer=%peer.node_id(), error=%e, "udp dtls ping failed"); break; }
                }
            }

            _ = probe_tick.tick() => {
                let ts = now_us();
                let max_probe_payload = inner.cfg().udp_mtu().saturating_sub(128).min(inner.cfg().bandwidth_probe_size());
                if max_probe_payload == 0 { continue; }
                let payload = bytes::BytesMut::zeroed(max_probe_payload).freeze();
                let frame = build_frame(
                    inner.self_id(), peer.node_id(), level,
                    FrameType::Ping, MessageClass::Regular,
                    peer.next_seq(), ts, payload,
                );
                match send_frame(&conn, &frame, &peer, inner.cfg().udp_mtu()).await {
                    Ok(sent) => pending.lock().insert(ts, sent),
                    Err(e) => { warn!(peer=%peer.node_id(), error=%e, "udp dtls probe failed"); break; }
                }
            }
        }
    }
    closed.cancel();
    let _ = conn.close().await;
    trace!(peer=%peer.node_id(), "udp dtls write pump exited");
}

async fn send_frame(
    conn: &Arc<dyn UtilConn + Send + Sync>,
    frame: &pb::Frame,
    peer: &PeerState,
    udp_mtu: usize,
) -> io::Result<usize> {
    let mut buf = bytes::BytesMut::with_capacity(frame.encoded_len());
    frame
        .encode(&mut buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if buf.len() > udp_mtu {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("frame {} > udp_mtu {}", buf.len(), udp_mtu),
        ));
    }
    let n = conn
        .send(&buf)
        .await
        .map_err(|e| io::Error::other(format!("dtls send: {e}")))?;
    peer.metrics().record_sent(TransportKind::Udp, n);
    Ok(n)
}

async fn handle_frame(
    frame: pb::Frame,
    incoming_wire_size: usize,
    conn: &Arc<dyn UtilConn + Send + Sync>,
    local_id: NodeIdentifier,
    peer: &PeerState,
    inbound: &InboundDispatch,
    pending: &Arc<parking_lot::Mutex<PendingPings>>,
    level: ServiceLevel,
) -> io::Result<()> {
    let ty = match pb::FrameType::try_from(frame.frame_type) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    match ty {
        pb::FrameType::FrameData => {
            let class = pb::MessageClass::try_from(frame.message_class)
                .map(MessageClass::from)
                .unwrap_or(MessageClass::Regular);
            inbound.dispatch(InboundMessage::new(
                peer.node_id(),
                level,
                TransportKind::Udp,
                class,
                frame.payload,
            ));
        }
        pb::FrameType::FramePing => {
            let echo = frame.payload.clone();
            let pong = build_frame(
                local_id,
                peer.node_id(),
                level,
                FrameType::Pong,
                MessageClass::Regular,
                peer.next_seq(),
                frame.ts_us,
                echo,
            );
            let mut buf = bytes::BytesMut::with_capacity(pong.encoded_len());
            pong.encode(&mut buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let n = conn
                .send(&buf)
                .await
                .map_err(|e| io::Error::other(format!("dtls pong: {e}")))?;
            peer.metrics().record_sent(TransportKind::Udp, n);
        }
        pb::FrameType::FramePong => {
            let now = now_us();
            if now > frame.ts_us {
                let rtt = Duration::from_micros(now - frame.ts_us);
                peer.metrics().record_rtt(TransportKind::Udp, rtt);
                if let Some(sent_size) = pending.lock().take(frame.ts_us) {
                    let total = sent_size + incoming_wire_size;
                    if total >= 256 {
                        peer.metrics().record_probe(TransportKind::Udp, total, rtt);
                    }
                }
            }
        }
        pb::FrameType::FrameKeepalive | pb::FrameType::FrameHello => {}
        pb::FrameType::FrameBye => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "peer sent BYE",
            ));
        }
    }
    Ok(())
}

struct PendingPings {
    inner: VecDeque<(u64, usize)>,
    cap: usize,
}
impl PendingPings {
    fn new(cap: usize) -> Self {
        Self {
            inner: VecDeque::with_capacity(cap),
            cap,
        }
    }
    fn insert(&mut self, ts: u64, sent: usize) {
        if self.inner.len() >= self.cap {
            self.inner.pop_front();
        }
        self.inner.push_back((ts, sent));
    }
    fn take(&mut self, ts: u64) -> Option<usize> {
        let pos = self.inner.iter().position(|(t, _)| *t == ts)?;
        self.inner.remove(pos).map(|(_, b)| b)
    }
}

enum MaybeInterval {
    Active(Interval),
    Disabled,
}
impl MaybeInterval {
    fn maybe(period: Duration) -> Self {
        if period.is_zero() {
            Self::Disabled
        } else {
            let mut iv = interval(period);
            iv.reset();
            Self::Active(iv)
        }
    }
    async fn tick(&mut self) {
        match self {
            Self::Active(iv) => {
                iv.tick().await;
            }
            Self::Disabled => std::future::pending::<()>().await,
        }
    }
}

#[inline]
fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}
