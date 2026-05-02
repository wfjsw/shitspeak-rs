//! The pluggable wire-transport layer.
//!
//! Each transport (TCP, KCP, QUIC, UDP) is a `struct` that implements
//! [`Endpoint`]. Endpoints own all of their per-transport state — TLS configs,
//! bound listen sockets, the QUIC `quinn::Endpoint` handle, etc. — so the
//! manager itself stays free of transport-specific fields. The manager keeps
//! one `Arc<EndpointStruct>` per kind in [`EndpointRegistry`] and forwards
//! `start` and `dial` calls through that.
//!
//! Adding a fifth transport is mechanical:
//!   1. Add a variant to `TransportKind`.
//!   2. Define `XxxEndpoint` and `impl Endpoint for XxxEndpoint`.
//!   3. Add an `Option<Arc<XxxEndpoint>>` field to `EndpointRegistry`.
//!   4. Add one match arm each to [`start_all`] and [`dispatch_dial`].
//! The compiler flags every site that needs updating.

use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::sleep;
use tracing::debug;

use crate::types::NodeIdentifier;

use super::connection::PeerState;
use super::manager::ManagerInner;
use super::service_level::{PeerAddress, TransportKind};
use super::stream_io::{spawn_stream_pump, StreamPumpConfig};

pub(crate) mod kcp;
pub(crate) mod quic;
pub(crate) mod tcp;
pub(crate) mod udp;

/// Common shape for every wire transport. Implementations own their own
/// per-transport state and are wrapped in an `Arc` before being placed in
/// [`EndpointRegistry`]. Both required methods take `self: Arc<Self>` so
/// they can move clones into spawned tasks.
pub(crate) trait Endpoint: Send + Sync + 'static {
    /// Which `TransportKind` this endpoint provides. There is exactly one
    /// `Endpoint` impl per `TransportKind`.
    const KIND: TransportKind;

    /// Bind any listeners and spawn accept tasks. Called once after every
    /// endpoint has been registered. Returns once listeners are bound;
    /// accept tasks run in the background until `inner.shutdown` fires.
    /// If the endpoint is configured with `listen_addr = None` this is a
    /// no-op and dial-only operation is preserved.
    fn start(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
    ) -> impl Future<Output = io::Result<()>> + Send;

    /// Dial a peer at `addr`. On success the impl must have installed an
    /// `ActiveStream` of `KIND` into `peer.install_stream(...)`, typically
    /// via [`install_stream_session`] (for stream transports) or its own
    /// session-pump installer (for UDP/DTLS).
    fn dial(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
        peer: Arc<PeerState>,
        addr: SocketAddr,
    ) -> impl Future<Output = io::Result<()>> + Send;
}

/// Holds one shared endpoint per `TransportKind`. `None` means the local
/// node didn't configure that transport.
pub(crate) struct EndpointRegistry {
    tcp: Option<Arc<tcp::TcpEndpoint>>,
    kcp: Option<Arc<kcp::KcpEndpoint>>,
    quic: Option<Arc<quic::QuicEndpoint>>,
    udp: Option<Arc<udp::UdpEndpoint>>,
}

impl EndpointRegistry {
    pub fn new(
        tcp: Option<Arc<tcp::TcpEndpoint>>,
        kcp: Option<Arc<kcp::KcpEndpoint>>,
        quic: Option<Arc<quic::QuicEndpoint>>,
        udp: Option<Arc<udp::UdpEndpoint>>,
    ) -> Self {
        Self { tcp, kcp, quic, udp }
    }

    pub fn empty() -> Self {
        Self { tcp: None, kcp: None, quic: None, udp: None }
    }

    pub fn any_configured(&self) -> bool {
        self.tcp.is_some() || self.kcp.is_some() || self.quic.is_some() || self.udp.is_some()
    }

    pub fn tcp(&self) -> Option<&Arc<tcp::TcpEndpoint>> {
        self.tcp.as_ref()
    }

    pub fn kcp(&self) -> Option<&Arc<kcp::KcpEndpoint>> {
        self.kcp.as_ref()
    }

    pub fn quic(&self) -> Option<&Arc<quic::QuicEndpoint>> {
        self.quic.as_ref()
    }

    pub fn udp(&self) -> Option<&Arc<udp::UdpEndpoint>> {
        self.udp.as_ref()
    }
}

/// Run `Endpoint::start` on every registered endpoint in a fixed order.
/// Bind errors propagate up to `ConnectionManager::start`.
pub(crate) async fn start_all(inner: Arc<ManagerInner>) -> io::Result<()> {
    if let Some(ep) = inner.endpoints().tcp().cloned() {
        ep.start(inner.clone()).await?;
    }
    if let Some(ep) = inner.endpoints().kcp().cloned() {
        ep.start(inner.clone()).await?;
    }
    if let Some(ep) = inner.endpoints().quic().cloned() {
        ep.start(inner.clone()).await?;
    }
    if let Some(ep) = inner.endpoints().udp().cloned() {
        ep.start(inner).await?;
    }
    Ok(())
}

/// Stream-pump session installer shared by every byte-stream transport
/// (TCP, KCP, QUIC). Wraps `stream` in the framed read/write pump and
/// registers the resulting [`ActiveStream`] on `peer`. `is_dialer` indicates
/// whether this stream came from an outbound dial (`true`) or an inbound
/// accept (`false`) — used to break ties when both sides race a connection.
pub(crate) fn install_stream_session<S>(
    inner: &Arc<ManagerInner>,
    peer_node: NodeIdentifier,
    transport: TransportKind,
    is_dialer: bool,
    stream: S,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let peer = inner.get_or_create_peer(peer_node);
    let cfg = StreamPumpConfig::new(
        inner.self_id(),
        peer_node,
        transport,
        inner.cfg().max_frame_bytes(),
        inner.cfg().outbound_capacity(),
        inner.cfg().ping_interval(),
        inner.cfg().bandwidth_probe_interval(),
        inner.cfg().bandwidth_probe_size(),
    );
    let active = spawn_stream_pump(stream, cfg, peer.clone(), inner.inbound().clone());
    if let Err(rejected) = peer.try_install_stream(inner.self_id(), is_dialer, active) {
        // The existing stream wins the race; close the loser so its TCP/TLS
        // connection drops cleanly without disturbing the survivor.
        rejected.cancel();
    }
}

/// Supervisor: every `reconnect_check_interval`, walk the peer table and
/// spawn dial tasks for peers whose configured transports don't all have
/// a live session yet. The `connecting` AtomicBool gates concurrent dial
/// tasks per peer; the per-peer backoff state controls retry timing.
pub(crate) async fn run_supervisor(inner: Arc<ManagerInner>) {
    let interval = inner.cfg().reconnect_check_interval();
    loop {
        if inner.shutdown().is_cancelled() {
            return;
        }
        for (_node, peer) in inner.iter_peers() {
            if !needs_dial(&peer) {
                continue;
            }
            if !peer.try_begin_connect() {
                continue;
            }
            let inner_c = inner.clone();
            let peer_c = peer.clone();
            tokio::spawn(async move {
                let _ = try_dial_peer(&inner_c, &peer_c).await;
                peer_c.end_connect();
            });
        }
        tokio::select! {
            _ = sleep(interval) => {}
            _ = inner.shutdown().cancelled() => return,
        }
    }
}

/// True iff at least one configured transport for this peer has no live session.
fn needs_dial(peer: &PeerState) -> bool {
    let live: HashSet<TransportKind> = peer.live_kinds().into_iter().collect();
    peer.snapshot_addresses()
        .iter()
        .any(|a| !live.contains(&a.transport()))
}

async fn try_dial_peer(inner: &Arc<ManagerInner>, peer: &Arc<PeerState>) -> io::Result<()> {
    {
        let mut bo = peer.backoff().lock();
        if !bo.ready(Instant::now()) {
            return Ok(());
        }
        bo.record_attempt();
    }

    let addrs = peer.snapshot_addresses();
    if addrs.is_empty() {
        return Ok(());
    }

    let live: HashSet<TransportKind> = peer.live_kinds().into_iter().collect();
    let mut any_success = false;
    let mut last_err: Option<io::Error> = None;
    for addr in addrs {
        if live.contains(&addr.transport()) {
            continue;
        }
        match dispatch_dial(inner, peer, addr).await {
            Ok(()) => {
                debug!(peer=%peer.node_id(), transport=?addr.transport(), "dial succeeded");
                any_success = true;
            }
            Err(e) => {
                debug!(peer=%peer.node_id(), transport=?addr.transport(), error=%e, "dial failed");
                last_err = Some(e);
            }
        }
    }
    if any_success {
        peer.backoff().lock().record_success();
    } else if last_err.is_some() {
        peer.backoff().lock().record_failure();
    }
    if let Some(e) = last_err {
        return Err(e);
    }
    Ok(())
}

/// The single dispatch site that maps a `PeerAddress` to its endpoint's
/// `dial` method. Adding a new transport requires only one new arm here.
async fn dispatch_dial(
    inner: &Arc<ManagerInner>,
    peer: &Arc<PeerState>,
    addr: PeerAddress,
) -> io::Result<()> {
    match addr.transport() {
        TransportKind::Tcp => match inner.endpoints().tcp().cloned() {
            Some(ep) => ep.dial(inner.clone(), peer.clone(), addr.addr()).await,
            None => Err(unconfigured(TransportKind::Tcp)),
        },
        TransportKind::Kcp => match inner.endpoints().kcp().cloned() {
            Some(ep) => ep.dial(inner.clone(), peer.clone(), addr.addr()).await,
            None => Err(unconfigured(TransportKind::Kcp)),
        },
        TransportKind::Quic => match inner.endpoints().quic().cloned() {
            Some(ep) => ep.dial(inner.clone(), peer.clone(), addr.addr()).await,
            None => Err(unconfigured(TransportKind::Quic)),
        },
        TransportKind::Udp => match inner.endpoints().udp().cloned() {
            Some(ep) => ep.dial(inner.clone(), peer.clone(), addr.addr()).await,
            None => Err(unconfigured(TransportKind::Udp)),
        },
    }
}

fn unconfigured(kind: TransportKind) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{kind:?} endpoint not configured on this node"),
    )
}
