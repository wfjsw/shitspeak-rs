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
//! 1. Add a variant to `TransportKind`.
//! 2. Define `XxxEndpoint` and `impl Endpoint for XxxEndpoint`.
//! 3. Add an `Option<Arc<XxxEndpoint>>` field to `EndpointRegistry`.
//! 4. Add one match arm each to [`start_all`] and [`dispatch_dial`].
//! The compiler flags every site that needs updating.

use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use futures_util::future::join_all;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{sleep, timeout};
use tracing::{debug, trace, warn};

use crate::types::NodeIdentifier;

use super::config::TransportConfig;
use super::connection::{PeerState, StreamKey, retry_cap_for_last_seen_age};
use super::manager::ManagerInner;
use super::native_stats::BoxedNativeLossSampler;
use super::service_level::{PeerAddress, SeedAddress, TransportKind};
use super::stream_io::{StreamPumpConfig, spawn_stream_pump};

pub(crate) mod kcp;
pub(crate) mod mux;
pub(crate) mod quic;
pub(crate) mod tcp;
pub(crate) mod udp;
pub(crate) mod udp_batch;

pub(crate) fn ipv6_only_for_address(addr: SocketAddr, listen_addrs: &[SocketAddr]) -> bool {
    addr.is_ipv6()
        && listen_addrs
            .iter()
            .any(|candidate| candidate.is_ipv4() && candidate.port() == addr.port())
}

pub(crate) fn socket_addr_supports_remote(
    local_addr: SocketAddr,
    ipv6_only: bool,
    remote_addr: SocketAddr,
) -> bool {
    local_addr.is_ipv4() == remote_addr.is_ipv4()
        || (remote_addr.is_ipv4()
            && local_addr.is_ipv6()
            && !ipv6_only
            && local_addr.ip().is_unspecified())
}

pub(crate) async fn bind_tcp_listener(
    addr: SocketAddr,
    ipv6_only: bool,
) -> io::Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    set_socket_ipv6_only(&socket, addr, ipv6_only);
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

pub(crate) async fn bind_udp_socket_with_ipv6_only(
    addr: SocketAddr,
    ipv6_only: bool,
) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    set_socket_ipv6_only(&socket, addr, ipv6_only);
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

fn set_socket_ipv6_only(socket: &socket2::Socket, addr: SocketAddr, ipv6_only: bool) {
    if addr.is_ipv6()
        && let Err(e) = socket.set_only_v6(ipv6_only)
    {
        debug!(%addr, %ipv6_only, error=%e, "unable to set IPv6-only socket mode");
    }
}

/// Bind an exclusive ephemeral UDP socket for outbound stream-style dials.
///
/// Raw UDP packet encryption reuses the shared mux listener when one is
/// configured. Stream-style UDP transports such as KCP need a separate
/// ephemeral source port so inbound listener traffic cannot be routed into a
/// client-side TLS state machine, and so they do not share the raw UDP/QUIC
/// port.
pub(crate) async fn bind_ephemeral_udp_dial_socket(
    remote_addr: SocketAddr,
) -> io::Result<UdpSocket> {
    let bind_addr = if remote_addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    UdpSocket::bind(bind_addr).await
}

/// Common shape for every wire transport. Implementations own their own
/// per-transport state and are wrapped in an `Arc` before being placed in
/// [`EndpointRegistry`]. Both required methods take `self: Arc<Self>` so
/// they can move clones into spawned tasks.
pub(crate) trait Endpoint: Send + Sync + 'static {
    /// Bind any listeners and spawn accept tasks. Called once after every
    /// endpoint has been registered. Returns once listeners are bound;
    /// accept tasks run in the background until `inner.shutdown` fires.
    /// If the endpoint is configured with no listen addresses this is a no-op
    /// and dial-only operation is preserved.
    fn start(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
    ) -> impl Future<Output = io::Result<()>> + Send;

    /// Dial a peer at `addr`. On success the impl must have installed an
    /// `ActiveStream` into `peer.install_stream(...)`, typically via
    /// [`install_stream_session`] (for stream transports) or its own
    /// datagram-pump installer (for UDP packet encryption).
    fn dial(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
        peer: Arc<PeerState>,
        addr: SocketAddr,
    ) -> impl Future<Output = io::Result<()>> + Send;

    /// Dial an address whose node id is not yet known. The endpoint must
    /// complete authentication, extract the remote node id from the validated
    /// certificate, reject self-loops, and install the live connection under
    /// the discovered node.
    fn dial_unidentified(
        self: Arc<Self>,
        inner: Arc<ManagerInner>,
        addr: SocketAddr,
    ) -> impl Future<Output = io::Result<NodeIdentifier>> + Send;
}

/// Holds one shared endpoint per `TransportKind`. `None` means the local
/// node didn't configure that transport.
#[derive(Clone)]
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
        Self {
            tcp,
            kcp,
            quic,
            udp,
        }
    }

    pub fn empty() -> Self {
        Self {
            tcp: None,
            kcp: None,
            quic: None,
            udp: None,
        }
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
/// registers the resulting [`ActiveStream`] on `peer`. `remote_addr` and
/// `is_dialer` form part of the live-session key so multiple usable paths to
/// the same peer can coexist.
pub(crate) fn install_stream_session<S>(
    inner: &Arc<ManagerInner>,
    peer_node: NodeIdentifier,
    transport: TransportKind,
    remote_addr: Option<SocketAddr>,
    is_dialer: bool,
    stream: S,
    native_sampler: Option<BoxedNativeLossSampler>,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    if inner.shutdown().is_cancelled() {
        return;
    }

    let peer = inner.get_or_create_peer(peer_node);
    let cfg = StreamPumpConfig::new(
        inner.self_id(),
        peer_node,
        transport,
        inner.cfg().max_frame_bytes(),
        inner.cfg().outbound_capacity(),
        inner.cfg().ping_interval(),
        inner.cfg().idle_ping_interval(),
        inner.cfg().native_stats_interval(),
        inner.cfg().stream_write_timeout(),
        inner.cfg().compression_config().clone(),
        inner.cfg().max_pending_pings(),
    );
    let active = spawn_stream_pump(
        stream,
        cfg,
        peer.clone(),
        inner.inbound().clone(),
        remote_addr,
        is_dialer,
        inner.shutdown().child_token(),
        native_sampler,
    );
    if inner.shutdown().is_cancelled() {
        active.cancel();
        return;
    }
    if let Err(rejected) = peer.try_install_stream(active) {
        // The exact connection key is already live; close the duplicate without
        // disturbing the survivor.
        rejected.cancel();
    }
}

/// Supervisor: every `reconnect_check_interval`, walk the peer table and
/// spawn dial tasks for peers whose address candidates don't all have a live
/// outbound session yet. The `connecting` AtomicBool gates concurrent dial
/// batches per peer; per-address backoff state controls retry timing.
pub(crate) async fn run_supervisor(inner: Arc<ManagerInner>) {
    let interval = inner.cfg().reconnect_check_interval();
    let mut last_unselected_probe: Option<Instant> = None;
    loop {
        if inner.shutdown().is_cancelled() {
            return;
        }
        let now = Instant::now();
        let wall_now = SystemTime::now();
        let local_ip_capability = LocalIpCapability::discover();
        let mut candidates: Vec<_> = inner
            .iter_peers()
            .into_iter()
            .filter(|(_, peer)| needs_dial(peer, inner.cfg(), now, wall_now, local_ip_capability))
            .collect();
        let mandatory_targets = mandatory_backbone_targets(&inner);
        candidates.sort_by(|a, b| compare_dial_candidates(a, b, &mandatory_targets));

        for (node, peer) in candidates.iter() {
            let mandatory = mandatory_targets.contains(node);
            let cap_reached =
                inner.outgoing_connection_count() >= inner.cfg().max_outgoing_connections();
            if cap_reached && !mandatory {
                break;
            }
            if cap_reached {
                debug!(
                    peer = %peer.node_id(),
                    max_outgoing_connections = inner.cfg().max_outgoing_connections(),
                    "outgoing S2S connection cap reached; dialing backbone target to preserve topology connectivity"
                );
            }
            if !peer.try_begin_connect() {
                continue;
            }
            let inner_c = inner.clone();
            let peer_c = peer.clone();
            tokio::spawn(async move {
                let _ = try_dial_peer(&inner_c, &peer_c, mandatory).await;
                peer_c.end_connect();
            });
        }

        if inner.outgoing_connection_count() >= inner.cfg().max_outgoing_connections()
            && unselected_probe_due(
                last_unselected_probe,
                inner.cfg().unselected_link_probe_interval(),
                now,
            )
            && let Some((node, peer)) = select_unselected_probe_candidate(
                &candidates,
                &mandatory_targets,
                inner.cfg(),
                local_ip_capability,
            )
            && peer.try_begin_connect()
        {
            last_unselected_probe = Some(now);
            let inner_c = inner.clone();
            let peer_c = peer.clone();
            let probe_hold = exploratory_probe_hold_time(inner.cfg());
            tokio::spawn(async move {
                debug!(
                    peer = %node,
                    max_outgoing_connections = inner_c.cfg().max_outgoing_connections(),
                    "probing unselected S2S link beyond outgoing cap"
                );
                let _ = try_dial_peer(&inner_c, &peer_c, true).await;
                peer_c.end_connect();
                tokio::select! {
                    _ = sleep(probe_hold) => prune_outgoing_to_soft_cap(&inner_c),
                    _ = inner_c.shutdown().cancelled() => {}
                }
            });
        }

        let mut registered_addresses = None;
        for addr in inner.cfg().seed_targets() {
            if seed_address_registered_in_snapshot(&inner, &mut registered_addresses, &addr) {
                continue;
            }
            let inner_c = inner.clone();
            tokio::spawn(async move {
                match probe_seed_address(&inner_c, addr.clone()).await {
                    Some(Ok(node)) => debug!(peer=%node, ?addr, "seed dial succeeded"),
                    Some(Err(e)) => debug!(?addr, error=%e, "seed dial failed"),
                    None => {}
                }
            });
        }

        tokio::select! {
            _ = sleep(interval) => {}
            _ = inner.shutdown().cancelled() => return,
        }
    }
}

fn backbone_targets(inner: &ManagerInner) -> HashSet<NodeIdentifier> {
    let mut nodes: Vec<NodeIdentifier> = inner
        .iter_peers()
        .into_iter()
        .filter(|(_, peer)| !peer.snapshot_addresses().is_empty())
        .map(|(node, _)| node)
        .collect();
    nodes.push(inner.self_id());
    nodes.sort_unstable();
    nodes.dedup();

    let Some(self_pos) = nodes.iter().position(|node| *node == inner.self_id()) else {
        return HashSet::new();
    };

    let mut targets = inner.required_outgoing_nodes();
    for offset in backbone_offsets(nodes.len()) {
        let target = nodes[(self_pos + offset) % nodes.len()];
        if target == inner.self_id() {
            continue;
        }
        if inner
            .get_peer(target)
            .is_some_and(|peer| !peer.snapshot_addresses().is_empty())
        {
            targets.insert(target);
        }
    }
    targets.retain(|target| {
        *target != inner.self_id()
            && inner
                .get_peer(*target)
                .is_some_and(|peer| !peer.snapshot_addresses().is_empty())
    });
    targets
}

/// Pick deterministic ring/finger targets from the whole known node-id space.
/// These edges are topology-preservation dials, not quality-improvement dials:
/// every node tries its successor plus exponentially farther nodes so the
/// capped outbound set still contains bridges out of local low-latency groups.
fn mandatory_backbone_targets(inner: &ManagerInner) -> HashSet<NodeIdentifier> {
    let mut targets = backbone_targets(inner);
    targets.retain(|target| {
        inner
            .get_peer(*target)
            .is_some_and(|peer| !peer.has_any_live_stream())
    });
    targets
}

fn backbone_offsets(node_count: usize) -> Vec<usize> {
    if node_count <= 1 {
        return Vec::new();
    }

    let mut offsets = Vec::new();
    let mut push_offset = |offset: usize| {
        if offset > 0 && offset < node_count && !offsets.contains(&offset) {
            offsets.push(offset);
        }
    };

    push_offset(1);
    push_offset(node_count / 2);

    let mut offset = 2;
    while offset < node_count {
        push_offset(offset);
        offset = offset.saturating_mul(2);
    }

    offsets.sort_unstable();
    offsets
}

fn unselected_probe_due(last_probe: Option<Instant>, interval: Duration, now: Instant) -> bool {
    !interval.is_zero() && last_probe.is_none_or(|last| now.duration_since(last) >= interval)
}

fn select_unselected_probe_candidate(
    candidates: &[(NodeIdentifier, Arc<PeerState>)],
    mandatory_targets: &HashSet<NodeIdentifier>,
    cfg: &TransportConfig,
    local_ip_capability: LocalIpCapability,
) -> Option<(NodeIdentifier, Arc<PeerState>)> {
    let now = Instant::now();
    let wall_now = SystemTime::now();
    candidates
        .iter()
        .find(|(node, peer)| {
            !mandatory_targets.contains(node)
                && peer_retry_ready(peer, cfg, now, wall_now, local_ip_capability)
        })
        .map(|(node, peer)| (*node, peer.clone()))
}

fn peer_retry_ready(
    peer: &PeerState,
    cfg: &TransportConfig,
    now: Instant,
    wall_now: SystemTime,
    local_ip_capability: LocalIpCapability,
) -> bool {
    let has_live_connection = peer.has_any_live_stream();
    peer.snapshot_addresses().iter().any(|addr| {
        if !local_ip_capability.supports_remote(addr.addr().ip()) {
            return false;
        }
        if peer.has_live_outgoing_to(*addr) {
            return false;
        }
        let retry_policy = address_retry_policy(peer, cfg, *addr, wall_now, has_live_connection);
        peer.address_retry_ready(*addr, now, retry_policy.retry_cap())
    })
}

fn compare_dial_candidates(
    a: &(NodeIdentifier, Arc<PeerState>),
    b: &(NodeIdentifier, Arc<PeerState>),
    mandatory_targets: &HashSet<NodeIdentifier>,
) -> std::cmp::Ordering {
    (!mandatory_targets.contains(&a.0))
        .cmp(&(!mandatory_targets.contains(&b.0)))
        .then_with(|| {
            peer_priority(&a.1)
                .partial_cmp(&peer_priority(&b.1))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .then_with(|| a.0.cmp(&b.0))
}

/// True iff at least one known address candidate has no live outbound session.
fn needs_dial(
    peer: &PeerState,
    cfg: &TransportConfig,
    now: Instant,
    wall_now: SystemTime,
    local_ip_capability: LocalIpCapability,
) -> bool {
    peer_retry_ready(peer, cfg, now, wall_now, local_ip_capability)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LocalIpCapability {
    has_ipv6: bool,
}

impl LocalIpCapability {
    fn discover() -> Self {
        Self {
            has_ipv6: super::local_ip::has_usable_ipv6_address(),
        }
    }

    fn supports_remote(self, ip: IpAddr) -> bool {
        ip.is_ipv4() || self.has_ipv6
    }
}

#[derive(Clone, Copy, Debug)]
struct AddressRetryPolicy {
    retry_floor: Duration,
    retry_cap: Duration,
    unconfirmed_while_connected: bool,
}

impl AddressRetryPolicy {
    fn normal(retry_cap: Duration) -> Self {
        Self {
            retry_floor: Duration::ZERO,
            retry_cap,
            unconfirmed_while_connected: false,
        }
    }

    fn unconfirmed_while_connected(retry_floor: Duration, retry_cap: Duration) -> Self {
        Self {
            retry_floor,
            retry_cap: retry_cap.max(retry_floor),
            unconfirmed_while_connected: true,
        }
    }

    fn retry_cap(&self) -> Duration {
        self.retry_cap
    }

    fn retry_floor(&self) -> Duration {
        self.retry_floor
    }

    fn is_unconfirmed_while_connected(&self) -> bool {
        self.unconfirmed_while_connected
    }
}

fn address_retry_policy(
    peer: &PeerState,
    cfg: &TransportConfig,
    addr: PeerAddress,
    wall_now: SystemTime,
    has_live_connection: bool,
) -> AddressRetryPolicy {
    if has_live_connection && !peer.address_is_currently_confirmed(addr) {
        return AddressRetryPolicy::unconfirmed_while_connected(
            cfg.unconfirmed_address_retry_floor(),
            cfg.unconfirmed_address_retry_cap(),
        );
    }

    AddressRetryPolicy::normal(retry_cap_for_last_seen_age(
        peer.last_seen_age(wall_now),
        cfg.backoff_cap(),
        cfg.stale_backoff_cap(),
        cfg.stale_backoff_after(),
    ))
}

fn should_decay_unconfirmed_address(
    retry_policy: AddressRetryPolicy,
    backoff: super::connection::BackoffSnapshot,
    cfg: &TransportConfig,
) -> bool {
    retry_policy.is_unconfirmed_while_connected()
        && cfg.unconfirmed_address_decay_failures() > 0
        && backoff.consecutive_failures() >= cfg.unconfirmed_address_decay_failures()
        && backoff.next_delay() >= retry_policy.retry_cap()
}

fn peer_priority(peer: &PeerState) -> f64 {
    let metrics = peer.metrics().snapshot_per_transport();
    metrics
        .values()
        .filter_map(|metric| metric.quality_score())
        .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .map(|score| -score)
        .unwrap_or(f64::INFINITY)
}

fn exploratory_probe_hold_time(cfg: &TransportConfig) -> Duration {
    let ping_window = cfg.ping_interval() + cfg.ping_interval();
    cfg.reconnect_check_interval().max(ping_window)
}

fn prune_outgoing_to_soft_cap(inner: &Arc<ManagerInner>) {
    let max = inner.cfg().max_outgoing_connections();
    if inner.outgoing_connection_count() <= max {
        return;
    }

    let protected = backbone_targets(inner);
    let mut candidates: Vec<(f64, NodeIdentifier, StreamKey, Arc<PeerState>)> = Vec::new();
    for (node, peer) in inner.iter_peers() {
        if protected.contains(&node) {
            continue;
        }
        let metrics = peer.metrics().snapshot_per_transport();
        for key in peer.outgoing_live_keys() {
            let kind = key.transport();
            let score = metrics
                .get(&kind)
                .and_then(|metric| metric.quality_score())
                .unwrap_or(f64::NEG_INFINITY);
            candidates.push((score, node, key, peer.clone()));
        }
    }

    candidates.sort_by(|a, b| {
        a.0.partial_cmp(&b.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| kind_sort_order(a.2).cmp(&kind_sort_order(b.2)))
    });

    for (_score, node, key, peer) in candidates {
        if inner.outgoing_connection_count() <= max {
            break;
        }
        if peer.drop_outgoing_stream(key) {
            debug!(
                peer = %node,
                transport = ?key.transport(),
                max_outgoing_connections = max,
                "pruned exploratory S2S outbound link after probe window"
            );
        }
    }
}

fn kind_sort_order(key: StreamKey) -> u8 {
    key.transport() as u8
}

fn seed_address_registered(inner: &ManagerInner, addr: &SeedAddress) -> bool {
    seed_address_peer_addr(inner, addr)
        .is_some_and(|peer_addr| peer_address_registered(inner, peer_addr))
}

fn seed_address_registered_in_snapshot(
    inner: &ManagerInner,
    registered_addresses: &mut Option<HashSet<PeerAddress>>,
    addr: &SeedAddress,
) -> bool {
    seed_address_peer_addr(inner, addr).is_some_and(|peer_addr| {
        registered_addresses
            .get_or_insert_with(|| registered_peer_addresses(inner))
            .contains(&peer_addr)
    })
}

fn seed_address_peer_addr(inner: &ManagerInner, addr: &SeedAddress) -> Option<PeerAddress> {
    inner
        .successful_seed_address(addr)
        .or_else(|| addr.as_static_peer_address())
}

fn registered_peer_addresses(inner: &ManagerInner) -> HashSet<PeerAddress> {
    inner
        .iter_peers()
        .into_iter()
        .flat_map(|(_, peer)| peer.snapshot_addresses())
        .collect()
}

fn peer_address_registered(inner: &ManagerInner, addr: PeerAddress) -> bool {
    inner
        .iter_peers()
        .into_iter()
        .any(|(_, peer)| peer.snapshot_addresses().contains(&addr))
}

async fn try_dial_peer(
    inner: &Arc<ManagerInner>,
    peer: &Arc<PeerState>,
    allow_cap_override: bool,
) -> io::Result<()> {
    let addrs = peer.snapshot_addresses();
    if addrs.is_empty() {
        return Ok(());
    }

    let wall_now = SystemTime::now();
    let has_live_connection = peer.has_any_live_stream();
    let now = Instant::now();

    let mut attempts = Vec::new();
    let mut planned_outgoing = 0usize;
    let local_ip_capability = LocalIpCapability::discover();
    for addr in addrs {
        if !local_ip_capability.supports_remote(addr.addr().ip()) {
            // debug!(
            //     ?addr,
            //     "skipping S2S dial candidate without matching local outgoing IP family"
            // );
            continue;
        }
        let transport = addr.transport();
        if peer.has_live_outgoing_to(addr) {
            continue;
        }
        let retry_policy =
            address_retry_policy(peer, inner.cfg(), addr, wall_now, has_live_connection);
        if !peer.address_retry_ready(addr, now, retry_policy.retry_cap()) {
            continue;
        }
        if inner.outgoing_connection_count() + planned_outgoing
            >= inner.cfg().max_outgoing_connections()
        {
            if !allow_cap_override || planned_outgoing > 0 {
                debug!(
                    peer = %peer.node_id(),
                    max_outgoing_connections = inner.cfg().max_outgoing_connections(),
                    "outgoing S2S connection cap reached; delaying non-critical dial"
                );
                break;
            }
            debug!(
                peer = %peer.node_id(),
                transport = ?transport,
                max_outgoing_connections = inner.cfg().max_outgoing_connections(),
                "outgoing S2S connection cap reached; attempting backbone dial to prevent partition"
            );
        }
        peer.record_address_attempt(addr);
        planned_outgoing += 1;
        attempts.push(async move {
            let result = dispatch_dial_with_timeout(inner, peer, addr).await;
            (addr, transport, result)
        });
        if planned_outgoing >= inner.cfg().max_dial_attempts_per_peer_tick() {
            break;
        }
    }

    if attempts.is_empty() {
        return Ok(());
    }

    let mut any_success = false;
    let mut last_err: Option<io::Error> = None;
    for (addr, transport, result) in join_all(attempts).await {
        match result {
            Ok(()) => {
                peer.confirm_address(addr);
                peer.record_address_success(addr);
                debug!(peer=%peer.node_id(), transport=?transport, "dial succeeded");
                any_success = true;
            }
            Err(e) => {
                let removed = should_remove_failed_address(&e) && peer.remove_address(addr);
                if removed {
                    debug!(
                        peer=%peer.node_id(),
                        ?addr,
                        error=%e,
                        "removed peer address candidate after identity/ping validation failure"
                    );
                } else {
                    let retry_policy = address_retry_policy(
                        peer,
                        inner.cfg(),
                        addr,
                        SystemTime::now(),
                        peer.has_any_live_stream(),
                    );
                    let backoff = if retry_policy.is_unconfirmed_while_connected() {
                        peer.record_address_failure_with_floor(
                            addr,
                            retry_policy.retry_floor(),
                            retry_policy.retry_cap(),
                        )
                    } else {
                        peer.record_address_failure(addr, retry_policy.retry_cap())
                    };
                    if should_decay_unconfirmed_address(retry_policy, backoff, inner.cfg())
                        && peer.remove_address(addr)
                    {
                        debug!(
                            peer=%peer.node_id(),
                            ?addr,
                            transport=?transport,
                            error=%e,
                            retry_cap_ms=retry_policy.retry_cap().as_millis(),
                            next_backoff_base_ms=backoff.next_delay().as_millis(),
                            consecutive_failures=backoff.consecutive_failures(),
                            "decayed unconfirmed peer address after repeated dial failures"
                        );
                    } else if retry_policy.is_unconfirmed_while_connected() {
                        debug!(
                            peer=%peer.node_id(),
                            ?addr,
                            transport=?transport,
                            error=%e,
                            retry_in_ms=backoff.retry_delay().as_millis(),
                            retry_floor_ms=retry_policy.retry_floor().as_millis(),
                            retry_cap_ms=retry_policy.retry_cap().as_millis(),
                            next_backoff_base_ms=backoff.next_delay().as_millis(),
                            consecutive_failures=backoff.consecutive_failures(),
                            "dial failed for unconfirmed peer address; will retry with stale-address backoff"
                        );
                    } else {
                        if backoff.consecutive_failures() < 5 {
                            debug!(
                                peer=%peer.node_id(),
                                ?addr,
                                transport=?transport,
                                error=%e,
                                retry_in_ms=backoff.retry_delay().as_millis(),
                                retry_cap_ms=retry_policy.retry_cap().as_millis(),
                                next_backoff_base_ms=backoff.next_delay().as_millis(),
                                consecutive_failures=backoff.consecutive_failures(),
                                "dial failed; will retry with exponential backoff"
                            );
                        } else {
                            trace!(
                                peer=%peer.node_id(),
                                ?addr,
                                transport=?transport,
                                error=%e,
                                retry_in_ms=backoff.retry_delay().as_millis(),
                                retry_cap_ms=retry_policy.retry_cap().as_millis(),
                                next_backoff_base_ms=backoff.next_delay().as_millis(),
                                consecutive_failures=backoff.consecutive_failures(),
                                "dial failed; will retry with exponential backoff"
                            );
                        }
                    }
                }
                last_err = Some(e);
            }
        }
    }
    if any_success {
        return Ok(());
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

async fn dispatch_dial_with_timeout(
    inner: &Arc<ManagerInner>,
    peer: &Arc<PeerState>,
    addr: PeerAddress,
) -> io::Result<()> {
    let timeout_duration = inner.cfg().dial_attempt_timeout();
    if timeout_duration.is_zero() {
        return dispatch_dial(inner, peer, addr).await;
    }
    timeout(timeout_duration, dispatch_dial(inner, peer, addr))
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "S2S dial attempt timed out",
            ))
        })
}

fn should_remove_failed_address(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::InvalidData {
        return true;
    }
    let message = error.to_string();
    message.contains("invalid peer certificate")
        || message.contains("certificate not valid for name")
}

fn is_self_loop_error(error: &io::Error) -> bool {
    error.to_string().contains("self-loop rejected")
}

async fn dial_resolved_seed_address(
    inner: &Arc<ManagerInner>,
    addr: PeerAddress,
) -> io::Result<NodeIdentifier> {
    let node = match addr.transport() {
        TransportKind::Tcp => match inner.endpoints().tcp().cloned() {
            Some(ep) => ep.dial_unidentified(inner.clone(), addr.addr()).await?,
            None => return Err(unconfigured(TransportKind::Tcp)),
        },
        TransportKind::Kcp => match inner.endpoints().kcp().cloned() {
            Some(ep) => ep.dial_unidentified(inner.clone(), addr.addr()).await?,
            None => return Err(unconfigured(TransportKind::Kcp)),
        },
        TransportKind::Quic => match inner.endpoints().quic().cloned() {
            Some(ep) => ep.dial_unidentified(inner.clone(), addr.addr()).await?,
            None => return Err(unconfigured(TransportKind::Quic)),
        },
        TransportKind::Udp => match inner.endpoints().udp().cloned() {
            Some(ep) => ep.dial_unidentified(inner.clone(), addr.addr()).await?,
            None => return Err(unconfigured(TransportKind::Udp)),
        },
    };
    let peer = inner.get_or_create_peer(node);
    peer.add_address(addr);
    Ok(node)
}

fn resolve_seed_address(seed: &SeedAddress) -> io::Result<Vec<PeerAddress>> {
    resolve_seed_address_with_capability(seed, LocalIpCapability::discover())
}

fn resolve_seed_address_with_capability(
    seed: &SeedAddress,
    local_ip_capability: LocalIpCapability,
) -> io::Result<Vec<PeerAddress>> {
    let mut addrs = Vec::new();
    let mut seen = HashSet::new();
    for addr in seed.addr().to_socket_addrs()? {
        if !local_ip_capability.supports_remote(addr.ip()) {
            debug!(
                %addr,
                seed = seed.addr(),
                "skipping resolved S2S seed address without matching local outgoing IP family"
            );
            continue;
        }
        let peer_addr = PeerAddress::new(addr, seed.transport());
        if peer_addr.is_dialable() && seen.insert(peer_addr) {
            addrs.push(peer_addr);
        }
    }
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!(
                "seed address {:?} resolved to no dialable addresses",
                seed.addr()
            ),
        ));
    }
    Ok(addrs)
}

pub(crate) async fn dial_seed_address(
    inner: &Arc<ManagerInner>,
    seed: &SeedAddress,
) -> io::Result<NodeIdentifier> {
    let resolved_addrs = resolve_seed_address(seed)?;
    let mut self_addrs = Vec::new();
    let addrs: Vec<_> = resolved_addrs
        .into_iter()
        .filter(|addr| {
            if seed_address_is_local(inner.cfg(), *addr) {
                self_addrs.push(*addr);
                false
            } else {
                true
            }
        })
        .collect();
    if addrs.is_empty() && !self_addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!(
                "seed address {:?} resolved only to local S2S addresses: {:?}",
                seed.addr(),
                self_addrs
            ),
        ));
    }
    let mut last_err = None;
    for addr in addrs {
        match dial_resolved_seed_address(inner, addr).await {
            Ok(node) => {
                inner.mark_seed_successful(seed.clone(), addr);
                return Ok(node);
            }
            Err(error) => {
                if is_self_loop_error(&error) {
                    return Err(error);
                }
                last_err = Some(error);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("seed address {:?} resolved to no addresses", seed.addr()),
        )
    }))
}

pub(crate) async fn probe_seed_address(
    inner: &Arc<ManagerInner>,
    addr: SeedAddress,
) -> Option<io::Result<NodeIdentifier>> {
    if seed_address_registered(inner, &addr) {
        return None;
    }
    let now = Instant::now();
    if inner.self_seed_quarantine_active(&addr, now) {
        return None;
    }
    let backoff = inner.seed_backoff(addr.clone());
    {
        let mut bo = backoff.lock();
        if !bo.ready(now, inner.cfg().backoff_cap()) {
            return None;
        }
        bo.record_attempt();
    }

    let result = dial_seed_address(inner, &addr).await;
    match &result {
        Ok(_) => {
            backoff.lock().record_success();
        }
        Err(error) if is_self_loop_error(error) || seed_error_resolved_only_to_local(error) => {
            let should_log = inner.quarantine_self_seed(addr.clone(), Instant::now());
            if should_log {
                warn!(
                    ?addr,
                    quarantine_secs = inner.cfg().self_seed_quarantine().as_secs(),
                    error = %error,
                    "quarantined S2S seed because it resolves back to the local node"
                );
            }
            backoff
                .lock()
                .record_failure(inner.cfg().self_seed_quarantine());
        }
        Err(_) => backoff.lock().record_failure(inner.cfg().backoff_cap()),
    }
    Some(result)
}

fn seed_error_resolved_only_to_local(error: &io::Error) -> bool {
    error
        .to_string()
        .contains("resolved only to local S2S addresses")
}

fn seed_address_is_local(cfg: &TransportConfig, addr: PeerAddress) -> bool {
    let socket = addr.addr();
    if local_advertised_sockets(cfg, addr.transport()).contains(&socket) {
        return true;
    }
    let listen_ports = local_listen_ports(cfg, addr.transport());
    if !listen_ports.contains(&socket.port()) {
        return false;
    }
    local_interface_ips(cfg).contains(&socket.ip())
}

fn local_advertised_sockets(cfg: &TransportConfig, transport: TransportKind) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let addrs = match transport {
        TransportKind::Tcp => cfg.tcp_advertise(),
        TransportKind::Kcp => cfg.kcp_advertise(),
        TransportKind::Quic => cfg.quic_advertise(),
        TransportKind::Udp => cfg.udp_advertise(),
    };
    out.extend(
        addrs
            .iter()
            .filter(|addr| !addr.ip().is_unspecified())
            .copied(),
    );
    let listen = match transport {
        TransportKind::Tcp => cfg.tcp_listen_addrs(),
        TransportKind::Kcp => cfg.kcp_listen_addrs(),
        TransportKind::Quic => cfg.quic_listen_addrs(),
        TransportKind::Udp => cfg.udp_listen_addrs(),
    };
    out.extend(
        listen
            .iter()
            .filter(|addr| !addr.ip().is_unspecified())
            .copied(),
    );
    out.sort_unstable();
    out.dedup();
    out
}

fn local_listen_ports(cfg: &TransportConfig, transport: TransportKind) -> HashSet<u16> {
    let addrs = match transport {
        TransportKind::Tcp => cfg.tcp_listen_addrs(),
        TransportKind::Kcp => cfg.kcp_listen_addrs(),
        TransportKind::Quic => cfg.quic_listen_addrs(),
        TransportKind::Udp => cfg.udp_listen_addrs(),
    };
    addrs.iter().map(|addr| addr.port()).collect()
}

fn local_interface_ips(cfg: &TransportConfig) -> HashSet<IpAddr> {
    let mut ips = super::local_ip::discover_all_interface_ips();
    ips.extend(super::local_ip::discover_interface_ips(
        cfg.local_advertise_interfaces(),
    ));
    ips.push(IpAddr::from([127, 0, 0, 1]));
    ips.push(IpAddr::from(std::net::Ipv6Addr::LOCALHOST));
    ips.into_iter().collect()
}

fn unconfigured(kind: TransportKind) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{kind:?} endpoint not configured on this node"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;

    use super::super::connection::ActiveStream;
    use super::super::metrics::MetricsTuning;

    fn tcp_peer_address(node_id: NodeIdentifier) -> PeerAddress {
        PeerAddress::new(
            format!("127.0.0.1:{}", 10_000 + node_id).parse().unwrap(),
            TransportKind::Tcp,
        )
    }

    fn peer_with_tcp_address(node_id: NodeIdentifier) -> Arc<PeerState> {
        let peer = PeerState::new(
            node_id,
            Duration::from_millis(10),
            Duration::from_secs(1),
            MetricsTuning::default(),
            1024 * 1024,
        );
        peer.add_address(tcp_peer_address(node_id));
        peer
    }

    fn install_live_stream(peer: &PeerState) {
        let budget = super::super::adaptive_queue::AdaptiveQueueBudget::new(1024 * 1024);
        let (tx, rx) =
            super::super::adaptive_queue::AdaptiveQueueSender::new(budget.split(1024 * 1024));
        std::mem::forget(rx);
        peer.install_stream(ActiveStream::new(
            TransportKind::Tcp,
            None,
            tx,
            CancellationToken::new(),
            false,
        ));
    }

    fn install_live_stream_at(peer: &PeerState, remote_addr: &str) {
        let budget = super::super::adaptive_queue::AdaptiveQueueBudget::new(1024 * 1024);
        let (tx, rx) =
            super::super::adaptive_queue::AdaptiveQueueSender::new(budget.split(1024 * 1024));
        std::mem::forget(rx);
        peer.install_stream(ActiveStream::new(
            TransportKind::Tcp,
            Some(remote_addr.parse().unwrap()),
            tx,
            CancellationToken::new(),
            false,
        ));
    }

    #[test]
    fn backbone_offsets_cover_successor_and_far_nodes() {
        assert_eq!(backbone_offsets(1), Vec::<usize>::new());
        assert_eq!(backbone_offsets(2), vec![1]);
        assert_eq!(backbone_offsets(7), vec![1, 2, 3, 4]);
        assert_eq!(backbone_offsets(16), vec![1, 2, 4, 8]);
    }

    #[test]
    fn ipv6_wildcard_is_dual_stack_unless_v4_socket_is_also_configured() {
        let v6: SocketAddr = "[::]:64739".parse().unwrap();
        let v4: SocketAddr = "0.0.0.0:64739".parse().unwrap();

        assert!(!ipv6_only_for_address(v6, &[v6]));
        assert!(socket_addr_supports_remote(
            v6,
            false,
            "172.23.0.7:64739".parse().unwrap()
        ));
        assert!(ipv6_only_for_address(v6, &[v4, v6]));
        assert!(!socket_addr_supports_remote(
            v6,
            true,
            "172.23.0.7:64739".parse().unwrap()
        ));
    }

    #[test]
    fn mandatory_backbone_candidate_sorts_before_high_quality_candidate() {
        let backbone = peer_with_tcp_address(2);
        let connected = peer_with_tcp_address(3);
        install_live_stream(&connected);
        connected
            .metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(1));
        connected
            .metrics()
            .record_payload_sent(TransportKind::Tcp, 1024 * 1024);

        let mut candidates = vec![
            (connected.node_id(), connected),
            (backbone.node_id(), backbone),
        ];
        let mandatory = HashSet::from([2]);
        candidates.sort_by(|a, b| compare_dial_candidates(a, b, &mandatory));

        assert_eq!(candidates[0].0, 2);
    }

    #[test]
    fn unselected_probe_interval_gates_exploratory_dials() {
        let now = Instant::now();
        let interval = Duration::from_secs(30);

        assert!(!unselected_probe_due(None, Duration::ZERO, now));
        assert!(unselected_probe_due(None, interval, now));
        assert!(!unselected_probe_due(
            Some(now - Duration::from_secs(10)),
            interval,
            now
        ));
        assert!(unselected_probe_due(
            Some(now - Duration::from_secs(30)),
            interval,
            now
        ));
    }

    #[test]
    fn exploratory_probe_hold_uses_reconnect_interval_without_bandwidth_probe_round_trip() {
        let cfg = TransportConfig::new("ca.pem".into(), "cert.pem".into(), "key.pem".into())
            .with_reconnect_check_interval(Duration::from_secs(1))
            .with_ping_interval(Duration::from_secs(2))
            .with_bandwidth_probe_interval(Duration::from_secs(10))
            .with_bandwidth_probe_size(1024);

        assert_eq!(exploratory_probe_hold_time(&cfg), Duration::from_secs(4));
    }

    #[test]
    fn unselected_probe_candidate_skips_mandatory_and_backed_off_peers() {
        let cfg = TransportConfig::new("ca.pem".into(), "cert.pem".into(), "key.pem".into())
            .with_backoff_initial(Duration::from_secs(30))
            .with_backoff_cap(Duration::from_secs(30));
        let mandatory = peer_with_tcp_address(2);
        let backed_off = peer_with_tcp_address(3);
        backed_off.record_address_attempt(tcp_peer_address(3));
        let ready = peer_with_tcp_address(4);
        let candidates = vec![
            (mandatory.node_id(), mandatory),
            (backed_off.node_id(), backed_off),
            (ready.node_id(), ready),
        ];
        let selected = select_unselected_probe_candidate(
            &candidates,
            &HashSet::from([2]),
            &cfg,
            LocalIpCapability { has_ipv6: true },
        )
        .expect("ready non-mandatory peer should be selected");

        assert_eq!(selected.0, 4);
    }

    #[test]
    fn local_ip_capability_skips_ipv6_when_no_usable_local_ipv6_exists() {
        let v4_only = LocalIpCapability { has_ipv6: false };
        let dual_stack = LocalIpCapability { has_ipv6: true };

        assert!(v4_only.supports_remote("100.64.12.34".parse().unwrap()));
        assert!(!v4_only.supports_remote("fd00::12".parse().unwrap()));
        assert!(dual_stack.supports_remote("fd00::12".parse().unwrap()));
    }

    #[test]
    fn peer_retry_ready_ignores_ipv6_candidate_without_local_ipv6() {
        let cfg = TransportConfig::new("ca.pem".into(), "cert.pem".into(), "key.pem".into());
        let peer = PeerState::new(
            2,
            Duration::from_millis(10),
            Duration::from_secs(1),
            MetricsTuning::default(),
            1024 * 1024,
        );
        peer.add_address(PeerAddress::new(
            "[fd00::12]:64739".parse().unwrap(),
            TransportKind::Tcp,
        ));

        assert!(!peer_retry_ready(
            &peer,
            &cfg,
            Instant::now(),
            SystemTime::now(),
            LocalIpCapability { has_ipv6: false },
        ));
        assert!(peer_retry_ready(
            &peer,
            &cfg,
            Instant::now(),
            SystemTime::now(),
            LocalIpCapability { has_ipv6: true },
        ));
    }

    #[test]
    fn seed_resolution_skips_ipv6_without_local_ipv6() {
        let seed = SeedAddress::new("[fd00::12]:64739".to_string(), TransportKind::Tcp);
        let err =
            resolve_seed_address_with_capability(&seed, LocalIpCapability { has_ipv6: false })
                .expect_err("IPv6 seed is not usable on an IPv4-only host");

        assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
        assert_eq!(
            resolve_seed_address_with_capability(&seed, LocalIpCapability { has_ipv6: true })
                .expect("IPv6 seed remains usable when local IPv6 exists"),
            vec![PeerAddress::new(
                "[fd00::12]:64739".parse().unwrap(),
                TransportKind::Tcp,
            )]
        );
    }

    #[test]
    fn retry_policy_uses_stale_address_backoff_only_when_peer_is_connected() {
        let cfg = TransportConfig::new("ca.pem".into(), "cert.pem".into(), "key.pem".into())
            .with_backoff_cap(Duration::from_secs(30))
            .with_unconfirmed_address_retry_floor(Duration::from_secs(5 * 60))
            .with_unconfirmed_address_retry_cap(Duration::from_secs(30 * 60));
        let peer = peer_with_tcp_address(2);
        let addr = tcp_peer_address(2);

        let disconnected = address_retry_policy(
            &peer,
            &cfg,
            addr,
            SystemTime::now(),
            peer.has_any_live_stream(),
        );
        assert!(!disconnected.is_unconfirmed_while_connected());
        assert_eq!(disconnected.retry_cap(), Duration::from_secs(30));

        install_live_stream_at(&peer, "10.9.9.9:51000");
        let connected = address_retry_policy(
            &peer,
            &cfg,
            addr,
            SystemTime::now(),
            peer.has_any_live_stream(),
        );
        assert!(connected.is_unconfirmed_while_connected());
        assert_eq!(connected.retry_floor(), Duration::from_secs(5 * 60));
        assert_eq!(connected.retry_cap(), Duration::from_secs(30 * 60));
    }

    #[test]
    fn retry_policy_keeps_normal_backoff_for_advertised_or_observed_addresses() {
        let cfg = TransportConfig::new("ca.pem".into(), "cert.pem".into(), "key.pem".into())
            .with_backoff_cap(Duration::from_secs(30));
        let peer = peer_with_tcp_address(2);
        let advertised = tcp_peer_address(2);
        let observed_ip = PeerAddress::new("10.9.9.9:64741".parse().unwrap(), TransportKind::Quic);
        peer.replace_advertised_addresses(&[advertised]);
        install_live_stream_at(&peer, "10.9.9.9:51000");

        let advertised_policy = address_retry_policy(
            &peer,
            &cfg,
            advertised,
            SystemTime::now(),
            peer.has_any_live_stream(),
        );
        let observed_policy = address_retry_policy(
            &peer,
            &cfg,
            observed_ip,
            SystemTime::now(),
            peer.has_any_live_stream(),
        );

        assert!(!advertised_policy.is_unconfirmed_while_connected());
        assert!(!observed_policy.is_unconfirmed_while_connected());
        assert_eq!(advertised_policy.retry_cap(), Duration::from_secs(30));
        assert_eq!(observed_policy.retry_cap(), Duration::from_secs(30));
    }

    #[test]
    fn stale_address_decay_waits_for_capped_failures() {
        let cfg = TransportConfig::new("ca.pem".into(), "cert.pem".into(), "key.pem".into())
            .with_unconfirmed_address_retry_floor(Duration::from_secs(5 * 60))
            .with_unconfirmed_address_retry_cap(Duration::from_secs(30 * 60))
            .with_unconfirmed_address_decay_failures(5);
        let policy = AddressRetryPolicy::unconfirmed_while_connected(
            cfg.unconfirmed_address_retry_floor(),
            cfg.unconfirmed_address_retry_cap(),
        );
        let peer = peer_with_tcp_address(2);
        let addr = tcp_peer_address(2);

        for _ in 0..4 {
            let backoff = peer.record_address_failure_with_floor(
                addr,
                policy.retry_floor(),
                policy.retry_cap(),
            );
            assert!(!should_decay_unconfirmed_address(policy, backoff, &cfg));
        }

        let backoff =
            peer.record_address_failure_with_floor(addr, policy.retry_floor(), policy.retry_cap());
        assert!(should_decay_unconfirmed_address(policy, backoff, &cfg));
    }

    #[test]
    fn failed_address_pruning_recognizes_certificate_name_errors() {
        let err = io::Error::other(
            "handshake: invalid peer certificate: certificate not valid for name \"node-4\"",
        );
        assert!(should_remove_failed_address(&err));
    }

    #[test]
    fn failed_address_pruning_keeps_transient_dial_errors() {
        let refused = io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused");
        let timed_out = io::Error::new(io::ErrorKind::TimedOut, "S2S dial attempt timed out");

        assert!(!should_remove_failed_address(&refused));
        assert!(!should_remove_failed_address(&timed_out));
    }
}
