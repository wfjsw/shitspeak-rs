//! `ConnectionManager` — public face of the transport module.
//!
//! Holds the peer table, the inbound dispatch sinks, the shutdown signal, and
//! a registry of per-transport endpoints. Each endpoint owns its own state
//! (TLS configs, bound listener, `quinn::Endpoint`, etc.) so the manager
//! itself stays free of transport-specific fields.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use parking_lot::RwLock;
use scc::HashMap as SccMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::types::NodeIdentifier;

use super::config::TransportConfig;
use super::connection::{BackoffState, OutboundFrame, PeerState};
use super::endpoint::{
    kcp::KcpEndpoint, quic::QuicEndpoint, tcp::TcpEndpoint, udp::UdpEndpoint, EndpointRegistry,
};
use super::error::{ConfigError, SendError, TransportError};
use super::identity::NodeIdentity;
use super::metrics::{assemble_snapshot, MetricsSnapshot, MetricsTuning};
use super::service_level::{MessageClass, PeerAddress, ServiceLevel, TransportKind};
use super::tls::build_tls_configs;

#[derive(Debug, Clone)]
pub(crate) struct PeerAddressSnapshot {
    node_id: NodeIdentifier,
    addresses: Vec<PeerAddress>,
    last_seen: Option<SystemTime>,
}

impl PeerAddressSnapshot {
    pub(crate) fn node_id(&self) -> NodeIdentifier {
        self.node_id
    }

    pub(crate) fn addresses(&self) -> &[PeerAddress] {
        &self.addresses
    }

    pub(crate) fn last_seen(&self) -> Option<SystemTime> {
        self.last_seen
    }
}

/// Inbound message handed to the caller via one of the two mpscs in
/// [`Inbound`]. The caller owns the receivers; the manager keeps the senders.
#[derive(Debug)]
pub struct InboundMessage {
    from: NodeIdentifier,
    level: ServiceLevel,
    transport: TransportKind,
    class: MessageClass,
    payload: Bytes,
}

impl InboundMessage {
    pub(crate) fn new(
        from: NodeIdentifier,
        level: ServiceLevel,
        transport: TransportKind,
        class: MessageClass,
        payload: Bytes,
    ) -> Self {
        Self {
            from,
            level,
            transport,
            class,
            payload,
        }
    }

    pub fn from(&self) -> NodeIdentifier {
        self.from
    }

    pub fn level(&self) -> ServiceLevel {
        self.level
    }

    pub fn transport(&self) -> TransportKind {
        self.transport
    }

    pub fn class(&self) -> MessageClass {
        self.class
    }

    pub fn payload(&self) -> &Bytes {
        &self.payload
    }
}

/// Receiver halves returned once at `start`.
pub struct Inbound {
    high_priority: mpsc::Receiver<InboundMessage>,
    regular: mpsc::Receiver<InboundMessage>,
}

impl Inbound {
    pub(crate) fn new(
        high_priority: mpsc::Receiver<InboundMessage>,
        regular: mpsc::Receiver<InboundMessage>,
    ) -> Self {
        Self {
            high_priority,
            regular,
        }
    }

    pub fn high_priority(&mut self) -> &mut mpsc::Receiver<InboundMessage> {
        &mut self.high_priority
    }

    pub fn regular(&mut self) -> &mut mpsc::Receiver<InboundMessage> {
        &mut self.regular
    }

    /// Consume the handle and return the two receivers (high-priority, regular).
    /// Used by callers (e.g. the overlay dispatcher) that want to take owned
    /// halves into separate tasks.
    pub fn into_parts(
        self,
    ) -> (
        mpsc::Receiver<InboundMessage>,
        mpsc::Receiver<InboundMessage>,
    ) {
        (self.high_priority, self.regular)
    }
}

/// Sender halves used by all stream/datagram pumps. Cheap to clone.
#[derive(Clone)]
pub(crate) struct InboundDispatch {
    high: mpsc::Sender<InboundMessage>,
    regular: mpsc::Sender<InboundMessage>,
}

impl InboundDispatch {
    pub fn new(high: mpsc::Sender<InboundMessage>, regular: mpsc::Sender<InboundMessage>) -> Self {
        Self { high, regular }
    }

    pub fn dispatch(&self, msg: InboundMessage) {
        match msg.class {
            MessageClass::HighPriority => {
                if let Err(e) = self.high.try_send(msg) {
                    warn!(error=%e, "high-priority inbound queue full; dropping frame");
                }
            }
            MessageClass::Regular => {
                if let Err(e) = self.regular.try_send(msg) {
                    warn!(error=%e, "regular inbound queue full; dropping frame");
                }
            }
        }
    }
}

/// Internal state shared across the manager handle, supervisor task, and all
/// endpoint accept/dial loops. Transport-specific state lives inside the
/// individual endpoints reachable through `endpoints`.
pub(crate) struct ManagerInner {
    self_id: NodeIdentifier,
    peers: Arc<SccMap<NodeIdentifier, Arc<PeerState>>>,
    seed_backoff: Arc<SccMap<PeerAddress, Arc<parking_lot::Mutex<BackoffState>>>>,
    required_outgoing: Arc<RwLock<HashSet<NodeIdentifier>>>,
    inbound: InboundDispatch,
    shutdown: CancellationToken,
    cfg: TransportConfig,
    endpoints: EndpointRegistry,
}

impl ManagerInner {
    pub fn self_id(&self) -> NodeIdentifier {
        self.self_id
    }

    pub fn inbound(&self) -> &InboundDispatch {
        &self.inbound
    }

    pub fn shutdown(&self) -> &CancellationToken {
        &self.shutdown
    }

    pub fn cfg(&self) -> &TransportConfig {
        &self.cfg
    }

    pub fn endpoints(&self) -> &EndpointRegistry {
        &self.endpoints
    }

    pub fn get_or_create_peer(&self, id: NodeIdentifier) -> Arc<PeerState> {
        if let Some(existing) = self.peers.get_sync(&id) {
            return existing.get().clone();
        }
        let new = PeerState::new(
            id,
            self.cfg.backoff_initial(),
            self.cfg.bandwidth_window(),
            MetricsTuning {
                latency_alpha: self.cfg.latency_ewma_alpha(),
                jitter_alpha: self.cfg.jitter_ewma_alpha(),
                throughput_alpha: self.cfg.throughput_ewma_alpha(),
            },
        );
        match self.peers.entry_sync(id) {
            scc::hash_map::Entry::Occupied(e) => e.get().clone(),
            scc::hash_map::Entry::Vacant(e) => {
                e.insert_entry(new.clone());
                new
            }
        }
    }

    pub fn get_peer(&self, id: NodeIdentifier) -> Option<Arc<PeerState>> {
        self.peers.get_sync(&id).map(|e| e.get().clone())
    }

    pub fn remove_peer(&self, id: NodeIdentifier) -> Option<Arc<PeerState>> {
        self.peers.remove_sync(&id).map(|(_, v)| v)
    }

    pub fn iter_peers(&self) -> Vec<(NodeIdentifier, Arc<PeerState>)> {
        let mut out = Vec::new();
        self.peers.iter_sync(|id, peer| {
            out.push((*id, peer.clone()));
            true
        });
        out
    }

    pub fn outgoing_connection_count(&self) -> usize {
        self.iter_peers()
            .into_iter()
            .map(|(_, peer)| peer.outgoing_live_count())
            .sum()
    }

    pub fn required_outgoing_nodes(&self) -> HashSet<NodeIdentifier> {
        self.required_outgoing.read().clone()
    }

    pub fn set_required_outgoing_nodes(&self, nodes: HashSet<NodeIdentifier>) {
        *self.required_outgoing.write() = nodes;
    }

    pub fn seed_backoff(&self, addr: PeerAddress) -> Arc<parking_lot::Mutex<BackoffState>> {
        if let Some(existing) = self.seed_backoff.get_sync(&addr) {
            return existing.get().clone();
        }
        let new = Arc::new(parking_lot::Mutex::new(BackoffState::new(
            self.cfg.backoff_initial(),
        )));
        match self.seed_backoff.entry_sync(addr) {
            scc::hash_map::Entry::Occupied(e) => e.get().clone(),
            scc::hash_map::Entry::Vacant(e) => {
                e.insert_entry(new.clone());
                new
            }
        }
    }
}

/// Public handle.
#[derive(Clone)]
pub struct ConnectionManager {
    pub(crate) inner: Arc<ManagerInner>,
}

impl ConnectionManager {
    /// Bring up listeners, build TLS configs, install peer table, and return
    /// the handle along with the two inbound receivers.
    pub async fn start(cfg: TransportConfig) -> Result<(Self, Inbound), TransportError> {
        let identity = Arc::new(NodeIdentity::load(
            cfg.ca_path(),
            cfg.cert_path(),
            cfg.key_path(),
        )?);
        let (server_tls, client_tls) = build_tls_configs(&identity)?;

        let endpoints = build_endpoints(&cfg, identity.clone(), server_tls, client_tls)?;
        if !endpoints.any_configured() {
            return Err(ConfigError::NoListener.into());
        }

        let (high_tx, high_rx) = mpsc::channel(cfg.inbound_high_capacity());
        let (regular_tx, regular_rx) = mpsc::channel(cfg.inbound_regular_capacity());
        let inbound = InboundDispatch::new(high_tx, regular_tx);

        let inner = Arc::new(ManagerInner {
            self_id: identity.node_id(),
            peers: Arc::new(SccMap::new()),
            seed_backoff: Arc::new(SccMap::new()),
            required_outgoing: Arc::new(RwLock::new(HashSet::new())),
            inbound,
            shutdown: CancellationToken::new(),
            endpoints,
            cfg,
        });

        super::endpoint::start_all(inner.clone()).await?;
        for addr in inner.cfg().seed_addresses().iter().copied() {
            let inner_c = inner.clone();
            tokio::spawn(async move {
                match super::endpoint::probe_seed_address(&inner_c, addr).await {
                    Some(Ok(node)) => debug!(peer=%node, ?addr, "initial seed dial succeeded"),
                    Some(Err(e)) => debug!(?addr, error=%e, "initial seed dial failed"),
                    None => {}
                }
            });
        }
        tokio::spawn(super::endpoint::run_supervisor(inner.clone()));

        Ok((
            ConnectionManager { inner },
            Inbound::new(high_rx, regular_rx),
        ))
    }

    pub fn local_node_id(&self) -> NodeIdentifier {
        self.inner.self_id
    }

    pub fn listen_addresses(&self) -> Vec<PeerAddress> {
        let cfg = self.inner.cfg();
        let mut addrs = Vec::with_capacity(4);

        addrs.extend(advertised_addresses(
            cfg.tcp_advertise(),
            cfg.tcp_listen(),
            TransportKind::Tcp,
        ));
        addrs.extend(advertised_addresses(
            cfg.kcp_advertise(),
            cfg.kcp_listen(),
            TransportKind::Kcp,
        ));
        addrs.extend(advertised_addresses(
            cfg.quic_advertise(),
            cfg.quic_listen(),
            TransportKind::Quic,
        ));
        addrs.extend(advertised_addresses(
            cfg.udp_advertise(),
            cfg.udp_listen(),
            TransportKind::Udp,
        ));

        addrs
    }

    pub(crate) async fn listen_addresses_with_public_ip_probe(&self) -> Vec<PeerAddress> {
        let mut addrs = self.listen_addresses();
        let public_ips = super::public_ip::discover_public_ips().await;
        if public_ips.is_empty() {
            return addrs;
        }
        add_public_ip_advertise_addresses(&mut addrs, self.inner.cfg(), &public_ips);
        addrs
    }

    pub async fn add_address(&self, node: NodeIdentifier, addr: PeerAddress) {
        if node == self.inner.self_id {
            return;
        }
        let peer = self.inner.get_or_create_peer(node);
        let candidates = peer.address_candidates(addr);
        if candidates.is_empty() {
            debug!(peer=%node, ?addr, "ignored unusable peer address");
            return;
        }
        for candidate in candidates {
            if candidate != addr {
                debug!(
                    peer=%node,
                    advertised=?addr,
                    candidate=?candidate,
                    "derived peer address candidate using observed remote IP"
                );
            }
            let added = peer.add_address(candidate);
            if added {
                debug!(peer=%node, ?candidate, "address added");
            }
        }
    }

    pub async fn add_address_seen_at(
        &self,
        node: NodeIdentifier,
        addr: PeerAddress,
        seen_at: std::time::SystemTime,
    ) {
        if node == self.inner.self_id {
            return;
        }
        let peer = self.inner.get_or_create_peer(node);
        let candidates = peer.address_candidates(addr);
        if candidates.is_empty() {
            debug!(peer=%node, ?addr, "ignored unusable peer address");
            return;
        }
        for candidate in candidates {
            if candidate != addr {
                debug!(
                    peer=%node,
                    advertised=?addr,
                    candidate=?candidate,
                    "derived peer address candidate using observed remote IP"
                );
            }
            let added = peer.add_address_seen_at(candidate, seen_at);
            if added {
                debug!(peer=%node, ?candidate, "address added");
            }
        }
    }

    pub async fn remove_address(&self, node: NodeIdentifier, addr: PeerAddress) {
        if let Some(peer) = self.inner.get_peer(node) {
            peer.remove_address(addr);
        }
    }

    pub async fn forget_node(&self, node: NodeIdentifier) {
        if let Some(peer) = self.inner.remove_peer(node) {
            // Cancel any active streams.
            for kind in peer.live_kinds() {
                peer.drop_stream(kind);
            }
        }
    }

    /// Send a `Data` frame to `node` using the best transport satisfying
    /// `level`. Falls back to a stronger transport when the requested level's
    /// flavor isn't currently up; returns `NoSuitableTransport` if nothing
    /// qualifies.
    pub async fn send(
        &self,
        node: NodeIdentifier,
        level: ServiceLevel,
        class: MessageClass,
        payload: Bytes,
    ) -> Result<(), SendError> {
        let peer = self
            .inner
            .get_peer(node)
            .ok_or(SendError::UnknownNode { node })?;

        let chosen = pick_transport(&peer, level).ok_or(SendError::NoSuitableTransport { node })?;

        self.send_stream(&peer, chosen, class, payload).await
    }

    /// Send via a specific transport, ignoring the fallback ordering. Useful
    /// for tests and for callers that already know which link they want.
    pub async fn send_via(
        &self,
        node: NodeIdentifier,
        transport: TransportKind,
        class: MessageClass,
        payload: Bytes,
    ) -> Result<(), SendError> {
        let peer = self
            .inner
            .get_peer(node)
            .ok_or(SendError::UnknownNode { node })?;
        self.send_stream(&peer, transport, class, payload).await
    }

    async fn send_stream(
        &self,
        peer: &Arc<PeerState>,
        kind: TransportKind,
        class: MessageClass,
        payload: Bytes,
    ) -> Result<(), SendError> {
        let sender = peer.try_get_stream(kind).ok_or(SendError::StreamClosed {
            node: peer.node_id(),
            transport: kind,
        })?;
        sender
            .try_send(OutboundFrame::new(class, payload))
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => SendError::Backpressure {
                    node: peer.node_id(),
                    transport: kind,
                },
                mpsc::error::TrySendError::Closed(_) => SendError::StreamClosed {
                    node: peer.node_id(),
                    transport: kind,
                },
            })?;
        Ok(())
    }

    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        let entries: Vec<_> = self
            .inner
            .iter_peers()
            .into_iter()
            .map(|(n, p)| (n, p.metrics().clone()))
            .collect();
        assemble_snapshot(entries)
    }

    pub(crate) fn peer_address_snapshot(&self) -> Vec<PeerAddressSnapshot> {
        let mut out: Vec<_> = self
            .inner
            .iter_peers()
            .into_iter()
            .filter_map(|(node_id, peer)| {
                let addresses = peer.snapshot_addresses();
                if addresses.is_empty() {
                    return None;
                }
                Some(PeerAddressSnapshot {
                    node_id,
                    addresses,
                    last_seen: peer.last_seen(),
                })
            })
            .collect();
        out.sort_by_key(|peer| peer.node_id);
        out
    }

    pub(crate) fn set_required_outgoing_nodes(&self, nodes: HashSet<NodeIdentifier>) {
        self.inner.set_required_outgoing_nodes(nodes);
    }

    pub async fn shutdown(&self) {
        self.inner.shutdown.cancel();
        // Drop streams.
        for (_, peer) in self.inner.iter_peers() {
            for k in peer.live_kinds() {
                peer.drop_stream(k);
            }
        }
    }
}

/// Pick a transport kind for `level`. Acceptance rules mirror the
/// overlay routing fallback (`crate::s2s::overlay::routing`):
///
/// * `BestEffort` accepts anything.
/// * `Reliable` accepts any reliable transport (TCP, KCP, QUIC) — not
///   UDP, since UDP can drop.
/// * `ReliableLowLatency` accepts KCP and QUIC (the strict guarantee)
///   *and* falls back to TCP when neither is live. The latency
///   guarantee is lost in that case but reliability is preserved —
///   acceptable for non-realtime traffic like moderation.
///
/// Among accepted transports, exact-level matches win; the rest are
/// ordered by stronger-first then a stable kind tiebreaker.
fn pick_transport(peer: &PeerState, level: ServiceLevel) -> Option<TransportKind> {
    let mut candidates: Vec<TransportKind> = peer
        .live_kinds()
        .into_iter()
        .filter(|k| accepts(*k, level))
        .collect();
    if candidates.is_empty() {
        return None;
    }

    candidates.sort_by_key(|k| {
        let provided = k.service_level();
        let exact_first = if provided == level { 0 } else { 1 };
        (exact_first, provided as u8, kind_order(*k))
    });
    candidates.first().copied()
}

fn accepts(kind: TransportKind, requested: ServiceLevel) -> bool {
    let provided = kind.service_level();
    match requested {
        ServiceLevel::BestEffort => true,
        ServiceLevel::Reliable | ServiceLevel::ReliableLowLatency => {
            // Both reliable tiers accept any reliable transport.
            provided != ServiceLevel::BestEffort
        }
    }
}

fn kind_order(k: TransportKind) -> u8 {
    match k {
        TransportKind::Tcp => 3,
        TransportKind::Quic => 1,
        TransportKind::Kcp => 2,
        TransportKind::Udp => 0,
    }
}

fn advertised_addresses(
    explicit: &[SocketAddr],
    listen: Option<SocketAddr>,
    transport: TransportKind,
) -> Vec<PeerAddress> {
    if !explicit.is_empty() {
        let mut addrs = Vec::with_capacity(explicit.len());
        for addr in explicit.iter().copied() {
            let peer_addr = PeerAddress::new(addr, transport);
            if peer_addr.is_dialable() {
                addrs.push(peer_addr);
            } else {
                debug!(
                    ?transport,
                    %addr,
                    "not advertising wildcard S2S explicit address"
                );
            }
        }
        return addrs;
    }

    let Some(addr) = listen else {
        return Vec::new();
    };
    let peer_addr = PeerAddress::new(addr, transport);
    if peer_addr.is_dialable() {
        vec![peer_addr]
    } else {
        debug!(
            ?transport,
            %addr,
            "not advertising wildcard S2S listen address; configure the matching *_advertise address"
        );
        Vec::new()
    }
}

fn add_public_ip_advertise_addresses(
    addrs: &mut Vec<PeerAddress>,
    cfg: &TransportConfig,
    public_ips: &[IpAddr],
) {
    push_public_ip_advertise_addresses(
        addrs,
        public_ips,
        cfg.tcp_advertise_override(),
        cfg.tcp_listen(),
        TransportKind::Tcp,
    );
    push_public_ip_advertise_addresses(
        addrs,
        public_ips,
        cfg.kcp_advertise_override(),
        cfg.kcp_listen(),
        TransportKind::Kcp,
    );
    push_public_ip_advertise_addresses(
        addrs,
        public_ips,
        cfg.quic_advertise_override(),
        cfg.quic_listen(),
        TransportKind::Quic,
    );
    push_public_ip_advertise_addresses(
        addrs,
        public_ips,
        cfg.udp_advertise_override(),
        cfg.udp_listen(),
        TransportKind::Udp,
    );
}

fn push_public_ip_advertise_addresses(
    addrs: &mut Vec<PeerAddress>,
    public_ips: &[IpAddr],
    explicit_override: bool,
    listen: Option<SocketAddr>,
    transport: TransportKind,
) {
    if explicit_override {
        return;
    }
    let Some(listen) = listen else {
        return;
    };
    if listen.port() == 0 || listen.ip().is_loopback() {
        return;
    }
    for ip in public_ips.iter().copied() {
        let candidate = PeerAddress::new(SocketAddr::new(ip, listen.port()), transport);
        if candidate.is_dialable() && !addrs.contains(&candidate) {
            addrs.push(candidate);
        }
    }
}

/// Build every endpoint for which the corresponding `<kind>_listen` is set.
/// Each endpoint owns its own state; the `EndpointRegistry` returned is
/// stored inside `ManagerInner` for dial dispatch.
fn build_endpoints(
    cfg: &TransportConfig,
    identity: Arc<NodeIdentity>,
    server_tls: Arc<rustls::ServerConfig>,
    client_tls: Arc<rustls::ClientConfig>,
) -> Result<EndpointRegistry, TransportError> {
    let has_seed = |kind| {
        cfg.seed_addresses()
            .iter()
            .any(|addr| addr.transport() == kind)
    };

    let tcp = (cfg.tcp_listen().is_some() || has_seed(TransportKind::Tcp)).then(|| {
        Arc::new(TcpEndpoint::new(
            server_tls.clone(),
            client_tls.clone(),
            cfg.tcp_listen(),
        ))
    });
    let kcp = (cfg.kcp_listen().is_some() || has_seed(TransportKind::Kcp)).then(|| {
        Arc::new(KcpEndpoint::new(
            server_tls.clone(),
            client_tls.clone(),
            cfg.kcp_listen(),
        ))
    });
    let quic = if cfg.quic_listen().is_some() || has_seed(TransportKind::Quic) {
        match cfg.quic_listen() {
            Some(addr) => Some(Arc::new(
                QuicEndpoint::new(server_tls.clone(), client_tls.clone(), Some(addr))
                    .map_err(|source| TransportError::Bind { addr, source })?,
            )),
            None => Some(Arc::new(QuicEndpoint::new(
                server_tls.clone(),
                client_tls.clone(),
                None,
            )?)),
        }
    } else {
        None
    };
    let udp = (cfg.udp_listen().is_some() || has_seed(TransportKind::Udp))
        .then(|| Arc::new(UdpEndpoint::new(identity, cfg.udp_listen())));

    Ok(EndpointRegistry::new(tcp, kcp, quic, udp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn socket(raw: &str) -> SocketAddr {
        raw.parse().unwrap()
    }

    #[test]
    fn advertised_addresses_skip_wildcard_listen_without_advertise() {
        assert_eq!(
            advertised_addresses(&[], Some(socket("0.0.0.0:64739")), TransportKind::Tcp),
            Vec::<PeerAddress>::new()
        );
    }

    #[test]
    fn advertised_addresses_use_all_explicit_advertise_values_for_wildcard_listen() {
        assert_eq!(
            advertised_addresses(
                &[socket("127.0.0.1:64740"), socket("127.0.0.2:64740")],
                Some(socket("0.0.0.0:64740")),
                TransportKind::Kcp,
            ),
            vec![
                PeerAddress::new(socket("127.0.0.1:64740"), TransportKind::Kcp),
                PeerAddress::new(socket("127.0.0.2:64740"), TransportKind::Kcp),
            ]
        );
    }

    #[test]
    fn advertised_addresses_use_concrete_listen_when_no_advertise_set() {
        assert_eq!(
            advertised_addresses(&[], Some(socket("127.0.0.1:64741")), TransportKind::Quic),
            vec![PeerAddress::new(
                socket("127.0.0.1:64741"),
                TransportKind::Quic
            )]
        );
    }

    #[test]
    fn advertised_addresses_skip_wildcard_explicit_advertise() {
        assert_eq!(
            advertised_addresses(
                &[socket("0.0.0.0:64742")],
                Some(socket("127.0.0.1:64742")),
                TransportKind::Udp,
            ),
            Vec::<PeerAddress>::new()
        );
    }

    #[test]
    fn public_ip_advertise_addresses_use_listen_ports_when_no_override_is_set() {
        let cfg = TransportConfig::new("ca.pem".into(), "cert.pem".into(), "key.pem".into())
            .with_tcp_listen(socket("0.0.0.0:64739"))
            .with_quic_listen(socket("[::]:64741"));
        let mut addrs = Vec::new();
        add_public_ip_advertise_addresses(
            &mut addrs,
            &cfg,
            &[
                "8.8.8.8".parse().unwrap(),
                "2001:4860:4860::8888".parse().unwrap(),
            ],
        );

        assert_eq!(
            addrs,
            vec![
                PeerAddress::new(socket("8.8.8.8:64739"), TransportKind::Tcp),
                PeerAddress::new(socket("[2001:4860:4860::8888]:64739"), TransportKind::Tcp),
                PeerAddress::new(socket("8.8.8.8:64741"), TransportKind::Quic),
                PeerAddress::new(socket("[2001:4860:4860::8888]:64741"), TransportKind::Quic),
            ]
        );
    }

    #[test]
    fn public_ip_advertise_addresses_respect_explicit_override() {
        let cfg = TransportConfig::new("ca.pem".into(), "cert.pem".into(), "key.pem".into())
            .with_tcp_listen(socket("0.0.0.0:64739"))
            .with_tcp_advertise_override(socket("203.0.113.10:64739"));
        let mut addrs = vec![PeerAddress::new(
            socket("203.0.113.10:64739"),
            TransportKind::Tcp,
        )];
        add_public_ip_advertise_addresses(&mut addrs, &cfg, &["8.8.8.8".parse().unwrap()]);

        assert_eq!(
            addrs,
            vec![PeerAddress::new(
                socket("203.0.113.10:64739"),
                TransportKind::Tcp
            )]
        );
    }
}
