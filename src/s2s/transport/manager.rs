//! `ConnectionManager` — public face of the transport module.
//!
//! Holds the peer table, the inbound dispatch sinks, the shutdown signal, and
//! a registry of per-transport endpoints. Each endpoint owns its own state
//! (TLS configs, bound listener, `quinn::Endpoint`, etc.) so the manager
//! itself stays free of transport-specific fields.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use bytes::Bytes;
use parking_lot::RwLock;
use scc::HashMap as SccMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::types::NodeIdentifier;

use super::SendOptions;
use super::config::TransportConfig;
use super::connection::{AddressBackoffSnapshot, BackoffState, OutboundFrame, PeerState};
use super::endpoint::{
    EndpointRegistry, kcp::KcpEndpoint, mux::UdpMuxSet, quic::QuicEndpoint, tcp::TcpEndpoint,
    udp::UdpEndpoint,
};
use super::error::{ConfigError, SendError, TransportError};
use super::identity::NodeIdentity;
use super::metrics::{MetricsSnapshot, MetricsTuning, assemble_snapshot};
use super::service_level::{
    MessageClass, PeerAddress, RoutingMetric, SeedAddress, ServiceLevel, TransportKind,
};
use super::tls::build_tls_configs;

#[derive(Debug, Clone)]
pub(crate) struct PeerAddressSnapshot {
    node_id: NodeIdentifier,
    addresses: Vec<PeerAddress>,
    address_backoffs: HashMap<PeerAddress, AddressBackoffSnapshot>,
    last_seen: Option<SystemTime>,
}

impl PeerAddressSnapshot {
    pub(crate) fn node_id(&self) -> NodeIdentifier {
        self.node_id
    }

    pub(crate) fn addresses(&self) -> &[PeerAddress] {
        &self.addresses
    }

    pub(crate) fn address_backoffs(&self) -> &HashMap<PeerAddress, AddressBackoffSnapshot> {
        &self.address_backoffs
    }

    pub(crate) fn last_seen(&self) -> Option<SystemTime> {
        self.last_seen
    }
}

/// Inbound message handed to the caller via one of the mpscs in
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
    control: mpsc::Receiver<InboundMessage>,
    high_priority: mpsc::Receiver<InboundMessage>,
    regular: mpsc::Receiver<InboundMessage>,
}

impl Inbound {
    pub(crate) fn new(
        control: mpsc::Receiver<InboundMessage>,
        high_priority: mpsc::Receiver<InboundMessage>,
        regular: mpsc::Receiver<InboundMessage>,
    ) -> Self {
        Self {
            control,
            high_priority,
            regular,
        }
    }

    pub fn control(&mut self) -> &mut mpsc::Receiver<InboundMessage> {
        &mut self.control
    }

    pub fn high_priority(&mut self) -> &mut mpsc::Receiver<InboundMessage> {
        &mut self.high_priority
    }

    pub fn regular(&mut self) -> &mut mpsc::Receiver<InboundMessage> {
        &mut self.regular
    }

    /// Consume the handle and return the receivers (control, high-priority, regular).
    /// Used by callers (e.g. the overlay dispatcher) that want to take owned
    /// halves into separate tasks.
    pub fn into_parts(
        self,
    ) -> (
        mpsc::Receiver<InboundMessage>,
        mpsc::Receiver<InboundMessage>,
        mpsc::Receiver<InboundMessage>,
    ) {
        (self.control, self.high_priority, self.regular)
    }
}

/// Sender halves used by all stream/datagram pumps. Cheap to clone.
#[derive(Clone)]
pub(crate) struct InboundDispatch {
    control: mpsc::Sender<InboundMessage>,
    high: mpsc::Sender<InboundMessage>,
    regular: mpsc::Sender<InboundMessage>,
}

impl InboundDispatch {
    pub fn new(
        control: mpsc::Sender<InboundMessage>,
        high: mpsc::Sender<InboundMessage>,
        regular: mpsc::Sender<InboundMessage>,
    ) -> Self {
        Self {
            control,
            high,
            regular,
        }
    }

    pub fn dispatch(&self, msg: InboundMessage) {
        match msg.class {
            MessageClass::Control => {
                if let Err(e) = self.control.try_send(msg) {
                    warn!(error=%e, "control inbound queue full; dropping frame");
                }
            }
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
    seed_backoff: Arc<SccMap<SeedAddress, Arc<parking_lot::Mutex<BackoffState>>>>,
    successful_seeds: Arc<SccMap<SeedAddress, PeerAddress>>,
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
                packet_loss_alpha: self.cfg.packet_loss_ewma_alpha(),
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

    pub fn seed_backoff(&self, addr: SeedAddress) -> Arc<parking_lot::Mutex<BackoffState>> {
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

    pub fn successful_seed_address(&self, addr: &SeedAddress) -> Option<PeerAddress> {
        self.successful_seeds
            .get_sync(addr)
            .map(|entry| *entry.get())
    }

    pub fn mark_seed_successful(&self, addr: SeedAddress, resolved: PeerAddress) {
        if self.successful_seeds.get_sync(&addr).is_some() {
            return;
        }
        match self.successful_seeds.entry_sync(addr) {
            scc::hash_map::Entry::Occupied(_) => {}
            scc::hash_map::Entry::Vacant(e) => {
                e.insert_entry(resolved);
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

        let (control_tx, control_rx) = mpsc::channel(cfg.inbound_control_capacity());
        let (high_tx, high_rx) = mpsc::channel(cfg.inbound_high_capacity());
        let (regular_tx, regular_rx) = mpsc::channel(cfg.inbound_regular_capacity());
        let inbound = InboundDispatch::new(control_tx, high_tx, regular_tx);

        let inner = Arc::new(ManagerInner {
            self_id: identity.node_id(),
            peers: Arc::new(SccMap::new()),
            seed_backoff: Arc::new(SccMap::new()),
            successful_seeds: Arc::new(SccMap::new()),
            required_outgoing: Arc::new(RwLock::new(HashSet::new())),
            inbound,
            shutdown: CancellationToken::new(),
            endpoints,
            cfg,
        });

        super::endpoint::start_all(inner.clone()).await?;
        for addr in inner.cfg().seed_targets() {
            let inner_c = inner.clone();
            tokio::spawn(async move {
                match super::endpoint::probe_seed_address(&inner_c, addr.clone()).await {
                    Some(Ok(node)) => debug!(peer=%node, ?addr, "initial seed dial succeeded"),
                    Some(Err(e)) => debug!(?addr, error=%e, "initial seed dial failed"),
                    None => {}
                }
            });
        }
        tokio::spawn(super::endpoint::run_supervisor(inner.clone()));

        Ok((
            ConnectionManager { inner },
            Inbound::new(control_rx, high_rx, regular_rx),
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
            cfg.tcp_listen_addrs(),
            TransportKind::Tcp,
            cfg.advertise_private_ips(),
        ));
        addrs.extend(advertised_addresses(
            cfg.kcp_advertise(),
            cfg.kcp_listen_addrs(),
            TransportKind::Kcp,
            cfg.advertise_private_ips(),
        ));
        addrs.extend(advertised_addresses(
            cfg.quic_advertise(),
            cfg.quic_listen_addrs(),
            TransportKind::Quic,
            cfg.advertise_private_ips(),
        ));
        addrs.extend(advertised_addresses(
            cfg.udp_advertise(),
            cfg.udp_listen_addrs(),
            TransportKind::Udp,
            cfg.advertise_private_ips(),
        ));

        addrs
    }

    pub(crate) async fn listen_addresses_with_public_ip_probe(&self) -> Vec<PeerAddress> {
        let mut addrs = self.listen_addresses();
        let local_ips =
            super::local_ip::discover_interface_ips(self.inner.cfg().local_advertise_interfaces());
        if !local_ips.is_empty() {
            add_discovered_ip_advertise_addresses(&mut addrs, self.inner.cfg(), &local_ips);
        }
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
            let added = peer.add_address(candidate);
            if added {
                if candidate != addr {
                    debug!(
                        peer=%node,
                        advertised=?addr,
                        candidate=?candidate,
                        "derived peer address candidate using observed remote IP"
                    );
                }
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
            let added = peer.add_address_seen_at(candidate, seen_at);
            if added {
                if candidate != addr {
                    debug!(
                        peer=%node,
                        advertised=?addr,
                        candidate=?candidate,
                        "derived peer address candidate using observed remote IP"
                    );
                }
                debug!(peer=%node, ?candidate, "address added");
            }
        }
    }

    pub(crate) async fn add_address_seen_at_with_backoff(
        &self,
        node: NodeIdentifier,
        addr: PeerAddress,
        seen_at: std::time::SystemTime,
        backoff: Option<AddressBackoffSnapshot>,
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
            let added = peer.add_address_seen_at_with_backoff(candidate, seen_at, backoff);
            if added {
                if candidate != addr {
                    debug!(
                        peer=%node,
                        advertised=?addr,
                        candidate=?candidate,
                        "derived peer address candidate using observed remote IP"
                    );
                }
                debug!(peer=%node, ?candidate, "address added");
            }
        }
    }

    pub(crate) fn replace_advertised_addresses_seen_at(
        &self,
        node: NodeIdentifier,
        addrs: Vec<PeerAddress>,
        seen_at: std::time::SystemTime,
    ) {
        if node == self.inner.self_id {
            return;
        }
        let peer = self.inner.get_or_create_peer(node);
        let mut advertised = Vec::with_capacity(addrs.len());
        for addr in addrs {
            if !advertised.contains(&addr) {
                advertised.push(addr);
            }
        }
        peer.replace_advertised_addresses(&advertised);
        peer.note_seen_at(seen_at);

        for addr in advertised {
            let candidates = peer.address_candidates(addr);
            if candidates.is_empty() {
                debug!(peer=%node, ?addr, "ignored unusable advertised peer address");
                continue;
            }
            for candidate in candidates {
                let added = peer.add_address_seen_at(candidate, seen_at);
                if added {
                    if candidate != addr {
                        debug!(
                            peer=%node,
                            advertised=?addr,
                            candidate=?candidate,
                            "derived peer address candidate using observed remote IP"
                        );
                    }
                    debug!(peer=%node, ?candidate, "advertised address added");
                }
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

    /// Send a `Data` frame using the best live transport under the sender's
    /// selected routing metric. Uses the service level's default
    /// [`RoutingMetric`] when `routing_metric` is `None`. If the first
    /// acceptable transport closes or
    /// is full before enqueue, retry the next acceptable transport.
    pub async fn send(
        &self,
        node: NodeIdentifier,
        level: ServiceLevel,
        routing_metric: Option<RoutingMetric>,
        class: MessageClass,
        payload: Bytes,
    ) -> Result<(), SendError> {
        self.send_with_options(
            node,
            level,
            routing_metric,
            class,
            payload,
            SendOptions::default(),
        )
        .await
    }

    pub async fn send_with_options(
        &self,
        node: NodeIdentifier,
        level: ServiceLevel,
        routing_metric: Option<RoutingMetric>,
        class: MessageClass,
        payload: Bytes,
        options: SendOptions,
    ) -> Result<(), SendError> {
        let routing_metric =
            routing_metric.unwrap_or_else(|| RoutingMetric::default_for_level(level));
        let peer = self
            .inner
            .get_peer(node)
            .ok_or(SendError::UnknownNode { node })?;

        let choices = pick_transports(&peer, level, routing_metric);
        if choices.is_empty() {
            return Err(SendError::NoSuitableTransport { node });
        }

        let mut first_err = None;
        let choice_count = choices.len();
        for (idx, chosen) in choices.into_iter().enumerate() {
            let wait_for_space = idx + 1 == choice_count;
            match self
                .send_stream(
                    &peer,
                    chosen,
                    class,
                    payload.clone(),
                    options,
                    wait_for_space,
                )
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        Err(first_err.unwrap_or(SendError::NoSuitableTransport { node }))
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
        self.send_via_with_options(node, transport, class, payload, SendOptions::default())
            .await
    }

    pub async fn send_via_with_options(
        &self,
        node: NodeIdentifier,
        transport: TransportKind,
        class: MessageClass,
        payload: Bytes,
        options: SendOptions,
    ) -> Result<(), SendError> {
        let peer = self
            .inner
            .get_peer(node)
            .ok_or(SendError::UnknownNode { node })?;
        self.send_stream(&peer, transport, class, payload, options, true)
            .await
    }

    async fn send_stream(
        &self,
        peer: &Arc<PeerState>,
        kind: TransportKind,
        class: MessageClass,
        payload: Bytes,
        options: SendOptions,
        wait_for_space: bool,
    ) -> Result<(), SendError> {
        let sender = peer.try_get_stream(kind).ok_or(SendError::StreamClosed {
            node: peer.node_id(),
            transport: kind,
        })?;
        let frame = OutboundFrame::with_options(class, payload, options);
        match sender.try_send(frame) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(frame)) if wait_for_space => sender
                .send(frame)
                .await
                .map_err(|_| SendError::StreamClosed {
                    node: peer.node_id(),
                    transport: kind,
                }),
            Err(mpsc::error::TrySendError::Full(_)) => Err(SendError::Backpressure {
                node: peer.node_id(),
                transport: kind,
            }),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(SendError::StreamClosed {
                node: peer.node_id(),
                transport: kind,
            }),
        }
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
        let now = Instant::now();
        let wall_now = SystemTime::now();
        let mut out: Vec<_> = self
            .inner
            .iter_peers()
            .into_iter()
            .filter_map(|(node_id, peer)| {
                let addresses = peer.snapshot_addresses();
                if addresses.is_empty() {
                    return None;
                }
                let address_backoffs = peer.snapshot_address_backoffs(&addresses, now, wall_now);
                Some(PeerAddressSnapshot {
                    node_id,
                    addresses,
                    address_backoffs,
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
/// Among measured accepted transports, the sender-selected routing metric
/// wins. Unmeasured transports are appended in the fixed fallback order:
/// exact-level first, then stronger-first with a stable kind tiebreaker.
#[cfg(test)]
fn pick_transport(
    peer: &PeerState,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
) -> Option<TransportKind> {
    pick_transports(peer, level, routing_metric)
        .first()
        .copied()
}

fn pick_transports(
    peer: &PeerState,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
) -> Vec<TransportKind> {
    let mut candidates: Vec<TransportKind> = peer
        .live_kinds()
        .into_iter()
        .filter(|k| accepts(*k, level))
        .collect();
    if candidates.is_empty() {
        return Vec::new();
    }

    let mut ranked = peer
        .metrics()
        .ranked_transports_for(level, routing_metric, &candidates);

    candidates.sort_by_key(|k| {
        let provided = k.service_level();
        let exact_first = if provided == level { 0 } else { 1 };
        (exact_first, provided as u8, kind_order(*k))
    });

    for candidate in candidates {
        if !ranked.contains(&candidate) {
            ranked.push(candidate);
        }
    }

    ranked
}

fn accepts(kind: TransportKind, requested: ServiceLevel) -> bool {
    kind.is_acceptable_for(requested)
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
    listen: &[SocketAddr],
    transport: TransportKind,
    advertise_private_ips: bool,
) -> Vec<PeerAddress> {
    if !explicit.is_empty() {
        let mut addrs = Vec::with_capacity(explicit.len());
        for addr in explicit.iter().copied() {
            let peer_addr = PeerAddress::new(addr, transport);
            if peer_addr.is_dialable()
                && (advertise_private_ips || !is_private_ip(peer_addr.addr().ip()))
            {
                addrs.push(peer_addr);
            } else if !peer_addr.is_dialable() {
                debug!(
                    ?transport,
                    %addr,
                    "not advertising wildcard S2S explicit address"
                );
            } else {
                debug!(
                    ?transport,
                    %addr,
                    "not advertising private S2S explicit address"
                );
            }
        }
        return addrs;
    }

    let mut addrs = Vec::with_capacity(listen.len());
    for addr in listen.iter().copied() {
        let peer_addr = PeerAddress::new(addr, transport);
        if peer_addr.is_dialable()
            && (advertise_private_ips || !is_private_ip(peer_addr.addr().ip()))
        {
            addrs.push(peer_addr);
        } else if !peer_addr.is_dialable() {
            debug!(
                ?transport,
                %addr,
                "not advertising wildcard S2S listen address; configure the matching *_advertise address"
            );
        } else {
            debug!(
                ?transport,
                %addr,
                "not advertising private S2S listen address"
            );
        }
    }
    addrs
}

fn add_public_ip_advertise_addresses(
    addrs: &mut Vec<PeerAddress>,
    cfg: &TransportConfig,
    public_ips: &[IpAddr],
) {
    add_discovered_ip_advertise_addresses(addrs, cfg, public_ips);
}

fn add_discovered_ip_advertise_addresses(
    addrs: &mut Vec<PeerAddress>,
    cfg: &TransportConfig,
    ips: &[IpAddr],
) {
    push_discovered_ip_advertise_addresses(
        addrs,
        ips,
        cfg.tcp_advertise_override(),
        cfg.tcp_listen_addrs(),
        TransportKind::Tcp,
        cfg.advertise_private_ips(),
    );
    push_discovered_ip_advertise_addresses(
        addrs,
        ips,
        cfg.kcp_advertise_override(),
        cfg.kcp_listen_addrs(),
        TransportKind::Kcp,
        cfg.advertise_private_ips(),
    );
    push_discovered_ip_advertise_addresses(
        addrs,
        ips,
        cfg.quic_advertise_override(),
        cfg.quic_listen_addrs(),
        TransportKind::Quic,
        cfg.advertise_private_ips(),
    );
    push_discovered_ip_advertise_addresses(
        addrs,
        ips,
        cfg.udp_advertise_override(),
        cfg.udp_listen_addrs(),
        TransportKind::Udp,
        cfg.advertise_private_ips(),
    );
}

fn push_discovered_ip_advertise_addresses(
    addrs: &mut Vec<PeerAddress>,
    ips: &[IpAddr],
    explicit_override: bool,
    listen: &[SocketAddr],
    transport: TransportKind,
    advertise_private_ips: bool,
) {
    if explicit_override {
        return;
    }
    for listen_addr in listen.iter().copied() {
        if listen_addr.port() == 0 || listen_addr.ip().is_loopback() {
            continue;
        }
        for ip in ips.iter().copied() {
            if !listen_supports_ip_family(listen_addr, ip) {
                continue;
            }
            if !advertise_private_ips && is_private_ip(ip) {
                continue;
            }
            let candidate = PeerAddress::new(SocketAddr::new(ip, listen_addr.port()), transport);
            if candidate.is_dialable() && !addrs.contains(&candidate) {
                addrs.push(candidate);
            }
        }
    }
}

fn listen_supports_ip_family(listen: SocketAddr, ip: IpAddr) -> bool {
    listen.is_ipv4() == ip.is_ipv4()
        || (ip.is_ipv4() && listen.is_ipv6() && listen.ip().is_unspecified())
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_private() || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00) == 0xfc00,
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
    let mux = UdpMuxSet::new(&udp_family_listen_addrs(cfg));
    let has_seed = |kind| {
        cfg.seed_targets()
            .iter()
            .any(|addr| addr.transport() == kind)
    };

    let tcp = (!cfg.tcp_listen_addrs().is_empty() || has_seed(TransportKind::Tcp)).then(|| {
        Arc::new(TcpEndpoint::new(
            server_tls.clone(),
            client_tls.clone(),
            cfg.tcp_listen_addrs().iter().copied(),
        ))
    });
    let kcp = (!cfg.kcp_listen_addrs().is_empty() || has_seed(TransportKind::Kcp)).then(|| {
        Arc::new(KcpEndpoint::new(
            server_tls.clone(),
            client_tls.clone(),
            cfg.kcp_listen_addrs().iter().copied(),
            mux.clone(),
        ))
    });
    let quic = if !cfg.quic_listen_addrs().is_empty() || has_seed(TransportKind::Quic) {
        let endpoint = QuicEndpoint::new(
            server_tls.clone(),
            client_tls.clone(),
            cfg.quic_listen_addrs().iter().copied(),
            mux.clone(),
        )
        .map_err(|e| {
            let (addr, source) = e.into_parts();
            TransportError::Bind { addr, source }
        })?;
        Some(Arc::new(endpoint))
    } else {
        None
    };
    let udp = (!cfg.udp_listen_addrs().is_empty() || has_seed(TransportKind::Udp)).then(|| {
        Arc::new(UdpEndpoint::new(
            identity,
            cfg.udp_listen_addrs().iter().copied(),
            mux,
        ))
    });

    Ok(EndpointRegistry::new(tcp, kcp, quic, udp))
}

fn udp_family_listen_addrs(cfg: &TransportConfig) -> Vec<(TransportKind, SocketAddr)> {
    let mut addrs = Vec::new();
    addrs.extend(
        cfg.kcp_listen_addrs()
            .iter()
            .copied()
            .map(|addr| (TransportKind::Kcp, addr)),
    );
    addrs.extend(
        cfg.quic_listen_addrs()
            .iter()
            .copied()
            .map(|addr| (TransportKind::Quic, addr)),
    );
    addrs.extend(
        cfg.udp_listen_addrs()
            .iter()
            .copied()
            .map(|addr| (TransportKind::Udp, addr)),
    );
    addrs
}

#[cfg(test)]
mod tests {
    use super::super::connection::ActiveStream;
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    fn socket(raw: &str) -> SocketAddr {
        raw.parse().unwrap()
    }

    fn peer_with_live_transports(
        kinds: &[TransportKind],
    ) -> (Arc<PeerState>, Vec<mpsc::Receiver<OutboundFrame>>) {
        let peer = PeerState::new(
            2,
            Duration::from_millis(10),
            Duration::from_secs(60),
            MetricsTuning::default(),
        );
        let mut receivers = Vec::new();
        for kind in kinds {
            let (tx, rx) = mpsc::channel(1);
            peer.install_stream(ActiveStream::new(
                *kind,
                None,
                tx,
                CancellationToken::new(),
                false,
            ));
            receivers.push(rx);
        }
        (peer, receivers)
    }

    #[tokio::test]
    async fn inbound_dispatch_routes_control_to_control_queue() {
        let (control_tx, mut control_rx) = mpsc::channel(1);
        let (high_tx, mut high_rx) = mpsc::channel(1);
        let (regular_tx, mut regular_rx) = mpsc::channel(1);
        let dispatch = InboundDispatch::new(control_tx, high_tx, regular_tx);

        dispatch.dispatch(InboundMessage::new(
            7,
            ServiceLevel::ReliableLowLatency,
            TransportKind::Tcp,
            MessageClass::Control,
            Bytes::from_static(b"control"),
        ));

        let msg = control_rx.recv().await.expect("control message");
        assert_eq!(msg.class(), MessageClass::Control);
        assert_eq!(&msg.payload()[..], b"control");
        assert!(high_rx.try_recv().is_err());
        assert!(regular_rx.try_recv().is_err());
    }

    #[test]
    fn fixed_transport_order_prefers_exact_level_when_unmeasured() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Quic]);

        assert_eq!(
            pick_transport(&peer, ServiceLevel::Reliable, RoutingMetric::ReliableCost),
            Some(TransportKind::Tcp)
        );
    }

    #[test]
    fn metric_transport_order_can_upgrade_reliable_from_bad_tcp() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Quic]);

        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(5));
        peer.metrics().record_payload_sent(TransportKind::Tcp, 100);
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(25));
        peer.metrics()
            .record_payload_sent(TransportKind::Quic, 1024 * 1024);
        std::thread::sleep(Duration::from_millis(10));

        assert_eq!(
            pick_transport(&peer, ServiceLevel::Reliable, RoutingMetric::ReliableCost),
            Some(TransportKind::Quic)
        );
    }

    #[test]
    fn conversational_transport_order_can_upgrade_best_effort_from_udp() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Udp, TransportKind::Quic]);

        peer.metrics()
            .record_rtt(TransportKind::Udp, Duration::from_millis(10));
        peer.metrics()
            .record_rtt(TransportKind::Udp, Duration::from_millis(250));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(70));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(71));

        assert_eq!(
            pick_transport(
                &peer,
                ServiceLevel::BestEffort,
                RoutingMetric::BestEffortCost
            ),
            Some(TransportKind::Udp)
        );
        assert_eq!(
            pick_transport(
                &peer,
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality
            ),
            Some(TransportKind::Quic)
        );
    }

    #[test]
    fn advertised_addresses_skip_wildcard_listen_without_advertise() {
        assert_eq!(
            advertised_addresses(&[], &[socket("0.0.0.0:64739")], TransportKind::Tcp, true),
            Vec::<PeerAddress>::new()
        );
    }

    #[test]
    fn advertised_addresses_use_all_explicit_advertise_values_for_wildcard_listen() {
        assert_eq!(
            advertised_addresses(
                &[socket("127.0.0.1:64740"), socket("127.0.0.2:64740")],
                &[socket("0.0.0.0:64740")],
                TransportKind::Kcp,
                true,
            ),
            vec![
                PeerAddress::new(socket("127.0.0.1:64740"), TransportKind::Kcp),
                PeerAddress::new(socket("127.0.0.2:64740"), TransportKind::Kcp),
            ]
        );
    }

    #[test]
    fn listen_addresses_can_publish_same_udp_socket_for_all_udp_family_transports() {
        let shared = socket("127.0.0.1:64739");
        let mut addrs = Vec::new();
        addrs.extend(advertised_addresses(
            &[],
            &[shared],
            TransportKind::Kcp,
            true,
        ));
        addrs.extend(advertised_addresses(
            &[],
            &[shared],
            TransportKind::Quic,
            true,
        ));
        addrs.extend(advertised_addresses(
            &[],
            &[shared],
            TransportKind::Udp,
            true,
        ));

        assert_eq!(
            addrs,
            vec![
                PeerAddress::new(shared, TransportKind::Kcp),
                PeerAddress::new(shared, TransportKind::Quic),
                PeerAddress::new(shared, TransportKind::Udp),
            ]
        );
    }

    #[test]
    fn advertised_addresses_use_concrete_listen_when_no_advertise_set() {
        assert_eq!(
            advertised_addresses(&[], &[socket("127.0.0.1:64741")], TransportKind::Quic, true),
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
                &[socket("127.0.0.1:64742")],
                TransportKind::Udp,
                true,
            ),
            Vec::<PeerAddress>::new()
        );
    }

    #[test]
    fn advertised_addresses_use_all_concrete_listen_addresses() {
        assert_eq!(
            advertised_addresses(
                &[],
                &[socket("192.0.2.10:64739"), socket("[2001:db8::10]:64739")],
                TransportKind::Tcp,
                true,
            ),
            vec![
                PeerAddress::new(socket("192.0.2.10:64739"), TransportKind::Tcp),
                PeerAddress::new(socket("[2001:db8::10]:64739"), TransportKind::Tcp),
            ]
        );
    }

    #[test]
    fn advertised_addresses_can_suppress_private_explicit_advertise_values() {
        assert_eq!(
            advertised_addresses(
                &[socket("10.0.0.10:64739"), socket("[fd00::10]:64739")],
                &[socket("0.0.0.0:64739")],
                TransportKind::Tcp,
                false,
            ),
            Vec::<PeerAddress>::new()
        );
    }

    #[test]
    fn advertised_addresses_can_suppress_private_concrete_listen_addresses() {
        assert_eq!(
            advertised_addresses(
                &[],
                &[socket("172.16.0.10:64739"), socket("[fc00::10]:64739")],
                TransportKind::Tcp,
                false,
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
                PeerAddress::new(socket("8.8.8.8:64741"), TransportKind::Quic),
                PeerAddress::new(socket("[2001:4860:4860::8888]:64741"), TransportKind::Quic),
            ]
        );
    }

    #[test]
    fn discovered_ip_advertise_addresses_can_publish_tailscale_and_ipv6_addresses() {
        let cfg = TransportConfig::new("ca.pem".into(), "cert.pem".into(), "key.pem".into())
            .with_tcp_listen(socket("0.0.0.0:64739"))
            .with_quic_listen(socket("[::]:64741"));
        let mut addrs = Vec::new();
        add_discovered_ip_advertise_addresses(
            &mut addrs,
            &cfg,
            &[
                "100.64.12.34".parse().unwrap(),
                "fd00::12".parse().unwrap(),
                "2001:4860:4860::8888".parse().unwrap(),
            ],
        );

        assert_eq!(
            addrs,
            vec![
                PeerAddress::new(socket("100.64.12.34:64739"), TransportKind::Tcp),
                PeerAddress::new(socket("100.64.12.34:64741"), TransportKind::Quic),
                PeerAddress::new(socket("[fd00::12]:64741"), TransportKind::Quic),
                PeerAddress::new(socket("[2001:4860:4860::8888]:64741"), TransportKind::Quic),
            ]
        );
    }

    #[test]
    fn discovered_ip_advertise_addresses_respect_private_ip_suppression() {
        let cfg = TransportConfig::new("ca.pem".into(), "cert.pem".into(), "key.pem".into())
            .with_advertise_private_ips(false)
            .with_tcp_listen(socket("0.0.0.0:64739"))
            .with_quic_listen(socket("[::]:64741"));
        let mut addrs = Vec::new();
        add_discovered_ip_advertise_addresses(
            &mut addrs,
            &cfg,
            &[
                "100.64.12.34".parse().unwrap(),
                "10.0.0.12".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                "fd00::12".parse().unwrap(),
                "2001:4860:4860::8888".parse().unwrap(),
            ],
        );

        assert_eq!(
            addrs,
            vec![
                PeerAddress::new(socket("8.8.8.8:64739"), TransportKind::Tcp),
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
