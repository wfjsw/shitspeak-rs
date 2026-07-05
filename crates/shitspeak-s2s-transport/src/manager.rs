//! `ConnectionManager` — public face of the transport module.
//!
//! Holds the peer table, the inbound dispatch sinks, the shutdown signal, and
//! a registry of per-transport endpoints. Each endpoint owns its own state
//! (TLS configs, bound listener, `quinn::Endpoint`, etc.) so the manager
//! itself stays free of transport-specific fields.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use scc::HashMap as SccMap;
use tokio::time::{MissedTickBehavior, interval};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::types::NodeIdentifier;

use super::SendOptions;
use super::adaptive_queue::{
    AdaptiveQueueBudget, AdaptiveQueueItem, AdaptiveQueueReceiver, AdaptiveQueueSender,
    SendAdaptiveError, TryAdaptiveSendError,
};
use super::config::TransportConfig;
use super::connection::OutboundEnvelope;
use super::connection::{AddressBackoffSnapshot, BackoffState, OutboundFrame, PeerState};
use super::endpoint::{
    EndpointRegistry,
    kcp::KcpEndpoint,
    mux::{UdpMuxQueueTuning, UdpMuxSet},
    quic::QuicEndpoint,
    tcp::TcpEndpoint,
    udp::UdpEndpoint,
};
use super::error::{ConfigError, SendError, TransportError};
use super::identity::NodeIdentity;
use super::metrics::{
    InboundQueueStatusSnapshot, MetricsSnapshot, MetricsTuning, QueueWatermark,
    QueueWatermarkReport, assemble_snapshot,
};
use super::service_level::{
    MessageClass, PeerAddress, RoutingMetric, SeedAddress, ServiceLevel, TransportKind,
};
use super::tls::build_tls_configs;

const OUTBOUND_DISPATCH_RETRY_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Debug, Clone)]
pub struct PeerAddressSnapshot {
    node_id: NodeIdentifier,
    addresses: Vec<PeerAddress>,
    address_backoffs: HashMap<PeerAddress, AddressBackoffSnapshot>,
    last_seen: Option<SystemTime>,
}

impl PeerAddressSnapshot {
    pub fn node_id(&self) -> NodeIdentifier {
        self.node_id
    }

    pub fn addresses(&self) -> &[PeerAddress] {
        &self.addresses
    }

    pub fn address_backoffs(&self) -> &HashMap<PeerAddress, AddressBackoffSnapshot> {
        &self.address_backoffs
    }

    pub fn last_seen(&self) -> Option<SystemTime> {
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

pub type AdaptiveInboundReceiver = AdaptiveQueueReceiver<InboundMessage>;

impl AdaptiveQueueItem for OutboundEnvelope {
    fn estimated_queue_bytes(&self) -> usize {
        super::adaptive_queue::QUEUE_ITEM_OVERHEAD_BYTES.saturating_add(self.payload().len())
    }
}

/// Receiver halves returned once at `start`.
pub struct Inbound {
    control: AdaptiveQueueReceiver<InboundMessage>,
    high_priority: AdaptiveQueueReceiver<InboundMessage>,
    regular: AdaptiveQueueReceiver<InboundMessage>,
}

impl Inbound {
    pub fn new(
        control: AdaptiveQueueReceiver<InboundMessage>,
        high_priority: AdaptiveQueueReceiver<InboundMessage>,
        regular: AdaptiveQueueReceiver<InboundMessage>,
    ) -> Self {
        Self {
            control,
            high_priority,
            regular,
        }
    }

    pub fn control(&mut self) -> &mut AdaptiveQueueReceiver<InboundMessage> {
        &mut self.control
    }

    pub fn high_priority(&mut self) -> &mut AdaptiveQueueReceiver<InboundMessage> {
        &mut self.high_priority
    }

    pub fn regular(&mut self) -> &mut AdaptiveQueueReceiver<InboundMessage> {
        &mut self.regular
    }

    /// Consume the handle and return the receivers (control, high-priority, regular).
    /// Used by callers (e.g. the overlay dispatcher) that want to take owned
    /// halves into separate tasks.
    pub fn into_parts(
        self,
    ) -> (
        AdaptiveQueueReceiver<InboundMessage>,
        AdaptiveQueueReceiver<InboundMessage>,
        AdaptiveQueueReceiver<InboundMessage>,
    ) {
        (self.control, self.high_priority, self.regular)
    }
}

/// Sender halves used by all stream/datagram pumps. Cheap to clone.
#[derive(Clone)]
pub(crate) struct InboundDispatch {
    control: AdaptiveQueueSender<InboundMessage>,
    high: AdaptiveQueueSender<InboundMessage>,
    regular: AdaptiveQueueSender<InboundMessage>,
    control_watermark: Arc<Mutex<QueueWatermark>>,
    high_watermark: Arc<Mutex<QueueWatermark>>,
    regular_watermark: Arc<Mutex<QueueWatermark>>,
}

impl InboundDispatch {
    pub fn new(
        control: AdaptiveQueueSender<InboundMessage>,
        high: AdaptiveQueueSender<InboundMessage>,
        regular: AdaptiveQueueSender<InboundMessage>,
    ) -> Self {
        let now = Instant::now();
        Self {
            control,
            high,
            regular,
            control_watermark: Arc::new(Mutex::new(QueueWatermark::new(now))),
            high_watermark: Arc::new(Mutex::new(QueueWatermark::new(now))),
            regular_watermark: Arc::new(Mutex::new(QueueWatermark::new(now))),
        }
    }

    pub fn dispatch(&self, msg: InboundMessage) {
        match msg.class {
            MessageClass::Control => {
                self.record_control(false);
                match self.control.try_send(msg) {
                    Ok(()) => self.record_control(false),
                    Err(TryAdaptiveSendError::Full(_)) => {
                        self.record_control(true);
                        warn!("control inbound adaptive queue full; dropping frame");
                    }
                    Err(TryAdaptiveSendError::Closed(_)) => {
                        self.record_control(true);
                        warn!("control inbound adaptive queue closed; dropping frame");
                    }
                }
            }
            MessageClass::HighPriority => {
                self.record_high(false);
                match self.high.try_send(msg) {
                    Ok(()) => self.record_high(false),
                    Err(TryAdaptiveSendError::Full(_)) => {
                        self.record_high(true);
                        warn!("high-priority inbound adaptive queue full; dropping frame");
                    }
                    Err(TryAdaptiveSendError::Closed(_)) => {
                        self.record_high(true);
                        warn!("high-priority inbound adaptive queue closed; dropping frame");
                    }
                }
            }
            MessageClass::Regular => {
                self.record_regular(false);
                match self.regular.try_send(msg) {
                    Ok(()) => self.record_regular(false),
                    Err(TryAdaptiveSendError::Full(_)) => {
                        self.record_regular(true);
                        warn!("regular inbound adaptive queue full; dropping frame");
                    }
                    Err(TryAdaptiveSendError::Closed(_)) => {
                        self.record_regular(true);
                        warn!("regular inbound adaptive queue closed; dropping frame");
                    }
                }
            }
        }
    }

    pub fn queue_status(&self) -> Vec<InboundQueueStatusSnapshot> {
        [
            (
                MessageClass::Control,
                &self.control,
                &self.control_watermark,
            ),
            (MessageClass::HighPriority, &self.high, &self.high_watermark),
            (
                MessageClass::Regular,
                &self.regular,
                &self.regular_watermark,
            ),
        ]
        .into_iter()
        .map(|(class, sender, watermark)| {
            let (depth, capacity) = sender_queue_depth(sender);
            let status = watermark.lock().snapshot().with_current(depth, capacity);
            InboundQueueStatusSnapshot::new(class, status)
        })
        .collect()
    }

    fn record_control(&self, is_full: bool) {
        self.record_queue_sample(
            MessageClass::Control,
            &self.control,
            &self.control_watermark,
            is_full,
        );
    }

    fn record_high(&self, is_full: bool) {
        self.record_queue_sample(
            MessageClass::HighPriority,
            &self.high,
            &self.high_watermark,
            is_full,
        );
    }

    fn record_regular(&self, is_full: bool) {
        self.record_queue_sample(
            MessageClass::Regular,
            &self.regular,
            &self.regular_watermark,
            is_full,
        );
    }

    fn record_queue_sample(
        &self,
        class: MessageClass,
        sender: &AdaptiveQueueSender<InboundMessage>,
        watermark: &Arc<Mutex<QueueWatermark>>,
        is_full: bool,
    ) {
        let (depth, capacity) = sender_queue_depth(sender);
        if let Some(report) = record_queue_watermark(watermark, depth, capacity, is_full) {
            let status = report.status();
            debug!(
                ?class,
                queue_capacity = status.capacity(),
                queue_depth = status.depth(),
                queue_high_watermark = status.high_depth(),
                queue_samples = status.samples(),
                queue_full_samples = status.full_samples(),
                interval_secs = report.interval().as_secs(),
                "s2s inbound queue watermark"
            );
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
        self.insert_peer_with_outbound_queue_bytes(id, outbound_queue_bytes(&self.cfg))
    }

    fn insert_peer_with_outbound_queue_bytes(
        &self,
        id: NodeIdentifier,
        outbound_queue_bytes: usize,
    ) -> Arc<PeerState> {
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
                packet_loss_alpha: self.cfg.packet_loss_ewma_alpha(),
            },
            outbound_queue_bytes,
        );
        match self.peers.entry_sync(id) {
            scc::hash_map::Entry::Occupied(e) => e.get().clone(),
            scc::hash_map::Entry::Vacant(e) => {
                e.insert_entry(new.clone());
                spawn_peer_outbound_dispatcher(Arc::new(self.clone_for_dispatcher()), new.clone());
                new
            }
        }
    }

    fn clone_for_dispatcher(&self) -> ManagerInner {
        ManagerInner {
            self_id: self.self_id,
            peers: self.peers.clone(),
            seed_backoff: self.seed_backoff.clone(),
            successful_seeds: self.successful_seeds.clone(),
            required_outgoing: self.required_outgoing.clone(),
            inbound: self.inbound.clone(),
            shutdown: self.shutdown.clone(),
            cfg: self.cfg.clone(),
            endpoints: self.endpoints.clone(),
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

        let inbound_budget = AdaptiveQueueBudget::auto();
        let (control_tx, control_rx) =
            AdaptiveQueueSender::new(inbound_budget.split(adaptive_lane_bytes(
                inbound_budget.max_bytes(),
                cfg.inbound_control_capacity(),
                40,
            )));
        let (high_tx, high_rx) = AdaptiveQueueSender::new(inbound_budget.split(
            adaptive_lane_bytes(inbound_budget.max_bytes(), cfg.inbound_high_capacity(), 35),
        ));
        let (regular_tx, regular_rx) =
            AdaptiveQueueSender::new(inbound_budget.split(adaptive_lane_bytes(
                inbound_budget.max_bytes(),
                cfg.inbound_regular_capacity(),
                35,
            )));
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

    pub fn test_with_live_streams(
        self_id: NodeIdentifier,
        peer_node: NodeIdentifier,
        kinds: &[TransportKind],
    ) -> (Self, Vec<AdaptiveQueueReceiver<OutboundFrame>>) {
        Self::test_with_live_streams_bytes(self_id, peer_node, kinds, 1024 * 1024)
    }

    pub fn test_with_live_streams_bytes(
        self_id: NodeIdentifier,
        peer_node: NodeIdentifier,
        kinds: &[TransportKind],
        queue_bytes: usize,
    ) -> (Self, Vec<AdaptiveQueueReceiver<OutboundFrame>>) {
        let (inbound, _inbound_rx) = test_inbound_dispatch();
        let cfg = TransportConfig::new("ca.pem".into(), "cert.pem".into(), "key.pem".into());
        let inner = Arc::new(ManagerInner {
            self_id,
            peers: Arc::new(SccMap::new()),
            seed_backoff: Arc::new(SccMap::new()),
            successful_seeds: Arc::new(SccMap::new()),
            required_outgoing: Arc::new(RwLock::new(HashSet::new())),
            inbound,
            shutdown: CancellationToken::new(),
            endpoints: EndpointRegistry::empty(),
            cfg,
        });

        let peer = inner.insert_peer_with_outbound_queue_bytes(peer_node, queue_bytes);
        let mut receivers = Vec::new();
        for kind in kinds {
            let (tx, rx) = test_outbound_queue_with_bytes(queue_bytes);
            peer.install_stream(super::connection::ActiveStream::new(
                *kind,
                None,
                tx,
                CancellationToken::new(),
                false,
            ));
            receivers.push(rx);
        }

        (Self { inner }, receivers)
    }

    pub fn test_install_live_stream(
        &self,
        peer_node: NodeIdentifier,
        kind: TransportKind,
    ) -> AdaptiveQueueReceiver<OutboundFrame> {
        let peer = self.inner.get_or_create_peer(peer_node);
        let (tx, rx) = test_outbound_queue(1);
        peer.install_stream(super::connection::ActiveStream::new(
            kind,
            None,
            tx,
            CancellationToken::new(),
            false,
        ));
        rx
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

    pub async fn listen_addresses_with_public_ip_probe(&self) -> Vec<PeerAddress> {
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

    pub async fn add_address_seen_at_with_backoff(
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

    pub fn replace_advertised_addresses_seen_at(
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
        self.send_ranked(node, level, routing_metric, class, payload, options, true)
            .await
    }

    pub async fn try_send(
        &self,
        node: NodeIdentifier,
        level: ServiceLevel,
        routing_metric: Option<RoutingMetric>,
        class: MessageClass,
        payload: Bytes,
    ) -> Result<(), SendError> {
        self.try_send_with_options(
            node,
            level,
            routing_metric,
            class,
            payload,
            SendOptions::default(),
        )
        .await
    }

    pub async fn try_send_with_options(
        &self,
        node: NodeIdentifier,
        level: ServiceLevel,
        routing_metric: Option<RoutingMetric>,
        class: MessageClass,
        payload: Bytes,
        options: SendOptions,
    ) -> Result<(), SendError> {
        self.send_ranked(node, level, routing_metric, class, payload, options, false)
            .await
    }

    async fn send_ranked(
        &self,
        node: NodeIdentifier,
        level: ServiceLevel,
        routing_metric: Option<RoutingMetric>,
        class: MessageClass,
        payload: Bytes,
        options: SendOptions,
        wait_on_final_transport: bool,
    ) -> Result<(), SendError> {
        let routing_metric =
            routing_metric.unwrap_or_else(|| RoutingMetric::default_for_level(level));
        let peer = self
            .inner
            .get_peer(node)
            .ok_or(SendError::UnknownNode { node })?;

        if !has_eligible_transport(&peer, level, routing_metric) {
            return Err(SendError::NoSuitableTransport { node });
        }

        let envelope = OutboundEnvelope::routed(level, routing_metric, class, payload, options);
        self.enqueue_outbound(&peer, envelope, wait_on_final_transport)
            .await
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
        if peer.try_get_stream(transport).is_none() {
            return Err(SendError::StreamClosed { node, transport });
        }
        let envelope = OutboundEnvelope::fixed_transport(transport, class, payload, options);
        self.enqueue_outbound(&peer, envelope, true).await
    }

    async fn enqueue_outbound(
        &self,
        peer: &Arc<PeerState>,
        envelope: OutboundEnvelope,
        wait_for_space: bool,
    ) -> Result<(), SendError> {
        let class = envelope.class();
        let sender = peer.outbound_sender();
        record_outbound_queue_sample(peer, class, &sender, false);
        match sender.try_send(envelope) {
            Ok(()) => {
                peer.notify_outbound_dispatch();
                record_outbound_queue_sample(peer, class, &sender, false);
                Ok(())
            }
            Err(TryAdaptiveSendError::Full(envelope)) if wait_for_space => {
                record_outbound_queue_sample(peer, class, &sender, true);
                sender
                    .send(envelope)
                    .await
                    .map_err(|SendAdaptiveError(_)| SendError::Shutdown)?;
                peer.notify_outbound_dispatch();
                record_outbound_queue_sample(peer, class, &sender, false);
                Ok(())
            }
            Err(TryAdaptiveSendError::Full(envelope)) => {
                record_outbound_queue_sample(peer, class, &sender, true);
                Err(SendError::Backpressure {
                    node: peer.node_id(),
                    transport: envelope.target_transport().unwrap_or_else(|| {
                        pick_transports(peer, envelope.level(), envelope.routing_metric())
                            .into_iter()
                            .next()
                            .unwrap_or(TransportKind::Tcp)
                    }),
                })
            }
            Err(TryAdaptiveSendError::Closed(_)) => Err(SendError::Shutdown),
        }
    }

    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        let entries: Vec<_> = self
            .inner
            .iter_peers()
            .into_iter()
            .map(|(n, p)| (n, p.metrics().clone()))
            .collect();
        let mut outbound_queues = self
            .inner
            .iter_peers()
            .into_iter()
            .flat_map(|(_, peer)| peer.outbound_queue_status())
            .collect::<Vec<_>>();
        outbound_queues.sort_by_key(|queue| (queue.peer(), queue.queue_key()));
        assemble_snapshot(entries, outbound_queues, self.inner.inbound.queue_status())
    }

    pub fn peer_address_snapshot(&self) -> Vec<PeerAddressSnapshot> {
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

    pub fn set_required_outgoing_nodes(&self, nodes: HashSet<NodeIdentifier>) {
        self.inner.set_required_outgoing_nodes(nodes);
    }

    pub fn live_transport_kinds(&self, node: NodeIdentifier) -> Vec<TransportKind> {
        self.inner
            .get_peer(node)
            .map(|peer| peer.live_kinds())
            .unwrap_or_default()
    }

    pub fn has_live_transport_kind(&self, node: NodeIdentifier, kind: TransportKind) -> bool {
        self.live_transport_kinds(node).contains(&kind)
    }

    pub fn live_peers(&self) -> Vec<(NodeIdentifier, Vec<TransportKind>)> {
        self.inner
            .iter_peers()
            .into_iter()
            .filter_map(|(node, peer)| {
                peer.has_any_live_stream()
                    .then(|| (node, peer.live_kinds()))
            })
            .collect()
    }

    pub fn record_peer_rtt(
        &self,
        node: NodeIdentifier,
        transport: TransportKind,
        rtt: std::time::Duration,
    ) {
        if let Some(peer) = self.inner.get_peer(node) {
            peer.metrics().record_rtt(transport, rtt);
        }
    }

    pub fn ranked_live_transports_for(
        &self,
        node: NodeIdentifier,
        level: ServiceLevel,
        metric: RoutingMetric,
    ) -> Vec<TransportKind> {
        let Some(peer) = self.inner.get_peer(node) else {
            return Vec::new();
        };
        let mut candidates = peer
            .live_kinds()
            .into_iter()
            .filter(|kind| kind.is_acceptable_for(level))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Vec::new();
        }

        let mut ranked = peer
            .metrics()
            .ranked_transports_for(level, metric, &candidates);
        candidates.sort_by_key(|kind| fallback_transport_rank(*kind, level));
        for candidate in candidates {
            if !ranked.contains(&candidate) {
                ranked.push(candidate);
            }
        }
        ranked
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
/// overlay routing fallback (`shitspeak_s2s::overlay::routing`):
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

    candidates.sort_by_key(|k| fallback_transport_rank(*k, level));

    for candidate in candidates {
        if !ranked.contains(&candidate) {
            ranked.push(candidate);
        }
    }

    ranked
}

fn has_eligible_transport(
    peer: &PeerState,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
) -> bool {
    !pick_transports(peer, level, routing_metric).is_empty()
}

fn spawn_peer_outbound_dispatcher(inner: Arc<ManagerInner>, peer: Arc<PeerState>) {
    let Some(receiver) = peer.take_outbound_receiver() else {
        return;
    };
    tokio::spawn(run_peer_outbound_dispatcher(inner, peer, receiver));
}

async fn run_peer_outbound_dispatcher(
    inner: Arc<ManagerInner>,
    peer: Arc<PeerState>,
    mut receiver: AdaptiveQueueReceiver<OutboundEnvelope>,
) {
    let mut retry_tick = interval(OUTBOUND_DISPATCH_RETRY_INTERVAL);
    retry_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        let maybe_envelope = tokio::select! {
            biased;
            _ = inner.shutdown().cancelled() => return,
            envelope = receiver.recv() => envelope,
        };
        let Some(mut envelope) = maybe_envelope else {
            return;
        };

        loop {
            if inner.shutdown().is_cancelled() {
                return;
            }
            match try_dispatch_envelope(&peer, envelope) {
                Ok(()) => break,
                Err(envelope_back) => {
                    envelope = envelope_back;
                }
            }

            tokio::select! {
                biased;
                _ = inner.shutdown().cancelled() => return,
                _ = peer.wait_for_outbound_dispatch_signal() => {}
                _ = retry_tick.tick() => {}
            }
        }
    }
}

fn try_dispatch_envelope(
    peer: &Arc<PeerState>,
    envelope: OutboundEnvelope,
) -> Result<(), OutboundEnvelope> {
    let class = envelope.class();
    let choices = if let Some(transport) = envelope.target_transport() {
        vec![transport]
    } else {
        pick_transports(peer, envelope.level(), envelope.routing_metric())
    };

    if choices.is_empty() {
        return Err(envelope);
    }

    let frame = envelope.clone().into_frame();
    for transport in choices {
        let Some(sender) = peer.try_get_stream(transport) else {
            continue;
        };
        if sender.depth_bytes() > 0 {
            record_outbound_stream_queue_sample(peer, transport, class, &sender, true);
            continue;
        }
        record_outbound_stream_queue_sample(peer, transport, class, &sender, false);
        match sender.try_send(frame.clone()) {
            Ok(()) => {
                record_outbound_stream_queue_sample(peer, transport, class, &sender, false);
                return Ok(());
            }
            Err(TryAdaptiveSendError::Full(_)) => {
                record_outbound_stream_queue_sample(peer, transport, class, &sender, true);
            }
            Err(TryAdaptiveSendError::Closed(_)) => {}
        }
    }

    Err(envelope)
}

fn accepts(kind: TransportKind, requested: ServiceLevel) -> bool {
    kind.is_acceptable_for(requested)
}

fn fallback_transport_rank(kind: TransportKind, requested: ServiceLevel) -> (u8, u8, u8) {
    let provided = kind.service_level();
    let exact_first = if provided == requested { 0 } else { 1 };
    (exact_first, provided as u8, kind_order(kind))
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

pub(crate) fn adaptive_lane_bytes(
    global_bytes: usize,
    legacy_capacity: usize,
    percent: usize,
) -> usize {
    let share = global_bytes.saturating_mul(percent).saturating_div(100);
    let legacy_floor = legacy_capacity.max(1).saturating_mul(512).max(512 * 1024);
    share.max(legacy_floor).min(global_bytes)
}

fn outbound_queue_bytes(cfg: &TransportConfig) -> usize {
    let budget = AdaptiveQueueBudget::auto();
    adaptive_lane_bytes(budget.max_bytes(), cfg.outbound_capacity(), 50)
}

fn test_outbound_queue_with_bytes(
    bytes: usize,
) -> (
    AdaptiveQueueSender<OutboundFrame>,
    AdaptiveQueueReceiver<OutboundFrame>,
) {
    let budget = AdaptiveQueueBudget::new(bytes);
    AdaptiveQueueSender::new(budget.split(budget.max_bytes()))
}

fn test_outbound_queue(
    legacy_capacity: usize,
) -> (
    AdaptiveQueueSender<OutboundFrame>,
    AdaptiveQueueReceiver<OutboundFrame>,
) {
    test_outbound_queue_with_bytes(adaptive_lane_bytes(
        1024 * 1024,
        legacy_capacity.max(1),
        100,
    ))
}

fn test_inbound_dispatch() -> (InboundDispatch, Inbound) {
    let budget = AdaptiveQueueBudget::new(3 * 1024 * 1024);
    let (control_tx, control_rx) = AdaptiveQueueSender::new(budget.split(1024 * 1024));
    let (high_tx, high_rx) = AdaptiveQueueSender::new(budget.split(1024 * 1024));
    let (regular_tx, regular_rx) = AdaptiveQueueSender::new(budget.split(1024 * 1024));
    (
        InboundDispatch::new(control_tx, high_tx, regular_tx),
        Inbound::new(control_rx, high_rx, regular_rx),
    )
}

fn record_outbound_queue_sample(
    peer: &PeerState,
    class: MessageClass,
    sender: &AdaptiveQueueSender<OutboundEnvelope>,
    is_full: bool,
) {
    let (depth, max_capacity) = sender_queue_depth(sender);
    peer.record_outbound_queue_sample(class, depth, max_capacity, is_full);
}

fn record_outbound_stream_queue_sample(
    peer: &PeerState,
    transport: TransportKind,
    class: MessageClass,
    sender: &AdaptiveQueueSender<OutboundFrame>,
    is_full: bool,
) {
    let (depth, max_capacity) = sender_queue_depth(sender);
    peer.record_outbound_stream_queue_sample(transport, class, depth, max_capacity, is_full);
}

fn sender_queue_depth<T>(sender: &AdaptiveQueueSender<T>) -> (usize, usize)
where
    T: AdaptiveQueueItem,
{
    (sender.depth_bytes(), sender.capacity_bytes())
}

fn record_queue_watermark(
    watermark: &Arc<Mutex<QueueWatermark>>,
    depth: usize,
    capacity: usize,
    is_full: bool,
) -> Option<QueueWatermarkReport> {
    watermark
        .lock()
        .record(Instant::now(), depth, capacity, is_full)
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
    let mux = UdpMuxSet::new(
        &udp_family_listen_addrs(cfg),
        UdpMuxQueueTuning::for_max_users(cfg.max_users()),
    );
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
    use tokio_util::sync::CancellationToken;

    fn socket(raw: &str) -> SocketAddr {
        raw.parse().unwrap()
    }

    fn peer_with_live_transports(
        kinds: &[TransportKind],
    ) -> (Arc<PeerState>, Vec<AdaptiveQueueReceiver<OutboundFrame>>) {
        let peer = PeerState::new(
            2,
            Duration::from_millis(10),
            Duration::from_secs(60),
            MetricsTuning::default(),
            1024 * 1024,
        );
        let mut receivers = Vec::new();
        for kind in kinds {
            let (tx, rx) = test_outbound_queue(1);
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
        let (dispatch, inbound) = test_inbound_dispatch();
        let (mut control_rx, mut high_rx, mut regular_rx) = inbound.into_parts();

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

    #[tokio::test]
    async fn inbound_dispatch_queue_status_tracks_depth_and_full_samples() {
        let (dispatch, inbound) = test_inbound_dispatch();
        let (_control_rx, _high_rx, mut regular_rx) = inbound.into_parts();

        dispatch.dispatch(InboundMessage::new(
            7,
            ServiceLevel::Reliable,
            TransportKind::Tcp,
            MessageClass::Regular,
            Bytes::from_static(b"first"),
        ));
        dispatch.dispatch(InboundMessage::new(
            7,
            ServiceLevel::Reliable,
            TransportKind::Tcp,
            MessageClass::Regular,
            Bytes::from_static(b"dropped"),
        ));

        let status = dispatch.queue_status();
        let regular = status
            .iter()
            .find(|queue| queue.class() == MessageClass::Regular)
            .expect("regular queue status")
            .status();
        assert_eq!(
            regular.depth(),
            (crate::adaptive_queue::QUEUE_ITEM_OVERHEAD_BYTES + b"first".len())
                + (crate::adaptive_queue::QUEUE_ITEM_OVERHEAD_BYTES + b"dropped".len())
        );
        assert!(regular.capacity() >= 1024 * 1024);
        assert!(
            regular.high_depth()
                >= crate::adaptive_queue::QUEUE_ITEM_OVERHEAD_BYTES + b"first".len()
        );
        assert_eq!(regular.samples(), 4);
        assert_eq!(regular.full_samples(), 0);

        assert_eq!(&regular_rx.recv().await.unwrap().payload()[..], b"first");
        assert_eq!(&regular_rx.recv().await.unwrap().payload()[..], b"dropped");
    }

    #[tokio::test]
    async fn try_send_with_options_returns_backpressure_when_all_eligible_streams_full() {
        let (transport, _receivers) = ConnectionManager::test_with_live_streams_bytes(
            1,
            2,
            &[TransportKind::Tcp],
            1024 * 1024,
        );

        transport
            .try_send_with_options(
                2,
                ServiceLevel::Reliable,
                None,
                MessageClass::Regular,
                Bytes::from(vec![1; 1024 * 1024 - 512]),
                SendOptions::default(),
            )
            .await
            .unwrap();

        let result = tokio::time::timeout(
            Duration::from_millis(20),
            transport.try_send_with_options(
                2,
                ServiceLevel::Reliable,
                None,
                MessageClass::Regular,
                Bytes::from_static(b"blocked"),
                SendOptions::default(),
            ),
        )
        .await
        .expect("try_send_with_options should not wait for queue space");

        assert!(matches!(
            result,
            Err(SendError::Backpressure {
                node: 2,
                transport: TransportKind::Tcp
            })
        ));
    }

    #[tokio::test]
    async fn dispatcher_falls_back_when_earlier_stream_handoff_is_full() {
        let (transport, mut receivers) = ConnectionManager::test_with_live_streams_bytes(
            1,
            2,
            &[TransportKind::Tcp, TransportKind::Quic],
            1024 * 1024,
        );

        let direct_peer = transport.inner.get_peer(2).expect("peer");
        let tcp_sender = direct_peer
            .try_get_stream(TransportKind::Tcp)
            .expect("tcp sender");
        tcp_sender
            .try_send(OutboundFrame::new(
                MessageClass::Regular,
                Bytes::from(vec![1; 1024 * 1024 - 512]),
            ))
            .unwrap();

        transport
            .try_send_with_options(
                2,
                ServiceLevel::Reliable,
                None,
                MessageClass::Regular,
                Bytes::from_static(b"fallback"),
                SendOptions::default(),
            )
            .await
            .unwrap();

        let forwarded = tokio::time::timeout(Duration::from_millis(50), receivers[1].recv())
            .await
            .expect("fallback dispatch should not wait for tcp")
            .expect("quic receiver");
        assert_eq!(&forwarded.payload()[..], b"fallback");
        assert_eq!(
            receivers[0].try_recv().unwrap().payload().len(),
            1024 * 1024 - 512
        );
    }

    #[tokio::test]
    async fn send_with_options_waits_for_peer_queue_space_not_stream_handoff_space() {
        let (transport, mut receivers) = ConnectionManager::test_with_live_streams_bytes(
            1,
            2,
            &[TransportKind::Tcp],
            1024 * 1024,
        );

        let direct_peer = transport.inner.get_peer(2).expect("peer");
        let tcp_sender = direct_peer
            .try_get_stream(TransportKind::Tcp)
            .expect("tcp sender");
        tcp_sender
            .try_send(OutboundFrame::new(
                MessageClass::Regular,
                Bytes::from(vec![1; 1024 * 1024 - 512]),
            ))
            .unwrap();

        transport
            .send_with_options(
                2,
                ServiceLevel::Reliable,
                None,
                MessageClass::Regular,
                Bytes::from_static(b"queued-before-routing"),
                SendOptions::default(),
            )
            .await
            .unwrap();

        assert_eq!(
            receivers[0].recv().await.unwrap().payload().len(),
            1024 * 1024 - 512
        );
        let forwarded = tokio::time::timeout(Duration::from_millis(50), receivers[0].recv())
            .await
            .expect("dispatcher should retry once handoff space is available")
            .expect("tcp receiver");
        assert_eq!(&forwarded.payload()[..], b"queued-before-routing");
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
