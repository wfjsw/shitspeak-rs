//! `ConnectionManager` — public face of the transport module.
//!
//! Holds the peer table, the inbound dispatch sinks, the shutdown signal, and
//! a registry of per-transport endpoints. Each endpoint owns its own state
//! (TLS configs, bound listener, `quinn::Endpoint`, etc.) so the manager
//! itself stays free of transport-specific fields.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use scc::HashMap as SccMap;
use tokio::time::{MissedTickBehavior, interval};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::types::NodeIdentifier;

use super::SendOptions;
use super::adaptive_queue::{
    AdaptiveQueueBudget, AdaptiveQueueItem, AdaptiveQueueReceiver, AdaptiveQueueSender, Queued,
    SendAdaptiveError, TryAdaptiveSendError,
};
use super::config::{KcpTuning, TransportConfig, TransportRoutingPolicy};
use super::connection::{
    AddressBackoffSnapshot, BackoffState, OutboundFrame, PeerOutboundReceiver, PeerOutboundSender,
    PeerState,
};
use super::connection::{OutboundEnvelope, TransportPayloadPlan};
use super::endpoint::{
    EndpointRegistry,
    kcp::KcpEndpoint,
    mux::{DISCRIMINATOR_LEN, UdpMuxQueueTuning, UdpMuxSet},
    quic::QuicEndpoint,
    tcp::TcpEndpoint,
    udp::{
        UDP_ENCRYPTED_OVERHEAD, UdpEndpoint, initial_udp_datagram_mtu, udp_datagram_mtu_ceiling,
    },
};
use super::error::{ConfigError, SendError, TransportError};
use super::frame::encoded_data_frame_len;
use super::identity::NodeIdentity;
use super::metrics::{
    ExpiredOutboundDropStage, InboundQueueStatusSnapshot, LinkMetrics, MetricsSnapshot,
    MetricsTuning, QueueWatermark, QueueWatermarkReport, TransportHealthExclusionReason,
    assemble_snapshot,
};
use super::service_level::{
    MessageClass, PeerAddress, RoutingMetric, SeedAddress, ServiceLevel, TransportKind,
};
use super::tls::build_tls_configs;

const OUTBOUND_DISPATCH_RETRY_INTERVAL: Duration = Duration::from_millis(5);
const DEADLINE_DRAIN_FALLBACK_BYTES_PER_SEC: f64 = 16.0 * 1024.0;
const DEADLINE_NEAR_EXPIRED_TTL: Duration = Duration::from_millis(20);
const MAX_CONSECUTIVE_HIGH_PRIORITY: usize = 32;
const MAX_OUTBOUND_INGRESS_PER_TURN: usize = 256;
const MAX_OUTBOUND_DISPATCH_ATTEMPTS_PER_TURN: usize = 128;
const MAX_OUTBOUND_EXPIRY_PURGES_PER_TURN: usize = 256;
const MAX_BLOCKED_LANE_PASSES: usize = 2;

#[derive(Debug, Clone, Copy)]
struct TransportSelectionConfig {
    routing: TransportRoutingPolicy,
    kcp: KcpTuning,
}

impl TransportSelectionConfig {
    fn from_config(cfg: &TransportConfig) -> Self {
        Self {
            routing: cfg.routing_policy(),
            kcp: cfg.kcp_tuning(),
        }
    }
}

impl From<TransportRoutingPolicy> for TransportSelectionConfig {
    fn from(routing: TransportRoutingPolicy) -> Self {
        Self {
            routing,
            kcp: KcpTuning::default(),
        }
    }
}

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
#[cfg_attr(any(test, feature = "test-support"), derive(Clone))]
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

    /// Construct an inbound frame for deterministic transport/overlay tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(
        from: NodeIdentifier,
        level: ServiceLevel,
        transport: TransportKind,
        class: MessageClass,
        payload: Bytes,
    ) -> Self {
        Self::new(from, level, transport, class, payload)
    }
}

pub type AdaptiveInboundReceiver = AdaptiveQueueReceiver<InboundMessage>;

impl AdaptiveQueueItem for OutboundEnvelope {
    fn estimated_queue_bytes(&self) -> usize {
        super::adaptive_queue::QUEUE_ITEM_OVERHEAD_BYTES
            .saturating_add(self.payloads().estimated_bytes())
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
    quarantined_self_seeds: Arc<SccMap<SeedAddress, Instant>>,
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
        new.set_udp_datagram_mtu_limits(
            initial_udp_datagram_mtu(self.cfg.udp_mtu()),
            udp_datagram_mtu_ceiling(self.cfg.udp_mtu()),
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
            quarantined_self_seeds: self.quarantined_self_seeds.clone(),
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

    pub fn self_seed_quarantine_active(&self, addr: &SeedAddress, now: Instant) -> bool {
        let Some(entry) = self.quarantined_self_seeds.get_sync(addr) else {
            return false;
        };
        if *entry.get() > now {
            return true;
        }
        drop(entry);
        let _ = self.quarantined_self_seeds.remove_sync(addr);
        false
    }

    pub fn quarantine_self_seed(&self, addr: SeedAddress, now: Instant) -> bool {
        let until = now + self.cfg.self_seed_quarantine();
        match self.quarantined_self_seeds.entry_sync(addr) {
            scc::hash_map::Entry::Occupied(mut entry) => {
                let should_log = *entry.get() <= now;
                *entry.get_mut() = until;
                should_log
            }
            scc::hash_map::Entry::Vacant(entry) => {
                entry.insert_entry(until);
                true
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
    /// Check whether an identity-encoded data payload fits as one frame on a
    /// selected transport. Stream transports have no datagram ceiling.
    pub fn payload_fits_transport(
        &self,
        node: NodeIdentifier,
        transport: TransportKind,
        level: ServiceLevel,
        class: MessageClass,
        payload: &[u8],
    ) -> bool {
        match transport {
            TransportKind::Tcp | TransportKind::Kcp | TransportKind::Quic => true,
            TransportKind::Udp => self
                .udp_datagram_len(node, level, class, payload.len())
                .is_some_and(|bytes| bytes <= self.udp_datagram_mtu_for(node)),
        }
    }

    fn udp_datagram_mtu_for(&self, node: NodeIdentifier) -> usize {
        self.inner
            .get_peer(node)
            .map(|peer| peer.udp_datagram_mtu())
            .unwrap_or_else(|| initial_udp_datagram_mtu(self.inner.cfg().udp_mtu()))
    }

    fn udp_datagram_len(
        &self,
        node: NodeIdentifier,
        level: ServiceLevel,
        class: MessageClass,
        payload_len: usize,
    ) -> Option<usize> {
        Some(
            DISCRIMINATOR_LEN
                .saturating_add(UDP_ENCRYPTED_OVERHEAD)
                .saturating_add(encoded_data_frame_len(
                    self.inner.self_id(),
                    node,
                    level,
                    class,
                    transport_timestamp_us(),
                    payload_len,
                )),
        )
    }

    /// Force a transport kind down for a peer in fault-injection tests.
    /// Reconnection remains owned by the normal transport supervisor.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_drop_transport_kind(&self, node: NodeIdentifier, kind: TransportKind) -> bool {
        let Some(peer) = self.inner.get_peer(node) else {
            return false;
        };
        let was_live = peer.live_kinds().contains(&kind);
        peer.drop_stream(kind);
        was_live
    }

    /// Test hook for a peer transport's link state. Taking it down cancels
    /// the current stream. Bringing it up observes whether the normal
    /// supervisor has reconnected it using retained peer addresses.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_set_transport_kind_up(
        &self,
        node: NodeIdentifier,
        kind: TransportKind,
        up: bool,
    ) -> bool {
        if up {
            return self.has_live_transport_kind(node, kind);
        }
        self.test_drop_transport_kind(node, kind)
    }

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
            quarantined_self_seeds: Arc::new(SccMap::new()),
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
            quarantined_self_seeds: Arc::new(SccMap::new()),
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
        self.send_ranked(
            node,
            level,
            routing_metric,
            class,
            TransportPayloadPlan::new(payload),
            options,
            true,
        )
        .await
    }

    pub async fn send_with_payload_plan(
        &self,
        node: NodeIdentifier,
        level: ServiceLevel,
        routing_metric: Option<RoutingMetric>,
        class: MessageClass,
        payloads: TransportPayloadPlan,
        options: SendOptions,
    ) -> Result<(), SendError> {
        self.send_ranked(node, level, routing_metric, class, payloads, options, true)
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
        self.send_ranked(
            node,
            level,
            routing_metric,
            class,
            TransportPayloadPlan::new(payload),
            options,
            false,
        )
        .await
    }

    pub async fn try_send_with_payload_plan(
        &self,
        node: NodeIdentifier,
        level: ServiceLevel,
        routing_metric: Option<RoutingMetric>,
        class: MessageClass,
        payloads: TransportPayloadPlan,
        options: SendOptions,
    ) -> Result<(), SendError> {
        self.send_ranked(node, level, routing_metric, class, payloads, options, false)
            .await
    }

    async fn send_ranked(
        &self,
        node: NodeIdentifier,
        level: ServiceLevel,
        routing_metric: Option<RoutingMetric>,
        class: MessageClass,
        payloads: TransportPayloadPlan,
        options: SendOptions,
        wait_on_final_transport: bool,
    ) -> Result<(), SendError> {
        let routing_metric =
            routing_metric.unwrap_or_else(|| RoutingMetric::default_for_level(level));
        let peer = self
            .inner
            .get_peer(node)
            .ok_or(SendError::UnknownNode { node })?;

        let selection = TransportSelectionConfig::from_config(self.inner.cfg());
        let choices = pick_transports(
            &peer,
            level,
            routing_metric,
            class,
            options,
            payloads.default_variant().primary().len(),
            selection,
        );
        if choices.is_empty() {
            return Err(SendError::NoSuitableTransport { node });
        }
        let choices_fit = choices.iter().any(|transport| {
            *transport == TransportKind::Udp
                || self.payload_fits_transport(
                    node,
                    *transport,
                    level,
                    class,
                    payloads.variant(*transport).primary(),
                )
        });
        if !choices_fit {
            return Err(SendError::NoSuitableTransport { node });
        }

        let envelope =
            OutboundEnvelope::routed_with_payloads(level, routing_metric, class, payloads, options);
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
        if envelope.options().is_expired() {
            peer.record_expired_outbound_drop(
                ExpiredOutboundDropStage::PeerQueueEnqueue,
                envelope.target_transport(),
                envelope.class(),
            );
            return Ok(());
        }
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
                        pick_transports(
                            peer,
                            envelope.level(),
                            envelope.routing_metric(),
                            envelope.class(),
                            envelope.options(),
                            envelope.payload().len(),
                            TransportSelectionConfig::from_config(self.inner.cfg()),
                        )
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
        let mut expired_outbound_drops = self
            .inner
            .iter_peers()
            .into_iter()
            .flat_map(|(_, peer)| peer.expired_outbound_drop_status())
            .collect::<Vec<_>>();
        expired_outbound_drops.sort_by_key(|drop| {
            (
                drop.peer(),
                drop.stage().name(),
                drop.transport(),
                drop.class() as u8,
            )
        });
        let mut transport_health_exclusions = self
            .inner
            .iter_peers()
            .into_iter()
            .flat_map(|(_, peer)| peer.transport_health_exclusion_status())
            .collect::<Vec<_>>();
        transport_health_exclusions
            .sort_by_key(|exclusion| (exclusion.peer(), exclusion.transport(), exclusion.reason()));
        assemble_snapshot(
            entries,
            outbound_queues,
            self.inner.inbound.queue_status(),
            expired_outbound_drops,
            transport_health_exclusions,
        )
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

    pub fn advertisable_transport_kinds(&self, node: NodeIdentifier) -> Vec<TransportKind> {
        self.inner
            .get_peer(node)
            .map(|peer| {
                advertisable_transport_kinds(
                    &peer,
                    TransportSelectionConfig::from_config(self.inner.cfg()),
                )
            })
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

    pub fn advertisable_peers(&self) -> Vec<(NodeIdentifier, Vec<TransportKind>)> {
        let selection = TransportSelectionConfig::from_config(self.inner.cfg());
        self.inner
            .iter_peers()
            .into_iter()
            .filter_map(|(node, peer)| {
                let kinds = advertisable_transport_kinds(&peer, selection);
                (!kinds.is_empty()).then_some((node, kinds))
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
        let candidates = peer
            .live_kinds()
            .into_iter()
            .filter(|kind| kind.is_acceptable_for(level))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Vec::new();
        }

        pick_transports(
            &peer,
            level,
            metric,
            MessageClass::HighPriority,
            SendOptions::default(),
            0,
            TransportSelectionConfig::from_config(self.inner.cfg()),
        )
    }

    /// Best queue-pressure penalty the sender would see for this peer now.
    /// Lower is better; expiring sends use adaptive deadline pressure while
    /// non-expiring regular sends use the existing queued-stream penalty.
    pub fn best_send_queue_pressure(
        &self,
        node: NodeIdentifier,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        options: SendOptions,
    ) -> Option<u8> {
        let peer = self.inner.get_peer(node)?;
        let now = Instant::now();
        pick_transports(
            &peer,
            level,
            routing_metric,
            class,
            options,
            0,
            TransportSelectionConfig::from_config(self.inner.cfg()),
        )
        .first()
        .copied()
        .map(|transport| send_queue_penalty(&peer, transport, class, options, now))
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
    pick_transports(
        peer,
        level,
        routing_metric,
        MessageClass::Regular,
        SendOptions::default(),
        0,
        TransportRoutingPolicy::default(),
    )
    .first()
    .copied()
}

fn pick_transports(
    peer: &PeerState,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    options: SendOptions,
    payload_len: usize,
    selection: impl Into<TransportSelectionConfig>,
) -> Vec<TransportKind> {
    let selection = selection.into();
    let now = Instant::now();
    let snapshot = peer.metrics().snapshot_per_transport();
    let mut candidates: Vec<TransportKind> = peer
        .live_kinds()
        .into_iter()
        .filter(|k| accepts(*k, level))
        .collect();
    if candidates.is_empty() {
        return Vec::new();
    }
    let has_viable_kcp_alternative = candidates.iter().copied().any(|transport| {
        transport != TransportKind::Kcp
            && transport_is_viable_alternative(peer, transport, &snapshot, selection.routing, now)
    });
    candidates.retain(|transport| {
        if let Some(reason) = transport_candidate_exclusion_reason(
            peer,
            *transport,
            level,
            class,
            options,
            &snapshot,
            selection,
            has_viable_kcp_alternative,
            now,
        ) {
            peer.record_transport_health_exclusion(*transport, reason);
            false
        } else {
            true
        }
    });
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

    apply_transport_routing_policy(
        peer,
        &mut ranked,
        level,
        routing_metric,
        class,
        options,
        payload_len,
        selection.routing,
    );
    enforce_expiring_voice_admission(
        peer,
        &mut ranked,
        level,
        routing_metric,
        class,
        options,
        selection.routing,
    );

    if options.expires_at().is_some() {
        ranked.sort_by_key(|kind| deadline_queue_penalty(peer, *kind, options, now));
        if class == MessageClass::HighPriority {
            ranked.retain(|kind| deadline_queue_penalty(peer, *kind, options, now) < 3);
        }
    } else if class == MessageClass::Regular {
        ranked.sort_by_key(|kind| regular_queue_penalty(peer, *kind));
    }

    ranked
}

fn advertisable_transport_kinds(
    peer: &PeerState,
    selection: TransportSelectionConfig,
) -> Vec<TransportKind> {
    let now = Instant::now();
    let snapshot = peer.metrics().snapshot_per_transport();
    let live = peer.live_kinds();
    let has_viable_kcp_alternative = live.iter().copied().any(|transport| {
        transport != TransportKind::Kcp
            && transport_is_viable_alternative(peer, transport, &snapshot, selection.routing, now)
    });
    live.into_iter()
        .filter(|transport| {
            transport_candidate_health_allows(
                peer,
                *transport,
                ServiceLevel::BestEffort,
                MessageClass::HighPriority,
                SendOptions::default(),
                &snapshot,
                selection,
                has_viable_kcp_alternative,
                now,
            )
        })
        .collect()
}

fn transport_candidate_health_allows(
    peer: &PeerState,
    transport: TransportKind,
    level: ServiceLevel,
    class: MessageClass,
    options: SendOptions,
    snapshot: &HashMap<TransportKind, LinkMetrics>,
    selection: TransportSelectionConfig,
    has_viable_kcp_alternative: bool,
    now: Instant,
) -> bool {
    transport_candidate_exclusion_reason(
        peer,
        transport,
        level,
        class,
        options,
        snapshot,
        selection,
        has_viable_kcp_alternative,
        now,
    )
    .is_none()
}

fn transport_candidate_exclusion_reason(
    peer: &PeerState,
    transport: TransportKind,
    level: ServiceLevel,
    class: MessageClass,
    options: SendOptions,
    snapshot: &HashMap<TransportKind, LinkMetrics>,
    selection: TransportSelectionConfig,
    has_viable_kcp_alternative: bool,
    now: Instant,
) -> Option<TransportHealthExclusionReason> {
    if kcp_should_fail_away(
        peer,
        transport,
        snapshot.get(&transport),
        selection,
        has_viable_kcp_alternative,
        now,
    ) {
        return Some(TransportHealthExclusionReason::KcpFailaway);
    }

    if (level == ServiceLevel::BestEffort
        || class == MessageClass::HighPriority
        || options.expires_at().is_some())
        && transport_queue_known_dead(
            peer,
            transport,
            snapshot.get(&transport),
            selection.routing,
            now,
        )
    {
        return Some(TransportHealthExclusionReason::StaleQueue);
    }

    None
}

fn transport_is_viable_alternative(
    peer: &PeerState,
    transport: TransportKind,
    snapshot: &HashMap<TransportKind, LinkMetrics>,
    policy: TransportRoutingPolicy,
    now: Instant,
) -> bool {
    !transport_queue_known_dead(peer, transport, snapshot.get(&transport), policy, now)
}

fn kcp_should_fail_away(
    peer: &PeerState,
    transport: TransportKind,
    link: Option<&LinkMetrics>,
    selection: TransportSelectionConfig,
    has_viable_alternative: bool,
    now: Instant,
) -> bool {
    if transport != TransportKind::Kcp || !transport_has_outstanding_queue_work(peer, transport) {
        return false;
    }
    let Some(last_update) = link.and_then(LinkMetrics::last_update) else {
        return false;
    };
    let no_progress_for = now.saturating_duration_since(last_update);
    let threshold = if has_viable_alternative {
        selection.kcp.failaway_with_alternative()
    } else {
        selection.kcp.failaway_without_alternative()
    };
    no_progress_for >= threshold
}

fn transport_queue_known_dead(
    peer: &PeerState,
    transport: TransportKind,
    link: Option<&LinkMetrics>,
    policy: TransportRoutingPolicy,
    now: Instant,
) -> bool {
    if !transport.is_stream() || !transport_has_outstanding_queue_work(peer, transport) {
        return false;
    }
    let Some(link) = link else {
        return false;
    };
    let Some(last_update) = link.last_update() else {
        return false;
    };
    if now.saturating_duration_since(last_update) < policy.transport_metric_stale_after() {
        return false;
    }
    link.wire_sent_bps() <= f64::EPSILON && link.wire_recv_bps() <= f64::EPSILON
}

fn transport_has_outstanding_queue_work(peer: &PeerState, transport: TransportKind) -> bool {
    peer.outbound_stream_queue_status(transport)
        .is_some_and(|status| status.depth() > 0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpFamilyHealth {
    Probing,
    Viable,
    Degraded,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportSelectionIntent {
    Default,
    TcpFavored,
    LatencySensitive,
}

fn apply_transport_routing_policy(
    peer: &PeerState,
    ranked: &mut Vec<TransportKind>,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    options: SendOptions,
    payload_len: usize,
    policy: TransportRoutingPolicy,
) {
    if ranked.len() < 2 || best_effort_without_voice_deadline(level, routing_metric, class, options)
    {
        return;
    }

    let Some(tcp_pos) = ranked.iter().position(|kind| *kind == TransportKind::Tcp) else {
        return;
    };

    let intent = transport_selection_intent(
        peer,
        level,
        routing_metric,
        class,
        options,
        payload_len,
        policy,
    );
    let snapshot = peer.metrics().snapshot_per_transport();
    let health = udp_family_health(peer, ranked, &snapshot, policy);
    let tcp_usable = tcp_transport_usable(peer, snapshot.get(&TransportKind::Tcp), policy);

    match intent {
        TransportSelectionIntent::Default => {}
        TransportSelectionIntent::TcpFavored => {
            if tcp_usable {
                move_transport_to_front(ranked, tcp_pos);
            }
        }
        TransportSelectionIntent::LatencySensitive => {
            if tcp_usable {
                if let Some(udp_pos) =
                    udp_family_promotion_position(ranked, &snapshot, routing_metric, health, policy)
                {
                    move_transport_to_front(ranked, udp_pos);
                } else {
                    move_transport_to_front(ranked, tcp_pos);
                }
            }
        }
    }
}

fn transport_selection_intent(
    peer: &PeerState,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    options: SendOptions,
    payload_len: usize,
    policy: TransportRoutingPolicy,
) -> TransportSelectionIntent {
    if level == ServiceLevel::BestEffort {
        return if is_expiring_conversational_voice(level, routing_metric, class, options) {
            TransportSelectionIntent::LatencySensitive
        } else {
            TransportSelectionIntent::Default
        };
    }
    if options.expires_at().is_none()
        && (class == MessageClass::Regular
            || payload_len >= policy.bulk_payload_threshold_bytes()
            || peer_bulk_backlog_bytes(peer) >= policy.bulk_backlog_threshold_bytes())
    {
        TransportSelectionIntent::TcpFavored
    } else {
        TransportSelectionIntent::LatencySensitive
    }
}

fn best_effort_without_voice_deadline(
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    options: SendOptions,
) -> bool {
    level == ServiceLevel::BestEffort
        && !is_expiring_conversational_voice(level, routing_metric, class, options)
}

fn is_expiring_conversational_voice(
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    options: SendOptions,
) -> bool {
    level == ServiceLevel::BestEffort
        && routing_metric == RoutingMetric::ConversationalQuality
        && class == MessageClass::HighPriority
        && options.expires_at().is_some()
}

fn enforce_expiring_voice_admission(
    peer: &PeerState,
    ranked: &mut Vec<TransportKind>,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    options: SendOptions,
    policy: TransportRoutingPolicy,
) {
    if !is_expiring_conversational_voice(level, routing_metric, class, options) {
        return;
    }

    let snapshot = peer.metrics().snapshot_per_transport();
    if udp_family_health(peer, ranked, &snapshot, policy) == UdpFamilyHealth::Viable {
        return;
    }

    let usable_tcp = ranked.contains(&TransportKind::Tcp)
        && tcp_transport_usable(peer, snapshot.get(&TransportKind::Tcp), policy);
    if usable_tcp {
        ranked.retain(|kind| *kind == TransportKind::Tcp);
    } else {
        ranked.clear();
    }
}

fn peer_bulk_backlog_bytes(peer: &PeerState) -> usize {
    [TransportKind::Tcp, TransportKind::Kcp, TransportKind::Quic]
        .into_iter()
        .filter_map(|kind| peer.outbound_stream_queue_status(kind))
        .fold(peer.outbound_queue_depth_bytes(), |sum, status| {
            sum.saturating_add(status.depth())
        })
}

fn udp_family_health(
    peer: &PeerState,
    ranked: &[TransportKind],
    snapshot: &HashMap<TransportKind, LinkMetrics>,
    policy: TransportRoutingPolicy,
) -> UdpFamilyHealth {
    const UDP_FAMILY: [TransportKind; 3] =
        [TransportKind::Kcp, TransportKind::Quic, TransportKind::Udp];

    let eligible_udp = UDP_FAMILY
        .into_iter()
        .filter(|transport| ranked.contains(transport))
        .collect::<Vec<_>>();
    if eligible_udp.is_empty() {
        return UdpFamilyHealth::Blocked;
    }
    if peer.max_consecutive_failures_for_transports(&eligible_udp)
        >= policy.udp_family_probe_loss_block_count()
    {
        return UdpFamilyHealth::Blocked;
    }

    let min_samples = policy.udp_family_min_samples();
    let tcp_loss = snapshot
        .get(&TransportKind::Tcp)
        .filter(|link| link.loss_sample_count() >= min_samples)
        .map(LinkMetrics::effective_packet_loss_ppm);

    let mut live_udp = false;
    let mut sampled_udp = false;
    let mut has_degraded_loss = false;

    for transport in UDP_FAMILY {
        if !ranked.contains(&transport) {
            continue;
        }
        live_udp = true;

        let Some(link) = snapshot.get(&transport) else {
            continue;
        };
        if link.consecutive_probe_losses() >= policy.udp_family_probe_loss_block_count() {
            return UdpFamilyHealth::Blocked;
        }
        if link.loss_sample_count() < min_samples {
            continue;
        }

        let loss = link.effective_packet_loss_ppm();
        if loss >= policy.udp_family_block_loss_ppm() {
            return UdpFamilyHealth::Blocked;
        }
        if tcp_loss.is_some_and(|tcp_loss| {
            loss >= tcp_loss.saturating_add(policy.udp_family_loss_excess_over_tcp_ppm())
        }) {
            has_degraded_loss = true;
        }
        sampled_udp = true;
    }

    if has_degraded_loss {
        UdpFamilyHealth::Degraded
    } else if sampled_udp {
        UdpFamilyHealth::Viable
    } else if live_udp {
        UdpFamilyHealth::Probing
    } else {
        UdpFamilyHealth::Blocked
    }
}

fn tcp_transport_usable(
    peer: &PeerState,
    link: Option<&LinkMetrics>,
    policy: TransportRoutingPolicy,
) -> bool {
    if peer
        .outbound_stream_queue_status(TransportKind::Tcp)
        .is_some_and(|status| status.full_samples() > 0 && status.depth() > 0)
    {
        return false;
    }
    !link.is_some_and(|link| {
        link.loss_sample_count() >= policy.udp_family_min_samples()
            && link.effective_packet_loss_ppm() >= policy.udp_family_block_loss_ppm()
    })
}

fn udp_family_promotion_position(
    ranked: &[TransportKind],
    snapshot: &HashMap<TransportKind, LinkMetrics>,
    routing_metric: RoutingMetric,
    health: UdpFamilyHealth,
    policy: TransportRoutingPolicy,
) -> Option<usize> {
    if health != UdpFamilyHealth::Viable {
        return None;
    }

    let Some(tcp) = snapshot.get(&TransportKind::Tcp) else {
        return None;
    };
    let Some(tcp_cost) = tcp.routing_cost(ServiceLevel::Reliable, routing_metric) else {
        return None;
    };

    let Some((udp_pos, udp, udp_cost)) = ranked.iter().enumerate().find_map(|(pos, transport)| {
        if !matches!(
            transport,
            TransportKind::Kcp | TransportKind::Quic | TransportKind::Udp
        ) {
            return None;
        }
        let link = snapshot.get(transport)?;
        if link.loss_sample_count() < policy.udp_family_min_samples() {
            return None;
        }
        let cost = link.routing_cost(ServiceLevel::Reliable, routing_metric)?;
        Some((pos, link, cost))
    }) else {
        return None;
    };

    let large_rtt_threshold_us = (policy.large_rtt_threshold_ms() as f64) * 1_000.0;
    let large_or_lossy = tcp.rtt_us() >= large_rtt_threshold_us
        || udp.rtt_us() >= large_rtt_threshold_us
        || tcp.effective_packet_loss_ppm() >= policy.lossy_link_threshold_ppm()
        || udp.effective_packet_loss_ppm() >= policy.lossy_link_threshold_ppm();
    if !large_or_lossy {
        return None;
    }

    let required = 1.0 - (policy.transport_switch_improvement_pct().min(100) as f64 / 100.0);
    if udp_cost <= tcp_cost * required {
        Some(udp_pos)
    } else {
        None
    }
}

fn move_transport_to_front(ranked: &mut Vec<TransportKind>, pos: usize) {
    if pos == 0 {
        return;
    }
    let transport = ranked.remove(pos);
    ranked.insert(0, transport);
}

fn send_queue_penalty(
    peer: &PeerState,
    transport: TransportKind,
    class: MessageClass,
    options: SendOptions,
    now: Instant,
) -> u8 {
    if options.expires_at().is_some() {
        deadline_queue_penalty(peer, transport, options, now)
    } else if class == MessageClass::Regular {
        regular_queue_penalty(peer, transport)
    } else {
        0
    }
}

fn deadline_queue_penalty(
    peer: &PeerState,
    transport: TransportKind,
    options: SendOptions,
    now: Instant,
) -> u8 {
    let Some(expires_at) = options.expires_at() else {
        return 0;
    };
    let remaining = expires_at.saturating_duration_since(now);
    if remaining.is_zero() || remaining <= DEADLINE_NEAR_EXPIRED_TTL {
        return 3;
    }

    let Some(status) = peer.outbound_stream_queue_status(transport) else {
        return 0;
    };
    if status.full_samples() > 0 && status.depth() > 0 {
        return 3;
    }

    let depth_bytes = status.depth();
    if depth_bytes == 0 {
        return 0;
    }

    let drain_bytes_per_ms = estimated_drain_bytes_per_ms(peer, transport);
    if !drain_bytes_per_ms.is_finite() || drain_bytes_per_ms <= 0.0 {
        return 3;
    }

    let queue_delay_ms = depth_bytes as f64 / drain_bytes_per_ms;
    let remaining_ms = remaining.as_secs_f64() * 1_000.0;
    if queue_delay_ms <= remaining_ms * 0.25 {
        0
    } else if queue_delay_ms <= remaining_ms * 0.50 {
        1
    } else if queue_delay_ms <= remaining_ms * 0.90 {
        2
    } else {
        3
    }
}

fn estimated_drain_bytes_per_ms(peer: &PeerState, transport: TransportKind) -> f64 {
    let drain_bytes_per_sec = peer
        .metrics()
        .snapshot_per_transport()
        .get(&transport)
        .map(|link| link.estimated_throughput_bps())
        .filter(|rate| rate.is_finite() && *rate >= DEADLINE_DRAIN_FALLBACK_BYTES_PER_SEC)
        .unwrap_or(DEADLINE_DRAIN_FALLBACK_BYTES_PER_SEC);
    drain_bytes_per_sec / 1_000.0
}

fn regular_queue_penalty(peer: &PeerState, transport: TransportKind) -> u8 {
    let Some(status) = peer.outbound_stream_queue_status(transport) else {
        return 0;
    };
    if status.depth() > 0 || status.full_samples() > 0 {
        1
    } else {
        0
    }
}

fn spawn_peer_outbound_dispatcher(inner: Arc<ManagerInner>, peer: Arc<PeerState>) {
    let Some(receiver) = peer.take_outbound_receiver() else {
        return;
    };
    tokio::spawn(run_peer_outbound_dispatcher(inner, peer, receiver));
}

#[derive(Default)]
struct OutboundScheduler {
    control: SchedulerLane,
    high_priority: SchedulerLane,
    regular: SchedulerLane,
    consecutive_high_priority: usize,
    next_id: u64,
    next_purge_lane: usize,
}

struct SchedulerNode {
    queued: Queued<OutboundEnvelope>,
    previous: Option<u64>,
    next: Option<u64>,
    expires_at: Option<Instant>,
}

#[derive(Default)]
struct SchedulerLane {
    nodes: HashMap<u64, SchedulerNode>,
    head: Option<u64>,
    tail: Option<u64>,
    expirations: BTreeSet<(Instant, u64)>,
}

impl SchedulerLane {
    fn push_back(&mut self, id: u64, queued: Queued<OutboundEnvelope>) {
        let expires_at = queued.item().options().expires_at();
        if let Some(deadline) = expires_at {
            self.expirations.insert((deadline, id));
        }
        let previous = self.tail;
        self.nodes.insert(
            id,
            SchedulerNode {
                queued,
                previous,
                next: None,
                expires_at,
            },
        );
        if let Some(previous) = previous {
            self.nodes.get_mut(&previous).expect("lane tail").next = Some(id);
        } else {
            self.head = Some(id);
        }
        self.tail = Some(id);
    }

    fn push_front(&mut self, id: u64, node: SchedulerNode) {
        if let Some(deadline) = node.expires_at {
            self.expirations.insert((deadline, id));
        }
        let old_head = self.head;
        let mut node = node;
        node.previous = None;
        node.next = old_head;
        self.nodes.insert(id, node);
        if let Some(old_head) = old_head {
            self.nodes.get_mut(&old_head).expect("lane head").previous = Some(id);
        } else {
            self.tail = Some(id);
        }
        self.head = Some(id);
    }

    fn pop_front(&mut self) -> Option<(u64, SchedulerNode)> {
        let id = self.head?;
        self.remove(id).map(|node| (id, node))
    }

    fn remove(&mut self, id: u64) -> Option<SchedulerNode> {
        let node = self.nodes.remove(&id)?;
        if let Some(deadline) = node.expires_at {
            self.expirations.remove(&(deadline, id));
        }
        if let Some(previous) = node.previous {
            self.nodes
                .get_mut(&previous)
                .expect("lane predecessor")
                .next = node.next;
        } else {
            self.head = node.next;
        }
        if let Some(next) = node.next {
            self.nodes.get_mut(&next).expect("lane successor").previous = node.previous;
        } else {
            self.tail = node.previous;
        }
        Some(node)
    }

    fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.nodes.len()
    }

    fn purge_expired(&mut self, peer: &PeerState, now: Instant, limit: usize) -> usize {
        let mut purged = 0;
        while purged < limit {
            let Some((deadline, id)) = self.expirations.first().copied() else {
                break;
            };
            if deadline > now {
                break;
            }
            let node = self.remove(id).expect("expiry index entry");
            let envelope = node.queued.item();
            peer.record_expired_outbound_drop(
                ExpiredOutboundDropStage::PeerQueueDispatch,
                envelope.target_transport(),
                envelope.class(),
            );
            purged += 1;
        }
        purged
    }

    fn has_expired(&self, now: Instant) -> bool {
        self.expirations
            .first()
            .is_some_and(|(deadline, _)| *deadline <= now)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DispatchAttempt {
    Empty,
    Dispatched,
    Blocked,
}

impl OutboundScheduler {
    fn push(&mut self, queued: Queued<OutboundEnvelope>) {
        if self.is_empty() {
            self.consecutive_high_priority = 0;
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        match queued.item().class() {
            MessageClass::Control => self.control.push_back(id, queued),
            MessageClass::HighPriority => self.high_priority.push_back(id, queued),
            MessageClass::Regular => self.regular.push_back(id, queued),
        }
    }

    fn is_empty(&self) -> bool {
        self.control.is_empty() && self.high_priority.is_empty() && self.regular.is_empty()
    }

    fn purge_expired(&mut self, peer: &PeerState, now: Instant, limit: usize) -> bool {
        let start = self.next_purge_lane;
        let mut remaining = limit;
        for offset in 0..3 {
            let purged = match (start + offset) % 3 {
                0 => self.control.purge_expired(peer, now, remaining),
                1 => self.high_priority.purge_expired(peer, now, remaining),
                _ => self.regular.purge_expired(peer, now, remaining),
            };
            remaining -= purged;
            if remaining == 0 {
                break;
            }
        }
        self.next_purge_lane = (start + 1) % 3;
        self.control.has_expired(now)
            || self.high_priority.has_expired(now)
            || self.regular.has_expired(now)
    }

    fn dispatch_ready(
        &mut self,
        peer: &Arc<PeerState>,
        selection: TransportSelectionConfig,
        max_attempts: usize,
    ) -> bool {
        let mut control_blocked = false;
        let mut high_blocked = false;
        let mut regular_blocked = false;
        let mut attempts = 0;
        let mut blocked_passes = 0;
        let mut made_progress = false;

        while attempts < max_attempts {
            if !control_blocked {
                attempts += 1;
                match try_dispatch_lane(&mut self.control, peer, selection, false) {
                    DispatchAttempt::Dispatched => {
                        made_progress = true;
                        continue;
                    }
                    DispatchAttempt::Blocked => control_blocked = true,
                    DispatchAttempt::Empty => {}
                }
            }

            let regular_first = self.consecutive_high_priority >= MAX_CONSECUTIVE_HIGH_PRIORITY
                && !self.regular.is_empty();
            let regular_waiting = !self.regular.is_empty();
            let first = if regular_first {
                (&mut self.regular, &mut regular_blocked, false)
            } else {
                (&mut self.high_priority, &mut high_blocked, true)
            };
            if !*first.1 {
                if attempts == max_attempts {
                    break;
                }
                attempts += 1;
                let allow_regular_backlog = !first.2 && regular_first;
                match try_dispatch_lane(first.0, peer, selection, allow_regular_backlog) {
                    DispatchAttempt::Dispatched => {
                        made_progress = true;
                        if first.2 {
                            if !regular_waiting {
                                self.consecutive_high_priority = 0;
                            } else {
                                self.consecutive_high_priority =
                                    self.consecutive_high_priority.saturating_add(1);
                            }
                        } else {
                            self.consecutive_high_priority = 0;
                        }
                        continue;
                    }
                    DispatchAttempt::Blocked => *first.1 = true,
                    DispatchAttempt::Empty => {}
                }
            }

            let second = if regular_first {
                (&mut self.high_priority, &mut high_blocked, true)
            } else {
                (&mut self.regular, &mut regular_blocked, false)
            };
            if !*second.1 {
                if attempts == max_attempts {
                    break;
                }
                attempts += 1;
                let allow_regular_backlog = !second.2 && regular_first;
                match try_dispatch_lane(second.0, peer, selection, allow_regular_backlog) {
                    DispatchAttempt::Dispatched => {
                        made_progress = true;
                        if second.2 {
                            if !regular_waiting {
                                self.consecutive_high_priority = 0;
                            } else {
                                self.consecutive_high_priority =
                                    self.consecutive_high_priority.saturating_add(1);
                            }
                        } else {
                            self.consecutive_high_priority = 0;
                        }
                        continue;
                    }
                    DispatchAttempt::Blocked => *second.1 = true,
                    DispatchAttempt::Empty => {}
                }
            }

            if made_progress && blocked_passes < MAX_BLOCKED_LANE_PASSES {
                control_blocked = false;
                high_blocked = false;
                regular_blocked = false;
                blocked_passes += 1;
                made_progress = false;
            } else {
                break;
            }
        }
        if self.is_empty() {
            self.consecutive_high_priority = 0;
        }
        attempts >= max_attempts && !self.is_empty()
    }
}

fn try_dispatch_lane(
    lane: &mut SchedulerLane,
    peer: &Arc<PeerState>,
    selection: TransportSelectionConfig,
    allow_regular_backlog: bool,
) -> DispatchAttempt {
    let Some((id, node)) = lane.pop_front() else {
        return DispatchAttempt::Empty;
    };
    let queued = node.queued;
    let class = queued.item().class();
    let queue_age = queued.enqueued_at().elapsed();
    match queued.try_consume(|envelope| {
        try_dispatch_envelope_with_policy(peer, envelope, selection, allow_regular_backlog)
    }) {
        Ok(()) => {
            trace!(
                peer = %peer.node_id(),
                ?class,
                queue_age_ms = queue_age.as_millis(),
                "dispatched queued outbound peer frame"
            );
            DispatchAttempt::Dispatched
        }
        Err(queued) => {
            lane.push_front(
                id,
                SchedulerNode {
                    expires_at: queued.item().options().expires_at(),
                    queued,
                    previous: None,
                    next: None,
                },
            );
            DispatchAttempt::Blocked
        }
    }
}

async fn run_peer_outbound_dispatcher(
    inner: Arc<ManagerInner>,
    peer: Arc<PeerState>,
    mut receiver: PeerOutboundReceiver,
) {
    let mut retry_tick = interval(OUTBOUND_DISPATCH_RETRY_INTERVAL);
    retry_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut scheduler = OutboundScheduler::default();
    loop {
        if inner.shutdown().is_cancelled() {
            return;
        }

        let mut drained = 0;
        'drain: while drained < MAX_OUTBOUND_INGRESS_PER_TURN {
            let mut found = false;
            for class in [
                MessageClass::Control,
                MessageClass::HighPriority,
                MessageClass::Regular,
            ] {
                match receiver.try_recv(class) {
                    Ok(queued) => {
                        scheduler.push(queued);
                        drained += 1;
                        found = true;
                        if drained == MAX_OUTBOUND_INGRESS_PER_TURN {
                            break 'drain;
                        }
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                    | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {}
                }
            }
            if !found {
                break;
            }
        }

        let more_expired =
            scheduler.purge_expired(&peer, Instant::now(), MAX_OUTBOUND_EXPIRY_PURGES_PER_TURN);
        let more_dispatch = scheduler.dispatch_ready(
            &peer,
            TransportSelectionConfig::from_config(inner.cfg()),
            MAX_OUTBOUND_DISPATCH_ATTEMPTS_PER_TURN,
        );

        if scheduler.is_empty() && receiver.is_closed() {
            return;
        }

        if drained == MAX_OUTBOUND_INGRESS_PER_TURN || more_expired || more_dispatch {
            tokio::task::yield_now().await;
            continue;
        }

        tokio::select! {
            biased;
            _ = inner.shutdown().cancelled() => return,
            queued = receiver.recv(), if !receiver.is_closed() => {
                if let Some(queued) = queued {
                    scheduler.push(queued);
                }
            }
            _ = peer.wait_for_outbound_dispatch_signal(), if !scheduler.is_empty() => {}
            _ = retry_tick.tick(), if !scheduler.is_empty() => {}
        }
    }
}

#[cfg(test)]
fn try_dispatch_envelope(
    peer: &Arc<PeerState>,
    envelope: OutboundEnvelope,
    selection: impl Into<TransportSelectionConfig>,
) -> Result<(), OutboundEnvelope> {
    try_dispatch_envelope_with_policy(peer, envelope, selection.into(), false)
}

fn try_dispatch_envelope_with_policy(
    peer: &Arc<PeerState>,
    envelope: OutboundEnvelope,
    selection: TransportSelectionConfig,
    allow_regular_backlog: bool,
) -> Result<(), OutboundEnvelope> {
    let now = Instant::now();
    if envelope.is_expired_at(now) {
        peer.record_expired_outbound_drop(
            ExpiredOutboundDropStage::PeerQueueDispatch,
            envelope.target_transport(),
            envelope.class(),
        );
        return Ok(());
    }
    let class = envelope.class();
    let choices = if let Some(transport) = envelope.target_transport() {
        let snapshot = peer.metrics().snapshot_per_transport();
        let live = peer.live_kinds();
        let has_viable_alternative = live.iter().copied().any(|candidate| {
            candidate != transport
                && candidate != TransportKind::Kcp
                && candidate.is_acceptable_for(envelope.level())
                && transport_is_viable_alternative(
                    peer,
                    candidate,
                    &snapshot,
                    selection.routing,
                    now,
                )
        });
        if let Some(reason) = transport_candidate_exclusion_reason(
            peer,
            transport,
            envelope.level(),
            class,
            envelope.options(),
            &snapshot,
            selection,
            has_viable_alternative,
            now,
        ) {
            peer.record_transport_health_exclusion(transport, reason);
            Vec::new()
        } else {
            vec![transport]
        }
    } else {
        pick_transports(
            peer,
            envelope.level(),
            envelope.routing_metric(),
            envelope.class(),
            envelope.options(),
            envelope.payload().len(),
            selection,
        )
    };

    if choices.is_empty() {
        return Err(envelope);
    }

    for transport in choices {
        let options = envelope.options();
        if options.is_expired() {
            peer.record_expired_outbound_drop(
                ExpiredOutboundDropStage::PeerQueueDispatch,
                Some(transport),
                class,
            );
            return Ok(());
        }
        let Some(sender) = peer.try_get_stream(transport) else {
            continue;
        };
        let variant = envelope.payloads().variant(transport);
        let frame = OutboundFrame::from_variant(class, variant, options);
        if class == MessageClass::Regular
            && !allow_regular_backlog
            && options.expires_at().is_none()
            && sender.depth_bytes() > 0
        {
            record_outbound_stream_queue_sample(peer, transport, class, &sender, true);
            continue;
        }
        record_outbound_stream_queue_sample(peer, transport, class, &sender, false);
        match sender.try_send(frame) {
            Ok(()) => {
                for sidecar in variant.sidecars() {
                    let _ = sender.try_send(OutboundFrame::with_options(
                        class,
                        sidecar.clone(),
                        options,
                    ));
                }
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

fn transport_timestamp_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .min(u128::from(u64::MAX)) as u64
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
    sender: &PeerOutboundSender,
    is_full: bool,
) {
    let depth = sender.depth_bytes();
    let max_capacity = sender.capacity_bytes();
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
    let udp_family_addrs = udp_family_listen_addrs(cfg);
    let mux_error_addr = udp_family_addrs
        .first()
        .map(|(_, addr)| *addr)
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let mux = UdpMuxSet::new(
        &udp_family_addrs,
        UdpMuxQueueTuning::for_max_users(cfg.max_users()),
    )
    .map_err(|source| TransportError::Bind {
        addr: mux_error_addr,
        source,
    })?;
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
            cfg.kcp_tuning(),
        ))
    });
    let quic = if !cfg.quic_listen_addrs().is_empty() || has_seed(TransportKind::Quic) {
        let endpoint = QuicEndpoint::new(
            server_tls,
            client_tls,
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
    use super::super::connection::TransportPayloadVariant;
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

    fn fill_stream_queue(peer: &PeerState, kind: TransportKind, bytes: usize) {
        let sender = peer.try_get_stream(kind).expect("live stream");
        sender
            .try_send(OutboundFrame::new(
                MessageClass::Regular,
                Bytes::from(vec![0; bytes]),
            ))
            .expect("stream queue should accept test payload");
    }

    fn age_zero_wire_metric(peer: &PeerState, kind: TransportKind, age: Duration) {
        peer.metrics().record_rtt(kind, Duration::from_millis(40));
        std::thread::sleep(age);
    }

    fn queued_envelope(
        transport: TransportKind,
        class: MessageClass,
        payload: &'static [u8],
        options: SendOptions,
    ) -> Queued<OutboundEnvelope> {
        let budget = AdaptiveQueueBudget::new(1024 * 1024);
        let (sender, mut receiver) = AdaptiveQueueSender::new(budget.split(budget.max_bytes()));
        sender
            .try_send(OutboundEnvelope::fixed_transport(
                transport,
                class,
                Bytes::from_static(payload),
                options,
            ))
            .expect("test envelope should fit");
        receiver
            .try_recv_queued()
            .expect("test envelope should be queued")
    }

    #[test]
    fn outbound_scheduler_skips_blocked_regular_lane() {
        let (peer, mut receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Quic]);
        fill_stream_queue(&peer, TransportKind::Tcp, 1024 * 1024 - 512);
        let mut scheduler = OutboundScheduler::default();
        scheduler.push(queued_envelope(
            TransportKind::Tcp,
            MessageClass::Regular,
            b"blocked regular",
            SendOptions::default(),
        ));
        scheduler.push(queued_envelope(
            TransportKind::Quic,
            MessageClass::HighPriority,
            b"ready high",
            SendOptions::default(),
        ));

        scheduler.dispatch_ready(&peer, TransportRoutingPolicy::default().into(), 128);

        assert_eq!(scheduler.regular.len(), 1);
        assert!(scheduler.high_priority.is_empty());
        assert_eq!(
            receivers[1].try_recv().unwrap().payload(),
            &Bytes::from_static(b"ready high")
        );
    }

    #[test]
    fn outbound_scheduler_dispatches_control_before_other_classes() {
        let (peer, mut receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        let mut scheduler = OutboundScheduler::default();
        scheduler.push(queued_envelope(
            TransportKind::Tcp,
            MessageClass::Regular,
            b"regular",
            SendOptions::default(),
        ));
        scheduler.push(queued_envelope(
            TransportKind::Tcp,
            MessageClass::HighPriority,
            b"high",
            SendOptions::default(),
        ));
        scheduler.push(queued_envelope(
            TransportKind::Tcp,
            MessageClass::Control,
            b"control",
            SendOptions::default(),
        ));

        scheduler.dispatch_ready(&peer, TransportRoutingPolicy::default().into(), 128);

        assert_eq!(
            receivers[0].try_recv().unwrap().class(),
            MessageClass::Control
        );
        assert_eq!(
            receivers[0].try_recv().unwrap().class(),
            MessageClass::HighPriority
        );
        scheduler.dispatch_ready(&peer, TransportRoutingPolicy::default().into(), 128);
        assert_eq!(
            receivers[0].try_recv().unwrap().class(),
            MessageClass::Regular
        );
    }

    #[test]
    fn outbound_scheduler_serves_regular_after_thirty_two_high_priority_frames() {
        let (peer, mut receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        let mut scheduler = OutboundScheduler::default();
        for _ in 0..33 {
            scheduler.push(queued_envelope(
                TransportKind::Tcp,
                MessageClass::HighPriority,
                b"high",
                SendOptions::default(),
            ));
        }
        scheduler.push(queued_envelope(
            TransportKind::Tcp,
            MessageClass::Regular,
            b"regular",
            SendOptions::default(),
        ));

        scheduler.dispatch_ready(&peer, TransportRoutingPolicy::default().into(), 128);

        for _ in 0..32 {
            assert_eq!(
                receivers[0].try_recv().unwrap().class(),
                MessageClass::HighPriority
            );
        }
        assert_eq!(
            receivers[0].try_recv().unwrap().class(),
            MessageClass::Regular
        );
        assert_eq!(
            receivers[0].try_recv().unwrap().class(),
            MessageClass::HighPriority
        );
    }

    #[test]
    fn outbound_scheduler_purges_expiring_high_while_regular_is_blocked() {
        let (peer, _receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        fill_stream_queue(&peer, TransportKind::Tcp, 1024 * 1024 - 512);
        let mut scheduler = OutboundScheduler::default();
        scheduler.push(queued_envelope(
            TransportKind::Tcp,
            MessageClass::Regular,
            b"blocked regular",
            SendOptions::default(),
        ));
        scheduler.push(queued_envelope(
            TransportKind::Tcp,
            MessageClass::HighPriority,
            b"expiring high",
            SendOptions::default().expire_after(Duration::from_millis(1)),
        ));
        scheduler.dispatch_ready(&peer, TransportRoutingPolicy::default().into(), 128);

        std::thread::sleep(Duration::from_millis(5));
        scheduler.purge_expired(&peer, Instant::now(), 128);

        assert_eq!(scheduler.regular.len(), 1);
        assert!(scheduler.high_priority.is_empty());
        assert!(peer.expired_outbound_drop_status().iter().any(|drop| {
            drop.stage() == ExpiredOutboundDropStage::PeerQueueDispatch
                && drop.transport() == Some(TransportKind::Tcp)
                && drop.class() == MessageClass::HighPriority
                && drop.frames() == 1
        }));
    }

    #[test]
    fn regular_admission_saturation_leaves_capacity_for_control() {
        let peer = PeerState::new(
            2,
            Duration::from_millis(10),
            Duration::from_secs(60),
            MetricsTuning::default(),
            1024 * 1024,
        );
        let sender = peer.outbound_sender();
        sender
            .try_send(OutboundEnvelope::fixed_transport(
                TransportKind::Tcp,
                MessageClass::Regular,
                Bytes::from(vec![0; 512 * 1024 - 256]),
                SendOptions::default(),
            ))
            .expect("regular reserved share");
        assert!(matches!(
            sender.try_send(OutboundEnvelope::fixed_transport(
                TransportKind::Tcp,
                MessageClass::Regular,
                Bytes::from_static(b"regular overflow"),
                SendOptions::default(),
            )),
            Err(TryAdaptiveSendError::Full(_))
        ));
        sender
            .try_send(OutboundEnvelope::fixed_transport(
                TransportKind::Tcp,
                MessageClass::Control,
                Bytes::from_static(b"control"),
                SendOptions::default(),
            ))
            .expect("control keeps reserved admission");
    }

    #[test]
    fn late_control_is_visible_behind_large_regular_ingress_burst() {
        let peer = PeerState::new(
            2,
            Duration::from_millis(10),
            Duration::from_secs(60),
            MetricsTuning::default(),
            1024 * 1024,
        );
        let sender = peer.outbound_sender();
        for _ in 0..300 {
            sender
                .try_send(OutboundEnvelope::fixed_transport(
                    TransportKind::Tcp,
                    MessageClass::Regular,
                    Bytes::from_static(b"regular"),
                    SendOptions::default(),
                ))
                .expect("regular burst fits reserved share");
        }
        sender
            .try_send(OutboundEnvelope::fixed_transport(
                TransportKind::Tcp,
                MessageClass::Control,
                Bytes::from_static(b"late control"),
                SendOptions::default(),
            ))
            .expect("late control fits");
        let mut receiver = peer.take_outbound_receiver().expect("peer receiver");

        let queued = receiver
            .try_recv(MessageClass::Control)
            .expect("control has a separate ingress lane");
        assert_eq!(queued.item().class(), MessageClass::Control);
    }

    #[test]
    fn late_priority_is_not_buried_under_regular_stream_staging() {
        let (peer, mut receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        let mut scheduler = OutboundScheduler::default();
        for _ in 0..100 {
            scheduler.push(queued_envelope(
                TransportKind::Tcp,
                MessageClass::Regular,
                b"regular",
                SendOptions::default(),
            ));
        }
        scheduler.dispatch_ready(&peer, TransportRoutingPolicy::default().into(), 128);
        scheduler.push(queued_envelope(
            TransportKind::Tcp,
            MessageClass::HighPriority,
            b"late high",
            SendOptions::default(),
        ));
        scheduler.push(queued_envelope(
            TransportKind::Tcp,
            MessageClass::Control,
            b"late control",
            SendOptions::default(),
        ));

        scheduler.dispatch_ready(&peer, TransportRoutingPolicy::default().into(), 128);

        assert_eq!(
            receivers[0].try_recv().unwrap().class(),
            MessageClass::Regular
        );
        assert_eq!(
            receivers[0].try_recv().unwrap().class(),
            MessageClass::Control
        );
        assert_eq!(
            receivers[0].try_recv().unwrap().class(),
            MessageClass::HighPriority
        );
        assert!(receivers[0].try_recv().is_err());
    }

    #[test]
    fn scheduler_bounds_dispatch_and_expiry_work_per_turn() {
        let (peer, _receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        let mut scheduler = OutboundScheduler::default();
        for _ in 0..200 {
            scheduler.push(queued_envelope(
                TransportKind::Tcp,
                MessageClass::HighPriority,
                b"high",
                SendOptions::default(),
            ));
        }
        assert!(scheduler.dispatch_ready(&peer, TransportRoutingPolicy::default().into(), 10,));
        assert!(!scheduler.high_priority.is_empty());

        let mut expiring = OutboundScheduler::default();
        for _ in 0..257 {
            expiring.push(queued_envelope(
                TransportKind::Tcp,
                MessageClass::Regular,
                b"expired",
                SendOptions::default().expire_after(Duration::ZERO),
            ));
        }
        assert!(expiring.purge_expired(&peer, Instant::now(), 256));
        assert_eq!(expiring.regular.len(), 1);
        assert!(!expiring.purge_expired(&peer, Instant::now(), 256));
        assert!(expiring.is_empty());
    }

    #[test]
    fn separated_high_priority_bursts_do_not_carry_fairness_debt() {
        let (peer, mut receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        let mut scheduler = OutboundScheduler::default();
        for _ in 0..32 {
            scheduler.push(queued_envelope(
                TransportKind::Tcp,
                MessageClass::HighPriority,
                b"old high",
                SendOptions::default(),
            ));
        }
        scheduler.dispatch_ready(&peer, TransportRoutingPolicy::default().into(), 128);
        while receivers[0].try_recv().is_ok() {}
        assert_eq!(scheduler.consecutive_high_priority, 0);

        scheduler.push(queued_envelope(
            TransportKind::Tcp,
            MessageClass::HighPriority,
            b"new high",
            SendOptions::default(),
        ));
        scheduler.push(queued_envelope(
            TransportKind::Tcp,
            MessageClass::Regular,
            b"regular",
            SendOptions::default(),
        ));
        scheduler.dispatch_ready(&peer, TransportRoutingPolicy::default().into(), 128);
        assert_eq!(
            receivers[0].try_recv().expect("new burst head").class(),
            MessageClass::HighPriority
        );
    }

    #[tokio::test]
    async fn shutdown_remains_responsive_with_outbound_backlog() {
        let (transport, _receivers) = ConnectionManager::test_with_live_streams_bytes(
            1,
            2,
            &[TransportKind::Tcp],
            1024 * 1024,
        );
        for _ in 0..300 {
            let _ = transport
                .try_send(
                    2,
                    ServiceLevel::Reliable,
                    None,
                    MessageClass::Regular,
                    Bytes::from_static(b"backlog"),
                )
                .await;
        }

        tokio::time::timeout(Duration::from_secs(1), transport.shutdown())
            .await
            .expect("shutdown should not wait for scheduler backlog");
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

    #[tokio::test]
    async fn expired_peer_queue_head_does_not_block_fresh_frame() {
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
            .try_send_with_options(
                2,
                ServiceLevel::Reliable,
                None,
                MessageClass::Regular,
                Bytes::from_static(b"stale"),
                SendOptions::default().expire_after(Duration::from_millis(1)),
            )
            .await
            .unwrap();
        transport
            .try_send_with_options(
                2,
                ServiceLevel::Reliable,
                None,
                MessageClass::Regular,
                Bytes::from_static(b"fresh"),
                SendOptions::default(),
            )
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(
            receivers[0].recv().await.unwrap().payload().len(),
            1024 * 1024 - 512
        );
        let forwarded = tokio::time::timeout(Duration::from_millis(50), receivers[0].recv())
            .await
            .expect("fresh frame should dispatch after expired head is dropped")
            .expect("tcp receiver");
        assert_eq!(&forwarded.payload()[..], b"fresh");
        assert!(receivers[0].try_recv().is_err());

        let snapshot = transport.metrics_snapshot();
        assert!(
            snapshot.expired_outbound_drops().iter().any(|drop| {
                drop.peer() == 2
                    && drop.stage() == ExpiredOutboundDropStage::PeerQueueDispatch
                    && (drop.transport().is_none() || drop.transport() == Some(TransportKind::Tcp))
                    && drop.class() == MessageClass::Regular
                    && drop.frames() == 1
            }),
            "expected one routed stale-frame drop, got {:?}",
            snapshot.expired_outbound_drops()
        );
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
    fn regular_reliable_traffic_keeps_tcp_despite_better_udp_family_metric() {
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
            Some(TransportKind::Tcp)
        );
    }

    #[test]
    fn latency_sensitive_traffic_promotes_viable_udp_family_on_large_rtt() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Quic]);

        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(180));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(60));
        for _ in 0..TransportRoutingPolicy::default().udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }

        let ranked = pick_transports(
            &peer,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableLowLatencyCost,
            MessageClass::HighPriority,
            SendOptions::default(),
            0,
            TransportRoutingPolicy::default(),
        );

        assert_eq!(ranked.first().copied(), Some(TransportKind::Quic));
    }

    #[test]
    fn large_non_expiring_payload_favors_tcp_even_with_viable_udp_family() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Quic]);
        let policy = TransportRoutingPolicy::default();

        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(180));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(60));
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }

        let ranked = pick_transports(
            &peer,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableLowLatencyCost,
            MessageClass::HighPriority,
            SendOptions::default(),
            policy.bulk_payload_threshold_bytes(),
            policy,
        );

        assert_eq!(ranked.first().copied(), Some(TransportKind::Tcp));
    }

    #[test]
    fn probing_udp_family_stays_behind_tcp() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Quic]);

        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(180));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(60));
        peer.metrics().record_probe_delivered(TransportKind::Quic);

        let ranked = pick_transports(
            &peer,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableLowLatencyCost,
            MessageClass::HighPriority,
            SendOptions::default(),
            0,
            TransportRoutingPolicy::default(),
        );

        assert_eq!(ranked.first().copied(), Some(TransportKind::Tcp));
    }

    #[test]
    fn udp_family_health_degrades_when_loss_exceeds_tcp() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Quic]);
        let policy = TransportRoutingPolicy::default();

        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Tcp);
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }
        for _ in 0..4 {
            peer.metrics().record_probe_lost(TransportKind::Quic);
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }
        peer.metrics()
            .record_native_loss_sample(TransportKind::Quic, 100, 20);

        let snapshot = peer.metrics().snapshot_per_transport();
        let health = udp_family_health(
            &peer,
            &[TransportKind::Tcp, TransportKind::Quic],
            &snapshot,
            policy,
        );

        assert_eq!(health, UdpFamilyHealth::Degraded);
    }

    #[test]
    fn repeated_udp_family_probe_losses_block_promotion() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Quic]);

        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(180));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(60));
        for _ in 0..TransportRoutingPolicy::default().udp_family_probe_loss_block_count() {
            peer.metrics().record_probe_lost(TransportKind::Quic);
        }

        let ranked = pick_transports(
            &peer,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableLowLatencyCost,
            MessageClass::HighPriority,
            SendOptions::default(),
            0,
            TransportRoutingPolicy::default(),
        );

        assert_eq!(ranked.first().copied(), Some(TransportKind::Tcp));
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
    fn expiring_high_priority_avoids_stream_that_cannot_drain_before_ttl() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        fill_stream_queue(&peer, TransportKind::Tcp, 64 * 1024);

        let ranked = pick_transports(
            &peer,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
            MessageClass::HighPriority,
            SendOptions::default().expire_after(Duration::from_secs(2)),
            0,
            TransportRoutingPolicy::default(),
        );

        assert_eq!(ranked.first().copied(), Some(TransportKind::Kcp));
    }

    #[test]
    fn expiring_best_effort_voice_avoids_stale_stream_queue() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        fill_stream_queue(&peer, TransportKind::Kcp, 64 * 1024);
        age_zero_wire_metric(&peer, TransportKind::Kcp, Duration::from_millis(275));

        let ranked = pick_transports(
            &peer,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            SendOptions::default().expire_after(Duration::from_millis(250)),
            0,
            TransportRoutingPolicy::default(),
        );

        assert_eq!(ranked, vec![TransportKind::Tcp]);
    }

    #[test]
    fn expiring_best_effort_voice_does_not_expire_on_high_rtt_alone() {
        let (peer, _receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(900));

        let ranked = pick_transports(
            &peer,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            SendOptions::default().expire_after(Duration::from_millis(250)),
            0,
            TransportRoutingPolicy::default(),
        );

        assert_eq!(ranked, vec![TransportKind::Tcp]);
    }

    #[test]
    fn expiring_best_effort_voice_rejects_only_probing_udp_family() {
        let (peer, _receivers) = peer_with_live_transports(&[TransportKind::Quic]);

        let ranked = pick_transports(
            &peer,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            SendOptions::default().expire_after(Duration::from_millis(250)),
            0,
            TransportRoutingPolicy::default(),
        );

        assert!(ranked.is_empty());
    }

    #[tokio::test]
    async fn generic_ranking_keeps_probing_udp_but_expiring_voice_rejects_it() {
        let (manager, _receivers) =
            ConnectionManager::test_with_live_streams(1, 2, &[TransportKind::Quic]);

        assert_eq!(
            manager.ranked_live_transports_for(
                2,
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
            ),
            vec![TransportKind::Quic]
        );
        assert!(matches!(
            manager
                .try_send_with_options(
                    2,
                    ServiceLevel::BestEffort,
                    Some(RoutingMetric::ConversationalQuality),
                    MessageClass::HighPriority,
                    Bytes::from_static(b"voice"),
                    SendOptions::default().expire_after(Duration::from_millis(750)),
                )
                .await,
            Err(SendError::NoSuitableTransport { node: 2 })
        ));

        let peer = manager.inner.get_peer(2).expect("test peer");
        for _ in 0..TransportRoutingPolicy::default().udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }
        assert_eq!(
            manager.ranked_live_transports_for(
                2,
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
            ),
            vec![TransportKind::Quic]
        );
    }

    #[test]
    fn expiring_best_effort_voice_prefers_tcp_when_udp_family_degraded() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Quic]);
        let policy = TransportRoutingPolicy::default();

        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(180));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(60));
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Tcp);
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }
        peer.metrics()
            .record_native_loss_sample(TransportKind::Quic, 100, 20);

        let ranked = pick_transports(
            &peer,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            SendOptions::default().expire_after(Duration::from_millis(250)),
            0,
            policy,
        );

        assert_eq!(ranked, vec![TransportKind::Tcp]);
    }

    #[test]
    fn expiring_best_effort_voice_rejects_blocked_udp_when_tcp_is_unusable() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Quic]);
        let policy = TransportRoutingPolicy::default();

        for _ in 0..policy.udp_family_probe_loss_block_count() {
            peer.metrics().record_probe_lost(TransportKind::Quic);
        }
        peer.record_outbound_stream_queue_sample(
            TransportKind::Tcp,
            MessageClass::HighPriority,
            1024 * 1024,
            1024 * 1024,
            true,
        );
        fill_stream_queue(&peer, TransportKind::Tcp, 1);

        let ranked = pick_transports(
            &peer,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            SendOptions::default().expire_after(Duration::from_millis(250)),
            0,
            policy,
        );

        assert!(ranked.is_empty());
    }

    #[test]
    fn expiring_best_effort_voice_can_use_healthy_materially_better_udp_family() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Quic]);
        let policy = TransportRoutingPolicy::default();

        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(180));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(60));
        peer.metrics()
            .record_payload_sent(TransportKind::Quic, 4 * 1024 * 1024);
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }

        let ranked = pick_transports(
            &peer,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            SendOptions::default().expire_after(Duration::from_millis(250)),
            0,
            policy,
        );

        assert_eq!(ranked.first().copied(), Some(TransportKind::Quic));
        assert!(ranked.contains(&TransportKind::Tcp));
    }

    #[test]
    fn expiring_best_effort_voice_accepts_healthy_sampled_udp_without_tcp() {
        let (peer, _receivers) = peer_with_live_transports(&[TransportKind::Quic]);
        let policy = TransportRoutingPolicy::default();

        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }

        let ranked = pick_transports(
            &peer,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            SendOptions::default().expire_after(Duration::from_millis(250)),
            0,
            policy,
        );

        assert_eq!(ranked, vec![TransportKind::Quic]);
    }

    #[test]
    fn expiring_best_effort_voice_accepts_healthy_sampled_raw_udp() {
        let (peer, _receivers) = peer_with_live_transports(&[TransportKind::Udp]);
        let policy = TransportRoutingPolicy::default();

        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Udp);
        }

        let ranked = pick_transports(
            &peer,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            SendOptions::default().expire_after(Duration::from_millis(250)),
            0,
            policy,
        );

        assert_eq!(ranked, vec![TransportKind::Udp]);
    }

    #[test]
    fn expiring_best_effort_voice_can_promote_healthy_raw_udp_over_tcp() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Udp]);
        let policy = TransportRoutingPolicy::default();

        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(180));
        peer.metrics()
            .record_rtt(TransportKind::Udp, Duration::from_millis(60));
        peer.metrics()
            .record_payload_sent(TransportKind::Udp, 4 * 1024 * 1024);
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Udp);
        }

        let ranked = pick_transports(
            &peer,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            SendOptions::default().expire_after(Duration::from_millis(250)),
            0,
            policy,
        );

        assert_eq!(ranked.first().copied(), Some(TransportKind::Udp));
        assert!(ranked.contains(&TransportKind::Tcp));
    }

    #[test]
    fn dead_bad_kcp_does_not_poison_live_healthy_quic() {
        let (peer, _receivers) = peer_with_live_transports(&[TransportKind::Quic]);
        let policy = TransportRoutingPolicy::default();

        for _ in 0..policy.udp_family_probe_loss_block_count() {
            peer.metrics().record_probe_lost(TransportKind::Kcp);
        }
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }

        let ranked = pick_transports(
            &peer,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            SendOptions::default().expire_after(Duration::from_millis(250)),
            0,
            policy,
        );

        assert_eq!(ranked, vec![TransportKind::Quic]);
    }

    #[test]
    fn faster_draining_stream_with_more_bytes_can_beat_slower_shallower_stream() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        fill_stream_queue(&peer, TransportKind::Tcp, 4 * 1024);
        fill_stream_queue(&peer, TransportKind::Kcp, 32 * 1024);
        peer.metrics().record_payload_sent(TransportKind::Tcp, 128);
        peer.metrics()
            .record_payload_sent(TransportKind::Kcp, 1024 * 1024);
        std::thread::sleep(Duration::from_millis(20));

        let ranked = pick_transports(
            &peer,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
            MessageClass::HighPriority,
            SendOptions::default().expire_after(Duration::from_millis(200)),
            0,
            TransportRoutingPolicy::default(),
        );

        assert_eq!(ranked.first().copied(), Some(TransportKind::Kcp));
    }

    #[test]
    fn expiring_high_priority_skips_saturated_kcp_when_alternative_exists() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        peer.record_outbound_stream_queue_sample(
            TransportKind::Kcp,
            MessageClass::HighPriority,
            1024 * 1024,
            1024 * 1024,
            true,
        );
        fill_stream_queue(&peer, TransportKind::Kcp, 1);

        let ranked = pick_transports(
            &peer,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
            MessageClass::HighPriority,
            SendOptions::default().expire_after(Duration::from_secs(2)),
            0,
            TransportRoutingPolicy::default(),
        );

        assert_eq!(ranked, vec![TransportKind::Tcp]);
    }

    #[test]
    fn stale_kcp_with_backlog_fails_away_fast_when_alternative_exists() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        fill_stream_queue(&peer, TransportKind::Kcp, 64 * 1024);
        age_zero_wire_metric(&peer, TransportKind::Kcp, Duration::from_millis(275));

        let ranked = pick_transports(
            &peer,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            SendOptions::default(),
            0,
            TransportRoutingPolicy::default(),
        );

        assert_eq!(ranked, vec![TransportKind::Tcp]);
    }

    #[test]
    fn stale_kcp_without_alternative_keeps_short_grace_then_excludes() {
        let (peer, _receivers) = peer_with_live_transports(&[TransportKind::Kcp]);
        fill_stream_queue(&peer, TransportKind::Kcp, 64 * 1024);
        age_zero_wire_metric(&peer, TransportKind::Kcp, Duration::from_millis(275));

        let during_grace = pick_transports(
            &peer,
            ServiceLevel::ReliableLowLatency,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            SendOptions::default(),
            0,
            TransportRoutingPolicy::default(),
        );
        assert_eq!(during_grace, vec![TransportKind::Kcp]);

        std::thread::sleep(Duration::from_millis(525));
        let after_grace = pick_transports(
            &peer,
            ServiceLevel::ReliableLowLatency,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            SendOptions::default(),
            0,
            TransportRoutingPolicy::default(),
        );
        assert!(after_grace.is_empty());
    }

    #[test]
    fn idle_stale_kcp_is_not_penalized() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        age_zero_wire_metric(&peer, TransportKind::Kcp, Duration::from_millis(275));

        let ranked = pick_transports(
            &peer,
            ServiceLevel::ReliableLowLatency,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            SendOptions::default(),
            0,
            TransportRoutingPolicy::default(),
        );

        assert!(ranked.contains(&TransportKind::Kcp));
    }

    #[test]
    fn expiring_high_priority_reports_no_choice_when_only_kcp_is_saturated() {
        let (peer, _receivers) = peer_with_live_transports(&[TransportKind::Kcp]);
        peer.record_outbound_stream_queue_sample(
            TransportKind::Kcp,
            MessageClass::HighPriority,
            1024 * 1024,
            1024 * 1024,
            true,
        );
        fill_stream_queue(&peer, TransportKind::Kcp, 1);

        let ranked = pick_transports(
            &peer,
            ServiceLevel::ReliableLowLatency,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            SendOptions::default().expire_after(Duration::from_secs(2)),
            0,
            TransportRoutingPolicy::default(),
        );

        assert!(ranked.is_empty());
    }

    #[test]
    fn expiring_high_priority_reuses_drained_stream_after_historical_full_sample() {
        let (peer, _receivers) = peer_with_live_transports(&[TransportKind::Kcp]);
        peer.record_outbound_stream_queue_sample(
            TransportKind::Kcp,
            MessageClass::HighPriority,
            1024 * 1024,
            1024 * 1024,
            true,
        );

        let ranked = pick_transports(
            &peer,
            ServiceLevel::ReliableLowLatency,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            SendOptions::default().expire_after(Duration::from_secs(2)),
            0,
            TransportRoutingPolicy::default(),
        );

        assert_eq!(ranked, vec![TransportKind::Kcp]);
    }

    #[test]
    fn expiring_regular_frame_can_use_queued_only_tcp_stream() {
        let (peer, mut receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        fill_stream_queue(&peer, TransportKind::Tcp, 64 * 1024);
        let envelope = OutboundEnvelope::routed(
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
            MessageClass::Regular,
            Bytes::from_static(b"catchup"),
            SendOptions::default().expire_after(Duration::from_secs(2)),
        );

        assert!(try_dispatch_envelope(&peer, envelope, TransportRoutingPolicy::default()).is_ok());
        assert_eq!(receivers[0].try_recv().unwrap().payload().len(), 64 * 1024);
        assert_eq!(&receivers[0].try_recv().unwrap().payload()[..], b"catchup");
    }

    #[test]
    fn unknown_deadline_throughput_uses_conservative_floor() {
        let (peer, _receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        fill_stream_queue(&peer, TransportKind::Tcp, 20 * 1024);

        let penalty = deadline_queue_penalty(
            &peer,
            TransportKind::Tcp,
            SendOptions::default().expire_after(Duration::from_secs(1)),
            Instant::now(),
        );

        assert_eq!(penalty, 3);
    }

    #[test]
    fn non_expiring_high_priority_keeps_existing_metric_order() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        fill_stream_queue(&peer, TransportKind::Tcp, 64 * 1024);

        let ranked = pick_transports(
            &peer,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
            MessageClass::HighPriority,
            SendOptions::default(),
            0,
            TransportRoutingPolicy::default(),
        );

        assert_eq!(ranked.first().copied(), Some(TransportKind::Tcp));
    }

    #[test]
    fn non_expiring_best_effort_voice_keeps_existing_metric_order() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Quic]);
        let policy = TransportRoutingPolicy::default();

        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(180));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(60));
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }

        let ranked = pick_transports(
            &peer,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            SendOptions::default(),
            0,
            policy,
        );

        assert_eq!(ranked.first().copied(), Some(TransportKind::Quic));
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

    #[tokio::test]
    async fn udp_payload_preflight_honors_the_exact_frame_boundary() {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(1, 2, &[TransportKind::Tcp]);
        let level = ServiceLevel::BestEffort;
        let class = MessageClass::HighPriority;
        let mut low = 0usize;
        let mut high = transport.inner.cfg().udp_mtu();
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            if transport.payload_fits_transport(
                2,
                TransportKind::Udp,
                level,
                class,
                &vec![0; middle],
            ) {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        assert!(transport.payload_fits_transport(
            2,
            TransportKind::Udp,
            level,
            class,
            &vec![0; low]
        ));
        assert!(!transport.payload_fits_transport(
            2,
            TransportKind::Udp,
            level,
            class,
            &vec![0; low + 1]
        ));
        assert_eq!(
            transport
                .udp_datagram_len(2, level, class, low)
                .expect("udp length"),
            transport.udp_datagram_mtu_for(2)
        );
    }

    #[tokio::test]
    async fn oversized_udp_send_is_admitted_for_transport_fragmentation() {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(1, 2, &[TransportKind::Tcp]);
        let mut udp_rx = transport.test_install_live_stream(2, TransportKind::Udp);
        transport
            .send_via(
                2,
                TransportKind::Udp,
                MessageClass::Regular,
                Bytes::from(vec![0; 128 * 1024]),
            )
            .await
            .expect("transport fragments oversized UDP payloads");
        assert_eq!(udp_rx.recv().await.unwrap().payload().len(), 128 * 1024);
    }

    #[test]
    fn payload_plan_keeps_transport_variants_independent() {
        let plan = TransportPayloadPlan::new(Bytes::from_static(b"rich")).with_variant(
            TransportKind::Udp,
            TransportPayloadVariant::new(Bytes::from_static(b"udp"))
                .with_sidecars([Bytes::from_static(b"sidecar")]),
        );
        assert_eq!(
            plan.variant(TransportKind::Tcp).primary(),
            &Bytes::from_static(b"rich")
        );
        assert_eq!(
            plan.variant(TransportKind::Udp).primary(),
            &Bytes::from_static(b"udp")
        );
        assert_eq!(plan.variant(TransportKind::Udp).sidecars().len(), 1);
    }
}
