//! `ConnectionManager` — public face of the transport module.
//!
//! Holds the peer table, the inbound dispatch sinks, the shutdown signal, and
//! a registry of per-transport endpoints. Each endpoint owns its own state
//! (TLS configs, bound listener, `quinn::Endpoint`, etc.) so the manager
//! itself stays free of transport-specific fields.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
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
    PeerState, QuicSessionStatusSnapshot, SessionSender, SessionTrySendError,
    VoiceTransportCandidateScore,
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
use super::identity::{
    NodeIdentity, OriginAuthenticationError, OriginSignature, OriginSignatureMetadata,
};
use super::metrics::{
    DatagramPathEvidenceEvent, DatagramPathHealthSnapshot, DatagramPathHealthState,
    ExpiredOutboundDropStage, InboundQueueStatusSnapshot, LinkMetrics, MetricsSnapshot,
    MetricsTuning, QueueWatermark, QueueWatermarkReport, TransportHealthExclusionReason,
    VoiceTransportBindingEventReason, assemble_snapshot, record_delivery_path_selection,
};
use super::service_level::{
    DeliveryPath, MessageClass, PeerAddress, RoutingMetric, SeedAddress, ServiceLevel,
    TransportKind,
};
use super::tls::build_tls_configs;

const OUTBOUND_DISPATCH_RETRY_INTERVAL: Duration = Duration::from_millis(5);
const DEADLINE_DRAIN_FALLBACK_BYTES_PER_SEC: f64 = 16.0 * 1024.0;
const DEADLINE_NEAR_EXPIRED_TTL: Duration = Duration::from_millis(20);
const OUTBOUND_QUEUE_SATURATED_PERCENT: usize = 90;
const MAX_CONSECUTIVE_HIGH_PRIORITY: usize = 32;
const MAX_OUTBOUND_INGRESS_PER_TURN: usize = 256;
const MAX_OUTBOUND_DISPATCH_ATTEMPTS_PER_TURN: usize = 128;
const MAX_OUTBOUND_EXPIRY_PURGES_PER_TURN: usize = 256;
const MAX_BLOCKED_LANE_PASSES: usize = 2;

#[derive(Debug, Clone, Copy)]
struct TransportSelectionConfig {
    routing: TransportRoutingPolicy,
    kcp: KcpTuning,
    max_frame_bytes: usize,
}

impl TransportSelectionConfig {
    fn from_config(cfg: &TransportConfig) -> Self {
        Self {
            routing: cfg.routing_policy(),
            kcp: cfg.kcp_tuning(),
            max_frame_bytes: cfg.max_frame_bytes(),
        }
    }
}

impl From<TransportRoutingPolicy> for TransportSelectionConfig {
    fn from(routing: TransportRoutingPolicy) -> Self {
        Self {
            routing,
            kcp: KcpTuning::default(),
            max_frame_bytes: usize::MAX,
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
            let status = watermark
                .lock()
                .snapshot_at(Instant::now())
                .with_current(depth, capacity);
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
            let utilization = status.high_depth() as f64 / status.capacity().max(1) as f64;
            macro_rules! log_watermark {
                ($level:ident) => {
                    tracing::$level!(
                        ?class,
                        queue_capacity = status.capacity(),
                        queue_depth = status.depth(),
                        queue_high_watermark = status.high_depth(),
                        queue_samples = status.samples(),
                        queue_full_samples = status.full_samples(),
                        interval_secs = report.interval().as_secs(),
                        "s2s inbound queue watermark"
                    );
                };
            }
            if utilization < 0.5 {
                log_watermark!(trace);
            } else if utilization < 0.7 {
                log_watermark!(debug);
            } else if utilization < 0.85 {
                log_watermark!(info);
            } else if utilization <= 0.95 {
                log_watermark!(warn);
            } else {
                log_watermark!(error);
            }
        }
    }
}

/// Internal state shared across the manager handle, supervisor task, and all
/// endpoint accept/dial loops. Transport-specific state lives inside the
/// individual endpoints reachable through `endpoints`.
pub(crate) struct ManagerInner {
    self_id: NodeIdentifier,
    identity: Option<Arc<NodeIdentity>>,
    peers: Arc<SccMap<NodeIdentifier, Arc<PeerState>>>,
    seed_backoff: Arc<SccMap<SeedAddress, Arc<parking_lot::Mutex<BackoffState>>>>,
    successful_seeds: Arc<SccMap<SeedAddress, PeerAddress>>,
    quarantined_self_seeds: Arc<SccMap<SeedAddress, Instant>>,
    required_outgoing: Arc<RwLock<HashSet<NodeIdentifier>>>,
    inbound: InboundDispatch,
    shutdown: CancellationToken,
    cfg: TransportConfig,
    endpoints: EndpointRegistry,
    #[cfg(test)]
    iter_peers_count: Arc<AtomicU64>,
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
            identity: self.identity.clone(),
            peers: self.peers.clone(),
            seed_backoff: self.seed_backoff.clone(),
            successful_seeds: self.successful_seeds.clone(),
            quarantined_self_seeds: self.quarantined_self_seeds.clone(),
            required_outgoing: self.required_outgoing.clone(),
            inbound: self.inbound.clone(),
            shutdown: self.shutdown.clone(),
            cfg: self.cfg.clone(),
            endpoints: self.endpoints.clone(),
            #[cfg(test)]
            iter_peers_count: self.iter_peers_count.clone(),
        }
    }

    pub fn get_peer(&self, id: NodeIdentifier) -> Option<Arc<PeerState>> {
        self.peers.get_sync(&id).map(|e| e.get().clone())
    }

    pub fn remove_peer(&self, id: NodeIdentifier) -> Option<Arc<PeerState>> {
        self.peers.remove_sync(&id).map(|(_, v)| v)
    }

    pub fn iter_peers(&self) -> Vec<(NodeIdentifier, Arc<PeerState>)> {
        #[cfg(test)]
        self.iter_peers_count.fetch_add(1, Ordering::Relaxed);
        let mut out = Vec::new();
        self.peers.iter_sync(|id, peer| {
            out.push((*id, peer.clone()));
            true
        });
        out
    }

    #[cfg(test)]
    fn reset_iter_peers_count(&self) {
        self.iter_peers_count.store(0, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn iter_peers_count(&self) -> u64 {
        self.iter_peers_count.load(Ordering::Relaxed)
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

/// Live health of the best-effort datagram lane for a peer — the lane voice
/// rides. Mirrors the overlay's active-lane preference (`NeighborMonitor`:
/// UDP datagram when usable, else QUIC datagram) and reports whether the lane
/// is hard-Blocked plus the active lane's effective loss, so the distribution
/// plane can escape immediately on a Blocked incumbent and shorten the
/// challenger confirm on hard loss without waiting out the soft window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BestEffortDatagramLaneHealth {
    /// Whether every observed best-effort datagram lane is Blocked — no usable
    /// datagram path remains for voice. `false` while no datagram lane has been
    /// observed: absence of an observation is not a Blocked lane.
    pub blocked: bool,
    /// Effective loss ppm of the active (non-Blocked) datagram lane, `None`
    /// when no lane is usable (or still insufficiently sampled).
    pub loss_ppm: Option<u32>,
    /// Loss sample count of the active lane; confidence for `loss_ppm`.
    pub loss_samples: u64,
}

/// Whether a peer (the destination the distribution plane sends voice to) is
/// reporting degraded reorder quality on the voice this node sent it — the
/// receiver-side gap signal. The sink's reorder buffer reports `opened_gap`,
/// deadline flushes, and held delay back to its immediate upstream peer every
/// 250 ms (`VoicePathFeedback`), and the transport folds those reports into a
/// suspect flag with a 5 s staleness window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BestEffortSinkFeedback {
    /// The sink reported degraded quality (sustained gap buffering, deadline
    /// flushes, or over-budget held delay) within the staleness window.
    /// `false` with no live feedback: absence of a report is not a suspicion.
    pub suspect: bool,
}

/// Public handle.
#[derive(Clone)]
pub struct ConnectionManager {
    pub(crate) inner: Arc<ManagerInner>,
}

impl ConnectionManager {
    pub fn routing_policy(&self) -> TransportRoutingPolicy {
        self.inner.cfg().routing_policy()
    }

    /// Maximum encoded transport frame size accepted by this manager.
    pub fn max_frame_bytes(&self) -> usize {
        self.inner.cfg().max_frame_bytes()
    }

    /// Check whether an identity-encoded data payload fits as one frame on a
    /// selected transport. Strict QUIC v2 carries BestEffort only as a
    /// DATAGRAM; a legacy QUIC stream remains an eligible fallback.
    pub fn payload_fits_transport(
        &self,
        node: NodeIdentifier,
        transport: TransportKind,
        level: ServiceLevel,
        class: MessageClass,
        payload: &[u8],
    ) -> bool {
        let encoded_len = encoded_data_frame_len(
            self.inner.self_id(),
            node,
            level,
            class,
            transport_timestamp_us(),
            payload.len(),
        );
        match transport {
            TransportKind::Tcp | TransportKind::Kcp => true,
            TransportKind::Quic => {
                if encoded_len > self.inner.cfg().max_frame_bytes() {
                    return false;
                }
                if level != ServiceLevel::BestEffort {
                    return true;
                }
                let Some(peer) = self.inner.get_peer(node) else {
                    return false;
                };
                peer.try_get_quic_v2_stream()
                    .and_then(|sender| sender.quic_v2_max_datagram_size())
                    .is_some_and(|max_datagram_size| encoded_len <= max_datagram_size)
                    || peer.try_get_legacy_quic_stream().is_some()
            }
            TransportKind::Udp => self
                .udp_datagram_len(node, level, class, payload.len())
                .is_some_and(|bytes| bytes <= self.udp_datagram_mtu_for(node)),
        }
    }

    /// Check a payload against the live v2 DATAGRAM ceiling, or the QUIC
    /// minimum when planning while the current connection is still v1.
    pub fn payload_fits_quic_v2_datagram(
        &self,
        node: NodeIdentifier,
        class: MessageClass,
        payload: &[u8],
    ) -> bool {
        let max_datagram_size = self
            .inner
            .get_peer(node)
            .and_then(|peer| peer.try_get_quic_v2_stream())
            .and_then(|sender| sender.quic_v2_max_datagram_size())
            .unwrap_or(1200);
        encoded_data_frame_len(
            self.inner.self_id(),
            node,
            ServiceLevel::BestEffort,
            class,
            transport_timestamp_us(),
            payload.len(),
        ) <= max_datagram_size.min(self.inner.cfg().max_frame_bytes())
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
        for (name, bytes) in [
            (
                "quic_datagram_send_buffer_bytes",
                cfg.quic_datagram_send_buffer_bytes(),
            ),
            (
                "quic_datagram_receive_buffer_bytes",
                cfg.quic_datagram_receive_buffer_bytes(),
            ),
        ] {
            if bytes != 0 && bytes < 1200 {
                return Err(ConfigError::InvalidQuicDatagramBuffer { name, bytes }.into());
            }
        }
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
            identity: Some(identity),
            peers: Arc::new(SccMap::new()),
            seed_backoff: Arc::new(SccMap::new()),
            successful_seeds: Arc::new(SccMap::new()),
            quarantined_self_seeds: Arc::new(SccMap::new()),
            required_outgoing: Arc::new(RwLock::new(HashSet::new())),
            inbound,
            shutdown: CancellationToken::new(),
            endpoints,
            cfg,
            #[cfg(test)]
            iter_peers_count: Arc::new(AtomicU64::new(0)),
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
        let cfg = TransportConfig::new("ca.pem".into(), "cert.pem".into(), "key.pem".into());
        Self::test_with_live_streams_config(self_id, peer_node, kinds, queue_bytes, cfg)
    }

    #[cfg(test)]
    fn test_with_live_streams_bandwidth_window(
        self_id: NodeIdentifier,
        peer_node: NodeIdentifier,
        kinds: &[TransportKind],
        bandwidth_window: Duration,
    ) -> (Self, Vec<AdaptiveQueueReceiver<OutboundFrame>>) {
        let cfg = TransportConfig::new("ca.pem".into(), "cert.pem".into(), "key.pem".into())
            .with_bandwidth_window(bandwidth_window);
        Self::test_with_live_streams_config(self_id, peer_node, kinds, 1024 * 1024, cfg)
    }

    fn test_with_live_streams_config(
        self_id: NodeIdentifier,
        peer_node: NodeIdentifier,
        kinds: &[TransportKind],
        queue_bytes: usize,
        cfg: TransportConfig,
    ) -> (Self, Vec<AdaptiveQueueReceiver<OutboundFrame>>) {
        let (inbound, _inbound_rx) = test_inbound_dispatch();
        let inner = Arc::new(ManagerInner {
            self_id,
            identity: None,
            peers: Arc::new(SccMap::new()),
            seed_backoff: Arc::new(SccMap::new()),
            successful_seeds: Arc::new(SccMap::new()),
            quarantined_self_seeds: Arc::new(SccMap::new()),
            required_outgoing: Arc::new(RwLock::new(HashSet::new())),
            inbound,
            shutdown: CancellationToken::new(),
            endpoints: EndpointRegistry::empty(),
            cfg,
            #[cfg(test)]
            iter_peers_count: Arc::new(AtomicU64::new(0)),
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

    /// Sign an end-to-end origin-bound payload with this node's configured
    /// certificate key. Callers receive only a detached proof, never key
    /// material.
    pub fn sign_origin_payload(
        &self,
        payload: &[u8],
    ) -> Result<OriginSignature, OriginAuthenticationError> {
        self.inner
            .identity
            .as_ref()
            .ok_or(OriginAuthenticationError::IdentityUnavailable)?
            .sign_origin_payload(payload)
    }

    /// Return the cached wire metadata for this node's detached origin proof
    /// without performing a signature operation.
    pub fn origin_signature_metadata(
        &self,
    ) -> Result<&OriginSignatureMetadata, OriginAuthenticationError> {
        Ok(self
            .inner
            .identity
            .as_ref()
            .ok_or(OriginAuthenticationError::IdentityUnavailable)?
            .origin_signature_metadata())
    }

    /// Verify a detached origin proof against this node's configured S2S CA
    /// and the claimed logical node identifier.
    pub fn verify_origin_payload(
        &self,
        claimed_node: NodeIdentifier,
        proof: &OriginSignature,
        payload: &[u8],
    ) -> Result<(), OriginAuthenticationError> {
        self.inner
            .identity
            .as_ref()
            .ok_or(OriginAuthenticationError::IdentityUnavailable)?
            .verify_origin_payload(claimed_node, proof, payload)
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

    /// Failures encountered while resolving implicit advertise candidates.
    /// They are reported only after all local and public-address discovery
    /// sources have been considered.
    pub fn implicit_advertise_failures(&self) -> &[String] {
        self.inner.cfg().implicit_advertise_failures()
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
            peer.retire();
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
            if *transport == TransportKind::Udp {
                return true;
            }
            if *transport == TransportKind::Quic && level == ServiceLevel::BestEffort {
                let stream_fits = peer.try_get_legacy_quic_stream().is_some_and(|_| {
                    let variant = payloads.variant_for_session(TransportKind::Quic, false);
                    std::iter::once(variant.primary())
                        .chain(variant.sidecars().iter())
                        .all(|payload| {
                            self.payload_fits_transport(
                                node,
                                TransportKind::Quic,
                                level,
                                class,
                                payload,
                            )
                        })
                });
                let datagram_fits = peer.try_get_quic_v2_stream().is_some_and(|sender| {
                    let variant = payloads.variant_for_session(TransportKind::Quic, true);
                    sender
                        .quic_v2_max_datagram_size()
                        .is_some_and(|max_datagram_size| {
                            quic_datagram_variant_fits(
                                node,
                                class,
                                variant,
                                max_datagram_size,
                                selection.max_frame_bytes,
                            )
                        })
                });
                return datagram_fits || stream_fits;
            }
            let variant = payloads.variant(*transport);
            std::iter::once(variant.primary())
                .chain(variant.sidecars().iter())
                .all(|payload| self.payload_fits_transport(node, *transport, level, class, payload))
        });
        if !choices_fit {
            if level == ServiceLevel::BestEffort
                && choices.contains(&TransportKind::Quic)
                && let Some(sender) = peer.try_get_quic_v2_stream()
            {
                sender.record_quic_datagram_drop();
                super::metrics::record_quic_datagram_drop(
                    super::metrics::QuicDatagramDropReason::NoFit,
                );
            }
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
        let peers = self.inner.iter_peers();
        let datagram_health_stale_after = self
            .inner
            .cfg()
            .routing_policy()
            .transport_metric_stale_after();
        let mut entries = Vec::with_capacity(peers.len());
        let mut outbound_queues = Vec::new();
        let mut expired_outbound_drops = Vec::new();
        let mut transport_health_exclusions = Vec::new();
        let mut datagram_path_health = Vec::new();
        let mut voice_transport_bindings = Vec::new();
        let mut voice_transport_binding_events = Vec::new();
        let mut voice_transport_challengers = Vec::new();
        for (node, peer) in peers {
            entries.push((node, peer.metrics().clone()));
            outbound_queues.extend(peer.outbound_queue_status());
            expired_outbound_drops.extend(peer.expired_outbound_drop_status());
            transport_health_exclusions.extend(peer.transport_health_exclusion_status());
            datagram_path_health
                .extend(peer.datagram_path_health_status(datagram_health_stale_after));
            voice_transport_bindings.extend(peer.voice_transport_binding_status());
            voice_transport_binding_events.extend(peer.voice_transport_binding_event_status());
            voice_transport_challengers.extend(peer.voice_transport_challenger_status());
        }
        outbound_queues.sort_by_key(|queue| (queue.peer(), queue.queue_key()));
        expired_outbound_drops.sort_by_key(|drop| {
            (
                drop.peer(),
                drop.stage().name(),
                drop.transport(),
                drop.class() as u8,
            )
        });
        transport_health_exclusions
            .sort_by_key(|exclusion| (exclusion.peer(), exclusion.transport(), exclusion.reason()));
        datagram_path_health.sort_by_key(|health| (health.peer(), health.path()));
        voice_transport_bindings.sort_by_key(|binding| binding.peer());
        voice_transport_binding_events.sort_by_key(|event| {
            (
                event.peer(),
                event.from_transport(),
                event.to_transport(),
                event.reason(),
            )
        });
        voice_transport_challengers.sort_by_key(|event| {
            (
                event.peer(),
                event.incumbent(),
                event.challenger(),
                event.outcome(),
            )
        });
        assemble_snapshot(
            entries,
            outbound_queues,
            self.inner.inbound.queue_status(),
            expired_outbound_drops,
            transport_health_exclusions,
            datagram_path_health,
            voice_transport_bindings,
            voice_transport_binding_events,
            voice_transport_challengers,
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

    /// Return immutable runtime status for every currently-live QUIC session.
    pub fn quic_session_status(&self) -> Vec<QuicSessionStatusSnapshot> {
        let cfg = self.inner.cfg();
        let mut out = self
            .inner
            .iter_peers()
            .into_iter()
            .flat_map(|(_, peer)| {
                peer.quic_session_status(
                    cfg.quic_datagram_send_buffer_bytes(),
                    cfg.quic_datagram_receive_buffer_bytes(),
                )
            })
            .collect::<Vec<_>>();
        out.sort_by_key(|snapshot| {
            (
                snapshot.peer(),
                snapshot.remote_addr(),
                snapshot.is_dialer(),
                snapshot.protocol(),
            )
        });
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

    /// Return the metrics used to select the best currently live transport
    /// for `node`. Selection and the returned value are derived from the same
    /// immutable per-peer snapshot. This observation does not record health
    /// exclusions or change transport recovery gates.
    pub fn selected_live_transport_metrics(
        &self,
        node: NodeIdentifier,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
    ) -> Option<(TransportKind, LinkMetrics)> {
        let peer = self.inner.get_peer(node)?;
        let snapshot = peer.metrics().snapshot_per_transport();
        let selected = observe_transports_with_snapshot(
            &peer,
            level,
            routing_metric,
            MessageClass::HighPriority,
            SendOptions::default(),
            0,
            TransportSelectionConfig::from_config(self.inner.cfg()),
            &snapshot,
        )
        .into_iter()
        .next()?;
        snapshot
            .get(&selected)
            .cloned()
            .map(|link| (selected, link))
    }

    /// Effective packet loss of the UDP datagram lane for `node`, or `None`
    /// when no UDP transport is live.
    ///
    /// Feeds `VoiceRouteQuality::datagram_loss_ppm`. This was the FEC gate
    /// input during the Phase 1 gate fix; that was reverted — the datagram
    /// lane degrades independently of the lane voice actually rides, so
    /// keying FEC on it fired parity at times the voice lane had no loss to
    /// recover (4->8: UDP-degradation windows did not align with listener
    /// reorder gaps). The field remains populated as a metric signal but is
    /// not currently read by production gate logic. KCP is excluded — voice
    /// is never routed onto it, so its loss does not reflect the voice lane.
    pub fn datagram_lane_effective_loss_ppm(&self, node: NodeIdentifier) -> Option<u32> {
        let peer = self.inner.get_peer(node)?;
        let snapshot = peer.metrics().snapshot_per_transport();
        peer.live_kinds()
            .into_iter()
            .filter(|kind| matches!(kind, TransportKind::Udp))
            .filter_map(|kind| snapshot.get(&kind))
            .map(|link| link.effective_packet_loss_ppm())
            .max()
    }

    /// Best queue-pressure penalty the sender would see for this peer now.
    /// Lower is better; this combines the peer dispatcher backlog with the
    /// selected stream. Expiring sends include estimated drain time while
    /// non-expiring sends use current fill for every message class.
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
        let policy = self.inner.cfg().routing_policy();
        let mut ranked = pick_transports(
            &peer,
            level,
            routing_metric,
            class,
            options,
            0,
            TransportSelectionConfig::from_config(self.inner.cfg()),
        );
        apply_voice_transport_stickiness(
            &peer,
            &mut ranked,
            level,
            routing_metric,
            class,
            options,
            policy,
            now,
            false,
        );
        ranked
            .first()
            .copied()
            .map(|transport| send_queue_penalty(&peer, transport, level, class, options, now))
    }

    /// Return the pressure for a conversational path. In addition to local
    /// queue pressure, sustained loss on the selected path is a soft failure
    /// so the overlay can select a cleaner relay.
    pub fn best_conversational_path_pressure(
        &self,
        node: NodeIdentifier,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        options: SendOptions,
    ) -> Option<u8> {
        let peer = self.inner.get_peer(node)?;
        let now = Instant::now();
        let policy = self.inner.cfg().routing_policy();
        let mut ranked = pick_transports(
            &peer,
            level,
            routing_metric,
            class,
            options,
            0,
            TransportSelectionConfig::from_config(self.inner.cfg()),
        );
        apply_voice_transport_stickiness(
            &peer,
            &mut ranked,
            level,
            routing_metric,
            class,
            options,
            policy,
            now,
            false,
        );
        let selected = ranked.first().copied()?;
        let queue_pressure = send_queue_penalty(&peer, selected, level, class, options, now);
        if routing_metric != RoutingMetric::ConversationalQuality {
            return Some(queue_pressure);
        }

        let snapshot = peer.metrics().snapshot_per_transport();
        let quality_transport = if level == ServiceLevel::BestEffort {
            preferred_conversational_datagram_path(&peer, &ranked, &snapshot, policy)
                .map(DeliveryPath::transport)
                .unwrap_or(selected)
        } else {
            selected
        };
        let quality_pressure = u8::from(
            peer.observe_conversational_transport_loss(
                quality_transport,
                snapshot
                    .get(&quality_transport)
                    .map(LinkMetrics::effective_packet_loss_ppm),
                policy.conversational_path_effective_loss_suspect_ppm(),
                policy.conversational_path_effective_loss_recover_ppm(),
            ),
        ) * 2;
        let playout_pressure = u8::from(peer.observe_conversational_transport_playout(
            quality_transport,
            snapshot.get(&quality_transport),
        )) * 2;
        let feedback_pressure = u8::from(peer.conversational_feedback_suspect(now)) * 2;
        Some(
            queue_pressure
                .max(quality_pressure)
                .max(playout_pressure)
                .max(feedback_pressure),
        )
    }

    /// Health of the best-effort datagram lane for `node` — the lane voice
    /// rides. Composite conversational pressure cannot express a hard-Blocked
    /// lane (the reliable fallback can look clean while voice has no datagram
    /// path), so the distribution plane uses this to (C2a) escape immediately
    /// when the incumbent lane is Blocked and (C2b) shorten the challenger
    /// confirm when the incumbent lane is losing at/above the full-dup
    /// threshold.
    pub fn best_effort_datagram_lane_health(
        &self,
        node: NodeIdentifier,
    ) -> BestEffortDatagramLaneHealth {
        let stale_after = self.inner.cfg().routing_policy().transport_metric_stale_after();
        let Some(peer) = self.inner.get_peer(node) else {
            return BestEffortDatagramLaneHealth::default();
        };
        let snapshots = peer.datagram_path_health_status(stale_after);
        active_best_effort_datagram_lane_health(&snapshots)
    }

    /// Whether `node` is reporting degraded reorder quality on the voice this
    /// node sent it — the receiver-side gap signal (C2c). This is the same
    /// suspect flag folded into the soft `feedback_pressure` inside
    /// [`Self::best_conversational_path_pressure`], but surfaced as a distinct
    /// boolean so the distribution plane can shorten the challenger confirm on
    /// a leaf-reported gap the same way it does on hard datagram loss (C2b) —
    /// the sink, not the sender, is the one hearing the loss.
    pub fn best_effort_sink_feedback(&self, node: NodeIdentifier) -> BestEffortSinkFeedback {
        let Some(peer) = self.inner.get_peer(node) else {
            return BestEffortSinkFeedback::default();
        };
        BestEffortSinkFeedback {
            suspect: peer.conversational_feedback_suspect(Instant::now()),
        }
    }

    pub fn record_conversational_path_feedback(
        &self,
        peer: NodeIdentifier,
        received_frames: u32,
        gap_buffered: u32,
        deadline_flush: u32,
        max_held_delay_us: u64,
    ) {
        if let Some(peer) = self.inner.get_peer(peer) {
            peer.record_conversational_feedback(
                received_frames,
                gap_buffered,
                deadline_flush,
                max_held_delay_us,
                Instant::now(),
            );
        }
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
    let snapshot = peer.metrics().snapshot_per_transport();
    pick_transports_with_snapshot(
        peer,
        level,
        routing_metric,
        class,
        options,
        payload_len,
        selection,
        &snapshot,
    )
}

#[allow(clippy::too_many_arguments)]
fn pick_transports_with_snapshot(
    peer: &PeerState,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    options: SendOptions,
    payload_len: usize,
    selection: impl Into<TransportSelectionConfig>,
    snapshot: &HashMap<TransportKind, LinkMetrics>,
) -> Vec<TransportKind> {
    rank_transports_with_snapshot(
        peer,
        level,
        routing_metric,
        class,
        options,
        payload_len,
        selection,
        snapshot,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn observe_transports_with_snapshot(
    peer: &PeerState,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    options: SendOptions,
    payload_len: usize,
    selection: impl Into<TransportSelectionConfig>,
    snapshot: &HashMap<TransportKind, LinkMetrics>,
) -> Vec<TransportKind> {
    rank_transports_with_snapshot(
        peer,
        level,
        routing_metric,
        class,
        options,
        payload_len,
        selection,
        snapshot,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn rank_transports_with_snapshot(
    peer: &PeerState,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    options: SendOptions,
    payload_len: usize,
    selection: impl Into<TransportSelectionConfig>,
    snapshot: &HashMap<TransportKind, LinkMetrics>,
    record_health_effects: bool,
) -> Vec<TransportKind> {
    let selection = selection.into();
    let now = Instant::now();
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
            && transport_is_viable_alternative(peer, transport, snapshot, selection.routing, now)
    });
    candidates.retain(|transport| {
        let reason = if record_health_effects {
            transport_candidate_exclusion_reason(
                peer,
                *transport,
                level,
                routing_metric,
                class,
                options,
                snapshot,
                selection,
                has_viable_kcp_alternative,
                now,
            )
        } else {
            transport_candidate_exclusion_reason_read_only(
                peer,
                *transport,
                level,
                routing_metric,
                class,
                options,
                snapshot,
                selection,
                has_viable_kcp_alternative,
                now,
            )
        };
        if let Some(reason) = reason {
            if record_health_effects {
                peer.record_transport_health_exclusion(*transport, reason);
            }
            false
        } else {
            true
        }
    });
    if candidates.is_empty() {
        return Vec::new();
    }

    let mut ranked =
        peer.metrics()
            .ranked_transports_for_snapshot(level, routing_metric, &candidates, snapshot);

    if level == ServiceLevel::BestEffort {
        ranked.sort_by(|left, right| {
            adjusted_routing_cost(*left, level, routing_metric, selection.routing, snapshot)
                .partial_cmp(&adjusted_routing_cost(
                    *right,
                    level,
                    routing_metric,
                    selection.routing,
                    snapshot,
                ))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| kind_order(*left).cmp(&kind_order(*right)))
        });
    }

    let best_effort = level == ServiceLevel::BestEffort;
    candidates.sort_by_key(|kind| {
        if best_effort {
            (0, 0, kind_order(*kind))
        } else {
            fallback_transport_rank(*kind, level)
        }
    });

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
        snapshot,
    );
    if options.expires_at().is_some() {
        ranked.sort_by_key(|kind| {
            deadline_queue_penalty_with_snapshot(peer, *kind, level, class, options, now, snapshot)
        });
        if class == MessageClass::HighPriority {
            ranked.retain(|kind| {
                deadline_queue_penalty_with_snapshot(
                    peer, *kind, level, class, options, now, snapshot,
                ) < 3
            });
        }
    } else {
        // A full stream cannot accept control or repair traffic any more than
        // it can accept bulk traffic. Apply current queue pressure to every
        // class so a reliable send does not keep selecting a saturated KCP
        // stream merely because it has the best historical link metric.
        ranked.sort_by_key(|kind| non_deadline_queue_penalty(peer, *kind, level, class));
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
                RoutingMetric::ConversationalQuality,
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
    routing_metric: RoutingMetric,
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
        routing_metric,
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
    routing_metric: RoutingMetric,
    class: MessageClass,
    options: SendOptions,
    snapshot: &HashMap<TransportKind, LinkMetrics>,
    selection: TransportSelectionConfig,
    has_viable_kcp_alternative: bool,
    now: Instant,
) -> Option<TransportHealthExclusionReason> {
    let reason = transport_candidate_exclusion_reason_read_only(
        peer,
        transport,
        level,
        routing_metric,
        class,
        options,
        snapshot,
        selection,
        has_viable_kcp_alternative,
        now,
    );
    if reason == Some(TransportHealthExclusionReason::KcpFailaway) {
        peer.require_kcp_best_effort_recovery();
    }
    reason
}

#[allow(clippy::too_many_arguments)]
fn transport_candidate_exclusion_reason_read_only(
    peer: &PeerState,
    transport: TransportKind,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
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
    if transport == TransportKind::Kcp
        && is_expiring_conversational_voice(level, routing_metric, class, options)
        && peer.kcp_best_effort_recovery_pending()
    {
        return Some(TransportHealthExclusionReason::KcpRecoveryPending);
    }

    let nonblocking_quic_path_available = level == ServiceLevel::BestEffort
        && transport == TransportKind::Quic
        && peer.try_get_quic_v2_stream().is_some();
    if !nonblocking_quic_path_available
        && (level == ServiceLevel::BestEffort
            || class == MessageClass::HighPriority
            || options.expires_at().is_some())
        && transport_queue_known_dead(
            peer,
            transport,
            snapshot.get(&transport),
            selection.routing,
            now,
        )
        && transport_lane_queue_known_dead(
            peer,
            transport,
            level,
            class,
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
    if transport == TransportKind::Quic && peer.try_get_quic_v2_stream().is_some() {
        return true;
    }
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

fn transport_lane_queue_known_dead(
    peer: &PeerState,
    transport: TransportKind,
    level: ServiceLevel,
    class: MessageClass,
    link: Option<&LinkMetrics>,
    policy: TransportRoutingPolicy,
    now: Instant,
) -> bool {
    if !transport.is_stream()
        || !peer
            .outbound_lane_queue_status(transport, level, class)
            .is_some_and(|status| status.depth() > 0)
    {
        return false;
    }
    let Some(link) = link else {
        return false;
    };
    let Some(last_update) = link.last_update() else {
        return false;
    };
    now.saturating_duration_since(last_update) >= policy.transport_metric_stale_after()
        && link.wire_sent_bps() <= f64::EPSILON
        && link.wire_recv_bps() <= f64::EPSILON
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
    snapshot: &HashMap<TransportKind, LinkMetrics>,
) {
    // BestEffort is ranked by logical delivery path.
    // Physical UDP-family promotion cannot distinguish QUIC DATAGRAM from a
    // QUIC stream and historically promoted KCP as if it were nonblocking.
    if level == ServiceLevel::BestEffort {
        return;
    }
    if ranked.len() < 2 {
        return;
    }

    let Some(tcp_pos) = ranked.iter().position(|kind| *kind == TransportKind::Tcp) else {
        return;
    };

    let intent = transport_selection_intent(peer, class, options, payload_len, policy);
    let health = udp_family_health(peer, ranked, snapshot, policy);
    let tcp_usable = tcp_transport_usable(peer, snapshot.get(&TransportKind::Tcp), policy);

    match intent {
        TransportSelectionIntent::TcpFavored => {
            if tcp_usable {
                move_transport_to_front(ranked, tcp_pos);
            }
        }
        TransportSelectionIntent::LatencySensitive => {
            if tcp_usable {
                if let Some(udp_pos) =
                    udp_family_promotion_position(ranked, snapshot, routing_metric, health, policy)
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
    class: MessageClass,
    options: SendOptions,
    payload_len: usize,
    policy: TransportRoutingPolicy,
) -> TransportSelectionIntent {
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

fn is_expiring_conversational_voice(
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    options: SendOptions,
) -> bool {
    is_conversational_best_effort(level, routing_metric, class) && options.expires_at().is_some()
}

fn preferred_conversational_datagram_path(
    peer: &PeerState,
    ranked: &[TransportKind],
    snapshot: &HashMap<TransportKind, LinkMetrics>,
    policy: TransportRoutingPolicy,
) -> Option<DeliveryPath> {
    for transport in ranked {
        let path = match transport {
            TransportKind::Udp if peer.try_get_stream(TransportKind::Udp).is_some() => {
                DeliveryPath::UdpDatagram
            }
            TransportKind::Quic if peer.try_get_quic_v2_stream().is_some() => {
                DeliveryPath::QuicDatagram
            }
            _ => continue,
        };
        if matches!(
            udp_family_health(peer, &[path.transport()], snapshot, policy),
            UdpFamilyHealth::Probing | UdpFamilyHealth::Viable
        ) {
            return Some(path);
        }
    }
    None
}

/// Resolve the best-effort datagram lane health for a peer from its per-path
/// datagram health snapshots. Mirrors the overlay's active-lane preference
/// (`NeighborMonitor::datagram_lane_loss`): UDP datagram when usable, else
/// QUIC datagram. `blocked` is true only when at least one datagram lane was
/// observed AND every observed lane is Blocked — a missing lane is not a
/// Blocked lane (fresh link, still probing).
fn active_best_effort_datagram_lane_health(
    snapshots: &[DatagramPathHealthSnapshot],
) -> BestEffortDatagramLaneHealth {
    let mut udp = None;
    let mut quic = None;
    let mut observed = 0u8;
    let mut blocked = 0u8;
    for snapshot in snapshots {
        match snapshot.path() {
            DeliveryPath::UdpDatagram | DeliveryPath::QuicDatagram => {
                observed += 1;
                if snapshot.state() == DatagramPathHealthState::Blocked {
                    blocked += 1;
                } else if snapshot.path() == DeliveryPath::UdpDatagram {
                    udp = Some(snapshot);
                } else {
                    quic = Some(snapshot);
                }
            }
            _ => {}
        }
    }
    let active = udp.or(quic);
    BestEffortDatagramLaneHealth {
        blocked: observed > 0 && observed == blocked,
        loss_ppm: active.and_then(|snapshot| snapshot.effective_loss_ppm()),
        loss_samples: active.map_or(0, |snapshot| snapshot.loss_samples()),
    }
}

fn is_conversational_best_effort(
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
) -> bool {
    level == ServiceLevel::BestEffort
        && routing_metric == RoutingMetric::ConversationalQuality
        && class == MessageClass::HighPriority
}

fn adjusted_routing_cost(
    transport: TransportKind,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    policy: TransportRoutingPolicy,
    snapshot: &HashMap<TransportKind, LinkMetrics>,
) -> f64 {
    let Some(cost) = snapshot
        .get(&transport)
        .and_then(|link| link.routing_cost(level, routing_metric))
        .filter(|cost| cost.is_finite())
    else {
        return f64::INFINITY;
    };
    if transport != TransportKind::Kcp || level != ServiceLevel::BestEffort {
        return cost;
    }
    cost * (1.0 + f64::from(policy.best_effort_kcp_cost_penalty_pct()) / 100.0)
}

fn apply_voice_transport_stickiness(
    peer: &PeerState,
    ranked: &mut Vec<TransportKind>,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    options: SendOptions,
    policy: TransportRoutingPolicy,
    now: Instant,
    observe: bool,
) -> Option<super::connection::VoiceTransportDecision> {
    apply_voice_transport_stickiness_with_pressure(
        peer,
        ranked,
        level,
        routing_metric,
        class,
        options,
        policy,
        now,
        None,
        observe,
    )
}

#[allow(clippy::too_many_arguments)]
fn apply_voice_transport_stickiness_with_pressure(
    peer: &PeerState,
    ranked: &mut Vec<TransportKind>,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    options: SendOptions,
    policy: TransportRoutingPolicy,
    now: Instant,
    pressure_overrides: Option<&HashMap<TransportKind, u8>>,
    observe: bool,
) -> Option<super::connection::VoiceTransportDecision> {
    if !policy.voice_path_stickiness_enabled()
        || !is_expiring_conversational_voice(level, routing_metric, class, options)
        || ranked.is_empty()
    {
        return None;
    }
    let snapshot = peer.metrics().snapshot_per_transport();
    let candidates = ranked
        .iter()
        .copied()
        .map(|transport| {
            VoiceTransportCandidateScore::new(
                transport,
                pressure_overrides
                    .and_then(|pressures| pressures.get(&transport).copied())
                    .unwrap_or_else(|| {
                        deadline_queue_penalty(peer, transport, level, class, options, now)
                    }),
                snapshot
                    .get(&transport)
                    .map(|_| {
                        adjusted_routing_cost(transport, level, routing_metric, policy, &snapshot)
                    })
                    .filter(|cost| cost.is_finite()),
            )
        })
        .collect::<Vec<_>>();
    let mut decision = peer.choose_voice_transport(
        &candidates,
        now,
        policy.voice_path_min_hold(),
        policy.voice_path_challenger_confirm(),
        policy.voice_path_idle_reset(),
        policy.transport_switch_improvement_pct(),
        observe,
    )?;
    if decision.reason() == VoiceTransportBindingEventReason::TransportUnavailable {
        let exclusion_reason = decision.incumbent().and_then(|incumbent| {
            if !peer.live_kinds().contains(&incumbent) {
                return None;
            }
            if peer
                .outbound_stream_queue_status(incumbent)
                .is_some_and(|status| status.capacity() > 0 && status.depth() >= status.capacity())
            {
                Some(VoiceTransportBindingEventReason::QueueFull)
            } else if deadline_queue_penalty(peer, incumbent, level, class, options, now) >= 3 {
                Some(VoiceTransportBindingEventReason::DeadlineImpossible)
            } else {
                None
            }
        });
        if let Some(reason) = exclusion_reason {
            decision = decision.with_reason(reason);
        }
    }
    if let Some(position) = ranked
        .iter()
        .position(|transport| *transport == decision.preferred())
    {
        move_transport_to_front(ranked, position);
    }
    Some(decision)
}

fn record_voice_transport_no_alternate(
    peer: &PeerState,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    options: SendOptions,
    now: Instant,
) {
    if !peer.record_voice_transport_no_alternate() {
        return;
    }
    let incumbent = peer
        .voice_transport_binding_status()
        .map(|binding| binding.transport());
    let incumbent_pressure = incumbent
        .map(|transport| deadline_queue_penalty(peer, transport, level, class, options, now));
    let (held_for, confirmation_for) = peer.voice_transport_binding_ages(now);
    debug!(
        peer = %peer.node_id(),
        ?incumbent,
        challenger = ?Option::<TransportKind>::None,
        incumbent_pressure,
        challenger_pressure = ?Option::<u8>::None,
        held_ms = held_for.as_millis(),
        confirmation_ms = confirmation_for.as_millis(),
        ?level,
        ?routing_metric,
        reason = VoiceTransportBindingEventReason::NoAlternate.name(),
        "voice transport escape had no eligible alternate"
    );
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
    const UDP_FAMILY: [TransportKind; 2] = [TransportKind::Quic, TransportKind::Udp];

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
        .is_some_and(|status| status.capacity() > 0 && status.depth() >= status.capacity())
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
        if !matches!(transport, TransportKind::Quic | TransportKind::Udp) {
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
    level: ServiceLevel,
    class: MessageClass,
    options: SendOptions,
    now: Instant,
) -> u8 {
    if options.expires_at().is_some() {
        route_deadline_queue_penalty(peer, transport, level, class, options, now)
    } else {
        non_deadline_queue_penalty(peer, transport, level, class)
            .max(peer_queue_fill_penalty(peer, class))
    }
}

/// Queue pressure used while choosing an overlay first hop must include the
/// routed peer queue as well as the selected transport's handoff queue. A
/// saturated peer dispatcher otherwise looks healthy until after routing has
/// already selected it and enqueue reports backpressure.
fn route_deadline_queue_penalty(
    peer: &PeerState,
    transport: TransportKind,
    level: ServiceLevel,
    class: MessageClass,
    options: SendOptions,
    now: Instant,
) -> u8 {
    let (peer_depth, peer_fill_penalty, peer_queue_full) = peer_queue_pressure(peer, class);
    if peer_queue_full {
        return 3;
    }
    let snapshot = peer.metrics().snapshot_per_transport();
    deadline_queue_penalty_with_additional_depth_and_snapshot(
        peer,
        transport,
        level,
        class,
        options,
        now,
        peer_depth,
        peer_fill_penalty,
        &snapshot,
    )
}

fn deadline_queue_penalty(
    peer: &PeerState,
    transport: TransportKind,
    level: ServiceLevel,
    class: MessageClass,
    options: SendOptions,
    now: Instant,
) -> u8 {
    let snapshot = peer.metrics().snapshot_per_transport();
    deadline_queue_penalty_with_snapshot(peer, transport, level, class, options, now, &snapshot)
}

fn deadline_queue_penalty_with_snapshot(
    peer: &PeerState,
    transport: TransportKind,
    level: ServiceLevel,
    class: MessageClass,
    options: SendOptions,
    now: Instant,
    snapshot: &HashMap<TransportKind, LinkMetrics>,
) -> u8 {
    deadline_queue_penalty_with_additional_depth_and_snapshot(
        peer, transport, level, class, options, now, 0, 0, snapshot,
    )
}

#[allow(clippy::too_many_arguments)]
fn deadline_queue_penalty_with_additional_depth_and_snapshot(
    peer: &PeerState,
    transport: TransportKind,
    level: ServiceLevel,
    class: MessageClass,
    options: SendOptions,
    now: Instant,
    additional_depth: usize,
    additional_fill_penalty: u8,
    snapshot: &HashMap<TransportKind, LinkMetrics>,
) -> u8 {
    let Some(expires_at) = options.expires_at() else {
        return 0;
    };
    let remaining = expires_at.saturating_duration_since(now);
    if remaining.is_zero() || remaining <= DEADLINE_NEAR_EXPIRED_TTL {
        return 3;
    }
    if level == ServiceLevel::BestEffort
        && transport == TransportKind::Quic
        && peer
            .try_get_quic_v2_stream()
            .and_then(|sender| sender.quic_v2_max_datagram_size())
            .is_some()
    {
        return additional_fill_penalty;
    }

    let Some(status) = peer.outbound_lane_queue_status(transport, level, class) else {
        return 0;
    };
    if status.capacity() > 0 && status.depth() >= status.capacity() {
        return 3;
    }
    if class == MessageClass::Control
        && (current_queue_fill_penalty(status.depth(), status.capacity()) == 3
            || additional_fill_penalty == 3)
    {
        return 3;
    }

    let depth_bytes = status.depth().saturating_add(additional_depth);
    if depth_bytes == 0 {
        return 0;
    }

    let drain_bytes_per_ms = estimated_drain_bytes_per_ms(snapshot.get(&transport));
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

fn peer_queue_fill_penalty(peer: &PeerState, class: MessageClass) -> u8 {
    peer_queue_pressure(peer, class).1
}

fn peer_queue_pressure(peer: &PeerState, class: MessageClass) -> (usize, u8, bool) {
    let sender = peer.outbound_sender();
    let depth = sender.depth_bytes();
    let capacity = sender.capacity_bytes();
    let (class_depth, class_capacity) = sender.class_depth_and_capacity(class);
    let fill_penalty = current_queue_fill_penalty(depth, capacity)
        .max(current_queue_fill_penalty(class_depth, class_capacity));
    let full = (capacity > 0 && depth >= capacity)
        || (class_capacity > 0 && class_depth >= class_capacity);
    (depth, fill_penalty, full)
}

fn estimated_drain_bytes_per_ms(link: Option<&LinkMetrics>) -> f64 {
    let drain_bytes_per_sec = link
        .map(|link| link.estimated_throughput_bps())
        .filter(|rate| rate.is_finite() && *rate >= DEADLINE_DRAIN_FALLBACK_BYTES_PER_SEC)
        .unwrap_or(DEADLINE_DRAIN_FALLBACK_BYTES_PER_SEC);
    drain_bytes_per_sec / 1_000.0
}

fn non_deadline_queue_penalty(
    peer: &PeerState,
    transport: TransportKind,
    level: ServiceLevel,
    class: MessageClass,
) -> u8 {
    if level == ServiceLevel::BestEffort
        && transport == TransportKind::Quic
        && peer
            .try_get_quic_v2_stream()
            .and_then(|sender| sender.quic_v2_max_datagram_size())
            .is_some()
    {
        return 0;
    }
    let Some(status) = peer.outbound_lane_queue_status(transport, level, class) else {
        return 0;
    };
    current_queue_fill_penalty(status.depth(), status.capacity())
}

fn current_queue_fill_penalty(depth: usize, capacity: usize) -> u8 {
    if depth == 0 || capacity == 0 {
        return 0;
    }
    if depth >= capacity
        || depth.saturating_mul(100) >= capacity.saturating_mul(OUTBOUND_QUEUE_SATURATED_PERCENT)
    {
        3
    } else {
        1
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
        if inner.shutdown().is_cancelled() || peer.retired().is_cancelled() {
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
            _ = peer.retired().cancelled() => return,
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

struct DeliveryCandidate {
    path: DeliveryPath,
    sender: SessionSender,
    quic_v2: bool,
}

fn delivery_candidates(
    peer: &PeerState,
    envelope: &OutboundEnvelope,
    choices: Vec<TransportKind>,
    max_frame_bytes: usize,
) -> (Vec<DeliveryCandidate>, Option<SessionSender>) {
    let mut candidates = Vec::with_capacity(choices.len().saturating_add(1));
    let mut no_fit_quic_sender = None;

    for transport in choices {
        if transport == TransportKind::Quic && envelope.level() == ServiceLevel::BestEffort {
            if let Some(sender) = peer.try_get_quic_v2_stream()
                && let Some(max_datagram_size) = sender.quic_v2_max_datagram_size()
            {
                let variant = envelope
                    .payloads()
                    .variant_for_session(TransportKind::Quic, true);
                if quic_datagram_variant_fits(
                    peer.node_id(),
                    envelope.class(),
                    variant,
                    max_datagram_size,
                    max_frame_bytes,
                ) {
                    candidates.push(DeliveryCandidate {
                        path: DeliveryPath::QuicDatagram,
                        sender: sender.clone(),
                        quic_v2: true,
                    });
                } else {
                    record_quic_datagram_evidence(
                        peer,
                        &sender,
                        DatagramPathEvidenceEvent::TooLarge,
                    );
                    no_fit_quic_sender = Some(sender);
                }
            }
            // Strict s2s/2 class streams reject BestEffort. Retain the
            // historical s2s/1 single-stream fallback, but never enqueue a
            // BestEffort frame on an s2s/2 reliable lane.
            if let Some(sender) = peer.try_get_legacy_quic_stream() {
                candidates.push(DeliveryCandidate {
                    path: DeliveryPath::QuicStream,
                    quic_v2: false,
                    sender,
                });
            }
            continue;
        }

        let Some(sender) = peer.try_get_stream(transport) else {
            continue;
        };
        let path = if transport == TransportKind::Udp {
            DeliveryPath::UdpDatagram
        } else {
            DeliveryPath::stream(transport).expect("non-UDP transport must have a stream path")
        };
        let quic_v2 = sender.quic_v2_max_datagram_size().is_some();
        candidates.push(DeliveryCandidate {
            path,
            sender,
            quic_v2,
        });
    }

    (candidates, no_fit_quic_sender)
}

fn prefer_best_effort_datagram_paths(
    peer: &PeerState,
    candidates: &mut Vec<DeliveryCandidate>,
    envelope: &OutboundEnvelope,
    policy: TransportRoutingPolicy,
) {
    if envelope.level() != ServiceLevel::BestEffort {
        return;
    }

    let snapshot = peer.metrics().snapshot_per_transport();
    let now = Instant::now();
    let expiring_voice = is_expiring_conversational_voice(
        envelope.level(),
        envelope.routing_metric(),
        envelope.class(),
        envelope.options(),
    );
    candidates.retain(|candidate| {
        if !candidate.path.is_datagram() {
            return true;
        }
        let physical_health =
            udp_family_health(peer, &[candidate.path.transport()], &snapshot, policy);
        observe_best_effort_datagram_path_health(peer, candidate.path, &snapshot, policy, now);
        matches!(
            physical_health,
            UdpFamilyHealth::Probing | UdpFamilyHealth::Viable
        )
    });
    if expiring_voice {
        candidates.retain(|candidate| {
            candidate.path.is_datagram()
                || delivery_candidate_lane_penalty(candidate, envelope, &snapshot, now) < 3
        });
    }
    candidates.sort_by(|left, right| {
        delivery_candidate_tier(left)
            .cmp(&delivery_candidate_tier(right))
            .then_with(|| {
                if left.path.is_datagram() {
                    std::cmp::Ordering::Equal
                } else {
                    delivery_candidate_lane_penalty(left, envelope, &snapshot, now).cmp(
                        &delivery_candidate_lane_penalty(right, envelope, &snapshot, now),
                    )
                }
            })
    });
}

fn observe_best_effort_datagram_path_health(
    peer: &PeerState,
    path: DeliveryPath,
    snapshot: &HashMap<TransportKind, LinkMetrics>,
    policy: TransportRoutingPolicy,
    now: Instant,
) -> DatagramPathHealthState {
    debug_assert!(path.is_datagram());
    if path == DeliveryPath::QuicDatagram {
        let evidence = peer
            .metrics()
            .datagram_path_evidence_snapshots_at(path, now);
        return peer.observe_quic_datagram_path_health(
            &evidence,
            policy.udp_family_min_samples(),
            policy.best_effort_quic_datagram_health_suspect_ppm(),
            policy.best_effort_quic_datagram_health_recover_ppm(),
            policy.best_effort_datagram_suspect_bad_windows(),
            policy.best_effort_datagram_recover_healthy(),
            policy.transport_metric_stale_after(),
            now,
        );
    }
    let transport = path.transport();
    let link = snapshot.get(&transport);
    let fresh_link = link.filter(|link| {
        link.last_update().is_some_and(|last_update| {
            now.saturating_duration_since(last_update) < policy.transport_metric_stale_after()
        })
    });
    let effective_loss_ppm = fresh_link.map(LinkMetrics::effective_packet_loss_ppm);
    let loss_samples = fresh_link.map(LinkMetrics::loss_sample_count).unwrap_or(0);
    let address_failures_blocked = peer.max_consecutive_failures_for_transports(&[transport])
        >= policy.udp_family_probe_loss_block_count();
    let consecutive_probe_losses_blocked = fresh_link.is_some_and(|link| {
        link.consecutive_probe_losses() >= policy.udp_family_probe_loss_block_count()
    });

    peer.observe_datagram_path_health(
        path,
        effective_loss_ppm,
        loss_samples,
        policy.udp_family_min_samples(),
        address_failures_blocked,
        consecutive_probe_losses_blocked,
        policy.best_effort_datagram_effective_loss_suspect_ppm(),
        policy.best_effort_datagram_effective_loss_recover_ppm(),
        policy.udp_family_block_loss_ppm(),
        now,
    )
}

fn delivery_candidate_tier(candidate: &DeliveryCandidate) -> u8 {
    match candidate.path {
        DeliveryPath::UdpDatagram | DeliveryPath::QuicDatagram => 0,
        DeliveryPath::QuicStream | DeliveryPath::TcpStream | DeliveryPath::KcpStream => 1,
    }
}

fn delivery_candidate_allowed_after_datagram_failure(
    path: DeliveryPath,
    prevent_stream_fallback: bool,
    datagram_enqueue_failed: bool,
) -> bool {
    !prevent_stream_fallback || !datagram_enqueue_failed || path.is_datagram()
}

fn delivery_candidate_lane_penalty(
    candidate: &DeliveryCandidate,
    envelope: &OutboundEnvelope,
    snapshot: &HashMap<TransportKind, LinkMetrics>,
    now: Instant,
) -> u8 {
    if candidate.path.is_datagram() {
        return 0;
    }

    let (depth, capacity) = candidate.sender.depth_capacity_for_path(
        candidate.path,
        envelope.level(),
        envelope.class(),
    );
    if capacity > 0 && depth >= capacity {
        return 3;
    }
    let Some(expires_at) = envelope.options().expires_at() else {
        return current_queue_fill_penalty(depth, capacity);
    };
    let remaining = expires_at.saturating_duration_since(now);
    if remaining.is_zero() || remaining <= DEADLINE_NEAR_EXPIRED_TTL {
        return 3;
    }
    if depth == 0 {
        return 0;
    }

    let drain_bytes_per_ms =
        estimated_drain_bytes_per_ms(snapshot.get(&candidate.path.transport()));
    if !drain_bytes_per_ms.is_finite() || drain_bytes_per_ms <= 0.0 {
        return 3;
    }
    let queue_delay_ms = depth as f64 / drain_bytes_per_ms;
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
            envelope.routing_metric(),
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

    let sticky_voice = envelope.target_transport().is_none()
        && selection.routing.voice_path_stickiness_enabled()
        && is_expiring_conversational_voice(
            envelope.level(),
            envelope.routing_metric(),
            envelope.class(),
            envelope.options(),
        );
    if choices.is_empty() {
        if sticky_voice {
            record_voice_transport_no_alternate(
                peer,
                envelope.level(),
                envelope.routing_metric(),
                class,
                envelope.options(),
                now,
            );
        }
        if envelope.level() == ServiceLevel::BestEffort {
            return Ok(());
        }
        return Err(envelope);
    }

    let attempted_transports = choices.clone();
    let (mut delivery_candidates, no_fit_quic_sender) =
        delivery_candidates(peer, &envelope, choices, selection.max_frame_bytes);
    prefer_best_effort_datagram_paths(peer, &mut delivery_candidates, &envelope, selection.routing);
    let voice_decision = if sticky_voice {
        let snapshot = peer.metrics().snapshot_per_transport();
        let mut path_pressures = HashMap::new();
        let mut path_transports = Vec::new();
        for candidate in &delivery_candidates {
            let transport = candidate.path.transport();
            let pressure = delivery_candidate_lane_penalty(candidate, &envelope, &snapshot, now);
            path_pressures
                .entry(transport)
                .and_modify(|existing: &mut u8| *existing = (*existing).min(pressure))
                .or_insert(pressure);
            if !path_transports.contains(&transport) {
                path_transports.push(transport);
            }
        }
        let decision = apply_voice_transport_stickiness_with_pressure(
            peer,
            &mut path_transports,
            envelope.level(),
            envelope.routing_metric(),
            envelope.class(),
            envelope.options(),
            selection.routing,
            now,
            Some(&path_pressures),
            true,
        );
        delivery_candidates.sort_by_key(|candidate| {
            (
                delivery_candidate_tier(candidate),
                path_transports
                    .iter()
                    .position(|transport| *transport == candidate.path.transport())
                    .unwrap_or(usize::MAX),
            )
        });
        decision
    } else {
        None
    };

    let prevent_stream_fallback_after_datagram_failure =
        envelope.level() == ServiceLevel::BestEffort;
    let mut datagram_enqueue_failed = false;
    let mut incumbent_failure = voice_decision.and_then(|decision| {
        let incumbent = decision.incumbent()?;
        if !attempted_transports.contains(&incumbent) {
            return None;
        }
        let sender_still_available = delivery_candidates
            .iter()
            .any(|candidate| candidate.path.transport() == incumbent);
        (!sender_still_available).then_some(VoiceTransportBindingEventReason::TransportUnavailable)
    });
    for candidate in delivery_candidates {
        let path = candidate.path;
        if !delivery_candidate_allowed_after_datagram_failure(
            path,
            prevent_stream_fallback_after_datagram_failure,
            datagram_enqueue_failed,
        ) {
            break;
        }
        let transport = path.transport();
        let options = envelope.options();
        if options.is_expired() {
            peer.record_expired_outbound_drop(
                ExpiredOutboundDropStage::PeerQueueDispatch,
                Some(transport),
                class,
            );
            return Ok(());
        }
        let sender = candidate.sender;
        let level = envelope.level();
        let quic_v2 = candidate.quic_v2;
        let variant = envelope.payloads().variant_for_session(transport, quic_v2);
        let quic_v2_datagram = path == DeliveryPath::QuicDatagram;
        let stream_path = !path.is_datagram();
        if quic_v2_datagram {
            for sidecar in variant.sidecars() {
                record_datagram_enqueue_result(
                    peer,
                    &sender,
                    sender.try_send_for_path(
                        path,
                        OutboundFrame::with_options(level, class, sidecar.clone(), options),
                    ),
                );
            }
        }
        let frame = OutboundFrame::from_variant(level, class, variant, options);
        if class == MessageClass::Regular
            && level != ServiceLevel::BestEffort
            && !allow_regular_backlog
            && options.expires_at().is_none()
            && !quic_v2
            && sender.depth_capacity_for_path(path, level, class).0 > 0
        {
            // Legacy streams share one FIFO across classes. Stage one Regular
            // frame at a time so late Control and HighPriority frames can pass.
            continue;
        }
        if stream_path {
            record_outbound_stream_queue_sample(peer, path, class, &sender, level, false);
        }
        match sender.try_send_for_path(path, frame) {
            Ok(outcome) => {
                if outcome.dropped_expired() {
                    return Ok(());
                }
                if quic_v2_datagram {
                    record_quic_datagram_evidence(
                        peer,
                        &sender,
                        DatagramPathEvidenceEvent::EnqueueAccepted,
                    );
                }
                if outcome.evicted_items() > 0 {
                    if quic_v2_datagram {
                        for _ in 0..outcome.evicted_items() {
                            sender.record_quic_datagram_drop();
                            super::metrics::record_quic_datagram_drop(
                                super::metrics::QuicDatagramDropReason::AppQueueEvicted,
                            );
                            record_quic_datagram_evidence(
                                peer,
                                &sender,
                                DatagramPathEvidenceEvent::Pressure,
                            );
                        }
                    } else if path == DeliveryPath::UdpDatagram {
                        // UDP evicts the oldest datagram to admit the newest.
                        // Record the generic queue-full watermark rather than
                        // the QUIC-named drop counter.
                        record_outbound_stream_queue_sample(peer, path, class, &sender, level, true);
                    }
                }
                for sidecar in variant.sidecars().iter().filter(|_| !quic_v2_datagram) {
                    let sidecar_outcome = sender.try_send_for_path(
                        path,
                        OutboundFrame::with_options(level, class, sidecar.clone(), options),
                    );
                    if let Ok(outcome) = sidecar_outcome {
                        if outcome.evicted_items() > 0 && path == DeliveryPath::UdpDatagram {
                            record_outbound_stream_queue_sample(peer, path, class, &sender, level, true);
                        }
                    }
                }
                if stream_path {
                    record_outbound_stream_queue_sample(peer, path, class, &sender, level, false);
                }
                record_delivery_path_selection(path);
                trace!(
                    peer = %peer.node_id(),
                    delivery_path = path.name(),
                    ?level,
                    ?class,
                    "selected outbound delivery path"
                );
                if let Some(decision) = voice_decision {
                    let selected_pressure =
                        deadline_queue_penalty(peer, transport, level, class, options, now);
                    let incumbent_pressure = decision.incumbent().map(|incumbent| {
                        deadline_queue_penalty(peer, incumbent, level, class, options, now)
                    });
                    peer.record_voice_transport_success(
                        transport,
                        now,
                        decision.reason(),
                        incumbent_failure,
                        Some(selected_pressure),
                        incumbent_pressure,
                    );
                }
                return Ok(());
            }
            Err(SessionTrySendError::TooLarge) => {
                if path.is_datagram() {
                    datagram_enqueue_failed = true;
                }
                if quic_v2_datagram {
                    record_quic_datagram_evidence(
                        peer,
                        &sender,
                        DatagramPathEvidenceEvent::TooLarge,
                    );
                    sender.record_quic_datagram_drop();
                    super::metrics::record_quic_datagram_drop(
                        super::metrics::QuicDatagramDropReason::TooLarge,
                    );
                }
                if stream_path {
                    record_outbound_stream_queue_sample(peer, path, class, &sender, level, true);
                }
                if voice_decision.is_some_and(|decision| decision.incumbent() == Some(transport)) {
                    incumbent_failure = Some(VoiceTransportBindingEventReason::QueueFull);
                }
            }
            Err(SessionTrySendError::Full) => {
                if path.is_datagram() {
                    datagram_enqueue_failed = true;
                }
                if quic_v2_datagram {
                    record_quic_datagram_evidence(
                        peer,
                        &sender,
                        DatagramPathEvidenceEvent::EnqueueRejected,
                    );
                }
                if stream_path {
                    record_outbound_stream_queue_sample(peer, path, class, &sender, level, true);
                }
                if voice_decision.is_some_and(|decision| decision.incumbent() == Some(transport)) {
                    incumbent_failure = Some(VoiceTransportBindingEventReason::QueueFull);
                }
            }
            Err(SessionTrySendError::Closed) => {
                if path.is_datagram() {
                    datagram_enqueue_failed = true;
                }
                if quic_v2_datagram {
                    record_quic_datagram_evidence(
                        peer,
                        &sender,
                        DatagramPathEvidenceEvent::EnqueueRejected,
                    );
                }
                if voice_decision.is_some_and(|decision| decision.incumbent() == Some(transport)) {
                    incumbent_failure = Some(VoiceTransportBindingEventReason::StreamClosed);
                }
            }
            Err(SessionTrySendError::UnsupportedPath) => {
                debug_assert!(
                    path == DeliveryPath::QuicStream && level == ServiceLevel::BestEffort,
                    "only strict QUIC v2 BestEffort stream delivery is unsupported"
                );
            }
        }
    }

    if sticky_voice {
        record_voice_transport_no_alternate(
            peer,
            envelope.level(),
            envelope.routing_metric(),
            class,
            envelope.options(),
            now,
        );
    }
    if envelope.level() == ServiceLevel::BestEffort {
        if let Some(sender) = no_fit_quic_sender {
            sender.record_quic_datagram_drop();
            super::metrics::record_quic_datagram_drop(
                super::metrics::QuicDatagramDropReason::NoFit,
            );
        }
        return Ok(());
    }
    Err(envelope)
}

fn record_datagram_enqueue_result(
    peer: &PeerState,
    sender: &SessionSender,
    result: Result<super::connection::SessionSendOutcome, SessionTrySendError>,
) {
    match result {
        Ok(outcome) => {
            if !outcome.dropped_expired() {
                record_quic_datagram_evidence(
                    peer,
                    sender,
                    DatagramPathEvidenceEvent::EnqueueAccepted,
                );
            }
            for _ in 0..outcome.evicted_items() {
                sender.record_quic_datagram_drop();
                super::metrics::record_quic_datagram_drop(
                    super::metrics::QuicDatagramDropReason::AppQueueEvicted,
                );
                record_quic_datagram_evidence(peer, sender, DatagramPathEvidenceEvent::Pressure);
            }
        }
        Err(SessionTrySendError::TooLarge) => {
            record_quic_datagram_evidence(peer, sender, DatagramPathEvidenceEvent::TooLarge);
            sender.record_quic_datagram_drop();
            super::metrics::record_quic_datagram_drop(
                super::metrics::QuicDatagramDropReason::TooLarge,
            );
        }
        Err(SessionTrySendError::Closed) | Err(SessionTrySendError::Full) => {
            record_quic_datagram_evidence(peer, sender, DatagramPathEvidenceEvent::EnqueueRejected);
        }
        // This helper only submits QUIC DATAGRAM paths. Keep the impossible
        // sender-side stream rejection exhaustive without altering evidence.
        Err(SessionTrySendError::UnsupportedPath) => {}
    }
}

fn record_quic_datagram_evidence(
    peer: &PeerState,
    sender: &SessionSender,
    event: DatagramPathEvidenceEvent,
) {
    let Some(session) = sender.quic_v2_datagram_evidence_session() else {
        return;
    };
    peer.metrics().record_datagram_path_evidence_for_session(
        DeliveryPath::QuicDatagram,
        session,
        event,
    );
}

fn quic_datagram_variant_fits(
    peer: NodeIdentifier,
    class: MessageClass,
    variant: &super::connection::TransportPayloadVariant,
    max_datagram_size: usize,
    max_frame_bytes: usize,
) -> bool {
    let fits = |payload: &Bytes| {
        let encoded_len = encoded_data_frame_len(
            u16::MAX,
            peer,
            ServiceLevel::BestEffort,
            class,
            transport_timestamp_us(),
            payload.len(),
        );
        encoded_len <= max_datagram_size && encoded_len <= max_frame_bytes
    };
    fits(variant.primary()) && variant.sidecars().iter().all(fits)
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
        TransportKind::Tcp => 2,
        TransportKind::Quic => 1,
        TransportKind::Kcp => 3,
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
    path: DeliveryPath,
    class: MessageClass,
    sender: &SessionSender,
    level: ServiceLevel,
    is_full: bool,
) {
    let transport = path.transport();
    let (depth, max_capacity) = sender.depth_capacity_for_path(path, level, class);
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
            cfg.quic_datagram_send_buffer_bytes(),
            cfg.quic_datagram_receive_buffer_bytes(),
            cfg.quic_alpn_protocols_override(),
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
    use super::super::connection::{
        ActiveStream, QuicV2SessionReceivers, QuicV2SessionSender, TransportPayloadVariant,
    };
    use super::*;
    use futures_util::FutureExt as _;

    #[tokio::test]
    async fn direct_config_rejects_undersized_enabled_quic_datagram_buffers() {
        let cfg = TransportConfig::new(
            "missing-ca".into(),
            "missing-cert".into(),
            "missing-key".into(),
        )
        .with_quic_datagram_send_buffer_bytes(1199);
        let error = match ConnectionManager::start(cfg).await {
            Ok(_) => panic!("undersized QUIC DATAGRAM buffer must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            TransportError::Config(ConfigError::InvalidQuicDatagramBuffer {
                name: "quic_datagram_send_buffer_bytes",
                bytes: 1199,
            })
        ));
    }

    #[test]
    fn active_best_effort_datagram_lane_health_prefers_udp_and_detects_full_block() {
        use crate::testing::datagram_path_health_snapshot;

        let snapshot = |path, state, loss| {
            datagram_path_health_snapshot(2, path, state, loss, if loss.is_some() { 40 } else { 0 })
        };
        // Healthy UDP beats a lossy QUIC fallback (UDP is the preferred lane).
        let health = active_best_effort_datagram_lane_health(&[
            snapshot(DeliveryPath::QuicDatagram, DatagramPathHealthState::Suspect, Some(80_000)),
            snapshot(DeliveryPath::UdpDatagram, DatagramPathHealthState::Healthy, Some(5_000)),
        ]);
        assert!(!health.blocked, "healthy UDP lane is not blocked");
        assert_eq!(health.loss_ppm, Some(5_000), "active lane is UDP");
        assert_eq!(health.loss_samples, 40);
        // A blocked UDP falls back to the QUIC datagram lane's loss.
        let health = active_best_effort_datagram_lane_health(&[
            snapshot(DeliveryPath::UdpDatagram, DatagramPathHealthState::Blocked, Some(200_000)),
            snapshot(DeliveryPath::QuicDatagram, DatagramPathHealthState::Suspect, Some(9_000)),
        ]);
        assert!(!health.blocked, "QUIC datagram fallback is usable");
        assert_eq!(health.loss_ppm, Some(9_000), "active lane falls back to QUIC");
        // All observed datagram lanes blocked -> hard Blocked signal.
        let health = active_best_effort_datagram_lane_health(&[
            snapshot(DeliveryPath::UdpDatagram, DatagramPathHealthState::Blocked, Some(200_000)),
            snapshot(DeliveryPath::QuicDatagram, DatagramPathHealthState::Blocked, Some(250_000)),
        ]);
        assert!(health.blocked, "every datagram lane Blocked");
        assert_eq!(health.loss_ppm, None, "no usable lane to read loss from");
        // The only observed datagram lane is blocked and there is no observed
        // fallback (QUIC datagram not established) — voice has no datagram path.
        let health = active_best_effort_datagram_lane_health(&[
            snapshot(DeliveryPath::UdpDatagram, DatagramPathHealthState::Blocked, Some(200_000)),
        ]);
        assert!(health.blocked, "only observed lane blocked and no fallback observed");
        assert_eq!(health.loss_ppm, None, "no fallback lane");
        // Absence of any datagram observation is not a Blocked lane.
        let health = active_best_effort_datagram_lane_health(&[]);
        assert!(!health.blocked, "no observation is not Blocked");
        assert_eq!(health.loss_ppm, None);
    }
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
    async fn live_quic_v1_status_reports_legacy_protocol_without_lanes() {
        let (manager, _receivers) =
            ConnectionManager::test_with_live_streams(1, 2, &[TransportKind::Quic]);

        let sessions = manager.quic_session_status();
        assert_eq!(sessions.len(), 1);
        let session = &sessions[0];
        assert_eq!(session.peer(), 2);
        assert_eq!(session.protocol(), super::super::QuicSessionProtocol::S2s1);
        assert!(!session.three_lane_ready());
        assert_eq!(session.max_datagram_size(), None);
        assert_eq!(session.datagram_send_buffer_bytes(), 65_536);
        assert_eq!(session.datagram_receive_buffer_bytes(), 262_144);
        assert_eq!(session.datagrams_queued(), 0);
        assert_eq!(session.datagrams_received(), 0);
        assert_eq!(session.datagrams_dropped(), 0);
    }

    fn install_test_stream(
        peer: &PeerState,
        kind: TransportKind,
        queue_bytes: usize,
    ) -> AdaptiveQueueReceiver<OutboundFrame> {
        install_test_stream_at(peer, kind, queue_bytes, None)
    }

    fn install_test_stream_at(
        peer: &PeerState,
        kind: TransportKind,
        queue_bytes: usize,
        remote_addr: Option<SocketAddr>,
    ) -> AdaptiveQueueReceiver<OutboundFrame> {
        let (tx, rx) = test_outbound_queue_with_bytes(queue_bytes);
        peer.install_stream(ActiveStream::new(
            kind,
            remote_addr,
            tx,
            CancellationToken::new(),
            false,
        ));
        rx
    }

    fn install_test_quic_v2(
        peer: &PeerState,
        remote_addr: SocketAddr,
        max_datagram_size: usize,
    ) -> QuicV2SessionReceivers {
        let (sender, receivers) =
            QuicV2SessionSender::new(1024 * 1024, 64 * 1024, 256 * 1024, max_datagram_size);
        peer.install_stream(ActiveStream::new_quic_v2(
            Some(remote_addr),
            sender,
            CancellationToken::new(),
            false,
        ));
        receivers
    }

    fn expiring_voice(payload: &'static [u8]) -> OutboundEnvelope {
        OutboundEnvelope::routed(
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            Bytes::from_static(payload),
            SendOptions::default().expire_after(Duration::from_secs(2)),
        )
    }

    fn fill_stream_queue(peer: &PeerState, kind: TransportKind, bytes: usize) {
        let sender = peer.try_get_stream(kind).expect("live stream");
        sender
            .try_send(OutboundFrame::new(
                ServiceLevel::Reliable,
                MessageClass::Regular,
                Bytes::from(vec![0; bytes]),
            ))
            .expect("stream queue should accept test payload");
    }

    fn fill_peer_dispatch_queue(peer: &PeerState, bytes: usize) {
        peer.outbound_sender()
            .try_send(OutboundEnvelope::routed(
                ServiceLevel::Reliable,
                RoutingMetric::ReliableCost,
                MessageClass::Control,
                Bytes::from(vec![0; bytes]),
                SendOptions::default(),
            ))
            .expect("peer dispatch queue should accept test payload");
    }

    #[test]
    fn same_kind_queue_status_tracks_newest_stream_used_for_send() {
        let peer = PeerState::new(
            2,
            Duration::from_millis(10),
            Duration::from_secs(60),
            MetricsTuning::default(),
            1024 * 1024,
        );
        let (old_tx, mut old_rx) = test_outbound_queue(1);
        old_tx
            .try_send(OutboundFrame::new(
                ServiceLevel::Reliable,
                MessageClass::Regular,
                Bytes::from(vec![0; 64 * 1024]),
            ))
            .expect("old stream queue should accept test payload");
        peer.install_stream(ActiveStream::new(
            TransportKind::Tcp,
            Some(socket("127.0.0.1:41001")),
            old_tx,
            CancellationToken::new(),
            false,
        ));

        std::thread::sleep(Duration::from_millis(1));
        let (new_tx, mut new_rx) = test_outbound_queue(1);
        peer.install_stream(ActiveStream::new(
            TransportKind::Tcp,
            Some(socket("127.0.0.1:41002")),
            new_tx,
            CancellationToken::new(),
            false,
        ));

        let status = peer
            .outbound_stream_queue_status(TransportKind::Tcp)
            .expect("TCP queue status");
        assert_eq!(status.depth(), 0, "status must describe the newest stream");

        peer.try_get_stream(TransportKind::Tcp)
            .expect("newest TCP stream")
            .try_send(OutboundFrame::new(
                ServiceLevel::Reliable,
                MessageClass::Regular,
                Bytes::from_static(b"newest"),
            ))
            .expect("newest stream should accept payload");
        assert_eq!(
            old_rx.try_recv().expect("old backlog").payload().len(),
            64 * 1024
        );
        assert!(old_rx.try_recv().is_err());
        assert_eq!(
            new_rx.try_recv().expect("new stream payload").payload(),
            &Bytes::from_static(b"newest")
        );
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
    fn legacy_regular_staging_deferral_is_not_reported_as_queue_full() {
        let (peer, mut receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        fill_stream_queue(&peer, TransportKind::Tcp, 300);

        let deferred = try_dispatch_envelope(
            &peer,
            OutboundEnvelope::fixed_transport(
                TransportKind::Tcp,
                MessageClass::Regular,
                Bytes::from_static(b"next regular"),
                SendOptions::default(),
            ),
            TransportRoutingPolicy::default(),
        );

        assert!(
            deferred.is_err(),
            "legacy Regular staging should stay shallow"
        );
        assert_eq!(receivers[0].try_recv().unwrap().payload().len(), 300);
        assert!(receivers[0].try_recv().is_err());
        assert_eq!(
            peer.outbound_stream_queue_status(TransportKind::Tcp)
                .unwrap()
                .full_samples(),
            0,
            "a scheduling deferral is not queue exhaustion"
        );
    }

    #[test]
    fn quic_v2_regular_lane_admits_backlog_until_actual_capacity() {
        let peer = PeerState::new(
            2,
            Duration::from_millis(10),
            Duration::from_secs(60),
            MetricsTuning::default(),
            1024 * 1024,
        );
        let (_control, _high, mut regular, _datagram) =
            install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1400).into_parts();
        fill_stream_queue(&peer, TransportKind::Quic, 300);

        try_dispatch_envelope(
            &peer,
            OutboundEnvelope::fixed_transport(
                TransportKind::Quic,
                MessageClass::Regular,
                Bytes::from_static(b"next regular"),
                SendOptions::default(),
            ),
            TransportRoutingPolicy::default(),
        )
        .expect("a partially occupied QUIC v2 Regular lane should remain admissible");

        assert_eq!(regular.try_recv().unwrap().payload().len(), 300);
        assert_eq!(
            regular.try_recv().unwrap().payload(),
            b"next regular".as_slice()
        );
        assert_eq!(
            peer.outbound_stream_queue_status(TransportKind::Quic)
                .unwrap()
                .full_samples(),
            0
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
    async fn forget_node_releases_queued_capacity_and_allows_fresh_peer() {
        let (transport, mut receivers) = ConnectionManager::test_with_live_streams_bytes(
            1,
            2,
            &[TransportKind::Tcp],
            1024 * 1024,
        );
        let retired_peer = transport.inner.get_peer(2).expect("peer");

        transport
            .try_send(
                2,
                ServiceLevel::Reliable,
                None,
                MessageClass::Regular,
                Bytes::from(vec![1; 1024 * 1024 - 512]),
            )
            .await
            .expect("fill stream handoff");
        tokio::time::timeout(Duration::from_secs(1), async {
            while retired_peer.outbound_queue_depth_bytes() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first envelope should reach the stream handoff");
        transport
            .try_send(
                2,
                ServiceLevel::Reliable,
                None,
                MessageClass::Regular,
                Bytes::from_static(b"held by dispatcher"),
            )
            .await
            .expect("queue behind full stream handoff");

        tokio::time::timeout(Duration::from_secs(1), async {
            while retired_peer.outbound_queue_depth_bytes() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dispatcher should retain the blocked envelope");

        transport.forget_node(2).await;
        assert!(
            !transport.inner.shutdown().is_cancelled(),
            "peer retirement must not start manager shutdown"
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            while retired_peer.outbound_queue_depth_bytes() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retiring the peer should release queued capacity");

        assert!(receivers[0].recv().await.is_some());
        assert!(
            receivers[0].recv().await.is_none(),
            "stream sender must close"
        );

        let mut fresh_receiver = transport.test_install_live_stream(2, TransportKind::Tcp);
        let fresh_peer = transport.inner.get_peer(2).expect("fresh peer");
        assert!(!Arc::ptr_eq(&retired_peer, &fresh_peer));
        transport
            .try_send(
                2,
                ServiceLevel::Reliable,
                None,
                MessageClass::Regular,
                Bytes::from_static(b"fresh"),
            )
            .await
            .expect("fresh peer accepts traffic");
        assert_eq!(
            &tokio::time::timeout(Duration::from_secs(1), fresh_receiver.recv())
                .await
                .expect("fresh dispatch timeout")
                .expect("fresh stream closed")
                .payload()[..],
            b"fresh"
        );
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
                ServiceLevel::Reliable,
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
                ServiceLevel::Reliable,
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
                ServiceLevel::Reliable,
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

    #[tokio::test]
    async fn selected_live_transport_metrics_requires_a_snapshot_entry() {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(1, 2, &[TransportKind::Tcp]);

        assert!(
            transport
                .selected_live_transport_metrics(
                    3,
                    ServiceLevel::BestEffort,
                    RoutingMetric::ConversationalQuality,
                )
                .is_none()
        );
        assert!(
            transport
                .selected_live_transport_metrics(
                    2,
                    ServiceLevel::BestEffort,
                    RoutingMetric::ConversationalQuality,
                )
                .is_none(),
            "an unmeasured fallback must not fabricate link metrics"
        );

        let peer = transport.inner.get_peer(2).expect("peer");
        peer.metrics().record_payload_sent(TransportKind::Tcp, 128);
        peer.metrics().record_probe_lost(TransportKind::Tcp);
        let (selected, link) = transport
            .selected_live_transport_metrics(
                2,
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
            )
            .expect("partial metrics for the selected fallback");
        assert_eq!(selected, TransportKind::Tcp);
        assert_eq!(link.samples(), 0, "the fallback remains unranked");
        assert_eq!(link.sent_bytes(), 128);
        assert_eq!(link.probe_packets(), 1);
    }

    #[tokio::test]
    async fn selected_live_transport_metrics_returns_the_selected_snapshot_value() {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(1, 2, &[TransportKind::Tcp]);
        transport.record_peer_rtt(2, TransportKind::Tcp, Duration::from_millis(37));
        let peer = transport.inner.get_peer(2).expect("peer");
        peer.metrics().reset_snapshot_count();

        let (selected, link) = transport
            .selected_live_transport_metrics(
                2,
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
            )
            .expect("measured live transport");

        assert_eq!(selected, TransportKind::Tcp);
        assert_eq!(link.rtt_us(), 37_000.0);
        assert_eq!(link.samples(), 1);
        assert_eq!(
            peer.metrics().snapshot_count(),
            1,
            "selection and returned metrics must share one peer snapshot"
        );
    }

    #[tokio::test]
    async fn conversational_path_pressure_promotes_confident_datagram_loss() {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(1, 2, &[TransportKind::Udp]);
        transport.record_peer_rtt(2, TransportKind::Udp, Duration::from_millis(40));
        let peer = transport.inner.get_peer(2).expect("peer");
        let policy = transport.routing_policy();
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics()
                .record_native_loss_sample(TransportKind::Udp, 1_000, 10);
        }

        assert_eq!(
            transport.best_conversational_path_pressure(
                2,
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
                MessageClass::HighPriority,
                SendOptions::default(),
            ),
            Some(2),
            "sustained datagram loss must expose a clean relay candidate"
        );

        assert!(peer.observe_conversational_transport_loss(
            TransportKind::Udp,
            Some(2_000),
            policy.conversational_path_effective_loss_suspect_ppm(),
            policy.conversational_path_effective_loss_recover_ppm(),
        ));
        assert!(!peer.observe_conversational_transport_loss(
            TransportKind::Udp,
            Some(1_400),
            policy.conversational_path_effective_loss_suspect_ppm(),
            policy.conversational_path_effective_loss_recover_ppm(),
        ));

        let (reliable_transport, _receivers) =
            ConnectionManager::test_with_live_streams(1, 2, &[TransportKind::Tcp]);
        reliable_transport.record_peer_rtt(2, TransportKind::Tcp, Duration::from_millis(40));
        let reliable_peer = reliable_transport.inner.get_peer(2).expect("peer");
        for _ in 0..policy.udp_family_min_samples() {
            reliable_peer
                .metrics()
                .record_native_loss_sample(TransportKind::Tcp, 1_000, 10);
        }
        assert_eq!(
            reliable_transport.best_conversational_path_pressure(
                2,
                ServiceLevel::Reliable,
                RoutingMetric::ConversationalQuality,
                MessageClass::Regular,
                SendOptions::default(),
            ),
            Some(2),
            "ConversationalQuality alone must enable the quality penalty"
        );
    }

    #[tokio::test]
    async fn receiver_playout_feedback_is_hysteretic_and_expires() {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(1, 2, &[TransportKind::Udp]);
        let peer = transport.inner.get_peer(2).expect("peer");
        let now = Instant::now();
        // Soft 250 ms cadence: one degraded report trips the suspect flag.
        peer.record_conversational_feedback(100, 2, 0, 0, now);
        assert!(peer.conversational_feedback_suspect(now));
        // One healthy report clears it.
        peer.record_conversational_feedback(100, 0, 0, 0, now);
        assert!(!peer.conversational_feedback_suspect(now));
        // A single deadline-flush frame degrades the route.
        peer.record_conversational_feedback(100, 0, 1, 0, now);
        assert!(peer.conversational_feedback_suspect(now));
        // A large held delay (Pillar D) is a UX symptom even with no flush:
        // the receiver is holding chunks late, which precedes a clip.
        peer.record_conversational_feedback(100, 0, 0, 500_000, now);
        assert!(peer.conversational_feedback_suspect(now));
        // A small held delay is healthy and clears the flag again.
        peer.record_conversational_feedback(100, 0, 0, 20_000, now);
        assert!(!peer.conversational_feedback_suspect(now));
        // The suspect flag expires when reports stop.
        peer.record_conversational_feedback(100, 0, 1, 0, now);
        assert!(peer.conversational_feedback_suspect(now));
        assert!(!peer.conversational_feedback_suspect(now + Duration::from_secs(6)));
    }

    #[tokio::test]
    async fn best_effort_sink_feedback_exposes_reported_gap_and_clears() {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(1, 2, &[TransportKind::Udp]);
        // No live feedback -> not suspect (absence of a report is not one).
        assert!(!transport.best_effort_sink_feedback(2).suspect);
        // A degraded report (gap-buffered >= 2% of received) trips the flag.
        transport.record_conversational_path_feedback(2, 100, 2, 0, 0);
        assert!(transport.best_effort_sink_feedback(2).suspect);
        // One healthy report clears it.
        transport.record_conversational_path_feedback(2, 100, 0, 0, 0);
        assert!(!transport.best_effort_sink_feedback(2).suspect);
        // Unknown peer -> default (not suspect).
        assert!(!transport.best_effort_sink_feedback(99).suspect);
    }

    #[tokio::test]
    async fn selected_live_transport_metrics_does_not_mutate_kcp_failaway_state() {
        let (transport, _receivers) = ConnectionManager::test_with_live_streams(
            1,
            2,
            &[TransportKind::Tcp, TransportKind::Kcp],
        );
        let peer = transport.inner.get_peer(2).expect("peer");
        transport.record_peer_rtt(2, TransportKind::Tcp, Duration::from_millis(40));
        fill_stream_queue(&peer, TransportKind::Kcp, 64 * 1024);
        age_zero_wire_metric(&peer, TransportKind::Kcp, Duration::from_millis(275));
        let exclusions_before = peer.transport_health_exclusion_status();

        let (selected, _) = transport
            .selected_live_transport_metrics(
                2,
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
            )
            .expect("healthy TCP observation");

        assert_eq!(selected, TransportKind::Tcp);
        assert!(!peer.kcp_best_effort_recovery_pending());
        assert_eq!(peer.transport_health_exclusion_status(), exclusions_before);

        assert_eq!(
            pick_transports(
                &peer,
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
                MessageClass::HighPriority,
                SendOptions::default(),
                0,
                TransportRoutingPolicy::default(),
            ),
            vec![TransportKind::Tcp],
            "the fixture must exercise a real active KCP failaway",
        );
        assert!(peer.kcp_best_effort_recovery_pending());
        assert!(
            peer.transport_health_exclusion_status()
                .iter()
                .any(|entry| {
                    entry.transport() == TransportKind::Kcp
                        && entry.reason() == TransportHealthExclusionReason::KcpFailaway
                })
        );
    }

    #[tokio::test]
    async fn global_metrics_snapshot_captures_each_peer_once() {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(1, 2, &[TransportKind::Tcp]);
        transport.test_install_live_stream(3, TransportKind::Udp);
        let peers = [
            transport.inner.get_peer(2).expect("peer 2"),
            transport.inner.get_peer(3).expect("peer 3"),
        ];
        for peer in &peers {
            peer.metrics().reset_snapshot_count();
        }
        transport.inner.reset_iter_peers_count();

        let snapshot = transport.metrics_snapshot();

        assert_eq!(transport.inner.iter_peers_count(), 1);
        assert!(snapshot.for_node(2).is_some());
        assert!(snapshot.for_node(3).is_some());
        for peer in peers {
            assert_eq!(peer.metrics().snapshot_count(), 1);
        }
    }

    #[tokio::test]
    async fn targeted_and_global_metrics_return_the_same_stable_link_values() {
        let window = Duration::from_millis(1);
        let (transport, _receivers) = ConnectionManager::test_with_live_streams_bandwidth_window(
            1,
            2,
            &[TransportKind::Tcp],
            window,
        );
        let peer = transport.inner.get_peer(2).expect("peer");
        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(37));
        peer.metrics().record_payload_sent(TransportKind::Tcp, 256);
        peer.metrics().record_probe_delivered(TransportKind::Tcp);
        tokio::time::sleep(Duration::from_millis(5)).await;

        let (_, targeted) = transport
            .selected_live_transport_metrics(
                2,
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
            )
            .expect("targeted metrics");
        let global_snapshot = transport.metrics_snapshot();
        let global = global_snapshot
            .for_node(2)
            .and_then(|links| links.get(&TransportKind::Tcp))
            .expect("global metrics");

        assert_eq!(targeted.rtt_us(), global.rtt_us());
        assert_eq!(targeted.jitter_us(), global.jitter_us());
        assert_eq!(targeted.sent_bytes(), global.sent_bytes());
        assert_eq!(targeted.recv_bytes(), global.recv_bytes());
        assert_eq!(targeted.wire_sent_bytes(), global.wire_sent_bytes());
        assert_eq!(targeted.wire_recv_bytes(), global.wire_recv_bytes());
        assert_eq!(targeted.window(), window);
        assert_eq!(targeted.window(), global.window());
        assert_eq!(
            targeted.throughput_confidence_ppm(),
            global.throughput_confidence_ppm()
        );
        assert_eq!(targeted.loss_breakdown(), global.loss_breakdown());
        assert_eq!(targeted.samples(), global.samples());
        assert_eq!(targeted.last_update(), global.last_update());
        assert_eq!(
            targeted.kcp_runtime().is_some(),
            global.kcp_runtime().is_some()
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

    #[tokio::test]
    async fn conversational_datagram_tier_precedes_slightly_better_streams() {
        let (peer, mut stream_receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        let (_control, _high, _regular, mut quic_datagram) =
            install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1400).into_parts();
        let policy = TransportRoutingPolicy::default();

        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(50));
        peer.metrics()
            .record_rtt(TransportKind::Kcp, Duration::from_millis(52));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(60));
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }
        let snapshot = peer.metrics().snapshot_per_transport();
        let tcp_cost = snapshot[&TransportKind::Tcp]
            .routing_cost(
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
            )
            .unwrap();
        let quic_cost = snapshot[&TransportKind::Quic]
            .routing_cost(
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
            )
            .unwrap();
        let material = 1.0 - (policy.transport_switch_improvement_pct() as f64 / 100.0);
        assert!(tcp_cost < quic_cost && tcp_cost > quic_cost * material);

        try_dispatch_envelope(&peer, expiring_voice(b"datagram-first"), policy).unwrap();

        assert_eq!(
            quic_datagram.recv().await.unwrap().payload(),
            b"datagram-first".as_slice()
        );
        assert!(stream_receivers.iter_mut().all(|rx| rx.try_recv().is_err()));
    }

    #[tokio::test]
    async fn non_expiring_conversational_route_uses_same_datagram_preference() {
        let (peer, mut stream_receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        let (_control, _high, _regular, mut quic_datagram) =
            install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1400).into_parts();
        let policy = TransportRoutingPolicy::default();

        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(50));
        peer.metrics()
            .record_rtt(TransportKind::Kcp, Duration::from_millis(52));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(60));
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }

        let envelope = OutboundEnvelope::routed(
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            Bytes::from_static(b"non-expiring-datagram"),
            SendOptions::default(),
        );
        try_dispatch_envelope(&peer, envelope, policy).unwrap();

        assert_eq!(
            quic_datagram.recv().await.unwrap().payload(),
            b"non-expiring-datagram".as_slice()
        );
        assert!(stream_receivers.iter_mut().all(|rx| rx.try_recv().is_err()));
    }

    #[tokio::test]
    async fn unhealthy_udp_does_not_suppress_healthy_quic_datagram_voice_path() {
        let (peer, mut stream_receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Udp]);
        let (_control, _high, _regular, mut quic_datagram) =
            install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1400).into_parts();
        let policy = TransportRoutingPolicy::default();

        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(50));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(60));
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }
        for _ in 0..policy
            .udp_family_min_samples()
            .max(u64::from(policy.udp_family_probe_loss_block_count()))
        {
            peer.metrics().record_probe_lost(TransportKind::Udp);
        }

        try_dispatch_envelope(&peer, expiring_voice(b"healthy-quic-datagram"), policy).unwrap();

        assert_eq!(
            quic_datagram.recv().await.unwrap().payload(),
            b"healthy-quic-datagram".as_slice()
        );
        assert!(stream_receivers.iter_mut().all(|rx| rx.try_recv().is_err()));
    }

    #[tokio::test]
    async fn probing_quic_datagram_precedes_measured_tcp_stream() {
        let (peer, mut stream_receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        let (_control, _high, _regular, mut quic_datagram) =
            install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1400).into_parts();
        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(10));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(100));

        try_dispatch_envelope(
            &peer,
            expiring_voice(b"probing-datagram"),
            TransportRoutingPolicy::default(),
        )
        .unwrap();

        assert_eq!(
            quic_datagram.recv().await.unwrap().payload(),
            b"probing-datagram".as_slice()
        );
        assert!(stream_receivers[0].try_recv().is_err());
    }

    #[test]
    fn datagram_health_hysteresis_is_delivery_path_specific() {
        let (peer, _receivers) = peer_with_live_transports(&[]);
        let now = Instant::now();

        assert_eq!(
            peer.observe_datagram_path_health(
                DeliveryPath::UdpDatagram,
                Some(6_000),
                32,
                32,
                false,
                false,
                5_000,
                2_500,
                250_000,
                now,
            ),
            DatagramPathHealthState::Suspect
        );
        assert_eq!(
            peer.observe_datagram_path_health(
                DeliveryPath::QuicDatagram,
                Some(1_000),
                32,
                32,
                false,
                false,
                5_000,
                2_500,
                250_000,
                now,
            ),
            DatagramPathHealthState::Healthy
        );
        assert_eq!(
            peer.observe_datagram_path_health(
                DeliveryPath::UdpDatagram,
                Some(4_000),
                64,
                32,
                false,
                false,
                5_000,
                2_500,
                250_000,
                now + Duration::from_secs(1),
            ),
            DatagramPathHealthState::Suspect,
            "the recovery threshold, not the enter threshold, releases a suspect path"
        );
        assert_eq!(
            peer.observe_datagram_path_health(
                DeliveryPath::UdpDatagram,
                Some(2_000),
                96,
                32,
                false,
                false,
                5_000,
                2_500,
                250_000,
                now + Duration::from_secs(2),
            ),
            DatagramPathHealthState::Healthy
        );

        let snapshots = peer.datagram_path_health_status(Duration::from_secs(10));
        let udp = snapshots
            .iter()
            .find(|snapshot| snapshot.path() == DeliveryPath::UdpDatagram)
            .unwrap();
        let quic = snapshots
            .iter()
            .find(|snapshot| snapshot.path() == DeliveryPath::QuicDatagram)
            .unwrap();
        assert_eq!(udp.state(), DatagramPathHealthState::Healthy);
        assert_eq!(udp.transitions(), 1);
        assert_eq!(quic.state(), DatagramPathHealthState::Healthy);
        assert_eq!(quic.transitions(), 0);
    }

    #[test]
    fn datagram_health_stale_samples_probe_and_removed_paths_are_pruned() {
        let (peer, _receivers) = peer_with_live_transports(&[]);
        let now = Instant::now();
        assert_eq!(
            peer.observe_datagram_path_health(
                DeliveryPath::UdpDatagram,
                Some(6_000),
                32,
                32,
                false,
                false,
                5_000,
                2_500,
                250_000,
                now,
            ),
            DatagramPathHealthState::Suspect
        );
        assert_eq!(
            peer.observe_datagram_path_health(
                DeliveryPath::UdpDatagram,
                None,
                0,
                32,
                false,
                false,
                5_000,
                2_500,
                250_000,
                now + Duration::from_secs(1),
            ),
            DatagramPathHealthState::Probing
        );
        let probing = peer.datagram_path_health_status(Duration::from_secs(10));
        assert_eq!(
            probing[0].reason(),
            super::super::metrics::DatagramPathHealthReason::InsufficientSamples
        );

        let (removed_peer, _receivers) = peer_with_live_transports(&[]);
        removed_peer.observe_datagram_path_health(
            DeliveryPath::QuicDatagram,
            Some(1_000),
            32,
            32,
            false,
            false,
            5_000,
            2_500,
            250_000,
            Instant::now() - Duration::from_secs(2),
        );
        assert!(
            removed_peer
                .datagram_path_health_status(Duration::from_secs(1))
                .is_empty()
        );
    }

    #[test]
    fn datagram_health_distinguishes_address_and_probe_failures() {
        let (peer, _receivers) = peer_with_live_transports(&[]);
        let now = Instant::now();
        peer.observe_datagram_path_health(
            DeliveryPath::UdpDatagram,
            None,
            0,
            32,
            true,
            false,
            5_000,
            2_500,
            250_000,
            now,
        );
        peer.observe_datagram_path_health(
            DeliveryPath::QuicDatagram,
            None,
            0,
            32,
            false,
            true,
            5_000,
            2_500,
            250_000,
            now,
        );
        let snapshots = peer.datagram_path_health_status(Duration::from_secs(10));
        assert_eq!(
            snapshots[0].reason(),
            super::super::metrics::DatagramPathHealthReason::AddressFailures
        );
        assert_eq!(
            snapshots[1].reason(),
            super::super::metrics::DatagramPathHealthReason::ProbeFailures
        );
    }

    #[tokio::test]
    async fn suspect_datagram_observation_does_not_change_selection() {
        let (peer, mut stream_receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        let (_control, _high, _regular, mut quic_datagram) =
            install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1400).into_parts();
        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(10));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(100));
        let policy = TransportRoutingPolicy::default();
        let start = Instant::now();
        for window in 0..policy.best_effort_datagram_suspect_bad_windows() {
            let event_at = start + Duration::from_secs(u64::from(window) * 2);
            for _ in 0..policy.udp_family_min_samples() {
                peer.metrics().record_datagram_path_evidence_at(
                    DeliveryPath::QuicDatagram,
                    DatagramPathEvidenceEvent::OutcomeFailure,
                    event_at,
                );
            }
            let now = event_at + Duration::from_millis(1_100);
            let snapshot = peer.metrics().snapshot_per_transport();
            let observed = observe_best_effort_datagram_path_health(
                &peer,
                DeliveryPath::QuicDatagram,
                &snapshot,
                policy,
                now,
            );
            let expected = if window + 1 >= policy.best_effort_datagram_suspect_bad_windows() {
                DatagramPathHealthState::Suspect
            } else {
                DatagramPathHealthState::Probing
            };
            let health = peer.datagram_path_health_status(Duration::from_secs(10));
            assert_eq!(observed, expected, "window {window}, health={health:?}");
        }

        try_dispatch_envelope(&peer, expiring_voice(b"shadow-suspect"), policy).unwrap();

        assert_eq!(
            quic_datagram.recv().await.unwrap().payload(),
            b"shadow-suspect".as_slice()
        );
        assert!(stream_receivers[0].try_recv().is_err());
        assert_eq!(
            peer.datagram_path_health_status(Duration::from_secs(10))[0].state(),
            DatagramPathHealthState::Suspect
        );
    }

    #[test]
    fn quic_datagram_shadow_observer_ignores_aggregate_quic_stream_loss() {
        let (peer, _receivers) = peer_with_live_transports(&[]);
        let policy = TransportRoutingPolicy::default();
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics()
                .record_native_loss_sample(TransportKind::Quic, 1_000_000, 1_200);
        }
        let snapshot = peer.metrics().snapshot_per_transport();
        assert_eq!(
            observe_best_effort_datagram_path_health(
                &peer,
                DeliveryPath::QuicDatagram,
                &snapshot,
                policy,
                Instant::now(),
            ),
            DatagramPathHealthState::Probing
        );
    }

    #[tokio::test]
    async fn stale_probe_streak_is_probing_in_shadow_health() {
        let (peer, mut stream_receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        let (_control, _high, _regular, quic_datagram) =
            install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1400).into_parts();
        let policy =
            TransportRoutingPolicy::default().with_transport_metric_stale_after(Duration::ZERO);
        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(10));
        for _ in 0..policy.udp_family_probe_loss_block_count() {
            peer.metrics().record_probe_lost(TransportKind::Quic);
        }

        try_dispatch_envelope(&peer, expiring_voice(b"stale-probe"), policy).unwrap();

        assert_eq!(
            stream_receivers[0].try_recv().unwrap().payload(),
            b"stale-probe".as_slice(),
            "the existing physical hard gate remains unchanged"
        );
        assert_eq!(quic_datagram.depth_bytes(), 0);
        let observations = peer.datagram_path_health_status(Duration::from_secs(10));
        assert_eq!(observations[0].state(), DatagramPathHealthState::Probing);
        assert_eq!(
            observations[0].reason(),
            super::super::metrics::DatagramPathHealthReason::InsufficientSamples
        );
    }

    #[test]
    fn failed_datagram_attempt_can_only_fall_through_to_another_datagram() {
        for path in [DeliveryPath::UdpDatagram, DeliveryPath::QuicDatagram] {
            assert!(delivery_candidate_allowed_after_datagram_failure(
                path, true, true
            ));
        }
        for path in [
            DeliveryPath::TcpStream,
            DeliveryPath::KcpStream,
            DeliveryPath::QuicStream,
        ] {
            assert!(!delivery_candidate_allowed_after_datagram_failure(
                path, true, true
            ));
            assert!(delivery_candidate_allowed_after_datagram_failure(
                path, false, true
            ));
            assert!(delivery_candidate_allowed_after_datagram_failure(
                path, true, false
            ));
        }
    }

    #[tokio::test]
    async fn blocked_quic_datagram_falls_back_to_tcp_stream() {
        let (peer, mut stream_receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        let (_control, mut quic_stream, _regular, quic_datagram) =
            install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1400).into_parts();
        let policy = TransportRoutingPolicy::default();
        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(10));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(100));
        for _ in 0..policy.udp_family_probe_loss_block_count() {
            peer.metrics().record_probe_lost(TransportKind::Quic);
        }

        try_dispatch_envelope(&peer, expiring_voice(b"tcp-fallback"), policy).unwrap();

        assert_eq!(
            stream_receivers[0].try_recv().unwrap().payload(),
            b"tcp-fallback".as_slice()
        );
        assert!(quic_stream.try_recv().is_err());
        assert_eq!(quic_datagram.depth_bytes(), 0);
    }

    #[tokio::test]
    async fn eligible_datagram_precedes_even_materially_better_streams() {
        let (peer, mut stream_receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        let (_control, _high, _regular, mut quic_datagram) =
            install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1400).into_parts();
        let policy = TransportRoutingPolicy::default();

        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(10));
        peer.metrics()
            .record_rtt(TransportKind::Kcp, Duration::from_millis(20));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_secs(2));
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }
        let snapshot = peer.metrics().snapshot_per_transport();
        let tcp_cost = snapshot[&TransportKind::Tcp]
            .routing_cost(
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
            )
            .unwrap();
        let quic_cost = snapshot[&TransportKind::Quic]
            .routing_cost(
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
            )
            .unwrap();
        let material = 1.0 - (policy.transport_switch_improvement_pct() as f64 / 100.0);
        assert!(tcp_cost <= quic_cost * material);

        try_dispatch_envelope(&peer, expiring_voice(b"datagram-first"), policy).unwrap();

        assert_eq!(
            quic_datagram.recv().await.unwrap().payload(),
            b"datagram-first".as_slice()
        );
        assert!(stream_receivers.iter_mut().all(|rx| rx.try_recv().is_err()));
    }

    #[test]
    fn all_best_effort_routes_put_udp_and_quic_datagram_before_streams() {
        let (peer, _stream_receivers) =
            peer_with_live_transports(&[TransportKind::Udp, TransportKind::Tcp]);
        let quic_receivers = install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1400);
        let policy = TransportRoutingPolicy::default();

        for (transport, rtt) in [
            (TransportKind::Udp, Duration::from_millis(50)),
            (TransportKind::Tcp, Duration::from_millis(55)),
            (TransportKind::Quic, Duration::from_millis(60)),
        ] {
            peer.metrics().record_rtt(transport, rtt);
        }
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Udp);
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }

        let envelope = OutboundEnvelope::routed(
            ServiceLevel::BestEffort,
            RoutingMetric::BestEffortCost,
            MessageClass::Regular,
            Bytes::from_static(b"tier-order"),
            SendOptions::default(),
        );
        let choices = vec![TransportKind::Udp, TransportKind::Tcp, TransportKind::Quic];
        let (mut candidates, _) = delivery_candidates(&peer, &envelope, choices, usize::MAX);
        prefer_best_effort_datagram_paths(&peer, &mut candidates, &envelope, policy);

        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.path)
                .collect::<Vec<_>>(),
            vec![
                DeliveryPath::UdpDatagram,
                DeliveryPath::QuicDatagram,
                DeliveryPath::TcpStream,
            ]
        );
        drop(quic_receivers);
    }

    #[tokio::test]
    async fn fitting_quic_datagram_is_not_masked_by_newer_legacy_quic() {
        let (peer, _receivers) = peer_with_live_transports(&[]);
        let (_control, _high, _regular, mut quic_datagram) =
            install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1400).into_parts();
        let mut legacy_quic = install_test_stream_at(
            &peer,
            TransportKind::Quic,
            1024 * 1024,
            Some(socket("127.0.0.2:64741")),
        );
        let policy = TransportRoutingPolicy::default();
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(60));
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }

        try_dispatch_envelope(&peer, expiring_voice(b"v2-not-masked"), policy).unwrap();

        assert_eq!(
            quic_datagram.recv().await.unwrap().payload(),
            b"v2-not-masked".as_slice()
        );
        assert!(legacy_quic.try_recv().is_err());
    }

    #[tokio::test]
    async fn datagram_preference_can_leave_stream_voice_binding_without_waiting_for_capacity() {
        let (peer, mut stream_receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        let policy = TransportRoutingPolicy::default();

        try_dispatch_envelope(&peer, expiring_voice(b"bind-stream"), policy).unwrap();
        assert_eq!(
            stream_receivers[0].try_recv().unwrap().payload(),
            b"bind-stream".as_slice()
        );
        assert_eq!(
            peer.voice_transport_binding_status().unwrap().transport(),
            TransportKind::Tcp
        );

        let (_control, _high, _regular, mut quic_datagram) =
            install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1400).into_parts();
        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(50));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(60));
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }

        try_dispatch_envelope(&peer, expiring_voice(b"prefer-datagram"), policy).unwrap();

        assert_eq!(
            quic_datagram.recv().await.unwrap().payload(),
            b"prefer-datagram".as_slice()
        );
        assert!(stream_receivers[0].try_recv().is_err());
        assert_eq!(
            peer.voice_transport_binding_status().unwrap().transport(),
            TransportKind::Quic
        );
    }

    #[tokio::test]
    async fn oversized_quic_datagram_falls_back_to_legacy_quic_stream() {
        let (peer, _receivers) = peer_with_live_transports(&[]);
        // Install legacy first so the newer v2 session would mask it through
        // the generic transport lookup. The legacy-only lookup must still
        // find the compatible fallback.
        let mut legacy_quic = install_test_stream_at(
            &peer,
            TransportKind::Quic,
            1024 * 1024,
            Some(socket("127.0.0.2:64741")),
        );
        let (_control, _high, _regular, quic_datagram) =
            install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1200).into_parts();

        let envelope = OutboundEnvelope::routed(
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            Bytes::from(vec![b'x'; 1200]),
            SendOptions::default(),
        );
        try_dispatch_envelope(&peer, envelope, TransportRoutingPolicy::default()).unwrap();

        assert_eq!(legacy_quic.try_recv().unwrap().payload().len(), 1200);
        assert_eq!(quic_datagram.depth_bytes(), 0);
    }

    #[test]
    fn oversized_quic_datagram_never_uses_quic_v2_reliable_stream() {
        let (peer, _receivers) = peer_with_live_transports(&[]);
        let (_control, mut high, _regular, quic_datagram) =
            install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1200).into_parts();

        let envelope = OutboundEnvelope::routed(
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            Bytes::from(vec![b'x'; 1200]),
            SendOptions::default().expire_after(Duration::from_millis(250)),
        );
        try_dispatch_envelope(&peer, envelope, TransportRoutingPolicy::default()).unwrap();

        assert!(high.try_recv().is_err());
        assert_eq!(quic_datagram.depth_bytes(), 0);
    }

    #[test]
    fn measured_cost_chooses_quic_or_tcp_within_reliable_fallback() {
        for (tcp_rtt, quic_rtt, expected) in [
            (10, 100, DeliveryPath::TcpStream),
            (100, 10, DeliveryPath::QuicStream),
        ] {
            let (peer, _receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
            let _quic_receiver = install_test_stream(&peer, TransportKind::Quic, 1024 * 1024);
            peer.metrics()
                .record_rtt(TransportKind::Tcp, Duration::from_millis(tcp_rtt));
            peer.metrics()
                .record_rtt(TransportKind::Quic, Duration::from_millis(quic_rtt));
            let envelope = expiring_voice(b"stream-choice");
            let choices = pick_transports(
                &peer,
                envelope.level(),
                envelope.routing_metric(),
                envelope.class(),
                envelope.options(),
                envelope.payload().len(),
                TransportRoutingPolicy::default(),
            );
            let (mut candidates, _) = delivery_candidates(&peer, &envelope, choices, usize::MAX);

            prefer_best_effort_datagram_paths(
                &peer,
                &mut candidates,
                &envelope,
                TransportRoutingPolicy::default(),
            );

            assert_eq!(candidates[0].path, expected);
        }
    }

    #[test]
    fn unmeasured_best_effort_orders_quic_then_tcp_then_kcp() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        let _quic_receiver = install_test_stream(&peer, TransportKind::Quic, 1024 * 1024);

        assert_eq!(
            pick_transports(
                &peer,
                ServiceLevel::BestEffort,
                RoutingMetric::BestEffortCost,
                MessageClass::Regular,
                SendOptions::default(),
                0,
                TransportRoutingPolicy::default(),
            ),
            vec![TransportKind::Quic, TransportKind::Tcp, TransportKind::Kcp]
        );
    }

    #[test]
    fn best_effort_penalizes_kcp_but_keeps_it_as_final_fallback() {
        let policy = TransportRoutingPolicy::default();
        let (peer, mut receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(50));
        peer.metrics()
            .record_rtt(TransportKind::Kcp, Duration::from_millis(45));
        let snapshot = peer.metrics().snapshot_per_transport();
        let raw_tcp = snapshot[&TransportKind::Tcp]
            .routing_cost(ServiceLevel::BestEffort, RoutingMetric::BestEffortCost)
            .unwrap();
        let raw_kcp = snapshot[&TransportKind::Kcp]
            .routing_cost(ServiceLevel::BestEffort, RoutingMetric::BestEffortCost)
            .unwrap();
        assert!(raw_kcp < raw_tcp);

        let envelope = OutboundEnvelope::routed(
            ServiceLevel::BestEffort,
            RoutingMetric::BestEffortCost,
            MessageClass::Regular,
            Bytes::from_static(b"avoid-kcp"),
            SendOptions::default(),
        );
        assert!(
            adjusted_routing_cost(
                TransportKind::Kcp,
                envelope.level(),
                envelope.routing_metric(),
                policy,
                &snapshot,
            ) > adjusted_routing_cost(
                TransportKind::Tcp,
                envelope.level(),
                envelope.routing_metric(),
                policy,
                &snapshot,
            )
        );
        try_dispatch_envelope(&peer, envelope, policy).unwrap();
        assert_eq!(
            receivers[0].try_recv().unwrap().payload(),
            b"avoid-kcp".as_slice()
        );
        assert!(receivers[1].try_recv().is_err());

        let (kcp_only, mut kcp_receiver) = peer_with_live_transports(&[TransportKind::Kcp]);
        let kcp_fallback = OutboundEnvelope::routed(
            ServiceLevel::BestEffort,
            RoutingMetric::BestEffortCost,
            MessageClass::Regular,
            Bytes::from_static(b"kcp-final"),
            SendOptions::default(),
        );
        try_dispatch_envelope(&kcp_only, kcp_fallback, policy).unwrap();
        assert_eq!(
            kcp_receiver[0].try_recv().unwrap().payload(),
            b"kcp-final".as_slice()
        );
    }

    #[test]
    fn adjusted_kcp_cost_drives_sticky_challenger_confirmation() {
        let policy = TransportRoutingPolicy::default();
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(42));
        peer.metrics()
            .record_rtt(TransportKind::Kcp, Duration::from_millis(40));
        let envelope = expiring_voice(b"sticky-cost");
        let started_at = Instant::now();

        let mut initial = vec![TransportKind::Kcp];
        let initial_decision = apply_voice_transport_stickiness(
            &peer,
            &mut initial,
            envelope.level(),
            envelope.routing_metric(),
            envelope.class(),
            envelope.options(),
            policy,
            started_at,
            true,
        )
        .unwrap();
        peer.record_voice_transport_success(
            TransportKind::Kcp,
            started_at,
            initial_decision.reason(),
            None,
            Some(0),
            None,
        );

        let ranked = || {
            pick_transports(
                &peer,
                envelope.level(),
                envelope.routing_metric(),
                envelope.class(),
                envelope.options(),
                envelope.payload().len(),
                policy,
            )
        };
        assert_eq!(ranked(), vec![TransportKind::Tcp, TransportKind::Kcp]);

        let challenger_started_at = started_at + policy.voice_path_min_hold();
        let mut held_choices = ranked();
        let held = apply_voice_transport_stickiness(
            &peer,
            &mut held_choices,
            envelope.level(),
            envelope.routing_metric(),
            envelope.class(),
            envelope.options(),
            policy,
            challenger_started_at,
            true,
        )
        .unwrap();
        assert_eq!(held.preferred(), TransportKind::Kcp);
        let (mut held_paths, _) = delivery_candidates(&peer, &envelope, held_choices, usize::MAX);
        prefer_best_effort_datagram_paths(&peer, &mut held_paths, &envelope, policy);
        assert_eq!(held_paths[0].path, DeliveryPath::KcpStream);

        let mut confirmed_choices = ranked();
        let confirmed = apply_voice_transport_stickiness(
            &peer,
            &mut confirmed_choices,
            envelope.level(),
            envelope.routing_metric(),
            envelope.class(),
            envelope.options(),
            policy,
            challenger_started_at + policy.voice_path_challenger_confirm(),
            true,
        )
        .unwrap();
        assert_eq!(confirmed.preferred(), TransportKind::Tcp);
        let (mut confirmed_paths, _) =
            delivery_candidates(&peer, &envelope, confirmed_choices, usize::MAX);
        prefer_best_effort_datagram_paths(&peer, &mut confirmed_paths, &envelope, policy);
        assert_eq!(confirmed_paths[0].path, DeliveryPath::TcpStream);
    }

    #[test]
    fn path_pressure_challenger_observes_sticky_confirmation() {
        let policy = TransportRoutingPolicy::default();
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Quic]);
        let envelope = expiring_voice(b"path-pressure");
        let started_at = Instant::now();
        peer.record_voice_transport_success(
            TransportKind::Tcp,
            started_at,
            VoiceTransportBindingEventReason::Initial,
            None,
            Some(0),
            None,
        );
        let pressures = HashMap::from([(TransportKind::Tcp, 2), (TransportKind::Quic, 0)]);
        let challenger_started_at = started_at + policy.voice_path_min_hold();

        let mut held = vec![TransportKind::Quic, TransportKind::Tcp];
        let held_decision = apply_voice_transport_stickiness_with_pressure(
            &peer,
            &mut held,
            envelope.level(),
            envelope.routing_metric(),
            envelope.class(),
            envelope.options(),
            policy,
            challenger_started_at,
            Some(&pressures),
            true,
        )
        .unwrap();
        assert_eq!(held_decision.preferred(), TransportKind::Tcp);
        assert_eq!(held[0], TransportKind::Tcp);

        let mut confirmed = vec![TransportKind::Quic, TransportKind::Tcp];
        let confirmed_decision = apply_voice_transport_stickiness_with_pressure(
            &peer,
            &mut confirmed,
            envelope.level(),
            envelope.routing_metric(),
            envelope.class(),
            envelope.options(),
            policy,
            challenger_started_at + policy.voice_path_challenger_confirm(),
            Some(&pressures),
            true,
        )
        .unwrap();
        assert_eq!(confirmed_decision.preferred(), TransportKind::Quic);
        assert_eq!(confirmed[0], TransportKind::Quic);
    }

    #[test]
    fn kcp_cost_penalty_does_not_change_reliable_ranking() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(50));
        peer.metrics()
            .record_rtt(TransportKind::Kcp, Duration::from_millis(10));

        let snapshot = peer.metrics().snapshot_per_transport();
        let raw = snapshot[&TransportKind::Kcp]
            .routing_cost(
                ServiceLevel::Reliable,
                RoutingMetric::ReliableLowLatencyCost,
            )
            .unwrap();
        assert_eq!(
            adjusted_routing_cost(
                TransportKind::Kcp,
                ServiceLevel::Reliable,
                RoutingMetric::ReliableLowLatencyCost,
                TransportRoutingPolicy::default(),
                &snapshot,
            ),
            raw
        );
    }

    #[test]
    fn non_expiring_best_effort_dispatch_applies_kcp_penalty() {
        let (peer, mut receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(50));
        peer.metrics()
            .record_rtt(TransportKind::Kcp, Duration::from_millis(45));
        let envelope = OutboundEnvelope::routed(
            ServiceLevel::BestEffort,
            RoutingMetric::BestEffortCost,
            MessageClass::Regular,
            Bytes::from_static(b"non-expiring-kcp"),
            SendOptions::default(),
        );

        try_dispatch_envelope(&peer, envelope, TransportRoutingPolicy::default()).unwrap();

        assert_eq!(
            receivers[0].try_recv().unwrap().payload(),
            b"non-expiring-kcp".as_slice()
        );
        assert!(receivers[1].try_recv().is_err());
    }

    #[test]
    fn blocked_quic_v2_datagram_falls_through_to_kcp() {
        let (peer, mut kcp_receiver) = peer_with_live_transports(&[TransportKind::Kcp]);
        let (_control, mut quic_high, _regular, quic_datagram) =
            install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1200).into_parts();
        for _ in 0..TransportRoutingPolicy::default().udp_family_probe_loss_block_count() {
            peer.metrics().record_probe_lost(TransportKind::Quic);
        }
        let envelope = OutboundEnvelope::routed(
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            Bytes::from_static(b"kcp-after-quic"),
            SendOptions::default().expire_after(Duration::from_millis(250)),
        );

        try_dispatch_envelope(&peer, envelope, TransportRoutingPolicy::default()).unwrap();

        assert_eq!(
            kcp_receiver[0].try_recv().unwrap().payload(),
            b"kcp-after-quic".as_slice()
        );
        assert!(quic_high.try_recv().is_err());
        assert_eq!(quic_datagram.depth_bytes(), 0);
    }

    #[tokio::test]
    async fn backlogged_legacy_quic_stream_cannot_displace_udp_when_datagram_does_not_fit() {
        let (peer, mut udp_receivers) = peer_with_live_transports(&[TransportKind::Udp]);
        let (_control, _high, _regular, quic_datagram) =
            install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1200).into_parts();
        let mut legacy_quic = install_test_stream_at(
            &peer,
            TransportKind::Quic,
            1024 * 1024,
            Some(socket("127.0.0.2:64741")),
        );
        let policy = TransportRoutingPolicy::default();

        peer.metrics()
            .record_rtt(TransportKind::Udp, Duration::from_secs(2));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(10));
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Udp);
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }
        let snapshot = peer.metrics().snapshot_per_transport();
        let udp_cost = snapshot[&TransportKind::Udp]
            .routing_cost(
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
            )
            .unwrap();
        let quic_cost = snapshot[&TransportKind::Quic]
            .routing_cost(
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
            )
            .unwrap();
        let material = 1.0 - (policy.transport_switch_improvement_pct() as f64 / 100.0);
        assert!(quic_cost <= udp_cost * material);

        peer.try_get_stream(TransportKind::Quic)
            .expect("legacy QUIC stream")
            .try_send(OutboundFrame::new(
                ServiceLevel::Reliable,
                MessageClass::Regular,
                Bytes::from(vec![b'q'; 64 * 1024]),
            ))
            .expect("legacy QUIC queue should accept backlog");

        let envelope = OutboundEnvelope::routed(
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            Bytes::from(vec![b'x'; 1200]),
            SendOptions::default(),
        );
        try_dispatch_envelope(&peer, envelope, policy).unwrap();

        assert_eq!(udp_receivers[0].recv().await.unwrap().payload().len(), 1200);
        assert_eq!(legacy_quic.recv().await.unwrap().payload().len(), 64 * 1024);
        assert!(legacy_quic.try_recv().is_err());
        assert_eq!(quic_datagram.depth_bytes(), 0);
    }

    #[tokio::test]
    async fn public_send_preflight_preserves_oversized_legacy_quic_fallback() {
        let (manager, _receivers) = ConnectionManager::test_with_live_streams(1, 2, &[]);
        let peer = manager.inner.get_peer(2).expect("test peer");
        let mut legacy_quic = install_test_stream_at(
            &peer,
            TransportKind::Quic,
            1024 * 1024,
            Some(socket("127.0.0.2:64741")),
        );
        let (_control, _high, _regular, quic_datagram) =
            install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1200).into_parts();

        manager
            .try_send_with_options(
                2,
                ServiceLevel::BestEffort,
                Some(RoutingMetric::ConversationalQuality),
                MessageClass::HighPriority,
                Bytes::from(vec![b'x'; 1200]),
                SendOptions::default(),
            )
            .await
            .unwrap();

        let forwarded = tokio::time::timeout(Duration::from_millis(50), legacy_quic.recv())
            .await
            .expect("legacy QUIC fallback should not be rejected by preflight")
            .expect("legacy QUIC receiver");
        assert_eq!(forwarded.payload().len(), 1200);
        assert_eq!(quic_datagram.depth_bytes(), 0);
    }

    #[tokio::test]
    async fn public_send_preflight_rejects_oversized_best_effort_with_only_quic_v2() {
        let (manager, _receivers) = ConnectionManager::test_with_live_streams(1, 2, &[]);
        let peer = manager.inner.get_peer(2).expect("test peer");
        let (_control, _high, _regular, quic_datagram) =
            install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1200).into_parts();

        let result = manager
            .try_send_with_options(
                2,
                ServiceLevel::BestEffort,
                Some(RoutingMetric::ConversationalQuality),
                MessageClass::HighPriority,
                Bytes::from(vec![b'x'; 1200]),
                SendOptions::default(),
            )
            .await;

        assert!(matches!(
            result,
            Err(SendError::NoSuitableTransport { node: 2 })
        ));
        assert_eq!(quic_datagram.depth_bytes(), 0);
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
    fn expiring_best_effort_voice_keeps_unmeasured_quic_stream_fallback() {
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

        assert_eq!(ranked, vec![TransportKind::Quic]);
    }

    #[tokio::test]
    async fn expiring_voice_can_use_unmeasured_quic_stream_fallback() {
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
        manager
            .try_send_with_options(
                2,
                ServiceLevel::BestEffort,
                Some(RoutingMetric::ConversationalQuality),
                MessageClass::HighPriority,
                Bytes::from_static(b"voice"),
                SendOptions::default().expire_after(Duration::from_millis(750)),
            )
            .await
            .unwrap();

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
    fn expiring_best_effort_voice_keeps_reliable_fallbacks_when_quic_is_degraded() {
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

        assert_eq!(ranked, vec![TransportKind::Tcp, TransportKind::Quic]);
    }

    #[test]
    fn expiring_best_effort_voice_keeps_quic_stream_when_datagram_is_blocked() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Quic]);
        let policy = TransportRoutingPolicy::default();

        for _ in 0..policy.udp_family_probe_loss_block_count() {
            peer.metrics().record_probe_lost(TransportKind::Quic);
        }
        fill_stream_queue(&peer, TransportKind::Tcp, 1024 * 1024 - 512);

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
        fill_stream_queue(&peer, TransportKind::Kcp, 1024 * 1024 - 512);

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
    fn non_expiring_repair_skips_currently_saturated_kcp_without_full_sample() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        // Reproduce the production watermark: the queue is effectively at
        // capacity, but the periodic full-sample counter has already reset.
        // Before current fill was considered for every class, best-effort
        // control/repair traffic kept selecting KCP ahead of TCP.
        fill_stream_queue(&peer, TransportKind::Kcp, 1024 * 1024 - 512);

        let kcp_status = peer
            .outbound_stream_queue_status(TransportKind::Kcp)
            .expect("KCP queue status");
        assert_eq!(kcp_status.full_samples(), 0);
        assert!(kcp_status.depth() < kcp_status.capacity());

        let ranked = pick_transports(
            &peer,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::Control,
            SendOptions::default(),
            0,
            TransportRoutingPolicy::default(),
        );

        assert_eq!(ranked.first().copied(), Some(TransportKind::Tcp));
        assert_eq!(
            non_deadline_queue_penalty(
                &peer,
                TransportKind::Kcp,
                ServiceLevel::BestEffort,
                MessageClass::Control,
            ),
            3
        );
    }

    #[test]
    fn route_pressure_includes_saturated_peer_dispatch_queue() {
        let (peer, _receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        let capacity = peer.outbound_queue_capacity_bytes();
        fill_peer_dispatch_queue(
            &peer,
            capacity - super::super::adaptive_queue::QUEUE_ITEM_OVERHEAD_BYTES,
        );

        assert_eq!(
            non_deadline_queue_penalty(
                &peer,
                TransportKind::Tcp,
                ServiceLevel::Reliable,
                MessageClass::Control,
            ),
            0
        );
        assert_eq!(peer.outbound_queue_depth_bytes(), capacity);
        assert_eq!(
            send_queue_penalty(
                &peer,
                TransportKind::Tcp,
                ServiceLevel::Reliable,
                MessageClass::Control,
                SendOptions::default(),
                Instant::now(),
            ),
            3,
        );
    }

    #[test]
    fn expiring_control_repair_hard_penalizes_currently_saturated_kcp() {
        let (peer, _receivers) = peer_with_live_transports(&[TransportKind::Kcp]);
        fill_stream_queue(&peer, TransportKind::Kcp, 1024 * 1024 - 512);
        peer.metrics()
            .record_payload_sent(TransportKind::Kcp, 8 * 1024 * 1024);

        let penalty = deadline_queue_penalty(
            &peer,
            TransportKind::Kcp,
            ServiceLevel::BestEffort,
            MessageClass::Control,
            SendOptions::default().expire_after(Duration::from_secs(2)),
            Instant::now(),
        );

        assert_eq!(penalty, 3);
    }

    #[test]
    fn expiring_primary_voice_uses_drain_time_at_ninety_percent_fill() {
        let (peer, _receivers) = peer_with_live_transports(&[TransportKind::Kcp]);
        fill_stream_queue(&peer, TransportKind::Kcp, 1024 * 1024 - 512);
        peer.metrics()
            .record_payload_sent(TransportKind::Kcp, 8 * 1024 * 1024);
        let options = SendOptions::default().expire_after(Duration::from_secs(2));

        assert!(
            deadline_queue_penalty(
                &peer,
                TransportKind::Kcp,
                ServiceLevel::ReliableLowLatency,
                MessageClass::HighPriority,
                options,
                Instant::now(),
            ) < 3
        );

        let ranked = pick_transports(
            &peer,
            ServiceLevel::ReliableLowLatency,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            options,
            0,
            TransportRoutingPolicy::default(),
        );

        assert_eq!(ranked, vec![TransportKind::Kcp]);
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
    fn failed_away_kcp_requires_fresh_ack_progress_before_best_effort_reentry() {
        let (peer, mut receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        fill_stream_queue(&peer, TransportKind::Kcp, 64 * 1024);
        age_zero_wire_metric(&peer, TransportKind::Kcp, Duration::from_millis(275));
        let select = || {
            pick_transports(
                &peer,
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
                MessageClass::HighPriority,
                SendOptions::default(),
                0,
                TransportRoutingPolicy::default(),
            )
        };

        assert_eq!(select(), vec![TransportKind::Tcp]);
        receivers[1]
            .try_recv()
            .expect("drain the KCP application queue after failaway");
        let recovery_exclusion = |options| {
            let snapshot = peer.metrics().snapshot_per_transport();
            transport_candidate_exclusion_reason(
                &peer,
                TransportKind::Kcp,
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
                MessageClass::HighPriority,
                options,
                &snapshot,
                TransportSelectionConfig::from(TransportRoutingPolicy::default()),
                true,
                Instant::now(),
            )
        };

        assert!(select().contains(&TransportKind::Kcp));
        assert_eq!(
            recovery_exclusion(SendOptions::default()),
            None,
            "the recovery gate is scoped to expiring conversational voice"
        );
        assert_eq!(
            recovery_exclusion(SendOptions::default().expire_after(Duration::from_secs(2))),
            Some(TransportHealthExclusionReason::KcpRecoveryPending)
        );
        peer.metrics()
            .record_native_loss_sample(TransportKind::Kcp, 1, 0);
        assert_eq!(
            recovery_exclusion(SendOptions::default().expire_after(Duration::from_secs(2))),
            Some(TransportHealthExclusionReason::KcpRecoveryPending),
            "outbound segment accounting is not ACK progress"
        );

        peer.metrics()
            .record_native_rtt(TransportKind::Kcp, Duration::from_millis(40));
        assert_eq!(
            recovery_exclusion(SendOptions::default().expire_after(Duration::from_secs(2))),
            None
        );
    }

    #[test]
    fn persistent_kcp_failaway_does_not_wake_its_own_dispatcher() {
        let (peer, _receivers) =
            peer_with_live_transports(&[TransportKind::Tcp, TransportKind::Kcp]);
        assert!(
            peer.wait_for_outbound_dispatch_signal()
                .now_or_never()
                .is_some(),
            "stream installation should signal dispatch"
        );

        fill_stream_queue(&peer, TransportKind::Kcp, 64 * 1024);
        peer.metrics()
            .record_rtt(TransportKind::Kcp, Duration::from_millis(40));
        let snapshot = peer.metrics().snapshot_per_transport();
        let selection = TransportSelectionConfig::from(TransportRoutingPolicy::default());
        let now = snapshot[&TransportKind::Kcp]
            .last_update()
            .expect("KCP metric timestamp")
            + selection.kcp.failaway_with_alternative();

        for _ in 0..3 {
            assert_eq!(
                transport_candidate_exclusion_reason(
                    &peer,
                    TransportKind::Kcp,
                    ServiceLevel::BestEffort,
                    RoutingMetric::ConversationalQuality,
                    MessageClass::HighPriority,
                    SendOptions::default(),
                    &snapshot,
                    selection,
                    true,
                    now,
                ),
                Some(TransportHealthExclusionReason::KcpFailaway)
            );
        }

        assert!(
            peer.wait_for_outbound_dispatch_signal()
                .now_or_never()
                .is_none(),
            "persistent failaway selection must not signal its own dispatcher"
        );
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
        fill_stream_queue(&peer, TransportKind::Kcp, 1024 * 1024 - 512);

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
    fn expiring_high_priority_reuses_recovered_stream_after_historical_full_sample() {
        let (peer, _receivers) = peer_with_live_transports(&[TransportKind::Kcp]);
        peer.record_outbound_stream_queue_sample(
            TransportKind::Kcp,
            MessageClass::HighPriority,
            1024 * 1024,
            1024 * 1024,
            true,
        );
        fill_stream_queue(&peer, TransportKind::Kcp, 1);

        let status = peer
            .outbound_stream_queue_status(TransportKind::Kcp)
            .expect("KCP queue status");
        assert_eq!(status.full_samples(), 1);
        assert!(status.depth() < status.capacity());

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
            ServiceLevel::Reliable,
            MessageClass::Regular,
            SendOptions::default().expire_after(Duration::from_secs(1)),
            Instant::now(),
        );

        assert_eq!(penalty, 3);
    }

    #[test]
    fn non_expiring_high_priority_prefers_clear_stream_over_metric_order() {
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

        assert_eq!(ranked.first().copied(), Some(TransportKind::Kcp));
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
    fn sticky_voice_hard_escape_commits_only_after_alternate_admission() {
        let (peer, mut receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        let policy = TransportRoutingPolicy::default();

        try_dispatch_envelope(&peer, expiring_voice(b"initial"), policy)
            .expect("initial voice frame should bind TCP");
        assert_eq!(
            receivers[0].try_recv().unwrap().payload(),
            &Bytes::from_static(b"initial")
        );
        assert_eq!(
            peer.voice_transport_binding_status().unwrap().transport(),
            TransportKind::Tcp
        );

        drop(receivers);
        let mut kcp_rx = install_test_stream(&peer, TransportKind::Kcp, 1024 * 1024);
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Kcp);
        }

        try_dispatch_envelope(&peer, expiring_voice(b"fallback"), policy)
            .expect("a closed incumbent should escape to KCP in the same dispatch");
        assert_eq!(
            peer.voice_transport_binding_status().unwrap().transport(),
            TransportKind::Kcp
        );
        assert_eq!(
            kcp_rx.try_recv().unwrap().payload(),
            &Bytes::from_static(b"fallback")
        );

        // Close the incumbent and leave the only alternate apparently
        // eligible, but too small to admit this frame. The attempted escape
        // must not poison the existing KCP binding.
        drop(kcp_rx);
        let mut tcp_rx = install_test_stream(&peer, TransportKind::Tcp, 257);
        let rejected = OutboundEnvelope::routed(
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            Bytes::from(vec![b'x'; 1024 * 1024]),
            SendOptions::default().expire_after(Duration::from_secs(2)),
        );

        // BestEffort that loses every viable candidate is dropped instead of
        // being requeued indefinitely.
        assert!(try_dispatch_envelope(&peer, rejected, policy).is_ok());
        assert!(tcp_rx.try_recv().is_err());
        assert_eq!(
            peer.voice_transport_binding_status().unwrap().transport(),
            TransportKind::Kcp
        );
    }

    #[test]
    fn disabled_fixed_control_and_non_expiring_sends_bypass_voice_stickiness() {
        let (peer, mut receivers) = peer_with_live_transports(&[TransportKind::Tcp]);
        let policy = TransportRoutingPolicy::default();
        try_dispatch_envelope(&peer, expiring_voice(b"bind"), policy).unwrap();
        assert_eq!(
            receivers[0].try_recv().unwrap().payload(),
            b"bind".as_slice()
        );

        let mut quic_rx = install_test_stream(&peer, TransportKind::Quic, 1024 * 1024);
        peer.metrics()
            .record_rtt(TransportKind::Tcp, Duration::from_millis(180));
        peer.metrics()
            .record_rtt(TransportKind::Quic, Duration::from_millis(60));
        for _ in 0..policy.udp_family_min_samples() {
            peer.metrics().record_probe_delivered(TransportKind::Quic);
        }

        let disabled = policy.with_voice_path_stickiness_enabled(false);
        try_dispatch_envelope(&peer, expiring_voice(b"disabled"), disabled).unwrap();
        assert_eq!(
            quic_rx.try_recv().unwrap().payload(),
            b"disabled".as_slice(),
            "disabled stickiness must preserve metric-ranked fallback selection"
        );

        let fixed = OutboundEnvelope::fixed_transport(
            TransportKind::Quic,
            MessageClass::HighPriority,
            Bytes::from_static(b"fixed"),
            SendOptions::default().expire_after(Duration::from_secs(2)),
        );
        try_dispatch_envelope(&peer, fixed, policy).unwrap();
        assert_eq!(quic_rx.try_recv().unwrap().payload(), b"fixed".as_slice());

        let control = OutboundEnvelope::routed(
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::Control,
            Bytes::from_static(b"control"),
            SendOptions::default().expire_after(Duration::from_secs(2)),
        );
        try_dispatch_envelope(&peer, control, policy).unwrap();
        let control = quic_rx
            .try_recv()
            .ok()
            .or_else(|| receivers[0].try_recv().ok())
            .expect("control bypass should be admitted");
        assert_eq!(control.payload(), b"control".as_slice());

        let non_expiring = OutboundEnvelope::routed(
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
            MessageClass::HighPriority,
            Bytes::from_static(b"non-expiring"),
            SendOptions::default(),
        );
        try_dispatch_envelope(&peer, non_expiring, policy).unwrap();
        let non_expiring = quic_rx
            .try_recv()
            .ok()
            .or_else(|| receivers[0].try_recv().ok())
            .expect("non-expiring bypass should be admitted");
        assert_eq!(non_expiring.payload(), b"non-expiring".as_slice());
        assert_eq!(
            peer.voice_transport_binding_status().unwrap().transport(),
            TransportKind::Tcp,
            "bypass sends must not mutate the sticky voice binding"
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
    async fn quic_best_effort_payload_preflight_requires_datagram_fit_or_legacy_stream() {
        let (manager, _receivers) = ConnectionManager::test_with_live_streams(1, 2, &[]);
        let peer = manager.inner.get_peer(2).expect("test peer");
        let _v2 = install_test_quic_v2(&peer, socket("127.0.0.1:64741"), 1200);
        let payload = vec![0; 1200];

        assert!(!manager.payload_fits_transport(
            2,
            TransportKind::Quic,
            ServiceLevel::BestEffort,
            MessageClass::HighPriority,
            &payload,
        ));

        let _legacy = install_test_stream_at(
            &peer,
            TransportKind::Quic,
            1024 * 1024,
            Some(socket("127.0.0.2:64741")),
        );
        assert!(manager.payload_fits_transport(
            2,
            TransportKind::Quic,
            ServiceLevel::BestEffort,
            MessageClass::HighPriority,
            &payload,
        ));
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
    fn dispatch_propagates_requested_level_to_primary_and_sidecars() {
        let (peer, mut receivers) = peer_with_live_transports(&[TransportKind::Tcp]);

        for level in ServiceLevel::ALL {
            let payloads = TransportPayloadPlan::new(Bytes::from_static(b"primary")).with_variant(
                TransportKind::Tcp,
                TransportPayloadVariant::new(Bytes::from_static(b"primary"))
                    .with_sidecars([Bytes::from_static(b"sidecar")]),
            );
            let envelope = OutboundEnvelope::routed_with_payloads(
                level,
                RoutingMetric::default_for_level(level),
                MessageClass::Control,
                payloads,
                SendOptions::default(),
            );

            try_dispatch_envelope(&peer, envelope, TransportRoutingPolicy::default())
                .expect("live TCP fallback should accept every requested level");

            let primary = receivers[0].try_recv().expect("primary frame");
            let sidecar = receivers[0].try_recv().expect("sidecar frame");
            assert_eq!(primary.level(), level);
            assert_eq!(sidecar.level(), level);
        }
    }

    #[test]
    fn payload_plan_keeps_transport_variants_independent() {
        let plan = TransportPayloadPlan::new(Bytes::from_static(b"rich"))
            .with_variant(
                TransportKind::Udp,
                TransportPayloadVariant::new(Bytes::from_static(b"udp"))
                    .with_sidecars([Bytes::from_static(b"sidecar")]),
            )
            .with_quic_v2_variant(TransportPayloadVariant::new(Bytes::from_static(b"quic-v2")));
        assert_eq!(
            plan.variant(TransportKind::Tcp).primary(),
            &Bytes::from_static(b"rich")
        );
        assert_eq!(
            plan.variant(TransportKind::Udp).primary(),
            &Bytes::from_static(b"udp")
        );
        assert_eq!(plan.variant(TransportKind::Udp).sidecars().len(), 1);
        assert_eq!(
            plan.variant_for_session(TransportKind::Quic, false)
                .primary(),
            &Bytes::from_static(b"rich")
        );
        assert_eq!(
            plan.variant_for_session(TransportKind::Quic, true)
                .primary(),
            &Bytes::from_static(b"quic-v2")
        );
    }
}
