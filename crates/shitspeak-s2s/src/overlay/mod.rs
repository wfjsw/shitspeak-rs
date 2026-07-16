//! Layer-2 overlay network for S2S traffic.
//!
//! Sits on top of the L1 [`shitspeak_s2s_transport::ConnectionManager`]
//! and provides cluster-level services to higher layers: discovery,
//! LSDB-derived membership, multi-hop routing across three service
//! levels, and an `OverlayData` envelope for L3 services.
//!
//! ## Architecture (Phase 2)
//!
//! Direct neighbors are discovered via the `Hello/HelloAck` protocol
//! (see [`neighbor`]). Each node publishes a Link-State Advertisement
//! (LSA) on triggered + periodic events; LSAs flood to direct neighbors
//! and feed the local [`lsdb::LinkStateDb`]. The LSDB is the single
//! source of truth for both routing (per-service-level Dijkstra) and
//! membership (alive iff non-tombstone LSA is current).
//!
//! ## Public API
//!
//! The overlay's send path is exposed via [`OverlayNetwork::send_unicast`],
//! [`send_multicast`](OverlayNetwork::send_multicast), and
//! [`send_broadcast`](OverlayNetwork::send_broadcast). L3 services
//! register a [`messaging::ServiceInbound`] handler keyed by a
//! `service_tag` (replications uses `tag = 1`).

pub(crate) mod attachment_metrics;
pub(crate) mod attachments;
pub(crate) mod config;
mod discovery;
mod distribution;
pub(crate) mod distribution_metrics;
mod duplicate;
mod error;
mod inbound;
mod lane;
pub mod lsdb;
pub mod membership;
pub mod messaging;
pub mod neighbor;
pub(crate) mod proto;
pub mod routing;
mod runtime;

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use bytes::Bytes;
use futures_util::future::join_all;
use tokio::sync::broadcast;
use tokio::time::{Instant, timeout};

use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{
    AdaptiveInboundReceiver, ConnectionManager, Inbound, InboundMessage, MessageClass,
    ServiceLevel, TransportKind,
};

const DISTRIBUTION_HOP_TTL: Duration = Duration::from_millis(80);

pub use config::{OverlayConfig, OverlayTuning, SeedPeer, TransportMask};
pub use duplicate::{DuplicateDetector, DuplicateEvidenceKind, DuplicateNodeSnapshot};
pub use error::OverlayError;
pub use lane::LaneId;
pub use lsdb::{ApplicationServices, ReplicationServices};
pub use membership::{MemberIncarnation, MemberSnapshot, MemberStatus, MembershipEvent};
pub use messaging::{
    OVERLAY_ATTACHMENT_SERVICE_TAG, OverlayAttachment, OverlayInboundMessage, OverlaySendOptions,
    ServiceInbound,
};

/// Dedicated reliable generic-tree service used only by the pre-release gate.
#[cfg(feature = "pre-release-workload")]
pub const PRE_RELEASE_DISTRIBUTION_SERVICE_TAG: u32 = 251;
pub use routing::{RouteEntry, RoutingMetric};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VoiceRouteQuality {
    next_hop: NodeIdentifier,
    transport: TransportKind,
    path_latency_us: u64,
    loss_ppm: u32,
    jitter_us: u64,
}

impl VoiceRouteQuality {
    pub fn new(
        next_hop: NodeIdentifier,
        transport: TransportKind,
        path_latency_us: u64,
        loss_ppm: u32,
        jitter_us: u64,
    ) -> Self {
        Self {
            next_hop,
            transport,
            path_latency_us,
            loss_ppm,
            jitter_us,
        }
    }

    pub fn next_hop(self) -> NodeIdentifier {
        self.next_hop
    }

    pub fn transport(self) -> TransportKind {
        self.transport
    }

    pub fn path_latency_us(self) -> u64 {
        self.path_latency_us
    }

    pub fn loss_ppm(self) -> u32 {
        self.loss_ppm
    }

    pub fn jitter_us(self) -> u64 {
        self.jitter_us
    }
}

#[derive(Debug, Clone)]
pub struct StartupDuplicateEvidence {
    source: NodeIdentifier,
    kind: &'static str,
}

impl StartupDuplicateEvidence {
    pub fn source(&self) -> NodeIdentifier {
        self.source
    }

    pub fn kind(&self) -> &'static str {
        self.kind
    }
}

pub async fn duplicate_startup_preflight(
    local_node: NodeIdentifier,
    inbound: Inbound,
    window: Duration,
) -> (Inbound, Option<StartupDuplicateEvidence>) {
    let (mut control, mut high_priority, mut regular) = inbound.into_parts();
    let deadline = Instant::now() + window.max(Duration::from_millis(1));
    let mut evidence = None;

    while evidence.is_none() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match timeout(
            deadline.saturating_duration_since(now),
            recv_preflight_any(&mut control, &mut high_priority, &mut regular),
        )
        .await
        {
            Ok(Some(msg)) => {
                evidence = startup_duplicate_evidence(local_node, &msg);
            }
            Ok(None) | Err(_) => break,
        }
    }

    (Inbound::new(control, high_priority, regular), evidence)
}

async fn recv_preflight_any(
    control: &mut AdaptiveInboundReceiver,
    high_priority: &mut AdaptiveInboundReceiver,
    regular: &mut AdaptiveInboundReceiver,
) -> Option<InboundMessage> {
    tokio::select! {
        msg = control.recv() => msg,
        msg = high_priority.recv() => msg,
        msg = regular.recv() => msg,
    }
}

fn startup_duplicate_evidence(
    local_node: NodeIdentifier,
    msg: &InboundMessage,
) -> Option<StartupDuplicateEvidence> {
    if msg.from() == local_node {
        return Some(StartupDuplicateEvidence {
            source: msg.from(),
            kind: "transport_peer",
        });
    }
    let decoded = proto::decode_message(msg.payload()).ok()?;
    let body = decoded.body?;
    match body {
        proto::OverlayBody::Hello(hello)
            if NodeIdentifier::try_from(hello.src_node).ok() == Some(local_node) =>
        {
            Some(StartupDuplicateEvidence {
                source: msg.from(),
                kind: "hello",
            })
        }
        proto::OverlayBody::HelloAck(ack)
            if NodeIdentifier::try_from(ack.src_node).ok() == Some(local_node) =>
        {
            Some(StartupDuplicateEvidence {
                source: msg.from(),
                kind: "hello_ack",
            })
        }
        _ => None,
    }
}

/// Public handle for the overlay network. Cheap to clone — internally a
/// shared `Arc`.
#[derive(Clone)]
pub struct OverlayNetwork {
    inner: Arc<runtime::OverlayInner>,
}

impl OverlayNetwork {
    /// Bring up the overlay over an already-started transport. Spawns
    /// all long-running tasks (Hello protocol, LSA emitter, anti-entropy,
    /// routing recomputer, diff watcher, inbound dispatcher); runs
    /// discovery bootstrap (seed addresses + persisted file) before
    /// returning.
    pub async fn start(
        transport: ConnectionManager,
        inbound: Inbound,
        cfg: OverlayConfig,
    ) -> Result<Self, OverlayError> {
        Self::start_with_max_users(transport, inbound, cfg, Arc::new(AtomicU64::new(0))).await
    }

    /// Bring up the overlay with local server capacity advertised in this
    /// node's LSA.
    pub async fn start_with_max_users(
        transport: ConnectionManager,
        inbound: Inbound,
        cfg: OverlayConfig,
        max_users: Arc<AtomicU64>,
    ) -> Result<Self, OverlayError> {
        Self::start_with_max_users_and_replication_services(
            transport,
            inbound,
            cfg,
            max_users,
            ReplicationServices::ALL,
        )
        .await
    }

    /// Bring up the overlay with local server capacity and replication service
    /// capability advertised in this node's LSA.
    pub async fn start_with_max_users_and_replication_services(
        transport: ConnectionManager,
        inbound: Inbound,
        cfg: OverlayConfig,
        max_users: Arc<AtomicU64>,
        replication_services: ReplicationServices,
    ) -> Result<Self, OverlayError> {
        Self::start_with_max_users_replication_and_application_services(
            transport,
            inbound,
            cfg,
            max_users,
            replication_services,
            ApplicationServices::ALL,
        )
        .await
    }

    /// Bring up the overlay with local server capacity, replication service
    /// capability, and application service capability advertised in this
    /// node's LSA.
    pub async fn start_with_max_users_replication_and_application_services(
        transport: ConnectionManager,
        inbound: Inbound,
        cfg: OverlayConfig,
        max_users: Arc<AtomicU64>,
        replication_services: ReplicationServices,
        application_services: ApplicationServices,
    ) -> Result<Self, OverlayError> {
        let inner = runtime::start_inner(
            transport,
            inbound,
            cfg,
            max_users,
            replication_services,
            application_services,
        )
        .await?;
        let network = Self { inner };
        distribution::register_control_handler(&network);
        Ok(network)
    }

    /// Local node id derived from the transport's TLS cert CN.
    pub fn local_node_id(&self) -> NodeIdentifier {
        self.inner.self_id
    }

    pub(crate) fn peer_clock_offsets(
        &self,
    ) -> Vec<(NodeIdentifier, neighbor::monitor::PeerClockOffset)> {
        self.inner.neighbor.peer_clock_offsets()
    }

    /// Local node's `boot_epoch` (microseconds since UNIX epoch, captured
    /// once at overlay start). Stable until the process restarts.
    pub fn local_boot_epoch(&self) -> u64 {
        self.inner.boot_epoch
    }

    #[cfg(feature = "pre-release-workload")]
    pub fn pre_release_distribution_epoch(&self) -> u64 {
        self.inner.lsdb.distribution_epoch()
    }

    #[cfg(feature = "pre-release-workload")]
    pub fn pre_release_metric_lsa_emissions(&self) -> u64 {
        lsdb::advert::pre_release_metric_lsa_emissions()
    }

    #[cfg(feature = "pre-release-workload")]
    pub fn pre_release_distribution_counters(&self) -> (u64, u64, u64, u64) {
        distribution_metrics::pre_release_counters()
    }

    /// Snapshot of every directed-edge RTT currently advertised in the
    /// LSDB. Zero values (uninitialized links) are filtered out.
    /// Tombstoned origins' edges are excluded so a recently-departed peer
    /// can't skew the distribution.
    ///
    /// Used by L3 (replications) to scale the strict-mode clock-tick
    /// cadence to the cluster's measured network latency.
    pub fn edge_rtt_snapshot(&self) -> Vec<std::time::Duration> {
        self.inner.lsdb.edge_rtt_snapshot()
    }

    /// Raw LSDB snapshot for diagnostics and topology rendering.
    pub fn link_state_snapshot(&self) -> Vec<lsdb::LsaEntry> {
        self.inner.lsdb.snapshot()
    }

    /// Snapshot of duplicate node-id observations and quarantine state.
    pub fn duplicate_node_snapshot(&self) -> Vec<DuplicateNodeSnapshot> {
        self.inner.duplicate_detector.snapshot()
    }

    /// Whether a node ID is currently quarantined due to duplicate identity evidence.
    pub fn is_node_quarantined(&self, node: NodeIdentifier) -> bool {
        self.inner.duplicate_detector.is_quarantined(node)
    }

    /// Current routing-table snapshot for diagnostics and topology rendering.
    pub fn routing_snapshot(&self) -> routing::RoutingTables {
        self.inner.routing.load().as_ref().clone()
    }

    /// Snapshot of the current membership view, sorted by node id.
    pub fn members(&self) -> Vec<MemberSnapshot> {
        self.inner
            .table
            .snapshot()
            .into_iter()
            .filter(|member| !self.is_node_quarantined(member.node_id()))
            .collect()
    }

    /// Look up one peer.
    pub fn member(&self, node: NodeIdentifier) -> Option<MemberSnapshot> {
        if self.is_node_quarantined(node) {
            None
        } else {
            self.inner.table.snapshot_one(node)
        }
    }

    /// IDs of every origin with a current non-tombstone LSA.
    pub fn alive_members(&self) -> Vec<NodeIdentifier> {
        self.inner
            .table
            .alive_members()
            .into_iter()
            .filter(|node| !self.is_node_quarantined(*node))
            .collect()
    }

    /// IDs of active members that advertise application voice service.
    pub(crate) fn voice_members(&self) -> Vec<NodeIdentifier> {
        self.inner
            .table
            .voice_members()
            .into_iter()
            .filter(|node| !self.is_node_quarantined(*node))
            .collect()
    }

    /// IDs of active members that advertise strict replication service.
    pub fn strict_replication_members(&self) -> Vec<NodeIdentifier> {
        self.inner
            .table
            .strict_replication_members()
            .into_iter()
            .filter(|node| !self.is_node_quarantined(*node))
            .collect()
    }

    /// IDs of active members that advertise content/blob replication service.
    pub fn content_replication_members(&self) -> Vec<NodeIdentifier> {
        self.inner
            .table
            .content_replication_members()
            .into_iter()
            .filter(|node| !self.is_node_quarantined(*node))
            .collect()
    }

    /// IDs of active members that advertise owner-scoped replication service.
    pub fn owner_replication_members(&self) -> Vec<NodeIdentifier> {
        self.inner
            .table
            .owner_replication_members()
            .into_iter()
            .filter(|node| !self.is_node_quarantined(*node))
            .collect()
    }

    /// Sum local max_users advertised by alive cluster members.
    pub fn alive_max_users(&self) -> u64 {
        self.members()
            .into_iter()
            .filter(|member| member.status() == MemberStatus::Alive)
            .map(|member| member.max_users())
            .sum()
    }

    /// Publish a changed local max_users value in the next local LSA.
    pub fn update_local_max_users(&self, max_users: u64) {
        self.inner
            .emitter
            .max_users
            .store(max_users, std::sync::atomic::Ordering::Relaxed);
        self.inner.emitter.poke_force();
    }

    /// Publish a changed local transit-routing policy in the next local LSA.
    pub fn update_route_transit_messages(&self, enabled: bool) {
        self.inner.emitter.update_route_transit_messages(enabled);
    }

    /// Publish changed local replication service capabilities in the next LSA.
    pub fn update_replication_services(&self, services: ReplicationServices) {
        self.inner.emitter.update_replication_services(services);
    }

    /// Subscribe to the membership-event stream. Each subscriber receives
    /// every event independently.
    pub fn subscribe_membership(&self) -> broadcast::Receiver<MembershipEvent> {
        self.inner.table.subscribe()
    }

    /// Register an L3 service handler for `tag`. The handler is invoked
    /// synchronously on the inbound dispatcher when an `OverlayData`
    /// frame with that tag is destined locally, or when the frame opts
    /// into transit processing for nodes it passes through.
    pub fn register_service(&self, tag: u32, handler: Arc<dyn ServiceInbound>) {
        self.inner.services.register(tag, handler);
    }

    pub fn unregister_service(&self, tag: u32) {
        self.inner.services.unregister(tag);
    }

    /// Send to a single peer using per-service-level routing.
    pub async fn send_unicast(
        &self,
        dst: NodeIdentifier,
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        self.send_unicast_with_options(dst, tag, level, class, body, OverlaySendOptions::default())
            .await
    }

    /// Send to a single peer using per-service-level routing and send options.
    pub async fn send_unicast_with_options(
        &self,
        dst: NodeIdentifier,
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
        options: OverlaySendOptions,
    ) -> Result<(), OverlayError> {
        messaging::send_unicast_with_options(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            dst,
            tag,
            level,
            class,
            body,
            options,
        )
        .await
    }

    /// Send to a single peer and also deliver to matching services on transit nodes.
    pub async fn send_unicast_with_transit_processing(
        &self,
        dst: NodeIdentifier,
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        messaging::send_unicast_with_transit_processing(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            dst,
            tag,
            level,
            class,
            body,
            true,
        )
        .await
    }

    /// Send to a single peer with an explicit routing metric and also deliver
    /// to matching services on transit nodes.
    pub async fn send_unicast_with_routing_metric_and_transit_processing(
        &self,
        dst: NodeIdentifier,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        messaging::send_unicast_with_routing_metric_and_transit_processing(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            dst,
            tag,
            level,
            routing_metric,
            class,
            body,
            true,
        )
        .await
    }

    /// Send to a single peer with an explicit routing metric.
    pub async fn send_unicast_with_routing_metric(
        &self,
        dst: NodeIdentifier,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        messaging::send_unicast_with_routing_metric_and_transit_processing(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            dst,
            tag,
            level,
            routing_metric,
            class,
            body,
            false,
        )
        .await
    }

    /// Send to a single peer on an ordered overlay lane.
    pub async fn send_unicast_on_lane(
        &self,
        dst: NodeIdentifier,
        lane: LaneId,
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        self.send_unicast_on_lane_with_options(
            dst,
            lane,
            tag,
            level,
            class,
            body,
            OverlaySendOptions::default(),
        )
        .await
    }

    /// Send to a single peer on an ordered overlay lane with send options.
    pub async fn send_unicast_on_lane_with_options(
        &self,
        dst: NodeIdentifier,
        lane: LaneId,
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
        options: OverlaySendOptions,
    ) -> Result<(), OverlayError> {
        self.send_unicast_on_lane_with_routing_metric_and_options(
            dst,
            lane,
            tag,
            level,
            RoutingMetric::default_for_level(level),
            class,
            body,
            options,
        )
        .await
    }

    /// Send to a single peer on an ordered overlay lane with an explicit metric.
    pub async fn send_unicast_on_lane_with_routing_metric(
        &self,
        dst: NodeIdentifier,
        lane: LaneId,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        self.send_unicast_on_lane_with_routing_metric_and_options(
            dst,
            lane,
            tag,
            level,
            routing_metric,
            class,
            body,
            OverlaySendOptions::default(),
        )
        .await
    }

    /// Send to a single peer on an ordered overlay lane with an explicit metric and send options.
    pub async fn send_unicast_on_lane_with_routing_metric_and_options(
        &self,
        dst: NodeIdentifier,
        lane: LaneId,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
        options: OverlaySendOptions,
    ) -> Result<(), OverlayError> {
        messaging::send_unicast_on_lane_with_options(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            dst,
            tag,
            level,
            routing_metric,
            class,
            body,
            lane,
            false,
            options,
        )
        .await
    }

    /// Send to a single peer on an ordered overlay lane and optionally process on transit nodes.
    pub async fn send_unicast_on_lane_with_routing_metric_and_transit_processing(
        &self,
        dst: NodeIdentifier,
        lane: LaneId,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
        process_on_transit: bool,
    ) -> Result<(), OverlayError> {
        messaging::send_unicast_on_lane(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            dst,
            tag,
            level,
            routing_metric,
            class,
            body,
            lane,
            process_on_transit,
        )
        .await
    }

    /// Send to a single peer without opting into an ordered overlay lane.
    pub async fn send_unicast_unordered_with_routing_metric(
        &self,
        dst: NodeIdentifier,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        self.send_unicast_unordered_with_routing_metric_and_options(
            dst,
            tag,
            level,
            routing_metric,
            class,
            body,
            OverlaySendOptions::default(),
        )
        .await
    }

    /// Send to a single peer without an ordered lane, using an explicit metric and send options.
    pub async fn send_unicast_unordered_with_routing_metric_and_options(
        &self,
        dst: NodeIdentifier,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
        options: OverlaySendOptions,
    ) -> Result<(), OverlayError> {
        messaging::send_unicast_with_routing_metric_unordered_and_options(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            dst,
            tag,
            level,
            routing_metric,
            class,
            body,
            false,
            options,
        )
        .await
    }

    /// Send an unordered unicast with optional opaque attachments. The
    /// attachment bytes are opportunistically packed by the forwarding path.
    pub async fn send_unicast_unordered_with_routing_metric_and_attachments(
        &self,
        dst: NodeIdentifier,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
        attachments: Vec<OverlayAttachment>,
        options: OverlaySendOptions,
    ) -> Result<(), OverlayError> {
        messaging::send_unicast_unordered_with_routing_metric_and_attachments(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            dst,
            tag,
            level,
            routing_metric,
            class,
            body,
            false,
            attachments,
            options,
        )
        .await
    }

    /// Send to a list of peers — fanned out per next-hop.
    pub async fn send_multicast(
        &self,
        dsts: &[NodeIdentifier],
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        self.send_multicast_with_options(
            dsts,
            tag,
            level,
            class,
            body,
            OverlaySendOptions::default(),
        )
        .await
    }

    /// Send to a list of peers with send options.
    pub async fn send_multicast_with_options(
        &self,
        dsts: &[NodeIdentifier],
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
        options: OverlaySendOptions,
    ) -> Result<(), OverlayError> {
        messaging::send_multicast_with_options(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            dsts,
            tag,
            level,
            class,
            body,
            options,
        )
        .await
    }

    /// Send a multicast with optional opaque attachments.
    pub async fn send_multicast_with_routing_metric_and_attachments(
        &self,
        dsts: &[NodeIdentifier],
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
        attachments: Vec<OverlayAttachment>,
        options: OverlaySendOptions,
    ) -> Result<(), OverlayError> {
        messaging::send_multicast_with_routing_metric_unordered_and_attachments(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            dsts,
            tag,
            level,
            routing_metric,
            class,
            body,
            false,
            attachments,
            options,
        )
        .await
    }

    /// Send to a list of peers and also deliver to matching services on transit nodes.
    pub async fn send_multicast_with_transit_processing(
        &self,
        dsts: &[NodeIdentifier],
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        messaging::send_multicast_with_transit_processing(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            dsts,
            tag,
            level,
            class,
            body,
            true,
        )
        .await
    }

    /// Send to a list of peers with an explicit routing metric and also
    /// deliver to matching services on transit nodes.
    pub async fn send_multicast_with_routing_metric_and_transit_processing(
        &self,
        dsts: &[NodeIdentifier],
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        messaging::send_multicast_with_routing_metric_and_transit_processing(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            dsts,
            tag,
            level,
            routing_metric,
            class,
            body,
            true,
        )
        .await
    }

    /// Send to a list of peers with an explicit routing metric.
    pub async fn send_multicast_with_routing_metric(
        &self,
        dsts: &[NodeIdentifier],
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        messaging::send_multicast_with_routing_metric_and_transit_processing(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            dsts,
            tag,
            level,
            routing_metric,
            class,
            body,
            false,
        )
        .await
    }

    /// Send to a list of peers on an ordered overlay lane.
    pub async fn send_multicast_on_lane(
        &self,
        dsts: &[NodeIdentifier],
        lane: LaneId,
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        self.send_multicast_on_lane_with_options(
            dsts,
            lane,
            tag,
            level,
            class,
            body,
            OverlaySendOptions::default(),
        )
        .await
    }

    /// Send to a list of peers on an ordered overlay lane with send options.
    pub async fn send_multicast_on_lane_with_options(
        &self,
        dsts: &[NodeIdentifier],
        lane: LaneId,
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
        options: OverlaySendOptions,
    ) -> Result<(), OverlayError> {
        self.send_multicast_on_lane_with_routing_metric_and_options(
            dsts,
            lane,
            tag,
            level,
            RoutingMetric::default_for_level(level),
            class,
            body,
            options,
        )
        .await
    }

    /// Send to a list of peers on an ordered overlay lane with an explicit metric.
    pub async fn send_multicast_on_lane_with_routing_metric(
        &self,
        dsts: &[NodeIdentifier],
        lane: LaneId,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        self.send_multicast_on_lane_with_routing_metric_and_options(
            dsts,
            lane,
            tag,
            level,
            routing_metric,
            class,
            body,
            OverlaySendOptions::default(),
        )
        .await
    }

    /// Send to a list of peers on an ordered overlay lane with an explicit metric and send options.
    pub async fn send_multicast_on_lane_with_routing_metric_and_options(
        &self,
        dsts: &[NodeIdentifier],
        lane: LaneId,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
        options: OverlaySendOptions,
    ) -> Result<(), OverlayError> {
        messaging::send_multicast_on_lane_with_options(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            dsts,
            tag,
            level,
            routing_metric,
            class,
            body,
            lane,
            false,
            options,
        )
        .await
    }

    /// Send to a list of peers on an ordered overlay lane and optionally process on transit nodes.
    pub async fn send_multicast_on_lane_with_routing_metric_and_transit_processing(
        &self,
        dsts: &[NodeIdentifier],
        lane: LaneId,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
        process_on_transit: bool,
    ) -> Result<(), OverlayError> {
        messaging::send_multicast_on_lane(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            dsts,
            tag,
            level,
            routing_metric,
            class,
            body,
            lane,
            process_on_transit,
        )
        .await
    }

    /// Send to a list of peers without opting into an ordered overlay lane.
    pub async fn send_multicast_unordered_with_routing_metric(
        &self,
        dsts: &[NodeIdentifier],
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        self.send_multicast_unordered_with_routing_metric_and_options(
            dsts,
            tag,
            level,
            routing_metric,
            class,
            body,
            OverlaySendOptions::default(),
        )
        .await
    }

    /// Send to a list of peers without an ordered lane, using an explicit metric and send options.
    pub async fn send_multicast_unordered_with_routing_metric_and_options(
        &self,
        dsts: &[NodeIdentifier],
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
        options: OverlaySendOptions,
    ) -> Result<(), OverlayError> {
        messaging::send_multicast_with_routing_metric_unordered_and_options(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            dsts,
            tag,
            level,
            routing_metric,
            class,
            body,
            false,
            options,
        )
        .await
    }

    /// Send to a list of peers using one source-rooted multicast tree. This
    /// is opt-in because every relay on the active tree must understand the
    /// tree envelope before an operator enables it cluster-wide.
    pub async fn send_multicast_tree_unordered_with_routing_metric_and_group_options(
        &self,
        dsts: &[NodeIdentifier],
        group: u64,
        group_version: u64,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
        options: OverlaySendOptions,
    ) -> Result<(), OverlayError> {
        self.send_multicast_tree_unordered_with_routing_metric_and_group_options_and_attachments(
            dsts,
            group,
            group_version,
            tag,
            level,
            routing_metric,
            class,
            body,
            Vec::new(),
            options,
        )
        .await
    }

    /// Send a source-rooted multicast tree with optional opaque attachments.
    /// Attachments are trimmed per logical branch as the tree is forwarded.
    pub async fn send_multicast_tree_unordered_with_routing_metric_and_group_options_and_attachments(
        &self,
        dsts: &[NodeIdentifier],
        group: u64,
        group_version: u64,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
        attachments: Vec<OverlayAttachment>,
        options: OverlaySendOptions,
    ) -> Result<(), OverlayError> {
        let dsts: Vec<_> = dsts
            .iter()
            .copied()
            .filter(|node| *node != self.inner.self_id)
            .collect();
        if dsts.is_empty() {
            return Ok(());
        }
        let Some(profile) = distribution::profile_for_service(tag) else {
            return self
                .send_multicast_with_routing_metric_and_attachments(
                    &dsts,
                    tag,
                    level,
                    routing_metric,
                    class,
                    body,
                    attachments.clone(),
                    options,
                )
                .await;
        };
        let all_dsts = dsts;
        let (dsts, mut legacy_dsts): (Vec<_>, Vec<_>) = all_dsts.into_iter().partition(|node| {
            self.inner.lsdb.supports_distribution_profile(
                *node,
                crate::overlay::lsdb::DistributionCapabilities::PROTOCOL_VERSION,
                profile.id(),
            )
        });
        if dsts.is_empty() {
            return self
                .send_multicast_with_routing_metric_and_attachments(
                    &legacy_dsts,
                    tag,
                    level,
                    routing_metric,
                    class,
                    body,
                    attachments.clone(),
                    options,
                )
                .await;
        }
        let level = profile.level();
        let routing_metric = profile.metric();
        let topology_epoch = self.inner.lsdb.distribution_epoch();
        let scope = distribution::TreeKey {
            source: self.inner.self_id,
            profile: profile.id(),
            group,
            group_version,
            topology_epoch,
            version: 0,
        };
        let routing = self.inner.routing.load_full();
        let routing_generation = routing.generation();
        let selected = if let Some(cached) = self
            .inner
            .distribution
            .cached_candidate(scope, routing_generation)
        {
            cached
        } else {
            self.inner
                .distribution
                .prepare_routing_generation(scope, routing_generation);
            let excluded = self.inner.distribution.failed_edges(scope);
            let mut tree_dsts = dsts.clone();
            let state = loop {
                let edges = routing.multicast_tree_edges_avoiding(
                    self.inner.self_id,
                    &tree_dsts,
                    level,
                    routing_metric,
                    &excluded,
                );
                let state = distribution::TreeState::new(
                    self.inner.self_id,
                    tree_dsts.iter().copied(),
                    edges,
                )
                .with_hop_ttl(options.transport_ttl().unwrap_or(DISTRIBUTION_HOP_TTL));
                let incompatible_relays: Vec<_> = state
                    .nodes()
                    .filter(|node| {
                        *node != self.inner.self_id
                            && !self.inner.lsdb.supports_distribution_profile(
                                *node,
                                crate::overlay::lsdb::DistributionCapabilities::PROTOCOL_VERSION,
                                profile.id(),
                            )
                    })
                    .collect();
                let uncovered: HashSet<_> = tree_dsts
                    .iter()
                    .copied()
                    .filter(|recipient| !state.is_reachable_from(self.inner.self_id, *recipient))
                    .collect();
                if incompatible_relays.is_empty() && uncovered.is_empty() {
                    break state;
                }
                let mut affected: HashSet<_> = incompatible_relays
                    .into_iter()
                    .flat_map(|relay| state.descendant_members(relay))
                    .collect();
                affected.extend(uncovered);
                if affected.is_empty() {
                    break state;
                }
                tree_dsts.retain(|recipient| !affected.contains(recipient));
                legacy_dsts.extend(affected);
                legacy_dsts.sort_unstable();
                legacy_dsts.dedup();
                if tree_dsts.is_empty() {
                    return self
                        .send_multicast_with_routing_metric_and_attachments(
                            &legacy_dsts,
                            tag,
                            level,
                            routing_metric,
                            class,
                            body,
                            attachments.clone(),
                            options,
                        )
                        .await;
                }
            };
            let recipient_path_cost = tree_dsts
                .iter()
                .filter_map(|recipient| {
                    routing
                        .lookup_with_metric(*recipient, level, routing_metric)
                        .map(|route| route.cost)
                })
                .fold(0_u64, u64::saturating_add);
            let key = distribution::TreeKey {
                version: distribution::tree_version(
                    self.inner.self_id,
                    profile.id(),
                    group,
                    group_version,
                    topology_epoch,
                    &state,
                ),
                ..scope
            };
            let Some(selected) = self.inner.distribution.stage_candidate_with_legacy(
                key,
                state,
                recipient_path_cost,
                routing_generation,
                legacy_dsts.iter().copied().collect(),
            ) else {
                distribution_metrics::record_compatibility_fallback_with_context(
                    distribution_metrics::DistributionMetricContext::new(
                        profile.id(),
                        tag,
                        self.inner.self_id,
                        Some(group),
                        distribution_metrics::EdgeDirection::Local,
                    ),
                    "invalid_tree",
                );
                let mut fallback_dsts = dsts.clone();
                fallback_dsts.extend(legacy_dsts.iter().copied());
                return self
                    .send_multicast_with_routing_metric_and_attachments(
                        &fallback_dsts,
                        tag,
                        level,
                        routing_metric,
                        class,
                        body,
                        attachments.clone(),
                        options,
                    )
                    .await;
            };
            selected
        };
        legacy_dsts = selected.legacy_members().iter().copied().collect();
        legacy_dsts.sort_unstable();
        let key = selected.key();
        let state = selected.state().clone();
        if self.inner.distribution.get(key).is_none() {
            self.inner.distribution.install(key, (*state).clone());
        }
        let active = self.inner.distribution.active_tree(scope);
        if active.as_ref().map(distribution::SelectedTree::key) != Some(key) {
            let peers: Vec<_> = state
                .nodes()
                .filter(|node| *node != self.inner.self_id)
                .collect();
            if self
                .inner
                .distribution
                .begin_publish(key, peers.iter().copied())
            {
                tracing::debug!(
                    source = %self.inner.self_id,
                    profile = profile.id(),
                    group,
                    group_version,
                    topology_epoch,
                    tree_version = key.version,
                    recipients = dsts.len(),
                    tree_nodes = peers.len(),
                    "publishing distribution tree"
                );
                let overlay = self.clone();
                let control = distribution::encode_install(key, &state);
                let mut peer_rtts: Vec<_> = peers
                    .iter()
                    .filter_map(|peer| {
                        routing
                            .lookup_with_metric(*peer, level, routing_metric)
                            .map(|route| Duration::from_micros(route.latency_us))
                    })
                    .collect();
                peer_rtts.sort_unstable();
                let p95_index = peer_rtts
                    .len()
                    .saturating_mul(95)
                    .div_ceil(100)
                    .saturating_sub(1);
                let p95 = peer_rtts
                    .get(p95_index)
                    .copied()
                    .unwrap_or(Duration::from_millis(200));
                let retry_delay = (p95.saturating_mul(2) + Duration::from_millis(100))
                    .clamp(Duration::from_millis(500), Duration::from_secs(3));
                let candidate_lifetime = Duration::from_secs(10).max(retry_delay.saturating_mul(4));
                tokio::spawn(async move {
                    let deadline = Instant::now() + candidate_lifetime;
                    loop {
                        let missing = overlay.inner.distribution.pending_peers(key);
                        if missing.is_empty() {
                            return;
                        }
                        let sends = missing.into_iter().map(|peer| {
                            let overlay = overlay.clone();
                            let control = control.clone();
                            async move {
                                let _ = overlay
                                    .send_unicast_unordered_with_routing_metric(
                                        peer,
                                        distribution::DISTRIBUTION_CONTROL_SERVICE_TAG,
                                        ServiceLevel::ReliableLowLatency,
                                        RoutingMetric::ReliableLowLatencyCost,
                                        MessageClass::Control,
                                        control,
                                    )
                                    .await;
                            }
                        });
                        join_all(sends).await;
                        if Instant::now() >= deadline {
                            distribution_metrics::record_candidate_build(
                                key.profile,
                                "ack_timeout",
                            );
                            overlay.inner.distribution.expire_candidate(key);
                            return;
                        }
                        tokio::time::sleep(retry_delay).await;
                    }
                });
            }
            if active.is_none() {
                distribution_metrics::record_compatibility_fallback_with_context(
                    distribution_metrics::DistributionMetricContext::new(
                        profile.id(),
                        tag,
                        self.inner.self_id,
                        Some(group),
                        distribution_metrics::EdgeDirection::Local,
                    ),
                    "tree_pending",
                );
                let mut fallback_dsts = dsts.clone();
                fallback_dsts.extend(legacy_dsts.iter().copied());
                return self
                    .send_multicast_with_routing_metric_and_attachments(
                        &fallback_dsts,
                        tag,
                        level,
                        routing_metric,
                        class,
                        body,
                        attachments.clone(),
                        options,
                    )
                    .await;
            }
        }
        let active = self
            .inner
            .distribution
            .active_tree(scope)
            .expect("distribution candidate activated or prior active retained");
        let tree_send =
            messaging::send_multicast_tree_unordered_with_routing_metric_and_attachments(
                &self.inner.transport,
                &self.inner.routing,
                &self.inner.distribution,
                &self.inner.neighbor,
                self.inner.self_id,
                self.inner.boot_epoch,
                self.inner.ordering(),
                active.state(),
                active.key(),
                tag,
                level,
                routing_metric,
                class,
                body.clone(),
                attachments.clone(),
                options,
            );
        if legacy_dsts.is_empty() {
            return tree_send.await;
        }
        let legacy_send = self.send_multicast_with_routing_metric_and_attachments(
            &legacy_dsts,
            tag,
            level,
            routing_metric,
            class,
            body,
            attachments,
            options,
        );
        let (tree_result, legacy_result) = tokio::join!(tree_send, legacy_send);
        tree_result?;
        legacy_result
    }

    /// Send to every alive peer.
    pub async fn send_broadcast(
        &self,
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        self.send_broadcast_with_options(tag, level, class, body, OverlaySendOptions::default())
            .await
    }

    /// Send to every alive peer with send options.
    pub async fn send_broadcast_with_options(
        &self,
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
        options: OverlaySendOptions,
    ) -> Result<(), OverlayError> {
        let alive = self.alive_members();
        messaging::send_broadcast_with_options(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            &alive,
            tag,
            level,
            class,
            body,
            options,
        )
        .await
    }

    /// Send to every alive peer without opting into an ordered overlay lane.
    pub async fn send_broadcast_unordered_with_routing_metric(
        &self,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        self.send_broadcast_unordered_with_routing_metric_and_options(
            tag,
            level,
            routing_metric,
            class,
            body,
            OverlaySendOptions::default(),
        )
        .await
    }

    /// Send to every alive peer without an ordered lane, using an explicit metric and send options.
    pub async fn send_broadcast_unordered_with_routing_metric_and_options(
        &self,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
        options: OverlaySendOptions,
    ) -> Result<(), OverlayError> {
        let alive = self.alive_members();
        messaging::send_broadcast_with_routing_metric_unordered_and_options(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            &alive,
            tag,
            level,
            routing_metric,
            class,
            body,
            false,
            options,
        )
        .await
    }

    /// Send to every alive peer and also deliver to matching services on transit nodes.
    pub async fn send_broadcast_with_transit_processing(
        &self,
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        let alive = self.alive_members();
        messaging::send_broadcast_with_transit_processing(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            &alive,
            tag,
            level,
            class,
            body,
            true,
        )
        .await
    }

    /// Send to every alive peer with an explicit routing metric and also
    /// deliver to matching services on transit nodes.
    pub async fn send_broadcast_with_routing_metric_and_transit_processing(
        &self,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        let alive = self.alive_members();
        messaging::send_broadcast_with_routing_metric_and_transit_processing(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            &alive,
            tag,
            level,
            routing_metric,
            class,
            body,
            true,
        )
        .await
    }

    /// Send to every alive peer with an explicit routing metric.
    pub async fn send_broadcast_with_routing_metric(
        &self,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        let alive = self.alive_members();
        messaging::send_broadcast_with_routing_metric_and_transit_processing(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            &alive,
            tag,
            level,
            routing_metric,
            class,
            body,
            false,
        )
        .await
    }

    /// Send to every alive peer on an ordered overlay lane.
    pub async fn send_broadcast_on_lane(
        &self,
        lane: LaneId,
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        self.send_broadcast_on_lane_with_options(
            lane,
            tag,
            level,
            class,
            body,
            OverlaySendOptions::default(),
        )
        .await
    }

    /// Send to every alive peer on an ordered overlay lane with send options.
    pub async fn send_broadcast_on_lane_with_options(
        &self,
        lane: LaneId,
        tag: u32,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
        options: OverlaySendOptions,
    ) -> Result<(), OverlayError> {
        self.send_broadcast_on_lane_with_routing_metric_and_options(
            lane,
            tag,
            level,
            RoutingMetric::default_for_level(level),
            class,
            body,
            options,
        )
        .await
    }

    /// Send to every alive peer on an ordered overlay lane with an explicit metric.
    pub async fn send_broadcast_on_lane_with_routing_metric(
        &self,
        lane: LaneId,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
    ) -> Result<(), OverlayError> {
        self.send_broadcast_on_lane_with_routing_metric_and_options(
            lane,
            tag,
            level,
            routing_metric,
            class,
            body,
            OverlaySendOptions::default(),
        )
        .await
    }

    /// Send to every alive peer on an ordered overlay lane with an explicit metric and send options.
    pub async fn send_broadcast_on_lane_with_routing_metric_and_options(
        &self,
        lane: LaneId,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
        options: OverlaySendOptions,
    ) -> Result<(), OverlayError> {
        let alive = self.alive_members();
        messaging::send_broadcast_on_lane_with_options(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            &alive,
            tag,
            level,
            routing_metric,
            class,
            body,
            lane,
            false,
            options,
        )
        .await
    }

    /// Send to every alive peer on an ordered overlay lane and optionally process on transit nodes.
    pub async fn send_broadcast_on_lane_with_routing_metric_and_transit_processing(
        &self,
        lane: LaneId,
        tag: u32,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
        class: MessageClass,
        body: Bytes,
        process_on_transit: bool,
    ) -> Result<(), OverlayError> {
        let alive = self.alive_members();
        messaging::send_broadcast_on_lane(
            &self.inner.transport,
            &self.inner.routing,
            self.inner.self_id,
            self.inner.boot_epoch,
            self.inner.ordering(),
            &alive,
            tag,
            level,
            routing_metric,
            class,
            body,
            lane,
            process_on_transit,
        )
        .await
    }

    /// Look up the next-hop for `dst` at `level`. Returns `None` if no
    /// route is known.
    pub fn route_to(&self, dst: NodeIdentifier, level: ServiceLevel) -> Option<NodeIdentifier> {
        self.inner
            .routing
            .load()
            .lookup(dst, level)
            .map(|e| e.next_hop)
    }

    /// Look up the next-hop for `dst` at `level` with an explicit routing
    /// metric. Returns `None` if no route is known.
    pub fn route_to_with_metric(
        &self,
        dst: NodeIdentifier,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
    ) -> Option<NodeIdentifier> {
        self.inner
            .routing
            .load()
            .lookup_with_metric(dst, level, routing_metric)
            .map(|e| e.next_hop)
    }

    pub fn voice_route_quality(&self, dst: NodeIdentifier) -> Option<VoiceRouteQuality> {
        let level = ServiceLevel::BestEffort;
        let routing_metric = RoutingMetric::ConversationalQuality;
        let entry = self
            .inner
            .routing
            .load()
            .lookup_with_metric(dst, level, routing_metric)?;
        let next_hop = entry.next_hop;
        let transport = self
            .inner
            .transport
            .ranked_live_transports_for(next_hop, level, routing_metric)
            .into_iter()
            .next()?;
        let metrics = self.inner.transport.metrics_snapshot();
        let link = metrics.for_node(next_hop)?.get(&transport)?;
        Some(VoiceRouteQuality::new(
            next_hop,
            transport,
            entry.latency_us,
            link.effective_packet_loss_ppm(),
            link.jitter_us().max(0.0) as u64,
        ))
    }

    /// Returns true if any route can satisfy `level` for `dst`.
    pub fn has_route(&self, dst: NodeIdentifier, level: ServiceLevel) -> bool {
        self.inner.routing.load().has_route(dst, level)
    }

    /// Returns true if a route exists and its next hop currently has a live
    /// transport that can carry `level`.
    pub fn has_live_route(&self, dst: NodeIdentifier, level: ServiceLevel) -> bool {
        self.has_live_route_with_metric(dst, level, RoutingMetric::default_for_level(level))
    }

    /// Returns true if any route can satisfy `level` for `dst` using an
    /// explicit routing metric.
    pub fn has_route_with_metric(
        &self,
        dst: NodeIdentifier,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
    ) -> bool {
        self.inner
            .routing
            .load()
            .has_route_with_metric(dst, level, routing_metric)
    }

    /// Returns true if a route exists for `routing_metric` and its next hop
    /// currently has a live transport that can carry `level`.
    pub fn has_live_route_with_metric(
        &self,
        dst: NodeIdentifier,
        level: ServiceLevel,
        routing_metric: RoutingMetric,
    ) -> bool {
        if dst == self.inner.self_id {
            return true;
        }
        let Some(next_hop) = self.route_to_with_metric(dst, level, routing_metric) else {
            return false;
        };
        !self
            .inner
            .transport
            .ranked_live_transports_for(next_hop, level, routing_metric)
            .is_empty()
    }

    /// Announce graceful leave (tombstone LSA flood) to every direct
    /// neighbor, then cancel internal tasks.
    pub async fn shutdown(&self) {
        self.inner.shutdown_graceful().await;
    }
}
