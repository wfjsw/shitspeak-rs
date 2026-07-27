//! Application-data path: send_unicast/multicast/broadcast,
//! per-next-hop forwarding with path-trace loop checking, service-tag
//! delivery registry.

pub mod delivery;
pub mod forward;
pub(crate) mod ordering;

use std::sync::Arc;

use bytes::Bytes;
use scc::HashMap as SccMap;

use shitspeak_core::NodeIdentifier;
use shitspeak_proto::s2s_overlay_proto as pb;
use shitspeak_s2s_transport::{ConnectionManager, MessageClass, ServiceLevel};

use self::ordering::OverlayOrdering;
use super::LaneId;
use super::distribution::{DistributionPlane, TreeKey, TreeState};
use super::error::OverlayError;
use super::neighbor::NeighborMonitor;
use super::routing::{RoutingHandle, RoutingMetric};

/// Reserved ordinary-unicast service tag for disposable attachment chunks.
pub const OVERLAY_ATTACHMENT_SERVICE_TAG: u32 = 252;

/// Opaque metadata attached to an overlay payload. Priority is local packing
/// policy and is not carried on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayAttachment {
    kind: u32,
    attachment_id: u64,
    priority: u32,
    payload: Bytes,
}

impl OverlayAttachment {
    pub fn new(kind: u32, attachment_id: u64, payload: Bytes) -> Self {
        Self {
            kind,
            attachment_id,
            priority: 0,
            payload,
        }
    }

    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    pub fn kind(&self) -> u32 {
        self.kind
    }

    pub fn attachment_id(&self) -> u64 {
        self.attachment_id
    }

    pub fn priority(&self) -> u32 {
        self.priority
    }

    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    pub(crate) fn to_proto(&self) -> pb::OverlayAttachment {
        pb::OverlayAttachment {
            kind: self.kind,
            attachment_id: self.attachment_id,
            payload: self.payload.to_vec(),
        }
    }
}

/// Inbound message handed to a registered service handler.
#[derive(Debug, Clone)]
pub struct OverlayInboundMessage {
    pub from: NodeIdentifier,
    /// Boot epoch asserted by the logical origin in the overlay envelope.
    /// A relay can carry this value but cannot authenticate it by itself;
    /// security-sensitive services must require their own origin-bound proof.
    pub(crate) origin_boot_epoch: u64,
    pub level: ServiceLevel,
    pub class: MessageClass,
    pub body: Bytes,
    /// Reserved compatibility metadata from older tree delivery versions.
    /// New delivery paths leave it unset and must not use it for timing.
    pub remote_playout_delay_ms: Option<u64>,
    /// This frame is a voice repair copy. It must retain that identity through
    /// voice reordering so an already-resolved gap cannot be reopened by a
    /// late NACK replay or alternate distribution-tree copy.
    pub(crate) is_distribution_repair: bool,
}

impl OverlayInboundMessage {
    /// Build an ordinary inbound message. Distribution metadata is opt-in so
    /// non-tree services never need to know about voice repair handling.
    pub fn new(
        from: NodeIdentifier,
        level: ServiceLevel,
        class: MessageClass,
        body: Bytes,
    ) -> Self {
        Self {
            from,
            origin_boot_epoch: 0,
            level,
            class,
            body,
            remote_playout_delay_ms: None,
            is_distribution_repair: false,
        }
    }

    /// Mark this as a voice repair copy for S2S reordering.
    pub fn with_distribution_repair(mut self, is_distribution_repair: bool) -> Self {
        self.is_distribution_repair = is_distribution_repair;
        self
    }

    /// Boot epoch asserted by the overlay envelope for the logical origin.
    /// This is metadata, not an authenticated origin credential.
    pub fn origin_boot_epoch(&self) -> u64 {
        self.origin_boot_epoch
    }
}

/// Trait implemented by L3 services (replications, etc) to receive
/// `OverlayData` payloads tagged with their `service_tag`.
///
/// **Convention**: the handler runs synchronously on the overlay's
/// inbound dispatcher; it MUST return quickly. Push the payload onto an
/// internal mpsc and let a separate task do real work.
pub trait ServiceInbound: Send + Sync + 'static {
    fn handle(&self, msg: OverlayInboundMessage);
}

/// Service-tag → handler registry.
pub struct ServiceRegistry {
    inner: SccMap<u32, Arc<dyn ServiceInbound>>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self {
            inner: SccMap::new(),
        }
    }

    pub fn register(&self, tag: u32, h: Arc<dyn ServiceInbound>) {
        // Insert/replace.
        let _ = self.inner.remove_sync(&tag);
        let _ = self.inner.insert_sync(tag, h);
    }

    pub fn unregister(&self, tag: u32) {
        let _ = self.inner.remove_sync(&tag);
    }

    pub fn get(&self, tag: u32) -> Option<Arc<dyn ServiceInbound>> {
        self.inner.get_sync(&tag).map(|e| e.get().clone())
    }
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OverlaySendOptions {
    allow_l1_compression: bool,
    transport_ttl: Option<std::time::Duration>,
    avoid_first_hop: Option<NodeIdentifier>,
    distribution_repair: bool,
    retained_logical_send: Option<[u8; 32]>,
}

impl OverlaySendOptions {
    pub fn allow_l1_compression(mut self) -> Self {
        self.allow_l1_compression = true;
        self
    }

    pub fn l1_compression_allowed(&self) -> bool {
        self.allow_l1_compression
    }

    pub fn expire_after(mut self, ttl: std::time::Duration) -> Self {
        self.transport_ttl = Some(ttl);
        self
    }

    pub fn transport_ttl(&self) -> Option<std::time::Duration> {
        self.transport_ttl
    }

    pub fn avoid_first_hop(mut self, node: NodeIdentifier) -> Self {
        self.avoid_first_hop = Some(node);
        self
    }

    pub fn avoided_first_hop(&self) -> Option<NodeIdentifier> {
        self.avoid_first_hop
    }

    /// Mark an ordinary overlay send as an application repair copy.
    ///
    /// This maps to the existing `OverlayData.distribution_repair` wire bit
    /// without adding a protocol field. Distribution-tree alternate repairs
    /// continue to set the bit internally with their target metadata.
    pub fn as_distribution_repair(mut self) -> Self {
        self.distribution_repair = true;
        self
    }

    pub fn is_distribution_repair(&self) -> bool {
        self.distribution_repair
    }

    /// Identify one logical ordered Reliable send whose delivery is already
    /// owned by the overlay until its end-to-end ACK arrives.
    pub(crate) fn retain_logical_send(mut self, identity: [u8; 32]) -> Self {
        self.retained_logical_send = Some(identity);
        self
    }

    pub(crate) fn retained_logical_send(&self) -> Option<[u8; 32]> {
        self.retained_logical_send
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_unicast_with_options(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dst: NodeIdentifier,
    tag: u32,
    level: ServiceLevel,
    class: MessageClass,
    body: Bytes,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    send_unicast_with_routing_metric_lane_and_transit_processing(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        dst,
        tag,
        level,
        RoutingMetric::default_for_level(level),
        class,
        body,
        None,
        false,
        options,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_unicast_unordered_with_routing_metric_and_attachments(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dst: NodeIdentifier,
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    process_on_transit: bool,
    attachments: Vec<OverlayAttachment>,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    forward::originate_with_attachments(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        vec![dst],
        tag,
        level,
        routing_metric,
        class,
        body,
        None,
        process_on_transit,
        attachments,
        options,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_unicast_with_transit_processing(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dst: NodeIdentifier,
    tag: u32,
    level: ServiceLevel,
    class: MessageClass,
    body: Bytes,
    process_on_transit: bool,
) -> Result<(), OverlayError> {
    send_unicast_with_routing_metric_lane_and_transit_processing(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        dst,
        tag,
        level,
        RoutingMetric::default_for_level(level),
        class,
        body,
        None,
        process_on_transit,
        OverlaySendOptions::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_unicast_with_routing_metric_and_transit_processing(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dst: NodeIdentifier,
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    process_on_transit: bool,
) -> Result<(), OverlayError> {
    send_unicast_with_routing_metric_lane_and_transit_processing(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        dst,
        tag,
        level,
        routing_metric,
        class,
        body,
        None,
        process_on_transit,
        OverlaySendOptions::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_unicast_on_lane(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dst: NodeIdentifier,
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    lane: LaneId,
    process_on_transit: bool,
) -> Result<(), OverlayError> {
    send_unicast_on_lane_with_options(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        dst,
        tag,
        level,
        routing_metric,
        class,
        body,
        lane,
        process_on_transit,
        OverlaySendOptions::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_unicast_on_lane_with_options(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dst: NodeIdentifier,
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    lane: LaneId,
    process_on_transit: bool,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    send_unicast_with_routing_metric_lane_and_transit_processing(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        dst,
        tag,
        level,
        routing_metric,
        class,
        body,
        Some(lane),
        process_on_transit,
        options,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_unicast_with_routing_metric_unordered_and_options(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dst: NodeIdentifier,
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    process_on_transit: bool,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    send_unicast_with_routing_metric_lane_and_transit_processing(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        dst,
        tag,
        level,
        routing_metric,
        class,
        body,
        None,
        process_on_transit,
        options,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn send_unicast_with_routing_metric_lane_and_transit_processing(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dst: NodeIdentifier,
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    lane: Option<LaneId>,
    process_on_transit: bool,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    forward::originate(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        vec![dst],
        tag,
        level,
        routing_metric,
        class,
        body,
        lane,
        process_on_transit,
        options,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_multicast_with_options(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dsts: &[NodeIdentifier],
    tag: u32,
    level: ServiceLevel,
    class: MessageClass,
    body: Bytes,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    send_multicast_with_routing_metric_lane_and_transit_processing(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        dsts,
        tag,
        level,
        RoutingMetric::default_for_level(level),
        class,
        body,
        None,
        false,
        options,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_multicast_with_routing_metric_unordered_and_attachments(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dsts: &[NodeIdentifier],
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    process_on_transit: bool,
    attachments: Vec<OverlayAttachment>,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    forward::originate_with_attachments(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        dsts.to_vec(),
        tag,
        level,
        routing_metric,
        class,
        body,
        None,
        process_on_transit,
        attachments,
        options,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_multicast_with_transit_processing(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dsts: &[NodeIdentifier],
    tag: u32,
    level: ServiceLevel,
    class: MessageClass,
    body: Bytes,
    process_on_transit: bool,
) -> Result<(), OverlayError> {
    send_multicast_with_routing_metric_lane_and_transit_processing(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        dsts,
        tag,
        level,
        RoutingMetric::default_for_level(level),
        class,
        body,
        None,
        process_on_transit,
        OverlaySendOptions::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_multicast_with_routing_metric_and_transit_processing(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dsts: &[NodeIdentifier],
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    process_on_transit: bool,
) -> Result<(), OverlayError> {
    send_multicast_with_routing_metric_lane_and_transit_processing(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        dsts,
        tag,
        level,
        routing_metric,
        class,
        body,
        None,
        process_on_transit,
        OverlaySendOptions::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_multicast_on_lane(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dsts: &[NodeIdentifier],
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    lane: LaneId,
    process_on_transit: bool,
) -> Result<(), OverlayError> {
    send_multicast_on_lane_with_options(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        dsts,
        tag,
        level,
        routing_metric,
        class,
        body,
        lane,
        process_on_transit,
        OverlaySendOptions::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_multicast_on_lane_with_options(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dsts: &[NodeIdentifier],
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    lane: LaneId,
    process_on_transit: bool,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    send_multicast_with_routing_metric_lane_and_transit_processing(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        dsts,
        tag,
        level,
        routing_metric,
        class,
        body,
        Some(lane),
        process_on_transit,
        options,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_multicast_with_routing_metric_unordered_and_options(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dsts: &[NodeIdentifier],
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    process_on_transit: bool,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    send_multicast_with_routing_metric_lane_and_transit_processing(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        dsts,
        tag,
        level,
        routing_metric,
        class,
        body,
        None,
        process_on_transit,
        options,
    )
    .await
}

/// Send an unordered multicast using a source-rooted forwarding tree.
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) async fn send_multicast_tree_unordered_with_routing_metric_and_options(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    distribution: &DistributionPlane,
    monitor: &NeighborMonitor,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    tree: &TreeState,
    key: TreeKey,
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    forward::originate_tree(
        transport,
        routing,
        distribution,
        monitor,
        self_id,
        boot_epoch,
        ordering,
        tree,
        key,
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_multicast_tree_unordered_with_routing_metric_and_attachments(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    distribution: &DistributionPlane,
    monitor: &NeighborMonitor,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    tree: &TreeState,
    key: TreeKey,
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    attachments: Vec<OverlayAttachment>,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    forward::originate_tree_with_attachments(
        transport,
        routing,
        distribution,
        monitor,
        self_id,
        boot_epoch,
        ordering,
        tree,
        key,
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

#[allow(clippy::too_many_arguments)]
async fn send_multicast_with_routing_metric_lane_and_transit_processing(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dsts: &[NodeIdentifier],
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    lane: Option<LaneId>,
    process_on_transit: bool,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    let dsts: Vec<NodeIdentifier> = dsts.iter().filter(|n| **n != self_id).copied().collect();
    forward::originate(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        dsts,
        tag,
        level,
        routing_metric,
        class,
        body,
        lane,
        process_on_transit,
        options,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_broadcast_with_options(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    alive: &[NodeIdentifier],
    tag: u32,
    level: ServiceLevel,
    class: MessageClass,
    body: Bytes,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    send_broadcast_with_routing_metric_lane_and_transit_processing(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        alive,
        tag,
        level,
        RoutingMetric::default_for_level(level),
        class,
        body,
        None,
        false,
        options,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_broadcast_with_transit_processing(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    alive: &[NodeIdentifier],
    tag: u32,
    level: ServiceLevel,
    class: MessageClass,
    body: Bytes,
    process_on_transit: bool,
) -> Result<(), OverlayError> {
    send_broadcast_with_routing_metric_lane_and_transit_processing(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        alive,
        tag,
        level,
        RoutingMetric::default_for_level(level),
        class,
        body,
        None,
        process_on_transit,
        OverlaySendOptions::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_broadcast_with_routing_metric_and_transit_processing(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    alive: &[NodeIdentifier],
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    process_on_transit: bool,
) -> Result<(), OverlayError> {
    send_broadcast_with_routing_metric_lane_and_transit_processing(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        alive,
        tag,
        level,
        routing_metric,
        class,
        body,
        None,
        process_on_transit,
        OverlaySendOptions::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_broadcast_on_lane(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    alive: &[NodeIdentifier],
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    lane: LaneId,
    process_on_transit: bool,
) -> Result<(), OverlayError> {
    send_broadcast_on_lane_with_options(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        alive,
        tag,
        level,
        routing_metric,
        class,
        body,
        lane,
        process_on_transit,
        OverlaySendOptions::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_broadcast_on_lane_with_options(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    alive: &[NodeIdentifier],
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    lane: LaneId,
    process_on_transit: bool,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    send_broadcast_with_routing_metric_lane_and_transit_processing(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        alive,
        tag,
        level,
        routing_metric,
        class,
        body,
        Some(lane),
        process_on_transit,
        options,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_broadcast_with_routing_metric_unordered_and_options(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    alive: &[NodeIdentifier],
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    process_on_transit: bool,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    send_broadcast_with_routing_metric_lane_and_transit_processing(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        alive,
        tag,
        level,
        routing_metric,
        class,
        body,
        None,
        process_on_transit,
        options,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn send_broadcast_with_routing_metric_lane_and_transit_processing(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    alive: &[NodeIdentifier],
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    lane: Option<LaneId>,
    process_on_transit: bool,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    let dsts: Vec<NodeIdentifier> = alive.iter().filter(|n| **n != self_id).copied().collect();
    if dsts.is_empty() {
        return Ok(());
    }
    forward::originate(
        transport,
        routing,
        self_id,
        boot_epoch,
        ordering,
        dsts,
        tag,
        level,
        routing_metric,
        class,
        body,
        lane,
        process_on_transit,
        options,
    )
    .await
}
