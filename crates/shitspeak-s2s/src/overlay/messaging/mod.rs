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
use shitspeak_s2s_transport::{ConnectionManager, MessageClass, ServiceLevel};

use self::ordering::OverlayOrdering;
use super::LaneId;
use super::distribution::{DistributionPlane, TreeKey, TreeState};
use super::error::OverlayError;
use super::neighbor::NeighborMonitor;
use super::routing::{RoutingHandle, RoutingMetric};

/// Inbound message handed to a registered service handler.
#[derive(Debug, Clone)]
pub struct OverlayInboundMessage {
    pub from: NodeIdentifier,
    pub level: ServiceLevel,
    pub class: MessageClass,
    pub body: Bytes,
    /// Source-installed remote playout baseline for a tree receiver. Legacy
    /// and non-voice services leave this unset.
    pub remote_playout_delay_ms: Option<u64>,
    /// This frame is the one permitted alternate copy for a failed
    /// distribution-tree child edge. It must retain that identity through
    /// voice reordering so remote playout never releases it after the media
    /// deadline.
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
            level,
            class,
            body,
            remote_playout_delay_ms: None,
            is_distribution_repair: false,
        }
    }

    /// Mark this as the alternate copy for a failed distribution-tree edge.
    /// The marker is consumed only by remote voice playout.
    pub fn with_distribution_repair(mut self, is_distribution_repair: bool) -> Self {
        self.is_distribution_repair = is_distribution_repair;
        self
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
#[allow(clippy::too_many_arguments)]
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
