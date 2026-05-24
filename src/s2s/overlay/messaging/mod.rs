//! Application-data path: send_unicast/multicast/broadcast,
//! per-next-hop forwarding with path-trace loop checking, service-tag
//! delivery registry.

pub mod delivery;
pub mod forward;
pub(crate) mod ordering;

use std::sync::Arc;

use bytes::Bytes;
use scc::HashMap as SccMap;

use crate::s2s::transport::{ConnectionManager, MessageClass, ServiceLevel};
use crate::types::NodeIdentifier;

use self::ordering::OverlayOrdering;
use super::error::OverlayError;
use super::routing::{RoutingHandle, RoutingMetric};
use super::LaneId;

/// Inbound message handed to a registered service handler.
#[derive(Debug, Clone)]
pub struct OverlayInboundMessage {
    pub from: NodeIdentifier,
    pub level: ServiceLevel,
    pub class: MessageClass,
    pub body: Bytes,
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

#[allow(clippy::too_many_arguments)]
pub async fn send_unicast(
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
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn send_unicast_with_transit_processing(
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
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn send_unicast_with_routing_metric_and_transit_processing(
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
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn send_unicast_on_lane(
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
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn send_unicast_with_routing_metric_unordered_and_transit_processing(
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
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn send_multicast(
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
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn send_multicast_with_transit_processing(
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
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn send_multicast_with_routing_metric_and_transit_processing(
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
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn send_multicast_on_lane(
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
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn send_multicast_with_routing_metric_unordered_and_transit_processing(
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
) -> Result<(), OverlayError> {
    let dsts: Vec<NodeIdentifier> = dsts.iter().copied().filter(|n| *n != self_id).collect();
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
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn send_broadcast(
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
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn send_broadcast_with_transit_processing(
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
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn send_broadcast_with_routing_metric_and_transit_processing(
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
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn send_broadcast_on_lane(
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
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn send_broadcast_with_routing_metric_unordered_and_transit_processing(
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
) -> Result<(), OverlayError> {
    let dsts: Vec<NodeIdentifier> = alive.iter().copied().filter(|n| *n != self_id).collect();
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
    )
    .await
}
