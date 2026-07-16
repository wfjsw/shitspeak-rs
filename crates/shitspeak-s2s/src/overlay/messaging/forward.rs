//! Routing-aware forwarding for `OverlayData` and ordered-lane repair control.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::future::join_all;
use prost::Message as _;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::application::proto::VOICE_SERVICE_TAG;
use crate::overlay::LaneId;
use crate::overlay::attachments::{AttachmentCache, AttachmentKey, TREE_HINT_ATTACHMENT_KIND};
use crate::overlay::config::OverlayConfig;
use crate::overlay::distribution::{
    DistributionPlane, PendingDistributionFrame, TreeKey, TreeState, UnknownTreeEnqueue,
};
use crate::overlay::neighbor::NeighborMonitor;
use shitspeak_core::NodeIdentifier;
use shitspeak_proto::s2s_overlay_proto as pb;
use shitspeak_s2s_transport::{
    ConnectionManager, MessageClass, SendError, SendOptions as TransportSendOptions, ServiceLevel,
    TransportKind, TransportPayloadPlan, TransportPayloadVariant,
};

use super::super::OverlayNetwork;
use super::super::error::OverlayError;
use super::super::proto::{
    OverlayBody, OverlayControlBody, class_from_wire, class_to_wire, encode_message,
    level_from_wire, level_to_wire, node_to_wire, route_metric_from_wire, route_metric_to_wire,
    wrap,
};
use super::super::routing::{RoutingHandle, RoutingMetric, RoutingTables};
use super::delivery;
use super::ordering::OverlayOrdering;
use super::{OverlayAttachment, OverlaySendOptions, ServiceRegistry};

const FORWARD_PAYLOAD_LOG_BYTES: usize = 256;
const CONTROL_LEVEL: ServiceLevel = ServiceLevel::ReliableLowLatency;
const CONTROL_METRIC: RoutingMetric = RoutingMetric::ReliableLowLatencyCost;
const VOICE_TRANSPORT_TTL: Duration = Duration::from_millis(750);
const DISTRIBUTION_PROCESSING_GUARD: Duration = Duration::from_millis(20);
const MAX_ATTACHMENT_BYTES: usize = 256 * 1024;
const MAX_ATTACHMENT_CHUNKS: usize = 512;
const MAX_ATTACHMENT_CHUNK_BYTES: usize = 512;

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn unix_time_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .min(u128::from(u64::MAX)) as u64
}

fn distribution_remaining_deadline(data: &pb::OverlayData) -> Option<Duration> {
    if let Some(deadline) = data.distribution_deadline_unix_us {
        let remaining = deadline.checked_sub(unix_time_us())?;
        return Some(Duration::from_micros(remaining));
    }
    legacy_distribution_remaining_deadline(data.distribution_deadline_unix_ms?, unix_time_ms())
}

fn legacy_distribution_remaining_deadline(
    deadline_unix_ms: u64,
    now_unix_ms: u64,
) -> Option<Duration> {
    deadline_unix_ms
        .checked_sub(now_unix_ms)
        .map(Duration::from_millis)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DistributionDeadlineError {
    Expired,
    MissingOffset,
    IssuerMismatch,
}

fn rebase_deadline_us(peer_deadline_us: u64, peer_ahead_us: i64) -> Option<u64> {
    u64::try_from(i128::from(peer_deadline_us) - i128::from(peer_ahead_us)).ok()
}

fn remaining_after_clock_guard(
    local_deadline_us: u64,
    local_now_us: u64,
    uncertainty: Duration,
) -> Result<Duration, DistributionDeadlineError> {
    let remaining_us = local_deadline_us
        .checked_sub(local_now_us)
        .ok_or(DistributionDeadlineError::Expired)?;
    let remaining = Duration::from_micros(remaining_us);
    let guard = uncertainty.saturating_add(DISTRIBUTION_PROCESSING_GUARD);
    (remaining > guard)
        .then_some(remaining.saturating_sub(guard))
        .ok_or(DistributionDeadlineError::Expired)
}

fn translate_v2_deadline_for_local_hop(
    data: &mut pb::OverlayData,
    monitor: &NeighborMonitor,
    self_id: NodeIdentifier,
    from: NodeIdentifier,
) -> Result<Duration, DistributionDeadlineError> {
    let issuer = data
        .distribution_deadline_issuer
        .and_then(|issuer| NodeIdentifier::try_from(issuer).ok())
        .ok_or(DistributionDeadlineError::IssuerMismatch)?;
    let peer_deadline_us = data
        .distribution_deadline_unix_us
        .ok_or(DistributionDeadlineError::IssuerMismatch)?;
    if issuer == self_id {
        let remaining = peer_deadline_us
            .checked_sub(unix_time_us())
            .ok_or(DistributionDeadlineError::Expired)?;
        return (remaining > 0)
            .then_some(Duration::from_micros(remaining))
            .ok_or(DistributionDeadlineError::Expired);
    }
    if issuer != from {
        return Err(DistributionDeadlineError::IssuerMismatch);
    }
    let offset = monitor
        .peer_clock_offset(from)
        .ok_or(DistributionDeadlineError::MissingOffset)?;
    // `peer_ahead_us` is peer_clock - local_clock. Convert the peer-issued
    // timestamp into this node's clock before making this node the issuer.
    let local_deadline_us = rebase_deadline_us(peer_deadline_us, offset.peer_ahead_us())
        .ok_or(DistributionDeadlineError::Expired)?;
    let remaining =
        remaining_after_clock_guard(local_deadline_us, unix_time_us(), offset.uncertainty())?;
    data.distribution_deadline_issuer = Some(node_to_wire(self_id));
    data.distribution_deadline_unix_us = Some(local_deadline_us);
    // New frames must not be evaluated by the legacy millisecond deadline
    // rule after their issuer has been rebased.
    data.distribution_deadline_unix_ms = None;
    Ok(remaining)
}

fn inbound_distribution_deadline(
    data: &mut pb::OverlayData,
    monitor: &NeighborMonitor,
    self_id: NodeIdentifier,
    from: NodeIdentifier,
) -> Result<(Duration, bool), DistributionDeadlineError> {
    if data.distribution_deadline_unix_us.is_some() || data.distribution_deadline_issuer.is_some() {
        return translate_v2_deadline_for_local_hop(data, monitor, self_id, from)
            .map(|remaining| (remaining, true));
    }
    distribution_remaining_deadline(data)
        .map(|remaining| (remaining, false))
        .ok_or(DistributionDeadlineError::Expired)
}

fn report_deadline_failure(
    distribution: &DistributionPlane,
    data: &pb::OverlayData,
    self_id: NodeIdentifier,
) {
    let Some(key) = tree_key_from_data(data) else {
        return;
    };
    let Some(tree) = distribution.get(key) else {
        return;
    };
    let Some((parent, _)) = tree.edges().find(|(_, child)| *child == self_id) else {
        return;
    };
    distribution.report_edge_failure(key, parent, self_id);
}

fn distribution_metric_context(
    data: &pb::OverlayData,
    direction: crate::overlay::distribution_metrics::EdgeDirection,
) -> Option<crate::overlay::distribution_metrics::DistributionMetricContext> {
    Some(
        crate::overlay::distribution_metrics::DistributionMetricContext::new(
            data.distribution_profile?,
            data.service_tag,
            NodeIdentifier::try_from(data.src).ok()?,
            data.distribution_group,
            direction,
        ),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForwardNextHop {
    Send { next_hop: NodeIdentifier },
    DropAlreadyVisited,
    DropNoRoute,
    DropLoop { next_hop: NodeIdentifier },
}

fn payload_hex_preview(payload: &[u8]) -> String {
    let shown = payload.len().min(FORWARD_PAYLOAD_LOG_BYTES);
    let mut out = String::with_capacity(shown * 2 + 24);
    use std::fmt::Write as _;
    for byte in &payload[..shown] {
        let _ = write!(&mut out, "{byte:02x}");
    }
    if shown < payload.len() {
        let _ = write!(&mut out, "...(+{} bytes)", payload.len() - shown);
    }
    out
}

/// Build, encode, and dispatch outbound `OverlayData` originated locally.
pub(crate) async fn originate(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dsts: Vec<NodeIdentifier>,
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    lane: Option<LaneId>,
    process_on_transit: bool,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    originate_with_attachments(
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
        Vec::new(),
        options,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn originate_with_attachments(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    boot_epoch: u64,
    ordering: &OverlayOrdering,
    dsts: Vec<NodeIdentifier>,
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    lane: Option<LaneId>,
    process_on_transit: bool,
    attachments: Vec<OverlayAttachment>,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    let dsts: Vec<NodeIdentifier> = dsts.into_iter().filter(|dst| *dst != self_id).collect();
    if dsts.is_empty() {
        return Ok(());
    }

    let Some(lane) = lane else {
        let data = pb::OverlayData {
            src: node_to_wire(self_id),
            dsts: dsts.iter().map(|d| node_to_wire(*d)).collect(),
            path_trace: vec![node_to_wire(self_id)],
            service_tag: tag,
            service_level: level_to_wire(level),
            message_class: class_to_wire(class),
            payload: body,
            process_on_transit,
            route_metric: route_metric_to_wire(routing_metric),
            ordered_delivery: false,
            ordering_seq: 0,
            ordering_dst: 0,
            lane_id: None,
            origin_boot_epoch: boot_epoch,
            origin_message_id: ordering.next_origin_message_id(),
            allow_l1_compression: options.l1_compression_allowed() && tag != VOICE_SERVICE_TAG,
            distribution_profile: None,
            distribution_tree_version: None,
            distribution_group: None,
            distribution_group_version: None,
            distribution_topology_epoch: None,
            distribution_deadline_unix_ms: None,
            distribution_repair: options.is_distribution_repair(),
            distribution_repair_target: None,
            distribution_deadline_issuer: None,
            distribution_deadline_unix_us: None,
            inline_attachments: attachments_to_proto(&attachments),
        };
        return forward_pb_as(
            transport,
            routing,
            self_id,
            data,
            class,
            /*is_originator=*/ true,
            options.transport_ttl(),
            options.avoided_first_hop(),
        )
        .await;
    };

    let _send_guard = ordering.outbound_send_guard().await;
    ordering.activate_local_lane(lane).await;
    preflight_routes(routing, self_id, &dsts, level, routing_metric)?;
    ordering
        .can_store_pending(&dsts, lane)
        .await
        .map_err(|(dst, lane)| OverlayError::OrderedWindowFull {
            dst,
            lane: lane.get(),
        })?;

    let message_id = ordering.next_origin_message_id();
    let mut first_err = None;
    for dst in dsts {
        let seq = ordering.next_outbound_seq(dst, lane).await;
        let data = pb::OverlayData {
            src: node_to_wire(self_id),
            dsts: vec![node_to_wire(dst)],
            path_trace: vec![node_to_wire(self_id)],
            service_tag: tag,
            service_level: level_to_wire(level),
            message_class: class_to_wire(class),
            payload: body.clone(),
            process_on_transit,
            route_metric: route_metric_to_wire(routing_metric),
            ordered_delivery: true,
            ordering_seq: seq,
            ordering_dst: node_to_wire(dst),
            lane_id: Some(lane.get()),
            origin_boot_epoch: boot_epoch,
            origin_message_id: message_id,
            allow_l1_compression: options.l1_compression_allowed() && tag != VOICE_SERVICE_TAG,
            distribution_profile: None,
            distribution_tree_version: None,
            distribution_group: None,
            distribution_group_version: None,
            distribution_topology_epoch: None,
            distribution_deadline_unix_ms: None,
            distribution_repair: options.is_distribution_repair(),
            distribution_repair_target: None,
            distribution_deadline_issuer: None,
            distribution_deadline_unix_us: None,
            inline_attachments: attachments_to_proto(&attachments),
        };
        ordering.store_pending(lane, data.clone()).await;
        ordering.cache_ordered_packet(&data).await;
        if let Err(err) = forward_pb_as(
            transport,
            routing,
            self_id,
            data,
            class,
            /*is_originator=*/ true,
            options.transport_ttl(),
            options.avoided_first_hop(),
        )
        .await
        {
            if first_err.is_none() {
                first_err = Some(err);
            }
        }
    }

    if let Some(err) = first_err {
        return Err(err);
    }
    Ok(())
}

/// Originate an unordered source-rooted multicast tree after its control-plane
/// state has been acknowledged by every tree node.
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) async fn originate_tree(
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
    process_on_transit: bool,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    originate_tree_with_attachments(
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
        process_on_transit,
        Vec::new(),
        options,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn originate_tree_with_attachments(
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
    process_on_transit: bool,
    attachments: Vec<OverlayAttachment>,
    options: OverlaySendOptions,
) -> Result<(), OverlayError> {
    let uses_hop_local_ttl = tree.hop_ttl().is_some();
    let data = pb::OverlayData {
        src: node_to_wire(self_id),
        dsts: vec![],
        path_trace: vec![node_to_wire(self_id)],
        service_tag: tag,
        service_level: level_to_wire(level),
        message_class: class_to_wire(class),
        payload: body,
        process_on_transit,
        route_metric: route_metric_to_wire(routing_metric),
        ordered_delivery: false,
        ordering_seq: 0,
        ordering_dst: 0,
        lane_id: None,
        origin_boot_epoch: boot_epoch,
        origin_message_id: ordering.next_origin_message_id(),
        allow_l1_compression: options.l1_compression_allowed() && tag != VOICE_SERVICE_TAG,
        distribution_profile: Some(key.profile),
        distribution_tree_version: Some(key.version),
        distribution_group: Some(key.group),
        distribution_group_version: Some(key.group_version),
        distribution_topology_epoch: Some(key.topology_epoch),
        distribution_deadline_unix_ms: None,
        distribution_repair: false,
        distribution_repair_target: None,
        distribution_deadline_issuer: (!uses_hop_local_ttl).then_some(node_to_wire(self_id)),
        distribution_deadline_unix_us: (!uses_hop_local_ttl).then(|| {
            unix_time_us().saturating_add(
                options
                    .transport_ttl()
                    .unwrap_or(VOICE_TRANSPORT_TTL)
                    .as_micros()
                    .min(u128::from(u64::MAX)) as u64,
            )
        }),
        inline_attachments: attachments_to_proto(&attachments),
    };
    forward_tree_data(
        transport,
        routing,
        distribution,
        monitor,
        self_id,
        data,
        tree,
        class,
        options.transport_ttl(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_inbound_with_distribution(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    services: &ServiceRegistry,
    ordering: &OverlayOrdering,
    distribution: &DistributionPlane,
    attachments: &AttachmentCache,
    monitor: &NeighborMonitor,
    self_id: NodeIdentifier,
    from: NodeIdentifier,
    mut data: pb::OverlayData,
    route_transit_messages: bool,
) {
    if data.service_tag == super::OVERLAY_ATTACHMENT_SERVICE_TAG {
        if consume_attachment_sidecar(attachments, self_id, &data) {
            return;
        }
    }
    cache_inline_attachments(attachments, &data);
    let Some(profile) = data.distribution_profile else {
        return handle_inbound(
            transport,
            routing,
            services,
            ordering,
            self_id,
            from,
            data,
            route_transit_messages,
        )
        .await;
    };
    let metric_context = distribution_metric_context(
        &data,
        crate::overlay::distribution_metrics::EdgeDirection::Inbound,
    );
    let uses_wall_clock_deadline = data.distribution_deadline_unix_ms.is_some()
        || data.distribution_deadline_unix_us.is_some()
        || data.distribution_deadline_issuer.is_some();
    let (remaining_deadline, translated_v2) = if uses_wall_clock_deadline {
        match inbound_distribution_deadline(&mut data, monitor, self_id, from) {
            Ok(result) => result,
            Err(DistributionDeadlineError::Expired) => {
                if let Some(context) = metric_context {
                    crate::overlay::distribution_metrics::record_deadline_translation_with_context(
                        context, "expired",
                    );
                    crate::overlay::distribution_metrics::record_deadline_expiry_with_context(
                        context, "expired",
                    );
                }
                report_deadline_failure(distribution, &data, self_id);
                tracing::debug!(profile, %from, "dropping expired distribution frame");
                return;
            }
            Err(DistributionDeadlineError::MissingOffset) => {
                if let Some(context) = metric_context {
                    crate::overlay::distribution_metrics::record_deadline_translation_with_context(
                        context,
                        "missing_offset",
                    );
                    crate::overlay::distribution_metrics::record_clock_offset_fallback_with_context(
                        context,
                        "child_clock_unready",
                    );
                }
                report_deadline_failure(distribution, &data, self_id);
                tracing::debug!(profile, %from, "dropping distribution frame without fresh direct-peer clock offset");
                return;
            }
            Err(DistributionDeadlineError::IssuerMismatch) => {
                if let Some(context) = metric_context {
                    crate::overlay::distribution_metrics::record_deadline_translation_with_context(
                        context,
                        "issuer_mismatch",
                    );
                }
                tracing::debug!(profile, %from, "dropping distribution frame with a non-direct deadline issuer");
                return;
            }
        }
    } else {
        // Version 3 expiry is created locally when each adjacent tree edge is
        // enqueued. It does not consult or carry a wall clock.
        (VOICE_TRANSPORT_TTL, false)
    };
    if translated_v2 {
        if let Some(context) = metric_context {
            crate::overlay::distribution_metrics::record_deadline_translation_with_context(
                context,
                "translated",
            );
        }
    }
    let (Some(version), Some(group), Some(group_version), Some(topology_epoch)) = (
        data.distribution_tree_version,
        data.distribution_group,
        data.distribution_group_version,
        data.distribution_topology_epoch,
    ) else {
        return;
    };
    let Ok(source) = NodeIdentifier::try_from(data.src) else {
        return;
    };
    let key = TreeKey {
        source,
        profile,
        group,
        group_version,
        topology_epoch,
        version,
    };
    if data.distribution_repair {
        let Some(target) = data
            .distribution_repair_target
            .and_then(|target| NodeIdentifier::try_from(target).ok())
        else {
            return;
        };
        if self_id != target {
            data.dsts = vec![node_to_wire(target)];
            let class = class_from_wire(data.message_class).unwrap_or(MessageClass::Regular);
            let _ = forward_pb_as(
                transport,
                routing,
                self_id,
                data,
                class,
                false,
                Some(remaining_deadline),
                None,
            )
            .await;
            return;
        }
        data.dsts.clear();
        data.distribution_repair_target = None;
    }
    if let Some(tree_hop) = data
        .dsts
        .first()
        .and_then(|target| NodeIdentifier::try_from(*target).ok())
    {
        if tree_hop != self_id {
            if !route_transit_messages {
                return;
            }
            let class = class_from_wire(data.message_class).unwrap_or(MessageClass::Regular);
            let _ = forward_pb_as(
                transport,
                routing,
                self_id,
                data,
                class,
                false,
                Some(remaining_deadline),
                None,
            )
            .await;
            return;
        }
        // `dsts` carries just the logical tree child while the ordinary
        // overlay underlay routes this copy across physical hops.
        data.dsts.clear();
    }
    let tree = match distribution.get(key) {
        Some(tree) => tree,
        None if is_realtime_distribution_frame(&data) => {
            let Some(tree) = decode_tree_hint(&data, key, self_id, attachments) else {
                tracing::debug!(
                    %source,
                    profile,
                    group,
                    topology_epoch,
                    version,
                    "dropping cacheless realtime distribution branch without inline tree hint"
                );
                crate::overlay::attachment_metrics::record_cacheless_branch_drop();
                return;
            };
            Arc::new(tree)
        }
        None => match distribution.queue_unknown(
            key,
            PendingDistributionFrame::new(from, data, route_transit_messages),
            remaining_deadline.min(Duration::from_millis(20)),
        ) {
            UnknownTreeEnqueue::Queued => {
                tracing::debug!(%source, profile, group, topology_epoch, version, "queued frame while requesting exact distribution tree");
                return;
            }
            UnknownTreeEnqueue::Full => {
                tracing::debug!(%source, profile, group, topology_epoch, version, "dropping distribution frame because exact-state recovery queue is full");
                return;
            }
            UnknownTreeEnqueue::AlreadyInstalled(frame) => {
                let Some(tree) = distribution.get(key) else {
                    return;
                };
                return process_distribution_frame(
                    transport,
                    routing,
                    distribution,
                    monitor,
                    ordering,
                    services,
                    self_id,
                    source,
                    frame.data,
                    tree,
                    frame.route_transit_messages,
                    remaining_deadline,
                )
                .await;
            }
        },
    };
    process_distribution_frame(
        transport,
        routing,
        distribution,
        monitor,
        ordering,
        services,
        self_id,
        source,
        data,
        tree,
        route_transit_messages,
        remaining_deadline,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn process_distribution_frame(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    distribution: &DistributionPlane,
    monitor: &NeighborMonitor,
    ordering: &OverlayOrdering,
    services: &ServiceRegistry,
    self_id: NodeIdentifier,
    source: NodeIdentifier,
    data: pb::OverlayData,
    tree: Arc<TreeState>,
    route_transit_messages: bool,
    remaining_deadline: Duration,
) {
    let class = class_from_wire(data.message_class).unwrap_or(MessageClass::Regular);
    let level = level_from_wire(data.service_level).unwrap_or(ServiceLevel::Reliable);
    if tree.is_member(self_id)
        && ordering
            .should_deliver_unordered(
                source,
                data.origin_boot_epoch,
                data.origin_message_id,
                data.service_tag,
            )
            .await
    {
        // `remote_playout_delay_ms` remains part of the inbound message for
        // wire/API compatibility, but the server no longer paces remote voice.
        // S2S reordering is the only remote buffering policy.
        delivery::deliver_with_remote_playout(
            services,
            data.service_tag,
            source,
            level,
            class,
            data.payload.clone(),
            None,
            data.distribution_repair,
        );
    }
    if route_transit_messages {
        let _ = forward_tree_data(
            transport,
            routing,
            distribution,
            monitor,
            self_id,
            data,
            &tree,
            class,
            Some(remaining_deadline),
        )
        .await;
    }
}

/// Re-enter normal distribution delivery after an exact tree install drains a
/// bounded unknown-state queue. The handler revalidates the version and wire
/// deadline; it never substitutes a newer tree or group snapshot.
pub(crate) async fn replay_distribution_frame(
    overlay: OverlayNetwork,
    frame: PendingDistributionFrame,
) {
    handle_inbound_with_distribution(
        &overlay.inner.transport,
        &overlay.inner.routing,
        &overlay.inner.services,
        overlay.inner.ordering(),
        &overlay.inner.distribution,
        &overlay.inner.attachments,
        &overlay.inner.neighbor,
        overlay.inner.self_id,
        frame.from,
        frame.data,
        frame.route_transit_messages,
    )
    .await;
}

/// Handle an inbound `OverlayData`: deliver locally if applicable, forward the remainder.
pub(crate) async fn handle_inbound(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    services: &ServiceRegistry,
    ordering: &OverlayOrdering,
    self_id: NodeIdentifier,
    _from: NodeIdentifier,
    data: pb::OverlayData,
    route_transit_messages: bool,
) {
    ordering.cache_ordered_packet(&data).await;
    let class = class_from_wire(data.message_class).unwrap_or(MessageClass::Regular);
    let level = level_from_wire(data.service_level).unwrap_or(ServiceLevel::Reliable);
    let src = NodeIdentifier::try_from(data.src).unwrap_or(0);
    let lane = data.lane_id.and_then(|id| LaneId::try_from(id).ok());
    let is_for_self = data
        .dsts
        .iter()
        .any(|d| NodeIdentifier::try_from(*d).ok() == Some(self_id));

    if is_for_self {
        if let Some(lane) = lane {
            if NodeIdentifier::try_from(data.ordering_dst).ok() == Some(self_id) {
                if let Some(outcome) = ordering.accept_inbound(self_id, &data, level, class).await {
                    send_ack(
                        transport,
                        routing,
                        self_id,
                        &data,
                        lane,
                        outcome.ack_next_seq,
                    )
                    .await;
                    if let Some((first, last)) = outcome.nack {
                        send_repair_request(transport, routing, self_id, &data, lane, first, last)
                            .await;
                    }
                    for msg in outcome.ready {
                        delivery::deliver(
                            services,
                            msg.tag(),
                            msg.src(),
                            msg.level(),
                            msg.class(),
                            msg.body(),
                        );
                    }
                }
            }
        } else if ordering
            .should_deliver_unordered(
                src,
                data.origin_boot_epoch,
                data.origin_message_id,
                data.service_tag,
            )
            .await
        {
            delivery::deliver_with_remote_playout(
                services,
                data.service_tag,
                src,
                level,
                class,
                data.payload.clone(),
                None,
                data.distribution_repair,
            );
        }
    } else if data.process_on_transit && transit_local_processing_allowed(data.service_tag) {
        let should_deliver = if lane.is_some() {
            ordering
                .should_deliver_transit(
                    src,
                    data.origin_boot_epoch,
                    data.origin_message_id,
                    data.service_tag,
                )
                .await
        } else {
            ordering
                .should_deliver_unordered(
                    src,
                    data.origin_boot_epoch,
                    data.origin_message_id,
                    data.service_tag,
                )
                .await
        };
        if should_deliver {
            delivery::deliver(
                services,
                data.service_tag,
                src,
                level,
                class,
                data.payload.clone(),
            );
        }
    }

    let remaining: Vec<u32> = data
        .dsts
        .iter()
        .filter(|d| NodeIdentifier::try_from(**d).ok() != Some(self_id))
        .copied()
        .collect();
    if remaining.is_empty() {
        return;
    }
    if !route_transit_messages {
        debug!(
            remaining = remaining.len(),
            "S2S transit routing disabled; dropping overlay data for other nodes"
        );
        return;
    }
    let remaining = if lane.is_none() {
        ordering
            .filter_unforwarded_unordered(
                src,
                data.origin_boot_epoch,
                data.origin_message_id,
                data.service_tag,
                remaining,
            )
            .await
    } else {
        remaining
    };
    if remaining.is_empty() {
        return;
    }
    let mut data2 = data;
    data2.dsts = remaining;
    let _ = forward_pb_as(
        transport, routing, self_id, data2, class, /*is_originator=*/ false, None, None,
    )
    .await;
}

fn transit_local_processing_allowed(service_tag: u32) -> bool {
    service_tag != VOICE_SERVICE_TAG
}

pub(crate) async fn handle_control(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    services: &ServiceRegistry,
    ordering: &OverlayOrdering,
    self_id: NodeIdentifier,
    _from: NodeIdentifier,
    control: pb::OverlayControl,
) {
    let Ok(origin) = NodeIdentifier::try_from(control.origin) else {
        return;
    };
    let Ok(final_dst) = NodeIdentifier::try_from(control.final_dst) else {
        return;
    };
    let Ok(requester) = NodeIdentifier::try_from(control.requester) else {
        return;
    };
    let Ok(lane) = LaneId::try_from(control.lane_id) else {
        return;
    };

    match control.body.clone() {
        Some(OverlayControlBody::Ack(ack)) => {
            if origin == self_id {
                ordering.apply_ack(final_dst, lane, ack.next_seq).await;
            } else {
                let _ = send_control_to(transport, routing, self_id, origin, control).await;
            }
        }
        Some(OverlayControlBody::RepairRequest(req)) => {
            if req.last_seq < req.first_seq {
                return;
            }
            let expected = req.last_seq.saturating_sub(req.first_seq).saturating_add(1) as usize;
            if expected > ordering.max_repair_request_packets() {
                return;
            }
            let cached = ordering
                .cached_range(
                    origin,
                    control.origin_boot_epoch,
                    final_dst,
                    lane,
                    req.first_seq,
                    req.last_seq,
                )
                .await;
            let cached_len = cached.len();
            if !cached.is_empty() {
                let _ = send_repair_response(
                    transport,
                    routing,
                    self_id,
                    requester,
                    origin,
                    control.origin_boot_epoch,
                    final_dst,
                    lane,
                    cached,
                    false,
                )
                .await;
            }
            if cached_len >= expected {
                return;
            }
            if origin == self_id {
                let packets = ordering
                    .pending_range(final_dst, lane, req.first_seq, req.last_seq)
                    .await;
                let _ = send_repair_response(
                    transport,
                    routing,
                    self_id,
                    requester,
                    origin,
                    control.origin_boot_epoch,
                    final_dst,
                    lane,
                    packets.clone(),
                    packets.is_empty(),
                )
                .await;
            } else {
                let _ = send_control_to(transport, routing, self_id, origin, control).await;
            }
        }
        Some(OverlayControlBody::RepairResponse(resp)) => {
            if requester == self_id {
                for data in resp.packets {
                    handle_inbound(
                        transport, routing, services, ordering, self_id, origin, data, true,
                    )
                    .await;
                }
            } else {
                let _ = send_control_to(transport, routing, self_id, requester, control).await;
            }
        }
        None => {}
    }
}

pub(crate) fn spawn_ordered_retransmit_task(
    ordering: Arc<OverlayOrdering>,
    transport: ConnectionManager,
    routing: RoutingHandle,
    self_id: NodeIdentifier,
    cfg: OverlayConfig,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        let tick = cfg.ordered_ack_timeout().max(Duration::from_millis(10));
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = sleep(tick) => {
                    let due = ordering.due_retransmits(Instant::now()).await;
                    for data in due {
                        let class = class_from_wire(data.message_class).unwrap_or(MessageClass::Regular);
                        let _ = forward_pb_as(
                            &transport,
                            &routing,
                            self_id,
                            data,
                            class,
                            false,
                            None,
                            None,
                        )
                        .await;
                    }
                }
            }
        }
    });
}

async fn send_ack(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    data: &pb::OverlayData,
    lane: LaneId,
    next_seq: u64,
) {
    let Ok(origin) = NodeIdentifier::try_from(data.src) else {
        return;
    };
    let control = pb::OverlayControl {
        origin: data.src,
        origin_boot_epoch: data.origin_boot_epoch,
        final_dst: node_to_wire(self_id),
        lane_id: lane.get(),
        requester: node_to_wire(self_id),
        path_trace: vec![node_to_wire(self_id)],
        body: Some(OverlayControlBody::Ack(pb::OverlayAck { next_seq })),
    };
    let _ = send_control_to(transport, routing, self_id, origin, control).await;
}

async fn send_repair_request(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    data: &pb::OverlayData,
    lane: LaneId,
    first_seq: u64,
    last_seq: u64,
) {
    let Ok(origin) = NodeIdentifier::try_from(data.src) else {
        return;
    };
    let control = pb::OverlayControl {
        origin: data.src,
        origin_boot_epoch: data.origin_boot_epoch,
        final_dst: node_to_wire(self_id),
        lane_id: lane.get(),
        requester: node_to_wire(self_id),
        path_trace: vec![node_to_wire(self_id)],
        body: Some(OverlayControlBody::RepairRequest(
            pb::OverlayRepairRequest {
                first_seq,
                last_seq,
            },
        )),
    };
    let _ = send_control_to(transport, routing, self_id, origin, control).await;
}

#[allow(clippy::too_many_arguments)]
async fn send_repair_response(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    requester: NodeIdentifier,
    origin: NodeIdentifier,
    origin_boot_epoch: u64,
    final_dst: NodeIdentifier,
    lane: LaneId,
    packets: Vec<pb::OverlayData>,
    not_found: bool,
) -> Result<(), OverlayError> {
    let control = pb::OverlayControl {
        origin: node_to_wire(origin),
        origin_boot_epoch,
        final_dst: node_to_wire(final_dst),
        lane_id: lane.get(),
        requester: node_to_wire(requester),
        path_trace: vec![node_to_wire(self_id)],
        body: Some(OverlayControlBody::RepairResponse(
            pb::OverlayRepairResponse { packets, not_found },
        )),
    };
    send_control_to(transport, routing, self_id, requester, control).await
}

async fn send_control_to(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    target: NodeIdentifier,
    mut control: pb::OverlayControl,
) -> Result<(), OverlayError> {
    if target == self_id {
        return Ok(());
    }
    let tables = routing.load();
    let path_trace_set = path_trace_set(&control.path_trace);
    let next_hop = match select_forward_next_hop(
        &tables,
        self_id,
        target,
        CONTROL_LEVEL,
        CONTROL_METRIC,
        &path_trace_set,
        false,
    )? {
        ForwardNextHop::Send { next_hop } => next_hop,
        ForwardNextHop::DropAlreadyVisited => {
            debug!(
                self_id = %self_id,
                target = %target,
                origin = %NodeIdentifier::try_from(control.origin).unwrap_or(0),
                final_dst = %NodeIdentifier::try_from(control.final_dst).unwrap_or(0),
                requester = %NodeIdentifier::try_from(control.requester).unwrap_or(0),
                lane = control.lane_id,
                path_trace = ?control.path_trace,
                "dropping overlay control because target is already in path_trace"
            );
            return Ok(());
        }
        ForwardNextHop::DropNoRoute => {
            debug!(
                self_id = %self_id,
                target = %target,
                origin = %NodeIdentifier::try_from(control.origin).unwrap_or(0),
                final_dst = %NodeIdentifier::try_from(control.final_dst).unwrap_or(0),
                requester = %NodeIdentifier::try_from(control.requester).unwrap_or(0),
                lane = control.lane_id,
                path_trace = ?control.path_trace,
                "dropping overlay control because no route exists"
            );
            return Ok(());
        }
        ForwardNextHop::DropLoop { next_hop } => {
            debug!(
                self_id = %self_id,
                target = %target,
                %next_hop,
                origin = %NodeIdentifier::try_from(control.origin).unwrap_or(0),
                final_dst = %NodeIdentifier::try_from(control.final_dst).unwrap_or(0),
                requester = %NodeIdentifier::try_from(control.requester).unwrap_or(0),
                lane = control.lane_id,
                path_trace = ?control.path_trace,
                "dropping overlay control because no loop-free route exists"
            );
            return Ok(());
        }
    };
    append_path_trace(&mut control.path_trace, self_id);
    let body = OverlayBody::Control(control);
    let packet_kind = crate::debug_io::classify_overlay_body(&body);
    let payload = encode_message(&wrap(body))?;
    let payload_len = payload.len();
    crate::debug_io::record_send_attempt(self_id, next_hop, packet_kind.clone());
    let result = transport
        .try_send(
            next_hop,
            CONTROL_LEVEL,
            Some(CONTROL_METRIC),
            MessageClass::Control,
            payload,
        )
        .await;
    if result.is_ok() {
        crate::debug_io::record_sent(self_id, next_hop, packet_kind, payload_len);
    }
    Ok(result?)
}

fn preflight_routes(
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    dsts: &[NodeIdentifier],
    level: ServiceLevel,
    routing_metric: RoutingMetric,
) -> Result<(), OverlayError> {
    let tables = routing.load();
    for dst in dsts {
        if *dst == self_id {
            continue;
        }
        if tables
            .lookup_with_metric(*dst, level, routing_metric)
            .is_none()
        {
            return Err(OverlayError::NoRoute { dst: *dst, level });
        }
    }
    Ok(())
}

fn path_trace_set(path_trace: &[u32]) -> HashSet<NodeIdentifier> {
    path_trace
        .iter()
        .filter_map(|node| NodeIdentifier::try_from(*node).ok())
        .collect()
}

fn append_path_trace(path_trace: &mut Vec<u32>, self_id: NodeIdentifier) {
    let self_wire = node_to_wire(self_id);
    if !path_trace.contains(&self_wire) {
        path_trace.push(self_wire);
    }
}

fn encode_overlay_data(data: &pb::OverlayData) -> Result<Bytes, prost::EncodeError> {
    encode_message(&wrap(OverlayBody::Data(data.clone())))
}

fn attachments_to_proto(attachments: &[OverlayAttachment]) -> Vec<pb::OverlayAttachment> {
    let mut ordered: Vec<_> = attachments.iter().collect();
    ordered.sort_by(|left, right| right.priority().cmp(&left.priority()));
    ordered
        .into_iter()
        .map(OverlayAttachment::to_proto)
        .collect()
}

fn attachment_key(data: &pb::OverlayData, kind: u32, attachment_id: u64) -> Option<AttachmentKey> {
    attachment_key_for_origin(data, data.origin_message_id, kind, attachment_id)
}

fn attachment_key_for_origin(
    data: &pb::OverlayData,
    origin_message_id: u64,
    kind: u32,
    attachment_id: u64,
) -> Option<AttachmentKey> {
    Some(AttachmentKey::new(
        NodeIdentifier::try_from(data.src).ok()?,
        data.origin_boot_epoch,
        origin_message_id,
        kind,
        attachment_id,
    ))
}

fn cache_inline_attachments(cache: &AttachmentCache, data: &pb::OverlayData) {
    for attachment in &data.inline_attachments {
        let Some(key) = attachment_key(data, attachment.kind, attachment.attachment_id) else {
            continue;
        };
        crate::overlay::attachment_metrics::record_inline_bytes(attachment.payload.len());
        let _ = cache.insert_inline(key, Bytes::copy_from_slice(&attachment.payload));
    }
}

/// Consume a sidecar only at its final overlay destination. A transit node
/// must leave it as an ordinary unicast envelope so older and newer nodes can
/// route it without knowing the attachment schema.
fn consume_attachment_sidecar(
    cache: &AttachmentCache,
    self_id: NodeIdentifier,
    data: &pb::OverlayData,
) -> bool {
    let is_for_self = data
        .dsts
        .iter()
        .any(|dst| NodeIdentifier::try_from(*dst).ok() == Some(self_id));
    if !is_for_self {
        return false;
    }
    let Ok(chunk) = pb::AttachmentChunk::decode(data.payload.as_ref()) else {
        crate::overlay::attachment_metrics::record_sidecar_chunk_dropped();
        return true;
    };
    if chunk.base_origin_boot_epoch != data.origin_boot_epoch
        || chunk.base_origin_message_id == 0
        || chunk.kind == TREE_HINT_ATTACHMENT_KIND && chunk.attachment_id == 0
    {
        crate::overlay::attachment_metrics::record_sidecar_chunk_dropped();
        return true;
    }
    let Some(key) = attachment_key_for_origin(
        data,
        chunk.base_origin_message_id,
        chunk.kind,
        chunk.attachment_id,
    ) else {
        return true;
    };
    let completed = cache.insert_chunk(
        key,
        chunk.chunk_index as usize,
        chunk.chunk_count as usize,
        chunk.total_bytes as usize,
        Bytes::from(chunk.payload),
    );
    if completed.is_some() {
        crate::overlay::attachment_metrics::record_sidecar_reassembled();
    }
    true
}

fn is_realtime_distribution_frame(data: &pb::OverlayData) -> bool {
    data.service_tag == VOICE_SERVICE_TAG
        || data.distribution_profile
            == Some(crate::overlay::distribution::VOICE_REALTIME_PROFILE_ID)
}

fn decode_tree_hint(
    data: &pb::OverlayData,
    key: TreeKey,
    self_id: NodeIdentifier,
    cache: &AttachmentCache,
) -> Option<TreeState> {
    let payload = data
        .inline_attachments
        .iter()
        .find(|attachment| attachment.kind == TREE_HINT_ATTACHMENT_KIND)
        .map(|attachment| Bytes::copy_from_slice(&attachment.payload))
        .or_else(|| {
            attachment_key(data, TREE_HINT_ATTACHMENT_KIND, key.version.max(1))
                .and_then(|key| cache.get(key))
        })?;
    let install = pb::DistributionTreeInstall::decode(payload.as_ref()).ok()?;
    if install.source != u32::from(key.source)
        || install.profile != key.profile
        || install.version != key.version
        || install.group != key.group
        || install.group_version != key.group_version
        || install.topology_epoch != key.topology_epoch
        || install.members.len() > 4096
        || install.edges.len() > 8192
    {
        return None;
    }
    let members = install
        .members
        .iter()
        .filter_map(|node| NodeIdentifier::try_from(*node).ok());
    let edges = install.edges.iter().filter_map(|edge| {
        Some((
            NodeIdentifier::try_from(edge.parent).ok()?,
            NodeIdentifier::try_from(edge.child).ok()?,
        ))
    });
    let tree = TreeState::new(key.source, members, edges)
        .with_hop_ttl(Duration::from_millis(u64::from(install.hop_ttl_ms)));
    if tree.children(key.source).len() != 1
        || !tree.is_valid_for_source(key.source)
        || !tree.is_reachable_from(key.source, self_id)
    {
        return None;
    }
    Some(tree)
}

fn tree_hint_for_child(
    key: TreeKey,
    tree: &TreeState,
    child: NodeIdentifier,
) -> Option<pb::OverlayAttachment> {
    let branch = tree.branch_for_child(key.source, child)?;
    let install = pb::DistributionTreeInstall {
        source: key.source.into(),
        profile: key.profile,
        version: key.version,
        members: branch.members().map(u32::from).collect(),
        edges: branch
            .edges()
            .map(|(parent, child)| pb::OverlayTreeEdge {
                parent: parent.into(),
                child: child.into(),
            })
            .collect(),
        group: key.group,
        topology_epoch: key.topology_epoch,
        group_version: key.group_version,
        playout_delays: Vec::new(),
        hop_ttl_ms: branch
            .hop_ttl()
            .map(|ttl| ttl.as_millis().min(u128::from(u32::MAX)) as u32)
            .unwrap_or_default(),
    };
    Some(pb::OverlayAttachment {
        kind: TREE_HINT_ATTACHMENT_KIND,
        attachment_id: key.version.max(1),
        payload: install.encode_to_vec(),
    })
}

fn tree_branch_data(
    data: &pb::OverlayData,
    tree: &TreeState,
    child: NodeIdentifier,
    path_trace: Vec<u32>,
) -> pb::OverlayData {
    let mut forwarded = reconstruct_forwarded_data(data, vec![node_to_wire(child)], path_trace);
    forwarded
        .inline_attachments
        .retain(|attachment| attachment.kind != TREE_HINT_ATTACHMENT_KIND);
    if let Some(key) = tree_key_from_data(data)
        && let Some(hint) = tree_hint_for_child(key, tree, child)
    {
        forwarded.inline_attachments.insert(0, hint);
    }
    forwarded
}

fn transport_payload_plan(
    transport: &ConnectionManager,
    next_hop: NodeIdentifier,
    level: ServiceLevel,
    class: MessageClass,
    data: &pb::OverlayData,
    path_trace: &[u32],
) -> Result<TransportPayloadPlan, prost::EncodeError> {
    let rich_payload = encode_overlay_data(data)?;
    if data.inline_attachments.is_empty() {
        return Ok(TransportPayloadPlan::new(rich_payload));
    }

    let mut udp_data = data.clone();
    udp_data.inline_attachments.clear();
    let mut selected = Vec::with_capacity(data.inline_attachments.len());
    for attachment in &data.inline_attachments {
        let mut candidate = udp_data.clone();
        candidate.inline_attachments = selected
            .iter()
            .cloned()
            .chain(std::iter::once(attachment.clone()))
            .collect();
        let candidate_payload = encode_overlay_data(&candidate)?;
        if transport.payload_fits_transport(
            next_hop,
            TransportKind::Udp,
            level,
            class,
            &candidate_payload,
        ) {
            selected.push(attachment.clone());
        }
    }
    let omitted = data
        .inline_attachments
        .iter()
        .filter(|attachment| {
            !selected.iter().any(|chosen| {
                chosen.kind == attachment.kind && chosen.attachment_id == attachment.attachment_id
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    udp_data.inline_attachments = selected;
    let udp_payload = encode_overlay_data(&udp_data)?;
    let sidecars = encode_attachment_sidecars(
        transport, next_hop, level, class, data, path_trace, &omitted,
    )?;
    Ok(TransportPayloadPlan::new(rich_payload).with_variant(
        TransportKind::Udp,
        TransportPayloadVariant::new(udp_payload).with_sidecars(sidecars),
    ))
}

fn encode_attachment_sidecars(
    transport: &ConnectionManager,
    next_hop: NodeIdentifier,
    level: ServiceLevel,
    class: MessageClass,
    base: &pb::OverlayData,
    path_trace: &[u32],
    attachments: &[pb::OverlayAttachment],
) -> Result<Vec<Bytes>, prost::EncodeError> {
    let mut sidecars = Vec::new();
    for attachment in attachments {
        if attachment.payload.len() > MAX_ATTACHMENT_BYTES {
            continue;
        }
        let mut chunk_size = MAX_ATTACHMENT_CHUNK_BYTES.min(attachment.payload.len().max(1));
        loop {
            let chunk_count = attachment.payload.len().div_ceil(chunk_size);
            if chunk_count > MAX_ATTACHMENT_CHUNKS {
                break;
            }
            let mut chunks = Vec::with_capacity(chunk_count);
            let mut fits = true;
            for chunk_index in 0..chunk_count {
                let start = chunk_index * chunk_size;
                let end = (start + chunk_size).min(attachment.payload.len());
                let chunk = pb::AttachmentChunk {
                    base_origin_boot_epoch: base.origin_boot_epoch,
                    base_origin_message_id: base.origin_message_id,
                    kind: attachment.kind,
                    attachment_id: attachment.attachment_id,
                    chunk_index: chunk_index as u32,
                    chunk_count: chunk_count as u32,
                    total_bytes: attachment.payload.len() as u32,
                    payload: attachment.payload[start..end].to_vec(),
                };
                let mut chunk_bytes = Vec::with_capacity(chunk.encoded_len());
                chunk.encode(&mut chunk_bytes)?;
                let sidecar =
                    attachment_sidecar_data(base, next_hop, level, path_trace, &chunk, chunk_bytes);
                let encoded = encode_overlay_data(&sidecar)?;
                if !transport.payload_fits_transport(
                    next_hop,
                    TransportKind::Udp,
                    level,
                    class,
                    &encoded,
                ) {
                    fits = false;
                    break;
                }
                chunks.push(encoded);
            }
            if fits {
                sidecars.extend(chunks);
                break;
            }
            if chunk_size == 1 {
                break;
            }
            chunk_size = (chunk_size / 2).max(1);
        }
    }
    crate::overlay::attachment_metrics::record_sidecar_chunks_emitted(sidecars.len());
    Ok(sidecars)
}

fn attachment_sidecar_data(
    base: &pb::OverlayData,
    next_hop: NodeIdentifier,
    level: ServiceLevel,
    path_trace: &[u32],
    chunk: &pb::AttachmentChunk,
    chunk_bytes: Vec<u8>,
) -> pb::OverlayData {
    pb::OverlayData {
        src: base.src,
        dsts: vec![node_to_wire(next_hop)],
        path_trace: path_trace.to_vec(),
        service_tag: super::OVERLAY_ATTACHMENT_SERVICE_TAG,
        service_level: level_to_wire(level),
        message_class: class_to_wire(MessageClass::Regular),
        payload: Bytes::from(chunk_bytes),
        process_on_transit: false,
        route_metric: route_metric_to_wire(routing_metric_for_sidecar(level)),
        ordered_delivery: false,
        ordering_seq: 0,
        ordering_dst: 0,
        lane_id: None,
        origin_boot_epoch: base.origin_boot_epoch,
        origin_message_id: sidecar_message_id(base.origin_message_id, chunk),
        allow_l1_compression: false,
        distribution_profile: None,
        distribution_tree_version: None,
        distribution_group: None,
        distribution_group_version: None,
        distribution_topology_epoch: None,
        distribution_deadline_unix_ms: None,
        distribution_repair: false,
        distribution_repair_target: None,
        distribution_deadline_issuer: None,
        distribution_deadline_unix_us: None,
        inline_attachments: Vec::new(),
    }
}

fn routing_metric_for_sidecar(level: ServiceLevel) -> RoutingMetric {
    RoutingMetric::default_for_level(level)
}

fn sidecar_message_id(base_message_id: u64, chunk: &pb::AttachmentChunk) -> u64 {
    base_message_id
        .wrapping_add(u64::from(chunk.kind).wrapping_mul(0x9e37_79b9))
        .wrapping_add(chunk.attachment_id.rotate_left(17))
        .wrapping_add(u64::from(chunk.chunk_index).wrapping_mul(0x1000_0001))
        .max(1)
}

/// Forward an `OverlayData` whose `dsts` may contain multiple final destinations.
async fn forward_pb_as(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    data: pb::OverlayData,
    transport_class: MessageClass,
    is_originator: bool,
    transport_ttl: Option<std::time::Duration>,
    avoid_first_hop: Option<NodeIdentifier>,
) -> Result<(), OverlayError> {
    let level = level_from_wire(data.service_level).unwrap_or(ServiceLevel::Reliable);
    let routing_metric = route_metric_from_wire(data.route_metric, level)
        .unwrap_or_else(|| RoutingMetric::default_for_level(level));
    let tables = routing.load();
    let send_options = transport_options_for_overlay_data(&data, transport_ttl);

    let path_trace_set = path_trace_set(&data.path_trace);
    let mut buckets: HashMap<NodeIdentifier, Vec<u32>> = HashMap::new();
    let mut first_err: Option<OverlayError> = None;
    for dst_wire in &data.dsts {
        let Ok(dst) = NodeIdentifier::try_from(*dst_wire) else {
            continue;
        };
        if dst == self_id {
            continue;
        }
        let next_hop = select_forward_next_hop_for_send(
            &tables,
            self_id,
            dst,
            level,
            routing_metric,
            &path_trace_set,
            is_originator,
            Some(transport),
            transport_class,
            send_options,
            avoid_first_hop,
        );
        let next_hop = match next_hop {
            Ok(next_hop) => next_hop,
            Err(error) => {
                if is_originator && first_err.is_none() {
                    first_err = Some(error);
                }
                continue;
            }
        };
        match next_hop {
            ForwardNextHop::Send { next_hop } => {
                buckets.entry(next_hop).or_default().push(*dst_wire);
            }
            ForwardNextHop::DropAlreadyVisited => {
                debug!(
                    self_id = %self_id,
                    src = %NodeIdentifier::try_from(data.src).unwrap_or(0),
                    %dst,
                    ?level,
                    ?routing_metric,
                    lane = ?data.lane_id,
                    path_trace = ?data.path_trace,
                    "dropping overlay data because destination is already in path_trace"
                );
            }
            ForwardNextHop::DropNoRoute => {
                debug!(
                    self_id = %self_id,
                    src = %NodeIdentifier::try_from(data.src).unwrap_or(0),
                    %dst,
                    ?level,
                    ?routing_metric,
                    lane = ?data.lane_id,
                    path_trace = ?data.path_trace,
                    "dropping overlay data because no route exists"
                );
            }
            ForwardNextHop::DropLoop { next_hop } => {
                debug!(
                    self_id = %self_id,
                    src = %NodeIdentifier::try_from(data.src).unwrap_or(0),
                    %dst,
                    %next_hop,
                    ?level,
                    ?routing_metric,
                    lane = ?data.lane_id,
                    path_trace = ?data.path_trace,
                    "dropping overlay data because no loop-free route exists"
                );
            }
        }
    }
    if buckets.is_empty() {
        return first_err.map_or(Ok(()), Err);
    }

    let mut new_trace = data.path_trace.clone();
    append_path_trace(&mut new_trace, self_id);
    let mut sends: Vec<
        Pin<Box<dyn Future<Output = (NodeIdentifier, Result<(), SendError>)> + Send>>,
    > = Vec::with_capacity(buckets.len());
    for (next_hop, bucket_dsts) in buckets {
        let pb_msg = reconstruct_forwarded_data(&data, bucket_dsts, new_trace.clone());
        if tracing::enabled!(tracing::Level::TRACE) {
            let dsts: Vec<NodeIdentifier> = pb_msg
                .dsts
                .iter()
                .filter_map(|dst| NodeIdentifier::try_from(*dst).ok())
                .collect();
            let path_trace: Vec<NodeIdentifier> = pb_msg
                .path_trace
                .iter()
                .filter_map(|node| NodeIdentifier::try_from(*node).ok())
                .collect();
            let payload_hex = payload_hex_preview(&pb_msg.payload);
            trace!(
                %next_hop,
                src = %NodeIdentifier::try_from(pb_msg.src).unwrap_or(0),
                dsts = ?dsts,
                path_trace = ?path_trace,
                service_tag = pb_msg.service_tag,
                ?level,
                ?routing_metric,
                transport_class = ?transport_class,
                process_on_transit = pb_msg.process_on_transit,
                payload_len = pb_msg.payload.len(),
                payload_hex = %payload_hex,
                "forwarding overlay data"
            );
        }

        let body = OverlayBody::Data(pb_msg.clone());
        let packet_kind = crate::debug_io::classify_overlay_body(&body);
        let payload_plan = match transport_payload_plan(
            transport,
            next_hop,
            level,
            transport_class,
            &pb_msg,
            &new_trace,
        ) {
            Ok(plan) => plan,
            Err(e) => {
                if is_originator {
                    return Err(OverlayError::Encode(e));
                }
                warn!(error=%e, "encode forward failed");
                continue;
            }
        };
        let payload_len = payload_plan.default_variant().primary().len();
        let transport = transport.clone();
        sends.push(Box::pin(async move {
            crate::debug_io::record_send_attempt(self_id, next_hop, packet_kind.clone());
            let result = transport
                .try_send_with_payload_plan(
                    next_hop,
                    level,
                    Some(routing_metric),
                    transport_class,
                    payload_plan,
                    send_options,
                )
                .await;
            if result.is_ok() {
                crate::debug_io::record_sent(self_id, next_hop, packet_kind, payload_len);
            }
            (next_hop, result)
        }));
    }

    for (next_hop, result) in join_all(sends).await {
        match result {
            Ok(()) => {
                trace!(%next_hop, ?level, "forwarded");
            }
            Err(e) => {
                if is_originator && first_err.is_none() {
                    first_err = Some(OverlayError::Send(e));
                } else {
                    debug!(%next_hop, error=%e, "forward send failed");
                }
            }
        }
    }
    if let Some(e) = first_err {
        return Err(e);
    }
    Ok(())
}

#[derive(Debug)]
enum TreeEdgeSendOutcome {
    Sent,
    /// The frame reached the child through an alternate first hop.  A missing
    /// direct transport still makes the tree edge ineligible for future
    /// sends, whereas a queue-pressure detour does not.
    FallbackSent {
        direct_unavailable: bool,
    },
    NoRoute,
    Loop,
    Backpressure(SendError),
    Transport(SendError),
}

impl TreeEdgeSendOutcome {
    fn label(&self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::FallbackSent { .. } => "fallback_sent",
            Self::NoRoute => "no_route",
            Self::Loop => "loop",
            Self::Backpressure(_) => "backpressure",
            Self::Transport(_) => "transport",
        }
    }

    fn into_error(self, child: NodeIdentifier, level: ServiceLevel) -> Option<OverlayError> {
        match self {
            Self::Sent | Self::FallbackSent { .. } => None,
            Self::NoRoute | Self::Loop => Some(OverlayError::NoRoute { dst: child, level }),
            Self::Backpressure(error) | Self::Transport(error) => Some(OverlayError::Send(error)),
        }
    }
}

#[cfg(test)]
async fn send_direct_tree_edge(
    transport: &ConnectionManager,
    self_id: NodeIdentifier,
    child: NodeIdentifier,
    data: &pb::OverlayData,
    path_trace: Vec<u32>,
    transport_class: MessageClass,
    hop_ttl: Duration,
) -> TreeEdgeSendOutcome {
    send_direct_tree_edge_with_routing(
        transport,
        None,
        self_id,
        child,
        vec![child],
        data,
        path_trace,
        transport_class,
        hop_ttl,
    )
    .await
}

async fn send_direct_tree_edge_with_routing(
    transport: &ConnectionManager,
    routing: Option<&RoutingHandle>,
    self_id: NodeIdentifier,
    child: NodeIdentifier,
    fallback_recipients: Vec<NodeIdentifier>,
    data: &pb::OverlayData,
    path_trace: Vec<u32>,
    transport_class: MessageClass,
    hop_ttl: Duration,
) -> TreeEdgeSendOutcome {
    if path_trace_set(&path_trace).contains(&child) {
        return TreeEdgeSendOutcome::Loop;
    }
    let level = level_from_wire(data.service_level).unwrap_or(ServiceLevel::Reliable);
    let routing_metric = route_metric_from_wire(data.route_metric, level)
        .unwrap_or_else(|| RoutingMetric::default_for_level(level));
    let pb_msg = reconstruct_forwarded_data(data, vec![node_to_wire(child)], path_trace.clone());
    let body = OverlayBody::Data(pb_msg.clone());
    let packet_kind = crate::debug_io::classify_overlay_body(&body);
    let payload_plan = match transport_payload_plan(
        transport,
        child,
        level,
        transport_class,
        &pb_msg,
        &path_trace,
    ) {
        Ok(payload_plan) => payload_plan,
        Err(error) => return TreeEdgeSendOutcome::Transport(SendError::Encode(error)),
    };
    let payload_len = payload_plan.default_variant().primary().len();
    // `expire_after` captures a fresh monotonic Instant here, independently
    // for this physical tree edge. No wall-clock translation is involved.
    let options = transport_options_for_overlay_data(data, Some(hop_ttl));

    // A pressure-aware selection may have no usable queue even while the
    // direct transport remains live. Only a genuinely unavailable transport
    // invalidates this tree edge; queue pressure is handled by the fallback
    // path without forcing a tree rebuild.
    let direct_unavailable = routing.is_some()
        && transport
            .ranked_live_transports_for(child, level, routing_metric)
            .is_empty();

    // A tree edge is normally sent directly to its child so the child can
    // continue the tree without another route calculation. Under queue
    // pressure, however, the direct peer queue can accept the frame and let
    // it expire before dispatch. Expiring voice traffic must use the same
    // pressure-aware alternate first hop as ordinary forwarding, with the
    // tree metadata removed for that one branch.
    if data.service_tag == VOICE_SERVICE_TAG
        && options.expires_at().is_some()
        && !fallback_recipients.is_empty()
        && let Some(routing) = routing
        && let Some(next_hop) = select_forward_next_hop_for_send(
            &routing.load(),
            self_id,
            child,
            level,
            routing_metric,
            &path_trace_set(&path_trace),
            true,
            Some(transport),
            transport_class,
            options,
            None,
        )
        .ok()
        .and_then(|next_hop| match next_hop {
            ForwardNextHop::Send { next_hop } => Some(next_hop),
            ForwardNextHop::DropAlreadyVisited
            | ForwardNextHop::DropNoRoute
            | ForwardNextHop::DropLoop { .. } => None,
        })
        .filter(|next_hop| *next_hop != child)
    {
        trace!(
            parent = %self_id,
            %child,
            %next_hop,
            "using pressure-aware alternate for voice tree edge"
        );
        // Legacy fallback removes tree metadata, so it must carry every
        // final recipient below this child rather than only the relay itself.
        let fallback = legacy_subtree_fallback_data(data, fallback_recipients, path_trace.clone());
        return match forward_pb_as(
            transport,
            routing,
            self_id,
            fallback,
            transport_class,
            true,
            Some(hop_ttl),
            None,
        )
        .await
        {
            Ok(()) => TreeEdgeSendOutcome::FallbackSent { direct_unavailable },
            Err(OverlayError::NoRoute { .. }) => TreeEdgeSendOutcome::NoRoute,
            Err(OverlayError::Send(error)) => match error {
                SendError::UnknownNode { .. } | SendError::NoSuitableTransport { .. } => {
                    TreeEdgeSendOutcome::NoRoute
                }
                error @ SendError::Backpressure { .. } => TreeEdgeSendOutcome::Backpressure(error),
                error => TreeEdgeSendOutcome::Transport(error),
            },
            Err(_) => TreeEdgeSendOutcome::NoRoute,
        };
    }

    crate::debug_io::record_send_attempt(self_id, child, packet_kind.clone());
    match transport
        .try_send_with_payload_plan(
            child,
            level,
            Some(routing_metric),
            transport_class,
            payload_plan,
            options,
        )
        .await
    {
        Ok(()) => {
            crate::debug_io::record_sent(self_id, child, packet_kind, payload_len);
            TreeEdgeSendOutcome::Sent
        }
        Err(SendError::UnknownNode { .. } | SendError::NoSuitableTransport { .. }) => {
            TreeEdgeSendOutcome::NoRoute
        }
        Err(error @ SendError::Backpressure { .. }) => TreeEdgeSendOutcome::Backpressure(error),
        Err(error) => TreeEdgeSendOutcome::Transport(error),
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward_tree_data_v3(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    distribution: &DistributionPlane,
    self_id: NodeIdentifier,
    data: pb::OverlayData,
    tree: &TreeState,
    transport_class: MessageClass,
    hop_ttl: Duration,
) -> Result<(), OverlayError> {
    let profile = data.distribution_profile.unwrap_or_default();
    let is_repair = data.distribution_repair;
    let level = level_from_wire(data.service_level).unwrap_or(ServiceLevel::Reliable);
    let mut path_trace = data.path_trace.clone();
    append_path_trace(&mut path_trace, self_id);
    let mut sends = Vec::new();
    for child in tree.children(self_id).iter().copied() {
        let edge_path_trace = path_trace.clone();
        let fallback_recipients = tree.descendant_members(child);
        let edge_data = tree_branch_data(&data, tree, child, edge_path_trace.clone());
        sends.push(async move {
            let outcome = send_direct_tree_edge_with_routing(
                transport,
                Some(routing),
                self_id,
                child,
                fallback_recipients,
                &edge_data,
                edge_path_trace,
                transport_class,
                hop_ttl,
            )
            .await;
            (child, outcome)
        });
    }

    let mut first_err = None;
    for (child, outcome) in join_all(sends).await {
        let outcome_label = outcome.label();
        crate::overlay::distribution_metrics::record_edge_forward(profile, outcome_label);
        if matches!(&outcome, TreeEdgeSendOutcome::Sent) {
            if let Some(key) = tree_key_from_data(&data) {
                distribution.record_edge_success(key, self_id, child);
            }
            if is_repair {
                crate::overlay::distribution_metrics::record_alternate_forward(profile);
            } else {
                crate::overlay::distribution_metrics::record_original_forward(profile);
            }
            trace!(parent = %self_id, %child, outcome = outcome_label, "sent direct distribution tree edge");
            continue;
        }
        if let TreeEdgeSendOutcome::FallbackSent { direct_unavailable } = &outcome {
            if *direct_unavailable {
                if let Some(key) = tree_key_from_data(&data) {
                    distribution.report_edge_failure(key, self_id, child);
                }
            }
            trace!(
                parent = %self_id,
                %child,
                outcome = outcome_label,
                "sent pressure-aware distribution subtree fallback"
            );
            continue;
        }

        debug!(
            parent = %self_id,
            %child,
            profile,
            repair = is_repair,
            outcome = outcome_label,
            "direct distribution tree edge failed"
        );
        if let Some(key) = tree_key_from_data(&data) {
            distribution.report_edge_failure(key, self_id, child);
        }

        let descendants = tree.descendant_members(child);
        let fallback_result = if descendants.is_empty() {
            outcome.into_error(child, level).map_or(Ok(()), Err)
        } else {
            let fallback = legacy_subtree_fallback_data(&data, descendants, path_trace.clone());
            forward_pb_as(
                transport,
                routing,
                self_id,
                fallback,
                transport_class,
                false,
                Some(hop_ttl),
                None,
            )
            .await
        };
        if let Err(error) = fallback_result {
            debug!(parent = %self_id, %child, %error, "distribution subtree fallback failed");
            if first_err.is_none() {
                first_err = Some(error);
            }
        }
    }
    first_err.map_or(Ok(()), Err)
}

async fn forward_tree_data(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    distribution: &DistributionPlane,
    monitor: &NeighborMonitor,
    self_id: NodeIdentifier,
    data: pb::OverlayData,
    tree: &TreeState,
    transport_class: MessageClass,
    transport_ttl: Option<std::time::Duration>,
) -> Result<(), OverlayError> {
    if let Some(hop_ttl) = tree.hop_ttl() {
        return forward_tree_data_v3(
            transport,
            routing,
            distribution,
            self_id,
            data,
            tree,
            transport_class,
            hop_ttl,
        )
        .await;
    }
    let profile = data.distribution_profile.unwrap_or_default();
    let is_repair = data.distribution_repair;
    let metric_context = distribution_metric_context(
        &data,
        crate::overlay::distribution_metrics::EdgeDirection::Outbound,
    );
    let level = level_from_wire(data.service_level).unwrap_or(ServiceLevel::Reliable);
    let routing_metric = route_metric_from_wire(data.route_metric, level)
        .unwrap_or_else(|| RoutingMetric::default_for_level(level));
    let requires_clock_offset =
        data.distribution_deadline_unix_us.is_some() || data.distribution_deadline_issuer.is_some();
    let mut path_trace = data.path_trace.clone();
    append_path_trace(&mut path_trace, self_id);
    let visited = path_trace_set(&path_trace);
    let mut sends: Vec<
        Pin<Box<dyn Future<Output = (NodeIdentifier, Result<(), OverlayError>)> + Send + '_>>,
    > = Vec::new();
    for child in tree.children(self_id).iter().copied() {
        if visited.contains(&child) {
            continue;
        }
        if requires_clock_offset {
            let next_hop = routing
                .load()
                .lookup_with_metric(child, level, routing_metric)
                .map(|route| route.next_hop);
            if !next_hop.is_some_and(|peer| monitor.has_mutual_fresh_peer_clock_offset(peer)) {
                // The owning tree state identifies this child subtree exactly,
                // so this node can fall back only that branch to ordinary
                // multicast without duplicating the rest of the tree.
                if let Some(context) = metric_context {
                    crate::overlay::distribution_metrics::record_clock_offset_fallback_with_context(
                        context,
                        "child_clock_unready",
                    );
                    crate::overlay::distribution_metrics::record_compatibility_fallback_with_context(
                        context,
                        "child_clock_unready",
                    );
                }
                let descendants = tree.descendant_members(child);
                let descendant_count = descendants.len();
                if !descendants.is_empty() {
                    let fallback =
                        legacy_subtree_fallback_data(&data, descendants, path_trace.clone());
                    sends.push(Box::pin(async move {
                        let result = forward_pb_as(
                            transport,
                            routing,
                            self_id,
                            fallback,
                            transport_class,
                            false,
                            Some(VOICE_TRANSPORT_TTL),
                            None,
                        )
                        .await;
                        (child, result)
                    }));
                }
                tracing::debug!(
                    parent = %self_id,
                    %child,
                    profile,
                    descendants = descendant_count,
                    "falling back distribution child subtree without mutual direct-peer clock readiness"
                );
                continue;
            }
        }
        let pb_msg = tree_branch_data(&data, tree, child, path_trace.clone());
        sends.push(Box::pin(async move {
            let result = forward_pb_as(
                transport,
                routing,
                self_id,
                pb_msg,
                transport_class,
                false,
                transport_ttl,
                None,
            )
            .await;
            if result.is_ok() {
                if is_repair {
                    crate::overlay::distribution_metrics::record_alternate_forward(profile);
                } else {
                    crate::overlay::distribution_metrics::record_original_forward(profile);
                }
            }
            (child, result)
        }));
    }
    let mut first_err = None;
    for (child, result) in join_all(sends).await {
        if result.is_ok() {
            if let Some(key) = tree_key_from_data(&data) {
                distribution.record_edge_success(key, self_id, child);
            }
        }
        if let Err(error) = result {
            tracing::debug!(
                parent = %self_id,
                %child,
                profile,
                repair = is_repair,
                error = %error,
                "distribution child-edge send failed"
            );
            if let Some(key) = tree_key_from_data(&data) {
                distribution.report_edge_failure(key, self_id, child);
                if should_attempt_alternate_tree_repair(&data) {
                    let mut repair = reconstruct_forwarded_data(
                        &data,
                        vec![node_to_wire(child)],
                        path_trace.clone(),
                    );
                    repair.distribution_repair = true;
                    repair.distribution_repair_target = Some(node_to_wire(child));
                    let remaining =
                        distribution_remaining_deadline(&repair).expect("eligible repair deadline");
                    let _ = forward_pb_as(
                        transport,
                        routing,
                        self_id,
                        repair,
                        transport_class,
                        false,
                        Some(remaining),
                        Some(child),
                    )
                    .await;
                }
            }
            if first_err.is_none() {
                first_err = Some(error);
            }
        }
    }
    first_err.map_or(Ok(()), Err)
}

fn should_attempt_alternate_tree_repair(data: &pb::OverlayData) -> bool {
    !data.distribution_repair
        && data.distribution_profile
            == Some(crate::overlay::distribution::VOICE_REALTIME_PROFILE_ID)
        && distribution_remaining_deadline(data)
            .is_some_and(|remaining| remaining >= Duration::from_millis(80))
}

fn tree_key_from_data(data: &pb::OverlayData) -> Option<TreeKey> {
    Some(TreeKey {
        source: NodeIdentifier::try_from(data.src).ok()?,
        profile: data.distribution_profile?,
        group: data.distribution_group?,
        group_version: data.distribution_group_version?,
        topology_epoch: data.distribution_topology_epoch?,
        version: data.distribution_tree_version?,
    })
}

/// Convert one unavailable tree branch into ordinary destination routing. The
/// recipient list is restricted to the logical child's subtree, so healthy
/// tree branches keep their single-copy forwarding behavior.
fn legacy_subtree_fallback_data(
    data: &pb::OverlayData,
    recipients: Vec<NodeIdentifier>,
    path_trace: Vec<u32>,
) -> pb::OverlayData {
    let mut fallback = reconstruct_forwarded_data(
        data,
        recipients.into_iter().map(node_to_wire).collect(),
        path_trace,
    );
    fallback.distribution_profile = None;
    fallback.distribution_tree_version = None;
    fallback.distribution_group = None;
    fallback.distribution_group_version = None;
    fallback.distribution_topology_epoch = None;
    fallback.distribution_deadline_unix_ms = None;
    // A repair is still a direct repair after its tree envelope is removed.
    // The receiver-side playout stage needs this classification to reject a
    // repair that arrives after the scheduled release.
    fallback.distribution_repair = data.distribution_repair;
    fallback.distribution_repair_target = None;
    fallback.distribution_deadline_issuer = None;
    fallback.distribution_deadline_unix_us = None;
    fallback
}

fn reconstruct_forwarded_data(
    data: &pb::OverlayData,
    dsts: Vec<u32>,
    path_trace: Vec<u32>,
) -> pb::OverlayData {
    pb::OverlayData {
        src: data.src,
        dsts,
        path_trace,
        service_tag: data.service_tag,
        service_level: data.service_level,
        message_class: data.message_class,
        payload: data.payload.clone(),
        process_on_transit: data.process_on_transit,
        route_metric: data.route_metric,
        ordered_delivery: data.ordered_delivery,
        ordering_seq: data.ordering_seq,
        ordering_dst: data.ordering_dst,
        lane_id: data.lane_id,
        origin_boot_epoch: data.origin_boot_epoch,
        origin_message_id: data.origin_message_id,
        allow_l1_compression: data.allow_l1_compression,
        distribution_profile: data.distribution_profile,
        distribution_tree_version: data.distribution_tree_version,
        distribution_group: data.distribution_group,
        distribution_group_version: data.distribution_group_version,
        distribution_topology_epoch: data.distribution_topology_epoch,
        distribution_deadline_unix_ms: data.distribution_deadline_unix_ms,
        distribution_repair: data.distribution_repair,
        distribution_repair_target: data.distribution_repair_target,
        distribution_deadline_issuer: data.distribution_deadline_issuer,
        distribution_deadline_unix_us: data.distribution_deadline_unix_us,
        inline_attachments: data.inline_attachments.clone(),
    }
}

fn transport_options_for_overlay_data(
    data: &pb::OverlayData,
    transport_ttl: Option<std::time::Duration>,
) -> TransportSendOptions {
    let mut options = TransportSendOptions::default();
    if data.allow_l1_compression && data.service_tag != VOICE_SERVICE_TAG {
        options = options.allow_l1_compression();
    }
    if let Some(ttl) = transport_ttl {
        options = options.expire_after(ttl);
    } else if data.service_tag == VOICE_SERVICE_TAG {
        options = options.expire_after(VOICE_TRANSPORT_TTL);
    }
    options
}

fn select_forward_next_hop(
    tables: &RoutingTables,
    self_id: NodeIdentifier,
    dst: NodeIdentifier,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    path_trace_set: &HashSet<NodeIdentifier>,
    is_originator: bool,
) -> Result<ForwardNextHop, OverlayError> {
    select_forward_next_hop_for_send(
        tables,
        self_id,
        dst,
        level,
        routing_metric,
        path_trace_set,
        is_originator,
        None,
        MessageClass::Regular,
        TransportSendOptions::default(),
        None,
    )
}

fn select_forward_next_hop_for_send(
    tables: &RoutingTables,
    self_id: NodeIdentifier,
    dst: NodeIdentifier,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    path_trace_set: &HashSet<NodeIdentifier>,
    is_originator: bool,
    transport: Option<&ConnectionManager>,
    transport_class: MessageClass,
    send_options: TransportSendOptions,
    avoid_first_hop: Option<NodeIdentifier>,
) -> Result<ForwardNextHop, OverlayError> {
    if path_trace_set.contains(&dst) {
        return Ok(ForwardNextHop::DropAlreadyVisited);
    }

    let Some(entry) = tables.lookup_with_metric(dst, level, routing_metric) else {
        if is_originator {
            return Err(OverlayError::NoRoute { dst, level });
        }
        return Ok(ForwardNextHop::DropNoRoute);
    };

    if path_trace_set.contains(&entry.next_hop) {
        if let Some(alternate) = tables.lookup_path_aware_with_metric(
            self_id,
            dst,
            level,
            routing_metric,
            path_trace_set,
        ) {
            return Ok(ForwardNextHop::Send {
                next_hop: alternate.next_hop,
            });
        }
        return Ok(ForwardNextHop::DropLoop {
            next_hop: entry.next_hop,
        });
    }

    if Some(entry.next_hop) == avoid_first_hop {
        if let Some(alternate) = tables.lookup_avoiding_first_hop_with_metric(
            self_id,
            dst,
            level,
            routing_metric,
            path_trace_set,
            entry.next_hop,
        ) {
            return Ok(ForwardNextHop::Send {
                next_hop: alternate.next_hop,
            });
        }
        return Ok(ForwardNextHop::DropNoRoute);
    }

    let next_hop = deadline_pressure_alternate(
        tables,
        self_id,
        dst,
        level,
        routing_metric,
        path_trace_set,
        transport,
        transport_class,
        send_options,
        entry.next_hop,
    )
    .unwrap_or(entry.next_hop);

    Ok(ForwardNextHop::Send { next_hop })
}

fn deadline_pressure_alternate(
    tables: &RoutingTables,
    self_id: NodeIdentifier,
    dst: NodeIdentifier,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    path_trace_set: &HashSet<NodeIdentifier>,
    transport: Option<&ConnectionManager>,
    transport_class: MessageClass,
    send_options: TransportSendOptions,
    current_next_hop: NodeIdentifier,
) -> Option<NodeIdentifier> {
    if send_options.expires_at().is_none() {
        return None;
    }
    let transport = transport?;
    let current_pressure = transport
        .best_send_queue_pressure(
            current_next_hop,
            level,
            routing_metric,
            transport_class,
            send_options,
        )
        .unwrap_or(3);
    if current_pressure < 2 {
        return None;
    }
    let alternate = tables.lookup_avoiding_first_hop_with_metric(
        self_id,
        dst,
        level,
        routing_metric,
        path_trace_set,
        current_next_hop,
    )?;
    if alternate.next_hop == current_next_hop {
        return None;
    }
    let alternate_pressure = transport.best_send_queue_pressure(
        alternate.next_hop,
        level,
        routing_metric,
        transport_class,
        send_options,
    )?;
    (alternate_pressure < current_pressure).then_some(alternate.next_hop)
}

#[cfg(test)]
mod tests {
    use super::super::super::proto::decode_message;
    use super::super::super::routing::{RouteEntry, dijkstra::EdgeCost, new_handle};
    use super::super::{OverlayInboundMessage, ServiceInbound};
    use super::*;
    use crate::overlay::attachments::AttachmentKey;
    use crate::overlay::duplicate::DuplicateDetector;
    use shitspeak_s2s_transport::{SendError, TransportKind};
    use tokio::sync::{broadcast, mpsc};
    use tokio::time::timeout;

    fn edge(cost: u64) -> EdgeCost {
        EdgeCost {
            primary: cost,
            latency_us: cost,
        }
    }

    fn test_overlay_data(allow_l1_compression: bool) -> pb::OverlayData {
        pb::OverlayData {
            src: node_to_wire(1),
            dsts: vec![node_to_wire(4)],
            path_trace: vec![node_to_wire(1)],
            service_tag: 7,
            service_level: level_to_wire(ServiceLevel::Reliable),
            message_class: class_to_wire(MessageClass::Regular),
            payload: Bytes::from_static(b"payload"),
            process_on_transit: false,
            route_metric: route_metric_to_wire(RoutingMetric::ReliableCost),
            ordered_delivery: false,
            ordering_seq: 0,
            ordering_dst: 0,
            lane_id: None,
            origin_boot_epoch: 11,
            origin_message_id: 22,
            allow_l1_compression,
            distribution_profile: None,
            distribution_tree_version: None,
            distribution_group: None,
            distribution_group_version: None,
            distribution_topology_epoch: None,
            distribution_deadline_unix_ms: None,
            distribution_repair: false,
            distribution_repair_target: None,
            distribution_deadline_issuer: None,
            distribution_deadline_unix_us: None,
            inline_attachments: Vec::new(),
        }
    }

    fn test_monitor() -> NeighborMonitor {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(2, 1, &[TransportKind::Tcp]);
        let (membership_events, _) = broadcast::channel(8);
        NeighborMonitor::new(
            2,
            transport,
            Arc::new(DuplicateDetector::new(2, Duration::from_secs(1))),
            OverlayConfig::new(Vec::new()),
            membership_events,
        )
    }

    fn monitor_with_peer_clock_offset(peer_ahead_us: i64) -> NeighborMonitor {
        let monitor = test_monitor();
        let local_receive = unix_time_us();
        let local_send = local_receive.saturating_sub(20_000);
        let peer_receive = u64::try_from(
            i128::from(local_send) + i128::from(peer_ahead_us) + i128::from(10_000_u64),
        )
        .expect("test clock offset should keep timestamps positive");
        monitor.record_hello_ack(
            1,
            1,
            7,
            local_send,
            peer_receive,
            peer_receive,
            local_receive,
            true,
            None,
        );
        monitor
    }

    fn routing_with_route(dst: NodeIdentifier, next_hop: NodeIdentifier) -> RoutingHandle {
        let routing = new_handle();
        let mut tables = RoutingTables::empty();
        let table = HashMap::from([(
            dst,
            RouteEntry {
                next_hop,
                cost: 1,
                latency_us: 1,
            },
        )]);
        for level in ServiceLevel::ALL {
            tables.insert_table(RoutingMetric::ReliableCost, level, table.clone());
        }
        routing.store(Arc::new(tables));
        routing
    }

    fn routing_with_routes(routes: &[(NodeIdentifier, NodeIdentifier)]) -> RoutingHandle {
        let routing = new_handle();
        let mut tables = RoutingTables::empty();
        let table: HashMap<_, _> = routes
            .iter()
            .map(|(dst, next_hop)| {
                (
                    *dst,
                    RouteEntry {
                        next_hop: *next_hop,
                        cost: 1,
                        latency_us: 1,
                    },
                )
            })
            .collect();
        for level in ServiceLevel::ALL {
            tables.insert_table(RoutingMetric::ReliableCost, level, table.clone());
        }
        routing.store(Arc::new(tables));
        routing
    }

    fn voice_routing_with_direct_and_indirect_route() -> RoutingHandle {
        let routing = new_handle();
        let mut tables = RoutingTables::empty();
        let table = HashMap::from([
            (
                4,
                RouteEntry {
                    next_hop: 4,
                    cost: 1,
                    latency_us: 1,
                },
            ),
            (
                5,
                RouteEntry {
                    next_hop: 3,
                    cost: 6,
                    latency_us: 6,
                },
            ),
        ]);
        let adjacency = HashMap::from([
            (1, vec![(4, edge(1)), (3, edge(5))]),
            (3, vec![(4, edge(1)), (5, edge(1))]),
        ]);
        for level in ServiceLevel::ALL {
            tables.insert_table_with_adjacency(
                RoutingMetric::ConversationalQuality,
                level,
                table.clone(),
                adjacency.clone(),
            );
        }
        routing.store(Arc::new(tables));
        routing
    }

    #[tokio::test]
    async fn v3_tree_edge_sends_directly_to_the_adjacent_child() {
        let (transport, mut receivers) =
            ConnectionManager::test_with_live_streams(1, 2, &[TransportKind::Tcp]);
        let mut child_rx = receivers.pop().expect("child receiver");
        let mut data = test_overlay_data(false);
        data.dsts.clear();
        data.distribution_profile = Some(1);

        let outcome = send_direct_tree_edge(
            &transport,
            1,
            2,
            &data,
            vec![node_to_wire(1)],
            MessageClass::Regular,
            Duration::from_millis(100),
        )
        .await;

        assert!(matches!(outcome, TreeEdgeSendOutcome::Sent));
        let forwarded = timeout(Duration::from_millis(50), child_rx.recv())
            .await
            .expect("direct child should receive promptly")
            .expect("child stream should remain open");
        let decoded = decode_message(forwarded.payload()).expect("overlay frame");
        let Some(OverlayBody::Data(forwarded)) = decoded.body else {
            panic!("not overlay data");
        };
        assert_eq!(forwarded.dsts, vec![node_to_wire(2)]);
    }

    #[tokio::test]
    async fn v3_tree_edge_reports_loop_before_transport_send() {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(1, 2, &[TransportKind::Tcp]);
        let outcome = send_direct_tree_edge(
            &transport,
            1,
            2,
            &test_overlay_data(false),
            vec![node_to_wire(1), node_to_wire(2)],
            MessageClass::Regular,
            Duration::from_millis(100),
        )
        .await;
        assert!(matches!(outcome, TreeEdgeSendOutcome::Loop));
    }

    #[tokio::test]
    async fn v3_tree_edge_reports_missing_adjacent_peer_as_no_route() {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(1, 3, &[TransportKind::Tcp]);
        let outcome = send_direct_tree_edge(
            &transport,
            1,
            2,
            &test_overlay_data(false),
            vec![node_to_wire(1)],
            MessageClass::Regular,
            Duration::from_millis(100),
        )
        .await;
        assert!(matches!(outcome, TreeEdgeSendOutcome::NoRoute));
    }

    #[tokio::test]
    async fn pressured_voice_tree_edge_uses_an_alternate_first_hop() {
        let (transport, mut receivers) =
            ConnectionManager::test_with_live_streams(1, 4, &[TransportKind::Tcp]);
        let _direct_rx = receivers.pop().expect("direct child receiver");
        let mut alternate_rx = transport.test_install_live_stream(3, TransportKind::Tcp);
        build_deadline_stream_pressure(&transport, 4).await;

        let routing = voice_routing_with_direct_and_indirect_route();
        let mut data = test_overlay_data(false);
        data.service_tag = VOICE_SERVICE_TAG;
        data.service_level = level_to_wire(ServiceLevel::BestEffort);
        data.message_class = class_to_wire(MessageClass::HighPriority);
        data.route_metric = route_metric_to_wire(RoutingMetric::ConversationalQuality);
        data.distribution_profile = Some(1);

        let outcome = send_direct_tree_edge_with_routing(
            &transport,
            Some(&routing),
            1,
            4,
            vec![4, 5],
            &data,
            vec![node_to_wire(1)],
            MessageClass::HighPriority,
            Duration::from_millis(100),
        )
        .await;

        assert!(matches!(
            outcome,
            TreeEdgeSendOutcome::FallbackSent {
                direct_unavailable: false
            }
        ));
        let forwarded = timeout(Duration::from_millis(50), alternate_rx.recv())
            .await
            .expect("alternate first hop should receive the fallback")
            .expect("alternate stream should remain open");
        let decoded = decode_message(forwarded.payload()).expect("overlay frame");
        let Some(OverlayBody::Data(forwarded)) = decoded.body else {
            panic!("not overlay data");
        };
        assert_eq!(forwarded.dsts, vec![node_to_wire(4), node_to_wire(5)]);
        assert_eq!(forwarded.distribution_profile, None);
    }

    #[tokio::test]
    async fn unavailable_voice_tree_edge_marks_fallback_as_failed_direct_edge() {
        let (transport, mut receivers) =
            ConnectionManager::test_with_live_streams(1, 3, &[TransportKind::Tcp]);
        let mut alternate_rx = receivers.pop().expect("alternate child receiver");

        let routing = voice_routing_with_direct_and_indirect_route();
        let mut data = test_overlay_data(false);
        data.service_tag = VOICE_SERVICE_TAG;
        data.service_level = level_to_wire(ServiceLevel::BestEffort);
        data.message_class = class_to_wire(MessageClass::HighPriority);
        data.route_metric = route_metric_to_wire(RoutingMetric::ConversationalQuality);
        data.distribution_profile = Some(1);

        let outcome = send_direct_tree_edge_with_routing(
            &transport,
            Some(&routing),
            1,
            4,
            vec![4],
            &data,
            vec![node_to_wire(1)],
            MessageClass::HighPriority,
            Duration::from_millis(100),
        )
        .await;

        assert!(matches!(
            outcome,
            TreeEdgeSendOutcome::FallbackSent {
                direct_unavailable: true
            }
        ));
        assert!(
            timeout(Duration::from_millis(50), alternate_rx.recv())
                .await
                .expect("alternate first hop should receive the fallback")
                .is_some()
        );
    }

    fn tables_with_direct_and_indirect_route() -> RoutingTables {
        let mut tables = RoutingTables::empty();
        tables.insert_table_with_adjacency(
            RoutingMetric::ReliableCost,
            ServiceLevel::Reliable,
            HashMap::from([(
                4,
                RouteEntry {
                    next_hop: 4,
                    cost: 1,
                    latency_us: 1,
                },
            )]),
            HashMap::from([
                (1, vec![(4, edge(1)), (3, edge(5))]),
                (3, vec![(4, edge(1))]),
            ]),
        );
        tables
    }

    fn routing_with_direct_and_indirect_route() -> RoutingHandle {
        let routing = new_handle();
        routing.store(Arc::new(tables_with_direct_and_indirect_route()));
        routing
    }

    fn control_routing_with_route(dst: NodeIdentifier, next_hop: NodeIdentifier) -> RoutingHandle {
        let routing = new_handle();
        let mut tables = RoutingTables::empty();
        let table = HashMap::from([(
            dst,
            RouteEntry {
                next_hop,
                cost: 1,
                latency_us: 1,
            },
        )]);
        tables.insert_table(CONTROL_METRIC, CONTROL_LEVEL, table);
        routing.store(Arc::new(tables));
        routing
    }

    fn overlay_data_for_dsts(dsts: &[NodeIdentifier]) -> pb::OverlayData {
        let mut data = test_overlay_data(false);
        data.dsts = dsts.iter().map(|dst| node_to_wire(*dst)).collect();
        data
    }

    fn test_control(path_trace: Vec<u32>) -> pb::OverlayControl {
        pb::OverlayControl {
            origin: node_to_wire(1),
            origin_boot_epoch: 11,
            final_dst: node_to_wire(4),
            lane_id: 7,
            requester: node_to_wire(2),
            path_trace,
            body: Some(OverlayControlBody::Ack(pb::OverlayAck { next_seq: 5 })),
        }
    }

    struct CaptureService {
        tx: mpsc::UnboundedSender<OverlayInboundMessage>,
    }

    impl ServiceInbound for CaptureService {
        fn handle(&self, msg: OverlayInboundMessage) {
            let _ = self.tx.send(msg);
        }
    }

    fn capture_services_for(
        tag: u32,
    ) -> (
        ServiceRegistry,
        mpsc::UnboundedReceiver<OverlayInboundMessage>,
    ) {
        let services = ServiceRegistry::new();
        let (tx, rx) = mpsc::unbounded_channel();
        services.register(tag, Arc::new(CaptureService { tx }));
        (services, rx)
    }

    fn capture_services() -> (
        ServiceRegistry,
        mpsc::UnboundedReceiver<OverlayInboundMessage>,
    ) {
        capture_services_for(7)
    }

    async fn fill_outbound_queue(transport: &ConnectionManager, peer: NodeIdentifier) {
        for _ in 0..4096 {
            match transport
                .try_send(
                    peer,
                    ServiceLevel::Reliable,
                    None,
                    MessageClass::Regular,
                    Bytes::from_static(b"x"),
                )
                .await
            {
                Ok(()) => {}
                Err(SendError::Backpressure { node, transport }) => {
                    assert_eq!(node, peer);
                    assert_eq!(transport, TransportKind::Tcp);
                    return;
                }
                Err(err) => panic!("unexpected outbound queue fill error: {err:?}"),
            }
        }
        panic!("outbound test queue did not report backpressure");
    }

    async fn build_deadline_stream_pressure(transport: &ConnectionManager, peer: NodeIdentifier) {
        transport
            .try_send_with_options(
                peer,
                ServiceLevel::Reliable,
                Some(RoutingMetric::ReliableCost),
                MessageClass::Regular,
                Bytes::from(vec![0; 512 * 1024]),
                TransportSendOptions::default(),
            )
            .await
            .expect("stream pressure seed should enqueue");

        for _ in 0..20 {
            if transport
                .best_send_queue_pressure(
                    peer,
                    ServiceLevel::Reliable,
                    RoutingMetric::ReliableCost,
                    MessageClass::HighPriority,
                    TransportSendOptions::default().expire_after(VOICE_TRANSPORT_TTL),
                )
                .is_none_or(|pressure| pressure == 3)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("stream queue pressure did not become visible");
    }

    #[test]
    fn payload_hex_preview_is_bounded() {
        assert_eq!(payload_hex_preview(&[]), "");
        assert_eq!(payload_hex_preview(&[0, 1, 0xab, 0xff]), "0001abff");

        let payload = vec![0xff; FORWARD_PAYLOAD_LOG_BYTES + 2];
        let preview = payload_hex_preview(&payload);
        assert!(preview.starts_with(&"ff".repeat(FORWARD_PAYLOAD_LOG_BYTES)));
        assert!(preview.ends_with("...(+2 bytes)"));
    }

    #[test]
    fn overlay_data_compression_flag_survives_encode_decode() {
        let data = test_overlay_data(true);
        let encoded = encode_message(&wrap(OverlayBody::Data(data))).unwrap();
        let decoded = decode_message(&encoded).unwrap();

        let Some(OverlayBody::Data(decoded)) = decoded.body else {
            panic!("not overlay data");
        };
        assert!(decoded.allow_l1_compression);
    }

    #[test]
    fn overlay_attachment_roundtrips_without_affecting_the_base_payload() {
        let mut data = test_overlay_data(false);
        data.inline_attachments.push(pb::OverlayAttachment {
            kind: 9,
            attachment_id: 77,
            payload: b"metadata".to_vec(),
        });
        let encoded = encode_message(&wrap(OverlayBody::Data(data))).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        let Some(OverlayBody::Data(decoded)) = decoded.body else {
            panic!("not overlay data");
        };
        assert_eq!(decoded.payload, Bytes::from_static(b"payload"));
        assert_eq!(decoded.inline_attachments[0].payload, b"metadata");
    }

    #[test]
    fn attachment_priority_is_packed_in_deterministic_order() {
        let attachments = vec![
            OverlayAttachment::new(1, 1, Bytes::from_static(b"low")).with_priority(1),
            OverlayAttachment::new(2, 2, Bytes::from_static(b"high")).with_priority(9),
        ];
        let encoded = attachments_to_proto(&attachments);
        assert_eq!(
            encoded.iter().map(|item| item.kind).collect::<Vec<_>>(),
            vec![2, 1]
        );
    }

    #[tokio::test]
    async fn oversized_udp_attachment_is_emitted_as_disposable_sidecars() {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(1, 2, &[TransportKind::Tcp]);
        let mut data = test_overlay_data(false);
        data.inline_attachments.push(pb::OverlayAttachment {
            kind: 9,
            attachment_id: 77,
            payload: vec![0xab; 16 * 1024],
        });
        let plan = transport_payload_plan(
            &transport,
            2,
            ServiceLevel::Reliable,
            MessageClass::Regular,
            &data,
            &data.path_trace,
        )
        .expect("payload plan");
        let udp = plan.variant(TransportKind::Udp);
        assert!(udp.primary().len() < plan.default_variant().primary().len());
        assert!(!udp.sidecars().is_empty());
    }

    #[test]
    fn tree_hint_is_trimmed_to_one_branch_and_validated() {
        let tree = TreeState::new(1, [4, 5, 8], [(1, 2), (2, 4), (2, 5), (5, 8)]);
        let key = TreeKey {
            source: 1,
            profile: 3,
            group: 4,
            group_version: 5,
            topology_epoch: 6,
            version: 7,
        };
        let hint = tree_hint_for_child(key, &tree, 2).expect("branch hint");
        let mut data = test_overlay_data(false);
        data.src = node_to_wire(1);
        data.distribution_profile = Some(key.profile);
        data.distribution_tree_version = Some(key.version);
        data.distribution_group = Some(key.group);
        data.distribution_group_version = Some(key.group_version);
        data.distribution_topology_epoch = Some(key.topology_epoch);
        data.inline_attachments = vec![hint];
        let decoded = decode_tree_hint(&data, key, 2, &AttachmentCache::default())
            .expect("valid branch hint");
        assert_eq!(decoded.children(1), &[2]);
        assert_eq!(decoded.children(2), &[4, 5]);
        assert!(decoded.is_member(4));
        assert!(decoded.is_reachable_from(2, 8));
    }

    #[test]
    fn sidecar_reassembly_uses_the_base_message_identity() {
        let cache = AttachmentCache::default();
        let data = pb::OverlayData {
            src: node_to_wire(1),
            dsts: vec![node_to_wire(2)],
            origin_boot_epoch: 11,
            origin_message_id: 900,
            service_tag: super::super::OVERLAY_ATTACHMENT_SERVICE_TAG,
            ..test_overlay_data(false)
        };
        let chunk = pb::AttachmentChunk {
            base_origin_boot_epoch: 11,
            base_origin_message_id: 22,
            kind: 9,
            attachment_id: 77,
            chunk_index: 0,
            chunk_count: 1,
            total_bytes: 4,
            payload: b"hint".to_vec(),
        };
        let mut sidecar = data;
        sidecar.payload = chunk.encode_to_vec().into();
        assert!(consume_attachment_sidecar(&cache, 2, &sidecar));
        assert_eq!(
            cache.get(AttachmentKey::new(1, 11, 22, 9, 77)),
            Some(Bytes::from_static(b"hint"))
        );
    }

    #[test]
    fn forwarding_reconstruction_preserves_compression_flag() {
        let data = test_overlay_data(true);
        let forwarded = reconstruct_forwarded_data(
            &data,
            vec![node_to_wire(5), node_to_wire(6)],
            vec![node_to_wire(1), node_to_wire(2)],
        );

        assert!(forwarded.allow_l1_compression);
        assert_eq!(forwarded.payload, data.payload);
        assert_eq!(forwarded.dsts, vec![node_to_wire(5), node_to_wire(6)]);
        assert_eq!(forwarded.path_trace, vec![node_to_wire(1), node_to_wire(2)]);
    }

    #[test]
    fn voice_overlay_data_gets_expiring_transport_options() {
        let mut data = test_overlay_data(false);
        assert!(
            transport_options_for_overlay_data(&data, None)
                .expires_at()
                .is_none()
        );

        data.service_tag = VOICE_SERVICE_TAG;
        let before = std::time::Instant::now();
        let options = transport_options_for_overlay_data(&data, None);
        let expires_at = options.expires_at().expect("voice fallback ttl");
        assert_eq!(VOICE_TRANSPORT_TTL, Duration::from_millis(750));
        assert!(expires_at > before);
        assert!(expires_at <= before + Duration::from_millis(775));
        assert!(!options.is_expired());
    }

    #[test]
    fn voice_overlay_data_honors_explicit_transport_ttl() {
        let mut data = test_overlay_data(false);
        data.service_tag = VOICE_SERVICE_TAG;

        let options = transport_options_for_overlay_data(&data, Some(Duration::ZERO));

        assert!(options.expires_at().is_some());
        assert!(options.is_expired());
    }

    #[test]
    fn transit_no_route_drops_instead_of_direct_fallback() {
        let tables = RoutingTables::empty();
        let path_trace = HashSet::from([1]);

        let selected = select_forward_next_hop(
            &tables,
            2,
            4,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
            &path_trace,
            false,
        )
        .unwrap();

        assert_eq!(selected, ForwardNextHop::DropNoRoute);
    }

    #[test]
    fn origin_no_route_still_errors() {
        let tables = RoutingTables::empty();
        let path_trace = HashSet::new();

        let err = select_forward_next_hop(
            &tables,
            1,
            4,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
            &path_trace,
            true,
        )
        .unwrap_err();

        assert!(matches!(err, OverlayError::NoRoute { dst: 4, .. }));
    }

    #[test]
    fn transit_loop_drops_when_no_path_aware_alternate_exists() {
        let mut tables = RoutingTables::empty();
        tables.insert_table(
            RoutingMetric::ReliableCost,
            ServiceLevel::Reliable,
            HashMap::from([(
                4,
                RouteEntry {
                    next_hop: 1,
                    cost: 1,
                    latency_us: 1,
                },
            )]),
        );
        let path_trace = HashSet::from([1]);

        let selected = select_forward_next_hop(
            &tables,
            2,
            4,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
            &path_trace,
            false,
        )
        .unwrap();

        assert_eq!(selected, ForwardNextHop::DropLoop { next_hop: 1 });
    }

    #[test]
    fn transit_loop_uses_path_aware_alternate_when_available() {
        let mut tables = RoutingTables::empty();
        tables.insert_table_with_adjacency(
            RoutingMetric::ReliableCost,
            ServiceLevel::Reliable,
            HashMap::from([(
                4,
                RouteEntry {
                    next_hop: 1,
                    cost: 2,
                    latency_us: 2,
                },
            )]),
            HashMap::from([
                (13, vec![(1, edge(1)), (2, edge(1)), (3, edge(5))]),
                (2, vec![(1, edge(1))]),
                (1, vec![(4, edge(1))]),
                (3, vec![(4, edge(5))]),
            ]),
        );
        let path_trace = HashSet::from([1]);

        let selected = select_forward_next_hop(
            &tables,
            13,
            4,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
            &path_trace,
            false,
        )
        .unwrap();

        assert_eq!(selected, ForwardNextHop::Send { next_hop: 3 });
    }

    #[test]
    fn already_visited_destination_drops() {
        let tables = RoutingTables::empty();
        let path_trace = HashSet::from([4]);

        let selected = select_forward_next_hop(
            &tables,
            2,
            4,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
            &path_trace,
            false,
        )
        .unwrap();

        assert_eq!(selected, ForwardNextHop::DropAlreadyVisited);
    }

    #[test]
    fn avoiding_first_hop_still_allows_indirect_route_to_that_destination() {
        let tables = tables_with_direct_and_indirect_route();
        let path_trace = HashSet::from([1]);

        let alternate = tables
            .lookup_avoiding_first_hop_with_metric(
                1,
                4,
                ServiceLevel::Reliable,
                RoutingMetric::ReliableCost,
                &path_trace,
                4,
            )
            .expect("indirect route should remain available");

        assert_eq!(alternate.next_hop, 3);
    }

    #[test]
    fn avoid_first_hop_option_selects_loop_free_alternate() {
        let tables = tables_with_direct_and_indirect_route();
        let path_trace = HashSet::from([1]);

        let selected = select_forward_next_hop_for_send(
            &tables,
            1,
            4,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
            &path_trace,
            true,
            None,
            MessageClass::Regular,
            TransportSendOptions::default(),
            Some(4),
        )
        .expect("alternate should be selectable");

        assert_eq!(selected, ForwardNextHop::Send { next_hop: 3 });
    }

    #[test]
    fn avoid_first_hop_option_drops_when_no_alternate_exists() {
        let mut tables = RoutingTables::empty();
        tables.insert_table_with_adjacency(
            RoutingMetric::ReliableCost,
            ServiceLevel::Reliable,
            HashMap::from([(
                4,
                RouteEntry {
                    next_hop: 4,
                    cost: 1,
                    latency_us: 1,
                },
            )]),
            HashMap::from([(1, vec![(4, edge(1))])]),
        );
        let path_trace = HashSet::from([1]);

        let selected = select_forward_next_hop_for_send(
            &tables,
            1,
            4,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
            &path_trace,
            true,
            None,
            MessageClass::Regular,
            TransportSendOptions::default(),
            Some(4),
        )
        .expect("selection should complete");

        assert_eq!(selected, ForwardNextHop::DropNoRoute);
    }

    #[tokio::test]
    async fn deadline_sensitive_forward_chooses_less_pressured_alternate_first_hop() {
        let (transport, mut receivers) =
            ConnectionManager::test_with_live_streams(1, 4, &[TransportKind::Tcp]);
        let _direct_rx = receivers.pop().unwrap();
        let mut alternate_rx = transport.test_install_live_stream(3, TransportKind::Tcp);
        build_deadline_stream_pressure(&transport, 4).await;
        let routing = routing_with_direct_and_indirect_route();
        let mut data = test_overlay_data(false);
        data.service_tag = VOICE_SERVICE_TAG;

        forward_pb_as(
            &transport,
            &routing,
            1,
            data,
            MessageClass::HighPriority,
            true,
            None,
            None,
        )
        .await
        .expect("voice forward should use alternate");

        let forwarded = timeout(Duration::from_millis(50), alternate_rx.recv())
            .await
            .expect("alternate first hop should receive forwarded voice")
            .expect("alternate receiver should stay open");
        let decoded = decode_message(forwarded.payload()).expect("overlay data");
        let Some(OverlayBody::Data(data)) = decoded.body else {
            panic!("not overlay data");
        };
        assert_eq!(data.dsts, vec![node_to_wire(4)]);
    }

    #[tokio::test]
    async fn deadline_sensitive_forward_keeps_direct_when_alternate_is_not_better() {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(1, 4, &[TransportKind::Tcp]);
        let _alternate_rx = transport.test_install_live_stream(3, TransportKind::Tcp);
        build_deadline_stream_pressure(&transport, 4).await;
        build_deadline_stream_pressure(&transport, 3).await;
        let tables = tables_with_direct_and_indirect_route();
        let path_trace = HashSet::from([1]);

        let selected = select_forward_next_hop_for_send(
            &tables,
            1,
            4,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
            &path_trace,
            true,
            Some(&transport),
            MessageClass::HighPriority,
            TransportSendOptions::default().expire_after(VOICE_TRANSPORT_TTL),
            None,
        )
        .expect("route should be selectable");

        assert_eq!(selected, ForwardNextHop::Send { next_hop: 4 });
    }

    #[tokio::test]
    async fn overlay_control_appends_self_to_path_trace() {
        let (transport, mut receivers) =
            ConnectionManager::test_with_live_streams(2, 4, &[TransportKind::Tcp]);
        let mut to_four = receivers.pop().unwrap();
        let routing = control_routing_with_route(4, 4);

        send_control_to(
            &transport,
            &routing,
            2,
            4,
            test_control(vec![node_to_wire(1)]),
        )
        .await
        .expect("control should send");

        let forwarded = timeout(Duration::from_millis(50), to_four.recv())
            .await
            .expect("destination 4 should receive control")
            .expect("receiver should stay open");
        let decoded = decode_message(forwarded.payload()).expect("overlay control");
        let Some(OverlayBody::Control(control)) = decoded.body else {
            panic!("not overlay control");
        };
        assert_eq!(control.path_trace, vec![node_to_wire(1), node_to_wire(2)]);
    }

    #[tokio::test]
    async fn overlay_control_drops_when_target_already_visited() {
        let (transport, mut receivers) =
            ConnectionManager::test_with_live_streams(2, 4, &[TransportKind::Tcp]);
        let mut to_four = receivers.pop().unwrap();
        let routing = control_routing_with_route(4, 4);

        send_control_to(
            &transport,
            &routing,
            2,
            4,
            test_control(vec![node_to_wire(1), node_to_wire(4)]),
        )
        .await
        .expect("drop is not an error");

        assert!(
            timeout(Duration::from_millis(20), to_four.recv())
                .await
                .is_err(),
            "visited control target should not receive a frame"
        );
    }

    #[tokio::test]
    async fn overlay_control_uses_path_aware_alternate_when_next_hop_was_visited() {
        let (transport, mut receivers) =
            ConnectionManager::test_with_live_streams(13, 3, &[TransportKind::Tcp]);
        let mut to_three = receivers.pop().unwrap();
        let routing = new_handle();
        let mut tables = RoutingTables::empty();
        tables.insert_table_with_adjacency(
            CONTROL_METRIC,
            CONTROL_LEVEL,
            HashMap::from([(
                4,
                RouteEntry {
                    next_hop: 1,
                    cost: 2,
                    latency_us: 2,
                },
            )]),
            HashMap::from([
                (13, vec![(1, edge(1)), (3, edge(5))]),
                (1, vec![(4, edge(1))]),
                (3, vec![(4, edge(5))]),
            ]),
        );
        routing.store(Arc::new(tables));

        send_control_to(
            &transport,
            &routing,
            13,
            4,
            test_control(vec![node_to_wire(1)]),
        )
        .await
        .expect("control should use alternate next hop");

        let forwarded = timeout(Duration::from_millis(50), to_three.recv())
            .await
            .expect("alternate next hop should receive control")
            .expect("receiver should stay open");
        let decoded = decode_message(forwarded.payload()).expect("overlay control");
        let Some(OverlayBody::Control(control)) = decoded.body else {
            panic!("not overlay control");
        };
        assert_eq!(control.path_trace, vec![node_to_wire(1), node_to_wire(13)]);
    }

    #[tokio::test]
    async fn overlay_control_drops_when_no_loop_free_route_exists() {
        let (transport, mut receivers) =
            ConnectionManager::test_with_live_streams(13, 1, &[TransportKind::Tcp]);
        let mut to_one = receivers.pop().unwrap();
        let routing = control_routing_with_route(4, 1);

        send_control_to(
            &transport,
            &routing,
            13,
            4,
            test_control(vec![node_to_wire(1)]),
        )
        .await
        .expect("drop is not an error");

        assert!(
            timeout(Duration::from_millis(20), to_one.recv())
                .await
                .is_err(),
            "looped control next hop should not receive a frame"
        );
    }

    #[tokio::test]
    async fn transit_overlay_forward_returns_promptly_when_peer_outbound_queue_is_full() {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(2, 4, &[TransportKind::Tcp]);
        fill_outbound_queue(&transport, 4).await;
        let routing = routing_with_route(4, 4);

        timeout(
            Duration::from_millis(50),
            forward_pb_as(
                &transport,
                &routing,
                2,
                test_overlay_data(false),
                MessageClass::Regular,
                false,
                None,
                None,
            ),
        )
        .await
        .expect("transit forward should not wait for outbound queue space")
        .unwrap();
    }

    #[tokio::test]
    async fn originated_overlay_forward_returns_backpressure_when_peer_outbound_queue_is_full() {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(1, 4, &[TransportKind::Tcp]);
        fill_outbound_queue(&transport, 4).await;
        let routing = routing_with_route(4, 4);

        let err = timeout(
            Duration::from_millis(50),
            forward_pb_as(
                &transport,
                &routing,
                1,
                test_overlay_data(false),
                MessageClass::Regular,
                true,
                None,
                None,
            ),
        )
        .await
        .expect("originated forward should not wait for outbound queue space")
        .unwrap_err();

        assert!(matches!(
            err,
            OverlayError::Send(SendError::Backpressure {
                node: 4,
                transport: TransportKind::Tcp,
            })
        ));
    }

    #[tokio::test]
    async fn originated_overlay_forward_still_reaches_healthy_peer_when_another_queue_is_full() {
        let (transport_to_stuck, _stuck_rx) =
            ConnectionManager::test_with_live_streams(1, 4, &[TransportKind::Tcp]);
        fill_outbound_queue(&transport_to_stuck, 4).await;

        let transport = transport_to_stuck;
        let mut healthy_rx = transport.test_install_live_stream(5, TransportKind::Tcp);
        let routing = routing_with_routes(&[(4, 4), (5, 5)]);

        let err = timeout(
            Duration::from_millis(50),
            forward_pb_as(
                &transport,
                &routing,
                1,
                overlay_data_for_dsts(&[4, 5]),
                MessageClass::Regular,
                true,
                None,
                None,
            ),
        )
        .await
        .expect("stuck peer should not block sending to healthy peer")
        .unwrap_err();

        assert!(matches!(
            err,
            OverlayError::Send(SendError::Backpressure {
                node: 4,
                transport: TransportKind::Tcp,
            })
        ));
        let forwarded = timeout(Duration::from_millis(50), healthy_rx.recv())
            .await
            .expect("healthy peer should receive its frame")
            .expect("healthy peer receiver should remain open");
        assert_eq!(forwarded.class(), MessageClass::Regular);
        let decoded = decode_message(forwarded.payload()).expect("overlay data");
        let Some(OverlayBody::Data(data)) = decoded.body else {
            panic!("not overlay data");
        };
        assert_eq!(data.dsts, vec![node_to_wire(5)]);
    }

    #[tokio::test]
    async fn originated_overlay_forward_still_reaches_healthy_peer_without_other_transport() {
        let (transport, mut receivers) =
            ConnectionManager::test_with_live_streams(1, 5, &[TransportKind::Tcp]);
        let mut healthy_rx = receivers.pop().expect("healthy receiver");
        let routing = routing_with_routes(&[(4, 4), (5, 5)]);

        let err = forward_pb_as(
            &transport,
            &routing,
            1,
            overlay_data_for_dsts(&[4, 5]),
            MessageClass::Regular,
            true,
            None,
            None,
        )
        .await
        .expect_err("missing transport should still be reported");

        assert!(
            matches!(
                err,
                OverlayError::Send(
                    SendError::NoSuitableTransport { node: 4 } | SendError::UnknownNode { node: 4 }
                )
            ),
            "unexpected error: {err:?}"
        );
        let forwarded = timeout(Duration::from_millis(50), healthy_rx.recv())
            .await
            .expect("healthy peer should receive its frame")
            .expect("healthy peer receiver should remain open");
        let decoded = decode_message(forwarded.payload()).expect("overlay data");
        let Some(OverlayBody::Data(data)) = decoded.body else {
            panic!("not overlay data");
        };
        assert_eq!(data.dsts, vec![node_to_wire(5)]);
    }

    #[tokio::test]
    async fn originated_unordered_overlay_data_has_message_identity() {
        let (transport, mut receivers) =
            ConnectionManager::test_with_live_streams(1, 4, &[TransportKind::Tcp]);
        let mut to_four = receivers.pop().unwrap();
        let routing = routing_with_route(4, 4);
        let ordering = OverlayOrdering::default();

        originate(
            &transport,
            &routing,
            1,
            1234,
            &ordering,
            vec![4],
            7,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
            MessageClass::Regular,
            Bytes::from_static(b"payload"),
            None,
            false,
            OverlaySendOptions::default(),
        )
        .await
        .expect("originated unordered overlay send");

        let forwarded = timeout(Duration::from_millis(50), to_four.recv())
            .await
            .expect("destination 4 should receive originated packet")
            .expect("receiver 4 should stay open");
        let decoded = decode_message(forwarded.payload()).expect("overlay data");
        let Some(OverlayBody::Data(data)) = decoded.body else {
            panic!("not overlay data");
        };
        assert!(!data.ordered_delivery);
        assert_eq!(data.origin_boot_epoch, 1234);
        assert_ne!(data.origin_message_id, 0);
        assert!(!data.distribution_repair);
    }

    #[tokio::test]
    async fn originated_unordered_repair_copy_sets_existing_wire_marker() {
        let (transport, mut receivers) =
            ConnectionManager::test_with_live_streams(1, 4, &[TransportKind::Tcp]);
        let mut to_four = receivers.pop().unwrap();
        let routing = routing_with_route(4, 4);
        let ordering = OverlayOrdering::default();

        originate(
            &transport,
            &routing,
            1,
            1234,
            &ordering,
            vec![4],
            VOICE_SERVICE_TAG,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
            MessageClass::Regular,
            Bytes::from_static(b"repair"),
            None,
            false,
            OverlaySendOptions::default().as_distribution_repair(),
        )
        .await
        .expect("originated repair copy");

        let forwarded = timeout(Duration::from_millis(50), to_four.recv())
            .await
            .expect("destination 4 should receive repair copy")
            .expect("receiver 4 should stay open");
        let decoded = decode_message(forwarded.payload()).expect("overlay data");
        let Some(OverlayBody::Data(data)) = decoded.body else {
            panic!("not overlay data");
        };
        assert!(data.distribution_repair);
        assert_eq!(data.distribution_repair_target, None);
    }

    #[tokio::test]
    async fn ordinary_repair_copy_reaches_receiver_with_repair_provenance() {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(2, 1, &[TransportKind::Tcp]);
        let routing = new_handle();
        let (services, mut delivered) = capture_services_for(VOICE_SERVICE_TAG);
        let ordering = OverlayOrdering::default();
        let mut data = test_overlay_data(false);
        data.service_tag = VOICE_SERVICE_TAG;
        data.dsts = vec![node_to_wire(2)];
        data.distribution_repair = true;

        handle_inbound(
            &transport, &routing, &services, &ordering, 2, 1, data, false,
        )
        .await;

        let msg = timeout(Duration::from_millis(50), delivered.recv())
            .await
            .expect("local service should receive repair copy")
            .expect("capture receiver should stay open");
        assert!(msg.is_distribution_repair);
    }

    #[tokio::test]
    async fn tree_delivery_ignores_legacy_remote_playout_metadata() {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(2, 1, &[TransportKind::Tcp]);
        let routing = new_handle();
        let distribution = DistributionPlane::default();
        let monitor = test_monitor();
        let (services, mut delivered) = capture_services_for(VOICE_SERVICE_TAG);
        let ordering = OverlayOrdering::default();
        let mut data = test_overlay_data(false);
        data.service_tag = VOICE_SERVICE_TAG;

        let tree = Arc::new(TreeState::new_with_playout(1, [2], [(1, 2)], [(2, 750)]));
        process_distribution_frame(
            &transport,
            &routing,
            &distribution,
            &monitor,
            &ordering,
            &services,
            2,
            1,
            data,
            tree,
            false,
            Duration::from_millis(750),
        )
        .await;

        let msg = timeout(Duration::from_millis(50), delivered.recv())
            .await
            .expect("tree member should receive frame")
            .expect("capture receiver should stay open");
        assert_eq!(msg.remote_playout_delay_ms, None);
    }

    #[tokio::test]
    async fn unordered_final_and_transit_duplicate_delivers_and_forwards_once() {
        let (transport, mut receivers) =
            ConnectionManager::test_with_live_streams(2, 4, &[TransportKind::Tcp]);
        let mut forwarded_to_four = receivers.pop().unwrap();
        let routing = routing_with_route(4, 4);
        let (services, mut delivered) = capture_services();
        let ordering = OverlayOrdering::default();

        let mut data = overlay_data_for_dsts(&[2, 4]);
        data.process_on_transit = true;
        data.origin_boot_epoch = 77;
        data.origin_message_id = 9001;

        handle_inbound(
            &transport,
            &routing,
            &services,
            &ordering,
            2,
            1,
            data.clone(),
            true,
        )
        .await;

        let msg = timeout(Duration::from_millis(50), delivered.recv())
            .await
            .expect("local service should receive final delivery")
            .expect("capture receiver should stay open");
        assert_eq!(msg.from, 1);
        assert_eq!(msg.body, Bytes::from_static(b"payload"));

        let forwarded = timeout(Duration::from_millis(50), forwarded_to_four.recv())
            .await
            .expect("first copy should forward destination 4")
            .expect("forward receiver should stay open");
        let decoded = decode_message(forwarded.payload()).expect("overlay data");
        let Some(OverlayBody::Data(forwarded_data)) = decoded.body else {
            panic!("not overlay data");
        };
        assert_eq!(forwarded_data.dsts, vec![node_to_wire(4)]);

        let mut duplicate = data;
        duplicate.dsts = vec![node_to_wire(4)];
        duplicate.path_trace = vec![node_to_wire(1), node_to_wire(3)];
        handle_inbound(
            &transport, &routing, &services, &ordering, 2, 3, duplicate, true,
        )
        .await;

        assert!(
            timeout(Duration::from_millis(20), delivered.recv())
                .await
                .is_err(),
            "duplicate unordered transit copy should not be delivered locally"
        );
        assert!(
            timeout(Duration::from_millis(20), forwarded_to_four.recv())
                .await
                .is_err(),
            "duplicate unordered transit copy should not forward destination 4 again"
        );
    }

    #[tokio::test]
    async fn voice_transit_processing_is_ignored_even_for_legacy_unordered_packets() {
        let (transport, mut receivers) =
            ConnectionManager::test_with_live_streams(2, 4, &[TransportKind::Tcp]);
        let mut forwarded_to_four = receivers.pop().unwrap();
        let routing = routing_with_route(4, 4);
        let (services, mut delivered) = capture_services_for(VOICE_SERVICE_TAG);
        let ordering = OverlayOrdering::default();

        let mut data = overlay_data_for_dsts(&[4]);
        data.service_tag = VOICE_SERVICE_TAG;
        data.process_on_transit = true;
        data.origin_message_id = 0;

        handle_inbound(&transport, &routing, &services, &ordering, 2, 1, data, true).await;

        assert!(
            timeout(Duration::from_millis(20), delivered.recv())
                .await
                .is_err(),
            "pure relay should not locally process transit voice frames"
        );

        let forwarded = timeout(Duration::from_millis(50), forwarded_to_four.recv())
            .await
            .expect("legacy voice transit packet should still be forwarded")
            .expect("forward receiver should stay open");
        let decoded = decode_message(forwarded.payload()).expect("overlay data");
        let Some(OverlayBody::Data(forwarded_data)) = decoded.body else {
            panic!("not overlay data");
        };
        assert_eq!(forwarded_data.dsts, vec![node_to_wire(4)]);
        assert_eq!(forwarded_data.service_tag, VOICE_SERVICE_TAG);
    }

    #[tokio::test]
    async fn unordered_overlapping_transit_copy_forwards_only_new_destinations() {
        let (transport, mut receivers) =
            ConnectionManager::test_with_live_streams(2, 4, &[TransportKind::Tcp]);
        let mut to_four = receivers.pop().unwrap();
        let mut to_five = transport.test_install_live_stream(5, TransportKind::Tcp);
        let mut to_six = transport.test_install_live_stream(6, TransportKind::Tcp);
        let routing = routing_with_routes(&[(4, 4), (5, 5), (6, 6)]);
        let services = ServiceRegistry::new();
        let ordering = OverlayOrdering::default();

        let mut first = overlay_data_for_dsts(&[4, 5]);
        first.origin_boot_epoch = 88;
        first.origin_message_id = 4242;
        handle_inbound(
            &transport, &routing, &services, &ordering, 2, 1, first, true,
        )
        .await;

        let forwarded_four = timeout(Duration::from_millis(50), to_four.recv())
            .await
            .expect("destination 4 should be forwarded")
            .expect("receiver 4 should stay open");
        let decoded = decode_message(forwarded_four.payload()).expect("overlay data");
        let Some(OverlayBody::Data(forwarded_four_data)) = decoded.body else {
            panic!("not overlay data");
        };
        assert_eq!(forwarded_four_data.dsts, vec![node_to_wire(4)]);

        let forwarded_five = timeout(Duration::from_millis(50), to_five.recv())
            .await
            .expect("destination 5 should be forwarded")
            .expect("receiver 5 should stay open");
        let decoded = decode_message(forwarded_five.payload()).expect("overlay data");
        let Some(OverlayBody::Data(forwarded_five_data)) = decoded.body else {
            panic!("not overlay data");
        };
        assert_eq!(forwarded_five_data.dsts, vec![node_to_wire(5)]);

        let mut overlapping = overlay_data_for_dsts(&[5, 6]);
        overlapping.origin_boot_epoch = 88;
        overlapping.origin_message_id = 4242;
        overlapping.path_trace = vec![node_to_wire(1), node_to_wire(3)];
        handle_inbound(
            &transport,
            &routing,
            &services,
            &ordering,
            2,
            3,
            overlapping,
            true,
        )
        .await;

        assert!(
            timeout(Duration::from_millis(20), to_five.recv())
                .await
                .is_err(),
            "destination 5 should already be marked forwarded"
        );

        let forwarded_six = timeout(Duration::from_millis(50), to_six.recv())
            .await
            .expect("new destination 6 should still be forwarded")
            .expect("receiver 6 should stay open");
        let decoded = decode_message(forwarded_six.payload()).expect("overlay data");
        let Some(OverlayBody::Data(forwarded_six_data)) = decoded.body else {
            panic!("not overlay data");
        };
        assert_eq!(forwarded_six_data.dsts, vec![node_to_wire(6)]);
    }

    #[test]
    fn alternate_tree_repair_requires_realtime_profile_and_80ms_deadline() {
        let eligible = pb::OverlayData {
            distribution_profile: Some(crate::overlay::distribution::VOICE_REALTIME_PROFILE_ID),
            distribution_deadline_unix_ms: Some(unix_time_ms().saturating_add(100)),
            ..Default::default()
        };
        assert!(should_attempt_alternate_tree_repair(&eligible));

        let too_late = pb::OverlayData {
            distribution_deadline_unix_ms: Some(unix_time_ms().saturating_add(79)),
            ..eligible.clone()
        };
        assert!(!should_attempt_alternate_tree_repair(&too_late));

        let repair_copy = pb::OverlayData {
            distribution_repair: true,
            ..eligible
        };
        assert!(!should_attempt_alternate_tree_repair(&repair_copy));
    }

    #[test]
    fn v2_deadline_rebases_from_direct_peer_clock() {
        // The issuer is 25 ms ahead, so its 1.025 s deadline means 1.000 s
        // in our local wall clock.
        assert_eq!(rebase_deadline_us(1_025_000, 25_000), Some(1_000_000));
        assert_eq!(rebase_deadline_us(1_000_000, -25_000), Some(1_025_000));
        assert_eq!(rebase_deadline_us(1, 2), None);
    }

    #[test]
    fn v2_deadline_rebases_htpdate_sized_clock_steps() {
        // htpdate can leave node 1 hundreds of milliseconds away from the
        // rest of the overlay. Signed rebasing must remain exact in either
        // direction and never underflow a deadline.
        assert_eq!(rebase_deadline_us(2_250_000, 500_000), Some(1_750_000));
        assert_eq!(rebase_deadline_us(1_750_000, -500_000), Some(2_250_000));
        assert_eq!(rebase_deadline_us(499_999, 500_000), None);
    }

    #[tokio::test]
    async fn v2_deadline_translation_rebases_issuer_and_charges_measured_guard() {
        let monitor = monitor_with_peer_clock_offset(500_000);
        let local_deadline = unix_time_us().saturating_add(300_000);
        let mut data = pb::OverlayData {
            distribution_deadline_unix_ms: Some(unix_time_ms().saturating_add(300)),
            distribution_deadline_issuer: Some(node_to_wire(1)),
            distribution_deadline_unix_us: Some(local_deadline.saturating_add(500_000)),
            ..Default::default()
        };

        let remaining = translate_v2_deadline_for_local_hop(&mut data, &monitor, 2, 1)
            .expect("fresh direct-peer estimate should translate v2 deadline");

        assert_eq!(data.distribution_deadline_issuer, Some(node_to_wire(2)));
        assert_eq!(data.distribution_deadline_unix_us, Some(local_deadline));
        assert_eq!(data.distribution_deadline_unix_ms, None);
        // The sample has 20 ms network RTT, so the local forwarding budget is
        // the rebased deadline minus 10 ms uncertainty and the 20 ms guard.
        assert!(remaining <= Duration::from_millis(270));
        assert!(remaining > Duration::from_millis(220));
    }

    #[tokio::test]
    async fn v2_deadline_without_fresh_direct_peer_estimate_requires_legacy_path() {
        let monitor = test_monitor();
        let mut data = pb::OverlayData {
            distribution_deadline_issuer: Some(node_to_wire(1)),
            distribution_deadline_unix_us: Some(unix_time_us().saturating_add(750_000)),
            ..Default::default()
        };

        assert_eq!(
            translate_v2_deadline_for_local_hop(&mut data, &monitor, 2, 1),
            Err(DistributionDeadlineError::MissingOffset)
        );
    }

    #[test]
    fn clock_fallback_clears_tree_state_for_only_the_child_subtree() {
        let mut data = test_overlay_data(false);
        data.distribution_profile = Some(crate::overlay::distribution::VOICE_REALTIME_PROFILE_ID);
        data.distribution_tree_version = Some(9);
        data.distribution_group = Some(0);
        data.distribution_group_version = Some(4);
        data.distribution_topology_epoch = Some(7);
        data.distribution_deadline_unix_ms = Some(unix_time_ms().saturating_add(750));
        data.distribution_deadline_issuer = Some(node_to_wire(1));
        data.distribution_deadline_unix_us = Some(unix_time_us().saturating_add(750_000));
        let fallback = legacy_subtree_fallback_data(&data, vec![2, 3], vec![node_to_wire(1)]);

        assert_eq!(fallback.dsts, vec![node_to_wire(2), node_to_wire(3)]);
        assert_eq!(fallback.path_trace, vec![node_to_wire(1)]);
        assert_eq!(fallback.distribution_profile, None);
        assert_eq!(fallback.distribution_tree_version, None);
        assert_eq!(fallback.distribution_group, None);
        assert_eq!(fallback.distribution_group_version, None);
        assert_eq!(fallback.distribution_topology_epoch, None);
        assert_eq!(fallback.distribution_deadline_unix_ms, None);
        assert!(!fallback.distribution_repair);
        assert_eq!(fallback.distribution_repair_target, None);
        assert_eq!(fallback.distribution_deadline_issuer, None);
        assert_eq!(fallback.distribution_deadline_unix_us, None);

        data.distribution_repair = true;
        let repair = legacy_subtree_fallback_data(&data, vec![2], Vec::new());
        assert!(repair.distribution_repair);
        assert_eq!(repair.distribution_profile, None);
    }

    #[tokio::test]
    async fn clock_unready_tree_children_fall_back_once_to_their_exact_subtrees() {
        let (transport, mut receivers) =
            ConnectionManager::test_with_live_streams(1, 2, &[TransportKind::Tcp]);
        let mut to_two = receivers.pop().expect("node 2 stream");
        let mut to_three = transport.test_install_live_stream(3, TransportKind::Tcp);
        let mut to_four = transport.test_install_live_stream(4, TransportKind::Tcp);
        let routing = routing_with_routes(&[(2, 2), (3, 3), (4, 4)]);
        let tree = TreeState::new(1, [2, 3, 4], [(1, 2), (2, 3), (1, 4)]);
        let distribution = DistributionPlane::default();
        let monitor = test_monitor();
        let mut data = test_overlay_data(false);
        data.dsts.clear();
        data.service_tag = VOICE_SERVICE_TAG;
        data.distribution_profile = Some(crate::overlay::distribution::VOICE_REALTIME_PROFILE_ID);
        data.distribution_tree_version = Some(9);
        data.distribution_group = Some(0);
        data.distribution_group_version = Some(1);
        data.distribution_topology_epoch = Some(1);
        data.distribution_deadline_issuer = Some(node_to_wire(1));
        data.distribution_deadline_unix_us = Some(unix_time_us().saturating_add(750_000));

        forward_tree_data(
            &transport,
            &routing,
            &distribution,
            &monitor,
            1,
            data,
            &tree,
            MessageClass::HighPriority,
            None,
        )
        .await
        .expect("clock fallback should use normal destination forwarding");

        for (dst, receiver) in [(2, &mut to_two), (3, &mut to_three), (4, &mut to_four)] {
            let forwarded = timeout(Duration::from_millis(50), receiver.recv())
                .await
                .expect("legacy subtree recipient should receive a frame")
                .expect("receiver should remain open");
            let decoded = decode_message(forwarded.payload()).expect("overlay data");
            let Some(OverlayBody::Data(data)) = decoded.body else {
                panic!("not overlay data");
            };
            assert_eq!(data.dsts, vec![node_to_wire(dst)]);
            assert_eq!(data.distribution_profile, None);
            assert_eq!(data.distribution_tree_version, None);
            assert_eq!(data.distribution_deadline_issuer, None);
            assert_eq!(data.distribution_deadline_unix_us, None);
        }

        assert!(
            timeout(Duration::from_millis(20), to_two.recv())
                .await
                .is_err(),
            "the fallback must not duplicate the node 2 branch"
        );
        assert!(
            timeout(Duration::from_millis(20), to_three.recv())
                .await
                .is_err(),
            "the fallback must not duplicate the node 3 branch"
        );
        assert!(
            timeout(Duration::from_millis(20), to_four.recv())
                .await
                .is_err(),
            "the fallback must not duplicate the node 4 branch"
        );
    }

    #[test]
    fn v2_deadline_requires_uncertainty_plus_processing_guard() {
        let uncertainty = Duration::from_millis(10);
        assert_eq!(
            remaining_after_clock_guard(31_000, 0, uncertainty),
            Ok(Duration::from_millis(1))
        );
        assert_eq!(
            remaining_after_clock_guard(30_000, 0, uncertainty),
            Err(DistributionDeadlineError::Expired)
        );
    }

    #[test]
    fn v1_deadline_still_uses_legacy_millisecond_fallback() {
        assert_eq!(
            legacy_distribution_remaining_deadline(1_100, 1_000),
            Some(Duration::from_millis(100)),
            "legacy v1 must not consume a fixed skew budget at each hop"
        );
        let data = pb::OverlayData {
            distribution_deadline_unix_ms: Some(unix_time_ms().saturating_add(100)),
            ..Default::default()
        };
        let remaining = distribution_remaining_deadline(&data).expect("legacy deadline");
        assert!(remaining <= Duration::from_millis(100));
        assert!(remaining > Duration::from_millis(50));
    }

    #[test]
    fn voice_transport_default_allows_long_haul_budget() {
        assert_eq!(VOICE_TRANSPORT_TTL, Duration::from_millis(750));
    }
}
