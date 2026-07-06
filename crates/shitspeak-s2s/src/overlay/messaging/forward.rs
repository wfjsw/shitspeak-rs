//! Routing-aware forwarding for `OverlayData` and ordered-lane repair control.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::future::join_all;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::application::proto::VOICE_SERVICE_TAG;
use crate::overlay::LaneId;
use crate::overlay::config::OverlayConfig;
use shitspeak_core::NodeIdentifier;
use shitspeak_proto::s2s_overlay_proto as pb;
use shitspeak_s2s_transport::{
    ConnectionManager, MessageClass, SendOptions as TransportSendOptions, ServiceLevel,
};

use super::super::error::OverlayError;
use super::super::proto::{
    OverlayBody, OverlayControlBody, class_from_wire, class_to_wire, encode_message,
    level_from_wire, level_to_wire, node_to_wire, route_metric_from_wire, route_metric_to_wire,
    wrap,
};
use super::super::routing::{RoutingHandle, RoutingMetric, RoutingTables};
use super::delivery;
use super::ordering::OverlayOrdering;
use super::{OverlaySendOptions, ServiceRegistry};

const FORWARD_PAYLOAD_LOG_BYTES: usize = 256;
const CONTROL_LEVEL: ServiceLevel = ServiceLevel::ReliableLowLatency;
const CONTROL_METRIC: RoutingMetric = RoutingMetric::ReliableLowLatencyCost;
const VOICE_TRANSPORT_TTL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectFallbackReason {
    NoRoute,
    Loop { next_hop: NodeIdentifier },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForwardNextHop {
    Send {
        next_hop: NodeIdentifier,
        fallback: Option<DirectFallbackReason>,
    },
    DropAlreadyVisited,
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
            allow_l1_compression: options.l1_compression_allowed(),
        };
        return forward_pb_as(
            transport, routing, self_id, data, class, /*is_originator=*/ true,
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
            allow_l1_compression: options.l1_compression_allowed(),
        };
        ordering.store_pending(lane, data.clone()).await;
        ordering.cache_ordered_packet(&data).await;
        if let Err(err) = forward_pb_as(
            transport, routing, self_id, data, class, /*is_originator=*/ true,
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
            delivery::deliver(
                services,
                data.service_tag,
                src,
                level,
                class,
                data.payload.clone(),
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
        transport, routing, self_id, data2, class, /*is_originator=*/ false,
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
                        ).await;
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
    control: pb::OverlayControl,
) -> Result<(), OverlayError> {
    if target == self_id {
        return Ok(());
    }
    let body = OverlayBody::Control(control);
    #[cfg(debug_assertions)]
    let packet_kind = crate::debug_io::classify_overlay_body(&body);
    let payload = encode_message(&wrap(body))?;
    #[cfg(debug_assertions)]
    let payload_len = payload.len();
    let result = send_encoded_to_target(
        transport,
        routing,
        self_id,
        target,
        CONTROL_LEVEL,
        CONTROL_METRIC,
        MessageClass::Control,
        payload,
        false,
    )
    .await;
    #[cfg(debug_assertions)]
    if result.is_ok() {
        crate::debug_io::record_sent(packet_kind, payload_len);
    }
    result
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

/// Forward an `OverlayData` whose `dsts` may contain multiple final destinations.
async fn forward_pb_as(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    data: pb::OverlayData,
    transport_class: MessageClass,
    is_originator: bool,
) -> Result<(), OverlayError> {
    let level = level_from_wire(data.service_level).unwrap_or(ServiceLevel::Reliable);
    let routing_metric = route_metric_from_wire(data.route_metric, level)
        .unwrap_or_else(|| RoutingMetric::default_for_level(level));
    let tables = routing.load();

    let path_trace_set: HashSet<NodeIdentifier> = data
        .path_trace
        .iter()
        .filter_map(|node| NodeIdentifier::try_from(*node).ok())
        .collect();
    let mut buckets: HashMap<NodeIdentifier, Vec<u32>> = HashMap::new();
    for dst_wire in &data.dsts {
        let Ok(dst) = NodeIdentifier::try_from(*dst_wire) else {
            continue;
        };
        if dst == self_id {
            continue;
        }
        match select_forward_next_hop(
            &tables,
            self_id,
            dst,
            level,
            routing_metric,
            &path_trace_set,
            is_originator,
        )? {
            ForwardNextHop::Send { next_hop, fallback } => {
                if let Some(reason) = fallback {
                    debug!(
                        self_id = %self_id,
                        src = %NodeIdentifier::try_from(data.src).unwrap_or(0),
                        %dst,
                        %next_hop,
                        ?reason,
                        ?level,
                        ?routing_metric,
                        "routing snapshot unstable; falling back to direct next hop"
                    );
                }
                buckets.entry(next_hop).or_default().push(*dst_wire);
            }
            ForwardNextHop::DropAlreadyVisited => {
                warn!(%dst, "destination already in path_trace; dropping");
            }
        }
    }
    if buckets.is_empty() {
        return Ok(());
    }

    let mut new_trace = data.path_trace.clone();
    let self_wire = node_to_wire(self_id);
    if !new_trace.contains(&self_wire) {
        new_trace.push(self_wire);
    }
    let mut sends = Vec::with_capacity(buckets.len());
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

        let send_options = transport_options_for_overlay_data(&pb_msg);
        let body = OverlayBody::Data(pb_msg);
        #[cfg(debug_assertions)]
        let packet_kind = crate::debug_io::classify_overlay_body(&body);
        let payload = match encode_message(&wrap(body)) {
            Ok(b) => b,
            Err(e) => {
                if is_originator {
                    return Err(OverlayError::Encode(e));
                }
                warn!(error=%e, "encode forward failed");
                continue;
            }
        };
        #[cfg(debug_assertions)]
        let payload_len = payload.len();
        let transport = transport.clone();
        sends.push(async move {
            let result = transport
                .try_send_with_options(
                    next_hop,
                    level,
                    Some(routing_metric),
                    transport_class,
                    payload,
                    send_options,
                )
                .await;
            #[cfg(debug_assertions)]
            if result.is_ok() {
                crate::debug_io::record_sent(packet_kind, payload_len);
            }
            (next_hop, result)
        });
    }

    let mut first_err: Option<OverlayError> = None;
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
    }
}

fn transport_options_for_overlay_data(data: &pb::OverlayData) -> TransportSendOptions {
    let mut options = TransportSendOptions::default();
    if data.allow_l1_compression {
        options = options.allow_l1_compression();
    }
    if data.service_tag == VOICE_SERVICE_TAG {
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
    let Some(entry) = tables.lookup_with_metric(dst, level, routing_metric) else {
        if is_originator {
            return Err(OverlayError::NoRoute { dst, level });
        }
        return direct_fallback(dst, path_trace_set, DirectFallbackReason::NoRoute);
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
                fallback: None,
            });
        }
        return direct_fallback(
            dst,
            path_trace_set,
            DirectFallbackReason::Loop {
                next_hop: entry.next_hop,
            },
        );
    }

    if path_trace_set.contains(&dst) {
        return Ok(ForwardNextHop::DropAlreadyVisited);
    }

    Ok(ForwardNextHop::Send {
        next_hop: entry.next_hop,
        fallback: None,
    })
}

fn direct_fallback(
    dst: NodeIdentifier,
    path_trace_set: &HashSet<NodeIdentifier>,
    reason: DirectFallbackReason,
) -> Result<ForwardNextHop, OverlayError> {
    if path_trace_set.contains(&dst) {
        return Ok(ForwardNextHop::DropAlreadyVisited);
    }
    Ok(ForwardNextHop::Send {
        next_hop: dst,
        fallback: Some(reason),
    })
}

#[allow(clippy::too_many_arguments)]
async fn send_encoded_to_target(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    _self_id: NodeIdentifier,
    target: NodeIdentifier,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    payload: Bytes,
    is_originator: bool,
) -> Result<(), OverlayError> {
    let tables = routing.load();
    let Some(entry) = tables.lookup_with_metric(target, level, routing_metric) else {
        if is_originator {
            return Err(OverlayError::NoRoute { dst: target, level });
        }
        return Ok(());
    };
    if is_originator {
        transport
            .try_send(entry.next_hop, level, Some(routing_metric), class, payload)
            .await?;
    } else {
        transport
            .try_send(entry.next_hop, level, Some(routing_metric), class, payload)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::super::proto::decode_message;
    use super::super::super::routing::{RouteEntry, dijkstra::EdgeCost, new_handle};
    use super::super::{OverlayInboundMessage, ServiceInbound};
    use super::*;
    use shitspeak_s2s_transport::{SendError, TransportKind};
    use tokio::sync::mpsc;
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
        }
    }

    fn routing_with_route(dst: NodeIdentifier, next_hop: NodeIdentifier) -> RoutingHandle {
        let routing = new_handle();
        let mut tables = RoutingTables::empty();
        let table = HashMap::from([(dst, RouteEntry { next_hop, cost: 1 })]);
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

    fn overlay_data_for_dsts(dsts: &[NodeIdentifier]) -> pb::OverlayData {
        let mut data = test_overlay_data(false);
        data.dsts = dsts.iter().map(|dst| node_to_wire(*dst)).collect();
        data
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
            transport_options_for_overlay_data(&data)
                .expires_at()
                .is_none()
        );

        data.service_tag = VOICE_SERVICE_TAG;
        let options = transport_options_for_overlay_data(&data);
        assert!(options.expires_at().is_some());
        assert!(!options.is_expired());
    }

    #[test]
    fn transit_no_route_uses_direct_fallback() {
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

        assert_eq!(
            selected,
            ForwardNextHop::Send {
                next_hop: 4,
                fallback: Some(DirectFallbackReason::NoRoute),
            }
        );
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
    fn transit_loop_uses_direct_fallback() {
        let mut tables = RoutingTables::empty();
        tables.insert_table(
            RoutingMetric::ReliableCost,
            ServiceLevel::Reliable,
            HashMap::from([(
                4,
                RouteEntry {
                    next_hop: 1,
                    cost: 1,
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

        assert_eq!(
            selected,
            ForwardNextHop::Send {
                next_hop: 4,
                fallback: Some(DirectFallbackReason::Loop { next_hop: 1 }),
            }
        );
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

        assert_eq!(
            selected,
            ForwardNextHop::Send {
                next_hop: 3,
                fallback: None,
            }
        );
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
}
