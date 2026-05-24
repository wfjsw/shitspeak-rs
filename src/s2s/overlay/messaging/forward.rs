//! Routing-aware forwarding for `OverlayData` and ordered-lane repair control.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::s2s::overlay::config::OverlayConfig;
use crate::s2s::overlay::LaneId;
use crate::s2s::transport::{ConnectionManager, MessageClass, ServiceLevel};
use crate::s2s_overlay_proto as pb;
use crate::types::NodeIdentifier;

use super::super::error::OverlayError;
use super::super::proto::{
    class_from_wire, class_to_wire, encode_message, level_from_wire, level_to_wire, node_from_wire,
    node_to_wire, route_metric_from_wire, route_metric_to_wire, wrap, OverlayBody,
    OverlayControlBody,
};
use super::super::routing::{RoutingHandle, RoutingMetric};
use super::delivery;
use super::ordering::OverlayOrdering;
use super::ServiceRegistry;

const FORWARD_PAYLOAD_LOG_BYTES: usize = 256;
const CONTROL_LEVEL: ServiceLevel = ServiceLevel::ReliableLowLatency;
const CONTROL_METRIC: RoutingMetric = RoutingMetric::ReliableLowLatencyCost;

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
pub async fn originate(
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
            origin_message_id: 0,
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
pub async fn handle_inbound(
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
    let src = node_from_wire(data.src).unwrap_or(0);
    let is_for_self = data
        .dsts
        .iter()
        .any(|d| node_from_wire(*d) == Some(self_id));

    if is_for_self {
        if let Some(lane) = data.lane_id.and_then(|id| LaneId::try_from(id).ok()) {
            if node_from_wire(data.ordering_dst) == Some(self_id) {
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
        } else {
            delivery::deliver(
                services,
                data.service_tag,
                src,
                level,
                class,
                data.payload.clone(),
            );
        }
    } else if data.process_on_transit {
        let should_deliver = ordering
            .should_deliver_transit(
                src,
                data.origin_boot_epoch,
                data.origin_message_id,
                data.service_tag,
            )
            .await;
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
        .filter(|d| node_from_wire(**d) != Some(self_id))
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
    let mut data2 = data;
    data2.dsts = remaining;
    let _ = forward_pb_as(
        transport, routing, self_id, data2, class, /*is_originator=*/ false,
    )
    .await;
}

pub async fn handle_control(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    services: &ServiceRegistry,
    ordering: &OverlayOrdering,
    self_id: NodeIdentifier,
    _from: NodeIdentifier,
    control: pb::OverlayControl,
) {
    let Some(origin) = node_from_wire(control.origin) else {
        return;
    };
    let Some(final_dst) = node_from_wire(control.final_dst) else {
        return;
    };
    let Some(requester) = node_from_wire(control.requester) else {
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
    let Some(origin) = node_from_wire(data.src) else {
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
    let Some(origin) = node_from_wire(data.src) else {
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
    let payload = encode_message(&wrap(OverlayBody::Control(control)))?;
    send_encoded_to_target(
        transport,
        routing,
        self_id,
        target,
        CONTROL_LEVEL,
        CONTROL_METRIC,
        MessageClass::Control,
        payload,
        true,
    )
    .await
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

    let path_trace_set: std::collections::HashSet<u32> = data.path_trace.iter().copied().collect();
    let mut buckets: HashMap<NodeIdentifier, Vec<u32>> = HashMap::new();
    for dst_wire in &data.dsts {
        let Some(dst) = node_from_wire(*dst_wire) else {
            continue;
        };
        if dst == self_id {
            continue;
        }
        let entry = match tables.lookup_with_metric(dst, level, routing_metric) {
            Some(e) => e,
            None => {
                if is_originator {
                    return Err(OverlayError::NoRoute { dst, level });
                }
                warn!(%dst, ?level, "no route; dropping dst");
                continue;
            }
        };
        if path_trace_set.contains(&node_to_wire(entry.next_hop)) {
            warn!(%dst, next_hop=%entry.next_hop, "next_hop in path_trace; dropping");
            continue;
        }
        buckets.entry(entry.next_hop).or_default().push(*dst_wire);
    }
    if buckets.is_empty() {
        return Ok(());
    }

    let mut new_trace = data.path_trace.clone();
    let self_wire = node_to_wire(self_id);
    if !new_trace.contains(&self_wire) {
        new_trace.push(self_wire);
    }
    let mut first_err: Option<OverlayError> = None;
    for (next_hop, bucket_dsts) in buckets {
        let pb_msg = pb::OverlayData {
            src: data.src,
            dsts: bucket_dsts,
            path_trace: new_trace.clone(),
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
        };
        if tracing::enabled!(tracing::Level::TRACE) {
            let dsts: Vec<NodeIdentifier> = pb_msg
                .dsts
                .iter()
                .filter_map(|dst| node_from_wire(*dst))
                .collect();
            let path_trace: Vec<NodeIdentifier> = pb_msg
                .path_trace
                .iter()
                .filter_map(|node| node_from_wire(*node))
                .collect();
            let payload_hex = payload_hex_preview(&pb_msg.payload);
            trace!(
                %next_hop,
                src = %node_from_wire(pb_msg.src).unwrap_or(0),
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

        let payload = match encode_message(&wrap(OverlayBody::Data(pb_msg))) {
            Ok(b) => b,
            Err(e) => {
                if is_originator {
                    return Err(OverlayError::Encode(e));
                }
                warn!(error=%e, "encode forward failed");
                continue;
            }
        };
        match transport
            .send(
                next_hop,
                level,
                Some(routing_metric),
                transport_class,
                payload,
            )
            .await
        {
            Ok(()) => trace!(%next_hop, ?level, "forwarded"),
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

#[allow(clippy::too_many_arguments)]
async fn send_encoded_to_target(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
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
    transport
        .send(entry.next_hop, level, Some(routing_metric), class, payload)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_hex_preview_is_bounded() {
        assert_eq!(payload_hex_preview(&[]), "");
        assert_eq!(payload_hex_preview(&[0, 1, 0xab, 0xff]), "0001abff");

        let payload = vec![0xff; FORWARD_PAYLOAD_LOG_BYTES + 2];
        let preview = payload_hex_preview(&payload);
        assert!(preview.starts_with(&"ff".repeat(FORWARD_PAYLOAD_LOG_BYTES)));
        assert!(preview.ends_with("...(+2 bytes)"));
    }
}
