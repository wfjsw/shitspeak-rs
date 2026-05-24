//! Routing-aware forwarding for `OverlayData`.
//!
//! Each forwarding step:
//!   1. Subtract self from `dsts`. If self is among them, hand off to
//!      `delivery::deliver` for local consumption.
//!   2. For every remaining `dst`, look up `next_hop` via
//!      `RoutingTables`. Drop `dst`s with no route (warn-log).
//!   3. Loop check: if `next_hop` is in `path_trace`, drop `dst` (warn-
//!      log; this is a misconfiguration or stale routing).
//!   4. Bucket destinations by `next_hop`. Emit one `OverlayData` per
//!      next-hop with `path_trace` extended by `self_id`.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use tracing::{debug, trace, warn};

use crate::s2s::transport::{ConnectionManager, MessageClass, ServiceLevel};
use crate::s2s_overlay_proto as pb;
use crate::types::NodeIdentifier;

use super::super::error::OverlayError;
use super::super::proto::{
    class_from_wire, class_to_wire, encode_message, level_from_wire, level_to_wire, node_from_wire,
    node_to_wire, route_metric_from_wire, route_metric_to_wire, wrap, OverlayBody,
};
use super::super::routing::{RoutingHandle, RoutingMetric, RoutingTables};
use super::delivery;
use super::ordering::{requires_ordering, OrderedDelivery, OverlayOrdering};
use super::ServiceRegistry;

const FORWARD_PAYLOAD_LOG_BYTES: usize = 256;

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

/// Build, encode, and dispatch an outbound `OverlayData` originated by
/// the local node.
pub async fn originate(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    ordering: &OverlayOrdering,
    dsts: Vec<NodeIdentifier>,
    tag: u32,
    level: ServiceLevel,
    routing_metric: RoutingMetric,
    class: MessageClass,
    body: Bytes,
    ordered_delivery: bool,
    process_on_transit: bool,
) -> Result<(), OverlayError> {
    if ordered_delivery && requires_ordering(level) {
        let _send_guard = ordering.outbound_send_guard().await;
        let mut first_err = None;
        for dst in dsts {
            let seq = ordering.next_outbound_seq(dst).await;
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
            };
            if let Err(err) = forward_pb(
                transport, routing, self_id, data, class, /*is_originator=*/ true,
            )
            .await
            {
                ordering.release_failed_outbound_seq(dst, seq).await;
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
        }
        if let Some(err) = first_err {
            return Err(err);
        }
        return Ok(());
    }

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
    };
    forward_pb(
        transport, routing, self_id, data, class, /*is_originator=*/ true,
    )
    .await
}

/// Handle an inbound `OverlayData`: deliver locally if applicable,
/// forward the remainder.
pub async fn handle_inbound(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    services: &ServiceRegistry,
    ordering: &OverlayOrdering,
    self_id: NodeIdentifier,
    from: NodeIdentifier,
    data: pb::OverlayData,
    route_transit_messages: bool,
) {
    let class = class_from_wire(data.message_class).unwrap_or(MessageClass::Regular);
    let is_for_self = data
        .dsts
        .iter()
        .any(|d| node_from_wire(*d) == Some(self_id));
    if is_for_self || data.process_on_transit {
        let level = level_from_wire(data.service_level).unwrap_or(ServiceLevel::Reliable);
        let src = node_from_wire(data.src).unwrap_or(0);
        if is_for_self
            && data.ordered_delivery
            && requires_ordering(level)
            && node_from_wire(data.ordering_dst) == Some(self_id)
        {
            let ready = ordering
                .accept_inbound(
                    self_id,
                    data.ordering_seq,
                    OrderedDelivery::new(src, data.service_tag, level, class, data.payload.clone()),
                )
                .await;
            for msg in ready {
                delivery::deliver(
                    services,
                    msg.tag(),
                    msg.src(),
                    msg.level(),
                    msg.class(),
                    msg.body(),
                );
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
    }
    // Forward the remainder if any.
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
            %from,
            remaining = remaining.len(),
            "S2S transit routing disabled; dropping overlay data for other nodes"
        );
        return;
    }
    let mut data2 = data;
    data2.dsts = remaining;
    let _ = forward_pb(
        transport, routing, self_id, data2, class, /*is_originator=*/ false,
    )
    .await;
}

/// Forward an `OverlayData` whose `dsts` already excludes self.
async fn forward_pb(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    data: pb::OverlayData,
    class: MessageClass,
    is_originator: bool,
) -> Result<(), OverlayError> {
    let level = level_from_wire(data.service_level).unwrap_or(ServiceLevel::Reliable);
    let routing_metric = route_metric_from_wire(data.route_metric, level)
        .unwrap_or_else(|| RoutingMetric::default_for_level(level));
    let tables = routing.load();

    // Bucket dsts by next_hop.
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
        // Loop check.
        if path_trace_set.contains(&node_to_wire(entry.next_hop)) {
            warn!(%dst, next_hop=%entry.next_hop, "next_hop in path_trace; dropping");
            continue;
        }
        buckets.entry(entry.next_hop).or_default().push(*dst_wire);
    }
    if buckets.is_empty() {
        if is_originator {
            return Ok(());
        }
        return Ok(());
    }

    // Build a path_trace including ourselves for the next hop.
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
                ?class,
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
            .send(next_hop, level, Some(routing_metric), class, payload)
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
