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
    node_to_wire, wrap, OverlayBody,
};
use super::super::routing::{RoutingHandle, RoutingTables};
use super::delivery;
use super::ServiceRegistry;

/// Build, encode, and dispatch an outbound `OverlayData` originated by
/// the local node.
pub async fn originate(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    self_id: NodeIdentifier,
    dsts: Vec<NodeIdentifier>,
    tag: u32,
    level: ServiceLevel,
    class: MessageClass,
    body: Bytes,
) -> Result<(), OverlayError> {
    let data = pb::OverlayData {
        src: node_to_wire(self_id),
        dsts: dsts.iter().map(|d| node_to_wire(*d)).collect(),
        path_trace: vec![node_to_wire(self_id)],
        service_tag: tag,
        service_level: level_to_wire(level),
        message_class: class_to_wire(class),
        payload: body.to_vec(),
    };
    forward_pb(transport, routing, self_id, data, class, /*is_originator=*/ true).await
}

/// Handle an inbound `OverlayData`: deliver locally if applicable,
/// forward the remainder.
pub async fn handle_inbound(
    transport: &ConnectionManager,
    routing: &RoutingHandle,
    services: &ServiceRegistry,
    self_id: NodeIdentifier,
    from: NodeIdentifier,
    data: pb::OverlayData,
) {
    let class = class_from_wire(data.message_class).unwrap_or(MessageClass::Regular);
    // Deliver-to-self if applicable.
    let is_for_self = data.dsts.iter().any(|d| node_from_wire(*d) == Some(self_id));
    if is_for_self {
        let level = level_from_wire(data.service_level).unwrap_or(ServiceLevel::Reliable);
        let src = node_from_wire(data.src).unwrap_or(0);
        delivery::deliver(
            services,
            data.service_tag,
            src,
            level,
            class,
            Bytes::from(data.payload.clone()),
        );
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
    let mut data2 = data;
    data2.dsts = remaining;
    let _ = forward_pb(transport, routing, self_id, data2, class, /*is_originator=*/ false).await;
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
    let tables = routing.load();

    // Bucket dsts by next_hop.
    let path_trace_set: std::collections::HashSet<u32> =
        data.path_trace.iter().copied().collect();
    let mut buckets: HashMap<NodeIdentifier, Vec<u32>> = HashMap::new();
    for dst_wire in &data.dsts {
        let Some(dst) = node_from_wire(*dst_wire) else {
            continue;
        };
        if dst == self_id {
            continue;
        }
        let entry = match tables.lookup(dst, level) {
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
        };
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
        match transport.send(next_hop, level, class, payload).await {
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
