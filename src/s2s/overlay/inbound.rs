//! Central inbound dispatcher.
//!
//! Reads frames from the transport's two `Inbound` mpscs (high-priority +
//! regular), decodes the prost-encoded `OverlayMessage`, and routes the
//! payload to the appropriate handler:
//!
//!   * `SwimPing`   → reply with `SwimAck` + apply piggyback gossip.
//!   * `SwimAck`    → wake any waiter in `PendingAcks` + apply piggyback.
//!   * `SwimPingReq`→ relay a probe to `target_node`; forward its ack back
//!                    to the requester.
//!   * `Gossip`     → apply standalone gossip digest.

use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use crate::s2s::transport::{Inbound, MessageClass, ServiceLevel};
use crate::s2s_overlay_proto as pb;
use crate::types::NodeIdentifier;

use super::membership::gossip::{apply_inbound_updates, pb_to_parts};
use super::membership::swim::{
    build_ack, send_overlay, PendingAcks, SwimContext,
};
use super::membership::view::MemberStatus;
use super::proto::{decode_message, encode_message, node_from_wire, node_to_wire, wrap, OverlayBody};

/// Spawn the inbound dispatcher task. Owns both halves of the transport's
/// `Inbound` and never returns until shutdown.
pub(crate) fn spawn_dispatcher(ctx: Arc<SwimContext>, inbound: Inbound) {
    let (high_priority, regular) = inbound.into_parts();
    tokio::spawn(run_dispatcher(ctx, high_priority, regular));
}

async fn run_dispatcher(
    ctx: Arc<SwimContext>,
    mut high: mpsc::Receiver<crate::s2s::transport::InboundMessage>,
    mut regular: mpsc::Receiver<crate::s2s::transport::InboundMessage>,
) {
    loop {
        tokio::select! {
            _ = ctx.shutdown.cancelled() => return,
            // Bias to regular since SWIM/gossip ride there. High-priority is
            // for application data (Phase 2+) and we still drain it.
            msg = regular.recv() => {
                let Some(m) = msg else { return };
                handle(&ctx, m).await;
            }
            msg = high.recv() => {
                let Some(m) = msg else { return };
                handle(&ctx, m).await;
            }
        }
    }
}

async fn handle(ctx: &SwimContext, msg: crate::s2s::transport::InboundMessage) {
    let raw = msg.payload().clone();
    let decoded = match decode_message(&raw) {
        Ok(d) => d,
        Err(e) => {
            warn!(from=%msg.from(), error=%e, "overlay decode failed");
            return;
        }
    };
    let Some(body) = decoded.body else {
        return;
    };
    match body {
        OverlayBody::SwimPing(ping) => handle_ping(ctx, ping).await,
        OverlayBody::SwimAck(ack) => handle_ack(ctx, ack),
        OverlayBody::SwimPingReq(req) => handle_ping_req(ctx, req).await,
        OverlayBody::Gossip(digest) => handle_gossip(ctx, digest),
    }
}

async fn handle_ping(ctx: &SwimContext, ping: pb::SwimPing) {
    let Some(src) = node_from_wire(ping.src_node) else { return };
    if src == ctx.self_id {
        return;
    }
    // Apply piggyback updates (including the source's own self-claim).
    apply_self_aware_updates(ctx, &ping.piggyback);
    apply_inbound_updates(&ctx.table, &ctx.transport, &ping.piggyback);
    ctx.table.note_ack(src);

    // Reply.
    let reply = build_ack(ctx, ping.nonce);
    if let Err(e) = send_overlay(&ctx.transport, src, reply).await {
        debug!(self_id=%ctx.self_id, peer=%src, error=%e, "ack send failed");
    }
}

fn handle_ack(ctx: &SwimContext, ack: pb::SwimAck) {
    let Some(src) = node_from_wire(ack.src_node) else { return };
    if src == ctx.self_id {
        return;
    }
    apply_self_aware_updates(ctx, &ack.piggyback);
    apply_inbound_updates(&ctx.table, &ctx.transport, &ack.piggyback);
    ctx.table.note_ack(src);
    let _ = ctx.pending_acks.deliver(ack.nonce);
}

async fn handle_ping_req(ctx: &SwimContext, req: pb::SwimPingReq) {
    let Some(src) = node_from_wire(req.src_node) else { return };
    let Some(target) = node_from_wire(req.target_node) else { return };
    if target == ctx.self_id {
        // We are the target; reply directly to the requester.
        let reply = build_ack(ctx, req.nonce);
        let _ = send_overlay(&ctx.transport, src, reply).await;
        return;
    }
    // Forward a fresh ping to the target. When the target's ack arrives we
    // synthesize an ack to the original requester.
    let proxy = NonceProxy::register(&ctx.pending_acks, src, req.nonce, ctx);
    let proxy_nonce = proxy.local_nonce;
    let body = OverlayBody::SwimPing(pb::SwimPing {
        src_node: node_to_wire(ctx.self_id),
        src_incarnation: ctx.current_incarnation(),
        nonce: proxy_nonce,
        piggyback: vec![],
    });
    let payload = match encode_message(&wrap(body)) {
        Ok(b) => b,
        Err(e) => {
            warn!(error=%e, "encode proxy ping failed");
            return;
        }
    };
    if let Err(e) = send_overlay(&ctx.transport, target, payload).await {
        debug!(peer=%target, error=%e, "proxy ping send failed");
    }
    // Spawn proxy waiter that forwards the ack on success.
    proxy.spawn_waiter(ctx);
}

fn handle_gossip(ctx: &SwimContext, digest: pb::GossipDigest) {
    apply_self_aware_updates(ctx, &digest.updates);
    apply_inbound_updates(&ctx.table, &ctx.transport, &digest.updates);
}

/// Inspect updates for any claim about *this* node. If a peer says we are
/// Suspect/Dead at incarnation >= ours, we bump our incarnation so the
/// next gossip wave refutes them.
fn apply_self_aware_updates(ctx: &SwimContext, updates: &[pb::GossipUpdate]) {
    for u in updates {
        let Some((node, inc, status, _addrs)) = pb_to_parts(u) else {
            continue;
        };
        if node != ctx.self_id {
            continue;
        }
        if matches!(status, MemberStatus::Suspect | MemberStatus::Dead)
            && inc >= ctx.current_incarnation()
        {
            let new_inc = ctx.bump_incarnation();
            tracing::info!(
                self_id = %ctx.self_id,
                bumped_to = new_inc,
                "refuting peer's stale Suspect/Dead claim"
            );
        }
    }
}

/// Tracks an in-flight indirect-probe forwarding so that when the proxy
/// ack lands, we forward it to the original requester.
struct NonceProxy {
    requester: NodeIdentifier,
    requester_nonce: u64,
    local_nonce: u64,
    rx: tokio::sync::oneshot::Receiver<()>,
}

impl NonceProxy {
    fn register(
        pending: &PendingAcks,
        requester: NodeIdentifier,
        requester_nonce: u64,
        ctx: &SwimContext,
    ) -> Self {
        let local_nonce = ctx.next_nonce();
        let rx = pending.register(local_nonce);
        Self { requester, requester_nonce, local_nonce, rx }
    }

    fn spawn_waiter(self, ctx: &SwimContext) {
        let timeout = ctx.cfg.swim_ping_interval();
        let transport = ctx.transport.clone();
        let table = ctx.table.clone();
        let pending = ctx.pending_acks.clone();
        let self_id = ctx.self_id;
        let inc = ctx.current_incarnation();
        let requester = self.requester;
        let requester_nonce = self.requester_nonce;
        let local_nonce = self.local_nonce;
        let rx = self.rx;
        tokio::spawn(async move {
            let res = tokio::time::timeout(timeout, rx).await;
            pending.forget(local_nonce);
            match res {
                Ok(Ok(())) => {
                    // Success — forward an ack to the requester. Piggyback
                    // current state so they refresh their view of us.
                    let body = OverlayBody::SwimAck(pb::SwimAck {
                        src_node: node_to_wire(self_id),
                        src_incarnation: inc,
                        nonce: requester_nonce,
                        piggyback: ctx_piggyback(self_id, inc, &table),
                    });
                    if let Ok(payload) = encode_message(&wrap(body)) {
                        let _ = transport
                            .send(
                                requester,
                                ServiceLevel::Reliable,
                                MessageClass::Regular,
                                payload,
                            )
                            .await;
                    }
                }
                _ => {
                    trace!(target=%requester, "proxy probe timed out");
                }
            }
        });
    }
}

/// Build a small piggyback list for a synthesized ack. Same shape as the
/// SWIM ticker's piggyback but without holding `ctx` across the await.
fn ctx_piggyback(
    self_id: NodeIdentifier,
    inc: u64,
    table: &Arc<super::membership::MembershipTable>,
) -> Vec<pb::GossipUpdate> {
    use super::membership::gossip::{record_to_pb, self_record_to_pb};
    let mut out = vec![self_record_to_pb(
        self_id,
        inc,
        MemberStatus::Alive,
        &[],
    )];
    for r in table.recent_updates(7) {
        out.push(record_to_pb(&r));
    }
    out
}
