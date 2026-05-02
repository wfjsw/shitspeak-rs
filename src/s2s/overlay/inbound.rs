//! Central inbound dispatcher.
//!
//! Reads frames from the transport's two `Inbound` mpscs (high-priority +
//! regular) and routes the decoded `OverlayMessage` to the appropriate
//! handler. The two queues are drained by **two independent tasks**:
//! high-priority traffic must never wait behind regular traffic.
//!
//! Why split tasks rather than `tokio::select!` with `biased;`? Decode and
//! handler dispatch may await (e.g., `transport.send` on a forwarder), so
//! a single multiplexed loop would still serialize a high-priority frame
//! behind a regular one whose handler is still in flight. Two tasks
//! preserve the producer-side priority that the L1 transport already
//! enforces by routing into separate `mpsc::Receiver`s based on
//! [`MessageClass`](crate::s2s::transport::MessageClass).
//!
//! `MessageClass` is also preserved end-to-end on the wire: forwarders
//! propagate it via `OverlayData.message_class`, and service handlers see
//! it on `OverlayInboundMessage.class` so voice (BestEffort + HighPriority)
//! receives priority across every hop.
//!
//! Routing:
//!   * `Hello`         → respond with HelloAck + update neighbor table.
//!   * `HelloAck`      → feed RTT + bump liveness in neighbor table.
//!   * `LsaFlood`      → admit each LSA + re-flood accepted ones.
//!   * `LsdbSync`      → respond with the LSAs the peer is missing.
//!   * `LsdbSyncResp`  → admit the LSAs in the delta (no re-flood).
//!   * `OverlayData`   → deliver locally if applicable, forward the rest.

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::warn;

use crate::s2s::transport::Inbound;

use super::lsdb::{handle_flood, handle_sync_request, handle_sync_response, LinkStateDb};
use super::messaging::forward as messaging_forward;
use super::neighbor::hello::{handle_hello_ack, respond_to_hello, HelloContext};
use super::neighbor::monitor::NeighborMonitor;
use super::proto::{decode_message, OverlayBody};
use super::routing::RoutingHandle;

/// Bundle of references the dispatcher needs to route inbound frames.
pub(crate) struct DispatcherCtx {
    pub hello: Arc<HelloContext>,
    pub monitor: Arc<NeighborMonitor>,
    pub lsdb: Arc<LinkStateDb>,
    pub routing: RoutingHandle,
    pub services: Arc<super::messaging::ServiceRegistry>,
    pub transport: crate::s2s::transport::ConnectionManager,
    pub self_id: crate::types::NodeIdentifier,
    pub shutdown: tokio_util::sync::CancellationToken,
}

/// Spawn one dispatcher task per priority queue. They run independently
/// so a slow handler on the regular queue cannot block high-priority
/// frames (and vice versa).
pub(crate) fn spawn_dispatcher(ctx: Arc<DispatcherCtx>, inbound: Inbound) {
    let (high, regular) = inbound.into_parts();
    tokio::spawn(run_queue(ctx.clone(), high, "high"));
    tokio::spawn(run_queue(ctx, regular, "regular"));
}

async fn run_queue(
    ctx: Arc<DispatcherCtx>,
    mut rx: mpsc::Receiver<crate::s2s::transport::InboundMessage>,
    label: &'static str,
) {
    loop {
        tokio::select! {
            biased;
            _ = ctx.shutdown.cancelled() => return,
            msg = rx.recv() => {
                let Some(m) = msg else {
                    tracing::trace!(queue = label, "inbound queue closed");
                    return;
                };
                handle(&ctx, m).await;
            }
        }
    }
}

async fn handle(ctx: &DispatcherCtx, msg: crate::s2s::transport::InboundMessage) {
    let from = msg.from();
    let kind = msg.transport();
    let raw = msg.payload().clone();
    let decoded = match decode_message(&raw) {
        Ok(d) => d,
        Err(e) => {
            warn!(%from, error=%e, "overlay decode failed");
            return;
        }
    };
    let Some(body) = decoded.body else {
        return;
    };
    match body {
        OverlayBody::Hello(h) => respond_to_hello(&ctx.hello, from, h).await,
        OverlayBody::HelloAck(a) => handle_hello_ack(&ctx.hello, from, a, kind),
        OverlayBody::LsaFlood(f) => {
            handle_flood(&ctx.lsdb, &ctx.monitor, &ctx.transport, from, f).await
        }
        OverlayBody::LsdbSync(req) => {
            handle_sync_request(&ctx.lsdb, &ctx.transport, from, req).await
        }
        OverlayBody::LsdbSyncResp(resp) => handle_sync_response(&ctx.lsdb, resp),
        OverlayBody::Data(data) => {
            messaging_forward::handle_inbound(
                &ctx.transport,
                &ctx.routing,
                &ctx.services,
                ctx.self_id,
                from,
                data,
            )
            .await
        }
    }
}
