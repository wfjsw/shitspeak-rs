//! Central inbound dispatcher.
//!
//! Reads frames from the transport's `Inbound` mpscs (control,
//! high-priority, and regular) and routes decoded `OverlayMessage`s to the
//! appropriate handler. The queues are drained by independent tasks so
//! overlay control traffic never waits behind application data.
//!
//! Why split tasks rather than `tokio::select!` with `biased;`? Decode and
//! handler dispatch may await (e.g., `transport.send` on a forwarder), so
//! a single multiplexed loop would still serialize a high-priority frame
//! behind a regular one whose handler is still in flight. Two tasks
//! preserve the producer-side priority that the L1 transport already
//! enforces by routing into separate `mpsc::Receiver`s based on
//! [`MessageClass`](shitspeak_s2s_transport::MessageClass).
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
//!   * `LsdbSyncResp`  → admit the LSAs in the delta + re-flood accepted repairs.
//!   * `OverlayData`   → deliver locally if applicable, forward the rest.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::warn;

use shitspeak_s2s_transport::{AdaptiveInboundReceiver, Inbound};

use super::duplicate::DuplicateDetector;
use super::lsdb::{
    LinkStateDb, LsaEmitter, LsaFloodPacer, handle_flood, handle_sync_request, handle_sync_response,
};
use super::messaging::forward as messaging_forward;
use super::neighbor::hello::{HelloContext, handle_hello_ack, respond_to_hello};
use super::neighbor::monitor::NeighborMonitor;
use super::proto::{OverlayBody, decode_message};
use super::routing::RoutingHandle;

/// Bundle of references the dispatcher needs to route inbound frames.
pub(crate) struct DispatcherCtx {
    pub hello: Arc<HelloContext>,
    pub monitor: Arc<NeighborMonitor>,
    pub lsdb: Arc<LinkStateDb>,
    pub routing: RoutingHandle,
    pub services: Arc<super::messaging::ServiceRegistry>,
    pub ordering: Arc<super::messaging::ordering::OverlayOrdering>,
    pub duplicate_detector: Arc<DuplicateDetector>,
    pub transport: shitspeak_s2s_transport::ConnectionManager,
    pub self_id: shitspeak_core::NodeIdentifier,
    pub shutdown: tokio_util::sync::CancellationToken,
    pub cfg: super::config::OverlayConfig,
    pub emitter: Arc<LsaEmitter>,
    pub flood_pacer: Arc<LsaFloodPacer>,
}

/// Spawn one dispatcher task per priority queue. They run independently
/// so a slow handler on the regular queue cannot block high-priority
/// frames (and vice versa).
pub(crate) fn spawn_dispatcher(ctx: Arc<DispatcherCtx>, inbound: Inbound) {
    let (control, high, regular) = inbound.into_parts();
    tokio::spawn(run_queue(ctx.clone(), control, "control"));
    tokio::spawn(run_queue(ctx.clone(), high, "high"));
    tokio::spawn(run_queue(ctx, regular, "regular"));
}

async fn run_queue(ctx: Arc<DispatcherCtx>, mut rx: AdaptiveInboundReceiver, label: &'static str) {
    loop {
        tokio::select! {
            biased;
            _ = ctx.shutdown.cancelled() => return,
            msg = rx.recv() => {
                let Some(m) = msg else {
                    tracing::trace!(queue = label, "inbound queue closed");
                    return;
                };
                handle(&ctx, label, m).await;
            }
        }
    }
}

async fn handle(
    ctx: &DispatcherCtx,
    queue: &'static str,
    msg: shitspeak_s2s_transport::InboundMessage,
) {
    let from = msg.from();
    let kind = msg.transport();
    let class = msg.class();
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
    let body_kind = body_kind(&body);
    if ctx.duplicate_detector.is_quarantined(from) {
        ctx.duplicate_detector.record_drop(from, body_kind);
        return;
    }
    let packet_kind = crate::debug_io::classify_overlay_body(&body);
    crate::debug_io::record_received(from, ctx.self_id, packet_kind, raw.len());
    let started = Instant::now();
    match body {
        OverlayBody::Hello(h) => respond_to_hello(&ctx.hello, from, h).await,
        OverlayBody::HelloAck(a) => handle_hello_ack(&ctx.hello, from, a, kind),
        OverlayBody::LsaFlood(f) => {
            handle_flood(
                &ctx.lsdb,
                &ctx.monitor,
                &ctx.transport,
                &ctx.flood_pacer,
                &ctx.duplicate_detector,
                from,
                f,
            )
            .await
        }
        OverlayBody::LsdbSync(req) => {
            handle_sync_request(
                &ctx.lsdb,
                &ctx.transport,
                ctx.self_id,
                from,
                req,
                ctx.cfg.lsdb_sync_max_response_lsas(),
            )
            .await
        }
        OverlayBody::LsdbSyncResp(resp) => handle_sync_response(
            &ctx.lsdb,
            &ctx.monitor,
            &ctx.transport,
            &ctx.flood_pacer,
            &ctx.duplicate_detector,
            from,
            resp,
        ),
        OverlayBody::Control(control) => {
            messaging_forward::handle_control(
                &ctx.transport,
                &ctx.routing,
                &ctx.services,
                &ctx.ordering,
                ctx.self_id,
                from,
                control,
            )
            .await
        }
        OverlayBody::Data(data) => {
            messaging_forward::handle_inbound(
                &ctx.transport,
                &ctx.routing,
                &ctx.services,
                &ctx.ordering,
                ctx.self_id,
                from,
                data,
                !ctx.emitter.transit_disabled(),
            )
            .await
        }
    }
    let elapsed = started.elapsed();
    if elapsed > Duration::from_secs(1) {
        warn!(
            queue,
            body_kind,
            source = %from,
            transport = ?kind,
            class = ?class,
            elapsed_ms = elapsed.as_millis(),
            "slow inbound overlay handler"
        );
    }
}

fn body_kind(body: &OverlayBody) -> &'static str {
    match body {
        OverlayBody::Hello(_) => "Hello",
        OverlayBody::HelloAck(_) => "HelloAck",
        OverlayBody::LsaFlood(_) => "LsaFlood",
        OverlayBody::LsdbSync(_) => "LsdbSync",
        OverlayBody::LsdbSyncResp(_) => "LsdbSyncResp",
        OverlayBody::Control(_) => "Control",
        OverlayBody::Data(_) => "OverlayData",
    }
}
