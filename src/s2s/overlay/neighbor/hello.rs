//! Direct-link Hello/HelloAck protocol.
//!
//! Replaces SWIM probes from Phase 1. Sends a `Hello` to every direct-
//! neighbor every `hello_interval`; the responder echoes a matching
//! `HelloAck` immediately. Round-trip times feed the transport's RTT
//! EWMA via `PeerMetrics::record_rtt`.
//!
//! When a direct link is observed up for the first time (it appears in
//! the neighbor monitor's snapshot), an `LsdbSync` full pull and snapshot
//! push are issued so both sides exchange LSAs that may have been learned
//! before the link was considered floodable.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::sync::broadcast;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::{trace, warn};

use crate::s2s::transport::{ConnectionManager, MessageClass, ServiceLevel};
use crate::s2s_overlay_proto as pb;
use crate::types::NodeIdentifier;

use super::super::config::OverlayConfig;
use super::super::lsdb::{LinkStateDb, full_pull, push_snapshot};
use super::super::proto::{OverlayBody, encode_message, node_to_wire, wrap};
use super::monitor::NeighborMonitor;

const HELLO_MESSAGE_CLASS: MessageClass = MessageClass::Control;

/// Mutable state shared by the Hello ticker.
pub struct HelloContext {
    pub self_id: NodeIdentifier,
    pub boot_epoch: u64,
    pub transport: ConnectionManager,
    pub monitor: Arc<NeighborMonitor>,
    pub lsdb: Arc<LinkStateDb>,
    pub cfg: OverlayConfig,
    pub shutdown: CancellationToken,
    pub nonce_counter: AtomicU64,
}

impl HelloContext {
    pub fn next_nonce(&self) -> u64 {
        self.nonce_counter.fetch_add(1, Ordering::Relaxed)
    }
}

/// Convert `Instant::now()` to a u64 microsecond timestamp suitable for
/// the wire `ts_send_us`. We use `SystemTime` since the receiver echoes
/// it verbatim — we only need a value uniquely tagged for this Hello.
fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Send one Hello to `dst`. Records the outbound nonce in the monitor so
/// we can match the corresponding HelloAck back to a sent_at Instant.
pub async fn send_hello(ctx: &HelloContext, dst: NodeIdentifier) {
    let nonce = ctx.next_nonce();
    let ts = now_us();
    let body = OverlayBody::Hello(pb::Hello {
        src_node: node_to_wire(ctx.self_id),
        src_boot_epoch: ctx.boot_epoch,
        nonce,
        ts_send_us: ts,
    });
    #[cfg(debug_assertions)]
    let packet_kind = crate::s2s::debug_io::classify_overlay_body(&body);
    let payload = match encode_message(&wrap(body)) {
        Ok(b) => b,
        Err(e) => {
            warn!(error=%e, "encode hello failed");
            return;
        }
    };
    #[cfg(debug_assertions)]
    let payload_len = payload.len();
    match ctx
        .transport
        .send(
            dst,
            ServiceLevel::Reliable,
            None,
            HELLO_MESSAGE_CLASS,
            payload,
        )
        .await
    {
        Ok(()) => {
            #[cfg(debug_assertions)]
            crate::s2s::debug_io::record_sent(packet_kind, payload_len);
            ctx.monitor.record_outbound_ping(dst, nonce);
        }
        Err(e) => trace!(peer=%dst, error=%e, "hello send failed"),
    }
}

/// Spawn the Hello ticker.
pub fn spawn_hello_task(ctx: Arc<HelloContext>) {
    tokio::spawn(async move {
        let mut tick = interval(ctx.cfg.hello_interval());
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ctx.shutdown.cancelled() => return,
                _ = tick.tick() => {}
            }
            let targets = ctx.monitor.sweep_and_collect_targets();
            for (nid, _kinds) in targets {
                send_hello(&ctx, nid).await;
            }
        }
    });
}

/// Spawn the link-up watcher: every time the monitor reports a newly-up peer,
/// schedule a full LSDB pull and push against only that peer.
pub fn spawn_link_up_watcher(
    ctx: Arc<HelloContext>,
    mut link_up_events: broadcast::Receiver<NodeIdentifier>,
) {
    tokio::spawn(async move {
        loop {
            let peer = tokio::select! {
                _ = ctx.shutdown.cancelled() => return,
                event = link_up_events.recv() => match event {
                    Ok(peer) => peer,
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(skipped, "link-up sync watcher lagged; skipped stale events");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                },
            };
            if !ctx.monitor.is_up(peer) {
                continue;
            }
            full_pull(&ctx.transport, ctx.self_id, peer).await;
            push_snapshot(
                &ctx.lsdb,
                &ctx.transport,
                peer,
                ctx.cfg.lsdb_sync_max_response_lsas(),
            )
            .await;
        }
    });
}

/// Inbound: respond to a Hello with a HelloAck echoing nonce + ts.
pub async fn respond_to_hello(ctx: &HelloContext, from: NodeIdentifier, hello: pb::Hello) {
    ctx.monitor.record_hello(from, hello.src_boot_epoch);
    let body = OverlayBody::HelloAck(pb::HelloAck {
        src_node: node_to_wire(ctx.self_id),
        src_boot_epoch: ctx.boot_epoch,
        nonce: hello.nonce,
        ts_send_us: hello.ts_send_us,
    });
    #[cfg(debug_assertions)]
    let packet_kind = crate::s2s::debug_io::classify_overlay_body(&body);
    let payload = match encode_message(&wrap(body)) {
        Ok(b) => b,
        Err(e) => {
            warn!(error=%e, "encode hello_ack failed");
            return;
        }
    };
    #[cfg(debug_assertions)]
    let payload_len = payload.len();
    match ctx
        .transport
        .send(
            from,
            ServiceLevel::Reliable,
            None,
            HELLO_MESSAGE_CLASS,
            payload,
        )
        .await
    {
        Ok(()) => {
            #[cfg(debug_assertions)]
            crate::s2s::debug_io::record_sent(packet_kind, payload_len);
        }
        Err(e) => trace!(peer=%from, error=%e, "hello_ack send failed"),
    }
}

/// Inbound: handle a HelloAck — feeds RTT and bumps liveness.
pub fn handle_hello_ack(
    ctx: &HelloContext,
    from: NodeIdentifier,
    ack: pb::HelloAck,
    transport_kind: crate::s2s::transport::TransportKind,
) {
    ctx.monitor.record_hello_ack(
        from,
        ack.src_boot_epoch,
        ack.nonce,
        ack.ts_send_us,
        Some(transport_kind),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_traffic_uses_control_class() {
        assert_eq!(HELLO_MESSAGE_CLASS, MessageClass::Control);
    }
}
