//! SWIM probe ticker.
//!
//! Spawns one task that on each `swim_ping_interval`:
//!   1. picks a target via `MembershipTable::next_probe_target`;
//!   2. sends a `SwimPing` over `Reliable` + `Regular`;
//!   3. waits up to `swim_ping_interval / 2` for a `SwimAck` matching the
//!      ping's nonce;
//!   4. on timeout, asks `swim_indirect_ping_count` random alive peers to
//!      indirect-ping the target;
//!   5. if no indirect ack arrives within another `swim_ping_interval`, the
//!      target is locally transitioned to `Suspect`.
//!
//! Suspicion → Dead is a separate reaper task driven by wall-clock age, not
//! by the ticker, because Suspect state must be observable for the full
//! `swim_suspicion_timeout` regardless of probe cadence.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use parking_lot::Mutex;
use rand::SeedableRng;
use tokio::sync::{oneshot, Notify};
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::s2s::transport::{ConnectionManager, MessageClass, ServiceLevel};
use crate::s2s_overlay_proto as pb;
use crate::types::NodeIdentifier;

use super::super::config::OverlayConfig;
use super::super::proto::{encode_message, node_to_wire, wrap, OverlayBody};
use super::gossip::{record_to_pb, self_record_to_pb};
use super::view::MemberStatus;
use super::MembershipTable;

/// Per-pending-ping state. The receiver is signaled by the inbound
/// dispatcher when a matching `SwimAck` arrives.
pub(crate) struct PendingAcks {
    inner: Mutex<HashMap<u64, oneshot::Sender<()>>>,
}

impl PendingAcks {
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    pub fn register(&self, nonce: u64) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        self.inner.lock().insert(nonce, tx);
        rx
    }

    /// Called by the inbound dispatcher when a `SwimAck` lands. Returns true
    /// if a sender was waiting (i.e., this ack matched a known ping).
    pub fn deliver(&self, nonce: u64) -> bool {
        if let Some(tx) = self.inner.lock().remove(&nonce) {
            let _ = tx.send(());
            true
        } else {
            false
        }
    }

    pub fn forget(&self, nonce: u64) {
        self.inner.lock().remove(&nonce);
    }
}

pub(crate) struct SwimContext {
    pub self_id: NodeIdentifier,
    pub incarnation: AtomicU64,
    pub cfg: OverlayConfig,
    pub transport: ConnectionManager,
    pub table: Arc<MembershipTable>,
    pub pending_acks: Arc<PendingAcks>,
    pub shutdown: CancellationToken,
    pub refute_signal: Arc<Notify>,
    pub nonce_counter: AtomicU64,
}

impl SwimContext {
    pub fn next_nonce(&self) -> u64 {
        self.nonce_counter.fetch_add(1, Ordering::Relaxed)
    }

    pub fn current_incarnation(&self) -> u64 {
        self.incarnation.load(Ordering::Relaxed)
    }

    /// Bump our own incarnation by 1 and notify the ticker so the next
    /// piggyback wave includes the refute. Returns the new value.
    pub fn bump_incarnation(&self) -> u64 {
        let new = self.incarnation.fetch_add(1, Ordering::SeqCst) + 1;
        self.refute_signal.notify_one();
        new
    }
}

/// Spawn the SWIM ticker. Runs forever until `shutdown` fires.
pub(crate) fn spawn_swim_task(ctx: Arc<SwimContext>) {
    tokio::spawn(run_ticker(ctx));
}

async fn run_ticker(ctx: Arc<SwimContext>) {
    let mut cursor: usize = 0;
    let mut rng = rand::rngs::SmallRng::seed_from_u64(seed_from_id(ctx.self_id));

    loop {
        tokio::select! {
            _ = ctx.shutdown.cancelled() => {
                debug!(self_id=%ctx.self_id, "swim ticker exiting");
                return;
            }
            _ = sleep(ctx.cfg.swim_ping_interval()) => {}
        }

        let Some((target, _addrs)) = ctx.table.next_probe_target(cursor) else {
            cursor = cursor.wrapping_add(1);
            continue;
        };
        cursor = cursor.wrapping_add(1);
        if target == ctx.self_id {
            continue;
        }

        // Direct ping with timeout.
        let direct_ok = direct_probe(&ctx, target).await;
        if direct_ok {
            ctx.table.note_ack(target);
            continue;
        }

        // Indirect ping fan-out.
        let indirect_ok = indirect_probe(&ctx, target, &mut rng).await;
        if indirect_ok {
            ctx.table.note_ack(target);
            continue;
        }

        // No path to the target. Mark Suspect locally.
        let events = ctx.table.local_transition(target, MemberStatus::Suspect);
        ctx.table.publish(events);
        debug!(peer=%target, "swim probe timed out -> Suspect");
    }
}

async fn direct_probe(ctx: &SwimContext, target: NodeIdentifier) -> bool {
    let nonce = ctx.next_nonce();
    let rx = ctx.pending_acks.register(nonce);

    let ping = build_ping(ctx, nonce);
    if let Err(e) = send_overlay(&ctx.transport, target, ping).await {
        debug!(self_id=%ctx.self_id, peer=%target, error=%e, "direct ping send failed");
        ctx.pending_acks.forget(nonce);
        return false;
    }

    match timeout(ctx.cfg.swim_ping_interval() / 2, rx).await {
        Ok(Ok(())) => {
            trace!(peer=%target, nonce, "direct ping acked");
            true
        }
        _ => {
            ctx.pending_acks.forget(nonce);
            false
        }
    }
}

async fn indirect_probe<R: rand::Rng>(
    ctx: &SwimContext,
    target: NodeIdentifier,
    rng: &mut R,
) -> bool {
    let helpers = ctx.table.pick_alive_random(
        ctx.cfg.swim_indirect_ping_count(),
        target,
        rng,
    );
    if helpers.is_empty() {
        return false;
    }

    let mut joins = Vec::with_capacity(helpers.len());
    for (helper, _) in helpers {
        if helper == ctx.self_id {
            continue;
        }
        let nonce = ctx.next_nonce();
        let rx = ctx.pending_acks.register(nonce);
        let req = build_ping_req(ctx, target, nonce);
        if let Err(e) = send_overlay(&ctx.transport, helper, req).await {
            warn!(peer=%helper, error=%e, "indirect ping-req send failed");
            ctx.pending_acks.forget(nonce);
            continue;
        }
        let pending = ctx.pending_acks.clone();
        joins.push(async move {
            let res = timeout(ctx.cfg.swim_ping_interval(), rx).await;
            pending.forget(nonce);
            matches!(res, Ok(Ok(())))
        });
    }
    if joins.is_empty() {
        return false;
    }
    // Race: first ack wins.
    let any = futures_util::future::select_all(joins.into_iter().map(Box::pin));
    let (ok, _idx, _rest) = any.await;
    ok
}

fn build_ping(ctx: &SwimContext, nonce: u64) -> Bytes {
    let piggyback = build_piggyback(ctx);
    let body = OverlayBody::SwimPing(pb::SwimPing {
        src_node: node_to_wire(ctx.self_id),
        src_incarnation: ctx.current_incarnation(),
        nonce,
        piggyback,
    });
    encode_message(&wrap(body)).expect("encode ping")
}

pub(crate) fn build_ack(ctx: &SwimContext, nonce: u64) -> Bytes {
    let piggyback = build_piggyback(ctx);
    let body = OverlayBody::SwimAck(pb::SwimAck {
        src_node: node_to_wire(ctx.self_id),
        src_incarnation: ctx.current_incarnation(),
        nonce,
        piggyback,
    });
    encode_message(&wrap(body)).expect("encode ack")
}

fn build_ping_req(ctx: &SwimContext, target: NodeIdentifier, nonce: u64) -> Bytes {
    let body = OverlayBody::SwimPingReq(pb::SwimPingReq {
        src_node: node_to_wire(ctx.self_id),
        target_node: node_to_wire(target),
        nonce,
    });
    encode_message(&wrap(body)).expect("encode ping_req")
}

fn build_piggyback(ctx: &SwimContext) -> Vec<pb::GossipUpdate> {
    let mut out = Vec::new();
    // Always include our own most-recent self-claim first so peers refresh
    // our incarnation if it bumped.
    out.push(self_record_to_pb(
        ctx.self_id,
        ctx.current_incarnation(),
        MemberStatus::Alive,
        &[],
    ));
    let cap = ctx.cfg.gossip_piggyback_max().saturating_sub(1);
    for r in ctx.table.recent_updates(cap) {
        out.push(record_to_pb(&r));
    }
    out
}

pub(crate) async fn send_overlay(
    transport: &ConnectionManager,
    dst: NodeIdentifier,
    payload: Bytes,
) -> Result<(), crate::s2s::transport::SendError> {
    transport
        .send(
            dst,
            ServiceLevel::Reliable,
            MessageClass::Regular,
            payload,
        )
        .await
}

fn seed_from_id(id: NodeIdentifier) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    (id as u64).wrapping_mul(0x9E3779B97F4A7C15) ^ now
}

/// Reaper task: every `swim_ping_interval`, sweep the table for members
/// that have been Suspect long enough to upgrade to Dead, and Dead long
/// enough to reap entirely.
pub(crate) fn spawn_reaper(ctx: Arc<SwimContext>) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = ctx.shutdown.cancelled() => return,
                _ = sleep(ctx.cfg.swim_ping_interval()) => {}
            }

            let now = std::time::Instant::now();
            let mut suspects_to_dead = Vec::new();
            for snap in ctx.table.snapshot() {
                if snap.status() == MemberStatus::Suspect
                    && now.duration_since(snap.last_state_change()) >= ctx.cfg.swim_suspicion_timeout()
                {
                    suspects_to_dead.push(snap.node_id());
                }
            }
            for n in suspects_to_dead {
                let events = ctx.table.local_transition(n, MemberStatus::Dead);
                ctx.table.publish(events);
                debug!(peer=%n, "swim suspect -> dead");
            }

            // Reap fully-dead entries. Tell transport to forget them so
            // the supervisor stops trying to dial.
            for reaped in ctx.table.reap_dead(ctx.cfg.swim_dead_timeout()) {
                ctx.transport.forget_node(reaped).await;
            }
        }
    });
}

/// Spawn the periodic refute task: when `refute_signal` fires, broadcast
/// a self-Alive gossip update to every alive member ASAP rather than waiting
/// for the next probe cycle.
pub(crate) fn spawn_refuter(ctx: Arc<SwimContext>) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = ctx.shutdown.cancelled() => return,
                _ = ctx.refute_signal.notified() => {}
            }
            broadcast_self_status(&ctx, MemberStatus::Alive).await;
        }
    });
}

/// Send our current self-claim to every alive member. Used both for refute
/// and for graceful leave.
pub(crate) async fn broadcast_self_status(ctx: &SwimContext, status: MemberStatus) {
    let snap = ctx.table.snapshot();
    let payload = build_self_announcement(ctx, status);
    for member in snap {
        if member.status() == MemberStatus::Alive {
            let _ = send_overlay(&ctx.transport, member.node_id(), payload.clone()).await;
        }
    }
}

fn build_self_announcement(ctx: &SwimContext, status: MemberStatus) -> Bytes {
    let body = OverlayBody::Gossip(pb::GossipDigest {
        updates: vec![self_record_to_pb(
            ctx.self_id,
            ctx.current_incarnation(),
            status,
            &[],
        )],
    });
    encode_message(&wrap(body)).expect("encode gossip")
}

#[allow(dead_code)]
fn _silence(_: Duration) {}
