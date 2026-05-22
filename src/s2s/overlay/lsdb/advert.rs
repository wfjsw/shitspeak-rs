//! Local LSA emission + flood propagation.
//!
//! ## Local emission
//!
//! Owns `(boot_epoch, next_seq)`. A `Notify` is signaled on:
//!  * Direct-link change (neighbor up/down/cost-change > threshold).
//!  * Periodic refresh tick (`lsa_refresh_interval`).
//!  * Graceful shutdown (one final tombstone LSA).
//!
//! Each emission builds an `LinkStateAdvert` from the current direct-
//! neighbor table, increments `next_seq`, admits to the local LSDB, and
//! floods to every direct neighbor.
//!
//! ## Flood propagation
//!
//! Inbound `LsaFlood` arms attempt to admit each LSA. Accepted LSAs are
//! re-flooded to every direct neighbor *except* the sender. Stale/below-
//! floor LSAs are dropped silently — flood quiesces naturally.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::sync::Notify;
use tokio::time::{interval, Instant as TokioInstant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::s2s::transport::{ConnectionManager, MessageClass, ServiceLevel};
use crate::s2s_overlay_proto as pb;
use crate::types::NodeIdentifier;

use super::super::config::OverlayConfig;
use super::super::discovery::learn_from_lsa;
use super::super::neighbor::monitor::{NeighborMonitor, NeighborSnapshot};
use super::super::proto::{encode_message, node_to_wire, wrap, OverlayBody};
use super::store::{AdmissionResult, LinkAdvertised, LinkStateDb, LsaEntry};

/// Local-LSA emitter state.
pub struct LsaEmitter {
    pub self_id: NodeIdentifier,
    pub boot_epoch: u64,
    pub max_users: Arc<AtomicU64>,
    force_next_emit: AtomicBool,
    next_seq: AtomicU64,
    /// Whether this node asks peers not to use it as a transit router.
    transit_disabled: AtomicBool,
    /// Last `(rtt_us, jitter_us, throughput_bps, loss_ppm)` per neighbor we
    /// last published. Used to apply the cost-change-threshold filter.
    last_published:
        parking_lot::Mutex<std::collections::HashMap<NodeIdentifier, (u64, u64, u64, u32)>>,
    /// Local listen addresses. Captured at construction.
    self_addresses: Vec<crate::s2s::transport::PeerAddress>,
    /// Notify to wake the emitter task on neighbor change.
    pub trigger: Notify,
}

impl LsaEmitter {
    pub fn new(
        self_id: NodeIdentifier,
        boot_epoch: u64,
        self_addresses: Vec<crate::s2s::transport::PeerAddress>,
        max_users: Arc<AtomicU64>,
        route_transit_messages: bool,
    ) -> Self {
        Self {
            self_id,
            boot_epoch,
            max_users,
            force_next_emit: AtomicBool::new(false),
            transit_disabled: AtomicBool::new(!route_transit_messages),
            next_seq: AtomicU64::new(1),
            last_published: parking_lot::Mutex::new(std::collections::HashMap::new()),
            self_addresses,
            trigger: Notify::new(),
        }
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::SeqCst)
    }

    /// Notify the emitter that something changed and an LSA should be sent.
    pub fn poke(&self) {
        self.trigger.notify_one();
    }

    /// Force the next poke to emit even if neighbor costs did not change.
    pub fn poke_force(&self) {
        self.force_next_emit.store(true, Ordering::Relaxed);
        self.trigger.notify_one();
    }

    pub fn transit_disabled(&self) -> bool {
        self.transit_disabled.load(Ordering::Relaxed)
    }

    pub fn update_route_transit_messages(&self, enabled: bool) {
        self.transit_disabled.store(!enabled, Ordering::Relaxed);
        self.poke_force();
    }
}

/// Build a fresh local LSA from the current neighbor snapshot.
pub fn build_local_lsa(
    emitter: &LsaEmitter,
    snap: &[NeighborSnapshot],
    tombstone: bool,
) -> LsaEntry {
    let links = if tombstone {
        Vec::new()
    } else {
        snap.iter()
            .map(|n| LinkAdvertised {
                neighbor: n.node_id,
                rtt_us: n.rtt_us,
                jitter_us: n.jitter_us,
                throughput_bps: n.throughput_bps,
                transports_mask: n.transports_mask,
                loss_ppm: n.loss_ppm,
            })
            .collect()
    };
    LsaEntry {
        origin: emitter.self_id,
        boot_epoch: emitter.boot_epoch,
        seq: emitter.next_seq(),
        ts_local_received: std::time::Instant::now(),
        tombstone,
        addresses: if tombstone {
            Vec::new()
        } else {
            emitter.self_addresses.clone()
        },
        links,
        max_users: if tombstone {
            0
        } else {
            emitter.max_users.load(Ordering::Relaxed)
        },
        transit_disabled: if tombstone {
            false
        } else {
            emitter.transit_disabled()
        },
    }
}

/// Has at least one published edge cost shifted enough to warrant a
/// re-emission?
pub fn cost_changed_significantly(
    emitter: &LsaEmitter,
    snap: &[NeighborSnapshot],
    rtt_pct: f64,
    tput_pct: f64,
) -> bool {
    let last = emitter.last_published.lock();
    let prev_set: std::collections::HashSet<NodeIdentifier> = last.keys().copied().collect();
    let now_set: std::collections::HashSet<NodeIdentifier> =
        snap.iter().map(|n| n.node_id).collect();
    if prev_set != now_set {
        return true;
    }
    for n in snap {
        let Some((prev_rtt, prev_jitter, prev_tput, prev_loss)) = last.get(&n.node_id).copied()
        else {
            return true;
        };
        if prev_rtt > 0 {
            let delta = (n.rtt_us as i64 - prev_rtt as i64).unsigned_abs();
            if (delta as f64) / (prev_rtt as f64) >= rtt_pct {
                return true;
            }
        } else if n.rtt_us > 0 {
            return true;
        }
        if prev_jitter > 0 {
            let delta = (n.jitter_us as i64 - prev_jitter as i64).unsigned_abs();
            if (delta as f64) / (prev_jitter as f64) >= rtt_pct {
                return true;
            }
        } else if n.jitter_us > 0 {
            return true;
        }
        if prev_tput > 0 {
            let delta = (n.throughput_bps as i64 - prev_tput as i64).unsigned_abs();
            if (delta as f64) / (prev_tput as f64) >= tput_pct {
                return true;
            }
        } else if n.throughput_bps > 0 {
            return true;
        }
        if prev_loss > 0 {
            let delta = (n.loss_ppm as i64 - prev_loss as i64).unsigned_abs();
            if (delta as f64) / (prev_loss as f64) >= rtt_pct {
                return true;
            }
        } else if n.loss_ppm >= 10_000 {
            return true;
        }
    }
    false
}

/// Stamp the published-baseline so future change-detection compares
/// against the snapshot we just emitted.
pub fn record_published(emitter: &LsaEmitter, snap: &[NeighborSnapshot]) {
    let mut last = emitter.last_published.lock();
    last.clear();
    for n in snap {
        last.insert(
            n.node_id,
            (n.rtt_us, n.jitter_us, n.throughput_bps, n.loss_ppm),
        );
    }
}

/// Flood `lsas` to every direct neighbor in `snap` except `exclude`.
pub async fn flood_to_neighbors(
    transport: &ConnectionManager,
    snap: &[NeighborSnapshot],
    lsas: Vec<pb::LinkStateAdvert>,
    exclude: Option<NodeIdentifier>,
) {
    if lsas.is_empty() {
        return;
    }
    let payload = match encode_message(&wrap(OverlayBody::LsaFlood(pb::LsaFlood {
        advertisements: lsas,
    }))) {
        Ok(b) => b,
        Err(e) => {
            warn!(error=%e, "encode lsa flood failed");
            return;
        }
    };
    for n in snap {
        if Some(n.node_id) == exclude {
            continue;
        }
        if let Err(e) = transport
            .send(
                n.node_id,
                ServiceLevel::Reliable,
                MessageClass::Regular,
                payload.clone(),
            )
            .await
        {
            trace!(peer=%n.node_id, error=%e, "lsa flood send failed");
        }
    }
}

/// Run the local-LSA emission loop. Triggers on:
///  * `emitter.trigger` notifications (from neighbor monitor).
///  * Periodic refresh.
pub fn spawn_emitter_task(
    emitter: Arc<LsaEmitter>,
    lsdb: Arc<LinkStateDb>,
    monitor: Arc<NeighborMonitor>,
    transport: ConnectionManager,
    cfg: OverlayConfig,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        // Emit once immediately so peers learn we exist.
        emit_once(&emitter, &lsdb, &monitor, &transport, &cfg, false).await;

        let mut refresh = interval(cfg.lsa_refresh_interval());
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First tick fires immediately; we already emitted, so absorb it.
        refresh.tick().await;

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = emitter.trigger.notified() => {
                    let snap = monitor.snapshot();
                    let changed = cost_changed_significantly(
                        &emitter,
                        &snap,
                        cfg.cost_rerun_rtt_pct(),
                        cfg.cost_rerun_throughput_pct(),
                    );
                    if emitter.force_next_emit.swap(false, Ordering::Relaxed) || changed {
                        emit_once(&emitter, &lsdb, &monitor, &transport, &cfg, false).await;
                    }
                }
                _ = refresh.tick() => {
                    emit_once(&emitter, &lsdb, &monitor, &transport, &cfg, false).await;
                }
            }
        }
    });
}

/// Build, admit locally, and flood one LSA. Public so shutdown can call it
/// to emit the final tombstone.
pub async fn emit_once(
    emitter: &LsaEmitter,
    lsdb: &LinkStateDb,
    monitor: &NeighborMonitor,
    transport: &ConnectionManager,
    _cfg: &OverlayConfig,
    tombstone: bool,
) {
    let snap = monitor.snapshot();
    let lsa = build_local_lsa(emitter, &snap, tombstone);
    let pb_lsa = lsa.to_pb();
    record_published(emitter, &snap);
    let _ = lsdb.admit(lsa);
    flood_to_neighbors(transport, &snap, vec![pb_lsa], None).await;
    debug!(
        seq = emitter.next_seq.load(Ordering::Relaxed) - 1,
        tombstone,
        neighbors = snap.len(),
        "local lsa emitted"
    );
}

/// Handle an inbound `LsaFlood`. Admit each LSA; re-flood accepted LSAs
/// (excluding the sender).
pub async fn handle_flood(
    lsdb: &LinkStateDb,
    monitor: &NeighborMonitor,
    transport: &ConnectionManager,
    sender: NodeIdentifier,
    flood: pb::LsaFlood,
) {
    let mut accepted: Vec<pb::LinkStateAdvert> = Vec::new();
    for pb_lsa in flood.advertisements {
        let Some(lsa) = LsaEntry::from_pb(&pb_lsa) else {
            continue;
        };
        match lsdb.admit(lsa.clone()) {
            AdmissionResult::Accepted => {
                learn_from_lsa(transport, &lsa);
                accepted.push(pb_lsa);
            }
            AdmissionResult::Stale | AdmissionResult::BelowFloor => {}
        }
    }
    if !accepted.is_empty() {
        let snap = monitor.snapshot();
        flood_to_neighbors(transport, &snap, accepted, Some(sender)).await;
    }
}

/// Capture `boot_epoch` for this process. Microsecond-precision since
/// epoch — assumed unique within a node id (the plan documents the
/// limitation).
pub fn capture_boot_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(1)
}
