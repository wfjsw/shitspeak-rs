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

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::sync::Notify;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::s2s::transport::{ConnectionManager, MessageClass, SendOptions, ServiceLevel};
use crate::s2s_overlay_proto as pb;
use crate::types::NodeIdentifier;

use super::super::config::OverlayConfig;
use super::super::discovery::learn_from_lsa;
use super::super::neighbor::monitor::{NeighborMonitor, NeighborSnapshot};
use super::super::proto::{OverlayBody, encode_message, node_from_wire, node_to_wire, wrap};
use super::store::{AdmissionResult, LinkAdvertised, LinkStateDb, LsaEntry, is_strictly_newer};

/// Local-LSA emitter state.
pub struct LsaEmitter {
    pub self_id: NodeIdentifier,
    pub boot_epoch: u64,
    pub max_users: Arc<AtomicU64>,
    force_next_emit: AtomicBool,
    next_seq: AtomicU64,
    /// Whether this node asks peers not to use it as a transit router.
    transit_disabled: AtomicBool,
    /// Last cost/breakdown tuple per neighbor we published. Used to apply the
    /// cost-change-threshold filter.
    last_published: parking_lot::Mutex<
        std::collections::HashMap<NodeIdentifier, (u64, u64, u64, u32, u32, u32, u32, u64)>,
    >,
    /// Local listen addresses. Captured at construction.
    self_addresses: Vec<crate::s2s::transport::PeerAddress>,
    /// Notify to wake the emitter task on neighbor change.
    pub trigger: Notify,
    last_emitted_content: parking_lot::Mutex<Option<(u64, Instant)>>,
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
            last_emitted_content: parking_lot::Mutex::new(None),
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

#[derive(Clone, Debug)]
struct LsaContent {
    tombstone: bool,
    addresses: Vec<crate::s2s::transport::PeerAddress>,
    links: Vec<LinkAdvertised>,
    max_users: u64,
    transit_disabled: bool,
}

fn build_local_lsa_content(
    emitter: &LsaEmitter,
    snap: &[NeighborSnapshot],
    tombstone: bool,
) -> LsaContent {
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
                probe_loss_ppm: n.probe_loss_ppm,
                native_loss_ppm: n.native_loss_ppm,
                data_health_ppm: n.data_health_ppm,
                loss_sample_count: n.loss_sample_count,
            })
            .collect()
    };
    LsaContent {
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

fn stamp_local_lsa(emitter: &LsaEmitter, content: LsaContent) -> LsaEntry {
    LsaEntry {
        origin: emitter.self_id,
        boot_epoch: emitter.boot_epoch,
        seq: emitter.next_seq(),
        ts_local_received: Instant::now(),
        tombstone: content.tombstone,
        addresses: content.addresses,
        links: content.links,
        max_users: content.max_users,
        transit_disabled: content.transit_disabled,
    }
}

fn content_fingerprint(content: &LsaContent) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    content.tombstone.hash(&mut hasher);
    for addr in &content.addresses {
        addr.hash(&mut hasher);
    }
    for link in &content.links {
        link.neighbor.hash(&mut hasher);
        link.rtt_us.hash(&mut hasher);
        link.jitter_us.hash(&mut hasher);
        link.throughput_bps.hash(&mut hasher);
        link.transports_mask.hash(&mut hasher);
        link.loss_ppm.hash(&mut hasher);
        link.probe_loss_ppm.hash(&mut hasher);
        link.native_loss_ppm.hash(&mut hasher);
        link.data_health_ppm.hash(&mut hasher);
        link.loss_sample_count.hash(&mut hasher);
    }
    content.max_users.hash(&mut hasher);
    content.transit_disabled.hash(&mut hasher);
    hasher.finish()
}

/// Build a fresh local LSA from the current neighbor snapshot.
pub fn build_local_lsa(
    emitter: &LsaEmitter,
    snap: &[NeighborSnapshot],
    tombstone: bool,
) -> LsaEntry {
    let content = build_local_lsa_content(emitter, snap, tombstone);
    stamp_local_lsa(emitter, content)
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
        let Some((
            prev_rtt,
            prev_jitter,
            prev_tput,
            prev_loss,
            prev_probe_loss,
            prev_native_loss,
            prev_data_health,
            prev_loss_samples,
        )) = last.get(&n.node_id).copied()
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
        for (current, previous) in [
            (n.probe_loss_ppm, prev_probe_loss),
            (n.native_loss_ppm, prev_native_loss),
            (n.data_health_ppm, prev_data_health),
        ] {
            if previous > 0 {
                let delta = (current as i64 - previous as i64).unsigned_abs();
                if (delta as f64) / (previous as f64) >= rtt_pct {
                    return true;
                }
            } else if current >= 10_000 {
                return true;
            }
        }
        if prev_loss_samples != n.loss_sample_count
            && (prev_loss_samples == 0 || n.loss_sample_count == 0)
        {
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
            (
                n.rtt_us,
                n.jitter_us,
                n.throughput_bps,
                n.loss_ppm,
                n.probe_loss_ppm,
                n.native_loss_ppm,
                n.data_health_ppm,
                n.loss_sample_count,
            ),
        );
    }
}

#[derive(Default)]
struct LsaFloodPending {
    by_peer: BTreeMap<NodeIdentifier, BTreeMap<NodeIdentifier, pb::LinkStateAdvert>>,
}

impl LsaFloodPending {
    fn enqueue_to_neighbors(
        &mut self,
        snap: &[NeighborSnapshot],
        lsas: Vec<pb::LinkStateAdvert>,
        exclude: Option<NodeIdentifier>,
    ) {
        if lsas.is_empty() {
            return;
        }
        for n in snap {
            if Some(n.node_id) == exclude {
                continue;
            }
            let pending = self.by_peer.entry(n.node_id).or_default();
            for lsa in &lsas {
                let Some(origin) = node_from_wire(lsa.origin) else {
                    continue;
                };
                match pending.get(&origin) {
                    Some(existing)
                        if !is_strictly_newer(
                            lsa.boot_epoch,
                            lsa.seq,
                            existing.boot_epoch,
                            existing.seq,
                        ) => {}
                    _ => {
                        pending.insert(origin, lsa.clone());
                    }
                }
            }
        }
    }

    fn drain_batches(
        &mut self,
        max_batch_lsas: usize,
    ) -> Vec<(NodeIdentifier, Vec<pb::LinkStateAdvert>)> {
        let max_batch_lsas = max_batch_lsas.max(1);
        let by_peer = std::mem::take(&mut self.by_peer);
        let mut out = Vec::new();
        for (peer, by_origin) in by_peer {
            let mut lsas: Vec<_> = by_origin.into_values().collect();
            lsas.sort_by_key(|lsa| (lsa.origin, lsa.boot_epoch, lsa.seq));
            for chunk in lsas.chunks(max_batch_lsas) {
                out.push((peer, chunk.to_vec()));
            }
        }
        out
    }

    fn is_empty(&self) -> bool {
        self.by_peer.values().all(BTreeMap::is_empty)
    }
}

/// Coalesces LSA floods for a short interval so a burst of accepted LSAs
/// becomes fewer frames without changing LSDB admission semantics.
pub struct LsaFloodPacer {
    transport: ConnectionManager,
    pending: parking_lot::Mutex<LsaFloodPending>,
}

impl LsaFloodPacer {
    pub fn new(transport: ConnectionManager) -> Self {
        Self {
            transport,
            pending: parking_lot::Mutex::new(LsaFloodPending::default()),
        }
    }

    pub fn enqueue_to_neighbors(
        &self,
        snap: &[NeighborSnapshot],
        lsas: Vec<pb::LinkStateAdvert>,
        exclude: Option<NodeIdentifier>,
    ) {
        self.pending
            .lock()
            .enqueue_to_neighbors(snap, lsas, exclude);
    }

    pub fn spawn(self: Arc<Self>, cfg: OverlayConfig, shutdown: CancellationToken) {
        tokio::spawn(async move {
            let interval_duration = if cfg.lsa_flood_pacing_interval().is_zero() {
                Duration::from_millis(1)
            } else {
                cfg.lsa_flood_pacing_interval()
            };
            let mut tick = interval(interval_duration);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        self.flush_pending(cfg.lsa_flood_max_batch_lsas()).await;
                        return;
                    }
                    _ = tick.tick() => {
                        self.flush_pending(cfg.lsa_flood_max_batch_lsas()).await;
                    }
                }
            }
        });
    }

    async fn flush_pending(&self, max_batch_lsas: usize) {
        let batches = {
            let mut pending = self.pending.lock();
            if pending.is_empty() {
                return;
            }
            pending.drain_batches(max_batch_lsas)
        };
        for (peer, lsas) in batches {
            send_lsa_flood(&self.transport, peer, lsas).await;
        }
    }
}

async fn send_lsa_flood(
    transport: &ConnectionManager,
    dst: NodeIdentifier,
    lsas: Vec<pb::LinkStateAdvert>,
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
    if let Err(e) = transport
        .send_with_options(
            dst,
            ServiceLevel::Reliable,
            None,
            MessageClass::Regular,
            payload,
            SendOptions::default().allow_l1_compression(),
        )
        .await
    {
        trace!(peer=%dst, error=%e, "lsa flood send failed");
    }
}

/// Flood `lsas` to every direct neighbor in `snap` except `exclude`.
/// This bypasses pacing and is used for shutdown tombstones.
pub async fn flood_to_neighbors(
    transport: &ConnectionManager,
    snap: &[NeighborSnapshot],
    lsas: Vec<pb::LinkStateAdvert>,
    exclude: Option<NodeIdentifier>,
) {
    if lsas.is_empty() {
        return;
    }
    for n in snap {
        if Some(n.node_id) == exclude {
            continue;
        }
        send_lsa_flood(transport, n.node_id, lsas.clone()).await;
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
    pacer: Arc<LsaFloodPacer>,
    cfg: OverlayConfig,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        // Emit once immediately so peers learn we exist.
        emit_once_with_reason(
            &emitter,
            &lsdb,
            &monitor,
            &transport,
            &pacer,
            &cfg,
            EmitReason::Changed,
        )
        .await;

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
                        emit_once_with_reason(
                            &emitter,
                            &lsdb,
                            &monitor,
                            &transport,
                            &pacer,
                            &cfg,
                            EmitReason::Changed,
                        ).await;
                    }
                }
                _ = refresh.tick() => {
                    emit_once_with_reason(
                        &emitter,
                        &lsdb,
                        &monitor,
                        &transport,
                        &pacer,
                        &cfg,
                        EmitReason::Periodic,
                    ).await;
                }
            }
        }
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmitReason {
    Changed,
    Periodic,
    Tombstone,
}

fn unchanged_refresh_deadline(cfg: &OverlayConfig) -> Duration {
    cfg.lsa_unchanged_refresh_interval()
        .min(cfg.lsa_max_age() / 2)
}

fn should_emit_content(
    emitter: &LsaEmitter,
    fingerprint: u64,
    reason: EmitReason,
    cfg: &OverlayConfig,
) -> bool {
    if reason != EmitReason::Periodic || !cfg.lsa_refresh_reduction_enabled() {
        return true;
    }
    let Some((last_fingerprint, last_at)) = *emitter.last_emitted_content.lock() else {
        return true;
    };
    if last_fingerprint != fingerprint {
        return true;
    }
    last_at.elapsed() >= unchanged_refresh_deadline(cfg)
}

fn record_emitted_content(emitter: &LsaEmitter, fingerprint: u64) {
    *emitter.last_emitted_content.lock() = Some((fingerprint, Instant::now()));
}

/// Build, admit locally, and flood one LSA. Public so shutdown can call it
/// to emit the final tombstone.
pub async fn emit_once(
    emitter: &LsaEmitter,
    lsdb: &LinkStateDb,
    monitor: &NeighborMonitor,
    transport: &ConnectionManager,
    pacer: &LsaFloodPacer,
    cfg: &OverlayConfig,
    tombstone: bool,
) {
    let reason = if tombstone {
        EmitReason::Tombstone
    } else {
        EmitReason::Changed
    };
    emit_once_with_reason(emitter, lsdb, monitor, transport, pacer, cfg, reason).await;
}

async fn emit_once_with_reason(
    emitter: &LsaEmitter,
    lsdb: &LinkStateDb,
    monitor: &NeighborMonitor,
    transport: &ConnectionManager,
    pacer: &LsaFloodPacer,
    cfg: &OverlayConfig,
    reason: EmitReason,
) {
    let snap = monitor.snapshot();
    let tombstone = reason == EmitReason::Tombstone;
    let content = build_local_lsa_content(emitter, &snap, tombstone);
    let fingerprint = content_fingerprint(&content);
    if !should_emit_content(emitter, fingerprint, reason, cfg) {
        trace!("unchanged local lsa refresh suppressed");
        return;
    }
    let lsa = stamp_local_lsa(emitter, content);
    let pb_lsa = lsa.to_pb();
    record_published(emitter, &snap);
    let _ = lsdb.admit(lsa);
    record_emitted_content(emitter, fingerprint);
    if tombstone {
        flood_to_neighbors(transport, &snap, vec![pb_lsa], None).await;
    } else {
        pacer.enqueue_to_neighbors(&snap, vec![pb_lsa], None);
    }
    debug!(
        seq = emitter.next_seq.load(Ordering::Relaxed) - 1,
        reason = ?reason,
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
    pacer: &LsaFloodPacer,
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
        pacer.enqueue_to_neighbors(&snap, accepted, Some(sender));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(ids: &[NodeIdentifier]) -> Vec<NeighborSnapshot> {
        ids.iter()
            .copied()
            .map(|node_id| NeighborSnapshot {
                node_id,
                rtt_us: 1_000,
                jitter_us: 0,
                throughput_bps: 1_000_000,
                transports_mask: 1,
                loss_ppm: 0,
                probe_loss_ppm: 0,
                native_loss_ppm: 0,
                data_health_ppm: 0,
                loss_sample_count: 0,
            })
            .collect()
    }

    fn pb_lsa(origin: NodeIdentifier, seq: u64) -> pb::LinkStateAdvert {
        pb::LinkStateAdvert {
            origin: node_to_wire(origin),
            boot_epoch: 1,
            seq,
            ..Default::default()
        }
    }

    #[test]
    fn pending_flood_coalesces_newest_and_excludes_sender() {
        let mut pending = LsaFloodPending::default();
        pending.enqueue_to_neighbors(&snap(&[1, 2, 3]), vec![pb_lsa(7, 1)], Some(2));
        pending.enqueue_to_neighbors(&snap(&[1, 2, 3]), vec![pb_lsa(7, 3)], Some(2));
        pending.enqueue_to_neighbors(&snap(&[1, 2, 3]), vec![pb_lsa(7, 2)], Some(2));
        pending.enqueue_to_neighbors(&snap(&[1, 2, 3]), vec![pb_lsa(8, 1)], Some(2));

        let batches = pending.drain_batches(1);
        assert_eq!(batches.len(), 4);
        assert!(batches.iter().all(|(peer, _)| *peer != 2));
        let mut seen = batches
            .into_iter()
            .flat_map(|(peer, lsas)| lsas.into_iter().map(move |lsa| (peer, lsa.origin, lsa.seq)))
            .collect::<Vec<_>>();
        seen.sort_unstable();
        assert_eq!(
            seen,
            vec![
                (1, node_to_wire(7), 3),
                (1, node_to_wire(8), 1),
                (3, node_to_wire(7), 3),
                (3, node_to_wire(8), 1),
            ]
        );
    }

    #[test]
    fn refresh_reduction_suppresses_unchanged_periodic_lsa() {
        let max_users = Arc::new(AtomicU64::new(10));
        let emitter = LsaEmitter::new(1, 100, vec![], max_users.clone(), true);
        let cfg = OverlayConfig::new(vec![])
            .with_lsa_max_age(Duration::from_secs(120))
            .with_lsa_unchanged_refresh_interval(Duration::from_secs(90));

        let content = build_local_lsa_content(&emitter, &[], false);
        let fingerprint = content_fingerprint(&content);
        assert!(should_emit_content(
            &emitter,
            fingerprint,
            EmitReason::Periodic,
            &cfg
        ));
        record_emitted_content(&emitter, fingerprint);
        assert!(!should_emit_content(
            &emitter,
            fingerprint,
            EmitReason::Periodic,
            &cfg
        ));

        *emitter.last_emitted_content.lock() =
            Some((fingerprint, Instant::now() - Duration::from_secs(61)));
        assert!(should_emit_content(
            &emitter,
            fingerprint,
            EmitReason::Periodic,
            &cfg
        ));

        max_users.store(20, Ordering::Relaxed);
        let changed = build_local_lsa_content(&emitter, &[], false);
        assert!(should_emit_content(
            &emitter,
            content_fingerprint(&changed),
            EmitReason::Periodic,
            &cfg
        ));
    }
}
