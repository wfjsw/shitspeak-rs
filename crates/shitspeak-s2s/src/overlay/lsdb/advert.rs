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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::Notify;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

#[cfg(feature = "pre-release-workload")]
static PRE_RELEASE_METRIC_LSA_EMISSIONS: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "pre-release-workload")]
pub(crate) fn pre_release_metric_lsa_emissions() -> u64 {
    PRE_RELEASE_METRIC_LSA_EMISSIONS.load(Ordering::Relaxed)
}

use shitspeak_core::NodeIdentifier;
use shitspeak_proto::s2s_overlay_proto as pb;
use shitspeak_s2s_transport::{ConnectionManager, MessageClass, SendOptions, ServiceLevel};

use super::super::config::OverlayConfig;
use super::super::discovery::learn_from_lsa;
use super::super::duplicate::{DuplicateDetector, DuplicateEvidenceKind};
use super::super::neighbor::monitor::{NeighborMonitor, NeighborSnapshot, NeighborTransportMetric};
use super::super::proto::{OverlayBody, encode_message, wrap};
use super::super::routing::dijkstra::MIN_ROUTE_LOSS_EXCLUSION_SAMPLES;
use super::store::{
    AdmissionResult, ApplicationServices, DistributionCapabilities, LinkAdvertised, LinkStateDb,
    LinkTransportAdvertised, LsaEntry, ReplicationServices, is_strictly_newer,
};

const RTT_GATE_BUCKET_US: u64 = 25_000;
const JITTER_GATE_BUCKET_US: u64 = 10_000;
const LOSS_GATE_BUCKET_PPM: u32 = 50_000;
const VOICE_UDP_LOSS_GATE_BUCKET_PPM: u32 = 10_000;
const VOICE_UDP_REPAIR_LOSS_START_PPM: u32 = 10_000;
const VOICE_UDP_FULL_DUP_LOSS_PPM: u32 = 30_000;
const VOICE_UDP_REPAIR_JITTER_START_US: u64 = 40_000;

/// Local-LSA emitter state.
pub struct LsaEmitter {
    pub self_id: NodeIdentifier,
    pub boot_epoch: u64,
    pub max_users: Arc<AtomicU64>,
    force_next_emit: AtomicBool,
    next_seq: AtomicU64,
    /// Whether this node asks peers not to use it as a transit router.
    transit_disabled: AtomicBool,
    strict_replication_enabled: AtomicBool,
    content_replication_enabled: AtomicBool,
    owner_replication_enabled: AtomicBool,
    voice_service_enabled: AtomicBool,
    distribution_capabilities: parking_lot::RwLock<DistributionCapabilities>,
    /// Last cost/breakdown tuple per neighbor we published. Used to apply the
    /// cost-change-threshold filter.
    last_published: parking_lot::Mutex<HashMap<NodeIdentifier, LinkGate>>,
    /// Local listen addresses. Captured at construction.
    self_addresses: Vec<shitspeak_s2s_transport::PeerAddress>,
    /// Notify to wake the emitter task on neighbor change.
    pub trigger: Notify,
    last_emitted_content: parking_lot::Mutex<Option<(ContentFingerprint, Instant)>>,
}

impl LsaEmitter {
    pub fn new(
        self_id: NodeIdentifier,
        boot_epoch: u64,
        self_addresses: Vec<shitspeak_s2s_transport::PeerAddress>,
        max_users: Arc<AtomicU64>,
        route_transit_messages: bool,
        replication_services: ReplicationServices,
        application_services: ApplicationServices,
    ) -> Self {
        Self {
            self_id,
            boot_epoch,
            max_users,
            force_next_emit: AtomicBool::new(false),
            transit_disabled: AtomicBool::new(!route_transit_messages),
            strict_replication_enabled: AtomicBool::new(replication_services.strict()),
            content_replication_enabled: AtomicBool::new(replication_services.content()),
            owner_replication_enabled: AtomicBool::new(replication_services.owner()),
            voice_service_enabled: AtomicBool::new(application_services.voice()),
            distribution_capabilities: parking_lot::RwLock::new(
                application_services.distribution().clone(),
            ),
            next_seq: AtomicU64::new(1),
            last_published: parking_lot::Mutex::new(HashMap::new()),
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

    pub fn replication_services(&self) -> ReplicationServices {
        ReplicationServices::new(
            self.strict_replication_enabled.load(Ordering::Relaxed),
            self.content_replication_enabled.load(Ordering::Relaxed),
            self.owner_replication_enabled.load(Ordering::Relaxed),
        )
    }

    pub fn application_services(&self) -> ApplicationServices {
        ApplicationServices::with_distribution_capabilities(
            self.voice_service_enabled.load(Ordering::Relaxed),
            self.distribution_capabilities.read().clone(),
        )
    }

    /// Publish a new generic distribution capability set in the next LSA.
    /// Profile registration uses this to make activation decisions visible to
    /// every potential relay through the normal LSDB flood path.
    pub fn update_distribution_capabilities(&self, capabilities: DistributionCapabilities) {
        *self.distribution_capabilities.write() = capabilities;
        self.poke_force();
    }

    pub fn update_replication_services(&self, services: ReplicationServices) {
        self.strict_replication_enabled
            .store(services.strict(), Ordering::Relaxed);
        self.content_replication_enabled
            .store(services.content(), Ordering::Relaxed);
        self.owner_replication_enabled
            .store(services.owner(), Ordering::Relaxed);
        self.poke_force();
    }
}

#[derive(Clone, Debug)]
struct LsaContent {
    tombstone: bool,
    addresses: Vec<shitspeak_s2s_transport::PeerAddress>,
    links: Vec<LinkAdvertised>,
    max_users: u64,
    transit_disabled: bool,
    replication_services: ReplicationServices,
    application_services: ApplicationServices,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ContentFingerprint {
    identity: u64,
    gate: u64,
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
                observed_recv_bps: n.observed_recv_bps,
                observed_sent_bps: n.observed_sent_bps,
                throughput_confidence_ppm: n.throughput_confidence_ppm,
                transports_mask: n.transports_mask,
                loss_ppm: n.loss_ppm,
                probe_loss_ppm: n.probe_loss_ppm,
                native_loss_ppm: n.native_loss_ppm,
                data_health_ppm: n.data_health_ppm,
                loss_sample_count: n.loss_sample_count,
                transport_metrics: n
                    .transport_metrics
                    .iter()
                    .map(|metric| {
                        LinkTransportAdvertised::new(
                            metric.transport(),
                            metric.rtt_us(),
                            metric.jitter_us(),
                            metric.loss_ppm(),
                            metric.loss_sample_count(),
                        )
                    })
                    .collect(),
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
        replication_services: if tombstone {
            ReplicationServices::NONE
        } else {
            emitter.replication_services()
        },
        application_services: if tombstone {
            ApplicationServices::none()
        } else {
            emitter.application_services()
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
        replication_services: content.replication_services,
        application_services: content.application_services,
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct LinkGate {
    rtt_us: u64,
    jitter_us: u64,
    throughput_bps: u64,
    observed_sent_bps: u64,
    throughput_confidence_ppm: u32,
    transports_mask: u32,
    loss_ppm: u32,
    loss_confident: bool,
    excessive_loss: bool,
    voice_udp: VoiceUdpGate,
}

impl LinkGate {
    fn from_snapshot(n: &NeighborSnapshot, cfg: &OverlayConfig) -> Self {
        Self::from_parts(
            n.rtt_us,
            n.jitter_us,
            n.throughput_bps,
            n.observed_sent_bps,
            n.throughput_confidence_ppm,
            n.transports_mask,
            n.loss_ppm,
            n.loss_sample_count,
            voice_udp_gate_from_neighbor_metrics(&n.transport_metrics),
            cfg,
        )
    }

    fn from_link(link: &LinkAdvertised, cfg: &OverlayConfig) -> Self {
        Self::from_parts(
            link.rtt_us,
            link.jitter_us,
            link.throughput_bps,
            link.observed_sent_bps,
            link.throughput_confidence_ppm,
            link.transports_mask,
            link.loss_ppm,
            link.loss_sample_count,
            voice_udp_gate_from_link_metrics(&link.transport_metrics),
            cfg,
        )
    }

    fn from_parts(
        rtt_us: u64,
        jitter_us: u64,
        throughput_bps: u64,
        observed_sent_bps: u64,
        throughput_confidence_ppm: u32,
        transports_mask: u32,
        loss_ppm: u32,
        loss_sample_count: u64,
        voice_udp: VoiceUdpGate,
        cfg: &OverlayConfig,
    ) -> Self {
        let loss_ppm = round_up_u32(loss_ppm, LOSS_GATE_BUCKET_PPM).min(1_000_000);
        let loss_confident = loss_sample_count >= MIN_ROUTE_LOSS_EXCLUSION_SAMPLES;
        Self {
            rtt_us: round_up_u64(rtt_us, RTT_GATE_BUCKET_US),
            jitter_us: round_up_u64(jitter_us, JITTER_GATE_BUCKET_US),
            throughput_bps: round_down_throughput_gate(throughput_bps),
            observed_sent_bps: round_down_throughput_gate(observed_sent_bps),
            throughput_confidence_ppm: round_up_u32(
                throughput_confidence_ppm,
                LOSS_GATE_BUCKET_PPM,
            )
            .min(1_000_000),
            transports_mask,
            loss_ppm,
            loss_confident,
            excessive_loss: loss_confident && loss_ppm >= cfg.max_route_packet_loss_ppm(),
            voice_udp,
        }
    }

    fn service_eligibility(self, cfg: &OverlayConfig) -> ServiceEligibility {
        if self.excessive_loss {
            return ServiceEligibility::default();
        }
        ServiceEligibility {
            best_effort: self.transports_mask & cfg.best_effort_transports_mask() != 0,
            reliable: self.transports_mask & cfg.reliable_transports_mask() != 0,
            reliable_low_latency: self.transports_mask & cfg.rll_transports_mask() != 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ServiceEligibility {
    best_effort: bool,
    reliable: bool,
    reliable_low_latency: bool,
}

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq)]
struct VoiceUdpGate {
    loss_ppm: u32,
    jitter_us: u64,
    loss_confident: bool,
    repair_loss_active: bool,
    full_dup_loss_active: bool,
    repair_jitter_active: bool,
}

fn voice_udp_gate(loss_ppm: u32, jitter_us: u64, loss_sample_count: u64) -> VoiceUdpGate {
    let loss_ppm = round_up_u32(loss_ppm, VOICE_UDP_LOSS_GATE_BUCKET_PPM).min(1_000_000);
    let jitter_us = round_up_u64(jitter_us, JITTER_GATE_BUCKET_US);
    let loss_confident = loss_sample_count >= MIN_ROUTE_LOSS_EXCLUSION_SAMPLES;
    VoiceUdpGate {
        loss_ppm,
        jitter_us,
        loss_confident,
        repair_loss_active: loss_ppm >= VOICE_UDP_REPAIR_LOSS_START_PPM,
        full_dup_loss_active: loss_ppm >= VOICE_UDP_FULL_DUP_LOSS_PPM,
        repair_jitter_active: jitter_us >= VOICE_UDP_REPAIR_JITTER_START_US,
    }
}

fn voice_udp_gate_from_neighbor_metrics(metrics: &[NeighborTransportMetric]) -> VoiceUdpGate {
    metrics
        .iter()
        .find(|metric| metric.transport() == shitspeak_s2s_transport::TransportKind::Udp)
        .map(|metric| {
            voice_udp_gate(
                metric.loss_ppm(),
                metric.jitter_us(),
                metric.loss_sample_count(),
            )
        })
        .unwrap_or_default()
}

fn voice_udp_gate_from_link_metrics(metrics: &[LinkTransportAdvertised]) -> VoiceUdpGate {
    metrics
        .iter()
        .find(|metric| metric.transport() == shitspeak_s2s_transport::TransportKind::Udp)
        .map(|metric| {
            voice_udp_gate(
                metric.loss_ppm(),
                metric.jitter_us(),
                metric.loss_sample_count(),
            )
        })
        .unwrap_or_default()
}

fn round_up_u64(value: u64, bucket: u64) -> u64 {
    if value == 0 || bucket == 0 {
        return value;
    }
    value
        .saturating_add(bucket - 1)
        .saturating_div(bucket)
        .saturating_mul(bucket)
}

fn round_up_u32(value: u32, bucket: u32) -> u32 {
    if value == 0 || bucket == 0 {
        return value;
    }
    value
        .saturating_add(bucket - 1)
        .saturating_div(bucket)
        .saturating_mul(bucket)
}

fn round_down_throughput_gate(value: u64) -> u64 {
    if value <= 1 {
        return value;
    }

    // Throughput improves as the value increases, so gate it at the lower
    // edge of a roughly 10% bucket. This keeps routing conservative while
    // preventing tiny estimator movement from changing the LSA fingerprint.
    let mut gate = 1u64;
    loop {
        let step = gate.saturating_add(9) / 10;
        let next = gate.saturating_add(step.max(1));
        if next > value || next <= gate {
            return gate;
        }
        gate = next;
    }
}

fn gate_delta_ratio_changed(previous: u64, current: u64, pct: f64, min_delta: u64) -> bool {
    if previous > 0 {
        let delta = current.abs_diff(previous);
        delta >= min_delta && (delta as f64) / (previous as f64) >= pct
    } else {
        current > 0
    }
}

fn content_gate_fingerprint(content: &LsaContent, cfg: &OverlayConfig) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    content.tombstone.hash(&mut hasher);
    for addr in &content.addresses {
        addr.hash(&mut hasher);
    }
    for link in &content.links {
        link.neighbor.hash(&mut hasher);
        LinkGate::from_link(link, cfg).hash(&mut hasher);
    }
    content.max_users.hash(&mut hasher);
    content.transit_disabled.hash(&mut hasher);
    content.replication_services.strict().hash(&mut hasher);
    content.replication_services.content().hash(&mut hasher);
    content.replication_services.owner().hash(&mut hasher);
    content.application_services.voice().hash(&mut hasher);
    content
        .application_services
        .distribution()
        .protocol_version()
        .hash(&mut hasher);
    content
        .application_services
        .distribution()
        .profile_ids()
        .hash(&mut hasher);
    hasher.finish()
}

fn content_identity_fingerprint(content: &LsaContent) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    content.tombstone.hash(&mut hasher);
    for addr in &content.addresses {
        addr.hash(&mut hasher);
    }
    for link in &content.links {
        link.neighbor.hash(&mut hasher);
        link.transports_mask.hash(&mut hasher);
    }
    content.max_users.hash(&mut hasher);
    content.transit_disabled.hash(&mut hasher);
    content.replication_services.strict().hash(&mut hasher);
    content.replication_services.content().hash(&mut hasher);
    content.replication_services.owner().hash(&mut hasher);
    content.application_services.voice().hash(&mut hasher);
    content
        .application_services
        .distribution()
        .protocol_version()
        .hash(&mut hasher);
    content
        .application_services
        .distribution()
        .profile_ids()
        .hash(&mut hasher);
    hasher.finish()
}

fn content_fingerprint(content: &LsaContent, cfg: &OverlayConfig) -> ContentFingerprint {
    ContentFingerprint {
        identity: content_identity_fingerprint(content),
        gate: content_gate_fingerprint(content, cfg),
    }
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
    cfg: &OverlayConfig,
) -> bool {
    let last = emitter.last_published.lock();
    let prev_set: HashSet<NodeIdentifier> = last.keys().copied().collect();
    let now_set: HashSet<NodeIdentifier> = snap.iter().map(|n| n.node_id).collect();
    if prev_set != now_set {
        trace!(
            previous = ?prev_set,
            current = ?now_set,
            "local lsa change gate crossed: neighbor set"
        );
        return true;
    }
    for n in snap {
        let Some(previous) = last.get(&n.node_id).copied() else {
            trace!(
                peer = %n.node_id,
                "local lsa change gate crossed: missing published baseline"
            );
            return true;
        };
        let current = LinkGate::from_snapshot(n, cfg);
        if previous.transports_mask != current.transports_mask {
            trace!(
                peer = %n.node_id,
                previous = previous.transports_mask,
                current = current.transports_mask,
                "local lsa change gate crossed: transport mask"
            );
            return true;
        }
        if gate_delta_ratio_changed(
            previous.rtt_us,
            current.rtt_us,
            cfg.cost_rerun_rtt_pct(),
            RTT_GATE_BUCKET_US * 2,
        ) {
            trace!(
                peer = %n.node_id,
                previous = previous.rtt_us,
                current = current.rtt_us,
                threshold_pct = cfg.cost_rerun_rtt_pct(),
                "local lsa change gate crossed: rtt"
            );
            return true;
        }
        if gate_delta_ratio_changed(
            previous.jitter_us,
            current.jitter_us,
            cfg.cost_rerun_rtt_pct(),
            JITTER_GATE_BUCKET_US * 2,
        ) {
            trace!(
                peer = %n.node_id,
                previous = previous.jitter_us,
                current = current.jitter_us,
                threshold_pct = cfg.cost_rerun_rtt_pct(),
                "local lsa change gate crossed: jitter"
            );
            return true;
        }
        if gate_delta_ratio_changed(
            previous.observed_sent_bps,
            current.observed_sent_bps,
            cfg.cost_rerun_throughput_pct(),
            1,
        ) {
            trace!(
                peer = %n.node_id,
                previous = previous.observed_sent_bps,
                current = current.observed_sent_bps,
                threshold_pct = cfg.cost_rerun_throughput_pct(),
                "local lsa change gate crossed: observed sent throughput"
            );
            return true;
        }
        if previous.throughput_confidence_ppm != current.throughput_confidence_ppm
            && (previous.observed_sent_bps > 0 || current.observed_sent_bps > 0)
        {
            trace!(
                peer = %n.node_id,
                previous = previous.throughput_confidence_ppm,
                current = current.throughput_confidence_ppm,
                "local lsa change gate crossed: throughput confidence"
            );
            return true;
        }
        if previous.loss_confident != current.loss_confident
            && (previous.loss_ppm > 0 || current.loss_ppm > 0)
        {
            trace!(
                peer = %n.node_id,
                previous = previous.loss_confident,
                current = current.loss_confident,
                "local lsa change gate crossed: loss confidence"
            );
            return true;
        }
        if previous.excessive_loss != current.excessive_loss {
            trace!(
                peer = %n.node_id,
                previous = previous.excessive_loss,
                current = current.excessive_loss,
                max_route_packet_loss_ppm = cfg.max_route_packet_loss_ppm(),
                "local lsa change gate crossed: excessive loss"
            );
            return true;
        }
        let loss_delta = previous.loss_ppm.abs_diff(current.loss_ppm);
        if loss_delta > 0 && loss_delta >= cfg.cost_rerun_loss_ppm() {
            trace!(
                peer = %n.node_id,
                previous = previous.loss_ppm,
                current = current.loss_ppm,
                threshold_ppm = cfg.cost_rerun_loss_ppm(),
                "local lsa change gate crossed: loss"
            );
            return true;
        }
    }
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalChange {
    Unchanged,
    Metric,
    Structural,
}

fn classify_local_change(
    emitter: &LsaEmitter,
    snap: &[NeighborSnapshot],
    cfg: &OverlayConfig,
) -> LocalChange {
    {
        let last = emitter.last_published.lock();
        let prev_set: HashSet<NodeIdentifier> = last.keys().copied().collect();
        let now_set: HashSet<NodeIdentifier> = snap.iter().map(|n| n.node_id).collect();
        if prev_set != now_set {
            return LocalChange::Structural;
        }
        for neighbor in snap {
            let Some(previous) = last.get(&neighbor.node_id).copied() else {
                return LocalChange::Structural;
            };
            let current = LinkGate::from_snapshot(neighbor, cfg);
            if previous.service_eligibility(cfg) != current.service_eligibility(cfg) {
                trace!(
                    peer = %neighbor.node_id,
                    previous = ?previous.service_eligibility(cfg),
                    current = ?current.service_eligibility(cfg),
                    "local lsa structural gate crossed: service eligibility"
                );
                return LocalChange::Structural;
            }
        }
    }

    if cost_changed_significantly(emitter, snap, cfg)
        || voice_cost_changed_significantly(emitter, snap, cfg)
    {
        LocalChange::Metric
    } else {
        LocalChange::Unchanged
    }
}

#[derive(Clone, Copy, Debug)]
struct PendingMetricChange {
    fingerprint: ContentFingerprint,
    stable_since: Instant,
}

impl PendingMetricChange {
    fn observe(pending: &mut Option<Self>, fingerprint: ContentFingerprint, now: Instant) {
        if pending
            .as_ref()
            .is_none_or(|candidate| candidate.fingerprint != fingerprint)
        {
            *pending = Some(Self {
                fingerprint,
                stable_since: now,
            });
        }
    }

    fn deadline(self, emitter: &LsaEmitter, cfg: &OverlayConfig) -> Instant {
        let stable_at = self.stable_since + cfg.lsa_metric_hold();
        let min_interval_at = emitter
            .last_emitted_content
            .lock()
            .as_ref()
            .map(|(_, emitted_at)| *emitted_at + cfg.lsa_metric_min_emit_interval())
            .unwrap_or(self.stable_since);
        stable_at.max(min_interval_at)
    }
}

/// Has UDP voice quality shifted enough to cross its metric gate?
pub fn voice_cost_changed_significantly(
    emitter: &LsaEmitter,
    snap: &[NeighborSnapshot],
    cfg: &OverlayConfig,
) -> bool {
    let last = emitter.last_published.lock();
    for n in snap {
        let Some(previous) = last.get(&n.node_id).copied() else {
            continue;
        };
        let current = LinkGate::from_snapshot(n, cfg);
        if previous.voice_udp != current.voice_udp {
            trace!(
                peer = %n.node_id,
                previous = ?previous.voice_udp,
                current = ?current.voice_udp,
                "local lsa urgent voice metric gate crossed: udp quality"
            );
            return true;
        }
    }
    false
}

/// Stamp the published-baseline so future change-detection compares
/// against the snapshot we just emitted.
pub fn record_published(emitter: &LsaEmitter, snap: &[NeighborSnapshot], cfg: &OverlayConfig) {
    let mut last = emitter.last_published.lock();
    last.clear();
    for n in snap {
        last.insert(n.node_id, LinkGate::from_snapshot(n, cfg));
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
        self.enqueue_to_neighbors_inner(snap, lsas, exclude, false);
    }

    fn enqueue_reflood_to_neighbors(
        &mut self,
        snap: &[NeighborSnapshot],
        lsas: Vec<pb::LinkStateAdvert>,
        exclude: Option<NodeIdentifier>,
    ) {
        self.enqueue_to_neighbors_inner(snap, lsas, exclude, true);
    }

    fn enqueue_to_neighbors_inner(
        &mut self,
        snap: &[NeighborSnapshot],
        lsas: Vec<pb::LinkStateAdvert>,
        exclude: Option<NodeIdentifier>,
        suppress_origin_neighbors: bool,
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
                let Ok(origin) = NodeIdentifier::try_from(lsa.origin) else {
                    continue;
                };
                if suppress_origin_neighbors
                    && (origin == n.node_id || lsa_lists_direct_neighbor(lsa, n.node_id))
                {
                    continue;
                }
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

fn lsa_lists_direct_neighbor(lsa: &pb::LinkStateAdvert, peer: NodeIdentifier) -> bool {
    lsa.links
        .iter()
        .any(|link| NodeIdentifier::try_from(link.neighbor).ok() == Some(peer))
}

/// Coalesces LSA floods for a short interval so a burst of accepted LSAs
/// becomes fewer frames without changing LSDB admission semantics.
pub struct LsaFloodPacer {
    self_id: NodeIdentifier,
    transport: ConnectionManager,
    pending: parking_lot::Mutex<LsaFloodPending>,
}

impl LsaFloodPacer {
    pub fn new(self_id: NodeIdentifier, transport: ConnectionManager) -> Self {
        Self {
            self_id,
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

    pub fn enqueue_reflood_to_neighbors(
        &self,
        snap: &[NeighborSnapshot],
        lsas: Vec<pb::LinkStateAdvert>,
        exclude: Option<NodeIdentifier>,
    ) {
        self.pending
            .lock()
            .enqueue_reflood_to_neighbors(snap, lsas, exclude);
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
            send_lsa_flood(&self.transport, self.self_id, peer, lsas).await;
        }
    }
}

async fn send_lsa_flood(
    transport: &ConnectionManager,
    self_id: NodeIdentifier,
    dst: NodeIdentifier,
    lsas: Vec<pb::LinkStateAdvert>,
) {
    if lsas.is_empty() {
        return;
    }
    let body = OverlayBody::LsaFlood(pb::LsaFlood {
        advertisements: lsas,
    });
    let packet_kind = crate::debug_io::classify_overlay_body(&body);
    let payload = match encode_message(&wrap(body)) {
        Ok(b) => b,
        Err(e) => {
            warn!(error=%e, "encode lsa flood failed");
            return;
        }
    };
    let payload_len = payload.len();
    match transport
        .try_send_with_options(
            dst,
            ServiceLevel::Reliable,
            None,
            MessageClass::Regular,
            payload,
            SendOptions::default().allow_l1_compression(),
        )
        .await
    {
        Ok(()) => crate::debug_io::record_sent(self_id, dst, packet_kind, payload_len),
        Err(e) => trace!(peer=%dst, error=%e, "lsa flood send failed"),
    }
}

/// Flood `lsas` to every direct neighbor in `snap` except `exclude`.
/// This bypasses pacing and is used for shutdown tombstones.
pub async fn flood_to_neighbors(
    transport: &ConnectionManager,
    self_id: NodeIdentifier,
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
        send_lsa_flood(transport, self_id, n.node_id, lsas.clone()).await;
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

        let mut pending_metric = None;

        loop {
            let pending_deadline = pending_metric
                .map(|candidate: PendingMetricChange| candidate.deadline(&emitter, &cfg));
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = emitter.trigger.notified() => {
                    let snap = monitor.snapshot();
                    if emitter.force_next_emit.swap(false, Ordering::Relaxed) {
                        pending_metric = None;
                        emit_once_with_reason(&emitter, &lsdb, &monitor, &transport, &pacer, &cfg, EmitReason::Changed).await;
                        continue;
                    }
                    match classify_local_change(&emitter, &snap, &cfg) {
                        LocalChange::Structural => {
                            pending_metric = None;
                            emit_once_with_reason(&emitter, &lsdb, &monitor, &transport, &pacer, &cfg, EmitReason::Changed).await;
                        }
                        LocalChange::Metric => {
                            let content = build_local_lsa_content(&emitter, &snap, false);
                            PendingMetricChange::observe(
                                &mut pending_metric,
                                content_fingerprint(&content, &cfg),
                                Instant::now(),
                            );
                        }
                        LocalChange::Unchanged => pending_metric = None,
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
                    let snap = monitor.snapshot();
                    match classify_local_change(&emitter, &snap, &cfg) {
                        LocalChange::Unchanged | LocalChange::Structural => pending_metric = None,
                        LocalChange::Metric => {
                            let content = build_local_lsa_content(&emitter, &snap, false);
                            PendingMetricChange::observe(
                                &mut pending_metric,
                                content_fingerprint(&content, &cfg),
                                Instant::now(),
                            );
                        }
                    }
                }
                _ = async {
                    match pending_deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    let snap = monitor.snapshot();
                    match classify_local_change(&emitter, &snap, &cfg) {
                        LocalChange::Structural => {
                            pending_metric = None;
                            emit_once_with_reason(&emitter, &lsdb, &monitor, &transport, &pacer, &cfg, EmitReason::Changed).await;
                        }
                        LocalChange::Metric => {
                            let content = build_local_lsa_content(&emitter, &snap, false);
                            PendingMetricChange::observe(
                                &mut pending_metric,
                                content_fingerprint(&content, &cfg),
                                Instant::now(),
                            );
                            let ready = pending_metric
                                .is_some_and(|candidate| candidate.deadline(&emitter, &cfg) <= Instant::now());
                            if ready {
                                pending_metric = None;
                                emit_once_with_reason(&emitter, &lsdb, &monitor, &transport, &pacer, &cfg, EmitReason::Metric).await;
                            }
                        }
                        LocalChange::Unchanged => pending_metric = None,
                    }
                }
            }
        }
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmitReason {
    Changed,
    Metric,
    Periodic,
    Tombstone,
}

fn unchanged_refresh_deadline(cfg: &OverlayConfig) -> Duration {
    cfg.lsa_unchanged_refresh_interval()
        .min((cfg.lsa_max_age() / 3).max(Duration::from_millis(1)))
}

fn should_emit_content(
    emitter: &LsaEmitter,
    fingerprint: ContentFingerprint,
    reason: EmitReason,
    cfg: &OverlayConfig,
) -> bool {
    if reason != EmitReason::Periodic || !cfg.lsa_refresh_reduction_enabled() {
        return true;
    }
    let Some((last, last_at)) = *emitter.last_emitted_content.lock() else {
        return true;
    };
    if last.identity != fingerprint.identity {
        return true;
    }
    if last.gate != fingerprint.gate {
        trace!("sub-threshold metric movement ignored for local lsa refresh");
    }
    last_at.elapsed() >= unchanged_refresh_deadline(cfg)
}

fn record_emitted_content(emitter: &LsaEmitter, fingerprint: ContentFingerprint) {
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
    let fingerprint = content_fingerprint(&content, cfg);
    if !should_emit_content(emitter, fingerprint, reason, cfg) {
        trace!("unchanged local lsa refresh suppressed");
        return;
    }
    let lsa = stamp_local_lsa(emitter, content);
    let lsa_origin = lsa.origin;
    let lsa_boot_epoch = lsa.boot_epoch;
    let lsa_seq = lsa.seq;
    let pb_lsa = lsa.to_pb();
    match lsdb.admit(lsa) {
        AdmissionResult::Accepted => {}
        AdmissionResult::Stale | AdmissionResult::BelowFloor => {
            warn!(
                origin = lsa_origin,
                boot_epoch = lsa_boot_epoch,
                seq = lsa_seq,
                reason = ?reason,
                "local lsa rejected by local lsdb; suppressing flood"
            );
            return;
        }
    }
    record_published(emitter, &snap, cfg);
    record_emitted_content(emitter, fingerprint);
    #[cfg(feature = "pre-release-workload")]
    if reason == EmitReason::Metric {
        PRE_RELEASE_METRIC_LSA_EMISSIONS.fetch_add(1, Ordering::Relaxed);
    }
    if tombstone {
        flood_to_neighbors(transport, emitter.self_id, &snap, vec![pb_lsa], None).await;
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
    duplicate_detector: &DuplicateDetector,
    sender: NodeIdentifier,
    flood: pb::LsaFlood,
) {
    let mut accepted: Vec<pb::LinkStateAdvert> = Vec::new();
    for pb_lsa in flood.advertisements {
        let Some(lsa) = LsaEntry::from_pb(&pb_lsa) else {
            continue;
        };
        duplicate_detector.observe_epoch(
            lsa.origin,
            lsa.boot_epoch,
            lsa.tombstone,
            DuplicateEvidenceKind::Lsa,
        );
        if duplicate_detector.is_quarantined(lsa.origin) {
            duplicate_detector.record_drop(lsa.origin, "lsa");
            continue;
        }
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
        pacer.enqueue_reflood_to_neighbors(&snap, accepted, Some(sender));
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

    use crate::overlay::proto::node_to_wire;
    use crate::overlay::routing::dijkstra;
    use shitspeak_s2s_transport::ServiceLevel;

    fn snap(ids: &[NodeIdentifier]) -> Vec<NeighborSnapshot> {
        ids.iter()
            .copied()
            .map(|node_id| NeighborSnapshot {
                node_id,
                rtt_us: 1_000,
                jitter_us: 0,
                throughput_bps: 1_000_000,
                observed_recv_bps: 1_000_000,
                observed_sent_bps: 1_000_000,
                throughput_confidence_ppm: 1_000_000,
                transports_mask: 1,
                loss_ppm: 0,
                probe_loss_ppm: 0,
                native_loss_ppm: 0,
                data_health_ppm: 0,
                loss_sample_count: 0,
                transport_metrics: Vec::new(),
            })
            .collect()
    }

    fn one_neighbor() -> NeighborSnapshot {
        snap(&[2]).into_iter().next().unwrap()
    }

    fn test_emitter() -> LsaEmitter {
        LsaEmitter::new(
            1,
            100,
            vec![],
            Arc::new(AtomicU64::new(10)),
            true,
            ReplicationServices::ALL,
            ApplicationServices::ALL,
        )
    }

    #[test]
    fn emitter_publishes_updated_distribution_capabilities() {
        let emitter = test_emitter();
        emitter.update_distribution_capabilities(DistributionCapabilities::v1([7, 3]));

        let lsa = build_local_lsa(&emitter, &[], false);
        assert_eq!(
            lsa.application_services.distribution().protocol_version(),
            1
        );
        assert_eq!(
            lsa.application_services.distribution().profile_ids(),
            &[3, 7]
        );
    }

    fn pb_lsa(origin: NodeIdentifier, seq: u64) -> pb::LinkStateAdvert {
        pb::LinkStateAdvert {
            origin: node_to_wire(origin),
            boot_epoch: 1,
            seq,
            ..Default::default()
        }
    }

    fn pb_lsa_with_links(
        origin: NodeIdentifier,
        seq: u64,
        links: &[NodeIdentifier],
    ) -> pb::LinkStateAdvert {
        pb::LinkStateAdvert {
            links: links
                .iter()
                .copied()
                .map(|neighbor| pb::LinkAdvert {
                    neighbor: node_to_wire(neighbor),
                    ..Default::default()
                })
                .collect(),
            ..pb_lsa(origin, seq)
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
    fn pending_reflood_skips_origin_and_origin_direct_neighbors() {
        let mut pending = LsaFloodPending::default();
        pending.enqueue_reflood_to_neighbors(
            &snap(&[1, 2, 3, 4, 7]),
            vec![pb_lsa_with_links(7, 1, &[1, 3])],
            Some(2),
        );

        let batches = pending.drain_batches(8);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].0, 4);
        assert_eq!(batches[0].1[0].origin, node_to_wire(7));
    }

    #[test]
    fn rounded_rtt_movement_inside_bucket_does_not_emit() {
        let cfg = OverlayConfig::new(vec![]);
        let emitter = test_emitter();
        let mut base = one_neighbor();
        base.rtt_us = 101_000;
        let base = vec![base];
        record_published(&emitter, &base, &cfg);

        let mut changed = base.clone();
        changed[0].rtt_us = 124_000;
        assert!(!cost_changed_significantly(&emitter, &changed, &cfg));

        changed[0].rtt_us = 160_000;
        assert!(cost_changed_significantly(&emitter, &changed, &cfg));
    }

    #[test]
    fn adjacent_rtt_bucket_movement_does_not_emit() {
        let cfg = OverlayConfig::new(vec![]);
        let emitter = test_emitter();
        let mut base = one_neighbor();
        base.rtt_us = 76_000;
        let base = vec![base];
        record_published(&emitter, &base, &cfg);

        let mut changed = base.clone();
        changed[0].rtt_us = 101_000;
        assert!(!cost_changed_significantly(&emitter, &changed, &cfg));

        changed[0].rtt_us = 126_000;
        assert!(cost_changed_significantly(&emitter, &changed, &cfg));
    }

    #[test]
    fn rounded_jitter_and_loss_movement_inside_buckets_do_not_emit() {
        let cfg = OverlayConfig::new(vec![]);
        let emitter = test_emitter();
        let mut base = one_neighbor();
        base.jitter_us = 11_000;
        base.loss_ppm = 101_000;
        base.loss_sample_count = MIN_ROUTE_LOSS_EXCLUSION_SAMPLES;
        let base = vec![base];
        record_published(&emitter, &base, &cfg);

        let mut changed = base.clone();
        changed[0].jitter_us = 19_000;
        changed[0].loss_ppm = 149_000;
        assert!(!cost_changed_significantly(&emitter, &changed, &cfg));
    }

    #[test]
    fn adjacent_jitter_bucket_movement_does_not_emit() {
        let cfg = OverlayConfig::new(vec![]);
        let emitter = test_emitter();
        let mut base = one_neighbor();
        base.jitter_us = 31_000;
        let base = vec![base];
        record_published(&emitter, &base, &cfg);

        let mut changed = base.clone();
        changed[0].jitter_us = 41_000;
        assert!(!cost_changed_significantly(&emitter, &changed, &cfg));

        changed[0].jitter_us = 51_000;
        assert!(cost_changed_significantly(&emitter, &changed, &cfg));
    }

    #[test]
    fn throughput_gate_is_conservative_and_ignores_tiny_changes() {
        let cfg = OverlayConfig::new(vec![]);
        let emitter = test_emitter();
        let mut base = one_neighbor();
        base.throughput_bps = 1_234_567;
        let base_gate = LinkGate::from_snapshot(&base, &cfg).throughput_bps;
        let base = vec![base];
        record_published(&emitter, &base, &cfg);

        let mut changed = base.clone();
        changed[0].throughput_bps = 1_234_568;
        let changed_gate = LinkGate::from_snapshot(&changed[0], &cfg).throughput_bps;
        assert!(base_gate <= base[0].throughput_bps);
        assert_eq!(base_gate, changed_gate);
        assert!(!cost_changed_significantly(&emitter, &changed, &cfg));
    }

    #[test]
    fn effective_loss_emits_on_confidence_max_crossing_or_configured_delta() {
        let cfg = OverlayConfig::new(vec![]);
        let emitter = test_emitter();
        let mut base = one_neighbor();
        base.loss_ppm = 50_000;
        base.loss_sample_count = MIN_ROUTE_LOSS_EXCLUSION_SAMPLES - 1;
        let base = vec![base];
        record_published(&emitter, &base, &cfg);

        let mut changed = base.clone();
        changed[0].loss_sample_count = MIN_ROUTE_LOSS_EXCLUSION_SAMPLES;
        assert!(cost_changed_significantly(&emitter, &changed, &cfg));

        let emitter = test_emitter();
        let mut base = one_neighbor();
        base.loss_ppm = 425_000;
        base.loss_sample_count = MIN_ROUTE_LOSS_EXCLUSION_SAMPLES;
        let base = vec![base];
        record_published(&emitter, &base, &cfg);

        let mut changed = base.clone();
        changed[0].loss_ppm = 451_000;
        assert!(cost_changed_significantly(&emitter, &changed, &cfg));

        let emitter = test_emitter();
        let mut base = one_neighbor();
        base.loss_ppm = 101_000;
        base.loss_sample_count = MIN_ROUTE_LOSS_EXCLUSION_SAMPLES;
        let base = vec![base];
        record_published(&emitter, &base, &cfg);

        let mut changed = base.clone();
        changed[0].loss_ppm = 201_000;
        assert!(cost_changed_significantly(&emitter, &changed, &cfg));
    }

    #[test]
    fn zero_effective_loss_confidence_movement_does_not_emit() {
        let cfg = OverlayConfig::new(vec![]);
        let emitter = test_emitter();
        let mut base = one_neighbor();
        base.loss_ppm = 0;
        base.loss_sample_count = MIN_ROUTE_LOSS_EXCLUSION_SAMPLES - 1;
        let base = vec![base];
        record_published(&emitter, &base, &cfg);

        let mut changed = base.clone();
        changed[0].loss_sample_count = MIN_ROUTE_LOSS_EXCLUSION_SAMPLES;
        assert!(!cost_changed_significantly(&emitter, &changed, &cfg));
    }

    #[test]
    fn tiny_effective_loss_movement_below_loss_delta_does_not_emit() {
        let cfg = OverlayConfig::new(vec![]);
        let emitter = test_emitter();
        let mut base = one_neighbor();
        base.loss_ppm = 0;
        base.loss_sample_count = MIN_ROUTE_LOSS_EXCLUSION_SAMPLES;
        let base = vec![base];
        record_published(&emitter, &base, &cfg);

        let mut changed = base.clone();
        changed[0].loss_ppm = 1;
        assert!(!cost_changed_significantly(&emitter, &changed, &cfg));
    }

    #[test]
    fn udp_voice_loss_bucket_triggers_urgent_gate_only() {
        let cfg = OverlayConfig::new(vec![]);
        let emitter = test_emitter();
        let mut base = one_neighbor();
        base.transport_metrics = vec![NeighborTransportMetric::new(
            shitspeak_s2s_transport::TransportKind::Udp,
            1_000,
            0,
            0,
            MIN_ROUTE_LOSS_EXCLUSION_SAMPLES,
        )];
        let base = vec![base];
        record_published(&emitter, &base, &cfg);

        let mut changed = base.clone();
        changed[0].transport_metrics = vec![NeighborTransportMetric::new(
            shitspeak_s2s_transport::TransportKind::Udp,
            1_000,
            0,
            10_000,
            MIN_ROUTE_LOSS_EXCLUSION_SAMPLES,
        )];

        assert!(voice_cost_changed_significantly(&emitter, &changed, &cfg));
        assert!(!cost_changed_significantly(&emitter, &changed, &cfg));
    }

    #[test]
    fn raw_loss_breakdown_and_sample_count_inside_confidence_class_do_not_emit() {
        let cfg = OverlayConfig::new(vec![]);
        let emitter = test_emitter();
        let mut base = one_neighbor();
        base.loss_ppm = 101_000;
        base.loss_sample_count = 0;
        let base = vec![base];
        record_published(&emitter, &base, &cfg);

        let mut changed = base.clone();
        changed[0].loss_sample_count = MIN_ROUTE_LOSS_EXCLUSION_SAMPLES - 1;
        assert!(!cost_changed_significantly(&emitter, &changed, &cfg));

        let emitter = test_emitter();
        let mut base = one_neighbor();
        base.loss_ppm = 101_000;
        base.probe_loss_ppm = 10_000;
        base.native_loss_ppm = 20_000;
        base.data_health_ppm = 30_000;
        base.loss_sample_count = MIN_ROUTE_LOSS_EXCLUSION_SAMPLES;
        let base = vec![base];
        record_published(&emitter, &base, &cfg);

        let mut changed = base.clone();
        changed[0].probe_loss_ppm = 300_000;
        changed[0].native_loss_ppm = 400_000;
        changed[0].data_health_ppm = 500_000;
        changed[0].loss_sample_count = MIN_ROUTE_LOSS_EXCLUSION_SAMPLES + 64;
        assert!(!cost_changed_significantly(&emitter, &changed, &cfg));
    }

    #[test]
    fn transport_mask_and_neighbor_set_changes_emit_immediately() {
        let cfg = OverlayConfig::new(vec![]);
        let emitter = test_emitter();
        let base = snap(&[2]);
        record_published(&emitter, &base, &cfg);

        let mut changed = base.clone();
        changed[0].transports_mask = 0b11;
        assert!(cost_changed_significantly(&emitter, &changed, &cfg));
        assert!(cost_changed_significantly(&emitter, &[], &cfg));
    }

    #[test]
    fn mask_churn_is_held_unless_service_eligibility_changes() {
        use crate::overlay::config::transport_bit;
        use shitspeak_s2s_transport::TransportKind;

        let cfg = OverlayConfig::new(vec![]);
        let emitter = test_emitter();
        let mut base = one_neighbor();
        base.transports_mask = transport_bit(TransportKind::Tcp);
        let base = vec![base];
        record_published(&emitter, &base, &cfg);

        let mut still_eligible = base.clone();
        still_eligible[0].transports_mask |= transport_bit(TransportKind::Udp);
        assert_eq!(
            classify_local_change(&emitter, &still_eligible, &cfg),
            LocalChange::Metric
        );

        let mut loses_reliable = base.clone();
        loses_reliable[0].transports_mask = transport_bit(TransportKind::Udp);
        assert_eq!(
            classify_local_change(&emitter, &loses_reliable, &cfg),
            LocalChange::Structural
        );

        let mut loses_all = base.clone();
        loses_all[0].transports_mask = 0;
        assert_eq!(
            classify_local_change(&emitter, &loses_all, &cfg),
            LocalChange::Structural
        );
    }

    #[test]
    fn stable_service_mask_churn_preserves_distribution_epoch_and_routes() {
        const MASK_SEQUENCE: [u32; 4] = [15, 13, 5, 15];

        let cfg = OverlayConfig::new(vec![]);
        let emitter = test_emitter();
        let db = LinkStateDb::new(Arc::new(super::super::store::LsaFloor::new(0, None)));
        let mut neighbor = one_neighbor();
        neighbor.transports_mask = MASK_SEQUENCE[0];
        let mut snapshot = vec![neighbor];

        let initial = build_local_lsa(&emitter, &snapshot, false);
        assert_eq!(db.admit(initial), AdmissionResult::Accepted);
        assert_eq!(
            db.admit(LsaEntry {
                origin: 2,
                boot_epoch: 200,
                seq: 1,
                ts_local_received: Instant::now(),
                tombstone: false,
                addresses: vec![],
                links: vec![],
                max_users: 10,
                transit_disabled: false,
                replication_services: ReplicationServices::ALL,
                application_services: ApplicationServices::ALL,
            }),
            AdmissionResult::Accepted
        );
        record_published(&emitter, &snapshot, &cfg);

        let structural_epoch = db.distribution_epoch();
        for (index, mask) in MASK_SEQUENCE.into_iter().enumerate().skip(1) {
            snapshot[0].transports_mask = mask;
            let change = classify_local_change(&emitter, &snapshot, &cfg);
            assert_ne!(
                change,
                LocalChange::Structural,
                "eligibility-preserving mask transition at sequence index {index}"
            );
            if index < MASK_SEQUENCE.len() - 1 {
                assert_eq!(change, LocalChange::Metric);
            } else {
                assert_eq!(change, LocalChange::Unchanged);
            }

            // Synthetic link-state injection follows the same construction and
            // admission path as the emitter, then exercises routing over the
            // accepted LSDB snapshot without waiting for EWMA sampling.
            let lsa = build_local_lsa(&emitter, &snapshot, false);
            assert_eq!(db.admit(lsa), AdmissionResult::Accepted);
            assert_eq!(db.distribution_epoch(), structural_epoch);

            let routes = dijkstra::compute(&db, 1, ServiceLevel::Reliable, &cfg);
            assert_eq!(routes.get(&2).map(|route| route.next_hop), Some(2));
        }
    }

    #[test]
    fn excessive_loss_eligibility_crossing_is_structural() {
        let cfg = OverlayConfig::new(vec![]);
        let emitter = test_emitter();
        let mut base = one_neighbor();
        base.loss_ppm = 100_000;
        base.loss_sample_count = MIN_ROUTE_LOSS_EXCLUSION_SAMPLES;
        let base = vec![base];
        record_published(&emitter, &base, &cfg);

        let mut changed = base.clone();
        changed[0].loss_ppm = cfg.max_route_packet_loss_ppm();
        assert_eq!(
            classify_local_change(&emitter, &changed, &cfg),
            LocalChange::Structural
        );
    }

    #[test]
    fn metric_candidate_obeys_stability_hold_and_minimum_emit_interval() {
        let cfg = OverlayConfig::new(vec![])
            .with_lsa_metric_hold(Duration::from_secs(5))
            .with_lsa_metric_min_emit_interval(Duration::from_secs(5));
        let emitter = test_emitter();
        let now = Instant::now();
        let first = ContentFingerprint {
            identity: 1,
            gate: 10,
        };
        let second = ContentFingerprint {
            identity: 1,
            gate: 20,
        };
        *emitter.last_emitted_content.lock() = Some((first, now));

        let mut pending = None;
        PendingMetricChange::observe(&mut pending, first, now);
        assert_eq!(
            pending.unwrap().deadline(&emitter, &cfg),
            now + Duration::from_secs(5)
        );

        PendingMetricChange::observe(&mut pending, second, now + Duration::from_secs(4));
        assert_eq!(
            pending.unwrap().deadline(&emitter, &cfg),
            now + Duration::from_secs(9)
        );

        *emitter.last_emitted_content.lock() = Some((first, now + Duration::from_secs(7)));
        assert_eq!(
            pending.unwrap().deadline(&emitter, &cfg),
            now + Duration::from_secs(12)
        );
    }

    #[test]
    fn metric_stabilization_defaults_to_five_seconds() {
        let cfg = OverlayConfig::new(vec![]);
        assert_eq!(cfg.lsa_metric_hold(), Duration::from_secs(5));
        assert_eq!(cfg.lsa_metric_min_emit_interval(), Duration::from_secs(5));
    }

    #[test]
    fn refresh_reduction_suppresses_unchanged_periodic_lsa() {
        let max_users = Arc::new(AtomicU64::new(10));
        let emitter = LsaEmitter::new(
            1,
            100,
            vec![],
            max_users.clone(),
            true,
            ReplicationServices::ALL,
            ApplicationServices::ALL,
        );
        let cfg = OverlayConfig::new(vec![])
            .with_lsa_max_age(Duration::from_secs(120))
            .with_lsa_unchanged_refresh_interval(Duration::from_secs(90));

        let content = build_local_lsa_content(&emitter, &[], false);
        let fingerprint = content_fingerprint(&content, &cfg);
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
        let changed_fingerprint = content_fingerprint(&changed, &cfg);
        assert!(should_emit_content(
            &emitter,
            changed_fingerprint,
            EmitReason::Periodic,
            &cfg
        ));
    }

    #[test]
    fn unchanged_refresh_deadline_leaves_room_before_lsa_expiry() {
        let cfg = OverlayConfig::new(vec![])
            .with_lsa_max_age(Duration::from_secs(5))
            .with_lsa_unchanged_refresh_interval(Duration::from_secs(90));

        assert_eq!(unchanged_refresh_deadline(&cfg), Duration::from_secs(5) / 3);
    }

    #[test]
    fn refresh_reduction_uses_rounded_gate_fingerprint() {
        let cfg = OverlayConfig::new(vec![])
            .with_lsa_max_age(Duration::from_secs(120))
            .with_lsa_unchanged_refresh_interval(Duration::from_secs(90));
        let emitter = test_emitter();
        let mut base = one_neighbor();
        base.rtt_us = 101_000;
        base.jitter_us = 11_000;
        base.loss_ppm = 101_000;
        base.loss_sample_count = MIN_ROUTE_LOSS_EXCLUSION_SAMPLES;
        let base = vec![base];

        let content = build_local_lsa_content(&emitter, &base, false);
        let fingerprint = content_fingerprint(&content, &cfg);
        record_emitted_content(&emitter, fingerprint);

        let mut changed = base.clone();
        changed[0].rtt_us = 124_000;
        changed[0].jitter_us = 19_000;
        changed[0].loss_ppm = 149_000;
        changed[0].probe_loss_ppm = 900_000;
        changed[0].native_loss_ppm = 900_000;
        changed[0].data_health_ppm = 900_000;
        changed[0].loss_sample_count = MIN_ROUTE_LOSS_EXCLUSION_SAMPLES + 16;
        let changed_content = build_local_lsa_content(&emitter, &changed, false);
        let changed_fingerprint = content_fingerprint(&changed_content, &cfg);

        assert_eq!(fingerprint.gate, changed_fingerprint.gate);
        assert_eq!(fingerprint.identity, changed_fingerprint.identity);
        assert!(!should_emit_content(
            &emitter,
            changed_fingerprint,
            EmitReason::Periodic,
            &cfg
        ));
    }

    #[test]
    fn refresh_reduction_suppresses_sub_threshold_metric_gate_movement() {
        let cfg = OverlayConfig::new(vec![])
            .with_lsa_max_age(Duration::from_secs(120))
            .with_lsa_unchanged_refresh_interval(Duration::from_secs(90));
        let emitter = test_emitter();
        let mut base = one_neighbor();
        base.rtt_us = 76_000;
        let base = vec![base];
        record_published(&emitter, &base, &cfg);

        let content = build_local_lsa_content(&emitter, &base, false);
        let fingerprint = content_fingerprint(&content, &cfg);
        record_emitted_content(&emitter, fingerprint);

        let mut changed = base.clone();
        changed[0].rtt_us = 101_000;
        let changed_content = build_local_lsa_content(&emitter, &changed, false);
        let changed_fingerprint = content_fingerprint(&changed_content, &cfg);

        assert_ne!(fingerprint.gate, changed_fingerprint.gate);
        assert_eq!(fingerprint.identity, changed_fingerprint.identity);
        assert!(!cost_changed_significantly(&emitter, &changed, &cfg));
        assert!(!should_emit_content(
            &emitter,
            changed_fingerprint,
            EmitReason::Periodic,
            &cfg
        ));
    }
}
