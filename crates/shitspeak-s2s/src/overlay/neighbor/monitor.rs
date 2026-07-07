//! Direct-neighbor table.
//!
//! Tracks every peer with a live L1 stream — these are the *direct
//! neighbors* whose edges feed into our locally-emitted LSA. State per
//! neighbor:
//!   * `boot_epoch` — last observed via Hello/HelloAck.
//!   * `miss_count` — consecutive stale Hello windows; once it crosses
//!     `hello_dead_interval / hello_interval`, the link is declared down.
//!   * `is_up` — whether we currently include this neighbor in our LSA.
//!
//! The monitor exposes a `snapshot()` that returns one
//! `NeighborSnapshot` per `is_up` neighbor with its current cost
//! readings (RTT / jitter / throughput / transports). This snapshot is
//! what `lsdb::advert::build_local_lsa` reads to construct each LSA.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::{Notify, broadcast};
use tracing::debug;

use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{ConnectionManager, TransportKind};

use super::super::config::OverlayConfig;
use super::super::config::kind_to_idx;
use super::super::duplicate::DuplicateDetector;
use super::super::membership::MembershipEvent;
use super::super::proto::transports_to_mask;
use super::super::routing::dijkstra::MIN_ROUTE_LOSS_EXCLUSION_SAMPLES;

/// Snapshot suitable for embedding as a `LinkAdvert` in an outbound LSA.
#[derive(Clone, Debug)]
pub struct NeighborSnapshot {
    pub node_id: NodeIdentifier,
    pub rtt_us: u64,
    pub jitter_us: u64,
    pub throughput_bps: u64,
    pub observed_recv_bps: u64,
    pub observed_sent_bps: u64,
    pub throughput_confidence_ppm: u32,
    pub transports_mask: u32,
    pub loss_ppm: u32,
    pub probe_loss_ppm: u32,
    pub native_loss_ppm: u32,
    pub data_health_ppm: u32,
    pub loss_sample_count: u64,
    pub transport_metrics: Vec<NeighborTransportMetric>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeighborTransportMetric {
    transport: TransportKind,
    rtt_us: u64,
    jitter_us: u64,
    loss_ppm: u32,
    loss_sample_count: u64,
}

impl NeighborTransportMetric {
    pub fn new(
        transport: TransportKind,
        rtt_us: u64,
        jitter_us: u64,
        loss_ppm: u32,
        loss_sample_count: u64,
    ) -> Self {
        Self {
            transport,
            rtt_us,
            jitter_us,
            loss_ppm,
            loss_sample_count,
        }
    }

    pub fn transport(self) -> TransportKind {
        self.transport
    }

    pub fn rtt_us(self) -> u64 {
        self.rtt_us
    }

    pub fn jitter_us(self) -> u64 {
        self.jitter_us
    }

    pub fn loss_ppm(self) -> u32 {
        self.loss_ppm
    }

    pub fn loss_sample_count(self) -> u64 {
        self.loss_sample_count
    }
}

#[derive(Debug)]
struct NeighborState {
    boot_epoch: u64,
    last_ack_at: Option<Instant>,
    miss_count: u32,
    is_up: bool,
    transports_mask: u32,
    loss_samples: VecDeque<(Instant, bool)>,
    /// Pending pings by nonce -> when sent (for RTT calculation on ack).
    pending: HashMap<u64, Instant>,
}

impl NeighborState {
    fn new() -> Self {
        Self {
            boot_epoch: 0,
            last_ack_at: None,
            miss_count: 0,
            is_up: false,
            transports_mask: 0,
            loss_samples: VecDeque::new(),
            pending: HashMap::new(),
        }
    }

    fn reset_quality_samples(&mut self) {
        // Probes sent before a link is usable should not seed its route cost.
        self.loss_samples.clear();
        self.pending.clear();
    }
}

fn record_loss_sample(st: &mut NeighborState, now: Instant, window: Duration, lost: bool) {
    prune_loss_samples(st, now, window);
    st.loss_samples.push_back((now, lost));
}

fn prune_loss_samples(st: &mut NeighborState, now: Instant, window: Duration) {
    let cutoff = now.checked_sub(window).unwrap_or(now);
    while st
        .loss_samples
        .front()
        .is_some_and(|(sample_at, _)| *sample_at < cutoff)
    {
        st.loss_samples.pop_front();
    }
}

fn expire_pending(st: &mut NeighborState, now: Instant, window: Duration) -> usize {
    let cutoff = now.checked_sub(window).unwrap_or(now);
    let mut expired = 0;
    st.pending.retain(|_, sent| {
        let keep = *sent > cutoff;
        if !keep {
            expired += 1;
        }
        keep
    });
    expired
}

fn record_expired_pending(st: &mut NeighborState, now: Instant, window: Duration) -> usize {
    let expired = expire_pending(st, now, window);
    if st.is_up {
        for _ in 0..expired {
            record_loss_sample(st, now, window, true);
        }
        expired
    } else {
        0
    }
}

fn missed_hello_window_threshold(cfg: &OverlayConfig) -> u32 {
    let interval = cfg.hello_interval().as_nanos().max(1);
    let dead = cfg.hello_dead_interval().as_nanos();
    let threshold = dead.saturating_add(interval - 1) / interval;
    threshold.clamp(1, u32::MAX as u128) as u32
}

fn note_stale_hello_window(st: &mut NeighborState, threshold: u32) -> bool {
    st.miss_count = st.miss_count.saturating_add(1);
    st.miss_count >= threshold.max(1)
}

fn packet_loss_snapshot(st: &mut NeighborState, now: Instant, window: Duration) -> (u32, u64, u64) {
    prune_loss_samples(st, now, window);
    let total = st.loss_samples.len();
    if total == 0 {
        return (0, 0, 0);
    }
    let lost = st
        .loss_samples
        .iter()
        .filter(|(_, sample_lost)| *sample_lost)
        .count();
    let ppm = ((lost as f64 / total as f64) * 1_000_000.0)
        .round()
        .clamp(0.0, 1_000_000.0) as u32;
    (ppm, total as u64, lost as u64)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectiveLossCandidate {
    transport: TransportKind,
    loss_ppm: u32,
    sample_count: u64,
}

fn consider_loss_candidate(
    best: &mut Option<EffectiveLossCandidate>,
    candidate: EffectiveLossCandidate,
) {
    if candidate.sample_count == 0 && candidate.loss_ppm == 0 {
        return;
    }
    let replace = best.is_none_or(|current| {
        let candidate_confident = candidate.sample_count >= MIN_ROUTE_LOSS_EXCLUSION_SAMPLES;
        let current_confident = current.sample_count >= MIN_ROUTE_LOSS_EXCLUSION_SAMPLES;
        (candidate_confident && !current_confident)
            || (candidate_confident == current_confident
                && (candidate.loss_ppm < current.loss_ppm
                    || (candidate.loss_ppm == current.loss_ppm
                        && candidate.sample_count > current.sample_count)))
    });
    if replace {
        *best = Some(candidate);
    }
}

fn selected_edge_loss(
    hello_loss_ppm: u32,
    hello_loss_samples: u64,
    best_reliable: Option<EffectiveLossCandidate>,
    best_any: Option<EffectiveLossCandidate>,
) -> (u32, u64) {
    // Routing can choose among live transports for a next hop. A single bad
    // UDP/KCP/TCP/QUIC session should not rewrite the whole edge when another
    // usable transport to the same peer is healthier.
    best_reliable
        .or(best_any)
        .map(|candidate| (candidate.loss_ppm, candidate.sample_count))
        .unwrap_or((hello_loss_ppm, hello_loss_samples))
}

/// Direct-neighbor table.
pub struct NeighborMonitor {
    self_id: NodeIdentifier,
    transport: ConnectionManager,
    duplicate_detector: Arc<DuplicateDetector>,
    cfg: OverlayConfig,
    state: Mutex<HashMap<NodeIdentifier, NeighborState>>,
    /// Notified whenever a neighbor goes up/down or boot_epoch changes.
    /// Wakes the LSA emitter and the LSDB sync trigger.
    on_change: Arc<Notify>,
    /// Notified when only volatile quality metrics changed.
    on_metric_change: Arc<Notify>,
    /// To emit `Restarted` events directly on Hello-driven boot_epoch
    /// increase (faster than waiting for the LSA).
    membership_events: broadcast::Sender<MembershipEvent>,
    /// Emits the peer id after a "link up" so the runtime can schedule a
    /// targeted `LsdbSync` pull/push repair for that peer.
    link_up_events: broadcast::Sender<NodeIdentifier>,
}

impl NeighborMonitor {
    pub fn new(
        self_id: NodeIdentifier,
        transport: ConnectionManager,
        duplicate_detector: Arc<DuplicateDetector>,
        cfg: OverlayConfig,
        membership_events: broadcast::Sender<MembershipEvent>,
    ) -> Self {
        Self {
            self_id,
            transport,
            duplicate_detector,
            cfg,
            state: Mutex::new(HashMap::new()),
            on_change: Arc::new(Notify::new()),
            on_metric_change: Arc::new(Notify::new()),
            membership_events,
            link_up_events: broadcast::channel(256).0,
        }
    }

    pub fn on_change(&self) -> Arc<Notify> {
        self.on_change.clone()
    }

    pub fn on_metric_change(&self) -> Arc<Notify> {
        self.on_metric_change.clone()
    }

    pub fn subscribe_link_up(&self) -> broadcast::Receiver<NodeIdentifier> {
        self.link_up_events.subscribe()
    }

    /// Build a snapshot of every currently-up neighbor with live cost
    /// metrics drawn from `metrics_snapshot()`.
    pub fn snapshot(&self) -> Vec<NeighborSnapshot> {
        let metrics = self.transport.metrics_snapshot();
        let now = Instant::now();
        let loss_window = self.cfg.hello_dead_interval();
        let mut g = self.state.lock();
        let mut out = Vec::with_capacity(g.len());
        for (nid, st) in g.iter_mut() {
            if !st.is_up {
                continue;
            }
            let (hello_loss_ppm, hello_loss_samples, _) =
                packet_loss_snapshot(st, now, loss_window);
            let mut probe_loss_ppm = hello_loss_ppm;
            let mut native_loss_ppm = 0;
            let mut data_health_ppm = 0;
            let mut loss_ppm = hello_loss_ppm;
            let mut loss_sample_count = hello_loss_samples;
            let mut best_reliable_loss = None;
            let mut best_any_loss = None;
            let mut transport_metrics = Vec::new();
            let kinds = self.transport.live_transport_kinds(*nid);
            let (
                rtt_us,
                jitter_us,
                observed_recv_bps,
                observed_sent_bps,
                throughput_confidence_ppm,
            ) = match metrics.for_node(*nid) {
                Some(per_t) => {
                    let mut best_rtt: Option<f64> = None;
                    let mut best_jitter: Option<f64> = None;
                    let mut total_recv_bps: f64 = 0.0;
                    let mut total_sent_bps: f64 = 0.0;
                    let mut confidence_ppm: u32 = 0;
                    for (k, m) in per_t {
                        if !kinds.contains(k) {
                            continue;
                        }
                        transport_metrics.push(NeighborTransportMetric::new(
                            *k,
                            m.rtt_us().max(0.0) as u64,
                            m.jitter_us().max(0.0) as u64,
                            m.effective_packet_loss_ppm(),
                            m.loss_sample_count(),
                        ));
                        probe_loss_ppm = probe_loss_ppm.max(m.probe_loss_ppm());
                        native_loss_ppm = native_loss_ppm.max(m.native_loss_ppm());
                        data_health_ppm = data_health_ppm.max(m.data_health_ppm());
                        let candidate = EffectiveLossCandidate {
                            transport: *k,
                            loss_ppm: m.effective_packet_loss_ppm(),
                            sample_count: m.loss_sample_count(),
                        };
                        consider_loss_candidate(&mut best_any_loss, candidate);
                        if *k != TransportKind::Udp {
                            consider_loss_candidate(&mut best_reliable_loss, candidate);
                        }
                        if m.rtt_us() > 0.0 {
                            best_rtt = Some(match best_rtt {
                                Some(prev) => prev.min(m.rtt_us()),
                                None => m.rtt_us(),
                            });
                            best_jitter = Some(match best_jitter {
                                Some(prev) => prev.min(m.jitter_us()),
                                None => m.jitter_us(),
                            });
                        }
                        total_recv_bps += m.observed_recv_bps();
                        total_sent_bps += m.observed_sent_bps();
                        confidence_ppm = confidence_ppm.max(m.throughput_confidence_ppm());
                    }
                    (loss_ppm, loss_sample_count) = selected_edge_loss(
                        hello_loss_ppm,
                        hello_loss_samples,
                        best_reliable_loss,
                        best_any_loss,
                    );
                    (
                        best_rtt.unwrap_or(0.0) as u64,
                        best_jitter.unwrap_or(0.0) as u64,
                        total_recv_bps as u64,
                        total_sent_bps as u64,
                        confidence_ppm,
                    )
                }
                None => (0, 0, 0, 0, 0),
            };
            transport_metrics.sort_by_key(|metric| kind_to_idx(metric.transport()));
            let throughput_bps = observed_recv_bps.max(observed_sent_bps);
            let transports_mask = transports_to_mask(&kinds);
            st.transports_mask = transports_mask;
            out.push(NeighborSnapshot {
                node_id: *nid,
                rtt_us,
                jitter_us,
                throughput_bps,
                observed_recv_bps,
                observed_sent_bps,
                throughput_confidence_ppm,
                transports_mask,
                loss_ppm,
                probe_loss_ppm,
                native_loss_ppm,
                data_health_ppm,
                loss_sample_count,
                transport_metrics,
            });
        }
        out.sort_by_key(|n| n.node_id);
        out
    }

    /// True if `node` is currently considered a direct neighbor.
    pub fn is_up(&self, node: NodeIdentifier) -> bool {
        self.state
            .lock()
            .get(&node)
            .map(|s| s.is_up)
            .unwrap_or(false)
    }

    /// Record an outbound Hello so we can match its ack later.
    pub fn record_outbound_ping(&self, dst: NodeIdentifier, nonce: u64) {
        let now = Instant::now();
        let mut g = self.state.lock();
        let st = g.entry(dst).or_insert_with(NeighborState::new);
        let expired = record_expired_pending(st, now, self.cfg.hello_dead_interval());
        if expired > 0 {
            self.on_metric_change.notify_one();
        }
        st.pending.insert(nonce, now);
    }

    /// Caller: inbound dispatcher when a `Hello` arrives. Updates
    /// boot_epoch tracking and returns `Restarted` if this is a higher
    /// boot_epoch than we'd seen for `from`.
    pub fn record_hello(&self, from: NodeIdentifier, boot_epoch: u64) {
        let (became_up, restarted) = {
            let mut g = self.state.lock();
            let st = g.entry(from).or_insert_with(NeighborState::new);
            let was_up = st.is_up;
            let prev_be = st.boot_epoch;
            let mut restarted = false;
            if boot_epoch > prev_be {
                st.boot_epoch = boot_epoch;
                // Only emit Restarted if we'd seen a *previous* epoch (>0).
                // First-ever boot_epoch is just initial state.
                if prev_be > 0 {
                    restarted = true;
                    let _ = self
                        .membership_events
                        .send(MembershipEvent::Restarted(from));
                    debug!(peer=%from, new_epoch=boot_epoch, "neighbor restart detected via hello");
                }
            }
            st.last_ack_at = Some(Instant::now());
            st.miss_count = 0;
            st.is_up = true;
            if !was_up || restarted {
                st.reset_quality_samples();
            }
            (!was_up, restarted)
        };
        if became_up {
            debug!(peer=%from, "direct link up");
            self.on_change.notify_one();
            let _ = self.link_up_events.send(from);
        } else if restarted {
            self.on_change.notify_one();
        }
    }

    /// Caller: inbound dispatcher when a `HelloAck` arrives. Records RTT
    /// (against the matched nonce), updates miss_count, and tracks
    /// boot_epoch.
    pub fn record_hello_ack(
        &self,
        from: NodeIdentifier,
        boot_epoch: u64,
        nonce: u64,
        _ts_send_us: u64,
        peer_metrics_target: Option<TransportKind>,
    ) {
        let now = Instant::now();
        let (was_up, sent_at_instant, restarted) = {
            let mut g = self.state.lock();
            let st = g.entry(from).or_insert_with(NeighborState::new);
            let was_up = st.is_up;
            let prev_be = st.boot_epoch;
            let mut restarted = false;
            if boot_epoch > prev_be {
                st.boot_epoch = boot_epoch;
                if prev_be > 0 {
                    restarted = true;
                    let _ = self
                        .membership_events
                        .send(MembershipEvent::Restarted(from));
                }
            }
            st.last_ack_at = Some(now);
            st.miss_count = 0;
            // RTT calc — prefer the recorded ts_send (echoed) over our own
            // pending table since either is a valid round-trip measurement.
            let sent_at_instant: Option<Instant> = st.pending.remove(&nonce);
            if !was_up || restarted {
                st.reset_quality_samples();
            }
            if sent_at_instant.is_some() {
                record_loss_sample(st, now, self.cfg.hello_dead_interval(), false);
            }
            st.is_up = true;
            // Cap pending table size — drop stale entries occasionally.
            if st.pending.len() > 32 {
                let cutoff = now - Duration::from_secs(60);
                st.pending.retain(|_, t| *t > cutoff);
            }
            (was_up, sent_at_instant, restarted)
        };
        let matched_ack = sent_at_instant.is_some();
        let rtt = sent_at_instant.map(|t| now.saturating_duration_since(t));
        let kind = peer_metrics_target.unwrap_or(TransportKind::Tcp);
        if let Some(rtt) = rtt {
            self.transport.record_peer_rtt(from, kind, rtt);
        }
        let became_up = !was_up;
        if became_up {
            debug!(peer=%from, ?rtt, "direct link up");
            self.on_change.notify_one();
            let _ = self.link_up_events.send(from);
        } else if restarted {
            self.on_change.notify_one();
        } else if matched_ack {
            self.on_metric_change.notify_one();
        }
    }

    /// Sweep neighbors on a tick. For each peer with a live L1 stream:
    ///   * if `last_ack_at` is older than `hello_dead_interval`, increment
    ///     `miss_count`. Once miss_count crosses the dead threshold, drop
    ///     the link from the LSA.
    /// For peers no longer in L1's live set, mark down.
    pub fn sweep_and_collect_targets(&self) -> Vec<(NodeIdentifier, Vec<TransportKind>)> {
        let live_peers = self.live_peers();
        let live_ids: HashSet<NodeIdentifier> = live_peers.iter().map(|(n, _)| *n).collect();
        let live_masks: HashMap<NodeIdentifier, u32> = live_peers
            .iter()
            .map(|(n, kinds)| (*n, transports_to_mask(kinds)))
            .collect();
        let now = Instant::now();
        let dead = self.cfg.hello_dead_interval();
        let missed_threshold = missed_hello_window_threshold(&self.cfg);
        let (transitions, mask_changes) = {
            let mut g = self.state.lock();
            let mut transitions = Vec::new();
            let mut mask_changes = Vec::new();

            // Sweep existing entries.
            let mut to_remove: Vec<NodeIdentifier> = Vec::new();
            for (nid, st) in g.iter_mut() {
                if !live_ids.contains(nid) {
                    if st.is_up {
                        st.is_up = false;
                        st.miss_count = 0;
                        st.transports_mask = 0;
                        transitions.push((*nid, false));
                    }
                    // L1 also dropped; eventually purge.
                    if st
                        .last_ack_at
                        .map_or(true, |t| now.duration_since(t) > dead * 4)
                    {
                        to_remove.push(*nid);
                    }
                    continue;
                }
                let current_mask = live_masks.get(nid).copied().unwrap_or(0);
                if st.is_up && st.transports_mask != current_mask {
                    st.transports_mask = current_mask;
                    mask_changes.push((*nid, current_mask));
                } else if !st.is_up {
                    st.transports_mask = current_mask;
                }
                if let Some(last) = st.last_ack_at {
                    if now.duration_since(last) >= dead {
                        record_expired_pending(st, now, dead);
                        if st.is_up && note_stale_hello_window(st, missed_threshold) {
                            st.is_up = false;
                            st.miss_count = 0;
                            st.transports_mask = 0;
                            transitions.push((*nid, false));
                        }
                    } else {
                        st.miss_count = 0;
                    }
                }
            }
            for n in to_remove {
                g.remove(&n);
            }
            (transitions, mask_changes)
        };

        for (n, _) in &transitions {
            debug!(peer=%n, "direct link down (hello dead-interval)");
        }
        for (n, mask) in &mask_changes {
            debug!(peer=%n, transports_mask=*mask, "direct link transport set changed");
        }
        if !transitions.is_empty() || !mask_changes.is_empty() {
            self.on_change.notify_one();
        }
        live_peers
    }

    /// Direct neighbor enumeration: every peer in the L1 manager with
    /// `has_any_live_stream`.
    fn live_peers(&self) -> Vec<(NodeIdentifier, Vec<TransportKind>)> {
        let mut out = Vec::new();
        for (nid, kinds) in self.transport.live_peers() {
            if nid == self.self_id {
                continue;
            }
            if self.duplicate_detector.is_quarantined(nid) {
                continue;
            }
            out.push((nid, kinds));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(
        transport: TransportKind,
        loss_ppm: u32,
        sample_count: u64,
    ) -> EffectiveLossCandidate {
        EffectiveLossCandidate {
            transport,
            loss_ppm,
            sample_count,
        }
    }

    #[test]
    fn selected_edge_loss_prefers_best_reliable_transport_over_bad_udp() {
        let mut best_any = None;
        let mut best_reliable = None;
        for candidate in [
            candidate(TransportKind::Udp, 500_000, 128),
            candidate(TransportKind::Tcp, 50_000, 96),
            candidate(TransportKind::Quic, 200_000, 256),
        ] {
            consider_loss_candidate(&mut best_any, candidate);
            if candidate.transport != TransportKind::Udp {
                consider_loss_candidate(&mut best_reliable, candidate);
            }
        }

        assert_eq!(
            selected_edge_loss(0, 0, best_reliable, best_any),
            (50_000, 96)
        );
    }

    #[test]
    fn selected_edge_loss_ignores_unsampled_zero_candidate() {
        let mut best_any = None;
        let mut best_reliable = None;
        for candidate in [
            candidate(TransportKind::Tcp, 0, 0),
            candidate(TransportKind::Kcp, 200_000, 64),
        ] {
            consider_loss_candidate(&mut best_any, candidate);
            if candidate.transport != TransportKind::Udp {
                consider_loss_candidate(&mut best_reliable, candidate);
            }
        }

        assert_eq!(
            selected_edge_loss(0, 0, best_reliable, best_any),
            (200_000, 64)
        );
    }

    #[test]
    fn selected_edge_loss_prefers_confident_reliable_candidate() {
        let mut best_any = None;
        let mut best_reliable = None;
        for candidate in [
            candidate(TransportKind::Tcp, 50_000, MIN_ROUTE_LOSS_EXCLUSION_SAMPLES),
            candidate(TransportKind::Quic, 0, MIN_ROUTE_LOSS_EXCLUSION_SAMPLES - 1),
        ] {
            consider_loss_candidate(&mut best_any, candidate);
            if candidate.transport != TransportKind::Udp {
                consider_loss_candidate(&mut best_reliable, candidate);
            }
        }

        assert_eq!(
            selected_edge_loss(0, 0, best_reliable, best_any),
            (50_000, MIN_ROUTE_LOSS_EXCLUSION_SAMPLES)
        );
    }

    #[test]
    fn selected_edge_loss_falls_back_to_udp_when_no_reliable_transport_is_sampled() {
        let mut best_any = None;
        let best_reliable = None;
        consider_loss_candidate(&mut best_any, candidate(TransportKind::Udp, 250_000, 40));

        assert_eq!(
            selected_edge_loss(0, 0, best_reliable, best_any),
            (250_000, 40)
        );
    }

    #[test]
    fn selected_edge_loss_falls_back_to_hello_when_no_transport_is_sampled() {
        assert_eq!(selected_edge_loss(333_333, 4, None, None), (333_333, 4));
    }

    #[test]
    fn missed_hello_window_threshold_ceilings_dead_over_interval() {
        let cfg = OverlayConfig::new(Vec::new())
            .with_hello_interval(Duration::from_millis(250))
            .with_hello_dead_interval(Duration::from_secs(1));
        assert_eq!(missed_hello_window_threshold(&cfg), 4);

        let cfg = OverlayConfig::new(Vec::new())
            .with_hello_interval(Duration::from_millis(300))
            .with_hello_dead_interval(Duration::from_secs(1));
        assert_eq!(missed_hello_window_threshold(&cfg), 4);
    }

    #[test]
    fn stale_hello_windows_require_threshold_before_down() {
        let mut state = NeighborState::new();
        state.is_up = true;

        assert!(!note_stale_hello_window(&mut state, 3));
        assert_eq!(state.miss_count, 1);
        assert!(!note_stale_hello_window(&mut state, 3));
        assert_eq!(state.miss_count, 2);
        assert!(note_stale_hello_window(&mut state, 3));
        assert_eq!(state.miss_count, 3);
    }
}
