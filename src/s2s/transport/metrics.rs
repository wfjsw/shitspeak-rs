//! Per-link telemetry: EWMA latency + RFC-3550-style jitter, packet loss, and
//! a sliding bandwidth meter. Aggregated per `(node, ServiceLevel)` so callers
//! can score path quality among co-existing transports.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::types::NodeIdentifier;

use super::service_level::{RoutingMetric, ServiceLevel, ServiceShape, TransportKind};

const E_MODEL_R0: f64 = 93.2;
const E_MODEL_DELAY_KNEE_MS: f64 = 177.3;
const E_MODEL_JITTER_BUFFER_FLOOR_MS: f64 = 20.0;
const E_MODEL_JITTER_BUFFER_MULTIPLIER: f64 = 4.0;
const E_MODEL_JITTER_IMPAIRMENT_FREE_MS: f64 = 5.0;
const E_MODEL_JITTER_IMPAIRMENT_PER_MS: f64 = 0.12;
const E_MODEL_PACKET_LOSS_ROBUSTNESS: f64 = 20.0;
const E_MODEL_BURST_RATIO: f64 = 1.0;
const E_MODEL_REFERENCE_THROUGHPUT_BYTES_PER_SEC: f64 = 24_000.0;
const E_MODEL_THROUGHPUT_IMPAIRMENT_PER_LOG2: f64 = 4.0;
const E_MODEL_MAX_THROUGHPUT_IMPAIRMENT: f64 = 20.0;
const DEFAULT_RELIABLE_THROUGHPUT_PENALTY_US_KBPS: f64 = 1_000_000.0;
const DEFAULT_RLL_JITTER_WEIGHT: f64 = 4.0;
const MAX_PACKET_LOSS_PPM: u32 = 1_000_000;
const DEFAULT_PACKET_LOSS_EWMA_ALPHA: f64 = 0.02;
const PACKET_LOSS_EWMA_METRIC_WEIGHT: f64 = 0.25;

pub(crate) fn apply_packet_loss_penalty(cost: f64, packet_loss_ppm: u32) -> f64 {
    let success = 1.0 - (packet_loss_ppm.min(999_999) as f64 / MAX_PACKET_LOSS_PPM as f64);
    (cost / success.max(0.001)).max(1.0)
}

pub(crate) fn conversational_effective_delay_us(rtt_us: f64, jitter_us: f64) -> u64 {
    let one_way_ms = rtt_us.max(1.0) / 2_000.0;
    let jitter_ms = jitter_us.max(0.0) / 1_000.0;
    let jitter_buffer_ms =
        E_MODEL_JITTER_BUFFER_FLOOR_MS.max(jitter_ms * E_MODEL_JITTER_BUFFER_MULTIPLIER);
    ((one_way_ms + jitter_buffer_ms) * 1_000.0).ceil() as u64
}

pub(crate) fn conversational_impairment(
    rtt_us: f64,
    jitter_us: f64,
    throughput_bytes_per_sec: f64,
    packet_loss_ppm: u32,
) -> f64 {
    let delay_ms = conversational_effective_delay_us(rtt_us, jitter_us) as f64 / 1_000.0;
    let delay_impairment = 0.024 * delay_ms
        + if delay_ms > E_MODEL_DELAY_KNEE_MS {
            0.11 * (delay_ms - E_MODEL_DELAY_KNEE_MS)
        } else {
            0.0
        };

    let jitter_ms = jitter_us.max(0.0) / 1_000.0;
    let jitter_impairment = ((jitter_ms - E_MODEL_JITTER_IMPAIRMENT_FREE_MS).max(0.0)
        * E_MODEL_JITTER_IMPAIRMENT_PER_MS)
        .min(15.0);

    let loss_pct = (packet_loss_ppm as f64 / 10_000.0).clamp(0.0, 100.0);
    let loss_impairment = if loss_pct <= 0.0 {
        0.0
    } else {
        (95.0 * loss_pct * E_MODEL_BURST_RATIO) / (loss_pct + E_MODEL_PACKET_LOSS_ROBUSTNESS)
    };

    let throughput = throughput_bytes_per_sec.max(1.0);
    let throughput_impairment = if throughput >= E_MODEL_REFERENCE_THROUGHPUT_BYTES_PER_SEC {
        0.0
    } else {
        (E_MODEL_REFERENCE_THROUGHPUT_BYTES_PER_SEC / throughput).log2()
            * E_MODEL_THROUGHPUT_IMPAIRMENT_PER_LOG2
    }
    .clamp(0.0, E_MODEL_MAX_THROUGHPUT_IMPAIRMENT);

    delay_impairment + jitter_impairment + loss_impairment + throughput_impairment
}

pub(crate) fn conversational_quality_score(
    rtt_us: f64,
    jitter_us: f64,
    throughput_bytes_per_sec: f64,
    packet_loss_ppm: u32,
) -> f64 {
    (E_MODEL_R0
        - conversational_impairment(rtt_us, jitter_us, throughput_bytes_per_sec, packet_loss_ppm))
    .clamp(0.0, 100.0)
}

/// EWMA smoothing coefficients for [`PeerMetrics`]. Values are configured
/// in [`super::config::TransportConfig`]; the [`Default`] impl mirrors
/// the historical hard-coded constants.
#[derive(Debug, Clone, Copy)]
pub struct MetricsTuning {
    /// Smoothing coefficient for the latency EWMA.
    pub latency_alpha: f64,
    /// Smoothing coefficient for the jitter EWMA (RFC 3550 uses 1/16).
    pub jitter_alpha: f64,
    /// Smoothing coefficient for the active-probe throughput EWMA.
    pub throughput_alpha: f64,
    /// Smoothing coefficient for the long-term packet-loss EWMA.
    pub packet_loss_alpha: f64,
}

impl Default for MetricsTuning {
    fn default() -> Self {
        Self {
            latency_alpha: 0.2,
            jitter_alpha: 1.0 / 16.0,
            throughput_alpha: 0.3,
            packet_loss_alpha: DEFAULT_PACKET_LOSS_EWMA_ALPHA,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct LinkMetrics {
    /// Smoothed round-trip time in microseconds.
    rtt_us: f64,
    /// Smoothed |Δrtt| in microseconds (jitter).
    jitter_us: f64,
    /// Data payload bytes received since the window started.
    recv_bytes: u64,
    /// Data payload bytes sent since the window started.
    sent_bytes: u64,
    /// Encoded transport-frame bytes received since the window started.
    wire_recv_bytes: u64,
    /// Encoded transport-frame bytes sent since the window started.
    wire_sent_bytes: u64,
    /// The wall-clock window over which `recv_bytes` / `sent_bytes` apply.
    window: Duration,
    /// Packet loss over the rolling probe/keepalive window, parts per million.
    packet_loss_ppm: u32,
    /// Long-term EWMA packet loss estimate, parts per million.
    packet_loss_ewma_ppm: u32,
    probe_packets: u64,
    lost_probe_packets: u64,
    samples: u64,
    last_update: Option<Instant>,
    /// EWMA of service-shaped active probe goodput, in useful payload bytes/sec.
    service_probes: HashMap<ServiceShape, ServiceProbeMetrics>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ServiceProbeMetrics {
    goodput_bps: f64,
    samples: u64,
}

impl ServiceProbeMetrics {
    pub fn goodput_bps(&self) -> f64 {
        self.goodput_bps
    }

    pub fn samples(&self) -> u64 {
        self.samples
    }
}

impl LinkMetrics {
    pub fn rtt_us(&self) -> f64 {
        self.rtt_us
    }

    pub fn jitter_us(&self) -> f64 {
        self.jitter_us
    }

    pub fn recv_bytes(&self) -> u64 {
        self.recv_bytes
    }

    pub fn sent_bytes(&self) -> u64 {
        self.sent_bytes
    }

    pub fn wire_recv_bytes(&self) -> u64 {
        self.wire_recv_bytes
    }

    pub fn wire_sent_bytes(&self) -> u64 {
        self.wire_sent_bytes
    }

    pub fn window(&self) -> Duration {
        self.window
    }

    pub fn packet_loss_ppm(&self) -> u32 {
        self.packet_loss_ppm
    }

    pub fn packet_loss_ewma_ppm(&self) -> u32 {
        self.packet_loss_ewma_ppm
    }

    pub fn effective_packet_loss_ppm(&self) -> u32 {
        effective_packet_loss_ppm(self.packet_loss_ppm, self.packet_loss_ewma_ppm)
    }

    pub fn probe_packets(&self) -> u64 {
        self.probe_packets
    }

    pub fn lost_probe_packets(&self) -> u64 {
        self.lost_probe_packets
    }

    pub fn samples(&self) -> u64 {
        self.samples
    }

    pub fn last_update(&self) -> Option<Instant> {
        self.last_update
    }

    pub fn probe_samples(&self) -> u64 {
        self.service_probes
            .values()
            .map(ServiceProbeMetrics::samples)
            .sum()
    }

    pub fn service_probe(&self, shape: ServiceShape) -> ServiceProbeMetrics {
        self.service_probes.get(&shape).copied().unwrap_or_default()
    }

    pub fn max_probe_goodput_bps(&self) -> f64 {
        self.service_probes
            .values()
            .map(ServiceProbeMetrics::goodput_bps)
            .fold(0.0, f64::max)
    }

    /// Approximate average inbound bandwidth in bytes/sec over the current window.
    pub fn recv_bps(&self) -> f64 {
        if self.window.is_zero() {
            return 0.0;
        }
        (self.recv_bytes as f64) / self.window.as_secs_f64()
    }

    /// Approximate average outbound bandwidth in bytes/sec over the current window.
    pub fn sent_bps(&self) -> f64 {
        if self.window.is_zero() {
            return 0.0;
        }
        (self.sent_bytes as f64) / self.window.as_secs_f64()
    }

    pub fn wire_recv_bps(&self) -> f64 {
        if self.window.is_zero() {
            return 0.0;
        }
        (self.wire_recv_bytes as f64) / self.window.as_secs_f64()
    }

    pub fn wire_sent_bps(&self) -> f64 {
        if self.window.is_zero() {
            return 0.0;
        }
        (self.wire_sent_bytes as f64) / self.window.as_secs_f64()
    }

    /// Best estimate of the link's available throughput. Returns whichever is
    /// larger of (a) actual bytes flowing in/out across the rolling window
    /// and (b) the active probe's measured throughput. This ensures an idle
    /// link still reports a non-zero throughput estimate.
    pub fn estimated_throughput_bps(&self) -> f64 {
        let utilized = self.recv_bps().max(self.sent_bps());
        utilized.max(self.max_probe_goodput_bps())
    }

    /// E-model-inspired conversational link-quality score. Higher is better.
    /// Packet loss uses the rolling estimate with a lower-weight long-term
    /// EWMA floor so persistent reliability issues still influence ranking.
    ///
    /// Links without RTT samples are left unranked so the dial scheduler can
    /// prefer peers with observed quality.
    pub fn quality_score(&self) -> Option<f64> {
        if self.samples == 0 {
            return None;
        }

        Some(conversational_quality_score(
            self.rtt_us,
            self.jitter_us,
            self.estimated_throughput_bps(),
            self.effective_packet_loss_ppm(),
        ))
    }

    /// Cost of this link under the sender-selected route metric. Lower is
    /// better. Links without RTT samples are left unranked.
    pub fn routing_cost(&self, _level: ServiceLevel, metric: RoutingMetric) -> Option<f64> {
        if self.samples == 0 {
            return None;
        }

        Some(match metric {
            RoutingMetric::ReliableCost => self.reliable_cost(),
            RoutingMetric::ReliableLowLatencyCost => self.reliable_low_latency_cost(),
            RoutingMetric::BestEffortCost => self.best_effort_cost(),
            RoutingMetric::ConversationalQuality => conversational_impairment(
                self.rtt_us,
                self.jitter_us,
                self.estimated_throughput_bps(),
                self.effective_packet_loss_ppm(),
            ),
        })
    }

    fn best_effort_cost(&self) -> f64 {
        apply_packet_loss_penalty(self.rtt_us.max(1.0), self.effective_packet_loss_ppm())
    }

    fn reliable_low_latency_cost(&self) -> f64 {
        apply_packet_loss_penalty(
            (self.rtt_us + DEFAULT_RLL_JITTER_WEIGHT * self.jitter_us).max(1.0),
            self.effective_packet_loss_ppm(),
        )
    }

    fn reliable_cost(&self) -> f64 {
        let throughput_kbps = (self.estimated_throughput_bps() / 1024.0).max(1.0);
        let penalty = DEFAULT_RELIABLE_THROUGHPUT_PENALTY_US_KBPS / throughput_kbps;
        apply_packet_loss_penalty(
            (self.rtt_us + penalty).max(1.0),
            self.effective_packet_loss_ppm(),
        )
    }
}

fn effective_packet_loss_ppm(rolling_ppm: u32, ewma_ppm: u32) -> u32 {
    let weighted_ewma = (ewma_ppm as f64 * PACKET_LOSS_EWMA_METRIC_WEIGHT)
        .round()
        .clamp(0.0, MAX_PACKET_LOSS_PPM as f64) as u32;
    rolling_ppm.max(weighted_ewma)
}

#[derive(Debug)]
struct SlidingCounters {
    bytes: u64,
    window_start: Instant,
    window: Duration,
}

impl SlidingCounters {
    fn new(window: Duration) -> Self {
        Self {
            bytes: 0,
            window_start: Instant::now(),
            window,
        }
    }
    fn record(&mut self, n: u64) {
        self.maybe_roll();
        self.bytes = self.bytes.saturating_add(n);
    }
    fn maybe_roll(&mut self) {
        if self.window_start.elapsed() >= self.window {
            self.bytes = 0;
            self.window_start = Instant::now();
        }
    }
    fn snapshot(&self) -> (u64, Duration) {
        (self.bytes, self.window_start.elapsed())
    }
}

#[derive(Debug)]
struct PacketLossWindow {
    delivered: u64,
    lost: u64,
    window_start: Instant,
    window: Duration,
}

impl PacketLossWindow {
    fn new(window: Duration) -> Self {
        Self {
            delivered: 0,
            lost: 0,
            window_start: Instant::now(),
            window,
        }
    }

    fn record_delivered(&mut self) {
        self.maybe_roll();
        self.delivered = self.delivered.saturating_add(1);
    }

    fn record_lost(&mut self) {
        self.maybe_roll();
        self.lost = self.lost.saturating_add(1);
    }

    fn maybe_roll(&mut self) {
        if self.window_start.elapsed() >= self.window {
            self.delivered = 0;
            self.lost = 0;
            self.window_start = Instant::now();
        }
    }

    fn snapshot(&self) -> (u64, u64, Duration) {
        let age = self.window_start.elapsed();
        if age >= self.window {
            return (0, 0, age);
        }
        (self.delivered, self.lost, age)
    }
}

#[derive(Debug)]
struct LinkInner {
    rtt_us: Option<f64>,
    jitter_us: f64,
    last_rtt_sample_us: Option<f64>,
    samples: u64,
    last_update: Option<Instant>,
    sent: SlidingCounters,
    recv: SlidingCounters,
    wire_sent: SlidingCounters,
    wire_recv: SlidingCounters,
    packet_loss: PacketLossWindow,
    packet_loss_ewma_ppm: f64,
    packet_loss_ewma_samples: u64,
    service_probes: HashMap<ServiceShape, ServiceProbeInner>,
}

#[derive(Debug, Clone, Copy)]
struct ServiceProbeInner {
    goodput_bps: f64,
    samples: u64,
}

impl LinkInner {
    fn new(window: Duration) -> Self {
        Self {
            rtt_us: None,
            jitter_us: 0.0,
            last_rtt_sample_us: None,
            samples: 0,
            last_update: None,
            sent: SlidingCounters::new(window),
            recv: SlidingCounters::new(window),
            wire_sent: SlidingCounters::new(window),
            wire_recv: SlidingCounters::new(window),
            packet_loss: PacketLossWindow::new(window),
            packet_loss_ewma_ppm: 0.0,
            packet_loss_ewma_samples: 0,
            service_probes: HashMap::new(),
        }
    }

    fn record_packet_loss_sample(&mut self, lost: bool, alpha: f64) {
        let sample = if lost {
            MAX_PACKET_LOSS_PPM as f64
        } else {
            0.0
        };
        if self.packet_loss_ewma_samples == 0 {
            self.packet_loss_ewma_ppm = sample;
        } else {
            let alpha = alpha.clamp(0.0, 1.0);
            self.packet_loss_ewma_ppm += alpha * (sample - self.packet_loss_ewma_ppm);
        }
        self.packet_loss_ewma_samples = self.packet_loss_ewma_samples.saturating_add(1);
    }
}

/// Per-`(transport, service-level)` metrics for a single peer.
#[derive(Debug)]
pub struct PeerMetrics {
    inner: Mutex<HashMap<TransportKind, LinkInner>>,
    window: Duration,
    tuning: MetricsTuning,
}

impl PeerMetrics {
    pub fn new(window: Duration, tuning: MetricsTuning) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            window,
            tuning,
        }
    }

    pub fn record_rtt(&self, transport: TransportKind, rtt: Duration) {
        let sample = rtt.as_micros() as f64;
        let mut g = self.inner.lock();
        let entry = g
            .entry(transport)
            .or_insert_with(|| LinkInner::new(self.window));
        entry.samples += 1;
        entry.last_update = Some(Instant::now());
        entry.rtt_us = Some(match entry.rtt_us {
            None => sample,
            Some(prev) => prev + self.tuning.latency_alpha * (sample - prev),
        });
        if let Some(prev_sample) = entry.last_rtt_sample_us {
            let delta = (sample - prev_sample).abs();
            entry.jitter_us += self.tuning.jitter_alpha * (delta - entry.jitter_us);
        }
        entry.last_rtt_sample_us = Some(sample);
    }

    pub fn record_sent(&self, transport: TransportKind, bytes: usize) {
        let mut g = self.inner.lock();
        g.entry(transport)
            .or_insert_with(|| LinkInner::new(self.window))
            .wire_sent
            .record(bytes as u64);
    }

    pub fn record_recv(&self, transport: TransportKind, bytes: usize) {
        let mut g = self.inner.lock();
        g.entry(transport)
            .or_insert_with(|| LinkInner::new(self.window))
            .wire_recv
            .record(bytes as u64);
    }

    pub fn record_payload_sent(&self, transport: TransportKind, bytes: usize) {
        let mut g = self.inner.lock();
        g.entry(transport)
            .or_insert_with(|| LinkInner::new(self.window))
            .sent
            .record(bytes as u64);
    }

    pub fn record_payload_recv(&self, transport: TransportKind, bytes: usize) {
        let mut g = self.inner.lock();
        g.entry(transport)
            .or_insert_with(|| LinkInner::new(self.window))
            .recv
            .record(bytes as u64);
    }

    pub fn record_probe_delivered(&self, transport: TransportKind) {
        let mut g = self.inner.lock();
        let entry = g
            .entry(transport)
            .or_insert_with(|| LinkInner::new(self.window));
        entry.packet_loss.record_delivered();
        entry.record_packet_loss_sample(false, self.tuning.packet_loss_alpha);
    }

    pub fn record_probe_lost(&self, transport: TransportKind) {
        let mut g = self.inner.lock();
        let entry = g
            .entry(transport)
            .or_insert_with(|| LinkInner::new(self.window));
        entry.packet_loss.record_lost();
        entry.record_packet_loss_sample(true, self.tuning.packet_loss_alpha);
    }

    /// Record one service-shaped active probe: `payload_bytes` useful bytes
    /// were delivered by this transport shape in `elapsed`.
    pub fn record_probe(
        &self,
        transport: TransportKind,
        shape: ServiceShape,
        payload_bytes: usize,
        elapsed: Duration,
    ) {
        if payload_bytes == 0 {
            return;
        }
        let secs = elapsed.as_secs_f64().max(1e-6);
        let bps = (payload_bytes as f64) / secs;
        let mut g = self.inner.lock();
        let entry = g
            .entry(transport)
            .or_insert_with(|| LinkInner::new(self.window));
        let probe = entry
            .service_probes
            .entry(shape)
            .or_insert(ServiceProbeInner {
                goodput_bps: bps,
                samples: 0,
            });
        if probe.samples > 0 {
            probe.goodput_bps += self.tuning.throughput_alpha * (bps - probe.goodput_bps);
        }
        probe.samples += 1;
    }

    pub fn snapshot_per_transport(&self) -> HashMap<TransportKind, LinkMetrics> {
        let g = self.inner.lock();
        g.iter()
            .map(|(t, inner)| {
                let (sent_bytes, sent_age) = inner.sent.snapshot();
                let (recv_bytes, recv_age) = inner.recv.snapshot();
                let (wire_sent_bytes, wire_sent_age) = inner.wire_sent.snapshot();
                let (wire_recv_bytes, wire_recv_age) = inner.wire_recv.snapshot();
                let (probe_delivered, probe_lost, loss_age) = inner.packet_loss.snapshot();
                let probe_packets = probe_delivered.saturating_add(probe_lost);
                let packet_loss_ppm = if probe_packets == 0 {
                    0
                } else {
                    ((probe_lost as f64 / probe_packets as f64) * MAX_PACKET_LOSS_PPM as f64)
                        .round()
                        .clamp(0.0, MAX_PACKET_LOSS_PPM as f64) as u32
                };
                let window = self.window.min(
                    recv_age
                        .max(sent_age)
                        .max(wire_recv_age)
                        .max(wire_sent_age)
                        .max(loss_age)
                        .max(Duration::from_micros(1)),
                );
                let m = LinkMetrics {
                    rtt_us: inner.rtt_us.unwrap_or(0.0),
                    jitter_us: inner.jitter_us,
                    sent_bytes,
                    recv_bytes,
                    wire_sent_bytes,
                    wire_recv_bytes,
                    window,
                    packet_loss_ppm,
                    packet_loss_ewma_ppm: inner
                        .packet_loss_ewma_ppm
                        .round()
                        .clamp(0.0, MAX_PACKET_LOSS_PPM as f64)
                        as u32,
                    probe_packets,
                    lost_probe_packets: probe_lost,
                    samples: inner.samples,
                    last_update: inner.last_update,
                    service_probes: inner
                        .service_probes
                        .iter()
                        .map(|(shape, probe)| {
                            (
                                *shape,
                                ServiceProbeMetrics {
                                    goodput_bps: probe.goodput_bps,
                                    samples: probe.samples,
                                },
                            )
                        })
                        .collect(),
                };
                (*t, m)
            })
            .collect()
    }

    /// Rank measured candidate transports for a requested service level using
    /// the sender-selected route metric. Returns only candidates with enough
    /// samples to compute a metric; callers can append their fixed fallback
    /// order for unmeasured transports.
    pub fn ranked_transports_for(
        &self,
        requested: ServiceLevel,
        metric: RoutingMetric,
        candidates: &[TransportKind],
    ) -> Vec<TransportKind> {
        let snapshot = self.snapshot_per_transport();
        let mut ranked: Vec<(TransportKind, f64)> = candidates
            .iter()
            .copied()
            .filter(|transport| transport.is_acceptable_for(requested))
            .filter_map(|transport| {
                snapshot
                    .get(&transport)
                    .and_then(|link| link.routing_cost(requested, metric))
                    .map(|cost| (transport, cost))
            })
            .collect();
        ranked.sort_by(|a, b| {
            a.1.partial_cmp(&b.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    transport_tie_rank(a.0, requested).cmp(&transport_tie_rank(b.0, requested))
                })
        });
        ranked.into_iter().map(|(transport, _)| transport).collect()
    }

    /// For a requested service level, pick the best measured candidate using
    /// the sender-selected route metric.
    pub fn best_transport_for(
        &self,
        requested: ServiceLevel,
        metric: RoutingMetric,
        candidates: &[TransportKind],
    ) -> Option<TransportKind> {
        self.ranked_transports_for(requested, metric, candidates)
            .into_iter()
            .next()
    }
}

fn transport_tie_rank(transport: TransportKind, requested: ServiceLevel) -> (u8, u8, u8) {
    let provided = transport.service_level();
    let exact_first = if provided == requested { 0 } else { 1 };
    (exact_first, provided as u8, transport_kind_order(transport))
}

fn transport_kind_order(transport: TransportKind) -> u8 {
    match transport {
        TransportKind::Tcp => 3,
        TransportKind::Quic => 1,
        TransportKind::Kcp => 2,
        TransportKind::Udp => 0,
    }
}

/// Aggregated snapshot for the whole manager. Keyed by node, then transport.
#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    per_node: HashMap<NodeIdentifier, HashMap<TransportKind, LinkMetrics>>,
}

impl MetricsSnapshot {
    pub fn per_node(&self) -> &HashMap<NodeIdentifier, HashMap<TransportKind, LinkMetrics>> {
        &self.per_node
    }

    pub fn for_node(&self, node: NodeIdentifier) -> Option<&HashMap<TransportKind, LinkMetrics>> {
        self.per_node.get(&node)
    }
}

/// Helper for the manager to assemble a `MetricsSnapshot` across all peers.
pub fn assemble_snapshot<I>(iter: I) -> MetricsSnapshot
where
    I: IntoIterator<Item = (NodeIdentifier, Arc<PeerMetrics>)>,
{
    let mut per_node = HashMap::new();
    for (node, m) in iter {
        per_node.insert(node, m.snapshot_per_transport());
    }
    MetricsSnapshot { per_node }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ewma_smoothing() {
        let m = PeerMetrics::new(Duration::from_secs(5), MetricsTuning::default());
        for us in [10_000, 12_000, 11_000, 13_000, 10_500] {
            m.record_rtt(TransportKind::Tcp, Duration::from_micros(us as u64));
        }
        let snap = m.snapshot_per_transport();
        let tcp = snap.get(&TransportKind::Tcp).unwrap();
        // EWMA with α=0.2 starting at 10000, sequence above ~ converges near 11k.
        assert!(
            tcp.rtt_us > 10_000.0 && tcp.rtt_us < 12_500.0,
            "rtt {}",
            tcp.rtt_us
        );
        assert!(tcp.jitter_us > 0.0);
        assert_eq!(tcp.samples, 5);
    }

    #[test]
    fn best_transport_picks_lowest_rtt() {
        let m = PeerMetrics::new(Duration::from_secs(5), MetricsTuning::default());
        let candidates = [TransportKind::Tcp, TransportKind::Quic, TransportKind::Udp];
        m.record_rtt(TransportKind::Tcp, Duration::from_millis(50));
        m.record_rtt(TransportKind::Quic, Duration::from_millis(20));
        m.record_rtt(TransportKind::Udp, Duration::from_millis(15));

        // For best-effort, all three qualify; lowest RTT wins.
        assert_eq!(
            m.best_transport_for(
                ServiceLevel::BestEffort,
                RoutingMetric::BestEffortCost,
                &candidates
            ),
            Some(TransportKind::Udp)
        );
        // For RLL, QUIC wins on latency; TCP remains an acceptable fallback.
        assert_eq!(
            m.best_transport_for(
                ServiceLevel::ReliableLowLatency,
                RoutingMetric::ReliableLowLatencyCost,
                &candidates
            ),
            Some(TransportKind::Quic)
        );
        // For Reliable, both TCP and QUIC qualify (QUIC is strictly stronger);
        // QUIC wins on lowest RTT.
        assert_eq!(
            m.best_transport_for(
                ServiceLevel::Reliable,
                RoutingMetric::ReliableCost,
                &candidates
            ),
            Some(TransportKind::Quic)
        );
    }

    #[test]
    fn reliable_policy_prefers_higher_throughput_over_lower_rtt() {
        let m = PeerMetrics::new(Duration::from_secs(60), MetricsTuning::default());
        let candidates = [TransportKind::Tcp, TransportKind::Quic];

        m.record_rtt(TransportKind::Tcp, Duration::from_millis(5));
        m.record_probe(
            TransportKind::Tcp,
            ServiceShape::Bulk,
            100,
            Duration::from_secs(1),
        );

        m.record_rtt(TransportKind::Quic, Duration::from_millis(25));
        m.record_probe(
            TransportKind::Quic,
            ServiceShape::Bulk,
            1024 * 1024,
            Duration::from_millis(50),
        );

        assert_eq!(
            m.best_transport_for(
                ServiceLevel::Reliable,
                RoutingMetric::ReliableCost,
                &candidates
            ),
            Some(TransportKind::Quic)
        );
    }

    #[test]
    fn conversational_policy_can_upgrade_best_effort_from_jittery_udp() {
        let m = PeerMetrics::new(Duration::from_secs(60), MetricsTuning::default());
        let candidates = [TransportKind::Udp, TransportKind::Quic];

        m.record_rtt(TransportKind::Udp, Duration::from_millis(10));
        m.record_rtt(TransportKind::Udp, Duration::from_millis(250));
        m.record_rtt(TransportKind::Quic, Duration::from_millis(70));
        m.record_rtt(TransportKind::Quic, Duration::from_millis(71));

        assert_eq!(
            m.best_transport_for(
                ServiceLevel::BestEffort,
                RoutingMetric::BestEffortCost,
                &candidates
            ),
            Some(TransportKind::Udp)
        );
        assert_eq!(
            m.best_transport_for(
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
                &candidates
            ),
            Some(TransportKind::Quic)
        );
    }

    #[test]
    fn packet_loss_penalty_affects_transport_ranking() {
        let m = PeerMetrics::new(Duration::from_secs(60), MetricsTuning::default());
        let candidates = [TransportKind::Udp, TransportKind::Quic];

        m.record_rtt(TransportKind::Udp, Duration::from_millis(10));
        m.record_probe_delivered(TransportKind::Udp);
        m.record_probe_lost(TransportKind::Udp);

        m.record_rtt(TransportKind::Quic, Duration::from_millis(15));
        m.record_probe_delivered(TransportKind::Quic);

        assert_eq!(
            m.best_transport_for(
                ServiceLevel::BestEffort,
                RoutingMetric::BestEffortCost,
                &candidates
            ),
            Some(TransportKind::Quic)
        );

        let udp = m
            .snapshot_per_transport()
            .get(&TransportKind::Udp)
            .unwrap()
            .packet_loss_ppm();
        assert_eq!(udp, 500_000);
    }

    #[test]
    fn packet_loss_ewma_tracks_probe_outcomes() {
        let m = PeerMetrics::new(
            Duration::from_secs(60),
            MetricsTuning {
                packet_loss_alpha: 0.5,
                ..MetricsTuning::default()
            },
        );

        m.record_probe_lost(TransportKind::Tcp);
        m.record_probe_delivered(TransportKind::Tcp);

        let snap = m.snapshot_per_transport();
        let tcp = snap.get(&TransportKind::Tcp).unwrap();
        assert_eq!(tcp.packet_loss_ppm(), 500_000);
        assert_eq!(tcp.packet_loss_ewma_ppm(), 500_000);
    }

    #[test]
    fn packet_loss_ewma_contributes_lower_weight_to_link_cost() {
        let clean = LinkMetrics {
            rtt_us: 10_000.0,
            samples: 1,
            ..LinkMetrics::default()
        };
        let historical_loss = LinkMetrics {
            packet_loss_ewma_ppm: 400_000,
            ..clean.clone()
        };
        let current_loss = LinkMetrics {
            packet_loss_ppm: 200_000,
            packet_loss_ewma_ppm: 400_000,
            ..clean.clone()
        };

        assert_eq!(clean.effective_packet_loss_ppm(), 0);
        assert_eq!(historical_loss.effective_packet_loss_ppm(), 100_000);
        assert_eq!(current_loss.effective_packet_loss_ppm(), 200_000);

        let clean_cost = clean
            .routing_cost(ServiceLevel::BestEffort, RoutingMetric::BestEffortCost)
            .unwrap();
        let historical_loss_cost = historical_loss
            .routing_cost(ServiceLevel::BestEffort, RoutingMetric::BestEffortCost)
            .unwrap();

        assert!(
            historical_loss_cost > clean_cost,
            "historical_loss_cost={historical_loss_cost} clean_cost={clean_cost}"
        );
    }

    #[test]
    fn probe_throughput_smooths() {
        let m = PeerMetrics::new(Duration::from_secs(5), MetricsTuning::default());
        // 8 KB useful payload in 1 ms = 8 MB/s.
        m.record_probe(
            TransportKind::Tcp,
            ServiceShape::Bulk,
            8192,
            Duration::from_millis(1),
        );
        m.record_probe(
            TransportKind::Tcp,
            ServiceShape::Bulk,
            8192,
            Duration::from_millis(1),
        );
        m.record_probe(
            TransportKind::Tcp,
            ServiceShape::Bulk,
            8192,
            Duration::from_millis(1),
        );
        let snap = m.snapshot_per_transport();
        let tcp = snap.get(&TransportKind::Tcp).unwrap();
        let expected = 8192.0 / 1e-3;
        assert!((tcp.max_probe_goodput_bps() - expected).abs() < 1.0);
        assert_eq!(tcp.probe_samples(), 3);
        assert_eq!(tcp.service_probe(ServiceShape::Bulk).samples(), 3);
    }

    #[test]
    fn estimated_throughput_takes_max() {
        let m = PeerMetrics::new(Duration::from_secs(60), MetricsTuning::default());
        m.record_payload_sent(TransportKind::Tcp, 100); // tiny actual flow
        m.record_probe(
            TransportKind::Tcp,
            ServiceShape::Bulk,
            8192,
            Duration::from_millis(1),
        ); // probe says 8 MB/s
        let snap = m.snapshot_per_transport();
        let tcp = snap.get(&TransportKind::Tcp).unwrap();
        // Probe estimate dominates because actual flow is tiny.
        assert!(tcp.estimated_throughput_bps() > 1_000_000.0);
    }

    #[test]
    fn quality_score_prefers_stronger_composite_link() {
        assert_eq!(LinkMetrics::default().quality_score(), None);

        let m = PeerMetrics::new(Duration::from_secs(60), MetricsTuning::default());

        m.record_rtt(TransportKind::Tcp, Duration::from_millis(5));
        m.record_rtt(TransportKind::Tcp, Duration::from_millis(80));
        m.record_probe(
            TransportKind::Tcp,
            ServiceShape::Bulk,
            1024,
            Duration::from_millis(100),
        );

        m.record_rtt(TransportKind::Quic, Duration::from_millis(25));
        m.record_rtt(TransportKind::Quic, Duration::from_millis(26));
        m.record_probe(
            TransportKind::Quic,
            ServiceShape::Bulk,
            1024 * 1024,
            Duration::from_millis(50),
        );

        let snap = m.snapshot_per_transport();
        let tcp = snap
            .get(&TransportKind::Tcp)
            .and_then(LinkMetrics::quality_score)
            .unwrap();
        let quic = snap
            .get(&TransportKind::Quic)
            .and_then(LinkMetrics::quality_score)
            .unwrap();

        assert!(quic > tcp, "quic={quic} tcp={tcp}");
    }

    #[test]
    fn bandwidth_counters_accumulate() {
        let m = PeerMetrics::new(Duration::from_secs(60), MetricsTuning::default());
        m.record_payload_sent(TransportKind::Tcp, 1024);
        m.record_payload_recv(TransportKind::Tcp, 512);
        m.record_sent(TransportKind::Tcp, 2048);
        m.record_recv(TransportKind::Tcp, 1536);
        let snap = m.snapshot_per_transport();
        let tcp = snap.get(&TransportKind::Tcp).unwrap();
        assert_eq!(tcp.sent_bytes, 1024);
        assert_eq!(tcp.recv_bytes, 512);
        assert_eq!(tcp.wire_sent_bytes(), 2048);
        assert_eq!(tcp.wire_recv_bytes(), 1536);
    }
}
