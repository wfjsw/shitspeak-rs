//! Per-link telemetry: EWMA latency + RFC-3550-style jitter, plus a sliding
//! bandwidth meter. Aggregated per `(node, ServiceLevel)` so callers can score
//! path quality among co-existing transports.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::types::NodeIdentifier;

use super::service_level::{ServiceLevel, TransportKind};

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
}

impl Default for MetricsTuning {
    fn default() -> Self {
        Self {
            latency_alpha: 0.2,
            jitter_alpha: 1.0 / 16.0,
            throughput_alpha: 0.3,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct LinkMetrics {
    /// Smoothed round-trip time in microseconds.
    rtt_us: f64,
    /// Smoothed |Δrtt| in microseconds (jitter).
    jitter_us: f64,
    /// Bytes received since the window started.
    recv_bytes: u64,
    /// Bytes sent since the window started.
    sent_bytes: u64,
    /// The wall-clock window over which `recv_bytes` / `sent_bytes` apply.
    window: Duration,
    samples: u64,
    last_update: Option<Instant>,
    /// EWMA of throughput observed during active bandwidth probes, in
    /// bytes/sec. Lower bound — the probe is small and finishes during a
    /// single RTT, so a high-bandwidth idle link still shows a finite value.
    probe_throughput_bps: f64,
    /// Number of probe round trips completed.
    probe_samples: u64,
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

    pub fn window(&self) -> Duration {
        self.window
    }

    pub fn samples(&self) -> u64 {
        self.samples
    }

    pub fn last_update(&self) -> Option<Instant> {
        self.last_update
    }

    pub fn probe_throughput_bps(&self) -> f64 {
        self.probe_throughput_bps
    }

    pub fn probe_samples(&self) -> u64 {
        self.probe_samples
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

    /// Best estimate of the link's available throughput. Returns whichever is
    /// larger of (a) actual bytes flowing in/out across the rolling window
    /// and (b) the active probe's measured throughput. This ensures an idle
    /// link still reports a non-zero throughput estimate.
    pub fn estimated_throughput_bps(&self) -> f64 {
        let utilized = self.recv_bps().max(self.sent_bps());
        utilized.max(self.probe_throughput_bps)
    }

    /// E-model-inspired conversational link-quality score. Higher is better.
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
            0,
        ))
    }
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
struct LinkInner {
    rtt_us: Option<f64>,
    jitter_us: f64,
    last_rtt_sample_us: Option<f64>,
    samples: u64,
    last_update: Option<Instant>,
    sent: SlidingCounters,
    recv: SlidingCounters,
    probe_throughput_bps: Option<f64>,
    probe_samples: u64,
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
            probe_throughput_bps: None,
            probe_samples: 0,
        }
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
            .sent
            .record(bytes as u64);
    }

    pub fn record_recv(&self, transport: TransportKind, bytes: usize) {
        let mut g = self.inner.lock();
        g.entry(transport)
            .or_insert_with(|| LinkInner::new(self.window))
            .recv
            .record(bytes as u64);
    }

    /// Record one bandwidth-probe round trip: `bytes_round_trip` bytes were
    /// exchanged in `rtt`. Computes `bytes / rtt` and feeds it into the
    /// probe-throughput EWMA. Tiny RTTs are clamped to avoid divide-by-zero.
    pub fn record_probe(&self, transport: TransportKind, bytes_round_trip: usize, rtt: Duration) {
        let secs = rtt.as_secs_f64().max(1e-6);
        let bps = (bytes_round_trip as f64) / secs;
        let mut g = self.inner.lock();
        let entry = g
            .entry(transport)
            .or_insert_with(|| LinkInner::new(self.window));
        entry.probe_throughput_bps = Some(match entry.probe_throughput_bps {
            None => bps,
            Some(prev) => prev + self.tuning.throughput_alpha * (bps - prev),
        });
        entry.probe_samples += 1;
    }

    pub fn snapshot_per_transport(&self) -> HashMap<TransportKind, LinkMetrics> {
        let g = self.inner.lock();
        g.iter()
            .map(|(t, inner)| {
                let (sent_bytes, _) = inner.sent.snapshot();
                let (recv_bytes, recv_age) = inner.recv.snapshot();
                let window = self.window.min(recv_age.max(Duration::from_micros(1)));
                let m = LinkMetrics {
                    rtt_us: inner.rtt_us.unwrap_or(0.0),
                    jitter_us: inner.jitter_us,
                    sent_bytes,
                    recv_bytes,
                    window,
                    samples: inner.samples,
                    last_update: inner.last_update,
                    probe_throughput_bps: inner.probe_throughput_bps.unwrap_or(0.0),
                    probe_samples: inner.probe_samples,
                };
                (*t, m)
            })
            .collect()
    }

    /// For a requested service level, pick the live link that satisfies the
    /// level with the smallest smoothed RTT. Returns `None` if no link
    /// qualifies (caller falls back to fixed-priority selection).
    pub fn best_transport_for(&self, requested: ServiceLevel) -> Option<TransportKind> {
        let g = self.inner.lock();
        g.iter()
            .filter(|(t, _)| t.service_level().satisfies(requested))
            .filter_map(|(t, inner)| inner.rtt_us.map(|r| (*t, r)))
            .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(t, _)| t)
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
        m.record_rtt(TransportKind::Tcp, Duration::from_millis(50));
        m.record_rtt(TransportKind::Quic, Duration::from_millis(20));
        m.record_rtt(TransportKind::Udp, Duration::from_millis(15));

        // For best-effort, all three qualify; lowest RTT wins.
        assert_eq!(
            m.best_transport_for(ServiceLevel::BestEffort),
            Some(TransportKind::Udp)
        );
        // For RLL (the strongest tier), only QUIC qualifies in this setup
        // (TCP is plain Reliable, UDP is BestEffort).
        assert_eq!(
            m.best_transport_for(ServiceLevel::ReliableLowLatency),
            Some(TransportKind::Quic)
        );
        // For Reliable, both TCP and QUIC qualify (QUIC is strictly stronger);
        // QUIC wins on lowest RTT.
        assert_eq!(
            m.best_transport_for(ServiceLevel::Reliable),
            Some(TransportKind::Quic)
        );
    }

    #[test]
    fn probe_throughput_smooths() {
        let m = PeerMetrics::new(Duration::from_secs(5), MetricsTuning::default());
        // 8 KB round trip in 1 ms = 8 MB/s.
        m.record_probe(TransportKind::Tcp, 8192, Duration::from_millis(1));
        m.record_probe(TransportKind::Tcp, 8192, Duration::from_millis(1));
        m.record_probe(TransportKind::Tcp, 8192, Duration::from_millis(1));
        let snap = m.snapshot_per_transport();
        let tcp = snap.get(&TransportKind::Tcp).unwrap();
        let expected = 8192.0 / 1e-3;
        assert!((tcp.probe_throughput_bps - expected).abs() < 1.0);
        assert_eq!(tcp.probe_samples, 3);
    }

    #[test]
    fn estimated_throughput_takes_max() {
        let m = PeerMetrics::new(Duration::from_secs(60), MetricsTuning::default());
        m.record_sent(TransportKind::Tcp, 100); // tiny actual flow
        m.record_probe(TransportKind::Tcp, 8192, Duration::from_millis(1)); // probe says 8 MB/s
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
        m.record_probe(TransportKind::Tcp, 1024, Duration::from_millis(100));

        m.record_rtt(TransportKind::Quic, Duration::from_millis(25));
        m.record_rtt(TransportKind::Quic, Duration::from_millis(26));
        m.record_probe(TransportKind::Quic, 1024 * 1024, Duration::from_millis(50));

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
        m.record_sent(TransportKind::Tcp, 1024);
        m.record_recv(TransportKind::Tcp, 512);
        let snap = m.snapshot_per_transport();
        let tcp = snap.get(&TransportKind::Tcp).unwrap();
        assert_eq!(tcp.sent_bytes, 1024);
        assert_eq!(tcp.recv_bytes, 512);
    }
}
