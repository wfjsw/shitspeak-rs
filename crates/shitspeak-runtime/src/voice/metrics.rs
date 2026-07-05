use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use shitspeak_s2s::status::PrometheusSample;

#[derive(Clone, Copy)]
pub(crate) enum VoiceIngressTransport {
    Udp,
    TcpTunnel,
}

impl VoiceIngressTransport {
    fn label(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::TcpTunnel => "tcp_tunnel",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum UdpDecryptPath {
    Address,
    IpFallback,
}

impl UdpDecryptPath {
    fn label(self) -> &'static str {
        match self {
            Self::Address => "address",
            Self::IpFallback => "ip_fallback",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum UdpDecryptResult {
    Success,
    Failure,
    NoCryptState,
}

impl UdpDecryptResult {
    fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::NoCryptState => "no_crypt_state",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum UdpDrainDropReason {
    ProcessingQueueFull,
    ProcessingQueueClosed,
    VoiceDisabled,
    PacketTooShort,
    PingDecodeFailed,
}

impl UdpDrainDropReason {
    fn label(self) -> &'static str {
        match self {
            Self::ProcessingQueueFull => "processing_queue_full",
            Self::ProcessingQueueClosed => "processing_queue_closed",
            Self::VoiceDisabled => "voice_disabled",
            Self::PacketTooShort => "packet_too_short",
            Self::PingDecodeFailed => "ping_decode_failed",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceQueueDropReason {
    RoutingQueueFullOrClosed,
    TcpQueueFull,
    TcpQueueClosed,
}

impl VoiceQueueDropReason {
    fn label(self) -> &'static str {
        match self {
            Self::RoutingQueueFullOrClosed => "routing_queue_full_or_closed",
            Self::TcpQueueFull => "tcp_queue_full",
            Self::TcpQueueClosed => "tcp_queue_closed",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceRouteSource {
    Local,
    S2s,
    Loopback,
}

impl VoiceRouteSource {
    fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::S2s => "s2s",
            Self::Loopback => "loopback",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceRouteKind {
    Normal,
    Target,
    Loopback,
}

impl VoiceRouteKind {
    fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Target => "target",
            Self::Loopback => "loopback",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceDispatchMode {
    Sequential,
    Rayon,
}

impl VoiceDispatchMode {
    fn label(self) -> &'static str {
        match self {
            Self::Sequential => "sequential",
            Self::Rayon => "rayon",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceEgressTransport {
    Udp,
    TcpTunnel,
}

impl VoiceEgressTransport {
    fn label(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::TcpTunnel => "tcp_tunnel",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VoiceEgressResult {
    Queued,
    Sent,
    Dropped,
    Failed,
}

impl VoiceEgressResult {
    fn label(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sent => "sent",
            Self::Dropped => "dropped",
            Self::Failed => "failed",
        }
    }
}

const INGRESS_TRANSPORT_COUNT: usize = 2;
const UDP_DECRYPT_PATH_COUNT: usize = 2;
const UDP_DECRYPT_RESULT_COUNT: usize = 3;
const UDP_DRAIN_DROP_REASON_COUNT: usize = 5;
const VOICE_QUEUE_DROP_REASON_COUNT: usize = 3;
const VOICE_ROUTE_SOURCE_COUNT: usize = 3;
const VOICE_ROUTE_KIND_COUNT: usize = 3;
const VOICE_DISPATCH_MODE_COUNT: usize = 2;
const VOICE_EGRESS_TRANSPORT_COUNT: usize = 2;
const VOICE_EGRESS_RESULT_COUNT: usize = 4;

const ROUTE_DIMENSIONS: [(VoiceRouteSource, VoiceRouteKind); 5] = [
    (VoiceRouteSource::Local, VoiceRouteKind::Normal),
    (VoiceRouteSource::Local, VoiceRouteKind::Target),
    (VoiceRouteSource::S2s, VoiceRouteKind::Normal),
    (VoiceRouteSource::S2s, VoiceRouteKind::Target),
    (VoiceRouteSource::Loopback, VoiceRouteKind::Loopback),
];

const FANOUT_BUCKETS: [(&str, u64); 8] = [
    ("0", 0),
    ("1", 1),
    ("2_4", 4),
    ("5_16", 16),
    ("17_64", 64),
    ("65_256", 256),
    ("257_512", 512),
    ("513_plus", u64::MAX),
];
const ROUTE_DURATION_BUCKETS_US: [(&str, u64); 8] = [
    ("le_100", 100),
    ("le_250", 250),
    ("le_500", 500),
    ("le_1000", 1_000),
    ("le_2500", 2_500),
    ("le_5000", 5_000),
    ("le_10000", 10_000),
    ("gt_10000", u64::MAX),
];
const UDP_FALLBACK_CANDIDATE_BUCKETS: [(&str, u64); 7] = [
    ("0", 0),
    ("1", 1),
    ("2_4", 4),
    ("5_8", 8),
    ("9_16", 16),
    ("17_32", 32),
    ("33_plus", u64::MAX),
];

static INGRESS_PACKETS: [AtomicU64; INGRESS_TRANSPORT_COUNT] = [const { AtomicU64::new(0) }; 2];
static INGRESS_BYTES: [AtomicU64; INGRESS_TRANSPORT_COUNT] = [const { AtomicU64::new(0) }; 2];
static UDP_DECRYPT_ATTEMPTS: [[AtomicU64; UDP_DECRYPT_RESULT_COUNT]; UDP_DECRYPT_PATH_COUNT] =
    [const { [const { AtomicU64::new(0) }; UDP_DECRYPT_RESULT_COUNT] }; UDP_DECRYPT_PATH_COUNT];
static UDP_IP_FALLBACKS: AtomicU64 = AtomicU64::new(0);
static UDP_IP_FALLBACK_CANDIDATE_BUCKETS: [AtomicU64; UDP_FALLBACK_CANDIDATE_BUCKETS.len()] =
    [const { AtomicU64::new(0) }; UDP_FALLBACK_CANDIDATE_BUCKETS.len()];
static UDP_DRAIN_DROPS: [AtomicU64; UDP_DRAIN_DROP_REASON_COUNT] =
    [const { AtomicU64::new(0) }; UDP_DRAIN_DROP_REASON_COUNT];
static QUEUE_DROPS: [AtomicU64; VOICE_QUEUE_DROP_REASON_COUNT] =
    [const { AtomicU64::new(0) }; VOICE_QUEUE_DROP_REASON_COUNT];
static ROUTED_FRAMES: [AtomicU64; VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT] =
    [const { AtomicU64::new(0) }; VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT];
static ROUTE_RESOLUTION_DURATION_TOTAL_US: [AtomicU64;
    VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT] =
    [const { AtomicU64::new(0) }; VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT];
static ROUTE_DURATION_TOTAL_US: [AtomicU64; VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT] =
    [const { AtomicU64::new(0) }; VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT];
static ROUTE_DURATION_BUCKETS: [[AtomicU64; ROUTE_DURATION_BUCKETS_US.len()];
    VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT] =
    [const { [const { AtomicU64::new(0) }; ROUTE_DURATION_BUCKETS_US.len()] };
        VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT];
static FANOUT_BUCKETS_TOTAL: [[AtomicU64; FANOUT_BUCKETS.len()];
    VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT] =
    [const { [const { AtomicU64::new(0) }; FANOUT_BUCKETS.len()] };
        VOICE_ROUTE_SOURCE_COUNT * VOICE_ROUTE_KIND_COUNT];
static DISPATCH_FRAMES: [AtomicU64; VOICE_DISPATCH_MODE_COUNT] =
    [const { AtomicU64::new(0) }; VOICE_DISPATCH_MODE_COUNT];
static EGRESS_PACKETS: [[AtomicU64; VOICE_EGRESS_RESULT_COUNT]; VOICE_EGRESS_TRANSPORT_COUNT] =
    [const { [const { AtomicU64::new(0) }; VOICE_EGRESS_RESULT_COUNT] };
        VOICE_EGRESS_TRANSPORT_COUNT];
static EGRESS_BYTES: [[AtomicU64; VOICE_EGRESS_RESULT_COUNT]; VOICE_EGRESS_TRANSPORT_COUNT] =
    [const { [const { AtomicU64::new(0) }; VOICE_EGRESS_RESULT_COUNT] };
        VOICE_EGRESS_TRANSPORT_COUNT];
static S2S_FORWARD_ATTEMPTS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

fn transport_index(transport: VoiceIngressTransport) -> usize {
    match transport {
        VoiceIngressTransport::Udp => 0,
        VoiceIngressTransport::TcpTunnel => 1,
    }
}

fn decrypt_path_index(path: UdpDecryptPath) -> usize {
    match path {
        UdpDecryptPath::Address => 0,
        UdpDecryptPath::IpFallback => 1,
    }
}

fn decrypt_result_index(result: UdpDecryptResult) -> usize {
    match result {
        UdpDecryptResult::Success => 0,
        UdpDecryptResult::Failure => 1,
        UdpDecryptResult::NoCryptState => 2,
    }
}

fn udp_drain_drop_index(reason: UdpDrainDropReason) -> usize {
    match reason {
        UdpDrainDropReason::ProcessingQueueFull => 0,
        UdpDrainDropReason::ProcessingQueueClosed => 1,
        UdpDrainDropReason::VoiceDisabled => 2,
        UdpDrainDropReason::PacketTooShort => 3,
        UdpDrainDropReason::PingDecodeFailed => 4,
    }
}

fn queue_drop_index(reason: VoiceQueueDropReason) -> usize {
    match reason {
        VoiceQueueDropReason::RoutingQueueFullOrClosed => 0,
        VoiceQueueDropReason::TcpQueueFull => 1,
        VoiceQueueDropReason::TcpQueueClosed => 2,
    }
}

fn route_source_index(source: VoiceRouteSource) -> usize {
    match source {
        VoiceRouteSource::Local => 0,
        VoiceRouteSource::S2s => 1,
        VoiceRouteSource::Loopback => 2,
    }
}

fn route_kind_index(kind: VoiceRouteKind) -> usize {
    match kind {
        VoiceRouteKind::Normal => 0,
        VoiceRouteKind::Target => 1,
        VoiceRouteKind::Loopback => 2,
    }
}

fn route_index(source: VoiceRouteSource, kind: VoiceRouteKind) -> usize {
    route_source_index(source) * VOICE_ROUTE_KIND_COUNT + route_kind_index(kind)
}

fn dispatch_mode_index(mode: VoiceDispatchMode) -> usize {
    match mode {
        VoiceDispatchMode::Sequential => 0,
        VoiceDispatchMode::Rayon => 1,
    }
}

fn egress_transport_index(transport: VoiceEgressTransport) -> usize {
    match transport {
        VoiceEgressTransport::Udp => 0,
        VoiceEgressTransport::TcpTunnel => 1,
    }
}

fn egress_result_index(result: VoiceEgressResult) -> usize {
    match result {
        VoiceEgressResult::Queued => 0,
        VoiceEgressResult::Sent => 1,
        VoiceEgressResult::Dropped => 2,
        VoiceEgressResult::Failed => 3,
    }
}

fn increment(value: &AtomicU64, amount: u64) {
    value.fetch_add(amount, Ordering::Relaxed);
}

fn observe_bucket(buckets: &[AtomicU64], definitions: &[(&str, u64)], value: u64) {
    if let Some((index, _)) = definitions
        .iter()
        .enumerate()
        .find(|(_, (_, upper_bound))| value <= *upper_bound)
    {
        increment(&buckets[index], 1);
    }
}

pub(crate) fn record_ingress(transport: VoiceIngressTransport, bytes: usize) {
    let index = transport_index(transport);
    increment(&INGRESS_PACKETS[index], 1);
    increment(&INGRESS_BYTES[index], bytes as u64);
}

pub(crate) fn record_udp_decrypt(path: UdpDecryptPath, result: UdpDecryptResult) {
    increment(
        &UDP_DECRYPT_ATTEMPTS[decrypt_path_index(path)][decrypt_result_index(result)],
        1,
    );
}

pub(crate) fn record_udp_ip_fallback(candidates: usize) {
    increment(&UDP_IP_FALLBACKS, 1);
    observe_bucket(
        &UDP_IP_FALLBACK_CANDIDATE_BUCKETS,
        &UDP_FALLBACK_CANDIDATE_BUCKETS,
        candidates as u64,
    );
}

pub(crate) fn record_udp_drain_drop(reason: UdpDrainDropReason) {
    increment(&UDP_DRAIN_DROPS[udp_drain_drop_index(reason)], 1);
}

pub(crate) fn record_queue_drop(reason: VoiceQueueDropReason) {
    increment(&QUEUE_DROPS[queue_drop_index(reason)], 1);
}

pub(crate) fn record_route(
    source: VoiceRouteSource,
    kind: VoiceRouteKind,
    fanout: usize,
    duration: Duration,
) {
    let index = route_index(source, kind);
    increment(&ROUTED_FRAMES[index], 1);
    observe_bucket(&FANOUT_BUCKETS_TOTAL[index], &FANOUT_BUCKETS, fanout as u64);
    let duration_us = duration.as_micros().min(u64::MAX as u128) as u64;
    increment(&ROUTE_DURATION_TOTAL_US[index], duration_us);
    observe_bucket(
        &ROUTE_DURATION_BUCKETS[index],
        &ROUTE_DURATION_BUCKETS_US,
        duration_us,
    );
}

pub(crate) fn record_route_resolution(
    source: VoiceRouteSource,
    kind: VoiceRouteKind,
    duration: Duration,
) {
    let index = route_index(source, kind);
    let duration_us = duration.as_micros().min(u64::MAX as u128) as u64;
    increment(&ROUTE_RESOLUTION_DURATION_TOTAL_US[index], duration_us);
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct VoiceRouteMetricSnapshot {
    frames: u64,
    duration: Duration,
}

#[cfg(test)]
impl VoiceRouteMetricSnapshot {
    pub(crate) fn frames(self) -> u64 {
        self.frames
    }

    pub(crate) fn duration(self) -> Duration {
        self.duration
    }

    pub(crate) fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            frames: self.frames.saturating_sub(earlier.frames),
            duration: self.duration.saturating_sub(earlier.duration),
        }
    }
}

#[cfg(test)]
pub(crate) fn route_metric_snapshot(
    source: VoiceRouteSource,
    kind: VoiceRouteKind,
) -> VoiceRouteMetricSnapshot {
    let index = route_index(source, kind);
    VoiceRouteMetricSnapshot {
        frames: ROUTED_FRAMES[index].load(Ordering::Relaxed),
        duration: Duration::from_micros(ROUTE_DURATION_TOTAL_US[index].load(Ordering::Relaxed)),
    }
}

#[cfg(test)]
pub(crate) fn route_resolution_metric_snapshot(
    source: VoiceRouteSource,
    kind: VoiceRouteKind,
) -> VoiceRouteMetricSnapshot {
    let index = route_index(source, kind);
    VoiceRouteMetricSnapshot {
        frames: ROUTED_FRAMES[index].load(Ordering::Relaxed),
        duration: Duration::from_micros(
            ROUTE_RESOLUTION_DURATION_TOTAL_US[index].load(Ordering::Relaxed),
        ),
    }
}

pub(crate) fn record_dispatch(mode: VoiceDispatchMode) {
    increment(&DISPATCH_FRAMES[dispatch_mode_index(mode)], 1);
}

pub(crate) fn record_egress(
    transport: VoiceEgressTransport,
    result: VoiceEgressResult,
    packets: usize,
    bytes: usize,
) {
    if packets == 0 && bytes == 0 {
        return;
    }
    let transport_index = egress_transport_index(transport);
    let result_index = egress_result_index(result);
    increment(
        &EGRESS_PACKETS[transport_index][result_index],
        packets as u64,
    );
    increment(&EGRESS_BYTES[transport_index][result_index], bytes as u64);
}

pub(crate) fn record_s2s_forward(sent: bool) {
    increment(&S2S_FORWARD_ATTEMPTS[usize::from(sent)], 1);
}

pub(crate) fn prometheus_samples() -> Vec<PrometheusSample> {
    let mut samples = Vec::new();

    for transport in [VoiceIngressTransport::Udp, VoiceIngressTransport::TcpTunnel] {
        let index = transport_index(transport);
        let labels = vec![("transport".to_owned(), transport.label().to_owned())];
        samples.push(PrometheusSample::new(
            "shitspeak_voice_ingress_packets_total",
            labels.clone(),
            INGRESS_PACKETS[index].load(Ordering::Relaxed) as f64,
        ));
        samples.push(PrometheusSample::new(
            "shitspeak_voice_ingress_bytes_total",
            labels,
            INGRESS_BYTES[index].load(Ordering::Relaxed) as f64,
        ));
    }

    for path in [UdpDecryptPath::Address, UdpDecryptPath::IpFallback] {
        for result in [
            UdpDecryptResult::Success,
            UdpDecryptResult::Failure,
            UdpDecryptResult::NoCryptState,
        ] {
            samples.push(PrometheusSample::new(
                "shitspeak_voice_udp_decrypt_attempts_total",
                vec![
                    ("path".to_owned(), path.label().to_owned()),
                    ("result".to_owned(), result.label().to_owned()),
                ],
                UDP_DECRYPT_ATTEMPTS[decrypt_path_index(path)][decrypt_result_index(result)]
                    .load(Ordering::Relaxed) as f64,
            ));
        }
    }

    samples.push(PrometheusSample::new(
        "shitspeak_voice_udp_ip_fallbacks_total",
        Vec::new(),
        UDP_IP_FALLBACKS.load(Ordering::Relaxed) as f64,
    ));
    for (index, (bucket, _)) in UDP_FALLBACK_CANDIDATE_BUCKETS.iter().enumerate() {
        samples.push(PrometheusSample::new(
            "shitspeak_voice_udp_ip_fallback_candidate_bucket_total",
            vec![("bucket".to_owned(), (*bucket).to_owned())],
            UDP_IP_FALLBACK_CANDIDATE_BUCKETS[index].load(Ordering::Relaxed) as f64,
        ));
    }

    for reason in [
        UdpDrainDropReason::ProcessingQueueFull,
        UdpDrainDropReason::ProcessingQueueClosed,
        UdpDrainDropReason::VoiceDisabled,
        UdpDrainDropReason::PacketTooShort,
        UdpDrainDropReason::PingDecodeFailed,
    ] {
        samples.push(PrometheusSample::new(
            "shitspeak_voice_udp_drain_drops_total",
            vec![("reason".to_owned(), reason.label().to_owned())],
            UDP_DRAIN_DROPS[udp_drain_drop_index(reason)].load(Ordering::Relaxed) as f64,
        ));
    }

    for reason in [
        VoiceQueueDropReason::RoutingQueueFullOrClosed,
        VoiceQueueDropReason::TcpQueueFull,
        VoiceQueueDropReason::TcpQueueClosed,
    ] {
        samples.push(PrometheusSample::new(
            "shitspeak_voice_queue_drops_total",
            vec![("reason".to_owned(), reason.label().to_owned())],
            QUEUE_DROPS[queue_drop_index(reason)].load(Ordering::Relaxed) as f64,
        ));
    }

    for (source, kind) in ROUTE_DIMENSIONS {
        let index = route_index(source, kind);
        let labels = vec![
            ("source".to_owned(), source.label().to_owned()),
            ("kind".to_owned(), kind.label().to_owned()),
        ];
        samples.push(PrometheusSample::new(
            "shitspeak_voice_routed_frames_total",
            labels.clone(),
            ROUTED_FRAMES[index].load(Ordering::Relaxed) as f64,
        ));
        for (bucket_index, (bucket, _)) in FANOUT_BUCKETS.iter().enumerate() {
            let mut labels = labels.clone();
            labels.push(("bucket".to_owned(), (*bucket).to_owned()));
            samples.push(PrometheusSample::new(
                "shitspeak_voice_fanout_bucket_total",
                labels,
                FANOUT_BUCKETS_TOTAL[index][bucket_index].load(Ordering::Relaxed) as f64,
            ));
        }
        for (bucket_index, (bucket, _)) in ROUTE_DURATION_BUCKETS_US.iter().enumerate() {
            let mut labels = labels.clone();
            labels.push(("bucket".to_owned(), (*bucket).to_owned()));
            samples.push(PrometheusSample::new(
                "shitspeak_voice_route_duration_us_bucket_total",
                labels,
                ROUTE_DURATION_BUCKETS[index][bucket_index].load(Ordering::Relaxed) as f64,
            ));
        }
    }

    for mode in [VoiceDispatchMode::Sequential, VoiceDispatchMode::Rayon] {
        samples.push(PrometheusSample::new(
            "shitspeak_voice_dispatch_frames_total",
            vec![("mode".to_owned(), mode.label().to_owned())],
            DISPATCH_FRAMES[dispatch_mode_index(mode)].load(Ordering::Relaxed) as f64,
        ));
    }

    for transport in [VoiceEgressTransport::Udp, VoiceEgressTransport::TcpTunnel] {
        for result in [
            VoiceEgressResult::Queued,
            VoiceEgressResult::Sent,
            VoiceEgressResult::Dropped,
            VoiceEgressResult::Failed,
        ] {
            let transport_index = egress_transport_index(transport);
            let result_index = egress_result_index(result);
            let labels = vec![
                ("transport".to_owned(), transport.label().to_owned()),
                ("result".to_owned(), result.label().to_owned()),
            ];
            samples.push(PrometheusSample::new(
                "shitspeak_voice_egress_packets_total",
                labels.clone(),
                EGRESS_PACKETS[transport_index][result_index].load(Ordering::Relaxed) as f64,
            ));
            samples.push(PrometheusSample::new(
                "shitspeak_voice_egress_bytes_total",
                labels,
                EGRESS_BYTES[transport_index][result_index].load(Ordering::Relaxed) as f64,
            ));
        }
    }

    for sent in [false, true] {
        samples.push(PrometheusSample::new(
            "shitspeak_voice_s2s_forward_attempts_total",
            vec![("sent".to_owned(), sent.to_string())],
            S2S_FORWARD_ATTEMPTS[usize::from(sent)].load(Ordering::Relaxed) as f64,
        ));
    }

    samples
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn route_samples_use_only_real_route_dimensions() {
        let route_dimensions = prometheus_samples()
            .into_iter()
            .filter(|sample| sample.name() == "shitspeak_voice_routed_frames_total")
            .map(|sample| {
                let source = sample
                    .labels()
                    .iter()
                    .find_map(|(key, value)| (key == "source").then_some(value.as_str()))
                    .expect("source label");
                let kind = sample
                    .labels()
                    .iter()
                    .find_map(|(key, value)| (key == "kind").then_some(value.as_str()))
                    .expect("kind label");
                (source.to_owned(), kind.to_owned())
            })
            .collect::<BTreeSet<_>>();

        assert_eq!(
            route_dimensions,
            BTreeSet::from([
                ("local".to_owned(), "normal".to_owned()),
                ("local".to_owned(), "target".to_owned()),
                ("s2s".to_owned(), "normal".to_owned()),
                ("s2s".to_owned(), "target".to_owned()),
                ("loopback".to_owned(), "loopback".to_owned()),
            ])
        );
    }
}
