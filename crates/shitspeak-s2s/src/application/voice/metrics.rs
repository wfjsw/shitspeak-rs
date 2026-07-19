use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::Instant;

use shitspeak_core::NodeIdentifier;

use crate::status::PrometheusSample;

const COUNT_BUCKETS: [(&str, u64); 8] = [
    ("0", 0),
    ("1", 1),
    ("2_4", 4),
    ("5_8", 8),
    ("9_16", 16),
    ("17_32", 32),
    ("33_64", 64),
    ("65_plus", u64::MAX),
];
const BYTE_BUCKETS: [(&str, u64); 8] = [
    ("le_512", 512),
    ("le_1024", 1_024),
    ("le_2048", 2_048),
    ("le_4096", 4_096),
    ("le_8192", 8_192),
    ("le_16384", 16_384),
    ("le_65536", 65_536),
    ("gt_65536", u64::MAX),
];

static METRICS: LazyLock<Mutex<VoiceAppMetrics>> =
    LazyLock::new(|| Mutex::new(VoiceAppMetrics::default()));
static REPAIR_CACHE_SOURCES: LazyLock<Mutex<Vec<Weak<dyn RepairCacheTelemetrySource>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

pub(crate) trait RepairCacheTelemetrySource: Send + Sync {
    fn snapshot(&self, now: Instant) -> (usize, usize);
}

pub(crate) fn register_repair_cache_telemetry_source(source: Arc<dyn RepairCacheTelemetrySource>) {
    REPAIR_CACHE_SOURCES
        .lock()
        .unwrap()
        .push(Arc::downgrade(&source));
}

fn repair_cache_telemetry_snapshot() -> (usize, usize) {
    let sources = {
        let mut registry = REPAIR_CACHE_SOURCES.lock().unwrap();
        let mut sources = Vec::with_capacity(registry.len());
        registry.retain(|source| {
            let Some(source) = source.upgrade() else {
                return false;
            };
            sources.push(source);
            true
        });
        sources
    };
    let now = Instant::now();
    sources.into_iter().map(|source| source.snapshot(now)).fold(
        (0_usize, 0_usize),
        |(occupancy, capacity), next| {
            (
                occupancy.saturating_add(next.0),
                capacity.saturating_add(next.1),
            )
        },
    )
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum VoiceSendMode {
    Broadcast,
    Multicast,
    Unicast,
    Targeted,
    TargetedFallback,
    TargetedNoop,
}

impl VoiceSendMode {
    fn label(self) -> &'static str {
        match self {
            Self::Broadcast => "broadcast",
            Self::Multicast => "multicast",
            Self::Unicast => "unicast",
            Self::Targeted => "targeted",
            Self::TargetedFallback => "targeted_fallback",
            Self::TargetedNoop => "targeted_noop",
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum VoiceSendResult {
    Sent,
    Failed,
    Noop,
}

impl VoiceSendResult {
    fn label(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Failed => "failed",
            Self::Noop => "noop",
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum VoiceReceiveResult {
    InOrder,
    GapBuffered,
    GapFilled,
    DuplicateOrLate,
    DeadlineFlush,
    BufferDrop,
    NoSinkDrop,
    SpeakerStateDrop,
}

impl VoiceReceiveResult {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::InOrder => "in_order",
            Self::GapBuffered => "gap_buffered",
            Self::GapFilled => "gap_filled",
            Self::DuplicateOrLate => "duplicate_or_late",
            Self::DeadlineFlush => "deadline_flush",
            Self::BufferDrop => "buffer_drop",
            Self::NoSinkDrop => "no_sink_drop",
            Self::SpeakerStateDrop => "speaker_state_drop",
        }
    }
}

/// The delivery lane that admitted an inbound voice frame.
///
/// This is intentionally a small fixed label set: queue pressure must remain
/// observable without multiplying the metric by sender or peer.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum VoiceIngressClass {
    Primary,
    Proactive,
}

impl VoiceIngressClass {
    fn label(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Proactive => "proactive",
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum VoiceDeadlineWakeResult {
    Sent,
    Coalesced,
}

impl VoiceDeadlineWakeResult {
    fn label(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Coalesced => "coalesced",
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum VoiceProactiveKind {
    Ordinary,
    Tail,
}

impl VoiceProactiveKind {
    fn label(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Tail => "tail",
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum VoiceProactiveResult {
    Queued,
    Sent,
    QueueBudgetShed,
    CreditShed,
    QueueShed,
    SendFailed,
}

impl VoiceProactiveResult {
    fn label(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sent => "sent",
            Self::QueueBudgetShed => "queue_budget_shed",
            Self::CreditShed => "credit_shed",
            Self::QueueShed => "queue_shed",
            Self::SendFailed => "send_failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum VoiceRepairResult {
    GapDetected,
    RequestScheduled,
    RequestSent,
    RequestFailed,
    RequestSuppressed,
    FrameServed,
    FrameSendFailed,
    FrameMissed,
    ProactiveCopySent,
    TailAckSent,
    TailAckReceived,
    TailRetrySent,
}

impl VoiceRepairResult {
    fn label(self) -> &'static str {
        match self {
            Self::GapDetected => "gap_detected",
            Self::RequestScheduled => "request_scheduled",
            Self::RequestSent => "request_sent",
            Self::RequestFailed => "request_failed",
            Self::RequestSuppressed => "request_suppressed",
            Self::FrameServed => "frame_served",
            Self::FrameSendFailed => "frame_send_failed",
            Self::FrameMissed => "frame_missed",
            Self::ProactiveCopySent => "proactive_copy_sent",
            Self::TailAckSent => "tail_ack_sent",
            Self::TailAckReceived => "tail_ack_received",
            Self::TailRetrySent => "tail_retry_sent",
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct SendKey {
    source: NodeIdentifier,
    mode: VoiceSendMode,
    dst_bucket: &'static str,
    bytes_bucket: &'static str,
    result: VoiceSendResult,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct ReceiveKey {
    source: NodeIdentifier,
    origin_node: NodeIdentifier,
    from_immediate: NodeIdentifier,
    result: VoiceReceiveResult,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct RepairKey {
    source: NodeIdentifier,
    peer: NodeIdentifier,
    result: VoiceRepairResult,
}

#[derive(Debug, Default)]
struct QueueBudget {
    capacity_bytes: u64,
    used_bytes: u64,
}

#[derive(Debug, Default)]
struct ProactiveBudget {
    queue_capacity_bytes: u64,
    queue_used_bytes: u64,
    credit_balance_bytes: u64,
    credit_cap_bytes: u64,
}

#[derive(Debug, Default)]
struct RepairCacheTelemetry {
    evictions: u64,
}

#[derive(Debug, Default)]
struct VoiceAppMetrics {
    sends: HashMap<SendKey, u64>,
    receives: HashMap<ReceiveKey, u64>,
    repairs: HashMap<RepairKey, u64>,
    reorder_pending: HashMap<NodeIdentifier, u64>,
    reorder_pending_buckets: HashMap<(NodeIdentifier, &'static str), u64>,
    ingress_admission_drops: HashMap<VoiceIngressClass, u64>,
    ingress_queue_budgets: HashMap<VoiceIngressClass, QueueBudget>,
    reorder_speaker_states: u64,
    reorder_speaker_cap: u64,
    deadline_wakes: HashMap<VoiceDeadlineWakeResult, u64>,
    proactive_budget: ProactiveBudget,
    proactive_outcomes: HashMap<(VoiceProactiveKind, VoiceProactiveResult), u64>,
    repair_cache: RepairCacheTelemetry,
}

pub(crate) fn record_send(
    source: NodeIdentifier,
    mode: VoiceSendMode,
    dst_count: usize,
    bytes: usize,
    result: VoiceSendResult,
) {
    let mut metrics = METRICS.lock().unwrap();
    let key = SendKey {
        source,
        mode,
        dst_bucket: bucket(&COUNT_BUCKETS, dst_count as u64),
        bytes_bucket: bucket(&BYTE_BUCKETS, bytes as u64),
        result,
    };
    *metrics.sends.entry(key).or_default() += 1;
}

pub(crate) fn record_receive(
    source: NodeIdentifier,
    origin_node: NodeIdentifier,
    from_immediate: NodeIdentifier,
    result: VoiceReceiveResult,
    count: usize,
) {
    if count == 0 {
        return;
    }
    let mut metrics = METRICS.lock().unwrap();
    let key = ReceiveKey {
        source,
        origin_node,
        from_immediate,
        result,
    };
    *metrics.receives.entry(key).or_default() += count as u64;
}

pub(crate) fn record_repair(
    source: NodeIdentifier,
    peer: NodeIdentifier,
    result: VoiceRepairResult,
    count: usize,
) {
    if count == 0 {
        return;
    }
    let mut metrics = METRICS.lock().unwrap();
    let key = RepairKey {
        source,
        peer,
        result,
    };
    *metrics.repairs.entry(key).or_default() += count as u64;
}

pub(crate) fn set_reorder_pending(source: NodeIdentifier, pending: usize) {
    let mut metrics = METRICS.lock().unwrap();
    metrics.reorder_pending.insert(source, pending as u64);
    let bucket = bucket(&COUNT_BUCKETS, pending as u64);
    *metrics
        .reorder_pending_buckets
        .entry((source, bucket))
        .or_default() += 1;
}

pub(crate) fn record_ingress_admission_drop(class: VoiceIngressClass) {
    let mut metrics = METRICS.lock().unwrap();
    *metrics.ingress_admission_drops.entry(class).or_default() += 1;
}

pub(crate) fn set_ingress_queue_budget(
    class: VoiceIngressClass,
    capacity_bytes: usize,
    used_bytes: usize,
) {
    let mut metrics = METRICS.lock().unwrap();
    let budget = metrics.ingress_queue_budgets.entry(class).or_default();
    budget.capacity_bytes = capacity_bytes as u64;
    budget.used_bytes = used_bytes as u64;
}

pub(crate) fn set_reorder_speaker_state(tracked: usize, cap: usize) {
    let mut metrics = METRICS.lock().unwrap();
    metrics.reorder_speaker_states = tracked as u64;
    metrics.reorder_speaker_cap = cap as u64;
}

pub(crate) fn record_deadline_wake(result: VoiceDeadlineWakeResult) {
    let mut metrics = METRICS.lock().unwrap();
    *metrics.deadline_wakes.entry(result).or_default() += 1;
}

pub(crate) fn set_proactive_queue_budget(capacity_bytes: usize, used_bytes: usize) {
    let mut metrics = METRICS.lock().unwrap();
    metrics.proactive_budget.queue_capacity_bytes = capacity_bytes as u64;
    metrics.proactive_budget.queue_used_bytes = used_bytes as u64;
}

pub(crate) fn set_proactive_credit(balance_bytes: usize, cap_bytes: usize) {
    let mut metrics = METRICS.lock().unwrap();
    metrics.proactive_budget.credit_balance_bytes = balance_bytes as u64;
    metrics.proactive_budget.credit_cap_bytes = cap_bytes as u64;
}

pub(crate) fn record_proactive_outcome(kind: VoiceProactiveKind, result: VoiceProactiveResult) {
    let mut metrics = METRICS.lock().unwrap();
    *metrics
        .proactive_outcomes
        .entry((kind, result))
        .or_default() += 1;
}

pub(crate) fn record_repair_cache_evictions(count: u64) {
    if count == 0 {
        return;
    }
    let mut metrics = METRICS.lock().unwrap();
    metrics.repair_cache.evictions = metrics.repair_cache.evictions.saturating_add(count);
}

pub(crate) fn prometheus_samples() -> Vec<PrometheusSample> {
    let (repair_cache_occupancy, repair_cache_capacity) = repair_cache_telemetry_snapshot();
    let metrics = METRICS.lock().unwrap();
    let mut out = Vec::new();

    for (key, count) in &metrics.sends {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_send_events_total",
            vec![
                ("source".to_owned(), key.source.to_string()),
                ("mode".to_owned(), key.mode.label().to_owned()),
                ("dst_bucket".to_owned(), key.dst_bucket.to_owned()),
                ("bytes_bucket".to_owned(), key.bytes_bucket.to_owned()),
                ("result".to_owned(), key.result.label().to_owned()),
            ],
            *count as f64,
        ));
    }

    for (key, count) in &metrics.receives {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_receive_events_total",
            vec![
                ("source".to_owned(), key.source.to_string()),
                ("origin_node".to_owned(), key.origin_node.to_string()),
                ("from_immediate".to_owned(), key.from_immediate.to_string()),
                ("result".to_owned(), key.result.label().to_owned()),
            ],
            *count as f64,
        ));
    }

    for (key, count) in &metrics.repairs {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_repair_events_total",
            vec![
                ("source".to_owned(), key.source.to_string()),
                ("peer".to_owned(), key.peer.to_string()),
                ("result".to_owned(), key.result.label().to_owned()),
            ],
            *count as f64,
        ));
    }

    for (source, pending) in &metrics.reorder_pending {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_reorder_pending",
            vec![("source".to_owned(), source.to_string())],
            *pending as f64,
        ));
    }
    for ((source, bucket), count) in &metrics.reorder_pending_buckets {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_reorder_pending_bucket_total",
            vec![
                ("source".to_owned(), source.to_string()),
                ("bucket".to_owned(), (*bucket).to_owned()),
            ],
            *count as f64,
        ));
    }

    for (class, count) in &metrics.ingress_admission_drops {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_ingress_admission_drops_total",
            vec![("class".to_owned(), class.label().to_owned())],
            *count as f64,
        ));
    }
    for (class, budget) in &metrics.ingress_queue_budgets {
        let labels = vec![("class".to_owned(), class.label().to_owned())];
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_ingress_queue_capacity_bytes",
            labels.clone(),
            budget.capacity_bytes as f64,
        ));
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_ingress_queue_used_bytes",
            labels,
            budget.used_bytes as f64,
        ));
    }
    out.push(PrometheusSample::new(
        "shitspeak_s2s_voice_reorder_speaker_states",
        Vec::new(),
        metrics.reorder_speaker_states as f64,
    ));
    out.push(PrometheusSample::new(
        "shitspeak_s2s_voice_reorder_speaker_cap",
        Vec::new(),
        metrics.reorder_speaker_cap as f64,
    ));
    for (result, count) in &metrics.deadline_wakes {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_deadline_wakes_total",
            vec![("result".to_owned(), result.label().to_owned())],
            *count as f64,
        ));
    }
    out.push(PrometheusSample::new(
        "shitspeak_s2s_voice_proactive_queue_capacity_bytes",
        Vec::new(),
        metrics.proactive_budget.queue_capacity_bytes as f64,
    ));
    out.push(PrometheusSample::new(
        "shitspeak_s2s_voice_proactive_queue_used_bytes",
        Vec::new(),
        metrics.proactive_budget.queue_used_bytes as f64,
    ));
    out.push(PrometheusSample::new(
        "shitspeak_s2s_voice_proactive_credit_balance_bytes",
        Vec::new(),
        metrics.proactive_budget.credit_balance_bytes as f64,
    ));
    out.push(PrometheusSample::new(
        "shitspeak_s2s_voice_proactive_credit_cap_bytes",
        Vec::new(),
        metrics.proactive_budget.credit_cap_bytes as f64,
    ));
    for ((kind, result), count) in &metrics.proactive_outcomes {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_proactive_events_total",
            vec![
                ("kind".to_owned(), kind.label().to_owned()),
                ("result".to_owned(), result.label().to_owned()),
            ],
            *count as f64,
        ));
    }
    out.push(PrometheusSample::new(
        "shitspeak_s2s_voice_repair_cache_occupancy",
        Vec::new(),
        repair_cache_occupancy as f64,
    ));
    out.push(PrometheusSample::new(
        "shitspeak_s2s_voice_repair_cache_capacity",
        Vec::new(),
        repair_cache_capacity as f64,
    ));
    out.push(PrometheusSample::new(
        "shitspeak_s2s_voice_repair_cache_evictions_total",
        Vec::new(),
        metrics.repair_cache.evictions as f64,
    ));

    out
}

fn bucket(definitions: &[(&'static str, u64)], value: u64) -> &'static str {
    definitions
        .iter()
        .find_map(|(label, upper)| (value <= *upper).then_some(*label))
        .unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_sample(name: &str, labels: &[(&str, &str)]) -> Option<crate::status::PrometheusSample> {
        prometheus_samples().into_iter().find(|sample| {
            sample.name() == name
                && labels.iter().all(|(key, value)| {
                    sample
                        .labels()
                        .iter()
                        .any(|(label_key, label_value)| label_key == key && label_value == value)
                })
        })
    }

    fn assert_no_unbounded_voice_labels(sample: &crate::status::PrometheusSample) {
        for forbidden in ["session", "user", "ip", "channel"] {
            assert!(
                sample
                    .labels()
                    .iter()
                    .all(|(label, _)| label.as_str() != forbidden),
                "{forbidden} label must not be exported on {}",
                sample.name()
            );
        }
    }

    #[test]
    fn send_metric_uses_bounded_labels() {
        record_send(
            4094,
            VoiceSendMode::Broadcast,
            3,
            900,
            VoiceSendResult::Sent,
        );
        let sample = find_sample(
            "shitspeak_s2s_voice_send_events_total",
            &[
                ("source", "4094"),
                ("mode", "broadcast"),
                ("dst_bucket", "2_4"),
                ("bytes_bucket", "le_1024"),
                ("result", "sent"),
            ],
        )
        .expect("send sample");

        assert_no_unbounded_voice_labels(&sample);
    }

    #[test]
    fn receive_repair_and_pending_metrics_use_bounded_labels() {
        record_receive(4094, 4093, 4092, VoiceReceiveResult::GapBuffered, 3);
        record_repair(4094, 4092, VoiceRepairResult::RequestSuppressed, 2);
        record_repair(4094, 4092, VoiceRepairResult::RequestFailed, 1);
        record_repair(4094, 4092, VoiceRepairResult::FrameSendFailed, 1);
        set_reorder_pending(4094, 9);

        let receive = find_sample(
            "shitspeak_s2s_voice_receive_events_total",
            &[
                ("source", "4094"),
                ("origin_node", "4093"),
                ("from_immediate", "4092"),
                ("result", "gap_buffered"),
            ],
        )
        .expect("receive sample");
        assert!(receive.value() >= 3.0);
        assert_no_unbounded_voice_labels(&receive);

        let repair = find_sample(
            "shitspeak_s2s_voice_repair_events_total",
            &[
                ("source", "4094"),
                ("peer", "4092"),
                ("result", "request_suppressed"),
            ],
        )
        .expect("repair sample");
        assert!(repair.value() >= 2.0);
        assert_no_unbounded_voice_labels(&repair);

        for result in ["request_failed", "frame_send_failed"] {
            let failure = find_sample(
                "shitspeak_s2s_voice_repair_events_total",
                &[("source", "4094"), ("peer", "4092"), ("result", result)],
            )
            .expect("explicit repair failure sample");
            assert!(failure.value() >= 1.0);
            assert_no_unbounded_voice_labels(&failure);
        }

        let pending = find_sample("shitspeak_s2s_voice_reorder_pending", &[("source", "4094")])
            .expect("pending gauge");
        assert_eq!(pending.value(), 9.0);
        assert_no_unbounded_voice_labels(&pending);

        let pending_bucket = find_sample(
            "shitspeak_s2s_voice_reorder_pending_bucket_total",
            &[("source", "4094"), ("bucket", "9_16")],
        )
        .expect("pending bucket");
        assert!(pending_bucket.value() >= 1.0);
        assert_no_unbounded_voice_labels(&pending_bucket);
    }

    #[test]
    fn adaptive_voice_protection_metrics_are_aggregate_and_bounded() {
        record_ingress_admission_drop(VoiceIngressClass::Primary);
        record_ingress_admission_drop(VoiceIngressClass::Proactive);
        set_ingress_queue_budget(VoiceIngressClass::Primary, 2_560_000, 524_288);
        set_ingress_queue_budget(VoiceIngressClass::Proactive, 320_000, 65_536);
        set_reorder_speaker_state(10_000, 10_000);
        record_deadline_wake(VoiceDeadlineWakeResult::Sent);
        record_deadline_wake(VoiceDeadlineWakeResult::Coalesced);
        set_proactive_queue_budget(320_000, 65_536);
        set_proactive_credit(32_768, 80_000);
        record_repair_cache_evictions(3);
        record_proactive_outcome(VoiceProactiveKind::Ordinary, VoiceProactiveResult::Queued);
        record_proactive_outcome(VoiceProactiveKind::Ordinary, VoiceProactiveResult::Sent);
        record_proactive_outcome(
            VoiceProactiveKind::Ordinary,
            VoiceProactiveResult::QueueBudgetShed,
        );
        record_proactive_outcome(
            VoiceProactiveKind::Ordinary,
            VoiceProactiveResult::CreditShed,
        );
        record_proactive_outcome(
            VoiceProactiveKind::Ordinary,
            VoiceProactiveResult::QueueShed,
        );
        record_proactive_outcome(
            VoiceProactiveKind::Ordinary,
            VoiceProactiveResult::SendFailed,
        );
        record_proactive_outcome(VoiceProactiveKind::Tail, VoiceProactiveResult::Sent);

        let primary_drop = find_sample(
            "shitspeak_s2s_voice_ingress_admission_drops_total",
            &[("class", "primary")],
        )
        .expect("primary admission drop");
        assert!(primary_drop.value() >= 1.0);
        assert_eq!(
            primary_drop.labels(),
            &[("class".to_owned(), "primary".to_owned())]
        );

        let proactive_capacity = find_sample(
            "shitspeak_s2s_voice_ingress_queue_capacity_bytes",
            &[("class", "proactive")],
        )
        .expect("proactive queue capacity");
        // Gauges are shared process-wide with asynchronous voice tests, so
        // their current value may have been refreshed by another service.
        // This test verifies the bounded aggregate dimension instead.
        assert!(proactive_capacity.value() >= 0.0);
        assert_eq!(
            proactive_capacity.labels(),
            &[("class".to_owned(), "proactive".to_owned())]
        );

        let speaker_states = find_sample("shitspeak_s2s_voice_reorder_speaker_states", &[])
            .expect("speaker state gauge");
        assert!(speaker_states.value() >= 0.0);
        assert!(speaker_states.labels().is_empty());
        let speaker_cap =
            find_sample("shitspeak_s2s_voice_reorder_speaker_cap", &[]).expect("speaker cap gauge");
        assert!(speaker_cap.value() >= 0.0);
        assert!(speaker_cap.labels().is_empty());

        let coalesced = find_sample(
            "shitspeak_s2s_voice_deadline_wakes_total",
            &[("result", "coalesced")],
        )
        .expect("coalesced deadline wake");
        assert!(coalesced.value() >= 1.0);
        assert_eq!(
            coalesced.labels(),
            &[("result".to_owned(), "coalesced".to_owned())]
        );

        let credit_cap = find_sample("shitspeak_s2s_voice_proactive_credit_cap_bytes", &[])
            .expect("proactive credit cap");
        assert!(credit_cap.value() >= 0.0);
        assert!(credit_cap.labels().is_empty());
        let proactive_sent = find_sample(
            "shitspeak_s2s_voice_proactive_events_total",
            &[("kind", "ordinary"), ("result", "sent")],
        )
        .expect("proactive sent outcome");
        assert!(proactive_sent.value() >= 1.0);
        assert_eq!(
            proactive_sent.labels(),
            &[
                ("kind".to_owned(), "ordinary".to_owned()),
                ("result".to_owned(), "sent".to_owned()),
            ]
        );
        for result in ["queue_budget_shed", "credit_shed"] {
            let shed = find_sample(
                "shitspeak_s2s_voice_proactive_events_total",
                &[("kind", "ordinary"), ("result", result)],
            )
            .expect("distinct proactive budget outcome");
            assert!(shed.value() >= 1.0);
        }
        let tail_sent = find_sample(
            "shitspeak_s2s_voice_proactive_events_total",
            &[("kind", "tail"), ("result", "sent")],
        )
        .expect("tail proactive outcome");
        assert!(tail_sent.value() >= 1.0);

        let repair_cache_occupancy = find_sample("shitspeak_s2s_voice_repair_cache_occupancy", &[])
            .expect("repair cache occupancy");
        assert!(repair_cache_occupancy.value() >= 0.0);
        assert!(repair_cache_occupancy.labels().is_empty());
        let repair_cache_capacity = find_sample("shitspeak_s2s_voice_repair_cache_capacity", &[])
            .expect("repair cache capacity");
        assert!(repair_cache_capacity.value() >= 0.0);
        let repair_cache_evictions =
            find_sample("shitspeak_s2s_voice_repair_cache_evictions_total", &[])
                .expect("repair cache evictions");
        assert!(repair_cache_evictions.value() >= 0.0);

        for sample in prometheus_samples().into_iter().filter(|sample| {
            sample.name().starts_with("shitspeak_s2s_voice_ingress_")
                || sample.name().starts_with("shitspeak_s2s_voice_proactive_")
                || sample.name().starts_with("shitspeak_s2s_voice_deadline_")
                || sample
                    .name()
                    .starts_with("shitspeak_s2s_voice_reorder_speaker_")
        }) {
            assert_no_unbounded_voice_labels(&sample);
        }
    }

    #[test]
    fn speaker_state_drop_is_exported_as_a_receive_outcome() {
        record_receive(4094, 4093, 4092, VoiceReceiveResult::SpeakerStateDrop, 1);
        let drop = find_sample(
            "shitspeak_s2s_voice_receive_events_total",
            &[
                ("source", "4094"),
                ("origin_node", "4093"),
                ("from_immediate", "4092"),
                ("result", "speaker_state_drop"),
            ],
        )
        .expect("speaker state drop");
        assert!(drop.value() >= 1.0);
    }
}
