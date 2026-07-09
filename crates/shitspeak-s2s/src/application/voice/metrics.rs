use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

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
    EpochReset,
    DeadlineFlush,
    BufferDrop,
    NoSinkDrop,
}

impl VoiceReceiveResult {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::InOrder => "in_order",
            Self::GapBuffered => "gap_buffered",
            Self::GapFilled => "gap_filled",
            Self::DuplicateOrLate => "duplicate_or_late",
            Self::EpochReset => "epoch_reset",
            Self::DeadlineFlush => "deadline_flush",
            Self::BufferDrop => "buffer_drop",
            Self::NoSinkDrop => "no_sink_drop",
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum VoiceRepairResult {
    GapDetected,
    RequestScheduled,
    RequestSent,
    RequestSuppressed,
    FrameServed,
    FrameMissed,
    ProactiveCopySent,
}

impl VoiceRepairResult {
    fn label(self) -> &'static str {
        match self {
            Self::GapDetected => "gap_detected",
            Self::RequestScheduled => "request_scheduled",
            Self::RequestSent => "request_sent",
            Self::RequestSuppressed => "request_suppressed",
            Self::FrameServed => "frame_served",
            Self::FrameMissed => "frame_missed",
            Self::ProactiveCopySent => "proactive_copy_sent",
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
struct VoiceAppMetrics {
    sends: HashMap<SendKey, u64>,
    receives: HashMap<ReceiveKey, u64>,
    repairs: HashMap<RepairKey, u64>,
    reorder_pending: HashMap<NodeIdentifier, u64>,
    reorder_pending_buckets: HashMap<(NodeIdentifier, &'static str), u64>,
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

pub(crate) fn prometheus_samples() -> Vec<PrometheusSample> {
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
}
