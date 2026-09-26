use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use shitspeak_core::NodeIdentifier;

use crate::application::voice::fec::{FecParityPath, FecSendOutcome};
use crate::application::voice::reorder::{ReorderResultCount, VoiceCopyKind};
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

/// How long after the reorder released past a sequence a copy of it arrived,
/// in milliseconds. A listener's jitter buffer is at most a few packet periods
/// deep, so the low buckets say what a longer server wait (or forwarding the
/// late copy) could still have saved.
const LATE_ARRIVAL_MS_BUCKETS: [(&str, u64); 8] = [
    ("le_10", 10),
    ("le_20", 20),
    ("le_40", 40),
    ("le_80", 80),
    ("le_160", 160),
    ("le_320", 320),
    ("le_640", 640),
    ("gt_640", u64::MAX),
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
    /// A frame the reorder rejected without delivering it, with why and which
    /// kind of copy arrived. Exported as `result="duplicate_or_late"` plus
    /// `reason` and `copy` labels.
    DuplicateOrLate {
        reason: DuplicateReason,
        copy: VoiceCopyKind,
    },
    DeadlineFlush,
    BufferDrop,
    NoSinkDrop,
    SpeakerStateDrop,
    /// A FEC reconstruction emitted out of order into a hole the reorder had
    /// already released past.
    FecLate,
}

impl VoiceReceiveResult {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::InOrder => "in_order",
            Self::GapBuffered => "gap_buffered",
            Self::GapFilled => "gap_filled",
            Self::DuplicateOrLate { .. } => "duplicate_or_late",
            Self::DeadlineFlush => "deadline_flush",
            Self::BufferDrop => "buffer_drop",
            Self::NoSinkDrop => "no_sink_drop",
            Self::SpeakerStateDrop => "speaker_state_drop",
            Self::FecLate => "fec_late",
        }
    }
}

/// Why the reorder rejected a frame without delivering it.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum DuplicateReason {
    /// From an older sender epoch, or a non-original copy of a newer one
    /// (only an original may restart a stream).
    StaleEpoch,
    /// A repair copy (overlay tree repair, or an older peer's reactive
    /// repair) for a speaker with no stream state.
    RepairWithoutStream,
    /// A repair copy while no gap was open.
    RepairWithoutGap,
    /// An equal or better copy of the same sequence was already buffered.
    AlreadyBuffered,
    /// Arrived after a deadline flush released past its sequence without it:
    /// genuinely late, the listener never received it.
    LateAfterRelease,
    /// The sequence was already delivered, by a copy of this kind.
    AlreadyDelivered(VoiceCopyKind),
    /// Below the delivery cursor but older than the delivery history.
    Untracked,
}

impl DuplicateReason {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::StaleEpoch => "stale_epoch",
            Self::RepairWithoutStream => "repair_without_stream",
            Self::RepairWithoutGap => "repair_without_gap",
            Self::AlreadyBuffered => "already_buffered",
            Self::LateAfterRelease => "late_after_release",
            Self::AlreadyDelivered(VoiceCopyKind::Original) => "delivered_original",
            Self::AlreadyDelivered(VoiceCopyKind::Proactive) => "delivered_proactive",
            Self::AlreadyDelivered(VoiceCopyKind::Fec) => "delivered_fec",
            Self::AlreadyDelivered(VoiceCopyKind::ReactiveRepair) => "delivered_repair",
            Self::Untracked => "untracked",
        }
    }
}

/// Where a FEC-reconstructed frame ended up in the reorder.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum FecRecoveryOutcome {
    /// Emitted or buffered before the reorder released past its sequence.
    InTime,
    /// Emitted out of order into an already released hole.
    Late,
    /// Rejected by the reorder (duplicate, too late, or buffer limits).
    Discarded,
}

impl FecRecoveryOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::InTime => "in_time",
            Self::Late => "late",
            Self::Discarded => "discarded",
        }
    }
}

/// How an armed reorder gap was ultimately resolved.
///
/// This is the split-mode decision metric: it measures what fraction of loss
/// events the *duplicate* path (or another repair mechanism) actually covers.
/// `duplicate` covers both a delayed/reordered primary frame and the split's
/// redundant copy — the reorder layer cannot tell them apart, both arrive as
/// `VoiceCopyKind::Original`. `fec` is reserved for change-set C3.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum GapResolution {
    Duplicate,
    Proactive,
    Reactive,
    Fec,
    Timeout,
}

impl GapResolution {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Duplicate => "duplicate",
            Self::Proactive => "proactive",
            Self::Reactive => "reactive",
            Self::Fec => "fec",
            Self::Timeout => "timeout",
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
}

impl VoiceProactiveKind {
    fn label(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
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

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum RepairCreditStage {
    Minted,
    Reserved,
    Committed,
    Refunded,
    CapDiscarded,
}

impl RepairCreditStage {
    fn label(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::Reserved => "reserved",
            Self::Committed => "committed",
            Self::Refunded => "refunded",
            Self::CapDiscarded => "cap_discarded",
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum RepairClassStage {
    Granted,
    Attempted,
    Sent,
    Shed,
}

impl RepairClassStage {
    fn label(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Attempted => "attempted",
            Self::Sent => "sent",
            Self::Shed => "shed",
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum RepairDestinationStage {
    Requested,
    PrivateGrant,
    OverflowGrant,
    Attempted,
    Sent,
    Shed,
}

impl RepairDestinationStage {
    fn label(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::PrivateGrant => "private_grant",
            Self::OverflowGrant => "overflow_grant",
            Self::Attempted => "attempted",
            Self::Sent => "sent",
            Self::Shed => "shed",
        }
    }
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
    ProactiveCopySent,
}

impl VoiceRepairResult {
    fn label(self) -> &'static str {
        match self {
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

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct FecSendKey {
    source: NodeIdentifier,
    first_hop: NodeIdentifier,
    outcome: FecSendOutcome,
    path: FecParityPath,
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
struct RepairAllocatorState {
    proactive_balance_bytes: u64,
    active_destinations: u64,
}

#[derive(Debug, Default)]
struct VoiceAppMetrics {
    sends: HashMap<SendKey, u64>,
    receives: HashMap<ReceiveKey, u64>,
    repairs: HashMap<RepairKey, u64>,
    reorder_pending: HashMap<NodeIdentifier, u64>,
    reorder_pending_buckets: HashMap<(NodeIdentifier, &'static str), u64>,
    reorder_held_frames: u64,
    reorder_max_held_delay_us: u64,
    ingress_admission_drops: HashMap<VoiceIngressClass, u64>,
    ingress_queue_budgets: HashMap<VoiceIngressClass, QueueBudget>,
    reorder_speaker_states: u64,
    reorder_speaker_cap: u64,
    deadline_wakes: HashMap<VoiceDeadlineWakeResult, u64>,
    gap_resolutions: HashMap<GapResolution, u64>,
    fec_sends: HashMap<FecSendKey, u64>,
    fec_send_bytes: HashMap<(NodeIdentifier, FecSendOutcome, FecParityPath), u64>,
    fec_recoveries: HashMap<FecRecoveryOutcome, u64>,
    gaps_opened: HashMap<&'static str, u64>,
    late_arrivals: HashMap<(VoiceCopyKind, &'static str), u64>,
    proactive_budget: ProactiveBudget,
    proactive_outcomes: HashMap<(VoiceProactiveKind, VoiceProactiveResult), u64>,
    repair_credit_quarters: HashMap<RepairCreditStage, u64>,
    repair_class_bytes: HashMap<RepairClassStage, u64>,
    repair_destination_bytes: HashMap<(NodeIdentifier, RepairDestinationStage), u64>,
    repair_allocator_state: RepairAllocatorState,
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

/// Record one parity send. `first_hop` is the data frames' first hop; `path`
/// says whether the parity rode it or the route's alternate.
pub(crate) fn record_fec_send(
    source: NodeIdentifier,
    first_hop: NodeIdentifier,
    bytes: usize,
    outcome: FecSendOutcome,
    path: FecParityPath,
) {
    let mut metrics = METRICS.lock().unwrap();
    let key = FecSendKey {
        source,
        first_hop,
        outcome,
        path,
    };
    *metrics.fec_sends.entry(key).or_default() += 1;
    *metrics
        .fec_send_bytes
        .entry((source, outcome, path))
        .or_default() += bytes as u64;
}

/// Record a receiver reorder gap opening over `missing_frames` consecutive
/// sequences: the loss-run length seen on arrival, the burstiness signal
/// behind the FEC's pacing and path diversity.
pub(crate) fn record_gap_opened(missing_frames: u64) {
    let mut metrics = METRICS.lock().unwrap();
    *metrics
        .gaps_opened
        .entry(bucket(&COUNT_BUCKETS, missing_frames))
        .or_default() += 1;
}

/// Record a copy of a sequence arriving `after_release` after the reorder had
/// already released past it.
pub(crate) fn record_late_arrival(copy: VoiceCopyKind, after_release: Duration) {
    let millis = u64::try_from(after_release.as_millis()).unwrap_or(u64::MAX);
    let mut metrics = METRICS.lock().unwrap();
    *metrics
        .late_arrivals
        .entry((copy, bucket(&LATE_ARRIVAL_MS_BUCKETS, millis)))
        .or_default() += 1;
}

/// Classify one reconstructed frame by the reorder results its push produced.
pub(crate) fn record_fec_recovery(results: &[ReorderResultCount]) {
    let has = |wanted: VoiceReceiveResult| results.iter().any(|r| r.result() == wanted);
    let outcome = if has(VoiceReceiveResult::FecLate) {
        FecRecoveryOutcome::Late
    } else if has(VoiceReceiveResult::InOrder) || has(VoiceReceiveResult::GapBuffered) {
        FecRecoveryOutcome::InTime
    } else {
        FecRecoveryOutcome::Discarded
    };
    let mut metrics = METRICS.lock().unwrap();
    *metrics.fec_recoveries.entry(outcome).or_default() += 1;
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

/// Aggregate held-delay signal: how many frames are currently held beyond the
/// in-order skew tolerance waiting for a repair, and the longest such hold.
pub(crate) fn set_reorder_held(held_frames: usize, max_held_delay_us: u64) {
    let mut metrics = METRICS.lock().unwrap();
    metrics.reorder_held_frames = held_frames as u64;
    metrics.reorder_max_held_delay_us = max_held_delay_us;
}

pub(crate) fn record_deadline_wake(result: VoiceDeadlineWakeResult) {
    let mut metrics = METRICS.lock().unwrap();
    *metrics.deadline_wakes.entry(result).or_default() += 1;
}

/// Record how an armed reorder gap was resolved (or lost). See
/// [`GapResolution`].
pub(crate) fn record_gap_resolution(resolution: GapResolution) {
    let mut metrics = METRICS.lock().unwrap();
    *metrics.gap_resolutions.entry(resolution).or_default() += 1;
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

pub(crate) fn record_repair_credit_quarters(stage: RepairCreditStage, quarters: usize) {
    if quarters == 0 {
        return;
    }
    let mut metrics = METRICS.lock().unwrap();
    let total = metrics.repair_credit_quarters.entry(stage).or_default();
    *total = total.saturating_add(quarters as u64);
}

pub(crate) fn record_repair_class_bytes(stage: RepairClassStage, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let mut metrics = METRICS.lock().unwrap();
    let total = metrics.repair_class_bytes.entry(stage).or_default();
    *total = total.saturating_add(bytes as u64);
}

/// Records per-destination allocator work. `NodeIdentifier` is a bounded u16
/// cluster identity, unlike session, user, address, or channel identifiers.
pub(crate) fn record_repair_destination_bytes(
    peer: NodeIdentifier,
    stage: RepairDestinationStage,
    bytes: usize,
) {
    if bytes == 0 {
        return;
    }
    let mut metrics = METRICS.lock().unwrap();
    let total = metrics
        .repair_destination_bytes
        .entry((peer, stage))
        .or_default();
    *total = total.saturating_add(bytes as u64);
}

pub(crate) fn set_repair_allocator_state(
    proactive_balance_bytes: usize,
    active_destinations: usize,
) {
    let mut metrics = METRICS.lock().unwrap();
    metrics.repair_allocator_state = RepairAllocatorState {
        proactive_balance_bytes: proactive_balance_bytes as u64,
        active_destinations: active_destinations as u64,
    };
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
        let mut labels = vec![
            ("source".to_owned(), key.source.to_string()),
            ("origin_node".to_owned(), key.origin_node.to_string()),
            ("from_immediate".to_owned(), key.from_immediate.to_string()),
            ("result".to_owned(), key.result.label().to_owned()),
        ];
        if let VoiceReceiveResult::DuplicateOrLate { reason, copy } = key.result {
            labels.push(("reason".to_owned(), reason.label().to_owned()));
            labels.push(("copy".to_owned(), copy.label().to_owned()));
        }
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_receive_events_total",
            labels,
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
        "shitspeak_s2s_voice_reorder_held_frames",
        Vec::new(),
        metrics.reorder_held_frames as f64,
    ));
    out.push(PrometheusSample::new(
        "shitspeak_s2s_voice_reorder_max_held_delay_microseconds",
        Vec::new(),
        metrics.reorder_max_held_delay_us as f64,
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
    for ((copy, bucket), count) in &metrics.late_arrivals {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_late_arrival_after_release_bucket_total",
            vec![
                ("copy".to_owned(), copy.label().to_owned()),
                ("bucket".to_owned(), (*bucket).to_owned()),
            ],
            *count as f64,
        ));
    }
    for (resolution, count) in &metrics.gap_resolutions {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_reorder_gap_resolution_total",
            vec![("resolution".to_owned(), resolution.label().to_owned())],
            *count as f64,
        ));
    }
    for (key, count) in &metrics.fec_sends {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_fec_sends_total",
            vec![
                ("source".to_owned(), key.source.to_string()),
                ("first_hop".to_owned(), key.first_hop.to_string()),
                (
                    "outcome".to_owned(),
                    match key.outcome {
                        FecSendOutcome::Sent => "sent".to_owned(),
                        FecSendOutcome::Shed => "shed".to_owned(),
                    },
                ),
                ("path".to_owned(), key.path.label().to_owned()),
            ],
            *count as f64,
        ));
    }
    for ((source, outcome, path), bytes) in &metrics.fec_send_bytes {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_fec_send_bytes_total",
            vec![
                ("source".to_owned(), source.to_string()),
                (
                    "outcome".to_owned(),
                    match outcome {
                        FecSendOutcome::Sent => "sent".to_owned(),
                        FecSendOutcome::Shed => "shed".to_owned(),
                    },
                ),
                ("path".to_owned(), path.label().to_owned()),
            ],
            *bytes as f64,
        ));
    }
    for (missing_frames, count) in &metrics.gaps_opened {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_reorder_gaps_opened_total",
            vec![("missing_frames".to_owned(), (*missing_frames).to_owned())],
            *count as f64,
        ));
    }
    for (outcome, count) in &metrics.fec_recoveries {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_fec_recovered_frames_total",
            vec![("outcome".to_owned(), outcome.label().to_owned())],
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
    for (stage, quarters) in &metrics.repair_credit_quarters {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_repair_credit_bytes_total",
            vec![("stage".to_owned(), stage.label().to_owned())],
            *quarters as f64 / 4.0,
        ));
    }
    for (stage, bytes) in &metrics.repair_class_bytes {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_repair_allocator_class_bytes_total",
            vec![
                ("class".to_owned(), "proactive".to_owned()),
                ("stage".to_owned(), stage.label().to_owned()),
            ],
            *bytes as f64,
        ));
    }
    for ((peer, stage), bytes) in &metrics.repair_destination_bytes {
        out.push(PrometheusSample::new(
            "shitspeak_s2s_voice_repair_allocator_destination_bytes_total",
            vec![
                ("peer".to_owned(), peer.to_string()),
                ("stage".to_owned(), stage.label().to_owned()),
            ],
            *bytes as f64,
        ));
    }
    let allocator = &metrics.repair_allocator_state;
    out.push(PrometheusSample::new(
        "shitspeak_s2s_voice_repair_allocator_state_bytes",
        vec![("state".to_owned(), "proactive_balance".to_owned())],
        allocator.proactive_balance_bytes as f64,
    ));
    out.push(PrometheusSample::new(
        "shitspeak_s2s_voice_repair_allocator_active_destinations",
        Vec::new(),
        allocator.active_destinations as f64,
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
        record_repair(4094, 4092, VoiceRepairResult::ProactiveCopySent, 2);
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
                ("result", "proactive_copy_sent"),
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

    #[test]
    fn gap_resolution_metric_is_bounded_and_counts_each_kind() {
        // The reorder path records these same labels through the production
        // hooks, so other tests share the static counter. Assert the delta this
        // test produced rather than an absolute total.
        let count_before = |resolution: GapResolution| {
            find_sample(
                "shitspeak_s2s_voice_reorder_gap_resolution_total",
                &[("resolution", resolution.label())],
            )
            .map(|sample| sample.value())
            .unwrap_or(0.0)
        };

        for (resolution, count) in [
            (GapResolution::Duplicate, 3),
            (GapResolution::Proactive, 2),
            (GapResolution::Reactive, 1),
            (GapResolution::Timeout, 4),
        ] {
            let before = count_before(resolution);
            for _ in 0..count {
                record_gap_resolution(resolution);
            }
            let sample = find_sample(
                "shitspeak_s2s_voice_reorder_gap_resolution_total",
                &[("resolution", resolution.label())],
            )
            .expect("gap resolution sample");
            assert_eq!(sample.value(), before + count as f64);
            assert_no_unbounded_voice_labels(&sample);
        }
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
    fn duplicate_or_late_is_exported_with_reason_and_copy_labels() {
        for (reason, copy, reason_label, copy_label) in [
            (
                DuplicateReason::AlreadyDelivered(VoiceCopyKind::Fec),
                VoiceCopyKind::Original,
                "delivered_fec",
                "original",
            ),
            (
                DuplicateReason::LateAfterRelease,
                VoiceCopyKind::ReactiveRepair,
                "late_after_release",
                "repair",
            ),
        ] {
            record_receive(
                4094,
                4093,
                4092,
                VoiceReceiveResult::DuplicateOrLate { reason, copy },
                2,
            );
            let sample = find_sample(
                "shitspeak_s2s_voice_receive_events_total",
                &[
                    ("source", "4094"),
                    ("origin_node", "4093"),
                    ("from_immediate", "4092"),
                    ("result", "duplicate_or_late"),
                    ("reason", reason_label),
                    ("copy", copy_label),
                ],
            )
            .expect("duplicate sample with reason and copy");
            assert!(sample.value() >= 2.0);
            assert_no_unbounded_voice_labels(&sample);
        }
        // Other results carry neither label.
        record_receive(4094, 4093, 4092, VoiceReceiveResult::InOrder, 1);
        let in_order = find_sample(
            "shitspeak_s2s_voice_receive_events_total",
            &[
                ("source", "4094"),
                ("origin_node", "4093"),
                ("from_immediate", "4092"),
                ("result", "in_order"),
            ],
        )
        .expect("in-order sample");
        assert!(
            in_order
                .labels()
                .iter()
                .all(|(key, _)| key != "reason" && key != "copy")
        );
    }

    #[test]
    fn late_arrivals_are_bucketed_by_copy_and_delay_after_release() {
        let count = |copy: &str, bucket: &str| {
            find_sample(
                "shitspeak_s2s_voice_late_arrival_after_release_bucket_total",
                &[("copy", copy), ("bucket", bucket)],
            )
            .map_or(0.0, |sample| sample.value())
        };
        let before_10 = count("original", "le_10");
        let before_80 = count("fec", "le_80");
        let before_gt = count("proactive", "gt_640");
        record_late_arrival(VoiceCopyKind::Original, Duration::from_millis(10));
        record_late_arrival(VoiceCopyKind::Fec, Duration::from_millis(41));
        record_late_arrival(VoiceCopyKind::Proactive, Duration::from_millis(641));
        assert!(count("original", "le_10") >= before_10 + 1.0);
        assert!(count("fec", "le_80") >= before_80 + 1.0);
        assert!(count("proactive", "gt_640") >= before_gt + 1.0);
        let sample = find_sample(
            "shitspeak_s2s_voice_late_arrival_after_release_bucket_total",
            &[("copy", "original"), ("bucket", "le_10")],
        )
        .expect("late arrival sample");
        assert_no_unbounded_voice_labels(&sample);
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

    #[test]
    fn repair_allocator_metrics_use_fixed_stage_and_bounded_peer_labels() {
        record_repair_credit_quarters(RepairCreditStage::Minted, 4_001);
        record_repair_credit_quarters(RepairCreditStage::Reserved, 2_800);
        record_repair_credit_quarters(RepairCreditStage::Committed, 2_400);
        record_repair_credit_quarters(RepairCreditStage::Refunded, 400);
        record_repair_credit_quarters(RepairCreditStage::CapDiscarded, 800);
        record_repair_class_bytes(RepairClassStage::Granted, 50);
        record_repair_class_bytes(RepairClassStage::Attempted, 75);
        record_repair_destination_bytes(3, RepairDestinationStage::Requested, 100);
        record_repair_destination_bytes(4, RepairDestinationStage::PrivateGrant, 75);
        record_repair_destination_bytes(15, RepairDestinationStage::OverflowGrant, 50);
        set_repair_allocator_state(700, 64);

        let minted = find_sample(
            "shitspeak_s2s_voice_repair_credit_bytes_total",
            &[("stage", "minted")],
        )
        .expect("minted repair credit");
        assert!(minted.value() >= 1_000.25);
        assert_no_unbounded_voice_labels(&minted);

        let granted = find_sample(
            "shitspeak_s2s_voice_repair_allocator_class_bytes_total",
            &[("class", "proactive"), ("stage", "granted")],
        )
        .expect("proactive grant");
        assert!(granted.value() >= 50.0);

        let requested = find_sample(
            "shitspeak_s2s_voice_repair_allocator_destination_bytes_total",
            &[("peer", "3"), ("stage", "requested")],
        )
        .expect("destination request");
        assert!(requested.value() >= 100.0);
        assert_no_unbounded_voice_labels(&requested);

        let balance = find_sample(
            "shitspeak_s2s_voice_repair_allocator_state_bytes",
            &[("state", "proactive_balance")],
        )
        .expect("proactive balance state");
        // Allocator gauges are process-global and asynchronous voice tests
        // may refresh them concurrently. This test verifies stable bounded
        // dimensions; exact state transitions are covered by budget tests.
        assert!(balance.value() >= 0.0);
        let destinations = find_sample(
            "shitspeak_s2s_voice_repair_allocator_active_destinations",
            &[],
        )
        .expect("active allocator destinations");
        assert!(destinations.value() >= 0.0);
    }
}
