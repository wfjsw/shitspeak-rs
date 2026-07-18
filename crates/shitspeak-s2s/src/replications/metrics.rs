use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::Duration;

use crate::status::PrometheusSample;

#[derive(Clone, Copy)]
pub(crate) enum CatchupMode {
    Strict,
    Owner,
}

impl CatchupMode {
    fn index(self) -> usize {
        match self {
            Self::Strict => 0,
            Self::Owner => 1,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Owner => "owner",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ReplicationPipelineKind {
    Strict,
    Owner,
    Blob,
    Unknown,
}

impl ReplicationPipelineKind {
    fn index(self) -> usize {
        match self {
            Self::Strict => 0,
            Self::Owner => 1,
            Self::Blob => 2,
            Self::Unknown => 3,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Owner => "owner",
            Self::Blob => "blob",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ReplicationPipelineStage {
    InboundDecode,
    Dispatch,
    ProtobufEncode,
    CatchupBuild,
    CatchupApply,
    MsgpackEncode,
    MsgpackDecode,
    RepoApply,
    SnapshotInstall,
    BlobReassemble,
    BlobHash,
    BlobStore,
}

/// Terminal outcome chosen for a stalled strict proposal.
///
/// The labels intentionally describe only the bounded protocol outcome; topic
/// and operation identifiers would create unbounded Prometheus cardinality.
#[derive(Clone, Copy)]
pub(crate) enum StrictResolutionOutcome {
    Commit,
    Abort,
}

impl StrictResolutionOutcome {
    fn index(self) -> usize {
        match self {
            Self::Commit => 0,
            Self::Abort => 1,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Abort => "abort",
        }
    }
}

impl ReplicationPipelineStage {
    fn index(self) -> usize {
        match self {
            Self::InboundDecode => 0,
            Self::Dispatch => 1,
            Self::ProtobufEncode => 2,
            Self::CatchupBuild => 3,
            Self::CatchupApply => 4,
            Self::MsgpackEncode => 5,
            Self::MsgpackDecode => 6,
            Self::RepoApply => 7,
            Self::SnapshotInstall => 8,
            Self::BlobReassemble => 9,
            Self::BlobHash => 10,
            Self::BlobStore => 11,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::InboundDecode => "inbound_decode",
            Self::Dispatch => "dispatch",
            Self::ProtobufEncode => "protobuf_encode",
            Self::CatchupBuild => "catchup_build",
            Self::CatchupApply => "catchup_apply",
            Self::MsgpackEncode => "msgpack_encode",
            Self::MsgpackDecode => "msgpack_decode",
            Self::RepoApply => "repo_apply",
            Self::SnapshotInstall => "snapshot_install",
            Self::BlobReassemble => "blob_reassemble",
            Self::BlobHash => "blob_hash",
            Self::BlobStore => "blob_store",
        }
    }
}

const CATCHUP_MODE_COUNT: usize = 2;
const REPLICATION_PIPELINE_KIND_COUNT: usize = 4;
const REPLICATION_PIPELINE_STAGE_COUNT: usize = 12;
const STRICT_RESOLUTION_OUTCOME_COUNT: usize = 2;
const REPLICATION_PIPELINE_KINDS: [ReplicationPipelineKind; REPLICATION_PIPELINE_KIND_COUNT] = [
    ReplicationPipelineKind::Strict,
    ReplicationPipelineKind::Owner,
    ReplicationPipelineKind::Blob,
    ReplicationPipelineKind::Unknown,
];
const REPLICATION_PIPELINE_STAGES: [ReplicationPipelineStage; REPLICATION_PIPELINE_STAGE_COUNT] = [
    ReplicationPipelineStage::InboundDecode,
    ReplicationPipelineStage::Dispatch,
    ReplicationPipelineStage::ProtobufEncode,
    ReplicationPipelineStage::CatchupBuild,
    ReplicationPipelineStage::CatchupApply,
    ReplicationPipelineStage::MsgpackEncode,
    ReplicationPipelineStage::MsgpackDecode,
    ReplicationPipelineStage::RepoApply,
    ReplicationPipelineStage::SnapshotInstall,
    ReplicationPipelineStage::BlobReassemble,
    ReplicationPipelineStage::BlobHash,
    ReplicationPipelineStage::BlobStore,
];
const CLIENT_QUEUE_BUCKETS_US: [(&str, u64); 7] = [
    ("le_1000", 1_000),
    ("le_10000", 10_000),
    ("le_50000", 50_000),
    ("le_250000", 250_000),
    ("le_1000000", 1_000_000),
    ("le_5000000", 5_000_000),
    ("gt_5000000", u64::MAX),
];

static CATCHUP_REQUESTS: [AtomicU64; CATCHUP_MODE_COUNT] =
    [const { AtomicU64::new(0) }; CATCHUP_MODE_COUNT];
static CATCHUP_RESPONSES: [AtomicU64; CATCHUP_MODE_COUNT] =
    [const { AtomicU64::new(0) }; CATCHUP_MODE_COUNT];
static CATCHUP_RESPONSE_OPS: [AtomicU64; CATCHUP_MODE_COUNT] =
    [const { AtomicU64::new(0) }; CATCHUP_MODE_COUNT];
static CATCHUP_RESPONSE_BYTES: [AtomicU64; CATCHUP_MODE_COUNT] =
    [const { AtomicU64::new(0) }; CATCHUP_MODE_COUNT];
static CATCHUP_SUPPRESSED: [AtomicU64; CATCHUP_MODE_COUNT] =
    [const { AtomicU64::new(0) }; CATCHUP_MODE_COUNT];
static CATCHUP_ACTIVE: AtomicUsize = AtomicUsize::new(0);

static REPLICATION_PIPELINE_STAGE_EVENTS: [[AtomicU64; REPLICATION_PIPELINE_STAGE_COUNT];
    REPLICATION_PIPELINE_KIND_COUNT] =
    [const { [const { AtomicU64::new(0) }; REPLICATION_PIPELINE_STAGE_COUNT] };
        REPLICATION_PIPELINE_KIND_COUNT];
static REPLICATION_PIPELINE_STAGE_DURATION_TOTAL_US: [[AtomicU64;
    REPLICATION_PIPELINE_STAGE_COUNT];
    REPLICATION_PIPELINE_KIND_COUNT] =
    [const { [const { AtomicU64::new(0) }; REPLICATION_PIPELINE_STAGE_COUNT] };
        REPLICATION_PIPELINE_KIND_COUNT];
static REPLICATION_PIPELINE_STAGE_DURATION_BUCKETS: [[[AtomicU64; CLIENT_QUEUE_BUCKETS_US.len()];
    REPLICATION_PIPELINE_STAGE_COUNT];
    REPLICATION_PIPELINE_KIND_COUNT] = [const {
    [const { [const { AtomicU64::new(0) }; CLIENT_QUEUE_BUCKETS_US.len()] };
        REPLICATION_PIPELINE_STAGE_COUNT]
}; REPLICATION_PIPELINE_KIND_COUNT];

static CLIENT_REPLICATION_QUEUE_DEPTH: AtomicUsize = AtomicUsize::new(0);
static CLIENT_REPLICATION_QUEUE_WAIT_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static CLIENT_REPLICATION_QUEUE_WAIT_SAMPLES: AtomicU64 = AtomicU64::new(0);
static CLIENT_REPLICATION_QUEUE_WAIT_BUCKETS: [AtomicU64; CLIENT_QUEUE_BUCKETS_US.len()] =
    [const { AtomicU64::new(0) }; CLIENT_QUEUE_BUCKETS_US.len()];

// These values are refreshed from the negotiated, alive-member capability
// snapshot. They are local observations of cluster state, rather than
// per-topic state, so they deliberately carry no topic or peer labels.
static STRICT_REPLICATION_CLUSTER_PROTOCOL_VERSION: AtomicU32 = AtomicU32::new(0);
static STRICT_REPLICATION_TERMINAL_RESOLUTION_READY: AtomicBool = AtomicBool::new(false);
static STRICT_REPLICATION_UNSUPPORTED_ACTIVE_PEERS: AtomicUsize = AtomicUsize::new(0);
static STRICT_REPLICATION_TERMINAL_DECISIONS: [AtomicU64; STRICT_RESOLUTION_OUTCOME_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_RESOLUTION_OUTCOME_COUNT];
static STRICT_REPLICATION_FENCE_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static STRICT_ADMISSION_METRIC_SOURCES: LazyLock<Mutex<Vec<Weak<StrictAdmissionMetrics>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// Per-runtime admission gauges aggregated at scrape time.
///
/// A process can host multiple strict topics. Weak sources let the exported
/// metrics combine every live runtime without a topic label or stale values
/// after a runtime is dropped.
#[derive(Default)]
pub(crate) struct StrictAdmissionMetrics {
    admitted: AtomicUsize,
    awaiting_local_cut: AtomicUsize,
    awaiting_peer: AtomicUsize,
    highest_barrier: AtomicU64,
}

impl StrictAdmissionMetrics {
    pub(crate) fn update(
        &self,
        admitted: usize,
        awaiting_local_cut: usize,
        awaiting_peer: usize,
        highest_barrier: u64,
    ) {
        self.admitted.store(admitted, Ordering::Relaxed);
        self.awaiting_local_cut
            .store(awaiting_local_cut, Ordering::Relaxed);
        self.awaiting_peer.store(awaiting_peer, Ordering::Relaxed);
        self.highest_barrier
            .store(highest_barrier, Ordering::Relaxed);
    }

    fn snapshot(&self) -> StrictAdmissionMetricSnapshot {
        StrictAdmissionMetricSnapshot {
            admitted: self.admitted.load(Ordering::Relaxed),
            awaiting_local_cut: self.awaiting_local_cut.load(Ordering::Relaxed),
            awaiting_peer: self.awaiting_peer.load(Ordering::Relaxed),
            highest_barrier: self.highest_barrier.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct StrictAdmissionMetricSnapshot {
    admitted: usize,
    awaiting_local_cut: usize,
    awaiting_peer: usize,
    highest_barrier: u64,
}

pub(crate) fn register_strict_admission_metrics() -> Arc<StrictAdmissionMetrics> {
    let source = Arc::new(StrictAdmissionMetrics {
        admitted: AtomicUsize::new(0),
        awaiting_local_cut: AtomicUsize::new(0),
        awaiting_peer: AtomicUsize::new(0),
        highest_barrier: AtomicU64::new(0),
    });
    STRICT_ADMISSION_METRIC_SOURCES
        .lock()
        .unwrap()
        .push(Arc::downgrade(&source));
    source
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

pub(crate) fn record_catchup_request(mode: CatchupMode) {
    increment(&CATCHUP_REQUESTS[mode.index()], 1);
}

pub(crate) fn record_catchup_response(mode: CatchupMode, ops: usize, bytes: usize) {
    let index = mode.index();
    increment(&CATCHUP_RESPONSES[index], 1);
    increment(&CATCHUP_RESPONSE_OPS[index], ops as u64);
    increment(&CATCHUP_RESPONSE_BYTES[index], bytes as u64);
}

pub(crate) fn record_catchup_suppressed(mode: CatchupMode) {
    increment(&CATCHUP_SUPPRESSED[mode.index()], 1);
}

pub(crate) fn record_catchup_active_delta(delta: isize) {
    if delta >= 0 {
        CATCHUP_ACTIVE.fetch_add(delta as usize, Ordering::Relaxed);
    } else {
        let decrement = delta.unsigned_abs();
        let _ = CATCHUP_ACTIVE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_sub(decrement))
        });
    }
}

pub(crate) fn record_pipeline_stage(
    kind: ReplicationPipelineKind,
    stage: ReplicationPipelineStage,
    duration: Duration,
) {
    let kind_index = kind.index();
    let stage_index = stage.index();
    let duration_us = duration.as_micros().min(u64::MAX as u128) as u64;
    increment(
        &REPLICATION_PIPELINE_STAGE_EVENTS[kind_index][stage_index],
        1,
    );
    increment(
        &REPLICATION_PIPELINE_STAGE_DURATION_TOTAL_US[kind_index][stage_index],
        duration_us,
    );
    observe_bucket(
        &REPLICATION_PIPELINE_STAGE_DURATION_BUCKETS[kind_index][stage_index],
        &CLIENT_QUEUE_BUCKETS_US,
        duration_us,
    );
}

pub fn set_client_replication_queue_depth(depth: usize) {
    CLIENT_REPLICATION_QUEUE_DEPTH.store(depth, Ordering::Relaxed);
}

pub fn record_client_replication_queue_wait(wait: std::time::Duration) {
    let wait_us = wait.as_micros().min(u64::MAX as u128) as u64;
    increment(&CLIENT_REPLICATION_QUEUE_WAIT_TOTAL_US, wait_us);
    increment(&CLIENT_REPLICATION_QUEUE_WAIT_SAMPLES, 1);
    observe_bucket(
        &CLIENT_REPLICATION_QUEUE_WAIT_BUCKETS,
        &CLIENT_QUEUE_BUCKETS_US,
        wait_us,
    );
}

/// Publishes the strict-replication protocol negotiated across alive peers.
///
/// `cluster_version` is the minimum advertised incremental protocol version,
/// `ready` reports whether terminal resolution may be emitted, and
/// `unsupported_active_peers` exposes why a rollout has not become ready.
pub(crate) fn set_strict_replication_protocol_status(
    cluster_version: u32,
    ready: bool,
    unsupported_active_peers: usize,
) {
    STRICT_REPLICATION_CLUSTER_PROTOCOL_VERSION.store(cluster_version, Ordering::Relaxed);
    STRICT_REPLICATION_TERMINAL_RESOLUTION_READY.store(ready, Ordering::Relaxed);
    STRICT_REPLICATION_UNSUPPORTED_ACTIVE_PEERS.store(unsupported_active_peers, Ordering::Relaxed);
}

/// Records a terminal decision applied by the strict-resolution protocol.
pub(crate) fn record_strict_resolution(outcome: StrictResolutionOutcome) {
    increment(&STRICT_REPLICATION_TERMINAL_DECISIONS[outcome.index()], 1);
}

/// Records a late or conflicting strict frame rejected by a resolution fence.
pub(crate) fn record_strict_fence_rejection() {
    increment(&STRICT_REPLICATION_FENCE_REJECTIONS, 1);
}

fn aggregate_strict_admission_metrics() -> StrictAdmissionMetricSnapshot {
    let mut sources = STRICT_ADMISSION_METRIC_SOURCES.lock().unwrap();
    aggregate_strict_admission_sources(&mut sources)
}

fn aggregate_strict_admission_sources(
    sources: &mut Vec<Weak<StrictAdmissionMetrics>>,
) -> StrictAdmissionMetricSnapshot {
    let mut aggregate = StrictAdmissionMetricSnapshot::default();
    sources.retain(|source| {
        let Some(source) = source.upgrade() else {
            return false;
        };
        let snapshot = source.snapshot();
        aggregate.admitted = aggregate.admitted.saturating_add(snapshot.admitted);
        aggregate.awaiting_local_cut = aggregate
            .awaiting_local_cut
            .saturating_add(snapshot.awaiting_local_cut);
        aggregate.awaiting_peer = aggregate
            .awaiting_peer
            .saturating_add(snapshot.awaiting_peer);
        aggregate.highest_barrier = aggregate.highest_barrier.max(snapshot.highest_barrier);
        true
    });
    aggregate
}

fn strict_admission_metric_samples(
    snapshot: StrictAdmissionMetricSnapshot,
) -> Vec<PrometheusSample> {
    let mut samples = Vec::with_capacity(4);
    for (state, value) in [
        ("admitted", snapshot.admitted),
        ("awaiting_local_cut", snapshot.awaiting_local_cut),
        ("awaiting_peer", snapshot.awaiting_peer),
    ] {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_admission_peer_states",
            vec![("state".to_owned(), state.to_owned())],
            value as f64,
        ));
    }
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_strict_replication_admission_highest_barrier",
        Vec::new(),
        snapshot.highest_barrier as f64,
    ));
    samples
}

pub(crate) fn prometheus_samples() -> Vec<PrometheusSample> {
    let mut samples = Vec::new();
    for mode in [CatchupMode::Strict, CatchupMode::Owner] {
        let labels = vec![("mode".to_owned(), mode.label().to_owned())];
        let index = mode.index();
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_replication_catchup_requests_total",
            labels.clone(),
            CATCHUP_REQUESTS[index].load(Ordering::Relaxed) as f64,
        ));
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_replication_catchup_responses_total",
            labels.clone(),
            CATCHUP_RESPONSES[index].load(Ordering::Relaxed) as f64,
        ));
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_replication_catchup_response_ops_total",
            labels.clone(),
            CATCHUP_RESPONSE_OPS[index].load(Ordering::Relaxed) as f64,
        ));
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_replication_catchup_response_bytes_total",
            labels.clone(),
            CATCHUP_RESPONSE_BYTES[index].load(Ordering::Relaxed) as f64,
        ));
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_replication_catchup_suppressed_total",
            labels,
            CATCHUP_SUPPRESSED[index].load(Ordering::Relaxed) as f64,
        ));
    }

    samples.push(PrometheusSample::new(
        "shitspeak_s2s_replication_catchup_active",
        Vec::new(),
        CATCHUP_ACTIVE.load(Ordering::Relaxed) as f64,
    ));
    for kind in REPLICATION_PIPELINE_KINDS {
        for stage in REPLICATION_PIPELINE_STAGES {
            let kind_index = kind.index();
            let stage_index = stage.index();
            let labels = vec![
                ("kind".to_owned(), kind.label().to_owned()),
                ("stage".to_owned(), stage.label().to_owned()),
            ];
            samples.push(PrometheusSample::new(
                "shitspeak_s2s_replication_pipeline_stage_events_total",
                labels.clone(),
                REPLICATION_PIPELINE_STAGE_EVENTS[kind_index][stage_index].load(Ordering::Relaxed)
                    as f64,
            ));
            samples.push(PrometheusSample::new(
                "shitspeak_s2s_replication_pipeline_stage_duration_us_total",
                labels.clone(),
                REPLICATION_PIPELINE_STAGE_DURATION_TOTAL_US[kind_index][stage_index]
                    .load(Ordering::Relaxed) as f64,
            ));
            for (bucket_index, (bucket, _)) in CLIENT_QUEUE_BUCKETS_US.iter().enumerate() {
                let mut labels = labels.clone();
                labels.push(("bucket".to_owned(), (*bucket).to_owned()));
                samples.push(PrometheusSample::new(
                    "shitspeak_s2s_replication_pipeline_stage_duration_us_bucket_total",
                    labels,
                    REPLICATION_PIPELINE_STAGE_DURATION_BUCKETS[kind_index][stage_index]
                        [bucket_index]
                        .load(Ordering::Relaxed) as f64,
                ));
            }
        }
    }
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_client_replication_worker_queue_depth",
        Vec::new(),
        CLIENT_REPLICATION_QUEUE_DEPTH.load(Ordering::Relaxed) as f64,
    ));
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_client_replication_worker_queue_wait_us_total",
        Vec::new(),
        CLIENT_REPLICATION_QUEUE_WAIT_TOTAL_US.load(Ordering::Relaxed) as f64,
    ));
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_client_replication_worker_queue_wait_samples_total",
        Vec::new(),
        CLIENT_REPLICATION_QUEUE_WAIT_SAMPLES.load(Ordering::Relaxed) as f64,
    ));
    for (index, (bucket, _)) in CLIENT_QUEUE_BUCKETS_US.iter().enumerate() {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_client_replication_worker_queue_wait_us_bucket_total",
            vec![("bucket".to_owned(), (*bucket).to_owned())],
            CLIENT_REPLICATION_QUEUE_WAIT_BUCKETS[index].load(Ordering::Relaxed) as f64,
        ));
    }

    samples.extend(strict_protocol_metric_samples(
        STRICT_REPLICATION_CLUSTER_PROTOCOL_VERSION.load(Ordering::Relaxed),
        STRICT_REPLICATION_TERMINAL_RESOLUTION_READY.load(Ordering::Relaxed),
        STRICT_REPLICATION_UNSUPPORTED_ACTIVE_PEERS.load(Ordering::Relaxed),
        [
            STRICT_REPLICATION_TERMINAL_DECISIONS[StrictResolutionOutcome::Commit.index()]
                .load(Ordering::Relaxed),
            STRICT_REPLICATION_TERMINAL_DECISIONS[StrictResolutionOutcome::Abort.index()]
                .load(Ordering::Relaxed),
        ],
        STRICT_REPLICATION_FENCE_REJECTIONS.load(Ordering::Relaxed),
    ));
    samples.extend(strict_admission_metric_samples(
        aggregate_strict_admission_metrics(),
    ));

    samples
}

fn strict_protocol_metric_samples(
    cluster_protocol_version: u32,
    terminal_resolution_ready: bool,
    unsupported_active_peers: usize,
    terminal_decisions: [u64; STRICT_RESOLUTION_OUTCOME_COUNT],
    fence_rejections: u64,
) -> Vec<PrometheusSample> {
    let mut samples = Vec::with_capacity(6);
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_strict_replication_cluster_protocol_version",
        Vec::new(),
        cluster_protocol_version as f64,
    ));
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_strict_replication_terminal_resolution_ready",
        Vec::new(),
        terminal_resolution_ready as u8 as f64,
    ));
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_strict_replication_unsupported_active_peers",
        Vec::new(),
        unsupported_active_peers as f64,
    ));
    for outcome in [
        StrictResolutionOutcome::Commit,
        StrictResolutionOutcome::Abort,
    ] {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_terminal_decisions_total",
            vec![("outcome".to_owned(), outcome.label().to_owned())],
            terminal_decisions[outcome.index()] as f64,
        ));
    }
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_strict_replication_fence_rejections_total",
        Vec::new(),
        fence_rejections as f64,
    ));
    samples
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_protocol_metrics_expose_readiness_and_terminal_outcomes() {
        let samples = strict_protocol_metric_samples(2, true, 2, [1, 1], 1);
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_cluster_protocol_version"
                && sample.value() == 2.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_terminal_resolution_ready"
                && sample.value() == 1.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_unsupported_active_peers"
                && sample.value() == 2.0
        }));
        for outcome in ["commit", "abort"] {
            assert!(samples.iter().any(|sample| {
                sample.name() == "shitspeak_s2s_strict_replication_terminal_decisions_total"
                    && sample.labels() == [("outcome".to_owned(), outcome.to_owned())]
                    && sample.value() == 1.0
            }));
        }
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_fence_rejections_total"
                && sample.value() == 1.0
        }));
    }

    #[test]
    fn strict_admission_metrics_expose_bounded_phase_counts_and_barrier() {
        let samples = strict_admission_metric_samples(StrictAdmissionMetricSnapshot {
            admitted: 3,
            awaiting_local_cut: 2,
            awaiting_peer: 1,
            highest_barrier: 101,
        });
        for (state, value) in [
            ("admitted", 3.0),
            ("awaiting_local_cut", 2.0),
            ("awaiting_peer", 1.0),
        ] {
            assert!(samples.iter().any(|sample| {
                sample.name() == "shitspeak_s2s_strict_replication_admission_peer_states"
                    && sample.labels() == [("state".to_owned(), state.to_owned())]
                    && sample.value() == value
            }));
        }
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_admission_highest_barrier"
                && sample.value() == 101.0
        }));
    }

    #[test]
    fn strict_admission_metrics_aggregate_only_live_runtime_sources() {
        let first = Arc::new(StrictAdmissionMetrics::default());
        first.update(2, 1, 0, 40);
        let second = Arc::new(StrictAdmissionMetrics::default());
        second.update(3, 0, 2, 90);
        let mut sources = vec![Arc::downgrade(&first), Arc::downgrade(&second)];

        assert_eq!(
            aggregate_strict_admission_sources(&mut sources),
            StrictAdmissionMetricSnapshot {
                admitted: 5,
                awaiting_local_cut: 1,
                awaiting_peer: 2,
                highest_barrier: 90,
            }
        );

        drop(second);
        assert_eq!(
            aggregate_strict_admission_sources(&mut sources),
            StrictAdmissionMetricSnapshot {
                admitted: 2,
                awaiting_local_cut: 1,
                awaiting_peer: 0,
                highest_barrier: 40,
            }
        );
        assert_eq!(sources.len(), 1);
    }
}
