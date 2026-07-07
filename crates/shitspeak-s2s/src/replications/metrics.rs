use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

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

const CATCHUP_MODE_COUNT: usize = 2;
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

static CLIENT_REPLICATION_QUEUE_DEPTH: AtomicUsize = AtomicUsize::new(0);
static CLIENT_REPLICATION_QUEUE_WAIT_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static CLIENT_REPLICATION_QUEUE_WAIT_SAMPLES: AtomicU64 = AtomicU64::new(0);
static CLIENT_REPLICATION_QUEUE_WAIT_BUCKETS: [AtomicU64; CLIENT_QUEUE_BUCKETS_US.len()] =
    [const { AtomicU64::new(0) }; CLIENT_QUEUE_BUCKETS_US.len()];

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

    samples
}
