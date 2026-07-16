use std::sync::atomic::{AtomicU64, Ordering};

use crate::status::PrometheusSample;

static INLINE_BYTES: AtomicU64 = AtomicU64::new(0);
static SIDECAR_CHUNKS_EMITTED: AtomicU64 = AtomicU64::new(0);
static SIDECAR_CHUNKS_DROPPED: AtomicU64 = AtomicU64::new(0);
static SIDECAR_CHUNKS_REASSEMBLED: AtomicU64 = AtomicU64::new(0);
static CACHELESS_BRANCH_DROPS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn record_inline_bytes(bytes: usize) {
    INLINE_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
}

pub(crate) fn record_sidecar_chunks_emitted(chunks: usize) {
    SIDECAR_CHUNKS_EMITTED.fetch_add(chunks as u64, Ordering::Relaxed);
}

pub(crate) fn record_sidecar_chunk_dropped() {
    SIDECAR_CHUNKS_DROPPED.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_sidecar_reassembled() {
    SIDECAR_CHUNKS_REASSEMBLED.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_cacheless_branch_drop() {
    CACHELESS_BRANCH_DROPS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn prometheus_samples() -> Vec<PrometheusSample> {
    [
        (
            "shitspeak_s2s_overlay_attachment_inline_bytes_total",
            INLINE_BYTES.load(Ordering::Relaxed),
        ),
        (
            "shitspeak_s2s_overlay_attachment_sidecar_chunks_emitted_total",
            SIDECAR_CHUNKS_EMITTED.load(Ordering::Relaxed),
        ),
        (
            "shitspeak_s2s_overlay_attachment_sidecar_chunks_dropped_total",
            SIDECAR_CHUNKS_DROPPED.load(Ordering::Relaxed),
        ),
        (
            "shitspeak_s2s_overlay_attachment_reassemblies_total",
            SIDECAR_CHUNKS_REASSEMBLED.load(Ordering::Relaxed),
        ),
        (
            "shitspeak_s2s_overlay_attachment_cacheless_branch_drops_total",
            CACHELESS_BRANCH_DROPS.load(Ordering::Relaxed),
        ),
    ]
    .into_iter()
    .map(|(name, value)| PrometheusSample::new(name, Vec::new(), value as f64))
    .collect()
}
