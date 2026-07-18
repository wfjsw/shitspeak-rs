use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex;

use super::metrics;

const REPAIR_CACHE_MAX_ENTRIES: usize = 8_192;
pub(crate) const REPAIR_RESPONSE_PAGE_SEQUENCES: u64 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct RepairKey {
    sender_session: u32,
    sender_epoch: u64,
    s2s_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ExpiryEntry {
    expires_at: Instant,
    key: RepairKey,
}

/// One encoded original retained for possible NACK replay. Routing is not
/// cached: the requester determines the destination and current first-hop
/// avoidance policy when the replay is sent.
#[derive(Debug, Clone)]
pub struct RepairFrame {
    sender_session: u32,
    sender_epoch: u64,
    s2s_seq: u64,
    body: Bytes,
}

impl RepairFrame {
    pub fn new(sender_session: u32, sender_epoch: u64, s2s_seq: u64, body: Bytes) -> Self {
        Self {
            sender_session,
            sender_epoch,
            s2s_seq,
            body,
        }
    }

    pub fn body(&self) -> &Bytes {
        &self.body
    }
}

#[derive(Debug, Clone)]
struct RepairEntry {
    body: Bytes,
    expires_at: Instant,
}

#[derive(Debug)]
struct RepairCacheInner {
    entries: HashMap<RepairKey, RepairEntry>,
    expiries: BTreeSet<ExpiryEntry>,
}

#[derive(Debug)]
struct RepairCacheState {
    max_entries: usize,
    inner: Mutex<RepairCacheInner>,
}

impl metrics::RepairCacheTelemetrySource for RepairCacheState {
    fn snapshot(&self, now: Instant) -> (usize, usize) {
        let mut inner = self.inner.lock();
        prune_expired_locked(&mut inner, now);
        (inner.entries.len(), self.max_entries)
    }
}

/// Bounded cache of recently-originated originals. Expiry is driven by an
/// ordered set, so hot voice paths never scan every cached frame to prune and
/// refreshing a frame replaces rather than accumulates expiry metadata.
#[derive(Debug)]
pub struct RepairCache {
    ttl: Duration,
    state: Arc<RepairCacheState>,
}

impl RepairCache {
    pub fn new(ttl: Duration) -> Self {
        let state = Arc::new(RepairCacheState {
            max_entries: REPAIR_CACHE_MAX_ENTRIES,
            inner: Mutex::new(RepairCacheInner {
                entries: HashMap::new(),
                expiries: BTreeSet::new(),
            }),
        });
        metrics::register_repair_cache_telemetry_source(state.clone());
        Self { ttl, state }
    }

    pub fn insert(&self, frame: RepairFrame) {
        self.insert_with_cache_ttl(frame, self.ttl);
    }

    pub fn insert_with_cache_ttl(&self, frame: RepairFrame, cache_ttl: Duration) {
        let cache_ttl = cache_ttl.max(self.ttl);
        if cache_ttl.is_zero() {
            return;
        }

        let now = Instant::now();
        let key = RepairKey {
            sender_session: frame.sender_session,
            sender_epoch: frame.sender_epoch,
            s2s_seq: frame.s2s_seq,
        };
        let expires_at = now + cache_ttl;
        let mut inner = self.state.inner.lock();
        prune_expired_locked(&mut inner, now);
        if let Some(previous) = inner.entries.insert(
            key,
            RepairEntry {
                body: frame.body,
                expires_at,
            },
        ) {
            inner.expiries.remove(&ExpiryEntry {
                expires_at: previous.expires_at,
                key,
            });
        }
        inner.expiries.insert(ExpiryEntry { expires_at, key });
        let evictions = enforce_capacity_locked(&mut inner, self.state.max_entries);
        drop(inner);
        metrics::record_repair_cache_evictions(evictions);
    }

    pub fn lookup_range(
        &self,
        sender_session: u32,
        sender_epoch: u64,
        first_seq: u64,
        last_seq: u64,
    ) -> Vec<RepairFrame> {
        let now = Instant::now();
        let mut inner = self.state.inner.lock();
        prune_expired_locked(&mut inner, now);
        let mut out = Vec::new();
        for s2s_seq in first_seq
            ..=last_seq
                .min(first_seq.saturating_add(REPAIR_RESPONSE_PAGE_SEQUENCES.saturating_sub(1)))
        {
            let key = RepairKey {
                sender_session,
                sender_epoch,
                s2s_seq,
            };
            let Some(entry) = inner.entries.get(&key) else {
                continue;
            };
            out.push(RepairFrame::new(
                sender_session,
                sender_epoch,
                s2s_seq,
                entry.body.clone(),
            ));
        }
        out
    }
}

fn prune_expired_locked(inner: &mut RepairCacheInner, now: Instant) {
    while let Some(expiry) = inner.expiries.first().copied() {
        if expiry.expires_at > now {
            break;
        }
        inner.expiries.remove(&expiry);
        if inner
            .entries
            .get(&expiry.key)
            .is_some_and(|entry| entry.expires_at == expiry.expires_at)
        {
            inner.entries.remove(&expiry.key);
        }
    }
}

fn enforce_capacity_locked(inner: &mut RepairCacheInner, max_entries: usize) -> u64 {
    let mut evictions = 0_u64;
    while inner.entries.len() > max_entries {
        let Some(expiry) = inner.expiries.pop_first() else {
            break;
        };
        if inner
            .entries
            .get(&expiry.key)
            .is_some_and(|entry| entry.expires_at == expiry.expires_at)
        {
            inner.entries.remove(&expiry.key);
            evictions = evictions.saturating_add(1);
        }
    }
    evictions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_cache_replays_exact_body_for_any_requester() {
        let cache = RepairCache::new(Duration::from_millis(300));
        assert_eq!(cache.state.max_entries, REPAIR_CACHE_MAX_ENTRIES);
        let body = Bytes::from_static(b"voice-frame");
        cache.insert(RepairFrame::new(9, 10, 11, body.clone()));

        let found = cache.lookup_range(9, 10, 11, 11);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].body(), &body);
    }

    #[test]
    fn repair_cache_expires_frames() {
        let cache = RepairCache::new(Duration::from_millis(1));
        cache.insert(RepairFrame::new(
            9,
            10,
            11,
            Bytes::from_static(b"voice-frame"),
        ));
        std::thread::sleep(Duration::from_millis(5));
        assert!(cache.lookup_range(9, 10, 11, 11).is_empty());
    }

    #[test]
    fn repair_cache_can_extend_single_frame_ttl() {
        let cache = RepairCache::new(Duration::from_millis(1));
        cache.insert(RepairFrame::new(9, 10, 11, Bytes::from_static(b"initial")));
        cache.insert_with_cache_ttl(
            RepairFrame::new(9, 10, 11, Bytes::from_static(b"refreshed")),
            Duration::from_millis(20),
        );
        std::thread::sleep(Duration::from_millis(5));
        let found = cache.lookup_range(9, 10, 11, 11);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].body(), &Bytes::from_static(b"refreshed"));
    }

    #[test]
    fn repeated_same_key_refresh_keeps_one_expiry_record() {
        let cache = RepairCache::new(Duration::from_secs(1));
        for value in 0..10_000_u32 {
            cache.insert(RepairFrame::new(
                9,
                10,
                11,
                Bytes::copy_from_slice(&value.to_le_bytes()),
            ));
        }

        let inner = cache.state.inner.lock();
        assert_eq!(inner.entries.len(), 1);
        assert_eq!(inner.expiries.len(), 1);
        assert_eq!(
            inner.entries.values().next().unwrap().body,
            Bytes::copy_from_slice(&9_999_u32.to_le_bytes())
        );
    }

    #[test]
    fn telemetry_snapshot_prunes_idle_expiry() {
        let cache = RepairCache::new(Duration::from_millis(1));
        cache.insert(RepairFrame::new(
            9,
            10,
            11,
            Bytes::from_static(b"voice-frame"),
        ));
        std::thread::sleep(Duration::from_millis(5));

        let occupancy = metrics::prometheus_samples()
            .into_iter()
            .find(|sample| sample.name() == "shitspeak_s2s_voice_repair_cache_occupancy")
            .expect("repair cache occupancy sample");
        assert!(occupancy.value() >= 0.0);
        let inner = cache.state.inner.lock();
        assert!(inner.entries.is_empty());
        assert!(inner.expiries.is_empty());
    }

    #[test]
    fn later_short_expiry_is_pruned_without_scanning_long_lived_entry() {
        let cache = RepairCache::new(Duration::from_millis(1));
        cache.insert_with_cache_ttl(
            RepairFrame::new(9, 10, 11, Bytes::from_static(b"long-lived")),
            Duration::from_secs(1),
        );
        cache.insert(RepairFrame::new(
            9,
            10,
            12,
            Bytes::from_static(b"short-lived"),
        ));
        std::thread::sleep(Duration::from_millis(10));

        assert_eq!(cache.lookup_range(9, 10, 11, 11).len(), 1);
        assert!(cache.lookup_range(9, 10, 12, 12).is_empty());
    }
}
