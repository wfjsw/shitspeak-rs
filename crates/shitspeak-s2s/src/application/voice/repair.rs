use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex;

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
    expiries: BinaryHeap<Reverse<ExpiryEntry>>,
}

/// Bounded cache of recently-originated originals. Expiry is driven by a
/// min-heap, so hot voice paths never scan every cached frame to prune.
#[derive(Debug)]
pub struct RepairCache {
    ttl: Duration,
    max_entries: usize,
    inner: Mutex<RepairCacheInner>,
}

impl RepairCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            max_entries: 8_192,
            inner: Mutex::new(RepairCacheInner {
                entries: HashMap::new(),
                expiries: BinaryHeap::new(),
            }),
        }
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
        let mut inner = self.inner.lock();
        prune_expired_locked(&mut inner, now);
        inner.entries.insert(
            key,
            RepairEntry {
                body: frame.body,
                expires_at,
            },
        );
        inner
            .expiries
            .push(Reverse(ExpiryEntry { expires_at, key }));
        enforce_capacity_locked(&mut inner, self.max_entries);
    }

    pub fn lookup_range(
        &self,
        sender_session: u32,
        sender_epoch: u64,
        first_seq: u64,
        last_seq: u64,
    ) -> Vec<RepairFrame> {
        let now = Instant::now();
        let mut inner = self.inner.lock();
        prune_expired_locked(&mut inner, now);
        let mut out = Vec::new();
        for s2s_seq in first_seq..=last_seq.min(first_seq.saturating_add(31)) {
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
    while let Some(Reverse(expiry)) = inner.expiries.peek().copied() {
        if expiry.expires_at > now {
            break;
        }
        inner.expiries.pop();
        if inner
            .entries
            .get(&expiry.key)
            .is_some_and(|entry| entry.expires_at == expiry.expires_at)
        {
            inner.entries.remove(&expiry.key);
        }
    }
}

fn enforce_capacity_locked(inner: &mut RepairCacheInner, max_entries: usize) {
    while inner.entries.len() > max_entries {
        let Some(Reverse(expiry)) = inner.expiries.pop() else {
            break;
        };
        if inner
            .entries
            .get(&expiry.key)
            .is_some_and(|entry| entry.expires_at == expiry.expires_at)
        {
            inner.entries.remove(&expiry.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_cache_replays_exact_body_for_any_requester() {
        let cache = RepairCache::new(Duration::from_millis(300));
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
        cache.insert_with_cache_ttl(
            RepairFrame::new(9, 10, 11, Bytes::from_static(b"voice-frame")),
            Duration::from_millis(20),
        );
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(cache.lookup_range(9, 10, 11, 11).len(), 1);
    }

    #[test]
    fn later_short_expiry_is_pruned_without_scanning_long_lived_entry() {
        let cache = RepairCache::new(Duration::from_millis(1));
        cache.insert_with_cache_ttl(
            RepairFrame::new(9, 10, 11, Bytes::from_static(b"long-lived")),
            Duration::from_millis(20),
        );
        cache.insert(RepairFrame::new(
            9,
            10,
            12,
            Bytes::from_static(b"short-lived"),
        ));
        std::thread::sleep(Duration::from_millis(5));

        assert_eq!(cache.lookup_range(9, 10, 11, 11).len(), 1);
        assert!(cache.lookup_range(9, 10, 12, 12).is_empty());
    }
}
