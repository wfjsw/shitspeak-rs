use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex;

use shitspeak_core::NodeIdentifier;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RepairKey {
    dst: NodeIdentifier,
    sender_session: u32,
    sender_epoch: u64,
    s2s_seq: u64,
}

#[derive(Debug, Clone)]
pub struct RepairFrame {
    dst: NodeIdentifier,
    sender_session: u32,
    sender_epoch: u64,
    s2s_seq: u64,
    body: Bytes,
    avoid_first_hop: Option<NodeIdentifier>,
    transport_ttl: Duration,
}

impl RepairFrame {
    pub fn new(
        dst: NodeIdentifier,
        sender_session: u32,
        sender_epoch: u64,
        s2s_seq: u64,
        body: Bytes,
        avoid_first_hop: Option<NodeIdentifier>,
        transport_ttl: Duration,
    ) -> Self {
        Self {
            dst,
            sender_session,
            sender_epoch,
            s2s_seq,
            body,
            avoid_first_hop,
            transport_ttl,
        }
    }

    pub fn dst(&self) -> NodeIdentifier {
        self.dst
    }

    pub fn body(&self) -> &Bytes {
        &self.body
    }

    pub fn avoid_first_hop(&self) -> Option<NodeIdentifier> {
        self.avoid_first_hop
    }

    pub fn transport_ttl(&self) -> Duration {
        self.transport_ttl
    }
}

#[derive(Debug, Clone)]
struct RepairEntry {
    body: Bytes,
    avoid_first_hop: Option<NodeIdentifier>,
    transport_ttl: Duration,
    expires_at: Instant,
}

#[derive(Debug)]
struct RepairCacheInner {
    entries: HashMap<RepairKey, RepairEntry>,
    order: VecDeque<RepairKey>,
}

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
            max_entries: 8192,
            inner: Mutex::new(RepairCacheInner {
                entries: HashMap::new(),
                order: VecDeque::new(),
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
            dst: frame.dst,
            sender_session: frame.sender_session,
            sender_epoch: frame.sender_epoch,
            s2s_seq: frame.s2s_seq,
        };
        let mut inner = self.inner.lock();
        prune_locked(&mut inner, self.max_entries, now);
        if !inner.entries.contains_key(&key) {
            inner.order.push_back(key);
        }
        inner.entries.insert(
            key,
            RepairEntry {
                body: frame.body,
                avoid_first_hop: frame.avoid_first_hop,
                transport_ttl: frame.transport_ttl,
                expires_at: now + cache_ttl,
            },
        );
        prune_locked(&mut inner, self.max_entries, now);
    }

    pub fn lookup_range(
        &self,
        dst: NodeIdentifier,
        sender_session: u32,
        sender_epoch: u64,
        first_seq: u64,
        last_seq: u64,
    ) -> Vec<RepairFrame> {
        let now = Instant::now();
        let mut inner = self.inner.lock();
        prune_locked(&mut inner, self.max_entries, now);
        let mut out = Vec::new();
        for s2s_seq in first_seq..=last_seq.min(first_seq.saturating_add(31)) {
            let key = RepairKey {
                dst,
                sender_session,
                sender_epoch,
                s2s_seq,
            };
            let Some(entry) = inner.entries.get(&key) else {
                continue;
            };
            out.push(RepairFrame::new(
                dst,
                sender_session,
                sender_epoch,
                s2s_seq,
                entry.body.clone(),
                entry.avoid_first_hop,
                entry.transport_ttl,
            ));
        }
        out
    }
}

fn prune_locked(inner: &mut RepairCacheInner, max_entries: usize, now: Instant) {
    let expired: Vec<RepairKey> = inner
        .order
        .iter()
        .copied()
        .filter(|key| {
            inner
                .entries
                .get(key)
                .is_none_or(|entry| now > entry.expires_at)
        })
        .collect();
    for key in expired {
        inner.entries.remove(&key);
    }
    inner.order.retain(|key| inner.entries.contains_key(key));

    while inner.entries.len() > max_entries {
        let Some(key) = inner.order.pop_front() else {
            break;
        };
        inner.entries.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_cache_replays_exact_body() {
        let cache = RepairCache::new(Duration::from_millis(300));
        let body = Bytes::from_static(b"voice-frame");
        cache.insert(RepairFrame::new(
            2,
            9,
            10,
            11,
            body.clone(),
            Some(3),
            Duration::from_millis(120),
        ));

        let found = cache.lookup_range(2, 9, 10, 11, 11);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].body(), &body);
        assert_eq!(found[0].avoid_first_hop(), Some(3));
        assert_eq!(found[0].transport_ttl(), Duration::from_millis(120));
    }

    #[test]
    fn repair_cache_expires_frames() {
        let cache = RepairCache::new(Duration::from_millis(1));
        cache.insert(RepairFrame::new(
            2,
            9,
            10,
            11,
            Bytes::from_static(b"voice-frame"),
            None,
            Duration::from_millis(120),
        ));
        std::thread::sleep(Duration::from_millis(5));
        assert!(cache.lookup_range(2, 9, 10, 11, 11).is_empty());
    }

    #[test]
    fn repair_cache_can_extend_single_frame_ttl() {
        let cache = RepairCache::new(Duration::from_millis(1));
        cache.insert_with_cache_ttl(
            RepairFrame::new(
                2,
                9,
                10,
                11,
                Bytes::from_static(b"voice-frame"),
                None,
                Duration::from_millis(120),
            ),
            Duration::from_millis(20),
        );
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(cache.lookup_range(2, 9, 10, 11, 11).len(), 1);
    }

    #[test]
    fn long_lived_frame_does_not_pin_expired_later_frame() {
        let cache = RepairCache::new(Duration::from_millis(1));
        cache.insert_with_cache_ttl(
            RepairFrame::new(
                2,
                9,
                10,
                11,
                Bytes::from_static(b"long-lived"),
                None,
                Duration::from_millis(120),
            ),
            Duration::from_millis(20),
        );
        cache.insert(RepairFrame::new(
            2,
            9,
            10,
            12,
            Bytes::from_static(b"short-lived"),
            None,
            Duration::from_millis(120),
        ));
        std::thread::sleep(Duration::from_millis(5));

        assert_eq!(cache.lookup_range(2, 9, 10, 11, 11).len(), 1);
        assert!(cache.lookup_range(2, 9, 10, 12, 12).is_empty());
    }
}
