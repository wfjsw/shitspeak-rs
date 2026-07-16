use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex;

use shitspeak_core::NodeIdentifier;

pub(crate) const TREE_HINT_ATTACHMENT_KIND: u32 = 1;
const MAX_ATTACHMENT_BYTES: usize = 256 * 1024;
const MAX_ATTACHMENT_CHUNKS: usize = 512;
const MAX_CACHED_ENTRIES: usize = 64;
const ATTACHMENT_CACHE_TTL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct AttachmentKey {
    source: NodeIdentifier,
    origin_boot_epoch: u64,
    origin_message_id: u64,
    kind: u32,
    attachment_id: u64,
}

impl AttachmentKey {
    pub(crate) fn new(
        source: NodeIdentifier,
        origin_boot_epoch: u64,
        origin_message_id: u64,
        kind: u32,
        attachment_id: u64,
    ) -> Self {
        Self {
            source,
            origin_boot_epoch,
            origin_message_id,
            kind,
            attachment_id,
        }
    }
}

#[derive(Default)]
pub(crate) struct AttachmentCache {
    inner: Mutex<HashMap<AttachmentKey, AttachmentEntry>>,
}

struct AttachmentEntry {
    total_bytes: usize,
    chunk_count: usize,
    chunks: BTreeMap<usize, Bytes>,
    expires_at: Instant,
}

impl AttachmentCache {
    pub(crate) fn insert_inline(&self, key: AttachmentKey, payload: Bytes) -> Option<Bytes> {
        if payload.len() > MAX_ATTACHMENT_BYTES {
            return None;
        }
        self.purge_expired();
        let mut inner = self.inner.lock();
        evict_oldest_if_full(&mut inner, key);
        inner.insert(
            key,
            AttachmentEntry {
                total_bytes: payload.len(),
                chunk_count: 1,
                chunks: BTreeMap::from([(0, payload.clone())]),
                expires_at: Instant::now() + ATTACHMENT_CACHE_TTL,
            },
        );
        Some(payload)
    }

    pub(crate) fn insert_chunk(
        &self,
        key: AttachmentKey,
        chunk_index: usize,
        chunk_count: usize,
        total_bytes: usize,
        payload: Bytes,
    ) -> Option<Bytes> {
        if chunk_count == 0
            || chunk_count > MAX_ATTACHMENT_CHUNKS
            || chunk_index >= chunk_count
            || total_bytes > MAX_ATTACHMENT_BYTES
            || payload.len() > total_bytes
        {
            return None;
        }
        self.purge_expired();
        let mut inner = self.inner.lock();
        if let Some(entry) = inner.get(&key)
            && entry.chunk_count == 1
            && entry.total_bytes == entry.chunks.get(&0).map_or(usize::MAX, Bytes::len)
        {
            return entry.chunks.get(&0).cloned();
        }
        if !inner.contains_key(&key) {
            evict_oldest_if_full(&mut inner, key);
        }
        let entry = inner.entry(key).or_insert_with(|| AttachmentEntry {
            total_bytes,
            chunk_count,
            chunks: BTreeMap::new(),
            expires_at: Instant::now() + ATTACHMENT_CACHE_TTL,
        });
        if entry.total_bytes != total_bytes || entry.chunk_count != chunk_count {
            inner.remove(&key);
            return None;
        }
        entry.expires_at = Instant::now() + ATTACHMENT_CACHE_TTL;
        entry.chunks.entry(chunk_index).or_insert(payload);
        let received = entry.chunks.values().map(Bytes::len).sum::<usize>();
        if entry.chunks.len() != chunk_count || received != total_bytes {
            return None;
        }
        let mut assembled = Vec::with_capacity(total_bytes);
        for index in 0..chunk_count {
            let chunk = entry.chunks.get(&index)?;
            assembled.extend_from_slice(chunk);
        }
        if assembled.len() != total_bytes {
            inner.remove(&key);
            return None;
        }
        let payload = Bytes::from(assembled);
        inner.insert(
            key,
            AttachmentEntry {
                total_bytes,
                chunk_count: 1,
                chunks: BTreeMap::from([(0, payload.clone())]),
                expires_at: Instant::now() + ATTACHMENT_CACHE_TTL,
            },
        );
        Some(payload)
    }

    pub(crate) fn get(&self, key: AttachmentKey) -> Option<Bytes> {
        self.purge_expired();
        let inner = self.inner.lock();
        let entry = inner.get(&key)?;
        if entry.chunks.len() != entry.chunk_count {
            return None;
        }
        let mut assembled = Vec::with_capacity(entry.total_bytes);
        for index in 0..entry.chunk_count {
            assembled.extend_from_slice(entry.chunks.get(&index)?);
        }
        (assembled.len() == entry.total_bytes).then(|| Bytes::from(assembled))
    }

    fn purge_expired(&self) {
        let now = Instant::now();
        self.inner.lock().retain(|_, entry| entry.expires_at > now);
    }
}

fn evict_oldest_if_full(inner: &mut HashMap<AttachmentKey, AttachmentEntry>, keep: AttachmentKey) {
    if inner.len() < MAX_CACHED_ENTRIES {
        return;
    }
    let Some(oldest) = inner
        .iter()
        .filter(|(key, _)| **key != keep)
        .min_by_key(|(_, entry)| entry.expires_at)
        .map(|(key, _)| *key)
    else {
        return;
    };
    inner.remove(&oldest);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> AttachmentKey {
        AttachmentKey::new(7, 11, 13, 17, 19)
    }

    #[test]
    fn inline_payload_is_available_as_a_complete_attachment() {
        let cache = AttachmentCache::default();
        assert_eq!(
            cache.insert_inline(key(), Bytes::from_static(b"hint")),
            Some(Bytes::from_static(b"hint"))
        );
        assert_eq!(cache.get(key()), Some(Bytes::from_static(b"hint")));
    }

    #[test]
    fn chunks_reassemble_in_order_and_ignore_duplicates() {
        let cache = AttachmentCache::default();
        assert_eq!(
            cache.insert_chunk(key(), 1, 3, 6, Bytes::from_static(b"ef")),
            None
        );
        assert_eq!(
            cache.insert_chunk(key(), 1, 3, 6, Bytes::from_static(b"wrong")),
            None
        );
        assert_eq!(
            cache.insert_chunk(key(), 0, 3, 6, Bytes::from_static(b"ab")),
            None
        );
        assert_eq!(
            cache.insert_chunk(key(), 2, 3, 6, Bytes::from_static(b"gh")),
            Some(Bytes::from_static(b"abefgh"))
        );
        assert_eq!(cache.get(key()), Some(Bytes::from_static(b"abefgh")));
    }

    #[test]
    fn invalid_chunk_bounds_are_discarded() {
        let cache = AttachmentCache::default();
        assert_eq!(
            cache.insert_chunk(
                key(),
                0,
                MAX_ATTACHMENT_CHUNKS + 1,
                1,
                Bytes::from_static(b"x")
            ),
            None
        );
        assert_eq!(
            cache.insert_chunk(key(), 1, 1, 1, Bytes::from_static(b"x")),
            None
        );
        assert_eq!(
            cache.insert_chunk(key(), 0, 1, MAX_ATTACHMENT_BYTES + 1, Bytes::new()),
            None
        );
    }
}
