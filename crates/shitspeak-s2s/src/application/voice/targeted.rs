//! Recipient index for the opt-in `delivery_strategy = "targeted"`
//! voice mode.
//!
//! Maps `(server_id, channel_id) → set<NodeIdentifier>` so a speaker's
//! node can choose likely destination nodes for normal channel speech.
//! Frames still carry unresolved voice intent, never resolved recipient
//! sessions; each receiving node resolves local recipients itself.
//!
//! ## Why this is opt-in
//!
//! Per the design notes in [`crate::application`], broadcast is
//! the default because:
//!
//! 1. Receivers only parse the small envelope — no Opus decode.
//! 2. Overlay routing pays transit cost on relay nodes whether the
//!    payload is targeted or broadcast.
//! 3. Targeted depends on a fresh recipient index; staleness can omit
//!    a node that would have resolved local recipients.
//!
//! Targeted only saves the *leaf* nodes that aren't recipients. For
//! large clusters with bandwidth-constrained leaf links, that can be
//! material — operators flip the strategy to `"targeted"` and bench.
//!
//! ## Index maintenance
//!
//! Runtime code populates this structure from the replicated
//! `ClientRepository` view. When an entry is missing or stale, the
//! speaker-side fallback in
//! [`VoiceService::send_for_channel`](super::ingress::VoiceService::send_for_channel)
//! degrades safely to the normal broad voice-member fan-out.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;
use scc::HashCache;

use shitspeak_core::{NodeIdentifier, default_server_id};

const REMOTE_NODE_LOOKUP_CACHE_MIN_CAPACITY: usize = 256;
const REMOTE_NODE_LOOKUP_CACHE_CHANNEL_MULTIPLIER: usize = 4;
const REMOTE_NODE_LOOKUP_CACHE_MAX_CAPACITY: usize = 65536;

/// Server-scoped recipient-index key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecipientIndexKey {
    server_id: String,
    channel_id: u32,
}

impl RecipientIndexKey {
    pub fn new(server_id: impl Into<String>, channel_id: u32) -> Self {
        Self {
            server_id: server_id.into(),
            channel_id,
        }
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }
}

/// Full recipient-index snapshot used by the runtime refresh bridge.
pub type RecipientIndexSnapshot = HashMap<RecipientIndexKey, BTreeSet<NodeIdentifier>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RemoteNodeLookup {
    Nodes(Arc<[NodeIdentifier]>),
    Missing { channel_id: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RemoteNodeLookupCacheKey {
    generation: u64,
    server_id: String,
    channel_ids: Vec<u32>,
    local_node_id: NodeIdentifier,
}

struct RemoteNodeLookupCache {
    state: RwLock<RemoteNodeLookupCacheState>,
}

struct RemoteNodeLookupCacheState {
    cache: Arc<HashCache<RemoteNodeLookupCacheKey, RemoteNodeLookup>>,
    current_max_capacity: usize,
}

impl RemoteNodeLookupCache {
    fn new(channel_count: usize) -> Self {
        let current_max_capacity = remote_node_lookup_cache_capacity(channel_count);
        Self {
            state: RwLock::new(RemoteNodeLookupCacheState {
                cache: Arc::new(HashCache::with_capacity(0, current_max_capacity)),
                current_max_capacity,
            }),
        }
    }

    fn read(&self, key: &RemoteNodeLookupCacheKey) -> Option<RemoteNodeLookup> {
        let cache = self.cache();
        cache.read_sync(key, |_, lookup| lookup.clone())
    }

    fn put(&self, key: RemoteNodeLookupCacheKey, value: RemoteNodeLookup) {
        let mut state = self.state.write();
        if state.current_max_capacity < REMOTE_NODE_LOOKUP_CACHE_MAX_CAPACITY
            && state.cache.len().saturating_mul(4) >= state.current_max_capacity.saturating_mul(3)
        {
            let next_capacity = state
                .current_max_capacity
                .saturating_mul(2)
                .min(REMOTE_NODE_LOOKUP_CACHE_MAX_CAPACITY);
            let next_cache = Arc::new(HashCache::with_capacity(0, next_capacity));
            state.cache.iter_sync(|key, value| {
                next_cache.entry_sync(key.clone()).put_entry(value.clone());
                true
            });
            *state = RemoteNodeLookupCacheState {
                cache: next_cache,
                current_max_capacity: next_capacity,
            };
        }
        state.cache.entry_sync(key).put_entry(value);
    }

    fn reset_for_channel_count(&self, channel_count: usize) {
        let desired_capacity = remote_node_lookup_cache_capacity(channel_count);
        let mut state = self.state.write();
        if state.current_max_capacity == desired_capacity {
            state.cache.clear_sync();
            return;
        }
        *state = RemoteNodeLookupCacheState {
            cache: Arc::new(HashCache::with_capacity(0, desired_capacity)),
            current_max_capacity: desired_capacity,
        };
    }

    #[cfg(test)]
    fn current_max_capacity(&self) -> usize {
        self.state.read().current_max_capacity
    }

    fn cache(&self) -> Arc<HashCache<RemoteNodeLookupCacheKey, RemoteNodeLookup>> {
        self.state.read().cache.clone()
    }
}

fn remote_node_lookup_cache_capacity(channel_count: usize) -> usize {
    channel_count
        .saturating_mul(REMOTE_NODE_LOOKUP_CACHE_CHANNEL_MULTIPLIER)
        .max(REMOTE_NODE_LOOKUP_CACHE_MIN_CAPACITY)
        .min(REMOTE_NODE_LOOKUP_CACHE_MAX_CAPACITY)
        .next_power_of_two()
}

/// (server-id, channel-id) → set of nodes hosting at least one interested
/// client.
///
/// Cheap to clone — internally `Arc<RwLock<...>>`. The map is replaced
/// wholesale on each reconcile pass to keep the read path lock-light.
pub struct RecipientIndex {
    inner: Arc<RwLock<RecipientIndexSnapshot>>,
    generation: AtomicU64,
    remote_node_lookup_cache: RemoteNodeLookupCache,
}

impl RecipientIndex {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            generation: AtomicU64::new(0),
            remote_node_lookup_cache: RemoteNodeLookupCache::new(0),
        })
    }

    /// Replace the membership set for a channel. Pass an empty set to mark
    /// it as deserted (the lookup will then return None).
    pub fn set_channel_nodes_in_server(
        &self,
        server_id: &str,
        channel_id: u32,
        nodes: BTreeSet<NodeIdentifier>,
    ) {
        let channel_count = {
            let mut g = self.inner.write();
            let key = RecipientIndexKey::new(server_id, channel_id);
            if nodes.is_empty() {
                g.remove(&key);
            } else {
                g.insert(key, nodes);
            }
            g.len()
        };
        self.invalidate_remote_node_lookup_cache(channel_count);
    }

    /// Replace the entire index in one shot. Cheaper than many
    /// per-channel `set_channel_nodes` calls when the reconciler has a
    /// fresh full snapshot.
    pub fn replace_all(&self, snapshot: RecipientIndexSnapshot) {
        let channel_count = snapshot.len();
        *self.inner.write() = snapshot;
        self.invalidate_remote_node_lookup_cache(channel_count);
    }

    /// Add `node` as an interested party in `channel_id`. Idempotent.
    pub fn add_in_server(&self, server_id: &str, channel_id: u32, node: NodeIdentifier) {
        let channel_count = {
            let mut g = self.inner.write();
            g.entry(RecipientIndexKey::new(server_id, channel_id))
                .or_default()
                .insert(node);
            g.len()
        };
        self.invalidate_remote_node_lookup_cache(channel_count);
    }

    /// Remove `node` from `channel_id`. If the channel ends up empty,
    /// it's dropped from the index.
    pub fn remove_in_server(&self, server_id: &str, channel_id: u32, node: NodeIdentifier) {
        let channel_count = {
            let mut g = self.inner.write();
            let key = RecipientIndexKey::new(server_id, channel_id);
            if let Some(set) = g.get_mut(&key) {
                set.remove(&node);
                if set.is_empty() {
                    g.remove(&key);
                }
            }
            g.len()
        };
        self.invalidate_remote_node_lookup_cache(channel_count);
    }

    /// Look up the set of nodes interested in `channel_id`. Returns
    /// `None` if the index has no entry — caller should then broadcast.
    pub fn lookup_nodes_for_in_server(
        &self,
        server_id: &str,
        channel_id: u32,
    ) -> Option<Vec<NodeIdentifier>> {
        let g = self.inner.read();
        g.get(&RecipientIndexKey::new(server_id, channel_id))
            .map(|s| s.iter().copied().collect())
    }

    pub(crate) fn lookup_remote_nodes_for_in_server(
        &self,
        server_id: &str,
        channel_id: u32,
        local_node_id: NodeIdentifier,
    ) -> RemoteNodeLookup {
        self.lookup_remote_nodes_for_channels_in_server(server_id, &[channel_id], local_node_id)
    }

    pub(crate) fn lookup_remote_nodes_for_channels_in_server(
        &self,
        server_id: &str,
        channel_ids: &[u32],
        local_node_id: NodeIdentifier,
    ) -> RemoteNodeLookup {
        let generation = self.generation();
        let cache_key = RemoteNodeLookupCacheKey {
            generation,
            server_id: server_id.to_owned(),
            channel_ids: channel_ids.to_vec(),
            local_node_id,
        };

        if let Some(lookup) = self.remote_node_lookup_cache.read(&cache_key) {
            return lookup;
        }

        let lookup =
            self.lookup_remote_nodes_for_channels_uncached(server_id, channel_ids, local_node_id);
        self.remote_node_lookup_cache.put(cache_key, lookup.clone());
        lookup
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Default-server compatibility wrapper.
    pub fn set_channel_nodes(&self, channel_id: u32, nodes: BTreeSet<NodeIdentifier>) {
        self.set_channel_nodes_in_server(default_server_id().as_str(), channel_id, nodes);
    }

    /// Default-server compatibility wrapper.
    pub fn add(&self, channel_id: u32, node: NodeIdentifier) {
        self.add_in_server(default_server_id().as_str(), channel_id, node);
    }

    /// Default-server compatibility wrapper.
    pub fn remove(&self, channel_id: u32, node: NodeIdentifier) {
        self.remove_in_server(default_server_id().as_str(), channel_id, node);
    }

    /// Default-server compatibility wrapper.
    pub fn lookup_nodes_for(&self, channel_id: u32) -> Option<Vec<NodeIdentifier>> {
        self.lookup_nodes_for_in_server(default_server_id().as_str(), channel_id)
    }

    /// Number of channels currently tracked. Mostly for tests / metrics.
    pub fn channel_count(&self) -> usize {
        self.inner.read().len()
    }

    fn lookup_remote_nodes_for_channels_uncached(
        &self,
        server_id: &str,
        channel_ids: &[u32],
        local_node_id: NodeIdentifier,
    ) -> RemoteNodeLookup {
        let g = self.inner.read();
        if let [channel_id] = channel_ids {
            return match g.get(&RecipientIndexKey::new(server_id, *channel_id)) {
                Some(nodes) => RemoteNodeLookup::Nodes(
                    nodes
                        .iter()
                        .copied()
                        .filter(|node| *node != local_node_id)
                        .collect::<Vec<_>>()
                        .into(),
                ),
                None => RemoteNodeLookup::Missing {
                    channel_id: *channel_id,
                },
            };
        }

        let mut remote_nodes = BTreeSet::new();
        for channel_id in channel_ids {
            let Some(nodes) = g.get(&RecipientIndexKey::new(server_id, *channel_id)) else {
                return RemoteNodeLookup::Missing {
                    channel_id: *channel_id,
                };
            };
            remote_nodes.extend(nodes.iter().copied().filter(|node| *node != local_node_id));
        }

        RemoteNodeLookup::Nodes(remote_nodes.into_iter().collect::<Vec<_>>().into())
    }

    #[cfg(test)]
    fn remote_node_lookup_cache_max_capacity(&self) -> usize {
        self.remote_node_lookup_cache.current_max_capacity()
    }

    fn invalidate_remote_node_lookup_cache(&self, channel_count: usize) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.remote_node_lookup_cache
            .reset_for_channel_count(channel_count);
    }
}

impl Default for RecipientIndex {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            generation: AtomicU64::new(0),
            remote_node_lookup_cache: RemoteNodeLookupCache::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_remove_lookup() {
        let idx = RecipientIndex::new();
        idx.add(7, 1);
        idx.add(7, 2);
        idx.add(7, 3);
        let mut nodes = idx.lookup_nodes_for(7).unwrap();
        nodes.sort();
        assert_eq!(nodes, vec![1, 2, 3]);

        idx.remove(7, 2);
        let mut nodes = idx.lookup_nodes_for(7).unwrap();
        nodes.sort();
        assert_eq!(nodes, vec![1, 3]);

        idx.remove(7, 1);
        idx.remove(7, 3);
        assert!(idx.lookup_nodes_for(7).is_none());
        assert_eq!(idx.channel_count(), 0);
    }

    #[test]
    fn scoped_channels_with_same_id_do_not_collide() {
        let idx = RecipientIndex::new();
        idx.add_in_server("alpha", 7, 1);
        idx.add_in_server("beta", 7, 2);

        assert_eq!(idx.lookup_nodes_for_in_server("alpha", 7), Some(vec![1]));
        assert_eq!(idx.lookup_nodes_for_in_server("beta", 7), Some(vec![2]));
        assert!(idx.lookup_nodes_for_in_server("gamma", 7).is_none());
    }

    #[test]
    fn replace_all_overwrites() {
        let idx = RecipientIndex::new();
        idx.add(1, 10);
        idx.add(2, 20);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            RecipientIndexKey::new(default_server_id(), 3),
            [30, 31].into_iter().collect(),
        );
        idx.replace_all(snapshot);
        assert!(idx.lookup_nodes_for(1).is_none());
        assert!(idx.lookup_nodes_for(2).is_none());
        let mut nodes = idx.lookup_nodes_for(3).unwrap();
        nodes.sort();
        assert_eq!(nodes, vec![30, 31]);
    }

    #[test]
    fn set_channel_nodes_empty_removes() {
        let idx = RecipientIndex::new();
        idx.add(7, 1);
        idx.set_channel_nodes(7, BTreeSet::new());
        assert!(idx.lookup_nodes_for(7).is_none());
    }

    #[test]
    fn remote_lookup_filters_self_and_reuses_cached_nodes() {
        let idx = RecipientIndex::new();
        idx.add(5, 1);
        idx.add(5, 2);
        idx.add(5, 7);

        let first = idx.lookup_remote_nodes_for_in_server(default_server_id().as_str(), 5, 7);
        let second = idx.lookup_remote_nodes_for_in_server(default_server_id().as_str(), 5, 7);

        match (first, second) {
            (RemoteNodeLookup::Nodes(first), RemoteNodeLookup::Nodes(second)) => {
                assert_eq!(first.as_ref(), &[1, 2]);
                assert!(Arc::ptr_eq(&first, &second));
            }
            other => panic!("expected cached node lookups, got {other:?}"),
        }
    }

    #[test]
    fn remote_lookup_generation_invalidates_on_replace_all() {
        let idx = RecipientIndex::new();
        idx.add(5, 1);
        let generation_after_add = idx.generation();

        let before = idx.lookup_remote_nodes_for_in_server(default_server_id().as_str(), 5, 7);
        assert!(matches!(
            before,
            RemoteNodeLookup::Nodes(nodes) if nodes.as_ref() == &[1]
        ));

        let mut snapshot = HashMap::new();
        snapshot.insert(
            RecipientIndexKey::new(default_server_id(), 5),
            [2, 7].into_iter().collect(),
        );
        idx.replace_all(snapshot);
        assert!(idx.generation() > generation_after_add);

        let after = idx.lookup_remote_nodes_for_in_server(default_server_id().as_str(), 5, 7);
        assert!(matches!(
            after,
            RemoteNodeLookup::Nodes(nodes) if nodes.as_ref() == &[2]
        ));
    }

    #[test]
    fn remote_lookup_missing_channel_preserves_fallback_signal() {
        let idx = RecipientIndex::new();
        idx.add(5, 1);

        let single = idx.lookup_remote_nodes_for_in_server(default_server_id().as_str(), 6, 7);
        assert_eq!(single, RemoteNodeLookup::Missing { channel_id: 6 });

        let multi = idx.lookup_remote_nodes_for_channels_in_server(
            default_server_id().as_str(),
            &[5, 6],
            7,
        );
        assert_eq!(multi, RemoteNodeLookup::Missing { channel_id: 6 });
    }

    #[test]
    fn remote_lookup_deduplicates_target_channels_and_noops_self_only() {
        let idx = RecipientIndex::new();
        idx.add(5, 1);
        idx.add(5, 7);
        idx.add(6, 1);
        idx.add(6, 2);
        idx.add(8, 7);

        let lookup = idx.lookup_remote_nodes_for_channels_in_server(
            default_server_id().as_str(),
            &[5, 6],
            7,
        );
        assert!(matches!(
            lookup,
            RemoteNodeLookup::Nodes(nodes) if nodes.as_ref() == &[1, 2]
        ));

        let self_only = idx.lookup_remote_nodes_for_in_server(default_server_id().as_str(), 8, 7);
        assert!(matches!(
            self_only,
            RemoteNodeLookup::Nodes(nodes) if nodes.is_empty()
        ));
    }

    #[test]
    fn remote_lookup_cache_capacity_tracks_snapshot_size() {
        let idx = RecipientIndex::new();
        assert_eq!(
            idx.remote_node_lookup_cache_max_capacity(),
            REMOTE_NODE_LOOKUP_CACHE_MIN_CAPACITY
        );

        let mut snapshot = HashMap::new();
        for channel_id in 0..100 {
            snapshot.insert(
                RecipientIndexKey::new(default_server_id(), channel_id),
                [1].into_iter().collect(),
            );
        }
        idx.replace_all(snapshot);
        assert_eq!(idx.remote_node_lookup_cache_max_capacity(), 512);

        idx.replace_all(HashMap::new());
        assert_eq!(
            idx.remote_node_lookup_cache_max_capacity(),
            REMOTE_NODE_LOOKUP_CACHE_MIN_CAPACITY
        );
    }
}
