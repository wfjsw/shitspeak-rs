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

use parking_lot::RwLock;

use shitspeak_core::{NodeIdentifier, default_server_id};

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

/// (server-id, channel-id) → set of nodes hosting at least one interested
/// client.
///
/// Cheap to clone — internally `Arc<RwLock<...>>`. The map is replaced
/// wholesale on each reconcile pass to keep the read path lock-light.
pub struct RecipientIndex {
    inner: Arc<RwLock<RecipientIndexSnapshot>>,
}

impl RecipientIndex {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
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
        let mut g = self.inner.write();
        let key = RecipientIndexKey::new(server_id, channel_id);
        if nodes.is_empty() {
            g.remove(&key);
        } else {
            g.insert(key, nodes);
        }
    }

    /// Replace the entire index in one shot. Cheaper than many
    /// per-channel `set_channel_nodes` calls when the reconciler has a
    /// fresh full snapshot.
    pub fn replace_all(&self, snapshot: RecipientIndexSnapshot) {
        *self.inner.write() = snapshot;
    }

    /// Add `node` as an interested party in `channel_id`. Idempotent.
    pub fn add_in_server(&self, server_id: &str, channel_id: u32, node: NodeIdentifier) {
        let mut g = self.inner.write();
        g.entry(RecipientIndexKey::new(server_id, channel_id))
            .or_default()
            .insert(node);
    }

    /// Remove `node` from `channel_id`. If the channel ends up empty,
    /// it's dropped from the index.
    pub fn remove_in_server(&self, server_id: &str, channel_id: u32, node: NodeIdentifier) {
        let mut g = self.inner.write();
        let key = RecipientIndexKey::new(server_id, channel_id);
        if let Some(set) = g.get_mut(&key) {
            set.remove(&node);
            if set.is_empty() {
                g.remove(&key);
            }
        }
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
}

impl Default for RecipientIndex {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
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
}
