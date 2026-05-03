//! Recipient index for the opt-in `delivery_strategy = "targeted"`
//! voice mode.
//!
//! Maps `channel_id → set<NodeIdentifier>` so a speaker's node can
//! compute the set of cross-node recipients for normal channel speech
//! (and for whisper-to-channel) instead of broadcasting.
//!
//! ## Why this is opt-in
//!
//! Per the design notes in [`crate::s2s::application`], broadcast is
//! the default because:
//!
//! 1. Receivers only parse the small envelope — no Opus decode.
//! 2. Overlay routing pays transit cost on relay nodes whether the
//!    payload is targeted or broadcast.
//! 3. Targeted depends on a fresh recipient index; staleness reorders
//!    risk silently dropping listeners on a re-routed cluster.
//!
//! Targeted only saves the *leaf* nodes that aren't recipients. For
//! large clusters with bandwidth-constrained leaf links, that can be
//! material — operators flip the strategy to `"targeted"` and bench.
//!
//! ## Index maintenance
//!
//! This module ships the in-memory data structure and the lookup API.
//! Population is left to the Server layer: each node knows its own
//! clients' channels and can either (a) periodically broadcast its
//! channel-residency summary (`set<channel_id>`) on a low-frequency
//! tag, or (b) leverage owner-scoped `ClientRepository` deltas (every
//! client move triggers a delta the speaker can observe via the same
//! replication stream). The reconcile cadence
//! ([`VoiceConfig::recipient_index_reconcile_secs`]) governs the
//! period if option (a) is used.
//!
//! Until that wiring is in place, `RecipientIndex::lookup_nodes_for`
//! returns an empty set; the speaker-side fallback in
//! [`VoiceService::send_for_channel`](super::ingress::VoiceService::send_for_channel)
//! is to broadcast — i.e., targeted mode degrades safely to broadcast
//! when the index isn't populated yet.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use parking_lot::RwLock;

use crate::types::NodeIdentifier;

/// Channel-id → set of nodes hosting at least one interested client.
///
/// Cheap to clone — internally `Arc<RwLock<...>>`. The map is replaced
/// wholesale on each reconcile pass to keep the read path lock-light.
pub struct RecipientIndex {
    inner: Arc<RwLock<HashMap<u32, BTreeSet<NodeIdentifier>>>>,
}

impl RecipientIndex {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Replace the membership set for `channel_id`. Pass an empty set
    /// to mark a channel as deserted (the lookup will then return None).
    pub fn set_channel_nodes(&self, channel_id: u32, nodes: BTreeSet<NodeIdentifier>) {
        let mut g = self.inner.write();
        if nodes.is_empty() {
            g.remove(&channel_id);
        } else {
            g.insert(channel_id, nodes);
        }
    }

    /// Replace the entire index in one shot. Cheaper than many
    /// per-channel `set_channel_nodes` calls when the reconciler has a
    /// fresh full snapshot.
    pub fn replace_all(&self, snapshot: HashMap<u32, BTreeSet<NodeIdentifier>>) {
        *self.inner.write() = snapshot;
    }

    /// Add `node` as an interested party in `channel_id`. Idempotent.
    pub fn add(&self, channel_id: u32, node: NodeIdentifier) {
        let mut g = self.inner.write();
        g.entry(channel_id).or_default().insert(node);
    }

    /// Remove `node` from `channel_id`. If the channel ends up empty,
    /// it's dropped from the index.
    pub fn remove(&self, channel_id: u32, node: NodeIdentifier) {
        let mut g = self.inner.write();
        if let Some(set) = g.get_mut(&channel_id) {
            set.remove(&node);
            if set.is_empty() {
                g.remove(&channel_id);
            }
        }
    }

    /// Look up the set of nodes interested in `channel_id`. Returns
    /// `None` if the index has no entry — caller should then broadcast.
    pub fn lookup_nodes_for(&self, channel_id: u32) -> Option<Vec<NodeIdentifier>> {
        let g = self.inner.read();
        g.get(&channel_id).map(|s| s.iter().copied().collect())
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
    fn replace_all_overwrites() {
        let idx = RecipientIndex::new();
        idx.add(1, 10);
        idx.add(2, 20);
        let mut snapshot = HashMap::new();
        snapshot.insert(3, [30, 31].into_iter().collect());
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
