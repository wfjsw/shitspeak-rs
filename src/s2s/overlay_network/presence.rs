use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

use super::NodeId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePresenceRecord {
    pub node_id: NodeId,
    pub metadata: HashMap<String, String>,
    pub metadata_updated_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodePresenceDelta {
    MetadataUpsert {
        node_id: NodeId,
        key: String,
        value: String,
        updated_ms: u64,
    },
    MetadataRemove {
        node_id: NodeId,
        key: String,
        updated_ms: u64,
    },
    MetadataReplace {
        node_id: NodeId,
        metadata: HashMap<String, String>,
        updated_ms: u64,
    },
}

#[derive(Debug, Default, Clone)]
pub struct NodePresenceMap {
    nodes: HashMap<NodeId, NodePresenceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceDigestEntry {
    pub node_id: NodeId,
    pub metadata_hash: u64,
    pub metadata_updated_ms: u64,
}

impl NodePresenceMap {
    pub fn apply_delta(&mut self, delta: NodePresenceDelta) {
        match delta {
            NodePresenceDelta::MetadataUpsert {
                node_id,
                key,
                value,
                updated_ms,
            } => {
                self.nodes
                    .entry(node_id)
                    .and_modify(|entry| {
                        if updated_ms >= entry.metadata_updated_ms {
                            entry.metadata.insert(key.clone(), value.clone());
                            entry.metadata_updated_ms = updated_ms;
                        }
                    })
                    .or_insert_with(|| NodePresenceRecord {
                        node_id,
                        metadata: HashMap::from([(key, value)]),
                        metadata_updated_ms: updated_ms,
                    });
            }
            NodePresenceDelta::MetadataRemove {
                node_id,
                key,
                updated_ms,
            } => {
                if let Some(existing) = self.nodes.get_mut(&node_id) {
                    if updated_ms >= existing.metadata_updated_ms {
                        existing.metadata.remove(&key);
                        existing.metadata_updated_ms = updated_ms;
                    }
                }
            }
            NodePresenceDelta::MetadataReplace {
                node_id,
                metadata,
                updated_ms,
            } => {
                self.nodes
                    .entry(node_id)
                    .and_modify(|entry| {
                        if updated_ms >= entry.metadata_updated_ms {
                            entry.metadata = metadata.clone();
                            entry.metadata_updated_ms = updated_ms;
                        }
                    })
                    .or_insert_with(|| NodePresenceRecord {
                        node_id,
                        metadata,
                        metadata_updated_ms: updated_ms,
                    });
            }
        }
    }

    pub fn digest(&self) -> Vec<PresenceDigestEntry> {
        let mut digest = self
            .nodes
            .values()
            .map(|node| PresenceDigestEntry {
                node_id: node.node_id,
                metadata_hash: hash_metadata(&node.metadata),
                metadata_updated_ms: node.metadata_updated_ms,
            })
            .collect::<Vec<_>>();
        digest.sort_by_key(|e| e.node_id);
        digest
    }

    pub fn stale_nodes_against(&self, remote: &[PresenceDigestEntry]) -> Vec<NodeId> {
        remote
            .iter()
            .filter_map(|entry| {
                let local = self.nodes.get(&entry.node_id);
                let stale = match local {
                    None => true,
                    Some(local) => {
                        local.metadata_updated_ms < entry.metadata_updated_ms
                            || hash_metadata(&local.metadata) != entry.metadata_hash
                    }
                };
                stale.then_some(entry.node_id)
            })
            .collect()
    }
}

fn hash_metadata(metadata: &HashMap<String, String>) -> u64 {
    let mut items = metadata
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect::<Vec<_>>();
    items.sort_unstable();

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for (k, v) in items {
        k.hash(&mut hasher);
        v.hash(&mut hasher);
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_upsert_and_remove_respect_timestamp() {
        let mut map = NodePresenceMap::default();
        map.apply_delta(NodePresenceDelta::MetadataUpsert {
            node_id: 1,
            key: "region".to_owned(),
            value: "us".to_owned(),
            updated_ms: 10,
        });
        map.apply_delta(NodePresenceDelta::MetadataUpsert {
            node_id: 1,
            key: "region".to_owned(),
            value: "eu".to_owned(),
            updated_ms: 5,
        });
        let digest = map.digest();
        assert_eq!(digest.len(), 1);

        map.apply_delta(NodePresenceDelta::MetadataRemove {
            node_id: 1,
            key: "region".to_owned(),
            updated_ms: 11,
        });
        let after = map.digest();
        assert_ne!(digest[0].metadata_hash, after[0].metadata_hash);
    }

    #[test]
    fn stale_nodes_detect_missing_or_old_metadata() {
        let mut map = NodePresenceMap::default();
        map.apply_delta(NodePresenceDelta::MetadataUpsert {
            node_id: 2,
            key: "a".to_owned(),
            value: "1".to_owned(),
            updated_ms: 10,
        });

        let remote = vec![PresenceDigestEntry {
            node_id: 2,
            metadata_hash: 0,
            metadata_updated_ms: 11,
        }];
        assert_eq!(map.stale_nodes_against(&remote), vec![2]);
    }
}
