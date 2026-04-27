use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::s2s::overlay_network::NodeId;

pub type VersionVector = BTreeMap<NodeId, u64>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OwnerReplicaRole {
    Writable,
    ReadOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnerOrderedFrame<T> {
    pub origin_node: NodeId,
    pub origin_version: u64,
    pub timestamp_ms: u64,
    pub payload: T,
}
