use bytes::Bytes;
use tokio::sync::broadcast;

use crate::s2s::core::transport::StreamClass;
use crate::s2s::core::NodeId;

#[derive(Debug, Clone)]
pub struct OverlayFrame {
    pub from: NodeId,
    pub recipients: Vec<NodeId>,
    pub class: StreamClass,
    pub payload: Bytes,
    pub path_trace: Vec<NodeId>,
}

#[derive(Debug, Clone)]
pub enum ClusterEvent {
    MemberAlive { node: NodeId, boot_id: String },
    MemberDead { node: NodeId },
    BootEpochChanged { node: NodeId, old: String, new: String },
}

pub trait ClusterView: Send + Sync {
    fn local_node(&self) -> NodeId;
    fn alive_nodes_excluding_self(&self) -> Vec<NodeId>;
    fn resolve_next_hop(&self, dst: NodeId) -> Option<NodeId>;
    fn resolve_direct_hop(&self, dst: NodeId) -> Option<NodeId>;
}

#[derive(Debug, Clone, Default)]
pub struct SendReceipt {
    pub delivered_to: usize,
}

#[derive(Debug, Clone, Default)]
pub struct DirectSendReceipt {
    pub attempted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct UnreliableSendReceipt {
    pub attempted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct MulticastReceipt {
    pub fanout_buckets: usize,
    pub recipients: usize,
}

pub type EventReceiver = broadcast::Receiver<ClusterEvent>;
