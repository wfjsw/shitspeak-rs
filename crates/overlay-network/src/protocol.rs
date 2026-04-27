use serde::{Deserialize, Serialize};

use crate::membership::MemberRecord;
use crate::presence::NodePresenceDelta;
use crate::routing::{RouteClass, RoutePath};
use crate::NodeId;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessageMode {
    Unicast,
    Multicast,
    Broadcast,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClusterMessage {
    Heartbeat {
        boot_id: String,
        members_seen: usize,
    },
    MembershipUpdate {
        record: MemberRecord,
    },
    NodePresence {
        delta: NodePresenceDelta,
    },
    PeerList {
        peers: Vec<String>,
    },
    DataForward {
        route_class: RouteClass,
        path: RoutePath,
        stream_id: u64,
        sequence: u64,
        path_trace: Vec<NodeId>,
        content_type: String,
        payload: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterEnvelope {
    pub version: u16,
    pub feature_bitmap: u64,
    pub from: NodeId,
    pub seq: u64,
    pub mode: MessageMode,
    pub body: ClusterMessage,
}
