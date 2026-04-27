use serde::{Deserialize, Serialize};

use super::membership::MemberRecord;
use super::presence::NodePresenceDelta;
use super::routing::{RouteClass, RoutePath};
use super::NodeId;

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
    Layer2 {
        message: ConsensusLayer2Message,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusLayer2Message {
    ReplicatedFrame {
        index: u64,
        term: u64,
        payload: Vec<u8>,
    },
    Layer3 {
        message: ApplicationLayer3Message,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApplicationLayer3Message {
    Replication {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_serialization_roundtrip() {
        let envelope = ClusterEnvelope {
            version: 1,
            feature_bitmap: 0,
            from: 1,
            seq: 42,
            mode: MessageMode::Unicast,
            body: ClusterMessage::Heartbeat {
                boot_id: "boot-1".to_owned(),
                members_seen: 3,
            },
        };

        let bytes = serde_json::to_vec(&envelope).expect("serialize envelope should work");
        let decoded: ClusterEnvelope =
            serde_json::from_slice(&bytes).expect("deserialize envelope should work");
        assert_eq!(decoded.seq, 42);
        assert_eq!(decoded.from, 1);
        assert!(matches!(decoded.body, ClusterMessage::Heartbeat { .. }));
    }
}
