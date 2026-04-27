use serde::{Deserialize, Serialize};

use crate::s2s::{overlay_network::NodeId, WalFrame};

use super::{OwnerOrderedFrame, VersionVector};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Layer3WireMessage {
    StrictFrame {
        from: NodeId,
        frame: WalFrame<Vec<u8>>,
    },
    OwnerFrame {
        from: NodeId,
        frame: OwnerOrderedFrame<Vec<u8>>,
    },
    StrictCatchupRequest {
        from: NodeId,
        applied_index: u64,
    },
    StrictCatchupResponse {
        from: NodeId,
        frames: Vec<WalFrame<Vec<u8>>>,
    },
    OwnerCatchupRequest {
        from: NodeId,
        version_vector: VersionVector,
    },
    OwnerCatchupResponse {
        from: NodeId,
        frames: Vec<OwnerOrderedFrame<Vec<u8>>>,
    },
}

pub fn encode_layer3_wire_message(msg: &Layer3WireMessage) -> Result<Vec<u8>, String> {
    serde_json::to_vec(msg).map_err(|e| format!("encode layer3 wire message failed: {e}"))
}

pub fn decode_layer3_wire_message(payload: &[u8]) -> Result<Layer3WireMessage, String> {
    serde_json::from_slice(payload).map_err(|e| format!("decode layer3 wire message failed: {e}"))
}
