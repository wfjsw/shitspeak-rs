use bytes::Bytes;
use serde::{Deserialize, Serialize};

use super::storage::ConsensusFrame;
use crate::s2s::core::NodeId;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatchupRequest {
    pub start_index: u64,
    pub end_index: Option<u64>,
    pub origin_hint: Option<NodeId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatchupResponse {
    pub frames: Vec<CatchupFrame>,
    pub max_available_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatchupFrame {
    pub index: u64,
    pub payload: Vec<u8>,
}

impl CatchupRequest {
    pub fn new(start_index: u64) -> Self {
        Self {
            start_index,
            end_index: None,
            origin_hint: None,
        }
    }

    pub fn with_end(mut self, end_index: u64) -> Self {
        self.end_index = Some(end_index);
        self
    }

    pub fn with_origin_hint(mut self, origin_hint: NodeId) -> Self {
        self.origin_hint = Some(origin_hint);
        self
    }

    pub fn encode(&self) -> Result<Bytes, String> {
        serde_json::to_vec(self)
            .map(Bytes::from)
            .map_err(|e| format!("encode catchup request failed: {e}"))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes)
            .map_err(|e| format!("decode catchup request failed: {e}"))
    }
}

impl CatchupResponse {
    pub fn new(max_available_index: u64) -> Self {
        Self {
            frames: Vec::new(),
            max_available_index,
        }
    }

    pub fn with_frames(mut self, frames: Vec<ConsensusFrame>) -> Self {
        self.frames = frames
            .into_iter()
            .map(|f| CatchupFrame {
                index: f.index,
                payload: f.payload.to_vec(),
            })
            .collect();
        self
    }

    pub fn encode(&self) -> Result<Bytes, String> {
        serde_json::to_vec(self)
            .map(Bytes::from)
            .map_err(|e| format!("encode catchup response failed: {e}"))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes)
            .map_err(|e| format!("decode catchup response failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip_works() {
        let req = CatchupRequest::new(7)
            .with_end(9)
            .with_origin_hint(4);
        let bytes = req.encode().expect("encode should succeed");
        let decoded = CatchupRequest::decode(&bytes).expect("decode should succeed");
        assert_eq!(decoded.start_index, 7);
        assert_eq!(decoded.end_index, Some(9));
        assert_eq!(decoded.origin_hint, Some(4));
    }

    #[test]
    fn response_roundtrip_works() {
        let response = CatchupResponse {
            frames: vec![CatchupFrame {
                index: 11,
                payload: b"abc".to_vec(),
            }],
            max_available_index: 17,
        };
        let bytes = response.encode().expect("encode should succeed");
        let decoded = CatchupResponse::decode(&bytes).expect("decode should succeed");
        assert_eq!(decoded.max_available_index, 17);
        assert_eq!(decoded.frames.len(), 1);
        assert_eq!(decoded.frames[0].index, 11);
    }
}
