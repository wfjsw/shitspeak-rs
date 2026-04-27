use super::OwnerOrderedFrame;

pub fn encode_owner_ordered_frame(frame: &OwnerOrderedFrame<Vec<u8>>) -> Result<Vec<u8>, String> {
    serde_json::to_vec(frame).map_err(|e| format!("encode owner-ordered frame failed: {e}"))
}

pub fn decode_owner_ordered_frame(payload: &[u8]) -> Result<OwnerOrderedFrame<Vec<u8>>, String> {
    serde_json::from_slice(payload).map_err(|e| format!("decode owner-ordered frame failed: {e}"))
}
