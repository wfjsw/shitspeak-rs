use bytes::Bytes;

#[derive(Debug, Clone)]
pub struct WireFrame {
    pub stream_id: u8,
    pub sequence: u64,
    pub payload: Bytes,
}

pub trait FrameCodec: Send + Sync {
    fn encode(&self, frame: &WireFrame) -> Result<Vec<u8>, String>;
    fn decode(&self, bytes: &[u8]) -> Result<WireFrame, String>;
}

#[derive(Debug, Default, Clone)]
pub struct JsonFrameCodec;

impl FrameCodec for JsonFrameCodec {
    fn encode(&self, frame: &WireFrame) -> Result<Vec<u8>, String> {
        #[derive(serde::Serialize)]
        struct SerializableFrame<'a> {
            stream_id: u8,
            sequence: u64,
            payload: &'a [u8],
        }

        serde_json::to_vec(&SerializableFrame {
            stream_id: frame.stream_id,
            sequence: frame.sequence,
            payload: frame.payload.as_ref(),
        })
        .map_err(|e| format!("encode wire frame failed: {e}"))
    }

    fn decode(&self, bytes: &[u8]) -> Result<WireFrame, String> {
        #[derive(serde::Deserialize)]
        struct SerializableFrame {
            stream_id: u8,
            sequence: u64,
            payload: Vec<u8>,
        }

        let decoded: SerializableFrame =
            serde_json::from_slice(bytes).map_err(|e| format!("decode wire frame failed: {e}"))?;

        Ok(WireFrame {
            stream_id: decoded.stream_id,
            sequence: decoded.sequence,
            payload: Bytes::from(decoded.payload),
        })
    }
}
