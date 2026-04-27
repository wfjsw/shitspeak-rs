use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};

use crate::s2s::overlay_network::{
    ApplicationLayer3Message, ClusterEnvelope, ClusterMessage, ConsensusLayer2Message,
    MessageMode, NodeId,
};
use crate::s2s::WalFrame;

use super::{
    decode_layer3_wire_message, encode_layer3_wire_message, Layer3WireMessage,
    OwnerOrderedFrame, OwnerOverlayCatchupTransport, StrictOverlayCatchupTransport,
    VersionVector,
};

#[derive(Debug, Clone)]
pub struct S2SLayer3Transport {
    local_node: NodeId,
    seq: Arc<AtomicU64>,
    strict_log: Arc<RwLock<Vec<WalFrame<Vec<u8>>>>>,
    owner_log: Arc<RwLock<Vec<OwnerOrderedFrame<Vec<u8>>>>>,
    outbound: Arc<RwLock<Vec<ClusterEnvelope>>>,
}

impl S2SLayer3Transport {
    pub fn new(local_node: NodeId) -> Self {
        Self {
            local_node,
            seq: Arc::new(AtomicU64::new(1)),
            strict_log: Arc::new(RwLock::new(Vec::new())),
            owner_log: Arc::new(RwLock::new(Vec::new())),
            outbound: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn ingest_overlay_envelope(&self, envelope: ClusterEnvelope) -> Result<bool, String> {
        let ClusterMessage::Layer2 {
            message:
                ConsensusLayer2Message::Layer3 {
                    message: ApplicationLayer3Message::Replication { payload },
                },
        } = envelope.body
        else {
            return Ok(false);
        };

        self.ingest_layer3_message(ApplicationLayer3Message::Replication { payload })
            .await
    }

    pub async fn ingest_layer3_message(&self, message: ApplicationLayer3Message) -> Result<bool, String> {
        let ApplicationLayer3Message::Replication { payload } = message;

        match decode_layer3_wire_message(&payload)? {
            Layer3WireMessage::StrictFrame { frame, .. } => {
                self.strict_log
                    .write()
                    .map_err(|_| "strict log lock poisoned".to_owned())?
                    .push(frame);
                Ok(true)
            }
            Layer3WireMessage::OwnerFrame { frame, .. } => {
                self.owner_log
                    .write()
                    .map_err(|_| "owner log lock poisoned".to_owned())?
                    .push(frame);
                Ok(true)
            }
            Layer3WireMessage::StrictCatchupResponse { frames, .. } => {
                self.strict_log
                    .write()
                    .map_err(|_| "strict log lock poisoned".to_owned())?
                    .extend(frames);
                Ok(true)
            }
            Layer3WireMessage::OwnerCatchupResponse { frames, .. } => {
                self.owner_log
                    .write()
                    .map_err(|_| "owner log lock poisoned".to_owned())?
                    .extend(frames);
                Ok(true)
            }
            Layer3WireMessage::StrictCatchupRequest { .. } | Layer3WireMessage::OwnerCatchupRequest { .. } => {
                Ok(true)
            }
        }
    }

    pub async fn drain_outbound_envelopes(&self) -> Vec<ClusterEnvelope> {
        let mut out = self
            .outbound
            .write()
            .expect("outbound lock poisoned");
        std::mem::take(&mut *out)
    }

    pub async fn strict_log_len(&self) -> usize {
        self.strict_log.read().expect("strict log lock poisoned").len()
    }

    pub async fn owner_log_len(&self) -> usize {
        self.owner_log.read().expect("owner log lock poisoned").len()
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    fn build_wire_envelope(&self, wire: &Layer3WireMessage) -> Result<ClusterEnvelope, String> {
        let payload = encode_layer3_wire_message(wire)?;
        Ok(ClusterEnvelope {
            version: 1,
            feature_bitmap: 0,
            from: self.local_node,
            seq: self.next_seq(),
            mode: MessageMode::Broadcast,
            body: ClusterMessage::Layer2 {
                message: ConsensusLayer2Message::Layer3 {
                    message: ApplicationLayer3Message::Replication { payload },
                },
            },
        })
    }

    fn strict_since_sync(&self, applied_index: u64) -> Result<Vec<WalFrame<Vec<u8>>>, String> {
        let log = self
            .strict_log
            .read()
            .map_err(|_| "strict log lock poisoned".to_owned())?;
        Ok(log
            .iter()
            .filter(|f| f.index > applied_index)
            .cloned()
            .collect())
    }

    fn owner_since_sync(&self, version_vector: &VersionVector) -> Result<Vec<OwnerOrderedFrame<Vec<u8>>>, String> {
        let log = self
            .owner_log
            .read()
            .map_err(|_| "owner log lock poisoned".to_owned())?;
        Ok(log
            .iter()
            .filter(|f| f.origin_version > version_vector.get(&f.origin_node).copied().unwrap_or(0))
            .cloned()
            .collect())
    }
}

impl StrictOverlayCatchupTransport for S2SLayer3Transport {
    type Error = String;

    fn broadcast_strict_frame(&self, frame: &WalFrame<Vec<u8>>) -> Result<(), Self::Error> {
        self.strict_log
            .write()
            .map_err(|_| "strict log lock poisoned".to_owned())?
            .push(frame.clone());
        let wire = Layer3WireMessage::StrictFrame {
            from: self.local_node,
            frame: frame.clone(),
        };
        let envelope = self.build_wire_envelope(&wire)?;
        self.outbound
            .write()
            .map_err(|_| "outbound lock poisoned".to_owned())?
            .push(envelope);
        Ok(())
    }

    fn fetch_strict_frames_since(&self, applied_index: u64) -> Result<Vec<WalFrame<Vec<u8>>>, Self::Error> {
        self.strict_since_sync(applied_index)
    }
}

impl OwnerOverlayCatchupTransport for S2SLayer3Transport {
    type Error = String;

    fn broadcast_owner_frame(&self, frame: &OwnerOrderedFrame<Vec<u8>>) -> Result<(), Self::Error> {
        self.owner_log
            .write()
            .map_err(|_| "owner log lock poisoned".to_owned())?
            .push(frame.clone());
        let wire = Layer3WireMessage::OwnerFrame {
            from: self.local_node,
            frame: frame.clone(),
        };
        let envelope = self.build_wire_envelope(&wire)?;
        self.outbound
            .write()
            .map_err(|_| "outbound lock poisoned".to_owned())?
            .push(envelope);
        Ok(())
    }

    fn fetch_owner_frames_since(
        &self,
        version_vector: &VersionVector,
    ) -> Result<Vec<OwnerOrderedFrame<Vec<u8>>>, Self::Error> {
        self.owner_since_sync(version_vector)
    }
}
