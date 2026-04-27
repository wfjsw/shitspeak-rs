use std::time::{SystemTime, UNIX_EPOCH};

use crate::s2s::overlay_network::NodeId;

use super::{
    Layer3ReplicationRuntime, OwnerOrderedFrame, OwnerOrderedStateEngine,
    OwnerOverlayCatchupTransport, OwnerReplicaRole, VersionVector,
};

#[derive(Debug, Clone)]
pub struct OwnerOrderedRuntime {
    pub local_node: NodeId,
    pub local_role: OwnerReplicaRole,
    pub version_vector: VersionVector,
}

impl OwnerOrderedRuntime {
    pub fn new(local_node: NodeId, local_role: OwnerReplicaRole) -> Self {
        let mut version_vector = VersionVector::new();
        version_vector.insert(local_node, 0);

        Self {
            local_node,
            local_role,
            version_vector,
        }
    }

    pub fn version_for(&self, node: NodeId) -> u64 {
        self.version_vector.get(&node).copied().unwrap_or(0)
    }

    pub fn version_vector(&self) -> &VersionVector {
        &self.version_vector
    }

    fn reserve_local_write(&mut self) -> Result<(NodeId, u64), String> {
        if self.local_role != OwnerReplicaRole::Writable {
            return Err("owner-ordered write rejected: local replica is read-only".to_owned());
        }

        let next = self.version_for(self.local_node).saturating_add(1);
        self.version_vector.insert(self.local_node, next);
        Ok((self.local_node, next))
    }

    pub fn propose_local<E, T>(
        &mut self,
        payload: Vec<u8>,
        engine: &mut E,
        transport: &T,
    ) -> Result<OwnerOrderedFrame<Vec<u8>>, String>
    where
        E: OwnerOrderedStateEngine<Error = String>,
        T: OwnerOverlayCatchupTransport<Error = String>,
    {
        let (origin_node, origin_version) = self.reserve_local_write()?;
        engine.apply_origin_committed(origin_node, origin_version, &payload)?;

        let frame = OwnerOrderedFrame {
            origin_node,
            origin_version,
            timestamp_ms: unix_ms_now(),
            payload,
        };

        transport.broadcast_owner_frame(&frame)?;
        Ok(frame)
    }

    pub fn ingest_remote<E>(
        &mut self,
        frame: OwnerOrderedFrame<Vec<u8>>,
        engine: &mut E,
    ) -> Result<bool, String>
    where
        E: OwnerOrderedStateEngine<Error = String>,
    {
        let current = self.version_for(frame.origin_node);
        if frame.origin_version <= current {
            return Ok(false);
        }

        let expected = current.saturating_add(1);
        if frame.origin_version != expected {
            return Err(format!(
                "owner-ordered frame gap for node {}: expected {}, got {}",
                frame.origin_node, expected, frame.origin_version
            ));
        }

        engine.apply_origin_committed(frame.origin_node, frame.origin_version, &frame.payload)?;
        self.version_vector
            .insert(frame.origin_node, frame.origin_version);
        Ok(true)
    }

    pub fn catch_up_with_overlay<E, T>(
        &mut self,
        engine: &mut E,
        transport: &T,
    ) -> Result<usize, String>
    where
        E: OwnerOrderedStateEngine<Error = String>,
        T: OwnerOverlayCatchupTransport<Error = String>,
    {
        let mut frames = transport.fetch_owner_frames_since(&self.version_vector)?;
        frames.sort_by_key(|f| (f.origin_node, f.origin_version));

        let mut applied = 0_usize;
        for frame in frames {
            if OwnerOrderedRuntime::ingest_remote(self, frame, engine)? {
                applied = applied.saturating_add(1);
            }
        }
        Ok(applied)
    }
}

impl<E, T> Layer3ReplicationRuntime<E, T> for OwnerOrderedRuntime
where
    E: OwnerOrderedStateEngine<Error = String>,
    T: OwnerOverlayCatchupTransport<Error = String>,
{
    type Command = Vec<u8>;
    type Frame = OwnerOrderedFrame<Vec<u8>>;

    fn propose_local(
        &mut self,
        payload: Self::Command,
        engine: &mut E,
        transport: &T,
    ) -> Result<Self::Frame, String> {
        OwnerOrderedRuntime::propose_local(self, payload, engine, transport)
    }

    fn ingest_remote(
        &mut self,
        frame: Self::Frame,
        engine: &mut E,
    ) -> Result<bool, String> {
        OwnerOrderedRuntime::ingest_remote(self, frame, engine)
    }

    fn catch_up_with_overlay(&mut self, engine: &mut E, transport: &T) -> Result<usize, String> {
        OwnerOrderedRuntime::catch_up_with_overlay(self, engine, transport)
    }
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
