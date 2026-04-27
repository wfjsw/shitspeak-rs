use crate::s2s::{
    decode_replicated_command, encode_replicated_command, ReplicatedCommand,
    ReplicatedStateEngine, StrictReplicationRuntime, StrictReplicationStorage, WalFrame,
    WalStorage,
};

use super::{Layer3ReplicationRuntime, StrictOverlayCatchupTransport};

#[derive(Debug, Clone)]
pub struct StrictOrderedOverlayRuntime {
    pub strict: StrictReplicationRuntime,
}

impl StrictOrderedOverlayRuntime {
    pub fn new(local_node: u16) -> Self {
        Self {
            strict: StrictReplicationRuntime::new(local_node),
        }
    }

    pub fn applied_index(&self) -> u64 {
        self.strict.strict_state.applied_index
    }

    pub fn propose_local<S, T>(
        &mut self,
        command: ReplicatedCommand,
        storage: &mut S,
        transport: &T,
    ) -> Result<WalFrame<ReplicatedCommand>, String>
    where
        S: StrictReplicationStorage,
        T: StrictOverlayCatchupTransport<Error = String>,
    {
        let frame = self.strict.propose_with_storage(command, storage)?;
        let payload = encode_replicated_command(&frame.payload)?;
        let wire_frame = WalFrame {
            index: frame.index,
            term: frame.term,
            payload,
        };
        transport.broadcast_strict_frame(&wire_frame)?;
        Ok(frame)
    }

    pub fn ingest_remote<S>(
        &mut self,
        frame: WalFrame<ReplicatedCommand>,
        storage: &mut S,
    ) -> Result<bool, String>
    where
        S: StrictReplicationStorage,
    {
        let wire_frame = WalFrame {
            index: frame.index,
            term: frame.term,
            payload: encode_replicated_command(&frame.payload)?,
        };
        ingest_strict_wire_frame(&mut self.strict, wire_frame, storage)
    }

    pub fn catch_up_with_overlay<S, T>(
        &mut self,
        storage: &mut S,
        transport: &T,
    ) -> Result<usize, String>
    where
        S: StrictReplicationStorage,
        T: StrictOverlayCatchupTransport<Error = String>,
    {
        let mut frames = transport.fetch_strict_frames_since(self.strict.strict_state.applied_index)?;
        frames.sort_by_key(|f| f.index);

        let mut applied = 0_usize;
        for frame in frames {
            if ingest_strict_wire_frame(&mut self.strict, frame, storage)? {
                applied = applied.saturating_add(1);
            }
        }
        Ok(applied)
    }
}

impl<S, T> Layer3ReplicationRuntime<S, T> for StrictOrderedOverlayRuntime
where
    S: StrictReplicationStorage,
    T: StrictOverlayCatchupTransport<Error = String>,
{
    type Command = ReplicatedCommand;
    type Frame = WalFrame<ReplicatedCommand>;

    fn propose_local(
        &mut self,
        command: Self::Command,
        storage: &mut S,
        transport: &T,
    ) -> Result<Self::Frame, String> {
        StrictOrderedOverlayRuntime::propose_local(self, command, storage, transport)
    }

    fn ingest_remote(
        &mut self,
        frame: Self::Frame,
        storage: &mut S,
    ) -> Result<bool, String> {
        StrictOrderedOverlayRuntime::ingest_remote(self, frame, storage)
    }

    fn catch_up_with_overlay(&mut self, storage: &mut S, transport: &T) -> Result<usize, String> {
        StrictOrderedOverlayRuntime::catch_up_with_overlay(self, storage, transport)
    }
}

pub(crate) fn ingest_strict_wire_frame<S>(
    strict: &mut StrictReplicationRuntime,
    frame: WalFrame<Vec<u8>>,
    storage: &mut S,
) -> Result<bool, String>
where
    S: StrictReplicationStorage,
{
    if frame.index <= strict.tempo.committed_index {
        return Ok(false);
    }

    let _ = decode_replicated_command(&frame.payload)?;
    {
        let wal = storage.wal_mut();
        wal.append_frame(frame.index, frame.term, &frame.payload)?;
    }
    {
        let engine = storage.engine_mut();
        engine.apply_committed(frame.index, &frame.payload)?;
    }

    strict.tempo.observe_remote_index(frame.index);
    strict.strict_state.applied_index = strict.strict_state.applied_index.max(frame.index);
    Ok(true)
}
