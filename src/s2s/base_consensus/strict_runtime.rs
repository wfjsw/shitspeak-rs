use super::{
    decode_replicated_command, encode_replicated_command, AppliedIndexProvider,
    InMemoryStateEngine, PartitionPolicy, PartitionRole, TempoCore,
    ReplicatedCommand, ReplicatedStateEngine, SnapshotHandle, StrictReplicationStorage,
    StrictState, StrictStateMode, WalFrame, WalStorage,
};
use super::super::overlay_network::MemberState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictCommitReservation {
    pub index: u64,
    pub timestamp_ms: u64,
    pub replica_id: u16,
}

#[derive(Debug, Clone)]
pub struct StrictReplicationRuntime {
    pub tempo: TempoCore,
    pub strict_state: StrictState,
    pub partition_policy: PartitionPolicy,
}

impl StrictReplicationRuntime {
    pub fn new(local_node: u16) -> Self {
        Self {
            tempo: TempoCore::new(local_node),
            strict_state: StrictState::default(),
            partition_policy: PartitionPolicy::default(),
        }
    }

    pub fn update_partition_role(&mut self, alive_nodes: usize, expected_cluster_size: usize) -> PartitionRole {
        let quorum = expected_cluster_size.max(1) / 2 + 1;
        let role = if alive_nodes >= quorum {
            PartitionRole::Majority
        } else {
            PartitionRole::Minority
        };
        self.partition_policy.set_role(role);
        self.strict_state
            .set_mode(self.partition_policy.strict_state_mode());
        role
    }

    pub fn reserve_commit(&mut self) -> Result<StrictCommitReservation, String> {
        if self.strict_state.mode != StrictStateMode::MajorityWritable {
            return Err("strict command rejected: minority partition is read-only".to_owned());
        }

        let slot = self.tempo.reserve_slot();
        Ok(StrictCommitReservation {
            index: TempoCore::order_index(slot.timestamp_ms, slot.replica_id),
            timestamp_ms: slot.timestamp_ms,
            replica_id: slot.replica_id,
        })
    }

    pub fn commit_reserved(&mut self, reservation: StrictCommitReservation) -> Result<(), String> {
        if reservation.index <= self.strict_state.applied_index {
            return Err(format!(
                "strict commit out of sequence: expected index above {}, got {}",
                self.strict_state.applied_index, reservation.index
            ));
        }

        self.tempo.observe_remote_index(reservation.index);
        self.strict_state.applied_index = reservation.index;
        Ok(())
    }

    pub fn payload_frame(
        &self,
        reservation: StrictCommitReservation,
        payload: Vec<u8>,
    ) -> WalFrame<Vec<u8>> {
        WalFrame {
            index: reservation.index,
            term: reservation.timestamp_ms,
            payload,
        }
    }

    pub fn propose_local<W, E>(
        &mut self,
        command: ReplicatedCommand,
        wal: &mut W,
        engine: &mut E,
    ) -> Result<WalFrame<ReplicatedCommand>, String>
    where
        W: WalStorage<Error = String>,
        E: ReplicatedStateEngine<Error = String>,
    {
        let reservation = self.reserve_commit()?;
        let frame = WalFrame {
            index: reservation.index,
            term: reservation.timestamp_ms,
            payload: command,
        };

        let payload = encode_replicated_command(&frame.payload)?;
        wal.append_frame(frame.index, frame.term, &payload)?;
        engine.apply_committed(frame.index, &payload)?;

        self.commit_reserved(reservation)?;

        Ok(frame)
    }

    pub fn propose_with_storage<S>(
        &mut self,
        command: ReplicatedCommand,
        storage: &mut S,
    ) -> Result<WalFrame<ReplicatedCommand>, String>
    where
        S: StrictReplicationStorage,
    {
        let reservation = self.reserve_commit()?;
        let frame = WalFrame {
            index: reservation.index,
            term: reservation.timestamp_ms,
            payload: command,
        };

        let payload = encode_replicated_command(&frame.payload)?;
        {
            let wal = storage.wal_mut();
            wal.append_frame(frame.index, frame.term, &payload)?;
        }
        {
            let engine = storage.engine_mut();
            engine.apply_committed(frame.index, &payload)?;
        }

        self.commit_reserved(reservation)?;

        Ok(frame)
    }

    pub fn replay_wal<E>(
        &mut self,
        frames: &[WalFrame<Vec<u8>>],
        engine: &mut E,
    ) -> Result<u64, String>
    where
        E: ReplicatedStateEngine<Error = String>,
    {
        let mut restored = 0_u64;
        for frame in frames {
            let _ = decode_replicated_command(&frame.payload)?;
            engine.apply_committed(frame.index, &frame.payload)?;
            if frame.index > self.strict_state.applied_index {
                self.strict_state.applied_index = frame.index;
            }
            self.tempo.observe_remote_index(frame.index);
            restored = restored.saturating_add(1);
        }
        Ok(restored)
    }

    pub fn install_snapshot<E>(
        &mut self,
        snapshot_bytes: Option<Vec<u8>>,
        engine: &mut E,
    ) -> Result<Option<u64>, String>
    where
        E: ReplicatedStateEngine<Error = String> + AppliedIndexProvider,
    {
        let Some(bytes) = snapshot_bytes else {
            return Ok(None);
        };

        engine.import_snapshot(&bytes)?;
        if let Some(index) = engine.highest_applied_index() {
            self.strict_state.applied_index = self.strict_state.applied_index.max(index);
            self.tempo.observe_remote_index(index);
            return Ok(Some(index));
        }

        Ok(None)
    }

    pub fn install_snapshot_from_storage<S>(
        &mut self,
        storage: &mut S,
    ) -> Result<Option<u64>, String>
    where
        S: StrictReplicationStorage,
    {
        let snapshot = storage.snapshot_ref().read_snapshot()?;
        self.install_snapshot(snapshot, storage.engine_mut())
    }

    pub fn compact_snapshot<E>(
        &mut self,
        snapshot: &mut impl SnapshotHandle<Error = String>,
        engine: &E,
        wal: &mut impl WalStorage<Error = String>,
    ) -> Result<Option<u64>, String>
    where
        E: ReplicatedStateEngine<Error = String> + AppliedIndexProvider,
    {
        let Some(last_index) = engine.highest_applied_index() else {
            return Ok(None);
        };

        let data = engine.export_snapshot()?;
        snapshot.install_snapshot(last_index, &data)?;
        wal.truncate_suffix(1)?;
        Ok(Some(last_index))
    }

    pub fn compact_with_storage<S>(&mut self, storage: &mut S) -> Result<Option<u64>, String>
    where
        S: StrictReplicationStorage,
    {
        let last_index = {
            let engine = storage.engine_ref();
            engine.highest_applied_index()
        };

        let Some(last_index) = last_index else {
            return Ok(None);
        };

        let data = {
            let engine = storage.engine_ref();
            engine.export_snapshot()?
        };

        storage
            .snapshot_mut()
            .install_snapshot(last_index, &data)?;
        storage
            .wal_mut()
            .truncate_suffix(1)?;
        Ok(Some(last_index))
    }

    pub fn ingest_membership_view(&mut self, states: &[MemberState], expected_cluster_size: usize) -> PartitionRole {
        let alive = states.iter().filter(|s| **s == MemberState::Alive).count();
        self.update_partition_role(alive, expected_cluster_size)
    }
}

impl Default for StrictReplicationRuntime {
    fn default() -> Self {
        Self::new(0)
    }
}

impl From<u16> for StrictReplicationRuntime {
    fn from(local_node: u16) -> Self {
        Self::new(local_node)
    }
}

impl StrictReplicationRuntime {
    pub fn make_in_memory_engine() -> InMemoryStateEngine {
        InMemoryStateEngine::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{
        AppliedIndexProvider, ReplicatedStateEngine, SnapshotHandle, StrictReplicationStorage,
        WalStorage,
    };

    #[derive(Default)]
    struct TestWal {
        frames: Vec<(u64, u64, Vec<u8>)>,
    }

    impl WalStorage for TestWal {
        type Error = String;

        fn append_frame(&mut self, index: u64, term: u64, payload: &[u8]) -> Result<(), Self::Error> {
            self.frames.push((index, term, payload.to_vec()));
            Ok(())
        }

        fn truncate_suffix(&mut self, from_index: u64) -> Result<(), Self::Error> {
            self.frames.retain(|(index, _, _)| *index < from_index);
            Ok(())
        }
    }

    #[derive(Default)]
    struct TestSnapshot {
        index: u64,
        data: Option<Vec<u8>>,
    }

    impl SnapshotHandle for TestSnapshot {
        type Error = String;

        fn install_snapshot(&mut self, last_included_index: u64, data: &[u8]) -> Result<(), Self::Error> {
            self.index = last_included_index;
            self.data = Some(data.to_vec());
            Ok(())
        }

        fn read_snapshot(&self) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.data.clone())
        }
    }

    #[derive(Default)]
    struct TestEngine {
        map: std::collections::BTreeMap<u64, Vec<u8>>,
    }

    impl ReplicatedStateEngine for TestEngine {
        type Error = String;

        fn apply_committed(&mut self, index: u64, payload: &[u8]) -> Result<(), Self::Error> {
            self.map.insert(index, payload.to_vec());
            Ok(())
        }

        fn export_snapshot(&self) -> Result<Vec<u8>, Self::Error> {
            serde_json::to_vec(&self.map).map_err(|e| format!("encode snapshot failed: {e}"))
        }

        fn import_snapshot(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            self.map = serde_json::from_slice(data).map_err(|e| format!("decode snapshot failed: {e}"))?;
            Ok(())
        }
    }

    impl AppliedIndexProvider for TestEngine {
        fn highest_applied_index(&self) -> Option<u64> {
            self.map.keys().next_back().copied()
        }
    }

    #[derive(Default)]
    struct TestStorage {
        wal: TestWal,
        snapshot: TestSnapshot,
        engine: TestEngine,
    }

    impl StrictReplicationStorage for TestStorage {
        type Wal = TestWal;
        type Snapshot = TestSnapshot;
        type Engine = TestEngine;

        fn wal_mut(&mut self) -> &mut Self::Wal {
            &mut self.wal
        }

        fn snapshot_ref(&self) -> &Self::Snapshot {
            &self.snapshot
        }

        fn snapshot_mut(&mut self) -> &mut Self::Snapshot {
            &mut self.snapshot
        }

        fn engine_ref(&self) -> &Self::Engine {
            &self.engine
        }

        fn engine_mut(&mut self) -> &mut Self::Engine {
            &mut self.engine
        }
    }

    fn command() -> ReplicatedCommand {
        ReplicatedCommand {
            domain: "ban".to_owned(),
            verb: "insert".to_owned(),
            payload: vec![1],
        }
    }

    #[test]
    fn propose_rejects_readonly_partition() {
        let mut runtime = StrictReplicationRuntime::new(1);
        let mut wal = TestWal::default();
        let mut engine = TestEngine::default();

        runtime.strict_state.set_mode(StrictStateMode::MinorityReadonly);
        let err = runtime
            .propose_local(command(), &mut wal, &mut engine)
            .expect_err("readonly must reject propose");
        assert!(err.contains("read-only"));
    }

    #[test]
    fn propose_with_storage_appends_and_applies() {
        let mut runtime = StrictReplicationRuntime::new(1);
        runtime.update_partition_role(3, 3);
        let mut storage = TestStorage::default();

        let frame = runtime
            .propose_with_storage(command(), &mut storage)
            .expect("propose should succeed");

        assert_eq!(frame.index, runtime.strict_state.applied_index);
        assert_eq!(runtime.tempo.committed_index, frame.index);
        assert_eq!(storage.wal.frames.len(), 1);
        assert_eq!(storage.engine.highest_applied_index(), Some(frame.index));
    }

    #[test]
    fn reserve_and_commit_allow_external_wal_and_snapshot_ownership() {
        let mut runtime = StrictReplicationRuntime::new(4);
        runtime.update_partition_role(3, 3);

        let reservation = runtime.reserve_commit().expect("reservation should succeed");
        assert!(reservation.timestamp_ms > 0);
        assert_eq!(reservation.replica_id, 4);

        runtime
            .commit_reserved(reservation)
            .expect("reserved commit should succeed");

        assert_eq!(runtime.strict_state.applied_index, runtime.tempo.committed_index);
        assert_eq!(runtime.tempo.last_applied, runtime.tempo.committed_index);
    }

    #[test]
    fn commit_reserved_rejects_out_of_sequence_index() {
        let mut runtime = StrictReplicationRuntime::new(4);
        runtime.update_partition_role(3, 3);

        let err = runtime
            .commit_reserved(StrictCommitReservation {
                index: 0,
                timestamp_ms: 0,
                replica_id: 4,
            })
            .expect_err("out-of-sequence commit should fail");

        assert!(err.contains("out of sequence"));
    }

    #[test]
    fn replay_and_snapshot_lifecycle_works() {
        let mut runtime = StrictReplicationRuntime::new(2);
        let mut engine = TestEngine::default();
        let cmd = command();
        let payload = encode_replicated_command(&cmd).expect("encode should work");
        let frames = vec![
            WalFrame { index: 1, term: 1, payload: payload.clone() },
            WalFrame { index: 2, term: 1, payload },
        ];

        let restored = runtime
            .replay_wal(&frames, &mut engine)
            .expect("replay should work");
        assert_eq!(restored, 2);
        assert_eq!(runtime.tempo.committed_index, 2);

        let snapshot_bytes = engine.export_snapshot().expect("export should work");
        let mut empty_engine = TestEngine::default();
        let installed = runtime
            .install_snapshot(Some(snapshot_bytes), &mut empty_engine)
            .expect("install snapshot should work");
        assert_eq!(installed, Some(2));
    }

    #[test]
    fn compaction_with_storage_truncates_suffix() {
        let mut runtime = StrictReplicationRuntime::new(9);
        runtime.update_partition_role(5, 5);
        let mut storage = TestStorage::default();

        for _ in 0..3 {
            runtime
                .propose_with_storage(command(), &mut storage)
                .expect("propose should succeed");
        }

        let compacted = runtime
            .compact_with_storage(&mut storage)
            .expect("compaction should succeed");
        let expected_index = runtime.strict_state.applied_index;
        assert_eq!(compacted, Some(expected_index));
        assert_eq!(storage.snapshot.index, expected_index);
        assert!(storage.wal.frames.is_empty());
    }
}
