#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::s2s::{
        AppliedIndexProvider, Layer3ReplicationRuntime, OwnerOrderedFrame, OwnerOrderedRuntime,
        OwnerOrderedStateEngine, OwnerOverlayCatchupTransport, OwnerReplicaRole,
        ReplicatedCommand, ReplicatedStateEngine, SnapshotHandle, StrictOrderedOverlayRuntime,
        StrictOverlayCatchupTransport, StrictReplicationStorage, StrictStateMode,
        VersionVector, WalFrame, WalStorage, encode_layer3_wire_message,
        encode_replicated_command, Layer3WireMessage, MessageMode, S2SLayer3Transport,
    };

    #[derive(Default)]
    struct CapturingTransport {
        strict_frames: std::sync::Mutex<Vec<WalFrame<Vec<u8>>>>,
        owner_frames: std::sync::Mutex<Vec<OwnerOrderedFrame<Vec<u8>>>>,
        strict_catchup: std::sync::Mutex<Vec<WalFrame<Vec<u8>>>>,
        owner_catchup: std::sync::Mutex<Vec<OwnerOrderedFrame<Vec<u8>>>>,
    }

    impl StrictOverlayCatchupTransport for CapturingTransport {
        type Error = String;

        fn broadcast_strict_frame(&self, frame: &WalFrame<Vec<u8>>) -> Result<(), Self::Error> {
            self.strict_frames
                .lock()
                .map_err(|_| "strict transport lock poisoned".to_owned())?
                .push(frame.clone());
            Ok(())
        }

        fn fetch_strict_frames_since(&self, applied_index: u64) -> Result<Vec<WalFrame<Vec<u8>>>, Self::Error> {
            let frames = self
                .strict_catchup
                .lock()
                .map_err(|_| "strict catch-up lock poisoned".to_owned())?
                .iter()
                .filter(|f| f.index > applied_index)
                .cloned()
                .collect::<Vec<_>>();
            Ok(frames)
        }
    }

    impl OwnerOverlayCatchupTransport for CapturingTransport {
        type Error = String;

        fn broadcast_owner_frame(&self, frame: &OwnerOrderedFrame<Vec<u8>>) -> Result<(), Self::Error> {
            self.owner_frames
                .lock()
                .map_err(|_| "owner transport lock poisoned".to_owned())?
                .push(frame.clone());
            Ok(())
        }

        fn fetch_owner_frames_since(
            &self,
            version_vector: &VersionVector,
        ) -> Result<Vec<OwnerOrderedFrame<Vec<u8>>>, Self::Error> {
            let frames = self
                .owner_catchup
                .lock()
                .map_err(|_| "owner catch-up lock poisoned".to_owned())?
                .iter()
                .filter(|f| f.origin_version > version_vector.get(&f.origin_node).copied().unwrap_or(0))
                .cloned()
                .collect::<Vec<_>>();
            Ok(frames)
        }
    }

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
        data: Option<Vec<u8>>,
    }

    impl SnapshotHandle for TestSnapshot {
        type Error = String;

        fn install_snapshot(&mut self, _last_included_index: u64, data: &[u8]) -> Result<(), Self::Error> {
            self.data = Some(data.to_vec());
            Ok(())
        }

        fn read_snapshot(&self) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.data.clone())
        }
    }

    #[derive(Default)]
    struct TestStrictEngine {
        map: BTreeMap<u64, Vec<u8>>,
    }

    impl ReplicatedStateEngine for TestStrictEngine {
        type Error = String;

        fn apply_committed(&mut self, index: u64, payload: &[u8]) -> Result<(), Self::Error> {
            self.map.insert(index, payload.to_vec());
            Ok(())
        }

        fn export_snapshot(&self) -> Result<Vec<u8>, Self::Error> {
            serde_json::to_vec(&self.map).map_err(|e| format!("snapshot encode failed: {e}"))
        }

        fn import_snapshot(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            self.map = serde_json::from_slice(data).map_err(|e| format!("snapshot decode failed: {e}"))?;
            Ok(())
        }
    }

    impl AppliedIndexProvider for TestStrictEngine {
        fn highest_applied_index(&self) -> Option<u64> {
            self.map.keys().next_back().copied()
        }
    }

    #[derive(Default)]
    struct TestStrictStorage {
        wal: TestWal,
        snapshot: TestSnapshot,
        engine: TestStrictEngine,
    }

    impl StrictReplicationStorage for TestStrictStorage {
        type Wal = TestWal;
        type Snapshot = TestSnapshot;
        type Engine = TestStrictEngine;

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

    #[derive(Default)]
    struct TestOwnerEngine {
        applied: BTreeMap<(u16, u64), Vec<u8>>,
    }

    impl OwnerOrderedStateEngine for TestOwnerEngine {
        type Error = String;

        fn apply_origin_committed(
            &mut self,
            origin_node: u16,
            origin_version: u64,
            payload: &[u8],
        ) -> Result<(), Self::Error> {
            self.applied
                .insert((origin_node, origin_version), payload.to_vec());
            Ok(())
        }
    }

    fn command() -> ReplicatedCommand {
        ReplicatedCommand {
            domain: "client".to_owned(),
            verb: "upsert".to_owned(),
            payload: vec![1, 2, 3],
        }
    }

    #[test]
    fn strict_runtime_propose_and_catch_up_share_same_shape() {
        let mut runtime = StrictOrderedOverlayRuntime::new(1);
        runtime.strict.update_partition_role(3, 3);
        runtime.strict.strict_state.set_mode(StrictStateMode::MajorityWritable);

        let mut storage = TestStrictStorage::default();
        let transport = CapturingTransport::default();

        let frame = runtime
            .propose_local(command(), &mut storage, &transport)
            .expect("strict propose should succeed");

        assert!(frame.index > 0);

        let payload = encode_replicated_command(&command()).expect("encode should succeed");
        transport
            .strict_catchup
            .lock()
            .expect("strict catch-up lock should not poison")
            .push(WalFrame {
                index: frame.index + 1,
                term: frame.term,
                payload,
            });

        let applied = runtime
            .catch_up_with_overlay(&mut storage, &transport)
            .expect("strict catch-up should succeed");
        assert_eq!(applied, 1);
    }

    #[test]
    fn owner_runtime_propose_and_catch_up_share_same_shape() {
        let mut runtime = OwnerOrderedRuntime::new(7, OwnerReplicaRole::Writable);
        let mut engine = TestOwnerEngine::default();
        let transport = CapturingTransport::default();

        let frame = <OwnerOrderedRuntime as Layer3ReplicationRuntime<
            TestOwnerEngine,
            CapturingTransport,
        >>::propose_local(&mut runtime, vec![9, 9], &mut engine, &transport)
        .expect("owner propose should succeed");
        assert_eq!(frame.origin_version, 1);

        transport
            .owner_catchup
            .lock()
            .expect("owner catch-up lock should not poison")
            .push(OwnerOrderedFrame {
                origin_node: 3,
                origin_version: 1,
                timestamp_ms: 10,
                payload: vec![8],
            });

        let applied = <OwnerOrderedRuntime as Layer3ReplicationRuntime<
            TestOwnerEngine,
            CapturingTransport,
        >>::catch_up_with_overlay(&mut runtime, &mut engine, &transport)
        .expect("owner catch-up should succeed");
        assert_eq!(applied, 1);
        assert_eq!(runtime.version_for(3), 1);
    }

    #[test]
    fn owner_runtime_enforces_per_origin_order() {
        let mut runtime = OwnerOrderedRuntime::new(5, OwnerReplicaRole::ReadOnly);
        let mut engine = TestOwnerEngine::default();

        let err = runtime
            .ingest_remote(
                OwnerOrderedFrame {
                    origin_node: 2,
                    origin_version: 2,
                    timestamp_ms: 1,
                    payload: vec![1],
                },
                &mut engine,
            )
            .expect_err("gap should fail");
        assert!(err.contains("expected 1"));
    }

    #[tokio::test]
    async fn built_in_transport_stores_and_fetches_strict_frames() {
        let transport = S2SLayer3Transport::new(11);
        let frame = WalFrame {
            index: 7,
            term: 3,
            payload: vec![1, 2, 3],
        };

        transport
            .broadcast_strict_frame(&frame)
            .expect("broadcast strict frame should succeed");

        let fetched = transport
            .fetch_strict_frames_since(0)
            .expect("fetch strict frames should succeed");
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].index, 7);

        let outbound = transport.drain_outbound_envelopes().await;
        assert_eq!(outbound.len(), 1);
        assert!(matches!(outbound[0].mode, MessageMode::Broadcast));
    }

    #[tokio::test]
    async fn built_in_transport_ingests_overlay_layer3_message() {
        let transport = S2SLayer3Transport::new(9);
        let wire = Layer3WireMessage::OwnerFrame {
            from: 2,
            frame: OwnerOrderedFrame {
                origin_node: 2,
                origin_version: 1,
                timestamp_ms: 10,
                payload: vec![8],
            },
        };
        let payload = encode_layer3_wire_message(&wire).expect("wire encode should succeed");
        let envelope = crate::s2s::ClusterEnvelope {
            version: 1,
            feature_bitmap: 0,
            from: 2,
            seq: 99,
            mode: MessageMode::Unicast,
            body: crate::s2s::ClusterMessage::Layer2 {
                message: crate::s2s::ConsensusLayer2Message::Layer3 {
                    message: crate::s2s::ApplicationLayer3Message::Replication { payload },
                },
            },
        };

        let accepted = transport
            .ingest_overlay_envelope(envelope)
            .await
            .expect("ingest should succeed");
        assert!(accepted);
        assert_eq!(transport.owner_log_len().await, 1);
    }
}
