use std::collections::BTreeMap;

use shitspeak_rs::s2s::{
    decode_replicated_command, route_owned_operation, choose_transport_pair, InMemoryStateEngine,
    MembershipTable, NodePresenceDelta, NodePresenceMap, OwnershipRoute,
    PartitionRole, ProbePlan, ReplicatedCommand, ReplicatedStateEngine, RouteCandidate,
    RouteClass, RoutePath, RouteSelectionPolicy, SnapshotHandle, StrictReplicationRuntime,
    StrictReplicationStorage, SwimState, TransportCapabilities, TransportKind, TransportRuntimePolicy,
    WalStorage, select_best_path, select_stable_path,
};

#[derive(Default)]
struct IntegrationWal {
    rows: Vec<(u64, u64, Vec<u8>)>,
}

impl WalStorage for IntegrationWal {
    type Error = String;

    fn append_frame(&mut self, index: u64, term: u64, payload: &[u8]) -> Result<(), Self::Error> {
        self.rows.push((index, term, payload.to_vec()));
        Ok(())
    }

    fn truncate_suffix(&mut self, from_index: u64) -> Result<(), Self::Error> {
        self.rows.retain(|(index, _, _)| *index < from_index);
        Ok(())
    }
}

#[derive(Default)]
struct IntegrationSnapshot {
    data: Option<Vec<u8>>,
}

impl SnapshotHandle for IntegrationSnapshot {
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
struct IntegrationEngine {
    applied: BTreeMap<u64, Vec<u8>>,
}

impl ReplicatedStateEngine for IntegrationEngine {
    type Error = String;

    fn apply_committed(&mut self, index: u64, payload: &[u8]) -> Result<(), Self::Error> {
        self.applied.insert(index, payload.to_vec());
        Ok(())
    }

    fn export_snapshot(&self) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(&self.applied).map_err(|e| format!("snapshot encode failed: {e}"))
    }

    fn import_snapshot(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.applied = serde_json::from_slice(data).map_err(|e| format!("snapshot decode failed: {e}"))?;
        Ok(())
    }
}

impl shitspeak_rs::s2s::AppliedIndexProvider for IntegrationEngine {
    fn highest_applied_index(&self) -> Option<u64> {
        self.applied.keys().next_back().copied()
    }
}

#[derive(Default)]
struct IntegrationStorage {
    wal: IntegrationWal,
    snapshot: IntegrationSnapshot,
    engine: IntegrationEngine,
}

impl StrictReplicationStorage for IntegrationStorage {
    type Wal = IntegrationWal;
    type Snapshot = IntegrationSnapshot;
    type Engine = IntegrationEngine;

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

fn cmd(domain: &str, verb: &str, payload: &[u8]) -> ReplicatedCommand {
    ReplicatedCommand {
        domain: domain.to_owned(),
        verb: verb.to_owned(),
        payload: payload.to_vec(),
    }
}

#[test]
fn strict_runtime_custom_storage_adapter_roundtrip() {
    let mut runtime = StrictReplicationRuntime::new(1);
    let role = runtime.update_partition_role(3, 3);
    assert_eq!(role, PartitionRole::Majority);

    let mut storage = IntegrationStorage::default();
    let frame = runtime
        .propose_with_storage(cmd("channels", "upsert", &[1, 2]), &mut storage)
        .expect("propose should succeed");
    assert!(frame.index > 0);
    assert_eq!(storage.wal.rows.len(), 1);

    let raw_payload = storage.wal.rows[0].2.clone();
    let decoded = decode_replicated_command(&raw_payload).expect("wal payload should decode");
    assert_eq!(decoded.domain, "channels");

    runtime
        .compact_with_storage(&mut storage)
        .expect("compaction should succeed");
    assert!(storage.snapshot.data.is_some());
    assert!(storage.wal.rows.is_empty());

    let mut recovering = StrictReplicationRuntime::new(1);
    let restored = recovering
        .install_snapshot_from_storage(&mut storage)
        .expect("snapshot restore should succeed");
    assert_eq!(restored, Some(frame.index));
}

#[test]
fn overlay_membership_presence_and_swim_flow() {
    let mut membership = MembershipTable::new(100, 200);
    membership.upsert_alive(1, "boot-1".to_owned(), 0);
    membership.upsert_alive(2, "boot-2".to_owned(), 0);
    let alive = membership.alive_nodes();
    assert_eq!(alive.len(), 2);

    let mut swim = SwimState::new(1);
    let ProbePlan {
        direct_target,
        indirect_helpers,
    } = swim.next_probe_plan(&alive, 2);
    assert_eq!(direct_target, Some(2));
    assert!(!indirect_helpers.contains(&1));

    let mut presence = NodePresenceMap::default();
    presence.apply_delta(NodePresenceDelta::MetadataUpsert {
        node_id: 2,
        key: "region".to_owned(),
        value: "us-east".to_owned(),
        updated_ms: 10,
    });

    let digest = presence.digest();
    assert_eq!(digest.len(), 1);

    let stale = presence.stale_nodes_against(&[shitspeak_rs::s2s::PresenceDigestEntry {
        node_id: 2,
        metadata_hash: 0,
        metadata_updated_ms: 11,
    }]);
    assert_eq!(stale, vec![2]);
}

#[test]
fn routing_transport_and_ownership_primitives_work_together() {
    let now = 10_000;
    let candidates = vec![
        RouteCandidate {
            path: RoutePath::Direct { target: 3 },
            sample: shitspeak_rs::s2s::LinkQualitySample {
                latency_ms: 60.0,
                jitter_ms: 6.0,
                loss_ratio: 0.05,
                bandwidth_kbps: 1000.0,
                updated_at_ms: now,
            },
        },
        RouteCandidate {
            path: RoutePath::Direct { target: 2 },
            sample: shitspeak_rs::s2s::LinkQualitySample {
                latency_ms: 20.0,
                jitter_ms: 3.0,
                loss_ratio: 0.01,
                bandwidth_kbps: 1000.0,
                updated_at_ms: now,
            },
        },
    ];

    let best = select_best_path(&candidates, now, 100).expect("best path should exist");
    let stable = select_stable_path(None, Some(best.clone()), now, RouteSelectionPolicy::default())
        .expect("stable state should initialize");
    assert_eq!(stable.selected.path, best.path);

    let caps = TransportCapabilities {
        supported: vec![TransportKind::Quic, TransportKind::TlsTcp],
    };
    let pair = choose_transport_pair(&caps, RouteClass::Reliable, &TransportRuntimePolicy::default())
        .expect("transport pair should be selected");
    assert_eq!(pair.primary, TransportKind::Quic);

    let op = shitspeak_rs::s2s::OwnedOperation {
        operation_id: 7,
        owner_node: 2,
        domain: "acl".to_owned(),
        payload: vec![9],
    };
    assert!(matches!(
        route_owned_operation(1, &op),
        OwnershipRoute::ForwardToOwner(2)
    ));
}

#[test]
fn in_memory_engine_is_available_for_external_embed_use() {
    let mut engine = InMemoryStateEngine::default();
    engine
        .apply_committed(1, &[1, 2, 3])
        .expect("in-memory engine apply should work");
    assert_eq!(engine.applied_len(), 1);
}
