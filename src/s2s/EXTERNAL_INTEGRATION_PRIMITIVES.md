# S2S External Integration Primitives

This document describes the stable primitive surfaces in `src/s2s` intended for integration by external components.

## Goals

- Keep consensus, overlay, and app wiring decoupled.
- Allow strict-order replication to plug into existing storage/domain structs.
- Expose simple primitive APIs with deterministic behavior.

## Primitive Modules

- `s2s::overlay_network`: membership, routing, transport selection, presence metadata, hardening, ownership routing.
- `s2s::base_consensus`: egalitarian Tempo-style timestamp ordering primitives, strict write mode, partition policy, storage traits, strict runtime.
- `s2s::layer3`: repository-facing replication runtimes that compose Layer 1 and Layer 2.
- `s2s::S2SManager`: app orchestration entrypoint that composes primitives.

## Strict Replication Integration Contract

Use `StrictReplicationStorage` to adapt your existing persisted state.

### Required capabilities

Your storage adapter must provide:

- WAL append/truncate via `WalStorage`.
- snapshot install/read via `SnapshotHandle`.
- committed apply plus snapshot import/export via `ReplicatedStateEngine`.
- applied-index query via `AppliedIndexProvider`.

### Adapter shape

Implement `StrictReplicationStorage` for any struct that already owns these components.

```rust
use shitspeak_rs::s2s::{
    AppliedIndexProvider, ReplicatedStateEngine, SnapshotHandle, StrictReplicationStorage,
    WalStorage,
};

struct ExistingStore<W, S, E> {
    wal: W,
    snapshot: S,
    engine: E,
}

impl<W, S, E> StrictReplicationStorage for ExistingStore<W, S, E>
where
    W: WalStorage<Error = String>,
    S: SnapshotHandle<Error = String>,
    E: ReplicatedStateEngine<Error = String> + AppliedIndexProvider,
{
    type Wal = W;
    type Snapshot = S;
    type Engine = E;

    fn wal_mut(&mut self) -> &mut Self::Wal { &mut self.wal }
    fn snapshot_ref(&self) -> &Self::Snapshot { &self.snapshot }
    fn snapshot_mut(&mut self) -> &mut Self::Snapshot { &mut self.snapshot }
    fn engine_ref(&self) -> &Self::Engine { &self.engine }
    fn engine_mut(&mut self) -> &mut Self::Engine { &mut self.engine }
}
```

### Runtime entrypoints

- `StrictReplicationRuntime::propose_with_storage`: egalitarian majority-gated local strict write.
- `StrictReplicationRuntime::install_snapshot_from_storage`: load current snapshot into engine.
- `StrictReplicationRuntime::replay_wal`: deterministic committed replay.
- `StrictReplicationRuntime::compact_with_storage`: snapshot+truncate compaction.

## Layer 3 Replication Runtime Contracts

### Strict ordered replication over overlay

- `StrictOrderedOverlayRuntime` wraps `StrictReplicationRuntime` and transport fanout.
- `StrictOverlayCatchupTransport::broadcast_strict_frame` is called with encoded strict WAL frames.
- Repository integrations keep domain serialization and persistence ownership, while Layer 3 handles frame broadcast and remote frame ingestion.
- `catch_up_with_overlay` fetches and applies missing strict frames when local strict state is stale.
- Built-in transport: `S2SLayer3Transport` implements strict transport hooks.

### Owner-ordered replication for client-style data

- `OwnerOrderedRuntime` implements per-writer ordering with no global total order requirement.
- `OwnerReplicaRole::Writable` allows local append for that replica; `OwnerReplicaRole::ReadOnly` rejects local writes.
- `VersionVector` tracks `{ node_id -> latest_origin_version }` and represents the combined cross-node view.
- `OwnerOrderedFrame` is ordered per origin node (`origin_node`, `origin_version`) and must be contiguous per origin at apply time.
- `OwnerOrderedStateEngine` is the repository-side hook to apply per-origin committed payloads.
- `catch_up_with_overlay` fetches and applies missing owner-ordered frames when local vector view is stale.
- `OwnerOverlayCatchupTransport` is the owner-model transport hook used for broadcast and catch-up fetch.
- Built-in transport: `S2SLayer3Transport` implements owner transport hooks.

### Shared call shape for model swapping

- Both models implement `Layer3ReplicationRuntime<S, T>` with the same method names:
    - `propose_local(...)`
    - `ingest_remote(...)`
    - `catch_up_with_overlay(...)`
- This keeps repository integration code nearly identical when switching between strict and owner-ordered models.

## Overlay Integration Contract

- Use `MembershipTable` for liveness state and transitions.
- Use `SwimState` for direct/indirect probing.
- Use `NodePresenceMap` for metadata anti-entropy only (not liveness authority).
- Use `OverlayNetwork` for route/transport selection and ingress hardening.
- Use `OverlaySocketRuntime` for concrete on-wire envelope transport (UDP listener for quic/udp/kcp classes, TCP listener for tls-tcp class).
- `ClusterEnvelope`/`ClusterMessage` are now actively exchanged over sockets in `S2SManager::spawn_runtime_task`:
    - outbound heartbeat broadcast (`ClusterMessage::Heartbeat`),
    - outbound Layer 3 replication frames (`ClusterMessage::Layer3Replication`),
    - inbound processing for heartbeat/membership/presence/peer-list/data-forward/layer3 variants.

### Concrete Layer 1 wire runtime

- `OverlaySocketRuntime::bind(local_node, quic_listen, tcp_listen, bootstrap_nodes)` binds configured listeners and starts async reader tasks.
- `send_envelope(...)` serializes `ClusterEnvelope` as JSON and sends to known peers using selected primary/fallback transport kinds.
- `drain_incoming(...)` returns decoded inbound envelopes with source address and frame length for hardening checks.
- `register_peer_addr(...)` allows peer discovery from inbound traffic and `PeerList` messages.

## Behavioral Guarantees

- Strict writes are rejected unless the local node is in a writable majority partition.
- Partition policy maps majority to writable and minority/unknown to read-only.
- WAL replay is monotonic by frame index when input is sorted.
- Snapshot compaction truncates WAL suffix after included index.
- Route selection filters stale telemetry and supports anti-flap stable switching.
- Owner-ordered runtime rejects out-of-order gaps per origin node and accepts independent progress across different origin nodes.
