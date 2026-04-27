# Layer 3 Replication Runtime

Layer 3 sits above:

- Layer 1: overlay membership/routing/transport primitives.
- Layer 2: strict consensus and persistence primitives.

It provides repository-facing replication APIs so repositories do not need to embed network logic.

Module path:

- `s2s::layer3`

## Shared Runtime Shape

Both strict-ordered and owner-ordered models implement the same runtime trait surface:

- `Layer3ReplicationRuntime<S>`
- `Layer3ReplicationRuntime<S, T>`
- `propose_local(command, storage, transport)`
- `ingest_remote(frame, storage)`
- `catch_up_with_overlay(storage, transport)`

Transport traits are model-specific:

- `StrictOverlayCatchupTransport` for strict-ordered runtime.
- `OwnerOverlayCatchupTransport` for owner-ordered runtime.

You only implement the trait for the model you plug in.

Default built-in implementation:

- `S2SLayer3Transport` (in `s2s::layer3`) implements both
	`StrictOverlayCatchupTransport` and `OwnerOverlayCatchupTransport`.
- Typical S2S usage should use `S2SLayer3Transport` directly instead of requiring an external transport implementation.

## Runtime 1: Strict Ordered Overlay Runtime

Type: `StrictOrderedOverlayRuntime`

Purpose:

- Keep strict ordering semantics from `StrictReplicationRuntime`.
- Persist/apply through repository storage adapters implementing Layer 2 storage traits.
- Broadcast strict wire frames through `StrictOverlayCatchupTransport`.

Flow:

1. Repository operation is encoded to `ReplicatedCommand` payload.
2. `propose_local` reserves and commits local strict order index.
3. Layer 3 broadcasts a strict wire frame to peers.
4. Peers call `ingest_remote` to append/apply and advance strict state.
5. Nodes that lag behind call `catch_up_with_overlay` to fetch and apply missing strict frames.

## Runtime 2: Owner-Ordered Runtime

Type: `OwnerOrderedRuntime`

Purpose:

- Support datasets where each writable replica has its own append order.
- Keep only per-origin ordering, not a global total order.
- Expose a version vector for full multi-replica view.

Data model:

- `OwnerOrderedFrame { origin_node, origin_version, timestamp_ms, payload }`
- `VersionVector = BTreeMap<NodeId, u64>`

Semantics:

- Local writes only if role is `OwnerReplicaRole::Writable`.
- Read-only nodes still ingest and apply remote owner-ordered frames.
- For each `origin_node`, versions must be contiguous (`n + 1`).
- Different origins may progress independently.
- Nodes with stale vectors call `catch_up_with_overlay` to fetch missing owner-ordered frames and apply them per origin.

This is suitable for client-repository style replication where each writer replica emits its own ordered log and nodes merge by vector version state.

For this runtime, the transport implementation uses `OwnerOverlayCatchupTransport` only.
