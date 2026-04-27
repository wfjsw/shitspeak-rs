# Base Consensus Integration Guide

## Public Primitives

- `TempoCore`, `TempoSlot`.
- `PartitionPolicy`, `PartitionRole`.
- `StrictState`, `StrictStateMode`, `ReplicatedCommand`.
- Storage traits: `WalStorage`, `SnapshotHandle`, `ReplicatedStateEngine`, `AppliedIndexProvider`, `StrictReplicationStorage`.
- Orchestration runtime: `StrictReplicationRuntime`.

## Integration Pattern

1. Wrap your existing persistence components into one adapter implementing `StrictReplicationStorage`.
2. Initialize runtime with local node id.
3. Update partition role from membership view.
4. Recover from snapshot and WAL on startup.
5. Use `reserve_commit` or `propose_with_storage` from any node in the writable majority.
6. Periodically call `compact_with_storage` for snapshot compaction.

## Error Semantics

- Minority/readonly propose: rejected.
- storage I/O or serialization failures: surfaced as `Err(String)`.

## Data Model Notes

- `ReplicatedCommand` is intentionally generic (`domain`, `verb`, `payload`).
- `WalFrame<T>` carries ordered index, term, and payload (`term` is the reserved Tempo timestamp in milliseconds).
