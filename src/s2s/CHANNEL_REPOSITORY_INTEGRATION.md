# Plugging Strict Consensus Into ChannelRepository

This integration path is designed to avoid a second WAL or snapshot format.

The repository keeps its own durability model:

- `ChannelOperation` remains the WAL entry shape.
- `Snapshot` remains the snapshot shape.
- `ChannelRepository` continues to serialize and deserialize its own payloads.

The strict consensus layer is only responsible for assigning ordered commit positions.

## Integration Flow

1. Build a `ChannelOperation` from your channel mutation intent.
2. Ask `StrictReplicationRuntime` for a `StrictCommitReservation`.
3. Copy `reservation.index` into `ChannelOperation.version`.
4. Commit through `ChannelRepository::apply_committed_operation`, which uses the repository's own WAL and snapshot pipeline.
5. Tell the runtime the reserved commit was persisted with `commit_reserved`.

## Local Submission Path

```rust
use std::sync::Arc;

use shitspeak_rs::channel_repository::{ChannelOperation, ChannelRepository};
use shitspeak_rs::s2s::{commit_local_channel_operation, StrictReplicationRuntime};

async fn commit_locally(
    runtime: &mut StrictReplicationRuntime,
    repo: &Arc<ChannelRepository>,
    op: ChannelOperation,
) -> Result<(), String> {
    commit_local_channel_operation(runtime, repo, op).await?;
    Ok(())
}
```

## Remote Apply Path

```rust
use std::sync::Arc;

use shitspeak_rs::channel_repository::ChannelRepository;
use shitspeak_rs::s2s::apply_replicated_channel_payload;

async fn apply_remote(
    repo: &Arc<ChannelRepository>,
    payload: &[u8],
) -> Result<(), String> {
    apply_replicated_channel_payload(repo, payload).await?;
    Ok(())
}
```

## Payload Ownership

- `channel_operation_to_payload` serializes a `ChannelOperation` to bytes.
- `channel_operation_from_payload` decodes it back.
- The strict layer treats those bytes as opaque ordering payload.

## Why this is lower disruption

- No parallel strict WAL for channel state.
- No alternate snapshot format for channel state.
- Existing repository commit/snapshot behavior remains authoritative.
- Strict consensus only allocates ordering metadata.
