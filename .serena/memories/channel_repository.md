# Channel Repository

## Types (src/channel_repository.rs)
- `ChannelOp` enum — Add, Update, Remove, SetAcls, SetGroups, Move
- `ChannelOperation` — op + channel_id + timestamp + version + payload
- `Snapshot` — serializable state snapshot
- `ChannelRepository` — main repository

## Channel (src/channels.rs)
- `Channel` struct — id, name, parent, description_hash, temporary, position, links, children, acls, groups
- `ChannelPatch` — partial update payload

## Persistence
- WAL: `channels.wal.jsonl` (append-only, fsync after every append, plain File)
- Snapshot: `channels.snapshot.json` (atomic rename)
- Startup: load snapshot → replay WAL entries with version > snapshot_version
- Compaction: save snapshot + truncate WAL

## Versioning
- Monotonic version counter (`AtomicU64`)
- In-memory operation log (`VecDeque<Arc<ChannelOperation>>`, bounded ring buffer)

## ACL Cache
- `RwLock<HashMap<(session_id: u64, channel_id: u32), BitFlags<ACLPermissions>>>`
- Invalidated on SetAcls or channel move

## Helper Functions
- `channel_to_proto_full` / `channel_to_proto_delta` — convert to protobuf
- `apply_op_to_map` — apply operation to channel map
- `apply_patch` — apply ChannelPatch to Channel
- `collect_subtree` — collect all descendant channel IDs
- `is_descendant` — check ancestry

## Replication (stubs)
- `subscribe()` → broadcast receiver of `Arc<ChannelOperation>`
- `apply_remote_operation(op)` — no re-log, no re-broadcast

## Known Issues (see channel_repo_issues memory)
- `new_in_memory()` was missing root channel creation
- WAL replay doesn't populate in-memory log
