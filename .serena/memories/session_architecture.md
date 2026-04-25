# Session Architecture

## Session ID
- Composite 32-bit: `node_id` (12 bits) | `local_session_id` (20 bits)
- `ClientSessionIdentifier` in `src/client/client_session_identifier.rs`
- Constants: `MAX_NODE_ID` (4095), `MAX_LOCAL_SESSION_ID` (1,048,575)

## Client State Split
- **ClientGlobalState**: Shared state synchronized across the cluster. Protected by `RwLock`. Changes produce `ClientGlobalStateDelta` entries broadcast to other nodes.
- **ClientLocalState**: Per-connection state, NOT synchronized. Includes TCP socket handles, UDP state, crypto state.
- **GlobalStateWriteGuard**: RAII guard that acquires write lock, allows mutation via DerefMut, and on Drop increments the user version and pushes a state log entry.

## State Log
- `ClientStateLogEntry` wraps a `ClientStateOperation` (Add/Update/Remove) with version info
- `ClientGlobalStateDelta` computed via diff functions (`diff_plain`, `diff_clone`, `diff_option`, etc.)
- `ClientStateBroadcastPayload` sent to other nodes for replication

## ClientRepository
- `src/client_repository.rs` — ONLY for session allocation and lookup
- NOT for channels (use ChannelRepository)
- `ClientRegister` handles session ID allocation
- `LOG_MAX_ENTRIES` constant for bounded log
