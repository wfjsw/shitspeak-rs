# Message Dispatch Concurrency

Client TCP protobuf dispatch in `src/server.rs::Server::handle_incoming_connection` uses a `tokio::task::JoinSet` for generic concurrent message handling.

Policy:
- `Ping` and `UDPTunnel` stay on the connection loop fast path and are awaited inline. Because the read loop processes one incoming message at a time, these realtime messages preserve receive order relative to each other and are not queued behind long-running RPC handlers.
- All other protobuf messages are spawned into the `JoinSet`. Long-running handlers such as `RequestBlob` or cross-node `UserStats` do not block subsequent reads from the same TCP connection.
- Handler task completions are folded back into connection lifecycle handling through the `JoinSet`: auth rejections still close the connection, other handler errors still become `MessageHandlerFailed`, and panics/cancellations map to `MessageHandlerTaskFailed`.
- Client publish/subscription activation is checked when a handler completes successfully and after inline realtime handlers, so successful spawned `Authenticate` still drives post-auth setup.

S2S UserStats RPC runtime in `src/s2s/application/user_stats/runtime.rs` also spawns owner-side request handling so a slow responder does not block later RPC replies from being correlated.