# Incomplete Parts Inventory (current checkout, 2026-05-17)

Project: `d:\shitspeak-rs`

Method: activated with Serena, read prior incomplete inventories, scanned explicit implementation markers, compared `Mumble.proto` messages with `src/messages/message.rs`, inspected likely gap symbols, ran verification.

Verification:
- `cargo check --all-targets`: passed. Only warning was Windows incremental compilation finalization access denied.
- `cargo test`: passed. Observed summaries: lib tests 281 passed / 4 ignored; bin tests 219 passed / 4 ignored; doc tests 0.

Confirmed remaining incomplete / intentionally unimplemented areas:

1. Two-phase S2S channel delete still lacks the per-socket shadow delivery layer from `channel_remove_s2s_plan.md`.
   - Implemented: `PendingDeleteState`, `ChannelOp::MarkPendingDelete`, nonce-bearing `DeleteChannel`, `CancelPendingDelete`, watchdog rollback, pending-delete redirect checks, and local client moves out of pending-delete subtrees.
   - Missing: `server.rs` still has only `client_log_rx` and `channel_log_rx`; no `session_channel_shadow` map. `channel_handler.rs::convert_channel_operation_to_messages` just calls `op.to_message()` and permission augmentation; it does not handle `MarkPendingDelete` synthetic `UserState` scans, stale `DeleteChannel` no-op guard, or straggler synthetic moves described in the plan.
   - Risk: observer sockets may still see stale/bouncy client channel state around remote moves and channel deletion ordering edge cases.

2. In-server Mumble `UserList` mutation is not implemented.
   - `src/client/handlers/user_list.rs::handle_user_list` authenticates, logs, and returns `Ok(())`.
   - Comment states this is intentional: user registration is delegated externally to the authenticator backend.
   - The `Authenticator` trait exposes `get_registered_users` and `unregister_user` hooks with default empty/no-op behavior, but the server does not mutate an internal user DB from `UserList` messages.

3. The standalone binary has no production authentication/user backend.
   - `src/main.rs` wires `NoopAuthenticator`, which accepts everyone as guest and grants `admin` group only to username `admin`.
   - This is a deliberate embedding/default fallback, not a compile blocker, but production auth/user-list behavior requires replacing the authenticator implementation.

4. S2S transport `FrameHello` and `FrameKeepalive` are reserved no-ops.
   - `src/s2s/transport/stream_io.rs::handle_inbound` and `src/s2s/transport/endpoint/udp.rs::handle_frame` ignore `FrameHello` / `FrameKeepalive`.
   - Current liveness/metrics use ping/pong and overlay hello, so this is currently a protocol-extension placeholder rather than a failing path.

Minor stale labels/comments:
- `src/channel_repository.rs` still has a `// S2S / replication stubs` section heading, even though core replication integration is implemented.
- `src/s2s/application/user_stats/runtime.rs` contains a test helper `expect("inbound not yet wired")`; production user-stats inbound registration and tests pass.

Older findings now obsolete in this checkout:
- `PluginDataTransmission` is implemented in the Rust message layer and cross-node routing; integration test `s2s_cross_node_plugin_data_transmission_routes_to_remote_recipient` passes.
- S2S strict quorum timeout behavior passes.
- S2S normal-channel voice and cross-node user-stats/moderation/plugin-data integration pass.
- Incoming `ContextActionModify` is not a silent no-op now; it is rejected as not-for-incoming and covered by an auth integration test.
