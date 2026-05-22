# Incomplete Parts Inventory (refreshed 2026-05-17)

Project: `d:\shitspeak-rs`

Scope: explicit placeholder scan, protocol/message coverage scan, S2S/channel/voice targeted symbol inspection, and verification commands against the current dirty worktree.

Current confirmed unfinished or incomplete areas:

1. PluginDataTransmission is absent from the Rust message layer.
   - `src/protos/Mumble.proto` defines `PluginDataTransmission`.
   - `src/messages/message.rs::Message` has no `PluginDataTransmission` variant.
   - Incoming wire type for plugin data will therefore go through the unknown-message path and be ignored by the server.

2. The channel-delete two-phase implementation exists, but the per-socket shadow delivery plan is not implemented.
   - Implemented now: `PendingDeleteState`, `ChannelOp::MarkPendingDelete`, nonce-bearing `DeleteChannel`, `CancelPendingDelete`, pending-delete auth/join redirects, a rollback watchdog, and local client moves out of pending-delete subtrees.
   - Still missing from `channel_remove_s2s_plan.md`: `server.rs` does not maintain `session_channel_shadow`, and `channel_handler.rs::convert_channel_operation_to_messages` still only converts normal channel ops plus permission info. It does not perform shadow-guarded synthetic `UserState` scans for `MarkPendingDelete` / straggler `DeleteChannel` delivery.
   - Practical risk: per-socket delivery order around remote client moves and channel deletion can still produce stale user-in-deleted-channel views in edge cases described by the plan.

3. `ContextActionModify` incoming handling is an explicit no-op.
   - The server advertises context actions via `ContextActionModify`, and executes incoming `ContextAction` messages.
   - Incoming `ContextActionModify` is accepted and returns `Ok(())` without changing state. Likely intentional policy, but unimplemented if client-side action registration/modification is desired.

4. `UserList` mutation is intentionally a no-op.
   - `handle_user_list` authenticates then logs and returns `Ok(())`.
   - Comment says user registration is delegated to the authenticator backend. Not a gap under that design, but the Mumble `UserList` mutation path is not implemented in-server.

5. Production auth backend is not implemented in this binary.
   - `main.rs` wires `NoopAuthenticator`, a development/default fallback.
   - Real auth/user DB behavior depends on embedding or replacing the `Authenticator` implementation.

6. Minor stale or compatibility no-ops remain.
   - `src/channel_repository.rs` still has a `// S2S / replication stubs` section heading even though replication integration is real.
   - `src/s2s/transport/stream_io.rs` and `src/s2s/transport/endpoint/udp.rs` treat `FrameKeepalive` / `FrameHello` as reserved no-ops.
   - `src/s2s/application/user_stats/runtime.rs` contains a test loopback `expect("inbound not yet wired")`; production user-stats inbound registration is implemented and tests pass.

Findings from older incomplete-parts memories that are obsolete now:
- S2S-safe two-phase channel deletion is no longer absent; core data model and operations are present.
- S2S voice is no longer limited to normal-channel speech; target intent broadcast and production recipient-index bridging are present.
- `strict_quorum_never_forms_times_out` now passes.
- `ClientRegister::get` no longer has the old node_id==0 FIXME behavior; current lookup compares against `local_node_id` directly.

Verification on 2026-05-17:
- `cargo check --all-targets`: passed. Cargo emitted only the known non-fatal Windows incremental compilation directory finalization warning (`Access is denied`).
- `cargo test`: passed. Summary observed: library tests 276 passed, 0 failed, 4 ignored; binary tests 216 passed, 0 failed, 4 ignored; doc tests 0 passed.
