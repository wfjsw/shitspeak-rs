# Incomplete Parts Inventory (2026-05-17)

Project: `d:\shitspeak-rs`

Static scan plus targeted symbol inspection found these current unfinished or incomplete areas:

1. S2S-safe two-phase channel deletion is not implemented.
   - `channel_remove_s2s_plan.md` describes pending-delete state, `MarkPendingDelete`, nonce-bearing `DeleteChannel`, `CancelPendingDelete`, watchdog rollback, per-socket `session_channel_shadow`, and pending-delete auth/join redirects.
   - Current `src/channels.rs::Channel` fields are only id/name/position/max_users/parent_id/inherit_acl/links/description_hash/acls; no pending-delete state.
   - Current `src/channel_repository.rs::ChannelOp` still has `DeleteChannel { id }` only; no `MarkPendingDelete`, no `CancelPendingDelete`, no nonce.
   - `src/client/handlers/channel_remove.rs::handle_channel_remove` moves currently known clients then proposes/deletes `DeleteChannel { id }` directly.
   - `src/channel_handler.rs::convert_channel_operation_to_messages` still calls `op.to_message()` and does not implement delete no-op guard, synthetic straggler moves, or shadow-state handling.

2. S2S voice is still partial beyond normal channel speech.
   - `src/voice/routing.rs::route_voice` sends S2S only for `AudioTarget::Normal`; direct remote `VoiceTarget` session recipients are explicitly deferred.
   - `src/voice/routing.rs::route_s2s_voice_frame` routes inbound S2S frames only to local users in the sender's current channel plus local listeners. It does not reproduce linked-channel fanout or whisper/shout target semantics.
   - `src/s2s/application/voice/targeted.rs::RecipientIndex` exists, and `VoiceService::send_for_channel` can use it, but production setup only installs an empty index. No production reconciler populates `set_channel_nodes`, `replace_all`, `add`, or `remove`; targeted delivery therefore falls back to broadcast/no-op in practice except tests.
   - `src/s2s/application/voice/ingress.rs` header still says the dispatch task is a no-op stub, but that is stale; tests show dispatch through reorderer/sink works.

3. S2S strict quorum timeout behavior is currently broken.
   - `cargo test s2s::replications::integration_tests::scenarios::strict_quorum_never_forms_times_out` fails: expected `Err(ReplicationError::ProposeTimeout(500ms))`, got `Ok(1)`.
   - Full `cargo test` failed only this test: 273 passed, 1 failed, 4 ignored profiling tests.
   - `cargo check --all-targets` passes with only the known Windows incremental compilation finalization warning.

4. Client session lookup still has an explicit ambiguity FIXME.
   - `src/client_repository.rs::ClientRegister::get` treats `node_id == 0` as ambiguous and falls through local then remote; it still needs local-node-id-aware lookup semantics.

5. Minor stale/compatibility stubs and placeholders remain.
   - `src/channel_repository.rs` module docs and section labels still call S2S methods stubs even though `apply_committed_operation`/snapshot integration are now real.
   - `src/s2s/overlay/messaging/mod.rs::ServiceRegistry::last_tag_for_inbound` is a compile-only compatibility stub returning 0; no production call sites were found.
   - `src/s2s/transport/stream_io.rs` has a reserved no-op branch for future use.
   - `src/s2s/application/user_stats/runtime.rs` test loopback path has `expect("inbound not yet wired")`, but production inbound registration exists and user-stats tests pass.

6. Intentional no-ops / out-of-scope items that are not implementation gaps by current design.
   - `Authenticator` default blob/user-list methods are no-op extension hooks unless a backend overrides them.
   - `UserList` handler intentionally no-ops because registration is delegated to the authenticator backend.
   - Incoming `ContextActionModify` no-ops; context actions are advertised server-to-client and inbound modify is not a client command this server accepts.
   - `NoopAuthenticator` in `main.rs` is the development/default fallback, not a complete production auth backend.
   - OCB2 profiling tests under `src/client/crypt/profile_test.rs` are intentionally `#[ignore]`.

Verification run on 2026-05-17:
- `cargo check --all-targets`: passed; Windows incremental finalization warning only.
- `cargo test s2s::application::voice`: 24 passed.
- `cargo test s2s::application::integration_tests::scenarios`: 4 passed.
- `cargo test s2s::replications::integration_tests::scenarios::strict_quorum_never_forms_times_out`: failed, expected timeout got `Ok(1)`.
- `cargo test`: 273 passed, 1 failed (`strict_quorum_never_forms_times_out`), 4 ignored.
