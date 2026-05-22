# Incomplete Parts Inventory (2026-05-16)

Analysis pass over `d:\shitspeak-rs` found these current implementation gaps:

1. S2S-safe two-phase channel deletion is not implemented.
   - `channel_remove_s2s_plan.md` describes `pending_delete`, `MarkPendingDelete`, `CancelPendingDelete`, nonce-bearing `DeleteChannel`, rollback watchdog, and per-socket `session_channel_shadow`.
   - Actual code has `ChannelOp::DeleteChannel { id }` only, `Channel` has no pending-delete fields, `handle_channel_remove` moves currently known clients then proposes/deletes directly, and `convert_channel_operation_to_messages` forwards `op.to_message()` without no-op guard/synthetic UserState injection.

2. S2S voice is partial.
   - `route_voice` only sends cross-node delivery for normal channel speech and comments say VoiceTarget direct remote recipients are deferred to a later phase.
   - `route_s2s_voice_frame` routes received S2S voice only to local users in the sender's current channel plus local listeners; it does not mirror linked-channel fanout or whisper/shout target semantics.
   - Targeted delivery mode has `RecipientIndex`, but production code only creates/sets an empty index. No production reconciler/population calls `set_channel_nodes`, `replace_all`, `add`, or `remove`; targeted therefore falls back to broadcast or no-ops except in tests.

3. S2S strict quorum failure behavior currently fails a test.
   - `cargo test` failed on `s2s::replications::integration_tests::scenarios::strict_quorum_never_forms_times_out`: expected `Err(ReplicationError::ProposeTimeout(500ms))`, got `Ok(1)`.
   - `cargo check` passed with known non-fatal Windows incremental compilation finalization warning.

4. Minor/stale stub markers remain.
   - `channel_repository.rs` docs still call S2S methods stubs, but methods are now real.
   - `s2s/application/voice/ingress.rs` header says dispatch task is a no-op stub, but it now dispatches through reorderer and sink; stale doc.
   - `s2s/overlay/messaging/mod.rs::ServiceRegistry::last_tag_for_inbound` is an actual compile-only compatibility stub returning 0 and has no call sites.

5. Intentional extension/default no-ops, not necessarily gaps:
   - `Authenticator` default blob/user-list hooks are no-op/empty unless a backend overrides them.
   - `UserList` handler intentionally no-ops because registration is delegated externally.
   - `NoopAuthenticator` in main accepts all users as guests and is a development fallback, not production auth.

Explicit FIXME:
- `ClientRegister::get` has `node_id == 0` ambiguity FIXME; it falls through local then remote pending a local-node-id-aware lookup.
