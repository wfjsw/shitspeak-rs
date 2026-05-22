# S2S voice/channel-delete/quorum gap closure completed 2026-05-17

Implemented requested plan:
- Voice S2S carries unresolved `VoiceIntent` in `VoiceFrame`; no resolved recipient session lists are encoded over S2S.
- Local and remote S2S voice use the same local resolver in `src/voice/routing.rs`; `ServerLoopback` remains local-only.
- `VoiceIntent::VoiceTarget` carries unresolved direct session IDs and channel target specs. Normal and targeted voice share routing, mute/suppression, batching, encryption, UDP/TCP fallback paths.
- S2S node fanout is only a transport optimization via recipient-index hints; correctness falls back to broadcast/local resolution.
- Channel delete is two-phase: `MarkPendingDelete`, nonce-bearing `DeleteChannel`, `CancelPendingDelete`, pending-delete watchdog/cancel, redirects away from pending-delete subtrees.
- Remote nodes now move their own local clients out after committed `MarkPendingDelete` before a later matching nonce delete emits `ChannelRemove`; behavior substitutes for a separately named per-socket shadow-state structure via local pending-delete moves plus client/channel log ordering.
- Strict quorum timeout now returns `ReplicationError::ProposeTimeout(cfg.propose_ttl())` when quorum never forms but membership remains healthy, preserving quorum-lost behavior on membership shrink.
- Client lookup now branches by `ClientRepository.local_node_id`.

Verification reported complete:
- `cargo fmt --check` passed.
- `cargo check --all-targets` passed.
- Focused tests passed: `strict_quorum_never_forms_times_out`, `stale_nonce_delete_is_semantic_no_op`, `matching_nonce_delete_removes_subtree_and_emits_remove`.
- Full `cargo test` passed: lib 276 passed / 0 failed / 4 ignored; main/test binary 216 passed / 0 failed / 4 ignored; doctests 0 passed.
- Recurring non-fatal Windows warning: incremental compilation finalization `Access is denied. (os error 5)`.

Key touched files: `src/voice/routing.rs`, `src/protos/S2SApplication.proto`, `src/s2s/application/voice/{ingress,send,reorder,targeted}.rs`, `src/s2s/application/proto.rs`, `src/channel_repository.rs`, `src/channels.rs`, `src/client/handlers/{authenticate,channel_remove,user_state}.rs`, `src/client_repository.rs`, `src/server.rs`, `src/config.rs`, `src/s2s/replications/strict/runtime.rs`, `src/s2s/testing/chaos.rs`, `src/s2s/replications/integration_tests/scenarios.rs`.