# S2S channel delete shadow delivery + transport control frames completed 2026-05-17

Implemented in current checkout:
- `src/channel_handler.rs` now defines `SessionChannelShadow` and shadow-aware channel operation conversion.
- `convert_channel_operation_to_messages_with_shadow` handles `MarkPendingDelete` by emitting synthetic `UserState` moves only for sessions whose per-socket shadow still shows them inside the pending-delete subtree.
- Successful `DeleteChannel` emits synthetic straggler moves before `ChannelRemove`; stale/no-op deletes do not emit `ChannelRemove` or synthetic moves.
- `sync_shadow_for_client_message` keeps each socket shadow updated from delivered `UserState`/`UserRemove` messages and emits inline synthetic redirects if a delivered user state points into an already pending-delete subtree.
- `src/server.rs` owns one `SessionChannelShadow` per client connection, seeds it after auth from currently visible authenticated clients, passes it through channel-log replay/live delivery, and updates it during client-log replay/live delivery.
- `src/s2s/transport/stream_io.rs` sends `FrameHello` when a stream pump starts, uses `FrameKeepalive` for periodic empty liveness RTT, and continues using `FramePing` for payload-carrying bandwidth probes. Inbound `FrameKeepalive` is echoed as `Pong`; inbound `FrameHello` is traced.
- `src/s2s/transport/endpoint/udp.rs` mirrors the same DTLS behavior: session-start Hello, periodic KeepAlive, echo KeepAlive/Ping as Pong, trace Hello.

Verification:
- `cargo fmt --check`: passed.
- `cargo check --all-targets`: passed with recurring non-fatal Windows incremental finalization warning.
- `cargo test channel_repository::tests`: passed.
- `cargo test integration_tests::scenarios::s2s`: passed.
- `cargo test s2s::transport::integration_tests`: passed.
- Full `cargo test`: passed. Observed summaries: lib 281 passed / 4 ignored; bin 219 passed / 4 ignored; doctests 0.

Note: worktree had many pre-existing unrelated modifications; touched files for this task were `src/channel_handler.rs`, `src/server.rs`, `src/s2s/transport/stream_io.rs`, and `src/s2s/transport/endpoint/udp.rs`.