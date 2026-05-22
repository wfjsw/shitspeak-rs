# WebRTC Foundation Implemented (2026-05-18)

Implemented first compile-safe slice of the WebRTC web client plan:
- Added `Config.web` with nested web auth and WebRTC settings.
- `config.toml` now includes disabled `[web]`, `[web.auth]`, `[web.auth.sso]`, and `[web.webrtc]` example sections.
- Added `ExternalAuthClaims` to `src/api/authenticator.rs`; subject is `u32` to match conventional server user_id type, no email field. Default `authenticate_external` maps claims to `AuthenticateResult` with `user_id = subject`.
- Added `src/web/` module:
  - `protocol.rs`: typed browser control protocol and server event JSON helpers.
  - `voice.rs`: low-SSRC allocator and inbound epoch/ack metadata state.
- Added JS SDK under `web/sdk/` with signaling, WebRTC peer/data channel lifecycle, password/SSO auth commands, PTT epoch control, and typed declarations.
- Added minimal static demo under `web/demo/` that uses the SDK.
- Updated integration test harness Config literal to use `WebConfig::default()`.

Validation run:
- `cargo test config::tests::web_config --lib`
- `cargo test web:: --lib`
- `cargo test --lib`
All passed.

Not implemented yet:
- Actual HTTP/WebSocket signaling server.
- Actual WebRTC media/session gateway using the `webrtc` crate.
- Refactor of TLS-specific `Client` transport/session loop for web sessions.
- RTP Opus bridge into `voice::codec::Audio` and web recipient RTP packetization.
