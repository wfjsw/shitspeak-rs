# WebRTC WebSocket Signaling Step (2026-05-18)

Implemented the next incremental step for the WebRTC web client plan: real WebSocket transport on the signaling endpoint, without serving frontend assets.

Files touched:
- `Cargo.toml`: added direct deps `base64 = "0.22.1"` and `sha1 = "0.10.6"` for RFC 6455 accept-key generation.
- `Cargo.lock`: `shitspeak-rs` now directly lists `base64` and `sha1`.
- `src/web/signaling.rs`: added HTTP header parsing, `/web/signaling` WebSocket upgrade validation, `Sec-WebSocket-Accept` generation, bounded masked client frame parser, unmasked server frame writer, ping/pong/close handling, and JSON error replies for SDK messages.

Behavior:
- `/health` and `/web/health` remain simple HTTP JSON endpoints.
- `GET /web/signaling` now requires a valid WebSocket upgrade (`Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`). Non-upgrade requests return `400` with `{"error":"websocket upgrade required"}`.
- Accepted WebSocket connections currently parse `offer` and `ice_candidate` JSON and reply with `{ "type": "error", "message": "webrtc signaling bridge is not implemented yet" }`, making the transport real while the WebRTC peer bridge remains pending.
- The frame reader preserves bytes already read beyond HTTP headers so clients can pipeline the first WebSocket frame with the upgrade request.
- No frontend/demo assets are served by the Rust app.

Tests added in `src/web/signaling.rs`:
- RFC 6455 accept-key known vector.
- Successful upgrade returns `101 Switching Protocols` and expected accept key.
- Non-upgrade signaling request returns `400`.
- Pipelined `offer` text frame receives JSON not-implemented error.

Validation:
- `cargo test web:: --lib` passed after formatting.
- `cargo test --lib` passed before formatting (295 passed, 4 ignored).

Next recommended implementation step:
- Add the actual WebRTC peer-connection/media bridge behind the signaling transport, or add password-auth session bootstrapping over the WebSocket first if the control/session identity path should be established before SDP handling.
