# WebRTC Signaling Skeleton Implemented (2026-05-18)

Implemented next server-side slice after the WebRTC foundation:
- Added `src/web/signaling.rs` with a small Tokio HTTP signaling-only server.
- The Rust server does not serve frontend assets. Per user direction, frontend SDK/demo stays in repo but is not served by the app.
- `[web].static_dir` was removed from config and `config.toml`.
- `SignalingServer` supports:
  - `GET /health` and `GET /web/health` -> 200 JSON `{status: ok}`
  - `GET /web/signaling` -> 501 JSON explicit placeholder: WebRTC signaling bridge not implemented yet
  - unknown paths -> 404 JSON
- Wired optional web signaling task into `Server::run` only when `config.web.enabled` is true. Disabled is a no-op.
- No new dependencies were added.

Validation:
- `cargo test web:: --lib`
- `cargo test config::tests::web_config --lib`
- `cargo test --lib`
All passed.

Still pending:
- Real WebSocket signaling upgrade/protocol.
- WebRTC peer connection/media bridge.
- Web session/control integration with existing client/session loop.
