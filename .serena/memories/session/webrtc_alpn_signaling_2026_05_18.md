# WebRTC ALPN Signaling Routing Implemented (2026-05-18)

Implemented ALPN-based separation on the regular Mumble TLS port:
- Server TLS config now advertises ALPN protocols `http/1.1` and `mumble`.
- After TLS accept in `handle_incoming_connection`, selected ALPN routes:
  - `http/1.1` -> `web::signaling::SignalingServer::handle_stream` on the same TLS stream.
  - `mumble` or no ALPN -> existing native Mumble protocol path.
  - unknown ALPN -> warn and close.
- Extracted native TLS Mumble logic into `handle_native_mumble_tls_connection` helper.
- `web.listen` is now optional extra separate signaling listener. If omitted and web is enabled, browser signaling can still use the main Mumble port through ALPN.
- `SignalingServer::handle_stream` is generic over `AsyncRead + AsyncWrite`, so it works for both raw separate listener streams and TLS streams selected by ALPN.
- No frontend assets are served by the app.

Validation:
- `cargo test web:: --lib`
- `cargo test config::tests::web_config --lib`
- `cargo test --lib`
All passed.

Remaining:
- Real WebSocket upgrade/signaling protocol inside `handle_stream`.
- WebRTC peer/media bridge.
- Web session/control integration with existing client/session loop.
