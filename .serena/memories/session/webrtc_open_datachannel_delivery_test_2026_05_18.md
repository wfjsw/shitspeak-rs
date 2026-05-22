# WebRTC open data-channel delivery test - 2026-05-18

Continued the WebRTC plan after the control transport policy slice.

Change:
- Added `send_event_delivers_over_open_control_channel` in `src/web/peer.rs`.
- The test builds a browser-like native `RTCPeerConnection`, creates the `shitspeak-control` data channel, negotiates against a real `WebRtcPeer`, forwards server trickled ICE candidates from `PeerSignal::IceCandidate`, waits for the control channel to open, calls `WebRtcPeer::send_event(ServerEvent::VoiceControlAck { epoch: 11 })`, and asserts the remote side receives the typed JSON event.
- Added a test-local `install_crypto_provider()` helper using `rustls::crypto::aws_lc_rs::default_provider().install_default()` because the data-channel DTLS path reaches Rustls provider selection; earlier SDP-only peer tests did not.

Validation:
- `cargo fmt`
- `cargo test web::peer::tests::send_event_delivers_over_open_control_channel --lib`: passed
- `cargo test web::peer::tests --lib`: 6 passed
- `cargo test web:: --lib`: 32 passed
- `cargo test --lib`: 316 passed, 4 ignored

Notes:
- Node is still unavailable (`node --version` not recognized), so SDK/Playwright tests remain blocked locally.
- This closes the Rust-side proof that preferred app-event delivery over an opened RTCDataChannel works, not only the fallback-before-open path.