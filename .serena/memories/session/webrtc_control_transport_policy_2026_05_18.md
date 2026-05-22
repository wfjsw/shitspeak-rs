# WebRTC control transport policy - 2026-05-18

Implemented the duplicate-event decision from the web client plan.

Policy:
- WebSocket remains the required transport for gateway setup: `gateway_config`, authentication, offer/answer, ICE candidates, and pre-data-channel fallback.
- Once the WebRTC `shitspeak-control` data channel is actually open and accepts a send, app/server events are delivered over the data channel only.
- If the data channel is absent, still connecting, closed, or send fails, the signaling WebSocket is used as fallback.

Code changes:
- `src/web/peer.rs`
  - `WebRtcPeer::send_event` now returns `bool` to report whether the event was accepted by an open RTCDataChannel.
  - It checks `RTCDataChannelState::Open` before sending.
  - Outbound voice metadata (`speaker_assigned`, `voice_segment_start`, `voice_segment_end`) now enters the signaling loop as `PeerSignal::ServerEvent`; the signaling loop applies the same preferred-transport policy.
  - Added test `send_event_reports_fallback_before_control_channel_opens`.
- `src/web/signaling.rs`
  - `send_web_outbound_message`, `send_peer_signal`, and signaling `voice_control` fallback now use data channel first and WebSocket only if data-channel delivery reports false.
  - Initial state during auth remains WebSocket-only because peer/control is not established at that phase.

Validation:
- `cargo fmt`
- `cargo test web::peer::tests --lib`: 5 passed
- `cargo test web:: --lib`: 31 passed
- `cargo test --lib`: 315 passed, 4 ignored

Remaining plan items:
- SDK/browser tests remain blocked locally because Node is not installed.
- Deeper real RTP media integration tests are still future work.
- SSO remains placeholder/rejection only unless implemented later.