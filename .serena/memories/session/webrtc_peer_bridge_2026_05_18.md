# WebRTC peer bridge slice - 2026-05-18

Implemented after metadata/control signaling:

- Added full Rust `webrtc = "0.17.1"` dependency while preserving existing direct `webrtc-dtls = "0.12"` / `webrtc-util = "0.11"` for S2S DTLS.
- Added `src/web/peer.rs` and exported it from `src/web/mod.rs`.
  - Builds real `RTCPeerConnection` with configured STUN/TURN ICE servers.
  - Registers default codecs/interceptors and negotiates Opus.
  - Handles WebSocket offer -> WebRTC answer.
  - Handles trickled ICE candidates both ways.
  - Emits ICE connection state as existing `ice_connection_state` server events.
  - Accepts the browser-created ordered `shitspeak-control` data channel and routes JSON control commands through the same native handlers used by signaling fallback.
  - Implements `voice_control` epoch ACK in both data channel and signaling fallback.
  - Keeps inbound RTP/Opus gated by acknowledged PTT epoch before calling `Client::push_voice_routing`.
  - Drains the web client's existing TCP voice queue into a single outbound Opus WebRTC track, preserving low-SSRC policy by using one persistent outbound speaker slot for now.
- Updated `src/web/signaling.rs`:
  - `offer` no longer returns placeholder not-implemented; it creates/stores a `WebRtcPeer` and sends `{type:"answer", sdp}`.
  - `ice_candidate` now calls `RTCPeerConnection::add_ice_candidate`.
  - WebSocket event loop forwards peer signals (`answer`, `ice_candidate`, ICE state/events).
  - Native outbound metadata is mirrored to the WebRTC data channel when open while still being sent over WebSocket.
  - Close frame closes the peer connection before removing the server client.
  - Web gateway auth marks the web client protocol version as 1.5.0 so existing routing encodes protobuf Opus for the web voice queue.
  - Web gateway auth now starts the normal per-client voice routing task; the outbound TCP voice send task is intentionally replaced by the WebRTC outbound-track drain.
- Updated `src/web/voice.rs`:
  - `VoiceEpoch` now includes `ptt: bool`; `InboundVoiceMetadata::update_epoch` takes PTT so inbound RTP can be dropped when PTT is off.
- Added/updated tests:
  - `websocket_offer_returns_webrtc_answer` covers actual offer/answer.
  - Invalid SDP offer now asserts the answer error rather than placeholder not-implemented.
  - Peer helper tests cover ICE server and voice-target mapping.

Validation:
- `cargo fmt`
- `cargo test web:: --lib`: 21 passed.
- `cargo test --lib`: 305 passed, 4 ignored.

Remaining gaps:
1. Outbound browser playback currently uses one persistent Opus WebRTC track/SSRC for all routed speakers. This preserves low SSRC count but metadata (`speaker_assigned`/segment start) is not yet fully mapped per speaker slot.
2. Inbound RTP frame numbering uses RTP timestamp as Mumble frame_number. It is routable but should be refined to a dedicated per-web-client sequence mapper.
3. The outbound RTP bridge decodes routed TCP-tunnel bytes from the existing web client queue and writes Opus samples; add integration/browser tests with a real peer pair.
4. Add real speaker slot allocator integration for native-to-web fanout and send `speaker_assigned`/`voice_segment_start/end` events with negotiated track identity.
5. Consider whether signaling fallback should continue mirroring events after data channel opens or migrate to data-channel-only for control/state after peer establishment.