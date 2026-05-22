# WebRTC Gateway Slot Negotiation Slice (2026-05-18)

Implemented the next WebRTC web-client plan slice to reconcile browser SDK speaker-slot count with the server low-SSRC policy.

Changes:
- `src/web/protocol.rs`
  - Added `WebGatewayConfig { max_speaker_slots, audio_bitrate }`.
  - Added `ServerEvent::GatewayConfig`, serialized as `type: "gateway_config"`.
  - Added a protocol test for the new event.
- `src/web/signaling.rs`
  - Sends `gateway_config` immediately after WebSocket upgrade and before auth/offer handling.
  - Accepts optional `speaker_slots` on `offer` signaling messages.
  - Caps requested speaker slots with `negotiated_speaker_slots(requested, server_max)` so a browser can ask for fewer slots but cannot exceed `web.webrtc.max_speaker_ssrcs`.
  - Added tests for default gateway config frame and negotiation capping. Existing signaling tests now explicitly consume the initial gateway config frame.
- `web/sdk/shitspeak.js`
  - `openSignaling()` waits for `gateway_config` before returning.
  - Peer/transceivers are created lazily after gateway config is known.
  - SDK uses server max speaker slots by default, or a caller-provided `maxSpeakerSlots` capped to the server max.
  - Offer includes `speaker_slots` so the Rust peer allocates the same bounded pool it negotiated with the browser.
  - `gatewayConfig` is exposed on the client instance.
- `web/sdk/shitspeak.d.ts`
  - Added `GatewayConfigEvent` and `gatewayConfig` property.
- `web/demo`
  - Speaker slots field is optional/blank by default. If blank, SDK uses server maximum; if specified, the demo requests that lower count.

Validation:
- `cargo fmt` passed.
- `cargo test web:: --lib` passed: 24 tests.
- `cargo test --lib` passed: 308 passed, 4 ignored.
- Node is not installed/recognized in this environment, so `node --check web/sdk/shitspeak.js` and `node --check web/demo/main.js` could not run.

Remaining plan items:
- Add a real WebRTC peer-pair test around recvonly speaker slots and server answer m-lines/tracks.
- Add inbound RTP timestamp-to-Mumble-frame monotonic sequence mapper; current inbound path still uses RTP timestamp as `frame_number`.
- Consider SDK/browser tests and event duplicate handling after the RTCDataChannel opens.
