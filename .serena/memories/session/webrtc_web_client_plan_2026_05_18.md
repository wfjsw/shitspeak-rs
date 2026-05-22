# WebRTC Web Client Plan (2026-05-18)

## Summary

Build an optional in-process WebRTC web gateway for `shitspeak-rs`, plus a JavaScript/TypeScript SDK and a thin demo app built on that SDK.

The browser will not speak raw Mumble TLS/UDP. The server will create normal internal client sessions, bridge browser control actions into existing handlers/state, and bridge WebRTC Opus RTP media into the existing `voice::codec::Audio` + `route_voice` pipeline.

Selected direction:
- In-process browser gateway inside `shitspeak-rs`.
- Public-internet deployment target with HTTPS and STUN/TURN.
- Use WebRTC media tracks for audio, not Mumble voice packets over RTCDataChannel.
- Support both username/password authentication and external SSO.
- Build a JS/TS SDK first, then a demo application on top of the SDK.

## Server Gateway

Add optional `[web]`, `[web.auth]`, and `[web.webrtc]` config:
- HTTPS/public base URL, bind address, allowed origins, static asset serving, and SDK/demo asset path.
- Password-auth enablement and SSO settings: issuer/JWKS/audience/claim mapping.
- ICE STUN/TURN servers, TURN credential policy, RTP track limits, bitrate defaults, and low-SSRC pool size.

Add an in-process HTTP/WebRTC gateway:
- Use `axum`/`tower-http` for APIs, static demo serving, and WebSocket or HTTP signaling.
- Add the Rust `webrtc` crate for `RTCPeerConnection`, RTP receive/send tracks, ICE, DTLS, and data channels.
- Refactor client I/O so web sessions can reuse existing session behavior: hide TLS-specific stream halves behind a private transport enum/trait supporting native TLS and web gateway sessions.
- Extract the session loop from `src/server.rs` so native TCP accept and web sessions share message handling, subscriptions, disconnect, idle timeout, and log replay behavior.

Authentication:
- Password auth maps to the existing `Authenticator::authenticate(username, password, auxiliary_data)` path.
- SSO verifies IdP tokens server-side using JWKS and maps claims into `AuthenticateResult`; implement as an additional web-auth mode, not a replacement for password auth.
- Native Mumble client certificate behavior remains unchanged.

## SDK, Demo, And Control Protocol

Create a JS/TS SDK as the primary browser-facing artifact:
- Own signaling, password/SSO auth flows, WebRTC connection lifecycle, data-channel protocol, media setup, reconnect, and state cache.
- Expose typed events for server state: channels, users, text messages, permissions, speaking state, disconnect/reconnect, and ICE status.
- Expose commands for authenticate, join/move channel, text chat, mute/deafen, PTT, voice target selection, user moderation, and admin actions where server ACLs allow them.

Build a thin demo app on top of the SDK:
- Login screen supporting password and SSO.
- Actual client UI: channel tree, user list, text chat, PTT, mute/deafen, device selection, and connection/ICE status.
- Keep the demo minimal; feature depth belongs in the SDK API and examples.

Use a reliable ordered RTCDataChannel for control:
- Browser sends typed JSON or compact binary commands.
- Server converts commands to existing `Message`/handler calls.
- Server converts outbound Mumble messages and state changes into typed SDK events.

## WebRTC Voice And Metadata Synchronization

Use WebRTC media tracks for audio:
- Browser microphone uses `getUserMedia()` and `RTCPeerConnection.addTrack()`.
- Server reads inbound Opus RTP, maps the inbound track/SSRC to the authenticated web client and current voice target, wraps payloads as `AudioPayload::Opus`, and calls `client.push_voice_routing(...)`.
- For web recipients, server packetizes routed Opus frames into RTP on stable outbound SSRCs/tracks.
- Native recipients keep the current UDP/TCP tunnel path unchanged.

Low-SSRC policy from Mumble issue https://github.com/mumble-voip/mumble/issues/3561:
- WebRTC/SRTP stacks retain per-SSRC crypto/replay state; media streams/tracks are hard to remove cleanly.
- Keep total SSRCs low: allocate stable reusable SSRCs, not one SSRC per talking burst or per voice context.
- Maintain a WebRTC SSRC allocator separate from Mumble session IDs.
- Prefer persistent RTP streams/tracks per speaker slot/session and mark inactive instead of renegotiating constantly.
- Reuse SSRCs after disconnect or clearly safe idle expiry.

Synchronize metadata with voice using SSRC mappings and epochs:
- Treat SSRC as the media identity for browser playback.
- Send `speaker_assigned` events over the data channel: `ssrc`, `speakerSession`, `trackId`, and `epoch`.
- Send `voice_segment_start` / `voice_segment_end` events with `ssrc`, `speakerSession`, `context`, `channelId`, `rtpTimestamp`, and `epoch`.
- Gate browser-to-server PTT/target changes with epochs: the browser sends `voice_control` with the new target and epoch; the server ACKs before routing voice under that epoch, or drops/holds frames until the epoch is known.
- Server-side routing uses RTP SSRC/timestamp/sequence plus current epoch state to build existing `Audio` values.
- Browser UI treats data-channel metadata as authoritative but approximate; exact sample-accurate metadata is not expected with media tracks.

## Test Plan

Rust unit tests:
- Password-auth and SSO claim mapping paths.
- Web command to internal message conversion.
- Internal message/state to SDK event conversion.
- SSRC allocator reuse and epoch ordering.
- RTP packetization/depacketization around existing Opus `Audio` payloads.

Rust integration tests:
- Web password-auth session appears as a normal local client.
- Web SSO session appears as a normal local client.
- Web text/channel/user actions hit existing ACL checks.
- Web-to-native, native-to-web, and web-to-web voice routing work.
- Disconnect, idle timeout, reconnect, and log replay behave like native sessions.

Browser/SDK tests:
- SDK fake-signaling tests for connection state, commands, events, reconnect, and metadata epoch handling.
- Playwright demo tests with fake media devices for login, channel navigation, text chat, PTT, mute/deafen, ICE failure UI, and reconnect.
- Public-internet deployment test with TURN enabled.

Regression:
- Existing native Mumble TLS/UDP tests continue passing.
- Existing voice benchmarks should show no regression for native-only fanout.
