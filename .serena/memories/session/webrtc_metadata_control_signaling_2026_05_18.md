# WebRTC metadata/control signaling slice - 2026-05-18

Implemented after the web gateway client allocation work:

- `src/web/protocol.rs`
  - Added typed JSON `ServerEvent` variants for native metadata/state:
    - `user_state`, `user_remove`, `channel_state`, `channel_remove`
    - `server_sync`, `server_config`, `permission_denied`, `codec_version`
    - richer `text_message` with target sessions/channels/trees.
  - Binary protobuf fields used by web events are represented as base64 strings.
  - Added a protocol test verifying absent patch fields are skipped for `user_state`.

- `src/web/signaling.rs`
  - Replaced placeholder outbound errors with native `Message` -> typed `ServerEvent` translation.
  - Password auth now sends `authenticated` first, then an initial state burst:
    - BFS channel state snapshot
    - current authenticated user states
    - self user state
    - server sync/config
    - codec version
  - Web sessions now subscribe to client/channel logs after the initial snapshot and translate ongoing updates to typed JSON events.
  - Added shadow handling via `SessionChannelShadow` to keep synthetic pending-delete moves aligned with native clients.
  - Added signaling WebSocket fallback handling for SDK control commands (`join_channel`, `send_text`, `set_mute`, `set_deaf`) by converting to native messages and calling `Client::handle_message`, so ACL and mutation semantics stay shared with native clients.
  - `voice_control` over signaling is currently accepted as a no-op fallback; real voice-control ack/routing should be done with the WebRTC media/data bridge.
  - Added test `websocket_join_channel_command_uses_server_handlers` covering join-channel over signaling.

- `web/sdk/shitspeak.js` and `.d.ts`
  - SDK tracks `speakers`, `users`, `channels`, `serverSync`, `serverConfig`, and `codecVersion`.
  - `user_state` and `channel_state` patches are merged into maps; channel `links_add`/`links_remove` are applied.
  - `sendCommand` now falls back to the signaling WebSocket if the WebRTC data channel is not open.

- `web/demo/*`
  - Demo shows current channels/users from SDK state.
  - Mic/PTT buttons are enabled after signaling auth as a temporary fallback until WebRTC media is wired.

Validation:

- `cargo fmt`
- `cargo test web:: --lib` passed: 18 tests.
- `cargo test --lib` passed: 302 passed, 4 ignored.

Remaining next steps:

1. Implement real WebRTC SDP/ICE peer bridge and media RTP/Opus path.
2. Replace signaling no-op `voice_control` with real metadata sync/ack tied to RTP epoch handling.
3. Move SDK commands back onto the WebRTC control data channel once the peer connection exists; keep signaling fallback only for pre-data-channel setup if desired.
4. Broaden tests for `send_text`, `set_mute`, `set_deaf`, permission denial translation, and peer update delivery between multiple web/native clients.
