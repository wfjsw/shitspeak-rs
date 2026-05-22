# WebRTC SDK Node tests - 2026-05-19

User provided Node executable path: `C:\Users\synopses0130\AppData\Roaming\fnm\node-versions\v22.22.2\installation\node.exe`. Sandbox requires elevated execution for this path because it is outside the workspace.

Implemented dependency-free SDK tests:
- Added `web/sdk/shitspeak.test.mjs`.
- Uses fake `WebSocket`, `RTCPeerConnection`, `RTCDataChannel`, and `MediaStream` objects; no npm/package setup required.
- Covers gateway config wait/application, server max speaker-slot capping, `bundlePolicy: "max-bundle"`, recvonly speaker transceiver creation, offer payload with `speaker_slots`, command fallback to WebSocket before control opens, command delivery over RTCDataChannel after open, PTT target encoding/epoch increments, state cache merging for users/channels, speaker metadata lifecycle, answer/ICE signal handling, and remote track aggregation into `remoteStream`.

Validation:
- `node.exe web/sdk/shitspeak.test.mjs`: passed all 5 tests.
- `node.exe --check web/sdk/shitspeak.js`: passed.
- `node.exe --check web/demo/main.js`: passed.
- `cargo test web:: --lib`: 32 passed.
- `cargo test --lib`: 316 passed, 4 ignored.

Notes:
- This closes the previously blocked SDK fake-signaling test slice locally.
- Playwright/browser demo tests still require a browser test harness/dependency setup if desired later.