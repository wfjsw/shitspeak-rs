# WebRTC Inbound Frame Mapper Slice (2026-05-18)

Implemented the next WebRTC web-client plan item: stop using raw RTP timestamps as Mumble `Audio.frame_number` for browser microphone traffic.

Changes:
- `src/web/voice.rs`
  - Added `RtpFrameNumberMapper` with private per-stream state.
  - Maps `(ssrc, voice_epoch, rtp_timestamp)` into a per-web-client monotonic `u64` Mumble frame sequence.
  - Normalizes random RTP timestamp starts to frame 0.
  - Converts RTP timestamp deltas using Opus 48 kHz clock / 100 Hz Mumble frame numbering (`480` RTP ticks per frame number).
  - Handles u32 RTP timestamp wrap with wrapping subtraction.
  - Forces monotonic progress for duplicate or sub-frame timestamp deltas.
  - Starts a new monotonic segment when SSRC or acknowledged voice-control epoch changes, without reusing frame numbers.
  - Added tests for random initial timestamp, small/duplicate timestamp deltas, RTP wrap, and epoch/SSRC changes.
- `src/web/peer.rs`
  - WebRtcPeer now owns an `Arc<Mutex<RtpFrameNumberMapper>>` shared by inbound audio track tasks.
  - `spawn_inbound_audio_task` now uses the mapper to set `Audio.frame_number` instead of `packet.header.timestamp as u64`.
  - The mapper is keyed by packet SSRC and current acknowledged voice-control epoch.

Validation:
- `cargo fmt` passed.
- `cargo test web::voice::tests --lib` passed: 9 tests.
- `cargo test web:: --lib` passed: 28 tests.
- `cargo test --lib` passed: 312 passed, 4 ignored.

Remaining WebRTC plan items:
- Add a real WebRTC peer-pair test verifying negotiated recvonly speaker slots, server answer m-lines/tracks, and speaker metadata events on routed native audio.
- Add SDK/browser tests if Node/Playwright become available.
- Decide whether metadata/state events should be de-duplicated or stop mirroring over WebSocket once the data channel opens.
