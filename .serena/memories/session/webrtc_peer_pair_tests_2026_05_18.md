# WebRTC Peer-Pair Tests Slice (2026-05-18)

Implemented the next WebRTC plan item around real peer negotiation and outbound metadata coverage.

Changes:
- `src/web/peer.rs`
  - Added `answer_offer_negotiates_bounded_sendonly_speaker_slots`.
    - Builds a browser-like `RTCPeerConnection` with `bundle_policy = MaxBundle` and three recvonly audio transceivers.
    - Creates an offer, answers it through real `WebRtcPeer::new(... max_speaker_ssrcs: 3 ...)` + `answer_offer`.
    - Applies the answer to the offer peer.
    - Asserts the server has exactly three audio transceivers negotiated as desired/current `Sendonly`.
    - Asserts the browser/offer peer has exactly three audio transceivers negotiated as desired/current `Recvonly`.
  - Extracted `speaker_assignment_events(audio, assignment, track_id, channel_id)` so outbound routed native audio metadata construction is deterministic and directly testable.
  - Added `speaker_assignment_events_include_track_context_and_timestamps`, covering `speaker_assigned` and `voice_segment_start` fields: SSRC, speaker session, track id, epoch, target context, channel id, and RTP timestamp.

Validation:
- `cargo fmt` passed.
- `cargo test web::peer::tests --lib` passed: 4 tests.
- `cargo test web:: --lib` passed: 30 tests.
- `cargo test --lib` passed: 314 passed, 4 ignored.

Notes:
- This adds real offer/answer transceiver coverage but still does not send live RTP over the peer pair. A future test could drive actual native-to-web RTP samples if the crate's local transport setup is stable enough in CI.
- Remaining WebRTC gaps: SDK/browser tests when Node/Playwright is available; decide whether duplicated event delivery over WebSocket + data channel should be de-duped or switched to data-channel-only after control open.
