# Voice Transit Processing Implementation (2026-05-16)

Implemented overlay opt-in transit delivery for S2S voice packets.

Key changes:
- Added `process_on_transit = 8` to `src/protos/S2SOverlay.proto::OverlayData`.
- `src/s2s/overlay/messaging/forward.rs` now delivers inbound `OverlayData` locally when either the local node is in `dsts` or `process_on_transit` is true, then forwards remaining destinations as before. The flag is preserved across per-next-hop fanout.
- Added opt-in overlay send APIs in `src/s2s/overlay/messaging/mod.rs` and `src/s2s/overlay/mod.rs` named `send_*_with_transit_processing`; existing send APIs still default to non-transit processing.
- `src/s2s/application/voice/send.rs` now uses the opt-in overlay APIs for voice unicast/multicast/broadcast.
- Added regression `three_node_voice_unicast_delivers_to_transit_node` in `src/s2s/application/integration_tests/scenarios.rs` using a 1-2-3 line topology; node 2 receives a node 1 -> node 3 voice frame even though it is only a transit node.
- Added explicit `cargo:rerun-if-changed` entries for proto files in `build.rs`; otherwise Cargo did not regenerate prost output after `S2SOverlay.proto` changed. Note: build.rs already had unrelated localization-generation edits in the worktree before this task.
- Serialized `Cluster::build_with_cfg` with a test-only async mutex in `src/s2s/testing/cluster.rs` to avoid documented ephemeral TCP port allocation races when multiple cluster integration tests run in parallel.

Verified:
- `cargo test three_node_voice_unicast_delivers_to_transit_node`
- `cargo test s2s::application::integration_tests::scenarios`
- `cargo check`

Caveat: verification completed with a Windows warning about finalizing incremental compilation cache directories (`Access is denied`), but commands exited successfully except for an earlier pre-fix parallel port race.