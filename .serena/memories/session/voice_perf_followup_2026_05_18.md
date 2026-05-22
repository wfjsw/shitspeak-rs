# Voice Perf Follow-up - 2026-05-18

After profiling, made two small low-risk wins in `src/voice/routing.rs`:

1. Raised `RAYON_FANOUT_THRESHOLD` from 256 to 512.
   - Fresh dispatch profile showed sequential is faster at 256 recipients (~117.5 us inline seq vs ~177.8 us spawn+Rayon) and Rayon starts winning at ~512 (~239.8 us inline seq vs ~215.2 us spawn+Rayon).
   - This avoids paying spawn/Rayon overhead too early for medium fanout.

2. Removed unnecessary `Arc<Vec<...>>` around the encoded plaintext cache snapshot in the large-fanout path.
   - The Vec is moved into the `spawn_blocking` closure and only borrowed by Rayon workers during the parallel iteration, so `Arc` was unnecessary.
   - Saves one heap allocation/refcount wrapper and clone on large fanout.

Verification:
- `cargo check` passed.
- `cargo test voice_udp` passed.
- Both emitted the known Windows incremental compilation finalization warning: Access is denied.

Remaining possible wins:
- Update Criterion fanout benchmark to use production `DatagramBatch`, so arena impact is measured directly.
- Receive path decrypt still creates a new `BytesMut` plaintext buffer per inbound UDP packet in `src/server.rs`; could use reusable buffer/arena or a decrypt-to-fixed-buffer path, but impact is ingress-only and smaller than fanout encryption.
- OCB2 decrypt is ~832 ns for 170 B and may be worth investigating only if inbound packet rate is the bottleneck.
- Larger structural win would require avoiding per-recipient encryption, which is not possible with independent recipient CryptState/IV without changing protocol/security properties.