# DatagramBatch Production-Shape Benchmark - 2026-05-18

User asked to add production-shape `DatagramBatch` fanout benchmarks.

Changes:
- Added `DatagramBatch` import and two new Criterion benches in `benches/voice_hotpath.rs`:
  - `fanout/seq_datagram_batch_encode_encrypt`
  - `fanout/rayon_datagram_batch_encode_encrypt`
- Benches encode once, precompute OCB2 plaintext checksum once, and encrypt each recipient directly into `DatagramBatch::try_push_zeroed`, matching production fanout buffer shape.
- Added `RAYON_DATAGRAM_BATCH_MIN_LEN = 256` in benchmark and mirrored production `with_min_len` behavior.
- Added both new bench functions to `criterion_group!`.

Important finding:
- First run of naive Rayon `DatagramBatch` fold/reduce was pathological: Rayon created too many tiny `DatagramBatch` arenas, causing huge times (e.g. 512 ~2.12 ms, 1024 ~3.99 ms, 2048 ~8.14 ms).
- Fixed production large-fanout path in `src/voice/routing.rs` by adding `RAYON_FANOUT_BATCH_MIN_LEN = 256` and `.with_min_len(RAYON_FANOUT_BATCH_MIN_LEN)` before `.fold(DatagramBatch::new, ...)`.
- Rerun showed sane Rayon results and large-fanout win again.

Current short-run estimates after fix:
- seq datagram batch: 64 ~21.7 us (339 ns/rcp), 256 ~70.9 us (277 ns/rcp), 512 ~165.6 us (324 ns/rcp), 1024 ~385.4 us (376 ns/rcp), 2048 ~807.0 us (394 ns/rcp).
- rayon datagram batch: 64 ~22.8 us (356 ns/rcp), 256 ~84.1 us (328 ns/rcp), 512 ~151.5 us (296 ns/rcp), 1024 ~202.3 us (198 ns/rcp), 2048 ~320.4 us (156 ns/rcp).

Validation:
- `cargo fmt -- src\voice\routing.rs benches\voice_hotpath.rs`
- `cargo check --benches` passed with known Windows incremental finalization warning.
- `cargo bench --bench voice_hotpath -- "datagram_batch" --noplot --sample-size 10 --measurement-time 1 --warm-up-time 1` ran successfully.
- `cargo test voice_udp` passed with known Windows incremental finalization warning.

Updated `voice_remaining_perf_wins.md` to mark the production-shape benchmark as implemented and include results.