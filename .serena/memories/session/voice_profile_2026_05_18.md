# Voice Path Profiling - 2026-05-18

User asked for step-by-step profiling of the voice path and hot points, after allocation/copy reduction work in UDP batching and OCB2 encryption.

Relevant current code:
- `src/server.rs`: UDP receive loop uses `BytesMut::with_capacity(MTU)` / `recv_buf_from`, then freezes received packet; decrypt still allocates a `BytesMut` for plaintext in the receive path.
- `src/voice/routing.rs`: `route_voice` resolves recipients and calls `flush_voice_batch`. `flush_voice_batch` caches plaintext encoding by `(PacketFormat, AudioContext)`, uses `DatagramBatch`, and calls `CryptState::encrypt_with_precomputed_checksum` per UDP recipient. Large fanout uses `spawn_blocking` + Rayon fold/reduce.
- `src/voice/udp_batch.rs`: `DatagramBatch` stores chunked `Vec<u8>` arenas plus metadata, avoiding one encrypted `Bytes` allocation per recipient before send.
- `src/client/crypt/ocb2.rs`: OCB2 encryption stages full blocks directly into destination and uses the precomputed plaintext checksum API for fanout.

Commands run:
- `cargo bench --bench voice_hotpath -- "encode/legacy" --noplot --sample-size 10 --measurement-time 1 --warm-up-time 1`
- `cargo bench --bench voice_hotpath -- "decode/legacy" --noplot --sample-size 10 --measurement-time 1 --warm-up-time 1`
- `cargo bench --bench voice_hotpath -- "crypt/" --noplot --sample-size 10 --measurement-time 1 --warm-up-time 1`
- `cargo bench --bench voice_hotpath -- "dispatch/single_call" --noplot --sample-size 10 --measurement-time 1 --warm-up-time 1`
- `cargo test --release --lib client::crypt::profile_test -- --ignored --nocapture --test-threads=1`
- `cargo bench --bench voice_e2e -- "voice_e2e/udp_roundtrip" --noplot --sample-size 10 --measurement-time 1 --warm-up-time 1`

Current 170-byte microbench means:
- encode legacy: ~139.6 ns
- decode legacy: ~294.5 ns, `udp_sync`: ~151.0 ns
- OCB2/CryptState encrypt: ~326.2 ns
- OCB2/CryptState decrypt: ~832.0 ns

Current fanout means (cached encode + encryption, 170 B opus):
- `fanout_seq_cached_encode_encrypt`: 64 = 29.3 us (458 ns/rcp), 256 = 110.1 us (430 ns/rcp), 512 = 223.8 us (437 ns/rcp), 1024 = 538.0 us (525 ns/rcp), 2048 = 1.045 ms (510 ns/rcp).
- `fanout_seq_cached_vec_encode_encrypt`: 64 = 30.3 us (474 ns/rcp), 256 = 118.2 us (462 ns/rcp), 512 = 233.1 us (455 ns/rcp), 1024 = 462.1 us (451 ns/rcp), 2048 = 1.076 ms (525 ns/rcp). This bench still allocates a Vec/Bytes per recipient and does not exactly reflect the production `DatagramBatch` arena path.

Dispatch strategy means:
- 64 recipients: inline seq 28.4 us, inline Rayon 101.3 us, spawn seq 50.0 us, spawn Rayon 129.8 us.
- 256 recipients: inline seq 117.5 us, inline Rayon 173.0 us, spawn seq 144.8 us, spawn Rayon 177.8 us.
- 512 recipients: inline seq 239.8 us, inline Rayon 212.2 us, spawn seq 266.5 us, spawn Rayon 215.2 us.
- 1024 recipients: inline seq 477.4 us, inline Rayon 314.6 us, spawn seq 584.7 us, spawn Rayon 310.0 us.
- 2048 recipients: inline seq 984.1 us, inline Rayon 477.6 us, spawn seq 1.145 ms, spawn Rayon 514.4 us.

Ignored crypto profiler:
- Fanout normal encrypt median per-recipient settles around ~288-291 ns/recipient for 64-256 recipients.
- Lean-layout CryptState only saved ~2%; boxed crypto/BytesMut indirection is not the major current hot point.
- OCB2 phase medians for 175 B plaintext: gf128 chain ~52.9 ns, AES 10 blocks ~29.9 ns, post-XOR+checksum ~152.8 ns, checksum-only ~55.4 ns, full OCB2 encrypt ~315.5 ns, hot CryptState encrypt ~284.5 ns.
- Precomputed checksum fanout at n=256: baseline encrypt x256 ~72.3 us (282.4 ns/rcp), optimized precompute + encrypt x256 ~46.1 us (180.1 ns/rcp), measured savings ~36.2%.

E2E UDP roundtrip sanity run:
- `voice_e2e/udp_roundtrip/server_1_4_all_legacy`: ~105.7 us.
- `server_1_5_client_1_4_legacy`: ~113.6 us.
- `server_1_5_client_1_5_protobuf`: ~110.1 us.

Hot points / conclusions:
1. Main CPU hot point is per-recipient OCB2 encryption in fanout. Encode is already cached and cheap. Encryption is still unavoidable per recipient because each recipient has different `CryptState`/IV.
2. OCB2 internal hot phase is post-XOR/checksum in normal encrypt; fanout mitigates this with precomputed plaintext checksum, saving ~36% in the lower-level profiler.
3. Ingress decrypt is slower than encrypt (~832 ns vs ~326 ns for 170 B) but happens once per inbound packet, not per recipient, so it is not the scaling bottleneck unless inbound packet rate is extreme.
4. Rayon/spawn_blocking only helps at large fanout: seq is better up to ~256 recipients; Rayon crosses over at ~512 recipients and is strongly better by 1024+. Current threshold should be checked against `RAYON_FANOUT_THRESHOLD`.
5. UDP send syscall path was not fully profiled on Windows; Linux `sendmmsg` path should reduce syscall cost. On Windows fallback is per-packet `send_to`, so kernel/syscall time can dominate live high-fanout scenarios beyond CPU microbenchmarks.
6. Remaining allocation/copy opportunities: production send uses `DatagramBatch` arena already; receive decrypt still allocates plaintext `BytesMut`; Criterion fanout benches should be updated to include production `DatagramBatch` to measure current allocation profile precisely.