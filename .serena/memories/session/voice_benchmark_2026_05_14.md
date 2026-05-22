# Voice Benchmark Findings (2026-05-14)

Context: `D:\shitspeak-rs`, rustc/cargo 1.95.0 on Windows MSVC. Benchmarks were run with short targeted Criterion passes: `cargo bench --bench voice_hotpath -- <filter> --noplot --sample-size 10 --measurement-time 1 --warm-up-time 1` after full `voice_hotpath` suite timed out at 20 min.

## Functional Coverage Check
Command: `cargo test voice -- --nocapture`, then isolated reruns of the 3 failures.
- 73/76 voice-filtered tests passed.
- Deterministic failures:
  - `integration_tests::scenarios::voice::voice_tcp_protobuf_round_trips`
  - `integration_tests::scenarios::voice::voice_udp_protobuf_round_trips_and_decrypts`
  - `integration_tests::scenarios::voice::voice_udp_format_matches_recipient_proto_version`
- Failure: 1.5/protobuf-capable recipient receives `PacketFormat::Legacy` instead of `PacketFormat::Protobuf`.
- Root condition found in `src/voice/routing.rs::client_packet_format`: protobuf is only used if `APP_PROTO_VER >= PROTOBUF_INTRODUCED_VERSION && client.uses_protobuf()`.
- Current `src/constants.rs::APP_PROTO_VER` is 1.4.0, so outbound protobuf is disabled in this build even for clients that declare 1.5.

## Hot-Path Criterion Results
Extracted from `target/criterion/*/new/estimates.json`, mean/stddev in ns.

Typical 170-byte Opus frame:
- `encode_legacy/170`: mean 128 ns, stddev 10 ns.
- `decode_legacy/170`: mean 144 ns, stddev 10 ns.
- `decode_legacy/udp_sync/170`: mean 109 ns, stddev 8 ns.
- `crypt_encrypt/170`: mean 384 ns, stddev 28 ns.
- `crypt_decrypt/170`: mean 817 ns, stddev 47 ns.

Fanout encode+encrypt:
- `fanout_seq_encode_encrypt/64`: 35,619 ns mean, stddev 4,263 ns.
- `fanout_seq_cached_vec_encode_encrypt/64`: 29,465 ns mean, stddev 1,573 ns.
- `fanout_seq_encode_encrypt/256`: 167,584 ns mean, stddev 16,402 ns.
- `fanout_seq_cached_vec_encode_encrypt/256`: 120,507 ns mean, stddev 7,900 ns.
- `fanout_seq_encode_encrypt/1024`: 571,943 ns mean, stddev 42,730 ns.
- `fanout_seq_cached_vec_encode_encrypt/1024`: 464,816 ns mean, stddev 4,630 ns.

Dispatch strategies:
- `dispatch_single_call/inline_seq/64`: 46,314 ns mean, stddev 2,703 ns.
- `dispatch_single_call/inline_rayon/64`: 101,752 ns mean, stddev 2,469 ns.
- `dispatch_single_call/inline_seq/512`: 231,806 ns mean, stddev 2,817 ns.
- `dispatch_single_call/inline_rayon/512`: 214,988 ns mean, stddev 25,148 ns.
- `dispatch_single_call/inline_seq/2048`: 1,023,240 ns mean, stddev 44,205 ns.
- `dispatch_single_call/inline_rayon/2048`: 599,294 ns mean, stddev 105,833 ns.

Multistream serial, `MULTISTREAM_M = 16` recipients/stream:
- `multistream_serial/inline_seq/1`: 7,085 ns mean, stddev 265 ns.
- `multistream_serial/inline_seq/8`: 93,361 ns mean, stddev 4,683 ns.

## Interpretation
- Codec framing is sub-microsecond and not the delay bottleneck for normal packet sizes.
- Crypto dominates single-recipient local CPU cost; decrypt is ~2x encrypt for 170-byte frames.
- Recipient fanout dominates under load and is the main CPU-side delay/jitter/bandwidth multiplier.
- Cached Vec fanout is consistently better than re-encoding per recipient and has much lower stddev at high recipient counts.
- Rayon/parallel dispatch helps only at very large recipient counts in current data; it is worse at small/medium counts and has higher jitter at 2048 recipients.
- Current benches are hot-path microbenchmarks, not true network end-to-end delay/jitter/bandwidth. The test harness is `#[cfg(test)]` and not reusable from benches without a cleanup.

## Optimization Plan
1. Fix or explicitly gate protobuf voice behavior before benchmarking protobuf E2E: either bump `APP_PROTO_VER` to 1.5 if intended, or update tests to expect legacy while server advertises 1.4.
2. Add an end-to-end voice benchmark harness reusing/refactoring test server/client setup under a bench/test-support feature. Measure TCP UDPTunnel, UDP legacy, UDP protobuf, mixed recipient proto versions, same channel, linked channel, whisper/shout, loopback, muted/no-route, and S2S routes.
3. For each E2E scenario, collect p50/p95/p99 delay, inter-arrival jitter, bytes in/out per packet, server CPU, recipient count, packet drops/timeouts. Use monotonic timestamps at send and receive; include payload sizes 24/80/170/512/1000 bytes and recipient counts 1/4/16/64/256/1024/2048 where practical.
4. Optimize fanout first: make cached encoded payload reuse the production path if not already, use preallocated Vec/BytesMut buffers, avoid per-recipient re-encode, and keep sequential path for small/medium groups.
5. Apply parallelism only above a measured threshold (current crossover appears somewhere above hundreds of recipients; 2048 benefits but with higher jitter). Make the threshold configurable or benchmark-derived.
6. Optimize network send path after fanout CPU: validate UDP batching/sendmmsg on Linux, record batch sizes and syscall counts, avoid spawning per-packet tasks, and keep TCP UDPTunnel fast-path ordered.
7. Add CI perf guardrails for representative hot-path groups and a shorter E2E smoke perf run, storing baseline JSON and checking regressions on mean + p99/jitter, not only Criterion mean.
