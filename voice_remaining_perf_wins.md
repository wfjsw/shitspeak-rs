# Voice Path Remaining Performance Wins

Date: 2026-05-18

This report summarizes the remaining meaningful performance work after the recent voice-path allocation and copy reductions:

- UDP receive now uses a reusable `BytesMut` and `recv_buf_from`.
- UDP fanout now writes encrypted datagrams into `DatagramBatch` chunk arenas.
- OCB2 encryption stages full blocks directly into the destination buffer.
- Fanout uses precomputed plaintext checksums.
- Rayon fanout threshold was raised to 512 after profiling showed 256-recipient fanout is still faster sequentially.

## Current Baseline

Measured with targeted release Criterion and ignored crypto profilers on the current tree.

| Stage | Mean |
| --- | ---: |
| Legacy encode, 170 B payload | ~140 ns |
| Legacy decode, UDP-sync path, 170 B payload | ~151 ns |
| Legacy decode, general path, 170 B payload | ~295 ns |
| OCB2/CryptState encrypt, 170 B payload | ~326 ns |
| OCB2/CryptState decrypt, 170 B payload | ~832 ns |

Cached-encode fanout, 170 B Opus payload:

| Recipients | Total | Per recipient |
| ---: | ---: | ---: |
| 64 | ~29.3 us | ~458 ns |
| 256 | ~110.1 us | ~430 ns |
| 512 | ~223.8 us | ~437 ns |
| 1024 | ~538.0 us | ~525 ns |
| 2048 | ~1.05 ms | ~510 ns |

Dispatch profile:

| Recipients | Inline sequential | Spawn + Rayon | Current conclusion |
| ---: | ---: | ---: | --- |
| 256 | ~117.5 us | ~177.8 us | Sequential wins |
| 512 | ~239.8 us | ~215.2 us | Rayon starts winning |
| 1024 | ~477.4 us | ~310.0 us | Rayon wins |
| 2048 | ~984.1 us | ~514.4 us | Rayon wins |

The core scaling cost is still per-recipient encryption in `flush_voice_batch`. Encoding is cached, packet allocation has been reduced, and OCB2 checksum precomputation already removes a large fanout tax. Further wins are narrower.

## Ranked Remaining Wins

### 1. Maintain Production-Shape `DatagramBatch` Fanout Benchmarks

Status: implemented, high value, low risk.

The previous Criterion fanout benches modeled older output-buffer patterns:

- `fanout/seq_cached_encode_encrypt` allocates `BytesMut` per recipient.
- `fanout/seq_cached_vec_encode_encrypt` allocates `Vec<u8>` and converts to `Bytes` per recipient.
- Production now uses `DatagramBatch`, which allocates chunk arenas and stores metadata.

The benchmark suite now includes production-shape benches that mirror:

- sequential `DatagramBatch::with_capacity(n)` plus `try_push_zeroed`;
- Rayon `.with_min_len(256).fold(DatagramBatch::new, ...)` plus `.reduce(...)`.

Current short-run estimates:

| Recipients | Sequential `DatagramBatch` | Rayon `DatagramBatch` |
| ---: | ---: | ---: |
| 64 | ~21.7 us, ~339 ns/recipient | ~22.8 us, ~356 ns/recipient |
| 256 | ~70.9 us, ~277 ns/recipient | ~84.1 us, ~328 ns/recipient |
| 512 | ~165.6 us, ~324 ns/recipient | ~151.5 us, ~296 ns/recipient |
| 1024 | ~385.4 us, ~376 ns/recipient | ~202.3 us, ~198 ns/recipient |
| 2048 | ~807.0 us, ~394 ns/recipient | ~320.4 us, ~156 ns/recipient |

Expected payoff:

- Prevents optimizing the wrong buffer pattern.
- Gives a baseline for whether zero-fill removal, metadata layout changes, or Rayon partition tuning are worth touching.
- Already exposed and fixed a large-fanout issue: naive Rayon `fold(DatagramBatch::new, ...)` created too many tiny batch arenas. The production path now uses `with_min_len(256)` before the fold.

Benchmark names:

- `fanout/seq_datagram_batch_encode_encrypt`
- `fanout/rayon_datagram_batch_encode_encrypt`

Decision criteria:

- If `DatagramBatch` is already within ~5% of the lower-level crypto-only fanout cost, stop chasing packet-buffer changes.
- If it is materially slower, inspect zero-fill, metadata, and chunk append costs.
- Optional future addition: mixed UDP/TCP fallback ratios, for example 0%, 10%, and 50% TCP fallback.

### 2. Reduce UDP Receive Decrypt Allocation and Zero-Fill

Status: likely small to medium win on ingress-heavy workloads, medium implementation risk.

Current code points:

- `Server::spawn_udp_process` creates a fresh `BytesMut` for address-match decrypt.
- IP fallback creates another fresh `BytesMut` per candidate.
- `CryptState::decrypt` takes `&mut BytesMut` and calls `dest.resize(plain_len, 0)`.

This creates allocation and zero-fill pressure on the receive path. It is not the scaling hot point for normal fanout because decrypt happens once per inbound packet, while encrypt happens once per outbound recipient. But if the server has high inbound packet rate, many NAT rebinding attempts, or many IP fallback candidates, this becomes meaningful.

Possible implementation:

- Add a lower-level decrypt API that accepts a pre-sized mutable slice:
  - `CryptState::decrypt_into(&mut self, dest: &mut [u8], data: &[u8]) -> Result<usize, CryptError>`
  - Keep the current `decrypt(&mut BytesMut, ...)` wrapper for callers that want owned `BytesMut`.
- In `spawn_udp_process`, allocate one reusable `[u8; MTU]`-sized buffer or one `BytesMut::with_capacity(MTU)` per loop iteration.
- For address-match decrypt, decrypt into the reusable buffer and decode from the slice immediately after a match.
- For IP fallback, reuse the same scratch for each candidate.

Expected payoff:

- Removes per-packet plaintext allocation on the fast address-match path.
- Reduces wasted allocation during failed fallback decrypt attempts.
- Does not reduce per-recipient fanout CPU.

Risks:

- OCB2 decrypt currently writes plaintext before tag verification. Any reused buffer must be treated as untrusted until decrypt succeeds.
- The current logic stores `decrypted_from_match: Option<BytesMut>` until after client matching. A slice-based path would need to restructure matching and decode so the scratch buffer lifetime stays local.
- Be careful not to hold a `crypt_state` lock while awaiting anything.

Measurement:

- Add a microbench for address-match UDP process decrypt+decode with reusable buffer.
- Add a fallback bench with candidate counts 1, 4, 16.
- Compare allocation counts under burst receive.

### 3. Investigate OCB2 Decrypt Copy Reduction

Status: possible CPU win for ingress, medium to high risk.

Encryption has already been changed to stage full blocks directly into the destination. Decrypt still uses a stack `bulk` scratch buffer for full ciphertext blocks:

1. ciphertext XOR delta into `bulk`;
2. AES decrypt `bulk` in place;
3. XOR delta from `bulk` into destination while computing checksum.

This mirrors the old encryption structure. It may be possible to stage ciphertext directly into `dest`, decrypt the full-block prefix in place, and then post-XOR/checksum in place, similar to the encryption-side improvement.

Expected payoff:

- Potentially reduces stack scratch use and full-block copy work in decrypt.
- The decrypt baseline is ~832 ns for a 170 B packet, so there is room if ingress decrypt is a bottleneck.

Risks:

- Decrypt authentication fails after plaintext bytes have already been staged. The existing code also writes before tag verification, but any refactor must preserve exact behavior and avoid exposing unauthenticated data to callers.
- OCB2 decrypt has IV/history logic in `CryptState::decrypt`; correctness tests must cover late/lost/replay behavior, not only OCB2 known-answer vectors.
- This does not help high-fanout outbound scaling.

Measurement:

- Add OCB2 decrypt phase decomposition matching the existing encrypt phase profiler.
- Benchmark `CryptState::decrypt` before and after for payload sizes 24, 80, 170, 512, 1000.
- Run known-answer tests plus UDP voice roundtrip tests.

### 4. Avoid Zero-Filling Send Batch Destination Slices

Status: possible small fanout win, medium risk.

`DatagramBatch::try_push_zeroed` reserves space by resizing the active chunk with zeroes before encryption writes into the slice.

For successful OCB2 encryption, the destination should be fully written:

- header/IV byte;
- tag bytes;
- all ciphertext bytes, including the final partial block.

If that write coverage is proven and enforced, the batch could reserve uninitialized capacity and let encryption initialize the bytes directly. That would remove zero-fill of every outgoing encrypted datagram.

Expected payoff:

- Saves a memory clear of `entry.bytes.len() + overhead` per UDP recipient.
- Impact grows with recipient count and payload size.

Risks:

- Rust safe APIs do not expose uninitialized `&mut [u8]` without care.
- A bug here can send uninitialized memory over UDP.
- The rollback path on encryption failure must remain correct.

Safer variant:

- Add a narrow internal API on `DatagramBatch` that uses `spare_capacity_mut` and a writer closure returning the exact initialized length.
- Only commit `set_len` after the writer succeeds.
- Keep `try_push_zeroed` as the default safe API.
- Add debug assertions/tests that encryption writes the exact expected length for all supported packet sizes.

Decision criteria:

- Only pursue after a production-shape `DatagramBatch` benchmark shows zero-fill is visible.
- If the gain is under ~3-5%, keep the zeroed path.

### 5. Tune Large-Fanout Work Partitioning

Status: possible small win for very large fanout, medium risk.

The current large path uses Rayon `fold` to create one `DatagramBatch` per worker and then `reduce` to append chunks and metadata. This avoids locking, but it can produce many chunks and does a metadata adjustment during append.

Potential options:

- Pre-partition `udp_items` into fixed chunks and process each chunk sequentially within Rayon.
- Size per-worker `DatagramBatch` with the chunk length instead of `DatagramBatch::new`.
- Avoid repeated cache lookup by resolving each recipient to a small cache index before entering Rayon.

Expected payoff:

- Most visible at 1024+ recipients.
- Could reduce chunk churn and lookup overhead.

Risks:

- More complicated code for a path already dominated by crypto.
- The per-recipient cache lookup is over at most four entries, so replacing it with cloned `Encoded` values may be worse.

Measurement:

- Use 512, 1024, 2048, and 4096 recipient benches.
- Measure both throughput and allocation count.
- Keep the current simple Rayon fold unless the win is clear.

### 6. Profile Live UDP Send Syscall Cost on Linux

Status: operational measurement, potentially high impact depending on deployment.

CPU microbenches do not include real kernel/network send cost. Production send behavior differs by OS:

- Linux uses `sendmmsg`.
- Non-Linux loops over `send_to`.

On Windows, live high-fanout may be syscall dominated even after CPU-side allocation reductions. On Linux, `sendmmsg` should help, but it still needs live measurement under realistic fanout and packet rate.

Expected payoff:

- If send syscall time dominates, CPU-side crypto optimizations will have limited user-visible effect.
- Confirms whether Linux batching is sufficient or whether send task architecture needs attention.

Measurement:

- Run a Linux benchmark or load test with 64, 256, 512, 1024 recipients.
- Capture CPU samples and syscall counts.
- Compare `sendmmsg` batch size, packet drops, and queue latency.

Potential follow-up:

- Tune `DATAGRAMS_PER_CHUNK` and Linux `sendmmsg` batch grouping together.
- Consider send queue backpressure metrics before changing architecture.

## Low-Value or Not Recommended Right Now

### Removing `Box<dyn CryptoMode>` from `CryptState`

The ignored profiler showed a lean-layout fanout only saved about 2%. This is not worth a broad refactor unless the crypto abstraction is being redesigned for other reasons.

### Further Encode Optimization

Encoding is around ~140 ns and is cached per `(PacketFormat, AudioContext)`. It is not a current hot point.

### Passing Borrowed Packets Across Async Channels

Borrowed packet references across `tokio::mpsc` task boundaries are not a good fit. The receive path must transfer ownership safely between the UDP drain and process tasks. The current `Bytes` handoff is appropriate. If more receive-side allocation reduction is needed, focus on decrypt scratch reuse after the channel boundary.

### Avoiding Per-Recipient Encryption

This is the real scaling cost, but it is not removable under the current security model. Each recipient has separate crypt state and IV. Sharing ciphertext across recipients would require a protocol/security change.

## Recommended Order

1. Add production-shape `DatagramBatch` Criterion benches and allocation counters.
2. If batch zero-fill is visible, prototype a safe commit-after-write batch API.
3. Add a reusable-buffer decrypt API and benchmark the UDP address-match path.
4. Profile OCB2 decrypt phases; only then consider destination-backed decrypt staging.
5. Run Linux live send profiling to decide whether syscall cost now dominates.
6. Leave `CryptState` layout and encode logic alone unless future profiles change.

## Verification Checklist for Any Follow-Up Patch

Run at minimum:

```powershell
cargo check
cargo test voice_udp
cargo test client::crypt::ocb2
cargo test --release --lib client::crypt::profile_test -- --ignored --nocapture --test-threads=1
```

For benchmark-impacting changes:

```powershell
cargo bench --bench voice_hotpath -- "crypt/" --noplot --sample-size 10 --measurement-time 1 --warm-up-time 1
cargo bench --bench voice_hotpath -- "dispatch/single_call" --noplot --sample-size 10 --measurement-time 1 --warm-up-time 1
cargo bench --bench voice_e2e -- "voice_e2e/udp_roundtrip" --noplot --sample-size 10 --measurement-time 1 --warm-up-time 1
```

Expect the known Windows incremental compilation finalization warning in this workspace:

```text
error finalizing incremental compilation session directory ... Access is denied. (os error 5)
```

That warning has not indicated test failure in the profiling runs.
