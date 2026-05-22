# Voice Route Arena Batch Fix (2026-05-18)

Context: user reported allocator pressure in voice route: up to ~1024 * 1024 allocations of ~1000-byte buffers every 10 ms under extreme fanout. Root source was `src/voice/routing.rs::flush_voice_batch` allocating `BytesMut::zeroed(...).freeze()` once per UDP recipient after encode-cache lookup.

Implementation:
- Added `src/voice/udp_batch.rs::DatagramBatch`, an owned chunked arena for encrypted UDP datagrams.
- `DatagramBatch` stores `Vec<Vec<u8>>` chunks plus private `QueuedDatagram { addr, chunk, offset, len }` metadata.
- Chunk size is `MTU * 64` (`DATAGRAMS_PER_CHUNK = 64`), matching the Linux sendmmsg chunk size and keeping allocation count around one large chunk per 64 max-MTU datagrams instead of one allocation per recipient.
- `try_push_zeroed(addr, len, write)` reserves zeroed space and lets the encrypt path write directly into the batch arena. On encryption failure, it rolls back the just-reserved range/chunk.
- `flush_batch`, fallback `send_each`, and Linux `sendmmsg_linux` now borrow slices from `DatagramBatch` during flush, so no per-datagram `Bytes` allocation is needed.
- `flush_voice_batch` sequential path now uses one `DatagramBatch::with_capacity(targets.len())` and encrypts directly into it.
- Large Rayon path uses `.fold(DatagramBatch::new, ...)` and `.reduce(...)` to build per-worker batch arenas without locking, then appends chunks/metadata.
- Previous UDP drain receive-buffer copy reduction remains in `src/server.rs`: `BytesMut::with_capacity(MTU)`, `recv_buf_from`, and `split().freeze()` into UDP processing channel.

Validation:
- `cargo fmt`
- `cargo check` passed, with existing Windows incremental compilation finalization warning (`Access is denied`).
- `cargo test voice_udp -- --nocapture --test-threads=1` passed (5 tests).
- `cargo test voice -- --nocapture --test-threads=1` passed (78 lib tests + 59 main tests).

Notes:
- This reduces per-fanout encrypted UDP payload allocations from O(recipients) to O(recipients / 64) chunks plus metadata Vec growth. It still zero-fills destination bytes because OCB2 writes into pre-sized output slices; avoid changing that without checking crypto write coverage.
- The batch data only lives until `flush_batch` returns, so borrowed slices are safe internally; channels still carry owned data where async task boundaries require ownership.
- Dirty worktree had many pre-existing `.serena` and plan files; do not revert unrelated files.