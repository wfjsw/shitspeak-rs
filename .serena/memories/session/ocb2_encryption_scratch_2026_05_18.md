# OCB2 Encryption Scratch Reduction (2026-05-18)

User asked whether allocation can be decreased for OCB2 encryption after voice route allocator pressure work.

Finding:
- `src/client/crypt/ocb2.rs` encryption paths did not allocate heap buffers inside OCB2. The repeated memory work was fixed-size stack scratch:
  - `delta_chain = [[0u8; 16]; MAX_BLOCKS + 2]`
  - `bulk = [0u8; MAX_PLAINTEXT_BYTES]`
- The fanout hot path calls `CryptState::encrypt_with_precomputed_checksum`, which delegates to `Ocb2::encrypt_with_plaintext_checksum`.
- `bulk` only needs the prefix `n_main * 16`; zero-initializing all 1024 bytes per recipient was unnecessary.

Implementation:
- Added helper `init_bulk_buffer` using `[MaybeUninit<u8>; MAX_PLAINTEXT_BYTES]` and writing exactly the active prefix before exposing it as `&mut [u8]` for AES.
- Updated both `Ocb2::encrypt_with_plaintext_checksum` (fanout path) and `CryptoMode for Ocb2::encrypt` to use the helper.
- Left decrypt unchanged because user asked about encryption and route fanout pressure is encryption-side. Same scratch pattern exists in decrypt if future work targets inbound CPU/memory work.

Effect:
- Does not reduce heap allocation count because OCB2 encryption already had no heap allocations.
- Reduces per-encryption stack zero-fill/memory initialization by avoiding full 1 KiB `bulk` zeroing and initializing only `n_main * 16` bytes.
- Correctness depends on AES only reading the returned initialized prefix; helper documents the unsafe boundary.

Validation:
- `cargo test client::crypt::ocb2 -- --nocapture --test-threads=1` passed.
- `cargo check` passed with existing Windows incremental-finalization warning (`Access is denied`).
- `cargo test voice_udp -- --nocapture --test-threads=1` passed.
- `cargo fmt` ran.

Related earlier work in this session:
- `session/voice_route_arena_batch_2026_05_18` reduced route fanout encrypted UDP payload heap allocations with `DatagramBatch`.
