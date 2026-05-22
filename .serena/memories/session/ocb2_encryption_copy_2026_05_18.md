# OCB2 Encryption Copy Reduction (2026-05-18)

User asked whether memory copy can be decreased for OCB2 encryption.

Finding:
- Previous OCB2 encryption full-block path used a separate stack `bulk` buffer:
  1. Phase 3 wrote `data ^ delta` into `bulk`.
  2. Phase 4 AES-encrypted `bulk` in place.
  3. Phase 5 wrote `bulk ^ delta` into `dest_ciphertext`.
- That meant every full-block byte was written to scratch and then copied/transformed into destination.

Implementation:
- Removed separate encryption `bulk` scratch from both `Ocb2::encrypt_with_plaintext_checksum` and `CryptoMode for Ocb2::encrypt`.
- Added `stage_full_blocks(dest_ciphertext, data, delta_chain, n_main) -> &mut [u8]`:
  - writes Phase 3 staging bytes directly into `dest_ciphertext[..n_main * 16]`;
  - returns that prefix for AES in-place encryption;
  - Phase 5 now XORs `delta` into `dest_ciphertext` in place.
- This removes the 1 KiB stack scratch from encryption and eliminates the post-AES scratch-to-destination full-block copy. Decrypt is unchanged.

Validation:
- `cargo test client::crypt::ocb2 -- --nocapture --test-threads=1` passed.
- `cargo check` passed with existing Windows incremental-finalization warning (`Access is denied`).
- `cargo test voice_udp -- --nocapture --test-threads=1` passed.
- `cargo fmt` ran.

Notes:
- The previous `MaybeUninit` helper from `session/ocb2_encryption_scratch_2026_05_18` was superseded by destination-backed staging, so there is no unsafe helper left in OCB2 encryption.
- The fanout hot path uses `CryptState::encrypt_with_precomputed_checksum`, so it benefits from the in-place destination staging.
