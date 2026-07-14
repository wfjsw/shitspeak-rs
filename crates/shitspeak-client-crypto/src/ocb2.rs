use aws_lc_rs::rand::SecureRandom;

use crate::{
    CryptoMode, aes_backend::Aes128, errors::CryptError, gf128::Gf128Ops, xor_backend::XorOps,
};

const BLOCK_SIZE: usize = 16;
/// Hard upper bound on plaintext we ever encrypt in one OCB2 call. The Mumble
/// UDP voice path caps wire packets at 1024 bytes (incl. tag overhead), so
/// the largest plaintext we'll see is comfortably below this.
const MAX_PLAINTEXT_BYTES: usize = 1024;
const MAX_BLOCKS: usize = MAX_PLAINTEXT_BYTES / BLOCK_SIZE; // 64

struct BatchPacketMeta {
    cleartext_len: usize,
    last_pos: usize,
    remaining: usize,
    n_main: usize,
    bulk_block_offset: usize,
}

fn stage_full_blocks<'a>(
    dest_ciphertext: &'a mut [u8],
    data: &[u8],
    delta_chain: &[[u8; BLOCK_SIZE]],
    n_main: usize,
    xor: XorOps,
) -> &'a mut [u8] {
    let bulk_len = n_main * BLOCK_SIZE;
    let bulk = &mut dest_ciphertext[..bulk_len];
    xor.xor_chain_into(bulk, &data[..bulk_len], &delta_chain[1..n_main + 1]);
    bulk
}

pub struct Ocb2 {
    key: [u8; BLOCK_SIZE],
    aes: Aes128,
    gf128: Gf128Ops,
    xor: XorOps,
}

impl Ocb2 {
    pub const KEY_SIZE: usize = BLOCK_SIZE;
    pub const NONCE_SIZE: usize = BLOCK_SIZE;
    pub const TAG_SIZE: usize = 3;

    pub fn from_key(key: [u8; BLOCK_SIZE]) -> Result<Self, CryptError> {
        Ok(Ocb2 {
            key,
            aes: Aes128::new(&key)?,
            gf128: Gf128Ops::new(),
            xor: XorOps::new(),
        })
    }

    #[cfg(test)]
    fn from_key_with_backend(
        key: [u8; BLOCK_SIZE],
        backend: crate::xor_backend::BackendKind,
    ) -> Result<Self, CryptError> {
        Ok(Ocb2 {
            key,
            aes: Aes128::new(&key)?,
            gf128: Gf128Ops::new(),
            xor: XorOps::for_test(backend),
        })
    }

    pub fn new(rng: &dyn SecureRandom) -> Result<Self, CryptError> {
        let mut key = [0u8; BLOCK_SIZE];
        rng.fill(&mut key)?;
        Ocb2::from_key(key)
    }

    /// Compute the plaintext-derived component of the OCB2 authentication
    /// checksum. The result depends only on the plaintext; in a fan-out
    /// broadcast where the same plaintext is encrypted to many recipients
    /// it can be computed once and passed to `encrypt_with_plaintext_checksum`
    /// to skip the per-recipient XOR-fold (Phase 5's hot inner loop).
    ///
    /// Layout: full-block XOR-fold over `plaintext[0..n_main*16]`, then for
    /// the partial-block tail of length `remaining`, the bytes
    /// `plaintext[last_pos..last_pos+remaining]` are XOR'd into `[0..remaining]`.
    /// Bytes `[remaining..16]` are left as the running fold value (which is
    /// where the per-recipient pad bytes get folded in during encrypt).
    pub fn compute_plaintext_checksum(plaintext: &[u8]) -> [u8; BLOCK_SIZE] {
        let n_main = plaintext.len().saturating_sub(1) / BLOCK_SIZE;
        let last_pos = n_main * BLOCK_SIZE;
        let remaining = plaintext.len() - last_pos;

        let mut checksum = [0u8; BLOCK_SIZE];
        XorOps::new().xor_fold(&mut checksum, &plaintext[..last_pos]);
        for j in 0..remaining {
            checksum[j] ^= plaintext[last_pos + j];
        }
        checksum
    }

    /// Variant of `encrypt` that takes a precomputed
    /// `compute_plaintext_checksum(data)` and skips the per-block plaintext
    /// XOR-fold inside Phase 5. The output ciphertext+tag is byte-identical
    /// to `<Self as CryptoMode>::encrypt(...)`. Intended for fan-out: compute
    /// the checksum once across all recipients sharing the same plaintext.
    ///
    /// Measured savings vs `encrypt` at n=256 fan-out, 175 B plaintext on
    /// Ryzen 7 5800H: **300.8 → 201.2 ns/recipient (−33%)**. Two thirds of
    /// the win comes from *unfusing* Phase 5 (post-XOR alone auto-vectorizes
    /// where the fused form does not — see the "DO NOT FUSE" warning at the
    /// Phase 5 loop below); the rest from skipping the fold itself. Reproduce
    /// with `cargo test --release --lib client::crypt::profile_test::profile_shared_checksum_savings -- --ignored --nocapture --test-threads=1`.
    pub fn encrypt_with_plaintext_checksum(
        &self,
        dest: &mut [u8],
        data: &[u8],
        nonce: &[u8],
        plaintext_checksum: &[u8; BLOCK_SIZE],
    ) -> Result<(), CryptError> {
        let cleartext_len = data.len();

        if nonce.len() != self.nonce_size() {
            return Err(CryptError::InvalidNonceSize);
        }
        if dest.len() < cleartext_len + self.overhead() {
            return Err(CryptError::DestinationBufferTooSmall);
        }
        if cleartext_len > MAX_PLAINTEXT_BYTES {
            return Err(CryptError::DestinationBufferTooSmall);
        }

        // Phases 1-4 are identical to `encrypt`. The precomputed checksum
        // saves Phase 5's per-block plaintext XOR-fold; Phase 5 below is
        // post-XOR only (no checksum update), and Phase 6 folds in the
        // per-recipient `pad[remaining..]` to reconstruct the final value.

        let mut delta_chain = [[0u8; BLOCK_SIZE]; MAX_BLOCKS + 2];
        delta_chain[0].copy_from_slice(nonce);
        self.aes.encrypt_blocks(&mut delta_chain[0])?;

        let last_pos = cleartext_len.saturating_sub(1) / BLOCK_SIZE * BLOCK_SIZE;
        let remaining = cleartext_len - last_pos;
        let n_main = last_pos / BLOCK_SIZE;

        self.gf128.fill_chain(&mut delta_chain, n_main + 1);

        let tag_size = self.overhead();
        let dest_ciphertext = &mut dest[tag_size..];

        let bulk = stage_full_blocks(dest_ciphertext, data, &delta_chain, n_main, self.xor);

        if !bulk.is_empty() {
            self.aes.encrypt_blocks(bulk)?;
        }

        // ── Phase 5 (post-XOR only). DO NOT FUSE A CHECKSUM XOR INTO THIS
        // LOOP. The plaintext fold is already in `plaintext_checksum`.
        //
        // The "natural" fused form (also writing `checksum[j] ^= data[..]`
        // inside this body, as `encrypt` does) interleaves three input
        // streams (`bulk`, `delta_chain`, `data`) and two output streams
        // (`dest_ciphertext`, `checksum`) per iteration, which defeats LLVM
        // auto-vectorization. The post-XOR alone vectorizes to AVX2 — phase
        // profile measures **fused 149.8 ns vs unfused 18.2 ns** for these
        // 10 blocks (`profile_test::profile_ocb2_phases`). Fusing back
        // would erase ~2/3 of this method's win over `encrypt`.
        //
        // If you want fewer loops, fuse Phase 3 with this one (both are
        // pure delta-XOR with simple access patterns) — but never the
        // checksum fold.
        self.xor.xor_chain_in_place(
            &mut dest_ciphertext[..n_main * BLOCK_SIZE],
            &delta_chain[1..n_main + 1],
        );

        // ── Phase 6: pad encrypt — same as `encrypt`.
        let final_delta = delta_chain[n_main + 1];
        let mut pad = [0u8; BLOCK_SIZE];
        let num_bits = (remaining * 8) as u16;
        pad[BLOCK_SIZE - 2] = ((num_bits >> 8) & 0xff) as u8;
        pad[BLOCK_SIZE - 1] = (num_bits & 0xff) as u8;
        for j in 0..BLOCK_SIZE {
            pad[j] ^= final_delta[j];
        }
        self.aes.encrypt_blocks(&mut pad)?;

        // Reconstruct the production checksum from the precomputed plaintext
        // fold. Derivation (see `encrypt` for the reference path):
        //
        //   production_checksum
        //     = (XOR_{i in 0..n_main} data[i*16..(i+1)*16])  // full blocks
        //       ^ tmp                                          // partial-block tail
        //   tmp[j] = data[last_pos+j]   for j in 0..remaining
        //   tmp[j] = pad[j]             for j in remaining..16
        //
        //   precomputed
        //     = (XOR_{i in 0..n_main} data[i*16..(i+1)*16])
        //       ^ data[last_pos..last_pos+remaining] zero-padded into [0..remaining]
        //
        // Subtracting (XOR is self-inverse): production_checksum ^ precomputed
        // = pad[remaining..16] in the upper bytes only. So:
        let mut checksum = *plaintext_checksum;
        for j in remaining..BLOCK_SIZE {
            checksum[j] ^= pad[j];
        }
        // Invariant verified by `precomputed_checksum_matches_encrypt_lengths`
        // across the empty / partial / exact-multiple / large-plaintext cases.

        // Partial-block ciphertext output. `tmp` is constructed identically
        // to `encrypt` but only consumed for the ciphertext write — its
        // contribution to the checksum is already accounted for above.
        let mut tmp = [0u8; BLOCK_SIZE];
        if remaining > 0 {
            tmp[..remaining].copy_from_slice(&data[last_pos..last_pos + remaining]);
        }
        tmp[remaining..].copy_from_slice(&pad[remaining..]);
        for j in 0..remaining {
            dest_ciphertext[last_pos + j] = pad[j] ^ tmp[j];
        }

        // ── Phase 7: tag — same as `encrypt`.
        let mut tag_buf = final_delta;
        self.gf128.triple(&mut tag_buf);
        for j in 0..BLOCK_SIZE {
            tag_buf[j] ^= checksum[j];
        }
        self.aes.encrypt_blocks(&mut tag_buf)?;

        dest[..tag_size].copy_from_slice(&tag_buf[..tag_size]);

        Ok(())
    }

    /// Experimental short-sequence encrypt used by the voice micro-batch
    /// benchmark. It keeps OCB2 semantics identical to
    /// `encrypt_with_plaintext_checksum`, but batches the independent AES
    /// stages across packets in the sequence:
    ///
    /// - all `E(nonce)` blocks;
    /// - all full-block ciphertext ECB work;
    /// - all partial-block pads;
    /// - all final tags.
    ///
    /// This models the crypto-side change that micro-buffering could unlock:
    /// a recipient's consecutive frames are still encrypted in order, but the
    /// AES backend sees wider independent work.
    pub fn encrypt_sequence_with_plaintext_checksums(
        &self,
        dests: &mut [&mut [u8]],
        datas: &[&[u8]],
        nonces: &[[u8; BLOCK_SIZE]],
        plaintext_checksums: &[[u8; BLOCK_SIZE]],
    ) -> Result<(), CryptError> {
        let count = datas.len();
        if dests.len() != count || nonces.len() != count || plaintext_checksums.len() != count {
            return Err(CryptError::DestinationBufferTooSmall);
        }
        if count == 0 {
            return Ok(());
        }

        let tag_size = self.overhead();
        let mut metas = Vec::with_capacity(count);
        let mut nonce_blocks = Vec::with_capacity(count * BLOCK_SIZE);
        for i in 0..count {
            let cleartext_len = datas[i].len();
            if cleartext_len > MAX_PLAINTEXT_BYTES {
                return Err(CryptError::DestinationBufferTooSmall);
            }
            if dests[i].len() < cleartext_len + tag_size {
                return Err(CryptError::DestinationBufferTooSmall);
            }

            let last_pos = cleartext_len.saturating_sub(1) / BLOCK_SIZE * BLOCK_SIZE;
            let remaining = cleartext_len - last_pos;
            let n_main = last_pos / BLOCK_SIZE;
            metas.push(BatchPacketMeta {
                cleartext_len,
                last_pos,
                remaining,
                n_main,
                bulk_block_offset: 0,
            });
            nonce_blocks.extend_from_slice(&nonces[i]);
        }

        self.aes.encrypt_blocks(&mut nonce_blocks)?;

        let mut delta_chains = Vec::with_capacity(count);
        let mut next_bulk_block = 0;
        for i in 0..count {
            let mut chain = [[0u8; BLOCK_SIZE]; MAX_BLOCKS + 2];
            chain[0].copy_from_slice(&nonce_blocks[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]);
            self.gf128.fill_chain(&mut chain, metas[i].n_main + 1);
            metas[i].bulk_block_offset = next_bulk_block;
            next_bulk_block += metas[i].n_main;
            delta_chains.push(chain);
        }

        let mut bulk = vec![0u8; next_bulk_block * BLOCK_SIZE];
        for i in 0..count {
            let meta = &metas[i];
            if meta.n_main == 0 {
                continue;
            }
            let start = meta.bulk_block_offset * BLOCK_SIZE;
            let end = start + meta.n_main * BLOCK_SIZE;
            stage_full_blocks(
                &mut bulk[start..end],
                datas[i],
                &delta_chains[i],
                meta.n_main,
                self.xor,
            );
        }

        if !bulk.is_empty() {
            self.aes.encrypt_blocks(&mut bulk)?;
        }

        for i in 0..count {
            let meta = &metas[i];
            let dest_ciphertext = &mut dests[i][tag_size..tag_size + meta.cleartext_len];
            let bulk_start = meta.bulk_block_offset * BLOCK_SIZE;
            let bulk_len = meta.n_main * BLOCK_SIZE;
            self.xor.xor_chain_into(
                &mut dest_ciphertext[..bulk_len],
                &bulk[bulk_start..bulk_start + bulk_len],
                &delta_chains[i][1..meta.n_main + 1],
            );
        }

        let mut pads = vec![0u8; count * BLOCK_SIZE];
        for i in 0..count {
            let meta = &metas[i];
            let final_delta = delta_chains[i][meta.n_main + 1];
            let pad = &mut pads[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
            let num_bits = (meta.remaining * 8) as u16;
            pad[BLOCK_SIZE - 2] = ((num_bits >> 8) & 0xff) as u8;
            pad[BLOCK_SIZE - 1] = (num_bits & 0xff) as u8;
            for j in 0..BLOCK_SIZE {
                pad[j] ^= final_delta[j];
            }
        }
        self.aes.encrypt_blocks(&mut pads)?;

        let mut tags = vec![0u8; count * BLOCK_SIZE];
        for i in 0..count {
            let meta = &metas[i];
            let pad = &pads[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
            let mut checksum = plaintext_checksums[i];
            for j in meta.remaining..BLOCK_SIZE {
                checksum[j] ^= pad[j];
            }

            let dest_ciphertext = &mut dests[i][tag_size..tag_size + meta.cleartext_len];
            for j in 0..meta.remaining {
                dest_ciphertext[meta.last_pos + j] = pad[j] ^ datas[i][meta.last_pos + j];
            }

            let mut tag_buf = delta_chains[i][meta.n_main + 1];
            self.gf128.triple(&mut tag_buf);
            for j in 0..BLOCK_SIZE {
                tag_buf[j] ^= checksum[j];
            }
            tags[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE].copy_from_slice(&tag_buf);
        }
        self.aes.encrypt_blocks(&mut tags)?;

        for i in 0..count {
            dests[i][..tag_size].copy_from_slice(&tags[i * BLOCK_SIZE..i * BLOCK_SIZE + tag_size]);
        }

        Ok(())
    }
}

impl CryptoMode for Ocb2 {
    fn nonce_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn key_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn overhead(&self) -> usize {
        Self::TAG_SIZE
    }

    fn key(&self) -> Option<&[u8]> {
        Some(&self.key)
    }

    fn encrypt_with_plaintext_checksum(
        &self,
        dest: &mut [u8],
        data: &[u8],
        nonce: &[u8],
        plaintext_checksum: &[u8; BLOCK_SIZE],
    ) -> Result<(), CryptError> {
        Ocb2::encrypt_with_plaintext_checksum(self, dest, data, nonce, plaintext_checksum)
    }

    fn encrypt_sequence_with_plaintext_checksums(
        &self,
        dests: &mut [&mut [u8]],
        datas: &[&[u8]],
        nonces: &[[u8; BLOCK_SIZE]],
        plaintext_checksums: &[[u8; BLOCK_SIZE]],
    ) -> Result<(), CryptError> {
        Ocb2::encrypt_sequence_with_plaintext_checksums(
            self,
            dests,
            datas,
            nonces,
            plaintext_checksums,
        )
    }

    fn encrypt(&self, dest: &mut [u8], data: &[u8], nonce: &[u8]) -> Result<(), CryptError> {
        let cleartext_len = data.len();

        if nonce.len() != self.nonce_size() {
            return Err(CryptError::InvalidNonceSize);
        }
        if dest.len() < cleartext_len + self.overhead() {
            return Err(CryptError::DestinationBufferTooSmall);
        }
        if cleartext_len > MAX_PLAINTEXT_BYTES {
            return Err(CryptError::DestinationBufferTooSmall);
        }

        // ── Phase 1: initial delta = E(nonce). 1 AES call.
        let mut delta_chain = [[0u8; BLOCK_SIZE]; MAX_BLOCKS + 2];
        delta_chain[0].copy_from_slice(nonce);
        self.aes.encrypt_blocks(&mut delta_chain[0])?;

        let last_pos = cleartext_len.saturating_sub(1) / BLOCK_SIZE * BLOCK_SIZE;
        let remaining = cleartext_len - last_pos;
        let n_main = last_pos / BLOCK_SIZE; // count of "main loop" full blocks

        // ── Phase 2: pre-compute all per-block deltas in one shot.
        // delta_chain[0]   = E(nonce)            (intermediate; never used directly below)
        // delta_chain[i]   = times2^i(E(nonce))  for i = 1..=n_main+1
        //   - delta_chain[1..=n_main]  → main-loop block deltas
        //   - delta_chain[n_main + 1]  → partial-block delta
        // The whole chain is dispatched once; the SIMD backend keeps the
        // running value in LE form between iterations to amortize the
        // BE↔LE byte-reverse cost.
        self.gf128.fill_chain(&mut delta_chain, n_main + 1);

        let tag_size = self.overhead();
        let dest_ciphertext = &mut dest[tag_size..];
        let mut checksum = [0u8; BLOCK_SIZE];

        // ── Phase 3: pre-XOR every main-loop block with its delta into one
        // contiguous buffer. Pure Rust, no FFI.
        let bulk = stage_full_blocks(dest_ciphertext, data, &delta_chain, n_main, self.xor);

        // ── Phase 4: ONE batched ECB encrypt for all main-loop blocks.
        if !bulk.is_empty() {
            self.aes.encrypt_blocks(bulk)?;
        }

        // ── Phase 5: post-XOR to produce ciphertext, accumulate checksum.
        // Pure Rust, no FFI.
        //
        // This loop is *intentionally fused* in the single-recipient path:
        // for one encrypt the data-stream load is amortized, so paying the
        // fold here is cheaper than a second pass. The fan-out path
        // (`encrypt_with_plaintext_checksum`) instead splits this into two
        // simpler loops — that variant gets ~33% faster because LLVM
        // auto-vectorizes the unfused post-XOR but not the fused form. See
        // the phase profile in `client::crypt::profile_test`. Do not "unify"
        // these two encrypt paths back into one body without re-measuring;
        // their optimal shapes differ.
        self.xor.xor_chain_in_place_and_fold_input(
            &mut dest_ciphertext[..n_main * BLOCK_SIZE],
            &data[..n_main * BLOCK_SIZE],
            &delta_chain[1..n_main + 1],
            &mut checksum,
        );

        // ── Phase 6: partial (or final empty) block. 1 AES call.
        let final_delta = delta_chain[n_main + 1];
        let mut pad = [0u8; BLOCK_SIZE];
        let num_bits = (remaining * 8) as u16;
        pad[BLOCK_SIZE - 2] = ((num_bits >> 8) & 0xff) as u8;
        pad[BLOCK_SIZE - 1] = (num_bits & 0xff) as u8;
        for j in 0..BLOCK_SIZE {
            pad[j] ^= final_delta[j];
        }
        self.aes.encrypt_blocks(&mut pad)?;

        // tmp = data fragment (first `remaining` bytes) | pad (upper bytes)
        let mut tmp = [0u8; BLOCK_SIZE];
        if remaining > 0 {
            tmp[..remaining].copy_from_slice(&data[last_pos..last_pos + remaining]);
        }
        tmp[remaining..].copy_from_slice(&pad[remaining..]);

        for j in 0..BLOCK_SIZE {
            checksum[j] ^= tmp[j];
        }
        for j in 0..remaining {
            dest_ciphertext[last_pos + j] = pad[j] ^ tmp[j];
        }

        // ── Phase 7: tag = E(times3(final_delta) ^ checksum). 1 AES call.
        let mut tag_buf = final_delta;
        self.gf128.triple(&mut tag_buf);
        for j in 0..BLOCK_SIZE {
            tag_buf[j] ^= checksum[j];
        }
        self.aes.encrypt_blocks(&mut tag_buf)?;

        dest[..tag_size].copy_from_slice(&tag_buf[..tag_size]);

        Ok(())
    }

    fn decrypt(&self, dest: &mut [u8], data: &[u8], nonce: &[u8]) -> Result<(), CryptError> {
        if nonce.len() != self.nonce_size() {
            return Err(CryptError::InvalidNonceSize);
        }
        if data.len() < self.overhead() {
            return Err(CryptError::DataTooShort);
        }

        let tag_len = self.overhead();
        let ciphertext_len = data.len() - tag_len;
        if dest.len() < ciphertext_len {
            return Err(CryptError::DestinationBufferTooSmall);
        }
        if ciphertext_len > MAX_PLAINTEXT_BYTES {
            return Err(CryptError::DestinationBufferTooSmall);
        }

        let tag = &data[..tag_len];
        let ciphertext = &data[tag_len..];

        // ── Phase 1: initial delta = E(nonce). 1 AES call (encrypt).
        let mut delta_chain = [[0u8; BLOCK_SIZE]; MAX_BLOCKS + 2];
        delta_chain[0].copy_from_slice(nonce);
        self.aes.encrypt_blocks(&mut delta_chain[0])?;

        let last_pos = ciphertext_len.saturating_sub(1) / BLOCK_SIZE * BLOCK_SIZE;
        let remaining = ciphertext_len - last_pos;
        let n_main = last_pos / BLOCK_SIZE;

        // ── Phase 2: pre-compute all deltas in one shot (see encrypt for layout).
        self.gf128.fill_chain(&mut delta_chain, n_main + 1);

        let mut checksum = [0u8; BLOCK_SIZE];

        // ── Phase 3: pre-XOR every main-loop ciphertext block with its delta
        // into one contiguous buffer.
        let mut bulk = [0u8; MAX_PLAINTEXT_BYTES];
        let bulk_len = n_main * BLOCK_SIZE;
        self.xor.xor_chain_into(
            &mut bulk[..bulk_len],
            &ciphertext[..bulk_len],
            &delta_chain[1..n_main + 1],
        );

        // ── Phase 4: ONE batched ECB decrypt.
        if bulk_len > 0 {
            self.aes.decrypt_blocks(&mut bulk[..bulk_len])?;
        }

        // ── Phase 5: post-XOR to produce plaintext, accumulate checksum.
        self.xor.xor_chain_into_and_fold_output(
            &mut dest[..bulk_len],
            &bulk[..bulk_len],
            &delta_chain[1..n_main + 1],
            &mut checksum,
        );

        // ── Phase 6: partial (or final empty) block. 1 AES call (encrypt).
        let final_delta = delta_chain[n_main + 1];
        let mut pad = [0u8; BLOCK_SIZE];
        let num_bits = (remaining * 8) as u16;
        pad[BLOCK_SIZE - 2] = ((num_bits >> 8) & 0xff) as u8;
        pad[BLOCK_SIZE - 1] = (num_bits & 0xff) as u8;
        for j in 0..BLOCK_SIZE {
            pad[j] ^= final_delta[j];
        }
        self.aes.encrypt_blocks(&mut pad)?;

        // tmp = ciphertext fragment (first `remaining` bytes), zero-padded.
        let mut tmp = [0u8; BLOCK_SIZE];
        if remaining > 0 {
            tmp[..remaining].copy_from_slice(&ciphertext[last_pos..last_pos + remaining]);
        }
        // tmp ^= pad (first `remaining` bytes are plaintext fragment;
        // upper bytes equal pad[remaining..] since tmp[remaining..] was zero).
        for j in 0..BLOCK_SIZE {
            tmp[j] ^= pad[j];
        }

        for j in 0..BLOCK_SIZE {
            checksum[j] ^= tmp[j];
        }
        if remaining > 0 {
            dest[last_pos..last_pos + remaining].copy_from_slice(&tmp[..remaining]);
        }

        // ── Phase 7: tag = E(times3(final_delta) ^ checksum). 1 AES call.
        let mut tag_buf = final_delta;
        self.gf128.triple(&mut tag_buf);
        for j in 0..BLOCK_SIZE {
            tag_buf[j] ^= checksum[j];
        }
        self.aes.encrypt_blocks(&mut tag_buf)?;

        if !consttime_eq(&tag_buf[..tag_len], tag) {
            return Err(CryptError::TagMismatch);
        }

        Ok(())
    }
}

fn consttime_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// `times2` and `times3` (GF(2^128) doubling/tripling) live in
// `super::gf128` with both scalar and SIMD backends, runtime-probed at
// startup. See the comments there for the polynomial definition.

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use hex::decode;

    fn must_decode_hex(s: &str) -> Bytes {
        Bytes::from(decode(s).expect("invalid hex"))
    }

    struct OcbVector {
        _name: &'static str,
        key: &'static str,
        nonce: &'static str,
        plaintext: &'static str,
        ciphertext: &'static str,
        tag: &'static str,
    }

    const VECTORS: &[OcbVector] = &[
        OcbVector {
            _name: "OCB2-AES-128-001",
            key: "000102030405060708090A0B0C0D0E0F",
            nonce: "000102030405060708090A0B0C0D0E0F",
            plaintext: "",
            ciphertext: "",
            tag: "BF3108130773AD5EC70EC69E7875A7B0",
        },
        OcbVector {
            _name: "OCB2-AES-128-002",
            key: "000102030405060708090A0B0C0D0E0F",
            nonce: "000102030405060708090A0B0C0D0E0F",
            plaintext: "0001020304050607",
            ciphertext: "C636B3A868F429BB",
            tag: "A45F5FDEA5C088D1D7C8BE37CABC8C5C",
        },
        OcbVector {
            _name: "OCB2-AES-128-003",
            key: "000102030405060708090A0B0C0D0E0F",
            nonce: "000102030405060708090A0B0C0D0E0F",
            plaintext: "000102030405060708090A0B0C0D0E0F",
            ciphertext: "52E48F5D19FE2D9869F0C4A4B3D2BE57",
            tag: "F7EE49AE7AA5B5E6645DB6B3966136F9",
        },
        OcbVector {
            _name: "OCB2-AES-128-003b",
            key: "000102030405060708090A0B0C0D0E0F",
            nonce: "000102030405060708090A0B0C0D0E0F",
            plaintext: "000102030405060708090A0B0C0D0E0F1011121314151617",
            ciphertext: "F75D6BC8B4DC8D66B836A2B08B32A636CC579E145D323BEB",
            tag: "A1A50F822819D6E0A216784AC24AC84C",
        },
        OcbVector {
            _name: "OCB2-AES-128-004",
            key: "000102030405060708090A0B0C0D0E0F",
            nonce: "000102030405060708090A0B0C0D0E0F",
            plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            ciphertext: "F75D6BC8B4DC8D66B836A2B08B32A636CEC3C555037571709DA25E1BB0421A27",
            tag: "09CA6C73F0B5C6C5FD587122D75F2AA3",
        },
        OcbVector {
            _name: "OCB2-AES-128-005",
            key: "000102030405060708090A0B0C0D0E0F",
            nonce: "000102030405060708090A0B0C0D0E0F",
            plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
            ciphertext: "F75D6BC8B4DC8D66B836A2B08B32A6369F1CD3C5228D79FD6C267F5F6AA7B231C7DFB9D59951AE9C",
            tag: "9DB0CDF880F73E3E10D4EB3217766688",
        },
    ];

    /// Verify that `encrypt_with_plaintext_checksum` produces output
    /// byte-identical to `encrypt` across every known-answer vector. This
    /// is the correctness boundary for the fan-out optimization in
    /// `CryptState::encrypt_with_precomputed_checksum`.
    #[test]
    fn precomputed_checksum_matches_encrypt_kat() {
        for v in VECTORS {
            let key_bytes = must_decode_hex(v.key);
            let key_arr: [u8; BLOCK_SIZE] = key_bytes.as_ref().try_into().unwrap();
            let ocb = Ocb2::from_key(key_arr).unwrap();
            let nonce = must_decode_hex(v.nonce);
            let plain = must_decode_hex(v.plaintext);

            let mut a = vec![0u8; plain.len() + ocb.overhead()];
            let mut b = vec![0u8; plain.len() + ocb.overhead()];

            ocb.encrypt(&mut a, &plain, &nonce).unwrap();

            let chk = Ocb2::compute_plaintext_checksum(&plain);
            ocb.encrypt_with_plaintext_checksum(&mut b, &plain, &nonce, &chk)
                .unwrap();

            assert_eq!(
                a, b,
                "precomputed-checksum encrypt diverged for {}",
                v._name
            );
        }
    }

    /// Sweep plaintext lengths around block boundaries — the partial-block
    /// tail handling in `encrypt_with_plaintext_checksum` is where the
    /// bookkeeping is most likely to drift.
    #[test]
    fn precomputed_checksum_matches_encrypt_lengths() {
        let key_arr: [u8; BLOCK_SIZE] = [0x42; BLOCK_SIZE];
        let nonce: [u8; BLOCK_SIZE] = [0xa5; BLOCK_SIZE];
        let ocb = Ocb2::from_key(key_arr).unwrap();

        // Cover empty, partial-only, exact-block-multiple, and offset-by-one
        // plaintexts on either side of n_main = 0..6. 1024 is the configured
        // MAX_PLAINTEXT_BYTES upper bound.
        let lengths: &[usize] = &[
            0, 1, 7, 15, 16, 17, 31, 32, 33, 47, 48, 64, 80, 96, 175, 256, 768, 1023, 1024,
        ];
        for &len in lengths {
            let plain: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(31) ^ 0x5a) as u8)
                .collect();

            let mut a = vec![0u8; plain.len() + ocb.overhead()];
            let mut b = vec![0u8; plain.len() + ocb.overhead()];

            ocb.encrypt(&mut a, &plain, &nonce).unwrap();
            let chk = Ocb2::compute_plaintext_checksum(&plain);
            ocb.encrypt_with_plaintext_checksum(&mut b, &plain, &nonce, &chk)
                .unwrap();

            assert_eq!(a, b, "precomputed-checksum mismatch at len={}", len);

            // Round-trip via standard decrypt: the optimized output must
            // verify against the same tag, otherwise the per-recipient
            // `pad[remaining..]` reconstruction is wrong.
            let mut dec = vec![0u8; plain.len()];
            ocb.decrypt(&mut dec, &b, &nonce).unwrap();
            assert_eq!(dec, plain, "decrypt round-trip failed at len={}", len);
        }
    }

    #[test]
    fn runtime_xor_backends_match_scalar_ocb2() {
        use crate::xor_backend::{BackendKind, XorOps};

        const LENGTHS: &[usize] = &[0, 1, 15, 16, 17, 31, 32, 175, 768, 1024];
        let key = [0x42u8; BLOCK_SIZE];
        let nonce = [0xa5u8; BLOCK_SIZE];
        let scalar = Ocb2::from_key_with_backend(key, BackendKind::Scalar).unwrap();

        for &len in LENGTHS {
            let plaintext: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(29) ^ 0x6d)
                .collect();
            let checksum = Ocb2::compute_plaintext_checksum(&plaintext);

            let mut expected = vec![0u8; len + scalar.overhead()];
            scalar
                .encrypt_with_plaintext_checksum(&mut expected, &plaintext, &nonce, &checksum)
                .unwrap();

            for &kind in &[BackendKind::Scalar, BackendKind::Sse2, BackendKind::Avx2] {
                if !XorOps::is_available(kind) {
                    continue;
                }
                let ocb = Ocb2::from_key_with_backend(key, kind).unwrap();
                let mut actual = vec![0u8; len + ocb.overhead()];
                ocb.encrypt_with_plaintext_checksum(&mut actual, &plaintext, &nonce, &checksum)
                    .unwrap();
                assert_eq!(actual, expected, "encrypt backend {kind:?} len={len}");

                let mut decrypted = vec![0u8; len];
                ocb.decrypt(&mut decrypted, &actual, &nonce).unwrap();
                assert_eq!(decrypted, plaintext, "decrypt backend {kind:?} len={len}");

                let mut tampered = actual.clone();
                tampered[0] ^= 1;
                let mut rejected = vec![0u8; len];
                assert!(matches!(
                    ocb.decrypt(&mut rejected, &tampered, &nonce),
                    Err(CryptError::TagMismatch)
                ));
            }
        }
    }

    #[test]
    fn runtime_xor_backends_match_scalar_sequence_encryption() {
        use crate::xor_backend::{BackendKind, XorOps};

        const LENGTHS: &[usize] = &[0, 1, 15, 16, 17, 31, 32, 175, 768, 1024];
        let key = [0x27u8; BLOCK_SIZE];
        let plaintexts: Vec<Vec<u8>> = LENGTHS
            .iter()
            .enumerate()
            .map(|(packet, &len)| {
                (0..len)
                    .map(|i| (i as u8).wrapping_mul(13) ^ packet as u8)
                    .collect()
            })
            .collect();
        let datas: Vec<&[u8]> = plaintexts.iter().map(Vec::as_slice).collect();
        let nonces: Vec<[u8; BLOCK_SIZE]> = LENGTHS
            .iter()
            .enumerate()
            .map(|(packet, _)| [packet as u8; BLOCK_SIZE])
            .collect();
        let checksums: Vec<[u8; BLOCK_SIZE]> = plaintexts
            .iter()
            .map(|data| Ocb2::compute_plaintext_checksum(data))
            .collect();

        let scalar = Ocb2::from_key_with_backend(key, BackendKind::Scalar).unwrap();
        let mut expected_outputs: Vec<Vec<u8>> = LENGTHS
            .iter()
            .map(|&len| vec![0u8; len + scalar.overhead()])
            .collect();
        let mut expected_refs: Vec<&mut [u8]> =
            expected_outputs.iter_mut().map(Vec::as_mut_slice).collect();
        scalar
            .encrypt_sequence_with_plaintext_checksums(
                &mut expected_refs,
                &datas,
                &nonces,
                &checksums,
            )
            .unwrap();
        drop(expected_refs);

        for &kind in &[BackendKind::Scalar, BackendKind::Sse2, BackendKind::Avx2] {
            if !XorOps::is_available(kind) {
                continue;
            }
            let ocb = Ocb2::from_key_with_backend(key, kind).unwrap();
            let mut actual_outputs: Vec<Vec<u8>> = LENGTHS
                .iter()
                .map(|&len| vec![0u8; len + ocb.overhead()])
                .collect();
            let mut actual_refs: Vec<&mut [u8]> =
                actual_outputs.iter_mut().map(Vec::as_mut_slice).collect();
            ocb.encrypt_sequence_with_plaintext_checksums(
                &mut actual_refs,
                &datas,
                &nonces,
                &checksums,
            )
            .unwrap();
            drop(actual_refs);

            assert_eq!(
                actual_outputs, expected_outputs,
                "sequence backend {kind:?}"
            );

            for ((output, data), nonce) in actual_outputs.iter().zip(&plaintexts).zip(&nonces) {
                let mut decrypted = vec![0u8; data.len()];
                ocb.decrypt(&mut decrypted, output, nonce).unwrap();
                assert_eq!(decrypted, *data, "sequence decrypt backend {kind:?}");
            }
        }
    }

    #[test]
    fn test_encrypt_decrypt_vectors() {
        for v in VECTORS {
            let key_bytes = must_decode_hex(v.key);
            let key_arr: [u8; BLOCK_SIZE] = key_bytes.as_ref().try_into().unwrap();
            let ocb = Ocb2::from_key(key_arr).unwrap();

            let nonce = must_decode_hex(v.nonce);
            let plain = must_decode_hex(v.plaintext);
            let expected_ct = must_decode_hex(v.ciphertext);
            let expected_tag = must_decode_hex(v.tag);

            let mut out = vec![0u8; plain.len() + ocb.overhead()];

            ocb.encrypt(&mut out, &plain, &nonce)
                .expect("encrypt failed");

            // split ciphertext and tag
            let ct = &out[ocb.overhead()..];
            let tag = &out[..ocb.overhead()];

            assert_eq!(
                ct,
                expected_ct.as_ref(),
                "ciphertext mismatch for {}",
                v._name
            );

            // expected_tag is 16 bytes; compare prefix of length overhead()
            assert_eq!(
                tag,
                &expected_tag[..ocb.overhead()],
                "tag mismatch for {}",
                v._name
            );

            // decrypt
            let mut combined = vec![0u8; out.len()];
            combined[..ocb.overhead()].copy_from_slice(tag);
            combined[ocb.overhead()..].copy_from_slice(ct);

            let mut dec = vec![0u8; plain.len()];
            ocb.decrypt(&mut dec, &combined, &nonce)
                .expect("decrypt failed");
            assert_eq!(dec, plain, "decrypted plaintext mismatch for {}", v._name);
        }
    }
}
