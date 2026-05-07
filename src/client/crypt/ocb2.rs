use aws_lc_rs::rand::SecureRandom;
use bytes::Bytes;

use crate::client::crypt::{
    aes_backend::Aes128, errors::CryptError, gf128::Gf128Ops, CryptoMode,
};

const BLOCK_SIZE: usize = 16;
/// Hard upper bound on plaintext we ever encrypt in one OCB2 call. The Mumble
/// UDP voice path caps wire packets at 1024 bytes (incl. tag overhead), so
/// the largest plaintext we'll see is comfortably below this.
const MAX_PLAINTEXT_BYTES: usize = 1024;
const MAX_BLOCKS: usize = MAX_PLAINTEXT_BYTES / BLOCK_SIZE; // 64

pub struct Ocb2 {
    key: Bytes,
    aes: Aes128,
    gf128: Gf128Ops,
}

impl Ocb2 {
    pub fn from_key(key: [u8; BLOCK_SIZE]) -> Result<Self, CryptError> {
        Ok(Ocb2 {
            key: Bytes::copy_from_slice(&key),
            aes: Aes128::new(&key)?,
            gf128: Gf128Ops::new(),
        })
    }

    pub fn new(rng: &dyn SecureRandom) -> Result<Self, CryptError> {
        let mut key = [0u8; BLOCK_SIZE];
        rng.fill(&mut key)?;
        Ocb2::from_key(key)
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
        3
    }

    fn key(&self) -> Option<&[u8]> {
        Some(self.key.as_ref())
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
        let mut bulk = [0u8; MAX_PLAINTEXT_BYTES];
        let bulk_len = n_main * BLOCK_SIZE;
        for i in 0..n_main {
            let block = &data[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
            let d = &delta_chain[i + 1];
            for j in 0..BLOCK_SIZE {
                bulk[i * BLOCK_SIZE + j] = block[j] ^ d[j];
            }
        }

        // ── Phase 4: ONE batched ECB encrypt for all main-loop blocks.
        if bulk_len > 0 {
            self.aes.encrypt_blocks(&mut bulk[..bulk_len])?;
        }

        // ── Phase 5: post-XOR to produce ciphertext, accumulate checksum.
        // Pure Rust, no FFI.
        for i in 0..n_main {
            let d = &delta_chain[i + 1];
            for j in 0..BLOCK_SIZE {
                dest_ciphertext[i * BLOCK_SIZE + j] = bulk[i * BLOCK_SIZE + j] ^ d[j];
                checksum[j] ^= data[i * BLOCK_SIZE + j];
            }
        }

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
        for i in 0..n_main {
            let block = &ciphertext[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
            let d = &delta_chain[i + 1];
            for j in 0..BLOCK_SIZE {
                bulk[i * BLOCK_SIZE + j] = block[j] ^ d[j];
            }
        }

        // ── Phase 4: ONE batched ECB decrypt.
        if bulk_len > 0 {
            self.aes.decrypt_blocks(&mut bulk[..bulk_len])?;
        }

        // ── Phase 5: post-XOR to produce plaintext, accumulate checksum.
        for i in 0..n_main {
            let d = &delta_chain[i + 1];
            for j in 0..BLOCK_SIZE {
                let plain = bulk[i * BLOCK_SIZE + j] ^ d[j];
                dest[i * BLOCK_SIZE + j] = plain;
                checksum[j] ^= plain;
            }
        }

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
            plaintext:
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
            ciphertext:
                "F75D6BC8B4DC8D66B836A2B08B32A6369F1CD3C5228D79FD6C267F5F6AA7B231C7DFB9D59951AE9C",
            tag: "9DB0CDF880F73E3E10D4EB3217766688",
        },
    ];

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
