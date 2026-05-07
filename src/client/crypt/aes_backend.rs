//! AES-128 ECB backend with runtime feature detection.
//!
//! Two implementations:
//!   - `Native`: pure-Rust AES-NI via `std::arch::x86_64` intrinsics. Hardware
//!     AES-NI runs at ~3-4 ns/block on modern x86_64 CPUs and the per-block
//!     pipelining of `aesenc` instructions gives ~4-8 GB/s aggregate
//!     throughput.  No FFI cost.
//!   - `Aws`: aws-lc-rs's `EncryptingKey::ecb` / `DecryptingKey::ecb`. Each
//!     call crosses an FFI boundary (~14 ns of overhead per call) but
//!     processes a full multi-block buffer in a single hop.  Always available.
//!
//! The backend is probed once at startup via `probe()`; all subsequent
//! `Aes128::new` calls use the cached result.  On x86_64 with AES-NI we use
//! the native intrinsics; everywhere else (including aarch64 and x86_64 CPUs
//! without AES-NI — exceedingly rare on modern hardware) we fall back to the
//! aws-lc-rs path.

use std::sync::OnceLock;

use aws_lc_rs::cipher::{
    DecryptingKey, DecryptionContext, EncryptingKey, UnboundCipherKey, AES_128,
};

use super::errors::CryptError;

const BLOCK_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendKind {
    Native,
    Aws,
}

static BACKEND_KIND: OnceLock<BackendKind> = OnceLock::new();

/// Probe the host for AES hardware acceleration and cache the choice.
///
/// Call this once during process startup so the backend selection (and the
/// `tracing::info!` that goes with it) happens at a predictable point rather
/// than on the first connection.  Subsequent calls are cheap (just a load).
pub fn probe() -> &'static str {
    let kind = *BACKEND_KIND.get_or_init(|| {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("sse2") {
                tracing::info!(
                    backend = "native-aesni",
                    arch = "x86_64",
                    "AES backend probe: using x86_64 AES-NI intrinsics"
                );
                return BackendKind::Native;
            }
        }
        tracing::info!(
            backend = "aws-lc-rs",
            arch = std::env::consts::ARCH,
            "AES backend probe: using aws-lc-rs (hardware AES-NI not detected)"
        );
        BackendKind::Aws
    });
    match kind {
        BackendKind::Native => "native-aesni",
        BackendKind::Aws => "aws-lc-rs",
    }
}

fn current_backend() -> BackendKind {
    *BACKEND_KIND.get_or_init(|| {
        // Same logic as `probe()` but without the log; if `probe()` was already
        // called this branch never runs because the OnceLock is filled.
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("sse2") {
                return BackendKind::Native;
            }
        }
        BackendKind::Aws
    })
}

/// AES-128 ECB key handle. Holds the chosen backend's per-key state.
pub struct Aes128 {
    inner: Aes128Inner,
}

enum Aes128Inner {
    #[cfg(target_arch = "x86_64")]
    Native(native::Aes128Ni),
    Aws {
        encrypt: EncryptingKey,
        decrypt: DecryptingKey,
    },
}

impl Aes128 {
    pub fn new(key: &[u8; BLOCK_SIZE]) -> Result<Self, CryptError> {
        Self::with_backend(current_backend(), key)
    }

    fn with_backend(kind: BackendKind, key: &[u8; BLOCK_SIZE]) -> Result<Self, CryptError> {
        match kind {
            #[cfg(target_arch = "x86_64")]
            BackendKind::Native => {
                // SAFETY: BackendKind::Native is only chosen after
                // `is_x86_feature_detected!("aes" + "sse2")` succeeded.
                let inner = unsafe { native::Aes128Ni::new(key) };
                Ok(Self {
                    inner: Aes128Inner::Native(inner),
                })
            }
            #[cfg(not(target_arch = "x86_64"))]
            BackendKind::Native => {
                // Native backend is only built on x86_64; if we somehow end up
                // here, fall back to aws.
                Self::with_backend(BackendKind::Aws, key)
            }
            BackendKind::Aws => {
                let encrypt = EncryptingKey::ecb(UnboundCipherKey::new(&AES_128, key)?)?;
                let decrypt = DecryptingKey::ecb(UnboundCipherKey::new(&AES_128, key)?)?;
                Ok(Self {
                    inner: Aes128Inner::Aws { encrypt, decrypt },
                })
            }
        }
    }

    /// Encrypt every 16-byte block in `buffer` in place.
    /// `buffer.len()` must be a positive multiple of 16.
    pub fn encrypt_blocks(&self, buffer: &mut [u8]) -> Result<(), CryptError> {
        debug_assert!(!buffer.is_empty() && buffer.len() % BLOCK_SIZE == 0);
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Aes128Inner::Native(k) => {
                // SAFETY: constructor only runs on AES-capable hosts.
                unsafe { k.encrypt_blocks(buffer) };
                Ok(())
            }
            Aes128Inner::Aws { encrypt, .. } => {
                encrypt.encrypt(buffer)?;
                Ok(())
            }
        }
    }

    /// Decrypt every 16-byte block in `buffer` in place.
    /// `buffer.len()` must be a positive multiple of 16.
    pub fn decrypt_blocks(&self, buffer: &mut [u8]) -> Result<(), CryptError> {
        debug_assert!(!buffer.is_empty() && buffer.len() % BLOCK_SIZE == 0);
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Aes128Inner::Native(k) => {
                // SAFETY: constructor only runs on AES-capable hosts.
                unsafe { k.decrypt_blocks(buffer) };
                Ok(())
            }
            Aes128Inner::Aws { decrypt, .. } => {
                decrypt.decrypt(buffer, DecryptionContext::None)?;
                Ok(())
            }
        }
    }
}

// ── Native AES-NI implementation ─────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod native {
    use std::arch::x86_64::*;

    /// AES-128 round keys for both directions.
    /// Encryption uses `enc[0..=10]`. Decryption uses inverse-MixColumns
    /// versions of the same keys, with `dec[0]` and `dec[10]` left raw (these
    /// correspond to the last and first encryption keys respectively).
    pub struct Aes128Ni {
        enc: [__m128i; 11],
        dec: [__m128i; 11],
    }

    // SAFETY: __m128i is just 16 bytes, plain Copy data.
    unsafe impl Send for Aes128Ni {}
    unsafe impl Sync for Aes128Ni {}

    impl Aes128Ni {
        /// SAFETY: caller asserts the host supports the `aes` and `sse2`
        /// target features.
        pub unsafe fn new(key: &[u8; 16]) -> Self {
            let enc = key_expansion(*key);
            let dec = inverse_round_keys(&enc);
            Self { enc, dec }
        }

        #[target_feature(enable = "aes,sse2")]
        pub unsafe fn encrypt_blocks(&self, buffer: &mut [u8]) {
            let mut chunks = buffer.chunks_exact_mut(BLOCK_BYTES * 8);
            for chunk in &mut chunks {
                encrypt_8(&self.enc, chunk);
            }
            let rem = chunks.into_remainder();
            for block in rem.chunks_exact_mut(BLOCK_BYTES) {
                let b = _mm_loadu_si128(block.as_ptr() as *const __m128i);
                let c = encrypt_one(&self.enc, b);
                _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, c);
            }
        }

        #[target_feature(enable = "aes,sse2")]
        pub unsafe fn decrypt_blocks(&self, buffer: &mut [u8]) {
            let mut chunks = buffer.chunks_exact_mut(BLOCK_BYTES * 8);
            for chunk in &mut chunks {
                decrypt_8(&self.dec, chunk);
            }
            let rem = chunks.into_remainder();
            for block in rem.chunks_exact_mut(BLOCK_BYTES) {
                let b = _mm_loadu_si128(block.as_ptr() as *const __m128i);
                let c = decrypt_one(&self.dec, b);
                _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, c);
            }
        }
    }

    const BLOCK_BYTES: usize = 16;

    #[target_feature(enable = "aes,sse2")]
    unsafe fn encrypt_one(rk: &[__m128i; 11], block: __m128i) -> __m128i {
        let mut s = _mm_xor_si128(block, rk[0]);
        s = _mm_aesenc_si128(s, rk[1]);
        s = _mm_aesenc_si128(s, rk[2]);
        s = _mm_aesenc_si128(s, rk[3]);
        s = _mm_aesenc_si128(s, rk[4]);
        s = _mm_aesenc_si128(s, rk[5]);
        s = _mm_aesenc_si128(s, rk[6]);
        s = _mm_aesenc_si128(s, rk[7]);
        s = _mm_aesenc_si128(s, rk[8]);
        s = _mm_aesenc_si128(s, rk[9]);
        _mm_aesenclast_si128(s, rk[10])
    }

    #[target_feature(enable = "aes,sse2")]
    unsafe fn decrypt_one(dk: &[__m128i; 11], block: __m128i) -> __m128i {
        let mut s = _mm_xor_si128(block, dk[0]);
        s = _mm_aesdec_si128(s, dk[1]);
        s = _mm_aesdec_si128(s, dk[2]);
        s = _mm_aesdec_si128(s, dk[3]);
        s = _mm_aesdec_si128(s, dk[4]);
        s = _mm_aesdec_si128(s, dk[5]);
        s = _mm_aesdec_si128(s, dk[6]);
        s = _mm_aesdec_si128(s, dk[7]);
        s = _mm_aesdec_si128(s, dk[8]);
        s = _mm_aesdec_si128(s, dk[9]);
        _mm_aesdeclast_si128(s, dk[10])
    }

    /// Pipelined 8-block ECB encrypt: independent blocks let the CPU dispatch
    /// `aesenc` instructions on every cycle (each has ~4-cycle latency but
    /// 1-cycle throughput on modern Intel/AMD).
    #[target_feature(enable = "aes,sse2")]
    unsafe fn encrypt_8(rk: &[__m128i; 11], chunk: &mut [u8]) {
        let p = chunk.as_mut_ptr();
        let mut b0 = _mm_loadu_si128(p.add(0) as *const __m128i);
        let mut b1 = _mm_loadu_si128(p.add(16) as *const __m128i);
        let mut b2 = _mm_loadu_si128(p.add(32) as *const __m128i);
        let mut b3 = _mm_loadu_si128(p.add(48) as *const __m128i);
        let mut b4 = _mm_loadu_si128(p.add(64) as *const __m128i);
        let mut b5 = _mm_loadu_si128(p.add(80) as *const __m128i);
        let mut b6 = _mm_loadu_si128(p.add(96) as *const __m128i);
        let mut b7 = _mm_loadu_si128(p.add(112) as *const __m128i);

        let k0 = rk[0];
        b0 = _mm_xor_si128(b0, k0);
        b1 = _mm_xor_si128(b1, k0);
        b2 = _mm_xor_si128(b2, k0);
        b3 = _mm_xor_si128(b3, k0);
        b4 = _mm_xor_si128(b4, k0);
        b5 = _mm_xor_si128(b5, k0);
        b6 = _mm_xor_si128(b6, k0);
        b7 = _mm_xor_si128(b7, k0);

        for i in 1..10 {
            let ki = rk[i];
            b0 = _mm_aesenc_si128(b0, ki);
            b1 = _mm_aesenc_si128(b1, ki);
            b2 = _mm_aesenc_si128(b2, ki);
            b3 = _mm_aesenc_si128(b3, ki);
            b4 = _mm_aesenc_si128(b4, ki);
            b5 = _mm_aesenc_si128(b5, ki);
            b6 = _mm_aesenc_si128(b6, ki);
            b7 = _mm_aesenc_si128(b7, ki);
        }
        let kl = rk[10];
        b0 = _mm_aesenclast_si128(b0, kl);
        b1 = _mm_aesenclast_si128(b1, kl);
        b2 = _mm_aesenclast_si128(b2, kl);
        b3 = _mm_aesenclast_si128(b3, kl);
        b4 = _mm_aesenclast_si128(b4, kl);
        b5 = _mm_aesenclast_si128(b5, kl);
        b6 = _mm_aesenclast_si128(b6, kl);
        b7 = _mm_aesenclast_si128(b7, kl);

        _mm_storeu_si128(p.add(0) as *mut __m128i, b0);
        _mm_storeu_si128(p.add(16) as *mut __m128i, b1);
        _mm_storeu_si128(p.add(32) as *mut __m128i, b2);
        _mm_storeu_si128(p.add(48) as *mut __m128i, b3);
        _mm_storeu_si128(p.add(64) as *mut __m128i, b4);
        _mm_storeu_si128(p.add(80) as *mut __m128i, b5);
        _mm_storeu_si128(p.add(96) as *mut __m128i, b6);
        _mm_storeu_si128(p.add(112) as *mut __m128i, b7);
    }

    #[target_feature(enable = "aes,sse2")]
    unsafe fn decrypt_8(dk: &[__m128i; 11], chunk: &mut [u8]) {
        let p = chunk.as_mut_ptr();
        let mut b0 = _mm_loadu_si128(p.add(0) as *const __m128i);
        let mut b1 = _mm_loadu_si128(p.add(16) as *const __m128i);
        let mut b2 = _mm_loadu_si128(p.add(32) as *const __m128i);
        let mut b3 = _mm_loadu_si128(p.add(48) as *const __m128i);
        let mut b4 = _mm_loadu_si128(p.add(64) as *const __m128i);
        let mut b5 = _mm_loadu_si128(p.add(80) as *const __m128i);
        let mut b6 = _mm_loadu_si128(p.add(96) as *const __m128i);
        let mut b7 = _mm_loadu_si128(p.add(112) as *const __m128i);

        let k0 = dk[0];
        b0 = _mm_xor_si128(b0, k0);
        b1 = _mm_xor_si128(b1, k0);
        b2 = _mm_xor_si128(b2, k0);
        b3 = _mm_xor_si128(b3, k0);
        b4 = _mm_xor_si128(b4, k0);
        b5 = _mm_xor_si128(b5, k0);
        b6 = _mm_xor_si128(b6, k0);
        b7 = _mm_xor_si128(b7, k0);

        for i in 1..10 {
            let ki = dk[i];
            b0 = _mm_aesdec_si128(b0, ki);
            b1 = _mm_aesdec_si128(b1, ki);
            b2 = _mm_aesdec_si128(b2, ki);
            b3 = _mm_aesdec_si128(b3, ki);
            b4 = _mm_aesdec_si128(b4, ki);
            b5 = _mm_aesdec_si128(b5, ki);
            b6 = _mm_aesdec_si128(b6, ki);
            b7 = _mm_aesdec_si128(b7, ki);
        }
        let kl = dk[10];
        b0 = _mm_aesdeclast_si128(b0, kl);
        b1 = _mm_aesdeclast_si128(b1, kl);
        b2 = _mm_aesdeclast_si128(b2, kl);
        b3 = _mm_aesdeclast_si128(b3, kl);
        b4 = _mm_aesdeclast_si128(b4, kl);
        b5 = _mm_aesdeclast_si128(b5, kl);
        b6 = _mm_aesdeclast_si128(b6, kl);
        b7 = _mm_aesdeclast_si128(b7, kl);

        _mm_storeu_si128(p.add(0) as *mut __m128i, b0);
        _mm_storeu_si128(p.add(16) as *mut __m128i, b1);
        _mm_storeu_si128(p.add(32) as *mut __m128i, b2);
        _mm_storeu_si128(p.add(48) as *mut __m128i, b3);
        _mm_storeu_si128(p.add(64) as *mut __m128i, b4);
        _mm_storeu_si128(p.add(80) as *mut __m128i, b5);
        _mm_storeu_si128(p.add(96) as *mut __m128i, b6);
        _mm_storeu_si128(p.add(112) as *mut __m128i, b7);
    }

    /// AES-128 key schedule via `aeskeygenassist`. Round constants for AES-128
    /// are 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 — the
    /// powers of 2 in GF(2^8) modulo the AES polynomial.
    #[target_feature(enable = "aes,sse2")]
    unsafe fn key_expansion(key: [u8; 16]) -> [__m128i; 11] {
        let mut rk = [_mm_setzero_si128(); 11];
        rk[0] = _mm_loadu_si128(key.as_ptr() as *const __m128i);
        rk[1] = expand_step::<0x01>(rk[0]);
        rk[2] = expand_step::<0x02>(rk[1]);
        rk[3] = expand_step::<0x04>(rk[2]);
        rk[4] = expand_step::<0x08>(rk[3]);
        rk[5] = expand_step::<0x10>(rk[4]);
        rk[6] = expand_step::<0x20>(rk[5]);
        rk[7] = expand_step::<0x40>(rk[6]);
        rk[8] = expand_step::<0x80>(rk[7]);
        rk[9] = expand_step::<0x1b>(rk[8]);
        rk[10] = expand_step::<0x36>(rk[9]);
        rk
    }

    #[target_feature(enable = "aes,sse2")]
    unsafe fn expand_step<const RCON: i32>(prev: __m128i) -> __m128i {
        // Given prev = (W0, W1, W2, W3) (4 little-endian 32-bit words inside
        // the __m128i), produce next = (W0^T, W0^W1^T, W0^W1^W2^T,
        // W0^W1^W2^W3^T) where T = SubWord(RotWord(W3)) ^ Rcon.
        //
        // Two shifts of the *running* k give us exactly the cumulative XOR
        // we need: each shift on the already-XORed value compresses what
        // Intel's reference does in three shifts of an evolving temp3.
        //
        //   step 1: k ^= slli<4>(k)  → (W0, W0^W1, W1^W2, W2^W3)
        //   step 2: k ^= slli<8>(k)  → (W0, W0^W1, W0^W1^W2, W0^W1^W2^W3)
        //
        // (slli<8> applied to the already-shifted lane 1 picks up `W0^W1`,
        // which is exactly what Intel's third shift+XOR adds back via a
        // separate temp3 chain.)
        let assist = _mm_aeskeygenassist_si128::<RCON>(prev);
        let temp = _mm_shuffle_epi32::<0xff>(assist); // (T, T, T, T)
        let mut k = prev;
        k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
        k = _mm_xor_si128(k, _mm_slli_si128::<8>(k));
        _mm_xor_si128(k, temp)
    }

    /// Build the decryption round-key schedule from the encryption schedule.
    /// `aesdec`/`aesdeclast` implement the equivalent inverse cipher, which
    /// expects the inverse-MixColumns of every middle round key.
    ///
    /// Layout: dec[0] = enc[10]            (used by initial XOR + first aesdec)
    ///         dec[i] = InvMixColumns(enc[10-i])  for i in 1..10
    ///         dec[10] = enc[0]            (used by aesdeclast)
    #[target_feature(enable = "aes,sse2")]
    unsafe fn inverse_round_keys(enc: &[__m128i; 11]) -> [__m128i; 11] {
        let mut dec = [_mm_setzero_si128(); 11];
        dec[0] = enc[10];
        for i in 1..10 {
            dec[i] = _mm_aesimc_si128(enc[10 - i]);
        }
        dec[10] = enc[0];
        dec
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS-197 Appendix B test vector. Single-block AES-128 ECB.
    const FIPS_KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    const FIPS_PLAIN: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ];
    const FIPS_CIPHER: [u8; 16] = [
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef,
        0x97,
    ];

    fn run_kat(kind: BackendKind) {
        let aes = Aes128::with_backend(kind, &FIPS_KEY).expect("backend init");
        let mut buf = FIPS_PLAIN;
        aes.encrypt_blocks(&mut buf).expect("encrypt");
        assert_eq!(buf, FIPS_CIPHER, "FIPS-197 KAT (encrypt) failed for {:?}", kind);
        aes.decrypt_blocks(&mut buf).expect("decrypt");
        assert_eq!(buf, FIPS_PLAIN, "FIPS-197 KAT (decrypt) failed for {:?}", kind);
    }

    #[test]
    fn fips197_kat_aws() {
        run_kat(BackendKind::Aws);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn fips197_kat_native() {
        if !std::is_x86_feature_detected!("aes") {
            eprintln!("skipping: host has no AES-NI");
            return;
        }
        run_kat(BackendKind::Native);
    }

    /// Multi-block ECB on each backend should be equivalent to running
    /// `encrypt_blocks` on each 16-byte block individually.
    #[test]
    fn multiblock_consistency_aws() {
        run_multiblock(BackendKind::Aws);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn multiblock_consistency_native() {
        if !std::is_x86_feature_detected!("aes") {
            return;
        }
        run_multiblock(BackendKind::Native);
    }

    fn run_multiblock(kind: BackendKind) {
        let key: [u8; 16] = [0x42; 16];
        let aes = Aes128::with_backend(kind, &key).unwrap();

        // 32 blocks (covers the 8-block pipelined path + 1-block remainder).
        let mut bulk = [0u8; 16 * 32];
        for (i, b) in bulk.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }
        let original = bulk;

        // Encrypt all-at-once
        aes.encrypt_blocks(&mut bulk).unwrap();
        let bulk_encrypted = bulk;

        // Encrypt block-by-block on a separate copy
        let mut block_by_block = original;
        for chunk in block_by_block.chunks_exact_mut(16) {
            aes.encrypt_blocks(chunk).unwrap();
        }
        assert_eq!(
            bulk_encrypted, block_by_block,
            "multi-block != block-by-block for {:?}",
            kind
        );

        // Round-trip
        aes.decrypt_blocks(&mut bulk).unwrap();
        assert_eq!(bulk, original, "decrypt round-trip failed for {:?}", kind);
    }

    /// Cross-backend parity: native and aws produce identical ciphertext.
    /// Only meaningful when both backends are available (x86_64 + AES-NI host).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn cross_backend_parity() {
        if !std::is_x86_feature_detected!("aes") {
            return;
        }

        let test_lengths = [16, 32, 64, 128, 16 * 7, 16 * 8, 16 * 9, 16 * 32, 16 * 64];
        for &n_bytes in &test_lengths {
            // Try a few different keys so we exercise different round-key
            // schedules.
            for key_seed in [0x00u8, 0x42, 0xa5, 0xff] {
                let key = [key_seed; 16];
                let mut buf_native = vec![0u8; n_bytes];
                for (i, b) in buf_native.iter_mut().enumerate() {
                    *b = ((i ^ key_seed as usize) & 0xff) as u8;
                }
                let mut buf_aws = buf_native.clone();

                let native = Aes128::with_backend(BackendKind::Native, &key).unwrap();
                let aws = Aes128::with_backend(BackendKind::Aws, &key).unwrap();

                native.encrypt_blocks(&mut buf_native).unwrap();
                aws.encrypt_blocks(&mut buf_aws).unwrap();
                assert_eq!(
                    buf_native, buf_aws,
                    "encrypt parity failed: n={} key_seed=0x{:02x}",
                    n_bytes, key_seed
                );

                native.decrypt_blocks(&mut buf_native).unwrap();
                aws.decrypt_blocks(&mut buf_aws).unwrap();
                assert_eq!(
                    buf_native, buf_aws,
                    "decrypt parity failed: n={} key_seed=0x{:02x}",
                    n_bytes, key_seed
                );
            }
        }
    }
}
