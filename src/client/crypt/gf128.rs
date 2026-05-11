//! GF(2^128) doubling/tripling for OCB2 deltas.
//!
//! `double(d)` computes d * x in GF(2^128) modulo the irreducible polynomial
//! x^128 + x^7 + x^2 + x + 1 (the "0x87" in the low byte). Values are stored
//! in `d` in big-endian byte order: byte 0 is the MSB of the 128-bit value.
//!
//! `triple(d)` computes d * (x + 1) = double(d) XOR d.
//!
//! ## Backends
//!
//!   - `Scalar`: pure-Rust 64-bit-word implementation. Reads the BE bytes as
//!     two u64s, performs a 128-bit shift with carry, writes back. Always
//!     available.
//!   - `Simd`: SSE2 + SSSE3 intrinsics. Same algorithm but the entire
//!     delta-chain loop runs inside one `#[target_feature]`-tagged function
//!     so the compiler inlines the intrinsics; this matters because each
//!     individual `double` is too small to absorb function-call overhead.
//!
//! ## Hot path: `fill_chain`
//!
//! OCB2 needs a chain of deltas where `chain[i+1] = double(chain[i])`. The
//! loop has a sequential dependency, but we can amortize the
//! backend-dispatch cost by handing the *whole chain* to the backend once.
//! For the SIMD path this also lets us keep the running value in LE form
//! between iterations and only byte-reverse once per stored chain entry.
//!
//! `triple` is called only once per OCB2 encrypt/decrypt, so it stays a
//! per-call dispatch.
//!
//! Probed once at startup via `probe()`; choice is cached and copied into
//! each `Ocb2` instance so the per-call match is a 1-byte compare.

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendKind {
    Scalar,
    Simd,
}

static BACKEND: OnceLock<BackendKind> = OnceLock::new();

/// Probe the host for SSE2+SSSE3 and cache the choice. Logs the decision via
/// `tracing::info!` on the first call. Subsequent calls just read the cache.
pub fn probe() -> &'static str {
    let kind = *BACKEND.get_or_init(|| {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("sse2") && std::is_x86_feature_detected!("ssse3") {
                tracing::info!(
                    backend = "simd-ssse3",
                    arch = "x86_64",
                    "GF(2^128) backend probe: using SSE2+SSSE3 SIMD"
                );
                return BackendKind::Simd;
            }
        }
        tracing::info!(
            backend = "scalar-u64",
            arch = std::env::consts::ARCH,
            "GF(2^128) backend probe: using scalar 64-bit-word fallback"
        );
        BackendKind::Scalar
    });
    match kind {
        BackendKind::Simd => "simd-ssse3",
        BackendKind::Scalar => "scalar-u64",
    }
}

fn current_backend() -> BackendKind {
    *BACKEND.get_or_init(|| {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("sse2") && std::is_x86_feature_detected!("ssse3") {
                return BackendKind::Simd;
            }
        }
        BackendKind::Scalar
    })
}

/// Per-instance cache of the chosen backend. Stored inline in `Ocb2` so the
/// per-call check is a 1-byte compare against the embedded enum tag.
#[derive(Debug, Clone, Copy)]
pub struct Gf128Ops {
    backend: BackendKind,
}

impl Gf128Ops {
    pub fn new() -> Self {
        Self {
            backend: current_backend(),
        }
    }

    /// Fill `chain[1..=count]` with iterated doublings of `chain[0]`.
    ///
    /// `chain[0]` must already hold the seed value (BE byte order, 16 bytes).
    /// `count` must satisfy `count + 1 <= chain.len()`.
    ///
    /// For tiny chains (count <= 4 — silence/comfort-noise packets) the
    /// scalar u64 path is taken unconditionally because the SIMD setup
    /// (BE↔LE byte-reverses + per-call dispatch) is more expensive than the
    /// few u64 shifts the chain actually needs.
    #[inline]
    pub fn fill_chain(self, chain: &mut [[u8; 16]], count: usize) {
        debug_assert!(count + 1 <= chain.len());
        if count <= 4 {
            scalar::fill_chain(chain, count);
            return;
        }
        match self.backend {
            #[cfg(target_arch = "x86_64")]
            BackendKind::Simd => {
                // SAFETY: `Simd` is only chosen when SSE2+SSSE3 was detected.
                unsafe { simd::fill_chain(chain, count) }
            }
            #[cfg(not(target_arch = "x86_64"))]
            BackendKind::Simd => scalar::fill_chain(chain, count),
            BackendKind::Scalar => scalar::fill_chain(chain, count),
        }
    }

    #[inline]
    pub fn triple(self, d: &mut [u8; 16]) {
        match self.backend {
            #[cfg(target_arch = "x86_64")]
            BackendKind::Simd => {
                // SAFETY: see `fill_chain`.
                unsafe { simd::triple(d) }
            }
            #[cfg(not(target_arch = "x86_64"))]
            BackendKind::Simd => scalar::triple(d),
            BackendKind::Scalar => scalar::triple(d),
        }
    }
}

// ── Scalar (u64-word) ────────────────────────────────────────────────────────

mod scalar {
    /// Compute `2 * v` in GF(2^128) where `v` is encoded as two big-endian
    /// u64 halves `(hi, lo)`. Returns the new `(hi, lo)`.
    #[inline]
    fn double_u64(hi: u64, lo: u64) -> (u64, u64) {
        let carry = hi >> 63;
        let new_hi = (hi << 1) | (lo >> 63);
        let new_lo = (lo << 1) ^ carry.wrapping_mul(0x87);
        (new_hi, new_lo)
    }

    pub fn double(d: &mut [u8; 16]) {
        let hi = u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]);
        let lo = u64::from_be_bytes([d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]]);
        let (nh, nl) = double_u64(hi, lo);
        d[0..8].copy_from_slice(&nh.to_be_bytes());
        d[8..16].copy_from_slice(&nl.to_be_bytes());
    }

    pub fn triple(d: &mut [u8; 16]) {
        let hi = u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]);
        let lo = u64::from_be_bytes([d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]]);
        let (dh, dl) = double_u64(hi, lo);
        d[0..8].copy_from_slice(&(hi ^ dh).to_be_bytes());
        d[8..16].copy_from_slice(&(lo ^ dl).to_be_bytes());
    }

    #[inline]
    pub fn fill_chain(chain: &mut [[u8; 16]], count: usize) {
        let seed = chain[0];
        let mut hi = u64::from_be_bytes([
            seed[0], seed[1], seed[2], seed[3], seed[4], seed[5], seed[6], seed[7],
        ]);
        let mut lo = u64::from_be_bytes([
            seed[8], seed[9], seed[10], seed[11], seed[12], seed[13], seed[14], seed[15],
        ]);
        for i in 1..=count {
            let (nh, nl) = double_u64(hi, lo);
            hi = nh;
            lo = nl;
            chain[i][0..8].copy_from_slice(&hi.to_be_bytes());
            chain[i][8..16].copy_from_slice(&lo.to_be_bytes());
        }
    }
}

// ── SIMD (SSE2 + SSSE3) ──────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod simd {
    use std::arch::x86_64::*;

    /// Mask for `_mm_shuffle_epi8` that byte-reverses a 16-byte vector.
    /// Applied once each side of the shift loop converts BE↔LE.
    #[inline]
    #[target_feature(enable = "sse2,ssse3")]
    unsafe fn reverse_mask() -> __m128i {
        _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
    }

    /// In LE byte order: lane 0 = LSB half, lane 1 = MSB half. Compute
    /// `2 * le` in GF(2^128). Carry from bit 63 of lane 0 propagates into
    /// bit 0 of lane 1; carry-out from bit 127 reduces by XOR'ing 0x87 into
    /// the LSB byte (byte 0).
    #[inline]
    #[target_feature(enable = "sse2,ssse3")]
    unsafe fn double_le(le: __m128i) -> __m128i {
        let shifted = _mm_slli_epi64::<1>(le);
        let carry_within = _mm_srli_epi64::<63>(le);
        let carry_to_hi = _mm_slli_si128::<8>(carry_within);
        let doubled = _mm_or_si128(shifted, carry_to_hi);

        // Carry-out from bit 127 = MSB of byte 15 of `le`.
        let mask = _mm_movemask_epi8(le) as u32;
        let carry_out = (mask >> 15) & 1;
        let xor_byte = (carry_out as u8 * 0x87) as i8;
        // XOR 0x87 (or 0) into byte 0 of LE.
        let xor_term = _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, xor_byte);
        _mm_xor_si128(doubled, xor_term)
    }

    /// Iterate `double_le` `count` times, byte-reversing each result back to
    /// BE on store. Crucially, the running value `v` stays in LE form
    /// between iterations — only the *seed* and each *output* are
    /// byte-reversed, not every step.
    #[target_feature(enable = "sse2,ssse3")]
    pub unsafe fn fill_chain(chain: &mut [[u8; 16]], count: usize) {
        let rev = reverse_mask();
        let seed = _mm_loadu_si128(chain[0].as_ptr() as *const __m128i);
        let mut v = _mm_shuffle_epi8(seed, rev);
        for i in 1..=count {
            v = double_le(v);
            let be = _mm_shuffle_epi8(v, rev);
            _mm_storeu_si128(chain[i].as_mut_ptr() as *mut __m128i, be);
        }
    }

    /// `triple(d) = double(d) XOR d`, computed in one fused pass.
    #[target_feature(enable = "sse2,ssse3")]
    pub unsafe fn triple(d: &mut [u8; 16]) {
        let rev = reverse_mask();
        let v = _mm_loadu_si128(d.as_ptr() as *const __m128i);
        let le = _mm_shuffle_epi8(v, rev);
        let doubled = double_le(le);
        let tripled = _mm_xor_si128(doubled, le);
        let be = _mm_shuffle_epi8(tripled, rev);
        _mm_storeu_si128(d.as_mut_ptr() as *mut __m128i, be);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn known_double_vectors() -> Vec<([u8; 16], [u8; 16])> {
        vec![
            // 0 → 0
            ([0u8; 16], [0u8; 16]),
            // [1, 0, ..., 0] = 2^120 → 2^121 = [2, 0, ..., 0]
            (
                {
                    let mut a = [0u8; 16];
                    a[0] = 0x01;
                    a
                },
                {
                    let mut a = [0u8; 16];
                    a[0] = 0x02;
                    a
                },
            ),
            // [0, ..., 0, 1] = 1 → 2 = [0, ..., 0, 2]
            (
                {
                    let mut a = [0u8; 16];
                    a[15] = 0x01;
                    a
                },
                {
                    let mut a = [0u8; 16];
                    a[15] = 0x02;
                    a
                },
            ),
            // MSB only [0x80, 0, ..., 0] = 2^127 → reduces to 0x87 in low byte
            (
                {
                    let mut a = [0u8; 16];
                    a[0] = 0x80;
                    a
                },
                {
                    let mut a = [0u8; 16];
                    a[15] = 0x87;
                    a
                },
            ),
            // [0xff; 16] → [0xff×15, 0x79] (carry through every byte then reduce)
            (
                [0xff; 16],
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0x79,
                ],
            ),
            // Mixed pattern from the original ocb2.rs times2 test.
            (
                [
                    0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xfe,
                ],
                [
                    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0x7b,
                ],
            ),
        ]
    }

    #[test]
    fn double_scalar_known_vectors() {
        for (input, expected) in known_double_vectors() {
            let mut d = input;
            scalar::double(&mut d);
            assert_eq!(d, expected, "scalar double({:02x?})", input);
        }
    }

    #[test]
    fn triple_scalar_known_vector() {
        // `[0x80, 0xff×14, 0xfe]` triples to `[0x81, 0×14, 0x85]` (= double XOR self).
        let input = [
            0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe,
        ];
        let expected = [
            0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x85,
        ];
        let mut d = input;
        scalar::triple(&mut d);
        assert_eq!(d, expected);
    }

    #[test]
    fn triple_scalar_equals_double_xor_self() {
        let inputs: [[u8; 16]; 6] = [
            [0u8; 16],
            [0xff; 16],
            [0x42; 16],
            {
                let mut a = [0u8; 16];
                a[0] = 0x80;
                a
            },
            {
                let mut a = [0u8; 16];
                a[15] = 0x01;
                a
            },
            [
                0xa5, 0xb6, 0xc7, 0xd8, 0xe9, 0xfa, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72,
                0x83, 0x94,
            ],
        ];
        for input in inputs {
            let mut doubled = input;
            scalar::double(&mut doubled);
            let mut tripled = input;
            scalar::triple(&mut tripled);
            let xor: [u8; 16] = std::array::from_fn(|i| doubled[i] ^ input[i]);
            assert_eq!(tripled, xor, "triple != double^input for {:02x?}", input);
        }
    }

    #[test]
    fn scalar_fill_chain_matches_iterated_double() {
        let seed = [
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        // Reference: iterated `double` calls.
        let mut reference: Vec<[u8; 16]> = vec![seed];
        let mut cur = seed;
        for _ in 0..32 {
            scalar::double(&mut cur);
            reference.push(cur);
        }

        // fill_chain.
        let mut chain = vec![[0u8; 16]; 33];
        chain[0] = seed;
        scalar::fill_chain(&mut chain, 32);

        assert_eq!(chain, reference);
    }

    fn parity_test_vectors() -> Vec<[u8; 16]> {
        vec![
            [0u8; 16],
            [0xff; 16],
            {
                let mut a = [0u8; 16];
                a[0] = 0x80;
                a
            },
            {
                let mut a = [0u8; 16];
                a[15] = 0x01;
                a
            },
            // High bit straddling the 64-bit lane boundary.
            {
                let mut a = [0u8; 16];
                a[7] = 0x80;
                a[8] = 0x01;
                a
            },
            [0x42u8; 16],
            [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [
                0xa5, 0xb6, 0xc7, 0xd8, 0xe9, 0xfa, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72,
                0x83, 0x94,
            ],
            // Carry chain through every byte.
            [
                0x40, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                0x80, 0x80,
            ],
        ]
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn simd_fill_chain_matches_scalar() {
        if !std::is_x86_feature_detected!("ssse3") {
            eprintln!("skipping: host has no SSSE3");
            return;
        }
        for seed in parity_test_vectors() {
            for &count in &[1usize, 2, 4, 8, 16, 32, 64] {
                let mut a_chain = vec![[0u8; 16]; count + 1];
                let mut b_chain = vec![[0u8; 16]; count + 1];
                a_chain[0] = seed;
                b_chain[0] = seed;
                scalar::fill_chain(&mut a_chain, count);
                unsafe { simd::fill_chain(&mut b_chain, count) };
                assert_eq!(
                    a_chain, b_chain,
                    "simd/scalar fill_chain diverged: seed={:02x?} count={}",
                    seed, count
                );
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn simd_triple_matches_scalar() {
        if !std::is_x86_feature_detected!("ssse3") {
            return;
        }
        for input in parity_test_vectors() {
            let mut a = input;
            let mut b = input;
            scalar::triple(&mut a);
            unsafe { simd::triple(&mut b) };
            assert_eq!(a, b, "triple parity failed for {:02x?}", input);
        }
    }

    /// Repeated doubling builds a 128-step chain — covers the full
    /// reduction-polynomial cycle for byte 0's MSB. Verify SIMD stays in
    /// lockstep with scalar.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn long_chain_parity() {
        if !std::is_x86_feature_detected!("ssse3") {
            return;
        }
        let mut seed = [0u8; 16];
        seed[15] = 0x01;
        let mut a_chain = vec![[0u8; 16]; 129];
        let mut b_chain = vec![[0u8; 16]; 129];
        a_chain[0] = seed;
        b_chain[0] = seed;
        scalar::fill_chain(&mut a_chain, 128);
        unsafe { simd::fill_chain(&mut b_chain, 128) };
        assert_eq!(a_chain, b_chain);
    }
}
