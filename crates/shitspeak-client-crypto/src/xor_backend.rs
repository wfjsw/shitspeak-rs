//! Runtime-dispatched XOR and XOR-fold primitives used by OCB2.
//!
//! The OCB2 hot loops operate on independent 16-byte blocks.  This module
//! keeps those loops in one small backend so the rest of the cipher can stay
//! in safe Rust while still using unaligned SSE2/AVX2 loads and stores when
//! the host supports them.

use std::sync::OnceLock;

const BLOCK_SIZE: usize = 16;
const AVX2_THRESHOLD: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendKind {
    Scalar,
    Sse2,
    Avx2,
}

static BACKEND: OnceLock<BackendKind> = OnceLock::new();

#[derive(Debug, Clone, Copy)]
pub(crate) struct XorOps {
    kind: BackendKind,
}

impl XorOps {
    pub(crate) fn new() -> Self {
        Self {
            kind: current_backend(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(kind: BackendKind) -> Self {
        Self { kind }
    }

    #[cfg(test)]
    pub(crate) fn is_available(kind: BackendKind) -> bool {
        match kind {
            BackendKind::Scalar => true,
            BackendKind::Sse2 => has_feature("sse2"),
            BackendKind::Avx2 => has_feature("avx2"),
        }
    }

    #[inline]
    fn backend_for_len(self, len: usize) -> BackendKind {
        if len < BLOCK_SIZE {
            return BackendKind::Scalar;
        }
        if self.kind == BackendKind::Avx2 && len >= AVX2_THRESHOLD {
            return BackendKind::Avx2;
        }
        if self.kind != BackendKind::Scalar {
            return BackendKind::Sse2;
        }
        BackendKind::Scalar
    }

    pub(crate) fn xor_chain_into(self, dest: &mut [u8], src: &[u8], deltas: &[[u8; BLOCK_SIZE]]) {
        assert_eq!(dest.len(), src.len());
        assert_eq!(dest.len(), deltas.len() * BLOCK_SIZE);

        match self.backend_for_len(dest.len()) {
            BackendKind::Scalar => scalar::xor_chain_into(dest, src, deltas),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            BackendKind::Sse2 => unsafe { simd::xor_chain_into_sse2(dest, src, deltas) },
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            BackendKind::Sse2 => scalar::xor_chain_into(dest, src, deltas),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            BackendKind::Avx2 => unsafe { simd::xor_chain_into_avx2(dest, src, deltas) },
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            BackendKind::Avx2 => scalar::xor_chain_into(dest, src, deltas),
        }
    }

    pub(crate) fn xor_chain_in_place(self, dest: &mut [u8], deltas: &[[u8; BLOCK_SIZE]]) {
        assert_eq!(dest.len(), deltas.len() * BLOCK_SIZE);

        match self.backend_for_len(dest.len()) {
            BackendKind::Scalar => scalar::xor_chain_in_place(dest, deltas),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            BackendKind::Sse2 => unsafe { simd::xor_chain_in_place_sse2(dest, deltas) },
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            BackendKind::Sse2 => scalar::xor_chain_in_place(dest, deltas),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            BackendKind::Avx2 => unsafe { simd::xor_chain_in_place_avx2(dest, deltas) },
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            BackendKind::Avx2 => scalar::xor_chain_in_place(dest, deltas),
        }
    }

    pub(crate) fn xor_chain_in_place_and_fold_input(
        self,
        dest: &mut [u8],
        data: &[u8],
        deltas: &[[u8; BLOCK_SIZE]],
        checksum: &mut [u8; BLOCK_SIZE],
    ) {
        assert_eq!(dest.len(), data.len());
        assert_eq!(dest.len(), deltas.len() * BLOCK_SIZE);

        match self.backend_for_len(dest.len()) {
            BackendKind::Scalar => {
                scalar::xor_chain_in_place_and_fold_input(dest, data, deltas, checksum)
            }
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            BackendKind::Sse2 => unsafe {
                simd::xor_chain_in_place_and_fold_input_sse2(dest, data, deltas, checksum)
            },
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            BackendKind::Sse2 => {
                scalar::xor_chain_in_place_and_fold_input(dest, data, deltas, checksum)
            }
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            BackendKind::Avx2 => unsafe {
                simd::xor_chain_in_place_and_fold_input_avx2(dest, data, deltas, checksum)
            },
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            BackendKind::Avx2 => {
                scalar::xor_chain_in_place_and_fold_input(dest, data, deltas, checksum)
            }
        }
    }

    pub(crate) fn xor_chain_into_and_fold_output(
        self,
        dest: &mut [u8],
        src: &[u8],
        deltas: &[[u8; BLOCK_SIZE]],
        checksum: &mut [u8; BLOCK_SIZE],
    ) {
        assert_eq!(dest.len(), src.len());
        assert_eq!(dest.len(), deltas.len() * BLOCK_SIZE);

        match self.backend_for_len(dest.len()) {
            BackendKind::Scalar => {
                scalar::xor_chain_into_and_fold_output(dest, src, deltas, checksum)
            }
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            BackendKind::Sse2 => unsafe {
                simd::xor_chain_into_and_fold_output_sse2(dest, src, deltas, checksum)
            },
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            BackendKind::Sse2 => {
                scalar::xor_chain_into_and_fold_output(dest, src, deltas, checksum)
            }
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            BackendKind::Avx2 => unsafe {
                simd::xor_chain_into_and_fold_output_avx2(dest, src, deltas, checksum)
            },
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            BackendKind::Avx2 => {
                scalar::xor_chain_into_and_fold_output(dest, src, deltas, checksum)
            }
        }
    }

    pub(crate) fn xor_fold(self, checksum: &mut [u8; BLOCK_SIZE], data: &[u8]) {
        match self.backend_for_len(data.len()) {
            BackendKind::Scalar => scalar::xor_fold(checksum, data),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            BackendKind::Sse2 => unsafe { simd::xor_fold_sse2(checksum, data) },
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            BackendKind::Sse2 => scalar::xor_fold(checksum, data),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            BackendKind::Avx2 => unsafe { simd::xor_fold_avx2(checksum, data) },
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            BackendKind::Avx2 => scalar::xor_fold(checksum, data),
        }
    }
}

fn current_backend() -> BackendKind {
    *BACKEND.get_or_init(|| {
        if has_feature("avx2") {
            BackendKind::Avx2
        } else if has_feature("sse2") {
            BackendKind::Sse2
        } else {
            BackendKind::Scalar
        }
    })
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
fn has_feature(feature: &str) -> bool {
    match feature {
        "sse2" => std::is_x86_feature_detected!("sse2"),
        "avx2" => std::is_x86_feature_detected!("avx2"),
        _ => false,
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
#[inline]
fn has_feature(_feature: &str) -> bool {
    false
}

mod scalar {
    use super::BLOCK_SIZE;

    #[inline]
    pub(super) fn xor_chain_into(dest: &mut [u8], src: &[u8], deltas: &[[u8; BLOCK_SIZE]]) {
        for (block_index, delta) in deltas.iter().enumerate() {
            let offset = block_index * BLOCK_SIZE;
            for j in 0..BLOCK_SIZE {
                dest[offset + j] = src[offset + j] ^ delta[j];
            }
        }
    }

    #[inline]
    pub(super) fn xor_chain_in_place(dest: &mut [u8], deltas: &[[u8; BLOCK_SIZE]]) {
        for (block_index, delta) in deltas.iter().enumerate() {
            let offset = block_index * BLOCK_SIZE;
            for j in 0..BLOCK_SIZE {
                dest[offset + j] ^= delta[j];
            }
        }
    }

    #[inline]
    pub(super) fn xor_chain_in_place_and_fold_input(
        dest: &mut [u8],
        data: &[u8],
        deltas: &[[u8; BLOCK_SIZE]],
        checksum: &mut [u8; BLOCK_SIZE],
    ) {
        for (block_index, delta) in deltas.iter().enumerate() {
            let offset = block_index * BLOCK_SIZE;
            for j in 0..BLOCK_SIZE {
                dest[offset + j] ^= delta[j];
                checksum[j] ^= data[offset + j];
            }
        }
    }

    #[inline]
    pub(super) fn xor_chain_into_and_fold_output(
        dest: &mut [u8],
        src: &[u8],
        deltas: &[[u8; BLOCK_SIZE]],
        checksum: &mut [u8; BLOCK_SIZE],
    ) {
        for (block_index, delta) in deltas.iter().enumerate() {
            let offset = block_index * BLOCK_SIZE;
            for j in 0..BLOCK_SIZE {
                let plain = src[offset + j] ^ delta[j];
                dest[offset + j] = plain;
                checksum[j] ^= plain;
            }
        }
    }

    #[inline]
    pub(super) fn xor_fold(checksum: &mut [u8; BLOCK_SIZE], data: &[u8]) {
        for (i, byte) in data.iter().enumerate() {
            checksum[i % BLOCK_SIZE] ^= byte;
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod simd {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    use super::BLOCK_SIZE;

    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn load128(ptr: *const u8) -> __m128i {
        unsafe { _mm_loadu_si128(ptr.cast::<__m128i>()) }
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn store128(ptr: *mut u8, value: __m128i) {
        unsafe { _mm_storeu_si128(ptr.cast::<__m128i>(), value) }
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn xor128(left: __m128i, right: __m128i) -> __m128i {
        _mm_xor_si128(left, right)
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn load256(ptr: *const u8) -> __m256i {
        unsafe { _mm256_loadu_si256(ptr.cast::<__m256i>()) }
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn store256(ptr: *mut u8, value: __m256i) {
        unsafe { _mm256_storeu_si256(ptr.cast::<__m256i>(), value) }
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn xor256(left: __m256i, right: __m256i) -> __m256i {
        _mm256_xor_si256(left, right)
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn reduce256(value: __m256i) -> __m128i {
        let low = _mm256_castsi256_si128(value);
        let high = _mm256_extracti128_si256::<1>(value);
        _mm_xor_si128(low, high)
    }

    #[target_feature(enable = "sse2")]
    pub(super) unsafe fn xor_chain_into_sse2(
        dest: &mut [u8],
        src: &[u8],
        deltas: &[[u8; BLOCK_SIZE]],
    ) {
        let delta_ptr = deltas.as_ptr().cast::<u8>();
        let mut offset = 0;
        while offset + BLOCK_SIZE <= dest.len() {
            let value = xor128(unsafe { load128(src.as_ptr().add(offset)) }, unsafe {
                load128(delta_ptr.add(offset))
            });
            unsafe { store128(dest.as_mut_ptr().add(offset), value) };
            offset += BLOCK_SIZE;
        }
        while offset < dest.len() {
            dest[offset] = src[offset] ^ unsafe { *delta_ptr.add(offset) };
            offset += 1;
        }
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn xor_chain_into_avx2(
        dest: &mut [u8],
        src: &[u8],
        deltas: &[[u8; BLOCK_SIZE]],
    ) {
        let delta_ptr = deltas.as_ptr().cast::<u8>();
        let mut offset = 0;
        while offset + 32 <= dest.len() {
            let value = xor256(unsafe { load256(src.as_ptr().add(offset)) }, unsafe {
                load256(delta_ptr.add(offset))
            });
            unsafe { store256(dest.as_mut_ptr().add(offset), value) };
            offset += 32;
        }
        if dest.len() - offset >= BLOCK_SIZE {
            let block_offset = offset / BLOCK_SIZE;
            unsafe {
                xor_chain_into_sse2(&mut dest[offset..], &src[offset..], &deltas[block_offset..])
            };
            return;
        }
        while offset < dest.len() {
            dest[offset] = src[offset] ^ unsafe { *delta_ptr.add(offset) };
            offset += 1;
        }
    }

    #[target_feature(enable = "sse2")]
    pub(super) unsafe fn xor_chain_in_place_sse2(dest: &mut [u8], deltas: &[[u8; BLOCK_SIZE]]) {
        let delta_ptr = deltas.as_ptr().cast::<u8>();
        let mut offset = 0;
        while offset + BLOCK_SIZE <= dest.len() {
            let value = xor128(unsafe { load128(dest.as_ptr().add(offset)) }, unsafe {
                load128(delta_ptr.add(offset))
            });
            unsafe { store128(dest.as_mut_ptr().add(offset), value) };
            offset += BLOCK_SIZE;
        }
        while offset < dest.len() {
            dest[offset] ^= unsafe { *delta_ptr.add(offset) };
            offset += 1;
        }
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn xor_chain_in_place_avx2(dest: &mut [u8], deltas: &[[u8; BLOCK_SIZE]]) {
        let delta_ptr = deltas.as_ptr().cast::<u8>();
        let mut offset = 0;
        while offset + 32 <= dest.len() {
            let value = xor256(unsafe { load256(dest.as_ptr().add(offset)) }, unsafe {
                load256(delta_ptr.add(offset))
            });
            unsafe { store256(dest.as_mut_ptr().add(offset), value) };
            offset += 32;
        }
        if dest.len() - offset >= BLOCK_SIZE {
            let block_offset = offset / BLOCK_SIZE;
            unsafe { xor_chain_in_place_sse2(&mut dest[offset..], &deltas[block_offset..]) };
            return;
        }
        while offset < dest.len() {
            dest[offset] ^= unsafe { *delta_ptr.add(offset) };
            offset += 1;
        }
    }

    #[target_feature(enable = "sse2")]
    pub(super) unsafe fn xor_chain_in_place_and_fold_input_sse2(
        dest: &mut [u8],
        data: &[u8],
        deltas: &[[u8; BLOCK_SIZE]],
        checksum: &mut [u8; BLOCK_SIZE],
    ) {
        let delta_ptr = deltas.as_ptr().cast::<u8>();
        let mut checksum_value = unsafe { load128(checksum.as_ptr()) };
        let mut offset = 0;
        while offset + BLOCK_SIZE <= dest.len() {
            let value = xor128(unsafe { load128(dest.as_ptr().add(offset)) }, unsafe {
                load128(delta_ptr.add(offset))
            });
            unsafe { store128(dest.as_mut_ptr().add(offset), value) };
            checksum_value = xor128(checksum_value, unsafe {
                load128(data.as_ptr().add(offset))
            });
            offset += BLOCK_SIZE;
        }
        unsafe { store128(checksum.as_mut_ptr(), checksum_value) };
        while offset < dest.len() {
            dest[offset] ^= unsafe { *delta_ptr.add(offset) };
            checksum[offset % BLOCK_SIZE] ^= data[offset];
            offset += 1;
        }
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn xor_chain_in_place_and_fold_input_avx2(
        dest: &mut [u8],
        data: &[u8],
        deltas: &[[u8; BLOCK_SIZE]],
        checksum: &mut [u8; BLOCK_SIZE],
    ) {
        let delta_ptr = deltas.as_ptr().cast::<u8>();
        let mut checksum_value = unsafe { _mm256_setzero_si256() };
        let mut offset = 0;
        while offset + 32 <= dest.len() {
            let value = xor256(unsafe { load256(dest.as_ptr().add(offset)) }, unsafe {
                load256(delta_ptr.add(offset))
            });
            unsafe { store256(dest.as_mut_ptr().add(offset), value) };
            checksum_value = xor256(checksum_value, unsafe {
                load256(data.as_ptr().add(offset))
            });
            offset += 32;
        }
        let folded = unsafe { reduce256(checksum_value) };
        let current = unsafe { load128(checksum.as_ptr()) };
        unsafe { store128(checksum.as_mut_ptr(), xor128(current, folded)) };
        if dest.len() - offset >= BLOCK_SIZE {
            let block_offset = offset / BLOCK_SIZE;
            unsafe {
                xor_chain_in_place_and_fold_input_sse2(
                    &mut dest[offset..],
                    &data[offset..],
                    &deltas[block_offset..],
                    checksum,
                )
            };
            return;
        }
        while offset < dest.len() {
            dest[offset] ^= unsafe { *delta_ptr.add(offset) };
            checksum[offset % BLOCK_SIZE] ^= data[offset];
            offset += 1;
        }
    }

    #[target_feature(enable = "sse2")]
    pub(super) unsafe fn xor_chain_into_and_fold_output_sse2(
        dest: &mut [u8],
        src: &[u8],
        deltas: &[[u8; BLOCK_SIZE]],
        checksum: &mut [u8; BLOCK_SIZE],
    ) {
        let delta_ptr = deltas.as_ptr().cast::<u8>();
        let mut checksum_value = unsafe { load128(checksum.as_ptr()) };
        let mut offset = 0;
        while offset + BLOCK_SIZE <= dest.len() {
            let value = xor128(unsafe { load128(src.as_ptr().add(offset)) }, unsafe {
                load128(delta_ptr.add(offset))
            });
            unsafe { store128(dest.as_mut_ptr().add(offset), value) };
            checksum_value = xor128(checksum_value, value);
            offset += BLOCK_SIZE;
        }
        unsafe { store128(checksum.as_mut_ptr(), checksum_value) };
        while offset < dest.len() {
            let value = src[offset] ^ unsafe { *delta_ptr.add(offset) };
            dest[offset] = value;
            checksum[offset % BLOCK_SIZE] ^= value;
            offset += 1;
        }
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn xor_chain_into_and_fold_output_avx2(
        dest: &mut [u8],
        src: &[u8],
        deltas: &[[u8; BLOCK_SIZE]],
        checksum: &mut [u8; BLOCK_SIZE],
    ) {
        let delta_ptr = deltas.as_ptr().cast::<u8>();
        let mut checksum_value = unsafe { _mm256_setzero_si256() };
        let mut offset = 0;
        while offset + 32 <= dest.len() {
            let value = xor256(unsafe { load256(src.as_ptr().add(offset)) }, unsafe {
                load256(delta_ptr.add(offset))
            });
            unsafe { store256(dest.as_mut_ptr().add(offset), value) };
            checksum_value = xor256(checksum_value, value);
            offset += 32;
        }
        let folded = unsafe { reduce256(checksum_value) };
        let current = unsafe { load128(checksum.as_ptr()) };
        unsafe { store128(checksum.as_mut_ptr(), xor128(current, folded)) };
        if dest.len() - offset >= BLOCK_SIZE {
            let block_offset = offset / BLOCK_SIZE;
            unsafe {
                xor_chain_into_and_fold_output_sse2(
                    &mut dest[offset..],
                    &src[offset..],
                    &deltas[block_offset..],
                    checksum,
                )
            };
            return;
        }
        while offset < dest.len() {
            let value = src[offset] ^ unsafe { *delta_ptr.add(offset) };
            dest[offset] = value;
            checksum[offset % BLOCK_SIZE] ^= value;
            offset += 1;
        }
    }

    #[target_feature(enable = "sse2")]
    pub(super) unsafe fn xor_fold_sse2(checksum: &mut [u8; BLOCK_SIZE], data: &[u8]) {
        let mut checksum_value = unsafe { load128(checksum.as_ptr()) };
        let mut offset = 0;
        while offset + BLOCK_SIZE <= data.len() {
            checksum_value = xor128(checksum_value, unsafe {
                load128(data.as_ptr().add(offset))
            });
            offset += BLOCK_SIZE;
        }
        unsafe { store128(checksum.as_mut_ptr(), checksum_value) };
        while offset < data.len() {
            checksum[offset % BLOCK_SIZE] ^= data[offset];
            offset += 1;
        }
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn xor_fold_avx2(checksum: &mut [u8; BLOCK_SIZE], data: &[u8]) {
        let mut checksum_value = unsafe { _mm256_setzero_si256() };
        let mut offset = 0;
        while offset + 32 <= data.len() {
            checksum_value = xor256(checksum_value, unsafe {
                load256(data.as_ptr().add(offset))
            });
            offset += 32;
        }
        let folded = unsafe { reduce256(checksum_value) };
        let current = unsafe { load128(checksum.as_ptr()) };
        unsafe { store128(checksum.as_mut_ptr(), xor128(current, folded)) };
        if data.len() - offset >= BLOCK_SIZE {
            unsafe { xor_fold_sse2(checksum, &data[offset..]) };
            return;
        }
        while offset < data.len() {
            checksum[offset % BLOCK_SIZE] ^= data[offset];
            offset += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(37) ^ seed)
            .collect()
    }

    fn deltas(blocks: usize, seed: u8) -> Vec<[u8; BLOCK_SIZE]> {
        (0..blocks)
            .map(|block| {
                let mut value = [0u8; BLOCK_SIZE];
                for (i, byte) in value.iter_mut().enumerate() {
                    *byte = (block as u8).wrapping_mul(19) ^ (i as u8).wrapping_mul(11) ^ seed;
                }
                value
            })
            .collect()
    }

    #[test]
    fn backend_operations_are_byte_identical() {
        let kinds = [BackendKind::Scalar, BackendKind::Sse2, BackendKind::Avx2];
        let block_lengths = [0, 16, 32, 48, 64, 80, 96, 128, 160, 768, 1024];
        let fold_lengths = [0, 1, 15, 16, 17, 31, 32, 47, 64, 65, 175, 768, 1024];
        let scalar = XorOps::for_test(BackendKind::Scalar);

        for &len in &block_lengths {
            let source = bytes(len, 0x31);
            let original = bytes(len, 0x72);
            let deltas = deltas(len / BLOCK_SIZE, 0xa5);

            let mut expected = vec![0u8; len];
            scalar.xor_chain_into(&mut expected, &source, &deltas);

            let mut expected_in_place = original.clone();
            scalar.xor_chain_in_place(&mut expected_in_place, &deltas);

            let mut expected_input = original.clone();
            let mut expected_input_checksum = [0x5au8; BLOCK_SIZE];
            scalar.xor_chain_in_place_and_fold_input(
                &mut expected_input,
                &source,
                &deltas,
                &mut expected_input_checksum,
            );

            let mut expected_output = vec![0u8; len];
            let mut expected_output_checksum = [0x96u8; BLOCK_SIZE];
            scalar.xor_chain_into_and_fold_output(
                &mut expected_output,
                &source,
                &deltas,
                &mut expected_output_checksum,
            );

            for &kind in &kinds {
                if !XorOps::is_available(kind) {
                    continue;
                }
                let ops = XorOps::for_test(kind);

                let mut actual = vec![0u8; len];
                ops.xor_chain_into(&mut actual, &source, &deltas);
                assert_eq!(actual, expected, "xor_chain_into {kind:?} len={len}");

                let mut actual_in_place = original.clone();
                ops.xor_chain_in_place(&mut actual_in_place, &deltas);
                assert_eq!(
                    actual_in_place, expected_in_place,
                    "xor_chain_in_place {kind:?} len={len}"
                );

                let mut actual_input = original.clone();
                let mut actual_input_checksum = [0x5au8; BLOCK_SIZE];
                ops.xor_chain_in_place_and_fold_input(
                    &mut actual_input,
                    &source,
                    &deltas,
                    &mut actual_input_checksum,
                );
                assert_eq!(
                    actual_input, expected_input,
                    "fused input {kind:?} len={len}"
                );
                assert_eq!(
                    actual_input_checksum, expected_input_checksum,
                    "fused input checksum {kind:?} len={len}"
                );

                let mut actual_output = vec![0u8; len];
                let mut actual_output_checksum = [0x96u8; BLOCK_SIZE];
                ops.xor_chain_into_and_fold_output(
                    &mut actual_output,
                    &source,
                    &deltas,
                    &mut actual_output_checksum,
                );
                assert_eq!(
                    actual_output, expected_output,
                    "fused output {kind:?} len={len}"
                );
                assert_eq!(
                    actual_output_checksum, expected_output_checksum,
                    "fused output checksum {kind:?} len={len}"
                );
            }
        }

        for &len in &fold_lengths {
            let data = bytes(len, 0x4c);
            let mut expected = [0x3du8; BLOCK_SIZE];
            scalar.xor_fold(&mut expected, &data);

            for &kind in &kinds {
                if !XorOps::is_available(kind) {
                    continue;
                }
                let mut actual = [0x3du8; BLOCK_SIZE];
                XorOps::for_test(kind).xor_fold(&mut actual, &data);
                assert_eq!(actual, expected, "xor_fold {kind:?} len={len}");
            }
        }
    }
}
