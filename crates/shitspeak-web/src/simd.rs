const HEADER_END: &[u8; 4] = b"\r\n\r\n";
const AVX2_THRESHOLD: usize = 64;

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendKind {
    Scalar,
    Sse2,
    Avx2,
}

static BACKEND: OnceLock<BackendKind> = OnceLock::new();

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

#[inline]
fn backend_for_len(kind: BackendKind, len: usize) -> BackendKind {
    if len < 16 {
        return BackendKind::Scalar;
    }
    if kind == BackendKind::Avx2 && len >= AVX2_THRESHOLD {
        BackendKind::Avx2
    } else if kind != BackendKind::Scalar {
        BackendKind::Sse2
    } else {
        BackendKind::Scalar
    }
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

pub(super) fn xor_mask(payload: &mut [u8], mask: [u8; 4]) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        match backend_for_len(current_backend(), payload.len()) {
            BackendKind::Avx2 => {
                // SAFETY: AVX2 was detected before selecting this kernel.
                unsafe { xor_mask_avx2(payload, mask) };
                return;
            }
            BackendKind::Sse2 => {
                // SAFETY: SSE2 was detected before selecting this kernel.
                unsafe { xor_mask_sse2(payload, mask) };
                return;
            }
            BackendKind::Scalar => {}
        }
    }

    xor_mask_scalar(payload, mask);
}

pub(super) fn find_header_end(buf: &[u8]) -> Option<usize> {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        match backend_for_len(current_backend(), buf.len()) {
            BackendKind::Avx2 => {
                // SAFETY: AVX2 was detected before selecting this kernel.
                return unsafe { find_header_end_avx2(buf) };
            }
            BackendKind::Sse2 => {
                // SAFETY: SSE2 was detected before selecting this kernel.
                return unsafe { find_header_end_sse2(buf) };
            }
            BackendKind::Scalar => {}
        }
    }

    find_header_end_scalar(buf)
}

fn xor_mask_scalar(payload: &mut [u8], mask: [u8; 4]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
}

fn find_header_end_scalar(buf: &[u8]) -> Option<usize> {
    buf.windows(HEADER_END.len())
        .position(|window| window == HEADER_END)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn xor_mask_avx2(payload: &mut [u8], mask: [u8; 4]) {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{
        _mm256_loadu_si256, _mm256_set1_epi32, _mm256_storeu_si256, _mm256_xor_si256,
    };
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{
        _mm256_loadu_si256, _mm256_set1_epi32, _mm256_storeu_si256, _mm256_xor_si256,
    };

    let vector_mask = _mm256_set1_epi32(i32::from_ne_bytes(mask));
    let mut offset = 0;
    while payload.len() - offset >= 32 {
        let pointer = unsafe { payload.as_mut_ptr().add(offset) };
        let value = unsafe { _mm256_loadu_si256(pointer.cast()) };
        let value = _mm256_xor_si256(value, vector_mask);
        unsafe { _mm256_storeu_si256(pointer.cast(), value) };
        offset += 32;
    }

    if payload.len() - offset >= 16 {
        // The AVX2 tier can still use a full SSE2 vector before the scalar
        // tail, keeping only fewer-than-16 bytes on the scalar path.
        unsafe { xor_mask_sse2(&mut payload[offset..], mask) };
        return;
    }
    xor_mask_scalar(&mut payload[offset..], mask);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sse2")]
unsafe fn xor_mask_sse2(payload: &mut [u8], mask: [u8; 4]) {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{_mm_loadu_si128, _mm_set1_epi32, _mm_storeu_si128, _mm_xor_si128};
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{_mm_loadu_si128, _mm_set1_epi32, _mm_storeu_si128, _mm_xor_si128};

    let vector_mask = _mm_set1_epi32(i32::from_ne_bytes(mask));
    let mut offset = 0;
    while payload.len() - offset >= 16 {
        let pointer = unsafe { payload.as_mut_ptr().add(offset) };
        let value = unsafe { _mm_loadu_si128(pointer.cast()) };
        let value = _mm_xor_si128(value, vector_mask);
        unsafe { _mm_storeu_si128(pointer.cast(), value) };
        offset += 16;
    }

    xor_mask_scalar(&mut payload[offset..], mask);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn find_header_end_avx2(buf: &[u8]) -> Option<usize> {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{
        _mm256_and_si256, _mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_movemask_epi8,
        _mm256_set1_epi8,
    };
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{
        _mm256_and_si256, _mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_movemask_epi8,
        _mm256_set1_epi8,
    };

    let carriage_return = _mm256_set1_epi8(b'\r' as i8);
    let line_feed = _mm256_set1_epi8(b'\n' as i8);
    let mut offset = 0;

    while buf.len().saturating_sub(offset) >= 35 {
        let pointer = unsafe { buf.as_ptr().add(offset) };
        let candidates = unsafe {
            let first = _mm256_cmpeq_epi8(_mm256_loadu_si256(pointer.cast()), carriage_return);
            let second = _mm256_cmpeq_epi8(_mm256_loadu_si256(pointer.add(1).cast()), line_feed);
            let third =
                _mm256_cmpeq_epi8(_mm256_loadu_si256(pointer.add(2).cast()), carriage_return);
            let fourth = _mm256_cmpeq_epi8(_mm256_loadu_si256(pointer.add(3).cast()), line_feed);
            _mm256_movemask_epi8(_mm256_and_si256(
                _mm256_and_si256(first, second),
                _mm256_and_si256(third, fourth),
            )) as u32
        };

        if candidates != 0 {
            return Some(offset + candidates.trailing_zeros() as usize);
        }
        offset += 32;
    }

    if buf.len() - offset >= 19 {
        return unsafe { find_header_end_sse2(&buf[offset..]) }.map(|index| offset + index);
    }
    find_header_end_scalar(&buf[offset..]).map(|index| offset + index)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sse2")]
unsafe fn find_header_end_sse2(buf: &[u8]) -> Option<usize> {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{
        _mm_and_si128, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8, _mm_set1_epi8,
    };
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{
        _mm_and_si128, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8, _mm_set1_epi8,
    };

    let carriage_return = _mm_set1_epi8(b'\r' as i8);
    let line_feed = _mm_set1_epi8(b'\n' as i8);
    let mut offset = 0;

    while buf.len().saturating_sub(offset) >= 19 {
        let pointer = unsafe { buf.as_ptr().add(offset) };
        let candidates = unsafe {
            let first = _mm_cmpeq_epi8(_mm_loadu_si128(pointer.cast()), carriage_return);
            let second = _mm_cmpeq_epi8(_mm_loadu_si128(pointer.add(1).cast()), line_feed);
            let third = _mm_cmpeq_epi8(_mm_loadu_si128(pointer.add(2).cast()), carriage_return);
            let fourth = _mm_cmpeq_epi8(_mm_loadu_si128(pointer.add(3).cast()), line_feed);
            _mm_movemask_epi8(_mm_and_si128(
                _mm_and_si128(first, second),
                _mm_and_si128(third, fourth),
            )) as u16
        };

        if candidates != 0 {
            return Some(offset + candidates.trailing_zeros() as usize);
        }
        offset += 16;
    }

    find_header_end_scalar(&buf[offset..]).map(|index| offset + index)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASKS: [[u8; 4]; 4] = [
        [0, 0, 0, 0],
        [1, 2, 3, 4],
        [0xff, 0x80, 0x01, 0x7f],
        [0xa5, 0x3c, 0x91, 0xe7],
    ];
    const VECTOR_BOUNDARIES: [usize; 21] = [
        0, 1, 2, 3, 4, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 95, 96, 97, 127,
    ];

    fn input(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| (index as u8).wrapping_mul(37).wrapping_add(11))
            .collect()
    }

    fn scalar_masked(mut payload: Vec<u8>, mask: [u8; 4]) -> Vec<u8> {
        xor_mask_scalar(&mut payload, mask);
        payload
    }

    #[test]
    fn xor_mask_handles_arbitrary_masks_and_vector_boundaries() {
        for mask in MASKS {
            for length in VECTOR_BOUNDARIES {
                let mut actual = input(length);
                xor_mask(&mut actual, mask);
                assert_eq!(actual, scalar_masked(input(length), mask));
            }
        }
    }

    #[test]
    fn find_header_end_handles_positions_absence_and_overlapping_patterns() {
        for position in [
            0, 1, 2, 3, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 95, 96, 97,
        ] {
            let mut input = vec![b'x'; position + HEADER_END.len()];
            input[position..].copy_from_slice(HEADER_END);
            assert_eq!(find_header_end(&input), Some(position));
        }

        assert_eq!(find_header_end(b""), None);
        assert_eq!(find_header_end(b"\r\n\r"), None);
        assert_eq!(find_header_end(b"\r\n\r\n"), Some(0));
        assert_eq!(find_header_end(b"x\r\n\r\n\r\n"), Some(1));
        assert_eq!(find_header_end(b"xx\r\n\r\n\r\n"), Some(2));

        let mut absent = vec![b'x'; 96];
        absent[15..19].copy_from_slice(b"\r\n\rx");
        absent[31..35].copy_from_slice(b"\r\nx\n");
        absent[63..67].copy_from_slice(b"\rx\r\n");
        assert_eq!(find_header_end(&absent), None);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn x86_mask_kernels_match_scalar() {
        for mask in MASKS {
            for length in VECTOR_BOUNDARIES {
                if std::is_x86_feature_detected!("avx2") {
                    let mut actual = input(length);
                    // SAFETY: The runtime check above guards the AVX2 kernel.
                    unsafe { xor_mask_avx2(&mut actual, mask) };
                    assert_eq!(actual, scalar_masked(input(length), mask));
                }
                if std::is_x86_feature_detected!("sse2") {
                    let mut actual = input(length);
                    // SAFETY: The runtime check above guards the SSE2 kernel.
                    unsafe { xor_mask_sse2(&mut actual, mask) };
                    assert_eq!(actual, scalar_masked(input(length), mask));
                }
            }
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn x86_header_kernels_match_scalar() {
        let mut inputs = vec![vec![], b"\r\n\r".to_vec(), b"x\r\n\r\n\r\n".to_vec()];
        for position in [
            0, 1, 2, 3, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 95, 96, 97,
        ] {
            let mut input = vec![b'x'; position + HEADER_END.len()];
            input[position..].copy_from_slice(HEADER_END);
            inputs.push(input);
        }

        for input in inputs {
            let expected = find_header_end_scalar(&input);
            if std::is_x86_feature_detected!("avx2") {
                // SAFETY: The runtime check above guards the AVX2 kernel.
                assert_eq!(unsafe { find_header_end_avx2(&input) }, expected);
            }
            if std::is_x86_feature_detected!("sse2") {
                // SAFETY: The runtime check above guards the SSE2 kernel.
                assert_eq!(unsafe { find_header_end_sse2(&input) }, expected);
            }
        }
    }

    #[test]
    #[ignore]
    fn profile_signaling_simd() {
        use std::hint::black_box;
        use std::time::Instant;

        const ITERATIONS: usize = 10_000;
        const PAYLOAD_LEN: usize = 4096;
        let mask = [0xa5, 0x3c, 0x91, 0xe7];

        let mut runtime_payload = input(PAYLOAD_LEN);
        let started = Instant::now();
        for iteration in 0..ITERATIONS {
            runtime_payload[0] ^= iteration as u8;
            xor_mask(&mut runtime_payload, mask);
            black_box(&runtime_payload);
        }
        let runtime_ns = started.elapsed().as_nanos() as f64 / ITERATIONS as f64;

        let mut scalar_payload = input(PAYLOAD_LEN);
        let started = Instant::now();
        for iteration in 0..ITERATIONS {
            scalar_payload[0] ^= iteration as u8;
            xor_mask_scalar(&mut scalar_payload, mask);
            black_box(&scalar_payload);
        }
        let scalar_ns = started.elapsed().as_nanos() as f64 / ITERATIONS as f64;

        let header = vec![b'x'; PAYLOAD_LEN];
        let started = Instant::now();
        let mut result = None;
        for _ in 0..ITERATIONS {
            result = find_header_end(black_box(&header));
        }
        let scan_ns = started.elapsed().as_nanos() as f64 / ITERATIONS as f64;

        let started = Instant::now();
        let mut scalar_result = None;
        for _ in 0..ITERATIONS {
            scalar_result = find_header_end_scalar(black_box(&header));
        }
        let scalar_scan_ns = started.elapsed().as_nanos() as f64 / ITERATIONS as f64;

        println!(
            "signaling SIMD profile: backend={:?} mask_runtime={runtime_ns:.2} ns mask_scalar={scalar_ns:.2} ns header_runtime={scan_ns:.2} ns header_scalar={scalar_scan_ns:.2} ns result={result:?}/{scalar_result:?}",
            backend_for_len(current_backend(), PAYLOAD_LEN),
        );
    }
}
