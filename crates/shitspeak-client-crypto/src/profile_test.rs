//! `#[ignore]`'d profiling tests that decompose the OCB2 encrypt cost.
//!
//! Run with:
//!     cargo test --release --lib client::crypt::profile_test -- --ignored --nocapture --test-threads=1
//!
//! These are not regression tests. Windows' `Instant::now` has a 100 ns
//! resolution, so each phase is timed by running B=10_000 iterations as one
//! batch and dividing — the effective per-iter resolution is then ~0.01 ns.
//! Compiler can elide repeated identical work, so every measured loop must
//! `black_box` both inputs and outputs and vary at least one input bit per
//! iteration.

#![cfg(test)]
#![allow(dead_code)]

use std::hint::black_box;
use std::time::Instant;

use super::aes_backend::Aes128;
use super::gf128::Gf128Ops;
use super::xor_backend::{BackendKind, XorOps};
use super::{CryptState, Ocb2};

const BLOCK_SIZE: usize = 16;

// 175-byte plaintext mirrors `encode_audio_packet(170-byte Opus, Normal, Legacy)`.
const PLAINTEXT_LEN: usize = 175;
const KEY: [u8; 16] = [0x42; 16];
const IV: [u8; 16] = [0x01; 16];

const BATCH: usize = 10_000;
const SAMPLES: usize = 200;

fn make_plaintext() -> Vec<u8> {
    let mut p = vec![0u8; PLAINTEXT_LEN];
    for (i, b) in p.iter_mut().enumerate() {
        *b = (i & 0xff) as u8;
    }
    p
}

/// Run `f(seed)` `BATCH` times per sample, take `SAMPLES` samples, return
/// the median ns per single iteration. `seed` varies with the iteration
/// index to defeat compiler CSE on the inner loop.
fn batch_time<F>(label: &str, mut f: F) -> f64
where
    F: FnMut(usize),
{
    // Warm up
    for i in 0..BATCH {
        f(i);
    }
    let mut samples: Vec<u64> = Vec::with_capacity(SAMPLES);
    for s in 0..SAMPLES {
        let t0 = Instant::now();
        for i in 0..BATCH {
            f(s * BATCH + i);
        }
        samples.push(t0.elapsed().as_nanos() as u64);
    }
    samples.sort_unstable();
    let med_total = samples[samples.len() / 2] as f64;
    let p10 = samples[samples.len() / 10] as f64 / BATCH as f64;
    let p90 = samples[samples.len() * 9 / 10] as f64 / BATCH as f64;
    let med = med_total / BATCH as f64;
    println!("  {label:50}  median={med:>7.2} ns/iter   p10={p10:>6.2}  p90={p90:>6.2}");
    med
}

// ── Decomposition: each OCB2 phase in isolation ──────────────────────────────

#[test]
#[ignore]
fn profile_ocb2_phases() {
    super::probe_aes_backend();
    super::probe_gf128_backend();

    let plaintext = make_plaintext();
    let ocb = Ocb2::from_key(KEY).expect("ocb2");
    let aes = Aes128::new(&KEY).expect("aes");
    let gf128 = Gf128Ops::new();

    let n_main = PLAINTEXT_LEN.saturating_sub(1) / BLOCK_SIZE; // 10
    let last_pos = n_main * BLOCK_SIZE;
    let remaining = PLAINTEXT_LEN - last_pos; // 15

    println!();
    println!(
        "=== OCB2 phase decomposition: plaintext={} B, n_main={}, remaining={} ===",
        PLAINTEXT_LEN, n_main, remaining
    );
    println!("(BATCH={}  SAMPLES={})", BATCH, SAMPLES);

    // Phase 0: output buffer allocation.
    batch_time("phase0_alloc:           vec![0u8; 179]", |i| {
        let mut buf = vec![0u8; PLAINTEXT_LEN + 4];
        buf[0] = i as u8;
        black_box(buf);
    });

    // Phase 1: E(nonce). 1 AES block.
    batch_time("phase1_aes_1block:     aes.encrypt_blocks(16 B)", |i| {
        let mut buf = [0u8; BLOCK_SIZE];
        buf.copy_from_slice(&IV);
        buf[0] ^= i as u8;
        aes.encrypt_blocks(black_box(&mut buf)).unwrap();
        black_box(buf);
    });

    // Phase 2: gf128 chain of 11 (= n_main + 1) deltas
    batch_time("phase2_gf128_chain:    fill_chain(11)", |i| {
        let mut chain = [[0u8; 16]; 12];
        chain[0] = IV;
        chain[0][0] ^= i as u8;
        gf128.fill_chain(black_box(&mut chain), n_main + 1);
        black_box(chain);
    });

    // Phase 3: pre-XOR data → bulk (n_main full blocks)
    batch_time(
        "phase3_pre_xor:        data ^ delta → bulk (10 blocks)",
        |i| {
            let mut bulk = [0u8; 1024];
            let mut chain = [[0xa5u8; 16]; 12];
            chain[0][0] ^= i as u8;
            let plaintext = black_box(&plaintext);
            for k in 0..n_main {
                let block = &plaintext[k * BLOCK_SIZE..(k + 1) * BLOCK_SIZE];
                let d = &chain[k + 1];
                for j in 0..BLOCK_SIZE {
                    bulk[k * BLOCK_SIZE + j] = block[j] ^ d[j];
                }
            }
            black_box(bulk);
        },
    );

    // Phase 4: batched ECB on n_main blocks
    batch_time("phase4_aes_10blocks:   aes.encrypt_blocks(160 B)", |i| {
        let mut bulk = [0u8; 160];
        for (k, b) in bulk.iter_mut().enumerate() {
            *b = (k ^ i) as u8;
        }
        aes.encrypt_blocks(black_box(&mut bulk)).unwrap();
        black_box(bulk);
    });

    // Phase 5: post-XOR + checksum (n_main blocks)  — production behavior
    batch_time("phase5_post_xor_chk:   bulk ^ delta + chk (10 blk)", |i| {
        let mut dest = [0u8; 1024];
        let mut bulk = [0x5au8; 1024];
        bulk[0] ^= i as u8;
        let mut chain = [[0xa5u8; 16]; 12];
        chain[0][0] ^= i as u8;
        let mut checksum = [0u8; 16];
        let plaintext = black_box(&plaintext);
        for k in 0..n_main {
            let d = &chain[k + 1];
            for j in 0..BLOCK_SIZE {
                dest[k * BLOCK_SIZE + j] = bulk[k * BLOCK_SIZE + j] ^ d[j];
                checksum[j] ^= plaintext[k * BLOCK_SIZE + j];
            }
        }
        black_box((dest, checksum));
    });

    // Phase 5b: post-XOR ONLY (no checksum) — gives the shared-checksum upper bound
    batch_time("phase5b_post_xor_only: bulk ^ delta  (no chk)", |i| {
        let mut dest = [0u8; 1024];
        let mut bulk = [0x5au8; 1024];
        bulk[0] ^= i as u8;
        let mut chain = [[0xa5u8; 16]; 12];
        chain[0][0] ^= i as u8;
        for k in 0..n_main {
            let d = &chain[k + 1];
            for j in 0..BLOCK_SIZE {
                dest[k * BLOCK_SIZE + j] = bulk[k * BLOCK_SIZE + j] ^ d[j];
            }
        }
        black_box(dest);
    });

    // Phase 5c: checksum fold ONLY — direct measurement of shared-checksum savings
    batch_time(
        "phase5c_checksum_only: XOR-fold of plaintext (10 blk)",
        |i| {
            let mut checksum = [0u8; 16];
            checksum[0] ^= i as u8;
            let plaintext = black_box(&plaintext);
            for k in 0..n_main {
                for j in 0..BLOCK_SIZE {
                    checksum[j] ^= plaintext[k * BLOCK_SIZE + j];
                }
            }
            black_box(checksum);
        },
    );

    // Compare the runtime-dispatched backend with the scalar reference for
    // one large hot-path buffer and one short full-vector buffer. The profile
    // is intentionally observational: CPU frequency and timer resolution
    // vary across development hosts, so it reports rather than asserts wins.
    let scalar_xor = XorOps::for_test(BackendKind::Scalar);
    let runtime_xor = XorOps::new();
    batch_time("phase3_scalar_xor_backend: 160 B", |i| {
        let mut bulk = [0u8; 160];
        let mut chain = [[0xa5u8; 16]; 12];
        chain[0][0] ^= i as u8;
        scalar_xor.xor_chain_into(&mut bulk, &plaintext[..160], &chain[1..n_main + 1]);
        black_box(bulk);
    });
    batch_time("phase3_runtime_xor_backend: 160 B", |i| {
        let mut bulk = [0u8; 160];
        let mut chain = [[0xa5u8; 16]; 12];
        chain[0][0] ^= i as u8;
        runtime_xor.xor_chain_into(&mut bulk, &plaintext[..160], &chain[1..n_main + 1]);
        black_box(bulk);
    });
    batch_time("phase3_runtime_xor_backend: 16 B", |i| {
        let mut bulk = [0u8; 16];
        let mut chain = [[0xa5u8; 16]; 2];
        chain[0][0] ^= i as u8;
        runtime_xor.xor_chain_into(&mut bulk, &plaintext[..16], &chain[1..2]);
        black_box(bulk);
    });
    batch_time("phase3_scalar_xor_backend: 16 B", |i| {
        let mut bulk = [0u8; 16];
        let mut chain = [[0xa5u8; 16]; 2];
        chain[0][0] ^= i as u8;
        scalar_xor.xor_chain_into(&mut bulk, &plaintext[..16], &chain[1..2]);
        black_box(bulk);
    });

    // Phase 6: pad encrypt. 1 AES block.
    batch_time("phase6_pad_aes:        aes.encrypt_blocks(16 B)", |i| {
        let mut pad = [0u8; BLOCK_SIZE];
        pad[14] = 0x01;
        pad[15] = 0x78;
        pad[0] ^= i as u8;
        aes.encrypt_blocks(black_box(&mut pad)).unwrap();
        black_box(pad);
    });

    // Phase 7: tag encrypt. 1 AES block + gf128.triple
    batch_time("phase7_tag:            gf128.triple + aes(16 B)", |i| {
        let mut tag_buf = [0xa5u8; 16];
        tag_buf[0] ^= i as u8;
        gf128.triple(black_box(&mut tag_buf));
        for j in 0..16 {
            tag_buf[j] ^= 0x5a;
        }
        aes.encrypt_blocks(black_box(&mut tag_buf)).unwrap();
        black_box(tag_buf);
    });

    // Reference: full Ocb2::encrypt (no per-state overhead from CryptState)
    let scalar_ocb = Ocb2::from_key_with_backend(KEY, BackendKind::Scalar).expect("scalar ocb2");
    batch_time("ref_scalar_Ocb2::encrypt (no CryptState wrapper)", |i| {
        let mut out = vec![0u8; PLAINTEXT_LEN + 3];
        let mut nonce = IV;
        nonce[0] ^= i as u8;
        super::CryptoMode::encrypt(
            black_box(&scalar_ocb),
            black_box(&mut out),
            black_box(&plaintext),
            black_box(&nonce),
        )
        .unwrap();
        black_box(out);
    });

    // Reference: full runtime-dispatched Ocb2::encrypt.
    batch_time("ref_full_Ocb2::encrypt (no CryptState wrapper)", |i| {
        let mut out = vec![0u8; PLAINTEXT_LEN + 3];
        let mut nonce = IV;
        nonce[0] ^= i as u8;
        super::CryptoMode::encrypt(
            black_box(&ocb),
            black_box(&mut out),
            black_box(&plaintext),
            black_box(&nonce),
        )
        .unwrap();
        black_box(out);
    });

    // Reference: full CryptState::encrypt (single state, hot)
    let mut state = CryptState::from_key("OCB2-AES128", &KEY, &IV, &IV).unwrap();
    let mut buf = vec![0u8; PLAINTEXT_LEN + 4];
    batch_time("ref_full_CryptState::encrypt (single hot state)", |_| {
        state
            .encrypt(black_box(&mut buf), black_box(&plaintext))
            .unwrap();
        black_box(&buf);
    });
}

// ── Fanout: per-recipient cost as a function of state count ──────────────────

#[test]
#[ignore]
fn profile_fanout_breakdown() {
    super::probe_aes_backend();
    super::probe_gf128_backend();

    let plaintext = make_plaintext();
    println!();
    println!("=== Fanout per-recipient cost (median over 200 fanout iters) ===");

    for &n in &[1usize, 4, 16, 64, 256] {
        let mk_states = || -> Vec<CryptState> {
            (0..n)
                .map(|_| CryptState::from_key("OCB2-AES128", &KEY, &IV, &IV).unwrap())
                .collect()
        };

        let mut buf = vec![0u8; PLAINTEXT_LEN + 4];
        // Warm up
        for _ in 0..50 {
            let mut states = mk_states();
            for s in &mut states {
                s.encrypt(&mut buf, &plaintext).unwrap();
            }
        }

        let mut times = Vec::with_capacity(200);
        for _ in 0..200 {
            let mut states = mk_states();
            let t0 = Instant::now();
            for s in &mut states {
                s.encrypt(&mut buf, &plaintext).unwrap();
            }
            black_box(&buf);
            times.push(t0.elapsed().as_nanos() as u64);
        }
        times.sort_unstable();
        let median = times[times.len() / 2] as f64;
        let per = median / n as f64;
        println!("  n={n:>4}   total={median:>10.0} ns   per_rcp={per:>7.1} ns");
    }
}

// ── Shared-checksum: precompute the plaintext fold once per fan-out ──────────

fn precompute_plaintext_checksum(plaintext: &[u8]) -> [u8; 16] {
    let n_main = plaintext.len().saturating_sub(1) / BLOCK_SIZE;
    let last_pos = n_main * BLOCK_SIZE;
    let remaining = plaintext.len() - last_pos;

    let mut checksum = [0u8; 16];
    for i in 0..n_main {
        for j in 0..BLOCK_SIZE {
            checksum[j] ^= plaintext[i * BLOCK_SIZE + j];
        }
    }
    for j in 0..remaining {
        checksum[j] ^= plaintext[last_pos + j];
    }
    checksum
}

#[test]
#[ignore]
fn profile_shared_checksum_savings() {
    super::probe_aes_backend();
    super::probe_gf128_backend();

    let plaintext = make_plaintext();
    let n = 256;

    println!();
    println!("=== Shared-checksum savings @ n=256 (measured against real API) ===");

    let mut buf = vec![0u8; PLAINTEXT_LEN + 4];
    let mk_states = || -> Vec<CryptState> {
        (0..n)
            .map(|_| CryptState::from_key("OCB2-AES128", &KEY, &IV, &IV).unwrap())
            .collect()
    };

    // Baseline: production CryptState::encrypt across N states.
    for _ in 0..50 {
        let mut states = mk_states();
        for s in &mut states {
            s.encrypt(&mut buf, &plaintext).unwrap();
        }
    }
    let mut baseline_samples: Vec<u64> = Vec::with_capacity(500);
    for _ in 0..500 {
        let mut states = mk_states();
        let t0 = Instant::now();
        for s in &mut states {
            s.encrypt(&mut buf, &plaintext).unwrap();
        }
        black_box(&buf);
        baseline_samples.push(t0.elapsed().as_nanos() as u64);
    }
    baseline_samples.sort_unstable();
    let baseline = baseline_samples[baseline_samples.len() / 2] as f64;

    // Optimized: precompute checksum once, then encrypt_with_precomputed_checksum N times.
    for _ in 0..50 {
        let mut states = mk_states();
        let chk = CryptState::compute_plaintext_checksum(&plaintext);
        for s in &mut states {
            s.encrypt_with_precomputed_checksum(&mut buf, &plaintext, &chk)
                .unwrap();
        }
    }
    let mut opt_samples: Vec<u64> = Vec::with_capacity(500);
    for _ in 0..500 {
        let mut states = mk_states();
        let t0 = Instant::now();
        let chk = CryptState::compute_plaintext_checksum(&plaintext);
        for s in &mut states {
            s.encrypt_with_precomputed_checksum(&mut buf, &plaintext, &chk)
                .unwrap();
        }
        black_box(&buf);
        opt_samples.push(t0.elapsed().as_nanos() as u64);
    }
    opt_samples.sort_unstable();
    let optimized = opt_samples[opt_samples.len() / 2] as f64;

    let savings = baseline - optimized;
    let pct = 100.0 * savings / baseline;

    println!();
    println!(
        "  baseline (encrypt × 256)             : {baseline:>10.0} ns  ({:.1} ns/rcp)",
        baseline / n as f64
    );
    println!(
        "  optimized (precompute + encrypt × 256): {optimized:>10.0} ns  ({:.1} ns/rcp)",
        optimized / n as f64
    );
    println!("  measured savings                     : {savings:>+10.0} ns  ({pct:>+5.1}%)");
}

// ── CryptState wrapper overhead: compare production layout to direct OCB2 ────

struct LeanState {
    encrypt_iv: [u8; 16],
    ocb2: Ocb2,
}

impl LeanState {
    fn new() -> Self {
        Self {
            encrypt_iv: IV,
            ocb2: Ocb2::from_key(KEY).expect("ocb2"),
        }
    }

    #[inline(always)]
    fn encrypt(&mut self, dest: &mut [u8], data: &[u8]) {
        for byte in self.encrypt_iv.iter_mut() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        // Direct concrete-type call — no vtable lookup.
        super::CryptoMode::encrypt(&self.ocb2, &mut dest[1..], data, &self.encrypt_iv).unwrap();
        dest[0] = self.encrypt_iv[0];
    }
}

#[test]
#[ignore]
fn profile_crypt_state_wrapper_overhead() {
    super::probe_aes_backend();
    super::probe_gf128_backend();

    let plaintext = make_plaintext();
    let n = 256;

    println!();
    println!("=== CryptState wrapper overhead @ n=256 ===");
    println!("(production CryptState now stores IVs and OCB2 inline)");

    let mut buf = vec![0u8; PLAINTEXT_LEN + 4];

    let mk_prod = || -> Vec<CryptState> {
        (0..n)
            .map(|_| CryptState::from_key("OCB2-AES128", &KEY, &IV, &IV).unwrap())
            .collect()
    };
    for _ in 0..50 {
        let mut s = mk_prod();
        for st in &mut s {
            st.encrypt(&mut buf, &plaintext).unwrap();
        }
    }
    let mut prod_samples: Vec<u64> = Vec::with_capacity(500);
    for _ in 0..500 {
        let mut states = mk_prod();
        let t0 = Instant::now();
        for s in &mut states {
            s.encrypt(&mut buf, &plaintext).unwrap();
        }
        black_box(&buf);
        prod_samples.push(t0.elapsed().as_nanos() as u64);
    }
    prod_samples.sort_unstable();
    let prod = prod_samples[prod_samples.len() / 2] as f64;

    let mk_lean = || -> Vec<LeanState> { (0..n).map(|_| LeanState::new()).collect() };
    for _ in 0..50 {
        let mut s = mk_lean();
        for st in &mut s {
            st.encrypt(&mut buf, &plaintext);
        }
    }
    let mut lean_samples: Vec<u64> = Vec::with_capacity(500);
    for _ in 0..500 {
        let mut states = mk_lean();
        let t0 = Instant::now();
        for s in &mut states {
            s.encrypt(&mut buf, &plaintext);
        }
        black_box(&buf);
        lean_samples.push(t0.elapsed().as_nanos() as u64);
    }
    lean_samples.sort_unstable();
    let lean = lean_samples[lean_samples.len() / 2] as f64;

    let savings = prod - lean;
    let pct = 100.0 * savings / prod;

    println!();
    println!(
        "  production CryptState fanout :   {prod:>10.0} ns  ({:.1} ns/rcp)",
        prod / n as f64
    );
    println!(
        "  direct OCB2 lower bound      :   {lean:>10.0} ns  ({:.1} ns/rcp)",
        lean / n as f64
    );
    println!("  savings                      :   {savings:>+10.0} ns  ({pct:>+5.1}%)");
}
