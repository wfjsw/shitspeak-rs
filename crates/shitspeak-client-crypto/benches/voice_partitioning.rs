//! Measures coarse Rayon partitioning for voice packet encryption.
//!
//! Each operation represents a single large voice fan-out. Work is split by
//! recipient runs, so no worker receives an individually scheduled packet.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rayon::prelude::*;
use std::hint::black_box;

use shitspeak_client_crypto::CryptState;

const KEY: [u8; 16] = [0x42; 16];
const IV_E: [u8; 16] = [0x01; 16];
const IV_D: [u8; 16] = [0x02; 16];
const FANOUT_SIZES: [usize; 3] = [512, 1024, 2048];
const PARTITION_MIN_LENS: [usize; 4] = [64, 128, 256, 512];

struct RecipientWork {
    crypt: CryptState,
    output: Vec<u8>,
}

fn make_crypt() -> CryptState {
    CryptState::from_key("OCB2-AES128", &KEY, &IV_E, &IV_D).expect("crypt state")
}

fn make_voice_plaintext(opus_len: usize) -> Vec<u8> {
    // Legacy VoiceOpus header, frame number, and packet length precede Opus.
    let mut plaintext = Vec::with_capacity(opus_len + 5);
    plaintext.push(0x80);
    write_mumble_varint(&mut plaintext, 1000);
    write_mumble_varint(&mut plaintext, opus_len as u64);
    plaintext.extend(std::iter::repeat_n(0xAB, opus_len));
    plaintext
}

fn write_mumble_varint(buffer: &mut Vec<u8>, value: u64) {
    if value < 0x80 {
        buffer.push(value as u8);
    } else if value < 0x4000 {
        buffer.push(0x80 | ((value >> 8) as u8 & 0x3F));
        buffer.push(value as u8);
    } else {
        unreachable!("benchmark payload fits a two-byte Mumble varint");
    }
}

fn make_work(fanout: usize, output_len: usize) -> Vec<RecipientWork> {
    (0..fanout)
        .map(|_| RecipientWork {
            crypt: make_crypt(),
            output: vec![0; output_len],
        })
        .collect()
}

fn encrypt_one(work: &mut RecipientWork, plaintext: &[u8], checksum: &[u8; 16]) {
    work.crypt
        .encrypt_with_precomputed_checksum(&mut work.output, plaintext, checksum)
        .expect("destination fits encrypted packet");
}

fn bench_voice_partitioning(c: &mut Criterion) {
    let mut group = c.benchmark_group("voice_encrypt/recipient_partitioning");
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(2));

    for opus_len in [170, 768] {
        let plaintext = make_voice_plaintext(opus_len);
        let checksum = CryptState::compute_plaintext_checksum(&plaintext);
        let output_len = plaintext.len() + make_crypt().overhead();

        for fanout in FANOUT_SIZES {
            group.throughput(Throughput::Elements(fanout as u64));
            let parameter = format!("opus={opus_len}/fanout={fanout}");

            group.bench_with_input(
                BenchmarkId::new("sequential", &parameter),
                &fanout,
                |b, &n| {
                    b.iter_with_setup(
                        || make_work(n, output_len),
                        |mut work| {
                            for recipient in &mut work {
                                encrypt_one(recipient, &plaintext, &checksum);
                            }
                            black_box(work);
                        },
                    );
                },
            );

            for min_len in PARTITION_MIN_LENS {
                group.bench_with_input(
                    BenchmarkId::new(format!("rayon_min_len={min_len}"), &parameter),
                    &fanout,
                    |b, &n| {
                        b.iter_with_setup(
                            || make_work(n, output_len),
                            |work| {
                                let output_prefix = work
                                    .into_par_iter()
                                    .with_min_len(min_len)
                                    .fold(
                                        || 0u8,
                                        |prefix, mut recipient| {
                                            encrypt_one(&mut recipient, &plaintext, &checksum);
                                            prefix ^ recipient.output[0]
                                        },
                                    )
                                    .reduce(|| 0u8, |left, right| left ^ right);
                                black_box(output_prefix);
                            },
                        );
                    },
                );
            }
        }
    }

    group.finish();
}

criterion_group!(benches, bench_voice_partitioning);
criterion_main!(benches);
