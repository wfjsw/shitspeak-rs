//! Microbenchmarks for the UDP voice hot path.
//!
//! The hot path on the server is:
//!   1. socket.recv_from -> Bytes copy -> mpsc try_send
//!   2. (process task) lookup client -> CryptState::decrypt -> IncomingUdpPacket::decode
//!   3. (routing task) route_voice -> bucket recipients
//!   4. (spawn_blocking + rayon) for each recipient: Audio::encode + CryptState::encrypt
//!   5. udp_batch::flush_batch (sendmmsg on Linux, send_to loop elsewhere)
//!
//! This bench isolates the CPU-bound steps (#2 decode, #4 encode+encrypt) so we
//! can attribute throughput limits to specific components and measure how the
//! per-recipient fan-out scales.

use bytes::Bytes;
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rayon::prelude::*;

use shitspeak_client_crypto::CryptState;
use shitspeak_messages::messages::encoder::{AudioContext, AudioTarget};
use shitspeak_rs::client::client_session_identifier::ClientSessionIdentifier;
use shitspeak_rs::voice::codec::{
    Audio, AudioPayload, IncomingUdpPacket, OpusPayload, PacketFormat,
};
use shitspeak_rs::voice::udp_batch::DatagramBatch;

const KEY: [u8; 16] = [0x42; 16];
const IV_E: [u8; 16] = [0x01; 16];
const IV_D: [u8; 16] = [0x02; 16];
const RAYON_DATAGRAM_BATCH_TARGET_LEN: usize = 256;
const PARTITIONED_FANOUT_SIZES: [usize; 8] = [40, 48, 56, 64, 96, 128, 512, 2048];
const PARTITION_TARGET_CHUNK_LENS: [usize; 6] = [16, 32, 64, 128, 256, 512];

fn capped_chunk_plan(
    fanout: usize,
    target_chunk_len: usize,
    rayon_workers: usize,
) -> (usize, usize) {
    let chunk_count = fanout
        .div_ceil(target_chunk_len)
        .min(rayon_workers.max(1))
        .min(fanout);
    (chunk_count, fanout.div_ceil(chunk_count))
}

fn make_crypt() -> CryptState {
    CryptState::from_key("OCB2-AES128", &KEY, &IV_E, &IV_D).expect("crypt state")
}

fn make_crypt_chunks(fanout: usize, chunk_count: usize) -> Vec<Vec<CryptState>> {
    (0..chunk_count)
        .map(|chunk_index| {
            let start = chunk_index * fanout / chunk_count;
            let end = (chunk_index + 1) * fanout / chunk_count;
            (start..end).map(|_| make_crypt()).collect()
        })
        .collect()
}

fn make_audio(opus_len: usize) -> Audio {
    Audio {
        target: AudioTarget::Normal,
        sender_session: Some(ClientSessionIdentifier::from(12345)),
        frame_number: 1000,
        audio_payload: AudioPayload::Opus(OpusPayload {
            frame: Bytes::from(vec![0xABu8; opus_len]),
            is_terminator: false,
        }),
        positional_data: None,
        volume_adjustment: 1.0,
        format: PacketFormat::Legacy,
    }
}

fn opus_sizes() -> [usize; 5] {
    // Realistic Opus frame sizes for voice:
    //   ~24 bytes  : silence/comfort noise
    //   ~80 bytes  : low-bitrate (32 kbit/s)
    //   ~170 bytes : typical Mumble bitrate (~58 kbit/s, 20ms frames)
    //   ~512 bytes : high-quality / multi-frame
    //   1000 bytes : near MAX_UDP_PACKET_SIZE (1024)
    [24, 80, 170, 512, 1000]
}

fn recipient_counts() -> [usize; 9] {
    [1, 4, 16, 64, 128, 256, 512, 1024, 2048]
}

// ── 1. Encoding only ─────────────────────────────────────────────────────────

fn bench_encode_legacy(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode/legacy");
    for &len in opus_sizes().iter() {
        let audio = make_audio(len);
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(len), &audio, |b, audio| {
            b.iter(|| {
                let out =
                    Audio::encode(black_box(audio), AudioContext::Normal, PacketFormat::Legacy);
                black_box(out)
            });
        });
    }
    group.finish();
}

fn bench_encode_protobuf(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode/protobuf");
    for &len in opus_sizes().iter() {
        let audio = make_audio(len);
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(len), &audio, |b, audio| {
            b.iter(|| {
                let out = Audio::encode(
                    black_box(audio),
                    AudioContext::Normal,
                    PacketFormat::Protobuf,
                );
                black_box(out)
            });
        });
    }
    group.finish();
}

// ── 2. Decoding only ─────────────────────────────────────────────────────────
//
// The server's legacy decoder expects client→server wire layout (no
// `sender_session` field on the wire). Hand-roll a minimal inbound packet
// for that - Audio::encode writes the server-to-client layout and would
// not round-trip.

fn write_mumble_varint(buf: &mut Vec<u8>, value: u64) {
    if value < 0x80 {
        buf.push(value as u8);
    } else if value < 0x4000 {
        buf.push(0x80 | ((value >> 8) as u8 & 0x3F));
        buf.push((value & 0xFF) as u8);
    } else if value < 0x200000 {
        buf.push(0xC0 | ((value >> 16) as u8 & 0x1F));
        buf.push(((value >> 8) & 0xFF) as u8);
        buf.push((value & 0xFF) as u8);
    } else {
        buf.push(0xE0 | ((value >> 24) as u8 & 0x0F));
        buf.push(((value >> 16) & 0xFF) as u8);
        buf.push(((value >> 8) & 0xFF) as u8);
        buf.push((value & 0xFF) as u8);
    }
}

fn build_inbound_legacy(opus_len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 4 + 4 + opus_len);
    let header = (0x04u8 << 5) | 0; // VoiceOpus + target=0
    buf.push(header);
    write_mumble_varint(&mut buf, 1000); // frame_number
    let size_flag = opus_len as u64 & 0x1FFF;
    write_mumble_varint(&mut buf, size_flag);
    buf.extend(std::iter::repeat(0xABu8).take(opus_len));
    buf
}

fn bench_decode_legacy(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode/legacy");
    let from_session = Some(ClientSessionIdentifier::from(12345));
    for &len in opus_sizes().iter() {
        let encoded = build_inbound_legacy(len);
        group.throughput(Throughput::Bytes(encoded.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(len), &encoded, |b, encoded| {
            b.iter(|| {
                let out = Audio::decode(black_box(encoded), from_session);
                black_box(out.unwrap())
            });
        });
    }
    for &len in opus_sizes().iter() {
        let encoded = build_inbound_legacy(len);
        group.throughput(Throughput::Bytes(encoded.len() as u64));
        group.bench_with_input(BenchmarkId::new("udp_sync", len), &encoded, |b, encoded| {
            b.iter(|| {
                let out = IncomingUdpPacket::decode(black_box(encoded), from_session);
                black_box(out.unwrap())
            });
        });
    }
    group.finish();
}

// ── 3. OCB2 encrypt / decrypt only ───────────────────────────────────────────

fn bench_crypt_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypt/encrypt");
    for &len in opus_sizes().iter() {
        // encrypt input is the encoded audio packet, not the Opus payload
        let audio = make_audio(len);
        let raw = Audio::encode(&audio, AudioContext::Normal, PacketFormat::Legacy);
        let plaintext_len = raw.len();
        group.throughput(Throughput::Bytes(plaintext_len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(len), &raw, |b, raw| {
            let mut state = make_crypt();
            let mut buf = vec![0u8; raw.len() + state.overhead()];
            b.iter(|| {
                state.encrypt(black_box(&mut buf), black_box(raw)).unwrap();
                black_box(&buf);
            });
        });
    }
    group.finish();
}

fn bench_crypt_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypt/decrypt");
    for &len in opus_sizes().iter() {
        let audio = make_audio(len);
        let raw = Audio::encode(&audio, AudioContext::Normal, PacketFormat::Legacy);
        let plaintext_len = raw.len();
        // Encrypt once into `cipher`, but to reuse for many decrypt iterations we
        // need decrypt to NOT advance the IV history. CryptState::decrypt does
        // mutate decrypt_iv & history. So we measure each decrypt individually
        // by re-encrypting per iteration via a sender state and decrypting via
        // a receiver state that tracks history. This still measures crypto
        // cost since encryption is roughly the same cost as decryption.
        group.throughput(Throughput::Bytes(plaintext_len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(len), &raw, |b, raw| {
            let mut sender = CryptState::from_key("OCB2-AES128", &KEY, &IV_E, &IV_D).unwrap();
            let mut receiver = CryptState::from_key("OCB2-AES128", &KEY, &IV_D, &IV_E).unwrap();
            let mut cipher = vec![0u8; raw.len() + sender.overhead()];
            let mut plain = bytes::BytesMut::with_capacity(raw.len());
            b.iter(|| {
                sender.encrypt(&mut cipher, raw).unwrap();
                plain.clear();
                receiver
                    .decrypt(black_box(&mut plain), black_box(&cipher))
                    .unwrap();
                black_box(&plain);
            });
        });
    }
    group.finish();
}

// ── 4. Combined per-recipient: encode + encrypt ──────────────────────────────
//
// This is the inner loop of `flush_voice_batch`'s `udp_items.into_par_iter()`
// branch.  Each iteration encodes the outgoing audio for the recipient's
// preferred format and encrypts with the recipient's CryptState.
//
// We compare:
//   (a) pure sequential loop (single thread, no rayon) — baseline
//   (b) rayon par_iter (work-stealing across the rayon threadpool) — production
//
// The crossover point where rayon wins tells us when the spawn_blocking + rayon
// fan-out overhead is amortized.

fn bench_fanout_seq(c: &mut Criterion) {
    let mut group = c.benchmark_group("fanout/seq_encode_encrypt");
    let opus_len = 170; // typical voice frame
    let audio = make_audio(opus_len);
    for &n in recipient_counts().iter() {
        // N independent crypt states — each recipient owns its own.
        let states: Vec<CryptState> = (0..n).map(|_| make_crypt()).collect();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &_n| {
            // Wrap states in a Mutex so the closure can take &mut CryptState
            // sequentially without owning them across iterations.
            let states_cell =
                std::cell::RefCell::new(states.iter().map(|_| make_crypt()).collect::<Vec<_>>());
            b.iter(|| {
                let mut states = states_cell.borrow_mut();
                let out: Vec<Bytes> = states
                    .iter_mut()
                    .map(|state| {
                        let raw = Audio::encode(&audio, AudioContext::Normal, PacketFormat::Legacy);
                        let mut buf = vec![0u8; raw.len() + state.overhead()];
                        state.encrypt(&mut buf, &raw).unwrap();
                        Bytes::from(buf)
                    })
                    .collect();
                black_box(out);
            });
        });
    }
    group.finish();
}

fn bench_fanout_rayon(c: &mut Criterion) {
    let mut group = c.benchmark_group("fanout/rayon_encode_encrypt");
    let opus_len = 170;
    let audio = make_audio(opus_len);
    for &n in recipient_counts().iter() {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            // Each iteration we hand rayon a fresh Vec<CryptState> wrapped in
            // parking_lot::Mutex, mirroring how production stores per-client
            // crypt state (CryptState is owned by each Client behind a Mutex).
            // We pre-build them once and reset minimal state by simply using
            // separate states each iteration (cheap since they are owned by
            // the closure).
            b.iter_with_setup(
                || (0..n).map(|_| make_crypt()).collect::<Vec<_>>(),
                |states| {
                    let out: Vec<Bytes> = states
                        .into_par_iter()
                        .map(|mut state| {
                            let raw =
                                Audio::encode(&audio, AudioContext::Normal, PacketFormat::Legacy);
                            let mut buf = vec![0u8; raw.len() + state.overhead()];
                            state.encrypt(&mut buf, &raw).unwrap();
                            Bytes::from(buf)
                        })
                        .collect();
                    black_box(out);
                },
            );
        });
    }
    group.finish();
}

// ── 5. Encrypt only fan-out (isolates AES cost from encode) ──────────────────

fn bench_fanout_seq_encrypt_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("fanout/seq_encrypt_only");
    let opus_len = 170;
    let audio = make_audio(opus_len);
    let raw = Audio::encode(&audio, AudioContext::Normal, PacketFormat::Legacy);
    for &n in recipient_counts().iter() {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &_n| {
            b.iter_with_setup(
                || (0..*&_n).map(|_| make_crypt()).collect::<Vec<_>>(),
                |mut states| {
                    let mut buf = vec![0u8; raw.len() + states[0].overhead()];
                    for state in states.iter_mut() {
                        state.encrypt(&mut buf, &raw).unwrap();
                    }
                    black_box(&buf);
                },
            );
        });
    }
    group.finish();
}

// ── 6. Combined per-recipient with shared plaintext (mirrors new flush) ──────
//
// Mirrors the post-patch sequential path in `flush_voice_batch`: encode the
// plaintext ONCE per (format, target) and clone the resulting Bytes for each
// recipient (cheap — Bytes is Arc-backed). Each recipient still pays its own
// encrypt cost, but the encode work is amortized.

fn bench_fanout_seq_cached(c: &mut Criterion) {
    let mut group = c.benchmark_group("fanout/seq_cached_encode_encrypt");
    let opus_len = 170;
    let audio = make_audio(opus_len);
    for &n in recipient_counts().iter() {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &_n| {
            b.iter_with_setup(
                || (0..*&_n).map(|_| make_crypt()).collect::<Vec<_>>(),
                |mut states| {
                    // Single encode shared across all recipients.
                    let raw = Audio::encode(&audio, AudioContext::Normal, PacketFormat::Legacy);
                    let out: Vec<bytes::Bytes> = states
                        .iter_mut()
                        .map(|state| {
                            let mut buf = bytes::BytesMut::zeroed(raw.len() + state.overhead());
                            state.encrypt(&mut buf, &raw).unwrap();
                            buf.freeze()
                        })
                        .collect();
                    black_box(out);
                },
            );
        });
    }
    group.finish();
}

// Same as seq_cached but uses Vec<u8> + Bytes::from (current production buffer
// pattern, but with cached encode). Isolates encode-cache benefit from the
// buffer-type swap.
fn bench_fanout_seq_cached_vec(c: &mut Criterion) {
    let mut group = c.benchmark_group("fanout/seq_cached_vec_encode_encrypt");
    let opus_len = 170;
    let audio = make_audio(opus_len);
    for &n in recipient_counts().iter() {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &_n| {
            b.iter_with_setup(
                || (0..*&_n).map(|_| make_crypt()).collect::<Vec<_>>(),
                |mut states| {
                    let raw = Audio::encode(&audio, AudioContext::Normal, PacketFormat::Legacy);
                    let out: Vec<bytes::Bytes> = states
                        .iter_mut()
                        .map(|state| {
                            let mut buf = vec![0u8; raw.len() + state.overhead()];
                            state.encrypt(&mut buf, &raw).unwrap();
                            bytes::Bytes::from(buf)
                        })
                        .collect();
                    black_box(out);
                },
            );
        });
    }
    group.finish();
}

// Mirrors the current production UDP fanout buffer shape: encode once, precompute
// the OCB2 plaintext checksum once, then encrypt each recipient directly into a
// DatagramBatch chunk arena.
fn bench_fanout_seq_datagram_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("fanout/seq_datagram_batch_encode_encrypt");
    let opus_len = 170;
    let audio = make_audio(opus_len);
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 64738));

    for &n in recipient_counts().iter() {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_with_setup(
                || (0..n).map(|_| make_crypt()).collect::<Vec<_>>(),
                |mut states| {
                    let raw = Audio::encode(&audio, AudioContext::Normal, PacketFormat::Legacy);
                    let checksum = CryptState::compute_plaintext_checksum(&raw);
                    let mut batch = DatagramBatch::with_capacity(states.len());

                    for state in &mut states {
                        let encrypted_len = raw.len() + state.overhead();
                        batch
                            .try_push_zeroed(addr, encrypted_len, |buf| {
                                state.encrypt_with_precomputed_checksum(buf, &raw, &checksum)
                            })
                            .unwrap();
                    }

                    black_box(batch);
                },
            );
        });
    }
    group.finish();
}

// Same production-shaped buffer path as above, but using the large-fanout
// Rayon fold/reduce layout from flush_voice_batch.
fn bench_fanout_rayon_datagram_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("fanout/rayon_capped_datagram_batch_encode_encrypt");
    let opus_len = 170;
    let audio = make_audio(opus_len);
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 64738));
    let rayon_workers = rayon::current_num_threads();

    for &n in recipient_counts().iter() {
        let (chunk_count, _) = capped_chunk_plan(n, RAYON_DATAGRAM_BATCH_TARGET_LEN, rayon_workers);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_with_setup(
                || make_crypt_chunks(n, chunk_count),
                |chunks| {
                    let raw = Audio::encode(&audio, AudioContext::Normal, PacketFormat::Legacy);
                    let checksum = CryptState::compute_plaintext_checksum(&raw);
                    let batch = chunks
                        .into_par_iter()
                        .map(|mut states| {
                            let mut batch = DatagramBatch::new();
                            for state in &mut states {
                                let encrypted_len = raw.len() + state.overhead();
                                batch
                                    .try_push_zeroed(addr, encrypted_len, |buf| {
                                        state
                                            .encrypt_with_precomputed_checksum(buf, &raw, &checksum)
                                    })
                                    .unwrap();
                            }
                            batch
                        })
                        .reduce(DatagramBatch::new, |mut left, right| {
                            left.append(right);
                            left
                        });

                    black_box(batch);
                },
            );
        });
    }
    group.finish();
}

// ── 7. Large fan-out partition size ─────────────────────────────────────────
//
// The production large-fanout path runs one `spawn_blocking` operation and
// creates explicitly balanced recipient runs. The number of runs is capped at
// the Rayon worker count, so every partial DatagramBatch represents useful
// coarse work rather than an independently scheduled packet.
fn bench_partitioned_fanout(c: &mut Criterion) {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 64738));
    let mut group = c.benchmark_group("fanout/partitioned_datagram_batch_encrypt");
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(2));
    let rayon_workers = rayon::current_num_threads();

    for opus_len in [170, 768] {
        let raw = Audio::encode(
            &make_audio(opus_len),
            AudioContext::Normal,
            PacketFormat::Legacy,
        );
        let checksum = CryptState::compute_plaintext_checksum(&raw);

        for fanout in PARTITIONED_FANOUT_SIZES {
            group.throughput(Throughput::Elements(fanout as u64));

            group.bench_with_input(
                BenchmarkId::new("sequential", format!("opus={opus_len}/fanout={fanout}")),
                &fanout,
                |b, &fanout| {
                    b.iter_with_setup(
                        || (0..fanout).map(|_| make_crypt()).collect::<Vec<_>>(),
                        |mut states| {
                            let mut batch = DatagramBatch::with_capacity(fanout);
                            for state in &mut states {
                                let encrypted_len = raw.len() + state.overhead();
                                batch
                                    .try_push_zeroed(addr, encrypted_len, |buf| {
                                        state
                                            .encrypt_with_precomputed_checksum(buf, &raw, &checksum)
                                    })
                                    .unwrap();
                            }
                            black_box(batch);
                        },
                    );
                },
            );

            for target_chunk_len in PARTITION_TARGET_CHUNK_LENS {
                let (chunk_count, chunk_len) =
                    capped_chunk_plan(fanout, target_chunk_len, rayon_workers);
                if chunk_count < 2 {
                    continue;
                }
                group.bench_with_input(
                    BenchmarkId::new(
                        format!(
                            "rayon_target={target_chunk_len}/chunks={chunk_count}/workers={rayon_workers}"
                        ),
                        format!("opus={opus_len}/fanout={fanout}/chunk_len={chunk_len}"),
                    ),
                    &fanout,
                    |b, &fanout| {
                        b.iter_with_setup(
                            || make_crypt_chunks(fanout, chunk_count),
                            |chunks| {
                                let batch = chunks
                                    .into_par_iter()
                                    .map(|mut states| {
                                        let mut batch = DatagramBatch::new();
                                        for state in &mut states {
                                            let encrypted_len = raw.len() + state.overhead();
                                            batch
                                                .try_push_zeroed(addr, encrypted_len, |buf| {
                                                    state.encrypt_with_precomputed_checksum(
                                                        buf, &raw, &checksum,
                                                    )
                                                })
                                                .unwrap();
                                        }
                                        batch
                                    })
                                    .reduce(DatagramBatch::new, |mut left, right| {
                                        left.append(right);
                                        left
                                    });
                                black_box(batch);
                            },
                        );
                    },
                );
            }
        }
    }

    group.finish();
}

// ── 8. spawn_blocking necessity ──────────────────────────────────────────────
//
// flush_voice_batch currently wraps the rayon par_iter inside spawn_blocking
// for the large-fanout path. Two questions:
//
// 1. Is spawn_blocking necessary? Rayon's par_iter blocks the caller until all
//    workers are done, so calling it directly from an async task DOES block the
//    tokio worker thread. spawn_blocking moves it to the blocking pool so the
//    worker remains free to schedule other tasks. But the spawn_blocking
//    handoff itself costs ~5–50 µs, which can dominate small workloads.
//
// 2. At what fanout size does the spawn_blocking overhead pay off?
//
// We benchmark four dispatch strategies inside the production tokio runtime
// (multi-thread, the default in main.rs):
//   - inline_seq   : sequential loop on the calling task
//   - inline_rayon : par_iter on the calling task (blocks the worker)
//   - spawn_seq    : sequential loop inside spawn_blocking
//   - spawn_rayon  : par_iter inside spawn_blocking (current production code)

fn make_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

/// Per-recipient encrypt work shared by all four dispatch strategies.
fn encrypt_one(state: &mut CryptState, raw: &bytes::Bytes) -> bytes::Bytes {
    let mut buf = bytes::BytesMut::zeroed(raw.len() + state.overhead());
    state.encrypt(&mut buf, raw).unwrap();
    buf.freeze()
}

fn dispatch_inline_seq(states: Vec<CryptState>, raw: bytes::Bytes) -> Vec<bytes::Bytes> {
    states
        .into_iter()
        .map(|mut s| encrypt_one(&mut s, &raw))
        .collect()
}

fn dispatch_inline_rayon(states: Vec<CryptState>, raw: bytes::Bytes) -> Vec<bytes::Bytes> {
    states
        .into_par_iter()
        .map(|mut s| encrypt_one(&mut s, &raw))
        .collect()
}

async fn dispatch_spawn_seq(states: Vec<CryptState>, raw: bytes::Bytes) -> Vec<bytes::Bytes> {
    tokio::task::spawn_blocking(move || dispatch_inline_seq(states, raw))
        .await
        .unwrap()
}

async fn dispatch_spawn_rayon(states: Vec<CryptState>, raw: bytes::Bytes) -> Vec<bytes::Bytes> {
    tokio::task::spawn_blocking(move || dispatch_inline_rayon(states, raw))
        .await
        .unwrap()
}

fn bench_dispatch_strategies(c: &mut Criterion) {
    let opus_len = 170;
    let audio = make_audio(opus_len);
    let raw = Audio::encode(&audio, AudioContext::Normal, PacketFormat::Legacy);
    let rt = make_runtime();

    let mut group = c.benchmark_group("dispatch/single_call");
    for &n in recipient_counts().iter() {
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("inline_seq", n), &n, |b, &n| {
            b.iter_with_setup(
                || (0..n).map(|_| make_crypt()).collect::<Vec<_>>(),
                |states| {
                    let out = dispatch_inline_seq(states, raw.clone());
                    black_box(out);
                },
            );
        });

        group.bench_with_input(BenchmarkId::new("inline_rayon", n), &n, |b, &n| {
            b.iter_with_setup(
                || (0..n).map(|_| make_crypt()).collect::<Vec<_>>(),
                |states| {
                    let out = dispatch_inline_rayon(states, raw.clone());
                    black_box(out);
                },
            );
        });

        group.bench_with_input(BenchmarkId::new("spawn_seq", n), &n, |b, &n| {
            b.iter_with_setup(
                || (0..n).map(|_| make_crypt()).collect::<Vec<_>>(),
                |states| {
                    let raw = raw.clone();
                    let out = rt.block_on(dispatch_spawn_seq(states, raw));
                    black_box(out);
                },
            );
        });

        group.bench_with_input(BenchmarkId::new("spawn_rayon", n), &n, |b, &n| {
            b.iter_with_setup(
                || (0..n).map(|_| make_crypt()).collect::<Vec<_>>(),
                |states| {
                    let raw = raw.clone();
                    let out = rt.block_on(dispatch_spawn_rayon(states, raw));
                    black_box(out);
                },
            );
        });
    }
    group.finish();
}

// ── 8. Multi-stream from one speaker ─────────────────────────────────────────
//
// Simulates a Mumble client that broadcasts to multiple targets simultaneously
// (e.g. one push-to-talk key bound to {NORMAL channel + whisper to user A +
// shout to channel B}). Each stream produces one packet per audio frame; on
// the server they all arrive on the same per-user routing queue and are
// processed serially by the per-user routing task.
//
// We measure total time to process K streams in series, each fanning out to
// M=16 recipients. K=1..=5 covers realistic keybind setups; the server has
// 20 ms (one Opus frame) to finish all K dispatches before the next batch
// arrives.

const MULTISTREAM_M: usize = 16;
fn stream_counts() -> [usize; 5] {
    [1, 2, 3, 5, 8]
}

fn bench_multistream(c: &mut Criterion) {
    let opus_len = 170;
    let audio = make_audio(opus_len);
    let raw = Audio::encode(&audio, AudioContext::Normal, PacketFormat::Legacy);
    let rt = make_runtime();

    let mut group = c.benchmark_group("multistream/serial");
    for &k in stream_counts().iter() {
        group.throughput(Throughput::Elements((k * MULTISTREAM_M) as u64));

        group.bench_with_input(BenchmarkId::new("inline_seq", k), &k, |b, &k| {
            b.iter_with_setup(
                || {
                    (0..k)
                        .map(|_| (0..MULTISTREAM_M).map(|_| make_crypt()).collect::<Vec<_>>())
                        .collect::<Vec<_>>()
                },
                |streams| {
                    for states in streams {
                        let out = dispatch_inline_seq(states, raw.clone());
                        black_box(out);
                    }
                },
            );
        });

        group.bench_with_input(BenchmarkId::new("inline_rayon", k), &k, |b, &k| {
            b.iter_with_setup(
                || {
                    (0..k)
                        .map(|_| (0..MULTISTREAM_M).map(|_| make_crypt()).collect::<Vec<_>>())
                        .collect::<Vec<_>>()
                },
                |streams| {
                    for states in streams {
                        let out = dispatch_inline_rayon(states, raw.clone());
                        black_box(out);
                    }
                },
            );
        });

        group.bench_with_input(BenchmarkId::new("spawn_seq", k), &k, |b, &k| {
            b.iter_with_setup(
                || {
                    (0..k)
                        .map(|_| (0..MULTISTREAM_M).map(|_| make_crypt()).collect::<Vec<_>>())
                        .collect::<Vec<_>>()
                },
                |streams| {
                    rt.block_on(async {
                        for states in streams {
                            let out = dispatch_spawn_seq(states, raw.clone()).await;
                            black_box(out);
                        }
                    });
                },
            );
        });

        group.bench_with_input(BenchmarkId::new("spawn_rayon", k), &k, |b, &k| {
            b.iter_with_setup(
                || {
                    (0..k)
                        .map(|_| (0..MULTISTREAM_M).map(|_| make_crypt()).collect::<Vec<_>>())
                        .collect::<Vec<_>>()
                },
                |streams| {
                    rt.block_on(async {
                        for states in streams {
                            let out = dispatch_spawn_rayon(states, raw.clone()).await;
                            black_box(out);
                        }
                    });
                },
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_encode_legacy,
    bench_encode_protobuf,
    bench_decode_legacy,
    bench_crypt_encrypt,
    bench_crypt_decrypt,
    bench_fanout_seq,
    bench_fanout_rayon,
    bench_fanout_seq_encrypt_only,
    bench_fanout_seq_cached,
    bench_fanout_seq_cached_vec,
    bench_fanout_seq_datagram_batch,
    bench_fanout_rayon_datagram_batch,
    bench_partitioned_fanout,
    bench_dispatch_strategies,
    bench_multistream,
);
criterion_main!(benches);
