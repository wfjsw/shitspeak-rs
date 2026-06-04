//! Benchmarks for exploring voice micro-buffering.
//!
//! The production UDP voice path processes each packet as it arrives:
//! decrypt -> decode -> route/fan-out -> encrypt recipients -> enqueue UDP.
//!
//! These benchmarks ask whether intentionally holding a very small number of
//! voice frames can buy enough CPU efficiency to be worth the added latency.
//! The tested micro-batch shape preserves voice continuity:
//!
//! - inbound frames are decrypted and decoded in stream order;
//! - each recipient's outbound frames are encrypted in frame order;
//! - the batched path can send a recipient's short ordered run together.
//!
//! With normal 20 ms Opus frames, a batch of N adds roughly `(N - 1) * 20 ms`
//! before the first buffered frame can be emitted. Batch sizes here are kept
//! deliberately small so the benchmark stays in the "micro" latency range.

use bytes::{Bytes, BytesMut};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rayon::prelude::*;
use std::{hint::black_box, net::SocketAddr};

use shitspeak_rs::client::client_session_identifier::ClientSessionIdentifier;
use shitspeak_rs::client::crypt::CryptState;
use shitspeak_rs::messages::encoder::AudioContext;
use shitspeak_rs::voice::codec::{Audio, IncomingUdpPacket, PacketFormat};
use shitspeak_rs::voice::udp_batch::DatagramBatch;

const KEY: [u8; 16] = [0x42; 16];
const IV_E: [u8; 16] = [0x01; 16];
const IV_D: [u8; 16] = [0x02; 16];
const OPUS_LEN: usize = 170;
const OPUS_FRAME_MS: usize = 20;
const RAYON_BATCH_MIN_LEN: usize = 64;

#[derive(Clone)]
struct EncodedFrame {
    bytes: Bytes,
    checksum: [u8; 16],
}

struct Workload {
    encrypted_inbound: Vec<Bytes>,
    inbound_receiver: CryptState,
    recipient_states: Vec<CryptState>,
}

fn make_crypt() -> CryptState {
    CryptState::from_key("OCB2-AES128", &KEY, &IV_E, &IV_D).expect("crypt state")
}

fn make_sender_crypt() -> CryptState {
    CryptState::from_key("OCB2-AES128", &KEY, &IV_E, &IV_D).expect("sender crypt state")
}

fn make_receiver_crypt() -> CryptState {
    CryptState::from_key("OCB2-AES128", &KEY, &IV_D, &IV_E).expect("receiver crypt state")
}

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

fn build_inbound_legacy(frame_number: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 4 + 2 + OPUS_LEN);
    let header = (0x04u8 << 5) | 0; // VoiceOpus + target=0
    buf.push(header);
    write_mumble_varint(&mut buf, frame_number);
    write_mumble_varint(&mut buf, OPUS_LEN as u64);
    buf.extend(std::iter::repeat_n(0xABu8, OPUS_LEN));
    buf
}

fn make_workload(batch_frames: usize, fanout: usize) -> Workload {
    let mut sender = make_sender_crypt();
    let encrypted_inbound = (0..batch_frames)
        .map(|i| {
            let clear = build_inbound_legacy(1000 + i as u64);
            let mut encrypted = vec![0u8; clear.len() + sender.overhead()];
            sender.encrypt(&mut encrypted, &clear).unwrap();
            Bytes::from(encrypted)
        })
        .collect();

    Workload {
        encrypted_inbound,
        inbound_receiver: make_receiver_crypt(),
        recipient_states: (0..fanout).map(|_| make_crypt()).collect(),
    }
}

fn decode_inbound_audio(receiver: &mut CryptState, packet: &[u8]) -> Audio {
    let mut decrypted = BytesMut::with_capacity(packet.len().saturating_sub(receiver.overhead()));
    receiver.decrypt(&mut decrypted, packet).unwrap();
    match IncomingUdpPacket::decode(&decrypted, Some(ClientSessionIdentifier::from(12345))).unwrap()
    {
        IncomingUdpPacket::Audio(audio) => audio,
        IncomingUdpPacket::Ping(_) => panic!("benchmark input unexpectedly decoded as ping"),
    }
}

fn encode_frame(audio: &Audio) -> EncodedFrame {
    let bytes = Audio::encode(audio, AudioContext::Normal, PacketFormat::Legacy);
    let checksum = CryptState::compute_plaintext_checksum(&bytes);
    EncodedFrame { bytes, checksum }
}

fn push_encrypted(
    batch: &mut DatagramBatch,
    addr: SocketAddr,
    state: &mut CryptState,
    frame: &EncodedFrame,
) {
    let encrypted_len = frame.bytes.len() + state.overhead();
    batch
        .try_push_zeroed(addr, encrypted_len, |buf| {
            state.encrypt_with_precomputed_checksum(buf, &frame.bytes, &frame.checksum)
        })
        .unwrap();
}

fn process_immediate_seq(mut workload: Workload, addr: SocketAddr) -> usize {
    let mut packets = 0;

    for packet in &workload.encrypted_inbound {
        let audio = decode_inbound_audio(&mut workload.inbound_receiver, packet);
        let frame = encode_frame(&audio);
        let mut batch = DatagramBatch::with_capacity(workload.recipient_states.len());

        for state in &mut workload.recipient_states {
            push_encrypted(&mut batch, addr, state, &frame);
            packets += 1;
        }

        black_box(batch);
    }

    packets
}

fn decode_batch(receiver: &mut CryptState, packets: &[Bytes]) -> Vec<Audio> {
    packets
        .iter()
        .map(|packet| decode_inbound_audio(receiver, packet))
        .collect()
}

fn encode_batch(audios: &[Audio]) -> Vec<EncodedFrame> {
    audios.iter().map(encode_frame).collect()
}

fn process_microbatch_frame_major_seq(mut workload: Workload, addr: SocketAddr) -> usize {
    let audios = decode_batch(&mut workload.inbound_receiver, &workload.encrypted_inbound);
    let frames = encode_batch(&audios);
    let mut batch = DatagramBatch::with_capacity(frames.len() * workload.recipient_states.len());
    let mut packets = 0;

    for frame in &frames {
        for state in &mut workload.recipient_states {
            push_encrypted(&mut batch, addr, state, frame);
            packets += 1;
        }
    }

    black_box(batch);
    packets
}

fn process_microbatch_recipient_major_seq(mut workload: Workload, addr: SocketAddr) -> usize {
    let audios = decode_batch(&mut workload.inbound_receiver, &workload.encrypted_inbound);
    let frames = encode_batch(&audios);
    let mut batch = DatagramBatch::with_capacity(frames.len() * workload.recipient_states.len());
    let mut packets = 0;

    for state in &mut workload.recipient_states {
        for frame in &frames {
            push_encrypted(&mut batch, addr, state, frame);
            packets += 1;
        }
    }

    black_box(batch);
    packets
}

fn process_microbatch_recipient_major_rayon(mut workload: Workload, addr: SocketAddr) -> usize {
    let audios = decode_batch(&mut workload.inbound_receiver, &workload.encrypted_inbound);
    let frames = encode_batch(&audios);
    let packets = frames.len() * workload.recipient_states.len();

    let batch = workload
        .recipient_states
        .into_par_iter()
        .with_min_len(RAYON_BATCH_MIN_LEN)
        .fold(DatagramBatch::new, |mut batch, mut state| {
            for frame in &frames {
                push_encrypted(&mut batch, addr, &mut state, frame);
            }
            batch
        })
        .reduce(DatagramBatch::new, |mut left, right| {
            left.append(right);
            left
        });

    black_box(batch);
    packets
}

fn encrypt_sequence_loop(state: &mut CryptState, frames: &[EncodedFrame]) -> Vec<Bytes> {
    frames
        .iter()
        .map(|frame| {
            let mut buf = vec![0u8; frame.bytes.len() + state.overhead()];
            state
                .encrypt_with_precomputed_checksum(&mut buf, &frame.bytes, &frame.checksum)
                .unwrap();
            Bytes::from(buf)
        })
        .collect()
}

fn encrypt_sequence_batch(state: &mut CryptState, frames: &[EncodedFrame]) -> Vec<Bytes> {
    let mut bufs = frames
        .iter()
        .map(|frame| vec![0u8; frame.bytes.len() + state.overhead()])
        .collect::<Vec<_>>();
    let mut dests = bufs
        .iter_mut()
        .map(|buf| buf.as_mut_slice())
        .collect::<Vec<_>>();
    let datas = frames
        .iter()
        .map(|frame| frame.bytes.as_ref())
        .collect::<Vec<_>>();
    let checksums = frames
        .iter()
        .map(|frame| frame.checksum)
        .collect::<Vec<_>>();

    state
        .encrypt_sequence_with_precomputed_checksums(&mut dests, &datas, &checksums)
        .unwrap();

    bufs.into_iter().map(Bytes::from).collect()
}

fn process_microbatch_crypto_loop_seq(mut workload: Workload) -> usize {
    let audios = decode_batch(&mut workload.inbound_receiver, &workload.encrypted_inbound);
    let frames = encode_batch(&audios);
    let mut packets = 0;

    for state in &mut workload.recipient_states {
        let out = encrypt_sequence_loop(state, &frames);
        packets += out.len();
        black_box(out);
    }

    packets
}

fn process_microbatch_crypto_batch_seq(mut workload: Workload) -> usize {
    let audios = decode_batch(&mut workload.inbound_receiver, &workload.encrypted_inbound);
    let frames = encode_batch(&audios);
    let mut packets = 0;

    for state in &mut workload.recipient_states {
        let out = encrypt_sequence_batch(state, &frames);
        packets += out.len();
        black_box(out);
    }

    packets
}

fn process_microbatch_crypto_batch_rayon(mut workload: Workload) -> usize {
    let audios = decode_batch(&mut workload.inbound_receiver, &workload.encrypted_inbound);
    let frames = encode_batch(&audios);
    let packets = frames.len() * workload.recipient_states.len();

    let out = workload
        .recipient_states
        .into_par_iter()
        .with_min_len(RAYON_BATCH_MIN_LEN)
        .map(|mut state| encrypt_sequence_batch(&mut state, &frames))
        .collect::<Vec<_>>();

    black_box(out);
    packets
}

fn batch_sizes() -> [usize; 4] {
    [1, 2, 4, 8]
}

fn fanout_sizes() -> [usize; 5] {
    [16, 64, 128, 256, 512]
}

fn added_latency_ms(batch_frames: usize) -> usize {
    batch_frames.saturating_sub(1) * OPUS_FRAME_MS
}

fn workload_label(fanout: usize, batch_frames: usize) -> String {
    format!(
        "fanout={fanout}/batch={batch_frames}/added_latency_ms={}",
        added_latency_ms(batch_frames)
    )
}

fn bench_voice_microbatch(c: &mut Criterion) {
    let addr = SocketAddr::from(([127, 0, 0, 1], 64738));
    let mut group = c.benchmark_group("voice_microbatch/decode_fanout");
    group.sample_size(20);

    for fanout in fanout_sizes() {
        for batch_frames in batch_sizes() {
            let label = workload_label(fanout, batch_frames);
            group.throughput(Throughput::Elements((fanout * batch_frames) as u64));

            group.bench_with_input(
                BenchmarkId::new("immediate_seq", &label),
                &(fanout, batch_frames),
                |b, &(fanout, batch_frames)| {
                    b.iter_batched(
                        || make_workload(batch_frames, fanout),
                        |workload| {
                            black_box(process_immediate_seq(workload, addr));
                        },
                        BatchSize::SmallInput,
                    );
                },
            );

            group.bench_with_input(
                BenchmarkId::new("microbatch_frame_major_seq", &label),
                &(fanout, batch_frames),
                |b, &(fanout, batch_frames)| {
                    b.iter_batched(
                        || make_workload(batch_frames, fanout),
                        |workload| {
                            black_box(process_microbatch_frame_major_seq(workload, addr));
                        },
                        BatchSize::SmallInput,
                    );
                },
            );

            group.bench_with_input(
                BenchmarkId::new("microbatch_recipient_major_seq", &label),
                &(fanout, batch_frames),
                |b, &(fanout, batch_frames)| {
                    b.iter_batched(
                        || make_workload(batch_frames, fanout),
                        |workload| {
                            black_box(process_microbatch_recipient_major_seq(workload, addr));
                        },
                        BatchSize::SmallInput,
                    );
                },
            );

            group.bench_with_input(
                BenchmarkId::new("microbatch_recipient_major_rayon", &label),
                &(fanout, batch_frames),
                |b, &(fanout, batch_frames)| {
                    b.iter_batched(
                        || make_workload(batch_frames, fanout),
                        |workload| {
                            black_box(process_microbatch_recipient_major_rayon(workload, addr));
                        },
                        BatchSize::SmallInput,
                    );
                },
            );

            group.bench_with_input(
                BenchmarkId::new("microbatch_crypto_loop_seq", &label),
                &(fanout, batch_frames),
                |b, &(fanout, batch_frames)| {
                    b.iter_batched(
                        || make_workload(batch_frames, fanout),
                        |workload| {
                            black_box(process_microbatch_crypto_loop_seq(workload));
                        },
                        BatchSize::SmallInput,
                    );
                },
            );

            group.bench_with_input(
                BenchmarkId::new("microbatch_crypto_batch_seq", &label),
                &(fanout, batch_frames),
                |b, &(fanout, batch_frames)| {
                    b.iter_batched(
                        || make_workload(batch_frames, fanout),
                        |workload| {
                            black_box(process_microbatch_crypto_batch_seq(workload));
                        },
                        BatchSize::SmallInput,
                    );
                },
            );

            group.bench_with_input(
                BenchmarkId::new("microbatch_crypto_batch_rayon", &label),
                &(fanout, batch_frames),
                |b, &(fanout, batch_frames)| {
                    b.iter_batched(
                        || make_workload(batch_frames, fanout),
                        |workload| {
                            black_box(process_microbatch_crypto_batch_rayon(workload));
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_voice_microbatch);
criterion_main!(benches);
