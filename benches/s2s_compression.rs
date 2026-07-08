use std::hint::black_box;
use std::io::Cursor;

use bytes::{Bytes, BytesMut};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use prost::Message as _;

use shitspeak_rs::s2s_application_proto as app_pb;
use shitspeak_rs::s2s_overlay_proto as overlay_pb;
use shitspeak_rs::s2s_replication_proto as repl_pb;
use shitspeak_rs::s2s_transport_proto as transport_pb;

const MIN_BYTES: usize = 1024;
const MIN_SAVINGS_PERCENT: usize = 10;
const ZSTD_LEVEL: i32 = 1;

fn encode<M: prost::Message>(msg: &M) -> Bytes {
    let mut buf = BytesMut::with_capacity(msg.encoded_len());
    msg.encode(&mut buf).unwrap();
    buf.freeze()
}

fn link_ads(count: u32, links_per_ad: u32) -> Vec<overlay_pb::LinkStateAdvert> {
    (0..count)
        .map(|origin| overlay_pb::LinkStateAdvert {
            origin,
            boot_epoch: 1,
            seq: origin as u64 + 1,
            ts_emit_us: 2,
            tombstone: false,
            addresses: vec![overlay_pb::AddressEntry {
                addr: "10.0.0.1:64739".to_string(),
                transport: 0,
            }],
            links: (0..links_per_ad)
                .map(|neighbor| overlay_pb::LinkAdvert {
                    neighbor,
                    rtt_us: 10_000,
                    jitter_us: 100,
                    throughput_bps: 1_000_000,
                    observed_recv_bps: 1_000_000,
                    observed_sent_bps: 1_000_000,
                    throughput_confidence_ppm: 1_000_000,
                    transports_mask: 0b1111,
                    loss_ppm: 10,
                    probe_loss_ppm: 10,
                    native_loss_ppm: 10,
                    data_health_ppm: 10,
                    loss_sample_count: 100,
                })
                .collect(),
            max_users: 100,
            transit_disabled: false,
            strict_replication_disabled: false,
            content_replication_disabled: false,
            owner_replication_disabled: false,
            voice_service_disabled: false,
        })
        .collect()
}

fn overlay_message(body: overlay_pb::overlay_message::Body) -> Bytes {
    encode(&overlay_pb::OverlayMessage { body: Some(body) })
}

fn overlay_data(service_tag: u32, payload: Bytes) -> Bytes {
    overlay_message(overlay_pb::overlay_message::Body::Data(
        overlay_pb::OverlayData {
            src: 1,
            dsts: vec![2],
            path_trace: vec![1],
            service_tag,
            service_level: 0,
            message_class: 1,
            payload,
            process_on_transit: false,
            route_metric: 2,
            ordered_delivery: false,
            ordering_seq: 0,
            ordering_dst: 0,
            lane_id: None,
            origin_boot_epoch: 1,
            origin_message_id: 1,
            allow_l1_compression: true,
        },
    ))
}

fn lsa_flood_payload() -> Bytes {
    overlay_message(overlay_pb::overlay_message::Body::LsaFlood(
        overlay_pb::LsaFlood {
            advertisements: link_ads(64, 8),
        },
    ))
}

fn lsdb_sync_resp_payload() -> Bytes {
    overlay_message(overlay_pb::overlay_message::Body::LsdbSyncResp(
        overlay_pb::LsdbSyncResp {
            delta: link_ads(128, 8),
        },
    ))
}

fn strict_catchup_resp_payload() -> Bytes {
    let resp = repl_pb::StrictCatchupResp {
        snapshot_version: 1000,
        snapshot_msgpack: Bytes::from(vec![0x44; 128 * 1024]),
        ops: (0..128)
            .map(|version| repl_pb::CatchupOp {
                version,
                op_msgpack: Bytes::from(vec![0x55; 512]),
                strict_op_id_hi: 0,
                strict_op_id_lo: 0,
                strict_ts_final: 0,
            })
            .collect(),
        has_more: true,
        next_chunk_token: 2,
        too_old_use_snapshot: false,
        history_version: 1000,
        history_freshness: 1_700_000_000,
        runtime_started_at: 1,
        history_node: 1,
    };
    let msg = repl_pb::ReplicationMessage {
        topic: "channels".to_string(),
        body: Some(repl_pb::replication_message::Body::Strict(
            repl_pb::StrictMessage {
                body: Some(repl_pb::strict_message::Body::CatchupResp(resp)),
            },
        )),
    };
    overlay_data(1, encode(&msg))
}

fn owner_catchup_resp_payload() -> Bytes {
    let resp = repl_pb::OwnerCatchupResp {
        origin_node: 1,
        origin_epoch: 1,
        snapshot_version: 500,
        snapshot_msgpack: Bytes::from(vec![0x66; 96 * 1024]),
        ops: (0..128)
            .map(|version| repl_pb::CatchupOp {
                version,
                op_msgpack: Bytes::from(vec![0x77; 512]),
                strict_op_id_hi: 0,
                strict_op_id_lo: 0,
                strict_ts_final: 0,
            })
            .collect(),
        has_more: true,
        next_chunk_token: 2,
        too_old_use_snapshot: false,
    };
    let msg = repl_pb::ReplicationMessage {
        topic: "clients".to_string(),
        body: Some(repl_pb::replication_message::Body::Owner(
            repl_pb::OwnerMessage {
                body: Some(repl_pb::owner_message::Body::CatchupResp(resp)),
            },
        )),
    };
    overlay_data(1, encode(&msg))
}

fn blob_chunk_payload() -> Bytes {
    let chunk = repl_pb::BlobChunk {
        request_id: 7,
        provider: 1,
        key: "0123456789abcdef0123456789abcdef01234567".to_string(),
        index: 3,
        chunk_size: 64 * 1024,
        total_size: 256 * 1024,
        data: Bytes::from(vec![0xAB; 64 * 1024]),
    };
    let msg = repl_pb::ReplicationMessage {
        topic: "blobs".to_string(),
        body: Some(repl_pb::replication_message::Body::Blob(
            repl_pb::BlobMessage {
                body: Some(repl_pb::blob_message::Body::Chunk(chunk)),
            },
        )),
    };
    overlay_data(1, encode(&msg))
}

fn plugin_data_payload() -> Bytes {
    let env = app_pb::PluginDataEnvelope {
        sender_session: 10,
        receiver_sessions: (100..180).collect(),
        data: Bytes::from(vec![0xCD; 48 * 1024]),
        data_id: Some("benchmark-plugin-payload".to_string()),
        server_id: "default".to_string(),
    };
    overlay_data(5, encode(&env))
}

fn frame_for_payload(payload: Bytes) -> transport_pb::Frame {
    transport_pb::Frame {
        src_node: 1,
        dst_node: 2,
        service_level: transport_pb::ServiceLevel::ServiceReliable as i32,
        frame_type: transport_pb::FrameType::FrameData as i32,
        message_class: transport_pb::MessageClass::ClassRegular as i32,
        ts_us: 1,
        payload,
        payload_encoding: transport_pb::PayloadEncoding::Identity as i32,
        uncompressed_payload_len: 0,
        payload_dictionary_id: 0,
    }
}

fn encode_raw_frame(payload: &Bytes) -> Bytes {
    encode(&frame_for_payload(payload.clone()))
}

fn encode_l1_compressed_frame(payload: &Bytes) -> Bytes {
    let mut frame = frame_for_payload(payload.clone());
    if payload.len() >= MIN_BYTES {
        let compressed =
            zstd::stream::encode_all(Cursor::new(payload.as_ref()), ZSTD_LEVEL).unwrap();
        let saves_enough = compressed.len() * 100 <= payload.len() * (100 - MIN_SAVINGS_PERCENT);
        if saves_enough {
            frame.payload = Bytes::from(compressed);
            frame.payload_encoding = transport_pb::PayloadEncoding::Zstd as i32;
            frame.uncompressed_payload_len = payload.len() as u64;
        }
    }
    encode(&frame)
}

fn decode_l1_frame(encoded: &Bytes) -> Bytes {
    let frame = transport_pb::Frame::decode(encoded.as_ref()).unwrap();
    match transport_pb::PayloadEncoding::try_from(frame.payload_encoding).unwrap() {
        transport_pb::PayloadEncoding::Identity => frame.payload,
        transport_pb::PayloadEncoding::Zstd => {
            Bytes::from(zstd::stream::decode_all(Cursor::new(frame.payload.as_ref())).unwrap())
        }
        transport_pb::PayloadEncoding::ZstdDict => {
            panic!("benchmark decoder was not configured with a zstd dictionary")
        }
    }
}

fn samples() -> Vec<(&'static str, Bytes)> {
    vec![
        ("lsa_flood", lsa_flood_payload()),
        ("lsdb_sync_resp", lsdb_sync_resp_payload()),
        ("strict_catchup_resp", strict_catchup_resp_payload()),
        ("owner_catchup_resp", owner_catchup_resp_payload()),
        ("blob_chunk", blob_chunk_payload()),
        ("plugin_data", plugin_data_payload()),
    ]
}

fn bench_s2s_l1_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("s2s/l1_compression");
    for (name, payload) in samples() {
        group.throughput(Throughput::Bytes(payload.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("raw_frame_encode", name),
            &payload,
            |b, p| {
                b.iter(|| black_box(encode_raw_frame(black_box(p))));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("zstd_frame_encode", name),
            &payload,
            |b, p| {
                b.iter(|| black_box(encode_l1_compressed_frame(black_box(p))));
            },
        );

        let compressed = encode_l1_compressed_frame(&payload);
        group.bench_with_input(
            BenchmarkId::new("zstd_frame_decode", name),
            &compressed,
            |b, encoded| {
                b.iter(|| black_box(decode_l1_frame(black_box(encoded))));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_s2s_l1_compression);
criterion_main!(benches);
