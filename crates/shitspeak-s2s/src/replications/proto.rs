//! Encode/decode helpers for `ReplicationMessage` and its inner variants.
//!
//! The outer overlay envelope (`OverlayData`) is provided by L2; this module
//! deals only with the bytes we put into the envelope's `payload`.

use bytes::{Bytes, BytesMut};
use prost::Message as _;

use shitspeak_proto::s2s_replication_proto as pb;

pub use pb::{
    BlobChunk, BlobChunkReq, BlobFind, BlobMessage, BlobOffer, CatchupOp, OwnerCatchupReq,
    OwnerCatchupResp, OwnerMessage, OwnerOp, ReplicationMessage, StrictCatchupReq,
    StrictCatchupResp, StrictClockTick, StrictCommit, StrictMessage, StrictPropose,
    StrictProposeAck, StrictRecoveryAck, StrictRecoveryCommit, StrictRecoveryReq,
    blob_message::Body as BlobBody, owner_message::Body as OwnerBody,
    replication_message::Body as ReplBody, strict_message::Body as StrictBody,
};

/// Encode a `ReplicationMessage` to bytes ready for the overlay payload.
pub fn encode(msg: &ReplicationMessage) -> Result<Bytes, prost::EncodeError> {
    let mut buf = BytesMut::with_capacity(msg.encoded_len());
    msg.encode(&mut buf)?;
    Ok(buf.freeze())
}

/// Decode bytes carried in the overlay envelope.
pub fn decode(src: &[u8]) -> Result<ReplicationMessage, prost::DecodeError> {
    ReplicationMessage::decode(src)
}

/// Build a strict outer message for a given topic.
pub fn wrap_strict(topic: impl Into<String>, body: StrictBody) -> ReplicationMessage {
    ReplicationMessage {
        topic: topic.into(),
        body: Some(ReplBody::Strict(StrictMessage { body: Some(body) })),
    }
}

/// Build an owner outer message for a given topic.
pub fn wrap_owner(topic: impl Into<String>, body: OwnerBody) -> ReplicationMessage {
    ReplicationMessage {
        topic: topic.into(),
        body: Some(ReplBody::Owner(OwnerMessage { body: Some(body) })),
    }
}

/// Build a blob outer message for a given topic.
pub fn wrap_blob(topic: impl Into<String>, body: BlobBody) -> ReplicationMessage {
    ReplicationMessage {
        topic: topic.into(),
        body: Some(ReplBody::Blob(BlobMessage { body: Some(body) })),
    }
}

/// Reserved overlay service tag for the replications subsystem.
pub const REPLICATION_SERVICE_TAG: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    fn pretend_msgpack(n: u8) -> Bytes {
        Bytes::from(vec![n; 64])
    }

    #[test]
    fn roundtrip_strict_propose() {
        let msg = wrap_strict(
            "channels",
            StrictBody::Propose(StrictPropose {
                coord_node: 7,
                op_id_hi: 0xDEAD_BEEF,
                op_id_lo: 0xFEED_FACE,
                ts_propose: 42,
                op_msgpack: pretend_msgpack(0xAB),
                src_clock: 100,
            }),
        );
        let bytes = encode(&msg).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back.topic, "channels");
        let Some(ReplBody::Strict(s)) = back.body else {
            panic!("not strict");
        };
        let Some(StrictBody::Propose(p)) = s.body else {
            panic!("not propose");
        };
        assert_eq!(p.coord_node, 7);
        assert_eq!(p.op_id_hi, 0xDEAD_BEEF);
        assert_eq!(p.op_id_lo, 0xFEED_FACE);
        assert_eq!(p.ts_propose, 42);
        assert_eq!(p.op_msgpack.len(), 64);
        assert!(p.op_msgpack.iter().all(|b| *b == 0xAB));
        assert_eq!(p.src_clock, 100);
    }

    #[test]
    fn roundtrip_strict_propose_ack() {
        let msg = wrap_strict(
            "bans",
            StrictBody::ProposeAck(StrictProposeAck {
                ack_node: 3,
                coord_node: 7,
                op_id_hi: 1,
                op_id_lo: 2,
                ts_local: 50,
                src_clock: 50,
            }),
        );
        let bytes = encode(&msg).unwrap();
        let back = decode(&bytes).unwrap();
        let Some(ReplBody::Strict(StrictMessage {
            body: Some(StrictBody::ProposeAck(a)),
        })) = back.body
        else {
            panic!()
        };
        assert_eq!(a.ack_node, 3);
        assert_eq!(a.coord_node, 7);
        assert_eq!(a.ts_local, 50);
    }

    #[test]
    fn roundtrip_strict_commit() {
        let msg = wrap_strict(
            "channels",
            StrictBody::Commit(StrictCommit {
                coord_node: 9,
                op_id_hi: 11,
                op_id_lo: 22,
                ts_final: 77,
                op_msgpack: pretend_msgpack(0xCD),
                src_clock: 80,
            }),
        );
        let bytes = encode(&msg).unwrap();
        let back = decode(&bytes).unwrap();
        let Some(ReplBody::Strict(StrictMessage {
            body: Some(StrictBody::Commit(c)),
        })) = back.body
        else {
            panic!()
        };
        assert_eq!(c.ts_final, 77);
        assert_eq!(c.op_msgpack.len(), 64);
    }

    #[test]
    fn roundtrip_strict_clock_tick_and_catchup() {
        let tick = wrap_strict(
            "channels",
            StrictBody::ClockTick(StrictClockTick {
                src_node: 1,
                src_clock: 999,
            }),
        );
        let bytes = encode(&tick).unwrap();
        decode(&bytes).unwrap();

        let req = wrap_strict(
            "channels",
            StrictBody::CatchupReq(StrictCatchupReq {
                src_node: 2,
                since_version: 5,
                chunk_token: 0,
                force_snapshot: false,
            }),
        );
        let bytes = encode(&req).unwrap();
        decode(&bytes).unwrap();

        let resp = wrap_strict(
            "channels",
            StrictBody::CatchupResp(StrictCatchupResp {
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: vec![
                    CatchupOp {
                        version: 6,
                        op_msgpack: pretend_msgpack(0x01),
                        strict_op_id_hi: 0,
                        strict_op_id_lo: 0,
                        strict_ts_final: 0,
                    },
                    CatchupOp {
                        version: 7,
                        op_msgpack: pretend_msgpack(0x02),
                        strict_op_id_hi: 0,
                        strict_op_id_lo: 0,
                        strict_ts_final: 0,
                    },
                ],
                has_more: true,
                next_chunk_token: 1,
                too_old_use_snapshot: false,
                history_version: 7,
                history_freshness: 123,
                runtime_started_at: 456,
                history_node: 2,
            }),
        );
        let bytes = encode(&resp).unwrap();
        let back = decode(&bytes).unwrap();
        let Some(ReplBody::Strict(StrictMessage {
            body: Some(StrictBody::CatchupResp(r)),
        })) = back.body
        else {
            panic!()
        };
        assert_eq!(r.ops.len(), 2);
        assert!(r.has_more);
        assert_eq!(r.next_chunk_token, 1);
    }

    #[test]
    fn roundtrip_owner_op_and_catchup() {
        let op = wrap_owner(
            "clients",
            OwnerBody::Op(OwnerOp {
                origin_node: 5,
                origin_epoch: 100_000,
                origin_version: 1,
                op_msgpack: pretend_msgpack(0x10),
            }),
        );
        let bytes = encode(&op).unwrap();
        let back = decode(&bytes).unwrap();
        let Some(ReplBody::Owner(OwnerMessage {
            body: Some(OwnerBody::Op(o)),
        })) = back.body
        else {
            panic!()
        };
        assert_eq!(o.origin_node, 5);
        assert_eq!(o.origin_epoch, 100_000);
        assert_eq!(o.origin_version, 1);
        assert_eq!(o.op_msgpack.len(), 64);

        let req = wrap_owner(
            "clients",
            OwnerBody::CatchupReq(OwnerCatchupReq {
                origin_node: 5,
                src_node: 7,
                known_epoch: 100_000,
                since_version: 0,
                chunk_token: 0,
            }),
        );
        let bytes = encode(&req).unwrap();
        decode(&bytes).unwrap();

        let resp = wrap_owner(
            "clients",
            OwnerBody::CatchupResp(OwnerCatchupResp {
                origin_node: 5,
                origin_epoch: 100_000,
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: vec![CatchupOp {
                    version: 1,
                    op_msgpack: pretend_msgpack(0x11),
                    strict_op_id_hi: 0,
                    strict_op_id_lo: 0,
                    strict_ts_final: 0,
                }],
                has_more: false,
                next_chunk_token: 0,
                too_old_use_snapshot: false,
            }),
        );
        let bytes = encode(&resp).unwrap();
        decode(&bytes).unwrap();
    }

    #[test]
    fn roundtrip_strict_recovery_messages() {
        let req = wrap_strict(
            "channels",
            StrictBody::RecoveryReq(StrictRecoveryReq {
                takeover_node: 4,
                ballot: ((4u64) << 32) | 1,
                coord_node: 7,
                op_id_hi: 0xAA,
                op_id_lo: 0xBB,
                src_clock: 50,
            }),
        );
        let back = decode(&encode(&req).unwrap()).unwrap();
        let Some(ReplBody::Strict(StrictMessage {
            body: Some(StrictBody::RecoveryReq(r)),
        })) = back.body
        else {
            panic!()
        };
        assert_eq!(r.takeover_node, 4);
        assert_eq!(r.coord_node, 7);
        assert_eq!(r.op_id_hi, 0xAA);

        let ack = wrap_strict(
            "channels",
            StrictBody::RecoveryAck(StrictRecoveryAck {
                ack_node: 5,
                ballot: ((4u64) << 32) | 1,
                coord_node: 7,
                op_id_hi: 0xAA,
                op_id_lo: 0xBB,
                promised: true,
                has_committed: false,
                committed_ts_final: 0,
                has_op: true,
                ts_local: 41,
                op_msgpack: pretend_msgpack(0x55),
                src_clock: 60,
            }),
        );
        let back = decode(&encode(&ack).unwrap()).unwrap();
        let Some(ReplBody::Strict(StrictMessage {
            body: Some(StrictBody::RecoveryAck(a)),
        })) = back.body
        else {
            panic!()
        };
        assert_eq!(a.ts_local, 41);
        assert!(a.has_op && a.promised && !a.has_committed);
        assert_eq!(a.op_msgpack.len(), 64);

        let cmt = wrap_strict(
            "channels",
            StrictBody::RecoveryCommit(StrictRecoveryCommit {
                takeover_node: 4,
                ballot: ((4u64) << 32) | 1,
                coord_node: 7,
                op_id_hi: 0xAA,
                op_id_lo: 0xBB,
                ts_final: 88,
                op_msgpack: pretend_msgpack(0x55),
                src_clock: 90,
            }),
        );
        let back = decode(&encode(&cmt).unwrap()).unwrap();
        let Some(ReplBody::Strict(StrictMessage {
            body: Some(StrictBody::RecoveryCommit(c)),
        })) = back.body
        else {
            panic!()
        };
        assert_eq!(c.ts_final, 88);
    }

    /// ~64 KiB op body must survive an encode+decode roundtrip without
    /// truncation at the proto layer.
    #[test]
    fn oversized_msgpack_decoded_intact() {
        let blob: Vec<u8> = (0..64 * 1024).map(|i| (i & 0xff) as u8).collect();
        let msg = wrap_strict(
            "channels",
            StrictBody::Propose(StrictPropose {
                coord_node: 1,
                op_id_hi: 0,
                op_id_lo: 1,
                ts_propose: 1,
                op_msgpack: Bytes::from(blob.clone()),
                src_clock: 1,
            }),
        );
        let bytes = encode(&msg).unwrap();
        let back = decode(&bytes).unwrap();
        let Some(ReplBody::Strict(StrictMessage {
            body: Some(StrictBody::Propose(p)),
        })) = back.body
        else {
            panic!()
        };
        assert_eq!(p.op_msgpack.len(), 64 * 1024);
        assert_eq!(p.op_msgpack, blob);
    }
}
