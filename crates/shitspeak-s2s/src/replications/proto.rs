//! Encode/decode helpers for `ReplicationMessage` and its inner variants.
//!
//! The outer overlay envelope (`OverlayData`) is provided by L2; this module
//! deals only with the bytes we put into the envelope's `payload`.

use std::sync::OnceLock;

use bytes::{Bytes, BytesMut};
use prost::Message as _;

use shitspeak_proto::s2s_replication_proto as pb;

pub use pb::{
    BlobChunk, BlobChunkReq, BlobFind, BlobMessage, BlobOffer, CatchupOp, OwnerCatchupReq,
    OwnerCatchupResp, OwnerMessage, OwnerOp, ReplicationMessage, StrictAccept, StrictAcceptAck,
    StrictAcceptedValue, StrictCatchupReason, StrictCatchupReq, StrictCatchupResp,
    StrictClockProbeReq, StrictClockProbeResp, StrictClockTick, StrictCommit, StrictDecision,
    StrictDecisionAbort, StrictDecisionCommit, StrictFrozenTarget, StrictHistoryProbeReq,
    StrictHistoryProbeResp, StrictHistoryTransferReq, StrictHistoryTransferResp, StrictMessage,
    StrictOriginAuth, StrictPendingValue, StrictPropose, StrictProposeAck, StrictProposeV1,
    StrictRecoveryAck, StrictRecoveryCommit, StrictRecoveryReq, StrictResolutionAck,
    StrictResolutionHint, StrictResolutionPrepare, StrictTerminalCut, StrictTerminalDelta,
    StrictTerminalPageKind, StrictTerminalState, StrictTerminalSyncAck, StrictTerminalSyncPage,
    StrictTerminalSyncReq, StrictTerminalSyncStatus, blob_message::Body as BlobBody,
    owner_message::Body as OwnerBody, replication_message::Body as ReplBody,
    strict_decision::Outcome as StrictDecisionOutcome, strict_message::Body as StrictBody,
    strict_resolution_ack::Observed as StrictResolutionObserved,
    strict_terminal_state::Outcome as StrictTerminalOutcome,
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

/// Domain separator for end-to-end strict origin proofs.
pub const STRICT_ORIGIN_SIGNATURE_DOMAIN: &[u8] = b"shitspeak-strict-origin-v1\0";
/// The bounded v2 origin-proof contract. A proof is carried on every strict
/// frame emitted by a v2-capable node, so terminal admission must reserve its
/// worst-case size for any later catchup responder, not only this node.
pub const STRICT_ORIGIN_AUTH_MAX_CERTIFICATES: usize = 4;
pub const STRICT_ORIGIN_AUTH_MAX_CERTIFICATE_CHAIN_BYTES: usize = 16 * 1024;
pub const STRICT_ORIGIN_AUTH_MAX_SIGNATURE_BYTES: usize = 8 * 1024;
/// Protocol-wide payload ceiling for authenticated strict v2 replication.
/// Nodes with a smaller routed-frame budget remain at v0 rather than
/// advertising a capability they cannot relay safely across the cluster.
pub const STRICT_V2_MAX_REPLICATION_PAYLOAD_BYTES: usize = 48 * 1024;

/// Check the origin-proof limits directly on a replication wire payload.
///
/// Prost allocates repeated `bytes` fields while decoding. This preflight
/// bounds the nested `StrictOriginAuth` representation before an adversarial
/// payload can materialize an unbounded certificate-chain vector. It accepts
/// unknown fields for protobuf compatibility, but rejects duplicate
/// `origin_auth` envelopes because the protocol emits exactly one.
pub(crate) fn strict_origin_auth_wire_within_bounds(src: &[u8]) -> bool {
    let mut offset = 0;
    let mut strict_seen = false;
    while offset < src.len() {
        let Some((field, wire_type)) = read_wire_key(src, &mut offset) else {
            return false;
        };
        if field == 2 {
            if wire_type != 2 || strict_seen {
                return false;
            }
            strict_seen = true;
            let Some(strict) = take_length_delimited(src, &mut offset) else {
                return false;
            };
            if !strict_message_origin_auth_wire_within_bounds(strict) {
                return false;
            }
        } else if !skip_wire_value(src, &mut offset, wire_type) {
            return false;
        }
    }
    true
}

fn strict_message_origin_auth_wire_within_bounds(src: &[u8]) -> bool {
    let mut offset = 0;
    let mut origin_auth_seen = false;
    while offset < src.len() {
        let Some((field, wire_type)) = read_wire_key(src, &mut offset) else {
            return false;
        };
        if field == 17 {
            if wire_type != 2 || origin_auth_seen {
                return false;
            }
            origin_auth_seen = true;
            let Some(auth) = take_length_delimited(src, &mut offset) else {
                return false;
            };
            if !origin_auth_fields_within_bounds(auth) {
                return false;
            }
        } else if !skip_wire_value(src, &mut offset, wire_type) {
            return false;
        }
    }
    true
}

fn origin_auth_fields_within_bounds(src: &[u8]) -> bool {
    let mut offset = 0;
    let mut certificate_count = 0usize;
    let mut certificate_bytes = 0usize;
    let mut signature_seen = false;

    while offset < src.len() {
        let Some((field, wire_type)) = read_wire_key(src, &mut offset) else {
            return false;
        };
        match field {
            1..=3 if wire_type == 0 => {
                if read_wire_varint(src, &mut offset).is_none() {
                    return false;
                }
            }
            4 if wire_type == 2 => {
                let Some(certificate) = take_length_delimited(src, &mut offset) else {
                    return false;
                };
                certificate_count = match certificate_count.checked_add(1) {
                    Some(count) if count <= STRICT_ORIGIN_AUTH_MAX_CERTIFICATES => count,
                    _ => return false,
                };
                certificate_bytes = match certificate_bytes.checked_add(certificate.len()) {
                    Some(bytes) if bytes <= STRICT_ORIGIN_AUTH_MAX_CERTIFICATE_CHAIN_BYTES => bytes,
                    _ => return false,
                };
            }
            5 if wire_type == 2 => {
                if signature_seen {
                    return false;
                }
                signature_seen = true;
                let Some(signature) = take_length_delimited(src, &mut offset) else {
                    return false;
                };
                if signature.len() > STRICT_ORIGIN_AUTH_MAX_SIGNATURE_BYTES {
                    return false;
                }
            }
            1..=5 => return false,
            _ if !skip_wire_value(src, &mut offset, wire_type) => return false,
            _ => {}
        }
    }
    true
}

fn read_wire_key(src: &[u8], offset: &mut usize) -> Option<(u64, u8)> {
    let key = read_wire_varint(src, offset)?;
    let field = key >> 3;
    (field != 0).then_some((field, (key & 0x07) as u8))
}

fn read_wire_varint(src: &[u8], offset: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *src.get(*offset)?;
        *offset += 1;
        let bits = u64::from(byte & 0x7F);
        if shift == 63 && bits > 1 {
            return None;
        }
        value |= bits << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

fn take_length_delimited<'a>(src: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let length = usize::try_from(read_wire_varint(src, offset)?).ok()?;
    let end = offset.checked_add(length)?;
    let value = src.get(*offset..end)?;
    *offset = end;
    Some(value)
}

fn skip_wire_value(src: &[u8], offset: &mut usize, wire_type: u8) -> bool {
    match wire_type {
        0 => read_wire_varint(src, offset).is_some(),
        1 => advance_wire_offset(src, offset, 8),
        2 => take_length_delimited(src, offset).is_some(),
        5 => advance_wire_offset(src, offset, 4),
        _ => false,
    }
}

fn advance_wire_offset(src: &[u8], offset: &mut usize, length: usize) -> bool {
    let Some(end) = offset.checked_add(length) else {
        return false;
    };
    if end > src.len() {
        return false;
    }
    *offset = end;
    true
}

/// Build a strict outer message for a given topic.
pub fn wrap_strict(topic: impl Into<String>, body: StrictBody) -> ReplicationMessage {
    ReplicationMessage {
        topic: topic.into(),
        body: Some(ReplBody::Strict(StrictMessage {
            body: Some(body),
            origin_auth: None,
        })),
    }
}

/// Build a strict outer message carrying a proof for the logical source.
pub fn wrap_strict_with_origin_auth(
    topic: impl Into<String>,
    body: StrictBody,
    origin_auth: StrictOriginAuth,
) -> ReplicationMessage {
    ReplicationMessage {
        topic: topic.into(),
        body: Some(ReplBody::Strict(StrictMessage {
            body: Some(body),
            origin_auth: Some(origin_auth),
        })),
    }
}

/// Canonical bytes signed by a strict logical origin.
///
/// The unsigned message is encoded separately so the proof does not sign
/// itself. Forwarders preserve the replication payload, making the proof
/// valid across any number of overlay hops.
pub fn strict_origin_signing_payload(
    topic: &str,
    body: &StrictBody,
    origin_node: u32,
    origin_boot_epoch: u64,
) -> Result<Bytes, prost::EncodeError> {
    let unsigned = wrap_strict(topic, body.clone());
    let encoded = encode(&unsigned)?;
    let mut payload = BytesMut::with_capacity(
        STRICT_ORIGIN_SIGNATURE_DOMAIN.len()
            + std::mem::size_of::<u32>()
            + std::mem::size_of::<u64>()
            + encoded.len(),
    );
    payload.extend_from_slice(STRICT_ORIGIN_SIGNATURE_DOMAIN);
    payload.extend_from_slice(&origin_node.to_be_bytes());
    payload.extend_from_slice(&origin_boot_epoch.to_be_bytes());
    payload.extend_from_slice(&encoded);
    Ok(payload.freeze())
}

/// Exact replication-payload size once an origin proof is attached.
pub fn strict_encoded_len_with_origin_auth(
    topic: &str,
    body: &StrictBody,
    origin_auth: &StrictOriginAuth,
) -> usize {
    wrap_strict_with_origin_auth(topic, body.clone(), origin_auth.clone()).encoded_len()
}

/// Replication-payload size with the protocol-wide maximum origin proof.
/// The large byte buffers in the budget template are initialized once and
/// shared by cheap `Bytes` clones across repeated readiness checks.
pub(crate) fn strict_encoded_len_with_origin_auth_budget(topic: &str, body: &StrictBody) -> usize {
    strict_encoded_len_with_origin_auth(topic, body, strict_origin_auth_budget_template_ref())
}

/// Whether a received or locally generated proof satisfies the bounded v2
/// wire contract. Limit it before cryptographic verification and use the
/// matching budget template for every frame-size admission decision.
pub fn strict_origin_auth_within_bounds(auth: &StrictOriginAuth) -> bool {
    strict_origin_auth_shape_within_bounds(
        auth.certificate_chain
            .iter()
            .map(|certificate| certificate.len()),
        auth.signature.len(),
    )
}

/// Whether proof metadata satisfies the bounded v2 wire contract. This lets
/// readiness and frame-size admission validate the local proof shape without
/// creating a detached signature merely to learn its maximum encoded size.
pub(crate) fn strict_origin_auth_shape_within_bounds(
    certificate_lengths: impl IntoIterator<Item = usize>,
    maximum_signature_len: usize,
) -> bool {
    let mut certificate_count = 0usize;
    let mut certificate_bytes = 0usize;
    for length in certificate_lengths {
        certificate_count = match certificate_count.checked_add(1) {
            Some(count) if count <= STRICT_ORIGIN_AUTH_MAX_CERTIFICATES => count,
            _ => return false,
        };
        certificate_bytes = match certificate_bytes.checked_add(length) {
            Some(bytes) if bytes <= STRICT_ORIGIN_AUTH_MAX_CERTIFICATE_CHAIN_BYTES => bytes,
            _ => return false,
        };
    }

    maximum_signature_len <= STRICT_ORIGIN_AUTH_MAX_SIGNATURE_BYTES
}

/// Conservative proof shape used for v2 frame admission. Scalar values use
/// their largest protobuf encoding and certificate bytes are split across the
/// maximum number of repeated fields to include every tag/length overhead.
pub fn strict_origin_auth_budget_template() -> StrictOriginAuth {
    strict_origin_auth_budget_template_ref().clone()
}

fn strict_origin_auth_budget_template_ref() -> &'static StrictOriginAuth {
    static TEMPLATE: OnceLock<StrictOriginAuth> = OnceLock::new();
    TEMPLATE.get_or_init(|| {
        let certificate_bytes_per_entry = (STRICT_ORIGIN_AUTH_MAX_CERTIFICATE_CHAIN_BYTES
            + STRICT_ORIGIN_AUTH_MAX_CERTIFICATES
            - 1)
            / STRICT_ORIGIN_AUTH_MAX_CERTIFICATES;
        StrictOriginAuth {
            origin_node: u32::MAX,
            origin_boot_epoch: u64::MAX,
            signature_scheme: u32::MAX,
            certificate_chain: (0..STRICT_ORIGIN_AUTH_MAX_CERTIFICATES)
                .map(|_| Bytes::from(vec![0; certificate_bytes_per_entry]))
                .collect(),
            signature: Bytes::from(vec![0; STRICT_ORIGIN_AUTH_MAX_SIGNATURE_BYTES]),
        }
    })
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

    fn roundtrip_strict_body(body: StrictBody) -> StrictBody {
        let msg = wrap_strict("channels", body);
        let back = decode(&encode(&msg).unwrap()).unwrap();
        let Some(ReplBody::Strict(strict)) = back.body else {
            panic!("not strict");
        };
        strict.body.expect("strict body")
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
    fn roundtrip_strict_propose_v1_uses_a_distinct_body() {
        let body = roundtrip_strict_body(StrictBody::ProposeV1(StrictProposeV1 {
            coord_node: 7,
            op_id_hi: 0xDEAD_BEEF,
            op_id_lo: 0xFEED_FACE,
            ts_propose: 42,
            op_msgpack: pretend_msgpack(0xAB),
            src_clock: 100,
            protocol_version: 1,
            frozen_targets: vec![],
        }));
        let StrictBody::ProposeV1(propose) = body else {
            panic!("not v1 propose");
        };
        assert_eq!(propose.protocol_version, 1);
        assert!(propose.frozen_targets.is_empty());
    }

    #[test]
    fn strict_origin_auth_roundtrips_and_binds_the_unsigned_body() {
        let body = StrictBody::ClockTick(StrictClockTick {
            src_node: 7,
            src_clock: 41,
        });
        let auth = StrictOriginAuth {
            origin_node: 7,
            origin_boot_epoch: 19,
            signature_scheme: 0x0807,
            certificate_chain: vec![Bytes::from_static(&[1, 2, 3])],
            signature: Bytes::from_static(&[4, 5, 6]),
        };
        let signed = strict_origin_signing_payload("channels", &body, 7, 19).unwrap();
        assert_ne!(
            signed,
            strict_origin_signing_payload("channels", &body, 8, 19).unwrap()
        );
        assert_ne!(
            signed,
            strict_origin_signing_payload("other-topic", &body, 7, 19).unwrap()
        );

        let decoded = decode(
            &encode(&wrap_strict_with_origin_auth(
                "channels",
                body,
                auth.clone(),
            ))
            .unwrap(),
        )
        .unwrap();
        let Some(ReplBody::Strict(StrictMessage {
            body: Some(StrictBody::ClockTick(_)),
            origin_auth: Some(received_auth),
        })) = decoded.body
        else {
            panic!("strict origin auth did not roundtrip");
        };
        assert_eq!(received_auth, auth);
    }

    #[test]
    fn strict_origin_auth_budget_is_bounded_and_conservative() {
        let template = strict_origin_auth_budget_template();
        assert!(strict_origin_auth_within_bounds(&template));
        assert_eq!(
            template
                .certificate_chain
                .iter()
                .map(|entry| entry.len())
                .sum::<usize>(),
            STRICT_ORIGIN_AUTH_MAX_CERTIFICATE_CHAIN_BYTES
        );

        let mut signature = template.signature.to_vec();
        signature.push(0);
        let oversized = StrictOriginAuth {
            signature: Bytes::from(signature),
            ..template.clone()
        };
        assert!(!strict_origin_auth_within_bounds(&oversized));

        let body = StrictBody::ClockTick(Default::default());
        assert_eq!(
            strict_encoded_len_with_origin_auth_budget("channels", &body),
            strict_encoded_len_with_origin_auth("channels", &body, &template),
        );
    }

    #[test]
    fn strict_origin_auth_shape_checks_metadata_without_signature_bytes() {
        assert!(strict_origin_auth_shape_within_bounds(
            [
                STRICT_ORIGIN_AUTH_MAX_CERTIFICATE_CHAIN_BYTES / 2,
                STRICT_ORIGIN_AUTH_MAX_CERTIFICATE_CHAIN_BYTES / 2,
            ],
            STRICT_ORIGIN_AUTH_MAX_SIGNATURE_BYTES,
        ));
        assert!(!strict_origin_auth_shape_within_bounds(
            [0; STRICT_ORIGIN_AUTH_MAX_CERTIFICATES + 1],
            0,
        ));
        assert!(!strict_origin_auth_shape_within_bounds(
            [STRICT_ORIGIN_AUTH_MAX_CERTIFICATE_CHAIN_BYTES + 1],
            0,
        ));
        assert!(!strict_origin_auth_shape_within_bounds(
            [],
            STRICT_ORIGIN_AUTH_MAX_SIGNATURE_BYTES + 1,
        ));
    }

    #[test]
    fn strict_origin_auth_wire_preflight_rejects_oversized_repeated_fields() {
        let body = StrictBody::ClockTick(Default::default());
        let bounded = wrap_strict_with_origin_auth(
            "channels",
            body.clone(),
            strict_origin_auth_budget_template(),
        );
        assert!(strict_origin_auth_wire_within_bounds(
            &encode(&bounded).expect("bounded proof should encode")
        ));

        let too_many_certificates = StrictOriginAuth {
            origin_node: 1,
            origin_boot_epoch: 1,
            signature_scheme: 0x0807,
            certificate_chain: (0..=STRICT_ORIGIN_AUTH_MAX_CERTIFICATES)
                .map(|_| Bytes::new())
                .collect(),
            signature: Bytes::new(),
        };
        let too_many =
            wrap_strict_with_origin_auth("channels", body.clone(), too_many_certificates);
        assert!(!strict_origin_auth_wire_within_bounds(
            &encode(&too_many).expect("oversized proof should encode")
        ));

        let oversized_chain = StrictOriginAuth {
            origin_node: 1,
            origin_boot_epoch: 1,
            signature_scheme: 0x0807,
            certificate_chain: vec![Bytes::from(vec![
                0;
                STRICT_ORIGIN_AUTH_MAX_CERTIFICATE_CHAIN_BYTES
                    + 1
            ])],
            signature: Bytes::new(),
        };
        let oversized = wrap_strict_with_origin_auth("channels", body, oversized_chain);
        assert!(!strict_origin_auth_wire_within_bounds(
            &encode(&oversized).expect("oversized proof should encode")
        ));
    }

    #[test]
    fn roundtrip_strict_v2_frozen_targets() {
        let frozen_targets = vec![
            StrictFrozenTarget {
                node: 3,
                boot_epoch: 18,
            },
            StrictFrozenTarget {
                node: 7,
                boot_epoch: 24,
            },
        ];

        let StrictBody::ProposeV1(propose) =
            roundtrip_strict_body(StrictBody::ProposeV1(StrictProposeV1 {
                coord_node: 7,
                op_id_hi: 0xAA,
                op_id_lo: 0xBB,
                ts_propose: 42,
                op_msgpack: pretend_msgpack(0xAB),
                src_clock: 100,
                protocol_version: 2,
                frozen_targets: frozen_targets.clone(),
            }))
        else {
            panic!("not v2 propose");
        };
        assert_eq!(propose.frozen_targets, frozen_targets);

        let StrictBody::ResolutionHint(hint) =
            roundtrip_strict_body(StrictBody::ResolutionHint(StrictResolutionHint {
                reporter_node: 3,
                coord_node: 7,
                op_id_hi: 0xAA,
                op_id_lo: 0xBB,
                ts_local: 54,
                op_msgpack: pretend_msgpack(0x12),
                src_clock: 62,
                reporter_boot_epoch: 18,
                protocol_version: 2,
                frozen_targets: frozen_targets.clone(),
            }))
        else {
            panic!("not v2 resolution hint");
        };
        assert_eq!(hint.frozen_targets, frozen_targets);

        let StrictBody::ResolutionPrepare(prepare) =
            roundtrip_strict_body(StrictBody::ResolutionPrepare(StrictResolutionPrepare {
                resolver_node: 4,
                ballot: 12,
                coord_node: 7,
                op_id_hi: 0xAA,
                op_id_lo: 0xBB,
                src_clock: 63,
                frozen_targets: frozen_targets.clone(),
            }))
        else {
            panic!("not v2 resolution prepare");
        };
        assert_eq!(prepare.frozen_targets, frozen_targets);

        let StrictBody::Decision(decision) =
            roundtrip_strict_body(StrictBody::Decision(StrictDecision {
                resolver_node: 7,
                ballot: 12,
                coord_node: 7,
                op_id_hi: 0xAA,
                op_id_lo: 0xBB,
                outcome: Some(StrictDecisionOutcome::Commit(StrictDecisionCommit {
                    ts_final: 55,
                    op_msgpack: pretend_msgpack(0x15),
                })),
                src_clock: 64,
                resolver_boot_epoch: 24,
                frozen_targets: frozen_targets.clone(),
                source_journal_id: Bytes::new(),
                source_terminal_generation: 0,
                source_previous_chain_digest: Bytes::new(),
                source_chain_digest: Bytes::new(),
                source_terminal_set_digest: Bytes::new(),
            }))
        else {
            panic!("not v2 decision");
        };
        assert_eq!(decision.resolver_boot_epoch, 24);
        assert_eq!(decision.frozen_targets, frozen_targets);
    }

    #[test]
    fn roundtrip_strict_v3_repair_bodies_and_decision_cut() {
        let base_cut = StrictTerminalCut {
            journal_id: Bytes::from_static(b"journal-lineage"),
            generation: 40,
            chain_digest: Bytes::from_static(b"chain-40"),
            terminal_set_digest: Bytes::from_static(b"set-40"),
        };
        let target_cut = StrictTerminalCut {
            generation: 41,
            chain_digest: Bytes::from_static(b"chain-41"),
            terminal_set_digest: Bytes::from_static(b"set-41"),
            ..base_cut.clone()
        };
        let terminal_state = StrictTerminalState {
            coord_node: 7,
            op_id_hi: 0xAA,
            op_id_lo: 0xBB,
            ballot: 19,
            outcome: Some(StrictTerminalOutcome::Abort(StrictDecisionAbort {})),
            resolver_node: 7,
            resolver_boot_epoch: 24,
            frozen_targets: vec![StrictFrozenTarget {
                node: 7,
                boot_epoch: 24,
            }],
        };

        let bodies = vec![
            StrictBody::ClockProbeReq(StrictClockProbeReq {
                src_node: 3,
                expected_responder_boot_epoch: 24,
                request_nonce: 101,
                reason: StrictCatchupReason::DeliveryWatermark as i32,
            }),
            StrictBody::ClockProbeResp(StrictClockProbeResp {
                responder_node: 7,
                expected_requester_boot_epoch: 18,
                request_nonce: 101,
                src_clock: 900,
                reason: StrictCatchupReason::DeliveryWatermark as i32,
            }),
            StrictBody::HistoryProbeReq(StrictHistoryProbeReq {
                src_node: 3,
                expected_responder_boot_epoch: 24,
                request_nonce: 102,
                reason: StrictCatchupReason::HistoryElection as i32,
            }),
            StrictBody::HistoryProbeResp(StrictHistoryProbeResp {
                responder_node: 7,
                expected_requester_boot_epoch: 18,
                request_nonce: 102,
                repository_version: 55,
                history_freshness: 123,
                runtime_started_at: 24,
                history_node: 7,
                terminal_cut: Some(target_cut.clone()),
                reason: StrictCatchupReason::HistoryElection as i32,
            }),
            StrictBody::TerminalSyncReq(StrictTerminalSyncReq {
                src_node: 3,
                expected_responder_boot_epoch: 24,
                reason: 4,
                known_source_cut: Some(base_cut.clone()),
                requester_terminal_set_digest: base_cut.terminal_set_digest.clone(),
                transfer_id: 0,
                request_nonce: 103,
                expected_cursor: 41,
            }),
            StrictBody::TerminalSyncPage(StrictTerminalSyncPage {
                responder_node: 7,
                expected_requester_boot_epoch: 18,
                transfer_id: 88,
                request_nonce: 103,
                status: 1,
                kind: 1,
                base_cut: Some(base_cut.clone()),
                target_cut: Some(target_cut.clone()),
                cursor: 41,
                next_cursor: 42,
                image_digest: Bytes::from_static(b"image"),
                checkpoint_states: Vec::new(),
                deltas: vec![StrictTerminalDelta {
                    generation: 41,
                    state: Some(terminal_state),
                    previous_chain_digest: base_cut.chain_digest.clone(),
                    chain_digest: target_cut.chain_digest.clone(),
                }],
                has_more: false,
            }),
            StrictBody::TerminalSyncAck(StrictTerminalSyncAck {
                src_node: 3,
                expected_responder_boot_epoch: 24,
                transfer_id: 88,
                request_nonce: 103,
                target_cut: Some(target_cut.clone()),
            }),
        ];

        for body in bodies {
            assert_eq!(roundtrip_strict_body(body.clone()), body);
        }
        assert_eq!(
            StrictCatchupReason::try_from(4).unwrap().as_str_name(),
            "STRICT_CATCHUP_REASON_TERMINAL_FENCE"
        );
        assert_eq!(
            StrictTerminalSyncStatus::try_from(1).unwrap().as_str_name(),
            "STRICT_TERMINAL_SYNC_STATUS_OK"
        );
        assert_eq!(
            StrictTerminalPageKind::try_from(1).unwrap().as_str_name(),
            "STRICT_TERMINAL_PAGE_KIND_DELTA"
        );

        let StrictBody::Decision(decision) =
            roundtrip_strict_body(StrictBody::Decision(StrictDecision {
                resolver_node: 7,
                ballot: 19,
                coord_node: 7,
                op_id_hi: 0xAA,
                op_id_lo: 0xBB,
                outcome: Some(StrictDecisionOutcome::Abort(StrictDecisionAbort {})),
                src_clock: 901,
                resolver_boot_epoch: 24,
                frozen_targets: Vec::new(),
                source_journal_id: target_cut.journal_id.clone(),
                source_terminal_generation: target_cut.generation,
                source_previous_chain_digest: base_cut.chain_digest,
                source_chain_digest: target_cut.chain_digest.clone(),
                source_terminal_set_digest: target_cut.terminal_set_digest.clone(),
            }))
        else {
            panic!("not v3 decision");
        };
        assert_eq!(decision.source_terminal_generation, 41);
        assert_eq!(decision.source_chain_digest, target_cut.chain_digest);
        assert_eq!(
            decision.source_terminal_set_digest,
            target_cut.terminal_set_digest
        );
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
                ack_boot_epoch: 17,
            }),
        );
        let bytes = encode(&msg).unwrap();
        let back = decode(&bytes).unwrap();
        let Some(ReplBody::Strict(StrictMessage {
            body: Some(StrictBody::ProposeAck(a)),
            ..
        })) = back.body
        else {
            panic!()
        };
        assert_eq!(a.ack_node, 3);
        assert_eq!(a.coord_node, 7);
        assert_eq!(a.ack_boot_epoch, 17);
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
            ..
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
                history_probe_only: false,
                terminal_state_cursor: 2,
                terminal_decision_generation: 7,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
                history_transfer: None,
            }),
        );
        let bytes = encode(&req).unwrap();
        let back = decode(&bytes).unwrap();
        let Some(ReplBody::Strict(StrictMessage {
            body: Some(StrictBody::CatchupReq(req)),
            ..
        })) = back.body
        else {
            panic!()
        };
        assert_eq!(req.terminal_state_cursor, 2);
        assert_eq!(req.terminal_decision_generation, 7);

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
                        strict_terminal_ballot: 0,
                        strict_terminal_resolver_node: 0,
                        strict_terminal_resolver_boot_epoch: 0,
                        strict_terminal_frozen_targets: Vec::new(),
                    },
                    CatchupOp {
                        version: 7,
                        op_msgpack: pretend_msgpack(0x02),
                        strict_op_id_hi: 0,
                        strict_op_id_lo: 0,
                        strict_ts_final: 0,
                        strict_terminal_ballot: 0,
                        strict_terminal_resolver_node: 0,
                        strict_terminal_resolver_boot_epoch: 0,
                        strict_terminal_frozen_targets: Vec::new(),
                    },
                ],
                has_more: true,
                next_chunk_token: 1,
                too_old_use_snapshot: false,
                history_version: 7,
                history_freshness: 123,
                runtime_started_at: 456,
                history_node: 2,
                terminal_states: vec![
                    StrictTerminalState {
                        coord_node: 7,
                        op_id_hi: 0xAA,
                        op_id_lo: 0xBB,
                        ballot: 19,
                        outcome: Some(StrictTerminalOutcome::Commit(StrictDecisionCommit {
                            ts_final: 8,
                            op_msgpack: pretend_msgpack(0x03),
                        })),
                        resolver_node: 0,
                        resolver_boot_epoch: 0,
                        frozen_targets: Vec::new(),
                    },
                    StrictTerminalState {
                        coord_node: 9,
                        op_id_hi: 0xCC,
                        op_id_lo: 0xDD,
                        ballot: 20,
                        outcome: Some(StrictTerminalOutcome::Abort(StrictDecisionAbort {})),
                        resolver_node: 0,
                        resolver_boot_epoch: 0,
                        frozen_targets: Vec::new(),
                    },
                ],
                next_terminal_state_cursor: 2,
                terminal_states_has_more: true,
                terminal_sync_only: true,
                request_force_snapshot: true,
                request_history_probe_only: true,
                terminal_decision_generation: 7,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
                snapshot_next_cursor: 0,
                snapshot_total_bytes: 0,
                snapshot_sha256: Bytes::new(),
                snapshot_has_more: false,
                snapshot_transfer_rejected: false,
                history_transfer: None,
            }),
        );
        let bytes = encode(&resp).unwrap();
        let back = decode(&bytes).unwrap();
        let Some(ReplBody::Strict(StrictMessage {
            body: Some(StrictBody::CatchupResp(r)),
            ..
        })) = back.body
        else {
            panic!()
        };
        assert_eq!(r.ops.len(), 2);
        assert!(r.has_more);
        assert_eq!(r.next_chunk_token, 1);
        assert_eq!(r.terminal_states.len(), 2);
        assert_eq!(r.next_terminal_state_cursor, 2);
        assert!(r.terminal_states_has_more);
        assert!(r.terminal_sync_only);
        assert!(r.request_force_snapshot);
        assert!(r.request_history_probe_only);
        assert_eq!(r.terminal_decision_generation, 7);
        assert!(matches!(
            r.terminal_states[0].outcome,
            Some(StrictTerminalOutcome::Commit(_))
        ));
        assert!(matches!(
            r.terminal_states[1].outcome,
            Some(StrictTerminalOutcome::Abort(_))
        ));
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
                    strict_terminal_ballot: 0,
                    strict_terminal_resolver_node: 0,
                    strict_terminal_resolver_boot_epoch: 0,
                    strict_terminal_frozen_targets: Vec::new(),
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
            ..
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
                ack_boot_epoch: 17,
            }),
        );
        let back = decode(&encode(&ack).unwrap()).unwrap();
        let Some(ReplBody::Strict(StrictMessage {
            body: Some(StrictBody::RecoveryAck(a)),
            ..
        })) = back.body
        else {
            panic!()
        };
        assert_eq!(a.ts_local, 41);
        assert_eq!(a.ack_boot_epoch, 17);
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
            ..
        })) = back.body
        else {
            panic!()
        };
        assert_eq!(c.ts_final, 88);
    }

    #[test]
    fn roundtrip_strict_v1_terminal_resolution_messages() {
        let StrictBody::Accept(accept) = roundtrip_strict_body(StrictBody::Accept(StrictAccept {
            coord_node: 7,
            ballot: 11,
            op_id_hi: 0xAA,
            op_id_lo: 0xBB,
            ts_final: 55,
            op_msgpack: pretend_msgpack(0x11),
            src_clock: 60,
        })) else {
            panic!("not strict accept");
        };
        assert_eq!(accept.ballot, 11);
        assert_eq!(accept.ts_final, 55);

        let StrictBody::AcceptAck(accept_ack) =
            roundtrip_strict_body(StrictBody::AcceptAck(StrictAcceptAck {
                ack_node: 3,
                coord_node: 7,
                ballot: 11,
                op_id_hi: 0xAA,
                op_id_lo: 0xBB,
                accepted: true,
                src_clock: 61,
                ack_boot_epoch: 17,
            }))
        else {
            panic!("not strict accept ack");
        };
        assert!(accept_ack.accepted);
        assert_eq!(accept_ack.ack_boot_epoch, 17);

        let StrictBody::ResolutionHint(hint) =
            roundtrip_strict_body(StrictBody::ResolutionHint(StrictResolutionHint {
                reporter_node: 3,
                coord_node: 7,
                op_id_hi: 0xAA,
                op_id_lo: 0xBB,
                ts_local: 54,
                op_msgpack: pretend_msgpack(0x12),
                src_clock: 62,
                reporter_boot_epoch: 18,
                protocol_version: 1,
                frozen_targets: vec![],
            }))
        else {
            panic!("not strict resolution hint");
        };
        assert_eq!(hint.protocol_version, 1);
        assert_eq!(hint.reporter_boot_epoch, 18);

        let StrictBody::ResolutionPrepare(prepare) =
            roundtrip_strict_body(StrictBody::ResolutionPrepare(StrictResolutionPrepare {
                resolver_node: 4,
                ballot: 12,
                coord_node: 7,
                op_id_hi: 0xAA,
                op_id_lo: 0xBB,
                src_clock: 63,
                frozen_targets: vec![],
            }))
        else {
            panic!("not strict resolution prepare");
        };
        assert_eq!(prepare.resolver_node, 4);
        assert_eq!(prepare.ballot, 12);

        let StrictBody::ResolutionAck(ack) =
            roundtrip_strict_body(StrictBody::ResolutionAck(StrictResolutionAck {
                ack_node: 5,
                ballot: 12,
                coord_node: 7,
                op_id_hi: 0xAA,
                op_id_lo: 0xBB,
                promised: true,
                observed: Some(StrictResolutionObserved::Accepted(StrictAcceptedValue {
                    ballot: 11,
                    ts_final: 55,
                    op_msgpack: pretend_msgpack(0x13),
                })),
                src_clock: 64,
                ack_boot_epoch: 19,
            }))
        else {
            panic!("not strict resolution ack");
        };
        let Some(StrictResolutionObserved::Accepted(accepted)) = ack.observed else {
            panic!("not accepted value");
        };
        assert_eq!(accepted.ballot, 11);
        assert_eq!(accepted.ts_final, 55);

        let StrictBody::ResolutionAck(pending_ack) =
            roundtrip_strict_body(StrictBody::ResolutionAck(StrictResolutionAck {
                ack_node: 6,
                ballot: 12,
                coord_node: 7,
                op_id_hi: 0xAA,
                op_id_lo: 0xBB,
                promised: true,
                observed: Some(StrictResolutionObserved::Pending(StrictPendingValue {
                    ts_local: 54,
                    op_msgpack: pretend_msgpack(0x14),
                    protocol_version: 0,
                })),
                src_clock: 65,
                ack_boot_epoch: 20,
            }))
        else {
            panic!("not strict pending resolution ack");
        };
        let Some(StrictResolutionObserved::Pending(pending)) = pending_ack.observed else {
            panic!("not pending value");
        };
        assert_eq!(pending.ts_local, 54);

        let StrictBody::ResolutionAck(terminal_ack) =
            roundtrip_strict_body(StrictBody::ResolutionAck(StrictResolutionAck {
                ack_node: 7,
                ballot: 12,
                coord_node: 7,
                op_id_hi: 0xCC,
                op_id_lo: 0xDD,
                promised: true,
                observed: Some(StrictResolutionObserved::Terminal(StrictTerminalState {
                    coord_node: 7,
                    op_id_hi: 0xCC,
                    op_id_lo: 0xDD,
                    ballot: 11,
                    outcome: Some(StrictTerminalOutcome::Abort(StrictDecisionAbort {})),
                    resolver_node: 0,
                    resolver_boot_epoch: 0,
                    frozen_targets: Vec::new(),
                })),
                src_clock: 66,
                ack_boot_epoch: 21,
            }))
        else {
            panic!("not strict terminal resolution ack");
        };
        let Some(StrictResolutionObserved::Terminal(terminal)) = terminal_ack.observed else {
            panic!("not terminal state");
        };
        assert!(matches!(
            terminal.outcome,
            Some(StrictTerminalOutcome::Abort(_))
        ));

        let StrictBody::Decision(commit) =
            roundtrip_strict_body(StrictBody::Decision(StrictDecision {
                resolver_node: 4,
                ballot: 12,
                coord_node: 7,
                op_id_hi: 0xAA,
                op_id_lo: 0xBB,
                outcome: Some(StrictDecisionOutcome::Commit(StrictDecisionCommit {
                    ts_final: 55,
                    op_msgpack: pretend_msgpack(0x15),
                })),
                src_clock: 67,
                resolver_boot_epoch: 0,
                frozen_targets: vec![],
                source_journal_id: Bytes::new(),
                source_terminal_generation: 0,
                source_previous_chain_digest: Bytes::new(),
                source_chain_digest: Bytes::new(),
                source_terminal_set_digest: Bytes::new(),
            }))
        else {
            panic!("not strict commit decision");
        };
        let Some(StrictDecisionOutcome::Commit(commit_value)) = commit.outcome else {
            panic!("not commit decision");
        };
        assert_eq!(commit_value.ts_final, 55);
        assert_eq!(commit.resolver_boot_epoch, 0);
        assert!(commit.frozen_targets.is_empty());

        let StrictBody::Decision(abort) =
            roundtrip_strict_body(StrictBody::Decision(StrictDecision {
                resolver_node: 4,
                ballot: 13,
                coord_node: 7,
                op_id_hi: 0xCC,
                op_id_lo: 0xDD,
                outcome: Some(StrictDecisionOutcome::Abort(StrictDecisionAbort {})),
                src_clock: 68,
                resolver_boot_epoch: 0,
                frozen_targets: vec![],
                source_journal_id: Bytes::new(),
                source_terminal_generation: 0,
                source_previous_chain_digest: Bytes::new(),
                source_chain_digest: Bytes::new(),
                source_terminal_set_digest: Bytes::new(),
            }))
        else {
            panic!("not strict abort decision");
        };
        assert!(matches!(
            abort.outcome,
            Some(StrictDecisionOutcome::Abort(_))
        ));
        assert_eq!(abort.resolver_boot_epoch, 0);
        assert!(abort.frozen_targets.is_empty());
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
            ..
        })) = back.body
        else {
            panic!()
        };
        assert_eq!(p.op_msgpack.len(), 64 * 1024);
        assert_eq!(p.op_msgpack, blob);
    }
}
