//! Strict-mode catchup: chunked snapshot + log replay over `OverlayData`.
//!
//! Legacy history paging is stateless on the server side: each request carries
//! `since_version` plus a continuation `chunk_token`; the server returns up to
//! [`crate::replications::ReplicationConfig::strict_max_catchup_ops`]
//! ops with `has_more` set when more are available. The client iterates by
//! re-issuing requests with the returned `next_chunk_token` until
//! `has_more = false`. V2 snapshots are deliberately different: a responder
//! pins one immutable image per peer/transfer and the receiver assembles
//! authenticated, in-order byte chunks before installing it. V3 history pages
//! are correlated and retained through their continuation or final ACK so a
//! lost response can be replayed without branching the cursor chain.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use aws_lc_rs::digest::{SHA256, digest};
use bytes::Bytes;
use prost::Message as _;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace, warn};

use super::super::error::ReplicationError;
use super::super::metrics::{
    self, CatchupMode, CatchupPhase, CatchupReason, ReplicationPipelineKind,
    ReplicationPipelineStage, StrictAdmissionEvent, StrictCatchupDuplicateOutcome,
    StrictCatchupSessionEvent, StrictCatchupSessionOutcome, StrictProbeKind, StrictProbeOutcome,
    StrictSnapshotReceiveEvent, StrictSnapshotResponderEvent,
};
use super::super::proto::{
    CatchupOp, StrictBody, StrictCatchupReason, StrictCatchupReq, StrictCatchupResp,
    StrictClockProbeReq, StrictClockProbeResp, StrictHistoryProbeReq, StrictHistoryProbeResp,
    StrictHistoryTransferResp, StrictTerminalDelta, StrictTerminalOutcome, StrictTerminalPageKind,
    StrictTerminalSyncAck, StrictTerminalSyncPage, StrictTerminalSyncReq, StrictTerminalSyncStatus,
};
use super::history_v3::HistoryServerRequest;
#[cfg(test)]
use super::runtime::STRICT_PROTOCOL_VERSION_V2;
use super::runtime::{
    BulkPageIdentity, HISTORY_ELECTION_SNAPSHOT_TOKEN, HistoryProbeResponseOutcome, HistoryRank,
    HistorySnapshotResponseOutcome, STRICT_PROTOCOL_VERSION_V5, SnapshotFormat,
    SnapshotReceiveTransfer, SnapshotTransfer, StrictRuntime, TerminalCommitProof,
    TerminalDecisionIdentity, is_v3_history_final_ack_confirmation, node_from_u32,
    replication_bulk_backpressure, terminal_identity_from_wire, validate_v3_metadata_control,
};
use super::session_reducer::{
    Cursor as SessionCursor, CursorKind as SessionCursorKind, Effect as SessionEffect,
    Event as SessionEvent, InboundArbitration as SessionInboundArbitration,
    PeerEpoch as SessionPeerEpoch, Status as SessionStatus, SyncKind as SessionSyncKind,
    TransferId as SessionTransferId, Trigger as SessionTrigger,
    TriggerOrigin as SessionTriggerOrigin, WireIdentity as SessionWireIdentity,
    WireNonce as SessionWireNonce,
};
use super::sync_v3::{
    InboundTerminalSyncDisposition, PeerIncarnation, ResponderSession, cut_from_wire,
    cut_to_reducer, cut_to_wire, source_cut_covers,
};
use super::terminal_journal::{
    CommitCandidate, StagedTerminalDecision, TerminalCut,
    TerminalDecision as JournalTerminalDecision, TerminalJournal,
};
use super::{HistoryMetadata, LogSlice, StrictLogMetadata, StrictReplicable, StrictSnapshotError};
use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::ServiceLevel;

/// Opt out of terminal-fence transfer for steady-state probes. Startup and
/// membership-heal catchup begin at zero and paginate the stable journal.
pub(crate) const TERMINAL_STATE_CURSOR_SKIP: u64 = u64::MAX;

const S2S_SNAPSHOT_ENVELOPE_VERSION: u32 = 1;
// Transfer ids are opaque echo tokens on every deployed protocol version, so
// their high bits can pin the immutable byte representation without adding a
// protobuf field or forcing a rolling-upgrade protocol bump. Untagged ids are
// accepted only for compatibility with older responders.
const SNAPSHOT_TRANSFER_FORMAT_TAG: u64 = 1 << 63;
const SNAPSHOT_TRANSFER_ENVELOPE_TAG: u64 = 1 << 62;
const SNAPSHOT_TRANSFER_COUNTER_MASK: u64 = SNAPSHOT_TRANSFER_ENVELOPE_TAG - 1;
const SNAPSHOT_TRANSFER_SEQUENCE_BITS: u32 = 24;
const SNAPSHOT_TRANSFER_SEQUENCE_MASK: u64 = (1 << SNAPSHOT_TRANSFER_SEQUENCE_BITS) - 1;
const SNAPSHOT_TRANSFER_BOOT_MASK: u64 =
    SNAPSHOT_TRANSFER_COUNTER_MASK >> SNAPSHOT_TRANSFER_SEQUENCE_BITS;

#[cfg(test)]
#[path = "catchup_snapshot_tests.rs"]
mod checkpoint_snapshot_tests;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct S2sSnapshotEnvelope {
    version: u32,
    repository_snapshot: Vec<u8>,
    applied_operations: Vec<S2sAppliedOperation>,
    retired_operations: Vec<S2sRetiredOperation>,
}

#[derive(Debug, Serialize, Deserialize)]
struct S2sAppliedOperation {
    op_id_hi: u64,
    op_id_lo: u64,
    repository_version: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct S2sRetiredOperation {
    op_id_hi: u64,
    max_counter: u64,
}

pub(super) fn encode_s2s_snapshot_envelope<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    snapshot_version: u64,
    repository_snapshot: Bytes,
) -> Result<Bytes, rmp_serde::encode::Error> {
    let state = rt.state.lock();
    let applied_operations = state
        .applied_operations
        .iter()
        .filter_map(|(op_id, version)| {
            (*version <= snapshot_version).then_some(S2sAppliedOperation {
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                repository_version: *version,
            })
        })
        .collect();
    let retired_operations = state
        .retired_operations
        .iter()
        .map(|(op_id_hi, max_counter)| S2sRetiredOperation {
            op_id_hi: *op_id_hi,
            max_counter: *max_counter,
        })
        .collect();
    rmp_serde::to_vec_named(&S2sSnapshotEnvelope {
        version: S2S_SNAPSHOT_ENVELOPE_VERSION,
        repository_snapshot: repository_snapshot.to_vec(),
        applied_operations,
        retired_operations,
    })
    .map(Bytes::from)
}

fn decode_s2s_snapshot_envelope(
    bytes: Bytes,
) -> Result<(Bytes, HashMap<(u64, u64), u64>, BTreeMap<u64, u64>), rmp_serde::decode::Error> {
    let envelope: S2sSnapshotEnvelope = rmp_serde::from_slice(&bytes)?;
    if envelope.version != S2S_SNAPSHOT_ENVELOPE_VERSION {
        return Err(rmp_serde::decode::Error::Syntax(
            "unsupported S2S snapshot envelope version".into(),
        ));
    }
    let applied = envelope
        .applied_operations
        .into_iter()
        .map(|operation| {
            (
                (operation.op_id_hi, operation.op_id_lo),
                operation.repository_version,
            )
        })
        .collect();
    let retired = envelope
        .retired_operations
        .into_iter()
        .map(|origin| (origin.op_id_hi, origin.max_counter))
        .collect();
    Ok((Bytes::from(envelope.repository_snapshot), applied, retired))
}

fn legacy_untagged_snapshot_is_ambiguous(bytes: &[u8]) -> bool {
    matches!(
        rmp_serde::from_slice::<S2sSnapshotEnvelope>(bytes),
        Ok(envelope) if envelope.version == S2S_SNAPSHOT_ENVELOPE_VERSION
    )
}

fn history_transfer_response<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    req: &StrictCatchupReq,
) -> Option<StrictHistoryTransferResp> {
    let transfer = req.history_transfer.as_ref()?;
    let requester = node_from_u32(req.src_node)?;
    Some(StrictHistoryTransferResp {
        expected_requester_boot_epoch: rt.net.member_boot_epoch(requester)?,
        transfer_id: transfer.transfer_id,
        request_nonce: transfer.request_nonce,
        cursor: transfer.expected_cursor,
        target_version: transfer.target_version,
    })
}

fn history_final_ack_confirmation<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    req: &StrictCatchupReq,
) -> Option<StrictCatchupResp> {
    req.history_transfer
        .as_ref()
        .is_some_and(|transfer| transfer.final_ack)
        .then(|| StrictCatchupResp {
            history_transfer: history_transfer_response(rt, req),
            ..Default::default()
        })
}

fn v3_history_reason(req: &StrictCatchupReq) -> Option<CatchupReason> {
    CatchupReason::from_v3_wire(req.history_transfer.as_ref()?.reason)
}

fn is_snapshot_completion_request(req: &StrictCatchupReq) -> bool {
    req.snapshot_transfer_id != 0
        && req.snapshot_chunk_cursor == 0
        && !req.force_snapshot
        && !req.history_probe_only
}

fn v3_history_request_phase(req: &StrictCatchupReq) -> CatchupPhase {
    if req
        .history_transfer
        .as_ref()
        .is_some_and(|transfer| transfer.final_ack)
    {
        CatchupPhase::FinalAck
    } else if req.force_snapshot
        || (req.snapshot_transfer_id != 0 && !is_snapshot_completion_request(req))
    {
        CatchupPhase::Snapshot
    } else {
        CatchupPhase::LogDelta
    }
}

fn v3_history_response_phase(response: &StrictCatchupResp) -> CatchupPhase {
    if response.too_old_use_snapshot
        || response.snapshot_transfer_id != 0
        || !response.snapshot_msgpack.is_empty()
    {
        CatchupPhase::Snapshot
    } else {
        CatchupPhase::LogDelta
    }
}

async fn send_v3_history_request<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    dst: NodeIdentifier,
    req: StrictCatchupReq,
) -> Result<(), ReplicationError> {
    let reason = v3_history_reason(&req).ok_or(ReplicationError::Malformed(
        "v3 history request lacks a bounded reason",
    ))?;
    let transfer = req
        .history_transfer
        .as_ref()
        .ok_or(ReplicationError::Malformed(
            "v3 history request lacks transfer correlation",
        ))?;
    let phase = if transfer.final_ack {
        CatchupPhase::FinalAck
    } else {
        v3_history_request_phase(&req)
    };
    let epoch = rt
        .net
        .member_boot_epoch(dst)
        .ok_or(ReplicationError::Malformed(
            "v3 history request destination has no active incarnation",
        ))?;
    let peer = PeerIncarnation::new(dst, epoch);
    if transfer.final_ack {
        rt.v3_retries.lock().register_history_final_ack(
            peer,
            req.clone(),
            rt.cfg.bulk_retry_delay(),
            rt.cfg.pending_propose_ttl(),
            rt.cfg.strict_bulk_retry_jitter_pct(),
            v3_retry_salt(rt.self_id, &rt.topic),
        );
    } else {
        rt.v3_retries.lock().register_history_request(
            peer,
            req.clone(),
            rt.cfg.bulk_retry_delay(),
            rt.cfg.pending_propose_ttl(),
            rt.cfg.strict_bulk_retry_jitter_pct(),
            v3_retry_salt(rt.self_id, &rt.topic),
        );
    }
    metrics::record_catchup_request_detail(CatchupMode::Strict, reason, phase);
    rt.net
        .send_redundant_catchup_unicast(dst, &rt.topic, StrictBody::CatchupReq(req), reason, phase)
        .await
}

async fn send_v3_history_response<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    dst: NodeIdentifier,
    req: &StrictCatchupReq,
    response: StrictCatchupResp,
) -> Result<bool, ReplicationError> {
    let reason = v3_history_reason(req).ok_or(ReplicationError::Malformed(
        "v3 history response lacks a bounded reason",
    ))?;
    let phase = v3_history_response_phase(&response);
    let records = response.ops.len();
    let encoded_len = encoded_response_len(rt, &response)?;
    if encoded_len > rt.strict_catchup_response_budget() {
        return Err(ReplicationError::Malformed(
            "v3 history response exceeds configured encoded response budget",
        ));
    }
    if let (Some(epoch), Some(transfer)) =
        (rt.net.member_boot_epoch(dst), req.history_transfer.as_ref())
    {
        if !rt.v3_history.lock().cache_server_response(
            PeerIncarnation::new(dst, epoch),
            transfer,
            response.clone(),
        ) {
            return Ok(false);
        }
    }
    metrics::record_catchup_response_detail(
        CatchupMode::Strict,
        reason,
        phase,
        records,
        encoded_len,
    );
    rt.net
        .send_bulk_catchup_unicast(
            dst,
            &rt.topic,
            StrictBody::CatchupResp(response),
            rt.cfg.bulk_retry_delay(),
            reason,
            phase,
        )
        .await
        .map(|()| true)
}

fn encoded_response_len<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    response: &StrictCatchupResp,
) -> Result<usize, ReplicationError> {
    rt.strict_replication_payload_len(&StrictBody::CatchupResp(response.clone()))
}

fn v2_encoded_response_len<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    response: &StrictCatchupResp,
) -> Result<usize, ReplicationError> {
    rt.v2_strict_replication_payload_len(&StrictBody::CatchupResp(response.clone()))
}

fn response_fits_budget<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    response: &StrictCatchupResp,
    v2_origin_proof: bool,
) -> bool {
    let encoded_len = match if v2_origin_proof {
        v2_encoded_response_len(rt, response)
    } else {
        encoded_response_len(rt, response)
    } {
        Ok(encoded_len) => encoded_len,
        Err(error) => {
            warn!(
                from,
                error = %error,
                "strict catchup response authentication framing failed"
            );
            return false;
        }
    };
    let max_bytes = rt.strict_catchup_response_budget();
    if encoded_len <= max_bytes {
        return true;
    }
    warn!(
        from,
        encoded_len,
        max_bytes,
        "strict catchup response exceeds the configured encoded response budget"
    );
    false
}

fn history_response_encoded_len<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    snapshot_version: u64,
    snapshot_msgpack: Bytes,
    too_old_use_snapshot: bool,
    ops: Vec<CatchupOp>,
    v2_origin_proof: bool,
) -> Result<usize, ReplicationError> {
    let response = StrictCatchupResp {
        snapshot_version,
        snapshot_msgpack,
        ops,
        // Use the largest encoded scalar fields and every boolean tag so this
        // remains a safe upper bound for the eventual response built below.
        has_more: true,
        next_chunk_token: u64::MAX,
        too_old_use_snapshot,
        history_version: u64::MAX,
        history_freshness: i64::MAX,
        runtime_started_at: u64::MAX,
        history_node: u32::MAX,
        terminal_states: Vec::new(),
        next_terminal_state_cursor: TERMINAL_STATE_CURSOR_SKIP,
        terminal_states_has_more: false,
        terminal_sync_only: false,
        request_force_snapshot: true,
        request_history_probe_only: true,
        terminal_decision_generation: u64::MAX,
        snapshot_transfer_id: 0,
        snapshot_chunk_cursor: 0,
        snapshot_next_cursor: 0,
        snapshot_total_bytes: 0,
        snapshot_sha256: Bytes::new(),
        snapshot_has_more: false,
        snapshot_transfer_rejected: false,
        history_transfer: Some(StrictHistoryTransferResp {
            expected_requester_boot_epoch: u64::MAX,
            transfer_id: u64::MAX,
            request_nonce: u64::MAX,
            cursor: u64::MAX,
            target_version: u64::MAX,
        }),
    };
    if v2_origin_proof {
        v2_encoded_response_len(rt, &response)
    } else {
        encoded_response_len(rt, &response)
    }
}

async fn send_response<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    response: StrictCatchupResp,
) {
    if !response_fits_budget(rt, from, &response, false) {
        return;
    }
    // Admission probes may first carry terminal-fence pages before their
    // final metadata response. Keep every page of that control exchange on
    // the redundant path; losing the terminal page prevents an excluded
    // participant from ever reaching the metadata cut it must prove.
    let history_probe = response.request_history_probe_only;
    let result = if history_probe {
        rt.net
            .send_redundant_unicast(from, &rt.topic, StrictBody::CatchupResp(response))
            .await
    } else {
        rt.net
            .send_bulk_unicast(
                from,
                &rt.topic,
                StrictBody::CatchupResp(response),
                rt.cfg.bulk_retry_delay(),
            )
            .await
    };
    if let Err(error) = result {
        warn!(from, error = %error, "strict catchup response send failed");
    }
}

async fn send_v2_response<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    response: StrictCatchupResp,
) -> SnapshotResponseSendOutcome {
    if !response_fits_budget(rt, from, &response, true) {
        return SnapshotResponseSendOutcome::Suppressed;
    }
    // See send_response: terminal pagination is part of the authenticated
    // admission probe and needs the same redundant delivery semantics as its
    // final metadata page.
    let history_probe = response.request_history_probe_only;
    let result = if history_probe {
        rt.net
            .send_redundant_unicast(from, &rt.topic, StrictBody::CatchupResp(response))
            .await
    } else {
        rt.net
            .send_bulk_unicast(
                from,
                &rt.topic,
                StrictBody::CatchupResp(response),
                rt.cfg.bulk_retry_delay(),
            )
            .await
    };
    if let Err(error) = result {
        warn!(from, error = %error, "strict v2 catchup response send failed");
        SnapshotResponseSendOutcome::Failed
    } else {
        SnapshotResponseSendOutcome::Sent
    }
}

fn v2_snapshot_transfer_supported<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    peer: NodeIdentifier,
) -> bool {
    rt.can_respond_to_v2_terminal_catchup(peer)
}

fn snapshot_sha256(snapshot_msgpack: &[u8]) -> Bytes {
    Bytes::copy_from_slice(digest(&SHA256, snapshot_msgpack).as_ref())
}

/// Snapshot image retention is capped across both directions of a strict
/// topic runtime. Always acquire the responder map before the receiver map
/// when operating on both maps.
fn expire_stale_snapshot_images(
    transfers: &mut HashMap<NodeIdentifier, SnapshotTransfer>,
    receivers: &mut HashMap<NodeIdentifier, SnapshotReceiveTransfer>,
    now: Instant,
    ttl: Duration,
    protected_receiver: Option<NodeIdentifier>,
) {
    transfers.retain(|_, transfer| now.duration_since(transfer.last_used_at) < ttl);
    receivers.retain(|peer, transfer| {
        Some(*peer) == protected_receiver || now.duration_since(transfer.last_used_at) < ttl
    });
}

fn retained_snapshot_bytes(
    transfers: &HashMap<NodeIdentifier, SnapshotTransfer>,
    receivers: &HashMap<NodeIdentifier, SnapshotReceiveTransfer>,
) -> Option<usize> {
    transfers
        .values()
        .map(|transfer| transfer.snapshot_msgpack.len())
        .chain(
            receivers
                .values()
                .map(|transfer| transfer.snapshot_msgpack.len()),
        )
        .try_fold(0usize, |total, bytes| total.checked_add(bytes))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotTransferCursor {
    Initial,
    Continuation(usize),
    StaleTransfer,
    InvalidCursor,
}

fn snapshot_transfer_cursor(
    transfer: &SnapshotTransfer,
    req: &StrictCatchupReq,
) -> SnapshotTransferCursor {
    if req.snapshot_transfer_id == 0 && req.snapshot_chunk_cursor == 0 {
        SnapshotTransferCursor::Initial
    } else if req.snapshot_transfer_id == transfer.id {
        usize::try_from(req.snapshot_chunk_cursor)
            .ok()
            .filter(|cursor| *cursor <= transfer.snapshot_msgpack.len())
            .map(SnapshotTransferCursor::Continuation)
            .unwrap_or(SnapshotTransferCursor::InvalidCursor)
    } else {
        SnapshotTransferCursor::StaleTransfer
    }
}

enum PinnedSnapshotTransferOutcome {
    Serve {
        transfer: SnapshotTransfer,
        cursor: usize,
        event: StrictSnapshotResponderEvent,
    },
    Ignore {
        event: StrictSnapshotResponderEvent,
        active_transfer_id: u64,
        active_version: u64,
        active_total_bytes: usize,
    },
    MissingTransfer,
    Reject,
}

/// A repository can report that a snapshot failure made durable strict
/// replication impossible without immediately lowering its advertised
/// version. Honor that explicit contract, while polling the version as a
/// defense for repositories that self-report capability loss instead.
fn snapshot_error_withdraws_repository_capability<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    error: &StrictSnapshotError,
) -> bool {
    let repository_v2_capable = rt.repository_v2_capable();
    if error.is_durability_failure() && repository_v2_capable {
        rt.net
            .report_strict_replication_repository_capability_loss();
        true
    } else {
        !repository_v2_capable
    }
}

fn tagged_snapshot_transfer_id(counter: u64, format: SnapshotFormat) -> u64 {
    SNAPSHOT_TRANSFER_FORMAT_TAG
        | match format {
            SnapshotFormat::Repository => 0,
            SnapshotFormat::S2sEnvelope => SNAPSHOT_TRANSFER_ENVELOPE_TAG,
        }
        | (counter & SNAPSHOT_TRANSFER_COUNTER_MASK)
}

fn snapshot_format_from_transfer_id(id: u64) -> Option<SnapshotFormat> {
    (id & SNAPSHOT_TRANSFER_FORMAT_TAG != 0).then(|| {
        if id & SNAPSHOT_TRANSFER_ENVELOPE_TAG != 0 {
            SnapshotFormat::S2sEnvelope
        } else {
            SnapshotFormat::Repository
        }
    })
}

fn snapshot_format_for_peer<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    peer: NodeIdentifier,
) -> SnapshotFormat {
    if rt.net.peer_strict_replication_protocol_version(peer) >= STRICT_PROTOCOL_VERSION_V5 {
        SnapshotFormat::S2sEnvelope
    } else {
        SnapshotFormat::Repository
    }
}

fn next_snapshot_transfer_id<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    format: SnapshotFormat,
) -> u64 {
    loop {
        let sequence = rt.snapshot_transfer_counter.fetch_add(1, Ordering::Relaxed)
            & SNAPSHOT_TRANSFER_SEQUENCE_MASK;
        if sequence != 0 {
            // Partition the 62 payload bits so sequential boot epochs have
            // disjoint transfer spaces. A runtime can originate over sixteen
            // million snapshot images for one topic before sequence reuse.
            let boot = rt.boot_epoch & SNAPSHOT_TRANSFER_BOOT_MASK;
            let identity = (boot << SNAPSHOT_TRANSFER_SEQUENCE_BITS) | sequence;
            return tagged_snapshot_transfer_id(identity, format);
        }
    }
}

/// Select the stable responder-side image for this request. An explicit
/// initial request can replay byte zero, while a matching continuation serves
/// its requested cursor. Stale ids and invalid cursors must not restart or
/// refresh a different pinned image.
fn pinned_snapshot_transfer<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    req: &StrictCatchupReq,
    terminal_decision_generation: u64,
) -> PinnedSnapshotTransferOutcome {
    let now = Instant::now();
    let protected_receiver = rt
        .state
        .lock()
        .history_election_fetching_snapshot()
        .map(|request| request.peer());
    // Keep the transfer lock held through repository capture and envelope
    // construction. Checkpoint rotation uses the same lock as its barrier,
    // preventing a newer retired floor from being paired with older snapshot
    // bytes.
    let mut transfers = rt.snapshot_transfers.lock();
    let mut receivers = rt.snapshot_receivers.lock();
    expire_stale_snapshot_images(
        &mut transfers,
        &mut receivers,
        now,
        rt.cfg.pending_propose_ttl(),
        protected_receiver,
    );
    if let Some(transfer) = transfers.get_mut(&from) {
        return match snapshot_transfer_cursor(transfer, req) {
            SnapshotTransferCursor::Initial => {
                transfer.last_used_at = now;
                PinnedSnapshotTransferOutcome::Serve {
                    transfer: transfer.clone(),
                    cursor: 0,
                    event: StrictSnapshotResponderEvent::InitialPagePrepared,
                }
            }
            SnapshotTransferCursor::Continuation(cursor) => {
                transfer.last_used_at = now;
                PinnedSnapshotTransferOutcome::Serve {
                    transfer: transfer.clone(),
                    cursor,
                    event: StrictSnapshotResponderEvent::ContinuationPrepared,
                }
            }
            SnapshotTransferCursor::StaleTransfer => PinnedSnapshotTransferOutcome::Ignore {
                event: StrictSnapshotResponderEvent::StaleTransferIgnored,
                active_transfer_id: transfer.id,
                active_version: transfer.version,
                active_total_bytes: transfer.snapshot_msgpack.len(),
            },
            SnapshotTransferCursor::InvalidCursor => PinnedSnapshotTransferOutcome::Ignore {
                event: StrictSnapshotResponderEvent::InvalidCursorIgnored,
                active_transfer_id: transfer.id,
                active_version: transfer.version,
                active_total_bytes: transfer.snapshot_msgpack.len(),
            },
        };
    }
    if req.snapshot_transfer_id != 0 || req.snapshot_chunk_cursor != 0 {
        return PinnedSnapshotTransferOutcome::MissingTransfer;
    }

    let Some(_snapshot_capture) = rt.begin_snapshot_capture() else {
        trace!(
            from,
            "strict snapshot capture deferred by checkpoint barrier"
        );
        return PinnedSnapshotTransferOutcome::Reject;
    };

    let (snapshot_metadata, mut snapshot_msgpack) = match rt.repo.snapshot_with_metadata() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let capability_withdrawn = snapshot_error_withdraws_repository_capability(rt, &error);
            warn!(
                from,
                error = %error,
                durability_failure = error.is_durability_failure(),
                capability_withdrawn,
                "strict v2 snapshot capture failed; declining transfer"
            );
            return PinnedSnapshotTransferOutcome::Reject;
        }
    };
    let version = snapshot_metadata.version;
    let format = snapshot_format_for_peer(rt, from);
    if format == SnapshotFormat::S2sEnvelope {
        snapshot_msgpack = match encode_s2s_snapshot_envelope(rt, version, snapshot_msgpack) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                warn!(from, %error, "strict S2S snapshot envelope encoding failed");
                return PinnedSnapshotTransferOutcome::Reject;
            }
        };
    }
    if snapshot_msgpack.len() > rt.cfg.strict_max_snapshot_transfer_bytes() {
        warn!(
            from,
            snapshot_bytes = snapshot_msgpack.len(),
            max_snapshot_bytes = rt.cfg.strict_max_snapshot_transfer_bytes(),
            "strict v2 snapshot exceeds the aggregate retained-image resource limit"
        );
        return PinnedSnapshotTransferOutcome::Reject;
    }
    let mut rank = HistoryRank::local(rt);
    rank.version = version;
    rank.freshness = snapshot_metadata.freshness;
    let transfer = SnapshotTransfer {
        id: next_snapshot_transfer_id(rt, format),
        format,
        version,
        snapshot_sha256: snapshot_sha256(&snapshot_msgpack),
        snapshot_msgpack,
        rank,
        terminal_decision_generation,
        last_used_at: now,
    };
    let Some(retained_bytes) = retained_snapshot_bytes(&transfers, &receivers) else {
        warn!(
            from,
            "strict v2 snapshot retained-byte accounting overflowed"
        );
        return PinnedSnapshotTransferOutcome::Reject;
    };
    let Some(required_bytes) = retained_bytes.checked_add(transfer.snapshot_msgpack.len()) else {
        warn!(
            from,
            "strict v2 snapshot retained-byte accounting overflowed"
        );
        return PinnedSnapshotTransferOutcome::Reject;
    };
    if required_bytes > rt.cfg.strict_max_snapshot_transfer_bytes() {
        warn!(
            from,
            retained_bytes,
            snapshot_bytes = transfer.snapshot_msgpack.len(),
            max_snapshot_bytes = rt.cfg.strict_max_snapshot_transfer_bytes(),
            "strict v2 snapshot would exceed the aggregate retained-image resource limit"
        );
        return PinnedSnapshotTransferOutcome::Reject;
    }
    transfers.insert(from, transfer.clone());
    PinnedSnapshotTransferOutcome::Serve {
        transfer,
        cursor: 0,
        event: StrictSnapshotResponderEvent::ImagePagePrepared,
    }
}

fn snapshot_chunk_response<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    transfer: &SnapshotTransfer,
    req: &StrictCatchupReq,
    cursor: usize,
) -> Option<StrictCatchupResp> {
    if snapshot_format_from_transfer_id(transfer.id) != Some(transfer.format) {
        return None;
    }
    let total = transfer.snapshot_msgpack.len();
    if cursor > total {
        return None;
    }
    let total_bytes = u64::try_from(total).ok()?;
    let build = |next: usize| {
        let next_cursor = u64::try_from(next).ok()?;
        Some(StrictCatchupResp {
            snapshot_version: transfer.version,
            snapshot_msgpack: transfer.snapshot_msgpack.slice(cursor..next),
            ops: Vec::new(),
            has_more: false,
            next_chunk_token: transfer.version,
            too_old_use_snapshot: true,
            history_version: transfer.rank.version,
            history_freshness: transfer.rank.freshness,
            runtime_started_at: transfer.rank.runtime_started_at,
            history_node: u32::from(transfer.rank.node_id),
            terminal_states: Vec::new(),
            next_terminal_state_cursor: TERMINAL_STATE_CURSOR_SKIP,
            terminal_states_has_more: false,
            terminal_sync_only: false,
            request_force_snapshot: req.force_snapshot,
            request_history_probe_only: false,
            terminal_decision_generation: transfer.terminal_decision_generation,
            snapshot_transfer_id: transfer.id,
            snapshot_chunk_cursor: u64::try_from(cursor).ok()?,
            snapshot_next_cursor: next_cursor,
            snapshot_total_bytes: total_bytes,
            snapshot_sha256: transfer.snapshot_sha256.clone(),
            snapshot_has_more: next < total,
            snapshot_transfer_rejected: false,
            history_transfer: history_transfer_response(rt, req),
        })
    };

    let mut low = 0usize;
    let mut high = total.saturating_sub(cursor);
    while low < high {
        let candidate = low + (high - low).div_ceil(2);
        let Some(response) = build(cursor + candidate) else {
            return None;
        };
        if v2_encoded_response_len(rt, &response)
            .is_ok_and(|encoded_len| encoded_len <= rt.strict_catchup_response_budget())
        {
            low = candidate;
        } else {
            high = candidate - 1;
        }
    }
    if total > cursor && low == 0 {
        return None;
    }
    build(cursor + low)
}

#[derive(Clone, Copy)]
enum SnapshotResponseSendOutcome {
    Sent,
    Suppressed,
    Failed,
}

fn record_snapshot_response_send_outcome(outcome: SnapshotResponseSendOutcome) {
    let event = match outcome {
        SnapshotResponseSendOutcome::Sent => return,
        SnapshotResponseSendOutcome::Suppressed => StrictSnapshotResponderEvent::ResponseSuppressed,
        SnapshotResponseSendOutcome::Failed => StrictSnapshotResponderEvent::ResponseSendFailed,
    };
    metrics::record_strict_snapshot_responder_event(event);
}

async fn send_snapshot_transfer_rejected<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    req: &StrictCatchupReq,
    terminal_decision_generation: u64,
) {
    let rank = HistoryRank::local(rt);
    let response = StrictCatchupResp {
        snapshot_version: rank.version,
        snapshot_msgpack: Bytes::new(),
        ops: Vec::new(),
        has_more: false,
        next_chunk_token: req.chunk_token.max(req.since_version),
        too_old_use_snapshot: true,
        history_version: rank.version,
        history_freshness: rank.freshness,
        runtime_started_at: rank.runtime_started_at,
        history_node: u32::from(rank.node_id),
        terminal_states: Vec::new(),
        next_terminal_state_cursor: TERMINAL_STATE_CURSOR_SKIP,
        terminal_states_has_more: false,
        terminal_sync_only: false,
        request_force_snapshot: req.force_snapshot,
        request_history_probe_only: false,
        terminal_decision_generation,
        snapshot_transfer_id: req.snapshot_transfer_id,
        snapshot_chunk_cursor: req.snapshot_chunk_cursor,
        snapshot_next_cursor: 0,
        snapshot_total_bytes: 0,
        snapshot_sha256: Bytes::new(),
        snapshot_has_more: false,
        snapshot_transfer_rejected: true,
        history_transfer: history_transfer_response(rt, req),
    };
    let outcome = if req.history_transfer.is_some() {
        match send_v3_history_response(rt, from, req, response).await {
            Ok(true) => SnapshotResponseSendOutcome::Sent,
            Ok(false) => SnapshotResponseSendOutcome::Suppressed,
            Err(error) => {
                warn!(from, %error, "strict v3 snapshot rejection send failed");
                SnapshotResponseSendOutcome::Failed
            }
        }
    } else {
        send_v2_response(rt, from, response).await
    };
    record_snapshot_response_send_outcome(outcome);
}

async fn respond_with_snapshot_transfer<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    req: &StrictCatchupReq,
    terminal_decision_generation: u64,
    build_started_at: Instant,
) {
    let (transfer, cursor, responder_event) =
        match pinned_snapshot_transfer(rt, from, req, terminal_decision_generation) {
            PinnedSnapshotTransferOutcome::Serve {
                transfer,
                cursor,
                event,
            } => (transfer, cursor, event),
            PinnedSnapshotTransferOutcome::Ignore {
                mut event,
                active_transfer_id,
                active_version,
                active_total_bytes,
            } => {
                if req.history_transfer.is_some() {
                    event = match event {
                        StrictSnapshotResponderEvent::StaleTransferIgnored => {
                            StrictSnapshotResponderEvent::StaleTransferRejected
                        }
                        StrictSnapshotResponderEvent::InvalidCursorIgnored => {
                            StrictSnapshotResponderEvent::InvalidCursorRejected
                        }
                        event => event,
                    };
                }
                metrics::record_strict_snapshot_responder_event(event);
                warn!(
                        topic = %rt.topic,
                        from,
                        reason = ?event,
                        requested_transfer_id = req.snapshot_transfer_id,
                        requested_cursor = req.snapshot_chunk_cursor,
                        active_transfer_id,
                        active_version,
                    active_total_bytes,
                    "ignoring stale strict v2 snapshot continuation"
                );
                if req.history_transfer.is_some() {
                    send_snapshot_transfer_rejected(rt, from, req, terminal_decision_generation)
                        .await;
                }
                return;
            }
            PinnedSnapshotTransferOutcome::MissingTransfer => {
                metrics::record_strict_snapshot_responder_event(
                    StrictSnapshotResponderEvent::MissingTransferRejected,
                );
                warn!(
                    topic = %rt.topic,
                    from,
                    requested_transfer_id = req.snapshot_transfer_id,
                    requested_cursor = req.snapshot_chunk_cursor,
                    "rejecting strict v2 snapshot continuation without a pinned image"
                );
                send_snapshot_transfer_rejected(rt, from, req, terminal_decision_generation).await;
                return;
            }
            PinnedSnapshotTransferOutcome::Reject => {
                metrics::record_strict_snapshot_responder_event(
                    StrictSnapshotResponderEvent::TransferRejected,
                );
                send_snapshot_transfer_rejected(rt, from, req, terminal_decision_generation).await;
                return;
            }
        };
    if req
        .history_transfer
        .as_ref()
        .is_some_and(|correlation| correlation.target_version != transfer.version)
    {
        rt.snapshot_transfers.lock().remove(&from);
        metrics::record_strict_snapshot_responder_event(
            StrictSnapshotResponderEvent::TransferRejected,
        );
        send_snapshot_transfer_rejected(rt, from, req, terminal_decision_generation).await;
        return;
    }
    // If a terminal decision landed after the image capture, the peer must
    // re-page the new fence cut before it receives any image that could
    // include the decision's repository delivery.
    if transfer.terminal_decision_generation != rt.terminal_decision_generation().await {
        rt.snapshot_transfers.lock().remove(&from);
        metrics::record_strict_snapshot_responder_event(
            StrictSnapshotResponderEvent::FenceInvalidated,
        );
        warn!(
            from,
            "strict v2 snapshot transfer invalidated by a newer terminal fence"
        );
        send_snapshot_transfer_rejected(rt, from, req, terminal_decision_generation).await;
        return;
    }
    let Some(response) = snapshot_chunk_response(rt, &transfer, req, cursor) else {
        metrics::record_strict_snapshot_responder_event(
            StrictSnapshotResponderEvent::TransferRejected,
        );
        warn!(
            from,
            max_bytes = rt.strict_catchup_response_budget(),
            "strict v2 snapshot transfer cannot fit one byte in the response budget"
        );
        send_snapshot_transfer_rejected(rt, from, req, terminal_decision_generation).await;
        return;
    };
    let response_bytes = response.snapshot_msgpack.len();
    metrics::record_strict_snapshot_responder_event(responder_event);
    metrics::record_pipeline_stage(
        ReplicationPipelineKind::Strict,
        ReplicationPipelineStage::CatchupBuild,
        build_started_at.elapsed(),
    );
    let outcome = if req.history_transfer.is_some() {
        match send_v3_history_response(rt, from, req, response).await {
            Ok(true) => SnapshotResponseSendOutcome::Sent,
            Ok(false) => SnapshotResponseSendOutcome::Suppressed,
            Err(error) => {
                warn!(from, %error, "strict v3 snapshot page send failed");
                SnapshotResponseSendOutcome::Failed
            }
        }
    } else {
        metrics::record_catchup_response(CatchupMode::Strict, 0, response_bytes);
        send_v2_response(rt, from, response).await
    };
    record_snapshot_response_send_outcome(outcome);
}

/// Build and send a `StrictCatchupResp` answering `req`.
pub(crate) async fn respond_to_request<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    req: StrictCatchupReq,
) {
    let mut history_replay = None;
    let mut history_server_peer = None;
    let correlated_v3_history = match req.history_transfer.as_ref() {
        Some(transfer) => {
            let valid_reason = StrictCatchupReason::try_from(transfer.reason)
                .ok()
                .is_some_and(|reason| {
                    !matches!(
                        reason,
                        StrictCatchupReason::TerminalFence
                            | StrictCatchupReason::DeliveryWatermark
                            | StrictCatchupReason::Unspecified
                    )
                });
            if !rt.v3_repair_supported_by(from)
                || transfer.expected_responder_boot_epoch != rt.boot_epoch
                || transfer.transfer_id == 0
                || transfer.request_nonce == 0
                || transfer.acknowledged_request_nonce == transfer.request_nonce
                || transfer.target_version < req.since_version
                || transfer.target_version > rt.repo.current_version()
                || !valid_reason
            {
                return;
            }
            let Some(epoch) = rt.net.member_boot_epoch(from) else {
                return;
            };
            let peer = PeerIncarnation::new(from, epoch);
            if transfer.final_ack {
                let accepted = rt
                    .v3_history
                    .lock()
                    .acknowledge_server_final(peer, transfer);
                if accepted {
                    rt.net.acknowledge_bulk_unicast(
                        from,
                        &rt.topic,
                        BulkPageIdentity::history(
                            transfer.transfer_id,
                            transfer.acknowledged_request_nonce,
                        ),
                    );
                    if let Some(confirmation) = history_final_ack_confirmation(rt, &req) {
                        let reason = CatchupReason::from_v3_wire(transfer.reason)
                            .unwrap_or(CatchupReason::RepositoryGap);
                        let _ = send_v3_metadata_control(
                            rt,
                            from,
                            StrictBody::CatchupResp(confirmation),
                            reason,
                            CatchupPhase::FinalAck,
                        )
                        .await;
                    }
                    resume_deferred_v3_terminal_sync(rt, peer).await;
                }
                return;
            }
            if rt.v3_sync.lock().has_periodic_work(peer) {
                let yielded_nonce = rt.v3_sync.lock().yield_terminal_client_for_history(peer);
                let Some(yielded_nonce) = yielded_nonce else {
                    return;
                };
                rt.v3_retries.lock().complete_request(peer, yielded_nonce);
            }
            match rt.v3_history.lock().begin_server_request(
                peer,
                transfer,
                rt.cfg.pending_propose_ttl(),
            ) {
                HistoryServerRequest::Build { preempted_pages } => {
                    for (transfer_id, request_nonce) in preempted_pages {
                        rt.net.acknowledge_bulk_unicast(
                            from,
                            &rt.topic,
                            BulkPageIdentity::history(transfer_id, request_nonce),
                        );
                    }
                    history_server_peer = Some(peer);
                }
                HistoryServerRequest::Replay(response) => {
                    metrics::record_strict_catchup_duplicate(
                        StrictCatchupDuplicateOutcome::CachedReplay,
                    );
                    history_replay = Some(response);
                }
                HistoryServerRequest::Suppress | HistoryServerRequest::Reject => return,
            }
            true
        }
        None => false,
    };
    if let Some(response) = history_replay {
        let _ = send_v3_history_response(rt, from, &req, response).await;
        return;
    }
    // Every admission/history probe needs a fresh directed clock proof. A
    // requester that already remembers the responder's terminal generation
    // legitimately starts at SKIP and must not lose the clock half of the
    // admission handshake merely because no terminal pagination is needed.
    let terminal_probe = req.history_probe_only;
    let Some(_permit) = rt
        .cfg
        .try_begin_catchup(CatchupMode::Strict, &rt.topic, from)
    else {
        if let (Some(peer), Some(transfer)) = (history_server_peer, req.history_transfer.as_ref()) {
            rt.v3_history.lock().abandon_server_request(peer, transfer);
        }
        return;
    };
    // V3 history continuations echo the exact response nonce whose physical
    // first-hop reservation is now durable. Legacy v2 can only correlate by
    // its advancing log or terminal cursor and therefore retains its single
    // legacy slot. Snapshot pages are intentionally excluded because the
    // production bulk pacer does not reserve an uncorrelated Legacy identity.
    if let Some(transfer) = req.history_transfer.as_ref() {
        if transfer.acknowledged_request_nonce != 0 {
            rt.net.acknowledge_bulk_unicast(
                from,
                &rt.topic,
                BulkPageIdentity::history(
                    transfer.transfer_id,
                    transfer.acknowledged_request_nonce,
                ),
            );
        }
    } else if req.chunk_token > req.since_version
        || (req.terminal_state_cursor != 0
            && req.terminal_state_cursor != TERMINAL_STATE_CURSOR_SKIP)
    {
        rt.net
            .acknowledge_bulk_unicast(from, &rt.topic, BulkPageIdentity::Legacy);
    }
    let snapshot_completion_request = is_snapshot_completion_request(&req);
    let completed_snapshot_transfer = if snapshot_completion_request {
        let mut transfers = rt.snapshot_transfers.lock();
        let completed = transfers.get(&from).is_some_and(|transfer| {
            transfer.id == req.snapshot_transfer_id && req.since_version >= transfer.version
        });
        if completed {
            transfers.remove(&from);
        }
        completed
    } else {
        false
    };
    if completed_snapshot_transfer {
        metrics::record_strict_snapshot_responder_event(
            StrictSnapshotResponderEvent::CompletionAcknowledged,
        );
    }
    if !rt.terminal_storage_ready() {
        warn!(
            from,
            "strict catchup declined because terminal storage is unavailable"
        );
        return;
    }
    if req.history_probe_only && req.since_version > rt.repo.current_version() {
        let local_version = rt.repo.current_version();
        // Admission probes carry the requester's durable version. This peer
        // may not know it was excluded from a frozen configuration, so use a
        // strictly newer authenticated requester cut to trigger normal
        // history election without waiting for steady-state anti-entropy.
        let started_history_election = {
            let mut state = rt.state.lock();
            if !state.history_election_blocks_steady_state() {
                state.request_history_election();
                true
            } else {
                false
            }
        };
        if started_history_election {
            rt.wake_clock_tick_loop();
        }
        // V3 fallbacks are independently rate-limited by the admission loop.
        // Legacy peers still need this reciprocal request immediately.
        if !rt.v3_repair_supported_by(from) {
            let reciprocal = StrictCatchupReq {
                src_node: rt.self_id as u32,
                since_version: local_version,
                chunk_token: local_version,
                force_snapshot: false,
                history_probe_only: false,
                terminal_state_cursor: 0,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
                history_transfer: None,
            };
            metrics::record_catchup_request(CatchupMode::Strict);
            if let Err(error) = rt
                .net
                .send_redundant_unicast(from, &rt.topic, StrictBody::CatchupReq(reciprocal))
                .await
            {
                trace!(%error, from, "strict reciprocal admission catchup request failed");
            }
        }
    }
    // This is a reply path for an authenticated request that has already
    // crossed the overlay. Do not discard its terminal fence merely because a
    // separate LSA is temporarily below v2; a genuine legacy requester is
    // still rejected by the per-peer capability check.
    let v2_terminal_catchup = rt.can_respond_to_v2_terminal_catchup(from);
    if terminal_probe && v2_terminal_catchup {
        rt.send_v2_terminal_probe_clock_reply(from).await;
    }
    // Older peers cannot echo a completed terminal-fence generation. Serving
    // ordinary history to them after any terminal decision would let a later
    // catchup erase the fence, so retain inbound compatibility but fail the
    // unsafe repair request closed.
    if !v2_terminal_catchup && rt.has_any_terminal_decision().await {
        warn!(
            from,
            "strict catchup declined because requester cannot prove a complete terminal fence sync"
        );
        return;
    }
    let build_started_at = std::time::Instant::now();
    let v2_snapshot_transfer = v2_snapshot_transfer_supported(rt, from);
    // Terminal decisions are durable fences and must reach a joining member
    // before it processes ordinary history. Page them independently from the
    // repository-version cursor so a long-lived journal cannot inflate every
    // catchup response beyond the transport frame cap.
    let current_terminal_decision_generation = rt.terminal_decision_generation().await;
    if !correlated_v3_history
        && v2_terminal_catchup
        && req.terminal_state_cursor == TERMINAL_STATE_CURSOR_SKIP
    {
        rt.acknowledge_terminal_catchup_snapshot(from, req.terminal_decision_generation);
    }
    let must_restart_terminal_sync = !correlated_v3_history
        && v2_terminal_catchup
        && req.terminal_state_cursor == TERMINAL_STATE_CURSOR_SKIP
        && req.terminal_decision_generation != current_terminal_decision_generation;
    if must_restart_terminal_sync {
        rt.reset_terminal_catchup_snapshot(from);
        rt.snapshot_transfers.lock().remove(&from);
    }
    // This identifies the exact stable terminal cut that must fence the
    // history image built below. It comes from the same journal snapshot as
    // the terminal page, rather than from a later independent journal read.
    let mut terminal_decision_generation = current_terminal_decision_generation;
    let terminal_state_cursor = if !correlated_v3_history
        && v2_terminal_catchup
        && (req.terminal_state_cursor != TERMINAL_STATE_CURSOR_SKIP || must_restart_terminal_sync)
    {
        let terminal_cursor = if must_restart_terminal_sync {
            0
        } else {
            req.terminal_state_cursor
        };
        let terminal_page = rt
            .terminal_states_for_catchup_page(
                from,
                terminal_cursor,
                rt.cfg.strict_max_catchup_ops(),
                rt.strict_catchup_response_budget(),
            )
            .await;
        terminal_decision_generation = terminal_page.terminal_decision_generation;
        if terminal_page.oversized {
            warn!(
                from,
                cursor = terminal_cursor,
                max_bytes = rt.strict_catchup_response_budget(),
                "strict terminal catchup state exceeds the configured response budget"
            );
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Strict,
                ReplicationPipelineStage::CatchupBuild,
                build_started_at.elapsed(),
            );
            return;
        }
        // The journal also retains promises and accepted values. An empty
        // page can therefore still have more records to examine before
        // ordinary history is safe to replay.
        if !terminal_page.states.is_empty() || terminal_page.has_more {
            let rank = HistoryRank::local(rt);
            let response_bytes = terminal_page
                .states
                .iter()
                .map(|state| state.encoded_len())
                .sum::<usize>();
            let next_terminal_state_cursor = terminal_page.next_cursor;
            let terminal_states_has_more = terminal_page.has_more;
            let resp = StrictCatchupResp {
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: Vec::new(),
                has_more: false,
                next_chunk_token: req.chunk_token.max(req.since_version),
                too_old_use_snapshot: false,
                history_version: rank.version,
                history_freshness: rank.freshness,
                runtime_started_at: rank.runtime_started_at,
                history_node: u32::from(rank.node_id),
                terminal_states: terminal_page.states,
                next_terminal_state_cursor,
                terminal_states_has_more,
                terminal_sync_only: true,
                request_force_snapshot: req.force_snapshot,
                request_history_probe_only: req.history_probe_only,
                terminal_decision_generation,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
                snapshot_next_cursor: 0,
                snapshot_total_bytes: 0,
                snapshot_sha256: Bytes::new(),
                snapshot_has_more: false,
                snapshot_transfer_rejected: false,
                history_transfer: history_transfer_response(rt, &req),
            };
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Strict,
                ReplicationPipelineStage::CatchupBuild,
                build_started_at.elapsed(),
            );
            metrics::record_catchup_response(CatchupMode::Strict, 0, response_bytes);
            send_v2_response(rt, from, resp).await;
            return;
        }
        // No terminal decision remains to transfer. Mark terminal sync
        // complete so ordinary-history pagination does not rescan a
        // promise-only journal tail on every chunk.
        TERMINAL_STATE_CURSOR_SKIP
    } else {
        TERMINAL_STATE_CURSOR_SKIP
    };

    if req.history_probe_only {
        let rank = HistoryRank::local(rt);
        let resp = StrictCatchupResp {
            snapshot_version: 0,
            snapshot_msgpack: Bytes::new(),
            ops: Vec::new(),
            has_more: false,
            next_chunk_token: 0,
            too_old_use_snapshot: false,
            history_version: rank.version,
            history_freshness: rank.freshness,
            runtime_started_at: rank.runtime_started_at,
            history_node: u32::from(rank.node_id),
            terminal_states: Vec::new(),
            next_terminal_state_cursor: terminal_state_cursor,
            terminal_states_has_more: false,
            terminal_sync_only: false,
            request_force_snapshot: req.force_snapshot,
            request_history_probe_only: req.history_probe_only,
            terminal_decision_generation,
            snapshot_transfer_id: 0,
            snapshot_chunk_cursor: 0,
            snapshot_next_cursor: 0,
            snapshot_total_bytes: 0,
            snapshot_sha256: Bytes::new(),
            snapshot_has_more: false,
            snapshot_transfer_rejected: false,
            history_transfer: history_transfer_response(rt, &req),
        };
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::CatchupBuild,
            build_started_at.elapsed(),
        );
        metrics::record_catchup_response(CatchupMode::Strict, 0, 0);
        if v2_terminal_catchup {
            send_v2_response(rt, from, resp).await;
        } else {
            send_response(rt, from, resp).await;
        }
        return;
    }

    if req.snapshot_transfer_id != 0 && !snapshot_completion_request {
        if !v2_snapshot_transfer {
            warn!(
                from,
                "strict snapshot-transfer continuation declined for a peer without v2 support"
            );
            return;
        }
        respond_with_snapshot_transfer(
            rt,
            from,
            &req,
            terminal_decision_generation,
            build_started_at,
        )
        .await;
        return;
    }

    let mut snapshot_version = 0u64;
    let mut snapshot_metadata = None;
    let mut snapshot_msgpack: Bytes = Bytes::new();
    let mut too_old_use_snapshot = false;
    let max_ops = rt.cfg.strict_max_catchup_ops().max(1);
    let max_bytes = rt.strict_catchup_response_budget();
    let force_snapshot = req.force_snapshot || req.chunk_token == HISTORY_ELECTION_SNAPSHOT_TOKEN;
    if force_snapshot && v2_snapshot_transfer {
        respond_with_snapshot_transfer(
            rt,
            from,
            &req,
            terminal_decision_generation,
            build_started_at,
        )
        .await;
        return;
    }
    let request_since = req.chunk_token.max(req.since_version);
    let (effective_ops, effective_since) = if force_snapshot {
        too_old_use_snapshot = true;
        let (metadata, snap) = match rt.repo.snapshot_with_metadata() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let capability_withdrawn =
                    snapshot_error_withdraws_repository_capability(rt, &error);
                warn!(
                    from,
                    error = %error,
                    durability_failure = error.is_durability_failure(),
                    capability_withdrawn,
                    "strict catchup snapshot capture failed; declining response"
                );
                metrics::record_pipeline_stage(
                    ReplicationPipelineKind::Strict,
                    ReplicationPipelineStage::CatchupBuild,
                    build_started_at.elapsed(),
                );
                return;
            }
        };
        let sv = metadata.version;
        snapshot_version = sv;
        snapshot_metadata = Some(metadata);
        snapshot_msgpack = snap;
        (Vec::new(), sv)
    } else {
        match rt.repo.log_since(request_since) {
            LogSlice::Available(ops) => (ops, request_since),
            LogSlice::TooOld => {
                if v2_snapshot_transfer {
                    respond_with_snapshot_transfer(
                        rt,
                        from,
                        &req,
                        terminal_decision_generation,
                        build_started_at,
                    )
                    .await;
                    return;
                }
                too_old_use_snapshot = true;
                let (metadata, snap) = match rt.repo.snapshot_with_metadata() {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        let capability_withdrawn =
                            snapshot_error_withdraws_repository_capability(rt, &error);
                        warn!(
                            from,
                            error = %error,
                            durability_failure = error.is_durability_failure(),
                            capability_withdrawn,
                            "strict catchup snapshot capture failed; declining response"
                        );
                        metrics::record_pipeline_stage(
                            ReplicationPipelineKind::Strict,
                            ReplicationPipelineStage::CatchupBuild,
                            build_started_at.elapsed(),
                        );
                        return;
                    }
                };
                let sv = metadata.version;
                snapshot_version = sv;
                snapshot_metadata = Some(metadata);
                snapshot_msgpack = snap;
                match rt.repo.log_since(sv) {
                    LogSlice::Available(ops) => (ops, sv),
                    LogSlice::TooOld => (Vec::new(), sv),
                }
            }
        }
    };

    let snapshot_response_len = match history_response_encoded_len(
        rt,
        snapshot_version,
        snapshot_msgpack.clone(),
        too_old_use_snapshot,
        Vec::new(),
        v2_terminal_catchup,
    ) {
        Ok(response_len) => response_len,
        Err(error) => {
            warn!(
                from,
                error = %error,
                "strict legacy snapshot response authentication framing failed"
            );
            return;
        }
    };
    if snapshot_response_len > max_bytes {
        warn!(
            from,
            snapshot_bytes = snapshot_msgpack.len(),
            response_bytes = snapshot_response_len,
            max_bytes,
            "strict catchup snapshot exceeds the encoded response budget"
        );
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::CatchupBuild,
            build_started_at.elapsed(),
        );
        return;
    }
    let mut catchup_ops: Vec<CatchupOp> = Vec::with_capacity(max_ops);
    let mut response_bytes = snapshot_msgpack.len();
    let mut next_chunk_token = effective_since;
    let mut has_more = false;
    let fixed_target_version = req
        .history_transfer
        .as_ref()
        .map(|transfer| transfer.target_version);
    for (v, entry) in &effective_ops {
        if fixed_target_version.is_some_and(|target| *v > target) {
            break;
        }
        if catchup_ops.len() >= max_ops {
            has_more = true;
            break;
        }
        let encode_started_at = std::time::Instant::now();
        match rmp_serde::to_vec(&entry.op) {
            Ok(b) => {
                let op_msgpack = Bytes::from(b);
                let (strict_op_id_hi, strict_op_id_lo, strict_ts_final, terminal_proof) =
                    match entry.metadata {
                        Some(metadata) => {
                            let terminal_proof = match rt
                                .terminal_commit_proof_for_catchup(
                                    (metadata.op_id_hi, metadata.op_id_lo),
                                    metadata.ts_final,
                                    &op_msgpack,
                                )
                                .await
                            {
                                Ok(proof) => proof,
                                Err(()) => {
                                    warn!(
                                        version = *v,
                                        op_id_hi = metadata.op_id_hi,
                                        op_id_lo = metadata.op_id_lo,
                                        "strict catchup history entry lacks a valid terminal fence"
                                    );
                                    metrics::record_pipeline_stage(
                                        ReplicationPipelineKind::Strict,
                                        ReplicationPipelineStage::CatchupBuild,
                                        build_started_at.elapsed(),
                                    );
                                    return;
                                }
                            };
                            (
                                metadata.op_id_hi,
                                metadata.op_id_lo,
                                metadata.ts_final,
                                terminal_proof,
                            )
                        }
                        None => (0, 0, 0, None),
                    };
                if terminal_proof.is_some() && !v2_terminal_catchup {
                    warn!(
                        from,
                        version = *v,
                        "strict v2 history cannot be served to a peer without v2 terminal identity support"
                    );
                    metrics::record_pipeline_stage(
                        ReplicationPipelineKind::Strict,
                        ReplicationPipelineStage::CatchupBuild,
                        build_started_at.elapsed(),
                    );
                    return;
                }
                let op = CatchupOp {
                    version: *v,
                    op_msgpack,
                    strict_op_id_hi,
                    strict_op_id_lo,
                    strict_ts_final,
                    strict_terminal_ballot: terminal_proof
                        .as_ref()
                        .map(|proof| proof.ballot)
                        .unwrap_or_default(),
                    strict_terminal_resolver_node: terminal_proof
                        .as_ref()
                        .map(|proof| proof.identity.resolver.node() as u32)
                        .unwrap_or_default(),
                    strict_terminal_resolver_boot_epoch: terminal_proof
                        .as_ref()
                        .map(|proof| proof.identity.resolver.boot_epoch())
                        .unwrap_or_default(),
                    strict_terminal_frozen_targets: terminal_proof
                        .as_ref()
                        .map(|proof| {
                            super::runtime::frozen_targets_to_wire(&proof.identity.frozen_targets)
                        })
                        .unwrap_or_default(),
                };
                let encoded_len = op.encoded_len();
                let mut candidate_ops = catchup_ops.clone();
                candidate_ops.push(op.clone());
                let candidate_response_len = match history_response_encoded_len(
                    rt,
                    snapshot_version,
                    snapshot_msgpack.clone(),
                    too_old_use_snapshot,
                    candidate_ops,
                    v2_terminal_catchup,
                ) {
                    Ok(response_len) => response_len,
                    Err(error) => {
                        warn!(
                            from,
                            version = *v,
                            error = %error,
                            "strict catchup history response authentication framing failed"
                        );
                        return;
                    }
                };
                if candidate_response_len > max_bytes {
                    if catchup_ops.is_empty() {
                        warn!(
                            from,
                            version = *v,
                            op_bytes = encoded_len,
                            response_bytes = candidate_response_len,
                            max_bytes,
                            "strict catchup history entry exceeds the encoded response budget"
                        );
                        metrics::record_pipeline_stage(
                            ReplicationPipelineKind::Strict,
                            ReplicationPipelineStage::CatchupBuild,
                            build_started_at.elapsed(),
                        );
                        return;
                    }
                    has_more = true;
                    break;
                }
                response_bytes = response_bytes.saturating_add(encoded_len);
                next_chunk_token = *v;
                catchup_ops.push(op);
            }
            Err(e) => {
                warn!(error=%e, "catchup op msgpack encode failed; skipping");
                // Advance the cursor past an unencodable entry so one bad
                // operation cannot permanently pin catchup pagination.
                next_chunk_token = *v;
            }
        }
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::MsgpackEncode,
            encode_started_at.elapsed(),
        );
    }
    if !has_more
        && next_chunk_token
            < fixed_target_version.unwrap_or_else(|| {
                effective_ops
                    .last()
                    .map(|(version, _)| *version)
                    .unwrap_or(effective_since)
            })
    {
        has_more = true;
    }
    // A terminal decision is persisted before its repository delivery. If a
    // decision appeared while this response captured history, do not send a
    // snapshot/log cut that includes the commit without its fence. Restart
    // terminal pagination from the new durable cut first. The generation was
    // captured with the terminal page (or verified from the request's echoed
    // completed cut), so an abort committed in the gap cannot be missed.
    if !correlated_v3_history
        && terminal_state_cursor == TERMINAL_STATE_CURSOR_SKIP
        && terminal_decision_generation != rt.terminal_decision_generation().await
    {
        if !v2_terminal_catchup {
            warn!(
                from,
                "strict catchup declined because a terminal fence appeared for a legacy requester"
            );
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Strict,
                ReplicationPipelineStage::CatchupBuild,
                build_started_at.elapsed(),
            );
            return;
        }
        rt.reset_terminal_catchup_snapshot(from);
        rt.snapshot_transfers.lock().remove(&from);
        let terminal_page = rt
            .terminal_states_for_catchup_page(
                from,
                0,
                rt.cfg.strict_max_catchup_ops(),
                rt.strict_catchup_response_budget(),
            )
            .await;
        if terminal_page.oversized || (!terminal_page.has_more && terminal_page.states.is_empty()) {
            warn!(
                from,
                "strict catchup terminal/history cut changed but cannot form a safe terminal page"
            );
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Strict,
                ReplicationPipelineStage::CatchupBuild,
                build_started_at.elapsed(),
            );
            return;
        }
        let rank = HistoryRank::local(rt);
        let response_bytes = terminal_page
            .states
            .iter()
            .map(|state| state.encoded_len())
            .sum::<usize>();
        let resp = StrictCatchupResp {
            snapshot_version: 0,
            snapshot_msgpack: Bytes::new(),
            ops: Vec::new(),
            has_more: false,
            next_chunk_token: req.chunk_token.max(req.since_version),
            too_old_use_snapshot: false,
            history_version: rank.version,
            history_freshness: rank.freshness,
            runtime_started_at: rank.runtime_started_at,
            history_node: u32::from(rank.node_id),
            terminal_states: terminal_page.states,
            next_terminal_state_cursor: terminal_page.next_cursor,
            terminal_states_has_more: terminal_page.has_more,
            terminal_sync_only: true,
            request_force_snapshot: req.force_snapshot,
            request_history_probe_only: req.history_probe_only,
            terminal_decision_generation: terminal_page.terminal_decision_generation,
            snapshot_transfer_id: 0,
            snapshot_chunk_cursor: 0,
            snapshot_next_cursor: 0,
            snapshot_total_bytes: 0,
            snapshot_sha256: Bytes::new(),
            snapshot_has_more: false,
            snapshot_transfer_rejected: false,
            history_transfer: history_transfer_response(rt, &req),
        };
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::CatchupBuild,
            build_started_at.elapsed(),
        );
        metrics::record_catchup_response(CatchupMode::Strict, 0, response_bytes);
        send_v2_response(rt, from, resp).await;
        return;
    }
    metrics::record_pipeline_stage(
        ReplicationPipelineKind::Strict,
        ReplicationPipelineStage::CatchupBuild,
        build_started_at.elapsed(),
    );

    let current_rank = HistoryRank::local(rt);
    // A snapshot is captured before this response is assembled. Advertise
    // the snapshot's own version rather than a later repository read so a
    // concurrent delivery cannot make the response reject itself.
    let rank = if too_old_use_snapshot {
        let snapshot_metadata = snapshot_metadata
            .expect("snapshot response must retain the atomically captured history metadata");
        HistoryRank {
            version: snapshot_metadata.version,
            freshness: snapshot_metadata.freshness,
            runtime_started_at: current_rank.runtime_started_at,
            node_id: current_rank.node_id,
            terminal_repository_base_version: current_rank.terminal_repository_base_version,
        }
    } else {
        current_rank
    };
    let resp = StrictCatchupResp {
        snapshot_version,
        snapshot_msgpack,
        ops: catchup_ops,
        has_more,
        next_chunk_token,
        too_old_use_snapshot,
        history_version: rank.version,
        history_freshness: rank.freshness,
        runtime_started_at: rank.runtime_started_at,
        history_node: u32::from(rank.node_id),
        terminal_states: Vec::new(),
        next_terminal_state_cursor: terminal_state_cursor,
        terminal_states_has_more: false,
        terminal_sync_only: false,
        request_force_snapshot: req.force_snapshot,
        request_history_probe_only: req.history_probe_only,
        terminal_decision_generation,
        snapshot_transfer_id: 0,
        snapshot_chunk_cursor: 0,
        snapshot_next_cursor: 0,
        snapshot_total_bytes: 0,
        snapshot_sha256: Bytes::new(),
        snapshot_has_more: false,
        snapshot_transfer_rejected: false,
        history_transfer: history_transfer_response(rt, &req),
    };
    let response_records = resp.ops.len();
    if correlated_v3_history {
        if let Err(error) = send_v3_history_response(rt, from, &req, resp).await {
            warn!(from, %error, "strict v3 repository history response send failed");
        }
    } else if v2_terminal_catchup {
        metrics::record_catchup_response(CatchupMode::Strict, response_records, response_bytes);
        send_v2_response(rt, from, resp).await;
    } else {
        metrics::record_catchup_response(CatchupMode::Strict, response_records, response_bytes);
        send_response(rt, from, resp).await;
    }
}

fn rearm_history_election<R: StrictReplicable>(rt: &StrictRuntime<R>) {
    {
        let mut state = rt.state.lock();
        state.finish_history_election();
        state.request_history_election();
    }
    rt.wake_clock_tick_loop();
}

fn rearm_history_election_if_fetching_from<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    peer: NodeIdentifier,
) {
    let rearmed = {
        let mut state = rt.state.lock();
        if state
            .history_election_fetching_snapshot()
            .is_some_and(|request| request.peer() == peer)
        {
            state.finish_history_election();
            state.request_history_election();
            true
        } else {
            false
        }
    };
    if rearmed {
        rt.wake_clock_tick_loop();
    }
}

fn request_history_election_if_inactive<R: StrictReplicable>(rt: &StrictRuntime<R>) {
    let requested = {
        let mut state = rt.state.lock();
        if state.history_election_active() {
            false
        } else {
            state.request_history_election();
            true
        }
    };
    if requested {
        rt.wake_clock_tick_loop();
    }
}

/// End a response whose exact V3 request nonce was already claimed.
///
/// Claiming consumes retry ownership. Every subsequent rejection must also
/// release the history client before rearming ranked recovery, otherwise the
/// stale client suppresses replacement work until its full session TTL.
async fn fail_claimed_v3_history_response<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    correlated_peer: Option<PeerIncarnation>,
) -> bool {
    let Some(peer) = correlated_peer else {
        return false;
    };
    finish_v3_history_transfer(rt, peer, StrictCatchupSessionOutcome::Failed).await;
    rearm_history_election(rt);
    true
}

pub(super) async fn install_snapshot_candidate<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    rank: HistoryRank,
    snapshot_version: u64,
    snapshot_msgpack: Bytes,
    apply_started_at: Instant,
    correlated_peer: Option<PeerIncarnation>,
) {
    let format = snapshot_format_for_peer(rt, from);
    install_snapshot_candidate_with_format(
        rt,
        from,
        rank,
        format,
        snapshot_version,
        snapshot_msgpack,
        apply_started_at,
        correlated_peer,
        None,
    )
    .await;
}

async fn install_snapshot_candidate_with_format<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    rank: HistoryRank,
    format: SnapshotFormat,
    snapshot_version: u64,
    snapshot_msgpack: Bytes,
    apply_started_at: Instant,
    correlated_peer: Option<PeerIncarnation>,
    completed_snapshot_transfer_id: Option<u64>,
) {
    let local_rank = HistoryRank::local(rt);
    // This state transition rechecks bootstrap and delivery fences while the
    // state lock is held. Do not use a stale boolean sampled before image
    // assembly to authorize an install.
    let outcome = rt.state.lock().record_history_snapshot_response(
        from,
        rank,
        local_rank,
        snapshot_version,
        snapshot_msgpack,
    );
    let HistorySnapshotResponseOutcome::Install(winner) = outcome else {
        if let Some(peer) = correlated_peer {
            // `Ignored` may mean the local repository won while `Retry`
            // already rearms inside the state transition. Both still need to
            // release the exact claimed client, but forcing a new election
            // for an ignored stale candidate would regress the local win.
            finish_v3_history_transfer(rt, peer, StrictCatchupSessionOutcome::Failed).await;
        }
        return;
    };
    // Delivery can begin after the state transition, so retain the explicit
    // fence immediately before the repository receives the replacement.
    if rt.delivery_in_flight() != 0 {
        warn!(
            from,
            "strict snapshot install deferred while terminal delivery is in flight"
        );
        if !fail_claimed_v3_history_response(rt, correlated_peer).await {
            rearm_history_election(rt);
        }
        return;
    }
    let snapshot_started_at = Instant::now();
    if rt.delivery_in_flight() != 0 {
        warn!(
            from,
            "strict snapshot install deferred while terminal delivery started"
        );
        if !fail_claimed_v3_history_response(rt, correlated_peer).await {
            rearm_history_election(rt);
        }
        return;
    }
    let installed_version = winner.snapshot_version;
    let staged_checkpoint = correlated_peer
        .filter(|peer| peer.node() == from)
        .and_then(|peer| {
            rt.v3_sync
                .lock()
                .staged_checkpoint_for_repository(peer, installed_version)
                .map(|checkpoint| (peer, checkpoint))
        });
    if staged_checkpoint.is_some() && installed_version < rt.repo.current_version() {
        warn!(
            from,
            snapshot_version = installed_version,
            repository_version = rt.repo.current_version(),
            "strict foreign terminal checkpoint cannot use an older repository image"
        );
        if !fail_claimed_v3_history_response(rt, correlated_peer).await {
            rearm_history_election(rt);
        }
        return;
    }
    if (staged_checkpoint.is_some()
        || rt.repository_base_required()
        || rt.pending_repository_image_install().is_some())
        && format != SnapshotFormat::S2sEnvelope
    {
        warn!(
            from,
            ?format,
            "strict repository-base recovery requires a v5 snapshot checkpoint"
        );
        if !fail_claimed_v3_history_response(rt, correlated_peer).await {
            rearm_history_election(rt);
        }
        return;
    }
    if !rt.repository_snapshot_satisfies_base(installed_version) {
        warn!(
            from,
            snapshot_version = installed_version,
            "strict snapshot is older than the required terminal-journal repository base"
        );
        if !fail_claimed_v3_history_response(rt, correlated_peer).await {
            rearm_history_election(rt);
        }
        return;
    }
    let (repository_snapshot, applied_checkpoint) = if format == SnapshotFormat::S2sEnvelope {
        match decode_s2s_snapshot_envelope(winner.snapshot_msgpack) {
            Ok((snapshot, applied, retired)) => (
                snapshot,
                Some((applied.into_iter().collect::<BTreeMap<_, _>>(), retired)),
            ),
            Err(error) => {
                warn!(from, %error, "strict S2S snapshot envelope decode failed");
                if !fail_claimed_v3_history_response(rt, correlated_peer).await {
                    rearm_history_election(rt);
                }
                return;
            }
        }
    } else {
        (winner.snapshot_msgpack, None)
    };
    let staged_decisions = match staged_checkpoint.as_ref() {
        Some((_, checkpoint)) => match checkpoint
            .states()
            .iter()
            .map(staged_terminal_decision)
            .collect::<Option<Vec<_>>>()
        {
            Some(decisions) => Some(decisions),
            None => {
                warn!(from, "strict staged terminal checkpoint became invalid");
                if !fail_claimed_v3_history_response(rt, correlated_peer).await {
                    rearm_history_election(rt);
                }
                return;
            }
        },
        None => None,
    };
    let intended_metadata = HistoryMetadata {
        version: installed_version,
        freshness: rank.freshness,
    };
    let prepared_checkpoint = if let Some((applied_checkpoint, retired_checkpoint)) =
        applied_checkpoint
    {
        // Persist the cross-store intent before replacing the repository. If
        // the process stops between these steps, the retained base marker and
        // checkpoint version keep delivery fenced on the old repository.
        rt.require_repository_base(installed_version);
        let applied_for_journal = applied_checkpoint.clone();
        let retired_for_journal = retired_checkpoint.clone();
        let staged_for_journal = staged_checkpoint.clone();
        let staged_decisions_for_journal = staged_decisions.clone();
        let existing_pending = rt
            .terminal_journal
            .lock()
            .await
            .pending_repository_image_install();
        let prepare_checkpoint = match existing_pending {
            None => true,
            Some(pending)
                if (pending.repository_version(), pending.history_freshness())
                    == (installed_version, rank.freshness) =>
            {
                false
            }
            Some(pending)
                if (installed_version, rank.freshness)
                    > (pending.repository_version(), pending.history_freshness()) =>
            {
                // The journal transaction below replaces both the
                // terminal checkpoint and its pending repository-image
                // identity before the newer image reaches the repository.
                // A crash therefore recovers either the old intent or the
                // complete newer intent, never an unmarked mixed state.
                true
            }
            Some(_) => {
                warn!(
                    from,
                    "strict snapshot does not match or advance the already-prepared repository image"
                );
                if !fail_claimed_v3_history_response(rt, correlated_peer).await {
                    rearm_history_election(rt);
                }
                return;
            }
        };
        let installed_retired = if prepare_checkpoint {
            match rt
                .with_terminal_journal_mutation(move |journal| {
                    if let Some((_, staged)) = staged_for_journal {
                        journal.install_staged_repository_checkpoint(
                            installed_version,
                            rank.freshness,
                            staged.target_cut(),
                            staged_decisions_for_journal
                                .as_deref()
                                .expect("staged decisions validated before journal mutation"),
                            &applied_for_journal,
                            &retired_for_journal,
                        )
                    } else {
                        journal.install_repository_checkpoint(
                            installed_version,
                            rank.freshness,
                            &applied_for_journal,
                            &retired_for_journal,
                        )
                    }
                })
                .await
            {
                Ok(retired) => retired,
                Err(error) => {
                    rt.record_terminal_journal_failure(&error);
                    warn!(from, %error, "strict repository-base checkpoint prepare failed");
                    if !fail_claimed_v3_history_response(rt, correlated_peer).await {
                        rearm_history_election(rt);
                    }
                    return;
                }
            }
        } else {
            rt.terminal_journal.lock().await.retired_origins()
        };
        rt.require_repository_image_install(intended_metadata);
        if prepare_checkpoint && let Some((peer, staged)) = &staged_checkpoint {
            rt.replace_runtime_terminal_checkpoint(
                applied_checkpoint.clone(),
                installed_retired.clone(),
            )
            .await;
            rt.v3_sync
                .lock()
                .remember_source_cut(*peer, staged.target_cut());
        }
        Some((
            applied_checkpoint,
            installed_retired,
            staged_checkpoint.is_some(),
        ))
    } else {
        None
    };
    let install_result = rt
        .repo
        .install_snapshot(installed_version, repository_snapshot)
        .await;
    metrics::record_pipeline_stage(
        ReplicationPipelineKind::Strict,
        ReplicationPipelineStage::SnapshotInstall,
        snapshot_started_at.elapsed(),
    );
    match install_result {
        Ok(()) => {
            let installed_metadata = rt.repo.history_metadata();
            if installed_metadata != intended_metadata {
                warn!(
                    from,
                    intended_version = intended_metadata.version,
                    intended_freshness = intended_metadata.freshness,
                    installed_version = installed_metadata.version,
                    installed_freshness = installed_metadata.freshness,
                    "strict repository snapshot metadata does not match the prepared terminal checkpoint"
                );
                if !fail_claimed_v3_history_response(rt, correlated_peer).await {
                    rearm_history_election(rt);
                }
                return;
            }
            if prepared_checkpoint.is_some() {
                let pending_intent = rt
                    .terminal_journal
                    .lock()
                    .await
                    .pending_repository_image_install();
                let Some(pending_intent) = pending_intent else {
                    warn!(
                        from,
                        "strict prepared repository checkpoint lost its durable install intent"
                    );
                    if !fail_claimed_v3_history_response(rt, correlated_peer).await {
                        rearm_history_election(rt);
                    }
                    return;
                };
                if pending_intent.repository_version() != intended_metadata.version
                    || pending_intent.history_freshness() != intended_metadata.freshness
                {
                    warn!(
                        from,
                        intended_version = intended_metadata.version,
                        intended_freshness = intended_metadata.freshness,
                        pending_version = pending_intent.repository_version(),
                        pending_freshness = pending_intent.history_freshness(),
                        "strict repository image does not match the durable install intent"
                    );
                    if !fail_claimed_v3_history_response(rt, correlated_peer).await {
                        rearm_history_election(rt);
                    }
                    return;
                }
                let completion = rt
                    .with_terminal_journal_mutation(move |journal| {
                        journal.complete_repository_image_install(pending_intent)
                    })
                    .await;
                match completion {
                    Ok(true) => {}
                    Ok(false) => {
                        warn!(
                            from,
                            "strict prepared repository checkpoint was not pending completion"
                        );
                        if !fail_claimed_v3_history_response(rt, correlated_peer).await {
                            rearm_history_election(rt);
                        }
                        return;
                    }
                    Err(error) => {
                        rt.record_terminal_journal_failure(&error);
                        warn!(from, %error, "strict repository image completion was not durable");
                        if !fail_claimed_v3_history_response(rt, correlated_peer).await {
                            rearm_history_election(rt);
                        }
                        return;
                    }
                }
            }
            if let Some((applied_checkpoint, installed_retired, source_replaced)) =
                prepared_checkpoint.as_ref()
                && !source_replaced
            {
                rt.state.lock().install_repository_checkpoint(
                    applied_checkpoint.clone(),
                    installed_retired.clone(),
                );
            }
            if !rt.finish_repository_base_install(installed_version) {
                warn!(
                    from,
                    snapshot_version = installed_version,
                    "strict repository-base requirement advanced during snapshot install"
                );
                if !fail_claimed_v3_history_response(rt, correlated_peer).await {
                    rearm_history_election(rt);
                }
                return;
            }
            if prepared_checkpoint.is_some()
                && !rt.finish_repository_image_install(intended_metadata)
            {
                warn!(
                    from,
                    snapshot_version = installed_version,
                    "strict repository image requirement advanced during snapshot install"
                );
                if !fail_claimed_v3_history_response(rt, correlated_peer).await {
                    rearm_history_election(rt);
                }
                return;
            }
            if let Some((peer, staged)) = &staged_checkpoint {
                rt.v3_sync
                    .lock()
                    .remove_staged_checkpoint(*peer, staged.target_cut());
            }
            rt.requeue_undelivered_terminal_journal_commits().await;
            rt.state.lock().finish_history_election();
            rt.wake_delivery_and_clock_tick();
            request_history_after_snapshot(
                rt,
                from,
                installed_version,
                correlated_peer,
                completed_snapshot_transfer_id,
            )
            .await;
        }
        Err(error) => {
            fail_claimed_v3_history_response(rt, correlated_peer).await;
            if snapshot_error_withdraws_repository_capability(rt, &error) {
                warn!(
                    from,
                    error = %error,
                    "strict snapshot install exposed a repository durability failure; withdrawing v2 capability"
                );
            }
            warn!(
                from,
                error = %error,
                "strict catchup snapshot install failed; rearming history election"
            );
            if correlated_peer.is_none() {
                rearm_history_election(rt);
            }
        }
    }
    metrics::record_pipeline_stage(
        ReplicationPipelineKind::Strict,
        ReplicationPipelineStage::CatchupApply,
        apply_started_at.elapsed(),
    );
}

async fn request_history_after_snapshot<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    snapshot_version: u64,
    correlated_peer: Option<PeerIncarnation>,
    completed_snapshot_transfer_id: Option<u64>,
) {
    if from == rt.self_id
        || !rt.net.has_route(from, ServiceLevel::Reliable)
        || !v2_snapshot_transfer_supported(rt, from)
    {
        fail_claimed_v3_history_response(rt, correlated_peer).await;
        return;
    }
    let history_transfer = correlated_peer.and_then(|peer| {
        rt.v3_history
            .lock()
            .continue_transfer(peer, snapshot_version)
    });
    if correlated_peer.is_some() && history_transfer.is_none() {
        fail_claimed_v3_history_response(rt, correlated_peer).await;
        return;
    }
    let req = StrictCatchupReq {
        src_node: rt.self_id as u32,
        since_version: snapshot_version,
        chunk_token: snapshot_version,
        force_snapshot: false,
        history_probe_only: false,
        terminal_state_cursor: TERMINAL_STATE_CURSOR_SKIP,
        terminal_decision_generation: rt.remembered_terminal_decision_generation(from),
        snapshot_transfer_id: completed_snapshot_transfer_id.unwrap_or(0),
        snapshot_chunk_cursor: 0,
        history_transfer,
    };
    let result = if correlated_peer.is_some() {
        send_v3_history_request(rt, from, req).await
    } else {
        metrics::record_catchup_request(CatchupMode::Strict);
        rt.net
            .send_unicast(from, &rt.topic, StrictBody::CatchupReq(req))
            .await
    };
    if let Err(error) = result {
        warn!(from, error = %error, "strict post-snapshot history catchup send failed");
    }
}

enum SnapshotReceiveOutcome {
    Continue {
        transfer_id: u64,
        snapshot_version: u64,
        next_cursor: u64,
        terminal_decision_generation: u64,
    },
    Complete {
        rank: HistoryRank,
        format: SnapshotFormat,
        snapshot_version: u64,
        snapshot_msgpack: Vec<u8>,
        snapshot_sha256: Bytes,
    },
    AmbiguousLegacy {
        transfer_id: u64,
    },
    Duplicate,
    Stale(StrictSnapshotReceiveEvent),
    Restart(StrictSnapshotReceiveEvent),
}

fn receive_snapshot_chunk<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    resp: &StrictCatchupResp,
    remote_rank: HistoryRank,
) -> SnapshotReceiveOutcome {
    let fetching_snapshot_from = rt
        .state
        .lock()
        .history_election_fetching_snapshot()
        .map(|source| source.peer());
    let fetching_from_source = fetching_snapshot_from == Some(from);
    let now = Instant::now();
    let (active_receiver_id, expired_receiver_id) = {
        // Expire under the global transfer-before-receiver lock order before
        // using receiver identity to reject a replacement first page.
        let mut transfers = rt.snapshot_transfers.lock();
        let mut receivers = rt.snapshot_receivers.lock();
        let receiver_id_before_expiry = receivers.get(&from).map(|transfer| transfer.id);
        expire_stale_snapshot_images(
            &mut transfers,
            &mut receivers,
            now,
            rt.cfg.pending_propose_ttl(),
            fetching_snapshot_from.filter(|peer| *peer != from),
        );
        let active_receiver_id = receivers.get(&from).map(|transfer| transfer.id);
        let expired_receiver_id = active_receiver_id
            .is_none()
            .then_some(receiver_id_before_expiry)
            .flatten();
        (active_receiver_id, expired_receiver_id)
    };
    if expired_receiver_id == Some(resp.snapshot_transfer_id) {
        return SnapshotReceiveOutcome::Restart(StrictSnapshotReceiveEvent::RestartExpiredReceiver);
    }
    if active_receiver_id.is_none()
        && !fetching_from_source
        && (resp.request_force_snapshot || rt.repo.current_version() >= resp.snapshot_version)
    {
        return SnapshotReceiveOutcome::Stale(StrictSnapshotReceiveEvent::StaleIdle);
    }
    if active_receiver_id.is_some_and(|transfer_id| transfer_id != resp.snapshot_transfer_id) {
        return SnapshotReceiveOutcome::Stale(StrictSnapshotReceiveEvent::StaleForeignTransfer);
    }
    if active_receiver_id.is_none() && resp.snapshot_chunk_cursor != 0 {
        return SnapshotReceiveOutcome::Stale(StrictSnapshotReceiveEvent::StaleMissingReceiver);
    }
    if !v2_snapshot_transfer_supported(rt, from)
        || !resp.too_old_use_snapshot
        || resp.terminal_sync_only
        || !resp.terminal_states.is_empty()
        || resp.terminal_states_has_more
        || resp.next_terminal_state_cursor != TERMINAL_STATE_CURSOR_SKIP
        || !resp.ops.is_empty()
        || resp.has_more
        || resp.snapshot_version != remote_rank.version
        || resp.snapshot_transfer_id == 0
        || resp.snapshot_sha256.len() != 32
    {
        return SnapshotReceiveOutcome::Restart(StrictSnapshotReceiveEvent::RestartInvalidEnvelope);
    }
    let Some(total_bytes) = usize::try_from(resp.snapshot_total_bytes).ok() else {
        return SnapshotReceiveOutcome::Restart(StrictSnapshotReceiveEvent::RestartInvalidCursor);
    };
    if total_bytes > rt.cfg.strict_max_snapshot_transfer_bytes() {
        warn!(
            from,
            advertised_bytes = resp.snapshot_total_bytes,
            max_snapshot_bytes = rt.cfg.strict_max_snapshot_transfer_bytes(),
            "strict v2 snapshot transfer exceeds the local aggregate resource limit"
        );
        return SnapshotReceiveOutcome::Restart(StrictSnapshotReceiveEvent::RestartResourceLimit);
    }
    let Some(chunk_cursor) = usize::try_from(resp.snapshot_chunk_cursor).ok() else {
        return SnapshotReceiveOutcome::Restart(StrictSnapshotReceiveEvent::RestartInvalidCursor);
    };
    let Some(next_cursor) = usize::try_from(resp.snapshot_next_cursor).ok() else {
        return SnapshotReceiveOutcome::Restart(StrictSnapshotReceiveEvent::RestartInvalidCursor);
    };
    let Some(expected_next_cursor) = chunk_cursor.checked_add(resp.snapshot_msgpack.len()) else {
        return SnapshotReceiveOutcome::Restart(StrictSnapshotReceiveEvent::RestartInvalidCursor);
    };
    if chunk_cursor > total_bytes
        || next_cursor > total_bytes
        || next_cursor != expected_next_cursor
        || resp.snapshot_has_more != (next_cursor < total_bytes)
        || (chunk_cursor < total_bytes && resp.snapshot_msgpack.is_empty())
    {
        return SnapshotReceiveOutcome::Restart(StrictSnapshotReceiveEvent::RestartInvalidCursor);
    }
    // Retained snapshot bytes span responder images and receiver assemblies.
    // Keep this source-map-then-receiver-map order in every dual-map path.
    let mut transfers = rt.snapshot_transfers.lock();
    let mut receivers = rt.snapshot_receivers.lock();
    expire_stale_snapshot_images(
        &mut transfers,
        &mut receivers,
        now,
        rt.cfg.pending_propose_ttl(),
        fetching_snapshot_from,
    );
    let replace = match receivers.get(&from) {
        Some(transfer) if transfer.id == resp.snapshot_transfer_id => false,
        Some(_) => {
            return SnapshotReceiveOutcome::Stale(StrictSnapshotReceiveEvent::StaleForeignTransfer);
        }
        None if chunk_cursor == 0 => true,
        None => {
            return SnapshotReceiveOutcome::Stale(StrictSnapshotReceiveEvent::StaleMissingReceiver);
        }
    };
    let tagged_format = snapshot_format_from_transfer_id(resp.snapshot_transfer_id);
    let snapshot_format = if replace {
        tagged_format.unwrap_or_else(|| snapshot_format_for_peer(rt, from))
    } else {
        let Some(transfer) = receivers.get(&from) else {
            return SnapshotReceiveOutcome::Restart(
                StrictSnapshotReceiveEvent::RestartMissingState,
            );
        };
        if tagged_format.is_some_and(|format| format != transfer.format) {
            receivers.remove(&from);
            return SnapshotReceiveOutcome::Restart(
                StrictSnapshotReceiveEvent::RestartFormatMismatch,
            );
        }
        transfer.format
    };
    if replace {
        // A new transfer supersedes this peer's old partial image before it
        // competes for the aggregate retained-byte budget.
        receivers.remove(&from);
    } else {
        let Some(transfer) = receivers.get(&from) else {
            return SnapshotReceiveOutcome::Restart(
                StrictSnapshotReceiveEvent::RestartMissingState,
            );
        };
        if transfer.id != resp.snapshot_transfer_id
            || transfer.version != resp.snapshot_version
            || transfer.total_bytes != resp.snapshot_total_bytes
            || transfer.snapshot_sha256 != resp.snapshot_sha256
            || transfer.rank != remote_rank
            || transfer.terminal_decision_generation != resp.terminal_decision_generation
        {
            receivers.remove(&from);
            return SnapshotReceiveOutcome::Restart(
                StrictSnapshotReceiveEvent::RestartMetadataMismatch,
            );
        }
        if transfer.next_cursor != resp.snapshot_chunk_cursor
            || transfer.snapshot_msgpack.len() != chunk_cursor
        {
            let duplicate = next_cursor <= transfer.snapshot_msgpack.len()
                && transfer.snapshot_msgpack.get(chunk_cursor..next_cursor)
                    == Some(resp.snapshot_msgpack.as_ref());
            if duplicate {
                return if snapshot_format_from_transfer_id(transfer.id).is_none()
                    && transfer.next_cursor == transfer.total_bytes
                    && legacy_untagged_snapshot_is_ambiguous(&transfer.snapshot_msgpack)
                {
                    SnapshotReceiveOutcome::AmbiguousLegacy {
                        transfer_id: transfer.id,
                    }
                } else {
                    SnapshotReceiveOutcome::Duplicate
                };
            }
            receivers.remove(&from);
            return SnapshotReceiveOutcome::Restart(StrictSnapshotReceiveEvent::RestartChunkOrder);
        }
    }

    let Some(retained_bytes) = retained_snapshot_bytes(&transfers, &receivers) else {
        warn!(
            from,
            "strict v2 snapshot retained-byte accounting overflowed"
        );
        receivers.remove(&from);
        return SnapshotReceiveOutcome::Restart(StrictSnapshotReceiveEvent::RestartResourceLimit);
    };
    let Some(required_bytes) = retained_bytes.checked_add(resp.snapshot_msgpack.len()) else {
        warn!(
            from,
            "strict v2 snapshot retained-byte accounting overflowed"
        );
        receivers.remove(&from);
        return SnapshotReceiveOutcome::Restart(StrictSnapshotReceiveEvent::RestartResourceLimit);
    };
    if required_bytes > rt.cfg.strict_max_snapshot_transfer_bytes() {
        warn!(
            from,
            retained_bytes,
            chunk_bytes = resp.snapshot_msgpack.len(),
            max_snapshot_bytes = rt.cfg.strict_max_snapshot_transfer_bytes(),
            "strict v2 snapshot chunk would exceed the aggregate retained-image resource limit"
        );
        // Do not leave a stalled partial image holding the cap after rejecting
        // this peer's chunk. The caller re-arms history election.
        receivers.remove(&from);
        return SnapshotReceiveOutcome::Restart(StrictSnapshotReceiveEvent::RestartResourceLimit);
    }
    if replace {
        receivers.insert(
            from,
            SnapshotReceiveTransfer {
                id: resp.snapshot_transfer_id,
                format: snapshot_format,
                version: resp.snapshot_version,
                total_bytes: resp.snapshot_total_bytes,
                snapshot_sha256: resp.snapshot_sha256.clone(),
                rank: remote_rank,
                terminal_decision_generation: resp.terminal_decision_generation,
                next_cursor: 0,
                snapshot_msgpack: Vec::new(),
                last_used_at: now,
            },
        );
    }
    let Some(transfer) = receivers.get_mut(&from) else {
        return SnapshotReceiveOutcome::Restart(StrictSnapshotReceiveEvent::RestartMissingState);
    };
    transfer.last_used_at = now;
    transfer
        .snapshot_msgpack
        .extend_from_slice(&resp.snapshot_msgpack);
    transfer.next_cursor = resp.snapshot_next_cursor;
    if resp.snapshot_has_more {
        return SnapshotReceiveOutcome::Continue {
            transfer_id: transfer.id,
            snapshot_version: transfer.version,
            next_cursor: transfer.next_cursor,
            terminal_decision_generation: transfer.terminal_decision_generation,
        };
    }
    let Some(transfer) = receivers.get(&from) else {
        return SnapshotReceiveOutcome::Restart(StrictSnapshotReceiveEvent::RestartMissingState);
    };
    if snapshot_sha256(&transfer.snapshot_msgpack) != transfer.snapshot_sha256 {
        receivers.remove(&from);
        return SnapshotReceiveOutcome::Restart(StrictSnapshotReceiveEvent::RestartDigestMismatch);
    }
    if snapshot_format_from_transfer_id(transfer.id).is_none()
        && legacy_untagged_snapshot_is_ambiguous(&transfer.snapshot_msgpack)
    {
        // The legacy token carries no representation bit. Exact envelope
        // bytes can also be a repository's legitimate raw snapshot, so
        // neither unwrapping nor passing the outer bytes through is safe.
        // Retain this verified image under the existing byte cap and TTL;
        // identical retries are suppressed as quarantined duplicates.
        return SnapshotReceiveOutcome::AmbiguousLegacy {
            transfer_id: transfer.id,
        };
    }
    let Some(transfer) = receivers.remove(&from) else {
        return SnapshotReceiveOutcome::Restart(StrictSnapshotReceiveEvent::RestartMissingState);
    };
    SnapshotReceiveOutcome::Complete {
        rank: transfer.rank,
        format: snapshot_format_from_transfer_id(transfer.id).unwrap_or(SnapshotFormat::Repository),
        snapshot_version: transfer.version,
        snapshot_msgpack: transfer.snapshot_msgpack,
        snapshot_sha256: transfer.snapshot_sha256,
    }
}

async fn request_next_snapshot_chunk<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    transfer_id: u64,
    snapshot_version: u64,
    next_cursor: u64,
    terminal_decision_generation: u64,
    correlated_peer: Option<PeerIncarnation>,
) {
    if from == rt.self_id
        || !rt.net.has_route(from, ServiceLevel::Reliable)
        || !v2_snapshot_transfer_supported(rt, from)
    {
        if let Some(peer) = correlated_peer {
            finish_v3_history_transfer(rt, peer, StrictCatchupSessionOutcome::Failed).await;
        }
        rearm_history_election(rt);
        return;
    }
    let history_transfer =
        correlated_peer.and_then(|peer| rt.v3_history.lock().continue_transfer(peer, next_cursor));
    if correlated_peer.is_some() && history_transfer.is_none() {
        // Claiming the preceding page consumed its retry owner. Cancellation,
        // expiry, or preemption can remove the client before this continuation
        // is prepared; leaving the elected phase intact would strand recovery
        // until the snapshot watchdog fires.
        if let Some(peer) = correlated_peer {
            finish_v3_history_transfer(rt, peer, StrictCatchupSessionOutcome::Failed).await;
        }
        rearm_history_election_if_fetching_from(rt, from);
        return;
    }
    let req = StrictCatchupReq {
        src_node: rt.self_id as u32,
        since_version: snapshot_version,
        chunk_token: snapshot_version,
        force_snapshot: true,
        history_probe_only: false,
        terminal_state_cursor: TERMINAL_STATE_CURSOR_SKIP,
        terminal_decision_generation,
        snapshot_transfer_id: transfer_id,
        snapshot_chunk_cursor: next_cursor,
        history_transfer,
    };
    let result = if correlated_peer.is_some() {
        send_v3_history_request(rt, from, req).await
    } else {
        metrics::record_catchup_request(CatchupMode::Strict);
        rt.net
            .send_unicast(from, &rt.topic, StrictBody::CatchupReq(req))
            .await
    };
    if let Err(error) = result {
        warn!(from, error = %error, "strict v2 snapshot chunk continuation send failed");
        if correlated_peer.is_none() {
            rearm_history_election(rt);
        }
    }
}

async fn apply_snapshot_transfer_response<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    resp: &StrictCatchupResp,
    remote_rank: HistoryRank,
    apply_started_at: Instant,
    correlated_peer: Option<PeerIncarnation>,
) {
    if resp.snapshot_transfer_rejected {
        metrics::record_strict_snapshot_receive_event(StrictSnapshotReceiveEvent::SourceRejected);
        let correlated = correlated_peer.is_some();
        if let Some(peer) = correlated_peer {
            finish_v3_history_transfer(rt, peer, StrictCatchupSessionOutcome::Failed).await;
        }
        let (fetching_from_source, election_active) = {
            let state = rt.state.lock();
            (
                state
                    .history_election_fetching_snapshot()
                    .is_some_and(|source| source.peer() == from),
                state.history_election_active(),
            )
        };
        let (active_transfer_id, rejected_active_transfer) = {
            let mut receivers = rt.snapshot_receivers.lock();
            let active_transfer_id = receivers.get(&from).map(|receiver| receiver.id);
            let rejected_active_transfer = resp.snapshot_transfer_id != 0
                && active_transfer_id == Some(resp.snapshot_transfer_id);
            if rejected_active_transfer || (correlated && fetching_from_source) {
                receivers.remove(&from);
            }
            (active_transfer_id, rejected_active_transfer)
        };
        warn!(
            topic = %rt.topic,
            from,
            fetching_from_source,
            correlated_v3_history = correlated,
            rejected_transfer_id = resp.snapshot_transfer_id,
            rejected_cursor = resp.snapshot_chunk_cursor,
            active_transfer_id = ?active_transfer_id,
            rejected_active_transfer,
            "strict v2 snapshot transfer was rejected by the source"
        );
        if fetching_from_source
            && (correlated
                || rejected_active_transfer
                || (resp.snapshot_transfer_id == 0 && active_transfer_id.is_none()))
        {
            rearm_history_election_if_fetching_from(rt, from);
        } else if rejected_active_transfer && !election_active {
            rearm_history_election(rt);
        }
        return;
    }
    let receiver_before = {
        let receivers = rt.snapshot_receivers.lock();
        receivers.get(&from).map(|receiver| {
            (
                receiver.id,
                receiver.version,
                receiver.next_cursor,
                receiver.total_bytes,
                receiver.terminal_decision_generation,
                receiver.snapshot_sha256.clone(),
            )
        })
    };
    match receive_snapshot_chunk(rt, from, resp, remote_rank) {
        SnapshotReceiveOutcome::Continue {
            transfer_id,
            snapshot_version,
            next_cursor,
            terminal_decision_generation,
        } => {
            metrics::record_strict_snapshot_receive_event(StrictSnapshotReceiveEvent::Continued);
            request_next_snapshot_chunk(
                rt,
                from,
                transfer_id,
                snapshot_version,
                next_cursor,
                terminal_decision_generation,
                correlated_peer,
            )
            .await;
        }
        SnapshotReceiveOutcome::Complete {
            rank,
            format,
            snapshot_version,
            snapshot_msgpack,
            snapshot_sha256: expected_sha256,
        } => {
            metrics::record_strict_snapshot_receive_event(StrictSnapshotReceiveEvent::Completed);
            if snapshot_sha256(&snapshot_msgpack) != expected_sha256 {
                if let Some(peer) = correlated_peer {
                    finish_v3_history_transfer(rt, peer, StrictCatchupSessionOutcome::Failed).await;
                }
                warn!(
                    from,
                    "strict v2 snapshot transfer SHA-256 verification failed"
                );
                rearm_history_election(rt);
                return;
            }
            install_snapshot_candidate_with_format(
                rt,
                from,
                rank,
                format,
                snapshot_version,
                Bytes::from(snapshot_msgpack),
                apply_started_at,
                correlated_peer,
                Some(resp.snapshot_transfer_id),
            )
            .await;
        }
        SnapshotReceiveOutcome::AmbiguousLegacy { transfer_id } => {
            metrics::record_strict_snapshot_receive_event(
                StrictSnapshotReceiveEvent::AmbiguousLegacy,
            );
            if let Some(peer) = correlated_peer {
                finish_v3_history_transfer(rt, peer, StrictCatchupSessionOutcome::Failed).await;
            }
            rearm_history_election_if_fetching_from(rt, from);
            warn!(
                from,
                transfer_id,
                "strict legacy snapshot has an ambiguous untagged representation; retaining quarantine and rearming history election"
            );
        }
        SnapshotReceiveOutcome::Duplicate => {
            metrics::record_strict_snapshot_receive_event(
                StrictSnapshotReceiveEvent::DuplicateActive,
            );
            trace!(
                topic = %rt.topic,
                from,
                transfer_id = resp.snapshot_transfer_id,
                chunk_cursor = resp.snapshot_chunk_cursor,
                "ignoring already-applied strict v2 snapshot chunk"
            );
            if let Some(peer) = correlated_peer {
                finish_v3_history_transfer(rt, peer, StrictCatchupSessionOutcome::Failed).await;
                let fetching_from_source = rt
                    .state
                    .lock()
                    .history_election_fetching_snapshot()
                    .is_some_and(|source| source.peer() == from);
                if fetching_from_source {
                    rt.snapshot_receivers.lock().remove(&from);
                    rearm_history_election_if_fetching_from(rt, from);
                }
            }
        }
        SnapshotReceiveOutcome::Stale(event) => {
            metrics::record_strict_snapshot_receive_event(event);
            warn!(
                topic = %rt.topic,
                from,
                reason = ?event,
                correlated_v3_history = correlated_peer.is_some(),
                transfer_id = resp.snapshot_transfer_id,
                chunk_cursor = resp.snapshot_chunk_cursor,
                next_cursor = resp.snapshot_next_cursor,
                total_bytes = resp.snapshot_total_bytes,
                chunk_bytes = resp.snapshot_msgpack.len(),
                snapshot_version = resp.snapshot_version,
                remote_repository_version = remote_rank.version,
                remote_freshness = remote_rank.freshness,
                terminal_decision_generation = resp.terminal_decision_generation,
                active_transfer_id = ?receiver_before.as_ref().map(|receiver| receiver.0),
                active_snapshot_version = ?receiver_before.as_ref().map(|receiver| receiver.1),
                active_next_cursor = ?receiver_before.as_ref().map(|receiver| receiver.2),
                active_total_bytes = ?receiver_before.as_ref().map(|receiver| receiver.3),
                active_terminal_decision_generation = ?receiver_before.as_ref().map(|receiver| receiver.4),
                active_snapshot_sha256 = ?receiver_before.as_ref().map(|receiver| &receiver.5),
                incoming_snapshot_sha256 = ?resp.snapshot_sha256,
                "ignoring stale strict v2 snapshot page"
            );
            if let Some(peer) = correlated_peer {
                finish_v3_history_transfer(rt, peer, StrictCatchupSessionOutcome::Failed).await;
                let fetching_from_source = rt
                    .state
                    .lock()
                    .history_election_fetching_snapshot()
                    .is_some_and(|source| source.peer() == from);
                if fetching_from_source {
                    rt.snapshot_receivers.lock().remove(&from);
                    rearm_history_election_if_fetching_from(rt, from);
                }
            }
            if event == StrictSnapshotReceiveEvent::StaleIdle
                && correlated_peer.is_none()
                && !resp.snapshot_has_more
                && resp.snapshot_next_cursor == resp.snapshot_total_bytes
                && rt.repo.current_version() >= resp.snapshot_version
            {
                metrics::record_strict_snapshot_receive_event(
                    StrictSnapshotReceiveEvent::CompletionRetried,
                );
                request_history_after_snapshot(
                    rt,
                    from,
                    resp.snapshot_version,
                    None,
                    Some(resp.snapshot_transfer_id),
                )
                .await;
            }
        }
        SnapshotReceiveOutcome::Restart(event) => {
            metrics::record_strict_snapshot_receive_event(event);
            if let Some(peer) = correlated_peer {
                finish_v3_history_transfer(rt, peer, StrictCatchupSessionOutcome::Failed).await;
            }
            rt.snapshot_receivers.lock().remove(&from);
            warn!(
                topic = %rt.topic,
                from,
                reason = ?event,
                correlated_v3_history = correlated_peer.is_some(),
                transfer_id = resp.snapshot_transfer_id,
                chunk_cursor = resp.snapshot_chunk_cursor,
                next_cursor = resp.snapshot_next_cursor,
                total_bytes = resp.snapshot_total_bytes,
                chunk_bytes = resp.snapshot_msgpack.len(),
                snapshot_version = resp.snapshot_version,
                remote_repository_version = remote_rank.version,
                remote_freshness = remote_rank.freshness,
                terminal_decision_generation = resp.terminal_decision_generation,
                active_transfer_id = ?receiver_before.as_ref().map(|receiver| receiver.0),
                active_snapshot_version = ?receiver_before.as_ref().map(|receiver| receiver.1),
                active_next_cursor = ?receiver_before.as_ref().map(|receiver| receiver.2),
                active_total_bytes = ?receiver_before.as_ref().map(|receiver| receiver.3),
                active_terminal_decision_generation = ?receiver_before.as_ref().map(|receiver| receiver.4),
                active_snapshot_sha256 = ?receiver_before.as_ref().map(|receiver| &receiver.5),
                incoming_snapshot_sha256 = ?resp.snapshot_sha256,
                "strict v2 snapshot page validation failed"
            );
            let (fetching_from_source, election_active) = {
                let state = rt.state.lock();
                (
                    state
                        .history_election_fetching_snapshot()
                        .is_some_and(|source| source.peer() == from),
                    state.history_election_active(),
                )
            };
            if fetching_from_source {
                rearm_history_election_if_fetching_from(rt, from);
            } else if !election_active
                && (receiver_before.is_some() || !resp.request_force_snapshot)
            {
                rearm_history_election(rt);
            }
        }
    }
}

/// Apply an inbound `StrictCatchupResp`. Installs the snapshot if
/// requested, then applies each op in order via `apply_committed`. If
/// `has_more`, continues pagination with the same validated peer. Returns
/// history metadata only when a metadata-only response is fully accepted.
pub(crate) async fn apply_response<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    resp: StrictCatchupResp,
) -> Option<HistoryMetadata> {
    let apply_started_at = std::time::Instant::now();
    let v3_peer = rt
        .net
        .member_boot_epoch(from)
        .filter(|_| rt.v3_repair_supported_by(from))
        .map(|epoch| PeerIncarnation::new(from, epoch));
    if is_v3_history_final_ack_confirmation(&resp) {
        let confirmed = match (&resp.history_transfer, v3_peer) {
            (Some(confirmation), Some(peer)) => {
                rt.v3_retries
                    .lock()
                    .complete_history_final_ack(peer, confirmation, rt.boot_epoch)
            }
            _ => false,
        };
        if confirmed {
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Strict,
                ReplicationPipelineStage::CatchupApply,
                apply_started_at.elapsed(),
            );
            return None;
        }
    }
    let correlated_v3_history = match (&resp.history_transfer, v3_peer) {
        (Some(transfer), Some(peer)) => {
            if !rt
                .v3_history
                .lock()
                .claim_response(peer, transfer, rt.boot_epoch)
            {
                metrics::record_strict_catchup_duplicate(StrictCatchupDuplicateOutcome::Suppressed);
                return None;
            }
            rt.v3_retries
                .lock()
                .complete_history_request(peer, transfer.request_nonce);
            Some(peer)
        }
        (Some(_), _) => return None,
        (None, Some(peer)) if rt.v3_history.lock().expects_response(peer) => return None,
        (None, _) => None,
    };
    let Some(remote_node) = super::runtime::node_from_u32(resp.history_node) else {
        warn!(
            node = resp.history_node,
            "strict catchup response has invalid history_node"
        );
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::CatchupApply,
            apply_started_at.elapsed(),
        );
        fail_claimed_v3_history_response(rt, correlated_v3_history).await;
        return None;
    };
    if remote_node != from {
        warn!(
            from,
            claimed = remote_node,
            "strict catchup response origin mismatch"
        );
        fail_claimed_v3_history_response(rt, correlated_v3_history).await;
        return None;
    }
    let v2_terminal_catchup = rt.can_respond_to_v2_terminal_catchup(from);
    if resp.terminal_sync_only
        && v2_terminal_catchup
        && (resp.next_terminal_state_cursor == 0
            || resp.next_terminal_state_cursor == TERMINAL_STATE_CURSOR_SKIP)
    {
        warn!(
            from,
            next_terminal_state_cursor = resp.next_terminal_state_cursor,
            "strict terminal catchup response has invalid cursor progress"
        );
        fail_claimed_v3_history_response(rt, correlated_v3_history).await;
        return None;
    }
    let inferred_legacy_repository_base = (correlated_v3_history.is_none()
        && rt.net.peer_strict_replication_protocol_version(from) >= STRICT_PROTOCOL_VERSION_V5
        && rt.repo.current_version() < resp.history_version
        && resp.terminal_states.iter().any(|terminal| {
            matches!(
                terminal.outcome.as_ref(),
                Some(StrictTerminalOutcome::Commit(_))
            )
        }))
    .then_some(resp.history_version);
    // Install terminal fences only after authenticating the response origin,
    // but before considering ordinary history. A joining replica must not
    // revive a delayed v1 proposal while replaying validated catchup.
    for terminal in resp.terminal_states.clone() {
        let terminal_is_commit = matches!(
            terminal.outcome.as_ref(),
            Some(StrictTerminalOutcome::Commit(_))
        );
        let installed = if let Some(required_version) =
            inferred_legacy_repository_base.filter(|_| terminal_is_commit)
        {
            // Pre-field V5 peers cannot advertise the exact repository base.
            // Persist the conservative head requirement atomically with the
            // imported commit before raising the in-memory delivery fence.
            rt.apply_catchup_terminal_commit_with_repository_base(terminal, required_version)
                .await
        } else {
            rt.apply_catchup_terminal_state(terminal).await
        };
        if !installed {
            metrics::record_strict_fence_rejection();
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Strict,
                ReplicationPipelineStage::CatchupApply,
                apply_started_at.elapsed(),
            );
            fail_claimed_v3_history_response(rt, correlated_v3_history).await;
            return None;
        }
    }
    // A v2 source supplies a persisted generation for its stable terminal
    // fence cut. Retain it only after every page in that cut has installed;
    // later steady-state catchup echoes it so a source restart or new fence
    // forces terminal pagination instead of trusting a cursor-only skip.
    if resp.terminal_sync_only {
        let terminal_page_acceptance = if v2_terminal_catchup {
            rt.accept_terminal_catchup_page(
                from,
                resp.terminal_decision_generation,
                resp.next_terminal_state_cursor,
                !resp.terminal_states_has_more,
            )
        } else {
            None
        };
        if v2_terminal_catchup && terminal_page_acceptance.is_none() {
            metrics::record_strict_catchup_duplicate(StrictCatchupDuplicateOutcome::Suppressed);
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Strict,
                ReplicationPipelineStage::CatchupApply,
                apply_started_at.elapsed(),
            );
            fail_claimed_v3_history_response(rt, correlated_v3_history).await;
            return None;
        }
        if v2_terminal_catchup && !resp.terminal_states_has_more {
            rt.remember_terminal_decision_generation(from, resp.terminal_decision_generation);
        }
        // A changed terminal-fence cut invalidates every partial image. The
        // next history request will start a new immutable transfer only after
        // all pages of the new cut are installed.
        rt.snapshot_receivers.lock().remove(&from);
        let mut continuation_sent = false;
        if from != rt.self_id
            && rt.net.has_route(from, ServiceLevel::Reliable)
            && v2_terminal_catchup
        {
            let req = StrictCatchupReq {
                src_node: rt.self_id as u32,
                since_version: resp.next_chunk_token,
                chunk_token: resp.next_chunk_token,
                force_snapshot: resp.request_force_snapshot,
                history_probe_only: resp.request_history_probe_only,
                terminal_state_cursor: if resp.terminal_states_has_more {
                    resp.next_terminal_state_cursor
                } else {
                    TERMINAL_STATE_CURSOR_SKIP
                },
                terminal_decision_generation: rt.remembered_terminal_decision_generation(from),
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
                history_transfer: None,
            };
            metrics::record_catchup_request(CatchupMode::Strict);
            continuation_sent = rt
                .net
                // Terminal pagination is a control-plane prerequisite for
                // both admission metadata and ordinary history. A lost final
                // continuation otherwise leaves clock evidence present but
                // history evidence permanently absent until another full
                // generation replay.
                .send_redundant_unicast(from, &rt.topic, StrictBody::CatchupReq(req))
                .await
                .is_ok();
        }
        if !continuation_sent {
            if let Some(acceptance) = terminal_page_acceptance {
                rt.rollback_terminal_catchup_page(acceptance);
            }
        }
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::CatchupApply,
            apply_started_at.elapsed(),
        );
        fail_claimed_v3_history_response(rt, correlated_v3_history).await;
        return None;
    }
    if v2_terminal_catchup {
        rt.remember_terminal_decision_generation(from, resp.terminal_decision_generation);
    }
    let remote_rank = HistoryRank {
        version: resp.history_version,
        freshness: resp.history_freshness,
        runtime_started_at: resp.runtime_started_at,
        node_id: remote_node,
        terminal_repository_base_version: 0,
    };
    if let Some(peer) = correlated_v3_history.filter(|_| {
        resp.too_old_use_snapshot
            && !resp.request_force_snapshot
            && (resp.snapshot_transfer_rejected || resp.snapshot_transfer_id != 0)
    }) {
        // Incremental admission and repository-gap transfers do not carry a
        // ranked snapshot authorization. A compacted source may fall back to
        // an image, but installing it directly would bypass history election.
        // End the doomed transfer at its first chunk and request a ranked
        // election when one is not already active, instead of downloading and
        // rejecting the same image forever.
        rt.snapshot_receivers.lock().remove(&from);
        finish_v3_history_transfer(rt, peer, StrictCatchupSessionOutcome::Failed).await;
        request_history_election_if_inactive(rt);
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::CatchupApply,
            apply_started_at.elapsed(),
        );
        return None;
    }
    if resp.snapshot_transfer_rejected || resp.snapshot_transfer_id != 0 {
        apply_snapshot_transfer_response(
            rt,
            from,
            &resp,
            remote_rank,
            apply_started_at,
            correlated_v3_history,
        )
        .await;
        return None;
    }
    if resp.snapshot_chunk_cursor != 0
        || resp.snapshot_next_cursor != 0
        || resp.snapshot_total_bytes != 0
        || !resp.snapshot_sha256.is_empty()
        || resp.snapshot_has_more
    {
        warn!(
            from,
            "strict catchup response has descriptor-less v2 snapshot-transfer fields"
        );
        if !fail_claimed_v3_history_response(rt, correlated_v3_history).await {
            rearm_history_election(rt);
        }
        return None;
    }
    let local_rank = HistoryRank::local(rt);
    let can_bootstrap = rt.state.lock().can_bootstrap_catchup();

    let metadata_only_response =
        !resp.too_old_use_snapshot && resp.snapshot_msgpack.is_empty() && resp.ops.is_empty();
    if metadata_only_response {
        if let Some(peer) = correlated_v3_history {
            finish_v3_history_transfer(rt, peer, StrictCatchupSessionOutcome::Completed).await;
            if resp.request_force_snapshot {
                rt.state.lock().finish_history_election();
            }
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Strict,
                ReplicationPipelineStage::CatchupApply,
                apply_started_at.elapsed(),
            );
            return None;
        }
        // Admission evidence is narrower than a generally processable empty
        // catch-up page. Require the canonical final history-probe shape so
        // contradictory pagination, terminal, or snapshot flags cannot be
        // interpreted as a convergence proof.
        let admission_metadata = (resp.snapshot_version == 0
            && !resp.has_more
            && resp.next_chunk_token == 0
            && resp.terminal_states.is_empty()
            && resp.next_terminal_state_cursor == TERMINAL_STATE_CURSOR_SKIP
            && !resp.terminal_states_has_more
            && !resp.terminal_sync_only
            && !resp.request_force_snapshot
            && resp.request_history_probe_only)
            .then_some(HistoryMetadata {
                version: remote_rank.version,
                freshness: remote_rank.freshness,
            });
        let local_metadata = rt.repo.history_metadata();
        let remote_history_ahead = remote_rank.version > local_metadata.version;
        let equal_version_metadata_diverged = !can_bootstrap
            && remote_rank.version == local_metadata.version
            && remote_rank.freshness != local_metadata.freshness;
        if remote_history_ahead {
            // Admission probes run at the bootstrap retry cadence. When a
            // temporarily excluded replica discovers that an admitted peer
            // is ahead, immediately enter the normal history election rather
            // than waiting for the 30-second steady-state anti-entropy loop.
            let mut state = rt.state.lock();
            if !state.history_election_blocks_steady_state() {
                state.request_history_election();
            }
            drop(state);
            rt.wake_clock_tick_loop();
        }
        if equal_version_metadata_diverged {
            warn!(
                from,
                version = remote_rank.version,
                local_freshness = local_metadata.freshness,
                remote_freshness = remote_rank.freshness,
                "strict anti-entropy found equal-version history metadata divergence"
            );
            rt.state.lock().request_history_election();
            rt.wake_clock_tick_loop();
            // The envelope is valid even though it disproves freshness.
            // Return the metadata so the admission state can clear any
            // previously observed history proof for this incarnation.
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Strict,
                ReplicationPipelineStage::CatchupApply,
                apply_started_at.elapsed(),
            );
            return admission_metadata;
        }
        let outcome =
            rt.state
                .lock()
                .record_history_probe_response(remote_node, remote_rank, local_rank);
        if !outcome.is_ignored() {
            if let HistoryProbeResponseOutcome::FetchSnapshot(request) = outcome {
                if let Err(e) = rt.send_history_snapshot_request(request).await {
                    warn!(
                        dst = request.peer(),
                        error = %e,
                        "strict catchup winning snapshot request failed"
                    );
                    rt.state.lock().request_history_election();
                }
            }
        }
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::CatchupApply,
            apply_started_at.elapsed(),
        );
        return admission_metadata;
    }

    if resp.too_old_use_snapshot {
        if resp.snapshot_version != remote_rank.version {
            warn!(
                from,
                snapshot_version = resp.snapshot_version,
                history_version = remote_rank.version,
                "strict catchup snapshot rank/version mismatch"
            );
            fail_claimed_v3_history_response(rt, correlated_v3_history).await;
            return None;
        }
        install_snapshot_candidate(
            rt,
            from,
            remote_rank,
            resp.snapshot_version,
            resp.snapshot_msgpack,
            apply_started_at,
            correlated_v3_history,
        )
        .await;
        return None;
    }

    if can_bootstrap && rt.repo.current_version() > 0 {
        if let Some(peer) = correlated_v3_history {
            // An incremental admission transfer can race a newly requested
            // history election. Its payload is intentionally inadmissible on
            // a nonempty repository, but retaining the client would suppress
            // all replacement probes until the long session TTL. Cancel it
            // and let the election select a fenced snapshot immediately.
            finish_v3_history_transfer(rt, peer, StrictCatchupSessionOutcome::Cancelled).await;
            rt.state.lock().request_history_election();
            rt.wake_clock_tick_loop();
        }
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::CatchupApply,
            apply_started_at.elapsed(),
        );
        return None;
    }

    if resp.ops.is_empty() {
        if let Some(peer) = correlated_v3_history {
            finish_v3_history_transfer(rt, peer, StrictCatchupSessionOutcome::Completed).await;
            if resp.request_force_snapshot {
                rt.state.lock().finish_history_election();
            }
        }
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::CatchupApply,
            apply_started_at.elapsed(),
        );
        return None;
    }

    for cop in resp.ops {
        // Dedup: skip ops we've already applied. This protects against
        // overlapping responses when two bootstrap requests are in
        // flight (e.g., the periodic retry loop fired again before the
        // first response arrived, or a `Joined` event-driven retry
        // raced with the periodic loop).
        if cop.version <= rt.repo.current_version() {
            continue;
        }
        let decode_started_at = std::time::Instant::now();
        let op: R::Op = match rmp_serde::from_slice(&cop.op_msgpack) {
            Ok(o) => o,
            Err(e) => {
                metrics::record_pipeline_stage(
                    ReplicationPipelineKind::Strict,
                    ReplicationPipelineStage::MsgpackDecode,
                    decode_started_at.elapsed(),
                );
                warn!(error=%e, "catchup op decode failed; aborting chunk");
                metrics::record_pipeline_stage(
                    ReplicationPipelineKind::Strict,
                    ReplicationPipelineStage::CatchupApply,
                    apply_started_at.elapsed(),
                );
                fail_claimed_v3_history_response(rt, correlated_v3_history).await;
                return None;
            }
        };
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::MsgpackDecode,
            decode_started_at.elapsed(),
        );
        if let Some(metadata) = match strict_metadata(&cop) {
            Ok(metadata) => metadata,
            Err(()) => {
                metrics::record_strict_fence_rejection();
                metrics::record_pipeline_stage(
                    ReplicationPipelineKind::Strict,
                    ReplicationPipelineStage::CatchupApply,
                    apply_started_at.elapsed(),
                );
                fail_claimed_v3_history_response(rt, correlated_v3_history).await;
                return None;
            }
        } {
            let encode_started_at = std::time::Instant::now();
            let op_msgpack = match rmp_serde::to_vec(&op) {
                Ok(bytes) => Bytes::from(bytes),
                Err(e) => {
                    metrics::record_pipeline_stage(
                        ReplicationPipelineKind::Strict,
                        ReplicationPipelineStage::MsgpackEncode,
                        encode_started_at.elapsed(),
                    );
                    warn!(error=%e, "catchup op re-encode failed; aborting chunk");
                    metrics::record_pipeline_stage(
                        ReplicationPipelineKind::Strict,
                        ReplicationPipelineStage::CatchupApply,
                        apply_started_at.elapsed(),
                    );
                    fail_claimed_v3_history_response(rt, correlated_v3_history).await;
                    return None;
                }
            };
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Strict,
                ReplicationPipelineStage::MsgpackEncode,
                encode_started_at.elapsed(),
            );
            let op_id = (metadata.metadata.op_id_hi, metadata.metadata.op_id_lo);
            if let Some(proof) = metadata.terminal_proof {
                if !rt
                    .apply_catchup_terminal_commit_proof(
                        op_id,
                        metadata.metadata.ts_final,
                        op_msgpack,
                        proof,
                    )
                    .await
                {
                    metrics::record_strict_fence_rejection();
                    metrics::record_pipeline_stage(
                        ReplicationPipelineKind::Strict,
                        ReplicationPipelineStage::CatchupApply,
                        apply_started_at.elapsed(),
                    );
                    fail_claimed_v3_history_response(rt, correlated_v3_history).await;
                    return None;
                }
                continue;
            }
            if rt.has_v2_terminal_descriptor(op_id).await {
                metrics::record_strict_fence_rejection();
                if rt.has_unresolved_v2_terminal_fence(op_id).await {
                    rt.defer_descriptorless_v2_commit(op_id).await;
                }
                metrics::record_pipeline_stage(
                    ReplicationPipelineKind::Strict,
                    ReplicationPipelineStage::CatchupApply,
                    apply_started_at.elapsed(),
                );
                fail_claimed_v3_history_response(rt, correlated_v3_history).await;
                return None;
            }
            {
                let mut state = rt.state.lock();
                if state.ordinary_commit_is_fenced(op_id) {
                    metrics::record_strict_fence_rejection();
                    continue;
                }
                // Catchup can replay a commit whose final timestamp is far
                // ahead of a restarted replica's in-memory Tempo clock. Keep
                // the local clock and its peer-clock slot in sync before the
                // committed-id dedup check so a duplicate response can still
                // repair stale clock state.
                state.clock = state.clock.max(metadata.metadata.ts_final);
                let clock = state.clock;
                state.peer_clocks.insert(rt.self_id, clock);
                if state.mark_committed(op_id, metadata.metadata.ts_final) {
                    state.buffer_commit(op_id, metadata.metadata.ts_final, op_msgpack);
                }
            }
            // The clock-tick loop supplies the next tick needed to move the
            // delivery watermark past ts_final. Wake both loops even when
            // the catchup commit was already known.
            rt.wake_delivery_and_clock_tick();
        } else if can_bootstrap {
            let repo_apply_started_at = std::time::Instant::now();
            rt.repo.apply_committed(cop.version, op).await;
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Strict,
                ReplicationPipelineStage::RepoApply,
                repo_apply_started_at.elapsed(),
            );
        }
    }
    if resp.has_more {
        if from == rt.self_id
            || !rt.net.has_route(from, ServiceLevel::Reliable)
            || !rt.can_respond_to_v2_terminal_catchup(from)
        {
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Strict,
                ReplicationPipelineStage::CatchupApply,
                apply_started_at.elapsed(),
            );
            fail_claimed_v3_history_response(rt, correlated_v3_history).await;
            return None;
        }
        let history_transfer = correlated_v3_history.and_then(|peer| {
            rt.v3_history
                .lock()
                .continue_transfer(peer, resp.next_chunk_token)
        });
        if correlated_v3_history.is_some() && history_transfer.is_none() {
            fail_claimed_v3_history_response(rt, correlated_v3_history).await;
            return None;
        }
        let req = StrictCatchupReq {
            src_node: rt.self_id as u32,
            since_version: resp.next_chunk_token,
            chunk_token: resp.next_chunk_token,
            force_snapshot: false,
            history_probe_only: false,
            terminal_state_cursor: resp.next_terminal_state_cursor,
            terminal_decision_generation: rt.remembered_terminal_decision_generation(from),
            snapshot_transfer_id: 0,
            snapshot_chunk_cursor: 0,
            history_transfer,
        };
        if correlated_v3_history.is_some() {
            let _ = send_v3_history_request(rt, from, req).await;
        } else {
            metrics::record_catchup_request(CatchupMode::Strict);
            let _ = rt
                .net
                .send_unicast(from, &rt.topic, StrictBody::CatchupReq(req))
                .await;
        }
    } else if let Some(peer) = correlated_v3_history {
        finish_v3_history_transfer(rt, peer, StrictCatchupSessionOutcome::Completed).await;
        if resp.request_force_snapshot {
            rt.state.lock().finish_history_election();
        }
    }
    metrics::record_pipeline_stage(
        ReplicationPipelineKind::Strict,
        ReplicationPipelineStage::CatchupApply,
        apply_started_at.elapsed(),
    );
    None
}

// ---------- Pairwise repair v3 ----------

/// Send bounded v3 metadata on the route-diverse control lane. Validation is
/// deliberately performed before invoking the transport so alternate/test
/// implementations cannot observe or enqueue an oversized control frame.
pub(super) async fn send_v3_metadata_control<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    dst: NodeIdentifier,
    body: StrictBody,
    reason: CatchupReason,
    phase: CatchupPhase,
) -> Result<(), ReplicationError> {
    send_v3_metadata_control_inner(rt, dst, body, reason, phase, true).await
}

/// Enqueue an already-existing logical control message. Retry callers use
/// this path so only the physical attempt counters grow when the same nonce
/// or final-ACK identity is retransmitted.
async fn retry_v3_metadata_control<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    dst: NodeIdentifier,
    body: StrictBody,
    reason: CatchupReason,
    phase: CatchupPhase,
) -> Result<(), ReplicationError> {
    send_v3_metadata_control_inner(rt, dst, body, reason, phase, false).await
}

async fn send_v3_metadata_control_inner<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    dst: NodeIdentifier,
    body: StrictBody,
    reason: CatchupReason,
    phase: CatchupPhase,
    record_logical: bool,
) -> Result<(), ReplicationError> {
    let encoded_len = match validate_v3_metadata_control(rt.net.as_ref(), &rt.topic, &body) {
        Ok(encoded_len) => encoded_len,
        Err(error) => {
            warn!(dst, topic = %rt.topic, %error, "rejecting strict v3 control frame");
            return Err(error);
        }
    };
    match (record_logical, &body) {
        (
            true,
            StrictBody::ClockProbeReq(_)
            | StrictBody::HistoryProbeReq(_)
            | StrictBody::TerminalSyncReq(_),
        ) => {
            metrics::record_catchup_request_detail(CatchupMode::Strict, reason, phase);
        }
        (
            true,
            StrictBody::ClockProbeResp(_)
            | StrictBody::HistoryProbeResp(_)
            | StrictBody::TerminalSyncAck(_)
            | StrictBody::CatchupResp(_),
        ) => {
            metrics::record_catchup_response_detail(
                CatchupMode::Strict,
                reason,
                phase,
                0,
                encoded_len,
            );
        }
        _ => {}
    }
    rt.net
        .send_redundant_catchup_unicast(dst, &rt.topic, body, reason, phase)
        .await
}

fn v3_peer<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    node: NodeIdentifier,
    boot_epoch: u64,
) -> Option<PeerIncarnation> {
    (rt.v3_repair_supported_by(node) && rt.net.member_boot_epoch(node) == Some(boot_epoch))
        .then_some(PeerIncarnation::new(node, boot_epoch))
}

pub(super) async fn request_v3_clock_probe<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    dst: NodeIdentifier,
    reason: StrictCatchupReason,
) -> bool {
    let metric_reason =
        CatchupReason::from_v3_wire(reason as i32).unwrap_or(CatchupReason::DeliveryWatermark);
    let Some(epoch) = rt.net.member_boot_epoch(dst) else {
        metrics::record_strict_probe_event(
            StrictProbeKind::Clock,
            metric_reason,
            StrictProbeOutcome::RejectedPeer,
        );
        return false;
    };
    if !rt.v3_repair_supported_by(dst) {
        metrics::record_strict_probe_event(
            StrictProbeKind::Clock,
            metric_reason,
            StrictProbeOutcome::RejectedPeer,
        );
        return false;
    }
    let Some(nonce) = rt.v3_sync.lock().record_clock_nonce(
        PeerIncarnation::new(dst, epoch),
        rt.cfg.pending_propose_ttl(),
    ) else {
        metrics::record_strict_probe_event(
            StrictProbeKind::Clock,
            metric_reason,
            StrictProbeOutcome::Coalesced,
        );
        return false;
    };
    let peer = PeerIncarnation::new(dst, epoch);
    let request = StrictClockProbeReq {
        src_node: rt.self_id as u32,
        expected_responder_boot_epoch: epoch,
        request_nonce: nonce,
        reason: reason as i32,
        requester_clock: rt.v3_clock_probe_requester_clock(),
    };
    if !register_v3_clock_probe_retry_if_current(rt, peer, request.clone()) {
        metrics::record_strict_probe_event(
            StrictProbeKind::Clock,
            metric_reason,
            StrictProbeOutcome::IgnoredNonce,
        );
        return false;
    }
    let sent = send_v3_metadata_control(
        rt,
        dst,
        StrictBody::ClockProbeReq(request),
        metric_reason,
        CatchupPhase::Metadata,
    )
    .await
    .is_ok();
    if sent {
        metrics::record_strict_probe_event(
            StrictProbeKind::Clock,
            metric_reason,
            StrictProbeOutcome::Sent,
        );
    }
    sent
}

pub(super) fn register_v3_clock_probe_retry_if_current<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    peer: PeerIncarnation,
    request: StrictClockProbeReq,
) -> bool {
    // Cross-map ownership always locks retries before sync. A response uses
    // the same order, so nonce acceptance cannot land between this current
    // check and retry registration.
    let mut retries = rt.v3_retries.lock();
    let sync = rt.v3_sync.lock();
    if !sync.clock_nonce_is_current(peer, request.request_nonce) {
        return false;
    }
    retries.register_clock_probe(
        peer,
        request,
        rt.cfg.bulk_retry_delay(),
        rt.cfg.pending_propose_ttl(),
        rt.cfg.strict_bulk_retry_jitter_pct(),
        v3_retry_salt(rt.self_id, &rt.topic),
    );
    true
}

pub(super) async fn recv_v3_clock_probe_req<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    req: StrictClockProbeReq,
) {
    let Some(reason) = CatchupReason::from_v3_wire(req.reason) else {
        return;
    };
    let Some(peer) = v3_peer(rt, from, epoch) else {
        return;
    };
    if node_from_u32(req.src_node) != Some(from)
        || req.expected_responder_boot_epoch != rt.boot_epoch
        || req.request_nonce == 0
    {
        return;
    }
    let cached_response = {
        rt.v3_sync.lock().cached_clock_probe_response(
            peer,
            req.request_nonce,
            rt.cfg.pending_propose_ttl(),
        )
    };
    if let Some(response) = cached_response {
        let _ = send_v3_metadata_control(
            rt,
            from,
            StrictBody::ClockProbeResp(response),
            reason,
            CatchupPhase::Metadata,
        )
        .await;
        return;
    }
    let response = StrictClockProbeResp {
        responder_node: rt.self_id as u32,
        expected_requester_boot_epoch: epoch,
        request_nonce: req.request_nonce,
        src_clock: rt.advance_v3_clock_probe(from, epoch, req.requester_clock),
        reason: req.reason,
    };
    rt.v3_sync.lock().remember_clock_probe_response(
        peer,
        response.clone(),
        rt.cfg.pending_propose_ttl(),
    );
    let _ = send_v3_metadata_control(
        rt,
        from,
        StrictBody::ClockProbeResp(response),
        reason,
        CatchupPhase::Metadata,
    )
    .await;
}

pub(super) fn recv_v3_clock_probe_resp<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    resp: StrictClockProbeResp,
) {
    let metric_reason =
        CatchupReason::from_v3_wire(resp.reason).unwrap_or(CatchupReason::DeliveryWatermark);
    let Some(peer) = v3_peer(rt, from, epoch) else {
        metrics::record_strict_probe_event(
            StrictProbeKind::Clock,
            metric_reason,
            StrictProbeOutcome::RejectedPeer,
        );
        debug!(
            topic = %rt.topic,
            peer = from,
            peer_boot_epoch = epoch,
            request_nonce = resp.request_nonce,
            reason = ?StrictCatchupReason::try_from(resp.reason).ok(),
            rejection = "peer",
            "strict clock probe response rejected"
        );
        return;
    };
    if node_from_u32(resp.responder_node) != Some(from)
        || resp.expected_requester_boot_epoch != rt.boot_epoch
        || CatchupReason::from_v3_wire(resp.reason).is_none()
    {
        metrics::record_strict_probe_event(
            StrictProbeKind::Clock,
            metric_reason,
            StrictProbeOutcome::RejectedEnvelope,
        );
        debug!(
            topic = %rt.topic,
            peer = from,
            peer_boot_epoch = epoch,
            request_nonce = resp.request_nonce,
            responder_node = resp.responder_node,
            expected_requester_boot_epoch = resp.expected_requester_boot_epoch,
            reason = ?StrictCatchupReason::try_from(resp.reason).ok(),
            rejection = "envelope",
            "strict clock probe response rejected"
        );
        return;
    }
    let accepted = {
        let mut retries = rt.v3_retries.lock();
        let accepted = rt
            .v3_sync
            .lock()
            .accept_clock_nonce(peer, resp.request_nonce);
        if accepted {
            retries.complete_clock_probe(peer, resp.request_nonce);
        }
        accepted
    };
    if !accepted {
        metrics::record_strict_probe_event(
            StrictProbeKind::Clock,
            metric_reason,
            StrictProbeOutcome::IgnoredNonce,
        );
        trace!(
            topic = %rt.topic,
            peer = from,
            peer_boot_epoch = epoch,
            request_nonce = resp.request_nonce,
            reason = ?StrictCatchupReason::try_from(resp.reason).ok(),
            rejection = "nonce_not_current",
            "strict clock probe response ignored"
        );
        return;
    }
    metrics::record_strict_probe_event(
        StrictProbeKind::Clock,
        metric_reason,
        StrictProbeOutcome::Accepted,
    );
    trace!(
        topic = %rt.topic,
        peer = from,
        peer_boot_epoch = epoch,
        request_nonce = resp.request_nonce,
        reason = ?StrictCatchupReason::try_from(resp.reason).ok(),
        source_clock = resp.src_clock,
        "strict clock probe response accepted"
    );
    rt.accept_v3_clock_probe(from, epoch, resp.src_clock);
}

pub(super) struct PreparedHistoryProbe {
    dst: NodeIdentifier,
    body: StrictBody,
    reason: CatchupReason,
}

pub(super) fn register_v3_history_probe_retry_if_current<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    peer: PeerIncarnation,
    request: StrictHistoryProbeReq,
) -> bool {
    let mut retries = rt.v3_retries.lock();
    let sync = rt.v3_sync.lock();
    if !sync.history_nonce_is_current(peer, request.request_nonce)
        || retries.history_probe_nonce_is_scheduled(peer, request.request_nonce)
    {
        return false;
    }
    retries.register_history_probe(
        peer,
        request,
        rt.cfg.bulk_retry_delay(),
        rt.cfg.pending_propose_ttl(),
        rt.cfg.strict_bulk_retry_jitter_pct(),
        v3_retry_salt(rt.self_id, &rt.topic),
    );
    true
}

pub(super) fn prepare_v3_history_probe<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    dst: NodeIdentifier,
    reason: StrictCatchupReason,
) -> Option<PreparedHistoryProbe> {
    let metric_reason =
        CatchupReason::from_v3_wire(reason as i32).unwrap_or(CatchupReason::HistoryElection);
    let Some(epoch) = rt.net.member_boot_epoch(dst) else {
        metrics::record_strict_probe_event(
            StrictProbeKind::History,
            metric_reason,
            StrictProbeOutcome::RejectedPeer,
        );
        return None;
    };
    if !rt.v3_repair_supported_by(dst) {
        metrics::record_strict_probe_event(
            StrictProbeKind::History,
            metric_reason,
            StrictProbeOutcome::RejectedPeer,
        );
        return None;
    }
    let peer = PeerIncarnation::new(dst, epoch);
    let (nonce, promoted_existing) = {
        let mut sync = rt.v3_sync.lock();
        match sync.record_history_nonce(peer, reason as i32, rt.cfg.pending_propose_ttl()) {
            Some(nonce) => (nonce, false),
            None if matches!(
                reason,
                StrictCatchupReason::HistoryElection | StrictCatchupReason::Admission
            ) =>
            {
                let nonce = sync.current_history_nonce(peer)?;
                (nonce, true)
            }
            None => return None,
        }
    };
    if promoted_existing {
        metrics::record_strict_probe_event(
            StrictProbeKind::History,
            metric_reason,
            StrictProbeOutcome::Coalesced,
        );
        let mut retries = rt.v3_retries.lock();
        if retries.history_probe_nonce_is_scheduled(peer, nonce) {
            if reason == StrictCatchupReason::HistoryElection {
                // The retained admission retry may already be deep into its
                // exponential schedule. Pull that one owner forward so the
                // election's shorter probe watchdog cannot repeatedly close
                // before the promoted response is retried.
                retries.expedite_history_probe(peer, nonce, Instant::now());
            }
            trace!(
                topic = %rt.topic,
                peer = dst,
                peer_boot_epoch = epoch,
                request_nonce = nonce,
                reason = ?reason,
                "strict history probe coalesced with retained retry owner"
            );
            return None;
        }
    }
    // A retained nonce without its retry entry has no remaining transmission
    // owner. Reuse its identity, but restore one reason-labelled send/retry
    // instead of leaving election or admission permanently pending.
    let request = StrictHistoryProbeReq {
        src_node: rt.self_id as u32,
        expected_responder_boot_epoch: epoch,
        request_nonce: nonce,
        reason: reason as i32,
    };
    if !register_v3_history_probe_retry_if_current(rt, peer, request.clone()) {
        metrics::record_strict_probe_event(
            StrictProbeKind::History,
            metric_reason,
            StrictProbeOutcome::IgnoredNonce,
        );
        return None;
    }
    if promoted_existing {
        metrics::record_strict_probe_event(
            StrictProbeKind::History,
            metric_reason,
            StrictProbeOutcome::RetryRestored,
        );
        debug!(
            topic = %rt.topic,
            peer = dst,
            peer_boot_epoch = epoch,
            request_nonce = nonce,
            reason = ?reason,
            "strict history probe restored missing retry owner"
        );
    }
    Some(PreparedHistoryProbe {
        dst,
        body: StrictBody::HistoryProbeReq(request),
        reason: CatchupReason::from_v3_wire(reason as i32)
            .unwrap_or(CatchupReason::HistoryElection),
    })
}

pub(super) async fn send_prepared_v3_history_probe<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    prepared: PreparedHistoryProbe,
) {
    let reason = prepared.reason;
    if send_v3_metadata_control(
        rt,
        prepared.dst,
        prepared.body,
        reason,
        CatchupPhase::Metadata,
    )
    .await
    .is_ok()
    {
        metrics::record_strict_probe_event(
            StrictProbeKind::History,
            reason,
            StrictProbeOutcome::Sent,
        );
    }
}

pub(super) async fn request_v3_history_probe<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    dst: NodeIdentifier,
    reason: StrictCatchupReason,
) {
    let Some(prepared) = prepare_v3_history_probe(rt, dst, reason) else {
        return;
    };
    send_prepared_v3_history_probe(rt, prepared).await;
}

pub(super) async fn recv_v3_history_probe_req<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    req: StrictHistoryProbeReq,
) {
    let Some(metric_reason) = CatchupReason::from_v3_wire(req.reason) else {
        return;
    };
    if v3_peer(rt, from, epoch).is_none()
        || node_from_u32(req.src_node) != Some(from)
        || req.expected_responder_boot_epoch != rt.boot_epoch
        || req.request_nonce == 0
    {
        return;
    }
    let rank = rt.v3_history_rank();
    let (cut, terminal_repository_base_version) = {
        let journal = rt.terminal_journal.lock().await;
        (
            cut_to_wire(journal.terminal_cut()),
            journal.repository_replay_base_version(rank.version),
        )
    };
    let _ = send_v3_metadata_control(
        rt,
        from,
        StrictBody::HistoryProbeResp(StrictHistoryProbeResp {
            responder_node: rt.self_id as u32,
            expected_requester_boot_epoch: epoch,
            request_nonce: req.request_nonce,
            repository_version: rank.version,
            history_freshness: rank.freshness,
            runtime_started_at: rank.runtime_started_at,
            history_node: rank.node_id as u32,
            terminal_cut: Some(cut),
            reason: req.reason,
            terminal_repository_base_version,
        }),
        metric_reason,
        CatchupPhase::Metadata,
    )
    .await;
}

/// Admission is reciprocal: installing a peer's source cut locally does not
/// prove that the peer covers the terminal fences required by this node.
/// While this incarnation is awaiting history proof, only an advertised
/// terminal set equal to the current local set may satisfy that proof.
async fn accept_v3_history_metadata_if_admissible<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    peer: PeerIncarnation,
    rank: HistoryRank,
    advertised_cut: TerminalCut,
) {
    let awaits_admission_proof = rt
        .state
        .lock()
        .peer_incarnation_awaits_history_proof(peer.node(), peer.boot_epoch());
    if awaits_admission_proof
        && advertised_cut.terminal_set_digest()
            != rt
                .terminal_journal
                .lock()
                .await
                .terminal_cut()
                .terminal_set_digest()
    {
        metrics::record_strict_admission_event(StrictAdmissionEvent::HistoryProofTerminalMismatch);
        let local_cut = rt.terminal_journal.lock().await.terminal_cut();
        debug!(
            topic = %rt.topic,
            peer = peer.node(),
            peer_boot_epoch = peer.boot_epoch(),
            remote_repository_version = rank.version,
            remote_history_freshness = rank.freshness,
            remote_terminal_set_digest = ?advertised_cut.terminal_set_digest(),
            local_repository_version = rt.repo.current_version(),
            local_terminal_set_digest = ?local_cut.terminal_set_digest(),
            rejection = "terminal_set_digest",
            "strict admission history proof rejected"
        );
        return;
    }
    rt.accept_v3_history_metadata(peer.node(), peer.boot_epoch(), rank);
}

/// Preserve repair evidence independently from a concurrent history election.
/// The election may select another repository source, but it cannot erase a
/// divergent terminal tail or repository gap owned by this exact peer.
async fn preserve_v3_history_probe_obligation<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    peer: PeerIncarnation,
    rank: HistoryRank,
    source_cut: TerminalCut,
    reason: StrictCatchupReason,
) {
    let local_cut = rt.terminal_journal.lock().await.terminal_cut();
    let terminal_equal = source_cut.terminal_set_digest() == local_cut.terminal_set_digest();
    let source_known = rt
        .v3_sync
        .lock()
        .known_source_cut(peer)
        .is_some_and(|known| source_cut_covers(known, source_cut));
    if terminal_equal || source_known {
        rt.v3_sync.lock().remember_source_cut(peer, source_cut);
        // The same response still belongs to the active election. Its winner
        // owns repository history, so never launch a competing history client
        // from this side obligation. Only a divergent terminal tail is
        // independent enough to repair immediately.
        return;
    }
    rt.v3_history
        .lock()
        .defer_until_terminal(peer, rank, source_cut, reason);
    request_v3_terminal_sync_toward(rt, peer.node(), reason, Some(source_cut)).await;
}

pub(super) async fn recv_v3_history_probe_resp<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    resp: StrictHistoryProbeResp,
) {
    let wire_metric_reason =
        CatchupReason::from_v3_wire(resp.reason).unwrap_or(CatchupReason::HistoryElection);
    let Some(peer) = v3_peer(rt, from, epoch) else {
        metrics::record_strict_probe_event(
            StrictProbeKind::History,
            wire_metric_reason,
            StrictProbeOutcome::RejectedPeer,
        );
        debug!(
            topic = %rt.topic,
            peer = from,
            peer_boot_epoch = epoch,
            request_nonce = resp.request_nonce,
            reason = ?StrictCatchupReason::try_from(resp.reason).ok(),
            rejection = "peer",
            "strict history probe response rejected"
        );
        return;
    };
    let valid_cut = resp.terminal_cut.as_ref().and_then(cut_from_wire);
    if node_from_u32(resp.responder_node) != Some(from)
        || node_from_u32(resp.history_node) != Some(from)
        || resp.expected_requester_boot_epoch != rt.boot_epoch
        || valid_cut.is_none()
    {
        metrics::record_strict_probe_event(
            StrictProbeKind::History,
            wire_metric_reason,
            StrictProbeOutcome::RejectedEnvelope,
        );
        debug!(
            topic = %rt.topic,
            peer = from,
            peer_boot_epoch = epoch,
            request_nonce = resp.request_nonce,
            responder_node = resp.responder_node,
            history_node = resp.history_node,
            expected_requester_boot_epoch = resp.expected_requester_boot_epoch,
            reason = ?StrictCatchupReason::try_from(resp.reason).ok(),
            rejection = "envelope",
            "strict history probe response rejected"
        );
        return;
    }
    let accepted_probe = {
        let mut retries = rt.v3_retries.lock();
        let accepted_probe = rt
            .v3_sync
            .lock()
            .accept_history_nonce(peer, resp.request_nonce);
        if accepted_probe.is_some() {
            retries.complete_history_probe(peer, resp.request_nonce);
        }
        accepted_probe
    };
    let Some(accepted_probe) = accepted_probe else {
        metrics::record_strict_probe_event(
            StrictProbeKind::History,
            wire_metric_reason,
            StrictProbeOutcome::IgnoredNonce,
        );
        trace!(
            topic = %rt.topic,
            peer = from,
            peer_boot_epoch = epoch,
            request_nonce = resp.request_nonce,
            reason = ?StrictCatchupReason::try_from(resp.reason).ok(),
            rejection = "nonce_not_current",
            "strict history probe response ignored"
        );
        return;
    };
    let effective_reason = accepted_probe.reason();
    let effective_metric_reason =
        CatchupReason::from_v3_wire(effective_reason).unwrap_or(wire_metric_reason);
    let election_pending = accepted_probe.election_pending();
    let Some(mut reason) = StrictCatchupReason::try_from(effective_reason).ok() else {
        return;
    };
    if CatchupReason::from_v3_wire(effective_reason).is_none() {
        return;
    }
    // Admission may reuse a nonce that startup election promoted while the
    // response was in flight. If that election has already closed, feeding
    // the delayed response back into its collector only drops the proof. In
    // particular, a divergent terminal cut then never starts the correlated
    // terminal sync that admission requires. Treat the still-authenticated
    // response as admission metadata; a later election attempt will allocate
    // its own correlated probe if one is still requested.
    let delayed_election_admission = if reason == StrictCatchupReason::HistoryElection {
        let state = rt.state.lock();
        !state.history_election_blocks_steady_state()
            && state.peer_incarnation_awaits_history_proof(from, epoch)
    } else {
        false
    };
    if delayed_election_admission {
        reason = StrictCatchupReason::Admission;
    }
    let rank = HistoryRank {
        version: resp.repository_version,
        freshness: resp.history_freshness,
        runtime_started_at: resp.runtime_started_at,
        node_id: from,
        terminal_repository_base_version: resp.terminal_repository_base_version,
    };
    if rank.terminal_repository_base_version > rank.version {
        metrics::record_strict_probe_event(
            StrictProbeKind::History,
            effective_metric_reason,
            StrictProbeOutcome::RejectedPayload,
        );
        debug!(
            topic = %rt.topic,
            peer = from,
            peer_boot_epoch = epoch,
            request_nonce = resp.request_nonce,
            reason = ?reason,
            repository_version = rank.version,
            history_freshness = rank.freshness,
            terminal_repository_base_version = rank.terminal_repository_base_version,
            rejection = "terminal_repository_base_above_head",
            "strict history probe response rejected after nonce acceptance"
        );
        return;
    }
    let response_cut = valid_cut.expect("validated terminal cut");
    metrics::record_strict_probe_event(
        StrictProbeKind::History,
        effective_metric_reason,
        StrictProbeOutcome::Accepted,
    );
    trace!(
        topic = %rt.topic,
        peer = from,
        peer_boot_epoch = epoch,
        request_nonce = resp.request_nonce,
        wire_reason = ?StrictCatchupReason::try_from(resp.reason).ok(),
        effective_reason = ?reason,
        repository_version = rank.version,
        history_freshness = rank.freshness,
        runtime_started_at = rank.runtime_started_at,
        terminal_repository_base_version = rank.terminal_repository_base_version,
        terminal_journal_id = ?response_cut.journal_id(),
        terminal_generation = response_cut.generation(),
        terminal_set_digest = ?response_cut.terminal_set_digest(),
        "strict history probe response accepted"
    );
    let repair_reason = accepted_probe
        .repair_reason()
        .or_else(|| {
            (election_pending
                && !matches!(
                    reason,
                    StrictCatchupReason::HistoryElection | StrictCatchupReason::Admission
                ))
            .then_some(reason as i32)
        })
        .and_then(|value| StrictCatchupReason::try_from(value).ok());
    if let Some(repair_reason) = repair_reason {
        preserve_v3_history_probe_obligation(rt, peer, rank, response_cut, repair_reason).await;
    }
    let election_requested = reason == StrictCatchupReason::HistoryElection || election_pending;
    if election_requested {
        if accepted_probe.admission_pending() || reason == StrictCatchupReason::Admission {
            // Admission remains an independent reciprocal obligation even
            // while the same metadata response feeds the election collector.
            rt.v3_history
                .lock()
                .defer_admission(peer, rank, response_cut);
        }
        reason = StrictCatchupReason::HistoryElection;
    }
    if reason == StrictCatchupReason::HistoryElection {
        // Startup election and admission often overlap. Metadata from an
        // election candidate is also a valid admission proof only when its
        // terminal fence is already known complete locally. A divergent cut
        // remains metadata-only until the elected source is synchronized.
        accept_v3_history_metadata_if_admissible(rt, peer, rank, response_cut).await;
    }
    let (source_peer, rank, source_cut) = if reason == StrictCatchupReason::HistoryElection {
        let pending_source_authorized =
            if rt
                .pending_repository_image_install()
                .is_some_and(|pending| {
                    (rank.version, rank.freshness) == (pending.version, pending.freshness)
                })
            {
                let durable_pending_cut = rt.terminal_journal.lock().await.terminal_cut();
                // The durable marker names repository metadata while the journal
                // itself retains the terminal lineage that authorized that image.
                // A same-tuple image from another lineage is not interchangeable;
                // a later cut is usable only when it append-only covers the exact
                // durable pending cut.
                source_cut_covers(response_cut, durable_pending_cut)
            } else {
                // A newer elected repository image will first install its own
                // terminal checkpoint and atomically supersede the old durable
                // marker. It therefore does not borrow authority from the old
                // pending lineage.
                true
            };
        let Some(selected) =
            rt.record_v3_history_election_rank(peer, rank, response_cut, pending_source_authorized)
        else {
            return;
        };
        (selected.peer(), selected.rank(), selected.source_cut())
    } else {
        (peer, rank, response_cut)
    };
    if v3_peer(rt, source_peer.node(), source_peer.boot_epoch()).is_none() {
        if reason == StrictCatchupReason::HistoryElection {
            rt.state.lock().request_history_election();
        }
        return;
    }
    let source_node = source_peer.node();
    let local_cut = rt.terminal_journal.lock().await.terminal_cut();
    let terminal_equal = source_cut.terminal_set_digest() == local_cut.terminal_set_digest();
    let source_already_known = rt
        .v3_sync
        .lock()
        .known_source_cut(source_peer)
        .is_some_and(|known| source_cut_covers(known, source_cut));
    // A checkpoint resets generation to zero while retaining retired-origin
    // commitment in the terminal-set digest. Only digest equality or a
    // previously installed source cut can prove this terminal set complete.
    let source_satisfied = terminal_equal || source_already_known;
    let local_history = rt.repo.history_metadata();
    let repository_version = local_history.version;
    let freshness_replacement_needed = reason == StrictCatchupReason::HistoryElection
        && rank.version == local_history.version
        && rank.freshness > local_history.freshness;
    let checkpoint_replacement_needed = reason == StrictCatchupReason::HistoryElection
        && !terminal_equal
        && source_cut.journal_id() != local_cut.journal_id()
        && rank.version >= repository_version;
    let repository_base_required = rt.repository_base_required();
    let history_needed = rank.version > repository_version
        || freshness_replacement_needed
        || repository_base_required
        || checkpoint_replacement_needed;
    let next_action = if !source_satisfied {
        "terminal_sync"
    } else if history_needed {
        "repository_transfer"
    } else if reason == StrictCatchupReason::HistoryElection {
        "finish_election"
    } else {
        "accept_admission_metadata"
    };
    debug!(
        topic = %rt.topic,
        peer = source_peer.node(),
        peer_boot_epoch = source_peer.boot_epoch(),
        reason = ?reason,
        local_repository_version = local_history.version,
        local_history_freshness = local_history.freshness,
        remote_repository_version = rank.version,
        remote_history_freshness = rank.freshness,
        local_terminal_journal_id = ?local_cut.journal_id(),
        local_terminal_generation = local_cut.generation(),
        local_terminal_set_digest = ?local_cut.terminal_set_digest(),
        remote_terminal_journal_id = ?source_cut.journal_id(),
        remote_terminal_generation = source_cut.generation(),
        remote_terminal_set_digest = ?source_cut.terminal_set_digest(),
        terminal_equal,
        source_already_known,
        source_satisfied,
        freshness_replacement_needed,
        checkpoint_replacement_needed,
        repository_base_required,
        history_needed,
        next_action,
        "strict history probe convergence decision"
    );
    if checkpoint_replacement_needed {
        rt.require_repository_base(rank.version);
    }
    let terminal_repository_base_version =
        if rank.terminal_repository_base_version == 0 && history_needed {
            // Rolling compatibility with pre-field V5 peers: zero can mean either
            // an omitted field or an exact genesis base. The wire version cannot
            // distinguish them, and terminal generation counts aborts rather than
            // repository mutations, so conservatively require the advertised
            // repository head whenever history recovery is needed.
            rank.version
        } else {
            rank.terminal_repository_base_version
        };
    if reason == StrictCatchupReason::HistoryElection
        && history_needed
        && repository_version < terminal_repository_base_version
    {
        // Latch the prefix requirement before either terminal synchronization
        // or the already-satisfied fast path can start repository transfer.
        rt.require_repository_base(terminal_repository_base_version);
    }
    if source_satisfied {
        rt.v3_sync
            .lock()
            .remember_source_cut(source_peer, source_cut);
        if history_needed {
            rt.v3_history
                .lock()
                .defer_until_terminal(source_peer, rank, source_cut, reason);
            start_v3_repository_after_terminal(rt, source_peer, None).await;
            return;
        }
        accept_v3_history_metadata_if_admissible(rt, source_peer, rank, source_cut).await;
        if reason == StrictCatchupReason::HistoryElection {
            rt.state.lock().finish_history_election();
            // Election metadata can also own a retained admission proof. The
            // completed election just made the repository cut stable, so
            // freeze it and consume that side obligation immediately instead
            // of waiting for another bootstrap interval and proof pair.
            let _ = rt.reconcile_peer_admissions();
            resume_deferred_v3_admissions(rt).await;
        }
        return;
    }
    rt.v3_history
        .lock()
        .defer_until_terminal(source_peer, rank, source_cut, reason);
    request_v3_terminal_sync_toward(rt, source_node, reason, Some(source_cut)).await;
}

/// Resume admission evidence that shared a promoted history-election nonce.
/// This is called by the admission cadence only after the election is neither
/// requested nor active. At that point it follows the ordinary admission
/// sequence: validate the peer's terminal cut, then pull repository history
/// only when the retained rank proves that this node is behind.
pub(super) async fn resume_deferred_v3_admissions<R: StrictReplicable>(rt: &StrictRuntime<R>) {
    if rt.state.lock().history_election_blocks_steady_state() {
        return;
    }
    let deferred = rt.v3_history.lock().take_deferred_admissions();
    for (index, candidate) in deferred.iter().copied().enumerate() {
        if rt.state.lock().history_election_blocks_steady_state() {
            let mut history = rt.v3_history.lock();
            for pending in deferred[index..].iter().copied() {
                history.defer_admission(pending.peer(), pending.rank(), pending.source_cut());
            }
            return;
        }
        let peer = candidate.peer();
        if v3_peer(rt, peer.node(), peer.boot_epoch()).is_none() {
            continue;
        }
        let (awaits_local_cut, awaits_history_proof) = {
            let state = rt.state.lock();
            (
                state.peer_incarnation_awaits_local_admission_cut(peer.node(), peer.boot_epoch()),
                state.peer_incarnation_awaits_history_proof(peer.node(), peer.boot_epoch()),
            )
        };
        if awaits_local_cut {
            rt.v3_history
                .lock()
                .defer_admission(peer, candidate.rank(), candidate.source_cut());
            continue;
        }
        if !awaits_history_proof {
            // The incarnation was removed, was already admitted, or already
            // has its history proof. In each case this retained response is
            // stale and must not start another synchronization session.
            continue;
        }
        let rank = candidate.rank();
        let source_cut = candidate.source_cut();
        let local_cut = rt.terminal_journal.lock().await.terminal_cut();
        let terminal_equal = source_cut.terminal_set_digest() == local_cut.terminal_set_digest();
        let known_source_cut = rt.v3_sync.lock().known_source_cut(peer);
        let repository_version = rt.repo.current_version();
        if rank.version == repository_version
            && rank.terminal_repository_base_version == rank.version
            && admission_requires_elected_checkpoint(source_cut, local_cut, known_source_cut)
        {
            // The deferred response survived an election attempt that did
            // not converge. When its terminal lineage is checkpointed at the
            // already-equal repository head, replaying it as admission would
            // start the same unranked checkpoint transfer and fail forever.
            // A newer repository or a terminal suffix above an older base is
            // legitimate admission repair and must still run normally.
            request_history_election_if_inactive(rt);
            continue;
        }
        let source_known =
            known_source_cut.is_some_and(|known| source_cut_covers(known, source_cut));
        let terminal_satisfied = terminal_equal || source_known;
        let history_needed = rank.version > rt.repo.current_version();
        if terminal_satisfied {
            rt.v3_sync.lock().remember_source_cut(peer, source_cut);
            if history_needed {
                rt.v3_history.lock().defer_until_terminal(
                    peer,
                    rank,
                    source_cut,
                    StrictCatchupReason::Admission,
                );
                start_v3_repository_after_terminal(rt, peer, None).await;
                continue;
            }
            accept_v3_history_metadata_if_admissible(rt, peer, rank, source_cut).await;
            continue;
        }
        rt.v3_history.lock().defer_until_terminal(
            peer,
            rank,
            source_cut,
            StrictCatchupReason::Admission,
        );
        request_v3_terminal_sync_toward(
            rt,
            peer.node(),
            StrictCatchupReason::Admission,
            Some(source_cut),
        )
        .await;
    }
}

fn admission_requires_elected_checkpoint(
    source_cut: TerminalCut,
    local_cut: TerminalCut,
    known_source_cut: Option<TerminalCut>,
) -> bool {
    source_cut.journal_id() != local_cut.journal_id()
        && source_cut.terminal_set_digest() != local_cut.terminal_set_digest()
        && known_source_cut.is_none_or(|known| known.journal_id() != source_cut.journal_id())
}

async fn start_v3_repository_after_terminal<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    peer: PeerIncarnation,
    inherited_metric_reason: Option<StrictCatchupReason>,
) -> bool {
    let Some(intent) = rt.v3_history.lock().take_after_terminal(peer) else {
        return false;
    };
    let rank = intent.rank();
    let reason = intent.reason();
    let source_cut = intent.source_cut();
    let source_known = rt
        .v3_sync
        .lock()
        .known_source_cut(peer)
        .is_some_and(|known| source_cut_covers(known, source_cut));
    let staged_checkpoint_bound = reason == StrictCatchupReason::HistoryElection
        && rt
            .v3_sync
            .lock()
            .bind_staged_checkpoint_to_repository(peer, source_cut, rank.version);
    if !source_known && !staged_checkpoint_bound {
        // Repository history may only begin after the exact metadata source
        // cut has been durably validated or staged as the exact elected
        // replacement. A missing elected stage cannot be repaired by
        // consuming unrelated terminal progress; restart source selection.
        if reason == StrictCatchupReason::HistoryElection {
            rearm_history_election(rt);
        } else {
            rt.v3_history
                .lock()
                .defer_until_terminal(peer, rank, source_cut, reason);
        }
        return false;
    }
    accept_v3_history_metadata_if_admissible(rt, peer, rank, source_cut).await;
    // Repository application can progress while terminal metadata is checked.
    // Base transfer decisions must use the current post-await repository cut.
    let local_history = rt.repo.history_metadata();
    if staged_checkpoint_bound {
        rt.require_repository_base(rank.version);
    }
    let freshness_replacement_needed = reason == StrictCatchupReason::HistoryElection
        && rank.version == local_history.version
        && rank.freshness > local_history.freshness;
    let forced_repository_install = reason == StrictCatchupReason::HistoryElection
        && (staged_checkpoint_bound
            || rt.repository_base_required()
            || freshness_replacement_needed);
    if forced_repository_install
        && rt.net.peer_strict_replication_protocol_version(peer.node()) < STRICT_PROTOCOL_VERSION_V5
    {
        rearm_history_election(rt);
        return false;
    }
    if matches!(
        reason,
        StrictCatchupReason::TerminalFence | StrictCatchupReason::DeliveryWatermark
    ) || rank.version < local_history.version
        || (rank.version == local_history.version && !forced_repository_install)
    {
        if reason == StrictCatchupReason::HistoryElection {
            rt.state.lock().finish_history_election();
        }
        return false;
    }
    let force_snapshot = reason == StrictCatchupReason::HistoryElection;
    let cursor = if force_snapshot {
        0
    } else {
        local_history.version
    };
    let Some(started) = rt.v3_history.lock().begin_transfer(
        peer,
        rank.version,
        cursor,
        reason,
        rt.cfg.pending_propose_ttl(),
        inherited_metric_reason.is_some(),
        inherited_metric_reason.unwrap_or(reason),
    ) else {
        return false;
    };
    let (transfer, preempted_metric_reason) = started.into_parts();
    if let Some(preempted_metric_reason) = preempted_metric_reason {
        rt.v3_retries.lock().cancel_history_request(peer);
        let preempted_reason = CatchupReason::from_v3_wire(preempted_metric_reason as i32)
            .unwrap_or(CatchupReason::RepositoryGap);
        metrics::record_strict_catchup_session_completion(
            preempted_reason,
            StrictCatchupSessionOutcome::Cancelled,
        );
    }
    if inherited_metric_reason.is_none() {
        let metric_reason =
            CatchupReason::from_v3_wire(reason as i32).unwrap_or(CatchupReason::RepositoryGap);
        metrics::record_strict_catchup_session_start(metric_reason);
    }
    let req = StrictCatchupReq {
        src_node: rt.self_id as u32,
        since_version: local_history.version,
        chunk_token: if force_snapshot {
            HISTORY_ELECTION_SNAPSHOT_TOKEN
        } else {
            cursor
        },
        force_snapshot,
        history_probe_only: false,
        terminal_state_cursor: TERMINAL_STATE_CURSOR_SKIP,
        terminal_decision_generation: 0,
        snapshot_transfer_id: 0,
        snapshot_chunk_cursor: 0,
        history_transfer: Some(transfer),
    };
    if let Err(error) = send_v3_history_request(rt, peer.node(), req).await {
        warn!(peer = peer.node(), %error, "strict v3 history request enqueue failed; retry retained");
    }
    true
}

async fn finish_v3_history_transfer<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    peer: PeerIncarnation,
    outcome: StrictCatchupSessionOutcome,
) {
    let (mut finished, deferred) = {
        let mut history = rt.v3_history.lock();
        (
            history.finish_transfer(peer, rt.self_id),
            history.take_deferred_terminal_intent(peer),
        )
    };
    rt.v3_retries.lock().cancel_history_request(peer);
    let metric_reason = finished.as_ref().map(|finished| {
        CatchupReason::from_v3_wire(finished.metric_reason() as i32)
            .unwrap_or(CatchupReason::RepositoryGap)
    });
    if let Some(reason) = metric_reason {
        metrics::record_strict_catchup_session_completion(reason, outcome);
    }
    let final_ack = (outcome == StrictCatchupSessionOutcome::Completed)
        .then(|| {
            finished
                .as_mut()
                .and_then(|finished| finished.take_final_ack())
        })
        .flatten();
    if let Some(ack) = final_ack {
        if let Some(reason) = metric_reason {
            metrics::record_strict_catchup_session_event(
                reason,
                StrictCatchupSessionEvent::FinalAck,
            );
        }
        let _ = send_v3_history_request(rt, peer.node(), ack).await;
    }
    if let Some((reason, desired_cut)) = deferred {
        // Box the deferred edge because a failed history start can finish the
        // history transfer and immediately resume a coalesced terminal sync.
        Box::pin(request_v3_terminal_sync_toward(
            rt,
            peer.node(),
            reason,
            desired_cut,
        ))
        .await;
    }
}

pub(super) async fn request_v3_terminal_sync<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    dst: NodeIdentifier,
    reason: StrictCatchupReason,
) {
    request_v3_terminal_sync_toward(rt, dst, reason, None).await;
}

fn terminal_session_wire(
    epoch: u64,
    transfer_id: u64,
    nonce: u64,
    cursor: u64,
) -> Option<SessionWireIdentity> {
    Some(SessionWireIdentity::new(
        SessionPeerEpoch::new(epoch),
        SessionTransferId::new(transfer_id),
        SessionWireNonce::new(nonce)?,
        SessionCursor::new(SessionCursorKind::TerminalGeneration, cursor),
    ))
}

fn terminal_start_wire(effects: &[SessionEffect]) -> Option<SessionWireIdentity> {
    effects.iter().find_map(|effect| match effect {
        SessionEffect::StartSession {
            kind: SessionSyncKind::Terminal,
            wire,
        } => Some(*wire),
        _ => None,
    })
}

fn terminal_effect_wire<F>(effects: &[SessionEffect], predicate: F) -> Option<SessionWireIdentity>
where
    F: Fn(&SessionEffect) -> Option<SessionWireIdentity>,
{
    effects.iter().find_map(predicate)
}

fn cancel_covered_terminal_followup<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    peer: PeerIncarnation,
    epoch: u64,
    wire: SessionWireIdentity,
) {
    rt.v3_sync.lock().transition_session(
        peer,
        SessionEvent::TransferExpired {
            epoch: SessionPeerEpoch::new(epoch),
            wire,
        },
    );
}

fn fail_v3_terminal_checkpoint_client<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    peer: PeerIncarnation,
    epoch: u64,
    wire: SessionWireIdentity,
    request_nonce: u64,
) {
    let completed = {
        let mut sync = rt.v3_sync.lock();
        let effects = sync.transition_session(
            peer,
            SessionEvent::ApplyFailed {
                epoch: SessionPeerEpoch::new(epoch),
                wire,
            },
        );
        if !effects
            .iter()
            .any(|effect| matches!(effect, SessionEffect::CancelRetry { wire: failed } if *failed == wire))
        {
            return;
        }
        if let Some(dirty_wire) = terminal_start_wire(&effects) {
            sync.transition_session(
                peer,
                SessionEvent::TransferExpired {
                    epoch: SessionPeerEpoch::new(epoch),
                    wire: dirty_wire,
                },
            );
        }
        sync.finish_client(peer)
    };
    rt.v3_retries.lock().complete_request(peer, request_nonce);
    let Some(completed) = completed else {
        return;
    };
    // The merged operational reason can be promoted while this correlated
    // transfer is in flight. Recovery authority belongs to the immutable
    // reason that started the client, not a later coalesced trigger.
    let recovery_reason = StrictCatchupReason::try_from(completed.started_reason()).ok();
    let metric_reason = CatchupReason::from_v3_wire(completed.started_reason())
        .unwrap_or(CatchupReason::TerminalFence);
    metrics::record_strict_catchup_session_completion(
        metric_reason,
        StrictCatchupSessionOutcome::Failed,
    );
    if matches!(
        recovery_reason,
        Some(StrictCatchupReason::Admission | StrictCatchupReason::RepositoryGap)
    ) {
        request_history_election_if_inactive(rt);
    }
}

async fn fail_v3_terminal_apply<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    peer: PeerIncarnation,
    epoch: u64,
    wire: SessionWireIdentity,
    request_nonce: u64,
) {
    let (effects, completed) = {
        let mut sync = rt.v3_sync.lock();
        let effects = sync.transition_session(
            peer,
            SessionEvent::ApplyFailed {
                epoch: SessionPeerEpoch::new(epoch),
                wire,
            },
        );
        let completed = sync.finish_failed_client(peer);
        (effects, completed)
    };
    rt.v3_retries.lock().complete_request(peer, request_nonce);
    let Some(completed) = completed else {
        return;
    };
    let metric_reason = CatchupReason::from_v3_wire(completed.started_reason())
        .unwrap_or(CatchupReason::TerminalFence);
    metrics::record_strict_catchup_session_completion(
        metric_reason,
        StrictCatchupSessionOutcome::Failed,
    );
    if let Some(dirty_wire) = terminal_start_wire(&effects) {
        let reason = StrictCatchupReason::try_from(completed.reason())
            .ok()
            .unwrap_or(StrictCatchupReason::TerminalFence);
        start_reducer_owned_terminal_client(rt, peer, reason, completed.desired_cut(), dirty_wire)
            .await;
    }
}

fn record_terminal_send_result<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    peer: PeerIncarnation,
    wire: SessionWireIdentity,
    result: &Result<(), ReplicationError>,
) {
    let Some(event) = result.as_ref().err().map(|error| match error {
        ReplicationError::StrictBulkAdmissionBusy { .. } => {
            SessionEvent::SendBackpressured { wire }
        }
        ReplicationError::Overlay(error) if replication_bulk_backpressure(error) => {
            SessionEvent::SendBackpressured { wire }
        }
        _ => SessionEvent::MessageLost { wire },
    }) else {
        return;
    };
    // The retry identity was armed by the reducer when it selected the send.
    // This transition records the transport outcome without allocating a new
    // nonce, cursor, page, or transfer.
    rt.v3_sync.lock().transition_session(peer, event);
}

pub(super) async fn request_v3_terminal_sync_toward<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    dst: NodeIdentifier,
    reason: StrictCatchupReason,
    desired_cut: Option<TerminalCut>,
) {
    let Some(epoch) = rt.net.member_boot_epoch(dst) else {
        return;
    };
    if !rt.v3_repair_supported_by(dst) {
        return;
    }
    let peer = PeerIncarnation::new(dst, epoch);
    let metric_reason =
        CatchupReason::from_v3_wire(reason as i32).unwrap_or(CatchupReason::TerminalFence);
    let force_elected_checkpoint = if reason == StrictCatchupReason::HistoryElection {
        let local_cut = rt.terminal_journal.lock().await.terminal_cut();
        desired_cut.is_some_and(|desired| {
            desired.journal_id() != local_cut.journal_id()
                && desired.terminal_set_digest() != local_cut.terminal_set_digest()
        })
    } else {
        false
    };
    {
        let mut history = rt.v3_history.lock();
        if history.has_active_transfer(peer) {
            history.defer_terminal_sync_toward(peer, reason, desired_cut);
            metrics::record_strict_catchup_session_event(
                metric_reason,
                StrictCatchupSessionEvent::Coalesced,
            );
            return;
        }
    }
    if !force_elected_checkpoint
        && desired_cut.is_some_and(|desired| {
            rt.v3_sync
                .lock()
                .known_source_cut(peer)
                .is_some_and(|known| source_cut_covers(known, desired))
        })
    {
        start_v3_repository_after_terminal(rt, peer, None).await;
        return;
    }
    let wire = {
        let mut sync = rt.v3_sync.lock();
        if force_elected_checkpoint && !sync.force_checkpoint_from_zero(peer) {
            rearm_history_election(rt);
            return;
        }
        // The lifecycle reducer owns the request cursor, while the durable
        // source cut is validated and retained by the payload coordinator.
        // Align them before every new/coalesced trigger so direct decisions
        // and a prior completed transfer become the exact delta baseline.
        if !force_elected_checkpoint && let Some(known) = sync.reusable_source_cut(peer) {
            sync.transition_session(
                peer,
                SessionEvent::SourceCutObserved {
                    epoch: SessionPeerEpoch::new(peer.boot_epoch()),
                    cut: cut_to_reducer(known),
                },
            );
        }
        let effects = sync.transition_session(
            peer,
            SessionEvent::Trigger(SessionTrigger {
                kind: SessionSyncKind::Terminal,
                origin: SessionTriggerOrigin::External,
                desired_cut: desired_cut.map(cut_to_reducer),
            }),
        );
        let Some(wire) = terminal_start_wire(&effects) else {
            sync.coalesce_terminal_intent_if_active(peer, reason as i32, desired_cut);
            metrics::record_strict_catchup_session_event(
                metric_reason,
                StrictCatchupSessionEvent::Coalesced,
            );
            return;
        };
        wire
    };
    start_reducer_owned_terminal_client(rt, peer, reason, desired_cut, wire).await;
}

async fn start_reducer_owned_terminal_client<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    peer: PeerIncarnation,
    reason: StrictCatchupReason,
    desired_cut: Option<TerminalCut>,
    wire: SessionWireIdentity,
) {
    let metric_reason =
        CatchupReason::from_v3_wire(reason as i32).unwrap_or(CatchupReason::TerminalFence);
    if wire.transfer().get() != 0 {
        metrics::record_strict_catchup_session_event(
            metric_reason,
            StrictCatchupSessionEvent::Coalesced,
        );
        return;
    }
    let known = rt.v3_sync.lock().begin_terminal_client_cache(
        peer,
        reason as i32,
        desired_cut,
        wire.nonce().get(),
        wire.cursor().value(),
        rt.cfg.pending_propose_ttl(),
    );
    metrics::record_strict_catchup_session_start(metric_reason);
    let set_digest = Bytes::copy_from_slice(
        rt.terminal_journal
            .lock()
            .await
            .terminal_cut()
            .terminal_set_digest(),
    );
    let request = StrictTerminalSyncReq {
        src_node: rt.self_id as u32,
        expected_responder_boot_epoch: peer.boot_epoch(),
        reason: reason as i32,
        known_source_cut: known.map(cut_to_wire),
        requester_terminal_set_digest: set_digest,
        transfer_id: 0,
        request_nonce: wire.nonce().get(),
        expected_cursor: wire.cursor().value(),
    };
    rt.v3_retries.lock().register_request(
        peer,
        request.clone(),
        rt.cfg.bulk_retry_delay(),
        rt.cfg.pending_propose_ttl(),
        rt.cfg.strict_bulk_retry_jitter_pct(),
        v3_retry_salt(rt.self_id, &rt.topic),
    );
    let send_result = send_v3_metadata_control(
        rt,
        peer.node(),
        StrictBody::TerminalSyncReq(request),
        metric_reason,
        CatchupPhase::Metadata,
    )
    .await;
    record_terminal_send_result(rt, peer, wire, &send_result);
}

async fn resume_deferred_v3_terminal_sync<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    peer: PeerIncarnation,
) {
    let deferred = rt.v3_sync.lock().take_deferred_client(peer);
    let Some((reason, desired_cut)) = deferred else {
        return;
    };
    let reason = StrictCatchupReason::try_from(reason)
        .ok()
        .unwrap_or(StrictCatchupReason::TerminalFence);
    request_v3_terminal_sync_toward(rt, peer.node(), reason, desired_cut).await;
}

async fn complete_deferred_v3_terminal_sync_from_equal_set<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    peer: PeerIncarnation,
) {
    let deferred = rt.v3_sync.lock().take_deferred_client(peer);
    let Some((_reason, desired_cut)) = deferred else {
        return;
    };
    rt.v3_sync.lock().clear_pending_collision_resume(peer);
    // The authenticated requester advertised the same canonical terminal set
    // as this node. Any cut captured from that requester by the preceding
    // metadata probe is therefore satisfied without opening the reverse
    // terminal direction merely to recover its source-lineage identity.
    if let Some(desired_cut) = desired_cut {
        rt.v3_sync.lock().remember_source_cut(peer, desired_cut);
    }
    start_v3_repository_after_terminal(rt, peer, None).await;
}

fn v3_retry_salt(node: NodeIdentifier, topic: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64 ^ node as u64;
    for byte in topic.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

/// Retry only the exact request or final ACK still owned by the peer
/// incarnation. The bulk transport separately handles enqueue backpressure.
pub(super) async fn retry_v3_terminal_transmissions<R: StrictReplicable>(rt: &StrictRuntime<R>) {
    let now = Instant::now();
    // Retry entries and client sessions share the same TTL, but are stored
    // separately. Expire the owning session on every retry-loop tick so a
    // lost request cannot leave its active gauge resident indefinitely.
    let expired_deferred = {
        let mut sync = rt.v3_sync.lock();
        sync.expire(now);
        sync.take_expired_deferred_clients()
    };
    let expired_history = rt.v3_history.lock().expire_clients(now);
    for expired in expired_history {
        let peer = expired.peer();
        let reason = CatchupReason::from_v3_wire(expired.metric_reason() as i32)
            .unwrap_or(CatchupReason::RepositoryGap);
        metrics::record_strict_catchup_session_completion(
            reason,
            StrictCatchupSessionOutcome::Expired,
        );
        rt.v3_retries.lock().cancel_history_request(peer);
        let deferred = { rt.v3_history.lock().take_deferred_terminal_intent(peer) };
        if let Some((reason, desired_cut)) = deferred {
            request_v3_terminal_sync_toward(rt, peer.node(), reason, desired_cut).await;
        }
    }
    let salt = v3_retry_salt(rt.self_id, &rt.topic);
    let (requests, final_acks, history_requests, history_final_acks, history_probes) =
        rt.v3_retries.lock().due(
            now,
            rt.cfg.strict_bulk_retry_max_delay(),
            rt.cfg.strict_bulk_retry_jitter_pct(),
            salt,
        );
    let clock_probes = rt.v3_retries.lock().due_clock_probes(
        now,
        rt.cfg.strict_bulk_retry_max_delay(),
        rt.cfg.strict_bulk_retry_jitter_pct(),
        salt,
    );
    for (peer, request) in clock_probes {
        if v3_peer(rt, peer.node(), peer.boot_epoch()).is_none()
            || !rt.v3_retries.lock().clock_probe_is_current(peer, &request)
            || !rt
                .v3_sync
                .lock()
                .clock_nonce_is_current(peer, request.request_nonce)
        {
            continue;
        }
        let reason =
            CatchupReason::from_v3_wire(request.reason).unwrap_or(CatchupReason::DeliveryWatermark);
        let _ = retry_v3_metadata_control(
            rt,
            peer.node(),
            StrictBody::ClockProbeReq(request),
            reason,
            CatchupPhase::Metadata,
        )
        .await;
    }
    for (peer, request) in requests {
        if v3_peer(rt, peer.node(), peer.boot_epoch()).is_none()
            || !rt.v3_retries.lock().request_is_current(peer, &request)
        {
            continue;
        }
        let Some(wire) = terminal_session_wire(
            peer.boot_epoch(),
            request.transfer_id,
            request.request_nonce,
            request.expected_cursor,
        ) else {
            continue;
        };
        let effects = rt
            .v3_sync
            .lock()
            .transition_session(peer, SessionEvent::RetryReady { wire });
        if !effects.iter().any(|effect| {
            matches!(effect, SessionEffect::SendRequest { kind: SessionSyncKind::Terminal, wire: expected } if *expected == wire)
        }) {
            continue;
        }
        let reason =
            CatchupReason::from_v3_wire(request.reason).unwrap_or(CatchupReason::TerminalFence);
        let send_result = retry_v3_metadata_control(
            rt,
            peer.node(),
            StrictBody::TerminalSyncReq(request),
            reason,
            CatchupPhase::Metadata,
        )
        .await;
        record_terminal_send_result(rt, peer, wire, &send_result);
    }
    for (peer, ack) in final_acks {
        if v3_peer(rt, peer.node(), peer.boot_epoch()).is_none()
            || !rt.v3_retries.lock().final_ack_is_current(peer, &ack)
        {
            continue;
        }
        let Some(target) = ack.target_cut.as_ref().and_then(cut_from_wire) else {
            continue;
        };
        let Some(wire) = terminal_session_wire(
            peer.boot_epoch(),
            ack.transfer_id,
            ack.request_nonce,
            target.generation(),
        ) else {
            continue;
        };
        let effects = rt
            .v3_sync
            .lock()
            .transition_session(peer, SessionEvent::RetryReady { wire });
        if !effects.iter().any(|effect| {
            matches!(effect, SessionEffect::SendAck { kind: SessionSyncKind::Terminal, wire: expected, .. } if *expected == wire)
        }) {
            continue;
        }
        let send_result = retry_v3_metadata_control(
            rt,
            peer.node(),
            StrictBody::TerminalSyncAck(ack),
            CatchupReason::TerminalFence,
            CatchupPhase::FinalAck,
        )
        .await;
        record_terminal_send_result(rt, peer, wire, &send_result);
    }
    for (peer, request) in history_requests {
        if v3_peer(rt, peer.node(), peer.boot_epoch()).is_none()
            || !rt.v3_history.lock().has_active_transfer(peer)
            || !rt
                .v3_retries
                .lock()
                .history_request_is_current(peer, &request)
        {
            continue;
        }
        let Some(reason) = v3_history_reason(&request) else {
            continue;
        };
        let phase = v3_history_request_phase(&request);
        let _ = rt
            .net
            .send_redundant_catchup_unicast(
                peer.node(),
                &rt.topic,
                StrictBody::CatchupReq(request),
                reason,
                phase,
            )
            .await;
    }
    for (peer, ack) in history_final_acks {
        if v3_peer(rt, peer.node(), peer.boot_epoch()).is_none()
            || !rt
                .v3_retries
                .lock()
                .history_final_ack_is_current(peer, &ack)
        {
            continue;
        }
        let Some(reason) = v3_history_reason(&ack) else {
            continue;
        };
        let _ = rt
            .net
            .send_redundant_catchup_unicast(
                peer.node(),
                &rt.topic,
                StrictBody::CatchupReq(ack),
                reason,
                CatchupPhase::FinalAck,
            )
            .await;
    }
    for (peer, request) in history_probes {
        if v3_peer(rt, peer.node(), peer.boot_epoch()).is_none()
            || !rt
                .v3_retries
                .lock()
                .history_probe_is_current(peer, &request)
            || !rt
                .v3_sync
                .lock()
                .history_nonce_is_current(peer, request.request_nonce)
        {
            continue;
        }
        let reason =
            CatchupReason::from_v3_wire(request.reason).unwrap_or(CatchupReason::RepositoryGap);
        let _ = retry_v3_metadata_control(
            rt,
            peer.node(),
            StrictBody::HistoryProbeReq(request),
            reason,
            CatchupPhase::Metadata,
        )
        .await;
    }
    for (peer, reason, desired_cut) in expired_deferred {
        if v3_peer(rt, peer.node(), peer.boot_epoch()).is_none() {
            continue;
        }
        let reason = StrictCatchupReason::try_from(reason)
            .ok()
            .unwrap_or(StrictCatchupReason::TerminalFence);
        request_v3_terminal_sync_toward(rt, peer.node(), reason, desired_cut).await;
    }
}

fn v3_error_page<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    epoch: u64,
    req: &StrictTerminalSyncReq,
    status: StrictTerminalSyncStatus,
) -> StrictTerminalSyncPage {
    StrictTerminalSyncPage {
        responder_node: rt.self_id as u32,
        expected_requester_boot_epoch: epoch,
        transfer_id: req.transfer_id,
        request_nonce: req.request_nonce,
        status: status as i32,
        kind: StrictTerminalPageKind::Unspecified as i32,
        base_cut: None,
        target_cut: None,
        cursor: req.expected_cursor,
        next_cursor: req.expected_cursor,
        image_digest: Bytes::new(),
        checkpoint_states: Vec::new(),
        deltas: Vec::new(),
        has_more: false,
    }
}

fn render_v3_page<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    journal: &TerminalJournal,
    session: &ResponderSession,
    nonce: u64,
    epoch: u64,
) -> Option<(StrictTerminalSyncPage, u64, Option<TerminalCut>)> {
    let limit = rt.cfg.strict_max_catchup_ops().max(1);
    let byte_limit = rt.strict_catchup_response_budget();
    match session.kind() {
        StrictTerminalPageKind::Delta => {
            let base = session.cursor_cut().or(session.base_cut())?;
            let page = journal.terminal_deltas_between(&base, &session.target_cut(), limit)?;
            let mut previous = *base.chain_digest();
            let mut progress = base;
            let mut deltas = Vec::new();
            for entry in page.into_entries() {
                let (generation, chain, op_id, record) = entry.into_parts();
                let state = StrictRuntime::<R>::terminal_state_from_journal_record(op_id, &record)?;
                let delta = StrictTerminalDelta {
                    generation,
                    state: Some(state),
                    previous_chain_digest: Bytes::copy_from_slice(&previous),
                    chain_digest: Bytes::copy_from_slice(&chain),
                };
                deltas.push(delta);
                let candidate = StrictTerminalSyncPage {
                    responder_node: rt.self_id as u32,
                    expected_requester_boot_epoch: epoch,
                    transfer_id: session.transfer_id(),
                    request_nonce: nonce,
                    status: StrictTerminalSyncStatus::Ok as i32,
                    kind: StrictTerminalPageKind::Delta as i32,
                    base_cut: Some(cut_to_wire(base)),
                    target_cut: Some(cut_to_wire(session.target_cut())),
                    cursor: base.generation(),
                    next_cursor: generation,
                    image_digest: Bytes::copy_from_slice(
                        session.target_cut().terminal_set_digest(),
                    ),
                    checkpoint_states: Vec::new(),
                    deltas: deltas.clone(),
                    has_more: generation < session.target_cut().generation(),
                };
                let fits = rt
                    .strict_replication_payload_len(&StrictBody::TerminalSyncPage(candidate))
                    .is_ok_and(|encoded| encoded <= byte_limit);
                if !fits {
                    deltas.pop();
                    if deltas.is_empty() {
                        return Some((
                            v3_resource_limit_page(rt, session, nonce, epoch),
                            base.generation(),
                            Some(base),
                        ));
                    }
                    break;
                }
                previous = chain;
                progress = journal.terminal_cut_at(generation)?;
            }
            let has_more = progress.generation() < session.target_cut().generation();
            Some((
                StrictTerminalSyncPage {
                    responder_node: rt.self_id as u32,
                    expected_requester_boot_epoch: epoch,
                    transfer_id: session.transfer_id(),
                    request_nonce: nonce,
                    status: if deltas.is_empty() {
                        StrictTerminalSyncStatus::UpToDate as i32
                    } else {
                        StrictTerminalSyncStatus::Ok as i32
                    },
                    kind: StrictTerminalPageKind::Delta as i32,
                    base_cut: Some(cut_to_wire(base)),
                    target_cut: Some(cut_to_wire(session.target_cut())),
                    cursor: base.generation(),
                    next_cursor: progress.generation(),
                    image_digest: Bytes::copy_from_slice(
                        session.target_cut().terminal_set_digest(),
                    ),
                    checkpoint_states: Vec::new(),
                    deltas,
                    has_more,
                },
                progress.generation(),
                Some(progress),
            ))
        }
        StrictTerminalPageKind::Checkpoint => {
            let page = journal.terminal_checkpoint_page_at(
                &session.target_cut(),
                session.next_cursor(),
                limit,
            )?;
            let cursor = page.cursor();
            let mut next = cursor;
            let mut states = Vec::new();
            for entry in page.into_entries() {
                let (op_id, record) = entry.into_parts();
                let state = StrictRuntime::<R>::terminal_state_from_journal_record(op_id, &record)?;
                states.push(state);
                let candidate_next = cursor.saturating_add(states.len() as u64);
                let candidate = StrictTerminalSyncPage {
                    responder_node: rt.self_id as u32,
                    expected_requester_boot_epoch: epoch,
                    transfer_id: session.transfer_id(),
                    request_nonce: nonce,
                    status: StrictTerminalSyncStatus::Ok as i32,
                    kind: StrictTerminalPageKind::Checkpoint as i32,
                    base_cut: session.base_cut().map(cut_to_wire),
                    target_cut: Some(cut_to_wire(session.target_cut())),
                    cursor,
                    next_cursor: candidate_next,
                    image_digest: Bytes::copy_from_slice(
                        session.target_cut().terminal_set_digest(),
                    ),
                    checkpoint_states: states.clone(),
                    deltas: Vec::new(),
                    has_more: candidate_next < session.target_cut().generation(),
                };
                let fits = rt
                    .strict_replication_payload_len(&StrictBody::TerminalSyncPage(candidate))
                    .is_ok_and(|encoded| encoded <= byte_limit);
                if !fits {
                    states.pop();
                    if states.is_empty() {
                        return Some((
                            v3_resource_limit_page(rt, session, nonce, epoch),
                            cursor,
                            None,
                        ));
                    }
                    break;
                }
                next = candidate_next;
            }
            let has_more = next < session.target_cut().generation();
            Some((
                StrictTerminalSyncPage {
                    responder_node: rt.self_id as u32,
                    expected_requester_boot_epoch: epoch,
                    transfer_id: session.transfer_id(),
                    request_nonce: nonce,
                    status: StrictTerminalSyncStatus::Ok as i32,
                    kind: StrictTerminalPageKind::Checkpoint as i32,
                    base_cut: session.base_cut().map(cut_to_wire),
                    target_cut: Some(cut_to_wire(session.target_cut())),
                    cursor,
                    next_cursor: next,
                    // v3 defines checkpoint image identity as the target set digest.
                    image_digest: Bytes::copy_from_slice(
                        session.target_cut().terminal_set_digest(),
                    ),
                    checkpoint_states: states,
                    deltas: Vec::new(),
                    has_more,
                },
                next,
                None,
            ))
        }
        StrictTerminalPageKind::Unspecified => None,
    }
}

fn v3_resource_limit_page<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    session: &ResponderSession,
    nonce: u64,
    epoch: u64,
) -> StrictTerminalSyncPage {
    StrictTerminalSyncPage {
        responder_node: rt.self_id as u32,
        expected_requester_boot_epoch: epoch,
        transfer_id: session.transfer_id(),
        request_nonce: nonce,
        status: StrictTerminalSyncStatus::ResourceLimit as i32,
        kind: session.kind() as i32,
        base_cut: session.base_cut().map(cut_to_wire),
        target_cut: Some(cut_to_wire(session.target_cut())),
        cursor: session.next_cursor(),
        next_cursor: session.next_cursor(),
        image_digest: Bytes::copy_from_slice(session.target_cut().terminal_set_digest()),
        checkpoint_states: Vec::new(),
        deltas: Vec::new(),
        has_more: false,
    }
}

async fn send_v3_page<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    dst: NodeIdentifier,
    page: StrictTerminalSyncPage,
    reason: CatchupReason,
    record_logical: bool,
) {
    let reducer_identity = terminal_session_wire(
        page.expected_requester_boot_epoch,
        page.transfer_id,
        page.request_nonce,
        page.cursor,
    )
    .map(|wire| {
        (
            PeerIncarnation::new(dst, page.expected_requester_boot_epoch),
            wire,
        )
    });
    let has_operations = !page.checkpoint_states.is_empty() || !page.deltas.is_empty();
    let phase = if has_operations {
        CatchupPhase::from_terminal_page_kind(page.kind).unwrap_or(CatchupPhase::Metadata)
    } else {
        CatchupPhase::Metadata
    };
    let records = page
        .checkpoint_states
        .len()
        .saturating_add(page.deltas.len());
    let body = StrictBody::TerminalSyncPage(page);
    let encoded_len = rt.strict_replication_payload_len(&body).unwrap_or(0);
    if record_logical {
        metrics::record_catchup_response_detail(
            CatchupMode::Strict,
            reason,
            phase,
            records,
            encoded_len,
        );
    }
    let send_result = if has_operations {
        rt.net
            .send_bulk_catchup_unicast(
                dst,
                &rt.topic,
                body,
                rt.cfg.bulk_retry_delay(),
                reason,
                phase,
            )
            .await
    } else {
        send_v3_metadata_control(rt, dst, body, reason, phase).await
    };
    if let Some((peer, wire)) = reducer_identity {
        record_terminal_send_result(rt, peer, wire, &send_result);
    }
}

pub(super) async fn recv_v3_terminal_sync_req<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    req: StrictTerminalSyncReq,
) {
    let Some(peer) = v3_peer(rt, from, epoch) else {
        return;
    };
    let Some(metric_reason) = CatchupReason::from_v3_wire(req.reason) else {
        return;
    };
    if node_from_u32(req.src_node) != Some(from)
        || req.expected_responder_boot_epoch != rt.boot_epoch
        || req.request_nonce == 0
        || req.requester_terminal_set_digest.len() != 32
    {
        return;
    }
    if rt.v3_history.lock().has_any_transfer(peer) {
        send_v3_page(
            rt,
            from,
            v3_error_page(rt, epoch, &req, StrictTerminalSyncStatus::ResourceLimit),
            metric_reason,
            true,
        )
        .await;
        return;
    }
    if req.transfer_id == 0 {
        let unmatched_active_responder = {
            let mut sync = rt.v3_sync.lock();
            sync.expire(Instant::now());
            sync.responder(peer)
                .is_some_and(|responder| !responder.matches_initial_nonce(req.request_nonce))
        };
        if unmatched_active_responder {
            // The peer may have yielded this request direction and resumed it
            // with a fresh initial identity while our original responder is
            // still waiting for its final ACK. Deflect that identity without
            // letting the reducer classify it as a cursor error: RESOURCE_LIMIT
            // retains the exact request and bounded retry schedule until this
            // responder completes or expires.
            send_v3_page(
                rt,
                from,
                v3_error_page(rt, epoch, &req, StrictTerminalSyncStatus::ResourceLimit),
                metric_reason,
                true,
            )
            .await;
            return;
        }
    }
    let mut arbitration = SessionInboundArbitration::KeepCurrent;
    if req.transfer_id == 0 {
        let disposition = rt
            .v3_sync
            .lock()
            .resolve_inbound_terminal_start(rt.self_id, peer);
        match disposition {
            InboundTerminalSyncDisposition::Accept => {}
            InboundTerminalSyncDisposition::Deflect => {
                // The lower node owns the first requester direction. Keep the
                // losing peer's request identity alive so its retry can be
                // yielded when our corresponding request arrives; never
                // allocate a second responder transfer for the collision.
                send_v3_page(
                    rt,
                    from,
                    v3_error_page(rt, epoch, &req, StrictTerminalSyncStatus::ResourceLimit),
                    metric_reason,
                    true,
                )
                .await;
                return;
            }
            InboundTerminalSyncDisposition::Yielded { cancelled_nonce } => {
                arbitration = SessionInboundArbitration::AcceptInbound;
                rt.v3_retries.lock().complete_request(peer, cancelled_nonce);
                metrics::record_strict_catchup_session_event(
                    metric_reason,
                    StrictCatchupSessionEvent::Coalesced,
                );
            }
        }
    }
    let Some(incoming_wire) = terminal_session_wire(
        epoch,
        req.transfer_id,
        req.request_nonce,
        req.expected_cursor,
    ) else {
        return;
    };
    let reducer_effects = rt.v3_sync.lock().transition_session(
        peer,
        SessionEvent::RequestReceived {
            kind: SessionSyncKind::Terminal,
            wire: incoming_wire,
            arbitration,
        },
    );
    if let Some(status) = reducer_effects.iter().find_map(|effect| match effect {
        SessionEffect::SendStatus { status, .. } => Some(*status),
        _ => None,
    }) {
        let status = match status {
            SessionStatus::TransferExpired => StrictTerminalSyncStatus::TransferExpired,
            SessionStatus::CursorMismatch => StrictTerminalSyncStatus::CursorMismatch,
            SessionStatus::IncarnationMismatch => StrictTerminalSyncStatus::IncarnationMismatch,
        };
        send_v3_page(
            rt,
            from,
            v3_error_page(rt, epoch, &req, status),
            metric_reason,
            true,
        )
        .await;
        return;
    }
    let reducer_request = terminal_effect_wire(&reducer_effects, |effect| match effect {
        SessionEffect::PreparePage {
            kind: SessionSyncKind::Terminal,
            request,
        } => Some(*request),
        _ => None,
    });
    let reducer_cached = reducer_effects.iter().any(|effect| {
        matches!(
            effect,
            SessionEffect::SendCachedPage {
                kind: SessionSyncKind::Terminal,
                ..
            }
        )
    });
    if reducer_request.is_none() && !reducer_cached {
        return;
    }
    // Equal terminal sets are a metadata-only fast path. Check this before
    // taking a bulk response-build permit and without allocating responder
    // transfer state; its cost is independent of retained journal length.
    if req.transfer_id == 0 {
        let (target, offered_cut_is_current) = {
            let journal = rt.terminal_journal.lock().await;
            let target = journal.terminal_cut();
            let offered_cut_is_current = req
                .known_source_cut
                .as_ref()
                .and_then(cut_from_wire)
                .is_some_and(|known| {
                    journal.recognizes_terminal_cut(&known) && source_cut_covers(known, target)
                });
            (target, offered_cut_is_current)
        };
        let terminal_sets_equal =
            req.requester_terminal_set_digest.as_ref() == target.terminal_set_digest();
        if terminal_sets_equal || offered_cut_is_current {
            let page = StrictTerminalSyncPage {
                responder_node: rt.self_id as u32,
                expected_requester_boot_epoch: epoch,
                transfer_id: 0,
                request_nonce: req.request_nonce,
                status: StrictTerminalSyncStatus::UpToDate as i32,
                kind: StrictTerminalPageKind::Delta as i32,
                base_cut: Some(cut_to_wire(target)),
                target_cut: Some(cut_to_wire(target)),
                cursor: target.generation(),
                next_cursor: target.generation(),
                image_digest: Bytes::copy_from_slice(target.terminal_set_digest()),
                checkpoint_states: Vec::new(),
                deltas: Vec::new(),
                has_more: false,
            };
            if let Some(request) = reducer_request {
                let effects = rt.v3_sync.lock().transition_session(
                    peer,
                    SessionEvent::UpToDateResponded {
                        request,
                        target_cut: cut_to_reducer(target),
                        satisfies_dirty: terminal_sets_equal,
                    },
                );
                if !effects.iter().any(|effect| {
                    matches!(
                        effect,
                        SessionEffect::SendPage {
                            kind: SessionSyncKind::Terminal,
                            ..
                        }
                    )
                }) {
                    return;
                }
            }
            send_v3_page(rt, from, page, metric_reason, true).await;
            // UP_TO_DATE deliberately allocates no responder transfer and
            // therefore has no final ACK edge. Equal canonical sets satisfy
            // both directions; an offered responder cut only satisfies the
            // requester direction, so preserve any yielded reverse intent.
            if terminal_sets_equal {
                complete_deferred_v3_terminal_sync_from_equal_set(rt, peer).await;
            } else {
                resume_deferred_v3_terminal_sync(rt, peer).await;
            }
            return;
        }
    }

    let Some(_permit) = rt
        .cfg
        .try_begin_catchup(CatchupMode::Strict, &rt.topic, from)
    else {
        if let Some(wire) = reducer_request {
            rt.v3_sync.lock().transition_session(
                peer,
                SessionEvent::TransferExpired {
                    epoch: SessionPeerEpoch::new(epoch),
                    wire,
                },
            );
        }
        // Simultaneous arbitration may have yielded our outbound client and
        // retained it as the reverse obligation. If this responder direction
        // cannot acquire resources, no final ACK will exist to resume that
        // client later, so rearm it immediately after expiring the inbound
        // reducer attempt.
        resume_deferred_v3_terminal_sync(rt, peer).await;
        return;
    };
    let now = Instant::now();
    let ttl = rt.cfg.pending_propose_ttl();
    let journal = rt.terminal_journal.lock().await;
    let response = {
        let mut sync = rt.v3_sync.lock();
        sync.expire(now);

        (|| -> Option<(StrictTerminalSyncPage, Option<BulkPageIdentity>, bool)> {
            if req.transfer_id != 0 {
                let Some(session) = sync.responder(peer).cloned() else {
                    return Some((
                        v3_error_page(rt, epoch, &req, StrictTerminalSyncStatus::TransferExpired),
                        None,
                        true,
                    ));
                };
                if session.transfer_id() != req.transfer_id {
                    return Some((
                        v3_error_page(rt, epoch, &req, StrictTerminalSyncStatus::TransferExpired),
                        None,
                        true,
                    ));
                }
                if let Some(page) = session.cached_page_for(req.request_nonce) {
                    metrics::record_strict_catchup_duplicate(
                        StrictCatchupDuplicateOutcome::CachedReplay,
                    );
                    return Some((page, None, false));
                }
                if session.next_cursor() != req.expected_cursor || session.final_nonce().is_some() {
                    return Some((
                        v3_error_page(rt, epoch, &req, StrictTerminalSyncStatus::CursorMismatch),
                        None,
                        true,
                    ));
                }
                let Some((page, next, progress)) =
                    render_v3_page(rt, &journal, &session, req.request_nonce, epoch)
                else {
                    sync.remove_responder(peer);
                    if let Some(wire) = reducer_request {
                        sync.transition_session(
                            peer,
                            SessionEvent::TransferExpired {
                                epoch: SessionPeerEpoch::new(epoch),
                                wire,
                            },
                        );
                    }
                    return None;
                };
                let request = reducer_request?;
                let effects = sync.transition_session(
                    peer,
                    SessionEvent::PagePrepared {
                        kind: SessionSyncKind::Terminal,
                        request,
                        next_cursor: SessionCursor::new(
                            SessionCursorKind::TerminalGeneration,
                            next,
                        ),
                        target_cut: cut_to_reducer(session.target_cut()),
                        has_more: page.has_more,
                    },
                );
                if !effects.iter().any(|effect| {
                    matches!(
                        effect,
                        SessionEffect::SendPage {
                            kind: SessionSyncKind::Terminal,
                            ..
                        }
                    )
                }) {
                    return None;
                }
                if let Some(active) = sync.responder_mut(peer) {
                    active.record_page(req.request_nonce, page.clone(), next, progress, ttl);
                }
                let acknowledged = session.cached_page_nonce().map(|request_nonce| {
                    BulkPageIdentity::terminal(session.transfer_id(), request_nonce)
                });
                return Some((page, acknowledged, true));
            }

            if let Some(existing) = sync.responder(peer).cloned() {
                return if let Some(page) = existing.cached_page_for(req.request_nonce) {
                    metrics::record_strict_catchup_duplicate(
                        StrictCatchupDuplicateOutcome::CachedReplay,
                    );
                    Some((page, None, false))
                } else {
                    Some((
                        v3_error_page(rt, epoch, &req, StrictTerminalSyncStatus::ResourceLimit),
                        None,
                        true,
                    ))
                };
            }
            if sync.completed_matches_request(peer, 0, req.request_nonce) {
                return Some((
                    v3_error_page(rt, epoch, &req, StrictTerminalSyncStatus::TransferExpired),
                    None,
                    true,
                ));
            }

            let known = req.known_source_cut.as_ref().and_then(cut_from_wire);
            let (target, kind) = {
                let target = journal.terminal_cut();
                let kind = if known
                    .as_ref()
                    .is_some_and(|cut| journal.recognizes_terminal_cut(cut))
                {
                    StrictTerminalPageKind::Delta
                } else {
                    StrictTerminalPageKind::Checkpoint
                };
                (target, kind)
            };
            let request = reducer_request?;
            let id = request.transfer().get();
            let session = ResponderSession::new(id, known, target, kind, req.request_nonce, ttl);
            let Some((page, next, progress)) =
                render_v3_page(rt, &journal, &session, req.request_nonce, epoch)
            else {
                sync.transition_session(
                    peer,
                    SessionEvent::TransferExpired {
                        epoch: SessionPeerEpoch::new(epoch),
                        wire: request,
                    },
                );
                return None;
            };
            let effects = sync.transition_session(
                peer,
                SessionEvent::PagePrepared {
                    kind: SessionSyncKind::Terminal,
                    request,
                    next_cursor: SessionCursor::new(SessionCursorKind::TerminalGeneration, next),
                    target_cut: cut_to_reducer(target),
                    has_more: page.has_more,
                },
            );
            if !effects.iter().any(|effect| {
                matches!(
                    effect,
                    SessionEffect::SendPage {
                        kind: SessionSyncKind::Terminal,
                        ..
                    }
                )
            }) {
                return None;
            }
            sync.insert_responder(peer, session);
            if let Some(active) = sync.responder_mut(peer) {
                active.record_page(req.request_nonce, page.clone(), next, progress, ttl);
            }
            Some((page, None, true))
        })()
    };
    drop(journal);

    let Some((page, acknowledged_bulk_page, record_logical)) = response else {
        return;
    };
    if let Some(identity) = acknowledged_bulk_page {
        rt.net.acknowledge_bulk_unicast(from, &rt.topic, identity);
    }
    send_v3_page(rt, from, page, metric_reason, record_logical).await;
}

fn validated_v3_terminal_state(
    terminal: &super::super::proto::StrictTerminalState,
) -> Option<(
    (u64, u64),
    Option<TerminalDecisionIdentity>,
    JournalTerminalDecision,
)> {
    let coord = node_from_u32(terminal.coord_node)?;
    let op_id = (terminal.op_id_hi, terminal.op_id_lo);
    if node_from_u32((op_id.0 >> 48) as u32) != Some(coord) {
        return None;
    }
    let identity = terminal_identity_from_wire(
        terminal.resolver_node,
        terminal.resolver_boot_epoch,
        &terminal.frozen_targets,
        terminal.ballot,
        op_id,
        coord,
    )
    .ok()?;
    let decision = match terminal.outcome.as_ref()? {
        super::super::proto::StrictTerminalOutcome::Commit(commit) => {
            JournalTerminalDecision::commit(CommitCandidate::from_bytes(
                terminal.ballot,
                commit.ts_final,
                commit.op_msgpack.clone(),
            ))
        }
        super::super::proto::StrictTerminalOutcome::Abort(_) => {
            JournalTerminalDecision::abort(terminal.ballot)
        }
    };
    Some((op_id, identity, decision))
}

fn staged_terminal_decision(
    terminal: &super::super::proto::StrictTerminalState,
) -> Option<StagedTerminalDecision> {
    let (op_id, identity, decision) = validated_v3_terminal_state(terminal)?;
    let (frozen_targets, resolver) = identity
        .map(|identity| (Some(identity.frozen_targets), Some(identity.resolver)))
        .unwrap_or((None, None));
    Some(StagedTerminalDecision::new(
        op_id,
        frozen_targets,
        resolver,
        decision,
    ))
}

pub(super) async fn recv_v3_terminal_sync_page<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    page: StrictTerminalSyncPage,
) {
    let Some(peer) = v3_peer(rt, from, epoch) else {
        return;
    };
    if node_from_u32(page.responder_node) != Some(from)
        || page.expected_requester_boot_epoch != rt.boot_epoch
        || page.request_nonce == 0
    {
        return;
    }
    let Some(status) = StrictTerminalSyncStatus::try_from(page.status).ok() else {
        return;
    };
    if !matches!(
        status,
        StrictTerminalSyncStatus::Ok | StrictTerminalSyncStatus::UpToDate
    ) {
        let (correlated, collision_deflection) = rt
            .v3_sync
            .lock()
            .client(peer)
            .map(|client| {
                let correlated = client.pending_nonce() == page.request_nonce
                    && (client.transfer_id() == 0 || client.transfer_id() == page.transfer_id);
                let collision_deflection = correlated
                    && status == StrictTerminalSyncStatus::ResourceLimit
                    && client.transfer_id() == 0
                    && page.transfer_id == 0
                    && page.base_cut.is_none()
                    && page.target_cut.is_none();
                (correlated, collision_deflection)
            })
            .unwrap_or((false, false));
        // RESOURCE_LIMIT is also the deterministic simultaneous-start
        // deflection. Retain the exact client/request identity: the peer's
        // winning request will either make us yield or this request will be
        // retried unchanged after the responder direction disappears.
        if collision_deflection {
            let ttl = rt.cfg.pending_propose_ttl();
            // The established joint-lock order is retry then sync. Renew both
            // leases as one transition so neither owner can expire alone.
            let mut retries = rt.v3_retries.lock();
            let mut sync = rt.v3_sync.lock();
            let can_extend = retries.request_nonce_is_current(peer, page.request_nonce)
                && sync
                    .client(peer)
                    .is_some_and(|client| client.can_extend_collision_expiry(page.request_nonce));
            if can_extend {
                retries.extend_current_request_expiry(peer, ttl);
                sync.client_mut(peer)
                    .expect("checked collision client exists")
                    .extend_collision_expiry(ttl);
            }
            return;
        }
        // A correlated capacity rejection is advisory, not terminal. Keep
        // the exact request, desired cut, reducer lifecycle, and its fixed-TTL
        // retry schedule. Replacing it here would reset backoff and turn a
        // persistently full responder into a nonce-allocation tight loop.
        if correlated && status == StrictTerminalSyncStatus::ResourceLimit {
            return;
        }
        if correlated {
            let completed = rt.v3_sync.lock().finish_failed_client(peer);
            rt.v3_retries
                .lock()
                .complete_request(peer, page.request_nonce);
            let (retry, pending_elected_history) = completed
                .as_ref()
                .map(|session| {
                    let fallback_reason = StrictCatchupReason::try_from(session.reason())
                        .ok()
                        .unwrap_or(StrictCatchupReason::TerminalFence);
                    let pending = rt.v3_history.lock().pending_after_terminal(peer);
                    (
                        pending
                            .map(|intent| (intent.reason(), Some(intent.source_cut())))
                            .unwrap_or((fallback_reason, session.desired_cut())),
                        pending.is_some_and(|intent| {
                            intent.reason() == StrictCatchupReason::HistoryElection
                        }),
                    )
                })
                .map(|(retry, elected)| (Some(retry), elected))
                .unwrap_or((None, false));
            if let Some(session) = completed {
                let reason = CatchupReason::from_v3_wire(session.started_reason())
                    .unwrap_or(CatchupReason::TerminalFence);
                let outcome = match status {
                    StrictTerminalSyncStatus::TransferExpired => {
                        StrictCatchupSessionOutcome::Expired
                    }
                    StrictTerminalSyncStatus::IncarnationMismatch => {
                        StrictCatchupSessionOutcome::IncarnationMismatch
                    }
                    StrictTerminalSyncStatus::ResourceLimit => {
                        StrictCatchupSessionOutcome::ResourceLimit
                    }
                    _ => StrictCatchupSessionOutcome::Failed,
                };
                metrics::record_strict_catchup_session_completion(reason, outcome);
            }
            if status == StrictTerminalSyncStatus::IncarnationMismatch && pending_elected_history {
                rearm_history_election(rt);
            }
            if status == StrictTerminalSyncStatus::CursorMismatch {
                // The peer rejected our reusable source cursor. Reset this
                // peer to a cursor-zero lifecycle while retaining the exact
                // desired cut captured above.
                rt.v3_sync.lock().reset_after_cursor_mismatch(peer);
            }
            if matches!(
                status,
                StrictTerminalSyncStatus::TransferExpired
                    | StrictTerminalSyncStatus::CursorMismatch
            ) && let Some((reason, desired_cut)) = retry
            {
                Box::pin(request_v3_terminal_sync_toward(
                    rt,
                    peer.node(),
                    reason,
                    desired_cut,
                ))
                .await;
            }
        }
        return;
    }
    if (status == StrictTerminalSyncStatus::Ok && page.transfer_id == 0)
        || (status == StrictTerminalSyncStatus::UpToDate && page.transfer_id != 0)
    {
        return;
    }
    let Some(kind) = StrictTerminalPageKind::try_from(page.kind).ok() else {
        return;
    };
    let Some(target) = page.target_cut.as_ref().and_then(cut_from_wire) else {
        return;
    };
    if page.image_digest.as_ref() != target.terminal_set_digest().as_slice() {
        return;
    }
    if rt.v3_sync.lock().client(peer).is_none() {
        let duplicate_ack = StrictTerminalSyncAck {
            src_node: rt.self_id as u32,
            expected_responder_boot_epoch: epoch,
            transfer_id: page.transfer_id,
            request_nonce: page.request_nonce,
            target_cut: Some(cut_to_wire(target)),
        };
        let ack_pending = rt
            .v3_retries
            .lock()
            .final_ack_is_current(peer, &duplicate_ack);
        let source_already_advanced =
            rt.v3_sync
                .lock()
                .known_source_cut(peer)
                .is_some_and(|known| {
                    known.journal_id() == target.journal_id()
                        && known.generation() >= target.generation()
                });
        if ack_pending || source_already_advanced {
            metrics::record_strict_catchup_duplicate(StrictCatchupDuplicateOutcome::Suppressed);
        }
        return;
    }
    let (expected_progress, reducer_wire) = {
        let mut sync = rt.v3_sync.lock();
        let Some(client) = sync.client(peer) else {
            return;
        };
        let delayed_duplicate = client.pending_nonce() != page.request_nonce
            && client.transfer_id() != 0
            && client.transfer_id() == page.transfer_id
            && client.target_cut().is_some_and(|cut| cut == target)
            && client.kind().is_some_and(|expected| expected == kind)
            && page.next_cursor <= client.next_cursor();
        if delayed_duplicate {
            if let Some(delayed_wire) =
                terminal_session_wire(epoch, page.transfer_id, page.request_nonce, page.cursor)
            {
                sync.transition_session(peer, SessionEvent::MessageDelayed { wire: delayed_wire });
            }
            metrics::record_strict_catchup_duplicate(StrictCatchupDuplicateOutcome::Suppressed);
            return;
        }
        if client.pending_nonce() != page.request_nonce
            || (client.transfer_id() != 0 && client.transfer_id() != page.transfer_id)
            || (status != StrictTerminalSyncStatus::UpToDate && client.next_cursor() != page.cursor)
            || client.target_cut().is_some_and(|cut| cut != target)
            || client.kind().is_some_and(|expected| expected != kind)
            || (client.target_cut().is_none()
                && client
                    .desired_cut()
                    .is_some_and(|desired| !source_cut_covers(target, desired)))
        {
            return;
        }
        let Some(wire) = terminal_session_wire(
            epoch,
            page.transfer_id,
            page.request_nonce,
            client.next_cursor(),
        ) else {
            return;
        };
        (client.progress_cut(), wire)
    };

    if page.next_cursor < page.cursor
        || (page.has_more && page.next_cursor == page.cursor)
        || page.has_more != (page.next_cursor < target.generation())
        || (!page.has_more && page.next_cursor != target.generation())
        || (status == StrictTerminalSyncStatus::UpToDate
            && (page.has_more
                || !page.deltas.is_empty()
                || !page.checkpoint_states.is_empty()
                || page.cursor != target.generation()))
    {
        return;
    }

    if status == StrictTerminalSyncStatus::UpToDate {
        let effects = rt.v3_sync.lock().transition_session(
            peer,
            SessionEvent::PageReceived {
                kind: SessionSyncKind::Terminal,
                wire: reducer_wire,
                next_cursor: SessionCursor::new(
                    SessionCursorKind::TerminalGeneration,
                    page.next_cursor,
                ),
                target_cut: cut_to_reducer(target),
                has_more: false,
            },
        );
        if !effects.iter().any(|effect| {
            matches!(effect, SessionEffect::ValidateAndApply { kind: SessionSyncKind::Terminal, wire } if *wire == reducer_wire)
        }) {
            metrics::record_strict_catchup_duplicate(StrictCatchupDuplicateOutcome::Suppressed);
            return;
        }
        if let Some(client) = rt.v3_sync.lock().client_mut(peer) {
            client.accept_manifest(page.transfer_id, target, kind, rt.cfg.pending_propose_ttl());
        }
        if let Some(client) = rt.v3_sync.lock().client_mut(peer) {
            client.set_progress_cut(target);
        }
    } else {
        match kind {
            StrictTerminalPageKind::Delta => {
                if !page.checkpoint_states.is_empty() {
                    return;
                }
                let Some(mut progress) = page.base_cut.as_ref().and_then(cut_from_wire) else {
                    return;
                };
                if page.cursor != progress.generation()
                    || !expected_progress
                        .is_some_and(|expected| expected.has_same_chain_position(&progress))
                    || progress.journal_id() != target.journal_id()
                    || progress.generation() > target.generation()
                {
                    return;
                }
                let mut validated = Vec::with_capacity(page.deltas.len());
                for delta in &page.deltas {
                    let Some(state) = delta.state.as_ref() else {
                        return;
                    };
                    let Some((op_id, identity, decision)) = validated_v3_terminal_state(state)
                    else {
                        return;
                    };
                    if !TerminalJournal::verifies_terminal_transition(
                        &progress,
                        delta.generation,
                        op_id,
                        identity
                            .as_ref()
                            .map(|identity| identity.frozen_targets.as_slice()),
                        identity.as_ref().map(|identity| identity.resolver),
                        &decision,
                        &delta.previous_chain_digest,
                        &delta.chain_digest,
                    ) {
                        return;
                    }
                    let Ok(chain) = <[u8; 32]>::try_from(delta.chain_digest.as_ref()) else {
                        return;
                    };
                    progress = TerminalCut::new(
                        *target.journal_id(),
                        delta.generation,
                        chain,
                        if delta.generation == target.generation() {
                            *target.terminal_set_digest()
                        } else {
                            [0; 32]
                        },
                    );
                    validated.push(state.clone());
                }
                if progress.generation() != page.next_cursor {
                    return;
                }
                let effects = rt.v3_sync.lock().transition_session(
                    peer,
                    SessionEvent::PageReceived {
                        kind: SessionSyncKind::Terminal,
                        wire: reducer_wire,
                        next_cursor: SessionCursor::new(
                            SessionCursorKind::TerminalGeneration,
                            page.next_cursor,
                        ),
                        target_cut: cut_to_reducer(target),
                        has_more: page.has_more,
                    },
                );
                if !effects.iter().any(|effect| {
                    matches!(effect, SessionEffect::ValidateAndApply { kind: SessionSyncKind::Terminal, wire } if *wire == reducer_wire)
                }) {
                    metrics::record_strict_catchup_duplicate(StrictCatchupDuplicateOutcome::Suppressed);
                    return;
                }
                if let Some(client) = rt.v3_sync.lock().client_mut(peer) {
                    client.accept_manifest(
                        page.transfer_id,
                        target,
                        kind,
                        rt.cfg.pending_propose_ttl(),
                    );
                }
                for state in validated {
                    if !rt.apply_v3_catchup_terminal_state(peer, state).await {
                        fail_v3_terminal_apply(rt, peer, epoch, reducer_wire, page.request_nonce)
                            .await;
                        return;
                    }
                }
                if let Some(client) = rt.v3_sync.lock().client_mut(peer) {
                    client.set_progress_cut(progress);
                }
            }
            StrictTerminalPageKind::Checkpoint => {
                if !page.deltas.is_empty() {
                    return;
                }
                let mut progress = if page.cursor == 0 {
                    TerminalCut::new(*target.journal_id(), 0, [0; 32], [0; 32])
                } else {
                    let Some(progress) = expected_progress else {
                        return;
                    };
                    if progress.generation() != page.cursor
                        || progress.journal_id() != target.journal_id()
                    {
                        return;
                    }
                    progress
                };
                let mut validated = Vec::with_capacity(page.checkpoint_states.len());
                for state in &page.checkpoint_states {
                    let Some((op_id, identity, decision)) = validated_v3_terminal_state(state)
                    else {
                        return;
                    };
                    let generation = progress.generation().saturating_add(1);
                    let Some(chain) = TerminalJournal::terminal_transition_chain_digest(
                        &progress,
                        generation,
                        op_id,
                        identity
                            .as_ref()
                            .map(|identity| identity.frozen_targets.as_slice()),
                        identity.as_ref().map(|identity| identity.resolver),
                        &decision,
                    ) else {
                        return;
                    };
                    progress = TerminalCut::new(
                        *target.journal_id(),
                        generation,
                        chain,
                        if generation == target.generation() {
                            *target.terminal_set_digest()
                        } else {
                            [0; 32]
                        },
                    );
                    validated.push(state.clone());
                }
                if progress.generation() != page.next_cursor {
                    return;
                }
                let effects = rt.v3_sync.lock().transition_session(
                    peer,
                    SessionEvent::PageReceived {
                        kind: SessionSyncKind::Terminal,
                        wire: reducer_wire,
                        next_cursor: SessionCursor::new(
                            SessionCursorKind::TerminalGeneration,
                            page.next_cursor,
                        ),
                        target_cut: cut_to_reducer(target),
                        has_more: page.has_more,
                    },
                );
                if !effects.iter().any(|effect| {
                    matches!(effect, SessionEffect::ValidateAndApply { kind: SessionSyncKind::Terminal, wire } if *wire == reducer_wire)
                }) {
                    metrics::record_strict_catchup_duplicate(StrictCatchupDuplicateOutcome::Suppressed);
                    return;
                }
                if let Some(client) = rt.v3_sync.lock().client_mut(peer) {
                    client.accept_manifest(
                        page.transfer_id,
                        target,
                        kind,
                        rt.cfg.pending_propose_ttl(),
                    );
                }
                let exact_elected_source = {
                    rt.v3_history
                        .lock()
                        .pending_after_terminal(peer)
                        .is_some_and(|intent| {
                            intent.reason() == StrictCatchupReason::HistoryElection
                                && intent.source_cut() == target
                        })
                };
                // Checkpoint authority is fixed by the correlated election
                // intent and client start. `reason()` is only the mutable
                // operational priority after coalescing and must not grant or
                // revoke authority for this already-started transfer.
                let stage_for_elected_repository = exact_elected_source;
                if stage_for_elected_repository {
                    let staged = rt.v3_sync.lock().client_mut(peer).is_some_and(|client| {
                        client.stage_checkpoint_page(target, validated.clone())
                    });
                    if !staged {
                        fail_v3_terminal_apply(rt, peer, epoch, reducer_wire, page.request_nonce)
                            .await;
                        rearm_history_election(rt);
                        return;
                    }
                } else {
                    let unranked_repository_client =
                        rt.v3_sync.lock().client(peer).is_some_and(|client| {
                            matches!(
                                StrictCatchupReason::try_from(client.started_reason()).ok(),
                                Some(
                                    StrictCatchupReason::Admission
                                        | StrictCatchupReason::RepositoryGap
                                )
                            )
                        });
                    // A checkpoint is one complete foreign lineage. Admission
                    // and repository-gap probes are not elected sources, so
                    // they may never union any part of that image locally.
                    if unranked_repository_client {
                        fail_v3_terminal_checkpoint_client(
                            rt,
                            peer,
                            epoch,
                            reducer_wire,
                            page.request_nonce,
                        );
                        return;
                    }
                    for state in validated {
                        if !rt.apply_v3_catchup_terminal_state(peer, state).await {
                            fail_v3_terminal_apply(
                                rt,
                                peer,
                                epoch,
                                reducer_wire,
                                page.request_nonce,
                            )
                            .await;
                            return;
                        }
                    }
                }
                if let Some(client) = rt.v3_sync.lock().client_mut(peer) {
                    client.set_progress_cut(progress);
                }
            }
            StrictTerminalPageKind::Unspecified => return,
        }
    }

    let apply_effects = rt.v3_sync.lock().transition_session(
        peer,
        SessionEvent::ApplySucceeded {
            epoch: SessionPeerEpoch::new(epoch),
            wire: reducer_wire,
        },
    );

    // The complete correlated page is durable locally. Any subsequent retry
    // must now refer to the next cursor (or the final ACK), never this page.
    rt.v3_retries
        .lock()
        .complete_request(peer, page.request_nonce);

    if page.has_more {
        let Some(continuation_wire) = terminal_effect_wire(&apply_effects, |effect| match effect {
            SessionEffect::Continue {
                kind: SessionSyncKind::Terminal,
                wire,
            } => Some(*wire),
            _ => None,
        }) else {
            return;
        };
        let (nonce, transfer_id, reason) = {
            let mut sync = rt.v3_sync.lock();
            let Some(client) = sync.client_mut(peer) else {
                return;
            };
            client.prepare_continuation(
                continuation_wire.nonce().get(),
                continuation_wire.cursor().value(),
            );
            (
                continuation_wire.nonce().get(),
                continuation_wire.transfer().get(),
                client.reason(),
            )
        };
        let known_source_cut = rt.v3_sync.lock().known_source_cut(peer).map(cut_to_wire);
        let requester_terminal_set_digest = Bytes::copy_from_slice(
            rt.terminal_journal
                .lock()
                .await
                .terminal_cut()
                .terminal_set_digest(),
        );
        let request = StrictTerminalSyncReq {
            src_node: rt.self_id as u32,
            expected_responder_boot_epoch: epoch,
            reason,
            known_source_cut,
            requester_terminal_set_digest,
            transfer_id,
            request_nonce: nonce,
            expected_cursor: page.next_cursor,
        };
        rt.v3_retries.lock().register_request(
            peer,
            request.clone(),
            rt.cfg.bulk_retry_delay(),
            rt.cfg.pending_propose_ttl(),
            rt.cfg.strict_bulk_retry_jitter_pct(),
            v3_retry_salt(rt.self_id, &rt.topic),
        );
        let metric_reason =
            CatchupReason::from_v3_wire(reason).unwrap_or(CatchupReason::TerminalFence);
        let send_result = send_v3_metadata_control(
            rt,
            from,
            StrictBody::TerminalSyncReq(request),
            metric_reason,
            CatchupPhase::Metadata,
        )
        .await;
        record_terminal_send_result(rt, peer, continuation_wire, &send_result);
        return;
    }

    let source_chain_complete = rt
        .v3_sync
        .lock()
        .client(peer)
        .and_then(|client| client.progress_cut())
        .is_some_and(|progress| progress.has_same_chain_position(&target));
    if !source_chain_complete {
        return;
    }

    let completed = {
        let mut sync = rt.v3_sync.lock();
        let staged = sync.publish_staged_checkpoint(peer, target);
        if !staged {
            sync.remember_source_cut(peer, target);
        }
        sync.begin_client_finalization(peer)
    };
    let Some(completed) = completed else {
        // A concurrently delivered copy may have passed the initial client
        // check before the first copy completed the session. Only the winner
        // owns completion, continuation, and active-gauge accounting.
        metrics::record_strict_catchup_duplicate(StrictCatchupDuplicateOutcome::Suppressed);
        return;
    };
    let completed_reason = CatchupReason::from_v3_wire(completed.started_reason())
        .unwrap_or(CatchupReason::TerminalFence);
    let follow_up_reason = StrictCatchupReason::try_from(completed.reason())
        .ok()
        .unwrap_or(StrictCatchupReason::TerminalFence);
    let inherited_metric_reason = StrictCatchupReason::try_from(completed.started_reason())
        .ok()
        .unwrap_or(StrictCatchupReason::TerminalFence);
    if page.transfer_id == 0 {
        rt.v3_sync.lock().finish_client_finalization(
            peer,
            page.transfer_id,
            page.request_nonce,
            target,
        );
        let dirty_wire = terminal_start_wire(&apply_effects);
        if let Some(dirty_wire) = dirty_wire.filter(|_| completed.dirty()) {
            metrics::record_strict_catchup_session_completion(
                completed_reason,
                StrictCatchupSessionOutcome::Completed,
            );
            metrics::record_strict_catchup_session_event(
                completed_reason,
                StrictCatchupSessionEvent::DirtyRefresh,
            );
            let reason = completed
                .dirty()
                .then_some(follow_up_reason)
                .unwrap_or(StrictCatchupReason::TerminalFence);
            let desired_cut = completed.dirty().then(|| completed.desired_cut()).flatten();
            start_reducer_owned_terminal_client(rt, peer, reason, desired_cut, dirty_wire).await;
        } else {
            if let Some(covered_wire) = dirty_wire {
                // The payload coordinator observed this trigger before the
                // responder fixed its manifest, so the completed target
                // already covers it. Retire the reducer-only follow-up before
                // handing the elected checkpoint to repository replacement.
                cancel_covered_terminal_followup(rt, peer, epoch, covered_wire);
            }
            if !start_v3_repository_after_terminal(rt, peer, Some(inherited_metric_reason)).await {
                metrics::record_strict_catchup_session_completion(
                    completed_reason,
                    StrictCatchupSessionOutcome::Completed,
                );
            }
        }
        return;
    }
    let ack = StrictTerminalSyncAck {
        src_node: rt.self_id as u32,
        expected_responder_boot_epoch: epoch,
        transfer_id: page.transfer_id,
        request_nonce: page.request_nonce,
        target_cut: Some(cut_to_wire(target)),
    };
    rt.v3_retries.lock().register_final_ack(
        peer,
        ack.clone(),
        rt.cfg.bulk_retry_delay(),
        rt.cfg.pending_propose_ttl(),
        rt.cfg.strict_bulk_retry_jitter_pct(),
        v3_retry_salt(rt.self_id, &rt.topic),
    );
    metrics::record_strict_catchup_session_event(
        completed_reason,
        StrictCatchupSessionEvent::FinalAck,
    );
    let final_ack_wire = terminal_session_wire(
        epoch,
        page.transfer_id,
        page.request_nonce,
        page.next_cursor,
    )
    .expect("validated terminal final ACK identity");
    let send_result = send_v3_metadata_control(
        rt,
        from,
        StrictBody::TerminalSyncAck(ack),
        completed_reason,
        CatchupPhase::FinalAck,
    )
    .await;
    record_terminal_send_result(rt, peer, final_ack_wire, &send_result);
}

pub(super) async fn recv_v3_terminal_sync_ack<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    ack: StrictTerminalSyncAck,
) {
    let Some(peer) = v3_peer(rt, from, epoch) else {
        return;
    };
    let Some(target) = ack.target_cut.as_ref().and_then(cut_from_wire) else {
        return;
    };
    if node_from_u32(ack.src_node) != Some(from)
        || ack.expected_responder_boot_epoch != rt.boot_epoch
    {
        return;
    }
    let responder_active = rt.v3_sync.lock().responder(peer).is_some();
    let mut responder_completion_effects = Vec::new();
    if responder_active {
        let Some(wire) = terminal_session_wire(
            epoch,
            ack.transfer_id,
            ack.request_nonce,
            target.generation(),
        ) else {
            return;
        };
        responder_completion_effects = rt.v3_sync.lock().transition_session(
            peer,
            SessionEvent::AckReceived {
                epoch: SessionPeerEpoch::new(epoch),
                wire,
                cut: cut_to_reducer(target),
            },
        );
        if !responder_completion_effects
            .iter()
            .any(|effect| matches!(effect, SessionEffect::ReleaseBulk { .. }))
        {
            return;
        }
    }
    let accepted = rt.v3_sync.lock().acknowledge_responder(
        peer,
        ack.transfer_id,
        ack.request_nonce,
        target,
        rt.cfg.pending_propose_ttl(),
    );
    if accepted {
        rt.net.acknowledge_bulk_unicast(
            from,
            &rt.topic,
            BulkPageIdentity::terminal(ack.transfer_id, ack.request_nonce),
        );
        let confirmation = StrictTerminalSyncAck {
            src_node: rt.self_id as u32,
            expected_responder_boot_epoch: epoch,
            transfer_id: ack.transfer_id,
            request_nonce: ack.request_nonce,
            target_cut: Some(cut_to_wire(target)),
        };
        let _ = send_v3_metadata_control(
            rt,
            from,
            StrictBody::TerminalSyncAck(confirmation),
            CatchupReason::TerminalFence,
            CatchupPhase::FinalAck,
        )
        .await;
        if let Some(dirty_wire) = terminal_start_wire(&responder_completion_effects) {
            let deferred = rt.v3_sync.lock().take_deferred_client(peer);
            let (reason, desired_cut) = deferred
                .map(|(reason, desired_cut)| {
                    (
                        StrictCatchupReason::try_from(reason)
                            .ok()
                            .unwrap_or(StrictCatchupReason::TerminalFence),
                        desired_cut,
                    )
                })
                .unwrap_or((StrictCatchupReason::TerminalFence, None));
            start_reducer_owned_terminal_client(rt, peer, reason, desired_cut, dirty_wire).await;
        } else {
            resume_deferred_v3_terminal_sync(rt, peer).await;
        }
        return;
    }

    let completed = rt.v3_sync.lock().finish_client_finalization(
        peer,
        ack.transfer_id,
        ack.request_nonce,
        target,
    );
    let Some(completed) = completed else {
        return;
    };
    rt.v3_retries
        .lock()
        .complete_final_ack(peer, ack.transfer_id, ack.request_nonce);
    let final_wire = terminal_session_wire(
        epoch,
        ack.transfer_id,
        ack.request_nonce,
        target.generation(),
    )
    .expect("validated terminal final ACK nonce");
    let final_effects = rt.v3_sync.lock().transition_session(
        peer,
        SessionEvent::FinalAckDelivered {
            epoch: SessionPeerEpoch::new(epoch),
            wire: final_wire,
        },
    );

    let completed_reason = CatchupReason::from_v3_wire(completed.started_reason())
        .unwrap_or(CatchupReason::TerminalFence);
    let follow_up_reason = StrictCatchupReason::try_from(completed.reason())
        .ok()
        .unwrap_or(StrictCatchupReason::TerminalFence);
    let inherited_metric_reason = StrictCatchupReason::try_from(completed.started_reason())
        .ok()
        .unwrap_or(StrictCatchupReason::TerminalFence);
    let dirty_wire = terminal_start_wire(&final_effects);
    if let Some(dirty_wire) = dirty_wire.filter(|_| completed.dirty()) {
        metrics::record_strict_catchup_session_completion(
            completed_reason,
            StrictCatchupSessionOutcome::Completed,
        );
        metrics::record_strict_catchup_session_event(
            completed_reason,
            StrictCatchupSessionEvent::DirtyRefresh,
        );
        let reason = completed
            .dirty()
            .then_some(follow_up_reason)
            .unwrap_or(StrictCatchupReason::TerminalFence);
        let desired_cut = completed.dirty().then(|| completed.desired_cut()).flatten();
        start_reducer_owned_terminal_client(rt, peer, reason, desired_cut, dirty_wire).await;
    } else {
        if let Some(covered_wire) = dirty_wire {
            // Keep reducer and payload coalescing aligned: a trigger merged
            // before the manifest was accepted is covered by this target and
            // must not delay the elected repository replacement.
            cancel_covered_terminal_followup(rt, peer, epoch, covered_wire);
        }
        if !start_v3_repository_after_terminal(rt, peer, Some(inherited_metric_reason)).await {
            metrics::record_strict_catchup_session_completion(
                completed_reason,
                StrictCatchupSessionOutcome::Completed,
            );
        }
    }
}

struct CatchupStrictMetadata {
    metadata: StrictLogMetadata,
    terminal_proof: Option<TerminalCommitProof>,
}

fn strict_metadata(op: &CatchupOp) -> Result<Option<CatchupStrictMetadata>, ()> {
    if op.strict_op_id_hi == 0 && op.strict_op_id_lo == 0 && op.strict_ts_final == 0 {
        return (op.strict_terminal_ballot == 0
            && op.strict_terminal_resolver_node == 0
            && op.strict_terminal_resolver_boot_epoch == 0
            && op.strict_terminal_frozen_targets.is_empty())
        .then_some(None)
        .ok_or(());
    }
    let metadata = StrictLogMetadata {
        op_id_hi: op.strict_op_id_hi,
        op_id_lo: op.strict_op_id_lo,
        ts_final: op.strict_ts_final,
    };
    let proof_fields_present = op.strict_terminal_ballot != 0
        || op.strict_terminal_resolver_node != 0
        || op.strict_terminal_resolver_boot_epoch != 0
        || !op.strict_terminal_frozen_targets.is_empty();
    let terminal_proof = if proof_fields_present {
        let coord = super::runtime::node_from_u32((metadata.op_id_hi >> 48) as u32).ok_or(())?;
        let identity = terminal_identity_from_wire(
            op.strict_terminal_resolver_node,
            op.strict_terminal_resolver_boot_epoch,
            &op.strict_terminal_frozen_targets,
            op.strict_terminal_ballot,
            (metadata.op_id_hi, metadata.op_id_lo),
            coord,
        )?
        .ok_or(())?;
        Some(TerminalCommitProof {
            ballot: op.strict_terminal_ballot,
            identity,
        })
    } else {
        None
    };
    Ok(Some(CatchupStrictMetadata {
        metadata,
        terminal_proof,
    }))
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicI64, Ordering},
        },
        time::{Duration, Instant},
    };

    use bytes::Bytes;
    use tokio_util::sync::CancellationToken;

    use super::{
        StrictReplicable, apply_response, request_next_snapshot_chunk, respond_to_request,
    };
    use crate::overlay::MemberIncarnation;
    use crate::replications::{
        config::ReplicationConfig,
        proto::{
            CatchupOp, StrictBody, StrictCatchupReason, StrictCatchupReq, StrictCatchupResp,
            StrictDecisionAbort, StrictHistoryProbeResp, StrictHistoryTransferResp,
            StrictResolutionPrepare, StrictTerminalOutcome, StrictTerminalState,
            StrictTerminalSyncPage, StrictTerminalSyncStatus,
        },
        strict::{
            runtime::{
                HistoryRank, STRICT_PROTOCOL_VERSION_V4, STRICT_PROTOCOL_VERSION_V5, StrictRuntime,
                make_op_id,
            },
            sync_v3::PeerIncarnation,
            terminal_journal::{FrozenTarget, TerminalJournal, TerminalResolver},
        },
        test_support::{CapturedFrame, CountingStrictRepo, MockNet},
    };
    use shitspeak_core::NodeIdentifier;

    fn test_runtime(
        self_id: NodeIdentifier,
        cfg: ReplicationConfig,
    ) -> (
        Arc<StrictRuntime<CountingStrictRepo>>,
        Arc<MockNet>,
        Arc<CountingStrictRepo>,
    ) {
        let net = MockNet::new(self_id, vec![1, 2]);
        // V4 participants retain the internal V2 terminal/snapshot contract.
        // Keep the shared fixture participant-supported; individual legacy
        // rejection tests explicitly lower the relevant peer advertisement.
        net.set_strict_replication_protocol_version(super::STRICT_PROTOCOL_VERSION_V5);
        net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V4));
        for peer in [1, 2, 3] {
            net.set_peer_strict_replication_protocol_version(peer, STRICT_PROTOCOL_VERSION_V4);
        }
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo.clone(),
            self_id,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(cfg),
        );
        rt.finish_history_election_for_test();
        (rt, net, repo)
    }

    fn terminal_abort(op_id: (u64, u64)) -> StrictTerminalState {
        StrictTerminalState {
            coord_node: 1,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            ballot: 10,
            outcome: Some(StrictTerminalOutcome::Abort(StrictDecisionAbort {})),
            resolver_node: 0,
            resolver_boot_epoch: 0,
            frozen_targets: Vec::new(),
        }
    }

    fn begin_correlated_history(
        rt: &StrictRuntime<CountingStrictRepo>,
        net: &MockNet,
        source: NodeIdentifier,
        source_epoch: u64,
        target_version: u64,
        reason: StrictCatchupReason,
    ) -> (PeerIncarnation, StrictHistoryTransferResp) {
        net.set_epoch(source, source_epoch);
        net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V5));
        net.set_peer_strict_replication_protocol_version(source, STRICT_PROTOCOL_VERSION_V5);
        let peer = PeerIncarnation::new(source, source_epoch);
        let request = rt
            .v3_history
            .lock()
            .begin_transfer(
                peer,
                target_version,
                rt.repo.current_version(),
                reason,
                rt.cfg.pending_propose_ttl(),
                false,
                reason,
            )
            .expect("correlated history transfer")
            .into_parts()
            .0;
        (
            peer,
            StrictHistoryTransferResp {
                expected_requester_boot_epoch: rt.boot_epoch,
                transfer_id: request.transfer_id,
                request_nonce: request.request_nonce,
                cursor: request.expected_cursor,
                target_version: request.target_version,
            },
        )
    }

    fn correlated_history_response(
        source: NodeIdentifier,
        transfer: StrictHistoryTransferResp,
        target_version: u64,
    ) -> StrictCatchupResp {
        StrictCatchupResp {
            history_version: target_version,
            history_node: source as u32,
            next_terminal_state_cursor: super::TERMINAL_STATE_CURSOR_SKIP,
            history_transfer: Some(transfer),
            ..Default::default()
        }
    }

    fn catchup_response(capture: CapturedFrame) -> StrictCatchupResp {
        let CapturedFrame::StrictUnicast { dst, body, .. } = capture else {
            panic!("expected strict unicast catchup response");
        };
        assert_eq!(dst, 2);
        let StrictBody::CatchupResp(resp) = body else {
            panic!("expected catchup response, got {body:?}");
        };
        resp
    }

    #[tokio::test]
    async fn correlated_history_terminal_install_failure_releases_client_and_rearms() {
        let (rt, net, _repo) = test_runtime(2, ReplicationConfig::default());
        let (peer, transfer) =
            begin_correlated_history(&rt, &net, 1, 11, 1, StrictCatchupReason::RepositoryGap);
        let mut response = correlated_history_response(1, transfer, 1);
        response
            .terminal_states
            .push(StrictTerminalState::default());

        apply_response(&rt, 1, response).await;

        assert!(!rt.v3_history.lock().has_active_transfer(peer));
        assert!(rt.state.lock().history_election_pending());
    }

    #[tokio::test]
    async fn correlated_history_malformed_op_releases_client_and_rearms() {
        let (rt, net, _repo) = test_runtime(2, ReplicationConfig::default());
        let (peer, transfer) =
            begin_correlated_history(&rt, &net, 1, 11, 1, StrictCatchupReason::RepositoryGap);
        let mut response = correlated_history_response(1, transfer, 1);
        response.ops.push(CatchupOp {
            version: 1,
            // 0xc1 is the reserved MessagePack marker and cannot decode as
            // the repository's u64 operation type.
            op_msgpack: Bytes::from_static(&[0xc1]),
            ..Default::default()
        });

        apply_response(&rt, 1, response).await;

        assert!(!rt.v3_history.lock().has_active_transfer(peer));
        assert!(rt.state.lock().history_election_pending());
    }

    #[tokio::test]
    async fn correlated_history_unavailable_continuation_releases_client_and_rearms() {
        let (rt, net, _repo) = test_runtime(2, ReplicationConfig::default());
        let (peer, transfer) =
            begin_correlated_history(&rt, &net, 1, 11, 1, StrictCatchupReason::RepositoryGap);
        net.set_reliable_routes([2]);
        let mut response = correlated_history_response(1, transfer, 1);
        response.ops.push(CatchupOp {
            // A duplicate is sufficient to reach continuation selection
            // without mutating repository state.
            version: 0,
            op_msgpack: Bytes::from(rmp_serde::to_vec(&7u64).unwrap()),
            ..Default::default()
        });
        response.has_more = true;
        response.next_chunk_token = 1;

        apply_response(&rt, 1, response).await;

        assert!(!rt.v3_history.lock().has_active_transfer(peer));
        assert!(rt.state.lock().history_election_pending());
    }

    #[tokio::test]
    async fn correlated_stale_snapshot_page_releases_client_and_rearms_current_election() {
        let (rt, net, _repo) = test_runtime(2, ReplicationConfig::default());
        begin_snapshot_fetch(&rt, 1);
        let (peer, transfer) =
            begin_correlated_history(&rt, &net, 1, 11, 1, StrictCatchupReason::HistoryElection);
        let chunk = Bytes::from_static(b"x");
        let mut response = correlated_history_response(1, transfer, 1);
        response.snapshot_version = 1;
        response.snapshot_msgpack = chunk;
        response.too_old_use_snapshot = true;
        response.request_force_snapshot = true;
        response.snapshot_transfer_id = 7;
        response.snapshot_chunk_cursor = 1;
        response.snapshot_next_cursor = 2;
        response.snapshot_total_bytes = 2;
        response.snapshot_sha256 = Bytes::from(vec![0x11; 32]);
        response.snapshot_has_more = false;

        apply_response(&rt, 1, response).await;

        assert!(!rt.v3_history.lock().has_active_transfer(peer));
        let state = rt.state.lock();
        assert!(state.history_election_pending());
        assert!(state.history_election_fetching_snapshot().is_none());
    }

    #[tokio::test]
    async fn correlated_duplicate_snapshot_page_releases_client_and_rearms_current_election() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 96, 4_000);
        let (sink, sink_net, _sink_repo) = test_runtime(2, cfg);
        begin_snapshot_fetch(&sink, 96);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first = catchup_response(source_net.drain_captures().pop().unwrap());
        apply_response(&sink, 1, first.clone()).await;
        sink_net.drain_captures();

        let (peer, transfer) = begin_correlated_history(
            &sink,
            &sink_net,
            1,
            11,
            96,
            StrictCatchupReason::HistoryElection,
        );
        let mut duplicate = first;
        duplicate.history_transfer = Some(transfer);
        apply_response(&sink, 1, duplicate).await;

        assert!(!sink.v3_history.lock().has_active_transfer(peer));
        assert!(!sink.snapshot_receivers.lock().contains_key(&1));
        let state = sink.state.lock();
        assert!(state.history_election_pending());
        assert!(state.history_election_fetching_snapshot().is_none());
    }

    #[tokio::test]
    async fn correlated_history_invalid_snapshot_envelope_releases_client_and_rearms() {
        let (rt, net, _repo) = test_runtime(2, ReplicationConfig::default());
        let remote_rank = super::HistoryRank {
            version: 1,
            freshness: 2,
            runtime_started_at: 3,
            node_id: 1,
            terminal_repository_base_version: 0,
        };
        let local_rank = super::HistoryRank::local(&rt);
        {
            let mut state = rt.state.lock();
            state.request_history_election();
            state.begin_history_election([1]);
            assert!(matches!(
                state.record_history_probe_response(1, remote_rank, local_rank),
                super::HistoryProbeResponseOutcome::FetchSnapshot(_)
            ));
        }
        let (peer, transfer) =
            begin_correlated_history(&rt, &net, 1, 11, 1, StrictCatchupReason::HistoryElection);
        let mut response = correlated_history_response(1, transfer, 1);
        response.history_freshness = remote_rank.freshness;
        response.runtime_started_at = remote_rank.runtime_started_at;
        response.snapshot_version = remote_rank.version;
        response.snapshot_msgpack = Bytes::from_static(b"invalid-v5-envelope");
        response.too_old_use_snapshot = true;
        response.request_force_snapshot = true;

        apply_response(&rt, 1, response).await;

        assert!(!rt.v3_history.lock().has_active_transfer(peer));
        assert!(rt.state.lock().history_election_pending());
    }

    fn catchup_request(capture: CapturedFrame) -> StrictCatchupReq {
        let CapturedFrame::StrictUnicast { dst, body, .. } = capture else {
            panic!("expected strict unicast catchup request");
        };
        assert_eq!(dst, 1);
        let StrictBody::CatchupReq(req) = body else {
            panic!("expected catchup request, got {body:?}");
        };
        req
    }

    fn force_snapshot_request() -> StrictCatchupReq {
        StrictCatchupReq {
            src_node: 2,
            since_version: 0,
            chunk_token: super::HISTORY_ELECTION_SNAPSHOT_TOKEN,
            force_snapshot: true,
            history_probe_only: false,
            terminal_state_cursor: 0,
            terminal_decision_generation: 0,
            snapshot_transfer_id: 0,
            snapshot_chunk_cursor: 0,
            history_transfer: None,
        }
    }

    struct SnapshotFreshnessRepo {
        version: u64,
        captured_freshness: i64,
        advertised_freshness: AtomicI64,
    }

    struct EnvelopeShapedRawRepo {
        install_attempts: parking_lot::Mutex<Vec<Bytes>>,
    }

    #[async_trait::async_trait]
    impl StrictReplicable for EnvelopeShapedRawRepo {
        type Op = u64;

        fn strict_replication_protocol_version(&self) -> u32 {
            super::STRICT_PROTOCOL_VERSION_V2
        }

        fn current_version(&self) -> u64 {
            0
        }

        fn snapshot_with_metadata(
            &self,
        ) -> Result<(super::HistoryMetadata, Bytes), crate::replications::strict::StrictSnapshotError>
        {
            unreachable!("receiver-only test repository")
        }

        fn log_since(
            &self,
            _since: u64,
        ) -> crate::replications::strict::LogSlice<
            crate::replications::strict::StrictLogEntry<Self::Op>,
        > {
            crate::replications::strict::LogSlice::TooOld
        }

        async fn apply_committed(&self, _version: u64, _op: Self::Op) {}

        async fn install_snapshot(
            &self,
            _version: u64,
            snapshot: Bytes,
        ) -> Result<(), crate::replications::strict::StrictSnapshotError> {
            self.install_attempts.lock().push(snapshot);
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl StrictReplicable for SnapshotFreshnessRepo {
        type Op = u64;

        fn strict_replication_protocol_version(&self) -> u32 {
            super::STRICT_PROTOCOL_VERSION_V2
        }

        fn current_version(&self) -> u64 {
            self.version
        }

        fn history_metadata(&self) -> super::HistoryMetadata {
            super::HistoryMetadata {
                version: self.version,
                freshness: self.advertised_freshness.load(Ordering::Acquire),
            }
        }

        fn snapshot_with_metadata(
            &self,
        ) -> Result<(super::HistoryMetadata, Bytes), crate::replications::strict::StrictSnapshotError>
        {
            let snapshot = rmp_serde::to_vec(&(self.version, self.captured_freshness))
                .map(Bytes::from)
                .map_err(|error| {
                    crate::replications::strict::StrictSnapshotError::new(format!(
                        "test snapshot encode failed: {error}"
                    ))
                })?;
            Ok((
                super::HistoryMetadata {
                    version: self.version,
                    freshness: self.captured_freshness,
                },
                snapshot,
            ))
        }

        fn log_since(
            &self,
            since: u64,
        ) -> crate::replications::strict::LogSlice<
            crate::replications::strict::StrictLogEntry<Self::Op>,
        > {
            if since >= self.version {
                crate::replications::strict::LogSlice::Available(Vec::new())
            } else {
                crate::replications::strict::LogSlice::TooOld
            }
        }

        async fn apply_committed(&self, _version: u64, _op: Self::Op) {}

        async fn install_snapshot(
            &self,
            version: u64,
            snapshot: Bytes,
        ) -> Result<(), crate::replications::strict::StrictSnapshotError> {
            let (snapshot_version, snapshot_freshness): (u64, i64) =
                rmp_serde::from_slice(&snapshot).map_err(|error| {
                    crate::replications::strict::StrictSnapshotError::new(format!(
                        "test snapshot decode failed: {error}"
                    ))
                })?;
            if snapshot_version != version || snapshot_version != self.version {
                return Err(crate::replications::strict::StrictSnapshotError::new(
                    "test snapshot version mismatch",
                ));
            }
            self.advertised_freshness
                .store(snapshot_freshness, Ordering::Release);
            Ok(())
        }
    }

    #[tokio::test]
    async fn snapshot_response_advertises_freshness_captured_with_its_bytes() {
        const CAPTURED_FRESHNESS: i64 = 41;
        const LATER_FRESHNESS: i64 = 42;

        for peer_protocol in [1, super::STRICT_PROTOCOL_VERSION_V2] {
            let net = MockNet::new(1, vec![1, 2]);
            net.set_strict_replication_protocol_version(super::STRICT_PROTOCOL_VERSION_V2);
            net.set_local_strict_replication_protocol_version(Some(
                super::STRICT_PROTOCOL_VERSION_V2,
            ));
            net.set_peer_strict_replication_protocol_version(2, peer_protocol);
            let repo = Arc::new(SnapshotFreshnessRepo {
                version: 7,
                captured_freshness: CAPTURED_FRESHNESS,
                advertised_freshness: AtomicI64::new(LATER_FRESHNESS),
            });
            let source = StrictRuntime::new(
                repo,
                1,
                1,
                "channels".to_owned(),
                net.clone(),
                CancellationToken::new(),
                Arc::new(ReplicationConfig::default()),
            );
            source.finish_history_election_for_test();

            respond_to_request(&source, 2, force_snapshot_request()).await;

            let response = catchup_response(net.drain_captures().pop().unwrap());
            assert_eq!(response.snapshot_version, 7);
            assert_eq!(
                response.history_freshness, CAPTURED_FRESHNESS,
                "protocol {peer_protocol} snapshot rank must describe the same repository image as its bytes"
            );
        }
    }

    fn begin_snapshot_fetch(rt: &StrictRuntime<CountingStrictRepo>, version: u64) {
        let remote_rank = super::HistoryRank {
            version,
            freshness: 0,
            runtime_started_at: 1,
            node_id: 1,
            terminal_repository_base_version: 0,
        };
        let local_rank = super::HistoryRank::local(rt);
        let mut state = rt.state.lock();
        state.request_history_election();
        state.begin_history_election([1]);
        assert!(matches!(
            state.record_history_probe_response(1, remote_rank, local_rank),
            super::HistoryProbeResponseOutcome::FetchSnapshot(_)
        ));
    }

    fn populate_repo(repo: &CountingStrictRepo, version: u64, salt: u64) {
        let mut state = repo.state.lock();
        state.0 = version;
        state.1 = (1..=version)
            .map(|entry| (entry, salt + entry, None))
            .collect();
    }

    fn configure_v5_peer(local_net: &MockNet, local: NodeIdentifier, peer: NodeIdentifier) {
        local_net.set_epoch(local, 1);
        local_net.set_epoch(peer, 1);
        local_net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V5));
        local_net.set_peer_strict_replication_protocol_version(peer, STRICT_PROTOCOL_VERSION_V5);
    }

    async fn elected_checkpoint_page(
        source: &StrictRuntime<CountingStrictRepo>,
        source_net: &MockNet,
        sink: &StrictRuntime<CountingStrictRepo>,
        sink_net: &MockNet,
    ) -> StrictTerminalSyncPage {
        {
            let mut state = sink.state.lock();
            state.request_history_election();
            state.begin_history_election([source.self_id]);
        }
        super::request_v3_history_probe(
            sink,
            source.self_id,
            super::StrictCatchupReason::HistoryElection,
        )
        .await;
        let request = sink_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    body: StrictBody::HistoryProbeReq(request),
                    ..
                } => Some(request),
                _ => None,
            })
            .expect("history election request");
        super::recv_v3_history_probe_req(source, sink.self_id, 1, request).await;
        let response = source_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    body: StrictBody::HistoryProbeResp(response),
                    ..
                } => Some(response),
                _ => None,
            })
            .expect("history election response");
        super::recv_v3_history_probe_resp(sink, source.self_id, 1, response).await;
        let request = sink_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    body: StrictBody::TerminalSyncReq(request),
                    ..
                } => Some(request),
                _ => None,
            })
            .expect("elected terminal checkpoint request");
        assert!(request.known_source_cut.is_none());
        super::recv_v3_terminal_sync_req(source, sink.self_id, 1, request).await;
        source_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    body: StrictBody::TerminalSyncPage(page),
                    ..
                } => Some(page),
                _ => None,
            })
            .expect("elected terminal checkpoint page")
    }

    async fn finish_terminal_checkpoint_handshake(
        source: &StrictRuntime<CountingStrictRepo>,
        source_net: &MockNet,
        sink: &StrictRuntime<CountingStrictRepo>,
        sink_net: &MockNet,
        page: StrictTerminalSyncPage,
    ) {
        super::recv_v3_terminal_sync_page(sink, source.self_id, 1, page).await;
        let ack = sink_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    body: StrictBody::TerminalSyncAck(ack),
                    ..
                } => Some(ack),
                _ => None,
            })
            .expect("terminal checkpoint ack");
        super::recv_v3_terminal_sync_ack(source, sink.self_id, 1, ack).await;
        let confirmation = source_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    body: StrictBody::TerminalSyncAck(ack),
                    ..
                } => Some(ack),
                _ => None,
            })
            .expect("terminal checkpoint ack confirmation");
        super::recv_v3_terminal_sync_ack(sink, source.self_id, 1, confirmation).await;
    }

    fn proofless_catchup_response(
        op_id: (u64, u64),
        ts_final: u64,
        value: u64,
    ) -> StrictCatchupResp {
        StrictCatchupResp {
            ops: vec![CatchupOp {
                version: 1,
                op_msgpack: Bytes::from(rmp_serde::to_vec(&value).unwrap()),
                strict_op_id_hi: op_id.0,
                strict_op_id_lo: op_id.1,
                strict_ts_final: ts_final,
                strict_terminal_ballot: 0,
                strict_terminal_resolver_node: 0,
                strict_terminal_resolver_boot_epoch: 0,
                strict_terminal_frozen_targets: Vec::new(),
            }],
            next_chunk_token: 1,
            history_version: 1,
            runtime_started_at: 1,
            history_node: 1,
            next_terminal_state_cursor: super::TERMINAL_STATE_CURSOR_SKIP,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn generation_zero_terminal_digest_mismatch_starts_sync_before_admission() {
        let (rt, net, repo) = test_runtime(1, ReplicationConfig::default());
        *repo.state.lock() = (1, vec![(1, 1, None)]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 1);
        net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V4));
        net.set_peer_strict_replication_protocol_version(2, STRICT_PROTOCOL_VERSION_V4);
        rt.seed_membership_snapshot([MemberIncarnation::new(1, 1), MemberIncarnation::new(2, 1)]);
        assert!(!rt.peer_incarnation_is_admitted(2, 1));

        let peer = PeerIncarnation::new(2, 1);
        let request_nonce = rt
            .v3_sync
            .lock()
            .record_history_nonce(
                peer,
                super::StrictCatchupReason::Admission as i32,
                rt.cfg.pending_propose_ttl(),
            )
            .expect("admission history nonce");
        let mut checkpointed = TerminalJournal::in_memory("channels");
        checkpointed
            .upsert_abort_decision(make_op_id(2, 1, 1), 1)
            .expect("remote terminal abort");
        checkpointed.checkpoint(1).expect("remote checkpoint");
        let remote_cut = checkpointed.terminal_cut();
        assert_eq!(remote_cut.generation(), 0);
        assert_ne!(
            remote_cut.terminal_set_digest(),
            rt.terminal_journal
                .lock()
                .await
                .terminal_cut()
                .terminal_set_digest()
        );
        net.drain_captures();

        super::recv_v3_history_probe_resp(
            &rt,
            2,
            1,
            StrictHistoryProbeResp {
                responder_node: 2,
                expected_requester_boot_epoch: 1,
                request_nonce,
                repository_version: repo.current_version(),
                terminal_repository_base_version: 1,
                history_freshness: repo.history_metadata().freshness,
                runtime_started_at: 1,
                history_node: 2,
                terminal_cut: Some(super::cut_to_wire(remote_cut)),
                reason: super::StrictCatchupReason::Admission as i32,
            },
        )
        .await;

        assert!(
            !rt.peer_incarnation_is_admitted(2, 1),
            "a mismatched terminal-set checkpoint cannot satisfy admission"
        );
        assert!(
            net.drain_captures().into_iter().any(|frame| matches!(
                frame,
                CapturedFrame::StrictUnicast {
                    dst: 2,
                    body: StrictBody::TerminalSyncReq(_),
                    ..
                }
            )),
            "generation zero with a different terminal-set digest must start checkpoint sync"
        );
    }

    #[tokio::test]
    async fn deferred_foreign_checkpoint_admission_rearms_without_failed_session() {
        let (rt, net, repo) = test_runtime(1, ReplicationConfig::default());
        *repo.state.lock() = (1, vec![(1, 1, None)]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 1);
        net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V4));
        net.set_peer_strict_replication_protocol_version(2, STRICT_PROTOCOL_VERSION_V4);
        rt.seed_membership_snapshot([MemberIncarnation::new(1, 1), MemberIncarnation::new(2, 1)]);

        let mut checkpointed = TerminalJournal::in_memory("channels");
        checkpointed
            .upsert_abort_decision(make_op_id(2, 1, 1), 1)
            .expect("remote terminal abort");
        checkpointed.checkpoint(1).expect("remote checkpoint");
        let remote_cut = checkpointed.terminal_cut();
        let peer = PeerIncarnation::new(2, 1);
        rt.state.lock().request_history_election();
        rt.v3_history.lock().defer_admission(
            peer,
            HistoryRank {
                version: repo.current_version(),
                freshness: repo.history_metadata().freshness,
                runtime_started_at: 1,
                node_id: 2,
                terminal_repository_base_version: 1,
            },
            remote_cut,
        );

        // Model a probe election that timed out after retaining the admission
        // side obligation. The admission cut freezes on the next production
        // reconciliation before the retained response is resumed.
        rt.state.lock().finish_history_election();
        assert!(!rt.peer_incarnation_is_admitted(2, 1));
        net.drain_captures();

        super::resume_deferred_v3_admissions(&rt).await;

        assert!(rt.state.lock().history_election_pending());
        assert!(rt.v3_sync.lock().client(peer).is_none());
        assert!(
            net.drain_captures().into_iter().all(|frame| !matches!(
                frame,
                CapturedFrame::StrictUnicast {
                    dst: 2,
                    body: StrictBody::TerminalSyncReq(_),
                    ..
                }
            )),
            "retained admission metadata must not start an unranked checkpoint session that can only fail and rearm the same election"
        );

        rt.state.lock().finish_history_election();
        assert!(!rt.peer_incarnation_is_admitted(2, 1));
        super::resume_deferred_v3_admissions(&rt).await;
        assert!(rt.v3_sync.lock().client(peer).is_none());
        assert!(
            net.drain_captures().is_empty(),
            "closing the rearmed election must not replay the consumed stale admission evidence"
        );
    }

    #[tokio::test]
    async fn failed_terminal_page_does_not_orphan_reducer_session() {
        let (rt, net, _repo) = test_runtime(1, ReplicationConfig::default());
        net.set_epoch(1, 1);
        net.set_epoch(2, 1);
        net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V4));
        net.set_peer_strict_replication_protocol_version(2, STRICT_PROTOCOL_VERSION_V4);
        rt.seed_membership_snapshot([MemberIncarnation::new(1, 1), MemberIncarnation::new(2, 1)]);

        super::request_v3_terminal_sync(&rt, 2, super::StrictCatchupReason::TerminalFence).await;
        let first = net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    dst: 2,
                    body: StrictBody::TerminalSyncReq(request),
                    ..
                } => Some(request),
                _ => None,
            })
            .expect("initial terminal sync request");

        super::recv_v3_terminal_sync_page(
            &rt,
            2,
            1,
            StrictTerminalSyncPage {
                responder_node: 2,
                expected_requester_boot_epoch: 1,
                transfer_id: first.transfer_id,
                request_nonce: first.request_nonce,
                status: StrictTerminalSyncStatus::TransferExpired as i32,
                kind: 0,
                base_cut: None,
                target_cut: None,
                cursor: 0,
                next_cursor: 0,
                image_digest: Bytes::new(),
                checkpoint_states: Vec::new(),
                deltas: Vec::new(),
                has_more: false,
            },
        )
        .await;
        let peer = PeerIncarnation::new(2, 1);
        assert!(rt.v3_sync.lock().client(peer).is_some());
        assert!(
            rt.v3_sync.lock().has_session_work(peer),
            "an expired payload session must hand lifecycle ownership to its replacement"
        );
        assert!(
            net.drain_captures().into_iter().any(|frame| matches!(
                frame,
                CapturedFrame::StrictUnicast {
                    dst: 2,
                    body: StrictBody::TerminalSyncReq(ref request),
                    ..
                } if request.request_nonce != first.request_nonce
            )),
            "an expired terminal page must immediately start a fresh replacement session"
        );
    }

    #[tokio::test]
    async fn staged_elected_checkpoint_is_not_remembered_before_journal_prepare() {
        let (source, source_net, source_repo) = test_runtime(1, ReplicationConfig::default());
        let (sink, sink_net, sink_repo) = test_runtime(2, ReplicationConfig::default());
        configure_v5_peer(&source_net, 1, 2);
        configure_v5_peer(&sink_net, 2, 1);
        populate_repo(&source_repo, 1, 10);
        populate_repo(&sink_repo, 1, 20);
        let source_op = make_op_id(1, 1, 1);
        source
            .terminal_journal
            .lock()
            .await
            .upsert_abort_decision(source_op, 10)
            .expect("source abort");
        let page = elected_checkpoint_page(&source, &source_net, &sink, &sink_net).await;
        let target = super::cut_from_wire(page.target_cut.as_ref().expect("target cut"))
            .expect("valid target cut");
        assert_eq!(
            super::StrictTerminalPageKind::try_from(page.kind).ok(),
            Some(super::StrictTerminalPageKind::Checkpoint)
        );

        super::recv_v3_terminal_sync_page(&sink, 1, 1, page).await;

        let peer = PeerIncarnation::new(1, 1);
        assert!(
            sink.v3_sync.lock().known_source_cut(peer).is_none(),
            "an in-memory staged cut is not durable source evidence"
        );
        assert!(
            sink.v3_sync
                .lock()
                .bind_staged_checkpoint_to_repository(peer, target, 1),
            "the elected checkpoint must remain staged for repository preparation"
        );
        assert!(sink.terminal_journal.lock().await.get(source_op).is_none());
    }

    #[tokio::test]
    async fn elected_checkpoint_coalesced_with_terminal_fence_still_stages_repository_replacement()
    {
        let (source, source_net, source_repo) = test_runtime(1, ReplicationConfig::default());
        let (sink, sink_net, sink_repo) = test_runtime(2, ReplicationConfig::default());
        configure_v5_peer(&source_net, 1, 2);
        configure_v5_peer(&sink_net, 2, 1);
        populate_repo(&source_repo, 1, 10);
        populate_repo(&sink_repo, 1, 20);
        let source_op = make_op_id(1, 1, 1);
        source
            .terminal_journal
            .lock()
            .await
            .upsert_abort_decision(source_op, 10)
            .expect("source abort");
        let page = elected_checkpoint_page(&source, &source_net, &sink, &sink_net).await;
        let target = super::cut_from_wire(page.target_cut.as_ref().expect("target cut"))
            .expect("valid target cut");

        super::request_v3_terminal_sync(
            &sink,
            source.self_id,
            super::StrictCatchupReason::TerminalFence,
        )
        .await;
        let peer = PeerIncarnation::new(source.self_id, 1);
        {
            let sync = sink.v3_sync.lock();
            let client = sync.client(peer).expect("elected terminal client");
            assert_eq!(
                StrictCatchupReason::try_from(client.reason()).ok(),
                Some(StrictCatchupReason::TerminalFence),
                "the later operational trigger must exercise reason promotion"
            );
        }

        finish_terminal_checkpoint_handshake(&source, &source_net, &sink, &sink_net, page).await;

        assert!(
            sink.v3_sync
                .lock()
                .staged_checkpoint_for_repository(peer, 1)
                .is_some_and(|checkpoint| checkpoint.target_cut() == target),
            "the correlated elected checkpoint must be bound to the atomic repository replacement"
        );
        assert!(
            sink.terminal_journal.lock().await.get(source_op).is_none(),
            "the elected image must not be unioned into the old repository lineage"
        );
        assert!(
            sink_net.drain_captures().into_iter().any(|frame| matches!(
                frame,
                CapturedFrame::StrictUnicast {
                    dst: 1,
                    body: StrictBody::CatchupReq(ref request),
                    ..
                } if request.force_snapshot
            )),
            "the elected replacement must continue into an atomic repository snapshot"
        );
    }

    #[tokio::test]
    async fn unranked_checkpoint_without_retired_conflict_rearms_instead_of_unioning() {
        let (source, source_net, _source_repo) = test_runtime(1, ReplicationConfig::default());
        let (sink, sink_net, _sink_repo) = test_runtime(2, ReplicationConfig::default());
        configure_v5_peer(&source_net, 1, 2);
        configure_v5_peer(&sink_net, 2, 1);
        let source_op = make_op_id(1, 1, 1);
        source
            .terminal_journal
            .lock()
            .await
            .upsert_abort_decision(source_op, 10)
            .expect("source abort");

        super::request_v3_terminal_sync(&sink, 1, super::StrictCatchupReason::Admission).await;
        let request = sink_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    body: StrictBody::TerminalSyncReq(request),
                    ..
                } => Some(request),
                _ => None,
            })
            .expect("unranked terminal request");
        super::recv_v3_terminal_sync_req(&source, 2, 1, request).await;
        let page = source_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    body: StrictBody::TerminalSyncPage(page),
                    ..
                } => Some(page),
                _ => None,
            })
            .expect("unranked terminal checkpoint");
        assert_eq!(
            super::StrictTerminalPageKind::try_from(page.kind).ok(),
            Some(super::StrictTerminalPageKind::Checkpoint)
        );

        super::recv_v3_terminal_sync_page(&sink, 1, 1, page).await;

        assert!(
            sink.terminal_journal.lock().await.get(source_op).is_none(),
            "an unranked checkpoint must never be unioned into the local lineage"
        );
        assert!(sink.state.lock().history_election_pending());
    }

    #[tokio::test]
    async fn unranked_checkpoint_coalesced_with_terminal_fence_rearms_without_applying() {
        let (source, source_net, _source_repo) = test_runtime(1, ReplicationConfig::default());
        let (sink, sink_net, _sink_repo) = test_runtime(2, ReplicationConfig::default());
        configure_v5_peer(&source_net, 1, 2);
        configure_v5_peer(&sink_net, 2, 1);
        let source_op = make_op_id(1, 1, 1);
        source
            .terminal_journal
            .lock()
            .await
            .upsert_abort_decision(source_op, 10)
            .expect("source abort");

        super::request_v3_terminal_sync(&sink, 1, super::StrictCatchupReason::Admission).await;
        let request = sink_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    body: StrictBody::TerminalSyncReq(request),
                    ..
                } => Some(request),
                _ => None,
            })
            .expect("unranked terminal request");
        super::recv_v3_terminal_sync_req(&source, 2, 1, request).await;
        let page = source_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    body: StrictBody::TerminalSyncPage(page),
                    ..
                } => Some(page),
                _ => None,
            })
            .expect("unranked terminal checkpoint");

        super::request_v3_terminal_sync(
            &sink,
            source.self_id,
            super::StrictCatchupReason::TerminalFence,
        )
        .await;
        let peer = PeerIncarnation::new(source.self_id, 1);
        {
            let sync = sink.v3_sync.lock();
            let client = sync.client(peer).expect("unranked terminal client");
            assert_eq!(
                StrictCatchupReason::try_from(client.started_reason()).ok(),
                Some(StrictCatchupReason::Admission)
            );
            assert_eq!(
                StrictCatchupReason::try_from(client.reason()).ok(),
                Some(StrictCatchupReason::TerminalFence),
                "the later operational trigger must exercise reason promotion"
            );
        }

        super::recv_v3_terminal_sync_page(&sink, source.self_id, 1, page).await;

        assert!(
            sink.terminal_journal.lock().await.get(source_op).is_none(),
            "a promoted operational reason must not authorize an unranked foreign checkpoint"
        );
        assert!(sink.state.lock().history_election_pending());
    }

    #[tokio::test]
    async fn equal_version_elected_checkpoint_rejects_v4_repository_snapshot() {
        let (source, source_net, source_repo) = test_runtime(1, ReplicationConfig::default());
        let (sink, sink_net, sink_repo) = test_runtime(2, ReplicationConfig::default());
        configure_v5_peer(&source_net, 1, 2);
        configure_v5_peer(&sink_net, 2, 1);
        source_net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V4));
        source_net.set_peer_strict_replication_protocol_version(2, STRICT_PROTOCOL_VERSION_V4);
        sink_net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V4));
        sink_net.set_peer_strict_replication_protocol_version(1, STRICT_PROTOCOL_VERSION_V4);
        populate_repo(&source_repo, 1, 10);
        populate_repo(&sink_repo, 1, 20);
        source
            .terminal_journal
            .lock()
            .await
            .upsert_abort_decision(make_op_id(1, 1, 1), 10)
            .expect("source abort");

        let page = elected_checkpoint_page(&source, &source_net, &sink, &sink_net).await;
        finish_terminal_checkpoint_handshake(&source, &source_net, &sink, &sink_net, page).await;

        assert!(
            sink_net.drain_captures().into_iter().all(|frame| !matches!(
                frame,
                CapturedFrame::StrictUnicast {
                    body: StrictBody::CatchupReq(_),
                    ..
                }
            )),
            "v4 cannot carry the repository checkpoint paired with an elected terminal image"
        );
        assert_eq!(sink_repo.log(), vec![(1, 21)]);
        assert!(sink.repository_base_required());
        assert!(sink.state.lock().history_election_pending());
    }

    #[tokio::test]
    async fn equal_version_higher_freshness_election_requests_repository_snapshot() {
        let source_net = MockNet::new(1, vec![1, 2]);
        let sink_net = MockNet::new(2, vec![1, 2]);
        configure_v5_peer(&source_net, 1, 2);
        configure_v5_peer(&sink_net, 2, 1);
        let source_repo = Arc::new(SnapshotFreshnessRepo {
            version: 1,
            captured_freshness: 20,
            advertised_freshness: AtomicI64::new(20),
        });
        let sink_repo = Arc::new(SnapshotFreshnessRepo {
            version: 1,
            captured_freshness: 10,
            advertised_freshness: AtomicI64::new(10),
        });
        let source = StrictRuntime::new(
            source_repo.clone(),
            1,
            1,
            "channels".to_owned(),
            source_net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let sink = StrictRuntime::new(
            sink_repo.clone(),
            2,
            1,
            "channels".to_owned(),
            sink_net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        let source_metadata = source_repo.history_metadata();
        let sink_metadata = sink_repo.history_metadata();
        assert_eq!(source_metadata.version, sink_metadata.version);
        assert!(source_metadata.freshness > sink_metadata.freshness);
        assert_eq!(
            source
                .terminal_journal
                .lock()
                .await
                .terminal_cut()
                .terminal_set_digest(),
            sink.terminal_journal
                .lock()
                .await
                .terminal_cut()
                .terminal_set_digest(),
            "the repository freshness difference must be the only elected divergence"
        );

        {
            let mut state = sink.state.lock();
            state.request_history_election();
            state.begin_history_election([source.self_id]);
        }
        super::request_v3_history_probe(
            &sink,
            source.self_id,
            super::StrictCatchupReason::HistoryElection,
        )
        .await;
        let request = sink_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    body: StrictBody::HistoryProbeReq(request),
                    ..
                } => Some(request),
                _ => None,
            })
            .expect("history election request");
        super::recv_v3_history_probe_req(&source, sink.self_id, 1, request).await;
        let response = source_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    body: StrictBody::HistoryProbeResp(response),
                    ..
                } => Some(response),
                _ => None,
            })
            .expect("history election response");

        super::recv_v3_history_probe_resp(&sink, source.self_id, 1, response).await;

        let history_request = sink_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    dst: 1,
                    body: StrictBody::CatchupReq(request),
                    ..
                } if request.force_snapshot => Some(request),
                _ => None,
            })
            .expect(
                "an elected same-version fresher repository must replace the stale local image",
            );
        assert_eq!(history_request.since_version, sink_metadata.version);
        assert_eq!(
            history_request.chunk_token,
            super::HISTORY_ELECTION_SNAPSHOT_TOKEN
        );

        respond_to_request(&source, sink.self_id, history_request).await;
        let history_response = source_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    dst: 2,
                    body: StrictBody::CatchupResp(response),
                    ..
                } => Some(response),
                _ => None,
            })
            .expect("forced freshness replacement snapshot");
        assert!(history_response.too_old_use_snapshot);
        apply_response(&sink, source.self_id, history_response).await;

        assert_eq!(sink_repo.history_metadata(), source_metadata);
        assert!(!sink.state.lock().history_election_pending());
        assert!(!sink.state.lock().history_election_active());

        let post_snapshot = sink_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    dst: 1,
                    body: StrictBody::CatchupReq(request),
                    ..
                } if request
                    .history_transfer
                    .as_ref()
                    .is_some_and(|transfer| !transfer.final_ack) =>
                {
                    Some(request)
                }
                _ => None,
            })
            .expect("post-snapshot freshness confirmation request");
        respond_to_request(&source, sink.self_id, post_snapshot).await;
        let post_snapshot_response = source_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    dst: 2,
                    body: StrictBody::CatchupResp(response),
                    ..
                } => Some(response),
                _ => None,
            })
            .expect("post-snapshot freshness confirmation response");
        apply_response(&sink, source.self_id, post_snapshot_response).await;

        let final_ack = sink_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    dst: 1,
                    body: StrictBody::CatchupReq(request),
                    ..
                } if request
                    .history_transfer
                    .as_ref()
                    .is_some_and(|transfer| transfer.final_ack) =>
                {
                    Some(request)
                }
                _ => None,
            })
            .expect("history final ACK");
        respond_to_request(&source, sink.self_id, final_ack).await;
        let confirmation = source_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    dst: 2,
                    body: StrictBody::CatchupResp(response),
                    ..
                } => Some(response),
                _ => None,
            })
            .expect("history final ACK confirmation");
        apply_response(&sink, source.self_id, confirmation).await;

        assert!(sink_net.drain_captures().is_empty());
        sink.try_bootstrap_catchup().await;
        super::retry_v3_terminal_transmissions(&sink).await;
        assert!(
            sink_net.drain_captures().is_empty(),
            "a converged freshness replacement must not restart metadata catchup"
        );
    }

    #[tokio::test]
    async fn equal_head_generation_zero_checkpoint_forces_v5_snapshot_then_stays_quiet() {
        let (source, source_net, source_repo) = test_runtime(1, ReplicationConfig::default());
        let (sink, sink_net, sink_repo) = test_runtime(2, ReplicationConfig::default());
        configure_v5_peer(&source_net, 1, 2);
        configure_v5_peer(&sink_net, 2, 1);
        populate_repo(&source_repo, 1, 10);
        populate_repo(&sink_repo, 1, 20);

        let source_op = make_op_id(1, 1, 1);
        let sink_op = make_op_id(2, 1, 1);
        let (source_cut, source_retired) = {
            let mut journal = source.terminal_journal.lock().await;
            journal
                .upsert_abort_decision(source_op, 10)
                .expect("source abort");
            journal.checkpoint(1).expect("source checkpoint");
            (journal.terminal_cut(), journal.retired_origins())
        };
        source.state.lock().retired_operations = source_retired;
        let (sink_cut, sink_retired) = {
            let mut journal = sink.terminal_journal.lock().await;
            journal
                .upsert_abort_decision(sink_op, 20)
                .expect("sink abort");
            journal.checkpoint(1).expect("sink checkpoint");
            (journal.terminal_cut(), journal.retired_origins())
        };
        sink.state.lock().retired_operations = sink_retired;
        assert_eq!(source_cut.generation(), 0);
        assert_eq!(sink_cut.generation(), 0);
        assert_ne!(
            source_cut.terminal_set_digest(),
            sink_cut.terminal_set_digest()
        );

        // Exercise the real metadata probe and terminal-checkpoint handshake.
        // The deployed regression returned immediately after the probe because
        // it treated every generation-zero cut as already satisfied and the
        // equal repository versions as requiring no history transfer.
        let page = elected_checkpoint_page(&source, &source_net, &sink, &sink_net).await;
        assert_eq!(
            super::StrictTerminalPageKind::try_from(page.kind).ok(),
            Some(super::StrictTerminalPageKind::Checkpoint)
        );
        finish_terminal_checkpoint_handshake(&source, &source_net, &sink, &sink_net, page).await;

        let history_request = sink_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    dst: 1,
                    body: StrictBody::CatchupReq(request),
                    ..
                } => Some(request),
                _ => None,
            })
            .expect("equal-head elected checkpoint must request a repository image");
        assert!(history_request.force_snapshot);
        assert_eq!(history_request.since_version, 1);
        assert_eq!(
            history_request.chunk_token,
            super::HISTORY_ELECTION_SNAPSHOT_TOKEN
        );
        let transfer = history_request
            .history_transfer
            .as_ref()
            .expect("correlated history transfer");
        assert_eq!(
            super::StrictCatchupReason::try_from(transfer.reason).ok(),
            Some(super::StrictCatchupReason::HistoryElection)
        );

        respond_to_request(&source, 2, history_request).await;
        let history_response = source_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    dst: 2,
                    body: StrictBody::CatchupResp(response),
                    ..
                } => Some(response),
                _ => None,
            })
            .expect("forced snapshot response");
        assert!(history_response.too_old_use_snapshot);
        apply_response(&sink, 1, history_response).await;

        // Snapshot installation continues the same correlated history
        // transfer once from the installed version so the source can prove
        // that no log tail raced the pinned image. Completion, and therefore
        // the final ACK, follows that metadata-only response.
        let post_snapshot = sink_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    dst: 1,
                    body: StrictBody::CatchupReq(request),
                    ..
                } if request
                    .history_transfer
                    .as_ref()
                    .is_some_and(|transfer| !transfer.final_ack) =>
                {
                    Some(request)
                }
                _ => None,
            })
            .expect("post-snapshot history confirmation request");
        assert_eq!(post_snapshot.since_version, 1);
        respond_to_request(&source, 2, post_snapshot).await;
        let post_snapshot_response = source_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    dst: 2,
                    body: StrictBody::CatchupResp(response),
                    ..
                } => Some(response),
                _ => None,
            })
            .expect("post-snapshot history confirmation response");
        assert!(post_snapshot_response.ops.is_empty());
        assert!(!post_snapshot_response.has_more);
        apply_response(&sink, 1, post_snapshot_response).await;

        let final_ack = sink_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    dst: 1,
                    body: StrictBody::CatchupReq(request),
                    ..
                } if request
                    .history_transfer
                    .as_ref()
                    .is_some_and(|transfer| transfer.final_ack) =>
                {
                    Some(request)
                }
                _ => None,
            })
            .expect("history final ACK");
        respond_to_request(&source, 2, final_ack).await;
        let confirmation = source_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    dst: 2,
                    body: StrictBody::CatchupResp(response),
                    ..
                } => Some(response),
                _ => None,
            })
            .expect("history final ACK confirmation");
        apply_response(&sink, 1, confirmation).await;

        assert_eq!(sink_repo.log(), source_repo.log());
        assert_eq!(
            sink.terminal_journal.lock().await.terminal_cut(),
            source_cut
        );
        assert!(!sink.repository_base_required());
        assert!(!sink.state.lock().history_election_pending());
        assert!(!sink.state.lock().history_election_active());
        assert!(sink_net.drain_captures().is_empty());

        sink.try_bootstrap_catchup().await;
        super::retry_v3_terminal_transmissions(&sink).await;
        assert!(
            sink_net.drain_captures().is_empty(),
            "a converged equal-head replacement must not restart metadata catchup"
        );
    }

    #[tokio::test]
    async fn terminal_only_pages_continue_across_global_floor_downgrade() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_ops(1);
        let (source, source_net, _) = test_runtime(1, cfg);
        source_net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V4));
        source_net.set_peer_strict_replication_protocol_version(2, STRICT_PROTOCOL_VERSION_V4);
        let first_id = make_op_id(1, 1, 1);
        let second_id = make_op_id(1, 1, 2);
        source
            .apply_catchup_terminal_state(terminal_abort(first_id))
            .await;
        source
            .apply_catchup_terminal_state(terminal_abort(second_id))
            .await;

        respond_to_request(
            &source,
            2,
            StrictCatchupReq {
                src_node: 2,
                since_version: 17,
                chunk_token: 17,
                force_snapshot: true,
                history_probe_only: true,
                terminal_state_cursor: 0,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
                history_transfer: None,
            },
        )
        .await;

        let first_page = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(first_page.terminal_sync_only);
        assert!(first_page.request_force_snapshot);
        assert!(first_page.request_history_probe_only);
        assert!(first_page.terminal_states_has_more);
        assert_eq!(first_page.terminal_states.len(), 1);
        assert_eq!(first_page.next_terminal_state_cursor, 1);
        assert_eq!(first_page.next_chunk_token, 17);

        let (sink, sink_net, _) = test_runtime(2, ReplicationConfig::default());
        sink_net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V4));
        sink_net.set_peer_strict_replication_protocol_version(1, STRICT_PROTOCOL_VERSION_V4);
        source_net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V4);
        sink_net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V4);
        apply_response(&sink, 1, first_page).await;
        let second_request = catchup_request(sink_net.drain_captures().pop().unwrap());
        assert!(second_request.force_snapshot);
        assert!(second_request.history_probe_only);
        assert_eq!(second_request.since_version, 17);
        assert_eq!(second_request.chunk_token, 17);
        assert_eq!(second_request.terminal_state_cursor, 1);

        respond_to_request(&source, 2, second_request).await;
        let second_page = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(second_page.terminal_sync_only);
        assert!(second_page.request_force_snapshot);
        assert!(second_page.request_history_probe_only);
        assert!(!second_page.terminal_states_has_more);
        assert_eq!(second_page.terminal_states.len(), 1);
        assert_eq!(second_page.next_terminal_state_cursor, 2);

        apply_response(&sink, 1, second_page).await;
        let history_request = catchup_request(sink_net.drain_captures().pop().unwrap());
        assert!(history_request.force_snapshot);
        assert!(history_request.history_probe_only);
        assert_eq!(
            history_request.terminal_state_cursor,
            super::TERMINAL_STATE_CURSOR_SKIP
        );

        respond_to_request(&source, 2, history_request).await;
        let history_response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(!history_response.terminal_sync_only);
        assert!(history_response.request_force_snapshot);
        assert!(history_response.request_history_probe_only);
        assert!(history_response.terminal_states.is_empty());
        assert_eq!(
            history_response.next_terminal_state_cursor,
            super::TERMINAL_STATE_CURSOR_SKIP
        );
    }

    #[tokio::test]
    async fn duplicate_terminal_only_page_does_not_fork_continuation() {
        let (sink, sink_net, _) = test_runtime(2, ReplicationConfig::default());
        let response = StrictCatchupResp {
            history_node: 1,
            terminal_states: vec![terminal_abort(make_op_id(1, 1, 1))],
            next_terminal_state_cursor: 1,
            terminal_states_has_more: false,
            terminal_sync_only: true,
            terminal_decision_generation: 7,
            ..Default::default()
        };

        apply_response(&sink, 1, response.clone()).await;
        let continuation = catchup_request(
            sink_net
                .drain_captures()
                .pop()
                .expect("first terminal page continuation"),
        );
        assert_eq!(
            continuation.terminal_state_cursor,
            super::TERMINAL_STATE_CURSOR_SKIP
        );
        assert_eq!(continuation.terminal_decision_generation, 7);

        apply_response(&sink, 1, response).await;
        assert!(
            sink_net.drain_captures().is_empty(),
            "a duplicate terminal page must not fork another continuation chain"
        );
    }

    #[tokio::test]
    async fn checkpoint_generation_reset_starts_new_terminal_progress() {
        let (sink, sink_net, _) = test_runtime(2, ReplicationConfig::default());
        let response = |generation, counter| StrictCatchupResp {
            history_node: 1,
            terminal_states: vec![terminal_abort(make_op_id(1, 1, counter))],
            next_terminal_state_cursor: 1,
            terminal_states_has_more: false,
            terminal_sync_only: true,
            terminal_decision_generation: generation,
            ..Default::default()
        };

        apply_response(&sink, 1, response(7, 1)).await;
        assert_eq!(sink_net.drain_captures().len(), 1);

        apply_response(&sink, 1, response(0, 2)).await;
        let captures = sink_net.drain_captures();
        assert_eq!(captures.len(), 1);
        let continuation = catchup_request(captures.into_iter().next().unwrap());
        assert_eq!(
            continuation.terminal_state_cursor,
            super::TERMINAL_STATE_CURSOR_SKIP
        );
        assert_eq!(continuation.terminal_decision_generation, 0);
    }

    #[tokio::test]
    async fn duplicate_intermediate_terminal_page_emits_one_continuation() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_ops(1);
        let (source, source_net, _) = test_runtime(1, cfg.clone());
        source
            .apply_catchup_terminal_state(terminal_abort(make_op_id(1, 1, 1)))
            .await;
        source
            .apply_catchup_terminal_state(terminal_abort(make_op_id(1, 1, 2)))
            .await;
        respond_to_request(
            &source,
            2,
            StrictCatchupReq {
                src_node: 2,
                terminal_state_cursor: 0,
                ..Default::default()
            },
        )
        .await;
        let page = catchup_response(
            source_net
                .drain_captures()
                .pop()
                .expect("first terminal page"),
        );
        assert!(page.terminal_sync_only);
        assert!(page.terminal_states_has_more);
        assert_eq!(page.next_terminal_state_cursor, 1);

        let (sink, sink_net, _) = test_runtime(2, cfg);
        apply_response(&sink, 1, page.clone()).await;
        apply_response(&sink, 1, page).await;

        let captures = sink_net.drain_captures();
        assert_eq!(
            captures.len(),
            1,
            "a duplicate intermediate terminal page must not branch pagination"
        );
        let continuation = catchup_request(captures.into_iter().next().unwrap());
        assert_eq!(continuation.terminal_state_cursor, 1);
    }

    #[tokio::test]
    async fn failed_terminal_continuation_can_be_retried_by_a_duplicate_page() {
        let (sink, sink_net, _) = test_runtime(2, ReplicationConfig::default());
        let response = StrictCatchupResp {
            history_node: 1,
            terminal_states: vec![terminal_abort(make_op_id(1, 1, 1))],
            next_terminal_state_cursor: 1,
            terminal_states_has_more: true,
            terminal_sync_only: true,
            terminal_decision_generation: 7,
            ..Default::default()
        };

        sink_net.fail_strict_unicasts_to([1]);
        apply_response(&sink, 1, response.clone()).await;
        assert!(sink_net.drain_captures().is_empty());

        sink_net.fail_strict_unicasts_to([]);
        apply_response(&sink, 1, response).await;
        let captures = sink_net.drain_captures();
        assert_eq!(captures.len(), 1);
        let continuation = catchup_request(captures.into_iter().next().unwrap());
        assert_eq!(continuation.terminal_state_cursor, 1);
    }

    #[tokio::test]
    async fn delayed_intermediate_terminal_page_does_not_regress_completed_generation() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_ops(1);
        let (source, source_net, _) = test_runtime(1, cfg.clone());
        source
            .apply_catchup_terminal_state(terminal_abort(make_op_id(1, 1, 1)))
            .await;
        source
            .apply_catchup_terminal_state(terminal_abort(make_op_id(1, 1, 2)))
            .await;
        respond_to_request(
            &source,
            2,
            StrictCatchupReq {
                src_node: 2,
                terminal_state_cursor: 0,
                ..Default::default()
            },
        )
        .await;
        let first_page = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(first_page.terminal_states_has_more);

        let (sink, sink_net, _) = test_runtime(2, cfg);
        apply_response(&sink, 1, first_page.clone()).await;
        let continuation = catchup_request(sink_net.drain_captures().pop().unwrap());
        respond_to_request(&source, 2, continuation).await;
        let final_page = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(!final_page.terminal_states_has_more);
        assert_eq!(
            first_page.terminal_decision_generation,
            final_page.terminal_decision_generation
        );

        apply_response(&sink, 1, final_page).await;
        let history_request = catchup_request(sink_net.drain_captures().pop().unwrap());
        assert_eq!(
            history_request.terminal_state_cursor,
            super::TERMINAL_STATE_CURSOR_SKIP
        );

        apply_response(&sink, 1, first_page).await;
        assert!(
            sink_net.drain_captures().is_empty(),
            "a delayed intermediate page from a completed generation must not regress pagination"
        );
    }

    #[tokio::test]
    async fn duplicate_final_terminal_request_replays_the_completed_cut() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_ops(1);
        let (source, source_net, _) = test_runtime(1, cfg);
        source
            .apply_catchup_terminal_state(terminal_abort(make_op_id(1, 1, 1)))
            .await;
        source
            .apply_catchup_terminal_state(terminal_abort(make_op_id(1, 1, 2)))
            .await;

        let first_request = StrictCatchupReq {
            src_node: 2,
            terminal_state_cursor: 0,
            ..Default::default()
        };
        respond_to_request(&source, 2, first_request).await;
        let first_page = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(first_page.terminal_states_has_more);
        assert_eq!(first_page.next_terminal_state_cursor, 1);

        let final_request = StrictCatchupReq {
            src_node: 2,
            terminal_state_cursor: first_page.next_terminal_state_cursor,
            ..Default::default()
        };
        respond_to_request(&source, 2, final_request.clone()).await;
        let final_page = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(!final_page.terminal_states_has_more);
        assert_eq!(final_page.next_terminal_state_cursor, 2);

        respond_to_request(&source, 2, final_request).await;
        let replayed_page = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(!replayed_page.terminal_states_has_more);
        assert_eq!(
            replayed_page.next_terminal_state_cursor, 2,
            "a duplicate final request must not restart the immutable cut at cursor zero"
        );
    }

    #[tokio::test]
    async fn correlated_terminal_proof_history_continues_across_global_floor_downgrade() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_ops(1);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        let (sink, sink_net, _) = test_runtime(2, cfg);
        for net in [&source_net, &sink_net] {
            net.set_epoch(1, 1);
            net.set_epoch(2, 1);
            net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V4));
        }
        source_net.set_peer_strict_replication_protocol_version(2, STRICT_PROTOCOL_VERSION_V4);
        sink_net.set_peer_strict_replication_protocol_version(1, STRICT_PROTOCOL_VERSION_V4);

        let frozen_targets = vec![FrozenTarget::new(1, 1), FrozenTarget::new(2, 1)];
        let resolver = TerminalResolver::new(1, 1);
        let mut entries = Vec::new();
        for version in 1..=2 {
            let op_id = make_op_id(1, 1, version);
            let value = 1_000 + version;
            let ts_final = 10 + version;
            let op_msgpack = Bytes::from(rmp_serde::to_vec(&value).unwrap());
            source
                .terminal_journal
                .lock()
                .await
                .upsert_v2_commit_decision_bytes(
                    op_id,
                    &frozen_targets,
                    resolver,
                    1,
                    ts_final,
                    op_msgpack,
                )
                .unwrap();
            entries.push((
                version,
                value,
                Some(super::StrictLogMetadata {
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    ts_final,
                }),
            ));
        }
        *source_repo.state.lock() = (2, entries);

        let peer = PeerIncarnation::new(1, 1);
        let transfer = sink
            .v3_history
            .lock()
            .begin_transfer(
                peer,
                2,
                0,
                crate::replications::proto::StrictCatchupReason::RepositoryGap,
                sink.cfg.pending_propose_ttl(),
                false,
                crate::replications::proto::StrictCatchupReason::RepositoryGap,
            )
            .expect("correlated repository history transfer")
            .into_parts()
            .0;
        respond_to_request(
            &source,
            2,
            StrictCatchupReq {
                src_node: 2,
                since_version: 0,
                chunk_token: 0,
                force_snapshot: false,
                history_probe_only: false,
                terminal_state_cursor: super::TERMINAL_STATE_CURSOR_SKIP,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
                history_transfer: Some(transfer),
            },
        )
        .await;
        let first = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(first.has_more);
        assert!(first.ops[0].strict_terminal_ballot > 0);

        source_net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V4);
        sink_net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V4);
        apply_response(&sink, 1, first).await;
        let continuation = sink_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    body: StrictBody::CatchupReq(request),
                    ..
                } if request.history_transfer.is_some() => Some(request),
                _ => None,
            })
            .expect("correlated history continuation");

        respond_to_request(&source, 2, continuation).await;
        let final_page = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(!final_page.has_more);
        assert!(final_page.ops[0].strict_terminal_ballot > 0);
        apply_response(&sink, 1, final_page).await;

        let final_ack = sink_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    body: StrictBody::CatchupReq(request),
                    ..
                } if request
                    .history_transfer
                    .as_ref()
                    .is_some_and(|transfer| transfer.final_ack) =>
                {
                    Some(request)
                }
                _ => None,
            })
            .expect("history final ACK");
        respond_to_request(&source, 2, final_ack).await;
        let confirmation = catchup_response(source_net.drain_captures().pop().unwrap());
        apply_response(&sink, 1, confirmation).await;

        let journal = sink.terminal_journal.lock().await;
        for version in 1..=2 {
            assert!(
                journal
                    .get(make_op_id(1, 1, version))
                    .and_then(|record| record.terminal_decision())
                    .is_some(),
                "terminal-proof history entry {version} did not converge"
            );
        }
        assert!(!sink.v3_history.lock().has_active_transfer(peer));
    }

    #[tokio::test]
    async fn oversized_terminal_state_is_declined_before_send() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(1);
        let (source, source_net, _) = test_runtime(1, cfg);
        source
            .apply_catchup_terminal_state(terminal_abort(make_op_id(1, 1, 99)))
            .await;

        respond_to_request(
            &source,
            2,
            StrictCatchupReq {
                src_node: 2,
                since_version: 0,
                chunk_token: 0,
                force_snapshot: false,
                history_probe_only: false,
                terminal_state_cursor: 0,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
                history_transfer: None,
            },
        )
        .await;

        assert!(
            source_net.drain_captures().is_empty(),
            "an unframeable terminal state must not be emitted as an oversized response"
        );
    }

    #[tokio::test]
    async fn terminal_sync_then_history_pagination_keeps_the_history_cursor() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_ops(1);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        let terminal_id = make_op_id(1, 1, 31);
        source
            .apply_catchup_terminal_state(terminal_abort(terminal_id))
            .await;
        {
            let mut state = source_repo.state.lock();
            state.0 = 3;
            state.1 = vec![(1, 101, None), (2, 102, None), (3, 103, None)];
        }
        let (sink, sink_net, _) = test_runtime(2, cfg);

        respond_to_request(
            &source,
            2,
            StrictCatchupReq {
                src_node: 2,
                since_version: 0,
                chunk_token: 0,
                force_snapshot: false,
                history_probe_only: false,
                terminal_state_cursor: 0,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
                history_transfer: None,
            },
        )
        .await;
        let terminal_response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(terminal_response.terminal_sync_only);
        assert_eq!(terminal_response.terminal_states.len(), 1);

        apply_response(&sink, 1, terminal_response).await;
        let first_history_request = catchup_request(sink_net.drain_captures().pop().unwrap());
        assert_eq!(
            first_history_request.terminal_state_cursor,
            super::TERMINAL_STATE_CURSOR_SKIP
        );
        assert_eq!(first_history_request.chunk_token, 0);

        respond_to_request(&source, 2, first_history_request).await;
        let first_history_response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(!first_history_response.terminal_sync_only);
        assert_eq!(first_history_response.ops.len(), 1);
        assert_eq!(first_history_response.ops[0].version, 1);
        assert!(first_history_response.has_more);
        apply_response(&sink, 1, first_history_response).await;

        let second_history_request = catchup_request(sink_net.drain_captures().pop().unwrap());
        assert_eq!(second_history_request.since_version, 1);
        assert_eq!(second_history_request.chunk_token, 1);
        assert_eq!(
            second_history_request.terminal_state_cursor,
            super::TERMINAL_STATE_CURSOR_SKIP
        );
        respond_to_request(&source, 2, second_history_request).await;
        let second_history_response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert_eq!(second_history_response.ops.len(), 1);
        assert_eq!(second_history_response.ops[0].version, 2);
        assert!(second_history_response.has_more);
        apply_response(&sink, 1, second_history_response).await;

        let third_history_request = catchup_request(sink_net.drain_captures().pop().unwrap());
        assert_eq!(third_history_request.chunk_token, 2);
        assert_eq!(
            third_history_request.terminal_state_cursor,
            super::TERMINAL_STATE_CURSOR_SKIP
        );
        respond_to_request(&source, 2, third_history_request).await;
        let third_history_response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert_eq!(third_history_response.ops.len(), 1);
        assert_eq!(third_history_response.ops[0].version, 3);
        assert!(!third_history_response.has_more);
    }

    #[tokio::test]
    async fn v2_snapshot_transfer_chunks_then_installs_the_verified_image() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 128, 10_000);
        let (sink, sink_net, sink_repo) = test_runtime(2, cfg.clone());
        begin_snapshot_fetch(&sink, 128);

        let mut request = force_snapshot_request();
        let mut chunk_count = 0usize;
        loop {
            respond_to_request(&source, 2, request).await;
            let response = catchup_response(source_net.drain_captures().pop().unwrap());
            assert_ne!(response.snapshot_transfer_id, 0);
            assert!(
                source
                    .v2_strict_replication_payload_len(&StrictBody::CatchupResp(response.clone()))
                    .unwrap()
                    <= cfg.strict_max_catchup_bytes()
            );
            chunk_count += 1;
            let has_more = response.snapshot_has_more;
            let transfer_id = response.snapshot_transfer_id;
            apply_response(&sink, 1, response).await;
            let captures = sink_net.drain_captures();
            if has_more {
                assert_eq!(
                    sink_repo.current_version(),
                    0,
                    "a partial image must never reach the repository"
                );
                assert_eq!(captures.len(), 1);
                request = catchup_request(captures.into_iter().next().unwrap());
                assert_ne!(request.snapshot_transfer_id, 0);
            } else {
                assert_eq!(captures.len(), 1);
                let history_request = catchup_request(captures.into_iter().next().unwrap());
                assert_eq!(history_request.snapshot_transfer_id, transfer_id);
                assert!(!history_request.force_snapshot);
                respond_to_request(&source, 2, history_request).await;
                assert!(source.snapshot_transfers.lock().is_empty());
                break;
            }
        }

        assert!(
            chunk_count > 1,
            "the test image must require multiple frames"
        );
        assert_eq!(sink_repo.current_version(), 128);
        assert_eq!(sink_repo.log(), source_repo.log());
    }

    #[tokio::test]
    async fn v2_snapshot_transfer_pins_its_image_across_source_changes() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 96, 3_000);
        let expected_log = source_repo.log();
        let (sink, sink_net, sink_repo) = test_runtime(2, cfg);
        begin_snapshot_fetch(&sink, 96);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(first_response.snapshot_has_more);
        let transfer_id = first_response.snapshot_transfer_id;
        apply_response(&sink, 1, first_response).await;
        let mut request = catchup_request(sink_net.drain_captures().pop().unwrap());

        populate_repo(&source_repo, 97, 30_000);
        loop {
            respond_to_request(&source, 2, request).await;
            let response = catchup_response(source_net.drain_captures().pop().unwrap());
            assert_eq!(response.snapshot_transfer_id, transfer_id);
            assert_eq!(response.snapshot_version, 96);
            let has_more = response.snapshot_has_more;
            apply_response(&sink, 1, response).await;
            let captures = sink_net.drain_captures();
            if has_more {
                request = catchup_request(captures.into_iter().next().unwrap());
            } else {
                break;
            }
        }

        assert_eq!(sink_repo.current_version(), 96);
        assert_eq!(sink_repo.log(), expected_log);
    }

    async fn assert_snapshot_format_survives_in_flight_protocol_change(
        captured_protocol: u32,
        installed_protocol: u32,
    ) {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 96, 40_000 + u64::from(captured_protocol));
        let expected_log = source_repo.log();
        let (sink, sink_net, sink_repo) = test_runtime(2, cfg);
        source_net.set_peer_strict_replication_protocol_version(2, captured_protocol);
        sink_net.set_peer_strict_replication_protocol_version(1, captured_protocol);
        begin_snapshot_fetch(&sink, 96);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(first_response.snapshot_has_more);
        apply_response(&sink, 1, first_response).await;
        let mut request = catchup_request(sink_net.drain_captures().pop().unwrap());

        // The immutable image is already in flight. A concurrent LSA change
        // must not reinterpret its bytes when the final chunk arrives.
        sink_net.set_peer_strict_replication_protocol_version(1, installed_protocol);
        loop {
            respond_to_request(&source, 2, request).await;
            let response = catchup_response(source_net.drain_captures().pop().unwrap());
            let has_more = response.snapshot_has_more;
            apply_response(&sink, 1, response).await;
            let captures = sink_net.drain_captures();
            if has_more {
                request = catchup_request(captures.into_iter().next().unwrap());
            } else {
                break;
            }
        }

        assert_eq!(sink_repo.current_version(), 96);
        assert_eq!(sink_repo.log(), expected_log);
    }

    #[tokio::test]
    async fn v5_snapshot_envelope_is_not_reinterpreted_as_raw_after_in_flight_downgrade() {
        assert_snapshot_format_survives_in_flight_protocol_change(
            STRICT_PROTOCOL_VERSION_V5,
            STRICT_PROTOCOL_VERSION_V4,
        )
        .await;
    }

    #[tokio::test]
    async fn v4_raw_snapshot_is_not_reinterpreted_as_envelope_after_in_flight_upgrade() {
        assert_snapshot_format_survives_in_flight_protocol_change(
            STRICT_PROTOCOL_VERSION_V4,
            STRICT_PROTOCOL_VERSION_V5,
        )
        .await;
    }

    async fn assert_legacy_untagged_raw_snapshot_ignores_asymmetric_peer_view(
        receiver_peer_protocol: u32,
    ) {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 96, 50_000);
        let expected_log = source_repo.log();
        let (sink, sink_net, sink_repo) = test_runtime(2, cfg);
        source_net.set_peer_strict_replication_protocol_version(2, STRICT_PROTOCOL_VERSION_V4);
        sink_net.set_peer_strict_replication_protocol_version(1, receiver_peer_protocol);
        begin_snapshot_fetch(&sink, 96);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let mut response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(response.snapshot_has_more);
        let tagged_id = response.snapshot_transfer_id;
        let legacy_id = tagged_id & super::SNAPSHOT_TRANSFER_COUNTER_MASK;
        assert_ne!(legacy_id, 0);

        loop {
            response.snapshot_transfer_id = legacy_id;
            let has_more = response.snapshot_has_more;
            apply_response(&sink, 1, response).await;
            if !has_more {
                break;
            }
            let mut continuation = catchup_request(sink_net.drain_captures().pop().unwrap());
            assert_eq!(continuation.snapshot_transfer_id, legacy_id);
            // A legacy responder used the same untagged token internally. The
            // current responder fixture retains its tagged cache key, so map
            // only the fixture-facing echo back without changing wire bytes.
            continuation.snapshot_transfer_id = tagged_id;
            respond_to_request(&source, 2, continuation).await;
            response = catchup_response(source_net.drain_captures().pop().unwrap());
        }

        assert_eq!(sink_repo.current_version(), 96);
        assert_eq!(sink_repo.log(), expected_log);
    }

    #[tokio::test]
    async fn legacy_untagged_envelope_shaped_raw_snapshot_is_quarantined_without_unwrapping() {
        let outer = Bytes::from(
            rmp_serde::to_vec_named(&super::S2sSnapshotEnvelope {
                version: super::S2S_SNAPSHOT_ENVELOPE_VERSION,
                repository_snapshot: b"valid-inner-repository-image".to_vec(),
                applied_operations: Vec::new(),
                retired_operations: Vec::new(),
            })
            .unwrap(),
        );
        let net = MockNet::new(2, vec![1, 2]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V5);
        net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V5));
        net.set_peer_strict_replication_protocol_version(1, STRICT_PROTOCOL_VERSION_V5);
        let repo = Arc::new(EnvelopeShapedRawRepo {
            install_attempts: parking_lot::Mutex::new(Vec::new()),
        });
        let sink = StrictRuntime::new(
            repo.clone(),
            2,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let remote_rank = super::HistoryRank {
            version: 1,
            freshness: 0,
            runtime_started_at: 1,
            node_id: 1,
            terminal_repository_base_version: 0,
        };
        let local_rank = super::HistoryRank::local(&sink);
        {
            let mut state = sink.state.lock();
            state.request_history_election();
            state.begin_history_election([1]);
            assert!(matches!(
                state.record_history_probe_response(1, remote_rank, local_rank),
                super::HistoryProbeResponseOutcome::FetchSnapshot(_)
            ));
        }
        net.set_epoch(1, 11);
        let peer = PeerIncarnation::new(1, 11);
        let history_request = sink
            .v3_history
            .lock()
            .begin_transfer(
                peer,
                remote_rank.version,
                0,
                StrictCatchupReason::HistoryElection,
                sink.cfg.pending_propose_ttl(),
                false,
                StrictCatchupReason::HistoryElection,
            )
            .expect("correlated elected snapshot transfer")
            .into_parts()
            .0;
        let outer_len = outer.len() as u64;

        apply_response(
            &sink,
            1,
            StrictCatchupResp {
                snapshot_version: 1,
                snapshot_msgpack: outer.clone(),
                too_old_use_snapshot: true,
                history_version: 1,
                runtime_started_at: 1,
                history_node: 1,
                request_force_snapshot: true,
                next_terminal_state_cursor: super::TERMINAL_STATE_CURSOR_SKIP,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 7,
                snapshot_chunk_cursor: 0,
                snapshot_next_cursor: outer_len,
                snapshot_total_bytes: outer_len,
                snapshot_sha256: super::snapshot_sha256(&outer),
                history_transfer: Some(StrictHistoryTransferResp {
                    expected_requester_boot_epoch: sink.boot_epoch,
                    transfer_id: history_request.transfer_id,
                    request_nonce: history_request.request_nonce,
                    cursor: history_request.expected_cursor,
                    target_version: history_request.target_version,
                }),
                ..Default::default()
            },
        )
        .await;

        assert!(
            repo.install_attempts.lock().is_empty(),
            "ambiguous raw bytes must not be unwrapped and installed as their inner payload"
        );
        {
            let receivers = sink.snapshot_receivers.lock();
            let quarantined = receivers.get(&1).expect("ambiguous transfer quarantine");
            assert_eq!(quarantined.snapshot_msgpack, outer);
        }
        assert!(!sink.v3_history.lock().has_active_transfer(peer));
        let state = sink.state.lock();
        assert!(state.history_election_pending());
        assert!(
            state.history_election_fetching_snapshot().is_none(),
            "an unusable elected image must rearm recovery instead of stranding FetchingSnapshot"
        );
        assert!(net.drain_captures().is_empty());
    }

    #[tokio::test]
    async fn missing_snapshot_continuation_client_rearms_current_election() {
        let (sink, sink_net, _sink_repo) = test_runtime(2, ReplicationConfig::default());
        begin_snapshot_fetch(&sink, 1);
        let (peer, response) = begin_correlated_history(
            &sink,
            &sink_net,
            1,
            11,
            1,
            StrictCatchupReason::HistoryElection,
        );
        {
            let mut history = sink.v3_history.lock();
            assert!(history.claim_response(peer, &response, sink.boot_epoch));
            assert!(history.finish_transfer(peer, sink.self_id).is_some());
        }

        request_next_snapshot_chunk(&sink, 1, 7, 1, 32, 0, Some(peer)).await;

        let state = sink.state.lock();
        assert!(state.history_election_pending());
        assert!(
            state.history_election_fetching_snapshot().is_none(),
            "a vanished continuation owner must rearm the elected recovery"
        );
        assert!(sink_net.drain_captures().is_empty());
    }

    #[tokio::test]
    async fn late_missing_snapshot_continuation_preserves_newer_elected_source() {
        let (sink, sink_net, _sink_repo) = test_runtime(2, ReplicationConfig::default());
        let current_rank = super::HistoryRank {
            version: 2,
            freshness: 0,
            runtime_started_at: 12,
            node_id: 3,
            terminal_repository_base_version: 0,
        };
        let local_rank = super::HistoryRank::local(&sink);
        {
            let mut state = sink.state.lock();
            state.request_history_election();
            state.begin_history_election([3]);
            assert!(matches!(
                state.record_history_probe_response(3, current_rank, local_rank),
                super::HistoryProbeResponseOutcome::FetchSnapshot(_)
            ));
        }
        let (late_peer, response) = begin_correlated_history(
            &sink,
            &sink_net,
            1,
            11,
            1,
            StrictCatchupReason::HistoryElection,
        );
        {
            let mut history = sink.v3_history.lock();
            assert!(history.claim_response(late_peer, &response, sink.boot_epoch));
            assert!(history.finish_transfer(late_peer, sink.self_id).is_some());
        }

        request_next_snapshot_chunk(&sink, 1, 7, 1, 32, 0, Some(late_peer)).await;

        assert_eq!(
            sink.state
                .lock()
                .history_election_fetching_snapshot()
                .expect("newer election retained")
                .peer(),
            3
        );
        assert!(sink_net.drain_captures().is_empty());
    }

    #[tokio::test]
    async fn legacy_untagged_raw_snapshot_ignores_receiver_envelope_capability_view() {
        assert_legacy_untagged_raw_snapshot_ignores_asymmetric_peer_view(
            STRICT_PROTOCOL_VERSION_V5,
        )
        .await;
    }

    #[tokio::test]
    async fn snapshot_pagination_continues_across_global_floor_downgrade() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 96, 60_000);
        let expected_log = source_repo.log();
        let (sink, sink_net, sink_repo) = test_runtime(2, cfg);
        for net in [&source_net, &sink_net] {
            net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V4));
        }
        source_net.set_peer_strict_replication_protocol_version(2, STRICT_PROTOCOL_VERSION_V4);
        sink_net.set_peer_strict_replication_protocol_version(1, STRICT_PROTOCOL_VERSION_V4);
        begin_snapshot_fetch(&sink, 96);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(first.snapshot_has_more);
        apply_response(&sink, 1, first).await;
        let mut request = catchup_request(sink_net.drain_captures().pop().unwrap());

        source_net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V4);
        sink_net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V4);
        loop {
            respond_to_request(&source, 2, request).await;
            let response = catchup_response(source_net.drain_captures().pop().unwrap());
            let has_more = response.snapshot_has_more;
            apply_response(&sink, 1, response).await;
            if !has_more {
                break;
            }
            request = catchup_request(sink_net.drain_captures().pop().unwrap());
        }

        assert_eq!(sink_repo.current_version(), 96);
        assert_eq!(sink_repo.log(), expected_log);
    }

    #[tokio::test]
    async fn duplicate_v2_snapshot_chunk_is_idempotent() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 96, 4_000);
        let (sink, sink_net, sink_repo) = test_runtime(2, cfg);
        begin_snapshot_fetch(&sink, 96);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(first_response.snapshot_has_more);

        apply_response(&sink, 1, first_response.clone()).await;
        let continuation = catchup_request(sink_net.drain_captures().pop().unwrap());
        let receiver_before_duplicate = {
            let receivers = sink.snapshot_receivers.lock();
            let receiver = receivers.get(&1).unwrap();
            (receiver.next_cursor, receiver.snapshot_msgpack.clone())
        };
        apply_response(&sink, 1, first_response).await;

        assert!(sink_net.drain_captures().is_empty());
        let receiver_after_duplicate = {
            let receivers = sink.snapshot_receivers.lock();
            let receiver = receivers.get(&1).unwrap();
            (receiver.next_cursor, receiver.snapshot_msgpack.clone())
        };
        assert_eq!(receiver_after_duplicate, receiver_before_duplicate);
        assert!(
            sink.state
                .lock()
                .history_election_fetching_snapshot()
                .is_some()
        );
        assert_eq!(sink_repo.current_version(), 0);

        let mut request = continuation;
        loop {
            respond_to_request(&source, 2, request).await;
            let response = catchup_response(source_net.drain_captures().pop().unwrap());
            let has_more = response.snapshot_has_more;
            apply_response(&sink, 1, response).await;
            let captures = sink_net.drain_captures();
            if has_more {
                assert_eq!(captures.len(), 1);
                request = catchup_request(captures.into_iter().next().unwrap());
            } else {
                break;
            }
        }

        assert_eq!(sink_repo.current_version(), 96);
        assert_eq!(sink_repo.log(), source_repo.log());
    }

    async fn assert_delayed_final_snapshot_page_retries_completion() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 96, 4_000);
        let (sink, sink_net, sink_repo) = test_runtime(2, cfg);
        begin_snapshot_fetch(&sink, 96);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_response = catchup_response(source_net.drain_captures().pop().unwrap());
        let delayed_first = first_response.clone();
        apply_response(&sink, 1, first_response).await;
        let mut request = catchup_request(sink_net.drain_captures().pop().unwrap());
        let delayed_final = loop {
            respond_to_request(&source, 2, request).await;
            let response = catchup_response(source_net.drain_captures().pop().unwrap());
            let has_more = response.snapshot_has_more;
            if has_more {
                apply_response(&sink, 1, response).await;
                request = catchup_request(sink_net.drain_captures().pop().unwrap());
            } else {
                assert!(response.snapshot_chunk_cursor > 0);
                let delayed = response.clone();
                apply_response(&sink, 1, response).await;
                break delayed;
            }
        };

        sink_net.drain_captures();
        assert_eq!(sink_repo.current_version(), 96);
        assert_eq!(sink_repo.log(), source_repo.log());
        assert!(!sink.state.lock().history_election_pending());
        assert!(!sink.state.lock().history_election_active());

        apply_response(&sink, 1, delayed_first).await;

        assert!(sink_net.drain_captures().is_empty());
        assert!(!sink.snapshot_receivers.lock().contains_key(&1));
        assert!(!sink.state.lock().history_election_pending());
        assert!(!sink.state.lock().history_election_active());

        let delayed_transfer_id = delayed_final.snapshot_transfer_id;
        apply_response(&sink, 1, delayed_final).await;

        let captures = sink_net.drain_captures();
        assert_eq!(captures.len(), 1);
        let completion_retry = catchup_request(captures.into_iter().next().unwrap());
        assert_eq!(completion_retry.since_version, 96);
        assert!(!completion_retry.force_snapshot);
        assert_eq!(completion_retry.snapshot_transfer_id, delayed_transfer_id);
        assert_eq!(completion_retry.snapshot_chunk_cursor, 0);
        respond_to_request(&source, 2, completion_retry).await;
        source_net.drain_captures();
        assert!(!source.snapshot_transfers.lock().contains_key(&2));
        assert_eq!(sink_repo.current_version(), 96);
        assert_eq!(sink_repo.log(), source_repo.log());
        assert!(!sink.snapshot_receivers.lock().contains_key(&1));
        assert!(!sink.state.lock().history_election_pending());
        assert!(!sink.state.lock().history_election_active());
    }

    #[tokio::test]
    async fn delayed_final_forced_snapshot_page_retries_completion_without_rearming() {
        assert_delayed_final_snapshot_page_retries_completion().await;
    }

    #[tokio::test]
    async fn delayed_single_page_fallback_snapshot_is_acknowledged_without_reinstall_or_rearm() {
        let (source, source_net, source_repo) = test_runtime(1, ReplicationConfig::default());
        populate_repo(&source_repo, 1, 8);
        let (sink, sink_net, sink_repo) = test_runtime(2, ReplicationConfig::default());
        begin_snapshot_fetch(&sink, 1);

        let mut request = force_snapshot_request();
        request.force_snapshot = false;
        respond_to_request(&source, 2, request).await;
        let response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(!response.request_force_snapshot);
        assert!(response.too_old_use_snapshot);
        assert_ne!(response.snapshot_transfer_id, 0);
        assert!(!response.snapshot_has_more);
        assert_eq!(response.snapshot_chunk_cursor, 0);
        let delayed = response.clone();

        apply_response(&sink, 1, response).await;
        sink_net.drain_captures();
        assert_eq!(sink_repo.current_version(), 1);
        assert_eq!(sink_repo.log(), source_repo.log());
        assert!(!sink.state.lock().history_election_active());

        apply_response(&sink, 1, delayed).await;

        let captures = sink_net.drain_captures();
        assert_eq!(captures.len(), 1);
        let completion_retry = catchup_request(captures.into_iter().next().unwrap());
        assert_eq!(completion_retry.since_version, 1);
        assert!(!completion_retry.force_snapshot);
        assert!(!sink.snapshot_receivers.lock().contains_key(&1));
        assert!(!sink.state.lock().history_election_pending());
        assert!(!sink.state.lock().history_election_active());
        assert_eq!(sink_repo.current_version(), 1);
        assert_eq!(sink_repo.log(), source_repo.log());
    }

    #[tokio::test]
    async fn superseded_v2_snapshot_page_does_not_abort_replacement_transfer() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 96, 4_000);
        let (sink, sink_net, sink_repo) = test_runtime(2, cfg);
        begin_snapshot_fetch(&sink, 96);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_a = catchup_response(source_net.drain_captures().pop().unwrap());
        let delayed_first_a = first_a.clone();
        apply_response(&sink, 1, first_a).await;
        let continuation_a = catchup_request(sink_net.drain_captures().pop().unwrap());
        respond_to_request(&source, 2, continuation_a).await;
        let delayed_a = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(delayed_a.snapshot_chunk_cursor > 0);

        source.snapshot_transfers.lock().clear();
        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_b = catchup_response(source_net.drain_captures().pop().unwrap());
        assert_ne!(first_b.snapshot_transfer_id, delayed_a.snapshot_transfer_id);
        // Model the receiver reset performed when the old transfer is
        // explicitly rejected or its election watchdog restarts recovery.
        sink.snapshot_receivers.lock().clear();
        apply_response(&sink, 1, first_b).await;
        let mut continuation_b = catchup_request(sink_net.drain_captures().pop().unwrap());
        let receiver_before_delayed_page = {
            let receivers = sink.snapshot_receivers.lock();
            let receiver = receivers.get(&1).unwrap();
            (
                receiver.id,
                receiver.next_cursor,
                receiver.snapshot_msgpack.clone(),
            )
        };
        let election_pending_before_delayed_page = sink.state.lock().history_election_pending();

        apply_response(&sink, 1, delayed_first_a).await;

        assert!(sink_net.drain_captures().is_empty());
        let receiver_after_delayed_first_page = {
            let receivers = sink.snapshot_receivers.lock();
            let receiver = receivers.get(&1).unwrap();
            (
                receiver.id,
                receiver.next_cursor,
                receiver.snapshot_msgpack.clone(),
            )
        };
        assert_eq!(
            receiver_after_delayed_first_page,
            receiver_before_delayed_page
        );

        apply_response(&sink, 1, delayed_a).await;

        assert!(sink_net.drain_captures().is_empty());
        let receiver_after_delayed_page = {
            let receivers = sink.snapshot_receivers.lock();
            let receiver = receivers.get(&1).unwrap();
            (
                receiver.id,
                receiver.next_cursor,
                receiver.snapshot_msgpack.clone(),
            )
        };
        assert_eq!(receiver_after_delayed_page, receiver_before_delayed_page);
        assert!(
            sink.state
                .lock()
                .history_election_fetching_snapshot()
                .is_some()
        );
        assert_eq!(
            sink.state.lock().history_election_pending(),
            election_pending_before_delayed_page
        );
        assert_eq!(sink_repo.current_version(), 0);

        loop {
            respond_to_request(&source, 2, continuation_b).await;
            let response = catchup_response(source_net.drain_captures().pop().unwrap());
            let has_more = response.snapshot_has_more;
            apply_response(&sink, 1, response).await;
            let captures = sink_net.drain_captures();
            if has_more {
                assert_eq!(captures.len(), 1);
                continuation_b = catchup_request(captures.into_iter().next().unwrap());
            } else {
                break;
            }
        }

        assert_eq!(sink_repo.current_version(), 96);
        assert_eq!(sink_repo.log(), source_repo.log());
    }

    #[tokio::test]
    async fn expired_partial_snapshot_does_not_block_replacement_first_page() {
        let cfg = ReplicationConfig::default()
            .with_strict_max_catchup_bytes(256)
            .with_pending_propose_ttl(Duration::from_secs(60));
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 96, 4_000);
        let (sink, sink_net, _sink_repo) = test_runtime(2, cfg);
        begin_snapshot_fetch(&sink, 96);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_a = catchup_response(source_net.drain_captures().pop().unwrap());
        apply_response(&sink, 1, first_a.clone()).await;
        sink_net.drain_captures();
        {
            let mut receivers = sink.snapshot_receivers.lock();
            receivers.get_mut(&1).unwrap().last_used_at = Instant::now()
                .checked_sub(sink.cfg.pending_propose_ttl())
                .unwrap();
        }

        source.snapshot_transfers.lock().clear();
        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_b = catchup_response(source_net.drain_captures().pop().unwrap());
        assert_ne!(first_b.snapshot_transfer_id, first_a.snapshot_transfer_id);
        apply_response(&sink, 1, first_b.clone()).await;

        let receivers = sink.snapshot_receivers.lock();
        assert_eq!(receivers.get(&1).unwrap().id, first_b.snapshot_transfer_id);
    }

    #[tokio::test]
    async fn expired_current_snapshot_continuation_rearms_election() {
        let cfg = ReplicationConfig::default()
            .with_strict_max_catchup_bytes(256)
            .with_pending_propose_ttl(Duration::from_secs(60));
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 96, 4_000);
        let (sink, sink_net, _sink_repo) = test_runtime(2, cfg);
        begin_snapshot_fetch(&sink, 96);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first = catchup_response(source_net.drain_captures().pop().unwrap());
        apply_response(&sink, 1, first).await;
        let continuation = catchup_request(sink_net.drain_captures().pop().unwrap());
        respond_to_request(&source, 2, continuation).await;
        let continuation_response = catchup_response(source_net.drain_captures().pop().unwrap());
        {
            let mut receivers = sink.snapshot_receivers.lock();
            receivers.get_mut(&1).unwrap().last_used_at = Instant::now()
                .checked_sub(sink.cfg.pending_propose_ttl())
                .unwrap();
        }
        crate::replications::strict::runtime::run_gc_pass(&sink);
        assert!(sink.snapshot_receivers.lock().contains_key(&1));
        let mut unrelated_request = force_snapshot_request();
        unrelated_request.src_node = 3;
        respond_to_request(&sink, 3, unrelated_request).await;
        sink_net.drain_captures();
        assert!(sink.snapshot_receivers.lock().contains_key(&1));

        apply_response(&sink, 1, continuation_response).await;

        assert!(!sink.snapshot_receivers.lock().contains_key(&1));
        let state = sink.state.lock();
        assert!(state.history_election_pending());
        assert!(state.history_election_fetching_snapshot().is_none());
    }

    #[tokio::test]
    async fn delayed_rejection_does_not_abort_replacement_snapshot_receiver() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 96, 4_000);
        let (sink, sink_net, _sink_repo) = test_runtime(2, cfg.clone());
        begin_snapshot_fetch(&sink, 96);

        let mut warmup_request = force_snapshot_request();
        warmup_request.src_node = 3;
        respond_to_request(&source, 3, warmup_request).await;
        source_net.drain_captures();
        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_a = catchup_response(source_net.drain_captures().pop().unwrap());
        apply_response(&sink, 1, first_a.clone()).await;
        let continuation_a = catchup_request(sink_net.drain_captures().pop().unwrap());

        let restarted = StrictRuntime::new(
            source_repo,
            1,
            2,
            "channels".to_owned(),
            source_net.clone(),
            CancellationToken::new(),
            Arc::new(cfg),
        );
        respond_to_request(&restarted, 2, force_snapshot_request()).await;
        let first_b = catchup_response(source_net.drain_captures().pop().unwrap());
        assert_ne!(first_b.snapshot_transfer_id, first_a.snapshot_transfer_id);
        sink.snapshot_receivers.lock().clear();
        apply_response(&sink, 1, first_b.clone()).await;
        sink_net.drain_captures();

        restarted.snapshot_transfers.lock().clear();
        respond_to_request(&restarted, 2, continuation_a).await;
        let delayed_rejection = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(delayed_rejection.snapshot_transfer_rejected);
        assert_eq!(
            delayed_rejection.snapshot_transfer_id,
            first_a.snapshot_transfer_id
        );
        apply_response(&sink, 1, delayed_rejection).await;

        let receivers = sink.snapshot_receivers.lock();
        assert_eq!(receivers.get(&1).unwrap().id, first_b.snapshot_transfer_id);
        assert!(
            sink.state
                .lock()
                .history_election_fetching_snapshot()
                .is_some()
        );
    }

    #[tokio::test]
    async fn delayed_completion_does_not_retire_newer_pinned_snapshot() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 96, 4_000);
        let (sink, sink_net, _sink_repo) = test_runtime(2, cfg.clone());
        begin_snapshot_fetch(&sink, 96);

        let mut warmup_request = force_snapshot_request();
        warmup_request.src_node = 3;
        respond_to_request(&source, 3, warmup_request).await;
        source_net.drain_captures();
        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_a = catchup_response(source_net.drain_captures().pop().unwrap());
        apply_response(&sink, 1, first_a).await;
        let mut request = catchup_request(sink_net.drain_captures().pop().unwrap());
        let delayed_final_a = loop {
            respond_to_request(&source, 2, request).await;
            let response = catchup_response(source_net.drain_captures().pop().unwrap());
            let has_more = response.snapshot_has_more;
            let delayed = response.clone();
            apply_response(&sink, 1, response).await;
            if has_more {
                request = catchup_request(sink_net.drain_captures().pop().unwrap());
            } else {
                break delayed;
            }
        };
        sink_net.drain_captures();

        let restarted = StrictRuntime::new(
            source_repo,
            1,
            2,
            "channels".to_owned(),
            source_net.clone(),
            CancellationToken::new(),
            Arc::new(cfg),
        );
        respond_to_request(&restarted, 2, force_snapshot_request()).await;
        let first_b = catchup_response(source_net.drain_captures().pop().unwrap());
        let transfer_b = first_b.snapshot_transfer_id;
        assert_ne!(transfer_b, delayed_final_a.snapshot_transfer_id);

        apply_response(&sink, 1, delayed_final_a.clone()).await;
        let captures = sink_net.drain_captures();
        assert_eq!(captures.len(), 1);
        let completion_a = catchup_request(captures.into_iter().next().unwrap());
        assert_eq!(
            completion_a.snapshot_transfer_id,
            delayed_final_a.snapshot_transfer_id
        );
        respond_to_request(&restarted, 2, completion_a).await;
        source_net.drain_captures();

        assert_eq!(
            restarted.snapshot_transfers.lock().get(&2).unwrap().id,
            transfer_b
        );
    }

    #[tokio::test]
    async fn stale_v2_snapshot_continuation_does_not_replay_pinned_image() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg);
        populate_repo(&source_repo, 96, 4_000);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_a = catchup_response(source_net.drain_captures().pop().unwrap());
        let continuation_a = StrictCatchupReq {
            src_node: 2,
            since_version: first_a.snapshot_version,
            chunk_token: first_a.snapshot_version,
            force_snapshot: true,
            history_probe_only: false,
            terminal_state_cursor: super::TERMINAL_STATE_CURSOR_SKIP,
            terminal_decision_generation: first_a.terminal_decision_generation,
            snapshot_transfer_id: first_a.snapshot_transfer_id,
            snapshot_chunk_cursor: first_a.snapshot_next_cursor,
            history_transfer: None,
        };

        source.snapshot_transfers.lock().clear();
        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_b = catchup_response(source_net.drain_captures().pop().unwrap());
        assert_ne!(first_b.snapshot_transfer_id, first_a.snapshot_transfer_id);
        let pinned_before_stale_request = {
            let transfers = source.snapshot_transfers.lock();
            let transfer = transfers.get(&2).unwrap();
            (transfer.id, transfer.last_used_at)
        };
        respond_to_request(&source, 2, continuation_a).await;

        assert!(source_net.drain_captures().is_empty());
        let pinned_after_stale_request = {
            let transfers = source.snapshot_transfers.lock();
            let transfer = transfers.get(&2).unwrap();
            (transfer.id, transfer.last_used_at)
        };
        assert_eq!(pinned_after_stale_request, pinned_before_stale_request);
    }

    #[tokio::test]
    async fn invalid_cursor_does_not_replay_or_refresh_pinned_snapshot() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg);
        populate_repo(&source_repo, 96, 4_000);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first = catchup_response(source_net.drain_captures().pop().unwrap());
        let pinned_before = {
            let transfers = source.snapshot_transfers.lock();
            let transfer = transfers.get(&2).unwrap();
            (transfer.id, transfer.last_used_at)
        };
        let invalid = StrictCatchupReq {
            src_node: 2,
            since_version: first.snapshot_version,
            chunk_token: first.snapshot_version,
            force_snapshot: true,
            history_probe_only: false,
            terminal_state_cursor: super::TERMINAL_STATE_CURSOR_SKIP,
            terminal_decision_generation: first.terminal_decision_generation,
            snapshot_transfer_id: first.snapshot_transfer_id,
            snapshot_chunk_cursor: first.snapshot_total_bytes.saturating_add(1),
            history_transfer: None,
        };

        respond_to_request(&source, 2, invalid).await;

        assert!(source_net.drain_captures().is_empty());
        let pinned_after = {
            let transfers = source.snapshot_transfers.lock();
            let transfer = transfers.get(&2).unwrap();
            (transfer.id, transfer.last_used_at)
        };
        assert_eq!(pinned_after, pinned_before);
    }

    #[tokio::test]
    async fn stale_v2_snapshot_continuation_without_pinned_image_is_rejected() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg);
        populate_repo(&source_repo, 96, 4_000);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first = catchup_response(source_net.drain_captures().pop().unwrap());
        let continuation = StrictCatchupReq {
            src_node: 2,
            since_version: first.snapshot_version,
            chunk_token: first.snapshot_version,
            force_snapshot: true,
            history_probe_only: false,
            terminal_state_cursor: super::TERMINAL_STATE_CURSOR_SKIP,
            terminal_decision_generation: first.terminal_decision_generation,
            snapshot_transfer_id: first.snapshot_transfer_id,
            snapshot_chunk_cursor: first.snapshot_next_cursor,
            history_transfer: None,
        };
        source.snapshot_transfers.lock().clear();

        respond_to_request(&source, 2, continuation).await;

        let rejection = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(rejection.snapshot_transfer_rejected);
        assert!(!source.snapshot_transfers.lock().contains_key(&2));
    }

    #[tokio::test]
    async fn stale_v2_snapshot_continuation_without_receiver_preserves_current_election() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 96, 4_000);
        let (sink, sink_net, sink_repo) = test_runtime(2, cfg);
        begin_snapshot_fetch(&sink, 96);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first = catchup_response(source_net.drain_captures().pop().unwrap());
        let continuation = StrictCatchupReq {
            src_node: 2,
            since_version: first.snapshot_version,
            chunk_token: first.snapshot_version,
            force_snapshot: true,
            history_probe_only: false,
            terminal_state_cursor: super::TERMINAL_STATE_CURSOR_SKIP,
            terminal_decision_generation: first.terminal_decision_generation,
            snapshot_transfer_id: first.snapshot_transfer_id,
            snapshot_chunk_cursor: first.snapshot_next_cursor,
            history_transfer: None,
        };
        respond_to_request(&source, 2, continuation).await;
        let stale_continuation = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(stale_continuation.snapshot_chunk_cursor > 0);

        apply_response(&sink, 1, stale_continuation).await;

        assert!(sink_net.drain_captures().is_empty());
        assert!(!sink.snapshot_receivers.lock().contains_key(&1));
        assert_eq!(sink_repo.current_version(), 0);
        assert!(
            sink.state
                .lock()
                .history_election_fetching_snapshot()
                .is_some_and(|source| source.peer() == 1)
        );
    }

    #[tokio::test]
    async fn malformed_stale_v2_snapshot_page_does_not_rearm_idle_election() {
        let (sink, sink_net, sink_repo) = test_runtime(2, ReplicationConfig::default());

        apply_response(
            &sink,
            1,
            StrictCatchupResp {
                snapshot_version: 1,
                too_old_use_snapshot: true,
                history_version: 1,
                history_node: 1,
                request_force_snapshot: true,
                next_terminal_state_cursor: super::TERMINAL_STATE_CURSOR_SKIP,
                snapshot_transfer_id: 7,
                snapshot_sha256: Bytes::new(),
                ..Default::default()
            },
        )
        .await;

        assert!(sink_net.drain_captures().is_empty());
        assert_eq!(sink_repo.current_version(), 0);
        assert!(!sink.state.lock().history_election_pending());
        assert!(!sink.state.lock().history_election_active());
    }

    #[tokio::test]
    async fn admission_fallback_snapshot_received_while_idle_rearms_history_election() {
        let (sink, sink_net, sink_repo) = test_runtime(2, ReplicationConfig::default());
        sink_net.set_epoch(1, 11);
        sink_net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V4));
        sink_net.set_peer_strict_replication_protocol_version(1, STRICT_PROTOCOL_VERSION_V4);
        let peer = PeerIncarnation::new(1, 11);
        let request = sink
            .v3_history
            .lock()
            .begin_transfer(
                peer,
                5,
                0,
                crate::replications::proto::StrictCatchupReason::Admission,
                sink.cfg.pending_propose_ttl(),
                false,
                crate::replications::proto::StrictCatchupReason::Admission,
            )
            .expect("correlated admission history transfer")
            .into_parts()
            .0;
        {
            let state = sink.state.lock();
            assert!(!state.history_election_pending());
            assert!(!state.history_election_active());
        }

        let source_repo = CountingStrictRepo::new();
        populate_repo(&source_repo, 5, 1_000);
        let (snapshot_version, snapshot) = source_repo.snapshot().expect("source snapshot");
        let snapshot_len = snapshot.len() as u64;
        apply_response(
            &sink,
            1,
            StrictCatchupResp {
                snapshot_version,
                snapshot_msgpack: snapshot.clone(),
                ops: Vec::new(),
                has_more: false,
                next_chunk_token: snapshot_version,
                too_old_use_snapshot: true,
                history_version: snapshot_version,
                history_freshness: 0,
                runtime_started_at: 11,
                history_node: 1,
                terminal_states: Vec::new(),
                next_terminal_state_cursor: super::TERMINAL_STATE_CURSOR_SKIP,
                terminal_states_has_more: false,
                terminal_sync_only: false,
                request_force_snapshot: false,
                request_history_probe_only: false,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 700,
                snapshot_chunk_cursor: 0,
                snapshot_next_cursor: snapshot_len,
                snapshot_total_bytes: snapshot_len,
                snapshot_sha256: super::snapshot_sha256(&snapshot),
                snapshot_has_more: false,
                snapshot_transfer_rejected: false,
                history_transfer: Some(StrictHistoryTransferResp {
                    expected_requester_boot_epoch: sink.boot_epoch,
                    transfer_id: request.transfer_id,
                    request_nonce: request.request_nonce,
                    cursor: request.expected_cursor,
                    target_version: request.target_version,
                }),
            },
        )
        .await;

        assert_eq!(
            sink_repo.current_version(),
            0,
            "an unsolicited fallback image must not install while the election is idle"
        );
        assert!(
            !sink.v3_history.lock().has_active_transfer(peer),
            "the rejected correlated admission client must finish"
        );
        assert!(
            sink.state.lock().history_election_pending(),
            "rejecting the compacted-source fallback must rearm recovery"
        );
    }

    #[tokio::test]
    async fn stale_admission_fallback_snapshot_preserves_active_history_election() {
        #[derive(Clone, Copy, Debug)]
        enum ActivePhase {
            Probing,
            Fetching,
            Installing,
        }

        for phase in [
            ActivePhase::Probing,
            ActivePhase::Fetching,
            ActivePhase::Installing,
        ] {
            let (sink, sink_net, sink_repo) = test_runtime(2, ReplicationConfig::default());
            sink_net.set_epoch(1, 11);
            sink_net
                .set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V4));
            sink_net.set_peer_strict_replication_protocol_version(1, STRICT_PROTOCOL_VERSION_V4);
            let stale_peer = PeerIncarnation::new(1, 11);
            let request = sink
                .v3_history
                .lock()
                .begin_transfer(
                    stale_peer,
                    5,
                    0,
                    crate::replications::proto::StrictCatchupReason::Admission,
                    sink.cfg.pending_propose_ttl(),
                    false,
                    crate::replications::proto::StrictCatchupReason::Admission,
                )
                .expect("correlated stale admission history transfer")
                .into_parts()
                .0;

            let election_rank = super::HistoryRank {
                version: 6,
                freshness: 0,
                runtime_started_at: 12,
                node_id: 3,
                terminal_repository_base_version: 0,
            };
            let local_rank = super::HistoryRank::local(&sink);
            {
                let mut state = sink.state.lock();
                state.request_history_election();
                state.begin_history_election([3]);
                if matches!(phase, ActivePhase::Fetching | ActivePhase::Installing) {
                    assert!(matches!(
                        state.record_history_probe_response(3, election_rank, local_rank),
                        super::HistoryProbeResponseOutcome::FetchSnapshot(_)
                    ));
                }
                if matches!(phase, ActivePhase::Installing) {
                    assert!(matches!(
                        state.record_history_snapshot_response(
                            3,
                            election_rank,
                            local_rank,
                            election_rank.version,
                            Bytes::from_static(b"ranked snapshot"),
                        ),
                        super::HistorySnapshotResponseOutcome::Install(_)
                    ));
                }
            }

            let fallback = Bytes::from_static(b"stale unranked fallback");
            let fallback_len = fallback.len() as u64;
            apply_response(
                &sink,
                1,
                StrictCatchupResp {
                    snapshot_version: 5,
                    snapshot_msgpack: fallback.clone(),
                    ops: Vec::new(),
                    has_more: false,
                    next_chunk_token: 5,
                    too_old_use_snapshot: true,
                    history_version: 5,
                    history_freshness: 0,
                    runtime_started_at: 11,
                    history_node: 1,
                    terminal_states: Vec::new(),
                    next_terminal_state_cursor: super::TERMINAL_STATE_CURSOR_SKIP,
                    terminal_states_has_more: false,
                    terminal_sync_only: false,
                    request_force_snapshot: false,
                    request_history_probe_only: false,
                    terminal_decision_generation: 0,
                    snapshot_transfer_id: 701,
                    snapshot_chunk_cursor: 0,
                    snapshot_next_cursor: fallback_len,
                    snapshot_total_bytes: fallback_len,
                    snapshot_sha256: super::snapshot_sha256(&fallback),
                    snapshot_has_more: false,
                    snapshot_transfer_rejected: false,
                    history_transfer: Some(StrictHistoryTransferResp {
                        expected_requester_boot_epoch: sink.boot_epoch,
                        transfer_id: request.transfer_id,
                        request_nonce: request.request_nonce,
                        cursor: request.expected_cursor,
                        target_version: request.target_version,
                    }),
                },
            )
            .await;

            assert_eq!(sink_repo.current_version(), 0);
            assert!(!sink.v3_history.lock().has_active_transfer(stale_peer));
            let state = sink.state.lock();
            assert!(
                state.history_election_active(),
                "stale fallback reset the {phase:?} election"
            );
            match phase {
                ActivePhase::Probing => {
                    assert!(state.history_election_fetching_snapshot().is_none());
                    assert!(!state.history_election_installing());
                }
                ActivePhase::Fetching => {
                    assert_eq!(
                        state
                            .history_election_fetching_snapshot()
                            .expect("fetching election retained")
                            .peer(),
                        3
                    );
                }
                ActivePhase::Installing => assert!(state.history_election_installing()),
            }
        }
    }

    #[tokio::test]
    async fn altered_duplicate_v2_snapshot_chunk_rearms_without_installing() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 96, 5_000);
        let (sink, sink_net, sink_repo) = test_runtime(2, cfg);
        begin_snapshot_fetch(&sink, 96);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(first_response.snapshot_has_more);
        apply_response(&sink, 1, first_response.clone()).await;
        sink_net.drain_captures();

        let mut altered = first_response;
        let mut chunk = altered.snapshot_msgpack.to_vec();
        chunk[0] ^= 0x80;
        altered.snapshot_msgpack = Bytes::from(chunk);
        apply_response(&sink, 1, altered).await;

        assert_eq!(sink_repo.current_version(), 0);
        assert!(!sink.snapshot_receivers.lock().contains_key(&1));
        assert!(sink.state.lock().history_election_pending());
    }

    #[tokio::test]
    async fn v2_snapshot_transfer_restarts_after_source_image_loss_is_rejected() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 96, 1_000);
        let (sink, sink_net, sink_repo) = test_runtime(2, cfg);
        begin_snapshot_fetch(&sink, 96);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(first_response.snapshot_has_more);
        let first_id = first_response.snapshot_transfer_id;
        apply_response(&sink, 1, first_response).await;
        let stale_continuation = catchup_request(sink_net.drain_captures().pop().unwrap());

        // Model a source restart after application state changed: its
        // ephemeral transfer cache is gone. It must reject the uncorrelated
        // continuation rather than turn it into a new cursor-zero image.
        populate_repo(&source_repo, 97, 20_000);
        source.snapshot_transfers.lock().clear();
        respond_to_request(&source, 2, stale_continuation).await;
        let rejection = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(rejection.snapshot_transfer_rejected);
        apply_response(&sink, 1, rejection).await;
        assert!(sink.state.lock().history_election_pending());

        begin_snapshot_fetch(&sink, 97);
        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_replacement = catchup_response(source_net.drain_captures().pop().unwrap());
        assert_ne!(first_replacement.snapshot_transfer_id, first_id);
        assert_eq!(first_replacement.snapshot_chunk_cursor, 0);
        let replacement_has_more = first_replacement.snapshot_has_more;
        apply_response(&sink, 1, first_replacement).await;
        let captures = sink_net.drain_captures();
        let mut request = replacement_has_more
            .then(|| catchup_request(captures.into_iter().next().expect("snapshot continuation")));
        loop {
            let Some(next_request) = request else {
                break;
            };
            respond_to_request(&source, 2, next_request).await;
            let response = catchup_response(source_net.drain_captures().pop().unwrap());
            let has_more = response.snapshot_has_more;
            apply_response(&sink, 1, response).await;
            let captures = sink_net.drain_captures();
            if has_more {
                request = Some(catchup_request(captures.into_iter().next().unwrap()));
            } else {
                request = None;
            }
        }

        assert_eq!(sink_repo.current_version(), 97);
        assert_eq!(sink_repo.log(), source_repo.log());
    }

    #[tokio::test]
    async fn responder_restart_rejects_missing_snapshot_transfer() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 96, 500);
        let (sink, sink_net, sink_repo) = test_runtime(2, cfg.clone());
        begin_snapshot_fetch(&sink, 96);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(first_response.snapshot_has_more);
        apply_response(&sink, 1, first_response.clone()).await;
        let continuation = catchup_request(sink_net.drain_captures().pop().unwrap());

        // A real runtime restart loses the ephemeral image. It must reject the
        // old continuation rather than reuse a transfer id for new bytes.
        populate_repo(&source_repo, 97, 9_000);
        let restarted = StrictRuntime::new(
            source_repo,
            1,
            2,
            "channels".to_owned(),
            source_net.clone(),
            CancellationToken::new(),
            Arc::new(cfg),
        );
        respond_to_request(&restarted, 2, continuation).await;
        let restarted_response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(restarted_response.snapshot_transfer_rejected);
        apply_response(&sink, 1, restarted_response).await;

        assert_eq!(sink_repo.current_version(), 0);
        assert!(sink.state.lock().history_election_pending());
    }

    #[tokio::test]
    async fn out_of_order_v2_snapshot_chunk_rearms_without_installing() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(256);
        let (source, source_net, source_repo) = test_runtime(1, cfg.clone());
        populate_repo(&source_repo, 96, 100);
        let (sink, sink_net, sink_repo) = test_runtime(2, cfg);
        begin_snapshot_fetch(&sink, 96);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(first_response.snapshot_has_more);
        apply_response(&sink, 1, first_response.clone()).await;
        sink_net.drain_captures();

        let mut out_of_order = first_response;
        out_of_order.snapshot_chunk_cursor = out_of_order.snapshot_next_cursor.saturating_add(1);
        out_of_order.snapshot_next_cursor = out_of_order
            .snapshot_chunk_cursor
            .saturating_add(out_of_order.snapshot_msgpack.len() as u64);
        apply_response(&sink, 1, out_of_order).await;

        assert_eq!(sink_repo.current_version(), 0);
        assert!(sink.state.lock().history_election_pending());
    }

    #[tokio::test]
    async fn v2_snapshot_hash_mismatch_rearms_without_installing() {
        let (source, source_net, source_repo) = test_runtime(1, ReplicationConfig::default());
        populate_repo(&source_repo, 1, 42);
        let (sink, _sink_net, sink_repo) = test_runtime(2, ReplicationConfig::default());
        begin_snapshot_fetch(&sink, 1);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let mut response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(!response.snapshot_has_more);
        let mut hash = response.snapshot_sha256.to_vec();
        hash[0] ^= 0x80;
        response.snapshot_sha256 = Bytes::from(hash);
        apply_response(&sink, 1, response).await;

        assert_eq!(sink_repo.current_version(), 0);
        assert!(sink.state.lock().history_election_pending());
    }

    #[tokio::test]
    async fn oversized_v2_snapshot_transfer_is_explicitly_rejected_and_retried() {
        let source_cfg = ReplicationConfig::default().with_strict_max_snapshot_transfer_bytes(1);
        let (source, source_net, source_repo) = test_runtime(1, source_cfg);
        populate_repo(&source_repo, 1, 55);
        let (sink, _sink_net, sink_repo) = test_runtime(2, ReplicationConfig::default());
        begin_snapshot_fetch(&sink, 1);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(response.snapshot_transfer_rejected);
        apply_response(&sink, 1, response).await;

        assert_eq!(sink_repo.current_version(), 0);
        assert!(sink.state.lock().history_election_pending());
    }

    #[tokio::test]
    async fn v2_snapshot_source_images_share_one_retained_byte_cap() {
        let sample = CountingStrictRepo::new();
        populate_repo(&sample, 16, 40_000);
        let (_, sample_snapshot) = sample.snapshot().unwrap();
        let snapshot_len = sample_snapshot.len();
        let aggregate_cap = snapshot_len.checked_mul(2).unwrap() - 1;
        let cfg =
            ReplicationConfig::default().with_strict_max_snapshot_transfer_bytes(aggregate_cap);
        let (source, source_net, source_repo) = test_runtime(1, cfg);
        populate_repo(&source_repo, 16, 40_000);
        assert_eq!(source_repo.snapshot().unwrap().1.len(), snapshot_len);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let first_response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(!first_response.snapshot_transfer_rejected);
        assert_eq!(
            source
                .snapshot_transfers
                .lock()
                .get(&2)
                .unwrap()
                .snapshot_msgpack
                .len(),
            snapshot_len
        );

        let mut second_request = force_snapshot_request();
        second_request.src_node = 3;
        respond_to_request(&source, 3, second_request).await;
        let CapturedFrame::StrictUnicast { dst, body, .. } =
            source_net.drain_captures().pop().unwrap()
        else {
            panic!("expected strict unicast catchup response");
        };
        assert_eq!(dst, 3);
        let StrictBody::CatchupResp(second_response) = body else {
            panic!("expected catchup response");
        };
        assert!(second_response.snapshot_transfer_rejected);
        let transfers = source.snapshot_transfers.lock();
        assert_eq!(transfers.len(), 1);
        assert!(transfers.contains_key(&2));
    }

    #[tokio::test]
    async fn v2_snapshot_receiver_assemblies_share_one_retained_byte_cap() {
        let cfg = ReplicationConfig::default().with_strict_max_snapshot_transfer_bytes(10);
        let (sink, sink_net, _) = test_runtime(2, cfg);
        let first_response = StrictCatchupResp {
            snapshot_version: 8,
            snapshot_msgpack: Bytes::from_static(b"abcdef"),
            ops: Vec::new(),
            has_more: false,
            next_chunk_token: 8,
            too_old_use_snapshot: true,
            history_version: 8,
            history_freshness: 0,
            runtime_started_at: 1,
            history_node: 1,
            terminal_states: Vec::new(),
            next_terminal_state_cursor: super::TERMINAL_STATE_CURSOR_SKIP,
            terminal_states_has_more: false,
            terminal_sync_only: false,
            request_force_snapshot: false,
            request_history_probe_only: false,
            terminal_decision_generation: 0,
            snapshot_transfer_id: 11,
            snapshot_chunk_cursor: 0,
            snapshot_next_cursor: 6,
            snapshot_total_bytes: 8,
            snapshot_sha256: Bytes::from(vec![0x11; 32]),
            snapshot_has_more: true,
            snapshot_transfer_rejected: false,
            history_transfer: None,
        };
        apply_response(&sink, 1, first_response).await;
        sink_net.drain_captures();

        let second_response = StrictCatchupResp {
            snapshot_version: 8,
            snapshot_msgpack: Bytes::from_static(b"12345"),
            ops: Vec::new(),
            has_more: false,
            next_chunk_token: 8,
            too_old_use_snapshot: true,
            history_version: 8,
            history_freshness: 0,
            runtime_started_at: 1,
            history_node: 3,
            terminal_states: Vec::new(),
            next_terminal_state_cursor: super::TERMINAL_STATE_CURSOR_SKIP,
            terminal_states_has_more: false,
            terminal_sync_only: false,
            request_force_snapshot: false,
            request_history_probe_only: false,
            terminal_decision_generation: 0,
            snapshot_transfer_id: 22,
            snapshot_chunk_cursor: 0,
            snapshot_next_cursor: 5,
            snapshot_total_bytes: 8,
            snapshot_sha256: Bytes::from(vec![0x22; 32]),
            snapshot_has_more: true,
            snapshot_transfer_rejected: false,
            history_transfer: None,
        };
        apply_response(&sink, 3, second_response).await;

        {
            let receivers = sink.snapshot_receivers.lock();
            assert_eq!(receivers.len(), 1);
            assert_eq!(
                receivers.get(&1).unwrap().snapshot_msgpack.as_slice(),
                b"abcdef"
            );
            assert!(!receivers.contains_key(&3));
        }
        assert!(sink.state.lock().history_election_pending());
    }

    #[tokio::test]
    async fn legacy_requester_never_receives_an_oversized_snapshot_frame() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(1);
        let (source, source_net, source_repo) = test_runtime(1, cfg);
        source_net.set_peer_strict_replication_protocol_version(2, 1);
        populate_repo(&source_repo, 1, 88);

        respond_to_request(&source, 2, force_snapshot_request()).await;

        assert!(
            source_net.drain_captures().is_empty(),
            "legacy catchup must fail closed instead of emitting a partial snapshot"
        );
    }

    #[tokio::test]
    async fn snapshot_capture_failure_returns_an_explicit_v2_rejection() {
        let (source, source_net, source_repo) = test_runtime(1, ReplicationConfig::default());
        source_repo.fail_snapshot_captures("injected snapshot capture failure");

        respond_to_request(
            &source,
            2,
            StrictCatchupReq {
                src_node: 2,
                since_version: 0,
                chunk_token: 0,
                force_snapshot: true,
                history_probe_only: false,
                terminal_state_cursor: super::TERMINAL_STATE_CURSOR_SKIP,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
                history_transfer: None,
            },
        )
        .await;

        let response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(response.snapshot_transfer_rejected);
        assert!(response.snapshot_msgpack.is_empty());
        assert_eq!(source_net.strict_repository_capability_loss_reports(), 0);
    }

    #[tokio::test]
    async fn typed_durability_snapshot_capture_failure_withdraws_repository_capability() {
        let (source, source_net, source_repo) = test_runtime(1, ReplicationConfig::default());
        source_repo.fail_snapshot_captures_durably_without_capability_loss(
            "injected durable snapshot capture failure",
        );

        respond_to_request(&source, 2, force_snapshot_request()).await;

        let response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(response.snapshot_transfer_rejected);
        assert_eq!(source_repo.strict_replication_protocol_version(), 2);
        assert_eq!(source_net.strict_repository_capability_loss_reports(), 1);
    }

    #[tokio::test]
    async fn snapshot_install_failure_rearms_history_election_without_applying_response_ops() {
        let net = MockNet::new(1, vec![1, 2]);
        let repo = CountingStrictRepo::new();
        repo.fail_snapshot_installs("injected snapshot install failure");
        let rt = StrictRuntime::new(
            repo.clone(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let remote_rank = super::HistoryRank {
            version: 1,
            freshness: 0,
            runtime_started_at: 1,
            node_id: 2,
            terminal_repository_base_version: 0,
        };
        let local_rank = super::HistoryRank::local(&rt);
        {
            let mut state = rt.state.lock();
            state.begin_history_election([2]);
            assert!(matches!(
                state.record_history_probe_response(2, remote_rank, local_rank),
                super::HistoryProbeResponseOutcome::FetchSnapshot(_)
            ));
        }

        apply_response(
            &rt,
            2,
            StrictCatchupResp {
                snapshot_version: 1,
                snapshot_msgpack: Bytes::from(rmp_serde::to_vec(&vec![(1u64, 101u64)]).unwrap()),
                ops: vec![CatchupOp {
                    version: 2,
                    op_msgpack: Bytes::from(rmp_serde::to_vec(&202u64).unwrap()),
                    strict_op_id_hi: 0,
                    strict_op_id_lo: 0,
                    strict_ts_final: 0,
                    strict_terminal_ballot: 0,
                    strict_terminal_resolver_node: 0,
                    strict_terminal_resolver_boot_epoch: 0,
                    strict_terminal_frozen_targets: Vec::new(),
                }],
                has_more: false,
                next_chunk_token: 2,
                too_old_use_snapshot: true,
                history_version: remote_rank.version,
                history_freshness: remote_rank.freshness,
                runtime_started_at: remote_rank.runtime_started_at,
                history_node: 2,
                terminal_states: Vec::new(),
                next_terminal_state_cursor: super::TERMINAL_STATE_CURSOR_SKIP,
                terminal_states_has_more: false,
                terminal_sync_only: false,
                request_force_snapshot: true,
                request_history_probe_only: false,
                terminal_decision_generation: 0,
                ..Default::default()
            },
        )
        .await;

        assert_eq!(repo.current_version(), 0);
        assert!(repo.log().is_empty());
        let state = rt.state.lock();
        assert!(state.history_election_pending());
        assert!(!state.history_election_active());
        assert!(state.can_bootstrap_catchup());
        assert_eq!(net.strict_repository_capability_loss_reports(), 0);
    }

    #[tokio::test]
    async fn durability_snapshot_install_failure_withdraws_repository_capability() {
        let (source, source_net, source_repo) = test_runtime(1, ReplicationConfig::default());
        populate_repo(&source_repo, 1, 1_000);
        let (sink, sink_net, sink_repo) = test_runtime(2, ReplicationConfig::default());
        sink_repo.fail_snapshot_installs_durably("injected durable snapshot failure");
        begin_snapshot_fetch(&sink, 1);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(!response.snapshot_has_more);
        apply_response(&sink, 1, response).await;

        assert_eq!(sink_net.strict_repository_capability_loss_reports(), 1);
        assert!(sink.state.lock().history_election_pending());
    }

    #[tokio::test]
    async fn typed_durability_snapshot_install_failure_withdraws_repository_capability() {
        let (source, source_net, source_repo) = test_runtime(1, ReplicationConfig::default());
        populate_repo(&source_repo, 1, 2_000);
        let (sink, sink_net, sink_repo) = test_runtime(2, ReplicationConfig::default());
        sink_repo.fail_snapshot_installs_durably_without_capability_loss(
            "injected durable snapshot install failure",
        );
        begin_snapshot_fetch(&sink, 1);

        respond_to_request(&source, 2, force_snapshot_request()).await;
        let response = catchup_response(source_net.drain_captures().pop().unwrap());
        assert!(!response.snapshot_has_more);
        apply_response(&sink, 1, response).await;

        assert_eq!(sink_repo.strict_replication_protocol_version(), 2);
        assert_eq!(sink_net.strict_repository_capability_loss_reports(), 1);
        assert!(sink.state.lock().history_election_pending());
    }

    #[tokio::test]
    async fn proofless_catchup_raises_far_behind_clock_and_delivers_after_tick() {
        let (rt, net, repo) = test_runtime(2, ReplicationConfig::default());
        let op_id = make_op_id(1, 1, 80_277);

        apply_response(&rt, 1, proofless_catchup_response(op_id, 80_277, 41)).await;

        {
            let state = rt.state.lock();
            assert_eq!(state.clock, 80_277, "catchup must not add an extra tick");
            assert_eq!(state.peer_clocks.get(&2), Some(&80_277));
            assert!(state.committed_ids.contains(&op_id));
        }

        // With no remote delivery-watermark participant, the catchup wake
        // must make the normal clock loop cross ts_final and unblock delivery.
        net.set_alive(vec![2]);
        rt.start();
        tokio::time::timeout(Duration::from_secs(1), async {
            while repo.current_version() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("far-ahead catchup commit did not converge after a clock tick");
        assert_eq!(repo.log(), vec![(1, 41)]);
        rt.shutdown.cancel();
    }

    #[tokio::test]
    async fn duplicate_proofless_catchup_repairs_clock_and_wakes_both_loops() {
        let (rt, _, _) = test_runtime(2, ReplicationConfig::default());
        let op_id = make_op_id(1, 1, 72);
        let response = proofless_catchup_response(op_id, 72, 42);

        apply_response(&rt, 1, response.clone()).await;
        tokio::time::timeout(Duration::from_millis(100), rt.deliver_signal.notified())
            .await
            .expect("initial catchup did not wake delivery");
        tokio::time::timeout(Duration::from_millis(100), rt.clock_tick_signal.notified())
            .await
            .expect("initial catchup did not wake clock ticking");

        {
            let mut state = rt.state.lock();
            state.clock = 1;
            state.peer_clocks.insert(2, 1);
        }
        apply_response(&rt, 1, response).await;

        {
            let state = rt.state.lock();
            assert_eq!(state.clock, 72);
            assert_eq!(state.peer_clocks.get(&2), Some(&72));
            assert_eq!(state.commit_buffer.len(), 1, "duplicate was re-buffered");
        }
        tokio::time::timeout(Duration::from_millis(100), rt.deliver_signal.notified())
            .await
            .expect("duplicate catchup did not wake delivery");
        tokio::time::timeout(Duration::from_millis(100), rt.clock_tick_signal.notified())
            .await
            .expect("duplicate catchup did not wake clock ticking");
    }

    #[tokio::test]
    async fn proofless_catchup_does_not_regress_a_higher_clock() {
        let (rt, _, _) = test_runtime(2, ReplicationConfig::default());
        {
            let mut state = rt.state.lock();
            state.clock = 90_000;
            state.peer_clocks.insert(2, 90_000);
        }

        apply_response(
            &rt,
            1,
            proofless_catchup_response(make_op_id(1, 1, 73), 80_277, 43),
        )
        .await;

        let state = rt.state.lock();
        assert_eq!(state.clock, 90_000);
        assert_eq!(state.peer_clocks.get(&2), Some(&90_000));
    }

    #[tokio::test]
    async fn catchup_ops_do_not_bypass_terminal_or_resolution_promise_fences() {
        let (rt, net, repo) = test_runtime(2, ReplicationConfig::default());
        let terminal_id = make_op_id(1, 1, 3);
        let promised_id = make_op_id(1, 1, 4);
        rt.recv_resolution_prepare(
            1,
            StrictResolutionPrepare {
                resolver_node: 1,
                ballot: 11,
                coord_node: 1,
                op_id_hi: promised_id.0,
                op_id_lo: promised_id.1,
                src_clock: 11,
                frozen_targets: Vec::new(),
            },
        )
        .await;
        net.drain_captures();
        let clock_before_catchup = {
            let state = rt.state.lock();
            (state.clock, state.peer_clocks.get(&2).copied())
        };

        apply_response(
            &rt,
            1,
            StrictCatchupResp {
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: vec![
                    CatchupOp {
                        version: 1,
                        op_msgpack: Bytes::from(rmp_serde::to_vec(&41u64).unwrap()),
                        strict_op_id_hi: terminal_id.0,
                        strict_op_id_lo: terminal_id.1,
                        strict_ts_final: 21,
                        strict_terminal_ballot: 0,
                        strict_terminal_resolver_node: 0,
                        strict_terminal_resolver_boot_epoch: 0,
                        strict_terminal_frozen_targets: Vec::new(),
                    },
                    CatchupOp {
                        version: 2,
                        op_msgpack: Bytes::from(rmp_serde::to_vec(&42u64).unwrap()),
                        strict_op_id_hi: promised_id.0,
                        strict_op_id_lo: promised_id.1,
                        strict_ts_final: 22,
                        strict_terminal_ballot: 0,
                        strict_terminal_resolver_node: 0,
                        strict_terminal_resolver_boot_epoch: 0,
                        strict_terminal_frozen_targets: Vec::new(),
                    },
                ],
                has_more: false,
                next_chunk_token: 2,
                too_old_use_snapshot: false,
                history_version: 2,
                history_freshness: 0,
                runtime_started_at: 1,
                history_node: 1,
                terminal_states: vec![terminal_abort(terminal_id)],
                next_terminal_state_cursor: 1,
                terminal_states_has_more: false,
                terminal_sync_only: false,
                request_force_snapshot: false,
                request_history_probe_only: false,
                terminal_decision_generation: 0,
                ..Default::default()
            },
        )
        .await;

        let state = rt.state.lock();
        assert!(!state.committed_ids.contains(&terminal_id));
        assert!(!state.committed_ids.contains(&promised_id));
        assert!(
            state
                .commit_buffer
                .values()
                .all(|buffered| buffered.op_id != terminal_id && buffered.op_id != promised_id)
        );
        assert_eq!(
            (state.clock, state.peer_clocks.get(&2).copied()),
            clock_before_catchup,
            "fenced catchup metadata must not advance the local clock"
        );
        assert!(repo.log().is_empty());
    }

    #[tokio::test]
    async fn legacy_requester_with_terminal_fence_is_declined() {
        let (source, source_net, _) = test_runtime(1, ReplicationConfig::default());
        source_net.set_peer_strict_replication_protocol_version(2, 0);
        let terminal_id = make_op_id(1, 1, 5);
        source
            .apply_catchup_terminal_state(terminal_abort(terminal_id))
            .await;

        respond_to_request(
            &source,
            2,
            StrictCatchupReq {
                src_node: 2,
                since_version: 0,
                chunk_token: 0,
                force_snapshot: false,
                history_probe_only: false,
                terminal_state_cursor: 0,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
                history_transfer: None,
            },
        )
        .await;

        assert!(
            source_net.drain_captures().is_empty(),
            "a requester without v2 terminal generations must not receive history that can outlive a fence"
        );
    }
}
