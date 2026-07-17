//! Strict-mode catchup: chunked snapshot + log replay over `OverlayData`.
//!
//! Ordinary history paging is stateless on the server side: each request
//! carries `since_version` plus a continuation `chunk_token`; the server returns up to
//! [`crate::replications::ReplicationConfig::strict_max_catchup_ops`]
//! ops with `has_more` set when more are available. The client iterates by
//! re-issuing requests with the returned `next_chunk_token` until
//! `has_more = false`. V2 snapshots are deliberately different: a responder
//! pins one immutable image per peer/transfer and the receiver assembles
//! authenticated, in-order byte chunks before installing it.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use aws_lc_rs::digest::{SHA256, digest};
use bytes::Bytes;
use prost::Message as _;
use tracing::warn;

use super::super::error::ReplicationError;
use super::super::metrics::{self, CatchupMode, ReplicationPipelineKind, ReplicationPipelineStage};
use super::super::proto::{CatchupOp, StrictBody, StrictCatchupReq, StrictCatchupResp};
use super::runtime::{
    HISTORY_ELECTION_SNAPSHOT_TOKEN, HistoryProbeResponseOutcome, HistoryRank,
    HistorySnapshotResponseOutcome, STRICT_PROTOCOL_VERSION_V2, SnapshotReceiveTransfer,
    SnapshotTransfer, StrictRuntime, TerminalCommitProof, terminal_identity_from_wire,
};
use super::{LogSlice, StrictLogMetadata, StrictReplicable, StrictSnapshotError};
use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::ServiceLevel;

/// Opt out of terminal-fence transfer for steady-state probes. Startup and
/// membership-heal catchup begin at zero and paginate the stable journal.
pub(crate) const TERMINAL_STATE_CURSOR_SKIP: u64 = u64::MAX;

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
    let history_probe = response.request_history_probe_only
        && response.terminal_states.is_empty()
        && response.ops.is_empty()
        && !response.terminal_sync_only;
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
) {
    if !response_fits_budget(rt, from, &response, true) {
        return;
    }
    let history_probe = response.request_history_probe_only
        && response.terminal_states.is_empty()
        && response.ops.is_empty()
        && !response.terminal_sync_only;
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
    }
}

fn v2_snapshot_transfer_supported<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    peer: NodeIdentifier,
) -> bool {
    rt.v2_terminal_catchup_supported_by(peer)
        && rt.repo.strict_replication_protocol_version() >= STRICT_PROTOCOL_VERSION_V2
        && rt.net.local_strict_replication_protocol_version() >= STRICT_PROTOCOL_VERSION_V2
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
) {
    transfers.retain(|_, transfer| now.duration_since(transfer.last_used_at) < ttl);
    receivers.retain(|_, transfer| now.duration_since(transfer.last_used_at) < ttl);
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

fn snapshot_transfer_cursor(transfer: &SnapshotTransfer, req: &StrictCatchupReq) -> usize {
    let requested_cursor = usize::try_from(req.snapshot_chunk_cursor).ok();
    if req.snapshot_transfer_id == 0 && req.snapshot_chunk_cursor == 0 {
        Some(0)
    } else if req.snapshot_transfer_id == transfer.id {
        requested_cursor.filter(|cursor| *cursor <= transfer.snapshot_msgpack.len())
    } else {
        None
    }
    .unwrap_or(0)
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

fn next_snapshot_transfer_id<R: StrictReplicable>(rt: &StrictRuntime<R>) -> u64 {
    loop {
        let id = rt.snapshot_transfer_counter.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}

/// Select the stable responder-side image for this request. A bad cursor or
/// stale transfer id deliberately restarts from byte zero of the existing
/// image, while a responder restart/TTL expiry creates a fresh image.
fn pinned_snapshot_transfer<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    req: &StrictCatchupReq,
    terminal_decision_generation: u64,
) -> Result<(SnapshotTransfer, usize), ()> {
    let now = Instant::now();
    {
        let mut transfers = rt.snapshot_transfers.lock();
        let mut receivers = rt.snapshot_receivers.lock();
        expire_stale_snapshot_images(
            &mut transfers,
            &mut receivers,
            now,
            rt.cfg.pending_propose_ttl(),
        );
        if let Some(transfer) = transfers.get_mut(&from) {
            transfer.last_used_at = now;
            return Ok((transfer.clone(), snapshot_transfer_cursor(transfer, req)));
        }
    }

    let (version, snapshot_msgpack) = match rt.repo.snapshot() {
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
            return Err(());
        }
    };
    if snapshot_msgpack.len() > rt.cfg.strict_max_snapshot_transfer_bytes() {
        warn!(
            from,
            snapshot_bytes = snapshot_msgpack.len(),
            max_snapshot_bytes = rt.cfg.strict_max_snapshot_transfer_bytes(),
            "strict v2 snapshot exceeds the aggregate retained-image resource limit"
        );
        return Err(());
    }
    let mut rank = HistoryRank::local(rt);
    rank.version = version;
    let transfer = SnapshotTransfer {
        id: next_snapshot_transfer_id(rt),
        version,
        snapshot_sha256: snapshot_sha256(&snapshot_msgpack),
        snapshot_msgpack,
        rank,
        terminal_decision_generation,
        last_used_at: now,
    };
    let mut transfers = rt.snapshot_transfers.lock();
    let mut receivers = rt.snapshot_receivers.lock();
    expire_stale_snapshot_images(
        &mut transfers,
        &mut receivers,
        now,
        rt.cfg.pending_propose_ttl(),
    );
    if let Some(existing) = transfers.get_mut(&from) {
        existing.last_used_at = now;
        return Ok((existing.clone(), snapshot_transfer_cursor(existing, req)));
    }
    let Some(retained_bytes) = retained_snapshot_bytes(&transfers, &receivers) else {
        warn!(
            from,
            "strict v2 snapshot retained-byte accounting overflowed"
        );
        return Err(());
    };
    let Some(required_bytes) = retained_bytes.checked_add(transfer.snapshot_msgpack.len()) else {
        warn!(
            from,
            "strict v2 snapshot retained-byte accounting overflowed"
        );
        return Err(());
    };
    if required_bytes > rt.cfg.strict_max_snapshot_transfer_bytes() {
        warn!(
            from,
            retained_bytes,
            snapshot_bytes = transfer.snapshot_msgpack.len(),
            max_snapshot_bytes = rt.cfg.strict_max_snapshot_transfer_bytes(),
            "strict v2 snapshot would exceed the aggregate retained-image resource limit"
        );
        return Err(());
    }
    transfers.insert(from, transfer.clone());
    Ok((transfer, 0))
}

fn snapshot_chunk_response<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    transfer: &SnapshotTransfer,
    req: &StrictCatchupReq,
    cursor: usize,
) -> Option<StrictCatchupResp> {
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
        snapshot_transfer_id: 0,
        snapshot_chunk_cursor: 0,
        snapshot_next_cursor: 0,
        snapshot_total_bytes: 0,
        snapshot_sha256: Bytes::new(),
        snapshot_has_more: false,
        snapshot_transfer_rejected: true,
    };
    send_v2_response(rt, from, response).await;
}

async fn respond_with_snapshot_transfer<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    req: &StrictCatchupReq,
    terminal_decision_generation: u64,
    build_started_at: Instant,
) {
    let (transfer, cursor) =
        match pinned_snapshot_transfer(rt, from, req, terminal_decision_generation) {
            Ok(transfer) => transfer,
            Err(()) => {
                send_snapshot_transfer_rejected(rt, from, req, terminal_decision_generation).await;
                return;
            }
        };
    // If a terminal decision landed after the image capture, the peer must
    // re-page the new fence cut before it receives any image that could
    // include the decision's repository delivery.
    if transfer.terminal_decision_generation != rt.terminal_decision_generation() {
        rt.snapshot_transfers.lock().remove(&from);
        warn!(
            from,
            "strict v2 snapshot transfer invalidated by a newer terminal fence"
        );
        send_snapshot_transfer_rejected(rt, from, req, terminal_decision_generation).await;
        return;
    }
    let Some(response) = snapshot_chunk_response(rt, &transfer, req, cursor) else {
        warn!(
            from,
            max_bytes = rt.strict_catchup_response_budget(),
            "strict v2 snapshot transfer cannot fit one byte in the response budget"
        );
        send_snapshot_transfer_rejected(rt, from, req, terminal_decision_generation).await;
        return;
    };
    let response_bytes = response.snapshot_msgpack.len();
    metrics::record_catchup_response(CatchupMode::Strict, 0, response_bytes);
    metrics::record_pipeline_stage(
        ReplicationPipelineKind::Strict,
        ReplicationPipelineStage::CatchupBuild,
        build_started_at.elapsed(),
    );
    send_v2_response(rt, from, response).await;
}

/// Build and send a `StrictCatchupResp` answering `req`.
pub(crate) async fn respond_to_request<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    req: StrictCatchupReq,
) {
    let terminal_probe =
        req.history_probe_only && req.terminal_state_cursor != TERMINAL_STATE_CURSOR_SKIP;
    let Some(_permit) = rt
        .cfg
        .try_begin_catchup(CatchupMode::Strict, &rt.topic, from)
    else {
        return;
    };
    if !rt.terminal_storage_ready() {
        warn!(
            from,
            "strict catchup declined because terminal storage is unavailable"
        );
        return;
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
    if !v2_terminal_catchup && rt.has_any_terminal_decision() {
        warn!(
            from,
            "strict catchup declined because requester cannot prove a complete terminal fence sync"
        );
        return;
    }
    let build_started_at = std::time::Instant::now();
    let v2_snapshot_transfer = v2_snapshot_transfer_supported(rt, from);
    // A normal history request after the final image chunk is the receiver's
    // implicit completion acknowledgement. Retain a completed image until
    // then (or TTL) so a lost final response can be retried safely.
    if req.snapshot_transfer_id == 0
        && !req.force_snapshot
        && !req.history_probe_only
        && rt
            .snapshot_transfers
            .lock()
            .get(&from)
            .is_some_and(|transfer| req.since_version >= transfer.version)
    {
        rt.snapshot_transfers.lock().remove(&from);
    }

    // Terminal decisions are durable fences and must reach a joining member
    // before it processes ordinary history. Page them independently from the
    // repository-version cursor so a long-lived journal cannot inflate every
    // catchup response beyond the transport frame cap.
    let current_terminal_decision_generation = rt.terminal_decision_generation();
    let must_restart_terminal_sync = v2_terminal_catchup
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
    let terminal_state_cursor = if v2_terminal_catchup
        && (req.terminal_state_cursor != TERMINAL_STATE_CURSOR_SKIP || must_restart_terminal_sync)
    {
        let terminal_cursor = if must_restart_terminal_sync {
            0
        } else {
            req.terminal_state_cursor
        };
        let terminal_page = rt.terminal_states_for_catchup_page(
            from,
            terminal_cursor,
            rt.cfg.strict_max_catchup_ops(),
            rt.strict_catchup_response_budget(),
        );
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

    if req.snapshot_transfer_id != 0 {
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
        let (sv, snap) = match rt.repo.snapshot() {
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
        snapshot_version = sv;
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
                let (sv, snap) = match rt.repo.snapshot() {
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
                snapshot_version = sv;
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
    for (v, entry) in &effective_ops {
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
                            let terminal_proof = match rt.terminal_commit_proof_for_catchup(
                                (metadata.op_id_hi, metadata.op_id_lo),
                                metadata.ts_final,
                                &op_msgpack,
                            ) {
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
                if terminal_proof.is_some() && !rt.v2_terminal_catchup_supported_by(from) {
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
            < effective_ops
                .last()
                .map(|(version, _)| *version)
                .unwrap_or(effective_since)
    {
        has_more = true;
    }
    // A terminal decision is persisted before its repository delivery. If a
    // decision appeared while this response captured history, do not send a
    // snapshot/log cut that includes the commit without its fence. Restart
    // terminal pagination from the new durable cut first. The generation was
    // captured with the terminal page (or verified from the request's echoed
    // completed cut), so an abort committed in the gap cannot be missed.
    if terminal_state_cursor == TERMINAL_STATE_CURSOR_SKIP
        && terminal_decision_generation != rt.terminal_decision_generation()
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
        let terminal_page = rt.terminal_states_for_catchup_page(
            from,
            0,
            rt.cfg.strict_max_catchup_ops(),
            rt.strict_catchup_response_budget(),
        );
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
    metrics::record_catchup_response(CatchupMode::Strict, catchup_ops.len(), response_bytes);
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
        HistoryRank {
            version: snapshot_version,
            freshness: current_rank.freshness,
            runtime_started_at: current_rank.runtime_started_at,
            node_id: current_rank.node_id,
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
    };
    if v2_terminal_catchup {
        send_v2_response(rt, from, resp).await;
    } else {
        send_response(rt, from, resp).await;
    }
}

fn rearm_history_election<R: StrictReplicable>(rt: &StrictRuntime<R>) {
    let mut state = rt.state.lock();
    state.finish_history_election();
    state.request_history_election();
    drop(state);
    rt.wake_clock_tick_loop();
}

async fn install_snapshot_candidate<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    rank: HistoryRank,
    snapshot_version: u64,
    snapshot_msgpack: Bytes,
    apply_started_at: Instant,
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
        return;
    };
    // Delivery can begin after the state transition, so retain the explicit
    // fence immediately before the repository receives the replacement.
    if rt.delivery_in_flight() != 0 {
        warn!(
            from,
            "strict snapshot install deferred while terminal delivery is in flight"
        );
        rearm_history_election(rt);
        return;
    }
    let snapshot_started_at = Instant::now();
    if rt.delivery_in_flight() != 0 {
        warn!(
            from,
            "strict snapshot install deferred while terminal delivery started"
        );
        rearm_history_election(rt);
        return;
    }
    let installed_version = winner.snapshot_version;
    let install_result = rt
        .repo
        .install_snapshot(installed_version, winner.snapshot_msgpack)
        .await;
    metrics::record_pipeline_stage(
        ReplicationPipelineKind::Strict,
        ReplicationPipelineStage::SnapshotInstall,
        snapshot_started_at.elapsed(),
    );
    match install_result {
        Ok(()) => {
            rt.state.lock().finish_history_election();
            request_history_after_snapshot(rt, from, installed_version).await;
        }
        Err(error) => {
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
            rearm_history_election(rt);
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
) {
    if from == rt.self_id
        || !rt.net.has_route(from, ServiceLevel::Reliable)
        || !v2_snapshot_transfer_supported(rt, from)
    {
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
        snapshot_transfer_id: 0,
        snapshot_chunk_cursor: 0,
    };
    metrics::record_catchup_request(CatchupMode::Strict);
    if let Err(error) = rt
        .net
        .send_unicast(from, &rt.topic, StrictBody::CatchupReq(req))
        .await
    {
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
        snapshot_version: u64,
        snapshot_msgpack: Vec<u8>,
        snapshot_sha256: Bytes,
    },
    Restart,
}

fn receive_snapshot_chunk<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    resp: &StrictCatchupResp,
    remote_rank: HistoryRank,
) -> SnapshotReceiveOutcome {
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
        return SnapshotReceiveOutcome::Restart;
    }
    let Some(total_bytes) = usize::try_from(resp.snapshot_total_bytes).ok() else {
        return SnapshotReceiveOutcome::Restart;
    };
    if total_bytes > rt.cfg.strict_max_snapshot_transfer_bytes() {
        warn!(
            from,
            advertised_bytes = resp.snapshot_total_bytes,
            max_snapshot_bytes = rt.cfg.strict_max_snapshot_transfer_bytes(),
            "strict v2 snapshot transfer exceeds the local aggregate resource limit"
        );
        return SnapshotReceiveOutcome::Restart;
    }
    let Some(chunk_cursor) = usize::try_from(resp.snapshot_chunk_cursor).ok() else {
        return SnapshotReceiveOutcome::Restart;
    };
    let Some(next_cursor) = usize::try_from(resp.snapshot_next_cursor).ok() else {
        return SnapshotReceiveOutcome::Restart;
    };
    let Some(expected_next_cursor) = chunk_cursor.checked_add(resp.snapshot_msgpack.len()) else {
        return SnapshotReceiveOutcome::Restart;
    };
    if chunk_cursor > total_bytes
        || next_cursor > total_bytes
        || next_cursor != expected_next_cursor
        || resp.snapshot_has_more != (next_cursor < total_bytes)
        || (chunk_cursor < total_bytes && resp.snapshot_msgpack.is_empty())
    {
        return SnapshotReceiveOutcome::Restart;
    }

    let now = Instant::now();
    // Retained snapshot bytes span responder images and receiver assemblies.
    // Keep this source-map-then-receiver-map order in every dual-map path.
    let mut transfers = rt.snapshot_transfers.lock();
    let mut receivers = rt.snapshot_receivers.lock();
    expire_stale_snapshot_images(
        &mut transfers,
        &mut receivers,
        now,
        rt.cfg.pending_propose_ttl(),
    );
    let replace = match receivers.get(&from) {
        Some(transfer) if transfer.id == resp.snapshot_transfer_id => false,
        Some(_) => chunk_cursor == 0,
        None => chunk_cursor == 0,
    };
    if !replace
        && receivers
            .get(&from)
            .is_none_or(|transfer| transfer.id != resp.snapshot_transfer_id)
    {
        return SnapshotReceiveOutcome::Restart;
    }
    if replace {
        // A new transfer supersedes this peer's old partial image before it
        // competes for the aggregate retained-byte budget.
        receivers.remove(&from);
    } else {
        let Some(transfer) = receivers.get(&from) else {
            return SnapshotReceiveOutcome::Restart;
        };
        if transfer.id != resp.snapshot_transfer_id
            || transfer.version != resp.snapshot_version
            || transfer.total_bytes != resp.snapshot_total_bytes
            || transfer.snapshot_sha256 != resp.snapshot_sha256
            || transfer.rank != remote_rank
            || transfer.terminal_decision_generation != resp.terminal_decision_generation
            || transfer.next_cursor != resp.snapshot_chunk_cursor
            || transfer.snapshot_msgpack.len() != chunk_cursor
        {
            receivers.remove(&from);
            return SnapshotReceiveOutcome::Restart;
        }
    }

    let Some(retained_bytes) = retained_snapshot_bytes(&transfers, &receivers) else {
        warn!(
            from,
            "strict v2 snapshot retained-byte accounting overflowed"
        );
        receivers.remove(&from);
        return SnapshotReceiveOutcome::Restart;
    };
    let Some(required_bytes) = retained_bytes.checked_add(resp.snapshot_msgpack.len()) else {
        warn!(
            from,
            "strict v2 snapshot retained-byte accounting overflowed"
        );
        receivers.remove(&from);
        return SnapshotReceiveOutcome::Restart;
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
        return SnapshotReceiveOutcome::Restart;
    }
    if replace {
        receivers.insert(
            from,
            SnapshotReceiveTransfer {
                id: resp.snapshot_transfer_id,
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
        return SnapshotReceiveOutcome::Restart;
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
    let Some(transfer) = receivers.remove(&from) else {
        return SnapshotReceiveOutcome::Restart;
    };
    SnapshotReceiveOutcome::Complete {
        rank: transfer.rank,
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
) {
    if from == rt.self_id
        || !rt.net.has_route(from, ServiceLevel::Reliable)
        || !v2_snapshot_transfer_supported(rt, from)
    {
        rearm_history_election(rt);
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
    };
    metrics::record_catchup_request(CatchupMode::Strict);
    if let Err(error) = rt
        .net
        .send_unicast(from, &rt.topic, StrictBody::CatchupReq(req))
        .await
    {
        warn!(from, error = %error, "strict v2 snapshot chunk continuation send failed");
        rearm_history_election(rt);
    }
}

async fn apply_snapshot_transfer_response<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    resp: &StrictCatchupResp,
    remote_rank: HistoryRank,
    apply_started_at: Instant,
) {
    if resp.snapshot_transfer_rejected {
        rt.snapshot_receivers.lock().remove(&from);
        warn!(
            from,
            "strict v2 snapshot transfer was rejected by the source; rearming history election"
        );
        rearm_history_election(rt);
        return;
    }
    match receive_snapshot_chunk(rt, from, resp, remote_rank) {
        SnapshotReceiveOutcome::Continue {
            transfer_id,
            snapshot_version,
            next_cursor,
            terminal_decision_generation,
        } => {
            request_next_snapshot_chunk(
                rt,
                from,
                transfer_id,
                snapshot_version,
                next_cursor,
                terminal_decision_generation,
            )
            .await;
        }
        SnapshotReceiveOutcome::Complete {
            rank,
            snapshot_version,
            snapshot_msgpack,
            snapshot_sha256: expected_sha256,
        } => {
            if snapshot_sha256(&snapshot_msgpack) != expected_sha256 {
                warn!(
                    from,
                    "strict v2 snapshot transfer SHA-256 verification failed"
                );
                rearm_history_election(rt);
                return;
            }
            install_snapshot_candidate(
                rt,
                from,
                rank,
                snapshot_version,
                Bytes::from(snapshot_msgpack),
                apply_started_at,
            )
            .await;
        }
        SnapshotReceiveOutcome::Restart => {
            rt.snapshot_receivers.lock().remove(&from);
            warn!(
                from,
                "strict v2 snapshot transfer identity or chunk order mismatch"
            );
            rearm_history_election(rt);
        }
    }
}

/// Apply an inbound `StrictCatchupResp`. Installs the snapshot if
/// requested, then applies each op in order via `apply_committed`. If
/// `has_more`, continues pagination with the same validated peer.
pub(crate) async fn apply_response<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    resp: StrictCatchupResp,
) {
    let apply_started_at = std::time::Instant::now();
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
        return;
    };
    if remote_node != from {
        warn!(
            from,
            claimed = remote_node,
            "strict catchup response origin mismatch"
        );
        return;
    }
    // Install terminal fences only after authenticating the response origin,
    // but before considering ordinary history. A joining replica must not
    // revive a delayed v1 proposal while replaying validated catchup.
    for terminal in resp.terminal_states.clone() {
        if !rt.apply_catchup_terminal_state(terminal) {
            metrics::record_strict_fence_rejection();
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Strict,
                ReplicationPipelineStage::CatchupApply,
                apply_started_at.elapsed(),
            );
            return;
        }
    }
    // A v2 source supplies a persisted generation for its stable terminal
    // fence cut. Retain it only after every page in that cut has installed;
    // later steady-state catchup echoes it so a source restart or new fence
    // forces terminal pagination instead of trusting a cursor-only skip.
    let v2_terminal_catchup = rt.v2_terminal_catchup_supported_by(from);
    if v2_terminal_catchup && (!resp.terminal_sync_only || !resp.terminal_states_has_more) {
        rt.remember_terminal_decision_generation(from, resp.terminal_decision_generation);
    }
    if resp.terminal_sync_only {
        // A changed terminal-fence cut invalidates every partial image. The
        // next history request will start a new immutable transfer only after
        // all pages of the new cut are installed.
        rt.snapshot_receivers.lock().remove(&from);
        if from != rt.self_id
            && rt.net.has_route(from, ServiceLevel::Reliable)
            && rt.v2_terminal_catchup_supported_by(from)
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
            };
            metrics::record_catchup_request(CatchupMode::Strict);
            let _ = rt
                .net
                .send_unicast(from, &rt.topic, StrictBody::CatchupReq(req))
                .await;
        }
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::CatchupApply,
            apply_started_at.elapsed(),
        );
        return;
    }
    let remote_rank = HistoryRank {
        version: resp.history_version,
        freshness: resp.history_freshness,
        runtime_started_at: resp.runtime_started_at,
        node_id: remote_node,
    };
    if resp.snapshot_transfer_rejected || resp.snapshot_transfer_id != 0 {
        apply_snapshot_transfer_response(rt, from, &resp, remote_rank, apply_started_at).await;
        return;
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
        rearm_history_election(rt);
        return;
    }
    let local_rank = HistoryRank::local(rt);
    let can_bootstrap = rt.state.lock().can_bootstrap_catchup();

    let metadata_only_response =
        !resp.too_old_use_snapshot && resp.snapshot_msgpack.is_empty() && resp.ops.is_empty();
    if metadata_only_response {
        let local_metadata = rt.repo.history_metadata();
        let equal_version_metadata_diverged = !can_bootstrap
            && remote_rank.version == local_metadata.version
            && remote_rank.freshness != local_metadata.freshness;
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
            return;
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
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Strict,
                ReplicationPipelineStage::CatchupApply,
                apply_started_at.elapsed(),
            );
            return;
        }
    }

    if resp.too_old_use_snapshot {
        if resp.snapshot_version != remote_rank.version {
            warn!(
                from,
                snapshot_version = resp.snapshot_version,
                history_version = remote_rank.version,
                "strict catchup snapshot rank/version mismatch"
            );
            return;
        }
        install_snapshot_candidate(
            rt,
            from,
            remote_rank,
            resp.snapshot_version,
            resp.snapshot_msgpack,
            apply_started_at,
        )
        .await;
        return;
    }

    if can_bootstrap && rt.repo.current_version() > 0 {
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::CatchupApply,
            apply_started_at.elapsed(),
        );
        return;
    }

    if resp.ops.is_empty() {
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::CatchupApply,
            apply_started_at.elapsed(),
        );
        return;
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
                return;
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
                return;
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
                    return;
                }
            };
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Strict,
                ReplicationPipelineStage::MsgpackEncode,
                encode_started_at.elapsed(),
            );
            let op_id = (metadata.metadata.op_id_hi, metadata.metadata.op_id_lo);
            if let Some(proof) = metadata.terminal_proof {
                if !rt.apply_catchup_terminal_commit_proof(
                    op_id,
                    metadata.metadata.ts_final,
                    op_msgpack,
                    proof,
                ) {
                    metrics::record_strict_fence_rejection();
                    metrics::record_pipeline_stage(
                        ReplicationPipelineKind::Strict,
                        ReplicationPipelineStage::CatchupApply,
                        apply_started_at.elapsed(),
                    );
                    return;
                }
                continue;
            }
            if rt.has_v2_terminal_descriptor(op_id) {
                metrics::record_strict_fence_rejection();
                if rt.has_unresolved_v2_terminal_fence(op_id) {
                    rt.defer_descriptorless_v2_commit(op_id).await;
                }
                metrics::record_pipeline_stage(
                    ReplicationPipelineKind::Strict,
                    ReplicationPipelineStage::CatchupApply,
                    apply_started_at.elapsed(),
                );
                return;
            }
            let mut should_wake = false;
            {
                let mut state = rt.state.lock();
                if state.ordinary_commit_is_fenced(op_id) {
                    metrics::record_strict_fence_rejection();
                    continue;
                }
                if state.mark_committed(op_id, metadata.metadata.ts_final) {
                    state.buffer_commit(op_id, metadata.metadata.ts_final, op_msgpack);
                    should_wake = true;
                }
            }
            if should_wake {
                rt.deliver_signal.notify_one();
            }
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
            || !rt.v2_terminal_catchup_supported_by(from)
        {
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Strict,
                ReplicationPipelineStage::CatchupApply,
                apply_started_at.elapsed(),
            );
            return;
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
        };
        metrics::record_catchup_request(CatchupMode::Strict);
        let _ = rt
            .net
            .send_unicast(from, &rt.topic, StrictBody::CatchupReq(req))
            .await;
    }
    metrics::record_pipeline_stage(
        ReplicationPipelineKind::Strict,
        ReplicationPipelineStage::CatchupApply,
        apply_started_at.elapsed(),
    );
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
    use std::sync::Arc;

    use bytes::Bytes;
    use tokio_util::sync::CancellationToken;

    use super::{StrictReplicable, apply_response, respond_to_request};
    use crate::replications::{
        config::ReplicationConfig,
        proto::{
            CatchupOp, StrictBody, StrictCatchupReq, StrictCatchupResp, StrictDecisionAbort,
            StrictResolutionPrepare, StrictTerminalOutcome, StrictTerminalState,
        },
        strict::runtime::{StrictRuntime, make_op_id},
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
        net.set_strict_replication_protocol_version(2);
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
        }
    }

    fn begin_snapshot_fetch(rt: &StrictRuntime<CountingStrictRepo>, version: u64) {
        let remote_rank = super::HistoryRank {
            version,
            freshness: 0,
            runtime_started_at: 1,
            node_id: 1,
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

    #[tokio::test]
    async fn terminal_only_pages_preserve_intent_and_resume_history_after_byte_pagination() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_ops(1);
        let (source, source_net, _) = test_runtime(1, cfg);
        let first_id = make_op_id(1, 1, 1);
        let second_id = make_op_id(1, 1, 2);
        source.apply_catchup_terminal_state(terminal_abort(first_id));
        source.apply_catchup_terminal_state(terminal_abort(second_id));

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
    async fn oversized_terminal_state_is_declined_before_send() {
        let cfg = ReplicationConfig::default().with_strict_max_catchup_bytes(1);
        let (source, source_net, _) = test_runtime(1, cfg);
        source.apply_catchup_terminal_state(terminal_abort(make_op_id(1, 1, 99)));

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
        source.apply_catchup_terminal_state(terminal_abort(terminal_id));
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
                assert_eq!(history_request.snapshot_transfer_id, 0);
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

    #[tokio::test]
    async fn v2_snapshot_transfer_restarts_from_a_new_source_image_after_loss() {
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
        let mut request = catchup_request(sink_net.drain_captures().pop().unwrap());

        // Model a source restart after application state changed: its
        // ephemeral transfer cache is gone, so it must select a new image at
        // cursor zero rather than splice bytes into the old one.
        populate_repo(&source_repo, 97, 20_000);
        source.snapshot_transfers.lock().clear();
        let mut saw_replacement = false;
        loop {
            respond_to_request(&source, 2, request).await;
            let response = catchup_response(source_net.drain_captures().pop().unwrap());
            if !saw_replacement {
                assert_ne!(response.snapshot_transfer_id, first_id);
                assert_eq!(response.snapshot_chunk_cursor, 0);
                saw_replacement = true;
            }
            let has_more = response.snapshot_has_more;
            apply_response(&sink, 1, response).await;
            let captures = sink_net.drain_captures();
            if has_more {
                request = catchup_request(captures.into_iter().next().unwrap());
            } else {
                break;
            }
        }

        assert!(saw_replacement);
        assert_eq!(sink_repo.current_version(), 97);
        assert_eq!(sink_repo.log(), source_repo.log());
    }

    #[tokio::test]
    async fn responder_restart_reusing_a_transfer_id_rearms_snapshot_election() {
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

        // A real runtime restart starts the ephemeral id counter at one
        // again. Even if that collides with the prior id, the receiver must
        // refuse to append a changed image at cursor zero.
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
        assert_eq!(
            restarted_response.snapshot_transfer_id,
            first_response.snapshot_transfer_id
        );
        assert_eq!(restarted_response.snapshot_chunk_cursor, 0);
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
            request_force_snapshot: true,
            request_history_probe_only: false,
            terminal_decision_generation: 0,
            snapshot_transfer_id: 11,
            snapshot_chunk_cursor: 0,
            snapshot_next_cursor: 6,
            snapshot_total_bytes: 8,
            snapshot_sha256: Bytes::from(vec![0x11; 32]),
            snapshot_has_more: true,
            snapshot_transfer_rejected: false,
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
            request_force_snapshot: true,
            request_history_probe_only: false,
            terminal_decision_generation: 0,
            snapshot_transfer_id: 22,
            snapshot_chunk_cursor: 0,
            snapshot_next_cursor: 5,
            snapshot_total_bytes: 8,
            snapshot_sha256: Bytes::from(vec![0x22; 32]),
            snapshot_has_more: true,
            snapshot_transfer_rejected: false,
        };
        apply_response(&sink, 3, second_response).await;

        let receivers = sink.snapshot_receivers.lock();
        assert_eq!(receivers.len(), 1);
        assert_eq!(
            receivers.get(&1).unwrap().snapshot_msgpack.as_slice(),
            b"abcdef"
        );
        assert!(!receivers.contains_key(&3));
        drop(receivers);
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
        assert!(repo.log().is_empty());
    }

    #[tokio::test]
    async fn legacy_requester_with_terminal_fence_is_declined() {
        let (source, source_net, _) = test_runtime(1, ReplicationConfig::default());
        source_net.set_peer_strict_replication_protocol_version(2, 0);
        let terminal_id = make_op_id(1, 1, 5);
        source.apply_catchup_terminal_state(terminal_abort(terminal_id));

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
            },
        )
        .await;

        assert!(
            source_net.drain_captures().is_empty(),
            "a requester without v2 terminal generations must not receive history that can outlive a fence"
        );
    }
}
