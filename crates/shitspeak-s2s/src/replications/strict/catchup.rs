//! Strict-mode catchup: chunked snapshot + log replay over `OverlayData`.
//!
//! The wire chunking strategy is intentionally stateless on the server
//! side: each request carries `since_version` plus a continuation
//! `chunk_token`; the server returns up to
//! [`crate::replications::ReplicationConfig::strict_max_catchup_ops`]
//! ops with `has_more` set when more are available. The client iterates by
//! re-issuing requests with the returned `next_chunk_token` until
//! `has_more = false`.

use bytes::Bytes;
use rand::seq::SliceRandom;
use tracing::warn;

use super::super::metrics::{self, CatchupMode, ReplicationPipelineKind, ReplicationPipelineStage};
use super::super::proto::{CatchupOp, StrictBody, StrictCatchupReq, StrictCatchupResp};
use super::runtime::{
    HISTORY_ELECTION_SNAPSHOT_TOKEN, HistoryProbeResponseOutcome, HistoryRank,
    HistorySnapshotResponseOutcome, StrictRuntime,
};
use super::{LogSlice, StrictLogMetadata, StrictReplicable};
use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::ServiceLevel;

/// Build and send a `StrictCatchupResp` answering `req`.
pub(crate) async fn respond_to_request<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    req: StrictCatchupReq,
) {
    let Some(_permit) = rt
        .cfg
        .try_begin_catchup(CatchupMode::Strict, &rt.topic, from)
    else {
        return;
    };
    let build_started_at = std::time::Instant::now();

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
        };
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::CatchupBuild,
            build_started_at.elapsed(),
        );
        metrics::record_catchup_response(CatchupMode::Strict, 0, 0);
        let _ = rt
            .net
            .send_bulk_unicast(
                from,
                &rt.topic,
                StrictBody::CatchupResp(resp),
                rt.cfg.bulk_retry_delay(),
            )
            .await;
        return;
    }

    let mut snapshot_version = 0u64;
    let mut snapshot_msgpack: Bytes = Bytes::new();
    let mut too_old_use_snapshot = false;

    let force_snapshot = req.force_snapshot || req.chunk_token == HISTORY_ELECTION_SNAPSHOT_TOKEN;
    let request_since = req.chunk_token.max(req.since_version);
    let (effective_ops, _effective_since) = if force_snapshot {
        too_old_use_snapshot = true;
        let (sv, snap) = rt.repo.snapshot();
        snapshot_version = sv;
        snapshot_msgpack = snap;
        (Vec::new(), sv)
    } else {
        match rt.repo.log_since(request_since) {
            LogSlice::Available(ops) => (ops, request_since),
            LogSlice::TooOld => {
                too_old_use_snapshot = true;
                let (sv, snap) = rt.repo.snapshot();
                snapshot_version = sv;
                snapshot_msgpack = snap;
                match rt.repo.log_since(sv) {
                    LogSlice::Available(ops) => (ops, sv),
                    LogSlice::TooOld => (Vec::new(), sv),
                }
            }
        }
    };

    let total = effective_ops.len();
    let take = total.min(rt.cfg.strict_max_catchup_ops().max(1));
    let mut catchup_ops: Vec<CatchupOp> = Vec::with_capacity(take);
    for (v, entry) in effective_ops.iter().take(take) {
        let encode_started_at = std::time::Instant::now();
        match rmp_serde::to_vec(&entry.op) {
            Ok(b) => catchup_ops.push(CatchupOp {
                version: *v,
                op_msgpack: Bytes::from(b),
                strict_op_id_hi: entry.metadata.map(|m| m.op_id_hi).unwrap_or(0),
                strict_op_id_lo: entry.metadata.map(|m| m.op_id_lo).unwrap_or(0),
                strict_ts_final: entry.metadata.map(|m| m.ts_final).unwrap_or(0),
            }),
            Err(e) => {
                warn!(error=%e, "catchup op msgpack encode failed; skipping");
            }
        }
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::MsgpackEncode,
            encode_started_at.elapsed(),
        );
    }
    let has_more = total > take;
    let next_chunk_token = catchup_ops
        .last()
        .map(|c| c.version)
        .unwrap_or(request_since);
    let response_bytes = snapshot_msgpack.len()
        + catchup_ops
            .iter()
            .map(|op| op.op_msgpack.len())
            .sum::<usize>();
    metrics::record_catchup_response(CatchupMode::Strict, catchup_ops.len(), response_bytes);
    metrics::record_pipeline_stage(
        ReplicationPipelineKind::Strict,
        ReplicationPipelineStage::CatchupBuild,
        build_started_at.elapsed(),
    );

    let rank = HistoryRank::local(rt);
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
    };
    let _ = rt
        .net
        .send_bulk_unicast(
            from,
            &rt.topic,
            StrictBody::CatchupResp(resp),
            rt.cfg.bulk_retry_delay(),
        )
        .await;
}

/// Apply an inbound `StrictCatchupResp`. Installs the snapshot if
/// requested, then applies each op in order via `apply_committed`. If
/// `has_more`, fires off another request to a random alive peer.
pub(crate) async fn apply_response<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    _from: NodeIdentifier,
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
    let remote_rank = HistoryRank {
        version: resp.history_version,
        freshness: resp.history_freshness,
        runtime_started_at: resp.runtime_started_at,
        node_id: remote_node,
    };
    let local_rank = HistoryRank::local(rt);
    let can_bootstrap = rt.state.lock().can_bootstrap_catchup();

    let metadata_only_response =
        !resp.too_old_use_snapshot && resp.snapshot_msgpack.is_empty() && resp.ops.is_empty();
    if metadata_only_response {
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
        let outcome = if can_bootstrap {
            rt.state.lock().record_history_snapshot_response(
                remote_node,
                remote_rank,
                local_rank,
                resp.snapshot_version,
                resp.snapshot_msgpack,
            )
        } else {
            HistorySnapshotResponseOutcome::Ignored
        };
        match outcome {
            HistorySnapshotResponseOutcome::Install(winner) => {
                let snapshot_started_at = std::time::Instant::now();
                rt.repo
                    .install_snapshot(winner.snapshot_version, winner.snapshot_msgpack)
                    .await;
                metrics::record_pipeline_stage(
                    ReplicationPipelineKind::Strict,
                    ReplicationPipelineStage::SnapshotInstall,
                    snapshot_started_at.elapsed(),
                );
                rt.state.lock().finish_history_election();
            }
            HistorySnapshotResponseOutcome::Retry | HistorySnapshotResponseOutcome::Ignored => {}
        }
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::CatchupApply,
            apply_started_at.elapsed(),
        );
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
        if let Some(metadata) = strict_metadata(&cop) {
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
            let op_id = (metadata.op_id_hi, metadata.op_id_lo);
            let mut should_wake = false;
            {
                let mut state = rt.state.lock();
                if state.mark_committed(op_id, metadata.ts_final) {
                    state.buffer_commit(op_id, metadata.ts_final, op_msgpack);
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
        let alive = rt.net.alive_members();
        let mut peers: Vec<NodeIdentifier> = alive
            .into_iter()
            .filter(|n| *n != rt.self_id && rt.net.has_route(*n, ServiceLevel::Reliable))
            .collect();
        if peers.is_empty() {
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Strict,
                ReplicationPipelineStage::CatchupApply,
                apply_started_at.elapsed(),
            );
            return;
        }
        let dst = {
            let mut rng = rand::rng();
            peers.shuffle(&mut rng);
            peers[0]
        };
        let req = StrictCatchupReq {
            src_node: rt.self_id as u32,
            since_version: resp.next_chunk_token,
            chunk_token: resp.next_chunk_token,
            force_snapshot: false,
            history_probe_only: false,
        };
        metrics::record_catchup_request(CatchupMode::Strict);
        let _ = rt
            .net
            .send_unicast(dst, &rt.topic, StrictBody::CatchupReq(req))
            .await;
    }
    metrics::record_pipeline_stage(
        ReplicationPipelineKind::Strict,
        ReplicationPipelineStage::CatchupApply,
        apply_started_at.elapsed(),
    );
}

fn strict_metadata(op: &CatchupOp) -> Option<StrictLogMetadata> {
    if op.strict_op_id_hi == 0 && op.strict_op_id_lo == 0 && op.strict_ts_final == 0 {
        return None;
    }
    Some(StrictLogMetadata {
        op_id_hi: op.strict_op_id_hi,
        op_id_lo: op.strict_op_id_lo,
        ts_final: op.strict_ts_final,
    })
}
