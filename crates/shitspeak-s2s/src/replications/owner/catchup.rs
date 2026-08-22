//! Owner-mode catchup: per-origin chunked snapshot + log replay.
//!
//! Same chunking model as strict catchup: stateless server-side, client
//! re-issues with `since_version = repo.known_versions()[origin].1`.

use bytes::Bytes;
use rand::seq::SliceRandom;
use tracing::{debug, warn};

use super::super::metrics::{self, CatchupMode, ReplicationPipelineKind, ReplicationPipelineStage};
use super::super::proto::{CatchupOp, OwnerBody, OwnerCatchupReq, OwnerCatchupResp, OwnerOp};
use super::runtime::OwnerRuntime;
use super::{LogSlice, OwnerReplicable, OwnerSnapshotInstallOutcome};
use shitspeak_core::NodeIdentifier;

fn catchup_response_payload_len<R: OwnerReplicable>(
    rt: &OwnerRuntime<R>,
    response: &OwnerCatchupResp,
) -> Option<usize> {
    rt.net
        .encoded_owner_payload_len(&rt.topic, &OwnerBody::CatchupResp(response.clone()))
        .map_err(|error| {
            warn!(error=%error, "owner catchup response sizing failed");
        })
        .ok()
}

fn catchup_response_fits<R: OwnerReplicable>(
    rt: &OwnerRuntime<R>,
    response: &OwnerCatchupResp,
) -> bool {
    catchup_response_payload_len(rt, response)
        .is_some_and(|len| len <= rt.net.max_replication_payload_bytes())
}

fn snapshot_response(
    origin: NodeIdentifier,
    origin_epoch: u64,
    snapshot_version: u64,
    snapshot_msgpack: Bytes,
    request_since: u64,
) -> OwnerCatchupResp {
    OwnerCatchupResp {
        origin_node: origin as u32,
        origin_epoch,
        snapshot_version,
        snapshot_msgpack,
        ops: Vec::new(),
        has_more: false,
        next_chunk_token: request_since,
        too_old_use_snapshot: true,
    }
}

pub(crate) async fn respond_to_request<R: OwnerReplicable>(
    rt: &OwnerRuntime<R>,
    from: NodeIdentifier,
    req: OwnerCatchupReq,
) {
    let Some(origin) = node_from_u32(req.origin_node) else {
        warn!("owner catchup req has invalid origin_node");
        return;
    };
    if node_from_u32(req.src_node) != Some(from) {
        warn!(from=%from, src_node=req.src_node, "owner catchup req source does not match sender");
        return;
    }
    let Some(_permit) = rt
        .cfg
        .try_begin_catchup(CatchupMode::Owner, &rt.topic, from)
    else {
        return;
    };
    let build_started_at = std::time::Instant::now();

    let authoritative_epoch = rt.authoritative_epoch(origin);
    let repo_known = rt.repo.known_versions();
    let materialized = if origin == rt.self_id {
        Some((rt.self_epoch, rt.repo.local_version()))
    } else {
        repo_known.get(&origin).copied()
    };
    let (origin_epoch, origin_version) = match materialized
        .filter(|(epoch, _)| Some(*epoch) == authoritative_epoch && req.known_epoch <= *epoch)
    {
        Some(p) => p,
        None => {
            // Relays may only advertise fully materialized state at the
            // LSDB-current epoch. An empty response lets the requester fall
            // back to the origin without exposing pending/runtime progress.
            debug!(
                origin=%origin,
                from=%from,
                req_epoch=req.known_epoch,
                authoritative_epoch=?authoritative_epoch,
                materialized=?materialized,
                "owner catchup response: no materialized state at current epoch; responding empty"
            );
            let response = OwnerCatchupResp {
                origin_node: origin as u32,
                origin_epoch: authoritative_epoch.unwrap_or(0),
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: vec![],
                has_more: false,
                next_chunk_token: 0,
                too_old_use_snapshot: false,
            };
            if catchup_response_fits(rt, &response) {
                let _ = rt
                    .net
                    .send_unicast(from, &rt.topic, OwnerBody::CatchupResp(response))
                    .await;
            } else {
                warn!(
                    max_bytes = rt.net.max_replication_payload_bytes(),
                    "owner catchup response envelope exceeds replication payload budget"
                );
            }
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Owner,
                ReplicationPipelineStage::CatchupBuild,
                build_started_at.elapsed(),
            );
            return;
        }
    };

    let mut snapshot_version = 0u64;
    let mut snapshot_msgpack: Bytes = Bytes::new();
    let mut too_old_use_snapshot = false;

    let request_since = req.since_version.max(req.chunk_token);
    let load_snapshot = |minimum_version| {
        rt.repo
            .snapshot_for_origin(origin)
            .filter(|(epoch, version, _)| *epoch == origin_epoch && *version >= minimum_version)
    };

    // Cold recovery prefers one atomic snapshot, but only if its fully
    // wrapped protobuf response fits the frame budget. Otherwise use the
    // existing contiguous, paged log path instead of constructing a response
    // that the transport must reject.
    let mut effective_ops: Vec<(u64, R::Op)> = Vec::new();
    let mut selected_snapshot = false;
    if request_since == 0 && origin_version > 0 {
        if let Some((_, version, snapshot)) = load_snapshot(origin_version) {
            let candidate = snapshot_response(
                origin,
                origin_epoch,
                version,
                snapshot.clone(),
                request_since,
            );
            if catchup_response_fits(rt, &candidate) {
                too_old_use_snapshot = true;
                snapshot_version = version;
                snapshot_msgpack = snapshot;
                selected_snapshot = true;
            } else {
                warn!(
                    origin=%origin,
                    epoch=origin_epoch,
                    snapshot_version=version,
                    snapshot_bytes=snapshot.len(),
                    max_bytes=rt.net.max_replication_payload_bytes(),
                    "owner cold snapshot exceeds replication payload budget; falling back to paged log"
                );
            }
        }
    }

    if !selected_snapshot {
        match rt.repo.log_for_origin(origin, request_since) {
            LogSlice::Available(ops) => {
                match bounded_contiguous_log(ops, request_since, origin_version) {
                    Some(ops) => effective_ops = ops,
                    None => too_old_use_snapshot = true,
                }
            }
            LogSlice::TooOld => too_old_use_snapshot = true,
        }
    }
    if too_old_use_snapshot && !selected_snapshot {
        if let Some((_, version, snapshot)) = load_snapshot(request_since) {
            let candidate = snapshot_response(
                origin,
                origin_epoch,
                version,
                snapshot.clone(),
                request_since,
            );
            if catchup_response_fits(rt, &candidate) {
                snapshot_version = version;
                snapshot_msgpack = snapshot;
                selected_snapshot = true;
            } else {
                warn!(
                    origin=%origin,
                    epoch=origin_epoch,
                    snapshot_version=version,
                    snapshot_bytes=snapshot.len(),
                    max_bytes=rt.net.max_replication_payload_bytes(),
                    "owner snapshot exceeds replication payload budget"
                );
            }
        }
    }

    let total = effective_ops.len();
    let max_ops = total.min(rt.cfg.owner_max_catchup_ops().max(1));
    let mut catchup_ops: Vec<CatchupOp> = Vec::with_capacity(max_ops);
    let mut encode_failed = false;
    let mut payload_limited = false;
    for (v, op) in effective_ops.iter().take(max_ops) {
        let encode_started_at = std::time::Instant::now();
        match rmp_serde::to_vec(op) {
            Ok(b) => {
                let op = CatchupOp {
                    version: *v,
                    op_msgpack: Bytes::from(b),
                    strict_op_id_hi: 0,
                    strict_op_id_lo: 0,
                    strict_ts_final: 0,
                    strict_terminal_ballot: 0,
                    strict_terminal_resolver_node: 0,
                    strict_terminal_resolver_boot_epoch: 0,
                    strict_terminal_frozen_targets: Vec::new(),
                };
                let mut candidate_ops = catchup_ops.clone();
                candidate_ops.push(op.clone());
                let candidate = OwnerCatchupResp {
                    origin_node: origin as u32,
                    origin_epoch,
                    snapshot_version: 0,
                    snapshot_msgpack: Bytes::new(),
                    has_more: total > candidate_ops.len(),
                    next_chunk_token: *v,
                    ops: candidate_ops,
                    too_old_use_snapshot: false,
                };
                if catchup_response_fits(rt, &candidate) {
                    catchup_ops.push(op);
                } else {
                    payload_limited = true;
                }
            }
            Err(e) => {
                warn!(error=%e, "owner catchup op encode failed; declining response tail");
                encode_failed = true;
            }
        }
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Owner,
            ReplicationPipelineStage::MsgpackEncode,
            encode_started_at.elapsed(),
        );
        if encode_failed || payload_limited {
            break;
        }
    }
    if encode_failed {
        catchup_ops.clear();
        too_old_use_snapshot = true;
    }
    if (encode_failed || payload_limited) && catchup_ops.is_empty() {
        if !selected_snapshot {
            if let Some((_, version, snapshot)) = load_snapshot(request_since) {
                let candidate = snapshot_response(
                    origin,
                    origin_epoch,
                    version,
                    snapshot.clone(),
                    request_since,
                );
                if catchup_response_fits(rt, &candidate) {
                    snapshot_version = version;
                    snapshot_msgpack = snapshot;
                    selected_snapshot = true;
                }
            }
        }
        if !selected_snapshot {
            // A normal empty response from the authoritative origin is proof
            // of version zero. Never emit that proof when the origin is
            // nonempty but neither its first op nor its snapshot fits.
            too_old_use_snapshot = true;
        }
    }
    let has_more = !encode_failed
        && !selected_snapshot
        && !catchup_ops.is_empty()
        && total > catchup_ops.len();
    let next_chunk_token = catchup_ops
        .last()
        .map(|c| c.version)
        .unwrap_or(request_since);
    let response_bytes = snapshot_msgpack.len()
        + catchup_ops
            .iter()
            .map(|op| op.op_msgpack.len())
            .sum::<usize>();
    metrics::record_catchup_response(CatchupMode::Owner, catchup_ops.len(), response_bytes);
    metrics::record_pipeline_stage(
        ReplicationPipelineKind::Owner,
        ReplicationPipelineStage::CatchupBuild,
        build_started_at.elapsed(),
    );
    debug!(
        origin=%origin,
        from=%from,
        req_since=request_since,
        origin_epoch=origin_epoch,
        origin_version=origin_version,
        snapshot=selected_snapshot,
        snapshot_version=snapshot_version,
        ops=catchup_ops.len(),
        total_available=total,
        has_more=has_more,
        too_old=too_old_use_snapshot,
        payload_limited=payload_limited,
        encode_failed=encode_failed,
        "owner catchup response built"
    );

    let resp = OwnerCatchupResp {
        origin_node: origin as u32,
        origin_epoch,
        snapshot_version,
        snapshot_msgpack,
        ops: catchup_ops,
        has_more,
        next_chunk_token,
        too_old_use_snapshot,
    };
    let Some(encoded_len) = catchup_response_payload_len(rt, &resp) else {
        return;
    };
    if encoded_len > rt.net.max_replication_payload_bytes() {
        warn!(
            origin=%origin,
            epoch=origin_epoch,
            encoded_bytes=encoded_len,
            max_bytes=rt.net.max_replication_payload_bytes(),
            "owner catchup response exceeds replication payload budget; suppressing send"
        );
        return;
    }
    let _ = rt
        .net
        .send_bulk_unicast(
            from,
            &rt.topic,
            OwnerBody::CatchupResp(resp),
            rt.cfg.bulk_retry_delay(),
        )
        .await;
}

pub(crate) async fn apply_response<R: OwnerReplicable>(
    rt: &OwnerRuntime<R>,
    from: NodeIdentifier,
    resp: OwnerCatchupResp,
) {
    let apply_started_at = std::time::Instant::now();
    let Some(origin) = node_from_u32(resp.origin_node) else {
        warn!("owner catchup resp has invalid origin_node");
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Owner,
            ReplicationPipelineStage::CatchupApply,
            apply_started_at.elapsed(),
        );
        return;
    };
    let resp_epoch = resp.origin_epoch;
    if origin == rt.self_id || !rt.epoch_is_current(origin, resp_epoch) {
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Owner,
            ReplicationPipelineStage::CatchupApply,
            apply_started_at.elapsed(),
        );
        return;
    }

    let _origin_guard = rt.lock_origin(origin).await;
    if !rt.epoch_is_current(origin, resp_epoch) {
        return;
    }
    let previous_chunk_token = rt.complete_catchup_attempt(origin).unwrap_or(0);

    let previous = rt.state.lock().known.get(&origin).copied();
    if previous.is_some_and(|(known_epoch, _)| known_epoch > resp_epoch) {
        return;
    }

    let has_snapshot = !resp.snapshot_msgpack.is_empty();
    let has_materialized_payload = has_snapshot || !resp.ops.is_empty();
    if previous.is_none() && from != origin && !has_materialized_payload {
        // An empty relay response is not proof that the current owner is at
        // version zero. Ask the origin before establishing the incarnation.
        debug!(
            origin=%origin,
            from=%from,
            epoch=resp_epoch,
            outcome="rearm_empty_relay_no_known",
            "owner catchup response: empty relay before incarnation; asking origin"
        );
        rt.rearm_catchup_retry(origin, resp_epoch);
        if rt.net.alive_members().contains(&origin) {
            let _ = rt
                .send_catchup_req_to(origin, origin, resp_epoch, 0, 0, "apply_empty_relay_ask_origin")
                .await;
        }
        return;
    }

    // `TooOld` without bytes is an explicit snapshot-unavailable response.
    // Applying its tail would create an unproven prefix, so retry directly.
    if resp.too_old_use_snapshot && resp.snapshot_msgpack.is_empty() {
        debug!(
            origin=%origin,
            from=%from,
            epoch=resp_epoch,
            known=?previous,
            outcome="rearm_too_old_empty",
            "owner catchup response: too_old with no snapshot bytes; retrying"
        );
        rt.rearm_catchup_retry(origin, resp_epoch);
        if from != origin && rt.net.alive_members().contains(&origin) {
            let since = if rt.origin_is_inactive(origin) {
                0
            } else {
                rt.state
                    .lock()
                    .known
                    .get(&origin)
                    .map(|(_, version)| *version)
                    .unwrap_or(0)
            };
            let _ = rt
                .send_catchup_req_to(origin, origin, resp_epoch, since, 0, "apply_too_old_empty_ask_origin")
                .await;
        }
        return;
    }

    if !has_snapshot && resp.ops.is_empty() && from == origin {
        // An empty response at the version we requested is also the normal
        // authoritative confirmation that an active nonempty origin is
        // already caught up. It neither proves version zero nor needs the
        // bounded retry used while establishing a fresh incarnation.
        let same_epoch_nonempty = previous.is_some_and(|(known_epoch, known_version)| {
            known_epoch == resp_epoch && known_version > 0
        });
        if same_epoch_nonempty && !rt.origin_is_inactive(origin) {
            debug!(
                origin=%origin,
                from=%from,
                epoch=resp_epoch,
                outcome="converged",
                "owner catchup response: authoritative empty confirms an active origin is caught up"
            );
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Owner,
                ReplicationPipelineStage::CatchupApply,
                apply_started_at.elapsed(),
            );
            return;
        }
        if same_epoch_nonempty {
            // Offline handling deliberately retains a same-epoch high-water
            // floor. A delayed empty response from that incarnation cannot
            // erase the floor or make old operations admissible again.
            debug!(
                origin=%origin,
                from=%from,
                epoch=resp_epoch,
                outcome="rearm_same_epoch_inactive",
                "owner catchup response: empty from active epoch but origin inactive; retaining floor"
            );
            rt.rearm_catchup_retry(origin, resp_epoch);
            return;
        }
        // Only the origin itself can prove that its current incarnation is
        // empty. This is the one valid response that establishes version 0.
        if rt.origin_is_inactive(origin)
            || previous
                .map(|(known_epoch, _)| known_epoch < resp_epoch)
                .unwrap_or(true)
        {
            rt.repo.reset_origin(origin, resp_epoch).await;
            if !rt.epoch_is_current(origin, resp_epoch) {
                rt.restore_current_epoch_after_race_locked(origin).await;
                return;
            }
            let mut state = rt.state.lock();
            state.wipe_origin(origin);
            state.known.insert(origin, (resp_epoch, 0));
            state
                .catchup_in_flight
                .insert(origin, std::time::Instant::now());
            drop(state);
            rt.mark_origin_active(origin);
        }
        let confirmations = rt.record_empty_origin_confirmation(origin, resp_epoch);
        debug!(
            origin=%origin,
            from=%from,
            epoch=resp_epoch,
            confirmations,
            outcome="establish_v0",
            "owner catchup response: authoritative origin proves version zero"
        );
        if confirmations < 2 {
            rt.schedule_origin_stabilization(origin, resp_epoch);
            rt.rearm_catchup_retry(origin, resp_epoch);
            return;
        }
    }

    if has_snapshot {
        if previous.is_some_and(|(known_epoch, known_version)| {
            known_epoch == resp_epoch && resp.snapshot_version < known_version
        }) {
            debug!(
                origin=%origin,
                from=%from,
                epoch=resp_epoch,
                snapshot_version=resp.snapshot_version,
                known=?previous,
                outcome="rearm_snapshot_stale",
                "owner catchup response: snapshot older than known state; retrying"
            );
            rt.rearm_catchup_retry(origin, resp_epoch);
            return;
        }
        let snapshot_started_at = std::time::Instant::now();
        let install = rt
            .repo
            .install_snapshot_for_origin(
                origin,
                resp_epoch,
                resp.snapshot_version,
                resp.snapshot_msgpack,
            )
            .await;
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Owner,
            ReplicationPipelineStage::SnapshotInstall,
            snapshot_started_at.elapsed(),
        );
        match install {
            Ok(OwnerSnapshotInstallOutcome::Installed) => {
                if !rt.epoch_is_current(origin, resp_epoch) {
                    rt.restore_current_epoch_after_race_locked(origin).await;
                    return;
                }
                let mut state = rt.state.lock();
                state
                    .known
                    .insert(origin, (resp_epoch, resp.snapshot_version));
                if previous.is_some_and(|(known_epoch, _)| known_epoch == resp_epoch) {
                    state.discard_pending_through(origin, resp.snapshot_version);
                } else {
                    state.pending_buffers.remove(&origin);
                }
                drop(state);
                rt.mark_origin_active(origin);
                if resp.snapshot_version > 0 {
                    rt.clear_empty_origin_confirmation(origin);
                    debug!(
                        origin=%origin,
                        from=%from,
                        epoch=resp_epoch,
                        snapshot_version=resp.snapshot_version,
                        outcome="snapshot_installed",
                        "owner catchup response: snapshot installed"
                    );
                } else if from == origin
                    && rt.record_empty_origin_confirmation(origin, resp_epoch) < 2
                {
                    debug!(
                        origin=%origin,
                        from=%from,
                        epoch=resp_epoch,
                        snapshot_version=0,
                        outcome="rearm_snapshot_empty_confirm",
                        "owner catchup response: snapshot installed but origin at version zero; confirming"
                    );
                    rt.schedule_origin_stabilization(origin, resp_epoch);
                    rt.rearm_catchup_retry(origin, resp_epoch);
                    return;
                }
            }
            Ok(OwnerSnapshotInstallOutcome::Deferred) => {
                debug!(
                    origin=%origin,
                    from=%from,
                    epoch=resp_epoch,
                    snapshot_version=resp.snapshot_version,
                    outcome="rearm_snapshot_deferred",
                    "owner catchup response: snapshot install deferred; retrying"
                );
                rt.rearm_catchup_retry(origin, resp_epoch);
                return;
            }
            Err(error) => {
                warn!(origin=%origin, epoch=resp_epoch, error=%error, outcome="rearm_snapshot_error", "owner snapshot install failed");
                rt.rearm_catchup_retry(origin, resp_epoch);
                return;
            }
        }
    }

    if rt.origin_is_inactive(origin) {
        // A removed transient shard may only become visible again through an
        // atomic snapshot (or a direct proof that the owner is version zero).
        debug!(
            origin=%origin,
            from=%from,
            epoch=resp_epoch,
            outcome="rearm_inactive_ask_origin",
            "owner catchup response: origin inactive; needs snapshot or v0 proof"
        );
        rt.rearm_catchup_retry(origin, resp_epoch);
        if from != origin && rt.net.alive_members().contains(&origin) {
            let _ = rt
                .send_catchup_req_to(origin, origin, resp_epoch, 0, 0, "apply_inactive_ask_origin")
                .await;
        }
        return;
    }

    // Keep the request timestamp after a response arrives. It is the retry
    // gate, not just an in-flight marker; clearing it here lets fast empty
    // responses bypass `owner_catchup_timeout`.
    for cop in resp.ops {
        rt.process_remote_op_locked(
            origin,
            OwnerOp {
                origin_node: origin as u32,
                origin_epoch: resp_epoch,
                origin_version: cop.version,
                op_msgpack: cop.op_msgpack,
            },
        )
        .await;
    }
    rt.drain_pending_after_snapshot_locked(origin, resp_epoch)
        .await;

    if resp.has_more {
        if resp.next_chunk_token <= previous_chunk_token {
            debug!(
                origin=%origin,
                from=%from,
                epoch=resp_epoch,
                chunk_token=resp.next_chunk_token,
                previous_chunk_token=previous_chunk_token,
                outcome="rearm_chunk_token_regressed",
                "owner catchup response: continuation token did not advance; retrying"
            );
            rt.rearm_catchup_retry(origin, resp_epoch);
            return;
        }
        debug!(
            origin=%origin,
            from=%from,
            epoch=resp_epoch,
            chunk_token=resp.next_chunk_token,
            outcome="continuation",
            "owner catchup response: more chunks available; continuing"
        );
        let alive = rt.net.alive_members();
        let mut peers: Vec<NodeIdentifier> = alive
            .into_iter()
            .filter(|n| *n != rt.self_id && *n != origin)
            .collect();
        let dst = if from == origin {
            origin
        } else if !peers.is_empty() {
            {
                let mut rng = rand::rng();
                peers.shuffle(&mut rng);
            }
            peers[0]
        } else {
            origin
        };
        let since = {
            let s = rt.state.lock();
            s.known.get(&origin).map(|(_, v)| *v).unwrap_or(0)
        };
        // Re-arm the in-flight gate so we don't double-trigger on
        // out-of-order ops arriving meanwhile.
        {
            let mut s = rt.state.lock();
            s.arm_catchup(
                origin,
                std::time::Instant::now(),
                rt.cfg.owner_catchup_timeout(),
            );
        }
        rt.send_catchup_continuation_with_fallback(
            dst,
            origin,
            resp_epoch,
            since,
            resp.next_chunk_token,
        )
        .await;
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Owner,
            ReplicationPipelineStage::CatchupApply,
            apply_started_at.elapsed(),
        );
        return;
    }

    let version_after = {
        let s = rt.state.lock();
        s.known.get(&origin).map(|(_, v)| *v).unwrap_or(0)
    };
    if from != origin && origin != rt.self_id && rt.net.alive_members().contains(&origin) {
        let known_epoch = rt.net.member_boot_epoch(origin).unwrap_or(resp_epoch);
        let _ = rt
            .send_catchup_req_to(origin, origin, known_epoch, version_after, 0, "apply_relay_followup")
            .await;
    }
    debug!(
        origin=%origin,
        from=%from,
        epoch=resp_epoch,
        version_after=version_after,
        served_by_relay=(from != origin),
        outcome="converged_apply",
        "owner catchup response: ops applied; caught up"
    );
    metrics::record_pipeline_stage(
        ReplicationPipelineKind::Owner,
        ReplicationPipelineStage::CatchupApply,
        apply_started_at.elapsed(),
    );
}

#[inline]
fn node_from_u32(v: u32) -> Option<NodeIdentifier> {
    if v <= u16::MAX as u32 {
        Some(v as NodeIdentifier)
    } else {
        None
    }
}

fn bounded_contiguous_log<Op>(
    mut ops: Vec<(u64, Op)>,
    since: u64,
    current_version: u64,
) -> Option<Vec<(u64, Op)>> {
    // The repository view may advance between `known_versions` and the log
    // capture. Bound the response to the version captured for this envelope.
    ops.retain(|(version, _)| *version <= current_version);
    if current_version <= since {
        return ops.is_empty().then_some(ops);
    }
    let mut expected = since.saturating_add(1);
    for (version, _) in &ops {
        if *version != expected {
            return None;
        }
        expected = expected.saturating_add(1);
    }
    if expected == current_version.saturating_add(1) {
        Some(ops)
    } else {
        None
    }
}
