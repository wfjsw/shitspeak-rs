//! Strict-mode catchup: chunked snapshot + log replay over `OverlayData`.
//!
//! The wire chunking strategy is intentionally stateless on the server
//! side: each request carries `since_version`; the server returns up to
//! [`crate::s2s::replications::ReplicationConfig::strict_max_catchup_ops`]
//! ops with `has_more` set when more are available. The client iterates by
//! re-issuing requests with `since_version = repo.current_version()` until
//! `has_more = false`.

use bytes::Bytes;
use rand::seq::SliceRandom;
use tracing::warn;

use super::super::proto::{CatchupOp, StrictBody, StrictCatchupReq, StrictCatchupResp};
use super::runtime::{
    HISTORY_ELECTION_SNAPSHOT_TOKEN, HistoryElectionCandidate, HistoryRank, StrictRuntime,
};
use super::{LogSlice, StrictReplicable};
use crate::types::NodeIdentifier;

/// Build and send a `StrictCatchupResp` answering `req`.
pub(crate) async fn respond_to_request<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    req: StrictCatchupReq,
) {
    let mut snapshot_version = 0u64;
    let mut snapshot_msgpack: Bytes = Bytes::new();
    let mut too_old_use_snapshot = false;

    let force_snapshot = req.force_snapshot || req.chunk_token == HISTORY_ELECTION_SNAPSHOT_TOKEN;
    let (effective_ops, _effective_since) = if force_snapshot {
        too_old_use_snapshot = true;
        let (sv, snap) = rt.repo.snapshot();
        snapshot_version = sv;
        snapshot_msgpack = snap;
        (Vec::new(), sv)
    } else {
        match rt.repo.log_since(req.since_version) {
            LogSlice::Available(ops) => (ops, req.since_version),
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
    let take = total.min(rt.cfg.strict_max_catchup_ops());
    let mut catchup_ops: Vec<CatchupOp> = Vec::with_capacity(take);
    for (v, op) in effective_ops.iter().take(take) {
        match rmp_serde::to_vec(op) {
            Ok(b) => catchup_ops.push(CatchupOp {
                version: *v,
                op_msgpack: Bytes::from(b),
            }),
            Err(e) => {
                warn!(error=%e, "catchup op msgpack encode failed; skipping");
            }
        }
    }
    let has_more = total > take;
    let next_chunk_token = catchup_ops
        .last()
        .map(|c| c.version)
        .unwrap_or(req.since_version);

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
        .send_unicast(from, &rt.topic, StrictBody::CatchupResp(resp))
        .await;
}

/// Apply an inbound `StrictCatchupResp`. Installs the snapshot if
/// requested, then applies each op in order via `apply_committed`. If
/// `has_more`, fires off another request to a random alive peer.
pub(crate) async fn apply_response<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    resp: StrictCatchupResp,
) {
    if !rt.state.lock().can_bootstrap_catchup() {
        return;
    }
    let Some(remote_node) = super::runtime::node_from_u32(resp.history_node) else {
        warn!(
            node = resp.history_node,
            "strict catchup response has invalid history_node"
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

    if resp.too_old_use_snapshot {
        let candidate = if remote_rank.beats(local_rank) && !resp.snapshot_msgpack.is_empty() {
            Some(HistoryElectionCandidate {
                rank: remote_rank,
                snapshot_version: resp.snapshot_version,
                snapshot_msgpack: resp.snapshot_msgpack,
            })
        } else {
            None
        };
        let winner = rt
            .state
            .lock()
            .record_history_election_response(remote_node, candidate);
        if let Some(winner) = winner {
            rt.repo
                .install_snapshot(winner.snapshot_version, winner.snapshot_msgpack)
                .await;
            rt.state.lock().finish_history_election();
        }
        return;
    }

    if !remote_rank.beats(local_rank) {
        rt.state
            .lock()
            .record_history_election_response(remote_node, None);
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
        let op: R::Op = match rmp_serde::from_slice(&cop.op_msgpack) {
            Ok(o) => o,
            Err(e) => {
                warn!(error=%e, "catchup op decode failed; aborting chunk");
                return;
            }
        };
        rt.repo.apply_committed(cop.version, op).await;
    }
    if resp.has_more {
        let alive = rt.net.alive_members();
        let mut peers: Vec<NodeIdentifier> =
            alive.into_iter().filter(|n| *n != rt.self_id).collect();
        if peers.is_empty() {
            return;
        }
        let dst = {
            let mut rng = rand::rng();
            peers.shuffle(&mut rng);
            peers[0]
        };
        let req = StrictCatchupReq {
            src_node: rt.self_id as u32,
            since_version: rt.repo.current_version(),
            chunk_token: resp.next_chunk_token,
            force_snapshot: false,
        };
        let _ = rt
            .net
            .send_unicast(dst, &rt.topic, StrictBody::CatchupReq(req))
            .await;
    }
    if !resp.has_more {
        rt.state
            .lock()
            .record_history_election_response(remote_node, None);
    }
}
