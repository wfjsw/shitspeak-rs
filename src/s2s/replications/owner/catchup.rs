//! Owner-mode catchup: per-origin chunked snapshot + log replay.
//!
//! Same chunking model as strict catchup: stateless server-side, client
//! re-issues with `since_version = repo.known_versions()[origin].1`.

use rand::seq::SliceRandom;
use tracing::warn;

use super::super::proto::{
    CatchupOp, OwnerBody, OwnerCatchupReq, OwnerCatchupResp,
};
use super::runtime::OwnerRuntime;
use super::{LogSlice, OwnerReplicable};
use crate::types::NodeIdentifier;

pub(crate) async fn respond_to_request<R: OwnerReplicable>(
    rt: &OwnerRuntime<R>,
    from: NodeIdentifier,
    req: OwnerCatchupReq,
) {
    let Some(origin) = node_from_u32(req.origin_node) else {
        warn!("owner catchup req has invalid origin_node");
        return;
    };

    let known = rt.repo.known_versions();
    let (origin_epoch, _origin_version) = match known.get(&origin) {
        Some(p) => *p,
        None => {
            // We don't know about this origin — respond empty.
            let _ = rt
                .net
                .send_unicast(
                    from,
                    &rt.topic,
                    OwnerBody::CatchupResp(OwnerCatchupResp {
                        origin_node: origin as u32,
                        origin_epoch: 0,
                        snapshot_version: 0,
                        snapshot_msgpack: vec![],
                        ops: vec![],
                        has_more: false,
                        next_chunk_token: 0,
                        too_old_use_snapshot: false,
                    }),
                )
                .await;
            return;
        }
    };

    let mut snapshot_version = 0u64;
    let mut snapshot_msgpack: Vec<u8> = Vec::new();
    let mut too_old_use_snapshot = false;

    let effective_ops: Vec<(u64, R::Op)> = match rt.repo.log_for_origin(origin, req.since_version)
    {
        LogSlice::Available(ops) => ops,
        LogSlice::TooOld => {
            too_old_use_snapshot = true;
            if let Some((sepoch, sver, snap)) = rt.repo.snapshot_for_origin(origin) {
                snapshot_version = sver;
                snapshot_msgpack = snap;
                // The snapshot epoch should equal the known epoch we just looked up.
                debug_assert_eq!(sepoch, origin_epoch);
                match rt.repo.log_for_origin(origin, sver) {
                    LogSlice::Available(ops) => ops,
                    LogSlice::TooOld => Vec::new(),
                }
            } else {
                Vec::new()
            }
        }
    };

    let total = effective_ops.len();
    let take = total.min(rt.cfg.owner_max_catchup_ops());
    let mut catchup_ops: Vec<CatchupOp> = Vec::with_capacity(take);
    for (v, op) in effective_ops.iter().take(take) {
        match rmp_serde::to_vec(op) {
            Ok(b) => catchup_ops.push(CatchupOp {
                version: *v,
                op_msgpack: b,
            }),
            Err(e) => warn!(error=%e, "owner catchup op encode failed; skipping"),
        }
    }
    let has_more = total > take;
    let next_chunk_token = catchup_ops
        .last()
        .map(|c| c.version)
        .unwrap_or(req.since_version);

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
    let _ = rt
        .net
        .send_unicast(from, &rt.topic, OwnerBody::CatchupResp(resp))
        .await;
}

pub(crate) async fn apply_response<R: OwnerReplicable>(
    rt: &OwnerRuntime<R>,
    resp: OwnerCatchupResp,
) {
    let Some(origin) = node_from_u32(resp.origin_node) else {
        warn!("owner catchup resp has invalid origin_node");
        return;
    };
    let resp_epoch = resp.origin_epoch;

    // If the response carries a snapshot, install it (and consider this a
    // fresh epoch root if it advances ours).
    if resp.too_old_use_snapshot && !resp.snapshot_msgpack.is_empty() {
        rt.repo
            .install_snapshot_for_origin(
                origin,
                resp_epoch,
                resp.snapshot_version,
                resp.snapshot_msgpack,
            )
            .await;
        let mut s = rt.state.lock();
        s.known.insert(origin, (resp_epoch, resp.snapshot_version));
        // Wipe pending under the new epoch root.
        s.pending_buffers.remove(&origin);
    }

    // If the responder reports a higher epoch than we have, treat that as
    // a network-driven epoch reset (same path as Classification::Reset).
    let needs_reset = {
        let s = rt.state.lock();
        match s.known.get(&origin) {
            Some((e, _)) => resp_epoch > *e,
            None => true,
        }
    };
    if needs_reset && !resp.too_old_use_snapshot {
        rt.repo.reset_origin(origin, resp_epoch).await;
        let mut s = rt.state.lock();
        s.known.insert(origin, (resp_epoch, 0));
        s.pending_buffers.remove(&origin);
    }

    for cop in resp.ops {
        let typed: R::Op = match rmp_serde::from_slice(&cop.op_msgpack) {
            Ok(o) => o,
            Err(e) => {
                warn!(error=%e, "owner catchup op decode failed; aborting chunk");
                return;
            }
        };
        rt.repo
            .apply_remote(origin, resp_epoch, cop.version, typed)
            .await;
        let mut s = rt.state.lock();
        s.known.insert(origin, (resp_epoch, cop.version));
    }

    // Clear catchup-in-flight unless we're going to immediately re-fire.
    {
        let mut s = rt.state.lock();
        s.catchup_in_flight.remove(&origin);
    }

    if resp.has_more {
        let alive = rt.net.alive_members();
        let mut peers: Vec<NodeIdentifier> = alive
            .into_iter()
            .filter(|n| *n != rt.self_id && *n != origin)
            .collect();
        let dst = if !peers.is_empty() {
            let mut rng = rand::thread_rng();
            peers.shuffle(&mut rng);
            peers[0]
        } else {
            origin
        };
        let since = {
            let s = rt.state.lock();
            s.known.get(&origin).map(|(_, v)| *v).unwrap_or(0)
        };
        let req = OwnerCatchupReq {
            origin_node: origin as u32,
            src_node: rt.self_id as u32,
            known_epoch: resp_epoch,
            since_version: since,
            chunk_token: resp.next_chunk_token,
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
        let _ = rt
            .net
            .send_unicast(dst, &rt.topic, OwnerBody::CatchupReq(req))
            .await;
    }
}

#[inline]
fn node_from_u32(v: u32) -> Option<NodeIdentifier> {
    if v <= u16::MAX as u32 {
        Some(v as NodeIdentifier)
    } else {
        None
    }
}
