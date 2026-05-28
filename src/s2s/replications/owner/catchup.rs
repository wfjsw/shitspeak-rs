//! Owner-mode catchup: per-origin chunked snapshot + log replay.
//!
//! Same chunking model as strict catchup: stateless server-side, client
//! re-issues with `since_version = repo.known_versions()[origin].1`.

use bytes::Bytes;
use rand::seq::SliceRandom;
use tracing::warn;

use super::super::proto::{CatchupOp, OwnerBody, OwnerCatchupReq, OwnerCatchupResp, OwnerOp};
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
                        snapshot_msgpack: Bytes::new(),
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
    let mut snapshot_msgpack: Bytes = Bytes::new();
    let mut too_old_use_snapshot = false;

    let effective_ops: Vec<(u64, R::Op)> = match rt.repo.log_for_origin(origin, req.since_version) {
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
                op_msgpack: Bytes::from(b),
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

    let previous_epoch = {
        let s = rt.state.lock();
        s.known.get(&origin).map(|(epoch, _)| *epoch)
    };
    if previous_epoch
        .map(|known_epoch| resp_epoch < known_epoch)
        .unwrap_or(false)
    {
        return;
    }

    let needs_restart_reset = previous_epoch
        .map(|known_epoch| resp_epoch > known_epoch)
        .unwrap_or(false);
    if needs_restart_reset {
        rt.repo.reset_origin(origin, resp_epoch).await;
        let mut s = rt.state.lock();
        s.known.insert(origin, (resp_epoch, 0));
        s.pending_buffers.remove(&origin);
    }

    // If the response carries a snapshot, install it (and consider this a
    // fresh epoch root if it advances ours).
    if resp.too_old_use_snapshot && !resp.snapshot_msgpack.is_empty() {
        let should_install = {
            let s = rt.state.lock();
            match s.known.get(&origin).copied() {
                Some((known_epoch, _)) if known_epoch > resp_epoch => false,
                Some((known_epoch, known_version)) if known_epoch == resp_epoch => {
                    known_version < resp.snapshot_version
                }
                _ => true,
            }
        };
        if should_install {
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
    }

    // Keep the request timestamp after a response arrives. It is the retry
    // gate, not just an in-flight marker; clearing it here lets fast empty
    // responses bypass `owner_catchup_timeout`.
    for cop in resp.ops {
        rt.process_remote_op(
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

    if resp.has_more {
        let alive = rt.net.alive_members();
        let mut peers: Vec<NodeIdentifier> = alive
            .into_iter()
            .filter(|n| *n != rt.self_id && *n != origin)
            .collect();
        let dst = if !peers.is_empty() {
            let mut rng = rand::rng();
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
