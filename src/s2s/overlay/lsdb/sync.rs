//! `LsdbSync` digest exchange — covers both partition-heal pull and
//! periodic anti-entropy with a single message shape.
//!
//! * Partition-heal: send `LsdbSync { have: [] }` (empty digest) right
//!   after a previously-down direct neighbor comes back up. The peer
//!   responds with every LSA it has.
//! * Anti-entropy: every `anti_entropy_interval` pick a random direct
//!   neighbor and send our full digest. The peer returns LSAs we are
//!   missing or stale on.
//!
//! In both cases the responder builds `LsdbSyncResp { delta }` containing
//! only the LSAs strictly newer than what the requester reports. Chunked
//! at [`OverlayConfig::lsdb_sync_max_response_lsas`] per frame so a single
//! response can fan into several `LsdbSyncResp`s.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::s2s::transport::{ConnectionManager, MessageClass, ServiceLevel};
use crate::s2s_overlay_proto as pb;
use crate::types::NodeIdentifier;

use super::super::config::OverlayConfig;
use super::super::neighbor::monitor::NeighborMonitor;
use super::super::proto::{
    encode_message, node_from_wire, node_to_wire, wrap, OverlayBody,
};
use super::store::{AdmissionResult, LinkStateDb, LsaEntry, OriginVersion};

/// Send an `LsdbSync` request to `dst`. `have` is our digest; pass `&[]`
/// for a full pull.
pub async fn send_request(
    transport: &ConnectionManager,
    self_id: NodeIdentifier,
    dst: NodeIdentifier,
    have: &[(NodeIdentifier, u64, u64)],
) {
    let body = OverlayBody::LsdbSync(pb::LsdbSync {
        src_node: node_to_wire(self_id),
        have: have
            .iter()
            .map(|(o, b, s)| pb::DigestEntry {
                origin: node_to_wire(*o),
                boot_epoch: *b,
                seq: *s,
            })
            .collect(),
    });
    match encode_message(&wrap(body)) {
        Ok(payload) => {
            if let Err(e) = transport
                .send(dst, ServiceLevel::Reliable, MessageClass::Regular, payload)
                .await
            {
                trace!(peer=%dst, error=%e, "lsdb sync send failed");
            }
        }
        Err(e) => warn!(error=%e, "lsdb sync encode failed"),
    }
}

/// Handle an inbound `LsdbSync` request. Build chunked `LsdbSyncResp`s
/// and send back to `sender`.
pub async fn handle_request(
    lsdb: &LinkStateDb,
    transport: &ConnectionManager,
    sender: NodeIdentifier,
    req: pb::LsdbSync,
    max_response_lsas: usize,
) {
    let mut peer_digest: HashMap<NodeIdentifier, OriginVersion> = HashMap::new();
    for d in &req.have {
        if let Some(origin) = node_from_wire(d.origin) {
            peer_digest.insert(
                origin,
                OriginVersion {
                    boot_epoch: d.boot_epoch,
                    seq: d.seq,
                },
            );
        }
    }
    let delta = lsdb.diff_for(&peer_digest);
    if delta.is_empty() {
        trace!(peer=%sender, "lsdb sync: nothing to send");
        return;
    }
    for chunk in delta.chunks(max_response_lsas.max(1)) {
        let body = OverlayBody::LsdbSyncResp(pb::LsdbSyncResp {
            delta: chunk.iter().map(|e| e.to_pb()).collect(),
        });
        let payload = match encode_message(&wrap(body)) {
            Ok(b) => b,
            Err(e) => {
                warn!(error=%e, "lsdb sync resp encode failed");
                return;
            }
        };
        if let Err(e) = transport
            .send(sender, ServiceLevel::Reliable, MessageClass::Regular, payload)
            .await
        {
            trace!(peer=%sender, error=%e, "lsdb sync resp send failed");
            return;
        }
    }
    debug!(peer=%sender, count = delta.len(), "lsdb sync resp sent");
}

/// Handle an inbound `LsdbSyncResp`. Each LSA goes through the normal
/// admission rule (including the floor check). Accepted LSAs are NOT
/// re-flooded — sync is point-to-point.
pub fn handle_response(lsdb: &LinkStateDb, resp: pb::LsdbSyncResp) {
    let mut accepted = 0usize;
    for pb_lsa in resp.delta {
        let Some(lsa) = LsaEntry::from_pb(&pb_lsa) else {
            continue;
        };
        if matches!(lsdb.admit(lsa), AdmissionResult::Accepted) {
            accepted += 1;
        }
    }
    if accepted > 0 {
        trace!(accepted, "lsdb sync resp processed");
    }
}

/// Periodic anti-entropy task. Picks one random direct neighbor every
/// `anti_entropy_interval` and sends our digest.
pub fn spawn_anti_entropy(
    lsdb: Arc<LinkStateDb>,
    monitor: Arc<NeighborMonitor>,
    transport: ConnectionManager,
    self_id: NodeIdentifier,
    cfg: OverlayConfig,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        let mut tick = interval(cfg.anti_entropy_interval());
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Drop the immediate first tick so we don't sync at start before
        // the cluster is even up.
        tick.tick().await;

        let mut rng = rand::rngs::SmallRng::from_entropy();
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tick.tick() => {}
            }
            let snap = monitor.snapshot();
            if snap.is_empty() {
                continue;
            }
            let pick = snap.choose(&mut rng).map(|n| n.node_id);
            let Some(target) = pick else { continue };
            let digest = lsdb.digest();
            send_request(&transport, self_id, target, &digest).await;
        }
    });
}

/// One-shot full pull on a previously-down link coming back up. Sends an
/// empty digest to `dst`.
pub async fn full_pull(
    transport: &ConnectionManager,
    self_id: NodeIdentifier,
    dst: NodeIdentifier,
) {
    send_request(transport, self_id, dst, &[]).await;
}
