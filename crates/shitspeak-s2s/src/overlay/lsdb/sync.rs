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

use rand::SeedableRng;
use rand::seq::IndexedRandom;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use shitspeak_core::NodeIdentifier;
use shitspeak_proto::s2s_overlay_proto as pb;
use shitspeak_s2s_transport::{ConnectionManager, MessageClass, SendOptions, ServiceLevel};

use super::super::config::OverlayConfig;
use super::super::discovery::learn_from_lsa;
use super::super::duplicate::{DuplicateDetector, DuplicateEvidenceKind};
use super::super::neighbor::monitor::NeighborMonitor;
use super::super::proto::{OverlayBody, encode_message, node_to_wire, wrap};
use super::advert::LsaFloodPacer;
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
    let packet_kind = crate::debug_io::classify_overlay_body(&body);
    match encode_message(&wrap(body)) {
        Ok(payload) => {
            let payload_len = payload.len();
            match transport
                .try_send_with_options(
                    dst,
                    ServiceLevel::Reliable,
                    None,
                    MessageClass::Regular,
                    payload,
                    SendOptions::default().allow_l1_compression(),
                )
                .await
            {
                Ok(()) => crate::debug_io::record_sent(self_id, dst, packet_kind, payload_len),
                Err(e) => trace!(peer=%dst, error=%e, "lsdb sync send failed"),
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
    self_id: NodeIdentifier,
    sender: NodeIdentifier,
    req: pb::LsdbSync,
    max_response_lsas: usize,
) {
    let mut peer_digest: HashMap<NodeIdentifier, OriginVersion> = HashMap::new();
    for d in &req.have {
        if let Ok(origin) = NodeIdentifier::try_from(d.origin) {
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
    send_response_chunks(transport, self_id, sender, &delta, max_response_lsas, true).await;
}

async fn send_response_chunks(
    transport: &ConnectionManager,
    self_id: NodeIdentifier,
    dst: NodeIdentifier,
    entries: &[LsaEntry],
    max_response_lsas: usize,
    nonblocking: bool,
) {
    for chunk in entries.chunks(max_response_lsas.max(1)) {
        let body = OverlayBody::LsdbSyncResp(pb::LsdbSyncResp {
            delta: chunk.iter().map(|e| e.to_pb()).collect(),
        });
        let packet_kind = crate::debug_io::classify_overlay_body(&body);
        let payload = match encode_message(&wrap(body)) {
            Ok(b) => b,
            Err(e) => {
                warn!(error=%e, "lsdb sync resp encode failed");
                return;
            }
        };
        let payload_len = payload.len();
        let result = if nonblocking {
            transport
                .try_send_with_options(
                    dst,
                    ServiceLevel::Reliable,
                    None,
                    MessageClass::Regular,
                    payload,
                    SendOptions::default().allow_l1_compression(),
                )
                .await
        } else {
            transport
                .send_with_options(
                    dst,
                    ServiceLevel::Reliable,
                    None,
                    MessageClass::Regular,
                    payload,
                    SendOptions::default().allow_l1_compression(),
                )
                .await
        };
        match result {
            Ok(()) => crate::debug_io::record_sent(self_id, dst, packet_kind, payload_len),
            Err(e) => {
                trace!(peer=%dst, error=%e, "lsdb sync resp send failed");
                return;
            }
        }
    }
    debug!(peer=%dst, count = entries.len(), "lsdb sync resp sent");
}

/// Push the current LSDB contents to a direct neighbor.
///
/// The normal full-pull path repairs what *we* are missing from a newly-up
/// neighbor. This push covers the opposite direction: LSAs we already learned
/// before that neighbor was considered up and therefore may not have flooded
/// to it.
pub async fn push_snapshot(
    lsdb: &LinkStateDb,
    transport: &ConnectionManager,
    self_id: NodeIdentifier,
    dst: NodeIdentifier,
    max_response_lsas: usize,
) {
    let entries = lsdb.snapshot();
    if entries.is_empty() {
        return;
    }
    send_response_chunks(transport, self_id, dst, &entries, max_response_lsas, true).await;
}

/// Handle an inbound `LsdbSyncResp`. Each LSA goes through the normal
/// admission rule (including the floor check). Accepted LSAs are re-flooded
/// just like flood-admitted LSAs so point-to-point repair can propagate.
pub fn handle_response(
    lsdb: &LinkStateDb,
    monitor: &NeighborMonitor,
    transport: &ConnectionManager,
    pacer: &LsaFloodPacer,
    duplicate_detector: &DuplicateDetector,
    sender: NodeIdentifier,
    resp: pb::LsdbSyncResp,
) {
    let mut accepted = 0usize;
    let mut accepted_lsas = Vec::new();
    for pb_lsa in resp.delta {
        let Some(lsa) = LsaEntry::from_pb(&pb_lsa) else {
            continue;
        };
        duplicate_detector.observe_epoch(
            lsa.origin,
            lsa.boot_epoch,
            lsa.tombstone,
            DuplicateEvidenceKind::Lsa,
        );
        if duplicate_detector.is_quarantined(lsa.origin) {
            duplicate_detector.record_drop(lsa.origin, "lsa");
            continue;
        }
        if matches!(lsdb.admit(lsa.clone()), AdmissionResult::Accepted) {
            learn_from_lsa(transport, &lsa);
            accepted_lsas.push(pb_lsa);
            accepted += 1;
        }
    }
    if accepted > 0 {
        trace!(accepted, "lsdb sync resp processed");
        let snap = monitor.snapshot();
        pacer.enqueue_reflood_to_neighbors(&snap, accepted_lsas, Some(sender));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::time::timeout;

    use super::super::store::LsaFloor;
    use shitspeak_s2s_transport::{SendError, TransportKind};

    fn entry(origin: NodeIdentifier, boot_epoch: u64, seq: u64) -> LsaEntry {
        LsaEntry {
            origin,
            boot_epoch,
            seq,
            ts_local_received: Instant::now(),
            tombstone: false,
            addresses: vec![],
            links: vec![],
            max_users: 0,
            transit_disabled: false,
            replication_services: super::super::store::ReplicationServices::ALL,
        }
    }

    async fn fill_outbound_queue(transport: &ConnectionManager, peer: NodeIdentifier) {
        for _ in 0..4096 {
            match transport
                .try_send(
                    peer,
                    ServiceLevel::Reliable,
                    None,
                    MessageClass::Regular,
                    Bytes::from_static(b"x"),
                )
                .await
            {
                Ok(()) => {}
                Err(SendError::Backpressure { node, transport }) => {
                    assert_eq!(node, peer);
                    assert_eq!(transport, TransportKind::Tcp);
                    return;
                }
                Err(err) => panic!("unexpected outbound queue fill error: {err:?}"),
            }
        }
        panic!("outbound test queue did not report backpressure");
    }

    #[tokio::test]
    async fn inbound_lsdb_sync_returns_promptly_when_peer_outbound_queue_is_full() {
        let (transport, _receivers) =
            ConnectionManager::test_with_live_streams(1, 2, &[TransportKind::Tcp]);
        fill_outbound_queue(&transport, 2).await;

        let lsdb = LinkStateDb::new(Arc::new(LsaFloor::new(1, None)));
        assert!(matches!(
            lsdb.admit(entry(1, 11, 1)),
            AdmissionResult::Accepted
        ));
        let req = pb::LsdbSync {
            src_node: node_to_wire(2),
            have: vec![],
        };

        timeout(
            Duration::from_millis(50),
            handle_request(&lsdb, &transport, 1, 2, req, 1),
        )
        .await
        .expect("inbound LSDB sync handler should not wait for outbound queue space");
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

        let mut rng = {
            let mut seed_rng = rand::rng();
            rand::rngs::SmallRng::from_rng(&mut seed_rng)
        };
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
