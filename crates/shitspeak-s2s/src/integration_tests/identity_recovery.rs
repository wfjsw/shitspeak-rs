//! Requirement 2: automatic recovery after an impostor fences this node id.
//!
//! A duplicate that boots with a higher `boot_epoch` is treated by every peer
//! as a restart of this node id, and those peers then reject this node's own
//! advertisements as stale — a block that outlives the impostor because it is
//! persisted in the LSDB floor. The only exit is minting a higher epoch.
//!
//! These tests cover the pieces that make that automatic: the fence notice a
//! peer sends back to a fenced origin, the refusal to admit a foreign copy of
//! our own LSA, and the guard's decision to request re-incarnation — but only
//! once the impostor is actually gone.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use shitspeak_core::NodeIdentifier;
use shitspeak_proto::s2s_overlay_proto as pb;
use shitspeak_s2s_transport::testing::{
    install_provider_once, loopback, mint_pki, pick_free_port, s2s_network_test_guard,
};
use shitspeak_s2s_transport::{
    ConnectionManager, Inbound, MessageClass, SeedAddress, ServiceLevel, TransportKind,
};

use crate::overlay::config::OverlayConfig;
use crate::overlay::{DuplicateDetector, HelloObservation};
use crate::overlay::identity::{
    IdentityProbeResponse, encode_identity_probe_resp, send_identity_probe,
};
use crate::overlay::identity_guard::{
    FenceTrigger, GuardDecision, GuardTuning, IdentityGuard, ReincarnationRequest,
};
use crate::overlay::lsdb::{AdmissionResult, LinkStateDb, LsaEntry, LsaFloodPacer, LsaFloor};
use crate::overlay::neighbor::NeighborMonitor;
use crate::overlay::proto::{OverlayBody, decode_message};
use crate::testing::transport_cfg;

/// Short guard timings so the decision logic is observable without waiting
/// out the production debounce and cooldown.
fn fast_tuning() -> GuardTuning {
    GuardTuning {
        // No debounce: these tests assert the decision itself, not the
        // confirmation delay the production default applies.
        fence_debounce: Duration::ZERO,
        probe_wait: Duration::from_millis(400),
        competitor_live_window: Duration::from_secs(30),
        reincarnation_cooldown: Duration::from_millis(50),
    }
}

/// Build an LSA entry the way the receive path does, so defaults and
/// validation match production rather than a hand-written struct.
fn lsa(origin: u16, boot_epoch: u64, seq: u64) -> LsaEntry {
    LsaEntry::from_pb(&pb::LinkStateAdvert {
        origin: u32::from(origin),
        boot_epoch,
        seq,
        ..Default::default()
    })
    .expect("hand-built LSA must decode")
}

fn observation(boot_epoch: u64, age: Duration) -> HelloObservation {
    HelloObservation { boot_epoch, age }
}

/// A node under test wired to a stub peer that answers identity probes with a
/// fixed set of overlay observations.
struct GuardHarness {
    guard: Arc<IdentityGuard>,
    node: ConnectionManager,
    shutdown: CancellationToken,
}

impl GuardHarness {
    /// Bring up node `node_id` plus a peer that reports `observations` for it.
    async fn start(
        node_id: NodeIdentifier,
        peer_id: NodeIdentifier,
        observations: Vec<HelloObservation>,
    ) -> Self {
        install_provider_once();
        let pki = mint_pki(&[node_id, peer_id]);
        let peer_port = pick_free_port().await;
        let node_port = pick_free_port().await;

        let (peer, peer_inbound) =
            ConnectionManager::start(transport_cfg(&pki, 1, loopback(peer_port)))
                .await
                .unwrap();
        let (node, node_inbound) = ConnectionManager::start(
            transport_cfg(&pki, 0, loopback(node_port)).with_seed_target(SeedAddress::new(
                loopback(peer_port).to_string(),
                TransportKind::Tcp,
            )),
        )
        .await
        .unwrap();

        let shutdown = CancellationToken::new();
        spawn_probe_responder(peer, peer_inbound, observations, shutdown.clone());

        let duplicate_detector = Arc::new(DuplicateDetector::new(node_id, Duration::from_secs(30)));
        let cfg = OverlayConfig::new(Vec::new());
        let (events, _) = tokio::sync::broadcast::channel(64);
        let monitor = Arc::new(NeighborMonitor::new(
            node_id,
            node.clone(),
            duplicate_detector,
            cfg,
            events,
        ));
        let _ = &monitor;
        let guard =
            IdentityGuard::with_tuning(node_id, 5, node.clone(), shutdown.clone(), fast_tuning());
        guard.spawn();
        // Stand in for the overlay dispatcher: without it the guard's probe
        // answers arrive on the inbound queue and are never delivered.
        {
            let guard = Arc::clone(&guard);
            let shutdown = shutdown.clone();
            let (mut control, _high, _regular) = node_inbound.into_parts();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        msg = control.recv() => {
                            let Some(msg) = msg else { return };
                            if let Some(response) = IdentityProbeResponse::decode(msg.payload()) {
                                guard.deliver_probe_response(response);
                            }
                        }
                    }
                }
            });
        }

        // Wait for the session so the guard has someone to probe.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if node.live_peers().iter().any(|(peer, _)| *peer == peer_id) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            node.live_peers().iter().any(|(peer, _)| *peer == peer_id),
            "guard harness never connected to its stub peer"
        );

        Self {
            guard,
            node,
            shutdown,
        }
    }

    async fn shutdown(self) {
        self.shutdown.cancel();
        self.node.shutdown().await;
    }
}

/// Answer every identity probe with a fixed observation set, so a test fully
/// controls what the node under test is told about its own liveness.
fn spawn_probe_responder(
    peer: ConnectionManager,
    mut inbound: Inbound,
    observations: Vec<HelloObservation>,
    shutdown: CancellationToken,
) {
    let floor = LsaFloor::new(0, None);
    let lsdb = LinkStateDb::new(Arc::new(LsaFloor::new(0, None)));
    tokio::spawn(async move {
        let mut replies = 0usize;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                msg = inbound.control().recv() => {
                    let Some(msg) = msg else { return };
                    let Ok(decoded) = decode_message(msg.payload()) else {
                        continue;
                    };
                    let Some(OverlayBody::IdentityProbe(probe)) = decoded.body else {
                        continue;
                    };
                    let Ok(subject) = NodeIdentifier::try_from(probe.subject) else {
                        continue;
                    };
                    // A live neighbour's hello stream refreshes its age rather
                    // than letting it grow without bound. Cycle the reported
                    // age so the requester sees the refresh.
                    let reported: Vec<HelloObservation> = observations
                        .iter()
                        .map(|observation| HelloObservation {
                            boot_epoch: observation.boot_epoch,
                            age: observation.age / 2
                                + Duration::from_millis((replies % 4) as u64 * 10),
                        })
                        .collect();
                    replies += 1;
                    let Some(payload) = encode_identity_probe_resp(
                        subject,
                        probe.nonce,
                        &reported,
                        &lsdb,
                        &floor,
                    ) else {
                        continue;
                    };
                    let _ = peer
                        .send(
                            msg.from(),
                            ServiceLevel::Reliable,
                            None,
                            MessageClass::Control,
                            payload,
                        )
                        .await;
                }
            }
        }
    });
}

fn decision_counts(guard: &IdentityGuard) -> HashMap<GuardDecision, u64> {
    guard.decision_counts().into_iter().collect()
}

/// The impostor has gone away: peers report no live foreign epoch for this
/// node id, so the guard must ask for re-incarnation above the impostor's.
#[tokio::test]
async fn identity_guard_requests_reincarnation_once_the_impostor_is_gone() {
    let _guard = s2s_network_test_guard().await;
    let harness = GuardHarness::start(1, 9, Vec::new()).await;
    let mut requests = harness.guard.reincarnation_requests();

    // A peer rejects our LSA because it holds epoch 500 for us; we run epoch 5.
    harness.guard.report_trigger(FenceTrigger::OriginFenced {
        fence_epoch: 500,
        fence_seq: 12,
    });

    let request = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if requests.changed().await.is_err() {
                return None;
            }
            if let Some(request) = requests.borrow_and_update().clone() {
                return Some(request);
            }
        }
    })
    .await
    .expect("guard never published a re-incarnation request")
    .expect("re-incarnation request channel closed");

    assert_eq!(
        request,
        ReincarnationRequest {
            floor_epoch: 500,
            reason: "origin_fenced",
            peers_answered: 1,
        }
    );
    assert_eq!(
        decision_counts(&harness.guard).get(&GuardDecision::Requested),
        Some(&1)
    );

    harness.shutdown().await;
}

/// While a peer still reports a live foreign epoch, the impostor is up.
/// Re-incarnating now would only fight it, so the guard must hold off.
#[tokio::test]
async fn identity_guard_holds_off_while_the_impostor_is_still_live() {
    let _guard = s2s_network_test_guard().await;
    let harness = GuardHarness::start(
        1,
        9,
        // The competitor's epoch 500, seen live moments ago.
        vec![observation(500, Duration::from_millis(40))],
    )
    .await;
    let mut requests = harness.guard.reincarnation_requests();

    harness.guard.report_trigger(FenceTrigger::OriginFenced {
        fence_epoch: 500,
        fence_seq: 12,
    });

    let quiet_until = tokio::time::Instant::now() + Duration::from_millis(1_500);
    loop {
        tokio::select! {
            changed = requests.changed() => {
                if changed.is_ok() && requests.borrow_and_update().is_some() {
                    panic!("the guard must not request re-incarnation while a competitor is live");
                }
            }
            _ = tokio::time::sleep_until(quiet_until) => break,
        }
    }

    let decisions = decision_counts(&harness.guard);
    assert!(
        decisions.get(&GuardDecision::CompetitorLive).is_some_and(|n| *n >= 1),
        "the guard must recognise the live competitor: {decisions:?}"
    );
    assert!(
        !decisions.contains_key(&GuardDecision::Requested),
        "the guard must not request re-incarnation: {decisions:?}"
    );

    harness.shutdown().await;
}

/// The guard only acts on a strictly higher epoch: an equal or lower one is
/// this node's own history and must never start the recovery path.
#[tokio::test]
async fn guard_ignores_triggers_at_or_below_the_local_epoch() {
    let _guard = s2s_network_test_guard().await;
    let harness = GuardHarness::start(1, 9, Vec::new()).await;

    harness.guard.report_trigger(FenceTrigger::OriginFenced {
        fence_epoch: 5,
        fence_seq: 1,
    });
    harness.guard.report_trigger(FenceTrigger::ForeignSelfLsa {
        foreign_epoch: 4,
        foreign_seq: 9,
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        decision_counts(&harness.guard).is_empty(),
        "a non-advancing epoch must not start the recovery path: {:?}",
        harness.guard.decision_counts()
    );
    assert!(harness.guard.reincarnation_requests().borrow().is_none());

    harness.shutdown().await;
}

/// A fenced origin must be told. Without this the fenced node never learns
/// why its advertisements vanish, and stays out until someone restarts it.
#[tokio::test]
async fn origin_fenced_notice_reaches_the_fenced_origin() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let pki = mint_pki(&[1, 2]);
    let peer_port = pick_free_port().await;
    let node_port = pick_free_port().await;

    let (peer, mut peer_inbound) =
        ConnectionManager::start(transport_cfg(&pki, 1, loopback(peer_port)))
            .await
            .unwrap();
    let (node, _node_inbound) = ConnectionManager::start(
        transport_cfg(&pki, 0, loopback(node_port)).with_seed_target(SeedAddress::new(
            loopback(peer_port).to_string(),
            TransportKind::Tcp,
        )),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The peer already holds epoch 500 for origin 2, so node 2's own
    // epoch-100 advertisement can never land there.
    let lsdb = LinkStateDb::new(Arc::new(LsaFloor::new(1, None)));
    lsdb.admit(lsa(2, 500, 7));
    let stale = lsa(2, 100, 42);

    crate::overlay::lsdb::advert::notice_origin_if_fenced(&lsdb, &node, 1, 2, &stale).await;

    let received = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let Some(msg) = peer_inbound.control().recv().await else {
                return None;
            };
            let Ok(decoded) = decode_message(msg.payload()) else {
                continue;
            };
            if let Some(OverlayBody::OriginFenced(fenced)) = decoded.body {
                return Some(fenced);
            }
        }
    })
    .await
    .expect("no OriginFenced notice arrived")
    .expect("inbound closed before the notice");

    assert_eq!(received.origin, 2);
    assert_eq!(received.fence_epoch, 500);
    assert_eq!(received.fence_seq, 7);

    node.shutdown().await;
    peer.shutdown().await;
}

/// This node is authoritative for its own LSA. A foreign copy must never be
/// admitted — it would replace our entry and suppress our own floods.
#[tokio::test]
async fn self_origin_lsa_is_rejected_and_reported_as_a_conflict() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let pki = mint_pki(&[1, 2]);
    let peer_port = pick_free_port().await;
    let node_port = pick_free_port().await;

    let (peer, _peer_inbound) =
        ConnectionManager::start(transport_cfg(&pki, 1, loopback(peer_port)))
            .await
            .unwrap();
    let (node, _node_inbound) = ConnectionManager::start(
        transport_cfg(&pki, 0, loopback(node_port)).with_seed_target(SeedAddress::new(
            loopback(peer_port).to_string(),
            TransportKind::Tcp,
        )),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let self_id = 1u16;
    let lsdb = Arc::new(LinkStateDb::new(Arc::new(LsaFloor::new(self_id, None))));
    let duplicate_detector = Arc::new(DuplicateDetector::new(self_id, Duration::from_secs(30)));
    let cfg = OverlayConfig::new(Vec::new());
    let (events, _) = tokio::sync::broadcast::channel(64);
    let monitor = Arc::new(NeighborMonitor::new(
        self_id,
        node.clone(),
        duplicate_detector.clone(),
        cfg,
        events,
    ));
    let pacer = LsaFloodPacer::new(self_id, node.clone());

    let shutdown = CancellationToken::new();
    let guard =
        IdentityGuard::with_tuning(self_id, 5, node.clone(), shutdown.clone(), fast_tuning());
    lsdb.set_identity_guard(guard.clone());
    guard.spawn();

    // Our own LSA first: this is what the impostor would displace.
    assert_eq!(lsdb.admit(lsa(self_id, 5, 3)), AdmissionResult::Accepted);

    crate::overlay::lsdb::handle_flood(
        &lsdb,
        &monitor,
        &node,
        &pacer,
        &duplicate_detector,
        2,
        pb::LsaFlood {
            advertisements: vec![pb::LinkStateAdvert {
                origin: u32::from(self_id),
                boot_epoch: 900,
                seq: 1,
                ..Default::default()
            }],
        },
    )
    .await;

    let entry = lsdb
        .get(self_id)
        .expect("our own origin must stay in the LSDB");
    assert_eq!(
        entry.boot_epoch, 5,
        "a foreign copy of our own LSA must never displace it"
    );

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        guard.reincarnation_requests().borrow().is_none(),
        "a single sighting must not request re-incarnation"
    );

    shutdown.cancel();
    node.shutdown().await;
    peer.shutdown().await;
}
/// Requirement 1's evidence rule, end to end over real transport: a peer that
/// keeps reporting a live overlay neighbour for this node id must cause the
/// boot to be refused.
#[tokio::test]
async fn startup_preflight_refuses_a_sustained_live_overlay_competitor() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let pki = mint_pki(&[2, 9]);
    let peer_port = pick_free_port().await;
    let node_port = pick_free_port().await;

    let (peer, peer_inbound) = ConnectionManager::start(transport_cfg(&pki, 1, loopback(peer_port)))
        .await
        .unwrap();
    let (node, node_inbound) = ConnectionManager::start(
        transport_cfg(&pki, 0, loopback(node_port)).with_seed_target(SeedAddress::new(
            loopback(peer_port).to_string(),
            TransportKind::Tcp,
        )),
    )
    .await
    .unwrap();
    let shutdown = CancellationToken::new();
    // The competitor's epoch 500, reported live on every probe.
    spawn_probe_responder(
        peer,
        peer_inbound,
        vec![observation(500, Duration::from_millis(30))],
        shutdown.clone(),
    );

    let (_inbound, evidence) = crate::overlay::duplicate_startup_identity_preflight(
        2,
        &node,
        node_inbound,
        std::time::Instant::now(),
        Duration::from_millis(1_500),
        Duration::from_millis(200),
        Duration::from_millis(800),
    )
    .await;

    let evidence = evidence.expect("a sustained live competitor must refuse the boot");
    assert_eq!(evidence.kind(), "identity_probe");
    assert_eq!(evidence.source(), 9);

    shutdown.cancel();
    node.shutdown().await;
}

/// The probe path used by both the boot preflight and the recovery guard must
/// be answered by a real overlay dispatcher, not just the test stub.
///
/// Nodes 1 and 2 form a mesh; a third identity asks node 1 about node 2. Every
/// identity is distinct, so there is one session per node id and the reply
/// cannot be routed to the wrong process.
#[tokio::test]
async fn overlay_dispatcher_answers_identity_probes_about_a_live_neighbour() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let pki = mint_pki(&[1, 2, 3]);
    let node1_port = pick_free_port().await;
    let node2_port = pick_free_port().await;
    let asker_port = pick_free_port().await;

    let seed = |target: u16, port: u16| {
        vec![crate::overlay::SeedPeer::new(
            target,
            vec![shitspeak_s2s_transport::PeerAddress::new(
                loopback(port),
                TransportKind::Tcp,
            )],
        )]
    };

    let (node1_transport, node1_inbound) =
        ConnectionManager::start(transport_cfg(&pki, 0, loopback(node1_port)))
            .await
            .unwrap();
    let node1 = crate::overlay::OverlayNetwork::start(
        node1_transport.clone(),
        node1_inbound,
        crate::testing::overlay_cfg(seed(2, node2_port)),
    )
    .await
    .unwrap();

    let (node2_transport, node2_inbound) =
        ConnectionManager::start(transport_cfg(&pki, 1, loopback(node2_port)))
            .await
            .unwrap();
    let node2 = crate::overlay::OverlayNetwork::start(
        node2_transport.clone(),
        node2_inbound,
        crate::testing::overlay_cfg(seed(1, node1_port)),
    )
    .await
    .unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if node1.alive_members().contains(&2) && node2.alive_members().contains(&1) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        node1.alive_members().contains(&2),
        "node 2 never became a live overlay neighbour of node 1: {:?}",
        node1.members()
    );

    let (asker, mut asker_inbound) =
        ConnectionManager::start(transport_cfg(&pki, 2, loopback(asker_port)))
            .await
            .unwrap();
    asker
        .add_address(
            1,
            shitspeak_s2s_transport::PeerAddress::new(
                loopback(node1_port),
                TransportKind::Tcp,
            ),
        )
        .await;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if asker.live_peers().iter().any(|(peer, _)| *peer == 1) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        asker.live_peers().iter().any(|(peer, _)| *peer == 1),
        "the asker never established a session to node 1"
    );

    // Pretend this identity has been up half a second: an observation fresher
    // than that proves the neighbour is alive now, not merely historically.
    let boot_start = std::time::Instant::now() - Duration::from_millis(500);
    let t_send = send_identity_probe(&asker, 3, 1, 2, 42)
        .await
        .expect("probe send failed");

    let response = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let Some(msg) = asker_inbound.control().recv().await else {
                return None;
            };
            if let Some(response) = IdentityProbeResponse::decode(msg.payload()) {
                return Some(response);
            }
        }
    })
    .await
    .expect("no identity probe response")
    .expect("inbound closed");

    assert_eq!(response.nonce, 42);
    assert_eq!(response.subject, 2);
    let live: Vec<u64> = response
        .hello_epochs
        .iter()
        .map(|observation| observation.boot_epoch)
        .collect();
    assert!(
        live.contains(&node2.local_boot_epoch()),
        "the peer must report its live neighbour's epoch: {live:?}"
    );
    assert!(
        response.proves_alive_after(t_send, boot_start),
        "a fresh observation must prove the neighbour is alive: {response:?}"
    );

    asker.shutdown().await;
    node2.shutdown().await;
    node2_transport.shutdown().await;
    node1.shutdown().await;
    node1_transport.shutdown().await;
}
