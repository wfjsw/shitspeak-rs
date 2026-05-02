//! Integration test scenarios.
//!
//! Each test brings up a [`Cluster`](crate::s2s::testing::Cluster) of two
//! or more `OverlayNetwork` instances on real `ConnectionManager`s, applies
//! optional [`LinkChaos`](crate::s2s::testing::LinkChaos), and asserts a
//! single end-to-end behavior. Common helpers (PKI, ports, wait predicates)
//! live in [`crate::s2s::testing`].

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::s2s::testing::{
    full_mesh_seeds, install_provider_once, line_seeds, loopback, mint_pki, overlay_cfg,
    pick_free_port, transport_cfg, wait_for_full_alive_mesh, wait_for_full_routing, wait_until,
    Capture, Cluster, MessageType,
};
use crate::s2s::transport::{
    ConnectionManager, MessageClass, PeerAddress, ServiceLevel, TransportKind,
};

use super::super::config::SeedPeer;
use super::super::membership::MembershipEvent;
use super::super::OverlayNetwork;

// ---------------------------------------------------------------------------
// Phase-2 baseline tests (5)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_node_mesh_forms_and_lsdb_converges() {
    let cluster = Cluster::build(&[1, 2], |idx, _ids, ports| {
        // Bidirectional seeding.
        let mut out = Vec::new();
        if idx == 0 {
            out.push(SeedPeer::new(
                2,
                vec![PeerAddress::new(loopback(ports[1]), TransportKind::Tcp)],
            ));
        } else {
            out.push(SeedPeer::new(
                1,
                vec![PeerAddress::new(loopback(ports[0]), TransportKind::Tcp)],
            ));
        }
        out
    })
    .await;

    let a = cluster.node(1);
    let b = cluster.node(2);
    assert_eq!(a.overlay.local_node_id(), 1);
    assert_eq!(b.overlay.local_node_id(), 2);

    assert!(
        wait_for_full_alive_mesh(&cluster, Duration::from_secs(8)).await,
        "2-node mesh failed to converge: A={:?}, B={:?}",
        a.overlay.members(),
        b.overlay.members()
    );

    cluster.shutdown_all().await;
}

#[tokio::test]
async fn graceful_shutdown_emits_left() {
    let cluster = Cluster::build(&[100, 200], |idx, _ids, ports| {
        if idx == 0 {
            vec![SeedPeer::new(
                200,
                vec![PeerAddress::new(loopback(ports[1]), TransportKind::Tcp)],
            )]
        } else {
            vec![SeedPeer::new(
                100,
                vec![PeerAddress::new(loopback(ports[0]), TransportKind::Tcp)],
            )]
        }
    })
    .await;

    let a = cluster.node(100);
    let b = cluster.node(200);

    assert!(
        wait_for_full_alive_mesh(&cluster, Duration::from_secs(8)).await,
        "2-node mesh failed to converge"
    );

    let mut events_a = a.overlay.subscribe_membership();
    b.overlay.shutdown().await;

    let mut got_left = false;
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < until {
        if let Ok(Ok(ev)) = timeout(Duration::from_millis(500), events_a.recv()).await {
            if matches!(ev, MembershipEvent::Left(200)) {
                got_left = true;
                break;
            }
        }
    }
    assert!(got_left, "never saw Left(200)");
    a.overlay.shutdown().await;
    a.transport.shutdown().await;
    b.transport.shutdown().await;
}

#[tokio::test]
async fn failure_detection_marks_peer_failed() {
    let cluster = Cluster::build(&[10, 20], |idx, _ids, ports| {
        if idx == 0 {
            vec![SeedPeer::new(
                20,
                vec![PeerAddress::new(loopback(ports[1]), TransportKind::Tcp)],
            )]
        } else {
            vec![SeedPeer::new(
                10,
                vec![PeerAddress::new(loopback(ports[0]), TransportKind::Tcp)],
            )]
        }
    })
    .await;

    let a = cluster.node(10);
    let b = cluster.node(20);

    assert!(
        wait_for_full_alive_mesh(&cluster, Duration::from_secs(8)).await,
        "2-node mesh failed to converge"
    );

    let mut events_a = a.overlay.subscribe_membership();

    // Hard-kill B's transport without graceful overlay shutdown.
    b.transport.shutdown().await;

    let mut got_failed = false;
    let until = tokio::time::Instant::now() + Duration::from_secs(15);
    while tokio::time::Instant::now() < until {
        if let Ok(Ok(ev)) = timeout(Duration::from_millis(500), events_a.recv()).await {
            if matches!(ev, MembershipEvent::Failed(20)) {
                got_failed = true;
                break;
            }
        }
    }
    assert!(got_failed, "never saw Failed(20)");
    a.overlay.shutdown().await;
    a.transport.shutdown().await;
}

#[tokio::test]
async fn service_registry_dispatch_unicast() {
    let cluster = Cluster::build(&[1, 2], |idx, _ids, ports| {
        if idx == 0 {
            vec![SeedPeer::new(
                2,
                vec![PeerAddress::new(loopback(ports[1]), TransportKind::Tcp)],
            )]
        } else {
            vec![SeedPeer::new(
                1,
                vec![PeerAddress::new(loopback(ports[0]), TransportKind::Tcp)],
            )]
        }
    })
    .await;

    let a = cluster.node(1);
    let b = cluster.node(2);

    let (tx, mut rx) = mpsc::channel(8);
    b.overlay.register_service(7, Arc::new(Capture(tx)));

    assert!(
        wait_until(Duration::from_secs(10), || a
            .overlay
            .route_to(2, ServiceLevel::Reliable)
            .is_some())
        .await,
        "A never learned a route to B"
    );

    a.overlay
        .send_unicast(
            2,
            7,
            ServiceLevel::Reliable,
            MessageClass::Regular,
            Bytes::from_static(b"hello"),
        )
        .await
        .unwrap();

    let received = timeout(Duration::from_secs(3), rx.recv()).await;
    let msg = received.unwrap().unwrap();
    assert_eq!(msg.from, 1);
    assert_eq!(&msg.body[..], b"hello");
    assert_eq!(msg.level, ServiceLevel::Reliable);

    cluster.shutdown_all().await;
}

#[tokio::test]
async fn broadcast_reaches_all_members() {
    let cluster = Cluster::build(&[1, 2, 3], full_mesh_seeds).await;

    let a = cluster.node(1);
    let b = cluster.node(2);
    let c = cluster.node(3);

    let (tx_b, mut rx_b) = mpsc::channel(8);
    let (tx_c, mut rx_c) = mpsc::channel(8);
    b.overlay.register_service(11, Arc::new(Capture(tx_b)));
    c.overlay.register_service(11, Arc::new(Capture(tx_c)));

    assert!(
        wait_for_full_alive_mesh(&cluster, Duration::from_secs(15)).await,
        "3-node mesh failed to converge"
    );
    assert!(
        wait_for_full_routing(&cluster, Duration::from_secs(10)).await,
        "routing tables did not include all peers"
    );

    a.overlay
        .send_broadcast(
            11,
            ServiceLevel::Reliable,
            MessageClass::Regular,
            Bytes::from_static(b"bcast"),
        )
        .await
        .unwrap();

    let got_b = timeout(Duration::from_secs(3), rx_b.recv()).await.unwrap();
    let got_c = timeout(Duration::from_secs(3), rx_c.recv()).await.unwrap();
    assert_eq!(&got_b.unwrap().body[..], b"bcast");
    assert_eq!(&got_c.unwrap().body[..], b"bcast");

    cluster.shutdown_all().await;
}

// ---------------------------------------------------------------------------
// Phase-2 advanced scenarios (5)
// ---------------------------------------------------------------------------

/// Ten-node full mesh: every node seeds every other; verify all converge
/// on the same membership view, all routing tables are populated, and a
/// broadcast from one node reaches the other nine.
#[tokio::test]
async fn ten_node_full_mesh_converges_and_broadcasts() {
    let ids: Vec<u16> = (1..=10).collect();
    let cluster = Cluster::build(&ids, full_mesh_seeds).await;

    // Register a service on every node so a broadcast hits everyone.
    let mut receivers: Vec<(u16, mpsc::Receiver<_>)> = Vec::new();
    for n in &cluster.nodes {
        if n.id == 1 {
            continue;
        }
        let (tx, rx) = mpsc::channel(16);
        n.overlay.register_service(42, Arc::new(Capture(tx)));
        receivers.push((n.id, rx));
    }

    assert!(
        wait_for_full_alive_mesh(&cluster, Duration::from_secs(30)).await,
        "10-node mesh did not converge: node 1 sees {:?}",
        cluster.node(1).overlay.alive_members()
    );
    assert!(
        wait_for_full_routing(&cluster, Duration::from_secs(15)).await,
        "10-node routing tables did not converge"
    );

    let sender = cluster.node(1);
    sender
        .overlay
        .send_broadcast(
            42,
            ServiceLevel::Reliable,
            MessageClass::Regular,
            Bytes::from_static(b"hi-everyone"),
        )
        .await
        .unwrap();

    for (id, mut rx) in receivers {
        let got = timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("node {id} never received broadcast"))
            .expect("rx closed");
        assert_eq!(&got.body[..], b"hi-everyone", "node {id} got wrong body");
        assert_eq!(got.from, 1, "node {id} got wrong source");
    }

    cluster.shutdown_all().await;
}

/// 3-node ring (A↔B, B↔C, A↔C) with a redundant direct A↔C link. After
/// killing the A↔C link bidirectionally, A's routing must converge onto
/// the A→B→C path within a few seconds, and unicast from A to C still
/// succeeds.
#[tokio::test]
async fn link_down_reroutes() {
    let cluster = Cluster::build(&[1, 2, 3], full_mesh_seeds).await;

    let a = cluster.node(1);
    let b = cluster.node(2);
    let c = cluster.node(3);

    let (tx_c, mut rx_c) = mpsc::channel(8);
    c.overlay.register_service(99, Arc::new(Capture(tx_c)));

    assert!(
        wait_for_full_alive_mesh(&cluster, Duration::from_secs(15)).await,
        "ring failed to converge"
    );
    assert!(
        wait_for_full_routing(&cluster, Duration::from_secs(10)).await,
        "routing did not include all peers"
    );

    // Initially, A's route to C is the direct link.
    assert_eq!(
        a.overlay.route_to(3, ServiceLevel::Reliable),
        Some(3),
        "expected A→C direct"
    );

    // Kill A↔C bidirectionally at the chaos layer.
    a.chaos.block(3);
    c.chaos.block(1);

    // Within ~1.5 × hello_dead_interval, A should mark C down as direct
    // neighbor, then re-emit an LSA missing the A→C edge. Routing then
    // recomputes to A→B→C.
    assert!(
        wait_until(Duration::from_secs(8), || a
            .overlay
            .route_to(3, ServiceLevel::Reliable)
            == Some(2))
        .await,
        "A did not reroute via B; current next-hop = {:?}",
        a.overlay.route_to(3, ServiceLevel::Reliable)
    );

    a.overlay
        .send_unicast(
            3,
            99,
            ServiceLevel::Reliable,
            MessageClass::Regular,
            Bytes::from_static(b"via-b"),
        )
        .await
        .unwrap();

    let got = timeout(Duration::from_secs(3), rx_c.recv()).await.unwrap();
    let m = got.unwrap();
    assert_eq!(&m.body[..], b"via-b");
    assert_eq!(m.from, 1);

    cluster.shutdown_all().await;
}

/// Restart B (same node id, new boot_epoch). A must observe
/// `MembershipEvent::Restarted(B)` faster than waiting for the next LSA
/// to flood — Hello carries the boot_epoch directly.
#[tokio::test]
async fn restart_detection_via_hello() {
    install_provider_once();
    // Keep the PKI alive across the B restart by minting once and
    // building two transports against the same cert/key pair.
    let pki = mint_pki(&[1, 2]);
    let port_a = pick_free_port().await;
    let port_b = pick_free_port().await;

    let seed_b = SeedPeer::new(
        2,
        vec![PeerAddress::new(loopback(port_b), TransportKind::Tcp)],
    );
    let seed_a = SeedPeer::new(
        1,
        vec![PeerAddress::new(loopback(port_a), TransportKind::Tcp)],
    );

    let (transport_a, inbound_a) =
        ConnectionManager::start(transport_cfg(&pki, 0, loopback(port_a)))
            .await
            .unwrap();
    let overlay_a = OverlayNetwork::start(transport_a.clone(), inbound_a, overlay_cfg(vec![seed_b]))
        .await
        .unwrap();

    {
        let (transport_b1, inbound_b1) =
            ConnectionManager::start(transport_cfg(&pki, 1, loopback(port_b)))
                .await
                .unwrap();
        let overlay_b1 =
            OverlayNetwork::start(transport_b1.clone(), inbound_b1, overlay_cfg(vec![seed_a.clone()]))
                .await
                .unwrap();

        // Wait for A to see B alive.
        assert!(
            wait_until(Duration::from_secs(8), || overlay_a
                .alive_members()
                .contains(&2))
            .await,
            "A never saw B alive (initial)"
        );

        // Tear B down quickly without graceful shutdown so A still has
        // B's last boot_epoch in its NeighborMonitor when the new B
        // appears (the monitor purges entries only after dead × 4).
        transport_b1.shutdown().await;
        drop(overlay_b1);
    }

    // Subscribe BEFORE starting B' so we don't race the Restarted event.
    let mut events_a = overlay_a.subscribe_membership();

    // Bring up a fresh B at the same listen address. SystemTime advances
    // monotonically, so the new boot_epoch is strictly greater.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (transport_b2, inbound_b2) =
        ConnectionManager::start(transport_cfg(&pki, 1, loopback(port_b)))
            .await
            .unwrap();
    let overlay_b2 = OverlayNetwork::start(transport_b2.clone(), inbound_b2, overlay_cfg(vec![seed_a]))
        .await
        .unwrap();

    let mut got_restarted = false;
    let until = tokio::time::Instant::now() + Duration::from_secs(8);
    while tokio::time::Instant::now() < until {
        if let Ok(Ok(ev)) = timeout(Duration::from_millis(500), events_a.recv()).await {
            if matches!(ev, MembershipEvent::Restarted(2)) {
                got_restarted = true;
                break;
            }
        }
    }
    assert!(got_restarted, "never saw Restarted(2)");

    overlay_a.shutdown().await;
    overlay_b2.shutdown().await;
    transport_a.shutdown().await;
    transport_b2.shutdown().await;
}

/// Partition {1,2} from {3,4}, let each side's view of the other age out,
/// then heal. The link-up watcher issues a full LsdbSync pull that
/// repopulates each side's LSDB; `Joined` events fire for the recovered
/// members.
#[tokio::test]
async fn partition_heal_sync() {
    let cluster = Cluster::build(&[1, 2, 3, 4], full_mesh_seeds).await;

    assert!(
        wait_for_full_alive_mesh(&cluster, Duration::from_secs(15)).await,
        "4-node mesh failed to converge"
    );

    let mut events_1 = cluster.node(1).overlay.subscribe_membership();

    // Partition.
    cluster.partition(&[1, 2], &[3, 4]);

    // Wait until node 1 no longer sees 3 and 4 (LSAs age out at lsa_max_age = 5s).
    assert!(
        wait_until(Duration::from_secs(15), || {
            let alive = cluster.node(1).overlay.alive_members();
            !alive.contains(&3) && !alive.contains(&4)
        })
        .await,
        "node 1 never lost sight of nodes 3,4 after partition: {:?}",
        cluster.node(1).overlay.alive_members()
    );

    // Drain residual events so we only assert on post-heal Joined/Restarted.
    while events_1.try_recv().is_ok() {}

    // Heal.
    cluster.heal_partition(&[1, 2], &[3, 4]);

    // Within hello_interval + dead_interval + sync_round_trip we should
    // see node 1 learn 3 and 4 again. Restarted(n) is also acceptable in
    // place of Joined(n) — the NeighborMonitor still has prev_be > 0 if
    // the entry wasn't purged.
    let mut joined = std::collections::HashSet::<u16>::new();
    let until = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < until && joined.len() < 2 {
        if let Ok(Ok(ev)) = timeout(Duration::from_millis(500), events_1.recv()).await {
            match ev {
                MembershipEvent::Joined(n) | MembershipEvent::Restarted(n) if n == 3 || n == 4 => {
                    joined.insert(n);
                }
                _ => {}
            }
        }
        // Even if events are missed, polling alive_members works.
        let alive: std::collections::HashSet<u16> =
            cluster.node(1).overlay.alive_members().into_iter().collect();
        if alive.contains(&3) {
            joined.insert(3);
        }
        if alive.contains(&4) {
            joined.insert(4);
        }
    }
    assert!(
        joined.contains(&3) && joined.contains(&4),
        "partition heal did not repopulate: joined = {:?}, alive_at_1 = {:?}",
        joined,
        cluster.node(1).overlay.alive_members()
    );

    cluster.shutdown_all().await;
}

/// 3-node line A-B-C where C drops the first several LsaFlood frames
/// from B. With anti-entropy on a tight cadence, C still learns A's LSA
/// well before the lsa_refresh_interval would deliver it.
#[tokio::test]
async fn anti_entropy_repairs_lost_lsa() {
    // Tighter anti-entropy so the test is fast; longer refresh so flood
    // alone is not enough.
    let cluster = Cluster::build_with_cfg(
        &[1, 2, 3],
        line_seeds,
        |_idx, base| {
            base.with_anti_entropy_interval(Duration::from_millis(150))
                .with_lsa_refresh_interval(Duration::from_secs(8))
        },
    )
    .await;

    let a = cluster.node(1);
    let b = cluster.node(2);
    let c = cluster.node(3);

    // Drop the first 5 LsaFloods from B at C — enough to clobber the
    // initial flood-based delivery of A's LSA. Anti-entropy must fill
    // the gap.
    c.chaos.drop_next_of_type_from(2, MessageType::LsaFlood, 5);

    // Wait for A↔B and B↔C to settle (Hellos are not blocked).
    assert!(
        wait_until(Duration::from_secs(8), || b
            .overlay
            .alive_members()
            .contains(&1)
            && b.overlay.alive_members().contains(&3))
        .await,
        "B never saw both A and C as direct neighbors"
    );

    // C must learn A only via anti-entropy (since flooded LSAs from B
    // are dropped). lsa_refresh_interval is 8s; anti_entropy is 150ms.
    // We give it 4s to converge — well under the refresh-fallback path.
    let learned = wait_until(Duration::from_secs(4), || {
        c.overlay.alive_members().contains(&1)
    })
    .await;
    assert!(
        learned,
        "C never learned A via anti-entropy: alive = {:?}",
        c.overlay.alive_members()
    );

    // Sanity: A also learns C (the chaos was C-side only).
    assert!(
        a.overlay.alive_members().contains(&3),
        "A never saw C: alive = {:?}",
        a.overlay.alive_members()
    );

    cluster.shutdown_all().await;
}
