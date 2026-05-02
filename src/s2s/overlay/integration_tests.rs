//! Phase-1 end-to-end smoke tests for the overlay network.
//!
//! Each test brings up two `OverlayNetwork` instances (each on top of its
//! own real `ConnectionManager`) and verifies a single membership behavior.
//! TLS material is minted into a tempdir per test using `rcgen`, mirroring
//! the pattern from `s2s::transport::integration_tests`.

use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::s2s::transport::{
    ConnectionManager, Inbound, PeerAddress, TransportConfig, TransportKind,
};

use super::config::{OverlayConfig, SeedPeer};
use super::membership::MembershipEvent;
use super::OverlayNetwork;

fn install_provider_once() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

struct Pki {
    _dir: TempDir,
    ca_path: PathBuf,
    nodes: Vec<(PathBuf, PathBuf)>,
}

fn mint_pki(node_cns: &[u16]) -> Pki {
    let dir = TempDir::new().unwrap();
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec!["s2s-overlay-test-ca".into()]).unwrap();
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "s2s-overlay-test-ca");
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert: Certificate = ca_params.self_signed(&ca_key).unwrap();

    let ca_path = dir.path().join("ca.pem");
    File::create(&ca_path)
        .unwrap()
        .write_all(ca_cert.pem().as_bytes())
        .unwrap();

    let mut nodes = Vec::new();
    for cn in node_cns {
        let node_key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![format!("node-{cn}")]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn.to_string());
        p.distinguished_name = dn;
        let node_cert = p.signed_by(&node_key, &ca_cert, &ca_key).unwrap();

        let cert_path = dir.path().join(format!("cert-{cn}.pem"));
        let key_path = dir.path().join(format!("key-{cn}.pem"));
        File::create(&cert_path)
            .unwrap()
            .write_all(node_cert.pem().as_bytes())
            .unwrap();
        File::create(&key_path)
            .unwrap()
            .write_all(node_key.serialize_pem().as_bytes())
            .unwrap();
        nodes.push((cert_path, key_path));
    }

    Pki { _dir: dir, ca_path, nodes }
}

fn transport_cfg(pki: &Pki, node_idx: usize, tcp: SocketAddr) -> TransportConfig {
    let (cert, key) = &pki.nodes[node_idx];
    TransportConfig::new(pki.ca_path.clone(), cert.clone(), key.clone())
        .with_tcp_listen(tcp)
        .with_reconnect_check_interval(Duration::from_millis(100))
        .with_backoff_initial(Duration::from_millis(50))
        .with_backoff_cap(Duration::from_millis(500))
        .with_ping_interval(Duration::from_secs(10)) // disable bandwidth probe for these tests
        .with_bandwidth_probe_size(0)
}

fn overlay_cfg(seeds: Vec<SeedPeer>) -> OverlayConfig {
    OverlayConfig::new(seeds)
        .with_swim_ping_interval(Duration::from_millis(200))
        .with_swim_indirect_ping_count(2)
        .with_swim_suspicion_timeout(Duration::from_millis(800))
        .with_swim_dead_timeout(Duration::from_secs(2))
        .with_gossip_piggyback_max(8)
        .with_peer_persistence_interval(Duration::from_secs(1))
}

fn loopback(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

async fn pick_free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// Helper: start a transport then an overlay over it. Returns both halves.
async fn start_node(
    pki: &Pki,
    node_idx: usize,
    listen_port: u16,
    seeds: Vec<SeedPeer>,
) -> (ConnectionManager, OverlayNetwork) {
    let t_cfg = transport_cfg(pki, node_idx, loopback(listen_port));
    let (transport, inbound) = ConnectionManager::start(t_cfg).await.unwrap();
    let o_cfg = overlay_cfg(seeds);
    let overlay = OverlayNetwork::start(transport.clone(), inbound, o_cfg)
        .await
        .unwrap();
    (transport, overlay)
}

/// Insert a chaos filter between the transport's inbound channel and the
/// overlay dispatcher. Frames whose source node ID is in `blocked` are
/// silently dropped; everything else is forwarded unchanged.
///
/// This lets a test simulate a one-directional network partition at the
/// overlay-message level without touching the real TCP stack.
fn intercept_inbound(real: Inbound, blocked: Arc<Mutex<HashSet<u16>>>) -> Inbound {
    let (high_tx, high_rx) = mpsc::channel(512);
    let (reg_tx, reg_rx) = mpsc::channel(512);
    let (mut real_high, mut real_reg) = real.into_parts();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = real_high.recv() => {
                    let Some(m) = msg else { return };
                    if !blocked.lock().unwrap().contains(&m.from()) {
                        let _ = high_tx.send(m).await;
                    }
                }
                msg = real_reg.recv() => {
                    let Some(m) = msg else { return };
                    if !blocked.lock().unwrap().contains(&m.from()) {
                        let _ = reg_tx.send(m).await;
                    }
                }
            }
        }
    });
    Inbound::new(high_rx, reg_rx)
}

/// Wait for `predicate(members)` to hold, polling every 100ms up to deadline.
async fn wait_for_members<F: Fn(&[super::MemberSnapshot]) -> bool>(
    overlay: &OverlayNetwork,
    deadline: Duration,
    predicate: F,
) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if predicate(&overlay.members()) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
async fn two_node_mesh_forms() {
    install_provider_once();
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

    let (_t_a, overlay_a) = start_node(&pki, 0, port_a, vec![seed_b]).await;
    let (_t_b, overlay_b) = start_node(&pki, 1, port_b, vec![seed_a]).await;

    assert_eq!(overlay_a.local_node_id(), 1);
    assert_eq!(overlay_b.local_node_id(), 2);

    // Each side knows of the other and sees them Alive within 5s.
    let a_sees_b = wait_for_members(&overlay_a, Duration::from_secs(5), |members| {
        members
            .iter()
            .any(|m| m.node_id() == 2 && m.status() == super::MemberStatus::Alive)
    })
    .await;
    let b_sees_a = wait_for_members(&overlay_b, Duration::from_secs(5), |members| {
        members
            .iter()
            .any(|m| m.node_id() == 1 && m.status() == super::MemberStatus::Alive)
    })
    .await;

    assert!(a_sees_b, "A never saw B as Alive: {:?}", overlay_a.members());
    assert!(b_sees_a, "B never saw A as Alive: {:?}", overlay_b.members());

    overlay_a.shutdown().await;
    overlay_b.shutdown().await;
}

#[tokio::test]
async fn failure_detection_marks_peer_failed() {
    install_provider_once();
    let pki = mint_pki(&[10, 20]);
    let port_a = pick_free_port().await;
    let port_b = pick_free_port().await;

    let seed_b = SeedPeer::new(
        20,
        vec![PeerAddress::new(loopback(port_b), TransportKind::Tcp)],
    );
    let seed_a = SeedPeer::new(
        10,
        vec![PeerAddress::new(loopback(port_a), TransportKind::Tcp)],
    );

    let (_t_a, overlay_a) = start_node(&pki, 0, port_a, vec![seed_b]).await;
    let (transport_b, overlay_b) = start_node(&pki, 1, port_b, vec![seed_a]).await;

    // Wait for the link to come up and B to be Alive on A's side.
    assert!(
        wait_for_members(&overlay_a, Duration::from_secs(5), |m| m
            .iter()
            .any(|x| x.node_id() == 20 && x.status() == super::MemberStatus::Alive))
            .await,
        "B never went Alive on A"
    );

    let mut events_a = overlay_a.subscribe_membership();

    // Hard-kill B's transport (no graceful overlay shutdown -> no LEFT).
    transport_b.shutdown().await;
    drop(overlay_b);

    // Within suspicion + dead timeout we should see a Failed event for B.
    let deadline = Duration::from_secs(8);
    let mut got_failed = false;
    let until = tokio::time::Instant::now() + deadline;
    while tokio::time::Instant::now() < until {
        if let Ok(Ok(ev)) = timeout(Duration::from_millis(500), events_a.recv()).await {
            if matches!(ev, MembershipEvent::Failed(20)) {
                got_failed = true;
                break;
            }
        }
    }
    assert!(got_failed, "never saw Failed(20)");

    overlay_a.shutdown().await;
}

#[tokio::test]
async fn graceful_shutdown_emits_left() {
    install_provider_once();
    let pki = mint_pki(&[100, 200]);
    let port_a = pick_free_port().await;
    let port_b = pick_free_port().await;

    let seed_b = SeedPeer::new(
        200,
        vec![PeerAddress::new(loopback(port_b), TransportKind::Tcp)],
    );
    let seed_a = SeedPeer::new(
        100,
        vec![PeerAddress::new(loopback(port_a), TransportKind::Tcp)],
    );

    let (_t_a, overlay_a) = start_node(&pki, 0, port_a, vec![seed_b]).await;
    let (_t_b, overlay_b) = start_node(&pki, 1, port_b, vec![seed_a]).await;

    assert!(
        wait_for_members(&overlay_a, Duration::from_secs(5), |m| m
            .iter()
            .any(|x| x.node_id() == 200 && x.status() == super::MemberStatus::Alive))
            .await,
        "B never went Alive on A"
    );

    let mut events_a = overlay_a.subscribe_membership();

    // Graceful overlay shutdown — broadcasts LEFT before tearing down.
    overlay_b.shutdown().await;

    // Within ~3 ping intervals, A should see Left(200).
    let deadline = Duration::from_secs(3);
    let mut got_left = false;
    let until = tokio::time::Instant::now() + deadline;
    while tokio::time::Instant::now() < until {
        if let Ok(Ok(ev)) = timeout(Duration::from_millis(300), events_a.recv()).await {
            if matches!(ev, MembershipEvent::Left(200)) {
                got_left = true;
                break;
            }
        }
    }
    assert!(got_left, "never saw Left(200)");

    overlay_a.shutdown().await;
}

// ── Suboptimal-network condition tests ─────────────────────────────────────

/// Three-node cluster where A only seeds B and C only seeds B. A and C must
/// discover each other exclusively through gossip piggybacked on their
/// respective exchanges with B — there is no direct seed link between them.
///
/// This exercises gossip address propagation: when B's ack to A carries C's
/// record (including C's address), A learns C's address, adds it to the
/// transport layer, and can subsequently probe C directly.
#[tokio::test]
async fn three_node_gossip_propagation() {
    install_provider_once();
    let pki = mint_pki(&[1, 2, 3]);

    let port_a = pick_free_port().await;
    let port_b = pick_free_port().await;
    let port_c = pick_free_port().await;

    let peer_a = SeedPeer::new(1, vec![PeerAddress::new(loopback(port_a), TransportKind::Tcp)]);
    let peer_b = SeedPeer::new(2, vec![PeerAddress::new(loopback(port_b), TransportKind::Tcp)]);
    let peer_c = SeedPeer::new(3, vec![PeerAddress::new(loopback(port_c), TransportKind::Tcp)]);

    // Topology: A ← B → C.  A and C have no direct seed for each other.
    let (_t_a, overlay_a) = start_node(&pki, 0, port_a, vec![peer_b.clone()]).await;
    let (_t_b, overlay_b) = start_node(&pki, 1, port_b, vec![peer_a, peer_c.clone()]).await;
    let (_t_c, overlay_c) = start_node(&pki, 2, port_c, vec![peer_b]).await;

    let deadline = Duration::from_secs(8);

    // A must see both B (direct) and C (via gossip) as Alive.
    let a_ok = wait_for_members(&overlay_a, deadline, |m| {
        m.iter().any(|x| x.node_id() == 2 && x.status() == super::MemberStatus::Alive)
            && m.iter().any(|x| x.node_id() == 3 && x.status() == super::MemberStatus::Alive)
    })
    .await;

    // C must see both B (direct) and A (via gossip) as Alive.
    let c_ok = wait_for_members(&overlay_c, deadline, |m| {
        m.iter().any(|x| x.node_id() == 1 && x.status() == super::MemberStatus::Alive)
            && m.iter().any(|x| x.node_id() == 2 && x.status() == super::MemberStatus::Alive)
    })
    .await;

    assert!(a_ok, "A never learned C via gossip: {:?}", overlay_a.members());
    assert!(c_ok, "C never learned A via gossip: {:?}", overlay_c.members());

    overlay_a.shutdown().await;
    overlay_b.shutdown().await;
    overlay_c.shutdown().await;
}

/// Hard-crash a node then restart it on the same port. The overlay's incarnation
/// is seeded from wall-clock nanoseconds on startup, so the restarted node's
/// incarnation is strictly greater than the value recorded in A's Dead entry.
/// The higher incarnation must win the merge and produce a `Joined` event,
/// proving that a crashed node can re-enter a cluster without manual operator
/// intervention.
#[tokio::test]
async fn crashed_node_rejoins_with_higher_incarnation() {
    install_provider_once();
    let pki = mint_pki(&[1, 2]);

    let port_a = pick_free_port().await;
    let port_b = pick_free_port().await;

    let peer_a = SeedPeer::new(1, vec![PeerAddress::new(loopback(port_a), TransportKind::Tcp)]);
    let peer_b = SeedPeer::new(2, vec![PeerAddress::new(loopback(port_b), TransportKind::Tcp)]);

    let (_t_a, overlay_a) = start_node(&pki, 0, port_a, vec![peer_b]).await;
    let (transport_b, overlay_b) = start_node(&pki, 1, port_b, vec![peer_a.clone()]).await;

    assert!(
        wait_for_members(&overlay_a, Duration::from_secs(5), |m| {
            m.iter().any(|x| x.node_id() == 2 && x.status() == super::MemberStatus::Alive)
        })
        .await,
        "B never became Alive on A"
    );
    let first_incarnation = overlay_a.member(2).unwrap().incarnation();

    let mut events_a = overlay_a.subscribe_membership();

    // Hard-crash B — no graceful leave, so A must detect the failure through
    // SWIM probe timeouts.
    transport_b.shutdown().await;
    drop(overlay_b);

    let until = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut got_failed = false;
    while tokio::time::Instant::now() < until {
        if let Ok(Ok(ev)) = timeout(Duration::from_millis(500), events_a.recv()).await {
            if matches!(ev, MembershipEvent::Failed(2)) {
                got_failed = true;
                break;
            }
        }
    }
    assert!(got_failed, "A never saw Failed(2) after hard crash");

    // Give the OS a moment to release port_b before we rebind.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Restart B on the same port with the same TLS identity. Its incarnation
    // is wall-clock seeded, so it is strictly greater than first_incarnation.
    let (_t_b2, overlay_b2) = start_node(&pki, 1, port_b, vec![peer_a]).await;

    let until2 = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut got_joined = false;
    while tokio::time::Instant::now() < until2 {
        if let Ok(Ok(ev)) = timeout(Duration::from_millis(500), events_a.recv()).await {
            if matches!(ev, MembershipEvent::Joined(2)) {
                got_joined = true;
                break;
            }
        }
    }
    assert!(got_joined, "A never saw Joined(2) after B restarted");

    let new_incarnation = overlay_a.member(2).unwrap().incarnation();
    assert!(
        new_incarnation > first_incarnation,
        "rejoin incarnation {new_incarnation} must exceed first-lifetime incarnation \
         {first_incarnation}"
    );

    overlay_a.shutdown().await;
    overlay_b2.shutdown().await;
}

/// Kill two of three cluster nodes simultaneously. The survivor must detect
/// both failures even though it has no alive indirect-probe helpers (all
/// potential helpers are also dead). This exercises the fallthrough path in
/// the SWIM ticker where `indirect_probe` returns false immediately because
/// `pick_alive_random` yields an empty set, relying solely on the suspicion
/// timer to drain Suspect → Dead.
#[tokio::test]
async fn simultaneous_dual_failure_both_detected() {
    install_provider_once();
    let pki = mint_pki(&[1, 2, 3]);

    let port_a = pick_free_port().await;
    let port_b = pick_free_port().await;
    let port_c = pick_free_port().await;

    let peer_a = SeedPeer::new(1, vec![PeerAddress::new(loopback(port_a), TransportKind::Tcp)]);
    let peer_b = SeedPeer::new(2, vec![PeerAddress::new(loopback(port_b), TransportKind::Tcp)]);
    let peer_c = SeedPeer::new(3, vec![PeerAddress::new(loopback(port_c), TransportKind::Tcp)]);

    // Fully-connected seeds so the mesh forms quickly before the failure.
    let (_t_a, overlay_a) =
        start_node(&pki, 0, port_a, vec![peer_b.clone(), peer_c.clone()]).await;
    let (transport_b, overlay_b) =
        start_node(&pki, 1, port_b, vec![peer_a.clone(), peer_c.clone()]).await;
    let (transport_c, overlay_c) =
        start_node(&pki, 2, port_c, vec![peer_a, peer_b]).await;

    assert!(
        wait_for_members(&overlay_a, Duration::from_secs(8), |m| {
            m.iter().any(|x| x.node_id() == 2 && x.status() == super::MemberStatus::Alive)
                && m.iter().any(|x| x.node_id() == 3 && x.status() == super::MemberStatus::Alive)
        })
        .await,
        "A never saw both B and C as Alive"
    );

    let mut events_a = overlay_a.subscribe_membership();

    // Hard-crash B and C concurrently. A is left with no alive indirect-probe
    // helpers and must detect both failures via direct probe timeouts alone.
    transport_b.shutdown().await;
    transport_c.shutdown().await;
    drop(overlay_b);
    drop(overlay_c);

    let until = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut failed_b = false;
    let mut failed_c = false;
    while tokio::time::Instant::now() < until && !(failed_b && failed_c) {
        if let Ok(Ok(ev)) = timeout(Duration::from_millis(300), events_a.recv()).await {
            match ev {
                MembershipEvent::Failed(2) => failed_b = true,
                MembershipEvent::Failed(3) => failed_c = true,
                _ => {}
            }
        }
    }

    assert!(failed_b, "A never detected failure of B (node 2)");
    assert!(failed_c, "A never detected failure of C (node 3)");

    overlay_a.shutdown().await;
}

/// Simulate a one-directional partition at the overlay-message level: A can
/// send pings to C (the TCP stream is intact), but all inbound overlay frames
/// *from* C are intercepted and dropped before they reach A's dispatcher.
///
/// A's direct SWIM probes to C will therefore always time out.  A must fall
/// back to asking B to relay an indirect probe (`SwimPingReq → B → C`).  B's
/// forwarded ack arrives at A with `src_node = B`, so it is *not* blocked by
/// the filter — the indirect path delivers a successful response, A calls
/// `note_ack(C)` and C remains Alive for the duration of the partition.
///
/// After the filter is lifted C must recover to a fully-Alive state, proving
/// that the protocol returns to normal once the partition heals.
#[tokio::test]
async fn indirect_probe_sustains_partitioned_peer() {
    install_provider_once();
    let pki = mint_pki(&[1, 2, 3]);

    let port_a = pick_free_port().await;
    let port_b = pick_free_port().await;
    let port_c = pick_free_port().await;

    let peer_a = SeedPeer::new(1, vec![PeerAddress::new(loopback(port_a), TransportKind::Tcp)]);
    let peer_b = SeedPeer::new(2, vec![PeerAddress::new(loopback(port_b), TransportKind::Tcp)]);
    let peer_c = SeedPeer::new(3, vec![PeerAddress::new(loopback(port_c), TransportKind::Tcp)]);

    // B and C start with no chaos — both are reachable normally.
    let t_cfg_b = transport_cfg(&pki, 1, loopback(port_b));
    let (transport_b, inbound_b) = ConnectionManager::start(t_cfg_b).await.unwrap();
    let overlay_b = OverlayNetwork::start(
        transport_b.clone(),
        inbound_b,
        overlay_cfg(vec![peer_a.clone(), peer_c.clone()]),
    )
    .await
    .unwrap();

    let t_cfg_c = transport_cfg(&pki, 2, loopback(port_c));
    let (transport_c, inbound_c) = ConnectionManager::start(t_cfg_c).await.unwrap();
    let overlay_c = OverlayNetwork::start(
        transport_c.clone(),
        inbound_c,
        overlay_cfg(vec![peer_a.clone(), peer_b.clone()]),
    )
    .await
    .unwrap();

    // A gets a chaos filter we can arm later to drop frames from C.
    let t_cfg_a = transport_cfg(&pki, 0, loopback(port_a));
    let (transport_a, inbound_a) = ConnectionManager::start(t_cfg_a).await.unwrap();
    let blocked: Arc<Mutex<HashSet<u16>>> = Arc::new(Mutex::new(HashSet::new()));
    let filtered_inbound = intercept_inbound(inbound_a, blocked.clone());
    let overlay_a = OverlayNetwork::start(
        transport_a.clone(),
        filtered_inbound,
        overlay_cfg(vec![peer_b, peer_c]),
    )
    .await
    .unwrap();

    // Establish the full mesh before arming the partition.
    assert!(
        wait_for_members(&overlay_a, Duration::from_secs(8), |m| {
            m.iter().any(|x| x.node_id() == 2 && x.status() == super::MemberStatus::Alive)
                && m.iter().any(|x| x.node_id() == 3 && x.status() == super::MemberStatus::Alive)
        })
        .await,
        "mesh never formed before partition test"
    );

    // Arm the partition: A can no longer receive any overlay message from C.
    blocked.lock().unwrap().insert(3);

    // Run ≥ 10 probe cycles while the partition is active. A's direct probes
    // to C all time out; indirect probes via B should keep C Alive (at worst
    // transiently Suspect, but never progressing to Dead).
    tokio::time::sleep(Duration::from_millis(200 * 12)).await;

    let c_status_during = overlay_a
        .member(3)
        .expect("C vanished from A's table")
        .status();
    assert_ne!(
        c_status_during,
        super::MemberStatus::Dead,
        "C went Dead despite indirect probes via B being available: {:?}",
        overlay_a.members()
    );

    // Heal the partition: direct acks from C flow through again.
    blocked.lock().unwrap().remove(&3);

    // C must recover fully to Alive within a few probe cycles.
    assert!(
        wait_for_members(&overlay_a, Duration::from_secs(5), |m| {
            m.iter().any(|x| x.node_id() == 3 && x.status() == super::MemberStatus::Alive)
        })
        .await,
        "C never recovered to Alive after partition healed: {:?}",
        overlay_a.members()
    );

    overlay_a.shutdown().await;
    overlay_b.shutdown().await;
    overlay_c.shutdown().await;
    drop(transport_b);
    drop(transport_c);
    drop(transport_a);
}
