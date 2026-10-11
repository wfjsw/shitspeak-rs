//! Replay of the 2026-10-04 duplicate-identity incident against live state.
//!
//! A node booted with another node's certificate. Its boot epoch was newer, so
//! every peer treated it as a restart of that node id and fenced the real
//! owner — a block that outlived the impostor because it is persisted in the
//! LSDB floor. The real node stayed out of strict replication until it was
//! restarted by hand.
//!
//! This replays that shape using production channel state pulled over SSH:
//!
//! 1. Nodes 1, 2 and 4 come up from their captured repositories and converge.
//! 2. A second process claims node 2's certificate with a later boot epoch.
//! 3. The peers fence the real node 2 — the reported symptom.
//! 4. The impostor goes away and node 2 recovers on its own.
//!
//! Captured state is staged by [`TestStrictReplicationState`], the same helper
//! the other strict-live scenarios use.
//!
//! ## Running
//!
//! ```text
//! SHITSPEAK_STRICT_LIVE_STATE_ROOT=D:/shitspeak-rs/tmp/dup-identity-20261004 \
//!   cargo test -p shitspeak-runtime --lib -- --ignored strict_identity_incident
//! ```
//!
//! The root holds `node-<id>/{channels.snapshot.json,channels.wal.jsonl,
//! terminal-channels.sqlite3}` per node, produced by
//! `tmp/capture-dup-identity-state.py`.

use std::sync::Arc;
use std::time::Duration;

use shitspeak_runtime_config::{S2sConfig, S2sSeedAddressConfig, S2sTransportKindConfig};
use shitspeak_s2s::testing::{
    Pki, install_provider_once, loopback, mint_pki, pick_free_port, s2s_network_test_guard,
    wait_until,
};

use crate::integration_tests::harness::test_server::{
    TestServer, TestServerOpts, TestStrictReplicationState, spawn_s2s_test_server_with_state,
};

/// How long a node may take to converge on copied production state.
const CONVERGENCE: Duration = Duration::from_secs(120);
/// How long recovery may take after the impostor leaves.
///
/// The guard debounces for several seconds before acting. In the variant
/// where peers quarantine the duplicated node id they also drop all of its
/// messages, so the owner sees no fence notice until the duplicate-detection
/// window (about two minutes) expires and its advertisements are rejected
/// against the persisted floor again. Recovery is still automatic, just
/// slower in that case.
const RECOVERY: Duration = Duration::from_secs(300);

fn fixture_root() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("SHITSPEAK_STRICT_LIVE_STATE_ROOT")
            .expect("SHITSPEAK_STRICT_LIVE_STATE_ROOT is required"),
    )
}

fn s2s_config(listen: std::net::SocketAddr, peers: &[std::net::SocketAddr]) -> S2sConfig {
    S2sConfig {
        enabled: true,
        tcp_listen: vec![listen],
        tcp_advertise: vec![listen.to_string()],
        seed_addresses: peers
            .iter()
            .copied()
            .filter(|address| *address != listen)
            .map(|address| S2sSeedAddressConfig::new(S2sTransportKindConfig::Tcp, address))
            .collect(),
        ..S2sConfig::default()
    }
}

fn local_boot_epoch(server: &TestServer) -> u64 {
    server
        .server
        .s2s_manager()
        .overlay()
        .map(|overlay| overlay.local_boot_epoch())
        .unwrap_or(0)
}

fn peer_view_of(server: &TestServer, node: u16) -> Option<u64> {
    server
        .server
        .s2s_manager()
        .overlay()
        .and_then(|overlay| overlay.member(node))
        .map(|member| member.boot_epoch())
}

/// The reported symptom and its automatic repair, replayed from live state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs SHITSPEAK_STRICT_LIVE_STATE_ROOT with captured production state"]
async fn duplicate_identity_incident_fences_then_recovers_automatically() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let root = fixture_root();

    // Certificates for the real nodes. Node 2's cert is deliberately reused by
    // the impostor below — that is exactly what happened.
    let pki: Arc<Pki> = Arc::new(mint_pki(&[1, 2, 4]));
    let mut ports = Vec::new();
    for _ in 0..3 {
        ports.push(pick_free_port().await);
    }
    let listen = |index: usize| loopback(ports[index]);
    let all: Vec<std::net::SocketAddr> = ports.iter().map(|port| loopback(*port)).collect();

    // 1. Real nodes come up from their captured repositories.
    let node1 = spawn_s2s_test_server_with_state(
        TestServerOpts::default(),
        Arc::clone(&pki),
        1,
        0,
        s2s_config(listen(0), &all),
        TestStrictReplicationState::from_directory(root.join("node-1")),
    )
    .await;
    let node2 = spawn_s2s_test_server_with_state(
        TestServerOpts::default(),
        Arc::clone(&pki),
        2,
        1,
        s2s_config(listen(1), &all),
        TestStrictReplicationState::from_directory(root.join("node-2")),
    )
    .await;
    let node4 = spawn_s2s_test_server_with_state(
        TestServerOpts::default(),
        Arc::clone(&pki),
        4,
        2,
        s2s_config(listen(2), &all),
        TestStrictReplicationState::from_directory(root.join("node-4")),
    )
    .await;

    let converged = wait_until(CONVERGENCE, || {
        [&node1, &node2, &node4].iter().all(|server| {
            let manager = server.server.s2s_manager();
            manager.application().is_some()
                && manager.replications().as_ref().is_some_and(|replications| {
                    replications.strict_capability_activation_ready()
                })
                && [1u16, 2, 4]
                    .iter()
                    .all(|peer| manager.overlay().is_some_and(|o| o.alive_members().contains(peer)))
        })
    })
    .await;
    assert!(converged, "copied-state nodes did not converge");

    let real_epoch = local_boot_epoch(&node2);
    assert!(real_epoch > 0, "node 2 never captured a boot epoch");

    // 2. Requirement 1: a node running the current code must refuse to boot
    //    when the identity is already live on the overlay. Its overlay should
    //    never come up at all.
    let impostor_port = pick_free_port().await;
    let refused = spawn_s2s_test_server_with_state(
        TestServerOpts::default(),
        Arc::clone(&pki),
        2,
        1, // node 2's certificate, exactly as the incident had it
        s2s_config(loopback(impostor_port), &all),
        TestStrictReplicationState::from_directory(root.join("node-2")),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(15)).await;
    assert_eq!(
        local_boot_epoch(&refused),
        0,
        "a duplicate must be refused while the real node 2 is live on the overlay"
    );
    refused.shutdown_gracefully().await;

    // 3. Now replay the incident itself: a node that predates duplicate
    //    detection slips in. It claims the same certificate with a later boot
    //    epoch, and the peers fence the real node 2 at that epoch.
    shitspeak_s2s::overlay::emulate_legacy_identity_preflight(true);
    let impostor_port = pick_free_port().await;
    let impostor = spawn_s2s_test_server_with_state(
        TestServerOpts::default(),
        Arc::clone(&pki),
        2,
        1,
        s2s_config(loopback(impostor_port), &all),
        TestStrictReplicationState::from_directory(root.join("node-2")),
    )
    .await;
    // The impostor's preflight runs asynchronously after spawn, so the
    // emulation must stay armed until its overlay is actually up.
    let impostor_up = wait_until(CONVERGENCE, || local_boot_epoch(&impostor) > 0).await;
    shitspeak_s2s::overlay::emulate_legacy_identity_preflight(false);
    assert!(impostor_up, "the impostor never started its overlay");
    let impostor_epoch = local_boot_epoch(&impostor);
    assert!(
        impostor_epoch > real_epoch,
        "the impostor must outrank the real node: {impostor_epoch} vs {real_epoch}"
    );

    // The reported symptom: the real node 2 stops being the node the peers
    // see. Depending on how the two live incarnations interleave, a peer
    // either pins the impostor's higher epoch or quarantines the id outright
    // and drops it — both leave the real node fenced out.
    let fenced = wait_until(CONVERGENCE, || {
        [&node1, &node4]
            .iter()
            .all(|server| peer_view_of(server, 2) != Some(real_epoch))
    })
    .await;
    assert!(
        fenced,
        "peers never fenced the real node 2: node1={:?} node4={:?}",
        peer_view_of(&node1, 2),
        peer_view_of(&node4, 2)
    );

    // 4. The impostor goes away. The real node must recover on its own: mint a
    //    higher epoch and be re-adopted, with no manual restart.
    impostor.shutdown_gracefully().await;

    let recovered = wait_until(RECOVERY, || {
        local_boot_epoch(&node2) > impostor_epoch
    })
    .await;
    assert!(
        recovered,
        "node 2 never re-incarnated above the impostor's epoch: {} vs {impostor_epoch}",
        local_boot_epoch(&node2)
    );
    let new_epoch = local_boot_epoch(&node2);
    assert!(new_epoch > impostor_epoch);

    let re_adopted = wait_until(CONVERGENCE, || {
        [&node1, &node4]
            .iter()
            .all(|server| peer_view_of(server, 2) == Some(new_epoch))
    })
    .await;
    assert!(
        re_adopted,
        "peers never adopted the recovered epoch: node1={:?} node4={:?}",
        peer_view_of(&node1, 2),
        peer_view_of(&node4, 2)
    );

    node4.shutdown_gracefully().await;
    node2.shutdown_gracefully().await;
    node1.shutdown_gracefully().await;
}

/// A clean replay must not trip the recovery path at all: with no impostor,
/// node 2 keeps the epoch it booted with.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs SHITSPEAK_STRICT_LIVE_STATE_ROOT with captured production state"]
async fn duplicate_identity_free_replay_keeps_the_original_epoch() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let root = fixture_root();

    let pki: Arc<Pki> = Arc::new(mint_pki(&[1, 2]));
    let a_port = pick_free_port().await;
    let b_port = pick_free_port().await;
    let all = [loopback(a_port), loopback(b_port)];

    let node1 = spawn_s2s_test_server_with_state(
        TestServerOpts::default(),
        Arc::clone(&pki),
        1,
        0,
        s2s_config(all[0], &all),
        TestStrictReplicationState::from_directory(root.join("node-1")),
    )
    .await;
    let node2 = spawn_s2s_test_server_with_state(
        TestServerOpts::default(),
        pki,
        2,
        1,
        s2s_config(all[1], &all),
        TestStrictReplicationState::from_directory(root.join("node-2")),
    )
    .await;

    let converged = wait_until(CONVERGENCE, || {
        node1
            .server
            .s2s_manager()
            .overlay()
            .is_some_and(|o| o.alive_members().contains(&2))
            && node2
                .server
                .s2s_manager()
                .overlay()
                .is_some_and(|o| o.alive_members().contains(&1))
    })
    .await;
    assert!(converged, "the pair did not converge");

    let epoch = local_boot_epoch(&node2);
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        local_boot_epoch(&node2),
        epoch,
        "node 2 must not re-incarnate when no impostor exists"
    );
    assert_eq!(peer_view_of(&node1, 2), Some(epoch));

    node2.shutdown_gracefully().await;
    node1.shutdown_gracefully().await;
}