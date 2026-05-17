//! End-to-end replication scenarios over a real overlay.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use tokio::time::timeout;

use super::super::config::ReplicationConfig;
use super::super::error::ReplicationError;
use super::super::proto::{self as repl_proto, OwnerBody, OwnerOp, REPLICATION_SERVICE_TAG};
use super::super::test_support::{CountingOwnerRepo, CountingStrictRepo};
use super::super::topic::{InboundBody, InboundFrame};
use super::super::{OwnerReplicable, StrictReplicable};
use super::harness::ReplCluster;
use crate::s2s::testing::chaos::MessageType;
use crate::s2s::testing::{wait_for_full_routing, wait_until};
use crate::s2s::transport::{MessageClass, ServiceLevel};

/// Checks strict replication convergence with sequential proposers.
/// Expected: three replicas converge to the same total-ordered 15-operation
/// log. The replicated channel/state operations carry Mumble/shitspeak
/// semantics from `D:\mumble\src\murmur\Messages.cpp` and
/// `D:\shitspeak\message.go`; the strict total order is this crate's S2S
/// replication contract.
#[tokio::test]
async fn strict_three_node_convergence() {
    let cluster = ReplCluster::build_full_mesh(&[1, 2, 3]).await;
    let repos: Vec<Arc<CountingStrictRepo>> = (0..3).map(|_| CountingStrictRepo::new()).collect();
    let mut handles = Vec::new();
    for (i, repo) in repos.iter().enumerate() {
        handles.push(
            cluster
                .register_strict(i, "channels", repo.clone())
                .unwrap(),
        );
    }
    // Give the topic registration a beat to settle (catchup bootstrap is
    // a no-op here since every repo is empty).
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Each node proposes 5 ops, distinguishable by origin.
    for (i, h) in handles.iter().enumerate() {
        let base = (i as u64) * 100;
        for k in 0..5 {
            timeout(Duration::from_secs(5), h.propose(base + k))
                .await
                .expect("propose timeout")
                .expect("propose result");
        }
    }

    let ok = wait_until(Duration::from_secs(10), || {
        repos.iter().all(|r| r.current_version() == 15)
    })
    .await;
    assert!(ok, "all nodes must reach version 15");

    // Assert the (version, op) sequence is identical across replicas.
    let log0 = repos[0].log();
    for r in &repos[1..] {
        assert_eq!(r.log(), log0, "replicas diverged on total order");
    }
    cluster.shutdown().await;
}

/// Checks strict replication with concurrent proposers.
/// Expected: all replicas converge to version 20 with the same interleaving,
/// despite A and B proposing concurrently. Mumble/shitspeak define the state
/// being replicated; this crate defines the S2S total-order protocol.
#[tokio::test]
async fn strict_concurrent_proposers_total_order() {
    let cluster = ReplCluster::build_full_mesh(&[10, 20, 30]).await;
    let repos: Vec<Arc<CountingStrictRepo>> = (0..3).map(|_| CountingStrictRepo::new()).collect();
    let mut handles = Vec::new();
    for (i, repo) in repos.iter().enumerate() {
        handles.push(
            cluster
                .register_strict(i, "channels", repo.clone())
                .unwrap(),
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let h_a = handles[0].clone();
    let h_b = handles[1].clone();
    let task_a = tokio::spawn(async move {
        for k in 0..10u64 {
            h_a.propose(1000 + k).await.unwrap();
        }
    });
    let task_b = tokio::spawn(async move {
        for k in 0..10u64 {
            h_b.propose(2000 + k).await.unwrap();
        }
    });
    task_a.await.unwrap();
    task_b.await.unwrap();

    let ok = wait_until(Duration::from_secs(15), || {
        repos.iter().all(|r| r.current_version() == 20)
    })
    .await;
    assert!(ok, "all nodes must reach version 20");

    let log0 = repos[0].log();
    for r in &repos[1..] {
        assert_eq!(
            r.log(),
            log0,
            "concurrent proposers must converge to identical interleaving"
        );
    }
    cluster.shutdown().await;
}

/// Checks strict-replication catchup for a late-joining topic.
/// Expected: after C is partitioned while A and B reach version 10, C heals,
/// registers the topic, pulls the full log, and matches A's log. This is this
/// crate's S2S catchup behavior for replicated Mumble/shitspeak state.
#[tokio::test]
async fn strict_late_join_catches_up_via_log() {
    use std::collections::HashSet;
    let cluster = ReplCluster::build_full_mesh(&[1, 2, 3]).await;

    // Partition C from {A, B} so A and B's `alive_members` drops C.
    cluster.cluster.partition(&[1, 2], &[3]);
    // Wait for the LSDB to age C out (lsa_max_age = 5s in the harness).
    let ok = wait_until(Duration::from_secs(8), || {
        let a: HashSet<u16> = cluster.cluster.nodes[0]
            .overlay
            .alive_members()
            .into_iter()
            .collect();
        let b: HashSet<u16> = cluster.cluster.nodes[1]
            .overlay
            .alive_members()
            .into_iter()
            .collect();
        !a.contains(&3) && !b.contains(&3)
    })
    .await;
    assert!(ok, "A and B must drop C from alive after partition");

    let repo_a = CountingStrictRepo::new();
    let repo_b = CountingStrictRepo::new();
    let h_a = cluster
        .register_strict(0, "channels", repo_a.clone())
        .unwrap();
    let h_b = cluster
        .register_strict(1, "channels", repo_b.clone())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    for k in 0..5u64 {
        h_a.propose(1000 + k).await.unwrap();
    }
    for k in 0..5u64 {
        h_b.propose(2000 + k).await.unwrap();
    }
    let ok = wait_until(Duration::from_secs(5), || {
        repo_a.current_version() == 10 && repo_b.current_version() == 10
    })
    .await;
    assert!(ok, "A and B must reach version 10 before C joins");

    // Heal partition; wait for C to come back into alive view.
    cluster.cluster.heal_partition(&[1, 2], &[3]);
    let ok = wait_until(Duration::from_secs(5), || {
        let c: HashSet<u16> = cluster.cluster.nodes[2]
            .overlay
            .alive_members()
            .into_iter()
            .collect();
        c.contains(&1) && c.contains(&2)
    })
    .await;
    assert!(ok, "C must see A and B as alive after heal");

    // Now register on C — catchup_bootstrap fires with current_version=0.
    let repo_c = CountingStrictRepo::new();
    let _h_c = cluster
        .register_strict(2, "channels", repo_c.clone())
        .unwrap();

    let ok = wait_until(Duration::from_secs(10), || repo_c.current_version() == 10).await;
    assert!(ok, "late join must catch up to version 10");
    assert_eq!(
        repo_c.log(),
        repo_a.log(),
        "late-joined replica must have identical log to peers"
    );
    cluster.shutdown().await;
}

/// Checks owner-mode replication from one owner to remote replicas.
/// Expected: B and C apply A's ten operations, record `(epoch_a, 10)`, and
/// match A's applied log. The owner-mode data model distributes local
/// Mumble/shitspeak state such as clients; the S2S owner log is local to this
/// crate.
#[tokio::test]
async fn owner_three_node_replication() {
    let cluster = ReplCluster::build_full_mesh(&[1, 2, 3]).await;
    let epoch_a = cluster.cluster.nodes[0].overlay.local_boot_epoch();

    let repos: Vec<Arc<CountingOwnerRepo>> = (0..3).map(|_| CountingOwnerRepo::new()).collect();
    let mut handles = Vec::new();
    for (i, repo) in repos.iter().enumerate() {
        handles.push(cluster.register_owner(i, "clients", repo.clone()).unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let h_a = handles[0].clone();
    for k in 0..10u64 {
        h_a.propose(500 + k).await.unwrap();
    }

    let ok = wait_until(Duration::from_secs(10), || {
        repos[1].applied_for(1).len() == 10 && repos[2].applied_for(1).len() == 10
    })
    .await;
    assert!(ok, "B and C must converge to A's 10 ops");

    // Each replica records (epoch_a, 10).
    let known_b = repos[1].known_versions();
    let known_c = repos[2].known_versions();
    assert_eq!(known_b.get(&1), Some(&(epoch_a, 10)));
    assert_eq!(known_c.get(&1), Some(&(epoch_a, 10)));

    // Replicas' applied logs match A's.
    let log_a = repos[0].applied_for(1);
    assert_eq!(repos[1].applied_for(1), log_a);
    assert_eq!(repos[2].applied_for(1), log_a);
    cluster.shutdown().await;
}

/// Checks owner-mode catchup for a late remote replica.
/// Expected: after A registers late and B proposes one more operation, A
/// detects the gap, pulls the missing owner log, and records `(epoch_b, 6)`.
/// This is this crate's S2S catchup behavior for owner-scoped Mumble/shitspeak
/// state.
#[tokio::test]
async fn owner_late_join_catches_up_via_log() {
    let cluster = ReplCluster::build_full_mesh(&[5, 6]).await;
    let epoch_b = cluster.cluster.nodes[1].overlay.local_boot_epoch();
    let repo_b = CountingOwnerRepo::new();
    let h_b = cluster
        .register_owner(1, "clients", repo_b.clone())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    for k in 0..5u64 {
        h_b.propose(700 + k).await.unwrap();
    }
    let ok = wait_until(Duration::from_secs(5), || repo_b.applied_for(6).len() == 5).await;
    assert!(ok, "owner B must apply its own 5 ops");

    // Register on A late: we get nothing automatically because owner
    // catchup is reactive — only `OwnerOp` arrivals or membership-driven
    // catchup hooks fire it. So have B propose one more op after A
    // registers; A should detect a gap and pull the missing 5 + 1.
    let repo_a = CountingOwnerRepo::new();
    let _h_a = cluster
        .register_owner(0, "clients", repo_a.clone())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    h_b.propose(999u64).await.unwrap();

    let ok = wait_until(Duration::from_secs(10), || repo_a.applied_for(6).len() == 6).await;
    assert!(ok, "late-joined replica must converge to all 6 ops");
    let known_a = repo_a.known_versions();
    assert_eq!(known_a.get(&6), Some(&(epoch_b, 6)));
    cluster.shutdown().await;
}

// ---------------------------------------------------------------------------
// Deferred scenarios from the previous milestone — now enabled.
// ---------------------------------------------------------------------------

/// Checks strict-replication quorum loss during a partition.
/// Expected: a proposal that still targets four nodes loses quorum after the
/// {1,2}|{3,4} partition is detected and returns `ReplicationError::QuorumLost`.
/// Mumble/shitspeak do not define distributed quorum; this is this crate's S2S
/// safety rule for replicated Mumble/shitspeak state.
#[tokio::test]
async fn strict_quorum_lost_on_partition() {
    let cluster = ReplCluster::build_full_mesh(&[1, 2, 3, 4]).await;
    let repos: Vec<Arc<CountingStrictRepo>> = (0..4).map(|_| CountingStrictRepo::new()).collect();
    let mut handles = Vec::new();
    for (i, repo) in repos.iter().enumerate() {
        handles.push(
            cluster
                .register_strict(i, "channels", repo.clone())
                .unwrap(),
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Block all inbound from 3,4 on node 1 (and symmetrically on node 2)
    // BEFORE proposing. Acks from 3,4 will be dropped at node 1; Hellos
    // also stop, so dead-detect will fire `Failed(3)` and `Failed(4)`
    // within ~hello_dead_interval seconds.
    cluster.cluster.partition(&[1, 2], &[3, 4]);

    // Propose immediately — alive_members on node 1 is still {1,2,3,4}.
    let h0 = handles[0].clone();
    let task = tokio::spawn(async move { h0.propose(7777u64).await });

    let res = timeout(Duration::from_secs(20), task)
        .await
        .expect("propose task hung")
        .expect("propose task panicked");
    assert!(
        matches!(res, Err(ReplicationError::QuorumLost)),
        "expected QuorumLost, got {:?}",
        res
    );

    cluster.shutdown().await;
}

/// Checks strict-replication behavior when a quorum never forms but membership
/// remains alive.
/// Expected: the coordinator receives only its self-ack plus one peer ack, so
/// fast quorum is never reached and the proposal resolves with
/// `ReplicationError::ProposeTimeout` instead of hanging or panicking.
#[tokio::test]
async fn strict_quorum_never_forms_times_out() {
    let cfg = ReplicationConfig::default()
        .with_delivery_tick_interval(Duration::from_millis(25))
        .with_propose_ttl(Duration::from_millis(500))
        .with_pending_propose_ttl(Duration::from_secs(2));
    let cluster = ReplCluster::build_full_mesh_with_config(&[1, 2, 3, 4], cfg.clone()).await;
    let repos: Vec<Arc<CountingStrictRepo>> = (0..4).map(|_| CountingStrictRepo::new()).collect();
    let mut handles = Vec::new();
    for (i, repo) in repos.iter().enumerate() {
        handles.push(
            cluster
                .register_strict(i, "channels", repo.clone())
                .unwrap(),
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    cluster
        .cluster
        .node(1)
        .chaos
        .drop_next_of_type_from(3, MessageType::StrictProposeAck, 1);
    cluster
        .cluster
        .node(1)
        .chaos
        .drop_next_of_type_from(4, MessageType::StrictProposeAck, 1);

    let h0 = handles[0].clone();
    let task = tokio::spawn(async move { h0.propose(6666u64).await });

    let res = timeout(Duration::from_secs(5), task)
        .await
        .expect("propose task hung while quorum never formed")
        .expect("propose task panicked while quorum never formed");
    assert!(
        matches!(res, Err(ReplicationError::ProposeTimeout(d)) if d == cfg.propose_ttl()),
        "expected ProposeTimeout({:?}), got {:?}",
        cfg.propose_ttl(),
        res
    );
    assert!(
        repos.iter().all(|r| r.current_version() == 0),
        "no replica should apply an uncommitted operation: versions = {:?}",
        repos
            .iter()
            .map(|r| r.current_version())
            .collect::<Vec<_>>()
    );
    assert!(
        wait_for_full_routing(&cluster.cluster, Duration::from_secs(2)).await,
        "membership/routing should remain healthy; only quorum acks were lost"
    );

    cluster.shutdown().await;
}

/// Checks strict replication when a target node is actually stopped.
/// Expected: a proposal started while the stale alive set still includes the
/// stopped node completes with the surviving fast quorum; the task does not
/// panic or hang while sends to the unreachable node fail underneath.
#[tokio::test]
async fn strict_unreachable_node_during_replication_survives() {
    let cluster = ReplCluster::build_full_mesh(&[1, 2, 3, 4]).await;
    let repos: Vec<Arc<CountingStrictRepo>> = (0..4).map(|_| CountingStrictRepo::new()).collect();
    let mut handles = Vec::new();
    for (i, repo) in repos.iter().enumerate() {
        handles.push(
            cluster
                .register_strict(i, "channels", repo.clone())
                .unwrap(),
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    cluster.managers[3].shutdown().await;
    cluster.cluster.nodes[3].shutdown().await;

    let h0 = handles[0].clone();
    let task = tokio::spawn(async move { h0.propose(8888u64).await });

    let version = timeout(Duration::from_secs(20), task)
        .await
        .expect("propose task hung after node became unreachable")
        .expect("propose task panicked after node became unreachable")
        .expect("surviving fast quorum should commit despite one unreachable target");
    assert_eq!(version, 1);

    let ok = wait_until(Duration::from_secs(5), || {
        repos[..3].iter().all(|r| r.current_version() == 1)
    })
    .await;
    assert!(ok, "surviving replicas should receive the committed op");
    assert_eq!(repos[3].current_version(), 0);

    for m in &cluster.managers[..3] {
        m.shutdown().await;
    }
    for n in &cluster.cluster.nodes[..3] {
        n.shutdown().await;
    }
}

/// Checks strict replication while direct cross-node links fail in a hostile,
/// randomly shaped but deterministic network.
/// Expected: each proposal routes around detected transient link cuts; no
/// proposal task panics or hangs, and every replica has the same total-ordered
/// log after each hostile-network round.
#[tokio::test]
async fn strict_replication_survives_random_cross_node_link_failures() {
    let node_ids: Vec<u16> = (1..=7).collect();
    let cluster = ReplCluster::build_full_mesh(&node_ids).await;
    let repos: Vec<Arc<CountingStrictRepo>> =
        node_ids.iter().map(|_| CountingStrictRepo::new()).collect();
    let mut handles = Vec::new();
    for (i, repo) in repos.iter().enumerate() {
        handles.push(
            cluster
                .register_strict(i, "channels", repo.clone())
                .unwrap(),
        );
    }
    for node in &cluster.cluster.nodes {
        node.chaos.set_jitter(Some(Duration::from_millis(40)));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let is_backbone = |a: u16, b: u16| {
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        hi == lo + 1 || (lo == 1 && hi == 7)
    };

    let mut rng = SmallRng::seed_from_u64(0x52_32_52_4f_42_55_53_54);
    let mut blocked_pairs = Vec::new();
    for round in 0..10u64 {
        while blocked_pairs.len() < 5 {
            let a = rng.gen_range(1..=7);
            let mut b = rng.gen_range(1..=7);
            while b == a {
                b = rng.gen_range(1..=7);
            }
            let pair = if a < b { (a, b) } else { (b, a) };
            if is_backbone(pair.0, pair.1) || blocked_pairs.contains(&pair) {
                continue;
            }
            cluster.cluster.node(pair.0).chaos.block(pair.1);
            cluster.cluster.node(pair.1).chaos.block(pair.0);
            blocked_pairs.push(pair);
        }

        assert!(
            wait_until(Duration::from_secs(15), || blocked_pairs.iter().all(
                |&(a, b)| {
                    let a_route = cluster
                        .cluster
                        .node(a)
                        .overlay
                        .route_to(b, ServiceLevel::Reliable);
                    let b_route = cluster
                        .cluster
                        .node(b)
                        .overlay
                        .route_to(a, ServiceLevel::Reliable);
                    matches!(a_route, Some(next) if next != b)
                        && matches!(b_route, Some(next) if next != a)
                }
            ))
            .await,
            "routing did not move off failed direct links: {:?}",
            blocked_pairs
        );
        assert!(
            wait_for_full_routing(&cluster.cluster, Duration::from_secs(10)).await,
            "routing did not converge while hostile links were failing"
        );

        let proposer = rng.gen_range(0..handles.len());
        let handle = handles[proposer].clone();
        let expected_version = round + 1;
        let task = tokio::spawn(async move { handle.propose(9000 + round).await });
        let version = timeout(Duration::from_secs(30), task)
            .await
            .expect("proposal hung while cross-node links were failing")
            .expect("proposal task panicked while cross-node links were failing")
            .expect("strict replication should route around hostile link failures");
        assert_eq!(version, expected_version);

        let ok = wait_until(Duration::from_secs(15), || {
            repos
                .iter()
                .all(|r| r.current_version() == expected_version)
        })
        .await;
        assert!(
            ok,
            "replicas did not converge after round {round}: versions = {:?}",
            repos
                .iter()
                .map(|r| r.current_version())
                .collect::<Vec<_>>()
        );

        for (a, b) in blocked_pairs.drain(..) {
            cluster.cluster.node(a).chaos.unblock(b);
            cluster.cluster.node(b).chaos.unblock(a);
        }
        assert!(
            wait_for_full_routing(&cluster.cluster, Duration::from_secs(15)).await,
            "routing did not converge after hostile links healed"
        );
    }

    let log0 = repos[0].log();
    for r in &repos[1..] {
        assert_eq!(r.log(), log0, "replicas diverged under hostile links");
    }

    cluster.shutdown().await;
}

/// Checks that owner-mode rejects forged local-origin operations.
/// Expected: B drops an `OwnerOp` sent by C but claiming B's origin, applies no
/// operation, and emits a warning trace. This is this crate's S2S integrity
/// rule for owner-scoped state derived from Mumble/shitspeak server state.
#[tokio::test]
#[tracing_test::traced_test]
async fn owner_remote_propose_dropped_with_warntrace() {
    let cluster = ReplCluster::build_full_mesh(&[1, 2, 3]).await;
    let repo_b = CountingOwnerRepo::new();
    let _h_b = cluster
        .register_owner(1, "clients", repo_b.clone())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Build the forged frame on C's side: OwnerOp{origin=B, ...}.
    let b_id = cluster.cluster.nodes[1].overlay.local_node_id();
    let b_epoch = cluster.cluster.nodes[1].overlay.local_boot_epoch();
    let op_msgpack = Bytes::from(rmp_serde::to_vec(&123u64).unwrap());
    let body = OwnerBody::Op(OwnerOp {
        origin_node: b_id as u32,
        origin_epoch: b_epoch,
        origin_version: 1,
        op_msgpack,
    });
    let msg = repl_proto::wrap_owner("clients", body);
    let bytes = repl_proto::encode(&msg).unwrap();

    cluster.cluster.nodes[2]
        .overlay
        .send_unicast(
            b_id,
            REPLICATION_SERVICE_TAG,
            ServiceLevel::Reliable,
            MessageClass::Regular,
            bytes,
        )
        .await
        .unwrap();

    // Give B's dispatch a beat to receive + drop.
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        repo_b.applied_for(b_id).is_empty(),
        "B applied a forged op: {:?}",
        repo_b.applied_for(b_id)
    );
    assert!(
        logs_contain("owner op claims local origin from foreign sender"),
        "warn trace missing"
    );

    cluster.shutdown().await;
}

/// Checks owner-mode gap detection and catchup.
/// Expected: when A drops B's version 2 operation, receiving version 3 triggers
/// catchup and A eventually applies all five B operations. This is this crate's
/// S2S repair behavior for owner-scoped Mumble/shitspeak state.
#[tokio::test]
async fn owner_gap_triggers_catchup() {
    let cluster = ReplCluster::build_full_mesh(&[1, 2, 3]).await;
    let repos: Vec<Arc<CountingOwnerRepo>> = (0..3).map(|_| CountingOwnerRepo::new()).collect();
    let mut handles = Vec::new();
    for (i, repo) in repos.iter().enumerate() {
        handles.push(cluster.register_owner(i, "clients", repo.clone()).unwrap());
    }

    // A's manager: drop ANY OwnerOp for origin = B's id, version = 2.
    let b_id = cluster.cluster.nodes[1].overlay.local_node_id();
    cluster.managers[0].set_inbound_filter(move |frame: &InboundFrame| {
        if let InboundBody::Owner(OwnerBody::Op(op)) = &frame.body {
            if (op.origin_node as u16) == b_id && op.origin_version == 2 {
                return false; // drop
            }
        }
        true
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let h_b = handles[1].clone();
    for k in 0..5u64 {
        h_b.propose(2000 + k).await.unwrap();
    }

    let ok = wait_until(Duration::from_secs(10), || {
        repos[0].applied_for(b_id).len() == 5
    })
    .await;
    assert!(
        ok,
        "A never converged via catchup: applied_for(B) = {:?}",
        repos[0].applied_for(b_id)
    );
    cluster.shutdown().await;
}
