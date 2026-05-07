//! End-to-end replication scenarios over a real overlay.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::time::timeout;

use super::super::error::ReplicationError;
use super::super::proto::{
    self as repl_proto, OwnerBody, OwnerOp, REPLICATION_SERVICE_TAG,
};
use super::super::test_support::{CountingOwnerRepo, CountingStrictRepo};
use super::super::topic::{InboundBody, InboundFrame};
use super::super::{OwnerReplicable, StrictReplicable};
use super::harness::ReplCluster;
use crate::s2s::testing::wait_until;
use crate::s2s::transport::{MessageClass, ServiceLevel};

/// 3 nodes; each proposes 5 ops; assert all replicas converge to the
/// same total-ordered log of length 15.
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

/// 3 nodes; A and B propose concurrently in tight loops; assert all
/// replicas converge to the SAME interleaving (Tempo total order).
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

/// 3-node cluster: partition C off, register the topic + propose between
/// A and B, then heal and register on C — its catchup bootstrap should
/// pull the entire log from a peer.
///
/// Note: per the plan, this exercises `spawn_catchup_bootstrap`. Late
/// join with C participating from the start would block A/B's proposals
/// (C is in `target_set` but has no topic to ack with), so we use the
/// existing partition primitive in the harness to ensure A and B see only
/// each other as alive while proposing.
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
    let h_a = cluster.register_strict(0, "channels", repo_a.clone()).unwrap();
    let h_b = cluster.register_strict(1, "channels", repo_b.clone()).unwrap();
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
    let _h_c = cluster.register_strict(2, "channels", repo_c.clone()).unwrap();

    let ok = wait_until(Duration::from_secs(10), || repo_c.current_version() == 10).await;
    assert!(ok, "late join must catch up to version 10");
    assert_eq!(
        repo_c.log(),
        repo_a.log(),
        "late-joined replica must have identical log to peers"
    );
    cluster.shutdown().await;
}

/// 3-node cluster: A is the owner. A proposes 10 ops; assert B and C
/// converge to `(epoch_a, 10)` for origin A and have the same applied
/// log.
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

/// 2 nodes: B is owner, A is a remote replica. B proposes; A applies.
/// Then we register the topic on A late, so A's catchup pulls from B.
#[tokio::test]
async fn owner_late_join_catches_up_via_log() {
    let cluster = ReplCluster::build_full_mesh(&[5, 6]).await;
    let epoch_b = cluster.cluster.nodes[1].overlay.local_boot_epoch();
    let repo_b = CountingOwnerRepo::new();
    let h_b = cluster.register_owner(1, "clients", repo_b.clone()).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    for k in 0..5u64 {
        h_b.propose(700 + k).await.unwrap();
    }
    let ok = wait_until(Duration::from_secs(5), || {
        repo_b.applied_for(6).len() == 5
    })
    .await;
    assert!(ok, "owner B must apply its own 5 ops");

    // Register on A late: we get nothing automatically because owner
    // catchup is reactive — only `OwnerOp` arrivals or membership-driven
    // catchup hooks fire it. So have B propose one more op after A
    // registers; A should detect a gap and pull the missing 5 + 1.
    let repo_a = CountingOwnerRepo::new();
    let _h_a = cluster.register_owner(0, "clients", repo_a.clone()).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    h_b.propose(999u64).await.unwrap();

    let ok = wait_until(Duration::from_secs(10), || {
        repo_a.applied_for(6).len() == 6
    })
    .await;
    assert!(ok, "late-joined replica must converge to all 6 ops");
    let known_a = repo_a.known_versions();
    assert_eq!(known_a.get(&6), Some(&(epoch_b, 6)));
    cluster.shutdown().await;
}

// ---------------------------------------------------------------------------
// Deferred scenarios from the previous milestone — now enabled.
// ---------------------------------------------------------------------------

/// 4-node mesh, fast-quorum = 3. We install a partition chaos block of
/// {1,2}|{3,4} BEFORE proposing so acks from 3,4 never reach the proposer
/// (they're dropped at node 1's inbound chaos), but node 1's `alive_members`
/// snapshot at propose-time still includes 3,4 (Hello dead-detect hasn't
/// fired yet) so `target_set = {1,2,3,4}, fq = 3`. Once Failed events for
/// 3,4 arrive, `on_membership_change` fires `QuorumLost` (still=2 < fq=3).
/// Recovery cannot help the proposer because its own coord (= itself) is
/// alive on the {1,2} side.
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

/// Node C forges an `OwnerOp` claiming origin = B and sends it to B over
/// the real overlay. B's runtime must drop the op (apply count stays
/// zero) AND emit a warn-trace.
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

/// 3-node owner-mode cluster. A's manager has a `ForwardingShim`-style
/// inbound filter that drops `OwnerOp{origin=B, version=2}`. B proposes
/// 5 ops; A is missing version 2 from the natural broadcast, detects the
/// gap on receiving version 3, fires `OwnerCatchupReq`, and converges.
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
