//! End-to-end replication scenarios over a real overlay.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;

use super::harness::ReplCluster;
use shitspeak_s2s::replications::proto::{
    self as repl_proto, OwnerBody, OwnerOp, REPLICATION_SERVICE_TAG,
};
use shitspeak_s2s::replications::strict::{HistoryMetadata, LogSlice, StrictLogEntry};
use shitspeak_s2s::replications::test_support::{CountingOwnerRepo, CountingStrictRepo};
use shitspeak_s2s::replications::{
    OwnerReplicable, ReplicationConfig, ReplicationError, StrictReplicable,
};
use shitspeak_s2s::testing::chaos::MessageType;
use shitspeak_s2s::testing::{wait_for_full_routing, wait_until};
use shitspeak_s2s_transport::{MessageClass, ServiceLevel};
use shitspeak_state::Channel;
use shitspeak_state::{
    ChannelOp, ChannelOperation, ChannelRepoTuning, ChannelRepository, ChannelRootConfig,
};

#[derive(Clone)]
struct TestChannelReplicationAdapter {
    repo: Arc<ChannelRepository>,
}

impl TestChannelReplicationAdapter {
    fn new(repo: Arc<ChannelRepository>) -> Self {
        Self { repo }
    }
}

#[derive(Serialize, Deserialize)]
struct TestChannelSnapshot {
    channels: Vec<Channel>,
    freshness: i64,
}

#[async_trait::async_trait]
impl StrictReplicable for TestChannelReplicationAdapter {
    type Op = ChannelOperation;

    fn current_version(&self) -> u64 {
        self.repo.current_version()
    }

    fn history_metadata(&self) -> HistoryMetadata {
        HistoryMetadata {
            version: self.repo.current_version(),
            freshness: self
                .repo
                .latest_timestamp_in_server(crate::types::DEFAULT_SERVER_ID),
        }
    }

    fn snapshot(&self) -> (u64, Bytes) {
        let version = self.repo.current_version();
        let repo = self.repo.clone();
        let channels =
            block_in_place_or_current(|handle| handle.block_on(repo.get_all())).unwrap_or_default();
        let freshness = self
            .repo
            .latest_timestamp_in_server(crate::types::DEFAULT_SERVER_ID);
        let bytes = Bytes::from(
            rmp_serde::to_vec(&TestChannelSnapshot {
                channels,
                freshness,
            })
            .unwrap_or_default(),
        );
        (version, bytes)
    }

    fn log_since(&self, since: u64) -> LogSlice<StrictLogEntry<Self::Op>> {
        let repo = self.repo.clone();
        let entries =
            block_in_place_or_current(|handle| handle.block_on(repo.get_log_since(since)));
        LogSlice::Available(
            entries
                .unwrap_or_default()
                .into_iter()
                .map(|op| (op.version, StrictLogEntry::new((*op).clone())))
                .collect(),
        )
    }

    async fn apply_committed(&self, version: u64, mut op: Self::Op) {
        op.version = version;
        self.repo.apply_committed_operation(op).await.unwrap();
    }

    async fn install_snapshot(&self, version: u64, snapshot: Bytes) {
        let snapshot: TestChannelSnapshot = rmp_serde::from_slice(&snapshot).unwrap();
        self.repo
            .install_s2s_snapshot(version, snapshot.channels)
            .await
            .unwrap();
    }
}

fn channel_tuning() -> ChannelRepoTuning {
    ChannelRepoTuning {
        log_max_entries: 128,
        snapshot_every_ops: 100,
        snapshot_every_secs: 60,
        wal_compaction_expire_count: 100,
    }
}

async fn wait_for_elected_channel_history(
    repos: &[Arc<ChannelRepository>],
    deadline: Duration,
) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if elected_channel_history_matches(repos).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    elected_channel_history_matches(repos).await
}

async fn elected_channel_history_matches(repos: &[Arc<ChannelRepository>]) -> bool {
    for repo in repos {
        if repo.current_version() != 5 {
            return false;
        }
        let channels = repo.get_all().await;
        let has_channel = |id| channels.iter().any(|channel| channel.id == id);
        if !has_channel(20) || !has_channel(21) || !has_channel(22) || has_channel(30) {
            return false;
        }
    }
    true
}

async fn channel_history_status(repos: &[Arc<ChannelRepository>]) -> Vec<String> {
    let mut out = Vec::with_capacity(repos.len());
    for (idx, repo) in repos.iter().enumerate() {
        let mut channels: Vec<_> = repo
            .get_all()
            .await
            .into_iter()
            .map(|channel| (channel.id, channel.name))
            .collect();
        channels.sort_by_key(|(id, _)| *id);
        out.push(format!(
            "repo{idx}: version={} channels={channels:?}",
            repo.current_version()
        ));
    }
    out
}

fn block_in_place_or_current<T>(f: impl FnOnce(&tokio::runtime::Handle) -> T) -> Option<T> {
    let handle = tokio::runtime::Handle::try_current().ok()?;
    Some(tokio::task::block_in_place(|| f(&handle)))
}

fn channel_create_op(node_id: u16, channel: Channel) -> ChannelOperation {
    ChannelOperation {
        server_id: crate::types::DEFAULT_SERVER_ID.to_owned(),
        version: 0,
        node_id,
        timestamp: chrono::Utc::now().timestamp(),
        emits_client_message: true,
        op: ChannelOp::CreateChannel { channel },
    }
}

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
            timeout(Duration::from_secs(20), h.propose(base + k))
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
/// Expected: all proposals complete and all replicas reach version 21 despite
/// A and B proposing concurrently after a warm-up write. Mumble/shitspeak
/// define the state being replicated; this crate defines the S2S protocol.
#[tokio::test]
async fn strict_concurrent_proposers_total_order() {
    let cfg = ReplicationConfig::default()
        .with_propose_ttl(Duration::from_secs(30))
        .with_pending_propose_ttl(Duration::from_secs(60));
    let cluster = ReplCluster::build_full_mesh_with_config(&[10, 20, 30], cfg).await;
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

    handles[0].propose(999).await.unwrap();
    let warmed = wait_until(Duration::from_secs(10), || {
        repos.iter().all(|r| r.current_version() == 1)
    })
    .await;
    assert!(warmed, "all nodes must apply the warm-up proposal");

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
        repos.iter().all(|r| r.current_version() == 21)
    })
    .await;
    assert!(ok, "all nodes must reach version 21");

    cluster.shutdown().await;
}

/// Checks strict-replication catchup for a late-joining topic.
/// Expected: after C is partitioned while A and B reach version 10, C heals,
/// registers the topic, pulls the full log, and matches A's log. This is this
/// crate's S2S catchup behavior for replicated Mumble/shitspeak state.
#[tokio::test]
async fn strict_late_join_catches_up_via_log() {
    use std::collections::HashSet;
    let cluster = ReplCluster::build_full_mesh_fast_failure(&[1, 2, 3]).await;

    // Partition C from {A, B} so A and B's `alive_members` drops C.
    cluster.cluster.partition(&[1, 2], &[3]);
    // Wait for the LSDB to age C out (lsa_max_age = 5s in this harness).
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
/// Expected: after A registers late, A proactively pulls B's existing owner
/// log without requiring another post-join operation and records `(epoch_b, 5)`.
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

    // Register on A late. Owner runtime startup should proactively request
    // catchup for already-alive origins, without waiting for another op.
    let repo_a = CountingOwnerRepo::new();
    let _h_a = cluster
        .register_owner(0, "clients", repo_a.clone())
        .unwrap();

    let ok = wait_until(Duration::from_secs(10), || repo_a.applied_for(6).len() == 5).await;
    assert!(
        ok,
        "late-joined replica must converge to all 5 existing ops"
    );
    let known_a = repo_a.known_versions();
    assert_eq!(known_a.get(&6), Some(&(epoch_b, 5)));
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
    let cluster = ReplCluster::build_full_mesh_fast_failure(&[1, 2, 3, 4]).await;
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

/// Checks channel repository history election across a real split-heal.
/// Expected: after {1,2}|{3,4} diverge, healing elects the longest/freshest
/// channel history and installs that snapshot on the losing side, removing
/// channels that only existed in the shorter partition history.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strict_channel_repository_split_heal_elects_one_complete_history() {
    let cfg = ReplicationConfig::default()
        .with_delivery_tick_interval(Duration::from_millis(25))
        .with_strict_bootstrap_retry_interval(Duration::from_millis(100));
    let cluster = ReplCluster::build_full_mesh_fast_failure_with_config(&[1, 2, 3, 4], cfg).await;
    let repos: Vec<Arc<ChannelRepository>> = [1u16, 2, 3, 4]
        .into_iter()
        .map(|node_id| {
            ChannelRepository::new_in_memory(
                node_id,
                ChannelRootConfig::new("Root"),
                channel_tuning(),
            )
        })
        .collect();
    let mut handles = Vec::new();
    for (i, repo) in repos.iter().enumerate() {
        handles.push(
            cluster
                .register_strict(
                    i,
                    "channels",
                    Arc::new(TestChannelReplicationAdapter::new(repo.clone())),
                )
                .unwrap(),
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    for channel_id in [10, 11] {
        handles[0]
            .propose(channel_create_op(
                1,
                Channel::new(
                    channel_id,
                    format!("common-{channel_id}"),
                    channel_id as i32,
                    0,
                    Some(0),
                ),
            ))
            .await
            .unwrap();
    }
    let converged = wait_until(Duration::from_secs(10), || {
        repos.iter().all(|repo| repo.current_version() == 2)
    })
    .await;
    assert!(converged, "pre-split common history did not converge");

    cluster.cluster.partition(&[1, 2], &[3, 4]);
    let partitioned = wait_until(Duration::from_secs(10), || {
        let left_ok = [1u16, 2].iter().all(|&node_id| {
            let alive = cluster.cluster.node(node_id).overlay.alive_members();
            !alive.contains(&3) && !alive.contains(&4)
        });
        let right_ok = [3u16, 4].iter().all(|&node_id| {
            let alive = cluster.cluster.node(node_id).overlay.alive_members();
            !alive.contains(&1) && !alive.contains(&2)
        });
        left_ok && right_ok
    })
    .await;
    assert!(partitioned, "partition did not age out of alive views");

    for channel_id in [20, 21, 22] {
        handles[0]
            .propose(channel_create_op(
                1,
                Channel::new(
                    channel_id,
                    format!("left-{channel_id}"),
                    channel_id as i32,
                    0,
                    Some(0),
                ),
            ))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for channel_id in [30] {
        handles[2]
            .propose(channel_create_op(
                3,
                Channel::new(
                    channel_id,
                    format!("right-{channel_id}"),
                    channel_id as i32,
                    0,
                    Some(0),
                ),
            ))
            .await
            .unwrap();
    }

    let divergent = wait_until(Duration::from_secs(10), || {
        repos[0].current_version() == 5
            && repos[1].current_version() == 5
            && repos[2].current_version() == 3
            && repos[3].current_version() == 3
    })
    .await;
    assert!(
        divergent,
        "partition sides did not form divergent histories"
    );

    cluster.cluster.heal_partition(&[1, 2], &[3, 4]);
    assert!(
        wait_for_full_routing(&cluster.cluster, Duration::from_secs(15)).await,
        "routing did not reconverge after partition heal"
    );

    let healed = wait_for_elected_channel_history(&repos, Duration::from_secs(45)).await;
    if !healed {
        panic!(
            "healed cluster did not converge on the elected channel history: {:?}",
            channel_history_status(&repos).await
        );
    }

    let names: Vec<Vec<String>> = repos
        .iter()
        .map(|repo| {
            let mut names = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(repo.get_all())
                    .into_iter()
                    .map(|channel| channel.name)
                    .collect::<Vec<_>>()
            });
            names.sort();
            names
        })
        .collect();
    for names_for_repo in &names[1..] {
        assert_eq!(names_for_repo, &names[0]);
    }

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

    let dropped_ack_attempts =
        ((cfg.propose_ttl().as_nanos() / cfg.delivery_tick_interval().as_nanos()) + 8)
            .min(u128::from(u32::MAX)) as u32;

    cluster.cluster.node(1).chaos.drop_next_of_type_from(
        3,
        MessageType::StrictProposeAck,
        dropped_ack_attempts,
    );
    cluster.cluster.node(1).chaos.drop_next_of_type_from(
        4,
        MessageType::StrictProposeAck,
        dropped_ack_attempts,
    );

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
            let a = rng.random_range(1..=7);
            let mut b = rng.random_range(1..=7);
            while b == a {
                b = rng.random_range(1..=7);
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

        let proposer = rng.random_range(0..handles.len());
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
/// Expected: B receives an `OwnerOp` sent by C but claiming B's origin, then
/// drops it without applying any operation. This is this crate's S2S integrity
/// rule for owner-scoped state derived from Mumble/shitspeak server state.
#[tokio::test]
async fn owner_remote_propose_dropped() {
    let cluster = ReplCluster::build_full_mesh(&[1, 2, 3]).await;
    let repo_b = CountingOwnerRepo::new();
    let _h_b = cluster
        .register_owner(1, "clients", repo_b.clone())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Build the forged frame on C's side: OwnerOp{origin=B, ...}.
    let b_id = cluster.cluster.nodes[1].overlay.local_node_id();
    let b_epoch = cluster.cluster.nodes[1].overlay.local_boot_epoch();
    let saw_forged_frame = Arc::new(AtomicBool::new(false));
    let saw_forged_frame_filter = Arc::clone(&saw_forged_frame);
    cluster.managers[1].set_owner_op_inbound_filter(move |origin_node, origin_version| {
        if origin_node == b_id && origin_version == 1 {
            saw_forged_frame_filter.store(true, Ordering::Relaxed);
        }
        true
    });
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
        saw_forged_frame.load(Ordering::Relaxed),
        "B did not receive the forged owner op"
    );
    assert!(
        repo_b.applied_for(b_id).is_empty(),
        "B applied a forged op: {:?}",
        repo_b.applied_for(b_id)
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
    cluster.managers[0].set_owner_op_inbound_filter(move |origin_node, origin_version| {
        if origin_node == b_id && origin_version == 2 {
            return false;
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
