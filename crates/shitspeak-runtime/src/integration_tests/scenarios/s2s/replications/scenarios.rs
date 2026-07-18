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
use crate::types::StrictReplicationMetadata;
use shitspeak_s2s::overlay::{OverlayNetwork, STRICT_REPLICATION_PROTOCOL_VERSION, SeedPeer};
use shitspeak_s2s::replications::proto::{
    self as repl_proto, OwnerBody, OwnerOp, REPLICATION_SERVICE_TAG,
};
use shitspeak_s2s::replications::strict::{
    HistoryMetadata, LogSlice, StrictCommitApplyOutcome, StrictLogEntry, StrictLogMetadata,
    StrictSnapshotError,
};
use shitspeak_s2s::replications::test_support::{CountingOwnerRepo, CountingStrictRepo};
use shitspeak_s2s::replications::{
    OwnerReplicable, ReplicationConfig, ReplicationError, ReplicationManager, StrictReplicable,
};
use shitspeak_s2s::testing::chaos::{FaultSelector, MessageType};
use shitspeak_s2s::testing::{
    loopback, overlay_cfg, transport_cfg, wait_for_full_routing, wait_until,
};
use shitspeak_s2s_transport::{
    ConnectionManager, MessageClass, PeerAddress, ServiceLevel, TransportKind,
};
use shitspeak_state::Channel;
use shitspeak_state::{
    ChannelOp, ChannelOperation, ChannelRepoTuning, ChannelRepository, ChannelRootConfig,
    StrictOperationApplyOutcome, StrictOperationId,
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
    strict_operation_ids: Vec<StrictOperationId>,
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

    fn strict_replication_protocol_version(&self) -> u32 {
        if self.repo.strict_operation_durability_enabled() {
            STRICT_REPLICATION_PROTOCOL_VERSION
        } else {
            0
        }
    }

    fn snapshot(&self) -> Result<(u64, Bytes), StrictSnapshotError> {
        let repo = self.repo.clone();
        let strict_snapshot = block_in_place_or_current(|handle| {
            handle.block_on(repo.strict_snapshot_in_server(crate::types::DEFAULT_SERVER_ID))
        })
        .ok_or_else(|| StrictSnapshotError::new("channel snapshot capture requires a runtime"))?;
        let (version, channels, freshness, strict_operation_ids) = strict_snapshot.into_parts();
        let bytes = rmp_serde::to_vec(&TestChannelSnapshot {
            channels,
            freshness,
            strict_operation_ids,
        })
        .map(Bytes::from)
        .map_err(|error| {
            StrictSnapshotError::new(format!("channel test snapshot encode failed: {error}"))
        })?;
        Ok((version, bytes))
    }

    fn log_since(&self, since: u64) -> LogSlice<StrictLogEntry<Self::Op>> {
        let repo = self.repo.clone();
        let entries = block_in_place_or_current(|handle| {
            handle.block_on(
                repo.strict_log_entries_since_in_server(crate::types::DEFAULT_SERVER_ID, since),
            )
        });
        match entries.flatten() {
            Some(entries) => LogSlice::Available(
                entries
                    .into_iter()
                    .map(|entry| {
                        let op = entry.op();
                        let log_entry = match entry.strict_metadata() {
                            Some(metadata) => StrictLogEntry::with_metadata(
                                (*op).clone(),
                                StrictLogMetadata {
                                    op_id_hi: metadata.op_id_hi(),
                                    op_id_lo: metadata.op_id_lo(),
                                    ts_final: metadata.ts_final(),
                                },
                            ),
                            None => StrictLogEntry::new((*op).clone()),
                        };
                        (op.version, log_entry)
                    })
                    .collect(),
            ),
            None => LogSlice::TooOld,
        }
    }

    async fn apply_committed(&self, version: u64, mut op: Self::Op) {
        op.version = version;
        self.repo.apply_committed_operation(op).await.unwrap();
    }

    async fn apply_committed_with_metadata(
        &self,
        version: u64,
        op: Self::Op,
        metadata: Option<StrictLogMetadata>,
    ) {
        if let Some(metadata) = metadata {
            let _ = self.apply_committed_once(version, op, metadata).await;
        } else {
            self.apply_committed(version, op).await;
        }
    }

    async fn apply_committed_once(
        &self,
        version: u64,
        mut op: Self::Op,
        metadata: StrictLogMetadata,
    ) -> StrictCommitApplyOutcome {
        op.version = version;
        match self
            .repo
            .apply_strict_operation_once(
                op,
                StrictReplicationMetadata::new(
                    metadata.op_id_hi,
                    metadata.op_id_lo,
                    metadata.ts_final,
                ),
            )
            .await
        {
            Ok(StrictOperationApplyOutcome::Applied) => StrictCommitApplyOutcome::Applied,
            Ok(StrictOperationApplyOutcome::AlreadyApplied) => {
                StrictCommitApplyOutcome::AlreadyApplied
            }
            Ok(StrictOperationApplyOutcome::VersionConflict) | Err(_) => {
                StrictCommitApplyOutcome::Failed
            }
        }
    }

    async fn install_snapshot(
        &self,
        version: u64,
        snapshot: Bytes,
    ) -> Result<(), StrictSnapshotError> {
        let snapshot: TestChannelSnapshot = rmp_serde::from_slice(&snapshot).map_err(|error| {
            StrictSnapshotError::new(format!("channel test snapshot decode failed: {error}"))
        })?;
        self.repo
            .install_s2s_snapshot_with_strict_operation_ids_in_server(
                crate::types::DEFAULT_SERVER_ID,
                version,
                snapshot.channels,
                snapshot.freshness,
                snapshot.strict_operation_ids,
            )
            .await
            .map_err(|error| {
                StrictSnapshotError::new(format!("channel test snapshot install failed: {error}"))
            })?;
        Ok(())
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

async fn wait_for_converged_channel_history(
    repos: &[Arc<ChannelRepository>],
    deadline: Duration,
) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if converged_channel_history_matches(repos).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    converged_channel_history_matches(repos).await
}

async fn converged_channel_history_matches(repos: &[Arc<ChannelRepository>]) -> bool {
    for repo in repos {
        if repo.current_version() != 6 {
            return false;
        }
        let channels = repo.get_all().await;
        let has_channel = |id| channels.iter().any(|channel| channel.id == id);
        if !has_channel(20) || !has_channel(21) || !has_channel(22) || !has_channel(30) {
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

/// A strict repository whose delivery path can be held after the runtime has
/// removed a terminal commit from its buffer. Catch-up capture/install remain
/// live so a healed peer exercises the admission protocol rather than an
/// artificial transport stall.
struct GatedCountingStrictRepo {
    inner: Arc<CountingStrictRepo>,
    delivery_gate: AtomicBool,
    delivery_blocked: AtomicBool,
    delivery_release: tokio::sync::Notify,
}

impl GatedCountingStrictRepo {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: CountingStrictRepo::new(),
            delivery_gate: AtomicBool::new(false),
            delivery_blocked: AtomicBool::new(false),
            delivery_release: tokio::sync::Notify::new(),
        })
    }

    fn block_delivery(&self) {
        self.delivery_gate.store(true, Ordering::Release);
        self.delivery_blocked.store(false, Ordering::Release);
    }

    fn delivery_is_blocked(&self) -> bool {
        self.delivery_blocked.load(Ordering::Acquire)
    }

    fn release_delivery(&self) {
        self.delivery_gate.store(false, Ordering::Release);
        self.delivery_release.notify_waiters();
    }

    fn log(&self) -> Vec<(u64, u64)> {
        self.inner.log()
    }

    async fn wait_for_delivery_release(&self) {
        while self.delivery_gate.load(Ordering::Acquire) {
            let released = self.delivery_release.notified();
            if !self.delivery_gate.load(Ordering::Acquire) {
                break;
            }
            self.delivery_blocked.store(true, Ordering::Release);
            released.await;
        }
    }
}

#[async_trait::async_trait]
impl StrictReplicable for GatedCountingStrictRepo {
    type Op = u64;

    fn strict_replication_protocol_version(&self) -> u32 {
        self.inner.strict_replication_protocol_version()
    }

    fn current_version(&self) -> u64 {
        self.inner.current_version()
    }

    fn history_metadata(&self) -> HistoryMetadata {
        self.inner.history_metadata()
    }

    fn snapshot(&self) -> Result<(u64, Bytes), StrictSnapshotError> {
        self.inner.snapshot()
    }

    fn log_since(&self, since: u64) -> LogSlice<StrictLogEntry<Self::Op>> {
        self.inner.log_since(since)
    }

    async fn apply_committed(&self, version: u64, op: Self::Op) {
        self.wait_for_delivery_release().await;
        self.inner.apply_committed(version, op).await;
    }

    async fn apply_committed_with_metadata(
        &self,
        version: u64,
        op: Self::Op,
        metadata: Option<StrictLogMetadata>,
    ) {
        self.wait_for_delivery_release().await;
        self.inner
            .apply_committed_with_metadata(version, op, metadata)
            .await;
    }

    async fn apply_committed_once(
        &self,
        version: u64,
        op: Self::Op,
        metadata: StrictLogMetadata,
    ) -> StrictCommitApplyOutcome {
        self.wait_for_delivery_release().await;
        self.inner.apply_committed_once(version, op, metadata).await
    }

    async fn install_snapshot(
        &self,
        version: u64,
        snapshot: Bytes,
    ) -> Result<(), StrictSnapshotError> {
        self.inner.install_snapshot(version, snapshot).await
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
            let result = timeout(Duration::from_secs(20), h.propose(base + k)).await;
            if !matches!(result, Ok(Ok(_))) {
                panic!(
                    "propose failed: proposer={i}, op={}, result={result:?}, states={:?}",
                    base + k,
                    handles
                        .iter()
                        .map(|handle| handle.debug_state())
                        .collect::<Vec<_>>()
                );
            }
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

/// Verifies that strict-v2 capability activation is derived from repository
/// registration, rather than an application-maintained capability manifest.
/// A later capable topic must preserve the already-advertised cumulative
/// protocol floor and remain usable for strict replication.
#[tokio::test]
async fn strict_capability_activation_is_automatic_and_floor_stable() {
    let cluster = ReplCluster::build_full_mesh(&[1, 2, 3]).await;
    let channel_repos: Vec<Arc<CountingStrictRepo>> =
        (0..3).map(|_| CountingStrictRepo::new()).collect();

    for (idx, repo) in channel_repos.iter().enumerate() {
        cluster
            .register_strict(idx, "channels", repo.clone())
            .unwrap();
    }

    assert!(
        wait_until(Duration::from_secs(8), || {
            cluster
                .managers
                .iter()
                .all(|manager| manager.strict_capability_activation_ready())
                && strict_protocol_floors(&cluster)
                    .iter()
                    .all(|(_, version)| *version == STRICT_REPLICATION_PROTOCOL_VERSION)
        })
        .await,
        "automatic first-topic registration did not activate the cumulative strict protocol floor: floors={:?}",
        strict_protocol_floors(&cluster),
    );

    let ban_repos: Vec<Arc<CountingStrictRepo>> =
        (0..3).map(|_| CountingStrictRepo::new()).collect();
    let mut ban_handles = Vec::new();
    for (idx, repo) in ban_repos.iter().enumerate() {
        ban_handles.push(cluster.register_strict(idx, "bans", repo.clone()).unwrap());
    }

    assert!(
        wait_until(Duration::from_secs(8), || {
            cluster
                .managers
                .iter()
                .all(|manager| manager.strict_capability_activation_ready())
                && strict_protocol_floors(&cluster)
                    .iter()
                    .all(|(_, version)| *version == STRICT_REPLICATION_PROTOCOL_VERSION)
        })
        .await,
        "later capable topic lowered the cumulative strict protocol floor: floors={:?}",
        strict_protocol_floors(&cluster),
    );

    let version = ban_handles[0].propose(42).await.unwrap();
    assert_eq!(version, 1);
    assert!(
        wait_until(Duration::from_secs(8), || {
            ban_repos
                .iter()
                .all(|repo| repo.current_version() == version)
        })
        .await,
        "later strict topic did not replicate after automatic activation: versions={:?}",
        ban_repos
            .iter()
            .map(|repo| repo.current_version())
            .collect::<Vec<_>>(),
    );

    cluster.shutdown().await;
}

/// Checks strict replication with concurrent proposers.
/// Expected: all proposals complete and all replicas reach version 21 despite
/// A and B proposing concurrently after a warm-up write, with an identical
/// total-order log at every replica. Mumble/shitspeak
/// define the state being replicated; this crate defines the S2S protocol.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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

    let tasks: Vec<_> = [(handles[0].clone(), 1000), (handles[1].clone(), 2000)]
        .into_iter()
        .map(|(handle, base)| {
            (
                base,
                tokio::spawn(async move {
                    for k in 0..10u64 {
                        handle.propose(base + k).await?;
                    }
                    Ok::<(), ReplicationError>(())
                }),
            )
        })
        .collect();
    for (base, task) in tasks {
        let result = timeout(Duration::from_secs(90), task)
            .await
            .expect("concurrent proposer hung")
            .expect("concurrent proposer panicked");
        if let Err(error) = result {
            panic!(
                "concurrent proposer {base} failed: {error:?}, node10={:?}, node20={:?}, node30={:?}",
                handles[0].debug_state(),
                handles[1].debug_state(),
                handles[2].debug_state(),
            );
        }
    }

    let ok = wait_until(Duration::from_secs(15), || {
        repos.iter().all(|r| r.current_version() == 21)
    })
    .await;
    assert!(ok, "all nodes must reach version 21");

    let log0 = repos[0].log();
    assert_eq!(
        log0.len(),
        21,
        "the committed log must contain every proposal"
    );
    for repo in &repos[1..] {
        let log = repo.log();
        let metadata = repo.state.lock().1.clone();
        assert_eq!(
            log, log0,
            "replicas diverged on total order: metadata={metadata:?}"
        );
    }

    cluster.shutdown().await;
}

/// Checks that a strict proposal does not bind its commit delivery to the
/// routes that existed during the propose phase. Quorum ACKs are delayed while
/// node 1's direct route to node 4 is withdrawn; after ACK processing resumes,
/// the commit must use the replacement multi-hop route and converge every log.
#[tokio::test]
async fn strict_route_change_between_propose_ack_and_commit_converges() {
    let cfg = ReplicationConfig::default()
        .with_propose_ttl(Duration::from_secs(30))
        .with_pending_propose_ttl(Duration::from_secs(45));
    let cluster = ReplCluster::build_full_mesh_fast_failure_with_config(&[1, 2, 3, 4], cfg).await;
    let repos: Vec<Arc<CountingStrictRepo>> = (0..4).map(|_| CountingStrictRepo::new()).collect();
    let mut handles = Vec::new();
    for (idx, repo) in repos.iter().enumerate() {
        handles.push(
            cluster
                .register_strict(idx, "channels-route-change", repo.clone())
                .unwrap(),
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let coordinator = cluster.cluster.node(1);
    for peer in [3, 4] {
        coordinator.chaos.set_delay(
            FaultSelector::new(peer, TransportKind::Tcp, MessageType::StrictAck),
            Duration::from_secs(12),
            Duration::ZERO,
        );
    }

    let handle = handles[0].clone();
    let proposal = tokio::spawn(async move { handle.propose(4242).await });
    tokio::time::sleep(Duration::from_millis(150)).await;

    coordinator.chaos.block(4);
    cluster.cluster.node(4).chaos.block(1);
    assert!(
        wait_until(Duration::from_secs(10), || {
            matches!(
                coordinator
                    .overlay
                    .route_to(4, ServiceLevel::Reliable),
                Some(next_hop) if next_hop != 4
            )
        })
        .await,
        "node 1 did not replace its direct route to node 4: {:?}",
        coordinator.overlay.route_to(4, ServiceLevel::Reliable)
    );

    let version = timeout(Duration::from_secs(35), proposal)
        .await
        .expect("proposal hung after route change")
        .expect("proposal task panicked")
        .expect("proposal failed after route change");
    assert_eq!(version, 1);
    assert!(
        wait_until(Duration::from_secs(10), || {
            repos.iter().all(|repo| repo.current_version() == 1)
        })
        .await,
        "commit did not converge after route change: versions={:?}",
        repos
            .iter()
            .map(|repo| repo.current_version())
            .collect::<Vec<_>>()
    );
    let log0 = repos[0].log();
    for repo in &repos[1..] {
        assert_eq!(repo.log(), log0, "replicas diverged after route change");
    }

    cluster.shutdown().await;
}

/// A peer that regains a route while an already-committed operation is inside
/// repository apply must remain outside the delivery watermark until its
/// history and clock pass the epoch-scoped admission barrier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strict_rejoining_peer_does_not_pin_buffered_delivery() {
    use std::collections::HashSet;

    let cfg = ReplicationConfig::default()
        .with_delivery_tick_interval(Duration::from_millis(25))
        .with_strict_bootstrap_retry_interval(Duration::from_millis(100))
        .with_propose_ttl(Duration::from_secs(20))
        .with_pending_propose_ttl(Duration::from_secs(30));
    let cluster = ReplCluster::build_full_mesh_fast_failure_with_config(&[1, 2, 3, 4], cfg).await;
    let repos: Vec<_> = (0..4).map(|_| GatedCountingStrictRepo::new()).collect();
    let mut handles = Vec::new();
    for (idx, repo) in repos.iter().enumerate() {
        handles.push(
            cluster
                .register_strict(idx, "channels-rejoin-admission", repo.clone())
                .unwrap(),
        );
    }

    assert!(
        wait_until(Duration::from_secs(8), || {
            cluster
                .managers
                .iter()
                .all(|manager| manager.strict_capability_activation_ready())
                && strict_protocol_floors(&cluster)
                    .iter()
                    .all(|(_, version)| *version == STRICT_REPLICATION_PROTOCOL_VERSION)
        })
        .await,
        "strict v2 capability did not converge before the rejoin scenario: floors={:?}",
        strict_protocol_floors(&cluster)
    );

    let warmup_version = handles[0].propose(100).await.unwrap();
    assert_eq!(warmup_version, 1);
    assert!(
        wait_until(Duration::from_secs(10), || {
            repos
                .iter()
                .all(|repo| repo.current_version() == warmup_version)
        })
        .await,
        "warm-up operation did not converge: versions={:?}",
        repos
            .iter()
            .map(|repo| repo.current_version())
            .collect::<Vec<_>>()
    );

    cluster.cluster.partition(&[1, 2, 3], &[4]);
    assert!(
        wait_until(Duration::from_secs(10), || {
            [1u16, 2, 3].into_iter().all(|node_id| {
                let alive: HashSet<_> = cluster
                    .cluster
                    .node(node_id)
                    .overlay
                    .alive_members()
                    .into_iter()
                    .collect();
                !alive.contains(&4)
                    && cluster
                        .cluster
                        .node(node_id)
                        .overlay
                        .route_to(4, ServiceLevel::Reliable)
                        .is_none()
            })
        })
        .await,
        "partitioned node 4 was not removed from the surviving membership"
    );

    for repo in &repos[..3] {
        repo.block_delivery();
    }
    let coordinator = handles[0].clone();
    let proposal = tokio::spawn(async move { coordinator.propose(200).await });

    assert!(
        wait_until(Duration::from_secs(10), || {
            repos[..3].iter().all(|repo| repo.delivery_is_blocked())
                && matches!(
                    handles[0].debug_state().local_proposal_quorum(),
                    Some((_, _, _, 3, _, true))
                )
        })
        .await,
        "the surviving frozen configuration did not commit into gated apply: states={:?}",
        handles
            .iter()
            .map(|handle| handle.debug_state())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        repos[3].current_version(),
        warmup_version,
        "partitioned node unexpectedly received the committed operation"
    );

    cluster.cluster.heal_partition(&[1, 2, 3], &[4]);
    assert!(
        wait_for_full_routing(&cluster.cluster, Duration::from_secs(10)).await,
        "routing did not reconverge while repository delivery was gated"
    );
    // Let the bootstrap worker observe the new exact incarnation and create
    // its admission barrier before repository apply is allowed to complete.
    tokio::time::sleep(Duration::from_millis(300)).await;

    for repo in &repos[..3] {
        repo.release_delivery();
    }
    let committed_version = timeout(Duration::from_secs(8), proposal)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "rejoined stale peer pinned committed delivery: states={:?}",
                handles
                    .iter()
                    .map(|handle| handle.debug_state())
                    .collect::<Vec<_>>()
            )
        })
        .expect("proposal task panicked")
        .expect("committed proposal returned an error after peer rejoin");
    assert_eq!(committed_version, 2);

    assert!(
        wait_until(Duration::from_secs(15), || {
            repos
                .iter()
                .all(|repo| repo.current_version() == committed_version)
        })
        .await,
        "automatic admission catch-up did not converge: versions={:?}, states={:?}",
        repos
            .iter()
            .map(|repo| repo.current_version())
            .collect::<Vec<_>>(),
        handles
            .iter()
            .map(|handle| handle.debug_state())
            .collect::<Vec<_>>()
    );
    let expected_log = repos[0].log();
    for repo in &repos[1..] {
        assert_eq!(
            repo.log(),
            expected_log,
            "strict logs diverged after rejoin"
        );
    }

    cluster.shutdown().await;
}

/// Checks that strict state from an old node incarnation cannot wedge the same
/// node ID after a real restart. The coordinator is stopped only after a peer
/// ACK proves its proposal is pending; a fresh coordinator then rejoins and a
/// later proposal must converge on all live replicas.
#[tokio::test]
async fn strict_same_id_restart_clears_old_pending_proposal() {
    let cfg = ReplicationConfig::default()
        .with_propose_ttl(Duration::from_secs(20))
        .with_pending_propose_ttl(Duration::from_secs(30));
    let mut cluster = ReplCluster::build_full_mesh_with_config(&[1, 2, 3], cfg.clone()).await;
    let repos: Vec<Arc<CountingStrictRepo>> = (0..3).map(|_| CountingStrictRepo::new()).collect();
    let mut handles = Vec::new();
    for (idx, repo) in repos.iter().enumerate() {
        handles.push(
            cluster
                .register_strict(idx, "channels-restart", repo.clone())
                .unwrap(),
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (old_epoch, old_port) = {
        let old_coordinator = cluster.cluster.node(1);
        let held_ack = FaultSelector::new(2, TransportKind::Tcp, MessageType::StrictAck);
        old_coordinator.chaos.drop_next(held_ack, 100);
        old_coordinator.chaos.drop_next(
            FaultSelector::new(3, TransportKind::Tcp, MessageType::StrictAck),
            100,
        );
        let old_handle = handles[0].clone();
        let old_proposal = tokio::spawn(async move { old_handle.propose(1111).await });
        assert!(
            wait_until(Duration::from_secs(3), || old_coordinator
                .chaos
                .remaining_drops(held_ack)
                < 100)
            .await,
            "peer ACK never proved the old proposal reached pending state"
        );

        cluster.managers[0].shutdown().await;
        old_coordinator.overlay.shutdown().await;
        old_coordinator.transport.shutdown().await;
        let _ = timeout(Duration::from_secs(3), old_proposal)
            .await
            .expect("old proposal did not terminate with its coordinator");
        (
            old_coordinator.overlay.local_boot_epoch(),
            old_coordinator.port,
        )
    };
    // A process restart drops every owner of the old terminal-journal lock.
    // Removing both local test references makes the replacement exercise the
    // same durable-journal handoff.
    drop(handles.remove(0));
    drop(cluster.managers.remove(0));

    tokio::time::sleep(Duration::from_millis(50)).await;
    let seeds = [2u16, 3]
        .into_iter()
        .map(|peer| {
            SeedPeer::new(
                peer,
                vec![PeerAddress::new(
                    loopback(cluster.cluster.node(peer).port),
                    TransportKind::Tcp,
                )],
            )
        })
        .collect();
    let (new_transport, new_inbound) =
        ConnectionManager::start(transport_cfg(&cluster.cluster.pki, 0, loopback(old_port)))
            .await
            .unwrap();
    let new_overlay = OverlayNetwork::start(
        new_transport.clone(),
        new_inbound,
        overlay_cfg(seeds).with_persistence_dir(cluster.persistence_dir(0).to_path_buf()),
    )
    .await
    .unwrap();
    assert!(
        new_overlay.local_boot_epoch() > old_epoch,
        "same-ID restart did not advance the incarnation"
    );
    assert!(
        wait_until(Duration::from_secs(8), || {
            new_overlay.route_to(2, ServiceLevel::Reliable).is_some()
                && new_overlay.route_to(3, ServiceLevel::Reliable).is_some()
        })
        .await,
        "restarted coordinator did not rejoin routing"
    );
    let new_manager = ReplicationManager::with_config(new_overlay.clone(), cfg);
    let new_repo = CountingStrictRepo::new();
    let new_handle = new_manager
        .register_strict("channels-restart", new_repo.clone())
        .unwrap();
    assert!(
        wait_until(Duration::from_secs(8), || {
            new_manager.strict_protocol_version() >= STRICT_REPLICATION_PROTOCOL_VERSION
                && cluster.managers.iter().all(|manager| {
                    manager.strict_protocol_version() >= STRICT_REPLICATION_PROTOCOL_VERSION
                })
        })
        .await,
        "restarted strict protocol capability did not converge after repository registration: restarted={}, node2={}, node3={}",
        new_manager.strict_protocol_version(),
        cluster.manager(0).strict_protocol_version(),
        cluster.manager(1).strict_protocol_version()
    );
    tokio::time::sleep(Duration::from_millis(300)).await;

    let version = match timeout(Duration::from_secs(20), handles[0].propose(2222)).await {
        Ok(Ok(version)) => version,
        result => panic!(
            "old pending proposal wedged the restarted node ID: result={result:?}, node2={:?}, node3={:?}, restarted={:?}",
            handles[0].debug_state(),
            handles[1].debug_state(),
            new_handle.debug_state(),
        ),
    };
    assert!(
        wait_until(Duration::from_secs(10), || {
            repos[1].current_version() == version
                && repos[2].current_version() == version
                && new_repo.current_version() == version
        })
        .await,
        "post-restart proposal did not converge: peer2={}, peer3={}, restarted={}",
        repos[1].current_version(),
        repos[2].current_version(),
        new_repo.current_version()
    );
    assert_eq!(repos[1].log(), repos[2].log());
    assert_eq!(new_repo.log(), repos[1].log());
    assert!(
        repos[1].log().iter().any(|(_, op)| *op == 2222),
        "the post-restart proposal is absent from the converged log"
    );
    assert!(
        repos[1].log().iter().any(|(_, op)| *op == 1111),
        "the recovered pre-restart proposal is absent from the converged log"
    );

    new_manager.shutdown().await;
    new_overlay.shutdown().await;
    new_transport.shutdown().await;
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
    assert!(
        wait_until(Duration::from_secs(10), || {
            handles.iter().all(|handle| {
                let state = handle.debug_state();
                state.admitted_peers() == 3
                    && !state.election_pending()
                    && !state.election_active()
            })
        })
        .await,
        "four-node strict admission did not converge: states={:?}",
        handles
            .iter()
            .map(|handle| handle.debug_state())
            .collect::<Vec<_>>()
    );

    // Keep the proposal in phase one until its immutable four-node target
    // descriptor is observable. Partitioning before descriptor registration
    // legitimately lets admission freeze the surviving {1,2} view instead.
    let coordinator = cluster.cluster.node(1);
    let held_acks: Vec<_> = [2, 3, 4]
        .into_iter()
        .map(|peer| FaultSelector::new(peer, TransportKind::Tcp, MessageType::StrictAck))
        .collect();
    for selector in held_acks.iter().copied() {
        coordinator.chaos.hold(selector);
    }

    let h0 = handles[0].clone();
    let task = tokio::spawn(async move { h0.propose(7777u64).await });
    assert!(
        wait_until(Duration::from_secs(5), || {
            matches!(
                handles[0].debug_state().local_proposal_quorum(),
                Some((_, _, _, 4, false, false))
            )
        })
        .await,
        "proposal did not freeze the four-node target set: state={:?}",
        handles[0].debug_state()
    );

    // Block all inbound from 3,4 on node 1 (and symmetrically on node 2).
    // Hellos stop, so dead-detect fires `Failed(3)` and `Failed(4)` within
    // ~hello_dead_interval seconds. The already-frozen descriptor cannot be
    // shrunk to the surviving side.
    cluster.cluster.partition(&[1, 2], &[3, 4]);

    let result = timeout(Duration::from_secs(20), task).await;
    for selector in held_acks {
        coordinator.chaos.release(selector);
    }
    let res = result
        .expect("propose task hung")
        .expect("propose task panicked");
    assert!(
        matches!(res, Err(ReplicationError::QuorumLost)),
        "expected QuorumLost, got {:?}",
        res
    );

    cluster.shutdown().await;
}

/// Checks durable v2 terminal-state convergence across a real split-heal.
/// Expected: after {1,2}|{3,4} diverge, healing retains every terminally
/// committed channel operation rather than allowing a history snapshot to
/// roll back the shorter partition's completed operation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strict_channel_repository_split_heal_preserves_all_terminal_commits() {
    let node_ids = [1u16, 2, 3, 4];
    // Keep these roots alive for the full test, including the reopen check
    // after the overlay/runtime has released its repository handles.
    let channel_storage_dirs = node_ids
        .iter()
        .map(|_| tempfile::tempdir().expect("strict channel repository storage dir"))
        .collect::<Vec<_>>();
    let cfg = ReplicationConfig::default()
        .with_delivery_tick_interval(Duration::from_millis(25))
        .with_strict_bootstrap_retry_interval(Duration::from_millis(100));
    let cluster = ReplCluster::build_full_mesh_fast_failure_with_config(&node_ids, cfg).await;
    let mut repos = Vec::with_capacity(node_ids.len());
    for (index, node_id) in node_ids.into_iter().enumerate() {
        repos.push(
            ChannelRepository::open(
                node_id,
                channel_storage_dirs[index].path(),
                ChannelRootConfig::new("Root"),
                channel_tuning(),
            )
            .await
            .expect("open durable strict channel repository"),
        );
    }
    assert!(
        repos
            .iter()
            .all(|repo| repo.strict_operation_durability_enabled()),
        "split-heal must exercise the durable v2 repository boundary"
    );
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

    let healed = wait_for_converged_channel_history(&repos, Duration::from_secs(45)).await;
    if !healed {
        panic!(
            "healed cluster did not converge on all terminal channel commits: {:?}",
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
    assert_eq!(
        names[0],
        vec![
            "Root".to_owned(),
            "common-10".to_owned(),
            "common-11".to_owned(),
            "left-20".to_owned(),
            "left-21".to_owned(),
            "left-22".to_owned(),
            "right-30".to_owned(),
        ],
        "all replicas must expose the same deterministic union of terminal commits"
    );

    let expected_operation_ids = repos[0].strict_operation_ids();
    assert_eq!(
        expected_operation_ids.len(),
        6,
        "the converged history must retain every committed strict operation id"
    );
    for repo in &repos[1..] {
        assert_eq!(
            repo.strict_operation_ids(),
            expected_operation_ids,
            "all replicas must retain the same sorted operation-id ledger"
        );
    }

    cluster.shutdown().await;
    drop(handles);
    drop(repos);
    drop(cluster);

    for (node_id, storage_dir) in [1u16, 2, 3, 4].into_iter().zip(&channel_storage_dirs) {
        let reopened = ChannelRepository::open(
            node_id,
            storage_dir.path(),
            ChannelRootConfig::new("Root"),
            channel_tuning(),
        )
        .await
        .expect("reopen durable strict channel repository");
        assert!(reopened.strict_operation_durability_enabled());
        assert_eq!(reopened.current_version(), 6);
        assert_eq!(reopened.strict_operation_ids(), expected_operation_ids);
    }
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

/// Current negotiated protocol floor as observed from each test node.
fn strict_protocol_floors(cluster: &ReplCluster) -> Vec<(u16, u32)> {
    cluster
        .cluster
        .nodes
        .iter()
        .zip(&cluster.managers)
        .map(|(node, manager)| {
            (
                node.overlay.local_node_id(),
                manager.strict_protocol_version(),
            )
        })
        .collect()
}

/// Checks strict replication while direct cross-node links fail in a hostile,
/// randomly shaped but deterministic network.
/// Expected: each proposal routes around detected transient link cuts; no
/// proposal task panics or hangs, and every replica has the same total-ordered
/// log after each hostile-network round.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strict_replication_survives_random_cross_node_link_failures() {
    let node_ids: Vec<u16> = (1..=7).collect();
    // Keep the retry cadence bounded while the test deliberately churns
    // routes.  The production default allows the adaptive clock tick to
    // grow to five seconds; under this synthetic jitter that leaves too
    // little time for a proposal's retry fanout before its ten-second TTL.
    let repl_cfg = ReplicationConfig::default()
        .with_fallback_clock_tick(Duration::from_millis(100))
        .with_min_clock_tick(Duration::from_millis(50))
        .with_max_clock_tick(Duration::from_millis(500))
        .with_propose_ttl(Duration::from_secs(20))
        .with_pending_propose_ttl(Duration::from_secs(40));
    let cluster = ReplCluster::build_full_mesh_with_config(&node_ids, repl_cfg).await;
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
    assert!(
        wait_until(Duration::from_secs(8), || {
            cluster
                .managers
                .iter()
                .all(|manager| manager.strict_capability_activation_ready())
                && strict_protocol_floors(&cluster)
                    .iter()
                    .all(|(_, version)| *version == STRICT_REPLICATION_PROTOCOL_VERSION)
        })
        .await,
        "automatic strict capability activation did not converge before hostile-link injection: floors={:?}",
        strict_protocol_floors(&cluster),
    );
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
        // Keep enough alternate paths for the 6-of-7 fast quorum while still
        // forcing every round to exercise indirect routing.
        while blocked_pairs.len() < 3 {
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
        let strict_idle = wait_until(Duration::from_secs(15), || {
            handles.iter().all(|handle| {
                let state = handle.debug_state();
                !state.election_pending() && !state.election_active()
            })
        })
        .await;
        assert!(
            strict_idle,
            "strict history election did not quiesce while hostile links were failing: protocol_floors={:?}, states={:?}",
            strict_protocol_floors(&cluster),
            handles
                .iter()
                .map(|handle| handle.debug_state())
                .collect::<Vec<_>>()
        );

        assert!(
            wait_until(Duration::from_secs(8), || {
                cluster
                    .managers
                    .iter()
                    .all(|manager| manager.strict_capability_activation_ready())
                    && strict_protocol_floors(&cluster)
                        .iter()
                        .all(|(_, version)| *version == STRICT_REPLICATION_PROTOCOL_VERSION)
            })
            .await,
            "strict capability floor did not remain v2 while hostile links were failing: round={round}, blocked_pairs={blocked_pairs:?}, floors={:?}",
            strict_protocol_floors(&cluster),
        );

        let proposer = rng.random_range(0..handles.len());
        let handle = handles[proposer].clone();
        let expected_version = round + 1;
        let mut task = tokio::spawn(async move { handle.propose(9000 + round).await });
        let deadline = tokio::time::sleep(Duration::from_secs(30));
        tokio::pin!(deadline);
        let mut last_phase_progress = None;
        let mut last_phase_propose_acks = None;
        let mut last_phase_invalid_targets = None;
        let mut last_phase_accept_acks = None;
        let task_result = loop {
            tokio::select! {
                result = &mut task => break result,
                _ = &mut deadline => {
                    panic!(
                        "proposal hung while cross-node links were failing: round={round}, proposer={proposer}, blocked_pairs={blocked_pairs:?}, protocol_floors={:?}, last_phase_progress={last_phase_progress:?}, last_phase_propose_acks={last_phase_propose_acks:?}, last_phase_invalid_targets={last_phase_invalid_targets:?}, states={:?}",
                        strict_protocol_floors(&cluster),
                        handles
                            .iter()
                            .map(|handle| handle.debug_state())
                            .collect::<Vec<_>>()
                    );
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    let state = handles[proposer].debug_state();
                    if let Some(progress) = state.local_proposal_quorum() {
                        last_phase_progress = Some(progress);
                        last_phase_propose_acks = state.local_proposal_acks().map(<[_]>::to_vec);
                        last_phase_invalid_targets = state
                            .local_proposal_invalid_targets()
                            .map(<[_]>::to_vec);
                        last_phase_accept_acks = Some(
                            state
                                .local_proposal_accept_acks()
                                .map(|acks| acks.to_vec()),
                        );
                    }
                }
            }
        };
        let version = task_result
            .unwrap_or_else(|e| panic!("proposal task panicked while cross-node links were failing: round={round}, proposer={proposer}, blocked_pairs={blocked_pairs:?}, join_error={e}"))
            .unwrap_or_else(|e| panic!("strict replication should route around hostile link failures: round={round}, proposer={proposer}, blocked_pairs={blocked_pairs:?}, error={e:?}, protocol_floors={:?}, last_phase_progress={last_phase_progress:?}, last_phase_propose_acks={last_phase_propose_acks:?}, last_phase_invalid_targets={last_phase_invalid_targets:?}, last_phase_accept_acks={last_phase_accept_acks:?}, states={:?}", strict_protocol_floors(&cluster), handles.iter().map(|h| h.debug_state()).collect::<Vec<_>>()));
        assert_eq!(version, expected_version);

        let ok = wait_until(Duration::from_secs(15), || {
            repos
                .iter()
                .all(|r| r.current_version() == expected_version)
        })
        .await;
        assert!(
            ok,
            "replicas did not converge after round {round}: versions = {:?}, blocked_pairs = {blocked_pairs:?}, protocol_floors = {:?}, states = {:?}",
            repos
                .iter()
                .map(|r| r.current_version())
                .collect::<Vec<_>>(),
            strict_protocol_floors(&cluster),
            handles
                .iter()
                .map(|handle| handle.debug_state())
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
