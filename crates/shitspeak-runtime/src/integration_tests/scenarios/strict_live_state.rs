//! Ignored full-runtime reproduction for copied production channel state.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future::join_all;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use tempfile::TempDir;

use crate::integration_tests::harness::{
    TestServer, TestServerOpts, TestStrictReplicationState, spawn_s2s_test_server_with_state,
};
use shitspeak_core::DEFAULT_SERVER_ID;
use shitspeak_runtime_config::{S2sConfig, S2sSeedAddressConfig, S2sTransportKindConfig};
use shitspeak_s2s::testing::{
    Pki, loopback, mint_pki, pick_free_port, s2s_network_test_guard, wait_until,
};
use shitspeak_s2s_transport::ServiceLevel;
use shitspeak_state::Channel;

// Preserve the production rank order: the two long-running forwarders win
// equal-head elections ahead of the newer regional replicas.
const NODE_IDS: [u16; 9] = [4_097, 4_096, 1, 4, 7, 15, 16, 8, 5];
const HEALTHY_VERSION: u64 = 10_980;
const HEALTHY_FRESHNESS: i64 = 1_786_195_429;
const LAGGING_VERSION: u64 = 10_977;
const CLUSTER_READY_DEADLINE: Duration = Duration::from_secs(90);
const CONVERGENCE_DEADLINE: Duration = Duration::from_secs(300);
const BASELINE_OBSERVATION: Duration = Duration::from_secs(45);
const QUIET_SETTLE: Duration = Duration::from_secs(20);
const STEADY_STATE_WARMUP: Duration = Duration::from_secs(65);
const MULTI_INTERVAL_OBSERVATION: Duration = Duration::from_secs(125);

const ACTIVE_JOURNAL_ID: &str = "aedd7949414a8099bdf64b33c111fcec";
const ACTIVE_CHAIN_DIGEST: &str =
    "f13be4f74baea7dadb30d67f6c1366e61f8e801a0e92c5abac92d4f94ce0750f";
const ACTIVE_TERMINAL_SET_DIGEST: &str =
    "9182c4cb8b91b46fc8af33e35ccf5f30b354da3022d970149f2479ae80f133cc";
const CHECKPOINT_TERMINAL_SET_DIGEST: &str =
    "e58b41cdee7a31bf4af337316de44da0d5f6f1eecfb7eeffd05d177f66716ccc";
const NODE_15_CURRENT_ORIGIN: [u8; 8] = [0x00, 0x0f, 0x58, 0x84, 0x53, 0xec, 0xe6, 0x7e];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expectation {
    BaselineStuck,
    FixedConverged,
}

impl Expectation {
    fn from_environment() -> Self {
        match std::env::var("SHITSPEAK_STRICT_LIVE_EXPECTATION").as_deref() {
            Ok("baseline_stuck") => Self::BaselineStuck,
            Ok("fixed_converged") => Self::FixedConverged,
            Ok(value) => panic!(
                "unsupported SHITSPEAK_STRICT_LIVE_EXPECTATION={value:?}; expected baseline_stuck or fixed_converged"
            ),
            Err(error) => panic!("SHITSPEAK_STRICT_LIVE_EXPECTATION is required: {error}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct TrafficSnapshot {
    requests: f64,
    responses: f64,
    send_attempts: f64,
    send_bytes: f64,
    elections_started: f64,
    elections_response_pending: f64,
    elections_local_won: f64,
    elections_remote_won: f64,
    elections_snapshot_started: f64,
    elections_finished: f64,
    elections_rearmed: f64,
    elections_timed_out: f64,
    history_sessions_started: f64,
    completed_history_sessions: f64,
    failed_history_sessions: f64,
    cancelled_history_sessions: f64,
    expired_history_sessions: f64,
    resource_limited_history_sessions: f64,
    foreign_lineage_elections_requested: f64,
    foreign_lineage_elections_deduped: f64,
    forced_checkpoints_sent: f64,
    catchups_active: f64,
    strict_sessions_active: f64,
    bulk_in_flight_bytes: f64,
}

impl TrafficSnapshot {
    fn capture(server: &TestServer) -> Self {
        Self {
            requests: metric_total(
                server,
                "shitspeak_s2s_replication_catchup_requests_total",
                &[],
            ),
            responses: metric_total(
                server,
                "shitspeak_s2s_replication_catchup_responses_total",
                &[],
            ),
            send_attempts: metric_total(
                server,
                "shitspeak_s2s_strict_replication_catchup_send_attempts_total",
                &[],
            ),
            send_bytes: metric_total(
                server,
                "shitspeak_s2s_strict_replication_catchup_send_bytes_total",
                &[],
            ),
            elections_started: metric_total(
                server,
                "shitspeak_s2s_strict_replication_history_election_events_total",
                &[("event", "started")],
            ),
            elections_response_pending: metric_total(
                server,
                "shitspeak_s2s_strict_replication_history_election_events_total",
                &[("event", "response_pending")],
            ),
            elections_local_won: metric_total(
                server,
                "shitspeak_s2s_strict_replication_history_election_events_total",
                &[("event", "local_won")],
            ),
            elections_remote_won: metric_total(
                server,
                "shitspeak_s2s_strict_replication_history_election_events_total",
                &[("event", "remote_won")],
            ),
            elections_snapshot_started: metric_total(
                server,
                "shitspeak_s2s_strict_replication_history_election_events_total",
                &[("event", "snapshot_started")],
            ),
            elections_finished: metric_total(
                server,
                "shitspeak_s2s_strict_replication_history_election_events_total",
                &[("event", "finished")],
            ),
            elections_rearmed: metric_total(
                server,
                "shitspeak_s2s_strict_replication_history_election_events_total",
                &[("event", "rearmed")],
            ),
            elections_timed_out: metric_total(
                server,
                "shitspeak_s2s_strict_replication_history_election_events_total",
                &[("event", "timed_out")],
            ),
            history_sessions_started: metric_total(
                server,
                "shitspeak_s2s_strict_replication_catchup_session_starts_total",
                &[("reason", "history_election")],
            ),
            completed_history_sessions: metric_total(
                server,
                "shitspeak_s2s_strict_replication_catchup_session_completions_total",
                &[("reason", "history_election"), ("outcome", "completed")],
            ),
            failed_history_sessions: metric_total(
                server,
                "shitspeak_s2s_strict_replication_catchup_session_completions_total",
                &[("reason", "history_election"), ("outcome", "failed")],
            ),
            cancelled_history_sessions: metric_total(
                server,
                "shitspeak_s2s_strict_replication_catchup_session_completions_total",
                &[("reason", "history_election"), ("outcome", "cancelled")],
            ),
            expired_history_sessions: metric_total(
                server,
                "shitspeak_s2s_strict_replication_catchup_session_completions_total",
                &[("reason", "history_election"), ("outcome", "expired")],
            ),
            resource_limited_history_sessions: metric_total(
                server,
                "shitspeak_s2s_strict_replication_catchup_session_completions_total",
                &[
                    ("reason", "history_election"),
                    ("outcome", "resource_limit"),
                ],
            ),
            foreign_lineage_elections_requested: metric_total(
                server,
                "shitspeak_s2s_strict_replication_divergence_events_total",
                &[("event", "foreign_lineage_election_requested")],
            ),
            foreign_lineage_elections_deduped: metric_total(
                server,
                "shitspeak_s2s_strict_replication_divergence_events_total",
                &[("event", "foreign_lineage_election_deduped")],
            ),
            forced_checkpoints_sent: metric_total(
                server,
                "shitspeak_s2s_strict_replication_divergence_events_total",
                &[("event", "forced_checkpoint_sent")],
            ),
            catchups_active: metric_total(server, "shitspeak_s2s_replication_catchup_active", &[]),
            strict_sessions_active: metric_total(
                server,
                "shitspeak_s2s_strict_replication_catchup_sessions_active",
                &[],
            ),
            bulk_in_flight_bytes: metric_total(
                server,
                "shitspeak_s2s_strict_replication_catchup_bulk_in_flight_bytes",
                &[],
            ),
        }
    }
}

#[derive(Debug)]
struct TerminalStatus {
    journal_id: Vec<u8>,
    generation: u64,
    chain_digest: Vec<u8>,
    terminal_set_digest: Vec<u8>,
    checkpoint_repository_version: Option<u64>,
    repository_image_install_pending: bool,
    node_15_retired_floor: Option<u64>,
    node_15_record_counters: Vec<u64>,
}

impl TerminalStatus {
    fn covers_healthy_terminal_state(&self) -> bool {
        if self.repository_image_install_pending {
            return false;
        }
        let covers_node_15 = self
            .node_15_retired_floor
            .is_some_and(|counter| counter >= 3)
            || [1, 2, 3]
                .iter()
                .all(|counter| self.node_15_record_counters.binary_search(counter).is_ok());
        let active = self.journal_id == decode_hex(ACTIVE_JOURNAL_ID)
            && self.generation == 4_106
            && self.chain_digest == decode_hex(ACTIVE_CHAIN_DIGEST)
            && self.terminal_set_digest == decode_hex(ACTIVE_TERMINAL_SET_DIGEST)
            && covers_node_15;
        let checkpointed = self.generation == 0
            && self.chain_digest == [0; 32]
            && self.terminal_set_digest == decode_hex(CHECKPOINT_TERMINAL_SET_DIGEST)
            && self
                .checkpoint_repository_version
                .is_some_and(|version| version >= HEALTHY_VERSION)
            && covers_node_15;
        active || checkpointed
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    hex::decode(value).expect("valid hard-coded live-state digest")
}

fn decode_u64(value: Vec<u8>) -> rusqlite::Result<u64> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            8,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected an eight-byte big-endian integer",
            )),
        )
    })?;
    Ok(u64::from_be_bytes(bytes))
}

fn fixture_repository_version(directory: &Path) -> u64 {
    let snapshot: serde_json::Value = serde_json::from_slice(
        &std::fs::read(directory.join("channels.snapshot.json"))
            .expect("read copied channel snapshot"),
    )
    .expect("parse copied channel snapshot");
    let mut version = snapshot["version"]
        .as_u64()
        .expect("copied channel snapshot version");
    let wal = std::fs::read_to_string(directory.join("channels.wal.jsonl"))
        .expect("read copied channel WAL");
    for line in wal.lines().filter(|line| !line.trim().is_empty()) {
        let entry: serde_json::Value =
            serde_json::from_str(line).expect("parse copied channel WAL entry");
        version = version.max(
            entry["version"]
                .as_u64()
                .expect("copied channel WAL version"),
        );
    }
    version
}

fn read_terminal_status(path: &Path) -> rusqlite::Result<TerminalStatus> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    connection.busy_timeout(Duration::from_secs(1))?;
    let (journal_id, generation, chain_digest, terminal_set_digest) = connection.query_row(
        "SELECT journal_id, generation, chain_digest, terminal_set_digest
         FROM journal_metadata WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                decode_u64(row.get::<_, Vec<u8>>(1)?)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        },
    )?;
    let checkpoint = connection
        .query_row(
            "SELECT repository_version, repository_image_install_pending
             FROM journal_checkpoint WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    decode_u64(row.get::<_, Vec<u8>>(0)?)?,
                    row.get::<_, i64>(1)? != 0,
                ))
            },
        )
        .optional()?;
    let node_15_retired_floor = connection
        .query_row(
            "SELECT max_counter FROM retired_origins WHERE op_id_hi = ?1",
            [NODE_15_CURRENT_ORIGIN.as_slice()],
            |row| decode_u64(row.get::<_, Vec<u8>>(0)?),
        )
        .optional()?;
    let mut node_15_records = connection.prepare(
        "SELECT op_id_lo FROM journal_records
         WHERE op_id_hi = ?1 ORDER BY op_id_lo",
    )?;
    let node_15_record_counters = node_15_records
        .query_map([NODE_15_CURRENT_ORIGIN.as_slice()], |row| {
            decode_u64(row.get::<_, Vec<u8>>(0)?)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let (checkpoint_repository_version, repository_image_install_pending) = checkpoint
        .map(|(version, pending)| (Some(version), pending))
        .unwrap_or((None, false));
    Ok(TerminalStatus {
        journal_id,
        generation,
        chain_digest,
        terminal_set_digest,
        checkpoint_repository_version,
        repository_image_install_pending,
        node_15_retired_floor,
        node_15_record_counters,
    })
}

fn metric_total(server: &TestServer, metric: &str, labels: &[(&str, &str)]) -> f64 {
    server
        .server
        .s2s_manager()
        .prometheus_samples()
        .unwrap_or_default()
        .into_iter()
        .filter(|sample| {
            sample.name() == metric
                && labels.iter().all(|(key, value)| {
                    sample.labels().iter().any(|(sample_key, sample_value)| {
                        sample_key == key && sample_value == value
                    })
                })
        })
        .map(|sample| sample.value())
        .sum()
}

fn canonical_channel_image(channels: &[Channel]) -> Vec<serde_json::Value> {
    let mut image = channels
        .iter()
        .map(|channel| {
            let mut links = channel.links.iter().copied().collect::<Vec<_>>();
            links.sort_unstable();
            let acls = channel
                .acls
                .iter()
                .map(|acl| serde_json::to_value(acl).expect("serialize channel ACL"))
                .collect::<Vec<_>>();
            serde_json::json!({
                "id": channel.id,
                "name": channel.name,
                "position": channel.position,
                "max_users": channel.max_users,
                "parent_id": channel.parent_id,
                "inherit_acl": channel.inherit_acl,
                "links": links,
                "description_hash": channel.description_hash,
                "acls": acls,
                "pending_delete": channel.pending_delete,
            })
        })
        .collect::<Vec<_>>();
    image.sort_unstable_by_key(|channel| channel["id"].as_u64().unwrap_or_default());
    image
}

fn production_s2s_config(
    listen: std::net::SocketAddr,
    all_addresses: &[std::net::SocketAddr],
) -> S2sConfig {
    let mut config = S2sConfig {
        enabled: true,
        tcp_listen: vec![listen],
        tcp_advertise: vec![listen.to_string()],
        seed_addresses: all_addresses
            .iter()
            .copied()
            .filter(|address| *address != listen)
            .map(|address| S2sSeedAddressConfig::new(S2sTransportKindConfig::Tcp, address))
            .collect(),
        ..S2sConfig::default()
    };
    config.replications.fallback_clock_tick_ms = 250;
    config.replications.min_clock_tick_ms = 100;
    config.replications.max_clock_tick_ms = 5_000;
    config.replications.delivery_tick_interval_ms = 50;
    config.replications.propose_ttl_ms = 10_000;
    config.replications.propose_semaphore_size = 32;
    config.replications.strict_max_catchup_ops = 256;
    config.replications.strict_bootstrap_retry_interval_ms = 2_000;
    config.replications.strict_steady_state_catchup_interval_ms = 60_000;
    config.replications.bulk_retry_delay_ms = 250;
    config.replications.bulk_max_in_flight_per_peer = 1;
    config.replications.pending_propose_ttl_ms = 20_000;
    config.replications.recovery_ttl_ms = 10_000;
    config.replications.owner_catchup_timeout_ms = 5_000;
    config.replications.owner_max_catchup_ops = 512;
    config
}

async fn spawn_live_cluster(
    fixture_root: &Path,
    pki: Arc<Pki>,
    expect_lagging_heads: bool,
) -> Vec<(u16, TestServer)> {
    for node_id in NODE_IDS {
        let expected_version = if expect_lagging_heads && matches!(node_id, 5 | 8) {
            LAGGING_VERSION
        } else {
            HEALTHY_VERSION
        };
        assert_eq!(
            fixture_repository_version(&fixture_root.join(format!("node-{node_id}"))),
            expected_version,
            "node {node_id} copied repository fixture has an unexpected head"
        );
    }

    let mut addresses = Vec::with_capacity(NODE_IDS.len());
    for _ in NODE_IDS {
        addresses.push(loopback(pick_free_port().await));
    }

    let mut servers = Vec::with_capacity(NODE_IDS.len());
    for (cert_index, node_id) in NODE_IDS.into_iter().enumerate() {
        let server = spawn_s2s_test_server_with_state(
            TestServerOpts::default(),
            Arc::clone(&pki),
            node_id,
            cert_index,
            production_s2s_config(addresses[cert_index], &addresses),
            TestStrictReplicationState::from_directory(
                fixture_root.join(format!("node-{node_id}")),
            ),
        )
        .await;
        let initial_version = server.server.get_channels().current_version();
        let expected_version = if expect_lagging_heads && matches!(node_id, 5 | 8) {
            LAGGING_VERSION
        } else {
            HEALTHY_VERSION
        };
        if expect_lagging_heads && matches!(node_id, 5 | 8) {
            assert!(
                (LAGGING_VERSION..=HEALTHY_VERSION).contains(&initial_version),
                "node {node_id} opened outside the copied-to-healthy catch-up range"
            );
        } else {
            assert_eq!(
                initial_version, expected_version,
                "node {node_id} did not open the copied repository head unchanged"
            );
        }
        servers.push((node_id, server));
    }
    servers
}

async fn wait_for_cluster(servers: &[(u16, TestServer)]) {
    let ready = wait_until(CLUSTER_READY_DEADLINE, || {
        servers.iter().all(|(node_id, server)| {
            let manager = server.server.s2s_manager();
            let Some(overlay) = manager.overlay() else {
                return false;
            };
            let Some(transport) = manager.transport() else {
                return false;
            };
            manager.application().is_some()
                && manager.replications().as_ref().is_some_and(|replications| {
                    replications.strict_capability_activation_ready()
                        && replications.strict_protocol_version() > 0
                })
                && servers.iter().all(|(peer_id, _)| {
                    node_id == peer_id
                        || (overlay.alive_members().contains(peer_id)
                            && overlay
                                .route_to(*peer_id, ServiceLevel::Reliable)
                                .is_some_and(|next_hop| {
                                    !transport.live_transport_kinds(next_hop).is_empty()
                                }))
                })
        })
    })
    .await;
    assert!(ready, "copied-state cluster did not become ready");
}

fn node<'a>(servers: &'a [(u16, TestServer)], node_id: u16) -> &'a TestServer {
    &servers
        .iter()
        .find(|(candidate, _)| *candidate == node_id)
        .unwrap_or_else(|| panic!("missing local node {node_id}"))
        .1
}

fn versions(servers: &[(u16, TestServer)]) -> Vec<(u16, u64)> {
    servers
        .iter()
        .map(|(node_id, server)| (*node_id, server.server.get_channels().current_version()))
        .collect()
}

async fn wait_for_repositories(servers: &[(u16, TestServer)]) {
    assert!(
        wait_until(CONVERGENCE_DEADLINE, || {
            servers.iter().all(|(_, server)| {
                server.server.get_channels().current_version() == HEALTHY_VERSION
            })
        })
        .await,
        "channel repositories did not reach {HEALTHY_VERSION}: {:?}",
        versions(servers)
    );

    let reference = node(servers, 1)
        .server
        .get_channels()
        .s2s_snapshot_in_server(DEFAULT_SERVER_ID)
        .await;
    assert_eq!(reference.version(), HEALTHY_VERSION);
    assert_eq!(reference.freshness(), HEALTHY_FRESHNESS);
    let reference_channels = canonical_channel_image(reference.channels());
    for (node_id, server) in servers {
        let snapshot = server
            .server
            .get_channels()
            .s2s_snapshot_in_server(DEFAULT_SERVER_ID)
            .await;
        assert_eq!(snapshot.version(), HEALTHY_VERSION, "node {node_id}");
        assert_eq!(snapshot.freshness(), HEALTHY_FRESHNESS, "node {node_id}");
        assert_eq!(
            canonical_channel_image(snapshot.channels()),
            reference_channels,
            "node {node_id} channel image diverged from the healthy image"
        );
    }
}

async fn wait_for_terminal_coverage(servers: &[(u16, TestServer)]) {
    let deadline = Instant::now() + CONVERGENCE_DEADLINE;
    loop {
        let statuses = terminal_statuses(servers);
        if statuses.iter().all(|(_, status)| {
            status
                .as_ref()
                .is_ok_and(TerminalStatus::covers_healthy_terminal_state)
        }) {
            return;
        }
        if Instant::now() >= deadline {
            panic!("terminal journals did not cover the healthy state: {statuses:#?}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn assert_all_nodes_can_donate_snapshots(servers: &[(u16, TestServer)]) {
    let all_available = wait_until(CLUSTER_READY_DEADLINE, || {
        servers.iter().all(|(_, server)| {
            server
                .server
                .s2s_manager()
                .replications()
                .and_then(|replications| {
                    replications.strict_snapshot_capture_available_for_test("channels")
                })
                == Some(true)
        })
    })
    .await;
    assert!(all_available, "not every node can donate a strict snapshot");
    for (node_id, server) in servers {
        let available = server
            .server
            .s2s_manager()
            .replications()
            .and_then(|replications| {
                replications.strict_snapshot_capture_available_for_test("channels")
            });
        assert_eq!(
            available,
            Some(true),
            "node {node_id} retained an in-memory repository-base fence"
        );
    }
}

fn terminal_statuses(servers: &[(u16, TestServer)]) -> Vec<(u16, Result<TerminalStatus, String>)> {
    servers
        .iter()
        .map(|(node_id, server)| {
            let status = server
                .strict_channel_terminal_journal_path()
                .ok_or_else(|| "terminal journal path is unavailable".to_owned())
                .and_then(|path| read_terminal_status(&path).map_err(|error| error.to_string()));
            (*node_id, status)
        })
        .collect()
}

fn traffic_snapshots(servers: &[(u16, TestServer)]) -> Vec<(u16, TrafficSnapshot)> {
    servers
        .iter()
        .map(|(node_id, server)| (*node_id, TrafficSnapshot::capture(server)))
        .collect()
}

fn assert_no_active_traffic(snapshots: &[(u16, TrafficSnapshot)]) {
    for (node_id, snapshot) in snapshots {
        assert_eq!(snapshot.catchups_active, 0.0, "node {node_id}");
        assert_eq!(snapshot.strict_sessions_active, 0.0, "node {node_id}");
        assert_eq!(snapshot.bulk_in_flight_bytes, 0.0, "node {node_id}");
    }
}

async fn wait_for_quiet(servers: &[(u16, TestServer)]) -> Vec<(u16, TrafficSnapshot)> {
    let deadline = Instant::now() + CONVERGENCE_DEADLINE;
    let mut unchanged_since = Instant::now();
    let mut previous = traffic_snapshots(servers);
    loop {
        if unchanged_since.elapsed() >= QUIET_SETTLE {
            return previous;
        }
        assert!(
            Instant::now() < deadline,
            "strict traffic never became quiet; versions={:?} terminal={:#?} last snapshot={previous:#?}",
            versions(servers),
            terminal_statuses(servers),
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        let current = traffic_snapshots(servers);
        if current != previous {
            previous = current;
            unchanged_since = Instant::now();
        }
    }
}

async fn assert_multi_interval_quiescence(servers: &[(u16, TestServer)]) {
    // Dominator witnesses are intentionally in-memory. After a restart, let
    // one configured 60-second metadata cadence rebuild them before measuring
    // whether the completed-election loop remains stopped.
    tokio::time::sleep(STEADY_STATE_WARMUP).await;
    let before = wait_for_quiet(servers).await;
    assert_no_active_traffic(&before);
    tokio::time::sleep(MULTI_INTERVAL_OBSERVATION).await;
    let after = traffic_snapshots(servers);
    assert_no_active_traffic(&after);

    // These counters are process-global, so one sample represents the whole
    // local cluster. Healthy strict anti-entropy still exchanges bounded
    // metadata once per configured 60-second interval; the incident symptom
    // is repeated elections and bulk catch-up, not that expected cadence.
    let before = before[0].1;
    let after = after[0].1;
    for (name, before, after) in [
        (
            "elections_started",
            before.elections_started,
            after.elections_started,
        ),
        (
            "elections_response_pending",
            before.elections_response_pending,
            after.elections_response_pending,
        ),
        (
            "elections_local_won",
            before.elections_local_won,
            after.elections_local_won,
        ),
        (
            "elections_remote_won",
            before.elections_remote_won,
            after.elections_remote_won,
        ),
        (
            "elections_snapshot_started",
            before.elections_snapshot_started,
            after.elections_snapshot_started,
        ),
        (
            "elections_finished",
            before.elections_finished,
            after.elections_finished,
        ),
        (
            "elections_rearmed",
            before.elections_rearmed,
            after.elections_rearmed,
        ),
        (
            "elections_timed_out",
            before.elections_timed_out,
            after.elections_timed_out,
        ),
        (
            "history_sessions_started",
            before.history_sessions_started,
            after.history_sessions_started,
        ),
        (
            "completed_history_sessions",
            before.completed_history_sessions,
            after.completed_history_sessions,
        ),
        (
            "failed_history_sessions",
            before.failed_history_sessions,
            after.failed_history_sessions,
        ),
        (
            "cancelled_history_sessions",
            before.cancelled_history_sessions,
            after.cancelled_history_sessions,
        ),
        (
            "expired_history_sessions",
            before.expired_history_sessions,
            after.expired_history_sessions,
        ),
        (
            "resource_limited_history_sessions",
            before.resource_limited_history_sessions,
            after.resource_limited_history_sessions,
        ),
        (
            "foreign_lineage_elections_requested",
            before.foreign_lineage_elections_requested,
            after.foreign_lineage_elections_requested,
        ),
        (
            "foreign_lineage_elections_deduped",
            before.foreign_lineage_elections_deduped,
            after.foreign_lineage_elections_deduped,
        ),
        (
            "forced_checkpoints_sent",
            before.forced_checkpoints_sent,
            after.forced_checkpoints_sent,
        ),
    ] {
        assert_eq!(
            after,
            before,
            "{name} changed after convergence; versions={:?} terminal={:#?}",
            versions(servers),
            terminal_statuses(servers),
        );
    }

    let directed_peers = (NODE_IDS.len() * NODE_IDS.len().saturating_sub(1)) as f64;
    let request_budget = directed_peers * 3.0;
    let response_budget = request_budget * 2.0;
    let send_attempt_budget = (request_budget + response_budget) * 3.0;
    assert!(after.requests - before.requests <= request_budget);
    assert!(after.responses - before.responses <= response_budget);
    assert!(after.send_attempts - before.send_attempts <= send_attempt_budget);
    assert!(
        after.send_bytes - before.send_bytes <= 1024.0 * 1024.0,
        "steady-state metadata exceeded 1 MiB over {MULTI_INTERVAL_OBSERVATION:?}: before={before:#?} after={after:#?}"
    );
}

async fn shutdown_cluster(servers: Vec<(u16, TestServer)>) {
    join_all(
        servers
            .into_iter()
            .map(|(_, server)| server.shutdown_gracefully()),
    )
    .await;
}

async fn capture_cluster(
    servers: Vec<(u16, TestServer)>,
    destination_root: &Path,
) -> std::io::Result<()> {
    let results = join_all(servers.into_iter().map(|(node_id, server)| {
        let destination = destination_root.join(format!("node-{node_id}"));
        async move {
            server
                .shutdown_gracefully_and_capture_strict_state(destination)
                .await
        }
    }))
    .await;
    for result in results {
        result?;
    }
    Ok(())
}

async fn assert_baseline_symptom(servers: Vec<(u16, TestServer)>) {
    let before = TrafficSnapshot::capture(node(&servers, 1));
    tokio::time::sleep(BASELINE_OBSERVATION).await;
    let after = TrafficSnapshot::capture(node(&servers, 1));
    let current_versions = versions(&servers);
    eprintln!(
        "strict-live baseline: versions={current_versions:?} before={before:#?} after={after:#?}"
    );
    assert_eq!(
        node(&servers, 5).server.get_channels().current_version(),
        LAGGING_VERSION
    );
    assert_eq!(
        node(&servers, 8).server.get_channels().current_version(),
        LAGGING_VERSION
    );
    for node_id in [5, 8] {
        let status = read_terminal_status(
            &node(&servers, node_id)
                .strict_channel_terminal_journal_path()
                .expect("strict channel terminal journal"),
        )
        .expect("read lagging terminal journal");
        assert!(
            !status.covers_healthy_terminal_state(),
            "node {node_id} unexpectedly acquired complete terminal coverage on the baseline build"
        );
    }
    assert!(after.elections_started > before.elections_started);
    assert!(after.send_attempts > before.send_attempts);
    assert!(after.send_bytes > before.send_bytes);
    shutdown_cluster(servers).await;
}

async fn assert_fixed_resolution(servers: Vec<(u16, TestServer)>, pki: Arc<Pki>) {
    wait_for_repositories(&servers).await;
    wait_for_terminal_coverage(&servers).await;
    assert_all_nodes_can_donate_snapshots(&servers).await;
    assert_multi_interval_quiescence(&servers).await;

    let restart_root = TempDir::new().expect("restart fixture root");
    capture_cluster(servers, restart_root.path())
        .await
        .expect("capture converged strict channel state");

    let restarted = spawn_live_cluster(restart_root.path(), pki, false).await;
    wait_for_cluster(&restarted).await;
    wait_for_repositories(&restarted).await;
    wait_for_terminal_coverage(&restarted).await;
    assert_all_nodes_can_donate_snapshots(&restarted).await;
    assert_multi_interval_quiescence(&restarted).await;

    let (offline, remaining): (Vec<_>, Vec<_>) = restarted
        .into_iter()
        .partition(|(node_id, _)| matches!(node_id, 5 | 8));
    shutdown_cluster(offline).await;
    assert!(
        wait_until(CLUSTER_READY_DEADLINE, || {
            remaining.iter().all(|(_, server)| {
                server
                    .server
                    .s2s_manager()
                    .overlay()
                    .is_some_and(|overlay| {
                        !overlay.alive_members().contains(&5)
                            && !overlay.alive_members().contains(&8)
                    })
            })
        })
        .await,
        "remaining replicas did not mark JP and DFW unavailable"
    );
    wait_for_cluster(&remaining).await;
    assert_multi_interval_quiescence(&remaining).await;
    shutdown_cluster(remaining).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires channel repository and strict terminal journals copied live through SSH"]
async fn strict_live_channel_state_reproduces_and_resolves_dfw_jp_stall() {
    let _guard = s2s_network_test_guard().await;
    let fixture_root = PathBuf::from(
        std::env::var_os("SHITSPEAK_STRICT_LIVE_STATE_ROOT")
            .expect("SHITSPEAK_STRICT_LIVE_STATE_ROOT is required"),
    );
    let expectation = Expectation::from_environment();
    let pki = Arc::new(mint_pki(&NODE_IDS));
    let servers = spawn_live_cluster(&fixture_root, Arc::clone(&pki), true).await;
    wait_for_cluster(&servers).await;

    match expectation {
        Expectation::BaselineStuck => assert_baseline_symptom(servers).await,
        Expectation::FixedConverged => assert_fixed_resolution(servers, pki).await,
    }
}
