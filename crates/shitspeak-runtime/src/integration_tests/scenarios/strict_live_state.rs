//! Ignored full-runtime reproduction for copied production channel state.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future::join_all;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use tempfile::TempDir;

use crate::integration_tests::harness::test_server::copy_sqlite_main_image;
use crate::integration_tests::harness::{
    TestServer, TestServerOpts, TestStrictReplicationState, spawn_s2s_test_server_with_config,
    spawn_s2s_test_server_with_state,
};
use shitspeak_core::{DEFAULT_SERVER_ID, NodeIdentifier};
use shitspeak_runtime_config::{S2sConfig, S2sSeedAddressConfig, S2sTransportKindConfig};
use shitspeak_s2s::replications::strict::StrictDeliveryCheckpointDebug;
use shitspeak_s2s::testing::{
    Pki, loopback, mint_pki, pick_free_port, s2s_network_test_guard, wait_until,
    write_checkpoint_terminal_fixture,
};
use shitspeak_s2s_transport::ServiceLevel;
use shitspeak_state::Channel;

// Preserve the production rank order: the two long-running forwarders win
// equal-head elections ahead of the newer regional replicas.
const PRODUCTION_NODE_RANK_ORDER: [u16; 9] = [4_097, 4_096, 1, 4, 7, 15, 16, 8, 5];
// Deliberately outside the production ID set: this identity has no copied
// repository or terminal journal on the first boot and must recover both over
// the v8 network protocol.
const EMPTY_BOOTSTRAP_NODE_ID: u16 = 4_095;
const CLUSTER_READY_DEADLINE: Duration = Duration::from_secs(90);
const CONVERGENCE_DEADLINE: Duration = Duration::from_secs(300);
const BASELINE_INTERVAL_OBSERVATION: Duration = Duration::from_secs(65);
const QUIET_SETTLE: Duration = Duration::from_secs(20);
const STEADY_STATE_WARMUP: Duration = Duration::from_secs(65);
const MULTI_INTERVAL_OBSERVATION: Duration = Duration::from_secs(125);
const QUIET_SEND_BYTES_PER_DIRECTED_PEER: f64 = (1024.0 * 1024.0) / 72.0;
const STRICT_RECOVERY_PROTOCOL_VERSION: u32 = 8;
const POST_RECOVERY_CHANNEL_ID: u32 = 4_000_000_015;

const NODE_15_CURRENT_ORIGIN: [u8; 8] = [0x00, 0x0f, 0x58, 0x84, 0x53, 0xec, 0xe6, 0x7e];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expectation {
    BaselineStuck,
    FixedConverged,
}

#[derive(Clone, Copy)]
enum StagedStateExpectation {
    Incident,
    Recovered,
}

#[derive(Debug)]
struct LiveFixture {
    active_node_ids: Vec<u16>,
    down_node_ids: Vec<u16>,
    initial_repository_versions: HashMap<u16, u64>,
    healthy_version: u64,
    healthy_freshness: i64,
    healthy_donor: u16,
    healthy_terminal_cut: TerminalCutStatus,
    eventual_target_nodes: Vec<u16>,
    healthy_lineage_nodes: Vec<u16>,
    foreign_lineage_nodes: Vec<u16>,
    lagging_nodes: Vec<u16>,
}

impl LiveFixture {
    fn recovery_node_ids(&self) -> Vec<u16> {
        let mut node_ids = Vec::with_capacity(self.active_node_ids.len() + 1);
        // Keep the recovered empty node first in the final acceptance order so
        // it is also the post-recovery strict proposal source. Staged startup
        // order is selected separately by `spawn_staged_fixed_cluster`.
        node_ids.push(EMPTY_BOOTSTRAP_NODE_ID);
        node_ids.push(self.healthy_donor);
        node_ids.extend(
            self.active_node_ids
                .iter()
                .copied()
                .filter(|node_id| *node_id != self.healthy_donor),
        );
        node_ids
    }
}

fn fixed_initial_witness_node_ids(topology_node_ids: &[u16]) -> Vec<u16> {
    topology_node_ids
        .iter()
        .copied()
        .filter(|node_id| *node_id != EMPTY_BOOTSTRAP_NODE_ID && *node_id != 15)
        .collect()
}

#[test]
fn fixed_staging_starts_copied_witnesses_before_empty_and_foreign_nodes() {
    let topology_node_ids = [4_095, 4_096, 4_097, 1, 4, 7, 15, 16, 8, 5];
    assert_eq!(
        fixed_initial_witness_node_ids(&topology_node_ids),
        [4_096, 4_097, 1, 4, 7, 16, 8, 5]
    );
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
    snapshot_source_rejections: f64,
    snapshot_transfer_rejections: f64,
    recovery_events: f64,
    recovery_topics_active: f64,
    recovery_certifying_topics: f64,
    recovery_terminal_topics: f64,
    recovery_snapshot_topics: f64,
    recovery_attempts: f64,
    recovery_retransmits: f64,
    recovery_send_attempts: f64,
    recovery_send_bytes: f64,
    recovery_certificate_failures: f64,
    recovery_stale_events: f64,
    recovery_donor_sessions_active: f64,
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
            snapshot_source_rejections: metric_total(
                server,
                "shitspeak_s2s_strict_replication_snapshot_receive_events_total",
                &[("event", "source_rejected")],
            ),
            snapshot_transfer_rejections: metric_total(
                server,
                "shitspeak_s2s_strict_replication_snapshot_responder_events_total",
                &[("event", "transfer_rejected")],
            ),
            recovery_events: recovery_event_total(server),
            recovery_topics_active: active_recovery_topic_total(server),
            recovery_certifying_topics: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_phase_topics",
                &[("phase", "certifying")],
            ),
            recovery_terminal_topics: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_phase_topics",
                &[("phase", "fetching_terminal_checkpoint")],
            ),
            recovery_snapshot_topics: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_phase_topics",
                &[("phase", "fetching_repository_snapshot")],
            ),
            recovery_attempts: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_attempts_total",
                &[],
            ),
            recovery_retransmits: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_retransmits_total",
                &[],
            ),
            recovery_send_attempts: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_send_attempts_total",
                &[],
            ),
            recovery_send_bytes: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_send_bytes_total",
                &[],
            ),
            recovery_certificate_failures: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_certificate_failures_total",
                &[],
            ),
            recovery_stale_events: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_stale_events_total",
                &[],
            ),
            recovery_donor_sessions_active: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_donor_sessions_active",
                &[],
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct TerminalCutStatus {
    journal_id: Vec<u8>,
    generation: u64,
    chain_digest: Vec<u8>,
    terminal_set_digest: Vec<u8>,
}

impl TerminalCutStatus {
    fn is_same_lineage_prefix_of(&self, target: &Self) -> bool {
        self.journal_id == target.journal_id
            && self.generation <= target.generation
            && (self.generation != target.generation
                || (self.chain_digest == target.chain_digest
                    && self.terminal_set_digest == target.terminal_set_digest))
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

#[derive(Debug)]
struct RecoveryArtifactStatus {
    repository_version: u64,
    history_freshness: u64,
}

impl TerminalStatus {
    fn cut(&self) -> TerminalCutStatus {
        TerminalCutStatus {
            journal_id: self.journal_id.clone(),
            generation: self.generation,
            chain_digest: self.chain_digest.clone(),
            terminal_set_digest: self.terminal_set_digest.clone(),
        }
    }

    fn has_same_terminal_cut_and_digest(&self, other: &Self) -> bool {
        self.journal_id == other.journal_id
            && self.generation == other.generation
            && self.chain_digest == other.chain_digest
            && self.terminal_set_digest == other.terminal_set_digest
    }

    fn covers_healthy_terminal_state(
        &self,
        healthy_version: u64,
        healthy_cut: &TerminalCutStatus,
    ) -> bool {
        if self.repository_image_install_pending {
            return false;
        }
        let covers_node_15 = self
            .node_15_retired_floor
            .is_some_and(|counter| counter >= 3)
            || [1, 2, 3]
                .iter()
                .all(|counter| self.node_15_record_counters.binary_search(counter).is_ok());
        self.cut() == *healthy_cut
            && self
                .checkpoint_repository_version
                .is_none_or(|version| version <= healthy_version)
            && covers_node_15
    }
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
        if entry["server_id"].as_str() == Some(DEFAULT_SERVER_ID) {
            version = version.max(
                entry["version"]
                    .as_u64()
                    .expect("copied channel WAL version"),
            );
        }
    }
    version
}

fn fixture_history_freshness(directory: &Path) -> i64 {
    let snapshot: serde_json::Value = serde_json::from_slice(
        &std::fs::read(directory.join("channels.snapshot.json"))
            .expect("read copied channel snapshot"),
    )
    .expect("parse copied channel snapshot");
    let mut freshness = snapshot["history_freshness"][DEFAULT_SERVER_ID]
        .as_i64()
        .expect("copied channel snapshot default history freshness");
    let wal = std::fs::read_to_string(directory.join("channels.wal.jsonl"))
        .expect("read copied channel WAL");
    for line in wal.lines().filter(|line| !line.trim().is_empty()) {
        let entry: serde_json::Value =
            serde_json::from_str(line).expect("parse copied channel WAL entry");
        if entry["server_id"].as_str() == Some(DEFAULT_SERVER_ID) {
            freshness = freshness.max(
                entry["timestamp"]
                    .as_i64()
                    .expect("copied channel WAL timestamp"),
            );
        }
    }
    freshness
}

fn ban_fixture_version(directory: &Path) -> u64 {
    let connection =
        Connection::open(directory.join("bans.sqlite3")).expect("open copied Ban repository");
    connection
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM ban_operations",
            [],
            |row| row.get::<_, i64>(0).map(|version| version.max(0) as u64),
        )
        .expect("read copied Ban repository version")
}

fn configured_active_node_ids() -> Vec<u16> {
    let configured = std::env::var("SHITSPEAK_STRICT_LIVE_ACTIVE_NODE_IDS")
        .expect("SHITSPEAK_STRICT_LIVE_ACTIVE_NODE_IDS is required");
    let mut requested = HashSet::new();
    for value in configured.split(',').map(str::trim) {
        assert!(
            !value.is_empty(),
            "SHITSPEAK_STRICT_LIVE_ACTIVE_NODE_IDS contains an empty node id"
        );
        let node_id = value
            .parse::<u16>()
            .unwrap_or_else(|error| panic!("invalid active node id {value:?}: {error}"));
        assert!(
            PRODUCTION_NODE_RANK_ORDER.contains(&node_id),
            "active node {node_id} is not in the production rank order"
        );
        assert!(requested.insert(node_id), "duplicate active node {node_id}");
    }
    assert!(!requested.is_empty(), "active node set must not be empty");
    assert!(
        requested.len() >= 3,
        "strict live recovery requires at least two witnesses and one recovering node"
    );

    PRODUCTION_NODE_RANK_ORDER
        .into_iter()
        .filter(|node_id| requested.contains(node_id))
        .collect()
}

fn copy_live_fixture(source_root: &Path, destination_root: &Path, node_ids: &[u16]) {
    for node_id in node_ids {
        let source = source_root.join(format!("node-{node_id}"));
        let destination = destination_root.join(format!("node-{node_id}"));
        std::fs::create_dir_all(&destination).expect("create derived incident node directory");
        for file_name in ["channels.snapshot.json", "channels.wal.jsonl"] {
            std::fs::copy(source.join(file_name), destination.join(file_name)).unwrap_or_else(
                |error| panic!("copy node {node_id} {file_name} into derived incident: {error}"),
            );
        }
        copy_sqlite_main_image(
            &source.join("terminal-channels.sqlite3"),
            &destination.join("terminal-channels.sqlite3"),
        )
        .unwrap_or_else(|error| {
            panic!("copy node {node_id} terminal-channels.sqlite3 into derived incident: {error}")
        });
    }
}

#[test]
fn live_fixture_copy_includes_wal_resident_terminal_updates() {
    let source_root = TempDir::new().expect("source fixture root");
    let source = source_root.path().join("node-1");
    std::fs::create_dir_all(&source).expect("create source node directory");
    std::fs::write(source.join("channels.snapshot.json"), b"snapshot")
        .expect("write channel snapshot");
    std::fs::write(source.join("channels.wal.jsonl"), b"wal").expect("write channel WAL");
    let source_terminal = source.join("terminal-channels.sqlite3");
    let source_connection = Connection::open(&source_terminal).expect("open source terminal");
    source_connection
        .execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA wal_autocheckpoint = 0;
             CREATE TABLE terminal_state (value TEXT NOT NULL);
             INSERT INTO terminal_state VALUES ('checkpointed');
             PRAGMA wal_checkpoint(TRUNCATE);",
        )
        .expect("create checkpointed terminal state");
    let checkpointed_main = std::fs::read(&source_terminal).expect("read checkpointed main");
    source_connection
        .execute("UPDATE terminal_state SET value = 'wal-resident'", [])
        .expect("write WAL-resident update");
    assert_eq!(
        std::fs::read(&source_terminal).expect("reread source main"),
        checkpointed_main
    );
    assert!(
        std::fs::metadata(source_terminal.with_extension("sqlite3-wal"))
            .expect("source WAL metadata")
            .len()
            > 32
    );
    let source_wal =
        std::fs::read(source_terminal.with_extension("sqlite3-wal")).expect("read source WAL");

    let destination_root = TempDir::new().expect("destination fixture root");
    copy_live_fixture(source_root.path(), destination_root.path(), &[1]);

    let copied_terminal = destination_root
        .path()
        .join("node-1")
        .join("terminal-channels.sqlite3");
    assert!(!copied_terminal.with_extension("sqlite3-wal").exists());
    assert!(!copied_terminal.with_extension("sqlite3-shm").exists());
    let copied_connection = Connection::open(copied_terminal).expect("open copied terminal");
    assert_eq!(
        copied_connection
            .query_row("SELECT value FROM terminal_state", [], |row| {
                row.get::<_, String>(0)
            })
            .expect("read copied terminal state"),
        "wal-resident"
    );
    assert_eq!(
        std::fs::read(&source_terminal).expect("read preserved source main"),
        checkpointed_main
    );
    assert_eq!(
        std::fs::read(source_terminal.with_extension("sqlite3-wal"))
            .expect("read preserved source WAL"),
        source_wal
    );
}

fn prepare_incident_fixture(source_root: &Path) -> TempDir {
    let active_node_ids = configured_active_node_ids();
    let incident = TempDir::new().expect("derived strict incident fixture root");
    copy_live_fixture(source_root, incident.path(), &active_node_ids);

    let statuses = active_node_ids
        .iter()
        .map(|node_id| {
            read_terminal_status(
                &incident
                    .path()
                    .join(format!("node-{node_id}"))
                    .join("terminal-channels.sqlite3"),
            )
            .unwrap_or_else(|error| panic!("read copied node {node_id} terminal fixture: {error}"))
        })
        .collect::<Vec<_>>();
    let healthy_target = active_node_ids
        .iter()
        .zip(&statuses)
        .filter(|(node_id, _)| **node_id != 15)
        .max_by_key(|(_, status)| status.generation)
        .map(|(_, status)| status.cut())
        .expect("non-node-15 terminal lineage target");
    let node_15_cut = active_node_ids
        .iter()
        .position(|node_id| *node_id == 15)
        .map(|index| statuses[index].cut());
    let node_15_is_on_healthy_lineage = node_15_cut.as_ref().is_some_and(|cut| {
        cut.is_same_lineage_prefix_of(&healthy_target)
            || healthy_target.is_same_lineage_prefix_of(cut)
    });
    if node_15_is_on_healthy_lineage {
        let healthy_witnesses = active_node_ids
            .iter()
            .filter(|node_id| **node_id != 15)
            .count();
        assert!(
            healthy_witnesses >= 2,
            "derived recovery incident requires at least two healthy witnesses"
        );
        let repository_version = fixture_repository_version(&incident.path().join("node-15"));
        write_checkpoint_terminal_fixture(
            incident
                .path()
                .join("node-15")
                .join("terminal-channels.sqlite3"),
            "channels",
            repository_version,
        )
        .expect("write valid foreign generation-zero journal for node 15");
        let foreign = read_terminal_status(
            &incident
                .path()
                .join("node-15")
                .join("terminal-channels.sqlite3"),
        )
        .expect("read derived foreign node 15 terminal fixture");
        assert_eq!(foreign.generation, 0);
        assert_eq!(foreign.chain_digest, [0; 32]);
        assert!(!foreign.cut().is_same_lineage_prefix_of(&healthy_target));
        assert_eq!(
            fixture_repository_version(&incident.path().join("node-15")),
            repository_version
        );
    }

    incident
}

fn derive_eventual_target(
    active_node_ids: &[u16],
    fixture_heads: &[(u16, u64)],
    terminal_cuts: &[(u16, TerminalCutStatus)],
) -> (u16, TerminalCutStatus, Vec<u16>) {
    let maximum_repository_version = fixture_heads
        .iter()
        .map(|(_, version)| *version)
        .max()
        .expect("active fixture head");
    let versions = fixture_heads.iter().copied().collect::<HashMap<_, _>>();
    let mut candidates = terminal_cuts
        .iter()
        .filter(|(node_id, _)| versions[node_id] == maximum_repository_version)
        .map(|(node_id, cut)| {
            let support = terminal_cuts
                .iter()
                .filter(|(_, candidate)| candidate.is_same_lineage_prefix_of(cut))
                .count();
            (*node_id, cut.clone(), support)
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right.2.cmp(&left.2).then_with(|| {
            active_node_ids
                .iter()
                .position(|node_id| *node_id == left.0)
                .cmp(
                    &active_node_ids
                        .iter()
                        .position(|node_id| *node_id == right.0),
                )
        })
    });
    let (donor, target_cut, _) = candidates
        .first()
        .cloned()
        .expect("freshest same-lineage representation donor");
    let eventual_witnesses = terminal_cuts
        .iter()
        .filter_map(|(node_id, cut)| {
            cut.is_same_lineage_prefix_of(&target_cut)
                .then_some(*node_id)
        })
        .collect();
    (donor, target_cut, eventual_witnesses)
}

#[test]
fn eventual_target_counts_same_lineage_nodes_after_ordinary_catchup() {
    let heads = [
        (4_097, 10_980),
        (4_096, 10_990),
        (1, 10_990),
        (4, 10_990),
        (7, 10_980),
        (15, 10_990),
        (16, 10_990),
        (8, 10_980),
        (5, 10_977),
    ];
    let target_cut = TerminalCutStatus {
        journal_id: vec![1; 16],
        generation: 4_106,
        chain_digest: vec![2; 32],
        terminal_set_digest: vec![3; 32],
    };
    let prefix_cut = |generation, marker| TerminalCutStatus {
        journal_id: target_cut.journal_id.clone(),
        generation,
        chain_digest: vec![marker; 32],
        terminal_set_digest: vec![marker.wrapping_add(1); 32],
    };
    // Exact live capture groups: four current same-lineage heads, four older
    // prefixes, and derived node 15 on a different generation-zero journal.
    let cuts = vec![
        (4_097, prefix_cut(4_096, 10)),
        (4_096, target_cut.clone()),
        (1, target_cut.clone()),
        (4, target_cut.clone()),
        (7, prefix_cut(4_096, 10)),
        (
            15,
            TerminalCutStatus {
                journal_id: vec![9; 16],
                generation: 0,
                chain_digest: vec![0; 32],
                terminal_set_digest: vec![8; 32],
            },
        ),
        (16, target_cut.clone()),
        (8, prefix_cut(4_096, 10)),
        (5, prefix_cut(4_093, 20)),
    ];
    let (donor, derived_target, eventual_witnesses) =
        derive_eventual_target(&PRODUCTION_NODE_RANK_ORDER, &heads, &cuts);
    assert_eq!(donor, 4_096);
    assert_eq!(derived_target, target_cut);
    assert_eq!(eventual_witnesses.len(), 8);
    assert!(!eventual_witnesses.contains(&15));
    assert_eq!(
        heads
            .iter()
            .filter(|(node_id, version)| {
                *version == 10_990 && eventual_witnesses.contains(node_id)
            })
            .count(),
        4,
        "the initial exact target lacks quorum even though ordinary catch-up makes eight witnesses eligible"
    );
}

fn load_live_fixture(fixture_root: &Path) -> LiveFixture {
    let active_node_ids = configured_active_node_ids();
    let requested = active_node_ids.iter().copied().collect::<HashSet<_>>();

    let down_node_ids = PRODUCTION_NODE_RANK_ORDER
        .into_iter()
        .filter(|node_id| !requested.contains(node_id))
        .collect::<Vec<_>>();

    let fixture_heads = active_node_ids
        .iter()
        .map(|node_id| {
            let directory = fixture_root.join(format!("node-{node_id}"));
            for file_name in [
                "channels.snapshot.json",
                "channels.wal.jsonl",
                "terminal-channels.sqlite3",
            ] {
                assert!(
                    directory.join(file_name).is_file(),
                    "active node {node_id} fixture is missing {file_name}"
                );
            }
            (*node_id, fixture_repository_version(&directory))
        })
        .collect::<Vec<_>>();
    let maximum_repository_version = fixture_heads
        .iter()
        .map(|(_, version)| *version)
        .max()
        .expect("active fixture head");
    let initial_repository_versions = fixture_heads.iter().copied().collect::<HashMap<_, _>>();
    let fixture_terminal_statuses = active_node_ids
        .iter()
        .map(|node_id| {
            let status = read_terminal_status(
                &fixture_root
                    .join(format!("node-{node_id}"))
                    .join("terminal-channels.sqlite3"),
            )
            .unwrap_or_else(|error| panic!("read active node {node_id} terminal fixture: {error}"));
            (*node_id, status)
        })
        .collect::<Vec<_>>();
    // The copied repository heads are a capture-time observation, not a
    // recovery certificate. Same-lineage replicas may first advance through
    // ordinary catch-up. Select the eventual target from the freshest copied
    // head whose terminal-journal lineage has the greatest cluster support,
    // including older same-lineage prefixes, then
    // let the v8 protocol certify that target after catch-up.
    let terminal_cuts = fixture_terminal_statuses
        .iter()
        .map(|(node_id, status)| (*node_id, status.cut()))
        .collect::<Vec<_>>();
    let (healthy_donor, healthy_terminal_cut, eventual_target_nodes) =
        derive_eventual_target(&active_node_ids, &fixture_heads, &terminal_cuts);
    let healthy_version = maximum_repository_version;
    let healthy_freshness =
        fixture_history_freshness(&fixture_root.join(format!("node-{healthy_donor}")));
    let lagging_nodes = fixture_heads
        .iter()
        .filter_map(|(node_id, version)| {
            (*version < healthy_version && eventual_target_nodes.contains(node_id))
                .then_some(*node_id)
        })
        .collect::<Vec<_>>();
    let healthy_lineage_nodes = fixture_terminal_statuses
        .iter()
        .filter_map(|(node_id, status)| {
            status
                .cut()
                .is_same_lineage_prefix_of(&healthy_terminal_cut)
                .then_some(*node_id)
        })
        .collect::<Vec<_>>();
    let foreign_lineage_nodes = fixture_terminal_statuses
        .iter()
        .filter_map(|(node_id, status)| {
            (!status
                .cut()
                .is_same_lineage_prefix_of(&healthy_terminal_cut))
            .then_some(*node_id)
        })
        .collect::<Vec<_>>();
    assert!(
        !foreign_lineage_nodes.is_empty(),
        "derived fixture does not contain a foreign terminal lineage: {fixture_terminal_statuses:#?}"
    );
    LiveFixture {
        active_node_ids,
        down_node_ids,
        initial_repository_versions,
        healthy_version,
        healthy_freshness,
        healthy_donor,
        healthy_terminal_cut,
        eventual_target_nodes,
        healthy_lineage_nodes,
        foreign_lineage_nodes,
        lagging_nodes,
    }
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

fn read_recovery_artifact_status(path: &Path) -> rusqlite::Result<RecoveryArtifactStatus> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    connection.busy_timeout(Duration::from_secs(1))?;
    connection.query_row(
        "SELECT repository_version, history_freshness
         FROM strict_recovery_artifact WHERE singleton = 1",
        [],
        |row| {
            Ok(RecoveryArtifactStatus {
                repository_version: decode_u64(row.get(0)?)?,
                history_freshness: decode_u64(row.get(1)?)?,
            })
        },
    )
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

fn active_recovery_topic_total(server: &TestServer) -> f64 {
    [
        "certifying",
        "fetching_terminal_checkpoint",
        "fetching_repository_snapshot",
        "prepared",
        "installing",
        "verifying",
        "backoff",
    ]
    .into_iter()
    .map(|phase| {
        metric_total(
            server,
            "shitspeak_s2s_strict_replication_recovery_phase_topics",
            &[("phase", phase)],
        )
    })
    .sum()
}

fn recovery_event_total(server: &TestServer) -> f64 {
    [
        "shitspeak_s2s_strict_replication_recovery_attempts_total",
        "shitspeak_s2s_strict_replication_recovery_coalesced_triggers_total",
        "shitspeak_s2s_strict_replication_recovery_retransmits_total",
        "shitspeak_s2s_strict_replication_recovery_donor_switches_total",
        "shitspeak_s2s_strict_replication_recovery_certificate_failures_total",
        "shitspeak_s2s_strict_replication_recovery_stale_events_total",
    ]
    .into_iter()
    .map(|metric| metric_total(server, metric, &[]))
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
    fixture: &LiveFixture,
    node_ids: &[u16],
    staged_state_expectation: StagedStateExpectation,
) -> Vec<(u16, TestServer)> {
    let mut addresses = Vec::with_capacity(node_ids.len());
    for _ in node_ids {
        addresses.push(loopback(pick_free_port().await));
    }

    spawn_live_nodes(
        fixture_root,
        pki,
        fixture,
        node_ids,
        &addresses,
        node_ids,
        staged_state_expectation,
    )
    .await
}

async fn spawn_live_nodes(
    fixture_root: &Path,
    pki: Arc<Pki>,
    fixture: &LiveFixture,
    topology_node_ids: &[u16],
    addresses: &[SocketAddr],
    node_ids: &[u16],
    staged_state_expectation: StagedStateExpectation,
) -> Vec<(u16, TestServer)> {
    assert_eq!(topology_node_ids.len(), addresses.len());
    let mut servers = Vec::with_capacity(node_ids.len());
    for node_id in node_ids.iter().copied() {
        let cert_index = topology_node_ids
            .iter()
            .position(|candidate| *candidate == node_id)
            .unwrap_or_else(|| panic!("node {node_id} is absent from the live topology"));
        let state_directory = fixture_root.join(format!("node-{node_id}"));
        let has_staged_state = state_directory.join("channels.snapshot.json").is_file();
        let server = if has_staged_state {
            let copied_version = fixture_repository_version(&state_directory);
            if fixture.active_node_ids.contains(&node_id) {
                match staged_state_expectation {
                    StagedStateExpectation::Incident => assert_eq!(
                        Some(&copied_version),
                        fixture.initial_repository_versions.get(&node_id),
                        "node {node_id} copied repository fixture has an unexpected incident head"
                    ),
                    StagedStateExpectation::Recovered => assert_eq!(
                        copied_version, fixture.healthy_version,
                        "node {node_id} copied repository fixture has an unexpected recovered head"
                    ),
                }
            } else {
                assert_eq!(
                    node_id, EMPTY_BOOTSTRAP_NODE_ID,
                    "unexpected non-production persisted node"
                );
                assert_eq!(
                    copied_version, fixture.healthy_version,
                    "restarted bootstrap node did not persist the recovered repository head"
                );
            }
            let server = spawn_s2s_test_server_with_state(
                TestServerOpts::default(),
                Arc::clone(&pki),
                node_id,
                cert_index,
                production_s2s_config(addresses[cert_index], &addresses),
                TestStrictReplicationState::from_directory(&state_directory),
            )
            .await;
            let initial_version = server
                .server
                .get_channels()
                .current_version_in_server(crate::types::DEFAULT_SERVER_ID);
            if copied_version < fixture.healthy_version {
                assert!(
                    (copied_version..=fixture.healthy_version).contains(&initial_version),
                    "node {node_id} opened outside the copied-to-healthy catch-up range"
                );
            } else {
                assert_eq!(
                    initial_version, copied_version,
                    "node {node_id} did not open the copied repository head unchanged"
                );
            }
            server
        } else {
            assert_eq!(
                node_id, EMPTY_BOOTSTRAP_NODE_ID,
                "copied production node {node_id} has no staged repository"
            );
            let server = spawn_s2s_test_server_with_config(
                TestServerOpts::default(),
                Arc::clone(&pki),
                node_id,
                cert_index,
                production_s2s_config(addresses[cert_index], &addresses),
            )
            .await;
            assert_eq!(
                server
                    .server
                    .get_channels()
                    .current_version_in_server(crate::types::DEFAULT_SERVER_ID),
                0,
                "network-bootstrap node did not start with an empty repository"
            );
            assert!(
                server.strict_channel_terminal_journal_path().is_some(),
                "network-bootstrap node did not create a fresh terminal journal"
            );
            server
        };
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
    assert!(
        ready,
        "copied-state cluster did not become ready: {:?}",
        live_node_diagnostics(servers)
    );
}

fn assert_recovery_v8_floor(servers: &[(u16, TestServer)]) {
    for (node_id, server) in servers {
        let protocol_version = server
            .server
            .s2s_manager()
            .replications()
            .expect("ready strict replications")
            .strict_protocol_version();
        assert!(
            protocol_version >= STRICT_RECOVERY_PROTOCOL_VERSION,
            "node {node_id} negotiated strict protocol v{protocol_version}, below the recovery-v8 floor"
        );
    }
}

fn assert_down_nodes_absent(servers: &[(u16, TestServer)], fixture: &LiveFixture) {
    for (node_id, server) in servers {
        let overlay = server
            .server
            .s2s_manager()
            .overlay()
            .expect("ready cluster overlay");
        for down_node_id in &fixture.down_node_ids {
            assert!(
                !overlay.alive_members().contains(down_node_id),
                "active node {node_id} unexpectedly reports down node {down_node_id} alive"
            );
        }
    }
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
        .map(|(node_id, server)| {
            (
                *node_id,
                server
                    .server
                    .get_channels()
                    .current_version_in_server(crate::types::DEFAULT_SERVER_ID),
            )
        })
        .collect()
}

#[derive(Debug)]
#[allow(dead_code)] // Fields are intentionally consumed by the derived panic diagnostic.
struct LiveNodeDiagnostic {
    node_id: u16,
    repository_version: u64,
    terminal_cut: String,
    repository_image_install_pending: Option<bool>,
    recovery_healthy: Option<bool>,
    recovery_phase: Option<&'static str>,
    recovery_attempt_id: Option<u64>,
    recovery_progress_remaining_ms: Option<u64>,
    recovery_frozen_denominator: Option<usize>,
    recovery_certificate_witnesses: Option<usize>,
    recovery_donor: Option<(u64, u64)>,
    recovery_donor_index: Option<usize>,
    recovery_failure_count: Option<usize>,
    recovery_last_failure: Option<&'static str>,
    terminal_storage_healthy: Option<bool>,
    history_election_pending: Option<bool>,
    history_election_active: Option<bool>,
    history_probe_pending_peers: Option<usize>,
    history_alive_peers: Option<usize>,
    history_election_phase: Option<&'static str>,
    history_election_peer: Option<NodeIdentifier>,
    history_client_transfers: Option<Vec<(NodeIdentifier, u64, i32, u64, u64, bool)>>,
    history_pending_intents: Option<Vec<(NodeIdentifier, u64, i32, u64, u64)>>,
    history_retry_requests: Option<Vec<(NodeIdentifier, u64, u64, u64, u32)>>,
    terminal_client_transfers: Option<Vec<(NodeIdentifier, u64, &'static str, i32, u64, u64)>>,
    snapshot_donation_available: Option<bool>,
}

#[derive(Debug)]
#[allow(dead_code)] // Fields are intentionally consumed by the derived panic diagnostic.
struct RecoveryTrafficDiagnostic {
    attempts: f64,
    coalesced_triggers: f64,
    certificate_failures: f64,
    donor_switches: f64,
    terminal_retransmits: f64,
    snapshot_retransmits: f64,
    stale_events: f64,
    completions: f64,
}

#[derive(Clone, Copy, Debug, Default)]
struct AnalysisBudgetCounters {
    send_bytes: f64,
    send_attempts: f64,
    recovery_send_bytes: f64,
    recovery_send_attempts: f64,
    catchup_requests: f64,
    catchup_responses: f64,
    recovery_attempts: f64,
    recovery_retransmits: f64,
    recovery_completion_ms: f64,
    recovery_completions: f64,
}

#[derive(Clone, Copy)]
struct AnalysisBudget {
    consensus_elapsed_ms: u128,
    traffic_bytes: f64,
    recovery_retransmits: f64,
}

fn analysis_budget(phase: &str) -> AnalysisBudget {
    match phase {
        "copied_witness_convergence" => AnalysisBudget {
            consensus_elapsed_ms: 30_000,
            traffic_bytes: 12_000_000.0,
            recovery_retransmits: 0.0,
        },
        "empty_node_network_bootstrap" | "foreign_lineage_recovery" => AnalysisBudget {
            consensus_elapsed_ms: 30_000,
            // Includes the exact v8 terminal checkpoint, repository envelope,
            // redundant control copies, and ordinary strict catch-up traffic.
            traffic_bytes: 5_000_000.0,
            recovery_retransmits: 0.0,
        },
        "full_cluster_restart" => AnalysisBudget {
            consensus_elapsed_ms: 25_000,
            traffic_bytes: 1_000_000.0,
            recovery_retransmits: 0.0,
        },
        "donor_removal" => AnalysisBudget {
            consensus_elapsed_ms: 5_000,
            traffic_bytes: 128_000.0,
            recovery_retransmits: 0.0,
        },
        "post_recovery_strict_write" => AnalysisBudget {
            consensus_elapsed_ms: 10_000,
            traffic_bytes: 256_000.0,
            recovery_retransmits: 0.0,
        },
        _ => panic!("missing strict-live analysis budget for phase {phase}"),
    }
}

impl AnalysisBudgetCounters {
    fn capture(servers: &[(u16, TestServer)]) -> Self {
        let Some((_, server)) = servers.first() else {
            return Self::default();
        };
        Self {
            send_bytes: metric_total(
                server,
                "shitspeak_s2s_strict_replication_catchup_send_bytes_total",
                &[],
            ),
            send_attempts: metric_total(
                server,
                "shitspeak_s2s_strict_replication_catchup_send_attempts_total",
                &[],
            ),
            recovery_send_bytes: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_send_bytes_total",
                &[],
            ),
            recovery_send_attempts: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_send_attempts_total",
                &[],
            ),
            catchup_requests: metric_total(
                server,
                "shitspeak_s2s_replication_catchup_requests_total",
                &[],
            ),
            catchup_responses: metric_total(
                server,
                "shitspeak_s2s_replication_catchup_responses_total",
                &[],
            ),
            recovery_attempts: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_attempts_total",
                &[],
            ),
            recovery_retransmits: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_retransmits_total",
                &[],
            ),
            recovery_completion_ms: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_completion_duration_ms_total",
                &[],
            ),
            recovery_completions: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_completion_duration_count",
                &[],
            ),
        }
    }
}

fn record_analysis_budget_observation(
    phase: &str,
    started_at: Instant,
    before: AnalysisBudgetCounters,
    servers: &[(u16, TestServer)],
) {
    let after = AnalysisBudgetCounters::capture(servers);
    let consensus_elapsed_ms = started_at.elapsed().as_millis();
    let catchup_traffic_bytes = after.send_bytes - before.send_bytes;
    let recovery_traffic_bytes = after.recovery_send_bytes - before.recovery_send_bytes;
    let traffic_bytes = catchup_traffic_bytes + recovery_traffic_bytes;
    let recovery_retransmits = after.recovery_retransmits - before.recovery_retransmits;
    eprintln!(
        "strict-live analysis-budget phase={phase} consensus_elapsed_ms={} \
         traffic_bytes={} catchup_traffic_bytes={} recovery_traffic_bytes={} \
         send_attempts={} recovery_send_attempts={} catchup_requests={} catchup_responses={} \
         recovery_attempts={} recovery_retransmits={} recovery_completion_ms={} recovery_completions={}",
        consensus_elapsed_ms,
        traffic_bytes,
        catchup_traffic_bytes,
        recovery_traffic_bytes,
        after.send_attempts - before.send_attempts,
        after.recovery_send_attempts - before.recovery_send_attempts,
        after.catchup_requests - before.catchup_requests,
        after.catchup_responses - before.catchup_responses,
        after.recovery_attempts - before.recovery_attempts,
        recovery_retransmits,
        after.recovery_completion_ms - before.recovery_completion_ms,
        after.recovery_completions - before.recovery_completions,
    );
    if matches!(
        phase,
        "empty_node_network_bootstrap" | "foreign_lineage_recovery"
    ) {
        assert!(
            after.recovery_attempts > before.recovery_attempts,
            "strict-live {phase} did not start mandatory v8 recovery"
        );
        assert!(
            after.recovery_completions > before.recovery_completions,
            "strict-live {phase} did not complete the mandatory v8 recovery state machine"
        );
        assert!(
            recovery_traffic_bytes > 0.0,
            "strict-live {phase} emitted no terminal/snapshot recovery traffic"
        );
    }
    let budget = analysis_budget(phase);
    assert!(
        consensus_elapsed_ms <= budget.consensus_elapsed_ms,
        "strict-live {phase} exceeded consensus budget: observed={consensus_elapsed_ms}ms budget={}ms",
        budget.consensus_elapsed_ms,
    );
    assert!(
        traffic_bytes <= budget.traffic_bytes,
        "strict-live {phase} exceeded traffic budget: observed={traffic_bytes} bytes budget={} bytes",
        budget.traffic_bytes,
    );
    assert!(
        recovery_retransmits <= budget.recovery_retransmits,
        "strict-live {phase} exceeded recovery retransmit budget: observed={recovery_retransmits} budget={}",
        budget.recovery_retransmits,
    );
}

impl RecoveryTrafficDiagnostic {
    fn capture(server: &TestServer) -> Self {
        Self {
            attempts: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_attempts_total",
                &[],
            ),
            coalesced_triggers: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_coalesced_triggers_total",
                &[],
            ),
            certificate_failures: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_certificate_failures_total",
                &[],
            ),
            donor_switches: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_donor_switches_total",
                &[],
            ),
            terminal_retransmits: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_retransmits_total",
                &[("phase", "fetching_terminal_checkpoint")],
            ),
            snapshot_retransmits: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_retransmits_total",
                &[("phase", "fetching_repository_snapshot")],
            ),
            stale_events: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_stale_events_total",
                &[],
            ),
            completions: metric_total(
                server,
                "shitspeak_s2s_strict_replication_recovery_completion_duration_count",
                &[],
            ),
        }
    }
}

fn abbreviated_hex(bytes: &[u8]) -> String {
    let length = bytes.len().min(8);
    let mut value = hex::encode(&bytes[..length]);
    if bytes.len() > length {
        value.push_str("...");
    }
    value
}

fn live_node_diagnostics(servers: &[(u16, TestServer)]) -> Vec<LiveNodeDiagnostic> {
    servers
        .iter()
        .map(|(node_id, server)| {
            let terminal = server
                .strict_channel_terminal_journal_path()
                .ok_or_else(|| "unavailable".to_owned())
                .and_then(|path| read_terminal_status(&path).map_err(|error| error.to_string()));
            let (terminal_cut, repository_image_install_pending) = match terminal {
                Ok(status) => (
                    format!(
                        "journal={} generation={} chain={} set={}",
                        hex::encode(status.journal_id),
                        status.generation,
                        abbreviated_hex(&status.chain_digest),
                        abbreviated_hex(&status.terminal_set_digest),
                    ),
                    Some(status.repository_image_install_pending),
                ),
                Err(error) => (format!("error={error}"), None),
            };
            let debug = server
                .server
                .s2s_manager()
                .strict_channel_debug_state_for_test(DEFAULT_SERVER_ID);
            LiveNodeDiagnostic {
                node_id: *node_id,
                repository_version: server
                    .server
                    .get_channels()
                    .current_version_in_server(crate::types::DEFAULT_SERVER_ID),
                terminal_cut,
                repository_image_install_pending,
                recovery_healthy: debug.as_ref().map(|state| state.recovery_healthy()),
                recovery_phase: debug.as_ref().map(|state| state.recovery_phase()),
                recovery_attempt_id: debug.as_ref().and_then(|state| state.recovery_attempt_id()),
                recovery_progress_remaining_ms: debug
                    .as_ref()
                    .and_then(|state| state.recovery_progress_remaining_ms()),
                recovery_frozen_denominator: debug
                    .as_ref()
                    .map(|state| state.recovery_frozen_denominator()),
                recovery_certificate_witnesses: debug
                    .as_ref()
                    .map(|state| state.recovery_certificate_witnesses()),
                recovery_donor: debug.as_ref().and_then(|state| state.recovery_donor()),
                recovery_donor_index: debug.as_ref().map(|state| state.recovery_donor_index()),
                recovery_failure_count: debug.as_ref().map(|state| state.recovery_failure_count()),
                recovery_last_failure: debug
                    .as_ref()
                    .and_then(|state| state.recovery_last_failure()),
                terminal_storage_healthy: debug
                    .as_ref()
                    .map(|state| state.terminal_storage_healthy()),
                history_election_pending: debug.as_ref().map(|state| state.election_pending()),
                history_election_active: debug.as_ref().map(|state| state.election_active()),
                history_probe_pending_peers: debug
                    .as_ref()
                    .and_then(|state| state.history_probe_pending_peers()),
                history_alive_peers: debug.as_ref().map(|state| state.history_alive_peers()),
                history_election_phase: debug.as_ref().map(|state| state.history_election_phase()),
                history_election_peer: debug
                    .as_ref()
                    .and_then(|state| state.history_election_peer()),
                history_client_transfers: debug
                    .as_ref()
                    .map(|state| state.history_client_transfers().to_vec()),
                history_pending_intents: debug
                    .as_ref()
                    .map(|state| state.history_pending_intents().to_vec()),
                history_retry_requests: debug
                    .as_ref()
                    .map(|state| state.history_retry_requests().to_vec()),
                terminal_client_transfers: debug
                    .as_ref()
                    .map(|state| state.terminal_client_transfers().to_vec()),
                snapshot_donation_available: server.server.s2s_manager().replications().and_then(
                    |replications| {
                        replications.strict_snapshot_capture_available_for_test("channels")
                    },
                ),
            }
        })
        .collect()
}

fn begin_live_stage(
    phase: &str,
    stage: &str,
    phase_started_at: Instant,
    servers: &[(u16, TestServer)],
) -> (Instant, AnalysisBudgetCounters) {
    let node_ids = servers
        .iter()
        .map(|(node_id, _)| *node_id)
        .collect::<Vec<_>>();
    eprintln!(
        "strict-live stage phase={phase} stage={stage} status=started \
         phase_elapsed_ms={} nodes={node_ids:?}",
        phase_started_at.elapsed().as_millis(),
    );
    (Instant::now(), AnalysisBudgetCounters::capture(servers))
}

fn finish_live_stage(
    phase: &str,
    stage: &str,
    phase_started_at: Instant,
    stage_started_at: Instant,
    before: AnalysisBudgetCounters,
    servers: &[(u16, TestServer)],
) {
    let after = AnalysisBudgetCounters::capture(servers);
    let recovery = servers
        .first()
        .map(|(_, server)| RecoveryTrafficDiagnostic::capture(server));
    eprintln!(
        "strict-live stage phase={phase} stage={stage} status=completed \
         stage_elapsed_ms={} phase_elapsed_ms={} catchup_traffic_bytes={} \
         recovery_traffic_bytes={} catchup_send_attempts={} recovery_send_attempts={} \
         catchup_requests={} catchup_responses={} recovery_attempts={} \
         recovery_retransmits={} aggregate_recovery={recovery:?} nodes={:?}",
        stage_started_at.elapsed().as_millis(),
        phase_started_at.elapsed().as_millis(),
        after.send_bytes - before.send_bytes,
        after.recovery_send_bytes - before.recovery_send_bytes,
        after.send_attempts - before.send_attempts,
        after.recovery_send_attempts - before.recovery_send_attempts,
        after.catchup_requests - before.catchup_requests,
        after.catchup_responses - before.catchup_responses,
        after.recovery_attempts - before.recovery_attempts,
        after.recovery_retransmits - before.recovery_retransmits,
        live_node_diagnostics(servers),
    );
}

async fn wait_for_repositories(servers: &[(u16, TestServer)], fixture: &LiveFixture) {
    assert!(
        wait_until(CONVERGENCE_DEADLINE, || {
            servers.iter().all(|(_, server)| {
                server
                    .server
                    .get_channels()
                    .current_version_in_server(crate::types::DEFAULT_SERVER_ID)
                    == fixture.healthy_version
            })
        })
        .await,
        "channel repositories did not reach {}: {:?}",
        fixture.healthy_version,
        live_node_diagnostics(servers)
    );

    let reference = servers
        .first()
        .expect("repository comparison requires one live node")
        .1
        .server
        .get_channels()
        .s2s_snapshot_in_server(DEFAULT_SERVER_ID)
        .await;
    assert_eq!(reference.version(), fixture.healthy_version);
    assert_eq!(reference.freshness(), fixture.healthy_freshness);
    let reference_channels = canonical_channel_image(reference.channels());
    // `operation_ids` is the frozen, repository-local pre-v5 migration
    // ledger. Protocol v8 imports it into the terminal journal on startup and
    // checkpoint snapshot installation deliberately preserves the receiver's
    // local copy. It is therefore not part of the canonical v8 repository
    // envelope; exact delivery ownership is carried by the S2S envelope's
    // applied/retired checkpoint and durably reconciled with the exact
    // terminal cut.
    for (node_id, server) in servers {
        let snapshot = server
            .server
            .get_channels()
            .s2s_snapshot_in_server(DEFAULT_SERVER_ID)
            .await;
        assert_eq!(
            snapshot.version(),
            fixture.healthy_version,
            "node {node_id}"
        );
        assert_eq!(
            snapshot.freshness(),
            fixture.healthy_freshness,
            "node {node_id}"
        );
        assert_eq!(
            canonical_channel_image(snapshot.channels()),
            reference_channels,
            "node {node_id} channel image diverged from the healthy image"
        );
    }
}

async fn delivery_checkpoint(server: &TestServer) -> Option<StrictDeliveryCheckpointDebug> {
    let replications = server.server.s2s_manager().replications()?;
    replications
        .strict_delivery_checkpoint_for_test("channels")
        .await
}

async fn wait_for_delivery_checkpoint_registration(
    node_id: u16,
    server: &TestServer,
) -> StrictDeliveryCheckpointDebug {
    let deadline = Instant::now() + CLUSTER_READY_DEADLINE;
    loop {
        if let Some(checkpoint) = delivery_checkpoint(server).await {
            return checkpoint;
        }
        assert!(
            Instant::now() < deadline,
            "node {node_id} did not register its strict delivery-checkpoint accessor"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn assert_exact_delivery_checkpoint(
    servers: &[(u16, TestServer)],
    expected: &StrictDeliveryCheckpointDebug,
) {
    for (node_id, server) in servers {
        let actual = delivery_checkpoint(server)
            .await
            .unwrap_or_else(|| panic!("node {node_id} could not capture its delivery checkpoint"));
        assert_eq!(
            &actual, expected,
            "node {node_id} outer applied/retired delivery checkpoint diverged"
        );
    }
}

async fn common_delivery_checkpoint(
    servers: &[(u16, TestServer)],
) -> Option<StrictDeliveryCheckpointDebug> {
    let (_, reference_server) = servers.first()?;
    let reference = delivery_checkpoint(reference_server).await?;
    for (_, server) in servers.iter().skip(1) {
        if delivery_checkpoint(server).await.as_ref() != Some(&reference) {
            return None;
        }
    }
    Some(reference)
}

async fn wait_for_terminal_coverage(
    servers: &[(u16, TestServer)],
    healthy_version: u64,
    healthy_cut: &TerminalCutStatus,
) {
    let deadline = Instant::now() + CONVERGENCE_DEADLINE;
    loop {
        let statuses = terminal_statuses(servers);
        if let Some(reference) = statuses
            .first()
            .and_then(|(_, status)| status.as_ref().ok())
        {
            let has_exact_common_cut = reference
                .covers_healthy_terminal_state(healthy_version, healthy_cut)
                && statuses.iter().all(|(_, status)| {
                    status.as_ref().is_ok_and(|status| {
                        status.covers_healthy_terminal_state(healthy_version, healthy_cut)
                            && status.has_same_terminal_cut_and_digest(reference)
                    })
                });
            if has_exact_common_cut {
                return;
            }
        }
        if Instant::now() >= deadline {
            // Recovery metrics are process-global in this in-process cluster,
            // so one capture is sufficient. Per-node reducer and journal
            // state identifies the stalled phase without duplicating a large
            // metric structure for every server.
            let traffic = servers
                .first()
                .map(|(_, server)| RecoveryTrafficDiagnostic::capture(server));
            panic!(
                "terminal journals did not converge to one healthy terminal cut and digest: \
                 nodes={:?}, aggregate_traffic={traffic:?}",
                live_node_diagnostics(servers),
            );
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
    assert!(
        all_available,
        "not every node can donate a strict snapshot: {:?}",
        live_node_diagnostics(servers)
    );
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

fn directed_peer_count(server_count: usize) -> f64 {
    (server_count * server_count.saturating_sub(1)) as f64
}

fn quiet_send_byte_budget(server_count: usize) -> f64 {
    directed_peer_count(server_count) * QUIET_SEND_BYTES_PER_DIRECTED_PEER
}

fn assert_no_active_traffic(snapshots: &[(u16, TrafficSnapshot)]) {
    for (node_id, snapshot) in snapshots {
        assert_eq!(snapshot.catchups_active, 0.0, "node {node_id}");
        assert_eq!(snapshot.strict_sessions_active, 0.0, "node {node_id}");
        assert_eq!(snapshot.recovery_topics_active, 0.0, "node {node_id}");
        assert_eq!(
            snapshot.recovery_donor_sessions_active, 0.0,
            "node {node_id}"
        );
        assert_eq!(snapshot.bulk_in_flight_bytes, 0.0, "node {node_id}");
        assert_eq!(snapshot.recovery_retransmits, 0.0, "node {node_id}");
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
    // local cluster. Once the exact repository and terminal envelope is
    // common, two complete anti-entropy intervals must not create any new
    // strict request, response, send, election, session, or recovery work.
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
        (
            "snapshot_source_rejections",
            before.snapshot_source_rejections,
            after.snapshot_source_rejections,
        ),
        (
            "snapshot_transfer_rejections",
            before.snapshot_transfer_rejections,
            after.snapshot_transfer_rejections,
        ),
        (
            "recovery_events",
            before.recovery_events,
            after.recovery_events,
        ),
        (
            "recovery_send_attempts",
            before.recovery_send_attempts,
            after.recovery_send_attempts,
        ),
        (
            "recovery_send_bytes",
            before.recovery_send_bytes,
            after.recovery_send_bytes,
        ),
        ("requests", before.requests, after.requests),
        ("responses", before.responses, after.responses),
        ("send_attempts", before.send_attempts, after.send_attempts),
        ("send_bytes", before.send_bytes, after.send_bytes),
    ] {
        assert_eq!(
            after,
            before,
            "{name} changed after convergence; versions={:?} terminal={:#?}",
            versions(servers),
            terminal_statuses(servers),
        );
    }

    assert!(
        after.send_bytes - before.send_bytes <= quiet_send_byte_budget(servers.len()),
        "steady-state metadata exceeded the active-topology budget over {MULTI_INTERVAL_OBSERVATION:?}: before={before:#?} after={after:#?}"
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

fn assert_incident_still_stalled(servers: &[(u16, TestServer)], fixture: &LiveFixture) {
    for (node_id, server) in servers {
        let expected_version = fixture.initial_repository_versions[node_id];
        assert_eq!(
            server
                .server
                .get_channels()
                .current_version_in_server(crate::types::DEFAULT_SERVER_ID),
            expected_version,
            "node {node_id} did not retain its incident repository head"
        );
    }
    let statuses = terminal_statuses(servers);
    let healthy_reference = statuses
        .iter()
        .find(|(node_id, _)| fixture.healthy_lineage_nodes.contains(node_id))
        .and_then(|(_, status)| status.as_ref().ok())
        .expect("healthy-lineage terminal journal");
    for node_id in &fixture.foreign_lineage_nodes {
        let status = statuses
            .iter()
            .find(|(candidate, _)| candidate == node_id)
            .and_then(|(_, status)| status.as_ref().ok())
            .unwrap_or_else(|| panic!("foreign-lineage terminal journal for node {node_id}"));
        assert!(
            !status.has_same_terminal_cut_and_digest(healthy_reference),
            "node {node_id} unexpectedly converged its foreign terminal lineage on the baseline build"
        );
    }
    for node_id in &fixture.lagging_nodes {
        let status = read_terminal_status(
            &node(servers, *node_id)
                .strict_channel_terminal_journal_path()
                .expect("strict channel terminal journal"),
        )
        .expect("read lagging terminal journal");
        assert!(
            !status.covers_healthy_terminal_state(
                fixture.healthy_version,
                &fixture.healthy_terminal_cut,
            ),
            "node {node_id} unexpectedly acquired complete terminal coverage on the baseline build"
        );
    }
}

async fn assert_baseline_symptom(servers: Vec<(u16, TestServer)>, fixture: &LiveFixture) {
    assert_incident_still_stalled(&servers, fixture);
    let metric_server = &servers.first().expect("active server").1;
    let initial = TrafficSnapshot::capture(metric_server);
    let mut before = initial;
    for interval in 1..=2 {
        tokio::time::sleep(BASELINE_INTERVAL_OBSERVATION).await;
        let after = TrafficSnapshot::capture(metric_server);
        assert_incident_still_stalled(&servers, fixture);
        eprintln!(
            "strict-live baseline interval {interval}: versions={:?} before={before:#?} after={after:#?}",
            versions(&servers)
        );
        assert!(
            after.elections_started > before.elections_started,
            "history elections did not remain active in baseline interval {interval}"
        );
        assert!(
            after.history_sessions_started > before.history_sessions_started,
            "history catch-up sessions did not remain active in baseline interval {interval}"
        );
        assert!(
            after.send_attempts > before.send_attempts,
            "strict catch-up sends did not remain active in baseline interval {interval}"
        );
        assert!(
            after.send_bytes > before.send_bytes,
            "strict catch-up bytes did not grow in baseline interval {interval}"
        );
        assert!(
            after.snapshot_source_rejections > before.snapshot_source_rejections,
            "snapshot sources did not keep rejecting catch-up in baseline interval {interval}"
        );
        assert!(
            after.snapshot_transfer_rejections > before.snapshot_transfer_rejections,
            "snapshot responders did not keep declining transfers in baseline interval {interval}"
        );
        before = after;
    }
    assert!(
        before.send_bytes - initial.send_bytes > quiet_send_byte_budget(servers.len()),
        "two baseline intervals did not exceed the converged active-topology traffic budget: initial={initial:#?} after={before:#?}"
    );
    shutdown_cluster(servers).await;
}

async fn assert_post_recovery_strict_write(
    servers: &[(u16, TestServer)],
    previous_checkpoint: &StrictDeliveryCheckpointDebug,
) {
    let consensus_started_at = Instant::now();
    let traffic_before = AnalysisBudgetCounters::capture(servers);
    let expected_delivery_version = servers
        .first()
        .expect("post-recovery proposal source")
        .1
        .server
        .get_channels()
        .current_version_in_server(crate::types::DEFAULT_SERVER_ID)
        .checked_add(1)
        .expect("post-recovery repository version");
    assert_eq!(
        servers.first().map(|(node_id, _)| *node_id),
        Some(EMPTY_BOOTSTRAP_NODE_ID),
        "the recovered empty node must be the post-recovery proposal source"
    );
    for (node_id, server) in servers {
        assert!(
            server
                .server
                .get_channels()
                .get_channel_in_server(crate::types::DEFAULT_SERVER_ID, POST_RECOVERY_CHANNEL_ID)
                .await
                .is_none(),
            "post-recovery strict-write channel already exists on node {node_id}"
        );
    }
    let result = servers
        .first()
        .expect("post-recovery proposal source")
        .1
        .server
        .s2s_manager()
        .propose_channel_op(
            DEFAULT_SERVER_ID,
            shitspeak_state::ChannelOp::CreateChannel {
                channel: Channel::new(
                    POST_RECOVERY_CHANNEL_ID,
                    "Strict Recovery Probe".to_owned(),
                    0,
                    0,
                    Some(0),
                ),
            },
        )
        .await;
    assert!(
        result.is_proposed(),
        "strict proposal remained fenced after recovery: {result:?}"
    );

    let deadline = Instant::now() + CLUSTER_READY_DEADLINE;
    loop {
        let mut missing = Vec::new();
        for (node_id, server) in servers {
            if server
                .server
                .get_channels()
                .get_channel_in_server(crate::types::DEFAULT_SERVER_ID, POST_RECOVERY_CHANNEL_ID)
                .await
                .is_none()
            {
                missing.push(*node_id);
            }
        }
        let common_checkpoint = if missing.is_empty() {
            common_delivery_checkpoint(servers).await
        } else {
            None
        };
        if common_checkpoint.as_ref().is_some_and(|checkpoint| {
            checkpoint != previous_checkpoint
                && checkpoint
                    .applied()
                    .iter()
                    .any(|(_, version)| *version == expected_delivery_version)
        }) {
            record_analysis_budget_observation(
                "post_recovery_strict_write",
                consensus_started_at,
                traffic_before,
                servers,
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "post-recovery strict write or its exact delivery checkpoint did not converge: missing_channels={missing:?}, common_checkpoint={common_checkpoint:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn assert_foreign_node_certified_full_topology(
    servers: &[(u16, TestServer)],
    fixture: &LiveFixture,
) {
    let quorum = 9 - 9 / 4;
    assert!(
        wait_until(CONVERGENCE_DEADLINE, || {
            let state = node(servers, 15)
                .server
                .s2s_manager()
                .strict_channel_debug_state_for_test(DEFAULT_SERVER_ID)
                .expect("node 15 strict recovery debug state");
            state.recovery_frozen_denominator() == 9
                && state.recovery_certificate_witnesses() >= quorum
        })
        .await,
        "node 15 never retained a 7-of-9 v8 certificate; debug={:?} versions={:?}",
        node(servers, 15)
            .server
            .s2s_manager()
            .strict_channel_debug_state_for_test(DEFAULT_SERVER_ID),
        versions(servers),
    );
    assert!(
        fixture.eventual_target_nodes.len() >= quorum,
        "only {:?} copied same-lineage witnesses can reach the certified target",
        fixture.eventual_target_nodes,
    );
}

async fn spawn_staged_fixed_cluster(
    fixture_root: &Path,
    pki: Arc<Pki>,
    fixture: &LiveFixture,
) -> (Vec<(u16, TestServer)>, StrictDeliveryCheckpointDebug) {
    assert_eq!(
        fixture.foreign_lineage_nodes,
        [15],
        "fixed acceptance derives exactly node 15 as the foreign lineage"
    );
    assert_eq!(
        fixture.healthy_donor, 4_096,
        "the fresh live capture must derive node 4096 as its target representation donor"
    );
    assert_eq!(
        fixture.eventual_target_nodes.len(),
        8,
        "all eight non-foreign copied nodes must be able to reach the target"
    );

    let topology_node_ids = fixture.recovery_node_ids();
    let mut addresses = Vec::with_capacity(topology_node_ids.len());
    for _ in &topology_node_ids {
        addresses.push(loopback(pick_free_port().await));
    }
    let initial_node_ids = fixed_initial_witness_node_ids(&topology_node_ids);
    assert_eq!(
        initial_node_ids.len(),
        8,
        "fixed acceptance must first start all eight copied non-foreign witnesses"
    );
    let witness_started_at = Instant::now();
    let witness_traffic_before = AnalysisBudgetCounters::default();
    let mut servers = spawn_live_nodes(
        fixture_root,
        Arc::clone(&pki),
        fixture,
        &topology_node_ids,
        &addresses,
        &initial_node_ids,
        StagedStateExpectation::Incident,
    )
    .await;
    // Runtime registration is asynchronous with server construction. Wait
    // only for the already-selected node 4096 target donor's accessor, not
    // for cluster convergence. Node 4096 is the immutable highest-ranked
    // target for this fixture and no strict write occurs during staged
    // startup, so registration timing cannot advance this outer checkpoint.
    let healthy_delivery_checkpoint = wait_for_delivery_checkpoint_registration(
        fixture.healthy_donor,
        node(&servers, fixture.healthy_donor),
    )
    .await;
    assert!(
        !healthy_delivery_checkpoint.applied().is_empty()
            || !healthy_delivery_checkpoint.retired().is_empty(),
        "copied healthy donor fixture unexpectedly has an empty delivery checkpoint"
    );
    let (stage_started_at, stage_traffic_before) = begin_live_stage(
        "copied_witness_convergence",
        "wait_for_cluster",
        witness_started_at,
        &servers,
    );
    wait_for_cluster(&servers).await;
    finish_live_stage(
        "copied_witness_convergence",
        "wait_for_cluster",
        witness_started_at,
        stage_started_at,
        stage_traffic_before,
        &servers,
    );
    assert_recovery_v8_floor(&servers);
    let (stage_started_at, stage_traffic_before) = begin_live_stage(
        "copied_witness_convergence",
        "wait_for_repositories",
        witness_started_at,
        &servers,
    );
    wait_for_repositories(&servers, fixture).await;
    finish_live_stage(
        "copied_witness_convergence",
        "wait_for_repositories",
        witness_started_at,
        stage_started_at,
        stage_traffic_before,
        &servers,
    );
    let (stage_started_at, stage_traffic_before) = begin_live_stage(
        "copied_witness_convergence",
        "wait_for_terminal_coverage",
        witness_started_at,
        &servers,
    );
    wait_for_terminal_coverage(
        &servers,
        fixture.healthy_version,
        &fixture.healthy_terminal_cut,
    )
    .await;
    finish_live_stage(
        "copied_witness_convergence",
        "wait_for_terminal_coverage",
        witness_started_at,
        stage_started_at,
        stage_traffic_before,
        &servers,
    );
    let (stage_started_at, stage_traffic_before) = begin_live_stage(
        "copied_witness_convergence",
        "snapshot_donation",
        witness_started_at,
        &servers,
    );
    assert_all_nodes_can_donate_snapshots(&servers).await;
    assert_exact_delivery_checkpoint(&servers, &healthy_delivery_checkpoint).await;
    finish_live_stage(
        "copied_witness_convergence",
        "snapshot_donation",
        witness_started_at,
        stage_started_at,
        stage_traffic_before,
        &servers,
    );
    record_analysis_budget_observation(
        "copied_witness_convergence",
        witness_started_at,
        witness_traffic_before,
        &servers,
    );

    let empty_state_directory = fixture_root.join(format!("node-{EMPTY_BOOTSTRAP_NODE_ID}"));
    assert!(
        !empty_state_directory.exists(),
        "network-bootstrap node must have no repository or terminal state before construction"
    );
    let empty_started_at = Instant::now();
    let empty_traffic_before = AnalysisBudgetCounters::capture(&servers);
    let mut empty = spawn_live_nodes(
        fixture_root,
        Arc::clone(&pki),
        fixture,
        &topology_node_ids,
        &addresses,
        &[EMPTY_BOOTSTRAP_NODE_ID],
        StagedStateExpectation::Incident,
    )
    .await;
    assert_eq!(empty.len(), 1);
    empty.append(&mut servers);
    servers = empty;
    wait_for_cluster(&servers).await;
    assert_recovery_v8_floor(&servers);
    wait_for_repositories(&servers, fixture).await;
    wait_for_terminal_coverage(
        &servers,
        fixture.healthy_version,
        &fixture.healthy_terminal_cut,
    )
    .await;
    assert_all_nodes_can_donate_snapshots(&servers).await;
    assert_exact_delivery_checkpoint(&servers, &healthy_delivery_checkpoint).await;
    record_analysis_budget_observation(
        "empty_node_network_bootstrap",
        empty_started_at,
        empty_traffic_before,
        &servers,
    );

    let foreign_started_at = Instant::now();
    let foreign_traffic_before = AnalysisBudgetCounters::capture(&servers);
    let mut foreign = spawn_live_nodes(
        fixture_root,
        pki,
        fixture,
        &topology_node_ids,
        &addresses,
        &[15],
        StagedStateExpectation::Incident,
    )
    .await;
    servers.append(&mut foreign);
    wait_for_cluster(&servers).await;
    assert_foreign_node_certified_full_topology(&servers, fixture).await;
    wait_for_repositories(&servers, fixture).await;
    wait_for_terminal_coverage(
        &servers,
        fixture.healthy_version,
        &fixture.healthy_terminal_cut,
    )
    .await;
    assert_all_nodes_can_donate_snapshots(&servers).await;
    assert_exact_delivery_checkpoint(&servers, &healthy_delivery_checkpoint).await;
    record_analysis_budget_observation(
        "foreign_lineage_recovery",
        foreign_started_at,
        foreign_traffic_before,
        &servers,
    );
    (servers, healthy_delivery_checkpoint)
}

async fn assert_fixed_resolution(
    servers: Vec<(u16, TestServer)>,
    pki: Arc<Pki>,
    fixture: &LiveFixture,
    healthy_delivery_checkpoint: StrictDeliveryCheckpointDebug,
) {
    assert!(
        servers
            .iter()
            .any(|(node_id, _)| *node_id == EMPTY_BOOTSTRAP_NODE_ID),
        "fixed-resolution topology omitted the empty network-bootstrap node"
    );
    assert_recovery_v8_floor(&servers);
    assert_down_nodes_absent(&servers, fixture);
    wait_for_repositories(&servers, fixture).await;
    wait_for_terminal_coverage(
        &servers,
        fixture.healthy_version,
        &fixture.healthy_terminal_cut,
    )
    .await;
    assert_all_nodes_can_donate_snapshots(&servers).await;
    assert_exact_delivery_checkpoint(&servers, &healthy_delivery_checkpoint).await;

    let configured_restart_root =
        std::env::var_os("SHITSPEAK_STRICT_LIVE_RESTART_CAPTURE_ROOT").map(PathBuf::from);
    let temporary_restart_root = configured_restart_root
        .is_none()
        .then(|| TempDir::new().expect("restart fixture root"));
    let restart_root = configured_restart_root.as_deref().unwrap_or_else(|| {
        temporary_restart_root
            .as_ref()
            .expect("temporary restart fixture root")
            .path()
    });
    std::fs::create_dir_all(restart_root).expect("create restart fixture root");
    let restart_started_at = Instant::now();
    let restart_traffic_before = AnalysisBudgetCounters::capture(&servers);
    capture_cluster(servers, restart_root)
        .await
        .expect("capture converged strict channel state");
    eprintln!(
        "strict-live restart fixture captured at {}",
        restart_root.display()
    );

    let recovery_node_ids = fixture.recovery_node_ids();
    let restarted = spawn_live_cluster(
        restart_root,
        pki,
        fixture,
        &recovery_node_ids,
        StagedStateExpectation::Recovered,
    )
    .await;
    wait_for_cluster(&restarted).await;
    assert_recovery_v8_floor(&restarted);
    assert_down_nodes_absent(&restarted, fixture);
    wait_for_repositories(&restarted, fixture).await;
    wait_for_terminal_coverage(
        &restarted,
        fixture.healthy_version,
        &fixture.healthy_terminal_cut,
    )
    .await;
    assert_all_nodes_can_donate_snapshots(&restarted).await;
    assert_exact_delivery_checkpoint(&restarted, &healthy_delivery_checkpoint).await;
    record_analysis_budget_observation(
        "full_cluster_restart",
        restart_started_at,
        restart_traffic_before,
        &restarted,
    );
    assert_multi_interval_quiescence(&restarted).await;

    let outage_started_at = Instant::now();
    let outage_traffic_before = AnalysisBudgetCounters::capture(&restarted);
    let outage_node_ids = vec![fixture.healthy_donor];
    let (offline, remaining): (Vec<_>, Vec<_>) = restarted
        .into_iter()
        .partition(|(node_id, _)| outage_node_ids.contains(node_id));
    let offline_node_ids = offline
        .iter()
        .map(|(node_id, _)| *node_id)
        .collect::<Vec<_>>();
    assert!(
        !offline_node_ids.is_empty(),
        "copied incident cluster has no selected node for the outage phase"
    );
    assert!(
        !remaining.is_empty(),
        "outage phase requires at least one surviving replica"
    );
    assert!(
        remaining
            .iter()
            .any(|(node_id, _)| *node_id == EMPTY_BOOTSTRAP_NODE_ID),
        "donor-removal phase omitted the recovered empty node"
    );
    shutdown_cluster(offline).await;
    for (_, server) in &remaining {
        let overlay = server
            .server
            .s2s_manager()
            .overlay()
            .expect("surviving server has overlay");
        for node_id in &offline_node_ids {
            // Graceful shutdown may have already delivered the departure on
            // localhost. Injection is intentionally idempotent; the exact
            // unavailable-state assertion below remains mandatory.
            let _ = overlay.fail_member_for_test(*node_id);
        }
    }
    assert!(
        wait_until(CLUSTER_READY_DEADLINE, || {
            remaining.iter().all(|(_, server)| {
                server
                    .server
                    .s2s_manager()
                    .overlay()
                    .is_some_and(|overlay| {
                        offline_node_ids
                            .iter()
                            .all(|node_id| !overlay.alive_members().contains(node_id))
                    })
            })
        })
        .await,
        "surviving replicas did not mark nodes {offline_node_ids:?} unavailable"
    );
    wait_for_cluster(&remaining).await;
    wait_for_terminal_coverage(
        &remaining,
        fixture.healthy_version,
        &fixture.healthy_terminal_cut,
    )
    .await;
    wait_for_repositories(&remaining, fixture).await;
    assert_all_nodes_can_donate_snapshots(&remaining).await;
    assert_exact_delivery_checkpoint(&remaining, &healthy_delivery_checkpoint).await;
    record_analysis_budget_observation(
        "donor_removal",
        outage_started_at,
        outage_traffic_before,
        &remaining,
    );
    assert_multi_interval_quiescence(&remaining).await;
    assert_post_recovery_strict_write(&remaining, &healthy_delivery_checkpoint).await;
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
    let incident_fixture = prepare_incident_fixture(&fixture_root);
    let fixture = load_live_fixture(incident_fixture.path());
    assert!(
        !incident_fixture
            .path()
            .join(format!("node-{EMPTY_BOOTSTRAP_NODE_ID}"))
            .exists(),
        "derived incident unexpectedly contains state for the network-bootstrap node"
    );

    match expectation {
        Expectation::BaselineStuck => {
            let node_ids = fixture.active_node_ids.clone();
            let pki = Arc::new(mint_pki(&node_ids));
            let servers = spawn_live_cluster(
                incident_fixture.path(),
                pki,
                &fixture,
                &node_ids,
                StagedStateExpectation::Incident,
            )
            .await;
            wait_for_cluster(&servers).await;
            assert_down_nodes_absent(&servers, &fixture);
            assert_baseline_symptom(servers, &fixture).await;
        }
        Expectation::FixedConverged => {
            assert_eq!(
                fixture.active_node_ids, PRODUCTION_NODE_RANK_ORDER,
                "fixed convergence acceptance requires copied nodes 1,4,5,7,8,15,16,4096,4097"
            );
            let node_ids = fixture.recovery_node_ids();
            let pki = Arc::new(mint_pki(&node_ids));
            let (servers, healthy_delivery_checkpoint) =
                spawn_staged_fixed_cluster(incident_fixture.path(), Arc::clone(&pki), &fixture)
                    .await;
            assert_down_nodes_absent(&servers, &fixture);
            assert_fixed_resolution(servers, pki, &fixture, healthy_delivery_checkpoint).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Ban repositories and strict terminal journals copied live through SSH"]
async fn strict_live_ban_state_resolves_jnb_dfw_staged_recovery() {
    let _guard = s2s_network_test_guard().await;
    let fixture_root = PathBuf::from(
        std::env::var_os("SHITSPEAK_STRICT_LIVE_BAN_STATE_ROOT")
            .expect("SHITSPEAK_STRICT_LIVE_BAN_STATE_ROOT is required"),
    );
    let nodes = [(8_u16, "node-4-dfw"), (15_u16, "node-15-jnb")];
    let captured_dfw_terminal_path = fixture_root
        .join("node-4-dfw")
        .join("terminal-bans.sqlite3");
    let captured_dfw_terminal = read_terminal_status(&captured_dfw_terminal_path)
        .expect("read captured DFW Ban terminal status");
    let certified_artifact = read_recovery_artifact_status(&captured_dfw_terminal_path)
        .expect("read captured DFW certified Ban recovery artifact");
    let certified_version = certified_artifact.repository_version;
    assert_eq!(
        certified_version, 6,
        "the captured DFW recovery artifact must name the incident's certified v6 image"
    );
    assert_eq!(
        certified_artifact.history_freshness, 1_786_418_705,
        "the captured DFW recovery artifact must retain the incident freshness"
    );
    assert!(
        captured_dfw_terminal.repository_image_install_pending,
        "the captured DFW Ban recovery must begin with its repository image pending"
    );
    assert_eq!(
        ban_fixture_version(&fixture_root.join("node-4-dfw")),
        7,
        "the copied DFW Ban repository must begin with the untagged incident v7 image"
    );
    assert_eq!(
        ban_fixture_version(&fixture_root.join("node-15-jnb")),
        certified_version,
        "the copied JNB Ban repository must retain the certified recovery image"
    );
    let node_ids = nodes.map(|(node_id, _)| node_id);
    let pki = Arc::new(mint_pki(&node_ids));
    let addresses = join_all(node_ids.iter().map(|_| pick_free_port()))
        .await
        .into_iter()
        .map(loopback)
        .collect::<Vec<_>>();
    let mut servers = Vec::with_capacity(nodes.len());
    for (cert_index, (node_id, directory)) in nodes.iter().enumerate() {
        let server = spawn_s2s_test_server_with_state(
            TestServerOpts::default(),
            Arc::clone(&pki),
            *node_id,
            cert_index,
            production_s2s_config(addresses[cert_index], &addresses),
            TestStrictReplicationState::from_directory(fixture_root.join(directory)),
        )
        .await;
        servers.push((*node_id, server));
    }
    wait_for_cluster(&servers).await;

    let startup_versions = servers
        .iter()
        .map(|(node_id, server)| (*node_id, server.server.get_bans().current_version()))
        .collect::<HashMap<_, _>>();
    assert_eq!(
        startup_versions[&15], certified_version,
        "JNB must retain the certified recovery image after startup"
    );
    assert_eq!(
        startup_versions[&8], certified_version,
        "DFW must replace its untagged v7 image from the certified recovery artifact at startup"
    );

    assert!(
        wait_until(CONVERGENCE_DEADLINE, || {
            servers
                .iter()
                .all(|(_, server)| server.server.get_bans().current_version() == certified_version)
        })
        .await,
        "the captured Ban-state replay did not restore DFW to the certified v6 image: {:?}",
        servers
            .iter()
            .map(|(node_id, server)| (*node_id, server.server.get_bans().current_version()))
            .collect::<HashMap<_, _>>()
    );

    let dfw = servers
        .iter()
        .find_map(|(node_id, server)| (*node_id == 8).then_some(server))
        .expect("DFW server");
    let dfw_terminal_path = dfw
        .strict_terminal_journal_path("bans")
        .expect("DFW durable Ban terminal journal");
    let durable_install_completed = wait_until(CONVERGENCE_DEADLINE, || {
        read_terminal_status(&dfw_terminal_path)
            .is_ok_and(|terminal| !terminal.repository_image_install_pending)
    })
    .await;
    assert!(
        durable_install_completed,
        "DFW did not durably complete its Ban repository-image install: {:?}",
        read_terminal_status(&dfw_terminal_path)
    );
    let dfw_terminal = read_terminal_status(&dfw_terminal_path)
        .expect("read DFW Ban terminal status after recovery");
    assert_eq!(
        dfw_terminal.checkpoint_repository_version,
        Some(certified_version)
    );
    assert!(
        !dfw_terminal.repository_image_install_pending,
        "DFW must complete its durable Ban repository-image install"
    );

    // Once the verified image and terminal checkpoint are installed, no
    // admission proof retry may retain catchup traffic. The shared traffic
    // snapshot includes every strict topic, so this also detects a Ban retry
    // leaking beyond the completed recovery fence.
    let quiet = wait_for_quiet(&servers).await;
    assert_no_active_traffic(&quiet);
}

/// Replays the exact DFW Ban repository and strict terminal journal captured
/// after the second production BanList update. The first committed SetBans
/// (v7) contains one certificate-only ASN entry; the durable v8 commit
/// replaces that list with two certificate-only `::/0` ASN entries. A schema
/// keyed only by `(address, mask)` rejects v8 and leaves the terminal delivery
/// retrying forever. The fixture is intentionally a single node: the commit
/// decision and its terminal delivery are already durable, so neither clients
/// nor network latency participate in this failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the DFW Ban repository and strict terminal journal copied live through SSH"]
async fn strict_live_ban_terminal_delivery_replays_dfw_second_certificate_only_update() {
    let _guard = s2s_network_test_guard().await;
    let fixture_root = PathBuf::from(
        std::env::var_os("SHITSPEAK_STRICT_LIVE_BAN_DELIVERY_ROOT")
            .expect("SHITSPEAK_STRICT_LIVE_BAN_DELIVERY_ROOT is required"),
    );
    let state_directory = fixture_root.join("node-4-dfw");
    let node_id = 8;
    let pki = Arc::new(mint_pki(&[node_id]));
    let address = loopback(pick_free_port().await);
    let server = spawn_s2s_test_server_with_state(
        TestServerOpts::default(),
        pki,
        node_id,
        0,
        production_s2s_config(address, &[address]),
        TestStrictReplicationState::from_directory(state_directory),
    )
    .await;

    let delivered = wait_until(CONVERGENCE_DEADLINE, || {
        server.server.get_bans().current_version() == 8
            && tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(server.server.get_bans().get_active_bans())
                    .len()
                    == 2
            })
    })
    .await;
    assert!(
        delivered,
        "the copied DFW v8 Ban terminal delivery did not apply both certificate-only entries; version={}, entries={:?}",
        server.server.get_bans().current_version(),
        server.server.get_bans().get_active_bans().await,
    );
    assert!(server.server.get_bans().is_asn_banned(45_090));
    assert!(server.server.get_bans().is_asn_banned(45_102));
    server.shutdown_gracefully().await;
}
