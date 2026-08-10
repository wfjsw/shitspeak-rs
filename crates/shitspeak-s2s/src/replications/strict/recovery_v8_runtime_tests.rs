//! Focused protocol-v8 recovery wire/session tests.

use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
    sync::Arc,
    time::{Duration, Instant},
};

use aws_lc_rs::digest::{SHA256, digest};
use bytes::Bytes;
use tokio_util::sync::CancellationToken;

use super::{
    recovery_reducer::{
        DonorFailure, LogicalTarget, ParticipantIncarnation, RecoveryAttemptId,
        RecoveryAttestation, RecoveryEffect, RecoveryEvent, RecoveryPhase, RecoveryTrigger,
        TerminalCut as ReducerCut,
    },
    recovery_staging::{RecoveryStagingExpectation, write_recovery_staging_artifact},
    recovery_v8_runtime::{
        attest_snapshot_request_for_test, attest_terminal_request_for_test,
        client_terminal_state_count, donor_session_counts, execute_due_transfer_retries,
        execute_effects, execute_effects_with_retry_clock_for_test,
        prune_idle_donor_sessions_after_timeout_for_test, recv_probe_req, recv_probe_resp,
        recv_snapshot_ack, recv_snapshot_page, recv_snapshot_req as recv_snapshot_req_runtime,
        recv_terminal_ack, recv_terminal_page, recv_terminal_req as recv_terminal_req_runtime,
        request_generation_zero_audit, restore_coordinator, spawn_startup_rollforward,
    },
    runtime::{BulkPageIdentity, StrictRuntime, make_op_id},
    sync_v3::cut_to_wire,
    terminal_journal::{TerminalCut, TerminalDecision as JournalTerminalDecision},
    terminal_journal_sqlite::{
        DurableRecoveryArtifactIntent, DurableRecoveryAttempt, DurableRecoveryFailure,
        DurableRecoveryParticipant, DurableRecoveryPhase, DurableRecoveryRepositoryMetadata,
        DurableRecoveryTarget, DurableRecoveryWitness,
    },
};
use crate::overlay::{MemberIncarnation, MembershipEvent};
use crate::replications::strict::StrictDeliveryCheckpointDebug;
use crate::replications::topic::ErasedStrictRuntime;
use crate::replications::{
    config::ReplicationConfig,
    proto::{
        StrictBody, StrictRecoveryContext, StrictRecoveryProbeReq, StrictRecoveryProbeResp,
        StrictRecoverySnapshotAck, StrictRecoverySnapshotPage, StrictRecoverySnapshotReq,
        StrictRecoveryStatus, StrictRecoveryTarget, StrictRecoveryTerminalAck,
        StrictRecoveryTerminalPage, StrictRecoveryTerminalReq, StrictTerminalState,
    },
    protocol::STRICT_PROTOCOL_VERSION_V8,
    strict::StrictReplicable,
    test_support::{
        CapturedFrame, CountingStrictRepo, MockBulkSendOutcome, MockNet, StrictSendLane,
        StrictSendOutcome,
    },
};

async fn recv_terminal_req(
    rt: &StrictRuntime<CountingStrictRepo>,
    from: NodeIdentifier,
    epoch: u64,
    authenticated: bool,
    request: StrictRecoveryTerminalReq,
) {
    if authenticated {
        attest_terminal_request_for_test(rt, from, epoch, &request);
    }
    recv_terminal_req_runtime(rt, from, epoch, authenticated, request).await;
}

async fn recv_snapshot_req(
    rt: &StrictRuntime<CountingStrictRepo>,
    from: NodeIdentifier,
    epoch: u64,
    authenticated: bool,
    request: StrictRecoverySnapshotReq,
) {
    if authenticated {
        attest_snapshot_request_for_test(rt, from, epoch, &request);
    }
    recv_snapshot_req_runtime(rt, from, epoch, authenticated, request).await;
}
use shitspeak_core::NodeIdentifier;

const REQUESTER: NodeIdentifier = 2;
const REQUESTER_EPOCH: u64 = 22;
const DONOR: NodeIdentifier = 1;
const DONOR_EPOCH: u64 = 11;
const SECOND_WITNESS: NodeIdentifier = 3;
const SECOND_WITNESS_EPOCH: u64 = 33;

#[test]
fn delivery_checkpoint_debug_view_is_sorted_and_encapsulated() {
    let mut applied = BTreeMap::new();
    applied.insert((9, 4), 3);
    applied.insert((1, 8), 2);
    let mut retired = BTreeMap::new();
    retired.insert(12, 7);
    retired.insert(3, 5);

    let checkpoint = StrictDeliveryCheckpointDebug::from_maps(applied, retired);

    assert_eq!(checkpoint.applied(), &[((1, 8), 2), ((9, 4), 3)]);
    assert_eq!(checkpoint.retired(), &[(3, 5), (12, 7)]);
}

#[tokio::test]
async fn installed_delivery_checkpoint_verification_rejects_outer_map_mismatch() {
    let (requester, _) = runtime(REQUESTER, REQUESTER_EPOCH);
    let applied_op = make_op_id(REQUESTER, REQUESTER_EPOCH, 1);
    {
        let mut journal = requester.terminal_journal.lock().await;
        journal
            .upsert_decision(
                applied_op,
                JournalTerminalDecision::commit_bytes(1, 1, Bytes::from_static(b"applied")),
            )
            .unwrap();
        journal.begin_delivery(applied_op, 1).unwrap();
        journal.finish_delivery(applied_op, 1).unwrap();
    }
    requester
        .state
        .lock()
        .applied_operations
        .insert(applied_op, 1);
    let expected_applied = BTreeMap::from([(applied_op, 1)]);
    assert!(
        requester
            .installed_delivery_checkpoint_matches(&expected_applied, &BTreeMap::new())
            .await,
        "a populated exact runtime and durable checkpoint must verify"
    );

    let missing_applied = BTreeMap::new();
    assert!(
        !requester
            .installed_delivery_checkpoint_matches(&missing_applied, &BTreeMap::new())
            .await,
        "repository metadata and terminal cut must not mask an applied checkpoint mismatch"
    );

    let durable_only_op = make_op_id(REQUESTER, REQUESTER_EPOCH, 2);
    {
        let mut journal = requester.terminal_journal.lock().await;
        journal
            .upsert_decision(
                durable_only_op,
                JournalTerminalDecision::commit_bytes(1, 2, Bytes::from_static(b"durable-only")),
            )
            .unwrap();
        journal.begin_delivery(durable_only_op, 2).unwrap();
        journal.finish_delivery(durable_only_op, 2).unwrap();
    }
    assert!(
        !requester
            .installed_delivery_checkpoint_matches(&expected_applied, &BTreeMap::new())
            .await,
        "an extra durable delivery marker must not be hidden by an exact runtime map"
    );

    requester
        .state
        .lock()
        .retired_operations
        .insert(make_op_id(REQUESTER, REQUESTER_EPOCH, 3).0, 3);
    assert!(
        !requester
            .installed_delivery_checkpoint_matches(&expected_applied, &BTreeMap::new())
            .await,
        "repository metadata and terminal cut must not mask a retired checkpoint mismatch"
    );
}

#[tokio::test]
async fn erased_runtime_delivery_checkpoint_accessor_captures_exact_populated_boundary() {
    let (requester, _) = runtime(REQUESTER, REQUESTER_EPOCH);
    let repository_version = requester.repo.current_version();
    let applied_op = make_op_id(REQUESTER, REQUESTER_EPOCH, 7);
    let retired_origin = make_op_id(DONOR, DONOR_EPOCH, 0).0;
    let applied = BTreeMap::from([(applied_op, repository_version)]);
    let retired = BTreeMap::from([(retired_origin, 6)]);
    {
        let mut journal = requester.terminal_journal.lock().await;
        journal
            .upsert_decision(
                applied_op,
                JournalTerminalDecision::commit_bytes(
                    1,
                    1,
                    Bytes::from_static(b"accessor-applied"),
                ),
            )
            .unwrap();
        journal
            .begin_delivery(applied_op, repository_version)
            .unwrap();
        journal
            .finish_delivery(applied_op, repository_version)
            .unwrap();
        journal
            .install_repository_checkpoint(
                repository_version,
                requester.repo.history_metadata().freshness,
                &applied,
                &retired,
            )
            .unwrap();
    }
    requester
        .state
        .lock()
        .install_repository_checkpoint(applied, retired);
    let checkpoint = ErasedStrictRuntime::delivery_checkpoint_for_test(requester.as_ref())
        .await
        .expect("populated strict runtime checkpoint boundary");

    assert_eq!(
        checkpoint.applied(),
        &[((applied_op.0, applied_op.1), repository_version)]
    );
    assert_eq!(checkpoint.retired(), &[(retired_origin, 6)]);
}

#[test]
#[ignore = "requires SHITSPEAK_STRICT_LIVE_STATE_ROOT"]
fn diagnose_live_fixture_v8_terminal_page_sizes() {
    fn repository_metadata(directory: &std::path::Path) -> (u64, i64) {
        let snapshot: serde_json::Value = serde_json::from_slice(
            &std::fs::read(directory.join("channels.snapshot.json")).expect("read snapshot"),
        )
        .expect("parse snapshot");
        let mut version = snapshot["version"].as_u64().expect("snapshot version");
        let mut freshness = snapshot["history_freshness"]["default"]
            .as_i64()
            .expect("snapshot freshness");
        for line in std::fs::read_to_string(directory.join("channels.wal.jsonl"))
            .expect("read WAL")
            .lines()
            .filter(|line| !line.trim().is_empty())
        {
            let entry: serde_json::Value = serde_json::from_str(line).expect("parse WAL entry");
            if entry["server_id"].as_str() == Some("default") {
                version = version.max(entry["version"].as_u64().expect("WAL version"));
                freshness = freshness.max(entry["timestamp"].as_i64().expect("WAL timestamp"));
            }
        }
        (version, freshness)
    }

    let fixture_root = std::path::PathBuf::from(
        std::env::var_os("SHITSPEAK_STRICT_LIVE_STATE_ROOT")
            .expect("SHITSPEAK_STRICT_LIVE_STATE_ROOT"),
    );
    for node in [4096_u16, 1, 4] {
        let directory = fixture_root.join(format!("node-{node}"));
        let source = directory.join("terminal-channels.sqlite3");
        let connection = rusqlite::Connection::open_with_flags(
            &source,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open fixture journal");
        let (record_count, raw_min, raw_max): (i64, i64, i64) = connection
            .query_row(
                "SELECT count(*),
                        coalesce(min(length(record)), 0),
                        coalesce(max(length(record)), 0)
                 FROM journal_records",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("query raw record lengths");
        let image = connection
            .serialize(rusqlite::MAIN_DB)
            .expect("serialize WAL-applied journal");
        let staged = tempfile::TempDir::new().expect("staged journal root");
        let journal_directory = staged.path().join("strict-terminal-journal");
        std::fs::create_dir_all(&journal_directory).expect("create journal directory");
        std::fs::write(
            journal_directory.join(format!("topic-{}.sqlite3", hex::encode("channels"))),
            &*image,
        )
        .expect("write WAL-applied journal");
        let journal = super::terminal_journal::TerminalJournal::load(
            Some(staged.path().to_path_buf()),
            "channels",
        )
        .expect("load fixture journal");
        let cut = journal.terminal_cut();
        let entries = journal
            .terminal_checkpoint_page_at(&cut, 0, usize::MAX)
            .expect("cursor-zero checkpoint")
            .into_entries();
        let states = entries
            .into_iter()
            .map(|entry| {
                let (op_id, record) = entry.into_parts();
                StrictRuntime::<CountingStrictRepo>::terminal_state_from_journal_record(
                    op_id, &record,
                )
                .expect("terminal record maps to wire state")
            })
            .collect::<Vec<_>>();
        let staged = states
            .iter()
            .enumerate()
            .map(|(index, state)| {
                super::catchup::staged_terminal_decision(state)
                    .unwrap_or_else(|| panic!("node {node} state {index} failed wire validation"))
            })
            .collect::<Vec<_>>();
        super::terminal_journal::TerminalJournal::validate_staged_terminal_checkpoint(cut, &staged)
            .unwrap_or_else(|error| panic!("node {node} staged checkpoint validation: {error}"));
        let (repository_version, history_freshness) = repository_metadata(&directory);
        let page_for = |checkpoint_states: Vec<StrictTerminalState>| {
            let next_cursor = checkpoint_states.len() as u64;
            StrictRecoveryTerminalPage {
                context: Some(StrictRecoveryContext {
                    requester_node: u32::MAX,
                    requester_boot_epoch: u64::MAX,
                    attempt_id: Bytes::from(vec![u8::MAX; 16]),
                    expected_donor_boot_epoch: u64::MAX,
                    target: Some(StrictRecoveryTarget {
                        repository_version,
                        history_freshness,
                        terminal_set_digest: Bytes::copy_from_slice(cut.terminal_set_digest()),
                    }),
                }),
                responder_node: u32::from(node),
                responder_boot_epoch: u64::MAX,
                status: StrictRecoveryStatus::Ok.into(),
                target_cut: Some(cut_to_wire(cut)),
                transfer_id: u64::MAX,
                request_nonce: u64::MAX,
                cursor: 0,
                next_cursor,
                checkpoint_digest: Bytes::copy_from_slice(cut.terminal_set_digest()),
                checkpoint_states,
                has_more: next_cursor < cut.generation(),
            }
        };
        let state_lengths = states
            .iter()
            .map(prost::Message::encoded_len)
            .collect::<Vec<_>>();
        let first_page = page_for(vec![states.first().expect("first state").clone()]);
        let first_body = StrictBody::RecoveryTerminalPage(first_page);
        let first_plain = prost::Message::encoded_len(&crate::replications::proto::wrap_strict(
            "channels",
            first_body.clone(),
        ));
        let first_authenticated =
            crate::replications::proto::strict_encoded_len_with_origin_auth_budget(
                "channels",
                &first_body,
            );
        let mut fitted = Vec::new();
        for state in &states {
            let mut candidate = fitted.clone();
            candidate.push(state.clone());
            let body = StrictBody::RecoveryTerminalPage(page_for(candidate));
            if crate::replications::proto::strict_encoded_len_with_origin_auth_budget(
                "channels", &body,
            ) > crate::replications::proto::STRICT_V2_MAX_REPLICATION_PAYLOAD_BYTES
            {
                break;
            }
            fitted.push(state.clone());
        }
        let fitted_body = StrictBody::RecoveryTerminalPage(page_for(fitted.clone()));
        let fitted_authenticated =
            crate::replications::proto::strict_encoded_len_with_origin_auth_budget(
                "channels",
                &fitted_body,
            );
        println!(
            "node={node} repository_version={repository_version} history_freshness={history_freshness} cut_generation={} rows={record_count} raw_min={raw_min} raw_max={raw_max} states={} first_state={} max_state={} first_page_plain={first_plain} first_page_authenticated={first_authenticated} budget={} fitted_states={} fitted_page_authenticated={fitted_authenticated}",
            cut.generation(),
            states.len(),
            state_lengths.first().copied().unwrap_or(0),
            state_lengths.iter().copied().max().unwrap_or(0),
            crate::replications::proto::STRICT_V2_MAX_REPLICATION_PAYLOAD_BYTES,
            fitted.len(),
        );
    }
}

fn runtime(
    self_id: NodeIdentifier,
    boot_epoch: u64,
) -> (Arc<StrictRuntime<CountingStrictRepo>>, Arc<MockNet>) {
    runtime_with_repo(self_id, boot_epoch, CountingStrictRepo::new_current())
}

fn runtime_with_repo(
    self_id: NodeIdentifier,
    boot_epoch: u64,
    repo: Arc<CountingStrictRepo>,
) -> (Arc<StrictRuntime<CountingStrictRepo>>, Arc<MockNet>) {
    runtime_with_repo_and_config(self_id, boot_epoch, repo, ReplicationConfig::default())
}

fn runtime_with_repo_and_config(
    self_id: NodeIdentifier,
    boot_epoch: u64,
    repo: Arc<CountingStrictRepo>,
    config: ReplicationConfig,
) -> (Arc<StrictRuntime<CountingStrictRepo>>, Arc<MockNet>) {
    let net = MockNet::new(self_id, vec![DONOR, REQUESTER, SECOND_WITNESS]);
    for (node, epoch) in [
        (DONOR, DONOR_EPOCH),
        (REQUESTER, REQUESTER_EPOCH),
        (SECOND_WITNESS, SECOND_WITNESS_EPOCH),
    ] {
        net.set_epoch(node, epoch);
        net.set_peer_strict_replication_protocol_version(node, STRICT_PROTOCOL_VERSION_V8);
    }
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V8);
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V8));
    let rt = StrictRuntime::new(
        repo,
        self_id,
        boot_epoch,
        "channels".to_owned(),
        net.clone(),
        CancellationToken::new(),
        Arc::new(config),
    );
    rt.finish_history_election_for_test();
    assert!(
        rt.recovery_v8_capability_ready(),
        "mandatory-v8 runtime fixture must have a fully capable electorate"
    );
    (rt, net)
}

#[test]
fn runtime_frozen_electorate_counts_restarted_node_once() {
    let (rt, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    assert!(rt.request_recovery_for_test());
    rt.take_recovery_effects();
    let attempt = rt
        .recovery_coordinator
        .lock()
        .attempt()
        .expect("active recovery attempt");
    assert_eq!(
        rt.recovery_coordinator.lock().frozen_electorate(),
        &[u64::from(DONOR), u64::from(SECOND_WITNESS)]
    );
    let target = LogicalTarget::new(7, 8, [9; 32]);
    let cut = |tag| ReducerCut::new([tag; 16], 1, [tag + 1; 32], [9; 32]);

    for epoch in [DONOR_EPOCH, DONOR_EPOCH + 1] {
        net.set_epoch(DONOR, epoch);
        rt.transition_recovery(RecoveryEvent::ProbeResponse {
            attempt,
            attestation: RecoveryAttestation::new(
                ParticipantIncarnation::new(u64::from(DONOR), epoch),
                target.clone(),
                cut(epoch as u8),
                epoch,
            ),
            authenticated: true,
            now_ms: epoch,
        });
    }
    assert_eq!(
        rt.recovery_coordinator.lock().phase(),
        RecoveryPhase::Certifying,
        "a restarted node still occupies only its original frozen node seat"
    );

    rt.transition_recovery(RecoveryEvent::ProbeResponse {
        attempt,
        attestation: RecoveryAttestation::new(
            ParticipantIncarnation::new(u64::from(SECOND_WITNESS), SECOND_WITNESS_EPOCH),
            target,
            cut(SECOND_WITNESS_EPOCH as u8),
            SECOND_WITNESS_EPOCH,
        ),
        authenticated: true,
        now_ms: SECOND_WITNESS_EPOCH,
    });
    assert_eq!(
        rt.recovery_coordinator.lock().phase(),
        RecoveryPhase::FetchingTerminalCheckpoint
    );
}

async fn populated_generation_zero_runtime(
    self_id: NodeIdentifier,
    boot_epoch: u64,
) -> (Arc<StrictRuntime<CountingStrictRepo>>, Arc<MockNet>) {
    let repo = CountingStrictRepo::new_current();
    repo.apply_committed(9, 99).await;
    runtime_with_repo(self_id, boot_epoch, repo)
}

async fn rotate_to_foreign_empty_lineage(
    rt: &Arc<StrictRuntime<CountingStrictRepo>>,
) -> TerminalCut {
    rt.with_terminal_journal_mutation(|journal| {
        journal
            .checkpoint(0)
            .expect("rotate donor to a distinct empty lineage");
        journal.terminal_cut()
    })
    .await
}

fn attempt_bytes(attempt: RecoveryAttemptId) -> Bytes {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&attempt.hi().to_be_bytes());
    bytes[8..].copy_from_slice(&attempt.lo().to_be_bytes());
    Bytes::copy_from_slice(&bytes)
}

fn target() -> LogicalTarget {
    LogicalTarget::new(8, 13, [4; 32])
}

async fn corroborate_local_generation_zero_image(rt: &Arc<StrictRuntime<CountingStrictRepo>>) {
    let metadata = rt.repo.history_metadata();
    let cut = rt.terminal_journal.lock().await.terminal_cut();
    let target = LogicalTarget::new(
        metadata.version,
        metadata.freshness,
        *cut.terminal_set_digest(),
    );
    for (node, epoch) in [
        (DONOR, DONOR_EPOCH),
        (REQUESTER, REQUESTER_EPOCH),
        (SECOND_WITNESS, SECOND_WITNESS_EPOCH),
    ]
    .into_iter()
    .filter(|(node, _)| *node != rt.self_id)
    {
        rt.record_recovery_target_witness_for_test(
            super::sync_v3::PeerIncarnation::new(node, epoch),
            &target,
        )
        .await;
    }
}

fn cut() -> ReducerCut {
    ReducerCut::new([1; 16], 2, [3; 32], [4; 32])
}

fn certify_terminal_transfer(
    rt: &Arc<StrictRuntime<CountingStrictRepo>>,
) -> (
    RecoveryAttemptId,
    ParticipantIncarnation,
    Vec<RecoveryEffect>,
) {
    certify_terminal_transfer_for(rt, target(), cut())
}

fn certify_terminal_transfer_for(
    rt: &Arc<StrictRuntime<CountingStrictRepo>>,
    target: LogicalTarget,
    cut: ReducerCut,
) -> (
    RecoveryAttemptId,
    ParticipantIncarnation,
    Vec<RecoveryEffect>,
) {
    let attempt = RecoveryAttemptId::new(REQUESTER_EPOCH, 7);
    let start_effects = rt.recovery_coordinator.lock().start_attempt(
        RecoveryTrigger::TerminalFence,
        attempt,
        vec![u64::from(DONOR), u64::from(SECOND_WITNESS)],
        1,
    );
    assert!(
        start_effects
            .iter()
            .any(|effect| matches!(effect, RecoveryEffect::SendProbes { .. }))
    );
    rt.transition_recovery(RecoveryEvent::ProbeResponse {
        attempt,
        attestation: RecoveryAttestation::new(
            ParticipantIncarnation::new(u64::from(SECOND_WITNESS), SECOND_WITNESS_EPOCH),
            target.clone(),
            cut.clone(),
            1,
        ),
        authenticated: true,
        now_ms: 2,
    });
    rt.take_recovery_effects();
    let donor = ParticipantIncarnation::new(u64::from(DONOR), DONOR_EPOCH);
    rt.transition_recovery(RecoveryEvent::ProbeResponse {
        attempt,
        attestation: RecoveryAttestation::new(donor.clone(), target, cut, 2),
        authenticated: true,
        now_ms: 3,
    });
    let effects = rt.take_recovery_effects();
    assert_eq!(
        rt.recovery_coordinator.lock().phase(),
        RecoveryPhase::FetchingTerminalCheckpoint
    );
    assert_eq!(rt.recovery_coordinator.lock().donor(), Some(&donor));
    (attempt, donor, effects)
}

#[tokio::test]
async fn unencodable_recovery_attempt_fences_only_its_topic() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let attempt = RecoveryAttemptId::new(REQUESTER_EPOCH, 700);
    requester.transition_recovery(RecoveryEvent::Trigger {
        trigger: RecoveryTrigger::TerminalFence,
        attempt,
        total_known_participants: 3,
        now_ms: 1,
    });
    requester.take_recovery_effects();

    // Runtime participants are u16 node identifiers. Injecting a larger
    // reducer witness exercises the durable-encoding invariant failure without
    // turning that one topic's failed attempt into a process-wide outage.
    requester.transition_recovery(RecoveryEvent::ProbeResponse {
        attempt,
        attestation: RecoveryAttestation::new(
            ParticipantIncarnation::new(u64::from(u16::MAX) + 1, 44),
            target(),
            cut(),
            2,
        ),
        authenticated: true,
        now_ms: 2,
    });
    requester.take_recovery_effects();
    requester.transition_recovery(RecoveryEvent::ProbeResponse {
        attempt,
        attestation: RecoveryAttestation::new(
            ParticipantIncarnation::new(u64::from(SECOND_WITNESS), SECOND_WITNESS_EPOCH),
            target(),
            cut(),
            1,
        ),
        authenticated: true,
        now_ms: 3,
    });

    execute_effects(&requester, requester.take_recovery_effects()).await;

    assert_eq!(
        net.strict_protocol_disable_reports(),
        0,
        "one topic's unencodable recovery attempt must not withdraw strict replication globally"
    );
    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::Backoff,
        "the affected topic must remain fenced pending recertification"
    );
    assert!(requester.take_recovery_effects().iter().any(
        |effect| matches!(effect, RecoveryEffect::Cleanup { attempt: queued } if *queued == attempt)
    ));
}

fn terminal_request(net: &MockNet) -> StrictRecoveryTerminalReq {
    net.drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                dst: DONOR,
                body: StrictBody::RecoveryTerminalReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("terminal recovery request")
}

fn probe_requests(net: &MockNet) -> BTreeMap<NodeIdentifier, StrictRecoveryProbeReq> {
    net.drain_captures()
        .into_iter()
        .filter_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                dst: candidate,
                body: StrictBody::RecoveryProbeReq(request),
                ..
            } => Some((candidate, request)),
            _ => None,
        })
        .collect()
}

fn probe_response(
    request: &StrictRecoveryProbeReq,
    responder: NodeIdentifier,
    responder_epoch: u64,
    target: StrictRecoveryTarget,
    cut: TerminalCut,
) -> StrictRecoveryProbeResp {
    let mut context = request.context.clone().expect("probe context");
    context.expected_donor_boot_epoch = responder_epoch;
    context.target = Some(target);
    StrictRecoveryProbeResp {
        context: Some(context),
        responder_node: responder as u32,
        responder_boot_epoch: responder_epoch,
        request_nonce: request.request_nonce,
        status: StrictRecoveryStatus::Ok.into(),
        terminal_cut: Some(cut_to_wire(cut)),
        runtime_started_at: responder_epoch,
        history_node: responder as u32,
    }
}

fn terminal_pages(net: &MockNet) -> Vec<StrictRecoveryTerminalPage> {
    net.drain_captures()
        .into_iter()
        .filter_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::RecoveryTerminalPage(page),
                ..
            } => Some(page),
            _ => None,
        })
        .collect()
}

fn snapshot_request(net: &MockNet) -> StrictRecoverySnapshotReq {
    net.drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                dst: DONOR,
                body: StrictBody::RecoverySnapshotReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("snapshot recovery request")
}

fn snapshot_pages(net: &MockNet) -> Vec<StrictRecoverySnapshotPage> {
    net.drain_captures()
        .into_iter()
        .filter_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::RecoverySnapshotPage(page),
                ..
            } => Some(page),
            _ => None,
        })
        .collect()
}

async fn begin_snapshot_transfer(
    rt: &Arc<StrictRuntime<CountingStrictRepo>>,
    net: &MockNet,
) -> (
    RecoveryAttemptId,
    ParticipantIncarnation,
    StrictRecoverySnapshotReq,
) {
    let (attempt, donor, effects) = certify_terminal_transfer(rt);
    execute_effects(rt, effects).await;
    let _ = terminal_request(net);
    rt.transition_recovery(RecoveryEvent::TransferProgress {
        attempt,
        donor: donor.clone(),
        kind: super::recovery_reducer::TransferKind::TerminalCheckpoint,
        authenticated: true,
        complete: true,
        now_ms: 4,
    });
    let effects = rt.take_recovery_effects();
    execute_effects(rt, effects).await;
    assert_eq!(
        rt.recovery_coordinator.lock().phase(),
        RecoveryPhase::FetchingRepositorySnapshot
    );
    let request = snapshot_request(net);
    (attempt, donor, request)
}

fn snapshot_digest(bytes: &[u8]) -> Bytes {
    Bytes::copy_from_slice(digest(&SHA256, bytes).as_ref())
}

#[tokio::test]
async fn corroborated_restarted_generation_zero_runtime_autonomously_enters_v8_certification() {
    let temp = tempfile::TempDir::new().expect("temporary strict state directory");
    let repo = CountingStrictRepo::new_current();
    let net = MockNet::new(REQUESTER, vec![DONOR, REQUESTER, SECOND_WITNESS]);
    net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));
    for (node, epoch) in [
        (DONOR, DONOR_EPOCH),
        (REQUESTER, REQUESTER_EPOCH),
        (SECOND_WITNESS, SECOND_WITNESS_EPOCH),
    ] {
        net.set_epoch(node, epoch);
        net.set_peer_strict_replication_protocol_version(node, STRICT_PROTOCOL_VERSION_V8);
    }
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V8);
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V8));
    repo.apply_committed(9, 99).await;

    {
        let initial = StrictRuntime::new(
            repo.clone(),
            REQUESTER,
            REQUESTER_EPOCH - 1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        initial.finish_history_election_for_test();
        assert_eq!(
            initial
                .terminal_journal
                .lock()
                .await
                .terminal_cut()
                .generation(),
            0,
            "restart fixture must retain a generation-zero terminal checkpoint"
        );
    }

    let recovered = StrictRuntime::new(
        repo,
        REQUESTER,
        REQUESTER_EPOCH,
        "channels".to_owned(),
        net,
        CancellationToken::new(),
        Arc::new(
            ReplicationConfig::default()
                .with_strict_bootstrap_retry_interval(Duration::from_millis(20)),
        ),
    );
    recovered.finish_history_election_for_test();
    corroborate_local_generation_zero_image(&recovered).await;
    recovered.start();

    tokio::time::timeout(Duration::from_secs(2), async {
        while recovered.recovery_coordinator.lock().phase() == RecoveryPhase::Healthy {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a corroborated quiescent generation-zero restart must start v8 certification");
    assert_eq!(
        recovered.recovery_coordinator.lock().phase(),
        RecoveryPhase::Certifying
    );
}

fn snapshot_response_page(
    request: &StrictRecoverySnapshotReq,
    cursor: u64,
    bytes: &'static [u8],
    total_bytes: u64,
    digest: Bytes,
) -> StrictRecoverySnapshotPage {
    let next_cursor = cursor + bytes.len() as u64;
    StrictRecoverySnapshotPage {
        context: request.context.clone(),
        responder_node: DONOR as u32,
        responder_boot_epoch: DONOR_EPOCH,
        status: StrictRecoveryStatus::Ok.into(),
        target_cut: request.target_cut.clone(),
        transfer_id: 92,
        request_nonce: request.request_nonce,
        cursor,
        next_cursor,
        total_bytes,
        snapshot_digest: digest,
        snapshot_bytes: Bytes::from_static(bytes),
        has_more: next_cursor < total_bytes,
    }
}

fn response_page(
    request: &StrictRecoveryTerminalReq,
    cursor: u64,
    next_cursor: u64,
    has_more: bool,
) -> StrictRecoveryTerminalPage {
    StrictRecoveryTerminalPage {
        context: request.context.clone(),
        responder_node: DONOR as u32,
        responder_boot_epoch: DONOR_EPOCH,
        status: StrictRecoveryStatus::Ok.into(),
        target_cut: request.target_cut.clone(),
        transfer_id: 91,
        request_nonce: request.request_nonce,
        cursor,
        next_cursor,
        checkpoint_digest: Bytes::from_static(&[4; 32]),
        checkpoint_states: vec![StrictTerminalState::default()],
        has_more,
    }
}

#[tokio::test]
async fn probe_request_requires_authentication_and_exact_requester_and_donor_incarnations() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    let base = StrictRecoveryProbeReq {
        context: Some(StrictRecoveryContext {
            requester_node: REQUESTER as u32,
            requester_boot_epoch: REQUESTER_EPOCH,
            attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 1)),
            expected_donor_boot_epoch: DONOR_EPOCH,
            target: None,
        }),
        request_nonce: 17,
    };

    recv_probe_req(&donor, REQUESTER, REQUESTER_EPOCH, false, base.clone()).await;
    assert!(net.drain_captures().is_empty());

    let mut wrong_requester = base.clone();
    wrong_requester
        .context
        .as_mut()
        .expect("context")
        .requester_boot_epoch += 1;
    recv_probe_req(&donor, REQUESTER, REQUESTER_EPOCH, true, wrong_requester).await;
    assert!(net.drain_captures().is_empty());

    let mut malformed_attempt = base.clone();
    malformed_attempt
        .context
        .as_mut()
        .expect("context")
        .attempt_id = Bytes::from_static(&[1; 15]);
    recv_probe_req(&donor, REQUESTER, REQUESTER_EPOCH, true, malformed_attempt).await;
    assert!(net.drain_captures().is_empty());

    let mut wrong_donor = base.clone();
    wrong_donor
        .context
        .as_mut()
        .expect("context")
        .expected_donor_boot_epoch += 1;
    recv_probe_req(&donor, REQUESTER, REQUESTER_EPOCH, true, wrong_donor).await;
    let mismatch = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::RecoveryProbeResp(response),
                ..
            } => Some(response),
            _ => None,
        })
        .expect("incarnation mismatch response");
    assert_eq!(mismatch.request_nonce, base.request_nonce);
    assert_eq!(
        StrictRecoveryStatus::try_from(mismatch.status).ok(),
        Some(StrictRecoveryStatus::IncarnationMismatch)
    );

    recv_probe_req(&donor, REQUESTER, REQUESTER_EPOCH, true, base).await;
    let response = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::RecoveryProbeResp(response),
                ..
            } => Some(response),
            _ => None,
        })
        .expect("probe response");
    let advertised_cut = donor.terminal_journal.lock().await.terminal_cut();
    assert_eq!(
        StrictRecoveryStatus::try_from(response.status).ok(),
        Some(StrictRecoveryStatus::Ok)
    );
    assert_eq!(response.terminal_cut, Some(cut_to_wire(advertised_cut)));
    let response_target = response
        .context
        .expect("response context")
        .target
        .expect("attested target");
    assert_eq!(response_target.repository_version, 0);
    assert_eq!(response_target.history_freshness, 0);
    assert_eq!(
        response_target.terminal_set_digest.as_ref(),
        advertised_cut.terminal_set_digest()
    );
}

#[tokio::test]
async fn probe_request_never_attests_ok_while_the_v8_participant_floor_is_lost() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V8 - 1);
    let request = StrictRecoveryProbeReq {
        context: Some(StrictRecoveryContext {
            requester_node: REQUESTER as u32,
            requester_boot_epoch: REQUESTER_EPOCH,
            attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 2)),
            expected_donor_boot_epoch: DONOR_EPOCH,
            target: None,
        }),
        request_nonce: 18,
    };

    recv_probe_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request).await;

    let response = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::RecoveryProbeResp(response),
                ..
            } => Some(response),
            _ => None,
        })
        .expect("a capability-blocked probe needs an explicit retryable response");
    assert_eq!(
        StrictRecoveryStatus::try_from(response.status).ok(),
        Some(StrictRecoveryStatus::RetryableFailure)
    );
}

#[tokio::test]
async fn mid_attempt_v8_floor_loss_cancels_queued_transfer_and_recertifies_after_restore() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (attempt, _donor, queued_transfer) = certify_terminal_transfer(&requester);
    let frozen_denominator = requester.recovery_coordinator.lock().frozen_denominator();

    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V8 - 1);
    execute_effects(&requester, queued_transfer).await;

    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::Backoff,
        "capability loss must suspend the durable attempt before transfer"
    );
    assert!(net.drain_captures().is_empty());
    assert_eq!(
        requester.recovery_coordinator.lock().frozen_denominator(),
        frozen_denominator,
        "capability loss must not shrink the attempt's frozen denominator"
    );
    assert!(
        requester
            .recovery_coordinator
            .lock()
            .certificate()
            .is_some(),
        "the old certificate remains durable only while the attempt is suspended"
    );

    let suspended_effects = requester.take_recovery_effects();
    execute_effects(&requester, suspended_effects).await;
    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::Backoff
    );
    assert!(net.drain_captures().is_empty());

    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V8);
    let retry_not_before = requester
        .recovery_coordinator
        .lock()
        .progress_deadline_ms()
        .expect("capability suspension must retain a timed retry");
    requester.transition_recovery(RecoveryEvent::RetryElapsed {
        attempt,
        now_ms: retry_not_before.saturating_sub(1),
    });
    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::Backoff,
        "the fixed 500ms recovery retry must not fire early"
    );
    assert!(requester.take_recovery_effects().is_empty());
    requester.transition_recovery(RecoveryEvent::RetryElapsed {
        attempt,
        now_ms: retry_not_before,
    });
    let retry_effects = requester.take_recovery_effects();
    execute_effects(&requester, retry_effects).await;

    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::Certifying
    );
    assert!(
        requester
            .recovery_coordinator
            .lock()
            .certificate()
            .is_none(),
        "restoring the floor must discard the old denominator and recertify"
    );
    let probes = probe_requests(&net);
    assert_eq!(probes.len(), 2);
    assert!(probes.contains_key(&DONOR));
    assert!(probes.contains_key(&SECOND_WITNESS));
}

#[tokio::test]
async fn probe_response_accepts_only_the_correlated_exact_attestation() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    assert!(requester.request_recovery_for_test());
    let attempt = requester
        .recovery_coordinator
        .lock()
        .attempt()
        .expect("active recovery attempt");
    let effects = requester.take_recovery_effects();
    execute_effects(&requester, effects).await;
    let requests = probe_requests(&net);
    let donor_request = requests.get(&DONOR).expect("donor probe");
    let witness_request = requests.get(&SECOND_WITNESS).expect("witness probe");
    let journal_cut = requester.terminal_journal.lock().await.terminal_cut();
    let exact_target = StrictRecoveryTarget {
        repository_version: 0,
        history_freshness: 0,
        terminal_set_digest: Bytes::copy_from_slice(journal_cut.terminal_set_digest()),
    };
    let exact = probe_response(
        donor_request,
        DONOR,
        DONOR_EPOCH,
        exact_target.clone(),
        journal_cut,
    );

    recv_probe_resp(&requester, DONOR, DONOR_EPOCH, false, exact.clone());

    let mut wrong_attempt = exact.clone();
    wrong_attempt.context.as_mut().expect("context").attempt_id = attempt_bytes(
        RecoveryAttemptId::new(attempt.hi(), attempt.lo().wrapping_add(1)),
    );
    recv_probe_resp(&requester, DONOR, DONOR_EPOCH, true, wrong_attempt);

    let mut wrong_incarnation = exact.clone();
    wrong_incarnation
        .context
        .as_mut()
        .expect("context")
        .expected_donor_boot_epoch += 1;
    recv_probe_resp(&requester, DONOR, DONOR_EPOCH, true, wrong_incarnation);

    let mut wrong_nonce = exact.clone();
    wrong_nonce.request_nonce = wrong_nonce.request_nonce.wrapping_add(1);
    recv_probe_resp(&requester, DONOR, DONOR_EPOCH, true, wrong_nonce);

    let mut mismatched_cut = exact.clone();
    mismatched_cut
        .terminal_cut
        .as_mut()
        .expect("terminal cut")
        .terminal_set_digest = Bytes::from_static(&[9; 32]);
    recv_probe_resp(&requester, DONOR, DONOR_EPOCH, true, mismatched_cut);

    let witness = probe_response(
        witness_request,
        SECOND_WITNESS,
        SECOND_WITNESS_EPOCH,
        exact_target,
        journal_cut,
    );
    recv_probe_resp(
        &requester,
        SECOND_WITNESS,
        SECOND_WITNESS_EPOCH,
        true,
        witness,
    );
    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::Certifying,
        "invalid donor attestations must not count toward quorum"
    );

    recv_probe_resp(&requester, DONOR, DONOR_EPOCH, true, exact);
    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::FetchingTerminalCheckpoint
    );
}

#[tokio::test]
async fn non_ok_probe_statuses_neither_certify_nor_fall_back_to_catchup() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    assert!(requester.request_recovery_for_test());
    execute_effects(&requester, requester.take_recovery_effects()).await;
    let requests = probe_requests(&net);
    let request = requests.get(&DONOR).expect("donor probe request");

    for status in [
        StrictRecoveryStatus::TargetMoved,
        StrictRecoveryStatus::IncarnationMismatch,
        StrictRecoveryStatus::ResourceLimit,
        StrictRecoveryStatus::RetryableFailure,
    ] {
        let mut response = probe_response(
            request,
            DONOR,
            DONOR_EPOCH,
            StrictRecoveryTarget {
                repository_version: target().repository_version(),
                history_freshness: target().history_freshness(),
                terminal_set_digest: Bytes::copy_from_slice(target().terminal_set_digest()),
            },
            TerminalCut::new([1; 16], 2, [3; 32], [4; 32]),
        );
        response.status = status.into();
        recv_probe_resp(&requester, DONOR, DONOR_EPOCH, true, response);
    }

    let coordinator = requester.recovery_coordinator.lock();
    assert_eq!(coordinator.phase(), RecoveryPhase::Certifying);
    assert!(coordinator.certificate().is_none());
    assert!(requester.take_recovery_effects().is_empty());
    assert!(
        net.drain_captures().into_iter().all(|frame| !matches!(
            frame,
            CapturedFrame::StrictUnicast {
                body: StrictBody::CatchupReq(_) | StrictBody::CatchupResp(_),
                ..
            }
        )),
        "a v8 probe status must never enter ordinary catch-up"
    );
}

#[tokio::test]
async fn certified_exact_generation_zero_image_completes_without_transfer_or_audit_churn() {
    let (requester, net) = populated_generation_zero_runtime(REQUESTER, REQUESTER_EPOCH).await;
    corroborate_local_generation_zero_image(&requester).await;
    let local_cut = requester.terminal_journal.lock().await.terminal_cut();
    assert_eq!(local_cut.generation(), 0);
    assert!(request_generation_zero_audit(&requester).await);
    let effects = requester.take_recovery_effects();
    execute_effects(&requester, effects).await;
    let requests = probe_requests(&net);
    let metadata = requester.repo.history_metadata();
    let exact_target = StrictRecoveryTarget {
        repository_version: metadata.version,
        history_freshness: metadata.freshness,
        terminal_set_digest: Bytes::copy_from_slice(local_cut.terminal_set_digest()),
    };
    for (node, epoch) in [(DONOR, DONOR_EPOCH), (SECOND_WITNESS, SECOND_WITNESS_EPOCH)] {
        let response = probe_response(
            requests.get(&node).expect("autonomous audit probe"),
            node,
            epoch,
            exact_target.clone(),
            local_cut,
        );
        recv_probe_resp(&requester, node, epoch, true, response);
    }
    let effects = requester.take_recovery_effects();
    execute_effects(&requester, effects).await;

    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::Healthy,
        "a quorum-certified exact local envelope needs no donor transfer"
    );
    assert!(
        net.drain_captures().into_iter().all(|frame| !matches!(
            frame,
            CapturedFrame::StrictUnicast {
                body: StrictBody::RecoveryTerminalReq(_) | StrictBody::RecoverySnapshotReq(_),
                ..
            }
        )),
        "exact local verification must not open terminal or repository sessions"
    );
    assert!(
        !request_generation_zero_audit(&requester).await,
        "the exact verified envelope must suppress periodic re-audits"
    );
    assert!(net.drain_captures().is_empty());
}

#[tokio::test]
async fn uncorroborated_generation_zero_image_does_not_start_autonomous_recovery() {
    let (requester, net) = populated_generation_zero_runtime(REQUESTER, REQUESTER_EPOCH).await;

    assert!(
        !request_generation_zero_audit(&requester).await,
        "a local generation-zero image without matching witness heads is not a certified recovery target"
    );
    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::Healthy
    );
    assert!(net.drain_captures().is_empty());
}

#[tokio::test]
async fn normal_repository_commit_after_runtime_construction_suppresses_generation_zero_audit() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    requester.apply_repository_commit(9, 99).await;
    corroborate_local_generation_zero_image(&requester).await;

    assert!(
        !request_generation_zero_audit(&requester).await,
        "a normal same-lineage mutation after construction must not be mistaken for copied generation-zero state"
    );
    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::Healthy
    );
    assert!(net.drain_captures().is_empty());
}

#[tokio::test]
async fn normal_repository_commit_yields_an_active_generation_zero_audit() {
    let (requester, _net) = populated_generation_zero_runtime(REQUESTER, REQUESTER_EPOCH).await;
    corroborate_local_generation_zero_image(&requester).await;
    assert!(request_generation_zero_audit(&requester).await);
    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::Certifying
    );

    requester.apply_repository_commit(10, 100).await;

    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::Healthy,
        "same-lineage repository progress must retain availability instead of leaving the periodic auditor fenced"
    );
    assert!(!request_generation_zero_audit(&requester).await);
}

#[tokio::test]
async fn ordinary_snapshot_catchup_suppresses_generation_zero_audit_even_for_the_same_image() {
    let (requester, net) = populated_generation_zero_runtime(REQUESTER, REQUESTER_EPOCH).await;
    let (version, snapshot) = requester.repo.snapshot().expect("startup repository image");
    requester
        .install_repository_snapshot(version, snapshot)
        .await
        .expect("ordinary catchup reinstall");
    corroborate_local_generation_zero_image(&requester).await;

    assert!(
        !request_generation_zero_audit(&requester).await,
        "ordinary catchup must retire the construction-time audit candidate even when it reinstalls identical bytes"
    );
    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::Healthy
    );
    assert!(net.drain_captures().is_empty());
}

#[tokio::test]
async fn metadata_and_cut_equality_without_a_verified_local_envelope_still_transfers() {
    let (requester, net) = populated_generation_zero_runtime(REQUESTER, REQUESTER_EPOCH).await;
    corroborate_local_generation_zero_image(&requester).await;
    let local_cut = requester.terminal_journal.lock().await.terminal_cut();
    assert!(request_generation_zero_audit(&requester).await);
    let effects = requester.take_recovery_effects();
    execute_effects(&requester, effects).await;
    let requests = probe_requests(&net);
    let metadata = requester.repo.history_metadata();
    let exact_target = StrictRecoveryTarget {
        repository_version: metadata.version,
        history_freshness: metadata.freshness,
        terminal_set_digest: Bytes::copy_from_slice(local_cut.terminal_set_digest()),
    };
    requester
        .repo
        .fail_snapshot_captures("local envelope unavailable");
    for (node, epoch) in [(DONOR, DONOR_EPOCH), (SECOND_WITNESS, SECOND_WITNESS_EPOCH)] {
        recv_probe_resp(
            &requester,
            node,
            epoch,
            true,
            probe_response(
                requests.get(&node).expect("autonomous audit probe"),
                node,
                epoch,
                exact_target.clone(),
                local_cut,
            ),
        );
    }
    let effects = requester.take_recovery_effects();
    execute_effects(&requester, effects).await;

    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::FetchingTerminalCheckpoint
    );
    assert!(net.drain_captures().iter().any(|frame| matches!(
        frame,
        CapturedFrame::StrictUnicast {
            body: StrictBody::RecoveryTerminalReq(_),
            ..
        }
    )));
}

#[tokio::test]
async fn terminal_request_rejects_unauthenticated_and_wrong_incarnation_contexts() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    let cut = donor.terminal_journal.lock().await.terminal_cut();
    let target = StrictRecoveryTarget {
        repository_version: 0,
        history_freshness: 0,
        terminal_set_digest: Bytes::copy_from_slice(cut.terminal_set_digest()),
    };
    let base = StrictRecoveryTerminalReq {
        context: Some(StrictRecoveryContext {
            requester_node: REQUESTER as u32,
            requester_boot_epoch: REQUESTER_EPOCH,
            attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 1)),
            expected_donor_boot_epoch: DONOR_EPOCH,
            target: Some(target),
        }),
        target_cut: Some(cut_to_wire(cut)),
        transfer_id: 0,
        request_nonce: 8,
        expected_cursor: 0,
    };

    recv_terminal_req(&donor, REQUESTER, REQUESTER_EPOCH, false, base.clone()).await;
    assert!(net.drain_captures().is_empty());

    let mut wrong_incarnation = base.clone();
    wrong_incarnation
        .context
        .as_mut()
        .expect("context")
        .expected_donor_boot_epoch += 1;
    recv_terminal_req(&donor, REQUESTER, REQUESTER_EPOCH, true, wrong_incarnation).await;
    let pages = terminal_pages(&net);
    assert_eq!(pages.len(), 1);
    assert_eq!(
        StrictRecoveryStatus::try_from(pages[0].status).ok(),
        Some(StrictRecoveryStatus::IncarnationMismatch)
    );

    recv_terminal_req(&donor, REQUESTER, REQUESTER_EPOCH, true, base).await;
    let pages = terminal_pages(&net);
    assert_eq!(pages.len(), 1);
    assert_eq!(
        StrictRecoveryStatus::try_from(pages[0].status).ok(),
        Some(StrictRecoveryStatus::Ok)
    );
}

#[tokio::test]
async fn donor_requires_the_exact_probe_attestation_before_terminal_or_snapshot_service() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    let cut = donor.terminal_journal.lock().await.terminal_cut();
    let context = StrictRecoveryContext {
        requester_node: REQUESTER as u32,
        requester_boot_epoch: REQUESTER_EPOCH,
        attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 402)),
        expected_donor_boot_epoch: DONOR_EPOCH,
        target: Some(StrictRecoveryTarget {
            repository_version: 0,
            history_freshness: 0,
            terminal_set_digest: Bytes::copy_from_slice(cut.terminal_set_digest()),
        }),
    };
    let terminal = StrictRecoveryTerminalReq {
        context: Some(context.clone()),
        target_cut: Some(cut_to_wire(cut)),
        transfer_id: 0,
        request_nonce: 74,
        expected_cursor: 0,
    };
    recv_terminal_req_runtime(&donor, REQUESTER, REQUESTER_EPOCH, true, terminal.clone()).await;
    assert_eq!(
        StrictRecoveryStatus::try_from(terminal_pages(&net)[0].status).ok(),
        Some(StrictRecoveryStatus::RetryableFailure)
    );

    attest_terminal_request_for_test(&donor, REQUESTER, REQUESTER_EPOCH, &terminal);
    recv_terminal_req_runtime(&donor, REQUESTER, REQUESTER_EPOCH, true, terminal).await;
    assert_eq!(
        StrictRecoveryStatus::try_from(terminal_pages(&net)[0].status).ok(),
        Some(StrictRecoveryStatus::Ok)
    );

    let unprobed_snapshot = StrictRecoverySnapshotReq {
        context: Some(StrictRecoveryContext {
            attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 403)),
            ..context
        }),
        target_cut: Some(cut_to_wire(cut)),
        transfer_id: 0,
        request_nonce: 75,
        expected_cursor: 0,
    };
    recv_snapshot_req_runtime(&donor, REQUESTER, REQUESTER_EPOCH, true, unprobed_snapshot).await;
    assert_eq!(
        StrictRecoveryStatus::try_from(snapshot_pages(&net)[0].status).ok(),
        Some(StrictRecoveryStatus::RetryableFailure)
    );
}

#[tokio::test]
async fn oversized_repository_image_returns_correlated_resource_limit() {
    let repo = CountingStrictRepo::new_current();
    *repo.state.lock() = (
        256,
        (1..=256).map(|version| (version, version, None)).collect(),
    );
    let (donor, net) = runtime_with_repo_and_config(
        DONOR,
        DONOR_EPOCH,
        repo,
        ReplicationConfig::default().with_strict_max_snapshot_transfer_bytes(128),
    );
    let cut = donor.terminal_journal.lock().await.terminal_cut();
    let request = StrictRecoverySnapshotReq {
        context: Some(StrictRecoveryContext {
            requester_node: REQUESTER as u32,
            requester_boot_epoch: REQUESTER_EPOCH,
            attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 407)),
            expected_donor_boot_epoch: DONOR_EPOCH,
            target: Some(StrictRecoveryTarget {
                repository_version: 256,
                history_freshness: 0,
                terminal_set_digest: Bytes::copy_from_slice(cut.terminal_set_digest()),
            }),
        }),
        target_cut: Some(cut_to_wire(cut)),
        transfer_id: 0,
        request_nonce: 81,
        expected_cursor: 0,
    };

    recv_snapshot_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request.clone()).await;

    let pages = snapshot_pages(&net);
    assert_eq!(pages.len(), 1);
    let page = &pages[0];
    assert_eq!(
        StrictRecoveryStatus::try_from(page.status).ok(),
        Some(StrictRecoveryStatus::ResourceLimit)
    );
    assert_eq!(page.context, request.context);
    assert_eq!(page.target_cut, request.target_cut);
    assert_eq!(page.transfer_id, request.transfer_id);
    assert_eq!(page.request_nonce, request.request_nonce);
    assert_eq!(page.cursor, request.expected_cursor);
    assert_eq!(page.next_cursor, request.expected_cursor);
    assert_eq!(page.total_bytes, 0);
    assert!(page.snapshot_digest.is_empty());
    assert!(page.snapshot_bytes.is_empty());
    assert!(!page.has_more);
}

#[tokio::test]
async fn terminal_ack_can_arrive_before_bulk_send_await_returns() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    let cut = donor.terminal_journal.lock().await.terminal_cut();
    let request = StrictRecoveryTerminalReq {
        context: Some(StrictRecoveryContext {
            requester_node: REQUESTER as u32,
            requester_boot_epoch: REQUESTER_EPOCH,
            attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 403)),
            expected_donor_boot_epoch: DONOR_EPOCH,
            target: Some(StrictRecoveryTarget {
                repository_version: 0,
                history_freshness: 0,
                terminal_set_digest: Bytes::copy_from_slice(cut.terminal_set_digest()),
            }),
        }),
        target_cut: Some(cut_to_wire(cut)),
        transfer_id: 0,
        request_nonce: 76,
        expected_cursor: 0,
    };
    let pause = net.pause_next_bulk_send_after_capture();
    let send = tokio::spawn({
        let donor = Arc::clone(&donor);
        async move {
            recv_terminal_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request).await;
        }
    });
    pause.wait_until_captured().await;
    let page = terminal_pages(&net)
        .into_iter()
        .next()
        .expect("bulk terminal page");
    recv_terminal_ack(
        &donor,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        StrictRecoveryTerminalAck {
            context: page.context.clone(),
            target_cut: page.target_cut.clone(),
            transfer_id: page.transfer_id,
            request_nonce: page.request_nonce,
            acknowledged_cursor: page.next_cursor,
            final_ack: !page.has_more,
        },
    )
    .await;

    assert_eq!(
        net.drain_bulk_acknowledgements().len(),
        1,
        "the page identity must be registered before the bulk send becomes visible"
    );
    pause.release();
    send.await.expect("terminal donor task");
}

#[tokio::test]
async fn duplicate_terminal_backpressure_preserves_the_original_ack_identity() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    let cut = donor.terminal_journal.lock().await.terminal_cut();
    let request = StrictRecoveryTerminalReq {
        context: Some(StrictRecoveryContext {
            requester_node: REQUESTER as u32,
            requester_boot_epoch: REQUESTER_EPOCH,
            attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 407)),
            expected_donor_boot_epoch: DONOR_EPOCH,
            target: Some(StrictRecoveryTarget {
                repository_version: 0,
                history_freshness: 0,
                terminal_set_digest: Bytes::copy_from_slice(cut.terminal_set_digest()),
            }),
        }),
        target_cut: Some(cut_to_wire(cut)),
        transfer_id: 0,
        request_nonce: 83,
        expected_cursor: 0,
    };
    net.script_bulk_send_outcomes([MockBulkSendOutcome::Sent, MockBulkSendOutcome::Backpressure]);

    recv_terminal_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request.clone()).await;
    let original = terminal_pages(&net)
        .pop()
        .expect("original retained terminal page");
    recv_terminal_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request).await;
    let retry = terminal_pages(&net)
        .pop()
        .expect("duplicate backpressure retry status");
    assert_eq!(
        StrictRecoveryStatus::try_from(retry.status).ok(),
        Some(StrictRecoveryStatus::RetryableFailure)
    );

    recv_terminal_ack(
        &donor,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        StrictRecoveryTerminalAck {
            context: original.context.clone(),
            target_cut: original.target_cut.clone(),
            transfer_id: original.transfer_id,
            request_nonce: original.request_nonce,
            acknowledged_cursor: original.next_cursor,
            final_ack: !original.has_more,
        },
    )
    .await;
    assert_eq!(
        net.drain_bulk_acknowledgements(),
        vec![(
            REQUESTER,
            "channels".to_owned(),
            BulkPageIdentity::recovery_terminal(original.transfer_id, original.request_nonce),
        )],
        "a failed duplicate send must not delete the retained original page's ACK identity"
    );
}

#[tokio::test]
async fn terminal_continuation_implicitly_releases_prior_bulk_page_before_send() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    donor
        .with_terminal_journal_mutation(|journal| {
            for sequence in 1..=3 {
                journal
                    .upsert_commit_decision_bytes(
                        make_op_id(DONOR, DONOR_EPOCH, sequence),
                        sequence,
                        sequence,
                        Bytes::from(vec![sequence as u8; 512]),
                    )
                    .expect("seed multipage checkpoint");
            }
        })
        .await;
    let cut = donor.terminal_journal.lock().await.terminal_cut();
    let context = StrictRecoveryContext {
        requester_node: REQUESTER as u32,
        requester_boot_epoch: REQUESTER_EPOCH,
        attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 405)),
        expected_donor_boot_epoch: DONOR_EPOCH,
        target: Some(StrictRecoveryTarget {
            repository_version: 0,
            history_freshness: 0,
            terminal_set_digest: Bytes::copy_from_slice(cut.terminal_set_digest()),
        }),
    };
    let sizing_request = StrictRecoveryTerminalReq {
        context: Some(context.clone()),
        target_cut: Some(cut_to_wire(cut)),
        transfer_id: 0,
        request_nonce: 78,
        expected_cursor: 0,
    };
    recv_terminal_req(&donor, REQUESTER, REQUESTER_EPOCH, true, sizing_request).await;
    let full = terminal_pages(&net).pop().expect("sizing terminal page");
    let budget = full
        .checkpoint_states
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, state)| {
            let mut one_state = full.clone();
            one_state.request_nonce = 79 + index as u64;
            one_state.cursor = index as u64;
            one_state.next_cursor = index as u64 + 1;
            one_state.checkpoint_states = vec![state];
            one_state.has_more = one_state.next_cursor < cut.generation();
            donor
                .v2_strict_replication_payload_len(&StrictBody::RecoveryTerminalPage(one_state))
                .expect("one-state terminal page size")
        })
        .max()
        .expect("seeded terminal states");
    net.set_max_replication_payload_bytes(budget);

    recv_terminal_req(
        &donor,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        StrictRecoveryTerminalReq {
            context: Some(context.clone()),
            target_cut: Some(cut_to_wire(cut)),
            transfer_id: 0,
            request_nonce: 79,
            expected_cursor: 0,
        },
    )
    .await;
    let first = terminal_pages(&net).pop().expect("first terminal page");
    assert!(first.has_more);
    net.script_bulk_send_outcomes([MockBulkSendOutcome::BackpressureUntilAcknowledged]);
    recv_terminal_req(
        &donor,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        StrictRecoveryTerminalReq {
            context: Some(context),
            target_cut: Some(cut_to_wire(cut)),
            transfer_id: first.transfer_id,
            request_nonce: 80,
            expected_cursor: first.next_cursor,
        },
    )
    .await;
    let second = terminal_pages(&net).pop().expect("second terminal page");
    assert_eq!(
        StrictRecoveryStatus::try_from(second.status).ok(),
        Some(StrictRecoveryStatus::Ok)
    );
    assert_eq!(second.cursor, first.next_cursor);
    assert_eq!(
        net.drain_bulk_acknowledgements().len(),
        1,
        "the authenticated continuation must release the prior bulk reservation before sending"
    );

    for (index, page) in [&first, &second].into_iter().enumerate() {
        recv_terminal_ack(
            &donor,
            REQUESTER,
            REQUESTER_EPOCH,
            true,
            StrictRecoveryTerminalAck {
                context: page.context.clone(),
                target_cut: page.target_cut.clone(),
                transfer_id: page.transfer_id,
                request_nonce: page.request_nonce,
                acknowledged_cursor: page.next_cursor,
                final_ack: !page.has_more,
            },
        )
        .await;
        assert_eq!(
            net.drain_bulk_acknowledgements().len(),
            usize::from(index == 1),
            "late explicit ACK {index} was not idempotent"
        );
    }
}

#[tokio::test]
async fn snapshot_ack_can_arrive_before_bulk_send_await_returns() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    let cut = donor.terminal_journal.lock().await.terminal_cut();
    let request = StrictRecoverySnapshotReq {
        context: Some(StrictRecoveryContext {
            requester_node: REQUESTER as u32,
            requester_boot_epoch: REQUESTER_EPOCH,
            attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 404)),
            expected_donor_boot_epoch: DONOR_EPOCH,
            target: Some(StrictRecoveryTarget {
                repository_version: 0,
                history_freshness: 0,
                terminal_set_digest: Bytes::copy_from_slice(cut.terminal_set_digest()),
            }),
        }),
        target_cut: Some(cut_to_wire(cut)),
        transfer_id: 0,
        request_nonce: 77,
        expected_cursor: 0,
    };
    let pause = net.pause_next_bulk_send_after_capture();
    let send = tokio::spawn({
        let donor = Arc::clone(&donor);
        async move {
            recv_snapshot_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request).await;
        }
    });
    pause.wait_until_captured().await;
    let page = snapshot_pages(&net)
        .into_iter()
        .next()
        .expect("bulk snapshot page");
    recv_snapshot_ack(
        &donor,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        StrictRecoverySnapshotAck {
            context: page.context.clone(),
            target_cut: page.target_cut.clone(),
            transfer_id: page.transfer_id,
            request_nonce: page.request_nonce,
            acknowledged_cursor: page.next_cursor,
            final_ack: !page.has_more,
        },
    )
    .await;

    assert_eq!(
        net.drain_bulk_acknowledgements().len(),
        1,
        "the snapshot page identity must remain registered across the send await"
    );
    pause.release();
    send.await.expect("snapshot donor task");
}

#[tokio::test]
async fn duplicate_snapshot_backpressure_preserves_the_original_ack_identity() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    let cut = donor.terminal_journal.lock().await.terminal_cut();
    let request = StrictRecoverySnapshotReq {
        context: Some(StrictRecoveryContext {
            requester_node: REQUESTER as u32,
            requester_boot_epoch: REQUESTER_EPOCH,
            attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 408)),
            expected_donor_boot_epoch: DONOR_EPOCH,
            target: Some(StrictRecoveryTarget {
                repository_version: 0,
                history_freshness: 0,
                terminal_set_digest: Bytes::copy_from_slice(cut.terminal_set_digest()),
            }),
        }),
        target_cut: Some(cut_to_wire(cut)),
        transfer_id: 0,
        request_nonce: 84,
        expected_cursor: 0,
    };
    net.script_bulk_send_outcomes([MockBulkSendOutcome::Sent, MockBulkSendOutcome::Backpressure]);

    recv_snapshot_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request.clone()).await;
    let original = snapshot_pages(&net)
        .pop()
        .expect("original retained snapshot page");
    recv_snapshot_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request).await;
    let retry = snapshot_pages(&net)
        .pop()
        .expect("duplicate backpressure retry status");
    assert_eq!(
        StrictRecoveryStatus::try_from(retry.status).ok(),
        Some(StrictRecoveryStatus::RetryableFailure)
    );

    recv_snapshot_ack(
        &donor,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        StrictRecoverySnapshotAck {
            context: original.context.clone(),
            target_cut: original.target_cut.clone(),
            transfer_id: original.transfer_id,
            request_nonce: original.request_nonce,
            acknowledged_cursor: original.next_cursor,
            final_ack: !original.has_more,
        },
    )
    .await;
    assert_eq!(
        net.drain_bulk_acknowledgements(),
        vec![(
            REQUESTER,
            "channels".to_owned(),
            BulkPageIdentity::recovery_snapshot(original.transfer_id, original.request_nonce),
        )],
        "a failed duplicate send must not delete the retained original snapshot ACK identity"
    );
}

#[tokio::test]
async fn snapshot_continuation_implicitly_releases_prior_bulk_page_before_send() {
    let repo = CountingStrictRepo::new_current();
    for version in 1..=1_000 {
        repo.apply_committed(version, version).await;
    }
    let (donor, net) = runtime_with_repo(DONOR, DONOR_EPOCH, repo);
    net.set_max_replication_payload_bytes(4_096);
    let cut = donor.terminal_journal.lock().await.terminal_cut();
    let context = StrictRecoveryContext {
        requester_node: REQUESTER as u32,
        requester_boot_epoch: REQUESTER_EPOCH,
        attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 406)),
        expected_donor_boot_epoch: DONOR_EPOCH,
        target: Some(StrictRecoveryTarget {
            repository_version: 1_000,
            history_freshness: 0,
            terminal_set_digest: Bytes::copy_from_slice(cut.terminal_set_digest()),
        }),
    };
    recv_snapshot_req(
        &donor,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        StrictRecoverySnapshotReq {
            context: Some(context.clone()),
            target_cut: Some(cut_to_wire(cut)),
            transfer_id: 0,
            request_nonce: 81,
            expected_cursor: 0,
        },
    )
    .await;
    let first = snapshot_pages(&net).pop().expect("first snapshot page");
    assert!(first.has_more, "fixture must produce a multipage snapshot");

    net.script_bulk_send_outcomes([MockBulkSendOutcome::BackpressureUntilAcknowledged]);
    recv_snapshot_req(
        &donor,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        StrictRecoverySnapshotReq {
            context: Some(context),
            target_cut: Some(cut_to_wire(cut)),
            transfer_id: first.transfer_id,
            request_nonce: 82,
            expected_cursor: first.next_cursor,
        },
    )
    .await;
    let second = snapshot_pages(&net).pop().expect("second snapshot page");
    assert_eq!(
        StrictRecoveryStatus::try_from(second.status).ok(),
        Some(StrictRecoveryStatus::Ok)
    );
    assert_eq!(second.cursor, first.next_cursor);
    assert_eq!(
        net.drain_bulk_acknowledgements().len(),
        1,
        "the snapshot continuation must release the prior reservation first"
    );

    for (index, page) in [&first, &second].into_iter().enumerate() {
        recv_snapshot_ack(
            &donor,
            REQUESTER,
            REQUESTER_EPOCH,
            true,
            StrictRecoverySnapshotAck {
                context: page.context.clone(),
                target_cut: page.target_cut.clone(),
                transfer_id: page.transfer_id,
                request_nonce: page.request_nonce,
                acknowledged_cursor: page.next_cursor,
                final_ack: !page.has_more,
            },
        )
        .await;
        assert_eq!(
            net.drain_bulk_acknowledgements().len(),
            usize::from(index == 1),
            "late explicit snapshot ACK {index} was not idempotent"
        );
    }
}

#[tokio::test]
async fn certifying_autonomous_auditor_yields_only_for_its_exact_prior_attestation() {
    let (donor, net) = populated_generation_zero_runtime(DONOR, DONOR_EPOCH).await;
    corroborate_local_generation_zero_image(&donor).await;
    assert!(request_generation_zero_audit(&donor).await);
    assert_eq!(
        donor.recovery_coordinator.lock().phase(),
        RecoveryPhase::Certifying
    );

    let requester_attempt = RecoveryAttemptId::new(REQUESTER_EPOCH, 404);
    let probe = StrictRecoveryProbeReq {
        context: Some(StrictRecoveryContext {
            requester_node: REQUESTER as u32,
            requester_boot_epoch: REQUESTER_EPOCH,
            attempt_id: attempt_bytes(requester_attempt),
            expected_donor_boot_epoch: DONOR_EPOCH,
            target: None,
        }),
        request_nonce: 77,
    };
    recv_probe_req(&donor, REQUESTER, REQUESTER_EPOCH, true, probe).await;
    let attestation = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::RecoveryProbeResp(response),
                ..
            } => Some(response),
            _ => None,
        })
        .expect("exact probe attestation");
    let request = StrictRecoveryTerminalReq {
        context: attestation.context,
        target_cut: attestation.terminal_cut,
        transfer_id: 0,
        request_nonce: 78,
        expected_cursor: 0,
    };
    recv_terminal_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request).await;

    assert_eq!(
        donor.recovery_coordinator.lock().phase(),
        RecoveryPhase::Healthy,
        "the autonomous audit must yield before donating its exact attested image"
    );
    assert_eq!(
        StrictRecoveryStatus::try_from(terminal_pages(&net)[0].status).ok(),
        Some(StrictRecoveryStatus::Ok)
    );
}

#[tokio::test]
async fn certifying_autonomous_auditor_does_not_yield_for_a_moved_attestation() {
    let (donor, net) = populated_generation_zero_runtime(DONOR, DONOR_EPOCH).await;
    corroborate_local_generation_zero_image(&donor).await;
    assert!(request_generation_zero_audit(&donor).await);
    let probe = StrictRecoveryProbeReq {
        context: Some(StrictRecoveryContext {
            requester_node: REQUESTER as u32,
            requester_boot_epoch: REQUESTER_EPOCH,
            attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 405)),
            expected_donor_boot_epoch: DONOR_EPOCH,
            target: None,
        }),
        request_nonce: 79,
    };
    recv_probe_req(&donor, REQUESTER, REQUESTER_EPOCH, true, probe).await;
    let attestation = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::RecoveryProbeResp(response),
                ..
            } => Some(response),
            _ => None,
        })
        .expect("probe attestation");
    let mut moved_context = attestation.context.expect("attested context");
    moved_context
        .target
        .as_mut()
        .expect("attested target")
        .repository_version += 1;
    recv_terminal_req_runtime(
        &donor,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        StrictRecoveryTerminalReq {
            context: Some(moved_context),
            target_cut: attestation.terminal_cut,
            transfer_id: 0,
            request_nonce: 80,
            expected_cursor: 0,
        },
    )
    .await;

    assert_eq!(
        donor.recovery_coordinator.lock().phase(),
        RecoveryPhase::Certifying,
        "a moved target must leave the autonomous audit fenced"
    );
    assert_eq!(
        StrictRecoveryStatus::try_from(terminal_pages(&net)[0].status).ok(),
        Some(StrictRecoveryStatus::TargetMoved)
    );
}

#[tokio::test]
async fn terminal_request_enforces_the_exact_attested_cut_and_repository_head() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    let current_cut = donor.terminal_journal.lock().await.terminal_cut();
    let context = StrictRecoveryContext {
        requester_node: REQUESTER as u32,
        requester_boot_epoch: REQUESTER_EPOCH,
        attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 2)),
        expected_donor_boot_epoch: DONOR_EPOCH,
        target: Some(StrictRecoveryTarget {
            repository_version: 0,
            history_freshness: 0,
            terminal_set_digest: Bytes::copy_from_slice(current_cut.terminal_set_digest()),
        }),
    };
    let exact = StrictRecoveryTerminalReq {
        context: Some(context.clone()),
        target_cut: Some(cut_to_wire(current_cut)),
        transfer_id: 0,
        request_nonce: 9,
        expected_cursor: 0,
    };
    recv_terminal_req(&donor, REQUESTER, REQUESTER_EPOCH, true, exact).await;
    assert_eq!(
        StrictRecoveryStatus::try_from(terminal_pages(&net)[0].status).ok(),
        Some(StrictRecoveryStatus::Ok)
    );

    let moved = StrictRecoveryTerminalReq {
        context: Some(context),
        target_cut: Some(cut_to_wire(TerminalCut::new(
            [9; 16],
            current_cut.generation(),
            *current_cut.chain_digest(),
            *current_cut.terminal_set_digest(),
        ))),
        transfer_id: 0,
        request_nonce: 10,
        expected_cursor: 0,
    };
    recv_terminal_req(&donor, REQUESTER, REQUESTER_EPOCH, true, moved).await;
    assert_eq!(
        StrictRecoveryStatus::try_from(terminal_pages(&net)[0].status).ok(),
        Some(StrictRecoveryStatus::TargetMoved)
    );
}

#[tokio::test]
async fn snapshot_request_cut_mismatch_returns_a_correlated_target_moved_status() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    let current_cut = donor.terminal_journal.lock().await.terminal_cut();
    let context = StrictRecoveryContext {
        requester_node: REQUESTER as u32,
        requester_boot_epoch: REQUESTER_EPOCH,
        attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 21)),
        expected_donor_boot_epoch: DONOR_EPOCH,
        target: Some(StrictRecoveryTarget {
            repository_version: 0,
            history_freshness: 0,
            terminal_set_digest: Bytes::copy_from_slice(current_cut.terminal_set_digest()),
        }),
    };
    let exact = StrictRecoverySnapshotReq {
        context: Some(context.clone()),
        target_cut: Some(cut_to_wire(current_cut)),
        transfer_id: 0,
        request_nonce: 41,
        expected_cursor: 0,
    };
    recv_snapshot_req(&donor, REQUESTER, REQUESTER_EPOCH, true, exact).await;
    assert_eq!(
        StrictRecoveryStatus::try_from(snapshot_pages(&net)[0].status).ok(),
        Some(StrictRecoveryStatus::Ok)
    );

    let moved = StrictRecoverySnapshotReq {
        context: Some(context),
        target_cut: Some(cut_to_wire(TerminalCut::new(
            [9; 16],
            current_cut.generation(),
            *current_cut.chain_digest(),
            *current_cut.terminal_set_digest(),
        ))),
        transfer_id: 0,
        request_nonce: 42,
        expected_cursor: 0,
    };
    recv_snapshot_req_runtime(&donor, REQUESTER, REQUESTER_EPOCH, true, moved.clone()).await;
    let response = snapshot_pages(&net)
        .pop()
        .expect("correlated target-moved snapshot response");
    assert_eq!(
        StrictRecoveryStatus::try_from(response.status).ok(),
        Some(StrictRecoveryStatus::TargetMoved)
    );
    assert_eq!(response.context, moved.context);
    assert_eq!(response.target_cut, moved.target_cut);
    assert_eq!(response.request_nonce, moved.request_nonce);
    assert_eq!(response.cursor, moved.expected_cursor);
    assert_eq!(response.next_cursor, moved.expected_cursor);
}

#[tokio::test]
async fn terminal_checkpoint_pages_are_bounded_by_the_encoded_replication_payload() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    donor
        .with_terminal_journal_mutation(|journal| {
            for sequence in 1..=3 {
                journal
                    .upsert_commit_decision_bytes(
                        make_op_id(DONOR, DONOR_EPOCH, sequence),
                        sequence,
                        sequence,
                        Bytes::from(vec![sequence as u8; 512]),
                    )
                    .expect("seed terminal checkpoint state");
            }
        })
        .await;
    let cut = donor.terminal_journal.lock().await.terminal_cut();
    let context = StrictRecoveryContext {
        requester_node: REQUESTER as u32,
        requester_boot_epoch: REQUESTER_EPOCH,
        attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 81)),
        expected_donor_boot_epoch: DONOR_EPOCH,
        target: Some(StrictRecoveryTarget {
            repository_version: 0,
            history_freshness: 0,
            terminal_set_digest: Bytes::copy_from_slice(cut.terminal_set_digest()),
        }),
    };
    let first_request = StrictRecoveryTerminalReq {
        context: Some(context.clone()),
        target_cut: Some(cut_to_wire(cut)),
        transfer_id: 0,
        request_nonce: 121,
        expected_cursor: 0,
    };
    recv_terminal_req(&donor, REQUESTER, REQUESTER_EPOCH, true, first_request).await;
    let full_page = terminal_pages(&net).pop().expect("unbounded terminal page");
    assert_eq!(
        StrictRecoveryStatus::try_from(full_page.status).ok(),
        Some(StrictRecoveryStatus::Ok),
        "unbounded checkpoint request must succeed: {full_page:?}"
    );
    assert_eq!(full_page.checkpoint_states.len(), 3);

    let mut one_state_page = full_page.clone();
    one_state_page.request_nonce = 122;
    one_state_page.next_cursor = 1;
    one_state_page.checkpoint_states.truncate(1);
    one_state_page.has_more = true;
    let budget = donor
        .v2_strict_replication_payload_len(&StrictBody::RecoveryTerminalPage(one_state_page))
        .expect("terminal page size");
    net.set_max_replication_payload_bytes(budget);

    let bounded_request = StrictRecoveryTerminalReq {
        context: Some(context.clone()),
        target_cut: Some(cut_to_wire(cut)),
        transfer_id: 0,
        request_nonce: 122,
        expected_cursor: 0,
    };
    recv_terminal_req(
        &donor,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        bounded_request.clone(),
    )
    .await;
    let bounded = terminal_pages(&net).pop().expect("bounded terminal page");
    assert_eq!(
        StrictRecoveryStatus::try_from(bounded.status).ok(),
        Some(StrictRecoveryStatus::Ok)
    );
    assert_eq!(bounded.cursor, 0);
    assert_eq!(bounded.next_cursor, 1);
    assert_eq!(bounded.checkpoint_states.len(), 1);
    assert!(bounded.has_more);
    assert!(
        donor
            .v2_strict_replication_payload_len(&StrictBody::RecoveryTerminalPage(bounded.clone()))
            .expect("bounded terminal page size")
            <= budget
    );

    net.set_max_replication_payload_bytes(budget - 1);
    let oversized_request = StrictRecoveryTerminalReq {
        request_nonce: 123,
        ..bounded_request
    };
    recv_terminal_req(
        &donor,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        oversized_request.clone(),
    )
    .await;
    let resource_limited = terminal_pages(&net)
        .pop()
        .expect("resource-limit terminal response");
    assert_eq!(
        StrictRecoveryStatus::try_from(resource_limited.status).ok(),
        Some(StrictRecoveryStatus::ResourceLimit)
    );
    assert_eq!(resource_limited.context, oversized_request.context);
    assert_eq!(resource_limited.target_cut, oversized_request.target_cut);
    assert_eq!(
        resource_limited.request_nonce,
        oversized_request.request_nonce
    );
    assert_eq!(resource_limited.cursor, oversized_request.expected_cursor);
    assert_eq!(
        resource_limited.next_cursor,
        oversized_request.expected_cursor
    );
    assert!(resource_limited.checkpoint_states.is_empty());
    assert!(!resource_limited.has_more);
}

#[tokio::test]
async fn terminal_ack_releases_only_the_authenticated_correlated_page() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    let current_cut = donor.terminal_journal.lock().await.terminal_cut();
    let request = StrictRecoveryTerminalReq {
        context: Some(StrictRecoveryContext {
            requester_node: REQUESTER as u32,
            requester_boot_epoch: REQUESTER_EPOCH,
            attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 61)),
            expected_donor_boot_epoch: DONOR_EPOCH,
            target: Some(StrictRecoveryTarget {
                repository_version: 0,
                history_freshness: 0,
                terminal_set_digest: Bytes::copy_from_slice(current_cut.terminal_set_digest()),
            }),
        }),
        target_cut: Some(cut_to_wire(current_cut)),
        transfer_id: 0,
        request_nonce: 101,
        expected_cursor: 0,
    };
    recv_terminal_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request.clone()).await;
    let page = terminal_pages(&net).pop().expect("terminal page");
    let exact = StrictRecoveryTerminalAck {
        context: request.context.clone(),
        target_cut: page.target_cut.clone(),
        transfer_id: page.transfer_id,
        request_nonce: page.request_nonce,
        acknowledged_cursor: page.next_cursor,
        final_ack: !page.has_more,
    };

    recv_terminal_ack(&donor, REQUESTER, REQUESTER_EPOCH, false, exact.clone()).await;

    let mut wrong_attempt = exact.clone();
    wrong_attempt.context.as_mut().expect("context").attempt_id =
        attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 62));
    recv_terminal_ack(&donor, REQUESTER, REQUESTER_EPOCH, true, wrong_attempt).await;

    let mut wrong_incarnation = exact.clone();
    wrong_incarnation
        .context
        .as_mut()
        .expect("context")
        .expected_donor_boot_epoch += 1;
    recv_terminal_ack(&donor, REQUESTER, REQUESTER_EPOCH, true, wrong_incarnation).await;

    let mut stale_nonce = exact.clone();
    stale_nonce.request_nonce = stale_nonce.request_nonce.wrapping_add(1);
    recv_terminal_ack(&donor, REQUESTER, REQUESTER_EPOCH, true, stale_nonce).await;

    let mut wrong_cut = exact.clone();
    wrong_cut
        .target_cut
        .as_mut()
        .expect("target cut")
        .journal_id = Bytes::from_static(&[8; 16]);
    recv_terminal_ack(&donor, REQUESTER, REQUESTER_EPOCH, true, wrong_cut).await;
    assert!(
        net.drain_bulk_acknowledgements().is_empty(),
        "stale or inexact terminal ACKs must not release bulk reservations"
    );

    recv_terminal_ack(&donor, REQUESTER, REQUESTER_EPOCH, true, exact.clone()).await;
    assert_eq!(
        net.drain_bulk_acknowledgements(),
        vec![(
            REQUESTER,
            "channels".to_owned(),
            BulkPageIdentity::recovery_terminal(exact.transfer_id, exact.request_nonce),
        )]
    );
}

#[tokio::test]
async fn requester_incarnation_loss_releases_unacked_donor_sessions() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    let current_cut = donor.terminal_journal.lock().await.terminal_cut();
    let attempt = RecoveryAttemptId::new(REQUESTER_EPOCH, 611);
    let context = Some(StrictRecoveryContext {
        requester_node: REQUESTER as u32,
        requester_boot_epoch: REQUESTER_EPOCH,
        attempt_id: attempt_bytes(attempt),
        expected_donor_boot_epoch: DONOR_EPOCH,
        target: Some(StrictRecoveryTarget {
            repository_version: 0,
            history_freshness: 0,
            terminal_set_digest: Bytes::copy_from_slice(current_cut.terminal_set_digest()),
        }),
    });
    recv_terminal_req(
        &donor,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        StrictRecoveryTerminalReq {
            context: context.clone(),
            target_cut: Some(cut_to_wire(current_cut)),
            transfer_id: 0,
            request_nonce: 401,
            expected_cursor: 0,
        },
    )
    .await;
    let terminal_page = terminal_pages(&net).pop().expect("terminal page");
    recv_snapshot_req(
        &donor,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        StrictRecoverySnapshotReq {
            context,
            target_cut: Some(cut_to_wire(current_cut)),
            transfer_id: 0,
            request_nonce: 402,
            expected_cursor: 0,
        },
    )
    .await;
    let snapshot_page = snapshot_pages(&net).pop().expect("snapshot page");
    assert_eq!(donor_session_counts(&donor), (1, 1));

    donor.on_membership_change(&MembershipEvent::Failed(MemberIncarnation::new(
        REQUESTER,
        REQUESTER_EPOCH,
    )));

    assert_eq!(
        donor_session_counts(&donor),
        (0, 0),
        "definitive requester-incarnation loss must not strand donor sessions"
    );
    let released = net.drain_bulk_acknowledgements();
    assert!(
        released.contains(&(
            REQUESTER,
            "channels".to_owned(),
            BulkPageIdentity::recovery_terminal(
                terminal_page.transfer_id,
                terminal_page.request_nonce,
            ),
        ))
    );
    assert!(
        released.contains(&(
            REQUESTER,
            "channels".to_owned(),
            BulkPageIdentity::recovery_snapshot(
                snapshot_page.transfer_id,
                snapshot_page.request_nonce,
            ),
        ))
    );
}

#[tokio::test]
async fn lost_final_acks_expire_and_no_longer_suppress_generation_zero_audit() {
    let (donor, net) = populated_generation_zero_runtime(DONOR, DONOR_EPOCH).await;
    corroborate_local_generation_zero_image(&donor).await;
    let metadata = donor.repo.history_metadata();
    let current_cut = donor.terminal_journal.lock().await.terminal_cut();
    let attempt = RecoveryAttemptId::new(REQUESTER_EPOCH, 612);
    let context = Some(StrictRecoveryContext {
        requester_node: REQUESTER as u32,
        requester_boot_epoch: REQUESTER_EPOCH,
        attempt_id: attempt_bytes(attempt),
        expected_donor_boot_epoch: DONOR_EPOCH,
        target: Some(StrictRecoveryTarget {
            repository_version: metadata.version,
            history_freshness: metadata.freshness,
            terminal_set_digest: Bytes::copy_from_slice(current_cut.terminal_set_digest()),
        }),
    });
    recv_terminal_req(
        &donor,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        StrictRecoveryTerminalReq {
            context: context.clone(),
            target_cut: Some(cut_to_wire(current_cut)),
            transfer_id: 0,
            request_nonce: 411,
            expected_cursor: 0,
        },
    )
    .await;
    let terminal_page = terminal_pages(&net).pop().expect("terminal page");
    recv_snapshot_req(
        &donor,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        StrictRecoverySnapshotReq {
            context,
            target_cut: Some(cut_to_wire(current_cut)),
            transfer_id: 0,
            request_nonce: 412,
            expected_cursor: 0,
        },
    )
    .await;
    let snapshot_page = snapshot_pages(&net).pop().expect("snapshot page");
    assert_eq!(donor_session_counts(&donor), (1, 1));
    assert!(
        !request_generation_zero_audit(&donor).await,
        "live donor sessions must continue to defer a competing local audit"
    );

    prune_idle_donor_sessions_after_timeout_for_test(&donor);

    assert_eq!(donor_session_counts(&donor), (0, 0));
    let released = net.drain_bulk_acknowledgements();
    assert!(
        released.contains(&(
            REQUESTER,
            "channels".to_owned(),
            BulkPageIdentity::recovery_terminal(
                terminal_page.transfer_id,
                terminal_page.request_nonce,
            ),
        ))
    );
    assert!(
        released.contains(&(
            REQUESTER,
            "channels".to_owned(),
            BulkPageIdentity::recovery_snapshot(
                snapshot_page.transfer_id,
                snapshot_page.request_nonce,
            ),
        ))
    );
    assert!(
        request_generation_zero_audit(&donor).await,
        "expired donor sessions must not permanently block local lineage auditing"
    );
}

#[tokio::test]
async fn terminal_pages_ignore_wrong_attempt_auth_incarnation_and_reordering() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (_, _, effects) = certify_terminal_transfer(&requester);
    execute_effects(&requester, effects).await;
    let request = terminal_request(&net);
    let page = response_page(&request, 0, 1, true);

    recv_terminal_page(&requester, DONOR, DONOR_EPOCH, false, page.clone()).await;
    assert!(net.drain_captures().is_empty());

    let mut wrong_attempt = page.clone();
    wrong_attempt.context.as_mut().expect("context").attempt_id =
        attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 99));
    recv_terminal_page(&requester, DONOR, DONOR_EPOCH, true, wrong_attempt).await;
    assert!(net.drain_captures().is_empty());

    recv_terminal_page(&requester, DONOR, DONOR_EPOCH + 1, true, page.clone()).await;
    assert!(net.drain_captures().is_empty());

    let mut reordered = page.clone();
    reordered.cursor = 1;
    reordered.next_cursor = 2;
    recv_terminal_page(&requester, DONOR, DONOR_EPOCH, true, reordered).await;
    assert!(net.drain_captures().is_empty());

    recv_terminal_page(&requester, DONOR, DONOR_EPOCH, true, page).await;
    let frames = net.drain_captures();
    assert!(frames.iter().any(|frame| matches!(
        frame,
        CapturedFrame::StrictUnicast {
            body: StrictBody::RecoveryTerminalAck(_),
            ..
        }
    )));
    assert!(frames.iter().any(|frame| matches!(
        frame,
        CapturedFrame::StrictUnicast {
            body: StrictBody::RecoveryTerminalReq(request),
            ..
        } if request.expected_cursor == 1
    )));
}

#[tokio::test]
async fn duplicate_prior_terminal_page_is_reacked_without_advancing_twice() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (attempt, _, effects) = certify_terminal_transfer(&requester);
    execute_effects(&requester, effects).await;
    let first_request = terminal_request(&net);
    let first_page = response_page(&first_request, 0, 1, true);
    recv_terminal_page(&requester, DONOR, DONOR_EPOCH, true, first_page.clone()).await;
    assert_eq!(client_terminal_state_count(&requester, attempt), Some(1));
    let next_request = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::RecoveryTerminalReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("continuation request");

    recv_terminal_page(&requester, DONOR, DONOR_EPOCH, true, first_page).await;
    assert_eq!(
        client_terminal_state_count(&requester, attempt),
        Some(1),
        "the duplicate page must not append its terminal state twice"
    );
    let duplicate_frames = net.drain_captures();
    assert_eq!(
        duplicate_frames
            .iter()
            .filter(|frame| matches!(
                frame,
                CapturedFrame::StrictUnicast {
                    body: StrictBody::RecoveryTerminalAck(_),
                    ..
                }
            ))
            .count(),
        1,
        "a lost ACK must be regenerated for the exact prior page"
    );
    assert_eq!(next_request.expected_cursor, 1);
}

#[tokio::test]
async fn lost_middle_terminal_checkpoint_page_replays_exact_identity_and_converges() {
    let donor_repo = CountingStrictRepo::new_current();
    let (donor_rt, donor_net) = runtime_with_repo_and_config(
        DONOR,
        DONOR_EPOCH,
        donor_repo.clone(),
        ReplicationConfig::default().with_strict_max_catchup_ops(1),
    );
    donor_rt
        .with_terminal_journal_mutation(|journal| {
            for sequence in 1..=5 {
                journal
                    .upsert_commit_decision_bytes(
                        make_op_id(DONOR, DONOR_EPOCH, sequence),
                        sequence,
                        sequence,
                        Bytes::from(vec![sequence as u8; 1_024]),
                    )
                    .expect("seed multipage terminal checkpoint");
            }
        })
        .await;
    let donor_cut = donor_rt.terminal_journal.lock().await.terminal_cut();
    let metadata = donor_repo.history_metadata();
    let target = LogicalTarget::new(
        metadata.version,
        metadata.freshness,
        *donor_cut.terminal_set_digest(),
    );
    let reducer_cut = ReducerCut::new(
        *donor_cut.journal_id(),
        donor_cut.generation(),
        *donor_cut.chain_digest(),
        *donor_cut.terminal_set_digest(),
    );

    let (requester, requester_net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let requester_state = tempfile::TempDir::new().expect("requester recovery state");
    requester_net.set_strict_protocol_state_dir(Some(requester_state.path().to_path_buf()));
    let (_attempt, _, effects) = certify_terminal_transfer_for(&requester, target, reducer_cut);
    execute_effects(&requester, effects).await;
    let first_request = terminal_request(&requester_net);

    recv_terminal_req(&donor_rt, REQUESTER, REQUESTER_EPOCH, true, first_request).await;
    let first_page = terminal_pages(&donor_net)
        .into_iter()
        .next()
        .expect("first terminal checkpoint page");
    assert!(
        first_page.has_more,
        "fixture must span at least three pages"
    );
    recv_terminal_page(&requester, DONOR, DONOR_EPOCH, true, first_page).await;
    let middle_request = terminal_request(&requester_net);

    recv_terminal_req_runtime(
        &donor_rt,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        middle_request.clone(),
    )
    .await;
    let lost_middle_page = terminal_pages(&donor_net)
        .into_iter()
        .next()
        .expect("middle terminal checkpoint page to drop");
    assert!(
        lost_middle_page.has_more,
        "fixture must retain a final page after the dropped middle page"
    );

    recv_terminal_req_runtime(&donor_rt, REQUESTER, REQUESTER_EPOCH, true, middle_request).await;
    let replayed_middle_page = terminal_pages(&donor_net)
        .into_iter()
        .next()
        .expect("replayed middle terminal checkpoint page");
    assert_eq!(replayed_middle_page, lost_middle_page);
    recv_terminal_page(&requester, DONOR, DONOR_EPOCH, true, replayed_middle_page).await;

    let mut terminal_complete = false;
    for _ in 0..16 {
        let request = terminal_request(&requester_net);
        recv_terminal_req_runtime(&donor_rt, REQUESTER, REQUESTER_EPOCH, true, request).await;
        let page = terminal_pages(&donor_net)
            .into_iter()
            .next()
            .expect("remaining terminal checkpoint page");
        let complete = !page.has_more;
        recv_terminal_page(&requester, DONOR, DONOR_EPOCH, true, page).await;
        if complete {
            terminal_complete = true;
            break;
        }
    }
    assert!(
        terminal_complete,
        "bounded terminal transfer did not complete"
    );

    execute_effects(&requester, requester.take_recovery_effects()).await;
    let first_snapshot_request = snapshot_request(&requester_net);
    recv_snapshot_req(
        &donor_rt,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        first_snapshot_request,
    )
    .await;
    let snapshot_page = snapshot_pages(&donor_net)
        .into_iter()
        .next()
        .expect("repository snapshot page");
    let mut snapshot_complete = !snapshot_page.has_more;
    recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, snapshot_page).await;
    for _ in 0..16 {
        if snapshot_complete {
            break;
        }
        let request = snapshot_request(&requester_net);
        recv_snapshot_req_runtime(&donor_rt, REQUESTER, REQUESTER_EPOCH, true, request).await;
        let page = snapshot_pages(&donor_net)
            .into_iter()
            .next()
            .expect("remaining repository snapshot page");
        snapshot_complete = !page.has_more;
        recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, page).await;
    }
    assert!(
        snapshot_complete,
        "bounded snapshot transfer did not complete"
    );
    for _ in 0..3 {
        let effects = requester.take_recovery_effects();
        if effects.is_empty() {
            break;
        }
        execute_effects(&requester, effects).await;
    }

    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::Healthy
    );
    assert_eq!(requester.repo.history_metadata(), metadata);
    assert_eq!(requester.repo.log(), donor_repo.log());
    assert_eq!(
        requester.terminal_journal.lock().await.terminal_cut(),
        donor_cut
    );
}

#[tokio::test]
async fn stale_target_moved_status_does_not_reset_the_correlated_transfer() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (_, _, effects) = certify_terminal_transfer(&requester);
    execute_effects(&requester, effects).await;
    let request = terminal_request(&net);
    let mut stale = response_page(&request, 0, 0, false);
    stale.status = StrictRecoveryStatus::TargetMoved.into();
    stale.request_nonce = request.request_nonce.wrapping_add(1);

    recv_terminal_page(&requester, DONOR, DONOR_EPOCH, true, stale).await;
    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::FetchingTerminalCheckpoint
    );
    assert!(requester.take_recovery_effects().is_empty());
}

#[tokio::test]
async fn resource_and_retryable_statuses_retain_donor_and_wire_identity() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (_, donor, effects) = certify_terminal_transfer(&requester);
    execute_effects(&requester, effects).await;
    let request = terminal_request(&net);

    for status in [
        StrictRecoveryStatus::ResourceLimit,
        StrictRecoveryStatus::RetryableFailure,
    ] {
        let mut page = response_page(&request, 0, 0, false);
        page.status = status.into();
        page.checkpoint_states.clear();
        recv_terminal_page(&requester, DONOR, DONOR_EPOCH, true, page.clone()).await;
        recv_terminal_page(&requester, DONOR, DONOR_EPOCH, true, page).await;
        assert_eq!(
            requester.recovery_coordinator.lock().phase(),
            RecoveryPhase::FetchingTerminalCheckpoint
        );
        assert_eq!(requester.recovery_coordinator.lock().donor(), Some(&donor));
        let effects = requester.take_recovery_effects();
        assert!(
            effects
                .iter()
                .any(|effect| matches!(effect, RecoveryEffect::Retry { .. }))
        );
        execute_effects(&requester, effects).await;
        assert!(
            net.drain_captures().is_empty(),
            "a retryable status must arm a delayed retry instead of creating an RTT-speed request loop"
        );
        execute_due_transfer_retries(
            &requester,
            Instant::now() + super::recovery_v8_runtime::RECOVERY_RETRY_DELAY,
        )
        .await;
        let mut retried_requests = net
            .drain_captures()
            .into_iter()
            .filter_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    dst: DONOR,
                    body: StrictBody::RecoveryTerminalReq(request),
                    ..
                } => Some(request),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            retried_requests.len(),
            1,
            "duplicate retry statuses must coalesce into one delayed send"
        );
        let retried = retried_requests.pop().expect("single delayed retry");
        assert_eq!(retried.transfer_id, request.transfer_id);
        assert_eq!(retried.request_nonce, request.request_nonce);
        assert_eq!(retried.expected_cursor, request.expected_cursor);
        assert_eq!(retried.target_cut, request.target_cut);
        assert_eq!(retried.context, request.context);
    }
}

#[tokio::test]
async fn full_donor_window_coalesces_retries_within_the_sixty_one_send_budget() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (attempt, donor, effects) = certify_terminal_transfer(&requester);
    execute_effects(&requester, effects).await;
    let initial = terminal_request(&net);
    let initial_context = initial.context.clone();
    let initial_cut = initial.target_cut.clone();
    let initial_transfer_id = initial.transfer_id;
    let initial_nonce = initial.request_nonce;
    let initial_cursor = initial.expected_cursor;

    let window_start = Instant::now();
    let retry_delay = super::recovery_v8_runtime::RECOVERY_RETRY_DELAY;
    let retry_slots = Duration::from_secs(30).as_millis() / retry_delay.as_millis();
    assert_eq!(retry_slots, 60);

    let mut donor_requests = 1_usize;
    for slot in 0..retry_slots {
        // Any number of retryable responses in one pacing slot must retain a
        // single pending retry for the same immutable wire identity.
        for _ in 0..3 {
            requester.transition_recovery(RecoveryEvent::DonorFailed {
                attempt,
                donor: donor.clone(),
                failure: DonorFailure::RetryableFailure,
                now_ms: slot as u64 * 500,
            });
        }
        let slot_start = window_start + retry_delay * slot as u32;
        execute_effects_with_retry_clock_for_test(
            &requester,
            requester.take_recovery_effects(),
            slot_start,
        )
        .await;

        execute_due_transfer_retries(
            &requester,
            slot_start + retry_delay - Duration::from_nanos(1),
        )
        .await;
        assert!(
            net.drain_captures().is_empty(),
            "retry slot {slot} sent before its 500ms not-before"
        );

        let due = slot_start + retry_delay;
        execute_due_transfer_retries(&requester, due).await;
        execute_due_transfer_retries(&requester, due).await;
        let requests = net
            .drain_captures()
            .into_iter()
            .filter_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    dst: DONOR,
                    body: StrictBody::RecoveryTerminalReq(request),
                    ..
                } => Some(request),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 1, "retry slot {slot}");
        donor_requests += requests.len();
        let retried = &requests[0];
        assert_eq!(retried.context, initial_context);
        assert_eq!(retried.target_cut, initial_cut);
        assert_eq!(retried.transfer_id, initial_transfer_id);
        assert_eq!(retried.request_nonce, initial_nonce);
        assert_eq!(retried.expected_cursor, initial_cursor);
    }

    assert_eq!(
        donor_requests, 61,
        "one initial send plus at most sixty paced retries in a 30-second donor window"
    );
    assert_eq!(requester.recovery_coordinator.lock().donor(), Some(&donor));
}

#[tokio::test]
async fn correlated_terminal_incarnation_mismatch_switches_to_the_second_witness() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (attempt, first_donor, effects) = certify_terminal_transfer(&requester);
    execute_effects(&requester, effects).await;
    let request = terminal_request(&net);
    let mut mismatch = response_page(&request, 0, 0, false);
    mismatch.status = StrictRecoveryStatus::IncarnationMismatch.into();
    mismatch.checkpoint_states.clear();

    recv_terminal_page(&requester, DONOR, DONOR_EPOCH, true, mismatch).await;

    let second_donor = ParticipantIncarnation::new(u64::from(SECOND_WITNESS), SECOND_WITNESS_EPOCH);
    let expected_cut = {
        let coordinator = requester.recovery_coordinator.lock();
        assert_eq!(coordinator.attempt(), Some(attempt));
        assert_eq!(
            coordinator.phase(),
            RecoveryPhase::FetchingTerminalCheckpoint
        );
        assert_eq!(coordinator.donor(), Some(&second_donor));
        assert_eq!(
            coordinator.failure_history().last(),
            Some(&super::recovery_reducer::RecoveryFailure::new(
                first_donor,
                DonorFailure::IncarnationLost,
            ))
        );
        coordinator
            .representation_cut()
            .expect("second witness representation")
            .clone()
    };
    let effects = requester.take_recovery_effects();
    assert!(effects.iter().any(|effect| matches!(
        effect,
        RecoveryEffect::SendTransfer {
            attempt: queued_attempt,
            donor,
            terminal_cut,
            kind: super::recovery_reducer::TransferKind::TerminalCheckpoint,
        } if *queued_attempt == attempt && donor == &second_donor && terminal_cut == &expected_cut
    )));
}

#[tokio::test]
async fn snapshot_request_rejects_unauthenticated_and_wrong_incarnation_contexts() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    let cut = donor.terminal_journal.lock().await.terminal_cut();
    let base = StrictRecoverySnapshotReq {
        context: Some(StrictRecoveryContext {
            requester_node: REQUESTER as u32,
            requester_boot_epoch: REQUESTER_EPOCH,
            attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 31)),
            expected_donor_boot_epoch: DONOR_EPOCH,
            target: Some(StrictRecoveryTarget {
                repository_version: 0,
                history_freshness: 0,
                terminal_set_digest: Bytes::copy_from_slice(cut.terminal_set_digest()),
            }),
        }),
        target_cut: Some(cut_to_wire(cut)),
        transfer_id: 0,
        request_nonce: 81,
        expected_cursor: 0,
    };

    recv_snapshot_req(&donor, REQUESTER, REQUESTER_EPOCH, false, base.clone()).await;
    assert!(net.drain_captures().is_empty());

    let mut wrong_attempt = base.clone();
    wrong_attempt.context.as_mut().expect("context").attempt_id = Bytes::from_static(&[1; 15]);
    recv_snapshot_req(&donor, REQUESTER, REQUESTER_EPOCH, true, wrong_attempt).await;
    assert!(net.drain_captures().is_empty());

    let mut wrong_incarnation = base.clone();
    wrong_incarnation
        .context
        .as_mut()
        .expect("context")
        .expected_donor_boot_epoch += 1;
    recv_snapshot_req(&donor, REQUESTER, REQUESTER_EPOCH, true, wrong_incarnation).await;
    let pages = snapshot_pages(&net);
    assert_eq!(pages.len(), 1);
    assert_eq!(
        StrictRecoveryStatus::try_from(pages[0].status).ok(),
        Some(StrictRecoveryStatus::IncarnationMismatch)
    );
}

#[tokio::test]
async fn snapshot_ack_releases_only_the_live_exact_server_page() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    let current_cut = donor.terminal_journal.lock().await.terminal_cut();
    let request = StrictRecoverySnapshotReq {
        context: Some(StrictRecoveryContext {
            requester_node: REQUESTER as u32,
            requester_boot_epoch: REQUESTER_EPOCH,
            attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 71)),
            expected_donor_boot_epoch: DONOR_EPOCH,
            target: Some(StrictRecoveryTarget {
                repository_version: 0,
                history_freshness: 0,
                terminal_set_digest: Bytes::copy_from_slice(current_cut.terminal_set_digest()),
            }),
        }),
        target_cut: Some(cut_to_wire(current_cut)),
        transfer_id: 0,
        request_nonce: 111,
        expected_cursor: 0,
    };
    recv_snapshot_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request.clone()).await;
    let page = snapshot_pages(&net).pop().expect("snapshot page");
    let exact = StrictRecoverySnapshotAck {
        context: request.context.clone(),
        target_cut: page.target_cut.clone(),
        transfer_id: page.transfer_id,
        request_nonce: page.request_nonce,
        acknowledged_cursor: page.next_cursor,
        final_ack: !page.has_more,
    };

    recv_snapshot_ack(&donor, REQUESTER, REQUESTER_EPOCH, false, exact.clone()).await;

    let mut wrong_attempt = exact.clone();
    wrong_attempt.context.as_mut().expect("context").attempt_id =
        attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 72));
    recv_snapshot_ack(&donor, REQUESTER, REQUESTER_EPOCH, true, wrong_attempt).await;

    let mut wrong_incarnation = exact.clone();
    wrong_incarnation
        .context
        .as_mut()
        .expect("context")
        .expected_donor_boot_epoch += 1;
    recv_snapshot_ack(&donor, REQUESTER, REQUESTER_EPOCH, true, wrong_incarnation).await;

    let mut stale_nonce = exact.clone();
    stale_nonce.request_nonce = stale_nonce.request_nonce.wrapping_add(1);
    recv_snapshot_ack(&donor, REQUESTER, REQUESTER_EPOCH, true, stale_nonce).await;

    let mut wrong_cut = exact.clone();
    wrong_cut
        .target_cut
        .as_mut()
        .expect("target cut")
        .journal_id = Bytes::from_static(&[8; 16]);
    recv_snapshot_ack(&donor, REQUESTER, REQUESTER_EPOCH, true, wrong_cut).await;
    assert!(
        net.drain_bulk_acknowledgements().is_empty(),
        "stale or inexact snapshot ACKs must not release bulk reservations"
    );

    recv_snapshot_ack(&donor, REQUESTER, REQUESTER_EPOCH, true, exact.clone()).await;
    assert_eq!(
        net.drain_bulk_acknowledgements(),
        vec![(
            REQUESTER,
            "channels".to_owned(),
            BulkPageIdentity::recovery_snapshot(exact.transfer_id, exact.request_nonce),
        )]
    );
}

#[tokio::test]
async fn snapshot_pages_ignore_wrong_auth_attempt_incarnation_and_reordering() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (_, _, request) = begin_snapshot_transfer(&requester, &net).await;
    let digest = snapshot_digest(b"abcd");
    let page = snapshot_response_page(&request, 0, b"ab", 4, digest);

    recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, false, page.clone()).await;
    assert!(net.drain_captures().is_empty());

    let mut wrong_attempt = page.clone();
    wrong_attempt.context.as_mut().expect("context").attempt_id =
        attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 99));
    recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, wrong_attempt).await;
    assert!(net.drain_captures().is_empty());

    recv_snapshot_page(&requester, DONOR, DONOR_EPOCH + 1, true, page.clone()).await;
    assert!(net.drain_captures().is_empty());

    let mut reordered = page.clone();
    reordered.cursor = 2;
    reordered.next_cursor = 4;
    reordered.snapshot_bytes = Bytes::from_static(b"cd");
    recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, reordered).await;
    assert!(net.drain_captures().is_empty());

    recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, page).await;
    let frames = net.drain_captures();
    assert!(frames.iter().any(|frame| matches!(
        frame,
        CapturedFrame::StrictUnicast {
            body: StrictBody::RecoverySnapshotAck(_),
            ..
        }
    )));
    assert!(frames.iter().any(|frame| matches!(
        frame,
        CapturedFrame::StrictUnicast {
            body: StrictBody::RecoverySnapshotReq(request),
            ..
        } if request.expected_cursor == 2
    )));
}

#[tokio::test]
async fn correlated_snapshot_incarnation_mismatch_restarts_terminal_transfer_with_second_witness() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (attempt, first_donor, request) = begin_snapshot_transfer(&requester, &net).await;
    let mut mismatch = snapshot_response_page(&request, 0, b"", 0, Bytes::new());
    mismatch.status = StrictRecoveryStatus::IncarnationMismatch.into();
    mismatch.transfer_id = 0;

    recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, mismatch).await;

    let second_donor = ParticipantIncarnation::new(u64::from(SECOND_WITNESS), SECOND_WITNESS_EPOCH);
    let expected_cut = {
        let coordinator = requester.recovery_coordinator.lock();
        assert_eq!(coordinator.attempt(), Some(attempt));
        assert_eq!(
            coordinator.phase(),
            RecoveryPhase::FetchingTerminalCheckpoint,
            "a new donor must restart at terminal cursor zero before serving a snapshot"
        );
        assert_eq!(coordinator.donor(), Some(&second_donor));
        assert_eq!(
            coordinator.failure_history().last(),
            Some(&super::recovery_reducer::RecoveryFailure::new(
                first_donor,
                DonorFailure::IncarnationLost,
            ))
        );
        coordinator
            .representation_cut()
            .expect("second witness representation")
            .clone()
    };
    let effects = requester.take_recovery_effects();
    assert!(effects.iter().any(|effect| matches!(
        effect,
        RecoveryEffect::SendTransfer {
            attempt: queued_attempt,
            donor,
            terminal_cut,
            kind: super::recovery_reducer::TransferKind::TerminalCheckpoint,
        } if *queued_attempt == attempt && donor == &second_donor && terminal_cut == &expected_cut
    )));
}

#[tokio::test]
async fn empty_non_final_snapshot_page_does_not_make_progress_or_resend() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (_, _, request) = begin_snapshot_transfer(&requester, &net).await;
    let deadline = requester.recovery_coordinator.lock().progress_deadline_ms();
    let page = snapshot_response_page(&request, 0, b"", 4, snapshot_digest(b"abcd"));

    recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, page).await;

    assert_eq!(
        requester.recovery_coordinator.lock().progress_deadline_ms(),
        deadline,
        "an empty non-final page must not refresh the progress deadline"
    );
    assert!(
        requester.take_recovery_effects().is_empty(),
        "an empty non-final page must not reach the reducer"
    );
    assert!(
        net.drain_captures().is_empty(),
        "an empty non-final page must not be acknowledged or trigger an immediate resend"
    );
}

#[tokio::test]
async fn duplicate_snapshot_page_replays_ack_without_advancing_the_cursor() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (_, _, request) = begin_snapshot_transfer(&requester, &net).await;
    let page = snapshot_response_page(&request, 0, b"ab", 4, snapshot_digest(b"abcd"));

    recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, page.clone()).await;
    let continuation = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::RecoverySnapshotReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("snapshot continuation request");
    assert_eq!(continuation.expected_cursor, 2);

    recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, page).await;
    let duplicate_frames = net.drain_captures();
    assert_eq!(
        duplicate_frames
            .iter()
            .filter(|frame| matches!(
                frame,
                CapturedFrame::StrictUnicast {
                    body: StrictBody::RecoverySnapshotAck(_),
                    ..
                }
            ))
            .count(),
        1,
        "the exact duplicate must replay its ACK"
    );
    assert!(!duplicate_frames.iter().any(|frame| matches!(
        frame,
        CapturedFrame::StrictUnicast {
            body: StrictBody::RecoverySnapshotReq(_),
            ..
        }
    )));
}

#[tokio::test]
async fn lost_middle_snapshot_page_replays_exact_identity_and_converges() {
    let donor_repo = CountingStrictRepo::new_current();
    *donor_repo.state.lock() = (
        4_000,
        (1..=4_000)
            .map(|version| (version, version, None))
            .collect(),
    );
    let (donor_rt, donor_net) = runtime_with_repo_and_config(
        DONOR,
        DONOR_EPOCH,
        donor_repo.clone(),
        ReplicationConfig::default().with_strict_max_catchup_bytes(4_096),
    );
    let (requester, requester_net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let requester_state = tempfile::TempDir::new().expect("requester recovery state");
    requester_net.set_strict_protocol_state_dir(Some(requester_state.path().to_path_buf()));
    let donor_cut = donor_rt.terminal_journal.lock().await.terminal_cut();
    let target = LogicalTarget::new(
        donor_repo.current_version(),
        donor_repo.history_metadata().freshness,
        *donor_cut.terminal_set_digest(),
    );
    let reducer_cut = ReducerCut::new(
        *donor_cut.journal_id(),
        donor_cut.generation(),
        *donor_cut.chain_digest(),
        *donor_cut.terminal_set_digest(),
    );
    let (attempt, donor, effects) = certify_terminal_transfer_for(&requester, target, reducer_cut);
    execute_effects(&requester, effects).await;
    let _ = terminal_request(&requester_net);
    requester.transition_recovery(RecoveryEvent::TransferProgress {
        attempt,
        donor: donor.clone(),
        kind: super::recovery_reducer::TransferKind::TerminalCheckpoint,
        authenticated: true,
        complete: true,
        now_ms: 4,
    });
    execute_effects(&requester, requester.take_recovery_effects()).await;
    let first_request = snapshot_request(&requester_net);

    recv_snapshot_req(&donor_rt, REQUESTER, REQUESTER_EPOCH, true, first_request).await;
    let first_page = snapshot_pages(&donor_net)
        .into_iter()
        .next()
        .expect("first snapshot page");
    assert!(
        first_page.has_more,
        "fixture must span at least three pages"
    );
    recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, first_page).await;
    let middle_request = snapshot_request(&requester_net);

    recv_snapshot_req_runtime(
        &donor_rt,
        REQUESTER,
        REQUESTER_EPOCH,
        true,
        middle_request.clone(),
    )
    .await;
    let lost_middle_page = snapshot_pages(&donor_net)
        .into_iter()
        .next()
        .expect("middle snapshot page to drop");
    assert!(
        lost_middle_page.has_more,
        "fixture must retain a final page after the dropped middle page"
    );

    // The reliable lane replays the retained request after losing its page.
    // The donor must return the immutable page identity and bytes, allowing
    // the requester to continue without moving its cursor or transfer.
    recv_snapshot_req_runtime(&donor_rt, REQUESTER, REQUESTER_EPOCH, true, middle_request).await;
    let replayed_middle_page = snapshot_pages(&donor_net)
        .into_iter()
        .next()
        .expect("replayed middle snapshot page");
    assert_eq!(replayed_middle_page, lost_middle_page);
    recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, replayed_middle_page).await;

    let mut transfer_complete = false;
    for _ in 0..64 {
        let request = snapshot_request(&requester_net);
        recv_snapshot_req_runtime(&donor_rt, REQUESTER, REQUESTER_EPOCH, true, request).await;
        let page = snapshot_pages(&donor_net)
            .into_iter()
            .next()
            .expect("remaining snapshot page");
        let complete = !page.has_more;
        recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, page).await;
        if complete {
            transfer_complete = true;
            break;
        }
    }
    assert!(
        transfer_complete,
        "bounded multipage transfer did not complete"
    );

    for _ in 0..3 {
        let effects = requester.take_recovery_effects();
        if effects.is_empty() {
            break;
        }
        execute_effects(&requester, effects).await;
    }
    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::Healthy
    );
    assert_eq!(
        requester.repo.history_metadata(),
        donor_repo.history_metadata()
    );
    assert_eq!(requester.repo.log(), donor_repo.log());
    assert_eq!(
        requester.terminal_journal.lock().await.terminal_cut(),
        donor_cut
    );
}

#[tokio::test]
async fn snapshot_total_and_digest_mismatches_cannot_complete_the_transfer() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (_attempt, _, request) = begin_snapshot_transfer(&requester, &net).await;
    let digest = snapshot_digest(b"abcd");
    let first = snapshot_response_page(&request, 0, b"ab", 4, digest.clone());
    recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, first).await;
    let continuation = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::RecoverySnapshotReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("snapshot continuation request");

    let wrong_total = snapshot_response_page(&continuation, 2, b"cd", 5, digest);
    recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, wrong_total).await;
    assert!(net.drain_captures().is_empty());
    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::FetchingRepositorySnapshot
    );

    let (second_requester, second_net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (_, _, second_request) = begin_snapshot_transfer(&second_requester, &second_net).await;
    let wrong_digest =
        snapshot_response_page(&second_request, 0, b"ab", 2, Bytes::from_static(&[9; 32]));
    recv_snapshot_page(&second_requester, DONOR, DONOR_EPOCH, true, wrong_digest).await;
    assert_eq!(
        second_requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::FetchingRepositorySnapshot,
        "a final page whose content digest is wrong must not complete recovery"
    );
    assert!(second_net.drain_captures().iter().all(|frame| !matches!(
        frame,
        CapturedFrame::StrictUnicast {
            body: StrictBody::RecoverySnapshotAck(ack),
            ..
        } if ack.final_ack
    )));
}

#[tokio::test]
async fn final_snapshot_page_revalidates_donor_after_staging_and_persistence() {
    let temp = tempfile::TempDir::new().unwrap();
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));
    let (attempt, donor, request) = begin_snapshot_transfer(&requester, &net).await;
    let image = b"complete staged repository image";
    let page = snapshot_response_page(
        &request,
        0,
        image,
        image.len() as u64,
        snapshot_digest(image),
    );
    let mut topic_hasher = std::collections::hash_map::DefaultHasher::new();
    "channels".hash(&mut topic_hasher);
    let staging_path = temp.path().join(format!(
        "strict-recovery-{:016x}-{:016x}-{:016x}.stage",
        topic_hasher.finish(),
        attempt.hi(),
        attempt.lo()
    ));

    let (receiving, replacement) = {
        let _journal_guard = requester.terminal_journal.lock().await;
        let receiver_rt = Arc::clone(&requester);
        let receiving = tokio::spawn(async move {
            recv_snapshot_page(&receiver_rt, DONOR, DONOR_EPOCH, true, page).await;
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !staging_path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("final snapshot page must reach the post-staging persistence window");

        let deadline = requester
            .recovery_coordinator
            .lock()
            .progress_deadline_ms()
            .expect("snapshot progress deadline");
        requester.transition_recovery(RecoveryEvent::Deadline {
            attempt,
            now_ms: deadline,
        });
        let failover_effects = requester.take_recovery_effects();
        let replacement =
            ParticipantIncarnation::new(u64::from(SECOND_WITNESS), SECOND_WITNESS_EPOCH);
        assert_eq!(
            requester.recovery_coordinator.lock().phase(),
            RecoveryPhase::FetchingTerminalCheckpoint
        );
        assert_eq!(
            requester.recovery_coordinator.lock().donor(),
            Some(&replacement)
        );
        assert!(failover_effects.iter().any(|effect| matches!(
            effect,
            RecoveryEffect::SendTransfer {
                donor: selected,
                kind: super::recovery_reducer::TransferKind::TerminalCheckpoint,
                ..
            } if selected == &replacement
        )));
        assert_ne!(replacement, donor);
        (receiving, replacement)
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), receiving)
        .await
        .expect("final snapshot receiver must resume")
        .expect("final snapshot receiver task");

    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::FetchingTerminalCheckpoint,
        "stale completion must not advance the replacement donor's phase"
    );
    assert_eq!(
        requester.recovery_coordinator.lock().donor(),
        Some(&replacement)
    );
    assert!(
        requester
            .terminal_journal
            .lock()
            .await
            .load_recovery_artifact_intent()
            .unwrap()
            .is_none(),
        "a stale final page must not leave its durable artifact intent attached"
    );
    assert!(
        net.drain_captures().iter().all(|frame| !matches!(
            frame,
            CapturedFrame::StrictUnicast {
                dst: DONOR,
                body: StrictBody::RecoverySnapshotAck(ack),
                ..
            } if ack.final_ack
        )),
        "the replaced donor must not receive a final ACK after the async persistence window"
    );
    assert!(
        !staging_path.exists(),
        "the stale donor's staging artifact must be removed"
    );
}

#[tokio::test]
async fn queued_send_transfer_is_ignored_after_phase_and_donor_change() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (attempt, original_donor, queued_effects) = certify_terminal_transfer(&requester);
    let deadline = requester
        .recovery_coordinator
        .lock()
        .progress_deadline_ms()
        .expect("terminal progress deadline");
    requester.transition_recovery(RecoveryEvent::Deadline {
        attempt,
        now_ms: deadline,
    });
    let replacement_effects = requester.take_recovery_effects();
    let replacement = ParticipantIncarnation::new(u64::from(SECOND_WITNESS), SECOND_WITNESS_EPOCH);
    assert_eq!(
        requester.recovery_coordinator.lock().donor(),
        Some(&replacement)
    );
    assert!(replacement_effects.iter().any(|effect| matches!(
        effect,
        RecoveryEffect::SendTransfer { donor, .. } if donor == &replacement
    )));

    execute_effects(&requester, queued_effects).await;

    assert!(
        net.drain_captures().iter().all(|frame| !matches!(
            frame,
            CapturedFrame::StrictUnicast {
                dst,
                body: StrictBody::RecoveryTerminalReq(_),
                ..
            } if *dst == NodeIdentifier::try_from(original_donor.node_id()).unwrap()
        )),
        "an effect queued for the former donor must be discarded before creating or sending its transfer"
    );
}

#[tokio::test]
async fn fenced_selected_donor_remains_retryable_until_deadline_switches_witness() {
    let (donor, donor_net) = runtime(DONOR, DONOR_EPOCH);
    let donor_cut = rotate_to_foreign_empty_lineage(&donor).await;
    let (metadata, _) = donor.recovery_advertised_head().await;
    let certified_target = LogicalTarget::new(
        metadata.version,
        metadata.freshness,
        *donor_cut.terminal_set_digest(),
    );
    let certified_cut = ReducerCut::new(
        *donor_cut.journal_id(),
        donor_cut.generation(),
        *donor_cut.chain_digest(),
        *donor_cut.terminal_set_digest(),
    );
    let (requester, requester_net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (attempt, selected_donor, effects) =
        certify_terminal_transfer_for(&requester, certified_target, certified_cut);
    execute_effects(&requester, effects).await;
    let request = terminal_request(&requester_net);

    donor.transition_recovery(RecoveryEvent::Trigger {
        trigger: RecoveryTrigger::TerminalFence,
        attempt: RecoveryAttemptId::new(DONOR_EPOCH, 99),
        total_known_participants: 3,
        now_ms: 1,
    });
    donor.take_recovery_effects();
    assert_eq!(
        donor.recovery_coordinator.lock().phase(),
        RecoveryPhase::Certifying,
        "the selected donor fixture must be fenced from transfer donation"
    );

    recv_terminal_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request).await;
    let page = terminal_pages(&donor_net)
        .into_iter()
        .next()
        .expect("fenced donor status response");
    assert!(
        donor_net
            .strict_send_observations()
            .iter()
            .any(|observation| {
                observation.lane == StrictSendLane::RedundantControl
                    && matches!(
                        &observation.body,
                        StrictBody::RecoveryTerminalPage(page)
                            if page.status == StrictRecoveryStatus::RetryableFailure as i32
                    )
            })
    );
    assert_eq!(
        StrictRecoveryStatus::try_from(page.status).unwrap(),
        StrictRecoveryStatus::RetryableFailure,
        "temporary donor fencing must not invalidate the logical certificate"
    );

    recv_terminal_page(&requester, DONOR, DONOR_EPOCH, true, page).await;
    let deadline = {
        let coordinator = requester.recovery_coordinator.lock();
        assert_eq!(
            coordinator.phase(),
            RecoveryPhase::FetchingTerminalCheckpoint
        );
        assert_eq!(coordinator.donor(), Some(&selected_donor));
        coordinator
            .progress_deadline_ms()
            .expect("terminal progress deadline")
    };
    requester.take_recovery_effects();

    requester.transition_recovery(RecoveryEvent::Deadline {
        attempt,
        now_ms: deadline,
    });
    let replacement = ParticipantIncarnation::new(u64::from(SECOND_WITNESS), SECOND_WITNESS_EPOCH);
    let effects = requester.take_recovery_effects();
    assert_eq!(
        requester.recovery_coordinator.lock().donor(),
        Some(&replacement)
    );
    assert!(effects.iter().any(|effect| matches!(
        effect,
        RecoveryEffect::SendTransfer {
            donor,
            kind: super::recovery_reducer::TransferKind::TerminalCheckpoint,
            ..
        } if donor == &replacement
    )));

    execute_effects(&requester, effects).await;
    assert!(requester_net.drain_captures().iter().any(|frame| matches!(
        frame,
        CapturedFrame::StrictUnicast {
            dst: SECOND_WITNESS,
            body: StrictBody::RecoveryTerminalReq(_),
            ..
        }
    )));
}

#[tokio::test]
async fn snapshot_resource_and_retryable_statuses_retain_wire_identity() {
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (_, donor, request) = begin_snapshot_transfer(&requester, &net).await;

    for status in [
        StrictRecoveryStatus::ResourceLimit,
        StrictRecoveryStatus::RetryableFailure,
    ] {
        let mut page = snapshot_response_page(&request, 0, b"", 0, Bytes::new());
        page.status = status.into();
        recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, page).await;
        assert_eq!(
            requester.recovery_coordinator.lock().phase(),
            RecoveryPhase::FetchingRepositorySnapshot
        );
        assert_eq!(requester.recovery_coordinator.lock().donor(), Some(&donor));
        let effects = requester.take_recovery_effects();
        assert!(
            effects
                .iter()
                .any(|effect| matches!(effect, RecoveryEffect::Retry { .. }))
        );
        execute_effects(&requester, effects).await;
        assert!(
            net.drain_captures().is_empty(),
            "a retryable snapshot status must not resend in the same executor turn"
        );
        execute_due_transfer_retries(
            &requester,
            Instant::now() + super::recovery_v8_runtime::RECOVERY_RETRY_DELAY,
        )
        .await;
        let retried = snapshot_request(&net);
        assert_eq!(retried.transfer_id, request.transfer_id);
        assert_eq!(retried.request_nonce, request.request_nonce);
        assert_eq!(retried.expected_cursor, request.expected_cursor);
        assert_eq!(retried.target_cut, request.target_cut);
        assert_eq!(retried.context, request.context);
    }
}

#[tokio::test]
async fn initial_snapshot_retryable_status_is_correlated_before_transfer_id_assignment() {
    let (requester, requester_net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (_, donor_incarnation, request) = begin_snapshot_transfer(&requester, &requester_net).await;
    assert_eq!(request.transfer_id, 0, "initial snapshot request identity");

    let (donor, donor_net) = runtime(DONOR, DONOR_EPOCH);
    donor.transition_recovery(RecoveryEvent::Trigger {
        trigger: RecoveryTrigger::TerminalFence,
        attempt: RecoveryAttemptId::new(DONOR_EPOCH, 100),
        total_known_participants: 3,
        now_ms: 1,
    });
    donor.take_recovery_effects();
    recv_snapshot_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request.clone()).await;
    let page = snapshot_pages(&donor_net)
        .into_iter()
        .next()
        .expect("fenced donor snapshot status response");
    assert_eq!(page.transfer_id, 0);
    assert_eq!(
        StrictRecoveryStatus::try_from(page.status).unwrap(),
        StrictRecoveryStatus::RetryableFailure
    );

    recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, page).await;
    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::FetchingRepositorySnapshot
    );
    assert_eq!(
        requester.recovery_coordinator.lock().donor(),
        Some(&donor_incarnation)
    );
    assert!(
        requester
            .take_recovery_effects()
            .iter()
            .any(|effect| matches!(effect, RecoveryEffect::Retry { .. }))
    );
}

#[tokio::test]
async fn terminal_donor_backpressure_reports_retry_and_preserves_request_identity() {
    let (donor, donor_net) = runtime(DONOR, DONOR_EPOCH);
    let terminal_cut = rotate_to_foreign_empty_lineage(&donor).await;
    let target = LogicalTarget::new(0, 0, *terminal_cut.terminal_set_digest());
    let reducer_cut = ReducerCut::new(
        *terminal_cut.journal_id(),
        terminal_cut.generation(),
        *terminal_cut.chain_digest(),
        *terminal_cut.terminal_set_digest(),
    );

    let (requester, requester_net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (attempt, expected_donor, effects) =
        certify_terminal_transfer_for(&requester, target, reducer_cut);
    execute_effects(&requester, effects).await;
    let request = terminal_request(&requester_net);

    donor_net.script_bulk_send_outcomes([MockBulkSendOutcome::Backpressure]);
    recv_terminal_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request.clone()).await;

    let attempted_page = donor_net
        .drain_strict_send_observations()
        .into_iter()
        .find_map(|observation| match observation {
            observation
                if observation.lane == StrictSendLane::Bulk
                    && observation.outcome == StrictSendOutcome::Backpressure =>
            {
                match observation.body {
                    StrictBody::RecoveryTerminalPage(page) => Some(page),
                    _ => None,
                }
            }
            _ => None,
        })
        .expect("backpressured terminal page");
    let status = terminal_pages(&donor_net)
        .pop()
        .expect("requester-visible terminal retry status");
    assert_eq!(
        StrictRecoveryStatus::try_from(status.status).ok(),
        Some(StrictRecoveryStatus::RetryableFailure)
    );
    assert_eq!(status.context, attempted_page.context);
    assert_eq!(status.target_cut, attempted_page.target_cut);
    assert_eq!(status.transfer_id, attempted_page.transfer_id);
    assert_eq!(status.request_nonce, attempted_page.request_nonce);
    assert_eq!(status.cursor, attempted_page.cursor);

    recv_terminal_page(&requester, DONOR, DONOR_EPOCH, true, status).await;
    assert_eq!(
        requester.recovery_coordinator.lock().attempt(),
        Some(attempt)
    );
    assert_eq!(
        requester.recovery_coordinator.lock().donor(),
        Some(&expected_donor)
    );
    let effects = requester.take_recovery_effects();
    assert!(effects.iter().any(
        |effect| matches!(effect, RecoveryEffect::Retry { attempt: retried } if *retried == attempt)
    ));
    execute_effects(&requester, effects).await;
    assert!(
        requester_net.drain_captures().is_empty(),
        "backpressure must arm the fixed-delay retry without sending immediately"
    );
    execute_due_transfer_retries(
        &requester,
        Instant::now() + super::recovery_v8_runtime::RECOVERY_RETRY_DELAY,
    )
    .await;
    assert_eq!(terminal_request(&requester_net), request);
}

#[tokio::test]
async fn snapshot_donor_backpressure_reports_retry_and_preserves_request_identity() {
    let (donor, donor_net) = runtime(DONOR, DONOR_EPOCH);
    let terminal_cut = rotate_to_foreign_empty_lineage(&donor).await;
    let target = LogicalTarget::new(0, 0, *terminal_cut.terminal_set_digest());
    let reducer_cut = ReducerCut::new(
        *terminal_cut.journal_id(),
        terminal_cut.generation(),
        *terminal_cut.chain_digest(),
        *terminal_cut.terminal_set_digest(),
    );

    let (requester, requester_net) = runtime(REQUESTER, REQUESTER_EPOCH);
    let (attempt, expected_donor, effects) =
        certify_terminal_transfer_for(&requester, target, reducer_cut);
    execute_effects(&requester, effects).await;
    let _ = terminal_request(&requester_net);
    requester.transition_recovery(RecoveryEvent::TransferProgress {
        attempt,
        donor: expected_donor.clone(),
        kind: super::recovery_reducer::TransferKind::TerminalCheckpoint,
        authenticated: true,
        complete: true,
        now_ms: 4,
    });
    let effects = requester.take_recovery_effects();
    execute_effects(&requester, effects).await;
    let request = snapshot_request(&requester_net);

    donor_net.script_bulk_send_outcomes([MockBulkSendOutcome::Backpressure]);
    recv_snapshot_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request.clone()).await;

    let attempted_page = donor_net
        .drain_strict_send_observations()
        .into_iter()
        .find_map(|observation| match observation {
            observation
                if observation.lane == StrictSendLane::Bulk
                    && observation.outcome == StrictSendOutcome::Backpressure =>
            {
                match observation.body {
                    StrictBody::RecoverySnapshotPage(page) => Some(page),
                    _ => None,
                }
            }
            _ => None,
        })
        .expect("backpressured snapshot page");
    let status = snapshot_pages(&donor_net)
        .pop()
        .expect("requester-visible snapshot retry status");
    assert_eq!(
        StrictRecoveryStatus::try_from(status.status).ok(),
        Some(StrictRecoveryStatus::RetryableFailure)
    );
    assert_eq!(status.context, attempted_page.context);
    assert_eq!(status.target_cut, attempted_page.target_cut);
    assert_eq!(status.transfer_id, attempted_page.transfer_id);
    assert_eq!(status.request_nonce, attempted_page.request_nonce);
    assert_eq!(status.cursor, attempted_page.cursor);

    recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, status).await;
    assert_eq!(
        requester.recovery_coordinator.lock().attempt(),
        Some(attempt)
    );
    assert_eq!(
        requester.recovery_coordinator.lock().donor(),
        Some(&expected_donor)
    );
    let effects = requester.take_recovery_effects();
    assert!(effects.iter().any(
        |effect| matches!(effect, RecoveryEffect::Retry { attempt: retried } if *retried == attempt)
    ));
    execute_effects(&requester, effects).await;
    assert!(
        requester_net.drain_captures().is_empty(),
        "backpressure must arm the fixed-delay retry without sending immediately"
    );
    execute_due_transfer_retries(
        &requester,
        Instant::now() + super::recovery_v8_runtime::RECOVERY_RETRY_DELAY,
    )
    .await;
    assert_eq!(snapshot_request(&requester_net), request);
}

#[tokio::test]
async fn snapshot_donor_backpressure_preserves_the_immutable_page_identity() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    let cut = donor.terminal_journal.lock().await.terminal_cut();
    let request = StrictRecoverySnapshotReq {
        context: Some(StrictRecoveryContext {
            requester_node: REQUESTER as u32,
            requester_boot_epoch: REQUESTER_EPOCH,
            attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 41)),
            expected_donor_boot_epoch: DONOR_EPOCH,
            target: Some(StrictRecoveryTarget {
                repository_version: 0,
                history_freshness: 0,
                terminal_set_digest: Bytes::copy_from_slice(cut.terminal_set_digest()),
            }),
        }),
        target_cut: Some(cut_to_wire(cut)),
        transfer_id: 0,
        request_nonce: 91,
        expected_cursor: 0,
    };
    net.script_bulk_send_outcomes([MockBulkSendOutcome::Backpressure, MockBulkSendOutcome::Sent]);

    recv_snapshot_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request.clone()).await;
    let retry_status = snapshot_pages(&net)
        .pop()
        .expect("backpressured page retry status");
    assert_eq!(
        StrictRecoveryStatus::try_from(retry_status.status).ok(),
        Some(StrictRecoveryStatus::RetryableFailure)
    );
    let first = net
        .drain_strict_send_observations()
        .into_iter()
        .find(|observation| {
            observation.lane == StrictSendLane::Bulk
                && observation.outcome == StrictSendOutcome::Backpressure
        })
        .expect("backpressured snapshot page");

    recv_snapshot_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request).await;
    let page = snapshot_pages(&net).pop().expect("retried snapshot page");
    let StrictBody::RecoverySnapshotPage(first_page) = first.body else {
        panic!("expected snapshot page")
    };
    assert_eq!(retry_status.transfer_id, first_page.transfer_id);
    assert_eq!(retry_status.request_nonce, first_page.request_nonce);
    assert_eq!(retry_status.cursor, first_page.cursor);
    assert_eq!(page.transfer_id, first_page.transfer_id);
    assert_eq!(page.request_nonce, first_page.request_nonce);
    assert_eq!(page.cursor, first_page.cursor);
    assert_eq!(page.next_cursor, first_page.next_cursor);
    assert_eq!(page.total_bytes, first_page.total_bytes);
    assert_eq!(page.snapshot_digest, first_page.snapshot_digest);
    assert_eq!(page.snapshot_bytes, first_page.snapshot_bytes);
}

#[tokio::test]
async fn terminal_donor_absorbs_transient_local_pacer_busy_without_protocol_retry() {
    let (donor, net) = runtime(DONOR, DONOR_EPOCH);
    let cut = donor.terminal_journal.lock().await.terminal_cut();
    let request = StrictRecoveryTerminalReq {
        context: Some(StrictRecoveryContext {
            requester_node: REQUESTER as u32,
            requester_boot_epoch: REQUESTER_EPOCH,
            attempt_id: attempt_bytes(RecoveryAttemptId::new(REQUESTER_EPOCH, 406)),
            expected_donor_boot_epoch: DONOR_EPOCH,
            target: Some(StrictRecoveryTarget {
                repository_version: 0,
                history_freshness: 0,
                terminal_set_digest: Bytes::copy_from_slice(cut.terminal_set_digest()),
            }),
        }),
        target_cut: Some(cut_to_wire(cut)),
        transfer_id: 0,
        request_nonce: 181,
        expected_cursor: 0,
    };
    net.script_bulk_send_outcomes([
        MockBulkSendOutcome::LocalPacerBusy(Duration::from_millis(1)),
        MockBulkSendOutcome::Sent,
    ]);

    recv_terminal_req(&donor, REQUESTER, REQUESTER_EPOCH, true, request).await;

    let pages = terminal_pages(&net);
    assert_eq!(
        pages.len(),
        1,
        "only the successfully admitted page is emitted"
    );
    assert_eq!(
        StrictRecoveryStatus::try_from(pages[0].status).ok(),
        Some(StrictRecoveryStatus::Ok),
        "local pacing must not become a protocol-level retryable failure"
    );
    let observations = net.drain_strict_send_observations();
    assert_eq!(
        observations
            .iter()
            .filter(|observation| observation.lane == StrictSendLane::Bulk)
            .count(),
        2,
        "the donor must retry the immutable page after the pacer's delay"
    );
}

#[test]
fn reducer_keeps_retryable_failures_on_the_certified_donor() {
    let mut coordinator = super::recovery_reducer::StrictRecoveryCoordinator::default();
    let attempt = RecoveryAttemptId::new(1, 2);
    let donor = ParticipantIncarnation::new(1, 11);
    coordinator.transition(RecoveryEvent::Trigger {
        trigger: RecoveryTrigger::Explicit,
        attempt,
        total_known_participants: 2,
        now_ms: 0,
    });
    coordinator.transition(RecoveryEvent::ProbeResponse {
        attempt,
        attestation: RecoveryAttestation::new(donor.clone(), target(), cut(), 1),
        authenticated: true,
        now_ms: 1,
    });
    for failure in [DonorFailure::ResourceLimit, DonorFailure::RetryableFailure] {
        let effects = coordinator.transition(RecoveryEvent::DonorFailed {
            attempt,
            donor: donor.clone(),
            failure,
            now_ms: 2,
        });
        assert_eq!(coordinator.donor(), Some(&donor));
        assert_eq!(
            coordinator.phase(),
            RecoveryPhase::FetchingTerminalCheckpoint
        );
        assert!(
            effects
                .iter()
                .any(|effect| matches!(effect, RecoveryEffect::Retry { .. }))
        );
    }
}

#[tokio::test]
async fn startup_verifying_restart_completes_after_repository_was_already_replaced() {
    #[derive(serde::Serialize)]
    struct NamedCountingSnapshot {
        entries: Vec<(u64, u64)>,
        strict_operation_ids: Vec<(u64, u64)>,
    }

    let temp = tempfile::TempDir::new().unwrap();
    let net = MockNet::new(REQUESTER, vec![DONOR, REQUESTER, SECOND_WITNESS]);
    for (node, epoch) in [
        (DONOR, DONOR_EPOCH),
        (REQUESTER, REQUESTER_EPOCH),
        (SECOND_WITNESS, SECOND_WITNESS_EPOCH),
    ] {
        net.set_epoch(node, epoch);
        net.set_peer_strict_replication_protocol_version(node, STRICT_PROTOCOL_VERSION_V8);
    }
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V8);
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V8));
    net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));

    let local = CountingStrictRepo::new_current();
    *local.state.lock() = (8, vec![(8, 222, None)]);
    let exact_repository_image = Bytes::from(
        rmp_serde::to_vec_named(&NamedCountingSnapshot {
            entries: vec![(8, 111)],
            strict_operation_ids: Vec::new(),
        })
        .expect("encode named donor snapshot"),
    );
    let staging_path = temp.path().join("exact-repository-image.stage");

    {
        let setup = StrictRuntime::new(
            local.clone(),
            REQUESTER,
            REQUESTER_EPOCH,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let cut = setup.terminal_journal.lock().await.terminal_cut();
        let attempt = RecoveryAttemptId::new(REQUESTER_EPOCH, 71);
        let durable_attempt_id = {
            let mut bytes = [0_u8; 16];
            bytes[..8].copy_from_slice(&attempt.hi().to_be_bytes());
            bytes[8..].copy_from_slice(&attempt.lo().to_be_bytes());
            bytes
        };
        let donor = DurableRecoveryParticipant::new(DONOR, DONOR_EPOCH);
        let witness = DurableRecoveryParticipant::new(SECOND_WITNESS, SECOND_WITNESS_EPOCH);
        let durable_attempt = DurableRecoveryAttempt::new(
            durable_attempt_id,
            DurableRecoveryPhase::Installing,
            2,
            Some(DurableRecoveryTarget::new(8, 0, *cut.terminal_set_digest())),
            vec![
                DurableRecoveryWitness::new(donor.clone(), cut),
                DurableRecoveryWitness::new(witness.clone(), cut),
            ],
            vec![donor.clone(), witness.clone()],
            Some(0),
            Some(donor.clone()),
            Some(cut),
            vec![],
        )
        .unwrap();
        let bound_image = super::catchup::encode_bound_s2s_snapshot_envelope(
            exact_repository_image.clone(),
            BTreeMap::new(),
            BTreeMap::new(),
            cut,
        )
        .unwrap();
        let manifest = write_recovery_staging_artifact(
            &staging_path,
            RecoveryStagingExpectation::new(
                attempt.hi(),
                attempt.lo(),
                super::HistoryMetadata {
                    version: 8,
                    freshness: 0,
                },
                cut,
            ),
            &bound_image,
        )
        .unwrap();
        let intent = DurableRecoveryArtifactIntent::new(
            durable_attempt_id,
            staging_path.clone(),
            *manifest.content_digest(),
            manifest.content_len(),
            DurableRecoveryRepositoryMetadata::new(8, 0),
            cut,
        );
        {
            let mut journal = setup.terminal_journal.lock().await;
            journal.persist_recovery_attempt(&durable_attempt).unwrap();
            journal
                .prepare_staged_recovery_checkpoint(
                    8,
                    0,
                    cut,
                    &[],
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    &durable_attempt,
                    &intent,
                )
                .unwrap();
        }
        setup
            .install_repository_snapshot(8, exact_repository_image.clone())
            .await
            .expect("install the staged repository before the simulated crash");
        setup
            .replace_runtime_terminal_checkpoint(BTreeMap::new(), BTreeMap::new())
            .await;
        assert_eq!(local.log(), vec![(8, 111)]);
        assert_eq!(
            local.history_metadata(),
            super::HistoryMetadata {
                version: 8,
                freshness: 0,
            }
        );
        assert_eq!(setup.terminal_journal.lock().await.terminal_cut(), cut);
        let verifying_attempt = DurableRecoveryAttempt::new(
            durable_attempt_id,
            DurableRecoveryPhase::Verifying,
            2,
            Some(DurableRecoveryTarget::new(8, 0, *cut.terminal_set_digest())),
            vec![
                DurableRecoveryWitness::new(donor.clone(), cut),
                DurableRecoveryWitness::new(witness.clone(), cut),
            ],
            vec![donor.clone(), witness],
            Some(0),
            Some(donor),
            Some(cut),
            vec![],
        )
        .unwrap();
        setup
            .with_terminal_journal_mutation(move |journal| {
                journal.persist_recovery_attempt(&verifying_attempt)
            })
            .await
            .unwrap();
    }

    let recovered = StrictRuntime::new(
        local.clone(),
        REQUESTER,
        REQUESTER_EPOCH + 1,
        "channels".to_owned(),
        net.clone(),
        CancellationToken::new(),
        Arc::new(ReplicationConfig::default()),
    );
    assert_eq!(
        recovered.recovery_coordinator.lock().phase(),
        RecoveryPhase::Verifying
    );
    assert!(recovered.pending_repository_image_install().is_some());
    spawn_startup_rollforward(recovered.clone());
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while recovered.recovery_coordinator.lock().phase() != RecoveryPhase::Healthy {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("startup recovery must finish");

    assert_eq!(
        local.log(),
        vec![(8, 111)],
        "metadata equality must not finalize a different repository image"
    );
    let (_, normalized_repository_image) = local.snapshot_with_metadata().unwrap();
    assert_ne!(
        normalized_repository_image, exact_repository_image,
        "successful installation need not preserve the donor's serialization"
    );
    assert!(recovered.pending_repository_image_install().is_none());
    {
        let journal = recovered.terminal_journal.lock().await;
        assert!(journal.load_recovery_attempt().unwrap().is_none());
        assert!(journal.load_recovery_artifact_intent().unwrap().is_none());
    }
    assert!(!staging_path.exists());
    assert_eq!(net.strict_protocol_disable_reports(), 0);
}

#[tokio::test]
async fn durable_restore_preserves_ranked_donor_order_and_failure_history() {
    let temp = tempfile::TempDir::new().unwrap();
    let net = MockNet::new(REQUESTER, vec![DONOR, REQUESTER, SECOND_WITNESS]);
    for (node, epoch) in [
        (DONOR, DONOR_EPOCH),
        (REQUESTER, REQUESTER_EPOCH),
        (SECOND_WITNESS, SECOND_WITNESS_EPOCH),
    ] {
        net.set_epoch(node, epoch);
        net.set_peer_strict_replication_protocol_version(node, STRICT_PROTOCOL_VERSION_V8);
    }
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V8);
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V8));
    net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));
    let rt = StrictRuntime::new(
        CountingStrictRepo::new(),
        REQUESTER,
        REQUESTER_EPOCH,
        "channels".to_owned(),
        net,
        CancellationToken::new(),
        Arc::new(ReplicationConfig::default()),
    );
    let cut = rt.terminal_journal.lock().await.terminal_cut();
    let attempt = RecoveryAttemptId::new(REQUESTER_EPOCH, 72);
    let donor = DurableRecoveryParticipant::new(DONOR, DONOR_EPOCH);
    let higher_rank = DurableRecoveryParticipant::new(SECOND_WITNESS, SECOND_WITNESS_EPOCH);
    let durable = DurableRecoveryAttempt::new(
        attempt_bytes(attempt).as_ref().try_into().unwrap(),
        DurableRecoveryPhase::FetchingTerminalCheckpoint,
        2,
        Some(DurableRecoveryTarget::new(0, 0, *cut.terminal_set_digest())),
        vec![
            DurableRecoveryWitness::new(donor.clone(), cut).with_history_rank(1),
            DurableRecoveryWitness::new(higher_rank.clone(), cut).with_history_rank(99),
        ],
        vec![higher_rank.clone(), donor.clone()],
        Some(0),
        Some(higher_rank.clone()),
        Some(cut),
        vec![DurableRecoveryFailure::new(
            donor.clone(),
            "target_moved",
            1,
        )],
    )
    .unwrap();
    rt.with_terminal_journal_mutation(move |journal| journal.persist_recovery_attempt(&durable))
        .await
        .unwrap();

    let (restored, effects) = {
        let journal = rt.terminal_journal.lock().await;
        restore_coordinator(&journal)
            .unwrap()
            .expect("durable recovery attempt")
    };
    assert_eq!(
        restored.donor(),
        Some(&ParticipantIncarnation::new(
            u64::from(SECOND_WITNESS),
            SECOND_WITNESS_EPOCH,
        ))
    );
    assert_eq!(restored.failure_history().len(), 1);
    assert_eq!(
        restored.failure_history()[0].donor(),
        &ParticipantIncarnation::new(u64::from(DONOR), DONOR_EPOCH)
    );
    assert_eq!(
        restored.failure_history()[0].reason(),
        DonorFailure::TargetMoved
    );
    assert!(matches!(
        effects.as_slice(),
        [RecoveryEffect::SendTransfer {
            donor,
            kind: super::recovery_reducer::TransferKind::TerminalCheckpoint,
            ..
        }] if donor.node_id() == u64::from(SECOND_WITNESS)
    ));
}

#[tokio::test]
async fn uncertified_timeout_reopens_in_backoff_without_premature_probe() {
    let temp = tempfile::TempDir::new().unwrap();
    let attempt;
    {
        let net = MockNet::new(REQUESTER, vec![DONOR, REQUESTER, SECOND_WITNESS]);
        for (node, epoch) in [
            (DONOR, DONOR_EPOCH),
            (REQUESTER, REQUESTER_EPOCH),
            (SECOND_WITNESS, SECOND_WITNESS_EPOCH),
        ] {
            net.set_epoch(node, epoch);
            net.set_peer_strict_replication_protocol_version(node, STRICT_PROTOCOL_VERSION_V8);
        }
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V8);
        net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V8));
        net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            REQUESTER,
            REQUESTER_EPOCH,
            "channels".to_owned(),
            net,
            shutdown,
            Arc::new(ReplicationConfig::default()),
        );
        rt.finish_history_election_for_test();
        assert!(rt.request_recovery_for_test());
        attempt = rt
            .recovery_coordinator
            .lock()
            .attempt()
            .expect("active recovery attempt");
        rt.take_recovery_effects();
        let deadline = rt
            .recovery_coordinator
            .lock()
            .progress_deadline_ms()
            .expect("certification deadline");
        rt.transition_recovery(RecoveryEvent::Deadline {
            attempt,
            now_ms: deadline,
        });
        assert_eq!(
            rt.recovery_coordinator.lock().phase(),
            RecoveryPhase::Backoff
        );
        execute_effects(&rt, rt.take_recovery_effects()).await;
    }

    let journal =
        super::terminal_journal::TerminalJournal::load(Some(temp.path().to_path_buf()), "channels")
            .unwrap();
    let durable = journal
        .load_recovery_attempt()
        .unwrap()
        .expect("timed-out recovery attempt");
    assert_eq!(durable.attempt_id().as_slice(), attempt_bytes(attempt));
    assert_eq!(durable.phase(), DurableRecoveryPhase::Backoff);
    let (mut restored, effects) = restore_coordinator(&journal)
        .unwrap()
        .expect("timed-out recovery coordinator");
    assert_eq!(restored.attempt(), Some(attempt));
    assert_eq!(restored.phase(), RecoveryPhase::Backoff);
    assert!(
        effects
            .iter()
            .all(|effect| !matches!(effect, RecoveryEffect::SendProbes { .. }))
    );
    let retry_not_before = restored
        .progress_deadline_ms()
        .expect("restored backoff retry deadline");
    let early = restored.transition(RecoveryEvent::RetryElapsed {
        attempt,
        now_ms: retry_not_before - 1,
    });
    assert!(early.is_empty());
    assert_eq!(restored.attempt(), Some(attempt));
    assert_eq!(restored.phase(), RecoveryPhase::Backoff);
}

#[tokio::test]
async fn restart_discards_partial_transfer_and_uses_same_attempt_with_fresh_wire_context() {
    let temp = tempfile::TempDir::new().unwrap();
    let net = MockNet::new(REQUESTER, vec![DONOR, REQUESTER, SECOND_WITNESS]);
    for (node, epoch) in [
        (DONOR, DONOR_EPOCH),
        (REQUESTER, REQUESTER_EPOCH),
        (SECOND_WITNESS, SECOND_WITNESS_EPOCH),
    ] {
        net.set_epoch(node, epoch);
        net.set_peer_strict_replication_protocol_version(node, STRICT_PROTOCOL_VERSION_V8);
    }
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V8);
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V8));
    net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));
    let repository = CountingStrictRepo::new_current();

    let (attempt, abandoned_wire_identity) = {
        let requester = StrictRuntime::new(
            repository.clone(),
            REQUESTER,
            REQUESTER_EPOCH,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        requester.finish_history_election_for_test();
        let (attempt, _, effects) = certify_terminal_transfer(&requester);
        execute_effects(&requester, effects).await;
        let first_request = terminal_request(&net);
        requester.transition_recovery(RecoveryEvent::TransferProgress {
            attempt,
            donor: ParticipantIncarnation::new(u64::from(DONOR), DONOR_EPOCH),
            kind: super::recovery_reducer::TransferKind::TerminalCheckpoint,
            authenticated: true,
            complete: true,
            now_ms: 4,
        });
        execute_effects(&requester, requester.take_recovery_effects()).await;
        let first_snapshot_request = snapshot_request(&net);
        let image = b"firstsecond";
        recv_snapshot_page(
            &requester,
            DONOR,
            DONOR_EPOCH,
            true,
            snapshot_response_page(
                &first_snapshot_request,
                0,
                b"first",
                image.len() as u64,
                snapshot_digest(image),
            ),
        )
        .await;
        let continuation = snapshot_request(&net);
        assert_eq!(continuation.expected_cursor, 5);
        assert_eq!(continuation.transfer_id, 92);
        {
            let journal = requester.terminal_journal.lock().await;
            let durable = journal
                .load_recovery_attempt()
                .unwrap()
                .expect("durable partial transfer attempt");
            assert_eq!(durable.attempt_id().as_slice(), attempt_bytes(attempt));
            assert_eq!(
                durable.phase(),
                DurableRecoveryPhase::FetchingRepositorySnapshot
            );
        }
        (
            attempt,
            (
                first_request
                    .context
                    .as_ref()
                    .expect("initial recovery context")
                    .requester_boot_epoch,
                first_request.request_nonce,
            ),
        )
    };

    let restarted_epoch = REQUESTER_EPOCH + 1;
    net.set_epoch(REQUESTER, restarted_epoch);
    let recovered = StrictRuntime::new(
        repository,
        REQUESTER,
        restarted_epoch,
        "channels".to_owned(),
        net.clone(),
        CancellationToken::new(),
        Arc::new(ReplicationConfig::default()),
    );
    assert_eq!(
        recovered.recovery_coordinator.lock().attempt(),
        Some(attempt)
    );
    assert_eq!(
        recovered.recovery_coordinator.lock().phase(),
        RecoveryPhase::FetchingTerminalCheckpoint
    );
    execute_effects(&recovered, recovered.take_recovery_effects()).await;
    let restarted_frames = net.drain_captures();
    assert!(
        !restarted_frames.iter().any(|frame| matches!(
            frame,
            CapturedFrame::StrictUnicast {
                body: StrictBody::RecoverySnapshotReq(_),
                ..
            }
        )),
        "restart must discard the partial snapshot rather than resume its cursor"
    );
    let restarted = restarted_frames
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                dst: DONOR,
                body: StrictBody::RecoveryTerminalReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("cursor-zero terminal recovery request after restart");
    let context = restarted.context.as_ref().expect("recovery context");
    assert_eq!(context.attempt_id, attempt_bytes(attempt));
    assert_eq!(context.requester_boot_epoch, restarted_epoch);
    assert_eq!(context.expected_donor_boot_epoch, DONOR_EPOCH);
    assert_eq!(restarted.transfer_id, 0);
    assert_eq!(restarted.expected_cursor, 0);
    assert_ne!(restarted.request_nonce, 0);
    assert_ne!(
        (context.requester_boot_epoch, restarted.request_nonce),
        abandoned_wire_identity,
        "the restarted transfer must use a fresh requester wire identity"
    );
    assert_eq!(client_terminal_state_count(&recovered, attempt), Some(0));
}

#[tokio::test]
async fn restart_during_partial_terminal_checkpoint_reuses_attempt_with_fresh_cursor_zero_wire() {
    let temp = tempfile::TempDir::new().unwrap();
    let net = MockNet::new(REQUESTER, vec![DONOR, REQUESTER, SECOND_WITNESS]);
    for (node, epoch) in [
        (DONOR, DONOR_EPOCH),
        (REQUESTER, REQUESTER_EPOCH),
        (SECOND_WITNESS, SECOND_WITNESS_EPOCH),
    ] {
        net.set_epoch(node, epoch);
        net.set_peer_strict_replication_protocol_version(node, STRICT_PROTOCOL_VERSION_V8);
    }
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V8);
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V8));
    net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));
    let repository = CountingStrictRepo::new_current();

    let (attempt, abandoned_wire_identity) = {
        let requester = StrictRuntime::new(
            repository.clone(),
            REQUESTER,
            REQUESTER_EPOCH,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        requester.finish_history_election_for_test();
        let (attempt, _, effects) = certify_terminal_transfer(&requester);
        execute_effects(&requester, effects).await;
        let first_request = terminal_request(&net);
        recv_terminal_page(
            &requester,
            DONOR,
            DONOR_EPOCH,
            true,
            response_page(&first_request, 0, 1, true),
        )
        .await;
        let continuation = terminal_request(&net);
        assert_eq!(continuation.expected_cursor, 1);
        assert_ne!(continuation.transfer_id, 0);
        assert_eq!(client_terminal_state_count(&requester, attempt), Some(1));
        {
            let journal = requester.terminal_journal.lock().await;
            let durable = journal
                .load_recovery_attempt()
                .unwrap()
                .expect("durable partial terminal transfer attempt");
            assert_eq!(durable.attempt_id().as_slice(), attempt_bytes(attempt));
            assert_eq!(
                durable.phase(),
                DurableRecoveryPhase::FetchingTerminalCheckpoint
            );
        }
        (
            attempt,
            (
                first_request
                    .context
                    .as_ref()
                    .expect("initial recovery context")
                    .requester_boot_epoch,
                first_request.request_nonce,
            ),
        )
    };

    let restarted_epoch = REQUESTER_EPOCH + 1;
    net.set_epoch(REQUESTER, restarted_epoch);
    let recovered = StrictRuntime::new(
        repository,
        REQUESTER,
        restarted_epoch,
        "channels".to_owned(),
        net.clone(),
        CancellationToken::new(),
        Arc::new(ReplicationConfig::default()),
    );
    assert_eq!(
        recovered.recovery_coordinator.lock().attempt(),
        Some(attempt)
    );
    assert_eq!(
        recovered.recovery_coordinator.lock().phase(),
        RecoveryPhase::FetchingTerminalCheckpoint
    );
    execute_effects(&recovered, recovered.take_recovery_effects()).await;
    let restarted = terminal_request(&net);
    let context = restarted.context.as_ref().expect("recovery context");
    assert_eq!(context.attempt_id, attempt_bytes(attempt));
    assert_eq!(context.requester_boot_epoch, restarted_epoch);
    assert_eq!(context.expected_donor_boot_epoch, DONOR_EPOCH);
    assert_eq!(restarted.transfer_id, 0);
    assert_eq!(restarted.expected_cursor, 0);
    assert_ne!(restarted.request_nonce, 0);
    assert_ne!(
        (context.requester_boot_epoch, restarted.request_nonce),
        abandoned_wire_identity,
        "restart must allocate a fresh requester wire identity"
    );
    assert_eq!(client_terminal_state_count(&recovered, attempt), Some(0));
}

#[tokio::test]
async fn startup_rollforward_recovers_artifact_without_matching_durable_attempt_locally() {
    let temp = tempfile::TempDir::new().unwrap();
    let net = MockNet::new(REQUESTER, vec![DONOR, REQUESTER, SECOND_WITNESS]);
    for (node, epoch) in [
        (DONOR, DONOR_EPOCH),
        (REQUESTER, REQUESTER_EPOCH),
        (SECOND_WITNESS, SECOND_WITNESS_EPOCH),
    ] {
        net.set_epoch(node, epoch);
        net.set_peer_strict_replication_protocol_version(node, STRICT_PROTOCOL_VERSION_V8);
    }
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V8);
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V8));
    net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));

    let local = CountingStrictRepo::new_current();
    *local.state.lock() = (8, vec![(8, 222, None)]);
    let donor_repository = CountingStrictRepo::new_current();
    *donor_repository.state.lock() = (8, vec![(8, 111, None)]);
    let (_, donor_snapshot) = donor_repository.snapshot().unwrap();

    {
        let setup = StrictRuntime::new(
            local.clone(),
            REQUESTER,
            REQUESTER_EPOCH,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let cut = setup.terminal_journal.lock().await.terminal_cut();
        let attempt = RecoveryAttemptId::new(REQUESTER_EPOCH, 73);
        let mut durable_attempt_id = [0_u8; 16];
        durable_attempt_id[..8].copy_from_slice(&attempt.hi().to_be_bytes());
        durable_attempt_id[8..].copy_from_slice(&attempt.lo().to_be_bytes());
        let donor = DurableRecoveryParticipant::new(DONOR, DONOR_EPOCH);
        let witness = DurableRecoveryParticipant::new(SECOND_WITNESS, SECOND_WITNESS_EPOCH);
        let durable_attempt = DurableRecoveryAttempt::new(
            durable_attempt_id,
            DurableRecoveryPhase::Installing,
            2,
            Some(DurableRecoveryTarget::new(8, 0, *cut.terminal_set_digest())),
            vec![
                DurableRecoveryWitness::new(donor, cut),
                DurableRecoveryWitness::new(witness, cut),
            ],
            vec![donor, witness],
            Some(0),
            Some(donor),
            Some(cut),
            vec![],
        )
        .unwrap();
        let bound_image = super::catchup::encode_bound_s2s_snapshot_envelope(
            donor_snapshot,
            BTreeMap::new(),
            BTreeMap::new(),
            cut,
        )
        .unwrap();
        let staging_path = temp.path().join("orphaned-recovery-image.stage");
        let manifest = write_recovery_staging_artifact(
            &staging_path,
            RecoveryStagingExpectation::new(
                attempt.hi(),
                attempt.lo(),
                super::HistoryMetadata {
                    version: 8,
                    freshness: 0,
                },
                cut,
            ),
            &bound_image,
        )
        .unwrap();
        let intent = DurableRecoveryArtifactIntent::new(
            durable_attempt_id,
            staging_path,
            *manifest.content_digest(),
            manifest.content_len(),
            DurableRecoveryRepositoryMetadata::new(8, 0),
            cut,
        );
        let mut journal = setup.terminal_journal.lock().await;
        journal.persist_recovery_attempt(&durable_attempt).unwrap();
        journal
            .prepare_staged_recovery_checkpoint(
                8,
                0,
                cut,
                &[],
                &BTreeMap::new(),
                &BTreeMap::new(),
                &durable_attempt,
                &intent,
            )
            .unwrap();
    }

    let journal_path = temp
        .path()
        .join("strict-terminal-journal")
        .join(format!("topic-{}.sqlite3", hex::encode("channels")));
    {
        let connection = rusqlite::Connection::open(journal_path).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys = OFF")
            .unwrap();
        assert_eq!(
            connection
                .execute("DELETE FROM strict_recovery_state", [])
                .unwrap(),
            1
        );
    }

    let recovered = StrictRuntime::new(
        local.clone(),
        REQUESTER,
        REQUESTER_EPOCH + 1,
        "channels".to_owned(),
        net.clone(),
        CancellationToken::new(),
        Arc::new(ReplicationConfig::default()),
    );
    assert_eq!(
        recovered.recovery_coordinator.lock().phase(),
        RecoveryPhase::Healthy,
        "the corrupted durable tuple currently restores no coordinator attempt"
    );
    assert_eq!(
        net.strict_protocol_disable_reports(),
        0,
        "the invalid correlation must not disable strict replication cluster-wide"
    );
    assert!(recovered.pending_repository_image_install().is_some());
    let runtime_sentinel = make_op_id(REQUESTER, REQUESTER_EPOCH + 1, 99);
    recovered
        .state
        .lock()
        .applied_operations
        .insert(runtime_sentinel, 8);

    spawn_startup_rollforward(recovered.clone());
    tokio::time::timeout(Duration::from_secs(2), async {
        while recovered.recovery_coordinator.lock().phase() == RecoveryPhase::Healthy {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("invalid recovery artifact correlation must start topic-local recertification");

    assert_eq!(
        net.strict_protocol_disable_reports(),
        0,
        "topic-local recovery must preserve strict availability elsewhere"
    );
    assert!(recovered.pending_repository_image_install().is_some());

    assert_eq!(local.log(), vec![(8, 222)]);
    assert_eq!(
        recovered
            .state
            .lock()
            .applied_operations
            .get(&runtime_sentinel),
        Some(&8),
        "startup must not replace the runtime terminal checkpoint"
    );
}

#[tokio::test]
async fn active_install_clears_repository_install_fences_before_completion() {
    #[derive(serde::Serialize)]
    struct NamedCountingSnapshot {
        entries: Vec<(u64, u64)>,
        strict_operation_ids: Vec<(u64, u64)>,
    }

    let temp = tempfile::TempDir::new().unwrap();
    let (requester, net) = runtime(REQUESTER, REQUESTER_EPOCH);
    net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));
    let journal_cut = requester.terminal_journal.lock().await.terminal_cut();
    let reducer_cut = ReducerCut::new(
        *journal_cut.journal_id(),
        journal_cut.generation(),
        *journal_cut.chain_digest(),
        *journal_cut.terminal_set_digest(),
    );
    let metadata = super::HistoryMetadata {
        version: 8,
        freshness: 0,
    };
    let target = LogicalTarget::new(
        metadata.version,
        metadata.freshness,
        *journal_cut.terminal_set_digest(),
    );
    let (attempt, donor, effects) = certify_terminal_transfer_for(&requester, target, reducer_cut);
    execute_effects(&requester, effects).await;
    let _ = terminal_request(&net);
    requester.transition_recovery(RecoveryEvent::TransferProgress {
        attempt,
        donor,
        kind: super::recovery_reducer::TransferKind::TerminalCheckpoint,
        authenticated: true,
        complete: true,
        now_ms: 4,
    });
    execute_effects(&requester, requester.take_recovery_effects()).await;
    let request = snapshot_request(&net);

    requester.require_repository_image_install(metadata);
    assert!(requester.repository_base_required());
    let repository_image = Bytes::from(
        rmp_serde::to_vec_named(&NamedCountingSnapshot {
            entries: vec![(8, 111)],
            strict_operation_ids: Vec::new(),
        })
        .unwrap(),
    );
    let bound_image = super::catchup::encode_bound_s2s_snapshot_envelope(
        repository_image,
        BTreeMap::new(),
        BTreeMap::new(),
        journal_cut,
    )
    .unwrap();
    let page = StrictRecoverySnapshotPage {
        context: request.context.clone(),
        responder_node: DONOR as u32,
        responder_boot_epoch: DONOR_EPOCH,
        status: StrictRecoveryStatus::Ok.into(),
        target_cut: request.target_cut.clone(),
        transfer_id: 92,
        request_nonce: request.request_nonce,
        cursor: 0,
        next_cursor: bound_image.len() as u64,
        total_bytes: bound_image.len() as u64,
        snapshot_digest: snapshot_digest(&bound_image),
        snapshot_bytes: bound_image,
        has_more: false,
    };
    recv_snapshot_page(&requester, DONOR, DONOR_EPOCH, true, page).await;
    for _ in 0..4 {
        let effects = requester.take_recovery_effects();
        if effects.is_empty() {
            break;
        }
        execute_effects(&requester, effects).await;
    }

    assert_eq!(
        requester.recovery_coordinator.lock().phase(),
        RecoveryPhase::Healthy
    );
    assert!(
        !requester.repository_base_required(),
        "successful active recovery must clear its repository install fences"
    );
}

#[tokio::test]
async fn startup_pending_repository_intent_without_artifact_waits_for_v8_then_recovers() {
    let temp = tempfile::TempDir::new().unwrap();
    let net = MockNet::new(REQUESTER, vec![DONOR, REQUESTER, SECOND_WITNESS]);
    for (node, epoch) in [
        (DONOR, DONOR_EPOCH),
        (REQUESTER, REQUESTER_EPOCH),
        (SECOND_WITNESS, SECOND_WITNESS_EPOCH),
    ] {
        net.set_epoch(node, epoch);
        net.set_peer_strict_replication_protocol_version(node, STRICT_PROTOCOL_VERSION_V8);
    }
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V8);
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V8));
    net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));

    let repo = CountingStrictRepo::new_current();
    *repo.state.lock() = (8, vec![(8, 111, None)]);
    {
        let setup = StrictRuntime::new(
            repo.clone(),
            REQUESTER,
            REQUESTER_EPOCH,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let mut journal = setup.terminal_journal.lock().await;
        journal
            .install_repository_checkpoint(8, 0, &BTreeMap::new(), &BTreeMap::new())
            .unwrap();
        assert!(journal.pending_repository_image_install().is_some());
        assert!(journal.load_recovery_artifact_intent().unwrap().is_none());
        assert!(journal.load_recovery_attempt().unwrap().is_none());
    }

    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V8 - 1);
    for node in [DONOR, REQUESTER, SECOND_WITNESS] {
        net.set_peer_strict_replication_protocol_version(node, STRICT_PROTOCOL_VERSION_V8 - 1);
    }

    let shutdown = CancellationToken::new();
    let recovered = StrictRuntime::new(
        repo,
        REQUESTER,
        REQUESTER_EPOCH + 1,
        "channels".to_owned(),
        net.clone(),
        shutdown.clone(),
        Arc::new(ReplicationConfig::default()),
    );
    recovered.start();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        recovered.recovery_coordinator.lock().phase(),
        RecoveryPhase::Healthy,
        "the pending marker must remain fenced without starting a pre-v8 fallback"
    );
    assert!(recovered.pending_repository_image_install().is_some());
    assert!(net.drain_captures().iter().all(|capture| !matches!(
        capture,
        CapturedFrame::StrictUnicast {
            body: StrictBody::RecoveryProbeReq(_),
            ..
        }
    )));

    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V8);
    for node in [DONOR, REQUESTER, SECOND_WITNESS] {
        net.set_peer_strict_replication_protocol_version(node, STRICT_PROTOCOL_VERSION_V8);
    }

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while recovered.recovery_coordinator.lock().phase() == RecoveryPhase::Healthy {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a legacy pending image marker must enter mandatory v8 recovery");

    assert_eq!(
        recovered.recovery_coordinator.lock().phase(),
        RecoveryPhase::Certifying
    );
    assert!(recovered.pending_repository_image_install().is_some());
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if net.drain_captures().iter().any(|capture| {
                matches!(
                    capture,
                    CapturedFrame::StrictUnicast {
                        body: StrictBody::RecoveryProbeReq(_),
                        ..
                    }
                )
            }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("mandatory v8 recovery must emit certification probes");
    shutdown.cancel();
}

#[tokio::test]
async fn startup_rollforward_removes_completed_recovery_orphan_idempotently() {
    let temp = tempfile::TempDir::new().unwrap();
    let net = MockNet::new(REQUESTER, vec![DONOR, REQUESTER, SECOND_WITNESS]);
    for (node, epoch) in [
        (DONOR, DONOR_EPOCH),
        (REQUESTER, REQUESTER_EPOCH),
        (SECOND_WITNESS, SECOND_WITNESS_EPOCH),
    ] {
        net.set_epoch(node, epoch);
        net.set_peer_strict_replication_protocol_version(node, STRICT_PROTOCOL_VERSION_V8);
    }
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V8);
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V8));
    net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));

    let recovered = StrictRuntime::new(
        CountingStrictRepo::new_current(),
        REQUESTER,
        REQUESTER_EPOCH,
        "channels".to_owned(),
        net,
        CancellationToken::new(),
        Arc::new(ReplicationConfig::default()),
    );
    assert_eq!(
        recovered.recovery_coordinator.lock().phase(),
        RecoveryPhase::Healthy
    );
    assert!(
        recovered
            .terminal_journal
            .lock()
            .await
            .load_recovery_artifact_intent()
            .unwrap()
            .is_none()
    );

    let attempt = RecoveryAttemptId::new(REQUESTER_EPOCH, 72);
    let mut topic_hasher = std::collections::hash_map::DefaultHasher::new();
    "channels".hash(&mut topic_hasher);
    let staging_path = temp.path().join(format!(
        "strict-recovery-{:016x}-{:016x}-{:016x}.stage",
        topic_hasher.finish(),
        attempt.hi(),
        attempt.lo()
    ));
    let terminal_cut = recovered.terminal_journal.lock().await.terminal_cut();
    write_recovery_staging_artifact(
        &staging_path,
        RecoveryStagingExpectation::new(
            attempt.hi(),
            attempt.lo(),
            super::HistoryMetadata {
                version: 0,
                freshness: 0,
            },
            terminal_cut,
        ),
        b"completed recovery image",
    )
    .unwrap();

    spawn_startup_rollforward(recovered.clone());
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while staging_path.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("startup must remove the unreferenced topic staging artifact");

    spawn_startup_rollforward(recovered.clone());
    tokio::task::yield_now().await;
    assert!(!staging_path.exists());
    assert_eq!(
        recovered.recovery_coordinator.lock().phase(),
        RecoveryPhase::Healthy
    );
    assert!(
        recovered
            .terminal_journal
            .lock()
            .await
            .load_recovery_artifact_intent()
            .unwrap()
            .is_none()
    );
}
