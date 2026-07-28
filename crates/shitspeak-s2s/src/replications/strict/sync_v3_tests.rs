//! Focused protocol-v3 repair tests.
//!
//! These tests deliberately exercise the pairwise repair seam without
//! starting the background strict runtime. That keeps timer traffic out of
//! the assertions and makes accidental coupling between metadata probes and
//! operation-bearing synchronization visible.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use tokio_util::sync::CancellationToken;

use super::{
    catchup::{
        recv_v3_clock_probe_resp, recv_v3_history_probe_resp, recv_v3_terminal_sync_page,
        recv_v3_terminal_sync_req, request_v3_clock_probe, request_v3_history_probe,
        request_v3_terminal_sync, respond_to_request, retry_v3_terminal_transmissions,
        send_v3_metadata_control,
    },
    runtime::{
        STRICT_PROTOCOL_VERSION_V2, STRICT_PROTOCOL_VERSION_V3,
        STRICT_V3_CONTROL_MAX_ENCODED_BYTES, StrictRuntime, make_op_id,
    },
    session_reducer::{
        Effect as SessionEffect, Event as SessionEvent, SyncKind as SessionSyncKind,
        Trigger as SessionTrigger, TriggerOrigin as SessionTriggerOrigin,
    },
    sync_v3::{
        InboundTerminalSyncDisposition, PeerIncarnation, ResponderSession, SourceTransitionOutcome,
        SyncV3State, cut_from_wire, cut_to_wire,
    },
    terminal_journal::{TerminalCut, TerminalJournal},
};
use crate::overlay::MemberIncarnation;
use crate::replications::{
    config::ReplicationConfig,
    metrics::{CatchupPhase, CatchupReason},
    proto::{
        StrictBody, StrictCatchupReason, StrictCatchupReq, StrictClockProbeReq,
        StrictClockProbeResp, StrictDecisionAbort, StrictDecisionCommit, StrictFrozenTarget,
        StrictHistoryProbeReq, StrictHistoryProbeResp, StrictHistoryTransferReq,
        StrictTerminalOutcome, StrictTerminalPageKind, StrictTerminalState, StrictTerminalSyncAck,
        StrictTerminalSyncPage, StrictTerminalSyncReq, StrictTerminalSyncStatus,
    },
    test_support::{
        CapturedFrame, CountingStrictRepo, MockBulkSendOutcome, MockNet, StrictSendLane,
        StrictSendOutcome,
    },
};
use shitspeak_core::NodeIdentifier;

fn runtime(
    self_id: NodeIdentifier,
    config: ReplicationConfig,
) -> (Arc<StrictRuntime<CountingStrictRepo>>, Arc<MockNet>) {
    let net = MockNet::new(self_id, vec![1, 2]);
    net.set_epoch(1, 11);
    net.set_epoch(2, 22);
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V3);
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V3));
    net.set_peer_strict_replication_protocol_version(
        if self_id == 1 { 2 } else { 1 },
        STRICT_PROTOCOL_VERSION_V3,
    );
    let repo = CountingStrictRepo::new();
    let rt = StrictRuntime::new(
        repo,
        self_id,
        if self_id == 1 { 11 } else { 22 },
        "channels".to_owned(),
        net.clone(),
        CancellationToken::new(),
        Arc::new(config),
    );
    rt.finish_history_election_for_test();
    (rt, net)
}

#[tokio::test]
async fn inbound_history_yields_opposing_terminal_client_then_resumes_it_after_final_ack() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    request_v3_terminal_sync(&rt, 2, StrictCatchupReason::TerminalFence).await;
    let initial_terminal = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("outbound terminal request");

    let history_request = StrictCatchupReq {
        src_node: 2,
        since_version: 0,
        chunk_token: 0,
        force_snapshot: false,
        history_probe_only: false,
        terminal_state_cursor: u64::MAX,
        terminal_decision_generation: 0,
        snapshot_transfer_id: 0,
        snapshot_chunk_cursor: 0,
        history_transfer: Some(StrictHistoryTransferReq {
            expected_responder_boot_epoch: 11,
            transfer_id: 700,
            request_nonce: 701,
            expected_cursor: 0,
            target_version: 0,
            reason: StrictCatchupReason::RepositoryGap as i32,
            acknowledged_request_nonce: 0,
            final_ack: false,
        }),
    };
    respond_to_request(&rt, 2, history_request).await;

    assert!(
        net.drain_captures().into_iter().any(|frame| matches!(
            frame,
            CapturedFrame::StrictUnicast {
                body: StrictBody::CatchupResp(_),
                ..
            }
        )),
        "history must win the cross-protocol collision"
    );
    assert!(
        rt.v3_sync
            .lock()
            .client(PeerIncarnation::new(2, 22))
            .is_none(),
        "the opposing terminal client must yield while history is served"
    );

    respond_to_request(
        &rt,
        2,
        StrictCatchupReq {
            src_node: 2,
            since_version: 0,
            chunk_token: 0,
            force_snapshot: false,
            history_probe_only: false,
            terminal_state_cursor: u64::MAX,
            terminal_decision_generation: 0,
            snapshot_transfer_id: 0,
            snapshot_chunk_cursor: 0,
            history_transfer: Some(StrictHistoryTransferReq {
                expected_responder_boot_epoch: 11,
                transfer_id: 700,
                request_nonce: 702,
                expected_cursor: 0,
                target_version: 0,
                reason: StrictCatchupReason::RepositoryGap as i32,
                acknowledged_request_nonce: 701,
                final_ack: true,
            }),
        },
    )
    .await;

    let resumed = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("terminal request must resume after history final ACK");
    assert_ne!(resumed.request_nonce, initial_terminal.request_nonce);
}

fn terminal_abort(sequence: u64) -> StrictTerminalState {
    let op_id = make_op_id(1, 11, sequence);
    StrictTerminalState {
        coord_node: 1,
        op_id_hi: op_id.0,
        op_id_lo: op_id.1,
        ballot: sequence.saturating_add(1),
        outcome: Some(StrictTerminalOutcome::Abort(StrictDecisionAbort {})),
        resolver_node: 0,
        resolver_boot_epoch: 0,
        frozen_targets: Vec::new(),
    }
}

fn terminal_page(frame: CapturedFrame) -> crate::replications::proto::StrictTerminalSyncPage {
    let CapturedFrame::StrictUnicast { dst, body, .. } = frame else {
        panic!("expected strict unicast");
    };
    assert_eq!(dst, 2);
    let StrictBody::TerminalSyncPage(page) = body else {
        panic!("expected terminal sync page, got {body:?}");
    };
    page
}

fn terminal_request(frame: CapturedFrame) -> StrictTerminalSyncReq {
    let CapturedFrame::StrictUnicast { dst, body, .. } = frame else {
        panic!("expected strict unicast");
    };
    assert_eq!(dst, 1);
    let StrictBody::TerminalSyncReq(request) = body else {
        panic!("expected terminal sync request, got {body:?}");
    };
    request
}

async fn initial_sync_request(
    source: &StrictRuntime<CountingStrictRepo>,
    nonce: u64,
    known_generation: u64,
    requester_set_digest: Bytes,
) -> StrictTerminalSyncReq {
    let known_source_cut = source
        .terminal_journal
        .lock()
        .await
        .terminal_cut_at(known_generation)
        .map(cut_to_wire);
    StrictTerminalSyncReq {
        src_node: 2,
        expected_responder_boot_epoch: 11,
        reason: StrictCatchupReason::SteadyState as i32,
        known_source_cut,
        requester_terminal_set_digest: requester_set_digest,
        transfer_id: 0,
        request_nonce: nonce,
        expected_cursor: 0,
    }
}

#[tokio::test]
async fn delivery_watermark_clock_probe_is_bounded_control_only() {
    let (rt, net) = runtime(1, ReplicationConfig::default());

    request_v3_clock_probe(&rt, 2, StrictCatchupReason::DeliveryWatermark).await;

    let observations = net.drain_strict_send_observations();
    assert_eq!(observations.len(), 1);
    let observation = &observations[0];
    assert_eq!(observation.lane, StrictSendLane::RedundantControl);
    assert!(observation.encoded.len() <= 2 * 1024);
    assert!(matches!(observation.body, StrictBody::ClockProbeReq(_)));
    assert!(!matches!(
        observation.body,
        StrictBody::HistoryProbeReq(_) | StrictBody::TerminalSyncReq(_) | StrictBody::CatchupReq(_)
    ));
}

#[tokio::test]
async fn every_operation_free_v3_control_shape_stays_under_the_encoded_limit() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    let cut = cut_to_wire(rt.terminal_journal.lock().await.terminal_cut());
    let controls = vec![
        StrictBody::ClockProbeReq(StrictClockProbeReq {
            src_node: 1,
            expected_responder_boot_epoch: 22,
            request_nonce: 1,
            reason: StrictCatchupReason::DeliveryWatermark as i32,
        }),
        StrictBody::ClockProbeResp(StrictClockProbeResp {
            responder_node: 1,
            expected_requester_boot_epoch: 22,
            request_nonce: 2,
            src_clock: u64::MAX,
            reason: StrictCatchupReason::DeliveryWatermark as i32,
        }),
        StrictBody::HistoryProbeReq(StrictHistoryProbeReq {
            src_node: 1,
            expected_responder_boot_epoch: 22,
            request_nonce: 3,
            reason: StrictCatchupReason::HistoryElection as i32,
        }),
        StrictBody::HistoryProbeResp(StrictHistoryProbeResp {
            responder_node: 1,
            expected_requester_boot_epoch: 22,
            request_nonce: 4,
            repository_version: u64::MAX,
            history_freshness: i64::MAX,
            runtime_started_at: u64::MAX,
            history_node: 1,
            terminal_cut: Some(cut.clone()),
            reason: StrictCatchupReason::HistoryElection as i32,
        }),
        StrictBody::TerminalSyncReq(StrictTerminalSyncReq {
            src_node: 1,
            expected_responder_boot_epoch: 22,
            reason: StrictCatchupReason::TerminalFence as i32,
            known_source_cut: Some(cut.clone()),
            requester_terminal_set_digest: Bytes::from_static(&[0; 32]),
            transfer_id: u64::MAX,
            request_nonce: u64::MAX,
            expected_cursor: u64::MAX,
        }),
        StrictBody::TerminalSyncPage(StrictTerminalSyncPage {
            responder_node: 1,
            expected_requester_boot_epoch: 22,
            transfer_id: u64::MAX,
            request_nonce: u64::MAX,
            status: StrictTerminalSyncStatus::ResourceLimit as i32,
            kind: StrictTerminalPageKind::Delta as i32,
            base_cut: Some(cut.clone()),
            target_cut: Some(cut.clone()),
            cursor: u64::MAX,
            next_cursor: u64::MAX,
            image_digest: Bytes::from_static(&[0; 32]),
            checkpoint_states: Vec::new(),
            deltas: Vec::new(),
            has_more: false,
        }),
        StrictBody::TerminalSyncAck(StrictTerminalSyncAck {
            src_node: 1,
            expected_responder_boot_epoch: 22,
            transfer_id: u64::MAX,
            request_nonce: u64::MAX,
            target_cut: Some(cut),
        }),
    ];

    for body in controls {
        send_v3_metadata_control(
            &rt,
            2,
            body,
            CatchupReason::TerminalFence,
            CatchupPhase::Metadata,
        )
        .await
        .expect("bounded v3 metadata control");
    }

    let observations = net.drain_strict_send_observations();
    assert_eq!(observations.len(), 7);
    assert!(observations.iter().all(|observation| {
        observation.lane == StrictSendLane::RedundantControl
            && observation.encoded.len() <= STRICT_V3_CONTROL_MAX_ENCODED_BYTES
    }));
}

#[tokio::test]
async fn oversized_v3_control_is_rejected_before_the_transport() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    let body = StrictBody::TerminalSyncReq(StrictTerminalSyncReq {
        src_node: 1,
        expected_responder_boot_epoch: 22,
        reason: StrictCatchupReason::TerminalFence as i32,
        known_source_cut: None,
        requester_terminal_set_digest: Bytes::from(vec![0; 3 * 1024]),
        transfer_id: 0,
        request_nonce: 1,
        expected_cursor: 0,
    });

    assert!(
        send_v3_metadata_control(
            &rt,
            2,
            body,
            CatchupReason::TerminalFence,
            CatchupPhase::Metadata,
        )
        .await
        .is_err()
    );
    assert!(net.drain_captures().is_empty());
    assert!(net.drain_strict_send_observations().is_empty());
}

#[tokio::test]
async fn v3_probe_is_not_dispatched_to_a_v2_peer() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    net.set_peer_strict_replication_protocol_version(2, STRICT_PROTOCOL_VERSION_V2);

    request_v3_clock_probe(&rt, 2, StrictCatchupReason::DeliveryWatermark).await;

    assert!(net.drain_captures().is_empty());
    assert!(net.drain_strict_send_observations().is_empty());
}

#[tokio::test]
async fn equal_terminal_set_digest_returns_one_metadata_page_without_a_transfer() {
    let (source, net) = runtime(1, ReplicationConfig::default());
    for sequence in 1..=32 {
        assert!(
            source
                .apply_catchup_terminal_state(terminal_abort(sequence))
                .await
        );
    }
    let digest = Bytes::copy_from_slice(
        source
            .terminal_journal
            .lock()
            .await
            .terminal_cut()
            .terminal_set_digest(),
    );
    let request = initial_sync_request(&source, 101, 0, digest).await;

    recv_v3_terminal_sync_req(&source, 2, 22, request).await;

    let page = terminal_page(net.drain_captures().pop().expect("one response"));
    assert_eq!(
        StrictTerminalSyncStatus::try_from(page.status).ok(),
        Some(StrictTerminalSyncStatus::UpToDate)
    );
    assert_eq!(
        page.transfer_id, 0,
        "equal state must not allocate a transfer"
    );
    assert!(page.checkpoint_states.is_empty());
    assert!(page.deltas.is_empty());
    assert!(!page.has_more);
    let observations = net.drain_strict_send_observations();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].lane, StrictSendLane::RedundantControl);
    assert!(observations[0].encoded.len() <= 2 * 1024);
    assert!(
        source
            .v3_sync
            .lock()
            .responder(PeerIncarnation::new(2, 22))
            .is_none()
    );
}

#[tokio::test]
async fn already_known_source_cut_returns_up_to_date_without_allocating_transfer() {
    let (source, net) = runtime(1, ReplicationConfig::default());
    for sequence in 1..=3 {
        assert!(
            source
                .apply_catchup_terminal_state(terminal_abort(sequence))
                .await
        );
    }
    let request = initial_sync_request(&source, 151, 3, Bytes::from_static(&[0x55; 32])).await;

    recv_v3_terminal_sync_req(&source, 2, 22, request).await;

    let page = terminal_page(net.drain_captures().pop().expect("one response"));
    assert_eq!(
        StrictTerminalSyncStatus::try_from(page.status).ok(),
        Some(StrictTerminalSyncStatus::UpToDate)
    );
    assert_eq!(page.transfer_id, 0);
    assert!(page.checkpoint_states.is_empty());
    assert!(page.deltas.is_empty());
    assert!(
        source
            .v3_sync
            .lock()
            .responder(PeerIncarnation::new(2, 22))
            .is_none()
    );
}

#[tokio::test]
async fn unrecognized_higher_restart_cut_cannot_claim_a_restored_responder_is_up_to_date() {
    let (source, net) = runtime(1, ReplicationConfig::default());
    let target = source.terminal_journal.lock().await.terminal_cut();
    let stale_higher_cut = TerminalCut::new(
        *target.journal_id(),
        target.generation().saturating_add(1),
        [0x71; 32],
        [0x72; 32],
    );

    recv_v3_terminal_sync_req(
        &source,
        2,
        22,
        StrictTerminalSyncReq {
            src_node: 2,
            expected_responder_boot_epoch: 11,
            reason: StrictCatchupReason::Admission as i32,
            known_source_cut: Some(cut_to_wire(stale_higher_cut)),
            requester_terminal_set_digest: Bytes::from_static(&[0x73; 32]),
            transfer_id: 0,
            request_nonce: 991,
            expected_cursor: 0,
        },
    )
    .await;

    let page = terminal_page(net.drain_captures().pop().expect("checkpoint response"));
    assert_eq!(
        StrictTerminalSyncStatus::try_from(page.status).ok(),
        Some(StrictTerminalSyncStatus::Ok)
    );
    assert_eq!(
        StrictTerminalPageKind::try_from(page.kind).ok(),
        Some(StrictTerminalPageKind::Checkpoint)
    );
    assert_ne!(page.transfer_id, 0);
    assert_eq!(page.target_cut, Some(cut_to_wire(target)));
}

#[tokio::test]
async fn history_election_syncs_from_the_winner_not_the_last_responder() {
    let net = MockNet::new(1, vec![1, 2, 3]);
    net.set_epoch(1, 11);
    net.set_epoch(2, 22);
    net.set_epoch(3, 33);
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V3);
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V3));
    net.set_peer_strict_replication_protocol_version(2, STRICT_PROTOCOL_VERSION_V3);
    net.set_peer_strict_replication_protocol_version(3, STRICT_PROTOCOL_VERSION_V3);
    let rt = StrictRuntime::new(
        CountingStrictRepo::new(),
        1,
        11,
        "channels".to_owned(),
        net.clone(),
        CancellationToken::new(),
        Arc::new(ReplicationConfig::default()),
    );
    {
        let mut state = rt.state.lock();
        state.finish_history_election();
        state.request_history_election();
        state.begin_history_election([2, 3]);
    }

    request_v3_history_probe(&rt, 2, StrictCatchupReason::HistoryElection).await;
    request_v3_history_probe(&rt, 3, StrictCatchupReason::HistoryElection).await;
    let requests = net.drain_captures();
    let mut nonce_2 = 0;
    let mut nonce_3 = 0;
    for frame in requests {
        let CapturedFrame::StrictUnicast { dst, body, .. } = frame else {
            continue;
        };
        let StrictBody::HistoryProbeReq(request) = body else {
            continue;
        };
        match dst {
            2 => nonce_2 = request.request_nonce,
            3 => nonce_3 = request.request_nonce,
            _ => {}
        }
    }
    assert_ne!(nonce_2, 0);
    assert_ne!(nonce_3, 0);
    let winner_cut = crate::replications::proto::StrictTerminalCut {
        journal_id: Bytes::from_static(&[2; 16]),
        generation: 1,
        chain_digest: Bytes::from_static(&[2; 32]),
        terminal_set_digest: Bytes::from_static(&[2; 32]),
    };
    let expected_winner_cut = cut_from_wire(&winner_cut).expect("winner cut");
    let last_cut = crate::replications::proto::StrictTerminalCut {
        journal_id: Bytes::from_static(&[3; 16]),
        generation: 1,
        chain_digest: Bytes::from_static(&[3; 32]),
        terminal_set_digest: Bytes::from_static(&[3; 32]),
    };

    recv_v3_history_probe_resp(
        &rt,
        2,
        22,
        StrictHistoryProbeResp {
            responder_node: 2,
            expected_requester_boot_epoch: 11,
            request_nonce: nonce_2,
            repository_version: 10,
            history_freshness: 10,
            runtime_started_at: 10,
            history_node: 2,
            terminal_cut: Some(winner_cut),
            reason: StrictCatchupReason::HistoryElection as i32,
        },
    )
    .await;
    assert!(net.drain_captures().is_empty());

    recv_v3_history_probe_resp(
        &rt,
        3,
        33,
        StrictHistoryProbeResp {
            responder_node: 3,
            expected_requester_boot_epoch: 11,
            request_nonce: nonce_3,
            repository_version: 5,
            history_freshness: 5,
            runtime_started_at: 10,
            history_node: 3,
            terminal_cut: Some(last_cut),
            reason: StrictCatchupReason::HistoryElection as i32,
        },
    )
    .await;

    let frames = net.drain_captures();
    assert_eq!(frames.len(), 1);
    assert!(matches!(
        &frames[0],
        CapturedFrame::StrictUnicast {
            dst: 2,
            body: StrictBody::TerminalSyncReq(_),
            ..
        }
    ));
    assert_eq!(
        rt.v3_sync
            .lock()
            .client(PeerIncarnation::new(2, 22))
            .and_then(|client| client.desired_cut()),
        Some(expected_winner_cut)
    );
    assert!(
        rt.v3_sync
            .lock()
            .client(PeerIncarnation::new(3, 33))
            .is_none()
    );
}

#[tokio::test]
async fn history_election_promotes_an_existing_periodic_probe_without_omitting_its_peer() {
    let net = MockNet::new(1, vec![1, 2, 3]);
    net.set_epoch(1, 11);
    net.set_epoch(2, 22);
    net.set_epoch(3, 33);
    // New rounds require the cumulative V5 cluster floor. Keep the endpoint
    // advertisements at V3 so this remains a focused V3 repair-coordinator
    // test rather than accidentally disabling bootstrap origination.
    net.set_strict_replication_protocol_version(
        crate::replications::protocol::STRICT_PROTOCOL_VERSION_CURRENT,
    );
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V3));
    net.set_peer_strict_replication_protocol_version(2, STRICT_PROTOCOL_VERSION_V3);
    net.set_peer_strict_replication_protocol_version(3, STRICT_PROTOCOL_VERSION_V3);
    let rt = StrictRuntime::new(
        CountingStrictRepo::new(),
        1,
        11,
        "channels".to_owned(),
        net.clone(),
        CancellationToken::new(),
        Arc::new(ReplicationConfig::default()),
    );

    assert!(
        rt.v3_sync
            .lock()
            .begin_client(
                PeerIncarnation::new(3, 33),
                StrictCatchupReason::SteadyState as i32,
                Duration::from_secs(30),
            )
            .is_some(),
        "peer three should begin with lower-priority transfer work"
    );
    request_v3_history_probe(&rt, 2, StrictCatchupReason::Admission).await;
    let periodic = net.drain_captures().pop().expect("periodic probe");
    let CapturedFrame::StrictUnicast {
        dst: 2,
        body: StrictBody::HistoryProbeReq(periodic),
        ..
    } = periodic
    else {
        panic!("expected periodic history probe");
    };
    assert_eq!(periodic.reason, StrictCatchupReason::Admission as i32);

    rt.try_bootstrap_catchup().await;

    let mut election_peers = Vec::new();
    for frame in net.drain_captures() {
        let CapturedFrame::StrictUnicast {
            dst,
            body: StrictBody::HistoryProbeReq(probe),
            ..
        } = frame
        else {
            continue;
        };
        assert_eq!(probe.reason, StrictCatchupReason::HistoryElection as i32);
        if dst == 2 {
            assert_eq!(
                probe.request_nonce, periodic.request_nonce,
                "promotion must preserve the outstanding probe identity"
            );
        }
        election_peers.push(dst);
    }
    election_peers.sort_unstable();
    assert_eq!(
        election_peers,
        vec![3],
        "the existing peer-two nonce keeps its scheduled retry instead of sending an immediate duplicate"
    );
    let accepted = rt
        .v3_sync
        .lock()
        .accept_history_nonce(PeerIncarnation::new(2, 22), periodic.request_nonce)
        .expect("promoted probe response");
    assert_eq!(
        accepted.reason(),
        StrictCatchupReason::Admission as i32,
        "the original admission obligation remains primary"
    );
    assert!(
        accepted.election_pending(),
        "the reused response must also enter the election collector"
    );
    assert!(
        accepted.admission_pending(),
        "promoting the nonce must preserve its independent admission intent"
    );
}

#[tokio::test]
async fn history_probe_does_not_pull_from_an_already_known_behind_source() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    let source_cut_wire = crate::replications::proto::StrictTerminalCut {
        journal_id: Bytes::from_static(&[7; 16]),
        generation: 4,
        chain_digest: Bytes::from_static(&[8; 32]),
        terminal_set_digest: Bytes::from_static(&[9; 32]),
    };
    let source_cut = cut_from_wire(&source_cut_wire).expect("source cut");
    let peer = PeerIncarnation::new(2, 22);
    rt.v3_sync.lock().remember_source_cut(peer, source_cut);

    request_v3_history_probe(&rt, 2, StrictCatchupReason::SteadyState).await;
    let request = net.drain_captures().pop().expect("history probe");
    let CapturedFrame::StrictUnicast {
        body: StrictBody::HistoryProbeReq(request),
        ..
    } = request
    else {
        panic!("expected history probe request");
    };

    recv_v3_history_probe_resp(
        &rt,
        2,
        22,
        StrictHistoryProbeResp {
            responder_node: 2,
            expected_requester_boot_epoch: 11,
            request_nonce: request.request_nonce,
            repository_version: 0,
            history_freshness: 0,
            runtime_started_at: 22,
            history_node: 2,
            terminal_cut: Some(source_cut_wire),
            reason: StrictCatchupReason::SteadyState as i32,
        },
    )
    .await;

    assert!(net.drain_captures().is_empty());
    assert!(rt.v3_sync.lock().client(peer).is_none());
}

#[tokio::test]
async fn recognized_cut_pages_only_missing_generations_over_bulk() {
    let config = ReplicationConfig::default().with_strict_max_catchup_ops(32);
    let (source, net) = runtime(1, config);
    for sequence in 1..=10 {
        assert!(
            source
                .apply_catchup_terminal_state(terminal_abort(sequence))
                .await
        );
    }
    let request = initial_sync_request(&source, 202, 7, Bytes::from_static(&[1; 32])).await;

    recv_v3_terminal_sync_req(&source, 2, 22, request).await;

    let page = terminal_page(net.drain_captures().pop().expect("one response"));
    assert_eq!(
        page.deltas
            .iter()
            .map(|delta| delta.generation)
            .collect::<Vec<_>>(),
        vec![8, 9, 10]
    );
    assert!(page.checkpoint_states.is_empty());
    assert!(!page.has_more);
    let observations = net.drain_strict_send_observations();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].lane, StrictSendLane::Bulk);
}

#[tokio::test]
async fn same_incarnation_repair_reuses_durable_cut_as_client_cursor_after_failure() {
    let config = ReplicationConfig::default().with_strict_max_catchup_ops(32);
    let (source, _source_net) = runtime(1, config.clone());
    let (sink, sink_net) = runtime(2, config);
    for sequence in 1..=3 {
        assert!(
            source
                .apply_catchup_terminal_state(terminal_abort(sequence))
                .await
        );
    }
    let peer = PeerIncarnation::new(1, 11);
    let known = source
        .terminal_journal
        .lock()
        .await
        .terminal_cut_at(2)
        .expect("source generation two");
    sink.v3_sync.lock().remember_source_cut(peer, known);
    sink.v3_sync.lock().discard_peer(1, false);

    request_v3_terminal_sync(&sink, 1, StrictCatchupReason::TerminalFence).await;
    let request = terminal_request(sink_net.drain_captures().pop().expect("repair request"));
    assert_eq!(
        request.known_source_cut.as_ref().and_then(cut_from_wire),
        Some(known)
    );
    assert_eq!(
        request.expected_cursor,
        known.generation(),
        "the reducer cursor must match the reusable cut sent on the wire"
    );
}

#[tokio::test]
async fn duplicate_initial_request_replays_the_byte_identical_page() {
    let config = ReplicationConfig::default().with_strict_max_catchup_ops(2);
    let (source, net) = runtime(1, config);
    for sequence in 1..=4 {
        assert!(
            source
                .apply_catchup_terminal_state(terminal_abort(sequence))
                .await
        );
    }
    let request = initial_sync_request(&source, 303, 0, Bytes::from_static(&[1; 32])).await;

    recv_v3_terminal_sync_req(&source, 2, 22, request.clone()).await;
    recv_v3_terminal_sync_req(&source, 2, 22, request).await;

    let observations = net.drain_strict_send_observations();
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].encoded, observations[1].encoded);
    let peer = PeerIncarnation::new(2, 22);
    assert!(source.v3_sync.lock().responder(peer).is_some());
}

#[tokio::test]
async fn duplicate_final_page_is_suppressed_without_another_ack_or_continuation() {
    let config = ReplicationConfig::default().with_strict_max_catchup_ops(32);
    let (source, source_net) = runtime(1, config.clone());
    let (sink, sink_net) = runtime(2, config);
    for sequence in 1..=4 {
        assert!(
            source
                .apply_catchup_terminal_state(terminal_abort(sequence))
                .await
        );
    }

    request_v3_terminal_sync(&sink, 1, StrictCatchupReason::SteadyState).await;
    let request = terminal_request(sink_net.drain_captures().pop().expect("initial request"));
    sink_net.drain_strict_send_observations();
    recv_v3_terminal_sync_req(&source, 2, 22, request).await;
    let page = terminal_page(source_net.drain_captures().pop().expect("terminal page"));
    assert!(!page.has_more);

    recv_v3_terminal_sync_page(&sink, 1, 11, page.clone()).await;
    let first_completion = sink_net.drain_captures();
    assert_eq!(first_completion.len(), 1);
    assert!(matches!(
        first_completion[0],
        CapturedFrame::StrictUnicast {
            body: StrictBody::TerminalSyncAck(_),
            ..
        }
    ));
    let completion_sends = sink_net.drain_strict_send_observations();
    assert_eq!(completion_sends.len(), 1);
    assert_eq!(completion_sends[0].lane, StrictSendLane::RedundantControl);

    recv_v3_terminal_sync_page(&sink, 1, 11, page).await;
    assert!(sink_net.drain_captures().is_empty());
    assert!(sink_net.drain_strict_send_observations().is_empty());
}

#[tokio::test]
async fn delayed_duplicate_page_does_not_block_the_active_continuation() {
    let config = ReplicationConfig::default().with_strict_max_catchup_ops(1);
    let (source, source_net) = runtime(1, config.clone());
    let (sink, sink_net) = runtime(2, config);
    for sequence in 1..=3 {
        assert!(
            source
                .apply_catchup_terminal_state(terminal_abort(sequence))
                .await
        );
    }

    request_v3_terminal_sync(&sink, 1, StrictCatchupReason::SteadyState).await;
    let request = terminal_request(sink_net.drain_captures().pop().expect("initial request"));
    sink_net.drain_strict_send_observations();
    recv_v3_terminal_sync_req(&source, 2, 22, request).await;
    let first_page = terminal_page(source_net.drain_captures().pop().expect("first page"));
    assert!(first_page.has_more);

    recv_v3_terminal_sync_page(&sink, 1, 11, first_page.clone()).await;
    let continuation = terminal_request(
        sink_net
            .drain_captures()
            .pop()
            .expect("continuation request"),
    );
    sink_net.drain_strict_send_observations();

    tokio::time::timeout(
        Duration::from_secs(1),
        recv_v3_terminal_sync_page(&sink, 1, 11, first_page),
    )
    .await
    .expect("delayed duplicate page handling must not block");

    let peer = PeerIncarnation::new(1, 11);
    let sync = sink.v3_sync.lock();
    let client = sync.client(peer).expect("active continuation");
    assert_eq!(client.pending_nonce(), continuation.request_nonce);
    assert_eq!(client.transfer_id(), continuation.transfer_id);
    assert_eq!(client.next_cursor(), continuation.expected_cursor);
    assert!(sink_net.drain_captures().is_empty());
    assert!(sink_net.drain_strict_send_observations().is_empty());
}

#[tokio::test]
async fn checkpoint_completes_when_requester_has_additional_local_fences() {
    let config = ReplicationConfig::default().with_strict_max_catchup_ops(32);
    let (source, source_net) = runtime(1, config.clone());
    let (sink, sink_net) = runtime(2, config);
    assert!(source.apply_catchup_terminal_state(terminal_abort(1)).await);
    assert!(sink.apply_catchup_terminal_state(terminal_abort(2)).await);

    request_v3_terminal_sync(&sink, 1, StrictCatchupReason::SteadyState).await;
    let request = terminal_request(sink_net.drain_captures().pop().expect("initial request"));
    recv_v3_terminal_sync_req(&source, 2, 22, request).await;
    let page = terminal_page(source_net.drain_captures().pop().expect("checkpoint page"));
    assert_eq!(
        StrictTerminalPageKind::try_from(page.kind).ok(),
        Some(StrictTerminalPageKind::Checkpoint)
    );
    let target = page
        .target_cut
        .as_ref()
        .and_then(cut_from_wire)
        .expect("target cut");

    recv_v3_terminal_sync_page(&sink, 1, 11, page).await;

    let completion = sink_net.drain_captures();
    assert_eq!(completion.len(), 1);
    assert!(matches!(
        completion[0],
        CapturedFrame::StrictUnicast {
            body: StrictBody::TerminalSyncAck(_),
            ..
        }
    ));
    let peer = PeerIncarnation::new(1, 11);
    assert!(sink.v3_sync.lock().client(peer).is_none());
    assert_eq!(sink.v3_sync.lock().known_source_cut(peer), Some(target));
    assert_ne!(
        sink.terminal_journal
            .lock()
            .await
            .terminal_cut()
            .terminal_set_digest(),
        target.terminal_set_digest(),
        "the source image must be tracked independently of the local superset"
    );
}

#[tokio::test]
async fn terminal_checkpoint_buffers_commit_from_disjoint_frozen_partition() {
    let config = ReplicationConfig::default().with_strict_max_catchup_ops(32);
    let (source, source_net) = runtime(1, config.clone());
    let (sink, sink_net) = runtime(2, config);
    let op_id = make_op_id(1, 11, 77);
    let committed = StrictTerminalState {
        coord_node: 1,
        op_id_hi: op_id.0,
        op_id_lo: op_id.1,
        ballot: 1,
        outcome: Some(StrictTerminalOutcome::Commit(StrictDecisionCommit {
            ts_final: 10,
            op_msgpack: Bytes::from(rmp_serde::to_vec(&77u64).unwrap()),
        })),
        resolver_node: 1,
        resolver_boot_epoch: 11,
        // Node 2 was outside the frozen partition configuration and learns
        // the authoritative commit only after the partition heals.
        frozen_targets: vec![StrictFrozenTarget {
            node: 1,
            boot_epoch: 11,
        }],
    };
    assert!(source.apply_catchup_terminal_state(committed).await);
    assert!(sink.apply_catchup_terminal_state(terminal_abort(2)).await);

    request_v3_terminal_sync(&sink, 1, StrictCatchupReason::TerminalFence).await;
    let request = terminal_request(sink_net.drain_captures().pop().expect("initial request"));
    recv_v3_terminal_sync_req(&source, 2, 22, request).await;
    let page = terminal_page(source_net.drain_captures().pop().expect("checkpoint page"));
    assert_eq!(
        StrictTerminalPageKind::try_from(page.kind).ok(),
        Some(StrictTerminalPageKind::Checkpoint)
    );

    recv_v3_terminal_sync_page(&sink, 1, 11, page).await;

    assert!(
        sink.state
            .lock()
            .commit_buffer
            .values()
            .any(|op| op.op_id == op_id),
        "terminal repair must queue the disjoint partition's durable commit for delivery"
    );
}

#[tokio::test]
async fn expired_continuation_is_explicit_and_never_restarts_at_zero() {
    let config = ReplicationConfig::default()
        .with_strict_max_catchup_ops(1)
        .with_pending_propose_ttl(Duration::ZERO);
    let (source, net) = runtime(1, config);
    for sequence in 1..=3 {
        assert!(
            source
                .apply_catchup_terminal_state(terminal_abort(sequence))
                .await
        );
    }
    recv_v3_terminal_sync_req(
        &source,
        2,
        22,
        initial_sync_request(&source, 404, 0, Bytes::from_static(&[1; 32])).await,
    )
    .await;
    let first = terminal_page(net.drain_captures().pop().expect("first page"));
    assert!(first.has_more);
    let peer = PeerIncarnation::new(2, 22);
    assert!(source.v3_sync.lock().responder(peer).is_some());
    let continuation = StrictTerminalSyncReq {
        src_node: 2,
        expected_responder_boot_epoch: 11,
        reason: StrictCatchupReason::SteadyState as i32,
        known_source_cut: first.base_cut.clone(),
        requester_terminal_set_digest: Bytes::from_static(&[1; 32]),
        transfer_id: first.transfer_id,
        request_nonce: 405,
        expected_cursor: first.next_cursor,
    };

    recv_v3_terminal_sync_req(&source, 2, 22, continuation).await;

    let expired = terminal_page(net.drain_captures().pop().expect("expiry response"));
    assert_eq!(
        StrictTerminalSyncStatus::try_from(expired.status).ok(),
        Some(StrictTerminalSyncStatus::TransferExpired)
    );
    assert_eq!(expired.transfer_id, first.transfer_id);
    assert_eq!(expired.cursor, first.next_cursor);
    assert!(source.v3_sync.lock().responder(peer).is_none());
}

#[test]
fn reason_only_session_triggers_coalesce_without_marking_dirty() {
    let mut state = SyncV3State::default();
    let peer = PeerIncarnation::new(2, 22);
    let ttl = Duration::from_secs(30);
    let first = state.begin_client(peer, StrictCatchupReason::SteadyState as i32, ttl);
    assert!(first.is_some());

    for _ in 0..100 {
        assert!(
            state
                .begin_client(peer, StrictCatchupReason::SteadyState as i32, ttl)
                .is_none()
        );
    }
    assert!(!state.client(peer).unwrap().dirty());

    assert!(
        state
            .begin_client(peer, StrictCatchupReason::TerminalFence as i32, ttl)
            .is_none()
    );
    assert!(!state.client(peer).unwrap().dirty());
    assert_eq!(
        state.client(peer).unwrap().reason(),
        StrictCatchupReason::TerminalFence as i32
    );

    // Once the responder has fixed a target, another terminal-fence trigger
    // may represent a newer head even when the caller has no explicit cut.
    // Coalesce it into exactly one dirty follow-up.
    let target = TerminalCut::new([1; 16], 1, [2; 32], [3; 32]);
    state
        .client_mut(peer)
        .unwrap()
        .accept_manifest(7, target, StrictTerminalPageKind::Delta, ttl);
    assert!(
        state
            .begin_client(peer, StrictCatchupReason::TerminalFence as i32, ttl)
            .is_none()
    );
    assert!(state.client(peer).unwrap().dirty());

    // Lower-priority periodic work coalesces without downgrading the reason.
    assert!(
        state
            .begin_client(peer, StrictCatchupReason::SteadyState as i32, ttl)
            .is_none()
    );
    assert_eq!(
        state.client(peer).unwrap().reason(),
        StrictCatchupReason::TerminalFence as i32
    );
    assert!(state.finish_client(peer).is_some());
    assert!(
        state
            .begin_client(peer, StrictCatchupReason::TerminalFence as i32, ttl)
            .is_some()
    );
}

#[test]
fn simultaneous_terminal_starts_choose_one_direction_by_node_id() {
    let peer = PeerIncarnation::new(2, 22);
    let ttl = Duration::from_secs(30);

    let mut lower = SyncV3State::default();
    assert!(
        lower
            .begin_client(peer, StrictCatchupReason::SteadyState as i32, ttl)
            .is_some()
    );
    assert_eq!(
        lower.resolve_inbound_terminal_start(1, peer),
        InboundTerminalSyncDisposition::Deflect
    );
    assert!(lower.client(peer).is_some());
    assert!(lower.responder(peer).is_none());

    let lower_peer = PeerIncarnation::new(1, 11);
    let mut higher = SyncV3State::default();
    let (nonce, _) = higher
        .begin_client(lower_peer, StrictCatchupReason::TerminalFence as i32, ttl)
        .expect("outbound client");
    assert_eq!(
        higher.resolve_inbound_terminal_start(2, lower_peer),
        InboundTerminalSyncDisposition::Yielded {
            cancelled_nonce: nonce
        }
    );
    assert!(higher.client(lower_peer).is_none());
    assert_eq!(
        higher.take_deferred_client(lower_peer),
        Some((StrictCatchupReason::TerminalFence as i32, None))
    );
}

#[test]
fn active_terminal_responder_allows_one_bounded_clock_probe() {
    let mut state = SyncV3State::default();
    let peer = PeerIncarnation::new(2, 22);
    let ttl = Duration::from_secs(30);
    let target = TerminalCut::new([1; 16], 1, [2; 32], [3; 32]);
    state.insert_responder(
        peer,
        ResponderSession::new(9, None, target, StrictTerminalPageKind::Checkpoint, 10, ttl),
    );
    assert!(state.has_checkpoint_blocking_work());

    assert!(
        state
            .begin_client(peer, StrictCatchupReason::TerminalFence as i32, ttl)
            .is_none()
    );
    assert!(state.client(peer).is_none());
    assert!(state.record_clock_nonce(peer, ttl).is_some());
    assert!(
        state.record_clock_nonce(peer, ttl).is_none(),
        "periodic triggers must not retransmit or extend the outstanding probe"
    );
    assert!(
        state
            .record_history_nonce(peer, StrictCatchupReason::Admission as i32, ttl)
            .is_none()
    );
    assert_eq!(
        state.take_deferred_client(peer),
        Some((StrictCatchupReason::TerminalFence as i32, None))
    );
    assert!(state.remove_responder(peer).is_some());
}

#[test]
fn active_terminal_client_allows_one_bounded_clock_probe() {
    let mut state = SyncV3State::default();
    let peer = PeerIncarnation::new(2, 22);
    let ttl = Duration::from_secs(30);

    assert!(
        state
            .begin_client(peer, StrictCatchupReason::TerminalFence as i32, ttl)
            .is_some()
    );
    assert!(state.has_checkpoint_blocking_work());
    assert!(state.record_clock_nonce(peer, ttl).is_some());
    for _ in 0..100 {
        assert!(
            state.record_clock_nonce(peer, ttl).is_none(),
            "periodic retries must remain bounded during an active terminal client"
        );
    }
}

#[test]
fn responder_expiry_releases_deferred_reverse_intent() {
    let mut state = SyncV3State::default();
    let peer = PeerIncarnation::new(2, 22);
    let ttl = Duration::from_secs(30);
    let target = TerminalCut::new([1; 16], 1, [2; 32], [3; 32]);
    state.insert_responder(
        peer,
        ResponderSession::new(9, None, target, StrictTerminalPageKind::Checkpoint, 10, ttl),
    );
    assert!(
        state
            .begin_client(peer, StrictCatchupReason::TerminalFence as i32, ttl)
            .is_none()
    );

    state.expire(Instant::now() + ttl + Duration::from_millis(1));
    assert_eq!(
        state.take_expired_deferred_clients(),
        vec![(peer, StrictCatchupReason::TerminalFence as i32, None)]
    );
}

#[test]
fn payload_cache_expiry_reconciles_reducer_and_stops_periodic_suppression() {
    let mut state = SyncV3State::default();
    let peer = PeerIncarnation::new(2, 22);
    let ttl = Duration::from_secs(30);
    let trigger = SessionEvent::Trigger(SessionTrigger {
        kind: SessionSyncKind::Terminal,
        origin: SessionTriggerOrigin::External,
        desired_cut: None,
    });

    let effects = state.transition_session(peer, trigger);
    let wire = effects
        .iter()
        .find_map(|effect| match effect {
            SessionEffect::StartSession {
                kind: SessionSyncKind::Terminal,
                wire,
            } => Some(*wire),
            _ => None,
        })
        .expect("terminal reducer session");
    state.begin_terminal_client_cache(
        peer,
        StrictCatchupReason::TerminalFence as i32,
        None,
        wire.nonce().get(),
        wire.cursor().value(),
        ttl,
    );
    assert!(state.has_session_work(peer));
    assert!(state.has_periodic_work(peer));

    state.expire(Instant::now() + ttl + Duration::from_millis(1));

    assert!(!state.has_session_work(peer));
    assert!(
        !state.has_periodic_work(peer),
        "an expired transfer must not suppress future periodic reconciliation"
    );
    assert!(
        state
            .transition_session(peer, trigger)
            .iter()
            .any(|effect| {
                matches!(
                    effect,
                    SessionEffect::StartSession {
                        kind: SessionSyncKind::Terminal,
                        ..
                    }
                )
            })
    );
}

#[tokio::test]
async fn higher_node_yields_simultaneous_equal_pull_without_reverse_branch() {
    let (rt, net) = runtime(2, ReplicationConfig::default());
    request_v3_terminal_sync(&rt, 1, StrictCatchupReason::SteadyState).await;
    let initial = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("higher-node outbound request");
    assert!(
        rt.v3_sync
            .lock()
            .client(PeerIncarnation::new(1, 11))
            .is_some()
    );

    recv_v3_terminal_sync_req(
        &rt,
        1,
        11,
        StrictTerminalSyncReq {
            src_node: 1,
            expected_responder_boot_epoch: 22,
            reason: StrictCatchupReason::SteadyState as i32,
            known_source_cut: None,
            requester_terminal_set_digest: initial.requester_terminal_set_digest,
            transfer_id: 0,
            request_nonce: 700,
            expected_cursor: 0,
        },
    )
    .await;

    assert!(
        rt.v3_sync
            .lock()
            .client(PeerIncarnation::new(1, 11))
            .is_none()
    );
    let frames = net.drain_captures();
    assert_eq!(
        frames
            .iter()
            .filter(|frame| matches!(
                frame,
                CapturedFrame::StrictUnicast {
                    body: StrictBody::TerminalSyncPage(_),
                    ..
                }
            ))
            .count(),
        1
    );
    assert!(!frames.iter().any(|frame| matches!(
        frame,
        CapturedFrame::StrictUnicast {
            body: StrictBody::TerminalSyncReq(_),
            ..
        }
    )));
    assert!(
        !rt.v3_sync
            .lock()
            .has_session_work(PeerIncarnation::new(1, 11)),
        "an equal-set collision must satisfy the yielded reverse intent and return Idle"
    );
}

#[tokio::test]
async fn collision_resource_limit_keeps_exact_outbound_request_active() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    request_v3_terminal_sync(&rt, 2, StrictCatchupReason::SteadyState).await;
    let request = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("outbound request");

    recv_v3_terminal_sync_page(
        &rt,
        2,
        22,
        StrictTerminalSyncPage {
            responder_node: 2,
            expected_requester_boot_epoch: 11,
            transfer_id: 0,
            request_nonce: request.request_nonce,
            status: StrictTerminalSyncStatus::ResourceLimit as i32,
            ..Default::default()
        },
    )
    .await;

    let peer = PeerIncarnation::new(2, 22);
    assert_eq!(
        rt.v3_sync
            .lock()
            .client(peer)
            .map(|client| client.pending_nonce()),
        Some(request.request_nonce)
    );
    assert!(rt.v3_retries.lock().request_is_current(peer, &request));

    let target = rt.terminal_journal.lock().await.terminal_cut();
    rt.v3_sync.lock().client_mut(peer).unwrap().accept_manifest(
        71,
        target,
        StrictTerminalPageKind::Checkpoint,
        Duration::from_secs(30),
    );
    recv_v3_terminal_sync_page(
        &rt,
        2,
        22,
        StrictTerminalSyncPage {
            responder_node: 2,
            expected_requester_boot_epoch: 11,
            transfer_id: 71,
            request_nonce: request.request_nonce,
            status: StrictTerminalSyncStatus::ResourceLimit as i32,
            base_cut: Some(cut_to_wire(target)),
            target_cut: Some(cut_to_wire(target)),
            ..Default::default()
        },
    )
    .await;
    assert!(rt.v3_sync.lock().client(peer).is_none());
}

#[test]
fn delayed_source_transitions_require_a_matching_bounded_history_position() {
    let mut state = SyncV3State::default();
    let peer = PeerIncarnation::new(2, 22);
    let journal_id = [7; 16];
    let cut0 = TerminalCut::new(journal_id, 0, [0; 32], [0; 32]);
    let cut1 = TerminalCut::new(journal_id, 1, [1; 32], [11; 32]);
    let cut2 = TerminalCut::new(journal_id, 2, [2; 32], [12; 32]);

    assert_eq!(
        state.observe_source_transition(peer, cut0, cut1, 2),
        SourceTransitionOutcome::Advanced
    );
    assert_eq!(
        state.observe_source_transition(peer, cut1, cut2, 2),
        SourceTransitionOutcome::Advanced
    );
    assert_eq!(
        state.observe_source_transition(peer, cut0, cut1, 2),
        SourceTransitionOutcome::Duplicate
    );

    let conflicting_cut1 = TerminalCut::new(journal_id, 1, [9; 32], [11; 32]);
    assert_eq!(
        state.observe_source_transition(peer, cut0, conflicting_cut1, 2),
        SourceTransitionOutcome::Rejected
    );

    // Reducing the bound evicts generation one while preserving the newest
    // transition. An unverifiable older replay is repaired by delta sync.
    let cut3 = TerminalCut::new(journal_id, 3, [3; 32], [13; 32]);
    assert_eq!(
        state.observe_source_transition(peer, cut2, cut3, 1),
        SourceTransitionOutcome::Advanced
    );
    assert_eq!(
        state.observe_source_transition(peer, cut0, cut1, 1),
        SourceTransitionOutcome::Rejected
    );
    assert_eq!(
        state.observe_source_transition(peer, cut2, cut3, 1),
        SourceTransitionOutcome::Duplicate
    );
}

#[test]
fn peer_restart_retains_only_the_reusable_durable_source_cut() {
    let mut state = SyncV3State::default();
    let old_peer = PeerIncarnation::new(2, 22);
    let new_peer = PeerIncarnation::new(2, 23);
    let old_cut = TerminalCut::new([4; 16], 8, [5; 32], [6; 32]);
    state.remember_source_cut(old_peer, old_cut);
    let start = state.transition_session(
        old_peer,
        SessionEvent::Trigger(SessionTrigger {
            kind: SessionSyncKind::Terminal,
            origin: SessionTriggerOrigin::External,
            desired_cut: None,
        }),
    );
    let old_wire = start
        .iter()
        .find_map(|effect| match effect {
            SessionEffect::StartSession { wire, .. } => Some(*wire),
            _ => None,
        })
        .expect("old incarnation reducer session");
    state.begin_terminal_client_cache(
        old_peer,
        StrictCatchupReason::SteadyState as i32,
        None,
        old_wire.nonce().get(),
        old_wire.cursor().value(),
        Duration::from_secs(30),
    );

    let restart_effects = state.restart_peer(2, 23);
    assert!(
        restart_effects.iter().any(
            |effect| matches!(effect, SessionEffect::CancelRetry { wire } if *wire == old_wire)
        )
    );
    assert!(
        restart_effects.iter().any(
            |effect| matches!(effect, SessionEffect::ReleaseBulk { wire } if *wire == old_wire)
        )
    );
    assert!(state.client(old_peer).is_none());
    assert!(!state.has_session_work(old_peer));
    assert!(!state.has_session_work(new_peer));
    assert_eq!(state.known_source_cut(new_peer), None);
    let (_, offered) = state
        .begin_client(
            new_peer,
            StrictCatchupReason::Admission as i32,
            Duration::from_secs(30),
        )
        .expect("replacement incarnation should start a fresh session");
    assert_eq!(offered, Some(old_cut));
    assert_eq!(state.known_source_cut(new_peer), None);

    // Fresh evidence from a restored responder may be below the offered
    // prior-incarnation cut. It replaces that untrusted baseline instead of
    // binding the stale higher generation to the new boot epoch.
    let restored_cut = TerminalCut::new([4; 16], 3, [7; 32], [8; 32]);
    state.remember_source_cut(new_peer, restored_cut);
    assert_eq!(state.known_source_cut(new_peer), Some(restored_cut));

    // A validated checkpoint from a different lineage replaces the offered
    // baseline instead of inheriting old-incarnation transfer state.
    let replacement_cut = TerminalCut::new([8; 16], 3, [9; 32], [10; 32]);
    state.remember_source_cut(new_peer, replacement_cut);
    assert_eq!(state.known_source_cut(new_peer), Some(replacement_cut));
}

#[tokio::test]
async fn production_catchup_decisions_cannot_fanout_or_dirty_the_owner_session() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    let peer = PeerIncarnation::new(2, 22);

    request_v3_terminal_sync(&rt, 2, StrictCatchupReason::TerminalFence).await;
    assert!(rt.v3_sync.lock().has_session_work(peer));
    net.drain_captures();
    net.drain_strict_send_observations();

    for sequence in 1..=32 {
        assert!(
            rt.apply_v3_catchup_terminal_state(peer, terminal_abort(sequence))
                .await
        );
    }

    assert!(rt.v3_sync.lock().has_session_work(peer));
    assert!(net.drain_captures().is_empty());
    assert!(net.drain_strict_send_observations().is_empty());

    // A delayed catchup duplicate remains an install/idempotency event. It
    // cannot allocate a continuation or emit transport work either.
    assert!(
        rt.apply_v3_catchup_terminal_state(peer, terminal_abort(1))
            .await
    );
    assert!(net.drain_captures().is_empty());
    assert!(net.drain_strict_send_observations().is_empty());
}

#[tokio::test]
async fn production_backpressure_replays_one_cached_page_without_branching_transfer() {
    let (source, net) = runtime(1, ReplicationConfig::default());
    assert!(source.apply_catchup_terminal_state(terminal_abort(1)).await);
    let peer = PeerIncarnation::new(2, 22);
    let request = initial_sync_request(&source, 71, 0, Bytes::from_static(&[0; 32])).await;

    net.script_bulk_send_outcomes([MockBulkSendOutcome::Backpressure]);
    recv_v3_terminal_sync_req(&source, 2, 22, request.clone()).await;

    let first = net
        .drain_strict_send_observations()
        .into_iter()
        .find(|observation| matches!(observation.body, StrictBody::TerminalSyncPage(_)))
        .expect("backpressured page attempt");
    assert_eq!(first.outcome, StrictSendOutcome::Backpressure);
    let StrictBody::TerminalSyncPage(first_page) = first.body else {
        unreachable!()
    };
    assert_ne!(first_page.transfer_id, 0);
    assert!(source.v3_sync.lock().has_session_work(peer));

    // The request retry is the delivery/loss signal available to this
    // request/response protocol. It must replay the cached bytes under the
    // same reducer-owned transfer rather than prepare another page.
    recv_v3_terminal_sync_req(&source, 2, 22, request).await;
    let replay = terminal_page(
        net.drain_captures()
            .into_iter()
            .find(|frame| {
                matches!(
                    frame,
                    CapturedFrame::StrictUnicast {
                        body: StrictBody::TerminalSyncPage(_),
                        ..
                    }
                )
            })
            .expect("cached page replay"),
    );
    assert_eq!(replay.transfer_id, first_page.transfer_id);
    assert_eq!(replay.request_nonce, first_page.request_nonce);
    assert_eq!(replay.cursor, first_page.cursor);
    assert_eq!(replay.next_cursor, first_page.next_cursor);
    assert!(source.v3_sync.lock().has_session_work(peer));
}

#[test]
fn wire_cut_rejects_an_all_zero_journal_lineage() {
    let invalid = crate::replications::proto::StrictTerminalCut {
        journal_id: Bytes::from_static(&[0; 16]),
        generation: 0,
        chain_digest: Bytes::from_static(&[0; 32]),
        terminal_set_digest: Bytes::from_static(&[0; 32]),
    };
    assert!(cut_from_wire(&invalid).is_none());
}

#[test]
fn probe_retries_are_suppressed_until_expiry_or_exact_cancellation() {
    let mut state = SyncV3State::default();
    let peer = PeerIncarnation::new(2, 22);
    let ttl = Duration::from_secs(30);

    let clock = state
        .record_clock_nonce(peer, ttl)
        .expect("initial clock nonce");
    assert_eq!(state.record_clock_nonce(peer, ttl), None);
    state.cancel_clock_nonce(peer, clock.saturating_add(1));
    assert_eq!(state.record_clock_nonce(peer, ttl), None);
    state.cancel_clock_nonce(peer, clock);
    let replacement_clock = state
        .record_clock_nonce(peer, ttl)
        .expect("clock nonce after exact cancellation");
    assert_ne!(replacement_clock, clock);

    let history = state
        .record_history_nonce(peer, StrictCatchupReason::Admission as i32, ttl)
        .expect("initial history nonce");
    assert_eq!(
        state.record_history_nonce(peer, StrictCatchupReason::Admission as i32, ttl),
        None,
        "periodic triggers must not retransmit an outstanding history request"
    );
    state.cancel_history_nonce(peer, history.saturating_add(1));
    assert_eq!(
        state.record_history_nonce(peer, StrictCatchupReason::Admission as i32, ttl),
        None,
        "a stale cancellation must not release history retry suppression"
    );

    state.expire(Instant::now() + ttl + Duration::from_millis(1));
    let replacement_history = state
        .record_history_nonce(peer, StrictCatchupReason::Admission as i32, ttl)
        .expect("history nonce after expiry");
    assert_ne!(replacement_history, history);
}

#[test]
fn history_election_does_not_overwrite_pending_terminal_fence_obligation() {
    let mut state = SyncV3State::default();
    let peer = PeerIncarnation::new(2, 22);
    let ttl = Duration::from_secs(30);
    let nonce = state
        .record_history_nonce(peer, StrictCatchupReason::TerminalFence as i32, ttl)
        .expect("terminal-fence probe");

    let promoted =
        state.record_history_nonce(peer, StrictCatchupReason::HistoryElection as i32, ttl);
    assert_eq!(promoted, None, "election must not re-enqueue the nonce");
    for _ in 0..100 {
        assert_eq!(
            state.record_history_nonce(peer, StrictCatchupReason::HistoryElection as i32, ttl),
            None,
            "repeated election triggers must not reset retry ownership"
        );
    }
    let accepted = state
        .accept_history_nonce(peer, nonce)
        .expect("correlated response");
    assert_eq!(
        accepted.reason(),
        StrictCatchupReason::TerminalFence as i32,
        "history election must not erase a higher-priority terminal repair"
    );
    assert!(accepted.election_pending());
}

#[test]
fn repository_gap_arriving_during_history_election_is_retained_as_an_obligation() {
    let mut state = SyncV3State::default();
    let peer = PeerIncarnation::new(2, 22);
    let ttl = Duration::from_secs(30);
    let nonce = state
        .record_history_nonce(peer, StrictCatchupReason::HistoryElection as i32, ttl)
        .expect("history-election probe");

    assert_eq!(
        state.record_history_nonce(peer, StrictCatchupReason::RepositoryGap as i32, ttl),
        None,
        "evidence must attach to the existing nonce without another send"
    );
    let accepted = state
        .accept_history_nonce(peer, nonce)
        .expect("correlated response");
    assert_eq!(
        accepted.reason(),
        StrictCatchupReason::HistoryElection as i32
    );
    assert_eq!(
        accepted.repair_reason(),
        Some(StrictCatchupReason::RepositoryGap as i32)
    );
}

#[test]
fn admission_probe_pair_is_independent_of_transfer_work_predicate() {
    let mut state = SyncV3State::default();
    let peer = PeerIncarnation::new(2, 22);
    let ttl = Duration::from_secs(30);

    assert!(
        state
            .record_history_nonce(peer, StrictCatchupReason::HistoryElection as i32, ttl)
            .is_some()
    );
    assert!(
        state.record_clock_nonce(peer, ttl).is_some(),
        "an outstanding history probe must not suppress admission clock evidence"
    );
    assert!(
        !state.has_periodic_work(peer),
        "bounded metadata probes are not operation-bearing transfer work"
    );

    assert!(
        state
            .begin_client(peer, StrictCatchupReason::Admission as i32, ttl)
            .is_some()
    );
    assert!(state.has_periodic_work(peer));
}

#[tokio::test]
async fn failed_probe_enqueue_keeps_fixed_ttl_retry_suppression() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    let peer = PeerIncarnation::new(2, 22);
    let ttl = Duration::from_secs(30);
    net.fail_strict_unicasts_to([2]);

    request_v3_clock_probe(&rt, 2, StrictCatchupReason::Admission).await;
    let failed_clock = net
        .drain_strict_send_observations()
        .into_iter()
        .find_map(|attempt| match attempt.body {
            StrictBody::ClockProbeReq(request) => Some(request.request_nonce),
            _ => None,
        })
        .expect("failed clock attempt");
    assert_eq!(rt.v3_sync.lock().record_clock_nonce(peer, ttl), None);
    rt.v3_sync.lock().cancel_clock_nonce(peer, failed_clock);

    request_v3_history_probe(&rt, 2, StrictCatchupReason::Admission).await;
    let failed_history = net
        .drain_strict_send_observations()
        .into_iter()
        .find_map(|attempt| match attempt.body {
            StrictBody::HistoryProbeReq(request) => Some(request.request_nonce),
            _ => None,
        })
        .expect("failed history attempt");
    assert_eq!(
        rt.v3_sync
            .lock()
            .record_history_nonce(peer, StrictCatchupReason::Admission as i32, ttl),
        None
    );
    rt.v3_sync.lock().cancel_history_nonce(peer, failed_history);
}

#[tokio::test]
async fn lost_clock_probe_retries_one_nonce_while_terminal_transfer_remains_active() {
    let retry_delay = Duration::from_millis(20);
    let config = ReplicationConfig::default()
        .with_bulk_retry_delay(retry_delay)
        .with_strict_bulk_retry_max_delay(retry_delay.saturating_mul(2))
        .with_strict_bulk_retry_jitter_pct(0)
        .with_pending_propose_ttl(Duration::from_secs(2));
    let (rt, net) = runtime(1, config);
    let peer = PeerIncarnation::new(2, 22);
    assert!(
        rt.v3_sync
            .lock()
            .begin_client(
                peer,
                StrictCatchupReason::TerminalFence as i32,
                rt.cfg.pending_propose_ttl(),
            )
            .is_some()
    );
    net.fail_strict_unicasts_to([2]);

    assert!(!request_v3_clock_probe(&rt, 2, StrictCatchupReason::DeliveryWatermark).await);
    let first = net
        .drain_strict_send_observations()
        .into_iter()
        .find_map(|attempt| match attempt.body {
            StrictBody::ClockProbeReq(request) => Some(request),
            _ => None,
        })
        .expect("initial failed clock probe");
    assert!(rt.v3_sync.lock().client(peer).is_some());

    assert!(!request_v3_clock_probe(&rt, 2, StrictCatchupReason::DeliveryWatermark).await);
    assert!(net.drain_strict_send_observations().is_empty());
    retry_v3_terminal_transmissions(&rt).await;
    assert!(
        net.drain_strict_send_observations().is_empty(),
        "retry must wait for its initial backoff"
    );

    tokio::time::sleep(retry_delay + Duration::from_millis(10)).await;
    retry_v3_terminal_transmissions(&rt).await;
    let retry = net
        .drain_strict_send_observations()
        .into_iter()
        .find_map(|attempt| match attempt.body {
            StrictBody::ClockProbeReq(request) => Some(request),
            _ => None,
        })
        .expect("clock probe retry after lost enqueue");
    assert_eq!(retry, first, "retry must preserve the correlated identity");
    assert!(rt.v3_sync.lock().client(peer).is_some());

    retry_v3_terminal_transmissions(&rt).await;
    assert!(
        net.drain_strict_send_observations().is_empty(),
        "retry must advance to a bounded later deadline"
    );
}

#[tokio::test]
async fn equal_cut_history_election_response_also_satisfies_admission_history() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    rt.seed_membership_snapshot([MemberIncarnation::new(1, 11), MemberIncarnation::new(2, 22)]);
    assert!(!rt.peer_incarnation_is_admitted(2, 22));

    request_v3_clock_probe(&rt, 2, StrictCatchupReason::Admission).await;
    let clock_request = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::ClockProbeReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("admission clock request");
    recv_v3_clock_probe_resp(
        &rt,
        2,
        22,
        StrictClockProbeResp {
            responder_node: 2,
            expected_requester_boot_epoch: 11,
            request_nonce: clock_request.request_nonce,
            src_clock: 1,
            reason: StrictCatchupReason::Admission as i32,
        },
    );
    assert!(!rt.peer_incarnation_is_admitted(2, 22));

    request_v3_history_probe(&rt, 2, StrictCatchupReason::HistoryElection).await;
    let history_request = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::HistoryProbeReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("history-election request");
    let local_cut = cut_to_wire(rt.terminal_journal.lock().await.terminal_cut());
    recv_v3_history_probe_resp(
        &rt,
        2,
        22,
        StrictHistoryProbeResp {
            responder_node: 2,
            expected_requester_boot_epoch: 11,
            request_nonce: history_request.request_nonce,
            repository_version: 0,
            history_freshness: 0,
            runtime_started_at: 22,
            history_node: 2,
            terminal_cut: Some(local_cut),
            reason: StrictCatchupReason::HistoryElection as i32,
        },
    )
    .await;

    assert!(
        rt.peer_incarnation_is_admitted(2, 22),
        "equal-cut election metadata is independently sufficient history evidence"
    );
    assert!(
        net.drain_captures().into_iter().all(|frame| !matches!(
            frame,
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncPage(_),
                ..
            }
        )),
        "equal-cut admission must not start an operation-bearing transfer"
    );
}

#[tokio::test]
async fn empty_remote_terminal_cut_cannot_admit_peer_missing_local_abort_fence() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    rt.terminal_journal
        .lock()
        .await
        .upsert_abort_decision((1, 99), 1)
        .expect("local abort fence");
    rt.seed_membership_snapshot([MemberIncarnation::new(1, 11), MemberIncarnation::new(2, 22)]);
    assert!(!rt.peer_incarnation_is_admitted(2, 22));

    request_v3_clock_probe(&rt, 2, StrictCatchupReason::Admission).await;
    let clock_request = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::ClockProbeReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("admission clock request");
    recv_v3_clock_probe_resp(
        &rt,
        2,
        22,
        StrictClockProbeResp {
            responder_node: 2,
            expected_requester_boot_epoch: 11,
            request_nonce: clock_request.request_nonce,
            src_clock: 1,
            reason: StrictCatchupReason::Admission as i32,
        },
    );

    request_v3_history_probe(&rt, 2, StrictCatchupReason::Admission).await;
    let history_request = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::HistoryProbeReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("admission history request");
    let empty_remote_cut = TerminalJournal::in_memory("empty-remote").terminal_cut();
    recv_v3_history_probe_resp(
        &rt,
        2,
        22,
        StrictHistoryProbeResp {
            responder_node: 2,
            expected_requester_boot_epoch: 11,
            request_nonce: history_request.request_nonce,
            repository_version: 0,
            history_freshness: 0,
            runtime_started_at: 22,
            history_node: 2,
            terminal_cut: Some(cut_to_wire(empty_remote_cut)),
            reason: StrictCatchupReason::Admission as i32,
        },
    )
    .await;

    assert!(
        !rt.peer_incarnation_is_admitted(2, 22),
        "an empty remote cut does not prove that the peer covers the local abort fence"
    );
}

#[tokio::test]
async fn delayed_election_response_with_divergent_cut_continues_admission_sync() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    rt.seed_membership_snapshot([MemberIncarnation::new(1, 11), MemberIncarnation::new(2, 22)]);
    assert!(!rt.peer_incarnation_is_admitted(2, 22));

    request_v3_history_probe(&rt, 2, StrictCatchupReason::HistoryElection).await;
    let history_request = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::HistoryProbeReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("history-election request");

    // `runtime()` deliberately leaves the election collector idle. This
    // models a promoted admission nonce whose election completed before the
    // peer's response arrived. A divergent cut must continue through the
    // admission terminal-sync path instead of being dropped by the closed
    // collector.
    let remote_cut = crate::replications::proto::StrictTerminalCut {
        journal_id: Bytes::from_static(&[7; 16]),
        generation: 1,
        chain_digest: Bytes::from_static(&[8; 32]),
        terminal_set_digest: Bytes::from_static(&[9; 32]),
    };
    recv_v3_history_probe_resp(
        &rt,
        2,
        22,
        StrictHistoryProbeResp {
            responder_node: 2,
            expected_requester_boot_epoch: 11,
            request_nonce: history_request.request_nonce,
            repository_version: 0,
            history_freshness: 0,
            runtime_started_at: 22,
            history_node: 2,
            terminal_cut: Some(remote_cut),
            reason: StrictCatchupReason::HistoryElection as i32,
        },
    )
    .await;

    assert!(net.drain_captures().into_iter().any(|frame| matches!(
        frame,
        CapturedFrame::StrictUnicast {
            dst: 2,
            body: StrictBody::TerminalSyncReq(_),
            ..
        }
    )));
}
