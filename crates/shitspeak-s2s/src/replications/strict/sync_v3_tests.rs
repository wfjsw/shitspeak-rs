//! Focused cumulative-repair tests for supported strict participants.
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
    StrictReplicable,
    catchup::{
        apply_response, recv_v3_clock_probe_req, recv_v3_clock_probe_resp,
        recv_v3_history_probe_resp, recv_v3_terminal_sync_ack, recv_v3_terminal_sync_page,
        recv_v3_terminal_sync_req, register_v3_clock_probe_retry_if_current,
        register_v3_history_probe_retry_if_current, request_v3_clock_probe,
        request_v3_history_probe, request_v3_terminal_sync, request_v3_terminal_sync_toward,
        respond_to_request, resume_deferred_v3_admissions, retry_v3_terminal_transmissions,
        send_v3_metadata_control,
    },
    runtime::{
        HistoryElectionSnapshotRequest, HistoryRank, STRICT_V3_CONTROL_MAX_ENCODED_BYTES,
        StrictRuntime, is_v3_metadata_control, make_op_id,
    },
    session_reducer::{
        Cursor as SessionCursor, CursorKind as SessionCursorKind, Cut as SessionCut,
        Effect as SessionEffect, Event as SessionEvent, PeerEpoch as SessionPeerEpoch,
        ProbeKind as SessionProbeKind, SyncKind as SessionSyncKind,
        TransferId as SessionTransferId, Trigger as SessionTrigger,
        TriggerOrigin as SessionTriggerOrigin, WireIdentity as SessionWireIdentity,
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
    metrics::{CatchupMode, CatchupPhase, CatchupReason},
    proto::{
        StrictBody, StrictCatchupReason, StrictCatchupReq, StrictCatchupResp, StrictClockProbeReq,
        StrictClockProbeResp, StrictDecisionAbort, StrictDecisionCommit, StrictFrozenTarget,
        StrictHistoryProbeReq, StrictHistoryProbeResp, StrictHistoryTransferReq,
        StrictHistoryTransferResp, StrictTerminalOutcome, StrictTerminalPageKind,
        StrictTerminalState, StrictTerminalSyncAck, StrictTerminalSyncPage, StrictTerminalSyncReq,
        StrictTerminalSyncStatus,
    },
    protocol::{
        STRICT_PROTOCOL_VERSION_V2, STRICT_PROTOCOL_VERSION_V4, STRICT_PROTOCOL_VERSION_V5,
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
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V4);
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V4));
    net.set_peer_strict_replication_protocol_version(
        if self_id == 1 { 2 } else { 1 },
        STRICT_PROTOCOL_VERSION_V4,
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

#[test]
fn only_the_reserved_empty_history_response_shape_is_control_metadata() {
    let confirmation = crate::replications::proto::StrictCatchupResp {
        history_transfer: Some(StrictHistoryTransferResp {
            request_nonce: 7,
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(is_v3_metadata_control(&StrictBody::CatchupResp(
        confirmation.clone()
    )));
    assert!(!is_v3_metadata_control(&StrictBody::CatchupResp(
        crate::replications::proto::StrictCatchupResp {
            history_node: 2,
            ..confirmation
        }
    )));
}

#[tokio::test]
async fn stalled_v3_election_resumes_ranked_checkpoint_instead_of_legacy_snapshot() {
    let (sink, net) = runtime(2, ReplicationConfig::default());
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V5);
    let peer = PeerIncarnation::new(1, 11);
    let source_cut = TerminalCut::new([1; 16], 7, [2; 32], [3; 32]);
    let rank = HistoryRank {
        version: 10,
        freshness: 20,
        runtime_started_at: 11,
        node_id: 1,
        terminal_repository_base_version: 10,
    };
    {
        let mut state = sink.state.lock();
        state.request_history_election();
        state.begin_history_election([1, 9]);
    }
    assert!(
        sink.record_v3_history_election_rank(peer, rank, source_cut, true)
            .await
            .is_none(),
        "the silent peer must keep the election probe pending",
    );

    let request = sink
        .state
        .lock()
        .conclude_stalled_history_election()
        .expect("best responsive rank");
    sink.send_history_snapshot_request(request)
        .await
        .expect("stalled election dispatch");

    let frames = net.drain_captures();
    assert!(
        frames.iter().any(|frame| matches!(
            frame,
            CapturedFrame::StrictUnicast {
                dst: 1,
                body: StrictBody::TerminalSyncReq(request),
                ..
            } if request.expected_cursor == 0
        )),
        "a stalled V3 winner must resume the elected terminal-checkpoint protocol: {frames:?}",
    );
    assert!(
        !frames.iter().any(|frame| matches!(
            frame,
            CapturedFrame::StrictUnicast {
                body: StrictBody::CatchupReq(request),
                ..
            } if request.force_snapshot && request.history_transfer.is_none()
        )),
        "the legacy snapshot path applies checkpoint states per operation and can hit retired floors",
    );
    assert_eq!(
        sink.v3_history
            .lock()
            .pending_after_terminal(peer)
            .expect("elected terminal prerequisite")
            .reason(),
        StrictCatchupReason::HistoryElection,
    );
}

#[tokio::test]
async fn stale_v3_election_incarnation_rearms_without_legacy_snapshot() {
    let (sink, net) = runtime(2, ReplicationConfig::default());
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V5);
    let peer = PeerIncarnation::new(1, 11);
    let source_cut = TerminalCut::new([1; 16], 7, [2; 32], [3; 32]);
    let rank = HistoryRank {
        version: 10,
        freshness: 20,
        runtime_started_at: 11,
        node_id: 1,
        terminal_repository_base_version: 10,
    };
    sink.v3_history
        .lock()
        .record_probe_candidate(peer, rank, source_cut);
    let request = HistoryElectionSnapshotRequest::new(1, rank);

    net.set_epoch(1, 12);
    sink.send_history_snapshot_request(request)
        .await
        .expect("stale election dispatch");

    let frames = net.drain_captures();
    assert!(
        !frames.iter().any(|frame| matches!(
            frame,
            CapturedFrame::StrictUnicast {
                body: StrictBody::CatchupReq(request),
                ..
            } if request.force_snapshot && request.history_transfer.is_none()
        )),
        "a restarted V3 winner must be re-probed, never sent a legacy snapshot request: {frames:?}",
    );
    assert!(
        sink.state.lock().can_start_history_election(),
        "the stale exact-incarnation candidate must rearm the election",
    );
}

#[tokio::test]
async fn lost_history_final_ack_confirmation_is_replayed_and_stops_retrying() {
    let retry_delay = Duration::from_millis(20);
    let config = ReplicationConfig::default()
        .with_bulk_retry_delay(retry_delay)
        .with_strict_bulk_retry_max_delay(retry_delay.saturating_mul(2))
        .with_strict_bulk_retry_jitter_pct(0)
        .with_pending_propose_ttl(Duration::from_secs(2));
    let (sink, sink_net) = runtime(1, config.clone());
    let (source, source_net) = runtime(2, config);
    let peer = PeerIncarnation::new(2, 22);
    let transfer = sink
        .v3_history
        .lock()
        .begin_transfer(
            peer,
            0,
            0,
            StrictCatchupReason::RepositoryGap,
            sink.cfg.pending_propose_ttl(),
            false,
            StrictCatchupReason::RepositoryGap,
        )
        .expect("history transfer")
        .into_parts()
        .0;
    let request = StrictCatchupReq {
        src_node: 1,
        since_version: 0,
        chunk_token: 0,
        force_snapshot: false,
        history_probe_only: false,
        terminal_state_cursor: u64::MAX,
        terminal_decision_generation: 0,
        snapshot_transfer_id: 0,
        snapshot_chunk_cursor: 0,
        history_transfer: Some(transfer),
    };

    respond_to_request(&source, 1, request).await;
    let response = source_net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::CatchupResp(response),
                ..
            } => Some(response),
            _ => None,
        })
        .expect("history response");
    apply_response(&sink, 2, response).await;
    let final_ack = sink_net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::CatchupReq(request),
                ..
            } if request
                .history_transfer
                .as_ref()
                .is_some_and(|transfer| transfer.final_ack) =>
            {
                Some(request)
            }
            _ => None,
        })
        .expect("history final ACK");

    respond_to_request(&source, 1, final_ack.clone()).await;
    let first_confirmation = source_net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::CatchupResp(response),
                ..
            } => Some(response),
            _ => None,
        })
        .expect("correlated final ACK confirmation");
    // Drop the first confirmation. The requester must retry the exact final
    // ACK and the responder must replay the exact confirmation rather than
    // treating its acknowledged page tombstone as an unrelated duplicate.
    tokio::time::sleep(retry_delay + Duration::from_millis(10)).await;
    retry_v3_terminal_transmissions(&sink).await;
    let retried_final_ack = sink_net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::CatchupReq(request),
                ..
            } if request
                .history_transfer
                .as_ref()
                .is_some_and(|transfer| transfer.final_ack) =>
            {
                Some(request)
            }
            _ => None,
        })
        .expect("history final ACK retry after lost confirmation");
    assert_eq!(retried_final_ack, final_ack);

    respond_to_request(&source, 1, retried_final_ack).await;
    let replayed_confirmation = source_net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::CatchupResp(response),
                ..
            } => Some(response),
            _ => None,
        })
        .expect("replayed correlated final ACK confirmation");
    assert_eq!(replayed_confirmation, first_confirmation);
    apply_response(&sink, 2, replayed_confirmation).await;

    tokio::time::sleep(retry_delay.saturating_mul(2) + Duration::from_millis(10)).await;
    retry_v3_terminal_transmissions(&sink).await;
    assert!(
        sink_net.drain_captures().into_iter().all(|frame| !matches!(
            frame,
            CapturedFrame::StrictUnicast {
                body: StrictBody::CatchupReq(StrictCatchupReq {
                    history_transfer: Some(StrictHistoryTransferReq {
                        final_ack: true,
                        ..
                    }),
                    ..
                }),
                ..
            }
        )),
        "a delivered and confirmed history final ACK must not retry"
    );
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

#[tokio::test]
async fn crossed_terminal_resume_is_backpressured_instead_of_cursor_mismatch_looping() {
    let retry_delay = Duration::from_millis(20);
    let ttl = Duration::from_millis(400);
    let config = ReplicationConfig::default()
        .with_strict_max_catchup_ops(32)
        .with_bulk_retry_delay(retry_delay)
        .with_strict_bulk_retry_max_delay(retry_delay.saturating_mul(2))
        .with_strict_bulk_retry_jitter_pct(0)
        .with_pending_propose_ttl(ttl);
    let (lower, lower_net) = runtime(1, config.clone());
    let (higher, higher_net) = runtime(2, config);
    lower
        .terminal_journal
        .lock()
        .await
        .upsert_abort_decision(make_op_id(1, 11, 1), 1)
        .expect("lower-node terminal abort");

    // Keep the crossed initial request identities distinct. Production peers
    // commonly have different reducer nonce histories; a completed reducer
    // probe advances that nonce without leaving a terminal tombstone.
    let peer = PeerIncarnation::new(1, 11);
    let probe_wire = higher
        .v3_sync
        .lock()
        .transition_session(
            peer,
            SessionEvent::StartProbe {
                kind: SessionProbeKind::Clock,
            },
        )
        .into_iter()
        .find_map(|effect| match effect {
            SessionEffect::SendRequest { wire, .. } => Some(wire),
            _ => None,
        })
        .expect("higher-node reducer nonce primer");
    higher.v3_sync.lock().transition_session(
        peer,
        SessionEvent::ProbeResponse {
            epoch: SessionPeerEpoch::new(11),
            nonce: probe_wire.nonce(),
        },
    );

    request_v3_terminal_sync(&lower, 2, StrictCatchupReason::TerminalFence).await;
    let lower_initial = lower_net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("lower-node initial request");
    request_v3_terminal_sync(&higher, 1, StrictCatchupReason::TerminalFence).await;
    let higher_initial = higher_net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("higher-node crossed initial request");

    recv_v3_terminal_sync_req(&higher, 1, 11, lower_initial).await;
    let winning_page = higher_net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncPage(page),
                ..
            } => Some(page),
            _ => None,
        })
        .expect("higher node must serve the winning lower-node direction");
    recv_v3_terminal_sync_page(&lower, 2, 22, winning_page).await;
    let winning_ack = lower_net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncAck(ack),
                ..
            } => Some(ack),
            _ => None,
        })
        .expect("winning terminal ACK");
    recv_v3_terminal_sync_ack(&higher, 1, 11, winning_ack).await;
    let mut higher_frames = higher_net.drain_captures();
    let confirmation = higher_frames
        .iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncAck(ack),
                ..
            } => Some(ack.clone()),
            _ => None,
        })
        .expect("winning terminal ACK confirmation");
    let resumed = higher_frames
        .drain(..)
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("higher-node deferred direction must resume");
    assert_ne!(resumed.request_nonce, higher_initial.request_nonce);

    recv_v3_terminal_sync_ack(&lower, 2, 22, confirmation).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    recv_v3_terminal_sync_req(&lower, 2, 22, higher_initial).await;
    let cached_page = lower_net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncPage(page),
                ..
            } => Some(page),
            _ => None,
        })
        .expect("lower node must cache the delayed crossed request");
    assert_eq!(cached_page.status, StrictTerminalSyncStatus::Ok as i32);

    recv_v3_terminal_sync_req(&lower, 2, 22, resumed.clone()).await;
    let deflection = lower_net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncPage(page),
                ..
            } => Some(page),
            _ => None,
        })
        .expect("active responder must deflect the unmatched resumed request");
    assert_eq!(
        deflection.status,
        StrictTerminalSyncStatus::ResourceLimit as i32,
        "an unmatched initial request must back off without entering the CursorMismatch retry loop"
    );
    recv_v3_terminal_sync_page(&higher, 1, 11, deflection).await;
    let client = higher
        .v3_sync
        .lock()
        .client(PeerIncarnation::new(1, 11))
        .cloned()
        .expect("advisory deflection must retain the resumed client");
    assert_eq!(client.pending_nonce(), resumed.request_nonce);

    // The original resumed-client lease expires before the retained responder.
    // A correlated collision response must extend that exact client and retry
    // without resetting its nonce or backoff.
    tokio::time::sleep(Duration::from_millis(250)).await;
    retry_v3_terminal_transmissions(&higher).await;
    let retained_retry = higher_net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("collision response must keep the exact retry alive");
    assert_eq!(retained_retry, resumed);
    recv_v3_terminal_sync_req(&lower, 2, 22, retained_retry).await;
    let second_deflection = lower_net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncPage(page),
                ..
            } => Some(page),
            _ => None,
        })
        .expect("retained responder must keep deflecting until expiry");
    assert_eq!(
        second_deflection.status,
        StrictTerminalSyncStatus::ResourceLimit as i32
    );
    recv_v3_terminal_sync_page(&higher, 1, 11, second_deflection).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    retry_v3_terminal_transmissions(&higher).await;
    let post_expiry_retry = higher_net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("exact retry must outlive the stale responder");
    assert_eq!(post_expiry_retry, resumed);
    recv_v3_terminal_sync_req(&lower, 2, 22, post_expiry_retry).await;
    let recovery_page = lower_net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncPage(page),
                ..
            } => Some(page),
            _ => None,
        })
        .expect("request must proceed after the stale responder expires");
    assert_eq!(recovery_page.status, StrictTerminalSyncStatus::Ok as i32);
    recv_v3_terminal_sync_page(&higher, 1, 11, recovery_page).await;
    let recovery_ack = higher_net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncAck(ack),
                ..
            } => Some(ack),
            _ => None,
        })
        .expect("recovered terminal transfer ACK");
    recv_v3_terminal_sync_ack(&lower, 2, 22, recovery_ack).await;
    let recovery_confirmation = lower_net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncAck(ack),
                ..
            } => Some(ack),
            _ => None,
        })
        .expect("recovered terminal ACK confirmation");
    recv_v3_terminal_sync_ack(&higher, 1, 11, recovery_confirmation).await;
    let higher_cut = higher.terminal_journal.lock().await.terminal_cut();
    let lower_cut = lower.terminal_journal.lock().await.terminal_cut();
    assert_eq!(higher_cut.generation(), lower_cut.generation());
    assert_eq!(
        higher_cut.terminal_set_digest(),
        lower_cut.terminal_set_digest()
    );
    assert!(
        higher
            .v3_sync
            .lock()
            .client(PeerIncarnation::new(1, 11))
            .is_none()
    );
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
            requester_clock: u64::MAX,
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
            terminal_repository_base_version: 0,
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
async fn satisfied_terminal_cut_latches_repository_base_before_snapshot_fetch() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V5);
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V5));
    net.set_peer_strict_replication_protocol_version(2, STRICT_PROTOCOL_VERSION_V5);
    let peer = PeerIncarnation::new(2, 22);
    let source_cut = rt.terminal_journal.lock().await.terminal_cut();
    {
        let mut state = rt.state.lock();
        state.request_history_election();
        state.begin_history_election([2]);
    }

    request_v3_history_probe(&rt, 2, StrictCatchupReason::HistoryElection).await;
    let request_nonce = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                dst: 2,
                body: StrictBody::HistoryProbeReq(request),
                ..
            } => Some(request.request_nonce),
            _ => None,
        })
        .expect("history probe request");

    recv_v3_history_probe_resp(
        &rt,
        2,
        22,
        StrictHistoryProbeResp {
            responder_node: 2,
            expected_requester_boot_epoch: 11,
            request_nonce,
            repository_version: 9_525,
            // Pre-field V5 peers decode with zero here. Their complete head
            // is the conservative base when it exceeds the terminal lineage.
            terminal_repository_base_version: 0,
            history_freshness: 9_525,
            runtime_started_at: 22,
            history_node: 2,
            terminal_cut: Some(cut_to_wire(source_cut)),
            reason: StrictCatchupReason::HistoryElection as i32,
        },
    )
    .await;

    assert!(
        rt.repository_base_required(),
        "an already-satisfied terminal cut must not bypass the repository-base fence"
    );
    assert!(rt.state.lock().can_bootstrap_catchup());
    assert!(
        rt.v3_sync
            .lock()
            .known_source_cut(peer)
            .is_some_and(|known| known == source_cut)
    );
    assert!(net.drain_captures().into_iter().any(|frame| matches!(
        frame,
        CapturedFrame::StrictUnicast {
            dst: 2,
            body: StrictBody::CatchupReq(StrictCatchupReq {
                force_snapshot: true,
                ..
            }),
            ..
        }
    )));
}

#[tokio::test]
async fn abort_heavy_terminal_cut_still_latches_legacy_repository_base() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    let source_cut = TerminalCut::new([2; 16], 10_000, [2; 32], [3; 32]);
    {
        let mut state = rt.state.lock();
        state.request_history_election();
        state.begin_history_election([2]);
    }

    request_v3_history_probe(&rt, 2, StrictCatchupReason::HistoryElection).await;
    let request_nonce = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                dst: 2,
                body: StrictBody::HistoryProbeReq(request),
                ..
            } => Some(request.request_nonce),
            _ => None,
        })
        .expect("history probe request");

    recv_v3_history_probe_resp(
        &rt,
        2,
        22,
        StrictHistoryProbeResp {
            responder_node: 2,
            expected_requester_boot_epoch: 11,
            request_nonce,
            repository_version: 9_525,
            terminal_repository_base_version: 0,
            history_freshness: 9_525,
            runtime_started_at: 22,
            history_node: 2,
            terminal_cut: Some(cut_to_wire(source_cut)),
            reason: StrictCatchupReason::HistoryElection as i32,
        },
    )
    .await;

    assert!(
        rt.repository_base_required(),
        "an omitted V5 base field must conservatively require the source head even when terminal generation is higher"
    );
}

#[tokio::test]
async fn newer_admission_probe_rearms_election_without_reciprocal_gap_request() {
    let (rt, net) = runtime(1, ReplicationConfig::default());

    respond_to_request(
        &rt,
        2,
        StrictCatchupReq {
            src_node: 2,
            since_version: 9_525,
            chunk_token: 9_525,
            force_snapshot: false,
            history_probe_only: true,
            terminal_state_cursor: u64::MAX,
            terminal_decision_generation: 0,
            snapshot_transfer_id: 0,
            snapshot_chunk_cursor: 0,
            history_transfer: None,
        },
    )
    .await;

    assert!(rt.state.lock().history_election_pending());
    assert!(
        !net.drain_captures().into_iter().any(|frame| matches!(
            frame,
            CapturedFrame::StrictUnicast {
                body: StrictBody::CatchupReq(StrictCatchupReq {
                    history_probe_only: false,
                    ..
                }),
                ..
            }
        )),
        "the ranked history election owns repair; a reciprocal legacy gap request duplicates it"
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
async fn foreign_lineage_terminal_fence_never_starts_terminal_sync_toward_the_peer() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    let peer = PeerIncarnation::new(2, 22);
    // A partitioned minority checkpoint mints a fresh journal id at
    // generation zero with an empty chain digest and its own terminal-set
    // digest: the wire-valid foreign lineage that used to fall through to a
    // per-operation terminal sync (endless wrong-direction catchup).
    let foreign_cut = TerminalCut::new([0xEE; 16], 0, [0; 32], [0xCC; 32]);
    let metadata = rt.repo.history_metadata();
    assert_ne!(
        foreign_cut.journal_id(),
        rt.terminal_journal.lock().await.terminal_cut().journal_id(),
        "fixture must model a fresh divergent lineage"
    );

    request_v3_history_probe(&rt, 2, StrictCatchupReason::TerminalFence).await;
    let request_nonce = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                dst: 2,
                body: StrictBody::HistoryProbeReq(request),
                ..
            } => Some(request.request_nonce),
            _ => None,
        })
        .expect("terminal-fence history probe request");

    // Majority side: the peer is not ahead, so the foreign lineage must be
    // dropped entirely instead of being adopted through terminal sync.
    recv_v3_history_probe_resp(
        &rt,
        2,
        22,
        StrictHistoryProbeResp {
            responder_node: 2,
            expected_requester_boot_epoch: 11,
            request_nonce,
            repository_version: metadata.version,
            terminal_repository_base_version: 0,
            history_freshness: metadata.freshness,
            runtime_started_at: 22,
            history_node: 2,
            terminal_cut: Some(cut_to_wire(foreign_cut)),
            reason: StrictCatchupReason::TerminalFence as i32,
        },
    )
    .await;

    let captures = net.drain_captures();
    assert!(
        !captures.iter().any(|frame| matches!(
            frame,
            CapturedFrame::StrictUnicast {
                dst: 2,
                body: StrictBody::TerminalSyncReq(_),
                ..
            }
        )),
        "a rank-behind foreign lineage must never be adopted through per-operation terminal sync"
    );
    assert!(
        !rt.state.lock().history_election_blocks_steady_state(),
        "a rank-behind foreign lineage must not re-arm the election on the majority side"
    );
    assert!(
        rt.v3_sync
            .lock()
            .known_source_cut(peer)
            .is_none_or(|known| known.journal_id() != foreign_cut.journal_id()),
        "the foreign lineage must not be remembered as a locally known source cut"
    );

    // Minority side: the same foreign lineage from an ahead peer must promote
    // the ranked election (never a terminal sync) so the divergent node pulls
    // the majority's elected checkpoint.
    request_v3_history_probe(&rt, 2, StrictCatchupReason::TerminalFence).await;
    let request_nonce = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                dst: 2,
                body: StrictBody::HistoryProbeReq(request),
                ..
            } => Some(request.request_nonce),
            _ => None,
        })
        .expect("second terminal-fence history probe request");

    recv_v3_history_probe_resp(
        &rt,
        2,
        22,
        StrictHistoryProbeResp {
            responder_node: 2,
            expected_requester_boot_epoch: 11,
            request_nonce,
            repository_version: metadata.version,
            terminal_repository_base_version: 0,
            history_freshness: metadata.freshness.saturating_add(1),
            runtime_started_at: 22,
            history_node: 2,
            terminal_cut: Some(cut_to_wire(foreign_cut)),
            reason: StrictCatchupReason::TerminalFence as i32,
        },
    )
    .await;

    let captures = net.drain_captures();
    assert!(
        !captures.iter().any(|frame| matches!(
            frame,
            CapturedFrame::StrictUnicast {
                dst: 2,
                body: StrictBody::TerminalSyncReq(_),
                ..
            }
        )),
        "an ahead foreign lineage must be elected, never per-operation terminal synced"
    );
    assert!(
        rt.state.lock().history_election_blocks_steady_state(),
        "an ahead foreign lineage must promote the ranked election"
    );
}

#[tokio::test]
async fn equal_history_empty_foreign_lineage_cannot_fence_a_complete_donor() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    {
        let mut journal = rt.terminal_journal.lock().await;
        journal
            .upsert_abort_decision((1, 1), 1)
            .expect("local terminal decision");
    }
    let local_cut = rt.terminal_journal.lock().await.terminal_cut();
    assert!(
        local_cut.generation() > 0,
        "fixture must model the complete majority lineage"
    );
    let empty_foreign_cut = TerminalJournal::in_memory("empty-foreign").terminal_cut();
    let metadata = rt.repo.history_metadata();
    {
        let mut state = rt.state.lock();
        state.request_history_election();
        state.begin_history_election([2]);
    }

    request_v3_history_probe(&rt, 2, StrictCatchupReason::HistoryElection).await;
    let request_nonce = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                dst: 2,
                body: StrictBody::HistoryProbeReq(request),
                ..
            } => Some(request.request_nonce),
            _ => None,
        })
        .expect("history-election probe request");

    recv_v3_history_probe_resp(
        &rt,
        2,
        22,
        StrictHistoryProbeResp {
            responder_node: 2,
            expected_requester_boot_epoch: 11,
            request_nonce,
            repository_version: metadata.version,
            terminal_repository_base_version: metadata.version,
            history_freshness: metadata.freshness,
            // This peer wins the old repository-only rank through the stable
            // runtime tie-breaker despite having an empty replacement journal.
            runtime_started_at: 1,
            history_node: 2,
            terminal_cut: Some(cut_to_wire(empty_foreign_cut)),
            reason: StrictCatchupReason::HistoryElection as i32,
        },
    )
    .await;

    assert!(
        !rt.repository_base_required(),
        "an equal-history empty journal must not poison a complete snapshot donor"
    );
    assert!(
        rt.begin_snapshot_capture().is_some(),
        "the complete node must remain available as a snapshot donor"
    );
    assert!(
        !rt.state.lock().history_election_blocks_steady_state(),
        "the complete local terminal lineage must win the equal-history election"
    );
    assert!(
        !net.drain_captures().into_iter().any(|frame| matches!(
            frame,
            CapturedFrame::StrictUnicast {
                dst: 2,
                body: StrictBody::TerminalSyncReq(_),
                ..
            }
        )),
        "the empty foreign checkpoint must not start replacement synchronization"
    );
}

#[tokio::test]
async fn equal_history_populated_lineage_beats_empty_lineage_in_any_response_order() {
    for populated_first in [true, false] {
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_epoch(1, 11);
        net.set_epoch(2, 22);
        net.set_epoch(3, 33);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            11,
            "channels".to_owned(),
            net,
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        rt.finish_history_election_for_test();
        let metadata = rt.repo.history_metadata();
        let mut populated_journal = TerminalJournal::in_memory("populated-remote");
        populated_journal
            .upsert_abort_decision((2, 1), 1)
            .expect("remote terminal decision");
        let populated_cut = populated_journal.terminal_cut();
        let empty_cut = TerminalJournal::in_memory("empty-remote").terminal_cut();
        let populated_rank = HistoryRank {
            version: metadata.version,
            freshness: metadata.freshness,
            // The complete source deliberately loses the repository-only
            // runtime tie-breaker to both local and the empty source.
            runtime_started_at: 99,
            node_id: 2,
            terminal_repository_base_version: metadata.version,
        };
        let empty_rank = HistoryRank {
            runtime_started_at: 1,
            node_id: 3,
            ..populated_rank
        };
        {
            let mut state = rt.state.lock();
            state.request_history_election();
            state.begin_history_election([2, 3]);
        }

        let selected = if populated_first {
            assert!(
                rt.record_v3_history_election_rank(
                    PeerIncarnation::new(2, 22),
                    populated_rank,
                    populated_cut,
                    true,
                )
                .await
                .is_none()
            );
            rt.record_v3_history_election_rank(
                PeerIncarnation::new(3, 33),
                empty_rank,
                empty_cut,
                true,
            )
            .await
        } else {
            assert!(
                rt.record_v3_history_election_rank(
                    PeerIncarnation::new(3, 33),
                    empty_rank,
                    empty_cut,
                    true,
                )
                .await
                .is_none()
            );
            rt.record_v3_history_election_rank(
                PeerIncarnation::new(2, 22),
                populated_rank,
                populated_cut,
                true,
            )
            .await
        }
        .expect("one remote source must win the completed election");

        assert_eq!(selected.peer(), PeerIncarnation::new(2, 22));
        assert_eq!(selected.source_cut(), populated_cut);
    }
}

#[tokio::test]
async fn election_revalidates_empty_winner_after_local_terminal_state_becomes_populated() {
    let net = MockNet::new(1, vec![1, 2, 3]);
    net.set_epoch(1, 11);
    net.set_epoch(2, 22);
    net.set_epoch(3, 33);
    let rt = StrictRuntime::new(
        CountingStrictRepo::new(),
        1,
        11,
        "channels".to_owned(),
        net,
        CancellationToken::new(),
        Arc::new(ReplicationConfig::default()),
    );
    rt.finish_history_election_for_test();
    let metadata = rt.repo.history_metadata();
    let first_cut = TerminalJournal::in_memory("first-empty").terminal_cut();
    let second_cut = TerminalJournal::in_memory("second-empty").terminal_cut();
    let first_rank = HistoryRank {
        version: metadata.version,
        freshness: metadata.freshness,
        runtime_started_at: 1,
        node_id: 2,
        terminal_repository_base_version: metadata.version,
    };
    let second_rank = HistoryRank {
        runtime_started_at: 2,
        node_id: 3,
        ..first_rank
    };
    {
        let mut state = rt.state.lock();
        state.request_history_election();
        state.begin_history_election([2, 3]);
    }

    assert!(
        rt.record_v3_history_election_rank(
            PeerIncarnation::new(2, 22),
            first_rank,
            first_cut,
            true,
        )
        .await
        .is_none()
    );
    rt.terminal_journal
        .lock()
        .await
        .upsert_abort_decision((1, 1), 1)
        .expect("concurrent local terminal decision");

    assert!(
        rt.record_v3_history_election_rank(
            PeerIncarnation::new(3, 33),
            second_rank,
            second_cut,
            true,
        )
        .await
        .is_none(),
        "an empty winner cached before the local fence must be rejected after the fence appears"
    );
    let state = rt.state.lock();
    assert!(state.history_election_pending());
    assert!(!state.history_election_active());
}

#[tokio::test]
async fn forced_checkpoint_abandons_opposing_terminal_client_and_sends_fresh_request() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    let peer = PeerIncarnation::new(2, 22);
    // An active per-operation terminal client toward the elected source (for
    // example from a terminal fence) must not silently block the forced
    // cursor-zero checkpoint replacement: the ranked election outranks
    // steady-state repair, and every transfer naming the old lineage must be
    // abandoned before the fresh lineage can be pulled.
    request_v3_terminal_sync(&rt, 2, StrictCatchupReason::TerminalFence).await;
    assert!(
        net.drain_captures().into_iter().any(|frame| matches!(
            frame,
            CapturedFrame::StrictUnicast {
                dst: 2,
                body: StrictBody::TerminalSyncReq(_),
                ..
            }
        )),
        "fixture: the terminal-fence trigger must open an active outbound client"
    );
    assert!(
        rt.v3_sync.lock().has_session_work(peer),
        "fixture: the terminal-fence trigger must leave a non-idle reducer session"
    );
    let local_cut = rt.terminal_journal.lock().await.terminal_cut();
    let foreign_cut = TerminalCut::new([0xEE; 16], local_cut.generation(), [0xDD; 32], [0xCC; 32]);
    assert_ne!(
        foreign_cut.journal_id(),
        local_cut.journal_id(),
        "fixture must model a foreign journal lineage"
    );

    request_v3_terminal_sync_toward(
        &rt,
        2,
        StrictCatchupReason::HistoryElection,
        Some(foreign_cut),
    )
    .await;

    let replacement = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                dst: 2,
                body: StrictBody::TerminalSyncReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("the forced checkpoint must send a fresh terminal sync request");
    assert_eq!(
        replacement.expected_cursor, 0,
        "the forced checkpoint must start from cursor zero after abandoning opposing work"
    );
    assert_eq!(
        replacement.requester_terminal_set_digest.as_ref(),
        rt.terminal_journal
            .lock()
            .await
            .terminal_cut()
            .terminal_set_digest(),
        "the replacement must advertise the local (pre-checkpoint) terminal set"
    );
}

#[tokio::test]
async fn history_election_syncs_from_the_winner_not_the_last_responder() {
    let net = MockNet::new(1, vec![1, 2, 3]);
    net.set_epoch(1, 11);
    net.set_epoch(2, 22);
    net.set_epoch(3, 33);
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V4);
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V4));
    net.set_peer_strict_replication_protocol_version(2, STRICT_PROTOCOL_VERSION_V4);
    net.set_peer_strict_replication_protocol_version(3, STRICT_PROTOCOL_VERSION_V4);
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
            terminal_repository_base_version: 0,
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
            terminal_repository_base_version: 0,
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
    // advertisements at the V4 support floor so this remains a focused
    // cumulative-repair coordinator test rather than accidentally disabling
    // bootstrap origination.
    net.set_strict_replication_protocol_version(
        crate::replications::protocol::STRICT_PROTOCOL_VERSION_CURRENT,
    );
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V4));
    net.set_peer_strict_replication_protocol_version(2, STRICT_PROTOCOL_VERSION_V4);
    net.set_peer_strict_replication_protocol_version(3, STRICT_PROTOCOL_VERSION_V4);
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
    retry_v3_terminal_transmissions(&rt).await;
    let expedited = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                dst: 2,
                body: StrictBody::HistoryProbeReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("election promotion must pull the retained retry inside the probe watchdog");
    assert_eq!(expedited.request_nonce, periodic.request_nonce);
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
async fn history_election_rearms_a_promoted_nonce_missing_its_retry_owner() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    let peer = PeerIncarnation::new(2, 22);
    let nonce = rt
        .v3_sync
        .lock()
        .record_history_nonce(
            peer,
            StrictCatchupReason::Admission as i32,
            rt.cfg.pending_propose_ttl(),
        )
        .expect("orphaned admission nonce");

    request_v3_history_probe(&rt, 2, StrictCatchupReason::HistoryElection).await;

    let request = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                dst: 2,
                body: StrictBody::HistoryProbeReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("election must restore transmission ownership for the promoted nonce");
    assert_eq!(request.request_nonce, nonce);
    assert_eq!(request.reason, StrictCatchupReason::HistoryElection as i32);
}

#[tokio::test]
async fn admission_rearms_a_retained_nonce_missing_its_retry_owner() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    let peer = PeerIncarnation::new(2, 22);
    let nonce = rt
        .v3_sync
        .lock()
        .record_history_nonce(
            peer,
            StrictCatchupReason::Admission as i32,
            rt.cfg.pending_propose_ttl(),
        )
        .expect("orphaned admission nonce");

    request_v3_history_probe(&rt, 2, StrictCatchupReason::Admission).await;

    let request = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                dst: 2,
                body: StrictBody::HistoryProbeReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("admission must restore transmission ownership for its retained nonce");
    assert_eq!(request.request_nonce, nonce);
    assert_eq!(request.reason, StrictCatchupReason::Admission as i32);
}

#[tokio::test]
async fn consumed_history_nonce_cannot_be_resurrected_by_late_retry_registration() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    let peer = PeerIncarnation::new(2, 22);
    let nonce = rt
        .v3_sync
        .lock()
        .record_history_nonce(
            peer,
            StrictCatchupReason::Admission as i32,
            rt.cfg.pending_propose_ttl(),
        )
        .expect("history nonce");
    let request = StrictHistoryProbeReq {
        src_node: 1,
        expected_responder_boot_epoch: 22,
        request_nonce: nonce,
        reason: StrictCatchupReason::Admission as i32,
    };

    assert!(
        rt.v3_sync
            .lock()
            .accept_history_nonce(peer, nonce)
            .is_some()
    );
    rt.v3_retries.lock().complete_history_probe(peer, nonce);
    let registered = register_v3_history_probe_retry_if_current(&rt, peer, request.clone());
    if registered {
        let _ = send_v3_metadata_control(
            &rt,
            2,
            StrictBody::HistoryProbeReq(request),
            CatchupReason::Admission,
            CatchupPhase::Metadata,
        )
        .await;
    }
    assert!(
        !registered,
        "registration after response consumption must reject the stale identity"
    );
    assert!(
        !rt.v3_retries
            .lock()
            .history_probe_nonce_is_scheduled(peer, nonce)
    );

    retry_v3_terminal_transmissions(&rt).await;
    assert!(
        net.drain_captures().is_empty(),
        "a consumed history identity must never retransmit"
    );
}

#[tokio::test]
async fn consumed_clock_nonce_cannot_be_resurrected_by_late_retry_registration() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    let peer = PeerIncarnation::new(2, 22);
    let nonce = rt
        .v3_sync
        .lock()
        .record_clock_nonce(peer, rt.cfg.pending_propose_ttl())
        .expect("clock nonce");
    let request = StrictClockProbeReq {
        src_node: 1,
        expected_responder_boot_epoch: 22,
        request_nonce: nonce,
        reason: StrictCatchupReason::Admission as i32,
        requester_clock: 0,
    };

    assert!(rt.v3_sync.lock().accept_clock_nonce(peer, nonce));
    rt.v3_retries.lock().complete_clock_probe(peer, nonce);
    let registered = register_v3_clock_probe_retry_if_current(&rt, peer, request.clone());
    if registered {
        let _ = send_v3_metadata_control(
            &rt,
            2,
            StrictBody::ClockProbeReq(request.clone()),
            CatchupReason::Admission,
            CatchupPhase::Metadata,
        )
        .await;
    }
    assert!(
        !registered,
        "registration after response consumption must reject the stale identity"
    );
    assert!(!rt.v3_retries.lock().clock_probe_is_current(peer, &request));

    retry_v3_terminal_transmissions(&rt).await;
    assert!(
        net.drain_captures().is_empty(),
        "a consumed clock identity must never retransmit"
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
            terminal_repository_base_version: 0,
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

async fn retired_checkpoint_conflict_requests_history_election(reason: StrictCatchupReason) {
    let config = ReplicationConfig::default().with_strict_max_catchup_ops(32);
    let (source, source_net) = runtime(1, config.clone());
    let (sink, sink_net) = runtime(2, config);
    let safe = make_op_id(1, 11, 1);
    let conflicting = make_op_id(2, 22, 1);
    let retired_floor = make_op_id(2, 30, 1);

    assert!(source.apply_catchup_terminal_state(terminal_abort(1)).await);
    assert!(
        source
            .apply_catchup_terminal_state(StrictTerminalState {
                coord_node: 2,
                op_id_hi: conflicting.0,
                op_id_lo: conflicting.1,
                ballot: 2,
                outcome: Some(StrictTerminalOutcome::Abort(StrictDecisionAbort {})),
                resolver_node: 0,
                resolver_boot_epoch: 0,
                frozen_targets: Vec::new(),
            })
            .await
    );
    {
        let mut journal = sink.terminal_journal.lock().await;
        journal
            .upsert_abort_decision(retired_floor, 2)
            .expect("retirement floor decision");
        journal.checkpoint(0).expect("retirement checkpoint");
        assert!(journal.is_retired(conflicting));
    }

    request_v3_terminal_sync(&sink, 1, reason).await;
    let request = terminal_request(sink_net.drain_captures().pop().expect("initial request"));
    recv_v3_terminal_sync_req(&source, 2, 22, request.clone()).await;
    let page = terminal_page(source_net.drain_captures().pop().expect("checkpoint page"));
    assert_eq!(
        StrictTerminalPageKind::try_from(page.kind).ok(),
        Some(StrictTerminalPageKind::Checkpoint)
    );
    assert_eq!(page.checkpoint_states.len(), 2);

    recv_v3_terminal_sync_page(&sink, 1, 11, page).await;

    let peer = PeerIncarnation::new(1, 11);
    assert!(sink.state.lock().history_election_pending());
    assert!(sink.v3_sync.lock().client(peer).is_none());
    assert!(!sink.v3_retries.lock().request_is_current(peer, &request));
    assert!(sink_net.drain_captures().into_iter().all(|frame| !matches!(
        frame,
        CapturedFrame::StrictUnicast {
            body: StrictBody::TerminalSyncAck(_),
            ..
        }
    )));
    let journal = sink.terminal_journal.lock().await;
    assert!(journal.get(safe).is_none());
    assert!(journal.is_retired(conflicting));
}

#[tokio::test]
async fn admission_checkpoint_retired_conflict_requests_history_election() {
    retired_checkpoint_conflict_requests_history_election(StrictCatchupReason::Admission).await;
}

#[tokio::test]
async fn repository_gap_checkpoint_retired_conflict_requests_history_election() {
    retired_checkpoint_conflict_requests_history_election(StrictCatchupReason::RepositoryGap).await;
}

#[tokio::test]
async fn active_history_election_stages_checkpoint_for_admission_started_client() {
    let config = ReplicationConfig::default().with_strict_max_catchup_ops(32);
    let (source, source_net) = runtime(1, config.clone());
    let (sink, sink_net) = runtime(2, config);
    let source_op = make_op_id(1, 11, 1);
    let conflicting = make_op_id(2, 22, 1);
    let retired_floor = make_op_id(2, 30, 1);
    assert!(source.apply_catchup_terminal_state(terminal_abort(1)).await);
    assert!(
        source
            .apply_catchup_terminal_state(StrictTerminalState {
                coord_node: 2,
                op_id_hi: conflicting.0,
                op_id_lo: conflicting.1,
                ballot: 2,
                outcome: Some(StrictTerminalOutcome::Abort(StrictDecisionAbort {})),
                resolver_node: 0,
                resolver_boot_epoch: 0,
                frozen_targets: Vec::new(),
            })
            .await
    );
    let source_cut = source.terminal_journal.lock().await.terminal_cut();
    {
        let mut journal = sink.terminal_journal.lock().await;
        journal
            .upsert_abort_decision(retired_floor, 2)
            .expect("retirement floor decision");
        journal.checkpoint(0).expect("retirement checkpoint");
        assert!(journal.is_retired(conflicting));
    }

    request_v3_terminal_sync(&sink, 1, StrictCatchupReason::Admission).await;
    let request = terminal_request(sink_net.drain_captures().pop().expect("admission request"));
    let peer = PeerIncarnation::new(1, 11);
    sink.state.lock().begin_history_election([1]);
    sink.v3_history.lock().defer_until_terminal(
        peer,
        HistoryRank {
            version: 1,
            freshness: 1,
            runtime_started_at: 11,
            node_id: 1,
            terminal_repository_base_version: 0,
        },
        source_cut,
        StrictCatchupReason::HistoryElection,
    );
    request_v3_terminal_sync(&sink, 1, StrictCatchupReason::HistoryElection).await;
    assert!(sink_net.drain_captures().is_empty());
    {
        let sync = sink.v3_sync.lock();
        let client = sync.client(peer).expect("coalesced elected client");
        assert_eq!(
            client.started_reason(),
            StrictCatchupReason::Admission as i32
        );
        assert_eq!(client.reason(), StrictCatchupReason::HistoryElection as i32);
    }

    recv_v3_terminal_sync_req(&source, 2, 22, request).await;
    let page = terminal_page(source_net.drain_captures().pop().expect("checkpoint page"));
    recv_v3_terminal_sync_page(&sink, 1, 11, page).await;

    assert!(sink_net.drain_captures().into_iter().any(|frame| matches!(
        frame,
        CapturedFrame::StrictUnicast {
            body: StrictBody::TerminalSyncAck(_),
            ..
        }
    )));
    let journal = sink.terminal_journal.lock().await;
    assert!(journal.get(source_op).is_none());
    assert!(journal.is_retired(conflicting));
}

/// Production regression: node 4 (eu.mumble.winterco.cn) ran a history
/// election against the cluster (gen 4103) while its own strict terminal
/// journal was divergent (gen 7, five retired origins) and had already
/// retired the cluster's current op range. Every elected terminal sync
/// failed 140/140 with "strict terminal commit rejected by durable journal
/// ... is retired by checkpoint", and peers kept admission-probing it
/// forever. The elected source advanced its cut between the probe (which
/// deferred the elected source_cut) and the checkpoint page render, so the
/// sink no longer matched the exact-elected staging gate and fell into the
/// per-op apply path, where its own stale retired-origin floor rejected the
/// incoming ops. The elected checkpoint must still be staged as a wholesale
/// journal replacement even when the deferred cut is slightly behind the
/// page target.
#[tokio::test]
async fn exact_elected_checkpoint_stages_when_source_advanced_over_retired_floor() {
    let config = ReplicationConfig::default().with_strict_max_catchup_ops(32);
    let (source, source_net) = runtime(1, config.clone());
    let (sink, sink_net) = runtime(2, config);
    // The source applies a first op, the sink captures that cut as its
    // elected source obligation, and then the source advances one more
    // generation before rendering the checkpoint page.
    assert!(source.apply_catchup_terminal_state(terminal_abort(1)).await);
    let deferred_cut = source.terminal_journal.lock().await.terminal_cut();
    assert!(source.apply_catchup_terminal_state(terminal_abort(2)).await);
    let advanced_cut = source.terminal_journal.lock().await.terminal_cut();
    assert_ne!(deferred_cut, advanced_cut);

    // The sink's divergent journal has a retired-origin floor covering the
    // source's current op (the production divergence: node 4 retired the
    // cluster's live op range).
    let source_op = make_op_id(1, 11, 2);
    let retired_floor = make_op_id(1, 30, 1);
    {
        let mut journal = sink.terminal_journal.lock().await;
        journal
            .upsert_abort_decision(retired_floor, 2)
            .expect("retirement floor decision");
        journal.checkpoint(0).expect("retirement checkpoint");
        assert!(journal.is_retired(source_op));
    }

    // Exact elected HistoryElection intent: the sink elected node 1 as the
    // repository source and defers its terminal obligation at the cut it
    // observed during the election.
    let peer = PeerIncarnation::new(1, 11);
    sink.state.lock().begin_history_election([1]);
    sink.v3_history.lock().defer_until_terminal(
        peer,
        HistoryRank {
            version: 1,
            freshness: 1,
            runtime_started_at: 11,
            node_id: 1,
            terminal_repository_base_version: 0,
        },
        deferred_cut,
        StrictCatchupReason::HistoryElection,
    );
    request_v3_terminal_sync_toward(
        &sink,
        1,
        StrictCatchupReason::HistoryElection,
        Some(deferred_cut),
    )
    .await;
    let request = terminal_request(sink_net.drain_captures().pop().expect("elected request"));
    recv_v3_terminal_sync_req(&source, 2, 22, request).await;
    let page = terminal_page(source_net.drain_captures().pop().expect("checkpoint page"));
    assert_eq!(
        StrictTerminalPageKind::try_from(page.kind).ok(),
        Some(StrictTerminalPageKind::Checkpoint)
    );
    assert_eq!(
        page.target_cut.as_ref().and_then(cut_from_wire),
        Some(advanced_cut),
        "the responder must render the checkpoint at its current (advanced) cut"
    );

    recv_v3_terminal_sync_page(&sink, 1, 11, page).await;

    // The elected checkpoint must be staged and acknowledged, not applied
    // per-op (which would reject the locally-retired op and fail the session
    // forever, exactly like production).
    assert!(
        sink_net.drain_captures().into_iter().any(|frame| matches!(
            frame,
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncAck(_),
                ..
            }
        )),
        "the elected checkpoint must be staged and acknowledged even after the source advanced"
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
fn failed_client_cleanup_does_not_expire_coalesced_dirty_followup() {
    let mut state = SyncV3State::default();
    let peer = PeerIncarnation::new(2, 22);
    let ttl = Duration::from_secs(30);
    let trigger = SessionEvent::Trigger(SessionTrigger {
        kind: SessionSyncKind::Terminal,
        origin: SessionTriggerOrigin::External,
        desired_cut: None,
    });
    let initial_wire = state
        .transition_session(peer, trigger)
        .into_iter()
        .find_map(|effect| match effect {
            SessionEffect::StartSession { wire, .. } => Some(wire),
            _ => None,
        })
        .expect("initial terminal wire");
    state.begin_terminal_client_cache(
        peer,
        StrictCatchupReason::TerminalFence as i32,
        None,
        initial_wire.nonce().get(),
        initial_wire.cursor().value(),
        ttl,
    );

    let target = TerminalCut::new([1; 16], 1, [2; 32], [3; 32]);
    let next_cursor = SessionCursor::new(SessionCursorKind::TerminalGeneration, 1);
    let applied_wire = SessionWireIdentity::new(
        initial_wire.epoch(),
        SessionTransferId::new(1),
        initial_wire.nonce(),
        initial_wire.cursor(),
    );
    let applying = state.transition_session(
        peer,
        SessionEvent::PageReceived {
            kind: SessionSyncKind::Terminal,
            wire: applied_wire,
            next_cursor,
            target_cut: SessionCut::new([1; 16], 1, [2; 32], [3; 32]),
            has_more: true,
        },
    );
    assert!(applying.iter().any(|effect| matches!(
        effect,
        SessionEffect::ValidateAndApply { wire, .. } if *wire == applied_wire
    )));
    state
        .client_mut(peer)
        .expect("initial client cache")
        .accept_manifest(1, target, StrictTerminalPageKind::Delta, ttl);
    assert!(matches!(
        state.transition_session(peer, trigger).as_slice(),
        [SessionEffect::Coalesced]
    ));

    let failed = state.transition_session(
        peer,
        SessionEvent::ApplyFailed {
            epoch: applied_wire.epoch(),
            wire: applied_wire,
        },
    );
    let replacement_wire = failed
        .iter()
        .find_map(|effect| match effect {
            SessionEffect::StartSession { wire, .. } => Some(*wire),
            _ => None,
        })
        .expect("dirty follow-up wire");

    assert!(state.finish_failed_client(peer).is_some());
    assert!(state.has_session_work(peer));
    let replacement_page_wire = SessionWireIdentity::new(
        replacement_wire.epoch(),
        SessionTransferId::new(2),
        replacement_wire.nonce(),
        replacement_wire.cursor(),
    );
    assert!(
        state
            .transition_session(
                peer,
                SessionEvent::PageReceived {
                    kind: SessionSyncKind::Terminal,
                    wire: replacement_page_wire,
                    next_cursor,
                    target_cut: SessionCut::new([1; 16], 1, [2; 32], [3; 32]),
                    has_more: true,
                },
            )
            .iter()
            .any(|effect| matches!(
                effect,
                SessionEffect::ValidateAndApply { wire, .. } if *wire == replacement_page_wire
            ))
    );
}

#[tokio::test]
async fn invalid_correlated_history_response_cleans_up_and_rearms_election() {
    let (sink, _net) = runtime(2, ReplicationConfig::default());
    let peer = PeerIncarnation::new(1, 11);
    let request = sink
        .v3_history
        .lock()
        .begin_transfer(
            peer,
            10,
            0,
            StrictCatchupReason::RepositoryGap,
            Duration::from_secs(30),
            false,
            StrictCatchupReason::RepositoryGap,
        )
        .expect("history transfer")
        .into_parts()
        .0;
    assert!(!sink.state.lock().history_election_pending());

    apply_response(
        &sink,
        1,
        StrictCatchupResp {
            // The response is correlated to the authenticated peer and exact
            // transfer, but its claimed history owner is invalid.
            history_node: 0,
            history_transfer: Some(StrictHistoryTransferResp {
                expected_requester_boot_epoch: 22,
                transfer_id: request.transfer_id,
                request_nonce: request.request_nonce,
                cursor: request.expected_cursor,
                target_version: request.target_version,
            }),
            ..Default::default()
        },
    )
    .await;

    assert!(
        !sink.v3_history.lock().has_active_transfer(peer),
        "a claimed invalid response must not strand its consumed client"
    );
    assert!(
        sink.state.lock().history_election_pending(),
        "the rejected correlated history response must rearm ranked recovery"
    );
}

#[tokio::test]
async fn correlated_transfer_expiry_rearms_exact_pending_terminal_repair() {
    let (sink, net) = runtime(2, ReplicationConfig::default());
    let peer = PeerIncarnation::new(1, 11);
    let source_cut = TerminalCut::new([7; 16], 9, [8; 32], [9; 32]);
    sink.v3_history.lock().defer_until_terminal(
        peer,
        HistoryRank {
            version: 10,
            freshness: 20,
            runtime_started_at: 30,
            node_id: 1,
            terminal_repository_base_version: 10,
        },
        source_cut,
        StrictCatchupReason::RepositoryGap,
    );
    request_v3_terminal_sync_toward(
        &sink,
        1,
        StrictCatchupReason::RepositoryGap,
        Some(source_cut),
    )
    .await;
    let initial = terminal_request(net.drain_captures().pop().expect("initial request"));

    recv_v3_terminal_sync_page(
        &sink,
        1,
        11,
        StrictTerminalSyncPage {
            responder_node: 1,
            expected_requester_boot_epoch: 22,
            transfer_id: initial.transfer_id,
            request_nonce: initial.request_nonce,
            status: StrictTerminalSyncStatus::TransferExpired as i32,
            ..Default::default()
        },
    )
    .await;

    assert!(
        !sink.v3_retries.lock().request_is_current(peer, &initial),
        "the expired request retry must be cleared"
    );
    assert!(
        sink.v3_history
            .lock()
            .pending_after_terminal(peer)
            .is_some()
    );
    let replacement = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("replacement terminal request");
    assert_ne!(replacement.request_nonce, initial.request_nonce);
    let sync = sink.v3_sync.lock();
    let client = sync.client(peer).expect("replacement client");
    assert_eq!(client.desired_cut(), Some(source_cut));
}

#[tokio::test]
async fn correlated_cursor_mismatch_restarts_exact_terminal_repair_from_zero() {
    let (sink, net) = runtime(2, ReplicationConfig::default());
    let peer = PeerIncarnation::new(1, 11);
    let source_cut = TerminalCut::new([7; 16], 9, [8; 32], [9; 32]);
    let stale_baseline = TerminalCut::new([7; 16], 4, [4; 32], [5; 32]);
    sink.v3_sync
        .lock()
        .remember_source_cut(peer, stale_baseline);
    sink.v3_history.lock().defer_until_terminal(
        peer,
        HistoryRank {
            version: 10,
            freshness: 20,
            runtime_started_at: 30,
            node_id: 1,
            terminal_repository_base_version: 10,
        },
        source_cut,
        StrictCatchupReason::RepositoryGap,
    );
    request_v3_terminal_sync_toward(
        &sink,
        1,
        StrictCatchupReason::RepositoryGap,
        Some(source_cut),
    )
    .await;
    let initial = terminal_request(net.drain_captures().pop().expect("initial request"));
    assert_eq!(initial.expected_cursor, stale_baseline.generation());
    // A concurrent trigger may already have promoted dirty reducer work when
    // the correlated error arrives. The rejected baseline must reset that
    // inherited wire too, rather than coalescing the repair behind it.
    request_v3_terminal_sync_toward(
        &sink,
        1,
        StrictCatchupReason::TerminalFence,
        Some(source_cut),
    )
    .await;
    assert!(net.drain_captures().is_empty());

    recv_v3_terminal_sync_page(
        &sink,
        1,
        11,
        StrictTerminalSyncPage {
            responder_node: 1,
            expected_requester_boot_epoch: 22,
            transfer_id: initial.transfer_id,
            request_nonce: initial.request_nonce,
            status: StrictTerminalSyncStatus::CursorMismatch as i32,
            ..Default::default()
        },
    )
    .await;

    assert!(
        !sink.v3_retries.lock().request_is_current(peer, &initial),
        "the mismatched cursor retry must be cleared"
    );
    let replacement = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                body: StrictBody::TerminalSyncReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("replacement terminal request");
    assert_ne!(replacement.request_nonce, initial.request_nonce);
    assert_eq!(replacement.expected_cursor, 0);
    let sync = sink.v3_sync.lock();
    let client = sync.client(peer).expect("replacement client");
    assert_eq!(client.desired_cut(), Some(source_cut));
}

#[tokio::test]
async fn capacity_resource_limit_keeps_bounded_exact_terminal_retry() {
    let retry_delay = Duration::from_millis(40);
    let ttl = Duration::from_millis(130);
    let config = ReplicationConfig::default()
        .with_bulk_retry_delay(retry_delay)
        .with_strict_bulk_retry_max_delay(retry_delay.saturating_mul(2))
        .with_strict_bulk_retry_jitter_pct(0)
        .with_pending_propose_ttl(ttl);
    let (sink, net) = runtime(2, config);
    let peer = PeerIncarnation::new(1, 11);
    let desired_cut = TerminalCut::new([7; 16], 9, [8; 32], [9; 32]);
    request_v3_terminal_sync_toward(
        &sink,
        1,
        StrictCatchupReason::RepositoryGap,
        Some(desired_cut),
    )
    .await;
    let initial = terminal_request(net.drain_captures().pop().expect("initial request"));

    recv_v3_terminal_sync_page(
        &sink,
        1,
        11,
        StrictTerminalSyncPage {
            responder_node: 1,
            expected_requester_boot_epoch: 22,
            transfer_id: 71,
            request_nonce: initial.request_nonce,
            status: StrictTerminalSyncStatus::ResourceLimit as i32,
            target_cut: Some(cut_to_wire(desired_cut)),
            ..Default::default()
        },
    )
    .await;

    assert!(
        net.drain_captures().is_empty(),
        "capacity rejection must not spin"
    );
    assert!(sink.v3_retries.lock().request_is_current(peer, &initial));
    assert_eq!(
        sink.v3_sync
            .lock()
            .client(peer)
            .and_then(|client| client.desired_cut()),
        Some(desired_cut)
    );
    retry_v3_terminal_transmissions(&sink).await;
    assert!(
        net.drain_captures().is_empty(),
        "the retained request must honor its initial backoff"
    );

    tokio::time::sleep(ttl + Duration::from_millis(20)).await;
    retry_v3_terminal_transmissions(&sink).await;
    assert!(
        net.drain_captures().is_empty(),
        "retry must stop at its fixed TTL"
    );
    assert!(sink.v3_sync.lock().client(peer).is_none());
    assert!(!sink.v3_retries.lock().request_is_current(peer, &initial));
}

#[tokio::test]
async fn correlated_incarnation_mismatch_rearms_pending_elected_history() {
    let (sink, net) = runtime(2, ReplicationConfig::default());
    let peer = PeerIncarnation::new(1, 11);
    let source_cut = TerminalCut::new([7; 16], 9, [8; 32], [9; 32]);
    sink.v3_history.lock().defer_until_terminal(
        peer,
        HistoryRank {
            version: 10,
            freshness: 20,
            runtime_started_at: 30,
            node_id: 1,
            terminal_repository_base_version: 10,
        },
        source_cut,
        StrictCatchupReason::HistoryElection,
    );
    request_v3_terminal_sync_toward(
        &sink,
        1,
        StrictCatchupReason::HistoryElection,
        Some(source_cut),
    )
    .await;
    let initial = terminal_request(net.drain_captures().pop().expect("initial request"));
    assert!(!sink.state.lock().history_election_pending());

    recv_v3_terminal_sync_page(
        &sink,
        1,
        11,
        StrictTerminalSyncPage {
            responder_node: 1,
            expected_requester_boot_epoch: 22,
            transfer_id: initial.transfer_id,
            request_nonce: initial.request_nonce,
            status: StrictTerminalSyncStatus::IncarnationMismatch as i32,
            ..Default::default()
        },
    )
    .await;

    assert!(sink.v3_sync.lock().client(peer).is_none());
    assert!(
        sink.v3_history
            .lock()
            .pending_after_terminal(peer)
            .is_some(),
        "the exact elected history obligation must survive"
    );
    assert!(
        sink.state.lock().history_election_pending(),
        "the invalid elected incarnation must rearm source ranking"
    );
}

#[test]
fn staged_checkpoint_accumulates_pages_until_the_repository_is_bound() {
    let mut state = SyncV3State::default();
    let peer = PeerIncarnation::new(1, 11);
    let target = TerminalCut::new([1; 16], 2, [2; 32], [3; 32]);
    state
        .begin_client(
            peer,
            StrictCatchupReason::HistoryElection as i32,
            Duration::from_secs(30),
        )
        .expect("terminal client");
    let client = state.client_mut(peer).expect("active terminal client");
    client.accept_manifest(
        7,
        target,
        StrictTerminalPageKind::Checkpoint,
        Duration::from_secs(30),
    );
    assert!(client.stage_checkpoint_page(target, vec![terminal_abort(1)]));
    assert!(client.stage_checkpoint_page(target, vec![terminal_abort(2)]));
    assert!(state.publish_staged_checkpoint(peer, target));
    assert!(state.bind_staged_checkpoint_to_repository(peer, target, 9_540));

    let staged = state
        .staged_checkpoint_for_repository(peer, 9_540)
        .expect("bound staged checkpoint");
    assert_eq!(staged.target_cut(), target);
    assert_eq!(staged.states().len(), 2);
}

#[test]
fn history_election_promotes_an_inflight_admission_terminal_client() {
    let mut state = SyncV3State::default();
    let peer = PeerIncarnation::new(1, 11);
    let ttl = Duration::from_secs(30);
    state
        .begin_client(peer, StrictCatchupReason::Admission as i32, ttl)
        .expect("admission terminal client");

    assert!(
        state
            .begin_client(peer, StrictCatchupReason::HistoryElection as i32, ttl)
            .is_none()
    );

    let client = state.client(peer).expect("promoted terminal client");
    assert_eq!(
        client.started_reason(),
        StrictCatchupReason::Admission as i32
    );
    assert_eq!(client.reason(), StrictCatchupReason::HistoryElection as i32);
}

#[test]
fn terminal_intent_deferred_behind_reducer_history_preserves_exact_desired_cut() {
    let mut state = SyncV3State::default();
    let peer = PeerIncarnation::new(2, 22);
    let desired_cut = TerminalCut::new([4; 16], 17, [5; 32], [6; 32]);

    assert!(
        state
            .transition_session(
                peer,
                SessionEvent::Trigger(SessionTrigger {
                    kind: SessionSyncKind::History,
                    origin: SessionTriggerOrigin::External,
                    desired_cut: None,
                }),
            )
            .iter()
            .any(|effect| matches!(
                effect,
                SessionEffect::StartSession {
                    kind: SessionSyncKind::History,
                    ..
                }
            ))
    );
    assert!(matches!(
        state
            .transition_session(
                peer,
                SessionEvent::Trigger(SessionTrigger {
                    kind: SessionSyncKind::Terminal,
                    origin: SessionTriggerOrigin::External,
                    desired_cut: Some(SessionCut::new([4; 16], 17, [5; 32], [6; 32])),
                }),
            )
            .as_slice(),
        [SessionEffect::Coalesced]
    ));

    assert!(state.coalesce_terminal_intent_if_active(
        peer,
        StrictCatchupReason::TerminalFence as i32,
        Some(desired_cut),
    ));
    assert_eq!(
        state.take_deferred_client(peer),
        Some((StrictCatchupReason::TerminalFence as i32, Some(desired_cut)))
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

#[tokio::test]
async fn yielded_reverse_terminal_sync_resumes_when_responder_admission_is_busy() {
    let config = ReplicationConfig::default()
        .with_catchup_max_in_flight_total(1)
        .with_catchup_max_in_flight_per_peer(1);
    let (rt, net) = runtime(2, config);
    request_v3_terminal_sync(&rt, 1, StrictCatchupReason::Admission).await;
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
    let _permit = rt
        .cfg
        .try_begin_catchup(CatchupMode::Strict, "occupied", 1)
        .expect("occupy the sole catchup permit");

    recv_v3_terminal_sync_req(
        &rt,
        1,
        11,
        StrictTerminalSyncReq {
            src_node: 1,
            expected_responder_boot_epoch: 22,
            reason: StrictCatchupReason::Admission as i32,
            known_source_cut: None,
            requester_terminal_set_digest: Bytes::from(vec![9; 32]),
            transfer_id: 0,
            request_nonce: 700,
            expected_cursor: 0,
        },
    )
    .await;

    assert!(
        net.drain_captures().into_iter().any(|frame| matches!(
            frame,
            CapturedFrame::StrictUnicast {
                dst: 1,
                body: StrictBody::TerminalSyncReq(StrictTerminalSyncReq {
                    transfer_id: 0,
                    request_nonce,
                    ..
                }),
                ..
            } if request_nonce != initial.request_nonce
        )),
        "a rejected responder direction must immediately resume the retained reverse client"
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
            .is_some(),
        "reciprocal admission metadata must not wait for the responder TTL"
    );
    assert!(
        state
            .record_history_nonce(peer, StrictCatchupReason::Admission as i32, ttl)
            .is_none(),
        "the active admission probe must still coalesce periodic duplicates"
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

#[test]
fn terminal_trigger_expires_stale_client_before_reducer_transition() {
    let mut state = SyncV3State::default();
    let peer = PeerIncarnation::new(2, 22);
    let trigger = SessionEvent::Trigger(SessionTrigger {
        kind: SessionSyncKind::Terminal,
        origin: SessionTriggerOrigin::External,
        desired_cut: None,
    });

    let initial_wire = state
        .transition_session(peer, trigger)
        .into_iter()
        .find_map(|effect| match effect {
            SessionEffect::StartSession {
                kind: SessionSyncKind::Terminal,
                wire,
            } => Some(wire),
            _ => None,
        })
        .expect("initial terminal wire");
    state.begin_terminal_client_cache(
        peer,
        StrictCatchupReason::TerminalFence as i32,
        None,
        initial_wire.nonce().get(),
        initial_wire.cursor().value(),
        Duration::ZERO,
    );

    let effects = state.transition_session(peer, trigger);
    assert!(effects.iter().any(|effect| {
        matches!(
            effect,
            SessionEffect::StartSession {
                kind: SessionSyncKind::Terminal,
                wire,
            } if *wire != initial_wire
        )
    }));
    assert!(state.client(peer).is_none());
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
    let sync = rt.v3_sync.lock();
    let client = sync
        .client(peer)
        .expect("capacity rejection must retain the bounded client");
    assert_eq!(client.transfer_id(), 71);
    assert_eq!(client.pending_nonce(), request.request_nonce);
    assert!(rt.v3_retries.lock().request_is_current(peer, &request));
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
async fn duplicate_v4_pairwise_clock_probe_request_replays_one_clock_response() {
    let (rt, net) = runtime(2, ReplicationConfig::default());
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V4);
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V4));
    net.set_peer_strict_replication_protocol_version(1, STRICT_PROTOCOL_VERSION_V4);
    let request = StrictClockProbeReq {
        src_node: 1,
        expected_responder_boot_epoch: 22,
        request_nonce: 7,
        requester_clock: 100,
        reason: StrictCatchupReason::Admission as i32,
    };

    recv_v3_clock_probe_req(&rt, 1, 11, request.clone()).await;
    let first = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                dst: 1,
                body: StrictBody::ClockProbeResp(response),
                ..
            } => Some(response),
            _ => None,
        })
        .expect("first clock probe response");
    let clock_after_first = rt.state.lock().clock;

    recv_v3_clock_probe_req(&rt, 1, 11, request).await;
    let second = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                dst: 1,
                body: StrictBody::ClockProbeResp(response),
                ..
            } => Some(response),
            _ => None,
        })
        .expect("duplicate clock probe response");

    assert_eq!(
        second, first,
        "duplicate retries must replay the same proof"
    );
    assert_eq!(
        rt.state.lock().clock,
        clock_after_first,
        "a duplicate probe must not ratchet the responder clock"
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
            terminal_repository_base_version: 0,
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
async fn newer_admission_metadata_starts_repository_catchup() {
    let (rt, net) = runtime(1, ReplicationConfig::default());
    rt.seed_membership_snapshot([MemberIncarnation::new(1, 11), MemberIncarnation::new(2, 22)]);
    assert!(!rt.peer_incarnation_is_admitted(2, 22));

    request_v3_history_probe(&rt, 2, StrictCatchupReason::Admission).await;
    let request_nonce = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                dst: 2,
                body: StrictBody::HistoryProbeReq(request),
                ..
            } => Some(request.request_nonce),
            _ => None,
        })
        .expect("admission history request");
    let source_cut = rt.terminal_journal.lock().await.terminal_cut();

    recv_v3_history_probe_resp(
        &rt,
        2,
        22,
        StrictHistoryProbeResp {
            responder_node: 2,
            expected_requester_boot_epoch: 11,
            request_nonce,
            repository_version: 1,
            terminal_repository_base_version: 0,
            history_freshness: 1,
            runtime_started_at: 22,
            history_node: 2,
            terminal_cut: Some(cut_to_wire(source_cut)),
            reason: StrictCatchupReason::Admission as i32,
        },
    )
    .await;

    assert!(net.drain_captures().into_iter().any(|frame| matches!(
        frame,
        CapturedFrame::StrictUnicast {
            dst: 2,
            body: StrictBody::CatchupReq(StrictCatchupReq {
                history_probe_only: false,
                force_snapshot: false,
                history_transfer: Some(_),
                ..
            }),
            ..
        }
    )));
}

#[tokio::test]
async fn newer_promoted_admission_foreign_checkpoint_rearms_after_election_closes() {
    let net = MockNet::new(1, vec![1, 2, 3]);
    net.set_epoch(1, 11);
    net.set_epoch(2, 22);
    net.set_epoch(3, 33);
    net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V4);
    net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V4));
    net.set_peer_strict_replication_protocol_version(2, STRICT_PROTOCOL_VERSION_V4);
    net.set_peer_strict_replication_protocol_version(3, STRICT_PROTOCOL_VERSION_V4);
    let rt = StrictRuntime::new(
        CountingStrictRepo::new(),
        1,
        11,
        "channels".to_owned(),
        net.clone(),
        CancellationToken::new(),
        Arc::new(ReplicationConfig::default()),
    );
    rt.finish_history_election_for_test();
    rt.seed_membership_snapshot([
        MemberIncarnation::new(1, 11),
        MemberIncarnation::new(2, 22),
        MemberIncarnation::new(3, 33),
    ]);

    request_v3_history_probe(&rt, 2, StrictCatchupReason::Admission).await;
    let admission_request = net
        .drain_captures()
        .into_iter()
        .find_map(|frame| match frame {
            CapturedFrame::StrictUnicast {
                dst: 2,
                body: StrictBody::HistoryProbeReq(request),
                ..
            } => Some(request),
            _ => None,
        })
        .expect("admission history request");
    {
        let mut state = rt.state.lock();
        state.request_history_election();
        state.begin_history_election([2, 3]);
    }
    request_v3_history_probe(&rt, 2, StrictCatchupReason::HistoryElection).await;
    let remote_cut = TerminalCut::new([7; 16], 1, [8; 32], [9; 32]);
    recv_v3_history_probe_resp(
        &rt,
        2,
        22,
        StrictHistoryProbeResp {
            responder_node: 2,
            expected_requester_boot_epoch: 11,
            request_nonce: admission_request.request_nonce,
            repository_version: 1,
            terminal_repository_base_version: 0,
            history_freshness: 1,
            runtime_started_at: 22,
            history_node: 2,
            terminal_cut: Some(cut_to_wire(remote_cut)),
            reason: StrictCatchupReason::Admission as i32,
        },
    )
    .await;
    assert!(
        net.drain_captures().is_empty(),
        "incomplete election defers repair"
    );

    rt.finish_history_election_for_test();
    rt.reconcile_peer_admissions();
    assert!(!rt.peer_incarnation_is_admitted(2, 22));
    resume_deferred_v3_admissions(&rt).await;

    assert!(rt.state.lock().history_election_blocks_steady_state());
    assert!(net.drain_captures().into_iter().all(|frame| !matches!(
        frame,
        CapturedFrame::StrictUnicast {
            dst: 2,
            body: StrictBody::TerminalSyncReq(_),
            ..
        }
    )));
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
            terminal_repository_base_version: 0,
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
async fn delayed_election_response_with_divergent_cut_rearms_election() {
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
    // peer's response arrived. A divergent cut must rearm a new global
    // election; admission is not authorized to synchronize that foreign
    // lineage on its own.
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
            terminal_repository_base_version: 0,
            history_freshness: 0,
            runtime_started_at: 22,
            history_node: 2,
            terminal_cut: Some(remote_cut),
            reason: StrictCatchupReason::HistoryElection as i32,
        },
    )
    .await;

    assert!(rt.state.lock().history_election_pending());
    assert!(net.drain_captures().into_iter().all(|frame| !matches!(
        frame,
        CapturedFrame::StrictUnicast {
            dst: 2,
            body: StrictBody::TerminalSyncReq(_),
            ..
        }
    )));
}
