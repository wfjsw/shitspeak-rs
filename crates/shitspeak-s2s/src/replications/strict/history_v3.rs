//! V3 repository-history sequencing and pagination correlation.
//!
//! Terminal transfer lifetime remains in `sync_v3`. This coordinator owns
//! only the metadata intent which must wait for terminal convergence and the
//! one repository suffix/snapshot pagination chain which may follow it.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use shitspeak_core::NodeIdentifier;

use super::runtime::HistoryRank;
use super::sync_v3::PeerIncarnation;
use super::terminal_journal::TerminalCut;
use crate::replications::proto::{
    StrictCatchupReason, StrictCatchupReq, StrictCatchupResp, StrictHistoryTransferReq,
    StrictHistoryTransferResp,
};

#[derive(Clone, Copy, Debug)]
pub(super) struct PendingHistoryIntent {
    rank: HistoryRank,
    reason: StrictCatchupReason,
    source_cut: TerminalCut,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuation_acknowledges_the_exact_preceding_request_nonce() {
        let peer = PeerIncarnation::new(2, 11);
        let mut state = HistoryV3State::default();
        let first = state
            .begin_transfer(
                peer,
                100,
                90,
                StrictCatchupReason::RepositoryGap,
                Duration::from_secs(30),
                false,
                StrictCatchupReason::RepositoryGap,
            )
            .expect("first request")
            .into_parts()
            .0;
        assert_eq!(first.acknowledged_request_nonce, 0);

        assert!(state.claim_response(
            peer,
            &StrictHistoryTransferResp {
                expected_requester_boot_epoch: 77,
                transfer_id: first.transfer_id,
                request_nonce: first.request_nonce,
                cursor: first.expected_cursor,
                target_version: first.target_version,
            },
            77
        ));
        let second = state
            .continue_transfer(peer, 95)
            .expect("continuation request");
        assert_eq!(second.transfer_id, first.transfer_id);
        assert_eq!(second.acknowledged_request_nonce, first.request_nonce);
        assert_ne!(second.request_nonce, first.request_nonce);

        assert!(state.claim_response(
            peer,
            &StrictHistoryTransferResp {
                expected_requester_boot_epoch: 77,
                transfer_id: second.transfer_id,
                request_nonce: second.request_nonce,
                cursor: second.expected_cursor,
                target_version: second.target_version,
            },
            77
        ));
        let third = state
            .continue_transfer(peer, 100)
            .expect("final continuation request");
        assert_eq!(third.acknowledged_request_nonce, second.request_nonce);
    }

    #[test]
    fn history_election_transfer_preempts_overlapping_admission_transfer() {
        let peer = PeerIncarnation::new(2, 11);
        let mut state = HistoryV3State::default();
        let admission = state
            .begin_transfer(
                peer,
                95,
                90,
                StrictCatchupReason::Admission,
                Duration::from_secs(30),
                false,
                StrictCatchupReason::Admission,
            )
            .expect("admission transfer")
            .into_parts()
            .0;

        let election = state.begin_transfer(
            peer,
            100,
            0,
            StrictCatchupReason::HistoryElection,
            Duration::from_secs(30),
            false,
            StrictCatchupReason::HistoryElection,
        );

        let (election, preempted) = election
            .expect("the winning snapshot must preempt an incremental admission client")
            .into_parts();
        assert_eq!(preempted, Some(StrictCatchupReason::Admission));
        assert_ne!(election.transfer_id, admission.transfer_id);
    }

    #[test]
    fn response_claim_is_atomic_and_final_page_has_explicit_ack() {
        let peer = PeerIncarnation::new(2, 11);
        let mut state = HistoryV3State::default();
        let request = state
            .begin_transfer(
                peer,
                100,
                90,
                StrictCatchupReason::RepositoryGap,
                Duration::from_secs(30),
                false,
                StrictCatchupReason::RepositoryGap,
            )
            .expect("request")
            .into_parts()
            .0;
        let response = StrictHistoryTransferResp {
            expected_requester_boot_epoch: 77,
            transfer_id: request.transfer_id,
            request_nonce: request.request_nonce,
            cursor: request.expected_cursor,
            target_version: request.target_version,
        };
        assert!(state.claim_response(peer, &response, 77));
        assert!(!state.claim_response(peer, &response, 77));
        let mut finished = state.finish_transfer(peer, 3).expect("finished");
        let ack = finished.take_final_ack().expect("final ack");
        let transfer = ack.history_transfer.expect("correlation");
        assert!(transfer.final_ack);
        assert_eq!(transfer.transfer_id, request.transfer_id);
        assert_eq!(transfer.acknowledged_request_nonce, request.request_nonce);
    }

    #[test]
    fn second_server_transfer_for_the_same_incarnation_is_rejected() {
        let peer = PeerIncarnation::new(2, 11);
        let mut state = HistoryV3State::default();
        let first = StrictHistoryTransferReq {
            transfer_id: 10,
            request_nonce: 20,
            ..Default::default()
        };
        assert!(matches!(
            state.begin_server_request(peer, &first, Duration::from_secs(30)),
            HistoryServerRequest::Build
        ));
        let competing = StrictHistoryTransferReq {
            transfer_id: 11,
            request_nonce: 21,
            ..Default::default()
        };
        assert!(matches!(
            state.begin_server_request(peer, &competing, Duration::from_secs(30)),
            HistoryServerRequest::Reject
        ));
    }

    #[test]
    fn acknowledged_server_page_is_a_tombstone_not_active_transfer() {
        let peer = PeerIncarnation::new(2, 11);
        let mut state = HistoryV3State::default();
        let request = StrictHistoryTransferReq {
            transfer_id: 10,
            request_nonce: 20,
            ..Default::default()
        };
        assert!(matches!(
            state.begin_server_request(peer, &request, Duration::from_secs(30)),
            HistoryServerRequest::Build
        ));
        assert!(state.cache_server_response(peer, &request, StrictCatchupResp::default()));
        assert!(state.has_server_transfer(peer));
        assert!(state.has_checkpoint_blocking_work(Instant::now()));

        let final_ack = StrictHistoryTransferReq {
            transfer_id: request.transfer_id,
            request_nonce: 21,
            acknowledged_request_nonce: request.request_nonce,
            final_ack: true,
            ..Default::default()
        };
        assert!(state.acknowledge_server_final(peer, &final_ack));
        assert!(!state.has_server_transfer(peer));
        assert!(!state.has_any_transfer(peer));
        assert!(!state.has_checkpoint_blocking_work(Instant::now()));
    }

    #[test]
    fn expired_server_page_does_not_suppress_new_periodic_work() {
        let peer = PeerIncarnation::new(2, 11);
        let mut state = HistoryV3State::default();
        let request = StrictHistoryTransferReq {
            transfer_id: 10,
            request_nonce: 20,
            ..Default::default()
        };
        assert!(matches!(
            state.begin_server_request(peer, &request, Duration::ZERO),
            HistoryServerRequest::Build
        ));
        assert!(!state.has_server_transfer(peer));
        assert!(!state.has_any_transfer(peer));
    }

    #[test]
    fn deferred_admission_rank_is_bounded_and_drained_once() {
        let peer = PeerIncarnation::new(2, 11);
        let mut state = HistoryV3State::default();
        let first_rank = HistoryRank {
            version: 3,
            freshness: 4,
            runtime_started_at: 5,
            node_id: 2,
            terminal_repository_base_version: 0,
        };
        let newer_rank = HistoryRank {
            version: 6,
            ..first_rank
        };
        let first_cut = TerminalCut::new([1; 16], 3, [2; 32], [3; 32]);
        let newer_cut = TerminalCut::new([1; 16], 6, [4; 32], [5; 32]);

        state.defer_admission(peer, first_rank, first_cut);
        state.defer_admission(peer, newer_rank, newer_cut);
        let deferred = state.take_deferred_admissions();
        assert_eq!(deferred.len(), 1);
        assert_eq!(deferred[0].peer(), peer);
        assert_eq!(deferred[0].rank(), newer_rank);
        assert_eq!(deferred[0].source_cut(), newer_cut);
        assert!(state.take_deferred_admissions().is_empty());
    }
}

impl PendingHistoryIntent {
    pub(super) fn rank(self) -> HistoryRank {
        self.rank
    }

    pub(super) fn reason(self) -> StrictCatchupReason {
        self.reason
    }

    pub(super) fn source_cut(self) -> TerminalCut {
        self.source_cut
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct HistoryProbeCandidate {
    peer: PeerIncarnation,
    rank: HistoryRank,
    source_cut: TerminalCut,
}

impl HistoryProbeCandidate {
    pub(super) fn peer(self) -> PeerIncarnation {
        self.peer
    }

    pub(super) fn rank(self) -> HistoryRank {
        self.rank
    }

    pub(super) fn source_cut(self) -> TerminalCut {
        self.source_cut
    }
}

#[derive(Clone, Copy, Debug)]
struct HistoryClient {
    transfer_id: u64,
    pending_nonce: u64,
    next_cursor: u64,
    target_version: u64,
    reason: StrictCatchupReason,
    metric_reason: StrictCatchupReason,
    processing_nonce: Option<u64>,
    expires_at: Instant,
}

#[derive(Clone)]
struct HistoryServerPage {
    response: Option<StrictCatchupResp>,
    acknowledged: bool,
    expires_at: Instant,
}

#[derive(Clone)]
pub(super) enum HistoryServerRequest {
    Build,
    Replay(StrictCatchupResp),
    Suppress,
    Reject,
}

pub(super) struct FinishedHistoryClient {
    peer: PeerIncarnation,
    metric_reason: StrictCatchupReason,
    final_ack: Option<StrictCatchupReq>,
}

pub(super) struct StartedHistoryTransfer {
    request: StrictHistoryTransferReq,
    preempted_metric_reason: Option<StrictCatchupReason>,
}

impl StartedHistoryTransfer {
    pub(super) fn into_parts(self) -> (StrictHistoryTransferReq, Option<StrictCatchupReason>) {
        (self.request, self.preempted_metric_reason)
    }
}

impl FinishedHistoryClient {
    pub(super) fn peer(&self) -> PeerIncarnation {
        self.peer
    }
    pub(super) fn metric_reason(&self) -> StrictCatchupReason {
        self.metric_reason
    }
    pub(super) fn take_final_ack(&mut self) -> Option<StrictCatchupReq> {
        self.final_ack.take()
    }
}

#[derive(Default)]
pub(super) struct HistoryV3State {
    next_id: u64,
    probe_candidates: HashMap<PeerIncarnation, HistoryProbeCandidate>,
    pending: HashMap<PeerIncarnation, PendingHistoryIntent>,
    clients: HashMap<PeerIncarnation, HistoryClient>,
    server_pages: HashMap<(PeerIncarnation, u64, u64), HistoryServerPage>,
    deferred_terminal: HashMap<PeerIncarnation, StrictCatchupReason>,
    deferred_admissions: HashMap<PeerIncarnation, HistoryProbeCandidate>,
}

fn reason_priority(reason: StrictCatchupReason) -> u8 {
    match reason {
        StrictCatchupReason::TerminalFence => 4,
        StrictCatchupReason::HistoryElection | StrictCatchupReason::Admission => 3,
        StrictCatchupReason::PeerBehind | StrictCatchupReason::RepositoryGap => 2,
        StrictCatchupReason::SteadyState
        | StrictCatchupReason::OwnerAntiEntropy
        | StrictCatchupReason::LegacyV2 => 1,
        StrictCatchupReason::DeliveryWatermark | StrictCatchupReason::Unspecified => 0,
    }
}

fn transfer_preempts(candidate: StrictCatchupReason, current: StrictCatchupReason) -> bool {
    reason_priority(candidate) > reason_priority(current)
        || (candidate == StrictCatchupReason::HistoryElection
            && current == StrictCatchupReason::Admission)
}

impl HistoryV3State {
    /// Whether a repository transfer still owns a fixed cursor/image whose
    /// accompanying terminal lineage must not be rotated underneath it.
    pub(super) fn has_checkpoint_blocking_work(&self, now: Instant) -> bool {
        self.clients.values().any(|client| client.expires_at > now)
            || self
                .server_pages
                .values()
                .any(|page| !page.acknowledged && page.expires_at > now)
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_id.max(1);
        self.next_id = id.wrapping_add(1).max(1);
        id
    }

    pub(super) fn defer_until_terminal(
        &mut self,
        peer: PeerIncarnation,
        rank: HistoryRank,
        source_cut: TerminalCut,
        reason: StrictCatchupReason,
    ) {
        let replacement = PendingHistoryIntent {
            rank,
            reason,
            source_cut,
        };
        self.pending
            .entry(peer)
            .and_modify(|current| {
                let higher_priority = reason_priority(reason) > reason_priority(current.reason);
                let same_intent_advanced = reason == current.reason
                    && (rank.beats(current.rank)
                        || (source_cut.journal_id() == current.source_cut.journal_id()
                            && source_cut.generation() > current.source_cut.generation()));
                if higher_priority || same_intent_advanced {
                    *current = replacement;
                }
            })
            .or_insert(replacement);
    }

    pub(super) fn record_probe_candidate(
        &mut self,
        peer: PeerIncarnation,
        rank: HistoryRank,
        source_cut: TerminalCut,
    ) {
        self.probe_candidates.insert(
            peer,
            HistoryProbeCandidate {
                peer,
                rank,
                source_cut,
            },
        );
    }

    /// Retain the admission half of a metadata probe whose nonce was promoted
    /// into an in-progress history election. The map is bounded to one rank
    /// and terminal cut per authenticated peer incarnation.
    pub(super) fn defer_admission(
        &mut self,
        peer: PeerIncarnation,
        rank: HistoryRank,
        source_cut: TerminalCut,
    ) {
        let replacement = HistoryProbeCandidate {
            peer,
            rank,
            source_cut,
        };
        self.deferred_admissions
            .entry(peer)
            .and_modify(|current| {
                let same_lineage_advanced = source_cut.journal_id()
                    == current.source_cut.journal_id()
                    && source_cut.generation() > current.source_cut.generation();
                if rank.beats(current.rank) || same_lineage_advanced {
                    *current = replacement;
                }
            })
            .or_insert(replacement);
    }

    pub(super) fn take_deferred_admissions(&mut self) -> Vec<HistoryProbeCandidate> {
        self.deferred_admissions
            .drain()
            .map(|(_, intent)| intent)
            .collect()
    }

    pub(super) fn probe_candidate(
        &self,
        peer: PeerIncarnation,
        expected_rank: HistoryRank,
    ) -> Option<HistoryProbeCandidate> {
        self.probe_candidates
            .get(&peer)
            .copied()
            .filter(|candidate| candidate.rank == expected_rank)
    }

    pub(super) fn take_after_terminal(
        &mut self,
        peer: PeerIncarnation,
    ) -> Option<PendingHistoryIntent> {
        self.pending.remove(&peer)
    }

    pub(super) fn pending_after_terminal(
        &self,
        peer: PeerIncarnation,
    ) -> Option<PendingHistoryIntent> {
        self.pending.get(&peer).copied()
    }

    pub(super) fn begin_transfer(
        &mut self,
        peer: PeerIncarnation,
        target_version: u64,
        cursor: u64,
        reason: StrictCatchupReason,
        ttl: Duration,
        _inherited_session: bool,
        metric_reason: StrictCatchupReason,
    ) -> Option<StartedHistoryTransfer> {
        let preempted_metric_reason = match self.clients.get(&peer) {
            Some(current) if transfer_preempts(reason, current.reason) => {
                Some(current.metric_reason)
            }
            Some(_) => return None,
            None => None,
        };
        if preempted_metric_reason.is_some() {
            self.clients.remove(&peer);
        }
        let transfer_id = self.next_id();
        let pending_nonce = self.next_id();
        self.clients.insert(
            peer,
            HistoryClient {
                transfer_id,
                pending_nonce,
                next_cursor: cursor,
                target_version,
                reason,
                metric_reason,
                processing_nonce: None,
                expires_at: Instant::now() + ttl,
            },
        );
        Some(StartedHistoryTransfer {
            request: StrictHistoryTransferReq {
                expected_responder_boot_epoch: peer.boot_epoch(),
                transfer_id,
                request_nonce: pending_nonce,
                expected_cursor: cursor,
                target_version,
                reason: reason as i32,
                acknowledged_request_nonce: 0,
                final_ack: false,
            },
            preempted_metric_reason,
        })
    }

    pub(super) fn claim_response(
        &mut self,
        peer: PeerIncarnation,
        response: &StrictHistoryTransferResp,
        local_boot_epoch: u64,
    ) -> bool {
        let Some(client) = self.clients.get_mut(&peer) else {
            return false;
        };
        let accepted = client.processing_nonce.is_none()
            && response.expected_requester_boot_epoch == local_boot_epoch
            && response.transfer_id == client.transfer_id
            && response.request_nonce == client.pending_nonce
            && response.cursor == client.next_cursor
            && response.target_version == client.target_version;
        if accepted {
            client.processing_nonce = Some(response.request_nonce);
        }
        accepted
    }

    pub(super) fn expects_response(&self, peer: PeerIncarnation) -> bool {
        self.clients.contains_key(&peer)
    }

    pub(super) fn has_active_transfer(&self, peer: PeerIncarnation) -> bool {
        self.clients.contains_key(&peer)
    }

    pub(super) fn has_server_transfer(&self, peer: PeerIncarnation) -> bool {
        let now = Instant::now();
        self.server_pages.iter().any(|((known_peer, _, _), page)| {
            *known_peer == peer && !page.acknowledged && page.expires_at > now
        })
    }

    pub(super) fn has_any_transfer(&self, peer: PeerIncarnation) -> bool {
        self.has_active_transfer(peer) || self.has_server_transfer(peer)
    }

    pub(super) fn defer_terminal_sync(
        &mut self,
        peer: PeerIncarnation,
        reason: StrictCatchupReason,
    ) {
        self.deferred_terminal
            .entry(peer)
            .and_modify(|current| {
                if reason_priority(reason) > reason_priority(*current) {
                    *current = reason;
                }
            })
            .or_insert(reason);
    }

    pub(super) fn take_deferred_terminal_sync(
        &mut self,
        peer: PeerIncarnation,
    ) -> Option<StrictCatchupReason> {
        self.deferred_terminal.remove(&peer)
    }

    pub(super) fn continue_transfer(
        &mut self,
        peer: PeerIncarnation,
        cursor: u64,
    ) -> Option<StrictHistoryTransferReq> {
        let nonce = self.next_id();
        let client = self.clients.get_mut(&peer)?;
        let acknowledged_request_nonce = client.processing_nonce.take()?;
        client.pending_nonce = nonce;
        client.next_cursor = cursor;
        Some(StrictHistoryTransferReq {
            expected_responder_boot_epoch: peer.boot_epoch(),
            transfer_id: client.transfer_id,
            request_nonce: nonce,
            expected_cursor: cursor,
            target_version: client.target_version,
            reason: client.reason as i32,
            acknowledged_request_nonce,
            final_ack: false,
        })
    }

    pub(super) fn finish_transfer(
        &mut self,
        peer: PeerIncarnation,
        src_node: NodeIdentifier,
    ) -> Option<FinishedHistoryClient> {
        let client = self.clients.remove(&peer)?;
        let final_ack = client.processing_nonce.map(|acknowledged_request_nonce| {
            let request_nonce = self.next_id();
            StrictCatchupReq {
                src_node: src_node as u32,
                since_version: client.next_cursor,
                chunk_token: client.next_cursor,
                force_snapshot: false,
                history_probe_only: false,
                terminal_state_cursor: u64::MAX,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
                history_transfer: Some(StrictHistoryTransferReq {
                    expected_responder_boot_epoch: peer.boot_epoch(),
                    transfer_id: client.transfer_id,
                    request_nonce,
                    expected_cursor: client.next_cursor,
                    target_version: client.target_version,
                    reason: client.reason as i32,
                    acknowledged_request_nonce,
                    final_ack: true,
                }),
            }
        });
        Some(FinishedHistoryClient {
            peer,
            metric_reason: client.metric_reason,
            final_ack,
        })
    }

    pub(super) fn expire_clients(&mut self, now: Instant) -> Vec<FinishedHistoryClient> {
        let peers: Vec<_> = self
            .clients
            .iter()
            .filter_map(|(peer, client)| (client.expires_at <= now).then_some(*peer))
            .collect();
        peers
            .into_iter()
            .filter_map(|peer| {
                let client = self.clients.remove(&peer)?;
                Some(FinishedHistoryClient {
                    peer,
                    metric_reason: client.metric_reason,
                    final_ack: None,
                })
            })
            .collect()
    }

    pub(super) fn begin_server_request(
        &mut self,
        peer: PeerIncarnation,
        request: &StrictHistoryTransferReq,
        ttl: Duration,
    ) -> HistoryServerRequest {
        let now = Instant::now();
        self.server_pages.retain(|_, page| page.expires_at > now);
        let key = (peer, request.transfer_id, request.request_nonce);
        if let Some(page) = self.server_pages.get(&key) {
            return if page.acknowledged {
                HistoryServerRequest::Suppress
            } else if let Some(response) = &page.response {
                HistoryServerRequest::Replay(response.clone())
            } else {
                HistoryServerRequest::Suppress
            };
        }
        if request.final_ack {
            return HistoryServerRequest::Reject;
        }
        if request.acknowledged_request_nonce != 0 {
            let previous = (
                peer,
                request.transfer_id,
                request.acknowledged_request_nonce,
            );
            let Some(page) = self.server_pages.get_mut(&previous) else {
                return HistoryServerRequest::Reject;
            };
            if page.acknowledged || page.response.is_none() {
                return HistoryServerRequest::Reject;
            }
            page.acknowledged = true;
        } else if self
            .server_pages
            .keys()
            .any(|(known_peer, _, _)| *known_peer == peer)
        {
            return HistoryServerRequest::Reject;
        }
        self.server_pages.insert(
            key,
            HistoryServerPage {
                response: None,
                acknowledged: false,
                expires_at: now + ttl,
            },
        );
        HistoryServerRequest::Build
    }

    pub(super) fn cache_server_response(
        &mut self,
        peer: PeerIncarnation,
        request: &StrictHistoryTransferReq,
        response: StrictCatchupResp,
    ) -> bool {
        self.server_pages
            .get_mut(&(peer, request.transfer_id, request.request_nonce))
            .is_some_and(|page| {
                if page.acknowledged || page.response.is_some() {
                    return false;
                }
                page.response = Some(response);
                true
            })
    }

    pub(super) fn abandon_server_request(
        &mut self,
        peer: PeerIncarnation,
        request: &StrictHistoryTransferReq,
    ) {
        let key = (peer, request.transfer_id, request.request_nonce);
        if self
            .server_pages
            .get(&key)
            .is_some_and(|page| page.response.is_none())
        {
            self.server_pages.remove(&key);
        }
    }

    pub(super) fn acknowledge_server_final(
        &mut self,
        peer: PeerIncarnation,
        request: &StrictHistoryTransferReq,
    ) -> bool {
        if !request.final_ack || request.acknowledged_request_nonce == 0 {
            return false;
        }
        let key = (
            peer,
            request.transfer_id,
            request.acknowledged_request_nonce,
        );
        let Some(page) = self.server_pages.get_mut(&key) else {
            return false;
        };
        if page.acknowledged || page.response.is_none() {
            return false;
        }
        page.acknowledged = true;
        true
    }

    pub(super) fn discard_peer(&mut self, node: NodeIdentifier) -> Vec<FinishedHistoryClient> {
        self.probe_candidates.retain(|peer, _| peer.node() != node);
        self.pending.retain(|peer, _| peer.node() != node);
        let peers: Vec<_> = self
            .clients
            .keys()
            .filter(|peer| peer.node() == node)
            .copied()
            .collect();
        let finished = peers
            .into_iter()
            .filter_map(|peer| {
                let client = self.clients.remove(&peer)?;
                Some(FinishedHistoryClient {
                    peer,
                    metric_reason: client.metric_reason,
                    final_ack: None,
                })
            })
            .collect();
        self.server_pages
            .retain(|(peer, _, _), _| peer.node() != node);
        self.deferred_terminal.retain(|peer, _| peer.node() != node);
        self.deferred_admissions
            .retain(|peer, _| peer.node() != node);
        finished
    }

    pub(super) fn cancel_clients(&mut self) -> Vec<FinishedHistoryClient> {
        self.clients
            .drain()
            .map(|(peer, client)| FinishedHistoryClient {
                peer,
                metric_reason: client.metric_reason,
                final_ack: None,
            })
            .collect()
    }
}
