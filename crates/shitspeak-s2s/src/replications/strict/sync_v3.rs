//! Pairwise strict-repair v3 session bookkeeping.
//!
//! Network I/O remains in `runtime`/`catchup`; this module owns correlation,
//! incarnation scoping, coalescing and transfer lifetime state.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use bytes::Bytes;
use shitspeak_core::NodeIdentifier;

use super::super::metrics::{
    self, CatchupReason, StrictCatchupSessionEvent, StrictCatchupSessionOutcome,
};
use super::super::proto::{
    StrictCatchupReason, StrictTerminalCut, StrictTerminalPageKind, StrictTerminalSyncPage,
};
use super::session_reducer::{
    self, Cut as ReducerCut, Effect as SessionEffect, Event as SessionEvent, PeerEpoch,
    SessionState,
};
use super::terminal_journal::TerminalCut;

pub(super) const JOURNAL_ID_LEN: usize = 16;
pub(super) const DIGEST_LEN: usize = 32;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) struct PeerIncarnation {
    node: NodeIdentifier,
    boot_epoch: u64,
}

impl PeerIncarnation {
    pub(super) fn new(node: NodeIdentifier, boot_epoch: u64) -> Self {
        Self { node, boot_epoch }
    }

    pub(super) fn node(self) -> NodeIdentifier {
        self.node
    }

    pub(super) fn boot_epoch(self) -> u64 {
        self.boot_epoch
    }
}

#[derive(Clone, Debug)]
pub(super) struct ClientSession {
    transfer_id: u64,
    pending_nonce: u64,
    next_cursor: u64,
    target_cut: Option<TerminalCut>,
    progress_cut: Option<TerminalCut>,
    desired_cut: Option<TerminalCut>,
    kind: Option<StrictTerminalPageKind>,
    // The active gauge is incremented under this immutable label. `reason`
    // may be promoted when a higher-priority trigger is coalesced, but the
    // eventual decrement must use the label that owns the gauge slot.
    started_reason: i32,
    reason: i32,
    dirty: bool,
    expires_at: Instant,
}

#[derive(Clone, Debug)]
pub(super) struct ResponderSession {
    transfer_id: u64,
    base_cut: Option<TerminalCut>,
    target_cut: TerminalCut,
    cursor_cut: Option<TerminalCut>,
    kind: StrictTerminalPageKind,
    next_cursor: u64,
    initial_nonce: u64,
    initial_page: Option<StrictTerminalSyncPage>,
    final_nonce: Option<u64>,
    cached_nonce: Option<u64>,
    cached_page: Option<StrictTerminalSyncPage>,
    expires_at: Instant,
}

#[derive(Clone, Copy, Debug)]
struct ProbeNonce {
    value: u64,
    reason: i32,
    admission_pending: bool,
    expires_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AcceptedHistoryProbe {
    reason: i32,
    admission_pending: bool,
}

impl AcceptedHistoryProbe {
    pub(super) fn reason(self) -> i32 {
        self.reason
    }

    pub(super) fn admission_pending(self) -> bool {
        self.admission_pending
    }
}

#[derive(Clone, Copy, Debug)]
struct CompletedResponder {
    transfer_id: u64,
    initial_nonce: u64,
    final_nonce: u64,
    target_cut: TerminalCut,
    expires_at: Instant,
}

#[derive(Clone, Copy, Debug)]
struct PendingSourceTransition {
    previous_cut: TerminalCut,
    resulting_cut: TerminalCut,
}

#[derive(Clone, Copy, Debug)]
struct DeferredClientIntent {
    reason: i32,
    desired_cut: Option<TerminalCut>,
}

impl DeferredClientIntent {
    fn merge(&mut self, reason: i32, desired_cut: Option<TerminalCut>) {
        if reason_priority(reason) > reason_priority(self.reason) {
            self.reason = reason;
        }
        if let Some(desired) = desired_cut {
            if self
                .desired_cut
                .is_none_or(|current| cut_advances(desired, current))
            {
                self.desired_cut = Some(desired);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InboundTerminalSyncDisposition {
    Accept,
    Deflect,
    Yielded { cancelled_nonce: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SourceTransitionOutcome {
    Advanced,
    Duplicate,
    Gap,
    Overflow,
    Rejected,
}

fn reason_priority(reason: i32) -> u8 {
    match StrictCatchupReason::try_from(reason).ok() {
        Some(StrictCatchupReason::TerminalFence) => 4,
        Some(StrictCatchupReason::HistoryElection | StrictCatchupReason::Admission) => 3,
        Some(StrictCatchupReason::PeerBehind | StrictCatchupReason::RepositoryGap) => 2,
        Some(
            StrictCatchupReason::SteadyState
            | StrictCatchupReason::OwnerAntiEntropy
            | StrictCatchupReason::LegacyV2,
        ) => 1,
        Some(StrictCatchupReason::DeliveryWatermark | StrictCatchupReason::Unspecified) | None => 0,
    }
}

fn cut_advances(candidate: TerminalCut, baseline: TerminalCut) -> bool {
    candidate.journal_id() != baseline.journal_id()
        || candidate.generation() > baseline.generation()
        || (candidate.generation() == baseline.generation() && candidate != baseline)
}

/// Whether an immutable source-journal cut is known to include `required`.
/// A later generation in the same lineage is sufficient because generations
/// are append-only. At the same generation every digest must match.
pub(super) fn source_cut_covers(candidate: TerminalCut, required: TerminalCut) -> bool {
    candidate.journal_id() == required.journal_id()
        && (candidate.generation() > required.generation()
            || (candidate.generation() == required.generation() && candidate == required))
}

impl ClientSession {
    fn merge_intent(&mut self, reason: i32, desired_cut: Option<TerminalCut>) {
        if reason_priority(reason) > reason_priority(self.reason) {
            self.reason = reason;
        }
        // Once a responder has advertised a fixed target, a newly observed
        // terminal fence can only be known to lie at or beyond that target.
        // Preserve one dirty follow-up even when the trigger did not carry an
        // explicit cut (the normal direct-decision path). Triggers coalesced
        // before the manifest arrives are already covered by the responder's
        // subsequently captured target.
        if desired_cut.is_none()
            && self.target_cut.is_some()
            && StrictCatchupReason::try_from(reason).ok()
                == Some(StrictCatchupReason::TerminalFence)
        {
            self.dirty = true;
        }
        if let Some(desired) = desired_cut {
            let baseline = self.target_cut.or(self.desired_cut).or(self.progress_cut);
            if baseline.is_some_and(|cut| cut_advances(desired, cut)) {
                self.dirty = true;
            }
            if self
                .desired_cut
                .is_none_or(|current| cut_advances(desired, current))
            {
                self.desired_cut = Some(desired);
            }
        }
    }

    pub(super) fn transfer_id(&self) -> u64 {
        self.transfer_id
    }

    pub(super) fn pending_nonce(&self) -> u64 {
        self.pending_nonce
    }

    pub(super) fn next_cursor(&self) -> u64 {
        self.next_cursor
    }

    pub(super) fn target_cut(&self) -> Option<TerminalCut> {
        self.target_cut
    }

    pub(super) fn progress_cut(&self) -> Option<TerminalCut> {
        self.progress_cut
    }

    pub(super) fn desired_cut(&self) -> Option<TerminalCut> {
        self.desired_cut
    }

    pub(super) fn kind(&self) -> Option<StrictTerminalPageKind> {
        self.kind
    }

    pub(super) fn reason(&self) -> i32 {
        self.reason
    }

    pub(super) fn started_reason(&self) -> i32 {
        self.started_reason
    }

    pub(super) fn dirty(&self) -> bool {
        self.dirty
    }

    pub(super) fn accept_manifest(
        &mut self,
        transfer_id: u64,
        target_cut: TerminalCut,
        kind: StrictTerminalPageKind,
        ttl: Duration,
    ) {
        self.transfer_id = transfer_id;
        self.target_cut = Some(target_cut);
        self.kind = Some(kind);
        self.expires_at = Instant::now() + ttl;
    }

    pub(super) fn set_progress_cut(&mut self, cut: TerminalCut) {
        self.progress_cut = Some(cut);
    }

    pub(super) fn prepare_continuation(&mut self, nonce: u64, next_cursor: u64) {
        self.pending_nonce = nonce;
        self.next_cursor = next_cursor;
    }
}

impl ResponderSession {
    pub(super) fn new(
        transfer_id: u64,
        base_cut: Option<TerminalCut>,
        target_cut: TerminalCut,
        kind: StrictTerminalPageKind,
        initial_nonce: u64,
        ttl: Duration,
    ) -> Self {
        Self {
            transfer_id,
            base_cut,
            target_cut,
            cursor_cut: base_cut,
            kind,
            next_cursor: if kind == StrictTerminalPageKind::Delta {
                base_cut.map_or(0, |cut| cut.generation())
            } else {
                0
            },
            initial_nonce,
            initial_page: None,
            final_nonce: None,
            cached_nonce: None,
            cached_page: None,
            expires_at: Instant::now() + ttl,
        }
    }

    pub(super) fn transfer_id(&self) -> u64 {
        self.transfer_id
    }

    pub(super) fn base_cut(&self) -> Option<TerminalCut> {
        self.base_cut
    }

    pub(super) fn target_cut(&self) -> TerminalCut {
        self.target_cut
    }

    pub(super) fn cursor_cut(&self) -> Option<TerminalCut> {
        self.cursor_cut
    }

    pub(super) fn kind(&self) -> StrictTerminalPageKind {
        self.kind
    }

    pub(super) fn next_cursor(&self) -> u64 {
        self.next_cursor
    }

    pub(super) fn final_nonce(&self) -> Option<u64> {
        self.final_nonce
    }

    pub(super) fn cached_page_for(&self, nonce: u64) -> Option<StrictTerminalSyncPage> {
        if self.initial_nonce == nonce {
            return self.initial_page.clone();
        }
        (self.cached_nonce == Some(nonce))
            .then(|| self.cached_page.clone())
            .flatten()
    }

    pub(super) fn cached_page_nonce(&self) -> Option<u64> {
        self.cached_nonce
    }

    pub(super) fn record_page(
        &mut self,
        nonce: u64,
        page: StrictTerminalSyncPage,
        next_cursor: u64,
        progress: Option<TerminalCut>,
        ttl: Duration,
    ) {
        self.next_cursor = next_cursor;
        if let Some(progress) = progress {
            self.cursor_cut = Some(progress);
        }
        if self.initial_page.is_none() && nonce == self.initial_nonce {
            self.initial_page = Some(page.clone());
        }
        self.cached_nonce = Some(nonce);
        self.cached_page = Some(page.clone());
        self.expires_at = Instant::now() + ttl;
        if !page.has_more {
            self.final_nonce = Some(nonce);
        }
    }
}

pub(super) struct SyncV3State {
    next_id: u64,
    // The pure reducer is the lifecycle authority for each authenticated peer
    // incarnation. Payload caches below remain separate so network and journal
    // work can be executed after the reducer transition has committed.
    sessions: HashMap<PeerIncarnation, SessionState>,
    // A source cut represents durable terminal fences already installed in
    // the local journal. Keep the newest node-level proof across a remote
    // boot-epoch replacement so the new incarnation may validate and reuse
    // the same lineage. All transfer/probe state remains incarnation-scoped.
    durable_source_cuts: HashMap<NodeIdentifier, TerminalCut>,
    known_source_cuts: HashMap<PeerIncarnation, TerminalCut>,
    pending_source_transitions: HashMap<PeerIncarnation, BTreeMap<u64, PendingSourceTransition>>,
    // Recent verified direct-decision transitions let delayed lower
    // generations be classified as true duplicates instead of accepting any
    // chain position merely because its journal lineage matches.
    source_transition_history: HashMap<PeerIncarnation, BTreeMap<u64, PendingSourceTransition>>,
    clock_nonces: HashMap<PeerIncarnation, ProbeNonce>,
    history_nonces: HashMap<PeerIncarnation, ProbeNonce>,
    clients: HashMap<PeerIncarnation, ClientSession>,
    // A client remains lifecycle-active while its final ACK is in flight.
    // Keeping it out of `clients` prevents a duplicate final page from
    // creating another continuation, while keeping it here prevents a dirty
    // trigger from opening a replacement session before ACK delivery.
    finalizing_clients: HashMap<PeerIncarnation, ClientSession>,
    responders: HashMap<PeerIncarnation, ResponderSession>,
    // A simultaneous pull is serialized by node-ID: the lower node owns the
    // first requester direction. The losing requester intent is resumed only
    // after the winning responder direction completes, so it cannot branch
    // the transfer while still preserving a required reverse reconciliation.
    deferred_clients: HashMap<PeerIncarnation, DeferredClientIntent>,
    expired_deferred_clients: HashSet<PeerIncarnation>,
    completed_responders: HashMap<PeerIncarnation, CompletedResponder>,
}

impl Default for SyncV3State {
    fn default() -> Self {
        Self {
            next_id: 1,
            sessions: HashMap::new(),
            durable_source_cuts: HashMap::new(),
            known_source_cuts: HashMap::new(),
            pending_source_transitions: HashMap::new(),
            source_transition_history: HashMap::new(),
            clock_nonces: HashMap::new(),
            history_nonces: HashMap::new(),
            clients: HashMap::new(),
            finalizing_clients: HashMap::new(),
            responders: HashMap::new(),
            deferred_clients: HashMap::new(),
            expired_deferred_clients: HashSet::new(),
            completed_responders: HashMap::new(),
        }
    }
}

impl SyncV3State {
    /// Commit one pure session transition and return the I/O work it selected.
    ///
    /// A stale incarnation is ignored before a state entry can be created. A
    /// newer incarnation replaces all reducer state for the same node. The
    /// reducer's explicit restart event is also supported by moving the
    /// resulting state to the new incarnation key.
    pub(super) fn transition_session(
        &mut self,
        peer: PeerIncarnation,
        event: SessionEvent,
    ) -> Vec<SessionEffect> {
        let newest_epoch = self
            .sessions
            .keys()
            .filter(|candidate| candidate.node == peer.node)
            .map(|candidate| candidate.boot_epoch)
            .max();
        if newest_epoch.is_some_and(|epoch| epoch > peer.boot_epoch) {
            return vec![SessionEffect::Ignored];
        }
        if newest_epoch.is_some_and(|epoch| epoch < peer.boot_epoch) {
            self.sessions
                .retain(|candidate, _| candidate.node != peer.node);
        }

        let state = self
            .sessions
            .remove(&peer)
            .unwrap_or_else(|| SessionState::new(PeerEpoch::new(peer.boot_epoch)));
        let (state, effects) = session_reducer::transition(state, event);
        let state_peer = PeerIncarnation::new(peer.node, state.epoch().get());
        if state_peer != peer {
            self.sessions
                .retain(|candidate, _| candidate.node != peer.node);
        }
        self.sessions.insert(state_peer, state);
        effects
    }

    /// Whether the incarnation currently owns probe, transfer, apply, ACK, or
    /// coalesced dirty work in the production reducer.
    pub(super) fn has_session_work(&self, peer: PeerIncarnation) -> bool {
        self.sessions
            .get(&peer)
            .is_some_and(|state| !state.is_idle())
    }

    pub(super) fn next_id(&mut self) -> u64 {
        let id = self.next_id.max(1);
        self.next_id = id.wrapping_add(1).max(1);
        id
    }

    pub(super) fn expire(&mut self, now: Instant) {
        let expired_clients: Vec<_> = self
            .clients
            .iter()
            .filter_map(|(peer, session)| (session.expires_at <= now).then_some(*peer))
            .collect();
        self.clients.retain(|_, session| {
            let retain = session.expires_at > now;
            if !retain {
                record_ended_client(session.started_reason, StrictCatchupSessionOutcome::Expired);
            }
            retain
        });
        let expired_finalizing: Vec<_> = self
            .finalizing_clients
            .iter()
            .filter_map(|(peer, session)| (session.expires_at <= now).then_some(*peer))
            .collect();
        self.finalizing_clients.retain(|_, session| {
            let retain = session.expires_at > now;
            if !retain {
                record_ended_client(session.started_reason, StrictCatchupSessionOutcome::Expired);
            }
            retain
        });
        let expired_responders: Vec<_> = self
            .responders
            .iter()
            .filter_map(|(peer, session)| (session.expires_at <= now).then_some(*peer))
            .collect();
        self.responders
            .retain(|_, session| session.expires_at > now);
        for peer in expired_responders.iter().copied() {
            if self.deferred_clients.contains_key(&peer) {
                self.expired_deferred_clients.insert(peer);
            }
        }
        let expired_lifecycles: HashSet<_> = expired_clients
            .into_iter()
            .chain(expired_finalizing)
            .chain(expired_responders)
            .collect();
        for peer in expired_lifecycles {
            let Some(wire) = self.sessions.get(&peer).and_then(SessionState::active_wire) else {
                continue;
            };
            let _ = self.transition_session(
                peer,
                SessionEvent::TransferExpired {
                    epoch: PeerEpoch::new(peer.boot_epoch),
                    wire,
                },
            );
            debug_assert!(
                !self.has_session_work(peer),
                "expired payload cache left reducer lifecycle active"
            );
        }
        self.completed_responders
            .retain(|_, completed| completed.expires_at > now);
        self.clock_nonces.retain(|_, nonce| nonce.expires_at > now);
        self.history_nonces
            .retain(|_, nonce| nonce.expires_at > now);
    }

    pub(super) fn known_source_cut(&self, peer: PeerIncarnation) -> Option<TerminalCut> {
        self.known_source_cuts.get(&peer).copied()
    }

    // A reusable cut is safe to offer to a replacement as an untrusted
    // baseline. It must not escape through `known_source_cut`, whose callers
    // use exact-incarnation knowledge for no-transfer fast paths.
    fn reusable_source_cut(&self, peer: PeerIncarnation) -> Option<TerminalCut> {
        self.known_source_cuts
            .get(&peer)
            .copied()
            .or_else(|| self.durable_source_cuts.get(&peer.node).copied())
    }

    pub(super) fn remember_source_cut(&mut self, peer: PeerIncarnation, cut: TerminalCut) {
        let exact_known = self.known_source_cuts.get(&peer).copied();
        if exact_known.is_some_and(|known| source_cut_covers(known, cut)) {
            // Once this exact incarnation has authenticated a cut, a delayed
            // lower response cannot regress it.  A node-level cut from an
            // older incarnation is deliberately excluded from this check:
            // the replacement must prove what its current journal owns.
            return;
        }
        let reusable = self.reusable_source_cut(peer);
        let lineage_changed = reusable.is_some_and(|known| known.journal_id() != cut.journal_id());
        // `cut` is fresh authenticated evidence from this boot epoch.  It
        // replaces (and may legitimately be below) the durable cut offered
        // from a prior incarnation, as after restoring an older journal.
        self.known_source_cuts.insert(peer, cut);
        self.durable_source_cuts.insert(peer.node, cut);
        if lineage_changed {
            self.pending_source_transitions.remove(&peer);
            self.source_transition_history.remove(&peer);
            return;
        }
        let remove_pending = if let Some(pending) = self.pending_source_transitions.get_mut(&peer) {
            pending.retain(|generation, _| *generation > cut.generation());
            pending.is_empty()
        } else {
            false
        };
        if remove_pending {
            self.pending_source_transitions.remove(&peer);
        }
    }

    pub(super) fn observe_source_transition(
        &mut self,
        peer: PeerIncarnation,
        previous_cut: TerminalCut,
        resulting_cut: TerminalCut,
        max_pending: usize,
    ) -> SourceTransitionOutcome {
        if previous_cut.journal_id() != resulting_cut.journal_id()
            || previous_cut.generation().checked_add(1) != Some(resulting_cut.generation())
        {
            return SourceTransitionOutcome::Rejected;
        }
        let known = self.reusable_source_cut(peer);
        if known.is_none() && previous_cut.generation() == 0 {
            self.known_source_cuts.insert(peer, resulting_cut);
            self.durable_source_cuts.insert(peer.node, resulting_cut);
            self.record_source_transition(peer, previous_cut, resulting_cut, max_pending);
            self.drain_source_transitions(peer, max_pending);
            return SourceTransitionOutcome::Advanced;
        }
        let Some(known) = known else {
            return self.store_source_gap(peer, previous_cut, resulting_cut, max_pending);
        };
        if resulting_cut == known {
            return SourceTransitionOutcome::Duplicate;
        }
        if resulting_cut.generation() < known.generation() {
            let historical_match = self
                .source_transition_history
                .get(&peer)
                .and_then(|history| history.get(&resulting_cut.generation()))
                .is_some_and(|transition| {
                    transition
                        .previous_cut
                        .has_same_chain_position(&previous_cut)
                        && transition.resulting_cut == resulting_cut
                });
            return if historical_match {
                SourceTransitionOutcome::Duplicate
            } else {
                SourceTransitionOutcome::Rejected
            };
        }
        if resulting_cut.generation() == known.generation() {
            return SourceTransitionOutcome::Rejected;
        }
        if previous_cut.generation() == known.generation()
            && previous_cut.journal_id() == known.journal_id()
            && previous_cut.chain_digest() == known.chain_digest()
        {
            self.known_source_cuts.insert(peer, resulting_cut);
            self.durable_source_cuts.insert(peer.node, resulting_cut);
            self.record_source_transition(peer, previous_cut, resulting_cut, max_pending);
            self.drain_source_transitions(peer, max_pending);
            return SourceTransitionOutcome::Advanced;
        }
        self.store_source_gap(peer, previous_cut, resulting_cut, max_pending)
    }

    fn store_source_gap(
        &mut self,
        peer: PeerIncarnation,
        previous_cut: TerminalCut,
        resulting_cut: TerminalCut,
        max_pending: usize,
    ) -> SourceTransitionOutcome {
        let pending = self.pending_source_transitions.entry(peer).or_default();
        if pending.len() >= max_pending.max(1) && !pending.contains_key(&resulting_cut.generation())
        {
            pending.clear();
            return SourceTransitionOutcome::Overflow;
        }
        let transition = PendingSourceTransition {
            previous_cut,
            resulting_cut,
        };
        if let Some(existing) = pending.get(&resulting_cut.generation()) {
            return if existing.previous_cut.has_same_chain_position(&previous_cut)
                && existing.resulting_cut == resulting_cut
            {
                SourceTransitionOutcome::Gap
            } else {
                SourceTransitionOutcome::Rejected
            };
        }
        pending.insert(resulting_cut.generation(), transition);
        SourceTransitionOutcome::Gap
    }

    fn record_source_transition(
        &mut self,
        peer: PeerIncarnation,
        previous_cut: TerminalCut,
        resulting_cut: TerminalCut,
        max_history: usize,
    ) {
        let history = self.source_transition_history.entry(peer).or_default();
        history.insert(
            resulting_cut.generation(),
            PendingSourceTransition {
                previous_cut,
                resulting_cut,
            },
        );
        let limit = max_history.max(1);
        while history.len() > limit {
            let Some(oldest) = history.keys().next().copied() else {
                break;
            };
            history.remove(&oldest);
        }
    }

    fn drain_source_transitions(&mut self, peer: PeerIncarnation, max_history: usize) {
        loop {
            let Some(known) = self.reusable_source_cut(peer) else {
                break;
            };
            let next_generation = known.generation().saturating_add(1);
            let Some(transition) = self
                .pending_source_transitions
                .get(&peer)
                .and_then(|pending| pending.get(&next_generation))
                .copied()
            else {
                break;
            };
            if transition.previous_cut.journal_id() != known.journal_id()
                || transition.previous_cut.generation() != known.generation()
                || transition.previous_cut.chain_digest() != known.chain_digest()
            {
                break;
            }
            self.known_source_cuts
                .insert(peer, transition.resulting_cut);
            self.durable_source_cuts
                .insert(peer.node, transition.resulting_cut);
            self.record_source_transition(
                peer,
                transition.previous_cut,
                transition.resulting_cut,
                max_history,
            );
            if let Some(pending) = self.pending_source_transitions.get_mut(&peer) {
                pending.remove(&next_generation);
            }
        }
        if self
            .pending_source_transitions
            .get(&peer)
            .is_some_and(BTreeMap::is_empty)
        {
            self.pending_source_transitions.remove(&peer);
        }
    }

    pub(super) fn record_clock_nonce(
        &mut self,
        peer: PeerIncarnation,
        ttl: Duration,
    ) -> Option<u64> {
        self.expire(Instant::now());
        if self.clients.contains_key(&peer) || self.responders.contains_key(&peer) {
            return None;
        }
        if let Some(pending) = self.clock_nonces.get_mut(&peer) {
            // A probe is a replayable metadata request, not transfer work.
            // Keep one identity across retries so a delayed response remains
            // correlated without allocating a second outstanding nonce.
            pending.expires_at = Instant::now() + ttl;
            return Some(pending.value);
        }
        let nonce = self.next_id();
        self.clock_nonces.insert(
            peer,
            ProbeNonce {
                value: nonce,
                reason: StrictCatchupReason::DeliveryWatermark as i32,
                admission_pending: false,
                expires_at: Instant::now() + ttl,
            },
        );
        Some(nonce)
    }

    pub(super) fn accept_clock_nonce(&mut self, peer: PeerIncarnation, nonce: u64) -> bool {
        if self.clock_nonces.get(&peer).map(|pending| pending.value) != Some(nonce) {
            return false;
        }
        self.clock_nonces.remove(&peer);
        true
    }

    pub(super) fn cancel_clock_nonce(&mut self, peer: PeerIncarnation, nonce: u64) {
        if self.clock_nonces.get(&peer).map(|pending| pending.value) == Some(nonce) {
            self.clock_nonces.remove(&peer);
        }
    }

    pub(super) fn record_history_nonce(
        &mut self,
        peer: PeerIncarnation,
        reason: i32,
        ttl: Duration,
    ) -> Option<u64> {
        self.expire(Instant::now());
        // Ordinary probes stand down behind transfer work. A history election
        // is different: omitting this live peer would make the election rank
        // only a subset. Its bounded metadata probe may coexist; any selected
        // terminal/history transfer still merges through the one client
        // coordinator below.
        if reason != StrictCatchupReason::HistoryElection as i32
            && (self.clients.contains_key(&peer) || self.responders.contains_key(&peer))
        {
            return None;
        }
        if let Some(pending) = self.history_nonces.get_mut(&peer) {
            pending.admission_pending |= reason == StrictCatchupReason::Admission as i32;
            // Admission and history election share a session priority tier,
            // but the election collector must own this response. Promote (or
            // reissue after a rearm) the existing probe while preserving its
            // nonce, so a lost older attempt cannot suppress a candidate.
            if reason == StrictCatchupReason::HistoryElection as i32
                || reason_priority(reason) > reason_priority(pending.reason)
            {
                pending.reason = reason;
            }
            // Retry the same request identity even when this trigger has no
            // higher priority. This repairs a request that was enqueued
            // before the remote topic existed without branching the probe.
            pending.expires_at = Instant::now() + ttl;
            return Some(pending.value);
        }
        let nonce = self.next_id();
        self.history_nonces.insert(
            peer,
            ProbeNonce {
                value: nonce,
                reason,
                admission_pending: reason == StrictCatchupReason::Admission as i32,
                expires_at: Instant::now() + ttl,
            },
        );
        Some(nonce)
    }

    pub(super) fn accept_history_nonce(
        &mut self,
        peer: PeerIncarnation,
        nonce: u64,
    ) -> Option<AcceptedHistoryProbe> {
        if self.history_nonces.get(&peer).map(|pending| pending.value) != Some(nonce) {
            return None;
        }
        self.history_nonces
            .remove(&peer)
            .map(|pending| AcceptedHistoryProbe {
                reason: pending.reason,
                admission_pending: pending.admission_pending,
            })
    }

    pub(super) fn cancel_history_nonce(&mut self, peer: PeerIncarnation, nonce: u64) {
        if self.history_nonces.get(&peer).map(|pending| pending.value) == Some(nonce) {
            self.history_nonces.remove(&peer);
        }
    }

    /// Whether this peer incarnation already owns coordinator work that a
    /// periodic repair trigger must not branch. Explicit protocol progress
    /// (a correlated continuation, ACK, or the admission probe pair) is not
    /// gated through this helper.
    pub(super) fn has_periodic_work(&self, peer: PeerIncarnation) -> bool {
        self.has_session_work(peer)
            || self.clients.contains_key(&peer)
            || self.finalizing_clients.contains_key(&peer)
            || self.responders.contains_key(&peer)
    }

    pub(super) fn coalesce_terminal_intent_if_active(
        &mut self,
        peer: PeerIncarnation,
        reason: i32,
        desired_cut: Option<TerminalCut>,
    ) -> bool {
        self.expire(Instant::now());
        if let Some(active) = self.clients.get_mut(&peer) {
            active.merge_intent(reason, desired_cut);
            return true;
        }
        if let Some(finalizing) = self.finalizing_clients.get_mut(&peer) {
            finalizing.merge_intent(reason, desired_cut);
            return true;
        }
        if self.responders.contains_key(&peer) {
            self.defer_client(peer, reason, desired_cut);
            return true;
        }
        false
    }

    #[cfg(test)]
    pub(super) fn begin_client(
        &mut self,
        peer: PeerIncarnation,
        reason: i32,
        ttl: Duration,
    ) -> Option<(u64, Option<TerminalCut>)> {
        self.begin_client_with_desired(peer, reason, None, ttl)
    }

    #[cfg(test)]
    pub(super) fn begin_client_with_desired(
        &mut self,
        peer: PeerIncarnation,
        reason: i32,
        desired_cut: Option<TerminalCut>,
        ttl: Duration,
    ) -> Option<(u64, Option<TerminalCut>)> {
        self.expire(Instant::now());
        if let Some(active) = self.clients.get_mut(&peer) {
            active.merge_intent(reason, desired_cut);
            return None;
        }
        if let Some(finalizing) = self.finalizing_clients.get_mut(&peer) {
            finalizing.merge_intent(reason, desired_cut);
            return None;
        }
        if self.responders.contains_key(&peer) {
            self.defer_client(peer, reason, desired_cut);
            return None;
        }
        let mut reason = reason;
        let mut desired_cut = desired_cut;
        if let Some(deferred) = self.deferred_clients.remove(&peer) {
            self.expired_deferred_clients.remove(&peer);
            if reason_priority(deferred.reason) > reason_priority(reason) {
                reason = deferred.reason;
            }
            if let Some(deferred_cut) = deferred.desired_cut {
                if desired_cut.is_none_or(|current| cut_advances(deferred_cut, current)) {
                    desired_cut = Some(deferred_cut);
                }
            }
        }
        let nonce = self.next_id();
        let known_source_cut = self.reusable_source_cut(peer);
        self.clients.insert(
            peer,
            ClientSession {
                transfer_id: 0,
                pending_nonce: nonce,
                next_cursor: 0,
                target_cut: None,
                progress_cut: known_source_cut,
                desired_cut,
                kind: None,
                started_reason: reason,
                reason,
                dirty: false,
                expires_at: Instant::now() + ttl,
            },
        );
        Some((nonce, known_source_cut))
    }

    /// Install only the payload cache for a terminal client whose lifecycle
    /// and wire identity were already created by the pure session reducer.
    pub(super) fn begin_terminal_client_cache(
        &mut self,
        peer: PeerIncarnation,
        reason: i32,
        desired_cut: Option<TerminalCut>,
        nonce: u64,
        cursor: u64,
        ttl: Duration,
    ) -> Option<TerminalCut> {
        let known_source_cut = self.reusable_source_cut(peer);
        self.clients.insert(
            peer,
            ClientSession {
                transfer_id: 0,
                pending_nonce: nonce,
                next_cursor: cursor,
                target_cut: None,
                progress_cut: known_source_cut,
                desired_cut,
                kind: None,
                started_reason: reason,
                reason,
                dirty: false,
                expires_at: Instant::now() + ttl,
            },
        );
        known_source_cut
    }

    fn defer_client(
        &mut self,
        peer: PeerIncarnation,
        reason: i32,
        desired_cut: Option<TerminalCut>,
    ) {
        self.deferred_clients
            .entry(peer)
            .and_modify(|intent| intent.merge(reason, desired_cut))
            .or_insert(DeferredClientIntent {
                reason,
                desired_cut,
            });
    }

    /// Resolve an initial inbound terminal-sync request against an outbound
    /// client for the same authenticated incarnation. The lower node ID owns
    /// the first requester direction. The higher node cancels its wire retry,
    /// retains its intent, and serves the lower node. Continuations never use
    /// this arbitration because their responder direction is already fixed.
    pub(super) fn resolve_inbound_terminal_start(
        &mut self,
        local_node: NodeIdentifier,
        peer: PeerIncarnation,
    ) -> InboundTerminalSyncDisposition {
        if self.finalizing_clients.contains_key(&peer) {
            return InboundTerminalSyncDisposition::Deflect;
        }
        if self.responders.contains_key(&peer) || !self.clients.contains_key(&peer) {
            return InboundTerminalSyncDisposition::Accept;
        }
        if local_node < peer.node {
            return InboundTerminalSyncDisposition::Deflect;
        }
        let session = self
            .clients
            .remove(&peer)
            .expect("checked terminal client exists");
        let cancelled_nonce = session.pending_nonce;
        self.defer_client(peer, session.reason, session.desired_cut);
        record_ended_client(
            session.started_reason,
            StrictCatchupSessionOutcome::Cancelled,
        );
        InboundTerminalSyncDisposition::Yielded { cancelled_nonce }
    }

    pub(super) fn take_deferred_client(
        &mut self,
        peer: PeerIncarnation,
    ) -> Option<(i32, Option<TerminalCut>)> {
        self.expired_deferred_clients.remove(&peer);
        self.deferred_clients
            .remove(&peer)
            .map(|intent| (intent.reason, intent.desired_cut))
    }

    pub(super) fn take_expired_deferred_clients(
        &mut self,
    ) -> Vec<(PeerIncarnation, i32, Option<TerminalCut>)> {
        let ready: Vec<_> = self.expired_deferred_clients.drain().collect();
        ready
            .into_iter()
            .filter_map(|peer| {
                if self.clients.contains_key(&peer)
                    || self.finalizing_clients.contains_key(&peer)
                    || self.responders.contains_key(&peer)
                {
                    return None;
                }
                self.deferred_clients
                    .remove(&peer)
                    .map(|intent| (peer, intent.reason, intent.desired_cut))
            })
            .collect()
    }

    pub(super) fn client(&self, peer: PeerIncarnation) -> Option<&ClientSession> {
        self.clients.get(&peer)
    }

    pub(super) fn client_mut(&mut self, peer: PeerIncarnation) -> Option<&mut ClientSession> {
        self.clients.get_mut(&peer)
    }

    pub(super) fn finish_client(&mut self, peer: PeerIncarnation) -> Option<ClientSession> {
        self.clients.remove(&peer)
    }

    /// Move a completed terminal transfer into its final-ACK handshake.
    ///
    /// The returned clone lets the caller build and send the ACK without
    /// surrendering ownership of the session lifecycle. A duplicate final
    /// page observes the finalizing entry and returns `None`.
    pub(super) fn begin_client_finalization(
        &mut self,
        peer: PeerIncarnation,
    ) -> Option<ClientSession> {
        if self.finalizing_clients.contains_key(&peer) {
            return None;
        }
        let session = self.clients.remove(&peer)?;
        self.finalizing_clients.insert(peer, session.clone());
        Some(session)
    }

    /// Complete only the exact final-ACK handshake currently owned by this
    /// peer incarnation. Delayed ACK delivery from another transfer cannot
    /// release the session lease or start a dirty follow-up.
    pub(super) fn finish_client_finalization(
        &mut self,
        peer: PeerIncarnation,
        transfer_id: u64,
        nonce: u64,
        target_cut: TerminalCut,
    ) -> Option<ClientSession> {
        let matches = self.finalizing_clients.get(&peer).is_some_and(|session| {
            session.transfer_id == transfer_id
                && session.pending_nonce == nonce
                && session.target_cut == Some(target_cut)
        });
        matches
            .then(|| self.finalizing_clients.remove(&peer))
            .flatten()
    }

    pub(super) fn responder(&self, peer: PeerIncarnation) -> Option<&ResponderSession> {
        self.responders.get(&peer)
    }

    pub(super) fn responder_mut(&mut self, peer: PeerIncarnation) -> Option<&mut ResponderSession> {
        self.responders.get_mut(&peer)
    }

    pub(super) fn insert_responder(&mut self, peer: PeerIncarnation, session: ResponderSession) {
        self.responders.insert(peer, session);
    }

    pub(super) fn remove_responder(&mut self, peer: PeerIncarnation) -> Option<ResponderSession> {
        self.responders.remove(&peer)
    }

    pub(super) fn acknowledge_responder(
        &mut self,
        peer: PeerIncarnation,
        transfer_id: u64,
        final_nonce: u64,
        target_cut: TerminalCut,
        ttl: Duration,
    ) -> bool {
        let Some(session) = self.responders.get(&peer) else {
            return self
                .completed_responders
                .get(&peer)
                .is_some_and(|completed| {
                    completed.transfer_id == transfer_id
                        && completed.final_nonce == final_nonce
                        && completed.target_cut == target_cut
                });
        };
        if session.transfer_id != transfer_id
            || session.final_nonce != Some(final_nonce)
            || session.target_cut != target_cut
        {
            return false;
        }
        let session = self
            .responders
            .remove(&peer)
            .expect("checked responder exists");
        self.completed_responders.insert(
            peer,
            CompletedResponder {
                transfer_id,
                initial_nonce: session.initial_nonce,
                final_nonce,
                target_cut,
                expires_at: Instant::now() + ttl,
            },
        );
        true
    }

    pub(super) fn completed_matches_request(
        &self,
        peer: PeerIncarnation,
        transfer_id: u64,
        nonce: u64,
    ) -> bool {
        self.completed_responders
            .get(&peer)
            .is_some_and(|completed| {
                (transfer_id != 0 && completed.transfer_id == transfer_id)
                    || (transfer_id == 0 && completed.initial_nonce == nonce)
            })
    }

    /// Move the lifecycle reducer to a replacement incarnation before
    /// dropping payload caches owned by the departed one. This keeps retry,
    /// bulk-release, and dirty-session cancellation decisions in the reducer
    /// instead of reconstructing them from the cache maps.
    pub(super) fn restart_peer(
        &mut self,
        node: NodeIdentifier,
        new_boot_epoch: u64,
    ) -> Vec<SessionEffect> {
        let previous = self
            .sessions
            .keys()
            .filter(|peer| peer.node == node && peer.boot_epoch < new_boot_epoch)
            .max_by_key(|peer| peer.boot_epoch)
            .copied();
        let effects = previous.map_or_else(Vec::new, |peer| {
            self.transition_session(
                peer,
                SessionEvent::PeerRestarted {
                    new_epoch: PeerEpoch::new(new_boot_epoch),
                },
            )
        });
        self.discard_peer_payload(node, true);
        effects
    }

    pub(super) fn discard_peer(&mut self, node: NodeIdentifier, restarted: bool) {
        // `durable_source_cuts` intentionally survives. It is only an offered
        // baseline; a replacement responder must validate that it still owns
        // the same journal lineage before continuing from it.
        self.sessions.retain(|peer, _| peer.node != node);
        self.discard_peer_payload(node, restarted);
    }

    fn discard_peer_payload(&mut self, node: NodeIdentifier, restarted: bool) {
        self.known_source_cuts.retain(|peer, _| peer.node != node);
        self.pending_source_transitions
            .retain(|peer, _| peer.node != node);
        self.source_transition_history
            .retain(|peer, _| peer.node != node);
        self.clock_nonces.retain(|peer, _| peer.node != node);
        self.history_nonces.retain(|peer, _| peer.node != node);
        self.clients.retain(|peer, session| {
            let retain = peer.node != node;
            if !retain {
                if restarted {
                    let reason = CatchupReason::from_v3_wire(session.reason)
                        .unwrap_or(CatchupReason::TerminalFence);
                    metrics::record_strict_catchup_session_event(
                        reason,
                        StrictCatchupSessionEvent::Restart,
                    );
                }
                record_ended_client(
                    session.started_reason,
                    StrictCatchupSessionOutcome::IncarnationMismatch,
                );
            }
            retain
        });
        self.finalizing_clients.retain(|peer, session| {
            let retain = peer.node != node;
            if !retain {
                if restarted {
                    let reason = CatchupReason::from_v3_wire(session.reason)
                        .unwrap_or(CatchupReason::TerminalFence);
                    metrics::record_strict_catchup_session_event(
                        reason,
                        StrictCatchupSessionEvent::Restart,
                    );
                }
                record_ended_client(
                    session.started_reason,
                    StrictCatchupSessionOutcome::IncarnationMismatch,
                );
            }
            retain
        });
        self.responders.retain(|peer, _| peer.node != node);
        self.deferred_clients.retain(|peer, _| peer.node != node);
        self.expired_deferred_clients
            .retain(|peer| peer.node != node);
        self.completed_responders
            .retain(|peer, _| peer.node != node);
    }

    pub(super) fn cancel_clients(&mut self) {
        for (_, session) in self.clients.drain() {
            record_ended_client(
                session.started_reason,
                StrictCatchupSessionOutcome::Cancelled,
            );
        }
        for (_, session) in self.finalizing_clients.drain() {
            record_ended_client(
                session.started_reason,
                StrictCatchupSessionOutcome::Cancelled,
            );
        }
        self.deferred_clients.clear();
        self.expired_deferred_clients.clear();
        self.sessions.clear();
    }
}

fn record_ended_client(reason: i32, outcome: StrictCatchupSessionOutcome) {
    let reason = CatchupReason::from_v3_wire(reason).unwrap_or(CatchupReason::TerminalFence);
    metrics::record_strict_catchup_session_completion(reason, outcome);
}

pub(super) fn cut_to_wire(cut: TerminalCut) -> StrictTerminalCut {
    StrictTerminalCut {
        journal_id: Bytes::copy_from_slice(cut.journal_id()),
        generation: cut.generation(),
        chain_digest: Bytes::copy_from_slice(cut.chain_digest()),
        terminal_set_digest: Bytes::copy_from_slice(cut.terminal_set_digest()),
    }
}

pub(super) fn cut_from_wire(cut: &StrictTerminalCut) -> Option<TerminalCut> {
    let journal_id: [u8; JOURNAL_ID_LEN] = cut.journal_id.as_ref().try_into().ok()?;
    let chain_digest: [u8; DIGEST_LEN] = cut.chain_digest.as_ref().try_into().ok()?;
    let terminal_set_digest: [u8; DIGEST_LEN] = cut.terminal_set_digest.as_ref().try_into().ok()?;
    if journal_id == [0; JOURNAL_ID_LEN] || (cut.generation == 0 && chain_digest != [0; DIGEST_LEN])
    {
        return None;
    }
    Some(TerminalCut::new(
        journal_id,
        cut.generation,
        chain_digest,
        terminal_set_digest,
    ))
}

pub(super) fn cut_to_reducer(cut: TerminalCut) -> ReducerCut {
    ReducerCut::new(
        *cut.journal_id(),
        cut.generation(),
        *cut.chain_digest(),
        *cut.terminal_set_digest(),
    )
}
