//! Pure lifecycle reducer for one strict catchup peer incarnation.
//!
//! Payload construction, durable application, clocks, and network I/O are
//! deliberately outside this module. Production adapters feed their results
//! back as events and execute the returned effects after committing the new
//! state. Keeping correlation and lifecycle decisions here makes the same
//! transition function usable by bounded model tests.

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PeerEpoch(u64);

impl PeerEpoch {
    pub(super) fn new(value: u64) -> Self {
        Self(value)
    }

    pub(super) fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct WireNonce(u64);

impl WireNonce {
    pub(super) fn new(value: u64) -> Option<Self> {
        (value != 0).then_some(Self(value))
    }

    pub(super) fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct TransferId(u64);

impl TransferId {
    pub(super) fn new(value: u64) -> Self {
        Self(value)
    }

    pub(super) fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum CursorKind {
    TerminalGeneration,
    HistoryLogVersion,
    HistorySnapshotByte,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Cursor {
    kind: CursorKind,
    value: u64,
}

impl Cursor {
    pub(super) fn new(kind: CursorKind, value: u64) -> Self {
        Self { kind, value }
    }

    #[allow(dead_code)]
    pub(super) fn kind(self) -> CursorKind {
        self.kind
    }

    pub(super) fn value(self) -> u64 {
        self.value
    }

    fn may_advance_to(self, next: Self) -> bool {
        (self.kind == next.kind && self.value <= next.value)
            || (self.kind == CursorKind::HistorySnapshotByte
                && next.kind == CursorKind::HistoryLogVersion)
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Cut {
    journal_id: [u8; 16],
    generation: u64,
    chain_digest: [u8; 32],
    terminal_set_digest: [u8; 32],
}

impl Cut {
    pub(super) const fn new(
        journal_id: [u8; 16],
        generation: u64,
        chain_digest: [u8; 32],
        terminal_set_digest: [u8; 32],
    ) -> Self {
        Self {
            journal_id,
            generation,
            chain_digest,
            terminal_set_digest,
        }
    }

    #[allow(dead_code)]
    pub(super) const fn journal_id(self) -> [u8; 16] {
        self.journal_id
    }

    pub(super) const fn generation(self) -> u64 {
        self.generation
    }

    #[allow(dead_code)]
    pub(super) const fn chain_digest(self) -> [u8; 32] {
        self.chain_digest
    }

    #[allow(dead_code)]
    pub(super) const fn terminal_set_digest(self) -> [u8; 32] {
        self.terminal_set_digest
    }

    fn may_advance_to(self, next: Self) -> bool {
        self.journal_id == next.journal_id
            && (next.generation > self.generation
                || (next.generation == self.generation
                    && next.chain_digest == self.chain_digest
                    && next.terminal_set_digest == self.terminal_set_digest))
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) enum SyncKind {
    Terminal,
    History,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) enum ProbeKind {
    Clock,
    History,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) enum TriggerOrigin {
    External,
    Membership,
    CatchupApply,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) enum DecisionOrigin {
    Local,
    Direct,
    Catchup,
}

/// Result of deterministic node-id arbitration when both peers initiate at once.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) enum InboundArbitration {
    KeepCurrent,
    AcceptInbound,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) struct Trigger {
    pub(super) kind: SyncKind,
    pub(super) origin: TriggerOrigin,
    pub(super) desired_cut: Option<Cut>,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) struct WireIdentity {
    epoch: PeerEpoch,
    transfer: TransferId,
    nonce: WireNonce,
    cursor: Cursor,
}

impl WireIdentity {
    pub(super) fn new(
        epoch: PeerEpoch,
        transfer: TransferId,
        nonce: WireNonce,
        cursor: Cursor,
    ) -> Self {
        Self {
            epoch,
            transfer,
            nonce,
            cursor,
        }
    }

    #[allow(dead_code)]
    pub(super) fn epoch(self) -> PeerEpoch {
        self.epoch
    }

    pub(super) fn transfer(self) -> TransferId {
        self.transfer
    }

    pub(super) fn nonce(self) -> WireNonce {
        self.nonce
    }

    pub(super) fn cursor(self) -> Cursor {
        self.cursor
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) struct ClientState {
    kind: SyncKind,
    initial: WireIdentity,
    wire: WireIdentity,
    target_cut: Option<Cut>,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) struct ApplyingState {
    client: ClientState,
    page: WireIdentity,
    next_cursor: Cursor,
    target_cut: Cut,
    has_more: bool,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) struct ResponderState {
    kind: SyncKind,
    initial: WireIdentity,
    request: WireIdentity,
    page: WireIdentity,
    target_cut: Cut,
    next_cursor: Cursor,
    final_page: bool,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) struct FinalizingState {
    kind: SyncKind,
    initial: WireIdentity,
    page: WireIdentity,
    ack: WireIdentity,
    acknowledged_cut: Cut,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) struct ProbeState {
    kind: ProbeKind,
    wire: WireIdentity,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) enum SessionPhase {
    Idle,
    Probe(ProbeState),
    TerminalClient(ClientState),
    TerminalApplying(ApplyingState),
    TerminalPreparing(ResponderPreparingState),
    TerminalResponder(ResponderState),
    HistoryClient(ClientState),
    HistoryApplying(ApplyingState),
    HistoryPreparing(ResponderPreparingState),
    HistoryResponder(ResponderState),
    Finalizing(FinalizingState),
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) struct ResponderPreparingState {
    kind: SyncKind,
    initial: WireIdentity,
    request: WireIdentity,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum TombstoneOutcome {
    Completed,
    Expired,
    ApplyFailed,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct TransferTombstone {
    initial: WireIdentity,
    transfer: TransferId,
    final_page: Option<WireIdentity>,
    final_ack: Option<WireIdentity>,
    kind: SyncKind,
    outcome: TombstoneOutcome,
}

const MAX_TOMBSTONES: usize = 8;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(super) struct SessionState {
    epoch: PeerEpoch,
    phase: SessionPhase,
    dirty: Option<Trigger>,
    // The validated cut this node has applied from the peer. This is an
    // outbound-client cursor only. A peer ACKing a cut served by this node is
    // the opposite direction and must never advance it.
    terminal_acknowledged_cut: Option<Cut>,
    history_acknowledged_cursor: Option<Cursor>,
    tombstones: Vec<TransferTombstone>,
    retry_armed: bool,
    next_nonce: u64,
    next_transfer: u64,
    initial_triggers: u32,
    dirty_followups: u32,
    sessions_created: u32,
}

impl SessionState {
    pub(super) fn new(epoch: PeerEpoch) -> Self {
        Self {
            epoch,
            phase: SessionPhase::Idle,
            dirty: None,
            terminal_acknowledged_cut: None,
            history_acknowledged_cursor: None,
            tombstones: Vec::new(),
            retry_armed: false,
            next_nonce: 1,
            next_transfer: 1,
            initial_triggers: 0,
            dirty_followups: 0,
            sessions_created: 0,
        }
    }

    pub(super) fn epoch(&self) -> PeerEpoch {
        self.epoch
    }

    #[allow(dead_code)]
    pub(super) fn phase(&self) -> SessionPhase {
        self.phase
    }

    pub(super) fn is_idle(&self) -> bool {
        self.phase == SessionPhase::Idle && self.dirty.is_none()
    }

    #[allow(dead_code)]
    pub(super) fn outstanding_nonce(&self) -> Option<WireNonce> {
        phase_wire(self.phase).map(WireIdentity::nonce)
    }

    /// The sole wire identity currently owned by this peer-incarnation
    /// lifecycle, if any. Payload-cache expiry uses this exact identity to
    /// reconcile the production reducer instead of fabricating a cursor.
    pub(super) fn active_wire(&self) -> Option<WireIdentity> {
        phase_wire(self.phase)
    }

    #[allow(dead_code)]
    pub(super) fn acknowledged_cut(&self) -> Option<Cut> {
        self.terminal_acknowledged_cut
    }

    #[allow(dead_code)]
    pub(super) fn acknowledged_history_cursor(&self) -> Option<Cursor> {
        self.history_acknowledged_cursor
    }

    #[allow(dead_code)]
    pub(super) fn sessions_created(&self) -> u32 {
        self.sessions_created
    }

    #[allow(dead_code)]
    pub(super) fn session_budget(&self) -> u32 {
        self.initial_triggers.saturating_add(self.dirty_followups)
    }

    #[allow(dead_code)]
    pub(super) fn active_sessions(&self) -> usize {
        usize::from(self.phase != SessionPhase::Idle)
    }

    #[allow(dead_code)]
    pub(super) fn potential(&self) -> u64 {
        let phase = match self.phase {
            SessionPhase::Idle => 0,
            SessionPhase::Finalizing(_) => 1,
            SessionPhase::Probe(_) => 2,
            SessionPhase::TerminalResponder(_) | SessionPhase::HistoryResponder(_) => 2,
            SessionPhase::TerminalPreparing(_) | SessionPhase::HistoryPreparing(_) => 3,
            SessionPhase::TerminalApplying(_) | SessionPhase::HistoryApplying(_) => 3,
            SessionPhase::TerminalClient(_) | SessionPhase::HistoryClient(_) => 4,
        };
        phase + u64::from(self.dirty.is_some()) * 5
    }

    fn allocate_nonce(&mut self) -> WireNonce {
        let value = self.next_nonce.max(1);
        self.next_nonce = value.saturating_add(1).max(1);
        WireNonce(value)
    }

    fn allocate_transfer(&mut self) -> TransferId {
        let value = self.next_transfer.max(1);
        self.next_transfer = value.saturating_add(1).max(1);
        TransferId(value)
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) enum Event {
    /// Align a future outbound terminal client with durable, source-specific
    /// peer knowledge maintained outside the lifecycle reducer.
    SourceCutObserved {
        epoch: PeerEpoch,
        cut: Cut,
    },
    Trigger(Trigger),
    StartProbe {
        kind: ProbeKind,
    },
    ProbeResponse {
        epoch: PeerEpoch,
        nonce: WireNonce,
    },
    RequestReceived {
        kind: SyncKind,
        wire: WireIdentity,
        arbitration: InboundArbitration,
    },
    PagePrepared {
        kind: SyncKind,
        request: WireIdentity,
        next_cursor: Cursor,
        target_cut: Cut,
        has_more: bool,
    },
    UpToDateResponded {
        request: WireIdentity,
        target_cut: Cut,
        /// Equal canonical terminal sets satisfy a coalesced reverse pull;
        /// no reducer-only dirty client may be left behind.
        satisfies_dirty: bool,
    },
    PageReceived {
        kind: SyncKind,
        wire: WireIdentity,
        next_cursor: Cursor,
        target_cut: Cut,
        has_more: bool,
    },
    ApplySucceeded {
        epoch: PeerEpoch,
        wire: WireIdentity,
    },
    ApplyFailed {
        epoch: PeerEpoch,
        wire: WireIdentity,
    },
    AckReceived {
        epoch: PeerEpoch,
        wire: WireIdentity,
        cut: Cut,
    },
    FinalAckDelivered {
        epoch: PeerEpoch,
        wire: WireIdentity,
    },
    SendBackpressured {
        wire: WireIdentity,
    },
    RetryReady {
        wire: WireIdentity,
    },
    TransferExpired {
        epoch: PeerEpoch,
        wire: WireIdentity,
    },
    PeerRestarted {
        new_epoch: PeerEpoch,
    },
    TerminalDecision {
        epoch: PeerEpoch,
        origin: DecisionOrigin,
        cut: Cut,
    },
    TombstoneExpired {
        epoch: PeerEpoch,
        transfer: TransferId,
    },
    MessageLost {
        wire: WireIdentity,
    },
    MessageDelayed {
        wire: WireIdentity,
    },
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) enum Status {
    TransferExpired,
    CursorMismatch,
    IncarnationMismatch,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) enum Effect {
    StartSession {
        kind: SyncKind,
        wire: WireIdentity,
    },
    SendRequest {
        kind: SyncKind,
        wire: WireIdentity,
    },
    SendPage {
        kind: SyncKind,
        wire: WireIdentity,
    },
    SendCachedPage {
        kind: SyncKind,
        wire: WireIdentity,
    },
    PreparePage {
        kind: SyncKind,
        request: WireIdentity,
    },
    SendAck {
        kind: SyncKind,
        wire: WireIdentity,
        cut: Cut,
    },
    SendStatus {
        wire: WireIdentity,
        status: Status,
    },
    ValidateAndApply {
        kind: SyncKind,
        wire: WireIdentity,
    },
    Continue {
        kind: SyncKind,
        wire: WireIdentity,
    },
    ScheduleRetry {
        wire: WireIdentity,
    },
    CancelRetry {
        wire: WireIdentity,
    },
    ReleaseBulk {
        wire: WireIdentity,
    },
    ApplyDecision {
        origin: DecisionOrigin,
        cut: Cut,
    },
    FanoutDecision {
        cut: Cut,
    },
    Coalesced,
    DirtyFollowup,
    Ignored,
}

/// Pure production transition function for one peer incarnation.
pub(super) fn transition(mut state: SessionState, event: Event) -> (SessionState, Vec<Effect>) {
    let mut effects = Vec::new();
    match event {
        Event::SourceCutObserved { epoch, cut } => {
            if epoch != state.epoch
                || matches!(
                    state.phase,
                    SessionPhase::TerminalClient(_)
                        | SessionPhase::TerminalApplying(_)
                        | SessionPhase::Finalizing(_)
                )
            {
                effects.push(Effect::Ignored);
            } else {
                state.terminal_acknowledged_cut =
                    monotone_cut(state.terminal_acknowledged_cut, cut);
            }
        }
        Event::Trigger(trigger) => {
            if trigger.origin == TriggerOrigin::CatchupApply {
                effects.push(Effect::Ignored);
            } else if state.phase == SessionPhase::Idle {
                state.initial_triggers = state.initial_triggers.saturating_add(1);
                start_client(&mut state, trigger.kind, &mut effects, false);
            } else {
                merge_dirty(&mut state.dirty, trigger);
                effects.push(Effect::Coalesced);
            }
        }
        Event::StartProbe { kind } => {
            if state.phase != SessionPhase::Idle {
                effects.push(Effect::Coalesced);
            } else {
                let nonce = state.allocate_nonce();
                let wire = WireIdentity::new(
                    state.epoch,
                    TransferId(0),
                    nonce,
                    Cursor::new(CursorKind::HistoryLogVersion, 0),
                );
                state.phase = SessionPhase::Probe(ProbeState { kind, wire });
                effects.push(Effect::SendRequest {
                    kind: SyncKind::History,
                    wire,
                });
                arm_retry(&mut state, wire, &mut effects);
            }
        }
        Event::ProbeResponse { epoch, nonce } => {
            if epoch != state.epoch {
                effects.push(Effect::Ignored);
            } else if let SessionPhase::Probe(probe) = state.phase {
                if probe.wire.nonce == nonce {
                    state.phase = SessionPhase::Idle;
                    state.retry_armed = false;
                    effects.push(Effect::CancelRetry { wire: probe.wire });
                    start_dirty_if_ready(&mut state, &mut effects);
                } else {
                    effects.push(Effect::Ignored);
                }
            } else {
                effects.push(Effect::Ignored);
            }
        }
        Event::RequestReceived {
            kind,
            wire,
            arbitration,
        } => receive_request(&mut state, kind, wire, arbitration, &mut effects),
        Event::PagePrepared {
            kind,
            request,
            next_cursor,
            target_cut,
            has_more,
        } => page_prepared(
            &mut state,
            kind,
            request,
            next_cursor,
            target_cut,
            has_more,
            &mut effects,
        ),
        Event::UpToDateResponded {
            request,
            target_cut,
            satisfies_dirty,
        } => up_to_date_responded(
            &mut state,
            request,
            target_cut,
            satisfies_dirty,
            &mut effects,
        ),
        Event::PageReceived {
            kind,
            wire,
            next_cursor,
            target_cut,
            has_more,
        } => receive_page(
            &mut state,
            kind,
            wire,
            next_cursor,
            target_cut,
            has_more,
            &mut effects,
        ),
        Event::ApplySucceeded { epoch, wire } => {
            if epoch != state.epoch {
                effects.push(Effect::Ignored);
            } else {
                apply_succeeded(&mut state, wire, &mut effects);
            }
        }
        Event::ApplyFailed { epoch, wire } => {
            if epoch != state.epoch {
                effects.push(Effect::Ignored);
            } else if phase_wire(state.phase) == Some(wire)
                && matches!(
                    state.phase,
                    SessionPhase::TerminalApplying(_) | SessionPhase::HistoryApplying(_)
                )
            {
                let applying = applying(state.phase).expect("applying phase checked");
                remember_tombstone(
                    &mut state,
                    TransferTombstone {
                        initial: applying.client.initial,
                        transfer: wire.transfer,
                        final_page: None,
                        final_ack: None,
                        kind: applying.client.kind,
                        outcome: TombstoneOutcome::ApplyFailed,
                    },
                );
                state.phase = SessionPhase::Idle;
                state.retry_armed = false;
                effects.push(Effect::CancelRetry { wire });
                effects.push(Effect::ReleaseBulk { wire });
                start_dirty_if_ready(&mut state, &mut effects);
            } else {
                effects.push(Effect::Ignored);
            }
        }
        Event::AckReceived { epoch, wire, cut } => {
            if epoch != state.epoch {
                effects.push(Effect::Ignored);
            } else if let Some(responder) = responder(state.phase) {
                let expected_ack = WireIdentity::new(
                    state.epoch,
                    responder.page.transfer,
                    responder.page.nonce,
                    responder.next_cursor,
                );
                if expected_ack == wire && responder.final_page && responder.target_cut == cut {
                    remember_tombstone(
                        &mut state,
                        TransferTombstone {
                            initial: responder.initial,
                            transfer: responder.page.transfer,
                            final_page: Some(responder.page),
                            final_ack: Some(expected_ack),
                            kind: responder.kind,
                            outcome: TombstoneOutcome::Completed,
                        },
                    );
                    state.phase = SessionPhase::Idle;
                    state.retry_armed = false;
                    effects.push(Effect::CancelRetry {
                        wire: responder.page,
                    });
                    effects.push(Effect::ReleaseBulk { wire });
                    start_dirty_if_ready(&mut state, &mut effects);
                } else {
                    effects.push(Effect::Ignored);
                }
            } else {
                effects.push(Effect::Ignored);
            }
        }
        Event::FinalAckDelivered { epoch, wire } => {
            if epoch != state.epoch {
                effects.push(Effect::Ignored);
            } else if let SessionPhase::Finalizing(finalizing) = state.phase {
                if finalizing.ack == wire {
                    remember_tombstone(
                        &mut state,
                        TransferTombstone {
                            initial: finalizing.initial,
                            transfer: wire.transfer,
                            final_page: Some(finalizing.page),
                            final_ack: Some(finalizing.ack),
                            kind: finalizing.kind,
                            outcome: TombstoneOutcome::Completed,
                        },
                    );
                    state.phase = SessionPhase::Idle;
                    state.retry_armed = false;
                    effects.push(Effect::CancelRetry { wire });
                    start_dirty_if_ready(&mut state, &mut effects);
                } else {
                    effects.push(Effect::Ignored);
                }
            } else {
                effects.push(Effect::Ignored);
            }
        }
        Event::SendBackpressured { wire } => {
            if wire.epoch != state.epoch || phase_wire(state.phase) != Some(wire) {
                effects.push(Effect::Ignored);
            } else if matches!(
                state.phase,
                SessionPhase::TerminalApplying(_) | SessionPhase::HistoryApplying(_)
            ) {
                effects.push(Effect::Ignored);
            } else if state.retry_armed {
                effects.push(Effect::Ignored);
            } else {
                arm_retry(&mut state, wire, &mut effects);
            }
        }
        Event::RetryReady { wire } => {
            if wire.epoch != state.epoch
                || phase_wire(state.phase) != Some(wire)
                || !state.retry_armed
                || matches!(
                    state.phase,
                    SessionPhase::TerminalApplying(_) | SessionPhase::HistoryApplying(_)
                )
            {
                effects.push(Effect::Ignored);
            } else {
                state.retry_armed = false;
                effects.push(match state.phase {
                    SessionPhase::TerminalResponder(responder)
                    | SessionPhase::HistoryResponder(responder) => Effect::SendPage {
                        kind: responder.kind,
                        wire,
                    },
                    SessionPhase::Finalizing(finalizing) => Effect::SendAck {
                        kind: finalizing.kind,
                        wire,
                        cut: finalizing.acknowledged_cut,
                    },
                    SessionPhase::Probe(_) => Effect::SendRequest {
                        kind: SyncKind::History,
                        wire,
                    },
                    SessionPhase::TerminalClient(client) | SessionPhase::HistoryClient(client) => {
                        Effect::SendRequest {
                            kind: client.kind,
                            wire,
                        }
                    }
                    SessionPhase::TerminalPreparing(_) | SessionPhase::HistoryPreparing(_) => {
                        Effect::Ignored
                    }
                    SessionPhase::TerminalApplying(_) | SessionPhase::HistoryApplying(_) => {
                        Effect::Ignored
                    }
                    SessionPhase::Idle => Effect::Ignored,
                });
                arm_retry(&mut state, wire, &mut effects);
            }
        }
        Event::TransferExpired { epoch, wire } => {
            if epoch != state.epoch || phase_wire(state.phase) != Some(wire) {
                effects.push(Effect::Ignored);
            } else {
                let (initial, kind) =
                    phase_initial_and_kind(state.phase).unwrap_or((wire, SyncKind::Terminal));
                let final_page = responder(state.phase).map(|value| value.page);
                remember_tombstone(
                    &mut state,
                    TransferTombstone {
                        initial,
                        transfer: wire.transfer,
                        final_page,
                        final_ack: None,
                        kind,
                        outcome: TombstoneOutcome::Expired,
                    },
                );
                state.phase = SessionPhase::Idle;
                // Expiry is terminal for this transfer. In particular, it
                // must not reinterpret a coalesced intent as an automatic
                // cursor-zero restart; a later external trigger may start a
                // fresh, explicitly identified session.
                state.dirty = None;
                state.retry_armed = false;
                effects.push(Effect::CancelRetry { wire });
                effects.push(Effect::ReleaseBulk { wire });
            }
        }
        Event::PeerRestarted { new_epoch } => {
            if new_epoch > state.epoch {
                if let Some(wire) = phase_wire(state.phase) {
                    effects.push(Effect::CancelRetry { wire });
                    effects.push(Effect::ReleaseBulk { wire });
                }
                state.epoch = new_epoch;
                state.phase = SessionPhase::Idle;
                state.dirty = None;
                state.tombstones.clear();
                state.retry_armed = false;
            } else {
                effects.push(Effect::Ignored);
            }
        }
        Event::TerminalDecision { epoch, origin, cut } => {
            if epoch != state.epoch {
                effects.push(Effect::Ignored);
            } else {
                // A locally installed decision is not proof of what this peer knows.
                effects.push(Effect::ApplyDecision { origin, cut });
                if origin == DecisionOrigin::Local {
                    effects.push(Effect::FanoutDecision { cut });
                }
                if origin != DecisionOrigin::Catchup && state.phase != SessionPhase::Idle {
                    merge_dirty(
                        &mut state.dirty,
                        Trigger {
                            kind: SyncKind::Terminal,
                            origin: TriggerOrigin::External,
                            desired_cut: Some(cut),
                        },
                    );
                }
            }
        }
        Event::TombstoneExpired { epoch, transfer } => {
            if epoch != state.epoch {
                effects.push(Effect::Ignored);
            } else {
                state.tombstones.retain(|entry| entry.transfer != transfer);
            }
        }
        Event::MessageLost { wire } | Event::MessageDelayed { wire } => {
            if wire.epoch != state.epoch || phase_wire(state.phase) != Some(wire) {
                effects.push(Effect::Ignored);
            }
        }
    }
    (state, effects)
}

fn start_client(
    state: &mut SessionState,
    kind: SyncKind,
    effects: &mut Vec<Effect>,
    dirty_followup: bool,
) {
    let nonce = state.allocate_nonce();
    let cursor_kind = match kind {
        SyncKind::Terminal => CursorKind::TerminalGeneration,
        SyncKind::History => CursorKind::HistoryLogVersion,
    };
    let wire = WireIdentity::new(
        state.epoch,
        TransferId(0),
        nonce,
        Cursor::new(
            cursor_kind,
            match kind {
                SyncKind::Terminal => state.terminal_acknowledged_cut.map_or(0, Cut::generation),
                SyncKind::History => state
                    .history_acknowledged_cursor
                    .filter(|cursor| cursor.kind == CursorKind::HistoryLogVersion)
                    .map_or(0, |cursor| cursor.value),
            },
        ),
    );
    let client = ClientState {
        kind,
        initial: wire,
        wire,
        target_cut: None,
    };
    state.phase = match kind {
        SyncKind::Terminal => SessionPhase::TerminalClient(client),
        SyncKind::History => SessionPhase::HistoryClient(client),
    };
    state.sessions_created = state.sessions_created.saturating_add(1);
    if dirty_followup {
        state.dirty_followups = state.dirty_followups.saturating_add(1);
        effects.push(Effect::DirtyFollowup);
    }
    effects.push(Effect::StartSession { kind, wire });
    effects.push(Effect::SendRequest { kind, wire });
    arm_retry(state, wire, effects);
}

fn start_dirty_if_ready(state: &mut SessionState, effects: &mut Vec<Effect>) {
    if state.phase != SessionPhase::Idle {
        return;
    }
    let Some(trigger) = state.dirty.take() else {
        return;
    };
    start_client(state, trigger.kind, effects, true);
}

fn merge_dirty(slot: &mut Option<Trigger>, incoming: Trigger) {
    match slot {
        Some(existing) => {
            if existing.kind == SyncKind::History && incoming.kind == SyncKind::Terminal {
                existing.kind = SyncKind::Terminal;
            }
            if let Some(incoming_cut) = incoming.desired_cut {
                if existing
                    .desired_cut
                    .is_none_or(|cut| cut.may_advance_to(incoming_cut))
                {
                    existing.desired_cut = Some(incoming_cut);
                }
            }
        }
        None => *slot = Some(incoming),
    }
}

fn receive_request(
    state: &mut SessionState,
    kind: SyncKind,
    wire: WireIdentity,
    arbitration: InboundArbitration,
    effects: &mut Vec<Effect>,
) {
    if wire.epoch != state.epoch {
        effects.push(Effect::SendStatus {
            wire,
            status: Status::IncarnationMismatch,
        });
        return;
    }
    if let Some(tombstone) = find_tombstone(state, kind, wire) {
        match (tombstone.outcome, tombstone.final_page) {
            (TombstoneOutcome::Completed, Some(page))
                if wire == tombstone.initial || wire.transfer == tombstone.transfer =>
            {
                effects.push(Effect::SendCachedPage {
                    kind: tombstone.kind,
                    wire: page,
                });
            }
            _ => effects.push(Effect::SendStatus {
                wire,
                status: Status::TransferExpired,
            }),
        }
        return;
    }
    if let Some(responder) = responder(state.phase) {
        if responder.request == wire || responder.initial == wire {
            effects.push(Effect::SendCachedPage {
                kind: responder.kind,
                wire: responder.page,
            });
        } else if !responder.final_page
            && wire.transfer == responder.page.transfer
            && wire.cursor == responder.next_cursor
            && wire.nonce != responder.page.nonce
            && kind == responder.kind
        {
            state.phase = preparing_phase(ResponderPreparingState {
                kind,
                initial: responder.initial,
                request: wire,
            });
            state.retry_armed = false;
            effects.push(Effect::CancelRetry {
                wire: responder.page,
            });
            effects.push(Effect::ReleaseBulk {
                wire: responder.page,
            });
            effects.push(Effect::PreparePage {
                kind,
                request: wire,
            });
        } else {
            effects.push(Effect::SendStatus {
                wire,
                status: Status::CursorMismatch,
            });
        }
        return;
    }
    if let Some(preparing) = preparing(state.phase) {
        if preparing.request == wire || preparing.initial == wire {
            effects.push(Effect::Ignored);
        } else {
            effects.push(Effect::Coalesced);
        }
        return;
    }
    if state.phase != SessionPhase::Idle {
        if arbitration == InboundArbitration::KeepCurrent || wire.transfer.get() != 0 {
            effects.push(Effect::Coalesced);
            return;
        }
        if let Some(active) = phase_wire(state.phase) {
            if let Some((_, kind)) = phase_initial_and_kind(state.phase) {
                merge_dirty(
                    &mut state.dirty,
                    Trigger {
                        kind,
                        origin: TriggerOrigin::External,
                        desired_cut: None,
                    },
                );
            }
            effects.push(Effect::CancelRetry { wire: active });
            effects.push(Effect::ReleaseBulk { wire: active });
        }
        state.phase = SessionPhase::Idle;
        state.retry_armed = false;
    }
    if wire.transfer.get() != 0 {
        effects.push(Effect::SendStatus {
            wire,
            status: Status::TransferExpired,
        });
        return;
    }
    let transfer = state.allocate_transfer();
    let page = WireIdentity::new(state.epoch, transfer, wire.nonce, wire.cursor);
    let preparing = ResponderPreparingState {
        kind,
        initial: wire,
        request: page,
    };
    state.phase = preparing_phase(preparing);
    effects.push(Effect::PreparePage {
        kind,
        request: page,
    });
}

fn page_prepared(
    state: &mut SessionState,
    kind: SyncKind,
    request: WireIdentity,
    next_cursor: Cursor,
    target_cut: Cut,
    has_more: bool,
    effects: &mut Vec<Effect>,
) {
    let Some(preparing) = preparing(state.phase) else {
        effects.push(Effect::Ignored);
        return;
    };
    if request.epoch != state.epoch
        || preparing.kind != kind
        || preparing.request != request
        || !request.cursor.may_advance_to(next_cursor)
        || (has_more && request.cursor == next_cursor)
        || !cursor_matches_kind(kind, request.cursor)
        || !cursor_matches_kind(kind, next_cursor)
    {
        effects.push(Effect::Ignored);
        return;
    }
    let responder = ResponderState {
        kind,
        initial: preparing.initial,
        request,
        page: request,
        target_cut,
        next_cursor,
        final_page: !has_more,
    };
    state.phase = responder_phase(responder);
    effects.push(Effect::SendPage {
        kind,
        wire: request,
    });
    arm_retry(state, request, effects);
}

fn up_to_date_responded(
    state: &mut SessionState,
    request: WireIdentity,
    _target_cut: Cut,
    satisfies_dirty: bool,
    effects: &mut Vec<Effect>,
) {
    let Some(preparing) = preparing(state.phase) else {
        effects.push(Effect::Ignored);
        return;
    };
    if request.epoch != state.epoch
        || preparing.request != request
        || preparing.initial.transfer.get() != 0
    {
        effects.push(Effect::Ignored);
        return;
    }
    let page = preparing.initial;
    remember_tombstone(
        state,
        TransferTombstone {
            initial: preparing.initial,
            transfer: TransferId(0),
            final_page: Some(page),
            final_ack: None,
            kind: preparing.kind,
            outcome: TombstoneOutcome::Completed,
        },
    );
    state.phase = SessionPhase::Idle;
    state.retry_armed = false;
    effects.push(Effect::SendPage {
        kind: preparing.kind,
        wire: page,
    });
    if satisfies_dirty {
        state.dirty = None;
    } else {
        start_dirty_if_ready(state, effects);
    }
}

fn receive_page(
    state: &mut SessionState,
    kind: SyncKind,
    wire: WireIdentity,
    next_cursor: Cursor,
    target_cut: Cut,
    has_more: bool,
    effects: &mut Vec<Effect>,
) {
    if wire.epoch != state.epoch {
        effects.push(Effect::Ignored);
        return;
    }
    let Some(client) = client(state.phase) else {
        effects.push(Effect::Ignored);
        return;
    };
    if client.kind != kind
        || client.wire.nonce != wire.nonce
        || (client.wire.transfer.get() != 0 && client.wire.transfer != wire.transfer)
        || (wire.transfer.get() == 0 && has_more)
        || client.wire.cursor != wire.cursor
        || !client.wire.cursor.may_advance_to(next_cursor)
        || (has_more && client.wire.cursor == next_cursor)
        || !cursor_matches_kind(kind, client.wire.cursor)
        || !cursor_matches_kind(kind, next_cursor)
        || client.target_cut.is_some_and(|known| known != target_cut)
        || (kind == SyncKind::Terminal
            && state
                .terminal_acknowledged_cut
                .is_some_and(|known| !known.may_advance_to(target_cut)))
    {
        effects.push(Effect::Ignored);
        return;
    }
    let mut client = client;
    client.wire = wire;
    client.target_cut = Some(target_cut);
    let applying = ApplyingState {
        client,
        page: wire,
        next_cursor,
        target_cut,
        has_more,
    };
    state.phase = match kind {
        SyncKind::Terminal => SessionPhase::TerminalApplying(applying),
        SyncKind::History => SessionPhase::HistoryApplying(applying),
    };
    state.retry_armed = false;
    effects.push(Effect::CancelRetry { wire });
    effects.push(Effect::ValidateAndApply { kind, wire });
}

fn apply_succeeded(state: &mut SessionState, wire: WireIdentity, effects: &mut Vec<Effect>) {
    let applying = match state.phase {
        SessionPhase::TerminalApplying(value) | SessionPhase::HistoryApplying(value)
            if value.page == wire =>
        {
            value
        }
        _ => {
            effects.push(Effect::Ignored);
            return;
        }
    };
    let kind = applying.client.kind;
    effects.push(Effect::ReleaseBulk { wire });
    if applying.has_more {
        let nonce = state.allocate_nonce();
        let continuation =
            WireIdentity::new(state.epoch, wire.transfer, nonce, applying.next_cursor);
        let client = ClientState {
            kind,
            initial: applying.client.initial,
            wire: continuation,
            target_cut: Some(applying.target_cut),
        };
        state.phase = match kind {
            SyncKind::Terminal => SessionPhase::TerminalClient(client),
            SyncKind::History => SessionPhase::HistoryClient(client),
        };
        effects.push(Effect::Continue {
            kind,
            wire: continuation,
        });
        effects.push(Effect::SendRequest {
            kind,
            wire: continuation,
        });
        arm_retry(state, continuation, effects);
    } else {
        match kind {
            SyncKind::Terminal => {
                state.terminal_acknowledged_cut =
                    monotone_cut(state.terminal_acknowledged_cut, applying.target_cut);
            }
            SyncKind::History => {
                state.history_acknowledged_cursor =
                    monotone_cursor(state.history_acknowledged_cursor, applying.next_cursor);
            }
        }
        // An UP_TO_DATE terminal response is deliberately transfer-less. It
        // completes the request without creating an ACK identity; allowing it
        // through the same Applying claim still makes concurrent duplicate
        // responses mutually exclusive before any durable adapter work.
        if wire.transfer.get() == 0 {
            remember_tombstone(
                state,
                TransferTombstone {
                    initial: applying.client.initial,
                    transfer: wire.transfer,
                    final_page: Some(wire),
                    final_ack: None,
                    kind,
                    outcome: TombstoneOutcome::Completed,
                },
            );
            state.phase = SessionPhase::Idle;
            state.retry_armed = false;
            start_dirty_if_ready(state, effects);
            return;
        }
        let ack = WireIdentity::new(state.epoch, wire.transfer, wire.nonce, applying.next_cursor);
        state.phase = SessionPhase::Finalizing(FinalizingState {
            kind,
            initial: applying.client.initial,
            page: wire,
            ack,
            acknowledged_cut: applying.target_cut,
        });
        effects.push(Effect::SendAck {
            kind,
            wire: ack,
            cut: applying.target_cut,
        });
        arm_retry(state, ack, effects);
    }
}

fn arm_retry(state: &mut SessionState, wire: WireIdentity, effects: &mut Vec<Effect>) {
    if !state.retry_armed {
        state.retry_armed = true;
        effects.push(Effect::ScheduleRetry { wire });
    }
}

fn remember_tombstone(state: &mut SessionState, tombstone: TransferTombstone) {
    state.tombstones.retain(|entry| {
        entry.transfer != tombstone.transfer || entry.initial.nonce != tombstone.initial.nonce
    });
    if state.tombstones.len() == MAX_TOMBSTONES {
        state.tombstones.remove(0);
    }
    state.tombstones.push(tombstone);
}

fn find_tombstone(
    state: &SessionState,
    kind: SyncKind,
    wire: WireIdentity,
) -> Option<TransferTombstone> {
    // Transfer IDs are allocated independently by each endpoint. A prior
    // locally initiated transfer can therefore share its numeric ID with the
    // peer's currently active responder transfer. The active session owns
    // that identity; consult historical tombstones only for unmatched wire.
    if wire.transfer.get() != 0
        && phase_wire(state.phase).is_some_and(|active| active.transfer == wire.transfer)
    {
        return None;
    }
    state.tombstones.iter().rev().copied().find(|entry| {
        entry.kind == kind
            && wire.epoch == entry.initial.epoch
            && ((wire.transfer.get() == 0 && wire.nonce == entry.initial.nonce)
                || (wire.transfer.get() != 0 && wire.transfer == entry.transfer))
    })
}

fn monotone_cursor(current: Option<Cursor>, next: Cursor) -> Option<Cursor> {
    match current {
        None => Some(next),
        Some(current) if current.may_advance_to(next) => Some(next),
        Some(current) => Some(current),
    }
}

fn monotone_cut(current: Option<Cut>, next: Cut) -> Option<Cut> {
    match current {
        None => Some(next),
        Some(current) if current.may_advance_to(next) => Some(next),
        Some(current) => Some(current),
    }
}

fn phase_wire(phase: SessionPhase) -> Option<WireIdentity> {
    match phase {
        SessionPhase::Idle => None,
        SessionPhase::Probe(value) => Some(value.wire),
        SessionPhase::TerminalClient(value) | SessionPhase::HistoryClient(value) => {
            Some(value.wire)
        }
        SessionPhase::TerminalApplying(value) | SessionPhase::HistoryApplying(value) => {
            Some(value.page)
        }
        SessionPhase::TerminalPreparing(value) | SessionPhase::HistoryPreparing(value) => {
            Some(value.request)
        }
        SessionPhase::TerminalResponder(value) | SessionPhase::HistoryResponder(value) => {
            Some(value.page)
        }
        SessionPhase::Finalizing(value) => Some(value.ack),
    }
}

fn phase_initial_and_kind(phase: SessionPhase) -> Option<(WireIdentity, SyncKind)> {
    match phase {
        SessionPhase::TerminalClient(value) | SessionPhase::HistoryClient(value) => {
            Some((value.initial, value.kind))
        }
        SessionPhase::TerminalApplying(value) | SessionPhase::HistoryApplying(value) => {
            Some((value.client.initial, value.client.kind))
        }
        SessionPhase::TerminalPreparing(value) | SessionPhase::HistoryPreparing(value) => {
            Some((value.initial, value.kind))
        }
        SessionPhase::TerminalResponder(value) | SessionPhase::HistoryResponder(value) => {
            Some((value.initial, value.kind))
        }
        SessionPhase::Finalizing(value) => Some((value.initial, value.kind)),
        SessionPhase::Idle | SessionPhase::Probe(_) => None,
    }
}

fn client(phase: SessionPhase) -> Option<ClientState> {
    match phase {
        SessionPhase::TerminalClient(value) | SessionPhase::HistoryClient(value) => Some(value),
        _ => None,
    }
}

fn responder(phase: SessionPhase) -> Option<ResponderState> {
    match phase {
        SessionPhase::TerminalResponder(value) | SessionPhase::HistoryResponder(value) => {
            Some(value)
        }
        _ => None,
    }
}

fn applying(phase: SessionPhase) -> Option<ApplyingState> {
    match phase {
        SessionPhase::TerminalApplying(value) | SessionPhase::HistoryApplying(value) => Some(value),
        _ => None,
    }
}

fn preparing(phase: SessionPhase) -> Option<ResponderPreparingState> {
    match phase {
        SessionPhase::TerminalPreparing(value) | SessionPhase::HistoryPreparing(value) => {
            Some(value)
        }
        _ => None,
    }
}

fn preparing_phase(value: ResponderPreparingState) -> SessionPhase {
    match value.kind {
        SyncKind::Terminal => SessionPhase::TerminalPreparing(value),
        SyncKind::History => SessionPhase::HistoryPreparing(value),
    }
}

fn responder_phase(value: ResponderState) -> SessionPhase {
    match value.kind {
        SyncKind::Terminal => SessionPhase::TerminalResponder(value),
        SyncKind::History => SessionPhase::HistoryResponder(value),
    }
}

fn cursor_matches_kind(kind: SyncKind, cursor: Cursor) -> bool {
    match kind {
        SyncKind::Terminal => cursor.kind == CursorKind::TerminalGeneration,
        SyncKind::History => matches!(
            cursor.kind,
            CursorKind::HistoryLogVersion | CursorKind::HistorySnapshotByte
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashSet, VecDeque};

    use super::*;

    const DEPTH: usize = 9;
    const JOURNAL_ID: [u8; 16] = [7; 16];
    const CUT_1: Cut = Cut::new(JOURNAL_ID, 1, [11; 32], [21; 32]);
    const CUT_2: Cut = Cut::new(JOURNAL_ID, 2, [22; 32], [42; 32]);

    fn trigger(kind: SyncKind) -> Event {
        Event::Trigger(Trigger {
            kind,
            origin: TriggerOrigin::External,
            desired_cut: Some(CUT_1),
        })
    }

    fn membership_trigger(kind: SyncKind) -> Event {
        Event::Trigger(Trigger {
            kind,
            origin: TriggerOrigin::Membership,
            desired_cut: Some(CUT_2),
        })
    }

    fn events(state: &SessionState) -> Vec<Event> {
        let old_epoch = PeerEpoch(state.epoch.get().saturating_sub(1));
        let orphan = WireIdentity::new(
            state.epoch,
            TransferId(999),
            WireNonce(999),
            Cursor::new(CursorKind::TerminalGeneration, 0),
        );
        let stale_initial = WireIdentity::new(
            old_epoch,
            TransferId(0),
            WireNonce(998),
            Cursor::new(CursorKind::TerminalGeneration, 0),
        );
        let mut result = vec![
            Event::SourceCutObserved {
                epoch: state.epoch,
                cut: CUT_1,
            },
            Event::SourceCutObserved {
                epoch: old_epoch,
                cut: CUT_2,
            },
            trigger(SyncKind::Terminal),
            trigger(SyncKind::History),
            membership_trigger(SyncKind::Terminal),
            Event::Trigger(Trigger {
                kind: SyncKind::Terminal,
                origin: TriggerOrigin::CatchupApply,
                desired_cut: Some(CUT_2),
            }),
            Event::TerminalDecision {
                epoch: state.epoch,
                origin: DecisionOrigin::Catchup,
                cut: CUT_1,
            },
            Event::TerminalDecision {
                epoch: state.epoch,
                origin: DecisionOrigin::Local,
                cut: CUT_2,
            },
            Event::TerminalDecision {
                epoch: state.epoch,
                origin: DecisionOrigin::Direct,
                cut: CUT_2,
            },
            Event::StartProbe {
                kind: ProbeKind::Clock,
            },
            Event::StartProbe {
                kind: ProbeKind::History,
            },
            Event::PeerRestarted {
                new_epoch: PeerEpoch(state.epoch.get().saturating_add(1)),
            },
            Event::PeerRestarted {
                new_epoch: old_epoch,
            },
            Event::RequestReceived {
                kind: SyncKind::Terminal,
                wire: orphan,
                arbitration: InboundArbitration::KeepCurrent,
            },
            Event::RequestReceived {
                kind: SyncKind::Terminal,
                wire: stale_initial,
                arbitration: InboundArbitration::KeepCurrent,
            },
        ];
        for tombstone in &state.tombstones {
            result.push(Event::RequestReceived {
                kind: tombstone.kind,
                wire: tombstone.initial,
                arbitration: InboundArbitration::KeepCurrent,
            });
            if let Some(ack) = tombstone.final_ack {
                result.push(Event::AckReceived {
                    epoch: state.epoch,
                    wire: ack,
                    cut: CUT_2,
                });
            }
        }
        if let Some(wire) = phase_wire(state.phase) {
            let stale_wire = WireIdentity::new(old_epoch, wire.transfer, wire.nonce, wire.cursor);
            result.extend([
                Event::SendBackpressured { wire },
                Event::RetryReady { wire },
                Event::MessageLost { wire },
                Event::MessageDelayed { wire },
                Event::TransferExpired {
                    epoch: state.epoch,
                    wire,
                },
                Event::TransferExpired {
                    epoch: old_epoch,
                    wire,
                },
                Event::PageReceived {
                    kind: SyncKind::Terminal,
                    wire: stale_wire,
                    next_cursor: Cursor::new(
                        CursorKind::TerminalGeneration,
                        wire.cursor.value.saturating_add(1),
                    ),
                    target_cut: CUT_2,
                    has_more: false,
                },
                Event::AckReceived {
                    epoch: old_epoch,
                    wire: stale_wire,
                    cut: CUT_2,
                },
            ]);
            match state.phase {
                SessionPhase::Probe(probe) => {
                    result.push(Event::ProbeResponse {
                        epoch: state.epoch,
                        nonce: probe.wire.nonce,
                    });
                }
                SessionPhase::TerminalClient(client) | SessionPhase::HistoryClient(client) => {
                    let target = client.target_cut.unwrap_or(CUT_1);
                    let page = WireIdentity::new(
                        state.epoch,
                        TransferId(client.wire.transfer.get().max(1)),
                        client.wire.nonce,
                        client.wire.cursor,
                    );
                    result.push(Event::PageReceived {
                        kind: client.kind,
                        wire: page,
                        next_cursor: Cursor::new(
                            client.wire.cursor.kind,
                            client.wire.cursor.value.saturating_add(1),
                        ),
                        target_cut: target,
                        has_more: false,
                    });
                    result.push(Event::PageReceived {
                        kind: client.kind,
                        wire: page,
                        next_cursor: Cursor::new(
                            client.wire.cursor.kind,
                            client.wire.cursor.value.saturating_add(1),
                        ),
                        target_cut: target,
                        has_more: true,
                    });
                    result.push(Event::PageReceived {
                        kind: client.kind,
                        wire: page,
                        next_cursor: Cursor::new(client.wire.cursor.kind, 0),
                        target_cut: target,
                        has_more: true,
                    });
                }
                SessionPhase::TerminalApplying(applying)
                | SessionPhase::HistoryApplying(applying) => {
                    result.push(Event::PageReceived {
                        kind: applying.client.kind,
                        wire: applying.page,
                        next_cursor: applying.next_cursor,
                        target_cut: applying.target_cut,
                        has_more: applying.has_more,
                    });
                    result.push(Event::ApplySucceeded {
                        epoch: state.epoch,
                        wire: applying.page,
                    });
                    result.push(Event::ApplyFailed {
                        epoch: state.epoch,
                        wire: applying.page,
                    });
                }
                SessionPhase::TerminalPreparing(preparing)
                | SessionPhase::HistoryPreparing(preparing) => {
                    result.push(Event::PagePrepared {
                        kind: preparing.kind,
                        request: preparing.request,
                        next_cursor: Cursor::new(
                            preparing.request.cursor.kind,
                            preparing.request.cursor.value.saturating_add(1),
                        ),
                        target_cut: CUT_2,
                        has_more: false,
                    });
                    result.push(Event::PagePrepared {
                        kind: preparing.kind,
                        request: preparing.request,
                        next_cursor: Cursor::new(
                            preparing.request.cursor.kind,
                            preparing.request.cursor.value.saturating_add(1),
                        ),
                        target_cut: CUT_2,
                        has_more: true,
                    });
                    if preparing.kind == SyncKind::Terminal && preparing.initial.transfer.get() == 0
                    {
                        result.push(Event::UpToDateResponded {
                            request: preparing.request,
                            target_cut: CUT_2,
                            satisfies_dirty: false,
                        });
                        result.push(Event::UpToDateResponded {
                            request: preparing.request,
                            target_cut: CUT_2,
                            satisfies_dirty: true,
                        });
                    }
                }
                SessionPhase::TerminalResponder(responder)
                | SessionPhase::HistoryResponder(responder) => {
                    result.push(Event::RequestReceived {
                        kind: responder.kind,
                        wire: responder.initial,
                        arbitration: InboundArbitration::KeepCurrent,
                    });
                    if !responder.final_page {
                        result.push(Event::RequestReceived {
                            kind: responder.kind,
                            wire: WireIdentity::new(
                                state.epoch,
                                responder.page.transfer,
                                WireNonce(responder.page.nonce.get().saturating_add(1)),
                                responder.next_cursor,
                            ),
                            arbitration: InboundArbitration::KeepCurrent,
                        });
                    }
                    result.push(Event::AckReceived {
                        epoch: state.epoch,
                        wire: WireIdentity::new(
                            state.epoch,
                            responder.page.transfer,
                            responder.page.nonce,
                            responder.next_cursor,
                        ),
                        cut: responder.target_cut,
                    });
                }
                SessionPhase::Finalizing(finalizing) => {
                    result.push(Event::FinalAckDelivered {
                        epoch: state.epoch,
                        wire: finalizing.ack,
                    });
                }
                SessionPhase::Idle => {}
            }
        } else {
            let initial = WireIdentity::new(
                state.epoch,
                TransferId(0),
                WireNonce(41),
                Cursor::new(CursorKind::TerminalGeneration, 0),
            );
            result.push(Event::RequestReceived {
                kind: SyncKind::Terminal,
                wire: initial,
                arbitration: InboundArbitration::KeepCurrent,
            });
        }
        result
    }

    fn assert_invariants(
        before: &SessionState,
        event: Event,
        after: &SessionState,
        effects: &[Effect],
    ) {
        assert!(
            after.active_sessions() <= 1,
            "more than one active session: {after:?}"
        );
        assert!(after.outstanding_nonce().into_iter().count() <= 1);
        assert!(after.sessions_created() <= after.session_budget());
        assert!(!after.retry_armed || phase_wire(after.phase).is_some());
        if before.epoch == after.epoch {
            if let (Some(old), Some(new)) = (before.acknowledged_cut(), after.acknowledged_cut()) {
                assert!(old.may_advance_to(new), "acknowledged cut regressed");
            }
            if let (Some(old), Some(new)) = (phase_wire(before.phase), phase_wire(after.phase)) {
                if old.transfer == new.transfer && old.cursor.kind == new.cursor.kind {
                    assert!(old.cursor.value <= new.cursor.value, "cursor regressed");
                }
            }
            if let (Some(old), Some(new)) = (
                before.acknowledged_history_cursor(),
                after.acknowledged_history_cursor(),
            ) {
                assert!(old.may_advance_to(new), "history cursor regressed");
            }
        }
        if matches!(
            event,
            Event::TerminalDecision {
                origin: DecisionOrigin::Catchup,
                ..
            }
        ) {
            assert!(!effects.iter().any(|effect| matches!(
                effect,
                Effect::FanoutDecision { .. } | Effect::StartSession { .. }
            )));
        }
        if let Event::PeerRestarted { new_epoch } = event {
            if new_epoch <= before.epoch {
                assert_eq!(before, after, "old incarnation mutated current state");
            }
        }

        if event_epoch(event).is_some_and(|epoch| epoch < before.epoch) {
            assert_eq!(
                before, after,
                "packet from an old incarnation mutated current state"
            );
        }

        if let Event::RequestReceived { wire, .. } = event {
            if wire.transfer.get() == 0
                && before.tombstones.iter().any(|entry| {
                    entry.outcome == TombstoneOutcome::Expired && entry.initial == wire
                })
            {
                assert_eq!(before.sessions_created(), after.sessions_created());
                assert!(!effects.iter().any(|effect| matches!(
                    effect,
                    Effect::PreparePage { .. }
                        | Effect::StartSession { .. }
                        | Effect::Continue { .. }
                )));
            }
        }
    }

    fn event_epoch(event: Event) -> Option<PeerEpoch> {
        match event {
            Event::SourceCutObserved { epoch, .. }
            | Event::ProbeResponse { epoch, .. }
            | Event::ApplySucceeded { epoch, .. }
            | Event::ApplyFailed { epoch, .. }
            | Event::AckReceived { epoch, .. }
            | Event::FinalAckDelivered { epoch, .. }
            | Event::TransferExpired { epoch, .. }
            | Event::TerminalDecision { epoch, .. }
            | Event::TombstoneExpired { epoch, .. } => Some(epoch),
            Event::RequestReceived { wire, .. }
            | Event::PageReceived { wire, .. }
            | Event::SendBackpressured { wire }
            | Event::RetryReady { wire }
            | Event::MessageLost { wire }
            | Event::MessageDelayed { wire } => Some(wire.epoch),
            Event::Trigger(_) | Event::StartProbe { .. } | Event::PeerRestarted { .. } => None,
            Event::PagePrepared { request, .. } | Event::UpToDateResponded { request, .. } => {
                Some(request.epoch)
            }
        }
    }

    #[test]
    fn bounded_event_orderings_cannot_create_a_self_sustaining_loop() {
        let initial = SessionState::new(PeerEpoch(1));
        let mut seen = HashSet::from([initial.clone()]);
        let mut queue = VecDeque::from([(initial, 0usize)]);
        while let Some((state, depth)) = queue.pop_front() {
            if depth == DEPTH {
                continue;
            }
            for event in events(&state) {
                let (next, effects) = transition(state.clone(), event);
                assert_invariants(&state, event, &next, &effects);

                let (duplicate, duplicate_effects) = transition(next.clone(), event);
                if matches!(
                    event,
                    Event::RequestReceived { .. }
                        | Event::PageReceived { .. }
                        | Event::AckReceived { .. }
                        | Event::FinalAckDelivered { .. }
                ) {
                    assert_eq!(duplicate.sessions_created(), next.sessions_created());
                    assert!(!duplicate_effects.iter().any(|effect| matches!(
                        effect,
                        Effect::Continue { .. } | Effect::StartSession { .. }
                    )));
                }

                if seen.insert(next.clone()) {
                    queue.push_back((next, depth + 1));
                }
            }
        }
        assert!(
            seen.len() > 100,
            "explorer did not cover a useful state space"
        );
    }

    fn fair_progress_event(state: &SessionState) -> Option<Event> {
        match state.phase {
            SessionPhase::Idle => None,
            SessionPhase::Probe(probe) => Some(Event::ProbeResponse {
                epoch: state.epoch,
                nonce: probe.wire.nonce,
            }),
            SessionPhase::TerminalClient(client) | SessionPhase::HistoryClient(client) => {
                let target_cut = match client.kind {
                    SyncKind::Terminal => state.terminal_acknowledged_cut.unwrap_or(CUT_1),
                    SyncKind::History => client.target_cut.unwrap_or(CUT_1),
                };
                Some(Event::PageReceived {
                    kind: client.kind,
                    wire: WireIdentity::new(
                        state.epoch,
                        TransferId(client.wire.transfer.get().max(1)),
                        client.wire.nonce,
                        client.wire.cursor,
                    ),
                    next_cursor: Cursor::new(
                        client.wire.cursor.kind,
                        client.wire.cursor.value.saturating_add(1),
                    ),
                    target_cut,
                    has_more: false,
                })
            }
            SessionPhase::TerminalApplying(applying) | SessionPhase::HistoryApplying(applying) => {
                Some(Event::ApplySucceeded {
                    epoch: state.epoch,
                    wire: applying.page,
                })
            }
            SessionPhase::TerminalPreparing(preparing)
            | SessionPhase::HistoryPreparing(preparing) => Some(Event::PagePrepared {
                kind: preparing.kind,
                request: preparing.request,
                next_cursor: Cursor::new(
                    preparing.request.cursor.kind,
                    preparing.request.cursor.value.saturating_add(1),
                ),
                target_cut: CUT_2,
                has_more: false,
            }),
            SessionPhase::TerminalResponder(responder)
            | SessionPhase::HistoryResponder(responder) => {
                if responder.final_page {
                    Some(Event::AckReceived {
                        epoch: state.epoch,
                        wire: WireIdentity::new(
                            state.epoch,
                            responder.page.transfer,
                            responder.page.nonce,
                            responder.next_cursor,
                        ),
                        cut: responder.target_cut,
                    })
                } else {
                    Some(Event::RequestReceived {
                        kind: responder.kind,
                        wire: WireIdentity::new(
                            state.epoch,
                            responder.page.transfer,
                            WireNonce(responder.page.nonce.get().saturating_add(1)),
                            responder.next_cursor,
                        ),
                        arbitration: InboundArbitration::KeepCurrent,
                    })
                }
            }
            SessionPhase::Finalizing(finalizing) => Some(Event::FinalAckDelivered {
                epoch: state.epoch,
                wire: finalizing.ack,
            }),
        }
    }

    #[test]
    fn fair_delivery_after_external_work_stops_reaches_idle() {
        let mut reachable = HashSet::new();
        let mut frontier = vec![SessionState::new(PeerEpoch(1))];
        for _ in 0..6 {
            let mut next_frontier = Vec::new();
            for state in frontier {
                reachable.insert(state.clone());
                for event in events(&state) {
                    let (next, _) = transition(state.clone(), event);
                    if !reachable.contains(&next) {
                        next_frontier.push(next);
                    }
                }
            }
            frontier = next_frontier;
        }

        for mut state in reachable {
            for _ in 0..32 {
                let Some(event) = fair_progress_event(&state) else {
                    break;
                };
                let before = state.potential();
                let sessions_before = state.sessions_created();
                let wire_before = phase_wire(state.phase);
                let (next, _) = transition(state, event);
                let after = next.potential();
                let created_session = next.sessions_created() > sessions_before;
                let cursor_progress =
                    wire_before
                        .zip(phase_wire(next.phase))
                        .is_some_and(|(old, new)| {
                            old.transfer == new.transfer
                                && old.cursor.kind == new.cursor.kind
                                && old.cursor.value < new.cursor.value
                        });
                assert!(
                    after < before || created_session || cursor_progress,
                    "fair progress did not reduce potential: {next:?}"
                );
                state = next;
            }
            assert!(state.is_idle(), "fair drain did not reach idle: {state:?}");
        }
    }

    #[test]
    fn expired_initial_request_is_a_tombstone_not_a_new_cursor_zero_transfer() {
        let initial = WireIdentity::new(
            PeerEpoch(1),
            TransferId(0),
            WireNonce(9),
            Cursor::new(CursorKind::TerminalGeneration, 0),
        );
        let state = SessionState::new(PeerEpoch(1));
        let (state, _) = transition(
            state,
            Event::RequestReceived {
                kind: SyncKind::Terminal,
                wire: initial,
                arbitration: InboundArbitration::KeepCurrent,
            },
        );
        let active = phase_wire(state.phase).unwrap();
        let (state, _) = transition(state, membership_trigger(SyncKind::Terminal));
        let (state, _) = transition(
            state,
            Event::TransferExpired {
                epoch: PeerEpoch(1),
                wire: active,
            },
        );
        assert!(state.is_idle(), "expiry must not auto-start dirty work");
        let starts = state.sessions_created();
        let (state, effects) = transition(
            state,
            Event::RequestReceived {
                kind: SyncKind::Terminal,
                wire: initial,
                arbitration: InboundArbitration::KeepCurrent,
            },
        );
        assert_eq!(state.sessions_created(), starts);
        assert!(effects.contains(&Effect::SendStatus {
            wire: initial,
            status: Status::TransferExpired,
        }));
    }

    #[test]
    fn backpressure_and_nonadvancing_pages_cannot_feed_an_effect_loop() {
        let (state, _) = transition(SessionState::new(PeerEpoch(1)), trigger(SyncKind::Terminal));
        let wire = phase_wire(state.phase).expect("terminal request");
        let (same, effects) = transition(state.clone(), Event::SendBackpressured { wire });
        assert_eq!(same, state);
        assert!(!effects.iter().any(|effect| matches!(
            effect,
            Effect::SendRequest { .. } | Effect::SendPage { .. } | Effect::SendAck { .. }
        )));

        let page = WireIdentity::new(PeerEpoch(1), TransferId(1), wire.nonce, wire.cursor);
        let (same, effects) = transition(
            state.clone(),
            Event::PageReceived {
                kind: SyncKind::Terminal,
                wire: page,
                next_cursor: wire.cursor,
                target_cut: CUT_1,
                has_more: true,
            },
        );
        assert_eq!(same, state);
        assert_eq!(effects, vec![Effect::Ignored]);
    }

    #[test]
    fn completed_and_unknown_transfers_never_reopen_at_cursor_zero() {
        let initial = WireIdentity::new(
            PeerEpoch(1),
            TransferId(0),
            WireNonce(9),
            Cursor::new(CursorKind::TerminalGeneration, 0),
        );
        let (state, effects) = transition(
            SessionState::new(PeerEpoch(1)),
            Event::RequestReceived {
                kind: SyncKind::Terminal,
                wire: initial,
                arbitration: InboundArbitration::KeepCurrent,
            },
        );
        let request = effects
            .iter()
            .find_map(|effect| match effect {
                Effect::PreparePage { request, .. } => Some(*request),
                _ => None,
            })
            .expect("page preparation");
        let (state, _) = transition(
            state,
            Event::PagePrepared {
                kind: SyncKind::Terminal,
                request,
                next_cursor: Cursor::new(CursorKind::TerminalGeneration, 1),
                target_cut: CUT_1,
                has_more: false,
            },
        );
        let ack = WireIdentity::new(
            PeerEpoch(1),
            request.transfer,
            request.nonce,
            Cursor::new(CursorKind::TerminalGeneration, 1),
        );
        let (state, _) = transition(
            state,
            Event::AckReceived {
                epoch: PeerEpoch(1),
                wire: ack,
                cut: CUT_1,
            },
        );
        assert!(state.is_idle());
        let (replayed, effects) = transition(
            state.clone(),
            Event::RequestReceived {
                kind: SyncKind::Terminal,
                wire: initial,
                arbitration: InboundArbitration::KeepCurrent,
            },
        );
        assert_eq!(replayed, state);
        assert!(!effects.iter().any(|effect| matches!(
            effect,
            Effect::PreparePage { .. } | Effect::StartSession { .. } | Effect::Continue { .. }
        )));

        let unknown = WireIdentity::new(
            PeerEpoch(1),
            TransferId(77),
            WireNonce(88),
            Cursor::new(CursorKind::TerminalGeneration, 0),
        );
        let (unchanged, effects) = transition(
            state.clone(),
            Event::RequestReceived {
                kind: SyncKind::Terminal,
                wire: unknown,
                arbitration: InboundArbitration::KeepCurrent,
            },
        );
        assert_eq!(unchanged, state);
        assert_eq!(
            effects,
            vec![Effect::SendStatus {
                wire: unknown,
                status: Status::TransferExpired,
            }]
        );
    }

    #[test]
    fn simultaneous_starts_arbitrate_and_dirty_triggers_create_one_followup() {
        let (client_state, _) =
            transition(SessionState::new(PeerEpoch(1)), trigger(SyncKind::Terminal));
        let inbound = WireIdentity::new(
            PeerEpoch(1),
            TransferId(0),
            WireNonce(41),
            Cursor::new(CursorKind::TerminalGeneration, 0),
        );
        let (kept, effects) = transition(
            client_state.clone(),
            Event::RequestReceived {
                kind: SyncKind::Terminal,
                wire: inbound,
                arbitration: InboundArbitration::KeepCurrent,
            },
        );
        assert_eq!(kept.phase, client_state.phase);
        assert_eq!(effects, vec![Effect::Coalesced]);
        let (yielded, effects) = transition(
            client_state,
            Event::RequestReceived {
                kind: SyncKind::Terminal,
                wire: inbound,
                arbitration: InboundArbitration::AcceptInbound,
            },
        );
        assert!(matches!(yielded.phase, SessionPhase::TerminalPreparing(_)));
        assert!(
            effects
                .iter()
                .any(|effect| matches!(effect, Effect::PreparePage { .. }))
        );

        let (mut state, _) =
            transition(SessionState::new(PeerEpoch(1)), trigger(SyncKind::Terminal));
        for _ in 0..100 {
            (state, _) = transition(state, trigger(SyncKind::Terminal));
        }
        let client = client(state.phase).expect("active client");
        let page = WireIdentity::new(
            PeerEpoch(1),
            TransferId(1),
            client.wire.nonce,
            client.wire.cursor,
        );
        (state, _) = transition(
            state,
            Event::PageReceived {
                kind: SyncKind::Terminal,
                wire: page,
                next_cursor: Cursor::new(CursorKind::TerminalGeneration, 1),
                target_cut: CUT_1,
                has_more: false,
            },
        );
        (state, _) = transition(
            state,
            Event::ApplySucceeded {
                epoch: PeerEpoch(1),
                wire: page,
            },
        );
        let final_ack = phase_wire(state.phase).expect("final ack");
        assert_eq!(state.sessions_created(), 1);
        (state, _) = transition(state, Event::MessageLost { wire: final_ack });
        let (retried, retry_effects) = transition(state, Event::RetryReady { wire: final_ack });
        assert_eq!(retried.sessions_created(), 1);
        assert!(retry_effects.iter().any(|effect| {
            matches!(effect, Effect::SendAck { wire, .. } if *wire == final_ack)
        }));
        state = retried;
        (state, _) = transition(
            state,
            Event::FinalAckDelivered {
                epoch: PeerEpoch(1),
                wire: final_ack,
            },
        );
        assert_eq!(state.sessions_created(), 2);
        assert_eq!(state.dirty_followups, 1);
    }

    #[test]
    fn responder_ack_does_not_replace_reverse_peer_source_cursor() {
        const LOCAL_CUT: Cut = Cut::new([9; 16], 7, [70; 32], [71; 32]);
        let epoch = PeerEpoch(1);
        let (state, _) = transition(
            SessionState::new(epoch),
            Event::SourceCutObserved { epoch, cut: CUT_1 },
        );
        let (state, effects) = transition(state, trigger(SyncKind::Terminal));
        let initial = effects
            .iter()
            .find_map(|effect| match effect {
                Effect::StartSession { wire, .. } => Some(*wire),
                _ => None,
            })
            .expect("initial terminal client");
        assert_eq!(initial.cursor.value(), CUT_1.generation());

        let inbound = WireIdentity::new(
            epoch,
            TransferId(0),
            WireNonce(41),
            Cursor::new(CursorKind::TerminalGeneration, 0),
        );
        let (state, effects) = transition(
            state,
            Event::RequestReceived {
                kind: SyncKind::Terminal,
                wire: inbound,
                arbitration: InboundArbitration::AcceptInbound,
            },
        );
        let request = effects
            .iter()
            .find_map(|effect| match effect {
                Effect::PreparePage { request, .. } => Some(*request),
                _ => None,
            })
            .expect("yielded responder page preparation");
        let (state, _) = transition(
            state,
            Event::PagePrepared {
                kind: SyncKind::Terminal,
                request,
                next_cursor: Cursor::new(CursorKind::TerminalGeneration, LOCAL_CUT.generation()),
                target_cut: LOCAL_CUT,
                has_more: false,
            },
        );
        let ack = WireIdentity::new(
            epoch,
            request.transfer,
            request.nonce,
            Cursor::new(CursorKind::TerminalGeneration, LOCAL_CUT.generation()),
        );
        let (state, effects) = transition(
            state,
            Event::AckReceived {
                epoch,
                wire: ack,
                cut: LOCAL_CUT,
            },
        );
        let reverse = effects
            .iter()
            .find_map(|effect| match effect {
                Effect::StartSession {
                    kind: SyncKind::Terminal,
                    wire,
                } => Some(*wire),
                _ => None,
            })
            .expect("dirty reverse terminal client");
        assert_eq!(state.acknowledged_cut(), Some(CUT_1));
        assert_eq!(reverse.cursor.value(), CUT_1.generation());
    }

    #[test]
    fn equal_set_response_satisfies_dirty_reverse_and_returns_idle() {
        const LOCAL_CUT: Cut = Cut::new([9; 16], 7, [70; 32], [71; 32]);
        let epoch = PeerEpoch(1);
        let (state, _) = transition(
            SessionState::new(epoch),
            Event::SourceCutObserved { epoch, cut: CUT_1 },
        );
        let (state, _) = transition(state, trigger(SyncKind::Terminal));
        let inbound = WireIdentity::new(
            epoch,
            TransferId(0),
            WireNonce(41),
            Cursor::new(CursorKind::TerminalGeneration, 0),
        );
        let (state, effects) = transition(
            state,
            Event::RequestReceived {
                kind: SyncKind::Terminal,
                wire: inbound,
                arbitration: InboundArbitration::AcceptInbound,
            },
        );
        let request = effects
            .iter()
            .find_map(|effect| match effect {
                Effect::PreparePage { request, .. } => Some(*request),
                _ => None,
            })
            .expect("yielded responder page preparation");
        let (state, effects) = transition(
            state,
            Event::UpToDateResponded {
                request,
                target_cut: LOCAL_CUT,
                satisfies_dirty: true,
            },
        );
        assert!(state.is_idle());
        assert_eq!(state.acknowledged_cut(), Some(CUT_1));
        assert!(
            !effects
                .iter()
                .any(|effect| matches!(effect, Effect::StartSession { .. }))
        );
    }

    #[test]
    fn observed_direct_source_cut_is_the_next_client_cursor() {
        let epoch = PeerEpoch(1);
        let (state, _) = transition(
            SessionState::new(epoch),
            Event::SourceCutObserved { epoch, cut: CUT_2 },
        );
        let (_, effects) = transition(state, trigger(SyncKind::Terminal));
        let wire = effects
            .iter()
            .find_map(|effect| match effect {
                Effect::StartSession { wire, .. } => Some(*wire),
                _ => None,
            })
            .expect("terminal client from observed source cut");
        assert_eq!(wire.cursor.value(), CUT_2.generation());
    }

    #[test]
    fn old_incarnation_packets_and_catchup_apply_are_side_effect_free() {
        let (state, _) = transition(SessionState::new(PeerEpoch(2)), trigger(SyncKind::Terminal));
        let stale = WireIdentity::new(
            PeerEpoch(1),
            TransferId(0),
            WireNonce(1),
            Cursor::new(CursorKind::TerminalGeneration, 0),
        );
        for event in [
            Event::PageReceived {
                kind: SyncKind::Terminal,
                wire: stale,
                next_cursor: Cursor::new(CursorKind::TerminalGeneration, 1),
                target_cut: CUT_1,
                has_more: false,
            },
            Event::AckReceived {
                epoch: PeerEpoch(1),
                wire: stale,
                cut: CUT_1,
            },
            Event::TransferExpired {
                epoch: PeerEpoch(1),
                wire: stale,
            },
        ] {
            let (next, _) = transition(state.clone(), event);
            assert_eq!(next, state);
        }
        let (next, effects) = transition(
            state.clone(),
            Event::TerminalDecision {
                epoch: PeerEpoch(2),
                origin: DecisionOrigin::Catchup,
                cut: CUT_1,
            },
        );
        assert_eq!(next, state);
        assert!(!effects.iter().any(|effect| matches!(
            effect,
            Effect::FanoutDecision { .. }
                | Effect::StartSession { .. }
                | Effect::SendRequest { .. }
        )));
    }
}
