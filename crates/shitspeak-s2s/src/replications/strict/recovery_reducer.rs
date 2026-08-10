//! Pure reducer for protocol-v8 strict foreign-lineage recovery.
//!
//! The reducer owns no I/O. Callers execute the returned effects and feed the
//! resulting, attempt-correlated events back into [`StrictRecoveryCoordinator`].

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecoveryAttemptId {
    hi: u64,
    lo: u64,
}

impl RecoveryAttemptId {
    pub const fn new(hi: u64, lo: u64) -> Self {
        Self { hi, lo }
    }

    pub const fn hi(self) -> u64 {
        self.hi
    }

    pub const fn lo(self) -> u64 {
        self.lo
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryPhase {
    Healthy,
    Certifying,
    FetchingTerminalCheckpoint,
    FetchingRepositorySnapshot,
    Prepared,
    Installing,
    Verifying,
    Backoff,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalTarget {
    repository_version: u64,
    history_freshness: i64,
    terminal_set_digest: [u8; 32],
}

impl LogicalTarget {
    pub const fn new(
        repository_version: u64,
        history_freshness: i64,
        terminal_set_digest: [u8; 32],
    ) -> Self {
        Self {
            repository_version,
            history_freshness,
            terminal_set_digest,
        }
    }

    pub const fn repository_version(&self) -> u64 {
        self.repository_version
    }

    pub const fn history_freshness(&self) -> i64 {
        self.history_freshness
    }

    pub const fn terminal_set_digest(&self) -> &[u8; 32] {
        &self.terminal_set_digest
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TerminalCut {
    journal_id: [u8; 16],
    generation: u64,
    chain_digest: [u8; 32],
    terminal_set_digest: [u8; 32],
}

impl TerminalCut {
    pub const fn new(
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

    pub const fn journal_id(&self) -> &[u8; 16] {
        &self.journal_id
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn chain_digest(&self) -> &[u8; 32] {
        &self.chain_digest
    }

    pub const fn terminal_set_digest(&self) -> &[u8; 32] {
        &self.terminal_set_digest
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ParticipantIncarnation {
    node_id: u64,
    boot_epoch: u64,
}

impl ParticipantIncarnation {
    pub const fn new(node_id: u64, boot_epoch: u64) -> Self {
        Self {
            node_id,
            boot_epoch,
        }
    }

    pub const fn node_id(&self) -> u64 {
        self.node_id
    }

    pub const fn boot_epoch(&self) -> u64 {
        self.boot_epoch
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryAttestation {
    witness: ParticipantIncarnation,
    target: LogicalTarget,
    terminal_cut: TerminalCut,
    history_rank: u64,
}

impl RecoveryAttestation {
    pub fn new(
        witness: ParticipantIncarnation,
        target: LogicalTarget,
        terminal_cut: TerminalCut,
        history_rank: u64,
    ) -> Self {
        Self {
            witness,
            target,
            terminal_cut,
            history_rank,
        }
    }

    pub fn witness(&self) -> &ParticipantIncarnation {
        &self.witness
    }

    pub fn target(&self) -> &LogicalTarget {
        &self.target
    }

    pub fn terminal_cut(&self) -> &TerminalCut {
        &self.terminal_cut
    }

    pub const fn history_rank(&self) -> u64 {
        self.history_rank
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCertificate {
    target: LogicalTarget,
    frozen_denominator: usize,
    witnesses: Vec<RecoveryAttestation>,
}

impl RecoveryCertificate {
    pub fn target(&self) -> &LogicalTarget {
        &self.target
    }

    pub const fn frozen_denominator(&self) -> usize {
        self.frozen_denominator
    }

    pub fn witnesses(&self) -> &[RecoveryAttestation] {
        &self.witnesses
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryTrigger {
    TerminalFence,
    Admission,
    ClockTick,
    MembershipChanged,
    GenerationZeroAudit,
    Explicit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferKind {
    TerminalCheckpoint,
    RepositorySnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DonorFailure {
    IncarnationLost,
    SustainedRouteLoss,
    TargetMoved,
    NoProgressDeadline,
    RetryableFailure,
    ResourceLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryFailure {
    donor: ParticipantIncarnation,
    reason: DonorFailure,
}

impl RecoveryFailure {
    pub const fn new(donor: ParticipantIncarnation, reason: DonorFailure) -> Self {
        Self { donor, reason }
    }

    pub const fn donor(&self) -> &ParticipantIncarnation {
        &self.donor
    }

    pub const fn reason(&self) -> DonorFailure {
        self.reason
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verification {
    target: LogicalTarget,
    terminal_cut: TerminalCut,
}

impl Verification {
    pub const fn new(target: LogicalTarget, terminal_cut: TerminalCut) -> Self {
        Self {
            target,
            terminal_cut,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryEvent {
    Trigger {
        trigger: RecoveryTrigger,
        attempt: RecoveryAttemptId,
        total_known_participants: usize,
        now_ms: u64,
    },
    ProbeResponse {
        attempt: RecoveryAttemptId,
        attestation: RecoveryAttestation,
        authenticated: bool,
        now_ms: u64,
    },
    TransferProgress {
        attempt: RecoveryAttemptId,
        donor: ParticipantIncarnation,
        kind: TransferKind,
        authenticated: bool,
        complete: bool,
        now_ms: u64,
    },
    Deadline {
        attempt: RecoveryAttemptId,
        now_ms: u64,
    },
    DonorFailed {
        attempt: RecoveryAttemptId,
        donor: ParticipantIncarnation,
        failure: DonorFailure,
        now_ms: u64,
    },
    Prepared {
        attempt: RecoveryAttemptId,
        donor: ParticipantIncarnation,
    },
    InstallStarted {
        attempt: RecoveryAttemptId,
        donor: ParticipantIncarnation,
    },
    Installed {
        attempt: RecoveryAttemptId,
        donor: ParticipantIncarnation,
    },
    Verified {
        attempt: RecoveryAttemptId,
        donor: ParticipantIncarnation,
        verification: Verification,
    },
    /// The executor reconstructed and decoded the local repository envelope
    /// after quorum certification and proved that it already carries the
    /// certificate's exact representation cut. No donor session is needed.
    LocalImageVerified {
        attempt: RecoveryAttemptId,
        donor: ParticipantIncarnation,
        verification: Verification,
    },
    AuditYield {
        attempt: RecoveryAttemptId,
    },
    Cancel {
        attempt: RecoveryAttemptId,
        now_ms: u64,
    },
    RetryElapsed {
        attempt: RecoveryAttemptId,
        now_ms: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryEffect {
    Persist,
    SendProbes {
        attempt: RecoveryAttemptId,
    },
    SendTransfer {
        attempt: RecoveryAttemptId,
        donor: ParticipantIncarnation,
        terminal_cut: TerminalCut,
        kind: TransferKind,
    },
    PrepareInstall {
        attempt: RecoveryAttemptId,
        donor: ParticipantIncarnation,
        terminal_cut: TerminalCut,
    },
    Install {
        attempt: RecoveryAttemptId,
        donor: ParticipantIncarnation,
    },
    Retry {
        attempt: RecoveryAttemptId,
    },
    Cleanup {
        attempt: RecoveryAttemptId,
    },
    ClearCompletedAttempt {
        attempt: RecoveryAttemptId,
    },
    Metric(RecoveryMetric),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryMetric {
    AttemptStarted,
    TriggerCoalesced,
    CertificateFailure,
    DonorSwitched,
    Retransmit,
    StaleEvent,
    Completed,
    Cancelled,
}

const PROGRESS_DEADLINE_MS: u64 = 30_000;
pub(super) const RECOVERY_RETRY_DELAY_MS: u64 = 500;

/// Durable reducer state reconstructed at startup. Wire transfer identities,
/// cursors, nonces, and deadlines are deliberately absent and are recreated
/// from the returned resume effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRestore {
    attempt: RecoveryAttemptId,
    phase: RecoveryPhase,
    frozen_denominator: usize,
    frozen_electorate: Vec<u64>,
    target: Option<LogicalTarget>,
    witnesses: Vec<RecoveryAttestation>,
    donor_order: Vec<ParticipantIncarnation>,
    current_donor_index: Option<usize>,
    current_donor: Option<ParticipantIncarnation>,
    representation_cut: Option<TerminalCut>,
    failure_history: Vec<RecoveryFailure>,
}

impl RecoveryRestore {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        attempt: RecoveryAttemptId,
        phase: RecoveryPhase,
        frozen_denominator: usize,
        target: Option<LogicalTarget>,
        witnesses: Vec<RecoveryAttestation>,
        donor_order: Vec<ParticipantIncarnation>,
        current_donor_index: Option<usize>,
        current_donor: Option<ParticipantIncarnation>,
        representation_cut: Option<TerminalCut>,
        failure_history: Vec<RecoveryFailure>,
    ) -> Self {
        let frozen_electorate = infer_frozen_electorate(
            frozen_denominator,
            witnesses.iter().map(|witness| witness.witness().node_id()),
        );
        Self::new_with_electorate(
            attempt,
            phase,
            frozen_denominator,
            frozen_electorate,
            target,
            witnesses,
            donor_order,
            current_donor_index,
            current_donor,
            representation_cut,
            failure_history,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_electorate(
        attempt: RecoveryAttemptId,
        phase: RecoveryPhase,
        frozen_denominator: usize,
        frozen_electorate: Vec<u64>,
        target: Option<LogicalTarget>,
        witnesses: Vec<RecoveryAttestation>,
        donor_order: Vec<ParticipantIncarnation>,
        current_donor_index: Option<usize>,
        current_donor: Option<ParticipantIncarnation>,
        representation_cut: Option<TerminalCut>,
        failure_history: Vec<RecoveryFailure>,
    ) -> Self {
        Self {
            attempt,
            phase,
            frozen_denominator,
            frozen_electorate,
            target,
            witnesses,
            donor_order,
            current_donor_index,
            current_donor,
            representation_cut,
            failure_history,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecoveryRestoreError {
    #[error("healthy recovery state cannot contain an active attempt")]
    HealthyAttempt,
    #[error("recovery quorum denominator is zero")]
    EmptyDenominator,
    #[error("recovery electorate does not match its frozen denominator")]
    ElectorateDenominatorMismatch,
    #[error("recovery electorate is not strictly sorted by unique node seat")]
    ElectorateOrder,
    #[error("recovery certificate state is incomplete")]
    IncompleteCertificate,
    #[error("recovery certificate has more witnesses than its frozen denominator")]
    CertificateExceedsDenominator,
    #[error("recovery certificate witnesses are not sorted and unique")]
    WitnessOrder,
    #[error("recovery witness does not attest the logical target")]
    WitnessTargetMismatch,
    #[error("recovery witness terminal digest does not match the logical target")]
    WitnessDigestMismatch,
    #[error("recovery donor is duplicated or is not a certified witness")]
    InvalidDonorOrder,
    #[error("recovery current donor index and identity must be present together")]
    IncompleteCurrentDonor,
    #[error("recovery current donor does not match donor order")]
    CurrentDonorMismatch,
    #[error("recovery representation cut does not match the target or current donor")]
    RepresentationMismatch,
    #[error("recovery phase is inconsistent with its durable certificate")]
    PhaseMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictRecoveryCoordinator {
    phase: RecoveryPhase,
    attempt: Option<RecoveryAttemptId>,
    frozen_denominator: usize,
    frozen_electorate: Vec<u64>,
    quorum: usize,
    attestations: BTreeMap<LogicalTarget, BTreeMap<ParticipantIncarnation, RecoveryAttestation>>,
    certification_progress: usize,
    certificate: Option<RecoveryCertificate>,
    donor_order: Vec<RecoveryAttestation>,
    donor_index: usize,
    representation_cut: Option<TerminalCut>,
    progress_deadline_ms: Option<u64>,
    representation_immutable: bool,
    failure_history: Vec<RecoveryFailure>,
    cleanup_emitted: bool,
    audit_yield_eligible: bool,
}

impl Default for StrictRecoveryCoordinator {
    fn default() -> Self {
        Self {
            phase: RecoveryPhase::Healthy,
            attempt: None,
            frozen_denominator: 0,
            frozen_electorate: Vec::new(),
            quorum: 0,
            attestations: BTreeMap::new(),
            certification_progress: 0,
            certificate: None,
            donor_order: Vec::new(),
            donor_index: 0,
            representation_cut: None,
            progress_deadline_ms: None,
            representation_immutable: false,
            failure_history: Vec::new(),
            cleanup_emitted: false,
            audit_yield_eligible: false,
        }
    }
}

impl StrictRecoveryCoordinator {
    /// Restore one durable active attempt before the runtime is published.
    /// Network phases resume with a fresh cursor-zero transfer under the same
    /// attempt identity; prepared/installing/verifying phases are driven by
    /// startup roll-forward instead of network effects.
    pub fn restore(
        restored: RecoveryRestore,
        now_ms: u64,
    ) -> Result<(Self, Vec<RecoveryEffect>), RecoveryRestoreError> {
        if restored.phase == RecoveryPhase::Healthy {
            return Err(RecoveryRestoreError::HealthyAttempt);
        }
        if restored.frozen_denominator == 0 {
            return Err(RecoveryRestoreError::EmptyDenominator);
        }
        if restored.frozen_electorate.len() != restored.frozen_denominator {
            return Err(RecoveryRestoreError::ElectorateDenominatorMismatch);
        }
        if restored
            .frozen_electorate
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(RecoveryRestoreError::ElectorateOrder);
        }
        let has_certificate_state = !restored.witnesses.is_empty()
            || !restored.donor_order.is_empty()
            || restored.current_donor_index.is_some()
            || restored.current_donor.is_some()
            || restored.representation_cut.is_some();
        if restored.target.is_none() && has_certificate_state {
            return Err(RecoveryRestoreError::IncompleteCertificate);
        }
        if restored.phase == RecoveryPhase::Certifying && restored.target.is_some() {
            return Err(RecoveryRestoreError::PhaseMismatch);
        }

        let quorum = fast_quorum_size(restored.frozen_denominator);
        let certificate = if let Some(target) = restored.target.clone() {
            if restored.witnesses.len() < quorum.max(1) {
                return Err(RecoveryRestoreError::IncompleteCertificate);
            }
            if restored.witnesses.len() > restored.frozen_denominator {
                return Err(RecoveryRestoreError::CertificateExceedsDenominator);
            }
            if restored
                .witnesses
                .windows(2)
                .any(|pair| pair[0].witness >= pair[1].witness)
            {
                return Err(RecoveryRestoreError::WitnessOrder);
            }
            if restored
                .witnesses
                .iter()
                .map(|witness| witness.witness.node_id)
                .collect::<BTreeSet<_>>()
                .len()
                != restored.witnesses.len()
            {
                return Err(RecoveryRestoreError::WitnessOrder);
            }
            for witness in &restored.witnesses {
                if restored
                    .frozen_electorate
                    .binary_search(&witness.witness.node_id)
                    .is_err()
                {
                    return Err(RecoveryRestoreError::WitnessOrder);
                }
                if witness.target != target {
                    return Err(RecoveryRestoreError::WitnessTargetMismatch);
                }
                if witness.terminal_cut.terminal_set_digest != target.terminal_set_digest {
                    return Err(RecoveryRestoreError::WitnessDigestMismatch);
                }
            }
            Some(RecoveryCertificate {
                target,
                frozen_denominator: restored.frozen_denominator,
                witnesses: restored.witnesses.clone(),
            })
        } else {
            None
        };

        if restored.current_donor_index.is_some() != restored.current_donor.is_some() {
            return Err(RecoveryRestoreError::IncompleteCurrentDonor);
        }
        let witnesses_by_incarnation = restored
            .witnesses
            .iter()
            .map(|witness| (witness.witness.clone(), witness.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut expected_donor_order = restored.witnesses.clone();
        expected_donor_order.sort_by(|a, b| {
            b.history_rank
                .cmp(&a.history_rank)
                .then_with(|| a.witness.cmp(&b.witness))
        });
        if restored.donor_order
            != expected_donor_order
                .iter()
                .map(|witness| witness.witness.clone())
                .collect::<Vec<_>>()
        {
            return Err(RecoveryRestoreError::InvalidDonorOrder);
        }
        let mut unique_donors = BTreeSet::new();
        let mut donor_order = Vec::with_capacity(restored.donor_order.len());
        for donor in &restored.donor_order {
            if !unique_donors.insert(donor.clone()) {
                return Err(RecoveryRestoreError::InvalidDonorOrder);
            }
            let Some(witness) = witnesses_by_incarnation.get(donor) else {
                return Err(RecoveryRestoreError::InvalidDonorOrder);
            };
            donor_order.push(witness.clone());
        }
        let donor_index = restored.current_donor_index.unwrap_or_default();
        match (&restored.current_donor, donor_order.get(donor_index)) {
            (Some(current), Some(expected)) if current == &expected.witness => {}
            (None, None) if donor_order.is_empty() => {}
            _ => return Err(RecoveryRestoreError::CurrentDonorMismatch),
        }

        if let Some(cut) = &restored.representation_cut {
            let Some(target) = restored.target.as_ref() else {
                return Err(RecoveryRestoreError::RepresentationMismatch);
            };
            if cut.terminal_set_digest != target.terminal_set_digest
                || donor_order
                    .get(donor_index)
                    .is_none_or(|donor| donor.terminal_cut != *cut)
            {
                return Err(RecoveryRestoreError::RepresentationMismatch);
            }
        }
        let requires_representation = matches!(
            restored.phase,
            RecoveryPhase::FetchingTerminalCheckpoint
                | RecoveryPhase::FetchingRepositorySnapshot
                | RecoveryPhase::Prepared
                | RecoveryPhase::Installing
                | RecoveryPhase::Verifying
        );
        if requires_representation
            && (certificate.is_none()
                || donor_order.is_empty()
                || restored.representation_cut.is_none())
        {
            return Err(RecoveryRestoreError::PhaseMismatch);
        }

        let resume_terminal = matches!(
            restored.phase,
            RecoveryPhase::FetchingTerminalCheckpoint | RecoveryPhase::FetchingRepositorySnapshot
        );
        let phase = if resume_terminal {
            RecoveryPhase::FetchingTerminalCheckpoint
        } else {
            restored.phase
        };
        let progress_deadline_ms = match phase {
            RecoveryPhase::Certifying | RecoveryPhase::FetchingTerminalCheckpoint => {
                Some(now_ms.saturating_add(PROGRESS_DEADLINE_MS))
            }
            RecoveryPhase::Backoff => Some(now_ms.saturating_add(RECOVERY_RETRY_DELAY_MS)),
            _ => None,
        };
        let mut attestations = BTreeMap::new();
        if let Some(certificate) = &certificate {
            attestations.insert(
                certificate.target.clone(),
                certificate
                    .witnesses
                    .iter()
                    .cloned()
                    .map(|witness| (witness.witness.clone(), witness))
                    .collect(),
            );
        }
        let coordinator = Self {
            phase,
            attempt: Some(restored.attempt),
            frozen_denominator: restored.frozen_denominator,
            frozen_electorate: restored.frozen_electorate,
            quorum,
            attestations,
            certification_progress: certificate
                .as_ref()
                .map_or(0, |certificate| certificate.witnesses.len()),
            certificate,
            donor_order,
            donor_index,
            representation_cut: restored.representation_cut.clone(),
            progress_deadline_ms,
            representation_immutable: matches!(
                phase,
                RecoveryPhase::Prepared | RecoveryPhase::Installing | RecoveryPhase::Verifying
            ),
            failure_history: restored.failure_history,
            cleanup_emitted: false,
            audit_yield_eligible: false,
        };
        let effects = match phase {
            RecoveryPhase::Certifying => vec![RecoveryEffect::SendProbes {
                attempt: restored.attempt,
            }],
            RecoveryPhase::FetchingTerminalCheckpoint => vec![RecoveryEffect::SendTransfer {
                attempt: restored.attempt,
                donor: coordinator
                    .donor()
                    .expect("validated recovery donor")
                    .clone(),
                terminal_cut: coordinator
                    .representation_cut
                    .clone()
                    .expect("validated representation cut"),
                kind: TransferKind::TerminalCheckpoint,
            }],
            RecoveryPhase::Backoff => vec![RecoveryEffect::Retry {
                attempt: restored.attempt,
            }],
            RecoveryPhase::Prepared | RecoveryPhase::Installing | RecoveryPhase::Verifying => {
                Vec::new()
            }
            RecoveryPhase::FetchingRepositorySnapshot | RecoveryPhase::Healthy => unreachable!(),
        };
        Ok((coordinator, effects))
    }

    pub fn phase(&self) -> RecoveryPhase {
        self.phase
    }

    pub fn attempt(&self) -> Option<RecoveryAttemptId> {
        self.attempt
    }

    pub fn certificate(&self) -> Option<&RecoveryCertificate> {
        self.certificate.as_ref()
    }

    pub fn donor(&self) -> Option<&ParticipantIncarnation> {
        self.donor_order
            .get(self.donor_index)
            .map(|attestation| &attestation.witness)
    }

    pub const fn frozen_denominator(&self) -> usize {
        self.frozen_denominator
    }

    pub fn frozen_electorate(&self) -> &[u64] {
        &self.frozen_electorate
    }

    /// Start an attempt from one exact membership view. The recovering node
    /// is excluded by the caller; each remaining node contributes exactly one
    /// node electorate seat for the lifetime of the attempt. The currently
    /// authenticated incarnation may replace an earlier vote for that seat.
    pub fn start_attempt(
        &mut self,
        trigger: RecoveryTrigger,
        attempt: RecoveryAttemptId,
        mut electorate: Vec<u64>,
        now_ms: u64,
    ) -> Vec<RecoveryEffect> {
        if self.phase != RecoveryPhase::Healthy {
            return vec![RecoveryEffect::Metric(RecoveryMetric::TriggerCoalesced)];
        }
        electorate.sort_unstable();
        if electorate.windows(2).any(|pair| pair[0] == pair[1]) {
            return vec![RecoveryEffect::Metric(RecoveryMetric::CertificateFailure)];
        }
        self.start(attempt, electorate.len() + 1, now_ms, trigger);
        self.frozen_electorate = electorate;
        vec![
            RecoveryEffect::Persist,
            RecoveryEffect::SendProbes { attempt },
            RecoveryEffect::Metric(RecoveryMetric::AttemptStarted),
        ]
    }

    pub const fn donor_index(&self) -> usize {
        self.donor_index
    }

    pub fn representation_cut(&self) -> Option<&TerminalCut> {
        self.representation_cut.as_ref()
    }

    pub fn progress_deadline_ms(&self) -> Option<u64> {
        self.progress_deadline_ms
    }

    pub fn failure_history(&self) -> &[RecoveryFailure] {
        &self.failure_history
    }

    pub fn transition(&mut self, event: RecoveryEvent) -> Vec<RecoveryEffect> {
        if let RecoveryEvent::Trigger {
            trigger,
            attempt,
            total_known_participants,
            now_ms,
        } = &event
        {
            if self.phase != RecoveryPhase::Healthy {
                return vec![RecoveryEffect::Metric(RecoveryMetric::TriggerCoalesced)];
            }
            self.start(*attempt, *total_known_participants, *now_ms, *trigger);
            return vec![
                RecoveryEffect::Persist,
                RecoveryEffect::SendProbes { attempt: *attempt },
                RecoveryEffect::Metric(RecoveryMetric::AttemptStarted),
            ];
        }

        let Some(event_attempt) = event.attempt() else {
            return Vec::new();
        };
        if self.attempt != Some(event_attempt) {
            return vec![RecoveryEffect::Metric(RecoveryMetric::StaleEvent)];
        }

        match event {
            RecoveryEvent::ProbeResponse {
                attestation,
                authenticated,
                now_ms,
                ..
            } => self.on_probe(attestation, authenticated, now_ms),
            RecoveryEvent::TransferProgress {
                donor,
                kind,
                authenticated,
                complete,
                now_ms,
                ..
            } => self.on_progress(donor, kind, authenticated, complete, now_ms),
            RecoveryEvent::Deadline { now_ms, .. } => self.on_deadline(now_ms),
            RecoveryEvent::DonorFailed {
                donor,
                failure,
                now_ms,
                ..
            } => self.on_donor_failed(donor, failure, now_ms),
            RecoveryEvent::Prepared { donor, .. } => {
                if self.phase != RecoveryPhase::FetchingRepositorySnapshot
                    || self.donor() != Some(&donor)
                {
                    return self.stale();
                }
                self.phase = RecoveryPhase::Prepared;
                vec![RecoveryEffect::Persist]
            }
            RecoveryEvent::InstallStarted { donor, .. } => {
                if self.phase != RecoveryPhase::Prepared || self.donor() != Some(&donor) {
                    return self.stale();
                }
                self.phase = RecoveryPhase::Installing;
                vec![
                    RecoveryEffect::Persist,
                    RecoveryEffect::Install {
                        attempt: event_attempt,
                        donor,
                    },
                ]
            }
            RecoveryEvent::Installed { donor, .. } => {
                if self.phase != RecoveryPhase::Installing || self.donor() != Some(&donor) {
                    return self.stale();
                }
                self.phase = RecoveryPhase::Verifying;
                vec![RecoveryEffect::Persist]
            }
            RecoveryEvent::Verified {
                donor,
                verification,
                ..
            } => self.on_verified(donor, verification, false),
            RecoveryEvent::LocalImageVerified {
                donor,
                verification,
                ..
            } => self.on_verified(donor, verification, true),
            RecoveryEvent::AuditYield { .. } => self.on_audit_yield(),
            RecoveryEvent::Cancel { now_ms, .. } => self.cancel(now_ms),
            RecoveryEvent::RetryElapsed { now_ms, .. } => {
                if self.phase != RecoveryPhase::Backoff {
                    return self.stale();
                }
                if self
                    .progress_deadline_ms
                    .is_some_and(|not_before| now_ms < not_before)
                {
                    return Vec::new();
                }
                self.phase = RecoveryPhase::Certifying;
                self.progress_deadline_ms = Some(now_ms.saturating_add(PROGRESS_DEADLINE_MS));
                self.attestations.clear();
                self.certification_progress = 0;
                self.certificate = None;
                self.donor_order.clear();
                self.donor_index = 0;
                self.representation_cut = None;
                self.representation_immutable = false;
                self.cleanup_emitted = false;
                vec![
                    RecoveryEffect::Persist,
                    RecoveryEffect::SendProbes {
                        attempt: event_attempt,
                    },
                ]
            }
            RecoveryEvent::Trigger { .. } => unreachable!(),
        }
    }

    fn start(
        &mut self,
        attempt: RecoveryAttemptId,
        participants: usize,
        now_ms: u64,
        trigger: RecoveryTrigger,
    ) {
        self.phase = RecoveryPhase::Certifying;
        self.attempt = Some(attempt);
        self.frozen_denominator = participants.saturating_sub(1);
        self.frozen_electorate.clear();
        self.quorum = fast_quorum_size(self.frozen_denominator);
        self.attestations.clear();
        self.certification_progress = 0;
        self.certificate = None;
        self.donor_order.clear();
        self.donor_index = 0;
        self.representation_cut = None;
        self.progress_deadline_ms = Some(now_ms.saturating_add(PROGRESS_DEADLINE_MS));
        self.representation_immutable = false;
        self.failure_history.clear();
        self.cleanup_emitted = false;
        self.audit_yield_eligible = trigger == RecoveryTrigger::GenerationZeroAudit;
    }

    fn on_probe(
        &mut self,
        attestation: RecoveryAttestation,
        authenticated: bool,
        now_ms: u64,
    ) -> Vec<RecoveryEffect> {
        if self.phase != RecoveryPhase::Certifying || !authenticated {
            return self.stale();
        }
        if attestation.terminal_cut.terminal_set_digest != attestation.target.terminal_set_digest {
            return self.stale();
        }
        if !self.frozen_electorate.is_empty()
            && self
                .frozen_electorate
                .binary_search(&attestation.witness.node_id)
                .is_err()
        {
            return self.stale();
        }
        if self
            .attestations
            .values()
            .any(|group| group.get(&attestation.witness) == Some(&attestation))
        {
            return Vec::new();
        }
        // One node seat has exactly one vote. A conflicting retransmission
        // replaces its earlier response instead of allowing restarted
        // incarnations of the same node to occupy multiple quorum seats.
        for group in self.attestations.values_mut() {
            group.retain(|witness, _| witness.node_id != attestation.witness.node_id);
        }
        let attested_target = attestation.target.clone();
        let target_attestation_count = {
            let target_attestations = self
                .attestations
                .entry(attested_target.clone())
                .or_default();
            target_attestations.insert(attestation.witness.clone(), attestation);
            target_attestations.len()
        };
        let max_distinct_witnesses = self
            .attestations
            .values()
            .map(BTreeMap::len)
            .max()
            .unwrap_or_default();
        // Certification progress is a monotone high-water mark. Replacing a
        // participant's vote may change its target group, but oscillating the
        // same finite votes can never earn the same deadline extension twice.
        if max_distinct_witnesses > self.certification_progress {
            self.certification_progress = max_distinct_witnesses;
            self.progress_deadline_ms = Some(now_ms.saturating_add(PROGRESS_DEADLINE_MS));
        }
        if target_attestation_count < self.quorum.max(1) {
            return Vec::new();
        }

        let target_attestations = self
            .attestations
            .get(&attested_target)
            .expect("inserted attestation target");
        let mut witnesses: Vec<_> = target_attestations.values().cloned().collect();
        witnesses.sort_by(|a, b| a.witness.cmp(&b.witness));
        let target = witnesses[0].target.clone();
        self.certificate = Some(RecoveryCertificate {
            target,
            frozen_denominator: self.frozen_denominator,
            witnesses: witnesses.clone(),
        });
        witnesses.sort_by(|a, b| {
            b.history_rank
                .cmp(&a.history_rank)
                .then_with(|| a.witness.cmp(&b.witness))
        });
        self.donor_order = witnesses;
        self.donor_index = 0;
        self.representation_cut = Some(self.donor_order[0].terminal_cut.clone());
        self.phase = RecoveryPhase::FetchingTerminalCheckpoint;
        let attempt = self.attempt.expect("active attempt");
        let donor = self.donor_order[0].witness.clone();
        let terminal_cut = self.representation_cut.clone().expect("representation cut");
        vec![
            RecoveryEffect::Persist,
            RecoveryEffect::SendTransfer {
                attempt,
                donor,
                terminal_cut,
                kind: TransferKind::TerminalCheckpoint,
            },
        ]
    }

    fn on_progress(
        &mut self,
        donor: ParticipantIncarnation,
        kind: TransferKind,
        authenticated: bool,
        complete: bool,
        now_ms: u64,
    ) -> Vec<RecoveryEffect> {
        if self.donor() != Some(&donor) || !authenticated {
            return self.stale();
        }
        let expected = match self.phase {
            RecoveryPhase::FetchingTerminalCheckpoint => TransferKind::TerminalCheckpoint,
            RecoveryPhase::FetchingRepositorySnapshot => TransferKind::RepositorySnapshot,
            _ => return self.stale(),
        };
        if kind != expected {
            return self.stale();
        }
        if self.representation_immutable && kind == TransferKind::RepositorySnapshot {
            return Vec::new();
        }
        self.progress_deadline_ms = Some(now_ms.saturating_add(PROGRESS_DEADLINE_MS));
        if !complete {
            return Vec::new();
        }
        let attempt = self.attempt.expect("active attempt");
        let cut = self.representation_cut.clone().expect("certified cut");
        if kind == TransferKind::TerminalCheckpoint {
            self.phase = RecoveryPhase::FetchingRepositorySnapshot;
            vec![
                RecoveryEffect::Persist,
                RecoveryEffect::SendTransfer {
                    attempt,
                    donor,
                    terminal_cut: cut,
                    kind: TransferKind::RepositorySnapshot,
                },
            ]
        } else {
            self.representation_immutable = true;
            vec![RecoveryEffect::PrepareInstall {
                attempt,
                donor,
                terminal_cut: cut,
            }]
        }
    }

    fn on_deadline(&mut self, now_ms: u64) -> Vec<RecoveryEffect> {
        if !matches!(
            self.phase,
            RecoveryPhase::Certifying
                | RecoveryPhase::FetchingTerminalCheckpoint
                | RecoveryPhase::FetchingRepositorySnapshot
        ) || self
            .progress_deadline_ms
            .is_some_and(|deadline| now_ms < deadline)
        {
            return Vec::new();
        }
        if self.phase == RecoveryPhase::Certifying {
            let mut effects = self.enter_backoff(now_ms);
            effects.push(RecoveryEffect::Metric(RecoveryMetric::CertificateFailure));
            return effects;
        }
        let donor = self.donor().cloned().expect("transfer donor");
        self.on_donor_failed(donor, DonorFailure::NoProgressDeadline, now_ms)
    }

    fn on_donor_failed(
        &mut self,
        donor: ParticipantIncarnation,
        failure: DonorFailure,
        now_ms: u64,
    ) -> Vec<RecoveryEffect> {
        if self.donor() != Some(&donor)
            || !matches!(
                self.phase,
                RecoveryPhase::FetchingTerminalCheckpoint
                    | RecoveryPhase::FetchingRepositorySnapshot
            )
        {
            return self.stale();
        }
        // Repository completion freezes both the certified representation
        // and its donor. Failures that were already in flight may still be
        // delivered before the local PrepareInstall completion event, but
        // they can no longer invalidate or replace the staged image.
        if self.representation_immutable {
            return Vec::new();
        }
        self.failure_history
            .push(RecoveryFailure::new(donor.clone(), failure));
        if failure == DonorFailure::TargetMoved {
            return self.enter_backoff(now_ms);
        }
        if !matches!(
            failure,
            DonorFailure::IncarnationLost
                | DonorFailure::SustainedRouteLoss
                | DonorFailure::NoProgressDeadline
        ) {
            let attempt = self.attempt.expect("active attempt");
            return vec![
                RecoveryEffect::Persist,
                RecoveryEffect::Retry { attempt },
                RecoveryEffect::Metric(RecoveryMetric::Retransmit),
            ];
        }
        if self.donor_index + 1 >= self.donor_order.len() {
            return self.enter_backoff(now_ms);
        }
        self.donor_index += 1;
        self.progress_deadline_ms = Some(now_ms.saturating_add(PROGRESS_DEADLINE_MS));
        let next = &self.donor_order[self.donor_index];
        self.representation_cut = Some(next.terminal_cut.clone());
        let attempt = self.attempt.expect("active attempt");
        // Terminal and repository payloads must share the new donor's exact
        // representation cut. Even if the prior donor's terminal transfer
        // completed, restart the new donor at terminal cursor zero.
        self.phase = RecoveryPhase::FetchingTerminalCheckpoint;
        let kind = TransferKind::TerminalCheckpoint;
        vec![
            RecoveryEffect::Persist,
            RecoveryEffect::SendTransfer {
                attempt,
                donor: next.witness.clone(),
                terminal_cut: next.terminal_cut.clone(),
                kind,
            },
            RecoveryEffect::Metric(RecoveryMetric::DonorSwitched),
        ]
    }

    fn enter_backoff(&mut self, now_ms: u64) -> Vec<RecoveryEffect> {
        self.phase = RecoveryPhase::Backoff;
        self.progress_deadline_ms = Some(now_ms.saturating_add(RECOVERY_RETRY_DELAY_MS));
        let attempt = self.attempt.expect("active attempt");
        vec![RecoveryEffect::Persist, RecoveryEffect::Retry { attempt }]
    }

    fn on_verified(
        &mut self,
        donor: ParticipantIncarnation,
        verification: Verification,
        local_certified_image: bool,
    ) -> Vec<RecoveryEffect> {
        if self.donor() != Some(&donor)
            || (self.phase != RecoveryPhase::Verifying
                && !(local_certified_image
                    && self.phase == RecoveryPhase::FetchingTerminalCheckpoint))
        {
            return self.stale();
        }
        let Some(certificate) = &self.certificate else {
            return self.stale();
        };
        if verification.target != certificate.target
            || Some(&verification.terminal_cut) != self.representation_cut.as_ref()
        {
            // Verification is a local, terminal install phase. A mismatched
            // completion cannot reopen certification or discard the frozen
            // staged representation. The executor may retry verification or
            // surface the mismatch while the replica remains fenced.
            return Vec::new();
        }
        let attempt = self.attempt.expect("active attempt");
        self.phase = RecoveryPhase::Healthy;
        self.attempt = None;
        self.progress_deadline_ms = None;
        self.audit_yield_eligible = false;
        let mut effects = vec![RecoveryEffect::Persist];
        if local_certified_image {
            effects[0] = RecoveryEffect::ClearCompletedAttempt { attempt };
        }
        effects.extend([
            RecoveryEffect::Cleanup { attempt },
            RecoveryEffect::Metric(RecoveryMetric::Completed),
        ]);
        effects
    }

    fn cancel(&mut self, now_ms: u64) -> Vec<RecoveryEffect> {
        if self.cleanup_emitted {
            return Vec::new();
        }
        let attempt = self.attempt.expect("active attempt");
        self.cleanup_emitted = true;
        // Cancellation releases attempt-owned resources but must not make an
        // unverified replica healthy. Retain the attempt identity through
        // backoff so a fresh wire transfer can resume certification.
        self.phase = RecoveryPhase::Backoff;
        self.progress_deadline_ms = Some(now_ms.saturating_add(RECOVERY_RETRY_DELAY_MS));
        vec![
            RecoveryEffect::Persist,
            RecoveryEffect::Cleanup { attempt },
            RecoveryEffect::Retry { attempt },
            RecoveryEffect::Metric(RecoveryMetric::Cancelled),
        ]
    }

    fn on_audit_yield(&mut self) -> Vec<RecoveryEffect> {
        if !self.audit_yield_eligible
            || !matches!(
                self.phase,
                RecoveryPhase::Certifying
                    | RecoveryPhase::FetchingTerminalCheckpoint
                    | RecoveryPhase::FetchingRepositorySnapshot
                    | RecoveryPhase::Backoff
            )
            || self.representation_immutable
        {
            return self.stale();
        }
        let attempt = self.attempt.expect("active audit attempt");
        self.phase = RecoveryPhase::Healthy;
        self.attempt = None;
        self.progress_deadline_ms = None;
        self.audit_yield_eligible = false;
        let mut effects = vec![RecoveryEffect::ClearCompletedAttempt { attempt }];
        if !self.cleanup_emitted {
            self.cleanup_emitted = true;
            effects.push(RecoveryEffect::Cleanup { attempt });
        }
        effects
    }

    fn stale(&self) -> Vec<RecoveryEffect> {
        vec![RecoveryEffect::Metric(RecoveryMetric::StaleEvent)]
    }
}

impl RecoveryEvent {
    fn attempt(&self) -> Option<RecoveryAttemptId> {
        Some(match self {
            Self::Trigger { attempt, .. }
            | Self::ProbeResponse { attempt, .. }
            | Self::TransferProgress { attempt, .. }
            | Self::Deadline { attempt, .. }
            | Self::DonorFailed { attempt, .. }
            | Self::Prepared { attempt, .. }
            | Self::InstallStarted { attempt, .. }
            | Self::Installed { attempt, .. }
            | Self::Verified { attempt, .. }
            | Self::LocalImageVerified { attempt, .. }
            | Self::AuditYield { attempt }
            | Self::Cancel { attempt, .. }
            | Self::RetryElapsed { attempt, .. } => *attempt,
        })
    }
}

fn infer_frozen_electorate(
    denominator: usize,
    occupied_nodes: impl IntoIterator<Item = u64>,
) -> Vec<u64> {
    let mut electorate = occupied_nodes.into_iter().collect::<BTreeSet<_>>();
    let mut candidate = 0u64;
    while electorate.len() < denominator {
        electorate.insert(candidate);
        let Some(next) = candidate.checked_add(1) else {
            break;
        };
        candidate = next;
    }
    electorate.into_iter().take(denominator).collect()
}

/// Fast quorum among the frozen participant denominator, excluding requester.
pub const fn fast_quorum_size(denominator: usize) -> usize {
    if denominator == 0 {
        0
    } else {
        denominator - denominator / 4
    }
}

#[cfg(test)]
mod exhaustive_tests {
    use super::*;

    const ATTEMPT: RecoveryAttemptId = RecoveryAttemptId::new(7, 11);

    fn target(tag: u8) -> LogicalTarget {
        LogicalTarget::new(40 + u64::from(tag), 9, [tag; 32])
    }

    fn cut(tag: u8) -> TerminalCut {
        TerminalCut::new([tag; 16], u64::from(tag), [tag + 1; 32], [tag + 2; 32])
    }

    fn cut_for_target(tag: u8, target: &LogicalTarget) -> TerminalCut {
        TerminalCut::new(
            [tag; 16],
            u64::from(tag),
            [tag + 1; 32],
            *target.terminal_set_digest(),
        )
    }

    fn peer(node_id: u64, boot_epoch: u64) -> ParticipantIncarnation {
        ParticipantIncarnation::new(node_id, boot_epoch)
    }

    fn attestation(
        node_id: u64,
        boot_epoch: u64,
        rank: u64,
        target: LogicalTarget,
        cut: TerminalCut,
    ) -> RecoveryAttestation {
        RecoveryAttestation::new(peer(node_id, boot_epoch), target, cut, rank)
    }

    fn start(coordinator: &mut StrictRecoveryCoordinator) {
        start_with_trigger(coordinator, RecoveryTrigger::Explicit);
    }

    fn start_with_trigger(coordinator: &mut StrictRecoveryCoordinator, trigger: RecoveryTrigger) {
        coordinator.transition(RecoveryEvent::Trigger {
            trigger,
            attempt: ATTEMPT,
            total_known_participants: 3,
            now_ms: 100,
        });
    }

    fn certify(coordinator: &mut StrictRecoveryCoordinator) {
        certify_with_trigger(coordinator, RecoveryTrigger::Explicit);
    }

    fn certify_with_trigger(coordinator: &mut StrictRecoveryCoordinator, trigger: RecoveryTrigger) {
        start_with_trigger(coordinator, trigger);
        let target = target(1);
        coordinator.transition(RecoveryEvent::ProbeResponse {
            attempt: ATTEMPT,
            attestation: attestation(2, 1, 10, target.clone(), cut_for_target(2, &target)),
            authenticated: true,
            now_ms: 101,
        });
        let terminal_cut = cut_for_target(1, &target);
        coordinator.transition(RecoveryEvent::ProbeResponse {
            attempt: ATTEMPT,
            attestation: attestation(1, 1, 20, target, terminal_cut),
            authenticated: true,
            now_ms: 102,
        });
        assert_eq!(
            coordinator.phase(),
            RecoveryPhase::FetchingTerminalCheckpoint
        );
    }

    #[test]
    fn attempt_id_exposes_wire_halves() {
        assert_eq!(ATTEMPT.hi(), 7);
        assert_eq!(ATTEMPT.lo(), 11);
    }

    #[test]
    fn fast_quorum_size_is_overflow_safe_at_usize_max() {
        assert_eq!(fast_quorum_size(usize::MAX), usize::MAX - usize::MAX / 4);
    }

    #[test]
    fn restarted_node_cannot_occupy_two_frozen_quorum_seats() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        coordinator.transition(RecoveryEvent::Trigger {
            trigger: RecoveryTrigger::Explicit,
            attempt: ATTEMPT,
            total_known_participants: 4,
            now_ms: 100,
        });
        let target = target(1);
        for (node_id, boot_epoch) in [(2, 1), (2, 2), (3, 1)] {
            coordinator.transition(RecoveryEvent::ProbeResponse {
                attempt: ATTEMPT,
                attestation: attestation(
                    node_id,
                    boot_epoch,
                    10,
                    target.clone(),
                    cut_for_target(node_id as u8, &target),
                ),
                authenticated: true,
                now_ms: 101 + boot_epoch,
            });
        }

        assert_eq!(coordinator.phase(), RecoveryPhase::Certifying);
        assert!(coordinator.certificate().is_none());
    }

    #[test]
    fn duplicate_triggers_coalesce_without_mutating_every_active_phase() {
        for phase in [
            RecoveryPhase::Certifying,
            RecoveryPhase::FetchingTerminalCheckpoint,
            RecoveryPhase::FetchingRepositorySnapshot,
            RecoveryPhase::Prepared,
            RecoveryPhase::Installing,
            RecoveryPhase::Verifying,
            RecoveryPhase::Backoff,
        ] {
            let mut coordinator = StrictRecoveryCoordinator::default();
            start(&mut coordinator);
            coordinator.phase = phase;
            coordinator.donor_index = 17;
            coordinator.progress_deadline_ms = Some(999);
            let before = coordinator.clone();
            let effects = coordinator.transition(RecoveryEvent::Trigger {
                trigger: RecoveryTrigger::Admission,
                attempt: RecoveryAttemptId::new(99, 100),
                total_known_participants: 100,
                now_ms: 500,
            });
            assert_eq!(coordinator, before);
            assert_eq!(
                effects,
                vec![RecoveryEffect::Metric(RecoveryMetric::TriggerCoalesced)]
            );
        }
    }

    #[test]
    fn stale_attempt_and_wrong_donor_incarnation_are_ignored() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        certify(&mut coordinator);
        let deadline = coordinator.progress_deadline_ms();
        let before = coordinator.clone();
        let effects = coordinator.transition(RecoveryEvent::Deadline {
            attempt: RecoveryAttemptId::new(7, 12),
            now_ms: u64::MAX,
        });
        assert_eq!(coordinator, before);
        assert_eq!(effects, coordinator.stale());

        let effects = coordinator.transition(RecoveryEvent::TransferProgress {
            attempt: ATTEMPT,
            donor: peer(1, 2),
            kind: TransferKind::TerminalCheckpoint,
            authenticated: true,
            complete: false,
            now_ms: 1_000,
        });
        assert_eq!(coordinator.progress_deadline_ms(), deadline);
        assert_eq!(effects, coordinator.stale());
    }

    #[test]
    fn local_install_callbacks_require_the_certified_donor_incarnation() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        certify(&mut coordinator);
        let donor = coordinator.donor().unwrap().clone();
        let wrong_donor = ParticipantIncarnation::new(donor.node_id(), donor.boot_epoch() + 1);
        let verification = Verification::new(
            coordinator.certificate().unwrap().target().clone(),
            coordinator.representation_cut().unwrap().clone(),
        );

        coordinator.phase = RecoveryPhase::Prepared;
        let before = coordinator.clone();
        assert_eq!(
            coordinator.transition(RecoveryEvent::InstallStarted {
                attempt: ATTEMPT,
                donor: wrong_donor.clone(),
            }),
            coordinator.stale()
        );
        assert_eq!(coordinator, before);
        assert_eq!(
            coordinator.transition(RecoveryEvent::InstallStarted {
                attempt: ATTEMPT,
                donor: donor.clone(),
            }),
            vec![
                RecoveryEffect::Persist,
                RecoveryEffect::Install {
                    attempt: ATTEMPT,
                    donor: donor.clone(),
                },
            ]
        );

        let before = coordinator.clone();
        assert_eq!(
            coordinator.transition(RecoveryEvent::Installed {
                attempt: ATTEMPT,
                donor: wrong_donor.clone(),
            }),
            coordinator.stale()
        );
        assert_eq!(coordinator, before);
        coordinator.transition(RecoveryEvent::Installed {
            attempt: ATTEMPT,
            donor: donor.clone(),
        });

        let before = coordinator.clone();
        assert_eq!(
            coordinator.transition(RecoveryEvent::Verified {
                attempt: ATTEMPT,
                donor: wrong_donor.clone(),
                verification: verification.clone(),
            }),
            coordinator.stale()
        );
        assert_eq!(coordinator, before);
        coordinator.transition(RecoveryEvent::Verified {
            attempt: ATTEMPT,
            donor: donor.clone(),
            verification: verification.clone(),
        });
        assert_eq!(coordinator.phase(), RecoveryPhase::Healthy);

        let mut local = StrictRecoveryCoordinator::default();
        certify(&mut local);
        let before = local.clone();
        assert_eq!(
            local.transition(RecoveryEvent::LocalImageVerified {
                attempt: ATTEMPT,
                donor: wrong_donor,
                verification,
            }),
            local.stale()
        );
        assert_eq!(local, before);
    }

    #[test]
    fn only_authenticated_progress_refreshes_deadline() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        certify(&mut coordinator);
        let original = coordinator.progress_deadline_ms();
        let donor = coordinator.donor().unwrap().clone();
        coordinator.transition(RecoveryEvent::TransferProgress {
            attempt: ATTEMPT,
            donor: donor.clone(),
            kind: TransferKind::TerminalCheckpoint,
            authenticated: false,
            complete: false,
            now_ms: 1_000,
        });
        assert_eq!(coordinator.progress_deadline_ms(), original);
        coordinator.transition(RecoveryEvent::TransferProgress {
            attempt: ATTEMPT,
            donor,
            kind: TransferKind::TerminalCheckpoint,
            authenticated: true,
            complete: false,
            now_ms: 1_000,
        });
        assert_eq!(
            coordinator.progress_deadline_ms(),
            Some(1_000 + PROGRESS_DEADLINE_MS)
        );
    }

    #[test]
    fn authenticated_duplicate_probe_response_does_not_refresh_certification_deadline() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        start(&mut coordinator);
        let terminal_cut = cut(1);
        let logical_target = LogicalTarget::new(41, 9, *terminal_cut.terminal_set_digest());
        let response = attestation(1, 1, 5, logical_target, terminal_cut);
        coordinator.transition(RecoveryEvent::ProbeResponse {
            attempt: ATTEMPT,
            attestation: response.clone(),
            authenticated: true,
            now_ms: 200,
        });
        let before_duplicate = coordinator.clone();

        let effects = coordinator.transition(RecoveryEvent::ProbeResponse {
            attempt: ATTEMPT,
            attestation: response,
            authenticated: true,
            now_ms: 20_000,
        });

        assert_eq!(coordinator, before_duplicate);
        assert!(effects.is_empty());
    }

    #[test]
    fn alternating_target_from_one_incarnation_cannot_extend_certification_forever() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        coordinator.transition(RecoveryEvent::Trigger {
            trigger: RecoveryTrigger::Explicit,
            attempt: ATTEMPT,
            total_known_participants: 7,
            now_ms: 100,
        });
        let first = target(1);
        let second = target(2);
        coordinator.transition(RecoveryEvent::ProbeResponse {
            attempt: ATTEMPT,
            attestation: attestation(1, 1, 5, first.clone(), cut_for_target(1, &first)),
            authenticated: true,
            now_ms: 200,
        });
        coordinator.transition(RecoveryEvent::ProbeResponse {
            attempt: ATTEMPT,
            attestation: attestation(2, 1, 5, second.clone(), cut_for_target(2, &second)),
            authenticated: true,
            now_ms: 300,
        });
        coordinator.transition(RecoveryEvent::ProbeResponse {
            attempt: ATTEMPT,
            attestation: attestation(1, 1, 5, second.clone(), cut_for_target(1, &second)),
            authenticated: true,
            now_ms: 400,
        });
        let high_water_deadline = coordinator.progress_deadline_ms();

        for (now_ms, attested_target) in [
            (500, first.clone()),
            (600, second.clone()),
            (700, first),
            (800, second),
        ] {
            coordinator.transition(RecoveryEvent::ProbeResponse {
                attempt: ATTEMPT,
                attestation: attestation(
                    1,
                    1,
                    5,
                    attested_target.clone(),
                    cut_for_target(1, &attested_target),
                ),
                authenticated: true,
                now_ms,
            });
            assert_eq!(coordinator.progress_deadline_ms(), high_water_deadline);
        }
        assert_eq!(coordinator.phase(), RecoveryPhase::Certifying);
        assert_eq!(coordinator.certification_progress, 2);
    }

    #[test]
    fn attestation_with_terminal_digest_outside_logical_target_is_rejected() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        coordinator.transition(RecoveryEvent::Trigger {
            trigger: RecoveryTrigger::Explicit,
            attempt: ATTEMPT,
            total_known_participants: 2,
            now_ms: 100,
        });
        let before_response = coordinator.clone();

        let effects = coordinator.transition(RecoveryEvent::ProbeResponse {
            attempt: ATTEMPT,
            attestation: RecoveryAttestation::new(peer(1, 1), target(1), cut(1), 5),
            authenticated: true,
            now_ms: 200,
        });

        assert_eq!(coordinator, before_response);
        assert_eq!(effects, coordinator.stale());
    }

    #[test]
    fn quorum_groups_by_target_and_distinct_incarnation() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        start(&mut coordinator);
        let first = target(1);
        let conflicting = target(2);
        for response in [
            attestation(1, 1, 5, first.clone(), cut_for_target(1, &first)),
            attestation(
                2,
                1,
                6,
                conflicting.clone(),
                cut_for_target(2, &conflicting),
            ),
            // Duplicate incarnation replaces, rather than adding, a vote.
            attestation(1, 1, 7, first.clone(), cut_for_target(3, &first)),
        ] {
            coordinator.transition(RecoveryEvent::ProbeResponse {
                attempt: ATTEMPT,
                attestation: response,
                authenticated: true,
                now_ms: 200,
            });
        }
        assert_eq!(coordinator.phase(), RecoveryPhase::Certifying);
        assert!(coordinator.certificate().is_none());

        coordinator.transition(RecoveryEvent::ProbeResponse {
            attempt: ATTEMPT,
            attestation: attestation(2, 2, 4, first.clone(), cut_for_target(4, &first)),
            authenticated: true,
            now_ms: 201,
        });
        let certificate = coordinator.certificate().unwrap();
        assert_eq!(certificate.target(), &first);
        assert_eq!(certificate.frozen_denominator(), 2);
        assert_eq!(certificate.witnesses().len(), 2);
    }

    #[test]
    fn donor_order_is_ranked_deterministically_and_switches_only_for_exclusive_causes() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        certify(&mut coordinator);
        assert_eq!(coordinator.donor(), Some(&peer(1, 1)));

        let effects = coordinator.transition(RecoveryEvent::DonorFailed {
            attempt: ATTEMPT,
            donor: peer(1, 1),
            failure: DonorFailure::RetryableFailure,
            now_ms: 300,
        });
        assert_eq!(coordinator.donor(), Some(&peer(1, 1)));
        assert!(effects.contains(&RecoveryEffect::Metric(RecoveryMetric::Retransmit)));

        coordinator.transition(RecoveryEvent::DonorFailed {
            attempt: ATTEMPT,
            donor: peer(1, 1),
            failure: DonorFailure::SustainedRouteLoss,
            now_ms: 301,
        });
        assert_eq!(coordinator.donor(), Some(&peer(2, 1)));
        assert_eq!(coordinator.failure_history().len(), 2);

        let mut moved = StrictRecoveryCoordinator::default();
        certify(&mut moved);
        moved.transition(RecoveryEvent::DonorFailed {
            attempt: ATTEMPT,
            donor: peer(1, 1),
            failure: DonorFailure::TargetMoved,
            now_ms: 302,
        });
        assert_eq!(moved.phase(), RecoveryPhase::Backoff);
    }

    #[test]
    fn snapshot_phase_donor_switch_restarts_terminal_checkpoint_for_new_representation() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        certify(&mut coordinator);
        let first_donor = coordinator.donor().unwrap().clone();
        coordinator.transition(RecoveryEvent::TransferProgress {
            attempt: ATTEMPT,
            donor: first_donor.clone(),
            kind: TransferKind::TerminalCheckpoint,
            authenticated: true,
            complete: true,
            now_ms: 300,
        });
        assert_eq!(
            coordinator.phase(),
            RecoveryPhase::FetchingRepositorySnapshot
        );

        let effects = coordinator.transition(RecoveryEvent::DonorFailed {
            attempt: ATTEMPT,
            donor: first_donor,
            failure: DonorFailure::SustainedRouteLoss,
            now_ms: 301,
        });

        assert_eq!(coordinator.donor(), Some(&peer(2, 1)));
        assert_eq!(
            coordinator.phase(),
            RecoveryPhase::FetchingTerminalCheckpoint
        );
        assert!(matches!(
            effects.as_slice(),
            [
                RecoveryEffect::Persist,
                RecoveryEffect::SendTransfer {
                    donor,
                    terminal_cut,
                    kind: TransferKind::TerminalCheckpoint,
                    ..
                },
                RecoveryEffect::Metric(RecoveryMetric::DonorSwitched),
            ] if donor == &peer(2, 1) && terminal_cut == &cut_for_target(2, &target(1))
        ));
    }

    #[test]
    fn delayed_donor_failure_cannot_discard_an_immutable_representation() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        certify(&mut coordinator);
        let first_donor = coordinator.donor().unwrap().clone();
        coordinator.transition(RecoveryEvent::DonorFailed {
            attempt: ATTEMPT,
            donor: first_donor,
            failure: DonorFailure::SustainedRouteLoss,
            now_ms: 300,
        });
        assert_eq!(coordinator.donor_index(), 1);

        let second_donor = coordinator.donor().unwrap().clone();
        coordinator.transition(RecoveryEvent::TransferProgress {
            attempt: ATTEMPT,
            donor: second_donor.clone(),
            kind: TransferKind::TerminalCheckpoint,
            authenticated: true,
            complete: true,
            now_ms: 301,
        });
        coordinator.transition(RecoveryEvent::TransferProgress {
            attempt: ATTEMPT,
            donor: second_donor.clone(),
            kind: TransferKind::RepositorySnapshot,
            authenticated: true,
            complete: true,
            now_ms: 302,
        });
        assert!(coordinator.representation_immutable);

        let immutable_state = coordinator.clone();

        let effects = coordinator.transition(RecoveryEvent::DonorFailed {
            attempt: ATTEMPT,
            donor: second_donor,
            failure: DonorFailure::TargetMoved,
            now_ms: 303,
        });

        assert!(effects.is_empty());
        assert_eq!(coordinator, immutable_state);
    }

    #[test]
    fn duplicate_repository_completion_emits_prepare_install_only_once() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        certify(&mut coordinator);
        let donor = coordinator.donor().unwrap().clone();
        coordinator.transition(RecoveryEvent::TransferProgress {
            attempt: ATTEMPT,
            donor: donor.clone(),
            kind: TransferKind::TerminalCheckpoint,
            authenticated: true,
            complete: true,
            now_ms: 300,
        });

        let first = coordinator.transition(RecoveryEvent::TransferProgress {
            attempt: ATTEMPT,
            donor: donor.clone(),
            kind: TransferKind::RepositorySnapshot,
            authenticated: true,
            complete: true,
            now_ms: 301,
        });
        let duplicate = coordinator.transition(RecoveryEvent::TransferProgress {
            attempt: ATTEMPT,
            donor,
            kind: TransferKind::RepositorySnapshot,
            authenticated: true,
            complete: true,
            now_ms: 302,
        });

        assert_eq!(
            first
                .iter()
                .chain(&duplicate)
                .filter(|effect| matches!(effect, RecoveryEffect::PrepareInstall { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn restore_resumes_same_attempt_with_fresh_terminal_transfer() {
        let first_cut = cut(1);
        let second_cut = TerminalCut::new([2; 16], 2, [3; 32], *first_cut.terminal_set_digest());
        let logical_target = LogicalTarget::new(41, 9, *first_cut.terminal_set_digest());
        let first = attestation(1, 1, 20, logical_target.clone(), first_cut);
        let second = attestation(2, 1, 10, logical_target.clone(), second_cut);
        let restore = RecoveryRestore::new(
            ATTEMPT,
            RecoveryPhase::FetchingRepositorySnapshot,
            2,
            Some(logical_target),
            vec![first.clone(), second],
            vec![first.witness().clone(), peer(2, 1)],
            Some(0),
            Some(first.witness().clone()),
            Some(first.terminal_cut().clone()),
            vec![RecoveryFailure::new(
                first.witness().clone(),
                DonorFailure::RetryableFailure,
            )],
        );

        let (mut coordinator, effects) =
            StrictRecoveryCoordinator::restore(restore, 900).expect("valid durable attempt");

        assert_eq!(coordinator.attempt(), Some(ATTEMPT));
        assert_eq!(
            coordinator.phase(),
            RecoveryPhase::FetchingTerminalCheckpoint
        );
        assert_eq!(
            coordinator.failure_history(),
            &[RecoveryFailure::new(
                first.witness().clone(),
                DonorFailure::RetryableFailure,
            )]
        );
        assert!(matches!(
            effects.as_slice(),
            [RecoveryEffect::SendTransfer {
                attempt: ATTEMPT,
                donor,
                terminal_cut,
                kind: TransferKind::TerminalCheckpoint,
            }] if donor == first.witness() && terminal_cut == first.terminal_cut()
        ));
        coordinator.transition(RecoveryEvent::TransferProgress {
            attempt: ATTEMPT,
            donor: first.witness().clone(),
            kind: TransferKind::TerminalCheckpoint,
            authenticated: true,
            complete: true,
            now_ms: 901,
        });
        assert_eq!(
            coordinator.phase(),
            RecoveryPhase::FetchingRepositorySnapshot
        );
    }

    #[test]
    fn restore_rejects_inconsistent_donor_identity() {
        let witness_cut = cut(1);
        let logical_target = LogicalTarget::new(41, 9, *witness_cut.terminal_set_digest());
        let witness = attestation(1, 1, 20, logical_target.clone(), witness_cut);
        let restore = RecoveryRestore::new(
            ATTEMPT,
            RecoveryPhase::FetchingTerminalCheckpoint,
            1,
            Some(logical_target),
            vec![witness.clone()],
            vec![witness.witness().clone()],
            Some(0),
            Some(peer(9, 9)),
            Some(witness.terminal_cut().clone()),
            Vec::new(),
        );

        assert_eq!(
            StrictRecoveryCoordinator::restore(restore, 900),
            Err(RecoveryRestoreError::CurrentDonorMismatch)
        );
    }

    #[test]
    fn restore_rejects_more_witnesses_than_the_frozen_denominator() {
        let logical_target = target(1);
        let witnesses = vec![
            attestation(
                1,
                1,
                30,
                logical_target.clone(),
                cut_for_target(1, &logical_target),
            ),
            attestation(
                2,
                1,
                20,
                logical_target.clone(),
                cut_for_target(2, &logical_target),
            ),
            attestation(
                3,
                1,
                10,
                logical_target.clone(),
                cut_for_target(3, &logical_target),
            ),
        ];
        let restore = RecoveryRestore::new(
            ATTEMPT,
            RecoveryPhase::FetchingTerminalCheckpoint,
            2,
            Some(logical_target),
            witnesses.clone(),
            witnesses
                .iter()
                .map(|witness| witness.witness().clone())
                .collect(),
            Some(0),
            Some(witnesses[0].witness().clone()),
            Some(witnesses[0].terminal_cut().clone()),
            Vec::new(),
        );

        assert_eq!(
            StrictRecoveryCoordinator::restore(restore, 900),
            Err(RecoveryRestoreError::CertificateExceedsDenominator)
        );
    }

    #[test]
    fn restore_requires_the_complete_deterministic_donor_order() {
        let logical_target = target(1);
        // Certificate witnesses are sorted by incarnation. Donors use history
        // rank descending and incarnation ascending as the tie-break.
        let witnesses = vec![
            attestation(
                1,
                1,
                10,
                logical_target.clone(),
                cut_for_target(1, &logical_target),
            ),
            attestation(
                2,
                1,
                20,
                logical_target.clone(),
                cut_for_target(2, &logical_target),
            ),
            attestation(
                3,
                1,
                20,
                logical_target.clone(),
                cut_for_target(3, &logical_target),
            ),
        ];
        let expected = vec![peer(2, 1), peer(3, 1), peer(1, 1)];

        for invalid_order in [
            vec![peer(2, 1), peer(3, 1)],
            vec![peer(3, 1), peer(2, 1), peer(1, 1)],
        ] {
            let current = invalid_order[0].clone();
            let current_cut = witnesses
                .iter()
                .find(|witness| witness.witness() == &current)
                .expect("donor remains a certified witness")
                .terminal_cut()
                .clone();
            let restore = RecoveryRestore::new(
                ATTEMPT,
                RecoveryPhase::FetchingTerminalCheckpoint,
                3,
                Some(logical_target.clone()),
                witnesses.clone(),
                invalid_order,
                Some(0),
                Some(current),
                Some(current_cut),
                Vec::new(),
            );

            assert_eq!(
                StrictRecoveryCoordinator::restore(restore, 900),
                Err(RecoveryRestoreError::InvalidDonorOrder)
            );
        }

        let restore = RecoveryRestore::new(
            ATTEMPT,
            RecoveryPhase::FetchingTerminalCheckpoint,
            3,
            Some(logical_target),
            witnesses.clone(),
            expected.clone(),
            Some(0),
            Some(expected[0].clone()),
            Some(witnesses[1].terminal_cut().clone()),
            Vec::new(),
        );
        let (coordinator, _) =
            StrictRecoveryCoordinator::restore(restore, 900).expect("deterministic donor order");
        assert_eq!(coordinator.donor(), Some(&expected[0]));
    }

    #[test]
    fn no_progress_deadline_switches_donor_but_early_deadline_does_not() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        certify(&mut coordinator);
        let deadline = coordinator.progress_deadline_ms().unwrap();
        assert!(
            coordinator
                .transition(RecoveryEvent::Deadline {
                    attempt: ATTEMPT,
                    now_ms: deadline - 1,
                })
                .is_empty()
        );
        assert_eq!(coordinator.donor(), Some(&peer(1, 1)));
        coordinator.transition(RecoveryEvent::Deadline {
            attempt: ATTEMPT,
            now_ms: deadline,
        });
        assert_eq!(coordinator.donor(), Some(&peer(2, 1)));
    }

    #[test]
    fn completion_requires_exact_target_and_all_terminal_cut_fields() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        certify(&mut coordinator);
        let donor = coordinator.donor().unwrap().clone();
        let exact_target = coordinator.certificate().unwrap().target().clone();
        let exact_cut = coordinator.representation_cut.clone().unwrap();
        coordinator.phase = RecoveryPhase::Verifying;

        let mut wrong_cut = exact_cut.clone();
        wrong_cut.chain_digest[0] ^= 1;
        let immutable_state = coordinator.clone();
        let effects = coordinator.transition(RecoveryEvent::Verified {
            attempt: ATTEMPT,
            donor: donor.clone(),
            verification: Verification::new(exact_target.clone(), wrong_cut),
        });
        assert!(effects.is_empty());
        assert_eq!(coordinator, immutable_state);

        let effects = coordinator.transition(RecoveryEvent::Verified {
            attempt: ATTEMPT,
            donor: donor.clone(),
            verification: Verification::new(target(9), exact_cut.clone()),
        });
        assert!(effects.is_empty());
        assert_eq!(coordinator, immutable_state);

        let effects = coordinator.transition(RecoveryEvent::Verified {
            attempt: ATTEMPT,
            donor,
            verification: Verification::new(exact_target, exact_cut),
        });
        assert_eq!(coordinator.phase(), RecoveryPhase::Healthy);
        assert!(effects.contains(&RecoveryEffect::Metric(RecoveryMetric::Completed)));
    }

    #[test]
    fn certified_exact_local_image_can_complete_before_opening_a_transfer() {
        let mut exact = StrictRecoveryCoordinator::default();
        certify(&mut exact);
        let exact_donor = exact.donor().unwrap().clone();
        let exact_target = exact.certificate().unwrap().target().clone();
        let exact_cut = exact.representation_cut().unwrap().clone();
        let effects = exact.transition(RecoveryEvent::LocalImageVerified {
            attempt: ATTEMPT,
            donor: exact_donor,
            verification: Verification::new(exact_target.clone(), exact_cut.clone()),
        });
        assert_eq!(exact.phase(), RecoveryPhase::Healthy);
        assert!(effects.contains(&RecoveryEffect::ClearCompletedAttempt { attempt: ATTEMPT }));
        assert!(effects.contains(&RecoveryEffect::Cleanup { attempt: ATTEMPT }));

        let mut wrong_target = StrictRecoveryCoordinator::default();
        certify(&mut wrong_target);
        let wrong_target_donor = wrong_target.donor().unwrap().clone();
        let certified_transfer = wrong_target.clone();
        let effects = wrong_target.transition(RecoveryEvent::LocalImageVerified {
            attempt: ATTEMPT,
            donor: wrong_target_donor,
            verification: Verification::new(target(99), exact_cut.clone()),
        });
        assert!(effects.is_empty());
        assert_eq!(wrong_target, certified_transfer);

        let mut wrong_cut = StrictRecoveryCoordinator::default();
        certify(&mut wrong_cut);
        let wrong_cut_donor = wrong_cut.donor().unwrap().clone();
        let certified_transfer = wrong_cut.clone();
        let mut mismatched_cut = exact_cut;
        mismatched_cut.journal_id[0] ^= 1;
        let effects = wrong_cut.transition(RecoveryEvent::LocalImageVerified {
            attempt: ATTEMPT,
            donor: wrong_cut_donor,
            verification: Verification::new(exact_target, mismatched_cut),
        });
        assert!(effects.is_empty());
        assert_eq!(wrong_cut, certified_transfer);

        let mut stale = StrictRecoveryCoordinator::default();
        certify(&mut stale);
        let stale_verification = Verification::new(
            stale.certificate().unwrap().target().clone(),
            stale.representation_cut().unwrap().clone(),
        );
        let stale_donor = stale.donor().unwrap().clone();
        let effects = stale.transition(RecoveryEvent::LocalImageVerified {
            attempt: RecoveryAttemptId::new(9, 9),
            donor: stale_donor,
            verification: stale_verification,
        });
        assert_eq!(stale.phase(), RecoveryPhase::FetchingTerminalCheckpoint);
        assert_eq!(
            effects,
            vec![RecoveryEffect::Metric(RecoveryMetric::StaleEvent)]
        );
    }

    #[test]
    fn cancellation_emits_one_aggregate_cleanup() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        certify(&mut coordinator);
        let first = coordinator.transition(RecoveryEvent::Cancel {
            attempt: ATTEMPT,
            now_ms: 200,
        });
        assert_eq!(
            first
                .iter()
                .filter(|effect| matches!(effect, RecoveryEffect::Cleanup { .. }))
                .count(),
            1
        );
        let second = coordinator.transition(RecoveryEvent::Cancel {
            attempt: ATTEMPT,
            now_ms: 201,
        });
        assert!(
            !second
                .iter()
                .any(|effect| matches!(effect, RecoveryEffect::Cleanup { .. }))
        );
    }

    #[test]
    fn audit_yield_after_cancel_does_not_emit_cleanup_twice_for_one_attempt() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        certify_with_trigger(&mut coordinator, RecoveryTrigger::GenerationZeroAudit);

        let cancelled = coordinator.transition(RecoveryEvent::Cancel {
            attempt: ATTEMPT,
            now_ms: 200,
        });
        let yielded = coordinator.transition(RecoveryEvent::AuditYield { attempt: ATTEMPT });

        assert_eq!(coordinator.phase(), RecoveryPhase::Healthy);
        assert!(yielded.contains(&RecoveryEffect::ClearCompletedAttempt { attempt: ATTEMPT }));
        assert!(
            !yielded
                .iter()
                .any(|effect| matches!(effect, RecoveryEffect::Cleanup { .. }))
        );
        assert_eq!(
            cancelled
                .iter()
                .chain(&yielded)
                .filter(|effect| matches!(effect, RecoveryEffect::Cleanup { attempt } if *attempt == ATTEMPT))
                .count(),
            1
        );
    }

    #[test]
    fn network_phase_generation_zero_audit_can_yield_but_prepared_cannot() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        certify_with_trigger(&mut coordinator, RecoveryTrigger::GenerationZeroAudit);
        let effects = coordinator.transition(RecoveryEvent::AuditYield { attempt: ATTEMPT });
        assert_eq!(coordinator.phase(), RecoveryPhase::Healthy);
        assert!(effects.iter().any(
            |effect| matches!(effect, RecoveryEffect::Cleanup { attempt } if *attempt == ATTEMPT)
        ));

        let mut prepared = StrictRecoveryCoordinator::default();
        certify_with_trigger(&mut prepared, RecoveryTrigger::GenerationZeroAudit);
        prepared.phase = RecoveryPhase::Prepared;
        prepared.representation_immutable = true;
        let effects = prepared.transition(RecoveryEvent::AuditYield { attempt: ATTEMPT });
        assert_eq!(prepared.phase(), RecoveryPhase::Prepared);
        assert_eq!(
            effects,
            vec![RecoveryEffect::Metric(RecoveryMetric::StaleEvent)]
        );
    }

    #[test]
    fn ordinary_recovery_attempt_cannot_accept_audit_yield() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        certify(&mut coordinator);
        let before = coordinator.clone();

        let effects = coordinator.transition(RecoveryEvent::AuditYield { attempt: ATTEMPT });

        assert_eq!(coordinator, before);
        assert_eq!(
            effects,
            vec![RecoveryEffect::Metric(RecoveryMetric::StaleEvent)]
        );
    }

    #[test]
    fn coalesced_trigger_cannot_grant_or_revoke_audit_yield_eligibility() {
        let mut ordinary = StrictRecoveryCoordinator::default();
        start(&mut ordinary);
        ordinary.transition(RecoveryEvent::Trigger {
            trigger: RecoveryTrigger::GenerationZeroAudit,
            attempt: RecoveryAttemptId::new(99, 1),
            total_known_participants: 3,
            now_ms: 200,
        });
        let effects = ordinary.transition(RecoveryEvent::AuditYield { attempt: ATTEMPT });
        assert_eq!(ordinary.phase(), RecoveryPhase::Certifying);
        assert_eq!(
            effects,
            vec![RecoveryEffect::Metric(RecoveryMetric::StaleEvent)]
        );

        let mut audit = StrictRecoveryCoordinator::default();
        start_with_trigger(&mut audit, RecoveryTrigger::GenerationZeroAudit);
        audit.transition(RecoveryEvent::Trigger {
            trigger: RecoveryTrigger::Explicit,
            attempt: RecoveryAttemptId::new(99, 2),
            total_known_participants: 3,
            now_ms: 200,
        });
        let effects = audit.transition(RecoveryEvent::AuditYield { attempt: ATTEMPT });
        assert_eq!(audit.phase(), RecoveryPhase::Healthy);
        assert!(effects.contains(&RecoveryEffect::ClearCompletedAttempt { attempt: ATTEMPT }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTEMPT: RecoveryAttemptId = RecoveryAttemptId::new(1, 2);
    const OTHER_ATTEMPT: RecoveryAttemptId = RecoveryAttemptId::new(3, 4);

    fn target(digest: u8) -> LogicalTarget {
        LogicalTarget::new(7, 11, [digest; 32])
    }

    fn cut(node: u8) -> TerminalCut {
        TerminalCut::new([node; 16], node as u64, [node; 32], [9; 32])
    }

    fn attestation(node: u64, rank: u64, terminal_cut: TerminalCut) -> RecoveryAttestation {
        RecoveryAttestation::new(
            ParticipantIncarnation::new(node, 1),
            target(9),
            terminal_cut,
            rank,
        )
    }

    fn start(coordinator: &mut StrictRecoveryCoordinator) {
        coordinator.transition(RecoveryEvent::Trigger {
            trigger: RecoveryTrigger::Explicit,
            attempt: ATTEMPT,
            total_known_participants: 3,
            now_ms: 100,
        });
    }

    fn certify(coordinator: &mut StrictRecoveryCoordinator) {
        start(coordinator);
        for response in [attestation(10, 1, cut(10)), attestation(20, 2, cut(20))] {
            coordinator.transition(RecoveryEvent::ProbeResponse {
                attempt: ATTEMPT,
                attestation: response,
                authenticated: true,
                now_ms: 200,
            });
        }
    }

    #[test]
    fn duplicate_triggers_coalesce_without_mutating_any_active_phase() {
        let active_phases = [
            RecoveryPhase::Certifying,
            RecoveryPhase::FetchingTerminalCheckpoint,
            RecoveryPhase::FetchingRepositorySnapshot,
            RecoveryPhase::Prepared,
            RecoveryPhase::Installing,
            RecoveryPhase::Verifying,
            RecoveryPhase::Backoff,
        ];

        for phase in active_phases {
            let mut coordinator = StrictRecoveryCoordinator::default();
            start(&mut coordinator);
            coordinator.phase = phase;
            let before = coordinator.clone();

            let effects = coordinator.transition(RecoveryEvent::Trigger {
                trigger: RecoveryTrigger::ClockTick,
                attempt: OTHER_ATTEMPT,
                total_known_participants: 99,
                now_ms: 99_000,
            });

            assert_eq!(coordinator, before, "phase {phase:?}");
            assert_eq!(
                effects,
                vec![RecoveryEffect::Metric(RecoveryMetric::TriggerCoalesced)]
            );
        }
    }

    #[test]
    fn stale_attempt_event_is_ignored() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        start(&mut coordinator);
        let before = coordinator.clone();

        let effects = coordinator.transition(RecoveryEvent::Deadline {
            attempt: OTHER_ATTEMPT,
            now_ms: 100_000,
        });

        assert_eq!(coordinator, before);
        assert_eq!(
            effects,
            vec![RecoveryEffect::Metric(RecoveryMetric::StaleEvent)]
        );
    }

    #[test]
    fn certification_timeout_enters_backoff_and_retry_restarts_certification() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        start(&mut coordinator);
        let deadline = coordinator.progress_deadline_ms().unwrap();

        assert!(
            coordinator
                .transition(RecoveryEvent::Deadline {
                    attempt: ATTEMPT,
                    now_ms: deadline - 1,
                })
                .is_empty()
        );
        assert_eq!(coordinator.phase(), RecoveryPhase::Certifying);

        assert_eq!(
            coordinator.transition(RecoveryEvent::Deadline {
                attempt: ATTEMPT,
                now_ms: deadline,
            }),
            vec![
                RecoveryEffect::Persist,
                RecoveryEffect::Retry { attempt: ATTEMPT },
                RecoveryEffect::Metric(RecoveryMetric::CertificateFailure)
            ]
        );
        assert_eq!(coordinator.phase(), RecoveryPhase::Backoff);
        assert_eq!(
            coordinator.progress_deadline_ms(),
            Some(deadline + RECOVERY_RETRY_DELAY_MS)
        );

        assert!(
            coordinator
                .transition(RecoveryEvent::RetryElapsed {
                    attempt: ATTEMPT,
                    now_ms: deadline + RECOVERY_RETRY_DELAY_MS - 1,
                })
                .is_empty(),
            "backoff cannot be collapsed by an executor or localhost wake"
        );
        assert_eq!(coordinator.phase(), RecoveryPhase::Backoff);

        assert_eq!(
            coordinator.transition(RecoveryEvent::RetryElapsed {
                attempt: ATTEMPT,
                now_ms: deadline + RECOVERY_RETRY_DELAY_MS,
            }),
            vec![
                RecoveryEffect::Persist,
                RecoveryEffect::SendProbes { attempt: ATTEMPT }
            ]
        );
        assert_eq!(coordinator.phase(), RecoveryPhase::Certifying);
        assert_eq!(
            coordinator.progress_deadline_ms(),
            Some(deadline + RECOVERY_RETRY_DELAY_MS + PROGRESS_DEADLINE_MS)
        );
    }

    #[test]
    fn matching_quorum_selects_highest_rank_donor_and_fails_over_deterministically() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        start(&mut coordinator);
        coordinator.transition(RecoveryEvent::ProbeResponse {
            attempt: ATTEMPT,
            attestation: attestation(10, 5, cut(10)),
            authenticated: true,
            now_ms: 200,
        });
        let effects = coordinator.transition(RecoveryEvent::ProbeResponse {
            attempt: ATTEMPT,
            attestation: attestation(20, 8, cut(20)),
            authenticated: true,
            now_ms: 201,
        });

        assert_eq!(
            coordinator.phase(),
            RecoveryPhase::FetchingTerminalCheckpoint
        );
        assert_eq!(
            coordinator.donor(),
            Some(&ParticipantIncarnation::new(20, 1))
        );
        let certificate = coordinator.certificate().unwrap();
        assert_eq!(certificate.frozen_denominator(), 2);
        assert_eq!(certificate.witnesses[0].witness.node_id(), 10);
        assert_eq!(certificate.witnesses[1].witness.node_id(), 20);
        assert!(matches!(
            effects.as_slice(),
            [
                RecoveryEffect::Persist,
                RecoveryEffect::SendTransfer {
                    donor,
                    kind: TransferKind::TerminalCheckpoint,
                    ..
                }
            ] if donor.node_id() == 20
        ));

        let effects = coordinator.transition(RecoveryEvent::DonorFailed {
            attempt: ATTEMPT,
            donor: ParticipantIncarnation::new(20, 1),
            failure: DonorFailure::SustainedRouteLoss,
            now_ms: 300,
        });
        assert_eq!(
            coordinator.donor(),
            Some(&ParticipantIncarnation::new(10, 1))
        );
        assert!(matches!(
            effects.as_slice(),
            [
                RecoveryEffect::Persist,
                RecoveryEffect::SendTransfer { donor, .. },
                RecoveryEffect::Metric(RecoveryMetric::DonorSwitched)
            ] if donor.node_id() == 10
        ));
    }

    #[test]
    fn conflicting_attestations_do_not_form_a_certificate() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        start(&mut coordinator);
        for (node, digest) in [(10, 9), (20, 8)] {
            coordinator.transition(RecoveryEvent::ProbeResponse {
                attempt: ATTEMPT,
                attestation: RecoveryAttestation::new(
                    ParticipantIncarnation::new(node, 1),
                    target(digest),
                    cut(node as u8),
                    node,
                ),
                authenticated: true,
                now_ms: 200,
            });
        }

        assert_eq!(coordinator.phase(), RecoveryPhase::Certifying);
        assert!(coordinator.certificate().is_none());
        assert!(coordinator.donor().is_none());
    }

    #[test]
    fn cancellation_emits_cleanup_exactly_once() {
        let mut coordinator = StrictRecoveryCoordinator::default();
        certify(&mut coordinator);

        let first = coordinator.transition(RecoveryEvent::Cancel {
            attempt: ATTEMPT,
            now_ms: 200,
        });
        let second = coordinator.transition(RecoveryEvent::Cancel {
            attempt: ATTEMPT,
            now_ms: 201,
        });

        assert_eq!(coordinator.phase(), RecoveryPhase::Backoff);
        assert_eq!(
            first
                .iter()
                .filter(|effect| matches!(effect, RecoveryEffect::Cleanup { .. }))
                .count(),
            1
        );
        assert_eq!(
            second
                .iter()
                .filter(|effect| matches!(effect, RecoveryEffect::Cleanup { .. }))
                .count(),
            0
        );
    }
}

#[cfg(test)]
mod autonomous_executor_proof_tests {
    use std::collections::{BTreeSet, VecDeque};

    use super::*;

    const ATTEMPT: RecoveryAttemptId = RecoveryAttemptId::new(91, 37);

    #[derive(Default)]
    struct ProofStats {
        edges: usize,
        terminal_configurations: usize,
        max_depth: usize,
        unique_configurations: BTreeSet<String>,
        phase_edges: BTreeSet<(u8, u8)>,
        phases: BTreeSet<String>,
        effects: BTreeSet<&'static str>,
    }

    fn effect_kind(effect: &RecoveryEffect) -> &'static str {
        match effect {
            RecoveryEffect::Persist => "Persist",
            RecoveryEffect::SendProbes { .. } => "SendProbes",
            RecoveryEffect::SendTransfer { .. } => "SendTransfer",
            RecoveryEffect::PrepareInstall { .. } => "PrepareInstall",
            RecoveryEffect::Install { .. } => "Install",
            RecoveryEffect::Retry { .. } => "Retry",
            RecoveryEffect::Cleanup { .. } => "Cleanup",
            RecoveryEffect::ClearCompletedAttempt { .. } => "ClearCompletedAttempt",
            RecoveryEffect::Metric(_) => "Metric",
        }
    }

    fn phase_rank(phase: RecoveryPhase) -> u8 {
        match phase {
            RecoveryPhase::Healthy | RecoveryPhase::Backoff => 0,
            RecoveryPhase::Verifying => 1,
            RecoveryPhase::Installing => 2,
            RecoveryPhase::Prepared => 3,
            RecoveryPhase::FetchingRepositorySnapshot => 4,
            RecoveryPhase::FetchingTerminalCheckpoint => 5,
            RecoveryPhase::Certifying => 6,
        }
    }

    fn certified_with_cut(cut: TerminalCut) -> (StrictRecoveryCoordinator, Vec<RecoveryEffect>) {
        let target = LogicalTarget::new(7, 11, *cut.terminal_set_digest());
        let donor = ParticipantIncarnation::new(2, 1);
        let mut coordinator = StrictRecoveryCoordinator::default();
        coordinator.transition(RecoveryEvent::Trigger {
            trigger: RecoveryTrigger::Explicit,
            attempt: ATTEMPT,
            total_known_participants: 2,
            now_ms: 100,
        });
        let effects = coordinator.transition(RecoveryEvent::ProbeResponse {
            attempt: ATTEMPT,
            attestation: RecoveryAttestation::new(donor, target, cut, 1),
            authenticated: true,
            now_ms: 101,
        });
        assert_eq!(
            coordinator.phase(),
            RecoveryPhase::FetchingTerminalCheckpoint
        );
        (coordinator, effects)
    }

    /// Enumerate every event that production effect execution can feed back
    /// without receiving another packet or a periodic clock event. An empty
    /// event list is a terminating executor outcome, not a transition.
    fn autonomous_outcomes(
        coordinator: &StrictRecoveryCoordinator,
        effect: &RecoveryEffect,
    ) -> Vec<Vec<RecoveryEvent>> {
        match effect {
            RecoveryEffect::Persist => {
                let mut outcomes = vec![Vec::new()];
                if let Some(attempt) = coordinator.attempt() {
                    outcomes.push(vec![RecoveryEvent::Cancel {
                        attempt,
                        now_ms: 200,
                    }]);
                }
                outcomes
            }
            // These are explicit cut points. A probe/transfer send cannot
            // feed the reducer without an authenticated packet. Retry is
            // armed behind the fixed timer by the runtime executor.
            RecoveryEffect::SendProbes { .. }
            | RecoveryEffect::Retry { .. }
            | RecoveryEffect::Cleanup { .. }
            | RecoveryEffect::ClearCompletedAttempt { .. }
            | RecoveryEffect::Metric(_) => vec![Vec::new()],
            RecoveryEffect::SendTransfer {
                attempt,
                donor,
                terminal_cut,
                kind,
            } => {
                let mut outcomes = vec![Vec::new()];
                // A generation-zero terminal transfer may be satisfied by an
                // exact local image before any request is put on the wire.
                if *kind == TransferKind::TerminalCheckpoint
                    && terminal_cut.generation() == 0
                    && coordinator.attempt() == Some(*attempt)
                    && coordinator.phase() == RecoveryPhase::FetchingTerminalCheckpoint
                    && coordinator.donor() == Some(donor)
                    && coordinator.representation_cut() == Some(terminal_cut)
                {
                    let target = coordinator
                        .certificate()
                        .expect("certified local-image candidate")
                        .target()
                        .clone();
                    outcomes.push(vec![RecoveryEvent::LocalImageVerified {
                        attempt: *attempt,
                        donor: donor.clone(),
                        verification: Verification::new(target, terminal_cut.clone()),
                    }]);
                }
                if coordinator.attempt() == Some(*attempt) {
                    outcomes.push(vec![RecoveryEvent::Cancel {
                        attempt: *attempt,
                        now_ms: 200,
                    }]);
                }
                outcomes
            }
            RecoveryEffect::PrepareInstall {
                attempt,
                donor,
                terminal_cut,
            } => {
                let mut outcomes = vec![Vec::new()];
                if coordinator.attempt() == Some(*attempt)
                    && coordinator.phase() == RecoveryPhase::FetchingRepositorySnapshot
                    && coordinator.donor() == Some(donor)
                    && coordinator.representation_cut() == Some(terminal_cut)
                {
                    // Local validation can fail before installation, or it
                    // can synchronously claim Prepared and Installing.
                    outcomes.extend([
                        vec![RecoveryEvent::DonorFailed {
                            attempt: *attempt,
                            donor: donor.clone(),
                            failure: DonorFailure::RetryableFailure,
                            now_ms: 200,
                        }],
                        vec![RecoveryEvent::DonorFailed {
                            attempt: *attempt,
                            donor: donor.clone(),
                            failure: DonorFailure::TargetMoved,
                            now_ms: 200,
                        }],
                        vec![
                            RecoveryEvent::Prepared {
                                attempt: *attempt,
                                donor: donor.clone(),
                            },
                            RecoveryEvent::InstallStarted {
                                attempt: *attempt,
                                donor: donor.clone(),
                            },
                        ],
                        vec![RecoveryEvent::Cancel {
                            attempt: *attempt,
                            now_ms: 200,
                        }],
                    ]);
                }
                outcomes
            }
            RecoveryEffect::Install { attempt, donor } => {
                let mut outcomes = vec![Vec::new()];
                if coordinator.attempt() == Some(*attempt)
                    && coordinator.phase() == RecoveryPhase::Installing
                    && coordinator.donor() == Some(donor)
                {
                    let certificate = coordinator
                        .certificate()
                        .expect("installing recovery certificate");
                    let verification = Verification::new(
                        certificate.target().clone(),
                        coordinator
                            .representation_cut()
                            .expect("installing representation")
                            .clone(),
                    );
                    outcomes.push(vec![
                        RecoveryEvent::Installed {
                            attempt: *attempt,
                            donor: donor.clone(),
                        },
                        RecoveryEvent::Verified {
                            attempt: *attempt,
                            donor: donor.clone(),
                            verification,
                        },
                    ]);
                    outcomes.push(vec![RecoveryEvent::Cancel {
                        attempt: *attempt,
                        now_ms: 200,
                    }]);
                }
                outcomes
            }
        }
    }

    fn explore_autonomous_closure(
        coordinator: StrictRecoveryCoordinator,
        pending: VecDeque<RecoveryEffect>,
        path: &mut BTreeSet<String>,
        depth: usize,
        stats: &mut ProofStats,
    ) {
        let signature = format!("{coordinator:?}|{pending:?}");
        assert!(
            path.insert(signature.clone()),
            "autonomous effect execution revisited a configuration"
        );
        stats.unique_configurations.insert(signature.clone());
        stats.phases.insert(format!("{:?}", coordinator.phase()));
        stats.effects.extend(pending.iter().map(effect_kind));
        stats.max_depth = stats.max_depth.max(depth);
        assert!(
            depth <= 16,
            "autonomous effect closure exceeded its proof bound"
        );

        let Some(effect) = pending.front() else {
            stats.terminal_configurations += 1;
            path.remove(&signature);
            return;
        };
        let mut remainder = pending.clone();
        remainder.pop_front();
        for events in autonomous_outcomes(&coordinator, effect) {
            stats.edges += 1;
            let mut next = coordinator.clone();
            let mut next_pending = remainder.clone();
            for event in events {
                let before = next.phase();
                next_pending.extend(next.transition(event));
                let after = next.phase();
                stats.phases.insert(format!("{after:?}"));
                if before != after {
                    let before_rank = phase_rank(before);
                    let after_rank = phase_rank(after);
                    assert!(
                        after_rank < before_rank,
                        "autonomous phase edge did not decrease rank: {before:?} -> {after:?}"
                    );
                    stats.phase_edges.insert((before_rank, after_rank));
                }
            }
            explore_autonomous_closure(next, next_pending, path, depth + 1, stats);
        }
        path.remove(&signature);
    }

    #[test]
    fn effect_executor_feedback_closure_is_acyclic_without_clock_or_network_events() {
        let mut started = StrictRecoveryCoordinator::default();
        let start_effects = started.transition(RecoveryEvent::Trigger {
            trigger: RecoveryTrigger::Explicit,
            attempt: ATTEMPT,
            total_known_participants: 2,
            now_ms: 100,
        });
        let zero_cut = TerminalCut::new([1; 16], 0, [2; 32], [3; 32]);
        let (local, local_effects) = certified_with_cut(zero_cut);

        let transfer_cut = TerminalCut::new([4; 16], 9, [5; 32], [6; 32]);
        let (mut transfer, _) = certified_with_cut(transfer_cut);
        let donor = transfer.donor().expect("certified donor").clone();
        transfer.transition(RecoveryEvent::TransferProgress {
            attempt: ATTEMPT,
            donor: donor.clone(),
            kind: TransferKind::TerminalCheckpoint,
            authenticated: true,
            complete: true,
            now_ms: 110,
        });
        let prepare_effects = transfer.transition(RecoveryEvent::TransferProgress {
            attempt: ATTEMPT,
            donor,
            kind: TransferKind::RepositorySnapshot,
            authenticated: true,
            complete: true,
            now_ms: 111,
        });
        assert!(matches!(
            prepare_effects.as_slice(),
            [RecoveryEffect::PrepareInstall { .. }]
        ));

        let mut stats = ProofStats::default();
        explore_autonomous_closure(
            started,
            start_effects.into(),
            &mut BTreeSet::new(),
            0,
            &mut stats,
        );
        explore_autonomous_closure(
            local,
            local_effects.into(),
            &mut BTreeSet::new(),
            0,
            &mut stats,
        );
        explore_autonomous_closure(
            transfer,
            prepare_effects.into(),
            &mut BTreeSet::new(),
            0,
            &mut stats,
        );

        eprintln!(
            "autonomous proof: unique={} edges={} terminals={} phase_edges={} max_depth={} phases={:?} effects={:?}",
            stats.unique_configurations.len(),
            stats.edges,
            stats.terminal_configurations,
            stats.phase_edges.len(),
            stats.max_depth,
            stats.phases,
            stats.effects,
        );
        assert_eq!(
            stats.phases,
            [
                "Backoff",
                "Certifying",
                "FetchingRepositorySnapshot",
                "FetchingTerminalCheckpoint",
                "Healthy",
                "Installing",
                "Prepared",
                "Verifying",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        assert_eq!(
            stats.effects,
            [
                "Cleanup",
                "ClearCompletedAttempt",
                "Install",
                "Metric",
                "Persist",
                "PrepareInstall",
                "Retry",
                "SendProbes",
                "SendTransfer",
            ]
            .into_iter()
            .collect()
        );
        assert!(stats.max_depth <= 16);
    }
}

#[cfg(test)]
mod extensive_matrix_tests {
    use super::*;

    const ATTEMPT: RecoveryAttemptId = RecoveryAttemptId::new(0xAA, 0x55);
    const STALE_ATTEMPT: RecoveryAttemptId = RecoveryAttemptId::new(0xAA, 0x56);

    fn target() -> LogicalTarget {
        LogicalTarget::new(77, 900, [0xA5; 32])
    }

    fn cut(node: u8) -> TerminalCut {
        TerminalCut::new(
            [node; 16],
            u64::from(node),
            [node.wrapping_add(1); 32],
            *target().terminal_set_digest(),
        )
    }

    fn peer(node: u64, epoch: u64) -> ParticipantIncarnation {
        ParticipantIncarnation::new(node, epoch)
    }

    fn attestation(node: u64, epoch: u64, rank: u64) -> RecoveryAttestation {
        RecoveryAttestation::new(peer(node, epoch), target(), cut(node as u8), rank)
    }

    fn started(participants: usize, now_ms: u64) -> StrictRecoveryCoordinator {
        let mut coordinator = StrictRecoveryCoordinator::default();
        assert_eq!(
            coordinator.transition(RecoveryEvent::Trigger {
                trigger: RecoveryTrigger::Explicit,
                attempt: ATTEMPT,
                total_known_participants: participants,
                now_ms,
            }),
            vec![
                RecoveryEffect::Persist,
                RecoveryEffect::SendProbes { attempt: ATTEMPT },
                RecoveryEffect::Metric(RecoveryMetric::AttemptStarted),
            ]
        );
        coordinator
    }

    fn certified() -> StrictRecoveryCoordinator {
        let mut coordinator = started(3, 100);
        assert!(
            coordinator
                .transition(RecoveryEvent::ProbeResponse {
                    attempt: ATTEMPT,
                    attestation: attestation(20, 1, 10),
                    authenticated: true,
                    now_ms: 101,
                })
                .is_empty()
        );
        assert_eq!(
            coordinator.transition(RecoveryEvent::ProbeResponse {
                attempt: ATTEMPT,
                attestation: attestation(10, 1, 20),
                authenticated: true,
                now_ms: 102,
            }),
            vec![
                RecoveryEffect::Persist,
                RecoveryEffect::SendTransfer {
                    attempt: ATTEMPT,
                    donor: peer(10, 1),
                    terminal_cut: cut(10),
                    kind: TransferKind::TerminalCheckpoint,
                },
            ]
        );
        coordinator
    }

    fn fetching_snapshot() -> StrictRecoveryCoordinator {
        let mut coordinator = certified();
        assert_eq!(
            coordinator.transition(RecoveryEvent::TransferProgress {
                attempt: ATTEMPT,
                donor: peer(10, 1),
                kind: TransferKind::TerminalCheckpoint,
                authenticated: true,
                complete: true,
                now_ms: 103,
            }),
            vec![
                RecoveryEffect::Persist,
                RecoveryEffect::SendTransfer {
                    attempt: ATTEMPT,
                    donor: peer(10, 1),
                    terminal_cut: cut(10),
                    kind: TransferKind::RepositorySnapshot,
                },
            ]
        );
        coordinator
    }

    fn coordinator_at_phase(phase: RecoveryPhase) -> StrictRecoveryCoordinator {
        match phase {
            RecoveryPhase::Healthy => StrictRecoveryCoordinator::default(),
            RecoveryPhase::Certifying => started(3, 100),
            RecoveryPhase::FetchingTerminalCheckpoint => certified(),
            RecoveryPhase::FetchingRepositorySnapshot => fetching_snapshot(),
            RecoveryPhase::Prepared => {
                let mut coordinator = fetching_snapshot();
                coordinator.transition(RecoveryEvent::TransferProgress {
                    attempt: ATTEMPT,
                    donor: peer(10, 1),
                    kind: TransferKind::RepositorySnapshot,
                    authenticated: true,
                    complete: true,
                    now_ms: 104,
                });
                coordinator.transition(RecoveryEvent::Prepared {
                    attempt: ATTEMPT,
                    donor: peer(10, 1),
                });
                coordinator
            }
            RecoveryPhase::Installing => {
                let mut coordinator = coordinator_at_phase(RecoveryPhase::Prepared);
                coordinator.transition(RecoveryEvent::InstallStarted {
                    attempt: ATTEMPT,
                    donor: peer(10, 1),
                });
                coordinator
            }
            RecoveryPhase::Verifying => {
                let mut coordinator = coordinator_at_phase(RecoveryPhase::Installing);
                coordinator.transition(RecoveryEvent::Installed {
                    attempt: ATTEMPT,
                    donor: peer(10, 1),
                });
                coordinator
            }
            RecoveryPhase::Backoff => {
                let mut coordinator = started(3, 100);
                coordinator.transition(RecoveryEvent::Deadline {
                    attempt: ATTEMPT,
                    now_ms: 100 + PROGRESS_DEADLINE_MS,
                });
                coordinator
            }
        }
    }

    #[test]
    fn every_trigger_coalesces_without_mutating_every_reachable_active_phase() {
        let triggers = [
            RecoveryTrigger::TerminalFence,
            RecoveryTrigger::Admission,
            RecoveryTrigger::ClockTick,
            RecoveryTrigger::MembershipChanged,
            RecoveryTrigger::GenerationZeroAudit,
            RecoveryTrigger::Explicit,
        ];
        let active_phases = [
            RecoveryPhase::Certifying,
            RecoveryPhase::FetchingTerminalCheckpoint,
            RecoveryPhase::FetchingRepositorySnapshot,
            RecoveryPhase::Prepared,
            RecoveryPhase::Installing,
            RecoveryPhase::Verifying,
            RecoveryPhase::Backoff,
        ];

        for phase in active_phases {
            for trigger in triggers {
                let mut coordinator = coordinator_at_phase(phase);
                let before = coordinator.clone();
                assert_eq!(
                    coordinator.transition(RecoveryEvent::Trigger {
                        trigger,
                        attempt: STALE_ATTEMPT,
                        total_known_participants: usize::MAX,
                        now_ms: u64::MAX,
                    }),
                    vec![RecoveryEffect::Metric(RecoveryMetric::TriggerCoalesced)],
                    "phase {phase:?}, trigger {trigger:?}"
                );
                assert_eq!(coordinator, before, "phase {phase:?}, trigger {trigger:?}");
            }
        }
    }

    #[test]
    fn every_wrong_donor_event_is_side_effect_free_in_every_active_phase() {
        let active_phases = [
            RecoveryPhase::Certifying,
            RecoveryPhase::FetchingTerminalCheckpoint,
            RecoveryPhase::FetchingRepositorySnapshot,
            RecoveryPhase::Prepared,
            RecoveryPhase::Installing,
            RecoveryPhase::Verifying,
            RecoveryPhase::Backoff,
        ];

        for phase in active_phases {
            let base = coordinator_at_phase(phase);
            let expected_donor = base.donor().cloned().unwrap_or_else(|| peer(10, 1));
            let wrong_donors = [
                peer(expected_donor.node_id(), expected_donor.boot_epoch() + 1),
                peer(
                    expected_donor.node_id() + 1_000,
                    expected_donor.boot_epoch(),
                ),
            ];

            for wrong_donor in wrong_donors {
                let verification = Verification::new(target(), cut(10));
                let events = [
                    RecoveryEvent::TransferProgress {
                        attempt: ATTEMPT,
                        donor: wrong_donor.clone(),
                        kind: TransferKind::TerminalCheckpoint,
                        authenticated: true,
                        complete: true,
                        now_ms: 200,
                    },
                    RecoveryEvent::DonorFailed {
                        attempt: ATTEMPT,
                        donor: wrong_donor.clone(),
                        failure: DonorFailure::TargetMoved,
                        now_ms: 200,
                    },
                    RecoveryEvent::Prepared {
                        attempt: ATTEMPT,
                        donor: wrong_donor.clone(),
                    },
                    RecoveryEvent::InstallStarted {
                        attempt: ATTEMPT,
                        donor: wrong_donor.clone(),
                    },
                    RecoveryEvent::Installed {
                        attempt: ATTEMPT,
                        donor: wrong_donor.clone(),
                    },
                    RecoveryEvent::Verified {
                        attempt: ATTEMPT,
                        donor: wrong_donor.clone(),
                        verification: verification.clone(),
                    },
                    RecoveryEvent::LocalImageVerified {
                        attempt: ATTEMPT,
                        donor: wrong_donor.clone(),
                        verification: verification.clone(),
                    },
                ];

                for event in events {
                    let mut coordinator = base.clone();
                    assert_eq!(
                        coordinator.transition(event.clone()),
                        vec![RecoveryEffect::Metric(RecoveryMetric::StaleEvent)],
                        "phase {phase:?}, donor {wrong_donor:?}, event {event:?}"
                    );
                    assert_eq!(
                        coordinator, base,
                        "phase {phase:?}, donor {wrong_donor:?}, event {event:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn nominal_full_path_emits_exact_effects() {
        let mut coordinator = fetching_snapshot();

        assert_eq!(
            coordinator.transition(RecoveryEvent::TransferProgress {
                attempt: ATTEMPT,
                donor: peer(10, 1),
                kind: TransferKind::RepositorySnapshot,
                authenticated: true,
                complete: true,
                now_ms: 104,
            }),
            vec![RecoveryEffect::PrepareInstall {
                attempt: ATTEMPT,
                donor: peer(10, 1),
                terminal_cut: cut(10),
            }]
        );
        assert_eq!(
            coordinator.transition(RecoveryEvent::Prepared {
                attempt: ATTEMPT,
                donor: peer(10, 1),
            }),
            vec![RecoveryEffect::Persist]
        );
        assert_eq!(coordinator.phase(), RecoveryPhase::Prepared);
        assert_eq!(
            coordinator.transition(RecoveryEvent::InstallStarted {
                attempt: ATTEMPT,
                donor: peer(10, 1),
            }),
            vec![
                RecoveryEffect::Persist,
                RecoveryEffect::Install {
                    attempt: ATTEMPT,
                    donor: peer(10, 1),
                },
            ]
        );
        assert_eq!(coordinator.phase(), RecoveryPhase::Installing);
        assert_eq!(
            coordinator.transition(RecoveryEvent::Installed {
                attempt: ATTEMPT,
                donor: peer(10, 1),
            }),
            vec![RecoveryEffect::Persist]
        );
        assert_eq!(coordinator.phase(), RecoveryPhase::Verifying);
        assert_eq!(
            coordinator.transition(RecoveryEvent::Verified {
                attempt: ATTEMPT,
                donor: peer(10, 1),
                verification: Verification::new(target(), cut(10)),
            }),
            vec![
                RecoveryEffect::Persist,
                RecoveryEffect::Cleanup { attempt: ATTEMPT },
                RecoveryEffect::Metric(RecoveryMetric::Completed),
            ]
        );
        assert_eq!(coordinator.phase(), RecoveryPhase::Healthy);
        assert_eq!(coordinator.attempt(), None);
    }

    #[test]
    fn every_stale_attempt_event_is_side_effect_free() {
        let base = certified();
        let verification = Verification::new(target(), cut(10));
        let events = [
            RecoveryEvent::ProbeResponse {
                attempt: STALE_ATTEMPT,
                attestation: attestation(10, 1, 20),
                authenticated: true,
                now_ms: 200,
            },
            RecoveryEvent::TransferProgress {
                attempt: STALE_ATTEMPT,
                donor: peer(10, 1),
                kind: TransferKind::TerminalCheckpoint,
                authenticated: true,
                complete: true,
                now_ms: 200,
            },
            RecoveryEvent::Deadline {
                attempt: STALE_ATTEMPT,
                now_ms: u64::MAX,
            },
            RecoveryEvent::DonorFailed {
                attempt: STALE_ATTEMPT,
                donor: peer(10, 1),
                failure: DonorFailure::TargetMoved,
                now_ms: 200,
            },
            RecoveryEvent::Prepared {
                attempt: STALE_ATTEMPT,
                donor: peer(10, 1),
            },
            RecoveryEvent::InstallStarted {
                attempt: STALE_ATTEMPT,
                donor: peer(10, 1),
            },
            RecoveryEvent::Installed {
                attempt: STALE_ATTEMPT,
                donor: peer(10, 1),
            },
            RecoveryEvent::Verified {
                attempt: STALE_ATTEMPT,
                donor: peer(10, 1),
                verification: verification.clone(),
            },
            RecoveryEvent::LocalImageVerified {
                attempt: STALE_ATTEMPT,
                donor: peer(10, 1),
                verification,
            },
            RecoveryEvent::AuditYield {
                attempt: STALE_ATTEMPT,
            },
            RecoveryEvent::Cancel {
                attempt: STALE_ATTEMPT,
                now_ms: 1_000,
            },
            RecoveryEvent::RetryElapsed {
                attempt: STALE_ATTEMPT,
                now_ms: 200,
            },
        ];

        for event in events {
            let mut coordinator = base.clone();
            assert_eq!(
                coordinator.transition(event.clone()),
                vec![RecoveryEffect::Metric(RecoveryMetric::StaleEvent)],
                "event {event:?}"
            );
            assert_eq!(coordinator, base, "event {event:?}");
        }

        let mut coordinator = base.clone();
        assert_eq!(
            coordinator.transition(RecoveryEvent::Trigger {
                trigger: RecoveryTrigger::MembershipChanged,
                attempt: STALE_ATTEMPT,
                total_known_participants: 99,
                now_ms: 200,
            }),
            vec![RecoveryEffect::Metric(RecoveryMetric::TriggerCoalesced)]
        );
        assert_eq!(coordinator, base);
    }

    #[test]
    fn donor_failure_matrix_is_exact_in_both_transfer_phases() {
        let switching = [
            DonorFailure::IncarnationLost,
            DonorFailure::SustainedRouteLoss,
            DonorFailure::NoProgressDeadline,
        ];
        let retransmitting = [DonorFailure::RetryableFailure, DonorFailure::ResourceLimit];

        for phase in [
            RecoveryPhase::FetchingTerminalCheckpoint,
            RecoveryPhase::FetchingRepositorySnapshot,
        ] {
            for failure in switching {
                let mut coordinator = coordinator_at_phase(phase);
                assert_eq!(
                    coordinator.transition(RecoveryEvent::DonorFailed {
                        attempt: ATTEMPT,
                        donor: peer(10, 1),
                        failure,
                        now_ms: 500,
                    }),
                    vec![
                        RecoveryEffect::Persist,
                        RecoveryEffect::SendTransfer {
                            attempt: ATTEMPT,
                            donor: peer(20, 1),
                            terminal_cut: cut(20),
                            kind: TransferKind::TerminalCheckpoint,
                        },
                        RecoveryEffect::Metric(RecoveryMetric::DonorSwitched),
                    ],
                    "phase {phase:?}, failure {failure:?}"
                );
                assert_eq!(
                    coordinator.phase(),
                    RecoveryPhase::FetchingTerminalCheckpoint
                );
                assert_eq!(coordinator.donor(), Some(&peer(20, 1)));
                assert_eq!(coordinator.representation_cut(), Some(&cut(20)));
            }

            for failure in retransmitting {
                let mut coordinator = coordinator_at_phase(phase);
                let before_donor = coordinator.donor().cloned();
                let before_cut = coordinator.representation_cut().cloned();
                assert_eq!(
                    coordinator.transition(RecoveryEvent::DonorFailed {
                        attempt: ATTEMPT,
                        donor: peer(10, 1),
                        failure,
                        now_ms: 500,
                    }),
                    vec![
                        RecoveryEffect::Persist,
                        RecoveryEffect::Retry { attempt: ATTEMPT },
                        RecoveryEffect::Metric(RecoveryMetric::Retransmit),
                    ],
                    "phase {phase:?}, failure {failure:?}"
                );
                assert_eq!(coordinator.phase(), phase);
                assert_eq!(coordinator.donor().cloned(), before_donor);
                assert_eq!(coordinator.representation_cut().cloned(), before_cut);
            }

            let mut coordinator = coordinator_at_phase(phase);
            assert_eq!(
                coordinator.transition(RecoveryEvent::DonorFailed {
                    attempt: ATTEMPT,
                    donor: peer(10, 1),
                    failure: DonorFailure::TargetMoved,
                    now_ms: 500,
                }),
                vec![
                    RecoveryEffect::Persist,
                    RecoveryEffect::Retry { attempt: ATTEMPT },
                ]
            );
            assert_eq!(coordinator.phase(), RecoveryPhase::Backoff);
        }
    }

    #[test]
    fn exhausting_last_certified_donor_enters_backoff_from_both_transfer_phases() {
        let mut terminal = certified();
        terminal.transition(RecoveryEvent::DonorFailed {
            attempt: ATTEMPT,
            donor: peer(10, 1),
            failure: DonorFailure::SustainedRouteLoss,
            now_ms: 500,
        });
        assert_eq!(
            terminal.transition(RecoveryEvent::DonorFailed {
                attempt: ATTEMPT,
                donor: peer(20, 1),
                failure: DonorFailure::IncarnationLost,
                now_ms: 501,
            }),
            vec![
                RecoveryEffect::Persist,
                RecoveryEffect::Retry { attempt: ATTEMPT },
            ]
        );
        assert_eq!(terminal.phase(), RecoveryPhase::Backoff);

        let mut snapshot = certified();
        snapshot.transition(RecoveryEvent::DonorFailed {
            attempt: ATTEMPT,
            donor: peer(10, 1),
            failure: DonorFailure::SustainedRouteLoss,
            now_ms: 500,
        });
        snapshot.transition(RecoveryEvent::TransferProgress {
            attempt: ATTEMPT,
            donor: peer(20, 1),
            kind: TransferKind::TerminalCheckpoint,
            authenticated: true,
            complete: true,
            now_ms: 501,
        });
        assert_eq!(snapshot.phase(), RecoveryPhase::FetchingRepositorySnapshot);
        assert_eq!(
            snapshot.transition(RecoveryEvent::DonorFailed {
                attempt: ATTEMPT,
                donor: peer(20, 1),
                failure: DonorFailure::NoProgressDeadline,
                now_ms: 502,
            }),
            vec![
                RecoveryEffect::Persist,
                RecoveryEffect::Retry { attempt: ATTEMPT },
            ]
        );
        assert_eq!(snapshot.phase(), RecoveryPhase::Backoff);
    }

    #[test]
    fn equal_rank_tie_break_and_fast_quorum_boundaries_are_deterministic() {
        let expected = [
            (0, 0),
            (1, 1),
            (2, 2),
            (3, 3),
            (4, 3),
            (5, 4),
            (6, 5),
            (7, 6),
            (8, 6),
            (9, 7),
        ];
        for (denominator, quorum) in expected {
            assert_eq!(fast_quorum_size(denominator), quorum, "{denominator}");
        }

        let mut coordinator = started(4, 100);
        for (index, node) in [30, 20, 10].into_iter().enumerate() {
            let effects = coordinator.transition(RecoveryEvent::ProbeResponse {
                attempt: ATTEMPT,
                attestation: attestation(node, 1, 50),
                authenticated: true,
                now_ms: 101 + index as u64,
            });
            if index < 2 {
                assert!(effects.is_empty());
                assert_eq!(coordinator.phase(), RecoveryPhase::Certifying);
            }
        }
        assert_eq!(coordinator.frozen_denominator(), 3);
        assert_eq!(coordinator.donor(), Some(&peer(10, 1)));
        assert_eq!(
            coordinator
                .certificate()
                .unwrap()
                .witnesses()
                .iter()
                .map(|witness| witness.witness().node_id())
                .collect::<Vec<_>>(),
            vec![10, 20, 30]
        );
    }

    #[test]
    fn verification_rejects_each_logical_target_field_independently() {
        let exact = target();
        let mut mutations = Vec::new();

        let mut repository_version = exact.clone();
        repository_version.repository_version += 1;
        mutations.push(repository_version);
        let mut history_freshness = exact.clone();
        history_freshness.history_freshness += 1;
        mutations.push(history_freshness);
        let mut terminal_set_digest = exact;
        terminal_set_digest.terminal_set_digest[0] ^= 1;
        mutations.push(terminal_set_digest);

        for mutation in mutations {
            let mut coordinator = coordinator_at_phase(RecoveryPhase::Verifying);
            assert!(
                coordinator
                    .transition(RecoveryEvent::Verified {
                        attempt: ATTEMPT,
                        donor: peer(10, 1),
                        verification: Verification::new(mutation, cut(10)),
                    })
                    .is_empty()
            );
            assert_eq!(coordinator.phase(), RecoveryPhase::Verifying);
            assert_eq!(coordinator.attempt(), Some(ATTEMPT));
        }
    }

    #[test]
    fn verification_rejects_each_terminal_cut_field_independently() {
        let exact = cut(10);
        let mut mutations = Vec::new();

        let mut journal_id = exact.clone();
        journal_id.journal_id[0] ^= 1;
        mutations.push(journal_id);
        let mut generation = exact.clone();
        generation.generation += 1;
        mutations.push(generation);
        let mut chain_digest = exact.clone();
        chain_digest.chain_digest[0] ^= 1;
        mutations.push(chain_digest);
        let mut terminal_set_digest = exact;
        terminal_set_digest.terminal_set_digest[0] ^= 1;
        mutations.push(terminal_set_digest);

        for mutation in mutations {
            let mut coordinator = coordinator_at_phase(RecoveryPhase::Verifying);
            assert!(
                coordinator
                    .transition(RecoveryEvent::Verified {
                        attempt: ATTEMPT,
                        donor: peer(10, 1),
                        verification: Verification::new(target(), mutation),
                    })
                    .is_empty()
            );
            assert_eq!(coordinator.phase(), RecoveryPhase::Verifying);
            assert_eq!(coordinator.attempt(), Some(ATTEMPT));
        }
    }

    #[test]
    fn cancellation_is_single_and_exact_in_every_reachable_active_phase() {
        for phase in [
            RecoveryPhase::Certifying,
            RecoveryPhase::FetchingTerminalCheckpoint,
            RecoveryPhase::FetchingRepositorySnapshot,
            RecoveryPhase::Prepared,
            RecoveryPhase::Installing,
            RecoveryPhase::Verifying,
            RecoveryPhase::Backoff,
        ] {
            let mut coordinator = coordinator_at_phase(phase);
            assert_eq!(coordinator.phase(), phase);
            assert_eq!(
                coordinator.transition(RecoveryEvent::Cancel {
                    attempt: ATTEMPT,
                    now_ms: 1_000,
                }),
                vec![
                    RecoveryEffect::Persist,
                    RecoveryEffect::Cleanup { attempt: ATTEMPT },
                    RecoveryEffect::Retry { attempt: ATTEMPT },
                    RecoveryEffect::Metric(RecoveryMetric::Cancelled),
                ],
                "phase {phase:?}"
            );
            assert_eq!(coordinator.phase(), RecoveryPhase::Backoff);
            assert!(
                coordinator
                    .transition(RecoveryEvent::Cancel {
                        attempt: ATTEMPT,
                        now_ms: 1_001,
                    })
                    .is_empty(),
                "phase {phase:?}"
            );
        }
    }

    #[test]
    fn deadline_event_matrix_is_exact_in_every_phase() {
        let mut certifying = coordinator_at_phase(RecoveryPhase::Certifying);
        let deadline = certifying.progress_deadline_ms().unwrap();
        let before_early = certifying.clone();
        assert!(
            certifying
                .transition(RecoveryEvent::Deadline {
                    attempt: ATTEMPT,
                    now_ms: deadline - 1,
                })
                .is_empty()
        );
        assert_eq!(certifying, before_early);
        assert_eq!(
            certifying.transition(RecoveryEvent::Deadline {
                attempt: ATTEMPT,
                now_ms: deadline,
            }),
            vec![
                RecoveryEffect::Persist,
                RecoveryEffect::Retry { attempt: ATTEMPT },
                RecoveryEffect::Metric(RecoveryMetric::CertificateFailure),
            ]
        );
        assert_eq!(certifying.phase(), RecoveryPhase::Backoff);

        for phase in [
            RecoveryPhase::FetchingTerminalCheckpoint,
            RecoveryPhase::FetchingRepositorySnapshot,
        ] {
            let mut coordinator = coordinator_at_phase(phase);
            let deadline = coordinator.progress_deadline_ms().unwrap();
            let before_early = coordinator.clone();
            assert!(
                coordinator
                    .transition(RecoveryEvent::Deadline {
                        attempt: ATTEMPT,
                        now_ms: deadline - 1,
                    })
                    .is_empty(),
                "phase {phase:?}"
            );
            assert_eq!(coordinator, before_early, "phase {phase:?}");
            assert_eq!(
                coordinator.transition(RecoveryEvent::Deadline {
                    attempt: ATTEMPT,
                    now_ms: deadline,
                }),
                vec![
                    RecoveryEffect::Persist,
                    RecoveryEffect::SendTransfer {
                        attempt: ATTEMPT,
                        donor: peer(20, 1),
                        terminal_cut: cut(20),
                        kind: TransferKind::TerminalCheckpoint,
                    },
                    RecoveryEffect::Metric(RecoveryMetric::DonorSwitched),
                ],
                "phase {phase:?}"
            );
            assert_eq!(
                coordinator.phase(),
                RecoveryPhase::FetchingTerminalCheckpoint,
                "phase {phase:?}"
            );
        }

        for phase in [
            RecoveryPhase::Prepared,
            RecoveryPhase::Installing,
            RecoveryPhase::Verifying,
            RecoveryPhase::Backoff,
        ] {
            let mut coordinator = coordinator_at_phase(phase);
            let before = coordinator.clone();
            assert!(
                coordinator
                    .transition(RecoveryEvent::Deadline {
                        attempt: ATTEMPT,
                        now_ms: u64::MAX,
                    })
                    .is_empty(),
                "phase {phase:?}"
            );
            assert_eq!(coordinator, before, "phase {phase:?}");
        }

        let mut healthy = coordinator_at_phase(RecoveryPhase::Healthy);
        let before = healthy.clone();
        assert_eq!(
            healthy.transition(RecoveryEvent::Deadline {
                attempt: ATTEMPT,
                now_ms: u64::MAX,
            }),
            vec![RecoveryEffect::Metric(RecoveryMetric::StaleEvent)]
        );
        assert_eq!(healthy, before);
    }

    #[test]
    fn every_deadline_addition_saturates_at_u64_max_without_wrapping() {
        let mut coordinator = started(3, u64::MAX - 1);
        assert_eq!(coordinator.progress_deadline_ms(), Some(u64::MAX));

        coordinator.transition(RecoveryEvent::ProbeResponse {
            attempt: ATTEMPT,
            attestation: attestation(20, 1, 10),
            authenticated: true,
            now_ms: u64::MAX,
        });
        assert_eq!(coordinator.progress_deadline_ms(), Some(u64::MAX));
        coordinator.transition(RecoveryEvent::ProbeResponse {
            attempt: ATTEMPT,
            attestation: attestation(10, 1, 20),
            authenticated: true,
            now_ms: u64::MAX,
        });
        assert_eq!(coordinator.progress_deadline_ms(), Some(u64::MAX));

        coordinator.transition(RecoveryEvent::TransferProgress {
            attempt: ATTEMPT,
            donor: peer(10, 1),
            kind: TransferKind::TerminalCheckpoint,
            authenticated: true,
            complete: false,
            now_ms: u64::MAX,
        });
        assert_eq!(coordinator.progress_deadline_ms(), Some(u64::MAX));
        assert_eq!(
            coordinator.transition(RecoveryEvent::Deadline {
                attempt: ATTEMPT,
                now_ms: u64::MAX,
            }),
            vec![
                RecoveryEffect::Persist,
                RecoveryEffect::SendTransfer {
                    attempt: ATTEMPT,
                    donor: peer(20, 1),
                    terminal_cut: cut(20),
                    kind: TransferKind::TerminalCheckpoint,
                },
                RecoveryEffect::Metric(RecoveryMetric::DonorSwitched),
            ]
        );
        assert_eq!(coordinator.progress_deadline_ms(), Some(u64::MAX));

        coordinator.transition(RecoveryEvent::DonorFailed {
            attempt: ATTEMPT,
            donor: peer(20, 1),
            failure: DonorFailure::TargetMoved,
            now_ms: u64::MAX,
        });
        coordinator.transition(RecoveryEvent::RetryElapsed {
            attempt: ATTEMPT,
            now_ms: u64::MAX,
        });
        assert_eq!(coordinator.progress_deadline_ms(), Some(u64::MAX));
    }

    #[test]
    fn network_retry_cycle_has_positive_time_variant_and_finite_donor_descent() {
        let mut coordinator = certified();
        let first_donor = coordinator.donor().cloned().expect("first donor");
        let first_deadline = coordinator
            .progress_deadline_ms()
            .expect("first donor deadline");

        // Even an optimal localhost responder cannot turn retry statuses into
        // authenticated progress. Each response asks the runtime for one
        // coalesced, timer-gated same-wire retry and leaves the phase deadline
        // unchanged. The runtime scheduler test proves the send-side gate.
        let retry_slots = PROGRESS_DEADLINE_MS / RECOVERY_RETRY_DELAY_MS;
        for slot in 0..retry_slots {
            let effects = coordinator.transition(RecoveryEvent::DonorFailed {
                attempt: ATTEMPT,
                donor: first_donor.clone(),
                failure: DonorFailure::RetryableFailure,
                now_ms: 104 + slot * RECOVERY_RETRY_DELAY_MS,
            });
            assert!(
                effects
                    .iter()
                    .any(|effect| matches!(effect, RecoveryEffect::Retry { attempt: ATTEMPT }))
            );
            assert_eq!(coordinator.progress_deadline_ms(), Some(first_deadline));
        }
        assert_eq!(
            1 + retry_slots,
            61,
            "one initial request plus at most one retry per 500ms slot"
        );

        let effects = coordinator.transition(RecoveryEvent::Deadline {
            attempt: ATTEMPT,
            now_ms: first_deadline,
        });
        assert_eq!(coordinator.donor_index(), 1);
        assert!(effects.iter().any(|effect| matches!(
            effect,
            RecoveryEffect::Metric(RecoveryMetric::DonorSwitched)
        )));

        let second_deadline = coordinator
            .progress_deadline_ms()
            .expect("replacement donor deadline");
        let effects = coordinator.transition(RecoveryEvent::Deadline {
            attempt: ATTEMPT,
            now_ms: second_deadline,
        });
        assert_eq!(coordinator.phase(), RecoveryPhase::Backoff);
        assert!(
            effects
                .iter()
                .any(|effect| matches!(effect, RecoveryEffect::Retry { attempt: ATTEMPT }))
        );
        let retry_not_before = coordinator
            .progress_deadline_ms()
            .expect("backoff not-before");
        assert_eq!(retry_not_before, second_deadline + RECOVERY_RETRY_DELAY_MS);
        assert!(
            coordinator
                .transition(RecoveryEvent::RetryElapsed {
                    attempt: ATTEMPT,
                    now_ms: retry_not_before - 1,
                })
                .is_empty()
        );
        assert_eq!(coordinator.phase(), RecoveryPhase::Backoff);
        assert!(
            coordinator
                .transition(RecoveryEvent::RetryElapsed {
                    attempt: ATTEMPT,
                    now_ms: retry_not_before,
                })
                .iter()
                .any(|effect| matches!(effect, RecoveryEffect::SendProbes { attempt: ATTEMPT }))
        );
        assert_eq!(coordinator.phase(), RecoveryPhase::Certifying);
    }

    #[test]
    fn target_moved_round_trip_cannot_collapse_backoff() {
        let mut coordinator = certified();
        let donor = coordinator.donor().cloned().expect("certified donor");
        let moved_at = 700;
        coordinator.transition(RecoveryEvent::DonorFailed {
            attempt: ATTEMPT,
            donor,
            failure: DonorFailure::TargetMoved,
            now_ms: moved_at,
        });
        let retry_not_before = moved_at + RECOVERY_RETRY_DELAY_MS;
        assert_eq!(coordinator.phase(), RecoveryPhase::Backoff);
        assert_eq!(coordinator.progress_deadline_ms(), Some(retry_not_before));
        assert!(
            coordinator
                .transition(RecoveryEvent::RetryElapsed {
                    attempt: ATTEMPT,
                    now_ms: moved_at,
                })
                .is_empty()
        );
        assert_eq!(coordinator.phase(), RecoveryPhase::Backoff);
    }
}
