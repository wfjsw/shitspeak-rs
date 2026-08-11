//! Protocol-v8 executor for foreign-lineage recovery.
//!
//! This module owns ephemeral wire identities and transfer assembly. It never
//! selects a donor or changes phases directly; all lifecycle changes are fed
//! back through the pure recovery reducer.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use aws_lc_rs::digest::{SHA256, digest};
use bytes::Bytes;
use parking_lot::Mutex;

use super::super::proto::{
    StrictBody, StrictRecoveryContext, StrictRecoveryProbeReq, StrictRecoveryProbeResp,
    StrictRecoverySnapshotAck, StrictRecoverySnapshotPage, StrictRecoverySnapshotReq,
    StrictRecoveryStatus, StrictRecoveryTarget, StrictRecoveryTerminalAck,
    StrictRecoveryTerminalPage, StrictRecoveryTerminalReq, StrictTerminalState,
};
use super::catchup::{
    decode_s2s_snapshot_envelope, delivery_checkpoint_is_valid, encode_bound_s2s_snapshot_envelope,
    staged_terminal_decision,
};
use super::recovery_reducer::{
    DonorFailure, LogicalTarget, ParticipantIncarnation, RECOVERY_RETRY_DELAY_MS,
    RecoveryAttemptId, RecoveryAttestation, RecoveryEffect, RecoveryEvent, RecoveryFailure,
    RecoveryPhase, RecoveryRestore, StrictRecoveryCoordinator, TerminalCut as ReducerCut,
    TransferKind, Verification,
};
use super::recovery_staging::{
    RecoveryStagingExpectation, RecoveryStagingManifest, delete_recovery_staging_artifact,
    verify_recovery_staging_artifact, write_recovery_staging_artifact,
};
use super::runtime::{BulkPageIdentity, OpId};
use super::runtime::{StrictRuntime, node_from_u32};
use super::sync_v3::{cut_from_wire, cut_to_wire};
use super::terminal_journal::TerminalCut;
use super::terminal_journal::TerminalJournal;
use super::terminal_journal_sqlite::{
    DurableRecoveryArtifactIntent, DurableRecoveryAttempt, DurableRecoveryFailure,
    DurableRecoveryParticipant, DurableRecoveryPhase, DurableRecoveryRepositoryMetadata,
    DurableRecoveryTarget, DurableRecoveryWitness,
};
use super::{HistoryMetadata, StrictReplicable};
use crate::replications::ReplicationError;
use shitspeak_core::NodeIdentifier;

const PAGE_OVERHEAD_RESERVE: usize = 2048;
// The requester switches donors after 30 seconds without progress. Keep a
// donor lease for twice that interval so every in-deadline retry can reuse the
// exact immutable wire identity, while abandoned sessions remain bounded.
const DONOR_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
pub(super) const RECOVERY_RETRY_DELAY: Duration = Duration::from_millis(RECOVERY_RETRY_DELAY_MS);

#[cfg(any(test, feature = "test-support"))]
fn recovery_terminal_trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("SHITSPEAK_STRICT_RECOVERY_TRACE").is_some())
}

macro_rules! recovery_terminal_trace {
    ($($arg:tt)*) => {
        #[cfg(any(test, feature = "test-support"))]
        if recovery_terminal_trace_enabled() {
            eprintln!("strict-recovery-v8 terminal: {}", format_args!($($arg)*));
        }
        #[cfg(not(any(test, feature = "test-support")))]
        if false {
            let _ = format_args!($($arg)*);
        }
    };
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ServerKey {
    requester: NodeIdentifier,
    requester_epoch: u64,
    attempt: RecoveryAttemptId,
}

struct ClientTransfer {
    donor: ParticipantIncarnation,
    target: LogicalTarget,
    cut: TerminalCut,
    terminal_id: u64,
    terminal_nonce: u64,
    terminal_cursor: u64,
    terminal_states: Vec<StrictTerminalState>,
    snapshot_id: u64,
    snapshot_nonce: u64,
    snapshot_cursor: u64,
    snapshot_total: Option<u64>,
    snapshot_digest: Option<[u8; 32]>,
    snapshot_bytes: Vec<u8>,
    staging: Option<(PathBuf, RecoveryStagingManifest)>,
}

struct ServerSnapshot {
    donor_epoch: u64,
    target: LogicalTarget,
    cut: TerminalCut,
    transfer_id: u64,
    bytes: Bytes,
    digest: [u8; 32],
    pending_pages: HashMap<(u64, u64), ServerPageAck>,
    last_authenticated_activity: Instant,
}

struct ServerTerminal {
    donor_epoch: u64,
    target: LogicalTarget,
    cut: TerminalCut,
    transfer_id: u64,
    pending_pages: HashMap<(u64, u64), ServerPageAck>,
    last_authenticated_activity: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ServerPageAck {
    next_cursor: u64,
    final_page: bool,
}

#[derive(Clone)]
struct ServerAttestation {
    target: LogicalTarget,
    cut: TerminalCut,
    last_authenticated_activity: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuditedGenerationZeroImage {
    target: LogicalTarget,
    terminal_cut: TerminalCut,
    envelope_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingTransferRetry {
    donor: ParticipantIncarnation,
    terminal_cut: ReducerCut,
    kind: TransferKind,
    not_before: Instant,
}

/// Attempt-scoped, ephemeral protocol state. Durable state remains in the
/// terminal journal and staging artifact; wire ids are deliberately renewed
/// after restart.
pub(super) struct RecoveryV8Runtime {
    next_wire_id: AtomicU64,
    probe_nonces: Mutex<HashMap<(RecoveryAttemptId, NodeIdentifier), u64>>,
    clients: Mutex<HashMap<RecoveryAttemptId, ClientTransfer>>,
    pending_transfer_retries: Mutex<BTreeMap<RecoveryAttemptId, PendingTransferRetry>>,
    server_terminals: Mutex<HashMap<ServerKey, ServerTerminal>>,
    server_snapshots: Mutex<HashMap<ServerKey, ServerSnapshot>>,
    generation_zero_image_at_construction: Mutex<Option<AuditedGenerationZeroImage>>,
    audited_generation_zero_image: Mutex<Option<AuditedGenerationZeroImage>>,
    served_probe_attestations: Mutex<HashMap<ServerKey, ServerAttestation>>,
    active_generation_zero_audit: Mutex<Option<RecoveryAttemptId>>,
    generation_zero_audit_deferred_until: Mutex<Option<Instant>>,
}

impl Default for RecoveryV8Runtime {
    fn default() -> Self {
        Self {
            next_wire_id: AtomicU64::new(1),
            probe_nonces: Mutex::new(HashMap::new()),
            clients: Mutex::new(HashMap::new()),
            pending_transfer_retries: Mutex::new(BTreeMap::new()),
            server_terminals: Mutex::new(HashMap::new()),
            server_snapshots: Mutex::new(HashMap::new()),
            generation_zero_image_at_construction: Mutex::new(None),
            audited_generation_zero_image: Mutex::new(None),
            served_probe_attestations: Mutex::new(HashMap::new()),
            active_generation_zero_audit: Mutex::new(None),
            generation_zero_audit_deferred_until: Mutex::new(None),
        }
    }
}

fn generation_zero_image(
    history_metadata: HistoryMetadata,
    repository_snapshot: Bytes,
    applied_operations: std::collections::BTreeMap<OpId, u64>,
    retired_operations: std::collections::BTreeMap<u64, u64>,
    terminal_cut: TerminalCut,
) -> Option<AuditedGenerationZeroImage> {
    if terminal_cut.generation() != 0 {
        return None;
    }
    let target = LogicalTarget::new(
        history_metadata.version,
        history_metadata.freshness,
        *terminal_cut.terminal_set_digest(),
    );
    let envelope = encode_bound_s2s_snapshot_envelope(
        repository_snapshot,
        applied_operations,
        retired_operations,
        terminal_cut,
    )
    .ok()?;
    Some(AuditedGenerationZeroImage {
        target,
        terminal_cut,
        envelope_digest: sha256(&envelope),
    })
}

/// Freeze the sole local image eligible for the periodic generation-zero
/// audit. This runs during construction, after the journal has restored the
/// runtime ledger and before the runtime can accept work.
pub(super) fn pin_generation_zero_image_at_construction<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
) {
    // Empty repositories cannot be generation-zero recovery candidates. In
    // particular, receiver-only repositories need not support producing a
    // snapshot merely to construct a runtime that will bootstrap from v8.
    if rt.repo.current_version() == 0 {
        return;
    }
    let Ok((history_metadata, repository_snapshot)) = rt.repo.snapshot_with_metadata() else {
        return;
    };
    let Ok(journal) = rt.terminal_journal.try_lock() else {
        return;
    };
    let terminal_cut = journal.terminal_cut();
    if terminal_cut.generation() != 0 || history_metadata.version == 0 {
        return;
    }
    let retired_operations = journal.retired_origins();
    let applied_operations = rt
        .state
        .lock()
        .applied_operations
        .iter()
        .filter_map(|(op_id, version)| {
            (*version <= history_metadata.version).then_some((*op_id, *version))
        })
        .collect();
    let image = generation_zero_image(
        history_metadata,
        repository_snapshot,
        applied_operations,
        retired_operations,
        terminal_cut,
    );
    *rt.recovery_v8.generation_zero_image_at_construction.lock() = image;
}

pub(super) fn suppress_generation_zero_audit_after_repository_mutation<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
) {
    let _recovery_start_guard = rt.strict_work_recovery_gate.lock();
    *rt.recovery_v8.generation_zero_image_at_construction.lock() = None;
    let active_attempt = *rt.recovery_v8.active_generation_zero_audit.lock();
    if let Some(attempt) = active_attempt {
        rt.transition_recovery(RecoveryEvent::AuditYield { attempt });
        if rt.recovery_coordinator.lock().phase() == RecoveryPhase::Healthy {
            *rt.recovery_v8.active_generation_zero_audit.lock() = None;
        }
    }
}

impl RecoveryV8Runtime {
    fn wire_id(&self) -> u64 {
        self.next_wire_id.fetch_add(1, Ordering::Relaxed).max(1)
    }

    fn cleanup(&self, attempt: RecoveryAttemptId, protected_staging_path: Option<&Path>) {
        self.probe_nonces
            .lock()
            .retain(|(candidate, _), _| *candidate != attempt);
        if let Some(client) = self.clients.lock().remove(&attempt) {
            if let Some((path, _)) = client.staging {
                if protected_staging_path != Some(path.as_path()) {
                    let _ = delete_recovery_staging_artifact(&path);
                }
            }
        }
        self.pending_transfer_retries.lock().remove(&attempt);
        let mut active_audit = self.active_generation_zero_audit.lock();
        if *active_audit == Some(attempt) {
            *active_audit = None;
        }
    }

    fn schedule_transfer_retry(
        &self,
        attempt: RecoveryAttemptId,
        donor: ParticipantIncarnation,
        terminal_cut: ReducerCut,
        kind: TransferKind,
        now: Instant,
    ) {
        let not_before = now.checked_add(RECOVERY_RETRY_DELAY).unwrap_or(now);
        let mut retries = self.pending_transfer_retries.lock();
        match retries.get(&attempt) {
            Some(pending)
                if pending.donor == donor
                    && pending.terminal_cut == terminal_cut
                    && pending.kind == kind => {}
            _ => {
                retries.insert(
                    attempt,
                    PendingTransferRetry {
                        donor,
                        terminal_cut,
                        kind,
                        not_before,
                    },
                );
            }
        }
    }

    fn take_due_transfer_retries(
        &self,
        now: Instant,
    ) -> Vec<(RecoveryAttemptId, PendingTransferRetry)> {
        let mut retries = self.pending_transfer_retries.lock();
        let due = retries
            .iter()
            .filter(|(_, retry)| now >= retry.not_before)
            .map(|(attempt, retry)| (*attempt, retry.clone()))
            .collect::<Vec<_>>();
        for (attempt, _) in &due {
            retries.remove(attempt);
        }
        due
    }

    pub(super) fn cancel_transfer_retry(&self, attempt: RecoveryAttemptId) {
        self.pending_transfer_retries.lock().remove(&attempt);
    }
}

#[cfg(test)]
pub(super) fn client_terminal_state_count<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    attempt: RecoveryAttemptId,
) -> Option<usize> {
    rt.recovery_v8
        .clients
        .lock()
        .get(&attempt)
        .map(|client| client.terminal_states.len())
}

#[cfg(test)]
pub(super) fn donor_session_counts<R: StrictReplicable>(rt: &StrictRuntime<R>) -> (usize, usize) {
    (
        rt.recovery_v8.server_terminals.lock().len(),
        rt.recovery_v8.server_snapshots.lock().len(),
    )
}

fn donor_session_expired(last_authenticated_activity: Instant, now: Instant) -> bool {
    now.checked_duration_since(last_authenticated_activity)
        .is_some_and(|idle| idle >= DONOR_SESSION_IDLE_TIMEOUT)
}

fn release_donor_reservations<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    reservations: Vec<(NodeIdentifier, BulkPageIdentity)>,
) {
    for (requester, identity) in reservations {
        rt.net
            .acknowledge_bulk_unicast(requester, &rt.topic, identity);
    }
}

fn prune_donor_sessions_where<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    mut should_prune_terminal: impl FnMut(&ServerKey, &ServerTerminal) -> bool,
    mut should_prune_snapshot: impl FnMut(&ServerKey, &ServerSnapshot) -> bool,
    mut should_prune_attestation: impl FnMut(&ServerKey, &ServerAttestation) -> bool,
) {
    let mut reservations = Vec::new();
    {
        let mut terminals = rt.recovery_v8.server_terminals.lock();
        terminals.retain(|key, terminal| {
            if !should_prune_terminal(key, terminal) {
                return true;
            }
            reservations.extend(terminal.pending_pages.keys().map(
                |&(transfer_id, request_nonce)| {
                    (
                        key.requester,
                        BulkPageIdentity::recovery_terminal(transfer_id, request_nonce),
                    )
                },
            ));
            false
        });
    }
    {
        let mut snapshots = rt.recovery_v8.server_snapshots.lock();
        snapshots.retain(|key, snapshot| {
            if !should_prune_snapshot(key, snapshot) {
                return true;
            }
            reservations.extend(snapshot.pending_pages.keys().map(
                |&(transfer_id, request_nonce)| {
                    (
                        key.requester,
                        BulkPageIdentity::recovery_snapshot(transfer_id, request_nonce),
                    )
                },
            ));
            false
        });
    }
    rt.recovery_v8
        .served_probe_attestations
        .lock()
        .retain(|key, attestation| !should_prune_attestation(key, attestation));
    sync_donor_session_metrics(rt);
    release_donor_reservations(rt, reservations);
}

fn prune_idle_donor_sessions_at<R: StrictReplicable>(rt: &StrictRuntime<R>, now: Instant) {
    prune_donor_sessions_where(
        rt,
        |_, terminal| donor_session_expired(terminal.last_authenticated_activity, now),
        |_, snapshot| donor_session_expired(snapshot.last_authenticated_activity, now),
        |_, attestation| donor_session_expired(attestation.last_authenticated_activity, now),
    );
}

pub(super) fn prune_idle_donor_sessions<R: StrictReplicable>(rt: &StrictRuntime<R>) {
    prune_idle_donor_sessions_at(rt, Instant::now());
}

#[cfg(test)]
pub(super) fn prune_idle_donor_sessions_after_timeout_for_test<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
) {
    prune_idle_donor_sessions_at(
        rt,
        Instant::now() + DONOR_SESSION_IDLE_TIMEOUT + Duration::from_millis(1),
    );
}

pub(super) fn prune_donor_sessions_for_requester<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    requester: NodeIdentifier,
    requester_epoch: u64,
) {
    prune_donor_sessions_where(
        rt,
        |key, _| key.requester == requester && key.requester_epoch == requester_epoch,
        |key, _| key.requester == requester && key.requester_epoch == requester_epoch,
        |key, _| key.requester == requester && key.requester_epoch == requester_epoch,
    );
}

pub(super) fn prune_restarted_requester_sessions<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    requester: NodeIdentifier,
    current_epoch: u64,
) {
    prune_donor_sessions_where(
        rt,
        |key, _| key.requester == requester && key.requester_epoch != current_epoch,
        |key, _| key.requester == requester && key.requester_epoch != current_epoch,
        |key, _| key.requester == requester && key.requester_epoch != current_epoch,
    );
}

fn sync_donor_session_metrics<R: StrictReplicable>(rt: &StrictRuntime<R>) {
    rt.recovery_metrics.set_donor_sessions(
        rt.recovery_v8.server_terminals.lock().len(),
        rt.recovery_v8.server_snapshots.lock().len(),
    );
}

fn refresh_exact_attestation<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    key: &ServerKey,
    target: &LogicalTarget,
    cut: TerminalCut,
) {
    if let Some(attestation) = rt.recovery_v8.served_probe_attestations.lock().get_mut(key)
        && attestation.target == *target
        && attestation.cut == cut
    {
        attestation.last_authenticated_activity = Instant::now();
    }
}

#[cfg(test)]
pub(super) fn attest_terminal_request_for_test<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    request: &StrictRecoveryTerminalReq,
) {
    let (Some(context), Some(cut), Some(target)) = (
        request.context.as_ref(),
        request.target_cut.as_ref().and_then(cut_from_wire),
        request
            .context
            .as_ref()
            .and_then(|context| context.target.as_ref())
            .and_then(target_from_wire),
    ) else {
        return;
    };
    let Some(attempt) = request_context(rt, from, epoch, context) else {
        return;
    };
    if context.expected_donor_boot_epoch == rt.boot_epoch {
        rt.recovery_v8.served_probe_attestations.lock().insert(
            ServerKey {
                requester: from,
                requester_epoch: epoch,
                attempt,
            },
            ServerAttestation {
                target,
                cut,
                last_authenticated_activity: Instant::now(),
            },
        );
    }
}

#[cfg(test)]
pub(super) fn attest_snapshot_request_for_test<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    request: &StrictRecoverySnapshotReq,
) {
    let (Some(context), Some(cut), Some(target)) = (
        request.context.as_ref(),
        request.target_cut.as_ref().and_then(cut_from_wire),
        request
            .context
            .as_ref()
            .and_then(|context| context.target.as_ref())
            .and_then(target_from_wire),
    ) else {
        return;
    };
    let Some(attempt) = request_context(rt, from, epoch, context) else {
        return;
    };
    if context.expected_donor_boot_epoch == rt.boot_epoch {
        rt.recovery_v8.served_probe_attestations.lock().insert(
            ServerKey {
                requester: from,
                requester_epoch: epoch,
                attempt,
            },
            ServerAttestation {
                target,
                cut,
                last_authenticated_activity: Instant::now(),
            },
        );
    }
}

fn attempt_bytes(attempt: RecoveryAttemptId) -> Bytes {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&attempt.hi().to_be_bytes());
    bytes[8..].copy_from_slice(&attempt.lo().to_be_bytes());
    Bytes::copy_from_slice(&bytes)
}

fn durable_attempt_id(attempt: RecoveryAttemptId) -> [u8; 16] {
    attempt_bytes(attempt)
        .as_ref()
        .try_into()
        .expect("attempt id")
}

fn attempt_from_context(context: &StrictRecoveryContext) -> Option<RecoveryAttemptId> {
    let bytes: [u8; 16] = context.attempt_id.as_ref().try_into().ok()?;
    Some(RecoveryAttemptId::new(
        u64::from_be_bytes(bytes[..8].try_into().ok()?),
        u64::from_be_bytes(bytes[8..].try_into().ok()?),
    ))
}

fn target_to_wire(target: &LogicalTarget) -> StrictRecoveryTarget {
    StrictRecoveryTarget {
        repository_version: target.repository_version(),
        history_freshness: target.history_freshness(),
        terminal_set_digest: Bytes::copy_from_slice(target.terminal_set_digest()),
    }
}

fn target_from_wire(target: &StrictRecoveryTarget) -> Option<LogicalTarget> {
    Some(LogicalTarget::new(
        target.repository_version,
        target.history_freshness,
        target.terminal_set_digest.as_ref().try_into().ok()?,
    ))
}

fn reducer_cut(cut: TerminalCut) -> ReducerCut {
    ReducerCut::new(
        *cut.journal_id(),
        cut.generation(),
        *cut.chain_digest(),
        *cut.terminal_set_digest(),
    )
}

fn journal_cut(cut: &ReducerCut) -> TerminalCut {
    TerminalCut::new(
        *cut.journal_id(),
        cut.generation(),
        *cut.chain_digest(),
        *cut.terminal_set_digest(),
    )
}

fn wire_context(
    requester: NodeIdentifier,
    requester_epoch: u64,
    attempt: RecoveryAttemptId,
    donor_epoch: u64,
    target: Option<&LogicalTarget>,
) -> StrictRecoveryContext {
    StrictRecoveryContext {
        requester_node: requester as u32,
        requester_boot_epoch: requester_epoch,
        attempt_id: attempt_bytes(attempt),
        expected_donor_boot_epoch: donor_epoch,
        target: target.map(target_to_wire),
    }
}

fn request_context<R: StrictReplicable>(
    _rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    context: &StrictRecoveryContext,
) -> Option<RecoveryAttemptId> {
    (node_from_u32(context.requester_node) == Some(from) && context.requester_boot_epoch == epoch)
        .then(|| attempt_from_context(context))
        .flatten()
}

fn response_context<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    context: &StrictRecoveryContext,
) -> Option<RecoveryAttemptId> {
    (node_from_u32(context.requester_node) == Some(rt.self_id)
        && context.requester_boot_epoch == rt.boot_epoch
        && context.expected_donor_boot_epoch == epoch
        && rt.net.member_boot_epoch(from) == Some(epoch))
    .then(|| attempt_from_context(context))
    .flatten()
}

fn status_failure(status: StrictRecoveryStatus) -> Option<DonorFailure> {
    match status {
        StrictRecoveryStatus::TargetMoved => Some(DonorFailure::TargetMoved),
        StrictRecoveryStatus::IncarnationMismatch => Some(DonorFailure::IncarnationLost),
        StrictRecoveryStatus::ResourceLimit => Some(DonorFailure::ResourceLimit),
        StrictRecoveryStatus::RetryableFailure | StrictRecoveryStatus::Unspecified => {
            Some(DonorFailure::RetryableFailure)
        }
        StrictRecoveryStatus::Ok => None,
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = digest(&SHA256, bytes);
    digest.as_ref().try_into().expect("SHA-256 is 32 bytes")
}

async fn capture_generation_zero_image<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
) -> Option<AuditedGenerationZeroImage> {
    let boundary = rt.capture_snapshot_terminal_boundary().await.ok()?;
    if boundary.terminal_cut.generation() != 0 {
        return None;
    }
    let expected_repository_snapshot = boundary.repository_snapshot.clone();
    let expected_applied_operations = boundary.applied_operations.clone();
    let expected_retired_operations = boundary.retired_operations.clone();
    let terminal_cut = boundary.terminal_cut;
    let envelope = encode_bound_s2s_snapshot_envelope(
        boundary.repository_snapshot.clone(),
        boundary.applied_operations.clone(),
        boundary.retired_operations.clone(),
        terminal_cut,
    )
    .ok()?;
    let decoded = decode_s2s_snapshot_envelope(envelope.clone()).ok()?;
    let exact_applied_operations = decoded.applied_operations.len()
        == expected_applied_operations.len()
        && expected_applied_operations
            .iter()
            .all(|(op_id, version)| decoded.applied_operations.get(op_id) == Some(version));
    if decoded.terminal_cut != Some(terminal_cut)
        || decoded.repository_snapshot != expected_repository_snapshot
        || !exact_applied_operations
        || decoded.retired_operations != expected_retired_operations
    {
        return None;
    }
    generation_zero_image(
        boundary.history_metadata,
        boundary.repository_snapshot,
        boundary.applied_operations,
        boundary.retired_operations,
        terminal_cut,
    )
}

/// A generation-zero checkpoint cannot prove that it belongs to the
/// cluster's current lineage without witnesses. Audit it autonomously once
/// per exact local image, including on a quiescent restart.
pub(super) async fn request_generation_zero_audit<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
) -> bool {
    if !rt.recovery_is_healthy() || rt.net.strict_participant_count() <= 1 {
        return false;
    }
    if rt
        .recovery_v8
        .generation_zero_audit_deferred_until
        .lock()
        .is_some_and(|deadline| Instant::now() < deadline)
        || !rt.recovery_v8.server_terminals.lock().is_empty()
        || !rt.recovery_v8.server_snapshots.lock().is_empty()
    {
        return false;
    }
    let Some(image) = capture_generation_zero_image(rt).await else {
        return false;
    };
    // A brand-new empty repository has no foreign copied state to audit and
    // may not yet have a topic runtime on every capable cluster participant.
    // Ordinary bootstrap owns that case. The incident shape is a populated,
    // already-current repository paired with generation zero.
    if image.target.repository_version() == 0 {
        return false;
    }
    let _recovery_start_guard = rt.strict_work_recovery_gate.lock();
    if rt
        .recovery_v8
        .generation_zero_image_at_construction
        .lock()
        .as_ref()
        != Some(&image)
    {
        return false;
    }
    if rt.recovery_v8.audited_generation_zero_image.lock().as_ref() == Some(&image) {
        return false;
    }
    if !rt.recovery_target_has_witness_quorum(&image.target) {
        return false;
    }
    if !rt.recovery_is_healthy() {
        return false;
    }
    let started = rt
        .request_recovery_under_gate(super::recovery_reducer::RecoveryTrigger::GenerationZeroAudit);
    if started {
        *rt.recovery_v8.active_generation_zero_audit.lock() =
            rt.recovery_coordinator.lock().attempt();
    }
    started
}

async fn complete_from_exact_local_image<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    attempt: RecoveryAttemptId,
    donor: &ParticipantIncarnation,
    target: &LogicalTarget,
    terminal_cut: &ReducerCut,
) -> bool {
    if !rt.recovery_v8_capability_ready() {
        return false;
    }
    let expected_cut = journal_cut(terminal_cut);
    let current = {
        let coordinator = rt.recovery_coordinator.lock();
        coordinator.attempt() == Some(attempt)
            && coordinator.phase() == RecoveryPhase::FetchingTerminalCheckpoint
            && coordinator.donor() == Some(donor)
            && coordinator
                .certificate()
                .is_some_and(|certificate| certificate.target() == target)
            && coordinator.representation_cut() == Some(terminal_cut)
    };
    if !current {
        return false;
    }
    let Some(image) = capture_generation_zero_image(rt).await else {
        return false;
    };
    if image.target != *target || image.terminal_cut != expected_cut {
        return false;
    }
    let still_current = {
        let coordinator = rt.recovery_coordinator.lock();
        coordinator.attempt() == Some(attempt)
            && coordinator.phase() == RecoveryPhase::FetchingTerminalCheckpoint
            && coordinator.donor() == Some(donor)
            && coordinator
                .certificate()
                .is_some_and(|certificate| certificate.target() == target)
            && coordinator.representation_cut() == Some(terminal_cut)
    };
    if !still_current {
        return false;
    }
    rt.transition_recovery(RecoveryEvent::LocalImageVerified {
        attempt,
        donor: donor.clone(),
        verification: Verification::new(target.clone(), terminal_cut.clone()),
    });
    if rt.recovery_coordinator.lock().phase() != RecoveryPhase::Healthy {
        return false;
    }
    *rt.recovery_v8.audited_generation_zero_image.lock() = Some(image);
    true
}

fn terminal_transfer_id(attempt: RecoveryAttemptId, donor_epoch: u64) -> u64 {
    attempt
        .hi()
        .rotate_left(17)
        .wrapping_add(attempt.lo().rotate_right(11))
        .wrapping_add(donor_epoch)
        .max(1)
}

fn durable_phase(phase: super::recovery_reducer::RecoveryPhase) -> Option<DurableRecoveryPhase> {
    use super::recovery_reducer::RecoveryPhase;
    match phase {
        RecoveryPhase::Healthy => None,
        RecoveryPhase::Certifying => Some(DurableRecoveryPhase::Certifying),
        RecoveryPhase::FetchingTerminalCheckpoint => {
            Some(DurableRecoveryPhase::FetchingTerminalCheckpoint)
        }
        RecoveryPhase::FetchingRepositorySnapshot => {
            Some(DurableRecoveryPhase::FetchingRepositorySnapshot)
        }
        RecoveryPhase::Prepared => Some(DurableRecoveryPhase::Prepared),
        RecoveryPhase::Installing => Some(DurableRecoveryPhase::Installing),
        RecoveryPhase::Verifying => Some(DurableRecoveryPhase::Verifying),
        RecoveryPhase::Backoff => Some(DurableRecoveryPhase::Backoff),
    }
}

fn reducer_phase(phase: DurableRecoveryPhase) -> super::recovery_reducer::RecoveryPhase {
    use super::recovery_reducer::RecoveryPhase;
    match phase {
        DurableRecoveryPhase::Certifying => RecoveryPhase::Certifying,
        DurableRecoveryPhase::FetchingTerminalCheckpoint => {
            RecoveryPhase::FetchingTerminalCheckpoint
        }
        DurableRecoveryPhase::FetchingRepositorySnapshot => {
            RecoveryPhase::FetchingRepositorySnapshot
        }
        DurableRecoveryPhase::Prepared => RecoveryPhase::Prepared,
        DurableRecoveryPhase::Installing => RecoveryPhase::Installing,
        DurableRecoveryPhase::Verifying => RecoveryPhase::Verifying,
        DurableRecoveryPhase::Backoff => RecoveryPhase::Backoff,
    }
}

pub(super) fn restore_coordinator(
    journal: &TerminalJournal,
) -> Result<Option<(StrictRecoveryCoordinator, Vec<RecoveryEffect>)>, String> {
    let Some(durable) = journal
        .load_recovery_attempt()
        .map_err(|error| error.to_string())?
    else {
        return Ok(None);
    };
    let attempt = attempt_from_bytes(durable.attempt_id())
        .ok_or_else(|| "durable recovery attempt id is invalid".to_owned())?;
    let target = durable.target().map(|target| {
        LogicalTarget::new(
            target.repository_version(),
            target.history_freshness(),
            *target.terminal_set_digest(),
        )
    });
    let witnesses = durable
        .witnesses()
        .iter()
        .map(|witness| {
            Ok(RecoveryAttestation::new(
                ParticipantIncarnation::new(
                    u64::from(witness.participant().node_id()),
                    witness.participant().boot_epoch(),
                ),
                target.clone().ok_or_else(|| {
                    "durable recovery witnesses require a certified target".to_owned()
                })?,
                reducer_cut(witness.terminal_cut()),
                witness.history_rank(),
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let donor_order = durable
        .donor_order()
        .iter()
        .map(|donor| ParticipantIncarnation::new(u64::from(donor.node_id()), donor.boot_epoch()))
        .collect();
    let current_donor = durable
        .current_donor()
        .map(|donor| ParticipantIncarnation::new(u64::from(donor.node_id()), donor.boot_epoch()));
    let failure_history = durable
        .failure_history()
        .iter()
        .map(|failure| {
            let reason = match failure.reason() {
                "incarnation_lost" => DonorFailure::IncarnationLost,
                "sustained_route_loss" => DonorFailure::SustainedRouteLoss,
                "target_moved" => DonorFailure::TargetMoved,
                "no_progress_deadline" => DonorFailure::NoProgressDeadline,
                "resource_limit" => DonorFailure::ResourceLimit,
                _ => DonorFailure::RetryableFailure,
            };
            RecoveryFailure::new(
                ParticipantIncarnation::new(
                    u64::from(failure.donor().node_id()),
                    failure.donor().boot_epoch(),
                ),
                reason,
            )
        })
        .collect();
    let current_donor_index = durable
        .current_donor_index()
        .map(|index| {
            usize::try_from(index)
                .map_err(|_| "durable recovery donor index does not fit usize".to_owned())
        })
        .transpose()?;
    StrictRecoveryCoordinator::restore(
        RecoveryRestore::new_with_electorate(
            attempt,
            reducer_phase(durable.phase()),
            usize::try_from(durable.frozen_quorum_denominator())
                .map_err(|_| "durable recovery denominator does not fit usize".to_owned())?,
            durable
                .frozen_electorate()
                .iter()
                .copied()
                .map(u64::from)
                .collect(),
            target,
            witnesses,
            donor_order,
            current_donor_index,
            current_donor,
            durable.representation_cut().map(reducer_cut),
            failure_history,
        ),
        0,
    )
    .map(Some)
    .map_err(|error| format!("invalid durable recovery coordinator: {error:?}"))
}

fn durable_attempt<R: StrictReplicable>(rt: &StrictRuntime<R>) -> Option<DurableRecoveryAttempt> {
    durable_attempt_for_phase(rt, None)
}

fn durable_attempt_for_phase<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    phase_override: Option<DurableRecoveryPhase>,
) -> Option<DurableRecoveryAttempt> {
    let coordinator = rt.recovery_coordinator.lock();
    let attempt = coordinator.attempt()?;
    let phase = phase_override.or_else(|| durable_phase(coordinator.phase()))?;
    let failure_history = coordinator
        .failure_history()
        .iter()
        .map(|failure| {
            Some(DurableRecoveryFailure::new(
                DurableRecoveryParticipant::new(
                    u16::try_from(failure.donor().node_id()).ok()?,
                    failure.donor().boot_epoch(),
                ),
                match failure.reason() {
                    DonorFailure::IncarnationLost => "incarnation_lost",
                    DonorFailure::SustainedRouteLoss => "sustained_route_loss",
                    DonorFailure::TargetMoved => "target_moved",
                    DonorFailure::NoProgressDeadline => "no_progress_deadline",
                    DonorFailure::RetryableFailure => "retryable_failure",
                    DonorFailure::ResourceLimit => "resource_limit",
                },
                1,
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    let Some(certificate) = coordinator.certificate() else {
        return DurableRecoveryAttempt::new_with_electorate(
            durable_attempt_id(attempt),
            phase,
            u64::try_from(coordinator.frozen_denominator()).ok()?,
            coordinator
                .frozen_electorate()
                .iter()
                .copied()
                .map(u16::try_from)
                .collect::<Result<Vec<_>, _>>()
                .ok()?,
            None,
            Vec::new(),
            Vec::new(),
            None,
            None,
            None,
            failure_history,
        )
        .ok();
    };
    let target = certificate.target();
    let mut witnesses = certificate
        .witnesses()
        .iter()
        .map(|witness| {
            Some((
                witness.history_rank(),
                DurableRecoveryWitness::new(
                    DurableRecoveryParticipant::new(
                        u16::try_from(witness.witness().node_id()).ok()?,
                        witness.witness().boot_epoch(),
                    ),
                    journal_cut(witness.terminal_cut()),
                )
                .with_history_rank(witness.history_rank()),
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    witnesses.sort_by_key(|(_, witness)| witness.participant());
    let durable_witnesses = witnesses
        .iter()
        .map(|(_, witness)| *witness)
        .collect::<Vec<_>>();
    witnesses.sort_by(|(left_rank, left), (right_rank, right)| {
        right_rank
            .cmp(left_rank)
            .then_with(|| left.participant().cmp(&right.participant()))
    });
    let donor_order = witnesses
        .into_iter()
        .map(|(_, witness)| witness.participant())
        .collect();
    DurableRecoveryAttempt::new_with_electorate(
        durable_attempt_id(attempt),
        phase,
        u64::try_from(certificate.frozen_denominator()).ok()?,
        coordinator
            .frozen_electorate()
            .iter()
            .copied()
            .map(u16::try_from)
            .collect::<Result<Vec<_>, _>>()
            .ok()?,
        Some(DurableRecoveryTarget::new(
            target.repository_version(),
            target.history_freshness(),
            *target.terminal_set_digest(),
        )),
        durable_witnesses,
        donor_order,
        Some(u64::try_from(coordinator.donor_index()).ok()?),
        Some(DurableRecoveryParticipant::new(
            u16::try_from(coordinator.donor()?.node_id()).ok()?,
            coordinator.donor()?.boot_epoch(),
        )),
        coordinator.representation_cut().map(journal_cut),
        failure_history,
    )
    .ok()
}

fn recertify_topic_after_local_recovery_failure<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    reason: &'static str,
) {
    let attempt = rt.recovery_coordinator.lock().attempt();
    tracing::error!(
        topic = %rt.topic,
        ?attempt,
        reason,
        "strict recovery attempt cannot continue; keeping only the topic fenced and recertifying"
    );
    if let Some(attempt) = attempt {
        rt.transition_recovery(RecoveryEvent::Cancel {
            attempt,
            now_ms: rt.recovery_now_ms(),
        });
    } else {
        let _ = rt.request_pending_repository_install_recovery();
    }
}

async fn persist_attempt<R: StrictReplicable>(rt: &StrictRuntime<R>) -> bool {
    let Some(attempt) = durable_attempt(rt) else {
        if rt.recovery_coordinator.lock().phase() == RecoveryPhase::Healthy {
            return true;
        }
        recertify_topic_after_local_recovery_failure(
            rt,
            "recovery state could not be encoded durably",
        );
        return false;
    };
    match rt
        .with_terminal_journal_mutation(move |journal| journal.persist_recovery_attempt(&attempt))
        .await
    {
        Ok(()) => true,
        Err(error) => {
            rt.record_terminal_journal_failure(&error);
            false
        }
    }
}

fn stage_path<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    attempt: RecoveryAttemptId,
) -> Option<PathBuf> {
    let directory = rt.net.strict_protocol_state_dir()?;
    let prefix = stage_prefix(&rt.topic);
    Some(directory.join(format!(
        "{prefix}{:016x}-{:016x}.stage",
        attempt.hi(),
        attempt.lo()
    )))
}

fn stage_prefix(topic: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    topic.hash(&mut hasher);
    format!("strict-recovery-{:016x}-", hasher.finish())
}

fn cleanup_orphaned_staging_artifacts<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    retained: Option<&Path>,
) {
    let Some(directory) = rt.net.strict_protocol_state_dir() else {
        return;
    };
    let prefix = stage_prefix(&rt.topic);
    let Ok(entries) = fs::read_dir(&directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if retained.is_some_and(|retained| retained == path) {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with(&prefix)
            && name.ends_with(".stage")
            && let Err(error) = delete_recovery_staging_artifact(&path)
        {
            tracing::warn!(topic = %rt.topic, path = %path.display(), %error, "strict recovery orphan staging cleanup failed");
        }
    }
}

async fn send_terminal_request<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    attempt: RecoveryAttemptId,
) {
    let request = {
        let coordinator = rt.recovery_coordinator.lock();
        if coordinator.attempt() != Some(attempt)
            || coordinator.phase() != RecoveryPhase::FetchingTerminalCheckpoint
        {
            return;
        }
        let clients = rt.recovery_v8.clients.lock();
        let Some(client) = clients.get(&attempt) else {
            return;
        };
        if coordinator.donor() != Some(&client.donor)
            || coordinator.representation_cut().map(journal_cut) != Some(client.cut)
        {
            return;
        }
        let Ok(donor) = NodeIdentifier::try_from(client.donor.node_id()) else {
            return;
        };
        let body = StrictBody::RecoveryTerminalReq(StrictRecoveryTerminalReq {
            context: Some(wire_context(
                rt.self_id,
                rt.boot_epoch,
                attempt,
                client.donor.boot_epoch(),
                Some(&client.target),
            )),
            target_cut: Some(cut_to_wire(client.cut)),
            transfer_id: client.terminal_id,
            request_nonce: client.terminal_nonce,
            expected_cursor: client.terminal_cursor,
        });
        (donor, body)
    };
    let _ = rt
        .net
        .send_redundant_unicast(request.0, &rt.topic, request.1)
        .await;
}

async fn send_snapshot_request<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    attempt: RecoveryAttemptId,
) {
    let (donor, body) = {
        let coordinator = rt.recovery_coordinator.lock();
        if coordinator.attempt() != Some(attempt)
            || coordinator.phase() != RecoveryPhase::FetchingRepositorySnapshot
        {
            return;
        }
        let clients = rt.recovery_v8.clients.lock();
        let Some(client) = clients.get(&attempt) else {
            return;
        };
        if coordinator.donor() != Some(&client.donor)
            || coordinator.representation_cut().map(journal_cut) != Some(client.cut)
        {
            return;
        }
        let Ok(donor) = NodeIdentifier::try_from(client.donor.node_id()) else {
            return;
        };
        (
            donor,
            StrictBody::RecoverySnapshotReq(StrictRecoverySnapshotReq {
                context: Some(wire_context(
                    rt.self_id,
                    rt.boot_epoch,
                    attempt,
                    client.donor.boot_epoch(),
                    Some(&client.target),
                )),
                target_cut: Some(cut_to_wire(client.cut)),
                transfer_id: client.snapshot_id,
                request_nonce: client.snapshot_nonce,
                expected_cursor: client.snapshot_cursor,
            }),
        )
    };
    let _ = rt.net.send_redundant_unicast(donor, &rt.topic, body).await;
}

pub(super) async fn execute_effects<R: StrictReplicable>(
    rt: &std::sync::Arc<StrictRuntime<R>>,
    effects: Vec<RecoveryEffect>,
) {
    execute_effects_with_retry_clock(rt, effects, None).await;
}

async fn execute_effects_with_retry_clock<R: StrictReplicable>(
    rt: &std::sync::Arc<StrictRuntime<R>>,
    effects: Vec<RecoveryEffect>,
    retry_now: Option<Instant>,
) {
    for effect in effects {
        if !rt.recovery_v8_capability_ready() {
            // Foreign-lineage evidence may deliberately create a durable
            // Certifying fence before the complete electorate supports v8.
            // Persist and clean up that attempt, but emit no recovery wire
            // traffic. Suppressing a queued network effect atomically moves
            // the durable attempt to timed Backoff; otherwise restoring the
            // v8 floor could strand it in a transfer phase with no request
            // armed. Cancel is the reducer's single attempt-wide cleanup
            // transition and retains the fence, electorate, and attempt id.
            match &effect {
                RecoveryEffect::Persist
                | RecoveryEffect::Cleanup { .. }
                | RecoveryEffect::Metric(_) => {}
                RecoveryEffect::Install { .. }
                    if matches!(
                        rt.recovery_coordinator.lock().phase(),
                        RecoveryPhase::Prepared
                            | RecoveryPhase::Installing
                            | RecoveryPhase::Verifying
                    ) =>
                {
                    rt.defer_recovery_effect(effect);
                    continue;
                }
                _ => {
                    let suspended = {
                        let coordinator = rt.recovery_coordinator.lock();
                        coordinator.attempt().filter(|_| {
                            matches!(
                                coordinator.phase(),
                                RecoveryPhase::Certifying
                                    | RecoveryPhase::FetchingTerminalCheckpoint
                                    | RecoveryPhase::FetchingRepositorySnapshot
                            )
                        })
                    };
                    if let Some(attempt) = suspended {
                        rt.transition_recovery(RecoveryEvent::Cancel {
                            attempt,
                            now_ms: rt.recovery_now_ms(),
                        });
                    }
                    continue;
                }
            }
        }
        match effect {
            RecoveryEffect::Persist => {
                if !persist_attempt(rt).await {
                    return;
                }
            }
            RecoveryEffect::SendProbes { attempt } => {
                if {
                    let coordinator = rt.recovery_coordinator.lock();
                    coordinator.attempt() != Some(attempt)
                        || coordinator.phase() != RecoveryPhase::Certifying
                } {
                    continue;
                }
                for peer in rt.net.alive_members() {
                    if peer == rt.self_id {
                        continue;
                    }
                    let Some(epoch) = rt.net.member_boot_epoch(peer) else {
                        continue;
                    };
                    let nonce = {
                        let mut nonces = rt.recovery_v8.probe_nonces.lock();
                        *nonces
                            .entry((attempt, peer))
                            .or_insert_with(|| rt.recovery_v8.wire_id())
                    };
                    let body = StrictBody::RecoveryProbeReq(StrictRecoveryProbeReq {
                        context: Some(wire_context(
                            rt.self_id,
                            rt.boot_epoch,
                            attempt,
                            epoch,
                            None,
                        )),
                        request_nonce: nonce,
                    });
                    let _ = rt.net.send_redundant_unicast(peer, &rt.topic, body).await;
                }
            }
            RecoveryEffect::SendTransfer {
                attempt,
                donor,
                terminal_cut,
                kind,
            } => {
                let effect_is_current = {
                    let coordinator = rt.recovery_coordinator.lock();
                    coordinator.attempt() == Some(attempt)
                        && coordinator.donor() == Some(&donor)
                        && coordinator.representation_cut() == Some(&terminal_cut)
                        && matches!(
                            (coordinator.phase(), kind),
                            (
                                RecoveryPhase::FetchingTerminalCheckpoint,
                                TransferKind::TerminalCheckpoint
                            ) | (
                                RecoveryPhase::FetchingRepositorySnapshot,
                                TransferKind::RepositorySnapshot
                            )
                        )
                };
                if !effect_is_current {
                    continue;
                }
                let Some(target) = rt
                    .recovery_coordinator
                    .lock()
                    .certificate()
                    .map(|certificate| certificate.target().clone())
                else {
                    continue;
                };
                if kind == TransferKind::TerminalCheckpoint
                    && terminal_cut.generation() == 0
                    && complete_from_exact_local_image(rt, attempt, &donor, &target, &terminal_cut)
                        .await
                {
                    continue;
                }
                {
                    let mut clients = rt.recovery_v8.clients.lock();
                    // A terminal SendTransfer begins a newly certified
                    // representation session, even when recertification
                    // selects the same donor and cut. Retry effects bypass
                    // this path and retain the existing wire identity.
                    let replace = kind == TransferKind::TerminalCheckpoint
                        || clients.get(&attempt).is_none_or(|client| {
                            client.donor != donor || client.cut != journal_cut(&terminal_cut)
                        });
                    if replace {
                        clients.insert(
                            attempt,
                            ClientTransfer {
                                donor: donor.clone(),
                                target,
                                cut: journal_cut(&terminal_cut),
                                terminal_id: 0,
                                terminal_nonce: rt.recovery_v8.wire_id(),
                                terminal_cursor: 0,
                                terminal_states: Vec::new(),
                                snapshot_id: 0,
                                snapshot_nonce: rt.recovery_v8.wire_id(),
                                snapshot_cursor: 0,
                                snapshot_total: None,
                                snapshot_digest: None,
                                snapshot_bytes: Vec::new(),
                                staging: None,
                            },
                        );
                    }
                }
                let still_current = {
                    let coordinator = rt.recovery_coordinator.lock();
                    coordinator.attempt() == Some(attempt)
                        && coordinator.donor() == Some(&donor)
                        && coordinator.representation_cut() == Some(&terminal_cut)
                        && matches!(
                            (coordinator.phase(), kind),
                            (
                                RecoveryPhase::FetchingTerminalCheckpoint,
                                TransferKind::TerminalCheckpoint
                            ) | (
                                RecoveryPhase::FetchingRepositorySnapshot,
                                TransferKind::RepositorySnapshot
                            )
                        )
                };
                if !still_current {
                    continue;
                }
                match kind {
                    TransferKind::TerminalCheckpoint => send_terminal_request(rt, attempt).await,
                    TransferKind::RepositorySnapshot => send_snapshot_request(rt, attempt).await,
                }
            }
            RecoveryEffect::PrepareInstall {
                attempt,
                donor,
                terminal_cut,
            } => {
                prepare_install(rt, attempt, donor, terminal_cut).await;
            }
            RecoveryEffect::Install { attempt, donor } => {
                if {
                    let coordinator = rt.recovery_coordinator.lock();
                    coordinator.attempt() == Some(attempt)
                        && coordinator.phase() == RecoveryPhase::Installing
                        && coordinator.donor() == Some(&donor)
                } {
                    install(rt, attempt, donor).await;
                }
            }
            RecoveryEffect::Retry { attempt } => {
                let transfer = {
                    let coordinator = rt.recovery_coordinator.lock();
                    if coordinator.attempt() != Some(attempt) {
                        continue;
                    }
                    let kind = match coordinator.phase() {
                        RecoveryPhase::FetchingTerminalCheckpoint => {
                            TransferKind::TerminalCheckpoint
                        }
                        RecoveryPhase::FetchingRepositorySnapshot => {
                            TransferKind::RepositorySnapshot
                        }
                        _ => continue,
                    };
                    let Some(donor) = coordinator.donor().cloned() else {
                        continue;
                    };
                    let Some(terminal_cut) = coordinator.representation_cut().cloned() else {
                        continue;
                    };
                    (donor, terminal_cut, kind)
                };
                rt.recovery_v8.schedule_transfer_retry(
                    attempt,
                    transfer.0,
                    transfer.1,
                    transfer.2,
                    retry_now.unwrap_or_else(Instant::now),
                );
            }
            RecoveryEffect::Cleanup { attempt } => {
                let protected_staging_path = rt
                    .terminal_journal
                    .lock()
                    .await
                    .load_recovery_artifact_intent()
                    .ok()
                    .flatten()
                    .map(|intent| intent.staging_path().to_path_buf());
                rt.recovery_v8
                    .cleanup(attempt, protected_staging_path.as_deref());
            }
            RecoveryEffect::ClearCompletedAttempt { attempt } => {
                let attempt_id = durable_attempt_id(attempt);
                if let Err(error) = rt
                    .with_terminal_journal_mutation(move |journal| {
                        journal.clear_recovery_attempt(&attempt_id)
                    })
                    .await
                {
                    rt.record_terminal_journal_failure(&error);
                    return;
                }
            }
            RecoveryEffect::Metric(_) => {}
        }
    }
}

#[cfg(test)]
pub(super) async fn execute_effects_with_retry_clock_for_test<R: StrictReplicable>(
    rt: &std::sync::Arc<StrictRuntime<R>>,
    effects: Vec<RecoveryEffect>,
    retry_now: Instant,
) {
    execute_effects_with_retry_clock(rt, effects, Some(retry_now)).await;
}

/// Execute each coalesced same-wire retry at most once after its fixed delay.
/// The full certified transfer identity is revalidated at expiry so an old
/// retry can never send on behalf of a replacement donor or representation.
pub(super) async fn execute_due_transfer_retries<R: StrictReplicable>(
    rt: &std::sync::Arc<StrictRuntime<R>>,
    now: Instant,
) {
    for (attempt, retry) in rt.recovery_v8.take_due_transfer_retries(now) {
        let current = {
            let coordinator = rt.recovery_coordinator.lock();
            coordinator.attempt() == Some(attempt)
                && coordinator.donor() == Some(&retry.donor)
                && coordinator.representation_cut() == Some(&retry.terminal_cut)
                && matches!(
                    (coordinator.phase(), retry.kind),
                    (
                        RecoveryPhase::FetchingTerminalCheckpoint,
                        TransferKind::TerminalCheckpoint
                    ) | (
                        RecoveryPhase::FetchingRepositorySnapshot,
                        TransferKind::RepositorySnapshot
                    )
                )
        };
        if !current {
            continue;
        }
        match retry.kind {
            TransferKind::TerminalCheckpoint => send_terminal_request(rt, attempt).await,
            TransferKind::RepositorySnapshot => send_snapshot_request(rt, attempt).await,
        }
    }
}

pub(super) fn spawn_startup_rollforward<R: StrictReplicable>(rt: std::sync::Arc<StrictRuntime<R>>) {
    tokio::spawn(async move {
        let intent = {
            let journal = rt.terminal_journal.lock().await;
            match journal.load_recovery_artifact_intent() {
                Ok(intent) => intent,
                Err(error) => {
                    rt.record_terminal_journal_failure(&error);
                    schedule_startup_rollforward_retry(std::sync::Arc::clone(&rt));
                    return;
                }
            }
        };
        let phase = rt.recovery_coordinator.lock().phase();
        if intent.is_some() || phase == RecoveryPhase::Healthy {
            cleanup_orphaned_staging_artifacts(
                rt.as_ref(),
                intent.as_ref().map(|intent| intent.staging_path()),
            );
        }
        let Some(intent) = intent else {
            let _ = rt.request_pending_repository_install_recovery();
            return;
        };
        let Some(attempt) = attempt_from_bytes(intent.attempt_id()) else {
            if rt.recovery_coordinator.lock().phase() == RecoveryPhase::Healthy {
                let _ = rt.request_pending_repository_install_recovery();
            } else {
                schedule_startup_rollforward_retry(std::sync::Arc::clone(&rt));
            }
            return;
        };
        let Some(donor) = rt.recovery_coordinator.lock().donor().cloned() else {
            tracing::warn!(
                topic = %rt.topic,
                attempt_hi = attempt.hi(),
                attempt_lo = attempt.lo(),
                phase = ?rt.recovery_coordinator.lock().phase(),
                "strict startup recovery artifact has no matching durable donor; keeping the topic fenced and recertifying"
            );
            if rt.recovery_coordinator.lock().phase() == RecoveryPhase::Healthy {
                let _ = rt.request_pending_repository_install_recovery();
            } else {
                schedule_startup_rollforward_retry(std::sync::Arc::clone(&rt));
            }
            return;
        };
        if !rt.startup_recovery_install_is_current_and_quiescent(attempt) {
            schedule_startup_rollforward_retry(std::sync::Arc::clone(&rt));
            return;
        }
        let metadata = intent.repository_metadata();
        let expected_metadata = HistoryMetadata {
            version: metadata.version(),
            freshness: metadata.freshness(),
        };
        let cut = intent.terminal_cut();
        let terminal_prepared = rt.terminal_journal.lock().await.terminal_cut() == cut;
        if !terminal_prepared {
            rt.require_repository_image_install(expected_metadata);
            recertify_topic_after_local_recovery_failure(
                rt.as_ref(),
                "durable recovery artifact does not match its prepared terminal checkpoint",
            );
            return;
        }
        let expectation =
            RecoveryStagingExpectation::new(attempt.hi(), attempt.lo(), expected_metadata, cut);
        let manifest = RecoveryStagingManifest::new(
            expectation,
            intent.content_length(),
            *intent.content_digest(),
        );
        let Ok(artifact) = verify_recovery_staging_artifact(intent.staging_path(), manifest) else {
            rt.require_repository_image_install(expected_metadata);
            recertify_topic_after_local_recovery_failure(
                rt.as_ref(),
                "durable recovery staging artifact is missing or invalid",
            );
            return;
        };
        let Ok(decoded) = decode_s2s_snapshot_envelope(artifact.into_repository_image()) else {
            rt.require_repository_image_install(expected_metadata);
            recertify_topic_after_local_recovery_failure(
                rt.as_ref(),
                "durable recovery staging artifact has an invalid snapshot envelope",
            );
            return;
        };
        if decoded.terminal_cut != Some(cut) {
            rt.require_repository_image_install(expected_metadata);
            recertify_topic_after_local_recovery_failure(
                rt.as_ref(),
                "durable recovery snapshot envelope does not match its terminal checkpoint",
            );
            return;
        }
        if !delivery_checkpoint_is_valid(
            metadata.version(),
            &decoded.applied_operations,
            &decoded.retired_operations,
        ) {
            rt.require_repository_image_install(expected_metadata);
            recertify_topic_after_local_recovery_failure(
                rt.as_ref(),
                "durable recovery snapshot has an invalid delivery checkpoint",
            );
            return;
        }
        let staged_repository_snapshot = decoded.repository_snapshot;
        let expected_applied: BTreeMap<_, _> = decoded.applied_operations.into_iter().collect();
        let expected_retired = decoded.retired_operations;
        if !rt.begin_startup_authoritative_recovery_install(attempt) {
            schedule_startup_rollforward_retry(std::sync::Arc::clone(&rt));
            return;
        }
        if rt
            .install_authoritative_recovery_snapshot(metadata.version(), staged_repository_snapshot)
            .await
            .is_err()
        {
            rt.finish_authoritative_recovery_install();
            schedule_startup_rollforward_retry(std::sync::Arc::clone(&rt));
            return;
        }
        rt.replace_runtime_terminal_checkpoint(expected_applied.clone(), expected_retired.clone())
            .await;
        let terminal_cut_matches = rt.terminal_journal.lock().await.terminal_cut() == cut;
        if rt.repo.history_metadata() != expected_metadata
            || !terminal_cut_matches
            || !rt
                .installed_delivery_checkpoint_matches(&expected_applied, &expected_retired)
                .await
        {
            rt.finish_authoritative_recovery_install();
            schedule_startup_rollforward_retry(std::sync::Arc::clone(&rt));
            return;
        }
        let phase = rt.recovery_coordinator.lock().phase();
        if phase == super::recovery_reducer::RecoveryPhase::Installing {
            rt.transition_recovery(RecoveryEvent::Installed {
                attempt,
                donor: donor.clone(),
            });
        }
        if rt.recovery_coordinator.lock().phase()
            != super::recovery_reducer::RecoveryPhase::Verifying
        {
            rt.finish_authoritative_recovery_install();
            schedule_startup_rollforward_retry(std::sync::Arc::clone(&rt));
            return;
        }
        let Some(verifying_attempt) = durable_attempt(&rt) else {
            rt.finish_authoritative_recovery_install();
            schedule_startup_rollforward_retry(std::sync::Arc::clone(&rt));
            return;
        };
        if let Err(error) = rt
            .with_terminal_journal_mutation(move |journal| {
                journal.persist_recovery_attempt(&verifying_attempt)
            })
            .await
        {
            rt.record_terminal_journal_failure(&error);
            rt.finish_authoritative_recovery_install();
            schedule_startup_rollforward_retry(std::sync::Arc::clone(&rt));
            return;
        }
        let attempt_id = *intent.attempt_id();
        let completed = rt
            .with_terminal_journal_mutation(move |journal| {
                let Some(repository_intent) = journal.pending_repository_image_install() else {
                    return Ok(false);
                };
                journal
                    .finalize_recovery_install(&attempt_id, repository_intent, cut)
                    .map(|()| true)
            })
            .await;
        let completed = match completed {
            Ok(completed) => completed,
            Err(error) => {
                rt.record_terminal_journal_failure(&error);
                rt.finish_authoritative_recovery_install();
                schedule_startup_rollforward_retry(std::sync::Arc::clone(&rt));
                return;
            }
        };
        if completed {
            let _ = rt.finish_repository_image_install(expected_metadata);
            let _ = rt.finish_repository_base_install(expected_metadata.version);
            rt.transition_recovery(RecoveryEvent::Verified {
                attempt,
                donor,
                verification: Verification::new(
                    LogicalTarget::new(
                        expected_metadata.version,
                        expected_metadata.freshness,
                        *cut.terminal_set_digest(),
                    ),
                    reducer_cut(cut),
                ),
            });
            let _ = delete_recovery_staging_artifact(intent.staging_path());
            rt.finish_authoritative_recovery_install();
        } else {
            rt.finish_authoritative_recovery_install();
            schedule_startup_rollforward_retry(std::sync::Arc::clone(&rt));
        }
    });
}

fn schedule_startup_rollforward_retry<R: StrictReplicable>(rt: std::sync::Arc<StrictRuntime<R>>) {
    tokio::spawn(async move {
        tokio::time::sleep(rt.cfg.strict_bootstrap_retry_interval()).await;
        spawn_startup_rollforward(rt);
    });
}

fn attempt_from_bytes(bytes: &[u8; 16]) -> Option<RecoveryAttemptId> {
    Some(RecoveryAttemptId::new(
        u64::from_be_bytes(bytes[..8].try_into().ok()?),
        u64::from_be_bytes(bytes[8..].try_into().ok()?),
    ))
}

async fn prepare_install<R: StrictReplicable>(
    rt: &std::sync::Arc<StrictRuntime<R>>,
    attempt: RecoveryAttemptId,
    donor: ParticipantIncarnation,
    terminal_cut: ReducerCut,
) {
    let prepared = {
        let coordinator = rt.recovery_coordinator.lock();
        if coordinator.attempt() != Some(attempt)
            || coordinator.phase() != RecoveryPhase::FetchingRepositorySnapshot
            || coordinator.donor() != Some(&donor)
            || coordinator.representation_cut() != Some(&terminal_cut)
        {
            return;
        }
        let mut clients = rt.recovery_v8.clients.lock();
        let Some(client) = clients.get_mut(&attempt) else {
            return;
        };
        if client.donor != donor {
            return;
        }
        let Some((path, manifest)) = client.staging.clone() else {
            return;
        };
        let Ok(verified) = verify_recovery_staging_artifact(&path, manifest) else {
            return donor_failed(rt, attempt, donor, DonorFailure::RetryableFailure);
        };
        let Ok(decoded) = decode_s2s_snapshot_envelope(verified.into_repository_image()) else {
            return donor_failed(rt, attempt, donor, DonorFailure::RetryableFailure);
        };
        if decoded.terminal_cut != Some(client.cut) {
            return donor_failed(rt, attempt, donor, DonorFailure::TargetMoved);
        }
        if !delivery_checkpoint_is_valid(
            client.target.repository_version(),
            &decoded.applied_operations,
            &decoded.retired_operations,
        ) {
            return donor_failed(rt, attempt, donor, DonorFailure::RetryableFailure);
        }
        let Some(staged) = client
            .terminal_states
            .iter()
            .map(staged_terminal_decision)
            .collect::<Option<Vec<_>>>()
        else {
            return donor_failed(rt, attempt, donor, DonorFailure::RetryableFailure);
        };
        let applied = decoded.applied_operations.into_iter().collect();
        (
            client.target.clone(),
            client.cut,
            path,
            manifest,
            staged,
            applied,
            decoded.retired_operations,
        )
    };
    let (target, cut, path, manifest, staged, applied, retired) = prepared;
    if !transfer_response_is_current(
        rt,
        attempt,
        &donor,
        cut,
        RecoveryPhase::FetchingRepositorySnapshot,
    ) {
        return;
    }
    let Some(durable_attempt) =
        durable_attempt_for_phase(rt, Some(DurableRecoveryPhase::Installing))
    else {
        recertify_topic_after_local_recovery_failure(
            rt.as_ref(),
            "prepared recovery representation could not be encoded durably",
        );
        return;
    };
    let artifact_intent = DurableRecoveryArtifactIntent::new(
        durable_attempt_id(attempt),
        path,
        *manifest.content_digest(),
        manifest.content_len(),
        DurableRecoveryRepositoryMetadata::new(
            target.repository_version(),
            target.history_freshness(),
        ),
        cut,
    );
    let mutation_rt = std::sync::Arc::clone(rt);
    let mutation_donor = donor.clone();
    let result = rt
        .with_terminal_journal_mutation(move |journal| {
            let coordinator = mutation_rt.recovery_coordinator.lock();
            if coordinator.attempt() != Some(attempt)
                || coordinator.phase() != RecoveryPhase::FetchingRepositorySnapshot
                || coordinator.donor() != Some(&mutation_donor)
                || coordinator.representation_cut().map(journal_cut) != Some(cut)
            {
                return None;
            }
            Some(journal.prepare_staged_recovery_checkpoint(
                target.repository_version(),
                target.history_freshness(),
                cut,
                &staged,
                &applied,
                &retired,
                &durable_attempt,
                &artifact_intent,
            ))
        })
        .await;
    match result {
        Some(Ok(_)) => {
            rt.suppress_checkpoint_for_current_terminal_representation()
                .await;
            rt.transition_recovery(RecoveryEvent::Prepared {
                attempt,
                donor: donor.clone(),
            });
            rt.transition_recovery(RecoveryEvent::InstallStarted { attempt, donor });
        }
        Some(Err(error)) => rt.record_terminal_journal_failure(&error),
        None => {}
    }
}

async fn install<R: StrictReplicable>(
    rt: &std::sync::Arc<StrictRuntime<R>>,
    attempt: RecoveryAttemptId,
    donor: ParticipantIncarnation,
) {
    let (path, manifest, target, cut, applied, retired) = {
        let coordinator = rt.recovery_coordinator.lock();
        if coordinator.attempt() != Some(attempt)
            || coordinator.phase() != RecoveryPhase::Installing
            || coordinator.donor() != Some(&donor)
        {
            return;
        }
        let clients = rt.recovery_v8.clients.lock();
        let Some(client) = clients.get(&attempt) else {
            schedule_local_install_retry(rt, attempt, donor);
            return;
        };
        if client.donor != donor {
            return;
        }
        let Some((path, manifest)) = client.staging.clone() else {
            schedule_local_install_retry(rt, attempt, donor);
            return;
        };
        let Ok(verified) = verify_recovery_staging_artifact(&path, manifest) else {
            schedule_local_install_retry(rt, attempt, donor);
            return;
        };
        let Ok(decoded) = decode_s2s_snapshot_envelope(verified.into_repository_image()) else {
            schedule_local_install_retry(rt, attempt, donor);
            return;
        };
        if decoded.terminal_cut != Some(client.cut) {
            schedule_local_install_retry(rt, attempt, donor);
            return;
        }
        if !delivery_checkpoint_is_valid(
            client.target.repository_version(),
            &decoded.applied_operations,
            &decoded.retired_operations,
        ) {
            schedule_local_install_retry(rt, attempt, donor);
            return;
        }
        (
            path,
            manifest,
            client.target.clone(),
            client.cut,
            decoded
                .applied_operations
                .into_iter()
                .collect::<BTreeMap<_, _>>(),
            decoded.retired_operations,
        )
    };
    let Ok(verified) = verify_recovery_staging_artifact(&path, manifest) else {
        schedule_local_install_retry(rt, attempt, donor);
        return;
    };
    let Ok(decoded) = decode_s2s_snapshot_envelope(verified.into_repository_image()) else {
        schedule_local_install_retry(rt, attempt, donor);
        return;
    };
    if !rt.begin_authoritative_recovery_install(attempt, &donor) {
        return;
    }
    let staged_repository_snapshot = decoded.repository_snapshot;
    if rt
        .install_authoritative_recovery_snapshot(
            target.repository_version(),
            staged_repository_snapshot,
        )
        .await
        .is_err()
    {
        rt.finish_authoritative_recovery_install();
        schedule_local_install_retry(rt, attempt, donor);
        return;
    }
    rt.replace_runtime_terminal_checkpoint(applied.clone(), retired.clone())
        .await;
    let expected_metadata = HistoryMetadata {
        version: target.repository_version(),
        freshness: target.history_freshness(),
    };
    let terminal_cut_matches = rt.terminal_journal.lock().await.terminal_cut() == cut;
    let verified = rt.repo.history_metadata() == expected_metadata
        && terminal_cut_matches
        && rt
            .installed_delivery_checkpoint_matches(&applied, &retired)
            .await;
    if !verified {
        rt.finish_authoritative_recovery_install();
        schedule_local_install_retry(rt, attempt, donor);
        return;
    }
    rt.transition_recovery(RecoveryEvent::Installed {
        attempt,
        donor: donor.clone(),
    });
    finalize_install(rt, attempt, donor).await;
}

fn schedule_local_install_retry<R: StrictReplicable>(
    rt: &std::sync::Arc<StrictRuntime<R>>,
    attempt: RecoveryAttemptId,
    donor: ParticipantIncarnation,
) {
    let rt = std::sync::Arc::clone(rt);
    tokio::spawn(async move {
        tokio::time::sleep(rt.cfg.strict_bootstrap_retry_interval()).await;
        let phase = {
            let coordinator = rt.recovery_coordinator.lock();
            if coordinator.attempt() != Some(attempt) || coordinator.donor() != Some(&donor) {
                return;
            }
            coordinator.phase()
        };
        match phase {
            RecoveryPhase::Installing => install(&rt, attempt, donor).await,
            RecoveryPhase::Verifying => finalize_install(&rt, attempt, donor).await,
            _ => {}
        }
    });
}

async fn finalize_install<R: StrictReplicable>(
    rt: &std::sync::Arc<StrictRuntime<R>>,
    attempt: RecoveryAttemptId,
    donor: ParticipantIncarnation,
) {
    let (path, manifest, target, cut) = {
        let coordinator = rt.recovery_coordinator.lock();
        if coordinator.attempt() != Some(attempt)
            || coordinator.phase() != RecoveryPhase::Verifying
            || coordinator.donor() != Some(&donor)
        {
            rt.finish_authoritative_recovery_install();
            return;
        }
        let clients = rt.recovery_v8.clients.lock();
        let Some(client) = clients.get(&attempt) else {
            rt.finish_authoritative_recovery_install();
            schedule_local_install_retry(rt, attempt, donor);
            return;
        };
        let Some((path, manifest)) = client.staging.clone() else {
            rt.finish_authoritative_recovery_install();
            schedule_local_install_retry(rt, attempt, donor);
            return;
        };
        (path, manifest, client.target.clone(), client.cut)
    };
    let expected_metadata = HistoryMetadata {
        version: target.repository_version(),
        freshness: target.history_freshness(),
    };
    let Ok(verified_artifact) = verify_recovery_staging_artifact(&path, manifest) else {
        rt.finish_authoritative_recovery_install();
        schedule_local_install_retry(rt, attempt, donor);
        return;
    };
    let Ok(decoded) = decode_s2s_snapshot_envelope(verified_artifact.into_repository_image())
    else {
        rt.finish_authoritative_recovery_install();
        schedule_local_install_retry(rt, attempt, donor);
        return;
    };
    if !delivery_checkpoint_is_valid(
        target.repository_version(),
        &decoded.applied_operations,
        &decoded.retired_operations,
    ) {
        rt.finish_authoritative_recovery_install();
        schedule_local_install_retry(rt, attempt, donor);
        return;
    }
    let expected_applied: BTreeMap<_, _> = decoded.applied_operations.into_iter().collect();
    let expected_retired = decoded.retired_operations;
    let terminal_cut_matches = rt.terminal_journal.lock().await.terminal_cut() == cut;
    if decoded.terminal_cut != Some(cut)
        || rt.repo.history_metadata() != expected_metadata
        || !terminal_cut_matches
        || !rt
            .installed_delivery_checkpoint_matches(&expected_applied, &expected_retired)
            .await
    {
        rt.finish_authoritative_recovery_install();
        schedule_local_install_retry(rt, attempt, donor);
        return;
    }
    let Some(verifying_attempt) = durable_attempt(rt) else {
        rt.finish_authoritative_recovery_install();
        schedule_local_install_retry(rt, attempt, donor);
        return;
    };
    if let Err(error) = rt
        .with_terminal_journal_mutation(move |journal| {
            journal.persist_recovery_attempt(&verifying_attempt)
        })
        .await
    {
        rt.record_terminal_journal_failure(&error);
        rt.finish_authoritative_recovery_install();
        schedule_local_install_retry(rt, attempt, donor);
        return;
    }
    let attempt_id = durable_attempt_id(attempt);
    let finalized = rt
        .with_terminal_journal_mutation(move |journal| {
            let Some(intent) = journal.pending_repository_image_install() else {
                return Ok(false);
            };
            journal
                .finalize_recovery_install(&attempt_id, intent, cut)
                .map(|()| true)
        })
        .await;
    let finalized = match finalized {
        Ok(finalized) => finalized,
        Err(error) => {
            rt.record_terminal_journal_failure(&error);
            rt.finish_authoritative_recovery_install();
            schedule_local_install_retry(rt, attempt, donor);
            return;
        }
    };
    if finalized {
        let _ = rt.finish_repository_image_install(expected_metadata);
        let _ = rt.finish_repository_base_install(expected_metadata.version);
        rt.transition_recovery(RecoveryEvent::Verified {
            attempt,
            donor,
            verification: Verification::new(target, reducer_cut(cut)),
        });
        let _ = delete_recovery_staging_artifact(&path);
        rt.recovery_v8.clients.lock().remove(&attempt);
        rt.finish_authoritative_recovery_install();
    } else {
        rt.finish_authoritative_recovery_install();
        schedule_local_install_retry(rt, attempt, donor);
    }
}

fn donor_failed<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    attempt: RecoveryAttemptId,
    donor: ParticipantIncarnation,
    failure: DonorFailure,
) {
    rt.transition_recovery(RecoveryEvent::DonorFailed {
        attempt,
        donor,
        failure,
        now_ms: rt.recovery_now_ms(),
    });
}

fn transfer_response_is_current<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    attempt: RecoveryAttemptId,
    donor: &ParticipantIncarnation,
    cut: TerminalCut,
    phase: RecoveryPhase,
) -> bool {
    let coordinator = rt.recovery_coordinator.lock();
    coordinator.attempt() == Some(attempt)
        && coordinator.phase() == phase
        && coordinator.donor() == Some(donor)
        && coordinator.representation_cut().map(journal_cut) == Some(cut)
}

async fn send_recovery_bulk_page<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    destination: NodeIdentifier,
    key: &ServerKey,
    body: StrictBody,
) -> Result<(), ReplicationError> {
    loop {
        let page_is_live = match &body {
            StrictBody::RecoveryTerminalPage(page) => rt
                .recovery_v8
                .server_terminals
                .lock()
                .get(key)
                .is_some_and(|terminal| {
                    terminal
                        .pending_pages
                        .contains_key(&(page.transfer_id, page.request_nonce))
                }),
            StrictBody::RecoverySnapshotPage(page) => rt
                .recovery_v8
                .server_snapshots
                .lock()
                .get(key)
                .is_some_and(|snapshot| {
                    snapshot
                        .pending_pages
                        .contains_key(&(page.transfer_id, page.request_nonce))
                }),
            _ => false,
        };
        if !page_is_live {
            return Ok(());
        }
        match rt
            .net
            .send_bulk_unicast(
                destination,
                &rt.topic,
                body.clone(),
                rt.cfg.strict_bootstrap_retry_interval(),
            )
            .await
        {
            Err(ReplicationError::StrictBulkAdmissionBusy { retry_after }) => {
                // Local scheduler pressure is not a remote protocol failure.
                // Retain the immutable page identity and honor the pacer's
                // exact delay without a durable failure round trip.
                tokio::select! {
                    _ = rt.shutdown.cancelled() => return Ok(()),
                    _ = tokio::time::sleep(retry_after) => {}
                }
            }
            result => return result,
        }
    }
}

fn take_implicit_terminal_continuation_ack<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    key: &ServerKey,
    target: &LogicalTarget,
    cut: TerminalCut,
    transfer_id: u64,
    expected_cursor: u64,
) -> Option<BulkPageIdentity> {
    if transfer_id == 0 || expected_cursor == 0 {
        return None;
    }
    let mut terminals = rt.recovery_v8.server_terminals.lock();
    let terminal = terminals.get_mut(key)?;
    if terminal.donor_epoch != rt.boot_epoch
        || &terminal.target != target
        || terminal.cut != cut
        || terminal.transfer_id != transfer_id
    {
        return None;
    }
    let identity =
        terminal
            .pending_pages
            .iter()
            .find_map(|(&(candidate_transfer, nonce), pending)| {
                (candidate_transfer == transfer_id
                    && !pending.final_page
                    && pending.next_cursor == expected_cursor)
                    .then_some((candidate_transfer, nonce))
            })?;
    terminal.pending_pages.remove(&identity)?;
    terminal.last_authenticated_activity = Instant::now();
    Some(BulkPageIdentity::recovery_terminal(identity.0, identity.1))
}

fn take_implicit_snapshot_continuation_ack<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    key: &ServerKey,
    target: &LogicalTarget,
    cut: TerminalCut,
    transfer_id: u64,
    expected_cursor: u64,
) -> Option<BulkPageIdentity> {
    if transfer_id == 0 || expected_cursor == 0 {
        return None;
    }
    let mut snapshots = rt.recovery_v8.server_snapshots.lock();
    let snapshot = snapshots.get_mut(key)?;
    if snapshot.donor_epoch != rt.boot_epoch
        || &snapshot.target != target
        || snapshot.cut != cut
        || snapshot.transfer_id != transfer_id
    {
        return None;
    }
    let identity =
        snapshot
            .pending_pages
            .iter()
            .find_map(|(&(candidate_transfer, nonce), pending)| {
                (candidate_transfer == transfer_id
                    && !pending.final_page
                    && pending.next_cursor == expected_cursor)
                    .then_some((candidate_transfer, nonce))
            })?;
    snapshot.pending_pages.remove(&identity)?;
    snapshot.last_authenticated_activity = Instant::now();
    Some(BulkPageIdentity::recovery_snapshot(identity.0, identity.1))
}

fn yield_generation_zero_audit_for_attested_transfer<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    key: &ServerKey,
    target: &LogicalTarget,
    cut: TerminalCut,
) -> bool {
    // Concurrent generation-zero audits must not yield to one another in a
    // cycle. The older incarnation, then lower node id, is the deterministic
    // representation donor and yields its network-only audit to a requester
    // below it in that same history-rank order.
    if (rt.boot_epoch, rt.self_id) >= (key.requester_epoch, key.requester) {
        return false;
    }
    let attested = rt
        .recovery_v8
        .served_probe_attestations
        .lock()
        .get(key)
        .is_some_and(|attested| attested.target == *target && attested.cut == cut);
    if !attested {
        return false;
    }
    let Some(local_attempt) = *rt.recovery_v8.active_generation_zero_audit.lock() else {
        return false;
    };
    let can_yield = {
        let coordinator = rt.recovery_coordinator.lock();
        coordinator.attempt() == Some(local_attempt)
            && matches!(
                coordinator.phase(),
                RecoveryPhase::Certifying
                    | RecoveryPhase::FetchingTerminalCheckpoint
                    | RecoveryPhase::FetchingRepositorySnapshot
                    | RecoveryPhase::Backoff
            )
    };
    if !can_yield {
        return false;
    }
    rt.transition_recovery(RecoveryEvent::AuditYield {
        attempt: local_attempt,
    });
    if rt.recovery_is_healthy() {
        *rt.recovery_v8.active_generation_zero_audit.lock() = None;
    }
    *rt.recovery_v8.generation_zero_audit_deferred_until.lock() =
        Some(Instant::now() + Duration::from_secs(30));
    rt.recovery_is_healthy()
}

pub(super) async fn recv_probe_req<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    authenticated: bool,
    request: StrictRecoveryProbeReq,
) {
    let Some(request_wire_context) = request.context.as_ref() else {
        return;
    };
    let Some(attempt) = authenticated
        .then(|| request_context(rt, from, epoch, request_wire_context))
        .flatten()
    else {
        return;
    };
    if request.request_nonce == 0 {
        return;
    }
    let (metadata, cut) = rt.recovery_advertised_head().await;
    let target = LogicalTarget::new(
        metadata.version,
        metadata.freshness,
        *cut.terminal_set_digest(),
    );
    // Certification is read-only evidence, not source admission or snapshot
    // donation. A participant may attest its current published head while it
    // is itself certifying; exact transfer requests remain fenced below until
    // the selected donor is Healthy. This prevents concurrent foreign-lineage
    // attempts from withholding every quorum witness from one another.
    let status = if request_wire_context.expected_donor_boot_epoch != rt.boot_epoch {
        StrictRecoveryStatus::IncarnationMismatch
    } else if !rt.recovery_v8_capability_ready() {
        StrictRecoveryStatus::RetryableFailure
    } else {
        StrictRecoveryStatus::Ok
    };
    let body = StrictBody::RecoveryProbeResp(StrictRecoveryProbeResp {
        context: Some(wire_context(
            from,
            epoch,
            attempt,
            rt.boot_epoch,
            Some(&target),
        )),
        responder_node: rt.self_id as u32,
        responder_boot_epoch: rt.boot_epoch,
        request_nonce: request.request_nonce,
        status: status.into(),
        terminal_cut: Some(cut_to_wire(cut)),
        runtime_started_at: rt.boot_epoch,
        history_node: rt.self_id as u32,
    });
    let attestation_key = ServerKey {
        requester: from,
        requester_epoch: epoch,
        attempt,
    };
    let attestation = ServerAttestation {
        target,
        cut,
        last_authenticated_activity: Instant::now(),
    };
    let previous_attestation = if status == StrictRecoveryStatus::Ok {
        let mut attestations = rt.recovery_v8.served_probe_attestations.lock();
        attestations.retain(|key, _| {
            key.requester != from || key.requester_epoch != epoch || key.attempt == attempt
        });
        attestations.insert(attestation_key.clone(), attestation.clone())
    } else {
        None
    };
    if rt
        .net
        .send_redundant_unicast(from, &rt.topic, body)
        .await
        .is_err()
        && status == StrictRecoveryStatus::Ok
    {
        let mut attestations = rt.recovery_v8.served_probe_attestations.lock();
        if attestations.get(&attestation_key).is_some_and(|current| {
            current.target == attestation.target && current.cut == attestation.cut
        }) {
            if let Some(previous) = previous_attestation {
                attestations.insert(attestation_key, previous);
            } else {
                attestations.remove(&attestation_key);
            }
        }
    }
}

pub(super) fn recv_probe_resp<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    authenticated: bool,
    response: StrictRecoveryProbeResp,
) {
    let Some(context) = response.context.as_ref() else {
        return;
    };
    let Some(attempt) = authenticated
        .then(|| response_context(rt, from, epoch, context))
        .flatten()
    else {
        return;
    };
    if node_from_u32(response.responder_node) != Some(from)
        || response.responder_boot_epoch != epoch
        || rt
            .recovery_v8
            .probe_nonces
            .lock()
            .get(&(attempt, from))
            .copied()
            != Some(response.request_nonce)
        || StrictRecoveryStatus::try_from(response.status).ok() != Some(StrictRecoveryStatus::Ok)
    {
        return;
    }
    let (Some(target), Some(cut)) = (
        context.target.as_ref().and_then(target_from_wire),
        response.terminal_cut.as_ref().and_then(cut_from_wire),
    ) else {
        return;
    };
    if target.terminal_set_digest() != cut.terminal_set_digest() {
        return;
    }
    rt.transition_recovery(RecoveryEvent::ProbeResponse {
        attempt,
        attestation: RecoveryAttestation::new(
            ParticipantIncarnation::new(u64::from(from), epoch),
            target,
            reducer_cut(cut),
            u64::MAX.saturating_sub(response.runtime_started_at),
        ),
        authenticated: true,
        now_ms: rt.recovery_now_ms(),
    });
}

pub(super) async fn recv_terminal_req<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    authenticated: bool,
    request: StrictRecoveryTerminalReq,
) {
    let (Some(context), Some(wire_cut)) = (request.context.as_ref(), request.target_cut.as_ref())
    else {
        recovery_terminal_trace!(
            "donor={} rejected requester={} epoch={} reason=missing_context_or_cut",
            rt.self_id,
            from,
            epoch
        );
        return;
    };
    let Some(attempt) = authenticated
        .then(|| request_context(rt, from, epoch, context))
        .flatten()
    else {
        recovery_terminal_trace!(
            "donor={} rejected requester={} epoch={} reason=authentication_or_context",
            rt.self_id,
            from,
            epoch
        );
        return;
    };
    if request.request_nonce == 0 || (request.transfer_id == 0) != (request.expected_cursor == 0) {
        recovery_terminal_trace!(
            "donor={} attempt={attempt:?} rejected requester={} reason=wire_identity transfer={} nonce={} cursor={}",
            rt.self_id,
            from,
            request.transfer_id,
            request.request_nonce,
            request.expected_cursor
        );
        return;
    }
    let Some(target) = context.target.as_ref().and_then(target_from_wire) else {
        recovery_terminal_trace!(
            "donor={} attempt={attempt:?} rejected requester={} reason=invalid_target",
            rt.self_id,
            from
        );
        return;
    };
    let Some(cut) = cut_from_wire(wire_cut) else {
        recovery_terminal_trace!(
            "donor={} attempt={attempt:?} rejected requester={} reason=invalid_cut",
            rt.self_id,
            from
        );
        return;
    };
    let server_key = ServerKey {
        requester: from,
        requester_epoch: epoch,
        attempt,
    };
    let attestation_status = {
        let attestations = rt.recovery_v8.served_probe_attestations.lock();
        match attestations.get(&server_key) {
            Some(attested) if attested.target == target && attested.cut == cut => {
                StrictRecoveryStatus::Ok
            }
            Some(_) => StrictRecoveryStatus::TargetMoved,
            None => StrictRecoveryStatus::RetryableFailure,
        }
    };
    if attestation_status == StrictRecoveryStatus::Ok {
        if let Some(page) = take_implicit_terminal_continuation_ack(
            rt,
            &server_key,
            &target,
            cut,
            request.transfer_id,
            request.expected_cursor,
        ) {
            rt.net.acknowledge_bulk_unicast(from, &rt.topic, page);
        }
        let _ = yield_generation_zero_audit_for_attested_transfer(rt, &server_key, &target, cut);
    }
    let recovery_callback_token = rt.recovery_callback_token();
    let (metadata, current_cut) = rt.recovery_advertised_head().await;
    let incarnation_matches = context.expected_donor_boot_epoch == rt.boot_epoch;
    let callback_is_current = rt.recovery_callback_is_current(recovery_callback_token);
    let head_is_exact = metadata.version == target.repository_version()
        && metadata.freshness == target.history_freshness()
        && current_cut == cut;
    let transfer_id = if request.transfer_id == 0 {
        terminal_transfer_id(attempt, rt.boot_epoch)
    } else {
        request.transfer_id
    };
    let terminal_page = |status: StrictRecoveryStatus,
                         checkpoint_states: Vec<StrictTerminalState>,
                         next_cursor: u64,
                         has_more: bool| StrictRecoveryTerminalPage {
        context: Some(wire_context(
            from,
            epoch,
            attempt,
            rt.boot_epoch,
            Some(&target),
        )),
        responder_node: rt.self_id as u32,
        responder_boot_epoch: rt.boot_epoch,
        status: status.into(),
        target_cut: Some(cut_to_wire(cut)),
        transfer_id,
        request_nonce: request.request_nonce,
        cursor: request.expected_cursor,
        next_cursor,
        checkpoint_digest: Bytes::copy_from_slice(cut.terminal_set_digest()),
        checkpoint_states,
        has_more,
    };
    let (mut status, mut states, mut next_cursor, mut has_more, mut status_reason) =
        if !incarnation_matches {
            (
                StrictRecoveryStatus::IncarnationMismatch,
                Vec::new(),
                request.expected_cursor,
                false,
                "incarnation_mismatch",
            )
        } else if attestation_status != StrictRecoveryStatus::Ok {
            (
                attestation_status,
                Vec::new(),
                request.expected_cursor,
                false,
                "missing_or_moved_attestation",
            )
        } else if !head_is_exact {
            (
                StrictRecoveryStatus::TargetMoved,
                Vec::new(),
                request.expected_cursor,
                false,
                "target_moved",
            )
        } else if !callback_is_current {
            (
                StrictRecoveryStatus::RetryableFailure,
                Vec::new(),
                request.expected_cursor,
                false,
                "callback_invalid_before_journal_read",
            )
        } else {
            let journal = rt.terminal_journal.lock().await;
            match journal.terminal_checkpoint_page_at(
                &cut,
                request.expected_cursor,
                rt.cfg.strict_max_catchup_ops(),
            ) {
                Some(page) => 'page: {
                    let cursor = page.cursor();
                    let mut next = cursor;
                    let mut states = Vec::new();
                    let byte_limit = rt.strict_catchup_response_budget();
                    for entry in page.into_entries() {
                        let (op_id, record) = entry.into_parts();
                        let Some(state) =
                            StrictRuntime::<R>::terminal_state_from_journal_record(op_id, &record)
                        else {
                            break 'page (
                                StrictRecoveryStatus::RetryableFailure,
                                Vec::new(),
                                request.expected_cursor,
                                false,
                                "terminal_record_conversion",
                            );
                        };
                        states.push(state);
                        let candidate_next = cursor.saturating_add(states.len() as u64);
                        let candidate = terminal_page(
                            StrictRecoveryStatus::Ok,
                            states.clone(),
                            candidate_next,
                            candidate_next < cut.generation(),
                        );
                        let fits = rt
                            .strict_replication_payload_len(&StrictBody::RecoveryTerminalPage(
                                candidate,
                            ))
                            .is_ok_and(|encoded| encoded <= byte_limit);
                        if !fits {
                            states.pop();
                            if states.is_empty() {
                                break 'page (
                                    StrictRecoveryStatus::ResourceLimit,
                                    Vec::new(),
                                    cursor,
                                    false,
                                    "single_state_exceeds_page_budget",
                                );
                            }
                            break;
                        }
                        next = candidate_next;
                    }
                    (
                        StrictRecoveryStatus::Ok,
                        states,
                        next,
                        next < cut.generation(),
                        "ok",
                    )
                }
                None => (
                    StrictRecoveryStatus::TargetMoved,
                    Vec::new(),
                    request.expected_cursor,
                    false,
                    "checkpoint_cut_unavailable",
                ),
            }
        };
    if status == StrictRecoveryStatus::Ok
        && !rt.recovery_callback_is_current(recovery_callback_token)
    {
        status = StrictRecoveryStatus::RetryableFailure;
        states.clear();
        next_cursor = request.expected_cursor;
        has_more = false;
        status_reason = "callback_invalid_after_journal_read";
    }
    let page = terminal_page(status, states, next_cursor, has_more);
    let body = StrictBody::RecoveryTerminalPage(page);
    let retryable_failure = match &body {
        StrictBody::RecoveryTerminalPage(page) if status == StrictRecoveryStatus::Ok => {
            let mut failure = page.clone();
            failure.status = StrictRecoveryStatus::RetryableFailure.into();
            failure.next_cursor = failure.cursor;
            failure.checkpoint_states.clear();
            failure.has_more = false;
            Some(StrictBody::RecoveryTerminalPage(failure))
        }
        _ => None,
    };
    let mut newly_registered = false;
    if status == StrictRecoveryStatus::Ok {
        let pending = ServerPageAck {
            next_cursor,
            final_page: !has_more,
        };
        let (registered, registered_now) = {
            let mut terminals = rt.recovery_v8.server_terminals.lock();
            if let Some(terminal) = terminals.get_mut(&server_key) {
                if terminal.donor_epoch != rt.boot_epoch
                    || terminal.target != target
                    || terminal.cut != cut
                    || terminal.transfer_id != transfer_id
                {
                    (false, false)
                } else {
                    match terminal
                        .pending_pages
                        .get(&(transfer_id, request.request_nonce))
                    {
                        Some(existing) if *existing == pending => {
                            terminal.last_authenticated_activity = Instant::now();
                            (true, false)
                        }
                        Some(_) => (false, false),
                        None => {
                            terminal
                                .pending_pages
                                .insert((transfer_id, request.request_nonce), pending);
                            terminal.last_authenticated_activity = Instant::now();
                            (true, true)
                        }
                    }
                }
            } else {
                terminals.insert(
                    server_key.clone(),
                    ServerTerminal {
                        donor_epoch: rt.boot_epoch,
                        target: target.clone(),
                        cut,
                        transfer_id,
                        pending_pages: HashMap::from([(
                            (transfer_id, request.request_nonce),
                            pending,
                        )]),
                        last_authenticated_activity: Instant::now(),
                    },
                );
                (true, true)
            }
        };
        if !registered {
            return;
        }
        newly_registered = registered_now;
        sync_donor_session_metrics(rt);
        refresh_exact_attestation(rt, &server_key, &target, cut);
    }
    let trace_boundary =
        request.expected_cursor == 0 || !has_more || status != StrictRecoveryStatus::Ok;
    if trace_boundary {
        recovery_terminal_trace!(
            "donor={} requester={} attempt={attempt:?} donor_epoch={} status={status:?} reason={status_reason} transfer={} nonce={} cursor={} next_cursor={} states={} has_more={} encoded={:?} budget={}",
            rt.self_id,
            from,
            rt.boot_epoch,
            transfer_id,
            request.request_nonce,
            request.expected_cursor,
            next_cursor,
            match &body {
                StrictBody::RecoveryTerminalPage(page) => page.checkpoint_states.len(),
                _ => 0,
            },
            has_more,
            rt.strict_replication_payload_len(&body),
            rt.strict_catchup_response_budget(),
        );
    }
    let sent = if status == StrictRecoveryStatus::Ok {
        send_recovery_bulk_page(rt, from, &server_key, body).await
    } else {
        // Status-only responses do not carry operation data and are never
        // acknowledged as bulk pages. Keep them off the bulk reservation so
        // retrying the same wire identity remains possible.
        rt.net.send_redundant_unicast(from, &rt.topic, body).await
    };
    if trace_boundary {
        recovery_terminal_trace!(
            "donor={} requester={} attempt={attempt:?} status={status:?} send={sent:?}",
            rt.self_id,
            from,
        );
    }
    if sent.is_err()
        && let Some(retryable_failure) = retryable_failure
    {
        if newly_registered {
            let mut terminals = rt.recovery_v8.server_terminals.lock();
            if let Some(terminal) = terminals.get_mut(&server_key) {
                terminal
                    .pending_pages
                    .remove(&(transfer_id, request.request_nonce));
            }
        }
        // A failed bulk enqueue has no acknowledged reservation. Report the
        // exact page identity on the control lane so the requester can retain
        // its cursor and immediately retry the same request identity.
        let _retry_sent = rt
            .net
            .send_redundant_unicast(from, &rt.topic, retryable_failure)
            .await;
        recovery_terminal_trace!(
            "donor={} requester={} attempt={attempt:?} status={:?} retry_status_send={_retry_sent:?}",
            rt.self_id,
            from,
            StrictRecoveryStatus::RetryableFailure,
        );
    }
}

pub(super) async fn recv_terminal_page<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    authenticated: bool,
    page: StrictRecoveryTerminalPage,
) {
    let Some(context) = page.context.as_ref() else {
        recovery_terminal_trace!(
            "requester={} rejected responder={} epoch={} reason=missing_context",
            rt.self_id,
            from,
            epoch
        );
        return;
    };
    let Some(attempt) = authenticated
        .then(|| response_context(rt, from, epoch, context))
        .flatten()
    else {
        recovery_terminal_trace!(
            "requester={} rejected responder={} epoch={} reason=authentication_or_context",
            rt.self_id,
            from,
            epoch
        );
        return;
    };
    let Some(status) = StrictRecoveryStatus::try_from(page.status).ok() else {
        recovery_terminal_trace!(
            "requester={} attempt={attempt:?} rejected responder={} reason=invalid_status value={}",
            rt.self_id,
            from,
            page.status
        );
        return;
    };
    if node_from_u32(page.responder_node) != Some(from) || page.responder_boot_epoch != epoch {
        recovery_terminal_trace!(
            "requester={} attempt={attempt:?} rejected responder={} reason=responder_incarnation wire_node={} wire_epoch={} authenticated_epoch={}",
            rt.self_id,
            from,
            page.responder_node,
            page.responder_boot_epoch,
            epoch
        );
        return;
    }
    let Some(page_cut) = page.target_cut.as_ref().and_then(cut_from_wire) else {
        recovery_terminal_trace!(
            "requester={} attempt={attempt:?} rejected responder={} reason=invalid_cut",
            rt.self_id,
            from
        );
        return;
    };
    let donor = ParticipantIncarnation::new(u64::from(from), epoch);
    let correlation = {
        let coordinator = rt.recovery_coordinator.lock();
        if coordinator.attempt() != Some(attempt)
            || coordinator.phase() != RecoveryPhase::FetchingTerminalCheckpoint
            || coordinator.donor() != Some(&donor)
            || coordinator.representation_cut().map(journal_cut) != Some(page_cut)
        {
            recovery_terminal_trace!(
                "requester={} attempt={attempt:?} rejected responder={} status={status:?} reason=coordinator expected_attempt={:?} phase={:?} expected_donor={:?} cut_matches={}",
                rt.self_id,
                from,
                coordinator.attempt(),
                coordinator.phase(),
                coordinator.donor(),
                coordinator.representation_cut().map(journal_cut) == Some(page_cut)
            );
            return;
        }
        let clients = rt.recovery_v8.clients.lock();
        let Some(client) = clients.get(&attempt) else {
            recovery_terminal_trace!(
                "requester={} attempt={attempt:?} rejected responder={} status={status:?} reason=missing_client",
                rt.self_id,
                from
            );
            return;
        };
        if context.target.as_ref().and_then(target_from_wire).as_ref() != Some(&client.target)
            || client.donor != donor
            || client.cut != page_cut
            || page.transfer_id == 0
            || (client.terminal_id != 0 && page.transfer_id != client.terminal_id)
        {
            0
        } else if page.request_nonce == client.terminal_nonce
            && page.cursor == client.terminal_cursor
        {
            1
        } else {
            let start = usize::try_from(page.cursor).unwrap_or(usize::MAX);
            let end = usize::try_from(page.next_cursor).unwrap_or(usize::MAX);
            if end <= client.terminal_states.len()
                && start <= end
                && client.terminal_states[start..end] == page.checkpoint_states
            {
                2
            } else {
                0
            }
        }
    };
    if correlation == 0 {
        recovery_terminal_trace!(
            "requester={} responder={} attempt={attempt:?} status={status:?} rejected reason=correlation transfer={} nonce={} cursor={} next_cursor={} states={} has_more={}",
            rt.self_id,
            from,
            page.transfer_id,
            page.request_nonce,
            page.cursor,
            page.next_cursor,
            page.checkpoint_states.len(),
            page.has_more
        );
        return;
    }
    if page.cursor == 0 || !page.has_more || correlation != 1 {
        recovery_terminal_trace!(
            "requester={} responder={} attempt={attempt:?} status={status:?} accepted_correlation={} transfer={} nonce={} cursor={} next_cursor={} states={} has_more={}",
            rt.self_id,
            from,
            correlation,
            page.transfer_id,
            page.request_nonce,
            page.cursor,
            page.next_cursor,
            page.checkpoint_states.len(),
            page.has_more
        );
    }
    if let Some(failure) = status_failure(status) {
        if correlation != 1 {
            recovery_terminal_trace!(
                "requester={} responder={} attempt={attempt:?} ignored failure={failure:?} reason=duplicate_correlation",
                rt.self_id,
                from
            );
            return;
        }
        let donor = ParticipantIncarnation::new(u64::from(from), epoch);
        donor_failed(rt, attempt, donor, failure);
        return;
    }
    if correlation == 2 {
        if !transfer_response_is_current(
            rt,
            attempt,
            &donor,
            page_cut,
            RecoveryPhase::FetchingTerminalCheckpoint,
        ) {
            return;
        }
        let ack = StrictBody::RecoveryTerminalAck(StrictRecoveryTerminalAck {
            context: page.context.clone(),
            target_cut: page.target_cut.clone(),
            transfer_id: page.transfer_id,
            request_nonce: page.request_nonce,
            acknowledged_cursor: page.next_cursor,
            final_ack: !page.has_more,
        });
        let _ = rt.net.send_redundant_unicast(from, &rt.topic, ack).await;
        return;
    }
    let accepted = {
        let coordinator = rt.recovery_coordinator.lock();
        if coordinator.attempt() != Some(attempt)
            || coordinator.phase() != RecoveryPhase::FetchingTerminalCheckpoint
            || coordinator.donor() != Some(&donor)
            || coordinator.representation_cut().map(journal_cut) != Some(page_cut)
        {
            return;
        }
        let mut clients = rt.recovery_v8.clients.lock();
        let Some(client) = clients.get_mut(&attempt) else {
            return;
        };
        if page.checkpoint_digest.as_ref() != client.cut.terminal_set_digest()
            || page.next_cursor
                != page
                    .cursor
                    .saturating_add(page.checkpoint_states.len() as u64)
            || (page.has_more && page.next_cursor == page.cursor)
        {
            recovery_terminal_trace!(
                "requester={} responder={} attempt={attempt:?} rejected reason=page_shape digest_matches={} expected_cursor={} cursor={} next_cursor={} states={} has_more={}",
                rt.self_id,
                from,
                page.checkpoint_digest.as_ref() == client.cut.terminal_set_digest(),
                client.terminal_cursor,
                page.cursor,
                page.next_cursor,
                page.checkpoint_states.len(),
                page.has_more
            );
            return;
        }
        client.terminal_id = page.transfer_id;
        client
            .terminal_states
            .extend(page.checkpoint_states.clone());
        client.terminal_cursor = page.next_cursor;
        let complete = !page.has_more;
        if !complete {
            client.terminal_nonce = rt.recovery_v8.wire_id();
        }
        complete
    };
    if accepted {
        let valid = {
            let clients = rt.recovery_v8.clients.lock();
            clients.get(&attempt).is_some_and(|client| {
                client
                    .terminal_states
                    .iter()
                    .map(staged_terminal_decision)
                    .collect::<Option<Vec<_>>>()
                    .is_some_and(|staged| {
                        super::terminal_journal::TerminalJournal::validate_staged_terminal_checkpoint(
                            client.cut,
                            &staged,
                        )
                        .is_ok()
                    })
            })
        };
        if !valid {
            recovery_terminal_trace!(
                "requester={} responder={} attempt={attempt:?} rejected reason=checkpoint_validation",
                rt.self_id,
                from
            );
            donor_failed(
                rt,
                attempt,
                ParticipantIncarnation::new(u64::from(from), epoch),
                DonorFailure::RetryableFailure,
            );
            return;
        }
    }
    let ack = StrictBody::RecoveryTerminalAck(StrictRecoveryTerminalAck {
        context: Some(wire_context(
            rt.self_id,
            rt.boot_epoch,
            attempt,
            epoch,
            context.target.as_ref().and_then(target_from_wire).as_ref(),
        )),
        target_cut: Some(cut_to_wire(page_cut)),
        transfer_id: page.transfer_id,
        request_nonce: page.request_nonce,
        acknowledged_cursor: page.next_cursor,
        final_ack: accepted,
    });
    if !transfer_response_is_current(
        rt,
        attempt,
        &donor,
        page_cut,
        RecoveryPhase::FetchingTerminalCheckpoint,
    ) {
        return;
    }
    let _ = rt.net.send_redundant_unicast(from, &rt.topic, ack).await;
    rt.transition_recovery(RecoveryEvent::TransferProgress {
        attempt,
        donor,
        kind: TransferKind::TerminalCheckpoint,
        authenticated: true,
        complete: accepted,
        now_ms: rt.recovery_now_ms(),
    });
    if !accepted {
        send_terminal_request_from_ref(rt, attempt).await;
    }
}

async fn send_terminal_request_from_ref<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    attempt: RecoveryAttemptId,
) {
    let Some(weak) = rt.weak_self.lock().clone() else {
        return;
    };
    if let Some(rt) = weak.upgrade() {
        send_terminal_request(&rt, attempt).await;
    }
}

pub(super) async fn recv_terminal_ack<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    authenticated: bool,
    ack: StrictRecoveryTerminalAck,
) {
    let Some(context) = ack.context.as_ref() else {
        return;
    };
    let Some(attempt) = authenticated
        .then(|| request_context(rt, from, epoch, context))
        .flatten()
    else {
        return;
    };
    let (Some(target), Some(cut)) = (
        context.target.as_ref().and_then(target_from_wire),
        ack.target_cut.as_ref().and_then(cut_from_wire),
    ) else {
        return;
    };
    let key = ServerKey {
        requester: from,
        requester_epoch: epoch,
        attempt,
    };
    let valid = if context.expected_donor_boot_epoch == rt.boot_epoch {
        let mut terminals = rt.recovery_v8.server_terminals.lock();
        let valid = terminals.get_mut(&key).is_some_and(|terminal| {
            let expected = ServerPageAck {
                next_cursor: ack.acknowledged_cursor,
                final_page: ack.final_ack,
            };
            let valid = terminal.donor_epoch == rt.boot_epoch
                && terminal.target == target
                && terminal.cut == cut
                && terminal.transfer_id == ack.transfer_id
                && terminal
                    .pending_pages
                    .get(&(ack.transfer_id, ack.request_nonce))
                    == Some(&expected)
                && terminal
                    .pending_pages
                    .remove(&(ack.transfer_id, ack.request_nonce))
                    .is_some();
            if valid {
                terminal.last_authenticated_activity = Instant::now();
            }
            valid
        });
        if valid && ack.final_ack {
            terminals.remove(&key);
        }
        valid
    } else {
        false
    };
    if !valid {
        return;
    }
    sync_donor_session_metrics(rt);
    refresh_exact_attestation(rt, &key, &target, cut);
    rt.net.acknowledge_bulk_unicast(
        from,
        &rt.topic,
        BulkPageIdentity::recovery_terminal(ack.transfer_id, ack.request_nonce),
    );
}

pub(super) async fn recv_snapshot_req<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    authenticated: bool,
    request: StrictRecoverySnapshotReq,
) {
    let (Some(context), Some(wire_cut)) = (request.context.as_ref(), request.target_cut.as_ref())
    else {
        return;
    };
    let Some(attempt) = authenticated
        .then(|| request_context(rt, from, epoch, context))
        .flatten()
    else {
        return;
    };
    if request.request_nonce == 0 || (request.transfer_id == 0) != (request.expected_cursor == 0) {
        return;
    }
    let Some(target) = context.target.as_ref().and_then(target_from_wire) else {
        return;
    };
    let Some(cut) = cut_from_wire(wire_cut) else {
        return;
    };
    if context.expected_donor_boot_epoch != rt.boot_epoch {
        send_snapshot_status(
            rt,
            from,
            epoch,
            attempt,
            target,
            cut,
            &request,
            StrictRecoveryStatus::IncarnationMismatch,
        )
        .await;
        return;
    }
    let recovery_callback_token = rt.recovery_callback_token();
    if !rt.recovery_callback_is_current(recovery_callback_token) {
        send_snapshot_status(
            rt,
            from,
            epoch,
            attempt,
            target,
            cut,
            &request,
            StrictRecoveryStatus::RetryableFailure,
        )
        .await;
        return;
    }
    let key = ServerKey {
        requester: from,
        requester_epoch: epoch,
        attempt,
    };
    let attestation_status = {
        let attestations = rt.recovery_v8.served_probe_attestations.lock();
        match attestations.get(&key) {
            Some(attested) if attested.target == target && attested.cut == cut => {
                StrictRecoveryStatus::Ok
            }
            Some(_) => StrictRecoveryStatus::TargetMoved,
            None => StrictRecoveryStatus::RetryableFailure,
        }
    };
    if attestation_status != StrictRecoveryStatus::Ok {
        send_snapshot_status(
            rt,
            from,
            epoch,
            attempt,
            target,
            cut,
            &request,
            attestation_status,
        )
        .await;
        return;
    }
    if let Some(page) = take_implicit_snapshot_continuation_ack(
        rt,
        &key,
        &target,
        cut,
        request.transfer_id,
        request.expected_cursor,
    ) {
        rt.net.acknowledge_bulk_unicast(from, &rt.topic, page);
    }
    if request.transfer_id == 0
        && request.expected_cursor == 0
        && !rt.recovery_v8.server_snapshots.lock().contains_key(&key)
    {
        let _gate = rt.snapshot_image_build_gate().await;
        let Some(_capture) = rt.begin_snapshot_capture() else {
            send_snapshot_status(
                rt,
                from,
                epoch,
                attempt,
                target,
                cut,
                &request,
                StrictRecoveryStatus::RetryableFailure,
            )
            .await;
            return;
        };
        let Ok(boundary) = rt.capture_snapshot_terminal_boundary().await else {
            send_snapshot_status(
                rt,
                from,
                epoch,
                attempt,
                target,
                cut,
                &request,
                StrictRecoveryStatus::RetryableFailure,
            )
            .await;
            return;
        };
        if !rt.recovery_callback_is_current(recovery_callback_token) {
            send_snapshot_status(
                rt,
                from,
                epoch,
                attempt,
                target,
                cut,
                &request,
                StrictRecoveryStatus::RetryableFailure,
            )
            .await;
            return;
        }
        if boundary.history_metadata.version != target.repository_version()
            || boundary.history_metadata.freshness != target.history_freshness()
            || boundary.terminal_cut != cut
        {
            send_snapshot_status(
                rt,
                from,
                epoch,
                attempt,
                target,
                cut,
                &request,
                StrictRecoveryStatus::TargetMoved,
            )
            .await;
            return;
        }
        let Ok(bytes) = encode_bound_s2s_snapshot_envelope(
            boundary.repository_snapshot,
            boundary.applied_operations,
            boundary.retired_operations,
            cut,
        ) else {
            send_snapshot_status(
                rt,
                from,
                epoch,
                attempt,
                target,
                cut,
                &request,
                StrictRecoveryStatus::RetryableFailure,
            )
            .await;
            return;
        };
        if bytes.len() > rt.cfg.strict_max_snapshot_transfer_bytes() {
            send_snapshot_status(
                rt,
                from,
                epoch,
                attempt,
                target,
                cut,
                &request,
                StrictRecoveryStatus::ResourceLimit,
            )
            .await;
            return;
        }
        rt.recovery_v8.server_snapshots.lock().insert(
            key.clone(),
            ServerSnapshot {
                donor_epoch: rt.boot_epoch,
                target: target.clone(),
                cut,
                transfer_id: rt.recovery_v8.wire_id(),
                digest: sha256(&bytes),
                bytes,
                pending_pages: HashMap::new(),
                last_authenticated_activity: Instant::now(),
            },
        );
        sync_donor_session_metrics(rt);
    }
    let body = (|| {
        let mut snapshots = rt.recovery_v8.server_snapshots.lock();
        let Some(snapshot) = snapshots.get_mut(&key) else {
            return None;
        };
        if snapshot.donor_epoch != rt.boot_epoch
            || snapshot.target != target
            || snapshot.cut != cut
            || (request.transfer_id != 0 && request.transfer_id != snapshot.transfer_id)
        {
            return None;
        }
        let cursor = usize::try_from(request.expected_cursor).unwrap_or(usize::MAX);
        if cursor > snapshot.bytes.len() {
            return None;
        }
        let page_len = rt
            .strict_catchup_response_budget()
            .saturating_sub(PAGE_OVERHEAD_RESERVE)
            .max(1)
            .min(snapshot.bytes.len() - cursor);
        let next = cursor + page_len;
        let pending = ServerPageAck {
            next_cursor: next as u64,
            final_page: next == snapshot.bytes.len(),
        };
        if snapshot
            .pending_pages
            .get(&(snapshot.transfer_id, request.request_nonce))
            .is_some_and(|existing| *existing != pending)
        {
            return None;
        }
        snapshot.last_authenticated_activity = Instant::now();
        let newly_registered = snapshot
            .pending_pages
            .insert((snapshot.transfer_id, request.request_nonce), pending)
            .is_none();
        Some((
            StrictBody::RecoverySnapshotPage(StrictRecoverySnapshotPage {
                context: Some(wire_context(
                    from,
                    epoch,
                    attempt,
                    rt.boot_epoch,
                    Some(&target),
                )),
                responder_node: rt.self_id as u32,
                responder_boot_epoch: rt.boot_epoch,
                status: StrictRecoveryStatus::Ok.into(),
                target_cut: Some(cut_to_wire(cut)),
                transfer_id: snapshot.transfer_id,
                request_nonce: request.request_nonce,
                cursor: request.expected_cursor,
                next_cursor: next as u64,
                total_bytes: snapshot.bytes.len() as u64,
                snapshot_digest: Bytes::copy_from_slice(&snapshot.digest),
                snapshot_bytes: snapshot.bytes.slice(cursor..next),
                has_more: next < snapshot.bytes.len(),
            }),
            newly_registered,
        ))
    })();
    let Some((body, newly_registered)) = body else {
        send_snapshot_status(
            rt,
            from,
            epoch,
            attempt,
            target,
            cut,
            &request,
            StrictRecoveryStatus::TargetMoved,
        )
        .await;
        return;
    };
    refresh_exact_attestation(rt, &key, &target, cut);
    if !rt.recovery_callback_is_current(recovery_callback_token) {
        send_snapshot_status(
            rt,
            from,
            epoch,
            attempt,
            target,
            cut,
            &request,
            StrictRecoveryStatus::RetryableFailure,
        )
        .await;
        return;
    }
    let retryable_failure = match &body {
        StrictBody::RecoverySnapshotPage(page) => {
            let mut failure = page.clone();
            failure.status = StrictRecoveryStatus::RetryableFailure.into();
            failure.next_cursor = failure.cursor;
            failure.total_bytes = 0;
            failure.snapshot_digest = Bytes::new();
            failure.snapshot_bytes = Bytes::new();
            failure.has_more = false;
            StrictBody::RecoverySnapshotPage(failure)
        }
        _ => unreachable!("snapshot donor constructed a non-snapshot page"),
    };
    let sent_identity = match &body {
        StrictBody::RecoverySnapshotPage(page) => (page.transfer_id, page.request_nonce),
        _ => unreachable!("snapshot donor constructed a non-snapshot page"),
    };
    let sent = send_recovery_bulk_page(rt, from, &key, body).await;
    if sent.is_err() {
        if newly_registered
            && let Some(snapshot) = rt.recovery_v8.server_snapshots.lock().get_mut(&key)
        {
            snapshot.pending_pages.remove(&sent_identity);
        }
        // The failed bulk page owns no live reservation. A status-only control
        // response keeps the generated transfer id while resetting progress,
        // allowing the requester to retry its unchanged request immediately.
        let _ = rt
            .net
            .send_redundant_unicast(from, &rt.topic, retryable_failure)
            .await;
    }
}

async fn send_snapshot_status<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    attempt: RecoveryAttemptId,
    target: LogicalTarget,
    cut: TerminalCut,
    request: &StrictRecoverySnapshotReq,
    status: StrictRecoveryStatus,
) {
    let body = StrictBody::RecoverySnapshotPage(StrictRecoverySnapshotPage {
        context: Some(wire_context(
            from,
            epoch,
            attempt,
            rt.boot_epoch,
            Some(&target),
        )),
        responder_node: rt.self_id as u32,
        responder_boot_epoch: rt.boot_epoch,
        status: status.into(),
        target_cut: Some(cut_to_wire(cut)),
        transfer_id: request.transfer_id,
        request_nonce: request.request_nonce,
        cursor: request.expected_cursor,
        next_cursor: request.expected_cursor,
        total_bytes: 0,
        snapshot_digest: Bytes::new(),
        snapshot_bytes: Bytes::new(),
        has_more: false,
    });
    let _ = rt.net.send_redundant_unicast(from, &rt.topic, body).await;
}

pub(super) async fn recv_snapshot_page<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    authenticated: bool,
    page: StrictRecoverySnapshotPage,
) {
    let Some(context) = page.context.as_ref() else {
        return;
    };
    let Some(attempt) = authenticated
        .then(|| response_context(rt, from, epoch, context))
        .flatten()
    else {
        return;
    };
    let Some(status) = StrictRecoveryStatus::try_from(page.status).ok() else {
        return;
    };
    if node_from_u32(page.responder_node) != Some(from) || page.responder_boot_epoch != epoch {
        return;
    }
    let Some(page_cut) = page.target_cut.as_ref().and_then(cut_from_wire) else {
        return;
    };
    let donor = ParticipantIncarnation::new(u64::from(from), epoch);
    let correlation = {
        let coordinator = rt.recovery_coordinator.lock();
        if coordinator.attempt() != Some(attempt)
            || coordinator.phase() != RecoveryPhase::FetchingRepositorySnapshot
            || coordinator.donor() != Some(&donor)
            || coordinator.representation_cut().map(journal_cut) != Some(page_cut)
        {
            return;
        }
        let clients = rt.recovery_v8.clients.lock();
        let Some(client) = clients.get(&attempt) else {
            return;
        };
        if context.target.as_ref().and_then(target_from_wire).as_ref() != Some(&client.target)
            || client.donor != donor
            || client.cut != page_cut
            || (status == StrictRecoveryStatus::Ok && page.transfer_id == 0)
            || (client.snapshot_id != 0 && client.snapshot_id != page.transfer_id)
        {
            0
        } else if page.request_nonce == client.snapshot_nonce
            && page.cursor == client.snapshot_cursor
        {
            1
        } else {
            let start = usize::try_from(page.cursor).unwrap_or(usize::MAX);
            let end = usize::try_from(page.next_cursor).unwrap_or(usize::MAX);
            if end <= client.snapshot_bytes.len()
                && start <= end
                && client.snapshot_bytes[start..end] == page.snapshot_bytes
            {
                2
            } else {
                0
            }
        }
    };
    if correlation == 0 {
        return;
    }
    if let Some(failure) = status_failure(status) {
        if correlation != 1 {
            return;
        }
        donor_failed(
            rt,
            attempt,
            ParticipantIncarnation::new(u64::from(from), epoch),
            failure,
        );
        return;
    }
    if correlation == 2 {
        if !transfer_response_is_current(
            rt,
            attempt,
            &donor,
            page_cut,
            RecoveryPhase::FetchingRepositorySnapshot,
        ) {
            return;
        }
        let ack = StrictBody::RecoverySnapshotAck(StrictRecoverySnapshotAck {
            context: page.context.clone(),
            target_cut: page.target_cut.clone(),
            transfer_id: page.transfer_id,
            request_nonce: page.request_nonce,
            acknowledged_cursor: page.next_cursor,
            final_ack: !page.has_more,
        });
        let _ = rt.net.send_redundant_unicast(from, &rt.topic, ack).await;
        return;
    }
    let (complete, expectation, image) = {
        let coordinator = rt.recovery_coordinator.lock();
        if coordinator.attempt() != Some(attempt)
            || coordinator.phase() != RecoveryPhase::FetchingRepositorySnapshot
            || coordinator.donor() != Some(&donor)
            || coordinator.representation_cut().map(journal_cut) != Some(page_cut)
        {
            return;
        }
        let mut clients = rt.recovery_v8.clients.lock();
        let Some(client) = clients.get_mut(&attempt) else {
            return;
        };
        let Ok(digest): Result<[u8; 32], _> = page.snapshot_digest.as_ref().try_into() else {
            return;
        };
        if page.next_cursor != page.cursor.saturating_add(page.snapshot_bytes.len() as u64)
            || page.total_bytes > rt.cfg.strict_max_snapshot_transfer_bytes() as u64
            || page.next_cursor > page.total_bytes
            || page.has_more != (page.next_cursor < page.total_bytes)
            || (page.has_more && page.next_cursor == page.cursor)
        {
            return;
        }
        if client
            .snapshot_total
            .is_some_and(|total| total != page.total_bytes)
            || client.snapshot_digest.is_some_and(|known| known != digest)
        {
            return;
        }
        client.snapshot_id = page.transfer_id;
        client.snapshot_total = Some(page.total_bytes);
        client.snapshot_digest = Some(digest);
        client
            .snapshot_bytes
            .extend_from_slice(&page.snapshot_bytes);
        client.snapshot_cursor = page.next_cursor;
        let complete = !page.has_more
            && client.snapshot_bytes.len() as u64 == page.total_bytes
            && sha256(&client.snapshot_bytes) == digest;
        if !complete {
            client.snapshot_nonce = rt.recovery_v8.wire_id();
        }
        let expectation = RecoveryStagingExpectation::new(
            attempt.hi(),
            attempt.lo(),
            HistoryMetadata {
                version: client.target.repository_version(),
                freshness: client.target.history_freshness(),
            },
            client.cut,
        );
        (
            complete,
            expectation,
            complete.then(|| client.snapshot_bytes.clone()),
        )
    };
    let ack = StrictBody::RecoverySnapshotAck(StrictRecoverySnapshotAck {
        context: Some(wire_context(
            rt.self_id,
            rt.boot_epoch,
            attempt,
            epoch,
            context.target.as_ref().and_then(target_from_wire).as_ref(),
        )),
        target_cut: Some(cut_to_wire(page_cut)),
        transfer_id: page.transfer_id,
        request_nonce: page.request_nonce,
        acknowledged_cursor: page.next_cursor,
        final_ack: complete,
    });
    if complete {
        let Some(path) = stage_path(rt, attempt) else {
            donor_failed(
                rt,
                attempt,
                ParticipantIncarnation::new(u64::from(from), epoch),
                DonorFailure::ResourceLimit,
            );
            return;
        };
        let Some(image) = image else {
            return;
        };
        let _ = delete_recovery_staging_artifact(&path);
        let Ok(manifest) = write_recovery_staging_artifact(&path, expectation, &image) else {
            donor_failed(
                rt,
                attempt,
                ParticipantIncarnation::new(u64::from(from), epoch),
                DonorFailure::RetryableFailure,
            );
            return;
        };
        if !persist_attempt(rt).await {
            let _ = delete_recovery_staging_artifact(&path);
            return;
        }
        let attached = {
            let coordinator = rt.recovery_coordinator.lock();
            if coordinator.attempt() != Some(attempt)
                || coordinator.phase() != RecoveryPhase::FetchingRepositorySnapshot
                || coordinator.donor() != Some(&donor)
                || coordinator.representation_cut().map(journal_cut) != Some(page_cut)
            {
                false
            } else {
                let mut clients = rt.recovery_v8.clients.lock();
                clients.get_mut(&attempt).is_some_and(|client| {
                    if client.donor != donor
                        || client.cut != page_cut
                        || client.snapshot_id != page.transfer_id
                        || client.snapshot_nonce != page.request_nonce
                        || client.snapshot_cursor != page.next_cursor
                    {
                        return false;
                    }
                    client.staging = Some((path.clone(), manifest));
                    true
                })
            }
        };
        if !attached {
            let _ = delete_recovery_staging_artifact(&path);
            return;
        }
    }
    if !transfer_response_is_current(
        rt,
        attempt,
        &donor,
        page_cut,
        RecoveryPhase::FetchingRepositorySnapshot,
    ) {
        return;
    }
    let _ = rt.net.send_redundant_unicast(from, &rt.topic, ack).await;
    rt.transition_recovery(RecoveryEvent::TransferProgress {
        attempt,
        donor,
        kind: TransferKind::RepositorySnapshot,
        authenticated: true,
        complete,
        now_ms: rt.recovery_now_ms(),
    });
    if !complete {
        send_snapshot_request_from_ref(rt, attempt).await;
    }
}

async fn send_snapshot_request_from_ref<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    attempt: RecoveryAttemptId,
) {
    let Some(weak) = rt.weak_self.lock().clone() else {
        return;
    };
    if let Some(rt) = weak.upgrade() {
        send_snapshot_request(&rt, attempt).await;
    }
}

pub(super) async fn recv_snapshot_ack<R: StrictReplicable>(
    rt: &StrictRuntime<R>,
    from: NodeIdentifier,
    epoch: u64,
    authenticated: bool,
    ack: StrictRecoverySnapshotAck,
) {
    let Some(context) = ack.context.as_ref() else {
        return;
    };
    let Some(attempt) = authenticated
        .then(|| request_context(rt, from, epoch, context))
        .flatten()
    else {
        return;
    };
    let (Some(target), Some(cut)) = (
        context.target.as_ref().and_then(target_from_wire),
        ack.target_cut.as_ref().and_then(cut_from_wire),
    ) else {
        return;
    };
    let key = ServerKey {
        requester: from,
        requester_epoch: epoch,
        attempt,
    };
    let valid = if context.expected_donor_boot_epoch == rt.boot_epoch {
        let mut snapshots = rt.recovery_v8.server_snapshots.lock();
        let valid = snapshots.get_mut(&key).is_some_and(|snapshot| {
            let expected = ServerPageAck {
                next_cursor: ack.acknowledged_cursor,
                final_page: ack.final_ack,
            };
            let valid = snapshot.donor_epoch == rt.boot_epoch
                && snapshot.target == target
                && snapshot.cut == cut
                && snapshot.transfer_id == ack.transfer_id
                && snapshot
                    .pending_pages
                    .get(&(ack.transfer_id, ack.request_nonce))
                    == Some(&expected)
                && snapshot
                    .pending_pages
                    .remove(&(ack.transfer_id, ack.request_nonce))
                    .is_some();
            if valid {
                snapshot.last_authenticated_activity = Instant::now();
            }
            valid
        });
        if valid && ack.final_ack {
            snapshots.remove(&key);
        }
        valid
    } else {
        false
    };
    if !valid {
        return;
    }
    if ack.final_ack {
        rt.recovery_v8.served_probe_attestations.lock().remove(&key);
    }
    sync_donor_session_metrics(rt);
    rt.net.acknowledge_bulk_unicast(
        from,
        &rt.topic,
        BulkPageIdentity::recovery_snapshot(ack.transfer_id, ack.request_nonce),
    );
}
