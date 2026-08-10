use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::{Duration, Instant};

use crate::status::PrometheusSample;

#[cfg(test)]
use super::proto::StrictTerminalSyncStatus;
use super::proto::{StrictCatchupReason, StrictTerminalPageKind};

#[derive(Clone, Copy)]
pub(crate) enum CatchupMode {
    Strict,
    Owner,
}

impl CatchupMode {
    fn index(self) -> usize {
        match self {
            Self::Strict => 0,
            Self::Owner => 1,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Owner => "owner",
        }
    }
}

/// Bounded initiating reasons for replication catchup work.
///
/// Never replace these labels with topic, peer, transfer, or operation data:
/// those values are deliberately excluded from the Prometheus surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CatchupReason {
    HistoryElection,
    Admission,
    SteadyState,
    TerminalFence,
    DeliveryWatermark,
    PeerBehind,
    RepositoryGap,
    LegacyV2,
    OwnerAntiEntropy,
}

impl CatchupReason {
    fn index(self) -> usize {
        match self {
            Self::HistoryElection => 0,
            Self::Admission => 1,
            Self::SteadyState => 2,
            Self::TerminalFence => 3,
            Self::DeliveryWatermark => 4,
            Self::PeerBehind => 5,
            Self::RepositoryGap => 6,
            Self::LegacyV2 => 7,
            Self::OwnerAntiEntropy => 8,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::HistoryElection => "history_election",
            Self::Admission => "admission",
            Self::SteadyState => "steady_state",
            Self::TerminalFence => "terminal_fence",
            Self::DeliveryWatermark => "delivery_watermark",
            Self::PeerBehind => "peer_behind",
            Self::RepositoryGap => "repository_gap",
            Self::LegacyV2 => "legacy_v2",
            Self::OwnerAntiEntropy => "owner_anti_entropy",
        }
    }

    /// Converts an authenticated v3 wire reason into its bounded metric
    /// dimension. An unspecified or unknown value is rejected instead of
    /// being folded into an unrelated reason and hiding malformed traffic.
    pub(crate) fn from_v3_wire(reason: i32) -> Option<Self> {
        match StrictCatchupReason::try_from(reason).ok()? {
            StrictCatchupReason::Unspecified => None,
            StrictCatchupReason::HistoryElection => Some(Self::HistoryElection),
            StrictCatchupReason::Admission => Some(Self::Admission),
            StrictCatchupReason::SteadyState => Some(Self::SteadyState),
            StrictCatchupReason::TerminalFence => Some(Self::TerminalFence),
            StrictCatchupReason::DeliveryWatermark => Some(Self::DeliveryWatermark),
            StrictCatchupReason::PeerBehind => Some(Self::PeerBehind),
            StrictCatchupReason::RepositoryGap => Some(Self::RepositoryGap),
            StrictCatchupReason::LegacyV2 => Some(Self::LegacyV2),
            StrictCatchupReason::OwnerAntiEntropy => Some(Self::OwnerAntiEntropy),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CatchupPhase {
    Metadata,
    TerminalDelta,
    TerminalCheckpoint,
    LogDelta,
    Snapshot,
    FinalAck,
}

impl CatchupPhase {
    fn index(self) -> usize {
        match self {
            Self::Metadata => 0,
            Self::TerminalDelta => 1,
            Self::TerminalCheckpoint => 2,
            Self::LogDelta => 3,
            Self::Snapshot => 4,
            Self::FinalAck => 5,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::TerminalDelta => "terminal_delta",
            Self::TerminalCheckpoint => "terminal_checkpoint",
            Self::LogDelta => "log_delta",
            Self::Snapshot => "snapshot",
            Self::FinalAck => "final_ack",
        }
    }

    /// Classifies the operation-bearing portion of a terminal-sync page.
    /// Status-only pages and manifests remain metadata and final ACKs are
    /// recorded explicitly by their send call site.
    pub(crate) fn from_terminal_page_kind(kind: i32) -> Option<Self> {
        match StrictTerminalPageKind::try_from(kind).ok()? {
            StrictTerminalPageKind::Unspecified => None,
            StrictTerminalPageKind::Delta => Some(Self::TerminalDelta),
            StrictTerminalPageKind::Checkpoint => Some(Self::TerminalCheckpoint),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictCatchupSessionOutcome {
    Completed,
    Failed,
    Cancelled,
    Expired,
    IncarnationMismatch,
    ResourceLimit,
}

impl StrictCatchupSessionOutcome {
    fn index(self) -> usize {
        match self {
            Self::Completed => 0,
            Self::Failed => 1,
            Self::Cancelled => 2,
            Self::Expired => 3,
            Self::IncarnationMismatch => 4,
            Self::ResourceLimit => 5,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::IncarnationMismatch => "incarnation_mismatch",
            Self::ResourceLimit => "resource_limit",
        }
    }

    #[cfg(test)]
    /// Maps terminal-sync protocol completion statuses to the bounded
    /// session outcome set. Successful `OK` pages are not completions until
    /// their fixed target is ACKed, so callers must record those separately.
    pub(crate) fn from_terminal_status(status: i32) -> Option<Self> {
        match StrictTerminalSyncStatus::try_from(status).ok()? {
            StrictTerminalSyncStatus::Unspecified | StrictTerminalSyncStatus::Ok => None,
            StrictTerminalSyncStatus::UpToDate => Some(Self::Completed),
            StrictTerminalSyncStatus::TransferExpired => Some(Self::Expired),
            StrictTerminalSyncStatus::CursorMismatch => Some(Self::Failed),
            StrictTerminalSyncStatus::IncarnationMismatch => Some(Self::IncarnationMismatch),
            StrictTerminalSyncStatus::ResourceLimit => Some(Self::ResourceLimit),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictCatchupSessionEvent {
    Coalesced,
    DirtyRefresh,
    Restart,
    FinalAck,
}

impl StrictCatchupSessionEvent {
    fn index(self) -> usize {
        match self {
            Self::Coalesced => 0,
            Self::DirtyRefresh => 1,
            Self::Restart => 2,
            Self::FinalAck => 3,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Coalesced => "coalesced",
            Self::DirtyRefresh => "dirty_refresh",
            Self::Restart => "restart",
            Self::FinalAck => "final_ack",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictCatchupLane {
    Control,
    Bulk,
}

impl StrictCatchupLane {
    fn index(self) -> usize {
        match self {
            Self::Control => 0,
            Self::Bulk => 1,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Bulk => "bulk",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictCatchupSendOutcome {
    Enqueued,
    Backpressured,
    RetryEnqueued,
    Exhausted,
    Rejected,
}

impl StrictCatchupSendOutcome {
    fn index(self) -> usize {
        match self {
            Self::Enqueued => 0,
            Self::Backpressured => 1,
            Self::RetryEnqueued => 2,
            Self::Exhausted => 3,
            Self::Rejected => 4,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Enqueued => "enqueued",
            Self::Backpressured => "backpressured",
            Self::RetryEnqueued => "retry_enqueued",
            Self::Exhausted => "exhausted",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictCatchupDuplicateOutcome {
    Suppressed,
    CachedReplay,
}

/// Bounded receiver-side outcomes for strict repository snapshot pages.
/// Exact peer, transfer, cursor, version, and digest values belong in logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictSnapshotReceiveEvent {
    Continued,
    Completed,
    DuplicateActive,
    StaleIdle,
    StaleForeignTransfer,
    StaleMissingReceiver,
    CompletionRetried,
    AmbiguousLegacy,
    SourceRejected,
    RestartInvalidEnvelope,
    RestartInvalidCursor,
    RestartFormatMismatch,
    RestartMetadataMismatch,
    RestartChunkOrder,
    RestartResourceLimit,
    RestartDigestMismatch,
    RestartExpiredReceiver,
    RestartMissingState,
}

impl StrictSnapshotReceiveEvent {
    fn index(self) -> usize {
        match self {
            Self::Continued => 0,
            Self::Completed => 1,
            Self::DuplicateActive => 2,
            Self::StaleIdle => 3,
            Self::StaleForeignTransfer => 4,
            Self::StaleMissingReceiver => 5,
            Self::CompletionRetried => 6,
            Self::AmbiguousLegacy => 7,
            Self::SourceRejected => 8,
            Self::RestartInvalidEnvelope => 9,
            Self::RestartInvalidCursor => 10,
            Self::RestartFormatMismatch => 11,
            Self::RestartMetadataMismatch => 12,
            Self::RestartChunkOrder => 13,
            Self::RestartResourceLimit => 14,
            Self::RestartDigestMismatch => 15,
            Self::RestartExpiredReceiver => 16,
            Self::RestartMissingState => 17,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Continued => "continued",
            Self::Completed => "completed",
            Self::DuplicateActive => "duplicate_active",
            Self::StaleIdle => "stale_idle",
            Self::StaleForeignTransfer => "stale_foreign_transfer",
            Self::StaleMissingReceiver => "stale_missing_receiver",
            Self::CompletionRetried => "completion_retried",
            Self::AmbiguousLegacy => "ambiguous_legacy",
            Self::SourceRejected => "source_rejected",
            Self::RestartInvalidEnvelope => "restart_invalid_envelope",
            Self::RestartInvalidCursor => "restart_invalid_cursor",
            Self::RestartFormatMismatch => "restart_format_mismatch",
            Self::RestartMetadataMismatch => "restart_metadata_mismatch",
            Self::RestartChunkOrder => "restart_chunk_order",
            Self::RestartResourceLimit => "restart_resource_limit",
            Self::RestartDigestMismatch => "restart_digest_mismatch",
            Self::RestartExpiredReceiver => "restart_expired_receiver",
            Self::RestartMissingState => "restart_missing_state",
        }
    }
}

/// Bounded responder-side outcomes for strict repository snapshot requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictSnapshotResponderEvent {
    ImagePagePrepared,
    InitialPagePrepared,
    ContinuationPrepared,
    CompletionAcknowledged,
    StaleTransferIgnored,
    StaleTransferRejected,
    InvalidCursorIgnored,
    InvalidCursorRejected,
    MissingTransferRejected,
    TransferRejected,
    FenceInvalidated,
    ResponseSendFailed,
    ResponseSuppressed,
}

impl StrictSnapshotResponderEvent {
    fn index(self) -> usize {
        match self {
            Self::ImagePagePrepared => 0,
            Self::InitialPagePrepared => 1,
            Self::ContinuationPrepared => 2,
            Self::CompletionAcknowledged => 3,
            Self::StaleTransferIgnored => 4,
            Self::StaleTransferRejected => 5,
            Self::InvalidCursorIgnored => 6,
            Self::InvalidCursorRejected => 7,
            Self::MissingTransferRejected => 8,
            Self::TransferRejected => 9,
            Self::FenceInvalidated => 10,
            Self::ResponseSendFailed => 11,
            Self::ResponseSuppressed => 12,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ImagePagePrepared => "image_page_prepared",
            Self::InitialPagePrepared => "initial_page_prepared",
            Self::ContinuationPrepared => "continuation_prepared",
            Self::CompletionAcknowledged => "completion_acknowledged",
            Self::StaleTransferIgnored => "stale_transfer_ignored",
            Self::StaleTransferRejected => "stale_transfer_rejected",
            Self::InvalidCursorIgnored => "invalid_cursor_ignored",
            Self::InvalidCursorRejected => "invalid_cursor_rejected",
            Self::MissingTransferRejected => "missing_transfer_rejected",
            Self::TransferRejected => "transfer_rejected",
            Self::FenceInvalidated => "fence_invalidated",
            Self::ResponseSendFailed => "response_send_failed",
            Self::ResponseSuppressed => "response_suppressed",
        }
    }
}

impl StrictCatchupDuplicateOutcome {
    fn index(self) -> usize {
        match self {
            Self::Suppressed => 0,
            Self::CachedReplay => 1,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Suppressed => "suppressed",
            Self::CachedReplay => "cached_replay",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictCatchupBackpressureEvent {
    Backpressured,
    Retry,
    ExhaustedRetry,
}

impl StrictCatchupBackpressureEvent {
    fn index(self) -> usize {
        match self {
            Self::Backpressured => 0,
            Self::Retry => 1,
            Self::ExhaustedRetry => 2,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Backpressured => "backpressured",
            Self::Retry => "retry",
            Self::ExhaustedRetry => "exhausted_retry",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictCatchupThrottleReason {
    NextHopBytes,
    Backoff,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictProbeKind {
    Clock,
    History,
}

impl StrictProbeKind {
    fn index(self) -> usize {
        match self {
            Self::Clock => 0,
            Self::History => 1,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Clock => "clock",
            Self::History => "history",
        }
    }
}

/// Bounded lifecycle outcomes for admission and election probes.
///
/// Peer, incarnation, nonce, and repository tuples belong in structured logs,
/// never in this Prometheus dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictProbeOutcome {
    Sent,
    Coalesced,
    RetryRestored,
    Accepted,
    RejectedPeer,
    RejectedEnvelope,
    IgnoredNonce,
    RejectedPayload,
}

impl StrictProbeOutcome {
    fn index(self) -> usize {
        match self {
            Self::Sent => 0,
            Self::Coalesced => 1,
            Self::RetryRestored => 2,
            Self::Accepted => 3,
            Self::RejectedPeer => 4,
            Self::RejectedEnvelope => 5,
            Self::IgnoredNonce => 6,
            Self::RejectedPayload => 7,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Coalesced => "coalesced",
            Self::RetryRestored => "retry_restored",
            Self::Accepted => "accepted",
            Self::RejectedPeer => "rejected_peer",
            Self::RejectedEnvelope => "rejected_envelope",
            Self::IgnoredNonce => "ignored_nonce",
            Self::RejectedPayload => "rejected_payload",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictAdmissionEvent {
    Started,
    Revoked,
    CutFrozen,
    HistoryProofAccepted,
    HistoryProofTerminalMismatch,
    ClockProofAccepted,
    ClockProofBelowBarrier,
    Admitted,
}

impl StrictAdmissionEvent {
    fn index(self) -> usize {
        match self {
            Self::Started => 0,
            Self::Revoked => 1,
            Self::CutFrozen => 2,
            Self::HistoryProofAccepted => 3,
            Self::HistoryProofTerminalMismatch => 4,
            Self::ClockProofAccepted => 5,
            Self::ClockProofBelowBarrier => 6,
            Self::Admitted => 7,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Revoked => "revoked",
            Self::CutFrozen => "cut_frozen",
            Self::HistoryProofAccepted => "history_proof_accepted",
            Self::HistoryProofTerminalMismatch => "history_proof_terminal_mismatch",
            Self::ClockProofAccepted => "clock_proof_accepted",
            Self::ClockProofBelowBarrier => "clock_proof_below_barrier",
            Self::Admitted => "admitted",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictHistoryElectionEvent {
    Started,
    ResponsePending,
    LocalWon,
    RemoteWon,
    SnapshotStarted,
    Finished,
    Rearmed,
    TimedOut,
}

impl StrictHistoryElectionEvent {
    fn index(self) -> usize {
        match self {
            Self::Started => 0,
            Self::ResponsePending => 1,
            Self::LocalWon => 2,
            Self::RemoteWon => 3,
            Self::SnapshotStarted => 4,
            Self::Finished => 5,
            Self::Rearmed => 6,
            Self::TimedOut => 7,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::ResponsePending => "response_pending",
            Self::LocalWon => "local_won",
            Self::RemoteWon => "remote_won",
            Self::SnapshotStarted => "snapshot_started",
            Self::Finished => "finished",
            Self::Rearmed => "rearmed",
            Self::TimedOut => "timed_out",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictHeadEvent {
    EvidenceChanged,
    EvidenceRepositoryVersionMismatch,
    EvidenceFreshnessMismatch,
    EvidenceTerminalDigestMismatch,
    EvidenceJournalLineageMismatch,
    AckAccepted,
    AckRejectedEnvelope,
    AckRejectedDigest,
    AckRejectedIdentity,
    TickAttempted,
}

impl StrictHeadEvent {
    fn index(self) -> usize {
        match self {
            Self::EvidenceChanged => 0,
            Self::EvidenceRepositoryVersionMismatch => 1,
            Self::EvidenceFreshnessMismatch => 2,
            Self::EvidenceTerminalDigestMismatch => 3,
            Self::EvidenceJournalLineageMismatch => 4,
            Self::AckAccepted => 5,
            Self::AckRejectedEnvelope => 6,
            Self::AckRejectedDigest => 7,
            Self::AckRejectedIdentity => 8,
            Self::TickAttempted => 9,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::EvidenceChanged => "evidence_changed",
            Self::EvidenceRepositoryVersionMismatch => "evidence_repository_version_mismatch",
            Self::EvidenceFreshnessMismatch => "evidence_freshness_mismatch",
            Self::EvidenceTerminalDigestMismatch => "evidence_terminal_digest_mismatch",
            Self::EvidenceJournalLineageMismatch => "evidence_journal_lineage_mismatch",
            Self::AckAccepted => "ack_accepted",
            Self::AckRejectedEnvelope => "ack_rejected_envelope",
            Self::AckRejectedDigest => "ack_rejected_digest",
            Self::AckRejectedIdentity => "ack_rejected_identity",
            Self::TickAttempted => "tick_attempted",
        }
    }
}

/// Bounded outcomes in the strict terminal-lineage divergence and recovery
/// path. Divergence is the state where a peer advertises a journal lineage
/// foreign to the local terminal set; recovery routes it through a ranked
/// history election instead of per-operation terminal sync.
///
/// Never replace these labels with topic, peer, transfer, journal, or digest
/// data: those values are deliberately excluded from the Prometheus surface
/// and belong in structured logs instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictTerminalDivergenceEvent {
    ForeignLineageDropped,
    ForeignLineageElectionRequested,
    ForeignLineageElectionDeduped,
    ForcedCheckpointAbandonedWork,
    ForcedCheckpointSent,
    StalledElectionRemoteWon,
    StalledElectionNoCandidate,
    StalledElectionKeptArmed,
    StalledElectionSourceUnsatisfied,
    TerminalDivergenceSuppressedSameLineage,
    TerminalDivergenceSuppressedLaggingGeneration,
    TerminalDivergenceSuppressedBehindPeer,
}

impl StrictTerminalDivergenceEvent {
    fn index(self) -> usize {
        match self {
            Self::ForeignLineageDropped => 0,
            Self::ForeignLineageElectionRequested => 1,
            Self::ForeignLineageElectionDeduped => 2,
            Self::ForcedCheckpointAbandonedWork => 3,
            Self::ForcedCheckpointSent => 4,
            Self::StalledElectionRemoteWon => 5,
            Self::StalledElectionNoCandidate => 6,
            Self::StalledElectionKeptArmed => 7,
            Self::StalledElectionSourceUnsatisfied => 8,
            Self::TerminalDivergenceSuppressedSameLineage => 9,
            Self::TerminalDivergenceSuppressedLaggingGeneration => 10,
            Self::TerminalDivergenceSuppressedBehindPeer => 11,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ForeignLineageDropped => "foreign_lineage_dropped",
            Self::ForeignLineageElectionRequested => "foreign_lineage_election_requested",
            Self::ForeignLineageElectionDeduped => "foreign_lineage_election_deduped",
            Self::ForcedCheckpointAbandonedWork => "forced_checkpoint_abandoned_work",
            Self::ForcedCheckpointSent => "forced_checkpoint_sent",
            Self::StalledElectionRemoteWon => "stalled_election_remote_won",
            Self::StalledElectionNoCandidate => "stalled_election_no_candidate",
            Self::StalledElectionKeptArmed => "stalled_election_kept_armed",
            Self::StalledElectionSourceUnsatisfied => "stalled_election_source_unsatisfied",
            Self::TerminalDivergenceSuppressedSameLineage => {
                "terminal_divergence_suppressed_same_lineage"
            }
            Self::TerminalDivergenceSuppressedLaggingGeneration => {
                "terminal_divergence_suppressed_lagging_generation"
            }
            Self::TerminalDivergenceSuppressedBehindPeer => {
                "terminal_divergence_suppressed_behind_peer"
            }
        }
    }
}

impl StrictCatchupThrottleReason {
    fn index(self) -> usize {
        match self {
            Self::NextHopBytes => 0,
            Self::Backoff => 1,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::NextHopBytes => "next_hop_bytes",
            Self::Backoff => "backoff",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ReplicationPipelineKind {
    Strict,
    Owner,
    Blob,
    Unknown,
}

impl ReplicationPipelineKind {
    fn index(self) -> usize {
        match self {
            Self::Strict => 0,
            Self::Owner => 1,
            Self::Blob => 2,
            Self::Unknown => 3,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Owner => "owner",
            Self::Blob => "blob",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ReplicationPipelineStage {
    InboundDecode,
    Dispatch,
    ProtobufEncode,
    CatchupBuild,
    CatchupApply,
    MsgpackEncode,
    MsgpackDecode,
    RepoApply,
    SnapshotInstall,
    BlobReassemble,
    BlobHash,
    BlobStore,
}

/// Terminal outcome chosen for a stalled strict proposal.
///
/// The labels intentionally describe only the bounded protocol outcome; topic
/// and operation identifiers would create unbounded Prometheus cardinality.
#[derive(Clone, Copy)]
pub(crate) enum StrictResolutionOutcome {
    Commit,
    Abort,
}

/// Bounded phases of the protocol-v8 foreign-lineage recovery coordinator.
///
/// Topics and attempt identifiers are deliberately not metric labels. A live
/// topic registers one [`StrictRecoveryMetrics`] source and scrape-time
/// aggregation reports how many topics occupy each phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictRecoveryPhase {
    Healthy,
    Certifying,
    FetchingTerminalCheckpoint,
    FetchingRepositorySnapshot,
    Prepared,
    Installing,
    Verifying,
    Backoff,
}

impl StrictRecoveryPhase {
    fn index(self) -> usize {
        match self {
            Self::Healthy => 0,
            Self::Certifying => 1,
            Self::FetchingTerminalCheckpoint => 2,
            Self::FetchingRepositorySnapshot => 3,
            Self::Prepared => 4,
            Self::Installing => 5,
            Self::Verifying => 6,
            Self::Backoff => 7,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Certifying => "certifying",
            Self::FetchingTerminalCheckpoint => "fetching_terminal_checkpoint",
            Self::FetchingRepositorySnapshot => "fetching_repository_snapshot",
            Self::Prepared => "prepared",
            Self::Installing => "installing",
            Self::Verifying => "verifying",
            Self::Backoff => "backoff",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictRecoveryTrigger {
    TerminalFence,
    Admission,
    ClockTick,
    Membership,
    DuplicateRequest,
}

impl StrictRecoveryTrigger {
    fn index(self) -> usize {
        match self {
            Self::TerminalFence => 0,
            Self::Admission => 1,
            Self::ClockTick => 2,
            Self::Membership => 3,
            Self::DuplicateRequest => 4,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::TerminalFence => "terminal_fence",
            Self::Admission => "admission",
            Self::ClockTick => "clock_tick",
            Self::Membership => "membership",
            Self::DuplicateRequest => "duplicate_request",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictRecoveryDonorSwitchReason {
    IncarnationLost,
    RouteLost,
    TargetMoved,
    NoProgress,
}

impl StrictRecoveryDonorSwitchReason {
    fn index(self) -> usize {
        match self {
            Self::IncarnationLost => 0,
            Self::RouteLost => 1,
            Self::TargetMoved => 2,
            Self::NoProgress => 3,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::IncarnationLost => "incarnation_lost",
            Self::RouteLost => "route_lost",
            Self::TargetMoved => "target_moved",
            Self::NoProgress => "no_progress",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictRecoveryCertificateFailure {
    NoQuorum,
    ConflictingTarget,
    InvalidAttestation,
    UnsupportedParticipant,
}

impl StrictRecoveryCertificateFailure {
    fn index(self) -> usize {
        match self {
            Self::NoQuorum => 0,
            Self::ConflictingTarget => 1,
            Self::InvalidAttestation => 2,
            Self::UnsupportedParticipant => 3,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::NoQuorum => "no_quorum",
            Self::ConflictingTarget => "conflicting_target",
            Self::InvalidAttestation => "invalid_attestation",
            Self::UnsupportedParticipant => "unsupported_participant",
        }
    }
}

/// Bounded classes of attempt-correlated callbacks ignored as stale.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictRecoveryStaleEvent {
    Probe,
    TerminalPage,
    SnapshotPage,
    Retry,
    Install,
}

impl StrictRecoveryStaleEvent {
    fn index(self) -> usize {
        match self {
            Self::Probe => 0,
            Self::TerminalPage => 1,
            Self::SnapshotPage => 2,
            Self::Retry => 3,
            Self::Install => 4,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::TerminalPage => "terminal_page",
            Self::SnapshotPage => "snapshot_page",
            Self::Retry => "retry",
            Self::Install => "install",
        }
    }
}

impl StrictResolutionOutcome {
    fn index(self) -> usize {
        match self {
            Self::Commit => 0,
            Self::Abort => 1,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Abort => "abort",
        }
    }
}

impl ReplicationPipelineStage {
    fn index(self) -> usize {
        match self {
            Self::InboundDecode => 0,
            Self::Dispatch => 1,
            Self::ProtobufEncode => 2,
            Self::CatchupBuild => 3,
            Self::CatchupApply => 4,
            Self::MsgpackEncode => 5,
            Self::MsgpackDecode => 6,
            Self::RepoApply => 7,
            Self::SnapshotInstall => 8,
            Self::BlobReassemble => 9,
            Self::BlobHash => 10,
            Self::BlobStore => 11,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::InboundDecode => "inbound_decode",
            Self::Dispatch => "dispatch",
            Self::ProtobufEncode => "protobuf_encode",
            Self::CatchupBuild => "catchup_build",
            Self::CatchupApply => "catchup_apply",
            Self::MsgpackEncode => "msgpack_encode",
            Self::MsgpackDecode => "msgpack_decode",
            Self::RepoApply => "repo_apply",
            Self::SnapshotInstall => "snapshot_install",
            Self::BlobReassemble => "blob_reassemble",
            Self::BlobHash => "blob_hash",
            Self::BlobStore => "blob_store",
        }
    }
}

const CATCHUP_MODE_COUNT: usize = 2;
const CATCHUP_REASON_COUNT: usize = 9;
const CATCHUP_PHASE_COUNT: usize = 6;
const CATCHUP_LOGICAL_METRIC_COUNT: usize =
    CATCHUP_MODE_COUNT * CATCHUP_REASON_COUNT * CATCHUP_PHASE_COUNT;
const STRICT_CATCHUP_SESSION_OUTCOME_COUNT: usize = 6;
const STRICT_CATCHUP_SESSION_EVENT_COUNT: usize = 4;
const STRICT_CATCHUP_LANE_COUNT: usize = 2;
const STRICT_CATCHUP_SEND_OUTCOME_COUNT: usize = 5;
const STRICT_CATCHUP_SEND_METRIC_COUNT: usize = CATCHUP_REASON_COUNT
    * CATCHUP_PHASE_COUNT
    * STRICT_CATCHUP_LANE_COUNT
    * STRICT_CATCHUP_SEND_OUTCOME_COUNT;
const STRICT_CATCHUP_DUPLICATE_OUTCOME_COUNT: usize = 2;
const STRICT_SNAPSHOT_RECEIVE_EVENT_COUNT: usize = 18;
const STRICT_SNAPSHOT_RESPONDER_EVENT_COUNT: usize = 13;
const STRICT_CATCHUP_BACKPRESSURE_EVENT_COUNT: usize = 3;
const STRICT_CATCHUP_BACKPRESSURE_METRIC_COUNT: usize =
    CATCHUP_REASON_COUNT * CATCHUP_PHASE_COUNT * STRICT_CATCHUP_BACKPRESSURE_EVENT_COUNT;
// Only expose throttle causes backed by an actual admission decision. Peer
// coalescing is reported as a session event, and there is currently no global
// session limiter; publishing either as a zero-valued throttle would imply a
// control that does not exist.
const STRICT_CATCHUP_THROTTLE_REASON_COUNT: usize = 2;
const STRICT_PROBE_KIND_COUNT: usize = 2;
const STRICT_PROBE_OUTCOME_COUNT: usize = 8;
const STRICT_PROBE_METRIC_COUNT: usize =
    STRICT_PROBE_KIND_COUNT * CATCHUP_REASON_COUNT * STRICT_PROBE_OUTCOME_COUNT;
const STRICT_ADMISSION_EVENT_COUNT: usize = 8;
const STRICT_HISTORY_ELECTION_EVENT_COUNT: usize = 8;
const STRICT_HEAD_EVENT_COUNT: usize = 10;
const STRICT_TERMINAL_DIVERGENCE_EVENT_COUNT: usize = 12;
const STRICT_RECOVERY_PHASE_COUNT: usize = 8;
const STRICT_RECOVERY_TRIGGER_COUNT: usize = 5;
const STRICT_RECOVERY_DONOR_SWITCH_REASON_COUNT: usize = 4;
const STRICT_RECOVERY_CERTIFICATE_FAILURE_COUNT: usize = 4;
const STRICT_RECOVERY_STALE_EVENT_COUNT: usize = 5;
const CATCHUP_REASONS: [CatchupReason; CATCHUP_REASON_COUNT] = [
    CatchupReason::HistoryElection,
    CatchupReason::Admission,
    CatchupReason::SteadyState,
    CatchupReason::TerminalFence,
    CatchupReason::DeliveryWatermark,
    CatchupReason::PeerBehind,
    CatchupReason::RepositoryGap,
    CatchupReason::LegacyV2,
    CatchupReason::OwnerAntiEntropy,
];
const CATCHUP_PHASES: [CatchupPhase; CATCHUP_PHASE_COUNT] = [
    CatchupPhase::Metadata,
    CatchupPhase::TerminalDelta,
    CatchupPhase::TerminalCheckpoint,
    CatchupPhase::LogDelta,
    CatchupPhase::Snapshot,
    CatchupPhase::FinalAck,
];
const STRICT_CATCHUP_SESSION_OUTCOMES: [StrictCatchupSessionOutcome;
    STRICT_CATCHUP_SESSION_OUTCOME_COUNT] = [
    StrictCatchupSessionOutcome::Completed,
    StrictCatchupSessionOutcome::Failed,
    StrictCatchupSessionOutcome::Cancelled,
    StrictCatchupSessionOutcome::Expired,
    StrictCatchupSessionOutcome::IncarnationMismatch,
    StrictCatchupSessionOutcome::ResourceLimit,
];
const ALL_STRICT_CATCHUP_SESSION_EVENTS: [StrictCatchupSessionEvent;
    STRICT_CATCHUP_SESSION_EVENT_COUNT] = [
    StrictCatchupSessionEvent::Coalesced,
    StrictCatchupSessionEvent::DirtyRefresh,
    StrictCatchupSessionEvent::Restart,
    StrictCatchupSessionEvent::FinalAck,
];
const STRICT_CATCHUP_LANES: [StrictCatchupLane; STRICT_CATCHUP_LANE_COUNT] =
    [StrictCatchupLane::Control, StrictCatchupLane::Bulk];
const STRICT_CATCHUP_SEND_OUTCOMES: [StrictCatchupSendOutcome; STRICT_CATCHUP_SEND_OUTCOME_COUNT] = [
    StrictCatchupSendOutcome::Enqueued,
    StrictCatchupSendOutcome::Backpressured,
    StrictCatchupSendOutcome::RetryEnqueued,
    StrictCatchupSendOutcome::Exhausted,
    StrictCatchupSendOutcome::Rejected,
];
const STRICT_CATCHUP_DUPLICATE_OUTCOMES: [StrictCatchupDuplicateOutcome;
    STRICT_CATCHUP_DUPLICATE_OUTCOME_COUNT] = [
    StrictCatchupDuplicateOutcome::Suppressed,
    StrictCatchupDuplicateOutcome::CachedReplay,
];
const STRICT_SNAPSHOT_RECEIVE_EVENTS: [StrictSnapshotReceiveEvent;
    STRICT_SNAPSHOT_RECEIVE_EVENT_COUNT] = [
    StrictSnapshotReceiveEvent::Continued,
    StrictSnapshotReceiveEvent::Completed,
    StrictSnapshotReceiveEvent::DuplicateActive,
    StrictSnapshotReceiveEvent::StaleIdle,
    StrictSnapshotReceiveEvent::StaleForeignTransfer,
    StrictSnapshotReceiveEvent::StaleMissingReceiver,
    StrictSnapshotReceiveEvent::CompletionRetried,
    StrictSnapshotReceiveEvent::AmbiguousLegacy,
    StrictSnapshotReceiveEvent::SourceRejected,
    StrictSnapshotReceiveEvent::RestartInvalidEnvelope,
    StrictSnapshotReceiveEvent::RestartInvalidCursor,
    StrictSnapshotReceiveEvent::RestartFormatMismatch,
    StrictSnapshotReceiveEvent::RestartMetadataMismatch,
    StrictSnapshotReceiveEvent::RestartChunkOrder,
    StrictSnapshotReceiveEvent::RestartResourceLimit,
    StrictSnapshotReceiveEvent::RestartDigestMismatch,
    StrictSnapshotReceiveEvent::RestartExpiredReceiver,
    StrictSnapshotReceiveEvent::RestartMissingState,
];
const STRICT_SNAPSHOT_RESPONDER_EVENTS: [StrictSnapshotResponderEvent;
    STRICT_SNAPSHOT_RESPONDER_EVENT_COUNT] = [
    StrictSnapshotResponderEvent::ImagePagePrepared,
    StrictSnapshotResponderEvent::InitialPagePrepared,
    StrictSnapshotResponderEvent::ContinuationPrepared,
    StrictSnapshotResponderEvent::CompletionAcknowledged,
    StrictSnapshotResponderEvent::StaleTransferIgnored,
    StrictSnapshotResponderEvent::StaleTransferRejected,
    StrictSnapshotResponderEvent::InvalidCursorIgnored,
    StrictSnapshotResponderEvent::InvalidCursorRejected,
    StrictSnapshotResponderEvent::MissingTransferRejected,
    StrictSnapshotResponderEvent::TransferRejected,
    StrictSnapshotResponderEvent::FenceInvalidated,
    StrictSnapshotResponderEvent::ResponseSendFailed,
    StrictSnapshotResponderEvent::ResponseSuppressed,
];
const ALL_STRICT_CATCHUP_BACKPRESSURE_EVENTS: [StrictCatchupBackpressureEvent;
    STRICT_CATCHUP_BACKPRESSURE_EVENT_COUNT] = [
    StrictCatchupBackpressureEvent::Backpressured,
    StrictCatchupBackpressureEvent::Retry,
    StrictCatchupBackpressureEvent::ExhaustedRetry,
];
const STRICT_CATCHUP_THROTTLE_REASONS: [StrictCatchupThrottleReason;
    STRICT_CATCHUP_THROTTLE_REASON_COUNT] = [
    StrictCatchupThrottleReason::NextHopBytes,
    StrictCatchupThrottleReason::Backoff,
];
const STRICT_PROBE_KINDS: [StrictProbeKind; STRICT_PROBE_KIND_COUNT] =
    [StrictProbeKind::Clock, StrictProbeKind::History];
const STRICT_PROBE_OUTCOMES: [StrictProbeOutcome; STRICT_PROBE_OUTCOME_COUNT] = [
    StrictProbeOutcome::Sent,
    StrictProbeOutcome::Coalesced,
    StrictProbeOutcome::RetryRestored,
    StrictProbeOutcome::Accepted,
    StrictProbeOutcome::RejectedPeer,
    StrictProbeOutcome::RejectedEnvelope,
    StrictProbeOutcome::IgnoredNonce,
    StrictProbeOutcome::RejectedPayload,
];
const STRICT_ADMISSION_EVENTS: [StrictAdmissionEvent; STRICT_ADMISSION_EVENT_COUNT] = [
    StrictAdmissionEvent::Started,
    StrictAdmissionEvent::Revoked,
    StrictAdmissionEvent::CutFrozen,
    StrictAdmissionEvent::HistoryProofAccepted,
    StrictAdmissionEvent::HistoryProofTerminalMismatch,
    StrictAdmissionEvent::ClockProofAccepted,
    StrictAdmissionEvent::ClockProofBelowBarrier,
    StrictAdmissionEvent::Admitted,
];
const STRICT_HISTORY_ELECTION_EVENTS: [StrictHistoryElectionEvent;
    STRICT_HISTORY_ELECTION_EVENT_COUNT] = [
    StrictHistoryElectionEvent::Started,
    StrictHistoryElectionEvent::ResponsePending,
    StrictHistoryElectionEvent::LocalWon,
    StrictHistoryElectionEvent::RemoteWon,
    StrictHistoryElectionEvent::SnapshotStarted,
    StrictHistoryElectionEvent::Finished,
    StrictHistoryElectionEvent::Rearmed,
    StrictHistoryElectionEvent::TimedOut,
];
const STRICT_HEAD_EVENTS: [StrictHeadEvent; STRICT_HEAD_EVENT_COUNT] = [
    StrictHeadEvent::EvidenceChanged,
    StrictHeadEvent::EvidenceRepositoryVersionMismatch,
    StrictHeadEvent::EvidenceFreshnessMismatch,
    StrictHeadEvent::EvidenceTerminalDigestMismatch,
    StrictHeadEvent::EvidenceJournalLineageMismatch,
    StrictHeadEvent::AckAccepted,
    StrictHeadEvent::AckRejectedEnvelope,
    StrictHeadEvent::AckRejectedDigest,
    StrictHeadEvent::AckRejectedIdentity,
    StrictHeadEvent::TickAttempted,
];
const STRICT_TERMINAL_DIVERGENCE_EVENTS: [StrictTerminalDivergenceEvent;
    STRICT_TERMINAL_DIVERGENCE_EVENT_COUNT] = [
    StrictTerminalDivergenceEvent::ForeignLineageDropped,
    StrictTerminalDivergenceEvent::ForeignLineageElectionRequested,
    StrictTerminalDivergenceEvent::ForeignLineageElectionDeduped,
    StrictTerminalDivergenceEvent::ForcedCheckpointAbandonedWork,
    StrictTerminalDivergenceEvent::ForcedCheckpointSent,
    StrictTerminalDivergenceEvent::StalledElectionRemoteWon,
    StrictTerminalDivergenceEvent::StalledElectionNoCandidate,
    StrictTerminalDivergenceEvent::StalledElectionKeptArmed,
    StrictTerminalDivergenceEvent::StalledElectionSourceUnsatisfied,
    StrictTerminalDivergenceEvent::TerminalDivergenceSuppressedSameLineage,
    StrictTerminalDivergenceEvent::TerminalDivergenceSuppressedLaggingGeneration,
    StrictTerminalDivergenceEvent::TerminalDivergenceSuppressedBehindPeer,
];
const STRICT_RECOVERY_PHASES: [StrictRecoveryPhase; STRICT_RECOVERY_PHASE_COUNT] = [
    StrictRecoveryPhase::Healthy,
    StrictRecoveryPhase::Certifying,
    StrictRecoveryPhase::FetchingTerminalCheckpoint,
    StrictRecoveryPhase::FetchingRepositorySnapshot,
    StrictRecoveryPhase::Prepared,
    StrictRecoveryPhase::Installing,
    StrictRecoveryPhase::Verifying,
    StrictRecoveryPhase::Backoff,
];
const STRICT_RECOVERY_TRIGGERS: [StrictRecoveryTrigger; STRICT_RECOVERY_TRIGGER_COUNT] = [
    StrictRecoveryTrigger::TerminalFence,
    StrictRecoveryTrigger::Admission,
    StrictRecoveryTrigger::ClockTick,
    StrictRecoveryTrigger::Membership,
    StrictRecoveryTrigger::DuplicateRequest,
];
const STRICT_RECOVERY_DONOR_SWITCH_REASONS: [StrictRecoveryDonorSwitchReason;
    STRICT_RECOVERY_DONOR_SWITCH_REASON_COUNT] = [
    StrictRecoveryDonorSwitchReason::IncarnationLost,
    StrictRecoveryDonorSwitchReason::RouteLost,
    StrictRecoveryDonorSwitchReason::TargetMoved,
    StrictRecoveryDonorSwitchReason::NoProgress,
];
const STRICT_RECOVERY_CERTIFICATE_FAILURES: [StrictRecoveryCertificateFailure;
    STRICT_RECOVERY_CERTIFICATE_FAILURE_COUNT] = [
    StrictRecoveryCertificateFailure::NoQuorum,
    StrictRecoveryCertificateFailure::ConflictingTarget,
    StrictRecoveryCertificateFailure::InvalidAttestation,
    StrictRecoveryCertificateFailure::UnsupportedParticipant,
];
const STRICT_RECOVERY_STALE_EVENTS: [StrictRecoveryStaleEvent; STRICT_RECOVERY_STALE_EVENT_COUNT] = [
    StrictRecoveryStaleEvent::Probe,
    StrictRecoveryStaleEvent::TerminalPage,
    StrictRecoveryStaleEvent::SnapshotPage,
    StrictRecoveryStaleEvent::Retry,
    StrictRecoveryStaleEvent::Install,
];
const REPLICATION_PIPELINE_KIND_COUNT: usize = 4;
const REPLICATION_PIPELINE_STAGE_COUNT: usize = 12;
const STRICT_RESOLUTION_OUTCOME_COUNT: usize = 2;
const REPLICATION_PIPELINE_KINDS: [ReplicationPipelineKind; REPLICATION_PIPELINE_KIND_COUNT] = [
    ReplicationPipelineKind::Strict,
    ReplicationPipelineKind::Owner,
    ReplicationPipelineKind::Blob,
    ReplicationPipelineKind::Unknown,
];
const REPLICATION_PIPELINE_STAGES: [ReplicationPipelineStage; REPLICATION_PIPELINE_STAGE_COUNT] = [
    ReplicationPipelineStage::InboundDecode,
    ReplicationPipelineStage::Dispatch,
    ReplicationPipelineStage::ProtobufEncode,
    ReplicationPipelineStage::CatchupBuild,
    ReplicationPipelineStage::CatchupApply,
    ReplicationPipelineStage::MsgpackEncode,
    ReplicationPipelineStage::MsgpackDecode,
    ReplicationPipelineStage::RepoApply,
    ReplicationPipelineStage::SnapshotInstall,
    ReplicationPipelineStage::BlobReassemble,
    ReplicationPipelineStage::BlobHash,
    ReplicationPipelineStage::BlobStore,
];
const CLIENT_QUEUE_BUCKETS_US: [(&str, u64); 7] = [
    ("le_1000", 1_000),
    ("le_10000", 10_000),
    ("le_50000", 50_000),
    ("le_250000", 250_000),
    ("le_1000000", 1_000_000),
    ("le_5000000", 5_000_000),
    ("gt_5000000", u64::MAX),
];

static CATCHUP_REQUESTS: [AtomicU64; CATCHUP_LOGICAL_METRIC_COUNT] =
    [const { AtomicU64::new(0) }; CATCHUP_LOGICAL_METRIC_COUNT];
static CATCHUP_RESPONSES: [AtomicU64; CATCHUP_LOGICAL_METRIC_COUNT] =
    [const { AtomicU64::new(0) }; CATCHUP_LOGICAL_METRIC_COUNT];
static CATCHUP_RESPONSE_OPS: [AtomicU64; CATCHUP_LOGICAL_METRIC_COUNT] =
    [const { AtomicU64::new(0) }; CATCHUP_LOGICAL_METRIC_COUNT];
static CATCHUP_RESPONSE_BYTES: [AtomicU64; CATCHUP_LOGICAL_METRIC_COUNT] =
    [const { AtomicU64::new(0) }; CATCHUP_LOGICAL_METRIC_COUNT];
static CATCHUP_SUPPRESSED: [AtomicU64; CATCHUP_LOGICAL_METRIC_COUNT] =
    [const { AtomicU64::new(0) }; CATCHUP_LOGICAL_METRIC_COUNT];
static CATCHUP_ACTIVE: AtomicUsize = AtomicUsize::new(0);

static STRICT_CATCHUP_SESSION_STARTS: [AtomicU64; CATCHUP_REASON_COUNT] =
    [const { AtomicU64::new(0) }; CATCHUP_REASON_COUNT];
static STRICT_CATCHUP_SESSION_COMPLETIONS: [AtomicU64;
    CATCHUP_REASON_COUNT * STRICT_CATCHUP_SESSION_OUTCOME_COUNT] =
    [const { AtomicU64::new(0) }; CATCHUP_REASON_COUNT * STRICT_CATCHUP_SESSION_OUTCOME_COUNT];
static STRICT_CATCHUP_SESSION_ACTIVE: [AtomicUsize; CATCHUP_REASON_COUNT] =
    [const { AtomicUsize::new(0) }; CATCHUP_REASON_COUNT];
static STRICT_CATCHUP_SESSION_EVENTS: [AtomicU64;
    CATCHUP_REASON_COUNT * STRICT_CATCHUP_SESSION_EVENT_COUNT] =
    [const { AtomicU64::new(0) }; CATCHUP_REASON_COUNT * STRICT_CATCHUP_SESSION_EVENT_COUNT];
static STRICT_CATCHUP_SEND_ATTEMPTS: [AtomicU64; STRICT_CATCHUP_SEND_METRIC_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_CATCHUP_SEND_METRIC_COUNT];
static STRICT_CATCHUP_SEND_BYTES: [AtomicU64; STRICT_CATCHUP_SEND_METRIC_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_CATCHUP_SEND_METRIC_COUNT];
static STRICT_CATCHUP_DUPLICATES: [AtomicU64; STRICT_CATCHUP_DUPLICATE_OUTCOME_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_CATCHUP_DUPLICATE_OUTCOME_COUNT];
static STRICT_SNAPSHOT_RECEIVE_EVENTS_TOTAL: [AtomicU64; STRICT_SNAPSHOT_RECEIVE_EVENT_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_SNAPSHOT_RECEIVE_EVENT_COUNT];
static STRICT_SNAPSHOT_RESPONDER_EVENTS_TOTAL: [AtomicU64; STRICT_SNAPSHOT_RESPONDER_EVENT_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_SNAPSHOT_RESPONDER_EVENT_COUNT];
static STRICT_CATCHUP_BACKPRESSURE_EVENTS: [AtomicU64; STRICT_CATCHUP_BACKPRESSURE_METRIC_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_CATCHUP_BACKPRESSURE_METRIC_COUNT];
static STRICT_CATCHUP_BACKOFF_DELAY_MS: [AtomicU64; CATCHUP_REASON_COUNT * CATCHUP_PHASE_COUNT] =
    [const { AtomicU64::new(0) }; CATCHUP_REASON_COUNT * CATCHUP_PHASE_COUNT];
static STRICT_CATCHUP_BULK_IN_FLIGHT_BYTES: AtomicUsize = AtomicUsize::new(0);
static STRICT_CATCHUP_THROTTLED: [AtomicU64; STRICT_CATCHUP_THROTTLE_REASON_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_CATCHUP_THROTTLE_REASON_COUNT];
static STRICT_PROBE_EVENTS: [AtomicU64; STRICT_PROBE_METRIC_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_PROBE_METRIC_COUNT];
static STRICT_ADMISSION_EVENTS_TOTAL: [AtomicU64; STRICT_ADMISSION_EVENT_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_ADMISSION_EVENT_COUNT];
static STRICT_HISTORY_ELECTION_EVENTS_TOTAL: [AtomicU64; STRICT_HISTORY_ELECTION_EVENT_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_HISTORY_ELECTION_EVENT_COUNT];
static STRICT_HEAD_EVENTS_TOTAL: [AtomicU64; STRICT_HEAD_EVENT_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_HEAD_EVENT_COUNT];
static STRICT_TERMINAL_DIVERGENCE_EVENTS_TOTAL: [AtomicU64;
    STRICT_TERMINAL_DIVERGENCE_EVENT_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_TERMINAL_DIVERGENCE_EVENT_COUNT];
static STRICT_RECOVERY_ATTEMPTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static STRICT_RECOVERY_COALESCED_TRIGGERS_TOTAL: [AtomicU64; STRICT_RECOVERY_TRIGGER_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_RECOVERY_TRIGGER_COUNT];
static STRICT_RECOVERY_RETRANSMITS_TOTAL: [AtomicU64; STRICT_RECOVERY_PHASE_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_RECOVERY_PHASE_COUNT];
static STRICT_RECOVERY_DONOR_SWITCHES_TOTAL: [AtomicU64;
    STRICT_RECOVERY_DONOR_SWITCH_REASON_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_RECOVERY_DONOR_SWITCH_REASON_COUNT];
static STRICT_RECOVERY_CERTIFICATE_FAILURES_TOTAL: [AtomicU64;
    STRICT_RECOVERY_CERTIFICATE_FAILURE_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_RECOVERY_CERTIFICATE_FAILURE_COUNT];
static STRICT_RECOVERY_STALE_EVENTS_TOTAL: [AtomicU64; STRICT_RECOVERY_STALE_EVENT_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_RECOVERY_STALE_EVENT_COUNT];
static STRICT_RECOVERY_COMPLETION_DURATION_MS_TOTAL: AtomicU64 = AtomicU64::new(0);
static STRICT_RECOVERY_COMPLETION_DURATION_COUNT: AtomicU64 = AtomicU64::new(0);
static STRICT_RECOVERY_SEND_ATTEMPTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static STRICT_RECOVERY_SEND_BYTES_TOTAL: AtomicU64 = AtomicU64::new(0);

static REPLICATION_PIPELINE_STAGE_EVENTS: [[AtomicU64; REPLICATION_PIPELINE_STAGE_COUNT];
    REPLICATION_PIPELINE_KIND_COUNT] =
    [const { [const { AtomicU64::new(0) }; REPLICATION_PIPELINE_STAGE_COUNT] };
        REPLICATION_PIPELINE_KIND_COUNT];
static REPLICATION_PIPELINE_STAGE_DURATION_TOTAL_US: [[AtomicU64;
    REPLICATION_PIPELINE_STAGE_COUNT];
    REPLICATION_PIPELINE_KIND_COUNT] =
    [const { [const { AtomicU64::new(0) }; REPLICATION_PIPELINE_STAGE_COUNT] };
        REPLICATION_PIPELINE_KIND_COUNT];
static REPLICATION_PIPELINE_STAGE_DURATION_BUCKETS: [[[AtomicU64; CLIENT_QUEUE_BUCKETS_US.len()];
    REPLICATION_PIPELINE_STAGE_COUNT];
    REPLICATION_PIPELINE_KIND_COUNT] = [const {
    [const { [const { AtomicU64::new(0) }; CLIENT_QUEUE_BUCKETS_US.len()] };
        REPLICATION_PIPELINE_STAGE_COUNT]
}; REPLICATION_PIPELINE_KIND_COUNT];

static CLIENT_REPLICATION_QUEUE_DEPTH: AtomicUsize = AtomicUsize::new(0);
static CLIENT_REPLICATION_QUEUE_WAIT_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static CLIENT_REPLICATION_QUEUE_WAIT_SAMPLES: AtomicU64 = AtomicU64::new(0);
static CLIENT_REPLICATION_QUEUE_WAIT_BUCKETS: [AtomicU64; CLIENT_QUEUE_BUCKETS_US.len()] =
    [const { AtomicU64::new(0) }; CLIENT_QUEUE_BUCKETS_US.len()];

// These values are refreshed from the negotiated, alive-member capability
// snapshot. They are local observations of cluster state, rather than
// per-topic state, so they deliberately carry no topic or peer labels.
static STRICT_REPLICATION_CLUSTER_PROTOCOL_VERSION: AtomicU32 = AtomicU32::new(0);
static STRICT_REPLICATION_TERMINAL_RESOLUTION_READY: AtomicBool = AtomicBool::new(false);
static STRICT_REPLICATION_UNSUPPORTED_ACTIVE_PEERS: AtomicUsize = AtomicUsize::new(0);
static STRICT_REPLICATION_TERMINAL_DECISIONS: [AtomicU64; STRICT_RESOLUTION_OUTCOME_COUNT] =
    [const { AtomicU64::new(0) }; STRICT_RESOLUTION_OUTCOME_COUNT];
static STRICT_REPLICATION_FENCE_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static STRICT_ADMISSION_METRIC_SOURCES: LazyLock<Mutex<Vec<Weak<StrictAdmissionMetrics>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));
static STRICT_RECOVERY_METRIC_SOURCES: LazyLock<Mutex<Vec<Weak<StrictRecoveryMetrics>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));
static STRICT_RECOVERY_METRIC_CLOCK: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Per-topic recovery gauges aggregated without exposing topic cardinality.
pub(crate) struct StrictRecoveryMetrics {
    phase: AtomicUsize,
    /// Milliseconds since the process-local metric epoch, plus one. Zero means
    /// the topic is healthy and has no active progress deadline.
    last_progress_ms: AtomicU64,
    donor_terminal_sessions: AtomicUsize,
    donor_snapshot_sessions: AtomicUsize,
}

impl Default for StrictRecoveryMetrics {
    fn default() -> Self {
        Self {
            phase: AtomicUsize::new(StrictRecoveryPhase::Healthy.index()),
            last_progress_ms: AtomicU64::new(0),
            donor_terminal_sessions: AtomicUsize::new(0),
            donor_snapshot_sessions: AtomicUsize::new(0),
        }
    }
}

impl StrictRecoveryMetrics {
    /// Changes the topic's recovery phase and starts that phase's progress
    /// clock. Subsequent refreshes must use [`Self::record_authenticated_progress`].
    pub(crate) fn set_phase(&self, phase: StrictRecoveryPhase) {
        let progress_ms = if phase == StrictRecoveryPhase::Healthy {
            0
        } else {
            strict_recovery_now_ms()
        };
        self.last_progress_ms.store(progress_ms, Ordering::Relaxed);
        self.phase.store(phase.index(), Ordering::Release);
    }

    /// Refreshes progress age after authenticated progress for the current
    /// attempt. Coalesced triggers, route activity, and unauthenticated frames
    /// must not call this method.
    pub(crate) fn record_authenticated_progress(&self) {
        if self.phase.load(Ordering::Acquire) != StrictRecoveryPhase::Healthy.index() {
            self.last_progress_ms
                .store(strict_recovery_now_ms(), Ordering::Relaxed);
        }
    }

    pub(crate) fn set_donor_sessions(&self, terminal: usize, snapshot: usize) {
        self.donor_terminal_sessions
            .store(terminal, Ordering::Relaxed);
        self.donor_snapshot_sessions
            .store(snapshot, Ordering::Relaxed);
    }

    fn snapshot(&self, now_ms: u64) -> (StrictRecoveryPhase, u64, usize, usize) {
        let phase_index = self.phase.load(Ordering::Acquire);
        let phase = STRICT_RECOVERY_PHASES
            .get(phase_index)
            .copied()
            .unwrap_or(StrictRecoveryPhase::Healthy);
        let last_progress_ms = self.last_progress_ms.load(Ordering::Relaxed);
        let progress_age_ms = if phase == StrictRecoveryPhase::Healthy || last_progress_ms == 0 {
            0
        } else {
            now_ms.saturating_sub(last_progress_ms)
        };
        (
            phase,
            progress_age_ms,
            self.donor_terminal_sessions.load(Ordering::Relaxed),
            self.donor_snapshot_sessions.load(Ordering::Relaxed),
        )
    }

    #[cfg(test)]
    pub(crate) fn progress_marker_for_test(&self) -> u64 {
        self.last_progress_ms.load(Ordering::Relaxed)
    }
}

fn strict_recovery_now_ms() -> u64 {
    STRICT_RECOVERY_METRIC_CLOCK
        .elapsed()
        .as_millis()
        .min((u64::MAX - 1) as u128) as u64
        + 1
}

pub(crate) fn register_strict_recovery_metrics(
    initial_phase: StrictRecoveryPhase,
) -> Arc<StrictRecoveryMetrics> {
    let source = Arc::new(StrictRecoveryMetrics::default());
    source.set_phase(initial_phase);
    STRICT_RECOVERY_METRIC_SOURCES
        .lock()
        .unwrap()
        .push(Arc::downgrade(&source));
    source
}

/// Per-runtime admission gauges aggregated at scrape time.
///
/// A process can host multiple strict topics. Weak sources let the exported
/// metrics combine every live runtime without a topic label or stale values
/// after a runtime is dropped.
#[derive(Default)]
pub(crate) struct StrictAdmissionMetrics {
    admitted: AtomicUsize,
    awaiting_local_cut: AtomicUsize,
    awaiting_peer: AtomicUsize,
    highest_barrier: AtomicU64,
    awaiting_history_only: AtomicUsize,
    awaiting_clock_only: AtomicUsize,
    awaiting_both_proofs: AtomicUsize,
    clock_demand_commit_buffer: AtomicBool,
    clock_demand_proposal: AtomicBool,
    clock_demand_missing_peer_clocks: AtomicUsize,
    unacknowledged_head_peers: AtomicUsize,
}

impl StrictAdmissionMetrics {
    pub(crate) fn update(
        &self,
        admitted: usize,
        awaiting_local_cut: usize,
        awaiting_peer: usize,
        highest_barrier: u64,
    ) {
        self.admitted.store(admitted, Ordering::Relaxed);
        self.awaiting_local_cut
            .store(awaiting_local_cut, Ordering::Relaxed);
        self.awaiting_peer.store(awaiting_peer, Ordering::Relaxed);
        self.highest_barrier
            .store(highest_barrier, Ordering::Relaxed);
    }

    pub(crate) fn update_proof_waits(
        &self,
        awaiting_history_only: usize,
        awaiting_clock_only: usize,
        awaiting_both_proofs: usize,
    ) {
        self.awaiting_history_only
            .store(awaiting_history_only, Ordering::Relaxed);
        self.awaiting_clock_only
            .store(awaiting_clock_only, Ordering::Relaxed);
        self.awaiting_both_proofs
            .store(awaiting_both_proofs, Ordering::Relaxed);
    }

    pub(crate) fn update_clock_demand(
        &self,
        commit_buffer: bool,
        proposal: bool,
        missing_peer_clocks: usize,
        unacknowledged_head_peers: usize,
    ) {
        self.clock_demand_commit_buffer
            .store(commit_buffer, Ordering::Relaxed);
        self.clock_demand_proposal
            .store(proposal, Ordering::Relaxed);
        self.clock_demand_missing_peer_clocks
            .store(missing_peer_clocks, Ordering::Relaxed);
        self.unacknowledged_head_peers
            .store(unacknowledged_head_peers, Ordering::Relaxed);
    }

    fn snapshot(&self) -> StrictAdmissionMetricSnapshot {
        StrictAdmissionMetricSnapshot {
            admitted: self.admitted.load(Ordering::Relaxed),
            awaiting_local_cut: self.awaiting_local_cut.load(Ordering::Relaxed),
            awaiting_peer: self.awaiting_peer.load(Ordering::Relaxed),
            highest_barrier: self.highest_barrier.load(Ordering::Relaxed),
            awaiting_history_only: self.awaiting_history_only.load(Ordering::Relaxed),
            awaiting_clock_only: self.awaiting_clock_only.load(Ordering::Relaxed),
            awaiting_both_proofs: self.awaiting_both_proofs.load(Ordering::Relaxed),
            clock_demand_commit_buffer: self.clock_demand_commit_buffer.load(Ordering::Relaxed)
                as usize,
            clock_demand_proposal: self.clock_demand_proposal.load(Ordering::Relaxed) as usize,
            clock_demand_missing_peer_clocks: self
                .clock_demand_missing_peer_clocks
                .load(Ordering::Relaxed),
            unacknowledged_head_peers: self.unacknowledged_head_peers.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct StrictAdmissionMetricSnapshot {
    admitted: usize,
    awaiting_local_cut: usize,
    awaiting_peer: usize,
    highest_barrier: u64,
    awaiting_history_only: usize,
    awaiting_clock_only: usize,
    awaiting_both_proofs: usize,
    clock_demand_commit_buffer: usize,
    clock_demand_proposal: usize,
    clock_demand_missing_peer_clocks: usize,
    unacknowledged_head_peers: usize,
}

pub(crate) fn register_strict_admission_metrics() -> Arc<StrictAdmissionMetrics> {
    let source = Arc::new(StrictAdmissionMetrics {
        admitted: AtomicUsize::new(0),
        awaiting_local_cut: AtomicUsize::new(0),
        awaiting_peer: AtomicUsize::new(0),
        highest_barrier: AtomicU64::new(0),
        awaiting_history_only: AtomicUsize::new(0),
        awaiting_clock_only: AtomicUsize::new(0),
        awaiting_both_proofs: AtomicUsize::new(0),
        clock_demand_commit_buffer: AtomicBool::new(false),
        clock_demand_proposal: AtomicBool::new(false),
        clock_demand_missing_peer_clocks: AtomicUsize::new(0),
        unacknowledged_head_peers: AtomicUsize::new(0),
    });
    STRICT_ADMISSION_METRIC_SOURCES
        .lock()
        .unwrap()
        .push(Arc::downgrade(&source));
    source
}

fn increment(value: &AtomicU64, amount: u64) {
    value.fetch_add(amount, Ordering::Relaxed);
}

fn observe_bucket(buckets: &[AtomicU64], definitions: &[(&str, u64)], value: u64) {
    if let Some((index, _)) = definitions
        .iter()
        .enumerate()
        .find(|(_, (_, upper_bound))| value <= *upper_bound)
    {
        increment(&buckets[index], 1);
    }
}

fn catchup_logical_index(mode: CatchupMode, reason: CatchupReason, phase: CatchupPhase) -> usize {
    (mode.index() * CATCHUP_REASON_COUNT + reason.index()) * CATCHUP_PHASE_COUNT + phase.index()
}

fn strict_session_completion_index(
    reason: CatchupReason,
    outcome: StrictCatchupSessionOutcome,
) -> usize {
    reason.index() * STRICT_CATCHUP_SESSION_OUTCOME_COUNT + outcome.index()
}

fn strict_session_event_index(reason: CatchupReason, event: StrictCatchupSessionEvent) -> usize {
    reason.index() * STRICT_CATCHUP_SESSION_EVENT_COUNT + event.index()
}

fn strict_send_index(
    reason: CatchupReason,
    phase: CatchupPhase,
    lane: StrictCatchupLane,
    outcome: StrictCatchupSendOutcome,
) -> usize {
    (((reason.index() * CATCHUP_PHASE_COUNT + phase.index()) * STRICT_CATCHUP_LANE_COUNT
        + lane.index())
        * STRICT_CATCHUP_SEND_OUTCOME_COUNT)
        + outcome.index()
}

fn strict_backpressure_index(
    reason: CatchupReason,
    phase: CatchupPhase,
    event: StrictCatchupBackpressureEvent,
) -> usize {
    (reason.index() * CATCHUP_PHASE_COUNT + phase.index()) * STRICT_CATCHUP_BACKPRESSURE_EVENT_COUNT
        + event.index()
}

fn strict_backoff_index(reason: CatchupReason, phase: CatchupPhase) -> usize {
    reason.index() * CATCHUP_PHASE_COUNT + phase.index()
}

fn strict_probe_index(
    probe: StrictProbeKind,
    reason: CatchupReason,
    outcome: StrictProbeOutcome,
) -> usize {
    (probe.index() * CATCHUP_REASON_COUNT + reason.index()) * STRICT_PROBE_OUTCOME_COUNT
        + outcome.index()
}

fn legacy_reason(mode: CatchupMode) -> CatchupReason {
    match mode {
        CatchupMode::Strict => CatchupReason::LegacyV2,
        CatchupMode::Owner => CatchupReason::OwnerAntiEntropy,
    }
}

pub(crate) fn record_catchup_request(mode: CatchupMode) {
    record_catchup_request_detail(mode, legacy_reason(mode), CatchupPhase::Metadata);
}

pub(crate) fn record_catchup_response(mode: CatchupMode, ops: usize, bytes: usize) {
    record_catchup_response_detail(
        mode,
        legacy_reason(mode),
        CatchupPhase::LogDelta,
        ops,
        bytes,
    );
}

pub(crate) fn record_catchup_request_detail(
    mode: CatchupMode,
    reason: CatchupReason,
    phase: CatchupPhase,
) {
    increment(
        &CATCHUP_REQUESTS[catchup_logical_index(mode, reason, phase)],
        1,
    );
}

/// Records logical response work. Retries and redundant route copies belong in
/// [`record_strict_catchup_send_attempt`] so transport amplification remains
/// distinct from the data required to converge.
pub(crate) fn record_catchup_response_detail(
    mode: CatchupMode,
    reason: CatchupReason,
    phase: CatchupPhase,
    ops: usize,
    bytes: usize,
) {
    let index = catchup_logical_index(mode, reason, phase);
    increment(&CATCHUP_RESPONSES[index], 1);
    increment(&CATCHUP_RESPONSE_OPS[index], ops as u64);
    increment(&CATCHUP_RESPONSE_BYTES[index], bytes as u64);
}

pub(crate) fn record_catchup_suppressed(mode: CatchupMode) {
    record_catchup_suppressed_detail(mode, legacy_reason(mode), CatchupPhase::Metadata);
}

pub(crate) fn record_catchup_suppressed_detail(
    mode: CatchupMode,
    reason: CatchupReason,
    phase: CatchupPhase,
) {
    increment(
        &CATCHUP_SUPPRESSED[catchup_logical_index(mode, reason, phase)],
        1,
    );
}

pub(crate) fn record_catchup_active_delta(delta: isize) {
    if delta >= 0 {
        CATCHUP_ACTIVE.fetch_add(delta as usize, Ordering::Relaxed);
    } else {
        let decrement = delta.unsigned_abs();
        let _ = CATCHUP_ACTIVE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_sub(decrement))
        });
    }
}

pub(crate) fn record_strict_catchup_session_start(reason: CatchupReason) {
    increment(&STRICT_CATCHUP_SESSION_STARTS[reason.index()], 1);
    STRICT_CATCHUP_SESSION_ACTIVE[reason.index()].fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_strict_catchup_session_completion(
    reason: CatchupReason,
    outcome: StrictCatchupSessionOutcome,
) {
    increment(
        &STRICT_CATCHUP_SESSION_COMPLETIONS[strict_session_completion_index(reason, outcome)],
        1,
    );
    let active = &STRICT_CATCHUP_SESSION_ACTIVE[reason.index()];
    let _ = active.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(1))
    });
}

pub(crate) fn record_strict_catchup_session_event(
    reason: CatchupReason,
    event: StrictCatchupSessionEvent,
) {
    increment(
        &STRICT_CATCHUP_SESSION_EVENTS[strict_session_event_index(reason, event)],
        1,
    );
}

/// Records each physical enqueue attempt, including redundant route copies and
/// retries. `bytes` is the exact encoded frame size attempted on that lane.
pub(crate) fn record_strict_catchup_send_attempt(
    reason: CatchupReason,
    phase: CatchupPhase,
    lane: StrictCatchupLane,
    outcome: StrictCatchupSendOutcome,
    bytes: usize,
) {
    let index = strict_send_index(reason, phase, lane, outcome);
    increment(&STRICT_CATCHUP_SEND_ATTEMPTS[index], 1);
    increment(&STRICT_CATCHUP_SEND_BYTES[index], bytes as u64);
}

pub(crate) fn record_strict_catchup_duplicate(outcome: StrictCatchupDuplicateOutcome) {
    increment(&STRICT_CATCHUP_DUPLICATES[outcome.index()], 1);
}

pub(crate) fn record_strict_snapshot_receive_event(event: StrictSnapshotReceiveEvent) {
    increment(&STRICT_SNAPSHOT_RECEIVE_EVENTS_TOTAL[event.index()], 1);
}

pub(crate) fn record_strict_snapshot_responder_event(event: StrictSnapshotResponderEvent) {
    increment(&STRICT_SNAPSHOT_RESPONDER_EVENTS_TOTAL[event.index()], 1);
}

pub(crate) fn record_strict_catchup_backpressure(
    reason: CatchupReason,
    phase: CatchupPhase,
    event: StrictCatchupBackpressureEvent,
    backoff: Duration,
) {
    increment(
        &STRICT_CATCHUP_BACKPRESSURE_EVENTS[strict_backpressure_index(reason, phase, event)],
        1,
    );
    let delay_ms = backoff.as_millis().min(u64::MAX as u128) as u64;
    increment(
        &STRICT_CATCHUP_BACKOFF_DELAY_MS[strict_backoff_index(reason, phase)],
        delay_ms,
    );
}

#[cfg(test)]
pub(crate) fn set_strict_catchup_bulk_in_flight_bytes(bytes: usize) {
    STRICT_CATCHUP_BULK_IN_FLIGHT_BYTES.store(bytes, Ordering::Relaxed);
}

pub(crate) fn record_strict_catchup_bulk_in_flight_bytes_delta(delta: isize) {
    if delta >= 0 {
        STRICT_CATCHUP_BULK_IN_FLIGHT_BYTES.fetch_add(delta as usize, Ordering::Relaxed);
    } else {
        let decrement = delta.unsigned_abs();
        let _ = STRICT_CATCHUP_BULK_IN_FLIGHT_BYTES.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| Some(current.saturating_sub(decrement)),
        );
    }
}

pub(crate) fn record_strict_catchup_throttled(reason: StrictCatchupThrottleReason) {
    increment(&STRICT_CATCHUP_THROTTLED[reason.index()], 1);
}

pub(crate) fn record_strict_probe_event(
    probe: StrictProbeKind,
    reason: CatchupReason,
    outcome: StrictProbeOutcome,
) {
    increment(
        &STRICT_PROBE_EVENTS[strict_probe_index(probe, reason, outcome)],
        1,
    );
}

pub(crate) fn record_strict_admission_event(event: StrictAdmissionEvent) {
    increment(&STRICT_ADMISSION_EVENTS_TOTAL[event.index()], 1);
}

pub(crate) fn record_strict_history_election_event(event: StrictHistoryElectionEvent) {
    increment(&STRICT_HISTORY_ELECTION_EVENTS_TOTAL[event.index()], 1);
}

pub(crate) fn record_strict_head_event(event: StrictHeadEvent) {
    increment(&STRICT_HEAD_EVENTS_TOTAL[event.index()], 1);
}

pub(crate) fn record_strict_terminal_divergence_event(event: StrictTerminalDivergenceEvent) {
    increment(&STRICT_TERMINAL_DIVERGENCE_EVENTS_TOTAL[event.index()], 1);
}

pub(crate) fn record_strict_recovery_attempt() {
    increment(&STRICT_RECOVERY_ATTEMPTS_TOTAL, 1);
}

pub(crate) fn record_strict_recovery_coalesced_trigger(trigger: StrictRecoveryTrigger) {
    increment(
        &STRICT_RECOVERY_COALESCED_TRIGGERS_TOTAL[trigger.index()],
        1,
    );
}

pub(crate) fn record_strict_recovery_retransmit(phase: StrictRecoveryPhase) {
    increment(&STRICT_RECOVERY_RETRANSMITS_TOTAL[phase.index()], 1);
}

pub(crate) fn record_strict_recovery_donor_switch(reason: StrictRecoveryDonorSwitchReason) {
    increment(&STRICT_RECOVERY_DONOR_SWITCHES_TOTAL[reason.index()], 1);
}

pub(crate) fn record_strict_recovery_certificate_failure(
    failure: StrictRecoveryCertificateFailure,
) {
    increment(
        &STRICT_RECOVERY_CERTIFICATE_FAILURES_TOTAL[failure.index()],
        1,
    );
}

pub(crate) fn record_strict_recovery_stale_event(event: StrictRecoveryStaleEvent) {
    increment(&STRICT_RECOVERY_STALE_EVENTS_TOTAL[event.index()], 1);
}

pub(crate) fn record_strict_recovery_completion(duration: Duration) {
    let duration_ms = duration.as_millis().min(u64::MAX as u128) as u64;
    increment(&STRICT_RECOVERY_COMPLETION_DURATION_MS_TOTAL, duration_ms);
    increment(&STRICT_RECOVERY_COMPLETION_DURATION_COUNT, 1);
}

/// Records one physical protocol-v8 recovery send attempt. Redundant control
/// copies call this once per route; bulk pages call it once per enqueue.
pub(crate) fn record_strict_recovery_send_attempt(bytes: usize) {
    increment(&STRICT_RECOVERY_SEND_ATTEMPTS_TOTAL, 1);
    increment(&STRICT_RECOVERY_SEND_BYTES_TOTAL, bytes as u64);
}

pub(crate) fn record_pipeline_stage(
    kind: ReplicationPipelineKind,
    stage: ReplicationPipelineStage,
    duration: Duration,
) {
    let kind_index = kind.index();
    let stage_index = stage.index();
    let duration_us = duration.as_micros().min(u64::MAX as u128) as u64;
    increment(
        &REPLICATION_PIPELINE_STAGE_EVENTS[kind_index][stage_index],
        1,
    );
    increment(
        &REPLICATION_PIPELINE_STAGE_DURATION_TOTAL_US[kind_index][stage_index],
        duration_us,
    );
    observe_bucket(
        &REPLICATION_PIPELINE_STAGE_DURATION_BUCKETS[kind_index][stage_index],
        &CLIENT_QUEUE_BUCKETS_US,
        duration_us,
    );
}

pub fn set_client_replication_queue_depth(depth: usize) {
    CLIENT_REPLICATION_QUEUE_DEPTH.store(depth, Ordering::Relaxed);
}

pub fn record_client_replication_queue_wait(wait: std::time::Duration) {
    let wait_us = wait.as_micros().min(u64::MAX as u128) as u64;
    increment(&CLIENT_REPLICATION_QUEUE_WAIT_TOTAL_US, wait_us);
    increment(&CLIENT_REPLICATION_QUEUE_WAIT_SAMPLES, 1);
    observe_bucket(
        &CLIENT_REPLICATION_QUEUE_WAIT_BUCKETS,
        &CLIENT_QUEUE_BUCKETS_US,
        wait_us,
    );
}

/// Publishes the strict-replication protocol negotiated across alive peers.
///
/// `cluster_version` is the minimum advertised incremental protocol version,
/// `ready` reports whether terminal resolution may be emitted, and
/// `unsupported_active_peers` exposes why a rollout has not become ready.
pub(crate) fn set_strict_replication_protocol_status(
    cluster_version: u32,
    ready: bool,
    unsupported_active_peers: usize,
) {
    STRICT_REPLICATION_CLUSTER_PROTOCOL_VERSION.store(cluster_version, Ordering::Relaxed);
    STRICT_REPLICATION_TERMINAL_RESOLUTION_READY.store(ready, Ordering::Relaxed);
    STRICT_REPLICATION_UNSUPPORTED_ACTIVE_PEERS.store(unsupported_active_peers, Ordering::Relaxed);
}

/// Records a terminal decision applied by the strict-resolution protocol.
pub(crate) fn record_strict_resolution(outcome: StrictResolutionOutcome) {
    increment(&STRICT_REPLICATION_TERMINAL_DECISIONS[outcome.index()], 1);
}

/// Records a late or conflicting strict frame rejected by a resolution fence.
pub(crate) fn record_strict_fence_rejection() {
    increment(&STRICT_REPLICATION_FENCE_REJECTIONS, 1);
}

fn aggregate_strict_admission_metrics() -> StrictAdmissionMetricSnapshot {
    let mut sources = STRICT_ADMISSION_METRIC_SOURCES.lock().unwrap();
    aggregate_strict_admission_sources(&mut sources)
}

fn aggregate_strict_admission_sources(
    sources: &mut Vec<Weak<StrictAdmissionMetrics>>,
) -> StrictAdmissionMetricSnapshot {
    let mut aggregate = StrictAdmissionMetricSnapshot::default();
    sources.retain(|source| {
        let Some(source) = source.upgrade() else {
            return false;
        };
        let snapshot = source.snapshot();
        aggregate.admitted = aggregate.admitted.saturating_add(snapshot.admitted);
        aggregate.awaiting_local_cut = aggregate
            .awaiting_local_cut
            .saturating_add(snapshot.awaiting_local_cut);
        aggregate.awaiting_peer = aggregate
            .awaiting_peer
            .saturating_add(snapshot.awaiting_peer);
        aggregate.highest_barrier = aggregate.highest_barrier.max(snapshot.highest_barrier);
        aggregate.awaiting_history_only = aggregate
            .awaiting_history_only
            .saturating_add(snapshot.awaiting_history_only);
        aggregate.awaiting_clock_only = aggregate
            .awaiting_clock_only
            .saturating_add(snapshot.awaiting_clock_only);
        aggregate.awaiting_both_proofs = aggregate
            .awaiting_both_proofs
            .saturating_add(snapshot.awaiting_both_proofs);
        aggregate.clock_demand_commit_buffer = aggregate
            .clock_demand_commit_buffer
            .saturating_add(snapshot.clock_demand_commit_buffer);
        aggregate.clock_demand_proposal = aggregate
            .clock_demand_proposal
            .saturating_add(snapshot.clock_demand_proposal);
        aggregate.clock_demand_missing_peer_clocks = aggregate
            .clock_demand_missing_peer_clocks
            .saturating_add(snapshot.clock_demand_missing_peer_clocks);
        aggregate.unacknowledged_head_peers = aggregate
            .unacknowledged_head_peers
            .saturating_add(snapshot.unacknowledged_head_peers);
        true
    });
    aggregate
}

fn strict_admission_metric_samples(
    snapshot: StrictAdmissionMetricSnapshot,
) -> Vec<PrometheusSample> {
    let mut samples = Vec::with_capacity(12);
    for (state, value) in [
        ("admitted", snapshot.admitted),
        ("awaiting_local_cut", snapshot.awaiting_local_cut),
        ("awaiting_peer", snapshot.awaiting_peer),
    ] {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_admission_peer_states",
            vec![("state".to_owned(), state.to_owned())],
            value as f64,
        ));
    }
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_strict_replication_admission_highest_barrier",
        Vec::new(),
        snapshot.highest_barrier as f64,
    ));
    for (proof, value) in [
        ("history", snapshot.awaiting_history_only),
        ("clock", snapshot.awaiting_clock_only),
        ("both", snapshot.awaiting_both_proofs),
    ] {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_admission_awaiting_proofs",
            vec![("proof".to_owned(), proof.to_owned())],
            value as f64,
        ));
    }
    for (reason, value) in [
        ("commit_buffer", snapshot.clock_demand_commit_buffer),
        ("proposal", snapshot.clock_demand_proposal),
        (
            "missing_peer_clock",
            snapshot.clock_demand_missing_peer_clocks,
        ),
        ("head_ack", snapshot.unacknowledged_head_peers),
    ] {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_clock_demand",
            vec![("reason".to_owned(), reason.to_owned())],
            value as f64,
        ));
    }
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_strict_replication_unacknowledged_head_peers",
        Vec::new(),
        snapshot.unacknowledged_head_peers as f64,
    ));
    samples
}

pub(crate) fn prometheus_samples() -> Vec<PrometheusSample> {
    let mut samples = Vec::new();
    for mode in [CatchupMode::Strict, CatchupMode::Owner] {
        for reason in CATCHUP_REASONS {
            for phase in CATCHUP_PHASES {
                let labels = vec![
                    ("mode".to_owned(), mode.label().to_owned()),
                    ("reason".to_owned(), reason.label().to_owned()),
                    ("phase".to_owned(), phase.label().to_owned()),
                ];
                let index = catchup_logical_index(mode, reason, phase);
                let requests = CATCHUP_REQUESTS[index].load(Ordering::Relaxed);
                let responses = CATCHUP_RESPONSES[index].load(Ordering::Relaxed);
                let ops = CATCHUP_RESPONSE_OPS[index].load(Ordering::Relaxed);
                let bytes = CATCHUP_RESPONSE_BYTES[index].load(Ordering::Relaxed);
                let suppressed = CATCHUP_SUPPRESSED[index].load(Ordering::Relaxed);
                let is_default_reason = reason == legacy_reason(mode);
                if requests > 0 || (is_default_reason && phase == CatchupPhase::Metadata) {
                    samples.push(PrometheusSample::new(
                        "shitspeak_s2s_replication_catchup_requests_total",
                        labels.clone(),
                        requests as f64,
                    ));
                }
                if responses > 0 || (is_default_reason && phase == CatchupPhase::LogDelta) {
                    samples.push(PrometheusSample::new(
                        "shitspeak_s2s_replication_catchup_responses_total",
                        labels.clone(),
                        responses as f64,
                    ));
                    samples.push(PrometheusSample::new(
                        "shitspeak_s2s_replication_catchup_response_ops_total",
                        labels.clone(),
                        ops as f64,
                    ));
                    samples.push(PrometheusSample::new(
                        "shitspeak_s2s_replication_catchup_response_bytes_total",
                        labels.clone(),
                        bytes as f64,
                    ));
                }
                if suppressed > 0 || (is_default_reason && phase == CatchupPhase::Metadata) {
                    samples.push(PrometheusSample::new(
                        "shitspeak_s2s_replication_catchup_suppressed_total",
                        labels,
                        suppressed as f64,
                    ));
                }
            }
        }
    }

    samples.push(PrometheusSample::new(
        "shitspeak_s2s_replication_catchup_active",
        Vec::new(),
        CATCHUP_ACTIVE.load(Ordering::Relaxed) as f64,
    ));
    samples.extend(strict_catchup_v3_metric_samples());
    for kind in REPLICATION_PIPELINE_KINDS {
        for stage in REPLICATION_PIPELINE_STAGES {
            let kind_index = kind.index();
            let stage_index = stage.index();
            let labels = vec![
                ("kind".to_owned(), kind.label().to_owned()),
                ("stage".to_owned(), stage.label().to_owned()),
            ];
            samples.push(PrometheusSample::new(
                "shitspeak_s2s_replication_pipeline_stage_events_total",
                labels.clone(),
                REPLICATION_PIPELINE_STAGE_EVENTS[kind_index][stage_index].load(Ordering::Relaxed)
                    as f64,
            ));
            samples.push(PrometheusSample::new(
                "shitspeak_s2s_replication_pipeline_stage_duration_us_total",
                labels.clone(),
                REPLICATION_PIPELINE_STAGE_DURATION_TOTAL_US[kind_index][stage_index]
                    .load(Ordering::Relaxed) as f64,
            ));
            for (bucket_index, (bucket, _)) in CLIENT_QUEUE_BUCKETS_US.iter().enumerate() {
                let mut labels = labels.clone();
                labels.push(("bucket".to_owned(), (*bucket).to_owned()));
                samples.push(PrometheusSample::new(
                    "shitspeak_s2s_replication_pipeline_stage_duration_us_bucket_total",
                    labels,
                    REPLICATION_PIPELINE_STAGE_DURATION_BUCKETS[kind_index][stage_index]
                        [bucket_index]
                        .load(Ordering::Relaxed) as f64,
                ));
            }
        }
    }
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_client_replication_worker_queue_depth",
        Vec::new(),
        CLIENT_REPLICATION_QUEUE_DEPTH.load(Ordering::Relaxed) as f64,
    ));
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_client_replication_worker_queue_wait_us_total",
        Vec::new(),
        CLIENT_REPLICATION_QUEUE_WAIT_TOTAL_US.load(Ordering::Relaxed) as f64,
    ));
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_client_replication_worker_queue_wait_samples_total",
        Vec::new(),
        CLIENT_REPLICATION_QUEUE_WAIT_SAMPLES.load(Ordering::Relaxed) as f64,
    ));
    for (index, (bucket, _)) in CLIENT_QUEUE_BUCKETS_US.iter().enumerate() {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_client_replication_worker_queue_wait_us_bucket_total",
            vec![("bucket".to_owned(), (*bucket).to_owned())],
            CLIENT_REPLICATION_QUEUE_WAIT_BUCKETS[index].load(Ordering::Relaxed) as f64,
        ));
    }

    samples.extend(strict_protocol_metric_samples(
        STRICT_REPLICATION_CLUSTER_PROTOCOL_VERSION.load(Ordering::Relaxed),
        STRICT_REPLICATION_TERMINAL_RESOLUTION_READY.load(Ordering::Relaxed),
        STRICT_REPLICATION_UNSUPPORTED_ACTIVE_PEERS.load(Ordering::Relaxed),
        [
            STRICT_REPLICATION_TERMINAL_DECISIONS[StrictResolutionOutcome::Commit.index()]
                .load(Ordering::Relaxed),
            STRICT_REPLICATION_TERMINAL_DECISIONS[StrictResolutionOutcome::Abort.index()]
                .load(Ordering::Relaxed),
        ],
        STRICT_REPLICATION_FENCE_REJECTIONS.load(Ordering::Relaxed),
    ));
    samples.extend(strict_admission_metric_samples(
        aggregate_strict_admission_metrics(),
    ));
    samples.extend(strict_convergence_event_metric_samples());
    samples.extend(strict_recovery_metric_samples());

    samples
}

fn strict_recovery_metric_samples() -> Vec<PrometheusSample> {
    let now_ms = strict_recovery_now_ms();
    let mut phase_topics = [0usize; STRICT_RECOVERY_PHASE_COUNT];
    let mut progress_age_ms = [0u64; STRICT_RECOVERY_PHASE_COUNT];
    let mut donor_terminal_sessions = 0usize;
    let mut donor_snapshot_sessions = 0usize;
    let mut sources = STRICT_RECOVERY_METRIC_SOURCES.lock().unwrap();
    sources.retain(|source| {
        let Some(source) = source.upgrade() else {
            return false;
        };
        let (phase, age_ms, terminal_sessions, snapshot_sessions) = source.snapshot(now_ms);
        phase_topics[phase.index()] = phase_topics[phase.index()].saturating_add(1);
        progress_age_ms[phase.index()] = progress_age_ms[phase.index()].max(age_ms);
        donor_terminal_sessions = donor_terminal_sessions.saturating_add(terminal_sessions);
        donor_snapshot_sessions = donor_snapshot_sessions.saturating_add(snapshot_sessions);
        true
    });

    let mut samples = Vec::new();
    for (kind, active) in [
        ("terminal", donor_terminal_sessions),
        ("snapshot", donor_snapshot_sessions),
    ] {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_recovery_donor_sessions_active",
            vec![("kind".to_owned(), kind.to_owned())],
            active as f64,
        ));
    }
    for phase in STRICT_RECOVERY_PHASES {
        let labels = vec![("phase".to_owned(), phase.label().to_owned())];
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_recovery_phase_topics",
            labels.clone(),
            phase_topics[phase.index()] as f64,
        ));
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_recovery_progress_age_ms",
            labels.clone(),
            progress_age_ms[phase.index()] as f64,
        ));
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_recovery_retransmits_total",
            labels,
            STRICT_RECOVERY_RETRANSMITS_TOTAL[phase.index()].load(Ordering::Relaxed) as f64,
        ));
    }
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_strict_replication_recovery_attempts_total",
        Vec::new(),
        STRICT_RECOVERY_ATTEMPTS_TOTAL.load(Ordering::Relaxed) as f64,
    ));
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_strict_replication_recovery_send_attempts_total",
        Vec::new(),
        STRICT_RECOVERY_SEND_ATTEMPTS_TOTAL.load(Ordering::Relaxed) as f64,
    ));
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_strict_replication_recovery_send_bytes_total",
        Vec::new(),
        STRICT_RECOVERY_SEND_BYTES_TOTAL.load(Ordering::Relaxed) as f64,
    ));
    for trigger in STRICT_RECOVERY_TRIGGERS {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_recovery_coalesced_triggers_total",
            vec![("event".to_owned(), trigger.label().to_owned())],
            STRICT_RECOVERY_COALESCED_TRIGGERS_TOTAL[trigger.index()].load(Ordering::Relaxed)
                as f64,
        ));
    }
    for reason in STRICT_RECOVERY_DONOR_SWITCH_REASONS {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_recovery_donor_switches_total",
            vec![("reason".to_owned(), reason.label().to_owned())],
            STRICT_RECOVERY_DONOR_SWITCHES_TOTAL[reason.index()].load(Ordering::Relaxed) as f64,
        ));
    }
    for failure in STRICT_RECOVERY_CERTIFICATE_FAILURES {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_recovery_certificate_failures_total",
            vec![("reason".to_owned(), failure.label().to_owned())],
            STRICT_RECOVERY_CERTIFICATE_FAILURES_TOTAL[failure.index()].load(Ordering::Relaxed)
                as f64,
        ));
    }
    for event in STRICT_RECOVERY_STALE_EVENTS {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_recovery_stale_events_total",
            vec![("event".to_owned(), event.label().to_owned())],
            STRICT_RECOVERY_STALE_EVENTS_TOTAL[event.index()].load(Ordering::Relaxed) as f64,
        ));
    }
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_strict_replication_recovery_completion_duration_ms_total",
        Vec::new(),
        STRICT_RECOVERY_COMPLETION_DURATION_MS_TOTAL.load(Ordering::Relaxed) as f64,
    ));
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_strict_replication_recovery_completion_duration_count",
        Vec::new(),
        STRICT_RECOVERY_COMPLETION_DURATION_COUNT.load(Ordering::Relaxed) as f64,
    ));
    samples
}

fn strict_convergence_event_metric_samples() -> Vec<PrometheusSample> {
    let mut samples = Vec::new();
    for probe in STRICT_PROBE_KINDS {
        for reason in CATCHUP_REASONS {
            for outcome in STRICT_PROBE_OUTCOMES {
                let value = STRICT_PROBE_EVENTS[strict_probe_index(probe, reason, outcome)]
                    .load(Ordering::Relaxed);
                if value == 0 {
                    continue;
                }
                samples.push(PrometheusSample::new(
                    "shitspeak_s2s_strict_replication_probe_events_total",
                    vec![
                        ("probe".to_owned(), probe.label().to_owned()),
                        ("reason".to_owned(), reason.label().to_owned()),
                        ("outcome".to_owned(), outcome.label().to_owned()),
                    ],
                    value as f64,
                ));
            }
        }
    }
    for event in STRICT_ADMISSION_EVENTS {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_admission_events_total",
            vec![("event".to_owned(), event.label().to_owned())],
            STRICT_ADMISSION_EVENTS_TOTAL[event.index()].load(Ordering::Relaxed) as f64,
        ));
    }
    for event in STRICT_HISTORY_ELECTION_EVENTS {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_history_election_events_total",
            vec![("event".to_owned(), event.label().to_owned())],
            STRICT_HISTORY_ELECTION_EVENTS_TOTAL[event.index()].load(Ordering::Relaxed) as f64,
        ));
    }
    for event in STRICT_HEAD_EVENTS {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_head_events_total",
            vec![("event".to_owned(), event.label().to_owned())],
            STRICT_HEAD_EVENTS_TOTAL[event.index()].load(Ordering::Relaxed) as f64,
        ));
    }
    for event in STRICT_TERMINAL_DIVERGENCE_EVENTS {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_divergence_events_total",
            vec![("event".to_owned(), event.label().to_owned())],
            STRICT_TERMINAL_DIVERGENCE_EVENTS_TOTAL[event.index()].load(Ordering::Relaxed) as f64,
        ));
    }
    samples
}

fn strict_catchup_v3_metric_samples() -> Vec<PrometheusSample> {
    let mut samples = Vec::new();

    for reason in CATCHUP_REASONS {
        let reason_labels = vec![("reason".to_owned(), reason.label().to_owned())];
        let starts = STRICT_CATCHUP_SESSION_STARTS[reason.index()].load(Ordering::Relaxed);
        if starts > 0 {
            samples.push(PrometheusSample::new(
                "shitspeak_s2s_strict_replication_catchup_session_starts_total",
                reason_labels.clone(),
                starts as f64,
            ));
        }
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_catchup_sessions_active",
            reason_labels.clone(),
            STRICT_CATCHUP_SESSION_ACTIVE[reason.index()].load(Ordering::Relaxed) as f64,
        ));

        for outcome in STRICT_CATCHUP_SESSION_OUTCOMES {
            let value = STRICT_CATCHUP_SESSION_COMPLETIONS
                [strict_session_completion_index(reason, outcome)]
            .load(Ordering::Relaxed);
            if value > 0 {
                samples.push(PrometheusSample::new(
                    "shitspeak_s2s_strict_replication_catchup_session_completions_total",
                    vec![
                        ("reason".to_owned(), reason.label().to_owned()),
                        ("outcome".to_owned(), outcome.label().to_owned()),
                    ],
                    value as f64,
                ));
            }
        }
        for event in ALL_STRICT_CATCHUP_SESSION_EVENTS {
            let value = STRICT_CATCHUP_SESSION_EVENTS[strict_session_event_index(reason, event)]
                .load(Ordering::Relaxed);
            if value > 0 {
                samples.push(PrometheusSample::new(
                    "shitspeak_s2s_strict_replication_catchup_session_events_total",
                    vec![
                        ("reason".to_owned(), reason.label().to_owned()),
                        ("event".to_owned(), event.label().to_owned()),
                    ],
                    value as f64,
                ));
            }
        }

        for phase in CATCHUP_PHASES {
            for lane in STRICT_CATCHUP_LANES {
                for outcome in STRICT_CATCHUP_SEND_OUTCOMES {
                    let index = strict_send_index(reason, phase, lane, outcome);
                    let attempts = STRICT_CATCHUP_SEND_ATTEMPTS[index].load(Ordering::Relaxed);
                    let bytes = STRICT_CATCHUP_SEND_BYTES[index].load(Ordering::Relaxed);
                    if attempts == 0 && bytes == 0 {
                        continue;
                    }
                    let labels = vec![
                        ("reason".to_owned(), reason.label().to_owned()),
                        ("phase".to_owned(), phase.label().to_owned()),
                        ("lane".to_owned(), lane.label().to_owned()),
                        ("outcome".to_owned(), outcome.label().to_owned()),
                    ];
                    samples.push(PrometheusSample::new(
                        "shitspeak_s2s_strict_replication_catchup_send_attempts_total",
                        labels.clone(),
                        attempts as f64,
                    ));
                    samples.push(PrometheusSample::new(
                        "shitspeak_s2s_strict_replication_catchup_send_bytes_total",
                        labels,
                        bytes as f64,
                    ));
                }
            }

            for event in ALL_STRICT_CATCHUP_BACKPRESSURE_EVENTS {
                let value = STRICT_CATCHUP_BACKPRESSURE_EVENTS
                    [strict_backpressure_index(reason, phase, event)]
                .load(Ordering::Relaxed);
                if value > 0 {
                    samples.push(PrometheusSample::new(
                        "shitspeak_s2s_strict_replication_catchup_backpressure_events_total",
                        vec![
                            ("reason".to_owned(), reason.label().to_owned()),
                            ("phase".to_owned(), phase.label().to_owned()),
                            ("event".to_owned(), event.label().to_owned()),
                        ],
                        value as f64,
                    ));
                }
            }
            let backoff_ms = STRICT_CATCHUP_BACKOFF_DELAY_MS[strict_backoff_index(reason, phase)]
                .load(Ordering::Relaxed);
            if backoff_ms > 0 {
                samples.push(PrometheusSample::new(
                    "shitspeak_s2s_strict_replication_catchup_backoff_delay_ms_total",
                    vec![
                        ("reason".to_owned(), reason.label().to_owned()),
                        ("phase".to_owned(), phase.label().to_owned()),
                    ],
                    backoff_ms as f64,
                ));
            }
        }
    }

    for outcome in STRICT_CATCHUP_DUPLICATE_OUTCOMES {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_catchup_duplicate_pages_total",
            vec![("outcome".to_owned(), outcome.label().to_owned())],
            STRICT_CATCHUP_DUPLICATES[outcome.index()].load(Ordering::Relaxed) as f64,
        ));
    }
    for event in STRICT_SNAPSHOT_RECEIVE_EVENTS {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_snapshot_receive_events_total",
            vec![("event".to_owned(), event.label().to_owned())],
            STRICT_SNAPSHOT_RECEIVE_EVENTS_TOTAL[event.index()].load(Ordering::Relaxed) as f64,
        ));
    }
    for event in STRICT_SNAPSHOT_RESPONDER_EVENTS {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_snapshot_responder_events_total",
            vec![("event".to_owned(), event.label().to_owned())],
            STRICT_SNAPSHOT_RESPONDER_EVENTS_TOTAL[event.index()].load(Ordering::Relaxed) as f64,
        ));
    }
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_strict_replication_catchup_bulk_in_flight_bytes",
        Vec::new(),
        STRICT_CATCHUP_BULK_IN_FLIGHT_BYTES.load(Ordering::Relaxed) as f64,
    ));
    for reason in STRICT_CATCHUP_THROTTLE_REASONS {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_catchup_throttled_total",
            vec![("reason".to_owned(), reason.label().to_owned())],
            STRICT_CATCHUP_THROTTLED[reason.index()].load(Ordering::Relaxed) as f64,
        ));
    }

    samples
}

fn strict_protocol_metric_samples(
    cluster_protocol_version: u32,
    terminal_resolution_ready: bool,
    unsupported_active_peers: usize,
    terminal_decisions: [u64; STRICT_RESOLUTION_OUTCOME_COUNT],
    fence_rejections: u64,
) -> Vec<PrometheusSample> {
    let mut samples = Vec::with_capacity(6);
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_strict_replication_cluster_protocol_version",
        Vec::new(),
        cluster_protocol_version as f64,
    ));
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_strict_replication_terminal_resolution_ready",
        Vec::new(),
        terminal_resolution_ready as u8 as f64,
    ));
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_strict_replication_unsupported_active_peers",
        Vec::new(),
        unsupported_active_peers as f64,
    ));
    for outcome in [
        StrictResolutionOutcome::Commit,
        StrictResolutionOutcome::Abort,
    ] {
        samples.push(PrometheusSample::new(
            "shitspeak_s2s_strict_replication_terminal_decisions_total",
            vec![("outcome".to_owned(), outcome.label().to_owned())],
            terminal_decisions[outcome.index()] as f64,
        ));
    }
    samples.push(PrometheusSample::new(
        "shitspeak_s2s_strict_replication_fence_rejections_total",
        Vec::new(),
        fence_rejections as f64,
    ));
    samples
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_recovery_metrics_register_in_restored_phase() {
        let source = register_strict_recovery_metrics(StrictRecoveryPhase::Installing);

        let (phase, _, _, _) = source.snapshot(strict_recovery_now_ms());
        assert_eq!(phase, StrictRecoveryPhase::Installing);
    }

    #[test]
    fn strict_recovery_metrics_use_bounded_phase_and_event_labels() {
        let source = register_strict_recovery_metrics(StrictRecoveryPhase::Healthy);
        source.set_phase(StrictRecoveryPhase::FetchingTerminalCheckpoint);
        source.record_authenticated_progress();
        source.set_donor_sessions(2, 1);
        record_strict_recovery_attempt();
        record_strict_recovery_coalesced_trigger(StrictRecoveryTrigger::TerminalFence);
        record_strict_recovery_retransmit(StrictRecoveryPhase::FetchingTerminalCheckpoint);
        record_strict_recovery_donor_switch(StrictRecoveryDonorSwitchReason::NoProgress);
        record_strict_recovery_certificate_failure(
            StrictRecoveryCertificateFailure::ConflictingTarget,
        );
        record_strict_recovery_stale_event(StrictRecoveryStaleEvent::TerminalPage);
        record_strict_recovery_completion(Duration::from_millis(123));
        record_strict_recovery_send_attempt(321);

        let samples = strict_recovery_metric_samples();
        let has_sample = |name: &str, key: &str, value: &str| {
            samples.iter().any(|sample| {
                sample.name() == name
                    && sample.labels() == [(key.to_owned(), value.to_owned())]
                    && sample.value() >= 1.0
            })
        };
        assert!(has_sample(
            "shitspeak_s2s_strict_replication_recovery_phase_topics",
            "phase",
            "fetching_terminal_checkpoint"
        ));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_recovery_progress_age_ms"
                && sample.labels()
                    == [(
                        "phase".to_owned(),
                        "fetching_terminal_checkpoint".to_owned(),
                    )]
                && sample.value() >= 0.0
        }));
        assert!(has_sample(
            "shitspeak_s2s_strict_replication_recovery_donor_sessions_active",
            "kind",
            "terminal"
        ));
        assert!(has_sample(
            "shitspeak_s2s_strict_replication_recovery_donor_sessions_active",
            "kind",
            "snapshot"
        ));
        assert!(has_sample(
            "shitspeak_s2s_strict_replication_recovery_coalesced_triggers_total",
            "event",
            "terminal_fence"
        ));
        assert!(has_sample(
            "shitspeak_s2s_strict_replication_recovery_retransmits_total",
            "phase",
            "fetching_terminal_checkpoint"
        ));
        assert!(has_sample(
            "shitspeak_s2s_strict_replication_recovery_donor_switches_total",
            "reason",
            "no_progress"
        ));
        assert!(has_sample(
            "shitspeak_s2s_strict_replication_recovery_certificate_failures_total",
            "reason",
            "conflicting_target"
        ));
        assert!(has_sample(
            "shitspeak_s2s_strict_replication_recovery_stale_events_total",
            "event",
            "terminal_page"
        ));
        assert!(samples.iter().any(|sample| {
            sample.name()
                == "shitspeak_s2s_strict_replication_recovery_completion_duration_ms_total"
                && sample.value() >= 123.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_recovery_completion_duration_count"
                && sample.value() >= 1.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_recovery_send_attempts_total"
                && sample.value() >= 1.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_recovery_send_bytes_total"
                && sample.value() >= 321.0
        }));
    }

    #[test]
    fn strict_recovery_wire_accounting_records_each_physical_attempt() {
        let attempts_before = STRICT_RECOVERY_SEND_ATTEMPTS_TOTAL.load(Ordering::Relaxed);
        let bytes_before = STRICT_RECOVERY_SEND_BYTES_TOTAL.load(Ordering::Relaxed);

        record_strict_recovery_send_attempt(101);
        record_strict_recovery_send_attempt(101);

        assert!(
            STRICT_RECOVERY_SEND_ATTEMPTS_TOTAL.load(Ordering::Relaxed)
                >= attempts_before.saturating_add(2)
        );
        assert!(
            STRICT_RECOVERY_SEND_BYTES_TOTAL.load(Ordering::Relaxed)
                >= bytes_before.saturating_add(202)
        );
    }

    #[test]
    fn v3_wire_dimensions_map_only_to_bounded_metric_values() {
        let protocol_reasons = [
            StrictCatchupReason::HistoryElection,
            StrictCatchupReason::Admission,
            StrictCatchupReason::SteadyState,
            StrictCatchupReason::TerminalFence,
            StrictCatchupReason::DeliveryWatermark,
            StrictCatchupReason::PeerBehind,
            StrictCatchupReason::RepositoryGap,
            StrictCatchupReason::LegacyV2,
            StrictCatchupReason::OwnerAntiEntropy,
        ];
        let mapped_reasons = protocol_reasons.map(|reason| {
            CatchupReason::from_v3_wire(reason as i32)
                .expect("every declared v3 reason needs a bounded metric label")
        });
        assert_eq!(mapped_reasons, CATCHUP_REASONS);
        assert_eq!(
            CatchupReason::from_v3_wire(StrictCatchupReason::Unspecified as i32),
            None
        );
        assert_eq!(CatchupReason::from_v3_wire(i32::MAX), None);

        assert_eq!(
            CatchupPhase::from_terminal_page_kind(StrictTerminalPageKind::Delta as i32),
            Some(CatchupPhase::TerminalDelta)
        );
        assert_eq!(
            CatchupPhase::from_terminal_page_kind(StrictTerminalPageKind::Checkpoint as i32),
            Some(CatchupPhase::TerminalCheckpoint)
        );
        assert_eq!(
            CatchupPhase::from_terminal_page_kind(StrictTerminalPageKind::Unspecified as i32),
            None
        );
        assert_eq!(CatchupPhase::from_terminal_page_kind(i32::MAX), None);

        assert_eq!(
            StrictCatchupSessionOutcome::from_terminal_status(
                StrictTerminalSyncStatus::UpToDate as i32,
            ),
            Some(StrictCatchupSessionOutcome::Completed)
        );
        assert_eq!(
            StrictCatchupSessionOutcome::from_terminal_status(
                StrictTerminalSyncStatus::TransferExpired as i32,
            ),
            Some(StrictCatchupSessionOutcome::Expired)
        );
        assert_eq!(
            StrictCatchupSessionOutcome::from_terminal_status(
                StrictTerminalSyncStatus::CursorMismatch as i32,
            ),
            Some(StrictCatchupSessionOutcome::Failed)
        );
        assert_eq!(
            StrictCatchupSessionOutcome::from_terminal_status(
                StrictTerminalSyncStatus::IncarnationMismatch as i32,
            ),
            Some(StrictCatchupSessionOutcome::IncarnationMismatch)
        );
        assert_eq!(
            StrictCatchupSessionOutcome::from_terminal_status(
                StrictTerminalSyncStatus::ResourceLimit as i32,
            ),
            Some(StrictCatchupSessionOutcome::ResourceLimit)
        );
        for incomplete in [
            StrictTerminalSyncStatus::Unspecified,
            StrictTerminalSyncStatus::Ok,
        ] {
            assert_eq!(
                StrictCatchupSessionOutcome::from_terminal_status(incomplete as i32),
                None
            );
        }
        assert_eq!(
            StrictCatchupSessionOutcome::from_terminal_status(i32::MAX),
            None
        );
    }

    #[test]
    fn strict_catchup_v3_metrics_use_only_bounded_labels_and_split_logical_from_physical() {
        record_catchup_request_detail(
            CatchupMode::Strict,
            CatchupReason::TerminalFence,
            CatchupPhase::Metadata,
        );
        record_catchup_response_detail(
            CatchupMode::Strict,
            CatchupReason::TerminalFence,
            CatchupPhase::TerminalDelta,
            3,
            777,
        );
        record_strict_catchup_session_start(CatchupReason::Admission);
        record_strict_catchup_session_event(
            CatchupReason::Admission,
            StrictCatchupSessionEvent::Coalesced,
        );
        record_strict_catchup_session_completion(
            CatchupReason::Admission,
            StrictCatchupSessionOutcome::ResourceLimit,
        );
        record_strict_catchup_send_attempt(
            CatchupReason::TerminalFence,
            CatchupPhase::TerminalDelta,
            StrictCatchupLane::Bulk,
            StrictCatchupSendOutcome::RetryEnqueued,
            1_024,
        );
        record_strict_catchup_duplicate(StrictCatchupDuplicateOutcome::CachedReplay);
        record_strict_snapshot_receive_event(StrictSnapshotReceiveEvent::StaleForeignTransfer);
        record_strict_snapshot_responder_event(
            StrictSnapshotResponderEvent::CompletionAcknowledged,
        );
        record_strict_catchup_backpressure(
            CatchupReason::PeerBehind,
            CatchupPhase::Snapshot,
            StrictCatchupBackpressureEvent::Retry,
            Duration::from_millis(250),
        );
        set_strict_catchup_bulk_in_flight_bytes(4_096);
        record_strict_catchup_throttled(StrictCatchupThrottleReason::NextHopBytes);

        let samples = prometheus_samples();
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_replication_catchup_response_bytes_total"
                && sample.labels()
                    == [
                        ("mode".to_owned(), "strict".to_owned()),
                        ("reason".to_owned(), "terminal_fence".to_owned()),
                        ("phase".to_owned(), "terminal_delta".to_owned()),
                    ]
                && sample.value() >= 777.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_catchup_send_bytes_total"
                && sample.labels()
                    == [
                        ("reason".to_owned(), "terminal_fence".to_owned()),
                        ("phase".to_owned(), "terminal_delta".to_owned()),
                        ("lane".to_owned(), "bulk".to_owned()),
                        ("outcome".to_owned(), "retry_enqueued".to_owned()),
                    ]
                && sample.value() >= 1_024.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_catchup_session_completions_total"
                && sample.labels()
                    == [
                        ("reason".to_owned(), "admission".to_owned()),
                        ("outcome".to_owned(), "resource_limit".to_owned()),
                    ]
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_catchup_backoff_delay_ms_total"
                && sample.value() >= 250.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_catchup_bulk_in_flight_bytes"
                && sample.value() == 4_096.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_snapshot_receive_events_total"
                && sample.labels() == [("event".to_owned(), "stale_foreign_transfer".to_owned())]
                && sample.value() >= 1.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_snapshot_responder_events_total"
                && sample.labels() == [("event".to_owned(), "completion_acknowledged".to_owned())]
                && sample.value() >= 1.0
        }));

        let allowed_labels = ["mode", "reason", "phase", "lane", "outcome", "event"];
        for sample in samples.iter().filter(|sample| {
            sample.name().contains("strict_replication_catchup")
                || sample.name().contains("replication_catchup_")
        }) {
            assert!(
                sample
                    .labels()
                    .iter()
                    .all(|(label, _)| allowed_labels.contains(&label.as_str()))
            );
        }
    }

    #[test]
    fn strict_protocol_metrics_expose_readiness_and_terminal_outcomes() {
        let samples = strict_protocol_metric_samples(2, true, 2, [1, 1], 1);
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_cluster_protocol_version"
                && sample.value() == 2.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_terminal_resolution_ready"
                && sample.value() == 1.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_unsupported_active_peers"
                && sample.value() == 2.0
        }));
        for outcome in ["commit", "abort"] {
            assert!(samples.iter().any(|sample| {
                sample.name() == "shitspeak_s2s_strict_replication_terminal_decisions_total"
                    && sample.labels() == [("outcome".to_owned(), outcome.to_owned())]
                    && sample.value() == 1.0
            }));
        }
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_fence_rejections_total"
                && sample.value() == 1.0
        }));
    }

    #[test]
    fn strict_admission_metrics_expose_bounded_phase_counts_and_barrier() {
        let samples = strict_admission_metric_samples(StrictAdmissionMetricSnapshot {
            admitted: 3,
            awaiting_local_cut: 2,
            awaiting_peer: 1,
            highest_barrier: 101,
            awaiting_history_only: 1,
            awaiting_clock_only: 2,
            awaiting_both_proofs: 3,
            clock_demand_commit_buffer: 1,
            clock_demand_proposal: 0,
            clock_demand_missing_peer_clocks: 2,
            unacknowledged_head_peers: 4,
        });
        for (state, value) in [
            ("admitted", 3.0),
            ("awaiting_local_cut", 2.0),
            ("awaiting_peer", 1.0),
        ] {
            assert!(samples.iter().any(|sample| {
                sample.name() == "shitspeak_s2s_strict_replication_admission_peer_states"
                    && sample.labels() == [("state".to_owned(), state.to_owned())]
                    && sample.value() == value
            }));
        }
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_admission_highest_barrier"
                && sample.value() == 101.0
        }));
        for (proof, value) in [("history", 1.0), ("clock", 2.0), ("both", 3.0)] {
            assert!(samples.iter().any(|sample| {
                sample.name() == "shitspeak_s2s_strict_replication_admission_awaiting_proofs"
                    && sample.labels() == [("proof".to_owned(), proof.to_owned())]
                    && sample.value() == value
            }));
        }
        for (reason, value) in [
            ("commit_buffer", 1.0),
            ("proposal", 0.0),
            ("missing_peer_clock", 2.0),
            ("head_ack", 4.0),
        ] {
            assert!(samples.iter().any(|sample| {
                sample.name() == "shitspeak_s2s_strict_replication_clock_demand"
                    && sample.labels() == [("reason".to_owned(), reason.to_owned())]
                    && sample.value() == value
            }));
        }
    }

    #[test]
    fn strict_admission_metrics_aggregate_only_live_runtime_sources() {
        let first = Arc::new(StrictAdmissionMetrics::default());
        first.update(2, 1, 0, 40);
        first.update_proof_waits(1, 0, 2);
        first.update_clock_demand(true, false, 1, 2);
        let second = Arc::new(StrictAdmissionMetrics::default());
        second.update(3, 0, 2, 90);
        second.update_proof_waits(0, 3, 1);
        second.update_clock_demand(true, true, 2, 1);
        let mut sources = vec![Arc::downgrade(&first), Arc::downgrade(&second)];

        assert_eq!(
            aggregate_strict_admission_sources(&mut sources),
            StrictAdmissionMetricSnapshot {
                admitted: 5,
                awaiting_local_cut: 1,
                awaiting_peer: 2,
                highest_barrier: 90,
                awaiting_history_only: 1,
                awaiting_clock_only: 3,
                awaiting_both_proofs: 3,
                clock_demand_commit_buffer: 2,
                clock_demand_proposal: 1,
                clock_demand_missing_peer_clocks: 3,
                unacknowledged_head_peers: 3,
            }
        );

        drop(second);
        assert_eq!(
            aggregate_strict_admission_sources(&mut sources),
            StrictAdmissionMetricSnapshot {
                admitted: 2,
                awaiting_local_cut: 1,
                awaiting_peer: 0,
                highest_barrier: 40,
                awaiting_history_only: 1,
                awaiting_clock_only: 0,
                awaiting_both_proofs: 2,
                clock_demand_commit_buffer: 1,
                clock_demand_proposal: 0,
                clock_demand_missing_peer_clocks: 1,
                unacknowledged_head_peers: 2,
            }
        );
        assert_eq!(sources.len(), 1);
    }

    #[test]
    fn strict_convergence_metrics_use_only_bounded_dimensions() {
        record_strict_probe_event(
            StrictProbeKind::History,
            CatchupReason::Admission,
            StrictProbeOutcome::IgnoredNonce,
        );
        record_strict_admission_event(StrictAdmissionEvent::HistoryProofTerminalMismatch);
        record_strict_history_election_event(StrictHistoryElectionEvent::Rearmed);
        record_strict_head_event(StrictHeadEvent::AckRejectedIdentity);
        record_strict_terminal_divergence_event(
            StrictTerminalDivergenceEvent::ForeignLineageDropped,
        );

        let samples = strict_convergence_event_metric_samples();
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_probe_events_total"
                && sample.labels()
                    == [
                        ("probe".to_owned(), "history".to_owned()),
                        ("reason".to_owned(), "admission".to_owned()),
                        ("outcome".to_owned(), "ignored_nonce".to_owned()),
                    ]
                && sample.value() >= 1.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_admission_events_total"
                && sample.labels()
                    == [(
                        "event".to_owned(),
                        "history_proof_terminal_mismatch".to_owned(),
                    )]
                && sample.value() >= 1.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_history_election_events_total"
                && sample.labels() == [("event".to_owned(), "rearmed".to_owned())]
                && sample.value() >= 1.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_head_events_total"
                && sample.labels() == [("event".to_owned(), "ack_rejected_identity".to_owned())]
                && sample.value() >= 1.0
        }));
        assert!(samples.iter().any(|sample| {
            sample.name() == "shitspeak_s2s_strict_replication_divergence_events_total"
                && sample.labels() == [("event".to_owned(), "foreign_lineage_dropped".to_owned())]
                && sample.value() >= 1.0
        }));
        for sample in samples {
            assert!(sample.labels().iter().all(|(label, _)| {
                ["probe", "reason", "outcome", "event"].contains(&label.as_str())
            }));
        }
    }
}
