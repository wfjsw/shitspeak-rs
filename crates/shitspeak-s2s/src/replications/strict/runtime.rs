//! Tempo state machine + delivery loop for one strict topic.
//!
//! The state struct ([`StrictState`]) is deliberately non-generic and
//! side-effect-free so it's directly unit-testable. The generic
//! [`StrictRuntime`] ties it to a `StrictReplicable` repo and a
//! [`StrictNet`] network abstraction (the production impl is
//! [`OverlayStrictNet`], the test impl is in `test_support.rs`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use prost::Message as _;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, trace, warn};

use super::super::capability::StrictParticipantCapability;
use super::super::config::ReplicationConfig;
use super::super::error::ReplicationError;
use super::super::metrics::{self, CatchupMode, ReplicationPipelineKind, ReplicationPipelineStage};
use super::super::proto::{
    self as repl_proto, REPLICATION_SERVICE_TAG, StrictAccept, StrictAcceptAck,
    StrictAcceptedValue, StrictBody, StrictCatchupReq, StrictCatchupResp, StrictClockTick,
    StrictCommit, StrictDecision, StrictDecisionAbort, StrictDecisionCommit, StrictDecisionOutcome,
    StrictFrozenTarget, StrictOriginAuth, StrictPendingValue, StrictPropose, StrictProposeAck,
    StrictProposeV1, StrictRecoveryAck, StrictRecoveryCommit, StrictRecoveryReq,
    StrictResolutionAck, StrictResolutionHint, StrictResolutionObserved, StrictResolutionPrepare,
    StrictTerminalOutcome, StrictTerminalState,
};
use super::super::protocol::{
    self as replication_protocol, ProtocolMember, ReplicationProtocolCapabilities,
};
use super::super::topic::ErasedStrictRuntime;
use super::terminal_journal::{
    FrozenTarget, TerminalDecision as JournalTerminalDecision, TerminalJournal,
    TerminalJournalError, TerminalJournalRecord, TerminalJournalSnapshotEntry, TerminalResolver,
};
use super::{HistoryMetadata, StrictCommitApplyOutcome, StrictLogMetadata, StrictReplicable};
use crate::overlay::{MembershipEvent, OverlayNetwork, OverlaySendOptions};
use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{MessageClass, RoutingMetric, ServiceLevel};

// ---------- Tunables ----------

/// Maximum number of clock ticks emitted in one demand-driven active burst.
///
/// A single tick should normally be enough after a commit because commit
/// handlers first raise the local clock to `ts_final`; the extra ticks cover
/// crossed wakeups and delayed peer observations without returning to the old
/// always-on heartbeat behavior.
const CLOCK_TICK_ACTIVE_BURST_TICKS: usize = 3;
const CLOCK_TICK_BURST_COOLDOWN_MULTIPLIER: u32 = 4;
pub(super) const STRICT_REPLICATION_SLOW_STAGE: Duration = Duration::from_secs(1);
const STRICT_DELIVERY_BLOCKED_LOG_INTERVAL: Duration = Duration::from_secs(5);
const STRICT_PROTOCOL_VERSION_V1: u32 = 1;
pub(super) const STRICT_PROTOCOL_VERSION_V2: u32 = super::super::protocol::STRICT_PROTOCOL_VERSION;
const NORMAL_ACCEPT_BALLOT: u64 = 0;
const OP_ID_BOOT_EPOCH_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;
/// Compute p95 of a slice of edge RTTs, clamped to
/// `[cfg.min_clock_tick(), cfg.max_clock_tick()]`. Empty input
/// → `cfg.fallback_clock_tick()`. Uses nearest-rank:
/// idx = `ceil(0.95 * n) - 1`.
pub(crate) fn p95_clock_tick_interval(samples: &[Duration], cfg: &ReplicationConfig) -> Duration {
    if samples.is_empty() {
        return cfg.fallback_clock_tick();
    }
    let mut buf: Vec<Duration> = samples.to_vec();
    buf.sort_unstable();
    let n = buf.len();
    // ceil(0.95 * n) - 1, with saturating subtraction for n=1.
    let idx_one_based = ((n as f64) * 0.95).ceil() as usize;
    let idx = idx_one_based.saturating_sub(1).min(n - 1);
    buf[idx].clamp(cfg.min_clock_tick(), cfg.max_clock_tick())
}

// ---------- OpId ----------

/// Globally unique op identifier. Encoded on the wire as `(hi, lo)`.
pub(crate) type OpId = (u64, u64);

#[inline]
pub(crate) fn make_op_id(self_id: NodeIdentifier, boot_epoch: u64, counter: u64) -> OpId {
    let hi = ((self_id as u64) << 48) | (boot_epoch & 0x0000_FFFF_FFFF_FFFF);
    (hi, counter)
}

/// Tempo fast quorum = ceil(3n/4). Defined in its own fn so unit tests can
/// pin the values across cluster sizes.
#[inline]
pub(crate) fn fast_quorum_size(n: usize) -> usize {
    if n == 0 { 0 } else { (3 * n).div_ceil(4) }
}

// ---------- Network abstraction ----------

/// A single LSDB/membership view used to freeze a proposal's target
/// incarnations together with the cumulative strict-protocol floor.
pub(crate) use replication_protocol::{StrictProtocolSnapshot, StrictProtocolTarget};

pub(crate) struct TerminalStatePage {
    pub(crate) states: Vec<StrictTerminalState>,
    pub(crate) next_cursor: u64,
    pub(crate) has_more: bool,
    pub(crate) oversized: bool,
    pub(crate) terminal_decision_generation: u64,
}

struct TerminalCatchupBudgetViolation {
    op_id: OpId,
    encoded_len: usize,
}

struct TerminalCatchupSnapshot {
    records: Vec<TerminalJournalSnapshotEntry>,
    terminal_decision_generation: u64,
    last_used_at: Instant,
}

/// A responder-side immutable image for one v2 snapshot transfer. This is
/// deliberately ephemeral: after a restart the requester detects the missing
/// transfer and restarts from a fresh, self-consistent image.
#[derive(Clone)]
pub(super) struct SnapshotTransfer {
    pub(super) id: u64,
    pub(super) version: u64,
    pub(super) snapshot_msgpack: Bytes,
    pub(super) snapshot_sha256: Bytes,
    pub(super) rank: HistoryRank,
    pub(super) terminal_decision_generation: u64,
    pub(super) last_used_at: Instant,
}

/// Receiver-side assembly state. Chunks are accepted strictly in byte order;
/// the repository never sees this image until its length and SHA-256 match.
pub(super) struct SnapshotReceiveTransfer {
    pub(super) id: u64,
    pub(super) version: u64,
    pub(super) total_bytes: u64,
    pub(super) snapshot_sha256: Bytes,
    pub(super) rank: HistoryRank,
    pub(super) terminal_decision_generation: u64,
    pub(super) next_cursor: u64,
    pub(super) snapshot_msgpack: Vec<u8>,
    pub(super) last_used_at: Instant,
}

#[async_trait]
pub(crate) trait StrictNet: Send + Sync + 'static {
    async fn send_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: StrictBody,
    ) -> Result<(), ReplicationError>;
    /// Send authenticated control traffic with one route-diverse duplicate.
    /// The default keeps lightweight test networks on their ordinary
    /// single-send behavior; production overlays override it when a lost
    /// one-way control message would strand a protocol round.
    async fn send_redundant_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: StrictBody,
    ) -> Result<(), ReplicationError> {
        self.send_unicast(dst, topic, body).await
    }
    async fn send_redundant_multicast(
        &self,
        dsts: &[NodeIdentifier],
        topic: &str,
        body: StrictBody,
    ) -> Result<(), ReplicationError> {
        self.send_multicast(dsts, topic, body).await
    }
    async fn send_bulk_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: StrictBody,
        _retry_delay: Duration,
    ) -> Result<(), ReplicationError> {
        self.send_unicast(dst, topic, body).await
    }
    async fn send_multicast(
        &self,
        dsts: &[NodeIdentifier],
        topic: &str,
        body: StrictBody,
    ) -> Result<(), ReplicationError>;
    async fn send_broadcast(&self, topic: &str, body: StrictBody) -> Result<(), ReplicationError>;
    /// Encoded strict replication payload length. Production implementations
    /// include any origin-proof bytes added immediately before transmission.
    fn encoded_strict_payload_len(
        &self,
        topic: &str,
        body: &StrictBody,
    ) -> Result<usize, ReplicationError> {
        Ok(repl_proto::wrap_strict(topic, body.clone()).encoded_len())
    }
    /// Encoded strict replication payload length under the v2 contract.
    ///
    /// Unlike `encoded_strict_payload_len`, this deliberately reserves the
    /// end-to-end origin-authentication envelope even before the local LSA
    /// advertises v2. It protects terminal admission and startup validation
    /// from accepting records that cannot later fit in authenticated catchup.
    fn encoded_v2_strict_payload_len(
        &self,
        topic: &str,
        body: &StrictBody,
    ) -> Result<usize, ReplicationError> {
        Ok(repl_proto::wrap_strict(topic, body.clone()).encoded_len())
    }
    fn alive_members(&self) -> Vec<NodeIdentifier>;
    fn member_boot_epoch(&self, _node: NodeIdentifier) -> Option<u64> {
        None
    }
    fn has_route(&self, _dst: NodeIdentifier, _level: ServiceLevel) -> bool {
        true
    }
    fn has_live_route(&self, dst: NodeIdentifier, level: ServiceLevel) -> bool {
        self.has_route(dst, level)
    }
    /// Effective strict protocol floor for this replication view. The
    /// participant floor covers strict endpoints; the transit floor covers
    /// relay-capable members so an old relay cannot strip opaque frames.
    fn strict_replication_protocol_version(&self) -> u32 {
        0
    }

    /// Local capability may fall below the advertised/LSDB floor before an
    /// asynchronous LSA downgrade reaches peers. Inbound v2 participation
    /// must consult this immediate fail-closed value.
    fn local_strict_replication_protocol_version(&self) -> u32 {
        self.strict_replication_protocol_version()
    }
    /// Version advertised by one peer. Terminal-state catchup adds a
    /// continuation exchange which legacy binaries do not understand, so it
    /// must be gated by the requester rather than only by the cluster floor.
    fn peer_strict_replication_protocol_version(&self, _peer: NodeIdentifier) -> u32 {
        self.strict_replication_protocol_version()
    }
    /// Freeze the participant/transit capability floor and strict target set
    /// from one membership view. Production avoids sampling these
    /// independently while LSDB updates are in flight; the default keeps
    /// test transports simple.
    fn strict_protocol_snapshot(&self) -> StrictProtocolSnapshot {
        StrictProtocolSnapshot {
            negotiated_version: self.strict_replication_protocol_version(),
            targets: self
                .alive_members()
                .into_iter()
                .map(|node| StrictProtocolTarget {
                    node,
                    boot_epoch: self.member_boot_epoch(node).unwrap_or_default(),
                })
                .collect(),
        }
    }
    fn unsupported_active_protocol_peers(&self, _required_version: u32) -> usize {
        0
    }
    fn strict_protocol_state_dir(&self) -> Option<PathBuf> {
        None
    }
    /// Whether this node can originate bounded, authenticated v2 frames.
    /// This is intentionally independent of the local LSA version so
    /// capability activation can fail closed before advertising v2.
    fn current_protocol_prerequisites_ready(
        &self,
        topic: &str,
        strict_max_catchup_bytes: usize,
    ) -> bool {
        // Test and alternate transports inherit this conservative check. The
        // production implementation below additionally reserves the actual
        // origin-authentication envelope for its local identity.
        v2_control_prerequisite_bodies(u32::MAX as NodeIdentifier)
            .into_iter()
            .all(|body| {
                self.encoded_v2_strict_payload_len(topic, &body)
                    .is_ok_and(|encoded_len| {
                        v2_prerequisite_payload_fits(
                            self.max_replication_payload_bytes(),
                            strict_max_catchup_bytes,
                            encoded_len,
                        )
                    })
            })
    }
    /// Maximum payload budget for one replication message after accounting for
    /// the local transport frame and overlay envelope.
    fn max_replication_payload_bytes(&self) -> usize {
        usize::MAX
    }
    /// Stop advertising terminal-resolution support after a local durable
    /// journal failure. Test transports intentionally keep this as a no-op.
    fn disable_strict_replication_protocol(&self) {}
    /// Clamp the local advertisement when one registered strict repository
    /// cannot honor the current protocol contract. A later coordinated
    /// registration pass may clear this non-sticky capability loss.
    fn report_strict_replication_repository_capability_loss(&self) {}
    /// Snapshot of every directed-edge RTT in the overlay's LSDB. Used to
    /// scale the clock-tick cadence to measured network latency.
    fn edge_rtt_snapshot(&self) -> Vec<Duration>;
}

/// Production `StrictNet` impl that wraps `OverlayNetwork`.
pub(crate) struct OverlayStrictNet {
    overlay: OverlayNetwork,
    participant_capability: Arc<StrictParticipantCapability>,
}

impl OverlayStrictNet {
    pub(crate) fn new(
        overlay: OverlayNetwork,
        participant_capability: Arc<StrictParticipantCapability>,
    ) -> Self {
        Self {
            overlay,
            participant_capability,
        }
    }

    fn member_replication_capabilities(
        member: &crate::overlay::MemberSnapshot,
    ) -> ReplicationProtocolCapabilities {
        let legacy = member.replication_services();
        replication_protocol::advertised_replication_capabilities(
            member.upper_layer_capabilities(),
            legacy.strict(),
            legacy.content(),
            legacy.owner(),
            member.strict_replication_protocol_version(),
        )
    }

    fn local_replication_capabilities(&self) -> ReplicationProtocolCapabilities {
        let services = self.overlay.legacy_local_replication_services();
        ReplicationProtocolCapabilities::new(
            services.strict(),
            services.content(),
            services.owner(),
            self.participant_capability.protocol_version(),
        )
    }

    fn protocol_members(&self) -> Vec<ProtocolMember> {
        self.overlay
            .members()
            .into_iter()
            .map(|member| {
                let capabilities = Self::member_replication_capabilities(&member);
                ProtocolMember::new(
                    member.node_id(),
                    member.boot_epoch(),
                    member.status().is_reachable(),
                    capabilities.strict_enabled(),
                    capabilities.strict_participant_protocol_version(),
                )
            })
            .collect()
    }

    fn protocol_snapshot(&self) -> StrictProtocolSnapshot {
        let local = self.local_replication_capabilities();
        replication_protocol::strict_protocol_snapshot(
            self.protocol_members(),
            local
                .strict_enabled()
                .then(|| local.strict_participant_protocol_version()),
        )
    }

    fn strict_origin_auth(
        &self,
        topic: &str,
        body: &StrictBody,
        reserve_max_signature_len: bool,
    ) -> Result<StrictOriginAuth, ReplicationError> {
        let origin_node = self.overlay.local_node_id() as u32;
        let origin_boot_epoch = self.overlay.local_boot_epoch();
        let signing_payload =
            repl_proto::strict_origin_signing_payload(topic, body, origin_node, origin_boot_epoch)?;
        let proof = self
            .overlay
            .sign_origin_payload(&signing_payload)
            .map_err(|error| ReplicationError::OriginAuthentication(error.to_string()))?;
        let signature = if reserve_max_signature_len {
            vec![0; proof.maximum_signature_len()]
        } else {
            proof.signature().to_vec()
        };
        let origin_auth = StrictOriginAuth {
            origin_node,
            origin_boot_epoch,
            signature_scheme: u32::from(proof.signature_scheme()),
            certificate_chain: proof
                .certificate_chain()
                .iter()
                .map(|certificate| Bytes::copy_from_slice(certificate))
                .collect(),
            signature: Bytes::from(signature),
        };
        if !repl_proto::strict_origin_auth_within_bounds(&origin_auth) {
            return Err(ReplicationError::OriginAuthentication(
                "local certificate proof exceeds the strict v2 wire bound".to_owned(),
            ));
        }
        Ok(origin_auth)
    }

    fn encode_strict_payload(
        &self,
        topic: &str,
        body: StrictBody,
    ) -> Result<Bytes, ReplicationError> {
        // Always attach an end-to-end proof in production. The field is
        // additive, so legacy decoders ignore it, but this avoids an LSA
        // transition racing a v2-associated response into an unsigned frame.
        let origin_auth = match self.strict_origin_auth(topic, &body, false) {
            Ok(origin_auth) => origin_auth,
            Err(error) => {
                self.participant_capability.disable_permanently();
                return Err(error);
            }
        };
        let message = repl_proto::wrap_strict_with_origin_auth(topic, body, origin_auth);
        Ok(repl_proto::encode(&message)?)
    }
}

fn minimum_v2_catchup_response_body(history_node: NodeIdentifier) -> StrictBody {
    // This is the smallest semantically valid v2 response: an empty history
    // probe after the responder has completed terminal-fence pagination.
    // It is an activation-time floor, not a substitute for normal per-frame
    // admission checks on actual terminal states or snapshot chunks.
    StrictBody::CatchupResp(StrictCatchupResp {
        snapshot_version: 0,
        snapshot_msgpack: Bytes::new(),
        ops: Vec::new(),
        has_more: false,
        next_chunk_token: 0,
        too_old_use_snapshot: false,
        history_version: 0,
        history_freshness: 0,
        runtime_started_at: 1,
        history_node: history_node as u32,
        terminal_states: Vec::new(),
        next_terminal_state_cursor: u64::MAX,
        terminal_states_has_more: false,
        terminal_sync_only: false,
        request_force_snapshot: false,
        request_history_probe_only: true,
        terminal_decision_generation: 0,
        snapshot_transfer_id: 0,
        snapshot_chunk_cursor: 0,
        snapshot_next_cursor: 0,
        snapshot_total_bytes: 0,
        snapshot_sha256: Bytes::new(),
        snapshot_has_more: false,
        snapshot_transfer_rejected: false,
    })
}

/// The smallest snapshot-control response that must always be transmitable
/// under v2. It deliberately includes every optional field that the chunk
/// and rejection control paths can require, with maximal scalar widths. The
/// value is an activation-time sizing sentinel only; no peer receives this
/// semantically contradictory combination of flags.
fn minimum_v2_snapshot_control_response_body(history_node: NodeIdentifier) -> StrictBody {
    StrictBody::CatchupResp(StrictCatchupResp {
        snapshot_version: u64::MAX,
        snapshot_msgpack: Bytes::from_static(&[0]),
        ops: Vec::new(),
        has_more: true,
        next_chunk_token: u64::MAX,
        too_old_use_snapshot: true,
        history_version: u64::MAX,
        history_freshness: i64::MAX,
        runtime_started_at: u64::MAX,
        history_node: history_node as u32,
        terminal_states: Vec::new(),
        next_terminal_state_cursor: u64::MAX,
        terminal_states_has_more: true,
        terminal_sync_only: true,
        request_force_snapshot: true,
        request_history_probe_only: true,
        terminal_decision_generation: u64::MAX,
        snapshot_transfer_id: u64::MAX,
        snapshot_chunk_cursor: u64::MAX,
        snapshot_next_cursor: u64::MAX,
        snapshot_total_bytes: u64::MAX,
        snapshot_sha256: Bytes::from_static(&[0; 32]),
        snapshot_has_more: true,
        snapshot_transfer_rejected: true,
    })
}

fn v2_control_prerequisite_bodies(history_node: NodeIdentifier) -> [StrictBody; 2] {
    [
        minimum_v2_catchup_response_body(history_node),
        minimum_v2_snapshot_control_response_body(history_node),
    ]
}

fn v2_prerequisite_payload_fits(
    local_budget: usize,
    strict_max_catchup_bytes: usize,
    encoded_len: usize,
) -> bool {
    local_budget >= repl_proto::STRICT_V2_MAX_REPLICATION_PAYLOAD_BYTES
        && encoded_len
            <= strict_max_catchup_bytes
                .min(local_budget)
                .min(repl_proto::STRICT_V2_MAX_REPLICATION_PAYLOAD_BYTES)
}

#[async_trait]
impl StrictNet for OverlayStrictNet {
    async fn send_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: StrictBody,
    ) -> Result<(), ReplicationError> {
        let options = if matches!(&body, StrictBody::CatchupResp(_)) {
            OverlaySendOptions::default().allow_l1_compression()
        } else {
            OverlaySendOptions::default()
        };
        let encode_started_at = Instant::now();
        let encoded = self.encode_strict_payload(topic, body);
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::ProtobufEncode,
            encode_started_at.elapsed(),
        );
        let bytes = encoded?;
        self.overlay
            .send_unicast_unordered_with_routing_metric_and_options(
                dst,
                REPLICATION_SERVICE_TAG,
                ServiceLevel::Reliable,
                RoutingMetric::ReliableCost,
                MessageClass::Regular,
                bytes,
                options,
            )
            .await?;
        Ok(())
    }

    async fn send_redundant_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: StrictBody,
    ) -> Result<(), ReplicationError> {
        let message_class = match &body {
            StrictBody::ProposeAck(_)
            | StrictBody::AcceptAck(_)
            | StrictBody::ResolutionAck(_)
            | StrictBody::Decision(_) => MessageClass::HighPriority,
            // A metadata-only response is the liveness escape hatch for a
            // durable terminal fence or delivery watermark. Keep responses
            // in the same control lane as ACKs while leaving requests and
            // bulk history regular.
            StrictBody::CatchupResp(response) if response.request_history_probe_only => {
                MessageClass::HighPriority
            }
            _ => MessageClass::Regular,
        };
        let bytes = self.encode_strict_payload(topic, body)?;
        let primary_next_hop = self.overlay.route_to_with_metric(
            dst,
            ServiceLevel::Reliable,
            RoutingMetric::ReliableCost,
        );
        let primary = self
            .overlay
            .send_unicast_unordered_with_routing_metric_and_options(
                dst,
                REPLICATION_SERVICE_TAG,
                ServiceLevel::Reliable,
                RoutingMetric::ReliableCost,
                message_class,
                bytes.clone(),
                OverlaySendOptions::default(),
            )
            .await;
        let Some(primary_next_hop) = primary_next_hop else {
            return primary.map_err(Into::into);
        };

        // A duplicate is useful only when it takes a different first hop.
        // If no alternate exists, preserve the primary result rather than
        // turning a successful enqueue into a spurious failure.
        let alternate = self
            .overlay
            .send_unicast_unordered_with_routing_metric_and_options(
                dst,
                REPLICATION_SERVICE_TAG,
                ServiceLevel::Reliable,
                RoutingMetric::ReliableCost,
                message_class,
                bytes,
                OverlaySendOptions::default().avoid_first_hop(primary_next_hop),
            )
            .await;
        match primary {
            Ok(()) => Ok(()),
            Err(primary_error) => alternate.map_err(|_| primary_error).map_err(Into::into),
        }
    }

    async fn send_redundant_multicast(
        &self,
        dsts: &[NodeIdentifier],
        topic: &str,
        body: StrictBody,
    ) -> Result<(), ReplicationError> {
        if dsts.is_empty() {
            return Ok(());
        }
        let message_class = if matches!(
            &body,
            StrictBody::ProposeV1(_)
                | StrictBody::ProposeAck(_)
                | StrictBody::Accept(_)
                | StrictBody::AcceptAck(_)
                | StrictBody::ResolutionPrepare(_)
                | StrictBody::ResolutionAck(_)
                | StrictBody::Decision(_)
                | StrictBody::ClockTick(_)
        ) {
            MessageClass::HighPriority
        } else {
            MessageClass::Regular
        };
        let encode_started_at = Instant::now();
        let bytes = self.encode_strict_payload(topic, body)?;
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::ProtobufEncode,
            encode_started_at.elapsed(),
        );
        let primary = self
            .overlay
            .send_multicast_unordered_with_routing_metric(
                dsts,
                REPLICATION_SERVICE_TAG,
                ServiceLevel::Reliable,
                RoutingMetric::ReliableCost,
                message_class,
                bytes.clone(),
            )
            .await;
        let mut alternate_succeeded = false;
        for dst in dsts.iter().copied() {
            let Some(primary_next_hop) = self.overlay.route_to_with_metric(
                dst,
                ServiceLevel::Reliable,
                RoutingMetric::ReliableCost,
            ) else {
                continue;
            };
            if self
                .overlay
                .send_unicast_unordered_with_routing_metric_and_options(
                    dst,
                    REPLICATION_SERVICE_TAG,
                    ServiceLevel::Reliable,
                    RoutingMetric::ReliableCost,
                    message_class,
                    bytes.clone(),
                    OverlaySendOptions::default().avoid_first_hop(primary_next_hop),
                )
                .await
                .is_ok()
            {
                alternate_succeeded = true;
            }
        }
        match primary {
            Ok(()) | Err(_) if alternate_succeeded => Ok(()),
            Ok(()) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn send_bulk_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: StrictBody,
        retry_delay: Duration,
    ) -> Result<(), ReplicationError> {
        let encode_started_at = Instant::now();
        let encoded = self.encode_strict_payload(topic, body);
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::ProtobufEncode,
            encode_started_at.elapsed(),
        );
        let bytes = encoded?;
        let options = OverlaySendOptions::default()
            .allow_l1_compression()
            .expire_after(retry_delay);
        let result = self
            .overlay
            .send_unicast_unordered_with_routing_metric_and_options(
                dst,
                REPLICATION_SERVICE_TAG,
                ServiceLevel::Reliable,
                RoutingMetric::ReliableCost,
                MessageClass::Regular,
                bytes.clone(),
                options,
            )
            .await;
        if let Err(error) = result {
            if replication_bulk_backpressure(&error) {
                sleep(retry_delay).await;
                self.overlay
                    .send_unicast_unordered_with_routing_metric_and_options(
                        dst,
                        REPLICATION_SERVICE_TAG,
                        ServiceLevel::Reliable,
                        RoutingMetric::ReliableCost,
                        MessageClass::Regular,
                        bytes,
                        options,
                    )
                    .await?;
                return Ok(());
            }
            return Err(error.into());
        }
        Ok(())
    }

    async fn send_multicast(
        &self,
        dsts: &[NodeIdentifier],
        topic: &str,
        body: StrictBody,
    ) -> Result<(), ReplicationError> {
        if dsts.is_empty() {
            return Ok(());
        }
        let encode_started_at = Instant::now();
        let encoded = self.encode_strict_payload(topic, body);
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::ProtobufEncode,
            encode_started_at.elapsed(),
        );
        let bytes = encoded?;
        self.overlay
            .send_multicast_unordered_with_routing_metric(
                dsts,
                REPLICATION_SERVICE_TAG,
                ServiceLevel::Reliable,
                RoutingMetric::ReliableCost,
                MessageClass::Regular,
                bytes,
            )
            .await?;
        Ok(())
    }

    async fn send_broadcast(&self, topic: &str, body: StrictBody) -> Result<(), ReplicationError> {
        let dsts = self.alive_members();
        self.send_multicast(&dsts, topic, body).await
    }

    fn encoded_strict_payload_len(
        &self,
        topic: &str,
        body: &StrictBody,
    ) -> Result<usize, ReplicationError> {
        self.encoded_v2_strict_payload_len(topic, body)
    }

    fn encoded_v2_strict_payload_len(
        &self,
        topic: &str,
        body: &StrictBody,
    ) -> Result<usize, ReplicationError> {
        // Construct a proof first so unavailable local signing material or an
        // oversized local certificate fails closed. Size every v2 candidate
        // against the protocol maximum, not this node's smaller proof.
        let _ = self.strict_origin_auth(topic, body, false)?;
        let origin_auth = repl_proto::strict_origin_auth_budget_template();
        Ok(repl_proto::strict_encoded_len_with_origin_auth(
            topic,
            body,
            &origin_auth,
        ))
    }

    fn alive_members(&self) -> Vec<NodeIdentifier> {
        self.protocol_snapshot()
            .targets
            .into_iter()
            .map(|target| target.node)
            .collect()
    }

    fn strict_replication_protocol_version(&self) -> u32 {
        let local = self.local_replication_capabilities();
        replication_protocol::strict_protocol_floor(
            &self.protocol_members(),
            local
                .strict_enabled()
                .then(|| local.strict_participant_protocol_version()),
        )
    }

    fn local_strict_replication_protocol_version(&self) -> u32 {
        self.participant_capability.protocol_version()
    }

    fn peer_strict_replication_protocol_version(&self, peer: NodeIdentifier) -> u32 {
        self.overlay
            .member(peer)
            .map(|member| {
                Self::member_replication_capabilities(&member).strict_participant_protocol_version()
            })
            .unwrap_or_default()
    }

    fn strict_protocol_snapshot(&self) -> StrictProtocolSnapshot {
        self.protocol_snapshot()
    }

    fn unsupported_active_protocol_peers(&self, required_version: u32) -> usize {
        replication_protocol::unsupported_protocol_peers(self.protocol_members(), required_version)
    }

    fn strict_protocol_state_dir(&self) -> Option<PathBuf> {
        self.overlay.persistence_dir()
    }

    fn current_protocol_prerequisites_ready(
        &self,
        topic: &str,
        strict_max_catchup_bytes: usize,
    ) -> bool {
        let local_budget = self.overlay.max_replication_payload_bytes();
        if local_budget < repl_proto::STRICT_V2_MAX_REPLICATION_PAYLOAD_BYTES {
            return false;
        }
        v2_control_prerequisite_bodies(self.overlay.local_node_id())
            .into_iter()
            .all(|body| {
                self.encoded_v2_strict_payload_len(topic, &body)
                    .is_ok_and(|encoded_len| {
                        v2_prerequisite_payload_fits(
                            local_budget,
                            strict_max_catchup_bytes,
                            encoded_len,
                        )
                    })
            })
    }

    fn max_replication_payload_bytes(&self) -> usize {
        self.overlay.max_replication_payload_bytes()
    }

    fn disable_strict_replication_protocol(&self) {
        self.participant_capability.disable_permanently();
    }

    fn report_strict_replication_repository_capability_loss(&self) {
        self.participant_capability
            .report_repository_capability_loss();
    }

    fn member_boot_epoch(&self, node: NodeIdentifier) -> Option<u64> {
        if node == self.overlay.local_node_id() {
            Some(self.overlay.local_boot_epoch())
        } else {
            self.overlay.member(node).map(|member| member.boot_epoch())
        }
    }

    fn has_route(&self, dst: NodeIdentifier, level: ServiceLevel) -> bool {
        self.overlay.has_route(dst, level)
    }

    fn has_live_route(&self, dst: NodeIdentifier, level: ServiceLevel) -> bool {
        self.overlay.has_live_route(dst, level)
    }

    fn edge_rtt_snapshot(&self) -> Vec<Duration> {
        self.overlay.edge_rtt_snapshot()
    }
}

fn replication_bulk_backpressure(error: &crate::overlay::OverlayError) -> bool {
    matches!(
        error,
        crate::overlay::OverlayError::Send(shitspeak_s2s_transport::SendError::Backpressure { .. })
    )
}

// ---------- State machine ----------

pub(crate) struct Proposal {
    pub op_msgpack: Bytes,
    pub ts_propose: u64,
    pub acks: HashMap<NodeIdentifier, u64>, // ack_node -> ts_local
    pub target_set: HashSet<NodeIdentifier>,
    pub(super) target_epochs: HashMap<NodeIdentifier, u64>,
    pub(super) invalid_targets: HashSet<NodeIdentifier>,
    pub accepted_waker: Option<oneshot::Sender<()>>,
    pub waker: Option<oneshot::Sender<Result<u64, ReplicationError>>>,
    pub committed: bool,
    pub protocol_version: u32,
    pub accept_acks: HashMap<NodeIdentifier, bool>,
    pub accept_started: bool,
    /// The immutable phase-two value emitted after the phase-one fast quorum.
    /// V2 retransmission must retain this exact body rather than rebuilding it
    /// from a later logical clock.
    pub(super) phase_two_accept: Option<StrictAccept>,
    #[cfg(any(test, feature = "test-support"))]
    pub(super) phase_two_retry_attempts: usize,
    #[cfg(any(test, feature = "test-support"))]
    pub(super) phase_two_floor_pauses: usize,
    pub started_at: Instant,
    /// Permit released when this proposal is removed from `proposals`.
    pub _permit: OwnedSemaphorePermit,
}

/// A caller-visible proposal that expired before a terminal decision. The
/// caller is released immediately, while an unresolved v2 fence is handed to
/// the durable terminal-resolution path after the state lock is released.
pub(crate) struct ExpiredProposal {
    op_id: OpId,
    waker: Option<oneshot::Sender<Result<u64, ReplicationError>>>,
    needs_v2_resolution: bool,
}

pub(crate) struct BufferedOp {
    pub op_msgpack: Bytes,
    pub ts_final: u64,
    pub op_id: OpId,
    buffered_at: Instant,
}

pub(crate) type BufferKey = (u64, OpId); // (ts_final, op_id)

pub(crate) const HISTORY_ELECTION_SNAPSHOT_TOKEN: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HistoryRank {
    pub version: u64,
    pub freshness: i64,
    pub runtime_started_at: u64,
    pub node_id: NodeIdentifier,
}

fn bootstrap_reachable_peers(net: &dyn StrictNet, self_id: NodeIdentifier) -> Vec<NodeIdentifier> {
    net.alive_members()
        .into_iter()
        // A logical route can outlive a broken first-hop transport while the
        // link-state view converges. Bootstrap must not wait for a probe sent
        // through such a route: it would pin the election until its coarse
        // timeout even though the remaining live peers have already replied.
        .filter(|node| *node != self_id && net.has_live_route(*node, ServiceLevel::Reliable))
        .collect()
}

impl HistoryRank {
    pub fn local<R: StrictReplicable>(rt: &StrictRuntime<R>) -> Self {
        let metadata = rt.repo.history_metadata();
        Self::from_metadata(metadata, rt.boot_epoch, rt.self_id)
    }

    pub fn from_metadata(
        metadata: HistoryMetadata,
        runtime_started_at: u64,
        node_id: NodeIdentifier,
    ) -> Self {
        Self {
            version: metadata.version,
            freshness: metadata.freshness,
            runtime_started_at,
            node_id,
        }
    }

    pub fn beats(self, other: Self) -> bool {
        (
            self.version,
            self.freshness,
            std::cmp::Reverse(self.runtime_started_at),
            std::cmp::Reverse(self.node_id),
        ) > (
            other.version,
            other.freshness,
            std::cmp::Reverse(other.runtime_started_at),
            std::cmp::Reverse(other.node_id),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HistoryElectionCandidate {
    pub rank: HistoryRank,
    pub snapshot_version: u64,
    pub snapshot_msgpack: Bytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HistoryElectionSnapshotRequest {
    peer: NodeIdentifier,
    expected_rank: HistoryRank,
}

impl HistoryElectionSnapshotRequest {
    pub(crate) fn new(peer: NodeIdentifier, expected_rank: HistoryRank) -> Self {
        Self {
            peer,
            expected_rank,
        }
    }

    pub(crate) fn peer(&self) -> NodeIdentifier {
        self.peer
    }

    pub(crate) fn expected_rank(&self) -> HistoryRank {
        self.expected_rank
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HistoryElectionPhase {
    Idle,
    Probing {
        pending_peers: HashSet<NodeIdentifier>,
        best_remote_rank: Option<HistoryRank>,
        started_at: Instant,
    },
    FetchingSnapshot {
        peer: NodeIdentifier,
        expected_rank: HistoryRank,
        started_at: Instant,
    },
    Installing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HistoryProbeResponseOutcome {
    Ignored,
    Pending,
    Finished,
    FetchSnapshot(HistoryElectionSnapshotRequest),
}

impl HistoryProbeResponseOutcome {
    pub(crate) fn is_ignored(&self) -> bool {
        matches!(self, Self::Ignored)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HistorySnapshotResponseOutcome {
    Ignored,
    Retry,
    Install(HistoryElectionCandidate),
}

impl Default for HistoryElectionPhase {
    fn default() -> Self {
        Self::Idle
    }
}

/// A `StrictPropose` we've ack'd but not yet committed. Held by every
/// replica that received the original Propose, so a takeover coordinator
/// can recover the op via the Tempo slow-path if the original coord dies.
pub(crate) struct PendingPropose {
    pub coord_node: NodeIdentifier,
    pub op_msgpack: Bytes,
    pub ts_local: u64,
    pub seen_at: Instant,
    pub protocol_version: u32,
    /// Immutable v2 membership descriptor. V1 intentionally has no
    /// descriptor and is therefore never re-resolved against a new view.
    frozen_targets: Option<Vec<FrozenTarget>>,
    /// A v2 proposal may only contribute an Accept after its descriptor and
    /// pending value have reached the terminal journal.
    v2_descriptor_durable: bool,
}

#[derive(Clone)]
struct AcceptedValue {
    ballot: u64,
    ts_final: u64,
    op_msgpack: Bytes,
}

#[derive(Clone)]
enum TerminalDecision {
    Commit(AcceptedValue),
    Abort { ballot: u64 },
}

#[derive(Clone)]
pub(crate) struct TerminalDecisionIdentity {
    pub(crate) resolver: TerminalResolver,
    pub(crate) frozen_targets: Vec<FrozenTarget>,
}

#[derive(Clone)]
pub(crate) struct TerminalCommitProof {
    pub(crate) ballot: u64,
    pub(crate) identity: TerminalDecisionIdentity,
}

struct Resolution {
    coord_node: NodeIdentifier,
    ballot: u64,
    started_at: Instant,
    target_set: HashSet<NodeIdentifier>,
    target_epochs: HashMap<NodeIdentifier, u64>,
    invalid_targets: HashSet<NodeIdentifier>,
    prepare_acks: HashMap<NodeIdentifier, ResolutionPrepareAck>,
}

#[derive(Clone)]
struct ResolutionPrepareAck {
    promised: bool,
    observed: ResolutionObserved,
}

#[derive(Clone)]
enum ResolutionObserved {
    None,
    Terminal {
        decision: TerminalDecision,
        identity: Option<TerminalDecisionIdentity>,
    },
    Accepted(AcceptedValue),
    Pending {
        ts_local: u64,
        op_msgpack: Bytes,
        protocol_version: u32,
    },
}

enum ResolutionDecision {
    Existing {
        decision: TerminalDecision,
        identity: Option<TerminalDecisionIdentity>,
    },
    Fresh(TerminalDecision),
}

struct PendingProposeRetry {
    op_msgpack: Bytes,
    ts_propose: u64,
    src_clock: u64,
    dsts: Vec<NodeIdentifier>,
    started_at: Instant,
    ack_count: usize,
    target_count: usize,
    fast_quorum: usize,
    accept_started: bool,
    protocol_version: u32,
    frozen_targets: Vec<FrozenTarget>,
}

struct PendingAcceptRetry {
    body: StrictAccept,
    dsts: Vec<NodeIdentifier>,
    started_at: Instant,
    accepted_count: usize,
    target_count: usize,
    fast_quorum: usize,
}

struct AcceptedProposal {
    body: StrictBody,
    dsts: Vec<NodeIdentifier>,
    accepted_waker: Option<oneshot::Sender<()>>,
    elapsed: Duration,
    ack_count: usize,
    target_count: usize,
    fast_quorum: usize,
    ts_final: u64,
    clock_now: u64,
    op_bytes: usize,
    commit_buffer_len: usize,
    pending_local_proposals: usize,
    pending_remote_proposes: usize,
}

struct V1AcceptProposal {
    body: StrictAccept,
    dsts: Vec<NodeIdentifier>,
}

enum ProposeQuorumOutcome {
    Legacy(AcceptedProposal),
    V1(V1AcceptProposal),
}

struct BufferedCommitLog {
    source: &'static str,
    from: Option<NodeIdentifier>,
    coord_node: Option<NodeIdentifier>,
    op_id: OpId,
    ts_final: u64,
    clock_now: u64,
    op_bytes: usize,
    commit_buffer_len: usize,
    pending_local_proposals: usize,
    pending_remote_proposes: usize,
}

#[derive(Clone, Copy)]
struct DeliveryWatermark {
    high_water: u64,
    low_water_node: NodeIdentifier,
    low_water_clock: u64,
    missing_clock_peers: usize,
}

#[derive(Clone)]
struct UncommittedProposalBlocker {
    kind: &'static str,
    op_id: OpId,
    coord_node: NodeIdentifier,
    ts: u64,
    age: Duration,
}

#[derive(Clone, Copy)]
struct NextBufferedOpDiagnostics {
    key: BufferKey,
    op_id: OpId,
    ts_final: u64,
    buffered_for: Duration,
}

struct DeliveryBlockDiagnostics {
    next: NextBufferedOpDiagnostics,
    raw_high_water: u64,
    effective_high_water: u64,
    watermark: DeliveryWatermark,
    pending_blocker: Option<UncommittedProposalBlocker>,
    alive_count: usize,
    commit_buffer_len: usize,
    pending_local_proposals: usize,
    pending_remote_proposes: usize,
}

#[derive(Default)]
struct DeliveryBlockedLogState {
    key: Option<BufferKey>,
    blocked_since: Option<Instant>,
    last_log_at: Option<Instant>,
}

/// Pure Tempo state machine. No async, no I/O — all logic operates on
/// in-memory state and returns effects. Designed to be exercised by unit
/// tests directly.
pub(crate) struct StrictState {
    pub clock: u64,
    /// `peer_clocks[m]` is the highest `src_clock` we've observed from `m`,
    /// piggybacked on any inbound frame. Includes self (kept in sync with
    /// `clock`).
    pub peer_clocks: HashMap<NodeIdentifier, u64>,
    pub proposals: HashMap<OpId, Proposal>,
    pub commit_buffer: BTreeMap<BufferKey, BufferedOp>,
    /// Terminal commits that have left `commit_buffer` and are awaiting a
    /// repository delivery outcome. A snapshot may not replace state across
    /// this interval because it could retain an op id while erasing the
    /// mutation just delivered for it.
    delivering_commits: HashSet<OpId>,
    pub delivered_high_water: u64,
    /// Per-op-id pending Propose state (for slow-path recovery).
    pub pending_proposes: HashMap<OpId, PendingPropose>,
    /// Per-op-id highest ballot we've promised in a `RecoveryReq`. Replicas
    /// reject any `RecoveryCommit` with `ballot < promised`.
    pub recovery_promises: HashMap<OpId, u64>,
    /// Per-op-id highest ballot promised by the v1 terminal-resolution
    /// protocol. A promise fences ordinary v1 accepts and commits.
    resolution_promises: HashMap<OpId, u64>,
    /// Accepted v1 values. A later resolver must retain the highest-ballot
    /// value rather than selecting an abort or a different timestamp.
    accepted_values: HashMap<OpId, AcceptedValue>,
    /// Durable terminal outcome mirrored in memory for hot-path checks.
    terminal_decisions: HashMap<OpId, TerminalDecision>,
    /// v2 identity paired with terminal outcomes that were authenticated
    /// against a frozen proposal descriptor.
    terminal_decision_identities: HashMap<OpId, TerminalDecisionIdentity>,
    /// Op-ids ever buffered for delivery (via `Commit` or `RecoveryCommit`).
    /// Used to dedup repeat commits with possibly-different `ts_final`.
    pub committed_ids: HashSet<OpId>,
    /// `op_id -> ts_final` for committed ops, retained until the op has
    /// cleared `delivered_high_water`. Lets us answer a recovery Prepare
    /// with the original `ts_final` even after the commit_buffer entry
    /// has been drained.
    pub committed_ts_final: HashMap<OpId, u64>,
    /// True when startup or partition-heal convergence still needs election.
    history_election_requested: bool,
    history_election_phase: HistoryElectionPhase,
    pub history_alive_peers: HashSet<NodeIdentifier>,
    /// Highest membership incarnation observed for each node, including a
    /// tombstone after removal. Keeping tombstones prevents reordered events
    /// from resurrecting an older process incarnation.
    member_incarnations: HashMap<NodeIdentifier, AppliedMemberIncarnation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AppliedMemberIncarnation {
    boot_epoch: u64,
    alive: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MembershipTransition {
    Ignored,
    Joined,
    Removed,
    Restarted,
}

impl StrictState {
    pub fn new() -> Self {
        Self {
            clock: 0,
            peer_clocks: HashMap::new(),
            proposals: HashMap::new(),
            commit_buffer: BTreeMap::new(),
            delivering_commits: HashSet::new(),
            delivered_high_water: 0,
            pending_proposes: HashMap::new(),
            recovery_promises: HashMap::new(),
            resolution_promises: HashMap::new(),
            accepted_values: HashMap::new(),
            terminal_decisions: HashMap::new(),
            terminal_decision_identities: HashMap::new(),
            committed_ids: HashSet::new(),
            committed_ts_final: HashMap::new(),
            history_election_requested: true,
            history_election_phase: HistoryElectionPhase::Idle,
            history_alive_peers: HashSet::new(),
            member_incarnations: HashMap::new(),
        }
    }

    fn apply_membership_event(&mut self, event: &MembershipEvent) -> MembershipTransition {
        let (member, kind) = match event {
            MembershipEvent::Joined(member) => (member, MembershipTransition::Joined),
            MembershipEvent::Left(member) | MembershipEvent::Failed(member) => {
                (member, MembershipTransition::Removed)
            }
            MembershipEvent::Restarted(member) => (member, MembershipTransition::Restarted),
        };
        let node = member.node_id();
        let boot_epoch = member.incarnation();
        let previous = self.member_incarnations.get(&node).copied();

        let transition = match (kind, previous) {
            (_, Some(previous)) if boot_epoch < previous.boot_epoch => {
                MembershipTransition::Ignored
            }
            (MembershipTransition::Removed, Some(previous))
                if boot_epoch == previous.boot_epoch && !previous.alive =>
            {
                MembershipTransition::Ignored
            }
            (MembershipTransition::Removed, _) => MembershipTransition::Removed,
            (MembershipTransition::Restarted, Some(previous))
                if boot_epoch <= previous.boot_epoch =>
            {
                MembershipTransition::Ignored
            }
            (MembershipTransition::Restarted, _) => MembershipTransition::Restarted,
            (MembershipTransition::Joined, Some(previous))
                if boot_epoch == previous.boot_epoch && previous.alive =>
            {
                MembershipTransition::Ignored
            }
            (MembershipTransition::Joined, Some(previous)) if boot_epoch > previous.boot_epoch => {
                // A Joined event can be the first observation of a restarted
                // process when the explicit Restarted event was missed.
                MembershipTransition::Restarted
            }
            (MembershipTransition::Joined, _) => MembershipTransition::Joined,
            (MembershipTransition::Ignored, _) => MembershipTransition::Ignored,
        };

        if transition != MembershipTransition::Ignored {
            self.member_incarnations.insert(
                node,
                AppliedMemberIncarnation {
                    boot_epoch,
                    alive: transition != MembershipTransition::Removed,
                },
            );
        }
        transition
    }

    /// Tempo clock advance: `clock = max(clock, peer_clock) + 1`.
    pub fn advance_clock(&mut self, peer_clock: u64) -> u64 {
        if peer_clock > self.clock {
            self.clock = peer_clock + 1;
        } else {
            self.clock += 1;
        }
        self.clock
    }

    /// Local-only tick (used when proposing).
    pub fn tick_clock(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// Update `peer_clocks[peer]` if `peer_clock` is higher than what we
    /// already had.
    pub fn observe_peer(&mut self, peer: NodeIdentifier, peer_clock: u64) {
        let entry = self.peer_clocks.entry(peer).or_insert(0);
        if peer_clock > *entry {
            *entry = peer_clock;
        }
    }

    /// Compute delivery high-water = `min(peer_clocks ∪ {self.clock})` over
    /// the current alive set. Peers known-alive but with no observation yet
    /// contribute `0`, holding delivery back until they tick — which is
    /// the conservative correct choice.
    pub fn delivery_high_water(&self, self_id: NodeIdentifier, alive: &[NodeIdentifier]) -> u64 {
        let mut min_seen = self.clock; // self's contribution
        for m in alive.iter().copied() {
            if m == self_id {
                continue;
            }
            let c = self.peer_clocks.get(&m).copied().unwrap_or(0);
            if c < min_seen {
                min_seen = c;
            }
        }
        min_seen
    }

    /// Buffer a committed op for later delivery. Idempotent: if an entry
    /// for the same `(ts_final, op_id)` is already present, leave it.
    pub fn buffer_commit(&mut self, op_id: OpId, ts_final: u64, op_msgpack: Bytes) {
        let key: BufferKey = (ts_final, op_id);
        self.commit_buffer.entry(key).or_insert(BufferedOp {
            op_msgpack,
            ts_final,
            op_id,
            buffered_at: Instant::now(),
        });
    }

    /// Pop every entry with `ts_final <= high_water` in
    /// `(ts_final, op_id)` ascending order. Caller is responsible for
    /// applying via the repo and firing wakers.
    pub fn drain_deliverable(&mut self, high_water: u64) -> Vec<BufferedOp> {
        let mut out = Vec::new();
        loop {
            let next_key = match self.commit_buffer.iter().next() {
                Some((k, _)) => *k,
                None => break,
            };
            if next_key.0 > high_water {
                break;
            }
            let (_, v) = self.commit_buffer.pop_first().unwrap();
            out.push(v);
        }
        out
    }

    fn mark_delivering_commits(&mut self, commits: &[BufferedOp]) {
        self.delivering_commits
            .extend(commits.iter().map(|commit| commit.op_id));
    }

    fn finish_delivering_commit(&mut self, op_id: OpId) {
        self.delivering_commits.remove(&op_id);
    }

    /// Earliest timestamp of a proposal this node has observed but not yet
    /// seen committed. A future commit for it can still land at this timestamp
    /// or later, so delivery must not pass it.
    pub fn earliest_uncommitted_proposal_ts(&self) -> Option<u64> {
        self.proposals
            .values()
            .filter(|p| !p.committed)
            .map(|p| p.ts_propose)
            .chain(self.pending_proposes.values().map(|p| p.ts_local))
            .min()
    }

    /// Fail every in-flight proposal whose received acks plus still-reachable
    /// missing targets can no longer reach fast-quorum. Returns the wakers to
    /// fire externally (locking discipline: state lock held during the search,
    /// then released before sending).
    pub fn fail_quorum_lost(
        &mut self,
        alive: &HashSet<NodeIdentifier>,
    ) -> Vec<(OpId, oneshot::Sender<Result<u64, ReplicationError>>)> {
        let mut to_fire = Vec::new();
        let mut to_remove = Vec::new();
        for (op_id, p) in self.proposals.iter_mut() {
            if p.committed {
                continue;
            }
            let fq = fast_quorum_size(p.target_set.len());
            let reachable_missing = p
                .target_set
                .iter()
                .filter(|n| {
                    alive.contains(*n)
                        && !p.invalid_targets.contains(*n)
                        && !p.acks.contains_key(*n)
                })
                .count();
            let possible_acks = p.acks.len() + reachable_missing;
            if possible_acks < fq {
                if let Some(w) = p.waker.take() {
                    to_fire.push((*op_id, w));
                }
                to_remove.push(*op_id);
            }
        }
        for id in to_remove {
            self.proposals.remove(&id);
        }
        to_fire
    }

    /// Returns true when a history-election snapshot can be installed without
    /// racing active strict traffic.
    pub fn can_bootstrap_catchup(&self) -> bool {
        self.history_election_requested
            && !matches!(
                self.history_election_phase,
                HistoryElectionPhase::Installing
            )
            && self.proposals.is_empty()
            && self.commit_buffer.is_empty()
            && self.delivering_commits.is_empty()
            && self.pending_proposes.is_empty()
            && self
                .recovery_promises
                .keys()
                .all(|op_id| self.committed_ids.contains(op_id))
    }

    pub fn can_start_history_election(&self) -> bool {
        self.can_bootstrap_catchup()
            && matches!(self.history_election_phase, HistoryElectionPhase::Idle)
    }

    #[cfg(test)]
    pub fn history_election_pending(&self) -> bool {
        self.history_election_requested
    }

    pub fn history_election_active(&self) -> bool {
        !matches!(self.history_election_phase, HistoryElectionPhase::Idle)
    }

    pub fn history_election_blocks_steady_state(&self) -> bool {
        self.history_election_requested || self.history_election_active()
    }

    #[cfg(test)]
    pub fn history_election_installing(&self) -> bool {
        matches!(
            self.history_election_phase,
            HistoryElectionPhase::Installing
        )
    }

    #[cfg(test)]
    pub fn history_election_fetching_snapshot(&self) -> Option<HistoryElectionSnapshotRequest> {
        match self.history_election_phase {
            HistoryElectionPhase::FetchingSnapshot {
                peer,
                expected_rank,
                ..
            } => Some(HistoryElectionSnapshotRequest::new(peer, expected_rank)),
            _ => None,
        }
    }

    pub fn request_history_election(&mut self) {
        if matches!(
            self.history_election_phase,
            HistoryElectionPhase::Installing
        ) {
            return;
        }
        self.history_election_requested = true;
        self.history_election_phase = HistoryElectionPhase::Idle;
    }

    pub fn begin_history_election(&mut self, peers: impl IntoIterator<Item = NodeIdentifier>) {
        if !self.can_start_history_election() {
            return;
        }
        let peers: HashSet<NodeIdentifier> = peers.into_iter().collect();
        self.history_alive_peers = peers.clone();
        self.history_election_phase = HistoryElectionPhase::Probing {
            pending_peers: peers,
            best_remote_rank: None,
            started_at: Instant::now(),
        };
    }

    pub fn history_election_timed_out(&self, now: Instant, timeout: Duration) -> bool {
        self.history_election_requested
            && match self.history_election_phase {
                HistoryElectionPhase::Probing { started_at, .. }
                | HistoryElectionPhase::FetchingSnapshot { started_at, .. } => {
                    now.duration_since(started_at) >= timeout
                }
                HistoryElectionPhase::Idle | HistoryElectionPhase::Installing => false,
            }
    }

    pub fn observe_history_alive_peers(
        &mut self,
        peers: impl IntoIterator<Item = NodeIdentifier>,
    ) -> bool {
        let peers: HashSet<NodeIdentifier> = peers.into_iter().collect();
        let expanded = peers
            .iter()
            .any(|peer| !self.history_alive_peers.contains(peer));
        self.history_alive_peers = peers;
        if expanded && !self.history_election_requested && !self.history_election_active() {
            self.request_history_election();
            true
        } else {
            false
        }
    }

    /// Reconcile an in-flight history election with the currently usable
    /// routes. A history rank is only useful while we can still fetch the
    /// corresponding image, so a lost candidate is discarded rather than
    /// allowing a stale route to pin the election until its watchdog fires.
    ///
    /// Returns a winning snapshot request that the caller must send after
    /// releasing the state lock.
    pub fn reconcile_history_election_reachability(
        &mut self,
        reachable_peers: impl IntoIterator<Item = NodeIdentifier>,
    ) -> Option<HistoryElectionSnapshotRequest> {
        let reachable_peers: HashSet<NodeIdentifier> = reachable_peers.into_iter().collect();
        self.history_alive_peers = reachable_peers.clone();

        let mut rearm = false;
        let probe_needs_completion = match &mut self.history_election_phase {
            HistoryElectionPhase::Probing {
                pending_peers,
                best_remote_rank,
                ..
            } => {
                pending_peers.retain(|peer| reachable_peers.contains(peer));
                if best_remote_rank
                    .as_ref()
                    .is_some_and(|rank| !reachable_peers.contains(&rank.node_id))
                {
                    *best_remote_rank = None;
                }
                true
            }
            HistoryElectionPhase::FetchingSnapshot { peer, .. }
                if !reachable_peers.contains(peer) =>
            {
                // The selected source vanished after it won the metadata
                // probe. Re-run the election against the live view instead
                // of waiting for a snapshot response that cannot arrive.
                rearm = true;
                false
            }
            HistoryElectionPhase::Idle
            | HistoryElectionPhase::FetchingSnapshot { .. }
            | HistoryElectionPhase::Installing => false,
        };

        if rearm {
            self.request_history_election();
        }

        if !probe_needs_completion {
            return None;
        }
        match self.complete_history_probe_if_ready() {
            HistoryProbeResponseOutcome::FetchSnapshot(request) => Some(request),
            HistoryProbeResponseOutcome::Ignored
            | HistoryProbeResponseOutcome::Pending
            | HistoryProbeResponseOutcome::Finished => None,
        }
    }

    pub fn abandon_history_election_peer(
        &mut self,
        peer: NodeIdentifier,
    ) -> Option<HistoryElectionSnapshotRequest> {
        self.history_alive_peers.remove(&peer);
        match &mut self.history_election_phase {
            HistoryElectionPhase::Probing { pending_peers, .. } => {
                pending_peers.remove(&peer);
                if !pending_peers.is_empty() {
                    return None;
                }
            }
            _ => return None,
        }
        let best_rank = match &self.history_election_phase {
            HistoryElectionPhase::Probing {
                best_remote_rank, ..
            } => *best_remote_rank,
            _ => None,
        };
        let Some(best_rank) = best_rank else {
            self.history_election_phase = HistoryElectionPhase::Idle;
            self.history_election_requested = true;
            return None;
        };

        let request = HistoryElectionSnapshotRequest::new(best_rank.node_id, best_rank);
        self.history_election_phase = HistoryElectionPhase::FetchingSnapshot {
            peer: request.peer(),
            expected_rank: request.expected_rank(),
            started_at: Instant::now(),
        };
        Some(request)
    }

    pub fn record_history_probe_response(
        &mut self,
        peer: NodeIdentifier,
        remote_rank: HistoryRank,
        local_rank: HistoryRank,
    ) -> HistoryProbeResponseOutcome {
        match &mut self.history_election_phase {
            HistoryElectionPhase::Probing {
                pending_peers,
                best_remote_rank,
                started_at,
            } => {
                if !pending_peers.remove(&peer) {
                    return HistoryProbeResponseOutcome::Ignored;
                }
                *started_at = Instant::now();
                if remote_rank.beats(local_rank) {
                    let replace = match best_remote_rank {
                        Some(current) => remote_rank.beats(*current),
                        None => true,
                    };
                    if replace {
                        *best_remote_rank = Some(remote_rank);
                    }
                }
            }
            _ => return HistoryProbeResponseOutcome::Ignored,
        }
        self.complete_history_probe_if_ready()
    }

    fn complete_history_probe_if_ready(&mut self) -> HistoryProbeResponseOutcome {
        let Some(best_rank) = (match &self.history_election_phase {
            HistoryElectionPhase::Probing {
                pending_peers,
                best_remote_rank,
                ..
            } if pending_peers.is_empty() => *best_remote_rank,
            HistoryElectionPhase::Probing { .. } => return HistoryProbeResponseOutcome::Pending,
            _ => return HistoryProbeResponseOutcome::Ignored,
        }) else {
            self.finish_history_election();
            return HistoryProbeResponseOutcome::Finished;
        };

        let request = HistoryElectionSnapshotRequest::new(best_rank.node_id, best_rank);
        self.history_election_phase = HistoryElectionPhase::FetchingSnapshot {
            peer: request.peer(),
            expected_rank: request.expected_rank(),
            started_at: Instant::now(),
        };
        HistoryProbeResponseOutcome::FetchSnapshot(request)
    }

    pub fn record_history_snapshot_response(
        &mut self,
        peer: NodeIdentifier,
        remote_rank: HistoryRank,
        local_rank: HistoryRank,
        snapshot_version: u64,
        snapshot_msgpack: Bytes,
    ) -> HistorySnapshotResponseOutcome {
        // Catchup responses arrive asynchronously. Recheck the complete
        // bootstrap predicate while holding the state lock rather than
        // trusting an earlier caller-side observation.
        if !self.can_bootstrap_catchup() {
            return HistorySnapshotResponseOutcome::Ignored;
        }
        let expected_rank = match self.history_election_phase {
            HistoryElectionPhase::FetchingSnapshot {
                peer: expected_peer,
                expected_rank,
                ..
            } if expected_peer == peer => expected_rank,
            HistoryElectionPhase::FetchingSnapshot { .. } => {
                return HistorySnapshotResponseOutcome::Ignored;
            }
            _ => return HistorySnapshotResponseOutcome::Ignored,
        };

        if !remote_rank.beats(local_rank) {
            self.finish_history_election();
            return HistorySnapshotResponseOutcome::Ignored;
        }

        // The responder may have advanced after its metadata probe. Its
        // snapshot is valid when it covers at least the rank that won the
        // election; requiring an exact post-probe rank turns concurrent
        // writes into endless self-rejected retries.
        if remote_rank.version >= expected_rank.version && !snapshot_msgpack.is_empty() {
            self.history_election_phase = HistoryElectionPhase::Installing;
            return HistorySnapshotResponseOutcome::Install(HistoryElectionCandidate {
                rank: remote_rank,
                snapshot_version,
                snapshot_msgpack,
            });
        }

        self.request_history_election();
        HistorySnapshotResponseOutcome::Retry
    }

    pub fn finish_history_election(&mut self) {
        self.history_election_requested = false;
        self.history_election_phase = HistoryElectionPhase::Idle;
    }

    /// Record a Propose we just ack'd so a takeover can recover it.
    #[cfg(test)]
    pub fn record_pending_propose(
        &mut self,
        op_id: OpId,
        coord: NodeIdentifier,
        op_msgpack: Bytes,
        ts_local: u64,
        now: Instant,
    ) {
        self.record_pending_propose_with_protocol(op_id, coord, op_msgpack, ts_local, now, 0);
    }

    pub fn record_pending_propose_with_protocol(
        &mut self,
        op_id: OpId,
        coord: NodeIdentifier,
        op_msgpack: Bytes,
        ts_local: u64,
        now: Instant,
        protocol_version: u32,
    ) {
        self.record_pending_propose_with_descriptor(
            op_id,
            coord,
            op_msgpack,
            ts_local,
            now,
            protocol_version,
            None,
            protocol_version < STRICT_PROTOCOL_VERSION_V2,
        );
    }

    pub(super) fn record_pending_propose_with_descriptor(
        &mut self,
        op_id: OpId,
        coord: NodeIdentifier,
        op_msgpack: Bytes,
        ts_local: u64,
        now: Instant,
        protocol_version: u32,
        frozen_targets: Option<Vec<FrozenTarget>>,
        v2_descriptor_durable: bool,
    ) {
        if self.committed_ids.contains(&op_id) {
            return;
        }
        self.pending_proposes.insert(
            op_id,
            PendingPropose {
                coord_node: coord,
                op_msgpack,
                ts_local,
                seen_at: now,
                protocol_version,
                frozen_targets,
                v2_descriptor_durable,
            },
        );
    }

    fn mark_v2_pending_descriptor_durable(
        &mut self,
        op_id: OpId,
        frozen_targets: &[FrozenTarget],
    ) -> bool {
        let Some(pending) = self.pending_proposes.get_mut(&op_id) else {
            return false;
        };
        if pending.protocol_version != STRICT_PROTOCOL_VERSION_V2
            || pending.frozen_targets.as_deref() != Some(frozen_targets)
        {
            return false;
        }
        pending.v2_descriptor_durable = true;
        true
    }

    /// Mark `op_id` as committed (via either Commit or RecoveryCommit) and
    /// drop any pending Propose we held for it. Returns `true` if this is
    /// the first time we've seen the op committed (caller should then
    /// buffer + advance clocks); `false` if we've already committed it.
    pub fn mark_committed(&mut self, op_id: OpId, ts_final: u64) -> bool {
        let inserted = self.committed_ids.insert(op_id);
        if inserted {
            self.committed_ts_final.insert(op_id, ts_final);
            self.pending_proposes.remove(&op_id);
            self.accepted_values.remove(&op_id);
        }
        inserted
    }

    fn resolution_promise(&self, op_id: OpId) -> u64 {
        self.resolution_promises.get(&op_id).copied().unwrap_or(0)
    }

    pub(crate) fn ordinary_commit_is_fenced(&self, op_id: OpId) -> bool {
        matches!(
            self.terminal_decisions.get(&op_id),
            Some(TerminalDecision::Abort { .. })
        ) || self.resolution_promise(op_id) > 0
    }

    fn try_resolution_promise(&mut self, op_id: OpId, ballot: u64) -> bool {
        let entry = self.resolution_promises.entry(op_id).or_insert(0);
        if ballot > *entry {
            *entry = ballot;
            true
        } else {
            false
        }
    }

    fn set_accepted_value(&mut self, op_id: OpId, value: AcceptedValue) -> bool {
        match self.accepted_values.get(&op_id) {
            Some(existing) if existing.ballot > value.ballot => false,
            Some(existing)
                if existing.ballot == value.ballot
                    && (existing.ts_final != value.ts_final
                        || existing.op_msgpack != value.op_msgpack) =>
            {
                false
            }
            Some(existing) if existing.ballot < value.ballot => {
                self.accepted_values.insert(op_id, value);
                true
            }
            Some(_) => true,
            None => {
                self.accepted_values.insert(op_id, value);
                true
            }
        }
    }

    fn set_terminal_decision(
        &mut self,
        op_id: OpId,
        decision: TerminalDecision,
        identity: Option<TerminalDecisionIdentity>,
    ) -> bool {
        let accepted = match (self.terminal_decisions.get(&op_id), &decision) {
            (Some(TerminalDecision::Commit(_)), TerminalDecision::Abort { .. }) => false,
            (Some(TerminalDecision::Abort { .. }), TerminalDecision::Commit(_)) => false,
            (Some(TerminalDecision::Commit(existing)), TerminalDecision::Commit(next)) => {
                existing.ballot <= next.ballot
                    && existing.ts_final == next.ts_final
                    && existing.op_msgpack == next.op_msgpack
            }
            (
                Some(TerminalDecision::Abort { ballot }),
                TerminalDecision::Abort { ballot: next },
            ) => *ballot <= *next,
            (None, _) => true,
        };
        let identity_matches = match (self.terminal_decision_identities.get(&op_id), &identity) {
            (Some(existing), Some(next)) => {
                existing.resolver == next.resolver && existing.frozen_targets == next.frozen_targets
            }
            (Some(_), None) => false,
            (None, Some(_)) => !self.terminal_decisions.contains_key(&op_id),
            (None, None) => true,
        };
        if accepted && identity_matches {
            self.terminal_decisions.insert(op_id, decision);
            if let Some(identity) = identity {
                self.terminal_decision_identities.insert(op_id, identity);
            } else {
                self.terminal_decision_identities.remove(&op_id);
            }
        }
        accepted && identity_matches
    }

    /// Returns `true` and updates `recovery_promises[op_id] = ballot` iff
    /// `ballot > current promised`.
    pub fn try_promise(&mut self, op_id: OpId, ballot: u64) -> bool {
        let entry = self.recovery_promises.entry(op_id).or_insert(0);
        if ballot > *entry {
            *entry = ballot;
            true
        } else {
            false
        }
    }

    /// Drop committed_ts_final entries that have been delivered
    /// everywhere. Frees the recovery state we no longer need to answer
    /// Prepare requests for. Conservative: only drops when the op's
    /// `ts_final < self.delivered_high_water` (strictly less, so the same
    /// ts_final cannot be re-bufferable from a stale commit).
    pub fn gc_committed_ts_final(&mut self) {
        let dhw = self.delivered_high_water;
        self.committed_ts_final
            .retain(|_, ts_final| *ts_final >= dhw);
    }

    /// Drop pending_proposes entries older than `pending_propose_ttl` only
    /// after their coordinator is no longer alive and they no longer protect
    /// the ordering of buffered commits.
    /// Returns the dropped op-ids for logging.
    pub fn gc_stale_pending_proposes(
        &mut self,
        now: Instant,
        pending_propose_ttl: Duration,
        alive: &HashSet<NodeIdentifier>,
    ) -> Vec<OpId> {
        let mut dropped = Vec::new();
        let max_buffered_ts = self.commit_buffer.keys().next_back().map(|(ts, _)| *ts);
        self.pending_proposes.retain(|op_id, p| {
            // A v1 prepared proposal is itself the durable ordering fence
            // that the terminal resolver must observe. It is never a local
            // TTL cleanup candidate; only a terminal decision removes it.
            if p.protocol_version >= STRICT_PROTOCOL_VERSION_V1 {
                return true;
            }
            let stale = now.duration_since(p.seen_at) >= pending_propose_ttl;
            let coord_alive = alive.contains(&p.coord_node);
            let protects_buffered_commit = max_buffered_ts.is_some_and(|ts| ts >= p.ts_local);
            if stale {
                if coord_alive || protects_buffered_commit {
                    return true;
                }
                dropped.push(*op_id);
            }
            !stale
        });
        dropped
    }

    /// Garbage-collect proposals stuck longer than `propose_ttl`.
    pub(crate) fn gc_stale_proposals(
        &mut self,
        now: Instant,
        propose_ttl: Duration,
    ) -> Vec<ExpiredProposal> {
        let mut expired = Vec::new();
        let mut to_remove = Vec::new();
        for (op_id, p) in self.proposals.iter_mut() {
            if now.duration_since(p.started_at) >= propose_ttl {
                expired.push(ExpiredProposal {
                    op_id: *op_id,
                    waker: p.waker.take(),
                    needs_v2_resolution: p.protocol_version == STRICT_PROTOCOL_VERSION_V2
                        && !p.committed,
                });
                to_remove.push(*op_id);
            }
        }
        for id in to_remove {
            self.proposals.remove(&id);
        }
        expired
    }
}

impl Default for StrictState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------- Recovery state (takeover-side) ----------

/// One in-progress recovery attempt for a single `op_id`. Lives on the
/// node that took over coordination. Removed once we either broadcast a
/// `RecoveryCommit` or abort.
pub(crate) struct Recovery {
    pub coord_node: NodeIdentifier,
    pub ballot: u64,
    pub started_at: Instant,
    /// Snapshot of alive members (∪ {self}) at recovery start, used for
    /// the recovery quorum size and to decide where to send Prepare.
    pub target_set: HashSet<NodeIdentifier>,
    target_epochs: HashMap<NodeIdentifier, u64>,
    invalid_targets: HashSet<NodeIdentifier>,
    pub prepare_acks: HashMap<NodeIdentifier, RecoveryPrepareAck>,
}

#[derive(Clone)]
pub(crate) struct RecoveryPrepareAck {
    pub promised: bool,
    pub has_committed: bool,
    pub committed_ts_final: u64,
    pub has_op: bool,
    pub ts_local: u64,
    pub op_msgpack: Bytes,
}

#[inline]
pub(crate) fn recovery_quorum_size(n: usize) -> usize {
    if n == 0 { 0 } else { n / 2 + 1 }
}

#[inline]
pub(crate) fn make_ballot(takeover_node: NodeIdentifier, attempt: u64) -> u64 {
    ((takeover_node as u64) << 32) | (attempt & 0xFFFF_FFFF)
}

// ---------- Generic runtime ----------

pub struct StrictRuntime<R: StrictReplicable> {
    pub(super) repo: Arc<R>,
    pub(super) self_id: NodeIdentifier,
    pub(super) boot_epoch: u64,
    pub(super) topic: String,
    pub(super) net: Arc<dyn StrictNet>,
    pub(super) state: Mutex<StrictState>,
    pub(super) deliver_signal: Notify,
    pub(super) clock_tick_signal: Notify,
    pub(super) propose_semaphore: Arc<Semaphore>,
    pub(super) next_op_counter: AtomicU64,
    pub(super) steady_catchup_cursor: AtomicU64,
    /// Cursor used only by terminal-fence repair probes. Keeping it separate
    /// from ordinary anti-entropy lets each newly observed stale fence query
    /// its coordinator first, then rotate across the remaining frozen peers.
    terminal_repair_cursor: AtomicU64,
    /// Monotonically increasing per-takeover-attempt counter, used as the
    /// low 32 bits of `ballot` so retries always outrank prior attempts.
    pub(super) recovery_attempt_counter: AtomicU64,
    /// Monotonically increasing local ballot source for resolution attempts
    /// while the original coordinator is still alive.
    resolution_attempt_counter: AtomicU64,
    /// In-progress recoveries we're leading. Async-driven, ephemeral —
    /// not part of the pure state machine.
    pub(super) recoveries: Mutex<HashMap<OpId, Recovery>>,
    resolutions: Mutex<HashMap<OpId, Resolution>>,
    /// Descriptorless legacy/catchup traffic observed against a durable v2
    /// fence. Each op gets one prompt retry loop until its authenticated
    /// terminal decision reaches disk.
    deferred_v2_resolution_hints: Mutex<HashSet<OpId>>,
    /// V2 acceptors retain an authenticated phase-two ACK until the accepted
    /// value is resolved. This prevents a transiently unavailable return
    /// route from making the coordinator permanently depend on another
    /// Accept retransmission.
    accept_ack_retries: Mutex<HashSet<OpId>>,
    /// Limit the broadcast fallback to the first positive ACK for one
    /// operation. Later Accept retransmissions use targeted route diversity.
    accept_ack_broadcasts: Mutex<HashSet<OpId>>,
    /// Limit the broadcast fallback to the first positive terminal-resolution
    /// ACK for one operation. Prepare retries remain targeted and redundant.
    resolution_ack_broadcasts: Mutex<HashSet<OpId>>,
    /// Weak self-pointer set immediately after `Arc::new`, used to spawn
    /// async work (recovery) from `&self` callbacks like `on_membership`.
    pub(super) weak_self: Mutex<Option<Weak<Self>>>,
    /// Time of the last bootstrap-catchup attempt. None = never. Used to
    /// throttle retries triggered by Joined/Restarted membership events
    /// (the alive view can outrun the routing table immediately after a
    /// heal, so the initial attempt may fail with NoRoute and we rely on
    /// later membership events to drive a retry).
    pub(super) last_bootstrap_attempt: Mutex<Option<Instant>>,
    delivery_blocked_log: Mutex<DeliveryBlockedLogState>,
    pub(super) shutdown: CancellationToken,
    pub(super) cfg: Arc<ReplicationConfig>,
    terminal_journal: Mutex<TerminalJournal>,
    terminal_catchup_snapshots: Mutex<HashMap<NodeIdentifier, TerminalCatchupSnapshot>>,
    /// Latest complete terminal fence cut learned from each v2 source. A
    /// restart deliberately loses this cache, causing the next catchup to
    /// re-page fences instead of trusting a cursor-only skip.
    terminal_catchup_generations: Mutex<HashMap<NodeIdentifier, u64>>,
    /// Per-peer images selected by v2 snapshot catchup. The key is a peer
    /// because a peer has at most one active transfer for this strict topic.
    /// Together with `snapshot_receivers`, retained image bytes are bounded
    /// in aggregate by `strict_max_snapshot_transfer_bytes`. Always acquire
    /// this responder map before the receiver map when retaining or expiring
    /// both directions.
    pub(super) snapshot_transfers: Mutex<HashMap<NodeIdentifier, SnapshotTransfer>>,
    /// Partial v2 images received from each peer. Their bytes share the same
    /// aggregate cap with responder-side images, rather than receiving an
    /// independent per-peer allowance.
    pub(super) snapshot_receivers: Mutex<HashMap<NodeIdentifier, SnapshotReceiveTransfer>>,
    pub(super) snapshot_transfer_counter: AtomicU64,
    terminal_protocol_storage_healthy: AtomicBool,
}

impl<R: StrictReplicable> StrictRuntime<R> {
    pub(crate) fn new(
        repo: Arc<R>,
        self_id: NodeIdentifier,
        boot_epoch: u64,
        topic: String,
        net: Arc<dyn StrictNet>,
        shutdown: CancellationToken,
        cfg: Arc<ReplicationConfig>,
    ) -> Arc<Self> {
        let propose_semaphore = Arc::new(Semaphore::new(cfg.propose_semaphore_size()));
        let mut strict_protocol_disabled = false;
        let journal = match TerminalJournal::load(net.strict_protocol_state_dir(), &topic) {
            Ok(journal) => journal,
            Err(error) => {
                error!(topic = %topic, error = %error, "strict terminal journal unavailable; v1 resolution remains disabled");
                net.disable_strict_replication_protocol();
                strict_protocol_disabled = true;
                TerminalJournal::in_memory(topic.clone())
            }
        };
        let terminal_protocol_storage_healthy =
            journal.durable_persistence_enabled() || cfg!(any(test, feature = "test-support"));
        if !terminal_protocol_storage_healthy && !strict_protocol_disabled {
            net.disable_strict_replication_protocol();
            strict_protocol_disabled = true;
        }
        // Registration can be deferred by a lazy topic resolver, after the
        // manager's initial capability activation pass. Recheck the concrete
        // topic here so an unframeable configured budget cannot leave the
        // local LSA advertising v2.
        if !net.current_protocol_prerequisites_ready(&topic, cfg.strict_max_catchup_bytes())
            && !strict_protocol_disabled
        {
            // This is a topic/configuration capability failure, not proof
            // that the terminal journal or identity has become corrupt. Clamp
            // immediately, but leave a later explicit coordinated topic
            // registration able to re-probe and re-enable v2.
            net.report_strict_replication_repository_capability_loss();
        }
        if repo.strict_replication_protocol_version() < STRICT_PROTOCOL_VERSION_V2 {
            // A terminal journal can recover the protocol decision, but it
            // cannot by itself make application of that decision exactly
            // once. Do not advertise the current protocol from a node that
            // lacks its complete repository capability contract.
            net.report_strict_replication_repository_capability_loss();
        }
        let arc = Arc::new(Self {
            repo,
            self_id,
            boot_epoch,
            topic,
            net,
            state: Mutex::new(StrictState::new()),
            deliver_signal: Notify::new(),
            clock_tick_signal: Notify::new(),
            propose_semaphore,
            next_op_counter: AtomicU64::new(1),
            steady_catchup_cursor: AtomicU64::new(0),
            terminal_repair_cursor: AtomicU64::new(0),
            recovery_attempt_counter: AtomicU64::new(1),
            recoveries: Mutex::new(HashMap::new()),
            resolution_attempt_counter: AtomicU64::new(1),
            resolutions: Mutex::new(HashMap::new()),
            deferred_v2_resolution_hints: Mutex::new(HashSet::new()),
            accept_ack_retries: Mutex::new(HashSet::new()),
            accept_ack_broadcasts: Mutex::new(HashSet::new()),
            resolution_ack_broadcasts: Mutex::new(HashSet::new()),
            weak_self: Mutex::new(None),
            last_bootstrap_attempt: Mutex::new(None),
            delivery_blocked_log: Mutex::new(DeliveryBlockedLogState::default()),
            shutdown,
            cfg,
            terminal_journal: Mutex::new(journal),
            terminal_catchup_snapshots: Mutex::new(HashMap::new()),
            terminal_catchup_generations: Mutex::new(HashMap::new()),
            snapshot_transfers: Mutex::new(HashMap::new()),
            snapshot_receivers: Mutex::new(HashMap::new()),
            snapshot_transfer_counter: AtomicU64::new(1),
            terminal_protocol_storage_healthy: AtomicBool::new(terminal_protocol_storage_healthy),
        });
        if let Some(violation) = arc.first_terminal_record_exceeding_catchup_budget() {
            // The journal remains authoritative for local delivery, but a
            // peer can never learn this terminal fence through bounded v2
            // catchup. Do not advertise a protocol this node cannot repair.
            arc.terminal_protocol_storage_healthy
                .store(false, Ordering::Release);
            if !strict_protocol_disabled {
                arc.net.disable_strict_replication_protocol();
            }
            error!(
                topic = %arc.topic,
                op_id_hi = violation.op_id.0,
                op_id_lo = violation.op_id.1,
                encoded_bytes = violation.encoded_len,
                catchup_budget_bytes = arc.strict_catchup_response_budget(),
                "strict terminal journal contains an unframeable pre-upgrade decision; strict replication is disabled for this process until restart after increasing the effective strict catchup budget or migrating/compacting the journal"
            );
        }
        arc.restore_terminal_journal();
        *arc.weak_self.lock() = Some(Arc::downgrade(&arc));
        arc
    }

    /// Spawn the delivery and clock-tick loops. Optionally kick off
    /// catch-up if the repo is empty and there's at least one alive peer.
    pub fn start(self: &Arc<Self>) {
        spawn_delivery_loop(self.clone());
        spawn_clock_tick_loop(self.clone());
        spawn_bootstrap_retry_loop(self.clone());
        spawn_steady_state_catchup_loop(self.clone());
    }

    pub(crate) fn seed_membership_snapshot(
        &self,
        members: impl IntoIterator<Item = crate::overlay::MemberIncarnation>,
    ) {
        let mut state = self.state.lock();
        for member in members {
            let _ = state.apply_membership_event(&MembershipEvent::Joined(member));
        }
    }

    pub(crate) fn wake_clock_tick_loop(&self) {
        self.clock_tick_signal.notify_one();
    }

    pub(crate) fn wake_delivery_and_clock_tick(&self) {
        self.deliver_signal.notify_one();
        self.wake_clock_tick_loop();
    }

    pub(crate) async fn send_history_snapshot_request(
        &self,
        request: HistoryElectionSnapshotRequest,
    ) -> Result<(), ReplicationError> {
        if !self.can_originate_v2() {
            return Ok(());
        }
        let body = StrictBody::CatchupReq(StrictCatchupReq {
            src_node: self.self_id as u32,
            since_version: 0,
            chunk_token: HISTORY_ELECTION_SNAPSHOT_TOKEN,
            force_snapshot: true,
            history_probe_only: false,
            terminal_state_cursor: 0,
            terminal_decision_generation: 0,
            snapshot_transfer_id: 0,
            snapshot_chunk_cursor: 0,
        });
        metrics::record_catchup_request(CatchupMode::Strict);
        self.net
            .send_redundant_unicast(request.peer(), &self.topic, body)
            .await
    }

    /// Send startup election probes while no strict traffic has been
    /// observed locally. Peers first respond with metadata-only history ranks;
    /// the best rank wins exactly one follow-up snapshot request.
    pub(crate) async fn try_bootstrap_catchup(self: &Arc<Self>) {
        if !self.can_originate_v2() {
            return;
        }
        {
            let state = self.state.lock();
            if !state.can_start_history_election() {
                return;
            }
        }
        {
            let mut last = self.last_bootstrap_attempt.lock();
            let now = Instant::now();
            if let Some(prev) = *last {
                if now.duration_since(prev) < self.cfg.strict_bootstrap_retry_interval() {
                    return;
                }
            }
            *last = Some(now);
        }
        let peers = bootstrap_reachable_peers(self.net.as_ref(), self.self_id);
        {
            let mut state = self.state.lock();
            state.observe_history_alive_peers(peers.iter().copied());
            if !state.can_start_history_election() {
                return;
            }
        }
        if peers.is_empty() {
            self.state.lock().finish_history_election();
            self.wake_delivery_and_clock_tick();
            return;
        }
        self.state
            .lock()
            .begin_history_election(peers.iter().copied());
        self.wake_clock_tick_loop();
        for dst in peers {
            let body = StrictBody::CatchupReq(StrictCatchupReq {
                src_node: self.self_id as u32,
                since_version: 0,
                chunk_token: 0,
                force_snapshot: false,
                history_probe_only: true,
                terminal_state_cursor: 0,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
            });
            metrics::record_catchup_request(CatchupMode::Strict);
            match self
                .net
                .send_redundant_unicast(dst, &self.topic, body)
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    debug!(%dst, error=%e, "strict catchup bootstrap send failed");
                    let request = self.state.lock().abandon_history_election_peer(dst);
                    if let Some(request) = request {
                        if let Err(e) = self.send_history_snapshot_request(request).await {
                            debug!(
                                dst = request.peer(),
                                error = %e,
                                "strict catchup winning snapshot request failed"
                            );
                            self.state.lock().request_history_election();
                        }
                    }
                }
            }
        }
    }

    /// Compute `(target_set, fast_quorum)` from the current alive view.
    pub fn snapshot_target_set(&self) -> (HashSet<NodeIdentifier>, usize) {
        let alive = self.net.alive_members();
        let mut tgt: HashSet<NodeIdentifier> = alive.into_iter().collect();
        tgt.insert(self.self_id);
        let fq = fast_quorum_size(tgt.len());
        (tgt, fq)
    }

    /// Returns the effective cumulative strict protocol version.
    ///
    /// This is evaluated for every new proposal so an older relay or node
    /// joining the active overlay immediately stops new strict origination.
    /// Terminal resolution also needs durable local state: without it, a
    /// restart could forget an abort fence and accept a delayed commit. In
    /// that case this node advertises and originates no strict protocol.
    pub(crate) fn current_protocol_version(&self) -> u32 {
        self.effective_protocol_version(self.net.strict_replication_protocol_version())
    }

    pub(super) fn effective_protocol_version(&self, negotiated_version: u32) -> u32 {
        // New rounds require the v2 frozen membership descriptor. A cluster
        // containing an older peer therefore stays at v0. Old payloads may
        // decode for wire compatibility, but this binary never originates a
        // new legacy round.
        let ready = negotiated_version >= STRICT_PROTOCOL_VERSION_V2
            && self.strict_v2_advertisement_prerequisites_ready();
        metrics::set_strict_replication_protocol_status(
            negotiated_version,
            ready,
            self.net
                .unsupported_active_protocol_peers(STRICT_PROTOCOL_VERSION_V2),
        );
        if ready { STRICT_PROTOCOL_VERSION_V2 } else { 0 }
    }

    /// Whether this process can durably retain a v1 promise/decision. This
    /// intentionally does not consult the current cluster floor: a v1 frame
    /// already frozen to an older all-v1 membership view may still need a
    /// durable reply after a legacy member joins.
    pub(super) fn terminal_storage_ready(&self) -> bool {
        (self
            .terminal_protocol_storage_healthy
            .load(Ordering::Acquire)
            || cfg!(any(test, feature = "test-support")))
            && self.repo.strict_replication_protocol_version() >= STRICT_PROTOCOL_VERSION_V1
    }

    pub(super) fn strict_catchup_response_budget(&self) -> usize {
        self.cfg
            .strict_max_catchup_bytes()
            .min(self.net.max_replication_payload_bytes())
            .min(repl_proto::STRICT_V2_MAX_REPLICATION_PAYLOAD_BYTES)
    }

    pub(super) fn strict_replication_payload_len(
        &self,
        body: &StrictBody,
    ) -> Result<usize, ReplicationError> {
        self.net.encoded_strict_payload_len(&self.topic, body)
    }

    /// Size a body that will be retained or sent under the v2 contract.
    /// Reserve origin authentication independently of the current LSA
    /// advertisement so later capability activation cannot make the retained
    /// record unsendable.
    pub(super) fn v2_strict_replication_payload_len(
        &self,
        body: &StrictBody,
    ) -> Result<usize, ReplicationError> {
        self.net.encoded_v2_strict_payload_len(&self.topic, body)
    }

    pub(super) fn delivery_in_flight(&self) -> usize {
        self.state.lock().delivering_commits.len()
    }

    pub(crate) fn v2_terminal_catchup_supported_by(&self, peer: NodeIdentifier) -> bool {
        self.can_originate_v2()
            && self.net.peer_strict_replication_protocol_version(peer) >= STRICT_PROTOCOL_VERSION_V2
    }

    /// Whether a locally durable v2 node may answer an authenticated terminal
    /// synchronization request from `peer`. Unlike a newly originated
    /// request, this is a continuation of a frozen v2 fence that has already
    /// reached us, so a temporary unrelated LSA-floor dip must not make us
    /// withhold the terminal record. A genuinely legacy peer still cannot
    /// enter this path.
    pub(super) fn can_respond_to_v2_terminal_catchup(&self, peer: NodeIdentifier) -> bool {
        self.local_v2_participation_ready()
            && self.net.peer_strict_replication_protocol_version(peer) >= STRICT_PROTOCOL_VERSION_V2
    }

    /// Fresh terminal-resolution ballots require v2's frozen membership
    /// descriptor. V1 frames are still accepted for compatibility, but a v1
    /// pending entry without that descriptor is never re-resolved against a
    /// rebuilt membership view.
    fn terminal_resolution_ready(&self) -> bool {
        self.local_v2_participation_ready()
            && self.current_protocol_version() >= STRICT_PROTOCOL_VERSION_V2
    }

    fn local_v2_participation_ready(&self) -> bool {
        let repository_ready = self.repository_v2_capable();
        self.terminal_storage_ready()
            && repository_ready
            && self.net.local_strict_replication_protocol_version() >= STRICT_PROTOCOL_VERSION_V2
    }

    /// LSA-independent readiness used by the manager's coordinated
    /// registration gate. It intentionally does not read the negotiated or
    /// advertised version: doing so would create a promotion deadlock where
    /// a runtime cannot prove readiness until the LSA has already promoted.
    pub(crate) fn strict_v2_advertisement_prerequisites_ready(&self) -> bool {
        self.terminal_storage_ready()
            && self.repository_v2_capable()
            && self.net.current_protocol_prerequisites_ready(
                &self.topic,
                self.cfg.strict_max_catchup_bytes(),
            )
    }

    fn can_originate_v2(&self) -> bool {
        self.local_v2_participation_ready()
            && self.current_protocol_version() >= STRICT_PROTOCOL_VERSION_V2
    }

    pub(super) fn repository_v2_capable(&self) -> bool {
        let ready = self.repo.strict_replication_protocol_version() >= STRICT_PROTOCOL_VERSION_V2;
        if !ready {
            self.net
                .report_strict_replication_repository_capability_loss();
        }
        ready
    }

    fn frozen_target_is_current(&self, target: &FrozenTarget) -> bool {
        if target.node() == self.self_id {
            return target.boot_epoch() == self.boot_epoch;
        }
        self.net.alive_members().contains(&target.node())
            && self.net.member_boot_epoch(target.node()) == Some(target.boot_epoch())
    }

    /// Test and local-call convenience only. Production strict dispatch
    /// supplies the origin epoch observed in the overlay envelope. Routed
    /// traffic is membership-trusted metadata, not an origin signature.
    fn direct_inbound_origin_boot_epoch(&self, from: NodeIdentifier) -> u64 {
        if from == self.self_id {
            self.boot_epoch
        } else {
            self.net.member_boot_epoch(from).unwrap_or_default()
        }
    }

    fn observed_origin_matches_epoch(
        &self,
        from: NodeIdentifier,
        origin_boot_epoch: u64,
        expected_boot_epoch: u64,
    ) -> bool {
        let observed_boot_epoch = if from == self.self_id {
            Some(self.boot_epoch)
        } else {
            self.net.member_boot_epoch(from).or_else(|| {
                self.state
                    .lock()
                    .member_incarnations
                    .get(&from)
                    .map(|incarnation| incarnation.boot_epoch)
            })
        };
        origin_boot_epoch == expected_boot_epoch && observed_boot_epoch == Some(origin_boot_epoch)
    }

    fn observed_origin_matches_epoch_in_state(
        &self,
        state: &StrictState,
        from: NodeIdentifier,
        origin_boot_epoch: u64,
        expected_boot_epoch: u64,
    ) -> bool {
        let observed_boot_epoch = if from == self.self_id {
            Some(self.boot_epoch)
        } else {
            self.net.member_boot_epoch(from).or_else(|| {
                state
                    .member_incarnations
                    .get(&from)
                    .map(|incarnation| incarnation.boot_epoch)
            })
        };
        origin_boot_epoch == expected_boot_epoch
            && observed_boot_epoch.map_or(true, |observed| observed == origin_boot_epoch)
    }

    /// Accept a frozen-incarnation frame after the membership view has
    /// temporarily aged the origin out. A missing member is not evidence of
    /// a replacement process; an explicitly observed different incarnation
    /// remains a hard rejection.
    fn observed_frozen_target_epoch_matches(
        &self,
        from: NodeIdentifier,
        origin_boot_epoch: u64,
        expected_boot_epoch: u64,
    ) -> bool {
        origin_boot_epoch == expected_boot_epoch
            && if from == self.self_id {
                origin_boot_epoch == self.boot_epoch
            } else {
                self.net
                    .member_boot_epoch(from)
                    .or_else(|| {
                        self.state
                            .lock()
                            .member_incarnations
                            .get(&from)
                            .map(|incarnation| incarnation.boot_epoch)
                    })
                    .map_or(true, |observed| observed == origin_boot_epoch)
            }
    }

    fn origin_matches_frozen_target(
        &self,
        from: NodeIdentifier,
        origin_boot_epoch: u64,
        targets: &[FrozenTarget],
    ) -> bool {
        FrozenTarget::find_in_canonical(targets, from)
            .is_some_and(|target| target.boot_epoch() == origin_boot_epoch)
    }

    fn observed_frozen_origin_is_current(
        &self,
        from: NodeIdentifier,
        origin_boot_epoch: u64,
        targets: &[FrozenTarget],
    ) -> bool {
        FrozenTarget::find_in_canonical(targets, from).is_some_and(|target| {
            self.observed_frozen_target_epoch_matches(from, origin_boot_epoch, target.boot_epoch())
        })
    }

    fn frozen_resolution_owner(&self, targets: &[FrozenTarget]) -> Option<NodeIdentifier> {
        targets
            .iter()
            .filter(|target| self.frozen_target_is_current(target))
            .map(FrozenTarget::node)
            .min()
    }

    fn unavailable_frozen_targets(&self, targets: &[FrozenTarget]) -> HashSet<NodeIdentifier> {
        targets
            .iter()
            .filter(|target| !self.frozen_target_is_current(target))
            .map(FrozenTarget::node)
            .collect()
    }

    fn record_terminal_journal_failure(&self, error: &TerminalJournalError) {
        if matches!(
            error,
            TerminalJournalError::Io { .. } | TerminalJournalError::Json { .. }
        ) && self
            .terminal_protocol_storage_healthy
            .swap(false, Ordering::AcqRel)
        {
            self.net.disable_strict_replication_protocol();
        }
    }

    /// Return the frozen v2 descriptor known for an operation, whether it is
    /// still pending in memory or only retained by the terminal journal.
    /// Descriptor-less legacy terminal traffic must never mutate such an op.
    fn v2_frozen_targets_for_op(&self, op_id: OpId) -> Option<Vec<FrozenTarget>> {
        if let Some(targets) = self
            .state
            .lock()
            .pending_proposes
            .get(&op_id)
            .filter(|pending| pending.protocol_version == STRICT_PROTOCOL_VERSION_V2)
            .and_then(|pending| pending.frozen_targets.clone())
        {
            return Some(targets);
        }
        self.terminal_journal
            .lock()
            .get(op_id)
            .and_then(TerminalJournalRecord::frozen_targets)
            .map(ToOwned::to_owned)
    }

    pub(crate) fn terminal_commit_proof_for_catchup(
        &self,
        op_id: OpId,
        ts_final: u64,
        op_msgpack: &Bytes,
    ) -> Result<Option<TerminalCommitProof>, ()> {
        let journal = self.terminal_journal.lock();
        let Some(record) = journal.get(op_id) else {
            return Ok(None);
        };
        let Some(frozen_targets) = record.frozen_targets() else {
            return Ok(None);
        };
        let (Some(resolver), Some(JournalTerminalDecision::Commit { candidate })) =
            (record.terminal_resolver(), record.terminal_decision())
        else {
            return Err(());
        };
        if candidate.ts_final() != ts_final || candidate.op_msgpack() != op_msgpack.as_ref() {
            return Err(());
        }
        Ok(Some(TerminalCommitProof {
            ballot: candidate.ballot(),
            identity: TerminalDecisionIdentity {
                resolver,
                frozen_targets: frozen_targets.to_vec(),
            },
        }))
    }

    pub(crate) fn has_unresolved_v2_terminal_fence(&self, op_id: OpId) -> bool {
        self.terminal_journal
            .lock()
            .get(op_id)
            .is_some_and(|record| {
                record.frozen_targets().is_some() && record.terminal_decision().is_none()
            })
    }

    pub(super) fn has_v2_terminal_descriptor(&self, op_id: OpId) -> bool {
        self.terminal_journal
            .lock()
            .get(op_id)
            .is_some_and(|record| record.frozen_targets().is_some())
    }

    pub(super) fn has_any_terminal_decision(&self) -> bool {
        self.terminal_journal.lock().snapshot().iter().any(|entry| {
            let (_, record) = entry.clone().into_parts();
            record.terminal_decision().is_some()
        })
    }

    pub(super) fn terminal_decision_generation(&self) -> u64 {
        self.terminal_journal.lock().terminal_decision_generation()
    }

    pub(super) fn remembered_terminal_decision_generation(&self, peer: NodeIdentifier) -> u64 {
        self.terminal_catchup_generations
            .lock()
            .get(&peer)
            .copied()
            .unwrap_or_default()
    }

    pub(super) fn remember_terminal_decision_generation(
        &self,
        peer: NodeIdentifier,
        terminal_decision_generation: u64,
    ) {
        self.terminal_catchup_generations
            .lock()
            .insert(peer, terminal_decision_generation);
    }

    pub(super) fn reset_terminal_catchup_snapshot(&self, peer: NodeIdentifier) {
        self.terminal_catchup_snapshots.lock().remove(&peer);
    }

    fn v2_resolution_hint_for_op(
        &self,
        op_id: OpId,
    ) -> Option<(NodeIdentifier, StrictResolutionHint)> {
        if !self.terminal_resolution_ready() {
            return None;
        }
        let state_pending = {
            let state = self.state.lock();
            if state.committed_ids.contains(&op_id) {
                return None;
            }
            state.pending_proposes.get(&op_id).and_then(|pending| {
                (pending.protocol_version == STRICT_PROTOCOL_VERSION_V2
                    && pending.v2_descriptor_durable)
                    .then(|| {
                        Some((
                            pending.coord_node,
                            pending.ts_local,
                            pending.op_msgpack.clone(),
                            pending.frozen_targets.clone(),
                            state.clock,
                        ))
                    })
                    .flatten()
            })
        };
        let (coord_node, ts_local, op_msgpack, frozen_targets, src_clock) =
            if let Some(pending) = state_pending {
                pending
            } else {
                let (coord_node, ts_local, op_msgpack, frozen_targets) = {
                    let journal = self.terminal_journal.lock();
                    let record = journal.get(op_id)?;
                    if record.terminal_decision().is_some() {
                        return None;
                    }
                    let frozen_targets = record.frozen_targets()?.to_vec();
                    let pending = record.pending_proposal()?;
                    (
                        node_from_op_id(op_id)?,
                        pending.ts_local(),
                        pending.op_msgpack_bytes(),
                        frozen_targets,
                    )
                };
                (
                    coord_node,
                    ts_local,
                    op_msgpack,
                    Some(frozen_targets),
                    self.state.lock().clock,
                )
            };
        let frozen_targets = frozen_targets?;
        if FrozenTarget::find_in_canonical(&frozen_targets, self.self_id)
            .is_none_or(|target| target.boot_epoch() != self.boot_epoch)
        {
            return None;
        }
        let owner = self.frozen_resolution_owner(&frozen_targets)?;
        Some((
            owner,
            StrictResolutionHint {
                reporter_node: self.self_id as u32,
                coord_node: coord_node as u32,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_local,
                op_msgpack,
                src_clock,
                reporter_boot_epoch: self.boot_epoch,
                protocol_version: STRICT_PROTOCOL_VERSION_V2,
                frozen_targets: frozen_targets_to_wire(&frozen_targets),
            },
        ))
    }

    async fn send_v2_resolution_hint_for_op(&self, op_id: OpId) {
        let Some((owner, hint)) = self.v2_resolution_hint_for_op(op_id) else {
            return;
        };
        if owner == self.self_id {
            self.recv_resolution_hint(self.self_id, hint).await;
        } else if let Err(error) = self
            .net
            .send_redundant_unicast(owner, &self.topic, StrictBody::ResolutionHint(hint))
            .await
        {
            trace!(%error, "send deferred strict v2 resolution hint failed");
        }
    }

    pub(crate) async fn defer_descriptorless_v2_commit(&self, op_id: OpId) {
        if !self.has_unresolved_v2_terminal_fence(op_id) {
            return;
        }
        // Claim the per-operation retry worker before its first send. Several
        // independent expiry and repair paths can observe the same durable
        // fence concurrently; inserting after the send would amplify every
        // caller into an unbounded reliable-queue fanout.
        if !self.deferred_v2_resolution_hints.lock().insert(op_id) {
            return;
        }
        self.send_v2_resolution_hint_for_op(op_id).await;
        let weak = self.weak_self.lock().clone();
        let Some(weak) = weak else {
            return;
        };
        tokio::spawn(async move {
            let Some(runtime) = weak.upgrade() else {
                return;
            };
            let interval = runtime.cfg.strict_bootstrap_retry_interval();
            loop {
                tokio::select! {
                    _ = runtime.shutdown.cancelled() => return,
                    _ = tokio::time::sleep(interval) => {}
                }
                if !runtime.has_unresolved_v2_terminal_fence(op_id) {
                    runtime.deferred_v2_resolution_hints.lock().remove(&op_id);
                    return;
                }
                runtime.send_v2_resolution_hint_for_op(op_id).await;
            }
        });
    }

    pub(crate) fn apply_catchup_terminal_commit_proof(
        &self,
        op_id: OpId,
        ts_final: u64,
        op_msgpack: Bytes,
        proof: TerminalCommitProof,
    ) -> bool {
        if !self.terminal_storage_ready() {
            metrics::record_strict_fence_rejection();
            return false;
        }
        let _ = self.apply_terminal_commit_with_descriptor(
            op_id,
            proof.ballot,
            ts_final,
            op_msgpack.clone(),
            Some(&proof.identity),
        );
        self.terminal_journal
            .lock()
            .get(op_id)
            .is_some_and(|record| {
                matches!(
                    record.terminal_decision(),
                    Some(JournalTerminalDecision::Commit { candidate })
                        if candidate.ts_final() == ts_final
                            && candidate.op_msgpack() == op_msgpack.as_ref()
                ) && record.terminal_resolver() == Some(proof.identity.resolver)
                    && record.frozen_targets() == Some(proof.identity.frozen_targets.as_slice())
            })
    }

    pub(super) fn persist_v2_pending_descriptor(
        &self,
        op_id: OpId,
        ts_local: u64,
        op_msgpack: Bytes,
        frozen_targets: &[FrozenTarget],
    ) -> bool {
        let persisted = {
            let mut journal = self.terminal_journal.lock();
            match journal.upsert_v2_pending_bytes(op_id, frozen_targets, ts_local, op_msgpack) {
                Ok(_) => true,
                Err(error) => {
                    self.record_terminal_journal_failure(&error);
                    warn!(
                        topic = %self.topic,
                        op_id_hi = op_id.0,
                        op_id_lo = op_id.1,
                        error = %error,
                        "strict v2 proposal descriptor could not persist"
                    );
                    false
                }
            }
        };
        if persisted {
            self.state
                .lock()
                .mark_v2_pending_descriptor_durable(op_id, frozen_targets);
        }
        persisted
    }

    fn restore_terminal_journal(&self) {
        let records = self.terminal_journal.lock().snapshot();
        if records.is_empty() {
            return;
        }
        let mut restored_commits = false;
        let mut state = self.state.lock();
        for entry in records {
            let (op_id, record) = entry.into_parts();
            let hydrate_v2_pending = record.frozen_targets().is_none_or(|targets| {
                FrozenTarget::find_in_canonical(targets, self.self_id)
                    .is_some_and(|target| target.boot_epoch() == self.boot_epoch)
            });
            hydrate_terminal_journal_record(&mut state, op_id, &record, hydrate_v2_pending);
            restored_commits |= enqueue_terminal_commit_for_delivery(&mut state, op_id, &record);
            if record.frozen_targets().is_none()
                && record.terminal_decision().is_none()
                && !state.pending_proposes.contains_key(&op_id)
            {
                if let Some(accepted) = record.accepted_commit() {
                    if let Some(coord_node) = node_from_op_id(op_id) {
                        // A crash after v1 Accept but before Decision must
                        // resume resolution after restart. Age the
                        // reconstructed pending entry so the normal
                        // deterministic resolver runs promptly.
                        state.record_pending_propose_with_protocol(
                            op_id,
                            coord_node,
                            accepted.op_msgpack_bytes(),
                            accepted.ts_final(),
                            Instant::now() - self.cfg.pending_propose_ttl(),
                            STRICT_PROTOCOL_VERSION_V1,
                        );
                    }
                }
            }
        }
        if state.clock > 0 {
            let clock = state.clock;
            state.peer_clocks.insert(self.self_id, clock);
        }
        drop(state);
        if restored_commits {
            // Startup history election remains an ordering fence. Once it
            // completes, the normal delivery loop will replay these durable
            // terminal commits through the repository's idempotency ledger.
            self.wake_delivery_and_clock_tick();
        }
    }

    fn apply_terminal_commit(
        &self,
        op_id: OpId,
        ballot: u64,
        ts_final: u64,
        op_msgpack: Bytes,
    ) -> bool {
        self.apply_terminal_commit_with_descriptor(op_id, ballot, ts_final, op_msgpack, None)
    }

    fn requeue_terminal_journal_commit(&self, op_id: OpId) -> bool {
        let Some(record) = self.terminal_journal.lock().get(op_id).cloned() else {
            return false;
        };
        if !matches!(
            record.terminal_decision(),
            Some(JournalTerminalDecision::Commit { .. })
        ) {
            return false;
        }
        let state_changed = {
            let mut state = self.state.lock();
            hydrate_terminal_journal_record(&mut state, op_id, &record, true);
            enqueue_terminal_commit_for_delivery(&mut state, op_id, &record)
        };
        if state_changed {
            self.wake_delivery_and_clock_tick();
        }
        state_changed
    }

    fn apply_terminal_commit_with_descriptor(
        &self,
        op_id: OpId,
        ballot: u64,
        ts_final: u64,
        op_msgpack: Bytes,
        identity: Option<&TerminalDecisionIdentity>,
    ) -> bool {
        if let Some(identity) = identity {
            if !self.v2_terminal_commit_fits_catchup_budget(
                op_id,
                &identity.frozen_targets,
                op_msgpack.clone(),
            ) {
                metrics::record_strict_fence_rejection();
                warn!(
                    op_id_hi = op_id.0,
                    op_id_lo = op_id.1,
                    max_bytes = self.strict_catchup_response_budget(),
                    "strict v2 terminal commit rejected because it exceeds the local catchup budget"
                );
                return false;
            }
        }
        let (journal_changed, record) = {
            let mut journal = self.terminal_journal.lock();
            let result = match identity {
                Some(identity) => journal.upsert_v2_commit_decision_bytes(
                    op_id,
                    &identity.frozen_targets,
                    identity.resolver,
                    ballot,
                    ts_final,
                    op_msgpack.clone(),
                ),
                None => journal.upsert_commit_decision_bytes(
                    op_id,
                    ballot,
                    ts_final,
                    op_msgpack.clone(),
                ),
            };
            match result {
                Ok(changed) => (
                    changed,
                    journal
                        .get(op_id)
                        .cloned()
                        .expect("terminal commit must have a journal record"),
                ),
                Err(error) => {
                    self.record_terminal_journal_failure(&error);
                    warn!(
                        topic = %self.topic,
                        op_id_hi = op_id.0,
                        op_id_lo = op_id.1,
                        error = %error,
                        "strict terminal commit rejected by durable journal"
                    );
                    metrics::record_strict_fence_rejection();
                    return false;
                }
            }
        };
        if !journal_changed {
            let state_changed = {
                let mut state = self.state.lock();
                hydrate_terminal_journal_record(&mut state, op_id, &record, true);
                enqueue_terminal_commit_for_delivery(&mut state, op_id, &record)
            };
            if state_changed {
                self.wake_delivery_and_clock_tick();
            }
            return state_changed;
        }
        let mut state_changed = false;
        {
            let mut state = self.state.lock();
            let decision = TerminalDecision::Commit(AcceptedValue {
                ballot,
                ts_final,
                op_msgpack: op_msgpack.clone(),
            });
            if !state.set_terminal_decision(op_id, decision, identity.cloned()) {
                metrics::record_strict_fence_rejection();
                return false;
            }
            state.try_resolution_promise(op_id, ballot);
            state.set_accepted_value(
                op_id,
                AcceptedValue {
                    ballot,
                    ts_final,
                    op_msgpack: op_msgpack.clone(),
                },
            );
            if ts_final > state.clock {
                state.clock = ts_final;
            }
            let clock = state.clock;
            state.peer_clocks.insert(self.self_id, clock);
            if state.mark_committed(op_id, ts_final) {
                state.buffer_commit(op_id, ts_final, op_msgpack);
                state_changed = true;
            }
        }
        if journal_changed || state_changed {
            metrics::record_strict_resolution(metrics::StrictResolutionOutcome::Commit);
        }
        if state_changed {
            self.wake_delivery_and_clock_tick();
        }
        state_changed
    }

    fn apply_terminal_abort(&self, op_id: OpId, ballot: u64) -> bool {
        self.apply_terminal_abort_with_descriptor(op_id, ballot, None)
    }

    fn apply_terminal_abort_with_descriptor(
        &self,
        op_id: OpId,
        ballot: u64,
        identity: Option<&TerminalDecisionIdentity>,
    ) -> bool {
        if let Some(identity) = identity {
            if !self.v2_terminal_abort_fits_catchup_budget(op_id, &identity.frozen_targets) {
                metrics::record_strict_fence_rejection();
                warn!(
                    op_id_hi = op_id.0,
                    op_id_lo = op_id.1,
                    max_bytes = self.strict_catchup_response_budget(),
                    "strict v2 terminal abort rejected because it exceeds the local catchup budget"
                );
                return false;
            }
        }
        let (journal_changed, record) = {
            let mut journal = self.terminal_journal.lock();
            let result = match identity {
                Some(identity) => journal.upsert_v2_abort_decision(
                    op_id,
                    &identity.frozen_targets,
                    identity.resolver,
                    ballot,
                ),
                None => journal.upsert_abort_decision(op_id, ballot),
            };
            match result {
                Ok(changed) => (
                    changed,
                    journal
                        .get(op_id)
                        .cloned()
                        .expect("terminal abort must have a journal record"),
                ),
                Err(error) => {
                    self.record_terminal_journal_failure(&error);
                    warn!(
                        topic = %self.topic,
                        op_id_hi = op_id.0,
                        op_id_lo = op_id.1,
                        error = %error,
                        "strict terminal abort rejected by durable journal"
                    );
                    metrics::record_strict_fence_rejection();
                    return false;
                }
            }
        };
        if !journal_changed {
            hydrate_terminal_journal_record(&mut self.state.lock(), op_id, &record, true);
            return false;
        }
        let (state_changed, waker) = {
            let mut state = self.state.lock();
            if !state.set_terminal_decision(
                op_id,
                TerminalDecision::Abort { ballot },
                identity.cloned(),
            ) {
                metrics::record_strict_fence_rejection();
                return false;
            }
            state.try_resolution_promise(op_id, ballot);
            state.accepted_values.remove(&op_id);
            state.pending_proposes.remove(&op_id);
            let waker = state
                .proposals
                .remove(&op_id)
                .and_then(|proposal| proposal.waker);
            (true, waker)
        };
        if journal_changed || state_changed {
            metrics::record_strict_resolution(metrics::StrictResolutionOutcome::Abort);
        }
        if let Some(waker) = waker {
            let _ = waker.send(Err(ReplicationError::ProposeTimeout(
                self.cfg.propose_ttl(),
            )));
        }
        self.wake_delivery_and_clock_tick();
        true
    }

    pub(crate) fn terminal_states_for_catchup_page(
        &self,
        peer: NodeIdentifier,
        cursor: u64,
        max_entries: usize,
        max_bytes: usize,
    ) -> TerminalStatePage {
        let (fresh_terminal_decision_generation, fresh_records) = self
            .terminal_journal
            .lock()
            .snapshot_with_terminal_decision_generation();
        let now = Instant::now();
        let (records, terminal_decision_generation, effective_cursor) = {
            let mut snapshots = self.terminal_catchup_snapshots.lock();
            if cursor == 0 {
                if let Some(snapshot) = snapshots.get_mut(&peer) {
                    // A retransmitted first page must keep the original
                    // stable cut. Replacing it would make a concurrent
                    // cursor-0 request shift every later page index.
                    snapshot.last_used_at = now;
                    (
                        snapshot.records.clone(),
                        snapshot.terminal_decision_generation,
                        0,
                    )
                } else {
                    snapshots.insert(
                        peer,
                        TerminalCatchupSnapshot {
                            records: fresh_records.clone(),
                            terminal_decision_generation: fresh_terminal_decision_generation,
                            last_used_at: now,
                        },
                    );
                    (fresh_records, fresh_terminal_decision_generation, 0)
                }
            } else if let Some(snapshot) = snapshots.get_mut(&peer) {
                snapshot.last_used_at = now;
                (
                    snapshot.records.clone(),
                    snapshot.terminal_decision_generation,
                    cursor,
                )
            } else {
                // A responder restart or session expiry must restart from the
                // beginning. Duplicate terminal states are idempotent, while
                // resuming a live BTreeMap index could silently skip a fence.
                snapshots.insert(
                    peer,
                    TerminalCatchupSnapshot {
                        records: fresh_records.clone(),
                        terminal_decision_generation: fresh_terminal_decision_generation,
                        last_used_at: now,
                    },
                );
                (fresh_records, fresh_terminal_decision_generation, 0)
            }
        };
        let page = self.terminal_state_page_from_records(
            &records,
            terminal_decision_generation,
            effective_cursor,
            max_entries,
            max_bytes,
        );
        if !page.has_more {
            self.terminal_catchup_snapshots.lock().remove(&peer);
        }
        page
    }

    fn terminal_state_page_from_records(
        &self,
        records: &[TerminalJournalSnapshotEntry],
        terminal_decision_generation: u64,
        cursor: u64,
        max_entries: usize,
        max_bytes: usize,
    ) -> TerminalStatePage {
        let mut next_index = usize::try_from(cursor)
            .unwrap_or(usize::MAX)
            .min(records.len());
        let mut states = Vec::new();
        let mut scanned_records = 0usize;
        let max_entries = max_entries.max(1);
        let max_bytes = max_bytes.max(1);

        while next_index < records.len()
            && states.len() < max_entries
            && scanned_records < max_entries
        {
            let (op_id, record) = records[next_index].clone().into_parts();
            next_index += 1;
            scanned_records += 1;
            let Some(state) = Self::terminal_state_from_journal_record(op_id, &record) else {
                continue;
            };
            let mut candidate_states = states.clone();
            candidate_states.push(state.clone());
            let encoded_len = self.terminal_catchup_response_encoded_len(candidate_states);
            if states.is_empty() && encoded_len > max_bytes {
                // Do not emit a frame that exceeds the configured transport
                // budget. The caller fails this catchup request closed so the
                // operator can raise the budget or compact the payload.
                return TerminalStatePage {
                    states,
                    next_cursor: next_index.saturating_sub(1) as u64,
                    has_more: true,
                    oversized: true,
                    terminal_decision_generation,
                };
            }
            if !states.is_empty() && encoded_len > max_bytes {
                // The cursor must point at this record again on the next
                // request; it has not been sent yet.
                next_index = next_index.saturating_sub(1);
                break;
            }
            states.push(state);
        }

        TerminalStatePage {
            states,
            next_cursor: next_index as u64,
            has_more: next_index < records.len(),
            oversized: false,
            terminal_decision_generation,
        }
    }

    /// Return the full replication payload size of a terminal-only catchup
    /// response. The maximal scalar fields make this a conservative bound for
    /// every actual response built from the same terminal states.
    fn terminal_catchup_response_encoded_len(
        &self,
        terminal_states: Vec<StrictTerminalState>,
    ) -> usize {
        let body = StrictBody::CatchupResp(StrictCatchupResp {
            snapshot_version: 0,
            snapshot_msgpack: Bytes::new(),
            ops: Vec::new(),
            has_more: false,
            next_chunk_token: u64::MAX,
            too_old_use_snapshot: false,
            history_version: u64::MAX,
            history_freshness: i64::MAX,
            runtime_started_at: u64::MAX,
            history_node: u32::MAX,
            terminal_states,
            next_terminal_state_cursor: u64::MAX,
            terminal_states_has_more: true,
            terminal_sync_only: true,
            request_force_snapshot: true,
            request_history_probe_only: true,
            terminal_decision_generation: u64::MAX,
            snapshot_transfer_id: 0,
            snapshot_chunk_cursor: 0,
            snapshot_next_cursor: 0,
            snapshot_total_bytes: 0,
            snapshot_sha256: Bytes::new(),
            snapshot_has_more: false,
            snapshot_transfer_rejected: false,
        });
        self.v2_strict_replication_payload_len(&body)
            .unwrap_or(usize::MAX)
    }

    fn first_terminal_record_exceeding_catchup_budget(
        &self,
    ) -> Option<TerminalCatchupBudgetViolation> {
        let budget = self.strict_catchup_response_budget();
        self.terminal_journal
            .lock()
            .snapshot()
            .into_iter()
            .find_map(|entry| {
                let (op_id, record) = entry.into_parts();
                let state = Self::terminal_state_from_journal_record(op_id, &record)?;
                let encoded_len = self.terminal_catchup_response_encoded_len(vec![state]);
                (encoded_len > budget)
                    .then_some(TerminalCatchupBudgetViolation { op_id, encoded_len })
            })
    }

    fn terminal_state_from_journal_record(
        op_id: OpId,
        record: &TerminalJournalRecord,
    ) -> Option<StrictTerminalState> {
        let coord_node = node_from_op_id(op_id)?;
        let decision = record.terminal_decision()?;
        let (resolver_node, resolver_boot_epoch, frozen_targets) =
            match (record.frozen_targets(), record.terminal_resolver()) {
                (None, None) => (0, 0, Vec::new()),
                (Some(frozen_targets), Some(resolver)) => (
                    resolver.node() as u32,
                    resolver.boot_epoch(),
                    frozen_targets_to_wire(frozen_targets),
                ),
                // Journal loading rejects this state, but retaining the
                // guard keeps catchup from accidentally serializing a
                // descriptor without its terminal resolver proof.
                _ => return None,
            };
        let outcome = match decision {
            JournalTerminalDecision::Commit { candidate } => {
                StrictTerminalOutcome::Commit(StrictDecisionCommit {
                    ts_final: candidate.ts_final(),
                    op_msgpack: candidate.op_msgpack_bytes(),
                })
            }
            JournalTerminalDecision::Abort { .. } => {
                StrictTerminalOutcome::Abort(StrictDecisionAbort {})
            }
        };
        Some(StrictTerminalState {
            coord_node: coord_node as u32,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            ballot: decision.ballot(),
            outcome: Some(outcome),
            resolver_node,
            resolver_boot_epoch,
            frozen_targets,
        })
    }

    pub(super) fn v2_terminal_commit_fits_catchup_budget(
        &self,
        op_id: OpId,
        frozen_targets: &[FrozenTarget],
        op_msgpack: Bytes,
    ) -> bool {
        self.v2_terminal_state_fits_catchup_budget(op_id, frozen_targets, |_| {
            StrictTerminalOutcome::Commit(StrictDecisionCommit {
                ts_final: u64::MAX,
                op_msgpack: op_msgpack.clone(),
            })
        })
    }

    fn v2_terminal_abort_fits_catchup_budget(
        &self,
        op_id: OpId,
        frozen_targets: &[FrozenTarget],
    ) -> bool {
        self.v2_terminal_state_fits_catchup_budget(op_id, frozen_targets, |_| {
            StrictTerminalOutcome::Abort(StrictDecisionAbort {})
        })
    }

    fn v2_terminal_state_fits_catchup_budget(
        &self,
        op_id: OpId,
        frozen_targets: &[FrozenTarget],
        outcome: impl Fn(&FrozenTarget) -> StrictTerminalOutcome,
    ) -> bool {
        let max_encoded_len = frozen_targets
            .iter()
            .map(|resolver| {
                let state = StrictTerminalState {
                    coord_node: node_from_op_id(op_id).unwrap_or(self.self_id) as u32,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    ballot: u64::MAX,
                    outcome: Some(outcome(resolver)),
                    resolver_node: resolver.node() as u32,
                    resolver_boot_epoch: resolver.boot_epoch(),
                    frozen_targets: frozen_targets_to_wire(frozen_targets),
                };
                self.terminal_catchup_response_encoded_len(vec![state])
            })
            .max();
        max_encoded_len
            .is_some_and(|encoded_len| encoded_len <= self.strict_catchup_response_budget())
    }

    #[cfg(test)]
    pub(crate) fn terminal_states_for_catchup(&self) -> Vec<StrictTerminalState> {
        self.terminal_states_for_catchup_page(self.self_id, 0, usize::MAX, usize::MAX)
            .states
    }

    pub(crate) fn apply_catchup_terminal_state(&self, terminal: StrictTerminalState) -> bool {
        if !self.terminal_storage_ready() {
            metrics::record_strict_fence_rejection();
            return false;
        }
        let Some(coord_node) = node_from_u32(terminal.coord_node) else {
            warn!(
                node = terminal.coord_node,
                "strict terminal catchup state has invalid coordinator"
            );
            return false;
        };
        let op_id = (terminal.op_id_hi, terminal.op_id_lo);
        if node_from_op_id(op_id) != Some(coord_node) {
            warn!(
                op_id_hi = op_id.0,
                op_id_lo = op_id.1,
                advertised_coord = coord_node,
                "strict terminal catchup state coordinator does not match op id"
            );
            return false;
        }
        let identity = match terminal_identity_from_wire(
            terminal.resolver_node,
            terminal.resolver_boot_epoch,
            &terminal.frozen_targets,
            terminal.ballot,
            op_id,
            coord_node,
        ) {
            Ok(identity) => identity,
            Err(()) => {
                metrics::record_strict_fence_rejection();
                return false;
            }
        };
        if identity.is_some() && !self.local_v2_participation_ready() {
            metrics::record_strict_fence_rejection();
            return false;
        }
        if self.v2_frozen_targets_for_op(op_id).is_some_and(|known| {
            identity
                .as_ref()
                .is_none_or(|identity| identity.frozen_targets != known)
        }) {
            metrics::record_strict_fence_rejection();
            return false;
        }
        let expected_outcome = terminal.outcome.clone();
        let outcome = terminal.outcome;
        match outcome {
            Some(StrictTerminalOutcome::Commit(commit)) => {
                let _ = self.apply_terminal_commit_with_descriptor(
                    op_id,
                    terminal.ballot,
                    commit.ts_final,
                    commit.op_msgpack,
                    identity.as_ref(),
                );
            }
            Some(StrictTerminalOutcome::Abort(_)) => {
                let _ = self.apply_terminal_abort_with_descriptor(
                    op_id,
                    terminal.ballot,
                    identity.as_ref(),
                );
            }
            None => {
                warn!(
                    op_id_hi = op_id.0,
                    op_id_lo = op_id.1,
                    "strict terminal catchup state omitted outcome"
                );
                return false;
            }
        }
        self.terminal_journal
            .lock()
            .get(op_id)
            .is_some_and(|record| {
                let outcome_matches = match (record.terminal_decision(), &expected_outcome) {
                    (
                        Some(JournalTerminalDecision::Commit { candidate }),
                        Some(StrictTerminalOutcome::Commit(commit)),
                    ) => {
                        candidate.ballot() == terminal.ballot
                            && candidate.ts_final() == commit.ts_final
                            && candidate.op_msgpack() == commit.op_msgpack.as_ref()
                    }
                    (
                        Some(JournalTerminalDecision::Abort { ballot }),
                        Some(StrictTerminalOutcome::Abort(_)),
                    ) => *ballot == terminal.ballot,
                    _ => false,
                };
                outcome_matches
                    && match (&identity, record.terminal_resolver()) {
                        (Some(identity), Some(resolver)) => {
                            identity.resolver == resolver
                                && record.frozen_targets()
                                    == Some(identity.frozen_targets.as_slice())
                        }
                        (None, None) => record.frozen_targets().is_none(),
                        _ => false,
                    }
            })
    }

    pub(crate) fn snapshot_target_epochs(
        &self,
        target_set: &HashSet<NodeIdentifier>,
    ) -> HashMap<NodeIdentifier, u64> {
        target_set
            .iter()
            .map(|node| {
                let epoch = if *node == self.self_id {
                    self.boot_epoch
                } else {
                    self.net.member_boot_epoch(*node).unwrap_or(0)
                };
                (*node, epoch)
            })
            .collect()
    }

    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    pub(crate) fn finish_history_election_for_test(&self) {
        self.state.lock().finish_history_election();
    }

    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    pub(crate) fn advance_clock_for_test(&self, minimum: u64) {
        let mut state = self.state.lock();
        let clock = state.clock.max(minimum);
        state.clock = clock;
        state.peer_clocks.insert(self.self_id, clock);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn debug_state(&self) -> super::StrictDebugState {
        let (
            election_pending,
            election_active,
            can_start_election,
            history_probe_pending_peers,
            history_alive_peers,
            clock,
            earliest_pending,
            earliest_pending_protocol_version,
            earliest_buffered,
            local_proposal_quorum,
            local_proposal_accept_ack_count,
            local_proposal_accept_acks,
            local_proposal_phase_two_retry,
            accepted_values,
            local_proposals,
            pending_proposes,
            buffered_commits,
            unresolved_promises,
            unresolved_terminal_promises,
        ) = {
            let state = self.state.lock();
            let unresolved_promises = state
                .recovery_promises
                .keys()
                .filter(|op_id| !state.committed_ids.contains(op_id))
                .count();
            let unresolved_terminal_promises = state
                .resolution_promises
                .keys()
                .filter(|op_id| !state.terminal_decisions.contains_key(op_id))
                .count();
            let earliest_pending = state
                .pending_proposes
                .iter()
                .min_by_key(|(_, pending)| pending.ts_local);
            let local_proposal_quorum = state
                .proposals
                .iter()
                .min_by_key(|(_, proposal)| proposal.started_at)
                .map(|(op_id, proposal)| {
                    (
                        *op_id,
                        proposal.acks.len(),
                        proposal
                            .accept_acks
                            .values()
                            .filter(|accepted| **accepted)
                            .count(),
                        proposal.target_set.len(),
                        proposal.accept_started,
                        proposal.committed,
                    )
                });
            let local_proposal_accept_ack_count = state
                .proposals
                .iter()
                .min_by_key(|(_, proposal)| proposal.started_at)
                .map(|(_, proposal)| proposal.accept_acks.len());
            let local_proposal_accept_acks = state
                .proposals
                .iter()
                .min_by_key(|(_, proposal)| proposal.started_at)
                .map(|(_, proposal)| {
                    let mut acks: Vec<_> = proposal
                        .accept_acks
                        .iter()
                        .map(|(node, accepted)| (*node, *accepted))
                        .collect();
                    acks.sort_unstable_by_key(|(node, _)| *node);
                    acks
                });
            let local_proposal_phase_two_retry = state
                .proposals
                .iter()
                .min_by_key(|(_, proposal)| proposal.started_at)
                .map(|(_, proposal)| {
                    (
                        proposal.phase_two_retry_attempts,
                        proposal.phase_two_floor_pauses,
                    )
                });
            let mut accepted_values = state
                .accepted_values
                .iter()
                .map(|(op_id, value)| (*op_id, value.ballot))
                .collect::<Vec<_>>();
            accepted_values.sort_unstable_by_key(|(op_id, ballot)| (*op_id, *ballot));
            (
                state.history_election_requested,
                state.history_election_active(),
                state.can_start_history_election(),
                match &state.history_election_phase {
                    HistoryElectionPhase::Probing { pending_peers, .. } => {
                        Some(pending_peers.len())
                    }
                    HistoryElectionPhase::Idle
                    | HistoryElectionPhase::FetchingSnapshot { .. }
                    | HistoryElectionPhase::Installing => None,
                },
                state.history_alive_peers.len(),
                state.clock,
                earliest_pending
                    .map(|(op_id, pending)| (*op_id, pending.ts_local, pending.coord_node)),
                earliest_pending.map(|(_, pending)| pending.protocol_version),
                state
                    .commit_buffer
                    .iter()
                    .next()
                    .map(|(_, buffered)| (buffered.op_id, buffered.ts_final)),
                local_proposal_quorum,
                local_proposal_accept_ack_count,
                local_proposal_accept_acks,
                local_proposal_phase_two_retry,
                accepted_values,
                state.proposals.len(),
                state.pending_proposes.len(),
                state.commit_buffer.len(),
                unresolved_promises,
                unresolved_terminal_promises,
            )
        };
        let active_recoveries = self.recoveries.lock().len();
        super::StrictDebugState {
            election_pending,
            election_active,
            can_start_election,
            history_probe_pending_peers,
            history_alive_peers,
            clock,
            earliest_pending,
            earliest_pending_protocol_version,
            earliest_buffered,
            local_proposal_quorum,
            local_proposal_accept_ack_count,
            local_proposal_accept_acks,
            local_proposal_phase_two_retry,
            accepted_values,
            local_proposals,
            pending_proposes,
            buffered_commits,
            unresolved_promises,
            unresolved_terminal_promises,
            active_recoveries,
        }
    }

    pub fn next_op_id(&self) -> OpId {
        let counter = self.next_op_counter.fetch_add(1, Ordering::Relaxed);
        make_op_id(self.self_id, self.boot_epoch, counter)
    }

    pub(crate) fn spawn_propose_retries(self: &Arc<Self>, op_id: OpId) {
        let rt = self.clone();
        tokio::spawn(async move {
            let broadcast_interval = rt
                .cfg
                .delivery_tick_interval()
                .max(Duration::from_millis(500));
            let mut last_broadcast_at = Instant::now();
            loop {
                let Some(retry) = rt.pending_propose_retry(op_id) else {
                    return;
                };
                let proposal_ttl = rt.cfg.propose_ttl();
                let elapsed = retry.started_at.elapsed();
                if elapsed >= proposal_ttl {
                    return;
                }
                let delay = rt
                    .cfg
                    .delivery_tick_interval()
                    .min(proposal_ttl.saturating_sub(elapsed));
                tokio::select! {
                    _ = rt.shutdown.cancelled() => return,
                    _ = tokio::time::sleep(delay) => {},
                }

                let Some(retry) = rt.pending_propose_retry(op_id) else {
                    return;
                };
                if retry.started_at.elapsed() >= rt.cfg.propose_ttl() {
                    return;
                }
                if retry.protocol_version != STRICT_PROTOCOL_VERSION_V2 {
                    // This node itself can no longer retain the v2 fence.
                    // Keep it durable for recovery, but never emit a legacy
                    // fallback body.
                    metrics::record_strict_fence_rejection();
                    return;
                }
                if !rt.local_v2_participation_ready() {
                    // A local repository/LSA readiness transition must pause
                    // a frozen v2 retry, not permanently discard it.
                    metrics::record_strict_fence_rejection();
                    continue;
                }
                if !rt.can_originate_v2() {
                    // A coordinated upgrade may briefly observe a v0 floor
                    // while LSAs/routing converge. Preserve retry state and
                    // wait for the floor to recover; emitting through a real
                    // legacy relay would be unsafe.
                    continue;
                }
                if retry.protocol_version == STRICT_PROTOCOL_VERSION_V2
                    && retry.ack_count >= retry.fast_quorum
                    && !retry.accept_started
                {
                    // Phase-one ACKs are authenticated evidence tied to the
                    // frozen descriptor, so retain them across a temporary
                    // floor downgrade. Once the floor recovers, resume the
                    // phase transition instead of needlessly retransmitting
                    // a proposal that already has a quorum.
                    rt.resume_v2_accept_from_phase_one_quorum(op_id).await;
                    continue;
                }
                if retry.dsts.is_empty() {
                    if retry.accept_started {
                        // Phase two has its own retry loop. Once every
                        // frozen target has durably observed the proposal,
                        // this loop has no remaining repair work.
                        return;
                    }
                    continue;
                }
                debug!(
                    topic = %rt.topic,
                    op_id_hi = op_id.0,
                    op_id_lo = op_id.1,
                    elapsed_ms = retry.started_at.elapsed().as_millis(),
                    ack_count = retry.ack_count,
                    target_count = retry.target_count,
                    fast_quorum = retry.fast_quorum,
                    missing_count = retry.dsts.len(),
                    phase_two_started = retry.accept_started,
                    "strict proposal retrying missing frozen-target acknowledgements"
                );
                let body = StrictBody::ProposeV1(StrictProposeV1 {
                    coord_node: rt.self_id as u32,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    ts_propose: retry.ts_propose,
                    op_msgpack: retry.op_msgpack,
                    src_clock: retry.src_clock,
                    protocol_version: STRICT_PROTOCOL_VERSION_V2,
                    frozen_targets: frozen_targets_to_wire(&retry.frozen_targets),
                });
                let now = Instant::now();
                let use_broadcast = now.duration_since(last_broadcast_at) >= broadcast_interval;
                if use_broadcast {
                    last_broadcast_at = now;
                }
                if let Err(e) = rt
                    .net
                    .send_redundant_multicast(&retry.dsts, &rt.topic, body.clone())
                    .await
                {
                    trace!(error=%e, "send propose retry multicast failed");
                }
                if use_broadcast {
                    if let Err(e) = rt.net.send_broadcast(&rt.topic, body).await {
                        trace!(error=%e, "send propose retry broadcast failed");
                    }
                }
            }
        });
    }

    /// Enforce the caller-visible proposal deadline independently of the
    /// delivery loop. A durable V2 fence may still resolve after the caller
    /// has timed out, but it must not retain an in-flight permit or leave the
    /// caller's receiver pending while delivery is watermark-blocked.
    pub(crate) fn spawn_proposal_deadline(self: &Arc<Self>, op_id: OpId) {
        let rt = self.clone();
        tokio::spawn(async move {
            let Some(started_at) = rt
                .state
                .lock()
                .proposals
                .get(&op_id)
                .map(|proposal| proposal.started_at)
            else {
                return;
            };
            let proposal_ttl = rt.cfg.propose_ttl();
            let mut phase_two_grace_used = false;
            let expired = loop {
                let remaining = proposal_ttl.saturating_sub(started_at.elapsed());
                tokio::select! {
                    _ = rt.shutdown.cancelled() => return,
                    _ = tokio::time::sleep(remaining) => {},
                }
                let phase_two_grace = {
                    let state = rt.state.lock();
                    let Some(proposal) = state.proposals.get(&op_id) else {
                        return;
                    };
                    if proposal.started_at != started_at
                        || proposal.started_at.elapsed() < proposal_ttl
                    {
                        return;
                    }
                    if phase_two_grace_used && proposal.committed {
                        // A phase-two quorum completed during the grace
                        // window. Leave the proposal for the delivery loop so
                        // its caller can receive the successful version.
                        return;
                    }
                    !phase_two_grace_used
                        && proposal.protocol_version == STRICT_PROTOCOL_VERSION_V2
                        && proposal.accept_started
                        && !proposal.committed
                        && proposal
                            .accept_acks
                            .values()
                            .filter(|accepted| **accepted)
                            .count()
                            >= fast_quorum_size(proposal.target_set.len())
                };
                if phase_two_grace {
                    phase_two_grace_used = true;
                    let grace = rt
                        .cfg
                        .delivery_tick_interval()
                        .max(Duration::from_millis(500));
                    tokio::select! {
                        _ = rt.shutdown.cancelled() => return,
                        _ = tokio::time::sleep(grace) => {},
                    }
                    continue;
                }
                let mut state = rt.state.lock();
                let Some(proposal) = state.proposals.get(&op_id) else {
                    return;
                };
                if proposal.started_at != started_at || proposal.started_at.elapsed() < proposal_ttl
                {
                    return;
                }
                break state
                    .proposals
                    .remove(&op_id)
                    .map(|proposal| ExpiredProposal {
                        op_id,
                        waker: proposal.waker,
                        needs_v2_resolution: proposal.protocol_version
                            == STRICT_PROTOCOL_VERSION_V2
                            && !proposal.committed,
                    });
            };
            let Some(expired) = expired else {
                return;
            };
            if let Some(waker) = expired.waker {
                let _ = waker.send(Err(ReplicationError::ProposeTimeout(proposal_ttl)));
            }
            if expired.needs_v2_resolution {
                // The caller's deadline is not an abort: the durable v2
                // descriptor remains a strict ordering fence. Hand it to the
                // deterministic terminal resolver so a transient route loss
                // cannot leave every replica pending forever.
                rt.defer_descriptorless_v2_commit(expired.op_id).await;
            }
        });
    }

    /// Retransmit v2 phase-two Accept messages until a fast quorum has
    /// acknowledged the exact frozen proposal or the caller's proposal TTL
    /// expires. A missed AcceptAck must not strand a durable v2 fence behind
    /// a transient route loss, but this loop never emits a legacy fallback.
    fn spawn_accept_retries(&self, op_id: OpId) {
        let Some(weak) = self.weak_self.lock().clone() else {
            return;
        };
        tokio::spawn(async move {
            let Some(rt) = weak.upgrade() else {
                return;
            };
            let broadcast_interval = rt
                .cfg
                .delivery_tick_interval()
                .max(Duration::from_millis(500));
            let mut last_broadcast_at = Instant::now();
            loop {
                let Some(retry) = rt.pending_accept_retry(op_id) else {
                    return;
                };
                let proposal_ttl = rt.cfg.propose_ttl();
                let elapsed = retry.started_at.elapsed();
                if elapsed >= proposal_ttl {
                    return;
                }
                let delay = rt
                    .cfg
                    .delivery_tick_interval()
                    .min(proposal_ttl.saturating_sub(elapsed));
                tokio::select! {
                    _ = rt.shutdown.cancelled() => return,
                    _ = tokio::time::sleep(delay) => {},
                }

                let Some(retry) = rt.pending_accept_retry(op_id) else {
                    return;
                };
                if retry.started_at.elapsed() >= rt.cfg.propose_ttl() {
                    return;
                }
                if !rt.local_v2_participation_ready() {
                    metrics::record_strict_fence_rejection();
                    continue;
                }
                if !rt.can_originate_v2() {
                    // See phase-one retry above: pause, rather than abandon,
                    // a frozen v2 round while the coordinated floor settles.
                    #[cfg(any(test, feature = "test-support"))]
                    if let Some(proposal) = rt.state.lock().proposals.get_mut(&op_id) {
                        proposal.phase_two_floor_pauses += 1;
                    }
                    continue;
                }
                if retry.dsts.is_empty() {
                    return;
                }
                debug!(
                    topic = %rt.topic,
                    op_id_hi = op_id.0,
                    op_id_lo = op_id.1,
                    elapsed_ms = retry.started_at.elapsed().as_millis(),
                    accepted_count = retry.accepted_count,
                    target_count = retry.target_count,
                    fast_quorum = retry.fast_quorum,
                    missing_count = retry.dsts.len(),
                    "strict v2 accept retrying missing phase-two acknowledgements"
                );
                let retry_self = retry.dsts.iter().any(|node| *node == rt.self_id);
                if retry_self {
                    rt.recv_accept(rt.self_id, retry.body.clone()).await;
                }
                let remote_dsts: Vec<_> = retry
                    .dsts
                    .iter()
                    .copied()
                    .filter(|node| *node != rt.self_id)
                    .collect();
                if remote_dsts.is_empty() {
                    continue;
                }
                #[cfg(any(test, feature = "test-support"))]
                if let Some(proposal) = rt.state.lock().proposals.get_mut(&op_id) {
                    proposal.phase_two_retry_attempts += 1;
                }
                if let Err(error) = rt
                    .net
                    .send_redundant_multicast(
                        &remote_dsts,
                        &rt.topic,
                        StrictBody::Accept(retry.body.clone()),
                    )
                    .await
                {
                    trace!(%error, "send strict v2 accept retry multicast failed");
                }
                let now = Instant::now();
                if now.duration_since(last_broadcast_at) >= broadcast_interval {
                    last_broadcast_at = now;
                    if let Err(error) = rt
                        .net
                        .send_broadcast(&rt.topic, StrictBody::Accept(retry.body))
                        .await
                    {
                        trace!(%error, "send strict v2 accept retry broadcast failed");
                    }
                }
            }
        });
    }

    fn pending_propose_retry(&self, op_id: OpId) -> Option<PendingProposeRetry> {
        let s = self.state.lock();
        let p = s.proposals.get(&op_id)?;
        if p.committed {
            return None;
        }
        let ack_count = p.acks.len();
        let target_count = p.target_set.len();
        let fast_quorum = fast_quorum_size(target_count);
        let frozen_targets = if p.protocol_version == STRICT_PROTOCOL_VERSION_V2 {
            let pending = s.pending_proposes.get(&op_id)?;
            if !pending.v2_descriptor_durable {
                return None;
            }
            pending.frozen_targets.clone()?
        } else {
            Vec::new()
        };
        let dsts = p
            .target_set
            .iter()
            .filter(|node| {
                **node != self.self_id
                    && !p.invalid_targets.contains(*node)
                    && !p.acks.contains_key(*node)
            })
            .copied()
            .collect();
        Some(PendingProposeRetry {
            op_msgpack: p.op_msgpack.clone(),
            ts_propose: p.ts_propose,
            src_clock: s.clock,
            dsts,
            started_at: p.started_at,
            ack_count,
            target_count,
            fast_quorum,
            accept_started: p.accept_started,
            protocol_version: p.protocol_version,
            frozen_targets,
        })
    }

    fn pending_accept_retry(&self, op_id: OpId) -> Option<PendingAcceptRetry> {
        let state = self.state.lock();
        let proposal = state.proposals.get(&op_id)?;
        if proposal.protocol_version != STRICT_PROTOCOL_VERSION_V2
            || !proposal.accept_started
            || proposal.committed
            || state.terminal_decisions.contains_key(&op_id)
        {
            return None;
        }
        let pending = state.pending_proposes.get(&op_id)?;
        if !pending.v2_descriptor_durable
            || pending.protocol_version != STRICT_PROTOCOL_VERSION_V2
            || pending.frozen_targets.is_none()
        {
            return None;
        }
        let body = proposal.phase_two_accept.clone()?;
        if body.ballot != NORMAL_ACCEPT_BALLOT {
            return None;
        }
        let target_count = proposal.target_set.len();
        let fast_quorum = fast_quorum_size(target_count);
        let accepted_count = proposal
            .accept_acks
            .values()
            .filter(|accepted| **accepted)
            .count();
        if accepted_count >= fast_quorum {
            return None;
        }
        let dsts = proposal
            .target_set
            .iter()
            .filter(|node| {
                !proposal.invalid_targets.contains(*node)
                    && proposal.accept_acks.get(*node) != Some(&true)
            })
            .copied()
            .collect();
        Some(PendingAcceptRetry {
            body,
            dsts,
            started_at: proposal.started_at,
            accepted_count,
            target_count,
            fast_quorum,
        })
    }

    // ------ Inbound recv handlers ------

    pub async fn recv_propose(&self, from: NodeIdentifier, p: StrictPropose) {
        // The descriptor-less proposal oneof is retained solely so upgraded
        // nodes can decode old traffic without treating it as malformed. New
        // strict work is v2-only; acknowledging this frame would originate a
        // fresh legacy round and reintroduce an unfenced commit path.
        let _ = (from, p);
        metrics::record_strict_fence_rejection();
    }

    /// Receive a non-legacy proposal from its own oneof tag. This must never
    /// be processed while durable terminal resolution is unavailable: an ACK
    /// from an in-memory fallback would otherwise contribute to a quorum that
    /// cannot survive this node restarting.
    pub async fn recv_propose_v1(&self, from: NodeIdentifier, p: StrictProposeV1) {
        self.recv_propose_v1_with_origin_epoch(
            from,
            self.direct_inbound_origin_boot_epoch(from),
            p,
        )
        .await;
    }

    async fn recv_propose_v1_with_origin_epoch(
        &self,
        from: NodeIdentifier,
        origin_boot_epoch: u64,
        p: StrictProposeV1,
    ) {
        if p.protocol_version != STRICT_PROTOCOL_VERSION_V2 {
            // V1 is decode-compatible only. Do not ACK, forward, or create a
            // new descriptor-less round from a legacy proposal.
            metrics::record_strict_fence_rejection();
            return;
        }
        if !matches!(p.protocol_version, STRICT_PROTOCOL_VERSION_V2)
            || !self.terminal_storage_ready()
        {
            metrics::record_strict_fence_rejection();
            return;
        }
        if p.protocol_version == STRICT_PROTOCOL_VERSION_V2 && !self.local_v2_participation_ready()
        {
            metrics::record_strict_fence_rejection();
            return;
        }
        if node_from_u32(p.coord_node) != Some(from) {
            metrics::record_strict_fence_rejection();
            warn!(
                from,
                coord_node = p.coord_node,
                "strict v1 propose origin mismatch"
            );
            return;
        }
        let op_id = (p.op_id_hi, p.op_id_lo);
        let frozen_targets = match p.protocol_version {
            STRICT_PROTOCOL_VERSION_V1 if p.frozen_targets.is_empty() => None,
            STRICT_PROTOCOL_VERSION_V1 => {
                metrics::record_strict_fence_rejection();
                warn!(
                    op_id_hi = op_id.0,
                    op_id_lo = op_id.1,
                    "strict v1 propose rejected: descriptor requires protocol v2"
                );
                return;
            }
            STRICT_PROTOCOL_VERSION_V2 => {
                let Some(coord) = node_from_u32(p.coord_node) else {
                    metrics::record_strict_fence_rejection();
                    return;
                };
                let Ok(targets) = frozen_targets_from_wire(&p.frozen_targets, op_id, coord) else {
                    metrics::record_strict_fence_rejection();
                    warn!(
                        op_id_hi = op_id.0,
                        op_id_lo = op_id.1,
                        "strict v2 propose rejected: invalid frozen target descriptor"
                    );
                    return;
                };
                if !targets.iter().any(|target| {
                    target.node() == self.self_id && target.boot_epoch() == self.boot_epoch
                }) {
                    metrics::record_strict_fence_rejection();
                    warn!(
                        op_id_hi = op_id.0,
                        op_id_lo = op_id.1,
                        "strict v2 propose rejected: local incarnation is not a frozen target"
                    );
                    return;
                }
                if !self.observed_frozen_origin_is_current(from, origin_boot_epoch, &targets) {
                    metrics::record_strict_fence_rejection();
                    warn!(
                        from,
                        origin_boot_epoch,
                        op_id_hi = op_id.0,
                        op_id_lo = op_id.1,
                        "strict v2 propose rejected: coordinator origin incarnation is stale"
                    );
                    return;
                }
                Some(targets)
            }
            _ => unreachable!("protocol version was validated above"),
        };
        self.recv_propose_inner(
            from,
            p.coord_node,
            op_id,
            p.ts_propose,
            p.op_msgpack,
            p.src_clock,
            p.protocol_version,
            frozen_targets,
        )
        .await;
    }

    async fn recv_propose_inner(
        &self,
        from: NodeIdentifier,
        coord_node: u32,
        op_id: OpId,
        ts_propose: u64,
        op_msgpack: Bytes,
        src_clock: u64,
        protocol_version: u32,
        frozen_targets: Option<Vec<FrozenTarget>>,
    ) {
        let Some(coord) = node_from_u32(coord_node) else {
            warn!(node = coord_node, "strict propose has invalid coord_node");
            return;
        };
        if node_from_op_id(op_id) != Some(coord) {
            metrics::record_strict_fence_rejection();
            warn!(
                op_id_hi = op_id.0,
                op_id_lo = op_id.1,
                coord,
                "strict propose coordinator does not match op id"
            );
            return;
        }
        if protocol_version == STRICT_PROTOCOL_VERSION_V2 {
            let Some(targets) = frozen_targets.as_deref() else {
                metrics::record_strict_fence_rejection();
                return;
            };
            if !self.v2_terminal_commit_fits_catchup_budget(op_id, targets, op_msgpack.clone()) {
                metrics::record_strict_fence_rejection();
                warn!(
                    op_id_hi = op_id.0,
                    op_id_lo = op_id.1,
                    max_bytes = self.strict_catchup_response_budget(),
                    "strict v2 propose rejected because its terminal fence exceeds the local catchup budget"
                );
                return;
            }
        }
        if protocol_version < STRICT_PROTOCOL_VERSION_V2 && self.has_v2_terminal_descriptor(op_id) {
            metrics::record_strict_fence_rejection();
            return;
        }
        // A retransmitted Propose must reuse the original ACK timestamp.
        // Advancing the local clock again would move this replica's pending
        // ordering barrier past a timestamp the coordinator can still commit.
        let (ts_local, local_clock_after, v2_pending_to_persist);
        {
            let mut s = self.state.lock();
            s.observe_peer(from, src_clock);
            if matches!(
                s.terminal_decisions.get(&op_id),
                Some(TerminalDecision::Abort { .. })
            ) {
                metrics::record_strict_fence_rejection();
                return;
            } else if let Some(TerminalDecision::Commit(value)) = s.terminal_decisions.get(&op_id) {
                ts_local = value.ts_final;
                local_clock_after = s.clock;
                v2_pending_to_persist = None;
            } else if let Some(pending) = s.pending_proposes.get(&op_id) {
                if pending.coord_node != coord || pending.protocol_version != protocol_version {
                    warn!(
                        op_id_hi = op_id.0,
                        op_id_lo = op_id.1,
                        expected_coord = pending.coord_node,
                        coord,
                        expected_protocol_version = pending.protocol_version,
                        protocol_version,
                        "strict propose ignored: op id changed coordinator or protocol version"
                    );
                    return;
                }
                if protocol_version == STRICT_PROTOCOL_VERSION_V2 {
                    if pending.frozen_targets.as_deref() != frozen_targets.as_deref()
                        || pending.op_msgpack != op_msgpack
                    {
                        metrics::record_strict_fence_rejection();
                        warn!(
                            op_id_hi = op_id.0,
                            op_id_lo = op_id.1,
                            "strict v2 propose rejected: descriptor or payload changed"
                        );
                        return;
                    }
                    let targets = frozen_targets
                        .clone()
                        .expect("v2 proposal descriptor was validated before state mutation");
                    v2_pending_to_persist = (!pending.v2_descriptor_durable)
                        .then(|| (targets, pending.op_msgpack.clone()));
                } else {
                    v2_pending_to_persist = None;
                }
                ts_local = pending.ts_local;
                local_clock_after = s.clock;
            } else if let Some(ts_final) = s.committed_ts_final.get(&op_id).copied() {
                // A late retry for an already committed operation is harmless.
                // Reuse its decided timestamp instead of creating a second ACK
                // value for the same operation.
                ts_local = ts_final;
                local_clock_after = s.clock;
                v2_pending_to_persist = None;
            } else {
                ts_local = s.advance_clock(ts_propose);
                local_clock_after = s.clock;
                s.peer_clocks.insert(self.self_id, local_clock_after);
                if protocol_version == STRICT_PROTOCOL_VERSION_V2 {
                    let targets = frozen_targets
                        .clone()
                        .expect("v2 proposal descriptor was validated before state mutation");
                    s.record_pending_propose_with_descriptor(
                        op_id,
                        coord,
                        op_msgpack.clone(),
                        ts_local,
                        Instant::now(),
                        protocol_version,
                        Some(targets.clone()),
                        false,
                    );
                    v2_pending_to_persist = Some((targets, op_msgpack.clone()));
                } else {
                    s.record_pending_propose_with_protocol(
                        op_id,
                        coord,
                        op_msgpack,
                        ts_local,
                        Instant::now(),
                        protocol_version,
                    );
                    v2_pending_to_persist = None;
                }
            }
            s.peer_clocks.insert(self.self_id, local_clock_after);
        }
        if let Some((targets, pending_bytes)) = v2_pending_to_persist {
            if !self.persist_v2_pending_descriptor(op_id, ts_local, pending_bytes, &targets) {
                let mut state = self.state.lock();
                if state.pending_proposes.get(&op_id).is_some_and(|pending| {
                    pending.protocol_version == STRICT_PROTOCOL_VERSION_V2
                        && pending.frozen_targets.as_deref() == Some(targets.as_slice())
                        && !pending.v2_descriptor_durable
                }) {
                    state.pending_proposes.remove(&op_id);
                }
                return;
            }
        }
        let ack = StrictBody::ProposeAck(StrictProposeAck {
            ack_node: self.self_id as u32,
            coord_node: coord as u32,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            ts_local,
            src_clock: local_clock_after,
            ack_boot_epoch: self.boot_epoch,
        });
        if let Err(e) = self
            .net
            .send_redundant_unicast(coord, &self.topic, ack)
            .await
        {
            trace!(error=%e, "send propose-ack failed");
        }
        self.wake_delivery_and_clock_tick();
    }

    pub async fn recv_propose_ack(&self, from: NodeIdentifier, ack: StrictProposeAck) {
        self.recv_propose_ack_with_origin_epoch(
            from,
            self.direct_inbound_origin_boot_epoch(from),
            ack,
        )
        .await;
    }

    async fn recv_propose_ack_with_origin_epoch(
        &self,
        from: NodeIdentifier,
        origin_boot_epoch: u64,
        ack: StrictProposeAck,
    ) {
        // A phase-one ACK for an already-frozen v2 proposal is evidence, not
        // authorization to emit another v2 frame. Keep a valid ACK while the
        // global floor temporarily falls during LSA/routing convergence; the
        // phase-one-to-phase-two transition below remains separately gated.
        if !self.local_v2_participation_ready() {
            metrics::record_strict_fence_rejection();
            return;
        }
        let can_start_phase_two = self.can_originate_v2();
        let op_id: OpId = (ack.op_id_hi, ack.op_id_lo);
        let ack_node = match node_from_u32(ack.ack_node) {
            Some(node) => node,
            None => {
                warn!(
                    node = ack.ack_node,
                    "strict propose ack has invalid ack_node"
                );
                return;
            }
        };
        let coord = match node_from_u32(ack.coord_node) {
            Some(node) => node,
            None => {
                warn!(
                    node = ack.coord_node,
                    "strict propose ack has invalid coord_node"
                );
                return;
            }
        };
        if coord != self.self_id {
            trace!(coord, "strict propose ack ignored: not coordinator");
            return;
        }
        if ack_node != from {
            warn!(from, ack_node, "strict propose ack origin mismatch");
            return;
        }

        let outcome = {
            let mut s = self.state.lock();
            let Some(p) = s.proposals.get(&op_id) else {
                return;
            };
            let expected_boot_epoch = p.target_epochs.get(&ack_node).copied().unwrap_or(0);
            if p.protocol_version != STRICT_PROTOCOL_VERSION_V2
                || p.committed
                || !p.target_set.contains(&ack_node)
                || expected_boot_epoch != ack.ack_boot_epoch
                || p.invalid_targets.contains(&ack_node)
                || (p.protocol_version == STRICT_PROTOCOL_VERSION_V2
                    && !self.local_v2_participation_ready())
                || (p.protocol_version == STRICT_PROTOCOL_VERSION_V2
                    && !self.observed_origin_matches_epoch_in_state(
                        &s,
                        ack_node,
                        origin_boot_epoch,
                        expected_boot_epoch,
                    ))
            {
                trace!(
                    ack_node,
                    "strict propose ack ignored: invalid frozen target"
                );
                return;
            }
            s.observe_peer(ack_node, ack.src_clock);

            let (
                protocol_version,
                op_bytes,
                op_bytes_len,
                dsts,
                ts_final,
                accepted_waker,
                elapsed,
                ack_count,
                target_count,
                fast_quorum,
            ) = {
                let Some(p) = s.proposals.get_mut(&op_id) else {
                    return;
                };
                p.acks.insert(ack_node, ack.ts_local);
                let target_count = p.target_set.len();
                let fast_quorum = fast_quorum_size(target_count);
                if p.acks.len() < fast_quorum {
                    return;
                }
                if !can_start_phase_two {
                    // A frozen v2 quorum is durable evidence, but a true
                    // legacy relay can strip or drop the phase-two body. The
                    // retry loop resumes this transition only after the
                    // negotiated floor has recovered.
                    return;
                }
                if p.protocol_version >= STRICT_PROTOCOL_VERSION_V1 && p.accept_started {
                    return;
                }
                let ts_final = p.acks.values().copied().max().unwrap_or(p.ts_propose);
                let protocol_version = p.protocol_version;
                if protocol_version >= STRICT_PROTOCOL_VERSION_V1 {
                    p.accept_started = true;
                } else {
                    p.committed = true;
                }
                (
                    protocol_version,
                    p.op_msgpack.clone(),
                    p.op_msgpack.len(),
                    p.target_set
                        .iter()
                        .filter(|node| **node != self.self_id)
                        .copied()
                        .collect::<Vec<_>>(),
                    ts_final,
                    if protocol_version >= STRICT_PROTOCOL_VERSION_V1 {
                        None
                    } else {
                        p.accepted_waker.take()
                    },
                    p.started_at.elapsed(),
                    p.acks.len(),
                    target_count,
                    fast_quorum,
                )
            };

            if ts_final > s.clock {
                s.clock = ts_final;
            }
            let clock_now = s.clock;
            s.peer_clocks.insert(self.self_id, clock_now);

            if protocol_version >= STRICT_PROTOCOL_VERSION_V1 {
                let body = StrictAccept {
                    coord_node: self.self_id as u32,
                    ballot: NORMAL_ACCEPT_BALLOT,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    ts_final,
                    op_msgpack: op_bytes,
                    src_clock: clock_now,
                };
                if protocol_version == STRICT_PROTOCOL_VERSION_V2 {
                    let proposal = s
                        .proposals
                        .get_mut(&op_id)
                        .expect("phase-two proposal must remain registered");
                    proposal.phase_two_accept = Some(body.clone());
                }
                ProposeQuorumOutcome::V1(V1AcceptProposal { body, dsts })
            } else {
                s.mark_committed(op_id, ts_final);
                s.buffer_commit(op_id, ts_final, op_bytes.clone());
                ProposeQuorumOutcome::Legacy(AcceptedProposal {
                    body: StrictBody::Commit(StrictCommit {
                        coord_node: self.self_id as u32,
                        op_id_hi: op_id.0,
                        op_id_lo: op_id.1,
                        ts_final,
                        op_msgpack: op_bytes,
                        src_clock: clock_now,
                    }),
                    dsts,
                    accepted_waker,
                    elapsed,
                    ack_count,
                    target_count,
                    fast_quorum,
                    ts_final,
                    clock_now,
                    op_bytes: op_bytes_len,
                    commit_buffer_len: s.commit_buffer.len(),
                    pending_local_proposals: s.proposals.values().filter(|p| !p.committed).count(),
                    pending_remote_proposes: s.pending_proposes.len(),
                })
            }
        };

        match outcome {
            ProposeQuorumOutcome::Legacy(mut accepted) => {
                log_accepted_proposal(&self.topic, op_id, &accepted);
                if let Some(w) = accepted.accepted_waker.take() {
                    let _ = w.send(());
                }
                self.wake_delivery_and_clock_tick();
                if let Err(e) = send_terminal_fanout_with_broadcast(
                    self.net.as_ref(),
                    &accepted.dsts,
                    &self.topic,
                    accepted.body.clone(),
                )
                .await
                {
                    trace!(error=%e, "send commit multicast failed");
                }
                spawn_commit_fanout_retries(
                    self.net.clone(),
                    self.shutdown.clone(),
                    self.topic.clone(),
                    accepted.dsts,
                    accepted.body,
                    self.cfg.delivery_tick_interval(),
                    self.cfg.pending_propose_ttl(),
                );
            }
            ProposeQuorumOutcome::V1(accept) => {
                self.send_normal_accept_phase(op_id, accept).await;
            }
        }
    }

    /// Promote a v2 proposal that already has its phase-one fast quorum.
    ///
    /// This is used after a transient capability-floor downgrade. The ACKs
    /// remain valid because they were authenticated against the immutable
    /// target descriptor, but sending phase two still requires the current
    /// cluster floor to be v2 so a genuinely legacy relay cannot carry it.
    async fn resume_v2_accept_from_phase_one_quorum(&self, op_id: OpId) {
        if !self.can_originate_v2() {
            return;
        }
        let accept = {
            let mut state = self.state.lock();
            let (ts_final, op_msgpack, dsts) = {
                let Some(proposal) = state.proposals.get_mut(&op_id) else {
                    return;
                };
                if proposal.protocol_version != STRICT_PROTOCOL_VERSION_V2
                    || proposal.committed
                    || proposal.accept_started
                    || proposal.acks.len() < fast_quorum_size(proposal.target_set.len())
                {
                    return;
                }
                proposal.accept_started = true;
                (
                    proposal
                        .acks
                        .values()
                        .copied()
                        .max()
                        .unwrap_or(proposal.ts_propose),
                    proposal.op_msgpack.clone(),
                    proposal
                        .target_set
                        .iter()
                        .filter(|node| **node != self.self_id)
                        .copied()
                        .collect::<Vec<_>>(),
                )
            };
            if ts_final > state.clock {
                state.clock = ts_final;
            }
            let src_clock = state.clock;
            state.peer_clocks.insert(self.self_id, src_clock);
            let body = StrictAccept {
                coord_node: self.self_id as u32,
                ballot: NORMAL_ACCEPT_BALLOT,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_final,
                op_msgpack,
                src_clock,
            };
            state
                .proposals
                .get_mut(&op_id)
                .expect("phase-two proposal must remain registered")
                .phase_two_accept = Some(body.clone());
            V1AcceptProposal { body, dsts }
        };
        self.send_normal_accept_phase(op_id, accept).await;
    }

    async fn send_normal_accept_phase(&self, op_id: OpId, accept: V1AcceptProposal) {
        if let Err(e) = self
            .net
            .send_redundant_multicast(
                &accept.dsts,
                &self.topic,
                StrictBody::Accept(accept.body.clone()),
            )
            .await
        {
            trace!(error=%e, "send strict v1 accept multicast failed");
        }
        self.recv_accept(self.self_id, accept.body).await;
        self.spawn_accept_retries(op_id);
    }

    /// Record the v1 phase-2 accept and reply to its coordinator. A prepared
    /// value cannot be accepted after a higher resolution promise or a
    /// terminal decision has fenced the operation.
    pub async fn recv_accept(&self, from: NodeIdentifier, accept: StrictAccept) {
        self.recv_accept_with_origin_epoch(
            from,
            self.direct_inbound_origin_boot_epoch(from),
            accept,
        )
        .await;
    }

    async fn recv_accept_with_origin_epoch(
        &self,
        from: NodeIdentifier,
        origin_boot_epoch: u64,
        accept: StrictAccept,
    ) {
        let Some(coord) = node_from_u32(accept.coord_node) else {
            warn!(
                node = accept.coord_node,
                "strict accept has invalid coordinator"
            );
            return;
        };
        if coord != from {
            warn!(from, coord, "strict accept origin mismatch");
            return;
        }
        let op_id = (accept.op_id_hi, accept.op_id_lo);
        if node_from_op_id(op_id) != Some(coord) {
            metrics::record_strict_fence_rejection();
            return;
        }
        // Phase 2 of the normal v1 fast path is always ballot zero. Higher
        // ballots belong exclusively to the terminal-resolution protocol;
        // accepting one here would let a forged normal Accept bypass its
        // durable promise/quorum rules.
        if accept.ballot != NORMAL_ACCEPT_BALLOT {
            metrics::record_strict_fence_rejection();
            warn!(
                ballot = accept.ballot,
                op_id_hi = op_id.0,
                op_id_lo = op_id.1,
                "strict accept rejected: normal accept used a nonzero ballot"
            );
            return;
        }
        if !self.terminal_storage_ready() {
            metrics::record_strict_fence_rejection();
            return;
        }
        if let Some(frozen_targets) = self.v2_frozen_targets_for_op(op_id) {
            if !self.local_v2_participation_ready() {
                metrics::record_strict_fence_rejection();
                self.send_accept_ack(coord, op_id, accept.ballot, false)
                    .await;
                return;
            }
            let local_is_frozen = FrozenTarget::find_in_canonical(&frozen_targets, self.self_id)
                .is_some_and(|target| target.boot_epoch() == self.boot_epoch);
            if !local_is_frozen
                || !self.observed_frozen_origin_is_current(from, origin_boot_epoch, &frozen_targets)
            {
                metrics::record_strict_fence_rejection();
                self.send_accept_ack(coord, op_id, accept.ballot, false)
                    .await;
                return;
            }
        }
        let (eligible, frozen_targets) = {
            let mut state = self.state.lock();
            state.observe_peer(from, accept.src_clock);
            let pending = state.pending_proposes.get(&op_id);
            let known_v1 = pending
                .is_some_and(|pending| pending.protocol_version >= STRICT_PROTOCOL_VERSION_V1)
                || state.proposals.get(&op_id).is_some_and(|proposal| {
                    proposal.protocol_version >= STRICT_PROTOCOL_VERSION_V1
                });
            let frozen_targets = pending.and_then(|pending| {
                (pending.protocol_version == STRICT_PROTOCOL_VERSION_V2
                    && pending.v2_descriptor_durable)
                    .then(|| pending.frozen_targets.clone())
                    .flatten()
            });
            let v2_descriptor_missing = pending.is_some_and(|pending| {
                pending.protocol_version == STRICT_PROTOCOL_VERSION_V2
                    && (!pending.v2_descriptor_durable || pending.frozen_targets.is_none())
            }) || state.proposals.get(&op_id).is_some_and(|proposal| {
                proposal.protocol_version == STRICT_PROTOCOL_VERSION_V2 && frozen_targets.is_none()
            });
            let v2_payload_mismatch = pending.is_some_and(|pending| {
                pending.protocol_version == STRICT_PROTOCOL_VERSION_V2
                    && pending.op_msgpack.as_ref() != accept.op_msgpack.as_ref()
            });
            let eligible = !(!known_v1
                || v2_descriptor_missing
                || v2_payload_mismatch
                || state.terminal_decisions.contains_key(&op_id)
                || accept.ballot < state.resolution_promise(op_id));
            if !eligible {
                metrics::record_strict_fence_rejection();
                (false, None)
            } else {
                (true, frozen_targets)
            }
        };
        let accepted = if eligible {
            let record = {
                let mut journal = self.terminal_journal.lock();
                let result = if let Some(frozen_targets) = frozen_targets.as_deref() {
                    journal.upsert_v2_accepted_bytes(
                        op_id,
                        frozen_targets,
                        accept.ballot,
                        accept.ts_final,
                        accept.op_msgpack.clone(),
                    )
                } else {
                    journal.upsert_accepted_bytes(
                        op_id,
                        accept.ballot,
                        accept.ts_final,
                        accept.op_msgpack.clone(),
                    )
                };
                match result {
                    Ok(_) => Some(
                        journal
                            .get(op_id)
                            .cloned()
                            .expect("accepted strict value must have a journal record"),
                    ),
                    Err(error) => {
                        self.record_terminal_journal_failure(&error);
                        warn!(
                            topic = %self.topic,
                            op_id_hi = op_id.0,
                            op_id_lo = op_id.1,
                            error = %error,
                            "strict accept rejected by durable journal"
                        );
                        metrics::record_strict_fence_rejection();
                        None
                    }
                }
            };
            let Some(record) = record else {
                self.send_accept_ack(coord, op_id, accept.ballot, false)
                    .await;
                return;
            };
            let mut state = self.state.lock();
            // A prepare may have won the race after this accept reached disk.
            // The journal check prevents a stale accept from becoming chosen,
            // and rehydrating here ensures either path reports the durable
            // accepted value to later resolution prepares.
            hydrate_terminal_journal_record(&mut state, op_id, &record, true);
            let accepted = record.terminal_decision().is_none()
                && record.accepted_commit().is_some_and(|candidate| {
                    candidate.ballot() == accept.ballot
                        && candidate.ts_final() == accept.ts_final
                        && candidate.op_msgpack() == accept.op_msgpack.as_ref()
                })
                && !state.terminal_decisions.contains_key(&op_id)
                && accept.ballot >= state.resolution_promise(op_id);
            if !accepted {
                metrics::record_strict_fence_rejection();
                false
            } else {
                if !state.pending_proposes.contains_key(&op_id) {
                    if let Some(frozen_targets) = frozen_targets.clone() {
                        state.record_pending_propose_with_descriptor(
                            op_id,
                            coord,
                            accept.op_msgpack.clone(),
                            accept.ts_final,
                            Instant::now(),
                            STRICT_PROTOCOL_VERSION_V2,
                            Some(frozen_targets),
                            true,
                        );
                    } else {
                        state.record_pending_propose_with_protocol(
                            op_id,
                            coord,
                            accept.op_msgpack.clone(),
                            accept.ts_final,
                            Instant::now(),
                            STRICT_PROTOCOL_VERSION_V1,
                        );
                    }
                }
                if accept.ts_final > state.clock {
                    state.clock = accept.ts_final;
                }
                let clock = state.clock;
                state.peer_clocks.insert(self.self_id, clock);
                true
            }
        } else {
            false
        };
        self.send_accept_ack(coord, op_id, accept.ballot, accepted)
            .await;
    }

    fn spawn_accept_ack_retries(&self, op_id: OpId, ack: StrictAcceptAck) {
        let is_v2_pending = self
            .state
            .lock()
            .pending_proposes
            .get(&op_id)
            .is_some_and(|pending| pending.protocol_version == STRICT_PROTOCOL_VERSION_V2);
        if !is_v2_pending {
            return;
        }
        let Some(weak) = self.weak_self.lock().clone() else {
            return;
        };
        if !self.accept_ack_retries.lock().insert(op_id) {
            return;
        }
        tokio::spawn(async move {
            let Some(rt) = weak.upgrade() else {
                return;
            };
            let started_at = Instant::now();
            let broadcast_interval = rt
                .cfg
                .delivery_tick_interval()
                .max(Duration::from_millis(500));
            let mut last_broadcast_at = started_at;
            loop {
                let elapsed = started_at.elapsed();
                let proposal_ttl = rt.cfg.propose_ttl();
                if elapsed >= proposal_ttl {
                    break;
                }
                let delay = rt
                    .cfg
                    .delivery_tick_interval()
                    .min(proposal_ttl.saturating_sub(elapsed));
                tokio::select! {
                    _ = rt.shutdown.cancelled() => break,
                    _ = sleep(delay) => {},
                }
                let retry_is_still_valid = {
                    let state = rt.state.lock();
                    state.pending_proposes.get(&op_id).is_some_and(|pending| {
                        pending.protocol_version == STRICT_PROTOCOL_VERSION_V2
                    }) && state
                        .accepted_values
                        .get(&op_id)
                        .is_some_and(|accepted| accepted.ballot == ack.ballot)
                        && state.terminal_decisions.get(&op_id).is_none()
                };
                if !retry_is_still_valid {
                    break;
                }
                let coord = ack.coord_node as NodeIdentifier;
                if coord == rt.self_id {
                    rt.recv_accept_ack(rt.self_id, ack.clone()).await;
                } else {
                    let now = Instant::now();
                    let use_broadcast = now.duration_since(last_broadcast_at) >= broadcast_interval;
                    if use_broadcast {
                        last_broadcast_at = now;
                    }
                    let result = if use_broadcast {
                        send_accept_ack_fanout(
                            rt.net.as_ref(),
                            coord,
                            &rt.topic,
                            StrictBody::AcceptAck(ack.clone()),
                        )
                        .await
                    } else {
                        rt.net
                            .send_redundant_unicast(
                                coord,
                                &rt.topic,
                                StrictBody::AcceptAck(ack.clone()),
                            )
                            .await
                    };
                    if let Err(error) = result {
                        trace!(%error, "retry strict accept ack failed");
                    }
                }
            }
            rt.accept_ack_retries.lock().remove(&op_id);
            rt.accept_ack_broadcasts.lock().remove(&op_id);
        });
    }

    async fn send_accept_ack(
        &self,
        coord: NodeIdentifier,
        op_id: OpId,
        ballot: u64,
        accepted: bool,
    ) {
        let src_clock = self.state.lock().clock;
        let ack = StrictAcceptAck {
            ack_node: self.self_id as u32,
            coord_node: coord as u32,
            ballot,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            accepted,
            src_clock,
            ack_boot_epoch: self.boot_epoch,
        };
        if coord == self.self_id {
            self.recv_accept_ack(self.self_id, ack.clone()).await;
            if accepted {
                self.spawn_accept_ack_retries(op_id, ack);
            }
        } else {
            if accepted && !self.accept_ack_broadcasts.lock().insert(op_id) {
                // Duplicate Accept frames are expected while the coordinator
                // repairs a hostile route. The first accepted ACK starts the
                // durable retry loop; do not amplify every duplicate into a
                // fresh immediate fanout.
                return;
            }
            let use_broadcast = accepted;
            let result = if use_broadcast {
                send_accept_ack_fanout(
                    self.net.as_ref(),
                    coord,
                    &self.topic,
                    StrictBody::AcceptAck(ack.clone()),
                )
                .await
            } else {
                self.net
                    .send_redundant_unicast(coord, &self.topic, StrictBody::AcceptAck(ack.clone()))
                    .await
            };
            if let Err(error) = result {
                trace!(%error, "send strict accept ack failed");
            }
            if accepted {
                self.spawn_accept_ack_retries(op_id, ack);
            }
        }
    }

    pub async fn recv_accept_ack(&self, from: NodeIdentifier, ack: StrictAcceptAck) {
        self.recv_accept_ack_with_origin_epoch(
            from,
            self.direct_inbound_origin_boot_epoch(from),
            ack,
        )
        .await;
    }

    async fn recv_accept_ack_with_origin_epoch(
        &self,
        from: NodeIdentifier,
        origin_boot_epoch: u64,
        ack: StrictAcceptAck,
    ) {
        if !self.terminal_storage_ready() {
            metrics::record_strict_fence_rejection();
            return;
        }
        let Some(ack_node) = node_from_u32(ack.ack_node) else {
            warn!(node = ack.ack_node, "strict accept ack has invalid node");
            return;
        };
        let Some(coord) = node_from_u32(ack.coord_node) else {
            warn!(
                node = ack.coord_node,
                "strict accept ack has invalid coordinator"
            );
            return;
        };
        if coord != self.self_id || ack_node != from {
            warn!(
                from,
                ack_node, coord, "strict accept ack origin or coordinator mismatch"
            );
            return;
        }
        let op_id = (ack.op_id_hi, ack.op_id_lo);
        if node_from_op_id(op_id) != Some(coord) {
            metrics::record_strict_fence_rejection();
            return;
        }
        // An AcceptAck can only acknowledge the normal ballot-zero phase.
        // Resolution ballots are acknowledged through ResolutionAck instead.
        if ack.ballot != NORMAL_ACCEPT_BALLOT {
            metrics::record_strict_fence_rejection();
            warn!(
                ballot = ack.ballot,
                op_id_hi = op_id.0,
                op_id_lo = op_id.1,
                "strict accept ack rejected: normal accept ack used a nonzero ballot"
            );
            return;
        }
        let terminal = {
            let mut state = self.state.lock();
            let Some(proposal) = state.proposals.get(&op_id) else {
                return;
            };
            let expected_boot_epoch = proposal.target_epochs.get(&ack_node).copied().unwrap_or(0);
            if proposal.protocol_version < STRICT_PROTOCOL_VERSION_V1
                || !proposal.accept_started
                || proposal.committed
                || !proposal.target_set.contains(&ack_node)
                || expected_boot_epoch != ack.ack_boot_epoch
                || proposal.invalid_targets.contains(&ack_node)
                || (proposal.protocol_version == STRICT_PROTOCOL_VERSION_V2
                    && !self.local_v2_participation_ready())
                || (proposal.protocol_version == STRICT_PROTOCOL_VERSION_V2
                    && !self.observed_origin_matches_epoch_in_state(
                        &state,
                        ack_node,
                        origin_boot_epoch,
                        expected_boot_epoch,
                    ))
            {
                metrics::record_strict_fence_rejection();
                return;
            }
            state.observe_peer(ack_node, ack.src_clock);
            let (
                accepted_count,
                fast_quorum,
                ts_final,
                op_msgpack,
                dsts,
                accepted_waker,
                frozen_targets,
            ) = {
                let proposal = state.proposals.get_mut(&op_id).expect("checked above");
                proposal.accept_acks.insert(ack_node, ack.accepted);
                let accepted_count = proposal.accept_acks.values().filter(|ok| **ok).count();
                let fast_quorum = fast_quorum_size(proposal.target_set.len());
                if accepted_count < fast_quorum {
                    return;
                }
                proposal.committed = true;
                (
                    accepted_count,
                    fast_quorum,
                    proposal
                        .acks
                        .values()
                        .copied()
                        .max()
                        .unwrap_or(proposal.ts_propose),
                    proposal.op_msgpack.clone(),
                    proposal
                        .target_set
                        .iter()
                        .filter(|node| **node != self.self_id)
                        .copied()
                        .collect::<Vec<_>>(),
                    proposal.accepted_waker.take(),
                    (proposal.protocol_version == STRICT_PROTOCOL_VERSION_V2)
                        .then(|| frozen_targets_from_epochs(&proposal.target_epochs)),
                )
            };
            let _ = accepted_count;
            let _ = fast_quorum;
            let src_clock = state.clock.max(ts_final);
            state.clock = src_clock;
            state.peer_clocks.insert(self.self_id, src_clock);
            Some((
                ts_final,
                op_msgpack,
                dsts,
                accepted_waker,
                src_clock,
                frozen_targets,
            ))
        };
        let Some((ts_final, op_msgpack, dsts, accepted_waker, src_clock, frozen_targets)) =
            terminal
        else {
            return;
        };
        let terminal_identity =
            frozen_targets
                .as_ref()
                .map(|frozen_targets| TerminalDecisionIdentity {
                    resolver: TerminalResolver::new(self.self_id, self.boot_epoch),
                    frozen_targets: frozen_targets.clone(),
                });
        if !self.apply_terminal_commit_with_descriptor(
            op_id,
            NORMAL_ACCEPT_BALLOT,
            ts_final,
            op_msgpack.clone(),
            terminal_identity.as_ref(),
        ) {
            if !self.requeue_terminal_journal_commit(op_id) {
                {
                    let mut state = self.state.lock();
                    if !state.committed_ids.contains(&op_id) {
                        if let Some(proposal) = state.proposals.get_mut(&op_id) {
                            proposal.committed = false;
                        }
                    }
                }
                self.defer_descriptorless_v2_commit(op_id).await;
            }
            return;
        }
        if let Some(waker) = accepted_waker {
            let _ = waker.send(());
        }
        let decision = StrictBody::Decision(StrictDecision {
            resolver_node: self.self_id as u32,
            ballot: NORMAL_ACCEPT_BALLOT,
            coord_node: self.self_id as u32,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            outcome: Some(StrictDecisionOutcome::Commit(StrictDecisionCommit {
                ts_final,
                op_msgpack,
            })),
            src_clock,
            resolver_boot_epoch: frozen_targets
                .as_ref()
                .map(|_| self.boot_epoch)
                .unwrap_or_default(),
            frozen_targets: frozen_targets
                .as_deref()
                .map(frozen_targets_to_wire)
                .unwrap_or_default(),
        });
        if let Err(error) = send_terminal_fanout_with_broadcast(
            self.net.as_ref(),
            &dsts,
            &self.topic,
            decision.clone(),
        )
        .await
        {
            trace!(%error, "send strict terminal commit decision failed");
        }
        spawn_commit_fanout_retries(
            self.net.clone(),
            self.shutdown.clone(),
            self.topic.clone(),
            dsts,
            decision,
            self.cfg.delivery_tick_interval(),
            self.cfg.pending_propose_ttl(),
        );
    }

    pub async fn recv_decision(&self, from: NodeIdentifier, decision: StrictDecision) {
        self.recv_decision_with_origin_epoch(
            from,
            self.direct_inbound_origin_boot_epoch(from),
            decision,
        )
        .await;
    }

    async fn recv_decision_with_origin_epoch(
        &self,
        from: NodeIdentifier,
        origin_boot_epoch: u64,
        decision: StrictDecision,
    ) {
        if !self.terminal_storage_ready() {
            metrics::record_strict_fence_rejection();
            return;
        }
        let Some(resolver) = node_from_u32(decision.resolver_node) else {
            warn!(
                node = decision.resolver_node,
                "strict decision has invalid resolver"
            );
            return;
        };
        if resolver != from {
            warn!(from, resolver, "strict decision origin mismatch");
            return;
        }
        let Some(coord) = node_from_u32(decision.coord_node) else {
            warn!(
                node = decision.coord_node,
                "strict decision has invalid coordinator"
            );
            return;
        };
        let op_id = (decision.op_id_hi, decision.op_id_lo);
        if node_from_op_id(op_id) != Some(coord) {
            metrics::record_strict_fence_rejection();
            return;
        }
        // Ballot zero is the coordinator's normal fast-path decision. A
        // different resolver must use a nonzero terminal-resolution ballot.
        if decision.ballot == NORMAL_ACCEPT_BALLOT && resolver != coord {
            metrics::record_strict_fence_rejection();
            warn!(
                resolver,
                coord,
                op_id_hi = op_id.0,
                op_id_lo = op_id.1,
                "strict decision rejected: ballot-zero resolver is not coordinator"
            );
            return;
        }
        let known_frozen_targets = self.v2_frozen_targets_for_op(op_id);
        let v2_frozen_targets = if decision.frozen_targets.is_empty() {
            if known_frozen_targets.is_some() || decision.resolver_boot_epoch != 0 {
                metrics::record_strict_fence_rejection();
                warn!(
                    resolver,
                    op_id_hi = op_id.0,
                    op_id_lo = op_id.1,
                    "strict decision rejected: v2 operation used a descriptor-less decision"
                );
                return;
            }
            None
        } else {
            if !self.local_v2_participation_ready() {
                metrics::record_strict_fence_rejection();
                return;
            }
            let Ok(frozen_targets) =
                frozen_targets_from_wire(&decision.frozen_targets, op_id, coord)
            else {
                metrics::record_strict_fence_rejection();
                return;
            };
            let local_is_frozen = FrozenTarget::find_in_canonical(&frozen_targets, self.self_id)
                .is_some_and(|target| target.boot_epoch() == self.boot_epoch);
            if !local_is_frozen
                || decision.resolver_boot_epoch != origin_boot_epoch
                || !self.origin_matches_frozen_target(resolver, origin_boot_epoch, &frozen_targets)
                || known_frozen_targets
                    .as_deref()
                    .is_some_and(|known| known != frozen_targets.as_slice())
            {
                metrics::record_strict_fence_rejection();
                warn!(
                    resolver,
                    origin_boot_epoch,
                    op_id_hi = op_id.0,
                    op_id_lo = op_id.1,
                    "strict v2 decision rejected: resolver incarnation or descriptor mismatch"
                );
                return;
            }
            Some(frozen_targets)
        };
        let terminal_identity =
            v2_frozen_targets
                .as_ref()
                .map(|frozen_targets| TerminalDecisionIdentity {
                    resolver: TerminalResolver::new(resolver, decision.resolver_boot_epoch),
                    frozen_targets: frozen_targets.clone(),
                });
        {
            let mut state = self.state.lock();
            state.observe_peer(from, decision.src_clock);
            if decision.ballot < state.resolution_promise(op_id) && terminal_identity.is_none() {
                metrics::record_strict_fence_rejection();
                return;
            }
        }
        let relay_decision = StrictBody::Decision(decision.clone());
        let applied = match decision.outcome {
            Some(StrictDecisionOutcome::Commit(commit)) => self
                .apply_terminal_commit_with_descriptor(
                    op_id,
                    decision.ballot,
                    commit.ts_final,
                    commit.op_msgpack,
                    terminal_identity.as_ref(),
                ),
            Some(StrictDecisionOutcome::Abort(_)) => self.apply_terminal_abort_with_descriptor(
                op_id,
                decision.ballot,
                terminal_identity.as_ref(),
            ),
            None => {
                warn!(
                    op_id_hi = op_id.0,
                    op_id_lo = op_id.1,
                    "strict decision omitted outcome"
                );
                false
            }
        };
        self.resolution_ack_broadcasts.lock().remove(&op_id);
        if applied {
            let mut dsts: Vec<_> = self.net.alive_members();
            if let Some(targets) = v2_frozen_targets.as_deref() {
                dsts.extend(targets.iter().map(FrozenTarget::node));
            }
            dsts.retain(|node| *node != self.self_id);
            dsts.sort_unstable();
            dsts.dedup();
            if let Err(error) = send_terminal_fanout_with_broadcast(
                self.net.as_ref(),
                &dsts,
                &self.topic,
                relay_decision.clone(),
            )
            .await
            {
                trace!(%error, "send relayed strict terminal decision failed");
            }
            spawn_commit_fanout_retries(
                self.net.clone(),
                self.shutdown.clone(),
                self.topic.clone(),
                dsts,
                relay_decision,
                self.cfg.delivery_tick_interval(),
                self.cfg.pending_propose_ttl(),
            );
        }
    }

    /// Receive an advisory stale-proposal report. Only the deterministic
    /// lowest live strict member starts a ballot; the hint is still useful
    /// when that resolver never received the original Propose.
    pub async fn recv_resolution_hint(&self, from: NodeIdentifier, hint: StrictResolutionHint) {
        self.recv_resolution_hint_with_origin_epoch(
            from,
            self.direct_inbound_origin_boot_epoch(from),
            hint,
        )
        .await;
    }

    async fn recv_resolution_hint_with_origin_epoch(
        &self,
        from: NodeIdentifier,
        origin_boot_epoch: u64,
        hint: StrictResolutionHint,
    ) {
        if !self.terminal_resolution_ready() {
            return;
        }
        let Some(reporter) = node_from_u32(hint.reporter_node) else {
            warn!(
                node = hint.reporter_node,
                "strict resolution hint has invalid reporter"
            );
            return;
        };
        let Some(coord) = node_from_u32(hint.coord_node) else {
            warn!(
                node = hint.coord_node,
                "strict resolution hint has invalid coordinator"
            );
            return;
        };
        if reporter != from {
            warn!(from, reporter, "strict resolution hint origin mismatch");
            return;
        }
        let op_id = (hint.op_id_hi, hint.op_id_lo);
        if hint.protocol_version != STRICT_PROTOCOL_VERSION_V2
            || node_from_op_id(op_id) != Some(coord)
        {
            metrics::record_strict_fence_rejection();
            return;
        }
        let Ok(frozen_targets) = frozen_targets_from_wire(&hint.frozen_targets, op_id, coord)
        else {
            metrics::record_strict_fence_rejection();
            warn!(
                op_id_hi = op_id.0,
                op_id_lo = op_id.1,
                "strict v2 resolution hint has invalid frozen target descriptor"
            );
            return;
        };
        if origin_boot_epoch != hint.reporter_boot_epoch
            || !self.observed_frozen_origin_is_current(reporter, origin_boot_epoch, &frozen_targets)
        {
            metrics::record_strict_fence_rejection();
            warn!(
                from,
                reporter,
                origin_boot_epoch,
                received_epoch = hint.reporter_boot_epoch,
                "strict resolution hint has stale reporter incarnation"
            );
            return;
        }
        let owner = self.frozen_resolution_owner(&frozen_targets);
        if owner != Some(self.self_id) {
            return;
        }
        self.start_resolution(
            op_id,
            coord,
            Some(ResolutionObserved::Pending {
                ts_local: hint.ts_local,
                op_msgpack: hint.op_msgpack,
                protocol_version: hint.protocol_version,
            }),
            frozen_targets,
        )
        .await;
    }

    /// Phase 1 of a terminal-resolution ballot. A resolver promise fences
    /// ordinary v1 accepts before it learns the strongest existing value.
    pub async fn recv_resolution_prepare(
        &self,
        from: NodeIdentifier,
        prepare: StrictResolutionPrepare,
    ) {
        self.recv_resolution_prepare_with_origin_epoch(
            from,
            self.direct_inbound_origin_boot_epoch(from),
            prepare,
        )
        .await;
    }

    async fn recv_resolution_prepare_with_origin_epoch(
        &self,
        from: NodeIdentifier,
        origin_boot_epoch: u64,
        prepare: StrictResolutionPrepare,
    ) {
        let Some(resolver) = node_from_u32(prepare.resolver_node) else {
            warn!(
                node = prepare.resolver_node,
                "strict resolution prepare has invalid resolver"
            );
            return;
        };
        let Some(coord) = node_from_u32(prepare.coord_node) else {
            warn!(
                node = prepare.coord_node,
                "strict resolution prepare has invalid coordinator"
            );
            return;
        };
        if resolver != from {
            warn!(from, resolver, "strict resolution prepare origin mismatch");
            return;
        }
        let op_id = (prepare.op_id_hi, prepare.op_id_lo);
        if prepare.ballot == 0 || node_from_op_id(op_id) != Some(coord) {
            metrics::record_strict_fence_rejection();
            let src_clock = self.state.lock().clock;
            self.send_resolution_ack(
                resolver,
                coord,
                op_id,
                prepare.ballot,
                false,
                ResolutionObserved::None,
                src_clock,
            )
            .await;
            return;
        }
        let frozen_targets = if prepare.frozen_targets.is_empty() {
            None
        } else {
            let Ok(targets) = frozen_targets_from_wire(&prepare.frozen_targets, op_id, coord)
            else {
                metrics::record_strict_fence_rejection();
                let src_clock = self.state.lock().clock;
                self.send_resolution_ack(
                    resolver,
                    coord,
                    op_id,
                    prepare.ballot,
                    false,
                    ResolutionObserved::None,
                    src_clock,
                )
                .await;
                return;
            };
            let local_is_frozen = targets.iter().any(|target| {
                target.node() == self.self_id && target.boot_epoch() == self.boot_epoch
            });
            let resolver_is_frozen =
                self.observed_frozen_origin_is_current(resolver, origin_boot_epoch, &targets);
            if !local_is_frozen || !resolver_is_frozen {
                metrics::record_strict_fence_rejection();
                let src_clock = self.state.lock().clock;
                self.send_resolution_ack(
                    resolver,
                    coord,
                    op_id,
                    prepare.ballot,
                    false,
                    ResolutionObserved::None,
                    src_clock,
                )
                .await;
                return;
            }
            Some(targets)
        };
        if frozen_targets.is_none() && self.v2_frozen_targets_for_op(op_id).is_some() {
            // A descriptor-less prepare belongs to the inbound-compatibility
            // v1 protocol. It cannot promise over a v2 operation, whose
            // original membership is an immutable part of the fence.
            metrics::record_strict_fence_rejection();
            let src_clock = self.state.lock().clock;
            self.send_resolution_ack(
                resolver,
                coord,
                op_id,
                prepare.ballot,
                false,
                ResolutionObserved::None,
                src_clock,
            )
            .await;
            return;
        }
        if frozen_targets.is_some() && !self.local_v2_participation_ready() {
            metrics::record_strict_fence_rejection();
            let src_clock = self.state.lock().clock;
            self.send_resolution_ack(
                resolver,
                coord,
                op_id,
                prepare.ballot,
                false,
                ResolutionObserved::None,
                src_clock,
            )
            .await;
            return;
        }
        if !self.terminal_storage_ready() {
            metrics::record_strict_fence_rejection();
            let src_clock = self.state.lock().clock;
            self.send_resolution_ack(
                resolver,
                coord,
                op_id,
                prepare.ballot,
                false,
                ResolutionObserved::None,
                src_clock,
            )
            .await;
            return;
        }
        let record = {
            let mut journal = self.terminal_journal.lock();
            let result = if let Some(frozen_targets) = frozen_targets.as_deref() {
                journal.upsert_v2_promise(op_id, frozen_targets, prepare.ballot)
            } else {
                journal.upsert_promise(op_id, prepare.ballot)
            };
            match result {
                Ok(_) => journal.get(op_id).cloned(),
                Err(error) => {
                    self.record_terminal_journal_failure(&error);
                    warn!(
                        topic = %self.topic,
                        op_id_hi = op_id.0,
                        op_id_lo = op_id.1,
                        error = %error,
                        "strict resolution promise could not persist"
                    );
                    None
                }
            }
        };
        let Some(record) = record else {
            let src_clock = self.state.lock().clock;
            self.send_resolution_ack(
                resolver,
                coord,
                op_id,
                prepare.ballot,
                false,
                ResolutionObserved::None,
                src_clock,
            )
            .await;
            return;
        };
        let (promised, observed, src_clock) = {
            let mut state = self.state.lock();
            state.observe_peer(from, prepare.src_clock);
            hydrate_terminal_journal_record(&mut state, op_id, &record, true);
            let promised =
                record.terminal_decision().is_some() || record.promise_ballot() == prepare.ballot;
            let observed = resolution_observed(&state, op_id);
            (promised, observed, state.clock)
        };
        self.send_resolution_ack(
            resolver,
            coord,
            op_id,
            prepare.ballot,
            promised,
            observed,
            src_clock,
        )
        .await;
    }

    async fn send_resolution_ack(
        &self,
        resolver: NodeIdentifier,
        coord: NodeIdentifier,
        op_id: OpId,
        ballot: u64,
        promised: bool,
        observed: ResolutionObserved,
        src_clock: u64,
    ) {
        let ack = StrictResolutionAck {
            ack_node: self.self_id as u32,
            ballot,
            coord_node: coord as u32,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            promised,
            observed: resolution_observed_to_wire(observed, op_id, coord),
            src_clock,
            ack_boot_epoch: self.boot_epoch,
        };
        if resolver == self.self_id {
            self.recv_resolution_ack(self.self_id, ack).await;
        } else {
            let use_broadcast = promised && self.resolution_ack_broadcasts.lock().insert(op_id);
            let body = StrictBody::ResolutionAck(ack);
            let result = if use_broadcast {
                send_resolution_ack_fanout(self.net.as_ref(), resolver, &self.topic, body).await
            } else {
                self.net
                    .send_redundant_unicast(resolver, &self.topic, body)
                    .await
            };
            if let Err(error) = result {
                if use_broadcast {
                    self.resolution_ack_broadcasts.lock().remove(&op_id);
                }
                trace!(%error, "send strict resolution ack failed");
            } else if use_broadcast {
                self.schedule_resolution_ack_broadcast_cleanup(op_id);
            }
        }
    }

    fn schedule_resolution_ack_broadcast_cleanup(&self, op_id: OpId) {
        let Some(weak) = self.weak_self.lock().clone() else {
            return;
        };
        let ttl = self.cfg.pending_propose_ttl();
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(ttl) => {}
            }
            if let Some(runtime) = weak.upgrade() {
                runtime.resolution_ack_broadcasts.lock().remove(&op_id);
            }
        });
    }

    pub async fn recv_resolution_ack(&self, from: NodeIdentifier, ack: StrictResolutionAck) {
        self.recv_resolution_ack_with_origin_epoch(
            from,
            self.direct_inbound_origin_boot_epoch(from),
            ack,
        )
        .await;
    }

    async fn recv_resolution_ack_with_origin_epoch(
        &self,
        from: NodeIdentifier,
        origin_boot_epoch: u64,
        ack: StrictResolutionAck,
    ) {
        if !self.terminal_storage_ready() {
            metrics::record_strict_fence_rejection();
            return;
        }
        let Some(ack_node) = node_from_u32(ack.ack_node) else {
            warn!(
                node = ack.ack_node,
                "strict resolution ack has invalid node"
            );
            return;
        };
        let Some(coord) = node_from_u32(ack.coord_node) else {
            warn!(
                node = ack.coord_node,
                "strict resolution ack has invalid coordinator"
            );
            return;
        };
        if ack_node != from {
            warn!(from, ack_node, "strict resolution ack origin mismatch");
            return;
        }
        let op_id = (ack.op_id_hi, ack.op_id_lo);
        if node_from_op_id(op_id) != Some(coord) {
            metrics::record_strict_fence_rejection();
            return;
        }
        let observed = match resolution_observed_from_wire(ack.observed, op_id, coord) {
            Ok(observed) => observed,
            Err(()) => {
                metrics::record_strict_fence_rejection();
                return;
            }
        };
        let decision = {
            let mut resolutions = self.resolutions.lock();
            let Some(resolution) = resolutions.get_mut(&op_id) else {
                return;
            };
            let expected_boot_epoch = resolution
                .target_epochs
                .get(&ack_node)
                .copied()
                .unwrap_or(0);
            if resolution.ballot != ack.ballot
                || resolution.coord_node != coord
                || !resolution.target_set.contains(&ack_node)
                || resolution.invalid_targets.contains(&ack_node)
                || expected_boot_epoch != ack.ack_boot_epoch
                || !self.observed_origin_matches_epoch(
                    ack_node,
                    origin_boot_epoch,
                    expected_boot_epoch,
                )
            {
                metrics::record_strict_fence_rejection();
                return;
            }
            if let ResolutionObserved::Terminal {
                identity: Some(identity),
                ..
            } = &observed
            {
                let expected_targets = frozen_targets_from_epochs(&resolution.target_epochs);
                if identity.frozen_targets != expected_targets
                    || FrozenTarget::find_in_canonical(
                        &identity.frozen_targets,
                        identity.resolver.node(),
                    )
                    .is_none_or(|target| target.boot_epoch() != identity.resolver.boot_epoch())
                {
                    metrics::record_strict_fence_rejection();
                    return;
                }
            } else if matches!(&observed, ResolutionObserved::Terminal { .. }) {
                // Every terminal observation in a v2 resolution must retain
                // the immutable descriptor that authenticated its decision.
                metrics::record_strict_fence_rejection();
                return;
            }
            resolution.prepare_acks.insert(
                ack_node,
                ResolutionPrepareAck {
                    promised: ack.promised,
                    observed,
                },
            );
            if resolution.prepare_acks.len() < recovery_quorum_size(resolution.target_set.len()) {
                return;
            }
            if resolution
                .prepare_acks
                .values()
                .any(|entry| !entry.promised)
            {
                resolutions.remove(&op_id);
                return;
            }
            let decision = choose_resolution_decision(
                resolution.coord_node,
                resolution.ballot,
                resolution
                    .prepare_acks
                    .values()
                    .map(|entry| &entry.observed),
            );
            let targets = resolution.target_set.clone();
            let invalid_targets = resolution.invalid_targets.clone();
            let frozen_targets = frozen_targets_from_epochs(&resolution.target_epochs);
            resolutions.remove(&op_id);
            Some((decision, targets, invalid_targets, frozen_targets))
        };
        let Some((choice, targets, invalid_targets, frozen_targets)) = decision else {
            return;
        };
        let (decision, terminal_identity) = match choice {
            ResolutionDecision::Existing { decision, identity } => {
                let Some(identity) = identity else {
                    metrics::record_strict_fence_rejection();
                    return;
                };
                if identity.frozen_targets != frozen_targets {
                    metrics::record_strict_fence_rejection();
                    return;
                }
                (decision, identity)
            }
            ResolutionDecision::Fresh(decision) => (
                decision,
                TerminalDecisionIdentity {
                    resolver: TerminalResolver::new(self.self_id, self.boot_epoch),
                    frozen_targets: frozen_targets.clone(),
                },
            ),
        };
        let src_clock = self.state.lock().clock;
        let body = match &decision {
            TerminalDecision::Commit(value) => {
                if !self.apply_terminal_commit_with_descriptor(
                    op_id,
                    value.ballot,
                    value.ts_final,
                    value.op_msgpack.clone(),
                    Some(&terminal_identity),
                ) {
                    return;
                }
                StrictBody::Decision(StrictDecision {
                    resolver_node: terminal_identity.resolver.node() as u32,
                    ballot: value.ballot,
                    coord_node: coord as u32,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    outcome: Some(StrictDecisionOutcome::Commit(StrictDecisionCommit {
                        ts_final: value.ts_final,
                        op_msgpack: value.op_msgpack.clone(),
                    })),
                    src_clock,
                    resolver_boot_epoch: terminal_identity.resolver.boot_epoch(),
                    frozen_targets: frozen_targets_to_wire(&terminal_identity.frozen_targets),
                })
            }
            TerminalDecision::Abort { ballot } => {
                if !self.apply_terminal_abort_with_descriptor(
                    op_id,
                    *ballot,
                    Some(&terminal_identity),
                ) {
                    return;
                }
                StrictBody::Decision(StrictDecision {
                    resolver_node: terminal_identity.resolver.node() as u32,
                    ballot: *ballot,
                    coord_node: coord as u32,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    outcome: Some(StrictDecisionOutcome::Abort(StrictDecisionAbort {})),
                    src_clock,
                    resolver_boot_epoch: terminal_identity.resolver.boot_epoch(),
                    frozen_targets: frozen_targets_to_wire(&terminal_identity.frozen_targets),
                })
            }
        };
        let dsts: Vec<NodeIdentifier> = targets
            .into_iter()
            .filter(|node| *node != self.self_id && !invalid_targets.contains(node))
            .collect();
        if let Err(error) =
            send_terminal_fanout_with_broadcast(self.net.as_ref(), &dsts, &self.topic, body.clone())
                .await
        {
            trace!(%error, "send strict terminal resolution decision failed");
        }
        spawn_commit_fanout_retries(
            self.net.clone(),
            self.shutdown.clone(),
            self.topic.clone(),
            dsts,
            body,
            self.cfg.delivery_tick_interval(),
            self.cfg.pending_propose_ttl(),
        );
    }

    async fn start_resolution(
        &self,
        op_id: OpId,
        coord: NodeIdentifier,
        hinted: Option<ResolutionObserved>,
        frozen_targets: Vec<FrozenTarget>,
    ) {
        if node_from_op_id(op_id) != Some(coord) {
            metrics::record_strict_fence_rejection();
            return;
        }
        if !FrozenTarget::is_valid_descriptor(&frozen_targets)
            || !self.terminal_resolution_ready()
            || self.frozen_resolution_owner(&frozen_targets) != Some(self.self_id)
        {
            return;
        }
        let Some(local_target) = FrozenTarget::find_in_canonical(&frozen_targets, self.self_id)
        else {
            metrics::record_strict_fence_rejection();
            return;
        };
        if local_target.boot_epoch() != self.boot_epoch {
            metrics::record_strict_fence_rejection();
            return;
        }
        // A resolver that only learned this operation through a v2 hint must
        // retain the hinted pending value before writing its promise. Without
        // that ordering, a crash after the promise can leave a durable fence
        // with no value to reconstruct and re-drive on restart.
        let hinted_pending_to_persist = match hinted.as_ref() {
            Some(ResolutionObserved::Pending {
                ts_local,
                op_msgpack,
                protocol_version: STRICT_PROTOCOL_VERSION_V2,
            }) => {
                let mut state = self.state.lock();
                if state.committed_ids.contains(&op_id) {
                    return;
                }
                match state.pending_proposes.get(&op_id) {
                    Some(pending)
                        if pending.coord_node == coord
                            && pending.protocol_version == STRICT_PROTOCOL_VERSION_V2
                            && pending.frozen_targets.as_deref()
                                == Some(frozen_targets.as_slice())
                            && pending.op_msgpack.as_ref() == op_msgpack.as_ref() =>
                    {
                        (!pending.v2_descriptor_durable)
                            .then(|| (pending.ts_local, pending.op_msgpack.clone()))
                    }
                    Some(_) => {
                        metrics::record_strict_fence_rejection();
                        return;
                    }
                    None => {
                        state.record_pending_propose_with_descriptor(
                            op_id,
                            coord,
                            op_msgpack.clone(),
                            *ts_local,
                            Instant::now(),
                            STRICT_PROTOCOL_VERSION_V2,
                            Some(frozen_targets.clone()),
                            false,
                        );
                        Some((*ts_local, op_msgpack.clone()))
                    }
                }
            }
            Some(ResolutionObserved::Pending { .. }) => {
                metrics::record_strict_fence_rejection();
                return;
            }
            _ => None,
        };
        if let Some((ts_local, op_msgpack)) = hinted_pending_to_persist {
            if !self.persist_v2_pending_descriptor(
                op_id,
                ts_local,
                op_msgpack.clone(),
                &frozen_targets,
            ) {
                let mut state = self.state.lock();
                if state.pending_proposes.get(&op_id).is_some_and(|pending| {
                    pending.coord_node == coord
                        && pending.protocol_version == STRICT_PROTOCOL_VERSION_V2
                        && pending.frozen_targets.as_deref() == Some(frozen_targets.as_slice())
                        && pending.ts_local == ts_local
                        && pending.op_msgpack == op_msgpack
                        && !pending.v2_descriptor_durable
                }) {
                    state.pending_proposes.remove(&op_id);
                }
                return;
            }
        }
        let target_set: HashSet<NodeIdentifier> =
            frozen_targets.iter().map(FrozenTarget::node).collect();
        let target_epochs: HashMap<NodeIdentifier, u64> = frozen_targets
            .iter()
            .map(|target| (target.node(), target.boot_epoch()))
            .collect();
        let invalid_targets = self.unavailable_frozen_targets(&frozen_targets);
        if target_set.len().saturating_sub(invalid_targets.len())
            < recovery_quorum_size(target_set.len())
        {
            // Keep the durable pending/accepted fence but do not create a
            // new promise round that cannot collect an old-configuration
            // quorum. A returning target with the same incarnation will
            // make a later retry eligible without ever shrinking quorum.
            return;
        }
        {
            let state = self.state.lock();
            if state.terminal_decisions.contains_key(&op_id) || state.committed_ids.contains(&op_id)
            {
                return;
            }
            if let Some(pending) = state.pending_proposes.get(&op_id) {
                if pending.protocol_version != STRICT_PROTOCOL_VERSION_V2
                    || !pending.v2_descriptor_durable
                    || pending.frozen_targets.as_deref() != Some(frozen_targets.as_slice())
                {
                    metrics::record_strict_fence_rejection();
                    return;
                }
            }
        }
        if self.resolutions.lock().contains_key(&op_id) {
            return;
        }
        let (ballot, record) = {
            let mut journal = self.terminal_journal.lock();
            if journal
                .get(op_id)
                .is_some_and(|record| record.terminal_decision().is_some())
            {
                return;
            }
            let prior_ballot = journal
                .get(op_id)
                .map(|record| record.promise_ballot())
                .unwrap_or(0);
            let attempt = self
                .resolution_attempt_counter
                .fetch_add(1, Ordering::Relaxed);
            // A resolver can restart or replace a higher-numbered departed
            // resolver. Preserve the node/attempt ordering for the normal
            // case, but always move above a durable promise when needed.
            let ballot = make_ballot(self.self_id, attempt).max(prior_ballot.saturating_add(1));
            if let Err(error) = journal.upsert_v2_promise(op_id, &frozen_targets, ballot) {
                self.record_terminal_journal_failure(&error);
                warn!(
                    topic = %self.topic,
                    op_id_hi = op_id.0,
                    op_id_lo = op_id.1,
                    error = %error,
                    "strict resolution could not persist local promise"
                );
                return;
            }
            let record = journal
                .get(op_id)
                .cloned()
                .expect("strict resolution promise must have a journal record");
            (ballot, record)
        };
        let self_observed = {
            let mut state = self.state.lock();
            hydrate_terminal_journal_record(&mut state, op_id, &record, true);
            if record.terminal_decision().is_some() || record.promise_ballot() > ballot {
                return;
            }
            state.resolution_promises.insert(op_id, ballot);
            match resolution_observed(&state, op_id) {
                ResolutionObserved::None => hinted.unwrap_or(ResolutionObserved::None),
                observed => observed,
            }
        };
        let mut prepare_acks = HashMap::new();
        prepare_acks.insert(
            self.self_id,
            ResolutionPrepareAck {
                promised: true,
                observed: self_observed,
            },
        );
        self.resolutions.lock().insert(
            op_id,
            Resolution {
                coord_node: coord,
                ballot,
                started_at: Instant::now(),
                target_set: target_set.clone(),
                target_epochs,
                invalid_targets: invalid_targets.clone(),
                prepare_acks,
            },
        );
        let src_clock = self.state.lock().clock;
        let prepare = StrictResolutionPrepare {
            resolver_node: self.self_id as u32,
            ballot,
            coord_node: coord as u32,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            src_clock,
            frozen_targets: frozen_targets_to_wire(&frozen_targets),
        };
        let dsts: Vec<NodeIdentifier> = target_set
            .iter()
            .filter(|node| **node != self.self_id && !invalid_targets.contains(node))
            .copied()
            .collect();
        if dsts.is_empty() {
            let observed = {
                let resolutions = self.resolutions.lock();
                resolutions
                    .get(&op_id)
                    .and_then(|resolution| {
                        resolution
                            .prepare_acks
                            .get(&self.self_id)
                            .map(|ack| ack.observed.clone())
                    })
                    .unwrap_or(ResolutionObserved::None)
            };
            self.recv_resolution_ack(
                self.self_id,
                StrictResolutionAck {
                    ack_node: self.self_id as u32,
                    ballot,
                    coord_node: coord as u32,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    promised: true,
                    observed: resolution_observed_to_wire(observed, op_id, coord),
                    src_clock,
                    ack_boot_epoch: self.boot_epoch,
                },
            )
            .await;
        } else {
            let body = StrictBody::ResolutionPrepare(prepare);
            if let Err(error) = self
                .net
                .send_redundant_multicast(&dsts, &self.topic, body.clone())
                .await
            {
                trace!(%error, "send strict resolution prepare failed");
            }
            self.spawn_resolution_prepare_retries(op_id, ballot, dsts, body);
        }
    }

    fn spawn_resolution_prepare_retries(
        &self,
        op_id: OpId,
        ballot: u64,
        dsts: Vec<NodeIdentifier>,
        body: StrictBody,
    ) {
        if dsts.is_empty() || self.cfg.pending_propose_ttl().is_zero() {
            return;
        }
        let weak = self.weak_self.lock().clone();
        let Some(weak) = weak else {
            return;
        };
        let interval = self.cfg.delivery_tick_interval();
        let retry_ttl = self.cfg.pending_propose_ttl();
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let started_at = Instant::now();
            loop {
                let elapsed = started_at.elapsed();
                if elapsed >= retry_ttl {
                    return;
                }
                let delay = interval.min(retry_ttl.saturating_sub(elapsed));
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(delay) => {}
                }
                if started_at.elapsed() >= retry_ttl {
                    return;
                }
                let Some(runtime) = weak.upgrade() else {
                    return;
                };
                let active = runtime
                    .resolutions
                    .lock()
                    .get(&op_id)
                    .is_some_and(|resolution| resolution.ballot == ballot);
                if !active {
                    return;
                }
                if let Err(error) = runtime
                    .net
                    .send_redundant_multicast(&dsts, &runtime.topic, body.clone())
                    .await
                {
                    trace!(%error, "strict resolution prepare retry failed");
                }
            }
        });
    }

    async fn send_stale_resolution_hints(&self) {
        if !self.terminal_resolution_ready() {
            return;
        }
        let now = Instant::now();
        let hints: Vec<(NodeIdentifier, StrictResolutionHint)> = {
            let state = self.state.lock();
            state
                .pending_proposes
                .iter()
                .filter(|(op_id, pending)| {
                    pending.protocol_version == STRICT_PROTOCOL_VERSION_V2
                        && pending.v2_descriptor_durable
                        && pending.frozen_targets.is_some()
                        && !state.terminal_decisions.contains_key(op_id)
                        && now.duration_since(pending.seen_at) >= self.cfg.pending_propose_ttl()
                })
                .filter_map(|(op_id, pending)| {
                    let frozen_targets = pending.frozen_targets.as_deref()?;
                    let owner = self.frozen_resolution_owner(frozen_targets)?;
                    Some((
                        owner,
                        StrictResolutionHint {
                            reporter_node: self.self_id as u32,
                            coord_node: pending.coord_node as u32,
                            op_id_hi: op_id.0,
                            op_id_lo: op_id.1,
                            ts_local: pending.ts_local,
                            op_msgpack: pending.op_msgpack.clone(),
                            src_clock: state.clock,
                            reporter_boot_epoch: self.boot_epoch,
                            protocol_version: pending.protocol_version,
                            frozen_targets: frozen_targets_to_wire(frozen_targets),
                        },
                    ))
                })
                .collect()
        };
        for (owner, hint) in hints {
            if owner == self.self_id {
                self.recv_resolution_hint(self.self_id, hint).await;
            } else if let Err(error) = self
                .net
                .send_redundant_unicast(owner, &self.topic, StrictBody::ResolutionHint(hint))
                .await
            {
                trace!(%error, "send strict resolution hint failed");
            }
        }
    }

    /// Re-drive a v2 terminal ballot as soon as its coordinator's frozen
    /// incarnation is gone. A legacy relay temporarily lowers the negotiated
    /// floor, so we retain the durable pending/accepted record and send no
    /// *new* resolution traffic until every active relay can carry v2.
    /// The original target descriptor remains the quorum configuration.
    async fn resume_lost_v2_coordinator_resolutions(&self) {
        if !self.terminal_resolution_ready() {
            return;
        }
        let hints: Vec<(NodeIdentifier, StrictResolutionHint)> = {
            let state = self.state.lock();
            state
                .pending_proposes
                .iter()
                .filter(|(op_id, pending)| {
                    pending.protocol_version == STRICT_PROTOCOL_VERSION_V2
                        && pending.v2_descriptor_durable
                        && pending.frozen_targets.is_some()
                        && !state.terminal_decisions.contains_key(op_id)
                })
                .filter_map(|(op_id, pending)| {
                    let frozen_targets = pending.frozen_targets.as_deref()?;
                    let coord_target =
                        FrozenTarget::find_in_canonical(frozen_targets, pending.coord_node)?;
                    if self.frozen_target_is_current(coord_target) {
                        return None;
                    }
                    let owner = self.frozen_resolution_owner(frozen_targets)?;
                    Some((
                        owner,
                        StrictResolutionHint {
                            reporter_node: self.self_id as u32,
                            coord_node: pending.coord_node as u32,
                            op_id_hi: op_id.0,
                            op_id_lo: op_id.1,
                            ts_local: pending.ts_local,
                            op_msgpack: pending.op_msgpack.clone(),
                            src_clock: state.clock,
                            reporter_boot_epoch: self.boot_epoch,
                            protocol_version: pending.protocol_version,
                            frozen_targets: frozen_targets_to_wire(frozen_targets),
                        },
                    ))
                })
                .collect()
        };
        for (owner, hint) in hints {
            if owner == self.self_id {
                self.recv_resolution_hint(self.self_id, hint).await;
            } else if let Err(error) = self
                .net
                .send_redundant_unicast(owner, &self.topic, StrictBody::ResolutionHint(hint))
                .await
            {
                trace!(%error, "send lost-coordinator strict resolution hint failed");
            }
        }
    }

    /// Re-drive a v2 terminal ballot when any member of its frozen
    /// configuration has changed incarnation. An in-flight ballot may have
    /// been addressed to that old process; retaining it would make the
    /// `resolutions` map suppress a fresh, viable old-configuration attempt.
    async fn resume_invalid_v2_target_resolutions(&self) {
        if !self.terminal_resolution_ready() {
            return;
        }
        let hints: Vec<(NodeIdentifier, StrictResolutionHint)> = {
            let state = self.state.lock();
            state
                .pending_proposes
                .iter()
                .filter(|(op_id, pending)| {
                    pending.protocol_version == STRICT_PROTOCOL_VERSION_V2
                        && pending.v2_descriptor_durable
                        && pending.frozen_targets.is_some()
                        && !state.terminal_decisions.contains_key(op_id)
                        && !state.committed_ids.contains(op_id)
                })
                .filter_map(|(op_id, pending)| {
                    let frozen_targets = pending.frozen_targets.as_deref()?;
                    if !frozen_targets
                        .iter()
                        .any(|target| !self.frozen_target_is_current(target))
                    {
                        return None;
                    }
                    let owner = self.frozen_resolution_owner(frozen_targets)?;
                    Some((
                        owner,
                        StrictResolutionHint {
                            reporter_node: self.self_id as u32,
                            coord_node: pending.coord_node as u32,
                            op_id_hi: op_id.0,
                            op_id_lo: op_id.1,
                            ts_local: pending.ts_local,
                            op_msgpack: pending.op_msgpack.clone(),
                            src_clock: state.clock,
                            reporter_boot_epoch: self.boot_epoch,
                            protocol_version: pending.protocol_version,
                            frozen_targets: frozen_targets_to_wire(frozen_targets),
                        },
                    ))
                })
                .collect()
        };
        for (owner, hint) in hints {
            if owner == self.self_id {
                self.recv_resolution_hint(self.self_id, hint).await;
            } else if let Err(error) = self
                .net
                .send_redundant_unicast(owner, &self.topic, StrictBody::ResolutionHint(hint))
                .await
            {
                trace!(%error, "send restarted-target strict resolution hint failed");
            }
        }
    }

    pub async fn recv_commit(&self, from: NodeIdentifier, c: StrictCommit) {
        // Retain decoder compatibility for the pre-v2 Commit body, but never
        // buffer, deliver, or gossip a descriptor-less commit from it.
        let _ = (from, c);
        metrics::record_strict_fence_rejection();
    }

    #[allow(dead_code)]
    async fn recv_legacy_commit_observed(&self, from: NodeIdentifier, c: StrictCommit) {
        let op_id: OpId = (c.op_id_hi, c.op_id_lo);
        if self.has_v2_terminal_descriptor(op_id) {
            metrics::record_strict_fence_rejection();
            self.defer_descriptorless_v2_commit(op_id).await;
            return;
        }
        {
            let state = self.state.lock();
            if matches!(
                state.terminal_decisions.get(&op_id),
                Some(TerminalDecision::Abort { .. })
            ) || state.resolution_promise(op_id) > 0
            {
                metrics::record_strict_fence_rejection();
                return;
            }
        }
        // An ordinary commit is authoritative for this op. Cancel an active
        // takeover before applying it so a later RecoveryCommit cannot race a
        // history-election snapshot install with a second decision path.
        self.recoveries.lock().remove(&op_id);
        let mut notify = false;
        let mut gossip: Option<StrictBody> = None;
        let mut buffered_log: Option<BufferedCommitLog> = None;
        {
            let mut s = self.state.lock();
            s.observe_peer(from, c.src_clock);
            // clock = max(clock, ts_final)
            if c.ts_final > s.clock {
                s.clock = c.ts_final;
            }
            let clock_now = s.clock;
            s.peer_clocks.insert(self.self_id, clock_now);
            // Idempotent: only buffer once. A late Commit arriving after a
            // RecoveryCommit (or vice versa) for the same op_id with a
            // different ts_final is silently ignored — a correct
            // implementation guarantees they agree (see plan §1.4); a
            // mismatch is logged at error level for postmortem.
            if let Some(prev_ts) = s.committed_ts_final.get(&op_id).copied() {
                if prev_ts != c.ts_final {
                    error!(
                        op_id_hi = op_id.0,
                        op_id_lo = op_id.1,
                        prev_ts,
                        new_ts = c.ts_final,
                        "strict commit ts_final disagreement; keeping first"
                    );
                }
            } else if s.mark_committed(op_id, c.ts_final) {
                let op_msgpack = Bytes::from(c.op_msgpack);
                let op_bytes = op_msgpack.len();
                s.buffer_commit(op_id, c.ts_final, op_msgpack.clone());
                buffered_log = Some(BufferedCommitLog {
                    source: "commit",
                    from: Some(from),
                    coord_node: node_from_u32(c.coord_node),
                    op_id,
                    ts_final: c.ts_final,
                    clock_now,
                    op_bytes,
                    commit_buffer_len: s.commit_buffer.len(),
                    pending_local_proposals: s.proposals.values().filter(|p| !p.committed).count(),
                    pending_remote_proposes: s.pending_proposes.len(),
                });
                notify = true;
                gossip = Some(StrictBody::Commit(StrictCommit {
                    coord_node: c.coord_node,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    ts_final: c.ts_final,
                    op_msgpack,
                    src_clock: clock_now,
                }));
            }
        }
        if let Some(log) = buffered_log {
            log_buffered_commit(&self.topic, log);
        }
        if notify {
            self.wake_delivery_and_clock_tick();
        }
        if let Some(body) = gossip {
            let dsts: Vec<NodeIdentifier> = self
                .net
                .alive_members()
                .into_iter()
                .filter(|node| *node != self.self_id)
                .collect();
            if let Err(e) = send_terminal_fanout_with_broadcast(
                self.net.as_ref(),
                &dsts,
                &self.topic,
                body.clone(),
            )
            .await
            {
                trace!(error=%e, "send commit gossip multicast failed");
            }
            spawn_commit_fanout_retries(
                self.net.clone(),
                self.shutdown.clone(),
                self.topic.clone(),
                dsts,
                body,
                self.cfg.delivery_tick_interval(),
                self.cfg.pending_propose_ttl(),
            );
        }
    }

    pub fn recv_clock_tick(&self, from: NodeIdentifier, t: StrictClockTick) {
        {
            let mut s = self.state.lock();
            s.observe_peer(from, t.src_clock);
        }
        // Tick may unblock delivery.
        self.deliver_signal.notify_one();
    }

    /// Reply to a valid terminal-only v2 probe with one fresh directed tick.
    ///
    /// A committed replica can otherwise stop ticking after draining its own
    /// buffer while another replica remains behind the strict delivery
    /// watermark. This is deliberately a direct reply to an authenticated
    /// catchup probe, rather than an echo on every inbound tick, so it cannot
    /// create a cluster-wide tick storm.
    pub(super) async fn send_v2_terminal_probe_clock_reply(&self, requester: NodeIdentifier) {
        if requester == self.self_id || !self.can_respond_to_v2_terminal_catchup(requester) {
            return;
        }
        let src_clock = {
            let mut state = self.state.lock();
            advance_clock_for_tick(&mut state, self.self_id)
        };
        let tick = StrictBody::ClockTick(StrictClockTick {
            src_node: self.self_id as u32,
            src_clock,
        });
        if let Err(error) = self
            .net
            .send_redundant_unicast(requester, &self.topic, tick)
            .await
        {
            trace!(%error, requester, "strict terminal probe clock reply failed");
        }
    }

    pub async fn recv_catchup_req(&self, from: NodeIdentifier, req: StrictCatchupReq) {
        super::catchup::respond_to_request(self, from, req).await
    }

    pub async fn recv_catchup_resp(&self, from: NodeIdentifier, resp: StrictCatchupResp) {
        super::catchup::apply_response(self, from, resp).await
    }

    // ------ Slow-path recovery handlers ------

    /// Phase 1 (Prepare): respond with our current state for `op_id` and,
    /// if the ballot is higher than any we've previously promised, accept
    /// it as our new promise.
    pub async fn recv_recovery_req(&self, from: NodeIdentifier, req: StrictRecoveryReq) {
        let op_id: OpId = (req.op_id_hi, req.op_id_lo);
        if self.has_v2_terminal_descriptor(op_id) {
            metrics::record_strict_fence_rejection();
            self.defer_descriptorless_v2_commit(op_id).await;
            return;
        }
        let coord = match node_from_u32(req.coord_node) {
            Some(c) => c,
            None => {
                warn!(node = req.coord_node, "recovery req has invalid coord_node");
                return;
            }
        };
        let takeover = match node_from_u32(req.takeover_node) {
            Some(c) => c,
            None => {
                warn!(
                    node = req.takeover_node,
                    "recovery req has invalid takeover_node"
                );
                return;
            }
        };
        let (promised, has_committed, committed_ts_final, has_op, ts_local, op_msgpack, src_clock) =
            {
                let mut s = self.state.lock();
                let v1_state =
                    s.pending_proposes.get(&op_id).is_some_and(|pending| {
                        pending.protocol_version >= STRICT_PROTOCOL_VERSION_V1
                    }) || s.proposals.get(&op_id).is_some_and(|proposal| {
                        proposal.protocol_version >= STRICT_PROTOCOL_VERSION_V1
                    }) || s.accepted_values.contains_key(&op_id);
                if v1_state {
                    metrics::record_strict_fence_rejection();
                    return;
                }
                s.observe_peer(from, req.src_clock);
                let promised = s.try_promise(op_id, req.ballot);
                let committed_ts_final = s.committed_ts_final.get(&op_id).copied();
                let has_committed = committed_ts_final.is_some();
                let pending = s.pending_proposes.get(&op_id);
                let (has_op, ts_local, op_msgpack) = pending
                    .map(|p| (true, p.ts_local, p.op_msgpack.clone()))
                    .unwrap_or((false, 0, Bytes::new()));
                (
                    promised,
                    has_committed,
                    committed_ts_final.unwrap_or(0),
                    has_op,
                    ts_local,
                    op_msgpack,
                    s.clock,
                )
            };
        let body = StrictBody::RecoveryAck(StrictRecoveryAck {
            ack_node: self.self_id as u32,
            ballot: req.ballot,
            coord_node: coord as u32,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            promised,
            has_committed,
            committed_ts_final,
            has_op,
            ts_local,
            op_msgpack,
            src_clock,
            ack_boot_epoch: self.boot_epoch,
        });
        if let Err(e) = self.net.send_unicast(takeover, &self.topic, body).await {
            trace!(error=%e, "send recovery-ack failed");
        }
    }

    /// Phase 1 reply (takeover-side): accumulate acks, decide outcome
    /// once we have a recovery quorum.
    pub async fn recv_recovery_ack(&self, from: NodeIdentifier, ack: StrictRecoveryAck) {
        let op_id: OpId = (ack.op_id_hi, ack.op_id_lo);
        let Some(ack_node) = node_from_u32(ack.ack_node) else {
            warn!(node = ack.ack_node, "recovery ack has invalid ack_node");
            return;
        };
        let Some(coord_node) = node_from_u32(ack.coord_node) else {
            warn!(node = ack.coord_node, "recovery ack has invalid coord_node");
            return;
        };
        if ack_node != from {
            warn!(from, ack_node, "recovery ack origin mismatch");
            return;
        }

        // Decide whether quorum is now reached.
        let decision = {
            let mut recoveries = self.recoveries.lock();
            let Some(rec) = recoveries.get_mut(&op_id) else {
                return;
            };
            if ack.ballot != rec.ballot
                || coord_node != rec.coord_node
                || !rec.target_set.contains(&ack_node)
                || rec.invalid_targets.contains(&ack_node)
                || rec.target_epochs.get(&ack_node).copied().unwrap_or(0) != ack.ack_boot_epoch
            {
                trace!(
                    from,
                    coord_node, "recovery ack ignored: does not match frozen recovery"
                );
                return;
            }
            rec.prepare_acks.insert(
                ack_node,
                RecoveryPrepareAck {
                    promised: ack.promised,
                    has_committed: ack.has_committed,
                    committed_ts_final: ack.committed_ts_final,
                    has_op: ack.has_op,
                    ts_local: ack.ts_local,
                    op_msgpack: ack.op_msgpack,
                },
            );
            self.state.lock().observe_peer(from, ack.src_clock);
            let rq = recovery_quorum_size(rec.target_set.len());
            if rec.prepare_acks.len() < rq {
                return;
            }
            // Quorum reached. Decide.
            let any_promise_lost = rec.prepare_acks.values().any(|a| !a.promised);
            if any_promise_lost {
                // A higher ballot exists; abort. Liveness will recover via
                // RecoveryCommit from the higher-ballot takeover.
                debug!(
                    op_id_hi = op_id.0,
                    op_id_lo = op_id.1,
                    "recovery aborted: higher ballot promised elsewhere"
                );
                recoveries.remove(&op_id);
                return;
            }
            // Prefer any has_committed result (the original coord did
            // commit before dying, somewhere in the recovery quorum).
            let committed_choice = rec
                .prepare_acks
                .values()
                .filter(|a| a.has_committed)
                .max_by_key(|a| a.committed_ts_final)
                .cloned();
            if let Some(c) = committed_choice {
                let ts_final = c.committed_ts_final;
                let bytes = if c.op_msgpack.is_empty() {
                    // Edge case: an ack reported has_committed=true but
                    // didn't include op_msgpack (e.g. it had committed
                    // long enough ago that committed_ts_final was GC'd —
                    // shouldn't happen, but be defensive). Fall back to
                    // any has_op ack with the same ts_final.
                    rec.prepare_acks
                        .values()
                        .find(|a| a.has_op && a.ts_local == ts_final)
                        .map(|a| a.op_msgpack.clone())
                        .unwrap_or_else(Bytes::new)
                } else {
                    c.op_msgpack
                };
                let coord = rec.coord_node;
                let ballot = rec.ballot;
                let target = rec.target_set.clone();
                recoveries.remove(&op_id);
                Some((ts_final, bytes, coord, ballot, target))
            } else {
                // No committed ack — the original coord never committed.
                // Pick the highest ts_local among has_op acks. If none has
                // an op, recovery aborts (no replica even saw the Propose).
                let best = rec
                    .prepare_acks
                    .values()
                    .filter(|a| a.has_op)
                    .max_by_key(|a| a.ts_local)
                    .cloned();
                match best {
                    Some(b) => {
                        let coord = rec.coord_node;
                        let ballot = rec.ballot;
                        let target = rec.target_set.clone();
                        recoveries.remove(&op_id);
                        Some((b.ts_local, b.op_msgpack, coord, ballot, target))
                    }
                    None => {
                        debug!(
                            op_id_hi = op_id.0,
                            op_id_lo = op_id.1,
                            "recovery aborted: no replica holds the op (genuinely lost)"
                        );
                        recoveries.remove(&op_id);
                        None
                    }
                }
            }
        };

        let Some((ts_final, op_msgpack, coord, ballot, target)) = decision else {
            return;
        };

        // Apply locally + advance our clock; broadcast RecoveryCommit.
        let clock_now;
        let mut notify = false;
        let mut buffered_log: Option<BufferedCommitLog> = None;
        {
            let mut s = self.state.lock();
            if ts_final > s.clock {
                s.clock = ts_final;
            }
            clock_now = s.clock;
            s.peer_clocks.insert(self.self_id, clock_now);
            if s.committed_ts_final.get(&op_id).copied().is_none()
                && s.mark_committed(op_id, ts_final)
            {
                let op_bytes = op_msgpack.len();
                s.buffer_commit(op_id, ts_final, op_msgpack.clone());
                buffered_log = Some(BufferedCommitLog {
                    source: "recovery_decision",
                    from: None,
                    coord_node: Some(coord),
                    op_id,
                    ts_final,
                    clock_now,
                    op_bytes,
                    commit_buffer_len: s.commit_buffer.len(),
                    pending_local_proposals: s.proposals.values().filter(|p| !p.committed).count(),
                    pending_remote_proposes: s.pending_proposes.len(),
                });
                notify = true;
            }
        }
        if let Some(log) = buffered_log {
            log_buffered_commit(&self.topic, log);
        }
        if notify {
            self.wake_delivery_and_clock_tick();
        }

        let dsts = recovery_commit_repair_dsts(self.net.as_ref(), self.self_id, &target);
        let body = StrictBody::RecoveryCommit(StrictRecoveryCommit {
            takeover_node: self.self_id as u32,
            ballot,
            coord_node: coord as u32,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            ts_final,
            op_msgpack,
            src_clock: clock_now,
        });
        if !dsts.is_empty() {
            if let Err(e) = self
                .net
                .send_redundant_multicast(&dsts, &self.topic, body.clone())
                .await
            {
                trace!(error=%e, "send recovery-commit multicast failed");
            }
        }
        spawn_recovery_commit_repair_retries(
            self.net.clone(),
            self.shutdown.clone(),
            self.topic.clone(),
            self.self_id,
            target,
            body,
            self.cfg.delivery_tick_interval(),
            self.cfg.pending_propose_ttl(),
        );
    }

    /// Phase 2 (Accept-and-Commit): apply if our promise still allows it.
    pub async fn recv_recovery_commit(&self, from: NodeIdentifier, c: StrictRecoveryCommit) {
        let op_id: OpId = (c.op_id_hi, c.op_id_lo);
        if self.has_v2_terminal_descriptor(op_id) {
            metrics::record_strict_fence_rejection();
            self.defer_descriptorless_v2_commit(op_id).await;
            return;
        }
        let mut notify = false;
        let mut buffered_log: Option<BufferedCommitLog> = None;
        {
            let mut s = self.state.lock();
            let v1_state = s
                .pending_proposes
                .get(&op_id)
                .is_some_and(|pending| pending.protocol_version >= STRICT_PROTOCOL_VERSION_V1)
                || s.proposals.get(&op_id).is_some_and(|proposal| {
                    proposal.protocol_version >= STRICT_PROTOCOL_VERSION_V1
                })
                || s.accepted_values.contains_key(&op_id);
            if v1_state
                || matches!(
                    s.terminal_decisions.get(&op_id),
                    Some(TerminalDecision::Abort { .. })
                )
            {
                metrics::record_strict_fence_rejection();
                return;
            }
            s.observe_peer(from, c.src_clock);
            let promised_now = s.recovery_promises.get(&op_id).copied().unwrap_or(0);
            if c.ballot < promised_now {
                trace!(
                    ballot = c.ballot,
                    promised = promised_now,
                    "recovery commit rejected: stale ballot"
                );
                return;
            }
            // Promote our promise so subsequent stale messages are filtered.
            s.try_promise(op_id, c.ballot);
            if c.ts_final > s.clock {
                s.clock = c.ts_final;
            }
            let clock_now = s.clock;
            s.peer_clocks.insert(self.self_id, clock_now);
            // Same dedup discipline as recv_commit.
            if let Some(prev_ts) = s.committed_ts_final.get(&op_id).copied() {
                if prev_ts != c.ts_final {
                    error!(
                        op_id_hi = op_id.0,
                        op_id_lo = op_id.1,
                        prev_ts,
                        new_ts = c.ts_final,
                        "recovery commit ts_final disagreement; keeping first"
                    );
                }
            } else if s.mark_committed(op_id, c.ts_final) {
                let op_msgpack = Bytes::from(c.op_msgpack);
                let op_bytes = op_msgpack.len();
                s.buffer_commit(op_id, c.ts_final, op_msgpack);
                buffered_log = Some(BufferedCommitLog {
                    source: "recovery_commit",
                    from: Some(from),
                    coord_node: node_from_u32(c.coord_node),
                    op_id,
                    ts_final: c.ts_final,
                    clock_now,
                    op_bytes,
                    commit_buffer_len: s.commit_buffer.len(),
                    pending_local_proposals: s.proposals.values().filter(|p| !p.committed).count(),
                    pending_remote_proposes: s.pending_proposes.len(),
                });
                notify = true;
            }
        }
        if let Some(log) = buffered_log {
            log_buffered_commit(&self.topic, log);
        }
        if notify {
            self.wake_delivery_and_clock_tick();
        }
    }

    /// Initiate recovery for every pending Propose whose coord just died,
    /// for which we are the deterministic takeover (= smallest alive node
    /// id excluding the failed coord). Idempotent: skips op_ids that
    /// already have an in-progress recovery.
    pub async fn maybe_initiate_recovery(&self, failed_coord: NodeIdentifier) {
        // Descriptor-less Recovery* messages are receive-only compatibility
        // syntax. A current node never begins a new recovery round with
        // them; v2 terminal resolution owns recovery for durable fences.
        let candidates: Vec<(OpId, PendingProposeSnapshot)> = Vec::new();
        let alive_with_self: HashSet<NodeIdentifier> = self
            .net
            .alive_members()
            .into_iter()
            .chain([self.self_id])
            .collect();
        let takeover = alive_with_self
            .iter()
            .filter(|n| **n != failed_coord)
            .copied()
            .min();
        if takeover != Some(self.self_id) {
            return;
        }
        for (op_id, snap) in candidates {
            let already_running = {
                let recoveries = self.recoveries.lock();
                recoveries.contains_key(&op_id)
            };
            if already_running {
                continue;
            }
            let attempt = self
                .recovery_attempt_counter
                .fetch_add(1, Ordering::Relaxed);
            let ballot = make_ballot(self.self_id, attempt);
            // Self-ack inline (we always promise our own ballot on creation).
            let self_ack = {
                let mut s = self.state.lock();
                let promised = s.try_promise(op_id, ballot);
                let committed_ts_final = s.committed_ts_final.get(&op_id).copied();
                RecoveryPrepareAck {
                    promised,
                    has_committed: committed_ts_final.is_some(),
                    committed_ts_final: committed_ts_final.unwrap_or(0),
                    has_op: true,
                    ts_local: snap.ts_local,
                    op_msgpack: snap.op_msgpack,
                }
            };
            let mut prepare_acks = HashMap::new();
            prepare_acks.insert(self.self_id, self_ack);
            let target_set = alive_with_self.clone();
            let target_epochs = self.snapshot_target_epochs(&target_set);
            {
                let mut recoveries = self.recoveries.lock();
                recoveries.insert(
                    op_id,
                    Recovery {
                        coord_node: failed_coord,
                        ballot,
                        started_at: Instant::now(),
                        target_set: target_set.clone(),
                        target_epochs,
                        invalid_targets: Default::default(),
                        prepare_acks,
                    },
                );
            }
            // Single-node mesh edge case: recovery_quorum = 1, self-ack
            // already satisfies it. Trigger the decision path manually.
            let rq = recovery_quorum_size(target_set.len());
            if rq <= 1 {
                self.try_decide_self_recovery(op_id).await;
                continue;
            }
            // Broadcast Prepare to everyone in target_set except self.
            let dsts: Vec<NodeIdentifier> = target_set
                .iter()
                .filter(|n| **n != self.self_id)
                .copied()
                .collect();
            let src_clock = {
                let s = self.state.lock();
                s.clock
            };
            let body = StrictBody::RecoveryReq(StrictRecoveryReq {
                takeover_node: self.self_id as u32,
                ballot,
                coord_node: failed_coord as u32,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                src_clock,
            });
            if let Err(e) = self
                .net
                .send_redundant_multicast(&dsts, &self.topic, body)
                .await
            {
                trace!(error=%e, "send recovery-prepare multicast failed");
            }
        }
    }

    /// Single-node-mesh recovery shortcut: feed the takeover's self-ack
    /// back through the same decision path as `recv_recovery_ack` would
    /// take from a remote, by synthesising a no-op ack call.
    async fn try_decide_self_recovery(&self, op_id: OpId) {
        // Build a synthetic ack matching what we already have in
        // recoveries[op_id].prepare_acks[self_id]. The decision logic in
        // recv_recovery_ack will see prepare_acks.len() == 1 and resolve.
        let synth = {
            let recoveries = self.recoveries.lock();
            let Some(rec) = recoveries.get(&op_id) else {
                return;
            };
            let Some(self_ack) = rec.prepare_acks.get(&self.self_id) else {
                return;
            };
            StrictRecoveryAck {
                ack_node: self.self_id as u32,
                ballot: rec.ballot,
                coord_node: rec.coord_node as u32,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                promised: self_ack.promised,
                has_committed: self_ack.has_committed,
                committed_ts_final: self_ack.committed_ts_final,
                has_op: self_ack.has_op,
                ts_local: self_ack.ts_local,
                op_msgpack: self_ack.op_msgpack.clone(),
                src_clock: 0,
                ack_boot_epoch: self.boot_epoch,
            }
        };
        // The ack handler will re-insert (idempotent), see quorum, decide.
        self.recv_recovery_ack(self.self_id, synth).await;
    }

    /// Handle alive-set changes. Called from the manager's membership-event
    /// fanout. Fires `QuorumLost` for any in-flight proposals that can no
    /// longer reach fast-quorum, and initiates slow-path recovery for any
    /// pending Propose whose coord just died.
    pub fn on_membership_change(&self, ev: &MembershipEvent) {
        let transition = self.state.lock().apply_membership_event(ev);
        if transition == MembershipTransition::Ignored {
            trace!(event = ?ev, "ignored stale or duplicate strict membership event");
            return;
        }
        // If a coord died (Failed or Left), we may need to take over
        // recovery for any of its in-flight Proposes we hold.
        let member = match ev {
            MembershipEvent::Joined(member)
            | MembershipEvent::Failed(member)
            | MembershipEvent::Left(member)
            | MembershipEvent::Restarted(member) => member,
        };
        let failed_coord = matches!(
            transition,
            MembershipTransition::Removed | MembershipTransition::Restarted
        )
        .then_some(member.node_id());
        let peer_removed = matches!(
            transition,
            MembershipTransition::Removed | MembershipTransition::Restarted
        );
        let mut history_snapshot_request = None;
        if peer_removed {
            let node = member.node_id();
            // A membership removal invalidates an outstanding bootstrap
            // probe/source for that incarnation immediately. The periodic
            // retry loop also reconciles stale routes, but this avoids
            // waiting for its timeout after a definitive membership event.
            let reachable_peers = bootstrap_reachable_peers(self.net.as_ref(), self.self_id)
                .into_iter()
                .filter(|peer| *peer != node);
            history_snapshot_request = self
                .state
                .lock()
                .reconcile_history_election_reachability(reachable_peers);
            // Every catchup image, cursor, and learned terminal generation is
            // scoped to one peer incarnation. A restarted node must begin a
            // fresh authenticated exchange rather than resume its predecessor.
            self.terminal_catchup_snapshots.lock().remove(&node);
            self.terminal_catchup_generations.lock().remove(&node);
            self.snapshot_transfers.lock().remove(&node);
            self.snapshot_receivers.lock().remove(&node);
            let alive_set: HashSet<NodeIdentifier> = self
                .net
                .alive_members()
                .into_iter()
                .chain([self.self_id])
                .collect();
            let wakers = {
                let mut s = self.state.lock();
                s.peer_clocks.remove(&node);
                for proposal in s.proposals.values_mut() {
                    proposal.acks.remove(&node);
                    if transition == MembershipTransition::Restarted
                        && proposal.target_set.contains(&node)
                    {
                        proposal.invalid_targets.insert(node);
                    }
                }
                s.fail_quorum_lost(&alive_set)
            };
            for recovery in self.recoveries.lock().values_mut() {
                recovery.prepare_acks.remove(&node);
                if transition == MembershipTransition::Restarted
                    && recovery.target_set.contains(&node)
                {
                    recovery.invalid_targets.insert(node);
                }
            }
            {
                let mut resolutions = self.resolutions.lock();
                if transition == MembershipTransition::Restarted {
                    // The old incarnation can never answer the Prepare it
                    // was sent. Drop the ephemeral attempt now; its durable
                    // promise remains in the journal and a fresh ballot will
                    // be re-driven below against the original descriptor.
                    resolutions.retain(|_, resolution| !resolution.target_set.contains(&node));
                } else {
                    for resolution in resolutions.values_mut() {
                        resolution.prepare_acks.remove(&node);
                    }
                }
            }
            for (op_id, w) in wakers {
                warn!(
                    topic = %self.topic,
                    op_id_hi = op_id.0,
                    op_id_lo = op_id.1,
                    alive = ?alive_set,
                    event = ?ev,
                    "strict proposal failed because fast quorum became unreachable"
                );
                let _ = w.send(Err(ReplicationError::QuorumLost));
            }
        }
        if let Some(coord) = failed_coord {
            // Spawn a task — maybe_initiate_recovery is async (needs the
            // network). Upgrade the weak self-pointer set in `new()`.
            let weak = self.weak_self.lock().clone();
            if let Some(weak) = weak {
                tokio::spawn(async move {
                    if let Some(rt) = weak.upgrade() {
                        rt.maybe_initiate_recovery(coord).await;
                    }
                });
            }
        }

        // A coordinator-loss event can race a temporary capability downgrade
        // caused by a joining legacy relay. V2 deliberately never falls back
        // to RecoveryReq; this asynchronous re-drive either starts a fresh
        // old-configuration ballot now or leaves the durable pending fence
        // for the GC pass to resume after capability recovery.
        let weak = self.weak_self.lock().clone();
        if let Some(weak) = weak {
            tokio::spawn(async move {
                if let Some(rt) = weak.upgrade() {
                    rt.resume_lost_v2_coordinator_resolutions().await;
                    rt.resume_invalid_v2_target_resolutions().await;
                }
            });
        }

        // A peer became reachable or restarted. Trigger history election for
        // both startup catchup and partition heal: split sides can have
        // divergent strict histories, so the merged cluster must converge on
        // one rank before normal traffic resumes.
        let peer_added = matches!(
            transition,
            MembershipTransition::Joined | MembershipTransition::Restarted
        );
        if peer_added {
            // Do not discard an active probe merely because the same live
            // incarnation was announced again. A true rejoin/restart was
            // removed from `history_alive_peers` above, so it still rearms a
            // fresh election before normal strict traffic can resume.
            let should_rearm = {
                let mut state = self.state.lock();
                if state.history_alive_peers.contains(&member.node_id()) {
                    false
                } else {
                    state.request_history_election();
                    true
                }
            };
            if should_rearm {
                // A restarted source must never receive a snapshot request
                // selected for its previous incarnation.
                history_snapshot_request = None;
                self.wake_clock_tick_loop();
                let weak = self.weak_self.lock().clone();
                if let Some(weak) = weak {
                    tokio::spawn(async move {
                        if let Some(rt) = weak.upgrade() {
                            rt.try_bootstrap_catchup().await;
                        }
                    });
                }
            }
        }

        if let Some(request) = history_snapshot_request {
            let weak = self.weak_self.lock().clone();
            if let Some(weak) = weak {
                tokio::spawn(async move {
                    if let Some(rt) = weak.upgrade()
                        && let Err(error) = rt.send_history_snapshot_request(request).await
                    {
                        debug!(
                            dst = request.peer(),
                            error = %error,
                            "strict catchup membership-reconciled snapshot request failed"
                        );
                        rt.state.lock().request_history_election();
                    }
                });
            }
        }

        self.deliver_signal.notify_one();
    }
}

/// Lightweight snapshot of a pending Propose, used to copy the bits we
/// need out from under the state lock before doing async work.
struct PendingProposeSnapshot {
    ts_local: u64,
    op_msgpack: Bytes,
}

impl<R: StrictReplicable> StrictRuntime<R> {
    fn operation_requires_v2_origin_proof(&self, op_id: OpId) -> bool {
        let state_requires_proof = {
            let state = self.state.lock();
            state
                .pending_proposes
                .get(&op_id)
                .is_some_and(|pending| pending.protocol_version == STRICT_PROTOCOL_VERSION_V2)
                || state
                    .proposals
                    .get(&op_id)
                    .is_some_and(|proposal| proposal.protocol_version == STRICT_PROTOCOL_VERSION_V2)
        };
        state_requires_proof
            || self.resolutions.lock().contains_key(&op_id)
            || self.has_v2_terminal_descriptor(op_id)
    }

    fn origin_is_admissible_for_frozen_operation(
        &self,
        from: NodeIdentifier,
        origin_boot_epoch: u64,
        op_id: OpId,
    ) -> bool {
        self.v2_frozen_targets_for_op(op_id).is_some_and(|targets| {
            self.origin_matches_frozen_target(from, origin_boot_epoch, &targets)
        })
    }

    fn origin_is_admissible_for_body(
        &self,
        from: NodeIdentifier,
        origin_boot_epoch: u64,
        body: &StrictBody,
    ) -> bool {
        if self.observed_origin_matches_epoch(from, origin_boot_epoch, origin_boot_epoch) {
            return true;
        }
        let op_id = match body {
            StrictBody::ProposeV1(propose)
                if propose.protocol_version >= STRICT_PROTOCOL_VERSION_V2 =>
            {
                Some((propose.op_id_hi, propose.op_id_lo))
            }
            StrictBody::ProposeAck(ack) => Some((ack.op_id_hi, ack.op_id_lo)),
            StrictBody::Accept(accept) => Some((accept.op_id_hi, accept.op_id_lo)),
            StrictBody::AcceptAck(ack) => Some((ack.op_id_hi, ack.op_id_lo)),
            StrictBody::Decision(decision) if !decision.frozen_targets.is_empty() => {
                Some((decision.op_id_hi, decision.op_id_lo))
            }
            _ => None,
        };
        op_id.is_some_and(|op_id| {
            self.origin_is_admissible_for_frozen_operation(from, origin_boot_epoch, op_id)
        })
    }

    fn reject_untrusted_v2_origin(&self) {
        metrics::record_strict_fence_rejection();
    }
}

#[async_trait]
impl<R: StrictReplicable> ErasedStrictRuntime for StrictRuntime<R> {
    async fn dispatch(
        &self,
        from: NodeIdentifier,
        origin_boot_epoch: u64,
        origin_authenticated: bool,
        body: StrictBody,
    ) {
        // Keep old wire messages decodable during coordinated upgrades, but
        // never execute an unproven strict operation. A proofless frame must
        // not advance clocks, install history/terminal state, or cause an
        // acknowledgement, recovery, gossip, or follow-up catchup request.
        if !origin_authenticated {
            metrics::record_strict_fence_rejection();
            return;
        }
        // The proof binds the asserted epoch, but a valid proof from a
        // previous incarnation is still replayable. Only accept it while the
        // authenticated origin matches the current known membership
        // incarnation. A transient unreachable event must not discard a
        // durable response from the frozen incarnation.
        if !self.origin_is_admissible_for_body(from, origin_boot_epoch, &body) {
            metrics::record_strict_fence_rejection();
            return;
        }
        match body {
            StrictBody::Propose(p) => self.recv_propose(from, p).await,
            StrictBody::ProposeV1(p) => {
                if p.protocol_version >= STRICT_PROTOCOL_VERSION_V2 && !origin_authenticated {
                    self.reject_untrusted_v2_origin();
                    return;
                }
                self.recv_propose_v1_with_origin_epoch(from, origin_boot_epoch, p)
                    .await
            }
            StrictBody::ProposeAck(a) => {
                if self.operation_requires_v2_origin_proof((a.op_id_hi, a.op_id_lo))
                    && !origin_authenticated
                {
                    self.reject_untrusted_v2_origin();
                    return;
                }
                self.recv_propose_ack_with_origin_epoch(from, origin_boot_epoch, a)
                    .await
            }
            StrictBody::Commit(c) => self.recv_commit(from, c).await,
            StrictBody::ClockTick(t) => self.recv_clock_tick(from, t),
            StrictBody::CatchupReq(r) => {
                if self.net.peer_strict_replication_protocol_version(from)
                    >= STRICT_PROTOCOL_VERSION_V2
                    && !origin_authenticated
                {
                    self.reject_untrusted_v2_origin();
                    return;
                }
                self.recv_catchup_req(from, r).await
            }
            StrictBody::CatchupResp(r) => {
                if self.net.peer_strict_replication_protocol_version(from)
                    >= STRICT_PROTOCOL_VERSION_V2
                    && !origin_authenticated
                {
                    self.reject_untrusted_v2_origin();
                    return;
                }
                self.recv_catchup_resp(from, r).await
            }
            StrictBody::RecoveryReq(_)
            | StrictBody::RecoveryAck(_)
            | StrictBody::RecoveryCommit(_) => {
                // RecoveryReq/RecoveryCommit are legacy descriptor-less
                // traffic. Decode them for compatibility but do not answer,
                // relay, or create a new legacy recovery round.
                metrics::record_strict_fence_rejection();
            }
            StrictBody::Accept(a) => {
                if self.operation_requires_v2_origin_proof((a.op_id_hi, a.op_id_lo))
                    && !origin_authenticated
                {
                    self.reject_untrusted_v2_origin();
                    return;
                }
                self.recv_accept_with_origin_epoch(from, origin_boot_epoch, a)
                    .await
            }
            StrictBody::AcceptAck(a) => {
                if self.operation_requires_v2_origin_proof((a.op_id_hi, a.op_id_lo))
                    && !origin_authenticated
                {
                    self.reject_untrusted_v2_origin();
                    return;
                }
                self.recv_accept_ack_with_origin_epoch(from, origin_boot_epoch, a)
                    .await
            }
            StrictBody::ResolutionHint(h) => {
                if h.protocol_version >= STRICT_PROTOCOL_VERSION_V2 && !origin_authenticated {
                    self.reject_untrusted_v2_origin();
                    return;
                }
                self.recv_resolution_hint_with_origin_epoch(from, origin_boot_epoch, h)
                    .await
            }
            StrictBody::ResolutionPrepare(p) => {
                if !p.frozen_targets.is_empty() && !origin_authenticated {
                    self.reject_untrusted_v2_origin();
                    return;
                }
                self.recv_resolution_prepare_with_origin_epoch(from, origin_boot_epoch, p)
                    .await
            }
            StrictBody::ResolutionAck(a) => {
                if self.operation_requires_v2_origin_proof((a.op_id_hi, a.op_id_lo))
                    && !origin_authenticated
                {
                    self.reject_untrusted_v2_origin();
                    return;
                }
                self.recv_resolution_ack_with_origin_epoch(from, origin_boot_epoch, a)
                    .await
            }
            StrictBody::Decision(d) => {
                if (!d.frozen_targets.is_empty()
                    || self.operation_requires_v2_origin_proof((d.op_id_hi, d.op_id_lo)))
                    && !origin_authenticated
                {
                    self.reject_untrusted_v2_origin();
                    return;
                }
                self.recv_decision_with_origin_epoch(from, origin_boot_epoch, d)
                    .await
            }
        }
    }

    fn on_membership(&self, ev: &MembershipEvent) {
        // Re-evaluate quorum + maybe initiate recovery on every event.
        // (Cheap path; spawn only fires on Failed/Left.)
        self.on_membership_change(ev);
    }

    fn strict_v2_advertisement_prerequisites_ready(&self) -> bool {
        StrictRuntime::strict_v2_advertisement_prerequisites_ready(self)
    }

    fn shutdown(&self) {
        self.shutdown.cancel();
        self.propose_semaphore.close();
        let proposals = {
            let mut state = self.state.lock();
            std::mem::take(&mut state.proposals)
        };
        for (_, mut proposal) in proposals {
            if let Some(waker) = proposal.waker.take() {
                let _ = waker.send(Err(ReplicationError::Shutdown));
            }
        }
    }
}

// ---------- Background loops ----------

async fn send_terminal_fanout(
    net: &dyn StrictNet,
    dsts: &[NodeIdentifier],
    topic: &str,
    body: StrictBody,
) -> Result<(), ReplicationError> {
    if dsts.is_empty() {
        return Ok(());
    }
    let multicast = net
        .send_redundant_multicast(dsts, topic, body.clone())
        .await;
    let mut direct_succeeded = false;
    for dst in dsts.iter().copied() {
        if net
            .send_redundant_unicast(dst, topic, body.clone())
            .await
            .is_ok()
        {
            direct_succeeded = true;
        }
    }
    match (multicast, direct_succeeded) {
        (Ok(()), _) | (Err(_), true) => Ok(()),
        (Err(error), false) => Err(error),
    }
}

async fn send_terminal_fanout_with_broadcast(
    net: &dyn StrictNet,
    dsts: &[NodeIdentifier],
    topic: &str,
    body: StrictBody,
) -> Result<(), ReplicationError> {
    let targeted = send_terminal_fanout(net, dsts, topic, body.clone()).await;
    let broadcast = net.send_broadcast(topic, body).await;
    match (targeted, broadcast) {
        (Ok(()), Ok(())) | (Ok(()), Err(_)) | (Err(_), Ok(())) => Ok(()),
        (Err(error), Err(_)) => Err(error),
    }
}

async fn send_accept_ack_fanout(
    net: &dyn StrictNet,
    coord: NodeIdentifier,
    topic: &str,
    body: StrictBody,
) -> Result<(), ReplicationError> {
    let unicast = net.send_redundant_unicast(coord, topic, body.clone()).await;
    let broadcast = net.send_broadcast(topic, body).await;
    match (unicast, broadcast) {
        (Ok(()), Ok(())) | (Ok(()), Err(_)) | (Err(_), Ok(())) => Ok(()),
        (Err(error), Err(_)) => Err(error),
    }
}

async fn send_resolution_ack_fanout(
    net: &dyn StrictNet,
    resolver: NodeIdentifier,
    topic: &str,
    body: StrictBody,
) -> Result<(), ReplicationError> {
    let unicast = net
        .send_redundant_unicast(resolver, topic, body.clone())
        .await;
    let broadcast = net.send_broadcast(topic, body).await;
    match (unicast, broadcast) {
        (Ok(()), Ok(())) | (Ok(()), Err(_)) | (Err(_), Ok(())) => Ok(()),
        (Err(error), Err(_)) => Err(error),
    }
}

fn spawn_commit_fanout_retries(
    net: Arc<dyn StrictNet>,
    shutdown: CancellationToken,
    topic: String,
    dsts: Vec<NodeIdentifier>,
    body: StrictBody,
    interval: Duration,
    retry_ttl: Duration,
) {
    if dsts.is_empty() || retry_ttl.is_zero() {
        return;
    }
    tokio::spawn(async move {
        let started_at = Instant::now();
        // Terminal decisions are already fanned out immediately. Keep the
        // long-lived repair worker below the delivery tick so several prior
        // rounds cannot monopolize the reliable control queues and starve a
        // new proposal's phase-two acknowledgements.
        let retry_interval = interval.max(Duration::from_millis(500));
        let broadcast_interval = retry_interval;
        let mut last_broadcast_at = started_at;
        loop {
            let elapsed = started_at.elapsed();
            if elapsed >= retry_ttl {
                return;
            }
            let delay = retry_interval.min(retry_ttl.saturating_sub(elapsed));
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(delay) => {},
            }
            if started_at.elapsed() >= retry_ttl {
                return;
            }
            let now = Instant::now();
            let use_broadcast = now.duration_since(last_broadcast_at) >= broadcast_interval;
            if use_broadcast {
                last_broadcast_at = now;
            }
            let result = if use_broadcast {
                send_terminal_fanout_with_broadcast(net.as_ref(), &dsts, &topic, body.clone()).await
            } else {
                send_terminal_fanout(net.as_ref(), &dsts, &topic, body.clone()).await
            };
            if let Err(e) = result {
                trace!(error=%e, "commit fanout retry failed");
            }
        }
    });
}

fn recovery_commit_repair_dsts(
    net: &dyn StrictNet,
    self_id: NodeIdentifier,
    frozen_targets: &HashSet<NodeIdentifier>,
) -> Vec<NodeIdentifier> {
    let mut dsts: Vec<_> = frozen_targets
        .iter()
        .copied()
        .chain(net.alive_members())
        .filter(|node| *node != self_id)
        .collect();
    dsts.sort_unstable();
    dsts.dedup();
    dsts
}

fn spawn_recovery_commit_repair_retries(
    net: Arc<dyn StrictNet>,
    shutdown: CancellationToken,
    topic: String,
    self_id: NodeIdentifier,
    frozen_targets: HashSet<NodeIdentifier>,
    body: StrictBody,
    interval: Duration,
    retry_ttl: Duration,
) {
    if retry_ttl.is_zero() {
        return;
    }
    tokio::spawn(async move {
        let started_at = Instant::now();
        loop {
            let elapsed = started_at.elapsed();
            if elapsed >= retry_ttl {
                return;
            }
            let delay = interval.min(retry_ttl.saturating_sub(elapsed));
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(delay) => {},
            }
            if started_at.elapsed() >= retry_ttl {
                return;
            }
            let dsts = recovery_commit_repair_dsts(net.as_ref(), self_id, &frozen_targets);
            if dsts.is_empty() {
                continue;
            }
            if let Err(e) = net
                .send_redundant_multicast(&dsts, &topic, body.clone())
                .await
            {
                trace!(error=%e, "recovery commit repair retry failed");
            }
        }
    });
}

fn spawn_delivery_loop<R: StrictReplicable>(rt: Arc<StrictRuntime<R>>) {
    let weak = {
        let rt = rt;
        Arc::downgrade(&rt)
    };
    tokio::spawn(async move {
        let Some(rt) = weak.upgrade() else {
            return;
        };
        let mut ticker = tokio::time::interval(rt.cfg.delivery_tick_interval());
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = rt.shutdown.cancelled() => return,
                _ = rt.deliver_signal.notified() => {}
                _ = ticker.tick() => {}
            }
            run_delivery_pass(&rt).await;
            run_gc_pass(&rt);
        }
    });
}

async fn run_delivery_pass<R: StrictReplicable>(rt: &Arc<StrictRuntime<R>>) {
    let alive = delivery_members(rt.net.as_ref(), rt.self_id);
    let now = Instant::now();
    let mut blocked: Option<DeliveryBlockDiagnostics> = None;
    let to_apply: Vec<BufferedOp> = {
        let mut s = rt.state.lock();
        // A newly requested, idle election may be waiting for an already
        // decided terminal commit to drain before it can safely begin. Do
        // not turn that prerequisite into a deadlock. Once probing or
        // installing starts, delivery remains fenced against the snapshot.
        if s.history_election_active() {
            Vec::new()
        } else {
            let watermark = delivery_watermark(&s, rt.self_id, &alive);
            let raw_high_water = watermark.high_water;
            // A peer at exactly `ts_final` can still coordinate or forward a
            // different commit with that same timestamp. Wait until every live
            // peer has advanced beyond the timestamp before draining its tie set.
            let mut effective_high_water = raw_high_water.saturating_sub(1);
            let pending_blocker = earliest_uncommitted_proposal_blocker(&s, rt.self_id, now);
            if let Some(ts) = s.earliest_uncommitted_proposal_ts() {
                effective_high_water = effective_high_water.min(ts.saturating_sub(1));
            }
            let drained = s.drain_deliverable(effective_high_water);
            s.mark_delivering_commits(&drained);
            if let Some(next) = next_buffered_op_diagnostics(&s, now) {
                if next.ts_final > effective_high_water {
                    blocked = Some(DeliveryBlockDiagnostics {
                        next,
                        raw_high_water,
                        effective_high_water,
                        watermark,
                        pending_blocker,
                        alive_count: alive.len(),
                        commit_buffer_len: s.commit_buffer.len(),
                        pending_local_proposals: s
                            .proposals
                            .values()
                            .filter(|p| !p.committed)
                            .count(),
                        pending_remote_proposes: s.pending_proposes.len(),
                    });
                }
            }
            drained
        }
    };
    if let Some(diagnostics) = blocked {
        log_delivery_blocked(rt, diagnostics);
    } else {
        clear_delivery_blocked(rt);
    }
    for buf in to_apply {
        let buffered_for = buf.buffered_at.elapsed();
        let decode_started_at = Instant::now();
        let op: R::Op = match rmp_serde::from_slice(&buf.op_msgpack) {
            Ok(o) => o,
            Err(e) => {
                metrics::record_pipeline_stage(
                    ReplicationPipelineKind::Strict,
                    ReplicationPipelineStage::MsgpackDecode,
                    decode_started_at.elapsed(),
                );
                warn!(
                    error = %e,
                    topic = %rt.topic,
                    op_id_hi = buf.op_id.0,
                    op_id_lo = buf.op_id.1,
                    ts_final = buf.ts_final,
                    buffered_for_ms = buffered_for.as_millis(),
                    "failed to decode committed op msgpack"
                );
                let mut state = rt.state.lock();
                state.finish_delivering_commit(buf.op_id);
                state.request_history_election();
                drop(state);
                rt.wake_clock_tick_loop();
                continue;
            }
        };
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::MsgpackDecode,
            decode_started_at.elapsed(),
        );
        let version = rt.repo.current_version() + 1;
        debug!(
            topic = %rt.topic,
            op_id_hi = buf.op_id.0,
            op_id_lo = buf.op_id.1,
            ts_final = buf.ts_final,
            version,
            buffered_for_ms = buffered_for.as_millis(),
            op_bytes = buf.op_msgpack.len(),
            "strict delivery applying committed op"
        );
        let apply_started = Instant::now();
        let apply_outcome = rt
            .repo
            .apply_committed_once(
                version,
                op,
                StrictLogMetadata {
                    op_id_hi: buf.op_id.0,
                    op_id_lo: buf.op_id.1,
                    ts_final: buf.ts_final,
                },
            )
            .await;
        let apply_elapsed = apply_started.elapsed();
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::RepoApply,
            apply_elapsed,
        );
        if apply_outcome == StrictCommitApplyOutcome::Failed {
            rt.net
                .report_strict_replication_repository_capability_loss();
            warn!(
                topic = %rt.topic,
                op_id_hi = buf.op_id.0,
                op_id_lo = buf.op_id.1,
                ts_final = buf.ts_final,
                "strict delivery repository application failed; rearming history election before retry"
            );
            {
                let mut state = rt.state.lock();
                // A version/ledger conflict cannot be repaired by blindly
                // replaying the same buffered commit. Re-enter the history
                // election first so a peer snapshot can reconcile the
                // repository version and durable operation-id ledger.
                state.finish_delivering_commit(buf.op_id);
                state.request_history_election();
                state.buffer_commit(buf.op_id, buf.ts_final, buf.op_msgpack);
            }
            rt.wake_delivery_and_clock_tick();
            let runtime = rt.clone();
            tokio::spawn(async move {
                runtime.try_bootstrap_catchup().await;
            });
            continue;
        }
        if apply_outcome == StrictCommitApplyOutcome::AlreadyApplied {
            debug!(
                topic = %rt.topic,
                op_id_hi = buf.op_id.0,
                op_id_lo = buf.op_id.1,
                "strict delivery replay was already applied by the repository"
            );
        }
        // Fire local proposer's waker, if any, and clear the proposal.
        let (waker, local_proposal_elapsed) = {
            let mut s = rt.state.lock();
            s.finish_delivering_commit(buf.op_id);
            if buf.ts_final > s.delivered_high_water {
                s.delivered_high_water = buf.ts_final;
            }
            let proposal = s.proposals.remove(&buf.op_id);
            let elapsed = proposal.as_ref().map(|p| p.started_at.elapsed());
            let waker = proposal.and_then(|p| p.waker);
            (waker, elapsed)
        };
        log_delivery_applied(
            &rt.topic,
            &buf,
            version,
            buffered_for,
            apply_elapsed,
            local_proposal_elapsed,
        );
        if let Some(w) = waker {
            let _ = w.send(Ok(version));
        }
    }
}

fn delivery_watermark(
    state: &StrictState,
    self_id: NodeIdentifier,
    alive: &[NodeIdentifier],
) -> DeliveryWatermark {
    let high_water = state.delivery_high_water(self_id, alive);
    let mut low_water_node = self_id;
    let mut low_water_clock = state.clock;
    let mut missing_clock_peers = 0;
    for node in alive.iter().copied() {
        if node == self_id {
            continue;
        }
        match state.peer_clocks.get(&node).copied() {
            Some(clock) => {
                if clock <= low_water_clock {
                    low_water_node = node;
                    low_water_clock = clock;
                }
            }
            None => {
                missing_clock_peers += 1;
                if low_water_clock != 0 {
                    low_water_node = node;
                    low_water_clock = 0;
                }
            }
        }
    }
    DeliveryWatermark {
        high_water,
        low_water_node,
        low_water_clock,
        missing_clock_peers,
    }
}

fn delivery_members(net: &dyn StrictNet, self_id: NodeIdentifier) -> Vec<NodeIdentifier> {
    let mut seen = HashSet::new();
    let mut members = Vec::new();
    for node in net.alive_members().into_iter().chain([self_id]) {
        if !seen.insert(node) {
            continue;
        }
        if node == self_id || net.has_live_route(node, ServiceLevel::Reliable) {
            members.push(node);
        }
    }
    members
}

fn earliest_uncommitted_proposal_blocker(
    state: &StrictState,
    self_id: NodeIdentifier,
    now: Instant,
) -> Option<UncommittedProposalBlocker> {
    let local = state
        .proposals
        .iter()
        .filter(|(_, proposal)| !proposal.committed)
        .map(|(op_id, proposal)| UncommittedProposalBlocker {
            kind: "local",
            op_id: *op_id,
            coord_node: self_id,
            ts: proposal.ts_propose,
            age: now.saturating_duration_since(proposal.started_at),
        });
    let remote = state
        .pending_proposes
        .iter()
        .map(|(op_id, pending)| UncommittedProposalBlocker {
            kind: "remote",
            op_id: *op_id,
            coord_node: pending.coord_node,
            ts: pending.ts_local,
            age: now.saturating_duration_since(pending.seen_at),
        });
    local.chain(remote).min_by_key(|blocker| blocker.ts)
}

fn next_buffered_op_diagnostics(
    state: &StrictState,
    now: Instant,
) -> Option<NextBufferedOpDiagnostics> {
    state
        .commit_buffer
        .iter()
        .next()
        .map(|(key, buffered)| NextBufferedOpDiagnostics {
            key: *key,
            op_id: buffered.op_id,
            ts_final: buffered.ts_final,
            buffered_for: now.saturating_duration_since(buffered.buffered_at),
        })
}

fn log_delivery_blocked<R: StrictReplicable>(
    rt: &Arc<StrictRuntime<R>>,
    diagnostics: DeliveryBlockDiagnostics,
) {
    let now = Instant::now();
    let (blocked_for, should_log) = {
        let mut state = rt.delivery_blocked_log.lock();
        if state.key != Some(diagnostics.next.key) {
            state.key = Some(diagnostics.next.key);
            state.blocked_since = Some(now);
            state.last_log_at = None;
        }
        let blocked_since = state.blocked_since.unwrap_or(now);
        let blocked_for = now.saturating_duration_since(blocked_since);
        let log_interval_elapsed = state.last_log_at.is_none_or(|last| {
            now.saturating_duration_since(last) >= STRICT_DELIVERY_BLOCKED_LOG_INTERVAL
        });
        let should_log = blocked_for >= STRICT_REPLICATION_SLOW_STAGE && log_interval_elapsed;
        if should_log {
            state.last_log_at = Some(now);
        }
        (blocked_for, should_log)
    };
    if !should_log {
        return;
    }

    let blocker_kind = diagnostics
        .pending_blocker
        .as_ref()
        .map(|blocker| blocker.kind)
        .unwrap_or("none");
    let blocker_op_id_hi = diagnostics
        .pending_blocker
        .as_ref()
        .map(|blocker| blocker.op_id.0)
        .unwrap_or(0);
    let blocker_op_id_lo = diagnostics
        .pending_blocker
        .as_ref()
        .map(|blocker| blocker.op_id.1)
        .unwrap_or(0);
    let blocker_coord_node = diagnostics
        .pending_blocker
        .as_ref()
        .map(|blocker| blocker.coord_node)
        .unwrap_or(0);
    let blocker_ts = diagnostics
        .pending_blocker
        .as_ref()
        .map(|blocker| blocker.ts)
        .unwrap_or(0);
    let blocker_age_ms = diagnostics
        .pending_blocker
        .as_ref()
        .map(|blocker| blocker.age.as_millis())
        .unwrap_or(0);

    warn!(
        topic = %rt.topic,
        op_id_hi = diagnostics.next.op_id.0,
        op_id_lo = diagnostics.next.op_id.1,
        ts_final = diagnostics.next.ts_final,
        blocked_for_ms = blocked_for.as_millis(),
        buffered_for_ms = diagnostics.next.buffered_for.as_millis(),
        raw_high_water = diagnostics.raw_high_water,
        effective_high_water = diagnostics.effective_high_water,
        low_water_node = diagnostics.watermark.low_water_node,
        low_water_clock = diagnostics.watermark.low_water_clock,
        missing_clock_peers = diagnostics.watermark.missing_clock_peers,
        blocker_kind,
        blocker_op_id_hi,
        blocker_op_id_lo,
        blocker_coord_node,
        blocker_ts,
        blocker_age_ms,
        alive_count = diagnostics.alive_count,
        commit_buffer_len = diagnostics.commit_buffer_len,
        pending_local_proposals = diagnostics.pending_local_proposals,
        pending_remote_proposes = diagnostics.pending_remote_proposes,
        "strict delivery blocked"
    );
}

fn clear_delivery_blocked<R: StrictReplicable>(rt: &Arc<StrictRuntime<R>>) {
    let mut state = rt.delivery_blocked_log.lock();
    if state.key.is_some() {
        *state = DeliveryBlockedLogState::default();
    }
}

fn log_delivery_applied(
    topic: &str,
    buf: &BufferedOp,
    version: u64,
    buffered_for: Duration,
    apply_elapsed: Duration,
    local_proposal_elapsed: Option<Duration>,
) {
    if apply_elapsed >= STRICT_REPLICATION_SLOW_STAGE
        || local_proposal_elapsed.is_some_and(|elapsed| elapsed >= STRICT_REPLICATION_SLOW_STAGE)
    {
        warn!(
            topic = %topic,
            op_id_hi = buf.op_id.0,
            op_id_lo = buf.op_id.1,
            ts_final = buf.ts_final,
            version,
            buffered_for_ms = buffered_for.as_millis(),
            apply_elapsed_ms = apply_elapsed.as_millis(),
            local_proposal_elapsed_ms = ?local_proposal_elapsed.map(|elapsed| elapsed.as_millis()),
            "strict delivery applied slowly"
        );
    } else {
        debug!(
            topic = %topic,
            op_id_hi = buf.op_id.0,
            op_id_lo = buf.op_id.1,
            ts_final = buf.ts_final,
            version,
            buffered_for_ms = buffered_for.as_millis(),
            apply_elapsed_ms = apply_elapsed.as_millis(),
            local_proposal_elapsed_ms = ?local_proposal_elapsed.map(|elapsed| elapsed.as_millis()),
            "strict delivery applied"
        );
    }
}

fn run_gc_pass<R: StrictReplicable>(rt: &Arc<StrictRuntime<R>>) {
    // Repository capability can be lost through a local non-strict write
    // path. Poll it here as well as on protocol ingress so the LSA clamps
    // even while this topic is otherwise idle.
    let _ = rt.repository_v2_capable();
    let now = Instant::now();
    let propose_ttl = rt.cfg.propose_ttl();
    let expired = {
        let mut s = rt.state.lock();
        s.gc_stale_proposals(now, propose_ttl)
    };
    for expired in expired {
        if let Some(waker) = expired.waker {
            let _ = waker.send(Err(ReplicationError::ProposeTimeout(propose_ttl)));
        }
        if expired.needs_v2_resolution {
            let runtime = rt.clone();
            tokio::spawn(async move {
                runtime.defer_descriptorless_v2_commit(expired.op_id).await;
            });
        }
    }
    // Recovery-related GC: drop ancient pending Proposes (we're past the
    // window where any takeover would still be useful), drop committed
    // ts_final entries that have been delivered everywhere, and drop
    // hung in-progress recoveries that never reached quorum.
    {
        let alive: HashSet<NodeIdentifier> = rt
            .net
            .alive_members()
            .into_iter()
            .chain([rt.self_id])
            .collect();
        let mut s = rt.state.lock();
        let _dropped = s.gc_stale_pending_proposes(now, rt.cfg.pending_propose_ttl(), &alive);
        s.gc_committed_ts_final();
    }
    {
        let mut recoveries = rt.recoveries.lock();
        let recovery_ttl = rt.cfg.recovery_ttl();
        recoveries.retain(|_, rec| now.duration_since(rec.started_at) < recovery_ttl);
    }
    {
        let mut resolutions = rt.resolutions.lock();
        let resolution_ttl = rt.cfg.recovery_ttl();
        resolutions
            .retain(|_, resolution| now.duration_since(resolution.started_at) < resolution_ttl);
    }
    {
        let mut snapshots = rt.terminal_catchup_snapshots.lock();
        let snapshot_ttl = rt.cfg.pending_propose_ttl();
        snapshots.retain(|_, snapshot| now.duration_since(snapshot.last_used_at) < snapshot_ttl);
    }
    {
        let snapshot_ttl = rt.cfg.pending_propose_ttl();
        // Keep the same source-map-then-receiver-map lock order as snapshot
        // admission. The two maps share one aggregate retained-image cap.
        let mut transfers = rt.snapshot_transfers.lock();
        let mut receivers = rt.snapshot_receivers.lock();
        transfers.retain(|_, transfer| now.duration_since(transfer.last_used_at) < snapshot_ttl);
        receivers.retain(|_, transfer| now.duration_since(transfer.last_used_at) < snapshot_ttl);
    }
    if rt.terminal_resolution_ready() {
        let runtime = rt.clone();
        tokio::spawn(async move {
            runtime.resume_lost_v2_coordinator_resolutions().await;
            runtime.send_stale_resolution_hints().await;
        });
    }
}

fn spawn_clock_tick_loop<R: StrictReplicable>(rt: Arc<StrictRuntime<R>>) {
    let weak = {
        let rt = rt;
        Arc::downgrade(&rt)
    };
    tokio::spawn(async move {
        let Some(rt) = weak.upgrade() else {
            return;
        };
        loop {
            tokio::select! {
                _ = rt.shutdown.cancelled() => return,
                _ = rt.clock_tick_signal.notified() => {}
            }
            loop {
                // Every wake publishes at least one fresh local clock. The
                // local commit buffer may have drained already, but peers can
                // still be waiting for this node's clock to cross their
                // delivery high-water.
                emit_clock_tick(&rt).await;
                let mut last_interval = rt.current_clock_tick_interval();
                for _ in 1..CLOCK_TICK_ACTIVE_BURST_TICKS {
                    if !rt.clock_tick_needed() {
                        break;
                    }
                    if !sleep_or_shutdown(&rt, last_interval).await {
                        return;
                    }
                    emit_clock_tick(&rt).await;
                    last_interval = rt.current_clock_tick_interval();
                }
                if !rt.clock_tick_needed() {
                    break;
                }
                let cooldown = clock_tick_burst_cooldown(last_interval, &rt.cfg);
                tokio::select! {
                    _ = rt.shutdown.cancelled() => return,
                    _ = rt.clock_tick_signal.notified() => {},
                    _ = tokio::time::sleep(cooldown) => {},
                }
            }
        }
    });
}

impl<R: StrictReplicable> StrictRuntime<R> {
    fn current_clock_tick_interval(&self) -> Duration {
        // Recompute every time: LSDB RTT measurements drift with network
        // conditions, and clock bursts should follow current link latency.
        let samples = self.net.edge_rtt_snapshot();
        p95_clock_tick_interval(&samples, &self.cfg)
    }

    fn clock_tick_needed(&self) -> bool {
        let alive = delivery_members(self.net.as_ref(), self.self_id);
        let state = self.state.lock();
        clock_tick_needed_for_state(&state, self.self_id, &alive)
    }
}

fn log_buffered_commit(topic: &str, log: BufferedCommitLog) {
    debug!(
        topic = %topic,
        source = log.source,
        from = ?log.from,
        coord_node = ?log.coord_node,
        op_id_hi = log.op_id.0,
        op_id_lo = log.op_id.1,
        ts_final = log.ts_final,
        clock_now = log.clock_now,
        op_bytes = log.op_bytes,
        commit_buffer_len = log.commit_buffer_len,
        pending_local_proposals = log.pending_local_proposals,
        pending_remote_proposes = log.pending_remote_proposes,
        "strict commit buffered"
    );
}

fn log_accepted_proposal(topic: &str, op_id: OpId, accepted: &AcceptedProposal) {
    if accepted.elapsed >= STRICT_REPLICATION_SLOW_STAGE {
        warn!(
            topic = %topic,
            op_id_hi = op_id.0,
            op_id_lo = op_id.1,
            elapsed_ms = accepted.elapsed.as_millis(),
            ack_count = accepted.ack_count,
            target_count = accepted.target_count,
            fast_quorum = accepted.fast_quorum,
            ts_final = accepted.ts_final,
            clock_now = accepted.clock_now,
            op_bytes = accepted.op_bytes,
            commit_buffer_len = accepted.commit_buffer_len,
            pending_local_proposals = accepted.pending_local_proposals,
            pending_remote_proposes = accepted.pending_remote_proposes,
            "strict proposal accepted slowly"
        );
    } else {
        debug!(
            topic = %topic,
            op_id_hi = op_id.0,
            op_id_lo = op_id.1,
            elapsed_ms = accepted.elapsed.as_millis(),
            ack_count = accepted.ack_count,
            target_count = accepted.target_count,
            fast_quorum = accepted.fast_quorum,
            ts_final = accepted.ts_final,
            clock_now = accepted.clock_now,
            commit_buffer_len = accepted.commit_buffer_len,
            pending_local_proposals = accepted.pending_local_proposals,
            pending_remote_proposes = accepted.pending_remote_proposes,
            "strict proposal accepted"
        );
    }
}

fn clock_tick_needed_for_state(
    state: &StrictState,
    self_id: NodeIdentifier,
    alive: &[NodeIdentifier],
) -> bool {
    if !state.commit_buffer.is_empty() || state.earliest_uncommitted_proposal_ts().is_some() {
        return true;
    }
    alive
        .iter()
        .filter(|node| **node != self_id)
        .any(|node| !state.peer_clocks.contains_key(node))
}

async fn emit_clock_tick<R: StrictReplicable>(rt: &Arc<StrictRuntime<R>>) {
    if !rt.can_originate_v2() {
        return;
    }
    let clock = {
        let mut s = rt.state.lock();
        advance_clock_for_tick(&mut s, rt.self_id)
    };
    let body = StrictBody::ClockTick(StrictClockTick {
        src_node: rt.self_id as u32,
        src_clock: clock,
    });
    let dsts: Vec<_> = rt
        .net
        .alive_members()
        .into_iter()
        .filter(|node| *node != rt.self_id)
        .collect();
    if let Err(e) = rt
        .net
        .send_redundant_multicast(&dsts, &rt.topic, body)
        .await
    {
        trace!(error=%e, "clock tick broadcast failed");
    }
}

async fn sleep_or_shutdown<R: StrictReplicable>(
    rt: &Arc<StrictRuntime<R>>,
    duration: Duration,
) -> bool {
    tokio::select! {
        _ = rt.shutdown.cancelled() => false,
        _ = tokio::time::sleep(duration) => true,
    }
}

fn clock_tick_burst_cooldown(interval: Duration, cfg: &ReplicationConfig) -> Duration {
    interval
        .checked_mul(CLOCK_TICK_BURST_COOLDOWN_MULTIPLIER)
        .unwrap_or_else(|| cfg.max_clock_tick())
        .clamp(cfg.min_clock_tick(), cfg.max_clock_tick())
}

fn advance_clock_for_tick(state: &mut StrictState, self_id: NodeIdentifier) -> u64 {
    let clock = state.tick_clock();
    // Keep our own peer_clocks slot in sync.
    state.peer_clocks.insert(self_id, clock);
    clock
}

/// Periodic catchup-bootstrap retry loop. Runs while a history election is
/// pending, and also keeps an idle watch on alive-set expansion so partition
/// heals that do not emit `Joined`/`Restarted` still trigger election.
fn spawn_bootstrap_retry_loop<R: StrictReplicable>(rt: Arc<StrictRuntime<R>>) {
    let weak = Arc::downgrade(&rt);
    drop(rt);
    tokio::spawn(async move {
        let Some(rt) = weak.upgrade() else {
            return;
        };
        let interval = rt.cfg.strict_bootstrap_retry_interval();
        loop {
            let peers = bootstrap_reachable_peers(rt.net.as_ref(), rt.self_id);
            let (should_probe, snapshot_request) = {
                let mut state = rt.state.lock();
                state.observe_history_alive_peers(peers.iter().copied());
                let snapshot_request =
                    state.reconcile_history_election_reachability(peers.iter().copied());
                if state.history_election_timed_out(Instant::now(), interval.saturating_mul(5)) {
                    // A probe may be accepted by the transport while its
                    // response is lost on a transient route. Re-arming the
                    // request in the same loop would keep every node in an
                    // election forever. Close this attempt and let normal
                    // anti-entropy (or a later membership/divergence event)
                    // schedule another one.
                    state.finish_history_election();
                }
                (state.can_start_history_election(), snapshot_request)
            };
            if let Some(request) = snapshot_request {
                if let Err(error) = rt.send_history_snapshot_request(request).await {
                    debug!(
                        dst = request.peer(),
                        error = %error,
                        "strict catchup reconciled snapshot request failed"
                    );
                    rt.state.lock().request_history_election();
                }
            }
            if should_probe {
                rt.try_bootstrap_catchup().await;
            }
            tokio::select! {
                _ = rt.shutdown.cancelled() => return,
                _ = tokio::time::sleep(interval) => {}
            }
        }
    });
}

fn spawn_steady_state_catchup_loop<R: StrictReplicable>(rt: Arc<StrictRuntime<R>>) {
    let weak = Arc::downgrade(&rt);
    drop(rt);
    tokio::spawn(async move {
        let Some(rt) = weak.upgrade() else {
            return;
        };
        let mut terminal_repair_ticker = tokio::time::interval(Duration::from_millis(500));
        terminal_repair_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut steady_state_ticker =
            tokio::time::interval(rt.cfg.strict_steady_state_catchup_interval());
        steady_state_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = rt.shutdown.cancelled() => return,
                _ = terminal_repair_ticker.tick() => {
                    // A durable v2 fence that missed its terminal decision,
                    // or a delivery watermark held behind one peer's clock,
                    // cannot wait for the much slower ordinary anti-entropy
                    // cadence. This probe is metadata-only and safe to run
                    // independently of history catch-up.
                    let _ = request_terminal_repair_probe(&rt).await;
                }
                _ = steady_state_ticker.tick() => {
                    request_steady_state_catchup(&rt).await;
                }
            }
        }
    });
}

/// Request only terminal-fence state needed to unblock strict delivery.
///
/// This intentionally runs while a history election is requested but still
/// idle: a durable v2 `PendingPropose` itself prevents that election from
/// starting, so waiting for ordinary catchup would deadlock the fence. The
/// request is metadata-only after terminal pagination; it never installs a
/// history snapshot or ordinary operation through this escape hatch.
///
/// The same directed probe also repairs a strict delivery watermark blocked
/// on one peer's clock. The responder sends a fresh authenticated unicast
/// tick for a valid v2 probe, avoiding broad tick echoes.
async fn request_terminal_repair_probe<R: StrictReplicable>(rt: &Arc<StrictRuntime<R>>) -> bool {
    if !rt.can_originate_v2() {
        return false;
    }
    let alive = delivery_members(rt.net.as_ref(), rt.self_id);
    // A pending fence may belong to the preceding round: waiting for its
    // full caller TTL can race the next proposal's own deadline. Give the
    // deterministic resolver the second half of that TTL to complete while
    // retaining a grace period for an in-flight normal phase-two exchange.
    let stale_after = rt
        .cfg
        .propose_ttl()
        .checked_div(2)
        .unwrap_or_else(|| rt.cfg.propose_ttl());
    let (candidates, preferred_peer, stale_pending): (
        Vec<(NodeIdentifier, Option<u64>)>,
        Option<NodeIdentifier>,
        Option<OpId>,
    ) = {
        let state = rt.state.lock();
        if state.history_election_active() {
            return false;
        }
        let pending = state
            .pending_proposes
            .iter()
            .filter(|(op_id, pending)| {
                pending.protocol_version == STRICT_PROTOCOL_VERSION_V2
                    && pending.v2_descriptor_durable
                    && pending.frozen_targets.is_some()
                    && !state.terminal_decisions.contains_key(op_id)
            })
            .min_by_key(|(_, pending)| pending.seen_at)
            .map(|(_, pending)| {
                (
                    pending.coord_node,
                    pending
                        .frozen_targets
                        .clone()
                        .expect("v2 pending repair requires a frozen descriptor"),
                )
            });
        let stale_pending = state
            .pending_proposes
            .iter()
            .filter(|(op_id, pending)| {
                pending.protocol_version == STRICT_PROTOCOL_VERSION_V2
                    && pending.v2_descriptor_durable
                    && pending.frozen_targets.is_some()
                    && !state.terminal_decisions.contains_key(op_id)
                    && pending.seen_at.elapsed() >= stale_after
            })
            .min_by_key(|(_, pending)| pending.seen_at)
            .map(|(op_id, _)| *op_id);
        if let Some((coord_node, frozen_targets)) = pending {
            (
                frozen_targets
                    .into_iter()
                    .filter(|target| target.node() != rt.self_id)
                    .map(|target| (target.node(), Some(target.boot_epoch())))
                    .collect::<Vec<_>>(),
                Some(coord_node),
                stale_pending,
            )
        } else {
            let watermark = delivery_watermark(&state, rt.self_id, &alive);
            let pending_barrier = state
                .earliest_uncommitted_proposal_ts()
                .map(|ts| ts.saturating_sub(1));
            let effective_high_water = pending_barrier
                .map_or(watermark.high_water.saturating_sub(1), |barrier| {
                    watermark.high_water.saturating_sub(1).min(barrier)
                });
            (
                state
                    .commit_buffer
                    .iter()
                    .next()
                    .filter(|(_, buffered)| buffered.ts_final > effective_high_water)
                    .filter(|_| watermark.low_water_node != rt.self_id)
                    .map(|_| vec![(watermark.low_water_node, None)])
                    .unwrap_or_default(),
                None,
                stale_pending,
            )
        }
    };

    if let Some(op_id) = stale_pending {
        // A coordinator's caller deadline is shorter than the pending-fence
        // retention window. Re-drive the deterministic terminal resolver
        // after the bounded grace period instead of waiting for the slower
        // GC/anti-entropy cadence. The resolver's durable ballot and frozen
        // quorum still decide whether this becomes a commit or abort.
        rt.defer_descriptorless_v2_commit(op_id).await;
    }

    let mut peers: Vec<_> = candidates
        .into_iter()
        .filter(|(node, frozen_epoch)| {
            // A watermark repair may target any currently live peer; it does
            // not assert a frozen-incarnation identity. A pending-proposal
            // repair does, so it never queries a replacement incarnation.
            *node != rt.self_id
                && frozen_epoch.is_none_or(|epoch| rt.net.member_boot_epoch(*node) == Some(epoch))
                && rt.net.has_route(*node, ServiceLevel::Reliable)
        })
        .map(|(node, _)| node)
        .collect();
    peers.sort_unstable_by_key(|node| (Some(*node) != preferred_peer, *node));
    peers.dedup();
    if peers.is_empty() {
        return false;
    }
    let cursor = rt.terminal_repair_cursor.fetch_add(1, Ordering::Relaxed) as usize;
    let dst = peers[cursor % peers.len()];
    if rt.net.peer_strict_replication_protocol_version(dst) < STRICT_PROTOCOL_VERSION_V2 {
        return false;
    }
    let req = StrictCatchupReq {
        src_node: rt.self_id as u32,
        since_version: 0,
        chunk_token: 0,
        force_snapshot: false,
        history_probe_only: true,
        terminal_state_cursor: 0,
        terminal_decision_generation: 0,
        snapshot_transfer_id: 0,
        snapshot_chunk_cursor: 0,
    };
    metrics::record_catchup_request(CatchupMode::Strict);
    match rt
        .net
        .send_redundant_unicast(dst, &rt.topic, StrictBody::CatchupReq(req))
        .await
    {
        Ok(()) => true,
        Err(error) => {
            trace!(%error, dst, "strict terminal repair probe send failed");
            false
        }
    }
}

async fn request_steady_state_catchup<R: StrictReplicable>(rt: &Arc<StrictRuntime<R>>) {
    if !rt.can_originate_v2() {
        return;
    }
    if rt.state.lock().history_election_blocks_steady_state() {
        return;
    }
    let alive = rt.net.alive_members();
    let mut peers: Vec<NodeIdentifier> = alive
        .into_iter()
        .filter(|node| *node != rt.self_id && rt.net.has_route(*node, ServiceLevel::Reliable))
        .collect();
    if peers.is_empty() {
        return;
    }
    peers.sort_unstable();
    let cursor = rt.steady_catchup_cursor.fetch_add(1, Ordering::Relaxed) as usize;
    let dst = peers[cursor % peers.len()];
    let req = StrictCatchupReq {
        src_node: rt.self_id as u32,
        since_version: rt.repo.current_version(),
        chunk_token: 0,
        force_snapshot: false,
        history_probe_only: false,
        terminal_state_cursor: super::catchup::TERMINAL_STATE_CURSOR_SKIP,
        terminal_decision_generation: rt.remembered_terminal_decision_generation(dst),
        snapshot_transfer_id: 0,
        snapshot_chunk_cursor: 0,
    };
    metrics::record_catchup_request(CatchupMode::Strict);
    let _ = rt
        .net
        .send_unicast(dst, &rt.topic, StrictBody::CatchupReq(req))
        .await;
}

// ---------- Helpers ----------

#[inline]
pub(crate) fn node_from_u32(v: u32) -> Option<NodeIdentifier> {
    if v <= u16::MAX as u32 {
        Some(v as NodeIdentifier)
    } else {
        None
    }
}

#[inline]
fn node_from_op_id(op_id: OpId) -> Option<NodeIdentifier> {
    node_from_u32((op_id.0 >> 48) as u32)
}

#[inline]
fn op_id_boot_epoch(op_id: OpId) -> u64 {
    op_id.0 & OP_ID_BOOT_EPOCH_MASK
}

pub(super) fn frozen_targets_to_wire(targets: &[FrozenTarget]) -> Vec<StrictFrozenTarget> {
    targets
        .iter()
        .map(|target| StrictFrozenTarget {
            node: target.node() as u32,
            boot_epoch: target.boot_epoch(),
        })
        .collect()
}

fn frozen_targets_from_wire(
    targets: &[StrictFrozenTarget],
    op_id: OpId,
    coord: NodeIdentifier,
) -> Result<Vec<FrozenTarget>, ()> {
    let targets: Vec<_> = targets
        .iter()
        .map(|target| {
            node_from_u32(target.node)
                .map(|node| FrozenTarget::new(node, target.boot_epoch))
                .ok_or(())
        })
        .collect::<Result<_, _>>()?;
    if !FrozenTarget::is_valid_descriptor(&targets) {
        return Err(());
    }
    let Some(coord_target) = FrozenTarget::find_in_canonical(&targets, coord) else {
        return Err(());
    };
    if coord_target.boot_epoch() & OP_ID_BOOT_EPOCH_MASK != op_id_boot_epoch(op_id) {
        return Err(());
    }
    Ok(targets)
}

pub(super) fn frozen_targets_from_epochs(
    target_epochs: &HashMap<NodeIdentifier, u64>,
) -> Vec<FrozenTarget> {
    let mut targets: Vec<_> = target_epochs
        .iter()
        .map(|(node, boot_epoch)| FrozenTarget::new(*node, *boot_epoch))
        .collect();
    targets.sort_by_key(FrozenTarget::node);
    debug_assert!(FrozenTarget::is_valid_descriptor(&targets));
    targets
}

/// Reconcile the durable terminal record before answering a prepare or
/// continuing after restart. The journal is the source of truth for promises
/// and accepted values, so this closes the accept/prepare interleaving where
/// an accept reached disk just before a higher prepare was recorded.
fn hydrate_terminal_journal_record(
    state: &mut StrictState,
    op_id: OpId,
    record: &TerminalJournalRecord,
    hydrate_v2_pending: bool,
) {
    if record.promise_ballot() > state.resolution_promise(op_id) {
        state
            .resolution_promises
            .insert(op_id, record.promise_ballot());
    }
    if hydrate_v2_pending
        && record.terminal_decision().is_none()
        && !state.committed_ids.contains(&op_id)
        && !state.pending_proposes.contains_key(&op_id)
    {
        if let (Some(frozen_targets), Some(pending), Some(coord)) = (
            record.frozen_targets(),
            record.pending_proposal(),
            node_from_op_id(op_id),
        ) {
            state.record_pending_propose_with_descriptor(
                op_id,
                coord,
                pending.op_msgpack_bytes(),
                pending.ts_local(),
                Instant::now() - Duration::from_secs(1),
                STRICT_PROTOCOL_VERSION_V2,
                Some(frozen_targets.to_vec()),
                true,
            );
        }
    }
    if let Some(accepted) = record.accepted_commit() {
        if accepted.ts_final() > state.clock {
            state.clock = accepted.ts_final();
        }
        state.set_accepted_value(
            op_id,
            AcceptedValue {
                ballot: accepted.ballot(),
                ts_final: accepted.ts_final(),
                op_msgpack: accepted.op_msgpack_bytes(),
            },
        );
    }
    if let Some(decision) = record.terminal_decision() {
        let decision = match decision {
            JournalTerminalDecision::Commit { candidate } => {
                if candidate.ts_final() > state.clock {
                    state.clock = candidate.ts_final();
                }
                TerminalDecision::Commit(AcceptedValue {
                    ballot: candidate.ballot(),
                    ts_final: candidate.ts_final(),
                    op_msgpack: candidate.op_msgpack_bytes(),
                })
            }
            JournalTerminalDecision::Abort { ballot } => {
                TerminalDecision::Abort { ballot: *ballot }
            }
        };
        let identity = match (record.frozen_targets(), record.terminal_resolver()) {
            (Some(frozen_targets), Some(resolver)) => Some(TerminalDecisionIdentity {
                resolver,
                frozen_targets: frozen_targets.to_vec(),
            }),
            _ => None,
        };
        state.set_terminal_decision(op_id, decision, identity);
    }
}

/// Queue a terminal commit restored from durable state for normal ordered
/// delivery. The journal intentionally has no "delivered" marker: recording
/// one after repository application would reintroduce the crash window this
/// protocol closes. Replaying through `StrictReplicable::apply_committed_once`
/// is safe whether the repository write completed before the crash or not.
fn enqueue_terminal_commit_for_delivery(
    state: &mut StrictState,
    op_id: OpId,
    record: &TerminalJournalRecord,
) -> bool {
    let Some(JournalTerminalDecision::Commit { candidate }) = record.terminal_decision() else {
        return false;
    };
    if state.mark_committed(op_id, candidate.ts_final()) {
        state.buffer_commit(op_id, candidate.ts_final(), candidate.op_msgpack_bytes());
        true
    } else {
        false
    }
}

fn resolution_observed(state: &StrictState, op_id: OpId) -> ResolutionObserved {
    if let Some(decision) = state.terminal_decisions.get(&op_id) {
        return ResolutionObserved::Terminal {
            decision: decision.clone(),
            identity: state.terminal_decision_identities.get(&op_id).cloned(),
        };
    }
    if let Some(accepted) = state.accepted_values.get(&op_id) {
        return ResolutionObserved::Accepted(accepted.clone());
    }
    if let Some(pending) = state.pending_proposes.get(&op_id) {
        return ResolutionObserved::Pending {
            ts_local: pending.ts_local,
            op_msgpack: pending.op_msgpack.clone(),
            protocol_version: pending.protocol_version,
        };
    }
    ResolutionObserved::None
}

fn resolution_observed_to_wire(
    observed: ResolutionObserved,
    op_id: OpId,
    coord: NodeIdentifier,
) -> Option<StrictResolutionObserved> {
    match observed {
        ResolutionObserved::None => None,
        ResolutionObserved::Terminal {
            decision: TerminalDecision::Commit(value),
            identity,
        } => Some(StrictResolutionObserved::Terminal(StrictTerminalState {
            coord_node: coord as u32,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            ballot: value.ballot,
            outcome: Some(StrictTerminalOutcome::Commit(StrictDecisionCommit {
                ts_final: value.ts_final,
                op_msgpack: value.op_msgpack,
            })),
            resolver_node: identity
                .as_ref()
                .map(|identity| identity.resolver.node() as u32)
                .unwrap_or_default(),
            resolver_boot_epoch: identity
                .as_ref()
                .map(|identity| identity.resolver.boot_epoch())
                .unwrap_or_default(),
            frozen_targets: identity
                .as_ref()
                .map(|identity| frozen_targets_to_wire(&identity.frozen_targets))
                .unwrap_or_default(),
        })),
        ResolutionObserved::Terminal {
            decision: TerminalDecision::Abort { ballot },
            identity,
        } => Some(StrictResolutionObserved::Terminal(StrictTerminalState {
            coord_node: coord as u32,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            ballot,
            outcome: Some(StrictTerminalOutcome::Abort(StrictDecisionAbort {})),
            resolver_node: identity
                .as_ref()
                .map(|identity| identity.resolver.node() as u32)
                .unwrap_or_default(),
            resolver_boot_epoch: identity
                .as_ref()
                .map(|identity| identity.resolver.boot_epoch())
                .unwrap_or_default(),
            frozen_targets: identity
                .as_ref()
                .map(|identity| frozen_targets_to_wire(&identity.frozen_targets))
                .unwrap_or_default(),
        })),
        ResolutionObserved::Accepted(value) => {
            Some(StrictResolutionObserved::Accepted(StrictAcceptedValue {
                ballot: value.ballot,
                ts_final: value.ts_final,
                op_msgpack: value.op_msgpack,
            }))
        }
        ResolutionObserved::Pending {
            ts_local,
            op_msgpack,
            protocol_version,
        } => Some(StrictResolutionObserved::Pending(StrictPendingValue {
            ts_local,
            op_msgpack,
            protocol_version,
        })),
    }
}

fn resolution_observed_from_wire(
    observed: Option<StrictResolutionObserved>,
    expected_op_id: OpId,
    expected_coord: NodeIdentifier,
) -> Result<ResolutionObserved, ()> {
    match observed {
        Some(StrictResolutionObserved::Terminal(terminal)) => {
            if terminal.coord_node != u32::from(expected_coord)
                || (terminal.op_id_hi, terminal.op_id_lo) != expected_op_id
            {
                return Err(());
            }
            let identity = terminal_identity_from_wire(
                terminal.resolver_node,
                terminal.resolver_boot_epoch,
                &terminal.frozen_targets,
                terminal.ballot,
                expected_op_id,
                expected_coord,
            )?;
            match terminal.outcome {
                Some(StrictTerminalOutcome::Commit(commit)) => Ok(ResolutionObserved::Terminal {
                    decision: TerminalDecision::Commit(AcceptedValue {
                        ballot: terminal.ballot,
                        ts_final: commit.ts_final,
                        op_msgpack: commit.op_msgpack,
                    }),
                    identity,
                }),
                Some(StrictTerminalOutcome::Abort(_)) => Ok(ResolutionObserved::Terminal {
                    decision: TerminalDecision::Abort {
                        ballot: terminal.ballot,
                    },
                    identity,
                }),
                None => Ok(ResolutionObserved::None),
            }
        }
        Some(StrictResolutionObserved::Accepted(accepted)) => {
            Ok(ResolutionObserved::Accepted(AcceptedValue {
                ballot: accepted.ballot,
                ts_final: accepted.ts_final,
                op_msgpack: accepted.op_msgpack,
            }))
        }
        Some(StrictResolutionObserved::Pending(pending)) => Ok(ResolutionObserved::Pending {
            ts_local: pending.ts_local,
            op_msgpack: pending.op_msgpack,
            protocol_version: pending.protocol_version,
        }),
        None => Ok(ResolutionObserved::None),
    }
}

pub(super) fn terminal_identity_from_wire(
    resolver_node: u32,
    resolver_boot_epoch: u64,
    frozen_targets: &[StrictFrozenTarget],
    ballot: u64,
    op_id: OpId,
    coord: NodeIdentifier,
) -> Result<Option<TerminalDecisionIdentity>, ()> {
    if frozen_targets.is_empty() {
        return (resolver_node == 0 && resolver_boot_epoch == 0)
            .then_some(None)
            .ok_or(());
    }
    let resolver = node_from_u32(resolver_node).ok_or(())?;
    if ballot == NORMAL_ACCEPT_BALLOT && resolver != coord {
        return Err(());
    }
    let frozen_targets = frozen_targets_from_wire(frozen_targets, op_id, coord)?;
    let target = FrozenTarget::find_in_canonical(&frozen_targets, resolver).ok_or(())?;
    if target.boot_epoch() != resolver_boot_epoch {
        return Err(());
    }
    Ok(Some(TerminalDecisionIdentity {
        resolver: TerminalResolver::new(resolver, resolver_boot_epoch),
        frozen_targets,
    }))
}

fn choose_resolution_decision<'a>(
    _coord: NodeIdentifier,
    ballot: u64,
    observations: impl Iterator<Item = &'a ResolutionObserved>,
) -> ResolutionDecision {
    let mut committed: Option<(AcceptedValue, Option<TerminalDecisionIdentity>)> = None;
    let mut aborted: Option<(u64, Option<TerminalDecisionIdentity>)> = None;
    let mut accepted: Option<AcceptedValue> = None;
    let mut pending: Option<(u64, Bytes, u32)> = None;

    for observed in observations {
        match observed {
            ResolutionObserved::Terminal {
                decision: TerminalDecision::Commit(value),
                identity,
            } => {
                if committed
                    .as_ref()
                    .is_none_or(|(current, _)| value.ballot > current.ballot)
                {
                    committed = Some((value.clone(), identity.clone()));
                }
            }
            ResolutionObserved::Terminal {
                decision: TerminalDecision::Abort { ballot },
                identity,
            } => {
                if aborted.as_ref().is_none_or(|(current, _)| ballot > current) {
                    aborted = Some((*ballot, identity.clone()));
                }
            }
            ResolutionObserved::Accepted(value) => {
                if accepted
                    .as_ref()
                    .is_none_or(|current| value.ballot > current.ballot)
                {
                    accepted = Some(value.clone());
                }
            }
            ResolutionObserved::Pending {
                ts_local,
                op_msgpack,
                protocol_version,
            } => {
                if pending.as_ref().is_none_or(|current| *ts_local > current.0) {
                    pending = Some((*ts_local, op_msgpack.clone(), *protocol_version));
                }
            }
            ResolutionObserved::None => {}
        }
    }

    if let Some((value, identity)) = committed {
        return ResolutionDecision::Existing {
            decision: TerminalDecision::Commit(value),
            identity,
        };
    }
    if let Some((ballot, identity)) = aborted {
        return ResolutionDecision::Existing {
            decision: TerminalDecision::Abort { ballot },
            identity,
        };
    }
    if let Some(value) = accepted {
        return ResolutionDecision::Fresh(TerminalDecision::Commit(AcceptedValue {
            ballot,
            ts_final: value.ts_final,
            op_msgpack: value.op_msgpack,
        }));
    }
    if let Some((ts_final, op_msgpack, _protocol_version)) = pending {
        // A terminal resolver has already persisted a fresh quorum ballot.
        // With no stronger accepted/terminal value to preserve, choosing the
        // prepared request is deterministic and makes the v1 liveness repair
        // automatic rather than dependent on a local rollout toggle.
        return ResolutionDecision::Fresh(TerminalDecision::Commit(AcceptedValue {
            ballot,
            ts_final,
            op_msgpack,
        }));
    }
    ResolutionDecision::Fresh(TerminalDecision::Abort { ballot })
}

// ---------- Unit tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replications::test_support::{CapturedFrame, CountingStrictRepo, MockNet};

    fn v1_runtime(
        cfg: ReplicationConfig,
    ) -> (
        Arc<StrictRuntime<CountingStrictRepo>>,
        Arc<MockNet>,
        Arc<CountingStrictRepo>,
    ) {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 1);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo.clone(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(cfg),
        );
        rt.finish_history_election_for_test();
        (rt, net, repo)
    }

    #[test]
    fn v2_prerequisites_require_the_protocol_ceiling_and_minimum_response_budget() {
        let encoded_len = 1024;
        let ceiling = repl_proto::STRICT_V2_MAX_REPLICATION_PAYLOAD_BYTES;

        assert!(!v2_prerequisite_payload_fits(
            ceiling - 1,
            ceiling,
            encoded_len
        ));
        assert!(!v2_prerequisite_payload_fits(
            ceiling,
            encoded_len - 1,
            encoded_len
        ));
        assert!(v2_prerequisite_payload_fits(ceiling, ceiling, encoded_len));
    }

    #[test]
    fn v2_prerequisites_size_the_actual_topic() {
        let body = minimum_v2_catchup_response_body(1);
        let auth = repl_proto::strict_origin_auth_budget_template();
        let short_len = repl_proto::strict_encoded_len_with_origin_auth("a", &body, &auth);
        let long_topic = "x".repeat(2048);
        let long_len = repl_proto::strict_encoded_len_with_origin_auth(&long_topic, &body, &auth);
        let ceiling = repl_proto::STRICT_V2_MAX_REPLICATION_PAYLOAD_BYTES;

        assert!(long_len > short_len);
        assert!(v2_prerequisite_payload_fits(ceiling, short_len, short_len));
        assert!(!v2_prerequisite_payload_fits(ceiling, short_len, long_len));
    }

    struct BlockingStrictRepo {
        version: std::sync::atomic::AtomicU64,
        delivery_started: tokio::sync::Notify,
        release_delivery: tokio::sync::Notify,
    }

    impl BlockingStrictRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                version: std::sync::atomic::AtomicU64::new(0),
                delivery_started: tokio::sync::Notify::new(),
                release_delivery: tokio::sync::Notify::new(),
            })
        }
    }

    #[async_trait::async_trait]
    impl StrictReplicable for BlockingStrictRepo {
        type Op = u64;

        fn strict_replication_protocol_version(&self) -> u32 {
            STRICT_PROTOCOL_VERSION_V2
        }

        fn current_version(&self) -> u64 {
            self.version.load(Ordering::Acquire)
        }

        fn snapshot(
            &self,
        ) -> Result<(u64, Bytes), crate::replications::strict::StrictSnapshotError> {
            Ok((self.current_version(), Bytes::new()))
        }

        fn log_since(
            &self,
            _since: u64,
        ) -> crate::replications::strict::LogSlice<
            crate::replications::strict::StrictLogEntry<Self::Op>,
        > {
            crate::replications::strict::LogSlice::Available(Vec::new())
        }

        async fn apply_committed(&self, version: u64, _op: Self::Op) {
            self.delivery_started.notify_one();
            self.release_delivery.notified().await;
            self.version.store(version, Ordering::Release);
        }

        async fn install_snapshot(
            &self,
            version: u64,
            _snapshot: Bytes,
        ) -> Result<(), crate::replications::strict::StrictSnapshotError> {
            self.version.store(version, Ordering::Release);
            Ok(())
        }
    }

    fn v2_frozen_targets() -> Vec<FrozenTarget> {
        vec![FrozenTarget::new(1, 1), FrozenTarget::new(2, 1)]
    }

    fn v2_frozen_targets_wire() -> Vec<StrictFrozenTarget> {
        frozen_targets_to_wire(&v2_frozen_targets())
    }

    async fn resolve_stale_with_remote_ack(
        rt: &Arc<StrictRuntime<CountingStrictRepo>>,
        net: &Arc<MockNet>,
        op_id: OpId,
        coord: NodeIdentifier,
        observed: Option<StrictResolutionObserved>,
    ) {
        net.drain_captures();
        rt.send_stale_resolution_hints().await;
        let prepare = net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictMulticast {
                    body: StrictBody::ResolutionPrepare(prepare),
                    ..
                } => Some(prepare),
                _ => None,
            })
            .expect("stale pending proposal must start terminal resolution");
        rt.recv_resolution_ack_with_origin_epoch(
            2,
            1,
            StrictResolutionAck {
                ack_node: 2,
                ballot: prepare.ballot,
                coord_node: coord as u32,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                promised: true,
                observed,
                src_clock: 20,
                ack_boot_epoch: 1,
            },
        )
        .await;
    }

    fn strict_probe_resp(
        node: NodeIdentifier,
        version: u64,
        freshness: i64,
        runtime_started_at: u64,
    ) -> StrictCatchupResp {
        StrictCatchupResp {
            snapshot_version: 0,
            snapshot_msgpack: Bytes::new(),
            ops: Vec::new(),
            terminal_states: Vec::new(),
            next_terminal_state_cursor: 0,
            terminal_states_has_more: false,
            terminal_sync_only: false,
            request_force_snapshot: false,
            request_history_probe_only: false,
            terminal_decision_generation: 0,
            snapshot_transfer_id: 0,
            snapshot_chunk_cursor: 0,
            snapshot_next_cursor: 0,
            snapshot_total_bytes: 0,
            snapshot_sha256: Bytes::new(),
            snapshot_has_more: false,
            snapshot_transfer_rejected: false,
            has_more: false,
            next_chunk_token: 0,
            too_old_use_snapshot: false,
            history_version: version,
            history_freshness: freshness,
            runtime_started_at,
            history_node: u32::from(node),
        }
    }

    fn strict_snapshot_resp(
        rank: HistoryRank,
        snapshot_version: u64,
        snapshot: Bytes,
    ) -> StrictCatchupResp {
        StrictCatchupResp {
            snapshot_version,
            snapshot_msgpack: snapshot,
            ops: Vec::new(),
            terminal_states: Vec::new(),
            next_terminal_state_cursor: 0,
            terminal_states_has_more: false,
            terminal_sync_only: false,
            request_force_snapshot: false,
            request_history_probe_only: false,
            terminal_decision_generation: 0,
            snapshot_transfer_id: 0,
            snapshot_chunk_cursor: 0,
            snapshot_next_cursor: 0,
            snapshot_total_bytes: 0,
            snapshot_sha256: Bytes::new(),
            snapshot_has_more: false,
            snapshot_transfer_rejected: false,
            has_more: false,
            next_chunk_token: 0,
            too_old_use_snapshot: true,
            history_version: rank.version,
            history_freshness: rank.freshness,
            runtime_started_at: rank.runtime_started_at,
            history_node: u32::from(rank.node_id),
        }
    }

    #[test]
    fn p95_clock_tick_returns_fallback_when_empty() {
        let cfg = ReplicationConfig::default();
        assert_eq!(
            p95_clock_tick_interval(&[], &cfg),
            cfg.fallback_clock_tick()
        );
    }

    #[test]
    fn p95_clock_tick_picks_correct_index_via_nearest_rank() {
        let cfg = ReplicationConfig::default();
        // n=20, p=0.95: idx_one_based = ceil(19.0) = 19, idx = 18.
        // Samples 50..=1000ms by 50: samples[18] = 950ms.
        let samples: Vec<Duration> = (1..=20).map(|i| Duration::from_millis(i * 50)).collect();
        let p95 = p95_clock_tick_interval(&samples, &cfg);
        assert_eq!(p95, Duration::from_millis(950));
        // n=100, samples 1..=100ms: idx_one_based = 95, idx = 94.
        // samples[94] = 95ms, clamped up to min_clock_tick().
        let samples: Vec<Duration> = (1..=100).map(Duration::from_millis).collect();
        let p95 = p95_clock_tick_interval(&samples, &cfg);
        assert_eq!(p95, cfg.min_clock_tick());
    }

    #[test]
    fn p95_clock_tick_clamps_to_min() {
        let cfg = ReplicationConfig::default();
        // All samples below min_clock_tick() ⇒ result clamped up.
        let samples = vec![Duration::from_millis(5); 10];
        assert_eq!(
            p95_clock_tick_interval(&samples, &cfg),
            cfg.min_clock_tick()
        );
    }

    #[test]
    fn p95_clock_tick_clamps_to_max() {
        let cfg = ReplicationConfig::default();
        // All samples above max_clock_tick() ⇒ result clamped down.
        let samples = vec![Duration::from_secs(30); 10];
        assert_eq!(
            p95_clock_tick_interval(&samples, &cfg),
            cfg.max_clock_tick()
        );
    }

    #[test]
    fn p95_clock_tick_ignores_single_outlier_above_p95_index() {
        let cfg = ReplicationConfig::default();
        // 19 fast edges + 1 slow outlier. n=20, idx = 18.
        // After sort, samples[18] is the last fast edge, samples[19] is the
        // outlier. The outlier sits at p100, NOT p95 — so p95 == 150ms.
        let mut samples: Vec<Duration> = vec![Duration::from_millis(150); 19];
        samples.push(Duration::from_secs(2));
        let p95 = p95_clock_tick_interval(&samples, &cfg);
        assert_eq!(p95, Duration::from_millis(150));

        // 39 fast edges + 1 outlier (n=40). idx = 37, still in the fast block.
        let mut samples: Vec<Duration> = vec![Duration::from_millis(150); 39];
        samples.push(Duration::from_secs(2));
        let p95 = p95_clock_tick_interval(&samples, &cfg);
        assert_eq!(p95, Duration::from_millis(150));
    }

    #[test]
    fn fast_quorum_size_matches_paper() {
        // ceil(3n/4)
        assert_eq!(fast_quorum_size(0), 0);
        assert_eq!(fast_quorum_size(1), 1);
        assert_eq!(fast_quorum_size(2), 2);
        assert_eq!(fast_quorum_size(3), 3);
        assert_eq!(fast_quorum_size(4), 3);
        assert_eq!(fast_quorum_size(5), 4);
        assert_eq!(fast_quorum_size(8), 6);
        assert_eq!(fast_quorum_size(9), 7);
    }

    #[test]
    fn make_op_id_unique_per_node_and_counter() {
        let a = make_op_id(7, 100, 1);
        let b = make_op_id(7, 100, 2);
        let c = make_op_id(8, 100, 1);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.0, c.0 ^ ((7u64 ^ 8u64) << 48));
    }

    #[test]
    fn clock_advances_on_propose_receive() {
        let mut s = StrictState::new();
        s.clock = 5;
        let new_clock = s.advance_clock(10);
        assert_eq!(new_clock, 11);
        assert_eq!(s.clock, 11);
        // If peer's clock is lower, our clock just ticks.
        let new_clock = s.advance_clock(3);
        assert_eq!(new_clock, 12);
    }

    #[test]
    fn clock_tick_advances_local_clock_and_peer_slot() {
        let mut s = StrictState::new();
        s.clock = 7;
        s.peer_clocks.insert(10, 7);

        let tick = advance_clock_for_tick(&mut s, 10);

        assert_eq!(tick, 8);
        assert_eq!(s.clock, 8);
        assert_eq!(s.peer_clocks[&10], 8);
    }

    #[test]
    fn clock_tick_not_needed_when_idle_and_alive_peers_observed() {
        let mut s = StrictState::new();
        s.finish_history_election();
        s.peer_clocks.insert(20, 3);
        s.peer_clocks.insert(30, 5);

        assert!(!clock_tick_needed_for_state(&s, 10, &[10, 20, 30]));
    }

    #[test]
    fn clock_tick_needed_for_pending_commit_buffer() {
        let mut s = StrictState::new();
        s.finish_history_election();
        s.peer_clocks.insert(20, 3);
        s.buffer_commit((1, 1), 5, Bytes::new());

        assert!(clock_tick_needed_for_state(&s, 10, &[10, 20]));
    }

    #[test]
    fn clock_tick_needed_for_pending_propose() {
        let mut s = StrictState::new();
        s.finish_history_election();
        s.peer_clocks.insert(20, 3);
        s.record_pending_propose((1, 1), 20, Bytes::new(), 5, Instant::now());

        assert!(clock_tick_needed_for_state(&s, 10, &[10, 20]));
    }

    #[test]
    fn clock_tick_needed_for_unobserved_alive_peer() {
        let mut s = StrictState::new();
        s.finish_history_election();
        s.peer_clocks.insert(20, 3);

        assert!(clock_tick_needed_for_state(&s, 10, &[10, 20, 30]));
    }

    #[test]
    fn clock_tick_not_needed_for_history_election_alone() {
        let s = StrictState::new();

        assert!(!clock_tick_needed_for_state(&s, 10, &[10]));
    }

    #[test]
    fn observe_peer_keeps_max_only() {
        let mut s = StrictState::new();
        s.observe_peer(1, 50);
        s.observe_peer(1, 30); // ignored
        s.observe_peer(1, 100);
        assert_eq!(s.peer_clocks[&1], 100);
    }

    #[test]
    fn commit_buffer_orders_by_ts_then_op_id() {
        let mut s = StrictState::new();
        s.buffer_commit((100, 1), 3, Bytes::from_static(b"a"));
        s.buffer_commit((50, 5), 1, Bytes::from_static(b"b"));
        s.buffer_commit((75, 3), 1, Bytes::from_static(b"c"));
        let drained = s.drain_deliverable(10);
        assert_eq!(drained.len(), 3);
        // Expected order: (1, (50,5)), (1, (75,3)), (3, (100,1))
        assert_eq!(drained[0].ts_final, 1);
        assert_eq!(drained[0].op_id, (50, 5));
        assert_eq!(drained[1].ts_final, 1);
        assert_eq!(drained[1].op_id, (75, 3));
        assert_eq!(drained[2].ts_final, 3);
        assert_eq!(drained[2].op_id, (100, 1));
    }

    #[test]
    fn drain_deliverable_respects_high_water() {
        let mut s = StrictState::new();
        s.buffer_commit((1, 1), 5, Bytes::new());
        s.buffer_commit((2, 1), 10, Bytes::new());
        let d = s.drain_deliverable(7);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].ts_final, 5);
        // The unread one stays.
        assert_eq!(s.commit_buffer.len(), 1);
    }

    #[test]
    fn earliest_uncommitted_proposal_ts_blocks_delivery_past_pending_work() {
        let mut s = StrictState::new();
        s.pending_proposes.insert(
            (1, 1),
            PendingPropose {
                coord_node: 20,
                op_msgpack: Bytes::new(),
                ts_local: 5,
                seen_at: Instant::now(),
                protocol_version: 0,
                frozen_targets: None,
                v2_descriptor_durable: true,
            },
        );
        s.buffer_commit((2, 2), 6, Bytes::from_static(b"later"));

        let hw = s
            .earliest_uncommitted_proposal_ts()
            .map(|ts| 10.min(ts.saturating_sub(1)))
            .unwrap_or(10);
        let drained = s.drain_deliverable(hw);

        assert!(drained.is_empty());
        assert_eq!(s.commit_buffer.len(), 1);
        s.pending_proposes.clear();
        assert_eq!(s.drain_deliverable(10).len(), 1);
    }

    #[test]
    fn delivery_high_water_is_min_over_alive_set_plus_self() {
        let mut s = StrictState::new();
        s.clock = 7;
        s.peer_clocks.insert(10, 7);
        s.peer_clocks.insert(20, 5);
        s.peer_clocks.insert(30, 9);
        s.peer_clocks.insert(99, 0); // not in alive snapshot below
        let alive = vec![10u16, 20, 30];
        let hw = s.delivery_high_water(10, &alive);
        assert_eq!(hw, 5); // min(self=7, 20=5, 30=9)
    }

    #[test]
    fn delivery_blocked_when_alive_peer_has_no_clock_observation() {
        let mut s = StrictState::new();
        s.clock = 7;
        s.peer_clocks.insert(20, 5);
        // 30 alive but never observed => contributes 0.
        let alive = vec![10u16, 20, 30];
        let hw = s.delivery_high_water(10, &alive);
        assert_eq!(hw, 0);
    }

    #[test]
    fn delivery_members_exclude_alive_peers_without_live_routes() {
        let net = MockNet::new(10, vec![10, 20, 30]);
        net.set_live_reliable_routes([20]);

        let members = delivery_members(net.as_ref(), 10);

        assert_eq!(members, vec![10, 20]);
    }

    #[test]
    fn delivery_high_water_ignores_unroutable_unobserved_peer() {
        let net = MockNet::new(10, vec![10, 20, 30]);
        net.set_live_reliable_routes([20]);
        let alive = delivery_members(net.as_ref(), 10);
        let mut s = StrictState::new();
        s.clock = 7;
        s.peer_clocks.insert(20, 5);

        let hw = s.delivery_high_water(10, &alive);

        assert_eq!(hw, 5);
    }

    #[test]
    fn clock_tick_not_needed_for_unroutable_unobserved_peer() {
        let net = MockNet::new(10, vec![10, 20, 30]);
        net.set_live_reliable_routes([20]);
        let alive = delivery_members(net.as_ref(), 10);
        let mut s = StrictState::new();
        s.finish_history_election();
        s.peer_clocks.insert(20, 3);

        assert!(!clock_tick_needed_for_state(&s, 10, &alive));
    }

    #[test]
    fn fail_quorum_lost_when_alive_set_shrinks() {
        let mut s = StrictState::new();
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let (tx, _rx) = oneshot::channel();
        let mut target = HashSet::new();
        target.insert(10);
        target.insert(20);
        target.insert(30);
        target.insert(40);
        let op_id: OpId = (1, 1);
        s.proposals.insert(
            op_id,
            Proposal {
                target_epochs: HashMap::new(),
                invalid_targets: HashSet::new(),
                op_msgpack: Bytes::new(),
                ts_propose: 1,
                acks: HashMap::new(),
                target_set: target,
                accepted_waker: None,
                waker: Some(tx),
                committed: false,
                protocol_version: 0,
                accept_acks: HashMap::new(),
                accept_started: false,
                phase_two_accept: None,
                phase_two_retry_attempts: 0,
                phase_two_floor_pauses: 0,
                started_at: Instant::now(),
                _permit: permit,
            },
        );
        // fast_quorum(4) = 3. Shrink alive to {10, 20} => still=2 < 3.
        let alive: HashSet<NodeIdentifier> = [10u16, 20].into_iter().collect();
        let wakers = s.fail_quorum_lost(&alive);
        assert_eq!(wakers.len(), 1);
        assert!(s.proposals.is_empty());
    }

    #[test]
    fn fail_quorum_lost_keeps_proposal_when_quorum_reachable() {
        let mut s = StrictState::new();
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let (tx, _rx) = oneshot::channel();
        let mut target = HashSet::new();
        target.insert(10);
        target.insert(20);
        target.insert(30);
        target.insert(40);
        let op_id: OpId = (2, 2);
        s.proposals.insert(
            op_id,
            Proposal {
                target_epochs: HashMap::new(),
                invalid_targets: HashSet::new(),
                op_msgpack: Bytes::new(),
                ts_propose: 1,
                acks: HashMap::new(),
                target_set: target,
                accepted_waker: None,
                waker: Some(tx),
                committed: false,
                protocol_version: 0,
                accept_acks: HashMap::new(),
                accept_started: false,
                phase_two_accept: None,
                phase_two_retry_attempts: 0,
                phase_two_floor_pauses: 0,
                started_at: Instant::now(),
                _permit: permit,
            },
        );
        // 3 still alive, fq=3, ok.
        let alive: HashSet<NodeIdentifier> = [10u16, 20, 30].into_iter().collect();
        let wakers = s.fail_quorum_lost(&alive);
        assert_eq!(wakers.len(), 0);
        assert_eq!(s.proposals.len(), 1);
    }

    #[test]
    fn fail_quorum_lost_counts_already_received_acks() {
        let mut s = StrictState::new();
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let (tx, _rx) = oneshot::channel();
        let target = HashSet::from([10u16, 20, 30, 40]);
        let op_id: OpId = (4, 4);
        s.proposals.insert(
            op_id,
            Proposal {
                target_epochs: HashMap::new(),
                invalid_targets: HashSet::new(),
                op_msgpack: Bytes::new(),
                ts_propose: 1,
                acks: HashMap::from([(10, 1), (30, 2)]),
                target_set: target,
                accepted_waker: None,
                waker: Some(tx),
                committed: false,
                protocol_version: 0,
                accept_acks: HashMap::new(),
                accept_started: false,
                phase_two_accept: None,
                phase_two_retry_attempts: 0,
                phase_two_floor_pauses: 0,
                started_at: Instant::now(),
                _permit: permit,
            },
        );

        // fast_quorum(4) = 3. Even though only {10, 20} are still alive,
        // ack from 30 was already received, so ack(10) + ack(30) +
        // reachable missing 20 can still reach quorum.
        let alive: HashSet<NodeIdentifier> = [10u16, 20].into_iter().collect();
        let wakers = s.fail_quorum_lost(&alive);

        assert_eq!(wakers.len(), 0);
        assert_eq!(s.proposals.len(), 1);
    }

    #[test]
    fn gc_stale_proposals_fires_after_ttl() {
        let cfg = ReplicationConfig::default();
        let mut s = StrictState::new();
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let (tx, _rx) = oneshot::channel();
        let mut target = HashSet::new();
        target.insert(10);
        let op_id: OpId = (3, 3);
        let stale = Instant::now() - cfg.propose_ttl() - Duration::from_secs(1);
        s.proposals.insert(
            op_id,
            Proposal {
                target_epochs: HashMap::new(),
                invalid_targets: HashSet::new(),
                op_msgpack: Bytes::new(),
                ts_propose: 1,
                acks: HashMap::new(),
                target_set: target,
                accepted_waker: None,
                waker: Some(tx),
                committed: false,
                protocol_version: 0,
                accept_acks: HashMap::new(),
                accept_started: false,
                phase_two_accept: None,
                phase_two_retry_attempts: 0,
                phase_two_floor_pauses: 0,
                started_at: stale,
                _permit: permit,
            },
        );
        let wakers = s.gc_stale_proposals(Instant::now(), cfg.propose_ttl());
        assert_eq!(wakers.len(), 1);
        assert!(s.proposals.is_empty());
    }

    // ---- Slow-path recovery state-machine tests ----

    #[test]
    fn recovery_quorum_size_matches_majority() {
        assert_eq!(recovery_quorum_size(0), 0);
        assert_eq!(recovery_quorum_size(1), 1);
        assert_eq!(recovery_quorum_size(2), 2);
        assert_eq!(recovery_quorum_size(3), 2);
        assert_eq!(recovery_quorum_size(4), 3);
        assert_eq!(recovery_quorum_size(5), 3);
        assert_eq!(recovery_quorum_size(7), 4);
    }

    #[test]
    fn recovery_commit_repair_includes_live_replacement_members() {
        let net = MockNet::new(2, vec![1, 2, 3]);
        let frozen_targets = HashSet::from([2, 3]);

        assert_eq!(
            recovery_commit_repair_dsts(net.as_ref(), 2, &frozen_targets),
            vec![1, 3]
        );
    }

    #[test]
    fn make_ballot_orders_by_node_then_attempt() {
        let a = make_ballot(2, 1);
        let b = make_ballot(2, 5);
        let c = make_ballot(3, 0);
        assert!(a < b, "same node, higher attempt wins");
        assert!(b < c, "higher node id outranks");
    }

    #[test]
    fn try_promise_is_monotonic() {
        let mut s = StrictState::new();
        let op_id: OpId = (1, 1);
        assert!(s.try_promise(op_id, 10));
        assert_eq!(s.recovery_promises[&op_id], 10);
        // Lower or equal ballots are rejected (no update, returns false).
        assert!(!s.try_promise(op_id, 5));
        assert!(!s.try_promise(op_id, 10));
        assert_eq!(s.recovery_promises[&op_id], 10);
        // Strictly higher succeeds.
        assert!(s.try_promise(op_id, 11));
        assert_eq!(s.recovery_promises[&op_id], 11);
    }

    #[test]
    fn mark_committed_dedups_repeat_calls() {
        let mut s = StrictState::new();
        let op_id: OpId = (7, 7);
        assert!(s.mark_committed(op_id, 100));
        assert_eq!(s.committed_ts_final[&op_id], 100);
        // Second call: false (already marked); does NOT overwrite ts_final.
        assert!(!s.mark_committed(op_id, 999));
        assert_eq!(s.committed_ts_final[&op_id], 100);
    }

    #[test]
    fn mark_committed_clears_pending_propose() {
        let mut s = StrictState::new();
        let op_id: OpId = (1, 2);
        s.record_pending_propose(op_id, 5, Bytes::from_static(b"x"), 33, Instant::now());
        assert!(s.pending_proposes.contains_key(&op_id));
        s.mark_committed(op_id, 50);
        assert!(!s.pending_proposes.contains_key(&op_id));
    }

    #[test]
    fn bootstrap_catchup_disabled_after_observed_strict_traffic() {
        let mut s = StrictState::new();
        assert!(s.can_bootstrap_catchup());

        s.record_pending_propose((1, 1), 10, Bytes::from_static(b"op"), 1, Instant::now());
        assert!(!s.can_bootstrap_catchup());
    }

    #[test]
    fn history_election_can_be_rearmed_after_prior_commits() {
        let mut s = StrictState::new();
        s.finish_history_election();
        s.committed_ids.insert((1, 1));
        s.committed_ts_final.insert((1, 1), 10);

        assert!(!s.can_bootstrap_catchup());
        s.request_history_election();

        assert!(s.can_bootstrap_catchup());
        assert!(s.history_election_pending());
    }

    #[test]
    fn history_election_rearm_stays_blocked_by_inflight_state() {
        let mut s = StrictState::new();
        s.finish_history_election();
        s.request_history_election();
        assert!(s.can_bootstrap_catchup());

        s.record_pending_propose((1, 1), 10, Bytes::from_static(b"op"), 1, Instant::now());
        assert!(!s.can_bootstrap_catchup());
    }

    #[test]
    fn snapshot_response_rechecks_the_delivery_fence_before_installing() {
        let mut s = StrictState::new();
        let local_rank = HistoryRank {
            version: 0,
            freshness: 0,
            runtime_started_at: 1,
            node_id: 1,
        };
        let remote_rank = HistoryRank {
            version: 1,
            freshness: 1,
            runtime_started_at: 2,
            node_id: 2,
        };
        s.history_election_phase = HistoryElectionPhase::FetchingSnapshot {
            peer: 2,
            expected_rank: remote_rank,
            started_at: Instant::now(),
        };
        s.delivering_commits.insert((9, 9));

        assert!(matches!(
            s.record_history_snapshot_response(
                2,
                remote_rank,
                local_rank,
                1,
                Bytes::from_static(b"snapshot"),
            ),
            HistorySnapshotResponseOutcome::Ignored
        ));
        assert!(matches!(
            s.history_election_phase,
            HistoryElectionPhase::FetchingSnapshot { .. }
        ));
    }

    #[test]
    fn committed_recovery_promise_does_not_permanently_fence_history_election() {
        let mut s = StrictState::new();
        let op_id = (1, 1);
        s.recovery_promises.insert(op_id, 7);
        assert!(!s.can_bootstrap_catchup());

        assert!(s.mark_committed(op_id, 10));

        assert!(s.can_bootstrap_catchup());
        assert_eq!(s.recovery_promises[&op_id], 7);
    }

    #[tokio::test]
    async fn descriptorless_commit_is_decode_only() {
        let net = MockNet::new(2, vec![1, 2, 3, 4]);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            2,
            0,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&1234u64).unwrap());

        rt.recv_commit(
            1,
            StrictCommit {
                coord_node: 1,
                op_id_hi: 1,
                op_id_lo: 7,
                ts_final: 10,
                op_msgpack,
                src_clock: 9,
            },
        )
        .await;

        assert!(net.drain_captures().is_empty());
        let state = rt.state.lock();
        assert!(state.committed_ids.is_empty());
        assert!(state.commit_buffer.is_empty());
    }

    #[tokio::test]
    async fn descriptorless_propose_is_decode_only() {
        let net = MockNet::new(2, vec![1, 2]);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            2,
            0,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let op_id = make_op_id(1, 0, 7);
        let proposal = StrictPropose {
            coord_node: 1,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            ts_propose: 10,
            op_msgpack: Bytes::from(rmp_serde::to_vec(&1234u64).unwrap()),
            src_clock: 10,
        };

        rt.recv_propose(1, proposal.clone()).await;
        let mut retry = proposal;
        retry.src_clock = 100;
        rt.recv_propose(1, retry).await;

        assert!(net.drain_captures().is_empty());
        let state = rt.state.lock();
        assert_eq!(state.clock, 0);
        assert!(!state.pending_proposes.contains_key(&op_id));
    }

    #[tokio::test]
    async fn bootstrap_catchup_only_targets_reliably_routable_peers() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        net.set_epoch(2, 1);
        net.set_epoch(3, 1);
        // Node 2 remains in the logical routing table, but its first-hop
        // transport is gone. Bootstrap must probe only node 3 instead of
        // waiting for a response that cannot arrive.
        net.set_reliable_routes([2, 3]);
        net.set_live_reliable_routes([3]);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            0,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        rt.try_bootstrap_catchup().await;

        let captures = net.captures();
        assert_eq!(captures.len(), 1);
        match &captures[0] {
            crate::replications::test_support::CapturedFrame::StrictUnicast {
                dst, body, ..
            } => {
                assert_eq!(*dst, 3);
                let StrictBody::CatchupReq(req) = body else {
                    panic!("expected catchup request, got {body:?}");
                };
                assert!(req.history_probe_only);
                assert!(!req.force_snapshot);
                assert_eq!(req.chunk_token, 0);
            }
            other => panic!("unexpected capture: {other:?}"),
        }
        assert_eq!(rt.state.lock().history_alive_peers, HashSet::from([3]));
    }

    #[tokio::test]
    async fn strict_history_probe_only_response_has_no_snapshot_or_ops() {
        let net = MockNet::new(2, vec![1, 2]);
        let repo = CountingStrictRepo::new();
        {
            let mut state = repo.state.lock();
            state.0 = 2;
            state.1 = vec![(1, 101, None), (2, 102, None)];
        }
        let rt = StrictRuntime::new(
            repo,
            2,
            77,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        rt.recv_catchup_req(
            1,
            StrictCatchupReq {
                src_node: 1,
                since_version: 0,
                chunk_token: HISTORY_ELECTION_SNAPSHOT_TOKEN,
                force_snapshot: true,
                history_probe_only: true,
                terminal_state_cursor: 0,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
            },
        )
        .await;

        let captures = net.drain_captures();
        assert_eq!(captures.len(), 1);
        match &captures[0] {
            crate::replications::test_support::CapturedFrame::StrictUnicast {
                dst, body, ..
            } => {
                assert_eq!(*dst, 1);
                let StrictBody::CatchupResp(resp) = body else {
                    panic!("expected catchup response, got {body:?}");
                };
                assert_eq!(resp.snapshot_msgpack.len(), 0);
                assert_eq!(resp.ops.len(), 0);
                assert!(!resp.has_more);
                assert!(!resp.too_old_use_snapshot);
                assert_eq!(resp.history_version, 2);
                assert_eq!(resp.runtime_started_at, 77);
                assert_eq!(resp.history_node, 2);
            }
            other => panic!("unexpected capture: {other:?}"),
        }
    }

    #[tokio::test]
    async fn strict_catchup_request_uses_chunk_token_as_continuation() {
        let net = MockNet::new(2, vec![1, 2]);
        let repo = CountingStrictRepo::new();
        {
            let mut state = repo.state.lock();
            state.0 = 5;
            state.1 = (1u64..=5)
                .map(|version| {
                    (
                        version,
                        100 + version,
                        Some(StrictLogMetadata {
                            op_id_hi: 7,
                            op_id_lo: version,
                            ts_final: version * 10,
                        }),
                    )
                })
                .collect();
        }
        let rt = StrictRuntime::new(
            repo,
            2,
            0,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default().with_strict_max_catchup_ops(2)),
        );

        rt.recv_catchup_req(
            1,
            StrictCatchupReq {
                src_node: 1,
                since_version: 0,
                chunk_token: 2,
                force_snapshot: false,
                history_probe_only: false,
                terminal_state_cursor: 0,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
            },
        )
        .await;

        let captures = net.drain_captures();
        assert_eq!(captures.len(), 1);
        match &captures[0] {
            crate::replications::test_support::CapturedFrame::StrictUnicast {
                dst, body, ..
            } => {
                assert_eq!(*dst, 1);
                let StrictBody::CatchupResp(resp) = body else {
                    panic!("expected catchup response, got {body:?}");
                };
                let versions: Vec<u64> = resp.ops.iter().map(|op| op.version).collect();
                assert_eq!(versions, vec![3, 4]);
                assert!(resp.has_more);
                assert_eq!(resp.next_chunk_token, 4);
            }
            other => panic!("unexpected capture: {other:?}"),
        }
    }

    #[tokio::test]
    async fn strict_catchup_followup_uses_response_token_when_repo_version_lags() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo.clone(),
            1,
            0,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        rt.state.lock().finish_history_election();

        let ops: Vec<repl_proto::CatchupOp> = (1u64..=2)
            .map(|version| repl_proto::CatchupOp {
                version,
                op_msgpack: Bytes::from(rmp_serde::to_vec(&(200 + version)).unwrap()),
                strict_op_id_hi: 9,
                strict_op_id_lo: version,
                strict_ts_final: 100 + version,
                strict_terminal_ballot: 0,
                strict_terminal_resolver_node: 0,
                strict_terminal_resolver_boot_epoch: 0,
                strict_terminal_frozen_targets: Vec::new(),
            })
            .collect();

        rt.recv_catchup_resp(
            2,
            StrictCatchupResp {
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops,
                terminal_states: Vec::new(),
                next_terminal_state_cursor: 0,
                terminal_states_has_more: false,
                terminal_sync_only: false,
                request_force_snapshot: false,
                request_history_probe_only: false,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
                snapshot_next_cursor: 0,
                snapshot_total_bytes: 0,
                snapshot_sha256: Bytes::new(),
                snapshot_has_more: false,
                snapshot_transfer_rejected: false,
                has_more: true,
                next_chunk_token: 2,
                too_old_use_snapshot: false,
                history_version: 2,
                history_freshness: 0,
                runtime_started_at: 0,
                history_node: 2,
            },
        )
        .await;

        assert_eq!(repo.current_version(), 0);
        assert_eq!(rt.state.lock().commit_buffer.len(), 2);

        let captures = net.drain_captures();
        assert_eq!(captures.len(), 1);
        match &captures[0] {
            crate::replications::test_support::CapturedFrame::StrictUnicast {
                dst, body, ..
            } => {
                assert_eq!(*dst, 2);
                let StrictBody::CatchupReq(req) = body else {
                    panic!("expected catchup request, got {body:?}");
                };
                assert_eq!(req.since_version, 2);
                assert_eq!(req.chunk_token, 2);
                assert!(!req.force_snapshot);
            }
            other => panic!("unexpected capture: {other:?}"),
        }
    }

    #[tokio::test]
    async fn strict_catchup_followup_does_not_transfer_token_to_another_peer() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_reliable_routes([3]);
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo,
            1,
            0,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        rt.state.lock().finish_history_election();

        rt.recv_catchup_resp(
            2,
            StrictCatchupResp {
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: vec![repl_proto::CatchupOp {
                    version: 1,
                    op_msgpack: Bytes::from(rmp_serde::to_vec(&201u64).unwrap()),
                    strict_op_id_hi: 9,
                    strict_op_id_lo: 1,
                    strict_ts_final: 101,
                    strict_terminal_ballot: 0,
                    strict_terminal_resolver_node: 0,
                    strict_terminal_resolver_boot_epoch: 0,
                    strict_terminal_frozen_targets: Vec::new(),
                }],
                terminal_states: Vec::new(),
                next_terminal_state_cursor: 0,
                terminal_states_has_more: false,
                terminal_sync_only: false,
                request_force_snapshot: false,
                request_history_probe_only: false,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
                snapshot_next_cursor: 0,
                snapshot_total_bytes: 0,
                snapshot_sha256: Bytes::new(),
                snapshot_has_more: false,
                snapshot_transfer_rejected: false,
                has_more: true,
                next_chunk_token: 1,
                too_old_use_snapshot: false,
                history_version: 1,
                history_freshness: 0,
                runtime_started_at: 0,
                history_node: 2,
            },
        )
        .await;

        assert!(
            net.drain_captures().is_empty(),
            "a continuation token is only valid with the peer that issued it"
        );
    }

    #[test]
    fn history_rank_orders_by_version_freshness_runtime_then_node() {
        let base = HistoryRank {
            version: 10,
            freshness: 100,
            runtime_started_at: 50,
            node_id: 8,
        };

        assert!(
            HistoryRank {
                version: 11,
                ..base
            }
            .beats(base)
        );
        assert!(
            HistoryRank {
                freshness: 101,
                ..base
            }
            .beats(base)
        );
        assert!(
            HistoryRank {
                runtime_started_at: 49,
                ..base
            }
            .beats(base)
        );
        assert!(HistoryRank { node_id: 7, ..base }.beats(base));
        assert!(!HistoryRank { node_id: 9, ..base }.beats(base));
    }

    #[test]
    fn history_election_waits_for_all_peers_and_keeps_best_candidate() {
        let mut s = StrictState::new();
        s.begin_history_election([2, 3, 4]);
        let local_rank = HistoryRank {
            version: 8,
            freshness: 0,
            runtime_started_at: 100,
            node_id: 1,
        };

        let rank_from_3 = HistoryRank {
            version: 10,
            freshness: 200,
            runtime_started_at: 50,
            node_id: 3,
        };
        let rank_from_4 = HistoryRank {
            version: 10,
            freshness: 200,
            runtime_started_at: 50,
            node_id: 4,
        };
        let rank_from_2 = HistoryRank {
            version: 9,
            freshness: 999,
            runtime_started_at: 1,
            node_id: 2,
        };

        assert_eq!(
            s.record_history_probe_response(2, rank_from_2, local_rank),
            HistoryProbeResponseOutcome::Pending
        );
        assert_eq!(
            s.record_history_probe_response(4, rank_from_4, local_rank),
            HistoryProbeResponseOutcome::Pending
        );
        let outcome = s.record_history_probe_response(3, rank_from_3, local_rank);
        let HistoryProbeResponseOutcome::FetchSnapshot(request) = outcome else {
            panic!("last probe should elect a snapshot fetch, got {outcome:?}");
        };

        assert_eq!(request.peer(), 3);
        assert_eq!(request.expected_rank(), rank_from_3);
        assert!(s.history_election_pending());
        assert_eq!(s.history_election_fetching_snapshot(), Some(request));

        let outcome = s.record_history_snapshot_response(
            3,
            rank_from_3,
            local_rank,
            10,
            Bytes::from_static(b"node3"),
        );
        let HistorySnapshotResponseOutcome::Install(winner) = outcome else {
            panic!("winning snapshot should enter install phase, got {outcome:?}");
        };

        assert_eq!(winner.rank, rank_from_3);
        assert_eq!(winner.snapshot_version, 10);
        assert!(s.history_election_pending());
        assert!(s.history_election_installing());

        s.finish_history_election();
        assert!(!s.history_election_pending());
        assert!(!s.history_election_installing());
    }

    #[test]
    fn history_election_prunes_a_lost_probe_and_fetches_the_surviving_best_rank() {
        let mut state = StrictState::new();
        state.begin_history_election([2, 3]);
        let local_rank = HistoryRank {
            version: 8,
            freshness: 0,
            runtime_started_at: 100,
            node_id: 1,
        };
        let rank_from_2 = HistoryRank {
            version: 9,
            freshness: 10,
            runtime_started_at: 20,
            node_id: 2,
        };

        assert_eq!(
            state.record_history_probe_response(2, rank_from_2, local_rank),
            HistoryProbeResponseOutcome::Pending
        );
        let request = state
            .reconcile_history_election_reachability([2])
            .expect("losing the final unanswered peer should complete the probe");
        assert_eq!(request.peer(), 2);
        assert_eq!(request.expected_rank(), rank_from_2);
    }

    #[test]
    fn history_election_rearms_when_its_snapshot_source_loses_reachability() {
        let mut state = StrictState::new();
        state.begin_history_election([2]);
        let local_rank = HistoryRank {
            version: 1,
            freshness: 0,
            runtime_started_at: 10,
            node_id: 1,
        };
        let remote_rank = HistoryRank {
            version: 2,
            freshness: 1,
            runtime_started_at: 9,
            node_id: 2,
        };
        assert!(matches!(
            state.record_history_probe_response(2, remote_rank, local_rank),
            HistoryProbeResponseOutcome::FetchSnapshot(_)
        ));

        assert!(state.reconcile_history_election_reachability([]).is_none());
        assert!(state.history_election_pending());
        assert!(!state.history_election_active());
        assert!(state.can_start_history_election());
    }

    #[test]
    fn history_election_does_not_fetch_from_a_lost_best_probe_responder() {
        let mut state = StrictState::new();
        state.begin_history_election([2, 3]);
        let local_rank = HistoryRank {
            version: 8,
            freshness: 0,
            runtime_started_at: 100,
            node_id: 1,
        };
        let lost_best_rank = HistoryRank {
            version: 10,
            freshness: 10,
            runtime_started_at: 20,
            node_id: 2,
        };
        let surviving_rank = HistoryRank {
            version: 7,
            freshness: 100,
            runtime_started_at: 1,
            node_id: 3,
        };
        assert_eq!(
            state.record_history_probe_response(2, lost_best_rank, local_rank),
            HistoryProbeResponseOutcome::Pending
        );
        assert!(state.reconcile_history_election_reachability([3]).is_none());
        assert_eq!(
            state.record_history_probe_response(3, surviving_rank, local_rank),
            HistoryProbeResponseOutcome::Finished
        );
        assert!(!state.history_election_pending());
        assert!(!state.history_election_active());
    }

    #[tokio::test]
    async fn strict_history_election_fetches_only_best_snapshot() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        net.set_epoch(2, 1);
        net.set_epoch(3, 1);
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo,
            1,
            100,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        rt.try_bootstrap_catchup().await;

        let captures = net.drain_captures();
        assert_eq!(captures.len(), 2);
        let mut probe_dsts = Vec::new();
        for capture in &captures {
            let crate::replications::test_support::CapturedFrame::StrictUnicast {
                dst, body, ..
            } = capture
            else {
                panic!("unexpected capture: {capture:?}");
            };
            probe_dsts.push(*dst);
            let StrictBody::CatchupReq(req) = body else {
                panic!("expected catchup request, got {body:?}");
            };
            assert!(req.history_probe_only);
            assert!(!req.force_snapshot);
            assert_eq!(req.chunk_token, 0);
        }
        probe_dsts.sort_unstable();
        assert_eq!(probe_dsts, vec![2, 3]);

        rt.recv_catchup_resp(2, strict_probe_resp(2, 10, 100, 40))
            .await;
        assert!(net.drain_captures().is_empty());

        rt.recv_catchup_resp(3, strict_probe_resp(3, 8, 999, 1))
            .await;

        let captures = net.drain_captures();
        assert_eq!(captures.len(), 1);
        match &captures[0] {
            crate::replications::test_support::CapturedFrame::StrictUnicast {
                dst, body, ..
            } => {
                assert_eq!(*dst, 2);
                let StrictBody::CatchupReq(req) = body else {
                    panic!("expected catchup request, got {body:?}");
                };
                assert!(!req.history_probe_only);
                assert!(req.force_snapshot);
                assert_eq!(req.chunk_token, HISTORY_ELECTION_SNAPSHOT_TOKEN);
            }
            other => panic!("unexpected capture: {other:?}"),
        }
    }

    #[tokio::test]
    async fn strict_history_election_local_best_requests_no_snapshot() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        net.set_epoch(2, 1);
        net.set_epoch(3, 1);
        let repo = CountingStrictRepo::new();
        repo.state.lock().0 = 12;
        let rt = StrictRuntime::new(
            repo,
            1,
            100,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        rt.try_bootstrap_catchup().await;
        assert_eq!(net.drain_captures().len(), 2);

        rt.recv_catchup_resp(2, strict_probe_resp(2, 10, 100, 40))
            .await;
        rt.recv_catchup_resp(3, strict_probe_resp(3, 11, 100, 40))
            .await;

        assert!(net.drain_captures().is_empty());
        assert!(!rt.state.lock().history_election_pending());
    }

    #[tokio::test]
    async fn strict_history_election_ignores_non_winning_snapshot_response() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        net.set_epoch(2, 1);
        net.set_epoch(3, 1);
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo.clone(),
            1,
            100,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        rt.try_bootstrap_catchup().await;
        net.drain_captures();
        rt.recv_catchup_resp(2, strict_probe_resp(2, 10, 100, 40))
            .await;
        rt.recv_catchup_resp(3, strict_probe_resp(3, 9, 100, 40))
            .await;
        let captures = net.drain_captures();
        assert_eq!(captures.len(), 1);

        let rank_from_3 = HistoryRank {
            version: 9,
            freshness: 100,
            runtime_started_at: 40,
            node_id: 3,
        };
        let snapshot = Bytes::from(rmp_serde::to_vec(&vec![(9u64, 909u64)]).unwrap());
        rt.recv_catchup_resp(3, strict_snapshot_resp(rank_from_3, 9, snapshot))
            .await;

        assert_eq!(repo.current_version(), 0);
        assert_eq!(repo.log(), Vec::<(u64, u64)>::new());
        let fetching = rt
            .state
            .lock()
            .history_election_fetching_snapshot()
            .expect("winning fetch should still be in progress");
        assert_eq!(fetching.peer(), 2);
        assert!(net.drain_captures().is_empty());
    }

    #[tokio::test]
    async fn bootstrap_send_failures_keep_retry_throttle() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        net.set_epoch(2, 1);
        net.set_epoch(3, 1);
        net.fail_strict_unicasts_to([2, 3]);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            100,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        rt.try_bootstrap_catchup().await;

        assert!(rt.last_bootstrap_attempt.lock().is_some());
        assert!(rt.state.lock().history_election_pending());
        assert!(!rt.state.lock().history_election_active());
        assert!(net.drain_captures().is_empty());
    }

    #[tokio::test]
    async fn steady_state_catchup_stands_down_while_history_election_is_pending() {
        let net = MockNet::new(1, vec![1, 2]);
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo,
            1,
            0,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        request_steady_state_catchup(&rt).await;

        assert!(
            net.drain_captures().is_empty(),
            "ordinary catchup must not race a pending history election"
        );
    }

    #[tokio::test]
    async fn non_snapshot_catchup_response_is_ignored_during_history_election() {
        let net = MockNet::new(1, vec![1, 2]);
        let repo = CountingStrictRepo::new();
        repo.apply_committed(1, 101).await;
        let rt = StrictRuntime::new(
            repo.clone(),
            1,
            0,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        rt.recv_catchup_resp(
            2,
            StrictCatchupResp {
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: vec![repl_proto::CatchupOp {
                    version: 1,
                    op_msgpack: Bytes::from(rmp_serde::to_vec(&201u64).unwrap()),
                    strict_op_id_hi: 0,
                    strict_op_id_lo: 0,
                    strict_ts_final: 0,
                    strict_terminal_ballot: 0,
                    strict_terminal_resolver_node: 0,
                    strict_terminal_resolver_boot_epoch: 0,
                    strict_terminal_frozen_targets: Vec::new(),
                }],
                terminal_states: Vec::new(),
                next_terminal_state_cursor: 0,
                terminal_states_has_more: false,
                terminal_sync_only: false,
                request_force_snapshot: false,
                request_history_probe_only: false,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
                snapshot_next_cursor: 0,
                snapshot_total_bytes: 0,
                snapshot_sha256: Bytes::new(),
                snapshot_has_more: false,
                snapshot_transfer_rejected: false,
                has_more: false,
                next_chunk_token: 1,
                too_old_use_snapshot: false,
                history_version: 1,
                history_freshness: 0,
                runtime_started_at: 0,
                history_node: 2,
            },
        )
        .await;

        assert_eq!(repo.current_version(), 1);
        assert_eq!(repo.log(), vec![(1, 101)]);
        assert!(rt.state.lock().history_election_pending());
        assert!(net.drain_captures().is_empty());
    }

    #[tokio::test]
    async fn empty_repo_accepts_log_catchup_during_startup_history_election() {
        let net = MockNet::new(1, vec![1, 2]);
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo.clone(),
            1,
            0,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );

        rt.recv_catchup_resp(
            2,
            StrictCatchupResp {
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: vec![
                    repl_proto::CatchupOp {
                        version: 1,
                        op_msgpack: Bytes::from(rmp_serde::to_vec(&201u64).unwrap()),
                        strict_op_id_hi: 0,
                        strict_op_id_lo: 0,
                        strict_ts_final: 0,
                        strict_terminal_ballot: 0,
                        strict_terminal_resolver_node: 0,
                        strict_terminal_resolver_boot_epoch: 0,
                        strict_terminal_frozen_targets: Vec::new(),
                    },
                    repl_proto::CatchupOp {
                        version: 2,
                        op_msgpack: Bytes::from(rmp_serde::to_vec(&202u64).unwrap()),
                        strict_op_id_hi: 0,
                        strict_op_id_lo: 0,
                        strict_ts_final: 0,
                        strict_terminal_ballot: 0,
                        strict_terminal_resolver_node: 0,
                        strict_terminal_resolver_boot_epoch: 0,
                        strict_terminal_frozen_targets: Vec::new(),
                    },
                ],
                terminal_states: Vec::new(),
                next_terminal_state_cursor: 0,
                terminal_states_has_more: false,
                terminal_sync_only: false,
                request_force_snapshot: false,
                request_history_probe_only: false,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
                snapshot_next_cursor: 0,
                snapshot_total_bytes: 0,
                snapshot_sha256: Bytes::new(),
                snapshot_has_more: false,
                snapshot_transfer_rejected: false,
                has_more: false,
                next_chunk_token: 2,
                too_old_use_snapshot: false,
                history_version: 2,
                history_freshness: 0,
                runtime_started_at: 0,
                history_node: 2,
            },
        )
        .await;

        assert_eq!(repo.log(), vec![(1, 201), (2, 202)]);
        assert!(rt.state.lock().history_election_pending());
    }

    #[tokio::test]
    async fn restarted_coordinator_preserves_v2_fence_without_reusing_stale_quorum() {
        use crate::overlay::MemberIncarnation;
        use crate::replications::test_support::CapturedFrame;

        let net = MockNet::new(1, vec![1, 2]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        net.set_epoch(2, 8);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            3,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let old_op = make_op_id(2, 7, 1);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&42u64).unwrap());
        let frozen_targets = vec![FrozenTarget::new(1, 3), FrozenTarget::new(2, 7)];
        {
            let mut state = rt.state.lock();
            state.peer_clocks.insert(2, 99);
            state.record_pending_propose_with_descriptor(
                old_op,
                2,
                op_msgpack.clone(),
                12,
                Instant::now(),
                STRICT_PROTOCOL_VERSION_V2,
                Some(frozen_targets.clone()),
                false,
            );
        }
        assert!(rt.persist_v2_pending_descriptor(old_op, 12, op_msgpack, &frozen_targets));

        rt.on_membership_change(&MembershipEvent::Restarted(MemberIncarnation::new(2, 8)));

        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert!(!net.captures().iter().any(|capture| {
            matches!(
                capture,
                CapturedFrame::StrictUnicast {
                    body: StrictBody::RecoveryReq(_)
                        | StrictBody::ResolutionHint(_)
                        | StrictBody::ResolutionPrepare(_),
                    ..
                } | CapturedFrame::StrictMulticast {
                    body: StrictBody::RecoveryReq(_)
                        | StrictBody::ResolutionPrepare(_)
                        | StrictBody::Decision(_),
                    ..
                }
            )
        }));
        assert!(rt.resolutions.lock().is_empty());

        let state = rt.state.lock();
        assert!(!state.peer_clocks.contains_key(&2));
        assert!(state.pending_proposes.contains_key(&old_op));
        assert!(state.history_election_pending());
    }

    #[test]
    fn membership_incarnation_fence_rejects_duplicate_and_stale_events() {
        use crate::overlay::MemberIncarnation;

        let mut state = StrictState::new();
        assert_eq!(
            state.apply_membership_event(&MembershipEvent::Joined(MemberIncarnation::new(2, 7))),
            MembershipTransition::Joined
        );
        assert_eq!(
            state.apply_membership_event(&MembershipEvent::Joined(MemberIncarnation::new(2, 7))),
            MembershipTransition::Ignored
        );
        assert_eq!(
            state.apply_membership_event(&MembershipEvent::Restarted(MemberIncarnation::new(2, 8))),
            MembershipTransition::Restarted
        );
        assert_eq!(
            state.apply_membership_event(&MembershipEvent::Failed(MemberIncarnation::new(2, 7))),
            MembershipTransition::Ignored,
            "a delayed failure from the prior process must not remove the new one"
        );
        assert_eq!(
            state.apply_membership_event(&MembershipEvent::Failed(MemberIncarnation::new(2, 8))),
            MembershipTransition::Removed
        );
        assert_eq!(
            state.apply_membership_event(&MembershipEvent::Restarted(MemberIncarnation::new(2, 8))),
            MembershipTransition::Ignored,
            "a duplicate restart must not resurrect a removed incarnation"
        );
        assert_eq!(
            state.apply_membership_event(&MembershipEvent::Joined(MemberIncarnation::new(2, 8))),
            MembershipTransition::Joined,
            "an explicit same-incarnation join is a valid partition heal"
        );
    }

    #[tokio::test]
    async fn propose_ack_requires_physical_sender_to_match_frozen_target_identity() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net,
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let op_id = (1, 9);
        let permit = rt.propose_semaphore.clone().acquire_owned().await.unwrap();
        rt.state.lock().proposals.insert(
            op_id,
            Proposal {
                target_epochs: HashMap::new(),
                invalid_targets: HashSet::new(),
                op_msgpack: Bytes::from_static(b"op"),
                ts_propose: 1,
                acks: HashMap::new(),
                target_set: HashSet::from([1, 2]),
                accepted_waker: None,
                waker: None,
                committed: false,
                protocol_version: 0,
                accept_acks: HashMap::new(),
                accept_started: false,
                phase_two_accept: None,
                phase_two_retry_attempts: 0,
                phase_two_floor_pauses: 0,
                started_at: Instant::now(),
                _permit: permit,
            },
        );

        rt.recv_propose_ack(
            3,
            StrictProposeAck {
                ack_boot_epoch: 0,
                ack_node: 2,
                coord_node: 1,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_local: 2,
                src_clock: 2,
            },
        )
        .await;

        let state = rt.state.lock();
        assert!(state.proposals[&op_id].acks.is_empty());
        assert!(!state.peer_clocks.contains_key(&2));
    }

    #[tokio::test]
    async fn target_restart_rejects_stale_ack_and_starts_v2_resolution() {
        use crate::overlay::MemberIncarnation;

        let net = MockNet::new(1, vec![1, 2, 3, 4]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        net.set_epoch(2, 8);
        net.set_epoch(3, 3);
        net.set_epoch(4, 4);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let op_id = make_op_id(1, 1, 10);
        let op_msgpack = Bytes::from_static(b"op");
        let frozen_targets = vec![
            FrozenTarget::new(1, 1),
            FrozenTarget::new(2, 7),
            FrozenTarget::new(3, 3),
            FrozenTarget::new(4, 4),
        ];
        let permit = rt.propose_semaphore.clone().acquire_owned().await.unwrap();
        {
            let mut state = rt.state.lock();
            state.proposals.insert(
                op_id,
                Proposal {
                    op_msgpack: op_msgpack.clone(),
                    ts_propose: 1,
                    acks: HashMap::from([(1, 1), (3, 3)]),
                    target_set: HashSet::from([1, 2, 3, 4]),
                    target_epochs: HashMap::from([(1, 1), (2, 7), (3, 3), (4, 4)]),
                    invalid_targets: HashSet::new(),
                    accepted_waker: None,
                    waker: None,
                    committed: false,
                    protocol_version: STRICT_PROTOCOL_VERSION_V2,
                    accept_acks: HashMap::new(),
                    accept_started: false,
                    phase_two_accept: None,
                    phase_two_retry_attempts: 0,
                    phase_two_floor_pauses: 0,
                    started_at: Instant::now(),
                    _permit: permit,
                },
            );
            state.record_pending_propose_with_descriptor(
                op_id,
                1,
                op_msgpack.clone(),
                1,
                Instant::now(),
                STRICT_PROTOCOL_VERSION_V2,
                Some(frozen_targets.clone()),
                false,
            );
        }
        assert!(rt.persist_v2_pending_descriptor(op_id, 1, op_msgpack, &frozen_targets));

        rt.on_membership_change(&MembershipEvent::Restarted(MemberIncarnation::new(2, 8)));
        {
            let state = rt.state.lock();
            let proposal = state
                .proposals
                .get(&op_id)
                .expect("quorum remains possible");
            assert!(proposal.invalid_targets.contains(&2));
        }

        rt.recv_propose_ack(
            2,
            StrictProposeAck {
                ack_node: 2,
                coord_node: 1,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_local: 8,
                src_clock: 8,
                ack_boot_epoch: 7,
            },
        )
        .await;
        assert!(!rt.state.lock().proposals[&op_id].acks.contains_key(&2));

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if net.captures().iter().any(|capture| {
                    matches!(
                        capture,
                        CapturedFrame::StrictMulticast {
                            body: StrictBody::ResolutionPrepare(prepare),
                            ..
                        } if (prepare.op_id_hi, prepare.op_id_lo) == op_id
                    )
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("restarted frozen target should start v2 terminal resolution");
    }

    #[tokio::test]
    async fn recovery_ack_requires_physical_sender_and_frozen_recovery_target() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net,
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let op_id = (2, 9);
        rt.recoveries.lock().insert(
            op_id,
            Recovery {
                target_epochs: HashMap::new(),
                invalid_targets: HashSet::new(),
                coord_node: 2,
                ballot: 11,
                started_at: Instant::now(),
                target_set: HashSet::from([1, 2]),
                prepare_acks: HashMap::new(),
            },
        );

        rt.recv_recovery_ack(
            3,
            StrictRecoveryAck {
                ack_boot_epoch: 0,
                ack_node: 2,
                ballot: 11,
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                promised: true,
                has_committed: false,
                committed_ts_final: 0,
                has_op: true,
                ts_local: 4,
                op_msgpack: Bytes::from_static(b"op"),
                src_clock: 4,
            },
        )
        .await;

        rt.recv_recovery_ack(
            3,
            StrictRecoveryAck {
                ack_boot_epoch: 0,
                ack_node: 3,
                ballot: 11,
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                promised: true,
                has_committed: false,
                committed_ts_final: 0,
                has_op: true,
                ts_local: 4,
                op_msgpack: Bytes::from_static(b"op"),
                src_clock: 4,
            },
        )
        .await;

        assert!(rt.recoveries.lock()[&op_id].prepare_acks.is_empty());
        assert!(!rt.state.lock().peer_clocks.contains_key(&3));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_stale_recovery_acks_cannot_enter_frozen_quorum() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net,
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let op_id = (2, 12);
        rt.recoveries.lock().insert(
            op_id,
            Recovery {
                coord_node: 2,
                ballot: 13,
                started_at: Instant::now(),
                target_set: HashSet::from([1, 2, 3]),
                target_epochs: HashMap::from([(1, 1), (2, 8), (3, 3)]),
                invalid_targets: HashSet::new(),
                prepare_acks: HashMap::new(),
            },
        );

        let mut tasks = Vec::new();
        for _ in 0..16 {
            let rt = rt.clone();
            tasks.push(tokio::spawn(async move {
                rt.recv_recovery_ack(
                    2,
                    StrictRecoveryAck {
                        ack_node: 2,
                        ballot: 13,
                        coord_node: 2,
                        op_id_hi: op_id.0,
                        op_id_lo: op_id.1,
                        promised: true,
                        has_committed: false,
                        committed_ts_final: 0,
                        has_op: true,
                        ts_local: 4,
                        op_msgpack: Bytes::from_static(b"old"),
                        src_clock: 4,
                        ack_boot_epoch: 7,
                    },
                )
                .await;
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }

        assert!(rt.recoveries.lock()[&op_id].prepare_acks.is_empty());
        assert!(!rt.state.lock().peer_clocks.contains_key(&2));
    }

    #[tokio::test]
    async fn descriptorless_commit_does_not_mutate_active_recovery() {
        let net = MockNet::new(1, vec![1, 2]);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net,
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let op_id = (2, 11);
        rt.recoveries.lock().insert(
            op_id,
            Recovery {
                coord_node: 2,
                ballot: 12,
                started_at: Instant::now(),
                target_set: HashSet::from([1, 2]),
                target_epochs: HashMap::from([(1, 1), (2, 2)]),
                invalid_targets: HashSet::new(),
                prepare_acks: HashMap::new(),
            },
        );

        rt.recv_commit(
            2,
            StrictCommit {
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_final: 9,
                op_msgpack: Bytes::from(rmp_serde::to_vec(&42u64).unwrap()),
                src_clock: 9,
            },
        )
        .await;

        assert!(rt.recoveries.lock().contains_key(&op_id));
        assert!(!rt.state.lock().committed_ids.contains(&op_id));
    }

    #[tokio::test]
    async fn equal_version_metadata_divergence_rearms_validated_history_election() {
        let net = MockNet::new(1, vec![1, 2]);
        let repo = CountingStrictRepo::new();
        repo.state.lock().0 = 4;
        let rt = StrictRuntime::new(
            repo,
            1,
            1,
            "channels".to_owned(),
            net,
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        rt.state.lock().finish_history_election();

        rt.recv_catchup_resp(2, strict_probe_resp(2, 4, 99, 2))
            .await;

        assert!(rt.state.lock().history_election_pending());
    }

    #[test]
    fn gc_stale_pending_proposes_drops_old_entries() {
        let cfg = ReplicationConfig::default();
        let mut s = StrictState::new();
        let stale_at = Instant::now() - cfg.pending_propose_ttl() - Duration::from_secs(1);
        let fresh_at = Instant::now();
        s.record_pending_propose((1, 1), 5, Bytes::new(), 1, stale_at);
        s.record_pending_propose((2, 2), 5, Bytes::new(), 2, fresh_at);
        let alive = HashSet::new();
        let dropped =
            s.gc_stale_pending_proposes(Instant::now(), cfg.pending_propose_ttl(), &alive);
        assert_eq!(dropped, vec![(1, 1)]);
        assert_eq!(s.pending_proposes.len(), 1);
        assert!(s.pending_proposes.contains_key(&(2, 2)));
    }

    #[test]
    fn gc_stale_pending_proposes_keeps_entries_from_alive_coord() {
        let cfg = ReplicationConfig::default();
        let mut s = StrictState::new();
        let stale_at = Instant::now() - cfg.pending_propose_ttl() - Duration::from_secs(1);
        s.record_pending_propose((1, 1), 5, Bytes::new(), 40, stale_at);
        let alive = HashSet::from([5u16]);

        let dropped =
            s.gc_stale_pending_proposes(Instant::now(), cfg.pending_propose_ttl(), &alive);

        assert!(dropped.is_empty());
        assert!(s.pending_proposes.contains_key(&(1, 1)));
    }

    #[test]
    fn gc_stale_pending_proposes_keeps_ordering_barriers_for_later_commits() {
        let cfg = ReplicationConfig::default();
        let mut s = StrictState::new();
        let stale_at = Instant::now() - cfg.pending_propose_ttl() - Duration::from_secs(1);
        s.record_pending_propose((1, 1), 5, Bytes::new(), 40, stale_at);
        s.buffer_commit((2, 2), 50, Bytes::new());
        let alive = HashSet::new();

        let dropped =
            s.gc_stale_pending_proposes(Instant::now(), cfg.pending_propose_ttl(), &alive);

        assert!(dropped.is_empty());
        assert!(s.pending_proposes.contains_key(&(1, 1)));
    }

    #[test]
    fn gc_committed_ts_final_drops_below_high_water() {
        let mut s = StrictState::new();
        s.delivered_high_water = 50;
        s.committed_ts_final.insert((1, 1), 30); // below: drop
        s.committed_ts_final.insert((2, 2), 50); // exactly at: keep
        s.committed_ts_final.insert((3, 3), 100); // above: keep
        s.gc_committed_ts_final();
        assert!(!s.committed_ts_final.contains_key(&(1, 1)));
        assert!(s.committed_ts_final.contains_key(&(2, 2)));
        assert!(s.committed_ts_final.contains_key(&(3, 3)));
    }

    #[tokio::test]
    async fn v2_stale_pending_commits_and_unblocks_delivery() {
        let cfg = ReplicationConfig::default().with_pending_propose_ttl(Duration::from_millis(1));
        let (rt, net, repo) = v1_runtime(cfg.clone());
        let op_id = make_op_id(2, 1, 1);
        let later_op = make_op_id(2, 1, 2);
        {
            let mut state = rt.state.lock();
            state.record_pending_propose_with_descriptor(
                op_id,
                2,
                Bytes::from(rmp_serde::to_vec(&41u64).unwrap()),
                5,
                Instant::now() - cfg.pending_propose_ttl() - Duration::from_millis(1),
                STRICT_PROTOCOL_VERSION_V2,
                Some(v2_frozen_targets()),
                true,
            );
            state.buffer_commit(
                later_op,
                10,
                Bytes::from(rmp_serde::to_vec(&99u64).unwrap()),
            );
            state.clock = 20;
            state.peer_clocks.insert(1, 20);
            state.peer_clocks.insert(2, 20);
        }

        run_delivery_pass(&rt).await;
        assert!(repo.log().is_empty());

        resolve_stale_with_remote_ack(&rt, &net, op_id, 2, None).await;
        {
            let state = rt.state.lock();
            assert!(!state.pending_proposes.contains_key(&op_id));
            assert!(matches!(
                state.terminal_decisions.get(&op_id),
                Some(TerminalDecision::Commit(value))
                    if value.ts_final == 5
            ));
        }

        run_delivery_pass(&rt).await;
        assert_eq!(repo.log(), vec![(1, 41), (2, 99)]);
    }

    #[tokio::test]
    async fn idle_history_election_drains_terminal_commit_before_bootstrap() {
        let (rt, _net, repo) = v1_runtime(ReplicationConfig::default());
        let op_id = make_op_id(2, 1, 57);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&157u64).unwrap());
        {
            let mut state = rt.state.lock();
            state.request_history_election();
            assert!(state.history_election_pending());
            assert!(!state.history_election_active());
            assert!(state.mark_committed(op_id, 10));
            state.buffer_commit(op_id, 10, op_msgpack);
            state.clock = 20;
            state.peer_clocks.insert(1, 20);
            state.peer_clocks.insert(2, 20);
            assert!(!state.can_start_history_election());
        }

        run_delivery_pass(&rt).await;

        assert_eq!(repo.log(), vec![(1, 157)]);
        let state = rt.state.lock();
        assert!(state.history_election_pending());
        assert!(!state.history_election_active());
        assert!(state.can_start_history_election());
    }

    #[tokio::test]
    async fn delivery_in_flight_blocks_bootstrap_until_repository_apply_completes() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        net.set_epoch(2, 1);
        let repo = BlockingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo.clone(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let op_id = make_op_id(1, 1, 99);
        {
            let mut state = rt.state.lock();
            assert!(state.mark_committed(op_id, 10));
            state.buffer_commit(op_id, 10, Bytes::from(rmp_serde::to_vec(&999u64).unwrap()));
            state.clock = 20;
            state.peer_clocks.insert(1, 20);
            state.peer_clocks.insert(2, 20);
        }

        let delivery = tokio::spawn({
            let rt = rt.clone();
            async move { run_delivery_pass(&rt).await }
        });
        repo.delivery_started.notified().await;

        {
            let state = rt.state.lock();
            assert!(state.delivering_commits.contains(&op_id));
            assert!(!state.can_start_history_election());
        }
        rt.try_bootstrap_catchup().await;
        assert!(net.drain_captures().is_empty());

        repo.release_delivery.notify_one();
        delivery.await.unwrap();
        {
            let state = rt.state.lock();
            assert!(!state.delivering_commits.contains(&op_id));
            assert!(state.can_start_history_election());
        }

        rt.try_bootstrap_catchup().await;
        assert!(net.captures().iter().any(|frame| matches!(
            frame,
            CapturedFrame::StrictUnicast {
                dst: 2,
                body: StrictBody::CatchupReq(_),
                ..
            }
        )));
    }

    #[tokio::test]
    async fn v2_stale_pending_commits_after_capability_negotiation() {
        let cfg = ReplicationConfig::default().with_pending_propose_ttl(Duration::from_millis(1));
        let (rt, net, _repo) = v1_runtime(cfg.clone());
        let op_id = make_op_id(2, 1, 3);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&73u64).unwrap());
        rt.state.lock().record_pending_propose_with_descriptor(
            op_id,
            2,
            op_msgpack.clone(),
            7,
            Instant::now() - cfg.pending_propose_ttl() - Duration::from_millis(1),
            STRICT_PROTOCOL_VERSION_V2,
            Some(v2_frozen_targets()),
            true,
        );

        resolve_stale_with_remote_ack(&rt, &net, op_id, 2, None).await;

        {
            let state = rt.state.lock();
            assert!(matches!(
                state.terminal_decisions.get(&op_id),
                Some(TerminalDecision::Commit(value))
                    if value.ts_final == 7 && value.op_msgpack == op_msgpack
            ));
        }
        assert!(net.captures().iter().any(|frame| {
            matches!(
                frame,
                CapturedFrame::StrictMulticast {
                    body: StrictBody::Decision(StrictDecision {
                        outcome: Some(StrictDecisionOutcome::Commit(_)),
                        ..
                    }),
                    ..
                }
            )
        }));
    }

    #[tokio::test]
    async fn v1_stale_proposal_commits_after_caller_timeout_without_manual_mode() {
        let cfg = ReplicationConfig::default().with_pending_propose_ttl(Duration::from_millis(1));
        let (rt, net, repo) = v1_runtime(cfg.clone());
        let (tx, mut rx) = oneshot::channel();

        rt.clone().begin_propose(55u64, tx).await.unwrap();
        let op_id = net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictMulticast {
                    body: StrictBody::ProposeV1(propose),
                    ..
                } => Some((propose.op_id_hi, propose.op_id_lo)),
                _ => None,
            })
            .expect("v1 proposal must multicast a prepare");

        let timeout_at = Instant::now() - cfg.propose_ttl() - Duration::from_millis(1);
        let expired = {
            let mut state = rt.state.lock();
            state.proposals.get_mut(&op_id).unwrap().started_at = timeout_at;
            state.pending_proposes.get_mut(&op_id).unwrap().seen_at =
                Instant::now() - cfg.pending_propose_ttl() - Duration::from_millis(1);
            state.gc_stale_proposals(Instant::now(), cfg.propose_ttl())
        };
        for expired in expired {
            let _ = expired
                .waker
                .expect("stale local proposal must retain its caller")
                .send(Err(ReplicationError::ProposeTimeout(cfg.propose_ttl())));
        }
        assert!(matches!(
            rx.try_recv(),
            Ok(Err(ReplicationError::ProposeTimeout(_)))
        ));
        assert!(rt.state.lock().pending_proposes.contains_key(&op_id));

        resolve_stale_with_remote_ack(&rt, &net, op_id, 1, None).await;
        {
            let mut state = rt.state.lock();
            assert!(matches!(
                state.terminal_decisions.get(&op_id),
                Some(TerminalDecision::Commit(_))
            ));
            state.clock = 20;
            state.peer_clocks.insert(1, 20);
            state.peer_clocks.insert(2, 20);
        }
        run_delivery_pass(&rt).await;
        assert_eq!(repo.log(), vec![(1, 55)]);
    }

    #[tokio::test]
    async fn local_propose_waits_for_v2_capability_without_emitting_legacy_frames() {
        let cfg = ReplicationConfig::default()
            .with_delivery_tick_interval(Duration::from_millis(1))
            .with_propose_ttl(Duration::from_secs(1));
        let (rt, net, _repo) = v1_runtime(cfg);
        net.set_strict_replication_protocol_version(0);
        let (tx, _rx) = oneshot::channel();
        let task = tokio::spawn({
            let rt = rt.clone();
            async move { rt.begin_propose(56u64, tx).await }
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(rt.state.lock().proposals.is_empty());
        assert!(net.drain_captures().is_empty());

        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        task.await.unwrap().unwrap();

        let frames = net.drain_captures();
        assert!(!frames.iter().any(|frame| {
            matches!(
                frame,
                CapturedFrame::StrictMulticast {
                    body: StrictBody::Propose(_),
                    ..
                }
            )
        }));
        assert!(frames.iter().any(|frame| {
            matches!(
                frame,
                CapturedFrame::StrictMulticast {
                    body: StrictBody::ProposeV1(StrictProposeV1 {
                        protocol_version: STRICT_PROTOCOL_VERSION_V2,
                        frozen_targets,
                        ..
                    }),
                    ..
                } if !frozen_targets.is_empty()
            )
        }));
    }

    #[tokio::test]
    async fn proofless_strict_dispatch_is_decode_only() {
        let (rt, net, _repo) = v1_runtime(ReplicationConfig::default());
        let op_id = make_op_id(2, 1, 58);

        rt.dispatch(
            2,
            1,
            false,
            StrictBody::ClockTick(StrictClockTick {
                src_node: 2,
                src_clock: u64::MAX,
            }),
        )
        .await;
        rt.dispatch(
            2,
            1,
            false,
            StrictBody::Decision(StrictDecision {
                resolver_node: 2,
                ballot: 9,
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                outcome: Some(StrictDecisionOutcome::Abort(StrictDecisionAbort {})),
                src_clock: 9,
                resolver_boot_epoch: 0,
                frozen_targets: Vec::new(),
            }),
        )
        .await;
        rt.dispatch(
            2,
            1,
            false,
            StrictBody::CatchupReq(StrictCatchupReq {
                src_node: 2,
                since_version: 0,
                chunk_token: 0,
                force_snapshot: false,
                history_probe_only: false,
                terminal_state_cursor: 0,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
            }),
        )
        .await;
        let mut response = strict_probe_resp(2, 0, 0, 0);
        response.terminal_states = vec![StrictTerminalState {
            coord_node: 2,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            ballot: 9,
            outcome: Some(StrictTerminalOutcome::Abort(StrictDecisionAbort {})),
            resolver_node: 0,
            resolver_boot_epoch: 0,
            frozen_targets: Vec::new(),
        }];
        rt.dispatch(2, 1, false, StrictBody::CatchupResp(response))
            .await;
        rt.dispatch(
            2,
            1,
            false,
            StrictBody::ResolutionPrepare(StrictResolutionPrepare {
                resolver_node: 2,
                ballot: 9,
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                src_clock: 9,
                frozen_targets: Vec::new(),
            }),
        )
        .await;

        let state = rt.state.lock();
        assert_eq!(state.clock, 0);
        assert!(state.pending_proposes.is_empty());
        assert!(state.terminal_decisions.is_empty());
        assert!(state.commit_buffer.is_empty());
        drop(state);
        assert!(net.drain_captures().is_empty());
    }

    #[tokio::test]
    async fn authenticated_stale_incarnation_frames_are_dropped() {
        let (rt, net, _repo) = v1_runtime(ReplicationConfig::default());
        let op_id = make_op_id(2, 1, 59);
        net.set_epoch(2, 2);

        rt.dispatch(
            2,
            1,
            true,
            StrictBody::ClockTick(StrictClockTick {
                src_node: 2,
                src_clock: u64::MAX,
            }),
        )
        .await;

        let mut response = strict_probe_resp(2, 0, 0, 0);
        response.terminal_states = vec![StrictTerminalState {
            coord_node: 2,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            ballot: 9,
            outcome: Some(StrictTerminalOutcome::Abort(StrictDecisionAbort {})),
            resolver_node: 0,
            resolver_boot_epoch: 0,
            frozen_targets: Vec::new(),
        }];
        rt.dispatch(2, 1, true, StrictBody::CatchupResp(response))
            .await;

        let state = rt.state.lock();
        assert!(!state.peer_clocks.contains_key(&2));
        assert!(!state.terminal_decisions.contains_key(&op_id));
    }

    #[tokio::test]
    async fn member_restart_discards_incarnation_scoped_catchup_caches() {
        use crate::overlay::MemberIncarnation;

        let (rt, net, _repo) = v1_runtime(ReplicationConfig::default());
        rt.seed_membership_snapshot([MemberIncarnation::new(2, 1)]);
        rt.terminal_catchup_snapshots.lock().insert(
            2,
            TerminalCatchupSnapshot {
                records: Vec::new(),
                terminal_decision_generation: 7,
                last_used_at: Instant::now(),
            },
        );
        rt.remember_terminal_decision_generation(2, 7);
        let rank = HistoryRank {
            version: 0,
            freshness: 0,
            runtime_started_at: 0,
            node_id: 2,
        };
        rt.snapshot_transfers.lock().insert(
            2,
            SnapshotTransfer {
                id: 1,
                version: 0,
                snapshot_msgpack: Bytes::new(),
                snapshot_sha256: Bytes::new(),
                rank: rank.clone(),
                terminal_decision_generation: 7,
                last_used_at: Instant::now(),
            },
        );
        rt.snapshot_receivers.lock().insert(
            2,
            SnapshotReceiveTransfer {
                id: 1,
                version: 0,
                total_bytes: 0,
                snapshot_sha256: Bytes::new(),
                rank,
                terminal_decision_generation: 7,
                next_cursor: 0,
                snapshot_msgpack: Vec::new(),
                last_used_at: Instant::now(),
            },
        );

        net.set_epoch(2, 2);
        rt.on_membership_change(&MembershipEvent::Restarted(MemberIncarnation::new(2, 2)));

        assert!(rt.terminal_catchup_snapshots.lock().get(&2).is_none());
        assert_eq!(rt.remembered_terminal_decision_generation(2), 0);
        assert!(rt.snapshot_transfers.lock().get(&2).is_none());
        assert!(rt.snapshot_receivers.lock().get(&2).is_none());
    }

    #[tokio::test]
    async fn v1_normal_accept_rejects_nonzero_ballot() {
        let (rt, net, _repo) = v1_runtime(ReplicationConfig::default());
        let op_id = make_op_id(2, 1, 30);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&130u64).unwrap());
        rt.recv_propose_v1(
            2,
            StrictProposeV1 {
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_propose: 30,
                op_msgpack: op_msgpack.clone(),
                src_clock: 30,
                protocol_version: STRICT_PROTOCOL_VERSION_V1,
                frozen_targets: Vec::new(),
            },
        )
        .await;
        net.drain_captures();

        rt.recv_accept(
            2,
            StrictAccept {
                coord_node: 2,
                ballot: 1,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_final: 31,
                op_msgpack,
                src_clock: 31,
            },
        )
        .await;

        let state = rt.state.lock();
        assert!(!state.pending_proposes.contains_key(&op_id));
        assert!(!state.accepted_values.contains_key(&op_id));
        drop(state);
        assert!(!net.drain_captures().iter().any(|frame| {
            matches!(
                frame,
                CapturedFrame::StrictUnicast {
                    body: StrictBody::AcceptAck(_),
                    ..
                }
            )
        }));
    }

    #[tokio::test]
    async fn v1_normal_accept_ack_rejects_nonzero_ballot() {
        let (rt, net, _repo) = v1_runtime(ReplicationConfig::default());
        let (delivered_tx, _delivered_rx) = oneshot::channel();
        rt.clone()
            .begin_propose(131u64, delivered_tx)
            .await
            .unwrap();
        let op_id = *rt
            .state
            .lock()
            .proposals
            .keys()
            .next()
            .expect("local proposal must be registered");
        net.drain_captures();

        rt.recv_propose_ack(
            2,
            StrictProposeAck {
                ack_node: 2,
                coord_node: 1,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_local: 2,
                src_clock: 2,
                ack_boot_epoch: 1,
            },
        )
        .await;
        assert!(
            rt.state.lock().proposals[&op_id]
                .accept_acks
                .contains_key(&1)
        );
        net.drain_captures();

        rt.recv_accept_ack(
            2,
            StrictAcceptAck {
                ack_node: 2,
                coord_node: 1,
                ballot: 1,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                accepted: true,
                src_clock: 3,
                ack_boot_epoch: 0,
            },
        )
        .await;

        let state = rt.state.lock();
        assert!(!state.proposals[&op_id].accept_acks.contains_key(&2));
        assert!(!state.terminal_decisions.contains_key(&op_id));
    }

    #[tokio::test]
    async fn v2_accept_retries_peers_without_a_positive_ack_and_commits() {
        let cfg = ReplicationConfig::default()
            .with_delivery_tick_interval(Duration::from_millis(1))
            .with_propose_ttl(Duration::from_secs(1));
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 1);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo,
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(cfg),
        );
        rt.finish_history_election_for_test();

        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (delivered_tx, _delivered_rx) = oneshot::channel();
        rt.clone()
            .begin_propose_with_accepted(132u64, Some(accepted_tx), delivered_tx)
            .await
            .unwrap();
        let op_id = *rt
            .state
            .lock()
            .proposals
            .keys()
            .next()
            .expect("local proposal must be registered");
        net.drain_captures();

        rt.recv_propose_ack(
            2,
            StrictProposeAck {
                ack_node: 2,
                coord_node: 1,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_local: 2,
                src_clock: 2,
                ack_boot_epoch: 1,
            },
        )
        .await;
        let initial_accept = net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictMulticast {
                    dsts,
                    body: StrictBody::Accept(accept),
                    ..
                } => Some((dsts, accept)),
                _ => None,
            })
            .expect("phase one quorum must send a phase-two accept");
        assert_eq!(initial_accept.0, vec![2]);

        // A delayed Propose can make the first Accept rejectable. It must
        // remain eligible for repair until it positively accepts the same
        // phase-two value.
        rt.recv_accept_ack(
            2,
            StrictAcceptAck {
                ack_node: 2,
                coord_node: 1,
                ballot: NORMAL_ACCEPT_BALLOT,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                accepted: false,
                src_clock: 3,
                ack_boot_epoch: 1,
            },
        )
        .await;
        assert_eq!(
            rt.state.lock().proposals[&op_id].accept_acks.get(&2),
            Some(&false)
        );

        let mut retried_accept = None;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            retried_accept = net
                .drain_captures()
                .into_iter()
                .find_map(|frame| match frame {
                    CapturedFrame::StrictMulticast {
                        dsts,
                        body: StrictBody::Accept(accept),
                        ..
                    } => Some((dsts, accept)),
                    _ => None,
                });
            if retried_accept.is_some() {
                break;
            }
        }
        let (retry_dsts, retry_accept) =
            retried_accept.expect("phase-two repair must retry a non-positive peer");
        assert_eq!(retry_dsts, vec![2]);
        assert_eq!(retry_accept, initial_accept.1);

        rt.recv_accept_ack(
            2,
            StrictAcceptAck {
                ack_node: 2,
                coord_node: 1,
                ballot: NORMAL_ACCEPT_BALLOT,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                accepted: true,
                src_clock: 4,
                ack_boot_epoch: 1,
            },
        )
        .await;
        accepted_rx
            .await
            .expect("positive phase-two quorum must complete the proposal");
        let state = rt.state.lock();
        assert!(state.proposals[&op_id].committed);
        assert!(matches!(
            state.terminal_decisions.get(&op_id),
            Some(TerminalDecision::Commit(_))
        ));
    }

    #[tokio::test]
    async fn v2_phase_two_keeps_repairing_frozen_targets_that_missed_propose() {
        let cfg = ReplicationConfig::default()
            .with_delivery_tick_interval(Duration::from_millis(1))
            .with_propose_ttl(Duration::from_secs(1));
        let net = MockNet::new(1, vec![1, 2, 3, 4]);
        for node in 1..=4 {
            net.set_epoch(node, 1);
        }
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(cfg),
        );
        rt.finish_history_election_for_test();

        let (delivered_tx, _delivered_rx) = oneshot::channel();
        rt.clone()
            .begin_propose(141u64, delivered_tx)
            .await
            .unwrap();
        let op_id = *rt
            .state
            .lock()
            .proposals
            .keys()
            .next()
            .expect("local proposal must be registered");
        net.drain_captures();

        // Self plus nodes 2 and 3 form the 3-of-4 fast quorum. Node 4 has
        // not seen the proposal, so the first Accept it receives would be
        // correctly rejected until a retry restores the frozen descriptor.
        for ack_node in [2, 3] {
            rt.recv_propose_ack(
                ack_node,
                StrictProposeAck {
                    ack_node: ack_node as u32,
                    coord_node: 1,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    ts_local: u64::from(ack_node),
                    src_clock: u64::from(ack_node),
                    ack_boot_epoch: 1,
                },
            )
            .await;
        }
        assert!(rt.state.lock().proposals[&op_id].accept_started);
        net.drain_captures();

        let mut repair = None;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            repair = net
                .drain_captures()
                .into_iter()
                .find_map(|frame| match frame {
                    CapturedFrame::StrictMulticast {
                        dsts,
                        body: StrictBody::ProposeV1(propose),
                        ..
                    } if (propose.op_id_hi, propose.op_id_lo) == op_id => Some((dsts, propose)),
                    _ => None,
                });
            if repair.is_some() {
                break;
            }
        }
        let (dsts, repair) = repair.expect("phase two must continue repairing a missed proposal");
        assert_eq!(dsts, vec![4]);
        assert_eq!(repair.protocol_version, STRICT_PROTOCOL_VERSION_V2);
        assert_eq!(repair.frozen_targets.len(), 4);
    }

    #[tokio::test]
    async fn v2_propose_retries_after_a_late_phase_one_ack_until_ttl() {
        let cfg = ReplicationConfig::default()
            .with_delivery_tick_interval(Duration::from_millis(1))
            .with_propose_ttl(Duration::from_secs(1));
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 1);
        net.set_epoch(3, 1);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(cfg),
        );
        rt.finish_history_election_for_test();

        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (delivered_tx, _delivered_rx) = oneshot::channel();
        rt.clone()
            .begin_propose_with_accepted(133u64, Some(accepted_tx), delivered_tx)
            .await
            .unwrap();
        let op_id = *rt
            .state
            .lock()
            .proposals
            .keys()
            .next()
            .expect("local proposal must be registered");
        net.drain_captures();

        // The former fixed 80-tick retry cap ended before the proposal TTL.
        // Let that interval pass before one phase-one acknowledgement appears.
        tokio::time::sleep(Duration::from_millis(120)).await;
        net.drain_captures();
        rt.recv_propose_ack(
            2,
            StrictProposeAck {
                ack_node: 2,
                coord_node: 1,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_local: 2,
                src_clock: 2,
                ack_boot_epoch: 1,
            },
        )
        .await;

        let mut retry_to_last_peer = None;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            retry_to_last_peer = net
                .drain_captures()
                .into_iter()
                .find_map(|frame| match frame {
                    CapturedFrame::StrictMulticast {
                        dsts,
                        body: StrictBody::ProposeV1(propose),
                        ..
                    } if dsts == vec![3] => Some(propose),
                    _ => None,
                });
            if retry_to_last_peer.is_some() {
                break;
            }
        }
        let retry = retry_to_last_peer
            .expect("a late phase-one ack must leave retries active through the proposal TTL");
        assert_eq!((retry.op_id_hi, retry.op_id_lo), op_id);

        rt.recv_propose_ack(
            3,
            StrictProposeAck {
                ack_node: 3,
                coord_node: 1,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_local: 3,
                src_clock: 3,
                ack_boot_epoch: 1,
            },
        )
        .await;
        rt.recv_accept_ack(
            2,
            StrictAcceptAck {
                ack_node: 2,
                coord_node: 1,
                ballot: NORMAL_ACCEPT_BALLOT,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                accepted: true,
                src_clock: 4,
                ack_boot_epoch: 1,
            },
        )
        .await;
        rt.recv_accept_ack(
            3,
            StrictAcceptAck {
                ack_node: 3,
                coord_node: 1,
                ballot: NORMAL_ACCEPT_BALLOT,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                accepted: true,
                src_clock: 5,
                ack_boot_epoch: 1,
            },
        )
        .await;
        accepted_rx
            .await
            .expect("late phase-one quorum must still complete the proposal");
        assert!(matches!(
            rt.state.lock().terminal_decisions.get(&op_id),
            Some(TerminalDecision::Commit(_))
        ));
    }

    #[tokio::test]
    async fn v2_phase_one_quorum_waits_for_protocol_floor_before_accept() {
        let cfg = ReplicationConfig::default()
            .with_delivery_tick_interval(Duration::from_secs(5))
            .with_propose_ttl(Duration::from_secs(10));
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 1);
        net.set_epoch(3, 1);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        net.set_local_strict_replication_protocol_version(Some(STRICT_PROTOCOL_VERSION_V2));
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(cfg),
        );
        rt.finish_history_election_for_test();

        let (delivered_tx, _delivered_rx) = oneshot::channel();
        rt.clone()
            .begin_propose(137u64, delivered_tx)
            .await
            .unwrap();
        let op_id = *rt
            .state
            .lock()
            .proposals
            .keys()
            .next()
            .expect("local proposal must be registered");
        net.drain_captures();

        // Model a remote LSA momentarily lowering the negotiated floor while
        // the local repository remains capable of retaining its v2 fence.
        net.set_strict_replication_protocol_version(0);
        assert!(rt.local_v2_participation_ready());
        assert_eq!(rt.current_protocol_version(), 0);

        for (node, clock) in [(2, 2), (3, 3)] {
            rt.recv_propose_ack(
                node,
                StrictProposeAck {
                    ack_node: node as u32,
                    coord_node: 1,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    ts_local: clock,
                    src_clock: clock,
                    ack_boot_epoch: 1,
                },
            )
            .await;
        }

        {
            let state = rt.state.lock();
            let proposal = &state.proposals[&op_id];
            assert_eq!(proposal.acks.len(), 3, "the frozen ACK quorum is retained");
            assert!(
                !proposal.accept_started,
                "a v0 floor must not emit phase two through a legacy relay"
            );
        }
        assert!(
            !net.drain_captures().iter().any(|frame| matches!(
                frame,
                CapturedFrame::StrictMulticast {
                    body: StrictBody::Accept(_),
                    ..
                }
            )),
            "a legacy floor must not receive a v2 phase-two frame"
        );

        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        rt.resume_v2_accept_from_phase_one_quorum(op_id).await;

        let mut accept_dsts = net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictMulticast {
                    dsts,
                    body: StrictBody::Accept(accept),
                    ..
                } if (accept.op_id_hi, accept.op_id_lo) == op_id => Some(dsts),
                _ => None,
            })
            .expect("a retained phase-one quorum must resume once the floor recovers");
        accept_dsts.sort_unstable();
        assert_eq!(accept_dsts, vec![2, 3]);
        assert!(rt.state.lock().proposals[&op_id].accept_started);
    }

    #[tokio::test]
    async fn v2_frozen_phase_responses_survive_transient_member_unreachability() {
        let (rt, net, _repo) = v1_runtime(ReplicationConfig::default());
        let (delivered_tx, _delivered_rx) = oneshot::channel();
        rt.clone()
            .begin_propose(140u64, delivered_tx)
            .await
            .unwrap();
        let op_id = *rt
            .state
            .lock()
            .proposals
            .keys()
            .next()
            .expect("local proposal must be registered");
        net.drain_captures();

        // The peer's current incarnation remains known, but a route flap has
        // temporarily removed it from the liveness view. Its signed frozen
        // phase responses were still durably made and must count.
        net.set_alive(vec![1]);
        rt.recv_propose_ack(
            2,
            StrictProposeAck {
                ack_node: 2,
                coord_node: 1,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_local: 2,
                src_clock: 2,
                ack_boot_epoch: 1,
            },
        )
        .await;
        rt.recv_accept_ack(
            2,
            StrictAcceptAck {
                ack_node: 2,
                coord_node: 1,
                ballot: NORMAL_ACCEPT_BALLOT,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                accepted: true,
                src_clock: 3,
                ack_boot_epoch: 1,
            },
        )
        .await;

        assert!(matches!(
            rt.state.lock().terminal_decisions.get(&op_id),
            Some(TerminalDecision::Commit(_))
        ));
    }

    #[tokio::test]
    async fn durable_v2_pending_fence_uses_terminal_only_repair_while_election_is_idle() {
        let (rt, net, _repo) = v1_runtime(ReplicationConfig::default());
        let op_id = make_op_id(2, 1, 138);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&138u64).unwrap());
        {
            let mut state = rt.state.lock();
            state.record_pending_propose_with_descriptor(
                op_id,
                2,
                op_msgpack,
                10,
                Instant::now(),
                STRICT_PROTOCOL_VERSION_V2,
                Some(v2_frozen_targets()),
                true,
            );
            // A pending fence correctly prevents bootstrap from starting, but
            // terminal-only repair must remain available in this Idle state.
            state.request_history_election();
            assert!(!state.history_election_active());
        }
        net.drain_captures();

        assert!(request_terminal_repair_probe(&rt).await);
        assert!(net.drain_captures().iter().any(|frame| {
            matches!(
                frame,
                CapturedFrame::StrictUnicast {
                    dst: 2,
                    body: StrictBody::CatchupReq(StrictCatchupReq {
                        since_version: 0,
                        chunk_token: 0,
                        force_snapshot: false,
                        history_probe_only: true,
                        terminal_state_cursor: 0,
                        terminal_decision_generation: 0,
                        snapshot_transfer_id: 0,
                        snapshot_chunk_cursor: 0,
                        ..
                    }),
                    ..
                }
            )
        }));
    }

    #[tokio::test]
    async fn stale_v2_pending_fence_starts_resolution_before_the_full_proposal_ttl() {
        let cfg = ReplicationConfig::default();
        let (rt, net, _repo) = v1_runtime(cfg.clone());
        let op_id = make_op_id(2, 1, 140);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&140u64).unwrap());
        let frozen_targets = v2_frozen_targets();
        let stale_at =
            Instant::now() - cfg.propose_ttl().checked_div(2).unwrap() - Duration::from_millis(1);
        rt.state.lock().record_pending_propose_with_descriptor(
            op_id,
            2,
            op_msgpack.clone(),
            10,
            stale_at,
            STRICT_PROTOCOL_VERSION_V2,
            Some(frozen_targets.clone()),
            false,
        );
        assert!(rt.persist_v2_pending_descriptor(op_id, 10, op_msgpack.clone(), &frozen_targets,));
        net.drain_captures();

        assert!(request_terminal_repair_probe(&rt).await);
        let captures = net.drain_captures();
        assert!(captures.iter().any(|frame| {
            matches!(
                frame,
                CapturedFrame::StrictMulticast {
                    dsts,
                    body: StrictBody::ResolutionPrepare(prepare),
                    ..
                } if dsts == &vec![2]
                    && prepare.op_id_hi == op_id.0
                    && prepare.op_id_lo == op_id.1
            )
        }));
        assert!(captures.iter().any(|frame| {
            matches!(
                frame,
                CapturedFrame::StrictUnicast {
                    dst: 2,
                    body: StrictBody::CatchupReq(StrictCatchupReq {
                        history_probe_only: true,
                        terminal_state_cursor: 0,
                        ..
                    }),
                    ..
                }
            )
        }));
        rt.shutdown.cancel();
    }

    #[tokio::test]
    async fn v2_terminal_probe_replies_with_a_directed_fresh_clock_tick() {
        let (rt, net, _repo) = v1_runtime(ReplicationConfig::default());
        net.drain_captures();

        rt.recv_catchup_req(
            2,
            StrictCatchupReq {
                src_node: 2,
                since_version: 0,
                chunk_token: 0,
                force_snapshot: false,
                history_probe_only: true,
                terminal_state_cursor: 0,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
            },
        )
        .await;

        assert!(net.drain_captures().iter().any(|frame| {
            matches!(
                frame,
                CapturedFrame::StrictUnicast {
                    dst: 2,
                    body: StrictBody::ClockTick(StrictClockTick { src_node: 1, src_clock }),
                    ..
                } if *src_clock > 0
            )
        }));
    }

    #[tokio::test]
    async fn terminal_repair_probe_installs_a_missed_v2_decision_before_pending_ttl() {
        let source_net = MockNet::new(1, vec![1, 2]);
        source_net.set_epoch(1, 1);
        source_net.set_epoch(2, 1);
        source_net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let source = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            source_net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        source.finish_history_election_for_test();

        let sink_net = MockNet::new(2, vec![1, 2]);
        sink_net.set_epoch(1, 1);
        sink_net.set_epoch(2, 1);
        sink_net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let sink_repo = CountingStrictRepo::new();
        let sink = StrictRuntime::new(
            sink_repo.clone(),
            2,
            1,
            "channels".to_owned(),
            sink_net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        sink.finish_history_election_for_test();

        let op_id = make_op_id(1, 1, 139);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&139u64).unwrap());
        let identity = TerminalDecisionIdentity {
            resolver: TerminalResolver::new(1, 1),
            frozen_targets: v2_frozen_targets(),
        };
        assert!(source.apply_terminal_commit_with_descriptor(
            op_id,
            NORMAL_ACCEPT_BALLOT,
            20,
            op_msgpack.clone(),
            Some(&identity),
        ));
        {
            let mut state = sink.state.lock();
            state.record_pending_propose_with_descriptor(
                op_id,
                1,
                op_msgpack,
                10,
                Instant::now(),
                STRICT_PROTOCOL_VERSION_V2,
                Some(v2_frozen_targets()),
                true,
            );
            state.request_history_election();
        }
        sink_net.drain_captures();
        source_net.drain_captures();

        assert!(request_terminal_repair_probe(&sink).await);
        let request = sink_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    dst: 1,
                    body: StrictBody::CatchupReq(request),
                    ..
                } => Some(request),
                _ => None,
            })
            .expect("sink must request the missing terminal decision from its frozen peer");
        source.recv_catchup_req(2, request).await;
        let response = source_net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictUnicast {
                    dst: 2,
                    body: StrictBody::CatchupResp(response),
                    ..
                } => Some(response),
                _ => None,
            })
            .expect("source must return the durable terminal decision");

        sink.recv_catchup_resp(1, response).await;
        assert!(!sink.state.lock().pending_proposes.contains_key(&op_id));
        assert!(matches!(
            sink.state.lock().terminal_decisions.get(&op_id),
            Some(TerminalDecision::Commit(value)) if value.ts_final == 20
        ));
        {
            let mut state = sink.state.lock();
            state.clock = 21;
            state.peer_clocks.insert(1, 21);
            state.peer_clocks.insert(2, 21);
        }
        run_delivery_pass(&sink).await;
        assert_eq!(sink_repo.log(), vec![(1, 139)]);
    }

    #[tokio::test]
    async fn proposal_deadline_releases_a_committed_but_undelivered_proposal() {
        let propose_ttl = Duration::from_millis(10);
        let cfg = ReplicationConfig::default().with_propose_ttl(propose_ttl);
        let net = MockNet::new(1, vec![1]);
        net.set_epoch(1, 1);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net,
            CancellationToken::new(),
            Arc::new(cfg),
        );
        rt.finish_history_election_for_test();

        let (delivered_tx, delivered_rx) = oneshot::channel();
        rt.clone()
            .begin_propose(134u64, delivered_tx)
            .await
            .unwrap();
        let op_id = *rt
            .state
            .lock()
            .proposals
            .keys()
            .next()
            .expect("single-node proposal must remain buffered without the delivery loop");
        assert!(rt.state.lock().proposals[&op_id].committed);
        assert!(matches!(
            rt.state.lock().terminal_decisions.get(&op_id),
            Some(TerminalDecision::Commit(_))
        ));

        assert!(matches!(
            delivered_rx.await,
            Ok(Err(ReplicationError::ProposeTimeout(timeout))) if timeout == propose_ttl
        ));
        assert!(!rt.state.lock().proposals.contains_key(&op_id));
        assert!(rt.state.lock().terminal_decisions.contains_key(&op_id));
    }

    #[tokio::test]
    async fn proposal_deadline_hands_an_unresolved_v2_fence_to_terminal_resolution() {
        let propose_ttl = Duration::from_millis(10);
        let cfg = ReplicationConfig::default().with_propose_ttl(propose_ttl);
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 1);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(cfg),
        );
        rt.finish_history_election_for_test();

        let (delivered_tx, delivered_rx) = oneshot::channel();
        rt.clone()
            .begin_propose(135u64, delivered_tx)
            .await
            .unwrap();
        let op_id = *rt
            .state
            .lock()
            .proposals
            .keys()
            .next()
            .expect("unacknowledged proposal must remain registered");
        net.drain_captures();

        assert!(matches!(
            delivered_rx.await,
            Ok(Err(ReplicationError::ProposeTimeout(timeout))) if timeout == propose_ttl
        ));
        assert!(!rt.state.lock().proposals.contains_key(&op_id));
        assert!(rt.state.lock().pending_proposes.contains_key(&op_id));

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(net.drain_captures().iter().any(|frame| {
            matches!(
                frame,
                CapturedFrame::StrictMulticast {
                    body: StrictBody::ResolutionPrepare(prepare),
                    ..
                } if prepare.op_id_hi == op_id.0 && prepare.op_id_lo == op_id.1
            )
        }));
    }

    #[tokio::test]
    async fn gc_expiry_hands_an_unresolved_v2_fence_to_terminal_resolution() {
        let propose_ttl = Duration::from_secs(1);
        let cfg = ReplicationConfig::default().with_propose_ttl(propose_ttl);
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 1);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(cfg),
        );
        rt.finish_history_election_for_test();

        let (delivered_tx, mut delivered_rx) = oneshot::channel();
        rt.clone()
            .begin_propose(136u64, delivered_tx)
            .await
            .unwrap();
        let op_id = *rt
            .state
            .lock()
            .proposals
            .keys()
            .next()
            .expect("unacknowledged proposal must remain registered");
        rt.state
            .lock()
            .proposals
            .get_mut(&op_id)
            .unwrap()
            .started_at = Instant::now() - propose_ttl - Duration::from_millis(1);
        net.drain_captures();

        run_gc_pass(&rt);

        assert!(matches!(
            delivered_rx.try_recv(),
            Ok(Err(ReplicationError::ProposeTimeout(timeout))) if timeout == propose_ttl
        ));
        assert!(!rt.state.lock().proposals.contains_key(&op_id));
        assert!(rt.state.lock().pending_proposes.contains_key(&op_id));

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(net.drain_captures().iter().any(|frame| {
            matches!(
                frame,
                CapturedFrame::StrictMulticast {
                    body: StrictBody::ResolutionPrepare(prepare),
                    ..
                } if prepare.op_id_hi == op_id.0 && prepare.op_id_lo == op_id.1
            )
        }));
    }

    #[tokio::test]
    async fn terminal_fanout_retries_after_the_former_fixed_window() {
        let net = MockNet::new(1, vec![1, 2]);
        let shutdown = CancellationToken::new();
        let body = StrictBody::Decision(StrictDecision {
            resolver_node: 1,
            ballot: NORMAL_ACCEPT_BALLOT,
            coord_node: 1,
            op_id_hi: make_op_id(1, 1, 135).0,
            op_id_lo: make_op_id(1, 1, 135).1,
            outcome: Some(StrictDecisionOutcome::Abort(StrictDecisionAbort {})),
            src_clock: 1,
            resolver_boot_epoch: 1,
            frozen_targets: vec![StrictFrozenTarget {
                node: 1,
                boot_epoch: 1,
            }],
        });
        spawn_commit_fanout_retries(
            net.clone(),
            shutdown.clone(),
            "channels".to_owned(),
            vec![2],
            body.clone(),
            Duration::from_millis(1),
            Duration::from_secs(1),
        );

        // Simulate an unavailable route for longer than the old 80-tick
        // fanout cap, then observe a fresh terminal decision retry after the
        // production repair cadence's backoff interval.
        tokio::time::sleep(Duration::from_millis(120)).await;
        net.drain_captures();
        let mut late_retry = None;
        for _ in 0..130 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            late_retry = net
                .drain_captures()
                .into_iter()
                .find_map(|frame| match frame {
                    CapturedFrame::StrictMulticast {
                        dsts,
                        body: captured,
                        ..
                    } if dsts == vec![2] => Some(captured),
                    _ => None,
                });
            if late_retry.is_some() {
                break;
            }
        }
        shutdown.cancel();
        assert_eq!(
            late_retry.expect("terminal fanout must outlive the former fixed retry window"),
            body
        );
    }

    #[tokio::test]
    async fn v1_ballot_zero_decision_requires_coordinator_resolver() {
        let (rt, _net, _repo) = v1_runtime(ReplicationConfig::default());
        let op_id = make_op_id(2, 1, 31);
        rt.recv_decision(
            1,
            StrictDecision {
                resolver_node: 1,
                ballot: NORMAL_ACCEPT_BALLOT,
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                outcome: Some(StrictDecisionOutcome::Abort(StrictDecisionAbort {})),
                src_clock: 31,
                resolver_boot_epoch: 0,
                frozen_targets: Vec::new(),
            },
        )
        .await;

        assert!(!rt.state.lock().terminal_decisions.contains_key(&op_id));
    }

    #[tokio::test]
    async fn accepted_value_beats_abort_and_is_rebroadcast_with_resolution_ballot() {
        let (rt, net, _repo) = v1_runtime(ReplicationConfig::default());
        let op_id = make_op_id(2, 1, 4);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&88u64).unwrap());
        rt.recv_propose_v1(
            2,
            StrictProposeV1 {
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_propose: 4,
                op_msgpack: op_msgpack.clone(),
                src_clock: 4,
                protocol_version: STRICT_PROTOCOL_VERSION_V2,
                frozen_targets: v2_frozen_targets_wire(),
            },
        )
        .await;
        rt.recv_accept(
            2,
            StrictAccept {
                coord_node: 2,
                ballot: NORMAL_ACCEPT_BALLOT,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_final: 9,
                op_msgpack: op_msgpack.clone(),
                src_clock: 9,
            },
        )
        .await;

        net.drain_captures();
        rt.start_resolution(op_id, 2, None, v2_frozen_targets())
            .await;
        let prepare = net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictMulticast {
                    body: StrictBody::ResolutionPrepare(prepare),
                    ..
                } => Some(prepare),
                _ => None,
            })
            .expect("accepted value must enter terminal resolution");
        rt.recv_resolution_ack_with_origin_epoch(
            2,
            1,
            StrictResolutionAck {
                ack_node: 2,
                ballot: prepare.ballot,
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                promised: true,
                observed: None,
                src_clock: 10,
                ack_boot_epoch: 1,
            },
        )
        .await;

        {
            let state = rt.state.lock();
            assert!(matches!(
                state.terminal_decisions.get(&op_id),
                Some(TerminalDecision::Commit(value))
                    if value.ballot == prepare.ballot
                        && value.ts_final == 9
                        && value.op_msgpack == op_msgpack
            ));
        }

        rt.recv_decision(
            2,
            StrictDecision {
                resolver_node: 2,
                ballot: prepare.ballot + 1,
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                outcome: Some(StrictDecisionOutcome::Abort(StrictDecisionAbort {})),
                src_clock: 11,
                resolver_boot_epoch: 1,
                frozen_targets: v2_frozen_targets_wire(),
            },
        )
        .await;
        assert!(matches!(
            rt.state.lock().terminal_decisions.get(&op_id),
            Some(TerminalDecision::Commit(value)) if value.ts_final == 9 && value.op_msgpack == op_msgpack
        ));
    }

    #[tokio::test]
    async fn late_ordinary_commit_is_fenced_after_terminal_abort() {
        let (rt, _net, repo) = v1_runtime(ReplicationConfig::default());
        let op_id = make_op_id(2, 1, 5);
        rt.recv_decision(
            2,
            StrictDecision {
                resolver_node: 2,
                ballot: 10,
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                outcome: Some(StrictDecisionOutcome::Abort(StrictDecisionAbort {})),
                src_clock: 10,
                resolver_boot_epoch: 0,
                frozen_targets: Vec::new(),
            },
        )
        .await;
        rt.recv_commit(
            2,
            StrictCommit {
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_final: 11,
                op_msgpack: Bytes::from(rmp_serde::to_vec(&89u64).unwrap()),
                src_clock: 11,
            },
        )
        .await;

        let state = rt.state.lock();
        assert!(!state.committed_ids.contains(&op_id));
        assert!(
            !state
                .commit_buffer
                .values()
                .any(|buffered| buffered.op_id == op_id)
        );
        assert!(repo.log().is_empty());
    }

    #[tokio::test]
    async fn legacy_recovery_does_not_start_for_v1_pending_proposals() {
        let (rt, net, _repo) = v1_runtime(ReplicationConfig::default());
        let op_id = make_op_id(2, 1, 6);
        rt.state.lock().record_pending_propose_with_protocol(
            op_id,
            2,
            Bytes::from(rmp_serde::to_vec(&90u64).unwrap()),
            6,
            Instant::now(),
            STRICT_PROTOCOL_VERSION_V1,
        );

        rt.maybe_initiate_recovery(2).await;

        assert!(!rt.recoveries.lock().contains_key(&op_id));
        assert!(!net.captures().iter().any(|frame| {
            matches!(
                frame,
                CapturedFrame::StrictMulticast {
                    body: StrictBody::RecoveryReq(_),
                    ..
                }
            )
        }));
    }

    #[tokio::test]
    async fn mixed_capability_coordinator_loss_suspends_then_retries_v2_resolution() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 1);
        net.set_epoch(3, 1);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        rt.finish_history_election_for_test();
        let op_id = make_op_id(2, 1, 32);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&132u64).unwrap());
        let frozen_targets = vec![
            FrozenTarget::new(1, 1),
            FrozenTarget::new(2, 1),
            FrozenTarget::new(3, 1),
        ];
        rt.recv_propose_v1(
            2,
            StrictProposeV1 {
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_propose: 32,
                op_msgpack: op_msgpack.clone(),
                src_clock: 32,
                protocol_version: STRICT_PROTOCOL_VERSION_V2,
                frozen_targets: frozen_targets_to_wire(&frozen_targets),
            },
        )
        .await;
        rt.recv_accept(
            2,
            StrictAccept {
                coord_node: 2,
                ballot: NORMAL_ACCEPT_BALLOT,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_final: 33,
                op_msgpack: op_msgpack.clone(),
                src_clock: 33,
            },
        )
        .await;
        net.drain_captures();

        // The coordinator dies while a legacy relay is active. The v2
        // operation stays durably fenced, but must neither fall back to the
        // legacy recovery protocol nor start a fresh terminal ballot that a
        // relay might not carry.
        net.set_alive(vec![1, 3]);
        net.set_strict_replication_protocol_version(0);
        rt.maybe_initiate_recovery(2).await;
        rt.resume_lost_v2_coordinator_resolutions().await;

        {
            let state = rt.state.lock();
            assert!(state.pending_proposes.contains_key(&op_id));
            assert!(state.accepted_values.contains_key(&op_id));
            assert!(!state.terminal_decisions.contains_key(&op_id));
        }
        assert!(
            rt.terminal_journal
                .lock()
                .get(op_id)
                .is_some_and(|record| record.accepted_commit().is_some())
        );
        assert!(!net.drain_captures().iter().any(|frame| {
            matches!(
                frame,
                CapturedFrame::StrictMulticast {
                    body: StrictBody::RecoveryReq(_)
                        | StrictBody::ResolutionPrepare(_)
                        | StrictBody::Decision(_),
                    ..
                }
            )
        }));

        // Once the cumulative floor returns to v2, the same durable barrier
        // immediately re-drives terminal resolution against the remaining
        // old-configuration cohort.
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        rt.resume_lost_v2_coordinator_resolutions().await;
        let prepare = net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictMulticast {
                    dsts,
                    body: StrictBody::ResolutionPrepare(prepare),
                    ..
                } if dsts == vec![3] => Some(prepare),
                _ => None,
            })
            .expect("capability restoration must re-drive v2 terminal resolution");
        rt.recv_resolution_ack(
            3,
            StrictResolutionAck {
                ack_node: 3,
                ballot: prepare.ballot,
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                promised: true,
                observed: None,
                src_clock: 34,
                ack_boot_epoch: 1,
            },
        )
        .await;

        assert!(matches!(
            rt.state.lock().terminal_decisions.get(&op_id),
            Some(TerminalDecision::Commit(value))
                if value.ts_final == 33 && value.op_msgpack == op_msgpack
        ));
    }

    #[tokio::test]
    async fn v2_resolution_does_not_count_a_restarted_target_toward_the_old_quorum() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 1);
        net.set_epoch(3, 1);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        rt.finish_history_election_for_test();
        let op_id = make_op_id(2, 1, 35);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&135u64).unwrap());
        let frozen_targets = vec![
            FrozenTarget::new(1, 1),
            FrozenTarget::new(2, 1),
            FrozenTarget::new(3, 1),
        ];
        rt.recv_propose_v1(
            2,
            StrictProposeV1 {
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_propose: 35,
                op_msgpack: op_msgpack.clone(),
                src_clock: 35,
                protocol_version: STRICT_PROTOCOL_VERSION_V2,
                frozen_targets: frozen_targets_to_wire(&frozen_targets),
            },
        )
        .await;
        rt.recv_accept(
            2,
            StrictAccept {
                coord_node: 2,
                ballot: NORMAL_ACCEPT_BALLOT,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_final: 36,
                op_msgpack: op_msgpack.clone(),
                src_clock: 36,
            },
        )
        .await;
        net.drain_captures();

        // Node 2 returns under a new incarnation. It remains reachable, but
        // it is unavailable to the frozen [1, 2@1, 3] terminal quorum.
        net.set_epoch(2, 2);
        rt.resume_lost_v2_coordinator_resolutions().await;
        let prepare = net
            .drain_captures()
            .into_iter()
            .find_map(|frame| match frame {
                CapturedFrame::StrictMulticast {
                    body: StrictBody::ResolutionPrepare(prepare),
                    ..
                } => Some(prepare),
                _ => None,
            })
            .expect("old configuration must start a terminal resolution");

        rt.recv_resolution_ack_with_origin_epoch(
            2,
            2,
            StrictResolutionAck {
                ack_node: 2,
                ballot: prepare.ballot,
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                promised: true,
                observed: None,
                src_clock: 37,
                // The replacement lies in the payload with the old epoch;
                // only the authenticated envelope identifies it as 2@2.
                ack_boot_epoch: 1,
            },
        )
        .await;
        assert!(
            !rt.state.lock().terminal_decisions.contains_key(&op_id),
            "a replacement process must not satisfy an old frozen quorum"
        );

        rt.recv_resolution_ack(
            3,
            StrictResolutionAck {
                ack_node: 3,
                ballot: prepare.ballot,
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                promised: true,
                observed: None,
                src_clock: 38,
                ack_boot_epoch: 1,
            },
        )
        .await;

        assert!(matches!(
            rt.state.lock().terminal_decisions.get(&op_id),
            Some(TerminalDecision::Commit(value))
                if value.ts_final == 36 && value.op_msgpack == op_msgpack
        ));
    }

    #[tokio::test]
    async fn v2_retransmit_persists_an_undurable_descriptor_before_acknowledging() {
        let temp = tempfile::TempDir::new().unwrap();
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 1);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let op_id = make_op_id(2, 1, 39);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&139u64).unwrap());
        let frozen_targets = v2_frozen_targets();
        rt.state.lock().record_pending_propose_with_descriptor(
            op_id,
            2,
            op_msgpack.clone(),
            40,
            Instant::now(),
            STRICT_PROTOCOL_VERSION_V2,
            Some(frozen_targets.clone()),
            false,
        );

        rt.recv_propose_v1(
            2,
            StrictProposeV1 {
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_propose: 39,
                op_msgpack: op_msgpack.clone(),
                src_clock: 39,
                protocol_version: STRICT_PROTOCOL_VERSION_V2,
                frozen_targets: frozen_targets_to_wire(&frozen_targets),
            },
        )
        .await;

        assert!(rt.state.lock().pending_proposes[&op_id].v2_descriptor_durable);
        let record = rt
            .terminal_journal
            .lock()
            .get(op_id)
            .cloned()
            .expect("retransmit must durably restore its pending descriptor");
        assert_eq!(record.frozen_targets(), Some(frozen_targets.as_slice()));
        assert!(record.pending_proposal().is_some_and(|pending| {
            pending.ts_local() == 40 && pending.op_msgpack() == op_msgpack.as_ref()
        }));
        assert!(net.drain_captures().iter().any(|frame| {
            matches!(
                frame,
                CapturedFrame::StrictUnicast {
                    dst: 2,
                    body: StrictBody::ProposeAck(StrictProposeAck { op_id_hi, op_id_lo, .. }),
                    ..
                } if (*op_id_hi, *op_id_lo) == op_id
            )
        }));
    }

    #[tokio::test]
    async fn v2_propose_rejects_a_restarted_coordinator_envelope() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 2);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let op_id = make_op_id(2, 1, 45);
        rt.recv_propose_v1_with_origin_epoch(
            2,
            1,
            StrictProposeV1 {
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_propose: 45,
                op_msgpack: Bytes::from(rmp_serde::to_vec(&145u64).unwrap()),
                src_clock: 45,
                protocol_version: STRICT_PROTOCOL_VERSION_V2,
                frozen_targets: v2_frozen_targets_wire(),
            },
        )
        .await;

        assert!(!rt.state.lock().pending_proposes.contains_key(&op_id));
        assert!(!net.drain_captures().iter().any(|frame| {
            matches!(
                frame,
                CapturedFrame::StrictUnicast {
                    body: StrictBody::ProposeAck(StrictProposeAck { op_id_hi, op_id_lo, .. }),
                    ..
                } if (*op_id_hi, *op_id_lo) == op_id
            )
        }));
    }

    #[tokio::test]
    async fn v2_hint_and_prepare_reject_a_restarted_resolver_envelope() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 2);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let op_id = make_op_id(2, 1, 46);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&146u64).unwrap());
        rt.recv_resolution_hint_with_origin_epoch(
            2,
            1,
            StrictResolutionHint {
                reporter_node: 2,
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_local: 46,
                op_msgpack,
                src_clock: 46,
                reporter_boot_epoch: 1,
                protocol_version: STRICT_PROTOCOL_VERSION_V2,
                frozen_targets: v2_frozen_targets_wire(),
            },
        )
        .await;
        assert!(rt.terminal_journal.lock().get(op_id).is_none());

        rt.recv_resolution_prepare_with_origin_epoch(
            2,
            1,
            StrictResolutionPrepare {
                resolver_node: 2,
                ballot: 47,
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                src_clock: 47,
                frozen_targets: v2_frozen_targets_wire(),
            },
        )
        .await;
        assert!(net.drain_captures().iter().any(|frame| {
            matches!(
                frame,
                CapturedFrame::StrictUnicast {
                    dst: 2,
                    body: StrictBody::ResolutionAck(StrictResolutionAck {
                        ballot: 47,
                        promised: false,
                        ..
                    }),
                    ..
                }
            )
        }));
        assert!(rt.terminal_journal.lock().get(op_id).is_none());
    }

    #[tokio::test]
    async fn v2_propose_ack_rejects_a_restarted_target_envelope() {
        let (rt, net, _repo) = v1_runtime(ReplicationConfig::default());
        let (tx, _rx) = oneshot::channel();
        rt.clone().begin_propose(147u64, tx).await.unwrap();
        let op_id = *rt
            .state
            .lock()
            .proposals
            .keys()
            .next()
            .expect("local proposal must be registered");

        net.set_epoch(2, 2);
        rt.recv_propose_ack_with_origin_epoch(
            2,
            2,
            StrictProposeAck {
                ack_node: 2,
                coord_node: 1,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_local: 47,
                src_clock: 47,
                // A replacement can copy the old payload epoch, but not the
                // authenticated overlay envelope epoch.
                ack_boot_epoch: 1,
            },
        )
        .await;

        assert!(!rt.state.lock().proposals[&op_id].acks.contains_key(&2));
    }

    #[tokio::test]
    async fn v2_accept_rejects_a_restarted_coordinator_envelope() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 2);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let op_id = make_op_id(2, 1, 48);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&148u64).unwrap());
        rt.state.lock().record_pending_propose_with_descriptor(
            op_id,
            2,
            op_msgpack.clone(),
            48,
            Instant::now(),
            STRICT_PROTOCOL_VERSION_V2,
            Some(v2_frozen_targets()),
            true,
        );

        rt.recv_accept_with_origin_epoch(
            2,
            2,
            StrictAccept {
                coord_node: 2,
                ballot: NORMAL_ACCEPT_BALLOT,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_final: 49,
                op_msgpack,
                src_clock: 49,
            },
        )
        .await;

        assert!(!rt.state.lock().accepted_values.contains_key(&op_id));
        assert!(net.drain_captures().iter().any(|frame| {
            matches!(
                frame,
                CapturedFrame::StrictUnicast {
                    dst: 2,
                    body: StrictBody::AcceptAck(StrictAcceptAck {
                        accepted: false,
                        ..
                    }),
                    ..
                }
            )
        }));
    }

    #[tokio::test]
    async fn v2_accept_ack_rejects_a_restarted_target_envelope() {
        let (rt, net, _repo) = v1_runtime(ReplicationConfig::default());
        let (tx, _rx) = oneshot::channel();
        rt.clone().begin_propose(150u64, tx).await.unwrap();
        let op_id = *rt
            .state
            .lock()
            .proposals
            .keys()
            .next()
            .expect("local proposal must be registered");
        rt.recv_propose_ack_with_origin_epoch(
            2,
            1,
            StrictProposeAck {
                ack_node: 2,
                coord_node: 1,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_local: 50,
                src_clock: 50,
                ack_boot_epoch: 1,
            },
        )
        .await;
        assert!(rt.state.lock().proposals[&op_id].accept_started);

        net.set_epoch(2, 2);
        rt.recv_accept_ack_with_origin_epoch(
            2,
            2,
            StrictAcceptAck {
                ack_node: 2,
                coord_node: 1,
                ballot: NORMAL_ACCEPT_BALLOT,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                accepted: true,
                src_clock: 51,
                ack_boot_epoch: 1,
            },
        )
        .await;

        let state = rt.state.lock();
        assert!(!state.proposals[&op_id].accept_acks.contains_key(&2));
        assert!(!state.terminal_decisions.contains_key(&op_id));
    }

    #[tokio::test]
    async fn v2_cold_decision_requires_matching_envelope_and_retains_descriptor() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 2);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let op_id = make_op_id(2, 1, 52);
        let decision = StrictDecision {
            resolver_node: 2,
            ballot: 52,
            coord_node: 2,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            outcome: Some(StrictDecisionOutcome::Commit(StrictDecisionCommit {
                ts_final: 53,
                op_msgpack: Bytes::from(rmp_serde::to_vec(&152u64).unwrap()),
            })),
            src_clock: 53,
            resolver_boot_epoch: 1,
            frozen_targets: v2_frozen_targets_wire(),
        };

        rt.recv_decision_with_origin_epoch(2, 2, decision.clone())
            .await;
        assert!(!rt.state.lock().terminal_decisions.contains_key(&op_id));

        // A terminal decision authored by the original resolver remains
        // valid even if it arrives after that resolver has restarted.
        rt.recv_decision_with_origin_epoch(2, 1, decision).await;
        assert!(matches!(
            rt.state.lock().terminal_decisions.get(&op_id),
            Some(TerminalDecision::Commit(value)) if value.ts_final == 53
        ));
        assert_eq!(
            rt.terminal_journal
                .lock()
                .get(op_id)
                .and_then(TerminalJournalRecord::frozen_targets),
            Some(v2_frozen_targets().as_slice())
        );
    }

    #[tokio::test]
    async fn v2_restart_does_not_rehydrate_or_accept_an_old_local_incarnation() {
        let temp = tempfile::TempDir::new().unwrap();
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 1);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));
        let op_id = make_op_id(2, 1, 54);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&154u64).unwrap());
        {
            let rt = StrictRuntime::new(
                CountingStrictRepo::new(),
                1,
                1,
                "channels".to_owned(),
                net.clone(),
                CancellationToken::new(),
                Arc::new(ReplicationConfig::default()),
            );
            rt.recv_propose_v1(
                2,
                StrictProposeV1 {
                    coord_node: 2,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    ts_propose: 54,
                    op_msgpack: op_msgpack.clone(),
                    src_clock: 54,
                    protocol_version: STRICT_PROTOCOL_VERSION_V2,
                    frozen_targets: v2_frozen_targets_wire(),
                },
            )
            .await;
        }

        net.set_epoch(1, 2);
        let recovered = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            2,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        assert!(!recovered.state.lock().pending_proposes.contains_key(&op_id));
        assert!(
            recovered
                .terminal_journal
                .lock()
                .get(op_id)
                .is_some_and(|record| record.pending_proposal().is_some())
        );

        recovered
            .recv_accept_with_origin_epoch(
                2,
                1,
                StrictAccept {
                    coord_node: 2,
                    ballot: NORMAL_ACCEPT_BALLOT,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    ts_final: 55,
                    op_msgpack: op_msgpack.clone(),
                    src_clock: 55,
                },
            )
            .await;
        assert!(!recovered.state.lock().accepted_values.contains_key(&op_id));

        recovered
            .recv_resolution_prepare_with_origin_epoch(
                2,
                1,
                StrictResolutionPrepare {
                    resolver_node: 2,
                    ballot: 56,
                    coord_node: 2,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    src_clock: 56,
                    frozen_targets: v2_frozen_targets_wire(),
                },
            )
            .await;
        assert_eq!(
            recovered
                .terminal_journal
                .lock()
                .get(op_id)
                .map(TerminalJournalRecord::promise_ballot),
            Some(0)
        );
    }

    #[tokio::test]
    async fn v2_hint_persists_pending_value_before_the_resolver_promise() {
        let temp = tempfile::TempDir::new().unwrap();
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 1);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));
        let op_id = make_op_id(2, 1, 41);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&141u64).unwrap());
        {
            let rt = StrictRuntime::new(
                CountingStrictRepo::new(),
                1,
                1,
                "channels".to_owned(),
                net.clone(),
                CancellationToken::new(),
                Arc::new(ReplicationConfig::default()),
            );
            rt.finish_history_election_for_test();
            rt.recv_resolution_hint(
                1,
                StrictResolutionHint {
                    reporter_node: 1,
                    coord_node: 2,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    ts_local: 42,
                    op_msgpack: op_msgpack.clone(),
                    src_clock: 42,
                    reporter_boot_epoch: 1,
                    protocol_version: STRICT_PROTOCOL_VERSION_V2,
                    frozen_targets: v2_frozen_targets_wire(),
                },
            )
            .await;

            let record = rt
                .terminal_journal
                .lock()
                .get(op_id)
                .cloned()
                .expect("hinted operation must enter the durable terminal journal");
            assert!(record.promise_ballot() > 0);
            assert_eq!(
                record.frozen_targets(),
                Some(v2_frozen_targets().as_slice())
            );
            assert!(record.pending_proposal().is_some_and(|pending| {
                pending.ts_local() == 42 && pending.op_msgpack() == op_msgpack.as_ref()
            }));
        }

        let recovered = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net,
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        assert!(matches!(
            recovered.state.lock().pending_proposes.get(&op_id),
            Some(PendingPropose {
                protocol_version,
                v2_descriptor_durable: true,
                ..
            }) if *protocol_version == STRICT_PROTOCOL_VERSION_V2
        ));
    }

    #[tokio::test]
    async fn v2_record_rejects_descriptorless_legacy_terminal_traffic() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 1);
        net.set_epoch(3, 1);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let rt = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let op_id = make_op_id(2, 1, 43);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&143u64).unwrap());
        rt.recv_propose_v1(
            2,
            StrictProposeV1 {
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_propose: 43,
                op_msgpack,
                src_clock: 43,
                protocol_version: STRICT_PROTOCOL_VERSION_V2,
                frozen_targets: v2_frozen_targets_wire(),
            },
        )
        .await;
        net.drain_captures();

        rt.recv_resolution_prepare(
            3,
            StrictResolutionPrepare {
                resolver_node: 3,
                ballot: 44,
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                src_clock: 44,
                frozen_targets: Vec::new(),
            },
        )
        .await;
        assert!(net.drain_captures().iter().any(|frame| {
            matches!(
                frame,
                CapturedFrame::StrictUnicast {
                    dst: 3,
                    body: StrictBody::ResolutionAck(StrictResolutionAck {
                        ballot: 44,
                        promised: false,
                        ..
                    }),
                    ..
                }
            )
        }));
        assert_eq!(
            rt.terminal_journal
                .lock()
                .get(op_id)
                .map(TerminalJournalRecord::promise_ballot),
            Some(0)
        );

        rt.recv_decision(
            3,
            StrictDecision {
                resolver_node: 3,
                ballot: 44,
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                outcome: Some(StrictDecisionOutcome::Abort(StrictDecisionAbort {})),
                src_clock: 44,
                resolver_boot_epoch: 0,
                frozen_targets: Vec::new(),
            },
        )
        .await;
        assert!(!rt.state.lock().terminal_decisions.contains_key(&op_id));
    }

    #[tokio::test]
    async fn catchup_rejects_terminal_states_from_a_misattributed_response() {
        let (rt, _net, _repo) = v1_runtime(ReplicationConfig::default());
        let op_id = make_op_id(2, 1, 7);
        let response = StrictCatchupResp {
            snapshot_version: 0,
            snapshot_msgpack: Bytes::new(),
            ops: Vec::new(),
            terminal_states: vec![StrictTerminalState {
                coord_node: 2,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ballot: 7,
                outcome: Some(StrictTerminalOutcome::Abort(StrictDecisionAbort {})),
                resolver_node: 0,
                resolver_boot_epoch: 0,
                frozen_targets: Vec::new(),
            }],
            next_terminal_state_cursor: 0,
            terminal_states_has_more: false,
            terminal_sync_only: false,
            request_force_snapshot: false,
            request_history_probe_only: false,
            terminal_decision_generation: 0,
            snapshot_transfer_id: 0,
            snapshot_chunk_cursor: 0,
            snapshot_next_cursor: 0,
            snapshot_total_bytes: 0,
            snapshot_sha256: Bytes::new(),
            snapshot_has_more: false,
            snapshot_transfer_rejected: false,
            has_more: false,
            next_chunk_token: 0,
            too_old_use_snapshot: false,
            history_version: 0,
            history_freshness: 0,
            runtime_started_at: 3,
            history_node: 3,
        };

        rt.recv_catchup_resp(2, response).await;

        assert!(!rt.state.lock().terminal_decisions.contains_key(&op_id));
    }

    #[tokio::test]
    async fn terminal_journal_reloads_and_catchup_replays_fences() {
        let temp = tempfile::TempDir::new().unwrap();
        let source_net = MockNet::new(1, vec![1, 2]);
        source_net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V1);
        source_net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));
        let abort_id = make_op_id(1, 1, 8);
        let commit_id = make_op_id(1, 1, 9);
        let commit_bytes = Bytes::from(rmp_serde::to_vec(&123u64).unwrap());
        {
            let source = StrictRuntime::new(
                CountingStrictRepo::new(),
                1,
                1,
                "channels".to_owned(),
                source_net.clone(),
                CancellationToken::new(),
                Arc::new(ReplicationConfig::default()),
            );
            assert!(source.apply_terminal_abort(abort_id, 8));
            assert!(source.apply_terminal_commit(commit_id, 9, 12, commit_bytes.clone()));
        }

        let source = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            source_net,
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let terminal_states = source.terminal_states_for_catchup();
        assert_eq!(terminal_states.len(), 2);
        assert!(matches!(
            source.state.lock().terminal_decisions.get(&abort_id),
            Some(TerminalDecision::Abort { .. })
        ));
        assert!(matches!(
            source.state.lock().terminal_decisions.get(&commit_id),
            Some(TerminalDecision::Commit(value))
                if value.ts_final == 12 && value.op_msgpack == commit_bytes
        ));

        let sink_net = MockNet::new(2, vec![1, 2]);
        sink_net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V1);
        let sink = StrictRuntime::new(
            CountingStrictRepo::new(),
            2,
            2,
            "channels".to_owned(),
            sink_net,
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        sink.recv_catchup_resp(
            1,
            StrictCatchupResp {
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: Vec::new(),
                terminal_states,
                next_terminal_state_cursor: 0,
                terminal_states_has_more: false,
                terminal_sync_only: false,
                request_force_snapshot: false,
                request_history_probe_only: false,
                terminal_decision_generation: 0,
                snapshot_transfer_id: 0,
                snapshot_chunk_cursor: 0,
                snapshot_next_cursor: 0,
                snapshot_total_bytes: 0,
                snapshot_sha256: Bytes::new(),
                snapshot_has_more: false,
                snapshot_transfer_rejected: false,
                has_more: false,
                next_chunk_token: 0,
                too_old_use_snapshot: false,
                history_version: 0,
                history_freshness: 0,
                runtime_started_at: 1,
                history_node: 1,
            },
        )
        .await;
        assert!(matches!(
            sink.state.lock().terminal_decisions.get(&abort_id),
            Some(TerminalDecision::Abort { .. })
        ));
        assert!(matches!(
            sink.state.lock().terminal_decisions.get(&commit_id),
            Some(TerminalDecision::Commit(value))
                if value.ts_final == 12 && value.op_msgpack == commit_bytes
        ));

        sink.recv_commit(
            1,
            StrictCommit {
                coord_node: 1,
                op_id_hi: abort_id.0,
                op_id_lo: abort_id.1,
                ts_final: 20,
                op_msgpack: Bytes::from(rmp_serde::to_vec(&999u64).unwrap()),
                src_clock: 20,
            },
        )
        .await;
        assert!(!sink.state.lock().committed_ids.contains(&abort_id));
    }

    #[tokio::test]
    async fn oversized_persisted_terminal_record_quarantines_v2_but_replays_locally() {
        let temp = tempfile::TempDir::new().unwrap();
        let net = MockNet::new(1, vec![1]);
        net.set_epoch(1, 1);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));
        let repo = CountingStrictRepo::new();
        let op_id = make_op_id(1, 1, 24);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&654u64).unwrap());

        {
            let source = StrictRuntime::new(
                repo.clone(),
                1,
                1,
                "channels".to_owned(),
                net.clone(),
                CancellationToken::new(),
                Arc::new(ReplicationConfig::default()),
            );
            assert!(source.apply_terminal_commit(op_id, 7, 12, op_msgpack));
        }
        assert_eq!(net.strict_protocol_disable_reports(), 0);

        let recovered = StrictRuntime::new(
            repo.clone(),
            1,
            2,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default().with_strict_max_catchup_bytes(1)),
        );

        assert!(
            !recovered
                .terminal_protocol_storage_healthy
                .load(Ordering::Acquire)
        );
        assert_eq!(net.strict_protocol_disable_reports(), 1);
        assert!(matches!(
            recovered.state.lock().terminal_decisions.get(&op_id),
            Some(TerminalDecision::Commit(value))
                if value.ts_final == 12 && value.op_msgpack == Bytes::from(rmp_serde::to_vec(&654u64).unwrap())
        ));

        recovered.finish_history_election_for_test();
        {
            let mut state = recovered.state.lock();
            state.clock = 20;
            state.peer_clocks.insert(1, 20);
        }
        run_delivery_pass(&recovered).await;
        assert_eq!(repo.log(), vec![(1, 654)]);
    }

    #[test]
    fn topic_construction_withdraws_v2_when_the_configured_budget_cannot_fit_a_response() {
        let net = MockNet::new(1, vec![1]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let runtime = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default().with_strict_max_catchup_bytes(1)),
        );

        assert_eq!(net.strict_repository_capability_loss_reports(), 1);
        assert_eq!(runtime.current_protocol_version(), 0);
        assert_eq!(runtime.strict_catchup_response_budget(), 1);
    }

    #[test]
    fn topic_construction_withdraws_v2_when_snapshot_control_exceeds_the_budget() {
        let net = MockNet::new(1, vec![1]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        let history_len = net
            .encoded_v2_strict_payload_len("channels", &minimum_v2_catchup_response_body(1))
            .unwrap();
        let snapshot_control_len = net
            .encoded_v2_strict_payload_len(
                "channels",
                &minimum_v2_snapshot_control_response_body(1),
            )
            .unwrap();
        assert!(
            snapshot_control_len > history_len,
            "test requires a real budget gap between history and snapshot control"
        );

        let runtime = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default().with_strict_max_catchup_bytes(history_len)),
        );

        assert_eq!(net.strict_repository_capability_loss_reports(), 1);
        assert_eq!(runtime.current_protocol_version(), 0);
    }

    #[tokio::test]
    async fn terminal_commit_replays_after_restart_without_reapplying_the_repository() {
        let temp = tempfile::TempDir::new().unwrap();
        let net = MockNet::new(1, vec![1]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V1);
        net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));
        let repo = CountingStrictRepo::new();
        let op_id = make_op_id(1, 1, 11);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&654u64).unwrap());

        {
            let runtime = StrictRuntime::new(
                repo.clone(),
                1,
                1,
                "channels".to_owned(),
                net.clone(),
                CancellationToken::new(),
                Arc::new(ReplicationConfig::default()),
            );
            runtime.finish_history_election_for_test();
            assert!(runtime.apply_terminal_commit(op_id, 7, 12, op_msgpack.clone()));
            {
                let mut state = runtime.state.lock();
                state.clock = 20;
                state.peer_clocks.insert(1, 20);
            }
            run_delivery_pass(&runtime).await;
            assert_eq!(repo.log(), vec![(1, 654)]);
        }

        let recovered = StrictRuntime::new(
            repo.clone(),
            1,
            2,
            "channels".to_owned(),
            net,
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        recovered.finish_history_election_for_test();
        {
            let mut state = recovered.state.lock();
            state.clock = 20;
            state.peer_clocks.insert(1, 20);
        }
        run_delivery_pass(&recovered).await;

        assert_eq!(repo.log(), vec![(1, 654)]);
    }

    #[tokio::test]
    async fn terminal_catchup_pages_use_a_stable_snapshot_across_new_decisions() {
        let (runtime, _net, _repo) =
            v1_runtime(ReplicationConfig::default().with_strict_max_catchup_ops(1));
        let first = make_op_id(1, 1, 1);
        let third = make_op_id(1, 1, 3);
        assert!(runtime.apply_terminal_abort(first, 1));
        assert!(runtime.apply_terminal_abort(third, 1));

        let first_page = runtime.terminal_states_for_catchup_page(2, 0, 1, usize::MAX);
        assert_eq!(first_page.states.len(), 1);
        assert_eq!(first_page.states[0].op_id_lo, 1);
        assert!(first_page.has_more);

        // This record sorts before the cursor in the live BTreeMap. A
        // transfer using the live index would resend or skip a terminal
        // fence; the existing peer snapshot must continue with `third`.
        let second = make_op_id(1, 1, 2);
        assert!(runtime.apply_terminal_abort(second, 1));
        let second_page =
            runtime.terminal_states_for_catchup_page(2, first_page.next_cursor, 1, usize::MAX);
        assert_eq!(second_page.states.len(), 1);
        assert_eq!(second_page.states[0].op_id_lo, 3);
        assert!(!second_page.has_more);

        // A later sync starts a fresh snapshot and picks up the concurrent
        // terminal fence without relying on the old live index.
        let refreshed = runtime.terminal_states_for_catchup_page(2, 0, usize::MAX, usize::MAX);
        let ids: Vec<_> = refreshed
            .states
            .iter()
            .map(|state| state.op_id_lo)
            .collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn terminal_catchup_bounds_promise_only_journal_scans() {
        let (runtime, _net, _repo) = v1_runtime(ReplicationConfig::default());
        let first_promise = make_op_id(1, 1, 21);
        let second_promise = make_op_id(1, 1, 22);
        let terminal = make_op_id(1, 1, 23);
        {
            let mut journal = runtime.terminal_journal.lock();
            journal.upsert_promise(first_promise, 1).unwrap();
            journal.upsert_promise(second_promise, 1).unwrap();
        }
        assert!(runtime.apply_terminal_abort(terminal, 1));

        let first_page = runtime.terminal_states_for_catchup_page(2, 0, 2, usize::MAX);
        assert!(first_page.states.is_empty());
        assert_eq!(first_page.next_cursor, 2);
        assert!(first_page.has_more);

        let second_page =
            runtime.terminal_states_for_catchup_page(2, first_page.next_cursor, 2, usize::MAX);
        assert_eq!(second_page.states.len(), 1);
        assert_eq!(second_page.states[0].op_id_lo, 23);
        assert!(!second_page.has_more);
    }

    #[tokio::test]
    async fn v1_inbound_is_rejected_without_repository_capability() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V1);
        let runtime = StrictRuntime::new(
            CountingStrictRepo::new_legacy(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let op_id = make_op_id(2, 1, 12);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&655u64).unwrap());

        runtime
            .recv_propose_v1(
                2,
                StrictProposeV1 {
                    coord_node: 2,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    ts_propose: 12,
                    op_msgpack: op_msgpack.clone(),
                    src_clock: 12,
                    protocol_version: STRICT_PROTOCOL_VERSION_V1,
                    frozen_targets: Vec::new(),
                },
            )
            .await;
        assert!(!runtime.state.lock().pending_proposes.contains_key(&op_id));

        runtime
            .recv_accept(
                2,
                StrictAccept {
                    coord_node: 2,
                    ballot: NORMAL_ACCEPT_BALLOT,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    ts_final: 13,
                    op_msgpack,
                    src_clock: 13,
                },
            )
            .await;

        assert!(runtime.state.lock().accepted_values.get(&op_id).is_none());
        assert!(net.drain_captures().is_empty());
    }

    #[tokio::test]
    async fn v2_accepted_value_is_reconstructed_as_stale_pending_after_restart() {
        let temp = tempfile::TempDir::new().unwrap();
        let cfg = ReplicationConfig::default();
        let op_id = make_op_id(2, 1, 10);
        let op_msgpack = Bytes::from(rmp_serde::to_vec(&456u64).unwrap());
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(1, 1);
        net.set_epoch(2, 1);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_V2);
        net.set_strict_protocol_state_dir(Some(temp.path().to_path_buf()));
        {
            let rt = StrictRuntime::new(
                CountingStrictRepo::new(),
                1,
                1,
                "channels".to_owned(),
                net.clone(),
                CancellationToken::new(),
                Arc::new(cfg.clone()),
            );
            rt.recv_propose_v1(
                2,
                StrictProposeV1 {
                    coord_node: 2,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    ts_propose: 10,
                    op_msgpack: op_msgpack.clone(),
                    src_clock: 10,
                    protocol_version: STRICT_PROTOCOL_VERSION_V2,
                    frozen_targets: v2_frozen_targets_wire(),
                },
            )
            .await;
            rt.recv_accept(
                2,
                StrictAccept {
                    coord_node: 2,
                    ballot: NORMAL_ACCEPT_BALLOT,
                    op_id_hi: op_id.0,
                    op_id_lo: op_id.1,
                    ts_final: 12,
                    op_msgpack: op_msgpack.clone(),
                    src_clock: 12,
                },
            )
            .await;
        }

        let recovered = StrictRuntime::new(
            CountingStrictRepo::new(),
            1,
            1,
            "channels".to_owned(),
            net.clone(),
            CancellationToken::new(),
            Arc::new(cfg.clone()),
        );
        recovered.finish_history_election_for_test();
        assert!(matches!(
            recovered.state.lock().pending_proposes.get(&op_id),
            Some(PendingPropose { protocol_version, .. })
                if *protocol_version == STRICT_PROTOCOL_VERSION_V2
        ));
        recovered
            .state
            .lock()
            .pending_proposes
            .get_mut(&op_id)
            .expect("restarted v2 pending entry must be restored")
            .seen_at = Instant::now() - cfg.pending_propose_ttl() - Duration::from_millis(1);

        resolve_stale_with_remote_ack(&recovered, &net, op_id, 2, None).await;
        assert!(matches!(
            recovered.state.lock().terminal_decisions.get(&op_id),
            Some(TerminalDecision::Commit(value))
                if value.ts_final == 12 && value.op_msgpack == op_msgpack
        ));
    }
}
