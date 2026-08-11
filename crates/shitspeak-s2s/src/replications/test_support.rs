//! In-test mocks for the [`StrictNet`](super::strict::runtime::StrictNet)
//! and [`OwnerNet`](super::owner::runtime::OwnerNet) abstractions.
//!
//! Captures every send into a `Vec<CapturedFrame>` and serves an
//! injectable alive-set / boot-epoch view, so unit tests can drive the
//! runtime state machines end-to-end without spinning up real loopback
//! transports.

#![cfg(any(test, feature = "test-support"))]

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use prost::Message as _;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use super::error::ReplicationError;
use super::owner::runtime::OwnerNet;
use super::proto::{OwnerBody, StrictBody};
use super::strict::runtime::{BulkPageIdentity, StrictNet};
use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{SendError, ServiceLevel, TransportKind};

/// Logical transport lane selected by the strict runtime.
///
/// This is intentionally recorded separately from [`CapturedFrame`] so the
/// long-standing frame shapes remain convenient for existing tests while new
/// pressure tests can assert that operation-bearing pages never use the
/// redundant control path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictSendLane {
    Ordinary,
    RedundantControl,
    Bulk,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrictSendTarget {
    Unicast(NodeIdentifier),
    Multicast(Vec<NodeIdentifier>),
    Broadcast,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictSendOutcome {
    Sent,
    InjectedFailure,
    Backpressure,
}

/// One attempted strict send, including the exact protobuf payload produced by
/// the mock transport before any enqueue outcome is applied.
#[derive(Debug, Clone)]
pub struct StrictSendObservation {
    pub lane: StrictSendLane,
    pub target: StrictSendTarget,
    pub topic: String,
    pub body: StrictBody,
    pub encoded: Bytes,
    pub retry_delay: Option<Duration>,
    pub outcome: StrictSendOutcome,
}

/// Script item consumed by successive calls to `send_bulk_unicast`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockBulkSendOutcome {
    Sent,
    Backpressure,
    LocalPacerBusy(Duration),
    BackpressureUntilAcknowledged,
    Failure,
}

/// Test barrier that exposes the interval after a bulk page is observable to
/// its receiver but before the sender's await completes.
pub struct MockBulkSendPause {
    captured: Notify,
    release: Notify,
}

impl MockBulkSendPause {
    pub async fn wait_until_captured(&self) {
        self.captured.notified().await;
    }

    pub fn release(&self) {
        self.release.notify_one();
    }
}

#[derive(Debug, Clone)]
pub enum CapturedFrame {
    StrictUnicast {
        dst: NodeIdentifier,
        topic: String,
        body: StrictBody,
    },
    StrictMulticast {
        dsts: Vec<NodeIdentifier>,
        topic: String,
        body: StrictBody,
    },
    StrictBroadcast {
        topic: String,
        body: StrictBody,
    },
    OwnerUnicast {
        dst: NodeIdentifier,
        topic: String,
        body: OwnerBody,
    },
    OwnerBroadcast {
        topic: String,
        body: OwnerBody,
    },
}

/// In-memory mock for both `StrictNet` and `OwnerNet`. Wraps an injectable
/// alive-set, boot-epoch map, edge-RTT samples, and destination route RTTs.
/// Captures every outbound frame.
pub struct MockNet {
    pub self_id: NodeIdentifier,
    pub alive: Mutex<Vec<NodeIdentifier>>,
    pub epochs: Mutex<std::collections::HashMap<NodeIdentifier, u64>>,
    strict_protocol_version: Mutex<u32>,
    local_strict_protocol_version: Mutex<Option<u32>>,
    strict_peer_protocol_versions: Mutex<std::collections::HashMap<NodeIdentifier, u32>>,
    max_replication_payload_bytes: Mutex<usize>,
    strict_protocol_disable_reports: Mutex<usize>,
    strict_repository_capability_loss_reports: Mutex<usize>,
    strict_protocol_state_dir: Mutex<Option<PathBuf>>,
    routes: Mutex<Option<std::collections::HashSet<(ServiceLevel, NodeIdentifier)>>>,
    live_routes: Mutex<Option<std::collections::HashSet<(ServiceLevel, NodeIdentifier)>>>,
    strict_unicast_failures: Mutex<std::collections::HashSet<NodeIdentifier>>,
    strict_multicast_failures: AtomicBool,
    owner_unicast_failures: Mutex<std::collections::HashSet<NodeIdentifier>>,
    pub captured: Mutex<Vec<CapturedFrame>>,
    strict_send_observations: Mutex<Vec<StrictSendObservation>>,
    bulk_acknowledgements: Mutex<Vec<(NodeIdentifier, String, BulkPageIdentity)>>,
    bulk_send_outcomes: Mutex<VecDeque<MockBulkSendOutcome>>,
    bulk_send_pause_after_capture: Mutex<Option<Arc<MockBulkSendPause>>>,
    pub edge_rtts: Mutex<Vec<Duration>>,
    route_rtts: Mutex<std::collections::HashMap<NodeIdentifier, Duration>>,
    /// Known strict replication participants (including currently unreachable
    /// members). None derives the participant count from the alive set plus
    /// the local node, preserving the legacy behavior where every live peer
    /// must acknowledge the head before rotation.
    strict_participants: Mutex<Option<Vec<NodeIdentifier>>>,
}

impl MockNet {
    pub fn new(self_id: NodeIdentifier, alive: Vec<NodeIdentifier>) -> Arc<Self> {
        Arc::new(Self {
            self_id,
            alive: Mutex::new(alive),
            epochs: Mutex::new(Default::default()),
            strict_protocol_version: Mutex::new(0),
            local_strict_protocol_version: Mutex::new(None),
            strict_peer_protocol_versions: Mutex::new(Default::default()),
            max_replication_payload_bytes: Mutex::new(usize::MAX),
            strict_protocol_disable_reports: Mutex::new(0),
            strict_repository_capability_loss_reports: Mutex::new(0),
            strict_protocol_state_dir: Mutex::new(None),
            routes: Mutex::new(None),
            live_routes: Mutex::new(None),
            strict_unicast_failures: Mutex::new(Default::default()),
            strict_multicast_failures: AtomicBool::new(false),
            owner_unicast_failures: Mutex::new(Default::default()),
            captured: Mutex::new(Vec::new()),
            strict_send_observations: Mutex::new(Vec::new()),
            bulk_acknowledgements: Mutex::new(Vec::new()),
            bulk_send_outcomes: Mutex::new(VecDeque::new()),
            bulk_send_pause_after_capture: Mutex::new(None),
            edge_rtts: Mutex::new(Vec::new()),
            route_rtts: Mutex::new(Default::default()),
            strict_participants: Mutex::new(None),
        })
    }

    pub fn set_strict_participants(&self, participants: impl IntoIterator<Item = NodeIdentifier>) {
        *self.strict_participants.lock() = Some(participants.into_iter().collect());
    }

    pub fn set_edge_rtts(&self, rtts: Vec<Duration>) {
        *self.edge_rtts.lock() = rtts;
    }

    pub fn set_route_rtt(&self, dst: NodeIdentifier, rtt: Duration) {
        self.route_rtts.lock().insert(dst, rtt);
    }

    pub fn set_alive(&self, alive: Vec<NodeIdentifier>) {
        *self.alive.lock() = alive;
    }

    pub fn set_routes(
        &self,
        level: ServiceLevel,
        routes: impl IntoIterator<Item = NodeIdentifier>,
    ) {
        *self.routes.lock() = Some(routes.into_iter().map(|dst| (level, dst)).collect());
    }

    pub fn set_reliable_routes(&self, routes: impl IntoIterator<Item = NodeIdentifier>) {
        self.set_routes(ServiceLevel::Reliable, routes);
    }

    pub fn set_live_routes(
        &self,
        level: ServiceLevel,
        routes: impl IntoIterator<Item = NodeIdentifier>,
    ) {
        *self.live_routes.lock() = Some(routes.into_iter().map(|dst| (level, dst)).collect());
    }

    pub fn set_live_reliable_routes(&self, routes: impl IntoIterator<Item = NodeIdentifier>) {
        self.set_live_routes(ServiceLevel::Reliable, routes);
    }

    pub fn fail_strict_unicasts_to(&self, dsts: impl IntoIterator<Item = NodeIdentifier>) {
        *self.strict_unicast_failures.lock() = dsts.into_iter().collect();
    }

    pub fn set_fail_strict_multicasts(&self, fail: bool) {
        self.strict_multicast_failures
            .store(fail, Ordering::Relaxed);
    }

    pub fn fail_owner_unicasts_to(&self, dsts: impl IntoIterator<Item = NodeIdentifier>) {
        *self.owner_unicast_failures.lock() = dsts.into_iter().collect();
    }

    pub fn set_epoch(&self, node: NodeIdentifier, epoch: u64) {
        self.epochs.lock().insert(node, epoch);
    }

    pub fn set_strict_replication_protocol_version(&self, version: u32) {
        *self.strict_protocol_version.lock() = version;
    }

    /// Override this node's immediate local capability independently of the
    /// negotiated cluster floor. Tests use this to model a transient remote
    /// LSA downgrade without pretending the local durable repository changed.
    pub fn set_local_strict_replication_protocol_version(&self, version: Option<u32>) {
        *self.local_strict_protocol_version.lock() = version;
    }

    pub fn set_peer_strict_replication_protocol_version(&self, peer: NodeIdentifier, version: u32) {
        self.strict_peer_protocol_versions
            .lock()
            .insert(peer, version);
    }

    pub fn set_max_replication_payload_bytes(&self, bytes: usize) {
        *self.max_replication_payload_bytes.lock() = bytes;
    }

    pub fn strict_repository_capability_loss_reports(&self) -> usize {
        *self.strict_repository_capability_loss_reports.lock()
    }

    pub fn strict_protocol_disable_reports(&self) -> usize {
        *self.strict_protocol_disable_reports.lock()
    }

    pub fn set_strict_protocol_state_dir(&self, state_dir: Option<PathBuf>) {
        *self.strict_protocol_state_dir.lock() = state_dir;
    }

    pub fn captures(&self) -> Vec<CapturedFrame> {
        self.captured.lock().clone()
    }

    pub fn drain_captures(&self) -> Vec<CapturedFrame> {
        std::mem::take(&mut *self.captured.lock())
    }

    pub fn strict_send_observations(&self) -> Vec<StrictSendObservation> {
        self.strict_send_observations.lock().clone()
    }

    pub fn drain_strict_send_observations(&self) -> Vec<StrictSendObservation> {
        std::mem::take(&mut *self.strict_send_observations.lock())
    }

    pub(crate) fn drain_bulk_acknowledgements(
        &self,
    ) -> Vec<(NodeIdentifier, String, BulkPageIdentity)> {
        std::mem::take(&mut *self.bulk_acknowledgements.lock())
    }

    /// Replace the scripted outcomes for successive bulk sends. Once the
    /// script is exhausted, later sends succeed.
    pub fn script_bulk_send_outcomes(
        &self,
        outcomes: impl IntoIterator<Item = MockBulkSendOutcome>,
    ) {
        *self.bulk_send_outcomes.lock() = outcomes.into_iter().collect();
    }

    pub fn pause_next_bulk_send_after_capture(&self) -> Arc<MockBulkSendPause> {
        let pause = Arc::new(MockBulkSendPause {
            captured: Notify::new(),
            release: Notify::new(),
        });
        *self.bulk_send_pause_after_capture.lock() = Some(Arc::clone(&pause));
        pause
    }

    pub fn strict_encoded_bytes_for_lane(&self, lane: StrictSendLane) -> usize {
        self.strict_send_observations
            .lock()
            .iter()
            .filter(|observation| observation.lane == lane)
            .map(|observation| observation.encoded.len())
            .sum()
    }

    fn observe_strict_send(
        &self,
        lane: StrictSendLane,
        target: StrictSendTarget,
        topic: &str,
        body: &StrictBody,
        retry_delay: Option<Duration>,
        outcome: StrictSendOutcome,
    ) {
        let encoded = Bytes::from(super::proto::wrap_strict(topic, body.clone()).encode_to_vec());
        self.strict_send_observations
            .lock()
            .push(StrictSendObservation {
                lane,
                target,
                topic: topic.to_owned(),
                body: body.clone(),
                encoded,
                retry_delay,
                outcome,
            });
    }

    pub fn count_strict_multicasts(&self) -> usize {
        self.captured
            .lock()
            .iter()
            .filter(|f| matches!(f, CapturedFrame::StrictMulticast { .. }))
            .count()
    }

    pub fn count_owner_broadcasts(&self) -> usize {
        self.captured
            .lock()
            .iter()
            .filter(|f| matches!(f, CapturedFrame::OwnerBroadcast { .. }))
            .count()
    }

    pub fn count_owner_unicasts(&self) -> usize {
        self.captured
            .lock()
            .iter()
            .filter(|f| matches!(f, CapturedFrame::OwnerUnicast { .. }))
            .count()
    }
}

#[async_trait]
impl StrictNet for MockNet {
    async fn send_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: StrictBody,
    ) -> Result<(), ReplicationError> {
        let failed = self.strict_unicast_failures.lock().contains(&dst);
        self.observe_strict_send(
            StrictSendLane::Ordinary,
            StrictSendTarget::Unicast(dst),
            topic,
            &body,
            None,
            if failed {
                StrictSendOutcome::InjectedFailure
            } else {
                StrictSendOutcome::Sent
            },
        );
        if failed {
            return Err(ReplicationError::Malformed(
                "injected strict unicast failure",
            ));
        }
        self.captured.lock().push(CapturedFrame::StrictUnicast {
            dst,
            topic: topic.to_owned(),
            body,
        });
        Ok(())
    }

    async fn send_redundant_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: StrictBody,
    ) -> Result<(), ReplicationError> {
        let failed = self.strict_unicast_failures.lock().contains(&dst);
        self.observe_strict_send(
            StrictSendLane::RedundantControl,
            StrictSendTarget::Unicast(dst),
            topic,
            &body,
            None,
            if failed {
                StrictSendOutcome::InjectedFailure
            } else {
                StrictSendOutcome::Sent
            },
        );
        if failed {
            return Err(ReplicationError::Malformed(
                "injected strict redundant unicast failure",
            ));
        }
        self.captured.lock().push(CapturedFrame::StrictUnicast {
            dst,
            topic: topic.to_owned(),
            body,
        });
        Ok(())
    }

    async fn send_bulk_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: StrictBody,
        retry_delay: Duration,
    ) -> Result<(), ReplicationError> {
        let scripted = self
            .bulk_send_outcomes
            .lock()
            .pop_front()
            .unwrap_or(MockBulkSendOutcome::Sent);
        let outcome = match scripted {
            MockBulkSendOutcome::Sent => StrictSendOutcome::Sent,
            MockBulkSendOutcome::Backpressure => StrictSendOutcome::Backpressure,
            MockBulkSendOutcome::LocalPacerBusy(_) => StrictSendOutcome::Backpressure,
            MockBulkSendOutcome::BackpressureUntilAcknowledged
                if self.bulk_acknowledgements.lock().is_empty() =>
            {
                StrictSendOutcome::Backpressure
            }
            MockBulkSendOutcome::BackpressureUntilAcknowledged => StrictSendOutcome::Sent,
            MockBulkSendOutcome::Failure => StrictSendOutcome::InjectedFailure,
        };
        self.observe_strict_send(
            StrictSendLane::Bulk,
            StrictSendTarget::Unicast(dst),
            topic,
            &body,
            Some(retry_delay),
            outcome,
        );
        match outcome {
            StrictSendOutcome::Sent => {
                self.captured.lock().push(CapturedFrame::StrictUnicast {
                    dst,
                    topic: topic.to_owned(),
                    body,
                });
                let pause = { self.bulk_send_pause_after_capture.lock().take() };
                if let Some(pause) = pause {
                    pause.captured.notify_one();
                    pause.release.notified().await;
                }
                Ok(())
            }
            StrictSendOutcome::Backpressure => match scripted {
                MockBulkSendOutcome::LocalPacerBusy(retry_after) => {
                    Err(ReplicationError::StrictBulkAdmissionBusy { retry_after })
                }
                _ => Err(ReplicationError::Overlay(
                    crate::overlay::OverlayError::Send(SendError::Backpressure {
                        node: dst,
                        transport: TransportKind::Tcp,
                    }),
                )),
            },
            StrictSendOutcome::InjectedFailure => Err(ReplicationError::Malformed(
                "injected strict bulk unicast failure",
            )),
        }
    }

    fn acknowledge_bulk_unicast(&self, dst: NodeIdentifier, topic: &str, page: BulkPageIdentity) {
        self.bulk_acknowledgements
            .lock()
            .push((dst, topic.to_owned(), page));
    }

    async fn send_multicast(
        &self,
        dsts: &[NodeIdentifier],
        topic: &str,
        body: StrictBody,
    ) -> Result<(), ReplicationError> {
        let failed = self.strict_multicast_failures.load(Ordering::Relaxed);
        self.observe_strict_send(
            StrictSendLane::Ordinary,
            StrictSendTarget::Multicast(dsts.to_vec()),
            topic,
            &body,
            None,
            if failed {
                StrictSendOutcome::InjectedFailure
            } else {
                StrictSendOutcome::Sent
            },
        );
        if failed {
            return Err(ReplicationError::Malformed(
                "injected strict multicast failure",
            ));
        }
        self.captured.lock().push(CapturedFrame::StrictMulticast {
            dsts: dsts.to_vec(),
            topic: topic.to_owned(),
            body,
        });
        Ok(())
    }

    async fn send_broadcast(&self, topic: &str, body: StrictBody) -> Result<(), ReplicationError> {
        self.observe_strict_send(
            StrictSendLane::Ordinary,
            StrictSendTarget::Broadcast,
            topic,
            &body,
            None,
            StrictSendOutcome::Sent,
        );
        self.captured.lock().push(CapturedFrame::StrictBroadcast {
            topic: topic.to_owned(),
            body,
        });
        Ok(())
    }

    fn alive_members(&self) -> Vec<NodeIdentifier> {
        self.alive.lock().clone()
    }

    fn strict_participant_count(&self) -> usize {
        if let Some(participants) = self.strict_participants.lock().as_ref() {
            return participants.len();
        }
        let mut participants: HashSet<_> = self.alive.lock().iter().copied().collect();
        participants.insert(self.self_id);
        participants.len()
    }

    fn strict_participant_incarnations(&self) -> Vec<(NodeIdentifier, u64)> {
        let mut participants: HashSet<_> = self
            .strict_participants
            .lock()
            .clone()
            .unwrap_or_else(|| self.alive.lock().clone())
            .into_iter()
            .collect();
        participants.insert(self.self_id);
        let epochs = self.epochs.lock();
        let mut incarnations = participants
            .into_iter()
            .map(|node| (node, epochs.get(&node).copied().unwrap_or_default()))
            .collect::<Vec<_>>();
        incarnations.sort_unstable_by_key(|(node, _)| *node);
        incarnations
    }

    fn member_boot_epoch(&self, node: NodeIdentifier) -> Option<u64> {
        self.epochs.lock().get(&node).copied()
    }

    fn strict_replication_protocol_version(&self) -> u32 {
        *self.strict_protocol_version.lock()
    }

    fn local_strict_replication_protocol_version(&self) -> u32 {
        self.local_strict_protocol_version
            .lock()
            .unwrap_or_else(|| *self.strict_protocol_version.lock())
    }

    fn peer_strict_replication_protocol_version(&self, peer: NodeIdentifier) -> u32 {
        self.strict_peer_protocol_versions
            .lock()
            .get(&peer)
            .copied()
            .unwrap_or_else(|| *self.strict_protocol_version.lock())
    }

    fn unsupported_active_protocol_peers(&self, required_version: u32) -> usize {
        let negotiated_version = *self.strict_protocol_version.lock();
        let local_version = self
            .local_strict_protocol_version
            .lock()
            .unwrap_or(negotiated_version);
        let peer_versions = self.strict_peer_protocol_versions.lock().clone();
        let participants: HashSet<_> = self
            .strict_participants
            .lock()
            .clone()
            .unwrap_or_else(|| self.alive.lock().clone())
            .into_iter()
            .chain([self.self_id])
            .collect();

        participants
            .into_iter()
            .filter(|participant| {
                let version = if *participant == self.self_id {
                    local_version
                } else {
                    peer_versions
                        .get(participant)
                        .copied()
                        .unwrap_or(negotiated_version)
                };
                version < required_version
            })
            .count()
    }

    fn strict_protocol_state_dir(&self) -> Option<PathBuf> {
        self.strict_protocol_state_dir.lock().clone()
    }

    fn max_replication_payload_bytes(&self) -> usize {
        *self.max_replication_payload_bytes.lock()
    }

    fn report_strict_replication_repository_capability_loss(&self) {
        *self.strict_repository_capability_loss_reports.lock() += 1;
    }

    fn has_route(&self, dst: NodeIdentifier, level: ServiceLevel) -> bool {
        match self.routes.lock().as_ref() {
            Some(routes) => routes.contains(&(level, dst)),
            None => true,
        }
    }

    fn has_live_route(&self, dst: NodeIdentifier, level: ServiceLevel) -> bool {
        match self.live_routes.lock().as_ref() {
            Some(routes) => routes.contains(&(level, dst)),
            None => self.has_route(dst, level),
        }
    }

    fn edge_rtt_snapshot(&self) -> Vec<Duration> {
        self.edge_rtts.lock().clone()
    }

    fn route_rtt(&self, dst: NodeIdentifier) -> Option<Duration> {
        self.route_rtts.lock().get(&dst).copied()
    }
}

#[async_trait]
impl OwnerNet for MockNet {
    async fn send_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: OwnerBody,
    ) -> Result<(), ReplicationError> {
        if self.owner_unicast_failures.lock().contains(&dst) {
            return Err(ReplicationError::Malformed(
                "injected owner unicast failure",
            ));
        }
        self.captured.lock().push(CapturedFrame::OwnerUnicast {
            dst,
            topic: topic.to_owned(),
            body,
        });
        Ok(())
    }

    async fn send_broadcast(&self, topic: &str, body: OwnerBody) -> Result<(), ReplicationError> {
        self.captured.lock().push(CapturedFrame::OwnerBroadcast {
            topic: topic.to_owned(),
            body,
        });
        Ok(())
    }

    fn alive_members(&self) -> Vec<NodeIdentifier> {
        self.alive.lock().clone()
    }

    fn local_node_id(&self) -> NodeIdentifier {
        self.self_id
    }

    fn member_boot_epoch(&self, node: NodeIdentifier) -> Option<u64> {
        self.epochs.lock().get(&node).copied()
    }

    fn max_replication_payload_bytes(&self) -> usize {
        *self.max_replication_payload_bytes.lock()
    }
}

// ---------- In-memory test repos ----------

use super::owner::{
    LogSlice as OwnerLog, OwnerReplicable, OwnerSnapshotInstallError, OwnerSnapshotInstallOutcome,
};
use super::strict::{
    HistoryMetadata, LogSlice as StrictLog, StrictCommitApplyOutcome, StrictLogEntry,
    StrictLogMetadata, StrictReplicable, StrictSnapshotError,
};

/// Mock strict-mode repo: holds a `(version, Vec<(version, op, metadata)>)` log.
pub struct CountingStrictRepo {
    pub state: Mutex<(u64, Vec<(u64, u64, Option<StrictLogMetadata>)>)>,
    strict_operation_ids: Mutex<HashSet<(u64, u64)>>,
    strict_protocol_version: u32,
    strict_repository_capable: AtomicBool,
    snapshot_guard: Mutex<()>,
    snapshot_capture_failure: Mutex<Option<String>>,
    snapshot_capture_durability_failure: Mutex<Option<String>>,
    snapshot_install_failure: Mutex<Option<String>>,
    snapshot_install_durability_failure: Mutex<Option<String>>,
    snapshot_install_durability_failure_without_capability_loss: Mutex<Option<String>>,
    ignore_stale_snapshot_installs: AtomicBool,
    strict_apply_failure: Mutex<bool>,
}

#[derive(Serialize, Deserialize)]
struct CountingStrictSnapshot {
    entries: Vec<(u64, u64)>,
    strict_operation_ids: Vec<(u64, u64)>,
}

impl CountingStrictRepo {
    pub fn new() -> Arc<Self> {
        Self::with_strict_protocol_version(crate::overlay::STRICT_REPLICATION_PROTOCOL_VERSION)
    }

    /// A repository fixture advertising the currently supported strict
    /// participant protocol. Integration scenarios that exercise admitted
    /// peers should use this instead of the legacy LSA compatibility value.
    pub fn new_current() -> Arc<Self> {
        Self::with_strict_protocol_version(
            crate::replications::protocol::STRICT_PROTOCOL_VERSION_CURRENT,
        )
    }

    pub fn new_v1() -> Arc<Self> {
        Self::with_strict_protocol_version(1)
    }

    pub fn new_legacy() -> Arc<Self> {
        Self::with_strict_protocol_version(0)
    }

    fn with_strict_protocol_version(strict_protocol_version: u32) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new((0, Vec::new())),
            strict_operation_ids: Mutex::new(HashSet::new()),
            strict_protocol_version,
            strict_repository_capable: AtomicBool::new(true),
            snapshot_guard: Mutex::new(()),
            snapshot_capture_failure: Mutex::new(None),
            snapshot_capture_durability_failure: Mutex::new(None),
            snapshot_install_failure: Mutex::new(None),
            snapshot_install_durability_failure: Mutex::new(None),
            snapshot_install_durability_failure_without_capability_loss: Mutex::new(None),
            ignore_stale_snapshot_installs: AtomicBool::new(false),
            strict_apply_failure: Mutex::new(false),
        })
    }

    pub fn fail_snapshot_captures(&self, message: impl Into<String>) {
        *self.snapshot_capture_failure.lock() = Some(message.into());
    }

    /// Simulate a repository which proves the snapshot failure was durable,
    /// but leaves protocol-capability withdrawal to its caller.
    pub fn fail_snapshot_captures_durably_without_capability_loss(
        &self,
        message: impl Into<String>,
    ) {
        *self.snapshot_capture_durability_failure.lock() = Some(message.into());
    }

    pub fn fail_snapshot_installs(&self, message: impl Into<String>) {
        *self.snapshot_install_failure.lock() = Some(message.into());
    }

    pub fn allow_snapshot_installs(&self) {
        *self.snapshot_install_failure.lock() = None;
    }

    /// Model repositories such as the Ban store, where a snapshot older than
    /// the durable head is an idempotent successful no-op.
    pub fn ignore_stale_snapshot_installs(&self) {
        self.ignore_stale_snapshot_installs
            .store(true, Ordering::Release);
    }

    pub fn fail_snapshot_installs_durably(&self, message: impl Into<String>) {
        *self.snapshot_install_durability_failure.lock() = Some(message.into());
    }

    /// Simulate a conforming repository that returns a typed durability error
    /// while its advertised protocol version has not yet changed.
    pub fn fail_snapshot_installs_durably_without_capability_loss(
        &self,
        message: impl Into<String>,
    ) {
        *self
            .snapshot_install_durability_failure_without_capability_loss
            .lock() = Some(message.into());
    }

    pub fn fail_strict_applies(&self) {
        *self.strict_apply_failure.lock() = true;
    }

    pub fn log(&self) -> Vec<(u64, u64)> {
        self.state
            .lock()
            .1
            .iter()
            .map(|(version, op, _)| (*version, *op))
            .collect()
    }
}

#[async_trait]
impl StrictReplicable for CountingStrictRepo {
    type Op = u64;

    fn strict_replication_protocol_version(&self) -> u32 {
        self.strict_repository_capable
            .load(Ordering::Acquire)
            .then_some(self.strict_protocol_version)
            .unwrap_or_default()
    }

    fn current_version(&self) -> u64 {
        self.state.lock().0
    }

    fn snapshot_with_metadata(&self) -> Result<(HistoryMetadata, Bytes), StrictSnapshotError> {
        let _snapshot_guard = self.snapshot_guard.lock();
        if let Some(message) = self.snapshot_capture_durability_failure.lock().clone() {
            return Err(StrictSnapshotError::durability_failure(message));
        }
        if let Some(message) = self.snapshot_capture_failure.lock().clone() {
            return Err(StrictSnapshotError::new(message));
        }
        let s = self.state.lock();
        let v = s.0;
        let entries: Vec<(u64, u64)> = s.1.iter().map(|(version, op, _)| (*version, *op)).collect();
        drop(s);
        let mut strict_operation_ids: Vec<_> =
            self.strict_operation_ids.lock().iter().copied().collect();
        strict_operation_ids.sort_unstable();
        let bytes = rmp_serde::to_vec(&CountingStrictSnapshot {
            entries,
            strict_operation_ids,
        })
        .map(Bytes::from)
        .map_err(|error| {
            StrictSnapshotError::new(format!("counting snapshot encode failed: {error}"))
        })?;
        Ok((
            HistoryMetadata {
                version: v,
                freshness: 0,
            },
            bytes,
        ))
    }

    fn log_since(&self, since: u64) -> StrictLog<StrictLogEntry<Self::Op>> {
        let s = self.state.lock();
        let log: Vec<_> =
            s.1.iter()
                .filter(|(v, _, _)| *v > since)
                .map(|(version, op, metadata)| {
                    (
                        *version,
                        StrictLogEntry {
                            op: *op,
                            metadata: *metadata,
                        },
                    )
                })
                .collect();
        StrictLog::Available(log)
    }

    async fn apply_committed(&self, version: u64, op: Self::Op) {
        let _snapshot_guard = self.snapshot_guard.lock();
        let mut s = self.state.lock();
        s.0 = version;
        s.1.push((version, op, None));
    }

    async fn apply_committed_with_metadata(
        &self,
        version: u64,
        op: Self::Op,
        metadata: Option<StrictLogMetadata>,
    ) {
        let _snapshot_guard = self.snapshot_guard.lock();
        let mut s = self.state.lock();
        s.0 = version;
        s.1.push((version, op, metadata));
    }

    async fn apply_committed_once(
        &self,
        version: u64,
        op: Self::Op,
        metadata: StrictLogMetadata,
    ) -> StrictCommitApplyOutcome {
        if *self.strict_apply_failure.lock() {
            return StrictCommitApplyOutcome::Failed;
        }
        let _snapshot_guard = self.snapshot_guard.lock();
        let inserted = self
            .strict_operation_ids
            .lock()
            .insert((metadata.op_id_hi, metadata.op_id_lo));
        if !inserted {
            return StrictCommitApplyOutcome::AlreadyApplied;
        }
        let mut s = self.state.lock();
        s.0 = version;
        s.1.push((version, op, Some(metadata)));
        StrictCommitApplyOutcome::Applied
    }

    async fn install_snapshot(
        &self,
        version: u64,
        snapshot: Bytes,
    ) -> Result<(), StrictSnapshotError> {
        let _snapshot_guard = self.snapshot_guard.lock();
        if let Some(message) = self
            .snapshot_install_durability_failure_without_capability_loss
            .lock()
            .clone()
        {
            return Err(StrictSnapshotError::durability_failure(message));
        }
        if let Some(message) = self.snapshot_install_durability_failure.lock().clone() {
            self.strict_repository_capable
                .store(false, Ordering::Release);
            return Err(StrictSnapshotError::durability_failure(message));
        }
        if let Some(message) = self.snapshot_install_failure.lock().clone() {
            return Err(StrictSnapshotError::new(message));
        }
        let decoded: CountingStrictSnapshot =
            rmp_serde::from_slice(&snapshot).map_err(|error| {
                StrictSnapshotError::new(format!("counting snapshot decode failed: {error}"))
            })?;
        {
            let mut s = self.state.lock();
            if self.ignore_stale_snapshot_installs.load(Ordering::Acquire) && version < s.0 {
                return Ok(());
            }
            s.0 = version;
            s.1 = decoded
                .entries
                .into_iter()
                .map(|(version, op)| (version, op, None))
                .collect();
        }
        *self.strict_operation_ids.lock() = decoded.strict_operation_ids.into_iter().collect();
        Ok(())
    }

    async fn install_authoritative_recovery_snapshot(
        &self,
        version: u64,
        snapshot: Bytes,
    ) -> Result<(), StrictSnapshotError> {
        let _snapshot_guard = self.snapshot_guard.lock();
        if let Some(message) = self
            .snapshot_install_durability_failure_without_capability_loss
            .lock()
            .clone()
        {
            return Err(StrictSnapshotError::durability_failure(message));
        }
        if let Some(message) = self.snapshot_install_durability_failure.lock().clone() {
            self.strict_repository_capable
                .store(false, Ordering::Release);
            return Err(StrictSnapshotError::durability_failure(message));
        }
        if let Some(message) = self.snapshot_install_failure.lock().clone() {
            return Err(StrictSnapshotError::new(message));
        }
        let decoded: CountingStrictSnapshot =
            rmp_serde::from_slice(&snapshot).map_err(|error| {
                StrictSnapshotError::new(format!(
                    "counting recovery snapshot decode failed: {error}"
                ))
            })?;
        {
            let mut s = self.state.lock();
            s.0 = version;
            s.1 = decoded
                .entries
                .into_iter()
                .map(|(version, op)| (version, op, None))
                .collect();
        }
        *self.strict_operation_ids.lock() = decoded.strict_operation_ids.into_iter().collect();
        Ok(())
    }
}

#[cfg(test)]
mod strict_repo_tests {
    use super::*;

    #[tokio::test]
    async fn strict_snapshot_preserves_operation_ids_for_duplicate_replay() {
        let source = CountingStrictRepo::new();
        let metadata = StrictLogMetadata {
            op_id_hi: 11,
            op_id_lo: 22,
            ts_final: 33,
        };
        assert_eq!(
            source.apply_committed_once(1, 101, metadata).await,
            StrictCommitApplyOutcome::Applied
        );
        let (version, snapshot) = source.snapshot().expect("snapshot should encode");

        let restored = CountingStrictRepo::new();
        restored
            .install_snapshot(version, snapshot)
            .await
            .expect("snapshot should install");
        assert_eq!(
            restored.apply_committed_once(2, 101, metadata).await,
            StrictCommitApplyOutcome::AlreadyApplied
        );
        assert_eq!(restored.current_version(), 1);
        assert_eq!(restored.log(), vec![(1, 101)]);
    }

    #[tokio::test]
    async fn malformed_strict_snapshot_is_rejected_without_replacing_state() {
        let repo = CountingStrictRepo::new();
        repo.apply_committed(1, 101).await;

        assert!(
            repo.install_snapshot(2, Bytes::from_static(b"not-msgpack"))
                .await
                .is_err()
        );
        assert_eq!(repo.current_version(), 1);
        assert_eq!(repo.log(), vec![(1, 101)]);
    }
}

/// Mock owner-mode repo: holds per-origin `(epoch, version, log)`.
pub struct CountingOwnerRepo {
    pub state: Mutex<std::collections::HashMap<NodeIdentifier, (u64, u64, Vec<(u64, u64)>)>>,
    /// Counts each call to `reset_origin(node, _)`.
    pub reset_calls: Mutex<Vec<(NodeIdentifier, u64)>>,
    /// Counts each call to `remove_origin(node)`.
    pub remove_calls: Mutex<Vec<NodeIdentifier>>,
    history_floors: Mutex<std::collections::HashMap<NodeIdentifier, u64>>,
    snapshot_install_behavior: Mutex<CountingOwnerSnapshotInstallBehavior>,
    snapshot_install_calls: Mutex<Vec<(NodeIdentifier, u64, u64)>>,
    local_version: AtomicU64,
}

enum CountingOwnerSnapshotInstallBehavior {
    Install,
    Defer,
    Fail(String),
}

impl CountingOwnerRepo {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(Default::default()),
            reset_calls: Mutex::new(Vec::new()),
            remove_calls: Mutex::new(Vec::new()),
            history_floors: Mutex::new(Default::default()),
            snapshot_install_behavior: Mutex::new(CountingOwnerSnapshotInstallBehavior::Install),
            snapshot_install_calls: Mutex::new(Vec::new()),
            local_version: AtomicU64::new(0),
        })
    }

    pub fn seed_origin(&self, origin: NodeIdentifier, epoch: u64, log: Vec<(u64, u64)>) {
        let version = log.last().map(|(version, _)| *version).unwrap_or(0);
        self.state.lock().insert(origin, (epoch, version, log));
    }

    pub fn set_local_version(&self, version: u64) {
        self.local_version.store(version, Ordering::Relaxed);
    }

    pub fn prune_through(&self, origin: NodeIdentifier, version: u64) {
        if let Some((_, _, log)) = self.state.lock().get_mut(&origin) {
            log.retain(|(entry_version, _)| *entry_version > version);
        }
        self.history_floors.lock().insert(origin, version);
    }

    pub fn defer_snapshot_installs(&self) {
        *self.snapshot_install_behavior.lock() = CountingOwnerSnapshotInstallBehavior::Defer;
    }

    pub fn fail_snapshot_installs(&self, message: impl Into<String>) {
        *self.snapshot_install_behavior.lock() =
            CountingOwnerSnapshotInstallBehavior::Fail(message.into());
    }

    pub fn allow_snapshot_installs(&self) {
        *self.snapshot_install_behavior.lock() = CountingOwnerSnapshotInstallBehavior::Install;
    }

    pub fn snapshot_install_calls(&self) -> Vec<(NodeIdentifier, u64, u64)> {
        self.snapshot_install_calls.lock().clone()
    }

    pub fn applied_for(&self, origin: NodeIdentifier) -> Vec<(u64, u64)> {
        self.state
            .lock()
            .get(&origin)
            .map(|(_, _, log)| log.clone())
            .unwrap_or_default()
    }

    pub fn reset_calls_for(&self, origin: NodeIdentifier) -> Vec<u64> {
        self.reset_calls
            .lock()
            .iter()
            .filter(|(o, _)| *o == origin)
            .map(|(_, e)| *e)
            .collect()
    }

    pub fn remove_calls_for(&self, origin: NodeIdentifier) -> usize {
        self.remove_calls
            .lock()
            .iter()
            .filter(|node| **node == origin)
            .count()
    }
}

#[async_trait]
impl OwnerReplicable for CountingOwnerRepo {
    type Op = u64;

    fn local_version(&self) -> u64 {
        self.local_version.load(Ordering::Relaxed)
    }

    fn known_versions(&self) -> std::collections::HashMap<NodeIdentifier, (u64, u64)> {
        self.state
            .lock()
            .iter()
            .map(|(k, (e, v, _))| (*k, (*e, *v)))
            .collect()
    }

    fn snapshot_for_origin(&self, origin: NodeIdentifier) -> Option<(u64, u64, Bytes)> {
        let s = self.state.lock();
        s.get(&origin).map(|(e, v, log)| {
            let bytes = Bytes::from(rmp_serde::to_vec(log).unwrap_or_default());
            (*e, *v, bytes)
        })
    }

    fn log_for_origin(&self, origin: NodeIdentifier, since: u64) -> OwnerLog<Self::Op> {
        let s = self.state.lock();
        match s.get(&origin) {
            Some((_, current_version, log)) => {
                let floor = self
                    .history_floors
                    .lock()
                    .get(&origin)
                    .copied()
                    .unwrap_or(0);
                if since < floor {
                    return OwnerLog::TooOld;
                }
                let out: Vec<(u64, u64)> = log
                    .iter()
                    .filter(|entry| entry.0 > since)
                    .copied()
                    .collect();
                let contiguous = if *current_version <= since {
                    out.is_empty()
                } else {
                    out.first()
                        .is_some_and(|(version, _)| *version == since + 1)
                        && out.windows(2).all(|pair| pair[1].0 == pair[0].0 + 1)
                        && out
                            .last()
                            .is_some_and(|(version, _)| version == current_version)
                };
                if contiguous {
                    OwnerLog::Available(out)
                } else {
                    OwnerLog::TooOld
                }
            }
            None => OwnerLog::Available(Vec::new()),
        }
    }

    async fn apply_remote(&self, origin: NodeIdentifier, epoch: u64, version: u64, op: Self::Op) {
        let mut s = self.state.lock();
        let entry = s.entry(origin).or_insert((epoch, 0, Vec::new()));
        entry.0 = epoch;
        entry.1 = version;
        entry.2.push((version, op));
    }

    async fn install_snapshot_for_origin(
        &self,
        origin: NodeIdentifier,
        epoch: u64,
        version: u64,
        snapshot: Bytes,
    ) -> Result<OwnerSnapshotInstallOutcome, OwnerSnapshotInstallError> {
        self.snapshot_install_calls
            .lock()
            .push((origin, epoch, version));
        match &*self.snapshot_install_behavior.lock() {
            CountingOwnerSnapshotInstallBehavior::Install => {}
            CountingOwnerSnapshotInstallBehavior::Defer => {
                return Ok(OwnerSnapshotInstallOutcome::Deferred);
            }
            CountingOwnerSnapshotInstallBehavior::Fail(message) => {
                return Err(OwnerSnapshotInstallError::new(message.clone()));
            }
        }
        let log: Vec<(u64, u64)> = rmp_serde::from_slice(&snapshot).map_err(|error| {
            OwnerSnapshotInstallError::new(format!(
                "counting owner snapshot decode failed: {error}"
            ))
        })?;
        let mut s = self.state.lock();
        s.insert(origin, (epoch, version, log));
        self.history_floors.lock().remove(&origin);
        Ok(OwnerSnapshotInstallOutcome::Installed)
    }

    async fn reset_origin(&self, origin: NodeIdentifier, new_epoch: u64) {
        self.reset_calls.lock().push((origin, new_epoch));
        // Drop the old log; epoch tracker will be set by the next apply.
        let mut s = self.state.lock();
        s.remove(&origin);
    }

    async fn remove_origin(&self, origin: NodeIdentifier) {
        self.remove_calls.lock().push(origin);
        let mut s = self.state.lock();
        s.remove(&origin);
    }
}

// ---------- End-to-end tests using MockNet + counting repos ----------

#[cfg(test)]
mod e2e_tests {
    use prost::Message as _;

    use super::super::config::ReplicationConfig;
    use super::super::owner::runtime::OwnerRuntime;
    use super::super::proto::{
        CatchupOp, OwnerBody, OwnerCatchupReq, OwnerCatchupResp, OwnerOp, StrictBody,
    };
    use super::super::protocol::{STRICT_PROTOCOL_VERSION_CURRENT, STRICT_PROTOCOL_VERSION_V2};
    use super::super::strict::runtime::{StrictRuntime, make_op_id};
    use super::*;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tokio_util::sync::CancellationToken;

    fn default_cfg() -> Arc<ReplicationConfig> {
        Arc::new(ReplicationConfig::default())
    }

    fn proposal_identity(body: &StrictBody) -> Option<(u64, u64, u64)> {
        match body {
            StrictBody::Propose(propose) => {
                Some((propose.op_id_hi, propose.op_id_lo, propose.ts_propose))
            }
            StrictBody::ProposeV1(propose) => {
                Some((propose.op_id_hi, propose.op_id_lo, propose.ts_propose))
            }
            _ => None,
        }
    }

    /// 1-node strict cluster: propose immediately self-acks, commits,
    /// delivers, applies. End-to-end.
    #[tokio::test]
    async fn strict_single_node_propose_end_to_end() {
        let net = MockNet::new(1, vec![1]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_CURRENT);
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo.clone(),
            1,
            42,
            "channels".into(),
            net.clone() as Arc<dyn StrictNet>,
            CancellationToken::new(),
            default_cfg(),
        );
        rt.start();

        let (tx, rx) = oneshot::channel();
        rt.clone().begin_propose(7u64, tx).await.unwrap();
        let version = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("propose should resolve")
            .unwrap()
            .unwrap();
        assert_eq!(version, 1);
        assert_eq!(repo.log(), vec![(1, 7)]);
    }

    #[tokio::test]
    async fn strict_propose_accepts_at_quorum_decision() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_CURRENT);
        net.set_epoch(2, 1);
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo.clone(),
            1,
            42,
            "channels".into(),
            net.clone() as Arc<dyn StrictNet>,
            CancellationToken::new(),
            default_cfg(),
        );
        rt.start();
        rt.finish_history_election_for_test();

        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (delivered_tx, delivered_rx) = oneshot::channel();
        rt.clone()
            .begin_propose_with_accepted(7u64, Some(accepted_tx), delivered_tx)
            .await
            .unwrap();

        let captures = net.drain_captures();
        let (op_id_hi, op_id_lo, ts_propose) = captures
            .iter()
            .find_map(|capture| {
                let CapturedFrame::StrictMulticast { body, .. } = capture else {
                    return None;
                };
                proposal_identity(body)
            })
            .expect("initial propose multicast");

        rt.recv_propose_ack(
            2,
            super::super::proto::StrictProposeAck {
                ack_node: 2,
                coord_node: 1,
                op_id_hi,
                op_id_lo,
                ts_local: ts_propose + 1,
                src_clock: ts_propose + 1,
                ack_boot_epoch: 1,
            },
        )
        .await;
        rt.recv_clock_tick(
            2,
            super::super::proto::StrictClockTick {
                src_node: 2,
                src_clock: ts_propose + 2,
                ..Default::default()
            },
        );
        rt.recv_accept_ack(
            2,
            super::super::proto::StrictAcceptAck {
                ack_node: 2,
                coord_node: 1,
                ballot: 0,
                op_id_hi,
                op_id_lo,
                accepted: true,
                src_clock: ts_propose + 3,
                ack_boot_epoch: 1,
            },
        )
        .await;
        // The protocol needs the local clock to advance beyond the decided
        // timestamp before delivery. Drive that deterministic condition here
        // instead of coupling this quorum test to the background tick cadence.
        rt.advance_clock_for_test(ts_propose + 3);
        rt.wake_delivery_and_clock_tick();

        tokio::time::timeout(Duration::from_secs(1), accepted_rx)
            .await
            .expect("proposal should be accepted")
            .expect("accepted signal should be sent");
        let version = tokio::time::timeout(Duration::from_secs(1), delivered_rx)
            .await
            .expect("proposal should still deliver")
            .unwrap()
            .unwrap();

        assert_eq!(version, 1);
        assert_eq!(repo.log(), vec![(1, 7)]);
    }

    /// recv_propose advances clock by max(clock, ts_propose) + 1 and emits
    /// a StrictProposeAck back to the coord via send_unicast.
    #[tokio::test]
    async fn strict_recv_propose_emits_ack() {
        let op_id = make_op_id(1, 1, 1);
        let net = MockNet::new(2, vec![1, 2]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_CURRENT);
        net.set_epoch(1, 1);
        net.set_epoch(2, 100);
        let repo = CountingStrictRepo::new_current();
        let rt = StrictRuntime::new(
            repo,
            2,
            100,
            "channels".into(),
            net.clone() as Arc<dyn StrictNet>,
            CancellationToken::new(),
            Arc::new(
                ReplicationConfig::default().with_delivery_tick_interval(Duration::from_secs(5)),
            ),
        );
        rt.finish_history_election_for_test();
        // No start(): only the detached ACK effect needs one scheduler turn.

        rt.recv_propose_v1(
            1,
            super::super::proto::StrictProposeV1 {
                coord_node: 1,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_propose: 50,
                op_msgpack: Bytes::from(rmp_serde::to_vec(&7u64).unwrap()),
                src_clock: 50,
                protocol_version: STRICT_PROTOCOL_VERSION_V2,
                frozen_targets: vec![
                    super::super::proto::StrictFrozenTarget {
                        node: 1,
                        boot_epoch: 1,
                    },
                    super::super::proto::StrictFrozenTarget {
                        node: 2,
                        boot_epoch: 100,
                    },
                ],
            },
        )
        .await;
        tokio::task::yield_now().await;

        let caps = net.captures();
        let matching_acks = caps
            .iter()
            .filter(|frame| {
                let body = match frame {
                    CapturedFrame::StrictUnicast { body, .. }
                    | CapturedFrame::StrictMulticast { body, .. }
                    | CapturedFrame::StrictBroadcast { body, .. } => body,
                    _ => return false,
                };
                matches!(
                    body,
                    StrictBody::ProposeAck(ack)
                        if (ack.op_id_hi, ack.op_id_lo) == op_id
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            matching_acks.len(),
            1,
            "the initial propose ack must use one targeted send"
        );
        match matching_acks[0] {
            CapturedFrame::StrictUnicast { dst, body, .. } => {
                assert_eq!(*dst, 1);
                match body {
                    StrictBody::ProposeAck(a) => {
                        assert_eq!(a.ack_node, 2);
                        assert_eq!(a.ts_local, 51);
                    }
                    _ => panic!("expected ProposeAck"),
                }
            }
            f => panic!("expected unicast ack, got {:?}", f),
        }
    }

    #[tokio::test]
    async fn strict_recv_propose_broadcasts_ack_when_initial_unicast_fails() {
        let op_id = make_op_id(1, 1, 2);
        let net = MockNet::new(2, vec![1, 2]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_CURRENT);
        net.set_epoch(1, 1);
        net.set_epoch(2, 100);
        net.fail_strict_unicasts_to([1]);
        let shutdown = CancellationToken::new();
        let rt = StrictRuntime::new(
            CountingStrictRepo::new_current(),
            2,
            100,
            "channels".into(),
            net.clone() as Arc<dyn StrictNet>,
            shutdown.clone(),
            Arc::new(
                ReplicationConfig::default().with_delivery_tick_interval(Duration::from_secs(5)),
            ),
        );
        rt.finish_history_election_for_test();

        rt.recv_propose_v1(
            1,
            super::super::proto::StrictProposeV1 {
                coord_node: 1,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_propose: 50,
                op_msgpack: Bytes::from(rmp_serde::to_vec(&7u64).unwrap()),
                src_clock: 50,
                protocol_version: STRICT_PROTOCOL_VERSION_V2,
                frozen_targets: vec![
                    super::super::proto::StrictFrozenTarget {
                        node: 1,
                        boot_epoch: 1,
                    },
                    super::super::proto::StrictFrozenTarget {
                        node: 2,
                        boot_epoch: 100,
                    },
                ],
            },
        )
        .await;
        tokio::task::yield_now().await;

        let matching_broadcasts = net
            .captures()
            .into_iter()
            .filter(|frame| {
                matches!(
                    frame,
                    CapturedFrame::StrictBroadcast {
                        body: StrictBody::ProposeAck(ack),
                        ..
                    } if (ack.op_id_hi, ack.op_id_lo) == op_id
                )
            })
            .count();
        shutdown.cancel();
        assert_eq!(
            matching_broadcasts, 1,
            "a failed initial targeted ACK must fall back to broadcast"
        );
    }

    #[tokio::test]
    async fn strict_propose_retries_only_missing_acks() {
        let cfg = Arc::new(
            ReplicationConfig::default()
                .with_delivery_tick_interval(Duration::from_millis(10))
                .with_propose_ttl(Duration::from_secs(5)),
        );
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_strict_replication_protocol_version(STRICT_PROTOCOL_VERSION_CURRENT);
        net.set_epoch(2, 1);
        net.set_epoch(3, 1);
        net.set_route_rtt(3, Duration::from_millis(100));
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo,
            1,
            100,
            "channels".into(),
            net.clone() as Arc<dyn StrictNet>,
            CancellationToken::new(),
            cfg,
        );
        let (tx, _rx) = oneshot::channel();
        rt.finish_history_election_for_test();

        rt.clone().begin_propose(11u64, tx).await.unwrap();
        let mut captures = net.drain_captures();
        let (op_id_hi, op_id_lo, ts_propose) = captures
            .iter()
            .find_map(|capture| {
                let CapturedFrame::StrictMulticast { body, .. } = capture else {
                    return None;
                };
                proposal_identity(body)
            })
            .expect("initial propose multicast");
        rt.recv_propose_ack(
            2,
            super::super::proto::StrictProposeAck {
                ack_node: 2,
                coord_node: 1,
                op_id_hi,
                op_id_lo,
                ts_local: ts_propose + 1,
                src_clock: ts_propose + 1,
                ack_boot_epoch: 1,
            },
        )
        .await;

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                captures.extend(net.drain_captures());
                if captures.iter().any(|capture| {
                    matches!(
                        capture,
                        CapturedFrame::StrictUnicast {
                            dst: 3,
                            body: StrictBody::Propose(_) | StrictBody::ProposeV1(_),
                            ..
                        }
                    )
                }) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("retry should target only the peer that has not acked");
    }

    /// Owner-mode: local propose broadcasts, then applies locally.
    #[tokio::test]
    async fn owner_propose_local_broadcasts_then_applies() {
        let net = MockNet::new(7, vec![7, 8, 9]);
        let repo = CountingOwnerRepo::new();
        let rt = OwnerRuntime::new(
            repo.clone(),
            7,
            123,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );
        let v = rt.clone().propose_local(42u64).await.unwrap();
        assert_eq!(v, 1);
        assert_eq!(net.count_owner_broadcasts(), 1);
        // Local apply happens via apply_remote(self_id, ...).
        assert_eq!(repo.applied_for(7), vec![(1, 42)]);
    }

    /// Owner-mode: gap triggers a catchup request on first sight.
    #[tokio::test]
    async fn owner_gap_triggers_catchup_request() {
        let net = MockNet::new(1, vec![1, 2, 3]); // origin 2, helper 3
        net.set_epoch(2, 200);
        let repo = CountingOwnerRepo::new();
        let rt = OwnerRuntime::new(
            repo.clone(),
            1,
            100,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );
        // First sight of origin 2 with a gap at v5.
        rt.recv_op(
            2,
            OwnerOp {
                origin_node: 2,
                origin_epoch: 200,
                origin_version: 5,
                op_msgpack: Bytes::from(rmp_serde::to_vec(&77u64).unwrap()),
            },
        )
        .await;
        // No apply yet (buffered).
        assert!(repo.applied_for(2).is_empty());
        // Should have emitted exactly one catchup req.
        assert_eq!(net.count_owner_unicasts(), 1);
        let caps = net.captures();
        let CapturedFrame::OwnerUnicast { dst, body, .. } = &caps[0] else {
            panic!()
        };
        assert_eq!(*dst, 2, "cold catchup must consult the origin first");
        match body {
            OwnerBody::CatchupReq(req) => {
                assert_eq!(req.origin_node, 2);
                assert_eq!(req.src_node, 1);
            }
            _ => panic!(),
        }
    }

    #[tokio::test]
    async fn owner_catchup_request_uses_chunk_token_as_continuation() {
        let net = MockNet::new(2, vec![1, 2]);
        let repo = CountingOwnerRepo::new();
        repo.state.lock().insert(
            2,
            (
                200,
                5,
                (1u64..=5).map(|version| (version, 700 + version)).collect(),
            ),
        );
        repo.set_local_version(5);
        let rt = OwnerRuntime::new(
            repo,
            2,
            200,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default().with_owner_max_catchup_ops(2)),
        );

        rt.recv_catchup_req(
            1,
            OwnerCatchupReq {
                src_node: 1,
                origin_node: 2,
                known_epoch: 200,
                since_version: 0,
                chunk_token: 2,
            },
        )
        .await;

        let captures = net.drain_captures();
        assert_eq!(captures.len(), 1);
        match &captures[0] {
            CapturedFrame::OwnerUnicast { dst, body, .. } => {
                assert_eq!(*dst, 1);
                let OwnerBody::CatchupResp(resp) = body else {
                    panic!("expected owner catchup response, got {body:?}");
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
    async fn owner_oversized_cold_snapshot_falls_back_to_frame_bounded_log_page() {
        let net = MockNet::new(2, vec![1, 2]);
        let repo = CountingOwnerRepo::new();
        repo.seed_origin(
            2,
            200,
            (1..=100).map(|version| (version, version)).collect(),
        );
        repo.set_local_version(100);

        let one_op = CatchupOp {
            version: 1,
            op_msgpack: Bytes::from(rmp_serde::to_vec(&1u64).unwrap()),
            strict_op_id_hi: 0,
            strict_op_id_lo: 0,
            strict_ts_final: 0,
            strict_terminal_ballot: 0,
            strict_terminal_resolver_node: 0,
            strict_terminal_resolver_boot_epoch: 0,
            strict_terminal_frozen_targets: Vec::new(),
        };
        let budget = super::super::proto::wrap_owner(
            "clients",
            OwnerBody::CatchupResp(OwnerCatchupResp {
                origin_node: 2,
                origin_epoch: 200,
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: vec![one_op],
                has_more: true,
                next_chunk_token: 1,
                too_old_use_snapshot: false,
            }),
        )
        .encoded_len();
        net.set_max_replication_payload_bytes(budget);

        let rt = OwnerRuntime::new(
            repo,
            2,
            200,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );
        rt.recv_catchup_req(
            1,
            OwnerCatchupReq {
                src_node: 1,
                origin_node: 2,
                known_epoch: 200,
                since_version: 0,
                chunk_token: 0,
            },
        )
        .await;

        let captures = net.drain_captures();
        let CapturedFrame::OwnerUnicast { body, .. } = &captures[0] else {
            panic!("expected response");
        };
        let OwnerBody::CatchupResp(resp) = body else {
            panic!("expected owner catchup response");
        };
        assert!(resp.snapshot_msgpack.is_empty());
        assert_eq!(resp.ops.len(), 1);
        assert_eq!(resp.ops[0].version, 1);
        assert!(resp.has_more);
        assert_eq!(resp.next_chunk_token, 1);
        assert!(super::super::proto::wrap_owner("clients", body.clone()).encoded_len() <= budget);
    }

    /// Owner-mode: epoch advance from `OwnerOp.origin_epoch` triggers
    /// `repo.reset_origin` exactly once, then applies the new op.
    #[tokio::test]
    async fn owner_higher_epoch_resets_and_applies() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(2, 11);
        let repo = CountingOwnerRepo::new();
        let rt = OwnerRuntime::new(
            repo.clone(),
            1,
            100,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );

        // Pre-seed knowledge that origin 2 was at (epoch=10, ver=4).
        repo.state
            .lock()
            .insert(2, (10, 4, vec![(1, 1), (2, 2), (3, 3), (4, 4)]));
        rt.state.lock().known.insert(2, (10, 4));

        // Now feed an op with epoch=11.
        rt.recv_op(
            2,
            OwnerOp {
                origin_node: 2,
                origin_epoch: 11,
                origin_version: 1,
                op_msgpack: Bytes::from(rmp_serde::to_vec(&999u64).unwrap()),
            },
        )
        .await;

        // reset_origin should have been called once with new_epoch=11.
        let resets = repo.reset_calls_for(2);
        assert_eq!(resets, vec![11]);
        // The new op is applied at (11, 1).
        assert_eq!(repo.applied_for(2), vec![(1, 999)]);
    }

    /// `MembershipEvent::Restarted` is restart handling: clear old state,
    /// call `reset_origin`, then request catchup from version 0.
    #[tokio::test]
    async fn owner_restarted_event_resets_and_catches_up_from_zero() {
        use crate::overlay::MembershipEvent;
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(2, 11);
        let repo = CountingOwnerRepo::new();
        let rt = OwnerRuntime::new(
            repo.clone(),
            1,
            100,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );

        repo.state
            .lock()
            .insert(2, (10, 2, vec![(1, 100), (2, 200)]));
        rt.state.lock().known.insert(2, (10, 2));

        // Pre-buffer ops at the old epoch.
        rt.state.lock().pending_buffers.insert(2, {
            let mut m = std::collections::BTreeMap::new();
            m.insert(
                3,
                super::super::owner::runtime::OwnerBufferedOp {
                    op_msgpack: bytes::Bytes::from_static(b"x"),
                },
            );
            m
        });
        rt.state
            .lock()
            .catchup_in_flight
            .insert(2, std::time::Instant::now());

        // Restart event arrives.
        rt.on_membership_event(&MembershipEvent::Restarted(
            crate::overlay::MemberIncarnation::new(2, 11),
        ));

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if repo.reset_calls_for(2) == vec![11] && net.count_owner_unicasts() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("restart handling should finish");

        assert!(rt.state.lock().pending_buffers.get(&2).is_none());
        assert!(repo.applied_for(2).is_empty());
        let caps = net.captures();
        let CapturedFrame::OwnerUnicast { body, .. } = &caps[0] else {
            panic!()
        };
        match body {
            OwnerBody::CatchupReq(req) => {
                assert_eq!(req.origin_node, 2);
                assert_eq!(req.known_epoch, 11);
                assert_eq!(req.since_version, 0);
            }
            _ => panic!(),
        }
    }

    /// `MembershipEvent::Failed` removes transient origin state without
    /// treating the event as an owner epoch reset.
    #[tokio::test]
    async fn owner_failed_event_removes_origin_without_epoch_reset() {
        use crate::overlay::MembershipEvent;
        let net = MockNet::new(1, vec![1]);
        let repo = CountingOwnerRepo::new();
        let rt = OwnerRuntime::new(
            repo.clone(),
            1,
            100,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );

        repo.state
            .lock()
            .insert(2, (10, 2, vec![(1, 100), (2, 200)]));
        rt.state.lock().known.insert(2, (10, 2));

        rt.on_membership_event(&MembershipEvent::Failed(
            crate::overlay::MemberIncarnation::new(2, 10),
        ));

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if repo.remove_calls_for(2) == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("offline handling should finish");

        assert_eq!(rt.state.lock().known.get(&2), Some(&(10, 2)));
        assert!(repo.reset_calls_for(2).is_empty());
        assert!(repo.applied_for(2).is_empty());
        assert_eq!(net.count_owner_unicasts(), 0);
    }

    #[tokio::test]
    async fn owner_duplicate_catchup_response_is_idempotent() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(2, 200);
        let repo = CountingOwnerRepo::new();
        let rt = OwnerRuntime::new(
            repo.clone(),
            1,
            100,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );

        let ops: Vec<CatchupOp> = (1..=5u64)
            .map(|version| CatchupOp {
                version,
                op_msgpack: Bytes::from(rmp_serde::to_vec(&(700 + version - 1)).unwrap()),
                strict_op_id_hi: 0,
                strict_op_id_lo: 0,
                strict_ts_final: 0,
                strict_terminal_ballot: 0,
                strict_terminal_resolver_node: 0,
                strict_terminal_resolver_boot_epoch: 0,
                strict_terminal_frozen_targets: Vec::new(),
            })
            .collect();
        let resp = OwnerCatchupResp {
            origin_node: 2,
            origin_epoch: 200,
            snapshot_version: 0,
            snapshot_msgpack: Bytes::new(),
            ops,
            has_more: false,
            next_chunk_token: 0,
            too_old_use_snapshot: false,
        };

        rt.recv_catchup_resp(2, resp.clone()).await;
        rt.recv_catchup_resp(2, resp).await;

        assert_eq!(
            repo.applied_for(2),
            vec![(1, 700), (2, 701), (3, 702), (4, 703), (5, 704)]
        );
        assert_eq!(repo.known_versions().get(&2), Some(&(200, 5)));
    }

    #[test]
    fn owner_runtime_seeds_repository_versions_and_local_zero() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(2, 200);
        let repo = CountingOwnerRepo::new();
        repo.seed_origin(2, 200, vec![(1, 10), (2, 20)]);

        let rt = OwnerRuntime::new(
            repo,
            1,
            100,
            "clients".into(),
            net as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );

        let state = rt.state.lock();
        assert_eq!(state.known.get(&1), Some(&(100, 0)));
        assert_eq!(state.known.get(&2), Some(&(200, 2)));
    }

    #[tokio::test]
    async fn owner_cold_catchup_uses_origin_then_relay_on_send_failure() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_epoch(2, 200);
        net.fail_owner_unicasts_to([2]);
        let repo = CountingOwnerRepo::new();
        let rt = OwnerRuntime::new(
            repo,
            1,
            100,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );

        rt.recv_op(
            2,
            OwnerOp {
                origin_node: 2,
                origin_epoch: 200,
                origin_version: 5,
                op_msgpack: Bytes::from(rmp_serde::to_vec(&50u64).unwrap()),
            },
        )
        .await;

        let captures = net.drain_captures();
        assert_eq!(captures.len(), 1);
        assert!(matches!(
            &captures[0],
            CapturedFrame::OwnerUnicast { dst: 3, body: OwnerBody::CatchupReq(req), .. }
                if req.since_version == 0 && req.known_epoch == 200
        ));
    }

    #[tokio::test]
    async fn owner_lost_origin_response_falls_back_before_anti_entropy() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_epoch(2, 200);
        let shutdown = CancellationToken::new();
        let rt = OwnerRuntime::new(
            CountingOwnerRepo::new(),
            1,
            100,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            shutdown.clone(),
            Arc::new(
                ReplicationConfig::default().with_owner_catchup_timeout(Duration::from_millis(30)),
            ),
        );

        rt.recv_op(
            2,
            OwnerOp {
                origin_node: 2,
                origin_epoch: 200,
                origin_version: 5,
                op_msgpack: Bytes::from(rmp_serde::to_vec(&50u64).unwrap()),
            },
        )
        .await;

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let destinations: Vec<_> = net
                    .captures()
                    .into_iter()
                    .filter_map(|capture| match capture {
                        CapturedFrame::OwnerUnicast {
                            dst,
                            body: OwnerBody::CatchupReq(_),
                            ..
                        } => Some(dst),
                        _ => None,
                    })
                    .collect();
                if destinations.starts_with(&[2]) && destinations.contains(&3) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("lost direct response should fall back to a relay at catchup timeout");
        shutdown.cancel();
    }

    #[tokio::test]
    async fn owner_lost_response_reprobes_origin_when_no_relay_exists() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(2, 200);
        let shutdown = CancellationToken::new();
        let rt = OwnerRuntime::new(
            CountingOwnerRepo::new(),
            1,
            100,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            shutdown.clone(),
            Arc::new(
                ReplicationConfig::default().with_owner_catchup_timeout(Duration::from_millis(30)),
            ),
        );

        rt.recv_op(
            2,
            OwnerOp {
                origin_node: 2,
                origin_epoch: 200,
                origin_version: 5,
                op_msgpack: Bytes::from(rmp_serde::to_vec(&50u64).unwrap()),
            },
        )
        .await;

        tokio::time::timeout(Duration::from_secs(1), async {
            while net.count_owner_unicasts() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("two-node catchup must reprobe the origin at the first timeout");
        assert!(net.captures().into_iter().all(|capture| matches!(
            capture,
            CapturedFrame::OwnerUnicast {
                dst: 2,
                body: OwnerBody::CatchupReq(_),
                ..
            }
        )));
        shutdown.cancel();
    }

    #[tokio::test]
    async fn owner_failed_continuation_send_falls_back_with_same_cursor() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_epoch(2, 200);
        net.fail_owner_unicasts_to([2]);
        let repo = CountingOwnerRepo::new();
        let rt = OwnerRuntime::new(
            repo.clone(),
            1,
            100,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );

        rt.recv_catchup_resp(
            2,
            OwnerCatchupResp {
                origin_node: 2,
                origin_epoch: 200,
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: (1..=2)
                    .map(|version| CatchupOp {
                        version,
                        op_msgpack: Bytes::from(rmp_serde::to_vec(&(700 + version)).unwrap()),
                        strict_op_id_hi: 0,
                        strict_op_id_lo: 0,
                        strict_ts_final: 0,
                        strict_terminal_ballot: 0,
                        strict_terminal_resolver_node: 0,
                        strict_terminal_resolver_boot_epoch: 0,
                        strict_terminal_frozen_targets: Vec::new(),
                    })
                    .collect(),
                has_more: true,
                next_chunk_token: 2,
                too_old_use_snapshot: false,
            },
        )
        .await;

        assert_eq!(repo.applied_for(2), vec![(1, 701), (2, 702)]);
        let captures = net.drain_captures();
        assert_eq!(captures.len(), 1);
        assert!(matches!(
            &captures[0],
            CapturedFrame::OwnerUnicast {
                dst: 3,
                body: OwnerBody::CatchupReq(req),
                ..
            } if req.origin_node == 2
                && req.known_epoch == 200
                && req.since_version == 2
                && req.chunk_token == 2
        ));
    }

    #[tokio::test]
    async fn owner_failed_continuation_send_rearms_bounded_retry_without_relay() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(2, 200);
        net.fail_owner_unicasts_to([2]);
        let shutdown = CancellationToken::new();
        let rt = OwnerRuntime::new(
            CountingOwnerRepo::new(),
            1,
            100,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            shutdown.clone(),
            Arc::new(
                ReplicationConfig::default().with_owner_catchup_timeout(Duration::from_millis(30)),
            ),
        );

        rt.recv_catchup_resp(
            2,
            OwnerCatchupResp {
                origin_node: 2,
                origin_epoch: 200,
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: vec![CatchupOp {
                    version: 1,
                    op_msgpack: Bytes::from(rmp_serde::to_vec(&701u64).unwrap()),
                    strict_op_id_hi: 0,
                    strict_op_id_lo: 0,
                    strict_ts_final: 0,
                    strict_terminal_ballot: 0,
                    strict_terminal_resolver_node: 0,
                    strict_terminal_resolver_boot_epoch: 0,
                    strict_terminal_frozen_targets: Vec::new(),
                }],
                has_more: true,
                next_chunk_token: 1,
                too_old_use_snapshot: false,
            },
        )
        .await;
        assert_eq!(net.count_owner_unicasts(), 0);

        net.fail_owner_unicasts_to([]);
        tokio::time::timeout(Duration::from_secs(1), async {
            while net.count_owner_unicasts() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failed continuation must retry before periodic anti-entropy");

        assert!(matches!(
            &net.captures()[0],
            CapturedFrame::OwnerUnicast {
                dst: 2,
                body: OwnerBody::CatchupReq(req),
                ..
            } if req.origin_node == 2
                && req.known_epoch == 200
                && req.since_version == 1
        ));
        shutdown.cancel();
    }

    #[tokio::test]
    async fn owner_relay_does_not_advertise_runtime_only_progress() {
        let net = MockNet::new(3, vec![1, 2, 3]);
        net.set_epoch(2, 200);
        let repo = CountingOwnerRepo::new();
        let rt = OwnerRuntime::new(
            repo,
            3,
            300,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );
        rt.state.lock().known.insert(2, (200, 5));

        rt.recv_catchup_req(
            1,
            OwnerCatchupReq {
                origin_node: 2,
                src_node: 1,
                known_epoch: 200,
                since_version: 0,
                chunk_token: 0,
            },
        )
        .await;

        let captures = net.drain_captures();
        let CapturedFrame::OwnerUnicast { body, .. } = &captures[0] else {
            panic!("expected relay response");
        };
        let OwnerBody::CatchupResp(resp) = body else {
            panic!("expected catchup response");
        };
        assert_eq!(resp.origin_epoch, 200);
        assert!(resp.ops.is_empty());
        assert!(resp.snapshot_msgpack.is_empty());
    }

    #[tokio::test]
    async fn owner_pruned_gap_returns_snapshot_not_discontinuous_log() {
        let net = MockNet::new(2, vec![1, 2]);
        let repo = CountingOwnerRepo::new();
        repo.seed_origin(
            2,
            200,
            (1..=5).map(|version| (version, version * 10)).collect(),
        );
        repo.set_local_version(5);
        repo.prune_through(2, 2);
        let rt = OwnerRuntime::new(
            repo,
            2,
            200,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );

        rt.recv_catchup_req(
            1,
            OwnerCatchupReq {
                origin_node: 2,
                src_node: 1,
                known_epoch: 200,
                since_version: 1,
                chunk_token: 0,
            },
        )
        .await;

        let captures = net.drain_captures();
        let CapturedFrame::OwnerUnicast { body, .. } = &captures[0] else {
            panic!("expected response");
        };
        let OwnerBody::CatchupResp(resp) = body else {
            panic!("expected catchup response");
        };
        assert!(resp.too_old_use_snapshot);
        assert_eq!(resp.snapshot_version, 5);
        assert!(!resp.snapshot_msgpack.is_empty());
        assert!(resp.ops.is_empty());
    }

    #[tokio::test]
    async fn owner_pruned_gap_never_sends_snapshot_larger_than_frame_budget() {
        let net = MockNet::new(2, vec![1, 2]);
        let repo = CountingOwnerRepo::new();
        repo.seed_origin(
            2,
            200,
            (1..=100).map(|version| (version, version)).collect(),
        );
        repo.set_local_version(100);
        repo.prune_through(2, 2);

        let budget = super::super::proto::wrap_owner(
            "clients",
            OwnerBody::CatchupResp(OwnerCatchupResp {
                origin_node: 2,
                origin_epoch: 200,
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: Vec::new(),
                has_more: false,
                next_chunk_token: 1,
                too_old_use_snapshot: true,
            }),
        )
        .encoded_len();
        net.set_max_replication_payload_bytes(budget);

        let rt = OwnerRuntime::new(
            repo,
            2,
            200,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );
        rt.recv_catchup_req(
            1,
            OwnerCatchupReq {
                src_node: 1,
                origin_node: 2,
                known_epoch: 200,
                since_version: 1,
                chunk_token: 0,
            },
        )
        .await;

        let captures = net.drain_captures();
        let CapturedFrame::OwnerUnicast { body, .. } = &captures[0] else {
            panic!("expected response");
        };
        let OwnerBody::CatchupResp(resp) = body else {
            panic!("expected owner catchup response");
        };
        assert!(resp.too_old_use_snapshot);
        assert!(resp.snapshot_msgpack.is_empty());
        assert!(resp.ops.is_empty());
        assert!(super::super::proto::wrap_owner("clients", body.clone()).encoded_len() <= budget);
    }

    #[tokio::test]
    async fn owner_first_op_over_budget_is_never_reported_as_empty_origin() {
        let net = MockNet::new(2, vec![1, 2]);
        let repo = CountingOwnerRepo::new();
        repo.seed_origin(2, 200, vec![(1, 10)]);
        repo.set_local_version(1);

        let budget = super::super::proto::wrap_owner(
            "clients",
            OwnerBody::CatchupResp(OwnerCatchupResp {
                origin_node: 2,
                origin_epoch: 200,
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: Vec::new(),
                has_more: false,
                next_chunk_token: 0,
                too_old_use_snapshot: true,
            }),
        )
        .encoded_len();
        net.set_max_replication_payload_bytes(budget);

        let rt = OwnerRuntime::new(
            repo,
            2,
            200,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );
        rt.recv_catchup_req(
            1,
            OwnerCatchupReq {
                src_node: 1,
                origin_node: 2,
                known_epoch: 200,
                since_version: 0,
                chunk_token: 0,
            },
        )
        .await;

        let captures = net.drain_captures();
        let CapturedFrame::OwnerUnicast { body, .. } = &captures[0] else {
            panic!("expected response");
        };
        let OwnerBody::CatchupResp(resp) = body else {
            panic!("expected owner catchup response");
        };
        assert!(resp.too_old_use_snapshot);
        assert!(resp.snapshot_msgpack.is_empty());
        assert!(resp.ops.is_empty());
        assert!(super::super::proto::wrap_owner("clients", body.clone()).encoded_len() <= budget);
    }

    #[tokio::test]
    async fn owner_deferred_and_invalid_snapshots_do_not_advance_or_apply_tail() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(2, 200);
        let repo = CountingOwnerRepo::new();
        repo.seed_origin(2, 200, vec![(1, 10), (2, 20)]);
        let shutdown = CancellationToken::new();
        let rt = OwnerRuntime::new(
            repo.clone(),
            1,
            100,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            shutdown.clone(),
            Arc::new(
                ReplicationConfig::default().with_owner_catchup_timeout(Duration::from_millis(30)),
            ),
        );
        let snapshot =
            Bytes::from(rmp_serde::to_vec(&vec![(1u64, 10u64), (2, 20), (3, 30)]).unwrap());
        let tail = CatchupOp {
            version: 4,
            op_msgpack: Bytes::from(rmp_serde::to_vec(&40u64).unwrap()),
            strict_op_id_hi: 0,
            strict_op_id_lo: 0,
            strict_ts_final: 0,
            strict_terminal_ballot: 0,
            strict_terminal_resolver_node: 0,
            strict_terminal_resolver_boot_epoch: 0,
            strict_terminal_frozen_targets: Vec::new(),
        };
        let response = OwnerCatchupResp {
            origin_node: 2,
            origin_epoch: 200,
            snapshot_version: 3,
            snapshot_msgpack: snapshot.clone(),
            ops: vec![tail.clone()],
            has_more: false,
            next_chunk_token: 0,
            too_old_use_snapshot: true,
        };

        repo.defer_snapshot_installs();
        rt.recv_catchup_resp(2, response.clone()).await;
        assert_eq!(rt.state.lock().known.get(&2), Some(&(200, 2)));
        assert_eq!(repo.applied_for(2), vec![(1, 10), (2, 20)]);

        tokio::time::timeout(Duration::from_secs(1), async {
            while net.count_owner_unicasts() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("deferred snapshot should retry at catchup timeout");
        net.drain_captures();

        repo.allow_snapshot_installs();
        let mut invalid = response.clone();
        invalid.snapshot_version = 2;
        invalid.snapshot_msgpack = Bytes::from_static(b"not-msgpack");
        rt.recv_catchup_resp(2, invalid).await;
        assert_eq!(rt.state.lock().known.get(&2), Some(&(200, 2)));
        assert_eq!(repo.applied_for(2), vec![(1, 10), (2, 20)]);

        rt.recv_catchup_resp(2, response).await;
        assert_eq!(rt.state.lock().known.get(&2), Some(&(200, 4)));
        assert_eq!(
            repo.applied_for(2),
            vec![(1, 10), (2, 20), (3, 30), (4, 40)]
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn owner_installed_snapshot_drains_buffered_suffix_once() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(2, 200);
        let repo = CountingOwnerRepo::new();
        repo.seed_origin(2, 200, vec![(1, 10), (2, 20)]);
        let rt = OwnerRuntime::new(
            repo.clone(),
            1,
            100,
            "clients".into(),
            net as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );
        rt.state
            .lock()
            .buffer_op(2, 4, Bytes::from(rmp_serde::to_vec(&40u64).unwrap()));
        let snapshot =
            Bytes::from(rmp_serde::to_vec(&vec![(1u64, 10u64), (2, 20), (3, 30)]).unwrap());

        rt.recv_catchup_resp(
            2,
            OwnerCatchupResp {
                origin_node: 2,
                origin_epoch: 200,
                snapshot_version: 3,
                snapshot_msgpack: snapshot,
                ops: vec![],
                has_more: false,
                next_chunk_token: 0,
                too_old_use_snapshot: true,
            },
        )
        .await;

        assert_eq!(rt.state.lock().known.get(&2), Some(&(200, 4)));
        assert!(rt.state.lock().pending_buffers.get(&2).is_none());
        assert_eq!(
            repo.applied_for(2),
            vec![(1, 10), (2, 20), (3, 30), (4, 40)]
        );
    }

    #[tokio::test]
    async fn owner_stale_lsdb_epoch_cannot_mutate_repository() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(2, 201);
        let repo = CountingOwnerRepo::new();
        repo.seed_origin(2, 200, vec![(1, 10), (2, 20)]);
        let rt = OwnerRuntime::new(
            repo.clone(),
            1,
            100,
            "clients".into(),
            net as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );

        rt.recv_op(
            2,
            OwnerOp {
                origin_node: 2,
                origin_epoch: 200,
                origin_version: 3,
                op_msgpack: Bytes::from(rmp_serde::to_vec(&30u64).unwrap()),
            },
        )
        .await;
        rt.recv_catchup_resp(
            2,
            OwnerCatchupResp {
                origin_node: 2,
                origin_epoch: 200,
                snapshot_version: 3,
                snapshot_msgpack: Bytes::from_static(b"not-msgpack"),
                ops: vec![],
                has_more: false,
                next_chunk_token: 0,
                too_old_use_snapshot: true,
            },
        )
        .await;

        assert_eq!(repo.applied_for(2), vec![(1, 10), (2, 20)]);
        assert!(repo.snapshot_install_calls().is_empty());
        assert_eq!(rt.state.lock().known.get(&2), Some(&(200, 2)));
    }

    #[tokio::test]
    async fn owner_offline_floor_blocks_regressive_same_epoch_snapshot() {
        use crate::overlay::MembershipEvent;
        let net = MockNet::new(1, vec![1]);
        net.set_epoch(2, 200);
        let repo = CountingOwnerRepo::new();
        repo.seed_origin(2, 200, vec![(1, 10), (2, 20)]);
        let rt = OwnerRuntime::new(
            repo.clone(),
            1,
            100,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );

        rt.on_membership_event(&MembershipEvent::Failed(
            crate::overlay::MemberIncarnation::new(2, 200),
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while repo.remove_calls_for(2) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(rt.state.lock().known.get(&2), Some(&(200, 2)));
        assert!(repo.applied_for(2).is_empty());

        net.set_alive(vec![1, 2]);
        rt.recv_catchup_resp(
            2,
            OwnerCatchupResp {
                origin_node: 2,
                origin_epoch: 200,
                snapshot_version: 1,
                snapshot_msgpack: Bytes::from(rmp_serde::to_vec(&vec![(1u64, 10u64)]).unwrap()),
                ops: vec![],
                has_more: false,
                next_chunk_token: 0,
                too_old_use_snapshot: true,
            },
        )
        .await;

        assert_eq!(rt.state.lock().known.get(&2), Some(&(200, 2)));
        assert!(repo.applied_for(2).is_empty());
        assert!(repo.snapshot_install_calls().is_empty());

        rt.recv_catchup_resp(
            2,
            OwnerCatchupResp {
                origin_node: 2,
                origin_epoch: 200,
                snapshot_version: 2,
                snapshot_msgpack: Bytes::from(
                    rmp_serde::to_vec(&vec![(1u64, 10u64), (2, 20)]).unwrap(),
                ),
                ops: vec![],
                has_more: false,
                next_chunk_token: 0,
                too_old_use_snapshot: true,
            },
        )
        .await;

        assert_eq!(repo.applied_for(2), vec![(1, 10), (2, 20)]);
        assert_eq!(rt.state.lock().known.get(&2), Some(&(200, 2)));
    }

    #[tokio::test]
    async fn owner_duplicate_same_epoch_restart_does_not_erase_new_state() {
        use crate::overlay::MembershipEvent;
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(2, 11);
        let repo = CountingOwnerRepo::new();
        repo.seed_origin(2, 11, vec![(1, 99)]);
        let rt = OwnerRuntime::new(
            repo.clone(),
            1,
            100,
            "clients".into(),
            net as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );

        rt.on_membership_event(&MembershipEvent::Restarted(
            crate::overlay::MemberIncarnation::new(2, 11),
        ));
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(repo.reset_calls_for(2).is_empty());
        assert_eq!(repo.applied_for(2), vec![(1, 99)]);
        assert_eq!(rt.state.lock().known.get(&2), Some(&(11, 1)));
    }

    #[tokio::test]
    async fn owner_empty_catchup_response_keeps_retry_gate() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        net.set_epoch(2, 200);
        let repo = CountingOwnerRepo::new();
        let rt = OwnerRuntime::new(
            repo.clone(),
            1,
            100,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            default_cfg(),
        );

        let timeout = rt.cfg.owner_catchup_timeout();
        let t0 = std::time::Instant::now();
        assert!(rt.state.lock().arm_catchup(2, t0, timeout));

        rt.recv_catchup_resp(
            3,
            OwnerCatchupResp {
                origin_node: 2,
                origin_epoch: 200,
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: vec![],
                has_more: false,
                next_chunk_token: 0,
                too_old_use_snapshot: false,
            },
        )
        .await;

        let mut state = rt.state.lock();
        assert!(state.catchup_in_flight.get(&2).is_some());
        assert!(!state.arm_catchup(2, t0 + Duration::from_millis(1), timeout));
    }

    #[tokio::test]
    async fn owner_converged_nonzero_empty_response_does_not_rearm_retry() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(2, 200);
        let repo = CountingOwnerRepo::new();
        repo.seed_origin(2, 200, vec![(1, 10), (2, 20)]);
        let rt = OwnerRuntime::new(
            repo.clone(),
            1,
            100,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            Arc::new(
                ReplicationConfig::default().with_owner_catchup_timeout(Duration::from_millis(30)),
            ),
        );

        rt.recv_catchup_resp(
            2,
            OwnerCatchupResp {
                origin_node: 2,
                origin_epoch: 200,
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: Vec::new(),
                has_more: false,
                next_chunk_token: 0,
                too_old_use_snapshot: false,
            },
        )
        .await;

        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(net.captures().is_empty());
        assert!(repo.reset_calls_for(2).is_empty());
        assert_eq!(rt.state.lock().known.get(&2), Some(&(200, 2)));
    }

    #[tokio::test]
    async fn owner_delayed_empty_response_cannot_erase_inactive_same_epoch_floor() {
        use crate::overlay::MembershipEvent;

        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(2, 200);
        let repo = CountingOwnerRepo::new();
        repo.seed_origin(2, 200, vec![(1, 10), (2, 20)]);
        let rt = OwnerRuntime::new(
            repo.clone(),
            1,
            100,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            Arc::new(
                ReplicationConfig::default().with_owner_catchup_timeout(Duration::from_millis(30)),
            ),
        );

        net.set_alive(vec![1]);
        rt.on_membership_event(&MembershipEvent::Failed(
            crate::overlay::MemberIncarnation::new(2, 200),
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !repo.applied_for(2).is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("offline handling should retain an inactive floor");
        net.set_alive(vec![1, 2]);

        rt.recv_catchup_resp(
            2,
            OwnerCatchupResp {
                origin_node: 2,
                origin_epoch: 200,
                snapshot_version: 0,
                snapshot_msgpack: Bytes::new(),
                ops: Vec::new(),
                has_more: false,
                next_chunk_token: 0,
                too_old_use_snapshot: false,
            },
        )
        .await;

        assert!(repo.reset_calls_for(2).is_empty());
        assert_eq!(rt.state.lock().known.get(&2), Some(&(200, 2)));
    }
}
