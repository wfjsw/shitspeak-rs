//! Per-topic owner-mode runtime.
//!
//! State is keyed by origin node id. The owner reads its own
//! `boot_epoch` from the overlay once at start; remote epochs come from
//! `OwnerOp.origin_epoch` and from `MembershipEvent::Restarted`. The
//! runtime never mints epochs.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use prost::Message as _;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use super::super::config::ReplicationConfig;
use super::super::error::ReplicationError;
use super::super::metrics::{self, CatchupMode, ReplicationPipelineKind, ReplicationPipelineStage};
use super::super::proto::{
    self as repl_proto, OwnerBody, OwnerCatchupReq, OwnerOp, REPLICATION_SERVICE_TAG,
};
use super::super::protocol::advertised_replication_capabilities;
use super::super::topic::ErasedOwnerRuntime;
use super::OwnerReplicable;
use crate::overlay::{LaneId, MembershipEvent, OverlayNetwork, OverlaySendOptions};
use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{MessageClass, ServiceLevel};

/// End-to-end ACKed overlay lane reserved for owner replication. This keeps
/// broadcast operations retained across connection replacement until every
/// destination has acknowledged them, so a periodic repair loop is not needed
/// to cover a missed tail.
const OWNER_REPLICATION_LANE: LaneId =
    LaneId::new(NonZeroU32::new(0x4f57_4e52).expect("owner replication lane id is non-zero"));

#[async_trait]
pub(crate) trait OwnerNet: Send + Sync + 'static {
    async fn send_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: OwnerBody,
    ) -> Result<(), ReplicationError>;
    async fn send_bulk_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: OwnerBody,
        _retry_delay: Duration,
    ) -> Result<(), ReplicationError> {
        self.send_unicast(dst, topic, body).await
    }
    async fn send_broadcast(&self, topic: &str, body: OwnerBody) -> Result<(), ReplicationError>;
    /// Exact encoded replication payload length before the overlay envelope
    /// is added. Keeping this on the network abstraction makes catchup
    /// admission use the same representation as transmission.
    fn encoded_owner_payload_len(
        &self,
        topic: &str,
        body: &OwnerBody,
    ) -> Result<usize, ReplicationError> {
        Ok(repl_proto::wrap_owner(topic, body.clone()).encoded_len())
    }
    /// Maximum payload budget for one replication message after accounting
    /// for the local transport frame and overlay envelope.
    fn max_replication_payload_bytes(&self) -> usize {
        usize::MAX
    }
    fn alive_members(&self) -> Vec<NodeIdentifier>;
    fn local_node_id(&self) -> NodeIdentifier;
    /// Look up an origin's `boot_epoch` via the overlay's LSDB. Used after
    /// a `Restarted` event to learn the new epoch.
    fn member_boot_epoch(&self, node: NodeIdentifier) -> Option<u64>;
}

pub(crate) struct OverlayOwnerNet {
    pub overlay: OverlayNetwork,
}

#[async_trait]
impl OwnerNet for OverlayOwnerNet {
    async fn send_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: OwnerBody,
    ) -> Result<(), ReplicationError> {
        let options = if matches!(&body, OwnerBody::CatchupResp(_)) {
            OverlaySendOptions::default().allow_l1_compression()
        } else {
            OverlaySendOptions::default()
        };
        let msg = repl_proto::wrap_owner(topic, body);
        let encode_started_at = Instant::now();
        let encoded = repl_proto::encode(&msg);
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Owner,
            ReplicationPipelineStage::ProtobufEncode,
            encode_started_at.elapsed(),
        );
        let bytes = encoded?;
        self.overlay
            .send_unicast_on_lane_with_options(
                dst,
                OWNER_REPLICATION_LANE,
                REPLICATION_SERVICE_TAG,
                ServiceLevel::Reliable,
                MessageClass::Regular,
                bytes,
                options,
            )
            .await?;
        Ok(())
    }

    async fn send_broadcast(&self, topic: &str, body: OwnerBody) -> Result<(), ReplicationError> {
        let msg = repl_proto::wrap_owner(topic, body);
        let encode_started_at = Instant::now();
        let encoded = repl_proto::encode(&msg);
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Owner,
            ReplicationPipelineStage::ProtobufEncode,
            encode_started_at.elapsed(),
        );
        let bytes = encoded?;
        let dsts = self
            .alive_members()
            .into_iter()
            .filter(|node| *node != self.local_node_id())
            .collect::<Vec<_>>();
        if dsts.is_empty() {
            return Ok(());
        }
        self.overlay
            .send_multicast_on_lane(
                &dsts,
                OWNER_REPLICATION_LANE,
                REPLICATION_SERVICE_TAG,
                ServiceLevel::Reliable,
                MessageClass::Regular,
                bytes,
            )
            .await?;
        Ok(())
    }

    async fn send_bulk_unicast(
        &self,
        dst: NodeIdentifier,
        topic: &str,
        body: OwnerBody,
        retry_delay: Duration,
    ) -> Result<(), ReplicationError> {
        let msg = repl_proto::wrap_owner(topic, body);
        let encode_started_at = Instant::now();
        let encoded = repl_proto::encode(&msg);
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Owner,
            ReplicationPipelineStage::ProtobufEncode,
            encode_started_at.elapsed(),
        );
        let bytes = encoded?;
        let options = OverlaySendOptions::default()
            .allow_l1_compression()
            .expire_after(retry_delay);
        let result = self
            .overlay
            .send_unicast_on_lane_with_options(
                dst,
                OWNER_REPLICATION_LANE,
                REPLICATION_SERVICE_TAG,
                ServiceLevel::Reliable,
                MessageClass::Regular,
                bytes.clone(),
                options,
            )
            .await;
        if let Err(error) = result {
            if replication_bulk_backpressure(&error) {
                sleep(retry_delay).await;
                self.overlay
                    .send_unicast_on_lane_with_options(
                        dst,
                        OWNER_REPLICATION_LANE,
                        REPLICATION_SERVICE_TAG,
                        ServiceLevel::Reliable,
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

    fn alive_members(&self) -> Vec<NodeIdentifier> {
        self.overlay
            .members()
            .into_iter()
            .filter(|member| member.status().is_reachable())
            .filter(|member| {
                let legacy = member.replication_services();
                advertised_replication_capabilities(
                    member.upper_layer_capabilities(),
                    legacy.strict(),
                    legacy.content(),
                    legacy.owner(),
                    member.strict_replication_protocol_version(),
                )
                .owner_enabled()
            })
            .map(|member| member.node_id())
            .collect()
    }

    fn local_node_id(&self) -> NodeIdentifier {
        self.overlay.local_node_id()
    }

    fn member_boot_epoch(&self, node: NodeIdentifier) -> Option<u64> {
        self.overlay.member(node).map(|m| m.boot_epoch())
    }

    fn max_replication_payload_bytes(&self) -> usize {
        self.overlay.max_replication_payload_bytes()
    }
}

fn replication_bulk_backpressure(error: &crate::overlay::OverlayError) -> bool {
    matches!(
        error,
        crate::overlay::OverlayError::Send(shitspeak_s2s_transport::SendError::Backpressure { .. })
    )
}

/// One pending out-of-order op buffered until the gap fills (or a snapshot
/// arrives via catchup).
pub(crate) struct OwnerBufferedOp {
    pub op_msgpack: Bytes,
}

#[derive(Clone, Copy)]
struct OwnerCatchupAttempt {
    generation: u64,
    epoch: u64,
    since_version: u64,
    gap_target_version: Option<u64>,
    chunk_token: u64,
    dst: NodeIdentifier,
}

pub(crate) struct OwnerState {
    /// `known[origin] = (epoch, last_applied_version)` for every origin
    /// we've ever seen.
    pub known: HashMap<NodeIdentifier, (u64, u64)>,
    /// Per-origin buffer of received-out-of-order ops, keyed by version.
    /// Cleared on epoch reset.
    pub pending_buffers: HashMap<NodeIdentifier, BTreeMap<u64, OwnerBufferedOp>>,
    /// Last time we issued a catchup request for `origin`. Despite the
    /// historical name, this remains set after a response so periodic
    /// anti-entropy cannot retry faster than `CATCHUP_TIMEOUT`.
    pub catchup_in_flight: HashMap<NodeIdentifier, Instant>,
    /// Origins whose transient repository state was removed while offline.
    /// Their `known` entry remains as a non-regression floor until an atomic
    /// snapshot at the same or a newer epoch is installed.
    inactive_origins: HashSet<NodeIdentifier>,
    catchup_attempts: HashMap<NodeIdentifier, OwnerCatchupAttempt>,
    empty_confirmations: HashMap<NodeIdentifier, (u64, u8)>,
    next_catchup_generation: u64,
}

impl OwnerState {
    pub fn new() -> Self {
        Self::with_known(HashMap::new())
    }

    pub fn with_known(known: HashMap<NodeIdentifier, (u64, u64)>) -> Self {
        Self {
            known,
            pending_buffers: HashMap::new(),
            catchup_in_flight: HashMap::new(),
            inactive_origins: HashSet::new(),
            catchup_attempts: HashMap::new(),
            empty_confirmations: HashMap::new(),
            next_catchup_generation: 0,
        }
    }

    /// Handle a fresh `OwnerOp` or one drained from the buffer.
    /// Returns one of:
    ///   * `Apply { epoch, version, op_msgpack }` if the op is the
    ///     expected next-version for the (origin, epoch);
    ///   * `Reset { new_epoch }` if `op.epoch > known.epoch`;
    ///   * `Buffer { epoch }` if there's a forward gap;
    ///   * `Drop { reason }` for stale ops.
    pub fn classify_op(&self, origin: NodeIdentifier, op: &OwnerOp) -> Classification {
        match self.known.get(&origin).copied() {
            None => {
                if op.origin_version == 1 {
                    Classification::Apply
                } else if op.origin_version == 0 {
                    Classification::Drop("origin_version 0 is invalid")
                } else {
                    Classification::Buffer
                }
            }
            Some((known_epoch, known_version)) => {
                if op.origin_epoch < known_epoch {
                    Classification::Drop("stale epoch")
                } else if op.origin_epoch > known_epoch {
                    Classification::Reset {
                        new_epoch: op.origin_epoch,
                    }
                } else if op.origin_version == known_version + 1 {
                    Classification::Apply
                } else if op.origin_version <= known_version {
                    Classification::Drop("duplicate or stale version")
                } else {
                    // version > known_version + 1 => gap
                    Classification::Buffer
                }
            }
        }
    }

    /// Record a successful apply, advance `known.version`.
    pub fn record_applied(&mut self, origin: NodeIdentifier, epoch: u64, version: u64) {
        match self.known.get(&origin).copied() {
            Some((known_epoch, known_version))
                if known_epoch > epoch || (known_epoch == epoch && known_version >= version) => {}
            _ => {
                self.known.insert(origin, (epoch, version));
            }
        }
        if let Some(buffer) = self.pending_buffers.get_mut(&origin) {
            buffer.retain(|pending_version, _| *pending_version > version);
            if buffer.is_empty() {
                self.pending_buffers.remove(&origin);
            }
        }
        if version > 0 {
            self.empty_confirmations.remove(&origin);
        }
    }

    /// Insert a buffered out-of-order op. Returns `true` if the buffer was
    /// previously empty (i.e. caller should consider arming catchup).
    pub fn buffer_op(&mut self, origin: NodeIdentifier, version: u64, op_msgpack: Bytes) -> bool {
        let buf = self.pending_buffers.entry(origin).or_default();
        let was_empty = buf.is_empty();
        buf.entry(version).or_insert(OwnerBufferedOp { op_msgpack });
        was_empty
    }

    /// After applying at `(epoch, new_version)`, drain any contiguous
    /// buffered ops at `new_version + 1, new_version + 2, …` for the same
    /// origin. Returns them in version order.
    pub fn drain_contiguous(
        &mut self,
        origin: NodeIdentifier,
        new_version: u64,
    ) -> Vec<(u64, Bytes)> {
        let mut out = Vec::new();
        let Some(buf) = self.pending_buffers.get_mut(&origin) else {
            return out;
        };
        let mut next = new_version + 1;
        while let Some(b) = buf.remove(&next) {
            out.push((next, b.op_msgpack));
            next += 1;
        }
        out
    }

    /// Discard snapshot-covered buffered entries while retaining a valid
    /// same-epoch suffix that can be drained after installation.
    pub fn discard_pending_through(&mut self, origin: NodeIdentifier, version: u64) {
        let Some(buffer) = self.pending_buffers.get_mut(&origin) else {
            return;
        };
        buffer.retain(|pending_version, _| *pending_version > version);
        if buffer.is_empty() {
            self.pending_buffers.remove(&origin);
        }
    }

    pub fn take_next_buffered(&mut self, origin: NodeIdentifier, version: u64) -> Option<Bytes> {
        let buffer = self.pending_buffers.get_mut(&origin)?;
        let bytes = buffer
            .remove(&(version + 1))
            .map(|buffered| buffered.op_msgpack);
        if buffer.is_empty() {
            self.pending_buffers.remove(&origin);
        }
        bytes
    }

    /// Wipe pending state for `origin` (used on epoch reset).
    pub fn wipe_origin(&mut self, origin: NodeIdentifier) {
        self.pending_buffers.remove(&origin);
        self.catchup_in_flight.remove(&origin);
        self.catchup_attempts.remove(&origin);
        self.empty_confirmations.remove(&origin);
    }

    fn record_empty_confirmation(&mut self, origin: NodeIdentifier, epoch: u64) -> u8 {
        let entry = self.empty_confirmations.entry(origin).or_insert((epoch, 0));
        if entry.0 != epoch {
            *entry = (epoch, 0);
        }
        entry.1 = entry.1.saturating_add(1).min(2);
        entry.1
    }

    fn empty_is_confirmed(&self, origin: NodeIdentifier, epoch: u64) -> bool {
        self.empty_confirmations
            .get(&origin)
            .is_some_and(|(confirmed_epoch, confirmations)| {
                *confirmed_epoch == epoch && *confirmations >= 2
            })
    }

    fn record_catchup_attempt(
        &mut self,
        origin: NodeIdentifier,
        epoch: u64,
        since_version: u64,
        gap_target_version: Option<u64>,
        chunk_token: u64,
        dst: NodeIdentifier,
    ) -> u64 {
        self.next_catchup_generation = self.next_catchup_generation.wrapping_add(1).max(1);
        let generation = self.next_catchup_generation;
        self.catchup_attempts.insert(
            origin,
            OwnerCatchupAttempt {
                generation,
                epoch,
                since_version,
                gap_target_version,
                chunk_token,
                dst,
            },
        );
        generation
    }

    /// Cancel a request watchdog once ordinary owner broadcasts have advanced
    /// beyond the version it requested and left no unresolved gap behind.
    /// Keep `catchup_in_flight` as the anti-entropy throttle timestamp.
    fn cancel_satisfied_catchup_attempt(&mut self, origin: NodeIdentifier, epoch: u64) -> bool {
        let Some(attempt) = self.catchup_attempts.get(&origin).copied() else {
            return false;
        };
        let caught_up_by_broadcast = attempt.gap_target_version.is_some_and(|target| {
            self.known
                .get(&origin)
                .is_some_and(|(known_epoch, known_version)| {
                    *known_epoch == epoch && *known_version >= target
                })
        }) && !self.pending_buffers.contains_key(&origin)
            && !self.inactive_origins.contains(&origin);
        if caught_up_by_broadcast {
            self.catchup_attempts.remove(&origin);
        }
        caught_up_by_broadcast
    }

    /// Should we issue a catchup for `origin`? Suppresses duplicates within
    /// `catchup_timeout`.
    pub fn arm_catchup(
        &mut self,
        origin: NodeIdentifier,
        now: Instant,
        catchup_timeout: Duration,
    ) -> bool {
        match self.catchup_in_flight.get(&origin) {
            Some(t) if now.duration_since(*t) < catchup_timeout => false,
            _ => {
                self.catchup_in_flight.insert(origin, now);
                true
            }
        }
    }

    /// A newly observed forward gap needs an immediate request even when a
    /// recent bootstrap or anti-entropy probe is still inside the throttle
    /// window. Callers only use this when the origin's pending buffer changes
    /// from empty to non-empty, which keeps later out-of-order ops deduplicated.
    pub fn arm_gap_catchup(&mut self, origin: NodeIdentifier, now: Instant) {
        self.catchup_in_flight.insert(origin, now);
    }
}

impl Default for OwnerState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Classification {
    Apply,
    Reset { new_epoch: u64 },
    Buffer,
    Drop(&'static str),
}

pub(crate) struct OwnerRuntime<R: OwnerReplicable> {
    pub repo: Arc<R>,
    pub self_id: NodeIdentifier,
    pub self_epoch: u64,
    pub topic: String,
    pub net: Arc<dyn OwnerNet>,
    pub state: Mutex<OwnerState>,
    pub local_counter: AtomicU64,
    pub weak_self: Mutex<Option<Weak<Self>>>,
    pub shutdown: CancellationToken,
    pub cfg: Arc<ReplicationConfig>,
    origin_locks: Mutex<HashMap<NodeIdentifier, Arc<AsyncMutex<()>>>>,
}

impl<R: OwnerReplicable> OwnerRuntime<R> {
    pub fn new(
        repo: Arc<R>,
        self_id: NodeIdentifier,
        self_epoch: u64,
        topic: String,
        net: Arc<dyn OwnerNet>,
        shutdown: CancellationToken,
        cfg: Arc<ReplicationConfig>,
    ) -> Arc<Self> {
        // Seed local_counter from the repo's existing local_version (so a
        // restart with state already loaded continues monotonically).
        let initial = repo.local_version();
        let mut known = repo.known_versions();
        // The local incarnation is authoritative even when an intentionally
        // empty, in-memory repository has no local shard to report yet.
        known.insert(self_id, (self_epoch, initial));
        let arc = Arc::new(Self {
            repo,
            self_id,
            self_epoch,
            topic,
            net,
            state: Mutex::new(OwnerState::with_known(known)),
            local_counter: AtomicU64::new(initial),
            weak_self: Mutex::new(None),
            shutdown,
            cfg,
            origin_locks: Mutex::new(HashMap::new()),
        });
        *arc.weak_self.lock() = Some(Arc::downgrade(&arc));
        arc
    }

    pub fn start(self: &Arc<Self>) {
        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            runtime.bootstrap_catchup_alive_members().await;
        });
    }

    pub(super) async fn lock_origin(&self, origin: NodeIdentifier) -> OwnedMutexGuard<()> {
        let lock = self
            .origin_locks
            .lock()
            .entry(origin)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone();
        lock.lock_owned().await
    }

    pub(super) fn authoritative_epoch(&self, origin: NodeIdentifier) -> Option<u64> {
        if origin == self.self_id {
            Some(self.self_epoch)
        } else {
            self.net.member_boot_epoch(origin)
        }
    }

    pub(super) fn epoch_is_current(&self, origin: NodeIdentifier, epoch: u64) -> bool {
        origin == self.self_id
            || (self.net.alive_members().contains(&origin)
                && self.authoritative_epoch(origin) == Some(epoch))
    }

    pub(super) fn origin_is_inactive(&self, origin: NodeIdentifier) -> bool {
        self.state.lock().inactive_origins.contains(&origin)
    }

    pub(super) fn mark_origin_active(&self, origin: NodeIdentifier) {
        self.state.lock().inactive_origins.remove(&origin);
    }

    /// Repair repository state when membership changes while a serialized
    /// reset/remove/snapshot operation is awaiting repository work.
    pub(super) async fn restore_current_epoch_after_race_locked(&self, origin: NodeIdentifier) {
        loop {
            if self.net.alive_members().contains(&origin) {
                let Some(current_epoch) = self.authoritative_epoch(origin) else {
                    self.repo.remove_origin(origin).await;
                    if self.authoritative_epoch(origin).is_some() {
                        continue;
                    }
                    let mut state = self.state.lock();
                    state.pending_buffers.remove(&origin);
                    state.catchup_in_flight.remove(&origin);
                    state.catchup_attempts.remove(&origin);
                    state.empty_confirmations.remove(&origin);
                    state.inactive_origins.insert(origin);
                    return;
                };
                let previous = self.state.lock().known.get(&origin).copied();
                self.repo.reset_origin(origin, current_epoch).await;
                if !self.epoch_is_current(origin, current_epoch) {
                    continue;
                }
                {
                    let mut state = self.state.lock();
                    state.wipe_origin(origin);
                    if previous.is_some_and(|(known_epoch, _)| known_epoch == current_epoch) {
                        // Same-incarnation rejoin: retain the monotonic floor,
                        // but require an atomic cold snapshot to rematerialize.
                        state.inactive_origins.insert(origin);
                    } else {
                        state.known.insert(origin, (current_epoch, 0));
                        state.inactive_origins.remove(&origin);
                    }
                }
                self.rearm_catchup_retry(origin, current_epoch);
                return;
            }

            self.repo.remove_origin(origin).await;
            if self.net.alive_members().contains(&origin) {
                continue;
            }
            let mut state = self.state.lock();
            state.pending_buffers.remove(&origin);
            state.catchup_in_flight.remove(&origin);
            state.catchup_attempts.remove(&origin);
            state.empty_confirmations.remove(&origin);
            state.inactive_origins.insert(origin);
            return;
        }
    }

    pub(super) fn complete_catchup_attempt(&self, origin: NodeIdentifier) -> Option<u64> {
        self.state
            .lock()
            .catchup_attempts
            .remove(&origin)
            .map(|attempt| attempt.chunk_token)
    }

    pub(super) fn record_empty_origin_confirmation(
        &self,
        origin: NodeIdentifier,
        epoch: u64,
    ) -> u8 {
        self.state.lock().record_empty_confirmation(origin, epoch)
    }

    pub(super) fn clear_empty_origin_confirmation(&self, origin: NodeIdentifier) {
        self.state.lock().empty_confirmations.remove(&origin);
    }

    fn track_catchup_attempt(
        &self,
        origin: NodeIdentifier,
        epoch: u64,
        since_version: u64,
        chunk_token: u64,
        dst: NodeIdentifier,
    ) {
        let generation = {
            let mut state = self.state.lock();
            state.catchup_in_flight.insert(origin, Instant::now());
            let gap_target_version = state
                .pending_buffers
                .get(&origin)
                .and_then(|pending| pending.keys().next_back().copied());
            state.record_catchup_attempt(
                origin,
                epoch,
                since_version,
                gap_target_version,
                chunk_token,
                dst,
            )
        };
        let timeout = self.cfg.owner_catchup_timeout();
        let weak = self.weak_self.lock().clone();
        if let Some(weak) = weak {
            tokio::spawn(async move {
                let Some(runtime) = weak.upgrade() else {
                    return;
                };
                tokio::select! {
                    _ = runtime.shutdown.cancelled() => return,
                    _ = sleep(timeout) => {}
                }
                runtime.retry_timed_out_catchup(origin, generation).await;
            });
        }
    }

    async fn retry_timed_out_catchup(&self, origin: NodeIdentifier, generation: u64) {
        let attempt = {
            let mut state = self.state.lock();
            let Some(attempt) = state.catchup_attempts.get(&origin).copied() else {
                return;
            };
            if attempt.generation != generation {
                return;
            }
            if state.cancel_satisfied_catchup_attempt(origin, attempt.epoch) {
                return;
            }
            state.catchup_attempts.remove(&origin);
            attempt
        };
        if !self.epoch_is_current(origin, attempt.epoch) {
            return;
        }

        let alive = self.net.alive_members();
        let mut relays: Vec<_> = alive
            .iter()
            .copied()
            .filter(|node| *node != self.self_id && *node != origin && *node != attempt.dst)
            .collect();
        {
            use rand::seq::SliceRandom;
            let mut rng = rand::rng();
            relays.shuffle(&mut rng);
        }
        let mut destinations = Vec::new();
        if attempt.dst == origin {
            destinations.extend(relays);
            if alive.contains(&origin) {
                destinations.push(origin);
            }
        } else {
            if alive.contains(&origin) {
                destinations.push(origin);
            }
            destinations.extend(relays);
        }
        for dst in destinations {
            if self
                .send_catchup_req_to(
                    dst,
                    origin,
                    attempt.epoch,
                    attempt.since_version,
                    attempt.chunk_token,
                    "retry_timeout",
                )
                .await
                .is_ok()
            {
                return;
            }
        }
        self.rearm_catchup_retry(origin, attempt.epoch);
    }

    async fn bootstrap_catchup_alive_members(&self) {
        let retry_delay = owner_bootstrap_retry_delay(self.cfg.owner_catchup_timeout());
        let stabilization_window = owner_stabilization_window(self.cfg.owner_catchup_timeout());
        let mut stable_since: Option<(Vec<(NodeIdentifier, u64)>, Instant)> = None;
        loop {
            let signature = self.alive_origin_epoch_signature();
            if signature
                .as_ref()
                .is_some_and(|signature| signature.is_empty())
            {
                return;
            }
            if self.alive_origins_known_at_current_epochs() {
                if let Some(signature) = signature.clone() {
                    match &mut stable_since {
                        Some((stable_signature, since)) if *stable_signature == signature => {
                            if since.elapsed() >= stabilization_window {
                                return;
                            }
                        }
                        slot => *slot = Some((signature, Instant::now())),
                    }
                }
            } else {
                stable_since = None;
            }
            self.catchup_alive_members().await;
            tokio::select! {
                _ = self.shutdown.cancelled() => return,
                _ = sleep(retry_delay) => {}
            }
        }
    }

    fn alive_origin_epoch_signature(&self) -> Option<Vec<(NodeIdentifier, u64)>> {
        let mut signature = Vec::new();
        for origin in self
            .net
            .alive_members()
            .into_iter()
            .filter(|origin| *origin != self.self_id)
        {
            signature.push((origin, self.authoritative_epoch(origin)?));
        }
        signature.sort_unstable();
        Some(signature)
    }

    pub(super) fn schedule_origin_stabilization(&self, origin: NodeIdentifier, epoch: u64) {
        let retry_delay = owner_bootstrap_retry_delay(self.cfg.owner_catchup_timeout());
        let deadline =
            Instant::now() + owner_stabilization_window(self.cfg.owner_catchup_timeout());
        let weak = self.weak_self.lock().clone();
        if let Some(weak) = weak {
            tokio::spawn(async move {
                let Some(runtime) = weak.upgrade() else {
                    return;
                };
                loop {
                    tokio::select! {
                        _ = runtime.shutdown.cancelled() => return,
                        _ = sleep(retry_delay) => {}
                    }
                    if Instant::now() >= deadline || !runtime.epoch_is_current(origin, epoch) {
                        return;
                    }
                    let since = runtime.origin_is_inactive(origin).then_some(0);
                    runtime
                        .request_catchup(origin, epoch, since, "stabilization")
                        .await;
                }
            });
        }
    }

    fn alive_origins_known_at_current_epochs(&self) -> bool {
        let members = self.net.alive_members();
        let state = self.state.lock();
        members
            .into_iter()
            .filter(|origin| *origin != self.self_id)
            .all(|origin| {
                let Some(current_epoch) = self.authoritative_epoch(origin) else {
                    return false;
                };
                state
                    .known
                    .get(&origin)
                    .is_some_and(|(known_epoch, known_version)| {
                        *known_epoch == current_epoch
                            && (*known_version > 0
                                || state.empty_is_confirmed(origin, current_epoch))
                    })
                    && !state.inactive_origins.contains(&origin)
            })
    }

    async fn catchup_alive_members(&self) {
        let members = self.net.alive_members();
        for origin in members {
            if origin == self.self_id {
                continue;
            }
            let known_epoch = self.known_epoch_for_origin(origin);
            let since = self.origin_is_inactive(origin).then_some(0);
            self.request_catchup(origin, known_epoch, since, "bootstrap")
                .await;
        }
    }

    fn known_epoch_for_origin(&self, origin: NodeIdentifier) -> u64 {
        self.net
            .member_boot_epoch(origin)
            .or_else(|| {
                self.state
                    .lock()
                    .known
                    .get(&origin)
                    .map(|(epoch, _)| *epoch)
            })
            .unwrap_or(0)
    }

    async fn request_catchup(
        &self,
        origin: NodeIdentifier,
        known_epoch: u64,
        since_version: Option<u64>,
        cause: &'static str,
    ) -> bool {
        if origin == self.self_id {
            return true;
        }
        let should_send = {
            let mut state = self.state.lock();
            state.arm_catchup(origin, Instant::now(), self.cfg.owner_catchup_timeout())
        };
        if should_send {
            let sent = self
                .send_catchup_req_since(origin, known_epoch, since_version, cause)
                .await;
            if !sent {
                self.state.lock().catchup_in_flight.remove(&origin);
                debug!(
                    origin=%origin,
                    epoch=known_epoch,
                    since=?since_version,
                    cause,
                    "owner catchup request could not reach any destination"
                );
            }
            sent
        } else {
            debug!(
                origin=%origin,
                epoch=known_epoch,
                since=?since_version,
                cause,
                "owner catchup request suppressed by throttle"
            );
            true
        }
    }

    fn clear_origin_tracking(&self, origin: NodeIdentifier) {
        let mut state = self.state.lock();
        state.known.remove(&origin);
        state.pending_buffers.remove(&origin);
        state.catchup_in_flight.remove(&origin);
        state.catchup_attempts.remove(&origin);
        state.empty_confirmations.remove(&origin);
    }

    async fn handle_origin_offline(&self, origin: NodeIdentifier, event_epoch: u64) {
        let _guard = self.lock_origin(origin).await;
        if self.net.alive_members().contains(&origin)
            || self
                .authoritative_epoch(origin)
                .is_some_and(|current_epoch| current_epoch != event_epoch)
            || self
                .state
                .lock()
                .known
                .get(&origin)
                .is_some_and(|(known_epoch, _)| *known_epoch > event_epoch)
        {
            return;
        }
        {
            let mut state = self.state.lock();
            state.pending_buffers.remove(&origin);
            state.catchup_in_flight.remove(&origin);
            state.catchup_attempts.remove(&origin);
            state.empty_confirmations.remove(&origin);
            state.inactive_origins.insert(origin);
        }
        self.repo.remove_origin(origin).await;
        if self.net.alive_members().contains(&origin) {
            self.restore_current_epoch_after_race_locked(origin).await;
        }
    }

    async fn handle_origin_restarted(&self, origin: NodeIdentifier, new_epoch: u64) {
        let _guard = self.lock_origin(origin).await;
        if !self.epoch_is_current(origin, new_epoch) {
            return;
        }
        let known = self.state.lock().known.get(&origin).copied();
        if known.is_some_and(|(known_epoch, _)| known_epoch > new_epoch) {
            return;
        }
        let since = if let Some((known_epoch, known_version)) = known {
            if known_epoch == new_epoch {
                if self.origin_is_inactive(origin) {
                    0
                } else {
                    known_version
                }
            } else {
                self.clear_origin_tracking(origin);
                self.repo.reset_origin(origin, new_epoch).await;
                if !self.epoch_is_current(origin, new_epoch) {
                    self.restore_current_epoch_after_race_locked(origin).await;
                    return;
                }
                let mut state = self.state.lock();
                state.known.insert(origin, (new_epoch, 0));
                state.inactive_origins.remove(&origin);
                0
            }
        } else {
            self.clear_origin_tracking(origin);
            self.repo.reset_origin(origin, new_epoch).await;
            if !self.epoch_is_current(origin, new_epoch) {
                self.restore_current_epoch_after_race_locked(origin).await;
                return;
            }
            let mut state = self.state.lock();
            state.known.insert(origin, (new_epoch, 0));
            state.inactive_origins.remove(&origin);
            0
        };
        if !self.epoch_is_current(origin, new_epoch) {
            return;
        }
        self.request_catchup(origin, new_epoch, Some(since), "restart")
            .await;
        self.schedule_origin_stabilization(origin, new_epoch);
    }

    async fn handle_origin_joined(&self, origin: NodeIdentifier) {
        let _guard = self.lock_origin(origin).await;
        let known_epoch = self.known_epoch_for_origin(origin);
        let since = self.origin_is_inactive(origin).then_some(0);
        self.request_catchup(origin, known_epoch, since, "join")
            .await;
        self.schedule_origin_stabilization(origin, known_epoch);
    }

    /// Local-side propose. Broadcasts first, then applies locally — see
    /// the trait doc for why.
    pub async fn propose_local(self: Arc<Self>, op: R::Op) -> Result<u64, ReplicationError> {
        let encode_started_at = Instant::now();
        let encoded = rmp_serde::to_vec(&op);
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Owner,
            ReplicationPipelineStage::MsgpackEncode,
            encode_started_at.elapsed(),
        );
        let op_msgpack = Bytes::from(encoded?);
        let version = match self.repo.local_version_hint(&op) {
            Some(version) => {
                let mut current = self.local_counter.load(Ordering::Relaxed);
                while current < version {
                    match self.local_counter.compare_exchange_weak(
                        current,
                        version,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(next) => current = next,
                    }
                }
                version
            }
            None => self.local_counter.fetch_add(1, Ordering::Relaxed) + 1,
        };

        let body = OwnerBody::Op(OwnerOp {
            origin_node: self.self_id as u32,
            origin_epoch: self.self_epoch,
            origin_version: version,
            op_msgpack: op_msgpack.clone(),
        });
        if let Err(e) = self.net.send_broadcast(&self.topic, body).await {
            // Broadcast failed; we still advance local state so a retry from
            // the caller doesn't reuse the version.
            trace!(error=%e, "owner broadcast failed");
        }
        // Now apply locally. This anchors the chosen ordering: the network
        // commit precedes the local apply.
        if !self.repo.local_op_already_applied(&op) {
            let apply_started_at = Instant::now();
            self.repo
                .apply_remote(self.self_id, self.self_epoch, version, op)
                .await;
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Owner,
                ReplicationPipelineStage::RepoApply,
                apply_started_at.elapsed(),
            );
        }
        let mut s = self.state.lock();
        s.record_applied(self.self_id, self.self_epoch, version);
        Ok(version)
    }

    pub async fn recv_op(&self, from: NodeIdentifier, op: OwnerOp) {
        let Some(origin) = node_from_u32(op.origin_node) else {
            warn!(node = op.origin_node, "owner op has invalid origin_node");
            return;
        };
        // Owner-mode rule: only the named origin may originate ops.
        if origin == self.self_id {
            // Loopback (from == self) is silent — that's just our own
            // broadcast coming back via the overlay. A non-self sender
            // means a peer is forging an OwnerOp claiming our origin slot;
            // drop it loudly so the operator can spot misbehaviour.
            if from != self.self_id {
                warn!(
                    from = %from, topic = %self.topic,
                    "owner op claims local origin from foreign sender; dropping"
                );
            }
            return;
        }
        if from != origin {
            warn!(from=%from, origin=%origin, "owner op sender does not match origin; dropping");
            return;
        }
        self.process_remote_op(origin, op).await;
    }

    pub(super) async fn process_remote_op(&self, origin: NodeIdentifier, op: OwnerOp) {
        let _guard = self.lock_origin(origin).await;
        self.process_remote_op_locked(origin, op).await;
    }

    pub(super) async fn process_remote_op_locked(&self, origin: NodeIdentifier, op: OwnerOp) {
        if !self.epoch_is_current(origin, op.origin_epoch) {
            trace!(
                origin=%origin,
                op_epoch=op.origin_epoch,
                current_epoch=?self.authoritative_epoch(origin),
                "owner op is not fenced by the current LSDB epoch; dropping"
            );
            return;
        }
        if self.origin_is_inactive(origin) {
            if op.origin_version == 0 {
                return;
            }
            let should_request = {
                let mut state = self.state.lock();
                let was_empty =
                    state.buffer_op(origin, op.origin_version, Bytes::from(op.op_msgpack));
                if was_empty {
                    state.arm_gap_catchup(origin, Instant::now());
                }
                was_empty
            };
            if should_request {
                self.send_catchup_req_since(origin, op.origin_epoch, Some(0), "gap_catchup")
                    .await;
            }
            return;
        }
        // Classify and act.
        let classification = {
            let s = self.state.lock();
            s.classify_op(origin, &op)
        };

        match classification {
            Classification::Drop(reason) => {
                trace!(origin=%origin, reason=reason, "owner op dropped");
            }
            Classification::Reset { new_epoch } => {
                self.repo.reset_origin(origin, new_epoch).await;
                if !self.epoch_is_current(origin, new_epoch) {
                    self.restore_current_epoch_after_race_locked(origin).await;
                    return;
                }
                {
                    let mut s = self.state.lock();
                    s.wipe_origin(origin);
                    s.known.insert(origin, (new_epoch, 0));
                }
                // Now re-classify the same op against the fresh state.
                let again = {
                    let s = self.state.lock();
                    s.classify_op(origin, &op)
                };
                match again {
                    Classification::Apply => self.apply_op(origin, op).await,
                    Classification::Buffer => {
                        let arm = {
                            let mut s = self.state.lock();
                            let was_empty =
                                s.buffer_op(origin, op.origin_version, Bytes::from(op.op_msgpack));
                            if was_empty {
                                s.arm_gap_catchup(origin, Instant::now());
                            }
                            was_empty
                        };
                        if arm {
                            self.send_catchup_req(origin, new_epoch, "gap_catchup")
                                .await;
                        }
                    }
                    other => {
                        warn!(
                            ?other,
                            "unexpected re-classification after epoch reset; dropping"
                        );
                    }
                }
            }
            Classification::Buffer => {
                let (arm, known_epoch) = {
                    let mut s = self.state.lock();
                    let known_epoch = s
                        .known
                        .get(&origin)
                        .copied()
                        .map(|(e, _)| e)
                        .unwrap_or(op.origin_epoch);
                    let was_empty =
                        s.buffer_op(origin, op.origin_version, Bytes::from(op.op_msgpack));
                    if was_empty {
                        s.arm_gap_catchup(origin, Instant::now());
                    }
                    let arm = was_empty;
                    (arm, known_epoch)
                };
                if arm {
                    self.send_catchup_req(origin, known_epoch, "gap_catchup")
                        .await;
                }
            }
            Classification::Apply => self.apply_op(origin, op).await,
        }
    }

    async fn apply_op(&self, origin: NodeIdentifier, op: OwnerOp) {
        let op_msgpack = op.op_msgpack;
        let epoch = op.origin_epoch;
        let version = op.origin_version;
        let decode_started_at = Instant::now();
        let typed: R::Op = match rmp_serde::from_slice(&op_msgpack) {
            Ok(o) => o,
            Err(e) => {
                metrics::record_pipeline_stage(
                    ReplicationPipelineKind::Owner,
                    ReplicationPipelineStage::MsgpackDecode,
                    decode_started_at.elapsed(),
                );
                warn!(error=%e, "owner op msgpack decode failed");
                return;
            }
        };
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Owner,
            ReplicationPipelineStage::MsgpackDecode,
            decode_started_at.elapsed(),
        );
        let apply_started_at = Instant::now();
        self.repo.apply_remote(origin, epoch, version, typed).await;
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Owner,
            ReplicationPipelineStage::RepoApply,
            apply_started_at.elapsed(),
        );
        if !self.epoch_is_current(origin, epoch) {
            self.restore_current_epoch_after_race_locked(origin).await;
            return;
        }
        let drained = {
            let mut s = self.state.lock();
            s.record_applied(origin, epoch, version);
            s.drain_contiguous(origin, version)
        };
        // Drain contiguous buffered ops, applying each in turn.
        let mut prev_v = version;
        for (v, bytes) in drained {
            let decode_started_at = Instant::now();
            let typed: R::Op = match rmp_serde::from_slice(&bytes) {
                Ok(o) => o,
                Err(e) => {
                    metrics::record_pipeline_stage(
                        ReplicationPipelineKind::Owner,
                        ReplicationPipelineStage::MsgpackDecode,
                        decode_started_at.elapsed(),
                    );
                    warn!(error=%e, "buffered owner op decode failed");
                    return;
                }
            };
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Owner,
                ReplicationPipelineStage::MsgpackDecode,
                decode_started_at.elapsed(),
            );
            let apply_started_at = Instant::now();
            self.repo.apply_remote(origin, epoch, v, typed).await;
            metrics::record_pipeline_stage(
                ReplicationPipelineKind::Owner,
                ReplicationPipelineStage::RepoApply,
                apply_started_at.elapsed(),
            );
            if !self.epoch_is_current(origin, epoch) {
                self.restore_current_epoch_after_race_locked(origin).await;
                return;
            }
            let mut s = self.state.lock();
            s.record_applied(origin, epoch, v);
            prev_v = v;
        }
        self.state
            .lock()
            .cancel_satisfied_catchup_attempt(origin, epoch);
        let _ = prev_v;
    }

    pub(super) async fn drain_pending_after_snapshot_locked(
        &self,
        origin: NodeIdentifier,
        epoch: u64,
    ) {
        loop {
            let (version, bytes) = {
                let mut state = self.state.lock();
                let Some((known_epoch, known_version)) = state.known.get(&origin).copied() else {
                    return;
                };
                if known_epoch != epoch {
                    return;
                }
                let Some(bytes) = state.take_next_buffered(origin, known_version) else {
                    return;
                };
                (known_version + 1, bytes)
            };
            self.apply_op(
                origin,
                OwnerOp {
                    origin_node: origin as u32,
                    origin_epoch: epoch,
                    origin_version: version,
                    op_msgpack: bytes,
                },
            )
            .await;
        }
    }

    /// Keep the catchup throttle armed and arrange a bounded retry instead of
    /// waiting for the much slower periodic anti-entropy interval.
    pub(super) fn rearm_catchup_retry(&self, origin: NodeIdentifier, epoch: u64) {
        self.state
            .lock()
            .catchup_in_flight
            .insert(origin, Instant::now());
        let timeout = self.cfg.owner_catchup_timeout();
        let weak = self.weak_self.lock().clone();
        if let Some(weak) = weak {
            tokio::spawn(async move {
                let Some(runtime) = weak.upgrade() else {
                    return;
                };
                tokio::select! {
                    _ = runtime.shutdown.cancelled() => return,
                    _ = sleep(timeout) => {}
                }
                if runtime.epoch_is_current(origin, epoch) {
                    let since = runtime.origin_is_inactive(origin).then_some(0);
                    runtime.request_catchup(origin, epoch, since, "rearm").await;
                }
            });
        }
    }

    async fn send_catchup_req(
        &self,
        origin: NodeIdentifier,
        known_epoch: u64,
        cause: &'static str,
    ) -> bool {
        self.send_catchup_req_since(origin, known_epoch, None, cause)
            .await
    }

    async fn send_catchup_req_since(
        &self,
        origin: NodeIdentifier,
        known_epoch: u64,
        since_version: Option<u64>,
        cause: &'static str,
    ) -> bool {
        let alive = self.net.alive_members();
        let since = since_version.unwrap_or_else(|| {
            let s = self.state.lock();
            s.known.get(&origin).map(|(_, v)| *v).unwrap_or(0)
        });

        // A cold catchup must consult the owner first. Only the owner can
        // authoritatively establish a new incarnation at version zero.
        // Incremental repairs may use fully-materialized relay state first.
        let mut candidates: Vec<NodeIdentifier> = alive
            .iter()
            .filter(|n| **n != self.self_id && **n != origin)
            .copied()
            .collect();
        {
            use rand::seq::SliceRandom;
            let mut rng = rand::rng();
            candidates.shuffle(&mut rng);
        }

        let origin_alive = alive.contains(&origin);
        let mut destinations = Vec::with_capacity(candidates.len() + usize::from(origin_alive));
        if since == 0 && origin_alive {
            destinations.push(origin);
            destinations.extend(candidates);
        } else {
            destinations.extend(candidates);
            if origin_alive {
                destinations.push(origin);
            }
        }
        for dst in destinations {
            if self
                .send_catchup_req_to(dst, origin, known_epoch, since, 0, cause)
                .await
                .is_ok()
            {
                return true;
            }
        }
        false
    }

    pub(super) async fn send_catchup_req_to(
        &self,
        dst: NodeIdentifier,
        origin: NodeIdentifier,
        known_epoch: u64,
        since_version: u64,
        chunk_token: u64,
        cause: &'static str,
    ) -> Result<(), ReplicationError> {
        let req = OwnerCatchupReq {
            origin_node: origin as u32,
            src_node: self.self_id as u32,
            known_epoch,
            since_version,
            chunk_token,
        };
        metrics::record_catchup_request(CatchupMode::Owner);
        self.net
            .send_unicast(dst, &self.topic, OwnerBody::CatchupReq(req))
            .await?;
        self.track_catchup_attempt(origin, known_epoch, since_version, chunk_token, dst);
        debug!(
            origin=%origin,
            dst=%dst,
            epoch=known_epoch,
            since=since_version,
            chunk_token=chunk_token,
            cause,
            "owner catchup request sent"
        );
        Ok(())
    }

    /// Send a multi-response continuation without losing its cursor when the
    /// preferred destination rejects the send immediately. A successful send
    /// installs the normal generation watchdog; if every live destination
    /// fails, re-arm the bounded retry path instead of waiting for periodic
    /// anti-entropy.
    pub(super) async fn send_catchup_continuation_with_fallback(
        &self,
        preferred_dst: NodeIdentifier,
        origin: NodeIdentifier,
        known_epoch: u64,
        since_version: u64,
        chunk_token: u64,
    ) {
        if self
            .send_catchup_req_to(
                preferred_dst,
                origin,
                known_epoch,
                since_version,
                chunk_token,
                "continuation",
            )
            .await
            .is_ok()
        {
            return;
        }

        let alive = self.net.alive_members();
        let mut relays: Vec<_> = alive
            .iter()
            .copied()
            .filter(|node| *node != self.self_id && *node != origin && *node != preferred_dst)
            .collect();
        {
            use rand::seq::SliceRandom;
            let mut rng = rand::rng();
            relays.shuffle(&mut rng);
        }
        let mut alternatives = Vec::with_capacity(relays.len() + 1);
        if preferred_dst != origin && alive.contains(&origin) {
            alternatives.push(origin);
        }
        alternatives.extend(relays);

        for dst in alternatives {
            if self
                .send_catchup_req_to(
                    dst,
                    origin,
                    known_epoch,
                    since_version,
                    chunk_token,
                    "continuation",
                )
                .await
                .is_ok()
            {
                return;
            }
        }
        self.rearm_catchup_retry(origin, known_epoch);
    }

    pub async fn recv_catchup_req(&self, from: NodeIdentifier, req: OwnerCatchupReq) {
        super::catchup::respond_to_request(self, from, req).await
    }

    pub async fn recv_catchup_resp(
        &self,
        from: NodeIdentifier,
        resp: super::super::proto::OwnerCatchupResp,
    ) {
        super::catchup::apply_response(self, from, resp).await
    }

    /// Handle a membership event. Offline removes transient owner state;
    /// restart is treated as offline-online and catches up from version 0;
    /// join proactively catches up pre-existing state.
    pub fn on_membership_event(&self, ev: &MembershipEvent) {
        match ev {
            MembershipEvent::Restarted(node) => {
                let weak = self.weak_self.lock().clone();
                let (node, epoch) = (node.node_id(), node.incarnation());
                if let Some(weak) = weak {
                    tokio::spawn(async move {
                        if let Some(runtime) = weak.upgrade() {
                            runtime.handle_origin_restarted(node, epoch).await;
                        }
                    });
                }
            }
            MembershipEvent::Failed(node) | MembershipEvent::Left(node) => {
                let weak = self.weak_self.lock().clone();
                let (node, epoch) = (node.node_id(), node.incarnation());
                if let Some(weak) = weak {
                    tokio::spawn(async move {
                        if let Some(runtime) = weak.upgrade() {
                            runtime.handle_origin_offline(node, epoch).await;
                        }
                    });
                }
            }
            MembershipEvent::Joined(node) => {
                let weak = self.weak_self.lock().clone();
                let node = node.node_id();
                if let Some(weak) = weak {
                    tokio::spawn(async move {
                        if let Some(runtime) = weak.upgrade() {
                            runtime.handle_origin_joined(node).await;
                        }
                    });
                }
            }
        }
    }
}

#[async_trait]
impl<R: OwnerReplicable> ErasedOwnerRuntime for OwnerRuntime<R> {
    async fn dispatch(&self, from: NodeIdentifier, body: OwnerBody) {
        match body {
            OwnerBody::Op(op) => self.recv_op(from, op).await,
            OwnerBody::CatchupReq(req) => self.recv_catchup_req(from, req).await,
            OwnerBody::CatchupResp(resp) => self.recv_catchup_resp(from, resp).await,
        }
    }

    fn on_membership(&self, ev: &MembershipEvent) {
        self.on_membership_event(ev);
    }

    fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

fn owner_bootstrap_retry_delay(catchup_timeout: Duration) -> Duration {
    catchup_timeout
        .checked_div(10)
        .unwrap_or(Duration::from_millis(100))
        .clamp(Duration::from_millis(50), Duration::from_millis(500))
}

fn owner_stabilization_window(catchup_timeout: Duration) -> Duration {
    catchup_timeout
        .checked_mul(4)
        .unwrap_or(Duration::from_secs(20))
        .min(Duration::from_secs(20))
}

#[inline]
fn node_from_u32(v: u32) -> Option<NodeIdentifier> {
    if v <= u16::MAX as u32 {
        Some(v as NodeIdentifier)
    } else {
        None
    }
}

// ---------- Unit tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replications::proto::OwnerCatchupResp;
    use crate::replications::test_support::{CapturedFrame, CountingOwnerRepo, MockNet};
    use std::sync::atomic::AtomicBool;

    fn op(origin: u16, epoch: u64, ver: u64) -> OwnerOp {
        OwnerOp {
            origin_node: origin as u32,
            origin_epoch: epoch,
            origin_version: ver,
            op_msgpack: Bytes::new(),
        }
    }

    #[test]
    fn classify_first_sight_v1_applies() {
        let s = OwnerState::new();
        assert_eq!(s.classify_op(7, &op(7, 100, 1)), Classification::Apply);
    }

    #[test]
    fn every_production_owner_enqueue_uses_end_to_end_ack_lane() {
        const SOURCE: &str = include_str!("runtime.rs");
        let production = SOURCE
            .split("// ---------- Unit tests ----------")
            .next()
            .expect("owner runtime production section");
        let lane_enqueues = production
            .matches(".send_unicast_on_lane_with_options(")
            .count()
            + production.matches(".send_multicast_on_lane(").count();

        assert_eq!(lane_enqueues, 4, "unexpected owner overlay enqueue added");
        assert_eq!(
            production.matches("OWNER_REPLICATION_LANE").count(),
            lane_enqueues + 1,
            "every owner overlay enqueue must use its ACK-retained lane"
        );
        assert!(!production.contains(".send_unicast_with_options("));
        assert!(!production.contains(".send_multicast("));
    }

    #[test]
    fn classify_first_sight_gap_buffers() {
        let s = OwnerState::new();
        assert_eq!(s.classify_op(7, &op(7, 100, 5)), Classification::Buffer);
    }

    #[test]
    fn classify_in_order_applies() {
        let mut s = OwnerState::new();
        s.record_applied(7, 100, 4);
        assert_eq!(s.classify_op(7, &op(7, 100, 5)), Classification::Apply);
    }

    #[test]
    fn classify_gap_buffers() {
        let mut s = OwnerState::new();
        s.record_applied(7, 100, 4);
        assert_eq!(s.classify_op(7, &op(7, 100, 7)), Classification::Buffer);
    }

    #[test]
    fn classify_higher_epoch_resets() {
        let mut s = OwnerState::new();
        s.record_applied(7, 100, 4);
        assert_eq!(
            s.classify_op(7, &op(7, 200, 1)),
            Classification::Reset { new_epoch: 200 }
        );
    }

    #[test]
    fn classify_lower_epoch_drops() {
        let mut s = OwnerState::new();
        s.record_applied(7, 200, 1);
        assert!(matches!(
            s.classify_op(7, &op(7, 100, 99)),
            Classification::Drop(_)
        ));
    }

    #[test]
    fn classify_duplicate_drops() {
        let mut s = OwnerState::new();
        s.record_applied(7, 100, 5);
        assert!(matches!(
            s.classify_op(7, &op(7, 100, 5)),
            Classification::Drop(_)
        ));
        assert!(matches!(
            s.classify_op(7, &op(7, 100, 4)),
            Classification::Drop(_)
        ));
    }

    #[test]
    fn drain_contiguous_returns_consecutive_ops() {
        let mut s = OwnerState::new();
        s.buffer_op(7, 6, Bytes::from_static(b"a"));
        s.buffer_op(7, 7, Bytes::from_static(b"b"));
        s.buffer_op(7, 9, Bytes::from_static(b"c"));
        let drained = s.drain_contiguous(7, 5);
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].0, 6);
        assert_eq!(drained[1].0, 7);
        // 9 stays buffered (gap at 8).
        let buf = s.pending_buffers.get(&7).unwrap();
        assert!(buf.contains_key(&9));
    }

    #[test]
    fn arm_catchup_suppresses_within_timeout() {
        let timeout = ReplicationConfig::default().owner_catchup_timeout();
        let mut s = OwnerState::new();
        let t0 = Instant::now();
        assert!(s.arm_catchup(7, t0, timeout));
        assert!(!s.arm_catchup(7, t0, timeout));
        // Way later — re-arm.
        assert!(s.arm_catchup(7, t0 + timeout + Duration::from_secs(1), timeout));
    }

    #[test]
    fn new_gap_bypasses_existing_catchup_throttle() {
        let timeout = ReplicationConfig::default().owner_catchup_timeout();
        let mut s = OwnerState::new();
        let bootstrap = Instant::now();
        assert!(s.arm_catchup(7, bootstrap, timeout));

        let gap = bootstrap + Duration::from_millis(1);
        s.arm_gap_catchup(7, gap);

        assert_eq!(s.catchup_in_flight.get(&7), Some(&gap));
        assert!(!s.arm_catchup(7, gap, timeout));
    }

    #[test]
    fn wipe_origin_clears_pending_and_catchup_state() {
        let timeout = ReplicationConfig::default().owner_catchup_timeout();
        let mut s = OwnerState::new();
        s.buffer_op(7, 6, Bytes::from_static(b"a"));
        s.arm_catchup(7, Instant::now(), timeout);
        s.wipe_origin(7);
        assert!(s.pending_buffers.get(&7).is_none());
        assert!(s.catchup_in_flight.get(&7).is_none());
    }

    #[test]
    fn broadcast_progress_cancels_watchdog_only_after_gap_is_filled() {
        let mut state = OwnerState::new();
        state.known.insert(7, (100, 4));
        let request_time = Instant::now();
        state.catchup_in_flight.insert(7, request_time);
        state.record_catchup_attempt(7, 100, 4, Some(6), 0, 7);
        state.buffer_op(7, 6, Bytes::new());
        state.record_applied(7, 100, 5);

        assert!(!state.cancel_satisfied_catchup_attempt(7, 100));
        assert!(state.catchup_attempts.contains_key(&7));

        state.record_applied(7, 100, 6);
        assert!(state.cancel_satisfied_catchup_attempt(7, 100));
        assert!(!state.catchup_attempts.contains_key(&7));
        assert_eq!(state.catchup_in_flight.get(&7), Some(&request_time));
    }

    #[test]
    fn broadcast_progress_does_not_cancel_non_gap_catchup() {
        let mut state = OwnerState::new();
        state.known.insert(7, (100, 4));
        state.record_catchup_attempt(7, 100, 4, None, 0, 7);
        state.record_applied(7, 100, 5);

        assert!(!state.cancel_satisfied_catchup_attempt(7, 100));
        assert!(state.catchup_attempts.contains_key(&7));
    }

    #[tokio::test(start_paused = true)]
    async fn owner_runtime_does_not_emit_periodic_background_catchup() {
        let net = MockNet::new(1, vec![1]);
        let shutdown = CancellationToken::new();
        let runtime = OwnerRuntime::new(
            CountingOwnerRepo::new(),
            1,
            100,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            shutdown.clone(),
            Arc::new(
                ReplicationConfig::default()
                    .with_owner_anti_entropy_interval(Duration::from_millis(100)),
            ),
        );
        runtime.start();
        tokio::task::yield_now().await;

        net.set_epoch(2, 200);
        net.set_alive(vec![1, 2]);
        tokio::time::advance(Duration::from_millis(500)).await;
        tokio::task::yield_now().await;
        assert!(
            net.captured.lock().is_empty(),
            "steady state must be driven by broadcasts rather than background catchup"
        );
        shutdown.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn broadcasts_that_fill_gap_prevent_catchup_retry() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(2, 200);
        let runtime = OwnerRuntime::new(
            CountingOwnerRepo::new(),
            1,
            100,
            "clients".into(),
            net.clone() as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            Arc::new(
                ReplicationConfig::default().with_owner_catchup_timeout(Duration::from_millis(30)),
            ),
        );
        runtime
            .recv_op(
                2,
                OwnerOp {
                    origin_node: 2,
                    origin_epoch: 200,
                    origin_version: 2,
                    op_msgpack: Bytes::from(rmp_serde::to_vec(&43u64).unwrap()),
                },
            )
            .await;
        runtime
            .recv_op(
                2,
                OwnerOp {
                    origin_node: 2,
                    origin_epoch: 200,
                    origin_version: 1,
                    op_msgpack: Bytes::from(rmp_serde::to_vec(&42u64).unwrap()),
                },
            )
            .await;

        tokio::time::advance(Duration::from_millis(31)).await;
        tokio::task::yield_now().await;
        let requests = net
            .captured
            .lock()
            .iter()
            .filter(|frame| {
                matches!(
                    frame,
                    CapturedFrame::OwnerUnicast {
                        body: OwnerBody::CatchupReq(_),
                        ..
                    }
                )
            })
            .count();
        assert_eq!(requests, 1, "satisfied watchdog must not retry");
    }

    #[tokio::test]
    async fn origin_lock_serializes_same_origin_without_blocking_another() {
        let net = MockNet::new(1, vec![1, 2, 3]);
        let runtime = OwnerRuntime::new(
            CountingOwnerRepo::new(),
            1,
            100,
            "clients".into(),
            net as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            Arc::new(ReplicationConfig::default()),
        );
        let first = runtime.lock_origin(2).await;
        let acquired = Arc::new(AtomicBool::new(false));
        let task_runtime = runtime.clone();
        let task_acquired = acquired.clone();
        let waiter = tokio::spawn(async move {
            let _guard = task_runtime.lock_origin(2).await;
            task_acquired.store(true, Ordering::Relaxed);
        });

        tokio::task::yield_now().await;
        assert!(!acquired.load(Ordering::Relaxed));
        let other_origin = tokio::time::timeout(Duration::from_millis(50), runtime.lock_origin(3))
            .await
            .expect("different origins must not share a serializer");
        drop(other_origin);
        drop(first);
        waiter.await.unwrap();
        assert!(acquired.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn empty_origin_requires_bounded_second_confirmation() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(2, 200);
        let runtime = OwnerRuntime::new(
            CountingOwnerRepo::new(),
            1,
            100,
            "clients".into(),
            net as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            Arc::new(
                ReplicationConfig::default().with_owner_catchup_timeout(Duration::from_millis(30)),
            ),
        );
        let response = OwnerCatchupResp {
            origin_node: 2,
            origin_epoch: 200,
            snapshot_version: 0,
            snapshot_msgpack: Bytes::new(),
            ops: Vec::new(),
            has_more: false,
            next_chunk_token: 0,
            too_old_use_snapshot: false,
        };

        runtime.recv_catchup_resp(2, response.clone()).await;
        assert_eq!(runtime.state.lock().known.get(&2), Some(&(200, 0)));
        assert!(!runtime.alive_origins_known_at_current_epochs());

        runtime.recv_catchup_resp(2, response).await;
        assert!(runtime.alive_origins_known_at_current_epochs());
    }

    #[tokio::test]
    async fn serialized_empty_snapshot_requires_bounded_second_confirmation() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(2, 200);
        let runtime = OwnerRuntime::new(
            CountingOwnerRepo::new(),
            1,
            100,
            "clients".into(),
            net as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            Arc::new(
                ReplicationConfig::default().with_owner_catchup_timeout(Duration::from_millis(30)),
            ),
        );
        let response = OwnerCatchupResp {
            origin_node: 2,
            origin_epoch: 200,
            snapshot_version: 0,
            snapshot_msgpack: Bytes::from(rmp_serde::to_vec(&Vec::<(u64, u64)>::new()).unwrap()),
            ops: Vec::new(),
            has_more: false,
            next_chunk_token: 0,
            too_old_use_snapshot: true,
        };

        runtime.recv_catchup_resp(2, response.clone()).await;
        assert_eq!(runtime.state.lock().known.get(&2), Some(&(200, 0)));
        assert!(!runtime.alive_origins_known_at_current_epochs());

        runtime.recv_catchup_resp(2, response).await;
        assert!(runtime.alive_origins_known_at_current_epochs());
    }

    #[tokio::test]
    async fn operation_between_empty_confirmations_converges_immediately() {
        let net = MockNet::new(1, vec![1, 2]);
        net.set_epoch(2, 200);
        let repo = CountingOwnerRepo::new();
        let runtime = OwnerRuntime::new(
            repo.clone(),
            1,
            100,
            "clients".into(),
            net as Arc<dyn OwnerNet>,
            CancellationToken::new(),
            Arc::new(
                ReplicationConfig::default().with_owner_catchup_timeout(Duration::from_millis(30)),
            ),
        );
        runtime
            .recv_catchup_resp(
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

        runtime
            .recv_op(
                2,
                OwnerOp {
                    origin_node: 2,
                    origin_epoch: 200,
                    origin_version: 1,
                    op_msgpack: Bytes::from(rmp_serde::to_vec(&42u64).unwrap()),
                },
            )
            .await;

        assert_eq!(repo.applied_for(2), vec![(1, 42)]);
        assert!(runtime.alive_origins_known_at_current_epochs());
    }
}
