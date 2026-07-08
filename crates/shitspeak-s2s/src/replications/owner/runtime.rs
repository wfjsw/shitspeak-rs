//! Per-topic owner-mode runtime.
//!
//! State is keyed by origin node id. The owner reads its own
//! `boot_epoch` from the overlay once at start; remote epochs come from
//! `OwnerOp.origin_epoch` and from `MembershipEvent::Restarted`. The
//! runtime never mints epochs.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{trace, warn};

use super::super::config::ReplicationConfig;
use super::super::error::ReplicationError;
use super::super::metrics::{self, CatchupMode, ReplicationPipelineKind, ReplicationPipelineStage};
use super::super::proto::{
    self as repl_proto, OwnerBody, OwnerCatchupReq, OwnerOp, REPLICATION_SERVICE_TAG,
};
use super::super::topic::ErasedOwnerRuntime;
use super::OwnerReplicable;
use crate::overlay::{MembershipEvent, OverlayNetwork, OverlaySendOptions};
use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{MessageClass, ServiceLevel};

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
            .send_unicast_with_options(
                dst,
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
            .send_multicast(
                &dsts,
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
            .send_unicast_with_options(
                dst,
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
                    .send_unicast_with_options(
                        dst,
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
        self.overlay.owner_replication_members()
    }

    fn local_node_id(&self) -> NodeIdentifier {
        self.overlay.local_node_id()
    }

    fn member_boot_epoch(&self, node: NodeIdentifier) -> Option<u64> {
        self.overlay.member(node).map(|m| m.boot_epoch())
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
}

impl OwnerState {
    pub fn new() -> Self {
        Self {
            known: HashMap::new(),
            pending_buffers: HashMap::new(),
            catchup_in_flight: HashMap::new(),
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

    /// Wipe pending state for `origin` (used on epoch reset).
    pub fn wipe_origin(&mut self, origin: NodeIdentifier) {
        self.pending_buffers.remove(&origin);
        self.catchup_in_flight.remove(&origin);
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
        let arc = Arc::new(Self {
            repo,
            self_id,
            self_epoch,
            topic,
            net,
            state: Mutex::new(OwnerState::new()),
            local_counter: AtomicU64::new(initial),
            weak_self: Mutex::new(None),
            shutdown,
            cfg,
        });
        *arc.weak_self.lock() = Some(Arc::downgrade(&arc));
        arc
    }

    pub fn start(self: &Arc<Self>) {
        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            runtime.bootstrap_catchup_alive_members().await;
        });
        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(runtime.cfg.owner_anti_entropy_interval());
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = runtime.shutdown.cancelled() => return,
                    _ = ticker.tick() => {
                        runtime.catchup_alive_members().await;
                    }
                }
            }
        });
    }

    async fn bootstrap_catchup_alive_members(&self) {
        let deadline =
            Instant::now() + self.cfg.owner_catchup_timeout().max(Duration::from_secs(1));
        let retry_delay = owner_bootstrap_retry_delay(self.cfg.owner_catchup_timeout());
        loop {
            if self.catchup_alive_members().await || Instant::now() >= deadline {
                return;
            }
            sleep(retry_delay).await;
        }
    }

    async fn catchup_alive_members(&self) -> bool {
        let members = self.net.alive_members();
        let mut saw_remote = false;
        let mut requests_ready = true;
        for origin in members {
            if origin == self.self_id {
                continue;
            }
            saw_remote = true;
            let known_epoch = self.known_epoch_for_origin(origin);
            requests_ready &= self.request_catchup(origin, known_epoch, None).await;
        }
        saw_remote && requests_ready
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
                .send_catchup_req_since(origin, known_epoch, since_version)
                .await;
            if !sent {
                self.state.lock().catchup_in_flight.remove(&origin);
            }
            sent
        } else {
            true
        }
    }

    fn clear_origin_tracking(&self, origin: NodeIdentifier) {
        let mut state = self.state.lock();
        state.known.remove(&origin);
        state.pending_buffers.remove(&origin);
        state.catchup_in_flight.remove(&origin);
    }

    async fn handle_origin_offline(&self, origin: NodeIdentifier) {
        self.repo.remove_origin(origin).await;
    }

    async fn handle_origin_restarted(&self, origin: NodeIdentifier) {
        let new_epoch = self.known_epoch_for_origin(origin);
        self.repo.reset_origin(origin, new_epoch).await;
        self.request_catchup(origin, new_epoch, Some(0)).await;
    }

    async fn handle_origin_joined(&self, origin: NodeIdentifier) {
        let known_epoch = self.known_epoch_for_origin(origin);
        self.request_catchup(origin, known_epoch, None).await;
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
        self.process_remote_op(origin, op).await;
    }

    pub(super) async fn process_remote_op(&self, origin: NodeIdentifier, op: OwnerOp) {
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
                            was_empty
                                && s.arm_catchup(
                                    origin,
                                    Instant::now(),
                                    self.cfg.owner_catchup_timeout(),
                                )
                        };
                        if arm {
                            self.send_catchup_req(origin, new_epoch).await;
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
                    let arm = was_empty
                        && s.arm_catchup(origin, Instant::now(), self.cfg.owner_catchup_timeout());
                    (arm, known_epoch)
                };
                if arm {
                    self.send_catchup_req(origin, known_epoch).await;
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
            let mut s = self.state.lock();
            s.record_applied(origin, epoch, v);
            prev_v = v;
        }
        let _ = prev_v;
    }

    async fn send_catchup_req(&self, origin: NodeIdentifier, known_epoch: u64) -> bool {
        self.send_catchup_req_since(origin, known_epoch, None).await
    }

    async fn send_catchup_req_since(
        &self,
        origin: NodeIdentifier,
        known_epoch: u64,
        since_version: Option<u64>,
    ) -> bool {
        let alive = self.net.alive_members();
        let since = since_version.unwrap_or_else(|| {
            let s = self.state.lock();
            s.known.get(&origin).map(|(_, v)| *v).unwrap_or(0)
        });

        // Prefer a non-origin alive peer; fall back to origin.
        let mut candidates: Vec<NodeIdentifier> = alive
            .iter()
            .filter(|n| **n != self.self_id && **n != origin)
            .copied()
            .collect();
        let pick = if !candidates.is_empty() {
            use rand::seq::SliceRandom;
            let mut rng = rand::rng();
            candidates.shuffle(&mut rng);
            candidates[0]
        } else if alive.contains(&origin) {
            origin
        } else {
            // No one to ask.
            return false;
        };
        let first = self
            .send_catchup_req_to(pick, origin, known_epoch, since, 0)
            .await;
        if first.is_ok() {
            return true;
        }
        if pick != origin && alive.contains(&origin) {
            return self
                .send_catchup_req_to(origin, origin, known_epoch, since, 0)
                .await
                .is_ok();
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
            .await
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
                self.clear_origin_tracking(*node);
                let weak = self.weak_self.lock().clone();
                let node = *node;
                if let Some(weak) = weak {
                    tokio::spawn(async move {
                        if let Some(runtime) = weak.upgrade() {
                            runtime.handle_origin_restarted(node).await;
                        }
                    });
                }
            }
            MembershipEvent::Failed(node) | MembershipEvent::Left(node) => {
                self.clear_origin_tracking(*node);
                let weak = self.weak_self.lock().clone();
                let node = *node;
                if let Some(weak) = weak {
                    tokio::spawn(async move {
                        if let Some(runtime) = weak.upgrade() {
                            runtime.handle_origin_offline(node).await;
                        }
                    });
                }
            }
            MembershipEvent::Joined(node) => {
                let weak = self.weak_self.lock().clone();
                let node = *node;
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
    fn wipe_origin_clears_pending_and_catchup_state() {
        let timeout = ReplicationConfig::default().owner_catchup_timeout();
        let mut s = OwnerState::new();
        s.buffer_op(7, 6, Bytes::from_static(b"a"));
        s.arm_catchup(7, Instant::now(), timeout);
        s.wipe_origin(7);
        assert!(s.pending_buffers.get(&7).is_none());
        assert!(s.catchup_in_flight.get(&7).is_none());
    }
}
