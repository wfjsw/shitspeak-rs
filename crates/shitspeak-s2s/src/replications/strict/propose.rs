//! Local propose flow for strict (Tempo) replication.
//!
//! Called from [`StrictHandle::propose`]. Acquires a semaphore permit,
//! freezes the alive set as the proposal's target set, registers the
//! proposal in state, and emits `StrictPropose` to every peer in the
//! target set. Self-ack is fed through the regular `recv_propose_ack`
//! path so the quorum-reached side-effects are not duplicated.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use tokio::sync::oneshot;
use tokio::time::{Instant as TokioInstant, sleep, sleep_until};
use tracing::trace;

use super::super::error::ReplicationError;
use super::super::metrics::{self, ReplicationPipelineKind, ReplicationPipelineStage};
use super::super::proto::{StrictBody, StrictProposeAck, StrictProposeV1};
use super::super::protocol::STRICT_PROTOCOL_VERSION_V2;
use super::StrictReplicable;
use super::runtime::{
    Proposal, STRICT_REPLICATION_SLOW_STAGE, StrictProtocolSnapshot, StrictRuntime,
    frozen_targets_from_epochs,
};

impl<R: StrictReplicable> StrictRuntime<R> {
    /// Begin a local proposal. Stores a waker in the proposal that the
    /// delivery path will fire once `apply_committed` returns.
    pub async fn begin_propose(
        self: Arc<Self>,
        op: R::Op,
        waker: oneshot::Sender<Result<u64, ReplicationError>>,
    ) -> Result<(), ReplicationError> {
        self.begin_propose_with_accepted(op, None, waker).await
    }

    pub async fn begin_propose_with_accepted(
        self: Arc<Self>,
        op: R::Op,
        accepted_waker: Option<oneshot::Sender<()>>,
        waker: oneshot::Sender<Result<u64, ReplicationError>>,
    ) -> Result<(), ReplicationError> {
        let fence_timeout = self.cfg.propose_ttl();
        let deadline = TokioInstant::now() + fence_timeout;
        while self.state.lock().history_election_blocks_steady_state() {
            if TokioInstant::now() >= deadline {
                return Err(ReplicationError::ProposeTimeout(fence_timeout));
            }
            tokio::select! {
                _ = self.shutdown.cancelled() => return Err(ReplicationError::Shutdown),
                _ = sleep_until(deadline) => return Err(ReplicationError::ProposeTimeout(fence_timeout)),
                _ = sleep(self.cfg.delivery_tick_interval()) => {}
            }
        }

        // Do not occupy scarce in-flight capacity while waiting for cluster
        // capability convergence. The single proposal deadline covers this
        // readiness phase and the subsequent permit acquisition.
        self.wait_for_v2_protocol_snapshot(deadline, fence_timeout)
            .await?;

        // Bound concurrent in-flight proposals per topic.
        let permit = tokio::select! {
            _ = self.shutdown.cancelled() => return Err(ReplicationError::Shutdown),
            _ = sleep_until(deadline) => return Err(ReplicationError::ProposeTimeout(fence_timeout)),
            permit = self.propose_semaphore.clone().acquire_owned() => {
                permit.map_err(|_| ReplicationError::Shutdown)?
            }
        };

        if self.shutdown.is_cancelled() {
            return Err(ReplicationError::Shutdown);
        }

        // Election can be rearmed while waiting for capacity.
        if self.state.lock().history_election_blocks_steady_state() {
            return Err(ReplicationError::ProposeTimeout(fence_timeout));
        }
        if TokioInstant::now() >= deadline {
            return Err(ReplicationError::ProposeTimeout(fence_timeout));
        }

        // A membership/LSA transition may have happened while capacity was
        // unavailable. Freeze the descriptor only from a fresh v2-ready view
        // immediately before registration and wire emission.
        let network_snapshot = self
            .wait_for_v2_protocol_snapshot(deadline, fence_timeout)
            .await?;

        let encode_started_at = Instant::now();
        let encoded = rmp_serde::to_vec(&op);
        metrics::record_pipeline_stage(
            ReplicationPipelineKind::Strict,
            ReplicationPipelineStage::MsgpackEncode,
            encode_started_at.elapsed(),
        );
        let op_msgpack = Bytes::from(encoded?);
        let op_id = self.next_op_id();
        let op_bytes = op_msgpack.len();
        // Capability and target membership were frozen from one v2-ready
        // LSDB view. A legacy member joining before that view settles keeps
        // this proposal in the readiness wait rather than causing v0 output.
        let protocol_version = self.effective_protocol_version(network_snapshot.negotiated_version);
        if protocol_version != STRICT_PROTOCOL_VERSION_V2 {
            return Err(ReplicationError::ProposeTimeout(fence_timeout));
        }
        let mut target_set: std::collections::HashSet<_> = network_snapshot
            .targets
            .iter()
            .map(|target| target.node)
            .collect();
        target_set.insert(self.self_id);
        let mut target_epochs: HashMap<_, _> = network_snapshot
            .targets
            .iter()
            .map(|target| (target.node, target.boot_epoch))
            .collect();
        target_epochs.insert(self.self_id, self.boot_epoch);
        let frozen_targets = frozen_targets_from_epochs(&target_epochs);
        // A v2 commit must always fit in one terminal catchup response. The
        // bound includes the full replication protobuf envelope, descriptor,
        // resolver identity, and worst-case scalar encoding rather than only
        // the raw operation bytes.
        if !self.v2_terminal_commit_fits_catchup_budget(op_id, &frozen_targets, op_msgpack.clone())
        {
            return Err(ReplicationError::Malformed(
                "strict v2 proposal exceeds terminal catchup response budget",
            ));
        }
        let fq = super::runtime::fast_quorum_size(target_set.len());
        let target_count = target_set.len();

        // Register the proposal and advance our local clock.
        let started_at = Instant::now();
        let (ts_propose, src_clock) = {
            let mut s = self.state.lock();
            // This check and proposal insertion must be one state-lock
            // transaction. Membership recovery may rearm the fence after
            // semaphore acquisition or encoding.
            if self.shutdown.is_cancelled() {
                return Err(ReplicationError::Shutdown);
            }
            if s.history_election_blocks_steady_state() || TokioInstant::now() >= deadline {
                return Err(ReplicationError::ProposeTimeout(fence_timeout));
            }
            let ts_propose = s.tick_clock();
            s.peer_clocks.insert(self.self_id, ts_propose);
            s.proposals.insert(
                op_id,
                Proposal {
                    op_msgpack: op_msgpack.clone(),
                    ts_propose,
                    acks: HashMap::new(),
                    target_set: target_set.clone(),
                    target_epochs,
                    invalid_targets: Default::default(),
                    accepted_waker,
                    waker: Some(waker),
                    committed: false,
                    protocol_version,
                    accept_acks: HashMap::new(),
                    accept_started: false,
                    phase_two_accept: None,
                    #[cfg(any(test, feature = "test-support"))]
                    phase_two_retry_attempts: 0,
                    #[cfg(any(test, feature = "test-support"))]
                    phase_two_floor_pauses: 0,
                    started_at,
                    _permit: permit,
                },
            );
            // Keep a local prepared record after the caller-visible proposal
            // times out. Its v2 descriptor is the coordinator's durable
            // evidence for automatic terminal resolution.
            s.record_pending_propose_with_descriptor(
                op_id,
                self.self_id,
                op_msgpack.clone(),
                ts_propose,
                started_at,
                protocol_version,
                Some(frozen_targets.clone()),
                false,
            );
            (ts_propose, s.clock)
        };
        if !self
            .persist_v2_pending_descriptor(op_id, ts_propose, op_msgpack.clone(), &frozen_targets)
            .await
        {
            let waker = {
                let mut state = self.state.lock();
                state.pending_proposes.remove(&op_id);
                state
                    .proposals
                    .remove(&op_id)
                    .and_then(|proposal| proposal.waker)
            };
            if let Some(waker) = waker {
                let _ = waker.send(Err(ReplicationError::Malformed(
                    "strict v2 proposal descriptor persistence failed",
                )));
            }
            return Err(ReplicationError::Malformed(
                "strict v2 proposal descriptor persistence failed",
            ));
        }
        self.spawn_proposal_deadline(op_id);
        // Start repair before awaiting the initial multicast. The first
        // attempt and every retry use one selected route per destination;
        // the RTT-scaled worker provides bounded recovery without duplicating
        // every proposal over alternate routes.
        self.spawn_propose_retries(op_id);
        tracing::debug!(
            topic = %self.topic,
            op_id_hi = op_id.0,
            op_id_lo = op_id.1,
            node = self.self_id,
            ts_propose,
            target_count,
            fast_quorum = fq,
            op_bytes,
            "strict proposal started"
        );

        // Send `StrictPropose` to every peer in the target set. We don't
        // include ourselves in the multicast — instead, we feed a
        // synthetic self-ack through `recv_propose_ack` so the same
        // quorum-evaluation code path runs (and a 1-node cluster
        // immediately commits).
        let dsts: Vec<_> = target_set
            .iter()
            .filter(|n| **n != self.self_id)
            .copied()
            .collect();
        let body = StrictBody::ProposeV1(StrictProposeV1 {
            coord_node: self.self_id as u32,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            ts_propose,
            op_msgpack,
            src_clock,
            protocol_version,
            frozen_targets: super::runtime::frozen_targets_to_wire(&frozen_targets),
        });
        if !dsts.is_empty() {
            if let Err(e) = self.net.send_multicast(&dsts, &self.topic, body).await {
                trace!(error=%e, "send propose multicast failed");
            }
        }
        let multicast_elapsed = started_at.elapsed();
        if multicast_elapsed >= STRICT_REPLICATION_SLOW_STAGE {
            tracing::warn!(
                topic = %self.topic,
                op_id_hi = op_id.0,
                op_id_lo = op_id.1,
                elapsed_ms = multicast_elapsed.as_millis(),
                target_count,
                peer_count = dsts.len(),
                "strict proposal multicast was slow"
            );
        }

        // Self-ack via the regular path.
        self.recv_propose_ack(
            self.self_id,
            StrictProposeAck {
                ack_node: self.self_id as u32,
                coord_node: self.self_id as u32,
                op_id_hi: op_id.0,
                op_id_lo: op_id.1,
                ts_local: ts_propose,
                src_clock,
                ack_boot_epoch: self.boot_epoch,
            },
        )
        .await;

        self.wake_delivery_and_clock_tick();

        Ok(())
    }

    async fn wait_for_v2_protocol_snapshot(
        &self,
        deadline: TokioInstant,
        fence_timeout: std::time::Duration,
    ) -> Result<StrictProtocolSnapshot, ReplicationError> {
        loop {
            if TokioInstant::now() >= deadline {
                return Err(ReplicationError::ProposeTimeout(fence_timeout));
            }
            let snapshot = self.net.strict_protocol_snapshot();
            if self.effective_protocol_version(snapshot.negotiated_version)
                == STRICT_PROTOCOL_VERSION_V2
            {
                let snapshot = self.filter_admitted_protocol_snapshot(snapshot);
                // A local incarnation must first establish its own admission
                // against the current routed view. Once established, later
                // pending peers remain excluded from this snapshot rather
                // than stopping healthy incumbent coordinators.
                if self.local_coordination_ready() {
                    return Ok(snapshot);
                }
            }
            tokio::select! {
                _ = self.shutdown.cancelled() => return Err(ReplicationError::Shutdown),
                _ = sleep_until(deadline) => return Err(ReplicationError::ProposeTimeout(fence_timeout)),
                _ = sleep(self.cfg.delivery_tick_interval()) => {}
            }
        }
    }
}
