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
use tracing::trace;

use super::super::error::ReplicationError;
use super::super::metrics::{self, ReplicationPipelineKind, ReplicationPipelineStage};
use super::super::proto::{StrictBody, StrictPropose, StrictProposeAck};
use super::StrictReplicable;
use super::runtime::{Proposal, STRICT_REPLICATION_SLOW_STAGE, StrictRuntime};

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
        tokio::time::timeout(fence_timeout, async {
            while self.state.lock().history_election_blocks_steady_state() {
                tokio::select! {
                    _ = self.shutdown.cancelled() => return Err(ReplicationError::Shutdown),
                    _ = tokio::time::sleep(self.cfg.delivery_tick_interval()) => {}
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| ReplicationError::ProposeTimeout(fence_timeout))??;

        // Bound concurrent in-flight proposals per topic.
        let permit = tokio::select! {
            _ = self.shutdown.cancelled() => return Err(ReplicationError::Shutdown),
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
        let (target_set, fq) = self.snapshot_target_set();
        let target_epochs = self.snapshot_target_epochs(&target_set);
        let target_count = target_set.len();

        // Register the proposal and advance our local clock.
        let started_at = Instant::now();
        let (ts_propose, src_clock) = {
            let mut s = self.state.lock();
            // This check and proposal insertion must be one state-lock
            // transaction. Membership recovery may rearm the fence after
            // semaphore acquisition or encoding.
            if s.history_election_blocks_steady_state() {
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
                    started_at,
                    _permit: permit,
                },
            );
            (ts_propose, s.clock)
        };
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
        let body = StrictBody::Propose(StrictPropose {
            coord_node: self.self_id as u32,
            op_id_hi: op_id.0,
            op_id_lo: op_id.1,
            ts_propose,
            op_msgpack,
            src_clock,
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
        self.spawn_propose_retries(op_id);

        Ok(())
    }
}
