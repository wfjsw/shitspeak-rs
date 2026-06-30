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
use super::super::proto::{StrictBody, StrictPropose, StrictProposeAck};
use super::StrictReplicable;
use super::runtime::{Proposal, StrictRuntime};

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
        // Bound concurrent in-flight proposals per topic.
        let permit = self
            .propose_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ReplicationError::Shutdown)?;

        let op_msgpack = Bytes::from(rmp_serde::to_vec(&op)?);
        let op_id = self.next_op_id();
        let (target_set, _fq) = self.snapshot_target_set();

        // Register the proposal and advance our local clock.
        let (ts_propose, src_clock) = {
            let mut s = self.state.lock();
            let ts_propose = s.tick_clock();
            s.peer_clocks.insert(self.self_id, ts_propose);
            s.proposals.insert(
                op_id,
                Proposal {
                    op_msgpack: op_msgpack.clone(),
                    ts_propose,
                    acks: HashMap::new(),
                    target_set: target_set.clone(),
                    accepted_waker,
                    waker: Some(waker),
                    committed: false,
                    started_at: Instant::now(),
                    _permit: permit,
                },
            );
            (ts_propose, s.clock)
        };

        // Send `StrictPropose` to every peer in the target set. We don't
        // include ourselves in the multicast — instead, we feed a
        // synthetic self-ack through `recv_propose_ack` so the same
        // quorum-evaluation code path runs (and a 1-node cluster
        // immediately commits).
        let dsts: Vec<_> = target_set
            .iter()
            .copied()
            .filter(|n| *n != self.self_id)
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
            },
        )
        .await;

        self.spawn_propose_retries(op_id);

        Ok(())
    }
}
