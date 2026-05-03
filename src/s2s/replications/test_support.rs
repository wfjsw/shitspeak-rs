//! In-test mocks for the [`StrictNet`](super::strict::runtime::StrictNet)
//! and [`OwnerNet`](super::owner::runtime::OwnerNet) abstractions.
//!
//! Captures every send into a `Vec<CapturedFrame>` and serves an
//! injectable alive-set / boot-epoch view, so unit tests can drive the
//! runtime state machines end-to-end without spinning up real loopback
//! transports.

#![cfg(test)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;

use super::error::ReplicationError;
use super::owner::runtime::OwnerNet;
use super::proto::{OwnerBody, StrictBody};
use super::strict::runtime::StrictNet;
use crate::types::NodeIdentifier;

#[derive(Debug, Clone)]
pub(crate) enum CapturedFrame {
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
/// alive-set, boot-epoch map, and edge-RTT sample list. Captures every
/// outbound frame.
pub(crate) struct MockNet {
    pub self_id: NodeIdentifier,
    pub alive: Mutex<Vec<NodeIdentifier>>,
    pub epochs: Mutex<std::collections::HashMap<NodeIdentifier, u64>>,
    pub captured: Mutex<Vec<CapturedFrame>>,
    pub edge_rtts: Mutex<Vec<Duration>>,
}

impl MockNet {
    pub fn new(self_id: NodeIdentifier, alive: Vec<NodeIdentifier>) -> Arc<Self> {
        Arc::new(Self {
            self_id,
            alive: Mutex::new(alive),
            epochs: Mutex::new(Default::default()),
            captured: Mutex::new(Vec::new()),
            edge_rtts: Mutex::new(Vec::new()),
        })
    }

    pub fn set_edge_rtts(&self, rtts: Vec<Duration>) {
        *self.edge_rtts.lock() = rtts;
    }

    pub fn set_alive(&self, alive: Vec<NodeIdentifier>) {
        *self.alive.lock() = alive;
    }

    pub fn set_epoch(&self, node: NodeIdentifier, epoch: u64) {
        self.epochs.lock().insert(node, epoch);
    }

    pub fn captures(&self) -> Vec<CapturedFrame> {
        self.captured.lock().clone()
    }

    pub fn drain_captures(&self) -> Vec<CapturedFrame> {
        std::mem::take(&mut *self.captured.lock())
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
        self.captured.lock().push(CapturedFrame::StrictUnicast {
            dst,
            topic: topic.to_owned(),
            body,
        });
        Ok(())
    }

    async fn send_multicast(
        &self,
        dsts: &[NodeIdentifier],
        topic: &str,
        body: StrictBody,
    ) -> Result<(), ReplicationError> {
        self.captured.lock().push(CapturedFrame::StrictMulticast {
            dsts: dsts.to_vec(),
            topic: topic.to_owned(),
            body,
        });
        Ok(())
    }

    async fn send_broadcast(
        &self,
        topic: &str,
        body: StrictBody,
    ) -> Result<(), ReplicationError> {
        self.captured.lock().push(CapturedFrame::StrictBroadcast {
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

    fn edge_rtt_snapshot(&self) -> Vec<Duration> {
        self.edge_rtts.lock().clone()
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
        self.captured.lock().push(CapturedFrame::OwnerUnicast {
            dst,
            topic: topic.to_owned(),
            body,
        });
        Ok(())
    }

    async fn send_broadcast(
        &self,
        topic: &str,
        body: OwnerBody,
    ) -> Result<(), ReplicationError> {
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
}

// ---------- In-memory test repos ----------

use super::owner::{LogSlice as OwnerLog, OwnerReplicable};
use super::strict::{LogSlice as StrictLog, StrictReplicable};

/// Mock strict-mode repo: holds a `(version, Vec<(version, op)>)` log.
pub(crate) struct CountingStrictRepo {
    pub state: Mutex<(u64, Vec<(u64, u64)>)>,
}

impl CountingStrictRepo {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new((0, Vec::new())),
        })
    }

    pub fn log(&self) -> Vec<(u64, u64)> {
        self.state.lock().1.clone()
    }
}

#[async_trait]
impl StrictReplicable for CountingStrictRepo {
    type Op = u64;

    fn current_version(&self) -> u64 {
        self.state.lock().0
    }

    fn snapshot(&self) -> (u64, Vec<u8>) {
        let s = self.state.lock();
        let v = s.0;
        let bytes = rmp_serde::to_vec(&s.1).unwrap_or_default();
        (v, bytes)
    }

    fn log_since(&self, since: u64) -> StrictLog<Self::Op> {
        let s = self.state.lock();
        let log: Vec<(u64, u64)> = s.1.iter().copied().filter(|(v, _)| *v > since).collect();
        StrictLog::Available(log)
    }

    async fn apply_committed(&self, version: u64, op: Self::Op) {
        let mut s = self.state.lock();
        s.0 = version;
        s.1.push((version, op));
    }

    async fn install_snapshot(&self, version: u64, snapshot: Vec<u8>) {
        let entries: Vec<(u64, u64)> = rmp_serde::from_slice(&snapshot).unwrap_or_default();
        let mut s = self.state.lock();
        s.0 = version;
        s.1 = entries;
    }
}

/// Mock owner-mode repo: holds per-origin `(epoch, version, log)`.
pub(crate) struct CountingOwnerRepo {
    pub state: Mutex<std::collections::HashMap<NodeIdentifier, (u64, u64, Vec<(u64, u64)>)>>,
    /// Counts each call to `reset_origin(node, _)`.
    pub reset_calls: Mutex<Vec<(NodeIdentifier, u64)>>,
}

impl CountingOwnerRepo {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(Default::default()),
            reset_calls: Mutex::new(Vec::new()),
        })
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
}

#[async_trait]
impl OwnerReplicable for CountingOwnerRepo {
    type Op = u64;

    fn local_version(&self) -> u64 {
        0
    }

    fn known_versions(&self) -> std::collections::HashMap<NodeIdentifier, (u64, u64)> {
        self.state
            .lock()
            .iter()
            .map(|(k, (e, v, _))| (*k, (*e, *v)))
            .collect()
    }

    fn snapshot_for_origin(&self, origin: NodeIdentifier) -> Option<(u64, u64, Vec<u8>)> {
        let s = self.state.lock();
        s.get(&origin).map(|(e, v, log)| {
            let bytes = rmp_serde::to_vec(log).unwrap_or_default();
            (*e, *v, bytes)
        })
    }

    fn log_for_origin(&self, origin: NodeIdentifier, since: u64) -> OwnerLog<Self::Op> {
        let s = self.state.lock();
        match s.get(&origin) {
            Some((_, _, log)) => {
                let out: Vec<(u64, u64)> = log.iter().copied().filter(|(v, _)| *v > since).collect();
                OwnerLog::Available(out)
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
        snapshot: Vec<u8>,
    ) {
        let log: Vec<(u64, u64)> = rmp_serde::from_slice(&snapshot).unwrap_or_default();
        let mut s = self.state.lock();
        s.insert(origin, (epoch, version, log));
    }

    async fn reset_origin(&self, origin: NodeIdentifier, new_epoch: u64) {
        self.reset_calls.lock().push((origin, new_epoch));
        // Drop the old log; epoch tracker will be set by the next apply.
        let mut s = self.state.lock();
        s.remove(&origin);
    }
}

// ---------- End-to-end tests using MockNet + counting repos ----------

#[cfg(test)]
mod e2e_tests {
    use super::*;
    use super::super::config::ReplicationConfig;
    use super::super::owner::runtime::OwnerRuntime;
    use super::super::proto::{
        OwnerBody, OwnerCatchupReq, OwnerOp, StrictBody, StrictCommit, StrictPropose,
        StrictProposeAck,
    };
    use super::super::strict::runtime::StrictRuntime;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tokio_util::sync::CancellationToken;

    fn default_cfg() -> Arc<ReplicationConfig> {
        Arc::new(ReplicationConfig::default())
    }

    /// 1-node strict cluster: propose immediately self-acks, commits,
    /// delivers, applies. End-to-end.
    #[tokio::test]
    async fn strict_single_node_propose_end_to_end() {
        let net = MockNet::new(1, vec![1]);
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

    /// recv_propose advances clock by max(clock, ts_propose) + 1 and emits
    /// a StrictProposeAck back to the coord via send_unicast.
    #[tokio::test]
    async fn strict_recv_propose_emits_ack() {
        let net = MockNet::new(2, vec![1, 2]);
        let repo = CountingStrictRepo::new();
        let rt = StrictRuntime::new(
            repo,
            2,
            100,
            "channels".into(),
            net.clone() as Arc<dyn StrictNet>,
            CancellationToken::new(),
            default_cfg(),
        );
        // No start(): we want fully synchronous control.

        rt.recv_propose(
            1,
            StrictPropose {
                coord_node: 1,
                op_id_hi: 1,
                op_id_lo: 1,
                ts_propose: 50,
                op_msgpack: rmp_serde::to_vec(&7u64).unwrap(),
                src_clock: 50,
            },
        )
        .await;

        let caps = net.captures();
        assert_eq!(caps.len(), 1);
        match &caps[0] {
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
                op_msgpack: rmp_serde::to_vec(&77u64).unwrap(),
            },
        )
        .await;
        // No apply yet (buffered).
        assert!(repo.applied_for(2).is_empty());
        // Should have emitted exactly one catchup req.
        assert_eq!(net.count_owner_unicasts(), 1);
        let caps = net.captures();
        let CapturedFrame::OwnerUnicast { body, .. } = &caps[0] else {
            panic!()
        };
        match body {
            OwnerBody::CatchupReq(req) => {
                assert_eq!(req.origin_node, 2);
                assert_eq!(req.src_node, 1);
            }
            _ => panic!(),
        }
    }

    /// Owner-mode: epoch advance from `OwnerOp.origin_epoch` triggers
    /// `repo.reset_origin` exactly once, then applies the new op.
    #[tokio::test]
    async fn owner_higher_epoch_resets_and_applies() {
        let net = MockNet::new(1, vec![1, 2]);
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
        repo.state.lock().insert(2, (10, 4, vec![(1, 1), (2, 2), (3, 3), (4, 4)]));
        rt.state.lock().known.insert(2, (10, 4));

        // Now feed an op with epoch=11.
        rt.recv_op(
            2,
            OwnerOp {
                origin_node: 2,
                origin_epoch: 11,
                origin_version: 1,
                op_msgpack: rmp_serde::to_vec(&999u64).unwrap(),
            },
        )
        .await;

        // reset_origin should have been called once with new_epoch=11.
        let resets = repo.reset_calls_for(2);
        assert_eq!(resets, vec![11]);
        // The new op is applied at (11, 1).
        assert_eq!(repo.applied_for(2), vec![(1, 999)]);
    }

    /// `MembershipEvent::Restarted` clears pending buffer for origin but
    /// does NOT call `reset_origin` until the next OwnerOp.
    #[tokio::test]
    async fn owner_restarted_event_clears_pending_no_immediate_reset() {
        use crate::s2s::overlay::MembershipEvent;
        let net = MockNet::new(1, vec![1, 2]);
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
        rt.state.lock().catchup_in_flight.insert(2, std::time::Instant::now());

        // Restart event arrives.
        rt.on_membership_event(&MembershipEvent::Restarted(2));

        // Pending buffer + catchup state cleared.
        assert!(rt.state.lock().pending_buffers.get(&2).is_none());
        assert!(rt.state.lock().catchup_in_flight.get(&2).is_none());
        // BUT no immediate reset_origin call.
        assert!(repo.reset_calls_for(2).is_empty());
    }
}

