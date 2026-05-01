use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;

use crate::s2s::core::overlay::{Overlay, OverlayError};
use crate::s2s::core::NodeId;

#[async_trait]
pub trait ReliableOverlay: Send + Sync {
    async fn send_reliable(&self, dst: NodeId, payload: Bytes) -> Result<(), OverlayError>;
    async fn broadcast_reliable(&self, payload: Bytes) -> Result<(), OverlayError>;
}

#[async_trait]
impl ReliableOverlay for Overlay {
    async fn send_reliable(&self, dst: NodeId, payload: Bytes) -> Result<(), OverlayError> {
        let _ = self
            .send(
                dst,
                crate::s2s::core::transport::StreamClass::Reliable,
                payload,
            )
            .await?;
        Ok(())
    }

    async fn broadcast_reliable(&self, payload: Bytes) -> Result<(), OverlayError> {
        let _ = self
            .send_broadcast(
                crate::s2s::core::transport::StreamClass::Reliable,
                payload,
            )
            .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct StrictRuntime {
    overlay: Arc<dyn ReliableOverlay>,
    state: Arc<Mutex<StrictState>>,
}

#[derive(Clone)]
pub struct OwnerRuntime {
    overlay: Arc<dyn ReliableOverlay>,
}

#[derive(Debug, Clone, Default)]
pub struct StrictHandle;

#[derive(Debug, Clone, Default)]
pub struct OwnerHandle;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictProposal {
    pub index: u64,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictInboundFrame {
    pub index: u64,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictGapSignal {
    pub expected: u64,
    pub received: u64,
}

#[derive(Debug, Default)]
struct StrictState {
    next_local_index: u64,
    expected_remote_index: u64,
    proposals: Vec<StrictProposal>,
    ingested_frames: Vec<StrictInboundFrame>,
    gap_signals: Vec<StrictGapSignal>,
}

impl StrictRuntime {
    pub fn start(overlay: Arc<dyn ReliableOverlay>) -> (Self, StrictHandle) {
        (
            Self {
                overlay,
                state: Arc::new(Mutex::new(StrictState {
                    next_local_index: 1,
                    expected_remote_index: 1,
                    ..StrictState::default()
                })),
            },
            StrictHandle,
        )
    }

    pub async fn fanout_reliable(&self, payload: Bytes) -> Result<(), OverlayError> {
        self.overlay.broadcast_reliable(payload).await
    }

    pub async fn send_reliable(&self, dst: NodeId, payload: Bytes) -> Result<(), OverlayError> {
        self.overlay.send_reliable(dst, payload).await
    }

    pub fn propose_local(&self, payload: Bytes) -> StrictProposal {
        let mut state = self.state.lock();
        let proposal = StrictProposal {
            index: state.next_local_index,
            payload,
        };
        state.next_local_index = state.next_local_index.saturating_add(1);
        state.proposals.push(proposal.clone());
        proposal
    }

    pub fn ingest_remote(&self, frame: StrictInboundFrame) -> Option<StrictGapSignal> {
        let mut state = self.state.lock();
        let expected = state.expected_remote_index;

        if frame.index > expected {
            let gap = StrictGapSignal {
                expected,
                received: frame.index,
            };
            state.gap_signals.push(gap.clone());
            state.expected_remote_index = frame.index.saturating_add(1);
            state.ingested_frames.push(frame);
            return Some(gap);
        }

        if frame.index == expected {
            state.expected_remote_index = state.expected_remote_index.saturating_add(1);
            state.ingested_frames.push(frame);
            return None;
        }

        // Duplicate or stale frame.
        None
    }

    pub fn expected_remote_index(&self) -> u64 {
        self.state.lock().expected_remote_index
    }

    pub fn proposals_snapshot(&self) -> Vec<StrictProposal> {
        self.state.lock().proposals.clone()
    }

    pub fn gap_signals_snapshot(&self) -> Vec<StrictGapSignal> {
        self.state.lock().gap_signals.clone()
    }
}

impl OwnerRuntime {
    pub fn start(overlay: Arc<dyn ReliableOverlay>) -> (Self, OwnerHandle) {
        (Self { overlay }, OwnerHandle)
    }

    pub async fn fanout_reliable(&self, payload: Bytes) -> Result<(), OverlayError> {
        self.overlay.broadcast_reliable(payload).await
    }

    pub async fn send_reliable(&self, dst: NodeId, payload: Bytes) -> Result<(), OverlayError> {
        self.overlay.send_reliable(dst, payload).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct StubReliableOverlay {
        sends: std::sync::Mutex<usize>,
        broadcasts: std::sync::Mutex<usize>,
    }

    #[async_trait]
    impl ReliableOverlay for StubReliableOverlay {
        async fn send_reliable(&self, _dst: NodeId, _payload: Bytes) -> Result<(), OverlayError> {
            *self.sends.lock().expect("lock") += 1;
            Ok(())
        }

        async fn broadcast_reliable(&self, _payload: Bytes) -> Result<(), OverlayError> {
            *self.broadcasts.lock().expect("lock") += 1;
            Ok(())
        }
    }

    #[tokio::test]
    async fn strict_runtime_uses_reliable_overlay_only() {
        let overlay = Arc::new(StubReliableOverlay::default());
        let (runtime, _handle) = StrictRuntime::start(overlay.clone());

        runtime
            .fanout_reliable(Bytes::from_static(b"x"))
            .await
            .expect("broadcast should succeed");
        runtime
            .send_reliable(7, Bytes::from_static(b"y"))
            .await
            .expect("send should succeed");

        assert_eq!(*overlay.broadcasts.lock().expect("lock"), 1);
        assert_eq!(*overlay.sends.lock().expect("lock"), 1);
    }

    #[test]
    fn strict_runtime_propose_assigns_incrementing_indices() {
        let overlay = Arc::new(StubReliableOverlay::default());
        let (runtime, _handle) = StrictRuntime::start(overlay);

        let first = runtime.propose_local(Bytes::from_static(b"a"));
        let second = runtime.propose_local(Bytes::from_static(b"b"));

        assert_eq!(first.index, 1);
        assert_eq!(second.index, 2);
        let proposals = runtime.proposals_snapshot();
        assert_eq!(proposals.len(), 2);
    }

    #[test]
    fn strict_runtime_detects_gap_in_remote_sequence() {
        let overlay = Arc::new(StubReliableOverlay::default());
        let (runtime, _handle) = StrictRuntime::start(overlay);

        let gap = runtime
            .ingest_remote(StrictInboundFrame {
                index: 3,
                payload: Bytes::from_static(b"x"),
            })
            .expect("gap should be detected");

        assert_eq!(gap.expected, 1);
        assert_eq!(gap.received, 3);
        assert_eq!(runtime.expected_remote_index(), 4);
        assert_eq!(runtime.gap_signals_snapshot().len(), 1);
    }

    #[test]
    fn strict_runtime_ingests_ordered_remote_frames_without_gap() {
        let overlay = Arc::new(StubReliableOverlay::default());
        let (runtime, _handle) = StrictRuntime::start(overlay);

        let g1 = runtime.ingest_remote(StrictInboundFrame {
            index: 1,
            payload: Bytes::from_static(b"x"),
        });
        let g2 = runtime.ingest_remote(StrictInboundFrame {
            index: 2,
            payload: Bytes::from_static(b"y"),
        });

        assert!(g1.is_none());
        assert!(g2.is_none());
        assert_eq!(runtime.expected_remote_index(), 3);
        assert!(runtime.gap_signals_snapshot().is_empty());
    }
}
