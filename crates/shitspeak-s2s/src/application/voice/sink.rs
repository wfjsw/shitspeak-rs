//! Receiver-side delivery hook.
//!
//! After the dispatch task pulls a [`VoiceFrame`] off the inbound mpsc
//! (and, in Phase 4+, after the per-(sender, epoch) reorder buffer has
//! emitted it), the frame is handed to an [`AudioSink`]. The production
//! sink lives in the `Server` layer and runs the existing per-recipient
//! local fan-out (decode envelope → re-target per local client → encrypt
//! → batched UDP send). Tests substitute a recording sink to assert
//! delivery shape.
//!
//! The sink is supplied via [`VoiceService::set_audio_sink`]. If no sink
//! is installed, frames are dropped (with a trace log) — useful for
//! single-node deployments where cross-node voice never fires.

use async_trait::async_trait;

use crate::application::proto::VoiceFrame;
use shitspeak_core::NodeIdentifier;

/// Remote playout bounds carried with every cross-node delivery.
///
/// The runtime latches a resolved delay for a talkspurt. The optional
/// preferred delay is installed by a distribution tree when it has a
/// recipient-specific path estimate; legacy multicast leaves it unset and
/// lets the runtime start from its observed-arrival baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteVoicePlayoutPolicy {
    min_delay_ms: u64,
    max_delay_ms: u64,
    p99_margin_ms: u64,
    idle_reset_ms: u64,
    preferred_delay_ms: Option<u64>,
}

impl RemoteVoicePlayoutPolicy {
    pub fn new(
        min_delay_ms: u64,
        max_delay_ms: u64,
        p99_margin_ms: u64,
        idle_reset_ms: u64,
    ) -> Self {
        Self {
            min_delay_ms,
            max_delay_ms: max_delay_ms.max(min_delay_ms),
            p99_margin_ms,
            idle_reset_ms,
            preferred_delay_ms: None,
        }
    }

    pub fn with_preferred_delay_ms(self, preferred_delay_ms: Option<u64>) -> Self {
        Self {
            preferred_delay_ms: preferred_delay_ms
                .map(|value| value.clamp(self.min_delay_ms, self.max_delay_ms)),
            ..self
        }
    }

    pub fn min_delay_ms(self) -> u64 {
        self.min_delay_ms
    }

    pub fn max_delay_ms(self) -> u64 {
        self.max_delay_ms
    }

    pub fn p99_margin_ms(self) -> u64 {
        self.p99_margin_ms
    }

    pub fn idle_reset_ms(self) -> u64 {
        self.idle_reset_ms
    }

    pub fn preferred_delay_ms(self) -> Option<u64> {
        self.preferred_delay_ms
    }
}

/// Receiver-side delivery callback. Implementations are expected to
/// finish quickly (or to spawn their own task); the dispatch task
/// awaits the call serially.
#[async_trait]
pub trait AudioSink: Send + Sync + 'static {
    /// Deliver a fully-emitted (post-reorder) voice frame.
    ///
    /// `from_immediate` is the next-hop overlay peer that handed us the
    /// bytes — not necessarily the speaker's node. The originator is
    /// recoverable from `frame.sender_session` (composite session id).
    async fn deliver(
        &self,
        from_immediate: NodeIdentifier,
        frame: VoiceFrame,
        playout: RemoteVoicePlayoutPolicy,
        is_repair: bool,
    );
}

#[cfg(any(test, feature = "test-support"))]
pub mod testing {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Default)]
    pub struct RecordingSink {
        pub received: Mutex<Vec<(NodeIdentifier, VoiceFrame)>>,
    }

    impl RecordingSink {
        pub fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        pub fn snapshot(&self) -> Vec<(NodeIdentifier, VoiceFrame)> {
            self.received.lock().unwrap().clone()
        }

        pub fn len(&self) -> usize {
            self.received.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl AudioSink for RecordingSink {
        async fn deliver(
            &self,
            from_immediate: NodeIdentifier,
            frame: VoiceFrame,
            _playout: RemoteVoicePlayoutPolicy,
            _is_repair: bool,
        ) {
            self.received.lock().unwrap().push((from_immediate, frame));
        }
    }
}
