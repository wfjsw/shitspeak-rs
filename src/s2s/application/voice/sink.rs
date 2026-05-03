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

use crate::s2s::application::proto::VoiceFrame;
use crate::types::NodeIdentifier;

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
    async fn deliver(&self, from_immediate: NodeIdentifier, frame: VoiceFrame);
}

#[cfg(test)]
pub(crate) mod testing {
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
        async fn deliver(&self, from_immediate: NodeIdentifier, frame: VoiceFrame) {
            self.received.lock().unwrap().push((from_immediate, frame));
        }
    }
}
