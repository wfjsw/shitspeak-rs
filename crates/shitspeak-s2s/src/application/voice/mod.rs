//! Cross-node voice fan-out and ingress.
//!
//! See [`crate::application`] for the design rationale (broadcast
//! default, opt-in targeted mode, per-(sender, epoch) reorder buffer).

pub mod ingress;
pub(crate) mod metrics;
pub mod reorder;
pub mod repair;
pub mod send;
pub mod sink;
pub mod targeted;

pub use ingress::{VoiceInbound, VoiceService};
pub use send::{OverlayVoiceTransport, VOICE_CLASS, VOICE_LEVEL, VoiceTransport, build_envelope};
pub use sink::AudioSink;
pub use targeted::{RecipientIndex, RecipientIndexKey, RecipientIndexSnapshot};
