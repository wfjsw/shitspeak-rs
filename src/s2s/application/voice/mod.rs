//! Cross-node voice fan-out and ingress.
//!
//! See [`crate::s2s::application`] for the design rationale (broadcast
//! default, opt-in targeted mode, per-(sender, epoch) reorder buffer).

pub mod ingress;
pub mod reorder;
pub mod send;
pub mod sink;
pub mod targeted;

pub use ingress::{VoiceInbound, VoiceService};
pub use send::{build_envelope, OverlayVoiceTransport, VoiceTransport, VOICE_CLASS, VOICE_LEVEL};
pub use sink::AudioSink;
pub use targeted::RecipientIndex;
