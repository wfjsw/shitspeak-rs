//! Voice routing — shared between TCP-tunneled and UDP voice paths.
//!
//! Both the TCP `UDPTunnel` handler and the UDP socket receive loop push
//! decoded audio into a per-user `VoiceRoutingPayload` channel; the
//! per-user routing task then calls `route_voice()` to fan out to recipients.
//!
//! On Linux, outgoing UDP voice packets are batched via `sendmmsg` for a
//! single-syscall flush.  On other platforms, per-packet `send_to` is used.

pub use shitspeak_voice::{codec, ping, routing_queue, udp_batch};
mod routing;

pub(crate) use routing::route_s2s_voice_frame;
pub use routing::route_voice;
pub use routing::spawn_voice_routing_task;
pub use routing::spawn_voice_tcp_task;
pub use shitspeak_voice::routing_queue::VoiceRoutingPayload;
