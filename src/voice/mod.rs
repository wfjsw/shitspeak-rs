//! Voice routing — shared between TCP-tunneled and UDP voice paths.
//!
//! `route_voice()` is the central function called by both the TCP `UDPTunnel`
//! handler and the UDP socket receive loop.
//!
//! On Linux, outgoing UDP voice packets are batched via `sendmmsg` for a
//! single-syscall flush.  On other platforms, per-packet `send_to` is used.

pub mod codec;
mod routing;
pub mod udp_batch;

pub use routing::route_voice;
