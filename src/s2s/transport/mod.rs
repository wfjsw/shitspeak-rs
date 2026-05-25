//! Layer-1 unified connection manager for S2S traffic.
//!
//! Hides four wire transports — TCP, KCP, QUIC, UDP — behind a single
//! peer-symmetric, mTLS-authenticated `ConnectionManager`. Every stream
//! transport carries mutual TLS rooted in a shared CA; the peer's
//! `NodeIdentifier` is extracted from the certificate's CN. UDP is
//! datagram-only and encrypts each packet under keys from a signed ephemeral
//! peer exchange rooted in the same CA.

mod compression;
mod config;
mod connection;
mod endpoint;
mod error;
mod frame;
mod identity;
mod manager;
mod metrics;
mod native_stats;
mod probe_schedule;
mod public_ip;
mod service_level;
mod stream_io;
mod tls;

#[cfg(test)]
mod integration_tests;

pub use compression::SendOptions;
pub use config::{TransportConfig, TransportTuning};
pub use error::{ConfigError, SendError, TransportError};
pub(crate) use manager::PeerAddressSnapshot;
pub use manager::{ConnectionManager, Inbound, InboundMessage};
pub use metrics::{LinkMetrics, MetricsSnapshot};
pub(crate) use metrics::{
    apply_packet_loss_penalty, conversational_effective_delay_us, conversational_impairment,
    conversational_quality_score,
};
pub use service_level::{
    MessageClass, PeerAddress, RoutingMetric, ServiceLevel, ServiceShape, TransportKind,
};
