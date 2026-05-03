//! Layer-1 unified connection manager for S2S traffic.
//!
//! Hides four wire transports — TCP, KCP, QUIC, UDP — behind a single
//! peer-symmetric, mTLS-authenticated `ConnectionManager`. Every stream
//! transport carries mutual TLS rooted in a shared CA; the peer's
//! `NodeIdentifier` is extracted from the certificate's CN. UDP is
//! datagram-only and trusts the source-node claim in the frame header.

mod config;
mod connection;
mod dtls_config;
mod endpoint;
mod error;
mod frame;
mod identity;
mod manager;
mod metrics;
mod service_level;
mod stream_io;
mod tls;

#[cfg(test)]
mod integration_tests;

pub use config::{TransportConfig, TransportTuning};
pub use error::{ConfigError, SendError, TransportError};
pub use manager::{ConnectionManager, Inbound, InboundMessage};
pub use metrics::{LinkMetrics, MetricsSnapshot};
pub use service_level::{MessageClass, PeerAddress, ServiceLevel, TransportKind};
