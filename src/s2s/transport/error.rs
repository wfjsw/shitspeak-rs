use std::io;
use std::net::SocketAddr;

use thiserror::Error;

use crate::types::NodeIdentifier;

use super::service_level::TransportKind;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("CA file unreadable at {path}: {source}")]
    CaRead { path: String, source: io::Error },
    #[error("certificate file unreadable at {path}: {source}")]
    CertRead { path: String, source: io::Error },
    #[error("private key file unreadable at {path}: {source}")]
    KeyRead { path: String, source: io::Error },
    #[error("CA file at {path} contains no certificates")]
    CaEmpty { path: String },
    #[error("certificate file at {path} contains no certificates")]
    CertEmpty { path: String },
    #[error("private key file at {path} contains no usable key")]
    KeyEmpty { path: String },
    #[error("certificate at {path} is missing a Common Name in its subject")]
    CnMissing { path: String },
    #[error("certificate Common Name {cn:?} cannot be parsed as a u16 NodeIdentifier")]
    CnNotNumeric { cn: String },
    #[error("X.509 parse error: {0}")]
    X509(String),
    #[error("rustls config error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("at least one listener (tcp/kcp/quic/udp) must be configured")]
    NoListener,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("io error binding {addr}: {source}")]
    Bind { addr: SocketAddr, source: io::Error },
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("quic config error: {0}")]
    Quic(String),
    #[error("manager has been shut down")]
    Shutdown,
}

#[derive(Debug, Error)]
pub enum SendError {
    #[error("no transport currently available for node {node} satisfying the requested level")]
    NoSuitableTransport { node: NodeIdentifier },
    #[error("node {node} is not known to the connection manager")]
    UnknownNode { node: NodeIdentifier },
    #[error("transport {transport:?} for node {node} is full; frame dropped")]
    Backpressure { node: NodeIdentifier, transport: TransportKind },
    #[error("transport {transport:?} for node {node} closed before frame could be sent")]
    StreamClosed { node: NodeIdentifier, transport: TransportKind },
    #[error("datagram of {bytes} bytes exceeds configured MTU of {mtu}")]
    DatagramTooLarge { bytes: usize, mtu: usize },
    #[error("encode error: {0}")]
    Encode(#[from] prost::EncodeError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("manager has been shut down")]
    Shutdown,
}
