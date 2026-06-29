use std::io;
use std::path::PathBuf;

use thiserror::Error;

use shitspeak_core::NodeIdentifier;
use shitspeak_s2s_transport::{SendError, TransportError};

#[derive(Debug, Error)]
pub enum OverlayError {
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("send error: {0}")]
    Send(#[from] SendError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("encode error: {0}")]
    Encode(#[from] prost::EncodeError),
    #[error("decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("persistence error: {path:?}: {source}")]
    Persistence { path: PathBuf, source: io::Error },
    #[error("persistence parse error: {path:?}: {source}")]
    PersistenceParse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("invalid config: {0}")]
    Config(String),
    #[error("manager has been shut down")]
    Shutdown,
    #[error("no route to {dst} at level {level:?}")]
    NoRoute {
        dst: NodeIdentifier,
        level: shitspeak_s2s_transport::ServiceLevel,
    },
    #[error("ordered lane {lane} pending window is full for destination {dst}")]
    OrderedWindowFull { dst: NodeIdentifier, lane: u32 },
    #[error("no service handler is registered for tag {tag}")]
    ServiceNotRegistered { tag: u32 },
}
