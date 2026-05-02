use std::io;
use std::path::PathBuf;

use thiserror::Error;

use crate::s2s::transport::{SendError, TransportError};

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
}
