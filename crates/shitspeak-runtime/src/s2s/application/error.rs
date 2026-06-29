use prost::{DecodeError, EncodeError};

use crate::s2s::overlay::OverlayError;

/// Errors surfaced by the `application` (L3) layer.
#[derive(Debug, thiserror::Error)]
pub enum ApplicationError {
    #[error("overlay: {0}")]
    Overlay(#[from] OverlayError),

    #[error("encode: {0}")]
    Encode(#[from] EncodeError),

    #[error("decode: {0}")]
    Decode(#[from] DecodeError),

    #[error("invalid envelope: {0}")]
    InvalidEnvelope(&'static str),

    #[error("rpc timed out")]
    Timeout,

    #[error("rpc service unavailable")]
    Unavailable,
}
