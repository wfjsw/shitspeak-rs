//! Errors surfaced by `ReplicationManager` and runtime handles.

use thiserror::Error;

use crate::overlay::OverlayError;
use shitspeak_core::NodeIdentifier;

#[derive(Debug, Error)]
pub enum ReplicationError {
    #[error("overlay error: {0}")]
    Overlay(#[from] OverlayError),
    #[error("encode error: {0}")]
    Encode(#[from] prost::EncodeError),
    #[error("decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("strict origin authentication failed: {0}")]
    OriginAuthentication(String),
    #[error("msgpack encode error: {0}")]
    MsgpackEncode(#[from] rmp_serde::encode::Error),
    #[error("msgpack decode error: {0}")]
    MsgpackDecode(#[from] rmp_serde::decode::Error),
    #[error("topic not registered: {0}")]
    TopicNotRegistered(String),
    #[error("topic already registered: {0}")]
    TopicAlreadyRegistered(String),
    #[error("quorum lost during proposal (alive members shrunk below fast-quorum)")]
    QuorumLost,
    #[error("propose timed out after {0:?}")]
    ProposeTimeout(std::time::Duration),
    #[error("manager has been shut down")]
    Shutdown,
    #[error("non-owner attempted to propose on owner-mode topic owned by {owner}")]
    NotOwner { owner: NodeIdentifier },
    #[error("malformed wire frame: {0}")]
    Malformed(&'static str),
}
