use serde::{Deserialize, Serialize};

use crate::session::ClientSessionIdentifier;

pub type NodeIdentifier = u16;

pub const DEFAULT_SERVER_ID: &str = "default";

pub fn default_server_id() -> String {
    DEFAULT_SERVER_ID.to_owned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StrictReplicationMetadata {
    op_id_hi: u64,
    op_id_lo: u64,
    ts_final: u64,
}

impl StrictReplicationMetadata {
    pub fn new(op_id_hi: u64, op_id_lo: u64, ts_final: u64) -> Self {
        Self {
            op_id_hi,
            op_id_lo,
            ts_final,
        }
    }

    pub fn op_id_hi(self) -> u64 {
        self.op_id_hi
    }

    pub fn op_id_lo(self) -> u64 {
        self.op_id_lo
    }

    pub fn ts_final(self) -> u64 {
        self.ts_final
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScopedSessionId {
    #[serde(default = "default_server_id")]
    server_id: String,
    session_id: ClientSessionIdentifier,
}

impl ScopedSessionId {
    pub fn new(server_id: impl Into<String>, session_id: ClientSessionIdentifier) -> Self {
        Self {
            server_id: server_id.into(),
            session_id,
        }
    }

    pub fn default(session_id: ClientSessionIdentifier) -> Self {
        Self::new(DEFAULT_SERVER_ID, session_id)
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    pub fn session_id(&self) -> ClientSessionIdentifier {
        self.session_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScopedChannelId {
    #[serde(default = "default_server_id")]
    server_id: String,
    channel_id: u32,
}

impl ScopedChannelId {
    pub fn new(server_id: impl Into<String>, channel_id: u32) -> Self {
        Self {
            server_id: server_id.into(),
            channel_id,
        }
    }

    pub fn default(channel_id: u32) -> Self {
        Self::new(DEFAULT_SERVER_ID, channel_id)
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }
}
