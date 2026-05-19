use serde::{Deserialize, Serialize};

use crate::client::client_session_identifier::ClientSessionIdentifier;

pub type NodeIdentifier = u16;

pub const DEFAULT_SERVER_ID: &str = "default";

pub fn default_server_id() -> String {
    DEFAULT_SERVER_ID.to_owned()
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
