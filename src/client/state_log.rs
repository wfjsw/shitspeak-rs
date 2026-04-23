//! Versioned client state log types.
//!
//! Every mutation to any client's `ClientGlobalState` (and every client
//! add/remove) produces a `ClientStateLogEntry` with a monotonic global
//! version number.  These entries are broadcast to per-client subscribers
//! so each client can construct its own update messages.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::client::client_session_identifier::ClientSessionIdentifier;
use crate::client_repository::ClientRepository;
use crate::protocol_version::ProtocolVersion;

// ─── Macros ──────────────────────────────────────────────────────────────────

/// In `from_diff`: compare `old.$getter()` vs `new.$getter()`, and if they
/// differ, set `d.$field = Some(<expr>)`.
macro_rules! diff_plain {
    ($d:ident, $old:ident, $new:ident, $field:ident, $getter:ident) => {
        if $old.$getter() != $new.$getter() {
            $d.$field = Some($new.$getter());
        }
    };
}
macro_rules! diff_clone {
    ($d:ident, $old:ident, $new:ident, $field:ident, $getter:ident) => {
        if $old.$getter() != $new.$getter() {
            $d.$field = Some($new.$getter().clone());
        }
    };
}
/// Like `diff_clone` but calls `.to_vec()` instead of `.clone()` — for
/// getters that return `&[u8]` when the delta field is `Vec<u8>`.
macro_rules! diff_to_vec {
    ($d:ident, $old:ident, $new:ident, $field:ident, $getter:ident) => {
        if $old.$getter() != $new.$getter() {
            $d.$field = Some($new.$getter().to_vec());
        }
    };
}
/// Like `diff_clone` but calls `.to_owned()` instead of `.clone()` — for
/// getters that return `&str` when the delta field is `String`.
macro_rules! diff_to_owned {
    ($d:ident, $old:ident, $new:ident, $field:ident, $getter:ident) => {
        if $old.$getter() != $new.$getter() {
            $d.$field = Some($new.$getter().to_owned());
        }
    };
}
macro_rules! diff_option {
    ($d:ident, $old:ident, $new:ident, $field:ident, $getter:ident) => {
        if $old.$getter() != $new.$getter() {
            $d.$field = Some($new.$getter().map(|s| s.to_owned()));
        }
    };
}



// ─── ClientGlobalStateDelta ───────────────────────────────────────────────────

/// A mirror of `ClientGlobalState` where every field is `Option<T>`.
/// Only `Some` fields represent values that changed in a transaction.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientGlobalStateDelta {
    pub protocol_version: Option<Option<ProtocolVersion>>,

    pub current_channel_id: Option<u32>,
    pub listening_channel_add: Option<HashSet<u32>>,
    pub listening_channel_remove: Option<HashSet<u32>>,

    // Voice / moderation
    pub mute: Option<bool>,
    pub deaf: Option<bool>,
    pub suppress: Option<bool>,
    pub self_mute: Option<bool>,
    pub self_deaf: Option<bool>,
    pub priority_speaker: Option<bool>,
    pub recording: Option<bool>,
    pub plugin_context: Option<Vec<u8>>,
    pub plugin_identity: Option<String>,

    // Texture blob
    pub texture_url: Option<Option<String>>,
    pub texture_hash: Option<Option<String>>,

    // Comment blob
    pub comment_url: Option<Option<String>>,
    pub comment_hash: Option<Option<String>>,

    // User identity
    pub user_id: Option<Option<u32>>,
    pub groups: Option<HashSet<String>>,
    pub tokens: Option<HashSet<String>>,
    pub display_name: Option<Option<String>>,
}

impl ClientGlobalStateDelta {
    /// Returns `true` if no fields are set (nothing changed).
    pub fn is_empty(&self) -> bool {
        !(self.protocol_version.is_some()
            || self.current_channel_id.is_some()
            || self.listening_channel_add.is_some()
            || self.listening_channel_remove.is_some()
            || self.mute.is_some()
            || self.deaf.is_some()
            || self.suppress.is_some()
            || self.self_mute.is_some()
            || self.self_deaf.is_some()
            || self.priority_speaker.is_some()
            || self.recording.is_some()
            || self.plugin_context.is_some()
            || self.plugin_identity.is_some()
            || self.texture_url.is_some()
            || self.texture_hash.is_some()
            || self.comment_url.is_some()
            || self.comment_hash.is_some()
            || self.user_id.is_some()
            || self.groups.is_some()
            || self.tokens.is_some()
            || self.display_name.is_some())
    }

}

// ─── ClientStateOperation ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientStateOperation {
    AddClient {
        session_id: ClientSessionIdentifier,
        real_ip: IpAddr,
        tcp_addr: SocketAddr,
        udp_addr: Option<SocketAddr>,
        local_addr: SocketAddr,
        cert_hash: Option<Vec<u8>>,
        login_time: DateTime<Utc>,
    },
    RemoveClient {
        session_id: ClientSessionIdentifier,
    },
    UpdateGlobalState {
        session_id: ClientSessionIdentifier,
        sender_session_id: Option<ClientSessionIdentifier>,
        delta: ClientGlobalStateDelta,
    },
}

impl ClientStateOperation {
    /// Return the `session_id` associated with this operation, if any.
    pub fn session_id(&self) -> Option<ClientSessionIdentifier> {
        match self {
            ClientStateOperation::AddClient { session_id, .. } => Some(*session_id),
            ClientStateOperation::RemoveClient { session_id } => Some(*session_id),
            ClientStateOperation::UpdateGlobalState { session_id, .. } => Some(*session_id),
        }
    }
}

// ─── ClientStateLogEntry ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientStateLogEntry {
    pub version: u64,
    pub node_id: u16,
    /// Unix timestamp (seconds since epoch) when the operation was created.
    pub timestamp: i64,
    #[serde(flatten)]
    pub op: ClientStateOperation,
}

/// Broadcast payload: a log entry plus the current version vector so
/// subscribers can detect when they're fully caught up.
#[derive(Debug, Clone)]
pub struct ClientStateBroadcastPayload {
    pub entry: Arc<ClientStateLogEntry>,
    /// Current version for every known node (local + remote).
    pub versions: HashMap<u16, u64>,
}

impl ClientStateLogEntry {
    /// Convert this log entry into the protobuf `Message` that should be
    /// sent to a subscriber.
    ///
    /// * `AddClient` → `UserState` snapshot of the new client
    /// * `RemoveClient` → `UserRemove` message
    /// * `UpdateGlobalState` → `UserState` delta (only changed fields)
    pub async fn to_message(
        &self,
        repo: &ClientRepository,
    ) -> Option<crate::messages::Message> {
        match &self.op {
            ClientStateOperation::AddClient { session_id, .. } => {
                let client = repo.get_client(*session_id).await?;
                let us: crate::messages::encoder::UserState =
                    client.build_user_state_for_broadcast().await;
                Some(crate::messages::Message::UserState(us.into()))
            }
            ClientStateOperation::RemoveClient { session_id } => {
                Some(crate::messages::encoder::UserRemove {
                    session: u32::from(*session_id),
                    actor: None,
                    reason: None,
                    ban: Some(false),
                }.into())
            }
            ClientStateOperation::UpdateGlobalState {
                session_id,
                sender_session_id,
                delta,
            } => {
                if delta.is_empty() {
                    return None;
                }
                let mut us = crate::mumble_proto::UserState {
                    session: Some(u32::from(*session_id)),
                    actor: sender_session_id.map(|f| u32::from(f)),
                    name: None,
                    user_id: None,
                    channel_id: None,
                    mute: None,
                    deaf: None,
                    suppress: None,
                    self_mute: None,
                    self_deaf: None,
                    texture: None,
                    plugin_context: None,
                    plugin_identity: None,
                    comment: None,
                    hash: None,
                    comment_hash: None,
                    texture_hash: None,
                    priority_speaker: None,
                    recording: None,
                    temporary_access_tokens: Vec::new(),
                    listening_channel_add: Vec::new(),
                    listening_channel_remove: Vec::new(),
                    listening_volume_adjustment: Vec::new(),
                };

                if let Some(ref v) = delta.display_name {
                    us.name = v.clone();
                }
                if let Some(ref v) = delta.user_id {
                    us.user_id = *v;
                }
                if let Some(v) = delta.current_channel_id {
                    us.channel_id = Some(v);
                }
                if let Some(v) = delta.mute {
                    us.mute = Some(v);
                }
                if let Some(v) = delta.deaf {
                    us.deaf = Some(v);
                }
                if let Some(v) = delta.suppress {
                    us.suppress = Some(v);
                }
                if let Some(v) = delta.self_mute {
                    us.self_mute = Some(v);
                }
                if let Some(v) = delta.self_deaf {
                    us.self_deaf = Some(v);
                }
                if let Some(v) = delta.priority_speaker {
                    us.priority_speaker = Some(v);
                }
                if let Some(v) = delta.recording {
                    us.recording = Some(v);
                }
                if let Some(ref v) = delta.plugin_context {
                    us.plugin_context = Some(v.clone());
                }
                if let Some(ref v) = delta.plugin_identity {
                    us.plugin_identity = Some(v.clone());
                }
                if let Some(ref v) = delta.texture_hash {
                    us.texture_hash = v.as_ref().and_then(|h| hex::decode(h).ok());
                }
                if let Some(ref v) = delta.comment_hash {
                    us.comment_hash = v.as_ref().and_then(|h| hex::decode(h).ok());
                }
                if let Some(ref v) = delta.listening_channel_add {
                    us.listening_channel_add = v.iter().copied().collect();
                }
                if let Some(ref v) = delta.listening_channel_remove {
                    us.listening_channel_remove = v.iter().copied().collect();
                }

                Some(crate::messages::Message::UserState(us))
            }
        }
    }
}
