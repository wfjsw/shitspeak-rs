//! Versioned client state log types.
//!
//! Every mutation to any client's `ClientGlobalState` (and every client
//! add/remove) produces a `ClientStateLogEntry` with a monotonic global
//! version number.  These entries are broadcast to per-client subscribers
//! so each client can construct its own update messages.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::client::client_session_identifier::ClientSessionIdentifier;
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
    pub listening_channel_id: Option<HashSet<u32>>,

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
            || self.listening_channel_id.is_some()
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

    /// Compute the delta between `old` and `new` — only fields that differ
    /// are set to `Some(new_value)`.
    pub fn from_diff(
        old: &super::client_global_state::ClientGlobalState,
        new: &super::client_global_state::ClientGlobalState,
    ) -> Self {
        let mut d = ClientGlobalStateDelta::default();

        diff_plain!(d, old, new, protocol_version, get_protocol_version);
        diff_plain!(d, old, new, current_channel_id, get_current_channel_id);
        diff_clone!(d, old, new, listening_channel_id, get_listening_channel_id);

        diff_plain!(d, old, new, mute, is_muted);
        diff_plain!(d, old, new, deaf, is_deafened);
        diff_plain!(d, old, new, suppress, is_suppressed);
        diff_plain!(d, old, new, self_mute, is_self_muted);
        diff_plain!(d, old, new, self_deaf, is_self_deafened);
        diff_plain!(d, old, new, priority_speaker, is_priority_speaker);
        diff_plain!(d, old, new, recording, is_recording);

        diff_to_vec!(d, old, new, plugin_context, get_plugin_context);
        diff_to_owned!(d, old, new, plugin_identity, get_plugin_identity);

        diff_option!(d, old, new, texture_url, get_texture_url);
        diff_option!(d, old, new, texture_hash, get_texture_hash);
        diff_option!(d, old, new, comment_url, get_comment_url);
        diff_option!(d, old, new, comment_hash, get_comment_hash);

        diff_plain!(d, old, new, user_id, get_user_id);
        diff_clone!(d, old, new, groups, get_groups);
        diff_clone!(d, old, new, tokens, get_tokens);
        diff_option!(d, old, new, display_name, get_display_name_opt);

        d
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
