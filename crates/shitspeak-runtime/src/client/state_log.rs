//! Versioned client state log types.
//!
//! Every mutation to any client's `ClientGlobalState` (and every client
//! add/remove) produces a `ClientStateLogEntry` with a monotonic global
//! version number.  These entries are broadcast to per-client subscribers
//! so each client can construct its own update messages.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::client::{ClientInstanceId, client_session_identifier::ClientSessionIdentifier};
use crate::client_repository::ClientRepository;
use crate::types::default_server_id;

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
/// Like `diff_clone` but copies into `Bytes` — for
/// getters that return `&[u8]` when the delta field is `Bytes`.
macro_rules! diff_to_vec {
    ($d:ident, $old:ident, $new:ident, $field:ident, $getter:ident) => {
        if $old.$getter() != $new.$getter() {
            $d.$field = Some(Bytes::copy_from_slice($new.$getter()));
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
    pub plugin_context: Option<Bytes>,
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
    pub is_superuser: Option<bool>,
    pub tokens: Option<HashSet<String>>,
    pub display_name: Option<Option<String>>,

    // Append new replicated fields to preserve positional MessagePack compatibility.
    pub hidden_from_regular_users: Option<bool>,
}

impl ClientGlobalStateDelta {
    pub fn from_global_state(
        state: &crate::client::client_global_state::ClientGlobalState,
    ) -> Self {
        Self {
            current_channel_id: Some(state.get_current_channel_id()),
            listening_channel_add: Some(state.get_listening_channel_id().clone()),
            listening_channel_remove: None,
            mute: Some(state.is_muted()),
            deaf: Some(state.is_deafened()),
            suppress: Some(state.is_suppressed()),
            hidden_from_regular_users: Some(state.is_hidden_from_regular_users()),
            self_mute: Some(state.is_self_muted()),
            self_deaf: Some(state.is_self_deafened()),
            priority_speaker: Some(state.is_priority_speaker()),
            recording: Some(state.is_recording()),
            plugin_context: Some(Bytes::copy_from_slice(state.get_plugin_context())),
            plugin_identity: Some(state.get_plugin_identity().to_owned()),
            texture_url: Some(state.get_texture_url().map(ToOwned::to_owned)),
            texture_hash: Some(state.get_texture_hash().map(ToOwned::to_owned)),
            comment_url: Some(state.get_comment_url().map(ToOwned::to_owned)),
            comment_hash: Some(state.get_comment_hash().map(ToOwned::to_owned)),
            user_id: Some(state.get_user_id()),
            groups: Some(state.get_groups().clone()),
            is_superuser: Some(state.is_superuser()),
            tokens: Some(state.get_tokens().clone()),
            display_name: Some(state.get_display_name_opt().map(ToOwned::to_owned)),
        }
    }

    /// Returns `true` if no fields are set (nothing changed).
    pub fn is_empty(&self) -> bool {
        !(self.current_channel_id.is_some()
            || self.listening_channel_add.is_some()
            || self.listening_channel_remove.is_some()
            || self.mute.is_some()
            || self.deaf.is_some()
            || self.suppress.is_some()
            || self.hidden_from_regular_users.is_some()
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
            || self.is_superuser.is_some()
            || self.tokens.is_some()
            || self.display_name.is_some())
    }

    pub fn affects_acl_generation(&self) -> bool {
        self.current_channel_id.is_some()
            || self.user_id.is_some()
            || self.groups.is_some()
            || self.is_superuser.is_some()
            || self.tokens.is_some()
    }

    pub fn affects_voice_routing(&self) -> bool {
        self.current_channel_id.is_some()
            || self.listening_channel_add.is_some()
            || self.listening_channel_remove.is_some()
            || self.deaf.is_some()
            || self.hidden_from_regular_users.is_some()
            || self.self_deaf.is_some()
            || self.user_id.is_some()
            || self.groups.is_some()
            || self.is_superuser.is_some()
            || self.tokens.is_some()
    }

    pub fn to_initial_user_state(
        &self,
        session_id: ClientSessionIdentifier,
        cert_hash: Option<&Bytes>,
    ) -> crate::messages::encoder::UserState {
        crate::messages::encoder::UserState {
            session: Some(session_id),
            actor: None,
            name: self.display_name.clone().flatten(),
            user_id: self.user_id.flatten(),
            channel_id: self.current_channel_id,
            mute: self.mute.filter(|value| *value),
            deaf: self.deaf.filter(|value| *value),
            suppress: self.suppress.filter(|value| *value),
            self_mute: self.self_mute.filter(|value| *value),
            self_deaf: self.self_deaf.filter(|value| *value),
            texture: None,
            plugin_context: self
                .plugin_context
                .as_ref()
                .filter(|value| !value.is_empty())
                .cloned(),
            plugin_identity: self
                .plugin_identity
                .as_ref()
                .filter(|value| !value.is_empty())
                .cloned(),
            comment: None,
            hash: cert_hash.map(|hash| hex::encode(hash)),
            comment_hash: self
                .comment_hash
                .as_ref()
                .and_then(|hash| hash.as_ref())
                .and_then(|hash| hex::decode(hash).ok().map(Bytes::from)),
            texture_hash: self
                .texture_hash
                .as_ref()
                .and_then(|hash| hash.as_ref())
                .and_then(|hash| hex::decode(hash).ok().map(Bytes::from)),
            priority_speaker: self.priority_speaker.filter(|value| *value),
            recording: self.recording.filter(|value| *value),
            temporary_access_tokens: Vec::new(),
            listening_channel_add: self
                .listening_channel_add
                .as_ref()
                .map(|channels| channels.iter().copied().collect())
                .unwrap_or_default(),
            listening_channel_remove: Vec::new(),
            listening_volume_adjustment: Vec::new(),
        }
    }
}

// ─── ClientStateOperation ────────────────────────────────────────────────────

mod ip_addr_string {
    use super::*;
    use serde::de::Error;

    pub fn serialize<S>(value: &IpAddr, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<IpAddr, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

mod socket_addr_string {
    use super::*;
    use serde::de::Error;

    pub fn serialize<S>(value: &SocketAddr, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SocketAddr, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

mod opt_socket_addr_string {
    use super::*;
    use serde::de::Error;

    pub fn serialize<S>(value: &Option<SocketAddr>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.map(|addr| addr.to_string()).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<SocketAddr>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        value
            .map(|addr| addr.parse().map_err(D::Error::custom))
            .transpose()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientStateOperation {
    AddClient {
        #[serde(default = "default_server_id")]
        server_id: String,
        session_id: ClientSessionIdentifier,
        #[serde(default)]
        client_instance_id: ClientInstanceId,
        #[serde(with = "ip_addr_string")]
        real_ip: IpAddr,
        #[serde(with = "socket_addr_string")]
        tcp_addr: SocketAddr,
        #[serde(with = "opt_socket_addr_string")]
        udp_addr: Option<SocketAddr>,
        #[serde(with = "socket_addr_string")]
        local_addr: SocketAddr,
        cert_hash: Option<Bytes>,
        login_time: DateTime<Utc>,
        initial_state: ClientGlobalStateDelta,
    },
    RemoveClient {
        #[serde(default = "default_server_id")]
        server_id: String,
        session_id: ClientSessionIdentifier,
        #[serde(default)]
        client_instance_id: ClientInstanceId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<ClientSessionIdentifier>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(default)]
        ban: bool,
    },
    UpdateGlobalState {
        #[serde(default = "default_server_id")]
        server_id: String,
        session_id: ClientSessionIdentifier,
        #[serde(default)]
        client_instance_id: ClientInstanceId,
        sender_session_id: Option<ClientSessionIdentifier>,
        delta: ClientGlobalStateDelta,
    },
    ResetNode {
        #[serde(default = "default_server_id")]
        server_id: String,
    },
}

impl ClientStateOperation {
    pub fn affects_voice_routing(&self) -> bool {
        match self {
            Self::AddClient { .. } | Self::RemoveClient { .. } | Self::ResetNode { .. } => true,
            Self::UpdateGlobalState { delta, .. } => delta.affects_voice_routing(),
        }
    }

    /// Return the `session_id` associated with this operation, if any.
    pub fn session_id(&self) -> Option<ClientSessionIdentifier> {
        match self {
            ClientStateOperation::AddClient { session_id, .. } => Some(*session_id),
            ClientStateOperation::RemoveClient { session_id, .. } => Some(*session_id),
            ClientStateOperation::UpdateGlobalState { session_id, .. } => Some(*session_id),
            ClientStateOperation::ResetNode { .. } => None,
        }
    }

    pub fn client_instance_id(&self) -> ClientInstanceId {
        match self {
            ClientStateOperation::AddClient {
                client_instance_id, ..
            }
            | ClientStateOperation::RemoveClient {
                client_instance_id, ..
            }
            | ClientStateOperation::UpdateGlobalState {
                client_instance_id, ..
            } => *client_instance_id,
            ClientStateOperation::ResetNode { .. } => 0,
        }
    }

    pub fn server_id(&self) -> &str {
        match self {
            ClientStateOperation::AddClient { server_id, .. } => server_id,
            ClientStateOperation::RemoveClient { server_id, .. } => server_id,
            ClientStateOperation::UpdateGlobalState { server_id, .. } => server_id,
            ClientStateOperation::ResetNode { server_id } => server_id,
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
    /// If `Some(v)`, this entry depends on channel state at version `v` or
    /// later.  Remote nodes must ensure their channel log is caught up to
    /// at least this version before applying this entry.
    pub channel_version_dep: Option<u64>,
    #[serde(flatten)]
    pub op: ClientStateOperation,
}

/// Broadcast payload: a log entry plus the current version vector so
/// subscribers can detect when they're fully caught up.
#[derive(Debug, Clone)]
pub struct ClientStateBroadcastPayload {
    pub entry: Arc<ClientStateLogEntry>,
    /// Current version for known nodes touched by this broadcast. A value of
    /// `0` means the node's old epoch was cleared and subscribers should
    /// forget their last-seen version for that node.
    pub versions: HashMap<u16, u64>,
    canonical_message: tokio::sync::OnceCell<Option<crate::messages::Message>>,
}

impl ClientStateBroadcastPayload {
    pub fn new(entry: Arc<ClientStateLogEntry>, versions: HashMap<u16, u64>) -> Self {
        Self {
            entry,
            versions,
            canonical_message: tokio::sync::OnceCell::new(),
        }
    }

    /// Returns the canonical protocol message for this publication.
    ///
    /// Message construction is shared by every projection shard, while the
    /// current-instance check is intentionally repeated for each caller. This
    /// preserves the existing behavior where an entry for a disconnected,
    /// replaced client is not delivered after its numeric session is reused.
    pub async fn canonical_message(
        &self,
        repo: &ClientRepository,
    ) -> Option<&crate::messages::Message> {
        if !self.entry.is_current_instance(repo).await {
            return None;
        }
        self.canonical_message
            .get_or_init(|| async { self.entry.to_message_unchecked() })
            .await
            .as_ref()
    }
}

impl ClientStateLogEntry {
    async fn is_current_instance(&self, repo: &ClientRepository) -> bool {
        match &self.op {
            ClientStateOperation::AddClient {
                server_id,
                session_id,
                client_instance_id,
                ..
            } => repo
                .get_client_in_server(server_id, *session_id)
                .await
                .is_some_and(|client| client.client_instance_id() == *client_instance_id),
            ClientStateOperation::RemoveClient {
                server_id,
                session_id,
                client_instance_id,
                ..
            } => repo
                .get_client_in_server(server_id, *session_id)
                .await
                .is_none_or(|client| {
                    *client_instance_id == 0 || client.client_instance_id() == *client_instance_id
                }),
            ClientStateOperation::UpdateGlobalState {
                server_id,
                session_id,
                client_instance_id,
                delta,
                ..
            } => {
                !delta.is_empty()
                    && repo
                        .get_client_in_server(server_id, *session_id)
                        .await
                        .is_some_and(|client| {
                            *client_instance_id == 0
                                || client.client_instance_id() == *client_instance_id
                        })
            }
            ClientStateOperation::ResetNode { .. } => false,
        }
    }

    /// Returns the destination carried by this viewer's own channel-change
    /// entry. Legacy replicated entries with instance id zero apply to the
    /// currently connected instance.
    pub fn own_channel_change_for(
        &self,
        viewer_session_id: ClientSessionIdentifier,
        viewer_client_instance_id: ClientInstanceId,
    ) -> Option<u32> {
        match &self.op {
            ClientStateOperation::UpdateGlobalState {
                session_id,
                client_instance_id,
                delta,
                ..
            } if *session_id == viewer_session_id
                && (*client_instance_id == 0
                    || *client_instance_id == viewer_client_instance_id) =>
            {
                delta.current_channel_id
            }
            _ => None,
        }
    }

    async fn acl_cache_flush_message_for(
        &self,
        repo: &ClientRepository,
        viewer_session_id: ClientSessionIdentifier,
        viewer_client_instance_id: ClientInstanceId,
    ) -> Option<crate::messages::Message> {
        match &self.op {
            ClientStateOperation::UpdateGlobalState {
                server_id,
                session_id,
                client_instance_id,
                delta,
                ..
            } if *session_id == viewer_session_id && delta.affects_acl_generation() => {
                if *client_instance_id != 0 && *client_instance_id != viewer_client_instance_id {
                    return None;
                }
                let client = repo.get_client_in_server(server_id, *session_id).await?;
                if *client_instance_id != 0 && client.client_instance_id() != *client_instance_id {
                    return None;
                }
                Some(crate::messages::encoder::PermissionQuery::flush_cache().into())
            }
            _ => None,
        }
    }

    pub async fn messages_for_client(
        &self,
        repo: &ClientRepository,
        viewer_session_id: ClientSessionIdentifier,
        viewer_client_instance_id: ClientInstanceId,
    ) -> Vec<crate::messages::Message> {
        let mut messages = Vec::new();
        if matches!(
            &self.op,
            ClientStateOperation::AddClient {
                session_id,
                client_instance_id,
                ..
            } if *session_id == viewer_session_id
                && *client_instance_id == viewer_client_instance_id
        ) {
            return messages;
        }
        if let Some(message) = self
            .acl_cache_flush_message_for(repo, viewer_session_id, viewer_client_instance_id)
            .await
        {
            messages.push(message);
        }
        if let Some(message) = self.to_message(repo).await {
            messages.push(message);
        }
        messages
    }

    /// Builds the per-client wrapper messages around an already materialized
    /// canonical state message. Recipient-specific ACL flushing remains local
    /// to the subscriber; only the common state message is shared.
    pub(crate) async fn messages_for_client_with_canonical(
        &self,
        repo: &ClientRepository,
        viewer_session_id: ClientSessionIdentifier,
        viewer_client_instance_id: ClientInstanceId,
        canonical_message: Option<&crate::messages::Message>,
    ) -> Vec<crate::messages::Message> {
        let mut messages = Vec::new();
        if matches!(
            &self.op,
            ClientStateOperation::AddClient {
                session_id,
                client_instance_id,
                ..
            } if *session_id == viewer_session_id
                && *client_instance_id == viewer_client_instance_id
        ) {
            return messages;
        }
        if let Some(message) = self
            .acl_cache_flush_message_for(repo, viewer_session_id, viewer_client_instance_id)
            .await
        {
            messages.push(message);
        }
        // Revalidate after recipient-specific async work. A session may have
        // been removed and numerically reused since the shared payload was
        // first materialized by another shard.
        if let Some(message) = canonical_message
            && self.is_current_instance(repo).await
        {
            messages.push(message.clone());
        }
        messages
    }

    /// Convert this log entry into the protobuf `Message` that should be
    /// sent to a subscriber.
    ///
    /// * `AddClient` -> `UserState` snapshot of the new client
    /// * `RemoveClient` -> `UserRemove` message
    /// * `UpdateGlobalState` -> `UserState` delta (only changed fields)
    pub async fn to_message(&self, repo: &ClientRepository) -> Option<crate::messages::Message> {
        if !self.is_current_instance(repo).await {
            return None;
        }
        self.to_message_unchecked()
    }

    fn to_message_unchecked(&self) -> Option<crate::messages::Message> {
        match &self.op {
            ClientStateOperation::AddClient {
                session_id,
                cert_hash,
                initial_state,
                ..
            } => {
                let us = initial_state.to_initial_user_state(*session_id, cert_hash.as_ref());
                Some(crate::messages::Message::UserState(us.into()))
            }
            ClientStateOperation::RemoveClient {
                session_id,
                actor,
                reason,
                ban,
                ..
            } => Some(
                crate::messages::encoder::UserRemove {
                    session: u32::from(*session_id),
                    actor: actor.map(u32::from),
                    reason: reason.clone(),
                    ban: Some(*ban),
                }
                .into(),
            ),
            ClientStateOperation::UpdateGlobalState {
                session_id,
                sender_session_id,
                delta,
                ..
            } => {
                let mut us = crate::messages::encoder::UserState {
                    session: Some(*session_id),
                    actor: *sender_session_id,
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
                    us.user_id = Some(v.unwrap_or(u32::MAX));
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
                    match v {
                        Some(hash) => {
                            us.texture_hash = hex::decode(hash).ok().map(Bytes::from);
                        }
                        None => {
                            us.texture = Some(Bytes::new());
                        }
                    }
                }
                if let Some(ref v) = delta.comment_hash {
                    match v {
                        Some(hash) => {
                            us.comment_hash = hex::decode(hash).ok().map(Bytes::from);
                        }
                        None => {
                            us.comment = Some(String::new());
                        }
                    }
                }
                if let Some(ref v) = delta.listening_channel_add {
                    us.listening_channel_add = v.iter().copied().collect();
                }
                if let Some(ref v) = delta.listening_channel_remove {
                    us.listening_channel_remove = v.iter().copied().collect();
                }

                Some(us.into())
            }
            ClientStateOperation::ResetNode { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_channel_change_matches_viewer_and_instance() {
        let session_id = ClientSessionIdentifier::new(2, 7).unwrap();
        let entry = ClientStateLogEntry {
            version: 1,
            node_id: 2,
            timestamp: 0,
            channel_version_dep: None,
            op: ClientStateOperation::UpdateGlobalState {
                server_id: "alpha".to_owned(),
                session_id,
                client_instance_id: 42,
                sender_session_id: None,
                delta: ClientGlobalStateDelta {
                    current_channel_id: Some(99),
                    ..Default::default()
                },
            },
        };

        assert_eq!(entry.own_channel_change_for(session_id, 42), Some(99));
        assert_eq!(entry.own_channel_change_for(session_id, 43), None);
        assert_eq!(
            entry.own_channel_change_for(ClientSessionIdentifier::new(2, 8).unwrap(), 42),
            None
        );

        let mut legacy = entry.clone();
        if let ClientStateOperation::UpdateGlobalState {
            client_instance_id, ..
        } = &mut legacy.op
        {
            *client_instance_id = 0;
        }
        assert_eq!(legacy.own_channel_change_for(session_id, 43), Some(99));
    }

    #[test]
    fn voice_routing_delta_classification_is_narrow() {
        for delta in [
            ClientGlobalStateDelta {
                current_channel_id: Some(7),
                ..Default::default()
            },
            ClientGlobalStateDelta {
                listening_channel_add: Some(HashSet::from([7])),
                ..Default::default()
            },
            ClientGlobalStateDelta {
                deaf: Some(true),
                ..Default::default()
            },
            ClientGlobalStateDelta {
                self_deaf: Some(true),
                ..Default::default()
            },
            ClientGlobalStateDelta {
                hidden_from_regular_users: Some(true),
                ..Default::default()
            },
            ClientGlobalStateDelta {
                groups: Some(HashSet::from(["casters".to_owned()])),
                ..Default::default()
            },
            ClientGlobalStateDelta {
                tokens: Some(HashSet::from(["voice".to_owned()])),
                ..Default::default()
            },
        ] {
            assert!(delta.affects_voice_routing());
        }

        for delta in [
            ClientGlobalStateDelta {
                mute: Some(true),
                ..Default::default()
            },
            ClientGlobalStateDelta {
                self_mute: Some(true),
                ..Default::default()
            },
            ClientGlobalStateDelta {
                recording: Some(true),
                ..Default::default()
            },
            ClientGlobalStateDelta {
                comment_hash: Some(Some("hash".to_owned())),
                ..Default::default()
            },
            ClientGlobalStateDelta {
                display_name: Some(Some("name".to_owned())),
                ..Default::default()
            },
        ] {
            assert!(!delta.affects_voice_routing());
        }
    }

    #[test]
    fn cleared_user_id_uses_mumble_wire_sentinel() {
        let session_id = ClientSessionIdentifier::new(2, 7).unwrap();
        let entry = ClientStateLogEntry {
            version: 1,
            node_id: 2,
            timestamp: 0,
            channel_version_dep: None,
            op: ClientStateOperation::UpdateGlobalState {
                server_id: "alpha".to_owned(),
                session_id,
                client_instance_id: 42,
                sender_session_id: None,
                delta: ClientGlobalStateDelta {
                    user_id: Some(None),
                    ..Default::default()
                },
            },
        };

        let message = entry
            .to_message_unchecked()
            .expect("user-id clear should produce a user-state message");
        assert!(matches!(
            message,
            crate::messages::Message::UserState(user_state)
                if user_state.user_id == Some(u32::MAX)
        ));
        assert!(matches!(
            entry.op,
            ClientStateOperation::UpdateGlobalState {
                delta: ClientGlobalStateDelta {
                    user_id: Some(None),
                    ..
                },
                ..
            }
        ));
    }

    #[tokio::test]
    async fn legacy_wildcard_update_projects_current_client_and_flushes_acl_cache() {
        let repo = ClientRepository::new(1, 16);
        let server_id = "alpha".to_owned();
        let session_id = ClientSessionIdentifier::new(2, 7).unwrap();
        let client_instance_id = 42;
        let ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let tcp_addr = SocketAddr::new(ip, 30_001);
        let local_addr = SocketAddr::new(ip, 64_738);
        let add = Arc::new(ClientStateLogEntry {
            version: 1,
            node_id: 2,
            timestamp: Utc::now().timestamp_millis(),
            channel_version_dep: None,
            op: ClientStateOperation::AddClient {
                server_id: server_id.clone(),
                session_id,
                client_instance_id,
                real_ip: ip,
                tcp_addr,
                udp_addr: None,
                local_addr,
                cert_hash: None,
                login_time: Utc::now(),
                initial_state: ClientGlobalStateDelta::default(),
            },
        });
        repo.apply_remote_operation(add, 0).await.unwrap();

        let update = ClientStateLogEntry {
            version: 2,
            node_id: 2,
            timestamp: Utc::now().timestamp_millis(),
            channel_version_dep: None,
            op: ClientStateOperation::UpdateGlobalState {
                server_id,
                session_id,
                client_instance_id: 0,
                sender_session_id: None,
                delta: ClientGlobalStateDelta {
                    display_name: Some(Some("updated".to_owned())),
                    groups: Some(HashSet::from(["staff".to_owned()])),
                    ..Default::default()
                },
            },
        };
        repo.apply_remote_operation(Arc::new(update.clone()), 0)
            .await
            .unwrap();

        let messages = update
            .messages_for_client(&repo, session_id, client_instance_id)
            .await;
        assert!(matches!(
            messages.as_slice(),
            [
                crate::messages::Message::PermissionQuery(query),
                crate::messages::Message::UserState(user_state),
            ] if query.flush == Some(true) && user_state.name.as_deref() == Some("updated")
        ));
    }

    #[tokio::test]
    async fn broadcast_canonical_message_is_shared_but_stale_instances_stay_suppressed() {
        let repo = ClientRepository::new(1, 16);
        let server_id = "alpha".to_owned();
        let session_id = ClientSessionIdentifier::new(2, 7).unwrap();
        let ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let tcp_addr = SocketAddr::new(ip, 30_001);
        let local_addr = SocketAddr::new(ip, 64_738);
        let add = Arc::new(ClientStateLogEntry {
            version: 1,
            node_id: 2,
            timestamp: Utc::now().timestamp_millis(),
            channel_version_dep: None,
            op: ClientStateOperation::AddClient {
                server_id: server_id.clone(),
                session_id,
                client_instance_id: 42,
                real_ip: ip,
                tcp_addr,
                udp_addr: None,
                local_addr,
                cert_hash: None,
                login_time: Utc::now(),
                initial_state: ClientGlobalStateDelta {
                    display_name: Some(Some("first".to_owned())),
                    ..Default::default()
                },
            },
        });
        repo.apply_remote_operation(Arc::clone(&add), 0)
            .await
            .unwrap();
        let payload = ClientStateBroadcastPayload::new(add, HashMap::from([(2, 1)]));

        let first = payload
            .canonical_message(&repo)
            .await
            .expect("current instance has a canonical message") as *const _;
        let second = payload
            .canonical_message(&repo)
            .await
            .expect("canonical message remains available") as *const _;
        assert_eq!(first, second, "the payload must reuse one materialization");

        let replacement = Arc::new(ClientStateLogEntry {
            version: 2,
            node_id: 2,
            timestamp: Utc::now().timestamp_millis(),
            channel_version_dep: None,
            op: ClientStateOperation::AddClient {
                server_id,
                session_id,
                client_instance_id: 43,
                real_ip: ip,
                tcp_addr,
                udp_addr: None,
                local_addr,
                cert_hash: None,
                login_time: Utc::now(),
                initial_state: ClientGlobalStateDelta::default(),
            },
        });
        repo.apply_remote_operation(replacement, 0).await.unwrap();

        assert!(
            payload.canonical_message(&repo).await.is_none(),
            "a cached message for the prior instance must not escape after session reuse"
        );
    }

    #[test]
    fn client_state_log_entry_msgpack_round_trips_add_client() {
        let entry = ClientStateLogEntry {
            version: 3,
            node_id: 1,
            timestamp: 123,
            channel_version_dep: None,
            op: ClientStateOperation::AddClient {
                server_id: default_server_id(),
                session_id: ClientSessionIdentifier::new(1, 42).unwrap(),
                client_instance_id: 99,
                real_ip: "203.0.113.17".parse().unwrap(),
                tcp_addr: "203.0.113.17:64738".parse().unwrap(),
                udp_addr: Some("203.0.113.17:64739".parse().unwrap()),
                local_addr: "10.0.0.1:64738".parse().unwrap(),
                cert_hash: Some(Bytes::from_static(b"hash")),
                login_time: chrono::DateTime::from_timestamp(123, 0).unwrap(),
                initial_state: ClientGlobalStateDelta {
                    display_name: Some(Some("alice".into())),
                    user_id: Some(Some(42)),
                    current_channel_id: Some(0),
                    ..ClientGlobalStateDelta::default()
                },
            },
        };

        let encoded = rmp_serde::to_vec(&entry).expect("encode client state entry");
        let decoded: ClientStateLogEntry =
            rmp_serde::from_slice(&encoded).expect("decode client state entry");

        assert_eq!(decoded.version, entry.version);
        assert_eq!(decoded.node_id, entry.node_id);
        match decoded.op {
            ClientStateOperation::AddClient {
                server_id,
                session_id,
                client_instance_id,
                real_ip,
                tcp_addr,
                udp_addr,
                local_addr,
                cert_hash,
                initial_state,
                ..
            } => {
                assert_eq!(server_id, default_server_id());
                assert_eq!(
                    u32::from(session_id),
                    u32::from(ClientSessionIdentifier::new(1, 42).unwrap())
                );
                assert_eq!(client_instance_id, 99);
                assert_eq!(real_ip, "203.0.113.17".parse::<IpAddr>().unwrap());
                assert_eq!(
                    tcp_addr,
                    "203.0.113.17:64738".parse::<SocketAddr>().unwrap()
                );
                assert_eq!(
                    udp_addr,
                    Some("203.0.113.17:64739".parse::<SocketAddr>().unwrap())
                );
                assert_eq!(local_addr, "10.0.0.1:64738".parse::<SocketAddr>().unwrap());
                assert_eq!(cert_hash, Some(Bytes::from_static(b"hash")));
                assert_eq!(initial_state.display_name, Some(Some("alice".into())));
                assert_eq!(initial_state.user_id, Some(Some(42)));
            }
            other => panic!("expected AddClient, got {other:?}"),
        }
    }
}
