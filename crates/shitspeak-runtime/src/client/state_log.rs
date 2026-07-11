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
}

impl ClientStateLogEntry {
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
                if *client_instance_id != viewer_client_instance_id {
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

    /// Convert this log entry into the protobuf `Message` that should be
    /// sent to a subscriber.
    ///
    /// * `AddClient` -> `UserState` snapshot of the new client
    /// * `RemoveClient` -> `UserRemove` message
    /// * `UpdateGlobalState` -> `UserState` delta (only changed fields)
    pub async fn to_message(&self, repo: &ClientRepository) -> Option<crate::messages::Message> {
        match &self.op {
            ClientStateOperation::AddClient {
                server_id,
                session_id,
                client_instance_id,
                cert_hash,
                initial_state,
                ..
            } => {
                let Some(client) = repo.get_client_in_server(server_id, *session_id).await else {
                    return None;
                };
                if client.client_instance_id() != *client_instance_id {
                    return None;
                }
                let us = initial_state.to_initial_user_state(*session_id, cert_hash.as_ref());
                Some(crate::messages::Message::UserState(us.into()))
            }
            ClientStateOperation::RemoveClient {
                server_id,
                session_id,
                client_instance_id,
                actor,
                reason,
                ban,
            } => {
                if let Some(client) = repo.get_client_in_server(server_id, *session_id).await {
                    if client.client_instance_id() != *client_instance_id {
                        return None;
                    }
                }
                Some(
                    crate::messages::encoder::UserRemove {
                        session: u32::from(*session_id),
                        actor: actor.map(u32::from),
                        reason: reason.clone(),
                        ban: Some(*ban),
                    }
                    .into(),
                )
            }
            ClientStateOperation::UpdateGlobalState {
                server_id,
                session_id,
                client_instance_id,
                sender_session_id,
                delta,
            } => {
                if delta.is_empty() {
                    return None;
                }
                let client = repo.get_client_in_server(server_id, *session_id).await?;
                if client.client_instance_id() != *client_instance_id {
                    return None;
                }
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
