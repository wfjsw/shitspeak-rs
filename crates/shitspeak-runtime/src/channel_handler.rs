//! Channel message handling with ACL support.
//!
//! This module provides utilities for converting channel operations to protocol messages,
//! with optional permission info and ACL handling. Useful for authentication, gap replay,
//! subscription broadcasts, and future features like S2S replication and admin APIs.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use crate::{
    channel_repository::{ChannelOp, ChannelOperation, ChannelRepository},
    channels::Channel,
    client::{
        Client,
        client_session_identifier::ClientSessionIdentifier,
        group::{
            ChannelHierarchy, ClientMembershipQuery, group_depends_on_home_channel,
            is_member_in_group,
        },
    },
    errors::WriteProtoMessageError,
    messages::{Message, encoder::ChannelState},
    server::Server,
};

#[derive(Debug, Clone, Default)]
pub struct SessionChannelShadow {
    session_channel: HashMap<ClientSessionIdentifier, u32>,
    sessions_by_channel: HashMap<u32, HashSet<ClientSessionIdentifier>>,
}

impl SessionChannelShadow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, session: ClientSessionIdentifier, channel_id: u32) -> Option<u32> {
        let old = self.session_channel.insert(session, channel_id);
        if old == Some(channel_id) {
            return old;
        }
        if let Some(old_channel_id) = old {
            self.remove_index_entry(session, old_channel_id);
        }
        self.sessions_by_channel
            .entry(channel_id)
            .or_default()
            .insert(session);
        old
    }

    pub fn remove(&mut self, session: &ClientSessionIdentifier) -> Option<u32> {
        let old = self.session_channel.remove(session)?;
        self.remove_index_entry(*session, old);
        Some(old)
    }

    pub fn clear(&mut self) {
        self.session_channel.clear();
        self.sessions_by_channel.clear();
    }

    pub fn extend(&mut self, sessions: impl IntoIterator<Item = (ClientSessionIdentifier, u32)>) {
        for (session, channel_id) in sessions {
            self.insert(session, channel_id);
        }
    }

    pub fn get(&self, session: &ClientSessionIdentifier) -> Option<&u32> {
        self.session_channel.get(session)
    }

    pub fn contains_key(&self, session: &ClientSessionIdentifier) -> bool {
        self.session_channel.contains_key(session)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&ClientSessionIdentifier, &u32)> {
        self.session_channel.iter()
    }

    pub fn values(&self) -> impl Iterator<Item = &u32> {
        self.session_channel.values()
    }

    pub fn sessions_in_channels(&self, channel_ids: &HashSet<u32>) -> Vec<ClientSessionIdentifier> {
        let mut sessions = HashSet::new();
        for channel_id in channel_ids {
            if let Some(channel_sessions) = self.sessions_by_channel.get(channel_id) {
                sessions.extend(channel_sessions.iter().copied());
            }
        }
        let mut sessions = sessions.into_iter().collect::<Vec<_>>();
        sessions.sort_by_key(|session| u32::from(*session));
        sessions
    }

    fn remove_index_entry(&mut self, session: ClientSessionIdentifier, channel_id: u32) {
        let Some(sessions) = self.sessions_by_channel.get_mut(&channel_id) else {
            return;
        };
        sessions.remove(&session);
        if sessions.is_empty() {
            self.sessions_by_channel.remove(&channel_id);
        }
    }
}

impl IntoIterator for SessionChannelShadow {
    type Item = (ClientSessionIdentifier, u32);
    type IntoIter = std::collections::hash_map::IntoIter<ClientSessionIdentifier, u32>;

    fn into_iter(self) -> Self::IntoIter {
        self.session_channel.into_iter()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ChannelTreeShadow {
    channel_ids: HashSet<u32>,
}

impl ChannelTreeShadow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, channel_id: u32) -> bool {
        self.channel_ids.insert(channel_id)
    }

    pub fn remove(&mut self, channel_id: &u32) -> bool {
        self.channel_ids.remove(channel_id)
    }

    pub fn contains(&self, channel_id: &u32) -> bool {
        self.channel_ids.contains(channel_id)
    }

    pub fn clear(&mut self) {
        self.channel_ids.clear();
    }

    pub fn extend(&mut self, channel_ids: impl IntoIterator<Item = u32>) {
        self.channel_ids.extend(channel_ids);
    }

    pub fn difference<'a>(&'a self, other: &'a Self) -> impl Iterator<Item = &'a u32> {
        self.channel_ids.difference(&other.channel_ids)
    }

    pub fn sync_message(&mut self, message: &Message) {
        match message {
            Message::ChannelState(channel_state) => {
                if let Some(channel_id) = channel_state.channel_id {
                    self.insert(channel_id);
                }
            }
            Message::ChannelRemove(channel_remove) => {
                self.remove(&channel_remove.channel_id);
            }
            _ => {}
        }
    }
}

impl FromIterator<u32> for ChannelTreeShadow {
    fn from_iter<T: IntoIterator<Item = u32>>(iter: T) -> Self {
        let mut shadow = Self::new();
        shadow.extend(iter);
        shadow
    }
}

impl IntoIterator for ChannelTreeShadow {
    type Item = u32;
    type IntoIter = std::collections::hash_set::IntoIter<u32>;

    fn into_iter(self) -> Self::IntoIter {
        self.channel_ids.into_iter()
    }
}

#[derive(Debug)]
pub(crate) enum ChannelReplayError {
    ClientWriteFailed(WriteProtoMessageError),
}

pub(crate) async fn permission_info_for_channel(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_id: u32,
) -> (bool, enumflags2::BitFlags<crate::acl::ACLPermissions>) {
    let server_id = client.server_id();
    let (_, channel, ancestors) = server
        .get_channels()
        .get_channel_with_ancestors_for_acl_in_server(&server_id, channel_id)
        .await;
    let is_enter_restricted = channel.as_ref().is_some_and(|channel| {
        crate::acl::channel_has_effective_restriction(
            channel,
            &ancestors,
            crate::acl::ACLPermissions::Traverse,
        ) || crate::acl::channel_has_effective_restriction(
            channel,
            &ancestors,
            crate::acl::ACLPermissions::Enter,
        )
    });
    let perms =
        crate::client::acl::compute_permissions_for_client(server, client, channel_id).await;
    (is_enter_restricted, perms)
}

/// Helper to add permission information to a ChannelState message.
/// Applied when `send_permission_info` is enabled.
pub async fn apply_permission_info_to_channel_state(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    cs_proto: &crate::messages::Message,
    channels: &Arc<ChannelRepository>,
) -> Option<crate::messages::Message> {
    if let crate::messages::Message::ChannelState(cs_proto) = cs_proto {
        if let Some(ch_id) = cs_proto.channel_id {
            let server_id = client.server_id();
            if channels
                .get_channel_in_server(&server_id, ch_id)
                .await
                .is_some()
            {
                let (is_enter_restricted, perms) =
                    permission_info_for_channel(server, client, ch_id).await;
                let encoder_cs: crate::messages::encoder::ChannelState = cs_proto.clone().into();
                return Some(
                    encoder_cs
                        .with_permission_info(is_enter_restricted, perms)
                        .into(),
                );
            }
        }
    }
    Some(cs_proto.clone())
}

/// Convert a channel operation to message(s) for a specific client.
/// Handles:
/// - Adding permission info to ChannelState when configured
/// - Converting SetAcls to PermissionQuery when configured
/// Returns a Vec<Message> (usually 1, but 2 for SetAcls if send_permission_info enabled)
pub async fn convert_channel_operation_to_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    op: &ChannelOperation,
    channels: &Arc<ChannelRepository>,
) -> Vec<crate::messages::Message> {
    convert_channel_operation_to_messages_with_shadow(server, client, op, channels, None).await
}

/// Convert a channel operation to messages while consulting a socket-local
/// view of user channel placement. This avoids dragging a client back to a
/// pending-delete parent if this socket already observed a newer move.
pub async fn convert_channel_operation_to_messages_with_shadow(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    op: &ChannelOperation,
    channels: &Arc<ChannelRepository>,
    mut session_channel_shadow: Option<&mut SessionChannelShadow>,
) -> Vec<crate::messages::Message> {
    let mut messages = Vec::new();
    let send_permission_info = server.read_config().send_permission_info;
    let server_id = client.server_id();
    if op.server_id != server_id {
        return messages;
    }

    if let Some(channel_ids) = channels
        .acl_affected_channel_ids_for_op(&server_id, &op.op)
        .await
    {
        messages.extend(
            build_channel_permission_query_refresh_messages_for_channel_ids(
                server,
                client,
                channels,
                channel_ids,
            )
            .await,
        );
    }

    match &op.op {
        ChannelOp::MarkPendingDelete {
            id,
            nonce,
            evict_clients,
        } => {
            if *evict_clients && let Some(shadow) = session_channel_shadow.as_deref_mut() {
                append_pending_delete_synthetic_moves(
                    server,
                    channels,
                    shadow,
                    *id,
                    *nonce,
                    false,
                    None,
                    &server_id,
                    &mut messages,
                )
                .await;
            }
        }
        ChannelOp::DeleteChannel { id, nonce } => {
            if op.emits_client_message {
                if let Some(shadow) = session_channel_shadow.as_deref_mut() {
                    let deleted_channel_ids = channels
                        .delete_visibility_hint_for_operation(op)
                        .map(|channel_ids| channel_ids.iter().copied().collect::<HashSet<_>>());
                    append_pending_delete_synthetic_moves(
                        server,
                        channels,
                        shadow,
                        *id,
                        *nonce,
                        true,
                        deleted_channel_ids.as_ref(),
                        &server_id,
                        &mut messages,
                    )
                    .await;
                }

                // Stale nonce deletes are committed for strict-log convergence
                // but must not emit ChannelRemove if the channel survived.
                if let Some(msg) = op.to_message() {
                    messages.push(msg);
                }
            }
        }
        ChannelOp::InstallSnapshot { channels, removed } => {
            for channel in ordered_snapshot_channels(channels) {
                messages.push(
                    build_channel_state_message(server, client, &channel)
                        .await
                        .into(),
                );
            }
            for channel_id in removed {
                messages.push(
                    crate::messages::encoder::ChannelRemove {
                        channel_id: *channel_id,
                    }
                    .into(),
                );
            }
        }
        _ => {
            if let Some(msg) = op.to_message() {
                let msg = if send_permission_info {
                    match apply_permission_info_to_channel_state(server, client, &msg, channels)
                        .await
                    {
                        Some(m) => m,
                        None => msg,
                    }
                } else {
                    msg
                };
                messages.push(msg);
            }
        }
    }

    if send_permission_info
        && let Some(channel_ids) = channels
            .acl_affected_channel_ids_for_op(&server_id, &op.op)
            .await
        && !matches!(op.op, ChannelOp::InstallSnapshot { .. })
    {
        messages.extend(
            build_channel_permission_info_refresh_messages_for_channel_ids(
                server,
                client,
                channels,
                channel_ids,
            )
            .await,
        );
    }

    messages
}

pub async fn sync_shadow_for_client_message(
    server: &Arc<Box<Server>>,
    channels: &Arc<ChannelRepository>,
    shadow: &mut SessionChannelShadow,
    server_id: &str,
    message: &Message,
) -> Vec<Message> {
    match message {
        Message::UserState(user_state) => {
            let Some(session) = user_state.session.map(ClientSessionIdentifier::from) else {
                return Vec::new();
            };
            let Some(channel_id) = user_state.channel_id else {
                return Vec::new();
            };

            shadow.insert(session, channel_id);
            synthetic_move_if_pending_delete(
                server, channels, shadow, session, channel_id, server_id,
            )
            .await
        }
        Message::UserRemove(user_remove) => {
            shadow.remove(&ClientSessionIdentifier::from(user_remove.session));
            Vec::new()
        }
        _ => Vec::new(),
    }
}

async fn synthetic_move_if_pending_delete(
    server: &Arc<Box<Server>>,
    channels: &Arc<ChannelRepository>,
    shadow: &mut SessionChannelShadow,
    session: ClientSessionIdentifier,
    channel_id: u32,
    server_id: &str,
) -> Vec<Message> {
    if !channels
        .is_pending_delete_subtree_in_server(server_id, channel_id)
        .await
    {
        return Vec::new();
    }

    let target = channels
        .redirect_pending_delete_target_in_server(server_id, channel_id)
        .await;
    let Some(target_client) = server
        .get_clients()
        .get_client_in_server(server_id, session)
        .await
    else {
        return Vec::new();
    };
    let target =
        crate::user_channel_cache::resolve_forced_move_channel(server, &target_client, target)
            .await;
    if target == channel_id {
        return Vec::new();
    }

    let message = synthetic_user_move(server, shadow, session, channel_id, target);
    message.into_iter().collect()
}

async fn append_pending_delete_synthetic_moves(
    server: &Arc<Box<Server>>,
    channels: &Arc<ChannelRepository>,
    shadow: &mut SessionChannelShadow,
    id: u32,
    nonce: u64,
    include_deleted_snapshot: bool,
    deleted_channel_ids: Option<&HashSet<u32>>,
    server_id: &str,
    messages: &mut Vec<Message>,
) {
    let subtree: std::collections::HashSet<u32> = if include_deleted_snapshot {
        if let Some(deleted_channel_ids) = deleted_channel_ids {
            deleted_channel_ids.clone()
        } else {
            deleted_subtree_from_shadow(channels, server_id, id, shadow).await
        }
    } else {
        channels
            .pending_delete_subtree_in_server(server_id, id, nonce)
            .await
            .into_iter()
            .collect()
    };
    if subtree.is_empty() {
        return;
    }

    let initial_target = channels
        .redirect_pending_delete_target_in_server(server_id, id)
        .await;
    let sessions = shadow.sessions_in_channels(&subtree);

    for session in sessions {
        let Some(current) = shadow.get(&session).copied() else {
            continue;
        };
        let Some(target_client) = server
            .get_clients()
            .get_client_in_server(server_id, session)
            .await
        else {
            continue;
        };
        let target = crate::user_channel_cache::resolve_forced_move_channel(
            server,
            &target_client,
            initial_target,
        )
        .await;
        if let Some(message) = synthetic_user_move(server, shadow, session, current, target) {
            messages.push(message);
        }
    }
}

async fn deleted_subtree_from_shadow(
    channels: &Arc<ChannelRepository>,
    server_id: &str,
    id: u32,
    shadow: &SessionChannelShadow,
) -> std::collections::HashSet<u32> {
    let channels_by_id: HashMap<u32, _> = channels
        .get_all_in_server(server_id)
        .await
        .into_iter()
        .map(|channel| (channel.id, channel))
        .collect();

    shadow
        .values()
        .copied()
        .filter(|channel_id| {
            *channel_id == id
                || !channels_by_id.contains_key(channel_id)
                || has_ancestor(&channels_by_id, *channel_id, id)
        })
        .collect()
}

fn has_ancestor(
    channels_by_id: &HashMap<u32, crate::channels::Channel>,
    channel_id: u32,
    ancestor_id: u32,
) -> bool {
    let mut current = channels_by_id
        .get(&channel_id)
        .and_then(|channel| channel.parent_id);
    while let Some(id) = current {
        if id == ancestor_id {
            return true;
        }
        current = channels_by_id
            .get(&id)
            .and_then(|channel| channel.parent_id);
    }
    false
}

fn synthetic_user_move(
    _server: &Arc<Box<Server>>,
    shadow: &mut SessionChannelShadow,
    session: ClientSessionIdentifier,
    current_channel: u32,
    target_channel: u32,
) -> Option<Message> {
    if current_channel == target_channel {
        return None;
    }
    shadow.insert(session, target_channel);
    Some(
        crate::messages::encoder::UserState {
            session: Some(session),
            actor: None,
            channel_id: Some(target_channel),
            ..Default::default()
        }
        .into(),
    )
}

/// Replay missed channel log entries for a client between versions.
/// Ensures clients catch up on channel state changes they missed due to network gaps.
pub async fn replay_channel_log_gap(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channels: &Arc<ChannelRepository>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut crate::client::visibility::UserVisibilityState,
    session_id: crate::client::client_session_identifier::ClientSessionIdentifier,
    last: u64,
    current: u64,
) -> Result<(), ChannelReplayError> {
    if current <= last + 1 {
        return Ok(());
    }

    tracing::warn!(
        "Client {:?} missed channel log entries: last={} current={}",
        session_id,
        last,
        current,
    );

    let server_id = client.server_id();
    let missed = channels.get_log_since_in_server(&server_id, last).await;
    if missed.is_empty() {
        let latest = channels.current_version_in_server(&server_id);
        if latest <= last {
            return Ok(());
        }
        tracing::error!(
            "Client {:?} channel log gap outside replay window; sending channel snapshot (last={}, latest={})",
            session_id,
            last,
            latest,
        );
        return replay_channel_snapshot(
            server,
            client,
            channels,
            channel_tree_shadow,
            session_channel_shadow,
            user_visibility,
            &server_id,
            latest,
        )
        .await;
    }
    if missed
        .first()
        .is_some_and(|entry| entry.version > last.saturating_add(1))
    {
        let latest = channels.current_version_in_server(&server_id);
        tracing::error!(
            "Client {:?} channel log gap starts after last seen version; sending channel snapshot (last={}, first_retained={}, latest={})",
            session_id,
            last,
            missed[0].version,
            latest,
        );
        return replay_channel_snapshot(
            server,
            client,
            channels,
            channel_tree_shadow,
            session_channel_shadow,
            user_visibility,
            &server_id,
            latest,
        )
        .await;
    }

    let mut outbound = Vec::new();
    for entry in &missed {
        if entry.version >= current {
            break;
        }
        let messages = convert_channel_operation_to_messages_with_shadow(
            server,
            client,
            entry,
            channels,
            Some(session_channel_shadow),
        )
        .await;
        for msg in messages {
            let projected = crate::client::visibility::project_message_with_shadow(
                server,
                client,
                user_visibility,
                session_channel_shadow,
                &server_id,
                &msg,
            )
            .await;
            for msg in projected {
                channel_tree_shadow.sync_message(&msg);
                outbound.push(msg);
            }
        }
        let refresh_scope =
            crate::client::visibility::visibility_refresh_scope_for_channel_operation_with_state(
                server,
                entry,
                user_visibility,
            )
            .await;
        let projected = crate::client::visibility::visibility_refresh_messages_with_shadow(
            server,
            client,
            user_visibility,
            session_channel_shadow,
            &server_id,
            refresh_scope,
        )
        .await;
        for msg in projected {
            channel_tree_shadow.sync_message(&msg);
            outbound.push(msg);
        }
        client.set_last_channel_version(entry.version).await;
    }

    client
        .write_proto_message_batch(&outbound)
        .await
        .map_err(ChannelReplayError::ClientWriteFailed)?;

    Ok(())
}

async fn replay_channel_snapshot(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channels: &Arc<ChannelRepository>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut crate::client::visibility::UserVisibilityState,
    server_id: &str,
    latest: u64,
) -> Result<(), ChannelReplayError> {
    let snapshot = channels.get_all_in_server(server_id).await;
    let current: ChannelTreeShadow = snapshot.iter().map(|channel| channel.id).collect();
    let mut removed = channel_tree_shadow
        .difference(&current)
        .copied()
        .collect::<Vec<_>>();
    removed.sort_unstable();

    let mut messages = Vec::with_capacity(snapshot.len() + removed.len());
    for channel in ordered_snapshot_channels(&snapshot) {
        messages.push(
            build_channel_state_message(server, client, &channel)
                .await
                .into(),
        );
    }
    for channel_id in removed {
        messages.push(crate::messages::encoder::ChannelRemove { channel_id }.into());
    }

    let mut outbound = Vec::new();
    for msg in messages {
        let projected = crate::client::visibility::project_message_with_shadow(
            server,
            client,
            user_visibility,
            session_channel_shadow,
            server_id,
            &msg,
        )
        .await;
        for msg in projected {
            channel_tree_shadow.sync_message(&msg);
            outbound.push(msg);
        }
    }

    client
        .write_proto_message_batch(&outbound)
        .await
        .map_err(ChannelReplayError::ClientWriteFailed)?;

    *channel_tree_shadow = current;
    client.set_last_channel_version(latest).await;
    Ok(())
}

pub fn ordered_snapshot_channels(
    channels: &[crate::channels::Channel],
) -> Vec<crate::channels::Channel> {
    let by_id: HashMap<u32, &crate::channels::Channel> = channels
        .iter()
        .map(|channel| (channel.id, channel))
        .collect();
    let mut children: HashMap<Option<u32>, Vec<u32>> = HashMap::new();
    for channel in channels {
        children
            .entry(channel.parent_id)
            .or_default()
            .push(channel.id);
    }
    for child_ids in children.values_mut() {
        child_ids.sort_by_key(|id| {
            by_id
                .get(id)
                .map(|channel| (channel.position, channel.id))
                .unwrap_or((0, *id))
        });
    }

    let mut out = Vec::with_capacity(channels.len());
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    if by_id.contains_key(&0) {
        queue.push_back(0);
    }

    while let Some(id) = queue.pop_front() {
        if !visited.insert(id) {
            continue;
        }
        let Some(channel) = by_id.get(&id) else {
            continue;
        };
        out.push((*channel).clone());
        if let Some(child_ids) = children.get(&Some(id)) {
            queue.extend(child_ids.iter().copied());
        }
    }

    let mut remaining: Vec<_> = channels
        .iter()
        .filter(|channel| !visited.contains(&channel.id))
        .cloned()
        .collect();
    remaining.sort_by_key(|channel| (channel.parent_id.unwrap_or(0), channel.position, channel.id));
    out.extend(remaining);
    out
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use crate::acl::ACL;
    use crate::channels::Channel;
    use crate::client::client_session_identifier::ClientSessionIdentifier;
    use crate::client::group::ChannelHierarchy;
    use crate::messages::{Message, encoder};

    use super::{
        ChannelTreeShadow, SessionChannelShadow, channels_affected_by_home_channel_move,
        channels_with_home_channel_dependent_acls, ordered_snapshot_channels,
    };

    fn channel(id: u32, parent_id: Option<u32>, position: i32) -> Channel {
        Channel::new(id, format!("channel-{id}"), position, 100, parent_id)
    }

    fn home_acl(group: &str, apply_here: bool, apply_subs: bool) -> ACL {
        ACL {
            user_id: None,
            group: Some(group.to_owned()),
            apply_here,
            apply_subs,
            allow: enumflags2::BitFlags::empty(),
            deny: enumflags2::BitFlags::empty(),
        }
    }

    fn ids(channels: Vec<Channel>) -> Vec<u32> {
        channels.into_iter().map(|channel| channel.id).collect()
    }

    fn session(id: u32) -> ClientSessionIdentifier {
        ClientSessionIdentifier::new(1, id).expect("valid session")
    }

    fn channel_set(ids: &[u32]) -> HashSet<u32> {
        ids.iter().copied().collect()
    }

    fn ancestors_for_channel(
        channel_id: u32,
        by_id: &HashMap<u32, Channel>,
    ) -> Option<Vec<Channel>> {
        let mut ancestors = Vec::new();
        let mut current = by_id.get(&channel_id)?;
        while let Some(parent_id) = current.parent_id {
            let Some(parent) = by_id.get(&parent_id) else {
                break;
            };
            ancestors.push(parent.clone());
            current = parent;
        }
        Some(ancestors)
    }

    fn ancestor_ids_for_channel(
        channel_id: u32,
        by_id: &HashMap<u32, Channel>,
    ) -> Option<Vec<u32>> {
        ancestors_for_channel(channel_id, by_id)
            .map(|ancestors| ancestors.into_iter().map(|ancestor| ancestor.id).collect())
    }

    fn baseline_home_channel_dependent_ids(channels: &[Channel]) -> Vec<u32> {
        let by_id: HashMap<u32, Channel> = channels
            .iter()
            .map(|channel| (channel.id, channel.clone()))
            .collect();

        channels
            .iter()
            .filter(|channel| {
                let ancestors = ancestors_for_channel(channel.id, &by_id).unwrap_or_default();
                crate::acl::effective_acl_chain_has_home_channel_dependent_group(
                    channel, &ancestors,
                )
            })
            .map(|channel| channel.id)
            .collect()
    }

    fn baseline_home_channel_move_affected_ids(
        channels: &[Channel],
        old_channel_id: u32,
        new_channel_id: u32,
    ) -> Vec<u32> {
        let by_id: HashMap<u32, Channel> = channels
            .iter()
            .map(|channel| (channel.id, channel.clone()))
            .collect();
        let Some(old_ancestors) = ancestor_ids_for_channel(old_channel_id, &by_id) else {
            return baseline_home_channel_dependent_ids(channels);
        };
        let Some(new_ancestors) = ancestor_ids_for_channel(new_channel_id, &by_id) else {
            return baseline_home_channel_dependent_ids(channels);
        };

        channels
            .iter()
            .filter(|channel| {
                let ancestors = ancestors_for_channel(channel.id, &by_id).unwrap_or_default();
                crate::acl::effective_acl_chain_home_channel_match_changes(
                    channel,
                    &ancestors,
                    ChannelHierarchy::new(old_channel_id, &old_ancestors),
                    ChannelHierarchy::new(new_channel_id, &new_ancestors),
                )
            })
            .map(|channel| channel.id)
            .collect()
    }

    #[test]
    fn ordered_snapshot_channels_is_root_first_position_ordered_with_orphans_last() {
        let channels = vec![
            channel(7, Some(99), 0),
            channel(3, Some(0), 1),
            channel(0, None, 0),
            channel(2, Some(0), 0),
            channel(5, Some(2), 0),
            channel(4, Some(3), 0),
            channel(6, Some(99), -1),
        ];

        let ordered_ids = ordered_snapshot_channels(&channels)
            .into_iter()
            .map(|channel| channel.id)
            .collect::<Vec<_>>();

        assert_eq!(ordered_ids, vec![0, 2, 3, 5, 4, 6, 7]);
    }

    #[test]
    fn home_channel_dependent_acl_scan_matches_effective_chain_inheritance() {
        let mut root = channel(0, None, 0);
        root.acls = vec![home_acl("in", false, true)];
        let inherited_child = channel(1, Some(0), 0);
        let mut inheritance_break = channel(2, Some(0), 1);
        inheritance_break.inherit_acl = false;
        inheritance_break.acls = vec![home_acl("out", false, true)];
        let local_inherited_child = channel(3, Some(2), 0);
        let mut second_break = channel(4, Some(3), 0);
        second_break.inherit_acl = false;

        let channels = vec![
            root,
            inherited_child,
            inheritance_break,
            local_inherited_child,
            second_break,
        ];

        let optimized = ids(channels_with_home_channel_dependent_acls(channels.clone()));
        let baseline = baseline_home_channel_dependent_ids(&channels);

        assert_eq!(optimized, baseline);
        assert_eq!(optimized, vec![1, 3]);
    }

    #[test]
    fn home_channel_move_scan_matches_effective_chain_inheritance() {
        let root = channel(0, None, 0);
        let mut parent = channel(10, Some(0), 0);
        parent.acls = vec![home_acl("~sub", false, true)];
        let first_child = channel(11, Some(10), 0);
        let second_child = channel(12, Some(10), 1);
        let mut inheritance_break = channel(13, Some(10), 2);
        inheritance_break.inherit_acl = false;
        inheritance_break.acls = vec![home_acl("~sub", false, true)];
        let local_child = channel(14, Some(13), 0);

        let channels = vec![
            root,
            parent,
            first_child,
            second_child,
            inheritance_break,
            local_child,
        ];

        let optimized_parent_scope = ids(channels_affected_by_home_channel_move(
            channels.clone(),
            11,
            0,
        ));
        let baseline_parent_scope = baseline_home_channel_move_affected_ids(&channels, 11, 0);
        assert_eq!(optimized_parent_scope, baseline_parent_scope);
        assert_eq!(optimized_parent_scope, vec![11, 12]);

        let optimized_local_scope = ids(channels_affected_by_home_channel_move(
            channels.clone(),
            14,
            11,
        ));
        let baseline_local_scope = baseline_home_channel_move_affected_ids(&channels, 14, 11);
        assert_eq!(optimized_local_scope, baseline_local_scope);
        assert_eq!(optimized_local_scope, vec![14]);
    }

    #[test]
    fn session_channel_shadow_tracks_insert_overwrite_remove_and_clear() {
        let mut shadow = SessionChannelShadow::new();
        shadow.insert(session(10), 1);
        shadow.insert(session(11), 1);
        shadow.insert(session(12), 2);

        assert_eq!(
            shadow.sessions_in_channels(&channel_set(&[1])),
            vec![session(10), session(11)]
        );

        shadow.insert(session(10), 2);
        assert_eq!(shadow.get(&session(10)).copied(), Some(2));
        assert_eq!(
            shadow.sessions_in_channels(&channel_set(&[1])),
            vec![session(11)]
        );
        assert_eq!(
            shadow.sessions_in_channels(&channel_set(&[2])),
            vec![session(10), session(12)]
        );

        assert_eq!(shadow.remove(&session(12)), Some(2));
        assert_eq!(
            shadow.sessions_in_channels(&channel_set(&[2])),
            vec![session(10)]
        );

        shadow.clear();
        assert!(shadow.get(&session(10)).is_none());
        assert!(
            shadow
                .sessions_in_channels(&channel_set(&[1, 2]))
                .is_empty()
        );
    }

    #[test]
    fn session_channel_shadow_extend_and_bucket_union_are_indexed() {
        let mut base = SessionChannelShadow::new();
        base.insert(session(10), 1);
        base.insert(session(11), 2);

        let mut shadow = SessionChannelShadow::new();
        shadow.extend(base);
        shadow.extend([(session(12), 2), (session(13), 3)]);

        assert!(shadow.contains_key(&session(10)));
        assert_eq!(
            shadow.sessions_in_channels(&channel_set(&[2, 3])),
            vec![session(11), session(12), session(13)]
        );
        assert_eq!(
            shadow
                .iter()
                .map(|(session, _)| *session)
                .collect::<HashSet<_>>(),
            HashSet::from([session(10), session(11), session(12), session(13)])
        );
    }

    #[test]
    fn channel_tree_shadow_sync_message_tracks_channel_state_and_remove() {
        let mut shadow = ChannelTreeShadow::new();

        let create_7: Message = encoder::ChannelState {
            channel_id: Some(7),
            ..Default::default()
        }
        .into();
        let create_8: Message = encoder::ChannelState {
            channel_id: Some(8),
            ..Default::default()
        }
        .into();

        shadow.sync_message(&create_7);
        shadow.sync_message(&create_8);

        assert!(shadow.contains(&7));
        assert!(shadow.contains(&8));

        let remove_7: Message = encoder::ChannelRemove { channel_id: 7 }.into();
        shadow.sync_message(&remove_7);

        assert!(!shadow.contains(&7));
        assert!(shadow.contains(&8));
    }
}

/// Build a ChannelState encoder message, optionally with permission info.
/// Used during initial authentication and other contexts to send channel state.
pub async fn build_channel_state_message(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel: &crate::channels::Channel,
) -> ChannelState {
    build_channel_state_message_with_options(
        server,
        client,
        channel,
        server.get_send_permission_info(),
    )
    .await
}

pub async fn build_channel_state_message_without_permission_info(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel: &crate::channels::Channel,
) -> ChannelState {
    build_channel_state_message_with_options(server, client, channel, false).await
}

async fn build_channel_state_message_with_options(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel: &crate::channels::Channel,
    include_permission_info: bool,
) -> ChannelState {
    let links: Vec<u32> = channel.links.iter().copied().collect();
    let mut cs = ChannelState {
        channel_id: Some(channel.id),
        parent: channel.parent_id,
        name: Some(channel.name.clone()),
        links: links.clone(),
        description: None,
        links_add: Vec::new(),
        links_remove: Vec::new(),
        temporary: Some(channel.is_temporary()),
        position: Some(channel.position),
        description_hash: channel
            .description_hash
            .as_ref()
            .and_then(|h| hex::decode(h).ok().map(bytes::Bytes::from)),
        max_users: Some(channel.max_users),
        is_enter_restricted: None,
        can_enter: None,
    };

    // Add permission info if configured
    if include_permission_info {
        let (is_enter_restricted, perms) =
            permission_info_for_channel(server, client, channel.id).await;
        cs = cs.with_permission_info(is_enter_restricted, perms);
    }

    cs
}

/// Build permission-only `ChannelState` deltas for the current channel tree.
pub async fn build_channel_permission_info_refresh_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channels: &Arc<ChannelRepository>,
) -> Vec<Message> {
    if !server.get_send_permission_info() {
        return Vec::new();
    }

    let server_id = client.server_id();
    let channels = channels.get_all_in_server(&server_id).await;
    build_channel_permission_info_refresh_messages_for_channels(server, client, channels).await
}

pub async fn build_channel_permission_query_refresh_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channels: &Arc<ChannelRepository>,
) -> Vec<Message> {
    let server_id = client.server_id();
    let channel_ids = channels
        .get_all_in_server(&server_id)
        .await
        .into_iter()
        .map(|channel| channel.id)
        .collect();
    build_channel_permission_query_refresh_messages_for_channel_ids(
        server,
        client,
        channels,
        channel_ids,
    )
    .await
}

pub async fn build_channel_permission_info_refresh_messages_for_channel_ids(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channels: &Arc<ChannelRepository>,
    channel_ids: HashSet<u32>,
) -> Vec<Message> {
    if channel_ids.is_empty() || !server.get_send_permission_info() {
        return Vec::new();
    }

    let server_id = client.server_id();
    let channels = channels
        .get_all_in_server(&server_id)
        .await
        .into_iter()
        .filter(|channel| channel_ids.contains(&channel.id))
        .collect();
    build_channel_permission_info_refresh_messages_for_channels(server, client, channels).await
}

pub async fn build_channel_permission_query_refresh_messages_for_channel_ids(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channels: &Arc<ChannelRepository>,
    mut channel_ids: HashSet<u32>,
) -> Vec<Message> {
    if channel_ids.is_empty() {
        return Vec::new();
    }

    let server_id = client.server_id();
    let existing_channel_ids: HashSet<u32> = channels
        .get_all_in_server(&server_id)
        .await
        .into_iter()
        .map(|channel| channel.id)
        .collect();
    channel_ids.retain(|channel_id| existing_channel_ids.contains(channel_id));
    let mut channel_ids: Vec<_> = channel_ids.into_iter().collect();
    channel_ids.sort_unstable();

    let mut messages = Vec::with_capacity(channel_ids.len());
    for channel_id in channel_ids {
        let perms =
            crate::client::acl::compute_permissions_for_client(server, client, channel_id).await;
        messages.push(
            crate::messages::encoder::PermissionQuery {
                channel_id: Some(channel_id),
                permissions: Some(perms.bits()),
                flush: Some(false),
            }
            .into(),
        );
    }
    messages
}

/// Build permission-only `ChannelState` deltas for channels whose permissions
/// may depend on the viewer's current channel.
pub async fn build_home_channel_permission_info_refresh_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channels: &Arc<ChannelRepository>,
    old_channel_id: Option<u32>,
    new_channel_id: u32,
) -> Vec<Message> {
    let server_id = client.server_id();
    let all_channels = channels.get_all_in_server(&server_id).await;
    let channels = match old_channel_id {
        Some(old_channel_id) => {
            channels_affected_by_home_channel_move(all_channels, old_channel_id, new_channel_id)
        }
        None => channels_with_home_channel_dependent_acls(all_channels),
    };
    build_scoped_permission_info_refresh_messages_for_channels(server, client, channels).await
}

pub async fn home_channel_dependent_channel_ids(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    old_channel_id: Option<u32>,
    new_channel_id: u32,
) -> Vec<u32> {
    let server_id = client.server_id();
    let all_channels = server.get_channels().get_all_in_server(&server_id).await;
    let channels = match old_channel_id {
        Some(old_channel_id) => {
            channels_affected_by_home_channel_move(all_channels, old_channel_id, new_channel_id)
        }
        None => channels_with_home_channel_dependent_acls(all_channels),
    };
    channels.into_iter().map(|channel| channel.id).collect()
}

async fn build_channel_permission_info_refresh_messages_for_channels(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    mut channels: Vec<Channel>,
) -> Vec<Message> {
    channels.sort_by_key(|channel| (channel.parent_id.unwrap_or(0), channel.position, channel.id));

    let mut messages = Vec::with_capacity(channels.len());
    for channel in channels {
        let (is_enter_restricted, perms) =
            permission_info_for_channel(server, client, channel.id).await;
        messages.push(
            ChannelState {
                channel_id: Some(channel.id),
                ..Default::default()
            }
            .with_permission_info(is_enter_restricted, perms)
            .into(),
        );
    }
    messages
}

async fn build_scoped_permission_info_refresh_messages_for_channels(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    mut channels: Vec<Channel>,
) -> Vec<Message> {
    channels.sort_by_key(|channel| (channel.parent_id.unwrap_or(0), channel.position, channel.id));

    let send_permission_info = server.get_send_permission_info();
    let mut messages = Vec::with_capacity(channels.len() * 2);
    for channel in channels {
        let (is_enter_restricted, perms) =
            permission_info_for_channel(server, client, channel.id).await;
        messages.push(
            crate::messages::encoder::PermissionQuery {
                channel_id: Some(channel.id),
                permissions: Some(perms.bits()),
                flush: Some(false),
            }
            .into(),
        );
        if send_permission_info {
            messages.push(
                ChannelState {
                    channel_id: Some(channel.id),
                    ..Default::default()
                }
                .with_permission_info(is_enter_restricted, perms)
                .into(),
            );
        }
    }
    messages
}

fn channels_with_home_channel_dependent_acls(channels: Vec<Channel>) -> Vec<Channel> {
    let tree = ChannelTree::new(&channels);
    let affected = tree.home_channel_dependent_acl_channel_ids();

    channels
        .into_iter()
        .filter(|channel| affected.contains(&channel.id))
        .collect()
}

fn channels_affected_by_home_channel_move(
    channels: Vec<Channel>,
    old_channel_id: u32,
    new_channel_id: u32,
) -> Vec<Channel> {
    let tree = ChannelTree::new(&channels);
    let Some(old_ancestors) = tree.ancestor_ids_for_channel(old_channel_id) else {
        return channels_with_home_channel_dependent_acls(channels);
    };
    let Some(new_ancestors) = tree.ancestor_ids_for_channel(new_channel_id) else {
        return channels_with_home_channel_dependent_acls(channels);
    };
    let old_home = ChannelHierarchy::new(old_channel_id, &old_ancestors);
    let new_home = ChannelHierarchy::new(new_channel_id, &new_ancestors);
    let affected = tree.home_channel_move_affected_channel_ids(old_home, new_home);

    channels
        .into_iter()
        .filter(|channel| affected.contains(&channel.id))
        .collect()
}

struct ChannelTree<'a> {
    by_id: HashMap<u32, &'a Channel>,
    children_by_parent_id: HashMap<Option<u32>, Vec<u32>>,
}

struct HomeChannelAcl<'a> {
    group: &'a str,
    channel_id: u32,
    ancestor_ids: Vec<u32>,
}

impl HomeChannelAcl<'_> {
    fn match_changes(
        &self,
        evaluation_channel: ChannelHierarchy<'_>,
        old_home: ChannelHierarchy<'_>,
        new_home: ChannelHierarchy<'_>,
    ) -> bool {
        let acl_channel = ChannelHierarchy::new(self.channel_id, &self.ancestor_ids);
        group_match_changes(
            self.group,
            evaluation_channel,
            acl_channel,
            old_home,
            new_home,
        )
    }
}

#[derive(Clone, Copy)]
enum AclApplication {
    Here,
    Subs,
}

impl<'a> ChannelTree<'a> {
    fn new(channels: &'a [Channel]) -> Self {
        let by_id: HashMap<u32, &Channel> = channels
            .iter()
            .map(|channel| (channel.id, channel))
            .collect();
        let mut children_by_parent_id: HashMap<Option<u32>, Vec<u32>> = HashMap::new();
        for channel in channels {
            children_by_parent_id
                .entry(channel.parent_id)
                .or_default()
                .push(channel.id);
        }
        for child_ids in children_by_parent_id.values_mut() {
            child_ids.sort_by_key(|id| {
                by_id
                    .get(id)
                    .map(|channel| (channel.position, channel.id))
                    .unwrap_or((0, *id))
            });
        }

        Self {
            by_id,
            children_by_parent_id,
        }
    }

    fn ancestor_ids_for_channel(&self, channel_id: u32) -> Option<Vec<u32>> {
        self.ancestors_for_channel(channel_id)
            .map(|ancestors| ancestors.iter().map(|ancestor| ancestor.id).collect())
    }

    fn ancestors_for_channel(&self, channel_id: u32) -> Option<Vec<&'a Channel>> {
        let mut ancestors = Vec::new();
        let mut current = *self.by_id.get(&channel_id)?;
        while let Some(parent_id) = current.parent_id {
            let Some(parent) = self.by_id.get(&parent_id).copied() else {
                break;
            };
            ancestors.push(parent);
            current = parent;
        }
        Some(ancestors)
    }

    fn home_channel_dependent_acl_channel_ids(&self) -> HashSet<u32> {
        let mut affected = HashSet::new();
        for root_id in self.root_ids() {
            self.collect_home_channel_dependent_acl_channel_ids(root_id, false, &mut affected);
        }
        affected
    }

    fn collect_home_channel_dependent_acl_channel_ids(
        &self,
        channel_id: u32,
        inherited_home_channel_dependent_acl: bool,
        affected: &mut HashSet<u32>,
    ) {
        let Some(channel) = self.by_id.get(&channel_id).copied() else {
            return;
        };
        let inherited_home_channel_dependent_acl =
            channel.inherit_acl && inherited_home_channel_dependent_acl;
        let applies_here = inherited_home_channel_dependent_acl
            || has_home_channel_dependent_acl(channel, AclApplication::Here);
        let applies_to_subs = has_home_channel_dependent_acl(channel, AclApplication::Subs);

        if applies_here {
            affected.insert(channel_id);
        }

        let descendant_inherited = inherited_home_channel_dependent_acl || applies_to_subs;
        self.for_each_child(channel_id, |child_id| {
            self.collect_home_channel_dependent_acl_channel_ids(
                child_id,
                descendant_inherited,
                affected,
            );
        });
    }

    fn home_channel_move_affected_channel_ids(
        &self,
        old_home: ChannelHierarchy<'_>,
        new_home: ChannelHierarchy<'_>,
    ) -> HashSet<u32> {
        let mut affected = HashSet::new();
        let mut actual_ancestor_ids = Vec::new();
        let mut effective_ancestor_ids = Vec::new();
        let mut inherited_acls = Vec::new();
        for root_id in self.root_ids() {
            self.collect_home_channel_move_affected_channel_ids(
                root_id,
                &mut actual_ancestor_ids,
                &mut effective_ancestor_ids,
                &mut inherited_acls,
                0,
                0,
                old_home,
                new_home,
                &mut affected,
            );
        }
        affected
    }

    fn collect_home_channel_move_affected_channel_ids(
        &self,
        channel_id: u32,
        actual_ancestor_ids: &mut Vec<u32>,
        effective_ancestor_ids: &mut Vec<u32>,
        inherited_acls: &mut Vec<HomeChannelAcl<'a>>,
        active_effective_start: usize,
        active_acl_start: usize,
        old_home: ChannelHierarchy<'_>,
        new_home: ChannelHierarchy<'_>,
        affected: &mut HashSet<u32>,
    ) {
        let Some(channel) = self.by_id.get(&channel_id).copied() else {
            return;
        };
        let target_ancestor_ids: Vec<u32> = actual_ancestor_ids.iter().rev().copied().collect();
        let effective_start = if channel.inherit_acl {
            active_effective_start
        } else {
            effective_ancestor_ids.len()
        };
        let effective_acl_start = if channel.inherit_acl {
            active_acl_start
        } else {
            inherited_acls.len()
        };
        let acl_ancestor_ids: Vec<u32> = effective_ancestor_ids[effective_start..]
            .iter()
            .rev()
            .copied()
            .collect();
        let evaluation_channel = ChannelHierarchy::new(channel.id, &target_ancestor_ids);
        let local_acl_channel = ChannelHierarchy::new(channel.id, &acl_ancestor_ids);

        let inherited_changes = inherited_acls[effective_acl_start..]
            .iter()
            .any(|acl| acl.match_changes(evaluation_channel, old_home, new_home));
        let local_here_changes = home_channel_match_changes_in_acls(
            channel,
            evaluation_channel,
            local_acl_channel,
            AclApplication::Here,
            old_home,
            new_home,
        );

        if inherited_changes || local_here_changes {
            affected.insert(channel_id);
        }

        let inherited_len = inherited_acls.len();
        for acl in channel.acls.iter().filter(|acl| {
            acl.apply_subs
                && acl
                    .group
                    .as_deref()
                    .is_some_and(group_depends_on_home_channel)
        }) {
            inherited_acls.push(HomeChannelAcl {
                group: acl.group.as_deref().unwrap_or_default(),
                channel_id: channel.id,
                ancestor_ids: acl_ancestor_ids.clone(),
            });
        }

        actual_ancestor_ids.push(channel.id);
        effective_ancestor_ids.push(channel.id);
        self.for_each_child(channel_id, |child_id| {
            self.collect_home_channel_move_affected_channel_ids(
                child_id,
                actual_ancestor_ids,
                effective_ancestor_ids,
                inherited_acls,
                effective_start,
                effective_acl_start,
                old_home,
                new_home,
                affected,
            );
        });
        effective_ancestor_ids.pop();
        actual_ancestor_ids.pop();
        inherited_acls.truncate(inherited_len);
    }

    fn root_ids(&self) -> Vec<u32> {
        let mut roots: Vec<u32> = self
            .by_id
            .values()
            .filter(|channel| {
                channel
                    .parent_id
                    .is_none_or(|parent_id| !self.by_id.contains_key(&parent_id))
            })
            .map(|channel| channel.id)
            .collect();
        roots.sort_by_key(|id| {
            self.by_id
                .get(id)
                .map(|channel| (channel.parent_id.unwrap_or(0), channel.position, channel.id))
                .unwrap_or((0, 0, *id))
        });
        roots
    }

    fn for_each_child(&self, channel_id: u32, mut f: impl FnMut(u32)) {
        if let Some(child_ids) = self.children_by_parent_id.get(&Some(channel_id)) {
            for child_id in child_ids {
                f(*child_id);
            }
        }
    }
}

fn home_channel_match_changes_in_acls(
    channel: &Channel,
    evaluation_channel: ChannelHierarchy<'_>,
    acl_channel: ChannelHierarchy<'_>,
    application: AclApplication,
    old_home: ChannelHierarchy<'_>,
    new_home: ChannelHierarchy<'_>,
) -> bool {
    for acl in &channel.acls {
        if !acl_applies(acl, application) {
            continue;
        }

        let Some(group) = acl.group.as_deref() else {
            continue;
        };
        if !group_depends_on_home_channel(group) {
            continue;
        }

        if group_match_changes(group, evaluation_channel, acl_channel, old_home, new_home) {
            return true;
        }
    }

    false
}

fn has_home_channel_dependent_acl(channel: &Channel, application: AclApplication) -> bool {
    channel.acls.iter().any(|acl| {
        acl_applies(acl, application)
            && acl
                .group
                .as_deref()
                .is_some_and(group_depends_on_home_channel)
    })
}

fn acl_applies(acl: &crate::acl::ACL, application: AclApplication) -> bool {
    match application {
        AclApplication::Here => acl.apply_here,
        AclApplication::Subs => acl.apply_subs,
    }
}

fn group_match_changes(
    group: &str,
    evaluation_channel: ChannelHierarchy<'_>,
    acl_channel: ChannelHierarchy<'_>,
    old_home: ChannelHierarchy<'_>,
    new_home: ChannelHierarchy<'_>,
) -> bool {
    let old_query =
        ClientMembershipQuery::new(&[], true, &[], None, false, None).with_home_channel(old_home);
    let new_query =
        ClientMembershipQuery::new(&[], true, &[], None, false, None).with_home_channel(new_home);
    let old_match = is_member_in_group(
        group,
        evaluation_channel,
        Some(acl_channel),
        &[],
        &old_query,
    );
    let new_match = is_member_in_group(
        group,
        evaluation_channel,
        Some(acl_channel),
        &[],
        &new_query,
    );
    old_match != new_match
}
