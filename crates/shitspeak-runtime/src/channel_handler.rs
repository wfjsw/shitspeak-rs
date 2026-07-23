//! Channel message handling with ACL support.
//!
//! This module provides utilities for converting channel operations to protocol messages,
//! with optional permission info and ACL handling. Useful for authentication, gap replay,
//! subscription broadcasts, and future features like S2S replication and admin APIs.

use shitspeak_state::{
    ACLPermissions, Channel, ChannelHierarchy, ChannelOp, ChannelOperation, ChannelRepository,
    ClientMembershipQuery, group_depends_on_home_channel, is_member_in_group,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use crate::{
    client::{
        Client,
        client_session_identifier::ClientSessionIdentifier,
        state_log::{ClientStateLogEntry, ClientStateOperation},
        visibility::UserVisibilityState,
    },
    errors::WriteProtoMessageError,
    messages::{Message, encoder::ChannelState},
    server::Server,
};

type PackedSessionId = u32;

/// Permission values already sent to one socket.
///
/// Values are stored exactly as they appeared on the wire (including the
/// client-cache marker bit). Keeping this state socket-local lets ACL refresh
/// projection omit known-identical values without making a cold/unknown value
/// unsafe: unknown channels always emit their first refresh.
#[derive(Debug, Clone, Default)]
pub struct ChannelPermissionShadow {
    permissions_by_channel: HashMap<u32, u32>,
}

impl ChannelPermissionShadow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, channel_id: u32) -> Option<u32> {
        self.permissions_by_channel.get(&channel_id).copied()
    }

    pub fn contains_value(&self, channel_id: u32, permissions: u32) -> bool {
        self.get(channel_id) == Some(permissions)
    }

    pub fn clear(&mut self) {
        self.permissions_by_channel.clear();
    }

    pub fn remove(&mut self, channel_id: u32) -> Option<u32> {
        self.permissions_by_channel.remove(&channel_id)
    }

    /// Synchronize state from a message after it has survived visibility
    /// projection and is accepted into the socket's outbound sequence.
    pub fn sync_message(&mut self, message: &Message) {
        match message {
            Message::PermissionQuery(query) if query.flush == Some(true) => self.clear(),
            Message::PermissionQuery(query) => {
                if let (Some(channel_id), Some(permissions)) = (query.channel_id, query.permissions)
                {
                    self.permissions_by_channel.insert(channel_id, permissions);
                }
            }
            Message::ChannelRemove(remove) => {
                self.remove(remove.channel_id);
            }
            _ => {}
        }
    }

    pub fn sync_messages<'a>(&mut self, messages: impl IntoIterator<Item = &'a Message>) {
        for message in messages {
            self.sync_message(message);
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SessionChannelShadow {
    session_channel: HashMap<PackedSessionId, u32>,
    sessions_by_channel: HashMap<u32, HashSet<PackedSessionId>>,
}

fn unpack_session_entry(
    (session, channel): (PackedSessionId, u32),
) -> (ClientSessionIdentifier, u32) {
    (ClientSessionIdentifier::from(session), channel)
}

impl SessionChannelShadow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, session: ClientSessionIdentifier, channel_id: u32) -> Option<u32> {
        let packed_session = u32::from(session);
        let old_channel_id = self.session_channel.insert(packed_session, channel_id);
        if old_channel_id == Some(channel_id) {
            return old_channel_id;
        }
        if let Some(old_channel_id) = old_channel_id {
            self.remove_index_entry(packed_session, old_channel_id);
        }
        self.sessions_by_channel
            .entry(channel_id)
            .or_default()
            .insert(packed_session);
        old_channel_id
    }

    pub fn remove(&mut self, session: &ClientSessionIdentifier) -> Option<u32> {
        let packed_session = u32::from(*session);
        let old_channel_id = self.session_channel.remove(&packed_session)?;
        self.remove_index_entry(packed_session, old_channel_id);
        Some(old_channel_id)
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
        self.session_channel.get(&u32::from(*session))
    }

    pub fn contains_key(&self, session: &ClientSessionIdentifier) -> bool {
        self.session_channel.contains_key(&u32::from(*session))
    }

    pub fn iter(&self) -> impl Iterator<Item = (ClientSessionIdentifier, &u32)> {
        self.session_channel
            .iter()
            .map(|(session, channel)| (ClientSessionIdentifier::from(*session), channel))
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
        let mut sessions = sessions
            .into_iter()
            .map(ClientSessionIdentifier::from)
            .collect::<Vec<_>>();
        sessions.sort_by_key(|session| u32::from(*session));
        sessions
    }

    fn remove_index_entry(&mut self, session: PackedSessionId, channel_id: u32) {
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
    type IntoIter = std::iter::Map<
        std::collections::hash_map::IntoIter<PackedSessionId, u32>,
        fn((PackedSessionId, u32)) -> (ClientSessionIdentifier, u32),
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.session_channel.into_iter().map(unpack_session_entry)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ChannelTreeShadow {
    channel_ids: HashSet<u32>,
}

/// The channel-tree work shared by permission and visibility refreshes after
/// the viewing client moves.  Keeping the snapshot here prevents each path
/// from independently cloning and indexing the complete channel tree.
#[derive(Debug)]
pub(crate) struct HomeChannelMoveImpact {
    channels: Vec<Channel>,
    channel_indexes: HashMap<u32, usize>,
    new_channel_id: u32,
    permission_channel_ids: HashSet<u32>,
    visibility_channel_ids: HashSet<u32>,
}

impl HomeChannelMoveImpact {
    pub(crate) async fn calculate(
        server: &Arc<Box<Server>>,
        client: &Arc<Box<Client>>,
        old_channel_id: Option<u32>,
        new_channel_id: u32,
    ) -> Self {
        let server_id = client.server_id();
        let channels = server.get_channels().get_all_in_server(&server_id).await;
        Self::from_channels(channels, old_channel_id, new_channel_id)
    }

    fn from_channels(
        channels: Vec<Channel>,
        old_channel_id: Option<u32>,
        new_channel_id: u32,
    ) -> Self {
        let tree = ChannelTree::new(&channels);
        let permission_channel_ids = match old_channel_id {
            Some(old_channel_id) => tree.home_channel_move_affected_channel_ids_for_channel_ids(
                old_channel_id,
                new_channel_id,
            ),
            None => tree.home_channel_dependent_acl_channel_ids(),
        };
        let mut visibility_channel_ids = permission_channel_ids.clone();
        tree.expand_descendant_closure(&mut visibility_channel_ids);
        drop(tree);
        let channel_indexes = channels
            .iter()
            .enumerate()
            .map(|(index, channel)| (channel.id, index))
            .collect();

        Self {
            channels,
            channel_indexes,
            new_channel_id,
            permission_channel_ids,
            visibility_channel_ids,
        }
    }

    pub(crate) fn channels(&self) -> &[Channel] {
        &self.channels
    }

    pub(crate) fn permission_channel_ids(&self) -> &HashSet<u32> {
        &self.permission_channel_ids
    }

    pub(crate) fn new_channel_id(&self) -> u32 {
        self.new_channel_id
    }

    fn channel(&self, channel_id: u32) -> Option<&Channel> {
        self.channel_indexes
            .get(&channel_id)
            .map(|index| &self.channels[*index])
    }

    pub(crate) fn visibility_channel_ids(&self) -> &HashSet<u32> {
        &self.visibility_channel_ids
    }
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

    pub(crate) fn channel_ids(&self) -> &HashSet<u32> {
        &self.channel_ids
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

/// Returns a channel and its complete parent chain from an in-memory channel
/// snapshot. The result is used to retain the viewer's own placement even
/// when an ACL update removes Traverse from that channel.
pub(crate) fn channel_and_ancestor_ids(
    channels: &[shitspeak_state::Channel],
    channel_id: u32,
) -> HashSet<u32> {
    let by_id: HashMap<u32, &shitspeak_state::Channel> = channels
        .iter()
        .map(|channel| (channel.id, channel))
        .collect();
    let mut result = HashSet::new();
    let mut current_id = channel_id;
    while let Some(channel) = by_id.get(&current_id) {
        if !result.insert(current_id) {
            break;
        }
        let Some(parent_id) = channel.parent_id else {
            break;
        };
        current_id = parent_id;
    }
    result
}

/// Extends `channel_ids` with every descendant of an already-affected
/// channel. Building the parent-to-children index once keeps reparent and
/// home-channel refreshes linear in the channel tree rather than repeatedly
/// walking it per affected root.
pub(crate) fn expand_channel_ids_to_descendant_closure(
    channels: &[shitspeak_state::Channel],
    channel_ids: &mut HashSet<u32>,
) {
    if channel_ids.is_empty() {
        return;
    }

    let mut children_by_parent = HashMap::<u32, Vec<u32>>::new();
    for channel in channels {
        if let Some(parent_id) = channel.parent_id {
            children_by_parent
                .entry(parent_id)
                .or_default()
                .push(channel.id);
        }
    }

    let mut pending = channel_ids.iter().copied().collect::<VecDeque<_>>();
    while let Some(channel_id) = pending.pop_front() {
        let Some(children) = children_by_parent.get(&channel_id) else {
            continue;
        };
        for child_id in children {
            if channel_ids.insert(*child_id) {
                pending.push_back(*child_id);
            }
        }
    }
}

/// Orders a set of channel removals so descendants are removed before their
/// parents. A client treats a removed parent as a subtree removal, so numeric
/// ID ordering can otherwise make the socket-local tree diverge.
pub(crate) fn channel_removal_ids_descendant_first(
    channels: &[shitspeak_state::Channel],
    channel_ids: &HashSet<u32>,
) -> Vec<u32> {
    let present_ids = channels
        .iter()
        .map(|channel| channel.id)
        .collect::<HashSet<_>>();
    let mut ordered = ordered_snapshot_channels(channels)
        .into_iter()
        .map(|channel| channel.id)
        .filter(|channel_id| channel_ids.contains(channel_id))
        .collect::<Vec<_>>();
    ordered.reverse();

    let mut missing = channel_ids
        .iter()
        .filter(|channel_id| !present_ids.contains(channel_id))
        .copied()
        .collect::<Vec<_>>();
    missing.sort_unstable_by(|left, right| right.cmp(left));
    ordered.extend(missing);
    ordered
}

async fn viewer_current_channel_and_ancestor_ids(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
) -> HashSet<u32> {
    let server_id = client.server_id();
    let channels = server.get_channels();
    let mut result = HashSet::new();
    let mut current_id = client.get_current_channel_id();
    loop {
        if !result.insert(current_id) {
            break;
        }
        let Some(channel) = channels.get_channel_in_server(&server_id, current_id).await else {
            break;
        };
        let Some(parent_id) = channel.parent_id else {
            break;
        };
        current_id = parent_id;
    }
    result
}

pub async fn can_view_channel(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_id: u32,
) -> bool {
    if !server.get_hide_channels_without_traverse() {
        return true;
    }

    crate::client::acl::compute_permissions_for_client(server, client, channel_id)
        .await
        .contains(shitspeak_state::ACLPermissions::Traverse)
}

/// Returns whether a channel and every parent up to root are traversable.
/// ACL evaluation intentionally remains per-channel; the ancestor walk is
/// only performed for surfaces that emit a complete channel reference.
pub async fn can_view_channel_with_ancestors(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_id: u32,
) -> bool {
    if !server.get_hide_channels_without_traverse() {
        return true;
    }

    let channels = server.get_channels();
    let server_id = client.server_id();
    let mut current_id = channel_id;
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(current_id) || !can_view_channel(server, client, current_id).await {
            return false;
        }
        let Some(channel) = channels.get_channel_in_server(&server_id, current_id).await else {
            return current_id == 0;
        };
        let Some(parent_id) = channel.parent_id else {
            return true;
        };
        current_id = parent_id;
    }
}

pub(crate) async fn can_view_channel_with_ancestors_at_home(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_id: u32,
    home_channel_id: u32,
) -> bool {
    if !server.get_hide_channels_without_traverse() {
        return true;
    }

    let channels = server.get_channels();
    let server_id = client.server_id();
    let mut current_id = channel_id;
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(current_id)
            || !crate::client::acl::compute_permissions_for_client_with_home_channel(
                server,
                client,
                current_id,
                home_channel_id,
            )
            .await
            .contains(shitspeak_state::ACLPermissions::Traverse)
        {
            return false;
        }
        let Some(channel) = channels.get_channel_in_server(&server_id, current_id).await else {
            return current_id == 0;
        };
        let Some(parent_id) = channel.parent_id else {
            return true;
        };
        current_id = parent_id;
    }
}

async fn channel_is_visible_in_shadow(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_tree_shadow: &ChannelTreeShadow,
    channel_id: u32,
) -> bool {
    if !server.get_hide_channels_without_traverse() {
        return true;
    }

    let channels = server.get_channels();
    let server_id = client.server_id();
    let mut retained_channel_ids = None;
    let mut current_id = channel_id;
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(current_id) || !channel_tree_shadow.contains(&current_id) {
            return false;
        }
        if !can_view_channel(server, client, current_id).await {
            let retained = match retained_channel_ids.as_ref() {
                Some(retained) => retained,
                None => {
                    retained_channel_ids =
                        Some(viewer_current_channel_and_ancestor_ids(server, client).await);
                    retained_channel_ids
                        .as_ref()
                        .expect("retained viewer channel IDs were just set")
                }
            };
            // Only updates to the viewer's own current channel or an
            // ancestor of it may bypass Traverse. A sibling must still be
            // rejected when one of its ancestors is hidden.
            if !retained.contains(&channel_id) {
                return false;
            }
        }
        let Some(channel) = channels.get_channel_in_server(&server_id, current_id).await else {
            return current_id == 0;
        };
        let Some(parent_id) = channel.parent_id else {
            return true;
        };
        current_id = parent_id;
    }
}

async fn filter_visible_channel_links(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_tree_shadow: &ChannelTreeShadow,
    links: &mut Vec<u32>,
) {
    let mut visible_links = Vec::with_capacity(links.len());
    for linked_id in links.iter().copied() {
        if channel_is_visible_in_shadow(server, client, channel_tree_shadow, linked_id).await {
            visible_links.push(linked_id);
        }
    }
    *links = visible_links;
}

/// Builds a channel snapshot containing only the tree visible to this client.
/// The shadow records exactly the channel IDs emitted to the socket.
pub async fn build_visible_channel_snapshot_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    snapshot: &[Channel],
    channel_tree_shadow: &mut ChannelTreeShadow,
    include_permission_info: bool,
) -> Vec<Message> {
    channel_tree_shadow.clear();

    let mut visible_channel_ids = HashSet::with_capacity(snapshot.len());
    if server.get_hide_channels_without_traverse() {
        for (index, channel) in snapshot.iter().enumerate() {
            if index != 0 && index % 64 == 0 {
                tokio::task::yield_now().await;
            }
            if can_view_channel(server, client, channel.id).await {
                visible_channel_ids.insert(channel.id);
            }
        }
        visible_channel_ids.extend(channel_and_ancestor_ids(
            snapshot,
            client.get_current_channel_id(),
        ));
        close_visible_channel_ancestors(snapshot, &mut visible_channel_ids);
    } else {
        visible_channel_ids.extend(snapshot.iter().map(|channel| channel.id));
    }

    let mut messages = Vec::with_capacity(visible_channel_ids.len());
    for (index, channel) in ordered_snapshot_channels(snapshot).into_iter().enumerate() {
        if index != 0 && index % 64 == 0 {
            tokio::task::yield_now().await;
        }
        if !visible_channel_ids.contains(&channel.id) {
            continue;
        }
        let mut state = build_channel_state_message_with_options(
            server,
            client,
            &channel,
            include_permission_info,
            None,
        )
        .await;
        state
            .links
            .retain(|channel_id| visible_channel_ids.contains(channel_id));
        channel_tree_shadow.insert(channel.id);
        messages.push(state.into());
    }
    messages
}

/// Filters a channel-scoped message against the state already sent to a
/// socket. Newly visible channels are introduced by reconciliation with a
/// complete ChannelState, never by a partial operation delta.
pub async fn project_channel_message(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_tree_shadow: &ChannelTreeShadow,
    message: &Message,
) -> Vec<Message> {
    if !server.get_hide_channels_without_traverse() {
        return vec![message.clone()];
    }

    match message {
        Message::ChannelState(channel_state) => {
            let Some(channel_id) = channel_state.channel_id else {
                return Vec::new();
            };
            if !channel_is_visible_in_shadow(server, client, channel_tree_shadow, channel_id).await
            {
                return Vec::new();
            }

            let mut projected = channel_state.clone();
            filter_visible_channel_links(server, client, channel_tree_shadow, &mut projected.links)
                .await;
            filter_visible_channel_links(
                server,
                client,
                channel_tree_shadow,
                &mut projected.links_add,
            )
            .await;
            projected
                .links_remove
                .retain(|linked_id| channel_tree_shadow.contains(linked_id));
            vec![Message::ChannelState(projected)]
        }
        Message::ChannelRemove(channel_remove) => channel_tree_shadow
            .contains(&channel_remove.channel_id)
            .then(|| vec![message.clone()])
            .unwrap_or_default(),
        Message::PermissionQuery(permission_query) => match permission_query.channel_id {
            None => vec![message.clone()],
            Some(channel_id)
                if channel_is_visible_in_shadow(
                    server,
                    client,
                    channel_tree_shadow,
                    channel_id,
                )
                .await =>
            {
                vec![message.clone()]
            }
            Some(_) => Vec::new(),
        },
        _ => vec![message.clone()],
    }
}

pub async fn project_message_with_visibility_shadows(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    user_visibility: &mut crate::client::visibility::UserVisibilityState,
    session_channel_shadow: &mut SessionChannelShadow,
    server_id: &str,
    message: &Message,
) -> Vec<Message> {
    project_message_with_visibility_shadows_at_home(
        server,
        client,
        channel_tree_shadow,
        user_visibility,
        session_channel_shadow,
        server_id,
        message,
        None,
    )
    .await
}

async fn project_message_with_visibility_shadows_at_home(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    user_visibility: &mut crate::client::visibility::UserVisibilityState,
    session_channel_shadow: &mut SessionChannelShadow,
    server_id: &str,
    message: &Message,
    effective_home_channel_id: Option<u32>,
) -> Vec<Message> {
    let channel_projected =
        project_channel_message(server, client, channel_tree_shadow, message).await;
    let mut out = Vec::new();
    for message in channel_projected {
        let projected = crate::client::visibility::project_message_with_shadow_at_home(
            server,
            client,
            user_visibility,
            session_channel_shadow,
            server_id,
            &message,
            effective_home_channel_id,
        )
        .await;
        for message in projected {
            channel_tree_shadow.sync_message(&message);
            out.push(message);
        }
    }
    out
}

/// Remove every channel in a committed delete subtree from the socket-local
/// shadow. Mumble's wire message names only the deleted parent, while the
/// client removes its descendants implicitly.
pub fn remove_deleted_channels_from_shadow(
    channels: &Arc<ChannelRepository>,
    op: &ChannelOperation,
    channel_tree_shadow: &mut ChannelTreeShadow,
) {
    let Some(deleted_channel_ids) = channels.delete_visibility_hint_for_operation(op) else {
        return;
    };
    for channel_id in deleted_channel_ids.iter() {
        channel_tree_shadow.remove(channel_id);
    }
}

pub(crate) fn remove_deleted_channel_permissions_from_shadow(
    channels: &Arc<ChannelRepository>,
    op: &ChannelOperation,
    permission_shadow: &mut ChannelPermissionShadow,
) {
    let Some(deleted_channel_ids) = channels.delete_visibility_hint_for_operation(op) else {
        return;
    };
    for channel_id in deleted_channel_ids.iter() {
        permission_shadow.remove(*channel_id);
    }
}

/// Synchronize projected permission messages in projection order.
pub(crate) fn suppress_known_projected_permission_messages(
    messages: Vec<Message>,
    permission_shadow: &mut ChannelPermissionShadow,
) -> Vec<Message> {
    let mut out = Vec::with_capacity(messages.len());
    for message in messages {
        permission_shadow.sync_message(&message);
        out.push(message);
    }
    out
}

#[derive(Debug, Default)]
pub struct ChannelVisibilityRefresh {
    additions: Vec<Message>,
    addition_ids: Vec<u32>,
    removals: Vec<Message>,
    removal_ids: Vec<u32>,
}

pub struct ClientAclOperationContext {
    hint: Arc<shitspeak_state::AclChangeHint>,
    evaluation: Option<crate::client::acl::ClientAclEvaluationContext>,
    old_acl: crate::client::acl::ChannelAclOverride,
    new_permissions:
        parking_lot::Mutex<HashMap<u32, enumflags2::BitFlags<shitspeak_state::ACLPermissions>>>,
    old_permissions:
        parking_lot::Mutex<HashMap<u32, enumflags2::BitFlags<shitspeak_state::ACLPermissions>>>,
    new_restrictions: parking_lot::Mutex<HashMap<u32, bool>>,
    old_restrictions: parking_lot::Mutex<HashMap<u32, bool>>,
}

impl ClientAclOperationContext {
    pub async fn for_operation(
        server: &Arc<Box<Server>>,
        client: &Arc<Box<Client>>,
        channels: &Arc<ChannelRepository>,
        operation: &ChannelOperation,
    ) -> Option<Self> {
        Self::for_operation_with_permission_queries(server, client, channels, operation, true).await
    }

    pub async fn for_operation_with_permission_queries(
        server: &Arc<Box<Server>>,
        client: &Arc<Box<Client>>,
        channels: &Arc<ChannelRepository>,
        operation: &ChannelOperation,
        emit_permission_queries: bool,
    ) -> Option<Self> {
        let hint = channels.acl_change_hint_for_operation(operation)?;
        if !hint.impact().state_changed() {
            return None;
        }
        let impact = hint.impact();
        let matches_here = crate::client::acl::client_matches_acl_viewer_scope(
            client,
            impact.apply_here().viewer_scope(),
        );
        let matches_subs = crate::client::acl::client_matches_acl_viewer_scope(
            client,
            impact.apply_subs().viewer_scope(),
        );
        let restriction_refresh = server.get_send_permission_info()
            && (impact.apply_here().restriction_may_change()
                || impact.apply_subs().restriction_may_change());
        let permission_info_here = server.get_send_permission_info()
            && impact
                .apply_here()
                .effective_permissions()
                .contains(ACLPermissions::Enter);
        let permission_info_subs = server.get_send_permission_info()
            && impact
                .apply_subs()
                .effective_permissions()
                .contains(ACLPermissions::Enter);
        let visibility_here = impact
            .apply_here()
            .effective_permissions()
            .contains(ACLPermissions::Traverse);
        let visibility_subs = impact
            .apply_subs()
            .effective_permissions()
            .contains(ACLPermissions::Traverse);
        let needs_evaluation = restriction_refresh
            || (matches_here
                && (emit_permission_queries || permission_info_here || visibility_here))
            || (matches_subs
                && (emit_permission_queries || permission_info_subs || visibility_subs));
        let evaluation = if needs_evaluation {
            Some(
                crate::client::acl::ClientAclEvaluationContext::new(
                    server,
                    client,
                    hint.tree_snapshot(),
                    None,
                )
                .await,
            )
        } else {
            None
        };
        let old_acl = crate::client::acl::ChannelAclOverride::new(
            hint.channel_id(),
            hint.old_inherit_acl(),
            hint.old_acls().to_vec(),
        );
        Some(Self {
            hint,
            evaluation,
            old_acl,
            new_permissions: parking_lot::Mutex::new(HashMap::new()),
            old_permissions: parking_lot::Mutex::new(HashMap::new()),
            new_restrictions: parking_lot::Mutex::new(HashMap::new()),
            old_restrictions: parking_lot::Mutex::new(HashMap::new()),
        })
    }

    fn evaluate(&self, channel_id: u32) -> enumflags2::BitFlags<shitspeak_state::ACLPermissions> {
        if let Some(permissions) = self.new_permissions.lock().get(&channel_id).copied() {
            return permissions;
        }
        let permissions = self
            .evaluation
            .as_ref()
            .map(|evaluation| evaluation.evaluate(channel_id))
            .unwrap_or_default();
        self.new_permissions.lock().insert(channel_id, permissions);
        permissions
    }

    async fn precompute_background(
        &self,
        server: &Arc<Box<Server>>,
        channel_ids: impl IntoIterator<Item = u32>,
    ) {
        let Some(evaluation) = self.evaluation.clone() else {
            return;
        };
        let old_acl = self.old_acl.clone();
        let mut channel_ids = channel_ids.into_iter().collect::<HashSet<_>>();
        {
            let new_permissions = self.new_permissions.lock();
            let old_permissions = self.old_permissions.lock();
            let new_restrictions = self.new_restrictions.lock();
            let old_restrictions = self.old_restrictions.lock();
            channel_ids.retain(|channel_id| {
                !new_permissions.contains_key(channel_id)
                    || !old_permissions.contains_key(channel_id)
                    || !new_restrictions.contains_key(channel_id)
                    || !old_restrictions.contains_key(channel_id)
            });
        }
        if channel_ids.is_empty() {
            return;
        }
        let computed = server
            .run_acl_bulk_task(async move {
                channel_ids
                    .into_iter()
                    .map(|channel_id| {
                        (
                            channel_id,
                            evaluation.evaluate(channel_id),
                            evaluation.evaluate_with_acl_override(channel_id, &old_acl),
                            evaluation.is_enter_restricted(channel_id),
                            evaluation.is_enter_restricted_with_acl_override(channel_id, &old_acl),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .await;
        let computed = match computed {
            Ok(computed) => computed,
            Err(error) => {
                tracing::error!(%error, "background ACL precomputation failed");
                return;
            }
        };
        let mut new_permissions = self.new_permissions.lock();
        let mut old_permissions = self.old_permissions.lock();
        let mut new_restrictions = self.new_restrictions.lock();
        let mut old_restrictions = self.old_restrictions.lock();
        for (channel_id, new, old, new_restricted, old_restricted) in computed {
            new_permissions.insert(channel_id, new);
            old_permissions.insert(channel_id, old);
            new_restrictions.insert(channel_id, new_restricted);
            old_restrictions.insert(channel_id, old_restricted);
        }
    }

    fn evaluate_old(
        &self,
        channel_id: u32,
    ) -> enumflags2::BitFlags<shitspeak_state::ACLPermissions> {
        if let Some(permissions) = self.old_permissions.lock().get(&channel_id).copied() {
            return permissions;
        }
        let permissions = self
            .evaluation
            .as_ref()
            .map(|evaluation| evaluation.evaluate_with_acl_override(channel_id, &self.old_acl))
            .unwrap_or_default();
        self.old_permissions.lock().insert(channel_id, permissions);
        permissions
    }

    fn is_enter_restricted(&self, channel_id: u32) -> bool {
        if let Some(restricted) = self.new_restrictions.lock().get(&channel_id).copied() {
            return restricted;
        }
        let restricted = self
            .evaluation
            .as_ref()
            .is_some_and(|evaluation| evaluation.is_enter_restricted(channel_id));
        self.new_restrictions.lock().insert(channel_id, restricted);
        restricted
    }

    fn was_enter_restricted(&self, channel_id: u32) -> bool {
        if let Some(restricted) = self.old_restrictions.lock().get(&channel_id).copied() {
            return restricted;
        }
        let restricted = self.evaluation.as_ref().is_some_and(|evaluation| {
            evaluation.is_enter_restricted_with_acl_override(channel_id, &self.old_acl)
        });
        self.old_restrictions.lock().insert(channel_id, restricted);
        restricted
    }

    pub(crate) fn can_view_channel(&self, channel_id: u32) -> bool {
        self.evaluate(channel_id)
            .contains(shitspeak_state::ACLPermissions::Traverse)
    }

    pub(crate) fn can_view_channel_with_ancestors(&self, channel_id: u32) -> bool {
        if !self.can_view_channel(channel_id) {
            return false;
        }
        self.hint
            .tree_snapshot()
            .ancestor_ids(channel_id)
            .unwrap_or_default()
            .iter()
            .all(|ancestor_id| {
                self.evaluate(*ancestor_id)
                    .contains(shitspeak_state::ACLPermissions::Traverse)
            })
    }

    pub(crate) fn visible_listener_channels(
        &self,
        channel_ids: impl IntoIterator<Item = u32>,
        include_ancestors: bool,
    ) -> HashSet<u32> {
        channel_ids
            .into_iter()
            .filter(|channel_id| {
                if include_ancestors {
                    self.can_view_channel_with_ancestors(*channel_id)
                } else {
                    self.can_view_channel(*channel_id)
                }
            })
            .collect()
    }
}

impl ChannelVisibilityRefresh {
    pub fn is_empty(&self) -> bool {
        self.additions.is_empty() && self.removals.is_empty()
    }

    pub fn append_additions_to(&self, messages: &mut Vec<Message>) {
        messages.extend(self.additions.iter().cloned());
    }

    pub fn append_removals_to(&self, messages: &mut Vec<Message>) {
        messages.extend(self.removals.iter().cloned());
    }

    pub fn apply_additions(&self, channel_tree_shadow: &mut ChannelTreeShadow) {
        for channel_id in &self.addition_ids {
            channel_tree_shadow.insert(*channel_id);
        }
    }

    pub fn apply_removals(&self, channel_tree_shadow: &mut ChannelTreeShadow) {
        for channel_id in &self.removal_ids {
            channel_tree_shadow.remove(channel_id);
        }
    }

    pub(crate) fn apply_permission_removals(
        &self,
        permission_shadow: &mut ChannelPermissionShadow,
    ) {
        for channel_id in &self.removal_ids {
            permission_shadow.remove(*channel_id);
        }
    }
}

/// Computes visible channel additions/removals after an ACL-sensitive change.
/// ACL channel operations scope this to their affected subtree; only a change
/// to the viewing client's ACL inputs asks for the full tree.
pub async fn prepare_channel_visibility_refresh(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_tree_shadow: &ChannelTreeShadow,
    scope: &crate::client::visibility::VisibilityRefreshScope,
) -> ChannelVisibilityRefresh {
    prepare_channel_visibility_refresh_inner(server, client, channel_tree_shadow, scope, None, None)
        .await
}

pub async fn prepare_channel_visibility_refresh_with_acl_context(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_tree_shadow: &ChannelTreeShadow,
    scope: &crate::client::visibility::VisibilityRefreshScope,
    acl_context: Option<&ClientAclOperationContext>,
) -> ChannelVisibilityRefresh {
    prepare_channel_visibility_refresh_inner(
        server,
        client,
        channel_tree_shadow,
        scope,
        None,
        acl_context,
    )
    .await
}

pub(crate) async fn prepare_channel_visibility_refresh_for_home_move(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_tree_shadow: &ChannelTreeShadow,
    scope: &crate::client::visibility::VisibilityRefreshScope,
    impact: &HomeChannelMoveImpact,
) -> ChannelVisibilityRefresh {
    prepare_channel_visibility_refresh_inner(
        server,
        client,
        channel_tree_shadow,
        scope,
        Some(impact),
        None,
    )
    .await
}

async fn prepare_channel_visibility_refresh_inner(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_tree_shadow: &ChannelTreeShadow,
    scope: &crate::client::visibility::VisibilityRefreshScope,
    home_move_impact: Option<&HomeChannelMoveImpact>,
    acl_context: Option<&ClientAclOperationContext>,
) -> ChannelVisibilityRefresh {
    if !server.get_hide_channels_without_traverse()
        || (!scope.includes_all_channels() && scope.channel_ids().is_empty())
    {
        return ChannelVisibilityRefresh::default();
    }

    let server_id = client.server_id();
    let mut affected_channel_ids = scope.channel_ids().clone();
    let candidate_channels = if scope.includes_all_channels() {
        let channels = match home_move_impact {
            Some(impact) => impact.channels().to_vec(),
            None => server.get_channels().get_all_in_server(&server_id).await,
        };
        affected_channel_ids.extend(channel_tree_shadow.channel_ids().iter().copied());
        affected_channel_ids.extend(channels.iter().map(|channel| channel.id));
        channels
    } else if let Some(impact) = home_move_impact {
        let mut candidate_channels = HashMap::with_capacity(affected_channel_ids.len());
        let mut pending = affected_channel_ids.iter().copied().collect::<Vec<_>>();
        while let Some(channel_id) = pending.pop() {
            if let Some(channel) = impact.channel(channel_id)
                && candidate_channels
                    .insert(channel.id, channel.clone())
                    .is_none()
                && let Some(parent_id) = channel.parent_id
            {
                pending.push(parent_id);
                affected_channel_ids.insert(parent_id);
            }
        }
        candidate_channels.into_values().collect()
    } else if let Some(context) = acl_context {
        let snapshot = context.hint.tree_snapshot();
        let mut channels_by_id = HashMap::with_capacity(affected_channel_ids.len());
        let mut pending = affected_channel_ids.iter().copied().collect::<Vec<_>>();
        while let Some(channel_id) = pending.pop() {
            if let Some(channel) = snapshot.channel(channel_id)
                && channels_by_id.insert(channel.id, channel.clone()).is_none()
                && let Some(parent_id) = channel.parent_id
            {
                pending.push(parent_id);
                affected_channel_ids.insert(parent_id);
            }
        }
        channels_by_id.into_values().collect()
    } else {
        // Include each candidate's ancestors.  A directly traversable child
        // must not be introduced (or retained) when one of those ancestors
        // is hidden or absent from this socket's tree.
        let mut channels_by_id = HashMap::with_capacity(affected_channel_ids.len());
        let mut pending = affected_channel_ids.iter().copied().collect::<Vec<_>>();
        while let Some(channel_id) = pending.pop() {
            if let Some(channel) = server
                .get_channels()
                .get_channel_in_server(&server_id, channel_id)
                .await
            {
                if channels_by_id.insert(channel.id, channel.clone()).is_none() {
                    if let Some(parent_id) = channel.parent_id {
                        pending.push(parent_id);
                        affected_channel_ids.insert(parent_id);
                    }
                }
            }
        }
        channels_by_id.into_values().collect()
    };

    let mut visible_channel_ids = HashSet::with_capacity(candidate_channels.len());
    if let Some(context) = acl_context {
        let mut acl_channel_ids = candidate_channels
            .iter()
            .map(|channel| channel.id)
            .collect::<HashSet<_>>();
        for channel in &candidate_channels {
            if let Some(ancestor_ids) = context.hint.tree_snapshot().ancestor_ids(channel.id) {
                acl_channel_ids.extend(ancestor_ids.iter().copied());
            }
        }
        context.precompute_background(server, acl_channel_ids).await;
    }
    for channel in &candidate_channels {
        let visible = match (home_move_impact, acl_context) {
            (Some(impact), _) if server.get_hide_channels_without_traverse() => {
                crate::client::acl::compute_permissions_for_client_with_home_channel(
                    server,
                    client,
                    channel.id,
                    impact.new_channel_id(),
                )
                .await
                .contains(shitspeak_state::ACLPermissions::Traverse)
            }
            (None, Some(context)) => context
                .evaluate(channel.id)
                .contains(shitspeak_state::ACLPermissions::Traverse),
            _ => can_view_channel(server, client, channel.id).await,
        };
        if visible {
            visible_channel_ids.insert(channel.id);
        }
    }
    let effective_home_channel_id = home_move_impact
        .map(HomeChannelMoveImpact::new_channel_id)
        .unwrap_or_else(|| client.get_current_channel_id());
    visible_channel_ids.extend(channel_and_ancestor_ids(
        &candidate_channels,
        effective_home_channel_id,
    ));
    close_visible_channel_ancestors(&candidate_channels, &mut visible_channel_ids);

    let removed_channel_ids = channel_tree_shadow
        .channel_ids()
        .iter()
        .filter(|channel_id| {
            affected_channel_ids.contains(channel_id) && !visible_channel_ids.contains(channel_id)
        })
        .copied()
        .collect::<Vec<_>>();
    let removed_channel_id_set = removed_channel_ids.into_iter().collect::<HashSet<_>>();
    let removed_channel_ids =
        channel_removal_ids_descendant_first(&candidate_channels, &removed_channel_id_set);

    let mut final_visible_channel_ids = channel_tree_shadow.channel_ids().clone();
    for channel_id in &removed_channel_ids {
        final_visible_channel_ids.remove(channel_id);
    }
    final_visible_channel_ids.extend(visible_channel_ids.iter().copied());

    let mut additions = Vec::with_capacity(visible_channel_ids.len());
    let mut addition_ids = Vec::with_capacity(visible_channel_ids.len());
    for channel in ordered_snapshot_channels(&candidate_channels) {
        if !visible_channel_ids.contains(&channel.id) || channel_tree_shadow.contains(&channel.id) {
            continue;
        }
        let mut state = build_channel_state_message_with_options(
            server,
            client,
            &channel,
            server.get_send_permission_info() && acl_context.is_none(),
            home_move_impact.map(HomeChannelMoveImpact::new_channel_id),
        )
        .await;
        if server.get_send_permission_info()
            && let Some(context) = acl_context
        {
            state = state.with_permission_info(
                context.is_enter_restricted(channel.id),
                context.evaluate(channel.id),
            );
        }
        state
            .links
            .retain(|linked_id| final_visible_channel_ids.contains(linked_id));
        addition_ids.push(channel.id);
        additions.push(state.into());
        if let Some(context) = acl_context {
            additions.push(
                shitspeak_messages::messages::encoder::PermissionQuery::refresh_channel_permissions(
                    channel.id,
                    context.evaluate(channel.id).bits(),
                )
                .into(),
            );
        }
    }

    let removals = removed_channel_ids
        .iter()
        .copied()
        .map(|channel_id| shitspeak_messages::messages::encoder::ChannelRemove { channel_id }.into())
        .collect::<Vec<_>>();

    ChannelVisibilityRefresh {
        additions,
        addition_ids,
        removals,
        removal_ids: removed_channel_ids,
    }
}

/// Reconciles the visible channel tree in a single transition order. New
/// callers that also refresh users should use `prepare_channel_visibility_refresh`
/// so removals can be placed after the user/listener removals.
pub async fn reconcile_channel_visibility(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    scope: &crate::client::visibility::VisibilityRefreshScope,
) -> Vec<Message> {
    let refresh =
        prepare_channel_visibility_refresh(server, client, channel_tree_shadow, scope).await;
    refresh.apply_removals(channel_tree_shadow);
    refresh.apply_additions(channel_tree_shadow);
    let mut messages = Vec::with_capacity(
        refresh
            .removals
            .len()
            .saturating_add(refresh.additions.len()),
    );
    refresh.append_removals_to(&mut messages);
    refresh.append_additions_to(&mut messages);
    messages
}

fn viewer_acl_delta_for_entry<'a>(
    entry: &'a ClientStateLogEntry,
    viewer_session_id: ClientSessionIdentifier,
    viewer_client_instance_id: crate::client::ClientInstanceId,
) -> Option<&'a crate::client::state_log::ClientGlobalStateDelta> {
    match &entry.op {
        ClientStateOperation::UpdateGlobalState {
            session_id,
            client_instance_id,
            delta,
            ..
        } if *session_id == viewer_session_id
            && (*client_instance_id == 0 || *client_instance_id == viewer_client_instance_id) =>
        {
            Some(delta)
        }
        _ => None,
    }
}

async fn client_log_permission_refresh_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    delta: Option<&crate::client::state_log::ClientGlobalStateDelta>,
    home_move_impact: Option<&HomeChannelMoveImpact>,
) -> Vec<Message> {
    let refresh_all = delta.is_some_and(|delta| {
        delta.user_id.is_some()
            || delta.groups.is_some()
            || delta.is_superuser.is_some()
            || delta.tokens.is_some()
    });

    if let Some(impact) = home_move_impact {
        if !refresh_all {
            return build_home_channel_permission_info_refresh_messages_from_impact(
                server, client, impact,
            )
            .await;
        }

        let mut channels = impact.channels().to_vec();
        channels.sort_by_key(|channel| channel.id);
        let mut messages = Vec::with_capacity(channels.len() * 2);
        for channel in &channels {
            let permissions = crate::client::acl::compute_permissions_for_client_with_home_channel(
                server,
                client,
                channel.id,
                impact.new_channel_id(),
            )
            .await;
            messages.push(
                shitspeak_messages::messages::encoder::PermissionQuery::refresh_channel_permissions(
                    channel.id,
                    permissions.bits(),
                )
                .into(),
            );
        }
        if server.get_send_permission_info() {
            for channel in ordered_snapshot_channels(&channels) {
                let (is_enter_restricted, permissions) = permission_info_for_channel_with_home(
                    server,
                    client,
                    channel.id,
                    impact.new_channel_id(),
                )
                .await;
                messages.push(
                    ChannelState {
                        channel_id: Some(channel.id),
                        ..Default::default()
                    }
                    .with_permission_info(is_enter_restricted, permissions)
                    .into(),
                );
            }
        }
        return messages;
    }

    let mut messages =
        build_channel_permission_query_refresh_messages(server, client, server.get_channels())
            .await;
    if server.get_send_permission_info() {
        messages.extend(
            build_channel_permission_info_refresh_messages(server, client, server.get_channels())
                .await,
        );
    }
    messages
}

/// Projects one versioned client-state entry into a complete, ordered socket
/// transition. All transports use this path so newly referenced channel IDs
/// are defined before permission or user messages and stale temporary paths
/// are removed only after the move has been delivered.
pub async fn project_client_log_entry_transition(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    user_visibility: &mut UserVisibilityState,
    session_channel_shadow: &mut SessionChannelShadow,
    entry: &ClientStateLogEntry,
) -> Vec<Message> {
    project_client_log_entry_transition_inner(
        server,
        client,
        channel_tree_shadow,
        user_visibility,
        session_channel_shadow,
        entry,
        None,
        false,
    )
    .await
}

/// Payload-aware variant used by projection shards after they have obtained
/// the publication's shared canonical message.
pub(crate) async fn project_client_log_entry_transition_with_canonical(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    user_visibility: &mut UserVisibilityState,
    session_channel_shadow: &mut SessionChannelShadow,
    entry: &ClientStateLogEntry,
    canonical_message: Option<&Message>,
) -> Vec<Message> {
    project_client_log_entry_transition_inner(
        server,
        client,
        channel_tree_shadow,
        user_visibility,
        session_channel_shadow,
        entry,
        canonical_message,
        true,
    )
    .await
}

async fn project_client_log_entry_transition_inner(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    user_visibility: &mut UserVisibilityState,
    session_channel_shadow: &mut SessionChannelShadow,
    entry: &ClientStateLogEntry,
    canonical_message: Option<&Message>,
    use_canonical_message: bool,
) -> Vec<Message> {
    let viewer_session_id = client.get_session_id();
    let viewer_client_instance_id = client.client_instance_id();
    let old_viewer_channel_id = session_channel_shadow.get(&viewer_session_id).copied();
    let new_viewer_channel_id =
        entry.own_channel_change_for(viewer_session_id, viewer_client_instance_id);
    let home_move_impact = match new_viewer_channel_id {
        Some(new_channel_id) => Some(
            HomeChannelMoveImpact::calculate(server, client, old_viewer_channel_id, new_channel_id)
                .await,
        ),
        None => None,
    };
    let visibility_scope =
        crate::client::visibility::visibility_refresh_scope_for_client_log_entry_with_home_move_impact(
            server,
            client,
            entry,
            old_viewer_channel_id,
            home_move_impact.as_ref(),
        )
        .await;
    let channel_refresh = match home_move_impact.as_ref() {
        Some(impact) => {
            prepare_channel_visibility_refresh_for_home_move(
                server,
                client,
                channel_tree_shadow,
                &visibility_scope,
                impact,
            )
            .await
        }
        None => {
            prepare_channel_visibility_refresh(
                server,
                client,
                channel_tree_shadow,
                &visibility_scope,
            )
            .await
        }
    };

    let mut out = Vec::new();
    channel_refresh.apply_additions(channel_tree_shadow);
    channel_refresh.append_additions_to(&mut out);

    if let Some(destination_channel_id) = new_viewer_channel_id {
        out.extend(
            build_enter_permission_query_refresh_messages(server, client, destination_channel_id)
                .await
                .into_iter()
                .filter(|message| {
                    matches!(message, Message::PermissionQuery(query)
                    if query.channel_id.is_some_and(|channel_id| {
                        channel_tree_shadow.contains(&channel_id)
                    }))
                }),
        );
    }

    let viewer_acl_delta =
        viewer_acl_delta_for_entry(entry, viewer_session_id, viewer_client_instance_id);
    let server_id = client.server_id();
    let entry_messages = if use_canonical_message {
        entry
            .messages_for_client_with_canonical(
                server.get_clients(),
                viewer_session_id,
                viewer_client_instance_id,
                canonical_message,
            )
            .await
    } else {
        entry
            .messages_for_client(
                server.get_clients(),
                viewer_session_id,
                viewer_client_instance_id,
            )
            .await
    };
    for message in entry_messages {
        let is_permission_flush =
            matches!(&message, Message::PermissionQuery(query) if query.flush == Some(true));
        let messages = if is_permission_flush {
            client_log_permission_refresh_messages(
                server,
                client,
                viewer_acl_delta,
                home_move_impact.as_ref(),
            )
            .await
        } else {
            vec![message]
        };
        for message in messages {
            if is_permission_flush && home_move_impact.is_some() {
                let channel_id = match &message {
                    Message::PermissionQuery(query) => query.channel_id,
                    Message::ChannelState(state) => state.channel_id,
                    _ => None,
                };
                if channel_id.is_some_and(|channel_id| channel_tree_shadow.contains(&channel_id)) {
                    out.push(message);
                }
                continue;
            }
            out.extend(
                project_message_with_visibility_shadows_at_home(
                    server,
                    client,
                    channel_tree_shadow,
                    user_visibility,
                    session_channel_shadow,
                    &server_id,
                    &message,
                    new_viewer_channel_id,
                )
                .await,
            );
        }
    }

    let visibility_messages =
        crate::client::visibility::visibility_refresh_messages_with_shadow_at_home(
            server,
            client,
            user_visibility,
            session_channel_shadow,
            &server_id,
            visibility_scope,
            new_viewer_channel_id,
        )
        .await;
    for message in visibility_messages {
        channel_tree_shadow.sync_message(&message);
        out.push(message);
    }

    channel_refresh.apply_removals(channel_tree_shadow);
    channel_refresh.append_removals_to(&mut out);
    out
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
) -> (bool, enumflags2::BitFlags<shitspeak_state::ACLPermissions>) {
    let server_id = client.server_id();
    let (_, channel, ancestors) = server
        .get_channels()
        .get_channel_with_ancestors_for_acl_in_server(&server_id, channel_id)
        .await;
    let is_enter_restricted = channel.as_ref().is_some_and(|channel| {
        shitspeak_state::channel_has_effective_restriction(
            channel,
            &ancestors,
            shitspeak_state::ACLPermissions::Traverse,
        ) || shitspeak_state::channel_has_effective_restriction(
            channel,
            &ancestors,
            shitspeak_state::ACLPermissions::Enter,
        )
    });
    let perms =
        crate::client::acl::compute_permissions_for_client(server, client, channel_id).await;
    (is_enter_restricted, perms)
}

async fn permission_info_for_channel_with_home(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_id: u32,
    home_channel_id: u32,
) -> (bool, enumflags2::BitFlags<shitspeak_state::ACLPermissions>) {
    let server_id = client.server_id();
    let (_, channel, ancestors) = server
        .get_channels()
        .get_channel_with_ancestors_for_acl_in_server(&server_id, channel_id)
        .await;
    let is_enter_restricted = channel.as_ref().is_some_and(|channel| {
        shitspeak_state::channel_has_effective_restriction(
            channel,
            &ancestors,
            shitspeak_state::ACLPermissions::Traverse,
        ) || shitspeak_state::channel_has_effective_restriction(
            channel,
            &ancestors,
            shitspeak_state::ACLPermissions::Enter,
        )
    });
    let perms = crate::client::acl::compute_permissions_for_client_with_home_channel(
        server,
        client,
        channel_id,
        home_channel_id,
    )
    .await;
    (is_enter_restricted, perms)
}

/// Helper to add permission information to a ChannelState message.
/// Applied when `send_permission_info` is enabled.
pub async fn apply_permission_info_to_channel_state(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    cs_proto: &shitspeak_messages::messages::Message,
    channels: &Arc<ChannelRepository>,
) -> Option<shitspeak_messages::messages::Message> {
    if let shitspeak_messages::messages::Message::ChannelState(cs_proto) = cs_proto {
        if let Some(ch_id) = cs_proto.channel_id {
            let server_id = client.server_id();
            if channels
                .get_channel_in_server(&server_id, ch_id)
                .await
                .is_some()
            {
                let (is_enter_restricted, perms) =
                    permission_info_for_channel(server, client, ch_id).await;
                let encoder_cs: shitspeak_messages::messages::encoder::ChannelState = cs_proto.clone().into();
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
) -> Vec<shitspeak_messages::messages::Message> {
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
    session_channel_shadow: Option<&mut SessionChannelShadow>,
) -> Vec<shitspeak_messages::messages::Message> {
    convert_channel_operation_to_messages_with_shadows(
        server,
        client,
        op,
        channels,
        session_channel_shadow,
        None,
    )
    .await
}

pub(crate) async fn convert_channel_operation_to_messages_with_shadows(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    op: &ChannelOperation,
    channels: &Arc<ChannelRepository>,
    session_channel_shadow: Option<&mut SessionChannelShadow>,
    permission_shadow: Option<&ChannelPermissionShadow>,
) -> Vec<shitspeak_messages::messages::Message> {
    convert_channel_operation_to_messages_with_acl_context(
        server,
        client,
        op,
        channels,
        session_channel_shadow,
        permission_shadow,
        None,
    )
    .await
}

pub async fn convert_channel_operation_to_messages_with_acl_context(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    op: &ChannelOperation,
    channels: &Arc<ChannelRepository>,
    session_channel_shadow: Option<&mut SessionChannelShadow>,
    _permission_shadow: Option<&ChannelPermissionShadow>,
    acl_context: Option<&ClientAclOperationContext>,
) -> Vec<shitspeak_messages::messages::Message> {
    convert_channel_operation_to_messages_with_acl_context_options(
        server,
        client,
        op,
        channels,
        session_channel_shadow,
        acl_context,
        true,
    )
    .await
}

pub async fn convert_channel_operation_to_messages_with_acl_context_options(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    op: &ChannelOperation,
    channels: &Arc<ChannelRepository>,
    mut session_channel_shadow: Option<&mut SessionChannelShadow>,
    acl_context: Option<&ClientAclOperationContext>,
    emit_permission_queries: bool,
) -> Vec<shitspeak_messages::messages::Message> {
    let mut messages = Vec::new();
    let mut permission_info_messages = Vec::new();
    let send_permission_info = server.read_config().send_permission_info;
    let server_id = client.server_id();
    if op.server_id != server_id {
        return messages;
    }

    let include_permission_info =
        send_permission_info && !matches!(op.op, ChannelOp::InstallSnapshot { .. });
    let permission_refresh = if !emit_permission_queries && !include_permission_info {
        None
    } else if let Some(context) = acl_context {
        Some(
            build_precise_acl_permission_refresh_messages_from_context(
                server,
                client,
                context,
                include_permission_info,
            )
            .await,
        )
    } else if let Some(hint) = channels.acl_change_hint_for_operation(op) {
        Some(
            build_precise_acl_permission_refresh_messages(
                server,
                client,
                hint,
                include_permission_info,
            )
            .await,
        )
    } else if let Some(channel_ids) = channels
        .acl_affected_channel_ids_for_op(&server_id, &op.op)
        .await
    {
        Some(
            build_channel_permission_refresh_messages_for_channel_ids(
                server,
                client,
                channels,
                channel_ids,
                include_permission_info,
            )
            .await,
        )
    } else {
        None
    };
    if let Some((permission_queries, permission_info)) = permission_refresh {
        if emit_permission_queries {
            messages.extend(permission_queries);
        }
        permission_info_messages = permission_info;
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
                    shitspeak_messages::messages::encoder::ChannelRemove {
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

    messages.extend(permission_info_messages);

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
        .filter(|channel_id| {
            **channel_id == id
                || !channels_by_id.contains_key(*channel_id)
                || has_ancestor(&channels_by_id, **channel_id, id)
        })
        .copied()
        .collect()
}

fn has_ancestor(
    channels_by_id: &HashMap<u32, shitspeak_state::Channel>,
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
        shitspeak_messages::messages::encoder::UserState {
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
    replay_channel_log_gap_inner(
        server,
        client,
        channels,
        channel_tree_shadow,
        session_channel_shadow,
        user_visibility,
        session_id,
        last,
        current,
        None,
    )
    .await
}

pub(crate) async fn replay_channel_log_gap_with_permission_shadow(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channels: &Arc<ChannelRepository>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut crate::client::visibility::UserVisibilityState,
    permission_shadow: &mut ChannelPermissionShadow,
    session_id: crate::client::client_session_identifier::ClientSessionIdentifier,
    last: u64,
    current: u64,
) -> Result<(), ChannelReplayError> {
    replay_channel_log_gap_inner(
        server,
        client,
        channels,
        channel_tree_shadow,
        session_channel_shadow,
        user_visibility,
        session_id,
        last,
        current,
        Some(permission_shadow),
    )
    .await
}

async fn replay_channel_log_gap_inner(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channels: &Arc<ChannelRepository>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut crate::client::visibility::UserVisibilityState,
    session_id: crate::client::client_session_identifier::ClientSessionIdentifier,
    last: u64,
    current: u64,
    mut permission_shadow: Option<&mut ChannelPermissionShadow>,
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
            permission_shadow,
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
            permission_shadow,
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
        if matches!(&entry.op, ChannelOp::InstallSnapshot { .. })
            && let Some(shadow) = permission_shadow.as_deref_mut()
        {
            shadow.clear();
        }
        let acl_context =
            ClientAclOperationContext::for_operation(server, client, channels, entry).await;
        let refresh_scope =
            crate::client::visibility::visibility_refresh_scope_for_channel_operation_with_state_for_client(
                server,
                client,
                entry,
                user_visibility,
            )
            .await;
        let channel_refresh = prepare_channel_visibility_refresh_with_acl_context(
            server,
            client,
            channel_tree_shadow,
            &refresh_scope,
            acl_context.as_ref(),
        )
        .await;
        let messages = convert_channel_operation_to_messages_with_acl_context(
            server,
            client,
            entry,
            channels,
            Some(session_channel_shadow),
            permission_shadow.as_deref(),
            acl_context.as_ref(),
        )
        .await;
        let mut deferred_channel_removals = Vec::new();
        for msg in messages {
            if matches!(msg, Message::ChannelRemove(_)) {
                deferred_channel_removals.extend(
                    project_channel_message(server, client, channel_tree_shadow, &msg).await,
                );
                continue;
            }
            for projected in project_message_with_visibility_shadows(
                server,
                client,
                channel_tree_shadow,
                user_visibility,
                session_channel_shadow,
                &server_id,
                &msg,
            )
            .await
            {
                if matches!(&projected, Message::ChannelRemove(_)) {
                    deferred_channel_removals.push(projected);
                } else {
                    if let Some(shadow) = permission_shadow.as_deref_mut() {
                        shadow.sync_message(&projected);
                    }
                    outbound.push(projected);
                }
            }
        }
        channel_refresh.apply_additions(channel_tree_shadow);
        channel_refresh.append_additions_to(&mut outbound);
        let projected =
            crate::client::visibility::visibility_refresh_messages_with_shadow_and_acl_context(
                server,
                client,
                user_visibility,
                session_channel_shadow,
                &server_id,
                refresh_scope,
                acl_context.as_ref(),
            )
            .await;
        for msg in projected {
            channel_tree_shadow.sync_message(&msg);
            if let Some(shadow) = permission_shadow.as_deref_mut() {
                shadow.sync_message(&msg);
            }
            outbound.push(msg);
        }
        channel_refresh.apply_removals(channel_tree_shadow);
        if let Some(shadow) = permission_shadow.as_deref_mut() {
            channel_refresh.apply_permission_removals(shadow);
        }
        channel_refresh.append_removals_to(&mut outbound);
        for message in deferred_channel_removals {
            if let Message::ChannelRemove(channel_remove) = &message {
                if !channel_tree_shadow.contains(&channel_remove.channel_id) {
                    continue;
                }
            }
            channel_tree_shadow.sync_message(&message);
            if let Some(shadow) = permission_shadow.as_deref_mut() {
                shadow.sync_message(&message);
            }
            outbound.push(message);
        }
        remove_deleted_channels_from_shadow(channels, entry, channel_tree_shadow);
        if let Some(shadow) = permission_shadow.as_deref_mut() {
            remove_deleted_channel_permissions_from_shadow(channels, entry, shadow);
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
    mut permission_shadow: Option<&mut ChannelPermissionShadow>,
    server_id: &str,
    latest: u64,
) -> Result<(), ChannelReplayError> {
    if let Some(shadow) = permission_shadow.as_deref_mut() {
        shadow.clear();
    }
    let snapshot = channels.get_all_in_server(server_id).await;
    let previous = channel_tree_shadow.clone();
    let mut current = ChannelTreeShadow::new();
    let messages = build_visible_channel_snapshot_messages(
        server,
        client,
        &snapshot,
        &mut current,
        server.get_send_permission_info(),
    )
    .await;
    let removed_channel_ids = previous
        .difference(&current)
        .copied()
        .collect::<HashSet<_>>();
    let removed = channel_removal_ids_descendant_first(&snapshot, &removed_channel_ids);

    let mut outbound = Vec::with_capacity(messages.len() + removed.len());
    *channel_tree_shadow = current;
    outbound.extend(messages);

    let mut visibility_scope = crate::client::visibility::VisibilityRefreshScope::new();
    visibility_scope.include_all_channels();
    visibility_scope.include_known_users();
    let visibility_messages = crate::client::visibility::visibility_refresh_messages_with_shadow(
        server,
        client,
        user_visibility,
        session_channel_shadow,
        server_id,
        visibility_scope,
    )
    .await;
    if let Some(shadow) = permission_shadow.as_deref_mut() {
        shadow.sync_messages(visibility_messages.iter());
    }
    outbound.extend(visibility_messages);

    for channel_id in removed {
        let message = shitspeak_messages::messages::encoder::ChannelRemove { channel_id }.into();
        if let Some(shadow) = permission_shadow.as_deref_mut() {
            shadow.sync_message(&message);
        }
        outbound.push(message);
    }

    client
        .write_proto_message_batch(&outbound)
        .await
        .map_err(ChannelReplayError::ClientWriteFailed)?;

    client.set_last_channel_version(latest).await;
    Ok(())
}

pub fn ordered_snapshot_channels(
    channels: &[shitspeak_state::Channel],
) -> Vec<shitspeak_state::Channel> {
    let by_id: HashMap<u32, &shitspeak_state::Channel> = channels
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

/// A channel is only useful to a client when its complete parent chain is
/// present too.  ACLs may make a non-inheriting child traversable while its
/// parent is not, so close the direct visibility result over the channel tree
/// before emitting any ChannelState messages.
pub(crate) fn close_visible_channel_ancestors(
    channels: &[shitspeak_state::Channel],
    visible_channel_ids: &mut HashSet<u32>,
) {
    let by_id: HashMap<u32, &shitspeak_state::Channel> = channels
        .iter()
        .map(|channel| (channel.id, channel))
        .collect();
    let initially_visible = visible_channel_ids.clone();
    let mut hidden = Vec::new();

    for channel_id in initially_visible {
        let mut current_id = channel_id;
        let mut visited = HashSet::new();
        let mut closed = true;
        loop {
            if !visited.insert(current_id) || !visible_channel_ids.contains(&current_id) {
                closed = false;
                break;
            }
            let Some(channel) = by_id.get(&current_id) else {
                closed = false;
                break;
            };
            let Some(parent_id) = channel.parent_id else {
                break;
            };
            current_id = parent_id;
        }
        if !closed {
            hidden.push(channel_id);
        }
    }

    for channel_id in hidden {
        visible_channel_ids.remove(&channel_id);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use crate::client::client_session_identifier::ClientSessionIdentifier;
    use shitspeak_messages::messages::{Message, encoder};
    use shitspeak_state::{ACL, ACLPermissions, Channel, ChannelHierarchy};

    use super::{
        ChannelPermissionShadow, ChannelTreeShadow, HomeChannelMoveImpact, SessionChannelShadow,
        channel_and_ancestor_ids, channel_removal_ids_descendant_first,
        channels_affected_by_home_channel_move, channels_with_home_channel_dependent_acls,
        close_visible_channel_ancestors, expand_channel_ids_to_descendant_closure,
        ordered_snapshot_channels, suppress_known_projected_permission_messages,
    };

    #[test]
    fn permission_shadow_tracks_projected_values_without_suppressing_messages() {
        let first: Message = encoder::PermissionQuery::refresh_channel_permissions(7, 0x10).into();
        let same = first.clone();
        let changed: Message =
            encoder::PermissionQuery::refresh_channel_permissions(7, 0x20).into();
        let mut shadow = ChannelPermissionShadow::new();

        let projected = suppress_known_projected_permission_messages(
            vec![first.clone(), same, changed.clone()],
            &mut shadow,
        );

        assert_eq!(projected.len(), 3);
        assert!(matches!(&projected[0], Message::PermissionQuery(query)
            if query.permissions == match &first { Message::PermissionQuery(query) => query.permissions, _ => None }));
        assert!(matches!(&projected[2], Message::PermissionQuery(query)
            if query.permissions == match &changed { Message::PermissionQuery(query) => query.permissions, _ => None }));
        let expected = match changed {
            Message::PermissionQuery(query) => query.permissions.expect("permission value"),
            _ => unreachable!(),
        };
        assert_eq!(shadow.get(7), Some(expected));
    }

    #[test]
    fn permission_shadow_flush_and_channel_remove_forget_values() {
        let query: Message = encoder::PermissionQuery::refresh_channel_permissions(9, 0x40).into();
        let flush: Message = encoder::PermissionQuery::flush_cache().into();
        let remove: Message = encoder::ChannelRemove { channel_id: 9 }.into();
        let mut shadow = ChannelPermissionShadow::new();

        shadow.sync_message(&query);
        assert!(shadow.get(9).is_some());
        shadow.sync_message(&remove);
        assert_eq!(shadow.get(9), None);

        shadow.sync_message(&query);
        let projected =
            suppress_known_projected_permission_messages(vec![flush, query.clone()], &mut shadow);
        assert_eq!(projected.len(), 2, "flush makes the following value cold");
        assert!(shadow.get(9).is_some());
    }

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
                shitspeak_state::effective_acl_chain_has_home_channel_dependent_group(
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
                shitspeak_state::effective_acl_chain_home_channel_match_changes(
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
    fn visible_channel_ids_are_closed_over_ancestors() {
        let channels = vec![
            channel(0, None, 0),
            channel(1, Some(0), 0),
            channel(2, Some(1), 0),
            channel(3, Some(99), 0),
        ];
        let mut visible = HashSet::from([0, 2, 3]);

        close_visible_channel_ancestors(&channels, &mut visible);

        assert_eq!(visible, HashSet::from([0]));
    }

    #[test]
    fn visible_channel_ids_keep_children_when_the_full_chain_is_visible() {
        let channels = vec![
            channel(0, None, 0),
            channel(1, Some(0), 0),
            channel(2, Some(1), 0),
        ];
        let mut visible = HashSet::from([0, 1, 2]);

        close_visible_channel_ancestors(&channels, &mut visible);

        assert_eq!(visible, HashSet::from([0, 1, 2]));
    }

    #[test]
    fn viewer_channel_path_includes_the_current_channel_and_every_ancestor() {
        let channels = vec![
            channel(0, None, 0),
            channel(40, Some(0), 0),
            channel(7, Some(40), 0),
            channel(99, Some(0), 1),
        ];

        assert_eq!(
            channel_and_ancestor_ids(&channels, 7),
            HashSet::from([0, 7, 40])
        );
    }

    #[test]
    fn descendant_closure_expands_each_affected_root_once() {
        let channels = vec![
            channel(0, None, 0),
            channel(100, Some(0), 0),
            channel(2, Some(100), 0),
            channel(3, Some(2), 0),
            channel(50, Some(0), 1),
            channel(51, Some(50), 0),
            channel(99, Some(0), 2),
        ];
        let mut affected = HashSet::from([100, 50]);

        expand_channel_ids_to_descendant_closure(&channels, &mut affected);

        assert_eq!(affected, HashSet::from([100, 2, 3, 50, 51]));
    }

    #[test]
    fn channel_removals_are_descendant_first_even_when_ids_are_not() {
        let channels = vec![
            channel(0, None, 0),
            channel(100, Some(0), 0),
            channel(2, Some(100), 0),
            channel(1, Some(2), 0),
            channel(50, Some(0), 1),
        ];
        let removed = HashSet::from([100, 2, 1]);

        assert_eq!(
            channel_removal_ids_descendant_first(&channels, &removed),
            vec![1, 2, 100]
        );
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
    fn home_channel_dependent_parent_path_gate_includes_descendants() {
        let root = channel(0, None, 0);
        let mut parent = channel(10, Some(0), 0);
        let mut parent_acl = home_acl("in", true, false);
        parent_acl.deny = ACLPermissions::Traverse.into();
        parent.acls = vec![parent_acl];
        let mut child = channel(11, Some(10), 0);
        child.inherit_acl = false;
        let channels = vec![root, parent, child];

        let optimized = ids(channels_with_home_channel_dependent_acls(channels.clone()));
        let baseline = baseline_home_channel_dependent_ids(&channels);
        assert_eq!(optimized, baseline);
        assert_eq!(optimized, vec![10, 11]);

        let optimized_move = ids(channels_affected_by_home_channel_move(
            channels.clone(),
            10,
            0,
        ));
        let baseline_move = baseline_home_channel_move_affected_ids(&channels, 10, 0);
        assert_eq!(optimized_move, baseline_move);
        assert_eq!(optimized_move, vec![10, 11]);
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
    fn home_channel_move_impact_reuses_snapshot_for_permission_and_visibility_scopes() {
        let root = channel(0, None, 0);
        let mut parent = channel(10, Some(0), 0);
        parent.acls = vec![home_acl("~sub", true, false)];
        let home = channel(11, Some(10), 0);
        let child = channel(12, Some(10), 1);
        let grandchild = channel(13, Some(12), 0);

        let impact = HomeChannelMoveImpact::from_channels(
            vec![root, parent, home, child, grandchild],
            Some(11),
            0,
        );

        assert_eq!(impact.channels().len(), 5);
        assert_eq!(impact.permission_channel_ids(), &HashSet::from([10]));
        assert_eq!(
            impact.visibility_channel_ids(),
            &HashSet::from([10, 11, 12, 13])
        );
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
    fn session_channel_shadow_extend_and_bucket_union() {
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
                .map(|(session, _)| session)
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
    channel: &shitspeak_state::Channel,
) -> ChannelState {
    build_channel_state_message_with_options(
        server,
        client,
        channel,
        server.get_send_permission_info(),
        None,
    )
    .await
}

pub async fn build_channel_state_message_without_permission_info(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel: &shitspeak_state::Channel,
) -> ChannelState {
    build_channel_state_message_with_options(server, client, channel, false, None).await
}

async fn build_channel_state_message_with_options(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel: &shitspeak_state::Channel,
    include_permission_info: bool,
    effective_home_channel_id: Option<u32>,
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
        let (is_enter_restricted, perms) = match effective_home_channel_id {
            Some(home_channel_id) => {
                permission_info_for_channel_with_home(server, client, channel.id, home_channel_id)
                    .await
            }
            None => permission_info_for_channel(server, client, channel.id).await,
        };
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

async fn build_precise_acl_permission_refresh_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    hint: Arc<shitspeak_state::AclChangeHint>,
    include_permission_info: bool,
) -> (Vec<Message>, Vec<Message>) {
    if !hint.impact().state_changed() {
        return (Vec::new(), Vec::new());
    }
    let evaluation = crate::client::acl::ClientAclEvaluationContext::new(
        server,
        client,
        hint.tree_snapshot(),
        None,
    )
    .await;
    let old_acl = crate::client::acl::ChannelAclOverride::new(
        hint.channel_id(),
        hint.old_inherit_acl(),
        hint.old_acls().to_vec(),
    );
    let context = ClientAclOperationContext {
        hint,
        evaluation: Some(evaluation),
        old_acl,
        new_permissions: parking_lot::Mutex::new(HashMap::new()),
        old_permissions: parking_lot::Mutex::new(HashMap::new()),
        new_restrictions: parking_lot::Mutex::new(HashMap::new()),
        old_restrictions: parking_lot::Mutex::new(HashMap::new()),
    };
    build_precise_acl_permission_refresh_messages_from_context(
        server,
        client,
        &context,
        include_permission_info,
    )
    .await
}

async fn build_precise_acl_permission_refresh_messages_from_context(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    context: &ClientAclOperationContext,
    include_permission_info: bool,
) -> (Vec<Message>, Vec<Message>) {
    let hint = &context.hint;
    let impact = hint.impact();
    if !impact.state_changed() {
        return (Vec::new(), Vec::new());
    }

    let here_matches = !impact.apply_here().effective_permissions().is_empty()
        && crate::client::acl::client_matches_acl_viewer_scope(
            client,
            impact.apply_here().viewer_scope(),
        );
    let subs_matches = !impact.apply_subs().effective_permissions().is_empty()
        && crate::client::acl::client_matches_acl_viewer_scope(
            client,
            impact.apply_subs().viewer_scope(),
        );
    let here_changes_structural_descendants = impact
        .apply_here()
        .effective_permissions()
        .contains(shitspeak_state::ACLPermissions::Traverse);
    let mut permission_query_ids = HashSet::new();
    let mut restriction_ids = HashSet::new();
    for channel_id in hint.affected_channel_ids().iter().copied() {
        let is_here = channel_id == hint.channel_id();
        if (is_here && here_matches)
            || (!is_here && (subs_matches || (here_changes_structural_descendants && here_matches)))
        {
            permission_query_ids.insert(channel_id);
        }
        let restriction_may_change = if is_here {
            impact.apply_here().restriction_may_change()
        } else {
            impact.apply_subs().restriction_may_change()
        };
        if restriction_may_change {
            // is_enter_restricted is channel metadata shared by all viewers,
            // even when the ACL permission itself targets one user/group.
            restriction_ids.insert(channel_id);
        }
    }
    if permission_query_ids.is_empty() && (!include_permission_info || restriction_ids.is_empty()) {
        return (Vec::new(), Vec::new());
    }

    let snapshot = hint.tree_snapshot();
    let mut channel_ids = permission_query_ids
        .union(&restriction_ids)
        .copied()
        .collect::<Vec<_>>();
    channel_ids.sort_unstable();

    context
        .precompute_background(server, channel_ids.iter().copied())
        .await;

    let mut permission_queries = Vec::new();
    let mut permission_info = Vec::new();
    for channel_id in channel_ids {
        let new_permissions = context.evaluate(channel_id);
        let old_permissions = context.evaluate_old(channel_id);
        let permission_changed = new_permissions != old_permissions;
        if permission_changed && permission_query_ids.contains(&channel_id) {
            permission_queries.push(
                shitspeak_messages::messages::encoder::PermissionQuery::refresh_channel_permissions(
                    channel_id,
                    new_permissions.bits(),
                )
                .into(),
            );
        }

        if include_permission_info {
            let new_restricted = context.is_enter_restricted(channel_id);
            let restriction_changed = restriction_ids.contains(&channel_id)
                && new_restricted != context.was_enter_restricted(channel_id);
            let enter_changed = new_permissions.contains(ACLPermissions::Enter)
                != old_permissions.contains(ACLPermissions::Enter);
            if (enter_changed && permission_query_ids.contains(&channel_id)) || restriction_changed
            {
                let Some(channel) = snapshot.channel(channel_id).cloned() else {
                    continue;
                };
                permission_info.push((channel, new_restricted, new_permissions));
            }
        }
    }

    permission_info.sort_by_key(|(channel, _, _)| {
        (channel.parent_id.unwrap_or(0), channel.position, channel.id)
    });
    let permission_info = permission_info
        .into_iter()
        .map(|(channel, is_enter_restricted, permissions)| {
            ChannelState {
                channel_id: Some(channel.id),
                ..Default::default()
            }
            .with_permission_info(is_enter_restricted, permissions)
            .into()
        })
        .collect();
    (permission_queries, permission_info)
}

/// Build the two ACL refresh message families from one permission evaluation
/// per affected channel. PermissionQuery messages retain channel-id ordering,
/// while optional ChannelState permission deltas retain channel-tree ordering.
async fn build_channel_permission_refresh_messages_for_channel_ids(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channels: &Arc<ChannelRepository>,
    channel_ids: HashSet<u32>,
    include_permission_info: bool,
) -> (Vec<Message>, Vec<Message>) {
    if channel_ids.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let server_id = client.server_id();
    let mut affected_channels = channels
        .get_all_in_server(&server_id)
        .await
        .into_iter()
        .filter(|channel| channel_ids.contains(&channel.id))
        .collect::<Vec<_>>();
    affected_channels.sort_by_key(|channel| channel.id);

    let mut permission_queries = Vec::with_capacity(affected_channels.len());
    let mut permission_info = Vec::with_capacity(affected_channels.len());
    for channel in affected_channels {
        let (is_enter_restricted, permissions) = if include_permission_info {
            permission_info_for_channel(server, client, channel.id).await
        } else {
            (
                false,
                crate::client::acl::compute_permissions_for_client(server, client, channel.id)
                    .await,
            )
        };
        permission_queries.push(
            shitspeak_messages::messages::encoder::PermissionQuery::refresh_channel_permissions(
                channel.id,
                permissions.bits(),
            )
            .into(),
        );
        if include_permission_info {
            permission_info.push((channel, is_enter_restricted, permissions));
        }
    }

    permission_info.sort_by_key(|(channel, _, _)| {
        (channel.parent_id.unwrap_or(0), channel.position, channel.id)
    });
    let permission_info = permission_info
        .into_iter()
        .map(|(channel, is_enter_restricted, permissions)| {
            ChannelState {
                channel_id: Some(channel.id),
                ..Default::default()
            }
            .with_permission_info(is_enter_restricted, permissions)
            .into()
        })
        .collect();

    (permission_queries, permission_info)
}

pub async fn build_channel_permission_query_refresh_messages_for_channel_ids(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channels: &Arc<ChannelRepository>,
    channel_ids: HashSet<u32>,
) -> Vec<Message> {
    build_channel_permission_refresh_messages_for_channel_ids(
        server,
        client,
        channels,
        channel_ids,
        false,
    )
    .await
    .0
}

/// Builds the destination and immediate-parent permission refreshes emitted
/// for a viewer's own channel transition. Permissions are evaluated against
/// the entry's destination home so lagged/replayed moves do not observe a
/// newer live home channel.
pub async fn build_enter_permission_query_refresh_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    destination_channel_id: u32,
) -> Vec<Message> {
    let server_id = client.server_id();
    let parent_id = server
        .get_channels()
        .get_channel_in_server(&server_id, destination_channel_id)
        .await
        .and_then(|channel| channel.parent_id);

    let mut channel_ids = vec![destination_channel_id];
    if let Some(parent_id) = parent_id {
        channel_ids.push(parent_id);
    }

    let mut messages = Vec::with_capacity(channel_ids.len());
    for channel_id in channel_ids {
        let permissions = crate::client::acl::compute_permissions_for_client_with_home_channel(
            server,
            client,
            channel_id,
            destination_channel_id,
        )
        .await;
        messages.push(
            shitspeak_messages::messages::encoder::PermissionQuery::refresh_channel_permissions(
                channel_id,
                permissions.bits(),
            )
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
    let impact = HomeChannelMoveImpact::from_channels(all_channels, old_channel_id, new_channel_id);
    build_home_channel_permission_info_refresh_messages_from_impact(server, client, &impact).await
}

pub(crate) async fn build_home_channel_permission_info_refresh_messages_from_impact(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    impact: &HomeChannelMoveImpact,
) -> Vec<Message> {
    let channels = impact
        .permission_channel_ids()
        .iter()
        .filter_map(|channel_id| impact.channel(*channel_id).cloned())
        .collect();
    build_scoped_permission_info_refresh_messages_for_channels(
        server,
        client,
        channels,
        impact.new_channel_id(),
    )
    .await
}

pub async fn home_channel_dependent_channel_ids(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    old_channel_id: Option<u32>,
    new_channel_id: u32,
) -> Vec<u32> {
    HomeChannelMoveImpact::calculate(server, client, old_channel_id, new_channel_id)
        .await
        .visibility_channel_ids()
        .iter()
        .copied()
        .collect()
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
    home_channel_id: u32,
) -> Vec<Message> {
    channels.sort_by_key(|channel| (channel.parent_id.unwrap_or(0), channel.position, channel.id));

    let send_permission_info = server.get_send_permission_info();
    let mut messages = Vec::with_capacity(channels.len() * 2);
    for channel in channels {
        let (is_enter_restricted, perms) =
            permission_info_for_channel_with_home(server, client, channel.id, home_channel_id)
                .await;
        messages.push(
            shitspeak_messages::messages::encoder::PermissionQuery::refresh_channel_permissions(
                channel.id,
                perms.bits(),
            )
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
    let affected = ChannelTree::new(&channels).home_channel_dependent_acl_channel_ids();

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
    let affected = {
        let tree = ChannelTree::new(&channels);
        tree.home_channel_move_affected_channel_ids_for_channel_ids(old_channel_id, new_channel_id)
    };

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
    affects_path: bool,
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
            self.collect_home_channel_dependent_acl_channel_ids(
                root_id,
                false,
                false,
                false,
                &mut affected,
            );
        }
        affected
    }

    fn collect_home_channel_dependent_acl_channel_ids(
        &self,
        channel_id: u32,
        inherited_home_channel_dependent_acl: bool,
        inherited_path_dependent_acl: bool,
        ancestor_path_dependent_acl: bool,
        affected: &mut HashSet<u32>,
    ) {
        let Some(channel) = self.by_id.get(&channel_id).copied() else {
            return;
        };
        let inherited_home_channel_dependent_acl =
            channel.inherit_acl && inherited_home_channel_dependent_acl;
        let inherited_path_dependent_acl = channel.inherit_acl && inherited_path_dependent_acl;
        let applies_here = inherited_home_channel_dependent_acl
            || has_home_channel_dependent_acl(channel, AclApplication::Here);
        let path_depends_here = inherited_path_dependent_acl
            || has_home_channel_dependent_path_acl(channel, AclApplication::Here);
        let applies_to_subs = has_home_channel_dependent_acl(channel, AclApplication::Subs);
        let path_applies_to_subs =
            has_home_channel_dependent_path_acl(channel, AclApplication::Subs);

        if applies_here || ancestor_path_dependent_acl {
            affected.insert(channel_id);
        }

        let descendant_inherited = inherited_home_channel_dependent_acl || applies_to_subs;
        let descendant_inherited_path = inherited_path_dependent_acl || path_applies_to_subs;
        let descendant_ancestor_path = ancestor_path_dependent_acl || path_depends_here;
        self.for_each_child(channel_id, |child_id| {
            self.collect_home_channel_dependent_acl_channel_ids(
                child_id,
                descendant_inherited,
                descendant_inherited_path,
                descendant_ancestor_path,
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
                false,
                old_home,
                new_home,
                &mut affected,
            );
        }
        affected
    }

    fn home_channel_move_affected_channel_ids_for_channel_ids(
        &self,
        old_channel_id: u32,
        new_channel_id: u32,
    ) -> HashSet<u32> {
        let Some(old_ancestors) = self.ancestor_ids_for_channel(old_channel_id) else {
            return self.home_channel_dependent_acl_channel_ids();
        };
        let Some(new_ancestors) = self.ancestor_ids_for_channel(new_channel_id) else {
            return self.home_channel_dependent_acl_channel_ids();
        };
        let old_home = ChannelHierarchy::new(old_channel_id, &old_ancestors);
        let new_home = ChannelHierarchy::new(new_channel_id, &new_ancestors);
        self.home_channel_move_affected_channel_ids(old_home, new_home)
    }

    fn expand_descendant_closure(&self, channel_ids: &mut HashSet<u32>) {
        let mut pending = channel_ids.iter().copied().collect::<VecDeque<_>>();
        while let Some(channel_id) = pending.pop_front() {
            let Some(children) = self.children_by_parent_id.get(&Some(channel_id)) else {
                continue;
            };
            for child_id in children {
                if channel_ids.insert(*child_id) {
                    pending.push_back(*child_id);
                }
            }
        }
    }

    fn collect_home_channel_move_affected_channel_ids(
        &self,
        channel_id: u32,
        actual_ancestor_ids: &mut Vec<u32>,
        effective_ancestor_ids: &mut Vec<u32>,
        inherited_acls: &mut Vec<HomeChannelAcl<'a>>,
        active_effective_start: usize,
        active_acl_start: usize,
        ancestor_path_changes: bool,
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
        let inherited_path_changes = inherited_acls[effective_acl_start..]
            .iter()
            .filter(|acl| acl.affects_path)
            .any(|acl| acl.match_changes(evaluation_channel, old_home, new_home));
        let local_here_changes = home_channel_match_changes_in_acls(
            channel,
            evaluation_channel,
            local_acl_channel,
            AclApplication::Here,
            old_home,
            new_home,
        );
        let local_here_path_changes = home_channel_path_match_changes_in_acls(
            channel,
            evaluation_channel,
            local_acl_channel,
            AclApplication::Here,
            old_home,
            new_home,
        );

        if ancestor_path_changes || inherited_changes || local_here_changes {
            affected.insert(channel_id);
        }
        let descendant_path_changes =
            ancestor_path_changes || inherited_path_changes || local_here_path_changes;

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
                affects_path: (acl.allow | acl.deny)
                    .intersects(ACLPermissions::Traverse | ACLPermissions::Write),
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
                descendant_path_changes,
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

fn home_channel_path_match_changes_in_acls(
    channel: &Channel,
    evaluation_channel: ChannelHierarchy<'_>,
    acl_channel: ChannelHierarchy<'_>,
    application: AclApplication,
    old_home: ChannelHierarchy<'_>,
    new_home: ChannelHierarchy<'_>,
) -> bool {
    channel.acls.iter().any(|acl| {
        acl_applies(acl, application)
            && (acl.allow | acl.deny).intersects(ACLPermissions::Traverse | ACLPermissions::Write)
            && acl.group.as_deref().is_some_and(|group| {
                group_depends_on_home_channel(group)
                    && group_match_changes(
                        group,
                        evaluation_channel,
                        acl_channel,
                        old_home,
                        new_home,
                    )
            })
    })
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

fn has_home_channel_dependent_path_acl(channel: &Channel, application: AclApplication) -> bool {
    channel.acls.iter().any(|acl| {
        acl_applies(acl, application)
            && (acl.allow | acl.deny).intersects(ACLPermissions::Traverse | ACLPermissions::Write)
            && acl
                .group
                .as_deref()
                .is_some_and(group_depends_on_home_channel)
    })
}

fn acl_applies(acl: &shitspeak_state::ACL, application: AclApplication) -> bool {
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
