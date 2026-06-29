use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::acl::ACLPermissions;
use crate::channel_handler::SessionChannelShadow;
use crate::channel_repository::{ChannelOp, ChannelOperation};
use crate::client::Client;
use crate::client::client_session_identifier::ClientSessionIdentifier;
use crate::client::state_log::{ClientGlobalStateDelta, ClientStateLogEntry, ClientStateOperation};
use crate::messages::Message;
use crate::messages::encoder::{UserRemove, UserState};
use crate::server::Server;

#[derive(Debug, Clone, Default)]
pub struct UserVisibilityState {
    known: HashMap<ClientSessionIdentifier, KnownUserVisibility>,
}

#[derive(Debug, Clone)]
struct KnownUserVisibility {
    channel_id: u32,
    listener_channels: HashSet<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct VisibilityRefreshScope {
    sessions: HashSet<ClientSessionIdentifier>,
    channels: HashSet<u32>,
    include_all_channels: bool,
    include_known_users: bool,
}

impl VisibilityRefreshScope {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn for_session(session: ClientSessionIdentifier) -> Self {
        let mut scope = Self::new();
        scope.include_session(session);
        scope
    }

    pub fn include_session(&mut self, session: ClientSessionIdentifier) {
        self.sessions.insert(session);
    }

    pub fn include_channel(&mut self, channel_id: u32) {
        self.channels.insert(channel_id);
    }

    pub fn include_channels(&mut self, channel_ids: impl IntoIterator<Item = u32>) {
        self.channels.extend(channel_ids);
    }

    pub fn include_all_channels(&mut self) {
        self.include_all_channels = true;
    }

    pub fn include_known_users(&mut self) {
        self.include_known_users = true;
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
            && self.channels.is_empty()
            && !self.include_all_channels
            && !self.include_known_users
    }

    pub fn merge(&mut self, other: VisibilityRefreshScope) {
        self.sessions.extend(other.sessions);
        self.channels.extend(other.channels);
        self.include_all_channels |= other.include_all_channels;
        self.include_known_users |= other.include_known_users;
    }
}

impl UserVisibilityState {
    pub fn clear(&mut self) {
        self.known.clear();
    }

    pub fn known_channel(&self, session: ClientSessionIdentifier) -> Option<u32> {
        self.known.get(&session).map(|known| known.channel_id)
    }

    fn get(&self, session: ClientSessionIdentifier) -> Option<&KnownUserVisibility> {
        self.known.get(&session)
    }

    fn insert(
        &mut self,
        session: ClientSessionIdentifier,
        channel_id: u32,
        listener_channels: HashSet<u32>,
    ) {
        self.known.insert(
            session,
            KnownUserVisibility {
                channel_id,
                listener_channels,
            },
        );
    }

    fn remove(&mut self, session: ClientSessionIdentifier) -> bool {
        self.known.remove(&session).is_some()
    }

    fn known_sessions(&self) -> impl Iterator<Item = ClientSessionIdentifier> + '_ {
        self.known.keys().copied()
    }

    fn known_sessions_in_channels<'a>(
        &'a self,
        channel_ids: &'a HashSet<u32>,
    ) -> impl Iterator<Item = ClientSessionIdentifier> + 'a {
        self.known.iter().filter_map(|(session, known)| {
            (channel_ids.contains(&known.channel_id)
                || known
                    .listener_channels
                    .iter()
                    .any(|channel_id| channel_ids.contains(channel_id)))
            .then_some(*session)
        })
    }
}

pub async fn can_view_user(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    target: &Arc<Box<Client>>,
) -> bool {
    if !server.get_hide_users_without_traverse() {
        return true;
    }
    if viewer.get_session_id() == target.get_session_id() {
        return true;
    }
    if !target.is_authenticated() {
        return false;
    }
    let perms = crate::client::acl::compute_permissions_for_client(
        server,
        viewer,
        target.get_current_channel_id(),
    )
    .await;
    perms.contains(ACLPermissions::Traverse)
}

pub async fn get_visible_client_in_server(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    server_id: &str,
    session: ClientSessionIdentifier,
) -> Option<Arc<Box<Client>>> {
    let target = server
        .get_clients()
        .get_client_in_server(server_id, session)
        .await?;
    if can_view_user(server, viewer, &target).await {
        Some(target)
    } else {
        None
    }
}

pub async fn visible_listener_channels(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    channels: HashSet<u32>,
) -> HashSet<u32> {
    if !server.get_hide_users_without_traverse() {
        return channels;
    }

    let mut visible = HashSet::new();
    for channel_id in channels {
        let perms =
            crate::client::acl::compute_permissions_for_client(server, viewer, channel_id).await;
        if perms.contains(ACLPermissions::Traverse) {
            visible.insert(channel_id);
        }
    }
    visible
}

pub async fn build_visible_user_state(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    target: &Arc<Box<Client>>,
) -> UserState {
    let mut state = target.build_user_state_for_broadcast();
    if server.get_hide_users_without_traverse() {
        let listener_channels =
            visible_listener_channels(server, viewer, target.get_listening_channel_ids()).await;
        state.listening_channel_add = sorted_channels(&listener_channels);
        state.listening_channel_remove.clear();
    }
    protect_user_state_hash_for_viewer(server, viewer, &mut state);
    state
}

pub fn user_state_projection_is_viewer_independent(server: &Arc<Box<Server>>) -> bool {
    !server.get_hide_users_without_traverse() && server.get_certificate_hash_privacy().is_none()
}

pub async fn initialize(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    channel_shadow: &mut SessionChannelShadow,
) {
    visibility.clear();
    channel_shadow.clear();
    let server_id = viewer.server_id();
    for target in server
        .get_clients()
        .get_all_clients_in_server(&server_id)
        .await
    {
        if !target.is_authenticated() {
            continue;
        }
        if !can_view_user(server, viewer, &target).await {
            continue;
        }
        let listener_channels =
            visible_listener_channels(server, viewer, target.get_listening_channel_ids()).await;
        let session = target.get_session_id();
        let channel_id = target.get_current_channel_id();
        visibility.insert(session, channel_id, listener_channels);
        channel_shadow.insert(session, channel_id);
    }
}

pub async fn project_message(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    message: &Message,
) -> Vec<Message> {
    match message {
        Message::UserState(user_state) => {
            let Ok(user_state) = UserState::try_from(user_state.clone()) else {
                return if server.get_hide_users_without_traverse() {
                    Vec::new()
                } else {
                    vec![message.clone()]
                };
            };
            let Some(session) = user_state.session else {
                return if server.get_hide_users_without_traverse() {
                    Vec::new()
                } else {
                    vec![message.clone()]
                };
            };
            if server.get_hide_users_without_traverse() {
                project_user_state(server, viewer, visibility, &user_state, session).await
            } else {
                let mut projected = user_state;
                protect_user_state_hash_for_viewer(server, viewer, &mut projected);
                vec![projected.into()]
            }
        }
        Message::UserRemove(user_remove) => {
            if !server.get_hide_users_without_traverse() {
                return vec![message.clone()];
            }
            let session = ClientSessionIdentifier::from(user_remove.session);
            if !visibility.remove(session) {
                return Vec::new();
            }
            let mut projected = UserRemove::from(user_remove.clone());
            projected.actor = visible_actor(
                server,
                viewer,
                projected.actor.map(ClientSessionIdentifier::from),
            )
            .await
            .map(u32::from);
            vec![projected.into()]
        }
        _ => vec![message.clone()],
    }
}

pub async fn project_message_with_shadow(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    channel_shadow: &mut SessionChannelShadow,
    server_id: &str,
    message: &Message,
) -> Vec<Message> {
    let projected = project_message(server, viewer, visibility, message).await;
    let mut out = Vec::new();
    for message in projected {
        out.extend(
            sync_projected_message_with_shadow(
                server,
                viewer,
                visibility,
                channel_shadow,
                server_id,
                message,
            )
            .await,
        );
    }
    out
}

pub async fn sync_projected_message_with_shadow(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    channel_shadow: &mut SessionChannelShadow,
    server_id: &str,
    message: Message,
) -> Vec<Message> {
    let mut out = vec![message.clone()];
    let synthetic = crate::channel_handler::sync_shadow_for_client_message(
        server,
        server.get_channels(),
        channel_shadow,
        server_id,
        &message,
    )
    .await;
    for synthetic_message in synthetic {
        let projected_synthetic =
            project_message(server, viewer, visibility, &synthetic_message).await;
        for projected in projected_synthetic {
            let _ = crate::channel_handler::sync_shadow_for_client_message(
                server,
                server.get_channels(),
                channel_shadow,
                server_id,
                &projected,
            )
            .await;
            out.push(projected);
        }
    }
    out
}

pub async fn visibility_refresh_messages(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    scope: VisibilityRefreshScope,
) -> Vec<Message> {
    if !server.get_hide_users_without_traverse() || scope.is_empty() {
        return Vec::new();
    }

    let server_id = viewer.server_id();
    let mut sessions = scope.sessions;
    if scope.include_known_users {
        sessions.extend(visibility.known_sessions());
    }

    let mut channels = scope.channels;
    if scope.include_all_channels {
        channels.extend(
            server
                .get_channels()
                .get_all_in_server(&server_id)
                .await
                .into_iter()
                .map(|channel| channel.id),
        );
    }

    if !channels.is_empty() {
        sessions.extend(visibility.known_sessions_in_channels(&channels));
        sessions.extend(
            server
                .get_clients()
                .get_clients_in_channels_or_listeners_in_server(&server_id, &channels)
                .await
                .into_iter()
                .filter(|target| target.is_authenticated())
                .map(|target| target.get_session_id()),
        );
    }

    let mut sessions = sessions.into_iter().collect::<Vec<_>>();
    sessions.sort_by_key(|session| u32::from(*session));
    sessions.dedup();

    let mut messages = Vec::new();
    for session in sessions {
        match server
            .get_clients()
            .get_client_in_server(&server_id, session)
            .await
        {
            Some(target) if target.is_authenticated() => {
                messages
                    .extend(refresh_target_visibility(server, viewer, visibility, &target).await);
            }
            _ if visibility.remove(session) => messages.push(hidden_user_remove(session)),
            _ => {}
        }
    }
    messages
}

pub async fn visibility_refresh_messages_with_shadow(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    channel_shadow: &mut SessionChannelShadow,
    server_id: &str,
    scope: VisibilityRefreshScope,
) -> Vec<Message> {
    let refresh = visibility_refresh_messages(server, viewer, visibility, scope).await;
    let mut out = Vec::new();
    for message in refresh {
        out.extend(
            sync_projected_message_with_shadow(
                server,
                viewer,
                visibility,
                channel_shadow,
                server_id,
                message,
            )
            .await,
        );
    }
    out
}

pub async fn visibility_refresh_scope_for_client_log_entry(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    entry: &ClientStateLogEntry,
    old_viewer_channel_id: Option<u32>,
) -> VisibilityRefreshScope {
    let mut scope = VisibilityRefreshScope::new();
    match &entry.op {
        ClientStateOperation::UpdateGlobalState {
            session_id, delta, ..
        } if *session_id == viewer.get_session_id() => {
            scope.merge(
                visibility_refresh_scope_for_viewer_delta(
                    server,
                    viewer,
                    delta,
                    old_viewer_channel_id,
                )
                .await,
            );
        }
        ClientStateOperation::ResetNode { .. } => {
            scope.include_known_users();
        }
        _ => {}
    }
    scope
}

pub async fn visibility_refresh_scope_for_channel_operation(
    server: &Arc<Box<Server>>,
    op: &ChannelOperation,
) -> VisibilityRefreshScope {
    let mut scope = VisibilityRefreshScope::new();
    let channels = server.get_channels();
    match &op.op {
        ChannelOp::CreateChannel { channel } => {
            scope.include_channel(channel.id);
        }
        ChannelOp::UpdateChannel { id, patch } | ChannelOp::EditChannel { id, patch, .. } => {
            if patch.parent_id.is_some() {
                scope.include_channels(channels.subtree_ids_in_server(&op.server_id, *id).await);
            }
        }
        ChannelOp::SetAcls { channel_id, .. } => {
            scope.include_channels(
                channels
                    .subtree_ids_in_server(&op.server_id, *channel_id)
                    .await,
            );
        }
        ChannelOp::DeleteChannel { id, .. } => {
            scope.include_channel(*id);
            scope.include_known_users();
        }
        ChannelOp::InstallSnapshot { channels, .. } => {
            scope.include_channels(channels.iter().map(|channel| channel.id));
            scope.include_known_users();
        }
        ChannelOp::MarkPendingDelete { .. }
        | ChannelOp::CancelPendingDelete { .. }
        | ChannelOp::AddLink { .. }
        | ChannelOp::RemoveLink { .. } => {}
    }
    scope
}

async fn visibility_refresh_scope_for_viewer_delta(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    delta: &ClientGlobalStateDelta,
    old_viewer_channel_id: Option<u32>,
) -> VisibilityRefreshScope {
    let mut scope = VisibilityRefreshScope::new();
    if delta.user_id.is_some()
        || delta.groups.is_some()
        || delta.is_superuser.is_some()
        || delta.tokens.is_some()
    {
        scope.include_all_channels();
        scope.include_known_users();
    } else if let Some(new_channel_id) = delta.current_channel_id {
        scope.include_channels(
            crate::channel_handler::home_channel_dependent_channel_ids(
                server,
                viewer,
                old_viewer_channel_id,
                new_channel_id,
            )
            .await,
        );
    }
    scope
}

async fn project_user_state(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    raw: &UserState,
    session: ClientSessionIdentifier,
) -> Vec<Message> {
    let server_id = viewer.server_id();
    let Some(target) = server
        .get_clients()
        .get_client_in_server(&server_id, session)
        .await
    else {
        if visibility.remove(session) {
            return vec![hidden_user_remove(session)];
        }
        return Vec::new();
    };

    let visible = can_view_user(server, viewer, &target).await;
    let known_before = visibility.get(session).cloned();
    if !visible {
        if visibility.remove(session) {
            return vec![hidden_user_remove(session)];
        }
        return Vec::new();
    }

    let current_channel = target.get_current_channel_id();
    let new_listeners =
        visible_listener_channels(server, viewer, target.get_listening_channel_ids()).await;

    if known_before.is_none() {
        visibility.insert(session, current_channel, new_listeners.clone());
        let mut state = target.build_user_state_for_broadcast();
        state.listening_channel_add = sorted_channels(&new_listeners);
        state.listening_channel_remove.clear();
        protect_user_state_hash_for_viewer(server, viewer, &mut state);
        return vec![state.into()];
    }

    let old = known_before.expect("checked is_some");
    visibility.insert(session, current_channel, new_listeners.clone());
    let mut projected = raw.clone();
    projected.actor = visible_actor(server, viewer, raw.actor).await;
    projected.listening_channel_add = sorted_difference(&new_listeners, &old.listener_channels);
    projected.listening_channel_remove = sorted_difference(&old.listener_channels, &new_listeners);
    protect_user_state_hash_for_viewer(server, viewer, &mut projected);

    if user_state_delta_empty(&projected) {
        Vec::new()
    } else {
        vec![projected.into()]
    }
}

async fn refresh_target_visibility(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    target: &Arc<Box<Client>>,
) -> Vec<Message> {
    let session = target.get_session_id();
    let known_before = visibility.get(session).cloned();
    let visible = can_view_user(server, viewer, target).await;

    if !visible {
        if visibility.remove(session) {
            return vec![hidden_user_remove(session)];
        }
        return Vec::new();
    }

    let current_channel = target.get_current_channel_id();
    let new_listeners =
        visible_listener_channels(server, viewer, target.get_listening_channel_ids()).await;

    match known_before {
        None => {
            visibility.insert(session, current_channel, new_listeners.clone());
            let mut state = target.build_user_state_for_broadcast();
            state.listening_channel_add = sorted_channels(&new_listeners);
            state.listening_channel_remove.clear();
            protect_user_state_hash_for_viewer(server, viewer, &mut state);
            vec![state.into()]
        }
        Some(old) => {
            visibility.insert(session, current_channel, new_listeners.clone());
            if old.channel_id != current_channel {
                let mut state = UserState {
                    session: Some(session),
                    channel_id: Some(current_channel),
                    ..Default::default()
                };
                state.listening_channel_add =
                    sorted_difference(&new_listeners, &old.listener_channels);
                state.listening_channel_remove =
                    sorted_difference(&old.listener_channels, &new_listeners);
                protect_user_state_hash_for_viewer(server, viewer, &mut state);
                vec![state.into()]
            } else {
                let adds = sorted_difference(&new_listeners, &old.listener_channels);
                let removes = sorted_difference(&old.listener_channels, &new_listeners);
                if adds.is_empty() && removes.is_empty() {
                    Vec::new()
                } else {
                    vec![
                        UserState {
                            session: Some(session),
                            listening_channel_add: adds,
                            listening_channel_remove: removes,
                            ..Default::default()
                        }
                        .into(),
                    ]
                }
            }
        }
    }
}

async fn visible_actor(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    actor: Option<ClientSessionIdentifier>,
) -> Option<ClientSessionIdentifier> {
    let actor = actor?;
    let server_id = viewer.server_id();
    let target = server
        .get_clients()
        .get_client_in_server(&server_id, actor)
        .await?;
    can_view_user(server, viewer, &target)
        .await
        .then_some(actor)
}

fn protect_user_state_hash_for_viewer(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    state: &mut UserState,
) {
    let Some((protection, secret)) = server.get_certificate_hash_privacy() else {
        return;
    };
    crate::privacy::protect_user_state_certificate_hash(
        state,
        viewer.is_superuser(),
        viewer.get_session_id(),
        protection,
        Some(secret.as_str()),
    );
}

fn hidden_user_remove(session: ClientSessionIdentifier) -> Message {
    UserRemove {
        session: u32::from(session),
        actor: None,
        reason: None,
        ban: Some(false),
    }
    .into()
}

fn sorted_channels(channels: &HashSet<u32>) -> Vec<u32> {
    let mut out = channels.iter().copied().collect::<Vec<_>>();
    out.sort_unstable();
    out
}

fn sorted_difference(left: &HashSet<u32>, right: &HashSet<u32>) -> Vec<u32> {
    let mut out = left.difference(right).copied().collect::<Vec<_>>();
    out.sort_unstable();
    out
}

fn user_state_delta_empty(state: &UserState) -> bool {
    state.actor.is_none()
        && state.name.is_none()
        && state.user_id.is_none()
        && state.channel_id.is_none()
        && state.mute.is_none()
        && state.deaf.is_none()
        && state.suppress.is_none()
        && state.self_mute.is_none()
        && state.self_deaf.is_none()
        && state.texture.is_none()
        && state.plugin_context.is_none()
        && state.plugin_identity.is_none()
        && state.comment.is_none()
        && state.hash.is_none()
        && state.comment_hash.is_none()
        && state.texture_hash.is_none()
        && state.priority_speaker.is_none()
        && state.recording.is_none()
        && state.temporary_access_tokens.is_empty()
        && state.listening_channel_add.is_empty()
        && state.listening_channel_remove.is_empty()
        && state.listening_volume_adjustment.is_empty()
}
