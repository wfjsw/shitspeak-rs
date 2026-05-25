use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::acl::ACLPermissions;
use crate::channel_handler::SessionChannelShadow;
use crate::client::Client;
use crate::client::client_session_identifier::ClientSessionIdentifier;
use crate::messages::Message;
use crate::messages::encoder::{UserRemove, UserState};
use crate::server::Server;

#[derive(Debug, Clone, Default)]
pub(crate) struct UserVisibilityState {
    known: HashMap<ClientSessionIdentifier, KnownUserVisibility>,
}

#[derive(Debug, Clone)]
struct KnownUserVisibility {
    channel_id: u32,
    listener_channels: HashSet<u32>,
}

impl UserVisibilityState {
    pub(crate) fn clear(&mut self) {
        self.known.clear();
    }

    pub(crate) fn known_channel(&self, session: ClientSessionIdentifier) -> Option<u32> {
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
}

pub(crate) async fn can_view_user(
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

pub(crate) async fn get_visible_client_in_server(
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

pub(crate) async fn visible_listener_channels(
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

pub(crate) async fn build_visible_user_state(
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
    state
}

pub(crate) async fn initialize(
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

pub(crate) async fn project_message(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
    message: &Message,
) -> Vec<Message> {
    if !server.get_hide_users_without_traverse() {
        return vec![message.clone()];
    }

    match message {
        Message::UserState(user_state) => {
            let Ok(user_state) = UserState::try_from(user_state.clone()) else {
                return Vec::new();
            };
            let Some(session) = user_state.session else {
                return Vec::new();
            };
            project_user_state(server, viewer, visibility, &user_state, session).await
        }
        Message::UserRemove(user_remove) => {
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

pub(crate) async fn project_message_with_shadow(
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

pub(crate) async fn sync_projected_message_with_shadow(
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

pub(crate) async fn reconcile_all(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
    visibility: &mut UserVisibilityState,
) -> Vec<Message> {
    if !server.get_hide_users_without_traverse() {
        return Vec::new();
    }

    let server_id = viewer.server_id();
    let mut messages = Vec::new();
    let clients = server
        .get_clients()
        .get_all_clients_in_server(&server_id)
        .await;
    let mut seen = HashSet::new();
    for target in clients {
        if !target.is_authenticated() {
            continue;
        }
        let session = target.get_session_id();
        seen.insert(session);
        messages.extend(reconcile_target(server, viewer, visibility, &target).await);
    }

    let known_sessions = visibility.known.keys().copied().collect::<Vec<_>>();
    for session in known_sessions {
        if !seen.contains(&session) && visibility.remove(session) {
            messages.push(
                UserRemove {
                    session: u32::from(session),
                    actor: None,
                    reason: None,
                    ban: Some(false),
                }
                .into(),
            );
        }
    }
    messages
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
        return vec![state.into()];
    }

    let old = known_before.expect("checked is_some");
    visibility.insert(session, current_channel, new_listeners.clone());
    let mut projected = raw.clone();
    projected.actor = visible_actor(server, viewer, raw.actor).await;
    projected.listening_channel_add = sorted_difference(&new_listeners, &old.listener_channels);
    projected.listening_channel_remove = sorted_difference(&old.listener_channels, &new_listeners);

    if user_state_delta_empty(&projected) {
        Vec::new()
    } else {
        vec![projected.into()]
    }
}

async fn reconcile_target(
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
