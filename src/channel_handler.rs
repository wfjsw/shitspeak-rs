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
    client::{Client, client_session_identifier::ClientSessionIdentifier},
    messages::{Message, encoder::ChannelState},
    server::Server,
};

pub type SessionChannelShadow = HashMap<ClientSessionIdentifier, u32>;

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
            if let Some(ch) = channels.get_channel_in_server(&server_id, ch_id).await {
                let perms =
                    crate::client::acl::compute_permissions_for_client(server, client, ch_id).await;
                let encoder_cs: crate::messages::encoder::ChannelState = cs_proto.clone().into();
                return Some(encoder_cs.with_permission_info(&ch, perms).into());
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

    match &op.op {
        ChannelOp::MarkPendingDelete { id, nonce } => {
            if let Some(shadow) = session_channel_shadow.as_deref_mut() {
                append_pending_delete_synthetic_moves(
                    server,
                    channels,
                    shadow,
                    *id,
                    *nonce,
                    false,
                    &server_id,
                    &mut messages,
                )
                .await;
            }
        }
        ChannelOp::DeleteChannel { id, nonce } => {
            if op.emits_client_message {
                if let Some(shadow) = session_channel_shadow.as_deref_mut() {
                    append_pending_delete_synthetic_moves(
                        server,
                        channels,
                        shadow,
                        *id,
                        *nonce,
                        true,
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

    // For SetAcls operations, generate PermissionQuery when send_permission_info is enabled
    if send_permission_info {
        if let ChannelOp::SetAcls { channel_id, .. } = &op.op {
            let perms =
                crate::client::acl::compute_permissions_for_client(server, client, *channel_id)
                    .await;
            let permission_query: crate::messages::Message =
                crate::messages::encoder::PermissionQuery {
                    channel_id: Some(*channel_id),
                    permissions: Some(perms.bits()),
                    flush: Some(false),
                }
                .into();
            messages.push(permission_query);
        }
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
    server_id: &str,
    messages: &mut Vec<Message>,
) {
    let subtree: std::collections::HashSet<u32> = if include_deleted_snapshot {
        deleted_subtree_from_shadow(channels, server_id, id, shadow).await
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

    let target = channels
        .redirect_pending_delete_target_in_server(server_id, id)
        .await;
    let sessions: Vec<_> = shadow
        .iter()
        .filter_map(|(session, channel_id)| subtree.contains(channel_id).then_some(*session))
        .collect();

    for session in sessions {
        let Some(current) = shadow.get(&session).copied() else {
            continue;
        };
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
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut crate::client::visibility::UserVisibilityState,
    session_id: crate::client::client_session_identifier::ClientSessionIdentifier,
    last: u64,
    current: u64,
) -> Result<(), ()> {
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
    if missed.is_empty() && last > 0 {
        tracing::error!(
            "Client {:?} channel log gap unrecoverable (last={})",
            session_id,
            last,
        );
        return Err(());
    }

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
                if client.write_proto_message(&msg).await.is_err() {
                    return Err(());
                }
            }
        }
        let reconcile =
            crate::client::visibility::reconcile_all(server, client, user_visibility).await;
        for msg in reconcile {
            let projected = crate::client::visibility::sync_projected_message_with_shadow(
                server,
                client,
                user_visibility,
                session_channel_shadow,
                &server_id,
                msg,
            )
            .await;
            for msg in projected {
                if client.write_proto_message(&msg).await.is_err() {
                    return Err(());
                }
            }
        }
        client.set_last_channel_version(entry.version).await;
    }

    Ok(())
}

fn ordered_snapshot_channels(
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

/// Build a ChannelState encoder message, optionally with permission info.
/// Used during initial authentication and other contexts to send channel state.
pub async fn build_channel_state_message(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel: &crate::channels::Channel,
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
    if server.get_send_permission_info() {
        let perms =
            crate::client::acl::compute_permissions_for_client(server, client, channel.id).await;
        cs = cs.with_permission_info(channel, perms);
    }

    cs
}
