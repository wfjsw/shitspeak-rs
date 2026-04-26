//! Channel message handling with ACL support.
//!
//! This module provides utilities for converting channel operations to protocol messages,
//! with optional permission info and ACL handling. Useful for authentication, gap replay,
//! subscription broadcasts, and future features like S2S replication and admin APIs.

use std::sync::Arc;

use crate::{
    channel_repository::ChannelRepository,
    client::Client,
    messages::encoder::ChannelState,
    server::Server,
};

/// Helper to add permission information to a ChannelState message.
/// Applied when `send_permission_info` is enabled.
pub async fn apply_permission_info_to_channel_state(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    cs_proto: &crate::messages::Message,
    channels: &Arc<ChannelRepository>,
) -> Option<crate::messages::Message> {
    if let crate::messages::Message::ChannelState(ref cs_proto) = cs_proto {
        if let Some(ch_id) = cs_proto.channel_id {
            if let Some(ch) = channels.get_channel(ch_id).await {
                let perms = crate::client::acl::compute_permissions_for_client(
                    server, client, ch_id,
                ).await;
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
    op: &crate::channel_repository::ChannelOperation,
    channels: &Arc<ChannelRepository>,
) -> Vec<crate::messages::Message> {
    let mut messages = Vec::new();
    let send_permission_info = server.read_config().send_permission_info;

    // Convert operation to message(s)
    if let Some(msg) = op.to_message() {
        // Add permission info to ChannelState if configured
        let msg = if send_permission_info {
            match apply_permission_info_to_channel_state(server, client, &msg, channels).await {
                Some(m) => m,
                None => msg,
            }
        } else {
            msg
        };
        messages.push(msg);
    }

    // For SetAcls operations, generate PermissionQuery when send_permission_info is enabled
    if send_permission_info {
        if let crate::channel_repository::ChannelOp::SetAcls { channel_id, .. } = &op.op {
            let perms = crate::client::acl::compute_permissions_for_client(
                server,
                client,
                *channel_id,
            ).await;
            let permission_query: crate::messages::Message = crate::messages::encoder::PermissionQuery {
                channel_id: Some(*channel_id),
                permissions: Some(perms.bits()),
                flush: Some(false),
            }.into();
            messages.push(permission_query);
        }
    }

    messages
}

/// Replay missed channel log entries for a client between versions.
/// Ensures clients catch up on channel state changes they missed due to network gaps.
pub async fn replay_channel_log_gap(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channels: &Arc<ChannelRepository>,
    session_id: crate::client::client_session_identifier::ClientSessionIdentifier,
    last: u64,
    current: u64,
) -> Result<(), ()> {
    if current <= last + 1 {
        return Ok(());
    }

    tracing::warn!(
        "Client {:?} missed channel log entries: last={} current={}",
        session_id, last, current,
    );

    let missed = channels.get_log_since(last).await;
    if missed.is_empty() && last > 0 {
        tracing::error!(
            "Client {:?} channel log gap unrecoverable (last={})",
            session_id, last,
        );
        return Err(());
    }

    for entry in &missed {
        if entry.version >= current {
            break;
        }
        let messages = convert_channel_operation_to_messages(server, client, entry, channels).await;
        for msg in messages {
            if client.write_proto_message(&msg).await.is_err() {
                return Err(());
            }
        }
        client.set_last_channel_version(entry.version).await;
    }

    Ok(())
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
            .and_then(|h| hex::decode(h).ok()),
        max_users: Some(channel.max_users),
        is_enter_restricted: None,
        can_enter: None,
    };

    // Add permission info if configured
    if server.get_send_permission_info() {
        let perms = crate::client::acl::compute_permissions_for_client(server, client, channel.id).await;
        cs = cs.with_permission_info(channel, perms);
    }

    cs
}
