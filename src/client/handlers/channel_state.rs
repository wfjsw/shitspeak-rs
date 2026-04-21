use std::sync::Arc;

use crate::{
    channels::{Channel, ChannelPatch},
    client::Client,
    errors::MessageHandlerError,
    messages::{Message, WriteMessageExt},
    mumble_proto::{ChannelState, PermissionDenied, permission_denied::DenyType},
    server::Server,
};

pub async fn handle_channel_state(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: ChannelState,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated().await {
        return Ok(());
    }

    // channel_id absent → create new channel
    // channel_id present → update existing channel

    match msg.channel_id {
        None => {
            // ── Create channel ────────────────────────────────────────────
            let parent_id = msg.parent.unwrap_or(0);
            let name = match msg.name {
                Some(n) if !n.is_empty() => n,
                _ => {
                    sender.write_proto_message(&Message::PermissionDenied(PermissionDenied {
                        r#type: Some(DenyType::ChannelName as i32),
                        session: Some(u32::from(sender.get_session_id())),
                        channel_id: None,
                        reason: Some("Channel name is required".to_owned()),
                        name: None,
                        permission: None,
                    })).await?;
                    return Ok(());
                }
            };

            let is_temp = msg.temporary.unwrap_or(false);
            let new_id = server.get_channels().next_channel_id(is_temp).await;

            let new_ch = Channel {
                id: new_id,
                name,
                parent_id: Some(parent_id),
                position: msg.position.unwrap_or(0),
                max_users: msg.max_users.unwrap_or(0),
                inherit_acl: true,
                links: std::collections::HashSet::new(),
                description_hash: None,
                acls: Vec::new(),
            };

            let created = match server.get_channels().create_channel(new_ch).await {
                Ok(ch) => ch,
                Err(e) => {
                    tracing::warn!("create_channel failed: {:?}", e);
                    sender.write_proto_message(&Message::PermissionDenied(PermissionDenied {
                        r#type: Some(DenyType::Text as i32),
                        session: Some(u32::from(sender.get_session_id())),
                        channel_id: None,
                        reason: Some(format!("Failed to create channel: {:?}", e)),
                        name: None,
                        permission: None,
                    })).await?;
                    return Ok(());
                }
            };

            // Broadcast new channel to all clients
            let broadcast = Message::ChannelState(crate::mumble_proto::ChannelState {
                channel_id: Some(created.id),
                parent: created.parent_id,
                name: Some(created.name.clone()),
                links: Vec::new(),
                description: None,
                links_add: Vec::new(),
                links_remove: Vec::new(),
                temporary: Some(created.is_temporary()),
                position: Some(created.position),
                description_hash: created.description_hash.as_ref().and_then(|h| hex::decode(h).ok()),
                max_users: Some(created.max_users),
                is_enter_restricted: None,
                can_enter: None,
            });
            server.get_clients().broadcast_all(&broadcast).await;
        }

        Some(channel_id) => {
            // ── Update existing channel ───────────────────────────────────
            if server.get_channels().get_channel(channel_id).await.is_none() {
                return Ok(());
            }

            let patch = ChannelPatch {
                name: msg.name,
                position: msg.position,
                max_users: msg.max_users,
                description_hash: None, // TODO: handle description blob
                parent_id: msg.parent.map(|p| Some(p)),
            };

            // Handle link additions/removals
            for link_add in &msg.links_add {
                let _ = server.get_channels().add_link(channel_id, *link_add).await;
            }
            for link_remove in &msg.links_remove {
                let _ = server.get_channels().remove_link(channel_id, *link_remove).await;
            }

            if let Err(e) = server.get_channels().update_channel(channel_id, patch).await {
                tracing::warn!("update_channel {channel_id} failed: {:?}", e);
                return Ok(());
            }

            // Fetch updated state and broadcast
            let Some(updated) = server.get_channels().get_channel(channel_id).await else {
                return Ok(());
            };
            let links: Vec<u32> = updated.links.iter().copied().collect();
            let broadcast = Message::ChannelState(crate::mumble_proto::ChannelState {
                channel_id: Some(updated.id),
                parent: updated.parent_id,
                name: Some(updated.name.clone()),
                links,
                description: None,
                links_add: msg.links_add,
                links_remove: msg.links_remove,
                temporary: Some(updated.is_temporary()),
                position: Some(updated.position),
                description_hash: updated.description_hash.as_ref().and_then(|h| hex::decode(h).ok()),
                max_users: Some(updated.max_users),
                is_enter_restricted: None,
                can_enter: None,
            });
            server.get_clients().broadcast_all(&broadcast).await;
        }
    }

    Ok(())
}
