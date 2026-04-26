use std::sync::Arc;

use crate::{
    acl::ACLPermissions,
    channels::{Channel, ChannelPatch},
    client::Client,
    errors::MessageHandlerError,
    messages::encoder::{ChannelState, DenyType, PermissionDenied},
    server::Server,
};

pub async fn handle_channel_state(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: ChannelState,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated().await {
        return Err(MessageHandlerError::protocol_violation(
            "ChannelState message received before authentication",
        ));
    }

    let session = sender.get_session_id();
    tracing::debug!(
        session = u32::from(session),
        channel_id = msg.channel_id,
        parent = msg.parent,
        name = msg.name,
        "ChannelState handler"
    );

    let channels = server.get_channels();

    // channel_id absent → create new channel
    // channel_id present → update existing channel

    match msg.channel_id {
        None => {
            // ── Create channel ────────────────────────────────────────────
            let parent_id = msg.parent.unwrap_or(0);
            let name = match msg.name {
                Some(n) if !n.is_empty() => n,
                _ => {
                    return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
                        r#type: DenyType::ChannelName,
                        session: u32::from(sender.get_session_id()),
                        channel_id: None,
                        reason: Some("Channel name is required".into()),
                        name: None,
                        permission: None,
                    }));
                }
            };

            // ACL: need MakeChannel on parent
            let parent_perms =
                crate::client::acl::compute_permissions_for_client(server, sender, parent_id).await;
            if !parent_perms.contains(ACLPermissions::MakeChannel) {
                return Err(MessageHandlerError::PermissionDenied(
                    PermissionDenied::for_permission(
                        u32::from(session),
                        Some(parent_id),
                        ACLPermissions::MakeChannel,
                    ),
                ));
            }

            let is_temp = msg.temporary.unwrap_or(false);
            let new_id = channels.next_channel_id(is_temp).await;

            let new_ch = Channel::new(
                new_id,
                name,
                msg.position.unwrap_or(0),
                msg.max_users.unwrap_or(0),
                Some(parent_id),
            );

            let created = match channels.create_channel(new_ch).await {
                Ok(ch) => ch,
                Err(e) => {
                    tracing::warn!("create_channel failed: {:?}", e);
                    return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
                        r#type: DenyType::Text,
                        session: u32::from(sender.get_session_id()),
                        channel_id: None,
                        reason: Some(format!("Failed to create channel: {:?}", e).into()),
                        name: None,
                        permission: None,
                    }));
                }
            };

            // Channel creation is logged and broadcast via ChannelRepository::commit().
            // Per-client subscribers will pick up the ChannelState delta.
        }

        Some(channel_id) => {
            // ── Update existing channel ───────────────────────────────────
            let channel = match channels.get_channel(channel_id).await {
                Some(ch) => ch,
                None => return Ok(()),
            };

            // ACL: need Write on the channel for name/description/position changes
            let has_write = {
                let perms =
                    crate::client::acl::compute_permissions_for_client(server, sender, channel_id)
                        .await;
                perms.contains(ACLPermissions::Write)
            };

            // Name change requires Write (root channel cannot be renamed)
            if msg.name.is_some() {
                if channel_id == 0 {
                    return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
                        r#type: DenyType::Permission,
                        session: u32::from(session),
                        channel_id: Some(0),
                        reason: Some("Cannot rename the root channel".into()),
                        name: None,
                        permission: None,
                    }));
                }
                if !has_write {
                    return Err(MessageHandlerError::PermissionDenied(
                        PermissionDenied::for_permission(
                            u32::from(session),
                            Some(channel_id),
                            ACLPermissions::Write,
                        ),
                    ));
                }
            }

            // Description change requires Write
            if msg.description.is_some() && !has_write {
                return Err(MessageHandlerError::PermissionDenied(
                    PermissionDenied::for_permission(
                        u32::from(session),
                        Some(channel_id),
                        ACLPermissions::Write,
                    ),
                ));
            }

            // Position change requires Write
            if msg.position.is_some() && !has_write {
                return Err(MessageHandlerError::PermissionDenied(
                    PermissionDenied::for_permission(
                        u32::from(session),
                        Some(channel_id),
                        ACLPermissions::Write,
                    ),
                ));
            }

            // Channel move (reparent): need Write on channel AND MakeChannel on new parent
            if let Some(new_parent) = msg.parent {
                if Some(new_parent) != channel.parent_id {
                    if !has_write {
                        return Err(MessageHandlerError::PermissionDenied(
                            PermissionDenied::for_permission(
                                u32::from(session),
                                Some(channel_id),
                                ACLPermissions::Write,
                            ),
                        ));
                    }
                    let parent_perms = crate::client::acl::compute_permissions_for_client(
                        server, sender, new_parent,
                    )
                    .await;
                    if !parent_perms.contains(ACLPermissions::MakeChannel) {
                        return Err(MessageHandlerError::PermissionDenied(
                            PermissionDenied::for_permission(
                                u32::from(session),
                                Some(new_parent),
                                ACLPermissions::MakeChannel,
                            ),
                        ));
                    }
                }
            }

            // Links: need LinkChannel on the channel
            if !msg.links_add.is_empty() || !msg.links_remove.is_empty() {
                let link_perms =
                    crate::client::acl::compute_permissions_for_client(server, sender, channel_id)
                        .await;
                if !link_perms.contains(ACLPermissions::LinkChannel) {
                    return Err(MessageHandlerError::PermissionDenied(
                        PermissionDenied::for_permission(
                            u32::from(session),
                            Some(channel_id),
                            ACLPermissions::LinkChannel,
                        ),
                    ));
                }
                // For link additions, also check LinkChannel on the target
                for link_add in &msg.links_add {
                    let target_perms = crate::client::acl::compute_permissions_for_client(
                        server, sender, *link_add,
                    )
                    .await;
                    if !target_perms.contains(ACLPermissions::LinkChannel) {
                        return Err(MessageHandlerError::PermissionDenied(
                            PermissionDenied::for_permission(
                                u32::from(session),
                                Some(*link_add),
                                ACLPermissions::LinkChannel,
                            ),
                        ));
                    }
                }
            }

            let patch = ChannelPatch {
                name: msg.name,
                position: msg.position,
                max_users: msg.max_users,
                description_hash: None, // TODO: handle description blob
                parent_id: msg.parent.map(|p| Some(p)),
            };

            if let Err(e) = channels
                .edit_channel(channel_id, patch, msg.links_add, msg.links_remove)
                .await
            {
                tracing::warn!("update_channel {channel_id} failed: {:?}", e);
                return Ok(());
            }

            // Channel update is logged and broadcast via a single ChannelRepository::commit().
            // Per-client subscribers will pick up the ChannelState delta.
        }
    }

    Ok(())
}
