use std::sync::Arc;

use crate::{
    acl::{ACL, ACLPermissions},
    channel_repository::ChannelOp,
    channels::{Channel, ChannelPatch},
    client::Client,
    errors::MessageHandlerError,
    localization::{TextKey, text},
    messages::encoder::{ChannelState, DenyType, PermissionDenied},
    server::Server,
};

pub async fn handle_channel_state(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: ChannelState,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated() {
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
    let server_id = sender.server_id();

    match msg.channel_id {
        None => {
            let parent_id = msg.parent.unwrap_or(0);
            let name = match msg.name {
                Some(n) if !n.is_empty() => n,
                _ => {
                    return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
                        r#type: DenyType::ChannelName,
                        session: u32::from(sender.get_session_id()),
                        channel_id: None,
                        reason: Some(text(sender.language(), TextKey::ChannelNameRequired)),
                        name: None,
                        permission: None,
                    }));
                }
            };

            if let Some(parent) = channels.get_channel_in_server(&server_id, parent_id).await {
                if parent.is_temporary() {
                    return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
                        r#type: DenyType::TemporaryChannel,
                        session: u32::from(session),
                        channel_id: Some(parent_id),
                        reason: None,
                        name: None,
                        permission: None,
                    }));
                }
            } else {
                return Ok(());
            }

            let is_temp = msg.temporary.unwrap_or(false);
            let required_permission = if is_temp {
                ACLPermissions::TempChannel
            } else {
                ACLPermissions::MakeChannel
            };
            let creator_parent_perms =
                crate::client::acl::compute_permissions_for_client(server, sender, parent_id).await;
            if !creator_parent_perms.contains(required_permission) {
                return Err(MessageHandlerError::PermissionDenied(
                    PermissionDenied::for_permission(
                        u32::from(session),
                        Some(parent_id),
                        required_permission,
                    ),
                ));
            }

            let new_id = channels
                .next_channel_id_in_server(&server_id, is_temp)
                .await;
            let description_hash = match description_blob_patch(server, msg.description.as_deref())
                .await
            {
                Ok(description_hash) => description_hash.flatten(),
                Err(e) => {
                    tracing::warn!(error = %e, channel_id = new_id, "create_channel failed to store description blob");
                    return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
                        r#type: DenyType::Text,
                        session: u32::from(sender.get_session_id()),
                        channel_id: None,
                        reason: Some(format!("Failed to create channel: {e}").into()),
                        name: None,
                        permission: None,
                    }));
                }
            };

            let mut new_ch = Channel::new(
                new_id,
                name,
                msg.position.unwrap_or(0),
                msg.max_users.unwrap_or(0),
                Some(parent_id),
            );
            new_ch.description_hash = description_hash;
            if is_temp && server.get_grant_temp_channel_creator_acl() {
                add_missing_creator_temp_channel_acls(server, sender, parent_id, &mut new_ch).await;
            }

            let op = ChannelOp::CreateChannel {
                channel: new_ch.clone(),
            };
            if let Err(e) = channels.validate_s2s_op_in_server(&server_id, &op).await {
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
            let proposed_s2s = server
                .s2s_manager()
                .propose_channel_op(Some(&server_id), op.clone())
                .await;
            if proposed_s2s {
                if is_temp {
                    sender.set_current_channel_id(
                        new_id,
                        server.get_clients(),
                        channels.current_version_in_server(&server_id),
                    );
                }
            } else {
                let created = match channels.create_channel_in_server(&server_id, new_ch).await {
                    Ok(channel) => channel,
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
                // Move the creator into the newly created temporary channel.
                if is_temp {
                    sender.set_current_channel_id(
                        created.id,
                        server.get_clients(),
                        channels.current_version_in_server(&server_id),
                    );
                }
            }
        }

        Some(channel_id) => {
            let channel = match channels.get_channel_in_server(&server_id, channel_id).await {
                Some(ch) => ch,
                None => return Ok(()),
            };

            let perms =
                crate::client::acl::compute_permissions_for_client(server, sender, channel_id)
                    .await;
            let has_write = perms.contains(ACLPermissions::Write);

            if msg.name.is_some() {
                if channel_id == 0 {
                    return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
                        r#type: DenyType::Permission,
                        session: u32::from(session),
                        channel_id: Some(0),
                        reason: Some(text(sender.language(), TextKey::CannotRenameRootChannel)),
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

            if (msg.description.is_some() || msg.position.is_some() || msg.max_users.is_some())
                && !has_write
            {
                return Err(MessageHandlerError::PermissionDenied(
                    PermissionDenied::for_permission(
                        u32::from(session),
                        Some(channel_id),
                        ACLPermissions::Write,
                    ),
                ));
            }

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

                    if let Some(parent) =
                        channels.get_channel_in_server(&server_id, new_parent).await
                    {
                        if parent.is_temporary() {
                            return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
                                r#type: DenyType::TemporaryChannel,
                                session: u32::from(session),
                                channel_id: Some(new_parent),
                                reason: None,
                                name: None,
                                permission: None,
                            }));
                        }
                    } else {
                        return Ok(());
                    }

                    let required_permission = if channel.is_temporary() {
                        ACLPermissions::TempChannel
                    } else {
                        ACLPermissions::MakeChannel
                    };
                    let parent_perms = crate::client::acl::compute_permissions_for_client(
                        server, sender, new_parent,
                    )
                    .await;
                    if !parent_perms.contains(required_permission) {
                        return Err(MessageHandlerError::PermissionDenied(
                            PermissionDenied::for_permission(
                                u32::from(session),
                                Some(new_parent),
                                required_permission,
                            ),
                        ));
                    }
                }
            }

            if !msg.links_add.is_empty() || !msg.links_remove.is_empty() {
                if !perms.contains(ACLPermissions::LinkChannel) {
                    return Err(MessageHandlerError::PermissionDenied(
                        PermissionDenied::for_permission(
                            u32::from(session),
                            Some(channel_id),
                            ACLPermissions::LinkChannel,
                        ),
                    ));
                }
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

            let description_hash =
                match description_blob_patch(server, msg.description.as_deref()).await {
                    Ok(description_hash) => description_hash,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            channel_id,
                            "update_channel failed to store description blob"
                        );
                        return Ok(());
                    }
                };

            let patch = ChannelPatch {
                name: msg.name,
                position: msg.position,
                max_users: msg.max_users,
                description_hash,
                parent_id: msg.parent.map(|p| Some(p)),
            };

            let op = ChannelOp::EditChannel {
                id: channel_id,
                patch: patch.clone(),
                links_add: msg.links_add.clone(),
                links_remove: msg.links_remove.clone(),
            };
            if let Err(e) = channels.validate_s2s_op_in_server(&server_id, &op).await {
                tracing::warn!("update_channel {channel_id} failed: {:?}", e);
                return Ok(());
            }
            if !server
                .s2s_manager()
                .propose_channel_op(Some(&server_id), op)
                .await
            {
                if let Err(e) = channels
                    .edit_channel_in_server(
                        &server_id,
                        channel_id,
                        patch,
                        msg.links_add,
                        msg.links_remove,
                    )
                    .await
                {
                    tracing::warn!("update_channel {channel_id} failed: {:?}", e);
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

async fn add_missing_creator_temp_channel_acls(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    parent_id: u32,
    channel: &mut Channel,
) {
    let (user_id, group) = match sender.get_user_id() {
        Some(user_id) => (Some(user_id as i32), None),
        None => match sender.get_certificate_hash() {
            Some(hash) => (None, Some(format!("${}", hex::encode(hash)))),
            None => return,
        },
    };

    let required = ACLPermissions::Write | ACLPermissions::Enter | ACLPermissions::Speak;
    let inherited = inherited_creator_permissions(server, sender, parent_id, channel).await;
    let missing = required & !inherited;
    if missing.is_empty() {
        return;
    }

    channel.acls.push(ACL {
        user_id,
        group,
        apply_here: true,
        apply_subs: false,
        allow: missing,
        deny: enumflags2::BitFlags::empty(),
    });
}

async fn inherited_creator_permissions(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    parent_id: u32,
    channel: &Channel,
) -> enumflags2::BitFlags<ACLPermissions> {
    let channels = server.get_channels();
    let mut ancestors = Vec::new();
    if let Some(parent) = channels
        .get_channel_in_server(&sender.server_id(), parent_id)
        .await
    {
        ancestors.push(parent);
    }
    ancestors.extend(
        channels
            .get_ancestors_in_server(&sender.server_id(), parent_id)
            .await,
    );

    let user_id = sender.get_user_id();
    let groups: Vec<String> = sender.get_groups_clone().into_iter().collect();
    let group_refs: Vec<&str> = groups.iter().map(String::as_str).collect();
    let tokens: Vec<String> = sender.get_tokens_clone().into_iter().collect();
    let token_refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
    let membership = crate::client::group::ClientMembershipQuery {
        groups: &group_refs,
        authenticated: user_id.is_some(),
        access_tokens: &token_refs,
        cert_hash: sender.get_certificate_hash(),
        has_verified_cert_chain: sender.is_verified(),
        ip_address: Some(sender.get_real_ip_address()),
        asn: None,
        country_code: None,
    };

    crate::acl::evaluate_permission_with_behavior(
        channel,
        &ancestors,
        user_id,
        &membership,
        channel.id,
        server.get_explicit_enter_deny_overrides_write(),
    )
}

async fn description_blob_patch(
    server: &Arc<Box<Server>>,
    description: Option<&str>,
) -> std::io::Result<Option<Option<String>>> {
    match description {
        Some("") => Ok(Some(None)),
        Some(description) => server
            .get_channel_blobs()
            .put(description.as_bytes())
            .await
            .map(|hash| Some(Some(hash))),
        None => Ok(None),
    }
}
