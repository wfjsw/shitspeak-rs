use std::sync::Arc;

use shitspeak_state::{ACL, ACLPermissions, Channel, ChannelOp, ChannelPatch};

use crate::{
    client::Client,
    errors::MessageHandlerError,
    localization::{TextKey, text},
    messages::{
        Message,
        encoder::{ChannelState, DenyType, PermissionDenied, TextMessage},
    },
    s2s::{ChannelOpCompletion, ChannelOpProposal, ChannelOpProposeResult},
    server::Server,
};

const CHANNEL_SETTINGS_PENDING_NOTICE_GRACE: std::time::Duration =
    std::time::Duration::from_millis(25);
const CHANNEL_REPOSITORY_REQUEST_SUBMITTED: &str =
    "Channel settings update submitted. Waiting for repository admission.";
const CHANNEL_REPOSITORY_REQUEST_COMMITTED: &str = "Channel settings update committed.";
const CHANNEL_REPOSITORY_REQUEST_UNABLE_TO_COMMIT: &str =
    "Channel settings update was unable to commit.";

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
                Some(n) if !n.is_empty() => {
                    if n.len() > crate::rate_limits::MAX_CHANNEL_NAME_BYTES {
                        return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
                            r#type: DenyType::TextTooLong,
                            session: u32::from(sender.get_session_id()),
                            channel_id: None,
                            reason: Some(
                                format!(
                                    "channel name exceeds {} bytes",
                                    crate::rate_limits::MAX_CHANNEL_NAME_BYTES
                                )
                                .into(),
                            ),
                            name: None,
                            permission: None,
                        }));
                    }
                    n
                }
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
            // Rate-limit temporary channel creation per client: even though a
            // temp channel only persists while its creator occupies it, an
            // attacker with TempChannel could still churn unlimited create
            // operations (each a WAL/S2S op plus optional description blob).
            if is_temp {
                let session_id = u32::from(session);
                if !server.temp_channel_rate_limiter().try_acquire(&session_id) {
                    return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
                        r#type: DenyType::TemporaryChannel,
                        session: session_id,
                        channel_id: Some(parent_id),
                        reason: Some("temporary channel creation rate limit exceeded".into()),
                        name: None,
                        permission: None,
                    }));
                }
            }
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
                .start_channel_op_proposal(Some(&server_id), op.clone())
                .await;
            if proposed_s2s.should_apply_locally() {
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
            } else {
                let Some(mut proposal) = proposed_s2s.into_started() else {
                    return Err(super::channel_op_propose_failed(
                        u32::from(session),
                        Some(parent_id),
                        None,
                    ));
                };
                let accepted = proposal.accepted().await;
                if !accepted.is_proposed() {
                    return Err(super::channel_op_propose_failed(
                        u32::from(session),
                        Some(parent_id),
                        accepted.failure_reason(),
                    ));
                }
                match wait_accepted_channel_op_commit_grace(sender, proposal).await? {
                    AcceptedChannelOpCommit::Completed(result) => {
                        if !result.is_proposed() {
                            return Err(super::channel_op_propose_failed(
                                u32::from(session),
                                Some(parent_id),
                                result.failure_reason(),
                            ));
                        }
                        if is_temp {
                            move_temp_channel_creator_after_commit(
                                server, sender, &server_id, new_id,
                            )
                            .await;
                        }
                    }
                    AcceptedChannelOpCommit::Pending(proposal) => {
                        if is_temp {
                            spawn_temp_channel_creator_move_after_commit(
                                Arc::clone(server),
                                Arc::clone(sender),
                                server_id.clone(),
                                new_id,
                                proposal,
                            );
                        } else {
                            spawn_channel_op_completion_log(
                                Arc::clone(sender),
                                proposal,
                                "create_channel",
                                new_id,
                            );
                        }
                    }
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
                if let Some(name) = &msg.name {
                    if name.len() > crate::rate_limits::MAX_CHANNEL_NAME_BYTES {
                        return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
                            r#type: DenyType::TextTooLong,
                            session: u32::from(session),
                            channel_id: Some(channel_id),
                            reason: Some(
                                format!(
                                    "channel name exceeds {} bytes",
                                    crate::rate_limits::MAX_CHANNEL_NAME_BYTES
                                )
                                .into(),
                            ),
                            name: None,
                            permission: None,
                        }));
                    }
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
            let proposed_s2s = server
                .s2s_manager()
                .start_channel_op_proposal(Some(&server_id), op)
                .await;
            if proposed_s2s.should_apply_locally() {
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
            } else {
                let Some(mut proposal) = proposed_s2s.into_started() else {
                    return Err(super::channel_op_propose_failed(
                        u32::from(session),
                        Some(channel_id),
                        None,
                    ));
                };
                let accepted = proposal.accepted().await;
                if !accepted.is_proposed() {
                    return Err(super::channel_op_propose_failed(
                        u32::from(session),
                        Some(channel_id),
                        accepted.failure_reason(),
                    ));
                }
                match wait_accepted_channel_op_commit_grace(sender, proposal).await? {
                    AcceptedChannelOpCommit::Completed(result) => {
                        if !result.is_proposed() {
                            return Err(super::channel_op_propose_failed(
                                u32::from(session),
                                Some(channel_id),
                                result.failure_reason(),
                            ));
                        }
                    }
                    AcceptedChannelOpCommit::Pending(proposal) => {
                        spawn_channel_op_completion_log(
                            Arc::clone(sender),
                            proposal,
                            "edit_channel",
                            channel_id,
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

pub(super) enum AcceptedChannelOpCommit {
    Completed(ChannelOpProposeResult),
    Pending(ChannelOpProposal),
}

pub(super) async fn wait_accepted_channel_op_commit_grace(
    sender: &Arc<Box<Client>>,
    mut proposal: ChannelOpProposal,
) -> Result<AcceptedChannelOpCommit, MessageHandlerError> {
    match proposal
        .wait_completed_for(CHANNEL_SETTINGS_PENDING_NOTICE_GRACE)
        .await
    {
        ChannelOpCompletion::Completed(result) => Ok(AcceptedChannelOpCommit::Completed(result)),
        ChannelOpCompletion::Pending => {
            send_channel_repository_notice(sender, CHANNEL_REPOSITORY_REQUEST_SUBMITTED).await?;
            Ok(AcceptedChannelOpCommit::Pending(proposal))
        }
    }
}

pub(super) fn spawn_channel_op_completion_log(
    sender: Arc<Box<Client>>,
    proposal: ChannelOpProposal,
    operation: &'static str,
    channel_id: u32,
) {
    tokio::spawn(async move {
        let result = proposal.completed_after_acceptance().await;
        if let Err(error) =
            send_channel_repository_notice(&sender, channel_repository_completion_notice(&result))
                .await
        {
            tracing::warn!(
                operation,
                channel_id,
                ?error,
                "failed to send channel operation completion notice"
            );
        }
        if !result.is_proposed() {
            tracing::warn!(
                operation,
                channel_id,
                "s2s channel operation failed after acceptance"
            );
        }
    });
}

fn spawn_temp_channel_creator_move_after_commit(
    server: Arc<Box<Server>>,
    sender: Arc<Box<Client>>,
    server_id: String,
    channel_id: u32,
    proposal: ChannelOpProposal,
) {
    tokio::spawn(async move {
        let result = proposal.completed_after_acceptance().await;
        if let Err(error) =
            send_channel_repository_notice(&sender, channel_repository_completion_notice(&result))
                .await
        {
            tracing::warn!(
                channel_id,
                ?error,
                "failed to send temporary channel operation completion notice"
            );
        }
        if !result.is_proposed() {
            tracing::warn!(
                channel_id,
                "s2s temporary channel create failed after acceptance"
            );
            return;
        }
        move_temp_channel_creator_after_commit(&server, &sender, &server_id, channel_id).await;
    });
}

async fn move_temp_channel_creator_after_commit(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    server_id: &str,
    channel_id: u32,
) {
    let session = sender.get_session_id();
    let Some(current) = server
        .get_clients()
        .get_client_in_server(server_id, session)
        .await
    else {
        return;
    };
    if current.client_instance_id() != sender.client_instance_id() {
        return;
    }
    if server
        .get_channels()
        .get_channel_in_server(server_id, channel_id)
        .await
        .is_none()
    {
        tracing::warn!(
            channel_id,
            "temporary channel create completed without local channel"
        );
        return;
    }
    sender.set_current_channel_id(
        channel_id,
        server.get_clients(),
        server.get_channels().current_version_in_server(server_id),
    );
}

async fn send_channel_repository_notice(
    sender: &Arc<Box<Client>>,
    notice: &'static str,
) -> Result<(), MessageHandlerError> {
    let message = Message::TextMessage(
        TextMessage {
            actor: None,
            session: vec![u32::from(sender.get_session_id())],
            channel_id: Vec::new(),
            tree_id: Vec::new(),
            message: notice.to_owned(),
        }
        .into(),
    );
    sender.write_proto_message(&message).await?;
    Ok(())
}

fn channel_repository_completion_notice(result: &ChannelOpProposeResult) -> &'static str {
    if result.is_proposed() {
        CHANNEL_REPOSITORY_REQUEST_COMMITTED
    } else {
        CHANNEL_REPOSITORY_REQUEST_UNABLE_TO_COMMIT
    }
}

async fn add_missing_creator_temp_channel_acls(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    parent_id: u32,
    channel: &mut Channel,
) {
    let (user_id, group) = match sender.get_user_id() {
        Some(user_id) => (Some(user_id), None),
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
    let home_channel_id = sender.get_current_channel_id();
    let home_ancestors: Vec<u32> = if home_channel_id == channel.id {
        ancestors.iter().map(|ancestor| ancestor.id).collect()
    } else {
        channels
            .get_ancestors_in_server(&sender.server_id(), home_channel_id)
            .await
            .into_iter()
            .map(|ancestor| ancestor.id)
            .collect()
    };
    let home_channel = shitspeak_state::ChannelHierarchy::new(home_channel_id, &home_ancestors);
    let membership = shitspeak_state::ClientMembershipQuery::new(
        &group_refs,
        user_id.is_some(),
        &token_refs,
        sender.get_certificate_hash(),
        sender.is_verified(),
        Some(sender.get_real_ip_address()),
    )
    .with_home_channel(home_channel);

    shitspeak_state::evaluate_permission_with_behavior_shared(
        channel,
        &ancestors,
        user_id,
        &membership,
        server.get_explicit_enter_deny_overrides_write(),
    )
}

async fn description_blob_patch(
    server: &Arc<Box<Server>>,
    description: Option<&str>,
) -> std::io::Result<Option<Option<String>>> {
    match description {
        Some("") => Ok(Some(None)),
        Some(description) => {
            if description.len() > crate::rate_limits::MAX_CHANNEL_DESCRIPTION_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "channel description exceeds {} bytes",
                        crate::rate_limits::MAX_CHANNEL_DESCRIPTION_BYTES
                    ),
                ));
            }
            server
                .get_channel_blobs()
                .put(description.as_bytes())
                .await
                .map(|hash| Some(Some(hash)))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CHANNEL_REPOSITORY_REQUEST_COMMITTED, CHANNEL_REPOSITORY_REQUEST_SUBMITTED,
        CHANNEL_REPOSITORY_REQUEST_UNABLE_TO_COMMIT, channel_repository_completion_notice,
    };
    use crate::s2s::ChannelOpProposeResult;

    #[test]
    fn pending_channel_update_uses_repository_admission_notice() {
        assert_eq!(
            CHANNEL_REPOSITORY_REQUEST_SUBMITTED,
            "Channel settings update submitted. Waiting for repository admission."
        );
    }

    #[test]
    fn completed_channel_update_uses_terminal_repository_notices() {
        assert_eq!(
            CHANNEL_REPOSITORY_REQUEST_COMMITTED,
            "Channel settings update committed."
        );
        assert_eq!(
            CHANNEL_REPOSITORY_REQUEST_UNABLE_TO_COMMIT,
            "Channel settings update was unable to commit."
        );
        assert_eq!(
            channel_repository_completion_notice(&ChannelOpProposeResult::Proposed),
            CHANNEL_REPOSITORY_REQUEST_COMMITTED
        );
        assert_eq!(
            channel_repository_completion_notice(&ChannelOpProposeResult::failed("quorum lost")),
            CHANNEL_REPOSITORY_REQUEST_UNABLE_TO_COMMIT
        );
    }
}
