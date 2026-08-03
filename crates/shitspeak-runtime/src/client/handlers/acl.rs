use shitspeak_state::{ACL, ACLPermissions, ChannelOp};

use crate::{
    client::Client,
    errors::MessageHandlerError,
    localization::{TextKey, text},
    messages::{
        Message,
        encoder::{Acl as EncoderAcl, ChanAcl},
    },
    server::Server,
};
use enumflags2::_internal::RawBitFlags;
use std::sync::Arc;

pub async fn handle_acl(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: EncoderAcl,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated() {
        return Err(MessageHandlerError::protocol_violation(
            "ACL message received before authentication",
        ));
    }

    let channel_id = msg.channel_id;
    tracing::debug!(
        session = u32::from(sender.get_session_id()),
        channel_id,
        query = msg.query,
        num_acls = msg.acls.len(),
        "ACL handler"
    );
    let server_id = sender.server_id();

    // Verify channel exists
    if server
        .get_channels()
        .get_channel_in_server(&server_id, channel_id)
        .await
        .is_none()
    {
        return Ok(());
    }

    let target_perm =
        crate::client::acl::compute_permissions_for_client(server, sender, channel_id).await;
    if !target_perm.contains(ACLPermissions::Write) {
        return Err(MessageHandlerError::PermissionDenied(
            shitspeak_messages::messages::encoder::PermissionDenied {
                r#type: shitspeak_messages::messages::encoder::DenyType::Permission,
                session: u32::from(sender.get_session_id()),
                channel_id: Some(channel_id),
                reason: Some(text(sender.language(), TextKey::WriteAclRequired)),
                name: None,
                permission: Some(ACLPermissions::Write.bits()),
            }
            .into(),
        ));
    }

    if msg.query.unwrap_or(false) {
        // ── Query mode: walk tree upward, serialize ACLs ─────────────────
        let channel = server
            .get_channels()
            .get_channel_in_server(&server_id, channel_id)
            .await
            .unwrap();
        let ancestors = server
            .get_channels()
            .get_ancestors_in_server(&server_id, channel_id)
            .await;

        let mut flattened_acls: Vec<ChanAcl> = Vec::with_capacity((ancestors.len() + 1) * 5);
        let mut chain: Vec<&shitspeak_state::Channel> = Vec::with_capacity(ancestors.len() + 1);
        chain.push(&channel);
        if channel.inherit_acl {
            for ancestor in &ancestors {
                chain.push(ancestor);
                if !ancestor.inherit_acl {
                    break;
                }
            }
        }

        // Mumble sends ACLs in root-to-target order so local entries stay below
        // inherited entries in the client editor after a query/reload cycle.
        for ch in chain.into_iter().rev() {
            let inherited = ch.id != channel_id;
            // For inherited (ancestor) channels, only include ACLs that apply to subs
            flattened_acls.extend(
                ch.acls
                    .iter()
                    .filter(|acl| !inherited || acl.apply_subs)
                    .map(|acl| ChanAcl {
                        apply_here: acl.apply_here,
                        apply_subs: acl.apply_subs,
                        inherited,
                        user_id: acl.user_id.map(|uid| uid as u32),
                        group: acl.group.clone(),
                        grant: acl.allow.bits(),
                        deny: acl.deny.bits(),
                    }),
            );
        }

        // Send back a single ACL response with target + inherited ACL entries.
        let acl_msg = EncoderAcl {
            channel_id,
            inherit_acls: Some(channel.inherit_acl),
            groups: Vec::new(),
            acls: flattened_acls,
            query: None,
        };
        sender
            .write_proto_message(&Message::ACL(acl_msg.into()))
            .await?;
    } else {
        // ── Update mode: apply new ACLs ──────────────────────────────────

        if !msg.groups.is_empty() {
            return Err(MessageHandlerError::PermissionDenied(
                shitspeak_messages::messages::encoder::PermissionDenied {
                    r#type: shitspeak_messages::messages::encoder::DenyType::Permission,
                    session: u32::from(sender.get_session_id()),
                    channel_id: Some(channel_id),
                    reason: Some("ACL group updates are not supported".into()),
                    name: None,
                    permission: Some(ACLPermissions::Write.bits()),
                }
                .into(),
            ));
        }

        let mut new_acls = Vec::new();
        for proto_acl in &msg.acls {
            new_acls.push(ACL {
                user_id: proto_acl.user_id,
                group: proto_acl.group.clone(),
                apply_here: proto_acl.apply_here,
                apply_subs: proto_acl.apply_subs,
                allow: enumflags2::BitFlags::from_bits_truncate(proto_acl.grant),
                deny: enumflags2::BitFlags::from_bits_truncate(proto_acl.deny),
            });
        }

        let inherit_acl = msg.inherit_acls.unwrap_or(true);

        // Safety fallback: if a registered non-superuser would lose Write,
        // include a Write|Traverse ACL in the same SetAcls transaction.
        if server.get_preserve_write_acl_on_edit()
            && sender.is_registered()
            && !sender.is_superuser()
        {
            let (channel, ancestors) = server
                .get_channels()
                .get_channel_with_ancestors_in_server(&server_id, channel_id)
                .await;
            if let Some(channel) = channel {
                let mut channel = channel.as_ref().clone();
                channel.inherit_acl = inherit_acl;
                channel.acls = new_acls.clone();
                channel.clear_effective_acl_cache();

                let user_id = sender.get_user_id();
                let groups: Vec<String> = sender.get_groups_clone().into_iter().collect();
                let group_refs: Vec<&str> = groups.iter().map(|s| s.as_str()).collect();
                let tokens: Vec<String> = sender.get_tokens_clone().into_iter().collect();
                let token_refs: Vec<&str> = tokens.iter().map(|s| s.as_str()).collect();
                let home_channel_id = sender.get_current_channel_id();
                let home_ancestors: Vec<u32> = if home_channel_id == channel_id {
                    ancestors.iter().map(|ancestor| ancestor.id).collect()
                } else {
                    server
                        .get_channels()
                        .get_ancestors_in_server(&server_id, home_channel_id)
                        .await
                        .into_iter()
                        .map(|ancestor| ancestor.id)
                        .collect()
                };
                let home_channel =
                    shitspeak_state::ChannelHierarchy::new(home_channel_id, &home_ancestors);
                let membership = shitspeak_state::ClientMembershipQuery::new(
                    &group_refs,
                    user_id.is_some(),
                    &token_refs,
                    sender.get_certificate_hash(),
                    sender.is_verified(),
                    Some(sender.get_real_ip_address()),
                )
                .with_home_channel(home_channel);

                let post_write = shitspeak_state::evaluate_permission_shared(
                    &channel,
                    &ancestors,
                    user_id,
                    &membership,
                );
                if !post_write.contains(ACLPermissions::Write) {
                    if let Some(uid) = user_id {
                        new_acls.push(ACL {
                            user_id: Some(uid),
                            group: None,
                            apply_here: true,
                            apply_subs: false,
                            allow: ACLPermissions::Write | ACLPermissions::Traverse,
                            deny: enumflags2::BitFlags::empty(),
                        });
                    }
                }
            }
        }

        let op = ChannelOp::SetAcls {
            channel_id,
            inherit_acl,
            acls: new_acls.clone(),
        };
        if let Err(e) = server
            .get_channels()
            .validate_s2s_op_in_server(&server_id, &op)
            .await
        {
            tracing::warn!("set_acls {channel_id} failed: {:?}", e);
            return Ok(());
        }
        let proposed_s2s = server
            .s2s_manager()
            .start_channel_op_proposal(Some(&server_id), op.clone())
            .await;
        if proposed_s2s.should_apply_locally() {
            let committed = match server
                .get_channels()
                .set_acls_with_committed_operation_if_changed_in_server(
                    &server_id,
                    channel_id,
                    inherit_acl,
                    new_acls,
                )
                .await
            {
                Ok(committed) => committed,
                Err(e) => {
                    tracing::warn!("set_acls {channel_id} failed: {:?}", e);
                    return Ok(());
                }
            };
            let Some(committed) = committed else {
                tracing::trace!(channel_id, "skipping unchanged ACL update");
                return Ok(());
            };
            server.reevaluate_speak_after_acl_change(&committed).await;
        } else {
            let Some(mut proposal) = proposed_s2s.into_started() else {
                return Err(super::channel_op_propose_failed(
                    u32::from(sender.get_session_id()),
                    Some(channel_id),
                    None,
                ));
            };
            let accepted = proposal.accepted().await;
            if !accepted.is_proposed() {
                return Err(super::channel_op_propose_failed(
                    u32::from(sender.get_session_id()),
                    Some(channel_id),
                    accepted.failure_reason(),
                ));
            }
            match super::channel_state::wait_accepted_channel_op_commit_grace(sender, proposal)
                .await?
            {
                super::channel_state::AcceptedChannelOpCommit::Completed(result) => {
                    if !result.is_proposed() {
                        return Err(super::channel_op_propose_failed(
                            u32::from(sender.get_session_id()),
                            Some(channel_id),
                            result.failure_reason(),
                        ));
                    }
                }
                super::channel_state::AcceptedChannelOpCommit::Pending(proposal) => {
                    super::channel_state::spawn_channel_op_completion_log(
                        proposal, "set_acls", channel_id,
                    );
                }
            }
        }

        // Permission refresh fanout is handled in each client's channel-log
        // broadcast loop (best-effort, no replay).
    }

    Ok(())
}
