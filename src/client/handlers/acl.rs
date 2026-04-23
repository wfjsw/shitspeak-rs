use std::sync::Arc;

use crate::{
    acl::ACL,
    client::Client,
    errors::MessageHandlerError,
    messages::{encoder::Acl as EncoderAcl, Message, WriteMessageExt},
    server::Server,
};

pub async fn handle_acl(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: EncoderAcl,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated().await {
        return Ok(());
    }

    let channel_id = msg.channel_id;
    tracing::debug!(session = u32::from(sender.get_session_id()), channel_id, query = msg.query, num_acls = msg.acls.len(), "ACL handler");

    // Verify channel exists
    if server.get_channels().get_channel(channel_id).await.is_none() {
        return Ok(());
    }

    if msg.query.unwrap_or(false) {
        // ── Query mode: walk tree upward, serialize ACLs ─────────────────
        let channel = server.get_channels().get_channel(channel_id).await.unwrap();
        let ancestors = server.get_channels().get_ancestors(channel_id).await;

        let mut acls = Vec::new();
        let mut inherit = true;

        // Collect ACLs from target channel and ancestors
        let mut chain: Vec<crate::channels::Channel> = vec![channel.clone()];
        chain.extend(ancestors.clone());

        for ch in &chain {
            for acl in &ch.acls {
                let proto_acl = crate::mumble_proto::acl::ChanAcl {
                    apply_here: Some(acl.apply_here),
                    apply_subs: Some(acl.apply_subs),
                    inherited: Some(ch.id != channel_id),
                    user_id: acl.user_id.map(|uid| uid as u32),
                    group: acl.group.clone(),
                    grant: Some(acl.allow.bits()),
                    deny: Some(acl.deny.bits()),
                };
                // Collect into a per-channel ACL message
                match acls.iter_mut().find(|a: &&mut EncoderAcl| a.channel_id == ch.id) {
                    Some(existing) => existing.acls.push(proto_acl),
                    None => acls.push(EncoderAcl {
                        channel_id: ch.id,
                        inherit_acls: Some(ch.inherit_acl),
                        groups: Vec::new(),
                        acls: vec![proto_acl],
                        query: Some(true),
                    }),
                }
            }
            inherit = ch.inherit_acl;
            if !inherit {
                break;
            }
        }

        // Send back the ACL list
        for acl_msg in acls {
            sender.write_proto_message(&Message::ACL(acl_msg.into())).await?;
        }
    } else {
        // ── Update mode: apply new ACLs ──────────────────────────────────
        // TODO: check Write permission on channel and root

        let mut new_acls = Vec::new();
        for proto_acl in &msg.acls {
            new_acls.push(ACL {
                user_id: proto_acl.user_id.map(|uid| uid as i32),
                group: proto_acl.group.clone(),
                apply_here: proto_acl.apply_here.unwrap_or(true),
                apply_subs: proto_acl.apply_subs.unwrap_or(false),
                allow: enumflags2::BitFlags::from_bits_truncate(proto_acl.grant.unwrap_or(0)),
                deny: enumflags2::BitFlags::from_bits_truncate(proto_acl.deny.unwrap_or(0)),
            });
        }

        let inherit_acl = msg.inherit_acls.unwrap_or(true);

        if let Err(e) = server.get_channels().set_acls(channel_id, inherit_acl, new_acls).await {
            tracing::warn!("set_acls {channel_id} failed: {:?}", e);
            return Ok(());
        }

        // Send updated PermissionQuery to all affected clients
        let all_clients = server.get_clients().get_all_clients().await;
        for client in &all_clients {
            if !client.is_authenticated().await {
                continue;
            }
            let client_ch = client.get_current_channel_id().await;
            // Check if this client is in the affected channel or a descendant
            let ancestors = server.get_channels().get_ancestors(client_ch).await;
            let affected = client_ch == channel_id
                || ancestors.iter().any(|a| a.id == channel_id);
            if affected {
                // Recompute and send permissions
                let perms = compute_permissions_for_client(server, client, client_ch).await;
                let reply: Message = crate::messages::encoder::PermissionQuery {
                    channel_id: Some(client_ch),
                    permissions: Some(perms.bits()),
                    flush: Some(false),
                }.into();
                let _ = client.write_proto_message(&reply).await;
            }
        }
    }

    Ok(())
}

/// Compute effective permissions for a client on a given channel.
pub(crate) async fn compute_permissions_for_client(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_id: u32,
) -> enumflags2::BitFlags<crate::acl::ACLPermissions> {
    let Some(channel) = server.get_channels().get_channel(channel_id).await else {
        return enumflags2::BitFlags::empty();
    };
    let ancestors = server.get_channels().get_ancestors(channel_id).await;

    let user_id = client.get_user_id().await;
    let groups: Vec<String> = client.get_groups_clone().await.into_iter().collect();
    let group_refs: Vec<&str> = groups.iter().map(|s| s.as_str()).collect();
    let tokens: Vec<String> = client.get_tokens_clone().await.into_iter().collect();
    let token_refs: Vec<&str> = tokens.iter().map(|s| s.as_str()).collect();

    let membership = crate::client::group::ClientMembershipQuery {
        groups: &group_refs,
        authenticated: client.is_authenticated().await,
        access_tokens: &token_refs,
        cert_hash: client.get_certificate_hash(),
        has_verified_cert_chain: client.has_certificate(),
        ip_address: Some(client.get_real_ip_address()),
        asn: None,
        country_code: None,
    };

    crate::acl::evaluate_permission(
        &channel,
        &ancestors,
        user_id,
        &membership,
        channel_id,
    )
}

