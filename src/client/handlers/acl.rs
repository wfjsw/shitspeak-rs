use std::sync::Arc;
use enumflags2::_internal::RawBitFlags;
use crate::{
    acl::{ACL, ACLPermissions},
    client::Client,
    errors::MessageHandlerError,
    messages::{Message, WriteMessageExt, encoder::{Acl as EncoderAcl, ChanAcl}},
    server::Server,
};

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
    tracing::debug!(session = u32::from(sender.get_session_id()), channel_id, query = msg.query, num_acls = msg.acls.len(), "ACL handler");

    // Verify channel exists
    if server.get_channels().get_channel(channel_id).await.is_none() {
        return Ok(());
    }

    let target_perm = crate::client::acl::compute_permissions_for_client(server, sender, channel_id).await;
    if !target_perm.contains(ACLPermissions::Write) {
        return Err(MessageHandlerError::PermissionDenied(
            crate::messages::encoder::PermissionDenied {
                r#type: crate::messages::encoder::DenyType::Permission,
                session: u32::from(sender.get_session_id()),
                channel_id: Some(channel_id),
                reason: Some("Write permission required to modify ACLs".into()),
                name: None,
                permission: Some(ACLPermissions::Write.bits()),
            }.into()
        ));
    }

    if msg.query.unwrap_or(false) {
        // ── Query mode: walk tree upward, serialize ACLs ─────────────────
        let channel = server.get_channels().get_channel(channel_id).await.unwrap();
        let ancestors = server.get_channels().get_ancestors(channel_id).await;

        let mut flattened_acls: Vec<ChanAcl> = Vec::with_capacity(ancestors.len() * 5); // heuristic initial capacity
        let mut inherit = true;

        // Collect ACLs from target channel and ancestors
        let mut chain: Vec<crate::channels::Channel> = vec![channel.clone()];
        chain.extend(ancestors.clone());

        for ch in &chain {
            let inherited = ch.id != channel_id;
            // For inherited (ancestor) channels, only include ACLs that apply to subs
            flattened_acls.extend(ch.acls.iter().filter(|acl| !inherited || acl.apply_subs).map(|acl| ChanAcl {
                apply_here: acl.apply_here,
                apply_subs: acl.apply_subs,
                inherited,
                user_id: acl.user_id.map(|uid| uid as u32),
                group: acl.group.clone(),
                grant: acl.allow.bits(),
                deny: acl.deny.bits(),
            }));

            inherit = ch.inherit_acl;
            if !inherit {
                break;
            }
        }

        // Send back a single ACL response with target + inherited ACL entries.
        let acl_msg = EncoderAcl {
            channel_id,
            inherit_acls: Some(channel.inherit_acl),
            groups: Vec::new(),
            acls: flattened_acls,
            query: None,
        };
        sender.write_proto_message(&Message::ACL(acl_msg.into())).await?;
    } else {
        // ── Update mode: apply new ACLs ──────────────────────────────────

        let mut new_acls = Vec::new();
        for proto_acl in &msg.acls {
            new_acls.push(ACL {
                user_id: proto_acl.user_id.map(|uid| uid as i32),
                group: proto_acl.group.clone(),
                apply_here: proto_acl.apply_here,
                apply_subs: proto_acl.apply_subs,
                allow: enumflags2::BitFlags::from_bits_truncate(proto_acl.grant),
                deny: enumflags2::BitFlags::from_bits_truncate(proto_acl.deny),
            });
        }

        let inherit_acl = msg.inherit_acls.unwrap_or(true);

        // Safety fallback: if the requesting client would lose Write (and is registered),
        // include a Write|Traverse ACL in the same SetAcls transaction.
        if sender.is_registered() {
            let (channel, ancestors) = server.get_channels().get_channel_with_ancestors(channel_id).await;
            if let Some(mut channel) = channel {
                channel.inherit_acl = inherit_acl;
                channel.acls = new_acls.clone();

                let user_id = sender.get_user_id();
                let groups: Vec<String> = sender.get_groups_clone().into_iter().collect();
                let group_refs: Vec<&str> = groups.iter().map(|s| s.as_str()).collect();
                let tokens: Vec<String> = sender.get_tokens_clone().into_iter().collect();
                let token_refs: Vec<&str> = tokens.iter().map(|s| s.as_str()).collect();
                let membership = crate::client::group::ClientMembershipQuery {
                    groups: &group_refs,
                    authenticated: user_id.is_some(),
                    access_tokens: &token_refs,
                    cert_hash: sender.get_certificate_hash(),
                    has_verified_cert_chain: sender.has_certificate(),
                    ip_address: Some(sender.get_real_ip_address()),
                    asn: None,
                    country_code: None,
                };

                let post_write = crate::acl::evaluate_permission(
                    &channel,
                    &ancestors,
                    user_id,
                    &membership,
                    channel_id,
                );
                if !post_write.contains(ACLPermissions::Write) {
                    if let Some(uid) = user_id {
                        new_acls.push(ACL {
                            user_id: Some(uid as i32),
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

        if let Err(e) = server.get_channels().set_acls(channel_id, inherit_acl, new_acls).await {
            tracing::warn!("set_acls {channel_id} failed: {:?}", e);
            return Ok(());
        }

        // Permission refresh fanout is handled in each client's channel-log
        // broadcast loop (best-effort, no replay).
    }

    Ok(())
}

