use std::sync::Arc;

use crate::{
    acl::ACLPermissions,
    ban_repository::BanOp,
    client::Client,
    errors::MessageHandlerError,
    messages::Message,
    messages::encoder::{PermissionDenied, UserRemove},
    server::Server,
};

pub async fn handle_user_remove(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: UserRemove,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated() {
        return Err(MessageHandlerError::protocol_violation(
            "UserRemove message received before authentication",
        ));
    }

    let target_raw = msg.session;
    tracing::debug!(
        session = u32::from(sender.get_session_id()),
        target = target_raw,
        ban = msg.ban,
        reason = msg.reason,
        "UserRemove handler"
    );
    if target_raw == 0 {
        return Ok(());
    }
    let target_session =
        crate::client::client_session_identifier::ClientSessionIdentifier::from(target_raw);
    let server_id = sender.server_id();
    let is_ban = msg.ban.unwrap_or(false);
    let target = match server
        .get_clients()
        .get_client_in_server(&server_id, target_session)
        .await
    {
        Some(c) if crate::client::visibility::can_view_user(server, sender, &c).await => c,
        Some(_) | None => return Ok(()),
    };
    let root_perms = crate::client::acl::compute_permissions_for_client(server, sender, 0).await;
    if is_ban {
        if !root_perms.contains(ACLPermissions::Ban) {
            return Err(MessageHandlerError::PermissionDenied(
                PermissionDenied::for_permission(
                    u32::from(sender.get_session_id()),
                    Some(0),
                    ACLPermissions::Ban,
                ),
            ));
        }
    } else if !root_perms.contains(ACLPermissions::Kick)
        && !root_perms.contains(ACLPermissions::Ban)
    {
        return Err(MessageHandlerError::PermissionDenied(
            PermissionDenied::for_permission(
                u32::from(sender.get_session_id()),
                Some(0),
                ACLPermissions::Kick,
            ),
        ));
    }

    let local_node_id = server.get_clients().local_node_id();

    // Cross-owner kick/ban: dispatch the intent to the owner. Same
    // fire-and-forget contract as `handle_user_state`. Bans get
    // persisted on the owner's node (where the target lives) and
    // propagate via the `BanRepository`'s strict replication; the
    // RemoveClient log entry, in turn, broadcasts UserRemove to all
    // subscribers via owner-scoped replication.
    if target_session.get_node_id() != local_node_id {
        let patch = crate::s2s::application::proto::UserRemovePatch {
            reason: msg.reason.clone().map(Into::into),
            ban: is_ban,
        };
        if !server.s2s_manager().dispatch_moderation_user_remove(
            Some(&server_id),
            sender.get_session_id(),
            target_session,
            patch,
        ) {
            tracing::trace!(
                target = target_raw,
                "cross-owner UserRemove dropped: S2S gateway unavailable",
            );
        }
        return Ok(());
    }

    let reason = msg.reason.clone().unwrap_or_default();

    if is_ban {
        let entry = crate::ban_repository::BanEntry {
            address: target.get_real_ip_address(),
            mask: if target.get_real_ip_address().is_ipv4() {
                32
            } else {
                128
            },
            name: {
                let gs = target.read_global_state();
                gs.get_display_name_opt().map(|s| s.to_owned())
            },
            hash: target.get_certificate_hash().map(|h| hex::encode(h)),
            reason: if reason.is_empty() {
                None
            } else {
                Some(reason.clone())
            },
            start: chrono::Utc::now().timestamp(),
            duration: 0, // permanent
        };
        let op = BanOp::AddBan {
            entry: entry.clone(),
        };
        if !server.s2s_manager().propose_ban_op(op).await {
            if let Err(e) = server.get_bans().add_ban(entry).await {
                tracing::warn!("Failed to persist ban: {e}");
            }
        }
        tracing::info!(
            "Ban added for session {:?} by {:?}: {}",
            target_session,
            sender.get_session_id(),
            reason
        );
    }

    // The RemoveClient log entry (emitted by remove_client below) will
    // drive the UserRemove broadcast to all per-client subscribers.
    // No need to broadcast manually.

    let actor = sender.get_session_id();
    let actor_for_target =
        if crate::client::visibility::can_view_user(server, &target, sender).await {
            Some(u32::from(actor))
        } else {
            None
        };
    let remove_notice: Message = UserRemove {
        session: target_raw,
        actor: actor_for_target,
        reason: msg.reason.clone(),
        ban: Some(is_ban),
    }
    .into();
    if let Err(e) = target.write_proto_message(&remove_notice).await {
        tracing::debug!(
            error = %e,
            target = target_raw,
            "failed to send kick notice to target before disconnect",
        );
    }

    let old_channel_id = target.get_current_channel_id();
    let removed = server
        .get_clients()
        .remove_client_in_server_with_metadata(
            &server_id,
            target_session,
            Some(actor),
            msg.reason.clone(),
            is_ban,
        )
        .await;
    let target = removed.as_ref().unwrap_or(&target);
    if let Err(e) = target.force_disconnect().await {
        tracing::debug!(
            error = %e,
            target = target_raw,
            "failed to forcibly disconnect removed client",
        );
    }
    crate::client::handlers::temp_channel::reap_if_empty_temporary_on_server(
        server,
        &server_id,
        old_channel_id,
    )
    .await;

    Ok(())
}
