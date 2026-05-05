use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::encoder::UserRemove,
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
    tracing::debug!(session = u32::from(sender.get_session_id()), target = target_raw, ban = msg.ban, reason = msg.reason, "UserRemove handler");
    if target_raw == 0 {
        return Ok(());
    }
    let target_session =
        crate::client::client_session_identifier::ClientSessionIdentifier::from(target_raw);
    let local_node_id = server.get_clients().local_node_id();

    // Cross-owner kick/ban: dispatch the intent to the owner. Same
    // fire-and-forget contract as `handle_user_state`. Bans get
    // persisted on the owner's node (where the target lives) and
    // propagate via the `BanRepository`'s strict replication; the
    // RemoveClient log entry, in turn, broadcasts UserRemove to all
    // subscribers via owner-scoped replication.
    if target_session.get_node_id() != local_node_id {
        if let Some(app) = server.s2s_manager().application() {
            let patch = crate::s2s::application::proto::UserRemovePatch {
                reason: msg.reason.clone().map(Into::into),
                ban: msg.ban.unwrap_or(false),
            };
            if let Err(e) = app
                .moderation()
                .dispatch_user_remove(sender.get_session_id(), target_session, patch)
                .await
            {
                tracing::warn!(
                    error = %e,
                    target = target_raw,
                    "moderation dispatch_user_remove failed",
                );
            }
        } else {
            tracing::trace!(
                target = target_raw,
                "cross-owner UserRemove dropped: ApplicationLayer not attached",
            );
        }
        return Ok(());
    }

    let target = match server.get_clients().get_client(target_session).await {
        Some(c) => c,
        None => return Ok(()),
    };

    // TODO: check Kick/Ban permissions against ACL; for now allow all authenticated.
    let is_ban = msg.ban.unwrap_or(false);
    let reason = msg.reason.clone().unwrap_or_default();

    if is_ban {
        let entry = crate::ban_repository::BanEntry {
            address: target.get_real_ip_address(),
            mask: if target.get_real_ip_address().is_ipv4() { 32 } else { 128 },
            name: {
                let gs = target.read_global_state();
                gs.get_display_name_opt().map(|s| s.to_owned())
            },
            hash: target.get_certificate_hash().map(|h| hex::encode(h)),
            reason: if reason.is_empty() { None } else { Some(reason.clone()) },
            start: chrono::Utc::now().timestamp(),
            duration: 0, // permanent
        };
        if let Err(e) = server.get_bans().add_ban(entry).await {
            tracing::warn!("Failed to persist ban: {e}");
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

    // Disconnect the target (TODO: actual TCP disconnect)
    // For now we just remove from the client list; disconnect() is a todo!()
    server.get_clients().remove_client(target_session).await;

    Ok(())
}
