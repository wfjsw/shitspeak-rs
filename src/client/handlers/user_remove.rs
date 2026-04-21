use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{Message, WriteMessageExt},
    mumble_proto::{PermissionDenied, UserRemove, permission_denied::DenyType},
    server::Server,
};

pub async fn handle_user_remove(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: UserRemove,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated().await {
        return Ok(());
    }

    let target_raw = msg.session;
    if target_raw == 0 {
        return Ok(());
    }
    let target_session =
        crate::client::client_session_identifier::ClientSessionIdentifier::from(target_raw);
    let target = match server.get_clients().get_client(target_session).await {
        Some(c) => c,
        None => return Ok(()),
    };

    // TODO: check Kick/Ban permissions against ACL; for now allow all authenticated.
    let is_ban = msg.ban.unwrap_or(false);
    let reason = msg.reason.clone().unwrap_or_default();

    if is_ban {
        // TODO: add to ban list
        tracing::info!(
            "Ban requested for session {:?} by {:?}: {}",
            target_session,
            sender.get_session_id(),
            reason
        );
    }

    // Broadcast UserRemove to all so clients remove the user from their list
    let broadcast = Message::UserRemove(UserRemove {
        session: target_raw,
        actor: Some(u32::from(sender.get_session_id())),
        reason: msg.reason.clone(),
        ban: Some(is_ban),
    });
    server.get_clients().broadcast_all(&broadcast).await;

    // Disconnect the target (TODO: actual TCP disconnect)
    // For now we just remove from the client list; disconnect() is a todo!()
    server.get_clients().remove_client(target_session).await;

    Ok(())
}
