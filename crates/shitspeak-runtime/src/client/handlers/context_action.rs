//! Handler for incoming `ContextAction` messages from clients.
//!
//! When a client triggers a context menu action, this handler looks up
//! the action in the server's [`ContextActionRegistry`] and dispatches it.

use std::sync::Arc;

use crate::{
    context_action::ContextActionPayload, errors::MessageHandlerError,
    messages::encoder::ContextAction, server::Server,
};

/// Handle an incoming `ContextAction` message.
///
/// Looks up the action in the registry and dispatches to the appropriate
/// callback (one-shot or toggle).  If the action is a toggle, the entire
/// action list is rebuilt and broadcast to all clients so that labels
/// reflect the new state.
pub async fn handle_context_action(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<crate::client::Client>>,
    msg: ContextAction,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated() {
        return Err(MessageHandlerError::protocol_violation(
            "ContextAction message received before authentication",
        ));
    }

    let actor_session = u32::from(sender.get_session_id());

    if crate::toggle_superuser_visibility::handle(server, sender, &msg).await {
        return Ok(());
    }

    let payload = ContextActionPayload {
        action: msg.action.clone(),
        actor_session,
        target_session: msg.session,
        target_channel_id: msg.channel_id,
    };

    let registry = server.context_actions();
    let handled = registry.dispatch(payload).await;

    if !handled {
        tracing::debug!(
            session = actor_session,
            action = %msg.action,
            "Unknown context action"
        );
        return Ok(());
    }

    tracing::debug!(
        session = actor_session,
        action = %msg.action,
        target_session = ?msg.session,
        target_channel = ?msg.channel_id,
        "Context action dispatched"
    );

    // Rebuild and broadcast the full action list so all clients see
    // updated toggle labels.
    let modify_list = registry.build_modify_list().await;
    let server_id = sender.server_id();
    for modify in modify_list {
        server
            .get_clients()
            .broadcast_all_in_server(&server_id, &modify.into())
            .await;
    }

    Ok(())
}
