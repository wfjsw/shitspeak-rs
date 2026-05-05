use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::encoder::UserList,
    server::Server,
};

/// UserList is intentionally a no-op.  User registration is handled
/// externally (by the authenticator backend), not by this server.
pub async fn handle_user_list(
    _server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: UserList,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated() {
        return Err(MessageHandlerError::protocol_violation(
            "UserList message received before authentication",
        ));
    }

    tracing::debug!(session = u32::from(sender.get_session_id()), num_users = msg.users.len(), "UserList handler (no-op)");
    Ok(())
}
