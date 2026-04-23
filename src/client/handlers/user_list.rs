use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{encoder::UserList, Message, WriteMessageExt},
    server::Server,
};

pub async fn handle_user_list(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: UserList,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated().await {
        return Ok(());
    }

    tracing::debug!(session = u32::from(sender.get_session_id()), num_users = msg.users.len(), "UserList handler");

    if msg.users.is_empty() {
        // Query mode: return registered user list
        let authenticator = server.get_authenticator();
        let registered = authenticator.get_registered_users("").await;

        let users: Vec<crate::mumble_proto::user_list::User> = registered
            .into_iter()
            .map(|u| crate::mumble_proto::user_list::User {
                user_id: u.user_id,
                name: Some(u.name),
                last_seen: None,
                last_channel: None,
            })
            .collect();

        let reply: Message = UserList { users }.into();
        sender.write_proto_message(&reply).await?;
    } else {
        // Update mode: rename or unregister users
        // TODO: require Write/Register permission on root
        let authenticator = server.get_authenticator();
        for user in &msg.users {
            if user.name.is_none() {
                // Empty name = unregister
                let _ = authenticator.unregister_user(user.user_id).await;
            }
            // Rename is handled by the authenticator backend
        }
    }

    Ok(())
}
