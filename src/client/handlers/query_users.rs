use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{Message, WriteMessageExt},
    mumble_proto::QueryUsers,
    server::Server,
};

pub async fn handle_query_users(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: QueryUsers,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated().await {
        return Ok(());
    }

    let authenticator = server.get_authenticator();

    // If specific IDs are requested, look them up.
    // Otherwise, if names are provided, search by name.
    // If neither, return empty.
    let mut ids = Vec::new();
    let mut names = Vec::new();

    if !msg.ids.is_empty() {
        // Look up by ID — query all registered users and filter
        let all_users = authenticator.get_registered_users("").await;
        for id in &msg.ids {
            if let Some(user) = all_users.iter().find(|u| u.user_id == *id) {
                ids.push(user.user_id);
                names.push(user.name.clone());
            }
        }
    } else if !msg.names.is_empty() {
        // Look up by name
        for name in &msg.names {
            let results = authenticator.get_registered_users(name).await;
            for user in results {
                ids.push(user.user_id);
                names.push(user.name);
            }
        }
    }

    let reply = Message::QueryUsers(QueryUsers { ids, names });
    sender.write_proto_message(&reply).await?;
    Ok(())
}

