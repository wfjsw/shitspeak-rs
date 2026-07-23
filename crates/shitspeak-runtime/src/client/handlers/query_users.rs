use std::{collections::HashMap, sync::Arc};

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{Message, encoder::QueryUsers},
    server::Server,
};

pub async fn handle_query_users(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: QueryUsers,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated() {
        return Err(MessageHandlerError::protocol_violation(
            "QueryUsers message received before authentication",
        ));
    }

    tracing::debug!(session = u32::from(sender.get_session_id()), ids = ?msg.ids, names = ?msg.names, "QueryUsers handler");

    let authenticator = server.get_authenticator();

    // If specific IDs are requested, look them up.
    // Otherwise, if names are provided, search by name.
    // If neither, return empty.
    let mut ids = Vec::new();
    let mut names = Vec::new();

    if !msg.ids.is_empty() {
        // Look up by ID — query all registered users and filter
        let all_users = authenticator.get_registered_users("").await;
        let mut users_by_id = HashMap::with_capacity(all_users.len());
        for user in &all_users {
            users_by_id.entry(user.user_id).or_insert(user);
        }
        for id in &msg.ids {
            if let Some(user) = users_by_id.get(id) {
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

    let reply: Message = QueryUsers { ids, names }.into();
    sender.write_proto_message(&reply).await?;
    Ok(())
}
