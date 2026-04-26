use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{encoder::TextMessage, Message},
    server::Server,
};

pub async fn handle_text_message(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: TextMessage,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated().await {
        return Err(MessageHandlerError::protocol_violation(
            "TextMessage message received before authentication",
        ));
    }

    let sender_session = u32::from(sender.get_session_id());
    tracing::debug!(session = sender_session, channels = ?msg.channel_id, trees = ?msg.tree_id, targets = ?msg.session, "TextMessage handler");

    // Relay as-is but stamp the actor session.
    let relay: Message = TextMessage {
        actor: Some(sender_session),
        session: msg.session.clone(),
        channel_id: msg.channel_id.clone(),
        tree_id: msg.tree_id.clone(),
        message: msg.message.clone(),
    }.into();

    // Direct messages: send to each target session
    for target_session in &msg.session {
        let session_id = crate::client::client_session_identifier::ClientSessionIdentifier::from(*target_session);
        server.get_clients().send_to(session_id, &relay).await;
    }

    // Channel messages: send to all users in the target channels
    for channel_id in &msg.channel_id {
        let all_clients = server.get_clients().get_all_clients().await;
        for client in &all_clients {
            if client.get_session_id() == sender.get_session_id() {
                continue; // don't echo back to sender
            }
            if client.get_current_channel_id().await == *channel_id && client.is_authenticated().await {
                let _ = client.write_proto_message(&relay).await;
            }
        }
    }

    // Tree messages: send to all users in channel subtrees
    for root_channel_id in &msg.tree_id {
        let channel_ids = collect_subtree_ids(server, *root_channel_id).await;
        let all_clients = server.get_clients().get_all_clients().await;
        for client in &all_clients {
            if client.get_session_id() == sender.get_session_id() {
                continue;
            }
            if channel_ids.contains(&client.get_current_channel_id().await) && client.is_authenticated().await {
                let _ = client.write_proto_message(&relay).await;
            }
        }
    }

    Ok(())
}

/// Collect all channel IDs in the subtree rooted at `root_id`.
async fn collect_subtree_ids(server: &Arc<Box<Server>>, root_id: u32) -> std::collections::HashSet<u32> {
    let all_channels = server.get_channels().get_all().await;
    let mut result = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(root_id);
    while let Some(id) = queue.pop_front() {
        if result.insert(id) {
            for ch in all_channels.iter().filter(|c| c.parent_id == Some(id)) {
                queue.push_back(ch.id);
            }
        }
    }
    result
}
