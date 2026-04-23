use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::encoder::ChannelRemove,
    server::Server,
};

pub async fn handle_channel_remove(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: ChannelRemove,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated().await {
        return Ok(());
    }

    let channel_id = msg.channel_id;
    tracing::debug!(session = u32::from(sender.get_session_id()), channel_id, "ChannelRemove handler");
    if channel_id == 0 {
        return Ok(());
    }

    // Verify channel exists
    if server.get_channels().get_channel(channel_id).await.is_none() {
        return Ok(());
    }

    // Move any users in this channel to its parent (or root)
    let parent_id = server
        .get_channels()
        .get_channel(channel_id)
        .await
        .and_then(|ch| ch.parent_id)
        .unwrap_or(0);

    let repo = server.get_clients();
    let all_clients = repo.get_all_clients().await;
    for client in &all_clients {
        if client.get_current_channel_id().await == channel_id {
            client.set_current_channel_id(parent_id, repo, server.get_channels().current_version()).await;
            // The channel move is now logged via the transactional guard;
            // per-client subscribers will pick up the UserState delta.
        }
    }

    if let Err(e) = server.get_channels().delete_channel(channel_id).await {
        tracing::warn!("delete_channel {channel_id} failed: {:?}", e);
        return Ok(());
    }

    // Channel deletion is logged and broadcast via ChannelRepository::commit().
    // Per-client subscribers will pick up the ChannelRemove message.

    Ok(())
}
