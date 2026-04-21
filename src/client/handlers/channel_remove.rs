use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::Message,
    mumble_proto::ChannelRemove,
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

    let all_clients = server.get_clients().get_all_clients().await;
    for client in &all_clients {
        if client.get_current_channel_id().await == channel_id {
            client.set_current_channel_id(parent_id).await;
            let move_msg: Message = {
                use crate::messages::encoder::UserState;
                let mut us = UserState::default();
                us.session = Some(client.get_session_id());
                us.channel_id = Some(parent_id);
                us.into()
            };
            server.get_clients().broadcast_all(&move_msg).await;
        }
    }

    if let Err(e) = server.get_channels().delete_channel(channel_id).await {
        tracing::warn!("delete_channel {channel_id} failed: {:?}", e);
        return Ok(());
    }

    // Broadcast removal
    let broadcast = Message::ChannelRemove(ChannelRemove {
        channel_id,
    });
    server.get_clients().broadcast_all(&broadcast).await;

    Ok(())
}
