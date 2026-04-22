use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{Message, WriteMessageExt},
    mumble_proto::BanList,
    server::Server,
};

pub async fn handle_ban_list(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: BanList,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated().await {
        return Ok(());
    }

    tracing::debug!(session = u32::from(sender.get_session_id()), query = msg.query, num_bans = msg.bans.len(), "BanList handler");

    // TODO: require Ban permission on root channel

    if msg.query.unwrap_or(false) {
        // Query mode: return current ban list (empty for now — no ban storage yet)
        let reply = Message::BanList(BanList {
            bans: Vec::new(),
            query: Some(false),
        });
        sender.write_proto_message(&reply).await?;
    } else {
        // Update mode: replace ban list with provided entries
        // TODO: persist ban list
        tracing::info!(
            "Ban list update from session {:?} with {} entries",
            sender.get_session_id(),
            msg.bans.len()
        );
    }

    Ok(())
}
