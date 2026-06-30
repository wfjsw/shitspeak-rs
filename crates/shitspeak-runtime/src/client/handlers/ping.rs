use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{Message, encoder::Ping},
    server::Server,
};

pub async fn handle_ping(
    _: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: Ping,
) -> Result<(), MessageHandlerError> {
    tracing::trace!(
        session = u32::from(sender.get_session_id()),
        timestamp = msg.timestamp,
        "Ping handler"
    );
    // Handle the ping message logic here
    sender.reset_last_ping().await;

    {
        let mut stats = sender.write_stats().await;
        stats.update_from_ping_message(&msg);
    }

    let response = {
        let mut crypt_state = sender.crypt_state();
        if let Some(state) = crypt_state.as_mut() {
            state.update_from_ping_message(&msg);
            state.create_ping_response(&msg)
        } else {
            msg.default_from_self()
        }
    };

    // Keep TCP ping replies out of the normal outbound queue so channel/user
    // fanout backlogs do not look like a dead connection to clients.
    let response: Message = response.into();
    sender.write_proto_message_direct(&response).await?;
    Ok(())
}
