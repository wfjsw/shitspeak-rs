use std::sync::Arc;

use crate::{
    client::Client, errors::MessageHandlerError, messages::Message, mumble_proto::Ping,
    server::Server,
};

pub async fn handle_ping(
    _: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: Ping,
) -> Result<(), MessageHandlerError> {
    // Handle the ping message logic here
    sender.reset_last_ping().await;
    sender.update_from_ping_message(&msg).await;
    let response = sender.create_ping_response(&msg).await;
    // Send the ping response back to the sender
    sender.write_proto_message(&Message::Ping(response)).await?;
    Ok(())
}
