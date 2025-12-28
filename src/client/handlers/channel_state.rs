use std::sync::Arc;

use crate::{
    client::Client, errors::MessageHandlerError, mumble_proto::ChannelState, server::Server,
};

pub async fn handle_channel_state(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: ChannelState,
) -> Result<(), MessageHandlerError> {
    // Handle channel state message logic here
    Ok(())
}
