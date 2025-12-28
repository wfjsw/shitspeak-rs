use std::sync::Arc;

use crate::{
    client::Client, errors::MessageHandlerError, mumble_proto::ChannelRemove, server::Server,
};

pub async fn handle_channel_remove(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: ChannelRemove,
) -> Result<(), MessageHandlerError> {
    // Handle channel remove message logic here
    Ok(())
}
