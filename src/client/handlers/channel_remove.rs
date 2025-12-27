use std::sync::Arc;

use crate::{client::Client, mumble_proto::ChannelRemove, server::Server};

pub fn handle_channel_remove(server: &Arc<Box<Server>>, sender: &Arc<Box<Client>>, msg: ChannelRemove) {
    // Handle channel remove message logic here
}
