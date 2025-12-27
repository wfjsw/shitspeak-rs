use std::sync::Arc;

use crate::{client::Client, mumble_proto::ChannelState, server::Server};

pub fn handle_channel_state(server: &Arc<Box<Server>>, sender: &Arc<Box<Client>>, msg: ChannelState) {
    // Handle channel state message logic here
}
