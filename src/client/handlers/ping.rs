use std::sync::Arc;

use crate::{client::Client, mumble_proto::Ping, server::Server};

pub async fn handle_ping(server: &Arc<Box<Server>>, sender: &Arc<Box<Client>>, msg: Ping)  {
    // Handle the ping message logic here


}
