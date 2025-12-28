use std::sync::Arc;

use crate::{client::Client, mumble_proto::PermissionQuery, server::Server};

pub async fn handle_permission_query(server: &Arc<Box<Server>>, sender: &Arc<Box<Client>>, msg: PermissionQuery) {
    // Handle permission query message logic here
}
