use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{Message, WriteMessageExt},
    mumble_proto::PermissionQuery,
    server::Server,
};

pub async fn handle_permission_query(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: PermissionQuery,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated().await {
        return Ok(());
    }

    let channel_id = msg.channel_id.unwrap_or(0);

    // Compute effective permissions using the ACL system
    let perms = super::acl::compute_permissions_for_client(server, sender, channel_id).await;

    let reply = Message::PermissionQuery(PermissionQuery {
        channel_id: Some(channel_id),
        permissions: Some(perms.bits()),
        flush: msg.flush,
    });

    sender.write_proto_message(&reply).await?;
    Ok(())
}

