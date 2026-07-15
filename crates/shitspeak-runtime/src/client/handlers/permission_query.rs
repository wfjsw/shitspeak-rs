use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{Message, WriteMessageExt, encoder::PermissionQuery},
    server::Server,
};

pub async fn handle_permission_query(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: PermissionQuery,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated() {
        return Err(MessageHandlerError::protocol_violation(
            "PermissionQuery message received before authentication",
        ));
    }

    tracing::debug!(
        session = u32::from(sender.get_session_id()),
        flush = msg.flush,
        "PermissionQuery handler"
    );

    if let Some(channel_id) = msg.channel_id {
        if !crate::channel_handler::can_view_channel_with_ancestors(server, sender, channel_id)
            .await
        {
            return Ok(());
        }

        // Compute effective permissions using the ACL system
        let perms =
            crate::client::acl::compute_permissions_for_client(server, sender, channel_id).await;

        tracing::debug!(
            session = u32::from(sender.get_session_id()),
            channel_id,
            permissions = perms.bits(),
            "Computed permissions for PermissionQuery"
        );

        let reply: Message =
            PermissionQuery::for_channel_permissions(channel_id, perms.bits()).into();

        sender.write_proto_message(&reply).await?;
    }

    Ok(())
}
