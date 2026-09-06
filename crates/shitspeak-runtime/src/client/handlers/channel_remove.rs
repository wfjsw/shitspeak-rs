use std::sync::Arc;

use shitspeak_state::{ACLPermissions, ChannelOp};

use crate::{
    client::Client,
    errors::MessageHandlerError,
    localization::{TextKey, text},
    messages::encoder::{ChannelRemove, DenyType, PermissionDenied},
    server::Server,
};

pub async fn handle_channel_remove(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: ChannelRemove,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated() {
        return Err(MessageHandlerError::protocol_violation(
            "ChannelRemove message received before authentication",
        ));
    }

    let channel_id = msg.channel_id;
    let server_id = sender.server_id();
    tracing::debug!(
        session = u32::from(sender.get_session_id()),
        channel_id,
        "ChannelRemove handler"
    );
    if channel_id == 0 {
        return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
            r#type: DenyType::Permission,
            session: u32::from(sender.get_session_id()),
            channel_id: Some(0),
            reason: Some(text(sender.language(), TextKey::CannotDeleteRootChannel)),
            name: None,
            permission: None,
        }));
    }

    let Some(_) = server
        .get_channels()
        .get_channel_in_server(&server_id, channel_id)
        .await
    else {
        return Ok(());
    };

    let perms =
        crate::client::acl::compute_permissions_for_client(server, sender, channel_id).await;
    if !perms.contains(ACLPermissions::Write) {
        return Err(MessageHandlerError::PermissionDenied(
            PermissionDenied::for_permission(
                u32::from(sender.get_session_id()),
                Some(channel_id),
                ACLPermissions::Write,
            ),
        ));
    }

    let delete = ChannelOp::DeleteChannel {
        id: channel_id,
        nonce: None,
    };
    let result = server
        .s2s_manager()
        .propose_channel_op(&server_id, delete)
        .await;
    if result.should_apply_locally() {
        if let Err(error) = server
            .get_channels()
            .delete_channel_in_server(&server_id, channel_id)
            .await
        {
            tracing::warn!(channel_id, %error, "channel deletion failed");
        }
    } else if !result.is_proposed() {
        return Err(super::channel_op_propose_failed(
            u32::from(sender.get_session_id()),
            Some(channel_id),
            result.failure_reason(),
        ));
    }
    Ok(())
}
