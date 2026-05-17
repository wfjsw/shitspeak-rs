use std::sync::Arc;

use crate::{
    acl::ACLPermissions,
    channel_repository::ChannelOp,
    client::Client,
    errors::MessageHandlerError,
    localization::{text, TextKey},
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

    let Some(channel) = server.get_channels().get_channel(channel_id).await else {
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

    let parent_id = channel.parent_id.unwrap_or(0);
    let nonce = rand::random::<u64>();

    let mark = ChannelOp::MarkPendingDelete {
        id: channel_id,
        nonce,
    };
    if let Err(e) = server.get_channels().validate_s2s_op(&mark).await {
        tracing::warn!("mark pending delete_channel {channel_id} failed: {:?}", e);
        return Ok(());
    }

    let s2s_marked = server.s2s_manager().propose_channel_op(mark).await;
    let deleting_subtree: std::collections::HashSet<u32> = if !s2s_marked {
        match server
            .get_channels()
            .mark_pending_delete(channel_id, nonce)
            .await
        {
            Ok(ids) => ids.into_iter().collect(),
            Err(e) => {
                tracing::warn!("mark pending delete_channel {channel_id} failed: {:?}", e);
                return Ok(());
            }
        }
    } else {
        server
            .get_channels()
            .pending_delete_subtree(channel_id, nonce)
            .await
            .into_iter()
            .collect()
    };
    let repo = server.get_clients();
    let local_clients = repo.get_local_clients().await;
    for client in &local_clients {
        if deleting_subtree.contains(&client.get_current_channel_id()) {
            client.set_current_channel_id(parent_id, repo, server.get_channels().current_version());
        }
    }

    let delete = ChannelOp::DeleteChannel {
        id: channel_id,
        nonce,
    };
    if let Err(e) = server.get_channels().validate_s2s_op(&delete).await {
        tracing::warn!("delete_channel {channel_id} failed: {:?}", e);
        let cancel = ChannelOp::CancelPendingDelete {
            id: channel_id,
            nonce,
        };
        if !server.s2s_manager().propose_channel_op(cancel).await {
            let _ = server
                .get_channels()
                .cancel_pending_delete(channel_id, nonce)
                .await;
        }
        return Ok(());
    }
    if !server.s2s_manager().propose_channel_op(delete).await {
        match server
            .get_channels()
            .apply_delete_channel(channel_id, nonce)
            .await
        {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("delete_channel {channel_id} failed: {:?}", e);
                let _ = server
                    .get_channels()
                    .cancel_pending_delete(channel_id, nonce)
                    .await;
                return Ok(());
            }
        }
    }

    Ok(())
}
