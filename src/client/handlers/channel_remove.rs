use std::sync::Arc;

use crate::{
    acl::ACLPermissions,
    channel_repository::ChannelOp,
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

    let Some(channel) = server
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

    let parent_id = channel.parent_id.unwrap_or(0);
    let nonce = rand::random::<u64>();

    let mark = ChannelOp::MarkPendingDelete {
        id: channel_id,
        nonce,
    };
    if let Err(e) = server
        .get_channels()
        .validate_s2s_op_in_server(&server_id, &mark)
        .await
    {
        tracing::warn!("mark pending delete_channel {channel_id} failed: {:?}", e);
        return Ok(());
    }

    let s2s_marked = server
        .s2s_manager()
        .propose_channel_op(Some(&server_id), mark)
        .await;
    let deleting_subtree: std::collections::HashSet<u32> = if !s2s_marked {
        match server
            .get_channels()
            .mark_pending_delete_in_server(&server_id, channel_id, nonce)
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
            .pending_delete_subtree_in_server(&server_id, channel_id, nonce)
            .await
            .into_iter()
            .collect()
    };
    let repo = server.get_clients();
    let local_clients = repo.get_local_clients_in_server(&server_id).await;
    for client in &local_clients {
        if deleting_subtree.contains(&client.get_current_channel_id()) {
            let channel_cache_key =
                crate::user_channel_cache::cache_key_for_client(client.as_ref()).await;
            client.set_current_channel_id(
                parent_id,
                repo,
                server.get_channels().current_version_in_server(&server_id),
            );
            if let Some(cache_key) = channel_cache_key.as_deref() {
                if let Err(error) = server
                    .get_user_channel_cache()
                    .remember_last_channel(cache_key, parent_id)
                    .await
                {
                    tracing::warn!(
                        error = %error,
                        cache_key,
                        "failed to stage user last channel cache"
                    );
                }
            }
        }
    }

    let delete = ChannelOp::DeleteChannel {
        id: channel_id,
        nonce,
    };
    if let Err(e) = server
        .get_channels()
        .validate_s2s_op_in_server(&server_id, &delete)
        .await
    {
        tracing::warn!("delete_channel {channel_id} failed: {:?}", e);
        let cancel = ChannelOp::CancelPendingDelete {
            id: channel_id,
            nonce,
        };
        if !server
            .s2s_manager()
            .propose_channel_op(Some(&server_id), cancel)
            .await
        {
            let _ = server
                .get_channels()
                .cancel_pending_delete_in_server(&server_id, channel_id, nonce)
                .await;
        }
        return Ok(());
    }
    if !server
        .s2s_manager()
        .propose_channel_op(Some(&server_id), delete)
        .await
    {
        match server
            .get_channels()
            .apply_delete_channel_in_server(&server_id, channel_id, nonce)
            .await
        {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("delete_channel {channel_id} failed: {:?}", e);
                let _ = server
                    .get_channels()
                    .cancel_pending_delete_in_server(&server_id, channel_id, nonce)
                    .await;
                return Ok(());
            }
        }
    }

    Ok(())
}
