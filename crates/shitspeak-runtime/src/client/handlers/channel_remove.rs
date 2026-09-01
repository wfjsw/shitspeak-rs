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
        evict_clients: true,
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
        .propose_channel_op(&server_id, mark)
        .await;
    let (deleting_subtree, marked_locally): (std::collections::HashSet<u32>, bool) =
        if s2s_marked.should_apply_locally() {
            match server
                .get_channels()
                .mark_pending_delete_in_server(&server_id, channel_id, nonce)
                .await
            {
                Ok(ids) => (ids.into_iter().collect(), true),
                Err(e) => {
                    tracing::warn!("mark pending delete_channel {channel_id} failed: {:?}", e);
                    return Ok(());
                }
            }
        } else if s2s_marked.is_proposed() {
            (
                server
                    .get_channels()
                    .pending_delete_subtree_in_server(&server_id, channel_id, nonce)
                    .await
                    .into_iter()
                    .collect(),
                false,
            )
        } else {
            return Err(super::channel_op_propose_failed(
                u32::from(sender.get_session_id()),
                Some(channel_id),
                s2s_marked.failure_reason(),
            ));
        };
    if !deleting_subtree.is_empty() {
        crate::user_channel_cache::move_local_clients_out_of_pending_delete(
            server,
            &server_id,
            channel_id,
            nonce,
            parent_id,
            server.get_channels().current_version_in_server(&server_id),
        )
        .await;
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
        let s2s_cancelled = server
            .s2s_manager()
            .propose_channel_op(&server_id, cancel)
            .await;
        if s2s_cancelled.should_apply_locally() || marked_locally {
            let _ = server
                .get_channels()
                .cancel_pending_delete_in_server(&server_id, channel_id, nonce)
                .await;
        } else if !s2s_cancelled.is_proposed() {
            return Err(super::channel_op_propose_failed(
                u32::from(sender.get_session_id()),
                Some(channel_id),
                s2s_cancelled.failure_reason(),
            ));
        }
        return Ok(());
    }
    let s2s_deleted = server
        .s2s_manager()
        .propose_channel_op(&server_id, delete)
        .await;
    if s2s_deleted.should_apply_locally() {
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
    } else if !s2s_deleted.is_proposed() {
        if marked_locally {
            let _ = server
                .get_channels()
                .cancel_pending_delete_in_server(&server_id, channel_id, nonce)
                .await;
        }
        return Err(super::channel_op_propose_failed(
            u32::from(sender.get_session_id()),
            Some(channel_id),
            s2s_deleted.failure_reason(),
        ));
    }

    Ok(())
}
