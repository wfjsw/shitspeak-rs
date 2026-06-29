use std::sync::Arc;

use crate::{
    acl::ACLPermissions,
    client::Client,
    client::client_session_identifier::ClientSessionIdentifier,
    errors::MessageHandlerError,
    messages::{Message, WriteMessageExt, encoder::TextMessage},
    server::Server,
};
use shitspeak_s2s::application::proto::TextMessageEnvelope;

pub async fn handle_text_message(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: TextMessage,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated() {
        return Err(MessageHandlerError::protocol_violation(
            "TextMessage message received before authentication",
        ));
    }

    let sender_session = u32::from(sender.get_session_id());
    let server_id = sender.server_id();
    tracing::debug!(session = sender_session, channels = ?msg.channel_id, trees = ?msg.tree_id, targets = ?msg.session, "TextMessage handler");

    let TextMessage {
        session,
        channel_id,
        tree_id,
        message,
        ..
    } = msg;

    let mut direct_sessions = Vec::new();
    let mut direct_recipients = Vec::new();
    for target_session in &session {
        let session_id = ClientSessionIdentifier::from(*target_session);
        let Some(target) = server
            .get_clients()
            .get_client_in_server(&server_id, session_id)
            .await
        else {
            continue;
        };
        if !crate::client::visibility::can_view_user(server, sender, &target).await {
            continue;
        }
        let target_channel = target.get_current_channel_id();
        let perms =
            crate::client::acl::compute_permissions_for_client(server, sender, target_channel)
                .await;
        if !perms.contains(ACLPermissions::TextMessage) {
            return Err(MessageHandlerError::PermissionDenied(
                crate::messages::encoder::PermissionDenied::for_permission(
                    sender_session,
                    Some(target_channel),
                    ACLPermissions::TextMessage,
                ),
            ));
        }
        direct_sessions.push(*target_session);
        direct_recipients.push(session_id);
    }

    let mut channel_ids = Vec::new();
    for target_channel in channel_id {
        let perms =
            crate::client::acl::compute_permissions_for_client(server, sender, target_channel)
                .await;
        if !perms.contains(ACLPermissions::TextMessage) {
            return Err(MessageHandlerError::PermissionDenied(
                crate::messages::encoder::PermissionDenied::for_permission(
                    sender_session,
                    Some(target_channel),
                    ACLPermissions::TextMessage,
                ),
            ));
        }
        channel_ids.push(target_channel);
    }

    let mut tree_roots = Vec::new();
    let mut tree_deliverable_channels = std::collections::HashSet::new();
    for root_channel_id in tree_id {
        let root_perms =
            crate::client::acl::compute_permissions_for_client(server, sender, root_channel_id)
                .await;
        if !root_perms.contains(ACLPermissions::TextMessage) {
            return Err(MessageHandlerError::PermissionDenied(
                crate::messages::encoder::PermissionDenied::for_permission(
                    sender_session,
                    Some(root_channel_id),
                    ACLPermissions::TextMessage,
                ),
            ));
        }

        let subtree = collect_subtree_ids(server, &server_id, root_channel_id).await;
        for channel_id in subtree {
            let perms =
                crate::client::acl::compute_permissions_for_client(server, sender, channel_id)
                    .await;
            if perms.contains(ACLPermissions::TextMessage) {
                tree_deliverable_channels.insert(channel_id);
            }
        }
        tree_roots.push(root_channel_id);
    }

    let relay: Message = TextMessage {
        actor: Some(sender_session),
        session: direct_sessions.clone(),
        channel_id: channel_ids.clone(),
        tree_id: tree_roots,
        message,
    }
    .into();

    let local_node_id = server.get_clients().local_node_id();
    let mut remote_by_node = std::collections::BTreeMap::<u16, Vec<u32>>::new();
    let mut delivered_sessions = std::collections::BTreeSet::<u32>::new();

    for session_id in direct_recipients {
        let Some(target) = server
            .get_clients()
            .get_client_in_server(&server_id, session_id)
            .await
        else {
            continue;
        };
        if !crate::client::visibility::can_view_user(server, &target, sender).await {
            continue;
        }
        if !delivered_sessions.insert(u32::from(session_id)) {
            continue;
        }
        if session_id.get_node_id() == local_node_id {
            server
                .get_clients()
                .send_to_in_server(&server_id, session_id, &relay)
                .await;
        } else {
            remote_by_node
                .entry(session_id.get_node_id())
                .or_default()
                .push(u32::from(session_id));
        }
    }

    let all_clients = server
        .get_clients()
        .get_all_clients_in_server(&server_id)
        .await;

    for target_channel in channel_ids {
        for client in &all_clients {
            if client.get_session_id() == sender.get_session_id() {
                continue;
            }
            if client.get_current_channel_id() == target_channel && client.is_authenticated() {
                if !crate::client::visibility::can_view_user(server, client, sender).await {
                    continue;
                }
                deliver_or_queue_text_recipient(
                    &relay,
                    client,
                    local_node_id,
                    &mut delivered_sessions,
                    &mut remote_by_node,
                )
                .await;
            }
        }
    }

    if !tree_deliverable_channels.is_empty() {
        for client in &all_clients {
            if client.get_session_id() == sender.get_session_id() {
                continue;
            }
            if tree_deliverable_channels.contains(&client.get_current_channel_id())
                && client.is_authenticated()
            {
                if !crate::client::visibility::can_view_user(server, client, sender).await {
                    continue;
                }
                deliver_or_queue_text_recipient(
                    &relay,
                    client,
                    local_node_id,
                    &mut delivered_sessions,
                    &mut remote_by_node,
                )
                .await;
            }
        }
    }

    if !remote_by_node.is_empty() {
        let Message::TextMessage(relay) = &relay else {
            return Ok(());
        };
        for (node_id, receiver_sessions) in remote_by_node {
            let envelope = TextMessageEnvelope {
                sender_session,
                receiver_sessions,
                session: relay.session.clone(),
                channel_id: relay.channel_id.clone(),
                tree_id: relay.tree_id.clone(),
                message: relay.message.clone(),
                server_id: server_id.clone(),
            };
            if !server
                .s2s_manager()
                .dispatch_text_message(node_id, envelope)
            {
                tracing::trace!(
                    node_id,
                    "cross-node TextMessage dropped: S2S gateway unavailable"
                );
            }
        }
    }

    Ok(())
}

async fn deliver_or_queue_text_recipient(
    relay: &Message,
    client: &Arc<Box<Client>>,
    local_node_id: u16,
    delivered_sessions: &mut std::collections::BTreeSet<u32>,
    remote_by_node: &mut std::collections::BTreeMap<u16, Vec<u32>>,
) {
    let session_id = client.get_session_id();
    if !delivered_sessions.insert(u32::from(session_id)) {
        return;
    }
    if session_id.get_node_id() == local_node_id {
        let _ = client.write_proto_message(relay).await;
    } else {
        remote_by_node
            .entry(session_id.get_node_id())
            .or_default()
            .push(u32::from(session_id));
    }
}

/// Collect all channel IDs in the subtree rooted at `root_id`.
async fn collect_subtree_ids(
    server: &Arc<Box<Server>>,
    server_id: &str,
    root_id: u32,
) -> std::collections::HashSet<u32> {
    let all_channels = server.get_channels().get_all_in_server(server_id).await;
    let mut result = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(root_id);
    while let Some(id) = queue.pop_front() {
        if result.insert(id) {
            for ch in all_channels.iter().filter(|c| c.parent_id == Some(id)) {
                queue.push_back(ch.id);
            }
        }
    }
    result
}
