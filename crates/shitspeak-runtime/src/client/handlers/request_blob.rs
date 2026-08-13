use std::{collections::HashSet, sync::Arc};

use tracing::Instrument;

use crate::{
    client::{Client, RequestBlobQueueEnqueueError},
    errors::MessageHandlerError,
    messages::{Message, encoder::RequestBlob},
    server::Server,
};

fn request_blob_queue_capacity(max_users: u64, channel_count: usize) -> usize {
    usize::try_from(max_users)
        .unwrap_or(usize::MAX)
        .saturating_mul(2)
        .saturating_add(channel_count)
}

fn retain_distinct_targets(targets: &mut Vec<u32>, limit: usize) {
    let mut seen = HashSet::with_capacity(targets.len().min(limit));
    targets.retain(|target| seen.len() < limit && seen.insert(*target));
}

fn normalize_request_blob(
    mut request: RequestBlob,
    max_users: u64,
    channel_count: usize,
) -> RequestBlob {
    let user_limit = usize::try_from(max_users).unwrap_or(usize::MAX).max(1);
    retain_distinct_targets(&mut request.session_texture, user_limit);
    retain_distinct_targets(&mut request.session_comment, user_limit);
    retain_distinct_targets(&mut request.channel_description, channel_count.max(1));
    request
}

fn request_is_empty(request: &RequestBlob) -> bool {
    request.session_texture.is_empty()
        && request.session_comment.is_empty()
        && request.channel_description.is_empty()
}

async fn get_session_blob(
    server: &Arc<Box<Server>>,
    key: &str,
    source_url: Option<&str>,
) -> Option<bytes::Bytes> {
    match source_url {
        Some(url) => server.get_session_blobs().get(key, url).await,
        None => match server.get_session_blobs().get_cached(key).await {
            Some(blob) => Some(blob),
            None => server.s2s_manager().get_session_blob(key).await,
        },
    }
}

pub async fn spawn_request_blob_task(server: Arc<Box<Server>>, sender: Arc<Box<Client>>) {
    let channel_count = server
        .get_channels()
        .len_in_server(&sender.server_id())
        .await;
    let limit = request_blob_queue_capacity(server.get_max_users(), channel_count);
    let span = sender.tracing_span();
    let server_span = sender.server_tracing_span();
    if !sender.install_request_blob_queue(limit) {
        server_span.in_scope(|| {
            span.in_scope(|| {
                tracing::error!(
                    session = u32::from(sender.get_session_id()),
                    "RequestBlob queue already installed"
                );
            });
        });
        sender.request_disconnect();
        return;
    }
    let Some(changed) = sender.request_blob_queue_notifier() else {
        server_span.in_scope(|| {
            span.in_scope(|| {
                tracing::error!(
                    session = u32::from(sender.get_session_id()),
                    "RequestBlob queue notifier missing after installation"
                );
            });
        });
        sender.request_disconnect();
        return;
    };

    let weak_sender = Arc::downgrade(&sender);
    tokio::spawn(
        async move {
            loop {
                // Create this before checking the queue. If an enqueue lands
                // after the empty check and before await, Notify retains a
                // permit and the worker wakes without losing the request.
                let notified = changed.notified();
                tokio::pin!(notified);
                let Some(sender) = weak_sender.upgrade() else {
                    break;
                };
                if sender.is_removed() {
                    sender.clear_request_blob_queue();
                    break;
                }
                let Some(request) = sender.dequeue_request_blob() else {
                    tokio::select! {
                        _ = &mut notified => {}
                        _ = sender.removed() => {
                            sender.clear_request_blob_queue();
                            break;
                        }
                    }
                    continue;
                };

                if let Err(error) = handle_request_blob_inner(&server, &sender, request).await {
                    if error.is_peer_disconnect() {
                        tracing::debug!(
                            session = u32::from(sender.get_session_id()),
                            error = %error,
                            "RequestBlob worker stopped after peer disconnect"
                        );
                    } else {
                        tracing::warn!(
                            session = u32::from(sender.get_session_id()),
                            error = %error,
                            "RequestBlob worker failed; disconnecting client"
                        );
                    }
                    sender.request_disconnect();
                    sender.clear_request_blob_queue();
                    break;
                }
            }
        }
        .instrument(span)
        .instrument(server_span),
    );
}

pub async fn handle_request_blob(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: RequestBlob,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated() {
        return Err(MessageHandlerError::protocol_violation(
            "RequestBlob message received before authentication",
        ));
    }

    let channel_count = server
        .get_channels()
        .len_in_server(&sender.server_id())
        .await;
    let request = normalize_request_blob(msg, server.get_max_users(), channel_count);
    if request_is_empty(&request) {
        return Ok(());
    }

    match sender.enqueue_request_blob(request) {
        Ok(()) => Ok(()),
        Err(RequestBlobQueueEnqueueError::Full(request)) => {
            tracing::debug!(
                session = u32::from(sender.get_session_id()),
                queue_limit = request_blob_queue_capacity(server.get_max_users(), channel_count),
                textures = request.session_texture.len(),
                comments = request.session_comment.len(),
                descriptions = request.channel_description.len(),
                "RequestBlob queue full; dropping request"
            );
            Ok(())
        }
        Err(RequestBlobQueueEnqueueError::Unavailable) => {
            tracing::warn!(
                session = u32::from(sender.get_session_id()),
                "RequestBlob queue worker unavailable; disconnecting client"
            );
            sender.request_disconnect();
            Ok(())
        }
    }
}

async fn handle_request_blob_inner(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: RequestBlob,
) -> Result<(), MessageHandlerError> {
    tracing::debug!(
        session = u32::from(sender.get_session_id()),
        textures = msg.session_texture.len(),
        comments = msg.session_comment.len(),
        descriptions = msg.channel_description.len(),
        "handling queued RequestBlob"
    );
    let server_id = sender.server_id();

    // ── Session textures ─────────────────────────────────────────────────
    for session_raw in &msg.session_texture {
        let session_id =
            crate::client::client_session_identifier::ClientSessionIdentifier::from(*session_raw);
        let Some(client) = server
            .get_clients()
            .get_client_in_server(&server_id, session_id)
            .await
        else {
            continue;
        };
        if !crate::client::visibility::can_view_user(server, sender, &client).await {
            continue;
        }

        let (texture_hash, texture_url) = {
            let gs = client.read_global_state();
            let texture_hash = gs
                .get_texture_hash()
                .and_then(|h| hex::decode(h).ok())
                .filter(|h| h.len() == 20);
            let texture_url = gs.get_texture_url().map(|s| s.to_owned());
            (texture_hash, texture_url)
        };

        // Fetch blob from store if we have a hash
        let texture_data = match texture_hash.as_ref() {
            Some(hash) => {
                let key = hex::encode(hash);
                get_session_blob(server, &key, texture_url.as_deref()).await
            }
            None => None,
        };

        let reply: Message = shitspeak_messages::messages::encoder::UserState {
            session: Some(
                crate::client::client_session_identifier::ClientSessionIdentifier::from(
                    *session_raw,
                ),
            ),
            actor: None,
            name: None,
            user_id: None,
            channel_id: None,
            mute: None,
            deaf: None,
            suppress: None,
            self_mute: None,
            self_deaf: None,
            texture: texture_data.clone(),
            plugin_context: None,
            plugin_identity: None,
            comment: None,
            hash: None,
            comment_hash: None,
            texture_hash: texture_hash.clone().map(bytes::Bytes::from),
            priority_speaker: None,
            recording: None,
            temporary_access_tokens: Vec::new(),
            listening_channel_add: Vec::new(),
            listening_channel_remove: Vec::new(),
            listening_volume_adjustment: Vec::new(),
        }
        .into();
        sender.write_proto_message(&reply).await?;
    }

    // ── Session comments ─────────────────────────────────────────────────
    for session_raw in &msg.session_comment {
        let session_id =
            crate::client::client_session_identifier::ClientSessionIdentifier::from(*session_raw);
        let Some(client) = server
            .get_clients()
            .get_client_in_server(&server_id, session_id)
            .await
        else {
            continue;
        };
        if !crate::client::visibility::can_view_user(server, sender, &client).await {
            continue;
        }

        let (comment_hash, comment_url) = {
            let gs = client.read_global_state();
            let comment_hash = gs
                .get_comment_hash()
                .and_then(|h| hex::decode(h).ok())
                .filter(|h| h.len() == 20);
            let comment_url = gs.get_comment_url().map(|s| s.to_owned());
            (comment_hash, comment_url)
        };

        let comment_data = match comment_hash.as_ref() {
            Some(hash) => {
                let key = hex::encode(hash);
                get_session_blob(server, &key, comment_url.as_deref()).await
            }
            None => None,
        };

        let reply: Message = shitspeak_messages::messages::encoder::UserState {
            session: Some(
                crate::client::client_session_identifier::ClientSessionIdentifier::from(
                    *session_raw,
                ),
            ),
            actor: None,
            name: None,
            user_id: None,
            channel_id: None,
            mute: None,
            deaf: None,
            suppress: None,
            self_mute: None,
            self_deaf: None,
            texture: None,
            plugin_context: None,
            plugin_identity: None,
            comment: comment_data
                .as_ref()
                .and_then(|b| String::from_utf8(b.to_vec()).ok()),
            hash: None,
            comment_hash: comment_hash.clone().map(bytes::Bytes::from),
            texture_hash: None,
            priority_speaker: None,
            recording: None,
            temporary_access_tokens: Vec::new(),
            listening_channel_add: Vec::new(),
            listening_channel_remove: Vec::new(),
            listening_volume_adjustment: Vec::new(),
        }
        .into();
        sender.write_proto_message(&reply).await?;
    }

    // ── Channel descriptions ─────────────────────────────────────────────
    for channel_id in &msg.channel_description {
        if !crate::channel_handler::can_view_channel_with_ancestors(server, sender, *channel_id)
            .await
        {
            continue;
        }
        let Some(ch) = server
            .get_channels()
            .get_channel_in_server(&server_id, *channel_id)
            .await
        else {
            continue;
        };
        let desc_data = match ch.description_hash.as_ref() {
            Some(hash) => match server.get_channel_blobs().get(hash).await.ok().flatten() {
                Some(bytes) => Some(bytes),
                None => {
                    server
                        .s2s_manager()
                        .get_channel_blob(Some(&server_id), hash)
                        .await
                }
            },
            None => None,
        };

        let mut links = Vec::with_capacity(ch.links.len());
        for linked_id in &ch.links {
            if crate::channel_handler::can_view_channel_with_ancestors(server, sender, *linked_id)
                .await
            {
                links.push(*linked_id);
            }
        }

        let mut cs = shitspeak_messages::messages::encoder::ChannelState {
            channel_id: Some(ch.id),
            parent: ch.parent_id,
            name: Some(ch.name.clone()),
            links,
            description: desc_data
                .as_ref()
                .and_then(|b| String::from_utf8(b.to_vec()).ok()),
            links_add: Vec::new(),
            links_remove: Vec::new(),
            temporary: Some(ch.is_temporary()),
            position: Some(ch.position),
            description_hash: ch
                .description_hash
                .as_ref()
                .and_then(|h| hex::decode(h).ok().map(bytes::Bytes::from)),
            max_users: Some(ch.max_users),
            is_enter_restricted: None,
            can_enter: None,
        };
        if server.get_send_permission_info() {
            let (is_enter_restricted, perms) =
                crate::channel_handler::permission_info_for_channel(server, sender, ch.id).await;
            cs = cs.with_permission_info(is_enter_restricted, perms);
        }
        let reply: Message = cs.into();
        sender.write_proto_message(&reply).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_limit_tracks_all_user_and_channel_targets_without_clamping() {
        assert_eq!(request_blob_queue_capacity(0, 0), 0);
        assert_eq!(request_blob_queue_capacity(7, 3), 17);
        assert_eq!(request_blob_queue_capacity(u64::MAX, 1), usize::MAX);
    }

    #[test]
    fn normalize_request_blob_deduplicates_and_caps_each_target_class() {
        let mut request = RequestBlob::default();
        request.session_texture = vec![11, 11, 12, 13];
        request.session_comment = vec![21, 22, 21, 23];
        request.channel_description = vec![31, 31, 32, 33];

        let normalized = normalize_request_blob(request, 2, 2);

        assert_eq!(normalized.session_texture, vec![11, 12]);
        assert_eq!(normalized.session_comment, vec![21, 22]);
        assert_eq!(normalized.channel_description, vec![31, 32]);
    }
}
