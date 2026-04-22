use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{Message, WriteMessageExt},
    mumble_proto::RequestBlob,
    server::Server,
};

pub async fn handle_request_blob(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: RequestBlob,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated().await {
        return Ok(());
    }

    tracing::debug!(session = u32::from(sender.get_session_id()), textures = msg.session_texture.len(), comments = msg.session_comment.len(), "RequestBlob handler");

    // ── Session textures ─────────────────────────────────────────────────
    for session_raw in &msg.session_texture {
        let session_id =
            crate::client::client_session_identifier::ClientSessionIdentifier::from(*session_raw);
        let Some(client) = server.get_clients().get_client(session_id).await else {
            continue;
        };
        let gs = client.read_global_state().await;
        let texture_hash = gs.get_texture_hash().map(|h| hex::decode(h).unwrap_or_default());
        let texture_url = gs.get_texture_url().map(|s| s.to_owned());
        drop(gs);

        // Fetch blob from store if we have a hash
        let texture_data = match texture_hash.as_ref() {
            Some(hash) => {
                let key = hex::encode(hash);
                match texture_url.as_deref() {
                    Some(url) => server.get_session_blobs().get(&key, url).await,
                    None => None,
                }
            }
            None => None,
        };

        let reply = Message::UserState(crate::mumble_proto::UserState {
            session: Some(*session_raw),
            actor: None,
            name: None,
            user_id: None,
            channel_id: None,
            mute: None,
            deaf: None,
            suppress: None,
            self_mute: None,
            self_deaf: None,
            texture: texture_data.as_ref().map(|b| b.to_vec()),
            plugin_context: None,
            plugin_identity: None,
            comment: None,
            hash: None,
            comment_hash: None,
            texture_hash: texture_hash.clone(),
            priority_speaker: None,
            recording: None,
            temporary_access_tokens: Vec::new(),
            listening_channel_add: Vec::new(),
            listening_channel_remove: Vec::new(),
            listening_volume_adjustment: Vec::new(),
        });
        sender.write_proto_message(&reply).await?;
    }

    // ── Session comments ─────────────────────────────────────────────────
    for session_raw in &msg.session_comment {
        let session_id =
            crate::client::client_session_identifier::ClientSessionIdentifier::from(*session_raw);
        let Some(client) = server.get_clients().get_client(session_id).await else {
            continue;
        };
        let gs = client.read_global_state().await;
        let comment_hash = gs.get_comment_hash().map(|h| hex::decode(h).unwrap_or_default());
        let comment_url = gs.get_comment_url().map(|s| s.to_owned());
        drop(gs);

        let comment_data = match comment_hash.as_ref() {
            Some(hash) => {
                let key = hex::encode(hash);
                match comment_url.as_deref() {
                    Some(url) => server.get_session_blobs().get(&key, url).await,
                    None => None,
                }
            }
            None => None,
        };

        let reply = Message::UserState(crate::mumble_proto::UserState {
            session: Some(*session_raw),
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
            comment: comment_data.as_ref().and_then(|b| String::from_utf8(b.to_vec()).ok()),
            hash: None,
            comment_hash: comment_hash.clone(),
            texture_hash: None,
            priority_speaker: None,
            recording: None,
            temporary_access_tokens: Vec::new(),
            listening_channel_add: Vec::new(),
            listening_channel_remove: Vec::new(),
            listening_volume_adjustment: Vec::new(),
        });
        sender.write_proto_message(&reply).await?;
    }

    // ── Channel descriptions ─────────────────────────────────────────────
    for channel_id in &msg.channel_description {
        let Some(ch) = server.get_channels().get_channel(*channel_id).await else {
            continue;
        };
        let desc_data = match ch.description_hash.as_ref() {
            Some(hash) => server.get_channel_blobs().get(hash).await.ok().flatten(),
            None => None,
        };

        let reply = Message::ChannelState(crate::mumble_proto::ChannelState {
            channel_id: Some(ch.id),
            parent: ch.parent_id,
            name: Some(ch.name.clone()),
            links: ch.links.iter().copied().collect(),
            description: desc_data.as_ref().and_then(|b| String::from_utf8(b.to_vec()).ok()),
            links_add: Vec::new(),
            links_remove: Vec::new(),
            temporary: Some(ch.is_temporary()),
            position: Some(ch.position),
            description_hash: ch
                .description_hash
                .as_ref()
                .and_then(|h| hex::decode(h).ok()),
            max_users: Some(ch.max_users),
            is_enter_restricted: None,
            can_enter: None,
        });
        sender.write_proto_message(&reply).await?;
    }

    Ok(())
}
