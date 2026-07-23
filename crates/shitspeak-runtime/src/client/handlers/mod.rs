mod acl;
mod authenticate;
mod ban_list;
mod channel_remove;
mod channel_state;
mod context_action;
mod crypt_setup;
mod permission_query;
mod ping;
mod plugin_data_transmission;
mod query_users;
mod request_blob;
pub mod temp_channel;
mod text_message;
mod udp_tunnel;
mod user_list;
mod user_remove;
mod user_state;
mod user_stats;
mod version;
mod voice_target;

use std::sync::Arc;

use acl::handle_acl;
use authenticate::handle_authenticate;
use ban_list::handle_ban_list;
use channel_remove::handle_channel_remove;
use channel_state::handle_channel_state;
use context_action::handle_context_action;
use crypt_setup::handle_crypt_setup;
use permission_query::handle_permission_query;
use ping::handle_ping;
use plugin_data_transmission::handle_plugin_data_transmission;
use query_users::handle_query_users;
use request_blob::handle_request_blob;
use text_message::handle_text_message;
use udp_tunnel::handle_udp_tunnel;
use user_list::handle_user_list;
use user_remove::handle_user_remove;
use user_state::handle_user_state;
use user_stats::handle_user_stats;
use version::handle_version;
use voice_target::handle_voice_target;

use crate::{
    errors::{MessageHandlerError, MessageTypeNotForIncoming},
    messages::{Message, errors::MessageProtocolError},
    server::Server,
};

fn channel_op_propose_failed(
    session: u32,
    channel_id: Option<u32>,
    reason: Option<&str>,
) -> MessageHandlerError {
    let reason = reason
        .map(|reason| format!("S2S channel operation failed: {reason}"))
        .unwrap_or_else(|| {
            "Channel operation failed because the S2S commit could not complete; please try again"
                .to_owned()
        });
    MessageHandlerError::PermissionDenied(shitspeak_messages::messages::encoder::PermissionDenied {
        r#type: shitspeak_messages::messages::encoder::DenyType::Permission,
        session,
        channel_id,
        reason: Some(reason.into()),
        name: None,
        permission: None,
    })
}

pub trait AsyncMessageHandlerExt {
    /// Dispatch a message to the appropriate handler.
    async fn handle_message(
        &self,
        server: &Arc<Box<Server>>,
        message: Message,
    ) -> Result<(), MessageHandlerError>;
}

pub(crate) use user_stats::ServerUserStatsResponder;

impl AsyncMessageHandlerExt for Arc<Box<crate::client::Client>> {
    async fn handle_message(
        &self,
        server: &Arc<Box<Server>>,
        message: Message,
    ) -> Result<(), MessageHandlerError> {
        self.in_tracing_span(handle_message_inner(self, server, message))
            .await
    }
}

async fn handle_message_inner(
    client: &Arc<Box<crate::client::Client>>,
    server: &Arc<Box<Server>>,
    message: Message,
) -> Result<(), MessageHandlerError> {
    let session = u32::from(client.get_session_id());
    let result = match message {
        Message::Version(version) => {
            tracing::debug!(
                session,
                version_v1 = ?version.version_v1,
                version_v2 = ?version.version_v2,
                release = ?version.release.as_deref(),
                os = ?version.os.as_deref(),
                os_version = ?version.os_version.as_deref(),
                "handling Version"
            );
            handle_version(server, client, version.into()).await
        }
        Message::UDPTunnel(data) => {
            tracing::trace!(session, len = data.len(), "handling UDPTunnel");
            handle_udp_tunnel(server, client, data).await
        }
        Message::Authenticate(authenticate) => {
            tracing::debug!(
                session,
                username = ?authenticate.username.as_deref(),
                has_password = authenticate.password.is_some(),
                token_count = authenticate.tokens.len(),
                celt_versions = ?authenticate.celt_versions,
                opus = ?authenticate.opus,
                client_type = ?authenticate.client_type,
                "handling Authenticate"
            );
            handle_authenticate(server, client, authenticate.into()).await
        }
        Message::Ping(ping) => {
            tracing::trace!(
                session,
                timestamp = ?ping.timestamp,
                good = ?ping.good,
                late = ?ping.late,
                lost = ?ping.lost,
                resync = ?ping.resync,
                udp_packets = ?ping.udp_packets,
                tcp_packets = ?ping.tcp_packets,
                "handling Ping"
            );
            handle_ping(
                server,
                client,
                ping.try_into().map_err(MessageProtocolError::from)?,
            )
            .await
        }
        Message::Reject(reject) => {
            tracing::debug!(
                session,
                reject_type = ?reject.r#type,
                has_reason = reject.reason.is_some(),
                "rejecting incoming Reject"
            );
            let message = Message::Reject(reject);
            Err(MessageTypeNotForIncoming::new(message).into())
        }
        Message::ServerSync(server_sync) => {
            tracing::debug!(
                session,
                sync_session = ?server_sync.session,
                max_bandwidth = ?server_sync.max_bandwidth,
                has_welcome_text = server_sync.welcome_text.is_some(),
                permissions = ?server_sync.permissions,
                "rejecting incoming ServerSync"
            );
            let message = Message::ServerSync(server_sync);
            Err(MessageTypeNotForIncoming::new(message).into())
        }
        Message::ChannelRemove(channel_remove) => {
            tracing::debug!(
                session,
                channel_id = channel_remove.channel_id,
                "handling ChannelRemove"
            );
            handle_channel_remove(server, client, channel_remove.into()).await
        }
        Message::ChannelState(channel_state) => {
            tracing::debug!(
                session,
                channel_id = channel_state.channel_id,
                parent = ?channel_state.parent,
                name = ?channel_state.name.as_deref(),
                links = channel_state.links.len(),
                links_add = channel_state.links_add.len(),
                links_remove = channel_state.links_remove.len(),
                temporary = ?channel_state.temporary,
                position = ?channel_state.position,
                has_description = channel_state.description.is_some(),
                has_description_hash = channel_state.description_hash.is_some(),
                max_users = ?channel_state.max_users,
                "handling ChannelState"
            );
            handle_channel_state(server, client, channel_state.into()).await
        }
        Message::UserRemove(user_remove) => {
            tracing::debug!(
                session,
                target = user_remove.session,
                actor = ?user_remove.actor,
                ban = ?user_remove.ban,
                has_reason = user_remove.reason.is_some(),
                "handling UserRemove"
            );
            handle_user_remove(server, client, user_remove.into()).await
        }
        Message::UserState(user_state) => {
            tracing::debug!(
                session,
                target = ?user_state.session,
                actor = ?user_state.actor,
                name = ?user_state.name.as_deref(),
                user_id = ?user_state.user_id,
                channel_id = ?user_state.channel_id,
                mute = ?user_state.mute,
                deaf = ?user_state.deaf,
                suppress = ?user_state.suppress,
                self_mute = ?user_state.self_mute,
                self_deaf = ?user_state.self_deaf,
                priority_speaker = ?user_state.priority_speaker,
                recording = ?user_state.recording,
                texture_len = user_state.texture.as_ref().map(|texture| texture.len()),
                plugin_context_len = user_state.plugin_context.as_ref().map(|context| context.len()),
                has_plugin_identity = user_state.plugin_identity.is_some(),
                has_comment = user_state.comment.is_some(),
                has_hash = user_state.hash.is_some(),
                has_comment_hash = user_state.comment_hash.is_some(),
                has_texture_hash = user_state.texture_hash.is_some(),
                temporary_access_tokens = user_state.temporary_access_tokens.len(),
                listening_channel_add = user_state.listening_channel_add.len(),
                listening_channel_remove = user_state.listening_channel_remove.len(),
                listening_volume_adjustments = user_state.listening_volume_adjustment.len(),
                "handling UserState"
            );
            handle_user_state(
                server,
                client,
                user_state.try_into().map_err(MessageProtocolError::from)?,
            )
            .await
        }
        Message::BanList(ban_list) => {
            tracing::debug!(
                session,
                query = ?ban_list.query,
                bans = ban_list.bans.len(),
                "handling BanList"
            );
            handle_ban_list(server, client, ban_list.into()).await
        }
        Message::TextMessage(text_message) => {
            tracing::debug!(
                session,
                actor = ?text_message.actor,
                targets = ?text_message.session,
                channels = ?text_message.channel_id,
                trees = ?text_message.tree_id,
                message_len = text_message.message.len(),
                "handling TextMessage"
            );
            handle_text_message(server, client, text_message.into()).await
        }
        Message::PermissionDenied(permission_denied) => {
            tracing::debug!(
                session,
                denied_session = permission_denied.session,
                deny_type = ?permission_denied.r#type,
                channel_id = ?permission_denied.channel_id,
                permission = ?permission_denied.permission,
                has_reason = permission_denied.reason.is_some(),
                has_name = permission_denied.name.is_some(),
                "rejecting incoming PermissionDenied"
            );
            let message = Message::PermissionDenied(permission_denied);
            Err(MessageTypeNotForIncoming::new(message).into())
        }
        Message::ACL(acl) => {
            tracing::debug!(
                session,
                channel_id = acl.channel_id,
                inherit_acls = ?acl.inherit_acls,
                groups = acl.groups.len(),
                acls = acl.acls.len(),
                query = ?acl.query,
                "handling ACL"
            );
            handle_acl(server, client, acl.into()).await
        }
        Message::QueryUsers(query_users) => {
            tracing::debug!(
                session,
                ids = ?query_users.ids,
                names = ?query_users.names,
                "handling QueryUsers"
            );
            handle_query_users(server, client, query_users.into()).await
        }
        Message::CryptSetup(crypt_setup) => {
            tracing::debug!(
                session,
                is_resync_request = crypt_setup.client_nonce.is_none(),
                key_len = crypt_setup.key.as_ref().map(|key| key.len()),
                client_nonce_len = crypt_setup.client_nonce.as_ref().map(|nonce| nonce.len()),
                server_nonce_len = crypt_setup.server_nonce.as_ref().map(|nonce| nonce.len()),
                "handling CryptSetup"
            );
            handle_crypt_setup(server, client, crypt_setup.into()).await
        }
        Message::ContextActionModify(context_action_modify) => {
            tracing::debug!(
                session,
                action = %context_action_modify.action,
                context = ?context_action_modify.context,
                operation = ?context_action_modify.operation,
                has_text = context_action_modify.text.is_some(),
                "rejecting incoming ContextActionModify"
            );
            let message = Message::ContextActionModify(context_action_modify);
            Err(MessageTypeNotForIncoming::new(message).into())
        }
        Message::ContextAction(context_action) => {
            tracing::debug!(
                session,
                target_session = ?context_action.session,
                channel_id = ?context_action.channel_id,
                action = %context_action.action,
                "handling ContextAction"
            );
            handle_context_action(server, client, context_action.into()).await
        }
        Message::UserList(user_list) => {
            tracing::debug!(
                session,
                num_users = user_list.users.len(),
                "handling UserList"
            );
            handle_user_list(server, client, user_list.into()).await
        }
        Message::VoiceTarget(voice_target) => {
            tracing::debug!(
                session,
                target_id = ?voice_target.id,
                targets = voice_target.targets.len(),
                "handling VoiceTarget"
            );
            handle_voice_target(server, client, voice_target.into()).await
        }
        Message::PermissionQuery(permission_query) => {
            tracing::debug!(
                session,
                channel_id = ?permission_query.channel_id,
                permissions = ?permission_query.permissions,
                flush = ?permission_query.flush,
                "handling PermissionQuery"
            );
            handle_permission_query(server, client, permission_query.into()).await
        }
        Message::CodecVersion(codec_version) => {
            tracing::debug!(
                session,
                alpha = codec_version.alpha,
                beta = codec_version.beta,
                prefer_alpha = codec_version.prefer_alpha,
                opus = ?codec_version.opus,
                "rejecting incoming CodecVersion"
            );
            let message = Message::CodecVersion(codec_version);
            Err(MessageTypeNotForIncoming::new(message).into())
        }
        Message::UserStats(user_stats) => {
            tracing::debug!(
                session,
                target = ?user_stats.session,
                stats_only = ?user_stats.stats_only,
                certificates = user_stats.certificates.len(),
                has_from_client = user_stats.from_client.is_some(),
                has_from_server = user_stats.from_server.is_some(),
                celt_versions = ?user_stats.celt_versions,
                address = ?user_stats.address,
                bandwidth = ?user_stats.bandwidth,
                opus = ?user_stats.opus,
                "handling UserStats"
            );
            handle_user_stats(server, client, user_stats.into()).await
        }
        Message::RequestBlob(request_blob) => {
            tracing::debug!(
                session,
                textures = request_blob.session_texture.len(),
                comments = request_blob.session_comment.len(),
                "handling RequestBlob"
            );
            handle_request_blob(server, client, request_blob.into()).await
        }
        Message::ServerConfig(server_config) => {
            tracing::debug!(
                session,
                max_bandwidth = ?server_config.max_bandwidth,
                has_welcome_text = server_config.welcome_text.is_some(),
                allow_html = ?server_config.allow_html,
                message_length = ?server_config.message_length,
                image_message_length = ?server_config.image_message_length,
                max_users = ?server_config.max_users,
                "rejecting incoming ServerConfig"
            );
            let message = Message::ServerConfig(server_config);
            Err(MessageTypeNotForIncoming::new(message).into())
        }
        Message::SuggestConfig(suggest_config) => {
            tracing::debug!(
                session,
                version_v1 = ?suggest_config.version_v1,
                version_v2 = ?suggest_config.version_v2,
                positional = ?suggest_config.positional,
                push_to_talk = ?suggest_config.push_to_talk,
                "rejecting incoming SuggestConfig"
            );
            let message = Message::SuggestConfig(suggest_config);
            Err(MessageTypeNotForIncoming::new(message).into())
        }
        Message::PluginDataTransmission(plugin_data) => {
            tracing::debug!(
                session,
                sender_session = ?plugin_data.sender_session,
                receivers = plugin_data.receiver_sessions.len(),
                data_id = ?plugin_data.data_id.as_deref(),
                data_len = plugin_data.data.as_ref().map(|data| data.len()),
                "handling PluginDataTransmission"
            );
            handle_plugin_data_transmission(server, client, plugin_data.into()).await
        }
    };

    // Triage the result: auth rejections and permission denials are sent
    // back to the client immediately; all other errors propagate.
    match result {
        Err(MessageHandlerError::ProtocolViolation(reason)) => {
            tracing::warn!(session, reason = %reason, "Protocol violation");
            let reject = crate::errors::AuthRejection::new_with_language(
                shitspeak_messages::messages::encoder::RejectType::None,
                client.language(),
            );
            let reject_msg: shitspeak_messages::messages::encoder::Reject = reject.clone().into();
            let msg = shitspeak_messages::messages::Message::Reject(reject_msg.into());
            client.write_proto_message_direct(&msg).await?;
            Err(MessageHandlerError::AuthRejection(reject))
        }
        Err(MessageHandlerError::AuthRejection(reject)) => {
            let reject_msg: shitspeak_messages::messages::encoder::Reject =
                reject.clone().localized(client.language()).into();
            let msg = shitspeak_messages::messages::Message::Reject(reject_msg.into());
            client.write_proto_message_direct(&msg).await?;
            Err(MessageHandlerError::AuthRejection(reject))
        }
        Err(MessageHandlerError::PermissionDenied(mut deny)) => {
            if deny.reason.is_none() {
                deny.reason = Some(crate::localization::permission_denied_reason(
                    client.language(),
                    deny.r#type,
                ));
            }
            tracing::warn!(
                session,
                denied_session = deny.session,
                deny_type = ?deny.r#type,
                channel_id = ?deny.channel_id,
                permission = ?deny.permission,
                name = ?deny.name,
                reason = ?deny.reason,
                "Permission denied"
            );
            let msg: shitspeak_messages::messages::Message = deny.into();
            client.write_proto_message(&msg).await?;
            Ok(())
        }
        other => other,
    }
}
