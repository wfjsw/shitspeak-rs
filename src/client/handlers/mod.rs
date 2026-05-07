mod acl;
mod authenticate;
mod ban_list;
mod channel_remove;
mod channel_state;
mod context_action;
mod crypt_setup;
mod permission_query;
mod ping;
mod query_users;
mod request_blob;
mod text_message;
mod user_list;
mod user_remove;
mod user_state;
mod user_stats;
mod version;
mod voice_target;

use std::sync::Arc;

use bytes::Bytes;
use prost::Message as _;

use acl::handle_acl;
use authenticate::handle_authenticate;
use ban_list::handle_ban_list;
use channel_remove::handle_channel_remove;
use channel_state::handle_channel_state;
use context_action::handle_context_action;
use crypt_setup::handle_crypt_setup;
use permission_query::handle_permission_query;
use ping::handle_ping;
use query_users::handle_query_users;
use request_blob::handle_request_blob;
use text_message::handle_text_message;
use user_list::handle_user_list;
use user_remove::handle_user_remove;
use user_stats::handle_user_stats;
use version::handle_version;
use voice_target::handle_voice_target;

use crate::{
    client::handlers::user_state::handle_user_state,
    errors::{MessageHandlerError, MessageTypeNotForIncoming},
    messages::{errors::MessageProtocolError, Message},
    server::Server,
};

/// Handle a TCP-tunneled voice packet.
///
/// The `data` is the raw voice packet bytes (legacy or protobuf format).
/// We decode it and push it to the per-user voice routing queue.
async fn handle_udp_tunnel(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<crate::client::Client>>,
    data: Bytes,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated() {
        return Err(MessageHandlerError::protocol_violation(
            "UDPTunnel message received before authentication",
        ));
    }

    // Match Mumble/shitspeak behavior: a tunneled voice packet means
    // this client currently prefers TCP transport for voice.
    sender.set_prefer_tcp_tunnel(true);

    let audio = match crate::voice::codec::decode_audio_packet(&data) {
        Ok(a) => a,
        Err(e) => {
            tracing::trace!(session = u32::from(sender.get_session_id()), len = data.len(), error = %e, "UDPTunnel: decode failed");
            return Ok(());
        }
    };

    tracing::trace!(session = u32::from(sender.get_session_id()), target = %audio.target, frame = audio.frame_number, len = audio.opus_data.len(), "UDPTunnel: routing voice");
    sender.push_voice_routing(audio, false);
    Ok(())
}

 
pub trait AsyncMessageHandlerExt {
    /// Dispatch a message to the appropriate handler.
    async fn handle_message(
        &self,
        server: &Arc<Box<Server>>,
        message: Message,
    ) -> Result<(), MessageHandlerError>;
}

impl AsyncMessageHandlerExt for Arc<Box<crate::client::Client>> {
    async fn handle_message(
        &self,
        server: &Arc<Box<Server>>,
        message: Message,
    ) -> Result<(), MessageHandlerError> {
        let session = u32::from(self.get_session_id());
        let result = match message {
            Message::Version(version) => {
                tracing::debug!(session, "handling Version");
                handle_version(server, self, version.into()).await
            }
            Message::UDPTunnel(data) => {
                tracing::trace!(session, len = data.len(), "handling UDPTunnel");
                handle_udp_tunnel(server, self, data).await
            }
            Message::Authenticate(authenticate) => {
                tracing::debug!(session, "handling Authenticate");
                handle_authenticate(server, self, authenticate.into()).await
            }
            Message::Ping(ping) => {
                tracing::trace!(session, "handling Ping");
                handle_ping(
                    server,
                    self,
                    ping.try_into().map_err(MessageProtocolError::from)?,
                )
                .await
            }
            Message::Reject(_) => {
                tracing::debug!(session, "rejecting incoming Reject");
                Err(MessageTypeNotForIncoming::new(message).into())
            }
            Message::ServerSync(_) => {
                tracing::debug!(session, "rejecting incoming ServerSync");
                Err(MessageTypeNotForIncoming::new(message).into())
            }
            Message::ChannelRemove(channel_remove) => {
                tracing::debug!(session, channel_id = channel_remove.channel_id, "handling ChannelRemove");
                handle_channel_remove(server, self, channel_remove.into()).await
            }
            Message::ChannelState(channel_state) => {
                tracing::debug!(session, channel_id = channel_state.channel_id, "handling ChannelState");
                handle_channel_state(server, self, channel_state.into()).await
            }
            Message::UserRemove(user_remove) => {
                tracing::debug!(session, target = user_remove.session, "handling UserRemove");
                handle_user_remove(server, self, user_remove.into()).await
            }
            Message::UserState(user_state) => {
                tracing::debug!(session, target = user_state.session, "handling UserState");
                handle_user_state(
                    server,
                    self,
                    user_state.try_into().map_err(MessageProtocolError::from)?,
                )
                .await
            }
            Message::BanList(ban_list) => {
                tracing::debug!(session, query = ban_list.query, "handling BanList");
                handle_ban_list(server, self, ban_list.into()).await
            }
            Message::TextMessage(text_message) => {
                tracing::debug!(session, channels = ?text_message.channel_id, trees = ?text_message.tree_id, "handling TextMessage");
                handle_text_message(server, self, text_message.into()).await
            }
            Message::PermissionDenied(_) => {
                tracing::debug!(session, "rejecting incoming PermissionDenied");
                Err(MessageTypeNotForIncoming::new(message).into())
            }
            Message::ACL(acl) => {
                tracing::debug!(session, channel_id = acl.channel_id, query = acl.query, "handling ACL");
                handle_acl(server, self, acl.into()).await
            }
            Message::QueryUsers(query_users) => {
                tracing::debug!(session, ids = ?query_users.ids, names = ?query_users.names, "handling QueryUsers");
                handle_query_users(server, self, query_users.into()).await
            }
            Message::CryptSetup(crypt_setup) => {
                tracing::debug!(session, "handling CryptSetup");
                handle_crypt_setup(server, self, crypt_setup.into()).await
            }
            Message::ContextActionModify(_) => {
                tracing::debug!(session, "handling ContextActionModify (no-op)");
                Ok(())
            }
            Message::ContextAction(context_action) => {
                tracing::debug!(session, action = %context_action.action, "handling ContextAction");
                handle_context_action(server, self, context_action.into()).await
            }
            Message::UserList(user_list) => {
                tracing::debug!(session, num_users = user_list.users.len(), "handling UserList");
                handle_user_list(server, self, user_list.into()).await
            }
            Message::VoiceTarget(voice_target) => {
                tracing::debug!(session, target_id = voice_target.id, "handling VoiceTarget");
                handle_voice_target(server, self, voice_target.into()).await
            }
            Message::PermissionQuery(permission_query) => {
                tracing::debug!(session, channel_id = permission_query.channel_id, "handling PermissionQuery");
                handle_permission_query(server, self, permission_query.into()).await
            }
            Message::CodecVersion(_) => {
                tracing::debug!(session, "rejecting incoming CodecVersion");
                Err(MessageTypeNotForIncoming::new(message).into())
            }
            Message::UserStats(user_stats) => {
                tracing::debug!(session, target = user_stats.session, "handling UserStats");
                handle_user_stats(server, self, user_stats.into()).await
            }
            Message::RequestBlob(request_blob) => {
                tracing::debug!(session, textures = request_blob.session_texture.len(), comments = request_blob.session_comment.len(), "handling RequestBlob");
                handle_request_blob(server, self, request_blob.into()).await
            }
            Message::ServerConfig(_) => {
                tracing::debug!(session, "rejecting incoming ServerConfig");
                Err(MessageTypeNotForIncoming::new(message).into())
            }
            Message::SuggestConfig(_) => {
                tracing::debug!(session, "rejecting incoming SuggestConfig");
                Err(MessageTypeNotForIncoming::new(message).into())
            }
        };

        // Triage the result: auth rejections and permission denials are sent
        // back to the client immediately; all other errors propagate.
        match result {
            Err(MessageHandlerError::ProtocolViolation(reason)) => {
                use crate::messages::WriteMessageExt;
                tracing::warn!(session, reason = %reason, "Protocol violation");
                let reject = crate::errors::AuthRejection::new(crate::messages::encoder::RejectType::None)
                    .because(reason);
                let reject_msg: crate::messages::encoder::Reject = reject.clone().into();
                let msg = crate::messages::Message::Reject(reject_msg.into());
                self.write_proto_message(&msg).await?;
                Err(MessageHandlerError::AuthRejection(reject))
            }
            Err(MessageHandlerError::AuthRejection(reject)) => {
                use crate::messages::WriteMessageExt;
                let reject_msg: crate::messages::encoder::Reject = reject.clone().into();
                let msg = crate::messages::Message::Reject(reject_msg.into());
                self.write_proto_message(&msg).await?;
                Err(MessageHandlerError::AuthRejection(reject))
            }
            Err(MessageHandlerError::PermissionDenied(deny)) => {
                use crate::messages::WriteMessageExt;
                let msg: crate::messages::Message = deny.into();
                self.write_proto_message(&msg).await?;
                Ok(())
            }
            other => other,
        }
    }
}
