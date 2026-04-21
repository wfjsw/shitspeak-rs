mod acl;
mod authenticate;
mod ban_list;
mod channel_remove;
mod channel_state;
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

use prost::Message as _;

use acl::handle_acl;
use authenticate::handle_authenticate;
use ban_list::handle_ban_list;
use channel_remove::handle_channel_remove;
use channel_state::handle_channel_state;
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
/// The `data` is the raw protobuf-encoded `Audio` message.  We decode it,
/// stamp the sender session, and pass it to `route_voice()`.
async fn handle_udp_tunnel(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<crate::client::Client>>,
    data: Vec<u8>,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated().await {
        return Ok(());
    }

    let audio = match crate::mumble_udp::Audio::decode(&*data) {
        Ok(a) => a,
        Err(_) => return Ok(()),
    };

    crate::voice::route_voice(server, sender, &audio, false).await;
    Ok(())
}

 
pub trait AsyncMessageHandlerExt {
    async fn read_and_handle_message(
        &self,
        server: &Arc<Box<Server>>,
    ) -> Result<(), MessageHandlerError>;
}

impl AsyncMessageHandlerExt for Arc<Box<crate::client::Client>> {
    async fn read_and_handle_message(
        &self,
        server: &Arc<Box<Server>>,
    ) -> Result<(), MessageHandlerError> {
        match self.read_proto_message().await {
            Ok(message) => match message {
                Message::Version(version) => handle_version(server, self, version.into()).await,
                Message::UDPTunnel(data) => {
                    handle_udp_tunnel(server, self, data).await
                }
                Message::Authenticate(authenticate) => {
                    handle_authenticate(server, self, authenticate.into()).await
                }
                Message::Ping(ping) => {
                    handle_ping(
                        server,
                        self,
                        ping.try_into().map_err(MessageProtocolError::from)?,
                    )
                    .await
                }
                Message::Reject(_) => Err(MessageTypeNotForIncoming::new(message).into()),
                Message::ServerSync(_) => Err(MessageTypeNotForIncoming::new(message).into()),
                Message::ChannelRemove(channel_remove) => {
                    handle_channel_remove(server, self, channel_remove).await
                }
                Message::ChannelState(channel_state) => {
                    handle_channel_state(server, self, channel_state).await
                }
                Message::UserRemove(user_remove) => {
                    handle_user_remove(server, self, user_remove).await
                }
                Message::UserState(user_state) => {
                    handle_user_state(
                        server,
                        self,
                        user_state.try_into().map_err(MessageProtocolError::from)?,
                    )
                    .await
                }
                Message::BanList(ban_list) => {
                    handle_ban_list(server, self, ban_list).await
                }
                Message::TextMessage(text_message) => {
                    handle_text_message(server, self, text_message).await
                }
                Message::PermissionDenied(_) => Err(MessageTypeNotForIncoming::new(message).into()),
                Message::ACL(acl) => {
                    handle_acl(server, self, acl).await
                }
                Message::QueryUsers(query_users) => {
                    handle_query_users(server, self, query_users).await
                }
                Message::CryptSetup(crypt_setup) => {
                    handle_crypt_setup(server, self, crypt_setup.into()).await
                }
                Message::ContextActionModify(_) => Ok(()),
                Message::ContextAction(_) => Ok(()),
                Message::UserList(user_list) => {
                    handle_user_list(server, self, user_list).await
                }
                Message::VoiceTarget(voice_target) => {
                    handle_voice_target(server, self, voice_target).await
                }
                Message::PermissionQuery(permission_query) => {
                    handle_permission_query(server, self, permission_query).await
                }
                Message::CodecVersion(_) => Err(MessageTypeNotForIncoming::new(message).into()),
                Message::UserStats(user_stats) => {
                    handle_user_stats(server, self, user_stats).await
                }
                Message::RequestBlob(request_blob) => {
                    handle_request_blob(server, self, request_blob).await
                }
                Message::ServerConfig(_) => Err(MessageTypeNotForIncoming::new(message).into()),
                Message::SuggestConfig(suggest_config) => {
                    Err(MessageTypeNotForIncoming::new(message).into())
                }
            },
            Err(e) => Err(e.into()),
        }
    }
}
