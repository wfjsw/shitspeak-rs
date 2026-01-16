mod acl;
mod authenticate;
mod ban_list;
mod channel_remove;
mod channel_state;
mod crypt_setup;
mod permission_query;
mod ping;
mod user_state;
mod version;
// mod query_users;
// mod request_blob;
// mod text_message;
// mod user_list;
// mod user_remove;
// mod user_state;
// mod user_stats;
// mod voice_target;

use std::sync::Arc;

use acl::handle_acl;
use authenticate::handle_authenticate;
// pub(crate) use ban_list::handle_ban_list;
use channel_remove::handle_channel_remove;
use channel_state::handle_channel_state;
use crypt_setup::handle_crypt_setup;
use permission_query::handle_permission_query;
use ping::handle_ping;
use version::handle_version;

use crate::{
    client::handlers::user_state::handle_user_state,
    errors::{MessageHandlerError, MessageTypeNotForIncoming},
    messages::{errors::MessageProtocolError, Message},
    server::Server,
};

 
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
                Message::UDPTunnel(items) => todo!(),
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
                Message::UserRemove(user_remove) => todo!(),
                Message::UserState(user_state) => {
                    handle_user_state(
                        server,
                        self,
                        user_state.try_into().map_err(MessageProtocolError::from)?,
                    )
                    .await
                }
                Message::BanList(ban_list) => todo!(),
                Message::TextMessage(text_message) => todo!(),
                Message::PermissionDenied(_) => Err(MessageTypeNotForIncoming::new(message).into()),
                Message::ACL(acl) => todo!(),
                Message::QueryUsers(query_users) => todo!(),
                Message::CryptSetup(crypt_setup) => {
                    handle_crypt_setup(server, self, crypt_setup.into()).await
                }
                Message::ContextActionModify(context_action_modify) => todo!(),
                Message::ContextAction(context_action) => todo!(),
                Message::UserList(user_list) => todo!(),
                Message::VoiceTarget(voice_target) => todo!(),
                Message::PermissionQuery(permission_query) => {
                    handle_permission_query(server, self, permission_query).await
                }
                Message::CodecVersion(_) => Err(MessageTypeNotForIncoming::new(message).into()),
                Message::UserStats(user_stats) => todo!(),
                Message::RequestBlob(request_blob) => todo!(),
                Message::ServerConfig(_) => Err(MessageTypeNotForIncoming::new(message).into()),
                Message::SuggestConfig(suggest_config) => {
                    Err(MessageTypeNotForIncoming::new(message).into())
                }
            },
            Err(e) => Err(e.into()),
        }
    }
}
