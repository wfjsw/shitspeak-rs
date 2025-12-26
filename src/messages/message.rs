use prost::Message as _;

use crate::{mumble_proto::*};

use message_macro::MessageConversion;

#[repr(u16)]
#[derive(Debug, Clone, PartialEq, MessageConversion)]
pub enum Message {
    Version(Version),
    UDPTunnel(Vec<u8>),
    Authenticate(Authenticate),
    Ping(Ping),
    Reject(Reject),
    ServerSync(ServerSync),
    ChannelRemove(ChannelRemove),
    ChannelState(ChannelState),
    UserRemove(UserRemove),
    UserState(UserState),
    BanList(BanList),
    TextMessage(TextMessage),
    PermissionDenied(PermissionDenied),
    ACL(Acl),
    QueryUsers(QueryUsers),
    CryptSetup(CryptSetup),
    ContextActionModify(ContextActionModify),
    ContextAction(ContextAction),
    UserList(UserList),
    VoiceTarget(VoiceTarget),
    PermissionQuery(PermissionQuery),
    CodecVersion(CodecVersion),
    UserStats(UserStats),
    RequestBlob(RequestBlob),
    ServerConfig(ServerConfig),
    SuggestConfig(SuggestConfig),
}
