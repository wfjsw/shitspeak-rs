use prost::Message as _;
use bytes::Bytes;

use crate::{mumble_proto::*};

use message_macro::MessageConversion;

#[repr(u16)]
#[derive(Debug, Clone, MessageConversion)]
pub enum Message {
    Version(Version),
    /// Wire message type 1 reserved for UDP-over-TCP payload bytes.
    ///
    /// Despite the historical `UDPTunnel` protobuf declaration, Mumble treats
    /// this as a raw frame: after the standard TCP message header
    /// `(u16 type, u32 len)`, the UDP packet bytes follow directly without a
    /// protobuf field wrapper.
    UDPTunnel(Bytes),
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

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_tunnel_to_proto_vec_is_raw_payload() {
        let payload = Bytes::from_static(&[0x80, 0x01, 0x02, 0x03]);
        let message = Message::UDPTunnel(payload.clone());

        assert_eq!(message.proto_tag(), 1);
        assert_eq!(message.encoded_len(), payload.len());
        assert_eq!(message.to_proto_vec().unwrap(), payload);
    }

    #[test]
    fn udp_tunnel_from_proto_uses_raw_payload() {
        let payload = Bytes::from_static(&[0x10, 0x20, 0x30]);

        match Message::from_proto(1, payload.clone()).unwrap() {
            Message::UDPTunnel(data) => assert_eq!(data, payload),
            other => panic!("expected UDPTunnel, got {other:?}"),
        }
    }
}
