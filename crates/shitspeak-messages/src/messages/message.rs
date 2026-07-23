use bytes::Bytes;
use prost::Message as _;

use shitspeak_proto::mumble_proto::*;

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
    PluginDataTransmission(PluginDataTransmission),
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

    #[test]
    fn plugin_data_transmission_uses_mumble_wire_tag_26() {
        let message = Message::PluginDataTransmission(
            shitspeak_proto::mumble_proto::PluginDataTransmission {
                sender_session: Some(7),
                receiver_sessions: vec![8, 9],
                data: Some(Bytes::from_static(b"plugin-payload")),
                data_id: Some("example.plugin".to_string()),
            },
        );

        assert_eq!(message.proto_tag(), 26);
        let decoded = Message::from_proto(26, message.to_proto_vec().unwrap()).unwrap();
        match decoded {
            Message::PluginDataTransmission(plugin) => {
                assert_eq!(plugin.sender_session, Some(7));
                assert_eq!(plugin.receiver_sessions, vec![8, 9]);
                assert_eq!(plugin.data, Some(Bytes::from_static(b"plugin-payload")));
                assert_eq!(plugin.data_id.as_deref(), Some("example.plugin"));
            }
            other => panic!("expected PluginDataTransmission, got {other:?}"),
        }
    }
}
