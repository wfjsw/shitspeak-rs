use bytes::Bytes;

use crate::messages::Message;

#[derive(Debug, Clone, Default)]
pub struct PluginDataTransmission {
    pub sender_session: Option<u32>,
    pub receiver_sessions: Vec<u32>,
    pub data: Option<Bytes>,
    pub data_id: Option<String>,
}

impl From<shitspeak_proto::mumble_proto::PluginDataTransmission> for PluginDataTransmission {
    fn from(proto: shitspeak_proto::mumble_proto::PluginDataTransmission) -> Self {
        Self {
            sender_session: proto.sender_session,
            receiver_sessions: proto.receiver_sessions,
            data: proto.data,
            data_id: proto.data_id,
        }
    }
}

impl From<PluginDataTransmission> for shitspeak_proto::mumble_proto::PluginDataTransmission {
    fn from(value: PluginDataTransmission) -> Self {
        shitspeak_proto::mumble_proto::PluginDataTransmission {
            sender_session: value.sender_session,
            receiver_sessions: value.receiver_sessions,
            data: value.data,
            data_id: value.data_id,
        }
    }
}

impl From<PluginDataTransmission> for Message {
    fn from(value: PluginDataTransmission) -> Self {
        Message::PluginDataTransmission(value.into())
    }
}
