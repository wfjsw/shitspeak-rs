use crate::messages::Message;

#[derive(Debug, Clone, Default)]
pub struct ChannelRemove {
    pub channel_id: u32,
}

impl From<shitspeak_proto::mumble_proto::ChannelRemove> for ChannelRemove {
    fn from(proto: shitspeak_proto::mumble_proto::ChannelRemove) -> Self {
        Self {
            channel_id: proto.channel_id,
        }
    }
}

impl From<ChannelRemove> for shitspeak_proto::mumble_proto::ChannelRemove {
    fn from(value: ChannelRemove) -> Self {
        shitspeak_proto::mumble_proto::ChannelRemove {
            channel_id: value.channel_id,
        }
    }
}

impl From<ChannelRemove> for Message {
    fn from(value: ChannelRemove) -> Self {
        Self::ChannelRemove(value.into())
    }
}
