use crate::messages::Message;

#[derive(Debug, Clone)]
pub struct ChannelRemove {
    pub channel_id: u32,
}

impl From<crate::mumble_proto::ChannelRemove> for ChannelRemove {
    fn from(proto: crate::mumble_proto::ChannelRemove) -> Self {
        Self {
            channel_id: proto.channel_id,
        }
    }
}

impl Default for ChannelRemove {
    fn default() -> Self {
        Self { channel_id: 0 }
    }
}

impl Into<crate::mumble_proto::ChannelRemove> for ChannelRemove {
    fn into(self) -> crate::mumble_proto::ChannelRemove {
        crate::mumble_proto::ChannelRemove {
            channel_id: self.channel_id,
        }
    }
}

impl Into<Message> for ChannelRemove {
    fn into(self) -> Message {
        Message::ChannelRemove(self.into())
    }
}
