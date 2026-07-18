use crate::messages::Message;

#[derive(Debug, Clone, Default)]
pub struct TextMessage {
    pub actor: Option<u32>,
    pub session: Vec<u32>,
    pub channel_id: Vec<u32>,
    pub tree_id: Vec<u32>,
    pub message: String,
}

impl From<crate::mumble_proto::TextMessage> for TextMessage {
    fn from(proto: crate::mumble_proto::TextMessage) -> Self {
        Self {
            actor: proto.actor,
            session: proto.session,
            channel_id: proto.channel_id,
            tree_id: proto.tree_id,
            message: proto.message,
        }
    }
}

impl From<TextMessage> for crate::mumble_proto::TextMessage {
    fn from(message: TextMessage) -> Self {
        crate::mumble_proto::TextMessage {
            actor: message.actor,
            session: message.session,
            channel_id: message.channel_id,
            tree_id: message.tree_id,
            message: message.message,
        }
    }
}

impl From<TextMessage> for Message {
    fn from(message: TextMessage) -> Self {
        Message::TextMessage(message.into())
    }
}
