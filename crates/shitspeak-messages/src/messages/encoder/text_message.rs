use crate::messages::Message;

#[derive(Debug, Clone)]
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

impl Default for TextMessage {
    fn default() -> Self {
        Self {
            actor: None,
            session: Vec::new(),
            channel_id: Vec::new(),
            tree_id: Vec::new(),
            message: String::new(),
        }
    }
}

impl Into<crate::mumble_proto::TextMessage> for TextMessage {
    fn into(self) -> crate::mumble_proto::TextMessage {
        crate::mumble_proto::TextMessage {
            actor: self.actor,
            session: self.session,
            channel_id: self.channel_id,
            tree_id: self.tree_id,
            message: self.message,
        }
    }
}

impl Into<Message> for TextMessage {
    fn into(self) -> Message {
        Message::TextMessage(self.into())
    }
}
