use crate::messages::Message;

#[derive(Debug, Clone)]
pub struct ContextAction {
    pub session: Option<u32>,
    pub channel_id: Option<u32>,
    pub action: String,
}

impl From<crate::mumble_proto::ContextAction> for ContextAction {
    fn from(proto: crate::mumble_proto::ContextAction) -> Self {
        Self {
            session: proto.session,
            channel_id: proto.channel_id,
            action: proto.action,
        }
    }
}

impl Default for ContextAction {
    fn default() -> Self {
        Self {
            session: None,
            channel_id: None,
            action: String::new(),
        }
    }
}

impl Into<crate::mumble_proto::ContextAction> for ContextAction {
    fn into(self) -> crate::mumble_proto::ContextAction {
        crate::mumble_proto::ContextAction {
            session: self.session,
            channel_id: self.channel_id,
            action: self.action,
        }
    }
}

impl Into<Message> for ContextAction {
    fn into(self) -> Message {
        Message::ContextAction(self.into())
    }
}
