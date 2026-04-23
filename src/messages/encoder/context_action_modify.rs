use crate::messages::Message;

#[derive(Debug, Clone)]
pub struct ContextActionModify {
    pub action: String,
    pub text: Option<String>,
    pub context: Option<u32>,
    pub operation: Option<i32>,
}

impl From<crate::mumble_proto::ContextActionModify> for ContextActionModify {
    fn from(proto: crate::mumble_proto::ContextActionModify) -> Self {
        Self {
            action: proto.action,
            text: proto.text,
            context: proto.context,
            operation: proto.operation,
        }
    }
}

impl Default for ContextActionModify {
    fn default() -> Self {
        Self {
            action: String::new(),
            text: None,
            context: None,
            operation: None,
        }
    }
}

impl Into<crate::mumble_proto::ContextActionModify> for ContextActionModify {
    fn into(self) -> crate::mumble_proto::ContextActionModify {
        crate::mumble_proto::ContextActionModify {
            action: self.action,
            text: self.text,
            context: self.context,
            operation: self.operation,
        }
    }
}

impl Into<Message> for ContextActionModify {
    fn into(self) -> Message {
        Message::ContextActionModify(self.into())
    }
}
