use crate::messages::Message;

#[derive(Debug, Clone, Default)]
pub struct ContextActionModify {
    pub action: String,
    pub text: Option<String>,
    pub context: Option<u32>,
    pub operation: Option<i32>,
}

impl From<shitspeak_proto::mumble_proto::ContextActionModify> for ContextActionModify {
    fn from(proto: shitspeak_proto::mumble_proto::ContextActionModify) -> Self {
        Self {
            action: proto.action,
            text: proto.text,
            context: proto.context,
            operation: proto.operation,
        }
    }
}

impl From<ContextActionModify> for shitspeak_proto::mumble_proto::ContextActionModify {
    fn from(context_action_modify: ContextActionModify) -> Self {
        shitspeak_proto::mumble_proto::ContextActionModify {
            action: context_action_modify.action,
            text: context_action_modify.text,
            context: context_action_modify.context,
            operation: context_action_modify.operation,
        }
    }
}

impl From<ContextActionModify> for Message {
    fn from(context_action_modify: ContextActionModify) -> Self {
        Self::ContextActionModify(context_action_modify.into())
    }
}
