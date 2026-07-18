use crate::messages::Message;

#[derive(Debug, Clone, Default)]
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

impl From<ContextAction> for crate::mumble_proto::ContextAction {
    fn from(context_action: ContextAction) -> Self {
        crate::mumble_proto::ContextAction {
            session: context_action.session,
            channel_id: context_action.channel_id,
            action: context_action.action,
        }
    }
}

impl From<ContextAction> for Message {
    fn from(context_action: ContextAction) -> Self {
        Self::ContextAction(context_action.into())
    }
}
