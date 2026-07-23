use super::RejectType;
use crate::messages::Message;

#[derive(Debug, Clone, Default)]
pub struct Reject {
    pub r#type: Option<RejectType>,
    pub reason: Option<String>,
}

impl From<shitspeak_proto::mumble_proto::Reject> for Reject {
    fn from(proto: shitspeak_proto::mumble_proto::Reject) -> Self {
        Self {
            r#type: proto.r#type.map(RejectType::from_proto),
            reason: proto.reason,
        }
    }
}

impl From<Reject> for shitspeak_proto::mumble_proto::Reject {
    fn from(value: Reject) -> Self {
        shitspeak_proto::mumble_proto::Reject {
            r#type: value.r#type.map(|t| t as i32),
            reason: value.reason,
        }
    }
}

impl From<Reject> for Message {
    fn from(value: Reject) -> Self {
        Message::Reject(value.into())
    }
}
