use super::RejectType;
use crate::messages::Message;

#[derive(Debug, Clone)]
pub struct Reject {
    pub r#type: Option<RejectType>,
    pub reason: Option<String>,
}

impl From<crate::mumble_proto::Reject> for Reject {
    fn from(proto: crate::mumble_proto::Reject) -> Self {
        Self {
            r#type: proto.r#type.map(RejectType::from_proto),
            reason: proto.reason,
        }
    }
}

impl Default for Reject {
    fn default() -> Self {
        Self {
            r#type: None,
            reason: None,
        }
    }
}

impl Into<crate::mumble_proto::Reject> for Reject {
    fn into(self) -> crate::mumble_proto::Reject {
        crate::mumble_proto::Reject {
            r#type: self.r#type.map(|t| t as i32),
            reason: self.reason,
        }
    }
}

impl Into<Message> for Reject {
    fn into(self) -> Message {
        Message::Reject(self.into())
    }
}
