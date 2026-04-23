use crate::messages::Message;

#[derive(Debug, Clone)]
pub struct PermissionDenied {
    pub r#type: Option<i32>,
    pub session: Option<u32>,
    pub channel_id: Option<u32>,
    pub reason: Option<String>,
    pub name: Option<String>,
    pub permission: Option<u32>,
}

impl From<crate::mumble_proto::PermissionDenied> for PermissionDenied {
    fn from(proto: crate::mumble_proto::PermissionDenied) -> Self {
        Self {
            r#type: proto.r#type,
            session: proto.session,
            channel_id: proto.channel_id,
            reason: proto.reason,
            name: proto.name,
            permission: proto.permission,
        }
    }
}

impl Default for PermissionDenied {
    fn default() -> Self {
        Self {
            r#type: None,
            session: None,
            channel_id: None,
            reason: None,
            name: None,
            permission: None,
        }
    }
}

impl Into<crate::mumble_proto::PermissionDenied> for PermissionDenied {
    fn into(self) -> crate::mumble_proto::PermissionDenied {
        crate::mumble_proto::PermissionDenied {
            r#type: self.r#type,
            session: self.session,
            channel_id: self.channel_id,
            reason: self.reason,
            name: self.name,
            permission: self.permission,
        }
    }
}

impl Into<Message> for PermissionDenied {
    fn into(self) -> Message {
        Message::PermissionDenied(self.into())
    }
}
