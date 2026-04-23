use crate::messages::Message;

#[derive(Debug, Clone)]
pub struct PermissionQuery {
    pub channel_id: Option<u32>,
    pub permissions: Option<u32>,
    pub flush: Option<bool>,
}

impl From<crate::mumble_proto::PermissionQuery> for PermissionQuery {
    fn from(proto: crate::mumble_proto::PermissionQuery) -> Self {
        Self {
            channel_id: proto.channel_id,
            permissions: proto.permissions,
            flush: proto.flush,
        }
    }
}

impl Default for PermissionQuery {
    fn default() -> Self {
        Self {
            channel_id: None,
            permissions: None,
            flush: None,
        }
    }
}

impl Into<crate::mumble_proto::PermissionQuery> for PermissionQuery {
    fn into(self) -> crate::mumble_proto::PermissionQuery {
        crate::mumble_proto::PermissionQuery {
            channel_id: self.channel_id,
            permissions: self.permissions,
            flush: self.flush,
        }
    }
}

impl Into<Message> for PermissionQuery {
    fn into(self) -> Message {
        Message::PermissionQuery(self.into())
    }
}
