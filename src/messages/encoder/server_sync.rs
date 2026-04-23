use crate::messages::Message;

#[derive(Debug, Clone)]
pub struct ServerSync {
    pub session: Option<u32>,
    pub max_bandwidth: Option<u32>,
    pub welcome_text: Option<String>,
    pub permissions: Option<u64>,
}

impl From<crate::mumble_proto::ServerSync> for ServerSync {
    fn from(proto: crate::mumble_proto::ServerSync) -> Self {
        Self {
            session: proto.session,
            max_bandwidth: proto.max_bandwidth,
            welcome_text: proto.welcome_text,
            permissions: proto.permissions,
        }
    }
}

impl Default for ServerSync {
    fn default() -> Self {
        Self {
            session: None,
            max_bandwidth: None,
            welcome_text: None,
            permissions: None,
        }
    }
}

impl Into<crate::mumble_proto::ServerSync> for ServerSync {
    fn into(self) -> crate::mumble_proto::ServerSync {
        crate::mumble_proto::ServerSync {
            session: self.session,
            max_bandwidth: self.max_bandwidth,
            welcome_text: self.welcome_text,
            permissions: self.permissions,
        }
    }
}

impl Into<Message> for ServerSync {
    fn into(self) -> Message {
        Message::ServerSync(self.into())
    }
}
