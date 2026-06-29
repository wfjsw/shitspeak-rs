use crate::messages::Message;

#[derive(Debug, Clone)]
pub struct ServerSync {
    pub session: Option<u32>,
    pub max_bandwidth: Option<u32>,
    pub welcome_text: Option<String>,
    pub permissions: Option<enumflags2::BitFlags<crate::acl::ACLPermissions>>,
}

impl From<crate::mumble_proto::ServerSync> for ServerSync {
    fn from(proto: crate::mumble_proto::ServerSync) -> Self {
        Self {
            session: proto.session,
            max_bandwidth: proto.max_bandwidth,
            welcome_text: proto.welcome_text,
            permissions: proto
                .permissions
                .map(|permissions| enumflags2::BitFlags::from_bits_truncate(permissions as u32)),
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
            permissions: self
                .permissions
                .map(|permissions| u64::from(permissions.bits())),
        }
    }
}

impl Into<Message> for ServerSync {
    fn into(self) -> Message {
        Message::ServerSync(self.into())
    }
}
