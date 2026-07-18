use crate::messages::Message;

#[derive(Debug, Clone, Default)]
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

impl From<ServerSync> for crate::mumble_proto::ServerSync {
    fn from(value: ServerSync) -> Self {
        crate::mumble_proto::ServerSync {
            session: value.session,
            max_bandwidth: value.max_bandwidth,
            welcome_text: value.welcome_text,
            permissions: value
                .permissions
                .map(|permissions| u64::from(permissions.bits())),
        }
    }
}

impl From<ServerSync> for Message {
    fn from(value: ServerSync) -> Self {
        Message::ServerSync(value.into())
    }
}
