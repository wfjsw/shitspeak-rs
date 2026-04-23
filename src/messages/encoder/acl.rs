use crate::messages::Message;

/// Encoder for `ACL` protobuf messages.
///
/// Wraps the protobuf `Acl` type with native Rust types for ACL entries.
#[derive(Debug, Clone)]
pub struct Acl {
    pub channel_id: u32,
    pub inherit_acls: Option<bool>,
    pub groups: Vec<crate::mumble_proto::acl::ChanGroup>,
    pub acls: Vec<crate::mumble_proto::acl::ChanAcl>,
    pub query: Option<bool>,
}

impl From<crate::mumble_proto::Acl> for Acl {
    fn from(proto: crate::mumble_proto::Acl) -> Self {
        Self {
            channel_id: proto.channel_id,
            inherit_acls: proto.inherit_acls,
            groups: proto.groups,
            acls: proto.acls,
            query: proto.query,
        }
    }
}

impl Default for Acl {
    fn default() -> Self {
        Self {
            channel_id: 0,
            inherit_acls: None,
            groups: Vec::new(),
            acls: Vec::new(),
            query: None,
        }
    }
}

impl Into<crate::mumble_proto::Acl> for Acl {
    fn into(self) -> crate::mumble_proto::Acl {
        crate::mumble_proto::Acl {
            channel_id: self.channel_id,
            inherit_acls: self.inherit_acls,
            groups: self.groups,
            acls: self.acls,
            query: self.query,
        }
    }
}

impl Into<Message> for Acl {
    fn into(self) -> Message {
        Message::ACL(self.into())
    }
}
