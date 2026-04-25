use crate::messages::Message;

/// A single ACL entry — native Rust type mirroring the protobuf `ChanAcl`.
#[derive(Debug, Clone)]
pub struct ChanAcl {
    pub apply_here: bool,
    pub apply_subs: bool,
    pub inherited: bool,
    pub user_id: Option<u32>,
    pub group: Option<String>,
    pub grant: u32,
    pub deny: u32,
}

impl From<crate::mumble_proto::acl::ChanAcl> for ChanAcl {
    fn from(proto: crate::mumble_proto::acl::ChanAcl) -> Self {
        Self {
            apply_here: proto.apply_here.unwrap_or(true),
            apply_subs: proto.apply_subs.unwrap_or(false),
            inherited: proto.inherited.unwrap_or(false),
            user_id: proto.user_id,
            group: proto.group,
            grant: proto.grant.unwrap_or(0),
            deny: proto.deny.unwrap_or(0),
        }
    }
}

impl Into<crate::mumble_proto::acl::ChanAcl> for ChanAcl {
    fn into(self) -> crate::mumble_proto::acl::ChanAcl {
        crate::mumble_proto::acl::ChanAcl {
            apply_here: Some(self.apply_here),
            apply_subs: Some(self.apply_subs),
            inherited: Some(self.inherited),
            user_id: self.user_id,
            group: self.group,
            grant: Some(self.grant),
            deny: Some(self.deny),
        }
    }
}

/// Encoder for `ACL` protobuf messages.
#[derive(Debug, Clone)]
pub struct Acl {
    pub channel_id: u32,
    pub inherit_acls: Option<bool>,
    pub groups: Vec<crate::mumble_proto::acl::ChanGroup>,
    pub acls: Vec<ChanAcl>,
    pub query: Option<bool>,
}

impl From<crate::mumble_proto::Acl> for Acl {
    fn from(proto: crate::mumble_proto::Acl) -> Self {
        Self {
            channel_id: proto.channel_id,
            inherit_acls: proto.inherit_acls,
            groups: proto.groups,
            acls: proto.acls.into_iter().map(|a| a.into()).collect(),
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
            acls: self.acls.into_iter().map(|a| a.into()).collect(),
            query: self.query,
        }
    }
}

impl Into<Message> for Acl {
    fn into(self) -> Message {
        Message::ACL(self.into())
    }
}
