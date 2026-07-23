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

impl From<shitspeak_proto::mumble_proto::acl::ChanAcl> for ChanAcl {
    fn from(proto: shitspeak_proto::mumble_proto::acl::ChanAcl) -> Self {
        Self {
            apply_here: proto.apply_here.unwrap_or(true),
            apply_subs: proto.apply_subs.unwrap_or(true),
            inherited: proto.inherited.unwrap_or(true),
            user_id: proto.user_id,
            group: proto.group,
            grant: proto.grant.unwrap_or(0),
            deny: proto.deny.unwrap_or(0),
        }
    }
}

impl From<ChanAcl> for shitspeak_proto::mumble_proto::acl::ChanAcl {
    fn from(acl: ChanAcl) -> Self {
        shitspeak_proto::mumble_proto::acl::ChanAcl {
            apply_here: Some(acl.apply_here),
            apply_subs: Some(acl.apply_subs),
            inherited: Some(acl.inherited),
            user_id: acl.user_id,
            group: acl.group,
            grant: Some(acl.grant),
            deny: Some(acl.deny),
        }
    }
}

/// Encoder for `ACL` protobuf messages.
#[derive(Debug, Clone)]
pub struct Acl {
    pub channel_id: u32,
    pub inherit_acls: Option<bool>,
    pub groups: Vec<shitspeak_proto::mumble_proto::acl::ChanGroup>,
    pub acls: Vec<ChanAcl>,
    pub query: Option<bool>,
}

impl From<shitspeak_proto::mumble_proto::Acl> for Acl {
    fn from(proto: shitspeak_proto::mumble_proto::Acl) -> Self {
        Self {
            channel_id: proto.channel_id,
            inherit_acls: Some(proto.inherit_acls.unwrap_or(true)),
            groups: proto.groups,
            acls: proto.acls.into_iter().map(ChanAcl::from).collect(),
            query: proto.query,
        }
    }
}

impl Default for Acl {
    fn default() -> Self {
        Self {
            channel_id: 0,
            inherit_acls: Some(true),
            groups: Vec::new(),
            acls: Vec::new(),
            query: None,
        }
    }
}

impl From<Acl> for shitspeak_proto::mumble_proto::Acl {
    fn from(acl: Acl) -> Self {
        shitspeak_proto::mumble_proto::Acl {
            channel_id: acl.channel_id,
            inherit_acls: acl.inherit_acls,
            groups: acl.groups,
            acls: acl
                .acls
                .into_iter()
                .map(shitspeak_proto::mumble_proto::acl::ChanAcl::from)
                .collect(),
            query: acl.query,
        }
    }
}

impl From<Acl> for Message {
    fn from(acl: Acl) -> Self {
        Message::ACL(acl.into())
    }
}
