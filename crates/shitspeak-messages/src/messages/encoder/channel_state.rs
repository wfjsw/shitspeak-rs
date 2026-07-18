use crate::messages::Message;
use bytes::Bytes;

/// Encoder for `ChannelState` protobuf messages.
///
/// Mirrors the protobuf fields with native Rust types.
#[derive(Debug, Clone, Default)]
pub struct ChannelState {
    pub channel_id: Option<u32>,
    pub parent: Option<u32>,
    pub name: Option<String>,
    pub links: Vec<u32>,
    pub description: Option<String>,
    pub links_add: Vec<u32>,
    pub links_remove: Vec<u32>,
    pub temporary: Option<bool>,
    pub position: Option<i32>,
    pub description_hash: Option<Bytes>,
    pub max_users: Option<u32>,
    pub is_enter_restricted: Option<bool>,
    pub can_enter: Option<bool>,
}

impl ChannelState {
    /// Fill `is_enter_restricted` and `can_enter` from the effective ACL
    /// chain and the given effective permissions. Call this when
    /// `send_permission_info` is enabled.
    pub fn with_permission_info(
        mut self,
        is_enter_restricted: bool,
        perms: enumflags2::BitFlags<crate::acl::ACLPermissions>,
    ) -> Self {
        use crate::acl::ACLPermissions;
        self.is_enter_restricted = Some(is_enter_restricted);
        self.can_enter = Some(perms.contains(ACLPermissions::Enter));
        self
    }
}

impl From<crate::mumble_proto::ChannelState> for ChannelState {
    fn from(proto: crate::mumble_proto::ChannelState) -> Self {
        Self {
            channel_id: proto.channel_id,
            parent: proto.parent,
            name: proto.name,
            links: proto.links,
            description: proto.description,
            links_add: proto.links_add,
            links_remove: proto.links_remove,
            temporary: proto.temporary,
            position: proto.position,
            description_hash: proto.description_hash.map(Bytes::from),
            max_users: proto.max_users,
            is_enter_restricted: proto.is_enter_restricted,
            can_enter: proto.can_enter,
        }
    }
}

impl From<ChannelState> for crate::mumble_proto::ChannelState {
    fn from(value: ChannelState) -> Self {
        crate::mumble_proto::ChannelState {
            channel_id: value.channel_id,
            parent: value.parent,
            name: value.name,
            links: value.links,
            description: value.description,
            links_add: value.links_add,
            links_remove: value.links_remove,
            temporary: value.temporary,
            position: value.position,
            description_hash: value.description_hash.map(|bytes| bytes.as_ref().to_vec()),
            max_users: value.max_users,
            is_enter_restricted: value.is_enter_restricted,
            can_enter: value.can_enter,
        }
    }
}

impl From<ChannelState> for Message {
    fn from(value: ChannelState) -> Self {
        Self::ChannelState(value.into())
    }
}
