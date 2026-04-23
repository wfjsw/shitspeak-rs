use crate::messages::Message;

/// Encoder for `ChannelState` protobuf messages.
///
/// Mirrors the protobuf fields with native Rust types.
#[derive(Debug, Clone)]
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
    pub description_hash: Option<Vec<u8>>,
    pub max_users: Option<u32>,
    pub is_enter_restricted: Option<bool>,
    pub can_enter: Option<bool>,
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
            description_hash: proto.description_hash,
            max_users: proto.max_users,
            is_enter_restricted: proto.is_enter_restricted,
            can_enter: proto.can_enter,
        }
    }
}

impl Default for ChannelState {
    fn default() -> Self {
        Self {
            channel_id: None,
            parent: None,
            name: None,
            links: Vec::new(),
            description: None,
            links_add: Vec::new(),
            links_remove: Vec::new(),
            temporary: None,
            position: None,
            description_hash: None,
            max_users: None,
            is_enter_restricted: None,
            can_enter: None,
        }
    }
}

impl Into<crate::mumble_proto::ChannelState> for ChannelState {
    fn into(self) -> crate::mumble_proto::ChannelState {
        crate::mumble_proto::ChannelState {
            channel_id: self.channel_id,
            parent: self.parent,
            name: self.name,
            links: self.links,
            description: self.description,
            links_add: self.links_add,
            links_remove: self.links_remove,
            temporary: self.temporary,
            position: self.position,
            description_hash: self.description_hash,
            max_users: self.max_users,
            is_enter_restricted: self.is_enter_restricted,
            can_enter: self.can_enter,
        }
    }
}

impl Into<Message> for ChannelState {
    fn into(self) -> Message {
        Message::ChannelState(self.into())
    }
}
