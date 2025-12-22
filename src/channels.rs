use std::collections::HashMap;

pub struct Channel {
    id: u32,
    name: String,
    position: i32,
    max_users: u32,
    parent_id: Option<u32>,
    inherit_acl: bool,
    link: Option<u32>,
    description_blob: Option<String>,
}

pub struct Channels {
    channel_list: HashMap<u32, Channel>
}

impl Channel {
    pub fn new(
        id: u32,
        name: String,
        position: i32,
        max_users: u32,
        parent_id: Option<u32>,
        inherit_acl: bool,
        link: Option<u32>,
        description_blob: Option<String>,
    ) -> Self {
        Channel {
            id,
            name,
            position,
            max_users,
            parent_id,
            inherit_acl,
            link,
            description_blob,
        }
    }

    pub fn has_description(&self) -> bool {
        match &self.description_blob {
            Some(desc) => !desc.is_empty(),
            None => false,
        }
    }

    pub fn is_temporary(&self) -> bool {
        (self.id & 0x8000_0000u32) != 0
    }

    pub fn is_root(&self) -> bool {
        self.parent_id.is_none()
    }

}

impl Channels {
    pub fn get_channel(&self, channel_id: u32) -> Option<&Channel> {
        self.channel_list.get(&channel_id)
    }

    pub fn get_parent(&self, channel: &Channel) -> Option<&Channel> {
        match channel.parent_id {
            Some(parent_id) => self.channel_list.get(&parent_id),
            None => None,
        }
    }

    pub fn get_children(&self, channel: &Channel) -> Vec<&Channel> {
        self.channel_list.values()
            .filter(|c| c.parent_id == Some(channel.id))
            .collect()
    }
}
