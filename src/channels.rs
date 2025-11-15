use std::collections::HashMap;

pub struct Channel {
    id: u32,
    name: String,
    position: i32,
    max_users: u32,
    parent_id: Option<u32>,
    inherit_acl: bool,
    link: Option<u32>,
    description_blob: String,
}

pub struct Channels {
    channel_list: HashMap<u32, Channel>
}

impl Channel {
}

impl Channels {
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
