use crate::messages::Message;

#[derive(Debug, Clone)]
pub struct BanList {
    pub bans: Vec<crate::mumble_proto::ban_list::BanEntry>,
    pub query: Option<bool>,
}

impl From<crate::mumble_proto::BanList> for BanList {
    fn from(proto: crate::mumble_proto::BanList) -> Self {
        Self {
            bans: proto.bans,
            query: proto.query,
        }
    }
}

impl Default for BanList {
    fn default() -> Self {
        Self {
            bans: Vec::new(),
            query: None,
        }
    }
}

impl Into<crate::mumble_proto::BanList> for BanList {
    fn into(self) -> crate::mumble_proto::BanList {
        crate::mumble_proto::BanList {
            bans: self.bans,
            query: self.query,
        }
    }
}

impl Into<Message> for BanList {
    fn into(self) -> Message {
        Message::BanList(self.into())
    }
}
