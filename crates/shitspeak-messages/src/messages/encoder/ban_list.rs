use crate::messages::Message;

#[derive(Debug, Clone, Default)]
pub struct BanList {
    pub bans: Vec<shitspeak_proto::mumble_proto::ban_list::BanEntry>,
    pub query: Option<bool>,
}

impl From<shitspeak_proto::mumble_proto::BanList> for BanList {
    fn from(proto: shitspeak_proto::mumble_proto::BanList) -> Self {
        Self {
            bans: proto.bans,
            query: proto.query,
        }
    }
}

impl From<BanList> for shitspeak_proto::mumble_proto::BanList {
    fn from(value: BanList) -> Self {
        shitspeak_proto::mumble_proto::BanList {
            bans: value.bans,
            query: value.query,
        }
    }
}

impl From<BanList> for Message {
    fn from(value: BanList) -> Self {
        Self::BanList(value.into())
    }
}
