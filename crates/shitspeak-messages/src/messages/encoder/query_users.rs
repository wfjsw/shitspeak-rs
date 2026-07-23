use crate::messages::Message;

#[derive(Debug, Clone, Default)]
pub struct QueryUsers {
    pub ids: Vec<u32>,
    pub names: Vec<String>,
}

impl From<shitspeak_proto::mumble_proto::QueryUsers> for QueryUsers {
    fn from(proto: shitspeak_proto::mumble_proto::QueryUsers) -> Self {
        Self {
            ids: proto.ids,
            names: proto.names,
        }
    }
}

impl From<QueryUsers> for shitspeak_proto::mumble_proto::QueryUsers {
    fn from(value: QueryUsers) -> Self {
        shitspeak_proto::mumble_proto::QueryUsers {
            ids: value.ids,
            names: value.names,
        }
    }
}

impl From<QueryUsers> for Message {
    fn from(value: QueryUsers) -> Self {
        Message::QueryUsers(value.into())
    }
}
