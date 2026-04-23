use crate::messages::Message;

#[derive(Debug, Clone)]
pub struct QueryUsers {
    pub ids: Vec<u32>,
    pub names: Vec<String>,
}

impl From<crate::mumble_proto::QueryUsers> for QueryUsers {
    fn from(proto: crate::mumble_proto::QueryUsers) -> Self {
        Self {
            ids: proto.ids,
            names: proto.names,
        }
    }
}

impl Default for QueryUsers {
    fn default() -> Self {
        Self {
            ids: Vec::new(),
            names: Vec::new(),
        }
    }
}

impl Into<crate::mumble_proto::QueryUsers> for QueryUsers {
    fn into(self) -> crate::mumble_proto::QueryUsers {
        crate::mumble_proto::QueryUsers {
            ids: self.ids,
            names: self.names,
        }
    }
}

impl Into<Message> for QueryUsers {
    fn into(self) -> Message {
        Message::QueryUsers(self.into())
    }
}
