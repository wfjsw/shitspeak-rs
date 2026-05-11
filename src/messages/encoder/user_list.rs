use crate::messages::Message;

#[derive(Debug, Clone)]
pub struct UserList {
    pub users: Vec<crate::mumble_proto::user_list::User>,
}

impl From<crate::mumble_proto::UserList> for UserList {
    fn from(proto: crate::mumble_proto::UserList) -> Self {
        Self { users: proto.users }
    }
}

impl Default for UserList {
    fn default() -> Self {
        Self { users: Vec::new() }
    }
}

impl Into<crate::mumble_proto::UserList> for UserList {
    fn into(self) -> crate::mumble_proto::UserList {
        crate::mumble_proto::UserList { users: self.users }
    }
}

impl Into<Message> for UserList {
    fn into(self) -> Message {
        Message::UserList(self.into())
    }
}
