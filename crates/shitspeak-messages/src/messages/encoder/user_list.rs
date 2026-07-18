use crate::messages::Message;

#[derive(Debug, Clone, Default)]
pub struct UserList {
    pub users: Vec<crate::mumble_proto::user_list::User>,
}

impl From<crate::mumble_proto::UserList> for UserList {
    fn from(proto: crate::mumble_proto::UserList) -> Self {
        Self { users: proto.users }
    }
}

impl From<UserList> for crate::mumble_proto::UserList {
    fn from(user_list: UserList) -> Self {
        Self {
            users: user_list.users,
        }
    }
}

impl From<UserList> for Message {
    fn from(user_list: UserList) -> Self {
        Message::UserList(user_list.into())
    }
}
