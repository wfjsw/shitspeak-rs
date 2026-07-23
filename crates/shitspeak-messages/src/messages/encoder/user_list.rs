use crate::messages::Message;

#[derive(Debug, Clone, Default)]
pub struct UserList {
    pub users: Vec<shitspeak_proto::mumble_proto::user_list::User>,
}

impl From<shitspeak_proto::mumble_proto::UserList> for UserList {
    fn from(proto: shitspeak_proto::mumble_proto::UserList) -> Self {
        Self { users: proto.users }
    }
}

impl From<UserList> for shitspeak_proto::mumble_proto::UserList {
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
