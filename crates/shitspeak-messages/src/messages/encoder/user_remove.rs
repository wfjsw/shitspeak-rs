use crate::messages::Message;

#[derive(Debug, Clone, Default)]
pub struct UserRemove {
    pub session: u32,
    pub actor: Option<u32>,
    pub reason: Option<String>,
    pub ban: Option<bool>,
}

impl From<crate::mumble_proto::UserRemove> for UserRemove {
    fn from(proto: crate::mumble_proto::UserRemove) -> Self {
        Self {
            session: proto.session,
            actor: proto.actor,
            reason: proto.reason,
            ban: proto.ban,
        }
    }
}

impl From<UserRemove> for crate::mumble_proto::UserRemove {
    fn from(user_remove: UserRemove) -> Self {
        crate::mumble_proto::UserRemove {
            session: user_remove.session,
            actor: user_remove.actor,
            reason: user_remove.reason,
            ban: user_remove.ban,
        }
    }
}

impl From<UserRemove> for Message {
    fn from(user_remove: UserRemove) -> Self {
        Message::UserRemove(user_remove.into())
    }
}
