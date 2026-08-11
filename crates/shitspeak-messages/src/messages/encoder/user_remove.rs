use crate::messages::Message;

#[derive(Debug, Clone, Default)]
pub struct UserRemove {
    pub session: u32,
    pub actor: Option<u32>,
    pub reason: Option<String>,
    pub ban: Option<bool>,
    pub ban_certificate: Option<bool>,
    pub ban_ip: Option<bool>,
}

impl From<shitspeak_proto::mumble_proto::UserRemove> for UserRemove {
    fn from(proto: shitspeak_proto::mumble_proto::UserRemove) -> Self {
        Self {
            session: proto.session,
            actor: proto.actor,
            reason: proto.reason,
            ban: proto.ban,
            ban_certificate: proto.ban_certificate,
            ban_ip: proto.ban_ip,
        }
    }
}

impl From<UserRemove> for shitspeak_proto::mumble_proto::UserRemove {
    fn from(user_remove: UserRemove) -> Self {
        shitspeak_proto::mumble_proto::UserRemove {
            session: user_remove.session,
            actor: user_remove.actor,
            reason: user_remove.reason,
            ban: user_remove.ban,
            ban_certificate: user_remove.ban_certificate,
            ban_ip: user_remove.ban_ip,
        }
    }
}

impl From<UserRemove> for Message {
    fn from(user_remove: UserRemove) -> Self {
        Message::UserRemove(user_remove.into())
    }
}
