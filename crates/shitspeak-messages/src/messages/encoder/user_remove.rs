use crate::messages::Message;

#[derive(Debug, Clone)]
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

impl Default for UserRemove {
    fn default() -> Self {
        Self {
            session: 0,
            actor: None,
            reason: None,
            ban: None,
        }
    }
}

impl Into<crate::mumble_proto::UserRemove> for UserRemove {
    fn into(self) -> crate::mumble_proto::UserRemove {
        crate::mumble_proto::UserRemove {
            session: self.session,
            actor: self.actor,
            reason: self.reason,
            ban: self.ban,
        }
    }
}

impl Into<Message> for UserRemove {
    fn into(self) -> Message {
        Message::UserRemove(self.into())
    }
}
