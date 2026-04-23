use crate::messages::Message;

#[derive(Debug, Clone)]
pub struct RequestBlob {
    pub session_texture: Vec<u32>,
    pub session_comment: Vec<u32>,
    pub channel_description: Vec<u32>,
}

impl From<crate::mumble_proto::RequestBlob> for RequestBlob {
    fn from(proto: crate::mumble_proto::RequestBlob) -> Self {
        Self {
            session_texture: proto.session_texture,
            session_comment: proto.session_comment,
            channel_description: proto.channel_description,
        }
    }
}

impl Default for RequestBlob {
    fn default() -> Self {
        Self {
            session_texture: Vec::new(),
            session_comment: Vec::new(),
            channel_description: Vec::new(),
        }
    }
}

impl Into<crate::mumble_proto::RequestBlob> for RequestBlob {
    fn into(self) -> crate::mumble_proto::RequestBlob {
        crate::mumble_proto::RequestBlob {
            session_texture: self.session_texture,
            session_comment: self.session_comment,
            channel_description: self.channel_description,
        }
    }
}

impl Into<Message> for RequestBlob {
    fn into(self) -> Message {
        Message::RequestBlob(self.into())
    }
}
