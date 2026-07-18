use crate::messages::Message;

#[derive(Debug, Clone, Default)]
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

impl From<RequestBlob> for crate::mumble_proto::RequestBlob {
    fn from(value: RequestBlob) -> Self {
        crate::mumble_proto::RequestBlob {
            session_texture: value.session_texture,
            session_comment: value.session_comment,
            channel_description: value.channel_description,
        }
    }
}

impl From<RequestBlob> for Message {
    fn from(value: RequestBlob) -> Self {
        Message::RequestBlob(value.into())
    }
}
