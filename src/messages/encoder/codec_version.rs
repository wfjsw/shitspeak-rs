use crate::messages::Message;

#[derive(Debug, Clone)]
pub struct CodecVersion {
    pub alpha: i32,
    pub beta: i32,
    pub prefer_alpha: bool,
    pub opus: Option<bool>,
}

impl From<crate::mumble_proto::CodecVersion> for CodecVersion {
    fn from(proto: crate::mumble_proto::CodecVersion) -> Self {
        Self {
            alpha: proto.alpha,
            beta: proto.beta,
            prefer_alpha: proto.prefer_alpha,
            opus: proto.opus,
        }
    }
}

impl Default for CodecVersion {
    fn default() -> Self {
        Self {
            alpha: 0,
            beta: 0,
            prefer_alpha: true,
            opus: None,
        }
    }
}

impl Into<crate::mumble_proto::CodecVersion> for CodecVersion {
    fn into(self) -> crate::mumble_proto::CodecVersion {
        crate::mumble_proto::CodecVersion {
            alpha: self.alpha,
            beta: self.beta,
            prefer_alpha: self.prefer_alpha,
            opus: self.opus,
        }
    }
}

impl Into<Message> for CodecVersion {
    fn into(self) -> Message {
        Message::CodecVersion(self.into())
    }
}
