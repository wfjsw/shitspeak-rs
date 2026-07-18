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

impl From<CodecVersion> for crate::mumble_proto::CodecVersion {
    fn from(codec_version: CodecVersion) -> Self {
        crate::mumble_proto::CodecVersion {
            alpha: codec_version.alpha,
            beta: codec_version.beta,
            prefer_alpha: codec_version.prefer_alpha,
            opus: codec_version.opus,
        }
    }
}

impl From<CodecVersion> for Message {
    fn from(codec_version: CodecVersion) -> Self {
        Self::CodecVersion(codec_version.into())
    }
}
