use crate::messages::Message;

#[derive(Debug, Clone)]
pub struct SuggestConfig {
    pub version: Option<u32>,
    pub positional: Option<bool>,
    pub push_to_talk: Option<bool>,
}

impl From<crate::mumble_proto::SuggestConfig> for SuggestConfig {
    fn from(proto: crate::mumble_proto::SuggestConfig) -> Self {
        Self {
            version: proto.version_v1,
            positional: proto.positional,
            push_to_talk: proto.push_to_talk,
        }
    }
}

impl Default for SuggestConfig {
    fn default() -> Self {
        Self {
            version: None,
            positional: None,
            push_to_talk: None,
        }
    }
}

impl Into<crate::mumble_proto::SuggestConfig> for SuggestConfig {
    fn into(self) -> crate::mumble_proto::SuggestConfig {
        crate::mumble_proto::SuggestConfig {
            version_v1: self.version,
            version_v2: self.version.map(|v| v as u64),
            positional: self.positional,
            push_to_talk: self.push_to_talk,
        }
    }
}

impl Into<Message> for SuggestConfig {
    fn into(self) -> Message {
        Message::SuggestConfig(self.into())
    }
}
