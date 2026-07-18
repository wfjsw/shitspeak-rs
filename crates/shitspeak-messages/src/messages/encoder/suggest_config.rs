use crate::messages::Message;

#[derive(Debug, Clone, Default)]
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

impl From<SuggestConfig> for crate::mumble_proto::SuggestConfig {
    fn from(config: SuggestConfig) -> Self {
        crate::mumble_proto::SuggestConfig {
            version_v1: config.version,
            version_v2: config.version.map(u64::from),
            positional: config.positional,
            push_to_talk: config.push_to_talk,
        }
    }
}

impl From<SuggestConfig> for Message {
    fn from(config: SuggestConfig) -> Self {
        Message::SuggestConfig(config.into())
    }
}
