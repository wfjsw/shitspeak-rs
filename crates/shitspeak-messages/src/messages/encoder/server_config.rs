use crate::messages::Message;

#[derive(Debug, Clone, Default)]
pub struct ServerConfig {
    pub max_bandwidth: Option<u32>,
    pub welcome_text: Option<String>,
    pub allow_html: Option<bool>,
    pub message_length: Option<u32>,
    pub image_message_length: Option<u32>,
    pub max_users: Option<u32>,
}

impl From<shitspeak_proto::mumble_proto::ServerConfig> for ServerConfig {
    fn from(proto: shitspeak_proto::mumble_proto::ServerConfig) -> Self {
        Self {
            max_bandwidth: proto.max_bandwidth,
            welcome_text: proto.welcome_text,
            allow_html: proto.allow_html,
            message_length: proto.message_length,
            image_message_length: proto.image_message_length,
            max_users: proto.max_users,
        }
    }
}

impl From<ServerConfig> for shitspeak_proto::mumble_proto::ServerConfig {
    fn from(value: ServerConfig) -> Self {
        shitspeak_proto::mumble_proto::ServerConfig {
            max_bandwidth: value.max_bandwidth,
            welcome_text: value.welcome_text,
            allow_html: value.allow_html,
            message_length: value.message_length,
            image_message_length: value.image_message_length,
            max_users: value.max_users,
            recording_allowed: None,
        }
    }
}

impl From<ServerConfig> for Message {
    fn from(value: ServerConfig) -> Self {
        Message::ServerConfig(value.into())
    }
}
