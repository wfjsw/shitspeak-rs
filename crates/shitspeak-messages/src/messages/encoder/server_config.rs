use crate::messages::Message;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub max_bandwidth: Option<u32>,
    pub welcome_text: Option<String>,
    pub allow_html: Option<bool>,
    pub message_length: Option<u32>,
    pub image_message_length: Option<u32>,
    pub max_users: Option<u32>,
}

impl From<crate::mumble_proto::ServerConfig> for ServerConfig {
    fn from(proto: crate::mumble_proto::ServerConfig) -> Self {
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

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_bandwidth: None,
            welcome_text: None,
            allow_html: None,
            message_length: None,
            image_message_length: None,
            max_users: None,
        }
    }
}

impl Into<crate::mumble_proto::ServerConfig> for ServerConfig {
    fn into(self) -> crate::mumble_proto::ServerConfig {
        crate::mumble_proto::ServerConfig {
            max_bandwidth: self.max_bandwidth,
            welcome_text: self.welcome_text,
            allow_html: self.allow_html,
            message_length: self.message_length,
            image_message_length: self.image_message_length,
            max_users: self.max_users,
            recording_allowed: None,
        }
    }
}

impl Into<Message> for ServerConfig {
    fn into(self) -> Message {
        Message::ServerConfig(self.into())
    }
}
