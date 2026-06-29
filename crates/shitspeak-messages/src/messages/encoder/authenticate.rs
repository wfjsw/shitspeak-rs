use crate::messages::Message;

#[derive(Debug, Clone, Copy)]
pub enum ClientType {
    Regular = 0,
    Bot = 1,
}

impl Into<i32> for ClientType {
    fn into(self) -> i32 {
        match self {
            ClientType::Regular => 0,
            ClientType::Bot => 1,
        }
    }
}

impl From<i32> for ClientType {
    fn from(value: i32) -> Self {
        match value {
            1 => ClientType::Bot,
            _ => ClientType::Regular,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Authenticate {
    pub username: Option<String>,
    pub password: Option<String>,
    pub tokens: Vec<String>,
    pub celt_versions: Vec<i32>,
    pub opus: Option<bool>,
    pub client_type: ClientType,
}

impl From<crate::mumble_proto::Authenticate> for Authenticate {
    fn from(proto: crate::mumble_proto::Authenticate) -> Self {
        Self {
            username: proto.username,
            password: proto.password,
            tokens: proto.tokens,
            celt_versions: proto.celt_versions,
            opus: proto.opus,
            client_type: proto
                .client_type
                .map_or(ClientType::Regular, |ct| ClientType::from(ct)),
        }
    }
}

impl Authenticate {}

impl Default for Authenticate {
    fn default() -> Self {
        Self {
            username: None,
            password: None,
            tokens: Vec::new(),
            celt_versions: Vec::new(),
            opus: None,
            client_type: ClientType::Regular,
        }
    }
}

impl Into<crate::mumble_proto::Authenticate> for Authenticate {
    fn into(self) -> crate::mumble_proto::Authenticate {
        crate::mumble_proto::Authenticate {
            username: self.username,
            password: self.password,
            tokens: self.tokens,
            celt_versions: self.celt_versions,
            opus: self.opus,
            client_type: Some(self.client_type.into()),
        }
    }
}

impl Into<Message> for Authenticate {
    fn into(self) -> Message {
        Message::Authenticate(self.into())
    }
}
