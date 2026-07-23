use crate::messages::Message;

#[derive(Debug, Clone, Copy)]
pub enum ClientType {
    Regular = 0,
    Bot = 1,
}

impl From<ClientType> for i32 {
    fn from(client_type: ClientType) -> Self {
        match client_type {
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

impl From<shitspeak_proto::mumble_proto::Authenticate> for Authenticate {
    fn from(proto: shitspeak_proto::mumble_proto::Authenticate) -> Self {
        Self {
            username: proto.username,
            password: proto.password,
            tokens: proto.tokens,
            celt_versions: proto.celt_versions,
            opus: proto.opus,
            client_type: proto
                .client_type
                .map_or(ClientType::Regular, ClientType::from),
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

impl From<Authenticate> for shitspeak_proto::mumble_proto::Authenticate {
    fn from(authenticate: Authenticate) -> Self {
        shitspeak_proto::mumble_proto::Authenticate {
            username: authenticate.username,
            password: authenticate.password,
            tokens: authenticate.tokens,
            celt_versions: authenticate.celt_versions,
            opus: authenticate.opus,
            client_type: Some(authenticate.client_type.into()),
        }
    }
}

impl From<Authenticate> for Message {
    fn from(authenticate: Authenticate) -> Self {
        Message::Authenticate(authenticate.into())
    }
}
