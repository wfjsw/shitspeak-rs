use crate::messages::{Message};

#[derive(Debug, Clone)]
pub struct CryptSetup {
    key: Option<Vec<u8>>,
    client_nonce: Option<Vec<u8>>,
    server_nonce: Option<Vec<u8>>,
}

impl From<crate::mumble_proto::CryptSetup> for CryptSetup {
    fn from(proto: crate::mumble_proto::CryptSetup) -> Self {
        Self {
            key: proto.key,
            client_nonce: proto.client_nonce,
            server_nonce: proto.server_nonce,
        }
    }
}

impl CryptSetup {
    pub fn new(
        key: Option<Vec<u8>>,
        client_nonce: Option<Vec<u8>>,
        server_nonce: Option<Vec<u8>>,
    ) -> Self {
        Self {
            key,
            client_nonce,
            server_nonce,
        }
    }

    pub fn is_client_request_resync(&self) -> bool {
        self.client_nonce.is_none()
    }

    pub fn client_nonce(&self) -> Option<&[u8]> {
        self.client_nonce.as_deref()
    }
}

impl Default for CryptSetup {
    fn default() -> Self {
        Self {
            key: None,
            client_nonce: None,
            server_nonce: None,
        }
    }
}

impl Into<crate::mumble_proto::CryptSetup> for CryptSetup {
    fn into(self) -> crate::mumble_proto::CryptSetup {
        crate::mumble_proto::CryptSetup {
            key: self.key,
            client_nonce: self.client_nonce,
            server_nonce: self.server_nonce,
        }
    }
}

impl Into<Message> for CryptSetup {
    fn into(self) -> Message {
        Message::CryptSetup(self.into())
    }
}
