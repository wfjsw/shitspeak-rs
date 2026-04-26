use crate::messages::{Message};
use bytes::Bytes;

#[derive(Debug, Clone)]
pub struct CryptSetup {
    key: Option<Bytes>,
    client_nonce: Option<Bytes>,
    server_nonce: Option<Bytes>,
}

impl From<crate::mumble_proto::CryptSetup> for CryptSetup {
    fn from(proto: crate::mumble_proto::CryptSetup) -> Self {
        Self {
            key: proto.key.map(Bytes::from),
            client_nonce: proto.client_nonce.map(Bytes::from),
            server_nonce: proto.server_nonce.map(Bytes::from),
        }
    }
}

impl CryptSetup {
    pub fn new(
        key: Option<Bytes>,
        client_nonce: Option<Bytes>,
        server_nonce: Option<Bytes>,
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
            key: self.key.map(|b| b.to_vec()),
            client_nonce: self.client_nonce.map(|b| b.to_vec()),
            server_nonce: self.server_nonce.map(|b| b.to_vec()),
        }
    }
}

impl Into<Message> for CryptSetup {
    fn into(self) -> Message {
        Message::CryptSetup(self.into())
    }
}
