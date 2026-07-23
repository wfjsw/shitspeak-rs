use crate::messages::Message;
use bytes::Bytes;

#[derive(Debug, Clone, Default)]
pub struct CryptSetup {
    key: Option<Bytes>,
    client_nonce: Option<Bytes>,
    server_nonce: Option<Bytes>,
}

impl From<shitspeak_proto::mumble_proto::CryptSetup> for CryptSetup {
    fn from(proto: shitspeak_proto::mumble_proto::CryptSetup) -> Self {
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

impl From<CryptSetup> for shitspeak_proto::mumble_proto::CryptSetup {
    fn from(crypt_setup: CryptSetup) -> Self {
        shitspeak_proto::mumble_proto::CryptSetup {
            key: crypt_setup.key.map(Vec::from),
            client_nonce: crypt_setup.client_nonce.map(Vec::from),
            server_nonce: crypt_setup.server_nonce.map(Vec::from),
        }
    }
}

impl From<CryptSetup> for Message {
    fn from(crypt_setup: CryptSetup) -> Self {
        Self::CryptSetup(crypt_setup.into())
    }
}
