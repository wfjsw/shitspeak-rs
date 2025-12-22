use std::convert::TryFrom;

use crate::{constants::{MAX_LOCAL_SESSION_ID, MAX_NODE_ID}, types::NodeIdentifier};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientSessionIdentifier {
    /// 12-bit field (0 ..= 0xFFF)
    pub node_id: NodeIdentifier,
    /// 20-bit field (0 ..= 0xFFFFF)
    pub local_session_id: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientSessionIdentifierError {
    #[error("node_id out of range (must be <= 0xFFF)")]
    NodeIdOutOfRange,
    #[error("local_session_id out of range (must be <= 0xFFFFF)")]
    LocalSessionIdOutOfRange,
}

impl ClientSessionIdentifier {

    /// Create a new identifier, returning an error if either part doesn't fit its bit-size.
    pub fn new(node_id: u16, local_session_id: u32) -> Result<Self, ClientSessionIdentifierError> {
        if node_id > MAX_NODE_ID {
            return Err(ClientSessionIdentifierError::NodeIdOutOfRange);
        }
        if local_session_id > MAX_LOCAL_SESSION_ID {
            return Err(ClientSessionIdentifierError::LocalSessionIdOutOfRange);
        }
        Ok(Self { node_id, local_session_id })
    }

    /// Pack the two parts into a single u32.
    /// Layout: [ node_id (bits 31..20) | local_session_id (bits 19..0) ]
    pub fn to_u32(self) -> u32 {
        ((self.node_id as u32) << 20) | (self.local_session_id & MAX_LOCAL_SESSION_ID)
    }
}

impl From<ClientSessionIdentifier> for u32 {
    fn from(id: ClientSessionIdentifier) -> Self {
        id.to_u32()
    }
}

impl TryFrom<u32> for ClientSessionIdentifier {
    type Error = ClientSessionIdentifierError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let local_session_id = value & MAX_LOCAL_SESSION_ID;
        let node_id = ((value >> 20) & (MAX_NODE_ID as u32)) as u16;
        Ok(ClientSessionIdentifier { node_id, local_session_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        let id = ClientSessionIdentifier::new(0xABC, 0x54321).unwrap();
        let packed = id.to_u32();
        let unpacked = ClientSessionIdentifier::try_from(packed).unwrap();
        assert_eq!(id, unpacked);
    }

    #[test]
    fn rejects_out_of_range() {
        assert!(ClientSessionIdentifier::new(0x1000, 0).is_err());
        assert!(ClientSessionIdentifier::new(0, 0x1_00000).is_err());
    }
}
