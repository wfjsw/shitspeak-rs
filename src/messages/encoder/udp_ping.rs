//! Domain-typed wrapper around `mumble_udp::Ping`. Mirrors the encoder
//! pattern used for other Mumble messages so the rest of the crate never
//! constructs or parses the protobuf type directly.

use prost::Message as _;

#[derive(Debug, Clone, Default)]
pub struct UdpPing {
    pub timestamp: u64,
    pub request_extended_information: bool,
    pub server_version_v2: u64,
    pub user_count: u32,
    pub max_user_count: u32,
    pub max_bandwidth_per_user: u32,
}

impl From<crate::mumble_udp::Ping> for UdpPing {
    fn from(proto: crate::mumble_udp::Ping) -> Self {
        Self {
            timestamp: proto.timestamp,
            request_extended_information: proto.request_extended_information,
            server_version_v2: proto.server_version_v2,
            user_count: proto.user_count,
            max_user_count: proto.max_user_count,
            max_bandwidth_per_user: proto.max_bandwidth_per_user,
        }
    }
}

impl From<UdpPing> for crate::mumble_udp::Ping {
    fn from(p: UdpPing) -> Self {
        crate::mumble_udp::Ping {
            timestamp: p.timestamp,
            request_extended_information: p.request_extended_information,
            server_version_v2: p.server_version_v2,
            user_count: p.user_count,
            max_user_count: p.max_user_count,
            max_bandwidth_per_user: p.max_bandwidth_per_user,
        }
    }
}

impl UdpPing {
    /// Decode a wire `MumbleUDP.Ping` payload (bytes after the 1-byte type prefix).
    pub fn decode_wire(data: &[u8]) -> Result<Self, prost::DecodeError> {
        crate::mumble_udp::Ping::decode(data).map(UdpPing::from)
    }

    /// Length of the encoded protobuf payload (without the 1-byte type prefix).
    pub fn encoded_len(&self) -> usize {
        let proto: crate::mumble_udp::Ping = self.clone().into();
        proto.encoded_len()
    }

    /// Encode the protobuf payload (without the 1-byte type prefix) into `buf`.
    pub fn encode(self, buf: &mut bytes::BytesMut) -> Result<(), prost::EncodeError> {
        let proto: crate::mumble_udp::Ping = self.into();
        proto.encode(buf)
    }
}
