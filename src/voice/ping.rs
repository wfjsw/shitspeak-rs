//! UDP ping packet encoding/decoding — supports both legacy (pre-1.5.0)
//! and protobuf (1.5.0+) formats.

use bytes::{BufMut, Bytes, BytesMut};
use prost::EncodeError;

use crate::messages::encoder::UdpPing;

use super::codec::{DecodeError, PacketFormat};

/// A decoded UDP ping request.
#[derive(Debug, Clone)]
pub struct PingRequest {
    /// Client timestamp — echoed back verbatim.
    pub timestamp: u64,
    /// Whether the client requested extended server information.
    pub request_extended_information: bool,
    /// The format used for this packet (determines response format).
    pub format: PacketFormat,
}

/// Server information included in ping responses.
pub struct PingResponse {
    pub timestamp: u64,
    pub server_version: crate::protocol_version::ProtocolVersion,
    pub user_count: u32,
    pub max_user_count: Option<u32>,
    pub max_bandwidth_per_user: u32,
}

impl PingRequest {
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let header = data.get(0).ok_or(DecodeError::TooShort)?;
        if *header == 0x1u8 {
            return Self::decode_protobuf(&data[1..]).map_err(|_| DecodeError::NotPing);
        }

        if data.len() == 12 {
            return Self::decode_legacy(&data).map_err(|_| DecodeError::NotPing);
        }

        Err(DecodeError::NotPing)
    }

    /// Decode a protobuf Ping packet (data is after the 2-byte header).
    pub(super) fn decode_protobuf(data: &[u8]) -> Result<Self, DecodeError> {
        let ping = UdpPing::decode_wire(data).map_err(DecodeError::ProtobufDecode)?;
        Ok(PingRequest {
            timestamp: ping.timestamp,
            request_extended_information: ping.request_extended_information,
            format: PacketFormat::Protobuf,
        })
    }

    /// Decode a legacy Ping packet.
    ///
    /// When called from the encrypted path (`decode_udp_packet`), `data` is the
    /// bytes after the type byte: a PDS varint-encoded timestamp (1–4 bytes for
    /// timestamps up to ~74 hours).
    ///
    /// When called from the unencrypted path (`PingRequest::decode`), `data` is
    /// the full 12-byte packet including the `\x00\x00\x00\x00` header followed
    /// by a raw big-endian u64 timestamp.
    pub(super) fn decode_legacy(data: &[u8]) -> Result<Self, DecodeError> {
        if data.is_empty() {
            return Err(DecodeError::TooShort);
        }

        let (request_extended_information, timestamp) = if data.len() < size_of::<u64>() {
            // Short form: PDS varint-encoded timestamp (encrypted pings from authenticated clients).
            let (ts, consumed) =
                super::codec::read_varint_slice(data).ok_or(DecodeError::UnparsableVarIntValue)?;
            if consumed != data.len() {
                return Err(DecodeError::UnparsableVarIntValue);
            }
            (false, ts as u64)
        } else if data.len() <= size_of::<u64>() + 1 {
            let bytes: [u8; 8] = data[..size_of::<u64>()]
                .try_into()
                .map_err(|_| DecodeError::UnparsableVarIntValue)?;
            (false, u64::from_be_bytes(bytes))
        } else if data.len() == 4 + size_of::<u64>() {
            let prefix: [u8; 4] = data[..4]
                .try_into()
                .map_err(|_| DecodeError::UnparsableVarIntValue)?;
            if u32::from_be_bytes(prefix) != 0 {
                return Err(DecodeError::TooShort);
            }
            let ts_bytes: [u8; 8] = data[4..4 + size_of::<u64>()]
                .try_into()
                .map_err(|_| DecodeError::UnparsableVarIntValue)?;
            (true, u64::from_be_bytes(ts_bytes))
        } else {
            return Err(DecodeError::NotPing);
        };

        Ok(PingRequest {
            timestamp,
            request_extended_information,
            format: PacketFormat::Legacy,
        })
    }

    /// Encode the authenticated UDP ping echo used on the encrypted voice socket.
    pub fn encode_authenticated_echo(&self) -> Result<Bytes, EncodeError> {
        Ok(match self.format {
            PacketFormat::Protobuf => {
                let ping = UdpPing {
                    timestamp: self.timestamp,
                    ..UdpPing::default()
                };
                let mut buf = BytesMut::with_capacity(1 + ping.encoded_len());
                buf.put_u8(0x01);
                ping.encode(&mut buf)?;
                buf.freeze()
            }
            PacketFormat::Legacy => {
                let mut buf = BytesMut::with_capacity(1 + legacy_varint_len(self.timestamp));
                buf.put_u8(0x20);
                write_legacy_varint(&mut buf, self.timestamp);
                buf.freeze()
            }
        })
    }
}

fn legacy_varint_len(value: u64) -> usize {
    if value <= 0x7F {
        1
    } else if value <= 0x3FFF {
        2
    } else if value <= 0x1F_FFFF {
        3
    } else {
        4
    }
}

fn write_legacy_varint(buf: &mut impl BufMut, value: u64) {
    if value <= 0x7F {
        buf.put_u8(value as u8);
    } else if value <= 0x3FFF {
        buf.put_u8(0x80 | (value >> 8) as u8);
        buf.put_u8((value & 0xFF) as u8);
    } else if value <= 0x1F_FFFF {
        buf.put_u8(0xC0 | (value >> 16) as u8);
        buf.put_u8(((value >> 8) & 0xFF) as u8);
        buf.put_u8((value & 0xFF) as u8);
    } else {
        let value = value.min(0x0FFF_FFFF);
        buf.put_u8(0xE0 | (value >> 24) as u8);
        buf.put_u8(((value >> 16) & 0xFF) as u8);
        buf.put_u8(((value >> 8) & 0xFF) as u8);
        buf.put_u8((value & 0xFF) as u8);
    }
}

impl PingResponse {
    /// Encode a ping response in the same format as the request.
    pub fn encode(&self, format: PacketFormat) -> Result<Bytes, EncodeError> {
        tracing::debug!(
            "Encoding ping response: format={}, timestamp={}, version={}, users={}/{}, max_bandwidth={}",
            format,
            self.timestamp,
            self.server_version.to_string(),
            self.user_count,
            self.max_user_count.unwrap_or(u32::MAX),
            self.max_bandwidth_per_user,
        );

        Ok(match format {
            PacketFormat::Protobuf => self.encode_protobuf()?,
            PacketFormat::Legacy => self.encode_legacy(),
        })
    }

    fn encode_protobuf(&self) -> Result<Bytes, EncodeError> {
        let ping = UdpPing {
            timestamp: self.timestamp,
            request_extended_information: false,
            server_version_v2: self.server_version.into(),
            user_count: self.user_count,
            max_user_count: self.max_user_count.unwrap_or(u32::MAX),
            max_bandwidth_per_user: self.max_bandwidth_per_user,
        };
        let mut buf = BytesMut::with_capacity(1 + ping.encoded_len());
        buf.put_u8(0x01); // type = Ping
        ping.encode(&mut buf)?;
        Ok(buf.freeze())
    }

    fn encode_legacy(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(20);
        buf.put_u32(self.server_version.into());
        buf.put_u64(self.timestamp);
        buf.put_u32(self.user_count);
        buf.put_u32(self.max_user_count.unwrap_or(u32::MAX));
        buf.put_u32(self.max_bandwidth_per_user);
        buf.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::voice::codec::IncomingUdpPacket;

    #[test]
    fn authenticated_legacy_echo_decodes_as_ping() {
        let request = PingRequest {
            timestamp: 300,
            request_extended_information: false,
            format: PacketFormat::Legacy,
        };

        let encoded = request.encode_authenticated_echo().expect("encode echo");
        assert_eq!(encoded[0], 0x20);

        let packet = IncomingUdpPacket::decode(&encoded, None).expect("decode ping");
        let IncomingUdpPacket::Ping(decoded) = packet else {
            panic!("expected ping");
        };
        assert_eq!(decoded.timestamp, request.timestamp);
        assert_eq!(decoded.format, PacketFormat::Legacy);
    }

    #[test]
    fn authenticated_protobuf_echo_decodes_as_ping() {
        let request = PingRequest {
            timestamp: 123_456,
            request_extended_information: false,
            format: PacketFormat::Protobuf,
        };

        let encoded = request.encode_authenticated_echo().expect("encode echo");
        assert_eq!(encoded[0], 0x01);

        let packet = IncomingUdpPacket::decode(&encoded, None).expect("decode ping");
        let IncomingUdpPacket::Ping(decoded) = packet else {
            panic!("expected ping");
        };
        assert_eq!(decoded.timestamp, request.timestamp);
        assert_eq!(decoded.format, PacketFormat::Protobuf);
    }
}
