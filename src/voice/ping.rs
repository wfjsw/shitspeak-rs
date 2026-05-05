//! UDP ping packet encoding/decoding — supports both legacy (pre-1.5.0)
//! and protobuf (1.5.0+) formats.

use bytes::{BufMut as _, Bytes, BytesMut};
use prost::{EncodeError, Message as _};
use tokio::io::AsyncReadExt;

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

pub async fn try_decode_ping(data: &[u8]) -> Result<PingRequest, DecodeError> {
    let header = data.get(0).ok_or(DecodeError::TooShort)?;
    if *header == 0x1u8 {
        return decode_ping_protobuf(&data[1..])
            .await
            .map_err(|_| DecodeError::NotPing);
    }

    if data.len() == 12 {
        return decode_ping_legacy(&data)
            .await
            .map_err(|_| DecodeError::NotPing);
    }

    Err(DecodeError::NotPing)
}

/// Decode a protobuf Ping packet (data is after the 2-byte header).
pub async fn decode_ping_protobuf(data: &[u8]) -> Result<PingRequest, DecodeError> {
    let ping = crate::mumble_udp::Ping::decode(data).map_err(DecodeError::ProtobufDecode)?;
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
/// When called from the unencrypted path (`try_decode_ping`), `data` is the
/// full 12-byte packet including the `\x00\x00\x00\x00` header followed by a
/// raw big-endian u64 timestamp.
pub async fn decode_ping_legacy(data: &[u8]) -> Result<PingRequest, DecodeError> {
    if data.is_empty() {
        return Err(DecodeError::TooShort);
    }

    let mut data_cursor = std::io::Cursor::new(data);
    let (request_extended_information, timestamp) = if data.len() < size_of::<u64>() {
        // Short form: PDS varint-encoded timestamp (encrypted pings from authenticated clients).
        let (ts, consumed) = super::codec::read_varint(data).ok_or(DecodeError::LegacyDecode)?;
        if consumed != data.len() {
            return Err(DecodeError::LegacyDecode);
        }
        (false, ts)
    } else if data.len() <= size_of::<u64>() + 1 {
        (false, data_cursor.read_u64().await.map_err(|_| DecodeError::LegacyDecode)?)
    } else if data.len() == 4 + size_of::<u64>() {
        if data_cursor.read_u32().await.map_err(|_| DecodeError::LegacyDecode)? != 0 {
            return Err(DecodeError::TooShort);
        }

        let timestamp = data_cursor.read_u64().await.map_err(|_| DecodeError::LegacyDecode)?;
        (true, timestamp)
    } else {
        return Err(DecodeError::NotPing);
    };

    Ok(PingRequest {
        timestamp,
        request_extended_information,
        format: PacketFormat::Legacy,
    })
}

/// Encode a ping response in the same format as the request.
pub fn encode_ping_response(response: &PingResponse, format: PacketFormat) -> Result<Bytes, EncodeError> {
    tracing::debug!(
        "Encoding ping response: format={}, timestamp={}, version={}, users={}/{}, max_bandwidth={}",
        format,
        response.timestamp,
        response.server_version.to_string(),
        response.user_count,
        response.max_user_count.unwrap_or(u32::MAX),
        response.max_bandwidth_per_user,
    );

    Ok(match format {
        PacketFormat::Protobuf => encode_ping_protobuf(response)?,
        PacketFormat::Legacy => encode_ping_legacy(response),
    })
}

fn encode_ping_protobuf(response: &PingResponse) -> Result<Bytes, EncodeError> {
    let msg = crate::mumble_udp::Ping {
        timestamp: response.timestamp,
        request_extended_information: false,
        server_version_v2: response.server_version.into(),
        user_count: response.user_count,
        max_user_count: response.max_user_count.unwrap_or(u32::MAX),
        max_bandwidth_per_user: response.max_bandwidth_per_user,
    };
    let mut buf = BytesMut::with_capacity(1 + msg.encoded_len());
    buf.put_u8(0x01); // type = Ping
    msg.encode(&mut buf)?;
    Ok(buf.freeze())
}

fn encode_ping_legacy(response: &PingResponse) -> Bytes {
    let mut buf = BytesMut::with_capacity(20);
    buf.put_u32(response.server_version.into());
    buf.put_u64(response.timestamp);
    buf.put_u32(response.user_count);
    buf.put_u32(response.max_user_count.unwrap_or(u32::MAX));
    buf.put_u32(response.max_bandwidth_per_user);
    buf.freeze()
}
