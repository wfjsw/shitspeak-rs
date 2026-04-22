//! UDP voice packet encoding/decoding — supports both legacy (pre-1.5.0)
//! and protobuf (1.5.0+) formats.
//!
//! ## Wire format detection
//!
//! The first byte(s) of a UDP packet determine the format:
//!
//! | First byte(s)              | Format    | Meaning                    |
//! |----------------------------|-----------|----------------------------|
//! | `0x00`                     | Protobuf  | Audio message              |
//! | `0x01`                     | Protobuf  | Ping message               |
//! | `0x00` (legacy)            | Legacy    | VoiceCELTAlpha             |
//! | `0x01` (legacy)            | Legacy    | Ping                       |
//! | `0x02` (legacy)            | Legacy    | VoiceSpeex                 |
//! | `0x03` (legacy)            | Legacy    | VoiceCELTBeta              |
//! | `0x04` (legacy)            | Legacy    | VoiceOpus                  |
//!
//! Protobuf packets are distinguished by having `(type << 8) | 0` as the
//! first two bytes (the second byte is always 0 for protobuf Audio/Ping).
//! Legacy packets have a single type byte followed by varint-encoded fields.

use std::fmt::Display;

use prost::Message as _;

/// The decoded result of a UDP voice packet.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedAudio {
    /// Target ID (0 = normal speech, 31 = loopback, other = whisper/shout).
    pub target: u32,
    /// Sender session ID.
    pub sender_session: u32,
    /// Frame number (sequence).
    pub frame_number: u64,
    /// Opus-encoded audio payload.
    pub opus_data: Vec<u8>,
    /// Optional positional data [x, y, z].
    pub positional_data: Vec<f32>,
    /// Volume adjustment factor (1.0 = no adjustment).
    pub volume_adjustment: f32,
    /// Whether this is the last frame in a transmission.
    pub is_terminator: bool,
    /// The format used for this packet.
    pub format: PacketFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketFormat {
    Legacy,
    Protobuf,
}

impl Display for PacketFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketFormat::Legacy => write!(f, "legacy"),
            PacketFormat::Protobuf => write!(f, "protobuf"),
        }
    }
}

/// Errors that can occur during UDP packet decoding.
#[derive(Debug)]
pub enum DecodeError {
    /// Packet too short to contain a valid header.
    TooShort,
    /// Unknown legacy message type (not a voice codec).
    NotVoice,
    /// Failed to decode protobuf.
    ProtobufDecode(prost::DecodeError),
    /// Failed to decode legacy varint fields.
    LegacyDecode,
}

/// The type of UDP packet received.
#[derive(Debug, Clone)]
pub enum UdpPacket {
    Audio(DecodedAudio),
    Ping(PingRequest),
}

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

/// Decode any UDP packet, returning either Audio or Ping.
///
/// Tries protobuf format first (detected by `data[1] == 0x00` for 2+ byte
/// packets).  If protobuf decode fails, falls back to legacy format.
pub fn decode_udp_packet(data: &[u8]) -> Result<UdpPacket, DecodeError> {
    if data.is_empty() {
        return Err(DecodeError::TooShort);
    }

    // Protobuf detection: first two bytes are (type << 8) | 0.
    // Only attempt if the second byte is exactly 0x00.
    if data.len() >= 2 && data[1] == 0x00 {
        if let Ok(packet) = try_decode_protobuf(data) {
            return Ok(packet);
        }
        // Protobuf detection was a false positive (legacy packet whose
        // second byte happened to be 0x00).  Fall through to legacy.
    }

    // Legacy format: first byte is the message type.
    match data[0] {
        0x00 => Ok(UdpPacket::Audio(decode_audio_legacy(&data[1..], "CELTAlpha")?)),
        0x02 => Ok(UdpPacket::Audio(decode_audio_legacy(&data[1..], "Speex")?)),
        0x03 => Ok(UdpPacket::Audio(decode_audio_legacy(&data[1..], "CELTBeta")?)),
        0x04 => Ok(UdpPacket::Audio(decode_audio_legacy(&data[1..], "Opus")?)),
        0x01 => Ok(UdpPacket::Ping(decode_ping_legacy(&data[1..])?)),
        _ => Err(DecodeError::NotVoice),
    }
}

/// Try to decode as protobuf.  Returns `Err` if it's not actually protobuf.
fn try_decode_protobuf(data: &[u8]) -> Result<UdpPacket, DecodeError> {
    match data[0] {
        0x00 => Ok(UdpPacket::Audio(decode_audio_protobuf(&data[2..])?)),
        0x01 => Ok(UdpPacket::Ping(decode_ping_protobuf(&data[2..])?)),
        _ => Err(DecodeError::NotVoice),
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::TooShort => write!(f, "packet too short"),
            DecodeError::NotVoice => write!(f, "not a voice packet"),
            DecodeError::ProtobufDecode(e) => write!(f, "protobuf decode error: {e}"),
            DecodeError::LegacyDecode => write!(f, "legacy decode error"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decode a UDP voice packet, auto-detecting legacy vs protobuf format.
pub fn decode_audio_packet(data: &[u8]) -> Result<DecodedAudio, DecodeError> {
    if data.is_empty() {
        return Err(DecodeError::TooShort);
    }

    // Protobuf detection: first two bytes are (type << 8) | 0.
    // Type 0 = Audio. The second byte being 0 is the key discriminator
    // because legacy VoiceCELTAlpha also has first byte 0 but the second
    // byte would be a varint (non-zero for any real target).
    if data.len() >= 2 && data[1] == 0x00 && (data[0] == 0x00 || data[0] == 0x01) {
        if data[0] == 0x00 {
            return decode_audio_protobuf(&data[2..]);
        }
        // data[0] == 0x01 is a protobuf Ping — not voice
        return Err(DecodeError::NotVoice);
    }

    // Legacy format: first byte is the message type.
    match data[0] {
        0x00 => decode_audio_legacy(&data[1..], "CELTAlpha"),
        0x02 => decode_audio_legacy(&data[1..], "Speex"),
        0x03 => decode_audio_legacy(&data[1..], "CELTBeta"),
        0x04 => decode_audio_legacy(&data[1..], "Opus"),
        0x01 => Err(DecodeError::NotVoice), // legacy Ping
        _ => Err(DecodeError::NotVoice),
    }
}

/// Decode a protobuf-encoded Audio packet (the `data` is after the 2-byte header).
fn decode_audio_protobuf(data: &[u8]) -> Result<DecodedAudio, DecodeError> {
    let audio = crate::mumble_udp::Audio::decode(data).map_err(DecodeError::ProtobufDecode)?;

    let target = audio.header.as_ref().map_or(0, |h| match h {
        crate::mumble_udp::audio::Header::Target(t) => *t,
        crate::mumble_udp::audio::Header::Context(_) => 0,
    });

    Ok(DecodedAudio {
        target,
        sender_session: audio.sender_session,
        frame_number: audio.frame_number,
        opus_data: audio.opus_data,
        positional_data: audio.positional_data,
        volume_adjustment: audio.volume_adjustment,
        is_terminator: audio.is_terminator,
        format: PacketFormat::Protobuf,
    })
}

/// Decode a legacy-format voice packet.
///
/// Legacy format (after the type byte):
///   varint target
///   If target == 0x1F (loopback):
///     varint position_count
///     varint session
///     varint sequence number
///   Else:
///     varint session
///     varint sequence number
///   remaining bytes = opus/celt/speex payload
fn decode_audio_legacy(data: &[u8], _codec: &str) -> Result<DecodedAudio, DecodeError> {
    if data.is_empty() {
        return Err(DecodeError::TooShort);
    }

    let mut pos = 0;

    // Read varint: target
    let (target, n) = read_varint(&data[pos..]).ok_or(DecodeError::LegacyDecode)?;
    pos += n;

    let (sender_session, frame_number) = if target == 0x1F {
        // Loopback: skip position_count, then session, then seq
        let (_pos_count, n1) = read_varint(&data[pos..]).ok_or(DecodeError::LegacyDecode)?;
        pos += n1;
        let (session, n2) = read_varint(&data[pos..]).ok_or(DecodeError::LegacyDecode)?;
        pos += n2;
        let (seq, n3) = read_varint(&data[pos..]).ok_or(DecodeError::LegacyDecode)?;
        pos += n3;
        (session, seq)
    } else {
        // Normal: second varint is session, third is sequence
        let (session, n1) = read_varint(&data[pos..]).ok_or(DecodeError::LegacyDecode)?;
        pos += n1;
        let (seq, n2) = read_varint(&data[pos..]).ok_or(DecodeError::LegacyDecode)?;
        pos += n2;
        (session, seq)
    };

    let opus_data = data[pos..].to_vec();

    Ok(DecodedAudio {
        target: target as u32,
        sender_session: sender_session as u32,
        frame_number,
        opus_data,
        positional_data: Vec::new(),
        volume_adjustment: 1.0,
        is_terminator: false,
        format: PacketFormat::Legacy,
    })
}

/// Read a varint from bytes. Returns `(value, bytes_consumed)`.
fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None; // overflow
        }
    }
    None // truncated
}

/// Encode audio data into a UDP packet using the specified format.
///
/// Returns the raw bytes ready to send via UDP.
pub fn encode_audio_packet(audio: &DecodedAudio, format: PacketFormat) -> Vec<u8> {
    match format {
        PacketFormat::Protobuf => encode_audio_protobuf(audio),
        PacketFormat::Legacy => encode_audio_legacy(audio),
    }
}

/// Encode as protobuf Audio message with 2-byte header.
fn encode_audio_protobuf(audio: &DecodedAudio) -> Vec<u8> {
    use crate::mumble_udp::{Audio, audio};

    let msg = Audio {
        header: Some(audio::Header::Target(audio.target)),
        sender_session: audio.sender_session,
        frame_number: audio.frame_number,
        opus_data: audio.opus_data.clone(),
        positional_data: audio.positional_data.clone(),
        volume_adjustment: audio.volume_adjustment,
        is_terminator: audio.is_terminator,
    };

    let proto_bytes = msg.encode_to_vec();
    let mut buf = Vec::with_capacity(2 + proto_bytes.len());
    buf.push(0x00); // type = Audio
    buf.push(0x00); // protobuf discriminator
    buf.extend_from_slice(&proto_bytes);
    buf
}

/// Encode as legacy voice packet.
///
/// Legacy format:
///   type byte (0x04 = Opus)
///   varint target
///   If target == 0x1F (loopback):
///     varint position_count (0 if no positional data)
///   varint session
///   varint sequence number
///   opus payload
fn encode_audio_legacy(audio: &DecodedAudio) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0x04); // VoiceOpus
    write_varint(&mut buf, audio.target as u64);
    if audio.target == 0x1F {
        write_varint(&mut buf, audio.positional_data.len() as u64 / 3);
    }
    write_varint(&mut buf, audio.sender_session as u64);
    write_varint(&mut buf, audio.frame_number);
    buf.extend_from_slice(&audio.opus_data);
    buf
}

/// Write a u64 as a varint into a Vec.
fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

// ── Ping decode / encode ──────────────────────────────────────────────────

/// Decode a protobuf Ping packet (data is after the 2-byte header).
fn decode_ping_protobuf(data: &[u8]) -> Result<PingRequest, DecodeError> {
    let ping = crate::mumble_udp::Ping::decode(data).map_err(DecodeError::ProtobufDecode)?;
    Ok(PingRequest {
        timestamp: ping.timestamp,
        request_extended_information: ping.request_extended_information,
        format: PacketFormat::Protobuf,
    })
}

/// Decode a legacy Ping packet (data is after the type byte).
/// Legacy ping format: varint timestamp, then optionally a request flag byte.
fn decode_ping_legacy(data: &[u8]) -> Result<PingRequest, DecodeError> {
    if data.is_empty() {
        return Err(DecodeError::TooShort);
    }
    let (timestamp, _) = read_varint(data).ok_or(DecodeError::LegacyDecode)?;
    // Legacy pings don't have an explicit request_extended_information flag;
    // clients that want server info send a second byte.
    let request_extended = data.len() > 1 && data[1] != 0;
    Ok(PingRequest {
        timestamp,
        request_extended_information: request_extended,
        format: PacketFormat::Legacy,
    })
}

/// Server information included in ping responses.
pub struct PingResponse {
    pub timestamp: u64,
    pub server_version: crate::protocol_version::ProtocolVersion,
    pub user_count: u32,
    pub max_user_count: u32,
    pub max_bandwidth_per_user: u32,
}

/// Encode a ping response in the same format as the request.
pub fn encode_ping_response(response: &PingResponse, format: PacketFormat) -> Vec<u8> {
    tracing::debug!(
        "Encoding ping response: format={}, timestamp={}, version={}, users={}/{}",
        format,
        response.timestamp,
        response.server_version.to_string(),
        response.user_count,
        response.max_user_count,
    );

    match format {
        PacketFormat::Protobuf => encode_ping_protobuf(response),
        PacketFormat::Legacy => encode_ping_legacy(response),
    }
}

fn encode_ping_protobuf(response: &PingResponse) -> Vec<u8> {
    let msg = crate::mumble_udp::Ping {
        timestamp: response.timestamp,
        request_extended_information: true,
        server_version_v2: response.server_version.into(),
        user_count: response.user_count,
        max_user_count: response.max_user_count,
        max_bandwidth_per_user: response.max_bandwidth_per_user,
    };
    let proto_bytes = msg.encode_to_vec();
    let mut buf = Vec::with_capacity(2 + proto_bytes.len());
    buf.push(0x01); // type = Ping
    buf.push(0x00); // protobuf discriminator
    buf.extend_from_slice(&proto_bytes);
    buf
}

fn encode_ping_legacy(response: &PingResponse) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0x01); // Ping type
    write_varint(&mut buf, response.timestamp);
    // Legacy extended info: version (4 bytes BE), users (4 bytes BE),
    // max users (4 bytes BE), max bandwidth (4 bytes BE)
    let version: u32 = response.server_version.into();
    buf.extend_from_slice(&version.to_be_bytes());
    buf.extend_from_slice(&response.user_count.to_be_bytes());
    buf.extend_from_slice(&response.max_user_count.to_be_bytes());
    buf.extend_from_slice(&response.max_bandwidth_per_user.to_be_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Protobuf roundtrip ───────────────────────────────────────────────

    #[test]
    fn protobuf_roundtrip() {
        let original = DecodedAudio {
            target: 0,
            sender_session: 42,
            frame_number: 100,
            opus_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            positional_data: vec![1.0, 2.0, 3.0],
            volume_adjustment: 0.8,
            is_terminator: false,
            format: PacketFormat::Protobuf,
        };

        let encoded = encode_audio_packet(&original, PacketFormat::Protobuf);
        let decoded = decode_audio_packet(&encoded).expect("decode protobuf");

        assert_eq!(decoded.target, original.target);
        assert_eq!(decoded.sender_session, original.sender_session);
        assert_eq!(decoded.frame_number, original.frame_number);
        assert_eq!(decoded.opus_data, original.opus_data);
        assert_eq!(decoded.format, PacketFormat::Protobuf);
    }

    // ── Legacy roundtrip ─────────────────────────────────────────────────

    #[test]
    fn legacy_roundtrip() {
        let original = DecodedAudio {
            target: 0,
            sender_session: 7,
            frame_number: 42,
            opus_data: vec![0x01, 0x02, 0x03],
            positional_data: Vec::new(),
            volume_adjustment: 1.0,
            is_terminator: false,
            format: PacketFormat::Legacy,
        };

        let encoded = encode_audio_packet(&original, PacketFormat::Legacy);
        let decoded = decode_audio_packet(&encoded).expect("decode legacy");

        assert_eq!(decoded.target, original.target);
        assert_eq!(decoded.sender_session, original.sender_session);
        assert_eq!(decoded.frame_number, original.frame_number);
        assert_eq!(decoded.opus_data, original.opus_data);
        assert_eq!(decoded.format, PacketFormat::Legacy);
    }

    // ── Legacy loopback ──────────────────────────────────────────────────

    #[test]
    fn legacy_loopback() {
        let original = DecodedAudio {
            target: 31,
            sender_session: 5,
            frame_number: 1,
            opus_data: vec![0xAA],
            positional_data: Vec::new(),
            volume_adjustment: 1.0,
            is_terminator: false,
            format: PacketFormat::Legacy,
        };

        let encoded = encode_audio_packet(&original, PacketFormat::Legacy);
        let decoded = decode_audio_packet(&encoded).expect("decode legacy loopback");

        assert_eq!(decoded.target, 31);
        assert_eq!(decoded.sender_session, 5);
        assert_eq!(decoded.frame_number, 1);
        assert_eq!(decoded.opus_data, vec![0xAA]);
    }

    // ── Format detection ─────────────────────────────────────────────────

    #[test]
    fn detect_protobuf_format() {
        let audio = DecodedAudio {
            target: 0,
            sender_session: 1,
            frame_number: 0,
            opus_data: vec![0x00],
            positional_data: Vec::new(),
            volume_adjustment: 1.0,
            is_terminator: false,
            format: PacketFormat::Protobuf,
        };
        let encoded = encode_audio_packet(&audio, PacketFormat::Protobuf);
        let decoded = decode_audio_packet(&encoded).expect("decode");
        assert_eq!(decoded.format, PacketFormat::Protobuf);
    }

    #[test]
    fn detect_legacy_format() {
        let audio = DecodedAudio {
            target: 0,
            sender_session: 1,
            frame_number: 0,
            opus_data: vec![0x00],
            positional_data: Vec::new(),
            volume_adjustment: 1.0,
            is_terminator: false,
            format: PacketFormat::Legacy,
        };
        let encoded = encode_audio_packet(&audio, PacketFormat::Legacy);
        let decoded = decode_audio_packet(&encoded).expect("decode");
        assert_eq!(decoded.format, PacketFormat::Legacy);
    }

    // ── Edge cases ───────────────────────────────────────────────────────

    #[test]
    fn empty_packet() {
        assert!(decode_audio_packet(&[]).is_err());
    }

    #[test]
    fn ping_not_voice() {
        // Protobuf ping: [0x01, 0x00, ...]
        let ping = vec![0x01, 0x00, 0x00];
        assert!(matches!(decode_audio_packet(&ping), Err(DecodeError::NotVoice)));

        // Legacy ping: [0x01, ...]
        let legacy_ping = vec![0x01, 0x00];
        assert!(matches!(decode_audio_packet(&legacy_ping), Err(DecodeError::NotVoice)));
    }

    #[test]
    fn unknown_type() {
        assert!(matches!(decode_audio_packet(&[0xFF]), Err(DecodeError::NotVoice)));
    }

    // ── Varint encoding ──────────────────────────────────────────────────

    #[test]
    fn varint_roundtrip() {
        let test_values = [0u64, 1, 127, 128, 255, 256, 0xFFFF, 0xFFFFFFFF];
        for &val in &test_values {
            let mut buf = Vec::new();
            write_varint(&mut buf, val);
            let (decoded, n) = read_varint(&buf).expect("read varint");
            assert_eq!(decoded, val, "varint roundtrip for {val}");
            assert_eq!(n, buf.len(), "consumed all bytes for {val}");
        }
    }
}
