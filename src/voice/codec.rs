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
//! | `(header >> 5) == 0`       | Legacy    | VoiceCELTAlpha             |
//! | `(header >> 5) == 1`       | Legacy    | Ping                       |
//! | `(header >> 5) == 2`       | Legacy    | VoiceSpeex                 |
//! | `(header >> 5) == 3`       | Legacy    | VoiceCELTBeta              |
//! | `(header >> 5) == 4`       | Legacy    | VoiceOpus                  |
//!
//! Protobuf UDP messages use a one-byte message type prefix.
//! Legacy voice packets encode type in the 3 MSBs and target/context
//! in the 5 LSBs of the first header byte.

use std::fmt::Display;

use bytes::{BufMut, Bytes, BytesMut};
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
    pub opus_data: Bytes,
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
    /// Not a ping
    NotPing,
}

/// The type of UDP packet received.
#[derive(Debug, Clone)]
pub enum UdpPacket {
    Audio(DecodedAudio),
    Ping(super::ping::PingRequest),
}

/// Decode any UDP packet, returning either Audio or Ping.
///
/// Tries protobuf format first (detected by `data[1] == 0x00` for 2+ byte
/// packets).  If protobuf decode fails, falls back to legacy format.
pub async fn decode_udp_packet(data: &[u8]) -> Result<UdpPacket, DecodeError> {
    if data.is_empty() {
        return Err(DecodeError::TooShort);
    }

    // Protobuf ping has an unambiguous one-byte type header.
    if data[0] == 0x01 {
        if let Ok(packet) = try_decode_protobuf(data).await {
            return Ok(packet);
        }
    }

    // Legacy pings can appear without header (12/24 bytes).
    if (data.len() == 12 || data.len() == 24)
        && super::ping::decode_ping_legacy(data).await.is_ok()
    {
        return Ok(UdpPacket::Ping(super::ping::decode_ping_legacy(data).await?));
    }

    // Protobuf audio (0x00) overlaps legacy CELTAlpha (type bits 000).
    // Try protobuf first and fall back to legacy if parse fails.
    if data[0] == 0x00 {
        if let Ok(packet) = try_decode_protobuf(data).await {
            return Ok(packet);
        }
    }

    // Legacy format: message type in top 3 bits of first header byte.
    let legacy_type = (data[0] >> 5) & 0x07;
    match legacy_type {
        0 => Ok(UdpPacket::Audio(decode_audio_legacy(data, "CELTAlpha")?)),
        1 => Ok(UdpPacket::Ping(super::ping::decode_ping_legacy(&data[1..]).await?)),
        2 => Ok(UdpPacket::Audio(decode_audio_legacy(data, "Speex")?)),
        3 => Ok(UdpPacket::Audio(decode_audio_legacy(data, "CELTBeta")?)),
        4 => Ok(UdpPacket::Audio(decode_audio_legacy(data, "Opus")?)),
        _ => Err(DecodeError::NotVoice),
    }
}

/// Try to decode as protobuf.  Returns `Err` if it's not actually protobuf.
async fn try_decode_protobuf(data: &[u8]) -> Result<UdpPacket, DecodeError> {
    match data[0] {
        0x00 => Ok(UdpPacket::Audio(decode_audio_protobuf(&data[1..])?)),
        0x01 => Ok(UdpPacket::Ping(super::ping::decode_ping_protobuf(&data[1..]).await?)),
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
            DecodeError::NotPing => write!(f, "not a ping packet"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decode a UDP voice packet, auto-detecting legacy vs protobuf format.
pub fn decode_audio_packet(data: &[u8]) -> Result<DecodedAudio, DecodeError> {
    if data.is_empty() {
        return Err(DecodeError::TooShort);
    }

    // Protobuf ping is not voice.
    if data[0] == 0x01 {
        return Err(DecodeError::NotVoice);
    }

    // Protobuf audio (0x00) overlaps with legacy CELTAlpha type bits.
    if data[0] == 0x00 {
        if let Ok(audio) = decode_audio_protobuf(&data[1..]) {
            return Ok(audio);
        }
    }

    // Legacy format: message type in top 3 bits of first header byte.
    let legacy_type = (data[0] >> 5) & 0x07;
    match legacy_type {
        0 => decode_audio_legacy(data, "CELTAlpha"),
        1 => Err(DecodeError::NotVoice),
        2 => decode_audio_legacy(data, "Speex"),
        3 => decode_audio_legacy(data, "CELTBeta"),
        4 => decode_audio_legacy(data, "Opus"),
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
        opus_data: Bytes::from(audio.opus_data),
        positional_data: audio.positional_data,
        volume_adjustment: audio.volume_adjustment,
        is_terminator: audio.is_terminator,
        format: PacketFormat::Protobuf,
    })
}

/// Decode a legacy-format voice packet.
///
/// Legacy format:
///   header byte: type in top 3 bits, target in low 5 bits
///   varint sender_session (server->client only)
///   If target == 0x1F (loopback):
///     varint position_count
///   varint sequence number
///   for Opus: varint payload_size_with_terminator_flag, then payload bytes
///   remaining bytes = opus/celt/speex payload
fn decode_audio_legacy(data: &[u8], _codec: &str) -> Result<DecodedAudio, DecodeError> {
    if data.len() < 2 {
        return Err(DecodeError::TooShort);
    }

    let target = (data[0] & 0x1f) as u32;

    // Try server-side packet shape first (client->server: no sender_session).
    // Fall back to server->client shape if needed.
    let parsed = decode_audio_legacy_inner(data, target, false)
        .or_else(|| decode_audio_legacy_inner(data, target, true))
        .ok_or(DecodeError::LegacyDecode)?;

    Ok(DecodedAudio {
        target,
        sender_session: parsed.0,
        frame_number: parsed.1,
        opus_data: parsed.2,
        positional_data: parsed.3,
        volume_adjustment: 1.0,
        is_terminator: parsed.4,
        format: PacketFormat::Legacy,
    })
}

fn decode_audio_legacy_inner(
    data: &[u8],
    target: u32,
    has_sender_session: bool,
) -> Option<(u32, u64, Bytes, Vec<f32>, bool)> {
    let mut pos = 1usize;

    let sender_session = if has_sender_session {
        let (session, n) = read_varint(&data[pos..])?;
        pos += n;
        session as u32
    } else {
        0
    };

    if target == 0x1F {
        let (_position_count, n) = read_varint(&data[pos..])?;
        pos += n;
    }

    let (frame_number, n) = read_varint(&data[pos..])?;
    pos += n;

    let (opus_data, is_terminator) = {
        let (size_flag, n) = read_varint(&data[pos..])?;
        pos += n;
        let payload_size = (size_flag & 0x1FFF) as usize;
        let is_terminator = (size_flag & 0x2000) != 0;
        if pos + payload_size > data.len() {
            return None;
        }
        let payload = Bytes::copy_from_slice(&data[pos..pos + payload_size]);
        pos += payload_size;
        (payload, is_terminator)
    };

    let positional_data = if data.len() == pos {
        Vec::new()
    } else if data.len() == pos + 12 {
        let mut out = Vec::with_capacity(3);
        for i in 0..3 {
            let start = pos + i * 4;
            let bytes: [u8; 4] = data[start..start + 4].try_into().ok()?;
            out.push(f32::from_le_bytes(bytes));
        }
        out
    } else {
        return None;
    };

    Some((sender_session, frame_number, opus_data, positional_data, is_terminator))
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
pub fn encode_audio_packet(audio: &DecodedAudio, format: PacketFormat) -> Bytes {
    match format {
        PacketFormat::Protobuf => encode_audio_protobuf(audio),
        PacketFormat::Legacy => encode_audio_legacy(audio),
    }
}

/// Encode as protobuf Audio message with 2-byte header.
fn encode_audio_protobuf(audio: &DecodedAudio) -> Bytes {
    use crate::mumble_udp::{Audio, audio};

    let msg = Audio {
        header: Some(audio::Header::Target(audio.target)),
        sender_session: audio.sender_session,
        frame_number: audio.frame_number,
        opus_data: audio.opus_data.to_vec(),
        positional_data: audio.positional_data.clone(),
        volume_adjustment: audio.volume_adjustment,
        is_terminator: audio.is_terminator,
    };

    let proto_bytes = msg.encode_to_vec();
    let mut buf = BytesMut::with_capacity(1 + proto_bytes.len());
    buf.put_u8(0x00); // type = Audio
    buf.extend_from_slice(&proto_bytes);
    buf.freeze()
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
fn encode_audio_legacy(audio: &DecodedAudio) -> Bytes {
    let mut buf = BytesMut::new();
    if audio.target >= (1 << 5) {
        return Bytes::new();
    }
    let header = (0x04u8 << 5) | ((audio.target as u8) & 0x1f); // VoiceOpus + target
    buf.put_u8(header);

    // Server->client legacy packets include sender session.
    write_varint(&mut buf, audio.sender_session as u64);

    if audio.target == 0x1F {
        write_varint(&mut buf, audio.positional_data.len() as u64 / 3);
    }
    write_varint(&mut buf, audio.frame_number);

    let size_flag = (audio.opus_data.len() as u64 & 0x1FFF)
        | if audio.is_terminator { 0x2000 } else { 0 };
    write_varint(&mut buf, size_flag);

    buf.extend_from_slice(&audio.opus_data);

    if audio.positional_data.len() == 3 {
        for f in &audio.positional_data {
            buf.extend_from_slice(&f.to_le_bytes());
        }
    }

    buf.freeze()
}

/// Write a u64 as a varint into a mutable byte buffer.
fn write_varint(buf: &mut BytesMut, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.put_u8(byte);
        if value == 0 {
            break;
        }
    }
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
            opus_data: Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]),
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
            opus_data: Bytes::from_static(&[0x01, 0x02, 0x03]),
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
            opus_data: Bytes::from_static(&[0xAA]),
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
            opus_data: Bytes::from_static(&[0x00]),
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
            opus_data: Bytes::from_static(&[0x00]),
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
        let ping = vec![0x01, 0x00];
        assert!(matches!(decode_audio_packet(&ping), Err(DecodeError::NotVoice)));

        // Legacy ping: type in top 3 bits => 0x20
        let legacy_ping = vec![0x20, 0x00];
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
            let mut buf = BytesMut::new();
            write_varint(&mut buf, val);
            let (decoded, n) = read_varint(&buf).expect("read varint");
            assert_eq!(decoded, val, "varint roundtrip for {val}");
            assert_eq!(n, buf.len(), "consumed all bytes for {val}");
        }
    }
}
