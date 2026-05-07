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
//! | `(header >> 5) == 0`       | Legacy    | VoiceCELTAlpha (rejected)  |
//! | `(header >> 5) == 1`       | Legacy    | Ping                       |
//! | `(header >> 5) == 2`       | Legacy    | VoiceSpeex (rejected)      |
//! | `(header >> 5) == 3`       | Legacy    | VoiceCELTBeta (rejected)   |
//! | `(header >> 5) == 4`       | Legacy    | VoiceOpus                  |
//!
//! ## Server role
//!
//! This implementation is server-only. Inbound packets are always
//! client→server (no `sender_session` field in the legacy wire format).
//! Outbound packets are always server→client (`sender_session` included in
//! legacy, `context` oneof used in protobuf instead of `target`).
//!
//! ## Varint encoding
//!
//! Legacy packets use Mumble's PacketDataStream varint, not LEB128:
//!
//! | First byte range | Length | Value formula                                     |
//! |------------------|--------|---------------------------------------------------|
//! | `0x00–0x7F`      | 1 byte | `byte & 0x7F`                                     |
//! | `0x80–0xBF`      | 2 byte | `((byte & 0x3F) << 8) | b1`                       |
//! | `0xC0–0xDF`      | 3 byte | `((byte & 0x1F) << 16) | (b1 << 8) | b2`          |
//! | `0xE0–0xEF`      | 4 byte | `((byte & 0x0F) << 24) | (b1 << 16) | … | b3`     |
//! | `0xF0–0xFF`      | special/negative — rejected                         |

use std::fmt::Display;

use bytes::{BufMut, Bytes, BytesMut};
use prost::Message as _;

use crate::messages::encoder::{Audio as AudioWire, AudioContext, AudioHeader, AudioTarget};

/// The decoded result of a UDP voice packet.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedAudio {
    /// Routing target carried by the inbound packet. For server→client packets
    /// reconstructed from a `DecodedAudio` (e.g. server loopback), this field
    /// is unused at the wire boundary — the caller of `encode_audio_packet`
    /// supplies an `AudioContext` separately.
    pub target: AudioTarget,
    /// Sender session ID. Zero for client→server (not present on wire).
    pub sender_session: u32,
    /// Frame number (sequence).
    pub frame_number: u64,
    /// Opus-encoded audio payload.
    pub opus_data: Bytes,
    /// Optional positional data [x, y, z] in metres. Empty or exactly 3 elements.
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
    /// Legacy codec (CELT-α, CELT-β, Speex) — not supported by this server.
    UnsupportedCodec,
    /// Failed to decode protobuf.
    ProtobufDecode(prost::DecodeError),
    /// Failed to decode legacy varint fields.
    LegacyDecode,
    /// Not a ping
    NotPing,
    /// Packet structure is valid but contains invalid field values.
    MalformedPacket,
}

/// The type of UDP packet received.
#[derive(Debug, Clone)]
pub enum UdpPacket {
    Audio(DecodedAudio),
    Ping(super::ping::PingRequest),
}

/// Decode any UDP packet, returning either Audio or Ping.
///
/// Tries protobuf format first (detected by first byte `0x00` or `0x01`).
/// Falls back to legacy format for other first-byte values.
pub fn decode_udp_packet(data: &[u8]) -> Result<UdpPacket, DecodeError> {
    if data.is_empty() {
        return Err(DecodeError::TooShort);
    }

    // Protobuf ping has an unambiguous one-byte type header.
    if data[0] == 0x01 {
        if let Ok(packet) = try_decode_protobuf(data) {
            return Ok(packet);
        }
    }

    // Legacy pings can appear without header (12/24 bytes).
    if data.len() == 12 || data.len() == 24 {
        if let Ok(ping) = super::ping::decode_ping_legacy(data) {
            return Ok(UdpPacket::Ping(ping));
        }
    }

    // Protobuf audio (0x00) overlaps legacy CELTAlpha (type bits 000).
    // Try protobuf first; propagate any domain error (MalformedPacket, etc.)
    // but fall through to legacy only when the bytes simply aren't valid protobuf.
    if data[0] == 0x00 {
        match try_decode_protobuf(data) {
            Ok(packet) => return Ok(packet),
            Err(DecodeError::ProtobufDecode(_)) | Err(DecodeError::NotVoice) => {}
            Err(e) => return Err(e),
        }
    }

    // Legacy format: message type in top 3 bits of first header byte.
    let legacy_type = (data[0] >> 5) & 0x07;
    match legacy_type {
        0 | 2 | 3 => Err(DecodeError::UnsupportedCodec), // CELTAlpha, Speex, CELTBeta
        1 => Ok(UdpPacket::Ping(super::ping::decode_ping_legacy(&data[1..])?)),
        4 => Ok(UdpPacket::Audio(decode_audio_legacy(data)?)),
        _ => Err(DecodeError::NotVoice),
    }
}

/// Try to decode as protobuf. Returns `Err` if it is not actually protobuf.
fn try_decode_protobuf(data: &[u8]) -> Result<UdpPacket, DecodeError> {
    match data[0] {
        0x00 => Ok(UdpPacket::Audio(decode_audio_protobuf(&data[1..])?)),
        0x01 => Ok(UdpPacket::Ping(super::ping::decode_ping_protobuf(&data[1..])?)),
        _ => Err(DecodeError::NotVoice),
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::TooShort => write!(f, "packet too short"),
            DecodeError::NotVoice => write!(f, "not a voice packet"),
            DecodeError::UnsupportedCodec => write!(f, "unsupported codec (only Opus is supported)"),
            DecodeError::ProtobufDecode(e) => write!(f, "protobuf decode error: {e}"),
            DecodeError::LegacyDecode => write!(f, "legacy decode error"),
            DecodeError::NotPing => write!(f, "not a ping packet"),
            DecodeError::MalformedPacket => write!(f, "malformed packet"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decode a UDP voice packet, auto-detecting legacy vs protobuf format.
///
/// Used for TCP-tunnelled voice (UDPTunnel message). Pings are rejected.
pub fn decode_audio_packet(data: &[u8]) -> Result<DecodedAudio, DecodeError> {
    if data.is_empty() {
        return Err(DecodeError::TooShort);
    }

    // Protobuf ping is not voice.
    if data[0] == 0x01 {
        return Err(DecodeError::NotVoice);
    }

    // Protobuf audio (0x00) overlaps with legacy CELTAlpha type bits.
    // Propagate domain errors (MalformedPacket, etc.); only fall through on
    // actual parse failures so a corrupt-but-valid-protobuf isn't silently
    // mis-decoded as legacy.
    if data[0] == 0x00 {
        match decode_audio_protobuf(&data[1..]) {
            Ok(audio) => return Ok(audio),
            Err(DecodeError::ProtobufDecode(_)) => {}
            Err(e) => return Err(e),
        }
    }

    // Legacy format: message type in top 3 bits of first header byte.
    let legacy_type = (data[0] >> 5) & 0x07;
    match legacy_type {
        0 | 2 | 3 => Err(DecodeError::UnsupportedCodec), // CELTAlpha, Speex, CELTBeta
        1 => Err(DecodeError::NotVoice),                  // legacy ping byte
        4 => decode_audio_legacy(data),
        _ => Err(DecodeError::NotVoice),
    }
}

/// Decode a protobuf-encoded Audio packet (`data` is the bytes after the type byte).
///
/// Delegates the protobuf parse to the encoder wrapper so the wire-level
/// `mumble_udp::Audio` type is contained there. The server is permissive about
/// which `oneof Header` variant the client sent — both `target` and `context`
/// are collapsed to `AudioTarget` by the wrapper.
fn decode_audio_protobuf(data: &[u8]) -> Result<DecodedAudio, DecodeError> {
    let audio = AudioWire::decode_wire(data).map_err(|e| match e {
        crate::messages::encoder::AudioWireError::Protobuf(e) => DecodeError::ProtobufDecode(e),
        crate::messages::encoder::AudioWireError::Domain(_) => DecodeError::MalformedPacket,
        crate::messages::encoder::AudioWireError::EncodeOverflow(_) => DecodeError::MalformedPacket,
    })?;

    let target = match audio.header {
        Some(AudioHeader::Target(t)) => t,
        // Server is permissive: accept Context the client (incorrectly) sent
        // and treat its value as a routing target.
        Some(AudioHeader::Context(c)) => AudioTarget::from(u32::from(c)),
        None => AudioTarget::Normal,
    };

    Ok(DecodedAudio {
        target,
        sender_session: audio.sender_session,
        frame_number: audio.frame_number,
        opus_data: audio.opus_data,
        positional_data: audio.positional_data,
        // proto3 default 0.0 means the field is unset; normalise to 1.0 (no-op gain)
        // so downstream code never multiplies audio samples by zero.
        volume_adjustment: if audio.volume_adjustment == 0.0 {
            1.0
        } else {
            audio.volume_adjustment
        },
        is_terminator: audio.is_terminator,
        format: PacketFormat::Protobuf,
    })
}

/// Decode a legacy-format Opus voice packet.
///
/// Inbound wire layout (client→server, server role):
/// ```text
/// byte 0       : header  (3 bits codec = 4/Opus | 5 bits target)
/// varint       : frame_number
/// varint       : payload_size | (0x2000 if is_terminator)
/// [payload_size bytes]: Opus payload
/// [12 bytes]   : optional positional data (3 × IEEE-754 float, little-endian)
/// ```
fn decode_audio_legacy(data: &[u8]) -> Result<DecodedAudio, DecodeError> {
    if data.len() < 2 {
        return Err(DecodeError::TooShort);
    }

    let target = AudioTarget::from((data[0] & 0x1f) as u32);

    decode_audio_legacy_inner(data, target).ok_or(DecodeError::LegacyDecode)
}

fn decode_audio_legacy_inner(data: &[u8], target: AudioTarget) -> Option<DecodedAudio> {
    // Skip the header byte. Client→server packets carry no sender_session.
    let mut pos = 1usize;

    let (frame_number, n) = read_varint(&data[pos..])?;
    pos += n;

    let (size_flag, n) = read_varint(&data[pos..])?;
    pos += n;
    let payload_size = (size_flag & 0x1FFF) as usize;
    let is_terminator = (size_flag & 0x2000) != 0;

    if pos + payload_size > data.len() {
        return None;
    }
    let opus_data = Bytes::copy_from_slice(&data[pos..pos + payload_size]);
    pos += payload_size;

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

    Some(DecodedAudio {
        target,
        sender_session: 0, // not present in client→server packets
        frame_number,
        opus_data,
        positional_data,
        volume_adjustment: 1.0,
        is_terminator,
        format: PacketFormat::Legacy,
    })
}

/// Read a Mumble PacketDataStream varint from `data`.
///
/// Returns `(value, bytes_consumed)` or `None` on truncation or unsupported
/// encoding (0xF0–0xFF: special/negative forms not used in voice packets).
pub(super) fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let c = *data.first()? as u64;
    if c & 0x80 == 0 {
        // 0x00–0x7F: 1 byte, 7-bit value
        Some((c, 1))
    } else if c & 0x40 == 0 {
        // 0x80–0xBF: 2 bytes, 14-bit value
        let b1 = *data.get(1)? as u64;
        Some(((c & 0x3F) << 8 | b1, 2))
    } else if c & 0x20 == 0 {
        // 0xC0–0xDF: 3 bytes, 21-bit value
        let b1 = *data.get(1)? as u64;
        let b2 = *data.get(2)? as u64;
        Some(((c & 0x1F) << 16 | b1 << 8 | b2, 3))
    } else if c & 0x10 == 0 {
        // 0xE0–0xEF: 4 bytes, 28-bit value
        let b1 = *data.get(1)? as u64;
        let b2 = *data.get(2)? as u64;
        let b3 = *data.get(3)? as u64;
        Some(((c & 0x0F) << 24 | b1 << 16 | b2 << 8 | b3, 4))
    } else {
        // 0xF0–0xFF: special/negative forms — not emitted by voice packets
        None
    }
}

/// Write a u64 as a Mumble PacketDataStream varint into `buf`.
///
/// Values above 2^28−1 are clamped to the maximum 4-byte representable value
/// (0x0FFFFFFF). Frame numbers in practice require at most 28 bits for any
/// session under 31 continuous days at 10 ms/frame.
fn write_varint(buf: &mut BytesMut, value: u64) {
    if value <= 0x7F {
        buf.put_u8(value as u8);
    } else if value <= 0x3FFF {
        buf.put_u8(0x80 | (value >> 8) as u8);
        buf.put_u8((value & 0xFF) as u8);
    } else if value <= 0x1F_FFFF {
        buf.put_u8(0xC0 | (value >> 16) as u8);
        buf.put_u8(((value >> 8) & 0xFF) as u8);
        buf.put_u8((value & 0xFF) as u8);
    } else if value <= 0x0FFF_FFFF {
        buf.put_u8(0xE0 | (value >> 24) as u8);
        buf.put_u8(((value >> 16) & 0xFF) as u8);
        buf.put_u8(((value >> 8) & 0xFF) as u8);
        buf.put_u8((value & 0xFF) as u8);
    } else {
        // Saturate: encode maximum 4-byte value.
        buf.put_u8(0xEF);
        buf.put_u8(0xFF);
        buf.put_u8(0xFF);
        buf.put_u8(0xFF);
    }
}

pub fn encode_audio_packet(
    audio: &DecodedAudio,
    context: AudioContext,
    format: PacketFormat,
) -> Bytes {
    match format {
        PacketFormat::Protobuf => encode_audio_protobuf(audio, context),
        PacketFormat::Legacy => encode_audio_legacy(audio, context),
    }
}

fn encode_audio_protobuf(audio: &DecodedAudio, context: AudioContext) -> Bytes {
    let wire = AudioWire {
        // Server→client: always emits the `context` variant of the oneof.
        header: Some(AudioHeader::Context(context)),
        sender_session: audio.sender_session,
        frame_number: audio.frame_number,
        opus_data: audio.opus_data.clone(),
        positional_data: audio.positional_data.clone(),
        volume_adjustment: audio.volume_adjustment,
        is_terminator: audio.is_terminator,
    };

    let total_len = 1 + wire.encoded_len();
    if total_len > 1024 {
        tracing::warn!(
            len = total_len,
            "protobuf voice packet exceeds MAX_UDP_PACKET_SIZE, dropping"
        );
        return Bytes::new();
    }
    let mut buf = BytesMut::with_capacity(total_len);
    buf.put_u8(0x00); // type = Audio
    wire.encode(&mut buf)
        .expect("BytesMut has reserved capacity equal to encoded_len()");
    buf.freeze()
}

fn encode_audio_legacy(audio: &DecodedAudio, context: AudioContext) -> Bytes {
    let context_bits = u32::from(context);
    // The 5-bit legacy header field can hold 0..=31; AudioContext is at most
    // 3, so it always fits — but check defensively in case the enum grows.
    if context_bits >= (1 << 5) {
        tracing::warn!(
            context = context_bits,
            "legacy voice context out of range, dropping"
        );
        return Bytes::new();
    }
    let header = (0x04u8 << 5) | (context_bits as u8 & 0x1f); // VoiceOpus + context

    let positional_len = if audio.positional_data.len() == 3 { 12 } else { 0 };
    let cap = 1 + 4 + 4 + 4 + audio.opus_data.len() + positional_len;

    let mut buf = BytesMut::with_capacity(cap);
    buf.put_u8(header);
    write_varint(&mut buf, audio.sender_session as u64);
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

    if buf.len() > 1024 {
        tracing::warn!(
            len = buf.len(),
            "legacy voice packet exceeds MAX_UDP_PACKET_SIZE, dropping"
        );
        return Bytes::new();
    }
    buf.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Varint encoding ──────────────────────────────────────────────────

    #[test]
    fn varint_roundtrip() {
        // Boundary values for each PacketDataStream encoding tier:
        // 1-byte: 0–127, 2-byte: 128–16383, 3-byte: 16384–2097151, 4-byte: 2097152–268435455
        let test_values = [
            0u64, 1, 127,           // 1-byte boundaries
            128, 255, 16383,        // 2-byte boundaries
            16384, 2097151,         // 3-byte boundaries
            2097152, 268435455,     // 4-byte boundaries
        ];
        for &val in &test_values {
            let mut buf = BytesMut::new();
            write_varint(&mut buf, val);
            let (decoded, n) = read_varint(&buf).expect("read varint");
            assert_eq!(decoded, val, "varint roundtrip for {val}");
            assert_eq!(n, buf.len(), "consumed all bytes for {val}");
        }
    }

    #[test]
    fn varint_differs_from_leb128_at_128() {
        // Confirm the encoding is NOT LEB128: LEB128(128) = [0x80, 0x01],
        // PacketDataStream(128)              = [0x80, 0x80].
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 128);
        assert_eq!(&buf[..], &[0x80, 0x80], "PDS encoding of 128");
    }

    // ── Protobuf codec ───────────────────────────────────────────────────

    #[test]
    fn protobuf_encode_uses_context_oneof() {
        // Server→client packets must carry context, not target.
        let audio = DecodedAudio {
            target: AudioTarget::Normal, // unused — context is the encoder param
            sender_session: 42,
            frame_number: 100,
            opus_data: Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]),
            positional_data: vec![],
            volume_adjustment: 1.0,
            is_terminator: false,
            format: PacketFormat::Protobuf,
        };
        let encoded = encode_audio_packet(&audio, AudioContext::Whisper, PacketFormat::Protobuf);
        assert_eq!(encoded[0], 0x00, "type byte");
        // Parse back: the server-side decoder collapses Context(2) into the
        // AudioTarget enum by raw value — VoiceTarget(2).
        let decoded = decode_audio_packet(&encoded).expect("decode protobuf");
        assert_eq!(decoded.target, AudioTarget::VoiceTarget(2));
        assert_eq!(decoded.sender_session, 42);
        assert_eq!(decoded.frame_number, 100);
        assert_eq!(decoded.format, PacketFormat::Protobuf);
    }

    #[test]
    fn protobuf_volume_normalization() {
        // A packet with no volume_adjustment field (proto3 default = 0.0)
        // must be normalised to 1.0 so downstream code does not mute audio.
        use crate::mumble_udp::{audio, Audio};
        use prost::Message as _;
        let msg = Audio {
            header: Some(audio::Header::Target(0)),
            sender_session: 1,
            frame_number: 0,
            opus_data: Bytes::from_static(&[0x01]),
            positional_data: vec![],
            volume_adjustment: 0.0, // explicitly "unset"
            is_terminator: false,
        };
        let mut buf = BytesMut::with_capacity(1 + msg.encoded_len());
        buf.put_u8(0x00);
        msg.encode(&mut buf).unwrap();
        let decoded = decode_audio_packet(&buf).expect("decode");
        assert_eq!(decoded.volume_adjustment, 1.0, "0.0 must normalise to 1.0");
    }

    #[test]
    fn protobuf_positional_count_validation() {
        use crate::mumble_udp::{audio, Audio};
        use prost::Message as _;
        // 2 floats is invalid — must be rejected.
        let msg = Audio {
            header: Some(audio::Header::Target(0)),
            sender_session: 1,
            frame_number: 0,
            opus_data: Bytes::from_static(&[0x01]),
            positional_data: vec![1.0, 2.0], // invalid: must be 0 or 3
            volume_adjustment: 0.0,
            is_terminator: false,
        };
        let mut buf = BytesMut::with_capacity(1 + msg.encoded_len());
        buf.put_u8(0x00);
        msg.encode(&mut buf).unwrap();
        assert!(
            matches!(decode_audio_packet(&buf), Err(DecodeError::MalformedPacket)),
            "2 positional floats must be rejected"
        );
    }

    // ── Legacy codec ─────────────────────────────────────────────────────

    /// Build a client→server legacy Opus packet (no sender_session).
    fn build_legacy_client_packet(
        target: u32,
        frame_number: u64,
        opus_data: &[u8],
        is_terminator: bool,
    ) -> BytesMut {
        let mut buf = BytesMut::new();
        let header = (0x04u8 << 5) | (target as u8 & 0x1f);
        buf.put_u8(header);
        write_varint(&mut buf, frame_number);
        let size_flag =
            (opus_data.len() as u64 & 0x1FFF) | if is_terminator { 0x2000 } else { 0 };
        write_varint(&mut buf, size_flag);
        buf.extend_from_slice(opus_data);
        buf
    }

    #[test]
    fn legacy_decode_client_to_server() {
        let packet = build_legacy_client_packet(0, 42, &[0x01, 0x02, 0x03], false);
        let decoded = decode_audio_packet(&packet).expect("decode legacy c→s");
        assert_eq!(decoded.target, AudioTarget::Normal);
        assert_eq!(decoded.sender_session, 0); // not present in client→server
        assert_eq!(decoded.frame_number, 42);
        assert_eq!(decoded.opus_data, &[0x01u8, 0x02, 0x03][..]);
        assert!(!decoded.is_terminator);
        assert_eq!(decoded.format, PacketFormat::Legacy);
    }

    #[test]
    fn legacy_decode_terminator() {
        let packet = build_legacy_client_packet(0, 10, &[], true);
        let decoded = decode_audio_packet(&packet).expect("decode terminator");
        assert!(decoded.is_terminator);
        assert_eq!(decoded.opus_data.len(), 0);
    }

    #[test]
    fn legacy_decode_loopback() {
        // target = 31 (loopback): no special position_count field
        let packet = build_legacy_client_packet(31, 1, &[0xAA], false);
        let decoded = decode_audio_packet(&packet).expect("decode loopback");
        assert_eq!(decoded.target, AudioTarget::ServerLoopback);
        assert_eq!(decoded.sender_session, 0);
        assert_eq!(decoded.frame_number, 1);
        assert_eq!(decoded.opus_data, &[0xAAu8][..]);
    }

    #[test]
    fn legacy_encode_server_to_client() {
        // Server→client legacy packets include sender_session.
        let audio = DecodedAudio {
            target: AudioTarget::Normal,
            sender_session: 7,
            frame_number: 42,
            opus_data: Bytes::from_static(&[0x01, 0x02, 0x03]),
            positional_data: Vec::new(),
            volume_adjustment: 1.0,
            is_terminator: false,
            format: PacketFormat::Legacy,
        };
        let encoded = encode_audio_packet(&audio, AudioContext::Normal, PacketFormat::Legacy);
        assert_eq!(encoded[0], 0x80); // Opus (0x04<<5) | target 0
        assert_eq!(encoded[1], 7);    // sender_session = 7 (1-byte PDS varint)
        assert_eq!(encoded[2], 42);   // frame_number = 42
        assert_eq!(encoded[3], 3);    // payload_size = 3, no terminator
        assert_eq!(&encoded[4..], &[0x01u8, 0x02, 0x03]);
    }

    #[test]
    fn legacy_encode_with_positional() {
        let audio = DecodedAudio {
            target: AudioTarget::Normal,
            sender_session: 1,
            frame_number: 0,
            opus_data: Bytes::from_static(&[0xAA]),
            positional_data: vec![1.0_f32, 2.0_f32, 3.0_f32],
            volume_adjustment: 1.0,
            is_terminator: false,
            format: PacketFormat::Legacy,
        };
        let encoded = encode_audio_packet(&audio, AudioContext::Normal, PacketFormat::Legacy);
        // Tail should be three 4-byte little-endian floats
        let tail_start = encoded.len() - 12;
        let x = f32::from_le_bytes(encoded[tail_start..tail_start + 4].try_into().unwrap());
        let y = f32::from_le_bytes(encoded[tail_start + 4..tail_start + 8].try_into().unwrap());
        let z = f32::from_le_bytes(encoded[tail_start + 8..].try_into().unwrap());
        assert_eq!(x, 1.0);
        assert_eq!(y, 2.0);
        assert_eq!(z, 3.0);
    }

    // ── Codec rejection ──────────────────────────────────────────────────

    #[test]
    fn celt_alpha_rejected() {
        // CELTAlpha = top 3 bits 000. Use 0x02 (not 0x00/0x01 which trigger
        // protobuf detection, and not 0x20 which is the legacy Ping marker).
        let packet = [0x02u8, 0x00, 0x00]; // type=CELTAlpha, target=2
        assert!(matches!(
            decode_audio_packet(&packet),
            Err(DecodeError::UnsupportedCodec)
        ));
    }

    #[test]
    fn speex_rejected() {
        let packet = [0x40u8, 0x00, 0x00]; // type=Speex
        assert!(matches!(
            decode_audio_packet(&packet),
            Err(DecodeError::UnsupportedCodec)
        ));
    }

    #[test]
    fn celt_beta_rejected() {
        let packet = [0x60u8, 0x00, 0x00]; // type=CELTBeta
        assert!(matches!(
            decode_audio_packet(&packet),
            Err(DecodeError::UnsupportedCodec)
        ));
    }

    // ── Format detection ─────────────────────────────────────────────────

    #[test]
    fn detect_protobuf_format() {
        let audio = DecodedAudio {
            target: AudioTarget::Normal,
            sender_session: 1,
            frame_number: 0,
            opus_data: Bytes::from_static(&[0x00]),
            positional_data: Vec::new(),
            volume_adjustment: 1.0,
            is_terminator: false,
            format: PacketFormat::Protobuf,
        };
        let encoded = encode_audio_packet(&audio, AudioContext::Normal, PacketFormat::Protobuf);
        let decoded = decode_audio_packet(&encoded).expect("decode");
        assert_eq!(decoded.format, PacketFormat::Protobuf);
    }

    #[test]
    fn detect_legacy_format() {
        let packet = build_legacy_client_packet(0, 0, &[0x00], false);
        let decoded = decode_audio_packet(&packet).expect("decode");
        assert_eq!(decoded.format, PacketFormat::Legacy);
    }

    // ── Edge cases ───────────────────────────────────────────────────────

    #[test]
    fn empty_packet() {
        assert!(decode_audio_packet(&[]).is_err());
    }

    #[test]
    fn ping_not_voice() {
        // Protobuf ping: first byte 0x01
        assert!(matches!(
            decode_audio_packet(&[0x01, 0x00]),
            Err(DecodeError::NotVoice)
        ));
        // Legacy ping: type bits 001 → 0x20
        assert!(matches!(
            decode_audio_packet(&[0x20, 0x00]),
            Err(DecodeError::NotVoice)
        ));
    }

    #[test]
    fn unknown_type() {
        assert!(matches!(
            decode_audio_packet(&[0xFF]),
            Err(DecodeError::NotVoice)
        ));
    }

    // ── Varint edge cases ────────────────────────────────────────────────

    #[test]
    fn varint_truncated_returns_none() {
        // 2-byte form needs 2 bytes; truncated at 1 must fail.
        assert!(read_varint(&[0x80]).is_none());
        // 3-byte form needs 3 bytes; truncated at 2 must fail.
        assert!(read_varint(&[0xC0, 0x00]).is_none());
        // 4-byte form needs 4 bytes; truncated at 3 must fail.
        assert!(read_varint(&[0xE0, 0x00, 0x00]).is_none());
    }

    #[test]
    fn varint_special_byte_returns_none() {
        // 0xF0–0xFF are special/negative forms rejected in voice packets.
        assert!(read_varint(&[0xF0]).is_none());
        assert!(read_varint(&[0xF8, 0x00, 0x00, 0x00, 0x00]).is_none());
        assert!(read_varint(&[0xFF]).is_none());
    }

    #[test]
    fn varint_three_and_four_byte_roundtrip() {
        // Explicit byte-level check for 3-byte and 4-byte boundaries.
        // 3-byte: 0xC0 | (value >> 16), middle byte, low byte
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 16384); // smallest 3-byte value
        assert_eq!(&buf[..], &[0xC0, 0x40, 0x00]);
        let (decoded, n) = read_varint(&buf).unwrap();
        assert_eq!((decoded, n), (16384, 3));

        buf.clear();
        write_varint(&mut buf, 2097151); // largest 3-byte value
        let (decoded, _) = read_varint(&buf).unwrap();
        assert_eq!(decoded, 2097151);

        // 4-byte: 0xE0 | (value >> 24), then three more bytes
        buf.clear();
        write_varint(&mut buf, 2097152); // smallest 4-byte value
        assert_eq!(buf.len(), 4);
        let (decoded, n) = read_varint(&buf).unwrap();
        assert_eq!((decoded, n), (2097152, 4));
    }

    // ── Legacy decode additional ─────────────────────────────────────────

    #[test]
    fn legacy_decode_with_positional_data() {
        let mut packet = build_legacy_client_packet(0, 1, &[0xAA, 0xBB], false);
        packet.extend_from_slice(&1.5f32.to_le_bytes());
        packet.extend_from_slice(&2.5f32.to_le_bytes());
        packet.extend_from_slice(&3.5f32.to_le_bytes());
        let decoded = decode_audio_packet(&packet).expect("decode with positional");
        assert_eq!(decoded.positional_data, vec![1.5f32, 2.5, 3.5]);
        assert_eq!(&decoded.opus_data[..], &[0xAAu8, 0xBB][..]);
    }

    #[test]
    fn legacy_decode_whisper_target() {
        let packet = build_legacy_client_packet(15, 0, &[0x01], false);
        let decoded = decode_audio_packet(&packet).expect("decode whisper target");
        assert_eq!(decoded.target, AudioTarget::VoiceTarget(15));
    }

    #[test]
    fn legacy_decode_large_frame_number() {
        // frame_number=128 requires a 2-byte PDS varint [0x80, 0x80].
        let packet = build_legacy_client_packet(0, 128, &[0x01], false);
        let decoded = decode_audio_packet(&packet).expect("decode large frame_number");
        assert_eq!(decoded.frame_number, 128);
    }

    #[test]
    fn legacy_decode_invalid_trailing_bytes() {
        // Trailing bytes that are neither 0 nor 12 bytes → LegacyDecode.
        let mut packet = build_legacy_client_packet(0, 0, &[0x01], false);
        packet.extend_from_slice(&[0xFF, 0xFF]); // 2 stray bytes after payload
        assert!(matches!(
            decode_audio_packet(&packet),
            Err(DecodeError::LegacyDecode)
        ));
    }

    // ── Legacy encode additional ─────────────────────────────────────────

    #[test]
    fn legacy_encode_terminator_sets_flag() {
        // is_terminator must set bit 0x2000 in the payload-size varint.
        // Server→client packet: sender_session=0 and frame_number=0 are both 1-byte varints,
        // so the size_flag varint starts at encoded[3].
        let audio = DecodedAudio {
            target: AudioTarget::Normal,
            sender_session: 0,
            frame_number: 0,
            opus_data: Bytes::new(),
            positional_data: vec![],
            volume_adjustment: 1.0,
            is_terminator: true,
            format: PacketFormat::Legacy,
        };
        let encoded = encode_audio_packet(&audio, AudioContext::Normal, PacketFormat::Legacy);
        // Skip header(1) + sender_session varint(1) + frame_number varint(1).
        let (size_flag, _) = read_varint(&encoded[3..]).expect("read size_flag");
        assert!(size_flag & 0x2000 != 0, "terminator bit must be set");
    }

    // ── Protobuf decode additional ────────────────────────────────────────

    #[test]
    fn protobuf_decode_three_positional_valid() {
        use crate::mumble_udp::{audio, Audio};
        use prost::Message as _;
        let msg = Audio {
            header: Some(audio::Header::Target(0)),
            sender_session: 1,
            frame_number: 0,
            opus_data: Bytes::from_static(&[0x01]),
            positional_data: vec![1.0, 2.0, 3.0],
            volume_adjustment: 1.0,
            is_terminator: false,
        };
        let mut buf = BytesMut::with_capacity(1 + msg.encoded_len());
        buf.put_u8(0x00);
        msg.encode(&mut buf).unwrap();
        let decoded = decode_audio_packet(&buf).expect("3 positional floats must be valid");
        assert_eq!(decoded.positional_data, vec![1.0f32, 2.0, 3.0]);
    }

    #[test]
    fn protobuf_decode_one_positional_invalid() {
        use crate::mumble_udp::{audio, Audio};
        use prost::Message as _;
        let msg = Audio {
            header: Some(audio::Header::Target(0)),
            sender_session: 1,
            frame_number: 0,
            opus_data: Bytes::from_static(&[0x01]),
            positional_data: vec![1.0],
            volume_adjustment: 1.0,
            is_terminator: false,
        };
        let mut buf = BytesMut::with_capacity(1 + msg.encoded_len());
        buf.put_u8(0x00);
        msg.encode(&mut buf).unwrap();
        assert!(matches!(
            decode_audio_packet(&buf),
            Err(DecodeError::MalformedPacket)
        ));
    }

    #[test]
    fn protobuf_decode_four_positional_invalid() {
        use crate::mumble_udp::{audio, Audio};
        use prost::Message as _;
        let msg = Audio {
            header: Some(audio::Header::Target(0)),
            sender_session: 1,
            frame_number: 0,
            opus_data: Bytes::from_static(&[0x01]),
            positional_data: vec![1.0, 2.0, 3.0, 4.0],
            volume_adjustment: 1.0,
            is_terminator: false,
        };
        let mut buf = BytesMut::with_capacity(1 + msg.encoded_len());
        buf.put_u8(0x00);
        msg.encode(&mut buf).unwrap();
        assert!(matches!(
            decode_audio_packet(&buf),
            Err(DecodeError::MalformedPacket)
        ));
    }

    #[test]
    fn protobuf_decode_volume_nonzero_passthrough() {
        // A non-zero volume_adjustment must pass through unchanged (not clamped to 1.0).
        use crate::mumble_udp::{audio, Audio};
        use prost::Message as _;
        let msg = Audio {
            header: Some(audio::Header::Target(0)),
            sender_session: 1,
            frame_number: 0,
            opus_data: Bytes::from_static(&[0x01]),
            positional_data: vec![],
            volume_adjustment: 0.5,
            is_terminator: false,
        };
        let mut buf = BytesMut::with_capacity(1 + msg.encoded_len());
        buf.put_u8(0x00);
        msg.encode(&mut buf).unwrap();
        let decoded = decode_audio_packet(&buf).expect("decode");
        assert_eq!(decoded.volume_adjustment, 0.5);
    }

    #[test]
    fn protobuf_decode_no_header_gives_zero_target() {
        // Missing header oneof defaults to target = 0.
        use crate::mumble_udp::Audio;
        use prost::Message as _;
        let msg = Audio {
            header: None,
            sender_session: 1,
            frame_number: 0,
            opus_data: Bytes::from_static(&[0x01]),
            positional_data: vec![],
            volume_adjustment: 1.0,
            is_terminator: false,
        };
        let mut buf = BytesMut::with_capacity(1 + msg.encoded_len());
        buf.put_u8(0x00);
        msg.encode(&mut buf).unwrap();
        let decoded = decode_audio_packet(&buf).expect("decode");
        assert_eq!(decoded.target, AudioTarget::Normal);
    }

    // ── Size limits ───────────────────────────────────────────────────────

    #[test]
    fn protobuf_encode_oversized_returns_empty() {
        let audio = DecodedAudio {
            target: AudioTarget::Normal,
            sender_session: 1,
            frame_number: 0,
            opus_data: Bytes::from(vec![0xAA; 2000]),
            positional_data: vec![],
            volume_adjustment: 1.0,
            is_terminator: false,
            format: PacketFormat::Protobuf,
        };
        let encoded = encode_audio_packet(&audio, AudioContext::Normal, PacketFormat::Protobuf);
        assert!(encoded.is_empty(), "oversized protobuf packet must be dropped");
    }

    #[test]
    fn legacy_encode_oversized_returns_empty() {
        let audio = DecodedAudio {
            target: AudioTarget::Normal,
            sender_session: 1,
            frame_number: 0,
            opus_data: Bytes::from(vec![0xBB; 2000]),
            positional_data: vec![],
            volume_adjustment: 1.0,
            is_terminator: false,
            format: PacketFormat::Legacy,
        };
        let encoded = encode_audio_packet(&audio, AudioContext::Normal, PacketFormat::Legacy);
        assert!(encoded.is_empty(), "oversized legacy packet must be dropped");
    }

    // ── decode_udp_packet ────────────────────────────────────────────────

    #[test]
    fn udp_packet_protobuf_audio() {
        let audio = DecodedAudio {
            target: AudioTarget::Normal,
            sender_session: 5,
            frame_number: 7,
            opus_data: Bytes::from_static(&[0x01, 0x02]),
            positional_data: vec![],
            volume_adjustment: 1.0,
            is_terminator: false,
            format: PacketFormat::Protobuf,
        };
        let encoded = encode_audio_packet(&audio, AudioContext::Normal, PacketFormat::Protobuf);
        let packet = decode_udp_packet(&encoded).expect("decode protobuf audio");
        let UdpPacket::Audio(a) = packet else { panic!("expected Audio") };
        assert_eq!(a.frame_number, 7);
        assert_eq!(a.format, PacketFormat::Protobuf);
    }

    #[test]
    fn udp_packet_legacy_opus() {
        let raw = build_legacy_client_packet(0, 3, &[0x01, 0x02], false);
        let packet = decode_udp_packet(&raw).expect("decode legacy audio");
        let UdpPacket::Audio(a) = packet else { panic!("expected Audio") };
        assert_eq!(a.frame_number, 3);
        assert_eq!(a.format, PacketFormat::Legacy);
    }

    #[test]
    fn udp_packet_celt_rejected() {
        // CELTAlpha type bits (top 3 = 000): use 0x02 to avoid the protobuf 0x00 path.
        let raw = [0x02u8, 0x00, 0x00];
        assert!(matches!(
            decode_udp_packet(&raw),
            Err(DecodeError::UnsupportedCodec)
        ));
    }

    #[test]
    fn udp_packet_malformed_packet_propagated() {
        // Valid protobuf bytes but invalid positional count must propagate MalformedPacket,
        // not silently fall through to the legacy decoder.
        use crate::mumble_udp::{audio, Audio};
        use prost::Message as _;
        let msg = Audio {
            header: Some(audio::Header::Target(0)),
            sender_session: 1,
            frame_number: 0,
            opus_data: Bytes::from_static(&[0x01]),
            positional_data: vec![1.0, 2.0], // invalid: 2 floats
            volume_adjustment: 1.0,
            is_terminator: false,
        };
        let mut buf = BytesMut::with_capacity(1 + msg.encoded_len());
        buf.put_u8(0x00);
        msg.encode(&mut buf).unwrap();
        assert!(matches!(
            decode_udp_packet(&buf),
            Err(DecodeError::MalformedPacket)
        ));
    }
}
