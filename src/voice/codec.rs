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

use std::{fmt::Display, io::Cursor};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use prost::Message as _;

use crate::{
    client::client_session_identifier::ClientSessionIdentifier,
    messages::encoder::{Audio as AudioWire, AudioContext, AudioHeader, AudioTarget},
};

// ── Core types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpusPayload {
    pub frame: Bytes,
    pub is_terminator: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioPayload {
    CELTAlpha(Bytes),
    CELTBeta(Bytes),
    Speex(Bytes),
    Opus(OpusPayload),
}

impl AudioPayload {
    pub fn len(&self) -> usize {
        match self {
            AudioPayload::CELTAlpha(b) | AudioPayload::CELTBeta(b) | AudioPayload::Speex(b) => {
                b.len()
            }
            AudioPayload::Opus(p) => p.frame.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Size of this payload as encoded on the legacy wire: `varint(size_flag) + frame bytes`.
    /// For Opus the size flag includes the terminator bit (`0x2000`); for CELT/Speex it
    /// is plain frame length.
    pub fn len_legacy(&self) -> usize {
        match self {
            AudioPayload::CELTAlpha(b) | AudioPayload::CELTBeta(b) | AudioPayload::Speex(b) => {
                b.len()
            }
            AudioPayload::Opus(p) => {
                let flag = p.frame.len() as u32 | if p.is_terminator { 0x2000 } else { 0 };
                let frame_len = p.frame.len();
                varint_encoded_len(flag) + frame_len
            }
        }
    }

    /// Write this payload into `buf` using legacy wire encoding.
    /// Opus: `varint(size_flag) + frame`. CELT/Speex: raw bytes verbatim.
    pub fn write_legacy_into(&self, buf: &mut impl BufMut) {
        match self {
            AudioPayload::Opus(p) => {
                let size_flag =
                    (p.frame.len() as u32 & 0x1FFF) | if p.is_terminator { 0x2000 } else { 0 };
                write_varint_buf(buf, size_flag);
                buf.put_slice(&p.frame);
            }
            AudioPayload::CELTAlpha(b) | AudioPayload::CELTBeta(b) | AudioPayload::Speex(b) => {
                buf.put_slice(b);
            }
        }
    }
}

/// The decoded result of a UDP voice packet.
#[derive(Debug, Clone, PartialEq)]
pub struct Audio {
    /// Routing target carried by the inbound packet. For server→client packets
    /// reconstructed from a `Audio` (e.g. server loopback), this field
    /// is unused at the wire boundary — the caller of `Audio::encode`
    /// supplies an `AudioContext` separately.
    pub target: AudioTarget,
    /// Sender session ID. Zero for client→server (not present on wire).
    pub sender_session: Option<ClientSessionIdentifier>,
    /// Frame number (sequence).
    pub frame_number: u64,
    /// Audio payload.
    pub audio_payload: AudioPayload,
    /// Optional positional data [x, y, z] in metres. Empty or exactly 3 elements.
    pub positional_data: Option<[f32; 3]>,
    /// Volume adjustment factor (1.0 = no adjustment).
    pub volume_adjustment: f32,
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
    /// Unexpected legacy message type (not a voice codec).
    NotVoice,
    /// Legacy codec (CELT-α, CELT-β, Speex) — not supported by this server.
    UnsupportedCodec,
    /// Failed to decode protobuf.
    ProtobufDecode(prost::DecodeError),
    /// Failed to decode legacy varint fields.
    UnparsableVarIntValue,
    /// Not a ping
    NotPing,
    /// Packet structure is valid but contains invalid field values.
    MalformedPacket,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::TooShort => write!(f, "packet too short"),
            DecodeError::NotVoice => write!(f, "not a voice packet"),
            DecodeError::UnsupportedCodec => {
                write!(f, "unsupported codec (only Opus is supported)")
            }
            DecodeError::ProtobufDecode(e) => write!(f, "protobuf decode error: {e}"),
            DecodeError::UnparsableVarIntValue => write!(f, "unparsable varint value"),
            DecodeError::NotPing => write!(f, "not a ping packet"),
            DecodeError::MalformedPacket => write!(f, "malformed packet"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyUdpMessageType {
    VoiceCELTAlpha = 0,
    Ping = 1,
    VoiceSpeex = 2,
    VoiceCELTBeta = 3,
    VoiceOpus = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidLegacyUdpMessageType(pub u8);

impl Display for InvalidLegacyUdpMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid legacy UDP message type: {}", self.0)
    }
}

impl std::error::Error for InvalidLegacyUdpMessageType {}

impl TryFrom<u8> for LegacyUdpMessageType {
    type Error = InvalidLegacyUdpMessageType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LegacyUdpMessageType::VoiceCELTAlpha),
            1 => Ok(LegacyUdpMessageType::Ping),
            2 => Ok(LegacyUdpMessageType::VoiceSpeex),
            3 => Ok(LegacyUdpMessageType::VoiceCELTBeta),
            4 => Ok(LegacyUdpMessageType::VoiceOpus),
            _ => Err(InvalidLegacyUdpMessageType(value)),
        }
    }
}

impl Into<u8> for LegacyUdpMessageType {
    fn into(self) -> u8 {
        self as u8
    }
}

impl From<AudioPayload> for LegacyUdpMessageType {
    fn from(value: AudioPayload) -> Self {
        match value {
            AudioPayload::CELTAlpha(_) => LegacyUdpMessageType::VoiceCELTAlpha,
            AudioPayload::CELTBeta(_) => LegacyUdpMessageType::VoiceCELTBeta,
            AudioPayload::Speex(_) => LegacyUdpMessageType::VoiceSpeex,
            AudioPayload::Opus(_) => LegacyUdpMessageType::VoiceOpus,
        }
    }
}

impl From<&AudioPayload> for LegacyUdpMessageType {
    fn from(value: &AudioPayload) -> Self {
        match value {
            AudioPayload::CELTAlpha(_) => LegacyUdpMessageType::VoiceCELTAlpha,
            AudioPayload::CELTBeta(_) => LegacyUdpMessageType::VoiceCELTBeta,
            AudioPayload::Speex(_) => LegacyUdpMessageType::VoiceSpeex,
            AudioPayload::Opus(_) => LegacyUdpMessageType::VoiceOpus,
        }
    }
}

/// The type of UDP packet received.
#[derive(Debug, Clone)]
pub enum IncomingUdpPacket {
    Audio(Audio),
    Ping(super::ping::PingRequest),
}

// ── Varint helpers ────────────────────────────────────────────────────────────

/// Read a Mumble PacketDataStream varint from `data`.
///
/// Returns `(value, bytes_consumed)` or `None` on truncation or unsupported
/// encoding (0xF0–0xFF: special/negative forms not used in voice packets).
pub(super) fn read_varint_slice(data: &[u8]) -> Option<(u32, usize)> {
    let c = *data.first()? as u32;
    if c & 0x80 == 0 {
        // 0x00–0x7F: 1 byte, 7-bit value
        Some((c, 1))
    } else if c & 0x40 == 0 {
        // 0x80–0xBF: 2 bytes, 14-bit value
        let b1 = *data.get(1)? as u32;
        Some(((c & 0x3F) << 8 | b1, 2))
    } else if c & 0x20 == 0 {
        // 0xC0–0xDF: 3 bytes, 21-bit value
        let b1 = *data.get(1)? as u32;
        let b2 = *data.get(2)? as u32;
        Some(((c & 0x1F) << 16 | b1 << 8 | b2, 3))
    } else if c & 0x10 == 0 {
        // 0xE0–0xEF: 4 bytes, 28-bit value
        let b1 = *data.get(1)? as u32;
        let b2 = *data.get(2)? as u32;
        let b3 = *data.get(3)? as u32;
        Some(((c & 0x0F) << 24 | b1 << 16 | b2 << 8 | b3, 4))
    } else {
        // 0xF0–0xFF: special/negative forms — not emitted by voice packets
        None
    }
}

/// Read a Mumble PacketDataStream varint from `data`, advancing the cursor by
/// the number of bytes consumed.
///
/// Returns `None` on truncation or unsupported encoding (0xF0–0xFF). On
/// `None` the cursor position is left unchanged.
pub fn read_varint(data: &mut Cursor<&[u8]>) -> Option<u32> {
    let pos = data.position() as usize;
    let remaining = data.get_ref().get(pos..)?;
    let (value, n) = read_varint_slice(remaining)?;
    data.set_position((pos + n) as u64);
    Some(value)
}

fn write_varint_buf(buf: &mut impl BufMut, value: u32) {
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
        buf.put_u8(0xEF);
        buf.put_u8(0xFF);
        buf.put_u8(0xFF);
        buf.put_u8(0xFF);
    }
}

/// Number of bytes required to encode `value` as a Mumble PDS varint.
fn varint_encoded_len(value: u32) -> usize {
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

// ── Public helpers ────────────────────────────────────────────────────────────

// ── UdpPacket impl ────────────────────────────────────────────────────────────

impl IncomingUdpPacket {
    /// Decode any UDP packet, returning either Audio or Ping.
    ///
    /// Tries protobuf format first (detected by first byte `0x00` or `0x01`).
    /// Falls back to legacy format for other first-byte values.
    ///
    /// `from_session` is passed to the audio decoder and used as the
    /// authoritative sender identity, overriding any session carried on the wire.
    pub fn decode(
        data: &[u8],
        from_session: Option<ClientSessionIdentifier>,
    ) -> Result<IncomingUdpPacket, DecodeError> {
        if data.is_empty() {
            return Err(DecodeError::TooShort);
        }

        // Protobuf ping has an unambiguous one-byte type header.
        if data[0] == 0x01 {
            if let Ok(packet) = Self::try_decode_protobuf(data, from_session) {
                return Ok(packet);
            }
        }

        // Legacy pings can appear without header (12/24 bytes).
        if data.len() == 12 || data.len() == 24 {
            if let Ok(ping) = super::ping::PingRequest::decode_legacy(data) {
                return Ok(IncomingUdpPacket::Ping(ping));
            }
        }

        // Protobuf audio (0x00) overlaps legacy CELTAlpha (type bits 000).
        // Try protobuf first; propagate any domain error (MalformedPacket, etc.)
        // but fall through to legacy only when the bytes simply aren't valid protobuf.
        if data[0] == 0x00 {
            match Self::try_decode_protobuf(data, from_session) {
                Ok(packet) => return Ok(packet),
                Err(DecodeError::ProtobufDecode(_)) | Err(DecodeError::NotVoice) => {}
                Err(e) => return Err(e),
            }
        }

        // Legacy format: message type in top 3 bits of first header byte.
        let legacy_type = (data[0] >> 5) & 0x07;
        match legacy_type {
            0 | 2 | 3 => Err(DecodeError::UnsupportedCodec), // CELTAlpha, Speex, CELTBeta
            1 => Ok(IncomingUdpPacket::Ping(
                super::ping::PingRequest::decode_legacy(&data[1..])?,
            )),
            4 => Ok(IncomingUdpPacket::Audio(Audio::decode_legacy(
                data,
                from_session,
            )?)),
            _ => Err(DecodeError::NotVoice),
        }
    }

    /// Try to decode as protobuf. Returns `Err` if it is not actually protobuf.
    fn try_decode_protobuf(
        data: &[u8],
        from_session: Option<ClientSessionIdentifier>,
    ) -> Result<IncomingUdpPacket, DecodeError> {
        match data[0] {
            0x00 => Ok(IncomingUdpPacket::Audio(Audio::decode_protobuf(
                &data[1..],
                from_session,
            )?)),
            0x01 => Ok(IncomingUdpPacket::Ping(
                super::ping::PingRequest::decode_protobuf(&data[1..])?,
            )),
            _ => Err(DecodeError::NotVoice),
        }
    }
}

// ── Audio impl ────────────────────────────────────────────────────────────────

impl Audio {
    /// Decode a UDP voice packet, auto-detecting legacy vs protobuf format.
    ///
    /// Used for TCP-tunnelled voice (UDPTunnel message). Pings are rejected.
    ///
    /// `from_session` is used as the authoritative sender identity: for protobuf
    /// packets it overrides the session carried on the wire; for legacy packets
    /// (which carry no session in the client→server direction) it is used directly.
    pub fn decode(
        data: &[u8],
        from_session: Option<ClientSessionIdentifier>,
    ) -> Result<Self, DecodeError> {
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
            match Self::decode_protobuf(&data[1..], from_session) {
                Ok(audio) => return Ok(audio),
                Err(DecodeError::ProtobufDecode(_)) => {}
                Err(e) => return Err(e),
            }
        }

        // Legacy format: message type in top 3 bits of first header byte.
        let legacy_type = (data[0] >> 5) & 0x07;
        match legacy_type {
            0 | 2 | 3 | 4 => Self::decode_legacy(data, from_session),
            1 => Err(DecodeError::NotVoice), // legacy ping byte
            _ => Err(DecodeError::NotVoice),
        }
    }

    /// Decode a protobuf-encoded Audio packet (`data` is the bytes after the type byte).
    ///
    /// Delegates the protobuf parse to the encoder wrapper so the wire-level
    /// `mumble_udp::Audio` type is contained there. The server is permissive about
    /// which `oneof Header` variant the client sent — both `target` and `context`
    /// are collapsed to `AudioTarget` by the wrapper.
    fn decode_protobuf(
        data: &[u8],
        from_session: Option<ClientSessionIdentifier>,
    ) -> Result<Self, DecodeError> {
        let audio = AudioWire::decode_wire(data).map_err(|e| match e {
            crate::messages::encoder::AudioWireError::Protobuf(e) => DecodeError::ProtobufDecode(e),
            crate::messages::encoder::AudioWireError::Domain(_) => DecodeError::MalformedPacket,
            crate::messages::encoder::AudioWireError::EncodeOverflow(_) => {
                DecodeError::MalformedPacket
            }
        })?;

        // Caller-supplied identity takes precedence over the wire field.
        let sender_session = from_session.or_else(|| {
            if audio.sender_session == 0 {
                None
            } else {
                Some(ClientSessionIdentifier::from(audio.sender_session))
            }
        });

        let target = match audio.header {
            Some(AudioHeader::Target(t)) => t,
            // Server is permissive: accept Context the client (incorrectly) sent
            // and treat its value as a routing target.
            Some(AudioHeader::Context(c)) => AudioTarget::from(u32::from(c)),
            None => AudioTarget::Normal,
        };

        let positional_data: Option<[f32; 3]> = match audio.positional_data.as_slice() {
            [] => None,
            &[x, y, z] => Some([x, y, z]),
            _ => return Err(DecodeError::MalformedPacket),
        };

        Ok(Audio {
            target,
            sender_session,
            frame_number: audio.frame_number,
            audio_payload: AudioPayload::Opus(OpusPayload {
                frame: audio.opus_data,
                is_terminator: audio.is_terminator,
            }),
            positional_data,
            // proto3 default 0.0 means the field is unset; normalise to 1.0 (no-op gain)
            // so downstream code never multiplies audio samples by zero.
            volume_adjustment: if audio.volume_adjustment == 0.0 {
                1.0
            } else {
                audio.volume_adjustment
            },
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
    fn decode_legacy(
        data: &[u8],
        from_session: Option<ClientSessionIdentifier>,
    ) -> Result<Self, DecodeError> {
        if data.len() < 2 {
            return Err(DecodeError::TooShort);
        }

        let mut data_reader = Cursor::new(data);

        let header = data_reader.get_u8();
        let udp_message_type = LegacyUdpMessageType::try_from((header & 0xe0) >> 5)
            .map_err(|_| DecodeError::NotVoice)?;
        let target = AudioTarget::from(header & 0x1f);

        if udp_message_type == LegacyUdpMessageType::Ping {
            return Err(DecodeError::NotVoice);
        }

        let frame_number =
            read_varint(&mut data_reader).ok_or(DecodeError::UnparsableVarIntValue)? as u64;

        let audio_payload = match udp_message_type {
            LegacyUdpMessageType::VoiceCELTAlpha
            | LegacyUdpMessageType::VoiceCELTBeta
            | LegacyUdpMessageType::VoiceSpeex => {
                // Length-prefixed frames: bit 7 = continuation, bits 0-6 = length.
                // Walk the chain only to find where the payload section ends; the
                // bytes (headers included) are forwarded verbatim.
                let start = data_reader.position() as usize;
                loop {
                    if !data_reader.has_remaining() {
                        return Err(DecodeError::MalformedPacket);
                    }
                    let header = data_reader.get_u8();
                    let length = (header & 0x7f) as usize;
                    let continuation = (header & 0x80) != 0;

                    if length > 0 {
                        if data_reader.remaining() < length {
                            return Err(DecodeError::MalformedPacket);
                        }
                        data_reader.advance(length);
                    }

                    if !continuation {
                        break;
                    }
                }
                let end = data_reader.position() as usize;
                let frame = Bytes::copy_from_slice(&data[start..end]);
                match udp_message_type {
                    LegacyUdpMessageType::VoiceCELTAlpha => AudioPayload::CELTAlpha(frame),
                    LegacyUdpMessageType::VoiceSpeex => AudioPayload::Speex(frame),
                    LegacyUdpMessageType::VoiceCELTBeta => AudioPayload::CELTBeta(frame),
                    _ => unreachable!(),
                }
            }
            LegacyUdpMessageType::VoiceOpus => {
                let size_flag =
                    read_varint(&mut data_reader).ok_or(DecodeError::UnparsableVarIntValue)?;
                let payload_size = (size_flag & 0x1FFF) as usize;
                let is_terminator = (size_flag & 0x2000) != 0;

                if data_reader.remaining() < payload_size {
                    return Err(DecodeError::MalformedPacket);
                }

                let frame = data_reader.copy_to_bytes(payload_size);
                AudioPayload::Opus(OpusPayload {
                    frame,
                    is_terminator,
                })
            }
            LegacyUdpMessageType::Ping => return Err(DecodeError::NotVoice),
        };

        let positional_data: Option<[f32; 3]> = match data_reader.remaining() {
            0 => None,
            12 => Some([
                data_reader.get_f32_ne(),
                data_reader.get_f32_ne(),
                data_reader.get_f32_ne(),
            ]),
            _ => return Err(DecodeError::MalformedPacket),
        };

        Ok(Audio {
            target,
            sender_session: from_session,
            frame_number,
            audio_payload,
            positional_data,
            volume_adjustment: 1.0,
            format: PacketFormat::Legacy,
        })
    }

    pub fn encode(&self, context: AudioContext, format: PacketFormat) -> Bytes {
        match format {
            PacketFormat::Protobuf => self.encode_protobuf(context),
            PacketFormat::Legacy => self.encode_legacy(context),
        }
    }

    fn encode_protobuf(&self, context: AudioContext) -> Bytes {
        // Protobuf wire format only carries Opus frames.
        let opus = match &self.audio_payload {
            AudioPayload::Opus(p) => p,
            AudioPayload::CELTAlpha(_) | AudioPayload::CELTBeta(_) | AudioPayload::Speex(_) => {
                tracing::warn!(
                    "non-Opus payload cannot be encoded as protobuf voice packet, dropping"
                );
                return Bytes::new();
            }
        };
        let positional_data = match self.positional_data {
            Some([x, y, z]) => vec![x, y, z],
            None => Vec::new(),
        };
        let wire = AudioWire {
            // Server→client: always emits the `context` variant of the oneof.
            header: Some(AudioHeader::Context(context)),
            sender_session: self.sender_session.map(u32::from).unwrap_or(0),
            frame_number: self.frame_number,
            opus_data: opus.frame.clone(),
            positional_data,
            volume_adjustment: self.volume_adjustment,
            is_terminator: opus.is_terminator,
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

    fn encode_legacy(&self, context: AudioContext) -> Bytes {
        let message_type: u8 = LegacyUdpMessageType::from(&self.audio_payload).into();
        let target: u8 = self.target.into();
        let header = (message_type << 5) | (target & 0x1f);

        let payload_len = self.audio_payload.len_legacy();
        let positional_len = if self.positional_data.is_some() {
            12
        } else {
            0
        };

        let cap = 1 + 4 + 4 + payload_len + positional_len;

        let mut buf = BytesMut::with_capacity(cap);
        buf.put_u8(header);
        write_varint_buf(&mut buf, self.sender_session.map(u32::from).unwrap_or(0));
        write_varint_buf(&mut buf, self.frame_number as u32);

        self.audio_payload.write_legacy_into(&mut buf);

        if let Some([x, y, z]) = self.positional_data {
            buf.put_f32_ne(x);
            buf.put_f32_ne(y);
            buf.put_f32_ne(z);
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
            0u32, 1, 127, // 1-byte boundaries
            128, 255, 16383, // 2-byte boundaries
            16384, 2097151, // 3-byte boundaries
            2097152, 268435455, // 4-byte boundaries
        ];
        for &val in &test_values {
            let mut buf = BytesMut::new();
            write_varint_buf(&mut buf, val);
            let (decoded, n) = read_varint_slice(&buf).expect("read varint");
            assert_eq!(decoded, val, "varint roundtrip for {val}");
            assert_eq!(n, buf.len(), "consumed all bytes for {val}");
        }
    }

    #[test]
    fn varint_differs_from_leb128_at_128() {
        // Confirm the encoding is NOT LEB128: LEB128(128) = [0x80, 0x01],
        // PacketDataStream(128)              = [0x80, 0x80].
        let mut buf = BytesMut::new();
        write_varint_buf(&mut buf, 128);
        assert_eq!(&buf[..], &[0x80, 0x80], "PDS encoding of 128");
    }

    // ── Protobuf codec ───────────────────────────────────────────────────

    #[test]
    fn protobuf_encode_uses_context_oneof() {
        // Server→client packets must carry context, not target.
        let audio = Audio {
            target: AudioTarget::Normal, // unused — context is the encoder param
            sender_session: Some(ClientSessionIdentifier::from(42)),
            frame_number: 100,
            audio_payload: AudioPayload::Opus(OpusPayload {
                frame: Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]),
                is_terminator: false,
            }),
            positional_data: None,
            volume_adjustment: 1.0,
            format: PacketFormat::Protobuf,
        };
        let encoded = audio.encode(AudioContext::Whisper, PacketFormat::Protobuf);
        assert_eq!(encoded[0], 0x00, "type byte");
        // Parse back: the server-side decoder collapses Context(2) into the
        // AudioTarget enum by raw value — VoiceTarget(2).
        let decoded = Audio::decode(&encoded, None).expect("decode protobuf");
        assert_eq!(decoded.target, AudioTarget::VoiceTarget(2));
        assert_eq!(
            decoded.sender_session,
            Some(ClientSessionIdentifier::from(42))
        );
        assert_eq!(decoded.frame_number, 100);
        assert_eq!(decoded.format, PacketFormat::Protobuf);
    }

    #[test]
    fn protobuf_volume_normalization() {
        // A packet with no volume_adjustment field (proto3 default = 0.0)
        // must be normalised to 1.0 so downstream code does not mute audio.
        use crate::mumble_udp::{Audio as WireAudio, audio};
        use prost::Message as _;
        let msg = WireAudio {
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
        let decoded = Audio::decode(&buf, None).expect("decode");
        assert_eq!(decoded.volume_adjustment, 1.0, "0.0 must normalise to 1.0");
    }

    #[test]
    fn protobuf_positional_count_validation() {
        use crate::mumble_udp::{Audio as WireAudio, audio};
        use prost::Message as _;
        // 2 floats is invalid — must be rejected.
        let msg = WireAudio {
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
            matches!(Audio::decode(&buf, None), Err(DecodeError::MalformedPacket)),
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
        write_varint_buf(&mut buf, frame_number as u32);
        let size_flag = (opus_data.len() as u32 & 0x1FFF) | if is_terminator { 0x2000 } else { 0 };
        write_varint_buf(&mut buf, size_flag);
        buf.extend_from_slice(opus_data);
        buf
    }

    #[test]
    fn legacy_decode_client_to_server() {
        let packet = build_legacy_client_packet(0, 42, &[0x01, 0x02, 0x03], false);
        let decoded = Audio::decode(&packet, None).expect("decode legacy c→s");
        assert_eq!(decoded.target, AudioTarget::Normal);
        assert_eq!(decoded.sender_session, None); // not present in client→server
        assert_eq!(decoded.frame_number, 42);
        assert_eq!(
            decoded.audio_payload,
            AudioPayload::Opus(OpusPayload {
                frame: Bytes::from_static(&[0x01, 0x02, 0x03]),
                is_terminator: false,
            })
        );
        assert_eq!(decoded.format, PacketFormat::Legacy);
    }

    #[test]
    fn legacy_decode_loopback() {
        // target = 31 (loopback): no special position_count field
        let packet = build_legacy_client_packet(31, 1, &[0xAA], false);
        let decoded = Audio::decode(&packet, None).expect("decode loopback");
        assert_eq!(decoded.target, AudioTarget::ServerLoopback);
        assert_eq!(decoded.sender_session, None);
        assert_eq!(decoded.frame_number, 1);
        assert_eq!(
            decoded.audio_payload,
            AudioPayload::Opus(OpusPayload {
                frame: Bytes::from_static(&[0xAA]),
                is_terminator: false,
            })
        );
    }

    #[test]
    fn legacy_encode_server_to_client() {
        // Server→client legacy packets include sender_session.
        let audio = Audio {
            target: AudioTarget::Normal,
            sender_session: Some(ClientSessionIdentifier::from(7)),
            frame_number: 42,
            audio_payload: AudioPayload::Opus(OpusPayload {
                frame: Bytes::from_static(&[0x01, 0x02, 0x03]),
                is_terminator: false,
            }),
            positional_data: None,
            volume_adjustment: 1.0,
            format: PacketFormat::Legacy,
        };
        let encoded = audio.encode(AudioContext::Normal, PacketFormat::Legacy);
        assert_eq!(encoded[0], 0x80); // Opus (0x04<<5) | target 0
        assert_eq!(encoded[1], 7); // sender_session = 7 (1-byte PDS varint)
        assert_eq!(encoded[2], 42); // frame_number = 42
        assert_eq!(encoded[3], 3); // payload_size = 3, no terminator
        assert_eq!(&encoded[4..], &[0x01u8, 0x02, 0x03]);
    }

    #[test]
    fn legacy_encode_with_positional() {
        let audio = Audio {
            target: AudioTarget::Normal,
            sender_session: Some(ClientSessionIdentifier::from(1)),
            frame_number: 0,
            audio_payload: AudioPayload::Opus(OpusPayload {
                frame: Bytes::from_static(&[0xAA]),
                is_terminator: false,
            }),
            positional_data: Some([1.0_f32, 2.0_f32, 3.0_f32]),
            volume_adjustment: 1.0,
            format: PacketFormat::Legacy,
        };
        let encoded = audio.encode(AudioContext::Normal, PacketFormat::Legacy);
        // Tail should be three 4-byte little-endian floats
        let tail_start = encoded.len() - 12;
        let x = f32::from_le_bytes(encoded[tail_start..tail_start + 4].try_into().unwrap());
        let y = f32::from_le_bytes(encoded[tail_start + 4..tail_start + 8].try_into().unwrap());
        let z = f32::from_le_bytes(encoded[tail_start + 8..].try_into().unwrap());
        assert_eq!(x, 1.0);
        assert_eq!(y, 2.0);
        assert_eq!(z, 3.0);
    }

    // ── Format detection ─────────────────────────────────────────────────

    #[test]
    fn detect_protobuf_format() {
        let audio = Audio {
            target: AudioTarget::Normal,
            sender_session: Some(ClientSessionIdentifier::from(1)),
            frame_number: 0,
            audio_payload: AudioPayload::Opus(OpusPayload {
                frame: Bytes::from_static(&[0x00]),
                is_terminator: false,
            }),
            positional_data: None,
            volume_adjustment: 1.0,
            format: PacketFormat::Protobuf,
        };
        let encoded = audio.encode(AudioContext::Normal, PacketFormat::Protobuf);
        let decoded = Audio::decode(&encoded, None).expect("decode");
        assert_eq!(decoded.format, PacketFormat::Protobuf);
    }

    #[test]
    fn detect_legacy_format() {
        let packet = build_legacy_client_packet(0, 0, &[0x00], false);
        let decoded = Audio::decode(&packet, None).expect("decode");
        assert_eq!(decoded.format, PacketFormat::Legacy);
    }

    // ── Edge cases ───────────────────────────────────────────────────────

    #[test]
    fn empty_packet() {
        assert!(Audio::decode(&[], None).is_err());
    }

    #[test]
    fn ping_not_voice() {
        // Protobuf ping: first byte 0x01
        assert!(matches!(
            Audio::decode(&[0x01, 0x00], None),
            Err(DecodeError::NotVoice)
        ));
        // Legacy ping: type bits 001 → 0x20
        assert!(matches!(
            Audio::decode(&[0x20, 0x00], None),
            Err(DecodeError::NotVoice)
        ));
    }

    #[test]
    fn unknown_type() {
        assert!(matches!(
            Audio::decode(&[0xFF], None),
            Err(DecodeError::NotVoice)
        ));
    }

    // ── Varint edge cases ────────────────────────────────────────────────

    #[test]
    fn varint_truncated_returns_none() {
        // 2-byte form needs 2 bytes; truncated at 1 must fail.
        assert!(read_varint_slice(&[0x80]).is_none());
        // 3-byte form needs 3 bytes; truncated at 2 must fail.
        assert!(read_varint_slice(&[0xC0, 0x00]).is_none());
        // 4-byte form needs 4 bytes; truncated at 3 must fail.
        assert!(read_varint_slice(&[0xE0, 0x00, 0x00]).is_none());
    }

    #[test]
    fn varint_special_byte_returns_none() {
        // 0xF0–0xFF are special/negative forms rejected in voice packets.
        assert!(read_varint_slice(&[0xF0]).is_none());
        assert!(read_varint_slice(&[0xF8, 0x00, 0x00, 0x00, 0x00]).is_none());
        assert!(read_varint_slice(&[0xFF]).is_none());
    }

    #[test]
    fn varint_three_and_four_byte_roundtrip() {
        // Explicit byte-level check for 3-byte and 4-byte boundaries.
        // 3-byte: 0xC0 | (value >> 16), middle byte, low byte
        let mut buf = BytesMut::new();
        write_varint_buf(&mut buf, 16384); // smallest 3-byte value
        assert_eq!(&buf[..], &[0xC0, 0x40, 0x00]);
        let (decoded, n) = read_varint_slice(&buf).unwrap();
        assert_eq!((decoded, n), (16384, 3));

        buf.clear();
        write_varint_buf(&mut buf, 2097151); // largest 3-byte value
        let (decoded, _) = read_varint_slice(&buf).unwrap();
        assert_eq!(decoded, 2097151);

        // 4-byte: 0xE0 | (value >> 24), then three more bytes
        buf.clear();
        write_varint_buf(&mut buf, 2097152); // smallest 4-byte value
        assert_eq!(buf.len(), 4);
        let (decoded, n) = read_varint_slice(&buf).unwrap();
        assert_eq!((decoded, n), (2097152, 4));
    }

    // ── Legacy decode additional ─────────────────────────────────────────

    #[test]
    fn legacy_decode_with_positional_data() {
        let mut packet = build_legacy_client_packet(0, 1, &[0xAA, 0xBB], false);
        packet.extend_from_slice(&1.5f32.to_le_bytes());
        packet.extend_from_slice(&2.5f32.to_le_bytes());
        packet.extend_from_slice(&3.5f32.to_le_bytes());
        let decoded = Audio::decode(&packet, None).expect("decode with positional");
        assert_eq!(decoded.positional_data, Some([1.5f32, 2.5, 3.5]));
        assert_eq!(
            decoded.audio_payload,
            AudioPayload::Opus(OpusPayload {
                frame: Bytes::from_static(&[0xAA, 0xBB]),
                is_terminator: false,
            })
        );
    }

    #[test]
    fn legacy_decode_whisper_target() {
        let packet = build_legacy_client_packet(15, 0, &[0x01], false);
        let decoded = Audio::decode(&packet, None).expect("decode whisper target");
        assert_eq!(decoded.target, AudioTarget::VoiceTarget(15));
    }

    #[test]
    fn legacy_decode_large_frame_number() {
        // frame_number=128 requires a 2-byte PDS varint [0x80, 0x80].
        let packet = build_legacy_client_packet(0, 128, &[0x01], false);
        let decoded = Audio::decode(&packet, None).expect("decode large frame_number");
        assert_eq!(decoded.frame_number, 128);
    }

    // ── Protobuf decode additional ────────────────────────────────────────

    #[test]
    fn protobuf_decode_three_positional_valid() {
        use crate::mumble_udp::{Audio as WireAudio, audio};
        use prost::Message as _;
        let msg = WireAudio {
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
        let decoded = Audio::decode(&buf, None).expect("3 positional floats must be valid");
        assert_eq!(decoded.positional_data, Some([1.0f32, 2.0, 3.0]));
    }

    #[test]
    fn protobuf_decode_one_positional_invalid() {
        use crate::mumble_udp::{Audio as WireAudio, audio};
        use prost::Message as _;
        let msg = WireAudio {
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
            Audio::decode(&buf, None),
            Err(DecodeError::MalformedPacket)
        ));
    }

    #[test]
    fn protobuf_decode_four_positional_invalid() {
        use crate::mumble_udp::{Audio as WireAudio, audio};
        use prost::Message as _;
        let msg = WireAudio {
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
            Audio::decode(&buf, None),
            Err(DecodeError::MalformedPacket)
        ));
    }

    #[test]
    fn protobuf_decode_volume_nonzero_passthrough() {
        // A non-zero volume_adjustment must pass through unchanged (not clamped to 1.0).
        use crate::mumble_udp::{Audio as WireAudio, audio};
        use prost::Message as _;
        let msg = WireAudio {
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
        let decoded = Audio::decode(&buf, None).expect("decode");
        assert_eq!(decoded.volume_adjustment, 0.5);
    }

    #[test]
    fn protobuf_decode_no_header_gives_zero_target() {
        // Missing header oneof defaults to target = 0.
        use crate::mumble_udp::Audio as WireAudio;
        use prost::Message as _;
        let msg = WireAudio {
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
        let decoded = Audio::decode(&buf, None).expect("decode");
        assert_eq!(decoded.target, AudioTarget::Normal);
    }

    // ── Size limits ───────────────────────────────────────────────────────

    #[test]
    fn protobuf_encode_oversized_returns_empty() {
        let audio = Audio {
            target: AudioTarget::Normal,
            sender_session: Some(ClientSessionIdentifier::from(1)),
            frame_number: 0,
            audio_payload: AudioPayload::Opus(OpusPayload {
                frame: Bytes::from(vec![0xAA; 2000]),
                is_terminator: false,
            }),
            positional_data: None,
            volume_adjustment: 1.0,
            format: PacketFormat::Protobuf,
        };
        let encoded = audio.encode(AudioContext::Normal, PacketFormat::Protobuf);
        assert!(
            encoded.is_empty(),
            "oversized protobuf packet must be dropped"
        );
    }

    #[test]
    fn legacy_encode_oversized_returns_empty() {
        let audio = Audio {
            target: AudioTarget::Normal,
            sender_session: Some(ClientSessionIdentifier::from(1)),
            frame_number: 0,
            audio_payload: AudioPayload::Opus(OpusPayload {
                frame: Bytes::from(vec![0xBB; 2000]),
                is_terminator: false,
            }),
            positional_data: None,
            volume_adjustment: 1.0,
            format: PacketFormat::Legacy,
        };
        let encoded = audio.encode(AudioContext::Normal, PacketFormat::Legacy);
        assert!(
            encoded.is_empty(),
            "oversized legacy packet must be dropped"
        );
    }

    // ── UdpPacket::decode ────────────────────────────────────────────────

    #[test]
    fn udp_packet_protobuf_audio() {
        let audio = Audio {
            target: AudioTarget::Normal,
            sender_session: Some(ClientSessionIdentifier::from(5)),
            frame_number: 7,
            audio_payload: AudioPayload::Opus(OpusPayload {
                frame: Bytes::from_static(&[0x01, 0x02]),
                is_terminator: false,
            }),
            positional_data: None,
            volume_adjustment: 1.0,
            format: PacketFormat::Protobuf,
        };
        let encoded = audio.encode(AudioContext::Normal, PacketFormat::Protobuf);
        let packet = IncomingUdpPacket::decode(&encoded, None).expect("decode protobuf audio");
        let IncomingUdpPacket::Audio(a) = packet else {
            panic!("expected Audio")
        };
        assert_eq!(a.frame_number, 7);
        assert_eq!(a.format, PacketFormat::Protobuf);
    }

    #[test]
    fn udp_packet_legacy_opus() {
        let raw = build_legacy_client_packet(0, 3, &[0x01, 0x02], false);
        let packet = IncomingUdpPacket::decode(&raw, None).expect("decode legacy audio");
        let IncomingUdpPacket::Audio(a) = packet else {
            panic!("expected Audio")
        };
        assert_eq!(a.frame_number, 3);
        assert_eq!(a.format, PacketFormat::Legacy);
    }

    #[test]
    fn udp_packet_celt_rejected() {
        // CELTAlpha type bits (top 3 = 000): use 0x02 to avoid the protobuf 0x00 path.
        let raw = [0x02u8, 0x00, 0x00];
        assert!(matches!(
            IncomingUdpPacket::decode(&raw, None),
            Err(DecodeError::UnsupportedCodec)
        ));
    }

    #[test]
    fn udp_packet_malformed_packet_propagated() {
        // Valid protobuf bytes but invalid positional count must propagate MalformedPacket,
        // not silently fall through to the legacy decoder.
        use crate::mumble_udp::{Audio as WireAudio, audio};
        use prost::Message as _;
        let msg = WireAudio {
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
            IncomingUdpPacket::decode(&buf, None),
            Err(DecodeError::MalformedPacket)
        ));
    }
}
