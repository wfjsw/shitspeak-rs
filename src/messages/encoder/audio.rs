//! Domain-typed wrapper around `mumble_udp::Audio`.
//!
//! All construction and parsing of `mumble_udp::Audio` is funneled through
//! this module so that the rest of the crate works with typed enums for the
//! routing target/context instead of raw `u32` field values.

use bytes::Bytes;
use prost::Message as _;

use crate::messages::errors::AudioProtocolError;

/// Routing context attached by the server to outbound (server→client) audio
/// packets. Encoded into the `context` variant of `mumble_udp::Audio.Header`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum AudioContext {
    /// Normal channel speech.
    Normal = 0,
    /// Shout: the speaker is talking to a channel they are not in.
    Shout = 1,
    /// Whisper: the speaker is talking to a specific user.
    Whisper = 2,
    /// Listen: the recipient is listening to a channel they are not in.
    Listen = 3,
}

impl From<AudioContext> for u32 {
    fn from(c: AudioContext) -> u32 {
        c as u32
    }
}

impl std::fmt::Display for AudioContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AudioContext::Normal => f.write_str("normal"),
            AudioContext::Shout => f.write_str("shout"),
            AudioContext::Whisper => f.write_str("whisper"),
            AudioContext::Listen => f.write_str("listen"),
        }
    }
}

/// Routing target attached by clients to inbound (client→server) audio
/// packets. Decoded from the `target` (or `context`) variant of
/// `mumble_udp::Audio.Header`. The protobuf permits any `u32` here; the
/// legacy wire format restricts to 0..=31.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioTarget {
    /// Normal channel speech (target = 0).
    Normal,
    /// Whisper or shout to a previously-registered VoiceTarget slot.
    /// Legacy wire restricts the slot ID to 1..=30; protobuf permits any
    /// `u32` ≠ 0 and ≠ 31.
    VoiceTarget(u32),
    /// Server loopback (target = 31).
    ServerLoopback,
}

impl From<u32> for AudioTarget {
    fn from(raw: u32) -> Self {
        match raw {
            0 => Self::Normal,
            0x1F => Self::ServerLoopback,
            n => Self::VoiceTarget(n),
        }
    }
}

impl From<u8> for AudioTarget {
    fn from(raw: u8) -> Self {
        Self::from(raw as u32)
    }
}

impl From<AudioTarget> for u32 {
    fn from(t: AudioTarget) -> u32 {
        match t {
            AudioTarget::Normal => 0,
            AudioTarget::ServerLoopback => 0x1F,
            AudioTarget::VoiceTarget(n) => n,
        }
    }
}

impl From<AudioTarget> for u8 {
    fn from(t: AudioTarget) -> u8 {
        match t {
            AudioTarget::Normal => 0,
            AudioTarget::ServerLoopback => 0x1F,
            AudioTarget::VoiceTarget(n) if n <= 30 => n as u8, // Legacy wire only supports up to 30 here.
            AudioTarget::VoiceTarget(_) => {
                tracing::debug!("voice target out of range for legacy wire, mocking as 30");
                30
            }
        }
    }
}

impl std::fmt::Display for AudioTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AudioTarget::Normal => f.write_str("normal"),
            AudioTarget::ServerLoopback => f.write_str("loopback"),
            AudioTarget::VoiceTarget(n) => write!(f, "voice_target({n})"),
        }
    }
}

/// The wire `Header` oneof preserved verbatim. Inbound packets typically
/// carry `Target`; outbound (server→client) packets always carry `Context`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioHeader {
    /// Client→server routing target.
    Target(AudioTarget),
    /// Server→client delivery context.
    Context(AudioContext),
}

/// Domain wrapper around `mumble_udp::Audio`. The only place in the crate
/// that constructs or destructures the protobuf type directly.
#[derive(Debug, Clone)]
pub struct Audio {
    pub header: Option<AudioHeader>,
    pub sender_session: u32,
    pub frame_number: u64,
    pub opus_data: Bytes,
    pub positional_data: Vec<f32>,
    pub volume_adjustment: f32,
    pub is_terminator: bool,
}

impl TryFrom<crate::mumble_udp::Audio> for Audio {
    type Error = AudioProtocolError;

    fn try_from(proto: crate::mumble_udp::Audio) -> Result<Self, AudioProtocolError> {
        // Positional data must be absent or exactly [x, y, z].
        if !matches!(proto.positional_data.len(), 0 | 3) {
            return Err(AudioProtocolError::InvalidPositionalDataLength(
                proto.positional_data.len(),
            ));
        }

        // The server is permissive: a `Context` from a client is treated as
        // a routing target with the same numeric value (matches Mumble's
        // reference behavior). The wrapper still preserves which variant the
        // wire used for downstream callers that care.
        let header = proto.header.map(|h| match h {
            crate::mumble_udp::audio::Header::Target(t) => {
                AudioHeader::Target(AudioTarget::from(t))
            }
            crate::mumble_udp::audio::Header::Context(c) => {
                AudioHeader::Target(AudioTarget::from(c))
            }
        });

        Ok(Self {
            header,
            sender_session: proto.sender_session,
            frame_number: proto.frame_number,
            opus_data: proto.opus_data,
            positional_data: proto.positional_data,
            volume_adjustment: proto.volume_adjustment,
            is_terminator: proto.is_terminator,
        })
    }
}

impl From<Audio> for crate::mumble_udp::Audio {
    fn from(a: Audio) -> Self {
        crate::mumble_udp::Audio {
            header: a.header.map(|h| match h {
                AudioHeader::Target(t) => crate::mumble_udp::audio::Header::Target(u32::from(t)),
                AudioHeader::Context(c) => crate::mumble_udp::audio::Header::Context(u32::from(c)),
            }),
            sender_session: a.sender_session,
            frame_number: a.frame_number,
            opus_data: a.opus_data,
            positional_data: a.positional_data,
            volume_adjustment: a.volume_adjustment,
            is_terminator: a.is_terminator,
        }
    }
}

/// Errors raised by `Audio::decode_wire` / `encode_wire`.
#[derive(Debug)]
pub enum AudioWireError {
    Protobuf(prost::DecodeError),
    Domain(AudioProtocolError),
    EncodeOverflow(prost::EncodeError),
}

impl Audio {
    /// Decode a wire `MumbleUDP.Audio` payload (the bytes after the 1-byte
    /// type prefix). Funnels protobuf parsing through prost and applies the
    /// domain validation in `TryFrom<mumble_udp::Audio>`.
    pub fn decode_wire(data: &[u8]) -> Result<Self, AudioWireError> {
        let proto = crate::mumble_udp::Audio::decode(data).map_err(AudioWireError::Protobuf)?;
        Self::try_from(proto).map_err(AudioWireError::Domain)
    }

    /// Length of the encoded protobuf payload (without the 1-byte type prefix).
    pub fn encoded_len(&self) -> usize {
        let proto: crate::mumble_udp::Audio = self.clone().into();
        proto.encoded_len()
    }

    /// Encode the protobuf payload (without the 1-byte type prefix) into `buf`.
    pub fn encode(self, buf: &mut bytes::BytesMut) -> Result<(), prost::EncodeError> {
        let proto: crate::mumble_udp::Audio = self.into();
        proto.encode(buf)
    }
}
