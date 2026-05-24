//! Frame envelope shared across all four transports.
//!
//! Wire format on streams:    `[u32 BE encoded_len][prost-encoded Frame]`
//! Wire format on UDP:        one prost-encoded `Frame` per datagram.

use bytes::{Bytes, BytesMut};
use prost::Message as ProstMessage;
use tokio_util::codec::LengthDelimitedCodec;

use crate::s2s_transport_proto as pb;
use crate::types::NodeIdentifier;

use super::service_level::{MessageClass, ServiceLevel};

/// Re-export the generated message under a domain-friendly alias.
pub use crate::s2s_transport_proto::Frame;

/// Internal frame disposition. Maps 1:1 onto `pb::FrameType` but keeps callers
/// off of the generated type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data,
    Hello,
    Ping,
    Pong,
    KeepAlive,
    Bye,
}

impl From<FrameType> for pb::FrameType {
    fn from(v: FrameType) -> Self {
        match v {
            FrameType::Data => pb::FrameType::FrameData,
            FrameType::Hello => pb::FrameType::FrameHello,
            FrameType::Ping => pb::FrameType::FramePing,
            FrameType::Pong => pb::FrameType::FramePong,
            FrameType::KeepAlive => pb::FrameType::FrameKeepalive,
            FrameType::Bye => pb::FrameType::FrameBye,
        }
    }
}

impl From<pb::FrameType> for FrameType {
    fn from(v: pb::FrameType) -> Self {
        match v {
            pb::FrameType::FrameData => FrameType::Data,
            pb::FrameType::FrameHello => FrameType::Hello,
            pb::FrameType::FramePing => FrameType::Ping,
            pb::FrameType::FramePong => FrameType::Pong,
            pb::FrameType::FrameKeepalive => FrameType::KeepAlive,
            pb::FrameType::FrameBye => FrameType::Bye,
        }
    }
}

impl TryFrom<i32> for FrameType {
    type Error = i32;
    fn try_from(value: i32) -> Result<Self, i32> {
        pb::FrameType::try_from(value)
            .map(FrameType::from)
            .map_err(|_| value)
    }
}

impl From<ServiceLevel> for pb::ServiceLevel {
    fn from(v: ServiceLevel) -> Self {
        match v {
            ServiceLevel::Reliable => pb::ServiceLevel::ServiceReliable,
            ServiceLevel::ReliableLowLatency => pb::ServiceLevel::ServiceReliableLowLatency,
            ServiceLevel::BestEffort => pb::ServiceLevel::ServiceBestEffort,
        }
    }
}

impl From<pb::ServiceLevel> for ServiceLevel {
    fn from(v: pb::ServiceLevel) -> Self {
        match v {
            pb::ServiceLevel::ServiceReliable => ServiceLevel::Reliable,
            pb::ServiceLevel::ServiceReliableLowLatency => ServiceLevel::ReliableLowLatency,
            pb::ServiceLevel::ServiceBestEffort => ServiceLevel::BestEffort,
        }
    }
}

impl TryFrom<i32> for ServiceLevel {
    type Error = i32;
    fn try_from(value: i32) -> Result<Self, i32> {
        pb::ServiceLevel::try_from(value)
            .map(ServiceLevel::from)
            .map_err(|_| value)
    }
}

impl From<MessageClass> for pb::MessageClass {
    fn from(v: MessageClass) -> Self {
        match v {
            MessageClass::Control => pb::MessageClass::ClassControl,
            MessageClass::HighPriority => pb::MessageClass::ClassHighPriority,
            MessageClass::Regular => pb::MessageClass::ClassRegular,
        }
    }
}

impl From<pb::MessageClass> for MessageClass {
    fn from(v: pb::MessageClass) -> Self {
        match v {
            pb::MessageClass::ClassControl => MessageClass::Control,
            pb::MessageClass::ClassHighPriority => MessageClass::HighPriority,
            pb::MessageClass::ClassRegular => MessageClass::Regular,
        }
    }
}

impl TryFrom<i32> for MessageClass {
    type Error = i32;
    fn try_from(value: i32) -> Result<Self, i32> {
        pb::MessageClass::try_from(value)
            .map(MessageClass::from)
            .map_err(|_| value)
    }
}

/// Encode a `Frame` into the supplied buffer (no length prefix).
#[inline]
pub fn encode_frame(frame: &Frame, buf: &mut BytesMut) -> Result<(), prost::EncodeError> {
    buf.reserve(frame.encoded_len());
    frame.encode(buf)
}

/// Encode a `Frame` into a fresh `Bytes`.
#[inline]
pub fn encode_frame_to_bytes(frame: &Frame) -> Result<Bytes, prost::EncodeError> {
    let mut buf = BytesMut::with_capacity(frame.encoded_len());
    frame.encode(&mut buf)?;
    Ok(buf.freeze())
}

/// Decode a `Frame` from a byte slice.
#[inline]
pub fn decode_frame(src: &[u8]) -> Result<Frame, prost::DecodeError> {
    Frame::decode(src)
}

/// Build a `LengthDelimitedCodec` configured for the stream wire format.
///
/// `[u32 BE encoded_len][prost-encoded Frame]` with `max_frame_bytes` enforced
/// on both encode and decode paths to bound memory use per connection.
pub fn stream_codec(max_frame_bytes: usize) -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_length(4)
        .length_field_type::<u32>()
        .big_endian()
        .max_frame_length(max_frame_bytes)
        .new_codec()
}

/// Convert a domain `NodeIdentifier` (u16) into the on-wire `u32` field.
#[inline]
pub fn node_to_wire(id: NodeIdentifier) -> u32 {
    id as u32
}

/// Convert an on-wire `u32` into a domain `NodeIdentifier`. Returns `None` if
/// the value does not fit in `u16`.
#[inline]
pub fn node_from_wire(v: u32) -> Option<NodeIdentifier> {
    if v <= u16::MAX as u32 {
        Some(v as NodeIdentifier)
    } else {
        None
    }
}

/// Construct a `Frame` from domain-typed inputs.
pub fn build_frame(
    src: NodeIdentifier,
    dst: NodeIdentifier,
    level: ServiceLevel,
    ty: FrameType,
    class: MessageClass,
    ts_us: u64,
    payload: Bytes,
) -> Frame {
    Frame {
        src_node: node_to_wire(src),
        dst_node: node_to_wire(dst),
        service_level: pb::ServiceLevel::from(level) as i32,
        frame_type: pb::FrameType::from(ty) as i32,
        message_class: pb::MessageClass::from(class) as i32,
        ts_us,
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_frame(payload: Bytes) {
        let f = build_frame(
            42,
            7,
            ServiceLevel::ReliableLowLatency,
            FrameType::Data,
            MessageClass::HighPriority,
            456_789,
            payload.clone(),
        );
        let mut buf = BytesMut::new();
        encode_frame(&f, &mut buf).expect("encode");
        let decoded = decode_frame(&buf).expect("decode");
        assert_eq!(decoded.src_node, 42);
        assert_eq!(decoded.dst_node, 7);
        assert_eq!(decoded.ts_us, 456_789);
        assert_eq!(decoded.payload, payload);
        assert_eq!(
            ServiceLevel::try_from(decoded.service_level).unwrap(),
            ServiceLevel::ReliableLowLatency
        );
        assert_eq!(
            FrameType::try_from(decoded.frame_type).unwrap(),
            FrameType::Data
        );
        assert_eq!(
            MessageClass::try_from(decoded.message_class).unwrap(),
            MessageClass::HighPriority
        );
    }

    #[test]
    fn roundtrip_empty() {
        roundtrip_frame(Bytes::new());
    }

    #[test]
    fn roundtrip_small() {
        roundtrip_frame(Bytes::from_static(b"hello world"));
    }

    #[test]
    fn roundtrip_large() {
        roundtrip_frame(Bytes::from(vec![0xab; 64 * 1024]));
    }

    #[test]
    fn node_id_helpers() {
        assert_eq!(node_to_wire(0), 0);
        assert_eq!(node_to_wire(u16::MAX), u16::MAX as u32);
        assert_eq!(node_from_wire(0), Some(0));
        assert_eq!(node_from_wire(u16::MAX as u32), Some(u16::MAX));
        assert_eq!(node_from_wire(u16::MAX as u32 + 1), None);
    }

    #[test]
    fn enum_conversions_total() {
        for lvl in [
            ServiceLevel::Reliable,
            ServiceLevel::ReliableLowLatency,
            ServiceLevel::BestEffort,
        ] {
            let i = pb::ServiceLevel::from(lvl) as i32;
            assert_eq!(ServiceLevel::try_from(i).unwrap(), lvl);
        }
        for ty in [
            FrameType::Data,
            FrameType::Hello,
            FrameType::Ping,
            FrameType::Pong,
            FrameType::KeepAlive,
            FrameType::Bye,
        ] {
            let i = pb::FrameType::from(ty) as i32;
            assert_eq!(FrameType::try_from(i).unwrap(), ty);
        }
        for c in [
            MessageClass::Control,
            MessageClass::HighPriority,
            MessageClass::Regular,
        ] {
            let i = pb::MessageClass::from(c) as i32;
            assert_eq!(MessageClass::try_from(i).unwrap(), c);
        }
    }
}
