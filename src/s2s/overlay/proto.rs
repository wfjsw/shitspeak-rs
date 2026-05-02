//! Thin wrappers around the prost-generated `s2s_overlay_proto` types.
//!
//! Exposes encode/decode helpers and conversions between the generated
//! enums and the public Rust enums so the rest of the overlay never has to
//! touch the proto types directly.

use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use prost::Message as _;

use crate::s2s::transport::{PeerAddress, TransportKind};
use crate::s2s_overlay_proto as pb;
use crate::types::NodeIdentifier;

pub use crate::s2s_overlay_proto::{
    overlay_message::Body as OverlayBody, GossipDigest, GossipUpdate, OverlayMessage, SwimAck,
    SwimPing, SwimPingReq,
};

/// Public Rust mirror of `pb::MemberStatus`. Kept in [`super::membership`].
pub use super::membership::view::MemberStatus;

impl From<MemberStatus> for pb::MemberStatus {
    fn from(v: MemberStatus) -> Self {
        match v {
            MemberStatus::Alive => pb::MemberStatus::Alive,
            MemberStatus::Suspect => pb::MemberStatus::Suspect,
            MemberStatus::Dead => pb::MemberStatus::Dead,
            MemberStatus::Left => pb::MemberStatus::Left,
        }
    }
}

impl From<pb::MemberStatus> for MemberStatus {
    fn from(v: pb::MemberStatus) -> Self {
        match v {
            pb::MemberStatus::Alive => MemberStatus::Alive,
            pb::MemberStatus::Suspect => MemberStatus::Suspect,
            pb::MemberStatus::Dead => MemberStatus::Dead,
            pb::MemberStatus::Left => MemberStatus::Left,
        }
    }
}

impl TryFrom<i32> for MemberStatus {
    type Error = i32;
    fn try_from(value: i32) -> Result<Self, i32> {
        pb::MemberStatus::try_from(value)
            .map(MemberStatus::from)
            .map_err(|_| value)
    }
}

/// Encode an `OverlayMessage` to a fresh `Bytes` ready for `transport.send(...)`.
pub fn encode_message(msg: &OverlayMessage) -> Result<Bytes, prost::EncodeError> {
    let mut buf = BytesMut::with_capacity(msg.encoded_len());
    msg.encode(&mut buf)?;
    Ok(buf.freeze())
}

/// Decode an `OverlayMessage` from the wire bytes.
pub fn decode_message(src: &[u8]) -> Result<OverlayMessage, prost::DecodeError> {
    OverlayMessage::decode(src)
}

/// Encode a `PeerAddress` into the wire form used in `AddressEntry`.
pub fn address_to_pb(addr: &PeerAddress) -> pb::AddressEntry {
    pb::AddressEntry {
        addr: addr.addr().to_string(),
        transport: kind_to_u32(addr.transport()),
    }
}

/// Decode an `AddressEntry`. Returns `None` on parse failure.
pub fn address_from_pb(entry: &pb::AddressEntry) -> Option<PeerAddress> {
    let addr: SocketAddr = entry.addr.parse().ok()?;
    let transport = u32_to_kind(entry.transport)?;
    Some(PeerAddress::new(addr, transport))
}

fn kind_to_u32(k: TransportKind) -> u32 {
    match k {
        TransportKind::Tcp => 0,
        TransportKind::Kcp => 1,
        TransportKind::Quic => 2,
        TransportKind::Udp => 3,
    }
}

fn u32_to_kind(v: u32) -> Option<TransportKind> {
    match v {
        0 => Some(TransportKind::Tcp),
        1 => Some(TransportKind::Kcp),
        2 => Some(TransportKind::Quic),
        3 => Some(TransportKind::Udp),
        _ => None,
    }
}

/// Construct an `OverlayMessage` carrying the supplied body.
pub fn wrap(body: OverlayBody) -> OverlayMessage {
    OverlayMessage { body: Some(body) }
}

/// Convert a domain `NodeIdentifier` to the `u32` field on the wire.
#[inline]
pub fn node_to_wire(id: NodeIdentifier) -> u32 {
    id as u32
}

/// Convert a wire `u32` to a `NodeIdentifier`. Returns `None` if the value
/// does not fit in `u16`.
#[inline]
pub fn node_from_wire(v: u32) -> Option<NodeIdentifier> {
    if v <= u16::MAX as u32 {
        Some(v as NodeIdentifier)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_conversions_total() {
        for s in [
            MemberStatus::Alive,
            MemberStatus::Suspect,
            MemberStatus::Dead,
            MemberStatus::Left,
        ] {
            let i = pb::MemberStatus::from(s) as i32;
            assert_eq!(MemberStatus::try_from(i).unwrap(), s);
        }
    }

    #[test]
    fn address_roundtrip() {
        let a = PeerAddress::new("127.0.0.1:1234".parse().unwrap(), TransportKind::Quic);
        let pb_a = address_to_pb(&a);
        let back = address_from_pb(&pb_a).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn message_roundtrip() {
        let msg = wrap(OverlayBody::SwimPing(SwimPing {
            src_node: 7,
            src_incarnation: 12345,
            nonce: 99,
            piggyback: vec![],
        }));
        let bytes = encode_message(&msg).unwrap();
        let decoded = decode_message(&bytes).unwrap();
        match decoded.body {
            Some(OverlayBody::SwimPing(p)) => {
                assert_eq!(p.src_node, 7);
                assert_eq!(p.src_incarnation, 12345);
                assert_eq!(p.nonce, 99);
            }
            other => panic!("unexpected body: {other:?}"),
        }
    }
}
