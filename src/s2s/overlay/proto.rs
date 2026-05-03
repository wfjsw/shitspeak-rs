//! Thin wrappers around the prost-generated `s2s_overlay_proto` types.
//!
//! Exposes encode/decode helpers and conversions between wire types and the
//! domain types the rest of the overlay uses.

use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use prost::Message as _;

use crate::s2s::transport::{MessageClass, PeerAddress, ServiceLevel, TransportKind};
use crate::s2s_overlay_proto as pb;
use crate::types::NodeIdentifier;

pub use crate::s2s_overlay_proto::{
    overlay_message::Body as OverlayBody, AddressEntry, DigestEntry, Hello, HelloAck, LinkAdvert,
    LinkStateAdvert, LsaFlood, LsdbSync, LsdbSyncResp, OverlayData, OverlayMessage,
};

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

/// Construct an `OverlayMessage` carrying the supplied body.
pub fn wrap(body: OverlayBody) -> OverlayMessage {
    OverlayMessage { body: Some(body) }
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

#[inline]
pub fn kind_to_u32(k: TransportKind) -> u32 {
    super::config::kind_to_idx(k)
}

#[inline]
pub fn u32_to_kind(v: u32) -> Option<TransportKind> {
    super::config::idx_to_kind(v)
}

/// Bitmask of every transport kind for which the peer is reachable.
pub fn transports_to_mask(kinds: &[TransportKind]) -> u32 {
    kinds.iter().fold(0u32, |acc, k| acc | super::config::transport_bit(*k))
}

pub fn mask_to_transports(mask: u32) -> Vec<TransportKind> {
    let mut out = Vec::new();
    for i in 0..4 {
        if mask & (1u32 << i) != 0 {
            if let Some(k) = super::config::idx_to_kind(i) {
                out.push(k);
            }
        }
    }
    out
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

/// Convert a `ServiceLevel` to its u32 wire value.
///
/// The wire encoding is stable and independent of the enum's
/// discriminant numbering: `0=Reliable, 1=RLL, 2=BestEffort`. This
/// avoids breaking on-the-wire compatibility if the enum is reordered
/// (which it has been: KCP/QUIC's `ReliableLowLatency` is now the
/// strongest tier numerically, but the wire still uses `0` for plain
/// `Reliable` so older peers don't misinterpret levels).
#[inline]
pub fn level_to_wire(l: ServiceLevel) -> u32 {
    match l {
        ServiceLevel::Reliable => 0,
        ServiceLevel::ReliableLowLatency => 1,
        ServiceLevel::BestEffort => 2,
    }
}

#[inline]
pub fn level_from_wire(v: u32) -> Option<ServiceLevel> {
    match v {
        0 => Some(ServiceLevel::Reliable),
        1 => Some(ServiceLevel::ReliableLowLatency),
        2 => Some(ServiceLevel::BestEffort),
        _ => None,
    }
}

#[inline]
pub fn class_to_wire(c: MessageClass) -> u32 {
    match c {
        MessageClass::HighPriority => 0,
        MessageClass::Regular => 1,
    }
}

#[inline]
pub fn class_from_wire(v: u32) -> Option<MessageClass> {
    match v {
        0 => Some(MessageClass::HighPriority),
        1 => Some(MessageClass::Regular),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_roundtrip() {
        let a = PeerAddress::new("127.0.0.1:1234".parse().unwrap(), TransportKind::Quic);
        let pb_a = address_to_pb(&a);
        let back = address_from_pb(&pb_a).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn message_roundtrip() {
        let msg = wrap(OverlayBody::Hello(Hello {
            src_node: 7,
            src_boot_epoch: 12345,
            nonce: 99,
            ts_send_us: 0,
        }));
        let bytes = encode_message(&msg).unwrap();
        let decoded = decode_message(&bytes).unwrap();
        match decoded.body {
            Some(OverlayBody::Hello(h)) => {
                assert_eq!(h.src_node, 7);
                assert_eq!(h.src_boot_epoch, 12345);
                assert_eq!(h.nonce, 99);
            }
            other => panic!("unexpected body: {other:?}"),
        }
    }

    #[test]
    fn level_class_roundtrip() {
        for l in [
            ServiceLevel::Reliable,
            ServiceLevel::ReliableLowLatency,
            ServiceLevel::BestEffort,
        ] {
            assert_eq!(level_from_wire(level_to_wire(l)).unwrap(), l);
        }
        for c in [MessageClass::HighPriority, MessageClass::Regular] {
            assert_eq!(class_from_wire(class_to_wire(c)).unwrap(), c);
        }
    }

    #[test]
    fn transport_mask_roundtrip() {
        let kinds = [TransportKind::Tcp, TransportKind::Quic];
        let mask = transports_to_mask(&kinds);
        let back = mask_to_transports(mask);
        assert!(back.contains(&TransportKind::Tcp));
        assert!(back.contains(&TransportKind::Quic));
        assert!(!back.contains(&TransportKind::Kcp));
    }
}
