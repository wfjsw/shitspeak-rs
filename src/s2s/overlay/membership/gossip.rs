//! Gossip-update conversion + apply helpers.
//!
//! `GossipUpdate` lives on the wire as a flat protobuf message. Converting
//! to and from our `MemberRecord` is mechanical; the interesting bit is the
//! `apply_inbound_updates` helper that merges a vec of updates into the
//! membership table and broadcasts any resulting `MembershipEvent`s.

use crate::s2s::transport::{ConnectionManager, PeerAddress};
use crate::s2s_overlay_proto as pb;
use crate::types::NodeIdentifier;

use super::super::proto::{address_from_pb, address_to_pb, node_from_wire, node_to_wire};
use super::view::{MemberRecord, MemberStatus};
use super::{MembershipEvent, MembershipTable};

/// Build a `pb::GossipUpdate` from one `MemberRecord` ready for piggyback.
pub fn record_to_pb(r: &MemberRecord) -> pb::GossipUpdate {
    pb::GossipUpdate {
        node: node_to_wire(r.node_id()),
        incarnation: r.incarnation(),
        status: pb::MemberStatus::from(r.status()) as i32,
        addresses: r.addresses().iter().map(address_to_pb).collect(),
    }
}

/// Build a Gossip update for our own self-state. Used to refute Suspect/Dead
/// claims about ourselves, or to advertise a graceful Left.
pub fn self_record_to_pb(
    self_id: NodeIdentifier,
    incarnation: u64,
    status: MemberStatus,
    addresses: &[PeerAddress],
) -> pb::GossipUpdate {
    pb::GossipUpdate {
        node: node_to_wire(self_id),
        incarnation,
        status: pb::MemberStatus::from(status) as i32,
        addresses: addresses.iter().map(address_to_pb).collect(),
    }
}

/// Decode a single `pb::GossipUpdate` into domain pieces. Returns `None` if
/// the message is malformed.
pub fn pb_to_parts(
    u: &pb::GossipUpdate,
) -> Option<(NodeIdentifier, u64, MemberStatus, Vec<PeerAddress>)> {
    let node = node_from_wire(u.node)?;
    let status = MemberStatus::try_from(u.status).ok()?;
    let addresses: Vec<PeerAddress> = u.addresses.iter().filter_map(address_from_pb).collect();
    Some((node, u.incarnation, status, addresses))
}

/// Apply a batch of inbound `GossipUpdate`s to the table. For each update
/// that talks about *us*, the caller is expected to handle refute/leave
/// separately — we filter them out here and return the resulting events.
///
/// Side effects on success:
///  * `MembershipEvent`s are published on the broadcast channel.
///  * For every learned address, `transport.add_address(node, addr)` is
///    called so the supervisor's dial loop can pick it up.
pub fn apply_inbound_updates(
    table: &MembershipTable,
    transport: &ConnectionManager,
    updates: &[pb::GossipUpdate],
) {
    let mut all_events = Vec::new();
    for u in updates {
        let Some((node, inc, status, addrs)) = pb_to_parts(u) else {
            continue;
        };
        if node == table.self_id() {
            continue; // refute logic lives elsewhere
        }
        // Tell the transport about every learned address.
        for a in &addrs {
            // Manager.add_address is async; we fire-and-forget on a tokio
            // local future. The caller spawns this inside an async ctx.
            let t = transport.clone();
            let node_c = node;
            let addr_c = *a;
            tokio::spawn(async move {
                t.add_address(node_c, addr_c).await;
            });
        }
        all_events.extend(table.merge_update(node, inc, status, &addrs));
    }
    table.publish(all_events);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_to_pb_roundtrip() {
        let r = MemberRecord::new_alive(
            42,
            123_456,
            vec![PeerAddress::new(
                "127.0.0.1:9".parse().unwrap(),
                crate::s2s::transport::TransportKind::Tcp,
            )],
        );
        let pb = record_to_pb(&r);
        let (node, inc, status, addrs) = pb_to_parts(&pb).unwrap();
        assert_eq!(node, 42);
        assert_eq!(inc, 123_456);
        assert_eq!(status, MemberStatus::Alive);
        assert_eq!(addrs.len(), 1);
    }
}
