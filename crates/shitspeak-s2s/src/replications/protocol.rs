//! Strict-replication capability policy.
//!
//! The overlay publishes capability observations, but it must not decide
//! which observations participate in strict replication negotiation.  This
//! module keeps that policy in the replication layer and deliberately models
//! local participation separately from opaque frame transit.

use shitspeak_core::NodeIdentifier;

/// One member's capabilities as consumed by strict-replication negotiation.
///
/// `participant_version` describes the local strict endpoint (journal,
/// repository and topic registration).  `transit_version` describes whether
/// the binary can carry opaque strict frames without interpreting them.  A
/// member may therefore have `participant_version == 0` while still having a
/// non-zero transit version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProtocolMember {
    node: NodeIdentifier,
    boot_epoch: u64,
    reachable: bool,
    strict_participant: bool,
    participant_version: u32,
    transit_enabled: bool,
    transit_version: u32,
}

impl ProtocolMember {
    pub(crate) fn new(
        node: NodeIdentifier,
        boot_epoch: u64,
        reachable: bool,
        strict_participant: bool,
        participant_version: u32,
        transit_enabled: bool,
        transit_version: u32,
    ) -> Self {
        Self {
            node,
            boot_epoch,
            reachable,
            strict_participant,
            participant_version,
            transit_enabled,
            transit_version,
        }
    }

    pub(crate) fn node(self) -> NodeIdentifier {
        self.node
    }

    pub(crate) fn boot_epoch(self) -> u64 {
        self.boot_epoch
    }

    pub(crate) fn reachable(self) -> bool {
        self.reachable
    }

    pub(crate) fn strict_participant(self) -> bool {
        self.strict_participant
    }

    pub(crate) fn participant_version(self) -> u32 {
        self.participant_version
    }

    pub(crate) fn transit_enabled(self) -> bool {
        self.transit_enabled
    }

    pub(crate) fn transit_version(self) -> u32 {
        self.transit_version
    }
}

/// A target incarnation for one strict replication round.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StrictProtocolTarget {
    pub(crate) node: NodeIdentifier,
    pub(crate) boot_epoch: u64,
}

/// Negotiated protocol floor and the strict-participant target set captured
/// from one membership view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StrictProtocolSnapshot {
    pub(crate) negotiated_version: u32,
    pub(crate) targets: Vec<StrictProtocolTarget>,
}

/// Independent blocker counts for diagnostics and health metrics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct UnsupportedProtocolPeers {
    participant: usize,
    transit: usize,
    peers: usize,
}

impl UnsupportedProtocolPeers {
    pub(crate) fn participant(self) -> usize {
        self.participant
    }

    pub(crate) fn transit(self) -> usize {
        self.transit
    }

    /// Number of distinct reachable members with at least one unsupported
    /// capability. Category counters may overlap for a member that is both a
    /// participant and a relay.
    pub(crate) fn total(self) -> usize {
        self.peers
    }
}

/// Compute the strict protocol floor and target set from one immutable member
/// view.  Strict targets include only active strict participants.  The floor
/// includes every active relay-capable member's transit capability so an old
/// relay cannot silently strip newer opaque frames.
pub(crate) fn strict_protocol_snapshot(
    members: impl IntoIterator<Item = ProtocolMember>,
    local_participant_version: Option<u32>,
    local_transit_version: u32,
) -> StrictProtocolSnapshot {
    let members: Vec<ProtocolMember> = members.into_iter().collect();
    let participant_floor = participant_floor(&members, local_participant_version);
    let transit_floor = transit_floor(&members, local_transit_version);
    let negotiated_version = if participant_floor == 0 {
        0
    } else {
        participant_floor.min(transit_floor)
    };

    let mut targets: Vec<_> = members
        .iter()
        .copied()
        .filter(|member| member.reachable() && member.strict_participant())
        .map(|member| StrictProtocolTarget {
            node: member.node(),
            boot_epoch: member.boot_epoch(),
        })
        .collect();
    targets.sort_by_key(|target| target.node);

    StrictProtocolSnapshot {
        negotiated_version,
        targets,
    }
}

/// Compute the participant/transit floors without constructing targets.
pub(crate) fn strict_protocol_floors(
    members: impl IntoIterator<Item = ProtocolMember>,
    local_participant_version: Option<u32>,
    local_transit_version: u32,
) -> (u32, u32, u32) {
    let members: Vec<ProtocolMember> = members.into_iter().collect();
    let participant = participant_floor(&members, local_participant_version);
    let transit = transit_floor(&members, local_transit_version);
    let effective = if participant == 0 {
        0
    } else {
        participant.min(transit)
    };
    (participant, transit, effective)
}

/// Count members that cannot understand the requested protocol version by
/// capability category. Unreachable members are ignored, as are members that
/// do not advertise the corresponding service.
pub(crate) fn unsupported_protocol_peers(
    members: impl IntoIterator<Item = ProtocolMember>,
    required_version: u32,
) -> UnsupportedProtocolPeers {
    let mut unsupported = UnsupportedProtocolPeers::default();
    for member in members {
        if !member.reachable() {
            continue;
        }
        let participant_unsupported =
            member.strict_participant() && member.participant_version() < required_version;
        let transit_unsupported =
            member.transit_enabled() && member.transit_version() < required_version;
        if participant_unsupported {
            unsupported.participant += 1;
        }
        if transit_unsupported {
            unsupported.transit += 1;
        }
        if participant_unsupported || transit_unsupported {
            unsupported.peers += 1;
        }
    }
    unsupported
}

fn participant_floor(members: &[ProtocolMember], local_version: Option<u32>) -> u32 {
    let mut floor = local_version.unwrap_or(u32::MAX);
    let mut found = local_version.is_some();
    for member in members.iter().copied() {
        if member.reachable() && member.strict_participant() {
            found = true;
            floor = floor.min(member.participant_version());
        }
    }
    if found { floor } else { 0 }
}

fn transit_floor(members: &[ProtocolMember], local_version: u32) -> u32 {
    let mut floor = local_version;
    for member in members.iter().copied() {
        if member.reachable() && member.transit_enabled() {
            floor = floor.min(member.transit_version());
        }
    }
    floor
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(
        node: NodeIdentifier,
        strict: bool,
        participant: u32,
        transit: bool,
        transit_version: u32,
    ) -> ProtocolMember {
        ProtocolMember::new(node, 1, true, strict, participant, transit, transit_version)
    }

    #[test]
    fn v2_participant_and_modern_relay_only_node_negotiate_v2() {
        let snapshot = strict_protocol_snapshot(
            [member(1, true, 2, true, 2), member(2, false, 0, true, 2)],
            Some(2),
            2,
        );
        assert_eq!(snapshot.negotiated_version, 2);
        assert_eq!(snapshot.targets.len(), 1);
        assert_eq!(snapshot.targets[0].node, 1);
    }

    #[test]
    fn old_transit_relay_lowers_effective_floor() {
        let (participant, transit, effective) = strict_protocol_floors(
            [member(1, true, 2, true, 0), member(2, false, 0, true, 0)],
            Some(2),
            2,
        );
        assert_eq!((participant, transit, effective), (2, 0, 0));
    }

    #[test]
    fn replication_disabled_modern_node_is_not_a_participant() {
        let snapshot = strict_protocol_snapshot(
            [member(1, true, 2, true, 2), member(2, false, 0, true, 2)],
            Some(2),
            2,
        );
        assert_eq!(
            snapshot.targets,
            [StrictProtocolTarget {
                node: 1,
                boot_epoch: 1
            }]
        );
        let blockers = unsupported_protocol_peers(
            [member(1, true, 2, true, 2), member(2, false, 0, true, 2)],
            2,
        );
        assert_eq!(blockers, UnsupportedProtocolPeers::default());
    }

    #[test]
    fn disabled_local_participant_does_not_pin_remote_v2_floor() {
        let (participant, transit, effective) = strict_protocol_floors(
            [member(1, true, 2, true, 2), member(2, false, 0, true, 2)],
            None,
            2,
        );
        assert_eq!((participant, transit, effective), (2, 2, 2));
    }

    #[test]
    fn no_strict_participants_fails_closed() {
        let snapshot = strict_protocol_snapshot([member(2, false, 0, true, 2)], None, 2);
        assert_eq!(snapshot.negotiated_version, 0);
        assert!(snapshot.targets.is_empty());
    }

    #[test]
    fn blocker_diagnostics_keep_participant_and_transit_separate() {
        let blockers = unsupported_protocol_peers(
            [member(1, true, 1, true, 2), member(2, false, 0, true, 1)],
            2,
        );
        assert_eq!(blockers.participant(), 1);
        assert_eq!(blockers.transit(), 1);
        assert_eq!(blockers.total(), 2);
    }

    #[test]
    fn blocker_total_counts_a_dual_role_peer_once() {
        let blockers = unsupported_protocol_peers([member(1, true, 1, true, 1)], 2);
        assert_eq!(blockers.participant(), 1);
        assert_eq!(blockers.transit(), 1);
        assert_eq!(blockers.total(), 1);
    }
}
