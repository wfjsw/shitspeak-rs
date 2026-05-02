//! Per-member status state machine.

use std::time::Instant;

use crate::s2s::transport::PeerAddress;
use crate::types::NodeIdentifier;

/// Lifecycle status of one member as observed by the local node.
///
/// Numerical ordering reflects "newer information wins" precedence on
/// gossip merge: a higher-numbered status overrides a lower-numbered one
/// for the same `(node, incarnation)` pair. `Left` always wins because
/// graceful leave is the strongest signal we can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum MemberStatus {
    Alive = 0,
    Suspect = 1,
    Dead = 2,
    Left = 3,
}

impl MemberStatus {
    /// True if this status indicates a peer we should still try to talk to.
    pub fn is_reachable(self) -> bool {
        matches!(self, MemberStatus::Alive | MemberStatus::Suspect)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            MemberStatus::Alive => "alive",
            MemberStatus::Suspect => "suspect",
            MemberStatus::Dead => "dead",
            MemberStatus::Left => "left",
        }
    }
}

/// One member's state as held in the local table. `incarnation` is the
/// generation number stamped by the *origin* node — bumping it lets the
/// origin refute stale `Suspect/Dead` claims about itself.
#[derive(Debug, Clone)]
pub struct MemberRecord {
    node_id: NodeIdentifier,
    status: MemberStatus,
    incarnation: u64,
    addresses: Vec<PeerAddress>,
    last_state_change: Instant,
    /// Wallclock of the last positive contact (ack received). Used by the
    /// SWIM ticker to decide who to probe next.
    last_ack_at: Option<Instant>,
}

impl MemberRecord {
    pub fn node_id(&self) -> NodeIdentifier {
        self.node_id
    }

    pub fn status(&self) -> MemberStatus {
        self.status
    }

    pub fn incarnation(&self) -> u64 {
        self.incarnation
    }

    pub fn addresses(&self) -> &[PeerAddress] {
        &self.addresses
    }

    pub fn last_state_change(&self) -> Instant {
        self.last_state_change
    }

    pub fn last_ack_at(&self) -> Option<Instant> {
        self.last_ack_at
    }

    pub fn set_status(&mut self, s: MemberStatus) {
        self.status = s;
    }

    pub fn add_address(&mut self, addr: PeerAddress) {
        if !self.addresses.contains(&addr) {
            self.addresses.push(addr);
        }
    }

    /// Override `last_state_change` (for tests).
    pub fn set_last_state_change(&mut self, t: Instant) {
        self.last_state_change = t;
    }
}

impl MemberRecord {
    pub fn new_alive(
        node_id: NodeIdentifier,
        incarnation: u64,
        addresses: Vec<PeerAddress>,
    ) -> Self {
        Self {
            node_id,
            status: MemberStatus::Alive,
            incarnation,
            addresses,
            last_state_change: Instant::now(),
            last_ack_at: Some(Instant::now()),
        }
    }

    pub fn new_seed(node_id: NodeIdentifier, addresses: Vec<PeerAddress>) -> Self {
        Self {
            node_id,
            status: MemberStatus::Suspect,
            incarnation: 0,
            addresses,
            last_state_change: Instant::now(),
            last_ack_at: None,
        }
    }

    /// Try to apply an update produced by `producer_incarnation` claiming
    /// `claim` for this member. Returns true if the record changed.
    ///
    /// Merge rule:
    ///   - higher incarnation always wins.
    ///   - same incarnation: higher MemberStatus number wins
    ///     (Left > Dead > Suspect > Alive).
    ///   - lower incarnation: ignored.
    pub fn merge(
        &mut self,
        new_incarnation: u64,
        claim: MemberStatus,
        new_addresses: &[PeerAddress],
    ) -> bool {
        let mut changed = false;

        if new_incarnation > self.incarnation {
            self.incarnation = new_incarnation;
            self.status = claim;
            self.last_state_change = Instant::now();
            changed = true;
        } else if new_incarnation == self.incarnation && claim > self.status {
            self.status = claim;
            self.last_state_change = Instant::now();
            changed = true;
        }

        // Always learn newly-known addresses regardless of incarnation —
        // the address space grows monotonically and is annotated by the
        // peer themselves.
        for a in new_addresses {
            if !self.addresses.contains(a) {
                self.addresses.push(*a);
                changed = true;
            }
        }

        changed
    }

    /// Locally observed transitions (no incarnation bump). Returns true if
    /// the record changed. Used by the SWIM ticker after a probe times out.
    pub fn local_transition(&mut self, new_status: MemberStatus) -> bool {
        if self.status == new_status {
            return false;
        }
        // Only allow strictly-monotonic upgrades within the same incarnation.
        if new_status <= self.status {
            return false;
        }
        self.status = new_status;
        self.last_state_change = Instant::now();
        true
    }

    pub fn note_ack(&mut self) {
        self.last_ack_at = Some(Instant::now());
        if self.status == MemberStatus::Suspect {
            // ack refutes Suspect locally. Origin's incarnation didn't change
            // — we just observed activity. Move back to Alive.
            self.status = MemberStatus::Alive;
            self.last_state_change = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(port: u16) -> PeerAddress {
        PeerAddress::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
            crate::s2s::transport::TransportKind::Tcp,
        )
    }

    #[test]
    fn higher_incarnation_overrides_status() {
        let mut r = MemberRecord::new_alive(1, 100, vec![addr(1)]);
        assert!(r.merge(200, MemberStatus::Suspect, &[]));
        assert_eq!(r.incarnation, 200);
        assert_eq!(r.status, MemberStatus::Suspect);
    }

    #[test]
    fn lower_incarnation_ignored() {
        let mut r = MemberRecord::new_alive(1, 200, vec![]);
        assert!(!r.merge(100, MemberStatus::Dead, &[]));
        assert_eq!(r.status, MemberStatus::Alive);
    }

    #[test]
    fn same_incarnation_status_monotonic() {
        let mut r = MemberRecord::new_alive(1, 100, vec![]);
        assert!(r.merge(100, MemberStatus::Suspect, &[]));
        assert_eq!(r.status, MemberStatus::Suspect);
        // Alive cannot downgrade Suspect at same incarnation.
        assert!(!r.merge(100, MemberStatus::Alive, &[]));
        assert_eq!(r.status, MemberStatus::Suspect);
        // Dead can upgrade Suspect at same incarnation.
        assert!(r.merge(100, MemberStatus::Dead, &[]));
        assert_eq!(r.status, MemberStatus::Dead);
    }

    #[test]
    fn left_always_dominates_same_incarnation() {
        let mut r = MemberRecord::new_alive(1, 100, vec![]);
        assert!(r.merge(100, MemberStatus::Left, &[]));
        assert_eq!(r.status, MemberStatus::Left);
        // and beats Dead at same incarnation
        let mut r2 = MemberRecord::new_alive(2, 100, vec![]);
        r2.merge(100, MemberStatus::Dead, &[]);
        assert!(r2.merge(100, MemberStatus::Left, &[]));
        assert_eq!(r2.status, MemberStatus::Left);
    }

    #[test]
    fn addresses_accumulate_monotonically() {
        let mut r = MemberRecord::new_alive(1, 100, vec![addr(1)]);
        assert!(r.merge(100, MemberStatus::Alive, &[addr(2)]));
        assert!(r.addresses.contains(&addr(1)));
        assert!(r.addresses.contains(&addr(2)));
        // duplicate is a no-op
        assert!(!r.merge(100, MemberStatus::Alive, &[addr(2)]));
    }

    #[test]
    fn ack_refutes_local_suspect() {
        let mut r = MemberRecord::new_alive(1, 100, vec![]);
        r.local_transition(MemberStatus::Suspect);
        assert_eq!(r.status, MemberStatus::Suspect);
        r.note_ack();
        assert_eq!(r.status, MemberStatus::Alive);
    }
}
