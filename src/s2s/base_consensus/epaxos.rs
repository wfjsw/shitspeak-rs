use serde::{Deserialize, Serialize};

use crate::s2s::overlay_network::NodeId;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct EpaxosBallot {
    pub epoch: u64,
    pub replica_id: NodeId,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct EpaxosInstanceId {
    pub replica_id: NodeId,
    pub local_instance: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpaxosReservation {
    pub instance: EpaxosInstanceId,
    pub sequence: u64,
    pub ballot: EpaxosBallot,
    pub dependencies: Vec<EpaxosInstanceId>,
}

#[derive(Debug, Clone)]
pub struct EpaxosCore {
    pub local_node: NodeId,
    pub local_instance: u64,
    pub max_sequence: u64,
    pub committed_index: u64,
    pub last_applied: u64,
    pub ballot_epoch: u64,
}

impl EpaxosCore {
    pub fn new(local_node: NodeId) -> Self {
        Self {
            local_node,
            local_instance: 0,
            max_sequence: 0,
            committed_index: 0,
            last_applied: 0,
            ballot_epoch: 1,
        }
    }

    pub fn reserve_instance(&mut self, dependencies: Vec<EpaxosInstanceId>) -> EpaxosReservation {
        self.local_instance = self.local_instance.saturating_add(1);
        self.max_sequence = self.max_sequence.saturating_add(1);
        EpaxosReservation {
            instance: EpaxosInstanceId {
                replica_id: self.local_node,
                local_instance: self.local_instance,
            },
            sequence: self.max_sequence,
            ballot: EpaxosBallot {
                epoch: self.ballot_epoch,
                replica_id: self.local_node,
            },
            dependencies,
        }
    }

    pub fn observe_remote_index(&mut self, order_index: u64) {
        self.max_sequence = self.max_sequence.max(Self::sequence_from_order_index(order_index));
        self.committed_index = self.committed_index.max(order_index);
        self.last_applied = self.last_applied.max(order_index);
    }

    pub fn commit_instance(&mut self, reservation: &EpaxosReservation) -> u64 {
        let order_index = Self::order_index(reservation.sequence, reservation.instance.replica_id);
        self.observe_remote_index(order_index);
        order_index
    }

    pub fn order_index(sequence: u64, replica_id: NodeId) -> u64 {
        (sequence << 16) | u64::from(replica_id)
    }

    pub fn sequence_from_order_index(order_index: u64) -> u64 {
        order_index >> 16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_is_egalitarian_and_monotonic() {
        let mut core = EpaxosCore::new(7);
        let first = core.reserve_instance(Vec::new());
        let second = core.reserve_instance(Vec::new());

        assert_eq!(first.instance.replica_id, 7);
        assert_eq!(first.instance.local_instance, 1);
        assert_eq!(second.instance.local_instance, 2);
        assert!(second.sequence > first.sequence);
    }

    #[test]
    fn order_index_is_deterministic() {
        let index_a = EpaxosCore::order_index(3, 1);
        let index_b = EpaxosCore::order_index(3, 2);
        assert!(index_b > index_a);
        assert_eq!(EpaxosCore::sequence_from_order_index(index_b), 3);
    }

    #[test]
    fn commit_observes_remote_progress() {
        let mut core = EpaxosCore::new(4);
        core.observe_remote_index(EpaxosCore::order_index(8, 2));
        let reserved = core.reserve_instance(Vec::new());
        assert_eq!(reserved.sequence, 9);
    }
}
