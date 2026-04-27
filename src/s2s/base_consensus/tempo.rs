use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::s2s::overlay_network::NodeId;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct TempoSlot {
    pub timestamp_ms: u64,
    pub replica_id: NodeId,
}

#[derive(Debug, Clone)]
pub struct TempoCore {
    pub local_node: NodeId,
    pub last_reserved_ts_ms: u64,
    pub committed_index: u64,
    pub last_applied: u64,
    pub committed_ops: u64,
}

impl TempoCore {
    pub fn new(local_node: NodeId) -> Self {
        Self {
            local_node,
            last_reserved_ts_ms: 0,
            committed_index: 0,
            last_applied: 0,
            committed_ops: 0,
        }
    }

    pub fn reserve_slot(&mut self) -> TempoSlot {
        self.reserve_slot_at(unix_ms_now())
    }

    pub fn reserve_slot_at(&mut self, observed_now_ms: u64) -> TempoSlot {
        let timestamp_ms = observed_now_ms.max(self.last_reserved_ts_ms.saturating_add(1));
        self.last_reserved_ts_ms = timestamp_ms;
        TempoSlot {
            timestamp_ms,
            replica_id: self.local_node,
        }
    }

    pub fn observe_remote_index(&mut self, order_index: u64) {
        if order_index > self.committed_index {
            self.committed_ops = self.committed_ops.saturating_add(1);
        }
        self.committed_index = self.committed_index.max(order_index);
        self.last_applied = self.last_applied.max(order_index);
        self.last_reserved_ts_ms = self
            .last_reserved_ts_ms
            .max(Self::timestamp_from_order_index(order_index));
    }

    pub fn commit_slot(&mut self, slot: TempoSlot) -> u64 {
        let order_index = Self::order_index(slot.timestamp_ms, slot.replica_id);
        self.observe_remote_index(order_index);
        order_index
    }

    pub fn order_index(timestamp_ms: u64, replica_id: NodeId) -> u64 {
        (timestamp_ms << 16) | u64::from(replica_id)
    }

    pub fn timestamp_from_order_index(order_index: u64) -> u64 {
        order_index >> 16
    }
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_uses_monotonic_timestamps() {
        let mut core = TempoCore::new(7);
        let first = core.reserve_slot_at(1000);
        let second = core.reserve_slot_at(1000);
        assert_eq!(first.timestamp_ms, 1000);
        assert_eq!(second.timestamp_ms, 1001);
    }

    #[test]
    fn order_index_is_timestamp_then_replica() {
        let a = TempoCore::order_index(1_000_000, 1);
        let b = TempoCore::order_index(1_000_000, 2);
        let c = TempoCore::order_index(1_000_001, 1);
        assert!(b > a);
        assert!(c > b);
        assert_eq!(TempoCore::timestamp_from_order_index(c), 1_000_001);
    }

    #[test]
    fn observing_remote_progress_advances_watermarks() {
        let mut core = TempoCore::new(3);
        let index = TempoCore::order_index(77, 4);
        core.observe_remote_index(index);
        assert_eq!(core.committed_index, index);
        assert_eq!(core.last_applied, index);
        assert_eq!(core.last_reserved_ts_ms, 77);
        assert_eq!(core.committed_ops, 1);
    }
}
